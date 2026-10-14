use ida_mcp::nexus::*;
use ida_mcp::router::{
    protocol::{RpcRequest, RpcResponse},
    transport::RpcConnection,
    RouterState,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

static TEST_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
async fn send(
    connection: &RpcConnection,
    id: &str,
    padding: usize,
) -> ida_mcp::router::transport::WaitingReply {
    let request = RpcRequest::new(id, "fixture", json!({"padding":"x".repeat(padding)}));
    let encoded = RpcConnection::encode(request)
        .await
        .expect("encode fixture");
    connection
        .enqueue(id.into(), encoded, deadline())
        .expect("admit fixture")
}
fn pair(capacity: usize) -> (RpcConnection, UnixStream) {
    let (client, server) = UnixStream::pair().expect("real OS UnixStream pair");
    let (reader, writer) = client.into_split();
    (RpcConnection::start(reader, writer, capacity), server)
}

#[tokio::test(flavor = "current_thread")]
async fn e18_real_pipe_backpressure_is_bounded_and_other_connection_progresses() {
    let _fixture_gate = TEST_GATE.lock().await;
    let (a, mut server_a) = pair(2);
    let first = send(&a, "r1", 4 * 1024 * 1024).await;
    let mut started = [0];
    tokio::io::AsyncReadExt::read_exact(&mut server_a, &mut started)
        .await
        .expect("A physical write started barrier");
    let second = send(&a, "r2", 0).await;
    assert_eq!(a.pending_len(), 2);
    assert!(matches!(
        a.enqueue("r3".into(), b"{}\n".to_vec(), deadline()),
        Err(ida_mcp::error::ToolError::Busy)
    ));
    let (b, server_b) = pair(2);
    let responder = tokio::spawn(async move {
        let (reader, mut writer) = server_b.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .expect("B request handshake");
        let request: RpcRequest = serde_json::from_str(&line).expect("B request");
        writer
            .write_all(
                format!(
                    "{}\n",
                    serde_json::to_string(&RpcResponse::ok(request.id, json!("B completed")))
                        .unwrap()
                )
                .as_bytes(),
            )
            .await
            .expect("B response");
    });
    let response = send(&b, "r100", 0).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), response.wait(3))
            .await
            .expect("B deadline")
            .expect("B result"),
        json!("B completed")
    );
    let router = RouterState::new().expect("router");
    let status = tokio::time::timeout(Duration::from_secs(1), router.status_snapshot())
        .await
        .expect("local status deadline");
    assert_eq!(status.worker_count, 0);
    assert_eq!(a.pending_len(), 2);
    drop(server_a); // real EOF while A remains blocked: each waiter receives classification.
    let first_error = first.wait(3).await.expect_err("A EOF").to_string();
    let second_error = second.wait(3).await.expect_err("queued EOF").to_string();
    assert!(first_error.contains("UnknownOutcome"), "{first_error}");
    assert!(second_error.contains("NotSent"), "{second_error}");
    assert_eq!(a.pending_len(), 0);
    responder.await.expect("B responder");
    b.close();
}

#[tokio::test(flavor = "current_thread")]
async fn fast_out_of_order_and_late_responses_never_cross_ids() {
    let _fixture_gate = TEST_GATE.lock().await;
    let (connection, server) = pair(8);
    let first = send(&connection, "r1", 0).await;
    let second = send(&connection, "r2", 0).await;
    let (reader, mut writer) = server.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    for _ in 0..2 {
        line.clear();
        reader
            .read_line(&mut line)
            .await
            .expect("request handshake");
    }
    for (id, value) in [("r2", 2), ("r1", 1), ("r1", 999)] {
        writer
            .write_all(
                format!(
                    "{}\n",
                    serde_json::to_string(&RpcResponse::ok(id, json!(value))).unwrap()
                )
                .as_bytes(),
            )
            .await
            .expect("response");
    }
    assert_eq!(second.wait(3).await.unwrap(), json!(2));
    assert_eq!(first.wait(3).await.unwrap(), json!(1));
    let third = send(&connection, "r3", 0).await;
    line.clear();
    reader.read_line(&mut line).await.expect("third request");
    writer
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"r3\",\"result\":3}\n")
        .await
        .unwrap();
    assert_eq!(third.wait(3).await.unwrap(), json!(3));
    assert_eq!(connection.pending_len(), 0);
    connection.close();
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_queued_request_is_removed_and_never_written() {
    let _fixture_gate = TEST_GATE.lock().await;
    let (connection, server) = pair(2);
    let first = send(&connection, "r1", 4 * 1024 * 1024).await;
    let queued = send(&connection, "r2", 0).await;
    drop(queued);
    assert_eq!(connection.pending_len(), 1);
    drop(server);
    assert!(first.wait(3).await.is_err());
    assert_eq!(connection.pending_len(), 0);
}

fn capabilities() -> NexusCapabilities {
    NexusCapabilities {
        runtime: NexusRuntime {
            ida: Version(9, 5, 0),
            python: Version(3, 14, 7),
            nexus: Some(Version(0, 13, 4)),
            domain: Some(Version(0, 5, 1)),
        },
        methods: BTreeMap::from([("fixture".into(), MethodEffect::MayWrite)]),
    }
}
async fn session(
    endpoint: &ida_mcp::router::nexus_transport::NexusEndpoint,
    lanes: &mut ida_mcp::router::nexus_transport::NexusLanes,
    name: &str,
) -> SessionLease {
    let client = ClientId::new(format!("c-{name}")).unwrap();
    let request = AcceptedRequest::new(
        &SystemClock,
        RequestId::new(format!("open-r-{name}")).unwrap(),
        None,
        "open",
        json!({}),
    )
    .unwrap();
    let identity = endpoint
        .transition(|sessions, backend| {
            sessions.open(
                &client,
                request,
                OpenSpec {
                    operation_id: OperationId::new(format!("open-o-{name}")).unwrap(),
                    path: format!("/fixture/{name}.i64"),
                    options: json!({}),
                },
                backend,
            )
        })
        .unwrap();
    let mut delivery = lanes.business.recv().await.expect("open delivery");
    assert!(matches!(
        delivery.begin().unwrap(),
        SessionCommand::Open { .. }
    ));
    delivery.acknowledged().unwrap();
    let lease = SessionLease {
        client_id: client,
        lease_id: LeaseId::new(format!("l-{name}")).unwrap(),
        instance_id: InstanceId::new(format!("i-{name}")).unwrap(),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    let disposition = endpoint
        .transition(|sessions, _| sessions.opened(&identity, lease.clone(), capabilities()))
        .unwrap();
    assert!(matches!(disposition, OpenDisposition::Ready(_)));
    lease
}
fn operation(
    endpoint: &ida_mcp::router::nexus_transport::NexusEndpoint,
    lease: &SessionLease,
    name: &str,
) -> OperationIdentity {
    let request = AcceptedRequest::new(
        &SystemClock,
        RequestId::new(format!("r-{name}")).unwrap(),
        Some(TaskId::new(format!("task-{name}")).unwrap()),
        "fixture",
        json!({}),
    )
    .unwrap();
    let identity = endpoint
        .transition(|sessions, _| {
            sessions.queue(
                &lease.client_id,
                lease,
                request,
                OperationId::new(format!("o-{name}")).unwrap(),
            )
        })
        .unwrap();
    endpoint
        .transition(|sessions, backend| sessions.dispatch(&lease.client_id, &identity, backend))
        .unwrap();
    identity
}
#[tokio::test(flavor = "current_thread")]
async fn e08_nexus_started_a_keeps_local_task_b_and_independent_control_live() {
    let _fixture_gate = TEST_GATE.lock().await;
    let router = RouterState::new().unwrap();
    router.install_nexus_capabilities(capabilities()).unwrap();
    let endpoint = router.nexus_endpoint();
    let mut lanes = endpoint.take_lanes().expect("single N3 handoff");
    let a = session(&endpoint, &mut lanes, "a").await;
    let b = session(&endpoint, &mut lanes, "b").await;
    let a_identity = operation(&endpoint, &a, "a");
    let mut blocked = lanes.business.recv().await.unwrap();
    let command = blocked.begin().expect("A started barrier");
    assert!(matches!(command, SessionCommand::Execute(_)));
    // Keep delivery alive: this models A's native operation still running.
    let b_identity = operation(&endpoint, &b, "b");
    let mut b_delivery = lanes.business.recv().await.unwrap();
    b_delivery.begin().unwrap();
    b_delivery.acknowledged().unwrap();
    endpoint
        .transition(|sessions, _| sessions.complete(&b_identity, Completion::Success(json!("B"))))
        .unwrap();
    let state = endpoint
        .transition(|sessions, _| sessions.operation_status(&a.client_id, &a_identity))
        .unwrap();
    assert_eq!(state.status, OperationStatus::Running);
    assert!(!state.execution_stopped);
    let task = ida_mcp::server::task::nexus_task_state_json(&state, "fixture", "fixture").unwrap();
    assert_eq!(task["status"], "running");
    tokio::time::timeout(Duration::from_secs(1), router.status_snapshot())
        .await
        .expect("router local deadline");
    endpoint
        .transition(|sessions, backend| {
            sessions.cancel(&a.client_id, &a_identity, CancelReason::Client, backend)
        })
        .unwrap();
    let mut control = tokio::time::timeout(Duration::from_secs(1), lanes.control.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(control.begin().unwrap(),SessionCommand::Cancel{identity,..} if identity==a_identity)
    );
    control.acknowledged().unwrap();
    assert!(
        !endpoint
            .transition(|sessions, _| sessions.operation_status(&a.client_id, &a_identity))
            .unwrap()
            .execution_stopped
    );
    blocked.failed(DispatchFailure::Uncertain(NexusError::new(
        NexusErrorCode::Disconnected,
        "A fixture disconnected after started",
    )));
    let unknown = endpoint
        .transition(|sessions, _| sessions.operation_status(&a.client_id, &a_identity))
        .unwrap();
    assert_eq!(unknown.status, OperationStatus::UnknownOutcome);
    assert!(!unknown.execution_stopped);
    endpoint
        .transition(|sessions, _| sessions.complete(&a_identity, Completion::Cancelled))
        .unwrap();
}
#[tokio::test(flavor = "current_thread")]
async fn enqueue_ok_then_consumer_drop_calls_n1_not_sent_callback() {
    let _fixture_gate = TEST_GATE.lock().await;
    let router = RouterState::new().unwrap();
    router.install_nexus_capabilities(capabilities()).unwrap();
    let endpoint = router.nexus_endpoint();
    let mut lanes = endpoint.take_lanes().unwrap();
    let lease = session(&endpoint, &mut lanes, "drop").await;
    let identity = operation(&endpoint, &lease, "drop");
    let delivery = lanes.business.recv().await.unwrap();
    drop(delivery);
    let snapshot = endpoint
        .transition(|sessions, _| sessions.operation_status(&lease.client_id, &identity))
        .unwrap();
    assert_eq!(snapshot.status, OperationStatus::Failed);
    assert!(snapshot.execution_stopped);
    assert_eq!(
        snapshot.error.unwrap().retry_advice(),
        RetryAdvice::ReconnectThenNewRequest
    );
}
#[tokio::test(flavor = "current_thread")]
async fn consumer_drop_inside_n1_transition_is_bounded_and_does_not_reverse_lock() {
    let _fixture_gate = TEST_GATE.lock().await;
    let router = RouterState::new().unwrap();
    router.install_nexus_capabilities(capabilities()).unwrap();
    let endpoint = router.nexus_endpoint();
    let mut lanes = endpoint.take_lanes().unwrap();
    let lease = session(&endpoint, &mut lanes, "lock-drop").await;
    let identity = operation(&endpoint, &lease, "lock-drop");
    let delivery = lanes.business.recv().await.unwrap();
    endpoint.transition(|_, _| drop(delivery));
    let snapshot = endpoint
        .transition(|sessions, _| sessions.operation_status(&lease.client_id, &identity))
        .unwrap();
    assert_eq!(snapshot.status, OperationStatus::Failed);
    assert!(snapshot.execution_stopped);
}

#[tokio::test(flavor = "current_thread")]
async fn worker_reads_control_while_a_is_started_and_same_idb_business_stays_serial() {
    let _fixture_gate = TEST_GATE.lock().await;
    let (client, server) = UnixStream::pair().unwrap();
    let (reader, writer) = server.into_split();
    let (started_send, mut started_receive) = tokio::sync::mpsc::channel(2);
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let dispatcher_release = release.clone();
    let server_task = tokio::spawn(ida_mcp::router::worker_io::serve(
        reader,
        writer,
        move |request| {
            let started = started_send.clone();
            let release = dispatcher_release.clone();
            async move {
                started.send(request.id.clone()).await.unwrap();
                if request.id == "a" {
                    release.notified().await;
                }
                Ok(json!(request.id))
            }
        },
    ));
    let (reader, mut writer) = client.into_split();
    let mut reader = BufReader::new(reader);
    writer
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"fixture\",\"params\":{}}\n")
        .await
        .unwrap();
    assert_eq!(started_receive.recv().await.unwrap(), "a");
    writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"b\",\"method\":\"fixture\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":\"control\",\"method\":\"__transport_status\",\"params\":{}}\n").await.unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(1), reader.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let control: RpcResponse = serde_json::from_str(&line).unwrap();
    assert_eq!(control.id, "control");
    assert_eq!(control.result.unwrap()["native_preemption"], false);
    assert!(
        started_receive.try_recv().is_err(),
        "B must not execute while A owns this IDB"
    );
    release.notify_one();
    assert_eq!(started_receive.recv().await.unwrap(), "b");
    for expected in ["a", "b"] {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(
            serde_json::from_str::<RpcResponse>(&line).unwrap().id,
            expected
        );
    }
    drop(writer);
    server_task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_execute_in_nexus_local_queue_is_not_sent() {
    let _fixture_gate = TEST_GATE.lock().await;
    let router = RouterState::new().unwrap();
    router.install_nexus_capabilities(capabilities()).unwrap();
    let endpoint = router.nexus_endpoint();
    let mut lanes = endpoint.take_lanes().unwrap();
    let lease = session(&endpoint, &mut lanes, "queued-cancel").await;
    let identity = operation(&endpoint, &lease, "queued-cancel");
    endpoint
        .transition(|sessions, backend| {
            sessions.cancel(&lease.client_id, &identity, CancelReason::Client, backend)
        })
        .unwrap();
    let mut queued = lanes.business.recv().await.unwrap();
    assert_eq!(queued.begin().unwrap_err().code, NexusErrorCode::Cancelled);
    let state = endpoint
        .transition(|sessions, _| sessions.operation_status(&lease.client_id, &identity))
        .unwrap();
    assert!(state.execution_stopped);
    assert_eq!(state.status, OperationStatus::Failed);
    drop(queued);
    drop(lanes); // Cancel delivery failure does not change the operation stop proof.
}

#[tokio::test(flavor = "current_thread")]
async fn nexus_partial_os_pipe_failure_uses_uncertain_callback_and_keeps_occupancy() {
    let _fixture_gate = TEST_GATE.lock().await;
    let router = RouterState::new().unwrap();
    router.install_nexus_capabilities(capabilities()).unwrap();
    let endpoint = router.nexus_endpoint();
    let mut lanes = endpoint.take_lanes().unwrap();
    let lease = session(&endpoint, &mut lanes, "partial").await;
    let request = AcceptedRequest::new(
        &SystemClock,
        RequestId::new("partial-r").unwrap(),
        None,
        "fixture",
        json!({"padding":"x".repeat(4*1024*1024)}),
    )
    .unwrap();
    let identity = endpoint
        .transition(|sessions, _| {
            sessions.queue(
                &lease.client_id,
                &lease,
                request,
                OperationId::new("partial-o").unwrap(),
            )
        })
        .unwrap();
    endpoint
        .transition(|sessions, backend| sessions.dispatch(&lease.client_id, &identity, backend))
        .unwrap();
    let delivery = lanes.business.recv().await.unwrap();
    let (mut writer, mut consumer) = UnixStream::pair().unwrap();
    let writing = tokio::spawn(async move { delivery.write(&mut writer).await });
    let mut byte = [0];
    tokio::io::AsyncReadExt::read_exact(&mut consumer, &mut byte)
        .await
        .expect("physical Nexus frame started barrier");
    drop(consumer);
    assert!(writing.await.unwrap().is_err());
    let state = endpoint
        .transition(|sessions, _| sessions.operation_status(&lease.client_id, &identity))
        .unwrap();
    assert_eq!(state.status, OperationStatus::UnknownOutcome);
    assert!(!state.execution_stopped);
    assert_eq!(
        state.error.unwrap().retry_advice(),
        RetryAdvice::NeverReplay
    );
}

struct ZeroWriter;
impl tokio::io::AsyncWrite for ZeroWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
#[tokio::test(flavor = "current_thread")]
async fn proven_zero_write_reports_not_sent_and_drains_pending() {
    let _fixture_gate = TEST_GATE.lock().await;
    let (reader, _keep_alive) = tokio::io::duplex(1);
    let connection = RpcConnection::start(reader, ZeroWriter, 2);
    let request = send(&connection, "r1", 0).await;
    let error = request.wait(3).await.unwrap_err().to_string();
    assert!(error.contains("NotSent"), "{error}");
    assert_eq!(connection.pending_len(), 0);
}
