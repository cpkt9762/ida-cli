use ida_mcp::blocking::{self, WorkClass};
use ida_mcp::nexus::*;
use ida_mcp::router::{
    nexus_transport::{NexusEndpoint, NexusLanes},
    protocol::RpcResponse,
    transport::RpcConnection,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

#[tokio::test(flavor = "current_thread")]
async fn encode_contention_must_not_close_an_unrelated_healthy_connection() {
    let _fixture_gate = super::FIXTURE_GATE.lock().await;
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (read, write) = client.into_split();
    let connection = RpcConnection::start(read, write, 2);
    let mut holders = Vec::new();
    for _ in 0..2 {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let job = tokio::spawn(blocking::run(WorkClass::Encode, move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        }));
        started_rx.await.expect("encoding permit held barrier");
        holders.push((release_tx, job));
    }
    let response = connection
        .enqueue(
            "healthy".into(),
            b"{\"jsonrpc\":\"2.0\",\"id\":\"healthy\",\"method\":\"fixture\",\"params\":{}}\n"
                .to_vec(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
    let (read, mut write) = server.into_split();
    let mut read = BufReader::new(read);
    let mut line = String::new();
    read.read_line(&mut line).await.unwrap();
    write
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"healthy\",\"result\":7}\n")
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_millis(500), response.wait(3)).await;
    let was_closed = connection.is_closed();
    for (release, job) in holders {
        release.send(()).unwrap();
        job.await.unwrap().unwrap();
    }
    connection.close();
    eprintln!("healthy result under unrelated encode contention: {result:?}; closed={was_closed}");
    assert!(
        !was_closed,
        "global encode occupancy closed a healthy connection"
    );
    assert!(
        matches!(result, Ok(Ok(ref value)) if *value == json!(7)),
        "unrelated healthy connection must progress"
    );
}

fn caps() -> NexusCapabilities {
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
async fn open(endpoint: &NexusEndpoint, lanes: &mut NexusLanes) -> SessionLease {
    let client = ClientId::new("client").unwrap();
    let request = AcceptedRequest::new(
        &SystemClock,
        RequestId::new("open-r").unwrap(),
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
                    operation_id: OperationId::new("open-o").unwrap(),
                    path: "/fixture/copy.i64".into(),
                    options: json!({}),
                },
                backend,
            )
        })
        .unwrap();
    let mut opening = lanes.business.recv().await.unwrap();
    opening.begin().unwrap();
    opening.acknowledged().unwrap();
    let lease = SessionLease {
        client_id: client,
        lease_id: LeaseId::new("lease").unwrap(),
        instance_id: InstanceId::new("owner").unwrap(),
        generation: 1,
        owner: OwnerKind::Managed,
    };
    assert!(matches!(
        endpoint
            .transition(|sessions, _| sessions.opened(&identity, lease.clone(), caps()))
            .unwrap(),
        OpenDisposition::Ready(_)
    ));
    lease
}
#[derive(Clone)]
struct CapturedWriter(Arc<Mutex<Vec<u8>>>);
impl AsyncWrite for CapturedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[test]
fn cancel_during_nexus_encoding_must_be_checked_before_first_byte() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let _fixture_gate=super::FIXTURE_GATE.lock().await;
        let endpoint = NexusEndpoint::with_capabilities(8, Ok(caps()));
        let mut lanes = endpoint.take_lanes().unwrap();
        let lease = open(&endpoint, &mut lanes).await;
        let request = AcceptedRequest::new(&SystemClock,RequestId::new("write-r").unwrap(),None,"fixture",json!({"timeout_secs":3})).unwrap();
        let identity = endpoint.transition(|s,_|s.queue(&lease.client_id,&lease,request,OperationId::new("write-o").unwrap())).unwrap();
        endpoint.transition(|s,b|s.dispatch(&lease.client_id,&identity,b)).unwrap();
        let delivery = lanes.business.recv().await.unwrap();
        let (started_tx,started_rx)=tokio::sync::oneshot::channel();
        let (release_tx,release_rx)=std::sync::mpsc::channel();
        let blocker=tokio::task::spawn_blocking(move||{started_tx.send(()).unwrap();release_rx.recv().unwrap();});
        started_rx.await.unwrap();
        let captured=Arc::new(Mutex::new(Vec::new()));
        let mut writer=CapturedWriter(captured.clone());
        let mut writing=Box::pin(delivery.write(&mut writer));
        let pending=std::future::poll_fn(|cx|Poll::Ready(matches!(writing.as_mut().poll(cx),Poll::Pending))).await;
        let cancellation=endpoint.transition(|s,b|s.cancel(&lease.client_id,&identity,CancelReason::Client,b));
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        let result=writing.await;
        let bytes=captured.lock().unwrap().len();
        let snapshot=endpoint.transition(|s,_|s.operation_status(&lease.client_id,&identity)).unwrap();
        drop(lanes);
        eprintln!("pending_encoding={pending}; cancellation={cancellation:?}; write_result={result:?}; wire_bytes={bytes}; state={snapshot:?}");
        assert!(pending, "physical sending must not have begun before cancellation");
        assert!(cancellation.is_ok());
        assert_eq!(bytes,0,"cancelled while still in encoding queue, before any byte could be sent");
        assert!(result.is_err());
        assert!(snapshot.execution_stopped);
    });
}

#[tokio::test(flavor = "current_thread")]
async fn one_second_worker_budget_must_not_be_truncated_to_zero() {
    let _fixture_gate = super::FIXTURE_GATE.lock().await;
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (read, write) = server.into_split();
    let serving = tokio::spawn(ida_mcp::router::worker_io::serve(
        read,
        write,
        |request| async move { Ok(request.params) },
    ));
    let (read, mut write) = client.into_split();
    let mut read = BufReader::new(read);
    write.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"short\",\"method\":\"fixture\",\"params\":{\"timeout_secs\":1}}\n").await.unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(1), read.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let response: RpcResponse = serde_json::from_str(&line).unwrap();
    drop(write);
    serving.await.unwrap().unwrap();
    let forwarded = response.result.unwrap()["timeout_secs"].as_u64().unwrap();
    eprintln!("forwarded positive one-second request budget = {forwarded}");
    assert!(
        forwarded > 0,
        "nearly one second remains but zero means immediate timeout in IdaWorker"
    );
}

#[test]
fn wire_deadline_consumes_encoding_pipe_and_receiver_residence() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let _fixture_gate = super::FIXTURE_GATE.lock().await;
        let endpoint = NexusEndpoint::with_capabilities(8, Ok(caps()));
        let mut lanes = endpoint.take_lanes().unwrap();
        let lease = open(&endpoint, &mut lanes).await;
        let request = AcceptedRequest::new(
            &SystemClock,
            RequestId::new("budget-r").unwrap(),
            None,
            "fixture",
            json!({"timeout_secs":3,"padding":"x".repeat(4*1024*1024)}),
        )
        .unwrap();
        let identity = endpoint
            .transition(|s, _| {
                s.queue(
                    &lease.client_id,
                    &lease,
                    request,
                    OperationId::new("budget-o").unwrap(),
                )
            })
            .unwrap();
        endpoint
            .transition(|s, b| s.dispatch(&lease.client_id, &identity, b))
            .unwrap();
        let delivery = lanes.business.recv().await.unwrap();
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let holder = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            released.recv().unwrap();
        });
        start.await.unwrap();
        let (mut writer, reader) = tokio::net::UnixStream::pair().unwrap();
        let mut writing = Box::pin(async move { delivery.write(&mut writer).await });
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(writing.as_mut().poll(cx).is_pending())).await
        );
        // Real total-deadline time must continue while the encoding barrier is held.
        tokio::time::sleep(Duration::from_millis(80)).await;
        release.send(()).unwrap();
        holder.await.unwrap();
        let writing = tokio::spawn(writing);
        let mut reader = BufReader::new(reader);
        let mut byte = [0];
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut byte)
            .await
            .unwrap();
        assert_eq!(byte[0], b'{'); // first byte: the real pipe is now partially written
        tokio::time::sleep(Duration::from_millis(80)).await;
        let mut line = String::from("{");
        reader.read_line(&mut line).await.unwrap();
        writing.await.unwrap().unwrap();
        let frame: ida_mcp::router::nexus_transport::NexusWireFrame =
            serde_json::from_str(&line).expect("versioned deadline-bearing wire frame");
        tokio::time::sleep(Duration::from_millis(80)).await;
        let (command, attempt) = frame.consume().unwrap();
        let SessionCommand::Execute(command) = command else {
            panic!("execute");
        };
        assert!(
            command.remaining_ms.milliseconds() <= 2760,
            "encoding/pipe/receiver time must not be regranted: {}",
            command.remaining_ms.milliseconds()
        );
        assert_eq!(
            attempt.target,
            DeliveryTarget::Execute {
                identity: identity.clone()
            }
        );
        endpoint
            .transition(|s, _| s.complete(&identity, Completion::Success(json!({}))))
            .unwrap();
    });
}

#[tokio::test(flavor = "current_thread")]
async fn sent_eof_close_timeout_then_cancel_never_proves_stopped_and_ready_result_wins() {
    let _fixture_gate = super::FIXTURE_GATE.lock().await;
    for event in ["eof", "close", "timeout", "success"] {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (read, write) = client.into_split();
        let connection = RpcConnection::start(read, write, 2);
        let reply = connection
            .enqueue(
                "sent".into(),
                b"{}\n".to_vec(),
                Instant::now() + Duration::from_millis(100),
            )
            .unwrap();
        let mut server = BufReader::new(server);
        let mut line = String::new();
        server.read_line(&mut line).await.unwrap();
        match event {
            "eof" => {
                drop(server);
                connection.closed().await;
            }
            "close" => {
                connection.close();
            }
            "timeout" => tokio::time::sleep(Duration::from_millis(110)).await,
            "success" => {
                server
                    .get_mut()
                    .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"sent\",\"result\":9}\n")
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(1), async {
                    while connection.pending_len() != 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            }
            _ => unreachable!(),
        }
        let preparation = ida_mcp::preprocess::Preparation::new(Duration::from_secs(3));
        preparation.cancel.cancel();
        let result = reply.wait_prepared(1, &preparation.cancel).await;
        if event == "success" {
            assert_eq!(result.unwrap(), json!(9));
        } else {
            let error = result.unwrap_err();
            assert!(
                !matches!(
                    error,
                    ida_mcp::error::ToolError::Preparation {
                        execution_stopped: true,
                        ..
                    }
                ),
                "{event}: {error}"
            );
            assert!(
                error.to_string().contains("UnknownOutcome")
                    || matches!(error, ida_mcp::error::ToolError::RequestOutcome { .. }),
                "{event}: {error}"
            );
        }
        connection.close();
        assert_eq!(connection.pending_len(), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn unicode_large_script_results_and_errors_reach_original_response_cache_and_json() {
    let _fixture_gate = super::FIXTURE_GATE.lock().await;
    let unicode = "λ".repeat(9 * 1024 * 1024);
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (read, write) = client.into_split();
    let connection = RpcConnection::start(read, write, 2);
    let (read, write) = server.into_split();
    let serving = tokio::spawn(ida_mcp::router::worker_io::serve_responses(
        read,
        write,
        move |request| {
            let unicode = unicode.clone();
            async move {
                if request.method == "error" {
                    let mut response = RpcResponse::err(request.id, -32000, unicode);
                    response.error.as_mut().unwrap().data = Some(json!({"source":"fixture"}));
                    response
                } else {
                    RpcResponse::ok(
                        request.id,
                        json!({"success":false,"stdout":unicode,"stderr":"fixture script error","result":{"unicode":"完整"}}),
                    )
                }
            }
        },
    ));
    for method in ["run_script", "error"] {
        let request =
            ida_mcp::router::protocol::RpcRequest::new(method, method, json!({"timeout_secs":10}));
        let reply = connection
            .enqueue(
                method.into(),
                RpcConnection::encode(request).await.unwrap(),
                Instant::now() + Duration::from_secs(10),
            )
            .unwrap();
        let result = reply.wait(10).await;
        if method == "run_script" {
            let value = result.unwrap();
            assert_eq!(value["success"], false);
            assert_eq!(value["stdout"].as_str().unwrap().len(), 18 * 1024 * 1024);
            assert_eq!(value["stderr"], "fixture script error");
            let cached = ida_mcp::server::response_cache::guard_response_size("run_script", value)
                .await
                .unwrap();
            assert_eq!(cached["cached"], true);
            let file = std::path::PathBuf::from(cached["file"].as_str().unwrap());
            let restored = blocking::run(WorkClass::Prepare, {
                let file = file.clone();
                move || {
                    serde_json::from_slice::<serde_json::Value>(&std::fs::read(file).unwrap())
                        .unwrap()
                }
            })
            .await
            .unwrap();
            assert_eq!(restored["result"]["unicode"], "完整");
            assert_eq!(
                restored["stdout"].as_str().unwrap().chars().count(),
                9 * 1024 * 1024
            );
            assert_eq!(restored["stderr"], "fixture script error");
            std::fs::remove_file(file).unwrap();
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.starts_with("IDA error: λ"));
            assert!(error.ends_with('λ'));
            assert!(error.len() > 16 * 1024 * 1024);
        }
        assert!(
            !connection.is_closed(),
            "legal large result/error cannot destroy the worker connection"
        );
    }
    connection.close();
    serving.await.unwrap().unwrap();
}
