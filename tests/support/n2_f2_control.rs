use ida_mcp::nexus::*;
use ida_mcp::router::nexus_transport::{NexusEndpoint, NexusLanes};
use serde_json::json;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::AsyncWrite;

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

struct ReadyWriter {
    ready: Arc<AtomicBool>,
    bytes: Arc<Mutex<Vec<u8>>>,
    prefix: usize,
    entered: Option<Arc<AtomicBool>>,
}
impl AsyncWrite for ReadyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(entered) = &self.entered {
            entered.store(true, Ordering::SeqCst);
        }
        if self.prefix > 0 {
            let length = self.prefix.min(bytes.len());
            self.prefix = 0;
            self.bytes
                .lock()
                .unwrap()
                .extend_from_slice(&bytes[..length]);
            return Poll::Ready(Ok(length));
        }
        if !self.ready.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
async fn expired_control(kind: &str, prefix: usize) {
    let endpoint = NexusEndpoint::with_capabilities(8, Ok(caps()));
    let mut lanes = endpoint.take_lanes().unwrap();
    let lease = open(&endpoint, &mut lanes).await;
    let accepted_at = Instant::now();
    match kind {
        "cancel" => {
            let request = AcceptedRequest::new(
                &SystemClock,
                RequestId::new("live-r").unwrap(),
                None,
                "fixture",
                json!({"timeout_secs":120}),
            )
            .unwrap();
            let identity = endpoint
                .transition(|s, _| {
                    s.queue(
                        &lease.client_id,
                        &lease,
                        request,
                        OperationId::new("live-o").unwrap(),
                    )
                })
                .unwrap();
            endpoint
                .transition(|s, b| s.dispatch(&lease.client_id, &identity, b))
                .unwrap();
            let mut execution = lanes.business.recv().await.unwrap();
            execution.begin().unwrap();
            execution.acknowledged().unwrap();
            endpoint
                .transition(|s, b| s.cancel(&lease.client_id, &identity, CancelReason::Client, b))
                .unwrap();
        }
        "release" => endpoint
            .transition(|s, b| s.release(&lease.client_id, &lease, b))
            .unwrap(),
        "shutdown" => {
            let request = AcceptedRequest::new(
                &SystemClock,
                RequestId::new("shutdown-r").unwrap(),
                None,
                "shutdown",
                json!({"timeout_secs":2}),
            )
            .unwrap();
            endpoint
                .transition(|s, b| {
                    s.shutdown(
                        &lease.client_id,
                        &lease,
                        ShutdownSpec {
                            request,
                            operation_id: OperationId::new("shutdown-o").unwrap(),
                            save: false,
                        },
                        b,
                    )
                })
                .unwrap();
        }
        _ => panic!("unexpected control {kind}"),
    }
    let delivery = lanes.control.recv().await.unwrap();
    let attempt = delivery.attempt.clone();
    let ready = Arc::new(AtomicBool::new(false));
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let mut writer = ReadyWriter {
        ready: ready.clone(),
        bytes: bytes.clone(),
        prefix,
        entered: None,
    };
    let mut writing = Box::pin(delivery.write(&mut writer));
    let pending =
        std::future::poll_fn(|cx| Poll::Ready(matches!(writing.as_mut().poll(cx), Poll::Pending)))
            .await;
    // Deliberately cross the control frame's 2s deadline; not a guessed start barrier.
    tokio::time::sleep_until((accepted_at + Duration::from_millis(2100)).into()).await;
    ready.store(true, Ordering::SeqCst);
    let result = writing.await;
    let length = bytes.lock().unwrap().len();
    eprintln!(
        "initial_pending={pending}; expired_control_result={result:?}; bytes_written={length}"
    );
    assert!(pending);
    assert_eq!(
        length, prefix,
        "expired {kind} must not write any additional bytes"
    );
    let error = result.unwrap_err();
    assert_eq!(error.code, NexusErrorCode::QueueExpired);
    assert_eq!(error.retry_advice(), RetryAdvice::NewRequest);
    let snapshot = endpoint
        .transition(|s, _| s.delivery_status(&lease.client_id, &attempt))
        .unwrap();
    let recorded = snapshot.error.as_ref().unwrap();
    if prefix > 0 && kind != "cancel" {
        assert_eq!(recorded.code, NexusErrorCode::UnknownOutcome);
        assert_eq!(recorded.retry_advice(), RetryAdvice::NeverReplay);
        assert_eq!(
            recorded.cause.as_ref().unwrap().code,
            NexusErrorCode::QueueExpired
        );
    } else {
        assert_eq!(recorded.code, NexusErrorCode::QueueExpired);
        assert_eq!(recorded.retry_advice(), RetryAdvice::NewRequest);
    }
    let state = endpoint
        .transition(|s, _| s.delivery_status(&lease.client_id, &attempt))
        .unwrap()
        .state;
    assert_eq!(
        state,
        if prefix == 0 {
            DeliveryState::NotSent
        } else {
            DeliveryState::Uncertain
        }
    );
    if kind == "cancel" {
        let DeliveryTarget::Cancel { identity, .. } = attempt.target else {
            panic!("cancel identity")
        };
        let snapshot = endpoint
            .transition(|s, _| s.operation_status(&lease.client_id, &identity))
            .unwrap();
        assert!(
            !snapshot.execution_stopped,
            "control delivery failure is not native stop evidence"
        );
    }
}
#[tokio::test(flavor = "current_thread")]
async fn expired_cancel_frame_must_be_rejected_before_ready_writer_observes_bytes() {
    expired_control("cancel", 0).await;
}
#[tokio::test(flavor = "current_thread")]
async fn expired_release_and_shutdown_are_not_sent() {
    for kind in ["release", "shutdown"] {
        expired_control(kind, 0).await;
    }
}
#[tokio::test(flavor = "current_thread")]
async fn partial_control_frames_expire_uncertain_without_more_bytes() {
    for kind in ["cancel", "release", "shutdown"] {
        expired_control(kind, 3).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn lifecycle_rejection_after_pending_write_keeps_cancelled_code_and_no_bytes() {
    let endpoint = NexusEndpoint::with_capabilities(8, Ok(caps()));
    let mut lanes = endpoint.take_lanes().unwrap();
    let client = ClientId::new("cancel-opening-client").unwrap();
    let identity = endpoint
        .transition(|s, b| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("cancel-opening-r").unwrap(),
                    None,
                    "open",
                    json!({}),
                )
                .unwrap(),
                OpenSpec {
                    operation_id: OperationId::new("cancel-opening-o").unwrap(),
                    path: "/fixture.i64".into(),
                    options: json!({}),
                },
                b,
            )
        })
        .unwrap();
    let delivery = lanes.business.recv().await.unwrap();
    let attempt = delivery.attempt.clone();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let mut writer = ReadyWriter {
        ready: ready.clone(),
        bytes: bytes.clone(),
        prefix: 0,
        entered: Some(entered.clone()),
    };
    let mut writing = Box::pin(delivery.write(&mut writer));
    std::future::poll_fn(|cx| match writing.as_mut().poll(cx) {
        Poll::Pending if entered.load(Ordering::SeqCst) => Poll::Ready(()),
        Poll::Pending => Poll::Pending,
        Poll::Ready(result) => panic!("must reach actual pending writer poll: {result:?}"),
    })
    .await;
    endpoint
        .transition(|s, _| s.cancel_open(&client, &identity))
        .unwrap();
    ready.store(true, Ordering::SeqCst);
    let error = writing.await.unwrap_err();
    assert_eq!(error.code, NexusErrorCode::Cancelled);
    assert_eq!(error.retry_advice(), RetryAdvice::NeverReplay);
    assert!(bytes.lock().unwrap().is_empty());
    let status = endpoint
        .transition(|s, _| s.delivery_status(&client, &attempt))
        .unwrap();
    assert_eq!(status.state, DeliveryState::NotSent);
    assert_eq!(status.error.unwrap(), error);
}

struct BrokenWriter(bool);
impl AsyncWrite for BrokenWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(if self.0 {
            Ok(0)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "fixture",
            ))
        })
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test(flavor = "current_thread")]
async fn actual_io_error_and_zero_write_remain_disconnected_not_sent() {
    for zero in [false, true] {
        let endpoint = NexusEndpoint::with_capabilities(8, Ok(caps()));
        let mut lanes = endpoint.take_lanes().unwrap();
        let lease = open(&endpoint, &mut lanes).await;
        endpoint
            .transition(|s, b| s.release(&lease.client_id, &lease, b))
            .unwrap();
        let delivery = lanes.control.recv().await.unwrap();
        let attempt = delivery.attempt.clone();
        let error = delivery.write(&mut BrokenWriter(zero)).await.unwrap_err();
        assert_eq!(error.code, NexusErrorCode::Disconnected);
        assert_eq!(error.retry_advice(), RetryAdvice::ReconnectThenNewRequest);
        let status = endpoint
            .transition(|s, _| s.delivery_status(&lease.client_id, &attempt))
            .unwrap();
        assert_eq!(status.state, DeliveryState::NotSent);
        assert_eq!(status.error.unwrap(), error);
    }
}
