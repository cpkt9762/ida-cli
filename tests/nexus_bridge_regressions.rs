//! F1 regression barriers cross the persistent Python bridge, both Unix lanes and N1.
use ida_mcp::{
    nexus::*,
    router::{
        nexus_bridge::{BridgeConfig, NexusBridge},
        RouterState,
    },
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::broadcast;
static IDS: AtomicU64 = AtomicU64::new(1);
fn id() -> String {
    format!(
        "f1-{}-{}",
        std::process::id(),
        IDS.fetch_add(1, Ordering::Relaxed)
    )
}
struct Rig {
    _router: RouterState,
    bridge: Arc<NexusBridge>,
    events: broadcast::Receiver<Value>,
    root: PathBuf,
    client: ClientId,
}
impl Rig {
    async fn new(scenario: &str) -> Self {
        let root = PathBuf::from(std::env::var_os("F1_ROOT").expect("isolated F1_ROOT")).join(id());
        std::fs::create_dir_all(&root).unwrap();
        let router = RouterState::new().unwrap();
        let python =
            PathBuf::from(std::env::var_os("F1_PYTHON").expect("fresh environment Python"));
        let mut environment = BTreeMap::new();
        environment.insert(
            "PATH".into(),
            std::env::var("PATH").expect("timeout executable search path"),
        );
        environment.insert("F1_ROOT".into(), root.to_string_lossy().into_owned());
        environment.insert("F1_SCENARIO".into(), scenario.into());
        if let Ok(directory) = std::env::var("F1_BRIDGE_DIR") {
            environment.insert("F1_BRIDGE_DIR".into(), directory);
        }
        environment.insert("IDA_CLI_HOME".into(), root.to_string_lossy().into_owned());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").to_string_lossy().into_owned(),
        );
        let bridge = router
            .connect_nexus(BridgeConfig {
                python,
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/nexus_race_fixture.py"),
                directory: root.join("ipc"),
                environment,
            })
            .await
            .unwrap();
        let events = bridge.subscribe();
        Self {
            _router: router,
            bridge,
            events,
            root,
            client: ClientId::new(id()).unwrap(),
        }
    }
    async fn event(&mut self, name: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let e = self.events.recv().await.unwrap();
                if e["event"] == name {
                    return e;
                }
                assert_ne!(e["event"], "bridge_disconnected", "{e}");
            }
        })
        .await
        .expect("cross-channel event barrier")
    }
    async fn marker(&self, name: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut poll = tokio::time::interval(Duration::from_millis(5));
            while !self.root.join(name).exists() {
                poll.tick().await;
            }
        })
        .await
        .expect("Python transport barrier");
    }
    fn release_marker(&self, name: &str) {
        std::fs::write(self.root.join(name), b"").unwrap();
    }
    async fn open(&mut self) -> SessionLease {
        self.bridge
            .endpoint()
            .transition(|s, t| {
                s.open(
                    &self.client,
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new(id()).unwrap(),
                        None,
                        "open",
                        json!({"timeout_secs":8}),
                    )
                    .unwrap(),
                    OpenSpec {
                        operation_id: OperationId::new(id()).unwrap(),
                        path: "fixture".into(),
                        options: json!({}),
                    },
                    t,
                )
            })
            .unwrap();
        serde_json::from_value(self.event("opened").await["lease"].clone()).unwrap()
    }
    fn begin(&self, lease: &SessionLease, code: &str) -> OperationIdentity {
        self.bridge
            .endpoint()
            .transition(|s, t| {
                let op = s.queue(
                    &self.client,
                    lease,
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new(id()).unwrap(),
                        None,
                        "execute_python",
                        json!({"code":code,"timeout_secs":8}),
                    )
                    .unwrap(),
                    OperationId::new(id()).unwrap(),
                )?;
                s.dispatch(&self.client, &op, t)?;
                Ok::<_, NexusError>(op)
            })
            .unwrap()
    }
    fn cancel(&self, op: &OperationIdentity) {
        self.bridge
            .endpoint()
            .transition(|s, t| s.cancel(&self.client, op, CancelReason::Client, t))
            .unwrap();
    }
    fn snapshot(&self, op: &OperationIdentity) -> OperationSnapshot {
        self.bridge
            .endpoint()
            .transition(|s, _| s.operation_status(&self.client, op))
            .unwrap()
    }
    async fn close(self) {
        self.bridge.shutdown().await.unwrap();
    }
}
#[tokio::test]
async fn p12_ack_before_response_loss_still_schedules_stop_proof() {
    let mut r = Rig::new("ack-first").await;
    let l = r.open().await;
    let op = r.begin(&l, "unknown");
    r.event("ack").await;
    r.marker("failure.arrived").await;
    r.cancel(&op);
    r.event("cancel_ack").await;
    r.release_marker("failure.release");
    r.event("uncertain").await;
    r.event("stopped").await;
    let s = r.snapshot(&op);
    assert_eq!(s.status, OperationStatus::UnknownOutcome);
    assert!(s.execution_stopped);
    r.close().await;
}
#[tokio::test]
async fn p13_control_proof_before_business_uncertain_never_becomes_success() {
    let mut r = Rig::new("early-proof").await;
    let l = r.open().await;
    let op = r.begin(&l, "unknown");
    r.event("ack").await;
    r.marker("uncertain.arrived").await;
    r.cancel(&op);
    r.event("cancel_ack").await;
    r.event("stopped").await;
    let before = r.snapshot(&op);
    r.release_marker("uncertain.release");
    r.event("uncertain").await;
    let after = r.snapshot(&op);
    assert_ne!(before.status, OperationStatus::Succeeded);
    assert_eq!(after.status, OperationStatus::UnknownOutcome);
    assert!(after.execution_stopped);
    r.bridge.status("alive").await.unwrap();
    r.event("local_status").await;
    r.close().await;
}
#[tokio::test]
async fn p14_one_lease_sse_loss_preserves_other_lease_and_active_operation() {
    let mut r = Rig::new("lease").await;
    let a = r.open().await;
    let b = r.open().await;
    let op = r.begin(&b, "block");
    r.event("ack").await;
    r.marker("business.arrived").await;
    r.release_marker("disconnect-first");
    r.event("disconnected").await;
    let (sa, sb) = r.bridge.endpoint().transition(|s, _| {
        (
            s.status(&r.client, &a).unwrap(),
            s.status(&r.client, &b).unwrap(),
        )
    });
    r.release_marker("business.release");
    r.event("completed").await;
    assert_eq!(sa.phase, SessionPhase::Disconnected);
    assert_eq!(sb.phase, SessionPhase::Active);
    assert_eq!(r.snapshot(&op).status, OperationStatus::Succeeded);
    r.close().await;
}
#[tokio::test]
async fn p25_cli_control_saturation_cannot_disconnect_bridge() {
    let mut r = Rig::new("control").await;
    let l = r.open().await;
    let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(std::sync::Barrier::new(3));
    let mut jobs = Vec::new();
    for _ in 0..2 {
        let started = started.clone();
        let release = release.clone();
        jobs.push(tokio::spawn(ida_mcp::blocking::run(
            ida_mcp::blocking::WorkClass::Control,
            move || {
                started.send(()).unwrap();
                release.wait();
            },
        )));
    }
    for _ in 0..2 {
        starts.recv().await.unwrap();
    }
    r.bridge.status("while-cli-full").await.unwrap();
    let event = tokio::time::timeout(Duration::from_secs(1), r.events.recv()).await;
    release.wait();
    for job in jobs {
        job.await.unwrap().unwrap();
    }
    assert_eq!(
        event.unwrap().unwrap()["event"],
        "local_status",
        "decode backpressure must preserve bridge"
    );
    assert_eq!(
        r.bridge
            .endpoint()
            .transition(|s, _| s.status(&r.client, &l))
            .unwrap()
            .phase,
        SessionPhase::Active
    );
    r.close().await;
}

// These client transport barriers keep U pending while earlier responses arrive.
// The verdict is observed on the real control socket; N1 still owns U throughout.
async fn causal_ordering(scenario: &str) {
    let mut r = Rig::new(scenario).await;
    let l = r.open().await;
    let op = r.begin(&l, "unknown");
    r.event("uncertain").await;
    if scenario == "late-success" {
        r.release_marker("start-success");
        r.marker("success.arrived").await;
    }
    if scenario == "stale-false" {
        r.release_marker("old-start");
        r.marker("old-false.arrived").await;
    }
    r.cancel(&op);
    r.event("cancel_ack").await;
    assert!(!r.snapshot(&op).execution_stopped);
    r.release_marker(if scenario == "late-success" {
        "success.release"
    } else {
        "old-false.release"
    });
    let verdict = r.event("local_status").await;
    let retained = verdict["retained"] == true;
    let before = r.snapshot(&op);
    r.marker("proof.arrived").await;
    r.release_marker("proof.release");
    r.event("stopped").await;
    let after = r.snapshot(&op);
    r.close().await;
    assert!(
        retained,
        "an earlier response must not retire the exact unknown identity: {verdict}"
    );
    assert_eq!(before.status, OperationStatus::UnknownOutcome);
    assert!(!before.execution_stopped);
    assert_eq!(after.status, OperationStatus::UnknownOutcome);
    assert!(after.execution_stopped);
}
#[tokio::test]
async fn p11_delayed_success_through_both_lanes_retains_unknown() {
    causal_ordering("late-success").await;
}
#[tokio::test]
async fn p11_false_issued_before_ack_through_both_lanes_retains_unknown() {
    causal_ordering("stale-false").await;
}
#[tokio::test]
async fn p26_stale_unknown_cannot_block_active_cancel_and_bridge_uses_exact_id() {
    let mut r = Rig::new("active-fairness").await;
    let l = r.open().await;
    let op = r.begin(&l, "unknown");
    r.event("uncertain").await;
    r.release_marker("active-check");
    let verdict = r.event("local_status").await;
    r.cancel(&op);
    let ack = r.event("cancel_ack").await;
    r.event("stopped").await;
    let snapshot = r.snapshot(&op);
    r.close().await;
    assert_eq!(
        verdict["accepted"], false,
        "active-only API must not choose an unknown identity"
    );
    assert_eq!(
        verdict["cancelled_ids"],
        json!([]),
        "stale unknown must never monopolize cancel_active: {verdict}"
    );
    assert_eq!(
        ack["attempt"]["target"]["identity"]["operation_id"],
        op.operation_id.as_str()
    );
    assert_eq!(
        ack["accepted"], true,
        "bridge must cancel the exact newer unknown"
    );
    assert_eq!(snapshot.status, OperationStatus::UnknownOutcome);
    assert!(snapshot.execution_stopped);
}
