//! F1 regression barriers cross the persistent Python bridge, both Unix lanes and N1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn released_waiter_retains_content_until_publication_syscall_returns() {
    ida_mcp::router::nexus_tools::n7_fix2_publish::released_waiter_retains_content_until_publication_syscall_returns().await;
}
use ida_mcp::{
    nexus::*,
    router::{
        nexus_bridge::{BridgeConfig, NexusBridge},
        RouterState,
    },
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
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
    pending: VecDeque<Value>,
    root: PathBuf,
    client: ClientId,
}
impl Rig {
    async fn new(scenario: &str) -> Self {
        let python = PathBuf::from(std::env::var_os("F1_PYTHON").expect(
            "F1_PYTHON is required for gate 13: prepare a fresh environment with timeout 180s python3 scripts/prepare_nexus_env.py --root <new-root> --ida-dir <IDA-MacOS> --eula-registry <test-ida.reg>, then set F1_PYTHON=<new-root>/venv/bin/python; see docs/TESTING.md"
        ));
        assert!(
            python.is_absolute() && python.is_file(),
            "F1_PYTHON must name the prepared environment's absolute venv/bin/python path"
        );
        let root = std::env::var_os("F1_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(id());
        std::fs::create_dir_all(&root).unwrap();
        let router = RouterState::new().unwrap();
        let mut environment = BTreeMap::new();
        environment.insert(
            "PATH".into(),
            std::env::var("PATH").expect("timeout executable search path"),
        );
        environment.insert("F1_ROOT".into(), root.to_string_lossy().into_owned());
        environment.insert("F1_SCENARIO".into(), scenario.into());
        if std::env::var_os("N4_F2_DELAY").is_some() {
            environment.insert("N4_F2_DELAY".into(), "1".into());
        }
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
            pending: VecDeque::new(),
            root,
            client: ClientId::new(id()).unwrap(),
        }
    }
    async fn event(&mut self, name: &str) -> Value {
        wait_event(
            &mut self.events,
            &mut self.pending,
            name,
            None,
            Duration::from_secs(if name == "opened" { 15 } else { 5 }),
        )
        .await
    }
    async fn operation_event(&mut self, name: &str, identity: &OperationIdentity) -> Value {
        wait_event(
            &mut self.events,
            &mut self.pending,
            name,
            Some(&identity.operation_id),
            Duration::from_secs(5),
        )
        .await
    }
    async fn marker(&self, name: &str) {
        tokio::time::timeout(Duration::from_secs(15), async {
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
    fn submit_open(&self) {
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
                        json!({"timeout_secs":20}),
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
    }
    async fn open(&mut self) -> SessionLease {
        self.submit_open();
        serde_json::from_value(self.event("opened").await["lease"].clone()).unwrap()
    }
    fn begin(&self, lease: &SessionLease, code: &str) -> OperationIdentity {
        self.begin_with_timeout(lease, code, 15)
    }
    fn begin_with_timeout(
        &self,
        lease: &SessionLease,
        code: &str,
        timeout: u64,
    ) -> OperationIdentity {
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
                        json!({"code":code,"timeout_secs":timeout}),
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
        let directory = self.root.join("ipc");
        drop(self);
        use std::os::unix::fs::FileTypeExt;
        for path in std::fs::read_dir(directory).expect("gate 13 IPC directory") {
            let path = path.expect("IPC entry").path();
            assert!(
                !path.symlink_metadata().unwrap().file_type().is_socket(),
                "gate 13 socket residue: {}",
                path.display()
            );
        }
    }
}

async fn early_open_disconnect(scenario: &str) {
    let mut r = Rig::new(scenario).await;
    let healthy = r.open().await;
    r.submit_open();
    r.event("disconnected").await;
    assert_eq!(
        r.bridge
            .endpoint()
            .transition(|s, _| s.status(&r.client, &healthy))
            .unwrap()
            .phase,
        SessionPhase::Active,
        "early open callback must not poison a sibling lease"
    );
    if scenario == "open-pre-disconnected" {
        r.marker("open-failed.arrived").await;
        r.release_marker("open-failed.release");
        r.event("failed").await;
    } else {
        r.marker("opened.arrived").await;
        r.release_marker("opened.release");
        let opened = r.event("opened").await;
        let lease: SessionLease = serde_json::from_value(opened["lease"].clone()).unwrap();
        assert_eq!(
            r.bridge
                .endpoint()
                .transition(|s, _| s.status(&r.client, &lease))
                .unwrap()
                .phase,
            SessionPhase::Disconnected,
            "buffered disconnect must apply atomically with opened"
        );
    }
    let op = r.begin(&healthy, "still-healthy");
    r.operation_event("completed", &op).await;
    assert_eq!(r.snapshot(&op).status, OperationStatus::Succeeded);
    r.close().await;
}

#[tokio::test]
async fn f2_open_disconnected_before_callback_registration_is_isolated() {
    early_open_disconnect("open-pre-disconnected").await;
}

#[tokio::test]
async fn f2_open_control_disconnect_arrives_before_business_opened_is_isolated() {
    early_open_disconnect("open-early-event").await;
}

#[tokio::test]
async fn f2_expired_proof_consumed_by_cancel_ack_and_supervisor() {
    let mut r = Rig::new("expired-proof").await;
    let lease = r.open().await;
    let op = r.begin_with_timeout(&lease, "unknown", 1);
    r.operation_event("uncertain", &op).await;
    r.cancel(&op);
    assert_eq!(r.operation_event("cancel_ack", &op).await["accepted"], true);
    r.event("stop_unconfirmed").await;
    // N1's actual deadline poll escalates the acknowledged client cancellation.
    let ack = r.operation_event("cancel_ack", &op).await;
    assert_eq!(ack["outcome"]["execution_stopped"], true);
    let at_ack = r.snapshot(&op);
    r.marker("stopped.arrived").await;
    r.release_marker("stopped.release");
    r.operation_event("stopped", &op).await;
    let cleanup = r.event("local_status").await;
    let after = r.snapshot(&op);
    r.close().await;
    assert!(
        at_ack.execution_stopped,
        "cancel_ack must consume authoritative proof before supervisor publication"
    );
    assert_eq!(after.status, OperationStatus::UnknownOutcome);
    assert!(after.execution_stopped);
    assert_eq!(
        cleanup["unknown_retained"], false,
        "expired supervisor must retire proven unknown"
    );
}
#[tokio::test]
async fn p12_ack_before_response_loss_still_schedules_stop_proof() {
    let mut r = Rig::new("ack-first").await;
    let l = r.open().await;
    let op = r.begin(&l, "unknown");
    r.operation_event("ack", &op).await;
    r.marker("failure.arrived").await;
    r.cancel(&op);
    r.operation_event("cancel_ack", &op).await;
    r.release_marker("failure.release");
    r.operation_event("uncertain", &op).await;
    r.operation_event("stopped", &op).await;
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
    r.operation_event("ack", &op).await;
    r.marker("uncertain.arrived").await;
    r.cancel(&op);
    r.operation_event("cancel_ack", &op).await;
    r.operation_event("stopped", &op).await;
    let before = r.snapshot(&op);
    r.release_marker("uncertain.release");
    r.operation_event("uncertain", &op).await;
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
    r.operation_event("ack", &op).await;
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
    r.operation_event("completed", &op).await;
    assert_eq!(sa.phase, SessionPhase::Disconnected);
    assert_eq!(sb.phase, SessionPhase::Active);
    assert_eq!(r.snapshot(&op).status, OperationStatus::Succeeded);
    r.close().await;
}
// A failed event wait must return the two occupied Control slots as well.
#[derive(Clone)]
struct ControlRelease {
    barrier: Arc<std::sync::Barrier>,
    released: Arc<std::sync::atomic::AtomicBool>,
}
impl ControlRelease {
    fn new() -> Self {
        Self {
            barrier: Arc::new(std::sync::Barrier::new(3)),
            released: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    fn release(&self) {
        if !self.released.swap(true, Ordering::SeqCst) {
            self.barrier.wait();
        }
    }
}
struct ControlReleaseGuard(ControlRelease);
impl Drop for ControlReleaseGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test]
async fn p25_failed_event_wait_releases_control_slots() {
    let release = ControlRelease::new();
    let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
    let mut jobs = Vec::new();
    for _ in 0..2 {
        let started = started.clone();
        let barrier = release.barrier.clone();
        jobs.push(tokio::spawn(ida_mcp::blocking::run(
            ida_mcp::blocking::WorkClass::Control,
            move || {
                started.send(()).unwrap();
                barrier.wait();
            },
        )));
    }
    for _ in 0..2 {
        starts.recv().await.unwrap();
    }
    let guarded = release.clone();
    let failed = tokio::spawn(async move {
        let _guard = ControlReleaseGuard(guarded);
        let (sender, mut events) = broadcast::channel(1);
        drop(sender); // Deterministically fail the same unified event helper.
        wait_event(
            &mut events,
            &mut VecDeque::new(),
            "local_status",
            None,
            Duration::from_secs(5),
        )
        .await;
    })
    .await;
    let released_on_failure = release.released.load(Ordering::SeqCst);
    // Test-only rescue lets the red regression exit without stranding workers.
    release.release();
    for job in jobs {
        job.await.unwrap().unwrap();
    }
    assert!(
        failed.unwrap_err().is_panic(),
        "inject event stream disconnection"
    );
    assert!(
        released_on_failure,
        "failed event wait stranded both Control permits"
    );
    ida_mcp::blocking::run(ida_mcp::blocking::WorkClass::Control, || ())
        .await
        .unwrap();
}
#[tokio::test]
async fn p25_cli_control_saturation_cannot_disconnect_bridge() {
    let mut r = Rig::new("control").await;
    let l = r.open().await;
    let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
    let release = ControlRelease::new();
    let mut jobs = Vec::new();
    for _ in 0..2 {
        let started = started.clone();
        let release = release.barrier.clone();
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
    let guard = ControlReleaseGuard(release.clone());
    r.bridge.status("while-cli-full").await.unwrap();
    let event = r.event("local_status").await;
    release.release();
    drop(guard);
    for job in jobs {
        job.await.unwrap().unwrap();
    }
    assert_eq!(
        event["event"], "local_status",
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
    r.operation_event("uncertain", &op).await;
    if scenario == "late-success" {
        if std::env::var_os("N4_F2_DELAY").is_some() {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        r.release_marker("start-success");
        r.marker("success.arrived").await;
    }
    if scenario == "stale-false" {
        r.release_marker("old-start");
        r.marker("old-false.arrived").await;
    }
    r.cancel(&op);
    r.operation_event("cancel_ack", &op).await;
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
    r.operation_event("stopped", &op).await;
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
    r.operation_event("uncertain", &op).await;
    r.release_marker("active-check");
    let verdict = r.event("local_status").await;
    r.cancel(&op);
    let ack = r.operation_event("cancel_ack", &op).await;
    r.operation_event("stopped", &op).await;
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

async fn wait_event(
    events: &mut broadcast::Receiver<Value>,
    pending: &mut VecDeque<Value>,
    name: &str,
    operation: Option<&OperationId>,
    budget: Duration,
) -> Value {
    let matches = |event: &Value| {
        event["event"] == name
            && operation.is_none_or(|id| {
                event["attempt"]["target"]["identity"]["operation_id"] == id.as_str()
            })
    };
    if let Some(index) = pending.iter().position(matches) {
        return pending.remove(index).unwrap();
    }
    tokio::time::timeout(budget, async {
        loop {
            let event = events.recv().await.unwrap();
            if matches(&event) {
                return event;
            }
            assert_ne!(event["event"], "bridge_disconnected", "{event}");
            pending.push_back(event);
        }
    })
    .await
    .expect("cross-channel event barrier")
}

#[tokio::test]
async fn n4_fix_event_helper_preserves_out_of_order_events() {
    for order in [["stopped", "uncertain"], ["uncertain", "stopped"]] {
        let (sender, mut events) = broadcast::channel(8);
        let mut pending = VecDeque::new();
        for name in order {
            sender.send(json!({"event":name})).unwrap();
        }
        assert_eq!(
            wait_event(
                &mut events,
                &mut pending,
                "uncertain",
                None,
                Duration::from_secs(1)
            )
            .await["event"],
            "uncertain"
        );
        assert_eq!(
            wait_event(
                &mut events,
                &mut pending,
                "stopped",
                None,
                Duration::from_secs(1)
            )
            .await["event"],
            "stopped"
        );
    }
}

#[tokio::test]
async fn n4_fix_event_helper_does_not_match_a_previous_operations_ack() {
    let (sender, mut events) = broadcast::channel(8);
    let mut pending = VecDeque::new();
    let first = OperationId::new("old-open").unwrap();
    let second = OperationId::new("current-execute").unwrap();
    for id in [&first, &second] {
        sender
            .send(json!({"event":"ack","attempt":{"target":{"identity":{"operation_id":id}}}}))
            .unwrap();
    }
    let current = wait_event(
        &mut events,
        &mut pending,
        "ack",
        Some(&second),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(
        current["attempt"]["target"]["identity"]["operation_id"],
        second.as_str()
    );
    let old = wait_event(
        &mut events,
        &mut pending,
        "ack",
        Some(&first),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(
        old["attempt"]["target"]["identity"]["operation_id"],
        first.as_str()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n5_f2_startup_cancellation_reaps_child_and_sockets() {
    use std::os::unix::fs::FileTypeExt;
    let base = PathBuf::from(std::env::var_os("F1_ROOT").expect("private short IPC root"));
    let python = PathBuf::from(std::env::var_os("F1_PYTHON").expect("prepared Python"));
    let mut residues = Vec::new();
    for mode in ["drop", "cancel", "deadline"] {
        for stage in ["spawn", "ready", "lifetime", "business"] {
            let root = base.join(id());
            std::fs::create_dir_all(&root).unwrap();
            let router = RouterState::new().unwrap();
            let cfg = BridgeConfig {
                python: python.clone(),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/nexus_race_fixture.py"),
                directory: root.join("ipc"),
                environment: BTreeMap::from([
                    ("PATH".into(), std::env::var("PATH").unwrap()),
                    ("F1_ROOT".into(), root.to_string_lossy().into_owned()),
                    ("F1_SCENARIO".into(), format!("startup-{stage}")),
                    ("IDA_CLI_HOME".into(), root.to_string_lossy().into_owned()),
                    (
                        "IDA_NEXUS_STATE_DIR".into(),
                        root.join("state").to_string_lossy().into_owned(),
                    ),
                ]),
            };
            let preparation = ida_mcp::preprocess::Preparation::new(Duration::from_secs(15));
            let cancel = preparation.cancel.clone();
            let (expire, expired) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(async move {
                let mut preparation = preparation;
                let mut start = Box::pin(NexusBridge::start(&router, cfg));
                if mode == "deadline" {
                    tokio::select! {
                        _ = &mut start => panic!("startup barrier released unexpectedly"),
                        _ = expired => preparation.deadline = std::time::Instant::now(),
                    }
                }
                preparation
                    .wait(async {
                        start
                            .await
                            .map_err(|e| ida_mcp::error::ToolError::IdaError(e.to_string()))
                    })
                    .await
            });
            tokio::time::timeout(Duration::from_secs(15), async {
                while !root.join("startup.arrived").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("deterministic startup phase barrier");
            let process: Value =
                serde_json::from_str(&std::fs::read_to_string(root.join("process.json")).unwrap())
                    .unwrap();
            let pid = i32::try_from(process["pid"].as_i64().unwrap()).unwrap();
            match mode {
                "drop" => {
                    task.abort();
                    assert!(matches!(task.await, Err(e) if e.is_cancelled()));
                }
                "cancel" => {
                    cancel.cancel();
                    assert!(task.await.unwrap().is_err());
                }
                _ => {
                    expire.send(()).unwrap();
                    assert!(task.await.unwrap().is_err());
                }
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                while unsafe { libc::kill(pid, 0) } == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("own startup child must be reaped");
            // Bounded cleanup completion, independent of child/runtime scheduling.
            let clean = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    let sockets: Vec<_> = std::fs::read_dir(root.join("ipc"))
                        .unwrap()
                        .map(|e| e.unwrap().path())
                        .filter(|p| match p.symlink_metadata() {
                            Ok(metadata) => metadata.file_type().is_socket(),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                            Err(error) => panic!("inspect owned startup socket: {error}"),
                        })
                        .collect();
                    if sockets.is_empty() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .is_ok();
            if !clean {
                residues.push(format!("{mode}/{stage}"));
                // Red-run cleanup is restricted to this test's fresh exact paths.
                for name in ["b", "c", "l"] {
                    let path = root.join("ipc").join(name);
                    if path.exists() {
                        std::fs::remove_file(path).unwrap();
                    }
                }
            }
        }
    }
    assert!(residues.is_empty(), "startup socket residues: {residues:?}");
}
