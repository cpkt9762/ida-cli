//! Bridge death inside the launch windows of a cold open (solre-fix H1).
//!
//! W2a: the helper and Rust both signed the launch intent, the SDK has not
//!      called Popen yet (`R3A_STARTUP_PHASE=LaunchIntent` barrier).
//! W2b: Popen returned a real IDA owner process, Spawned is not signed yet
//!      (`R3A_STARTUP_PHASE=PopenReturn` barrier).
//! Each case kills only its own private bridge and never signals the helper;
//! the only process this test ever signals is a worker whose command line
//! carries the private launch suffix recorded in the helper registry.
use super::super::RouterState;
use super::*;
use crate::preprocess::Preparation;
use tokio::sync::broadcast;

use crate::nexus;

#[allow(dead_code)] // Shared contract rig also exposes open/deadline helpers.
#[path = "nexus_contract.rs"]
mod continuation_contract;

const SETTLE_DEADLINE: Duration = Duration::from_secs(40);

struct Case {
    router: RouterState,
    bridge: Arc<NexusBridge>,
    root: PathBuf,
    opening: tokio::task::JoinHandle<()>,
    suffix: String,
    watch: String,
    sample: PathBuf,
}

fn live_workers(suffix: &str) -> Vec<u32> {
    let table = std::process::Command::new("/bin/ps")
        .args(["-axww", "-o", "pid=,command="])
        .output()
        .expect("process table");
    let needle = format!("--record-suffix {suffix}");
    String::from_utf8_lossy(&table.stdout)
        .lines()
        .filter(|line| line.contains(&needle))
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .collect()
}

fn registry(root: &std::path::Path) -> Value {
    serde_json::from_slice(
        &std::fs::read(root.join("ipc/helper-state.json")).expect("helper registry"),
    )
    .expect("helper registry JSON")
}

async fn case(phase: &str) -> Case {
    case_at_authorization(phase, "claimed").await
}

async fn case_at_authorization(phase: &str, authorization_phase: &str) -> Case {
    static IDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let root =
        PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private test root")).join(format!(
            "bridge-loss-{}-{}",
            std::process::id(),
            IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
    std::fs::create_dir(&root).expect("fresh private case");
    std::fs::create_dir(root.join("barrier")).expect("barrier root");
    let sample = root.join("sample");
    std::fs::copy(
        std::env::var_os("R2_REAL_INPUT").expect("private mini seed"),
        &sample,
    )
    .expect("sample copy");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_STARTUP_PHASE".into(), phase.into());
    environment.insert(
        "R3A_WORKER_AUTHORIZATION_PHASE".into(),
        authorization_phase.into(),
    );
    environment.insert("R5_ROOT".into(), root.join("barrier").display().to_string());
    let router = RouterState::new().expect("router");
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("F1_PYTHON").expect("prepared Python")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/nexus_client_fixture.py"),
            directory: root.join("ipc"),
            environment,
        })
        .await
        .expect("actual bridge and helper");
    let opening_router = router.clone();
    let opening_path = sample.display().to_string();
    let opening = tokio::spawn(async move {
        // The bridge is killed while this open is parked at the barrier; its
        // result is irrelevant, only the custody state it leaves behind is.
        let _ = opening_router
            .ensure_cli_worker_prepared(
                &opening_path,
                None,
                Preparation::new(Duration::from_secs(60)),
            )
            .await;
    });
    tokio::time::timeout(Duration::from_secs(40), async {
        while !root.join("barrier/startup.arrived").exists() {
            assert!(
                !opening.is_finished(),
                "open ended before the launch barrier"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("launch barrier reached");
    let saved = registry(&root);
    let (watch, item) = saved["items"]
        .as_object()
        .and_then(|items| items.iter().find(|(_, item)| item["launch"].is_object()))
        .map(|(watch, item)| (watch.clone(), item.clone()))
        .expect("helper signed launch intent");
    let suffix = item["launch"]["suffix"]
        .as_str()
        .expect("suffix")
        .to_owned();
    Case {
        router,
        bridge,
        root,
        opening,
        suffix,
        watch,
        sample,
    }
}

/// A helper that accepted `finish` proves it held no watch and no parent.
async fn helper_holdings(bridge: &NexusBridge) -> Value {
    let helper = bridge.state.helper.as_ref().expect("helper");
    if helper.is_finished() {
        return json!({"used":0,"parent_count":0,"finished":true});
    }
    helper
        .call(json!({"kind":"heartbeat","summary_only":true}))
        .await
        .expect("helper heartbeat")
}

/// The abandonment event carries the immutable fact's evidence.
async fn abandonment(events: &mut broadcast::Receiver<Value>) -> Option<Value> {
    loop {
        match events.try_recv() {
            Ok(event) if event["event"] == "launch_abandoned_unspawned" => return Some(event),
            Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(_) => return None,
        }
    }
}

impl Case {
    async fn kill_bridge(&self) {
        self.bridge
            .terminate()
            .await
            .expect("kill only the own bridge");
        tokio::time::timeout(Duration::from_secs(5), async {
            while self
                .bridge
                .state
                .bridge_exit
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("exact waitpid of the dead bridge");
    }

    async fn shutdown_ready(&self) -> (Result<(), crate::error::ToolError>, Duration) {
        let started = std::time::Instant::now();
        let result = self
            .bridge
            .wait_shutdown_ready(&Preparation::new(SETTLE_DEADLINE))
            .await;
        (result, started.elapsed())
    }

    /// What a CLI request gets from the daemon after the bridge was lost.
    async fn cli_request(&self) -> crate::error::ToolError {
        self.router
            .ensure_cli_worker_prepared(
                &self.sample.display().to_string(),
                None,
                Preparation::new(Duration::from_secs(20)),
            )
            .await
            .err()
            .expect("a lost bridge cannot open")
    }

    fn evidence(&self, name: &str, value: Value) {
        std::fs::write(
            self.root.join(name),
            serde_json::to_vec_pretty(&value).expect("encode evidence"),
        )
        .expect("write evidence");
    }

    /// Test hygiene only: whatever the product left, make the private helper
    /// and any worker of this case go away. The product relies on the 300s
    /// helper orphan expiry instead.
    async fn cleanup(self) {
        self.opening.abort();
        for pid in live_workers(&self.suffix) {
            let _ = std::process::Command::new("/bin/kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
        // Orphan helpers retain their obligations and expire on their own.
        drop(self.router);
    }
}

/// W2a: nothing was ever spawned. The daemon must be able to shut down without
/// waiting for the helper orphan expiry, and must say why in durable evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_loss_before_popen_settles_the_unspawned_launch() {
    let case = case("LaunchIntent").await;
    assert!(
        live_workers(&case.suffix).is_empty(),
        "W2a must not have a worker yet"
    );
    let mut events = case.bridge.subscribe();
    case.kill_bridge().await;
    let (result, elapsed) = case.shutdown_ready().await;
    let held = helper_holdings(&case.bridge).await;
    let settled = abandonment(&mut events).await;
    let saved = registry(&case.root);
    case.evidence(
        "w2a-result.json",
        json!({"result":format!("{result:?}"),"elapsed_ms":elapsed.as_millis() as u64,
            "held":held["used"],"registry":saved["items"]}),
    );
    let lifecycle = case.bridge.lifecycle_status();
    case.evidence("w2a-lifecycle.json", lifecycle.clone());
    let ok = result.is_ok();
    let used = held["used"].clone();
    let parents = held["parent_count"].clone();
    let workers = live_workers(&case.suffix);
    let watch = case.watch.clone();
    case.cleanup().await;
    assert!(
        ok,
        "shutdown must complete after bridge loss in W2a: {result:?} after {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(30), "bounded: {elapsed:?}");
    let settled = settled.expect("durable abandonment evidence is announced");
    assert_eq!(settled["evidence"]["decision"], json!("revoked"));
    assert!(settled["evidence"]["authorization"].as_str().is_some());
    assert_eq!(
        used,
        json!(0),
        "settled launch leaves no helper watch ({watch})"
    );
    assert_eq!(
        parents,
        json!(0),
        "settled launch leaves no parent reservation"
    );
    assert!(workers.is_empty(), "no worker may exist: {workers:?}");
}

/// W2b with the owner already gone before it ever published: same evidence
/// rule, and the process table shows no worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_loss_after_popen_with_dead_owner_settles_the_launch() {
    let case = case_at_authorization("PopenReturn", "unclaimed").await;
    let workers = live_workers(&case.suffix);
    assert_eq!(
        workers.len(),
        1,
        "W2b has a real owner process: {workers:?}"
    );
    let mut events = case.bridge.subscribe();
    case.kill_bridge().await;
    for pid in &workers {
        let status = std::process::Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .expect("kill the case-private worker");
        assert!(status.success());
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while !live_workers(&case.suffix).is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("worker gone");
    let (result, elapsed) = case.shutdown_ready().await;
    let held = helper_holdings(&case.bridge).await;
    let settled = abandonment(&mut events).await;
    case.evidence(
        "w2b-dead-result.json",
        json!({"result":format!("{result:?}"),"elapsed_ms":elapsed.as_millis() as u64,
            "held":held["used"]}),
    );
    let ok = result.is_ok();
    let used = held["used"].clone();
    case.cleanup().await;
    assert!(ok, "shutdown must complete once the unspawned owner is provably gone: {result:?} after {elapsed:?}");
    assert_eq!(used, json!(0));
    let settled = settled.expect("durable abandonment evidence is announced");
    assert_eq!(settled["evidence"]["decision"], json!("revoked"));
}

/// W2b with a live owner: the launch must never be settled as abandoned while
/// a worker with the launch suffix exists. The existing public-lifetime path
/// takes over, and shutdown becomes ready only after the orphan exited by its
/// own lease-grace rule. No signal is sent to the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_loss_after_popen_with_live_owner_waits_for_its_public_lifetime() {
    let case = case("PopenReturn").await;
    let workers = live_workers(&case.suffix);
    assert_eq!(
        workers.len(),
        1,
        "W2b has a real owner process: {workers:?}"
    );
    let mut events = case.bridge.subscribe();
    case.kill_bridge().await;
    let (result, elapsed) = case.shutdown_ready().await;
    let settled = abandonment(&mut events).await;
    let after = live_workers(&case.suffix);
    let saved = registry(&case.root);
    case.evidence(
        "w2b-live-result.json",
        json!({"result":format!("{result:?}"),"elapsed_ms":elapsed.as_millis() as u64,
            "workers_before":workers,"workers_after":after,"registry":saved["items"]}),
    );
    let ok = result.is_ok();
    case.cleanup().await;
    assert!(
        ok,
        "shutdown ready after the orphan owner exits: {result:?} after {elapsed:?}"
    );
    assert!(
        after.is_empty(),
        "no worker may outlive the settled launch: {after:?}"
    );
    assert!(
        settled.is_none(),
        "a launch with a live owner is never settled by absence: {settled:?}"
    );
    assert!(
        elapsed > Duration::from_secs(5),
        "a live owner must not be settled by absence evidence: {elapsed:?}"
    );
}

/// H2: the daemon leaves by itself once the lost bridge's custody allows it, and
/// until then every request gets the dedicated retry-once refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_exits_by_itself_after_bridge_loss_in_w2a() {
    let case = case("LaunchIntent").await;
    case.kill_bridge().await;
    case.router.arm_bridge_loss_exit();
    let refusal = case.cli_request().await;
    let typed = case.router.bridge_loss_not_dispatched(&refusal).is_some();
    // The actual router/socket response feeds the CLI retry path. Transport
    // Disconnected alone must not invite replay, even on this lost bridge.
    let generic = NexusError::new(NexusErrorCode::Disconnected, "transport NotSent").into();
    let generic_typed = case.router.bridge_loss_not_dispatched(&generic).is_some();
    let mut continuation_results = Vec::new();
    for failure in ["generation", "lease", "notsent"] {
        let mut rig = continuation_contract::Rig::new();
        let lease = rig.connect("continued", "owner", 1);
        let write = rig.queue(&lease, "write", "batch_rename", 120);
        rig.dispatch(&write);
        rig.sessions
            .yield_operation(&write, json!({"index":1}))
            .expect("completed first write slice");
        let error = match failure {
            "notsent" => {
                rig.backend.fail_business = Some(DispatchFailure::NotSent(NexusError::new(
                    NexusErrorCode::Disconnected,
                    "next slice not sent",
                )));
                rig.sessions
                    .dispatch(&lease.client_id, &write, &mut rig.backend)
                    .expect_err("next slice not sent")
            }
            _ => {
                if failure == "lease" {
                    rig.sessions.lease_disconnected(&lease).expect("lease loss");
                } else {
                    assert!(rig
                        .sessions
                        .disconnected(&lease.instance_id, lease.generation));
                }
                rig.snapshot(&write).error.expect("continuation error")
            }
        };
        let response =
            crate::server::socket_listener::failure_response(&case.router, "1", &error.into());
        let (code, requests) = crate::cli::test_bridge_loss_response_no_replay(response).await;
        continuation_results.push((failure, code, requests, rig.backend.writes));
    }

    let cancel = tokio_util::sync::CancellationToken::new();
    let watcher = {
        let router = case.router.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { router.exit_after_bridge_loss(cancel).await })
    };
    let started = std::time::Instant::now();
    let left = tokio::time::timeout(SETTLE_DEADLINE, cancel.cancelled()).await;
    let elapsed = started.elapsed();
    case.evidence(
        "h2-w2a-result.json",
        json!({"refusal":refusal.to_string(),"typed":typed,"left":left.is_ok(),
            "elapsed_ms":elapsed.as_millis() as u64}),
    );
    cancel.cancel();
    let _ = watcher.await;
    case.cleanup().await;
    assert!(
        !generic_typed,
        "generic Disconnected is never entrance refusal"
    );
    for (failure, code, requests, writes) in continuation_results {
        assert_eq!(code, -32000, "{failure}: no retry permission");
        assert_eq!(requests, 1, "{failure}: no CLI replay");
        assert_eq!(writes, 1, "{failure}: completed write not repeated");
    }
    assert!(
        typed,
        "a request refused before dispatch must carry the typed code: {refusal}"
    );
    assert!(
        left.is_ok(),
        "daemon must leave by itself after the launch is settled"
    );
}

/// H2 negative: while a live orphan owner keeps custody unsettled the daemon is
/// not forced out; it leaves only after that owner exited by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_waits_for_a_live_orphan_owner_before_leaving() {
    let case = case("PopenReturn").await;
    let workers = live_workers(&case.suffix);
    assert_eq!(
        workers.len(),
        1,
        "W2b has a real owner process: {workers:?}"
    );
    case.kill_bridge().await;
    case.router.arm_bridge_loss_exit();
    let cancel = tokio_util::sync::CancellationToken::new();
    let watcher = {
        let router = case.router.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { router.exit_after_bridge_loss(cancel).await })
    };
    tokio::time::sleep(Duration::from_secs(8)).await;
    let early = cancel.is_cancelled();
    let still_alive = live_workers(&case.suffix);
    let refusal = case.cli_request().await;
    let typed = case.router.bridge_loss_not_dispatched(&refusal).is_some();
    let started = std::time::Instant::now();
    let left = tokio::time::timeout(Duration::from_secs(60), cancel.cancelled()).await;
    let after = live_workers(&case.suffix);
    case.evidence(
        "h2-w2b-live-result.json",
        json!({"early":early,"still_alive":still_alive,"typed":typed,"left":left.is_ok(),
            "waited_more_ms":started.elapsed().as_millis() as u64,"workers_after":after}),
    );
    cancel.cancel();
    let _ = watcher.await;
    case.cleanup().await;
    assert!(
        !early,
        "daemon left while the orphan owner still held custody"
    );
    assert!(
        !still_alive.is_empty(),
        "the orphan owner is still alive at the check"
    );
    assert!(
        typed,
        "requests keep the typed refusal while waiting: {refusal}"
    );
    assert!(
        left.is_ok(),
        "daemon leaves once the owner exited by itself"
    );
    assert!(
        after.is_empty(),
        "no worker may outlive the daemon exit: {after:?}"
    );
}

/// A process that does not leave by itself (stdio `serve`) must not invite a
/// retry: its refusal stays an ordinary error that says how to restart it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unarmed_process_reports_the_loss_without_the_retry_code() {
    let case = case("LaunchIntent").await;
    case.kill_bridge().await;
    let refusal = case.cli_request().await;
    let typed = case.router.bridge_loss_not_dispatched(&refusal).is_some();
    let text = refusal.to_string();
    // Let the dead acquisition settle so its cache lock (process-wide under
    // IDA_CLI_HOME) is released before the next case in this process opens.
    let (settled, _) = case.shutdown_ready().await;
    case.cleanup().await;
    assert!(settled.is_ok(), "{settled:?}");
    assert!(!typed, "unarmed process tagged the retry code: {text}");
    assert!(
        text.contains("bridge disconnected") && text.contains("ida-cli shutdown"),
        "{text}"
    );
    assert!(text.contains("does not exit by itself"), "{text}");
}
