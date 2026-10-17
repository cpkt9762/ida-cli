//! Expected-red facts on the current product, using its actual Tools/N1/bridge.
//! Assertions keep the ordinary target green while recording the unfixed defects.
use ida_mcp::{
    nexus::*,
    preprocess::Preparation,
    router::{RouterState, nexus_bridge::BridgeConfig, nexus_bridge::NexusBridge},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::broadcast;

struct Rig {
    router: RouterState,
    bridge: Arc<NexusBridge>,
    root: PathBuf,
    events: broadcast::Receiver<Value>,
    evidence: Vec<Value>,
}

impl Rig {
    async fn new(scenario: &str) -> Self {
        let root = PathBuf::from(std::env::var_os("R0_CASE_ROOT").expect("private R0 root"))
            .join(scenario);
        std::fs::create_dir_all(&root).expect("create private case");
        let router = RouterState::new().expect("create real RouterState");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R0_CASE_ROOT".into(), root.display().to_string());
        environment.insert("R0_SCENARIO".into(), scenario.into());
        environment.insert("HOME".into(), root.join("home").display().to_string());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(
                    std::env::var_os("R0_PYTHON").expect("fixed prepared SDK Python"),
                ),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r0_bridge_fixture.py"),
                directory: root.join("ipc"),
                environment,
            })
            .await
            .expect("production bridge starts with unchanged pinned SDK");
        let events = bridge.subscribe();
        Self {
            router,
            bridge,
            root,
            events,
            evidence: Vec::new(),
        }
    }
    fn signal(&self, name: &str) {
        std::fs::write(self.root.join(name), b"").expect("release exact private barrier");
    }
    async fn marker(&self, name: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !self.root.join(name).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("owned HTTP boundary marker");
    }
    async fn event(&mut self, name: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = self.events.recv().await.expect("real bridge event");
                self.evidence.push(event.clone());
                if event["event"] == name {
                    return event;
                }
            }
        })
        .await
        .expect("expected production event");
        self.evidence.last().expect("event recorded").clone()
    }
    async fn n1_open(&mut self, client: &ClientId, operation: &str) -> SessionLease {
        self.n1_submit(client, operation, json!({"spawn":false}));
        serde_json::from_value(self.event("opened").await["lease"].clone()).expect("public lease")
    }
    fn n1_submit(&self, client: &ClientId, operation: &str, options: Value) {
        self.bridge
            .endpoint()
            .transition(|s, t| {
                s.open(
                    client,
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new(operation).expect("request id"),
                        None,
                        "open",
                        json!({"timeout_secs":10}),
                    )
                    .expect("accepted request"),
                    OpenSpec {
                        operation_id: OperationId::new(operation).expect("operation id"),
                        path: self.root.join("tiny.i64").display().to_string(),
                        options,
                    },
                    t,
                )
            })
            .expect("N1 real open");
    }
    async fn finish(self, fact: Value) {
        self.signal("owner-release");
        self.marker("owner-released").await;
        let owner_proof: Value = serde_json::from_slice(
            &std::fs::read(self.root.join("owner-proof.json")).expect("public SDK lifetime probe"),
        )
        .expect("public proof JSON");
        assert_eq!(owner_proof["public_lifetime_released"], true);
        let shutdown = self.bridge.shutdown().await;
        // F2 intentionally has a disconnected bridge; record its cleanup result.
        let path = self.root.join("rust-result.json");
        let value = json!({"scope":"current-product-expected-red", "fact":fact,
            "events":self.evidence,"public_owner_proof":owner_proof,"shutdown":format!("{shutdown:?}")});
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&value).expect("encode evidence"),
        )
        .expect("write evidence");
        let pid: Value = serde_json::from_slice(
            &std::fs::read(self.root.join("process.json")).expect("owned process record"),
        )
        .expect("process identity JSON");
        let pid = i32::try_from(pid["pid"].as_i64().expect("PID integer")).expect("native PID");
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "own bridge must be reaped"
        );
        let root = self.root.clone();
        drop(self); // N1 owns the business/control listeners until RouterState drops.
        use std::os::unix::fs::FileTypeExt;
        for entry in std::fs::read_dir(root.join("ipc")).expect("IPC directory") {
            assert!(
                !entry
                    .expect("IPC entry")
                    .file_type()
                    .expect("IPC type")
                    .is_socket(),
                "socket residue"
            );
        }
        assert!(
            root.join("fixture-audit.json").is_file(),
            "fixture finally must complete"
        );
        assert!(
            !std::fs::read_dir(root.join("state/instances"))
                .expect("private registry")
                .any(|entry| entry
                    .expect("registry entry")
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "json")),
            "registration residue"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_product_red_baselines() {
    let mut slow = Rig::new("slow-owner").await;
    let path = slow.root.join("tiny.i64");
    let (_, token) = slow
        .router
        .ensure_worker_prepared(
            path.to_str().expect("UTF8 path"),
            None,
            None,
            Preparation::new(Duration::from_secs(10)),
        )
        .await
        .expect("real Tools open");
    let close = slow.router.nexus_close_token(&token).await;
    assert!(
        close.is_err(),
        "F1: fixed product would close after owner proof"
    );
    slow.event("release_unconfirmed").await;
    slow.signal("owner-release");
    slow.marker("owner-released").await;
    let reopen = slow
        .router
        .ensure_worker_prepared(
            path.to_str().expect("UTF8 path"),
            None,
            None,
            Preparation::new(Duration::from_secs(5)),
        )
        .await;
    assert!(
        reopen.is_err(),
        "F1 current Tools still blocks after actual public lifetime released"
    );
    slow.finish(json!({"id":"F1", "close":format!("{close:?}"),
        "reopen_after_public_lifetime":format!("{reopen:?}")}))
        .await;

    let mut early = Rig::new("early-analysis").await;
    early.n1_submit(
        &ClientId::new("r0-early").expect("client"),
        "open-early",
        json!({"spawn":false,"wait_analysis":true}),
    );
    let open = early.event("remote_error").await;
    assert_eq!(
        open["remote_code"], "execution_error",
        "F4 cleanup fails before public acquisition delivery"
    );
    assert!(
        open.get("lease").is_none(),
        "no acquired lease delivered to N1"
    );
    let identity: OpenIdentity =
        serde_json::from_value(open["attempt"]["target"]["identity"].clone())
            .expect("actual N1 open identity");
    let progress = early
        .bridge
        .endpoint()
        .transition(|state, _| state.open_progress(&identity.client_id, &identity))
        .expect("query actual N1 open outcome");
    assert!(
        progress.0.is_none() && progress.1.is_some(),
        "N1 records failure without acquisition"
    );
    early.signal("snapshot-request");
    early.marker("snapshot.json").await;
    let snapshot: Value = serde_json::from_slice(
        &std::fs::read(early.root.join("snapshot.json")).expect("transport snapshot"),
    )
    .expect("snapshot JSON");
    assert_eq!(
        snapshot["physical_leases"], 1,
        "F4 real acquired lease remains at server boundary"
    );
    assert_eq!(
        snapshot["release_requests"], 0,
        "failed cleanup cannot invent a release"
    );
    early
        .finish(json!({"id":"F4", "caller":open,"n1_outcome":format!("{progress:?}"),"external_input":snapshot}))
        .await;

    let mut group = Rig::new("lost-ack").await;
    let a = ClientId::new("r0-a").expect("client A");
    let b = ClientId::new("r0-b").expect("client B");
    let lease_a = group.n1_open(&a, "open-a").await;
    let lease_b = group.n1_open(&b, "open-b").await;
    group.signal("disconnect-primary");
    group.event("disconnected").await;
    group
        .bridge
        .endpoint()
        .transition(|s, t| s.release(&a, &lease_a, t))
        .expect("real N1 release");
    group.event("release_unconfirmed").await;
    group.event("bridge_disconnected").await;
    let status = group
        .bridge
        .endpoint()
        .transition(|s, _| s.status(&b, &lease_b))
        .expect("B status");
    assert_eq!(
        status.phase,
        SessionPhase::Disconnected,
        "F2 unrelated B still loses bridge"
    );
    group
        .finish(json!({"id":"F2", "unrelated_b":format!("{:?}",status.phase)}))
        .await;
}
