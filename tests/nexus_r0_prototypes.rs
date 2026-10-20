//! R0 historical F1/F4 expected-red facts and R5 production F2 isolation.
use ida_mcp::{
    nexus::*,
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, nexus_bridge::NexusBridge, RouterState},
};
use serde_json::{json, Value};
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
        .unwrap_or_else(|error| panic!("expected {name}: {error}; events={:?}", self.evidence));
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
        let _ = std::fs::remove_file(self.root.join("owner-released"));
        self.signal("owner-release");
        self.marker("owner-released").await;
        let owner_proof: Value = serde_json::from_slice(
            &std::fs::read(self.root.join("owner-proof.json")).expect("public SDK lifetime probe"),
        )
        .expect("public proof JSON");
        assert_eq!(owner_proof["public_lifetime_released"], true);
        let shutdown = self.bridge.shutdown().await;
        // Preserve cleanup evidence for both historical red and R5 fixed scenarios.
        let path = self.root.join("rust-result.json");
        let value = json!({"scope":if fact["id"] == "F2" {"R5-production-isolation"} else {"current-product-lifecycle-regression"}, "fact":fact,
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
async fn current_product_lifecycle_regressions() {
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
        close.is_ok(),
        "F1: parsed detach ACK must close the client reference"
    );
    slow.event("released").await;
    slow.signal("owner-release");
    slow.marker("owner-released").await;
    slow.signal("owner-reopen");
    slow.marker("owner-reopened").await;
    let reopen = slow
        .router
        .ensure_worker_prepared(
            path.to_str().expect("UTF8 path"),
            None,
            None,
            Preparation::new(Duration::from_secs(10)),
        )
        .await;
    assert!(
        reopen.is_ok(),
        "F1: reopen succeeds after actual public lifetime released: {reopen:?}"
    );
    let (_, reopened_token) = reopen.as_ref().expect("F1 reopened lease");
    slow.router.nexus_close_token(reopened_token).await.expect("close reopened reference");
    slow.finish(json!({"id":"F1", "close":format!("{close:?}"),
        "reopen_after_public_lifetime":format!("{reopen:?}")}))
        .await;

    let mut early = Rig::new("early-analysis").await;
    early.n1_submit(
        &ClientId::new("r0-early").expect("client"),
        "open-early",
        json!({"spawn":false,"wait_analysis":true}),
    );
    let open = early.event("failed").await;
    assert_eq!(open["error"]["code"], "operation_failed");
    assert!(open["error"]["message"].as_str().expect("analysis error").contains("wait_autoanalysis"));
    let lease: SessionLease = serde_json::from_value(open["lease"].clone()).expect("F4 acquired lease is retained explicitly");
    let identity: OpenIdentity = serde_json::from_value(open["attempt"]["target"]["identity"].clone()).expect("actual N1 open identity");
    let progress = early.bridge.endpoint().transition(|state, _| state.open_progress(&identity.client_id, &identity)).expect("N1 open outcome");
    assert!(progress.1.is_some(), "caller receives a definite analysis failure");
    assert_eq!(early.bridge.lifecycle_status()["resources"], 1, "F4 acquired lease remains in explicit custody until public proof");
    assert_eq!(early.bridge.endpoint().transition(|s,_|s.status(&lease.client_id,&lease)).expect("retained N1 lease").phase, SessionPhase::ReleaseRequired);
    early.signal("snapshot-request");
    early.marker("snapshot.json").await;
    let snapshot: Value = serde_json::from_slice(
        &std::fs::read(early.root.join("snapshot.json")).expect("transport snapshot"),
    )
    .expect("snapshot JSON");
    assert_eq!(
        snapshot["physical_leases"], 1,
        "F4 unconfirmed native stop must retain the real acquired lease"
    );
    assert_eq!(
        snapshot["release_requests"], 0,
        "no detach is invented while execution stop is unconfirmed"
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
    let release = group.event("uncertain").await;
    assert_eq!(release["attempt"]["target"]["kind"], "release");
    assert_eq!(release["error"]["code"], "unknown_outcome");
    let control = group.bridge.status("r5-b-control").await;
    if control.is_ok() {
        loop {
            let event = group
                .events
                .recv()
                .await
                .expect("control or physical failure");
            group.evidence.push(event.clone());
            if matches!(
                event["event"].as_str(),
                Some("local_status" | "bridge_disconnected")
            ) {
                break;
            }
        }
    }
    let status = group
        .bridge
        .endpoint()
        .transition(|s, _| s.status(&b, &lease_b))
        .expect("B status");
    let mut query = None;
    if status.phase == SessionPhase::Active {
        let operation = group
            .bridge
            .endpoint()
            .transition(|s, t| {
                let operation = s.queue(
                    &b,
                    &lease_b,
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new("r5-b-query").expect("query request"),
                        None,
                        "execute_python",
                        json!({"code":"result = 42"}),
                    )
                    .expect("accept B query"),
                    OperationId::new("r5-b-query").expect("query identity"),
                )?;
                s.dispatch(&b, &operation, t)?;
                Ok::<_, NexusError>(operation)
            })
            .expect("B query dispatch remains available");
        query = Some(group.event("completed").await);
        let snapshot = group
            .bridge
            .endpoint()
            .transition(|s, _| s.operation_status(&b, &operation))
            .expect("N1 B query result");
        assert_eq!(snapshot.status, OperationStatus::Succeeded);
    }
    let query_result = query
        .as_ref()
        .map(|event| event["result"]["result"].clone());
    group
        .finish(
            json!({"id":"F2", "unrelated_b":format!("{:?}",status.phase),
        "control":format!("{control:?}"), "query":query}),
        )
        .await;
    assert_eq!(
        status.phase,
        SessionPhase::Active,
        "R5: unrelated B must remain Active"
    );
    assert!(control.is_ok(), "B control must remain usable");
    assert_eq!(query_result, Some(json!(42)), "real SDK B query result");
}
