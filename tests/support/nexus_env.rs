use ida_mcp::nexus::*;
use ida_mcp::router::{
    nexus_bridge::{BridgeConfig, NexusBridge},
    RouterState,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::broadcast;
static IDS: AtomicU64 = AtomicU64::new(1);
pub fn id() -> String {
    format!(
        "n3-{}-{}",
        std::process::id(),
        IDS.fetch_add(1, Ordering::Relaxed)
    )
}
pub fn root() -> PathBuf {
    PathBuf::from(
        std::env::var_os("N3_ENV_ROOT").expect("N3_ENV_ROOT prepared by verify_nexus_e2e.py"),
    )
}
pub fn variables() -> BTreeMap<String, String> {
    serde_json::from_str(
        &std::fs::read_to_string(root().join("rust-env.json"))
            .expect("isolated environment manifest"),
    )
    .expect("environment JSON")
}
pub fn config() -> BridgeConfig {
    let env = variables();
    BridgeConfig {
        python: root().join("venv/bin/python"),
        script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/support/nexus_client_fixture.py"),
        directory: PathBuf::from(env.get("N3_IPC_ROOT").expect("short external IPC root"))
            .join(id()),
        environment: env,
    }
}
pub fn record(event: Value) {
    use std::io::Write;
    let mut output = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root().join("rust-evidence.jsonl"))
        .expect("evidence log");
    writeln!(output, "{event}").expect("persist event evidence");
}
pub struct Client {
    pub _router: RouterState,
    pub bridge: Arc<NexusBridge>,
    pub events: broadcast::Receiver<Value>,
    pub client: ClientId,
}
impl Client {
    pub async fn new() -> Self {
        Self::configured(config()).await
    }
    pub async fn configured(cfg: BridgeConfig) -> Self {
        assert_eq!(
            std::env::var("IDA_TEST").expect("explicit real IDA opt-in"),
            "1"
        );
        let router = RouterState::new().expect("router");
        let bridge = router
            .connect_nexus(cfg.clone())
            .await
            .expect("real persistent bridge readiness");
        assert!(Arc::ptr_eq(
            &bridge,
            &router.connect_nexus(cfg).await.expect("reuse bridge")
        ));
        let events = bridge.subscribe();
        record(json!({"event":"bridge_started", "pid":bridge.pid}));
        Self {
            _router: router,
            bridge,
            events,
            client: ClientId::new(id()).unwrap(),
        }
    }
    pub async fn event(&mut self, predicate: impl Fn(&Value) -> bool) -> Value {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let event = self.events.recv().await.expect("bridge event channel");
                record(event.clone());
                if predicate(&event) {
                    return event;
                }
            }
        })
        .await
        .expect("event barrier deadline")
    }
    pub async fn open(&mut self, path: &Path, options: Value) -> (SessionLease, Value) {
        let request = AcceptedRequest::new(
            &SystemClock,
            RequestId::new(id()).unwrap(),
            None,
            "open",
            json!({"timeout_secs":15}),
        )
        .unwrap();
        let preparation = ida_mcp::preprocess::Preparation::new(Duration::from_secs(15));
        let prepared = ida_mcp::router::nexus_bridge::cache::prepare_open(
            path.to_path_buf(),
            root().join("cli-home/idb"),
            &preparation,
        )
        .await
        .expect("bounded central-cache preparation");
        let op = OperationId::new(id()).unwrap();
        let identity = self
            .bridge
            .endpoint()
            .transition(|s, t| {
                s.open(
                    &self.client,
                    request,
                    OpenSpec {
                        operation_id: op,
                        path: prepared.to_string_lossy().into_owned(),
                        options,
                    },
                    t,
                )
            })
            .expect("N1 open admission");
        let event = self
            .event(|event| {
                event["attempt"]["target"]["identity"]["operation_id"]
                    == identity.operation_id.as_str()
                    && event["event"] != "ack"
            })
            .await;
        assert_eq!(event["event"], "opened", "{event}");
        let lease: SessionLease = serde_json::from_value(event["lease"].clone()).unwrap();
        let snapshot = self
            .bridge
            .endpoint()
            .transition(|s, _| s.status(&self.client, &lease))
            .unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Active);
        (lease, event)
    }
    pub async fn execute(
        &mut self,
        lease: &SessionLease,
        method: &str,
        params: Value,
    ) -> OperationSnapshot {
        let identity = self.begin(lease, method, params);
        self.finish(&identity).await
    }
    pub fn begin(&self, lease: &SessionLease, method: &str, params: Value) -> OperationIdentity {
        let request = AcceptedRequest::new(
            &SystemClock,
            RequestId::new(id()).unwrap(),
            None,
            method,
            params,
        )
        .unwrap();
        self.bridge
            .endpoint()
            .transition(|s, t| {
                let identity = s.queue(
                    &self.client,
                    lease,
                    request,
                    OperationId::new(id()).unwrap(),
                )?;
                s.dispatch(&self.client, &identity, t)?;
                Ok::<_, NexusError>(identity)
            })
            .expect("N1 execute admission")
    }
    pub async fn finish(&mut self, identity: &OperationIdentity) -> OperationSnapshot {
        self.event(|event| {
            event["attempt"]["target"]["identity"]["operation_id"] == identity.operation_id.as_str()
                && matches!(
                    event["event"].as_str(),
                    Some("completed" | "remote_error" | "uncertain" | "stopped")
                )
        })
        .await;
        self.bridge
            .endpoint()
            .transition(|s, _| s.operation_status(&self.client, identity))
            .unwrap()
    }
    pub async fn value(&mut self, lease: &SessionLease, method: &str, params: Value) -> Value {
        let result = self.execute(lease, method, params).await;
        assert_eq!(result.status, OperationStatus::Succeeded, "{result:?}");
        assert!(result.execution_stopped);
        result.result.unwrap()["result"].clone()
    }
    pub async fn release(&mut self, lease: &SessionLease) {
        self.bridge
            .endpoint()
            .transition(|s, t| s.release(&self.client, lease, t))
            .unwrap();
        let event = self
            .event(|event| {
                event["event"] == "released"
                    && event["attempt"]["target"]["lease"]["lease_id"] == lease.lease_id.as_str()
            })
            .await;
        assert_eq!(event["event"], "released");
        assert_eq!(
            self.bridge
                .endpoint()
                .transition(|s, _| s.status(&self.client, lease))
                .unwrap()
                .phase,
            SessionPhase::Released
        );
    }
}
/// Independent sample bytes; production cache preparation chooses the IDB path.
pub fn sample(label: &str) -> PathBuf {
    let mut bytes = std::fs::read(root().join("fixtures/mini")).unwrap();
    bytes.extend_from_slice(label.as_bytes());
    let raw = root().join("fixtures").join(label);
    std::fs::write(&raw, bytes).unwrap();
    raw
}
