use ida_mcp::{
    nexus::*,
    preprocess::Preparation,
    router::{
        nexus_bridge::{BridgeConfig, NexusBridge},
        RouterState,
    },
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

async fn marker(path: &Path) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    Ok(())
}

struct Events {
    values: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    failure: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    task: tokio::task::JoinHandle<()>,
    path: PathBuf,
}
impl Events {
    fn new(bridge: &NexusBridge, root: &Path) -> Self {
        let mut receiver = bridge.subscribe();
        let values = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let failure = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = values.clone();
        let errors = failure.clone();
        let task = tokio::spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok(event) => sink.lock().expect("event sink").push(event),
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(error) => {
                        *errors.lock().expect("event error") = Some(error.to_string());
                        break;
                    }
                }
            }
        });
        Self {
            values,
            failure,
            task,
            path: root.join("rr3-events.json"),
        }
    }
    async fn settled(&self, watch: &Value) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                anyhow::ensure!(
                    self.failure.lock().expect("event failure").is_none(),
                    "lost actual events"
                );
                if self
                    .values
                    .lock()
                    .expect("events")
                    .iter()
                    .any(|v| v["event"] == "custody_settled" && v["watch"] == *watch)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
}
impl Drop for Events {
    fn drop(&mut self) {
        self.task.abort();
        std::fs::write(
            &self.path,
            serde_json::to_vec_pretty(&*self.values.lock().expect("events")).expect("event JSON"),
        )
        .expect("event evidence");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr3_production_save_refusal_plus_real_writer_failure_reaches_caller_and_status() {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private case"));
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_SCENARIO".into(), "r2-save-refused".into());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("private fixed SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3b_fix4_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("real final bridge/helper/N1");
    let events = Events::new(&bridge, &root);
    let result: anyhow::Result<Value> = async {
        let (_, token) = router.ensure_worker_prepared(root.join("tiny.i64").to_str().expect("path"), None, None, Preparation::new(Duration::from_secs(10))).await?;
        let initial = bridge.lifecycle_status();
        let watch = initial["resource_details"][0]["watch"].clone();
        let lease: SessionLease = serde_json::from_value(initial["resource_details"][0]["lease"].clone())?;
        std::fs::write(root.join("poison-root"), b"")?;
        let closer = router.clone();
        let closing = tokio::spawn(async move { closer.nexus_close_token(&token).await });
        marker(&root.join("rr3-sideband.arrived")).await?;
        let preflight:Value = serde_json::from_slice(&std::fs::read(root.join("production-preflight.json"))?)?;
        anyhow::ensure!(preflight["outcome"]["protection"]["close_safe"]==true
            && preflight["outcome"]["cause"].is_null()
            && preflight["outcome"]["save_guard_error"].as_str().is_some_and(|s|s.contains("saving refused")),
            "production guard must return nonexception save refusal: {preflight}");
        std::fs::write(root.join("owner-release"), b"")?;
        events.settled(&watch).await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while bridge.lifecycle_status()["retirement_acks"]!=0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }).await?;
        anyhow::ensure!(bridge.lifecycle_status()["resources"]==0, "primary resource must be publicly settled before sideband");
        std::fs::write(root.join("rr3-sideband.release"), b"")?;
        let caller = tokio::time::timeout(Duration::from_secs(4), closing).await??;
        let caller_text = format!("{caller:?}");
        let status = bridge.endpoint().transition(|s,_|s.status(&lease.client_id,&lease))?;
        let observations = router.status_snapshot().await.owner_observations;
        let facts = observations.iter().find(|v|v["lease"]==json!(lease)).expect("retained exact lease");
        std::fs::write(root.join("snapshot-request"), b"")?;
        marker(&root.join("snapshot.json")).await?;
        let http:Value = serde_json::from_slice(&std::fs::read(root.join("snapshot.json"))?)?;
        let terminal:Value = serde_json::from_slice(&std::fs::read(root.join("actual-terminal.json"))?)?;
        let writer:Value = serde_json::from_slice(&std::fs::read(root.join("actual-writer-error.json"))?)?;
        let actual = json!({"caller_error":match &caller {Err(ida_mcp::error::ToolError::Nexus(error))=>Some(error.clone()),_=>None},"caller":caller_text,"status":status,"facts":facts,"http":http,"terminal":terminal,
            "writer":writer,"production_preflight":preflight,"physical":bridge.lifecycle_status(),
            "caller_has_save_refusal":caller_text.contains("saving refused"),
            "status_has_save_refusal":facts["save_guard_error"].as_str().is_some_and(|s|s.contains("saving refused"))});
        std::fs::write(root.join("rr3-actual.json"), serde_json::to_vec_pretty(&actual)?)?;
        let delivery = status.control_delivery.as_ref().expect("actual release attempt");
        anyhow::ensure!(caller.is_err() && status.phase==SessionPhase::Released && delivery.state==DeliveryState::NotSent, "wrong real N1/caller state: {actual}");
        anyhow::ensure!(facts["preflight"]["cause"].is_null()
            && facts["preflight"]["save_guard_error"]==preflight["outcome"]["save_guard_error"]
            && facts["observation_error"]["message"].as_str().is_some_and(|s|s.contains("RetainedEvidenceFull")),
            "missing actual guard or independent real writer failure: {actual}");
        let error=delivery.error.as_ref().expect("typed writer command error");
        let ida_mcp::error::ToolError::Nexus(caller_error)=caller.as_ref().expect_err("writer failure") else {anyhow::bail!("caller lost Nexus error type")};
        anyhow::ensure!(delivery.attempt==serde_json::from_value(terminal["attempt"].clone())?
            && terminal["event"]=="not_sent" && facts["attempt"]==json!(delivery.attempt)
            && facts["command_error"]==json!(error) && terminal["error"]==json!(error)
            && facts["observation_error"]==terminal["observation_error"]
            && caller_error.code==error.code && caller_error.cause==error.cause
            && caller_error.message.starts_with(&error.message),"typed command/attempt changed: {actual}");
        anyhow::ensure!(facts["save_guard_error"]==preflight["outcome"]["save_guard_error"]
            && terminal["save_guard_error"]==facts["save_guard_error"]
            && facts["preflight"]["save_guard_error"]==facts["save_guard_error"]
            && caller_error.message.contains(facts["save_guard_error"].as_str().expect("known save refusal")),
            "save rejection must agree at caller/top-level/nested status: {actual}");
        let requests = http["requests"].as_array().expect("actual HTTP requests");
        anyhow::ensure!(requests.iter().filter(|v|v["endpoint"]=="lease").count()==1
            && requests.iter().all(|v|v["endpoint"]!="/release_lease"), "unexpected extra attach/detach: {actual}");
        anyhow::ensure!(actual["caller_has_save_refusal"]==true && actual["status_has_save_refusal"]==true,
            "RR3-F1: known production save refusal missing from real close caller/status: {actual}");
        Ok(actual)
    }.await;
    for name in ["rr3-sideband.release", "owner-release", "guard.release"] {
        std::fs::write(root.join(name), b"").expect("release own barrier");
    }
    let stopped = bridge.shutdown().await;
    let forced = if stopped.is_err() {
        Some(
            bridge
                .test_helper_fault(true)
                .await
                .expect("precise owned failed helper cleanup"),
        )
    } else {
        None
    };
    std::fs::write(root.join("rr3-result.json"), serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),"shutdown":format!("{stopped:?}"),"forced_failed_case_cleanup":forced})).expect("result JSON")).expect("result evidence");
    stopped.expect("natural shutdown");
    result.expect("known save refusal must reach actual close caller and status");
}
