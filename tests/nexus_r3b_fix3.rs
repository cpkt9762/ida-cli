//! Ordinary close after primary proof; actual N1, SDK, installed bridge/helper.
#![cfg(feature = "nexus-test-support")]
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
fn release(root: &Path, name: &str) -> anyhow::Result<()> {
    std::fs::write(root.join(format!("{name}.release")), b"")?;
    Ok(())
}
struct EventLog {
    values: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    error: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    task: tokio::task::JoinHandle<()>,
    path: PathBuf,
}
impl EventLog {
    fn new(bridge: &NexusBridge, root: &Path) -> Self {
        let mut receiver = bridge.subscribe();
        let values = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let error = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = values.clone();
        let failure = error.clone();
        let task = tokio::spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok(event) => sink.lock().expect("test sink").push(event),
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(e) => {
                        *failure.lock().expect("test sink error") = Some(e.to_string());
                        break;
                    }
                }
            }
        });
        Self {
            values,
            error,
            task,
            path: root.join("actual-events.json"),
        }
    }
    async fn matching(&self, name: &str, watch: &Value) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let error = self.error.lock().expect("sink error").clone();
                anyhow::ensure!(
                    error.is_none(),
                    "actual test event receiver lost events: {error:?}"
                );
                if self
                    .values
                    .lock()
                    .expect("events")
                    .iter()
                    .any(|e| e["event"] == name && e["watch"] == *watch)
                {
                    break Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await??;
        Ok(())
    }
}
impl Drop for EventLog {
    fn drop(&mut self) {
        self.task.abort();
        std::fs::write(
            &self.path,
            serde_json::to_vec_pretty(&*self.values.lock().expect("events")).expect("events JSON"),
        )
        .expect("event evidence");
    }
}
async fn startup_settled(events: &EventLog, watch: &Value) -> anyhow::Result<()> {
    events.matching("startup_settled", watch).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr1_sdk_completion_and_last_watch_race_settle_exact_absence() {
    completion_case("race", "").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr1_sdk_completion_before_last_watch_retains_until_full_closure() {
    completion_case("completion-first", "").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr1_last_watch_before_sdk_completion_retains_until_sdk_finishes() {
    completion_case("proof-first", "").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr2_ordinary_late_observation_rejects_foreign_identities() {
    completion_case("proof-first", "identities").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr2_ordinary_persistence_failure_keeps_cause_and_notsent() {
    completion_case("proof-first", "persistence").await;
}
async fn completion_case(order: &str, mode: &str) {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("new private case"));
    let router = RouterState::new().expect("router");
    for name in ["proof_before_retire", "sdk_pending"] {
        if name == "sdk_pending" && order == "proof-first" {
            continue;
        }
        std::fs::write(root.join(format!("{name}.arm")), b"").expect("arm only a scheduling point");
    }
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3F2_CASE".into(), "completion".into());
    environment.insert("R3F3_CASE".into(), mode.into());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed new SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3b_fix3_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("installed bridge/helper actual N1");
    let events = EventLog::new(&bridge, &root);
    let result:anyhow::Result<Value>=async {
        let (_,token)=router.ensure_worker_prepared(root.join("a/tiny.i64").to_str().expect("path"),None,None,Preparation::new(Duration::from_secs(15))).await?;
        let primary_watch=bridge.lifecycle_status()["resource_details"][0]["watch"].clone();
        let primary:SessionLease=serde_json::from_value(bridge.lifecycle_status()["resource_details"][0]["lease"].clone())?;
        std::fs::write(root.join("a/disconnect-primary"),b"")?;
        marker(&root.join("a/disconnected")).await?;
        let closing_router=router.clone();let close_token=token.clone();let mut closing=tokio::spawn(async move{closing_router.nexus_close_token(&close_token).await});
        marker(&root.join("compensation.arrived")).await?;
        let child:Value=serde_json::from_slice(&std::fs::read(root.join("failed-child.json"))?)?;
        let acquisition:AcquisitionId=serde_json::from_value(child["acquisition"].clone())?;
        std::fs::write(root.join("a/owner-release"),b"")?;
        tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                let helper:Value=serde_json::from_slice(&std::fs::read(root.join("i/helper-state.json"))?)?;
                if helper["items"][child["watch"].as_str().expect("actual watch")]["proof"].is_object(){break Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }).await??;
        events.matching("custody_settled",&primary_watch).await?;
        anyhow::ensure!(bridge.lifecycle_status()["retirement_acks"]==0,"original retirement ACK must have left the table");
        anyhow::ensure!(bridge.lifecycle_status()["resource_details"].as_array().expect("resources").iter().all(|r|r["lease"]!=json!(primary)),"late ordinary observation must miss the actual active primary table");
        release(&root,"compensation")?;
        tokio::time::timeout(Duration::from_secs(3),async {
            while !root.join("before_sdk_finished.arrived").exists() {
                if closing.is_finished() {anyhow::bail!("caller ended before actual SDK completion hook: {:?}",(&mut closing).await?);}
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Ok::<_,anyhow::Error>(())
        }).await??;
        marker(&root.join("proof_before_retire.arrived")).await?;
        anyhow::ensure!(!bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?,"SDK still executing and last watch must retain slot");
        let before=bridge.lifecycle_status();
        if order=="proof-first" {
            release(&root,"proof_before_retire")?;startup_settled(&events,&child["watch"]).await?;
            anyhow::ensure!(!bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?,"public proof alone cannot finish SDK");
            release(&root,"before_sdk_finished")?;
        }else{
            release(&root,"before_sdk_finished")?;marker(&root.join("sdk_pending.arrived")).await?;
            let pending:Value=serde_json::from_slice(&std::fs::read(root.join("sdk_pending.arrived"))?)?;
            anyhow::ensure!(pending["pending"]==true&&pending["acquisition"]==json!(acquisition),"actual A must have read the last pending watch");
            if order=="race" {
                release(&root,"proof_before_retire")?;startup_settled(&events,&child["watch"]).await?;
                anyhow::ensure!(!bridge.endpoint().transition(|s,_|s.acquisition_sdk_finished(&acquisition))?,"B must finish before A writes SDK finished");
                anyhow::ensure!(bridge.lifecycle_status()["startup_and_pre_attach"]==0,"B removed last actual startup");
                release(&root,"sdk_pending")?;
            }else{
                release(&root,"sdk_pending")?;marker(&root.join("after_sdk_finished.json")).await?;
                anyhow::ensure!(!bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?,"remaining watch closure cannot be skipped");
                release(&root,"proof_before_retire")?;startup_settled(&events,&child["watch"]).await?;
            }
        }
        let caller=tokio::time::timeout(Duration::from_secs(4),closing).await??;
        anyhow::ensure!(caller.is_err()&&format!("{caller:?}").contains("controlled auxiliary observe NotSent"),"original cause lost: {caller:?}");
        marker(&root.join("after_sdk_finished.json")).await?;
        let status=bridge.endpoint().transition(|s,_|s.status(&primary.client_id,&primary))?;
        let delivery=status.control_delivery.as_ref().expect("original release attempt");
        anyhow::ensure!(status.phase==SessionPhase::Released && delivery.state==DeliveryState::NotSent,
            "public proof must not invent an original attempt ACK: {status:?}");
        let error=delivery.error.as_ref().expect("typed original error");
        anyhow::ensure!(error.code==NexusErrorCode::OperationFailed && error.message=="RuntimeError: controlled auxiliary observe NotSent after helper subscribe" && error.cause.is_none(),
            "original typed N1 cause changed: {error:?}");
        let ida_mcp::error::ToolError::Nexus(caller_error)=caller.as_ref().expect_err("original failure") else {anyhow::bail!("caller lost Nexus type")};
        anyhow::ensure!(caller_error.code==error.code && caller_error.cause==error.cause && caller_error.message.starts_with(&error.message),"caller differs from actual N1 error");
        let observations=router.status_snapshot().await.owner_observations;
        let facts=observations.iter().find(|v|v["lease"]==json!(primary)).expect("exact retained primary facts");
        anyhow::ensure!(facts["terminal"]=="not_sent" && facts["attempt"]==json!(delivery.attempt)
            && facts["command_error"]==json!(error) && facts["preflight"]["detach_called"]==false
            && facts["preflight"]["cause"]["type"]=="RuntimeError"
            && facts["preflight"]["cause"]["message"]=="controlled auxiliary observe NotSent after helper subscribe"
            && facts["outcome"]["detach_called"]==false && facts["owner_pending"]==false,
            "structured status lost original attempt/cause: {facts}");
        anyhow::ensure!(!root.join("a/release-requested").exists(),"public proof must not cause detach replay");
        if mode=="persistence" {
            anyhow::ensure!(facts["observation_error"]["message"].as_str().is_some_and(|m|m.contains("RetainedEvidenceFull")),"independent writer failure lost: {facts}");
        } else {
            anyhow::ensure!(facts["observation_error"].is_null(),"unexpected sideband failure: {facts}");
        }
        if mode=="identities" {
            let rejected:Value=serde_json::from_slice(&std::fs::read(root.join("identity-rejections.json"))?)?;
            anyhow::ensure!(rejected.as_array().expect("identity rows").len()==6,"missing real cross-layer refusals");
        }
        marker(&root.join("a/requests.json")).await?;
        let requests:Value=serde_json::from_slice(&std::fs::read(root.join("a/requests.json"))?)?;
        let http=requests.as_array().expect("actual HTTP inputs");
        anyhow::ensure!(http.iter().filter(|v|v["endpoint"]=="lease").count()==1
            && http.iter().all(|v|v["endpoint"]!="/release_lease"),"unexpected extra attach or detach: {requests}");
        std::fs::write(root.join("ordinary-facts.json"),serde_json::to_vec_pretty(&json!({"status":status,"facts":facts,"caller":caller_error}))?)?;
        let after=bridge.lifecycle_status();
        std::fs::write(root.join("completion-before-assert.json"),serde_json::to_vec_pretty(&json!({"order":order,"before":before,"after":after,"caller":format!("{caller:?}"),"acquisition":acquisition}))?)?;
        anyhow::ensure!(bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?,"finished SDK plus zero actual watches must close exact reservation naturally");
        let ended:Value=serde_json::from_slice(&std::fs::read(root.join("after_sdk_finished.json"))?)?;
        if order!="completion-first" {anyhow::ensure!(ended["retained_child"]==false,"empty old child cannot remain RPC candidate");}
        anyhow::ensure!(ended["sdk_entered"]==false&&ended["has_handle"]==false&&ended["has_lease"]==false,"failed child sent extra SDK attach");
        // With tenant=2, another healthy parent must still get its second slot.
        let (_,other)=router.ensure_worker_prepared(root.join("b/tiny.i64").to_str().expect("B path"),None,None,Preparation::new(Duration::from_secs(15))).await?;
        std::fs::write(root.join("b/disconnect-primary"),b"")?;
        marker(&root.join("b/disconnected")).await?;
        router.nexus_close_token(&other).await?;
        Ok(json!({"caller":format!("{caller:?}"),"ended":ended,"physical":bridge.lifecycle_status()}))
    }.await;
    for name in [
        "proof_before_retire",
        "sdk_pending",
        "before_sdk_finished",
        "compensation",
    ] {
        release(&root, name).expect("finally release own test barrier");
    }
    for name in ["a", "b"] {
        std::fs::write(root.join(name).join("owner-release"), b"").expect("own owner release");
        std::fs::write(root.join(name).join("guard.release"), b"").expect("own guard release");
    }
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0
            || bridge.lifecycle_status()["startup_and_pre_attach"] != 0
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let stopped = bridge.shutdown().await;
    let forced = if stopped.is_err() {
        Some(
            bridge
                .test_helper_fault(true)
                .await
                .expect("precise failed helper cleanup"),
        )
    } else {
        None
    };
    std::fs::write(root.join("completion-result.json"),serde_json::to_vec_pretty(&json!({"order":order,"result":format!("{result:?}"),"shutdown":format!("{stopped:?}"),"forced_failed_case_cleanup":forced})).expect("result JSON")).expect("result");
    if result.is_ok() {
        settled.expect("exact resource closure");
        stopped.expect("natural helper/bridge finish");
    }
    result.expect("actual N1/Python/helper completion authority must join both facts");
}
