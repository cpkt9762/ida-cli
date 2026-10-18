//! Actual RR1 completion race, scope, retry and publication regressions.
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
    completion_case("race").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr1_sdk_completion_before_last_watch_retains_until_full_closure() {
    completion_case("completion-first").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr1_last_watch_before_sdk_completion_retains_until_sdk_finishes() {
    completion_case("proof-first").await;
}
async fn completion_case(order: &str) {
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
    environment.insert("R3B_CASE".into(), "rr1-lifetime".into());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed new SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3b_fix2_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("installed bridge/helper actual N1");
    let events = EventLog::new(&bridge, &root);
    let result:anyhow::Result<Value>=async {
        let (_,token)=router.ensure_worker_prepared(root.join("a/tiny.i64").to_str().expect("path"),None,None,Preparation::new(Duration::from_secs(15))).await?;
        router.nexus_close_token(&token).await?;
        let context:Vec<String>=serde_json::from_slice(&std::fs::read(root.join("late-cleanup-context.json"))?)?;
        let mut closing=tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            use std::io::{Read,Write};
            let mut socket=std::os::unix::net::UnixStream::connect(&context[2])?;
            socket.set_read_timeout(Some(Duration::from_secs(4)))?;
            socket.write_all(format!("cleanup:{}:{}",context[0],context[1]).as_bytes())?;
            let mut reply=[0;2];socket.read_exact(&mut reply)?;Ok(reply.to_vec())
        });
        marker(&root.join("compensation.arrived")).await?;
        let child:Value=serde_json::from_slice(&std::fs::read(root.join("failed-child.json"))?)?;
        let acquisition:AcquisitionId=serde_json::from_value(child["acquisition"].clone())?;
        let parent_before=bridge.endpoint().transition(|s,_|s.open_progress(&acquisition.parent.client_id,&acquisition.parent))?;
        std::fs::write(root.join("a/owner-release"),b"")?;
        tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                let helper:Value=serde_json::from_slice(&std::fs::read(root.join("i/helper-state.json"))?)?;
                if helper["items"][child["watch"].as_str().expect("actual watch")]["proof"].is_object(){break Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }).await??;
        release(&root,"compensation")?;
        tokio::time::timeout(Duration::from_secs(3),async {
            while !root.join("before_sdk_finished.arrived").exists() {
                if closing.is_finished() {anyhow::bail!("lifetime caller ended before actual SDK completion hook: {:?}",(&mut closing).await?);}
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
        anyhow::ensure!(caller?==b"no","actual lifetime caller must receive failed auxiliary custody");
        let status=router.status_snapshot().await.owner_observations;
        anyhow::ensure!(serde_json::to_string(&status)?.contains("controlled auxiliary observe NotSent"),"original typed auxiliary cause lost: {status:?}");
        marker(&root.join("after_sdk_finished.json")).await?;
        let after=bridge.lifecycle_status();
        anyhow::ensure!(bridge.endpoint().transition(|s,_|s.open_progress(&acquisition.parent.client_id,&acquisition.parent))?==parent_before,"auxiliary completion rewrote original parent result");
        std::fs::write(root.join("completion-before-assert.json"),serde_json::to_vec_pretty(&json!({"order":order,"before":before,"after":after,"caller":format!("{status:?}"),"acquisition":acquisition}))?)?;
        anyhow::ensure!(bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?,"finished SDK plus zero actual watches must close exact reservation naturally");
        let ended:Value=serde_json::from_slice(&std::fs::read(root.join("after_sdk_finished.json"))?)?;
        if order!="completion-first" {anyhow::ensure!(ended["retained_child"]==false,"empty old child cannot remain RPC candidate");}
        anyhow::ensure!(ended["sdk_entered"]==false&&ended["has_handle"]==false&&ended["has_lease"]==false,"failed child sent extra SDK attach");
        // With tenant=2, another healthy parent must still get its second slot.
        let (_,other)=router.ensure_worker_prepared(root.join("b/tiny.i64").to_str().expect("B path"),None,None,Preparation::new(Duration::from_secs(15))).await?;
        std::fs::write(root.join("b/disconnect-primary"),b"")?;
        marker(&root.join("b/disconnected")).await?;
        router.nexus_close_token(&other).await?;
        Ok(json!({"caller":format!("{status:?}"),"ended":ended,"physical":bridge.lifecycle_status()}))
    }.await;
    for name in [
        "proof_before_retire",
        "sdk_pending",
        "before_sdk_finished",
        "compensation",
        "resource_before_consumer",
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
        settled.expect("exact resources naturally settle");
        stopped.expect("natural helper/bridge finish");
    }
    result.expect("actual N1/Python/helper completion authority must join both facts");
}

fn guard_busy(path: &Path) -> anyhow::Result<bool> {
    use std::os::fd::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    // SAFETY: independent live descriptor, nonblocking native flock only.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(false);
    }
    let error = std::io::Error::last_os_error();
    anyhow::ensure!(
        error.kind() == std::io::ErrorKind::WouldBlock,
        "unexpected guard probe error: {error}"
    );
    Ok(true)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr1_verification_root_retry_after_old_ack_and_bridge_eof_cleans_exact_copy() {
    retry_case(true, "retry-resolved").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr1_verification_root_retry_early_handle_after_old_ack_and_eof_cleans_copy() {
    retry_case(true, "retry-acquired").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr1_ordinary_final_root_retry_never_gains_verification_delete_authority() {
    retry_case(false, "retry-resolved").await;
}
async fn retry_case(verification: bool, mode: &str) {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("new private retry case"));
    let home = PathBuf::from(std::env::var_os("IDA_CLI_HOME").expect("private home"));
    let cache = home.join("idb");
    std::fs::create_dir_all(&cache).expect("private cache");
    let raw = root.join("raw");
    std::fs::write(&raw, b"new private verification input").expect("new input");
    let hash = blake3::hash(b"new private verification input").to_hex()[..12].to_string();
    let legacy = cache.join(format!("legacy.{hash}.dylib.i64"));
    std::fs::copy(
        std::env::var_os("R3F1_SAMPLE").expect("private seed copy"),
        &legacy,
    )
    .expect("fresh legacy copy");
    let original = std::fs::read(&legacy).expect("legacy original");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3F2_CASE".into(), mode.into());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3b_fix2_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("actual installed bridge/helper");
    let events = EventLog::new(&bridge, &root);
    let path = if verification {
        raw
    } else {
        root.join("tiny.i64")
    };
    let opening_router = router.clone();
    let opening = tokio::spawn(async move {
        opening_router
            .ensure_worker_prepared(
                path.to_str().expect("path"),
                None,
                None,
                Preparation::new(Duration::from_secs(30)),
            )
            .await
    });
    let result:anyhow::Result<Value>=async {
        marker(&root.join("before_retry.arrived")).await?;
        let previous:Value=serde_json::from_slice(&std::fs::read(root.join("before_retry.json"))?)?;
        let first:AcquisitionId=serde_json::from_value(previous["acquisition"].clone())?;
        anyhow::ensure!(first.ordinal==1&&first.purpose==if verification{AcquisitionPurpose::Verification}else{AcquisitionPurpose::Final},"wrong first source: {first:?}");
        events.matching("custody_settled",&previous["watch"]).await?;
        anyhow::ensure!(bridge.lifecycle_status()["retirement_acks"]==0,"ordinal1 receipt must be ACKed and removed before retry");
        let retired_first=bridge.lifecycle_status();
        release(&root,"before_retry")?;marker(&root.join("retry_current.arrived")).await?;
        let current:Value=serde_json::from_slice(&std::fs::read(root.join("retry_current.json"))?)?;
        let acquisition:AcquisitionId=serde_json::from_value(current["acquisition"].clone())?;
        anyhow::ensure!(acquisition.ordinal==2&&acquisition.purpose==AcquisitionPurpose::InitialRootRetry&&acquisition.parent==first.parent,"retry identity changed: {current}");
        anyhow::ensure!(current["verification_path"].is_string()==verification,"Python obligation must follow retry");
        let target=PathBuf::from(current["target"].as_str().ok_or_else(||anyhow::anyhow!("target"))?);let directory=target.parent().ok_or_else(||anyhow::anyhow!("copy parent"))?;
        let identity=legacy.canonicalize()?;let key=blake3::hash(identity.as_os_str().as_encoded_bytes()).to_hex();let guard=cache.join(format!(".open-{key}.lock"));
        if verification {anyhow::ensure!(guard_busy(&guard)?&&target.exists()&&directory.join("input").exists()&&!directory.join("closed").exists(),"verification copy/guard responsibility not continuous");}
        std::fs::write(root.join("verification_dispatch.arm"),b"")?;
        bridge.terminate().await?;
        let caller=tokio::time::timeout(Duration::from_secs(4),opening).await??;
        anyhow::ensure!(caller.is_err(),"bridge EOF cannot publish final business");
        tokio::time::timeout(Duration::from_secs(8),async{
            while !bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?{tokio::time::sleep(Duration::from_millis(5)).await;}
            Ok::<_,anyhow::Error>(())
        }).await??;
        marker(&root.join("verification_dispatch.arrived")).await?;
        let dispatched:Value=serde_json::from_slice(&std::fs::read(root.join("verification_dispatch.arrived"))?)?;
        anyhow::ensure!(dispatched["acquisition"]==json!(acquisition),"cleanup cannot be triggered by late ordinal1 receipt");
        release(&root,"verification_dispatch")?;
        let physical=bridge.lifecycle_status();let history=bridge.endpoint().transition(|s,_|s.open_progress(&first.parent.client_id,&first.parent))?;
        anyhow::ensure!(history.1.is_some()&&(!verification||history.0.is_none()),"Unknown/original parent history was rewritten: {history:?}");
        std::fs::write(root.join("retry-after-proof.json"),serde_json::to_vec_pretty(&json!({"first_retirement_acked":retired_first,"current":current,"actual_cleanup_filter_input":dispatched,"physical":physical,"history":history,
            "closed_exists":directory.join("closed").exists(),"probe_exists":target.exists(),"scope":"actual Rust/N1/fixed SDK/installed Python/helper, controlled native HTTP/IDA inputs"}))?)?;
        if verification {
            tokio::time::timeout(Duration::from_secs(3),async{
                while target.exists()||directory.join("input").exists()||guard_busy(&guard)?{tokio::time::sleep(Duration::from_millis(5)).await;}
                Ok::<_,anyhow::Error>(())
            }).await??;
            anyhow::ensure!(!legacy.with_extension("").exists()&&std::fs::read(&legacy)?==original,"failed retry published final input or changed original");
        }else{
            anyhow::ensure!(physical["blocked"].as_object().is_some_and(|v|v.is_empty()),"ordinary retry must skip cleanup, not attempt then be rejected");
            anyhow::ensure!(target.exists()&&!directory.join("closed").exists(),"ordinary retry acquired verification deletion authority");
        }
        bridge.shutdown().await?;
        Ok(json!({"caller":format!("{caller:?}"),"acquisition":acquisition,"source_verification":verification,"physical":physical}))
    }.await;
    release(&root, "verification_dispatch").expect("finally filter");
    release(&root, "before_retry").expect("finally retry");
    release(&root, "retry_current").expect("finally current");
    std::fs::write(root.join("owner-release"), b"").expect("own owner");
    let stopped = bridge.shutdown().await;
    let forced = if stopped.is_err() {
        let _ = bridge.terminate().await;
        Some(
            bridge
                .test_helper_fault(true)
                .await
                .expect("exact failed helper cleanup"),
        )
    } else {
        None
    };
    std::fs::write(
        root.join("retry-result.json"),
        serde_json::to_vec_pretty(
            &json!({"result":format!("{result:?}"),"forced_failed_case_cleanup":forced}),
        )
        .expect("JSON"),
    )
    .expect("evidence");
    result.expect("verification retry obligation must survive old receipt ACK and bridge EOF");
}

async fn opened_event(log: &EventLog, operation: &str) -> anyhow::Result<Value> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let values = log.values.lock().expect("actual event log").clone();
            for event in values {
                if event["attempt"]["target"]["identity"]["operation_id"] == operation {
                    anyhow::ensure!(
                        event["event"] != "failed" && event["event"] != "uncertain",
                        "normal caller failed: {event}"
                    );
                    if event["event"] == "opened" {
                        return Ok::<_, anyhow::Error>(event);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rr1_publication_permission_is_continuous_against_a_normal_second_caller() {
    let root =
        PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private real publication case"));
    let home = PathBuf::from(std::env::var_os("IDA_CLI_HOME").expect("private home"));
    std::fs::create_dir_all(&home).expect("worker cwd");
    let input = root.join("raw");
    std::fs::copy(
        std::env::var_os("R2_REAL_INPUT").expect("fresh private mini"),
        &input,
    )
    .expect("new input");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3F2_CASE".into(), "publication".into());
    environment.insert(
        "R3F2_ENV".into(),
        std::env::var("R2_RUN_ROOT").expect("private env root") + "/env",
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3b_fix2_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("real production bridge/helper/IDA");
    let second_root = root.join("second");
    std::fs::create_dir(&second_root).expect("second private client");
    let second_home = second_root.join("home");
    std::fs::create_dir(&second_home).expect("second HOME");
    let second_tmp = second_root.join("tmp");
    std::fs::create_dir(&second_tmp).expect("second TMP");
    let mut second_env: BTreeMap<String, String> = std::env::vars().collect();
    second_env.insert("R3F2_CASE".into(), "publication".into());
    second_env.insert(
        "R3F2_ENV".into(),
        std::env::var("R2_RUN_ROOT").expect("root") + "/env",
    );
    second_env.insert("HOME".into(), second_home.display().to_string());
    second_env.insert("TMPDIR".into(), second_tmp.display().to_string());
    second_env.insert(
        "IDA_CLI_HOME".into(),
        second_home.join(".ida").display().to_string(),
    );
    second_env.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        second_root.join("state").display().to_string(),
    );
    std::fs::create_dir_all(second_home.join(".ida")).expect("second worker cwd");
    let second_router = RouterState::new().expect("second normal router");
    let other_bridge = second_router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3b_fix2_bridge.py"),
            directory: root.join("j"),
            environment: second_env,
        })
        .await
        .expect("independent normal bridge/helper");
    let second_log = EventLog::new(&other_bridge, &second_root);
    let log = EventLog::new(&bridge, &root);
    let client = ClientId::new("publication-seed").expect("client");
    let mut token = None;
    let result:anyhow::Result<Value>=async {
        bridge.endpoint().transition(|s,t|s.open(&client,AcceptedRequest::new(&SystemClock,RequestId::new("seed")?,None,"open",json!({"timeout_secs":30}))?,
            OpenSpec{operation_id:OperationId::new("seed")?,path:input.display().to_string(),options:json!({"output_database":root.join("seed.i64"),"auto_analysis":false,"wait_analysis":false})},t))?;
        let seed=opened_event(&log,"seed").await?;let seed_lease:SessionLease=serde_json::from_value(seed["lease"].clone())?;
        bridge.endpoint().transition(|s,t|s.release(&client,&seed_lease,t))?;
        tokio::time::timeout(Duration::from_secs(8),async{while bridge.lifecycle_status()["resources"]!=0{tokio::time::sleep(Duration::from_millis(5)).await;}}).await?;
        let cache=home.join("idb");std::fs::create_dir_all(&cache)?;let hash=blake3::hash(&std::fs::read(&input)?).to_hex()[..12].to_string();
        let legacy=cache.join(format!("legacy.{hash}.dylib.i64"));std::fs::copy(root.join("seed.i64"),&legacy)?;
        let destination=legacy.with_extension("");
        std::fs::write(root.join("publication_validated.arm"),b"")?;
        let publisher_router=router.clone();let publisher_path=input.clone();
        let publisher=tokio::spawn(async move{publisher_router.ensure_worker_prepared(publisher_path.to_str().expect("input"),None,None,Preparation::new(Duration::from_secs(30))).await});
        marker(&root.join("publication_validated.arrived")).await?;
        let validated:Value=serde_json::from_slice(&std::fs::read(root.join("publication_validated.arrived"))?)?;
        let copy=PathBuf::from(validated["directory"].as_str().ok_or_else(||anyhow::anyhow!("copy"))?);
        let probe=copy.join("probe.i64");
        let coord=std::fs::read_dir(&copy)?.filter_map(Result::ok).find(|p|p.file_name().to_string_lossy().starts_with(".ida-cli-txn-")).ok_or_else(||anyhow::anyhow!("actual stable coord"))?.path();
        let second_input=root.join("second-raw");std::fs::copy(&input,&second_input)?;
        let second_client=ClientId::new("normal-publication-caller")?;
        let second=other_bridge.endpoint().transition(|s,t|s.open(&second_client,AcceptedRequest::new(&SystemClock,RequestId::new("publication-racer")?,None,"open",json!({"timeout_secs":30}))?,
            OpenSpec{operation_id:OperationId::new("publication-racer")?,path:second_input.display().to_string(),
                options:json!({"output_database":probe,"auto_analysis":false,"wait_analysis":false})},t))?;
        marker(&root.join("publication_second_before_gate.arrived")).await?;
        anyhow::ensure!(!destination.exists(),"input already published before permission window");
        // B is paused before its own gate, so any target EX here belongs to A.
        let publisher_holds_target=guard_busy(&coord.join("lock"))?;
        release(&root,"publication_second_before_gate")?;
        let second_admitted_before_publication=!publisher_holds_target;
        if second_admitted_before_publication {
            tokio::time::timeout(Duration::from_secs(3),async {
                while other_bridge.lifecycle_status()["startup_and_pre_attach"]==0&&other_bridge.lifecycle_status()["resources"]==0 {tokio::time::sleep(Duration::from_millis(2)).await;}
            }).await?;
            let journal:Value=serde_json::from_slice(&std::fs::read(coord.join("custody.json"))?)?;
            anyhow::ensure!(journal["entries"].as_object().is_some_and(|m|m.values().any(|entry|entry["acquisition"]["parent"]["operation_id"]=="publication-racer")),"normal second caller must own actual signed target responsibility");
        }
        let before=bridge.lifecycle_status();
        release(&root,"publication_validated")?;
        let published=tokio::time::timeout(Duration::from_secs(4),publisher).await??;
        let after=bridge.lifecycle_status();
        std::fs::write(root.join("publication-window.json"),serde_json::to_vec_pretty(&json!({"target_ex_held_across_window":publisher_holds_target,
            "second_admitted_before_publication":second_admitted_before_publication,"second_authority":other_bridge.lifecycle_status(),"second_parent":second,"before":before,"after":after,
            "publisher_result":format!("{published:?}"),"destination_exists":destination.exists(),"second_gate_admitted":root.join("publication_second_admitted").exists(),
            "scope":"actual Rust cache publication and normal production N1 OpenSpec/public SDK output_database caller, real private IDA"}))?)?;
        if second_admitted_before_publication{anyhow::ensure!(!destination.exists(),"normal new owner admitted in permission gap: destination was published before cleanup rejected");}
        let (_,reference)=published?;token=Some(reference);
        anyhow::ensure!(publisher_holds_target&&destination.is_file(),"publisher must retain exact authority through commit");
        let second_ready=opened_event(&second_log,"publication-racer").await?;
        let second_lease:SessionLease=serde_json::from_value(second_ready["lease"].clone())?;
        anyhow::ensure!(other_bridge.endpoint().transition(|s,_|s.status(&second_client,&second_lease))?.phase==SessionPhase::Active,"first cleanup harmed later normal owner");
        other_bridge.endpoint().transition(|s,t|s.release(&second_client,&second_lease,t))?;
        Ok(json!({"target_ex_held":publisher_holds_target,"destination":destination,"second_ready":second_ready}))
    }.await;
    release(&root, "publication_validated").expect("finally publisher");
    release(&root, "publication_second_before_gate").expect("finally normal gate");
    if let Some(token) = token {
        router
            .nexus_close_token(&token)
            .await
            .expect("close own published lease");
    }
    std::fs::write(
        root.join("publication-body-result.txt"),
        format!("{result:?}"),
    )
    .expect("body evidence");
    for closing_bridge in [&bridge, &other_bridge] {
        let resources = closing_bridge.lifecycle_status()["resource_details"]
            .as_array()
            .expect("actual resources")
            .clone();
        for resource in resources {
            let lease: SessionLease =
                serde_json::from_value(resource["lease"].clone()).expect("actual resource lease");
            let status = closing_bridge
                .endpoint()
                .transition(|s, _| s.status(&lease.client_id, &lease))
                .expect("actual state");
            if matches!(status.phase, SessionPhase::Active | SessionPhase::Preparing) {
                let cleanup = closing_bridge
                    .endpoint()
                    .transition(|s, t| s.release(&lease.client_id, &lease, t));
                if let Err(error) = cleanup {
                    assert_eq!(
                        error.code,
                        NexusErrorCode::CancelPending,
                        "own cleanup refusal"
                    );
                }
            }
        }
    }
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0
            || other_bridge.lifecycle_status()["resources"] != 0
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let first_other_shutdown = other_bridge.shutdown().await;
    let other_shutdown = if first_other_shutdown.is_err() {
        let pending = tokio::time::timeout(Duration::from_secs(8), async {
            while other_bridge.lifecycle_status()["startup_and_pre_attach"] != 0
                || other_bridge.lifecycle_status()["resources"] != 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        if pending.is_ok() {
            other_bridge.shutdown().await
        } else {
            first_other_shutdown
        }
    } else {
        first_other_shutdown
    };
    let shutdown = bridge.shutdown().await;
    std::fs::write(root.join("publication-result.json"),serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),"settled":settled.is_ok(),"shutdown":format!("{shutdown:?}"),"second_shutdown":format!("{other_shutdown:?}")})).expect("JSON")).expect("publication result");
    settled.expect("real owners naturally close");
    shutdown.expect("natural helper finish");
    other_shutdown.expect("second natural helper finish");
    result.expect(
        "normal caller permission cannot change between validated closure and input publication",
    );
}
