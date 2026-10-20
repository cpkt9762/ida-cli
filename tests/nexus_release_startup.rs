//! Real worker startup timeout: a failed open cannot imply native startup stopped.
use ida_mcp::{
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_start_timeout_retains_guard_until_real_worker_grace_exit() {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private startup root"));
    let input = root.join("startup-input");
    std::fs::copy(
        std::env::var_os("R2_REAL_INPUT").expect("private raw fixture"),
        &input,
    )
    .expect("copy startup input");
    let sibling = root.join("healthy-input");
    let mut sibling_bytes = std::fs::read(&input).expect("read private Mach-O copy");
    sibling_bytes.push(0); // Distinct content key; Mach-O permits trailing padding.
    std::fs::write(&sibling, sibling_bytes).expect("write independent healthy sample");
    let script = root.join("startup.py");
    let arrived = root.join("startup.arrived");
    let release = root.join("startup.release");
    let wrote = root.join("startup-wrote-after-failure.json");
    std::fs::write(&script, format!("from pathlib import Path\nimport time,os,json\nPath({arrived:?}).touch()\nwhile not Path({release:?}).exists(): time.sleep(.01)\nPath({wrote:?}).write_text(json.dumps({{'pid':os.getpid(),'monotonic':time.monotonic()}}))\n",arrived=arrived.to_str().expect("utf8"),release=release.to_str().expect("utf8"),wrote=wrote.to_str().expect("utf8"))).expect("write real native startup barrier");
    let router = RouterState::new().expect("startup router");
    let mut environment: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R7A_STARTUP_SCRIPT".into(), script.display().to_string());
    environment.insert("R7A_STARTUP_SCRIPT_ONCE".into(), "1".into());
    environment.insert(
        "R7A_ROOT_TRACE".into(),
        root.join("startup-rpc.jsonl").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("matching SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r7a_real_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("real bridge/helper");
    let active = router.clone();
    let opening = tokio::spawn(async move {
        active
            .ensure_worker_prepared(
                input.to_str().expect("utf8"),
                None,
                None,
                Preparation::new(Duration::from_secs(30)),
            )
            .await
    });
    let mut evidence = Vec::<Value>::new();
    let mut healthy: Option<(String, String)> = None;
    let result:anyhow::Result<()> = async {
        tokio::time::timeout(Duration::from_secs(10),async {
            while !arrived.exists() { anyhow::ensure!(!opening.is_finished(),"open failed before native barrier");tokio::time::sleep(Duration::from_millis(10)).await; }
            Ok::<_,anyhow::Error>(())
        }).await??;
        let failed=tokio::time::timeout(Duration::from_secs(8),opening).await??;
        anyhow::ensure!(failed.is_err(),"startup timeout unexpectedly opened");
        let cause=format!("{failed:?}");
        anyhow::ensure!(cause.contains("WorkerStartError") && cause.contains("timed out waiting"),"original SDK startup failure missing: {cause}");
        let retained=bridge.lifecycle_status();
        anyhow::ensure!(retained["startup_and_pre_attach"].as_u64().is_some_and(|n|n>0),"failure returned startup capacity before worker stopped: {retained}");
        anyhow::ensure!(ida_mcp::router::nexus_bridge::cache_lock::try_exclusive(&ida_mcp::idb_store::idb_root()).is_err(),"failure dropped the startup root guard");
        anyhow::ensure!(!wrote.exists(),"worker escaped the explicit barrier");
        evidence.push(json!({"stage":"failed_while_native_blocked","cause":cause,"retained":retained}));
        healthy = Some(router.ensure_worker_prepared(sibling.to_str().expect("UTF8 sibling"),
            None, None, Preparation::new(Duration::from_secs(30))).await?);
        let handle = &healthy.as_ref().expect("healthy acquisition").0;
        let before = router.route_request(Some(handle), "get_analysis_status", json!({})).await?;
        anyhow::ensure!(before["auto_is_ok"].is_boolean(), "healthy sibling unavailable before proof");
        evidence.push(json!({"stage":"healthy_sibling_before_late_proof","result":before}));
        std::fs::write(&release,b"")?;
        tokio::time::timeout(Duration::from_secs(5),async {
            while !wrote.exists(){tokio::time::sleep(Duration::from_millis(10)).await;}
        }).await?;
        evidence.push(json!({"stage":"native_wrote_after_failed_open","write":serde_json::from_slice::<Value>(&std::fs::read(&wrote)?)?}));
        let settled=tokio::time::timeout(Duration::from_secs(40),async {
            loop {
                let status=bridge.lifecycle_status();
                if status["startup_and_pre_attach"]==0 && status["resources"]==1 && status["retirement_acks"]==0 { evidence.push(json!({"stage":"public_grace_exit_settled","status":status}));break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await;
        evidence.push(json!({"stage":"after_grace_wait","status":bridge.lifecycle_status()}));
        settled?;
        let after = router.route_request(Some(handle), "get_analysis_status", json!({})).await?;
        anyhow::ensure!(after["auto_is_ok"].is_boolean(), "late proof disconnected healthy sibling");
        evidence.push(json!({"stage":"healthy_sibling_after_late_proof","result":after}));
        Ok(())
    }.await;
    std::fs::write(&release, b"").expect("finally release only this native startup");
    let healthy_cleanup = match healthy.take() {
        Some((_, token)) => router.nexus_close_token(&token).await,
        None => Ok(None),
    };
    let all_settled = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = bridge.lifecycle_status();
            if status["resources"] == 0
                && status["startup_and_pre_attach"] == 0
                && status["retirement_acks"] == 0
            {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let shutdown = bridge.shutdown().await;
    std::fs::write(root.join("startup-native-result.json"),serde_json::to_vec_pretty(&json!({
        "result":format!("{result:?}"),"healthy_cleanup":format!("{healthy_cleanup:?}"),
        "all_settled":all_settled.as_ref().ok(),"shutdown":format!("{shutdown:?}"),"evidence":evidence
    })).expect("encode startup evidence")).expect("write startup evidence");
    result.expect("native startup remains protected after WorkerStartError");
    healthy_cleanup.expect("healthy sibling releases independently");
    all_settled.expect("all physical resources and ACKs settle");
    shutdown.expect("natural helper shutdown after startup settlement");
}

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_request_uses_active_sibling_while_reference_is_releasing() {
    ida_mcp::router::nexus_tools::n7_fix2_publish::real_default_request_ignores_releasing_sibling()
        .await;
}
