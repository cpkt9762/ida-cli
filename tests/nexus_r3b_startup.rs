//! Verification-purpose startup through real cache preparation and retained ownership.
#![cfg(feature = "nexus-test-support")]
use ida_mcp::{
    nexus::*,
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Write,
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::PathBuf,
    time::Duration,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verification_without_handle_retains_exact_launch_copy_and_budget() {
    let root = PathBuf::from(std::env::var_os("R5_ROOT").expect("private startup case"));
    let envroot = PathBuf::from(std::env::var_os("R5_ENV").expect("fresh SDK env"));
    let phase = std::env::var("R3A_STARTUP_PHASE").expect("phase");
    let fault = std::env::var("R3F1_STARTUP_FAULT").expect("fault");
    let mut clock = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(root.join("clock"))
        .expect("private clock");
    clock.write_all(&0_u64.to_be_bytes()).expect("clock");
    let input = root.join("raw");
    std::fs::copy(envroot.join("fixtures/mini"), &input).expect("private input");
    let cache = envroot.join("cli-home/idb");
    std::fs::create_dir_all(&cache).expect("private cache");
    let hash =
        blake3::hash(&std::fs::read(&input).expect("input bytes")).to_hex()[..12].to_string();
    let legacy = cache.join(format!("legacy.{hash}.dylib.i64"));
    std::fs::copy(
        std::env::var_os("R3F1_SAMPLE").expect("read-only saved IDB input"),
        &legacy,
    )
    .expect("new private IDB copy");
    let original = std::fs::read(&legacy).expect("legacy bytes");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("N3_ENV_ROOT".into(), envroot.display().to_string());
    environment.insert(
        "IDA_CLI_HELPER_TEST_CLOCK".into(),
        root.join("clock").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: envroot.join("venv/bin/python"),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/nexus_client_fixture.py"),
            directory: root.join("ipc"),
            environment,
        })
        .await
        .expect("production bridge/helper");
    let mut events = bridge.subscribe();
    let mut evidence = Vec::new();
    let preparing = Preparation::new(Duration::from_secs(30));
    let cancel = preparing.cancel.clone();
    let opening_router = router.clone();
    let opening = tokio::spawn(async move {
        opening_router
            .ensure_worker_prepared(input.to_str().expect("path"), None, None, preparing)
            .await
    });
    let result:anyhow::Result<Value>=async {
        tokio::time::timeout(Duration::from_secs(8),async{
            while !root.join("startup.arrived").exists(){anyhow::ensure!(!opening.is_finished(),"verification ended before barrier");tokio::time::sleep(Duration::from_millis(5)).await;}
            Ok::<_,anyhow::Error>(())
        }).await??;
        let saved:Value=serde_json::from_slice(&std::fs::read(root.join("ipc/helper-state.json"))?)?;
        let launch=saved["items"].as_object().and_then(|m|m.values().find(|i|i["launch"].is_object())).ok_or_else(||anyhow::anyhow!("durable verification LaunchIntent missing"))?.clone();
        let acquisition:AcquisitionId=serde_json::from_value(launch["acquisition"].clone())?;
        anyhow::ensure!(acquisition.purpose==AcquisitionPurpose::Verification&&acquisition.ordinal==1,"ordinary startup cannot substitute for verification");
        let target=PathBuf::from(launch["launch"]["target"].as_str().ok_or_else(||anyhow::anyhow!("target"))?);
        let directory=target.parent().ok_or_else(||anyhow::anyhow!("copy directory"))?;
        let before=bridge.lifecycle_status();
        anyhow::ensure!(directory.join("input").exists()&&target.exists()&&!directory.join("closed").exists(),"copy disappeared before launch/owner proof");
        anyhow::ensure!(bridge.endpoint().transition(|s,_|s.acquisition_lease(&acquisition))?.is_none(),"barrier must precede acquired callback");
        anyhow::ensure!(!bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?,"live launch lost physical reservation");
        match fault.as_str(){
            "eof"=>bridge.terminate().await?,
            "cancel"=>{cancel.cancel();},
            "failure"=>{},
            _=>anyhow::bail!("unknown startup fault"),
        }
        if fault!="eof" {std::fs::write(root.join("startup.release"),b"")?;}
        let outcome=tokio::time::timeout(Duration::from_secs(4),opening).await??;
        anyhow::ensure!(outcome.is_err(),"failed verification revived final acquisition");
        let cause=format!("{outcome:?}");
        if fault=="failure" {anyhow::ensure!(cause.contains("controlled verification startup failure"),"original failure cause lost: {cause}");}
        if fault=="cancel" {anyhow::ensure!(cause.to_lowercase().contains("cancel"),"original cancel cause lost: {cause}");}
        anyhow::ensure!(!legacy.with_extension("").exists()&&std::fs::read(&legacy)?==original,"failed verification published input or modified original");
        if phase=="LaunchIntent"&&fault!="cancel" {
            // No Popen completion/public owner source exists. Never infer a
            // release proof from process absence or an empty registry suffix.
            anyhow::ensure!(target.exists()&&directory.join("input").exists(),"unproven LaunchIntent copy removed");
            anyhow::ensure!(!bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?,"unproved launch returned capacity");
            if fault=="failure"{bridge.terminate().await?;}
            bridge.test_detach_observer();clock.write_all_at(&301_u64.to_be_bytes(),0)?;
            let orphan=bridge.test_wait_injected_orphan().await?;
            let state:Value=serde_json::from_slice(&std::fs::read(root.join("ipc/helper-state.json"))?)?;
            let retained=&state["items"][launch["watch"].as_str().ok_or_else(||anyhow::anyhow!("watch"))?];
            anyhow::ensure!(retained.get("proof").is_none()&&retained["abandoned"]["record"]["kind"]=="ObservationAbandoned","absence fabricated proof");
            return Ok(json!({"cause":cause,"before":before,"retained":retained,"orphan":orphan,"expected_unproven_source":true}));
        }
        // A test client closes only the exact publicly discovered late worker.
        // It uses SDK requests; no owner proof or private errors are injected.
        let code=r#"
import json,os,sys,time
from ida_nexus import DatabaseHandle,DatabaseOpenOptions,discover_databases
deadline=time.monotonic()+8
while True:
    matches=[d.instance for d in discover_databases(timeout=.2)
             if os.path.realpath(d.instance.idb_path)==os.path.realpath(sys.argv[1]) and d.instance.record_id.endswith('-'+sys.argv[2])]
    assert len(matches)<=1,matches
    if matches:break
    assert time.monotonic()<deadline,'late verification worker never became ready'
    time.sleep(.005)
handle=DatabaseHandle.open(sys.argv[1],options=DatabaseOpenOptions(spawn=False,startup_timeout=8))
outcome=handle.close_outcome(wait_for_database=True,timeout=8)
assert outcome['owner_released'] is True,outcome
print(json.dumps({'owner_released':outcome['owner_released']}))
"#;
        // A cancelled live bridge may already close the late handle itself.
        let closed=bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?;
        if !closed && fault!="cancel" {
            let mut command=tokio::process::Command::new(envroot.join("venv/bin/python"));
            command.args(["-I","-B","-c",code,target.to_str().ok_or_else(||anyhow::anyhow!("target UTF8"))?,launch["launch"]["suffix"].as_str().ok_or_else(||anyhow::anyhow!("suffix"))?])
                .env("IDA_NEXUS_STATE_DIR",envroot.join("state")).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
            let child=ida_mcp::router::nexus_bridge::test_spawn_child(&mut command)?;
            let output=tokio::time::timeout(Duration::from_secs(12),ida_mcp::router::nexus_bridge::test_output_child(child)).await??;
            std::fs::write(root.join("external-close.json"),&output.stdout)?;
            anyhow::ensure!(output.status.success(),"late public close failed: {}",String::from_utf8_lossy(&output.stderr));
        }
        tokio::time::timeout(Duration::from_secs(8),async{
            loop {
                while let Ok(event)=events.try_recv(){anyhow::ensure!(event["event"]!="opened","failed verification published final");evidence.push(event);}
                if bridge.endpoint().transition(|s,_|s.acquisition_closed(&acquisition))?&&!target.exists()&&!directory.join("input").exists(){break Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        anyhow::ensure!(!legacy.with_extension("").exists()&&std::fs::read(&legacy)?==original,"late responsibility revived business");
        let settled=bridge.lifecycle_status();bridge.shutdown().await?;
        Ok(json!({"cause":cause,"acquisition":acquisition,"before":before,"settled":settled,"budget_secs":30,"copy_payload_removed":true,"scope":"actual private IDA verification, LaunchIntent/Popen before acquired, RetainedOpen verification cleanup"}))
    }.await;
    let forced = if result.is_err() {
        let _ = bridge.terminate().await;
        Some(
            bridge
                .test_helper_fault(true)
                .await
                .expect("exact own failed helper"),
        )
    } else {
        None
    };
    std::fs::write(root.join("verification-startup.json"),serde_json::to_vec_pretty(&json!({"phase":phase,"fault":fault,"result":format!("{result:?}"),"evidence":evidence,"forced":forced})).expect("evidence")).expect("write evidence");
    result.expect("verification startup responsibility and precise cleanup");
}
