//! R5 startup rejection and one real tiny IDA chain. Fresh isolated roots only.
use ida_mcp::{
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[tokio::test]
async fn readiness_rejects_before_any_grant_and_reaps_exact_child() {
    let base = PathBuf::from(std::env::var_os("R5_ROOT").expect("private R5 root"));
    let mut records = Vec::new();
    for fault in [
        "missing-wire",
        "missing-schema",
        "missing-release",
        "missing-open",
        "missing-owner_observation",
        "missing-client_hash",
        "missing-sdk_boundary",
        "missing-client_modules",
        "sdk_boundary",
        "module-handle",
        "module-resolver",
        "module-options",
        "module-missing",
        "module-extra",
        "missing-capabilities",
        "wire",
        "schema",
        "release",
        "open",
        "owner_observation",
        "wrong-hash",
        "unknown-capability",
        "missing-capability",
        "duplicate-capability",
        "wrong-home",
        "old-wire",
        "bool-wire",
        "unknown-field",
        "relative-state",
        "sdk-version",
        "domain-version",
    ] {
        let root = base.join(fault);
        std::fs::create_dir(&root).expect("new case");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R5_ROOT".into(), root.display().to_string());
        environment.insert("R5_FAULT".into(), fault.into());
        let router = RouterState::new().expect("router");
        let result = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("F1_PYTHON").expect("prepared Python")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r5_readiness_fixture.py"),
                directory: root.join("ipc"),
                environment,
            })
            .await;
        let error = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("incompatible readiness accepted: {fault}"),
        };
        assert!(
            error.contains("ProtocolMismatch"),
            "wrong rejection boundary for {fault}: {error}"
        );
        let process: Value = serde_json::from_slice(
            &std::fs::read(root.join("process.json")).expect("registered own child"),
        )
        .expect("process identity");
        let pid = i32::try_from(process["pid"].as_i64().expect("pid")).expect("native pid");
        tokio::time::timeout(Duration::from_secs(3), async {
            // SAFETY: signal zero only queries our registered child; no signal is sent.
            loop {
                if unsafe { libc::kill(pid, 0) } != 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("exact rejected child reaped");
        tokio::time::timeout(Duration::from_secs(3), async {
            while ["b", "c", "l"]
                .iter()
                .any(|n| root.join("ipc").join(n).exists())
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("own startup endpoints removed");
        records.push(json!({"fault":fault,"rejected":error,"pid":pid,"reaped":true,"grants":0,"physical_acquisitions":0}));
    }
    std::fs::write(
        base.join("readiness-rejections.json"),
        serde_json::to_vec_pretty(&records).expect("encode cases"),
    )
    .expect("write evidence");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_tiny_default_home_open_query_close() {
    let root = PathBuf::from(std::env::var_os("R5_ROOT").expect("private real root"));
    let sample = root.join("tiny");
    let envroot = PathBuf::from(std::env::var_os("R5_ENV").expect("fresh prepared environment"));
    std::fs::copy(envroot.join("fixtures/mini"), &sample).expect("private tiny sample copy");
    let router = RouterState::new().expect("real RouterState");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.remove("IDA_CLI_HOME");
    environment.insert("N3_ENV_ROOT".into(), envroot.display().to_string());
    environment.insert(
        "IDAPYTHON_VENV_EXECUTABLE".into(),
        envroot.join("venv/bin/python").display().to_string(),
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
        .expect("production Rust readiness with unset IDA_CLI_HOME");
    let mut custody_events = bridge.subscribe();
    // Tools must agree with the startup default. This test process has no explicit home.
    let (handle, token) = router
        .ensure_worker_prepared(
            sample.to_str().expect("path"),
            None,
            None,
            Preparation::new(Duration::from_secs(60)),
        )
        .await
        .expect("production Tools real IDA open");
    let result = router
        .route_request(Some(&handle), "get_database_info", json!({}))
        .await
        .expect("production real IDA query");
    router
        .nexus_close_token(&token)
        .await
        .expect("production real tiny close");
    let mut evidence = Vec::new();
    let settlement = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = custody_events.recv().await.expect("real custody event");
            let settled = event["event"] == "custody_settled";
            evidence.push(event);
            if settled {
                break;
            }
        }
    })
    .await;
    std::fs::write(
        root.join("custody-events.json"),
        serde_json::to_vec_pretty(&evidence).expect("custody evidence JSON"),
    )
    .expect("custody evidence");
    settlement.expect("public proof and both producers must settle before shutdown");
    bridge.shutdown().await.expect("normal bridge shutdown");
    std::fs::write(root.join("real-result.json"),serde_json::to_vec_pretty(&json!({"scope":"R5-production-tiny","query":result,"default_home":ida_mcp::idb_store::ida_home()})).expect("encode evidence")).expect("write evidence");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_tiny_startup_bridge_fault_keeps_exact_launch_obligation() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let root = PathBuf::from(std::env::var_os("R5_ROOT").expect("private root"));
    let envroot = PathBuf::from(std::env::var_os("R5_ENV").expect("prepared root"));
    let phase = std::env::var("R3A_STARTUP_PHASE").expect("startup barrier phase");
    let clock_path = root.join("clock");
    let mut clock = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&clock_path)
        .expect("private injected clock");
    clock.write_all(&0_u64.to_be_bytes()).expect("clock offset");
    let sample = root.join("tiny");
    std::fs::copy(envroot.join("fixtures/mini"), &sample).expect("private tiny copy");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.remove("IDA_CLI_HOME");
    environment.insert("N3_ENV_ROOT".into(), envroot.display().to_string());
    environment.insert(
        "IDA_CLI_HELPER_TEST_CLOCK".into(),
        clock_path.display().to_string(),
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
        .expect("verified bridge/helper");
    let mut events = bridge.subscribe();
    let opening_router = router.clone();
    let opening = tokio::spawn(async move {
        opening_router
            .ensure_worker_prepared(
                sample.to_str().expect("sample"),
                None,
                None,
                Preparation::new(Duration::from_secs(30)),
            )
            .await
    });
    let mut evidence = Vec::new();
    let result=async {
        tokio::time::timeout(Duration::from_secs(10),async {
            while !root.join("startup.arrived").exists() {
                anyhow::ensure!(!opening.is_finished(),"open ended before startup barrier");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<(),anyhow::Error>(())
        }).await??;
        let saved:Value=serde_json::from_slice(&std::fs::read(root.join("ipc/helper-state.json"))?)?;
        let item=saved["items"].as_object().and_then(|m|m.values().find(|i|i["launch"].is_object()))
            .ok_or_else(||anyhow::anyhow!("durable launch missing before Popen/stage barrier"))?.clone();
        anyhow::ensure!(item["receipt"]["record"]["kind"] == "SpawnIntent","intent not signed");
        let acquired=evidence.iter().any(|e:&Value|e["event"] == "opened");
        anyhow::ensure!(!acquired,"startup barrier acquired a lease prematurely");
        if matches!(phase.as_str(),"Spawned"|"LogReady"|"Ready") {
            anyhow::ensure!(item["spawned"]["record"]["os_identity"]["birth"].is_array(),"exact birth not signed before log/ready");
        } else {
            anyhow::ensure!(item.get("spawned").is_none(),"birth synthesized before Spawned callback");
        }
        bridge.terminate().await?; // Exact bridge fault, never the IDA owner.
        let outcome=tokio::time::timeout(Duration::from_secs(5),opening).await??;
        anyhow::ensure!(outcome.is_err(),"bridge EOF revived a successful open");
        if phase == "LaunchIntent" {
            bridge.test_detach_observer();
            use std::os::unix::fs::FileExt;
            clock.write_all_at(&301_u64.to_be_bytes(),0)?;
            let exit=bridge.test_wait_injected_orphan().await?;
            std::fs::write(root.join("orphan-exit.json"),serde_json::to_vec_pretty(&exit)?)?;
            let saved:Value=serde_json::from_slice(&std::fs::read(root.join("ipc/helper-state.json"))?)?;
            let abandoned=&saved["items"][item["watch"].as_str().ok_or_else(||anyhow::anyhow!("watch missing"))?];
            anyhow::ensure!(abandoned.get("proof").is_none() && abandoned["abandoned"]["record"]["kind"] == "ObservationAbandoned",
                "startup-only orphan was erased or converted to release");
            std::fs::write(root.join("startup-evidence.json"),serde_json::to_vec_pretty(&saved)?)?;
        } else {
            let code=r#"
import json,os,sys,time
from ida_nexus import DatabaseHandle,DatabaseOpenOptions,discover_databases
deadline=time.monotonic()+10
while True:
    matches=[d.instance for d in discover_databases(timeout=.2)
             if os.path.realpath(d.instance.idb_path)==os.path.realpath(sys.argv[1])
             and d.instance.record_id.endswith('-'+sys.argv[2])]
    assert len(matches)<=1,matches
    if matches:break
    assert time.monotonic()<deadline,'late worker never became publicly ready'
    time.sleep(.005)
handle=DatabaseHandle.open(sys.argv[1],options=DatabaseOpenOptions(spawn=False,startup_timeout=10))
outcome=handle.close_outcome(wait_for_database=True,timeout=10)
assert outcome['owner_released'] is True,outcome
print(json.dumps({'owner_released':outcome['owner_released'],'lease_released':outcome['lease_released']}))
"#;
            let mut command=tokio::process::Command::new(envroot.join("venv/bin/python"));
            command.args(["-I","-B","-c",code,item["launch"]["target"].as_str().ok_or_else(||anyhow::anyhow!("launch target missing"))?,
                    item["launch"]["suffix"].as_str().ok_or_else(||anyhow::anyhow!("launch suffix missing"))?])
                .env("IDA_NEXUS_STATE_DIR",envroot.join("state"))
                .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            let child=ida_mcp::router::nexus_bridge::test_spawn_child(&mut command)?;
            let output=tokio::time::timeout(Duration::from_secs(15),ida_mcp::router::nexus_bridge::test_output_child(child)).await??;
            std::fs::write(root.join("external-close.json"),&output.stdout)?;
            anyhow::ensure!(output.status.success(),"private late worker close failed: {}",String::from_utf8_lossy(&output.stderr));
            tokio::time::timeout(Duration::from_secs(8),async {
                loop {
                    let event=events.recv().await?;
                    let settled=event["event"] == "startup_settled";
                    evidence.push(event);
                    if settled {break Ok::<(),anyhow::Error>(());}
                }
            }).await??;
            bridge.shutdown().await?;
            let helpers_before = std::fs::read(root.join("ipc/helper-state.json"))?;
            // A late poll used to reconnect the successfully finished helper.
            // Exercise that exact production path, rather than sleeping and
            // hoping the background heartbeat happens to win the race.
            anyhow::ensure!(bridge.test_finished_helper_heartbeat().await.is_err(),
                "heartbeat revived a successfully finished helper");
            anyhow::ensure!(!root.join("ipc/h").exists(), "finished helper endpoint remains live");
            anyhow::ensure!(std::fs::read(root.join("ipc/helper-state.json"))? == helpers_before,
                "late heartbeat rewrote finished helper registry");
        }
        Ok::<(),anyhow::Error>(())
    }.await;
    std::fs::write(
        root.join("startup-events.json"),
        serde_json::to_vec_pretty(&evidence).expect("evidence JSON"),
    )
    .expect("events");
    let forced = if result.is_err() {
        Some(
            bridge
                .test_helper_fault(true)
                .await
                .expect("exact failed helper cleanup"),
        )
    } else {
        None
    };
    std::fs::write(root.join("startup-audit.json"),serde_json::to_vec_pretty(&json!({"phase":phase,
        "error":result.as_ref().err().map(ToString::to_string),"forced_failed_case_cleanup":forced})).expect("audit JSON")).expect("audit");
    result.expect("startup responsibility survives exact bridge fault");
}
