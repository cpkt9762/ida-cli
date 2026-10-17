//! Production custody/preparation with the fixed SDK and independent observer.
use ida_mcp::{
    nexus::*,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[test]
fn public_owner_birth_timestamp_survives_both_json_hops() {
    // Actual Python public started_at from the failing routine round. Exact
    // OwnerKey equality must survive bridge -> Rust -> target writer.
    let source = r#"{"started_at":1792260249.6594481}"#;
    let parsed: Value = serde_json::from_str(source).expect("public owner JSON");
    assert_eq!(
        parsed["started_at"]
            .as_f64()
            .expect("public timestamp")
            .to_bits(),
        1792260249.6594481_f64.to_bits(),
        "JSON parser changed exact physical identity"
    );
    let roundtrip = serde_json::to_string(&parsed).expect("owner forward JSON");
    assert_eq!(
        roundtrip, source,
        "target writer would receive a different public identity"
    );
}

#[tokio::test]
async fn final_preparation_and_f4_keep_exact_physical_responsibility() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ida_mcp=debug")
        .with_test_writer()
        .try_init();
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private test root"));
    for scenario in [
        "healthy",
        "early-analysis",
        "backup-source",
        "proof-ack-barrier",
    ] {
        let root = base.join(scenario);
        std::fs::create_dir_all(&root).expect("private scenario root");
        let router = RouterState::new().expect("real RouterState");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
        environment.insert("R3A_SCENARIO".into(), scenario.into());
        environment.insert("HOME".into(), root.join("home").display().to_string());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK Python")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r3a_bridge_fixture.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("verified installed production bridge + helper");
        let mut evidence = Vec::new();
        let result = case(&bridge, &root, scenario, 0, &mut evidence).await;
        // Always release only our private input owner and wait our exact child.
        std::fs::write(root.join("owner-release"), b"").expect("finally release private owner");
        std::fs::write(root.join("proof-ack.release"), b"")
            .expect("finally release private proof barrier");
        let stopped = bridge.shutdown().await;
        let forced = if stopped.is_err() {
            Some(
                bridge
                    .test_helper_fault(true)
                    .await
                    .expect("bounded exact failed-case helper cleanup"),
            )
        } else {
            None
        };
        std::fs::write(
            root.join("events.json"),
            serde_json::to_vec_pretty(&evidence).expect("event JSON"),
        )
        .expect("event evidence");
        std::fs::write(root.join("audit.json"), serde_json::to_vec_pretty(&json!({
            "shutdown":stopped.as_ref().err().map(ToString::to_string), "forced_failed_case_cleanup":forced,
        })).expect("audit JSON")).expect("audit evidence");
        result.expect("production case assertions; cleanup and events saved first");
        stopped.expect("natural bridge/helper shutdown; forced cleanup is never a pass");
    }
}

async fn case(
    bridge: &std::sync::Arc<ida_mcp::router::nexus_bridge::NexusBridge>,
    root: &std::path::Path,
    scenario: &str,
    round: usize,
    evidence: &mut Vec<Value>,
) -> anyhow::Result<()> {
    let mut events = bridge.subscribe();
    let client = ClientId::new(format!("r3a-{scenario}"))?;
    let identity = bridge.endpoint().transition(|s, t| {
        s.open(
            &client,
            AcceptedRequest::new(
                &SystemClock,
                RequestId::new(format!("open-{round}"))?,
                None,
                "open",
                json!({"timeout_secs":15}),
            )?,
            OpenSpec {
                operation_id: OperationId::new(format!("open-{round}"))?,
                path: target_path(root).display().to_string(),
                options: json!({"spawn":false,"wait_analysis":true}),
            },
            t,
        )
    })?;
    let terminal = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let event = events.recv().await?;
            evidence.push(event.clone());
            if ["opened", "failed", "uncertain", "remote_error"]
                .iter()
                .any(|n| event["event"] == *n)
                && event["attempt"]["target"]["kind"] == "open"
            {
                break Ok::<Value, anyhow::Error>(event);
            }
        }
    })
    .await??;
    let (lease, failure) = bridge
        .endpoint()
        .transition(|s, _| s.open_progress(&client, &identity))?;
    let lease = lease.ok_or_else(|| {
        anyhow::anyhow!("F4 must retain actual acquired lease; terminal={terminal}")
    })?;
    let status = bridge
        .endpoint()
        .transition(|s, _| s.status(&client, &lease))?;
    let successful_terminal = terminal["event"] == "opened";
    let healthy = scenario != "early-analysis";
    if healthy && successful_terminal {
        anyhow::ensure!(terminal["event"] == "opened", "{terminal}");
        anyhow::ensure!(failure.is_none(), "healthy parent failed: {failure:?}");
        anyhow::ensure!(status.phase == SessionPhase::Active, "{status:?}");
        bridge
            .endpoint()
            .transition(|s, t| s.release(&client, &lease, t))?;
    } else if scenario == "early-analysis" {
        anyhow::ensure!(terminal["event"] == "failed", "{terminal}");
        anyhow::ensure!(failure.is_some(), "F4 parent failure lost");
        std::fs::write(root.join("snapshot-request"), b"")?;
        wait_for(|| Ok(root.join("snapshot.json").is_file())).await?;
        let snapshot: Value = serde_json::from_slice(&std::fs::read(root.join("snapshot.json"))?)?;
        anyhow::ensure!(
            snapshot["analysis_failed"] == true && snapshot["physical_leases"] == 1,
            "original F4 physical acquired lease/analysis failure changed: {snapshot}"
        );
        anyhow::ensure!(
            snapshot["requests"]
                .as_array()
                .is_some_and(|requests| !requests
                    .iter()
                    .any(|r| r["endpoint"] == "/release_lease")),
            "failed fresh cleanup cannot invent a detach: {snapshot}"
        );
        anyhow::ensure!(
            matches!(
                status.phase,
                SessionPhase::ReleaseRequired | SessionPhase::ReleaseRequested
            ),
            "{status:?}"
        );
    }
    if healthy {
        wait_for(|| Ok(root.join("release-requested").exists())).await?;
    }
    if scenario == "backup-source" {
        let paused = bridge.test_helper_pause().await?;
        std::fs::write(
            root.join("paused-helper.json"),
            serde_json::to_vec_pretty(&paused)?,
        )?;
    }
    std::fs::write(root.join("owner-release"), b"")?;
    if scenario == "backup-source" {
        wait_for(|| Ok(root.join("owner-released").exists())).await?;
        let fault = bridge.test_helper_fault(false).await?;
        std::fs::write(root.join("fault.json"), serde_json::to_vec_pretty(&fault)?)?;
    }
    if scenario == "proof-ack-barrier" {
        wait_for(|| Ok(root.join("proof-ack.arrived").exists())).await?;
        let snapshot: Value =
            serde_json::from_slice(&std::fs::read(root.join("proof-source-snapshot.json"))?)?;
        anyhow::ensure!(
            snapshot["original_instances"]
                .as_u64()
                .is_some_and(|n| n > 0)
                && snapshot["custody_originals"]
                    .as_u64()
                    .is_some_and(|n| n > 0),
            "original public source dropped before durable ACK: {snapshot}"
        );
        let proof = PathBuf::from(
            snapshot["proof_path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("proof path missing"))?,
        );
        anyhow::ensure!(proof.is_file(), "unacknowledged proof was removed");
        let coord = proof
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .ok_or_else(|| anyhow::anyhow!("proof namespace missing"))?;
        let journal: Value = serde_json::from_slice(&std::fs::read(coord.join("custody.json"))?)?;
        anyhow::ensure!(
            !journal["entries"].as_object().is_some_and(|m| m.is_empty()),
            "unacknowledged producer was compacted"
        );
        std::fs::write(root.join("proof-ack.release"), b"")?;
    }
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let event: Value = events.recv().await?;
            evidence.push(event.clone());
            if event["event"] == "custody_settled" {
                break Ok::<(), anyhow::Error>(());
            }
        }
    })
    .await??;
    anyhow::ensure!(
        bridge
            .endpoint()
            .transition(|s, _| s.status(&client, &lease))?
            .phase
            == SessionPhase::Released,
        "N1 exact physical owner not released"
    );
    if healthy {
        anyhow::ensure!(successful_terminal, "{terminal}");
    }
    if scenario == "backup-source" {
        anyhow::ensure!(
            evidence
                .iter()
                .any(|event| event["event"] == "owner_released"
                    && event["proof"]["record"]["source"] == "bridge_original"),
            "backup original public source was not consumed"
        );
    }
    Ok(())
}

fn target_path(root: &std::path::Path) -> PathBuf {
    let managed = root.join("cache/generations/g-fixed/input.i64");
    if managed.exists() {
        managed
    } else {
        root.join("tiny.i64")
    }
}

#[tokio::test]
async fn no_handle_terminal_attempt_and_unknown_attach_have_distinct_custody() {
    for scenario in [
        "attach-rejected",
        "attach-eof",
        "early-cancel",
        "helper-crash",
        "analysis-eof",
        "analysis-cancel",
        "monitor-start",
        "custody-ack-loss",
        "custody-ack-loss-cancel",
        "callback-ack-error",
        "analysis-http-timeout",
        "preparation-not-sent",
    ] {
        acquisition_fault(scenario).await;
    }
}

async fn acquisition_fault(scenario: &str) {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private fault root"))
        .join(scenario);
    std::fs::create_dir_all(&root).expect("private fault directory");
    let router = RouterState::new().expect("real router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    for (key, value) in [
        ("R3A_CASE_ROOT", root.clone()),
        ("HOME", root.join("home")),
        ("IDA_NEXUS_STATE_DIR", root.join("state")),
    ] {
        environment.insert(key.into(), value.display().to_string());
    }
    environment.insert("R3A_SCENARIO".into(), scenario.into());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed Python")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("production bridge/helper");
    let mut events = bridge.subscribe();
    let mut evidence = Vec::new();
    let result = async {
        let client = ClientId::new("fault-client")?;
        let identity = bridge.endpoint().transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("fault-open")?,
                    None,
                    "open",
                    json!({"timeout_secs":match scenario {"analysis-http-timeout"=>8,"preparation-not-sent"=>4,_=>15}}),
                )?,
                OpenSpec {
                    operation_id: OperationId::new("fault-open")?,
                    path: root.join("tiny.i64").display().to_string(),
                    options: json!({"spawn":false,"wait_analysis":true}),
                },
                t,
            )
        })?;
        if scenario == "early-cancel" {
            wait_for(|| Ok(root.join("attach-response.arrived").exists())).await?;
            bridge
                .endpoint()
                .transition(|s, _| s.cancel_open(&client, &identity))?;
            std::fs::write(root.join("attach-response.release"), b"")?;
        }
        if scenario == "custody-ack-loss-cancel" {
            wait_for(||Ok(root.join("custody-ack-fault").exists())).await?;
            bridge.endpoint().transition(|s,_|s.cancel_open(&client,&identity))?;
        }
        if matches!(scenario, "helper-crash" | "analysis-cancel") {
            wait_for(|| Ok(root.join("analysis.arrived").exists())).await?;
            let coord = std::fs::read_dir(&root)?.filter_map(Result::ok)
                .find(|entry|entry.file_name().to_string_lossy().starts_with(".ida-cli-txn-"))
                .ok_or_else(||anyhow::anyhow!("actual coordination root missing"))?.path();
            let independent_lock = std::fs::OpenOptions::new().read(true).write(true).open(coord.join("lock"))?;
            use std::os::fd::AsRawFd;
            // SAFETY: this valid test-owned descriptor is held across flock.
            if unsafe { libc::flock(independent_lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            drop(independent_lock);
            if scenario == "helper-crash" {
                // A second process performs real fixed-SDK attach while the
                // first acquisition is stopped inside analysis. Both use the
                // same verified target gate and exact public owner.
                let script = r#"
import json,runpy,sys
from pathlib import Path
root=Path(sys.argv[1])
sys.argv=[str(root/'i/installation/bootstrap.py'),'target_journal']
module=runpy.run_path(sys.argv[0],run_name='verified_second_opener')['load_entry']()
from owner_identity import state_identity
from ida_nexus import DatabaseHandle,DatabaseOpenOptions
with module.Target(root/'tiny.i64') as target:
 with target.locked(nb=True):
  module.Journal(target).gate(state_identity())
  outcome=DatabaseHandle.open_outcome(str(root/'tiny.i64'),options=DatabaseOpenOptions(spawn=False))
  handle=outcome['handle']
  assert outcome['cause'] is None and handle is not None,outcome['failure_kind']
  handle.claim_acquired()
try:
 closed=handle.close_outcome(wait_for_database=False,timeout=1)
 assert closed['lease_released'] is True,closed
 print(json.dumps({'attached':True,'lease_released':closed['lease_released'],'owner_pending':closed['owner_pending']}))
finally:
 handle.close_outcome(wait_for_database=False,timeout=1)
"#;
                let mut command = tokio::process::Command::new(
                    std::env::var_os("R3A_PYTHON").expect("fixed Python"));
                command.args(["-I", "-B", "-c", script]).arg(&root)
                    .env("IDA_NEXUS_STATE_DIR", root.join("state"))
                    .env("HOME", root.join("home")).kill_on_drop(true);
                let output = tokio::time::timeout(Duration::from_secs(5), command.output()).await??;
                std::fs::write(root.join("second-opener.json"), &output.stdout)?;
                anyhow::ensure!(output.status.success(), "second opener failed: {}", String::from_utf8_lossy(&output.stderr));
                let fault = bridge.test_helper_fault(false).await?;
                std::fs::write(root.join("fault.json"), serde_json::to_vec_pretty(&fault)?)?;
            } else {
                bridge.endpoint().transition(|s,_|s.cancel_open(&client,&identity))?;
            }
            std::fs::write(root.join("analysis.release"), b"")?;
        }
        let terminal = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let event = events.recv().await?;
                evidence.push(event.clone());
                if event["attempt"]["target"]["kind"] == "open"
                    && ["opened", "failed", "uncertain", "remote_error"]
                        .iter()
                        .any(|name| event["event"] == *name)
                {
                    break Ok::<Value, anyhow::Error>(event);
                }
            }
        })
        .await??;
        let (lease, _) = bridge
            .endpoint()
            .transition(|s, _| s.open_progress(&client, &identity))?;
        if scenario == "attach-rejected" {
            anyhow::ensure!(lease.is_none(), "rejected attach acquired a lease");
            anyhow::ensure!(terminal["event"] == "failed", "typed lease_absent must have a definite failed parent");
            // The owner is still alive. Only the typed no-attach watch can close.
            tokio::time::timeout(Duration::from_secs(4), async {
                loop {
                    let event = events.recv().await?;
                    evidence.push(event.clone());
                    if event["event"] == "custody_settled" {
                        break Ok::<(), anyhow::Error>(());
                    }
                }
            })
            .await??;
            anyhow::ensure!(
                !root.join("owner-released").exists(),
                "no-attach fabricated public release"
            );
        } else {
            if scenario == "attach-eof" {
                anyhow::ensure!(lease.is_none(), "unknown attach must not invent handle");
                anyhow::ensure!(
                    !evidence.iter().any(|e| e["event"] == "custody_settled"),
                    "unknown attach responsibility vanished"
                );
            } else {
                let lease = lease
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("actual acquired handle lost: {terminal}"))?;
                if matches!(scenario, "helper-crash" | "custody-ack-loss") {
                    anyhow::ensure!(
                        terminal["event"] == "opened",
                        "helper reconnect failed preparation: {terminal}"
                    );
                    bridge
                        .endpoint()
                        .transition(|s, t| s.release(&client, lease, t))?;
                    wait_for(|| Ok(root.join("release-requested").exists())).await?;
                } else {
                    anyhow::ensure!(terminal["event"] != "opened", "cancelled parent revived");
                }
                if matches!(scenario,"analysis-eof" | "analysis-http-timeout") {
                    let uncertain = evidence.iter().find(|event|event["event"] == "uncertain"
                        && event["attempt"]["target"]["kind"] == "execute")
                        .ok_or_else(||anyhow::anyhow!("exact internal uncertain fact missing"))?;
                    let operation:OperationIdentity = serde_json::from_value(uncertain["attempt"]["target"]["identity"].clone())?;
                    let snapshot = bridge.endpoint().transition(|s,_|s.operation_progress(&client,&operation))?;
                    anyhow::ensure!(!snapshot.execution_stopped,"transport EOF fabricated internal stop");
                    anyhow::ensure!(!root.join("release-requested").exists(),"detach sent before exact internal stop");
                }
            }
            std::fs::write(root.join("owner-release"), b"")?;
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    let event = events.recv().await?;
                    evidence.push(event.clone());
                    if event["event"] == "custody_settled" {
                        break Ok::<(), anyhow::Error>(());
                    }
                }
            })
            .await??;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    for name in [
        "owner-release",
        "attach-response.release",
        "analysis.release",
        "analysis-timeout.release",
    ] {
        std::fs::write(root.join(name), b"").expect("finally release private input barriers");
    }
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
    std::fs::write(
        root.join("events.json"),
        serde_json::to_vec_pretty(&evidence).expect("events JSON"),
    )
    .expect("events evidence");
    std::fs::write(root.join("audit.json"),serde_json::to_vec_pretty(&json!({"error":result.as_ref().err().map(ToString::to_string),
        "shutdown":stopped.as_ref().err().map(ToString::to_string),"forced_failed_case_cleanup":forced})).expect("audit JSON")).expect("audit");
    result.expect("real cross-process exact custody assertions");
    stopped.expect("natural cleanup");
    if matches!(
        scenario,
        "early-cancel" | "custody-ack-loss-cancel" | "preparation-not-sent"
    ) {
        let requests: Value = serde_json::from_slice(
            &std::fs::read(root.join("requests.json")).expect("native inputs evidence"),
        )
        .expect("requests JSON");
        for request in requests.as_array().expect("requests list") {
            assert_ne!(
                request["endpoint"], "/wait_autoanalysis",
                "early cancellation dispatched analysis"
            );
            if request["endpoint"] == "/execute_python" {
                assert!(
                    request["code"]
                        .as_str()
                        .expect("public code")
                        .contains("result = module.release_lease("),
                    "early cancellation dispatched preparation instead of exact cleanup"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tools_future_drop_keeps_acquired_preparation_custody() {
    use ida_mcp::preprocess::Preparation;
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private Tools root"));
    std::fs::create_dir_all(&root).expect("private root");
    let router = RouterState::new().expect("real router");
    assert!(
        router.uses_nexus(),
        "run this isolated target with IDA_CLI_NEXUS_DEV=1"
    );
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_SCENARIO".into(), "tools-barrier".into());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed Python")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("installed production bridge/helper");
    let mut events = bridge.subscribe();
    let opening_router = router.clone();
    let path = root.join("tiny.i64");
    let mut opening = tokio::spawn(async move {
        opening_router
            .ensure_worker_prepared(
                path.to_str().expect("path"),
                None,
                None,
                Preparation::new(Duration::from_secs(15)),
            )
            .await
    });
    let mut evidence = Vec::new();
    let result = async {
        tokio::select! {
            reached = wait_for(|| Ok(root.join("analysis.arrived").exists())) => reached?,
            completed = &mut opening => anyhow::bail!("Tools completed before preparation barrier: {completed:?}"),
        }
        opening.abort();
        anyhow::ensure!(
            opening.await.is_err_and(|e| e.is_cancelled()),
            "Tools future did not drop"
        );
        std::fs::write(root.join("analysis.release"), b"")?;
        wait_for(|| Ok(root.join("release-requested").exists())).await?;
        // Detach ACK and dropped caller do not prove owner exit.
        std::fs::write(root.join("owner-release"), b"")?;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let event = events.recv().await?;
                let settled = event["event"] == "custody_settled";
                evidence.push(event);
                if settled {
                    break Ok::<(), anyhow::Error>(());
                }
            }
        })
        .await??;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    for name in ["owner-release", "analysis.release"] {
        std::fs::write(root.join(name), b"").expect("finally release owned inputs");
    }
    std::fs::write(
        root.join("events.json"),
        serde_json::to_vec_pretty(&evidence).expect("events JSON"),
    )
    .expect("events");
    let stopped = bridge.shutdown().await;
    let forced = if stopped.is_err() {
        Some(
            bridge
                .test_helper_fault(true)
                .await
                .expect("exact failed helper cleanup"),
        )
    } else {
        None
    };
    std::fs::write(root.join("audit.json"),serde_json::to_vec_pretty(&json!({"error":result.as_ref().err().map(ToString::to_string),
        "shutdown":stopped.as_ref().err().map(ToString::to_string),"forced_failed_case_cleanup":forced})).expect("audit JSON")).expect("audit");
    result.expect("future drop preserves resource custody until public proof");
    stopped.expect("natural cleanup");
}

async fn wait_for(mut condition: impl FnMut() -> anyhow::Result<bool>) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if condition()? {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn direct_fixed_target_128_healthy_epochs_are_bounded() {
    routine(false).await;
}

#[tokio::test]
async fn managed_fixed_target_128_healthy_epochs_and_gc_are_bounded() {
    routine(true).await;
}

async fn routine(managed: bool) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ida_mcp=warn")
        .with_test_writer()
        .try_init();
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private test root"));
    let root = base.join(if managed {
        "managed-routine"
    } else {
        "direct-routine"
    });
    std::fs::create_dir_all(&root).expect("private routine root");
    let router = RouterState::new().expect("real router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
    environment.insert("R3A_SCENARIO".into(), "healthy".into());
    environment.insert("R3A_MANAGED".into(), if managed { "1" } else { "0" }.into());
    environment.insert("HOME".into(), root.join("home").display().to_string());
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK Python")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("real installed bridge/helper");
    let mut evidence = Vec::new();
    let mut stats = Vec::new();
    let result = async {
        use std::os::unix::fs::MetadataExt;
        let mut stable = None;
        for round in 0..128 {
            case(&bridge, &root, "healthy", round, &mut evidence).await?;
            let owner_event = evidence.iter().rev().find(|e|e["event"] == "owner_released")
                .ok_or_else(||anyhow::anyhow!("public owner event missing"))?;
            let path = PathBuf::from(owner_event["proof"]["path"].as_str().ok_or_else(||anyhow::anyhow!("proof path missing"))?);
            let coord = path.parent().and_then(|p|p.parent()).and_then(|p|p.parent()).ok_or_else(||anyhow::anyhow!("fixed coord parent missing"))?;
            let journal: Value = serde_json::from_slice(&std::fs::read(coord.join("custody.json"))?)?;
            anyhow::ensure!(journal["entries"].as_object().is_some_and(|m|m.is_empty()), "routine live refs remain: {journal}");
            anyhow::ensure!(journal["closed_through"] == round+1 && journal["next_epoch"] == round+2, "epoch watermark regressed");
            anyhow::ensure!(journal["summary"].as_array().is_some_and(|a|a.len() <= 64), "summary is unbounded");
            anyhow::ensure!(journal["closed_after_holes"] == json!([]) && journal["compaction"].is_null(), "closed holes/intent remain");
            let lock = std::fs::symlink_metadata(coord.join("lock"))?;
            let identity = (lock.dev(), lock.ino());
            if let Some(old) = stable { anyhow::ensure!(old == identity, "stable target lock was replaced"); }
            stable = Some(identity);
            let mut files = Vec::new();
            collect_files(coord, &mut files)?;
            let bytes: u64 = files.iter().map(|p|std::fs::metadata(p).map(|m|m.len())).collect::<std::io::Result<Vec<_>>>()?.iter().sum();
            anyhow::ensure!(files.len() == 3 && bytes < 32768, "healthy target records grew: files={} bytes={bytes}", files.len());
            stats.push(json!({"round":round+1,"files":files.len(),"bytes":bytes,"lock":[identity.0,identity.1],"summary":journal["summary"].as_array().map(Vec::len)}));
            if managed {
                gc(&root, round+1, u64::MAX, 1000+round).await?;
            }
            if round != 127 {
                std::fs::write(root.join("next-owner"), (round+1).to_string())?;
                wait_for(|| Ok(std::fs::read_to_string(root.join("owner-generation")).ok().as_deref() == Some((round+1).to_string().as_str()))).await?;
            }
        }
        if managed {
            gc(&root, 129, 0, 2000).await?;
            let result = gc(&root, 130, 0, 2002).await?;
            anyhow::ensure!(result["evicted_groups"] == 1, "public proof/settlement did not permit GC: {result}");
            let coord = root.join("cache/.nexus-coordination/generations/g-fixed");
            let lock = std::fs::symlink_metadata(coord.join("lock"))?;
            anyhow::ensure!(Some((lock.dev(),lock.ino())) == stable, "GC replaced coordination lock");
        }
        Ok::<(), anyhow::Error>(())
    }.await;
    std::fs::write(root.join("owner-release"), b"").expect("finally private owner release");
    let stopped = bridge.shutdown().await;
    let forced = if stopped.is_err() {
        Some(
            bridge
                .test_helper_fault(true)
                .await
                .expect("own failed helper cleanup"),
        )
    } else {
        None
    };
    std::fs::write(
        root.join("events.json"),
        serde_json::to_vec_pretty(&evidence).expect("events JSON"),
    )
    .expect("events");
    std::fs::write(
        root.join("record-stats.json"),
        serde_json::to_vec_pretty(&stats).expect("stats JSON"),
    )
    .expect("stats");
    std::fs::write(root.join("audit.json"), serde_json::to_vec_pretty(&json!({"forced_failed_case_cleanup":forced,"error":result.as_ref().err().map(ToString::to_string),"shutdown":stopped.as_ref().err().map(ToString::to_string)})).expect("audit JSON")).expect("audit");
    result.expect("all 128 complete healthy real custody rounds and bounded records");
    stopped.expect("natural shutdown; forced cleanup never counts as green");
}

fn collect_files(directory: &std::path::Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_files(&entry.path(), files)?;
        } else {
            files.push(entry.path());
        }
    }
    Ok(())
}

async fn gc(
    root: &std::path::Path,
    serial: usize,
    limit: u64,
    clock: usize,
) -> anyhow::Result<Value> {
    let pending = root.join("gc-request.new");
    std::fs::write(
        &pending,
        serde_json::to_vec(&json!({"serial":serial,"limit":limit,"clock":clock}))?,
    )?;
    std::fs::rename(pending, root.join("gc-request"))?;
    wait_for(|| {
        let Ok(data) = std::fs::read(root.join("gc-result")) else {
            return Ok(false);
        };
        Ok(serde_json::from_slice::<Value>(&data)?["serial"] == serial)
    })
    .await?;
    let value: Value = serde_json::from_slice(&std::fs::read(root.join("gc-result"))?)?;
    anyhow::ensure!(
        value["result"]["rejected"]
            .as_array()
            .is_some_and(|a| a.is_empty()),
        "GC rejected a healthy settled target: {value}"
    );
    Ok(value["result"].clone())
}
