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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn helper_session_survives_the_router_process_groups_sighup() {
    use ida_mcp::router::nexus_bridge::{test_output_child, test_spawn_child};
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private signal root"));
    if std::env::var("R6_HUP_CHILD").as_deref() == Ok("1") {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("owned SIGHUP receiver");
        let router = RouterState::new().expect("child router");
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r2_client_bridge.py"),
                directory: root.join("signal-i"),
                environment: std::env::vars().collect(),
            })
            .await
            .expect("real Rust helper launcher");
        let before = bridge
            .test_finished_helper_heartbeat()
            .await
            .expect("ready helper");
        std::fs::write(
            root.join("signal-ready.json"),
            serde_json::to_vec_pretty(&before).expect("JSON"),
        )
        .expect("publish ready");
        tokio::time::timeout(Duration::from_secs(10), signal.recv())
            .await
            .expect("parent SIGHUP")
            .expect("signal received");
        let after = bridge
            .test_finished_helper_heartbeat()
            .await
            .expect("helper survives actual router group HUP");
        assert_eq!(
            before["identity"], after["identity"],
            "helper restarted after group HUP"
        );
        assert_ne!(after["identity"]["sid"], std::process::id());
        bridge
            .shutdown()
            .await
            .expect("bridge wait and surviving helper finish");
        std::fs::write(
            root.join("signal-result.json"),
            serde_json::to_vec_pretty(
                &json!({"before":before,"after":after,"received_sighup":true}),
            )
            .expect("JSON"),
        )
        .expect("signal evidence");
        return;
    }
    let mut command = tokio::process::Command::new("sh");
    command
        .args([
            "-c",
            "trap '' HUP; exec timeout --foreground 30s \"$@\"",
            "owned-hup-supervisor",
        ])
        .arg(std::env::current_exe().expect("test binary"));
    command
        .args([
            "helper_session_survives_the_router_process_groups_sighup",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("R6_HUP_CHILD", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    // SAFETY: setsid is async-signal-safe; this creates a group containing only
    // the exact owned test child and its future bridge, never the caller group.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = test_spawn_child(&mut command).expect("private process-group child");
    let pid = child.id().expect("owned child pid");
    wait_for(|| Ok(root.join("signal-ready.json").exists()))
        .await
        .expect("child initialized helper");
    // SAFETY: the unreaped child PID is pinned by Child; verify its private
    // group before delivering SIGHUP exclusively to that group.
    unsafe {
        assert_eq!(libc::getpgid(pid as i32), pid as i32);
        assert_eq!(libc::kill(-(pid as i32), libc::SIGHUP), 0);
    }
    let output = tokio::time::timeout(Duration::from_secs(40), test_output_child(child))
        .await
        .expect("bounded actual wait")
        .expect("child wait");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: Value = serde_json::from_slice(
        &std::fs::read(root.join("signal-result.json")).expect("signal evidence"),
    )
    .expect("JSON");
    assert_eq!(evidence["received_sighup"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_and_helper_loss_preserve_draining_owner_until_public_release() {
    use ida_mcp::preprocess::Preparation;
    use ida_mcp::router::nexus_bridge::{test_output_child, test_spawn_child};
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private base"));
    for (mode, helper_fault, proof_first) in [
        ("bridge-held", false, false),
        ("both-held", true, false),
        ("bridge-proof", false, true),
        ("both-proof", true, true),
    ] {
        let root = base.join(mode);
        std::fs::create_dir_all(root.join("a")).expect("private owner");
        let mut command = tokio::process::Command::new("timeout");
        command
            .arg("45s")
            .arg(std::env::var_os("R3A_PYTHON").expect("fixed SDK"))
            .args([
                "-B",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/support/r2_multi_bridge.py"
                ),
                "--owner",
            ])
            .arg(root.join("a"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let child = test_spawn_child(&mut command).expect("independent public owner process");
        wait_for(|| Ok(root.join("a/ready").exists()))
            .await
            .expect("real owner ready");
        let router = RouterState::new().expect("router");
        let environment: BTreeMap<String, String> = std::env::vars().collect();
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r2_client_bridge.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("production independent bridge/helper");
        let mut successor = None;
        let result:anyhow::Result<Value>=async {
            let (_,token)=router.ensure_worker_prepared(root.join("a/tiny.i64").to_str().expect("path"),None,None,
                Preparation::new(Duration::from_secs(10))).await?;
            let lease:SessionLease=serde_json::from_value(bridge.lifecycle_status()["resource_details"][0]["lease"].clone())?;
            router.nexus_close_token(&token).await?;
            wait_for(||Ok(root.join("a/release-requested").exists())).await?;
            let held=bridge.lifecycle_status();
            anyhow::ensure!(held["resources"]==1,"last ACK discarded owner responsibility: {held}");
            let acknowledged=bridge.endpoint().transition(|s,_|s.status(&lease.client_id,&lease))?;
            anyhow::ensure!(acknowledged.phase==SessionPhase::Released,
                "last ACK did not finish its exact N1 lease");
            if proof_first {
                std::fs::write(root.join("a/owner-release"),b"")?;
                wait_for(||Ok(bridge.lifecycle_status()["resources"]==0 && bridge.lifecycle_status()["retirement_acks"]==0)).await?;
            }
            bridge.terminate().await?;
            std::fs::write(root.join("after-bridge.json"),serde_json::to_vec_pretty(&bridge.lifecycle_status())?)?;
            if mode=="bridge-held" {
                let next=RouterState::new()?;
                let mut environment:BTreeMap<String,String>=std::env::vars().collect();
                environment.insert("R6_CAPABILITY_TRACE".into(),root.join("next-sdk.jsonl").display().to_string());
                let adapter=next.connect_nexus(BridgeConfig {
                    python:PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
                    script:PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/r2_client_bridge.py"),
                    directory:root.join("next"),environment,
                }).await?;
                successor=Some((next,adapter.clone()));
                let refused=gate_attempt(&adapter,&root.join("a/tiny.i64"),"held").await?;
                anyhow::ensure!(refused["event"]!="opened" && !root.join("next-sdk.jsonl").exists(),
                    "new router bypassed failed-owner-held gate: {refused}");
                std::fs::write(root.join("next-held.json"),serde_json::to_vec_pretty(&refused)?)?;
            }
            let fault=if helper_fault {Some(bridge.test_helper_fault(false).await?)} else {None};
            if !proof_first {
                anyhow::ensure!(bridge.lifecycle_status()["resources"]==1,"bridge/helper death fabricated owner proof");
                if helper_fault {
                    // I5 requires a healthy public observer again. Releasing
                    // the final original before re-subscription is the separate
                    // explicitly blocked missing-source case, not convergence.
                    wait_for(||Ok(bridge.lifecycle_status()["helper"]["snapshot"]["recovered"]==true
                        && bridge.lifecycle_status()["helper"]["snapshot"]["owner_count"]==1)).await?;
                }
                std::fs::write(root.join("a/owner-release"),b"")?;
            }
            let settled=wait_for(||Ok(bridge.lifecycle_status()["resources"]==0)).await;
            std::fs::write(root.join("after-owner.json"),serde_json::to_vec_pretty(&bridge.lifecycle_status())?)?;
            settled?;
            anyhow::ensure!(bridge.lifecycle_status()["retirement_acks"]==if proof_first {0}else{1},
                "a dead bridge must not fabricate a retirement delivery ACK");
            let after=bridge.endpoint().transition(|s,_|s.status(&lease.client_id,&lease))?;
            anyhow::ensure!(after.phase==SessionPhase::Released && json!(after.control_delivery)==json!(acknowledged.control_delivery),"public lifetime rewrote exact ACK history: {after:?}");
            if let Some((_,adapter))=&successor {
                wait_for(||Ok(root.join("a/requests.json").exists())).await?;
                let admitted=gate_attempt(adapter,&root.join("a/tiny.i64"),"after-proof").await?;
                anyhow::ensure!(root.join("next-sdk.jsonl").exists() && adapter.lifecycle_status()["resources"]==0,
                    "new router failed to consume exact target proof before its new SDK request: {admitted}");
                std::fs::write(root.join("next-after-proof.json"),serde_json::to_vec_pretty(&admitted)?)?;
            }
            Ok(json!({"mode":mode,"held":held,"after":bridge.lifecycle_status(),"session":after,"helper_fault":fault}))
        }.await;
        std::fs::write(root.join("a/owner-release"), b"")
            .expect("finally release owned native lifetime");
        let output = test_output_child(child).await.expect("actual owner wait");
        let successor_shutdown = match successor {
            Some((_, adapter)) => Some(adapter.shutdown().await),
            None => None,
        };
        let shutdown = bridge.shutdown().await;
        std::fs::write(root.join("draining-result.json"),serde_json::to_vec_pretty(&json!({"result":result.as_ref().ok(),
            "error":result.as_ref().err().map(ToString::to_string),"owner_exit":output.status.code(),
            "owner_stderr":String::from_utf8_lossy(&output.stderr),"shutdown":format!("{shutdown:?}")})).expect("evidence")).expect("write evidence");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        shutdown.expect("failed bridge and exact helper naturally collected");
        if let Some(stopped) = successor_shutdown {
            stopped.expect("new router/helper naturally collected");
        }
        result.expect("real bridge/helper crashes cannot replace public owner proof");
    }
}

async fn gate_attempt(
    bridge: &ida_mcp::router::nexus_bridge::NexusBridge,
    path: &std::path::Path,
    name: &str,
) -> anyhow::Result<Value> {
    let mut events = bridge.subscribe();
    let client = ClientId::new(format!("r6-new-{name}"))?;
    bridge.endpoint().transition(|s, t| {
        s.open(
            &client,
            AcceptedRequest::new(
                &SystemClock,
                RequestId::new(name)?,
                None,
                "open",
                json!({"timeout_secs":3}),
            )?,
            OpenSpec {
                operation_id: OperationId::new(name)?,
                path: path.display().to_string(),
                options: json!({"spawn":false}),
            },
            t,
        )
    })?;
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = events.recv().await?;
            if matches!(
                event["event"].as_str(),
                Some("opened" | "failed" | "not_sent" | "uncertain")
            ) {
                break Ok::<_, anyhow::Error>(event);
            }
        }
    })
    .await??)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filesystem_capability_refusal_precedes_public_sdk_calls() {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private case"));
    let physical = std::env::var_os("R6_VOLUME_ROOT");
    let parent = physical.as_ref().map_or_else(
        || root.join("unsupported"),
        |volume| {
            PathBuf::from(volume).join(root.parent().expect("case").file_name().expect("label"))
        },
    );
    std::fs::create_dir(&parent).expect("fresh target parent");
    let path = parent.join("tiny.i64");
    let bytes = b"private capability refusal input; must remain unchanged";
    std::fs::write(&path, bytes).expect("private input");
    let before = std::fs::metadata(&path).expect("input identity");
    let trace = root.join("sdk-calls.jsonl");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R6_CAPABILITY_TRACE".into(), trace.display().to_string());
    environment.insert(
        "R6_CAPABILITY_FAULT".into(),
        if physical.is_some() { "0" } else { "1" }.into(),
    );
    let router = RouterState::new().expect("production router");
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r2_client_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("production installed bridge");
    let mut events = bridge.subscribe();
    let client = ClientId::new("r6-capabilities").expect("client");
    let opening = bridge
        .endpoint()
        .transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("refused-open")?,
                    None,
                    "open",
                    json!({"timeout_secs":10}),
                )?,
                OpenSpec {
                    operation_id: OperationId::new("refused-open")?,
                    path: path.display().to_string(),
                    options: json!({"spawn":true}),
                },
                t,
            )
        })
        .expect("accepted caller");
    let terminal = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await?;
            if matches!(
                event["event"].as_str(),
                Some("opened" | "failed" | "uncertain" | "not_sent")
            ) {
                break Ok::<_, anyhow::Error>(event);
            }
        }
    })
    .await
    .expect("bounded real terminal")
    .expect("event stream");
    let progress = bridge
        .endpoint()
        .transition(|s, _| s.open_progress(&client, &opening))
        .expect("caller status");
    let status = bridge.lifecycle_status();
    let shutdown = bridge.shutdown().await;
    let trace_text = match std::fs::read_to_string(&trace) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => panic!("SDK trace unreadable: {error}"),
    };
    let sdk_calls: Vec<Value> = trace_text
        .lines()
        .map(|line| serde_json::from_str(line).expect("complete SDK trace record"))
        .collect();
    std::fs::write(root.join("capability-refusal.json"),serde_json::to_vec_pretty(&json!({
        "terminal":terminal,"caller_status":progress,"lifecycle_status":status,"physical_volume":physical,
        "target":path,"sdk_calls":sdk_calls,"shutdown":format!("{shutdown:?}")})).expect("evidence JSON")).expect("evidence");
    shutdown.expect("natural teardown");
    assert_eq!(terminal["event"], "failed");
    let message = terminal["error"]["message"].as_str().expect("public error");
    let capabilities = &terminal["diagnostics"]["filesystem_capabilities"];
    assert_eq!(capabilities["supported"], false);
    assert_eq!(capabilities["cleanup_errors"], json!([]));
    assert_eq!(capabilities["no_replace_rename"]["errno"], libc::ENOTSUP);
    for text in [
        "FilesystemCapabilitiesRefused",
        "no_replace_rename_unsupported",
        "errno",
    ] {
        assert!(message.contains(text), "{message}");
    }
    if physical.is_some() {
        assert_eq!(capabilities["filesystem"], "exfat");
        assert_eq!(capabilities["hardlink"]["errno"], 45);
        for text in ["exfat", "hardlink_unsupported", "45"] {
            assert!(message.contains(text), "{message}");
        }
    }
    assert!(progress.0.is_none(), "refusal fabricated a handle");
    assert!(progress
        .1
        .expect("status retains exact refusal")
        .message
        .contains(message.trim_start_matches("RuntimeError: ")));
    assert_eq!(status["resources"], 0);
    assert_eq!(status["startup_and_pre_attach"], 0);
    // Record the existing status observer as well. Its independent discovery
    // does not belong to this target request or establish target admission.
    assert!(
        sdk_calls
            .iter()
            .all(|call| call["origin"] == "background_status"
                && call["sdk_call"] == "discover_databases"),
        "target request reached Nexus: {sdk_calls:?}"
    );
    assert_eq!(std::fs::read(&path).expect("unchanged input"), bytes);
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::fs::metadata(&path).expect("retained identity").ino(),
        before.ino()
    );
    let entries: Vec<_> = std::fs::read_dir(&parent)
        .expect("parent")
        .map(|v| v.expect("entry").path())
        .collect();
    assert_eq!(
        entries,
        vec![path],
        "refusal left coordination or probe debris"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn analysis_does_not_hold_target_ex_against_an_independent_home() {
    use ida_mcp::{
        preprocess::Preparation,
        router::nexus_bridge::{test_output_child, test_spawn_child},
    };
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private case root"));
    let path = root.join("a/tiny.i64");
    if std::env::var("R6_ANALYSIS_CHILD").as_deref() == Ok("1") {
        let router = RouterState::new().expect("independent process router");
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r2_client_bridge.py"),
                directory: root.join("b/i"),
                environment: std::env::vars().collect(),
            })
            .await
            .expect("second production bridge and target gate");
        let result: anyhow::Result<Value> = async {
            let (handle, token) = router
                .ensure_worker_prepared(
                    path.to_str().expect("path"),
                    None,
                    None,
                    Preparation::new(Duration::from_secs(10)),
                )
                .await?;
            let status = bridge.lifecycle_status();
            anyhow::ensure!(
                status["resources"] == 1,
                "second home did not acquire a real handle: {status}"
            );
            std::fs::write(
                root.join("b-opened.json"),
                serde_json::to_vec(&json!({"handle":handle,"status":status,
                "home":std::env::var("IDA_CLI_HOME").expect("private second home")}))?,
            )?;
            wait_for(|| Ok(root.join("b-close").exists())).await?;
            anyhow::ensure!(
                router.nexus_close_token(&token).await?.is_some(),
                "second close lost its lease"
            );
            std::fs::write(root.join("b-closed"), b"")?;
            tokio::time::timeout(Duration::from_secs(8), async {
                while bridge.lifecycle_status()["resources"] != 0
                    || bridge.lifecycle_status()["retirement_acks"] != 0
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            Ok(status)
        }
        .await;
        let shutdown = bridge.shutdown().await;
        std::fs::write(root.join("b-result.json"),serde_json::to_vec_pretty(&json!({"result":result.as_ref().ok(),
            "error":result.as_ref().err().map(ToString::to_string),"shutdown":format!("{shutdown:?}")})).expect("JSON")).expect("evidence");
        shutdown.expect("second natural shutdown");
        result.expect("second home passes target gate during analysis");
        return;
    }
    for name in ["a", "b", "b-home/.ida", "b-tmp", "state"] {
        std::fs::create_dir_all(root.join(name)).expect("new owned directories");
    }
    let router = RouterState::new().expect("parent production router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_CASE_ROOT".into(), root.join("a").display().to_string());
    environment.insert("R3A_SCENARIO".into(), "analysis-barrier".into());
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("a/i"),
            environment,
        })
        .await
        .expect("production N1 bridge and held native analysis input");
    let mut events = bridge.subscribe();
    let client = ClientId::new("r6-analysis-a").expect("client");
    bridge
        .endpoint()
        .transition(|s, t| {
            s.open(
                &client,
                AcceptedRequest::new(
                    &SystemClock,
                    RequestId::new("analysis-open")?,
                    None,
                    "open",
                    json!({"timeout_secs":20}),
                )?,
                OpenSpec {
                    operation_id: OperationId::new("analysis-open")?,
                    path: path.display().to_string(),
                    options: json!({"spawn":false,"wait_analysis":true}),
                },
                t,
            )
        })
        .expect("real preparing open");
    let mut child = None;
    let result:anyhow::Result<Value>=async {
        wait_for(||Ok(root.join("a/analysis.arrived").exists())).await?;
        let before=bridge.lifecycle_status();
        let lease:SessionLease=serde_json::from_value(before["resource_details"][0]["lease"].clone())?;
        anyhow::ensure!(bridge.endpoint().transition(|s,_|s.status(&client,&lease))?.phase==SessionPhase::Preparing,
            "first caller must still be in real analysis preparation");
        let mut command=tokio::process::Command::new("timeout");
        command.arg("30s").arg(std::env::var_os("R3A_PYTHON").expect("prepared telemetry Python"))
            .args(["-B","-c","import subprocess,sys; raise SystemExit(subprocess.run(sys.argv[1:],check=False).returncode)"])
            .arg(std::env::current_exe().expect("same test binary"))
            .args(["analysis_does_not_hold_target_ex_against_an_independent_home","--exact","--nocapture","--test-threads=1"])
            .env("R6_ANALYSIS_CHILD","1").env("HOME",root.join("b-home"))
            .env("IDA_CLI_HOME",root.join("b-home/.ida")).env("TMPDIR",root.join("b-tmp"))
            .env("IDA_NEXUS_STATE_DIR",root.join("state")).env("IDA_NEXUS_IPC_ROOT",root.join("b/ipc"))
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
        child=Some(test_spawn_child(&mut command)?);
        wait_for(||Ok(root.join("b-opened.json").exists())).await?;
        anyhow::ensure!(!root.join("a/analysis.release").exists(),"B must acquire before A analysis resumes");
        let second:Value=serde_json::from_slice(&std::fs::read(root.join("b-opened.json"))?)?;
        anyhow::ensure!(second["home"]==root.join("b-home/.ida").display().to_string(),"second process reused the first home");
        anyhow::ensure!(second["status"]["resource_details"][0]["owner"]==before["resource_details"][0]["owner"],
            "the independent home must attach to the same physical owner");
        std::fs::write(root.join("a/analysis.release"),b"")?;
        tokio::time::timeout(Duration::from_secs(8),async {
            loop {
                let event=events.recv().await?;
                if event["event"]=="opened" {break Ok::<_,anyhow::Error>(event);}
            }
        }).await??;
        bridge.endpoint().transition(|s,t|s.release(&client,&lease,t))?;
        tokio::time::timeout(Duration::from_secs(8),async {
            loop {
                let event=events.recv().await?;
                if event["event"]=="released" {break Ok::<_,anyhow::Error>(event);}
            }
        }).await??;
        std::fs::write(root.join("b-close"),b"")?;
        wait_for(||Ok(root.join("b-closed").exists())).await?;
        Ok(json!({"preparing":before,"second_home":second,"analysis_released_after_second_acquired":true}))
    }.await;
    for name in ["a/analysis.release", "a/owner-release", "b-close"] {
        std::fs::write(root.join(name), b"").expect("finally release only owned barriers");
    }
    let child_output = match child {
        Some(child) => Some(
            test_output_child(child)
                .await
                .expect("actual independent child wait"),
        ),
        None => None,
    };
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0
            || bridge.lifecycle_status()["retirement_acks"] != 0
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let shutdown = bridge.shutdown().await;
    std::fs::write(root.join("analysis-two-home.json"),serde_json::to_vec_pretty(&json!({"result":result.as_ref().ok(),
        "error":result.as_ref().err().map(ToString::to_string),"child_status":child_output.as_ref().map(|o|o.status.code()),
        "child_stdout":child_output.as_ref().map(|o|String::from_utf8_lossy(&o.stdout)),
        "child_stderr":child_output.as_ref().map(|o|String::from_utf8_lossy(&o.stderr)),
        "settled":settled.is_ok(),"shutdown":format!("{shutdown:?}")})).expect("JSON")).expect("evidence");
    let output = child_output.expect("independent child was actually created");
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    settled.expect("all current resources settle");
    shutdown.expect("parent natural shutdown");
    result.expect("analysis does not own target EX");
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
        "observe-handoff-failed",
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
                command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
                let child=ida_mcp::router::nexus_bridge::test_spawn_child(&mut command)?;
                let output = tokio::time::timeout(Duration::from_secs(5), ida_mcp::router::nexus_bridge::test_output_child(child)).await??;
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
        if scenario == "attach-rejected" || scenario == "observe-handoff-failed" {
            anyhow::ensure!(lease.is_none(), "rejected attach acquired a lease");
            anyhow::ensure!(terminal["event"] == "failed", "typed lease_absent must have a definite failed parent");
            if scenario == "observe-handoff-failed" {
                anyhow::ensure!(terminal["error"]["message"].as_str().is_some_and(|m|m.contains("controlled observation handoff NotSent")),
                    "cleanup must preserve the original callback error: {terminal}");
            }
            // The owner is still alive. Only the typed no-attach watch can close.
            if !evidence.iter().any(|event| event["event"] == "custody_settled") {
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
            }
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
        if lease.is_none() {
            let status=bridge.endpoint().transition(|s,_|Ok::<_,NexusError>(s.acquisition_status()))?;
            let parent=status["parents"].as_array().expect("parents").iter().find(|p|p["parent"]==serde_json::to_value(&identity).expect("identity"))
                .ok_or_else(||anyhow::anyhow!("parent diagnostic missing"))?;
            anyhow::ensure!(parent["acquisitions"].as_array().expect("acquisitions").iter().all(|a|a["physical_slot"]==false),
                "proved absent/closed physical resources still consume a tenant slot: {parent}");
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
        let mut stable_namespace=None;
        for round in 0..128 {
            case(&bridge, &root, "healthy", round, &mut evidence).await?;
            let framing:Value=serde_json::from_slice(&std::fs::read(root.join("http-framing.json"))?)?;
            anyhow::ensure!(framing["tcp_nodelay_enabled"]==true && framing["protocol"]=="HTTP/1.1",
                "fixed-epoch fixture transport must not add Nagle/delayed-ACK stalls");
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
            let names=if managed {vec!["lock","target.json","volume.json"]}
                else {vec!["lock","root.lock","target.json","volume.json"]};
            let mut expected:std::collections::BTreeSet<PathBuf>=names.iter().map(PathBuf::from).collect();
            expected.insert(PathBuf::from("custody.json"));
            let actual=files.iter().map(|p|p.strip_prefix(coord).map(PathBuf::from))
                .collect::<Result<std::collections::BTreeSet<_>,_>>()?;
            anyhow::ensure!(actual==expected,"healthy target has unknown/unsettled routine records: {actual:?}");
            let namespace=names.iter().map(|name| {
                let path=coord.join(name);
                let meta=std::fs::symlink_metadata(&path)?;
                anyhow::ensure!(meta.is_file() && meta.nlink()==1 && meta.mode()&0o777==0o600,"namespace identity/mode changed");
                Ok::<_,anyhow::Error>(json!({"name":name,"device":meta.dev(),"inode":meta.ino(),"bytes":meta.len(),
                    "hash":blake3::hash(&std::fs::read(path)?).to_hex().to_string()}))
            }).collect::<Result<Vec<_>,_>>()?;
            if let Some(previous)=&stable_namespace {anyhow::ensure!(previous==&namespace,"stable namespace bytes/inodes changed across healthy epochs");}
            stable_namespace=Some(namespace.clone());
            let namespace_bytes:u64=namespace.iter().map(|v|v["bytes"].as_u64().expect("namespace size")).sum();
            anyhow::ensure!(bytes < 32768 && bytes==namespace_bytes+std::fs::metadata(coord.join("custody.json"))?.len(),
                "healthy records grew outside the original byte bound: files={} bytes={bytes}",files.len());
            stats.push(json!({"round":round+1,"files":files.len(),"bytes":bytes,"namespace":namespace,
                "routine_files":1,"routine_bytes":bytes-namespace_bytes,"lock":[identity.0,identity.1],
                "summary":journal["summary"].as_array().map(Vec::len)}));
            if managed {
                gc(&root, round+1, u64::MAX, 1000+round).await?;
            }
            if round != 127 {
                let next_owner = root.join("next-owner.new");
                std::fs::write(&next_owner, (round+1).to_string())?;
                std::fs::rename(next_owner, root.join("next-owner"))?;
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

#[tokio::test]
async fn r9_late_ordinal_retirement_and_public_proof_before_release_return() {
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private test root"));
    for scenario in [
        "r9-retire-before",
        "r9-retire-after",
        "r9-proof-before-release",
    ] {
        let root = base.join(scenario);
        std::fs::create_dir_all(&root).expect("isolated r9 scenario");
        let router = RouterState::new().expect("real N1 router");
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
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r3a_bridge_fixture.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("real bridge/helper/SDK");
        let mut events = bridge.subscribe();
        let client = ClientId::new(scenario).expect("test client");
        let opened = bridge
            .endpoint()
            .transition(|s, t| {
                s.open(
                    &client,
                    AcceptedRequest::new(
                        &SystemClock,
                        RequestId::new("r9-open")?,
                        None,
                        "open",
                        json!({"timeout_secs":20}),
                    )?,
                    OpenSpec {
                        operation_id: OperationId::new("r9-open")?,
                        path: root.join("tiny.i64").display().to_string(),
                        options: json!({"spawn":false,"wait_analysis":false}),
                    },
                    t,
                )
            })
            .expect("reserve production open");
        let mut evidence = Vec::new();
        let result = async {
            if scenario == "r9-proof-before-release" {
                tokio::time::timeout(Duration::from_secs(12), async {
                    loop {
                        let event = events.recv().await?;
                        evidence.push(event.clone());
                        if event["event"] == "owner_released" {
                            break Ok::<_, anyhow::Error>(());
                        }
                    }
                })
                .await??;
                anyhow::ensure!(
                    root.join("r9-release.arrived").exists(),
                    "proof did not precede release return barrier"
                );
                // Wait for retirement while the actual SDK detach response is withheld.
                wait_for(|| Ok(root.join("r9-retirement.json").exists())).await?;
                std::fs::write(root.join("r9-release.release"), b"")?;
            }
            let terminal = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    let event = events.recv().await?;
                    evidence.push(event.clone());
                    if event["attempt"]["target"]["kind"] == "open"
                        && ["opened", "failed", "uncertain"]
                            .iter()
                            .any(|kind| event["event"] == *kind)
                    {
                        break Ok::<_, anyhow::Error>(event);
                    }
                }
            })
            .await??;
            anyhow::ensure!(terminal["event"] == "opened", "r9 failed: {terminal}");
            wait_for(|| Ok(root.join("r9-retirement.json").exists())).await?;
            let retirement: Value =
                serde_json::from_slice(&std::fs::read(root.join("r9-retirement.json"))?)?;
            if scenario == "r9-retire-after" {
                anyhow::ensure!(
                    retirement["current_ordinal"] == 2,
                    "not actually late: {retirement}"
                );
            } else {
                anyhow::ensure!(
                    retirement["current_ordinal"] == 1,
                    "prior retirement did not precede next ordinal: {retirement}"
                );
            }
            anyhow::ensure!(
                root.join("r9-next-ordinal").exists(),
                "next ordinal not acquired"
            );
            let (lease, failure) = bridge
                .endpoint()
                .transition(|s, _| s.open_progress(&client, &opened))?;
            anyhow::ensure!(failure.is_none(), "parent failed: {failure:?}");
            let lease = lease.ok_or_else(|| anyhow::anyhow!("new lease missing"))?;
            anyhow::ensure!(
                bridge
                    .endpoint()
                    .transition(|s, _| s.status(&client, &lease))?
                    .phase
                    == SessionPhase::Active,
                "new ordinal retired by old receipt"
            );
            bridge
                .endpoint()
                .transition(|s, t| s.release(&client, &lease, t))?;
            wait_for(|| Ok(root.join("release-requested").exists())).await?;
            std::fs::write(root.join("owner-release"), b"")?;
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    let event = events.recv().await?;
                    evidence.push(event.clone());
                    if event["event"] == "custody_settled" && event["acquisition"]["ordinal"] == 2 {
                        break Ok::<_, anyhow::Error>(());
                    }
                }
            })
            .await??;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        std::fs::write(root.join("r9-release.release"), b"")
            .expect("release private response barrier");
        std::fs::write(root.join("owner-release"), b"").expect("release private lifetime input");
        let shutdown = bridge.shutdown().await;
        let forced = if shutdown.is_err() {
            Some(
                bridge
                    .test_helper_fault(true)
                    .await
                    .expect("owned failed-case cleanup"),
            )
        } else {
            None
        };
        std::fs::write(root.join("q1-evidence.json"),serde_json::to_vec_pretty(&json!({"events":evidence,
            "error":result.as_ref().err().map(ToString::to_string),"shutdown":shutdown.as_ref().err().map(ToString::to_string),"forced":forced})).expect("evidence JSON")).expect("save evidence");
        result.expect("r9 production barrier assertions");
        shutdown.expect("natural bridge/helper exit");
    }
}
