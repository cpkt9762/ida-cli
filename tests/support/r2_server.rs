//! Exercise the actual MCP close wrapper over production custody and SDK.
use super::*;
use crate::preprocess::OutputRecorded as _;
use crate::{
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_save_public_rpc_refusal_reaches_mcp_and_cli_without_prefill() {
    if std::env::var("R6_SAVE_CHILD").as_deref() != Ok("1") {
        use crate::preprocess::SpawnRecorded as _;
        let output=tokio::process::Command::new("timeout")
            .arg("30s").arg(std::env::current_exe().expect("lib executable"))
            .args(["--exact","server::r2_lifecycle::explicit_save_public_rpc_refusal_reaches_mcp_and_cli_without_prefill","--nocapture"])
            .env("R6_SAVE_CHILD","1")
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .kill_on_drop(true).spawn_recorded().expect("private MCP/CLI child")
            .output_recorded().await.expect("child reaped");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"))
        .join("explicit-save");
    std::fs::create_dir_all(&root).expect("private fixture");
    let router = RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
    environment.insert("R3A_SCENARIO".into(), "slow-owner".into());
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fresh SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("production bridge/helper");
    let server = IdaMcpServer::new(router.clone());
    let result: anyhow::Result<Value> = async {
        let path = root.join("tiny.i64");
        let (handle, token) = router
            .ensure_worker_prepared(
                path.to_str().expect("path"),
                None,
                None,
                Preparation::new(Duration::from_secs(10)),
            )
            .await?;
        std::fs::write(root.join("save-refuse"), b"")?;
        let code = "import sys\nresult = sys.modules['_ida_cli_save_guard_v1'].save_database()";
        let mcp = server
            .run_script(Parameters(RunScriptRequest {
                db_handle: Some(handle),
                code: Some(code.to_owned()),
                file: None,
                timeout_secs: Some(10),
            }))
            .await?;
        let expected=json!({"success":false,"stdout":"","stderr":"",
            "error":"saving refused: explicit native save rejected",
            "error_summary":"saving refused: explicit native save rejected"});
        let body:Value=serde_json::from_str(&mcp.content[0].as_text().expect("native script JSON envelope").text)?;
        anyhow::ensure!(mcp.is_error==Some(false) && body==expected,
            "MCP changed the native run_script failure envelope or lost the public save refusal: {mcp:?}");
        let cli = super::socket_listener::test_save_rpc(
            router.clone(),
            path.to_str().expect("path"),
            code,
        )
        .await;
        anyhow::ensure!(cli["error"].is_null() && cli["result"]==expected,
            "CLI changed the native run_script failure envelope or lost the public save refusal: {cli}");
        let calls: Value =
            serde_json::from_slice(&std::fs::read(root.join("save-refusals.json"))?)?;
        anyhow::ensure!(
            calls["calls"] == 2,
            "each caller must execute exactly once: {calls}"
        );
        router.nexus_close_token(&token).await?;
        Ok(json!({"mcp":mcp,"cli":cli,"native_save_calls":calls}))
    }
    .await;
    std::fs::write(root.join("owner-release"), b"").expect("finally real owner lifetime unlock");
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0
            || bridge.lifecycle_status()["retirement_acks"] != 0
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let shutdown = bridge.shutdown().await;
    std::fs::write(root.join("save-callers.json"),serde_json::to_vec_pretty(&json!({"result":result.as_ref().ok(),
        "error":result.as_ref().err().map(ToString::to_string),"settled":settled.is_ok(),"shutdown":format!("{shutdown:?}")})).expect("JSON")).expect("evidence");
    settled.expect("exact custody settles");
    shutdown.expect("natural shutdown");
    result.expect("real explicit-save callers");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_preserves_text_error_and_lifecycle() {
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private MCP root"));
    if std::env::var("R2_MCP_CHILD").as_deref() != Ok("1") {
        use crate::preprocess::SpawnRecorded as _;
        let private = base.join("mcp-selector");
        for name in ["home", "tmp", "state", "ipc", "cases"] {
            std::fs::create_dir_all(private.join(name)).expect("private MCP child directories");
        }
        let child =
            tokio::process::Command::new(std::env::current_exe().expect("lib test executable"))
                .args([
                    "--exact",
                    "server::r2_lifecycle::close_preserves_text_error_and_lifecycle",
                    "--nocapture",
                ])
                .env("R2_MCP_CHILD", "1")
                .env("R3A_CASE_ROOT", private.join("cases"))
                .env("HOME", private.join("home"))
                .env("TMPDIR", private.join("tmp"))
                .env("IDA_CLI_HOME", private.join("home/.ida"))
                .env("IDA_NEXUS_STATE_DIR", private.join("state"))
                .env("IDA_NEXUS_IPC_ROOT", private.join("ipc"))
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn_recorded()
                .expect("isolated Nexus MCP child");
        let output = child.output_recorded().await.expect("MCP child reaped");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "isolated MCP assertions failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    for scenario in [
        "slow-owner",
        "r2-save-refused",
        "lost-ack",
        "r2-save-refused-notsent",
    ] {
        let root = base.join(scenario);
        std::fs::create_dir_all(&root).expect("private case");
        let router = crate::router::RouterState::new().expect("router");
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
        environment.insert("R3A_SCENARIO".into(), scenario.into());
        environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        let bridge = router
            .connect_nexus(BridgeConfig {
                python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK Python")),
                script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/r3a_bridge_fixture.py"),
                directory: root.join("i"),
                environment,
            })
            .await
            .expect("production bridge/helper");
        let server = IdaMcpServer::new(router.clone());
        let mut owner_wait_reference = None;
        let mut events = bridge.subscribe();
        let result: anyhow::Result<Value> = async {
            let (_, token) = router
                .ensure_worker_prepared(
                    root.join("tiny.i64").to_str().expect("utf8"),
                    None,
                    None,
                    Preparation::new(Duration::from_secs(10)),
                )
                .await?;
            let lease: crate::nexus::SessionLease = loop {
                let event = events.recv().await?;
                if event["event"] == "opened" {
                    break serde_json::from_value(event["lease"].clone())?;
                }
            };
            if scenario != "slow-owner" {
                std::fs::write(root.join("poison-root"), b"")?;
            }
            let response = server
                .close_idb_routed(&router, &CloseIdbRequest { token: Some(token) })
                .await?;
            anyhow::ensure!(
                response.is_error.unwrap_or(false) == (scenario != "slow-owner"),
                "MCP caller error flag changed: {response:?}"
            );
            let text = &response.content[0]
                .as_text()
                .expect("existing close text")
                .text;
            if scenario == "slow-owner" {
                anyhow::ensure!(
                    text == crate::server::LAST_REFERENCE_CLOSED,
                    "last-reference close text changed: {text}"
                );
            } else {
                anyhow::ensure!(
                    text.contains("saving refused"),
                    "guard cause missing: {text}"
                );
            }
            if matches!(scenario, "lost-ack" | "r2-save-refused-notsent") {
                let details = response
                    .structured_content
                    .as_ref()
                    .and_then(|v| v.get("nexus"))
                    .ok_or_else(|| {
                        anyhow::anyhow!("missing structured Nexus error: {response:?}")
                    })?;
                let original = if scenario == "r2-save-refused-notsent" {
                    // Cleanup may already own the next attempt. This fixture's
                    // original terminal has exactly this typed cause contract.
                    json!({"code":"operation_failed", "cause":null,
                        "retry":"never_replay", "automatic_replay":false})
                } else {
                    bridge
                        .endpoint()
                        .transition(|s, _| s.status(&lease.client_id, &lease))?
                        .control_delivery
                        .and_then(|d| d.error)
                        .ok_or_else(|| anyhow::anyhow!("N1 original error missing"))?
                        .details()
                };
                for key in ["code", "cause", "retry", "automatic_replay"] {
                    anyhow::ensure!(
                        details[key] == original[key],
                        "original {key} changed: {details} vs {original}"
                    );
                }
            }
            anyhow::ensure!(
                response.content.len() == 1,
                "close has one legacy text item"
            );
            let body = &response.meta.as_ref().expect("lifecycle meta").0["nexus"];
            anyhow::ensure!(
                body["lifecycle"]["lease_detached"]
                    == (!matches!(scenario, "lost-ack" | "r2-save-refused-notsent"))
                    && body["lifecycle"]["owner_pending"] == true
                    && body["lifecycle"]["root_shared_guard"] == true,
                "MCP lifecycle must distinguish ACK from owner: {body}"
            );
            if matches!(scenario, "lost-ack" | "r2-save-refused-notsent") {
                let repeated = super::socket_listener::test_close_rpc(
                    router.clone(),
                    root.join("tiny.i64").to_str().expect("utf8"),
                )
                .await;
                anyhow::ensure!(
                    repeated["error"]["message"]
                        .as_str()
                        .is_some_and(|s| s.contains("saving refused")
                            && (scenario != "lost-ack" || s.contains("UnknownOutcome"))),
                    "actual CLI close lost guard refusal or original uncertainty: {repeated}"
                );
                let original = if scenario == "r2-save-refused-notsent" {
                    // Cleanup may already own the next attempt. This fixture's
                    // original terminal has exactly this typed cause contract.
                    json!({"code":"operation_failed", "cause":null,
                        "retry":"never_replay", "automatic_replay":false})
                } else {
                    bridge
                        .endpoint()
                        .transition(|s, _| s.status(&lease.client_id, &lease))?
                        .control_delivery
                        .and_then(|d| d.error)
                        .ok_or_else(|| anyhow::anyhow!("CLI original error missing"))?
                        .details()
                };
                for key in ["code", "cause", "retry", "automatic_replay"] {
                    anyhow::ensure!(
                        repeated["error"]["data"]["nexus"][key] == original[key],
                        "CLI lost structured {key}: {repeated}"
                    );
                }
                std::fs::write(root.join("snapshot-request"), b"")?;
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !root.join("snapshot.json").exists() {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await?;
                let snapshot: Value =
                    serde_json::from_slice(&std::fs::read(root.join("snapshot.json"))?)?;
                anyhow::ensure!(
                    snapshot["requests"].as_array().is_some_and(|r| r
                        .iter()
                        .filter(|v| v["endpoint"] == "/release_lease")
                        .count()
                        == usize::from(scenario == "lost-ack")),
                    "CLI/MCP repeated close replayed unknown detach: {snapshot}"
                );
            }
            let active_before_wait = router.worker_count().await;
            let reference = body["lifecycle"]["owner_observation_ref"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("owner reference missing from MCP response"))?;
            owner_wait_reference = Some(reference.to_owned());
            let resources = bridge.lifecycle_status()["resources"].clone();
            let pending =
                super::socket_listener::test_owner_wait_rpc(router.clone(), reference, 0).await;
            anyhow::ensure!(
                pending["error"]["code"] == -32000
                    && pending["error"]["message"]
                        .as_str()
                        .is_some_and(|s| s.contains("timed out")),
                "CLI wait must use its own budget without requiring a path: {pending}"
            );
            anyhow::ensure!(
                router.worker_count().await == active_before_wait
                    && bridge.lifecycle_status()["resources"] == resources,
                "CLI owner wait created a new lease or changed retained owner resources"
            );
            Ok(json!({"mcp":response,"cli_pending":pending}))
        }
        .await;
        std::fs::write(root.join("owner-release"), b"").expect("finally release owned lifetime");
        let settled = tokio::time::timeout(Duration::from_secs(8), async {
            while bridge.lifecycle_status()["resources"] != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let completed_wait = match owner_wait_reference {
            Some(reference) => Some(
                super::socket_listener::test_owner_wait_rpc(router.clone(), &reference, 2).await,
            ),
            None => None,
        };
        let remaining_leases = router.worker_count().await;
        let stopped = bridge.shutdown().await;
        std::fs::write(root.join("mcp-result.json"), serde_json::to_vec_pretty(&json!({
            "response":result.as_ref().ok(),"error":result.as_ref().err().map(ToString::to_string),
            "settled":settled.is_ok(),"shutdown":format!("{stopped:?}"),"cli_completed":completed_wait
        })).expect("encode evidence")).expect("evidence");
        settled.expect("public lifetime custody settled");
        stopped.expect("natural helper and bridge shutdown");
        result.expect("actual MCP and CLI wrapper assertions");
        let completed_wait = completed_wait.expect("owner wait reference");
        assert!(
            completed_wait["error"].is_null() && completed_wait["result"]["owner_released"] == true,
            "CLI wait did not consume public owner proof: {completed_wait}"
        );
        assert_eq!(remaining_leases, 0, "CLI proof wait acquired a fresh lease");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_proof_before_terminal_keeps_actual_mcp_and_cli_error_responsibility() {
    let base = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    if std::env::var("R2_MCP_CHILD").as_deref() != Ok("1") {
        use crate::preprocess::SpawnRecorded as _;
        let output=tokio::process::Command::new(std::env::current_exe().expect("lib test"))
            .args(["--exact","server::r2_lifecycle::public_proof_before_terminal_keeps_actual_mcp_and_cli_error_responsibility","--nocapture"])
            .env("R2_MCP_CHILD","1")
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .kill_on_drop(true).spawn_recorded().expect("isolated MCP child")
            .output_recorded().await.expect("reaped child");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    for mode in ["mcp", "cli"] {
        for scenario in ["rf4-notsent", "rf4-uncertain"] {
            let root = base.join(format!("{mode}-{scenario}"));
            std::fs::create_dir_all(&root).expect("case");
            let router = crate::router::RouterState::new().expect("router");
            let mut environment: BTreeMap<String, String> = std::env::vars().collect();
            environment.insert("R3A_CASE_ROOT".into(), root.display().to_string());
            environment.insert("R3A_SCENARIO".into(), scenario.into());
            environment.insert(
                "IDA_NEXUS_STATE_DIR".into(),
                root.join("state").display().to_string(),
            );
            let bridge = router
                .connect_nexus(BridgeConfig {
                    python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
                    script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/support/r3a_bridge_fixture.py"),
                    directory: root.join("i"),
                    environment,
                })
                .await
                .expect("production bridge/helper");
            let mut events = bridge.subscribe();
            let result: anyhow::Result<Value> = async {
                let path = root.join("tiny.i64");
                let (_, token) = router
                    .ensure_worker_prepared(
                        path.to_str().expect("path"),
                        None,
                        None,
                        Preparation::new(Duration::from_secs(10)),
                    )
                    .await?;
                let lease: crate::nexus::SessionLease = loop {
                    let event = events.recv().await?;
                    if event["event"] == "opened" {
                        break serde_json::from_value(event["lease"].clone())?;
                    }
                };
                if scenario == "rf4-notsent" {
                    std::fs::write(root.join("poison-root"), b"")?;
                }
                let caller_router = router.clone();
                let caller = tokio::spawn(async move {
                    if mode == "cli" {
                        super::socket_listener::test_close_rpc(
                            caller_router,
                            path.to_str().expect("path"),
                        )
                        .await
                    } else {
                        let server = IdaMcpServer::new(caller_router.clone());
                        serde_json::to_value(
                            server
                                .close_idb_routed(
                                    &caller_router,
                                    &CloseIdbRequest { token: Some(token) },
                                )
                                .await
                                .expect("MCP"),
                        )
                        .expect("JSON")
                    }
                });
                tokio::time::timeout(Duration::from_secs(3), async {
                    while !root.join("terminal.arrived").exists() {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await?;
                std::fs::write(root.join("owner-release"), b"")?;
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        let status = bridge
                            .endpoint()
                            .transition(|s, _| s.status(&lease.client_id, &lease))?;
                        if status.phase == crate::nexus::SessionPhase::Released {
                            break Ok::<_, anyhow::Error>(());
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await??;
                tokio::time::sleep(Duration::from_millis(100)).await;
                let premature = caller.is_finished();
                std::fs::write(root.join("terminal.release"), b"")?;
                let response = caller.await?;
                std::fs::write(
                    root.join("caller.json"),
                    serde_json::to_vec_pretty(&response)?,
                )?;
                anyhow::ensure!(
                    !premature,
                    "public proof returned command success before terminal: {response}"
                );
                let nexus = if mode == "cli" {
                    &response["error"]["data"]["nexus"]
                } else {
                    &response["structuredContent"]["nexus"]
                };
                let original = bridge
                    .endpoint()
                    .transition(|s, _| s.status(&lease.client_id, &lease))?
                    .control_delivery
                    .and_then(|d| d.error)
                    .ok_or_else(|| anyhow::anyhow!("original terminal error missing"))?;
                let details = original.details();
                for key in ["code", "cause", "retry", "automatic_replay"] {
                    anyhow::ensure!(
                        nexus[key] == details[key],
                        "caller lost {key}: {response} vs {details}"
                    );
                }
                Ok(response)
            }
            .await;
            std::fs::write(root.join("terminal.release"), b"").expect("finally terminal");
            std::fs::write(root.join("owner-release"), b"").expect("finally lifetime");
            let settled = tokio::time::timeout(Duration::from_secs(8), async {
                while bridge.lifecycle_status()["resources"] != 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            let shutdown = bridge.shutdown().await;
            std::fs::write(root.join("result.json"),serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),"settled":settled.is_ok(),"shutdown":format!("{shutdown:?}")})).expect("encode")).expect("evidence");
            settled.expect("proof custody");
            shutdown.expect("natural shutdown");
            result.expect("proof independent of caller terminal");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_owner_waits_share_real_listener_without_starving_status_or_cancel() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    if std::env::var("R2_MCP_CHILD").as_deref() != Ok("1") {
        use crate::preprocess::SpawnRecorded as _;
        let private = root.join("owner-listener");
        for name in ["home", "tmp", "state", "ipc", "cases"] {
            std::fs::create_dir_all(private.join(name)).expect("private listener directories");
        }
        let output = tokio::process::Command::new(std::env::current_exe().expect("lib executable"))
            .args(["--exact", "server::r2_lifecycle::eight_owner_waits_share_real_listener_without_starving_status_or_cancel", "--nocapture"])
            .env("R2_MCP_CHILD", "1")
            .env("R3A_CASE_ROOT", private.join("cases"))
            .env("HOME", private.join("home")).env("TMPDIR", private.join("tmp"))
            .env("IDA_CLI_HOME", private.join("home/.ida"))
            .env("IDA_NEXUS_STATE_DIR", private.join("state"))
            .env("IDA_NEXUS_IPC_ROOT", private.join("ipc"))
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .kill_on_drop(true).spawn_recorded().expect("isolated observer child")
            .output_recorded().await.expect("child reaped");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let router = crate::router::RouterState::new().expect("router");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R3A_SCENARIO".into(), "slow-owner".into());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r3a_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("bridge");
    async fn rpc(path: &std::path::Path, method: &str, params: Value) -> anyhow::Result<Value> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        let (read, mut write) = stream.into_split();
        let mut data = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":"concurrent","method":method,"params":params}),
        )?;
        data.push(b'\n');
        write.write_all(&data).await?;
        let mut line = String::new();
        BufReader::new(read).read_line(&mut line).await?;
        Ok(serde_json::from_str(&line)?)
    }
    std::fs::create_dir_all(
        crate::idb_store::discovery_path()
            .parent()
            .expect("discovery parent"),
    )
    .expect("private discovery directory");
    let stop = tokio_util::sync::CancellationToken::new();
    let socket = root.join("c.sock");
    let listener = tokio::spawn(super::socket_listener::run_socket_listener(
        socket.clone(),
        router.clone(),
        stop.clone(),
    ));
    let result: anyhow::Result<Value> = async {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !socket.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let (_, token) = router
            .ensure_worker_prepared(
                root.join("tiny.i64").to_str().expect("path"),
                None,
                None,
                Preparation::new(Duration::from_secs(10)),
            )
            .await?;
        router.nexus_close_token(&token).await?;
        let before = router.status_snapshot().await;
        let reference = before
            .owner_observations
            .first()
            .and_then(|v| v["owner_observation_ref"].as_str())
            .ok_or_else(|| anyhow::anyhow!("owner reference"))?
            .to_owned();
        let resources = bridge.lifecycle_status()["resources"].clone();
        let mut waits = Vec::new();
        for _ in 0..8 {
            let path = socket.clone();
            let reference = reference.clone();
            waits.push(tokio::spawn(async move {
                rpc(
                    &path,
                    "wait_owner_exit",
                    json!({"owner_observation_ref":reference,"timeout_secs":2}),
                )
                .await
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        anyhow::ensure!(
            waits.iter().all(|w| !w.is_finished()),
            "all eight owner waits must be pending on the same listener"
        );
        let status = tokio::time::timeout(
            Duration::from_millis(500),
            rpc(&socket, "status", json!({})),
        )
        .await??;
        let cancel = tokio::time::timeout(
            Duration::from_millis(500),
            rpc(
                &socket,
                "cancel_task",
                json!({"task_id":"missing","token":token}),
            ),
        )
        .await??;
        std::fs::write(
            root.join("listener-control.json"),
            serde_json::to_vec_pretty(&json!({"status":status,"cancel":cancel}))?,
        )?;
        let mut outcomes = Vec::new();
        for wait in waits {
            outcomes.push(match wait.await? {
                Ok(value) => value,
                Err(error) => json!({"transport_error":error.to_string()}),
            });
        }
        std::fs::write(
            root.join("listener-results.json"),
            serde_json::to_vec_pretty(&json!({"status":status,"cancel":cancel,"waits":outcomes}))?,
        )?;
        anyhow::ensure!(
            status["error"].is_null(),
            "status starved by owner waits: {status}"
        );
        anyhow::ensure!(
            !cancel.to_string().contains("lane capacity full"),
            "cancel starved: {cancel}"
        );
        anyhow::ensure!(
            outcomes.iter().all(|v| v["error"]["message"]
                .as_str()
                .is_some_and(|s| s.contains("timed out"))),
            "wait admission/deadline changed: {outcomes:?}"
        );
        anyhow::ensure!(
            router.worker_count().await == 0 && bridge.lifecycle_status()["resources"] == resources,
            "wait acquired lease"
        );
        let mut disconnected = Vec::new();
        for _ in 0..8 {
            let mut peer = tokio::net::UnixStream::connect(&socket).await?;
            let mut request = serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":"drop","method":"wait_owner_exit",
                "params":{"owner_observation_ref":reference,"timeout_secs":20}}),
            )?;
            request.push(b'\n');
            peer.write_all(&request).await?;
            disconnected.push(peer);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(disconnected);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let replacement = rpc(
            &socket,
            "wait_owner_exit",
            json!({"owner_observation_ref":reference,"timeout_secs":0}),
        )
        .await?;
        anyhow::ensure!(
            replacement["error"]["message"]
                .as_str()
                .is_some_and(|s| s.contains("timed out")),
            "disconnected clients retained observation slots: {replacement}"
        );
        Ok(json!({"status":status,"cancel":cancel,"waits":outcomes,"replacement":replacement}))
    }
    .await;
    stop.cancel();
    listener
        .await
        .expect("listener joined")
        .expect("listener clean");
    super::socket_listener::cleanup_socket_files(&socket);
    std::fs::write(root.join("owner-release"), b"").expect("finally owner");
    tokio::time::timeout(Duration::from_secs(8), async {
        while bridge.lifecycle_status()["resources"] != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proof cleanup");
    bridge.shutdown().await.expect("natural shutdown");
    result.expect("shared listener capacity");
}
