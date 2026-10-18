//! Exercise the actual MCP close wrapper over production custody and SDK.
use super::*;
use crate::{preprocess::Preparation, router::nexus_bridge::BridgeConfig};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

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
                .env("IDA_CLI_NEXUS_DEV", "1")
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
        let output = child.wait_with_output().await.expect("MCP child reaped");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "isolated MCP assertions failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    for scenario in ["slow-owner", "r2-save-refused", "lost-ack"] {
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
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        let server = IdaMcpServer::new(
            Arc::new(IdaWorker::new(tx)),
            ServerMode::Router(router.clone()),
        );
        let mut owner_wait_reference = None;
        let result: anyhow::Result<Value> = async {
            let (_, token) = router
                .ensure_worker_prepared(
                    root.join("tiny.i64").to_str().expect("utf8"),
                    None,
                    None,
                    Preparation::new(Duration::from_secs(10)),
                )
                .await?;
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
                    text == "Database closed",
                    "existing close text changed: {text}"
                );
            } else {
                anyhow::ensure!(
                    text.contains("saving refused"),
                    "guard cause missing: {text}"
                );
            }
            let body: Value = serde_json::from_str(
                &response.content[1]
                    .as_text()
                    .expect("lifecycle content")
                    .text,
            )?;
            anyhow::ensure!(
                body["lifecycle"]["lease_detached"] == (scenario != "lost-ack")
                    && body["lifecycle"]["owner_pending"] == true
                    && body["lifecycle"]["root_shared_guard"] == true,
                "MCP lifecycle must distinguish ACK from owner: {body}"
            );
            if scenario == "lost-ack" {
                let repeated = super::socket_listener::test_close_rpc(
                    router.clone(),
                    root.join("tiny.i64").to_str().expect("utf8"),
                )
                .await;
                anyhow::ensure!(
                    repeated["error"]["message"].as_str().is_some_and(|s| s
                        .contains("saving refused")
                        && s.contains("UnknownOutcome")),
                    "actual CLI close lost guard refusal or original uncertainty: {repeated}"
                );
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
                        == 1),
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
