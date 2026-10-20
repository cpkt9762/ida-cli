//! Real large-database release through Tools/N1, with one unchanged router.
use ida_mcp::process_spawn::StdOutputFenced;
use ida_mcp::{
    preprocess::Preparation,
    router::{nexus_bridge::BridgeConfig, RouterState},
};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn note(rows: &Arc<Mutex<Vec<Value>>>, start: Instant, stage: &str, value: Value) {
    rows.lock().expect("release trace lock").push(json!({
        "elapsed": start.elapsed().as_secs_f64(), "stage": stage, "value": value
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_saved_comment_survives_immediate_reopen_on_same_router() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private case root"));
    let seed = PathBuf::from(std::env::var_os("R7A_LARGE_SEED").expect("analyzed seed path"));
    assert!(
        seed.metadata().expect("seed metadata").len() > 100_000_000,
        "packed seed must exceed 100MB"
    );
    let path = root.join("large.i64");
    std::fs::copy(&seed, &path).expect("complete private copy of analyzed seed");
    let router = RouterState::new().expect("one router");
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("matching prepared SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("nexus_bridge/bridge.py"),
            directory: root.join("i"),
            environment: std::env::vars().collect(),
        })
        .await
        .expect("matching production bridge readiness");
    let start = Instant::now();
    let rows = Arc::new(Mutex::new(Vec::new()));
    let mut events = bridge.subscribe();
    let captured = rows.clone();
    let observer = tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            note(&captured, start, "bridge_event", event);
        }
    });
    let prepare = || Preparation::new(Duration::from_secs(120));
    let hold_owner = std::env::var("R7A_OWNER_BARRIER").as_deref() == Ok("1");
    let arrived = root.join("owner-close.arrived");
    let release = root.join("owner-close.release");
    let controller = if hold_owner {
        let (arrived, release, rows) = (arrived.clone(), release.clone(), rows.clone());
        Some(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(60), async {
                while !arrived.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("real owner reached the close barrier");
            note(&rows, start, "owner_barrier_arrived", Value::Null);
            // A deliberate minimum hold proves the >2s functional boundary.
            tokio::time::sleep(Duration::from_secs(3)).await;
            note(&rows, start, "owner_barrier_released", Value::Null);
            std::fs::write(release, b"").expect("release only this owner barrier");
        }))
    } else {
        None
    };
    let mut tokens = Vec::new();
    let result: anyhow::Result<Value> = async {
        note(&rows, start, "open_accepted", json!({"path":path}));
        let (handle, token) = router.ensure_worker_prepared(path.to_str().expect("utf8"), None, None, prepare()).await?;
        tokens.push(token.clone());
        note(&rows, start, "open_ready", json!({"handle":handle}));
        let trace = root.join("owner-events.jsonl");
        let code = format!(r#"import ida_bytes,ida_ida,json,time
assert ida_bytes.set_cmt(ida_ida.inf_get_min_ea(), 'r7a-large-saved-comment', False)
assert ida_bytes.get_cmt(ida_ida.inf_get_min_ea(), False)=='r7a-large-saved-comment'
import ida_domain
from pathlib import Path
_original_close=ida_domain.Database.close
def _traced_close(self,*args,**kwargs):
    with open({trace:?},'a') as f: f.write(json.dumps({{'stage':'close_database_enter','monotonic':time.monotonic(),'args':args,'kwargs':kwargs}})+'\n')
    if {hold}:
        Path({arrived:?}).touch()
        while not Path({release:?}).exists(): time.sleep(0.01)
    result=_original_close(self,*args,**kwargs)
    with open({trace:?},'a') as f: f.write(json.dumps({{'stage':'close_database_return','monotonic':time.monotonic()}})+'\n')
    return result
ida_domain.Database.close=_traced_close
print('r7a-large-saved-comment')"#, trace=trace.to_str().expect("utf8"),
            hold=if hold_owner {"True"} else {"False"},
            arrived=arrived.to_str().expect("utf8"), release=release.to_str().expect("utf8"));
        let changed = router.route_request_prepared(Some(&handle), "run_script", json!({"code":code}), prepare()).await?;
        anyhow::ensure!(changed["success"] == true && changed["stdout"] == "r7a-large-saved-comment\n", "write/read failed: {changed}");
        note(&rows, start, "comment_read_back", changed);
        note(&rows, start, "close_issued", Value::Null);
        let closed = router.nexus_close_token(&token).await;
        note(&rows, start, "close_returned", json!({"result":format!("{closed:?}")}));
        // No status call or owner wait goes between the last ACK and new open.
        note(&rows, start, "reopen_accepted", json!({"budget_seconds":120}));
        let reopened = router.ensure_worker_prepared(path.to_str().expect("utf8"), None, None, prepare()).await;
        note(&rows, start, "reopen_returned", json!({"result":format!("{reopened:?}")}));
        let (fresh, next_token) = reopened?;
        tokens.push(next_token.clone());
        closed?;
        let read = router.route_request_prepared(Some(&fresh), "run_script", json!({"code":
            "import ida_ida,ida_bytes\nprint(ida_bytes.get_cmt(ida_ida.inf_get_min_ea(),False))"}), prepare()).await?;
        note(&rows, start, "reopened_comment", read.clone());
        anyhow::ensure!(read["success"] == true && read["stdout"] == "r7a-large-saved-comment\n", "saved comment lost: {read}");
        router.nexus_close_token(&next_token).await?;
        Ok(json!({"saved_read":read,"router_restarts":0}))
    }.await;
    std::fs::write(&release, b"").expect("finally release the private owner barrier");
    if let Some(controller) = controller {
        controller.abort();
        let _ = controller.await;
    }
    let acquired_count = tokens.len();
    for token in tokens {
        let closed = router.nexus_close_token(&token).await;
        note(
            &rows,
            start,
            "finally_close",
            json!({"result":format!("{closed:?}")}),
        );
    }
    if std::env::var("R7A_CUSTODY_SETTLEMENT").as_deref() == Ok("1") {
        let settled = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let count = rows
                    .lock()
                    .expect("settlement trace")
                    .iter()
                    .filter(|row| {
                        row["stage"] == "bridge_event" && row["value"]["event"] == "custody_settled"
                    })
                    .filter_map(|row| {
                        row["value"]["lease"]["lease_id"]
                            .as_str()
                            .map(str::to_owned)
                    })
                    .collect::<std::collections::HashSet<_>>()
                    .len();
                if count == acquired_count {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        note(
            &rows,
            start,
            "custody_settlement",
            json!({"complete":settled.is_ok(),"expected":acquired_count}),
        );
        settled.expect("every acquired lease receives its production custody settlement");
    }
    // Observe natural shutdown/public proof; no force-kill is a success condition.
    let shutdown = bridge.shutdown().await;
    note(
        &rows,
        start,
        "shutdown",
        json!({"result":format!("{shutdown:?}")}),
    );
    observer.abort();
    let _ = observer.await;
    std::fs::write(
        root.join("large-release.json"),
        serde_json::to_vec_pretty(&json!({
            "seed":seed,"path":path,"result":format!("{result:?}"),
            "shutdown":format!("{shutdown:?}"),"trace":*rows.lock().expect("final trace")
        }))
        .expect("encode trace"),
    )
    .expect("write release evidence");
    shutdown.expect("natural bridge shutdown");
    result.expect("large saved readback on the original router");
}

fn release_case(case: &str) {
    let root =
        PathBuf::from(std::env::var_os("N3_ENV_ROOT").expect("fresh prepared release environment"));
    let variables: std::collections::BTreeMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(root.join("rust-env.json")).expect("release runtime variables"),
    )
    .expect("valid private environment");
    let status = std::process::Command::new("timeout")
        .arg("180s")
        .arg(root.join("venv/bin/python"))
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/verify_nexus_release.py"))
        .arg("--root")
        .arg(&root)
        .arg("--binary")
        .arg(std::env::var_os("N9_RELEASE_BINARY").expect("explicit release binary"))
        .arg("--baseline")
        .arg(std::env::var_os("N4_BASELINE").expect("fixed N0 baseline"))
        .arg("--case")
        .arg(case)
        .env_clear()
        .envs(variables)
        .status_fenced()
        .expect("bounded real release driver");
    assert!(
        status.success(),
        "{case} failed with {status}; inspect persisted case result"
    );
    let evidence: Value = serde_json::from_slice(
        &std::fs::read(root.join(format!("{case}-result.json"))).expect("release case evidence"),
    )
    .expect("valid release evidence JSON");
    assert_eq!(evidence["case"], case);
    assert_eq!(evidence["status"], "PASS");
    assert_eq!(evidence["cleanup"], "PASS");
}

#[test]
fn e27_shutdown_and_same_product_restart() {
    release_case("E27");
}