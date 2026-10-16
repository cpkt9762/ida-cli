//! Real N6 write, output, persistence and cancellation acceptance.
#[path = "support/nexus_env.rs"]
mod env;
use env::*;
use ida_mcp::nexus::*;
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};

fn scenario(case: &str) {
    assert_eq!(std::env::var("IDA_TEST").expect("real IDA opt-in"), "1");
    let status = std::process::Command::new("timeout")
        .arg("150s")
        .arg(root().join("venv/bin/python"))
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/compare_nexus_n6.py"))
        .arg("--root")
        .arg(root())
        .arg("--baseline")
        .arg(std::env::var_os("N4_BASELINE").expect("fixed N0"))
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_ida-cli"))
        .arg("--case")
        .arg(case)
        .env_clear()
        .envs(variables())
        .status()
        .expect("launch bounded N6 real driver");
    assert!(status.success(), "{case}: {status}");
    let result: Value = serde_json::from_str(
        &std::fs::read_to_string(root().join(format!("{case}-result.json")))
            .expect("scenario evidence"),
    )
    .expect("scenario JSON");
    assert_eq!(result["status"], "PASS");
}

#[test]
fn n6_e04_all_write_and_advanced_methods() {
    scenario("E04-N6");
}
#[test]
fn n6_e20_seven_categories_survive_save_close_reopen() {
    scenario("E20");
}
#[test]
fn n6_tools_and_aliases_preserve_mcp_contract() {
    scenario("N6-tools");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n6_e20_cancelled_write_retains_first_slice_without_replay() {
    let mut client = Client::new().await;
    let (lease, _) = client.open(&sample("n6-write-cancel"), json!({})).await;
    let functions = client.value(&lease, "list_functions", json!({})).await;
    assert_eq!(functions["ok"], true, "list functions: {functions}");
    let ea = functions["value"]["functions"][0]["address"].clone();
    assert!(
        ea.as_str().is_some_and(|s| s.starts_with("0x")),
        "real function address: {functions}"
    );
    let job = id();
    let op = client.begin(
        &lease,
        "batch_rename",
        json!({"_n5_job":job,
        "renames":[{"address":ea,"new_name":"n6_first_committed"},
                   {"address":ea,"new_name":"n6_must_not_execute"}]}),
    );
    client
        .event(|event| {
            event["event"] == "yielded"
                && event["attempt"]["target"]["identity"]["operation_id"]
                    == op.operation_id.as_str()
        })
        .await;
    let stopped = client
        .bridge
        .endpoint()
        .transition(|s, t| {
            let progress = s.operation_progress(&client.client, &op)?;
            assert_eq!(progress.status, OperationStatus::Queued);
            assert!(progress.execution_stopped);
            s.cancel(&client.client, &op, CancelReason::Client, t)
        })
        .expect("cancel only the queued continuation");
    assert_eq!(stopped.status, OperationStatus::Cancelled);
    assert!(stopped.execution_stopped);
    assert!(stopped
        .error
        .as_ref()
        .expect("partial effects warning")
        .message
        .contains("effects may remain"));
    // Explicit cleanup is serialized through the same public Execute queue.
    client
        .value(&lease, "_n5_cleanup", json!({"_n5_job":job}))
        .await;
    let observed = client
        .value(
            &lease,
            "get_function_by_name",
            json!({"name":"n6_first_committed"}),
        )
        .await;
    assert_eq!(observed["ok"], true, "first slice readback: {observed}");
    assert_eq!(observed["value"]["address"], ea);
    assert_eq!(observed["value"]["name"], "n6_first_committed");
    let second = client
        .value(
            &lease,
            "get_function_by_name",
            json!({"name":"n6_must_not_execute"}),
        )
        .await;
    assert_eq!(
        second["ok"], false,
        "cancelled second slice must not run: {second}"
    );
    assert!(
        second["error"]
            .as_str()
            .expect("business error text")
            .contains("Function not found: n6_must_not_execute"),
        "{second}"
    );
    let code = "import sys,json\nm=sys.modules['_ida_cli_nexus_slices_v1']\nprint(json.dumps([len(m.jobs),m.counter is None]))";
    let clean = client
        .value(&lease, "run_script", json!({"code":code}))
        .await;
    assert_eq!(clean["ok"], true, "hook readback: {clean}");
    assert_eq!(clean["value"]["stdout"], "[0, true]\n");
    assert_eq!(clean["value"]["stderr"], "");
    record(
        json!({"case":"E20-cancel","status":"PASS","operation":stopped,
                  "first_slice":observed,"readback":second,"hooks":clean}),
    );
    client.release(&lease).await;
    tokio::time::timeout(Duration::from_secs(10), client.bridge.shutdown())
        .await
        .expect("bridge stop deadline")
        .expect("owned bridge stopped");
}
