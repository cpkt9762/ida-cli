//! Real N4 acceptance through the actual CLI and both MCP transports.
//! The Python driver uses only the fixed binary baseline, never old source.
use ida_mcp::process_spawn::StdOutputFenced;
use serde_json::Value;
use std::path::PathBuf;

fn contract(case: &str) {
    assert_eq!(std::env::var("IDA_TEST").expect("real IDA opt-in"), "1");
    let root = PathBuf::from(std::env::var_os("N3_ENV_ROOT").expect("fresh prepared environment"));
    let variables: std::collections::BTreeMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(root.join("rust-env.json")).expect("isolated runtime variables"),
    )
    .expect("valid environment JSON");
    let baseline = std::env::var_os("N4_BASELINE").expect("independent N0 baseline binary");
    let status = std::process::Command::new("timeout")
        // E04/E16 aggregate dozens of real CLI children and custody cleanup.
        // E22 has three native baseline starts; the whole suite remains 180s.
        .arg(if case == "E22" {
            "90s"
        } else if matches!(case, "E04" | "E16") {
            "120s"
        } else {
            "30s"
        })
        .arg(root.join("venv/bin/python"))
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/compare_nexus_baseline.py"))
        .arg("--root")
        .arg(&root)
        .arg("--baseline")
        .arg(baseline)
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_ida-cli"))
        .arg("--case")
        .arg(case)
        .env_clear()
        .envs(variables)
        .status_fenced()
        .expect("launch real contract driver with shell timeout");
    assert!(
        status.success(),
        "{case} failed with {status}; see environment logs"
    );
    let result: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(format!("{case}-result.json")))
            .expect("persisted scenario evidence"),
    )
    .expect("valid scenario JSON");
    assert_eq!(result["case"], case);
    assert_eq!(result["status"], "PASS");
}

#[test]
fn e04_fixed_n0_output_comparison() {
    contract("E04");
}
#[test]
fn e16_cli_stdio_http_and_independent_close_token() {
    contract("E16");
}
#[test]
fn e17_unicode_streams_errors_and_response_cache() {
    contract("E17");
}
#[test]
fn e22_old_cache_proof_preserves_edits_and_warm_lease() {
    contract("E22");
}
