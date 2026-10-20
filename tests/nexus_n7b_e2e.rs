//! Real E24/E25, selected one exact case per fresh prepared environment.
use ida_mcp::process_spawn::StdOutputFenced;
use std::path::PathBuf;

fn run(case: &str, sample_variable: &str) {
    assert_eq!(
        std::env::var("IDA_TEST").expect("explicit real IDA opt-in"),
        "1"
    );
    let root =
        PathBuf::from(std::env::var_os("N3_ENV_ROOT").expect("fresh prepared private environment"));
    let sample =
        PathBuf::from(std::env::var_os(sample_variable).expect("explicit read-only source sample"));
    let variables: std::collections::BTreeMap<String, String> = serde_json::from_slice(
        &std::fs::read(root.join("rust-env.json")).expect("private runtime variables"),
    )
    .expect("runtime JSON");
    let binary = std::env::var_os("N7B_E2E_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_ida-cli")));
    assert!(
        binary.is_absolute() && binary.is_file(),
        "explicit candidate binary must exist"
    );
    let status = std::process::Command::new("timeout")
        .arg(if case == "E25" { "330s" } else { "170s" })
        .arg(root.join("venv/bin/python"))
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/n7b_special.py"))
        .arg("--root")
        .arg(&root)
        .arg("--binary")
        .arg(binary)
        .arg("--case")
        .arg(case)
        .arg("--sample")
        .arg(sample)
        .env_clear()
        .envs(variables)
        .status_fenced()
        .expect("start real special-input driver");
    assert!(
        status.success(),
        "{case}: {status}; inspect the private case evidence"
    );
    let result: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(format!("{case}-result.json"))).expect("case result"),
    )
    .expect("case JSON");
    assert_eq!(result["case"], case);
    assert_eq!(result["status"], "PASS");
}
#[test]
fn e24_real_sbpf_build_query_decompile_and_cached_reopen() {
    run("E24", "N7B_SBPF_SAMPLE");
}
#[test]
fn e24_real_sbpf_idat_cancel_reaps_owned_tree() {
    run("E24-cancel", "N7B_SBPF_SAMPLE");
}
#[test]
fn e25_real_dsc_new_existing_and_cached_reopen() {
    run("E25", "N7B_DSC_SAMPLE");
}
