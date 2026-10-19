//! N7a: real Nexus cache owners and real router preprocessing cancellation.
use ida_mcp::process_spawn::StdOutputFenced;
use std::path::PathBuf;

fn special(case: &str) {
    assert_eq!(
        std::env::var("IDA_TEST").expect("explicit real IDA opt-in"),
        "1"
    );
    let root =
        PathBuf::from(std::env::var_os("N3_ENV_ROOT").expect("prepared private environment"));
    let variables: std::collections::BTreeMap<String, String> = serde_json::from_slice(
        &std::fs::read(root.join("rust-env.json")).expect("private environment variables"),
    )
    .expect("environment JSON");
    let status = std::process::Command::new("timeout")
        .arg("30s")
        .arg(root.join("venv/bin/python"))
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/n7_special.py"))
        .arg("--root")
        .arg(&root)
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_ida-cli"))
        .arg("--case")
        .arg(case)
        .env_clear()
        .envs(variables)
        .status_fenced()
        .expect("start real special-input driver");
    assert!(
        status.success(),
        "{case}: {status}; see environment evidence"
    );
}
#[test]
fn e21_external_owner_and_refresh() {
    special("E21-held");
}
#[test]
fn e21_before_rename() {
    special("E21-before-rename");
}
#[test]
fn e21_after_rename() {
    special("E21-after-rename");
}
#[test]
fn e21_before_delete() {
    special("E21-before-delete");
}
#[test]
fn e21_release_grace_reclaim_and_reopen() {
    special("E21-release");
}
#[test]
fn e19_router_preprocessor_cancel() {
    special("E19");
}
#[test]
fn f3_cold_routers_share_edits_and_prewarm_hits() {
    special("F3-cold");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e21_router_lease_excludes_actual_store_gc() {
    let root = PathBuf::from(std::env::var_os("N3_ENV_ROOT").expect("fresh environment"));
    let router = ida_mcp::router::RouterState::new().expect("real Nexus router");
    let (_, token) = router
        .ensure_worker_prepared(
            root.join("fixtures/mini").to_str().expect("UTF-8 fixture"),
            None,
            None,
            ida_mcp::preprocess::Preparation::new(std::time::Duration::from_secs(15)),
        )
        .await
        .expect("real cache open");
    let cache = root.join("cli-home/idb");
    let directory = std::fs::read_dir(cache.join("generations"))
        .expect("published generation")
        .next()
        .expect("one generation")
        .expect("generation entry")
        .path();
    let before = std::fs::read(directory.join("input")).expect("retained input");
    let held_root = cache.clone();
    let stats = tokio::task::spawn_blocking(move || {
        ida_mcp::idb_store::IdbStore::with_root(held_root).evict_to_limit(0, &Default::default())
    })
    .await
    .expect("bounded GC worker");
    assert_eq!(stats.evicted_groups, 0);
    assert_eq!(
        std::fs::read(directory.join("input")).expect("active input survives"),
        before
    );
    router
        .nexus_close_token(&token)
        .await
        .expect("release actual owner");
    router
        .shutdown_nexus()
        .await
        .expect("private bridge shutdown");
    let released_root = cache.clone();
    let deleted = tokio::task::spawn_blocking(move || {
        let store = ida_mcp::idb_store::IdbStore::with_root(released_root);
        assert_eq!(
            store.evict_to_limit(0, &Default::default()).evicted_groups,
            0
        );
        store.evict_to_limit(0, &Default::default()).evicted_groups
    })
    .await
    .expect("released GC worker");
    assert_eq!(
        deleted, 1,
        "released generation reclaimed only after repeated checks"
    );
    assert!(!directory.exists());
    std::fs::write(root.join("E21-lock-result.json"), r#"{"case":"E21-lock","status":"PASS","held_guard_rejected_gc":true,"released_generation_reclaimed":true}"#)
        .expect("persist lock evidence");
}
