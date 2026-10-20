use super::*;
use crate::preprocess::Preparation;

fn budget() -> Preparation {
    Preparation::new(Duration::from_secs(60))
}

async fn rig(capacity: usize) -> (RouterState, PathBuf) {
    static IDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private test root"))
        .join(format!("cli-warm-{}-{}", std::process::id(), IDS.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir(&root).expect("fresh private CLI fixture");
    for name in ["a", "b", "c", "d"] {
        std::fs::copy(std::env::var_os("R2_REAL_INPUT").expect("private mini seed"), root.join(name)).expect("sample copy");
    }
    let mut config = RouterConfig::from_env();
    config.max_warm_workers = capacity;
    let router = RouterState::with_config(config).expect("explicit warm capacity");
    router.connect_nexus(nexus_bridge::BridgeConfig {
        python: PathBuf::from(std::env::var_os("F1_PYTHON").expect("prepared Python")),
        script: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/nexus_client_fixture.py"),
        directory: root.join("ipc"),
        environment: std::env::vars().collect(),
    }).await.expect("actual Nexus bridge");
    (router, root)
}

async fn acquire(router: &RouterState, path: &std::path::Path) -> Result<DbHandle, crate::error::ToolError> {
    router.ensure_cli_worker_prepared(path.to_str().expect("sample path"), None, budget()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unrelated_warm_and_cold_paths_pass_a_blocked_open_and_same_path_coalesces() {
    let (router, root) = rig(6).await;
    let warm = acquire(&router, &root.join("b")).await.expect("warm B");
    drop(warm);
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    router.cli_open_pause.lock().await.insert(root.join("a"), (entered.clone(), resume.clone()));
    let a_router = router.clone();
    let a_path = root.join("a");
    let a = tokio::spawn(async move { acquire(&a_router, &a_path).await });
    tokio::time::timeout(Duration::from_secs(10), entered.notified()).await.expect("A reached first-open barrier");
    let mut same = Vec::new();
    for _ in 0..1 {
        let router = router.clone();
        let path = root.join("a");
        same.push(tokio::spawn(async move { acquire(&router, &path).await }));
    }
    let b = tokio::time::timeout(Duration::from_secs(2), acquire(&router, &root.join("b"))).await;
    let c = tokio::time::timeout(Duration::from_secs(10), acquire(&router, &root.join("c"))).await;
    resume.notify_one();
    let first = a.await.expect("A task").expect("A open");
    let mut matching = Vec::new();
    for task in same { matching.push(task.await.expect("same path task").expect("same path open")); }
    let handles = router.nexus_tools.handles();
    drop((first, matching, b.as_ref().ok(), c.as_ref().ok()));
    // Request guards are released before shutdown once pinning is implemented.
    let b_ok = matches!(b, Ok(Ok(_)));
    let c_ok = matches!(c, Ok(Ok(_)));
    drop((b, c));
    router.shutdown_nexus().await.expect("confirmed test cleanup");
    assert!(b_ok, "warm B waited for unrelated A");
    assert_eq!(handles.len(), 3, "one lease per canonical path, not per simultaneous caller");
    assert!(c_ok, "new C waited for unrelated A");
}
