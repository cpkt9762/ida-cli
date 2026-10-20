use super::*;
use crate::preprocess::Preparation;
use serde_json::json;

fn resolved_handle(value: &(DbHandle, CliLeaseGuard)) -> &str {
    &value.0
}

async fn query(
    router: &RouterState,
    handle: &str,
) -> Result<serde_json::Value, crate::error::ToolError> {
    router
        .route_request_prepared(Some(handle), "list_functions", json!({}), budget())
        .await
}

fn budget() -> Preparation {
    Preparation::new(Duration::from_secs(60))
}

async fn rig(capacity: usize) -> (RouterState, PathBuf) {
    static IDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let root =
        PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private test root")).join(format!(
            "cli-warm-{}-{}",
            std::process::id(),
            IDS.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&root).expect("fresh private CLI fixture");
    for name in ["a", "b", "c", "d"] {
        std::fs::copy(
            std::env::var_os("R2_REAL_INPUT").expect("private mini seed"),
            root.join(name),
        )
        .expect("sample copy");
    }
    let mut config = RouterConfig::from_env();
    config.max_warm_workers = capacity;
    let router = RouterState::with_config(config).expect("explicit warm capacity");
    router
        .connect_nexus(nexus_bridge::BridgeConfig {
            python: PathBuf::from(std::env::var_os("F1_PYTHON").expect("prepared Python")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/nexus_client_fixture.py"),
            directory: root.join("ipc"),
            environment: std::env::vars().collect(),
        })
        .await
        .expect("actual Nexus bridge");
    (router, root)
}

async fn acquire(
    router: &RouterState,
    path: &std::path::Path,
) -> Result<(DbHandle, CliLeaseGuard), crate::error::ToolError> {
    router
        .ensure_cli_worker_prepared(path.to_str().expect("sample path"), None, budget())
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unrelated_warm_and_cold_paths_pass_a_blocked_open_and_same_path_coalesces() {
    let (router, root) = rig(6).await;
    let warm = acquire(&router, &root.join("b")).await.expect("warm B");
    drop(warm);
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    router
        .cli_open_pause
        .lock()
        .await
        .insert(root.join("a"), (entered.clone(), resume.clone()));
    let a_router = router.clone();
    let a_path = root.join("a");
    let a = tokio::spawn(async move { acquire(&a_router, &a_path).await });
    tokio::time::timeout(Duration::from_secs(10), entered.notified())
        .await
        .expect("A reached first-open barrier");
    let mut same = Vec::new();
    for _ in 0..1 {
        let router = router.clone();
        let path = root.join(".").join("a");
        same.push(tokio::spawn(async move { acquire(&router, &path).await }));
    }
    let b = tokio::time::timeout(Duration::from_secs(2), acquire(&router, &root.join("b"))).await;
    let c = tokio::time::timeout(Duration::from_secs(10), acquire(&router, &root.join("c"))).await;
    resume.notify_one();
    let first = a.await.expect("A task").expect("A open");
    let mut matching = Vec::new();
    for task in same {
        matching.push(task.await.expect("same path task").expect("same path open"));
    }
    for request in &matching {
        assert_eq!(
            resolved_handle(request),
            resolved_handle(&first),
            "canonical aliases share the exact lease"
        );
    }
    let handles = router.nexus_tools.handles();
    drop((first, matching, b.as_ref().ok(), c.as_ref().ok()));
    // Request guards are released before shutdown once pinning is implemented.
    let b_ok = matches!(b, Ok(Ok(_)));
    let c_ok = matches!(c, Ok(Ok(_)));
    drop((b, c));
    router
        .shutdown_nexus()
        .await
        .expect("confirmed test cleanup");
    assert!(b_ok, "warm B waited for unrelated A");
    assert_eq!(
        handles.len(),
        3,
        "one lease per canonical path, not per simultaneous caller"
    );
    assert!(c_ok, "new C waited for unrelated A");
}

#[tokio::test]
async fn in_use_entry_is_not_evicted_and_full_capacity_uses_a_request_reference() {
    let (router, root) = rig(1).await;
    let b = acquire(&router, &root.join("b"))
        .await
        .expect("pin B before dispatch");
    let c = acquire(&router, &root.join("c"))
        .await
        .expect("full pinned pool cannot reject C");
    let c_result = query(&router, resolved_handle(&c)).await;
    let pool = router.warm_pool.lock().await;
    let retained = pool.contains_key(&root.join("b")) && !pool.contains_key(&root.join("c"));
    assert_eq!(pool.len(), 1, "warm capacity remains exact");
    drop(pool);
    let b_result = query(&router, resolved_handle(&b)).await;
    let prewarm = router
        .prewarm_path_with_options(root.join("d").to_str().unwrap(), true, "default")
        .await;
    let prewarm_completed_without_retention = prewarm.as_ref().is_ok_and(|value| {
        value["kept_warm"] == false
            && value["database_info"]["function_count"]
                .as_u64()
                .is_some_and(|count| count >= 2)
    });
    drop((b, c));
    router
        .shutdown_nexus()
        .await
        .expect("cleanup all request references");
    assert!(
        retained,
        "in-use warm B was evicted instead of using a request-level C reference"
    );
    assert!(
        b_result.is_ok(),
        "eviction invalidated B's admitted request: {b_result:?}"
    );
    assert!(
        c_result.is_ok(),
        "capacity fallback did not execute C: {c_result:?}"
    );
    assert!(
        prewarm_completed_without_retention,
        "full pinned pool must report actual retention without failing prewarm: {prewarm:?}"
    );
}

#[tokio::test]
async fn failed_eviction_keeps_the_exact_warm_token_tracked() {
    let (router, root) = rig(1).await;
    let b = acquire(&router, &root.join("b")).await.expect("warm B");
    let handle = resolved_handle(&b).to_string();
    let token = router.warm_pool.lock().await[&root.join("b")].token.clone();
    drop(b);
    let started = root.join("started");
    let resume = root.join("resume");
    let worker = router.clone();
    let code = format!("from pathlib import Path\nimport time\nPath({:?}).touch()\nwhile not Path({:?}).exists(): time.sleep(.01)\nprint('completed')", started.to_str().unwrap(), resume.to_str().unwrap());
    // Deliberately use this lease outside the CLI pin: N1 must independently
    // reject eviction, and its failure must not discard pool responsibility.
    let work = tokio::spawn(async move {
        worker
            .route_request_prepared(Some(&handle), "run_script", json!({"code":code}), budget())
            .await
    });
    tokio::time::timeout(Duration::from_secs(15), async {
        while !started.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("actual cooperative operation started");
    let error = acquire(&router, &root.join("c"))
        .await
        .err()
        .map(|error| error.to_string());
    let tracked = router
        .warm_pool
        .lock()
        .await
        .get(&root.join("b"))
        .map(|entry| entry.token.clone());
    std::fs::write(resume, b"complete").expect("release operation barrier");
    let terminal = work
        .await
        .expect("operation task")
        .expect("definite terminal");
    assert_eq!(terminal["stdout"], "completed\n");
    router.shutdown_nexus().await.expect("cleanup retained B");
    assert!(
        error
            .as_deref()
            .is_some_and(|message| message.contains("CancelPending")),
        "actual close error must be reported: {error:?}"
    );
    assert_eq!(
        tracked,
        Some(token),
        "failed close lost its exact warm authority"
    );
}

#[tokio::test]
async fn explicit_close_and_shutdown_refuse_a_pinned_but_not_yet_dispatched_request() {
    let (router, root) = rig(1).await;
    let b = acquire(&router, &root.join("b"))
        .await
        .expect("admitted before N1 enqueue");
    let close = router.nexus_close_path_detailed(&root.join("b")).await.0;
    let shutdown = router.shutdown_nexus().await;
    let tracked = router.warm_pool.lock().await.contains_key(&root.join("b"));
    drop(b);
    router
        .shutdown_nexus()
        .await
        .expect("shutdown succeeds after the pin ends");
    assert!(
        close.is_err() && shutdown.is_err(),
        "busy request must retain service and lease"
    );
    assert!(tracked, "refusal removed warm tracking");
}

#[tokio::test]
async fn prewarm_does_not_replace_a_reference_held_by_a_cli_request() {
    let (router, root) = rig(1).await;
    let b = acquire(&router, &root.join("b")).await.expect("admitted B");
    let token = router.warm_pool.lock().await[&root.join("b")].token.clone();
    let prewarm = router
        .prewarm_path_with_options(root.join("b").to_str().unwrap(), true, "default")
        .await;
    let retained = router.warm_pool.lock().await[&root.join("b")].token == token;
    let usable = query(&router, resolved_handle(&b)).await;
    drop(b);
    router.shutdown_nexus().await.expect("cleanup prewarm");
    assert!(
        prewarm.is_ok(),
        "prewarm on existing warm path: {prewarm:?}"
    );
    assert!(
        retained && usable.is_ok(),
        "prewarm replaced an in-use close authority"
    );
}

#[tokio::test]
async fn zero_warm_capacity_still_runs_a_request_reference() {
    let (router, root) = rig(0).await;
    let request = acquire(&router, &root.join("b")).await;
    let worked = match &request {
        Ok(request) => query(&router, resolved_handle(request)).await.is_ok(),
        Err(_) => false,
    };
    drop(request);
    router
        .shutdown_nexus()
        .await
        .expect("cleanup uncached request");
    assert!(worked, "disabling retention cannot disable CLI operations");
}
