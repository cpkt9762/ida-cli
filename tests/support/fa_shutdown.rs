use super::*;

#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_shutdown_waits_for_exact_helper_retirement() {
    let root = std::env::temp_dir().join(format!("fa-shutdown-{}", std::process::id()));
    std::fs::create_dir(&root).expect("fresh shutdown case");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R0_CASE_ROOT".into(), root.display().to_string());
    environment.insert("R0_SCENARIO".into(), "healthy".into());
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    let router = super::super::RouterState::new().expect("router");
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("F1_PYTHON").expect("prepared Python")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r0_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("actual bridge and helper");
    let helper = bridge.state.helper.as_ref().expect("actual helper");
    helper
        .call(json!({"kind":"reserve_parent", "parent":"held-retirement"}))
        .await
        .expect("reserve delayed retirement");
    let mut events = bridge.subscribe();
    let shutting = bridge.clone();
    let mut shutdown = tokio::spawn(async move { shutting.shutdown().await });
    // Keep the parent reserved until shutdown positively reaches its wait gate.
    // The old code closes the bridge then fails finish instead of reaching it.
    let (waited, early) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::select! {
            result = &mut shutdown => (false, Some(result.expect("shutdown task"))),
            () = async { loop { if events.recv().await.expect("shutdown event")["event"] == "shutdown_observations_pending" { break; } } } => (true, None),
        }
    }).await.expect("bounded shutdown scheduling barrier");
    helper
        .call(json!({"kind":"retire_parent", "parent":"held-retirement"}))
        .await
        .expect("release exact reservation");
    let result = match early {
        Some(result) => result,
        None => shutdown.await.expect("shutdown task"),
    };
    if result.is_err() {
        helper.finish().await.expect("red-run helper cleanup");
    }
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec(&json!({"wait_gate":waited,"shutdown":format!("{result:?}")}))
            .expect("encode"),
    )
    .expect("evidence");
    assert!(
        waited,
        "raw shutdown bypassed the held helper retirement barrier: {result:?}"
    );
    result.expect("natural shutdown after retirement");
}

/// The bridge died after its helper signed an obligation but before Rust learned of
/// it (F: bridge death during a cold open). Rust tracks nothing, the exact bridge
/// process is gone, and no router code can advance what only the helper holds.
/// Shutdown must complete in bounded time and leave that obligation durable.
#[cfg(feature = "nexus-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_after_bridge_death_retains_untracked_helper_obligation() {
    let root = std::env::temp_dir().join(format!("fa-bridge-death-{}", std::process::id()));
    std::fs::create_dir(&root).expect("fresh bridge-death case");
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R0_CASE_ROOT".into(), root.display().to_string());
    environment.insert("R0_SCENARIO".into(), "healthy".into());
    environment.insert(
        "IDA_NEXUS_STATE_DIR".into(),
        root.join("state").display().to_string(),
    );
    let router = super::super::RouterState::new().expect("router");
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("F1_PYTHON").expect("prepared Python")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r0_bridge_fixture.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("actual bridge and helper");
    let helper = bridge.state.helper.as_ref().expect("actual helper");
    helper
        .call(json!({"kind":"reserve_parent", "parent":"signed-before-rust-knew"}))
        .await
        .expect("helper holds an obligation Rust never tracked");
    bridge.terminate().await.expect("kill only the own bridge");
    tokio::time::timeout(Duration::from_secs(5), async {
        while bridge
            .state
            .bridge_exit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("exact waitpid of the dead bridge");
    let lifecycle = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let lifecycle = bridge.lifecycle_status();
            if lifecycle["untracked_helper_obligations"].is_object() {
                return lifecycle;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("status names the helper-only obligation");
    assert_eq!(lifecycle["resources"], 0);
    assert_eq!(lifecycle["startup_and_pre_attach"], 0);
    assert_eq!(lifecycle["ready"], false);
    assert_eq!(
        lifecycle["next_action"],
        "shutdown_then_restart_helper_retains_obligations"
    );
    assert_eq!(lifecycle["untracked_helper_obligations"]["parent_count"], 1);
    // A lost bridge is never replaced: opens fail at once with the restart
    // guidance instead of queueing behind locks the dead acquisition retains.
    let refused = tokio::time::timeout(
        Duration::from_secs(2),
        router.refresh_nexus_cache(
            "/nonexistent-bridge-death-case",
            crate::preprocess::Preparation::new(Duration::from_secs(60)),
        ),
    )
    .await
    .expect("a lost bridge refuses opens immediately");
    let Err(refused) = refused else {
        panic!("a lost bridge cannot open");
    };
    let refused = refused.to_string();
    assert!(
        refused.contains("bridge disconnected") && refused.contains("ida-cli shutdown"),
        "open after bridge loss must name the restart path: {refused}"
    );
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(25), bridge.shutdown())
        .await
        .map(|result| result.map_err(|error| error.to_string()));
    let elapsed = started.elapsed();
    let held = helper
        .call(json!({"kind":"heartbeat", "summary_only":true}))
        .await
        .map(|reply| reply["parent_count"].clone());
    // Test hygiene only: the product leaves this to the helper's orphan expiry.
    helper
        .call(json!({"kind":"retire_parent", "parent":"signed-before-rust-knew"}))
        .await
        .expect("release the fixture reservation");
    helper.finish().await.expect("fixture helper cleanup");
    std::fs::write(
        root.join("result.json"),
        serde_json::to_vec(&json!({"shutdown":format!("{result:?}"),
            "elapsed_ms":elapsed.as_millis() as u64,"held":format!("{held:?}")}))
        .expect("encode"),
    )
    .expect("evidence");
    assert!(
        matches!(result, Ok(Ok(()))),
        "shutdown after bridge death must not be refused forever: {result:?} after {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(12),
        "shutdown must be bounded: {elapsed:?}"
    );
    assert_eq!(
        held.expect("helper still reachable"),
        json!(1),
        "the untracked obligation stays durable in the helper"
    );
}

#[test]
fn pending_history_head_cannot_block_retirement_of_later_closed_records() {
    let mut history = std::collections::VecDeque::from([
        json!({"name":"pending", "ready":false}),
        json!({"name":"closed-old", "ready":true}),
        json!({"name":"closed-new", "ready":true}),
    ]);
    let retired = take_closed_history(&mut history, 1, |item| item["ready"] == true);
    assert_eq!(retired, vec![json!({"name":"closed-old", "ready":true})]);
    assert_eq!(
        history,
        std::collections::VecDeque::from([
            json!({"name":"pending", "ready":false}),
            json!({"name":"closed-new", "ready":true}),
        ])
    );
}
