use super::*;

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
