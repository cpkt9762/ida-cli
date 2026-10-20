//! Script argument failures are local admission failures, before bridge startup.
use ida_mcp::{error::ToolError, router::RouterState};
use serde_json::json;

#[tokio::test]
async fn script_input_errors_precede_any_nexus_action() {
    for (params, expected) in [
        (
            json!({}),
            "Provide either 'code' (inline Python) or 'file' (path to .py)",
        ),
        (
            json!({"code":"print('x')","file":"ignored.py"}),
            "Provide either 'code' or 'file', not both",
        ),
    ] {
        let router = RouterState::new().expect("private router");
        let error = router
            .route_request(None, "run_script", params)
            .await
            .expect_err("invalid script arguments");
        assert!(
            matches!(&error, ToolError::InvalidParams(message) if message == expected),
            "{error:?}"
        );
        assert!(
            router.status_snapshot().await.nexus_lifecycle.is_none(),
            "no bridge for invalid input"
        );
    }
}

#[tokio::test]
async fn script_file_read_failure_precedes_any_nexus_action() {
    let router = RouterState::new().expect("private router");
    let path = std::env::temp_dir().join(format!("missing-script-{}.py", std::process::id()));
    assert!(!path.exists());
    let error = router
        .route_request(None, "run_script", json!({"file":path}))
        .await
        .expect_err("missing file");
    assert!(
        matches!(&error,ToolError::InvalidPath(message) if message.starts_with("Failed to read script file '")),
        "{error:?}"
    );
    assert!(
        router.status_snapshot().await.nexus_lifecycle.is_none(),
        "no bridge for failed read"
    );
}

#[tokio::test]
async fn enqueue_rejects_missing_script_without_task_or_bridge() {
    let router = RouterState::new().expect("private router");
    let error = router
        .enqueue_route_task(
            "unused-binary",
            "run_script",
            json!({"file":"missing-script.py"}),
            None,
            0,
            None,
        )
        .await
        .expect_err("reject before queue publication");
    assert!(matches!(error, ToolError::InvalidPath(_)));
    assert!(router.list_task_states().is_empty());
    assert!(router.status_snapshot().await.nexus_lifecycle.is_none());
    assert_eq!(
        router
            .nexus_endpoint()
            .transition(|s, _| s.retention_status())
            .total_used,
        0
    );
}

#[tokio::test]
async fn script_file_resolves_once_and_inline_empty_code_stays_valid() {
    use ida_mcp::preprocess::Preparation;
    use std::time::Duration;
    let path = std::env::temp_dir().join(format!("resolved-script-{}.py", std::process::id()));
    std::fs::write(&path, "print('resolved')").expect("private script");
    let preparation = Preparation::new(Duration::from_secs(3));
    let params = RouterState::prepare_request_params(
        "run_script",
        json!({"file":path,"timeout_secs":2}),
        &preparation,
    )
    .await
    .expect("bounded file read");
    std::fs::remove_file(path).expect("remove source before second admission");
    let resolved = RouterState::prepare_request_params("run_script", params, &preparation)
        .await
        .expect("no second file read");
    assert_eq!(resolved["code"], "print('resolved')");
    let empty = RouterState::prepare_request_params("run_script", json!({"code":""}), &preparation)
        .await
        .expect("explicit empty code is valid");
    assert_eq!(empty["code"], "");
}
