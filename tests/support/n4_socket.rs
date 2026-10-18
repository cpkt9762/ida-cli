use super::*;
use tokio::io::AsyncBufReadExt;

#[tokio::test]
async fn n4_fix_busy_shutdown_does_not_exit() {
    if !crate::router::n4_fix_regressions::isolated(
        "server::socket_listener::n4_fix_regressions::n4_fix_busy_shutdown_does_not_exit",
    )
    .await
    {
        return;
    }
    let router = RouterState::new().unwrap();
    assert!(router.uses_nexus());
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let job = tokio::spawn(async move {
        let input = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        handle_cli_connection(
            server,
            &router,
            &signal,
            input.acquire_owned().await.unwrap(),
            std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
            std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        )
        .await
        .unwrap();
    });
    let (reader, mut writer) = client.into_split();
    writer
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"s\",\"method\":\"shutdown\",\"params\":{}}\n")
        .await
        .unwrap();
    let mut line = String::new();
    BufReader::new(reader).read_line(&mut line).await.unwrap();
    let response: RpcResponse = serde_json::from_str(&line).unwrap();
    assert!(response.error.unwrap().message.contains("Busy"));
    job.await.unwrap();
    assert!(
        !shutdown.is_cancelled(),
        "rejected shutdown must leave service running"
    );
}

#[tokio::test]
async fn n4_fix_task_status_uses_control_dispatch() {
    if !crate::router::n4_fix_regressions::isolated(
        "server::socket_listener::n4_fix_regressions::n4_fix_task_status_uses_control_dispatch",
    )
    .await
    {
        return;
    }
    let router = RouterState::new().unwrap();
    for method in ["task_status", "get_task_status"] {
        let (response, _) = dispatch_cli_request(
            &RpcRequest::new("task", method, serde_json::json!({"task_id":"missing"})),
            &router,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(response.error.unwrap().message, "unknown task_id");
    }
}
