use crate::router::protocol::{RpcRequest, RpcResponse};
use crate::router::RouterState;
use crate::tool_registry::primary_name_for;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::UnixListener;
use tracing::{debug, info};

pub async fn run_socket_listener(socket_path: PathBuf, router: RouterState) -> anyhow::Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    info!("CLI socket listening on {:?}", socket_path);

    let discovery_path = std::path::Path::new("/tmp/ida-cli.socket");
    std::fs::write(discovery_path, socket_path.to_string_lossy().as_bytes())?;

    loop {
        let (stream, _) = listener.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_cli_connection(stream, &router).await {
                debug!("CLI connection ended: {}", e);
            }
        });
    }
}

pub fn cleanup_socket_files(socket_path: &std::path::Path) {
    let _ = std::fs::remove_file(socket_path);
    let _ = std::fs::remove_file("/tmp/ida-cli.socket");
}

async fn handle_cli_connection(
    stream: tokio::net::UnixStream,
    router: &RouterState,
) -> anyhow::Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut line = String::new();

    reader.read_line(&mut line).await?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let resp = match serde_json::from_str::<RpcRequest>(trimmed) {
        Ok(req) => {
            let (mut response, ref_guard) = dispatch_cli_request(&req, router).await;
            if let Some(result) = response.result.take() {
                response.result = Some(super::response_cache::guard_response_size(
                    &req.method,
                    result,
                ));
            }
            let _ = ref_guard;
            response
        }
        Err(e) => RpcResponse::err("null", -32700, format!("Parse error: {e}")),
    };

    let json = serde_json::to_string(&resp)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

struct CliRefGuard {
    router: RouterState,
    token: String,
}

impl Drop for CliRefGuard {
    fn drop(&mut self) {
        let router = self.router.clone();
        let token = self.token.clone();
        tokio::spawn(async move {
            router.release_ref_token(&token).await;
        });
    }
}

async fn dispatch_cli_request(
    req: &RpcRequest,
    router: &RouterState,
) -> (RpcResponse, Option<CliRefGuard>) {
    let method = primary_name_for(&req.method);

    let path = req
        .params
        .get("path")
        .and_then(|v| v.as_str())
        .map(String::from);
    let tenant_id = req
        .params
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .map(String::from);

    match method {
        "close" => {
            let resp = if let Some(ref p) = path {
                let canonical =
                    std::fs::canonicalize(p).unwrap_or_else(|_| std::path::PathBuf::from(p));
                match router.close_by_path(&canonical, tenant_id.as_deref()).await {
                    Ok(()) => RpcResponse::ok(&req.id, serde_json::json!({"ok": true})),
                    Err(e) => RpcResponse::err(&req.id, -32000, e.to_string()),
                }
            } else {
                RpcResponse::err(&req.id, -32001, "close requires 'path' parameter")
            };
            (resp, None)
        }

        "shutdown" => {
            router.shutdown_all().await;
            let resp = RpcResponse::ok(
                &req.id,
                serde_json::json!({"ok": true, "message": "server shutting down"}),
            );
            (resp, None)
        }

        "status" => {
            let status = router.status_snapshot().await;
            let resp = RpcResponse::ok(
                &req.id,
                serde_json::to_value(status).unwrap_or_else(|_| serde_json::json!({})),
            );
            (resp, None)
        }
        "list_tasks" => {
            let tasks: Vec<_> = router
                .list_task_states()
                .into_iter()
                .filter_map(|state| {
                    Some(serde_json::json!({
                        "task_id": state.id,
                        "message": state.message,
                        "created_at": state.created_at_iso,
                        "updated_at": state.updated_at_iso,
                        "status": match state.status {
                            crate::server::task::TaskStatus::Running => "running",
                            crate::server::task::TaskStatus::Completed => "completed",
                            crate::server::task::TaskStatus::Failed => "failed",
                            crate::server::task::TaskStatus::Cancelled => "cancelled",
                        },
                        "result": state.result,
                    }))
                })
                .collect();
            let resp = RpcResponse::ok(&req.id, serde_json::json!({ "tasks": tasks }));
            (resp, None)
        }
        "task_status" => {
            let task_id = req
                .params
                .get("task_id")
                .and_then(|v| v.as_str())
                .map(String::from);
            let resp = match task_id.and_then(|id| router.task_state(&id)) {
                Some(state) => RpcResponse::ok(
                    &req.id,
                    serde_json::json!({
                        "task_id": state.id,
                        "message": state.message,
                        "created_at": state.created_at_iso,
                        "updated_at": state.updated_at_iso,
                        "status": match state.status {
                            crate::server::task::TaskStatus::Running => "running",
                            crate::server::task::TaskStatus::Completed => "completed",
                            crate::server::task::TaskStatus::Failed => "failed",
                            crate::server::task::TaskStatus::Cancelled => "cancelled",
                        },
                        "result": state.result,
                        "remote": state.result.as_ref().and_then(|v| v.get("remote")).and_then(|v| v.as_bool()).unwrap_or(false),
                    }),
                ),
                None => RpcResponse::err(&req.id, -32001, "unknown task_id"),
            };
            (resp, None)
        }
        "enqueue" => {
            let method_name = req
                .params
                .get("method")
                .and_then(|v| v.as_str())
                .map(primary_name_for)
                .map(str::to_string);
            let priority = req
                .params
                .get("priority")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u8;
            let tenant_id = req
                .params
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned);
            let dedupe_key = req
                .params
                .get("dedupe_key")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned);
            let task_params = req
                .params
                .get("task_params")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let federate = req
                .params
                .get("federate")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let resp = match (path.as_deref(), method_name.as_deref()) {
                (Some(path), Some(method)) if federate => {
                    match router
                        .enqueue_federated_task(
                            path,
                            method,
                            task_params,
                            tenant_id,
                            priority,
                            dedupe_key,
                        )
                        .await
                    {
                        Ok(value) => RpcResponse::ok(&req.id, value),
                        Err(err) => RpcResponse::err(&req.id, -32000, err.to_string()),
                    }
                }
                (Some(path), Some(method)) => match router
                    .enqueue_route_task(path, method, task_params, tenant_id, priority, dedupe_key)
                    .await
                {
                    Ok(value) => RpcResponse::ok(&req.id, value),
                    Err(err) => RpcResponse::err(&req.id, -32000, err.to_string()),
                },
                _ => RpcResponse::err(
                    &req.id,
                    -32001,
                    "enqueue requires path and method",
                ),
            };
            (resp, None)
        }
        "cancel_task" => {
            let task_id = req
                .params
                .get("task_id")
                .and_then(|v| v.as_str())
                .map(String::from);
            let resp = match task_id {
                Some(task_id) => {
                    if router.cancel_task(&task_id).await {
                        RpcResponse::ok(
                            &req.id,
                            serde_json::json!({ "ok": true, "task_id": task_id }),
                        )
                    } else {
                        RpcResponse::err(&req.id, -32001, "task not found")
                    }
                }
                None => RpcResponse::err(&req.id, -32001, "cancel_task requires task_id"),
            };
            (resp, None)
        }

        "prewarm" => {
            let resp = if let Some(ref p) = path {
                let queue = req.params.get("queue").and_then(|v| v.as_bool()).unwrap_or(false);
                let keep_warm = req
                    .params
                    .get("keep_warm")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let priority = req
                    .params
                    .get("priority")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u8;
                let tenant_id = req
                    .params
                    .get("tenant_id")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned);

                let result = if queue {
                    router.enqueue_prewarm(p, priority, keep_warm, tenant_id).await
                } else {
                    router
                        .prewarm_path_with_options(
                            p,
                            keep_warm,
                            tenant_id.as_deref().unwrap_or("default"),
                        )
                        .await
                };

                match result {
                    Ok(value) => RpcResponse::ok(&req.id, value),
                    Err(e) => RpcResponse::err(&req.id, -32000, e.to_string()),
                }
            } else {
                RpcResponse::err(&req.id, -32001, "prewarm requires 'path' parameter")
            };
            (resp, None)
        }

        _ => {
            let resolve_result = if let Some(ref p) = path {
                router
                    .ensure_worker_with_ref(p, tenant_id.as_deref())
                    .await
                    .map(|(h, token)| (h, Some(token)))
            } else {
                return (
                    RpcResponse::err(
                        &req.id,
                        -32602,
                        "CLI requires 'path' parameter to identify the target binary",
                    ),
                    None,
                );
            };

            match resolve_result {
                Ok((handle, ref_token)) => {
                    let ref_guard = ref_token.map(|token| CliRefGuard {
                        router: router.clone(),
                        token,
                    });
                    match router
                        .route_request(Some(&handle), method, req.params.clone())
                        .await
                    {
                        Ok(v) => (RpcResponse::ok(&req.id, v), ref_guard),
                        Err(e) => (RpcResponse::err(&req.id, -32000, e.to_string()), ref_guard),
                    }
                }
                Err(e) => (RpcResponse::err(&req.id, -32000, e.to_string()), None),
            }
        }
    }
}
