use crate::router::protocol::{RpcRequest, RpcResponse};
use crate::router::RouterState;
use crate::tool_registry::primary_name_for;
use std::path::PathBuf;
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Run the CLI socket listener. `shutdown` is the service-wide cancel token
/// that outer accept loops (stdio / HTTP) also watch; the shutdown RPC
/// triggers it so the whole service exits, not just the workers.
pub async fn run_socket_listener(
    socket_path: PathBuf,
    router: RouterState,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    info!("CLI socket listening on {:?}", socket_path);

    let discovery_path = crate::idb_store::discovery_path();
    std::fs::write(&discovery_path, socket_path.to_string_lossy().as_bytes())?;
    let input_gate = std::sync::Arc::new(tokio::sync::Semaphore::new(128));
    let business_gate = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
    let control_gate = std::sync::Arc::new(tokio::sync::Semaphore::new(8));

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("CLI socket listener: shutdown signalled, stopping accept loop");
                break;
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let input_permit=match input_gate.clone().try_acquire_owned() {
                    Ok(permit)=>permit,
                    Err(_)=>{
                        // Nonblocking refusal; a stopped peer cannot hold the accept loop.
                        let _=stream.try_write(b"{\"jsonrpc\":\"2.0\",\"id\":\"null\",\"error\":{\"code\":-32000,\"message\":\"Busy: CLI input capacity full\"}}\n");
                        continue;
                    }
                };
                let router = router.clone();
                let shutdown = shutdown.clone();
                let business_gate=business_gate.clone();
                let control_gate=control_gate.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_cli_connection(stream, &router, &shutdown, input_permit, business_gate, control_gate).await {
                        debug!("CLI connection ended: {}", e);
                    }
                });
            }
        }
    }

    Ok(())
}

pub fn cleanup_socket_files(socket_path: &std::path::Path) {
    let _ = std::fs::remove_file(socket_path);
    let _ = std::fs::remove_file(crate::idb_store::discovery_path());
}

async fn handle_cli_connection(
    stream: tokio::net::UnixStream,
    router: &RouterState,
    shutdown: &CancellationToken,
    input_permit: tokio::sync::OwnedSemaphorePermit,
    business_gate: std::sync::Arc<tokio::sync::Semaphore>,
    control_gate: std::sync::Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut bytes = Vec::new();
    let exists = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::router::transport::read_frame(&mut reader, &mut bytes),
    )
    .await??;
    if !exists {
        return Ok(());
    }
    // Small control frames can be classified without entering a busy business pool.
    let parsed = if bytes.len() <= 64 * 1024 {
        serde_json::from_slice::<RpcRequest>(&bytes)
    } else {
        crate::blocking::request_decode(move || serde_json::from_slice::<RpcRequest>(&bytes))
            .await?
    };
    let control = parsed.as_ref().is_ok_and(|request| {
        matches!(
            primary_name_for(&request.method),
            "status" | "list_tasks" | "task_status" | "cancel_task"
        )
    });
    let nexus_shutdown = router.uses_nexus()
        && parsed
            .as_ref()
            .is_ok_and(|req| primary_name_for(&req.method) == "shutdown");
    let gate = if control { control_gate } else { business_gate };
    let execution_permit = gate.try_acquire_owned();
    let resp = match parsed {
        Ok(req) if execution_permit.is_err() => {
            RpcResponse::err(&req.id, -32000, "Busy: CLI lane capacity full")
        }
        Ok(req) => {
            drop(input_permit); // Classified work now owns its independent lane capacity.
            let (mut response, ref_guard) = dispatch_cli_request(&req, router, shutdown).await;
            if !control {
                if let Some(result) = response.result.take() {
                    response.result =
                        Some(super::response_cache::cache_or_inline(&req.method, result).await);
                }
            }
            let _ = ref_guard;
            response
        }
        Err(e) => RpcResponse::err("null", -32700, format!("Parse error: {e}")),
    };

    let json = if control {
        crate::blocking::run(crate::blocking::WorkClass::Control, move || {
            serde_json::to_vec(&resp)
        })
        .await??
    } else {
        crate::blocking::response(move || serde_json::to_vec(&resp)).await??
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        writer.write_all(&json).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    })
    .await??;
    if nexus_shutdown {
        shutdown.cancel();
    }
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
        if router.uses_nexus() {
            crate::router::nexus_tools::Tools::abandon(router, token);
            return;
        }
        tokio::spawn(async move {
            router.release_ref_token(&token).await;
        });
    }
}

async fn dispatch_cli_request(
    req: &RpcRequest,
    router: &RouterState,
    shutdown: &CancellationToken,
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
                // Match what ensure_worker_with_ref_idb does when it
                // registers the worker: expand `~/...` first, then
                // canonicalise. Otherwise `close --path ~/foo` would
                // never hit a worker keyed on `/home/user/foo`.
                let expanded = crate::expand_path(p);
                let canonical = std::fs::canonicalize(&expanded).unwrap_or(expanded);
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
            // Trip the service-wide cancel token so the outer transport loop
            // (stdio or HTTP) also exits instead of leaving a zombie server.
            if !router.uses_nexus() {
                shutdown.cancel();
            }
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
                .map(|state| crate::router::task_state_json(&state))
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
                Some(state) => RpcResponse::ok(&req.id, crate::router::task_state_json(&state)),
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
                _ => RpcResponse::err(&req.id, -32001, "enqueue requires path and method"),
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
                let queue = req
                    .params
                    .get("queue")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
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
                    router
                        .enqueue_prewarm(p, priority, keep_warm, tenant_id)
                        .await
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
            if router.uses_nexus() {
                if let Err(error) = crate::router::nexus_tools::Tools::require(method) {
                    return (RpcResponse::err(&req.id, -32000, error.to_string()), None);
                }
            }
            let maximum = if method == "open" { 3600 } else { 600 };
            let seconds = req
                .params
                .get("timeout_secs")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(120)
                .min(maximum);
            let preparation =
                crate::preprocess::Preparation::new(std::time::Duration::from_secs(seconds));
            let resolve_result = if let Some(ref p) = path {
                router
                    .ensure_worker_prepared(p, None, tenant_id.as_deref(), preparation.clone())
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
                        .route_request_prepared(
                            Some(&handle),
                            method,
                            req.params.clone(),
                            preparation,
                        )
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

#[cfg(test)]
mod n2_tests {
    use super::*;
    use tokio::io::AsyncBufReadExt;
    #[tokio::test(flavor = "current_thread")]
    async fn local_control_has_capacity_while_cli_business_lane_is_full() {
        let router = RouterState::new().expect("isolated router");
        let business = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let _blocked_business = business.clone().acquire_owned().await.unwrap();
        let control = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let input = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let task = tokio::spawn(async move {
            handle_cli_connection(
                server,
                &router,
                &CancellationToken::new(),
                input.acquire_owned().await.unwrap(),
                business,
                control,
            )
            .await
        });
        let (reader, mut writer) = client.into_split();
        writer
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":\"control\",\"method\":\"status\",\"params\":{}}\n",
            )
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            BufReader::new(reader).read_line(&mut line),
        )
        .await
        .expect("independent control deadline")
        .unwrap();
        let response: RpcResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(response.id, "control");
        assert!(response.error.is_none());
        assert_eq!(response.result.unwrap()["worker_count"], 0);
        task.await.unwrap().unwrap();
    }
}
