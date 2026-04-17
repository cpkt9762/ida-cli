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

    match method {
        "close" => {
            let resp = if let Some(ref p) = path {
                let canonical =
                    std::fs::canonicalize(p).unwrap_or_else(|_| std::path::PathBuf::from(p));
                match router.close_by_path(&canonical).await {
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
            let handles = router.all_handles().await;
            let resp = RpcResponse::ok(
                &req.id,
                serde_json::json!({
                    "worker_count": handles.len(),
                    "workers": handles,
                }),
            );
            (resp, None)
        }

        _ => {
            let resolve_result = if let Some(ref p) = path {
                router
                    .ensure_worker_with_ref(p)
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
