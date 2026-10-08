//! MCP over a Unix socket.
//!
//! The daemon serves the same MCP surface as `serve-http` on
//! `~/.ida/mcp.sock`: one rmcp session per accepted connection, framed as
//! newline-delimited JSON-RPC (the stdio framing). Local clients connect by
//! path instead of discovering the daemon's random HTTP port. Access is
//! limited to the daemon's own user: the socket file is chmod 0600 and every
//! peer's effective uid is checked before the handshake.

use rmcp::{RoleServer, Service, ServiceExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Back-off after a failed `accept`, so a persistent error (EMFILE) does not spin.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(200);

/// Accept MCP sessions on `path` until `shutdown` fires, then remove the socket.
///
/// The caller must already hold the daemon singleton (see `socket_is_live`),
/// so a socket file left at `path` belongs to a dead daemon and is replaced.
pub async fn run_mcp_socket_listener<S, F>(
    path: PathBuf,
    make_server: F,
    shutdown: CancellationToken,
) -> anyhow::Result<()>
where
    S: Service<RoleServer> + Send + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    let listener = bind_private(&path)?;
    info!("MCP socket listening on {:?}", path);
    let own_uid = unsafe { libc::geteuid() };

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        warn!("MCP socket accept failed: {e}");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                if !peer_is_owner(&stream, own_uid) {
                    continue;
                }
                let server = make_server();
                let session_shutdown = shutdown.clone();
                tokio::spawn(async move { serve_session(server, stream, session_shutdown).await });
            }
        }
    }

    let _ = std::fs::remove_file(&path);
    info!("MCP socket listener stopped");
    Ok(())
}

fn bind_private(path: &Path) -> anyhow::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => info!("Removed stale MCP socket {:?}", path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::anyhow!("cannot remove stale MCP socket {path:?}: {e}")),
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| anyhow::anyhow!("cannot bind MCP socket {path:?}: {e}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow::anyhow!("cannot chmod MCP socket {path:?}: {e}"))?;
    Ok(listener)
}

fn peer_is_owner(stream: &UnixStream, own_uid: libc::uid_t) -> bool {
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == own_uid => true,
        Ok(cred) => {
            warn!(peer_uid = cred.uid(), "rejecting MCP socket peer owned by another user");
            false
        }
        Err(e) => {
            warn!("rejecting MCP socket peer without credentials: {e}");
            false
        }
    }
}

async fn serve_session<S>(server: S, stream: UnixStream, shutdown: CancellationToken)
where
    S: Service<RoleServer> + Send + 'static,
{
    let running = match server.serve(stream).await {
        Ok(running) => running,
        Err(e) => {
            warn!("MCP socket handshake failed: {e}");
            return;
        }
    };
    let session = running.cancellation_token();
    tokio::select! {
        result = running.waiting() => {
            if let Err(e) = result {
                warn!("MCP socket session ended with error: {e}");
            }
        }
        _ = shutdown.cancelled() => session.cancel(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::ServerHandler;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[derive(Clone)]
    struct EmptyServer;
    impl ServerHandler for EmptyServer {}

    /// Unix socket paths are capped near 104 bytes on macOS, so stay in /tmp.
    fn temp_socket(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        PathBuf::from("/tmp").join(format!("ida-mcp-{label}-{}-{nanos}.sock", std::process::id()))
    }

    #[tokio::test]
    async fn test_bind_private_replaces_stale_file_and_restricts_mode() {
        let path = temp_socket("bind");
        std::fs::write(&path, b"stale").expect("write stale placeholder");
        let listener = bind_private(&path).expect("bind over a stale file");
        let mode = std::fs::metadata(&path).expect("socket metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(listener);
        std::fs::remove_file(&path).expect("cleanup socket");
    }

    #[tokio::test]
    async fn test_listener_answers_initialize_and_removes_socket_on_shutdown() {
        let path = temp_socket("init");
        let shutdown = CancellationToken::new();
        let listener = tokio::spawn(run_mcp_socket_listener(path.clone(), || EmptyServer, shutdown.clone()));

        let mut stream = None;
        for _ in 0..100 {
            if let Ok(s) = UnixStream::connect(&path).await {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let stream = stream.expect("listener should accept within 2s");
        let (reader, mut writer) = stream.into_split();
        let request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-socket-test","version":"0"}}}"#;
        writer.write_all(request.as_bytes()).await.expect("write initialize");
        writer.write_all(b"\n").await.expect("write newline");

        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), BufReader::new(reader).read_line(&mut line))
            .await
            .expect("initialize response within 5s")
            .expect("read initialize response");
        let response: serde_json::Value = serde_json::from_str(&line).expect("response is one JSON line");
        assert_eq!(response["id"], 1);
        assert!(response["result"]["serverInfo"].is_object(), "unexpected response: {line}");

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), listener)
            .await
            .expect("listener stops within 5s")
            .expect("listener task joins")
            .expect("listener returns Ok");
        assert!(!path.exists(), "socket file should be removed on shutdown");
    }
}
