//! MCP over a Unix socket.
//!
//! The daemon serves the same MCP surface as `serve-http` on
//! `~/.ida/mcp.sock`: one rmcp session per accepted connection, framed as
//! newline-delimited JSON-RPC (the stdio framing). Local clients connect by
//! path instead of discovering the daemon's random HTTP port. Access is
//! limited to the daemon's own user: the socket file is chmod 0600 and every
//! peer's effective uid is checked before the handshake.

use rmcp::{RoleServer, Service, ServiceExt};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Back-off after a failed `accept`, so a persistent error (EMFILE) does not spin.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(200);
const SESSION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct BoundMcpSocket {
    listener: Option<UnixListener>,
    cleanup: SocketCleanup,
    _owner_lock: McpSocketOwnerLock,
}

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> AbortOnDrop<T> {
    fn handle_mut(&mut self) -> &mut JoinHandle<T> {
        &mut self.0
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Accept MCP sessions on `path` until `shutdown` fires, then remove the socket.
pub async fn run_mcp_socket_listener<S, F>(
    path: PathBuf,
    make_server: F,
    shutdown: CancellationToken,
) -> anyhow::Result<()>
where
    S: Service<RoleServer> + Send + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    let socket = bind_mcp_socket(path)?;
    run_bound_mcp_socket_listener(socket, make_server, shutdown).await
}

pub async fn run_bound_mcp_socket_listener<S, F>(
    socket: BoundMcpSocket,
    make_server: F,
    shutdown: CancellationToken,
) -> anyhow::Result<()>
where
    S: Service<RoleServer> + Send + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    let listener = socket
        .listener
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("MCP socket listener was already consumed"))?;
    let path = socket.cleanup.path.clone();
    info!("MCP socket listening on {:?}", path);
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let own_uid = unsafe { libc::geteuid() };
    let mut sessions = JoinSet::new();

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = joined {
                    warn!("MCP socket session task failed: {error}");
                }
            }
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
                sessions.spawn(async move {
                    serve_session(server, stream, session_shutdown).await
                });
            }
        }
    }

    let drain_sessions = async {
        while let Some(result) = sessions.join_next().await {
            if let Err(error) = result {
                warn!("MCP socket session task failed during shutdown: {error}");
            }
        }
    };
    if tokio::time::timeout(SESSION_SHUTDOWN_TIMEOUT, drain_sessions)
        .await
        .is_err()
    {
        warn!("MCP socket sessions did not stop within shutdown timeout");
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
    }
    info!("MCP socket listener stopped");
    Ok(())
}

pub fn bind_mcp_socket(path: PathBuf) -> anyhow::Result<BoundMcpSocket> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow::anyhow!(
                "cannot create MCP socket directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let mut owner_lock = McpSocketOwnerLock::acquire(&path)?;
    remove_stale_socket(&path, owner_lock.recorded_identity(), || {})?;
    let listener = UnixListener::bind(&path)
        .map_err(|e| anyhow::anyhow!("cannot bind MCP socket {path:?}: {e}"))?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| anyhow::anyhow!("cannot stat MCP socket {path:?}: {error}"))?;
    let cleanup = SocketCleanup {
        path: path.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow::anyhow!("cannot chmod MCP socket {path:?}: {e}"))?;
    owner_lock.record_identity(SocketIdentity::from_metadata(&metadata))?;
    Ok(BoundMcpSocket {
        listener: Some(listener),
        cleanup,
        _owner_lock: owner_lock,
    })
}

fn remove_stale_socket<F>(
    path: &Path,
    recorded_identity: Option<SocketIdentity>,
    before_recheck: F,
) -> anyhow::Result<()>
where
    F: FnOnce(),
{
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "cannot inspect existing MCP socket {}: {error}",
                path.display()
            ))
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        anyhow::bail!(
            "refusing to replace symlink at MCP socket path {}",
            path.display()
        );
    }
    if !file_type.is_socket() {
        anyhow::bail!(
            "refusing to replace non-socket file at MCP socket path {}",
            path.display()
        );
    }
    let original_identity = SocketIdentity::from_metadata(&metadata);
    if recorded_identity != Some(original_identity) {
        anyhow::bail!(
            "cannot confirm MCP socket {} is stale: owner record does not match its identity",
            path.display()
        );
    }

    before_recheck();
    let current = std::fs::symlink_metadata(path).map_err(|error| {
        anyhow::anyhow!(
            "MCP socket {} changed while checking staleness: {error}",
            path.display()
        )
    })?;
    if !current.file_type().is_socket()
        || SocketIdentity::from_metadata(&current) != original_identity
    {
        anyhow::bail!(
            "MCP socket {} changed identity while checking staleness; refusing to remove it",
            path.display()
        );
    }
    std::fs::remove_file(path).map_err(|remove_error| {
        anyhow::anyhow!(
            "cannot remove stale MCP socket {}: {remove_error}",
            path.display()
        )
    })?;
    info!("Removed stale MCP socket {:?}", path);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug)]
struct McpSocketOwnerLock {
    file: File,
    path: PathBuf,
}

impl McpSocketOwnerLock {
    fn acquire(socket_path: &Path) -> anyhow::Result<Self> {
        let path = owner_lock_path(socket_path)?;
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                anyhow::bail!(
                    "refusing unsafe MCP socket owner lock path {}",
                    path.display()
                );
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| {
                anyhow::anyhow!(
                    "cannot open MCP socket owner lock {}: {error}",
                    path.display()
                )
            })?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                anyhow::anyhow!(
                    "cannot chmod MCP socket owner lock {}: {error}",
                    path.display()
                )
            })?;
        // SAFETY: file owns this live descriptor; LOCK_NB guarantees the probe
        // cannot block behind another daemon holding the ownership lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            anyhow::bail!(
                "MCP socket owner lock {} is held by another process: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
        Ok(Self { file, path })
    }

    fn recorded_identity(&mut self) -> Option<SocketIdentity> {
        if self.file.seek(SeekFrom::Start(0)).is_err() {
            return None;
        }
        let mut record = String::new();
        if self.file.read_to_string(&mut record).is_err() {
            return None;
        }
        let (device, inode) = record.trim().split_once(':')?;
        Some(SocketIdentity {
            device: device.parse().ok()?,
            inode: inode.parse().ok()?,
        })
    }

    fn record_identity(&mut self, identity: SocketIdentity) -> anyhow::Result<()> {
        self.file.set_len(0).map_err(|error| {
            anyhow::anyhow!(
                "cannot truncate MCP socket owner lock {}: {error}",
                self.path.display()
            )
        })?;
        self.file.seek(SeekFrom::Start(0)).map_err(|error| {
            anyhow::anyhow!(
                "cannot seek MCP socket owner lock {}: {error}",
                self.path.display()
            )
        })?;
        write!(self.file, "{}:{}", identity.device, identity.inode).map_err(|error| {
            anyhow::anyhow!(
                "cannot write MCP socket owner lock {}: {error}",
                self.path.display()
            )
        })?;
        self.file.sync_data().map_err(|error| {
            anyhow::anyhow!(
                "cannot sync MCP socket owner lock {}: {error}",
                self.path.display()
            )
        })
    }
}

fn owner_lock_path(socket_path: &Path) -> anyhow::Result<PathBuf> {
    let mut name = socket_path
        .file_name()
        .ok_or_else(|| {
            anyhow::anyhow!("MCP socket path {} has no file name", socket_path.display())
        })?
        .to_os_string();
    name.push(".lock");
    Ok(socket_path.with_file_name(name))
}

#[derive(Debug)]
struct SocketCleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        remove_socket_if_same(&self.path, self.device, self.inode);
    }
}

fn remove_socket_if_same(path: &Path, device: u64, inode: u64) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_socket() && metadata.dev() == device && metadata.ino() == inode {
        if let Err(error) = std::fs::remove_file(path) {
            warn!("cannot remove MCP socket {}: {error}", path.display());
        }
    }
}

fn peer_is_owner(stream: &UnixStream, own_uid: libc::uid_t) -> bool {
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == own_uid => true,
        Ok(cred) => {
            warn!(
                peer_uid = cred.uid(),
                "rejecting MCP socket peer owned by another user"
            );
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
    let running = tokio::select! {
        result = server.serve(stream) => {
            match result {
                Ok(running) => running,
                Err(error) => {
                    warn!("MCP socket handshake failed: {error}");
                    return;
                }
            }
        }
        _ = shutdown.cancelled() => return,
    };
    let session = running.cancellation_token();
    let mut waiting = AbortOnDrop(tokio::spawn(running.waiting()));
    tokio::select! {
        result = waiting.handle_mut() => {
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => warn!("MCP socket session ended with error: {error}"),
                Err(error) => warn!("MCP socket wait task failed: {error}"),
            }
        }
        _ = shutdown.cancelled() => {
            session.cancel();
            match tokio::time::timeout(SESSION_SHUTDOWN_TIMEOUT, waiting.handle_mut()).await {
                Ok(Ok(Ok(_))) => {}
                Ok(Ok(Err(error))) => warn!("MCP socket session ended with error: {error}"),
                Ok(Err(error)) => warn!("MCP socket wait task failed: {error}"),
                Err(_) => {
                    warn!("MCP socket session did not stop within shutdown timeout");
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::ServerHandler;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[derive(Clone)]
    struct EmptyServer;
    impl ServerHandler for EmptyServer {}

    /// Unix socket paths are capped near 104 bytes on macOS.
    fn temp_socket(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        PathBuf::from("/private/tmp").join(format!(
            "ida-mcp-{label}-{}-{nanos}.sock",
            std::process::id()
        ))
    }

    fn test_owner_lock_path(path: &Path) -> PathBuf {
        owner_lock_path(path).expect("valid test socket path")
    }

    #[tokio::test]
    async fn test_bind_replaces_stale_socket_and_restricts_mode() {
        let path = temp_socket("stale");
        let first = bind_mcp_socket(path.clone()).expect("bind first socket");
        let BoundMcpSocket {
            listener,
            cleanup,
            _owner_lock,
        } = first;
        std::mem::forget(cleanup);
        drop(listener);
        drop(_owner_lock);

        let socket = bind_mcp_socket(path.clone()).expect("bind over stale socket");
        let mode = std::fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let lock_mode = std::fs::metadata(test_owner_lock_path(&path))
            .expect("owner lock metadata")
            .permissions()
            .mode();
        assert_eq!(lock_mode & 0o777, 0o600);
        drop(socket);
        assert!(!path.exists(), "owned socket should be removed on drop");
        std::fs::remove_file(test_owner_lock_path(&path)).expect("cleanup owner lock");
    }

    #[tokio::test]
    async fn test_bind_refuses_regular_file() {
        let path = temp_socket("file");
        std::fs::write(&path, b"do not delete").expect("write regular file");
        let error = bind_mcp_socket(path.clone()).expect_err("regular file must be rejected");
        assert!(error.to_string().contains("non-socket"));
        assert_eq!(
            std::fs::read(&path).expect("read preserved regular file"),
            b"do not delete"
        );
        std::fs::remove_file(&path).expect("cleanup regular file");
        std::fs::remove_file(test_owner_lock_path(&path)).expect("cleanup owner lock");
    }

    #[tokio::test]
    async fn test_bind_refuses_symlink() {
        let path = temp_socket("symlink");
        let target = temp_socket("symlink-target");
        std::fs::write(&target, b"target").expect("write symlink target");
        std::os::unix::fs::symlink(&target, &path).expect("create symlink");
        let error = bind_mcp_socket(path.clone()).expect_err("symlink must be rejected");
        assert!(error.to_string().contains("symlink"));
        assert!(std::fs::symlink_metadata(&path)
            .expect("symlink metadata")
            .file_type()
            .is_symlink());
        std::fs::remove_file(&path).expect("cleanup symlink");
        std::fs::remove_file(target).expect("cleanup symlink target");
        std::fs::remove_file(test_owner_lock_path(&path)).expect("cleanup owner lock");
    }

    #[tokio::test]
    async fn test_bind_refuses_active_socket() {
        let path = temp_socket("active");
        let active = bind_mcp_socket(path.clone()).expect("bind active socket");
        let error = bind_mcp_socket(path.clone()).expect_err("active socket must be rejected");
        assert!(error.to_string().contains("owner lock"));
        drop(active);
        std::fs::remove_file(test_owner_lock_path(&path)).expect("cleanup owner lock");
    }

    #[tokio::test]
    async fn test_full_accept_queue_probe_is_bounded_and_preserves_socket() {
        let path = temp_socket("full-queue");
        let active = bind_mcp_socket(path.clone()).expect("bind queue test socket");
        let listener = active.listener.as_ref().expect("active listener");
        // SAFETY: listener owns a valid AF_UNIX listening descriptor; listen only
        // updates its backlog and does not outlive the descriptor.
        let listen_result = unsafe { libc::listen(listener.as_raw_fd(), 1) };
        assert_eq!(listen_result, 0, "set queue test backlog");
        let original = std::fs::symlink_metadata(&path).expect("queue socket metadata");

        let mut clients = Vec::new();
        let mut saturated = false;
        for _ in 0..32 {
            match tokio::time::timeout(Duration::from_millis(20), UnixStream::connect(&path)).await
            {
                Ok(Ok(stream)) => clients.push(stream),
                Ok(Err(_)) | Err(_) => {
                    saturated = true;
                    break;
                }
            }
        }
        assert!(saturated, "accept queue should be saturated for this test");

        let started = Instant::now();
        let attempt_path = path.clone();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::task::spawn_blocking(move || bind_mcp_socket(attempt_path)),
        )
        .await
        .expect("ownership probe must be bounded")
        .expect("ownership probe task")
        .expect_err("full accept queue must not be treated as stale");
        assert!(error.to_string().contains("owner lock"));
        assert!(started.elapsed() < Duration::from_secs(1));

        let current = std::fs::symlink_metadata(&path).expect("preserved queue socket metadata");
        assert_eq!(current.dev(), original.dev());
        assert_eq!(current.ino(), original.ino());
        drop(clients);
        drop(active);
        std::fs::remove_file(test_owner_lock_path(&path)).expect("cleanup owner lock");
    }

    #[tokio::test]
    async fn test_stale_probe_refuses_replaced_socket_identity() {
        let path = temp_socket("identity-race");
        let first = bind_mcp_socket(path.clone()).expect("bind original socket");
        let BoundMcpSocket {
            listener,
            cleanup,
            _owner_lock,
        } = first;
        std::mem::forget(cleanup);
        drop(listener);
        drop(_owner_lock);
        let original = std::fs::symlink_metadata(&path).expect("original socket metadata");
        let replacement = Arc::new(Mutex::new(None));
        let replacement_for_probe = replacement.clone();
        let mut owner_lock =
            McpSocketOwnerLock::acquire(&path).expect("acquire released owner lock");
        let recorded_identity = owner_lock.recorded_identity();
        let path_for_probe = path.clone();

        let error = remove_stale_socket(&path, recorded_identity, move || {
            std::fs::remove_file(&path_for_probe).expect("remove original stale socket");
            let new_listener =
                StdUnixListener::bind(&path_for_probe).expect("bind replacement socket");
            *replacement_for_probe
                .lock()
                .expect("replacement holder mutex") = Some(new_listener);
        })
        .expect_err("replacement identity must be rejected");
        assert!(error.to_string().contains("changed identity"));

        let current = std::fs::symlink_metadata(&path).expect("replacement socket metadata");
        assert!(current.file_type().is_socket());
        assert_ne!(
            (current.dev(), current.ino()),
            (original.dev(), original.ino())
        );
        let replacement_listener = replacement
            .lock()
            .expect("replacement holder mutex")
            .take()
            .expect("replacement listener retained");
        drop(replacement_listener);
        std::fs::remove_file(&path).expect("cleanup replacement socket");
        drop(owner_lock);
        std::fs::remove_file(test_owner_lock_path(&path)).expect("cleanup owner lock");
    }

    #[tokio::test]
    async fn test_listener_answers_initialize_and_removes_socket_on_shutdown() {
        let path = temp_socket("init");
        let shutdown = CancellationToken::new();
        let listener = tokio::spawn(run_mcp_socket_listener(
            path.clone(),
            || EmptyServer,
            shutdown.clone(),
        ));

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
        writer
            .write_all(request.as_bytes())
            .await
            .expect("write initialize");
        writer.write_all(b"\n").await.expect("write newline");

        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            BufReader::new(reader).read_line(&mut line),
        )
        .await
        .expect("initialize response within 5s")
        .expect("read initialize response");
        let response: serde_json::Value =
            serde_json::from_str(&line).expect("response is one JSON line");
        assert_eq!(response["id"], 1);
        assert!(
            response["result"]["serverInfo"].is_object(),
            "unexpected response: {line}"
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), listener)
            .await
            .expect("listener stops within 5s")
            .expect("listener task joins")
            .expect("listener returns Ok");
        assert!(!path.exists(), "socket file should be removed on shutdown");
        std::fs::remove_file(test_owner_lock_path(&path)).expect("cleanup owner lock");
    }

    #[tokio::test]
    async fn test_shutdown_cancels_connection_during_handshake() {
        let path = temp_socket("handshake");
        let shutdown = CancellationToken::new();
        let listener = tokio::spawn(run_mcp_socket_listener(
            path.clone(),
            || EmptyServer,
            shutdown.clone(),
        ));

        for _ in 0..100 {
            if UnixStream::connect(&path).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), listener)
            .await
            .expect("listener stops with handshake in flight")
            .expect("listener task joins")
            .expect("listener returns Ok");
        assert!(!path.exists(), "socket file should be removed on shutdown");
        std::fs::remove_file(test_owner_lock_path(&path)).expect("cleanup owner lock");
    }
}
