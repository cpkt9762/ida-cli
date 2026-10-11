//! Stdio proxy for attaching an MCP client to the long-lived daemon.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy)]
pub struct AttachOptions {
    pub no_autostart: bool,
    pub connect_timeout: Duration,
    pub startup_timeout: Duration,
}

impl Default for AttachOptions {
    fn default() -> Self {
        Self {
            no_autostart: false,
            connect_timeout: Duration::from_secs(5),
            startup_timeout: Duration::from_secs(10),
        }
    }
}

pub async fn run_stdio_proxy(options: AttachOptions) -> anyhow::Result<()> {
    let stream = connect_mcp(options).await?;
    proxy_stream(tokio::io::stdin(), tokio::io::stdout(), stream).await
}

pub async fn proxy_stream<R, W>(
    mut input: R,
    mut output: W,
    stream: UnixStream,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut daemon_read, mut daemon_write) = stream.into_split();
    let upstream = async {
        tokio::io::copy(&mut input, &mut daemon_write).await?;
        daemon_write.shutdown().await
    };
    let downstream = async {
        tokio::io::copy(&mut daemon_read, &mut output).await?;
        output.flush().await
    };
    tokio::pin!(upstream);
    tokio::pin!(downstream);

    tokio::select! {
        result = &mut upstream => {
            result?;
            downstream.await?;
        }
        result = &mut downstream => {
            result?;
        }
    }
    Ok(())
}

pub async fn connect_mcp(options: AttachOptions) -> anyhow::Result<UnixStream> {
    let mcp_path = crate::idb_store::mcp_socket_path();
    let daemon_path = crate::idb_store::socket_path();
    let startup_lock = crate::idb_store::startup_lock_path();
    connect_mcp_with(
        &mcp_path,
        &daemon_path,
        &startup_lock,
        options,
        start_daemon,
    )
    .await
}

async fn connect_mcp_with<F>(
    mcp_path: &Path,
    daemon_path: &Path,
    startup_lock: &Path,
    options: AttachOptions,
    starter: F,
) -> anyhow::Result<UnixStream>
where
    F: FnOnce() -> anyhow::Result<()>,
{
    if let Ok(stream) = connect_with_timeout(mcp_path, options.connect_timeout).await {
        return Ok(stream);
    }

    if socket_is_live(daemon_path, options.connect_timeout).await {
        anyhow::bail!(
            "the running ida-cli daemon does not expose the MCP socket at {}; \
             install the upgraded ida-cli and restart that daemon explicitly",
            mcp_path.display()
        );
    }

    if options.no_autostart {
        anyhow::bail!(
            "no ida-cli MCP daemon is available at {} and --no-autostart was requested",
            mcp_path.display()
        );
    }

    let _startup_guard = acquire_startup_lock(startup_lock, options.startup_timeout).await?;

    if let Ok(stream) = connect_with_timeout(mcp_path, options.connect_timeout).await {
        return Ok(stream);
    }
    if socket_is_live(daemon_path, options.connect_timeout).await {
        anyhow::bail!(
            "the running ida-cli daemon does not expose the MCP socket at {}; \
             install the upgraded ida-cli and restart that daemon explicitly",
            mcp_path.display()
        );
    }

    starter()?;
    wait_for_mcp_socket(mcp_path, options.connect_timeout, options.startup_timeout).await
}

fn start_daemon() -> anyhow::Result<()> {
    let exe = std::env::current_exe()
        .map_err(|error| anyhow::anyhow!("cannot find ida-cli executable: {error}"))?;
    let child = std::process::Command::new(exe)
        .args(["serve-http", "--bind", "127.0.0.1:0"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| anyhow::anyhow!("failed to start ida-cli daemon: {error}"))?;
    tracing::info!(pid = child.id(), "started ida-cli daemon for MCP attach");
    Ok(())
}

async fn connect_with_timeout(path: &Path, timeout: Duration) -> anyhow::Result<UnixStream> {
    match tokio::time::timeout(timeout, UnixStream::connect(path)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(anyhow::anyhow!(
            "cannot connect to MCP socket {}: {error}",
            path.display()
        )),
        Err(_) => Err(anyhow::anyhow!(
            "connection to MCP socket {} timed out after {:.3}s",
            path.display(),
            timeout.as_secs_f64()
        )),
    }
}

async fn socket_is_live(path: &Path, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, UnixStream::connect(path)).await,
        Ok(Ok(_))
    )
}

async fn wait_for_mcp_socket(
    path: &Path,
    connect_timeout: Duration,
    startup_timeout: Duration,
) -> anyhow::Result<UnixStream> {
    let deadline = Instant::now() + startup_timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            anyhow::bail!(
                "ida-cli daemon did not expose MCP socket {} within {:.3}s; check {}",
                path.display(),
                startup_timeout.as_secs_f64(),
                crate::idb_store::log_path().display()
            );
        }
        let attempt_timeout = connect_timeout.min(remaining);
        if let Ok(stream) = connect_with_timeout(path, attempt_timeout).await {
            return Ok(stream);
        }
        tokio::time::sleep(CONNECT_RETRY_DELAY.min(remaining)).await;
    }
}

async fn acquire_startup_lock(path: &Path, timeout: Duration) -> anyhow::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow::anyhow!(
                "cannot create startup lock directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|error| anyhow::anyhow!("cannot open startup lock {}: {error}", path.display()))?;
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `file` owns this live descriptor for the duration of the flock call.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 };
        if locked {
            return Ok(file);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            anyhow::bail!(
                "timed out waiting {:.3}s for startup lock {}",
                timeout.as_secs_f64(),
                path.display()
            );
        }
        tokio::time::sleep(CONNECT_RETRY_DELAY.min(remaining)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    use tokio::net::UnixListener;

    fn temp_paths(label: &str) -> (PathBuf, PathBuf, PathBuf) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let root = PathBuf::from("/private/tmp")
            .join(format!("ida-attach-{label}-{}-{nanos}", std::process::id()));
        (
            root.with_extension("mcp.sock"),
            root.with_extension("rpc.sock"),
            root.with_extension("lock"),
        )
    }

    async fn run_fake_mcp(listener: UnixListener, clients: usize) {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..clients {
            let (stream, _) = listener.accept().await.expect("accept fake MCP client");
            tasks.spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut line = String::new();
                while reader.read_line(&mut line).await.expect("read request") != 0 {
                    let request: serde_json::Value =
                        serde_json::from_str(line.trim()).expect("request JSON");
                    let method = request["method"].as_str().expect("request method");
                    let response = match method {
                        "initialize" => serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": request["id"],
                            "result": {"serverInfo": {"name": "fake", "version": "1"}}
                        }),
                        "tools/list" => serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": request["id"],
                            "result": {"tools": [{"name": "fake_tool"}]}
                        }),
                        _ => serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": request["id"],
                            "error": {"code": -32601, "message": "unknown"}
                        }),
                    };
                    let bytes = serde_json::to_vec(&response).expect("response JSON");
                    writer.write_all(&bytes).await.expect("write response");
                    writer.write_all(b"\n").await.expect("write newline");
                    line.clear();
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.expect("fake MCP connection task");
        }
    }

    async fn proxy_requests(path: &Path, requests: &[u8]) -> Vec<u8> {
        let stream = UnixStream::connect(path).await.expect("connect fake MCP");
        let (mut input_writer, input_reader) = tokio::io::duplex(4096);
        let (output_writer, mut output_reader) = tokio::io::duplex(4096);
        let proxy = tokio::spawn(proxy_stream(input_reader, output_writer, stream));
        input_writer
            .write_all(requests)
            .await
            .expect("write proxy stdin");
        input_writer.shutdown().await.expect("close proxy stdin");
        let mut output = Vec::new();
        output_reader
            .read_to_end(&mut output)
            .await
            .expect("read proxy stdout");
        proxy.await.expect("proxy task").expect("proxy result");
        output
    }

    #[tokio::test]
    async fn proxy_passes_initialize_and_tools_list_without_killing_listener() {
        let (mcp_path, _, _) = temp_paths("passthrough");
        let listener = UnixListener::bind(&mcp_path).expect("bind fake MCP");
        let server = tokio::spawn(run_fake_mcp(listener, 2));
        let requests = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n"
        );

        let first = proxy_requests(&mcp_path, requests.as_bytes()).await;
        let second = proxy_requests(&mcp_path, requests.as_bytes()).await;
        let first_lines: Vec<_> = first.split(|byte| *byte == b'\n').collect();
        assert_eq!(first_lines.len(), 3);
        assert!(String::from_utf8_lossy(&first).contains("\"serverInfo\""));
        assert!(String::from_utf8_lossy(&first).contains("\"fake_tool\""));
        assert_eq!(first, second);

        server.await.expect("fake MCP server");
        std::fs::remove_file(&mcp_path).expect("cleanup fake MCP socket");
    }

    #[tokio::test]
    async fn two_attach_proxies_can_run_concurrently() {
        let (mcp_path, _, _) = temp_paths("concurrent");
        let listener = UnixListener::bind(&mcp_path).expect("bind fake MCP");
        let server = tokio::spawn(run_fake_mcp(listener, 2));
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\",\"params\":{}}\n";
        let (first, second) = tokio::join!(
            proxy_requests(&mcp_path, request),
            proxy_requests(&mcp_path, request)
        );
        assert_eq!(first, second);
        assert!(String::from_utf8_lossy(&first).contains("\"fake_tool\""));
        server.await.expect("fake MCP server");
        std::fs::remove_file(&mcp_path).expect("cleanup fake MCP socket");
    }

    #[tokio::test]
    async fn no_autostart_reports_missing_daemon() {
        let (mcp_path, daemon_path, lock_path) = temp_paths("no-start");
        let called = Arc::new(AtomicBool::new(false));
        let called_for_start = called.clone();
        let error = connect_mcp_with(
            &mcp_path,
            &daemon_path,
            &lock_path,
            AttachOptions {
                no_autostart: true,
                connect_timeout: Duration::from_millis(20),
                startup_timeout: Duration::from_millis(100),
            },
            move || {
                called_for_start.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect_err("missing daemon must fail");
        assert!(error.to_string().contains("--no-autostart"));
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn old_daemon_without_mcp_socket_returns_upgrade_hint() {
        let (mcp_path, daemon_path, lock_path) = temp_paths("old-daemon");
        let daemon = UnixListener::bind(&daemon_path).expect("bind fake daemon RPC socket");
        let called = Arc::new(AtomicBool::new(false));
        let called_for_start = called.clone();
        let error = connect_mcp_with(
            &mcp_path,
            &daemon_path,
            &lock_path,
            AttachOptions {
                no_autostart: false,
                connect_timeout: Duration::from_millis(50),
                startup_timeout: Duration::from_millis(100),
            },
            move || {
                called_for_start.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect_err("old daemon must not be restarted");
        assert!(error.to_string().contains("upgrade"));
        assert!(!called.load(Ordering::SeqCst));
        drop(daemon);
        std::fs::remove_file(&daemon_path).expect("cleanup fake daemon socket");
    }

    #[tokio::test]
    async fn autostart_wait_is_bounded() {
        let (mcp_path, daemon_path, lock_path) = temp_paths("bounded");
        let started = Instant::now();
        let error = connect_mcp_with(
            &mcp_path,
            &daemon_path,
            &lock_path,
            AttachOptions {
                no_autostart: false,
                connect_timeout: Duration::from_millis(20),
                startup_timeout: Duration::from_millis(120),
            },
            || Ok(()),
        )
        .await
        .expect_err("missing socket after autostart must time out");
        assert!(error.to_string().contains("within 0.120s"));
        assert!(started.elapsed() < Duration::from_secs(1));
        std::fs::remove_file(&lock_path).expect("cleanup startup lock");
    }
}
