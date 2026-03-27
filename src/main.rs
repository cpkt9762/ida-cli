//! Headless IDA Pro MCP Server
//!
//! This binary runs an MCP server that provides headless IDA Pro access
//! via stdin/stdout transport.
//!
//! Architecture:
//! - Main thread: Runs IDA worker loop (IDA requires main thread)
//! - Background thread: Runs tokio runtime with async MCP server

use bytes::Bytes;
use clap::{Args, Parser, Subcommand};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::http::{header::ORIGIN, Request, Response, StatusCode};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use ida_mcp::{
    disasm::generate_disasm_line, expand_path, ida, rpc_dispatch, DbInfo, FunctionInfo,
    IdaMcpServer, IdaWorker, ServerMode,
};
use idalib::{idb::IDBOpenOptions, Address, IDB};
use rmcp::transport::stdio;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::ServiceExt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tower_service::Service;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Layer};

const REQUEST_QUEUE_CAPACITY: usize = 64;

#[derive(Parser)]
#[command(name = "ida-mcp", version, about = "Headless IDA Pro MCP Server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the MCP server (default)
    Serve(ServeArgs),
    /// Run the MCP server over Streamable HTTP (SSE)
    ServeHttp(ServeHttpArgs),
    /// Internal: worker subprocess controlled by a router.
    /// Reads JSON-RPC requests from stdin, dispatches to IDA worker, writes responses to stdout.
    ServeWorker,
    /// Run a direct CLI probe to exercise idalib
    Probe(ProbeArgs),
    /// CLI client: send commands to a running server via Unix socket
    Cli(ida_mcp::cli::CliArgs),
}

#[derive(Args, Default)]
struct ServeArgs {}

#[derive(Args)]
struct ServeHttpArgs {
    /// Bind address (e.g., 127.0.0.1:8765)
    #[arg(long, default_value = "127.0.0.1:8765")]
    bind: String,
    /// SSE keep-alive interval in seconds (0 disables)
    #[arg(long, default_value_t = 15)]
    sse_keep_alive_secs: u64,
    /// Use stateless mode (POST only; no sessions)
    #[arg(long)]
    stateless: bool,
    /// Return application/json in stateless mode instead of SSE framing.
    #[arg(long)]
    json_response: bool,
    /// Allowed Origin values (comma-separated). Defaults to localhost only.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "http://localhost,http://127.0.0.1"
    )]
    allow_origin: Vec<String>,
}

#[derive(Clone)]
struct OriginCheckService<S> {
    inner: S,
    allowed_origins: Arc<std::collections::HashSet<String>>,
}

impl<S> OriginCheckService<S> {
    fn new(inner: S, allowed_origins: Arc<std::collections::HashSet<String>>) -> Self {
        Self {
            inner,
            allowed_origins,
        }
    }
}

impl<B, S> Service<Request<B>> for OriginCheckService<S>
where
    B: http_body::Body + Send + 'static,
    B::Error: std::fmt::Display,
    S: Service<
            Request<B>,
            Response = Response<BoxBody<Bytes, std::convert::Infallible>>,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<BoxBody<Bytes, std::convert::Infallible>>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let allowed_origins = self.allowed_origins.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            if let Some(origin) = req.headers().get(ORIGIN).and_then(|v| v.to_str().ok()) {
                if !allowed_origins.contains(origin) {
                    let resp = Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Full::new(Bytes::from("Forbidden")).boxed())
                        .expect("valid response");
                    return Ok(resp);
                }
            }
            inner.call(req).await
        })
    }
}

#[derive(Args)]
struct ProbeArgs {
    /// Path to the .i64/.idb database
    #[arg(long)]
    path: String,
    /// Output .i64/.idb path when opening a raw binary (defaults to <path>.i64)
    #[arg(long)]
    idb_out: Option<String>,
    /// Force auto-analysis (default: on for raw binaries, off for .i64/.idb)
    #[arg(long)]
    auto_analyse: bool,
    /// List the first N functions (optional)
    #[arg(long)]
    list: Option<usize>,
    /// Resolve a function name (optional)
    #[arg(long)]
    resolve: Option<String>,
    /// Disassemble a function by name (optional)
    #[arg(long)]
    disasm_by_name: Option<String>,
    /// Disassemble at an address (hex 0x... or decimal, optional)
    #[arg(long)]
    disasm_addr: Option<String>,
    /// Decompile a function at an address (hex 0x... or decimal, optional)
    #[arg(long)]
    decompile_addr: Option<String>,
    /// Instruction count for disassembly (default: 20)
    #[arg(long, default_value_t = 20)]
    count: usize,
    /// Enable IDA console messages (may be verbose)
    #[arg(long)]
    ida_console: bool,
}

fn main() -> anyhow::Result<()> {
    // Initialize logging:
    //   stderr : RUST_LOG  or  ida_mcp=info  (low-noise)
    //   /tmp/ida-mcp.log : RUST_LOG  or  ida_mcp=debug  (verbose, for post-mortem)
    {
        use std::fs::OpenOptions;
        use std::sync::Mutex;

        const LOG_PATH: &str = "/tmp/ida-mcp.log";
        let stderr_layer = fmt::layer().with_writer(std::io::stderr).with_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("ida_mcp=info")),
        );

        match OpenOptions::new().create(true).append(true).open(LOG_PATH) {
            Ok(log_file) => {
                let file_layer = fmt::layer()
                    .with_writer(Mutex::new(log_file))
                    .with_ansi(false)
                    .with_target(true)
                    .with_line_number(true)
                    .with_filter(
                        EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| EnvFilter::new("ida_mcp=debug")),
                    );
                tracing_subscriber::registry()
                    .with(stderr_layer)
                    .with(file_layer)
                    .init();
                eprintln!("[ida-mcp] log -> {LOG_PATH}");
            }
            Err(e) => {
                eprintln!("[ida-mcp] warn: cannot open log file {LOG_PATH}: {e}");
                tracing_subscriber::registry().with(stderr_layer).init();
            }
        }
    }

    info!(
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        "=== ida-mcp started ==="
    );
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve(ServeArgs::default())) {
        Command::Serve(args) => run_server(args),
        Command::ServeHttp(args) => run_server_http(args),
        Command::ServeWorker => run_serve_worker(),
        Command::Probe(args) => run_probe(args),
        Command::Cli(args) => run_cli(args),
    }
}

fn run_cli(args: ida_mcp::cli::CliArgs) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(ida_mcp::cli::run(args))
}

async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigquit = signal(SignalKind::quit())?;
        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
            _ = sigquit.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    Ok(())
}

fn run_server(_args: ServeArgs) -> anyhow::Result<()> {
    run_server_multi()
}

fn run_server_multi() -> anyhow::Result<()> {
    info!("Starting IDA MCP Server (multi-IDB router mode)");

    let router = ida_mcp::router::RouterState::new()?;

    let (tx, _rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
    let worker = Arc::new(IdaWorker::new(tx));

    let server_handle = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        rt.block_on(async move {
            info!("MCP server (router mode) listening on stdio");
            let server = IdaMcpServer::new(worker.clone(), ServerMode::Router(router.clone()));
            router.start_watchdog(
                std::time::Duration::from_secs(8 * 3600),
                std::time::Duration::from_secs(5 * 60),
                None,
            );

            let socket_path = PathBuf::from(format!("/tmp/ida-mcp-{}.sock", std::process::id()));
            let socket_path_cleanup = socket_path.clone();
            let router_for_socket = router.clone();
            tokio::spawn(async move {
                if let Err(e) = ida_mcp::server::socket_listener::run_socket_listener(
                    socket_path,
                    router_for_socket,
                )
                .await
                {
                    warn!("Socket listener failed: {e}");
                }
            });

            let sanitized = ida_mcp::server::SanitizedIdaServer(server);
            let mut service = Some(sanitized.serve(stdio()).await?);
            let shutdown_notify = Arc::new(Notify::new());
            let shutdown_signal = shutdown_notify.clone();
            let router_for_signal = router.clone();

            tokio::spawn(async move {
                if wait_for_shutdown_signal().await.is_ok() {
                    info!("Shutdown signal received (router mode)");
                    router_for_signal.shutdown_all().await;
                    ida_mcp::server::socket_listener::cleanup_socket_files(&socket_path_cleanup);
                    shutdown_signal.notify_one();
                }
            });

            loop {
                tokio::select! {
                    _ = shutdown_notify.notified() => {
                        if let Some(mut running) = service.take() {
                            let _ = running.close().await?;
                        }
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if let Some(running) = service.as_ref() {
                            if running.is_transport_closed() {
                                if let Some(running) = service.take() {
                                    let _ = running.waiting().await?;
                                }
                                break;
                            }
                        }
                    }
                }
            }
            info!("MCP server shutting down (router mode)");
            router.shutdown_all().await;
            Ok::<_, anyhow::Error>(())
        })
    });

    if let Err(e) = server_handle.join() {
        error!("Server thread panicked: {:?}", e);
    }

    info!("Server stopped");
    Ok(())
}

fn run_serve_worker() -> anyhow::Result<()> {
    use ida_mcp::router::protocol::{RpcRequest, RpcResponse};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    info!("Starting IDA MCP Server (worker mode)");

    let (tx, rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
    let worker = IdaWorker::new(tx);

    // Oneshot channel: main thread signals after IDA loop exits (DB closed & lock released).
    // The orphan monitor awaits this before calling process::exit.
    let (ida_done_tx, ida_done_rx) = tokio::sync::oneshot::channel::<()>();

    let worker_for_rpc = worker.clone();
    let server_handle = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        rt.block_on(async move {
            info!("Worker RPC handler starting on stdin/stdout");

            let stdin = tokio::io::stdin();
            let stdout = tokio::io::stdout();
            let mut reader = tokio::io::BufReader::new(stdin);
            let mut writer = tokio::io::BufWriter::new(stdout);
            let mut line_buf = String::new();

            // Orphan detection: monitor parent process liveness.
            // When the parent (router) is killed/crashed, getppid() changes
            // (reparented to init). The monitor triggers shutdown so the
            // worker doesn't linger as an orphan holding IDB locks.
            #[cfg(unix)]
            {
                let worker_for_monitor = worker_for_rpc.clone();
                tokio::spawn(async move {
                    let parent_pid = unsafe { libc::getppid() };
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                    loop {
                        interval.tick().await;
                        let current = unsafe { libc::getppid() };
                        if current != parent_pid {
                            warn!(
                                "Parent process died (ppid {} -> {}), worker self-terminating",
                                parent_pid, current
                            );
                            let _ = worker_for_monitor.shutdown().await;
                            // Wait for IDA loop to confirm DB closure, or timeout.
                            tokio::select! {
                                _ = ida_done_rx => {
                                    info!("IDA loop confirmed done, exiting");
                                }
                                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                                    warn!("IDA loop did not finish within 30s, forcing exit");
                                }
                            }
                            std::process::exit(1);
                        }
                    }
                });
            }

            loop {
                line_buf.clear();
                match reader.read_line(&mut line_buf).await {
                    Ok(0) => {
                        // EOF — router closed the pipe
                        info!("Worker stdin closed (EOF), shutting down");
                        let _ = worker_for_rpc.shutdown().await;
                        break;
                    }
                    Ok(_) => {
                        let trimmed = line_buf.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        let req: RpcRequest = match serde_json::from_str(trimmed) {
                            Ok(r) => r,
                            Err(e) => {
                                let err_resp =
                                    RpcResponse::err("null", -32700, format!("Parse error: {e}"));
                                if let Ok(json) = serde_json::to_string(&err_resp) {
                                    let _ = writer.write_all(json.as_bytes()).await;
                                    let _ = writer.write_all(b"\n").await;
                                    let _ = writer.flush().await;
                                }
                                continue;
                            }
                        };

                        let id = req.id.clone();
                        let is_shutdown = req.method == "shutdown";

                        let result = rpc_dispatch::dispatch_rpc(&req, &worker_for_rpc).await;

                        let response = match result {
                            Ok(value) => RpcResponse::ok(&id, value),
                            Err(e) => RpcResponse::err(&id, -32000, e.to_string()),
                        };

                        let json = match serde_json::to_string(&response) {
                            Ok(j) => j,
                            Err(e) => serde_json::to_string(&RpcResponse::err(
                                &id,
                                -32603,
                                format!("Serialization error: {e}"),
                            ))
                            .unwrap_or_default(),
                        };
                        let _ = writer.write_all(json.as_bytes()).await;
                        let _ = writer.write_all(b"\n").await;
                        let _ = writer.flush().await;

                        if is_shutdown {
                            info!("Shutdown request processed, exiting RPC loop");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Worker stdin read error: {e}");
                        let _ = worker_for_rpc.shutdown().await;
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        })
    });

    // Main thread: IDA worker loop (IDA requires main thread)
    info!("Starting IDA worker loop (worker mode)");
    ida::run_ida_loop(rx);
    info!("IDA worker loop finished");
    let _ = ida_done_tx.send(());
    if let Err(e) = server_handle.join() {
        error!("Worker RPC handler thread panicked: {:?}", e);
    }

    info!("Worker stopped");
    Ok(())
}

fn run_server_http(args: ServeHttpArgs) -> anyhow::Result<()> {
    info!("Starting IDA MCP Server (streamable HTTP + multi-IDB router mode)");
    if args.json_response && !args.stateless {
        info!("--json-response is ignored unless --stateless is also set");
    }

    let bind_addr: SocketAddr = args
        .bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;

    let (tx, _rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
    let worker = Arc::new(IdaWorker::new(tx));

    let router = ida_mcp::router::RouterState::new()?;

    let worker_for_factory = worker.clone();
    let worker_for_shutdown = worker.clone();
    let router_for_factory = router.clone();
    let router_for_shutdown = router.clone();
    let router_for_final = router.clone();
    let server_handle = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        let result = rt.block_on(async move {
            let session_manager = Arc::new(LocalSessionManager::default());
            let cancel = tokio_util::sync::CancellationToken::new();
            let cancel_for_config = cancel.clone();
            let config = StreamableHttpServerConfig {
                sse_keep_alive: if args.sse_keep_alive_secs == 0 {
                    None
                } else {
                    Some(Duration::from_secs(args.sse_keep_alive_secs))
                },
                sse_retry: None,
                stateful_mode: !args.stateless,
                cancellation_token: cancel_for_config,
                json_response: args.json_response,
            };

            let service = StreamableHttpService::new(
                move || {
                    let mode = ServerMode::Router(router_for_factory.clone());
                    Ok(ida_mcp::server::SanitizedIdaServer(IdaMcpServer::new(
                        worker_for_factory.clone(),
                        mode,
                    )))
                },
                session_manager,
                config,
            );
            router.start_watchdog(
                std::time::Duration::from_secs(8 * 3600),
                std::time::Duration::from_secs(5 * 60),
                Some(std::time::Duration::from_secs(60)),
            );

            let socket_path = PathBuf::from(format!("/tmp/ida-mcp-{}.sock", std::process::id()));
            let socket_path_cleanup = socket_path.clone();
            let router_for_socket = router.clone();
            tokio::spawn(async move {
                if let Err(e) = ida_mcp::server::socket_listener::run_socket_listener(
                    socket_path,
                    router_for_socket,
                )
                .await
                {
                    warn!("Socket listener failed: {e}");
                }
            });

            let allowed_origins: std::collections::HashSet<String> = args
                .allow_origin
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let allowed_origins = Arc::new(allowed_origins);
            let service = OriginCheckService::new(service, allowed_origins);

            let listener = tokio::net::TcpListener::bind(bind_addr)
                .await
                .map_err(|e| anyhow::anyhow!("bind failed: {e}"))?;
            info!("MCP HTTP server listening on http://{bind_addr}");

            let shutdown_worker = worker_for_shutdown.clone();
            let cancel_for_shutdown = cancel.clone();
            let router_for_signal = router_for_shutdown.clone();
            tokio::spawn(async move {
                if wait_for_shutdown_signal().await.is_ok() {
                    info!("Shutdown signal received");
                    router_for_signal.shutdown_all().await;
                    let _ = shutdown_worker.close_for_shutdown().await;
                    let _ = shutdown_worker.shutdown().await;
                    ida_mcp::server::socket_listener::cleanup_socket_files(&socket_path_cleanup);
                    cancel_for_shutdown.cancel();
                }
            });

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("HTTP server shutting down");
                        break;
                    }
                    res = listener.accept() => {
                        let (stream, _) = res.map_err(|e| anyhow::anyhow!("accept failed: {e}"))?;
                        let svc = service.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let conn = http1::Builder::new().serve_connection(
                                io,
                                TowerToHyperService::new(svc),
                            );
                            if let Err(err) = conn.await {
                                tracing::error!("http connection error: {err}");
                            }
                        });
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        });
        if let Err(err) = result {
            error!("HTTP server error: {err}");
        }
    });

    if let Err(e) = server_handle.join() {
        error!("Server thread panicked: {:?}", e);
    }

    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(router_for_final.shutdown_all());
    }

    info!("Server stopped");
    Ok(())
}

fn run_probe(args: ProbeArgs) -> anyhow::Result<()> {
    info!("Starting IDA MCP Server (probe mode)");
    if let Ok(idadir) = std::env::var("IDADIR") {
        info!("IDADIR={}", idadir);
    }
    info!("Initializing IDA library on main thread");
    idalib::init_library();
    info!("IDA library initialized successfully");
    if let Ok(ver) = idalib::version() {
        info!(
            "IDA version {}.{}.{}",
            ver.major(),
            ver.minor(),
            ver.build()
        );
    }
    if args.ida_console {
        idalib::enable_console_messages(true);
        info!("IDA console messages enabled");
    }

    let path = expand_path(&args.path);
    info!("Opening database: {}", path.display());

    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();
    let path_display = path.display().to_string();
    let ticker = thread::spawn(move || {
        let start = Instant::now();
        loop {
            thread::sleep(Duration::from_secs(10));
            if done_clone.load(Ordering::Relaxed) {
                break;
            }
            info!(
                path = %path_display,
                elapsed = start.elapsed().as_secs(),
                "Still opening database..."
            );
        }
    });

    let open_start = Instant::now();
    let db = open_db_for_probe(&path, &args);
    done.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    let db =
        db.map_err(|e| anyhow::anyhow!("Failed to open database: {}: {}", path.display(), e))?;

    let meta = db.meta();
    let info = DbInfo {
        path: path.display().to_string(),
        file_type: format!("{:?}", meta.filetype()),
        processor: db.processor().long_name(),
        bits: if meta.is_64bit() {
            64
        } else if meta.is_32bit_exactly() {
            32
        } else {
            16
        },
        function_count: db.function_count(),
        debug_info: None,
        analysis_status: ida::handlers::analysis::build_analysis_status(&db),
    };
    info!("Database opened in {}s", open_start.elapsed().as_secs());
    println!("{}", serde_json::to_string_pretty(&info)?);

    if let Some(limit) = args.list {
        let list = list_functions(&db, 0, limit);
        println!("{}", serde_json::to_string_pretty(&list)?);
    }

    if let Some(name) = args.resolve.as_deref() {
        let func = resolve_function(&db, name)?;
        println!("{}", serde_json::to_string_pretty(&func)?);
    }

    if let Some(name) = args.disasm_by_name.as_deref() {
        let text = disasm_by_name(&db, name, args.count)?;
        println!("{}", text);
    }

    if let Some(addr_str) = args.disasm_addr.as_deref() {
        let addr = parse_address(addr_str)?;
        let text = disasm_at(&db, addr, args.count)?;
        println!("{}", text);
    }

    if let Some(addr_str) = args.decompile_addr.as_deref() {
        let addr = parse_address(addr_str)?;
        let func = db
            .function_at(addr)
            .ok_or_else(|| anyhow::anyhow!("Function not found at address {:#x}", addr))?;
        if !db.decompiler_available() {
            return Err(anyhow::anyhow!("Decompiler not available"));
        }
        let cfunc = db
            .decompile(&func)
            .map_err(|e| anyhow::anyhow!("Decompile failed: {}", e))?;
        println!("{}", cfunc.pseudocode());
    }

    info!("Probe completed");
    Ok(())
}

fn open_db_for_probe(path: &PathBuf, args: &ProbeArgs) -> Result<IDB, idalib::IDAError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_idb = ext == "i64" || ext == "idb";

    if is_idb {
        if args.auto_analyse {
            info!("Opening existing IDB with auto-analysis enabled");
            IDB::open_with(path, true, true) // auto_analyse=true, save=true to pack on close
        } else {
            IDB::open_with(path, false, true) // save=true to pack on close
        }
    } else {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(true);
        let out_path = if let Some(out) = args.idb_out.as_deref() {
            PathBuf::from(out)
        } else {
            path.with_extension("i64")
        };
        info!(
            "Opening raw binary with auto-analysis (idb_out={})",
            out_path.display()
        );
        opts.idb(&out_path).save(true).open(path)
    }
}

fn parse_address(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
            .map_err(|_| anyhow::anyhow!("Invalid address format: {}", s))
    } else {
        s.parse::<u64>()
            .map_err(|_| anyhow::anyhow!("Invalid address format: {}", s))
    }
}

fn list_functions(db: &IDB, offset: usize, limit: usize) -> ida_mcp::FunctionListResult {
    let total = db.function_count();
    let mut functions = Vec::with_capacity(limit.min(total.saturating_sub(offset)));

    for (idx, (_id, func)) in db.functions().enumerate() {
        if idx < offset {
            continue;
        }
        if functions.len() >= limit {
            break;
        }

        let addr = func.start_address();
        let name = func.name().unwrap_or_else(|| format!("sub_{:x}", addr));
        let size = func.len();

        functions.push(FunctionInfo {
            address: format!("{:#x}", addr),
            name,
            size,
        });
    }

    let next_offset = if offset + functions.len() < total {
        Some(offset + functions.len())
    } else {
        None
    };

    ida_mcp::FunctionListResult {
        functions,
        total,
        next_offset,
    }
}

fn resolve_function(db: &IDB, name: &str) -> anyhow::Result<FunctionInfo> {
    for (_id, func) in db.functions() {
        if let Some(func_name) = func.name() {
            if func_name == name || func_name.contains(name) {
                let addr = func.start_address();
                let size = func.len();
                return Ok(FunctionInfo {
                    address: format!("{:#x}", addr),
                    name: func_name,
                    size,
                });
            }
        }
    }

    Err(anyhow::anyhow!("Function not found: {}", name))
}

fn disasm_by_name(db: &IDB, name: &str, count: usize) -> anyhow::Result<String> {
    let func = resolve_function(db, name)?;
    let addr = parse_address(&func.address)?;
    disasm_at(db, addr, count)
}

fn disasm_at(db: &IDB, addr: Address, count: usize) -> anyhow::Result<String> {
    let mut lines = Vec::with_capacity(count);
    let mut current_addr: Address = addr;

    for _ in 0..count {
        if let Some(line) = generate_disasm_line(db, current_addr) {
            lines.push(format!("{:#x}:\t{}", current_addr, line));
        } else {
            break;
        }

        if let Some(insn) = db.insn_at(current_addr) {
            current_addr += insn.len() as u64;
        } else if let Some(next) = db.next_head(current_addr) {
            if next <= current_addr {
                break;
            }
            current_addr = next;
        } else {
            break;
        }
    }

    if lines.is_empty() {
        return Err(anyhow::anyhow!("Address out of range: {:#x}", addr));
    }

    Ok(lines.join("\n"))
}
