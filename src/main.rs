//! Headless IDA CLI and MCP Server
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
use ida_mcp::ida::{IdaBackend, WorkerBackendKind};
use ida_mcp::{federation, ida, rpc_dispatch, IdaMcpServer, IdaWorker, ServerMode};
use rmcp::transport::stdio;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::ServiceExt;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::Notify;
use tower_service::Service;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Layer};

const REQUEST_QUEUE_CAPACITY: usize = 64;

#[derive(Parser)]
#[command(name = "ida-cli", version, about = "Headless IDA CLI and MCP Server")]
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
    ServeWorker(ServeWorkerArgs),
    /// Internal: probe the active IDA runtime and select the worker backend.
    #[command(hide = true)]
    ProbeRuntime,

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
    /// Maximum number of in-flight HTTP requests before returning 503.
    #[arg(long, default_value_t = 256)]
    max_inflight_requests: usize,
}

#[derive(Args, Clone)]
struct ServeWorkerArgs {
    /// Internal backend selection used by the router.
    #[arg(long, value_enum, default_value_t = WorkerBackendKind::NativeLinked, hide = true)]
    backend: WorkerBackendKind,
}

#[derive(Clone)]
struct GatewayService<S> {
    inner: S,
    allowed_origins: Arc<std::collections::HashSet<String>>,
    router: ida_mcp::router::RouterState,
    inflight_limit: Arc<tokio::sync::Semaphore>,
}

impl<S> GatewayService<S> {
    fn new(
        inner: S,
        allowed_origins: Arc<std::collections::HashSet<String>>,
        router: ida_mcp::router::RouterState,
        inflight_limit: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        Self {
            inner,
            allowed_origins,
            router,
            inflight_limit,
        }
    }
}

impl<B, S> Service<Request<B>> for GatewayService<S>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send + 'static,
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
        let router = self.router.clone();
        let inflight_limit = self.inflight_limit.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let path = req.uri().path().to_string();

            if req.method() == hyper::http::Method::GET {
                if path == "/healthz" {
                    return Ok(json_response(
                        StatusCode::OK,
                        serde_json::json!({"ok": true, "service": "ida-cli"}),
                    ));
                }
                if path == "/readyz" {
                    let status = router.status_snapshot().await;
                    let ready = status
                        .runtime_probe
                        .as_ref()
                        .map(|probe| probe.supported)
                        .unwrap_or(false);
                    let code = if ready {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    };
                    return Ok(json_response(
                        code,
                        serde_json::json!({
                            "ok": ready,
                            "runtime_probe": status.runtime_probe,
                            "worker_count": status.worker_count,
                            "max_workers": status.max_workers,
                        }),
                    ));
                }
                if path == "/statusz" {
                    let status = router.status_snapshot_federated().await;
                    let value = serde_json::to_value(status)
                        .unwrap_or_else(|_| serde_json::json!({"error": "status serialization failed"}));
                    return Ok(json_response(StatusCode::OK, value));
                }
                if path == "/federationz" {
                    let nodes = router.federation_nodes_snapshot().await;
                    let statuses = crate::federation::probe_nodes(&nodes);
                    return Ok(json_response(
                        StatusCode::OK,
                        serde_json::json!({ "nodes": statuses }),
                    ));
                }
                if path == "/metrics" {
                    let status = router.status_snapshot().await;
                    return Ok(metrics_response(&status));
                }
                if path == "/tasksz" {
                    let tasks: Vec<_> = router
                        .list_task_states()
                        .into_iter()
                        .map(|state| ida_mcp::router::task_state_json(&state))
                        .collect();
                    return Ok(json_response(StatusCode::OK, serde_json::json!({ "tasks": tasks })));
                }
                if let Some(task_id) = path.strip_prefix("/taskz/") {
                    let resp = match router.task_state(task_id) {
                        Some(state) =>
                            json_response(StatusCode::OK, ida_mcp::router::task_state_json(&state)),
                        None => json_response(
                            StatusCode::NOT_FOUND,
                            serde_json::json!({"error": "unknown task_id"}),
                        ),
                    };
                    return Ok(resp);
                }
            }

            if let Some(origin) = req.headers().get(ORIGIN).and_then(|v| v.to_str().ok()) {
                if !allowed_origins.contains(origin) {
                    let resp = Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Full::new(Bytes::from("Forbidden")).boxed())
                        .expect("valid response");
                    return Ok(resp);
                }
            }

            let Ok(_permit) = inflight_limit.clone().try_acquire_owned() else {
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "ok": false,
                        "error": "server overloaded",
                        "reason": "max in-flight request limit reached",
                    }),
                ));
            };

            if req.method() == hyper::http::Method::POST && path == "/enqueuez" {
                let body = match req.into_body().collect().await {
                    Ok(body) => body.to_bytes(),
                    Err(err) => {
                        return Ok(json_response(
                            StatusCode::BAD_REQUEST,
                            serde_json::json!({"error": format!("invalid request body: {err}")}),
                        ));
                    }
                };
                let value: serde_json::Value = match serde_json::from_slice(&body) {
                    Ok(value) => value,
                    Err(err) => {
                        return Ok(json_response(
                            StatusCode::BAD_REQUEST,
                            serde_json::json!({"error": format!("invalid json: {err}")}),
                        ));
                    }
                };

                let path = value.get("path").and_then(|v| v.as_str());
                let method = value.get("method").and_then(|v| v.as_str());
                let priority = value
                    .get("priority")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u8;
                let tenant_id = value
                    .get("tenant_id")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned);
                let dedupe_key = value
                    .get("dedupe_key")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned);
                let params = value
                    .get("task_params")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                let federate = value
                    .get("federate")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let resp = match (path, method) {
                    (Some(path), Some(method)) if federate => match router
                        .enqueue_federated_task(path, method, params, tenant_id, priority, dedupe_key)
                        .await
                    {
                        Ok(value) => json_response(StatusCode::OK, value),
                        Err(err) => json_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            serde_json::json!({"error": err.to_string()}),
                        ),
                    },
                    (Some(path), Some(method)) => match router
                        .enqueue_route_task(path, method, params, tenant_id, priority, dedupe_key)
                        .await
                    {
                        Ok(value) => json_response(StatusCode::OK, value),
                        Err(err) => json_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            serde_json::json!({"error": err.to_string()}),
                        ),
                    },
                    _ => json_response(
                        StatusCode::BAD_REQUEST,
                        serde_json::json!({"error": "enqueuez requires path and method"}),
                    ),
                };
                return Ok(resp);
            }

            if req.method() == hyper::http::Method::POST && path == "/federationz/register" {
                let body = match req.into_body().collect().await {
                    Ok(body) => body.to_bytes(),
                    Err(err) => {
                        return Ok(json_response(
                            StatusCode::BAD_REQUEST,
                            serde_json::json!({"error": format!("invalid request body: {err}")}),
                        ));
                    }
                };
                let node: crate::federation::FederationNodeConfig =
                    match serde_json::from_slice(&body) {
                        Ok(node) => node,
                        Err(err) => {
                            return Ok(json_response(
                                StatusCode::BAD_REQUEST,
                                serde_json::json!({"error": format!("invalid federation node json: {err}")}),
                            ));
                        }
                    };
                let value = router.register_federation_node(node).await;
                return Ok(json_response(StatusCode::OK, value));
            }

            if req.method() == hyper::http::Method::POST && path == "/federationz/heartbeat" {
                let body = match req.into_body().collect().await {
                    Ok(body) => body.to_bytes(),
                    Err(err) => {
                        return Ok(json_response(
                            StatusCode::BAD_REQUEST,
                            serde_json::json!({"error": format!("invalid request body: {err}")}),
                        ));
                    }
                };
                let node: federation::FederationNodeConfig = match serde_json::from_slice(&body) {
                    Ok(node) => node,
                    Err(err) => {
                        return Ok(json_response(
                            StatusCode::BAD_REQUEST,
                            serde_json::json!({"error": format!("invalid federation heartbeat json: {err}")}),
                        ));
                    }
                };
                let value = router.heartbeat_federation_node(node).await;
                return Ok(json_response(StatusCode::OK, value));
            }

            if req.method() == hyper::http::Method::POST && path == "/federationz/unregister" {
                let body = match req.into_body().collect().await {
                    Ok(body) => body.to_bytes(),
                    Err(err) => {
                        return Ok(json_response(
                            StatusCode::BAD_REQUEST,
                            serde_json::json!({"error": format!("invalid request body: {err}")}),
                        ));
                    }
                };
                let value: serde_json::Value = match serde_json::from_slice(&body) {
                    Ok(value) => value,
                    Err(err) => {
                        return Ok(json_response(
                            StatusCode::BAD_REQUEST,
                            serde_json::json!({"error": format!("invalid json: {err}")}),
                        ));
                    }
                };
                let Some(name) = value.get("name").and_then(|v| v.as_str()) else {
                    return Ok(json_response(
                        StatusCode::BAD_REQUEST,
                        serde_json::json!({"error": "missing federation node name"}),
                    ));
                };
                let value = router.unregister_federation_node(name).await;
                return Ok(json_response(StatusCode::OK, value));
            }

            inner.call(req).await
        })
    }
}

fn json_response(
    status: StatusCode,
    value: serde_json::Value,
) -> Response<BoxBody<Bytes, std::convert::Infallible>> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"error\":\"serialization failed\"}".to_vec());
    Response::builder()
        .status(status)
        .header(hyper::http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)).boxed())
        .expect("valid response")
}

fn metrics_response(
    status: &ida_mcp::router::RouterStatus,
) -> Response<BoxBody<Bytes, std::convert::Infallible>> {
    let mut lines = Vec::new();
    lines.push("# HELP ida_cli_workers Number of live workers".to_string());
    lines.push("# TYPE ida_cli_workers gauge".to_string());
    lines.push(format!("ida_cli_workers {}", status.worker_count));

    lines.push("# HELP ida_cli_max_workers Configured worker limit".to_string());
    lines.push("# TYPE ida_cli_max_workers gauge".to_string());
    lines.push(format!("ida_cli_max_workers {}", status.max_workers));

    lines.push("# HELP ida_cli_max_pending_per_worker Configured per-worker queue limit".to_string());
    lines.push("# TYPE ida_cli_max_pending_per_worker gauge".to_string());
    lines.push(format!(
        "ida_cli_max_pending_per_worker {}",
        status.max_pending_per_worker
    ));

    lines.push("# HELP ida_cli_max_workers_per_tenant Configured per-tenant worker limit".to_string());
    lines.push("# TYPE ida_cli_max_workers_per_tenant gauge".to_string());
    lines.push(format!(
        "ida_cli_max_workers_per_tenant {}",
        status.max_workers_per_tenant
    ));

    lines.push("# HELP ida_cli_max_pending_per_tenant Configured per-tenant pending limit".to_string());
    lines.push("# TYPE ida_cli_max_pending_per_tenant gauge".to_string());
    lines.push(format!(
        "ida_cli_max_pending_per_tenant {}",
        status.max_pending_per_tenant
    ));

    lines.push("# HELP ida_cli_max_concurrent_spawns Configured concurrent spawn limit".to_string());
    lines.push("# TYPE ida_cli_max_concurrent_spawns gauge".to_string());
    lines.push(format!(
        "ida_cli_max_concurrent_spawns {}",
        status.max_concurrent_spawns
    ));

    lines.push("# HELP ida_cli_warm_pool_size Number of warm leased workers".to_string());
    lines.push("# TYPE ida_cli_warm_pool_size gauge".to_string());
    lines.push(format!("ida_cli_warm_pool_size {}", status.warm_pool.len()));

    lines.push("# HELP ida_cli_prewarm_queue_depth Number of queued prewarm tasks".to_string());
    lines.push("# TYPE ida_cli_prewarm_queue_depth gauge".to_string());
    lines.push(format!(
        "ida_cli_prewarm_queue_depth {}",
        status.prewarm_queue.len()
    ));

    lines.push("# HELP ida_cli_prewarm_active Number of active prewarm tasks".to_string());
    lines.push("# TYPE ida_cli_prewarm_active gauge".to_string());
    lines.push(format!(
        "ida_cli_prewarm_active {}",
        status.prewarm_active.len()
    ));

    lines.push("# HELP ida_cli_idb_cache_bytes Size of cached databases in bytes".to_string());
    lines.push("# TYPE ida_cli_idb_cache_bytes gauge".to_string());
    lines.push(format!(
        "ida_cli_idb_cache_bytes {}",
        status.idb_cache.total_size_bytes
    ));

    lines.push("# HELP ida_cli_response_cache_bytes Size of cached responses in bytes".to_string());
    lines.push("# TYPE ida_cli_response_cache_bytes gauge".to_string());
    lines.push(format!(
        "ida_cli_response_cache_bytes {}",
        status.response_cache.total_size_bytes
    ));

    for (backend, count) in &status.backend_counts {
        lines.push(format!(
            "ida_cli_backend_workers{{backend=\"{}\"}} {}",
            backend, count
        ));
    }

    for (tenant, count) in &status.tenant_worker_counts {
        lines.push(format!(
            "ida_cli_tenant_workers{{tenant=\"{}\"}} {}",
            tenant, count
        ));
    }

    for (tenant, count) in &status.tenant_pending_counts {
        lines.push(format!(
            "ida_cli_tenant_pending{{tenant=\"{}\"}} {}",
            tenant, count
        ));
    }

    if let Some(runtime_probe) = &status.runtime_probe {
        let supported = if runtime_probe.supported { 1 } else { 0 };
        let backend = runtime_probe.backend.map(|b| b.to_string()).unwrap_or_default();
        let version = runtime_probe
            .runtime
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        lines.push(format!(
            "ida_cli_runtime_probe{{backend=\"{}\",version=\"{}\"}} {}",
            backend, version, supported
        ));
    }

    let body = lines.join("\n") + "\n";
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Full::new(Bytes::from(body)).boxed())
        .expect("valid response")
}

fn main() -> anyhow::Result<()> {
    // Initialize logging:
    //   stderr : RUST_LOG  or  ida_mcp=info  (low-noise)
    //   ~/.ida/logs/server.log : RUST_LOG  or  ida_mcp=debug  (verbose, for post-mortem)
    let _ = ida_mcp::idb_store::ensure_dirs();
    {
        use std::fs::OpenOptions;
        use std::sync::Mutex;

        let log_path_buf = ida_mcp::idb_store::log_path();
        let log_path_str = log_path_buf.display().to_string();
        let stderr_layer = fmt::layer().with_writer(std::io::stderr).with_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("ida_mcp=info")),
        );

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path_buf)
        {
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
                eprintln!("[ida-cli] log -> {log_path_str}");
            }
            Err(e) => {
                eprintln!("[ida-cli] warn: cannot open log file {log_path_str}: {e}");
                tracing_subscriber::registry().with(stderr_layer).init();
            }
        }
    }

    info!(
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        "=== ida-cli started ==="
    );

    // Detect if invoked as "ida-cli" → flat CLI mode
    let exe_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));

    if exe_name.as_deref() == Some("ida-cli") {
        // If first arg is a server command, still use full Command parsing
        // (auto_start_server() spawns self + "serve-http" arg)
        let first_arg = std::env::args().nth(1);
        let is_server_mode = matches!(
            first_arg.as_deref(),
            Some("serve" | "serve-http" | "serve-worker" | "probe-runtime")
        );

        if !is_server_mode {
            // Flat CLI mode: parse CliArgs directly
            let args = ida_mcp::cli::CliArgs::parse();
            return run_cli(args);
        }
    }

    // Server mode: full Command parsing
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve(ServeArgs::default())) {
        Command::Serve(args) => run_server(args),
        Command::ServeHttp(args) => run_server_http(args),
        Command::ServeWorker(args) => run_serve_worker(args),
        Command::ProbeRuntime => run_probe_runtime(),

        Command::Cli(args) => run_cli(args),
    }
}

fn run_probe_runtime() -> anyhow::Result<()> {
    let probe = match std::panic::catch_unwind(|| {
        ida::native_backend().init_library();
        ida::native_backend().version()
    }) {
        Ok(Ok(version)) => ida::probe_native_runtime(version),
        Ok(Err(err)) => ida::RuntimeProbeResult::error(err.to_string()),
        Err(_) => ida::RuntimeProbeResult::error("native runtime probe panicked"),
    };

    println!("{}", serde_json::to_string(&probe)?);
    Ok(())
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
        let mut sigint = signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = sigint.recv() => {},
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
    info!("Starting ida-cli server (multi-IDB router mode)");

    if ida_mcp::idb_store::socket_is_live() {
        let pid = std::fs::read_to_string(ida_mcp::idb_store::pid_path()).unwrap_or_default();
        anyhow::bail!(
            "Another server instance is already running (pid {}). \
             Use `ida-cli shutdown` to stop it first.",
            pid.trim()
        );
    }

    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }

    let router = ida_mcp::router::RouterState::new()?;

    let (tx, _rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
    let worker = Arc::new(IdaWorker::new(tx));

    let server_handle = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        rt.block_on(async move {
            let _ = std::fs::write(
                ida_mcp::idb_store::pid_path(),
                std::process::id().to_string(),
            );

            info!("ida-cli server (router mode) listening on stdio");
            let server = IdaMcpServer::new(worker.clone(), ServerMode::Router(router.clone()));
            router.start_watchdog(
                std::time::Duration::from_secs(8 * 3600),
                std::time::Duration::from_secs(5 * 60),
                None,
            );

            let cancel = tokio_util::sync::CancellationToken::new();
            let socket_path = ida_mcp::idb_store::socket_path();
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

            let cancel_watch = cancel.clone();
            let shutdown_signal_cancel = shutdown_notify.clone();
            tokio::spawn(async move {
                cancel_watch.cancelled().await;
                shutdown_signal_cancel.notify_one();
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
            info!("ida-cli server shutting down (router mode)");
            router.shutdown_all().await;
            let _ = std::fs::remove_file(ida_mcp::idb_store::pid_path());
            let _ = std::fs::remove_file(ida_mcp::idb_store::socket_path());
            Ok::<_, anyhow::Error>(())
        })
    });

    if let Err(e) = server_handle.join() {
        error!("Server thread panicked: {:?}", e);
    }

    info!("Server stopped");
    Ok(())
}

fn run_serve_worker(args: ServeWorkerArgs) -> anyhow::Result<()> {
    use ida_mcp::router::protocol::{RpcRequest, RpcResponse};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    info!(backend = %args.backend, "Starting ida-cli worker");

    if matches!(args.backend, WorkerBackendKind::IdatCompat) {
        return ida_mcp::idat_compat::run_worker();
    }

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
    info!("Starting ida-cli server (streamable HTTP + multi-IDB router mode)");
    if args.json_response && !args.stateless {
        info!("--json-response is ignored unless --stateless is also set");
    }

    if ida_mcp::idb_store::socket_is_live() {
        let pid = std::fs::read_to_string(ida_mcp::idb_store::pid_path()).unwrap_or_default();
        anyhow::bail!(
            "Another server instance is already running (pid {}). \
             Use `ida-cli shutdown` to stop it first.",
            pid.trim()
        );
    }

    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
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
            let _ = std::fs::write(
                ida_mcp::idb_store::pid_path(),
                std::process::id().to_string(),
            );

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
                None,
            );

            let socket_path = ida_mcp::idb_store::socket_path();
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
            let inflight_limit =
                Arc::new(tokio::sync::Semaphore::new(args.max_inflight_requests.max(1)));
            let service = GatewayService::new(
                service,
                allowed_origins,
                router.clone(),
                inflight_limit,
            );

            let listener = tokio::net::TcpListener::bind(bind_addr)
                .await
                .map_err(|e| anyhow::anyhow!("bind failed: {e}"))?;
            info!("ida-cli HTTP server listening on http://{bind_addr}");

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

    let _ = std::fs::remove_file(ida_mcp::idb_store::pid_path());
    let _ = std::fs::remove_file(ida_mcp::idb_store::socket_path());
    info!("Server stopped");
    Ok(())
}

