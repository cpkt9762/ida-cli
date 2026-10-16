//! Multi-IDB Router — manages worker subprocesses.
//!
//! Architecture:
//! - Each open IDB gets a `WorkerProcess` running `ida-cli serve-worker`
//! - Requests are routed to workers via JSON-RPC over stdin/stdout
//! - Router maintains an "active" handle for backward compatibility

pub mod nexus_bridge;
pub mod nexus_tools;
pub mod nexus_transport;
pub mod protocol;
pub mod transport;
pub mod worker_io;

use crate::ida::{RuntimeProbeResult, WorkerBackendKind};
use crate::router::protocol::RpcRequest;
use crate::server::task::{TaskRegistry, TaskState, TaskStatus};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(test)]
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::{Mutex, Semaphore};
use tracing::{info, warn};

pub type DbHandle = String;
pub type ReqId = String;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct WorkerKey {
    tenant_id: String,
    path: PathBuf,
}

pub struct WorkerProcess {
    pub backend: WorkerBackendKind,
    pub tenant_id: String,
    pub child: Child,
    pub connection: transport::RpcConnection,
    pub close_token: Option<String>,
    pub open_path: Option<PathBuf>,
    pub last_active: Instant,
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub max_workers: usize,
    pub max_workers_per_tenant: usize,
    pub max_pending_per_worker: usize,
    pub max_pending_per_tenant: usize,
    pub max_concurrent_spawns: usize,
    pub max_warm_workers: usize,
    pub max_queued_prewarms: usize,
    pub max_active_prewarms: usize,
    pub max_prewarms_per_tenant: usize,
    pub max_idb_cache_bytes: u64,
    pub max_response_cache_bytes: u64,
    pub max_queued_tasks: usize,
    pub max_active_tasks: usize,
    pub max_tasks_per_tenant: usize,
    pub node_id: String,
}

impl RouterConfig {
    pub fn from_env() -> Self {
        let cpu_hint = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let default_max_workers = cpu_hint.saturating_mul(8).max(16);
        let max_workers = std::env::var("IDA_CLI_MAX_WORKERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default_max_workers);
        let max_pending_per_worker = std::env::var("IDA_CLI_MAX_PENDING_PER_WORKER")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(64);
        let max_workers_per_tenant = std::env::var("IDA_CLI_MAX_WORKERS_PER_TENANT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or((default_max_workers / 4).max(4));
        let max_pending_per_tenant = std::env::var("IDA_CLI_MAX_PENDING_PER_TENANT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(512);
        let max_concurrent_spawns = std::env::var("IDA_CLI_MAX_CONCURRENT_SPAWNS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or_else(|| max_workers.clamp(1, 4));
        let max_warm_workers = std::env::var("IDA_CLI_MAX_WARM_WORKERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(16);
        let max_queued_prewarms = std::env::var("IDA_CLI_MAX_QUEUED_PREWARMS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(256);
        let max_active_prewarms = std::env::var("IDA_CLI_MAX_ACTIVE_PREWARMS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(4);
        let max_prewarms_per_tenant = std::env::var("IDA_CLI_MAX_PREWARMS_PER_TENANT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(2);
        let max_idb_cache_bytes = std::env::var("IDA_CLI_MAX_IDB_CACHE_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(50 * 1024 * 1024 * 1024);
        let max_response_cache_bytes = std::env::var("IDA_CLI_MAX_RESPONSE_CACHE_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2 * 1024 * 1024 * 1024);
        let max_queued_tasks = std::env::var("IDA_CLI_MAX_QUEUED_TASKS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(512);
        let max_active_tasks = std::env::var("IDA_CLI_MAX_ACTIVE_TASKS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(16);
        let max_tasks_per_tenant = std::env::var("IDA_CLI_MAX_TASKS_PER_TENANT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(8);
        let node_id = std::env::var("IDA_CLI_NODE_ID").unwrap_or_else(|_| {
            format!(
                "{}-{}",
                std::env::var("HOSTNAME").unwrap_or_else(|_| "ida-cli".to_string()),
                std::process::id()
            )
        });

        Self {
            max_workers,
            max_workers_per_tenant,
            max_pending_per_worker,
            max_pending_per_tenant,
            max_concurrent_spawns,
            max_warm_workers,
            max_queued_prewarms,
            max_active_prewarms,
            max_prewarms_per_tenant,
            max_idb_cache_bytes,
            max_response_cache_bytes,
            max_queued_tasks,
            max_active_tasks,
            max_tasks_per_tenant,
            node_id,
        }
    }
}

#[derive(Debug, Clone)]
struct WarmLease {
    handle: DbHandle,
    token: String,
    path: PathBuf,
    cache_path: Option<PathBuf>,
    tenant_id: String,
    pinned_at: Instant,
    last_hit: Instant,
}

#[derive(Debug, Clone, Serialize)]
pub struct WarmLeaseStatus {
    pub path: String,
    pub handle: String,
    pub tenant_id: String,
    pub cache_path: Option<String>,
    pub pinned_secs: u64,
    pub idle_secs: u64,
}

#[derive(Debug, Clone)]
struct QueuedPrewarmTask {
    task_id: String,
    path: String,
    tenant_id: String,
    priority: u8,
    keep_warm: bool,
    enqueued_at: Instant,
}

#[derive(Debug, Clone)]
struct ActivePrewarmTask {
    task_id: String,
    path: String,
    tenant_id: String,
    priority: u8,
    keep_warm: bool,
    started_at: Instant,
}

#[derive(Debug, Clone)]
struct QueuedRouteTask {
    preparation: crate::preprocess::Preparation,
    task_id: String,
    path: String,
    method: String,
    params: serde_json::Value,
    tenant_id: String,
    priority: u8,
    enqueued_at: Instant,
}

#[derive(Debug, Clone)]
struct ActiveRouteTask {
    task_id: String,
    path: String,
    method: String,
    tenant_id: String,
    priority: u8,
    started_at: Instant,
}

#[derive(Debug, Default)]
struct PrewarmQueueState {
    queued: Vec<QueuedPrewarmTask>,
    active: HashMap<String, ActivePrewarmTask>,
    recent: Vec<serde_json::Value>,
    next_task_id: u64,
    tenant_active: HashMap<String, usize>,
}

#[derive(Debug, Default)]
struct RouteQueueState {
    queued: Vec<QueuedRouteTask>,
    active: HashMap<String, ActiveRouteTask>,
    tenant_active: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrewarmTaskStatus {
    pub task_id: String,
    pub path: String,
    pub tenant_id: String,
    pub priority: u8,
    pub keep_warm: bool,
    pub state: String,
    pub age_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteTaskStatus {
    pub task_id: String,
    pub path: String,
    pub method: String,
    pub tenant_id: String,
    pub priority: u8,
    pub state: String,
    pub age_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkerStatus {
    pub handle: String,
    pub backend: String,
    pub tenant_id: String,
    pub pid: Option<u32>,
    pub open_path: Option<String>,
    pub pending_requests: usize,
    pub ref_count: usize,
    pub idle_secs: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouterStatus {
    pub metadata: DaemonMetadata,
    pub worker_count: usize,
    pub active_handle: Option<String>,
    pub max_workers: usize,
    pub max_workers_per_tenant: usize,
    pub max_pending_per_worker: usize,
    pub max_pending_per_tenant: usize,
    pub max_concurrent_spawns: usize,
    pub max_warm_workers: usize,
    pub max_queued_prewarms: usize,
    pub max_active_prewarms: usize,
    pub max_prewarms_per_tenant: usize,
    pub max_idb_cache_bytes: u64,
    pub max_response_cache_bytes: u64,
    pub max_queued_tasks: usize,
    pub max_active_tasks: usize,
    pub max_tasks_per_tenant: usize,
    pub node_id: String,
    pub runtime_probe: Option<RuntimeProbeResult>,
    pub backend_counts: HashMap<String, usize>,
    pub tenant_worker_counts: HashMap<String, usize>,
    pub tenant_pending_counts: HashMap<String, usize>,
    pub workers: Vec<WorkerStatus>,
    pub warm_pool: Vec<WarmLeaseStatus>,
    pub prewarm_queue: Vec<PrewarmTaskStatus>,
    pub prewarm_active: Vec<PrewarmTaskStatus>,
    pub prewarm_recent: Vec<serde_json::Value>,
    pub route_queue: Vec<RouteTaskStatus>,
    pub route_active: Vec<RouteTaskStatus>,
    pub recent_tasks: Vec<serde_json::Value>,
    pub idb_cache: Option<crate::idb_store::IdbStoreStats>,
    pub response_cache: Option<crate::server::response_cache::ResponseCacheStats>,
    pub cache_statistics_error: Option<String>,
    pub cache_statistics_refreshing: bool,
    pub federation_nodes: Vec<crate::federation::FederationNodeStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DaemonMetadata {
    pub version: String,
    pub rpc_socket_path: String,
    pub mcp_socket_path: String,
    pub http_address: Option<String>,
    pub backend: Option<String>,
    pub ida_version: Option<String>,
    pub supported_methods: Vec<String>,
    pub supported_tools: Vec<String>,
}

type CacheSnapshot = (
    Option<crate::idb_store::IdbStoreStats>,
    Option<crate::server::response_cache::ResponseCacheStats>,
    Option<String>,
);

#[derive(Clone)]
pub struct RouterState {
    inner: Arc<Mutex<RouterInner>>,
    references: Arc<std::sync::Mutex<ReferenceTokens>>,
    config: Arc<RouterConfig>,
    spawn_gate: Arc<Semaphore>,
    nexus: Arc<std::sync::Mutex<(nexus_transport::NexusEndpoint, bool)>>,
    nexus_bridge: Arc<tokio::sync::OnceCell<Arc<nexus_bridge::NexusBridge>>>,
    nexus_tools: Arc<nexus_tools::Tools>,
    cached_probe: Arc<Mutex<Option<RuntimeProbeResult>>>,
    warm_pool: Arc<Mutex<HashMap<PathBuf, WarmLease>>>,
    prewarm_queue: Arc<Mutex<PrewarmQueueState>>,
    route_queue: Arc<Mutex<RouteQueueState>>,
    task_registry: TaskRegistry,
    federation_nodes: Arc<Mutex<HashMap<String, crate::federation::FederationNodeRecord>>>,
    http_address: Arc<Mutex<Option<String>>>,
    maintenance_started: Arc<AtomicBool>,
    metadata_refreshing: Arc<AtomicBool>,
    cache_stats: Arc<Mutex<CacheSnapshot>>,
}

impl std::fmt::Debug for RouterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterState").finish_non_exhaustive()
    }
}

struct RouterInner {
    workers: HashMap<DbHandle, WorkerProcess>,
    active: Option<DbHandle>,
    path_to_handle: HashMap<WorkerKey, DbHandle>,
    req_counter: u64,
    exe_path: PathBuf,
}

// Only short in-memory token operations use this lock. It is never held
// across await, I/O, or acquisition of inner/warm_pool. When combined, lock
// order is warm_pool -> inner -> references. Drop can release without a task.
#[derive(Default)]
struct ReferenceTokens {
    token_to_handle: HashMap<String, DbHandle>,
    ref_tokens: HashMap<DbHandle, HashSet<String>>,
}
impl ReferenceTokens {
    fn release(&mut self, token: &str) -> Option<(DbHandle, usize)> {
        let handle = self.token_to_handle.remove(token)?;
        let remaining = self
            .ref_tokens
            .get_mut(&handle)
            .map(|tokens| {
                tokens.remove(token);
                tokens.len()
            })
            .unwrap_or(0);
        Some((handle, remaining))
    }
}
pub(crate) struct ScopedRefToken {
    references: Arc<std::sync::Mutex<ReferenceTokens>>,
    token: Option<String>,
    nexus_router: Option<RouterState>,
}
impl ScopedRefToken {
    pub(crate) fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Transfer only after the completed response contains this token.
    pub(crate) fn transfer(&mut self) {
        self.token.take();
    }

    fn release(&mut self) -> Option<(DbHandle, usize)> {
        self.token.take().and_then(|token| {
            if let Some(router) = &self.nexus_router {
                nexus_tools::Tools::abandon(router.clone(), token);
                return None;
            }
            self.references
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .release(&token)
        })
    }
}
impl Drop for ScopedRefToken {
    fn drop(&mut self) {
        self.release();
    }
}

impl RouterState {
    fn normalize_tenant(tenant_id: Option<&str>) -> String {
        tenant_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("default")
            .to_string()
    }

    fn worker_key(path: PathBuf, tenant_id: &str) -> WorkerKey {
        WorkerKey {
            tenant_id: tenant_id.to_string(),
            path,
        }
    }

    pub fn new() -> anyhow::Result<Self> {
        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ida-cli"));
        let config = Arc::new(RouterConfig::from_env());

        Ok(Self {
            inner: Arc::new(Mutex::new(RouterInner {
                workers: HashMap::new(),
                active: None,
                path_to_handle: HashMap::new(),
                req_counter: 0,
                exe_path,
            })),
            references: Arc::new(std::sync::Mutex::new(ReferenceTokens::default())),
            config: config.clone(),
            spawn_gate: Arc::new(Semaphore::new(config.max_concurrent_spawns)),
            nexus: Arc::new(std::sync::Mutex::new((
                nexus_transport::NexusEndpoint::new(config.max_pending_per_tenant),
                false,
            ))),
            nexus_bridge: Arc::new(tokio::sync::OnceCell::new()),
            nexus_tools: Arc::new(nexus_tools::Tools::new(config.max_pending_per_tenant)?),
            cached_probe: Arc::new(Mutex::new(None)),
            warm_pool: Arc::new(Mutex::new(HashMap::new())),
            prewarm_queue: Arc::new(Mutex::new(PrewarmQueueState::default())),
            route_queue: Arc::new(Mutex::new(RouteQueueState::default())),
            task_registry: TaskRegistry::new(),
            federation_nodes: Arc::new(Mutex::new(crate::federation::load_node_map_from_env())),
            http_address: Arc::new(Mutex::new(None)),
            maintenance_started: Arc::new(AtomicBool::new(false)),
            metadata_refreshing: Arc::new(AtomicBool::new(false)),
            cache_stats: Arc::new(Mutex::new((None, None, None))),
        })
    }

    pub fn nexus_endpoint(&self) -> nexus_transport::NexusEndpoint {
        self.nexus
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .clone()
    }
    pub fn uses_nexus(&self) -> bool {
        self.nexus_tools.selected()
    }
    pub async fn nexus_close_token(
        &self,
        token: &str,
    ) -> Result<Option<(String, usize)>, crate::error::ToolError> {
        self.nexus_tools.close_token(self, token).await
    }
    pub async fn nexus_open_details(
        &self,
        handle: &str,
        preparation: crate::preprocess::Preparation,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        self.nexus_tools
            .open_details(self, handle, preparation)
            .await
    }
    /// Internal N3 connection point; public CLI/MCP tools are switched in N4.
    pub async fn connect_nexus(
        &self,
        config: nexus_bridge::BridgeConfig,
    ) -> anyhow::Result<Arc<nexus_bridge::NexusBridge>> {
        self.nexus_bridge
            .get_or_try_init(|| async {
                nexus_bridge::NexusBridge::start(self, config)
                    .await
                    .map(Arc::new)
            })
            .await
            .cloned()
    }
    pub fn install_nexus_capabilities(
        &self,
        capabilities: crate::nexus::NexusCapabilities,
    ) -> Result<(), crate::nexus::NexusError> {
        capabilities.runtime.validate()?;
        let mut endpoint = self.nexus.lock().unwrap_or_else(|e| e.into_inner());
        if endpoint.1 {
            return Err(crate::nexus::NexusError::new(
                crate::nexus::NexusErrorCode::Busy,
                "Nexus endpoint already installed",
            ));
        }
        *endpoint = (
            nexus_transport::NexusEndpoint::with_capabilities(
                self.config.max_pending_per_tenant,
                Ok(capabilities),
            ),
            true,
        );
        Ok(())
    }

    pub async fn set_http_address(&self, address: Option<String>) {
        *self.http_address.lock().await = address;
    }

    pub async fn federation_nodes_snapshot(&self) -> Vec<crate::federation::FederationNodeRecord> {
        self.federation_nodes
            .lock()
            .await
            .values()
            .cloned()
            .collect()
    }

    pub async fn register_federation_node(
        &self,
        node: crate::federation::FederationNodeConfig,
    ) -> serde_json::Value {
        let mut nodes = self.federation_nodes.lock().await;
        let replaced = nodes
            .insert(
                node.name.clone(),
                crate::federation::FederationNodeRecord::new(node.clone(), "dynamic"),
            )
            .is_some();
        serde_json::json!({
            "ok": true,
            "replaced": replaced,
            "node": node,
        })
    }

    pub async fn heartbeat_federation_node(
        &self,
        node: crate::federation::FederationNodeConfig,
    ) -> serde_json::Value {
        let mut nodes = self.federation_nodes.lock().await;
        let mut record = nodes.remove(&node.name).unwrap_or_else(|| {
            crate::federation::FederationNodeRecord::new(node.clone(), "heartbeat")
        });
        record.config = node.clone();
        record.source = "heartbeat".to_string();
        record.touch(crate::server::task::iso_now());
        nodes.insert(node.name.clone(), record);
        serde_json::json!({
            "ok": true,
            "node": node,
        })
    }

    pub async fn unregister_federation_node(&self, name: &str) -> serde_json::Value {
        let mut nodes = self.federation_nodes.lock().await;
        let removed = nodes.remove(name).is_some();
        serde_json::json!({
            "ok": removed,
            "name": name,
        })
    }

    fn apply_worker_env(cmd: &mut Command) {
        for var in &["DYLD_LIBRARY_PATH", "IDADIR", "LD_LIBRARY_PATH", "PATH"] {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }
    }

    async fn probe_worker_backend(
        &self,
        exe_path: &std::path::Path,
    ) -> Result<RuntimeProbeResult, anyhow::Error> {
        if let Some(cached) = self.cached_probe.lock().await.clone() {
            return Ok(cached);
        }

        let mut cmd = Command::new(exe_path);
        cmd.arg("probe-runtime")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        Self::apply_worker_env(&mut cmd);

        let output = crate::preprocess::run(
            cmd,
            crate::preprocess::Preparation::new(Duration::from_secs(5)),
        )
        .await
        .map_err(|e| anyhow::anyhow!("runtime probe: {e}"))?;

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if !output.status.success() {
            let mut msg = format!("probe-runtime exited with status {}", output.status);
            if !stderr.is_empty() {
                msg.push_str(&format!(": {stderr}"));
            }
            return Err(anyhow::anyhow!(msg));
        }

        let mut probe = serde_json::from_str::<RuntimeProbeResult>(&stdout).map_err(|e| {
            anyhow::anyhow!(
                "failed to parse probe-runtime output: {e}; stdout={stdout:?}; stderr={stderr:?}"
            )
        })?;
        if let Ok(forced) = std::env::var("IDA_CLI_WORKER_BACKEND") {
            let forced = forced.trim();
            if probe.supported {
                let backend = match forced {
                    "native-linked" => Some(WorkerBackendKind::NativeLinked),
                    "idat-compat" => Some(WorkerBackendKind::IdatCompat),
                    "" => None,
                    other => {
                        warn!(
                            backend = other,
                            "ignoring invalid IDA_CLI_WORKER_BACKEND; expected native-linked or idat-compat"
                        );
                        None
                    }
                };
                if let Some(backend) = backend {
                    if let Some(runtime) = probe.runtime.clone() {
                        probe = RuntimeProbeResult::supported(runtime, backend);
                    }
                }
            }
        }
        *self.cached_probe.lock().await = Some(probe.clone());
        Ok(probe)
    }

    /// Spawn a new worker subprocess for the given IDB path.
    /// Returns the db_handle (existing handle if file already open).
    pub async fn spawn_worker(
        &self,
        path: &str,
        tenant_id: Option<&str>,
    ) -> Result<(DbHandle, Option<String>), anyhow::Error> {
        // Expand `~/...` before canonicalising; see ensure_worker_with_ref_idb
        // for the detailed rationale.
        let expanded = crate::expand_path(path);
        let canonical_path = crate::blocking::run(crate::blocking::WorkClass::Prepare, move || {
            std::fs::canonicalize(&expanded)
        })
        .await??;
        let tenant_id = Self::normalize_tenant(tenant_id);
        let worker_key = Self::worker_key(canonical_path.clone(), &tenant_id);

        let exe_path = {
            let mut inner = self.inner.lock().await;

            if let Some(existing_handle) = inner.path_to_handle.get(&worker_key).cloned() {
                info!(
                    "Tenant {} path {:?} already open with handle {}, issuing new ref token",
                    tenant_id, canonical_path, existing_handle
                );
                let now = {
                    use std::time::{SystemTime, UNIX_EPOCH};
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                };
                let pid = std::process::id();
                let nonce = inner.req_counter;
                inner.req_counter += 1;
                let ref_token = format!("{now:x}-{pid:x}-{nonce:x}");

                let mut references = self.references.lock().unwrap_or_else(|e| e.into_inner());
                references
                    .token_to_handle
                    .insert(ref_token.clone(), existing_handle.clone());
                references
                    .ref_tokens
                    .entry(existing_handle.clone())
                    .or_default()
                    .insert(ref_token.clone());

                return Ok((existing_handle, Some(ref_token)));
            }

            inner.exe_path.clone()
        };
        let _spawn_permit = self
            .spawn_gate
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("spawn gate is closed"))?;
        let probe = self.probe_worker_backend(&exe_path).await?;
        let backend = probe.backend.ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                probe.reason.unwrap_or_else(|| {
                    "runtime probe reported no usable worker backend".to_string()
                })
            )
        })?;
        let runtime = probe
            .runtime
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "Spawning worker {} for path {:?} using backend {} (runtime {})",
            "<pending>", canonical_path, backend, runtime
        );

        loop {
            let maybe_evict = {
                let inner = self.inner.lock().await;
                if inner.workers.len() < self.config.max_workers {
                    None
                } else {
                    inner
                        .workers
                        .iter()
                        .filter(|(handle, worker)| {
                            let ref_count = self
                                .references
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .ref_tokens
                                .get(*handle)
                                .map(|set| set.len())
                                .unwrap_or(0);
                            ref_count == 0
                                && worker.connection.pending_len() == 0
                                && inner.active.as_deref() != Some(handle.as_str())
                        })
                        .min_by_key(|(_, worker)| worker.last_active)
                        .map(|(handle, _)| handle.clone())
                }
            };

            match maybe_evict {
                Some(handle) => {
                    warn!(
                        handle = %handle,
                        max_workers = self.config.max_workers,
                        "worker limit reached, evicting oldest idle worker"
                    );
                    self.close_worker(&handle)
                        .await
                        .map_err(|e| anyhow::anyhow!("failed to evict idle worker: {e}"))?;
                }
                None => break,
            }
        }

        let mut inner = self.inner.lock().await;
        let tenant_worker_count = inner
            .workers
            .values()
            .filter(|worker| worker.tenant_id == tenant_id)
            .count();
        if tenant_worker_count >= self.config.max_workers_per_tenant {
            return Err(anyhow::anyhow!(
                "tenant worker limit reached ({}) for tenant {}",
                self.config.max_workers_per_tenant,
                tenant_id
            ));
        }
        if inner.workers.len() >= self.config.max_workers {
            return Err(anyhow::anyhow!(
                "worker limit reached ({}) and no idle worker was evictable",
                self.config.max_workers
            ));
        }
        if let Some(existing_handle) = inner.path_to_handle.get(&worker_key).cloned() {
            info!(
                "Tenant {} path {:?} became active while probing backend; reusing handle {}",
                tenant_id, canonical_path, existing_handle
            );
            let now = {
                use std::time::{SystemTime, UNIX_EPOCH};
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            };
            let pid = std::process::id();
            let nonce = inner.req_counter;
            inner.req_counter += 1;
            let ref_token = format!("{now:x}-{pid:x}-{nonce:x}");

            let mut references = self.references.lock().unwrap_or_else(|e| e.into_inner());
            references
                .token_to_handle
                .insert(ref_token.clone(), existing_handle.clone());
            references
                .ref_tokens
                .entry(existing_handle.clone())
                .or_default()
                .insert(ref_token.clone());

            return Ok((existing_handle, Some(ref_token)));
        }

        let handle: DbHandle = format!("{:016x}", {
            use std::time::{SystemTime, UNIX_EPOCH};
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0) as u64;
            let pid = std::process::id() as u64;
            let counter = inner.req_counter;
            inner.req_counter += 1;
            t ^ (pid << 32) ^ counter
        });
        drop(inner);
        info!(
            "Spawning worker {} for path {:?} using backend {} (runtime {})",
            handle, canonical_path, backend, runtime
        );

        let mut cmd = Command::new(&exe_path);
        cmd.arg("serve-worker")
            .arg("--backend")
            .arg(backend.as_cli_arg())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        Self::apply_worker_env(&mut cmd);

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn worker process: {e}"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get worker stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get worker stdout"))?;

        let connection =
            transport::RpcConnection::start(stdout, stdin, self.config.max_pending_per_worker);

        let close_token = format!("ref-{handle}");

        let worker = WorkerProcess {
            backend,
            tenant_id: tenant_id.clone(),
            child,
            connection,
            close_token: Some(close_token.clone()),
            open_path: Some(canonical_path.clone()),
            last_active: Instant::now(),
        };

        let mut inner = self.inner.lock().await;
        if inner.workers.len() >= self.config.max_workers
            || inner
                .workers
                .values()
                .filter(|w| w.tenant_id == tenant_id)
                .count()
                >= self.config.max_workers_per_tenant
        {
            drop(inner);
            worker.connection.close();
            let mut child = worker.child;
            child.kill().await?;
            return Err(anyhow::anyhow!("worker limit reached during spawn"));
        }
        if let Some(existing) = inner.path_to_handle.get(&worker_key).cloned() {
            drop(inner);
            worker.connection.close();
            let mut child = worker.child;
            child.kill().await?;
            let token = self.issue_ref_for_handle(&existing).await;
            return Ok((existing, Some(token)));
        }
        inner.path_to_handle.insert(worker_key, handle.clone());
        self.references
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .token_to_handle
            .insert(close_token.clone(), handle.clone());
        let mut init_refs = HashSet::new();
        init_refs.insert(close_token.clone());
        self.references
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ref_tokens
            .insert(handle.clone(), init_refs);
        let connection = worker.connection.clone();
        inner.workers.insert(handle.clone(), worker);
        inner.active = Some(handle.clone());
        drop(inner);
        let router = self.clone();
        let watched_handle = handle.clone();
        tokio::spawn(async move {
            connection.closed().await;
            if let Err(e) = router.close_worker(&watched_handle).await {
                warn!(error=%e,"closed connection worker cleanup failed");
            }
        });

        Ok((handle, Some(close_token)))
    }

    /// Route a request to the appropriate worker process.
    /// If handle is None, routes to the active worker.
    pub async fn route_request(
        &self,
        handle: Option<&str>,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        let maximum = if method == "open" { 3600 } else { 600 };
        let timeout_secs = params
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(120)
            .min(maximum);
        let preparation = crate::preprocess::Preparation::new(Duration::from_secs(timeout_secs));
        self.route_request_prepared(handle, method, params, preparation)
            .await
    }

    pub async fn route_request_prepared(
        &self,
        handle: Option<&str>,
        method: &str,
        params: serde_json::Value,
        preparation: crate::preprocess::Preparation,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        use crate::error::ToolError;
        if self.uses_nexus() {
            return self
                .nexus_tools
                .execute(self, handle, method, params, preparation)
                .await;
        }
        preparation.check()?;
        let maximum = if method == "open" { 3600 } else { 600 };
        let timeout_secs = params
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(120)
            .min(maximum);
        let deadline = preparation.deadline;
        let (target_handle, req_id) = {
            let mut inner = self.inner.lock().await;
            let target = match handle {
                Some(h) => h.to_string(),
                None if inner.workers.len() > 1 => {
                    return Err(ToolError::InvalidParams(
                        "db_handle is required when multiple databases are open".into(),
                    ))
                }
                None => inner.active.clone().ok_or(ToolError::NoDatabaseOpen)?,
            };
            let counter = inner.req_counter;
            inner.req_counter = counter.checked_add(1).ok_or(ToolError::Busy)?;
            (target, format!("r{counter}"))
        };
        let mut params = params;
        protocol::attach_deadline(&mut params, deadline)?;
        let bytes = preparation
            .wait(transport::RpcConnection::encode(RpcRequest::new(
                &req_id, method, params,
            )))
            .await?;
        let waiting = {
            let mut inner = self.inner.lock().await;
            let tenant = inner
                .workers
                .get(&target_handle)
                .ok_or_else(|| {
                    ToolError::InvalidParams(format!("Unknown db_handle: {target_handle}"))
                })?
                .tenant_id
                .clone();
            let count: usize = inner
                .workers
                .values()
                .filter(|w| w.tenant_id == tenant)
                .map(|w| w.connection.pending_len())
                .sum();
            if count >= self.config.max_pending_per_tenant {
                return Err(ToolError::Busy);
            }
            let worker = inner
                .workers
                .get_mut(&target_handle)
                .ok_or(ToolError::WorkerClosed)?;
            let waiting = worker.connection.enqueue(req_id, bytes, deadline)?;
            worker.last_active = Instant::now();
            waiting
        };
        waiting
            .wait_prepared(timeout_secs, &preparation.cancel)
            .await
    }

    pub async fn close_worker(&self, handle: &str) -> Result<(), crate::error::ToolError> {
        self.close_worker_inner(handle, false).await.map(|_| ())
    }

    async fn close_worker_inner(
        &self,
        handle: &str,
        only_unreferenced: bool,
    ) -> Result<bool, crate::error::ToolError> {
        let mut warm_pool = self.warm_pool.lock().await;
        let worker = {
            let mut inner = self.inner.lock().await;
            let mut references = self.references.lock().unwrap_or_else(|e| e.into_inner());
            if only_unreferenced
                && references
                    .ref_tokens
                    .get(handle)
                    .is_some_and(|tokens| !tokens.is_empty())
            {
                return Ok(false);
            }
            warm_pool.retain(|_, lease| lease.handle != handle);
            let worker = inner.workers.remove(handle);
            if let Some(worker) = &worker {
                if let Some(path) = &worker.open_path {
                    inner
                        .path_to_handle
                        .remove(&Self::worker_key(path.clone(), &worker.tenant_id));
                }
                if let Some(tokens) = references.ref_tokens.remove(handle) {
                    for token in tokens {
                        references.token_to_handle.remove(&token);
                    }
                }
                if inner.active.as_deref() == Some(handle) {
                    inner.active = inner.workers.keys().next().cloned();
                }
            }
            worker
        };
        drop(warm_pool);
        let closed = worker.is_some();
        if let Some(mut worker) = worker {
            if only_unreferenced {
                let preparation = crate::preprocess::current().unwrap_or_else(|| {
                    crate::preprocess::Preparation::new(Duration::from_secs(120))
                });
                for method in ["close", "shutdown"] {
                    let id = format!("release-{handle}-{method}");
                    let result = async {
                        preparation.check()?;
                        let bytes = preparation
                            .wait(transport::RpcConnection::encode(RpcRequest::new(
                                &id,
                                method,
                                serde_json::json!({}),
                            )))
                            .await?;
                        worker
                            .connection
                            .enqueue(id, bytes, preparation.deadline)?
                            .wait_prepared(120, &preparation.cancel)
                            .await
                    }
                    .await;
                    if let Err(error) = result {
                        warn!(%handle, method, %error, "unreferenced prewarm worker graceful close failed");
                    }
                }
            }
            worker.connection.close();
            worker
                .child
                .kill()
                .await
                .map_err(|e| crate::error::ToolError::IdaError(format!("worker cleanup: {e}")))?;
            info!("Closed worker {}", handle);
        }
        Ok(closed)
    }

    pub(crate) fn scoped_ref(&self, token: String) -> ScopedRefToken {
        ScopedRefToken {
            references: self.references.clone(),
            token: Some(token),
            nexus_router: self.uses_nexus().then(|| self.clone()),
        }
    }

    pub(crate) async fn release_failed_open(
        &self,
        handle: &str,
        reference: &mut ScopedRefToken,
    ) -> Result<(), crate::error::ToolError> {
        // Reused workers receive a new token. Only the creator receives the
        // exact initial token recorded on this worker, including spawn races.
        let created = {
            let inner = self.inner.lock().await;
            inner.workers.get(handle).is_some_and(|worker| {
                reference.token().is_some() && worker.close_token.as_deref() == reference.token()
            })
        };
        reference.release();
        if created {
            // Recheck under the removal lock: another client may have acquired
            // a reference since creation or since releasing this opener's ref.
            self.close_worker_inner(handle, true).await?;
        }
        Ok(())
    }

    /// Release a reference token. Returns `Some((handle, remaining))` if the token was valid:
    /// `remaining > 0` means other clients still hold refs (do NOT close the worker),
    /// `remaining == 0` means last reference released (caller should close the worker).
    /// Returns `None` if the token was not found (invalid or already released).
    pub async fn release_ref_token(&self, token: &str) -> Option<(DbHandle, usize)> {
        if self.uses_nexus() {
            return match self.nexus_close_token(token).await {
                Ok(value) => value,
                Err(error) => {
                    warn!(%error,"Nexus reference release unconfirmed; tracking retained");
                    None
                }
            };
        }
        self.references
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .release(token)
    }

    pub async fn handle_for_token(&self, token: &str) -> Option<DbHandle> {
        if self.uses_nexus() {
            return self.nexus_tools.handle_for_token(token);
        }
        self.references
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .token_to_handle
            .get(token)
            .cloned()
    }

    pub async fn active_handle(&self) -> Option<DbHandle> {
        if self.uses_nexus() {
            return self.nexus_tools.active();
        }
        let inner = self.inner.lock().await;
        inner.active.clone()
    }

    pub async fn all_handles(&self) -> Vec<DbHandle> {
        if self.uses_nexus() {
            return self.nexus_tools.handles();
        }
        let inner = self.inner.lock().await;
        inner.workers.keys().cloned().collect()
    }

    pub async fn worker_count(&self) -> usize {
        if self.uses_nexus() {
            return self.nexus_tools.workers(self).len();
        }
        let inner = self.inner.lock().await;
        inner.workers.len()
    }

    async fn status_snapshot_inner(&self, include_federation: bool) -> RouterStatus {
        let runtime_probe = self.cached_probe.lock().await.clone();
        self.refresh_metadata();
        let cache_stats = self.cache_stats.lock().await.clone();
        let (backend, ida_version, supported_methods, supported_tools) =
            match runtime_probe.as_ref().and_then(|probe| probe.backend) {
                Some(backend) => (
                    Some(backend.to_string()),
                    runtime_probe
                        .as_ref()
                        .and_then(|probe| probe.runtime.as_ref())
                        .map(ToString::to_string),
                    crate::ida::supported_methods_for(backend)
                        .iter()
                        .map(|method| (*method).to_string())
                        .collect(),
                    crate::ida::supported_tools_for(backend),
                ),
                None => (None, None, Vec::new(), Vec::new()),
            };
        let metadata = DaemonMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            rpc_socket_path: crate::idb_store::socket_path().display().to_string(),
            mcp_socket_path: crate::idb_store::mcp_socket_path().display().to_string(),
            http_address: self.http_address.lock().await.clone(),
            backend,
            ida_version,
            supported_methods,
            supported_tools,
        };
        let inner = self.inner.lock().await;
        let mut backend_counts: HashMap<String, usize> = HashMap::new();
        let mut tenant_worker_counts: HashMap<String, usize> = HashMap::new();
        let mut tenant_pending_counts: HashMap<String, usize> = HashMap::new();
        let workers = inner
            .workers
            .iter()
            .map(|(handle, worker)| {
                let backend_name = worker.backend.to_string();
                *backend_counts.entry(backend_name.clone()).or_default() += 1;
                *tenant_worker_counts
                    .entry(worker.tenant_id.clone())
                    .or_default() += 1;
                *tenant_pending_counts
                    .entry(worker.tenant_id.clone())
                    .or_default() += worker.connection.pending_len();
                WorkerStatus {
                    handle: handle.clone(),
                    backend: backend_name,
                    tenant_id: worker.tenant_id.clone(),
                    pid: worker.child.id(),
                    open_path: worker.open_path.as_ref().map(|p| p.display().to_string()),
                    pending_requests: worker.connection.pending_len(),
                    ref_count: self
                        .references
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .ref_tokens
                        .get(handle)
                        .map(|s| s.len())
                        .unwrap_or(0),
                    idle_secs: worker.last_active.elapsed().as_secs(),
                    active: inner.active.as_deref() == Some(handle.as_str()),
                }
            })
            .collect();

        let worker_count = inner.workers.len();
        let active_handle = inner.active.clone();
        drop(inner);

        let warm_pool = self
            .warm_pool
            .lock()
            .await
            .values()
            .map(|lease| WarmLeaseStatus {
                path: lease.path.display().to_string(),
                handle: lease.handle.clone(),
                tenant_id: lease.tenant_id.clone(),
                cache_path: lease.cache_path.as_ref().map(|p| p.display().to_string()),
                pinned_secs: lease.pinned_at.elapsed().as_secs(),
                idle_secs: lease.last_hit.elapsed().as_secs(),
            })
            .collect();

        let queue = self.prewarm_queue.lock().await;
        let prewarm_queue = queue
            .queued
            .iter()
            .map(|task| PrewarmTaskStatus {
                task_id: task.task_id.clone(),
                path: task.path.clone(),
                tenant_id: task.tenant_id.clone(),
                priority: task.priority,
                keep_warm: task.keep_warm,
                state: "queued".to_string(),
                age_secs: task.enqueued_at.elapsed().as_secs(),
            })
            .collect();
        let prewarm_active = queue
            .active
            .values()
            .map(|task| PrewarmTaskStatus {
                task_id: task.task_id.clone(),
                path: task.path.clone(),
                tenant_id: task.tenant_id.clone(),
                priority: task.priority,
                keep_warm: task.keep_warm,
                state: "running".to_string(),
                age_secs: task.started_at.elapsed().as_secs(),
            })
            .collect();
        let prewarm_recent = queue.recent.clone();
        drop(queue);

        let route_queue = self.route_queue.lock().await;
        let queued_route_tasks = route_queue
            .queued
            .iter()
            .map(|task| RouteTaskStatus {
                task_id: task.task_id.clone(),
                path: task.path.clone(),
                method: task.method.clone(),
                tenant_id: task.tenant_id.clone(),
                priority: task.priority,
                state: "queued".to_string(),
                age_secs: task.enqueued_at.elapsed().as_secs(),
            })
            .collect();
        let active_route_tasks = route_queue
            .active
            .values()
            .map(|task| RouteTaskStatus {
                task_id: task.task_id.clone(),
                path: task.path.clone(),
                method: task.method.clone(),
                tenant_id: task.tenant_id.clone(),
                priority: task.priority,
                state: "running".to_string(),
                age_secs: task.started_at.elapsed().as_secs(),
            })
            .collect();
        drop(route_queue);

        let recent_tasks = self
            .task_registry
            .list_all()
            .into_iter()
            .filter(|task| task.status != TaskStatus::Running)
            .rev()
            .take(32)
            .map(|task| task_state_json(&task))
            .collect();

        let mut status = RouterStatus {
            metadata,
            worker_count,
            active_handle,
            max_workers: self.config.max_workers,
            max_workers_per_tenant: self.config.max_workers_per_tenant,
            max_pending_per_worker: self.config.max_pending_per_worker,
            max_pending_per_tenant: self.config.max_pending_per_tenant,
            max_concurrent_spawns: self.config.max_concurrent_spawns,
            max_warm_workers: self.config.max_warm_workers,
            max_queued_prewarms: self.config.max_queued_prewarms,
            max_active_prewarms: self.config.max_active_prewarms,
            max_prewarms_per_tenant: self.config.max_prewarms_per_tenant,
            max_idb_cache_bytes: self.config.max_idb_cache_bytes,
            max_response_cache_bytes: self.config.max_response_cache_bytes,
            max_queued_tasks: self.config.max_queued_tasks,
            max_active_tasks: self.config.max_active_tasks,
            max_tasks_per_tenant: self.config.max_tasks_per_tenant,
            node_id: self.config.node_id.clone(),
            runtime_probe,
            backend_counts,
            tenant_worker_counts,
            tenant_pending_counts,
            workers,
            warm_pool,
            prewarm_queue,
            prewarm_active,
            prewarm_recent,
            route_queue: queued_route_tasks,
            route_active: active_route_tasks,
            recent_tasks,
            idb_cache: cache_stats.0,
            response_cache: cache_stats.1,
            cache_statistics_error: cache_stats.2,
            cache_statistics_refreshing: self.metadata_refreshing.load(Ordering::SeqCst),
            federation_nodes: if include_federation {
                {
                    let nodes = self.federation_nodes_snapshot().await;
                    crate::blocking::run(crate::blocking::WorkClass::Metadata, move || {
                        crate::federation::probe_nodes(&nodes)
                    })
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "federation probe unavailable");
                        Vec::new()
                    })
                }
            } else {
                Vec::new()
            },
        };
        if self.uses_nexus() {
            status.runtime_probe = None;
            status.metadata.backend = Some("nexus".into());
            status.metadata.ida_version = Some("9.5".into());
            status.metadata.supported_methods = nexus_tools::METHODS
                .iter()
                .map(|name| (*name).into())
                .collect();
            status.metadata.supported_tools = status.metadata.supported_methods.clone();
            status.workers = self.nexus_tools.workers(self);
            status.worker_count = status.workers.len();
            status.active_handle = self.nexus_tools.active();
            status.backend_counts = HashMap::from([("nexus".into(), status.worker_count)]);
            status.tenant_worker_counts = HashMap::from([("default".into(), status.worker_count)]);
        }
        status
    }

    fn refresh_metadata(&self) {
        if self
            .metadata_refreshing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let router = self.clone();
        tokio::spawn(async move {
            let exe = router.inner.lock().await.exe_path.clone();
            if !router.uses_nexus() && router.cached_probe.lock().await.is_none() {
                if let Err(e) =
                    tokio::time::timeout(Duration::from_secs(5), router.probe_worker_backend(&exe))
                        .await
                {
                    warn!(error = %e, "background runtime probe expired");
                }
            }
            match crate::blocking::run(crate::blocking::WorkClass::Metadata, || {
                Ok::<_, std::io::Error>((
                    crate::idb_store::IdbStore::new().try_stats()?,
                    crate::server::response_cache::try_stats()?,
                ))
            })
            .await
            {
                Ok(Ok((idb, response))) => {
                    *router.cache_stats.lock().await = (Some(idb), Some(response), None)
                }
                Ok(Err(e)) => router.cache_stats.lock().await.2 = Some(e.to_string()),
                Err(e) => router.cache_stats.lock().await.2 = Some(e.to_string()),
            }
            router.metadata_refreshing.store(false, Ordering::SeqCst);
        });
    }

    pub async fn status_snapshot(&self) -> RouterStatus {
        self.status_snapshot_inner(false).await
    }

    pub async fn status_snapshot_federated(&self) -> RouterStatus {
        self.status_snapshot_inner(true).await
    }

    pub async fn shutdown_all(&self) {
        if self.uses_nexus() {
            self.warm_pool.lock().await.clear();
            if let Err(error) = self.nexus_tools.shutdown(self).await {
                warn!(%error,"Nexus shutdown incomplete");
            }
            return;
        }
        let handles: Vec<DbHandle> = {
            let inner = self.inner.lock().await;
            inner.workers.keys().cloned().collect()
        };
        for handle in handles {
            let _ = self.close_worker(&handle).await;
        }
        info!("All workers shut down");
    }

    pub async fn issue_ref_for_handle(&self, handle: &str) -> String {
        let mut inner = self.inner.lock().await;
        self.issue_ref_locked(&mut inner, handle)
    }

    fn issue_ref_locked(&self, inner: &mut RouterInner, handle: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let nonce = inner.req_counter;
        inner.req_counter += 1;
        let token = format!("cli-{now:x}-{nonce:x}");

        let mut references = self.references.lock().unwrap_or_else(|e| e.into_inner());
        references
            .token_to_handle
            .insert(token.clone(), handle.to_string());
        references
            .ref_tokens
            .entry(handle.to_string())
            .or_default()
            .insert(token.clone());
        token
    }

    /// Returns `(db_handle, ref_token)`. Caller MUST release `ref_token` when done.
    pub async fn ensure_worker_with_ref(
        &self,
        path: &str,
        tenant_id: Option<&str>,
    ) -> Result<(DbHandle, String), crate::error::ToolError> {
        self.ensure_worker_with_ref_idb(path, None, tenant_id).await
    }

    pub async fn ensure_worker_with_ref_idb(
        &self,
        path: &str,
        explicit_idb_output: Option<&str>,
        tenant_id: Option<&str>,
    ) -> Result<(DbHandle, String), crate::error::ToolError> {
        self.ensure_worker_prepared(
            path,
            explicit_idb_output,
            tenant_id,
            crate::preprocess::Preparation::new(Duration::from_secs(3600)),
        )
        .await
    }

    pub async fn ensure_worker_prepared(
        &self,
        path: &str,
        explicit_idb_output: Option<&str>,
        tenant_id: Option<&str>,
        preparation: crate::preprocess::Preparation,
    ) -> Result<(DbHandle, String), crate::error::ToolError> {
        use crate::error::ToolError;
        if self.uses_nexus() {
            if explicit_idb_output.is_some() || tenant_id.is_some_and(|t| t != "default") {
                return Err(ToolError::NotSupported(
                    "Nexus N4 custom outputs and tenant overrides are not implemented".into(),
                ));
            }
            return self.nexus_tools.open(self, path, preparation).await;
        }
        let tenant_id = Self::normalize_tenant(tenant_id);
        preparation.check()?;
        let resolved = resolve_open_path(path, preparation.clone()).await?;
        let open_path = resolved.open_path.as_deref().unwrap_or(path);

        // Expand `~/...` before canonicalising — `std::fs::canonicalize`
        // does not do shell-style tilde expansion, so any client that
        // passes `~/foo` would otherwise produce a literal `~/foo` key
        // and a broken worker registry.
        let expanded_path = crate::expand_path(path);
        let expanded_open = crate::expand_path(open_path);
        let (canonical, canonical_open) = preparation
            .wait(crate::blocking::run(
                crate::blocking::WorkClass::Prepare,
                move || {
                    Ok::<_, ToolError>((
                        std::fs::canonicalize(&expanded_path).map_err(|e| {
                            ToolError::InvalidPath(format!("{}: {e}", expanded_path.display()))
                        })?,
                        std::fs::canonicalize(&expanded_open).map_err(|e| {
                            ToolError::InvalidPath(format!("{}: {e}", expanded_open.display()))
                        })?,
                    ))
                },
            ))
            .await??;
        let worker_key = Self::worker_key(canonical.clone(), &tenant_id);

        let handle = {
            let mut inner = self.inner.lock().await;
            if let Some(h) = inner.path_to_handle.get(&worker_key).cloned() {
                if let Some(worker) = inner.workers.get_mut(&h) {
                    worker.last_active = Instant::now();
                }
                let token = self.issue_ref_locked(&mut inner, &h);
                Some((h, token))
            } else {
                None
            }
        };

        let (handle, mut initial_reference) = if let Some((h, token)) = handle {
            return Ok((h, token));
        } else {
            let spawned = tokio::select! {biased;
                _=preparation.cancel.cancelled()=>return Err(ToolError::Preparation {message:"cancelled before worker startup completed".into(),execution_stopped:false}),
                _=tokio::time::sleep_until(preparation.deadline.into())=>return Err(ToolError::Preparation {message:"total deadline expired during worker startup".into(),execution_stopped:false}),
                result=self.spawn_worker(path,Some(&tenant_id))=>result,
            };
            let (h, initial_token) =
                spawned.map_err(|e| ToolError::IdaError(format!("spawn_worker failed: {e}")))?;

            let mut initial_reference = initial_token.map(|token| self.scoped_ref(token));

            let effective_idb_output = explicit_idb_output
                .map(String::from)
                .or(resolved.idb_output_path);
            let open_params = serde_json::json!({
                "path": canonical_open.display().to_string(),
                "idb_output_path": effective_idb_output,
                "auto_analyse": true,
                "timeout_secs": 3600,
            });
            let opened = async {
                self.route_request_prepared(Some(&h), "open", open_params, preparation.clone())
                    .await?;
                if effective_idb_output.is_some() {
                    let binary = canonical.clone();
                    let recorded = preparation
                        .wait(crate::blocking::run(
                            crate::blocking::WorkClass::Prepare,
                            move || {
                                crate::idb_store::IdbStore::new()
                                    .try_record(&binary)
                            },
                        ))
                        .await;
                    match recorded {
                        Ok(recorded) => {
                            preparation.check()?;
                            if let Err(error) = recorded {
                                warn!(binary = %canonical.display(), index = %crate::idb_store::idb_root().join("index.json").display(), %error, "optional post-open index record failed");
                            }
                        }
                        Err(ToolError::Busy) => {
                            preparation.check()?;
                            warn!(handle = %h, "optional post-open index record skipped: local capacity full");
                        }
                        Err(error) => return Err(error),
                    }
                }
                let binary = canonical.clone();
                let sbpf = preparation
                    .wait(crate::blocking::run(
                        crate::blocking::WorkClass::Prepare,
                        move || is_sbpf_elf(&binary),
                    ))
                    .await;
                let sbpf = match sbpf {
                    Ok(value) => {
                        preparation.check()?;
                        value
                    }
                    Err(ToolError::Busy) => {
                        preparation.check()?;
                        warn!(handle = %h, "optional post-open sBPF detection skipped: local capacity full");
                        false
                    }
                    Err(error) => return Err(error),
                };
                if sbpf {
                    self.detect_and_rename_sbpf_entry(&h, preparation.clone())
                        .await?;
                }
                Ok::<_, ToolError>(())
            }
            .await;
            if let Err(error) = opened {
                warn!(handle = %h, error = %error, "open or required follow-up failed, releasing opener reference");
                if let Some(reference) = initial_reference.as_mut() {
                    reference.release();
                }
                if let Err(cleanup) = preparation.scope(self.close_worker_inner(&h, true)).await {
                    warn!(handle = %h, error = %cleanup, "failed-open worker cleanup failed");
                }
                return Err(error);
            }

            (h, initial_reference)
        };

        let ref_token = if let Some(token) = initial_reference
            .as_mut()
            .and_then(|reference| reference.token.take())
        {
            token
        } else {
            self.issue_ref_for_handle(&handle).await
        };

        Ok((handle, ref_token))
    }

    async fn detect_and_rename_sbpf_entry(
        &self,
        handle: &str,
        preparation: crate::preprocess::Preparation,
    ) -> Result<(), crate::error::ToolError> {
        async fn query(
            router: &RouterState,
            handle: &str,
            method: &str,
            params: serde_json::Value,
            preparation: crate::preprocess::Preparation,
        ) -> Result<Option<serde_json::Value>, crate::error::ToolError> {
            let result = router
                .route_request_prepared(Some(handle), method, params, preparation.clone())
                .await;
            // A response can win the waiter race with cancellation. It must not
            // authorize another optional native request after the common deadline.
            match result {
                Ok(value) => {
                    preparation.check()?;
                    Ok(Some(value))
                }
                Err(error) if optional_sbpf_failure(&error) => {
                    preparation.check()?;
                    warn!(%handle, %method, %error, "optional sBPF post-open query failed");
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        }
        let Some(entrypoint) = query(
            self,
            handle,
            "get_function_by_name",
            serde_json::json!({"name":"entrypoint"}),
            preparation.clone(),
        )
        .await?
        else {
            return Ok(());
        };
        let ep_addr: Option<u64> = entrypoint
            .get("address")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());

        let Some(ep_addr) = ep_addr else {
            return Ok(());
        };
        let ep_hex = format!("0x{:x}", ep_addr);

        let Some(cg_val) = query(
            self,
            handle,
            "build_callgraph",
            serde_json::json!({"roots": ep_hex, "max_depth": 2, "max_nodes": 256}),
            preparation.clone(),
        )
        .await?
        else {
            return Ok(());
        };

        let edges = match cg_val.get("edges").and_then(|v| v.as_array()) {
            Some(e) => e.clone(),
            None => return Ok(()),
        };
        let nodes = cg_val
            .get("nodes")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let addr_to_name: std::collections::HashMap<&str, &str> = nodes
            .iter()
            .filter_map(|n| Some((n.get("address")?.as_str()?, n.get("name")?.as_str()?)))
            .collect();

        let is_syscall = |addr: &str| {
            addr_to_name
                .get(addr)
                .map(|name| name.starts_with("_sol_") || *name == "_abort")
                .unwrap_or(false)
        };

        let direct: Vec<&str> = edges
            .iter()
            .filter_map(|e| {
                if e.get("from")?.as_str()? == ep_hex {
                    e.get("to")?.as_str()
                } else {
                    None
                }
            })
            .filter(|addr| !is_syscall(addr))
            .collect();
        if direct.len() != 2 {
            return Ok(());
        }

        let c0 = edges
            .iter()
            .filter(|e| e.get("from").and_then(|v| v.as_str()) == Some(direct[0]))
            .count();
        let c1 = edges
            .iter()
            .filter(|e| e.get("from").and_then(|v| v.as_str()) == Some(direct[1]))
            .count();
        if c0 == c1 {
            return Ok(());
        }
        let pi_hex = if c0 > c1 { direct[0] } else { direct[1] };

        if query(
            self,
            handle,
            "rename_symbol",
            serde_json::json!({"address": pi_hex, "new_name": "process_instruction"}),
            preparation,
        )
        .await?
        .is_none()
        {
            return Ok(());
        }

        info!(handle = %handle, pi = %pi_hex, "sBPF: renamed process_instruction");
        Ok(())
    }

    pub async fn close_by_path(
        &self,
        path: &std::path::Path,
        tenant_id: Option<&str>,
    ) -> Result<(), crate::error::ToolError> {
        if self.uses_nexus() {
            return self.nexus_tools.close_path(self, path).await;
        }
        let tenant_id = Self::normalize_tenant(tenant_id);
        let handle = {
            let inner = self.inner.lock().await;
            inner
                .path_to_handle
                .get(&Self::worker_key(path.to_path_buf(), &tenant_id))
                .cloned()
        };
        if let Some(h) = handle {
            let _ = self
                .route_request(Some(&h), "close", serde_json::json!({}))
                .await;
            let _ = self
                .route_request(Some(&h), "shutdown", serde_json::json!({}))
                .await;
            self.close_worker(&h).await
        } else {
            Err(crate::error::ToolError::NoDatabaseOpen)
        }
    }

    pub async fn prewarm_path(
        &self,
        path: &str,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        self.prewarm_path_with_options(path, false, "default").await
    }

    pub async fn prewarm_path_with_options(
        &self,
        path: &str,
        keep_warm: bool,
        tenant_id: &str,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        use crate::error::ToolError;
        let preparation = crate::preprocess::current()
            .unwrap_or_else(|| crate::preprocess::Preparation::new(Duration::from_secs(3600)));
        if self.uses_nexus() {
            return self
                .prewarm_nexus(path, keep_warm, tenant_id, preparation)
                .await;
        }
        preparation.check()?;

        let expanded = crate::expand_path(path);
        if !expanded.exists() {
            return Err(ToolError::InvalidPath(format!(
                "File not found: {}",
                expanded.display()
            )));
        }

        let canonical = preparation
            .wait(crate::blocking::run(
                crate::blocking::WorkClass::Prepare,
                move || std::fs::canonicalize(&expanded),
            ))
            .await?
            .map_err(|e| ToolError::InvalidPath(e.to_string()))?;
        let tenant_id = Self::normalize_tenant(Some(tenant_id));
        let already_open = {
            let inner = self.inner.lock().await;
            inner
                .path_to_handle
                .contains_key(&Self::worker_key(canonical.clone(), &tenant_id))
        };

        let before = canonical.clone();
        let cached_before = preparation
            .wait(crate::blocking::run(
                crate::blocking::WorkClass::Prepare,
                move || crate::idb_store::IdbStore::new().prepared_paths(&before),
            ))
            .await?
            .map_err(|e| ToolError::IdaError(e.to_string()))?
            .0
            .map(|p| p.display().to_string());

        let (handle, ref_token) = self
            .ensure_worker_prepared(path, None, Some(&tenant_id), preparation.clone())
            .await?;
        let mut reference = self.scoped_ref(ref_token);
        let backend = {
            let inner = self.inner.lock().await;
            inner
                .workers
                .get(&handle)
                .map(|worker| worker.backend.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        };

        let database_info = match self
            .route_request_prepared(
                Some(&handle),
                "get_database_info",
                serde_json::json!({}),
                preparation.clone(),
            )
            .await
        {
            Ok(value) => Some(value),
            Err(error) if optional_sbpf_failure(&error) => {
                preparation.check()?;
                warn!(path=%canonical.display(), %error, "optional prewarm database info unavailable");
                None
            }
            Err(error) => return Err(error),
        };
        preparation.check()?;
        let after = canonical.clone();
        let observed = preparation
            .wait(crate::blocking::run(
                crate::blocking::WorkClass::Prepare,
                move || crate::idb_store::IdbStore::new().prepared_paths(&after),
            ))
            .await;
        let cached_after = match observed {
            Ok(Ok((cache, _))) => {
                preparation.check()?;
                cache.map(|p| p.display().to_string())
            }
            Ok(Err(error)) => {
                preparation.check()?;
                warn!(path=%canonical.display(), %error, "optional prewarm cache observation failed");
                None
            }
            Err(ToolError::Busy) => {
                preparation.check()?;
                warn!(path=%canonical.display(), "optional prewarm cache observation skipped: local capacity full");
                None
            }
            Err(error) => return Err(error),
        };

        let mut closed_worker = false;
        let mut kept_warm = false;
        if keep_warm {
            preparation
                .wait(self.install_warm_lease(
                    canonical.clone(),
                    handle.clone(),
                    &mut reference,
                    tenant_id.to_string(),
                    cached_after.as_ref().map(PathBuf::from),
                ))
                .await?;
            kept_warm = true;
        } else {
            reference.release();
            if !already_open {
                // Recheck refs and detach this exact handle under inner. A later
                // opener cannot be closed through a stale path lookup.
                closed_worker = preparation
                    .scope(self.close_worker_inner(&handle, true))
                    .await?;
            }
        }

        Ok(serde_json::json!({
            "path": canonical.display().to_string(),
            "backend": backend,
            "cached_before": cached_before.is_some(),
            "cached_after": cached_after.is_some(),
            "cache_path": cached_after,
            "database_info": database_info,
            "already_open": already_open,
            "kept_warm": kept_warm,
            "worker_closed_after_prewarm": closed_worker,
        }))
    }

    async fn prewarm_nexus(
        &self,
        path: &str,
        keep_warm: bool,
        tenant: &str,
        preparation: crate::preprocess::Preparation,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        use crate::error::ToolError;
        if keep_warm && self.config.max_warm_workers == 0 {
            return Err(ToolError::Busy);
        }
        let expanded = crate::expand_path(path);
        let canonical = preparation
            .wait(crate::blocking::run(
                crate::blocking::WorkClass::Prepare,
                move || {
                    expanded
                        .canonicalize()
                        .map_err(|e| ToolError::InvalidPath(e.to_string()))
                },
            ))
            .await??;
        let already_open = self
            .nexus_tools
            .workers(self)
            .iter()
            .any(|w| w.open_path.as_deref() == canonical.to_str());
        let (handle, token) = self
            .ensure_worker_prepared(path, None, Some(tenant), preparation.clone())
            .await?;
        let cached_before = self.nexus_tools.cache_hit(&handle)?;
        let mut reference = nexus_tools::ReferenceGuard::new(self.clone(), token.clone());
        let details = self
            .nexus_open_details(&handle, preparation.clone())
            .await?;
        let info = self
            .route_request_prepared(
                Some(&handle),
                "get_database_info",
                serde_json::json!({}),
                preparation.clone(),
            )
            .await?;
        let idb = details["path"]
            .as_str()
            .ok_or_else(|| ToolError::IdaError("Nexus open missing cache path".into()))?
            .to_string();
        if keep_warm {
            loop {
                preparation.check()?;
                let mut pool = self.warm_pool.lock().await;
                if pool.contains_key(&canonical) || pool.len() < self.config.max_warm_workers {
                    let previous = pool.insert(
                        canonical.clone(),
                        WarmLease {
                            handle,
                            token: token.clone(),
                            path: canonical.clone(),
                            cache_path: Some(PathBuf::from(&idb)),
                            tenant_id: "default".into(),
                            pinned_at: Instant::now(),
                            last_hit: Instant::now(),
                        },
                    );
                    reference.transfer();
                    drop(pool);
                    if let Some(previous) = previous {
                        self.nexus_close_token(&previous.token).await?;
                    }
                    break;
                }
                let oldest = pool
                    .values()
                    .min_by_key(|lease| lease.last_hit)
                    .map(|lease| lease.path.clone());
                drop(pool);
                if let Some(oldest) = oldest {
                    self.release_warm_lease(&oldest).await?;
                }
            }
        } else {
            self.nexus_close_token(&token).await?;
            reference.transfer();
        }
        Ok(
            serde_json::json!({"path":canonical.display().to_string(),"backend":"nexus","cached_before":cached_before,"cached_after":true,"cache_path":idb,"database_info":info,"already_open":already_open,"kept_warm":keep_warm,"worker_closed_after_prewarm":!keep_warm && !already_open}),
        )
    }

    async fn install_warm_lease(
        &self,
        canonical_path: PathBuf,
        handle: DbHandle,
        reference: &mut ScopedRefToken,
        tenant_id: String,
        cache_path: Option<PathBuf>,
    ) -> Result<(), crate::error::ToolError> {
        loop {
            let mut pool = self.warm_pool.lock().await;
            if let Some(preparation) = crate::preprocess::current() {
                preparation.check()?;
            }
            if pool.contains_key(&canonical_path) || pool.len() < self.config.max_warm_workers {
                let token = reference.token.take().ok_or_else(|| {
                    crate::error::ToolError::IdaError(
                        "prewarm reference already transferred".into(),
                    )
                })?;
                let previous = pool.insert(
                    canonical_path.clone(),
                    WarmLease {
                        handle,
                        token,
                        path: canonical_path,
                        cache_path,
                        tenant_id,
                        pinned_at: Instant::now(),
                        last_hit: Instant::now(),
                    },
                );
                if let Some(previous) = previous {
                    // Replacing a lease transfers exactly one new token. The
                    // old worker remains available to any other references/GC.
                    self.references
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .release(&previous.token);
                }
                return Ok(());
            }
            let candidate = pool
                .iter()
                .min_by_key(|(_, lease)| lease.last_hit)
                .map(|(path, _)| path.clone());
            drop(pool);
            if let Some(path) = candidate {
                self.release_warm_lease(&path).await?;
            }
        }
    }

    async fn release_warm_lease(&self, path: &PathBuf) -> Result<(), crate::error::ToolError> {
        let lease = self.warm_pool.lock().await.remove(path);
        if let Some(lease) = lease {
            if let Some((handle, remaining)) = self.release_ref_token(&lease.token).await {
                if remaining == 0 {
                    self.close_worker_inner(&handle, true).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn enqueue_prewarm(
        &self,
        path: &str,
        priority: u8,
        keep_warm: bool,
        tenant_id: Option<String>,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        use crate::error::ToolError;

        let tenant_id = tenant_id.unwrap_or_else(|| "default".to_string());
        let mut queue = self.prewarm_queue.lock().await;
        if queue.queued.len() >= self.config.max_queued_prewarms {
            return Err(ToolError::Busy);
        }
        let task_id = format!("prewarm-{}", queue.next_task_id);
        queue.next_task_id += 1;
        queue.queued.push(QueuedPrewarmTask {
            task_id: task_id.clone(),
            path: path.to_string(),
            tenant_id: tenant_id.clone(),
            priority,
            keep_warm,
            enqueued_at: Instant::now(),
        });
        queue.queued.sort_by(|lhs, rhs| {
            rhs.priority
                .cmp(&lhs.priority)
                .then_with(|| lhs.enqueued_at.cmp(&rhs.enqueued_at))
        });
        let queued = queue.queued.len();
        let result = serde_json::json!({
            "task_id": task_id,
            "status": "queued",
            "path": path,
            "tenant_id": tenant_id,
            "priority": priority,
            "keep_warm": keep_warm,
            "queued": queued,
        });
        drop(queue);
        self.drive_prewarm_queue().await;
        Ok(result)
    }

    pub async fn enqueue_route_task(
        &self,
        path: &str,
        method: &str,
        params: serde_json::Value,
        tenant_id: Option<String>,
        priority: u8,
        dedupe_key: Option<String>,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        use crate::error::ToolError;
        if self.uses_nexus() {
            nexus_tools::Tools::require(crate::tool_registry::primary_name_for(method))?;
        }

        let tenant_id = Self::normalize_tenant(tenant_id.as_deref());
        let mut queue = self.route_queue.lock().await;
        if queue.queued.len() >= self.config.max_queued_tasks {
            return Err(ToolError::Busy);
        }

        let active_for_tenant = queue.tenant_active.get(&tenant_id).copied().unwrap_or(0);
        if active_for_tenant >= self.config.max_tasks_per_tenant {
            return Err(ToolError::Busy);
        }

        let task_id = match self.task_registry.create_with_key(
            "job",
            dedupe_key.as_deref(),
            &format!("Queued {method}"),
        ) {
            Ok(id) => id,
            Err(existing) => {
                let original = self
                    .task_registry
                    .get(&existing)
                    .ok_or(ToolError::WorkerClosed)?;
                let meta = original.meta.unwrap_or(serde_json::Value::Null);
                return Ok(
                    serde_json::json!({"task_id":existing,"status":"queued","path":meta["path"],"method":meta["method"],"tenant_id":meta["tenant_id"],"priority":meta["priority"]}),
                );
            }
        };
        self.task_registry.merge_meta(
            &task_id,
            serde_json::json!({
                "tenant_id": tenant_id,
                "path": path,
                "method": method,
                "priority": priority,
                "remote": false,
            }),
        );

        if self.task_registry.get(&task_id).is_some() && !queue.active.contains_key(&task_id) {
            queue.queued.push(QueuedRouteTask {
                task_id: task_id.clone(),
                path: path.to_string(),
                method: method.to_string(),
                preparation: {
                    let maximum = if method == "open" { 3600 } else { 600 };
                    let seconds = params
                        .get("timeout_secs")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(120)
                        .min(maximum);
                    let preparation =
                        crate::preprocess::Preparation::new(Duration::from_secs(seconds));
                    self.task_registry
                        .set_cancellation(&task_id, preparation.cancel.clone());
                    preparation
                },
                params,
                tenant_id: tenant_id.clone(),
                priority,
                enqueued_at: Instant::now(),
            });
            queue.queued.sort_by(|lhs, rhs| {
                rhs.priority
                    .cmp(&lhs.priority)
                    .then_with(|| lhs.enqueued_at.cmp(&rhs.enqueued_at))
            });
        }

        let result = serde_json::json!({
            "task_id": task_id,
            "status": "queued",
            "path": path,
            "method": method,
            "tenant_id": tenant_id,
            "priority": priority,
        });
        drop(queue);
        self.drive_route_queue().await;
        Ok(result)
    }

    pub async fn enqueue_federated_task(
        &self,
        path: &str,
        method: &str,
        params: serde_json::Value,
        tenant_id: Option<String>,
        priority: u8,
        dedupe_key: Option<String>,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        use crate::error::ToolError;
        if self.uses_nexus() {
            nexus_tools::Tools::require(crate::tool_registry::primary_name_for(method))?;
        }

        let tenant_id = Self::normalize_tenant(tenant_id.as_deref());
        let nodes = self.federation_nodes_snapshot().await;
        let candidates =
            crate::federation::choose_ready_nodes(&nodes, Some(method), Some(&tenant_id));
        if candidates.is_empty() {
            return Err(ToolError::IdaError(
                "no ready federation node available".to_string(),
            ));
        }

        let task_id = match self.task_registry.create_with_key(
            "federated",
            dedupe_key.as_deref(),
            &format!("Dispatching {method} to federation"),
        ) {
            Ok(id) => id,
            Err(existing) => existing,
        };
        self.task_registry.merge_meta(
            &task_id,
            serde_json::json!({
                "tenant_id": tenant_id,
                "path": path,
                "method": method,
                "priority": priority,
                "remote": true,
            }),
        );

        let mut last_error = None;
        let mut chosen = None;
        let mut remote_task_id = None;
        let mut remote_url = None;
        for node in candidates {
            let payload = serde_json::json!({
                "path": path,
                "method": method,
                "priority": priority,
                "tenant_id": tenant_id,
                "dedupe_key": dedupe_key,
                "task_params": params,
                "federate": false,
            });

            match crate::federation::submit_enqueue(&node, &payload) {
                Ok(remote) => {
                    let task = remote
                        .response
                        .get("task_id")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned);
                    if let Some(task) = task {
                        chosen = Some(node.clone());
                        remote_task_id = Some(task);
                        remote_url = Some(remote.url.clone());
                        break;
                    } else {
                        last_error =
                            Some(format!("remote node {} did not return task_id", node.name));
                    }
                }
                Err(err) => {
                    last_error = Some(format!("{}: {err}", node.name));
                }
            }
        }

        let Some(node) = chosen else {
            return Err(ToolError::IdaError(format!(
                "federation enqueue failed across all candidate nodes: {}",
                last_error.unwrap_or_else(|| "unknown error".to_string())
            )));
        };

        if let Some(state) = self.task_registry.get(&task_id) {
            if state.status == TaskStatus::Running {
                let remote_task_id = remote_task_id.expect("remote task id set");
                self.task_registry.update_message(
                    &task_id,
                    &format!("Queued remotely on {} as {}", node.name, remote_task_id),
                );
                self.task_registry.merge_meta(
                    &task_id,
                    serde_json::json!({
                        "node": node.name,
                        "url": remote_url.clone().unwrap_or_else(|| node.url.clone()),
                        "remote_task_id": remote_task_id,
                    }),
                );

                let registry = self.task_registry.clone();
                let task_id_for_poll = task_id.clone();
                let remote_node = node.clone();
                let remote_url = remote_url.unwrap_or_else(|| remote_node.url.clone());
                let poll_handle = tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(2));
                    loop {
                        interval.tick().await;
                        match crate::federation::fetch_remote_task(&remote_node, &remote_task_id) {
                            Ok(remote_status) => {
                                let payload = remote_status.payload;
                                let status = payload
                                    .get("status")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                let message = payload
                                    .get("message")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(status);
                                registry.update_message(
                                    &task_id_for_poll,
                                    &format!("remote {}: {}", remote_node.name, message),
                                );
                                match status {
                                    "completed" => {
                                        registry.complete(
                                            &task_id_for_poll,
                                            serde_json::json!({
                                                "remote": true,
                                                "node": remote_node.name,
                                                "url": remote_url,
                                                "remote_task_id": remote_task_id,
                                                "payload": payload,
                                            }),
                                        );
                                        break;
                                    }
                                    "failed" => {
                                        registry.fail(
                                            &task_id_for_poll,
                                            &format!(
                                                "remote {} failed: {}",
                                                remote_node.name, message
                                            ),
                                        );
                                        break;
                                    }
                                    "cancelled" => {
                                        registry.fail(
                                            &task_id_for_poll,
                                            &format!("remote {} cancelled", remote_node.name),
                                        );
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            Err(err) => {
                                registry.update_message(
                                    &task_id_for_poll,
                                    &format!("remote poll error: {err}"),
                                );
                            }
                        }
                    }
                });
                self.task_registry.set_handle(&task_id, poll_handle);
            }
        }

        Ok(serde_json::json!({
            "task_id": task_id,
            "status": "queued",
            "path": path,
            "method": method,
            "tenant_id": tenant_id,
            "priority": priority,
            "remote": true,
            "node": node.name,
            "url": node.url,
        }))
    }

    pub fn task_state(&self, task_id: &str) -> Option<TaskState> {
        self.task_registry.get(task_id)
    }

    pub fn list_task_states(&self) -> Vec<TaskState> {
        self.task_registry.list_all()
    }

    pub async fn cancel_task(&self, task_id: &str) -> bool {
        let queued = {
            let mut queue = self.route_queue.lock().await;
            let mut removed = false;
            queue.queued.retain(|task| {
                if task.task_id != task_id {
                    return true;
                }
                task.preparation.cancel.cancel();
                removed = true;
                false
            });
            removed
        };
        if queued {
            self.task_registry.cancellation_confirmed(task_id);
            return true;
        }
        self.task_registry.cancel(task_id)
    }

    async fn drive_prewarm_queue(&self) {
        loop {
            let task = {
                let mut queue = self.prewarm_queue.lock().await;
                if queue.active.len() >= self.config.max_active_prewarms {
                    None
                } else {
                    let pos = queue.queued.iter().position(|task| {
                        queue
                            .tenant_active
                            .get(&task.tenant_id)
                            .copied()
                            .unwrap_or(0)
                            < self.config.max_prewarms_per_tenant
                    });
                    pos.map(|idx| {
                        let task = queue.queued.remove(idx);
                        queue
                            .tenant_active
                            .entry(task.tenant_id.clone())
                            .and_modify(|count| *count += 1)
                            .or_insert(1);
                        queue.active.insert(
                            task.task_id.clone(),
                            ActivePrewarmTask {
                                task_id: task.task_id.clone(),
                                path: task.path.clone(),
                                tenant_id: task.tenant_id.clone(),
                                priority: task.priority,
                                keep_warm: task.keep_warm,
                                started_at: Instant::now(),
                            },
                        );
                        task
                    })
                }
            };

            let Some(task) = task else { break };
            let state = self.clone();
            tokio::spawn(async move {
                let result = state
                    .prewarm_path_with_options(&task.path, task.keep_warm, &task.tenant_id)
                    .await;
                let mut queue = state.prewarm_queue.lock().await;
                queue.active.remove(&task.task_id);
                if let Some(count) = queue.tenant_active.get_mut(&task.tenant_id) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        queue.tenant_active.remove(&task.tenant_id);
                    }
                }
                let summary = match result {
                    Ok(value) => serde_json::json!({
                        "task_id": task.task_id,
                        "path": task.path,
                        "tenant_id": task.tenant_id,
                        "status": "completed",
                        "result": value,
                    }),
                    Err(err) => serde_json::json!({
                        "task_id": task.task_id,
                        "path": task.path,
                        "tenant_id": task.tenant_id,
                        "status": "failed",
                        "error": err.to_string(),
                    }),
                };
                queue.recent.push(summary);
                if queue.recent.len() > 64 {
                    let drain = queue.recent.len() - 64;
                    queue.recent.drain(0..drain);
                }
            });
        }
    }

    async fn drive_route_queue(&self) {
        loop {
            let task = {
                let mut queue = self.route_queue.lock().await;
                if queue.active.len() >= self.config.max_active_tasks {
                    None
                } else {
                    let pos = queue.queued.iter().position(|task| {
                        queue
                            .tenant_active
                            .get(&task.tenant_id)
                            .copied()
                            .unwrap_or(0)
                            < self.config.max_tasks_per_tenant
                    });
                    pos.map(|idx| {
                        let task = queue.queued.remove(idx);
                        queue
                            .tenant_active
                            .entry(task.tenant_id.clone())
                            .and_modify(|count| *count += 1)
                            .or_insert(1);
                        queue.active.insert(
                            task.task_id.clone(),
                            ActiveRouteTask {
                                task_id: task.task_id.clone(),
                                path: task.path.clone(),
                                method: task.method.clone(),
                                tenant_id: task.tenant_id.clone(),
                                priority: task.priority,
                                started_at: Instant::now(),
                            },
                        );
                        task
                    })
                }
            };

            let Some(task) = task else { break };
            self.task_registry
                .update_message(&task.task_id, &format!("Running {}", task.method));

            let state = self.clone();
            tokio::spawn(async move {
                let work = async {
                    let (handle, token) = state
                        .ensure_worker_prepared(
                            &task.path,
                            None,
                            Some(&task.tenant_id),
                            task.preparation.clone(),
                        )
                        .await?;
                    let _reference = state.scoped_ref(token);
                    state
                        .route_request_prepared(
                            Some(&handle),
                            &task.method,
                            task.params.clone(),
                            task.preparation.clone(),
                        )
                        .await
                };
                let result = if state.uses_nexus() {
                    match crate::nexus::TaskId::new(task.task_id.clone()) {
                        Ok(task_id) => nexus_tools::CURRENT_TASK_ID.scope(task_id, work).await,
                        Err(error) => Err(error.into()),
                    }
                } else {
                    work.await
                };

                let mut queue = state.route_queue.lock().await;
                queue.active.remove(&task.task_id);
                if let Some(count) = queue.tenant_active.get_mut(&task.tenant_id) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        queue.tenant_active.remove(&task.tenant_id);
                    }
                }
                drop(queue);

                match result {
                    Ok(value) => {
                        if task.preparation.cancel.is_cancelled() {
                            state.task_registry.cancellation_confirmed(&task.task_id);
                        } else {
                            state.task_registry.complete(&task.task_id, value);
                        }
                    }
                    Err(err) => {
                        if task.preparation.cancel.is_cancelled()
                            && matches!(
                                err,
                                crate::error::ToolError::Preparation {
                                    execution_stopped: true,
                                    ..
                                }
                            )
                        {
                            state.task_registry.cancellation_confirmed(&task.task_id);
                        } else {
                            state.task_registry.fail(&task.task_id, &err.to_string());
                        }
                    }
                }
            });
        }
    }

    pub async fn shutdown_nexus(&self) -> Result<(), crate::error::ToolError> {
        self.nexus_tools.shutdown(self).await
    }
    pub async fn refresh_nexus_cache(
        &self,
        path: &str,
        preparation: crate::preprocess::Preparation,
    ) -> Result<(DbHandle, String), crate::error::ToolError> {
        self.nexus_tools
            .open_refresh(self, path, preparation, true)
            .await
    }

    async fn prune_caches(&self) {
        let warm_pool = self.warm_pool.lock().await;
        let pinned_groups: HashSet<String> = warm_pool
            .values()
            .filter_map(|lease| lease.cache_path.as_ref())
            .map(|path| path.with_extension("").display().to_string())
            .collect();
        drop(warm_pool);

        let idb_limit = self.config.max_idb_cache_bytes;
        let response_limit = self.config.max_response_cache_bytes;
        if let Err(e) = crate::blocking::run(crate::blocking::WorkClass::Metadata, move || {
            let _ = crate::idb_store::IdbStore::new().evict_to_limit(idb_limit, &pinned_groups);
            let _ = crate::server::response_cache::prune_to_limit(response_limit);
        })
        .await
        {
            warn!(error = %e, "cache maintenance unavailable");
        }
    }

    /// `auto_exit_grace`: `Some(duration)` → exit when no workers remain for that
    /// long. `None` → disable auto-exit (stdio MCP mode).
    pub fn start_watchdog(
        &self,
        idle_timeout: Duration,
        check_interval: Duration,
        auto_exit_grace: Option<Duration>,
    ) {
        if self
            .maintenance_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let state = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(check_interval);
            let mut empty_since: Option<tokio::time::Instant> = None;

            loop {
                ticker.tick().await;
                let expired: Vec<DbHandle> = {
                    let inner = state.inner.lock().await;
                    inner
                        .workers
                        .iter()
                        .filter(|(h, w)| {
                            let ref_count = state
                                .references
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .ref_tokens
                                .get(*h)
                                .map(|set| set.len())
                                .unwrap_or(0);
                            ref_count == 0
                                && w.connection.pending_len() == 0
                                && w.last_active.elapsed() > idle_timeout
                        })
                        .map(|(h, _)| h.clone())
                        .collect()
                };
                for handle in expired {
                    warn!(
                        "GC: closing idle worker {} (ref_count=0, idle > {}s)",
                        handle,
                        idle_timeout.as_secs()
                    );
                    let _ = state.close_worker(&handle).await;
                }

                state.drive_prewarm_queue().await;
                state.drive_route_queue().await;
                state.prune_caches().await;

                if let Some(grace) = auto_exit_grace {
                    let worker_count = state.worker_count().await;
                    if worker_count == 0 {
                        if let Some(since) = empty_since {
                            if since.elapsed() >= grace {
                                info!(
                                    "No workers remaining for {}s, server auto-exiting",
                                    grace.as_secs()
                                );
                                // Tidy up pid / unix socket / discovery file
                                // so the next client does not hit a stale
                                // `~/.ida/server.sock` or `/tmp/ida-cli.socket`.
                                let _ = std::fs::remove_file(crate::idb_store::pid_path());
                                crate::server::socket_listener::cleanup_socket_files(
                                    &crate::idb_store::socket_path(),
                                );
                                std::process::exit(0);
                            }
                        } else {
                            empty_since = Some(tokio::time::Instant::now());
                        }
                    } else {
                        empty_since = None;
                    }
                }
            }
        });
    }
}

impl Default for RouterState {
    fn default() -> Self {
        Self::new().expect("Failed to create RouterState")
    }
}

pub fn task_state_json(state: &TaskState) -> serde_json::Value {
    let status = match state.status {
        TaskStatus::Running => "running",
        TaskStatus::Completed => "completed",
        TaskStatus::Failed => "failed",
        TaskStatus::Cancelled => "cancelled",
    };
    let mut value = serde_json::json!({
        "task_id": state.id,
        "status": status,
        "message": state.message,
        "created_at": state.created_at_iso,
        "updated_at": state.updated_at_iso,
        "meta": state.meta,
        "result": state.result,
    });

    if let Some(result) = &state.result {
        if let Some(obj) = value.as_object_mut() {
            if let Some(remote) = result.get("remote").and_then(|v| v.as_bool()) {
                obj.insert("remote".to_string(), serde_json::json!(remote));
            }
            if let Some(node) = result.get("node").and_then(|v| v.as_str()) {
                obj.insert("node".to_string(), serde_json::json!(node));
            }
            if let Some(task_id) = result.get("remote_task_id").and_then(|v| v.as_str()) {
                obj.insert("remote_task_id".to_string(), serde_json::json!(task_id));
            }
        }
    }

    value
}

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EM_BPF: u16 = 247;
const EM_SBF: u16 = 263;

// Legacy RPC carries worker business errors and transport failures as strings.
// Keep this compatibility boundary centralized until N9 removes the old wire.
fn optional_sbpf_failure(error: &crate::error::ToolError) -> bool {
    match error {
        crate::error::ToolError::Busy => true, // local admission proved zero send
        crate::error::ToolError::IdaError(message) => {
            !message.starts_with("NotSent")
                && !message.starts_with("UnknownOutcome")
                && !message.contains("execution_stopped=false")
                && !message.contains("never replay")
                && message != "Worker channel closed"
        }
        _ => false,
    }
}

pub fn is_sbpf_elf(path: &std::path::Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut header = [0u8; 20];
    if f.read_exact(&mut header).is_err() {
        return false;
    }
    if header[..4] != ELF_MAGIC {
        return false;
    }
    let machine = u16::from_le_bytes([header[18], header[19]]);
    machine == EM_BPF || machine == EM_SBF
}

pub(crate) struct ResolvedPath {
    /// Path to pass to IDA for opening (may be .i64, .dylib, or the original binary)
    pub(crate) open_path: Option<String>,
    /// Where the .i64 should be saved (centralized path, only when not already cached)
    pub(crate) idb_output_path: Option<String>,
}

pub(crate) async fn resolve_open_path(
    path: &str,
    preparation: crate::preprocess::Preparation,
) -> Result<ResolvedPath, crate::error::ToolError> {
    let input = crate::expand_path(path);
    let original = input.clone();
    let prepared = preparation
        .wait(crate::blocking::run(
            crate::blocking::WorkClass::Prepare,
            move || {
                let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "i64" || ext == "idb" {
                    return Ok((
                        ResolvedPath {
                            open_path: None,
                            idb_output_path: None,
                        },
                        None,
                    ));
                }
                let store = crate::idb_store::IdbStore::new();
                let (cached, destination) = store.prepared_paths(&input).map_err(|e| {
                    crate::error::ToolError::IdaError(format!(
                        "prepare input {}: {e}",
                        input.display()
                    ))
                })?;
                if let Some(cached) = cached {
                    return Ok((
                        ResolvedPath {
                            open_path: Some(cached.display().to_string()),
                            idb_output_path: None,
                        },
                        None,
                    ));
                }
                if is_sbpf_elf(&input) {
                    return Ok((
                        ResolvedPath {
                            open_path: Some(destination.display().to_string()),
                            idb_output_path: None,
                        },
                        Some(destination),
                    ));
                }
                let i64 = input.with_extension("i64");
                let open_path = if i64.exists() {
                    Some(i64.display().to_string())
                } else {
                    None
                };
                let idb_output_path = if open_path.is_some() || input.with_extension("id0").exists()
                {
                    None
                } else {
                    Some(destination.display().to_string())
                };
                Ok::<_, crate::error::ToolError>((
                    ResolvedPath {
                        open_path,
                        idb_output_path,
                    },
                    None,
                ))
            },
        ))
        .await??;
    preparation.check()?;
    if let Some(destination) = prepared.1 {
        crate::sbpf::run_sbx_aot_i64(&original, &destination, preparation.clone()).await?;
    }
    preparation.check()?;
    Ok(prepared.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn queued_dedupe_cancel_removes_all_work_without_overwriting_original() {
        let router = RouterState::new().unwrap();
        {
            let mut queue = router.route_queue.lock().await;
            for i in 0..router.config.max_active_tasks {
                let id = format!("occupied-{i}");
                queue.active.insert(
                    id.clone(),
                    ActiveRouteTask {
                        task_id: id,
                        path: "fixture".into(),
                        method: "barrier".into(),
                        tenant_id: "occupant".into(),
                        priority: 0,
                        started_at: Instant::now(),
                    },
                );
            }
        }
        let first = router
            .enqueue_route_task(
                "/fixture/first",
                "fixture",
                serde_json::json!({"timeout_secs":1}),
                Some("tenant".into()),
                1,
                Some("same".into()),
            )
            .await
            .unwrap();
        let id = first["task_id"].as_str().unwrap();
        let original = router.route_queue.lock().await.queued[0]
            .preparation
            .clone();
        let second = router
            .enqueue_route_task(
                "/fixture/second",
                "fixture",
                serde_json::json!({"timeout_secs":600}),
                Some("other".into()),
                9,
                Some("same".into()),
            )
            .await
            .unwrap();
        let count = router.route_queue.lock().await.queued.len();
        let meta = router.task_registry.get(id).unwrap().meta.unwrap();
        let cancelled = router.cancel_task(id).await;
        router.route_queue.lock().await.active.clear();
        router.drive_route_queue().await;
        assert_eq!(second["task_id"], first["task_id"]);
        assert_eq!(count, 1, "dedupe must not insert a second queued operation");
        assert_eq!(
            meta["path"], "/fixture/first",
            "dedupe must not overwrite accepted metadata"
        );
        assert_eq!(meta["tenant_id"], "tenant");
        assert!(
            cancelled && original.cancel.is_cancelled(),
            "original token must receive cancellation"
        );
        let queue = router.route_queue.lock().await;
        assert!(
            queue.queued.is_empty() && queue.active.is_empty() && queue.tenant_active.is_empty()
        );
        assert_eq!(
            router.task_registry.get(id).unwrap().status,
            crate::server::task::TaskStatus::Cancelled
        );
    }

    #[test]
    fn nexus_business_capacity_uses_tenant_configuration_and_control_remains_independent() {
        let mut router = RouterState::new().unwrap();
        let mut config = (*router.config).clone();
        config.max_pending_per_worker = 1;
        config.max_pending_per_tenant = 3;
        router.config = Arc::new(config);
        let caps = crate::nexus::NexusCapabilities {
            runtime: crate::nexus::NexusRuntime {
                ida: crate::nexus::Version(9, 5, 0),
                python: crate::nexus::Version(3, 14, 7),
                nexus: Some(crate::nexus::Version(0, 13, 4)),
                domain: Some(crate::nexus::Version(0, 5, 1)),
            },
            methods: Default::default(),
        };
        router.install_nexus_capabilities(caps).unwrap();
        let endpoint = router.nexus_endpoint();
        let lanes = endpoint.take_lanes().unwrap();
        assert_eq!(lanes.business.max_capacity(), 3);
        assert_eq!(lanes.control.max_capacity(), 8);
        for i in 0..4 {
            let request = crate::nexus::AcceptedRequest::new(
                &crate::nexus::SystemClock,
                crate::nexus::RequestId::new(format!("r-{i}")).unwrap(),
                None,
                "open",
                serde_json::json!({}),
            )
            .unwrap();
            let client = crate::nexus::ClientId::new("fixture").unwrap();
            let result = endpoint.transition(|sessions, backend| {
                sessions.open(
                    &client,
                    request,
                    crate::nexus::OpenSpec {
                        operation_id: crate::nexus::OperationId::new(format!("o-{i}")).unwrap(),
                        path: "/fixture.i64".into(),
                        options: serde_json::json!({}),
                    },
                    backend,
                )
            });
            if i < 3 {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.unwrap_err().code, crate::nexus::NexusErrorCode::Busy);
            }
        }
        drop(lanes);
        endpoint.transition(|_, _| ());
    }

    #[test]
    fn test_router_module_exists() {
        let _ = std::module_path!();
    }

    #[test]
    fn test_protocol_types_accessible() {
        use crate::router::protocol::{RpcRequest, RpcResponse};
        use serde_json::json;
        let req = RpcRequest::new("test-id", "open", json!({"path": "/tmp/test.i64"}));
        assert_eq!(req.id, "test-id");
        let resp = RpcResponse::ok("test-id", json!({"ok": true}));
        assert_eq!(resp.id, "test-id");
    }

    #[tokio::test]
    async fn test_router_state_creation() {
        let router = RouterState::new().expect("RouterState should be created");
        assert_eq!(router.worker_count().await, 0);
        assert!(router.active_handle().await.is_none());
        assert!(router.all_handles().await.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn n2_red_blocked_pipe_does_not_hold_global_state() {
        let router = RouterState::new().expect("router");
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import signal; print('started', flush=True); signal.pause()",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("fixture child");
        crate::preprocess::record_owned_fixture(
            child.id().expect("owned spawned PID"),
            false,
            "router-blocked-pipe",
        );
        let stdin = child.stdin.take().expect("fixture stdin");
        let mut reader = BufReader::new(child.stdout.take().expect("fixture stdout"));
        let mut started = String::new();
        reader
            .read_line(&mut started)
            .await
            .expect("started barrier");
        assert_eq!(started.trim(), "started");
        router.inner.lock().await.workers.insert(
            "blocked".into(),
            WorkerProcess {
                backend: WorkerBackendKind::NativeLinked,
                tenant_id: "fixture".into(),
                child,
                connection: transport::RpcConnection::start(reader, stdin, 2),
                close_token: None,
                open_path: None,
                last_active: Instant::now(),
            },
        );
        let cloned = router.clone();
        let call = tokio::spawn(async move {
            cloned
                .route_request(
                    Some("blocked"),
                    "fixture",
                    serde_json::json!({"padding": "x".repeat(4 * 1024 * 1024)}),
                )
                .await
        });
        let connection = router
            .inner
            .lock()
            .await
            .workers
            .get("blocked")
            .expect("fixture worker")
            .connection
            .clone();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !connection.has_written_bytes() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("physical A write started barrier");
        tokio::time::timeout(Duration::from_millis(200), router.worker_count())
            .await
            .expect("blocked connection must not hold router inner");
        let preparation = crate::preprocess::Preparation::new(Duration::from_secs(5));
        let cancel = preparation.cancel.clone();
        let queued_router = router.clone();
        let queued = tokio::spawn(async move {
            queued_router
                .route_request_prepared(
                    Some("blocked"),
                    "queued",
                    serde_json::json!({}),
                    preparation,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.pending_len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second request admitted behind blocked frame");
        assert!(cancel.cancel());
        let error = tokio::time::timeout(Duration::from_secs(1), queued)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(
                error,
                crate::error::ToolError::Preparation {
                    execution_stopped: true,
                    ..
                }
            ),
            "{error}"
        );
        assert_eq!(
            connection.pending_len(),
            1,
            "cancelled queued request must release pending identity"
        );
        call.abort();
        assert!(call.await.expect_err("cancel waiter").is_cancelled());
        router
            .close_worker("blocked")
            .await
            .expect("reap disposable fixture worker");
    }

    #[tokio::test]
    async fn test_status_snapshot_with_empty_probe_cache_does_not_deadlock() {
        let router = RouterState::new().expect("RouterState should be created");
        router.inner.lock().await.exe_path = PathBuf::from("/nonexistent/ida-cli-for-probe-test");
        let status =
            tokio::time::timeout(std::time::Duration::from_secs(10), router.status_snapshot())
                .await
                .expect("status_snapshot must not deadlock when the probe cache is empty");
        assert!(status.runtime_probe.is_none());
        assert!(router.cached_probe.try_lock().is_ok());
    }

    #[tokio::test]
    async fn test_status_metadata_reports_daemon_endpoints_and_capabilities() {
        let router = RouterState::new().expect("RouterState should be created");
        let probe: RuntimeProbeResult = serde_json::from_value(serde_json::json!({
            "runtime": {"major": 9, "minor": 5, "build": 261001},
            "backend": "native-linked",
            "supported": true,
            "reason": null,
            "supported_methods": []
        }))
        .expect("valid runtime probe fixture");
        *router.cached_probe.lock().await = Some(probe);
        router
            .set_http_address(Some("http://127.0.0.1:43123".to_string()))
            .await;

        let status = router.status_snapshot().await;
        assert_eq!(status.metadata.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            status.metadata.rpc_socket_path,
            crate::idb_store::socket_path().display().to_string()
        );
        assert_eq!(
            status.metadata.mcp_socket_path,
            crate::idb_store::mcp_socket_path().display().to_string()
        );
        assert_eq!(
            status.metadata.http_address.as_deref(),
            Some("http://127.0.0.1:43123")
        );
        assert_eq!(status.metadata.backend.as_deref(), Some("native-linked"));
        assert_eq!(status.metadata.ida_version.as_deref(), Some("9.5.261001"));
        assert!(status.metadata.supported_methods.len() > 50);
        assert!(status.metadata.supported_tools.len() > 50);
    }

    #[tokio::test]
    async fn test_route_request_no_active_fails() {
        let router = RouterState::new().unwrap();
        let result = router
            .route_request(None, "list_functions", serde_json::json!({}))
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_task_state_json_exposes_meta_and_remote_fields() {
        let now = std::time::Instant::now();
        let state = TaskState {
            id: "job-1".to_string(),
            status: TaskStatus::Completed,
            message: "Completed".to_string(),
            meta: Some(serde_json::json!({
                "tenant_id": "team-a",
                "path": "/tmp/sample.bin",
                "method": "list_functions",
            })),
            result: Some(serde_json::json!({
                "remote": true,
                "node": "node-a",
                "remote_task_id": "task-9",
            })),
            created_at: now,
            updated_at: now,
            created_at_iso: "2026-04-17T00:00:00Z".to_string(),
            updated_at_iso: "2026-04-17T00:00:01Z".to_string(),
            key: None,
        };

        let value = task_state_json(&state);
        assert_eq!(value["meta"]["tenant_id"], "team-a");
        assert_eq!(value["meta"]["method"], "list_functions");
        assert_eq!(value["remote"], true);
        assert_eq!(value["node"], "node-a");
        assert_eq!(value["remote_task_id"], "task-9");
    }

    #[test]
    #[ignore = "requires IDA Pro license and compiled binary"]
    fn test_worker_subprocess_responds() {}

    #[test]
    #[ignore = "requires IDA Pro license and compiled binary"]
    fn test_worker_eof_graceful_shutdown() {}
}

#[cfg(test)]
#[path = "../../tests/support/n2_f1_router.rs"]
pub(crate) mod n2_f1_regressions;

#[cfg(test)]
#[path = "../../tests/support/n4_router.rs"]
pub(crate) mod n4_fix_regressions;
