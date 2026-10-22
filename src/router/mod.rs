//! Multi-IDB router for Nexus leases, request lanes and background tasks.

pub mod listing;
pub mod nexus_bridge;
pub mod nexus_tools;
pub mod nexus_transport;
pub mod protocol;
pub mod transport;
pub mod worker_io;

use crate::router::listing::{ClientIdentity, IdbListing};
use crate::server::task::{TaskRegistry, TaskState, TaskStatus};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{info, warn};

pub type DbHandle = String;
pub type ReqId = String;
type CliPathGates = std::sync::Mutex<HashMap<PathBuf, std::sync::Weak<CliPath>>>;
#[cfg(test)]
type CliOpenPause = (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub max_workers: usize,
    pub max_workers_per_tenant: usize,
    pub max_pending_per_worker: usize,
    pub max_pending_per_tenant: usize,
    pub nexus_retention_capacity: usize,
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
        // Historical pool fields remain in status for wire compatibility.
        // Nexus admission is controlled by max_pending_per_tenant instead.
        let max_workers = 0;
        let max_workers_per_tenant = 0;
        let max_pending_per_worker = 0;
        let max_pending_per_tenant = std::env::var("IDA_CLI_MAX_PENDING_PER_TENANT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(512);
        let nexus_retention_capacity = std::env::var("IDA_CLI_NEXUS_RETENTION_CAPACITY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(262144);
        let max_concurrent_spawns = 0;
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
            nexus_retention_capacity,
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

#[derive(Debug)]
struct CliPath {
    gate: Arc<Mutex<()>>,
    requests: std::sync::atomic::AtomicUsize,
}

pub(crate) struct CliLeaseGuard {
    activity: Arc<CliPath>,
    _admission: tokio::sync::OwnedRwLockReadGuard<()>,
    reference: Option<nexus_tools::ReferenceGuard>,
}
impl CliLeaseGuard {
    fn new(activity: Arc<CliPath>, admission: tokio::sync::OwnedRwLockReadGuard<()>) -> Self {
        activity.requests.fetch_add(1, Ordering::AcqRel);
        Self {
            activity,
            _admission: admission,
            reference: None,
        }
    }
}
impl Drop for CliLeaseGuard {
    fn drop(&mut self) {
        self.activity.requests.fetch_sub(1, Ordering::AcqRel);
    }
}

fn cli_request_busy() -> crate::error::ToolError {
    crate::nexus::NexusError::new(
        crate::nexus::NexusErrorCode::CancelPending,
        "CLI request is still in use; lease and warm tracking retained",
    )
    .into()
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
    activity: Arc<CliPath>,
    _slot: Arc<tokio::sync::OwnedSemaphorePermit>,
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
    pub owner_observations: Vec<serde_json::Value>,
    pub nexus_lifecycle: Option<serde_json::Value>,
    pub nexus_retention: crate::nexus::NexusRetentionStatus,
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
    pub runtime_probe: Option<serde_json::Value>,
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
    pub installed_ida_version: Option<String>,
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
    config: Arc<RouterConfig>,
    nexus: Arc<std::sync::Mutex<(nexus_transport::NexusEndpoint, bool)>>,
    nexus_bridge: Arc<tokio::sync::OnceCell<Arc<nexus_bridge::NexusBridge>>>,
    nexus_tools: Arc<nexus_tools::Tools>,
    warm_pool: Arc<Mutex<HashMap<PathBuf, WarmLease>>>,
    cli_open_gate: Arc<CliPathGates>,
    warm_slots: Arc<tokio::sync::Semaphore>,
    cli_admission: Arc<tokio::sync::RwLock<()>>,
    #[cfg(test)]
    cli_open_pause: Arc<Mutex<HashMap<PathBuf, CliOpenPause>>>,
    prewarm_queue: Arc<Mutex<PrewarmQueueState>>,
    route_queue: Arc<Mutex<RouteQueueState>>,
    task_registry: TaskRegistry,
    federation_nodes: Arc<Mutex<HashMap<String, crate::federation::FederationNodeRecord>>>,
    http_address: Arc<Mutex<Option<String>>>,
    maintenance_started: Arc<AtomicBool>,
    /// Set while `exit_after_bridge_loss` runs (serve-http daemon only).
    bridge_loss_exit_armed: Arc<AtomicBool>,
    metadata_refreshing: Arc<AtomicBool>,
    cache_stats: Arc<Mutex<CacheSnapshot>>,
}

impl std::fmt::Debug for RouterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterState").finish_non_exhaustive()
    }
}

pub(crate) struct ScopedRefToken {
    token: Option<String>,
    nexus_router: RouterState,
}
impl ScopedRefToken {
    fn release(&mut self) {
        if let Some(token) = self.token.take() {
            nexus_tools::Tools::abandon(self.nexus_router.clone(), token);
        }
    }
}
impl Drop for ScopedRefToken {
    fn drop(&mut self) {
        self.release();
    }
}

impl RouterState {
    #[cfg(test)]
    pub(crate) async fn register_test_lease(
        &self,
        path: &str,
        client: &ClientIdentity,
    ) -> (String, String) {
        self.nexus_tools.register_test_lease(path, client).await
    }

    fn normalize_tenant(tenant_id: Option<&str>) -> String {
        tenant_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("default")
            .to_string()
    }

    pub fn new() -> anyhow::Result<Self> {
        Self::with_config(RouterConfig::from_env())
    }

    /// Construct a router with explicit admission settings.
    pub fn with_config(config: RouterConfig) -> anyhow::Result<Self> {
        let config = Arc::new(config);
        Ok(Self {
            config: config.clone(),
            nexus: Arc::new(std::sync::Mutex::new((
                nexus_transport::NexusEndpoint::with_limits(
                    config.max_pending_per_tenant,
                    config.nexus_retention_capacity,
                    Err(crate::nexus::NexusError::new(
                        crate::nexus::NexusErrorCode::BridgeUnavailable,
                        "N3 capability handshake is not installed",
                    )),
                ),
                false,
            ))),
            nexus_bridge: Arc::new(tokio::sync::OnceCell::new()),
            nexus_tools: Arc::new(nexus_tools::Tools::new(config.max_pending_per_tenant)?),
            warm_pool: Arc::new(Mutex::new(HashMap::new())),
            cli_open_gate: Arc::new(std::sync::Mutex::new(HashMap::new())),
            warm_slots: Arc::new(tokio::sync::Semaphore::new(config.max_warm_workers)),
            cli_admission: Arc::new(tokio::sync::RwLock::new(())),
            #[cfg(test)]
            cli_open_pause: Arc::new(Mutex::new(HashMap::new())),
            prewarm_queue: Arc::new(Mutex::new(PrewarmQueueState::default())),
            route_queue: Arc::new(Mutex::new(RouteQueueState::default())),
            task_registry: TaskRegistry::new(),
            federation_nodes: Arc::new(Mutex::new(crate::federation::load_node_map_from_env())),
            http_address: Arc::new(Mutex::new(None)),
            maintenance_started: Arc::new(AtomicBool::new(false)),
            bridge_loss_exit_armed: Arc::new(AtomicBool::new(false)),
            metadata_refreshing: Arc::new(AtomicBool::new(false)),
            cache_stats: Arc::new(Mutex::new((None, None, None))),
        })
    }

    /// Check the fixed dependency and protocol handshake before accepting clients.
    pub async fn initialize_nexus(&self) -> Result<(), crate::error::ToolError> {
        nexus_tools::Tools::bridge(self).await?;
        Ok(())
    }

    pub fn nexus_endpoint(&self) -> nexus_transport::NexusEndpoint {
        self.nexus
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .clone()
    }

    pub async fn nexus_close_token(
        &self,
        token: &str,
    ) -> Result<Option<(String, usize)>, crate::error::ToolError> {
        self.nexus_tools.close_token(self, token).await
    }
    pub async fn nexus_wait_owner_exit(
        &self,
        reference: &str,
        preparation: crate::preprocess::Preparation,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        self.nexus_tools
            .wait_owner_exit(self, reference, preparation)
            .await
    }
    pub(crate) async fn nexus_close_token_detailed(
        &self,
        token: &str,
    ) -> (
        Result<Option<(String, usize)>, crate::error::ToolError>,
        Option<serde_json::Value>,
    ) {
        self.nexus_tools.close_token_detailed(self, token).await
    }
    pub(crate) async fn open_nexus_dsc(
        &self,
        path: &str,
        config: nexus_bridge::cache::special::DscInput,
        preparation: crate::preprocess::Preparation,
    ) -> Result<(String, String), crate::error::ToolError> {
        self.nexus_tools
            .open_dsc(self, path, preparation, config)
            .await
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
    /// Production connection: config.directory is the IPC parent, not an owned directory.
    async fn connect_nexus_session(
        &self,
        config: nexus_bridge::BridgeConfig,
    ) -> anyhow::Result<Arc<nexus_bridge::NexusBridge>> {
        self.nexus_bridge
            .get_or_try_init(|| async {
                nexus_bridge::NexusBridge::start_session(self, config)
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
            nexus_transport::NexusEndpoint::with_limits(
                self.config.max_pending_per_tenant,
                self.config.nexus_retention_capacity,
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
        let params = Self::prepare_request_params(method, params, &preparation).await?;
        return self
            .nexus_tools
            .execute(self, handle, method, params, preparation)
            .await;
    }

    /// Shared admission for CLI, queued jobs and MCP, before acquiring an IDB.
    pub async fn prepare_request_params(
        method: &str,
        params: serde_json::Value,
        preparation: &crate::preprocess::Preparation,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        if crate::tool_registry::primary_name_for(method) != "run_script" {
            return Ok(params);
        }
        preparation.check()?;
        let mut request: crate::server::RunScriptRequest =
            serde_json::from_value(params).map_err(|error| {
                crate::error::ToolError::InvalidParams(format!("invalid params: {error}"))
            })?;
        request.code = Some(
            crate::server::resolve_script_code(request.code, request.file.take(), preparation)
                .await?,
        );
        serde_json::to_value(request)
            .map_err(|error| crate::error::ToolError::InvalidParams(error.to_string()))
    }

    pub(crate) fn scoped_ref(&self, token: String) -> ScopedRefToken {
        ScopedRefToken {
            token: Some(token),
            nexus_router: self.clone(),
        }
    }

    /// Release a reference token. Returns `Some((handle, remaining))` if the token was valid:
    /// `remaining > 0` means other clients still hold refs (do NOT close the worker),
    /// `remaining == 0` means last reference released (caller should close the worker).
    /// Returns `None` if the token was not found (invalid or already released).
    pub async fn release_ref_token(&self, token: &str) -> Option<(DbHandle, usize)> {
        return match self.nexus_close_token(token).await {
            Ok(value) => value,
            Err(error) => {
                warn!(%error,"Nexus reference release unconfirmed; tracking retained");
                None
            }
        };
    }

    pub async fn handle_for_token(&self, token: &str) -> Option<DbHandle> {
        self.nexus_tools.handle_for_token(token)
    }

    pub async fn active_handle(&self) -> Option<DbHandle> {
        self.nexus_tools.active()
    }

    pub async fn all_handles(&self) -> Vec<DbHandle> {
        self.nexus_tools.handles()
    }

    pub async fn worker_count(&self) -> usize {
        self.nexus_tools.workers(self).len()
    }

    /// List the databases the daemon holds open, oldest first.
    ///
    /// `caller` marks the entries and holders that belong to the asking
    /// client. This reads registry state only: it never spawns, probes, or
    /// talks to a worker, so it cannot block behind a slow `open`. Close
    /// tokens are never part of the result.
    pub(crate) fn set_nexus_client(&self, handle: &str, client: &ClientIdentity) {
        self.nexus_tools.set_client(handle, client);
    }

    pub async fn list_idbs(&self, caller: Option<&ClientIdentity>) -> IdbListing {
        self.nexus_tools.list_idbs(caller)
    }

    async fn status_snapshot_inner(&self, include_federation: bool) -> RouterStatus {
        self.refresh_metadata();
        let cache_stats = self.cache_stats.lock().await.clone();
        let supported_methods: Vec<String> = nexus_tools::METHODS
            .iter()
            .map(|name| (*name).into())
            .collect();
        let metadata = DaemonMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            rpc_socket_path: crate::idb_store::socket_path().display().to_string(),
            mcp_socket_path: crate::idb_store::mcp_socket_path().display().to_string(),
            http_address: self.http_address.lock().await.clone(),
            backend: Some("nexus".into()),
            ida_version: self
                .nexus_bridge
                .get()
                .map(|bridge| bridge.ida_version.clone()),
            installed_ida_version: self
                .nexus_bridge
                .get()
                .and_then(|bridge| bridge.installed_ida_version.clone()),
            supported_tools: nexus_tools::Tools::supported_tools(),
            supported_methods,
        };
        let workers = self.nexus_tools.workers(self);
        let worker_count = workers.len();
        let active_handle = self.nexus_tools.active();
        let backend_counts = HashMap::from([("nexus".into(), worker_count)]);
        let tenant_worker_counts = HashMap::from([("default".into(), worker_count)]);
        let tenant_pending_counts = HashMap::from([(
            "default".into(),
            workers.iter().map(|w| w.pending_requests).sum(),
        )]);
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

        let status = RouterStatus {
            owner_observations: self.nexus_tools.owner_status(self),
            nexus_lifecycle: self.nexus_bridge.get().map(|b| b.lifecycle_status()),
            nexus_retention: self
                .nexus_endpoint()
                .transition(|s, _| s.retention_status()),
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
            runtime_probe: None,
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
        if let Err(error) = self.shutdown_nexus().await {
            warn!(%error,"Nexus shutdown incomplete");
        }
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

        if explicit_idb_output.is_some() || tenant_id.is_some_and(|t| t != "default") {
            return Err(ToolError::NotSupported(
                "Nexus N4 custom outputs and tenant overrides are not implemented".into(),
            ));
        }
        #[cfg(test)]
        let pause = self
            .cli_open_pause
            .lock()
            .await
            .get(std::path::Path::new(path))
            .cloned();
        #[cfg(test)]
        if let Some((entered, resume)) = pause {
            entered.notify_one();
            resume.notified().await;
        }
        return self.nexus_tools.open(self, path, preparation).await;
    }

    fn cli_path_gate(&self, path: &std::path::Path) -> Arc<CliPath> {
        let mut paths = self
            .cli_open_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        paths.retain(|_, gate| gate.strong_count() > 0);
        paths
            .entry(path.to_path_buf())
            .or_default()
            .upgrade()
            .unwrap_or_else(|| {
                let gate = Arc::new(CliPath {
                    gate: Arc::new(Mutex::new(())),
                    requests: std::sync::atomic::AtomicUsize::new(0),
                });
                paths.insert(path.to_path_buf(), Arc::downgrade(&gate));
                gate
            })
    }

    /// CLI path requests share a bounded daemon-owned warm reference. MCP
    /// openers and background tasks keep their independent close authorities.
    pub(crate) async fn ensure_cli_worker_prepared(
        &self,
        path: &str,
        tenant_id: Option<&str>,
        preparation: crate::preprocess::Preparation,
    ) -> Result<(DbHandle, CliLeaseGuard), crate::error::ToolError> {
        use crate::error::ToolError;
        if tenant_id.is_some_and(|tenant| tenant != "default") {
            return Err(ToolError::NotSupported(
                "Nexus tenant overrides are not implemented".into(),
            ));
        }
        let expanded = crate::expand_path(path);
        let canonical = preparation
            .wait(crate::blocking::run(
                crate::blocking::WorkClass::Prepare,
                move || {
                    expanded
                        .canonicalize()
                        .map_err(|error| ToolError::InvalidPath(error.to_string()))
                },
            ))
            .await??;
        let admission = preparation
            .wait(async { Ok(self.cli_admission.clone().read_owned().await) })
            .await?;
        let activity = self.cli_path_gate(&canonical);
        let mut request = CliLeaseGuard::new(activity.clone(), admission);
        let _opening = preparation
            .wait(async { Ok(activity.gate.clone().lock_owned().await) })
            .await?;
        let existing = self.warm_pool.lock().await.get(&canonical).cloned();
        if let Some(existing) = existing {
            if self.nexus_tools.active_reference(self, &existing.handle) {
                if let Some(warm) = self.warm_pool.lock().await.get_mut(&canonical) {
                    warm.last_hit = Instant::now();
                }
                return Ok((existing.handle, request));
            }
            // This resolving request has not dispatched on the stale lease.
            // Other admitted users still pin it and must not be interrupted.
            self.release_warm_lease_locked(&canonical, 1).await?;
        }
        let slot = self.warm_slot(&canonical).await?;
        let (handle, token) = self
            .ensure_worker_prepared(
                canonical
                    .to_str()
                    .ok_or_else(|| ToolError::InvalidPath("non-UTF8 CLI path".into()))?,
                None,
                tenant_id,
                preparation.clone(),
            )
            .await?;
        let mut reference = nexus_tools::ReferenceGuard::new(self.clone(), token.clone());
        preparation.check()?;
        if let Some(slot) = slot {
            self.warm_pool.lock().await.insert(
                canonical.clone(),
                WarmLease {
                    handle: handle.clone(),
                    token,
                    path: canonical,
                    cache_path: None,
                    tenant_id: "default".into(),
                    pinned_at: Instant::now(),
                    last_hit: Instant::now(),
                    activity,
                    _slot: Arc::new(slot),
                },
            );
            reference.transfer();
        } else {
            // Capacity pressure is an explicit request-level lifetime, not an
            // alternate backend or a retry after a failed close/open.
            request.reference = Some(reference);
        }
        Ok((handle, request))
    }

    async fn warm_slot(
        &self,
        current: &std::path::Path,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, crate::error::ToolError> {
        if let Ok(slot) = self.warm_slots.clone().try_acquire_owned() {
            return Ok(Some(slot));
        }
        let mut candidates: Vec<_> = self
            .warm_pool
            .lock()
            .await
            .values()
            .filter(|entry| {
                entry.path != current && entry.activity.requests.load(Ordering::Acquire) == 0
            })
            .map(|entry| (entry.last_hit, entry.path.clone(), entry.activity.clone()))
            .collect();
        candidates.sort_by_key(|(last, _, _)| *last);
        for (_, path, activity) in candidates {
            // Never await a second path's admission lock: that could block
            // unrelated opens, or invert two concurrent eviction lock orders.
            let Ok(_idle) = activity.gate.clone().try_lock_owned() else {
                continue;
            };
            if activity.requests.load(Ordering::Acquire) != 0 {
                continue;
            }
            self.release_warm_lease_locked(&path, 0).await?;
            return Ok(self.warm_slots.clone().try_acquire_owned().ok());
        }
        Ok(None)
    }

    async fn release_warm_lease_locked(
        &self,
        path: &std::path::Path,
        resolving: usize,
    ) -> Result<(), crate::error::ToolError> {
        let lease = self.warm_pool.lock().await.get(path).cloned();
        if let Some(lease) = lease {
            if lease.activity.requests.load(Ordering::Acquire) > resolving {
                return Err(cli_request_busy());
            }
            self.nexus_close_token(&lease.token).await?;
            let mut pool = self.warm_pool.lock().await;
            if pool
                .get(path)
                .is_some_and(|entry| entry.token == lease.token)
            {
                pool.remove(path);
            }
        }
        Ok(())
    }

    pub(crate) async fn nexus_close_path_detailed(
        &self,
        path: &std::path::Path,
    ) -> (
        Result<(), crate::error::ToolError>,
        Option<serde_json::Value>,
    ) {
        let activity = self.cli_path_gate(path);
        if activity.requests.load(Ordering::Acquire) != 0 {
            return (Err(cli_request_busy()), None);
        }
        let _path = activity.gate.lock().await;
        if activity.requests.load(Ordering::Acquire) != 0 {
            return (Err(cli_request_busy()), None);
        }
        self.nexus_tools.close_path_detailed(self, path).await
    }

    pub async fn close_by_path(
        &self,
        path: &std::path::Path,
        _tenant_id: Option<&str>,
    ) -> Result<(), crate::error::ToolError> {
        self.nexus_close_path_detailed(path).await.0
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
        let preparation = crate::preprocess::current()
            .unwrap_or_else(|| crate::preprocess::Preparation::new(Duration::from_secs(3600)));

        return self
            .prewarm_nexus(path, keep_warm, tenant_id, preparation)
            .await;
    }

    async fn prewarm_nexus(
        &self,
        path: &str,
        keep_warm: bool,
        tenant: &str,
        preparation: crate::preprocess::Preparation,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        use crate::error::ToolError;
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
        let admission = preparation
            .wait(async { Ok(self.cli_admission.clone().read_owned().await) })
            .await?;
        let activity = self.cli_path_gate(&canonical);
        let _request = CliLeaseGuard::new(activity.clone(), admission);
        let _path = if keep_warm {
            Some(
                preparation
                    .wait(async { Ok(activity.gate.clone().lock_owned().await) })
                    .await?,
            )
        } else {
            None
        };
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
        let mut kept_warm = false;
        if keep_warm {
            let previous = self.warm_pool.lock().await.get(&canonical).cloned();
            if let Some(previous) = previous {
                if self.nexus_tools.active_reference(self, &previous.handle) {
                    // Keep the existing authority, including its admitted users.
                    self.nexus_close_token(&token).await?;
                    reference.transfer();
                    if let Some(warm) = self.warm_pool.lock().await.get_mut(&canonical) {
                        warm.cache_path = Some(PathBuf::from(&idb));
                        warm.last_hit = Instant::now();
                    }
                    kept_warm = true;
                } else {
                    self.release_warm_lease_locked(&canonical, 1).await?;
                }
            }
            if !kept_warm {
                if let Some(slot) = self.warm_slot(&canonical).await? {
                    self.warm_pool.lock().await.insert(
                        canonical.clone(),
                        WarmLease {
                            handle,
                            token: token.clone(),
                            path: canonical.clone(),
                            cache_path: Some(PathBuf::from(&idb)),
                            tenant_id: "default".into(),
                            pinned_at: Instant::now(),
                            last_hit: Instant::now(),
                            activity,
                            _slot: Arc::new(slot),
                        },
                    );
                    reference.transfer();
                    kept_warm = true;
                }
            }
        }
        if !kept_warm {
            self.nexus_close_token(&token).await?;
            reference.transfer();
        }

        Ok(
            serde_json::json!({"path":canonical.display().to_string(),"backend":"nexus","cached_before":cached_before,"cached_after":true,"cache_path":idb,"database_info":info,"already_open":already_open,"kept_warm":kept_warm,"worker_closed_after_prewarm":!kept_warm && !already_open}),
        )
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
        nexus_tools::Tools::require(crate::tool_registry::primary_name_for(method))?;

        let script_preparation = if crate::tool_registry::primary_name_for(method) == "run_script" {
            let seconds = params
                .get("timeout_secs")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(120)
                .min(600);
            Some(crate::preprocess::Preparation::new(Duration::from_secs(
                seconds,
            )))
        } else {
            None
        };
        let params = if let Some(preparation) = &script_preparation {
            Self::prepare_request_params(method, params, preparation).await?
        } else {
            params
        };
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
                    let preparation = script_preparation.unwrap_or_else(|| {
                        let maximum = if method == "open" { 3600 } else { 600 };
                        let seconds = params
                            .get("timeout_secs")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(120)
                            .min(maximum);
                        crate::preprocess::Preparation::new(Duration::from_secs(seconds))
                    });
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
        nexus_tools::Tools::require(crate::tool_registry::primary_name_for(method))?;

        let seconds = params
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(120)
            .min(600);
        let preparation = crate::preprocess::Preparation::new(Duration::from_secs(seconds));
        let params = Self::prepare_request_params(method, params, &preparation).await?;
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
                let result = {
                    match crate::nexus::TaskId::new(task.task_id.clone()) {
                        Ok(task_id) => nexus_tools::CURRENT_TASK_ID.scope(task_id, work).await,
                        Err(error) => Err(error.into()),
                    }
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

    /// Declare that this process leaves by itself after a bridge loss. Only then
    /// does a pre-dispatch refusal carry the retry-once code, because a client
    /// can only retry on a fresh daemon if this one is going away.
    pub fn arm_bridge_loss_exit(&self) {
        self.bridge_loss_exit_armed.store(true, Ordering::SeqCst);
    }
    pub(crate) fn bridge_loss_exit_armed(&self) -> bool {
        self.bridge_loss_exit_armed.load(Ordering::SeqCst)
    }
    /// The Nexus bridge was lost; this router never replaces it.
    pub fn nexus_bridge_lost(&self) -> bool {
        self.nexus_bridge
            .get()
            .is_some_and(|bridge| bridge.is_lost())
    }
    /// A request failure that provably happened before anything reached the lost
    /// bridge: only the outer entrance refusal proves that the entire request
    /// was untouched. A NotSent continuation may follow completed writes.
    pub fn bridge_loss_not_dispatched<'a>(
        &self,
        error: &'a crate::error::ToolError,
    ) -> Option<&'a crate::ida::nexus::NexusError> {
        match error {
            crate::error::ToolError::Nexus(nexus)
                if nexus.code == crate::ida::nexus::NexusErrorCode::BridgeLostNotDispatched
                    && self.nexus_bridge_lost()
                    && self.bridge_loss_exit_armed() =>
            {
                Some(nexus)
            }
            _ => None,
        }
    }
    /// Daemon self-exit gate after bridge loss: Ok once the lost bridge's custody
    /// allows the same shutdown `ida-cli shutdown` would accept. Does not take the
    /// CLI admission lock, so requests keep getting their typed error meanwhile.
    pub async fn bridge_loss_shutdown_ready(&self) -> Result<(), crate::error::ToolError> {
        let Some(bridge) = self.nexus_bridge.get() else {
            return Ok(());
        };
        bridge
            .wait_shutdown_ready(&crate::preprocess::Preparation::new(Duration::from_secs(5)))
            .await
    }
    /// Daemon-only (`serve-http`): a lost Nexus bridge is never replaced inside this
    /// process, so once the same custody conditions that `ida-cli shutdown`
    /// requires are met the daemon leaves by itself (`cancel` is the service token
    /// that stops the listeners and removes socket and discovery files) and a fresh
    /// daemon serves the next request. While they are not met nothing is forced:
    /// requests keep getting their typed error and the reason is logged whenever
    /// it changes. The stdio `serve` process does not run this: it is the MCP
    /// server of its client and exits only with it.
    pub async fn exit_after_bridge_loss(&self, cancel: tokio_util::sync::CancellationToken) {
        self.bridge_loss_exit_armed.store(true, Ordering::SeqCst);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
            if self.nexus_bridge_lost() {
                break;
            }
        }
        warn!(target: "ida_mcp::shutdown",
            "Nexus bridge lost; this daemon exits by itself once custody allows a safe shutdown");
        let mut reported = String::new();
        loop {
            let attempt = match self.bridge_loss_shutdown_ready().await {
                Ok(()) => {
                    match tokio::time::timeout(Duration::from_secs(30), self.shutdown_nexus()).await
                    {
                        Ok(result) => result.map_err(|error| error.to_string()),
                        Err(_) => Err("CancelPending: shutdown exceeded its total deadline".into()),
                    }
                }
                Err(error) => Err(error.to_string()),
            };
            match attempt {
                Ok(()) => {
                    info!(target: "ida_mcp::shutdown",
                        "Nexus bridge lost and custody settled; daemon exiting so a fresh daemon can serve");
                    cancel.cancel();
                    return;
                }
                Err(reason) => {
                    if reason != reported {
                        warn!(target: "ida_mcp::shutdown", %reason,
                            "Nexus bridge lost; daemon retained until custody allows a safe shutdown");
                        reported = reason;
                    }
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
    }
    pub async fn shutdown_nexus(&self) -> Result<(), crate::error::ToolError> {
        let _exclusive = self
            .cli_admission
            .clone()
            .try_write_owned()
            .map_err(|_| cli_request_busy())?;
        self.nexus_tools.shutdown(self).await?;
        self.warm_pool.lock().await.clear();
        Ok(())
    }
    pub async fn cleanup_probe(&self) -> anyhow::Result<()> {
        if let Some(bridge) = self.nexus_bridge.get() {
            bridge.cleanup_probe().await?;
        }
        Ok(())
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
        _idle_timeout: Duration,
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
                "list_functions",
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
                "list_functions",
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
        config.max_pending_per_tenant = 3;
        config.nexus_retention_capacity = 262144;
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
        assert_eq!(
            endpoint.transition(|s, _| s.retention_status().business_capacity),
            262144
        );
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
    fn rv81_retention_environment_is_independent_of_pending_limit() {
        if std::env::var_os("RV81_CONFIG_CHILD").is_some() {
            let config = RouterConfig::from_env();
            assert_eq!(config.max_pending_per_tenant, 1);
            assert_eq!(config.nexus_retention_capacity, 3);
            let router = RouterState::new().expect("configured router");
            let usage = router
                .nexus_endpoint()
                .transition(|sessions, _| sessions.retention_status());
            assert_eq!(
                (
                    usage.business_capacity,
                    usage.internal_capacity,
                    usage.total_capacity
                ),
                (3, 144, 192)
            );
            assert_eq!(
                router
                    .nexus_endpoint()
                    .transition(|s, _| s.retention_status().business_capacity),
                3
            );
            assert_eq!(
                router
                    .nexus_endpoint()
                    .take_lanes()
                    .expect("business lane")
                    .business
                    .max_capacity(),
                1
            );
            return;
        }
        let output = std::process::Command::new("timeout")
            .arg("30s")
            .arg(std::env::current_exe().expect("unit-test executable"))
            .args([
                "--exact",
                "router::tests::rv81_retention_environment_is_independent_of_pending_limit",
                "--nocapture",
            ])
            .env("RV81_CONFIG_CHILD", "1")
            .env("IDA_CLI_MAX_PENDING_PER_TENANT", "1")
            .env("IDA_CLI_NEXUS_RETENTION_CAPACITY", "3")
            .output()
            .expect("isolated config test child");
        assert!(
            output.status.success(),
            "config child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    }

    #[tokio::test]
    async fn rv81_status_exposes_configured_retention_and_growing_usage() {
        let mut router = RouterState::new().expect("router");
        let mut config = (*router.config).clone();
        config.max_pending_per_tenant = 1;
        config.nexus_retention_capacity = 2;
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
        router
            .install_nexus_capabilities(caps)
            .expect("capabilities");
        let before = router.status_snapshot().await;
        assert_eq!(before.max_pending_per_tenant, 1);
        assert_eq!(before.nexus_retention.business_used, 0);
        assert_eq!(before.nexus_retention.business_capacity, 2);
        let endpoint = router.nexus_endpoint();
        let mut lanes = endpoint.take_lanes().expect("business lane");
        for index in 0..2 {
            let identity = endpoint
                .transition(|s, t| {
                    s.open(
                        &crate::nexus::ClientId::new("rv81-status").unwrap(),
                        crate::nexus::AcceptedRequest::new(
                            &crate::nexus::SystemClock,
                            crate::nexus::RequestId::new(format!("r-{index}")).unwrap(),
                            None,
                            "open",
                            serde_json::json!({}),
                        )
                        .unwrap(),
                        crate::nexus::OpenSpec {
                            operation_id: crate::nexus::OperationId::new(format!("o-{index}"))
                                .unwrap(),
                            path: "/fixture.i64".into(),
                            options: serde_json::json!({}),
                        },
                        t,
                    )
                })
                .expect("retention permits another request after terminal NotSent");
            drop(lanes.business.try_recv().expect("exact local delivery"));
            endpoint.transition(|s, _| {
                assert!(s
                    .open_progress(&identity.client_id, &identity)
                    .expect("terminal NotSent tombstone")
                    .1
                    .is_some())
            });
            let status = serde_json::to_value(router.status_snapshot().await).unwrap();
            assert_eq!(status["nexus_retention"]["business_used"], index + 1);
            assert_eq!(status["nexus_retention"]["business_capacity"], 2);
            assert_eq!(status["nexus_retention"]["total_used"], index + 1);
            assert_eq!(status["nexus_retention"]["total_capacity"], 128);
            assert_eq!(status["max_pending_per_tenant"], 1);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_supported_tools_lists_every_tool_mcp_admits() {
        let router = RouterState::new().unwrap();
        let status = router.status_snapshot().await;
        for tool in [
            "read_byte",
            "read_word",
            "read_dword",
            "read_qword",
            "convert_number",
            "decompile_structured",
            "search_structs",
            "open_idb",
            "close_idb",
            "list_idbs",
            "tool_catalog",
            "tool_help",
            "get_task_status",
        ] {
            assert!(
                status.metadata.supported_tools.iter().any(|t| t == tool),
                "supported_tools misses {tool}"
            );
        }
        assert_eq!(
            status.metadata.supported_tools.len(),
            crate::tool_registry::all_tools().count()
        );
        assert!(
            status
                .metadata
                .supported_methods
                .iter()
                .all(|m| nexus_tools::METHODS.contains(&m.as_str())),
            "supported_methods stays the worker method list"
        );
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
}

#[cfg(test)]
#[path = "../../tests/support/n4_router.rs"]
pub(crate) mod n4_fix_regressions;

#[cfg(all(test, feature = "nexus-test-support"))]
#[path = "../../tests/support/cli_warm.rs"]
mod cli_warm_regressions;
