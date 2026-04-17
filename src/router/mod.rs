//! Multi-IDB Router — manages worker subprocesses.
//!
//! Architecture:
//! - Each open IDB gets a `WorkerProcess` running `ida-cli serve-worker`
//! - Requests are routed to workers via JSON-RPC over stdin/stdout
//! - Router maintains an "active" handle for backward compatibility

pub mod protocol;

use crate::ida::{RuntimeProbeResult, WorkerBackendKind};
use crate::router::protocol::{RpcRequest, RpcResponse};
use crate::server::task::{TaskRegistry, TaskState, TaskStatus};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::Command;
use tokio::process::{Child, ChildStdin};
use tokio::sync::{oneshot, Mutex, Semaphore};
use tracing::{debug, error, info, warn};

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
    pub writer: BufWriter<ChildStdin>,
    pub pending: HashMap<ReqId, oneshot::Sender<Result<serde_json::Value, String>>>,
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
    pub idb_cache: crate::idb_store::IdbStoreStats,
    pub response_cache: crate::server::response_cache::ResponseCacheStats,
}

#[derive(Clone)]
pub struct RouterState {
    inner: Arc<Mutex<RouterInner>>,
    config: Arc<RouterConfig>,
    spawn_gate: Arc<Semaphore>,
    cached_probe: Arc<Mutex<Option<RuntimeProbeResult>>>,
    warm_pool: Arc<Mutex<HashMap<PathBuf, WarmLease>>>,
    prewarm_queue: Arc<Mutex<PrewarmQueueState>>,
    route_queue: Arc<Mutex<RouteQueueState>>,
    task_registry: TaskRegistry,
    maintenance_started: Arc<AtomicBool>,
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
    token_to_handle: HashMap<String, DbHandle>,
    ref_tokens: HashMap<DbHandle, HashSet<String>>,
    req_counter: u64,
    exe_path: PathBuf,
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
                token_to_handle: HashMap::new(),
                ref_tokens: HashMap::new(),
                req_counter: 0,
                exe_path,
            })),
            config: config.clone(),
            spawn_gate: Arc::new(Semaphore::new(config.max_concurrent_spawns)),
            cached_probe: Arc::new(Mutex::new(None)),
            warm_pool: Arc::new(Mutex::new(HashMap::new())),
            prewarm_queue: Arc::new(Mutex::new(PrewarmQueueState::default())),
            route_queue: Arc::new(Mutex::new(RouteQueueState::default())),
            task_registry: TaskRegistry::new(),
            maintenance_started: Arc::new(AtomicBool::new(false)),
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
            .stderr(std::process::Stdio::piped());
        Self::apply_worker_env(&mut cmd);

        let output = cmd
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("failed to run probe-runtime: {e}"))?;

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if !output.status.success() {
            let mut msg = format!("probe-runtime exited with status {}", output.status);
            if !stderr.is_empty() {
                msg.push_str(&format!(": {stderr}"));
            }
            return Err(anyhow::anyhow!(msg));
        }

        let probe = serde_json::from_str::<RuntimeProbeResult>(&stdout).map_err(|e| {
            anyhow::anyhow!(
                "failed to parse probe-runtime output: {e}; stdout={stdout:?}; stderr={stderr:?}"
            )
        })?;
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
        let canonical_path = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
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

                inner
                    .token_to_handle
                    .insert(ref_token.clone(), existing_handle.clone());
                inner
                    .ref_tokens
                    .entry(existing_handle.clone())
                    .or_insert_with(HashSet::new)
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
                            let ref_count =
                                inner.ref_tokens.get(*handle).map(|set| set.len()).unwrap_or(0);
                            ref_count == 0
                                && worker.pending.is_empty()
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

            inner
                .token_to_handle
                .insert(ref_token.clone(), existing_handle.clone());
            inner
                .ref_tokens
                .entry(existing_handle.clone())
                .or_insert_with(HashSet::new)
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

        let writer = BufWriter::new(stdin);

        let close_token = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let pid = std::process::id();
            let nonce = inner.req_counter;
            format!("{now:x}-{pid:x}-{nonce:x}")
        };

        let worker = WorkerProcess {
            backend,
            tenant_id: tenant_id.clone(),
            child,
            writer,
            pending: HashMap::new(),
            close_token: Some(close_token.clone()),
            open_path: Some(canonical_path.clone()),
            last_active: Instant::now(),
        };

        let handle_for_reader = handle.clone();
        let inner_arc = self.inner.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line_buf = String::new();
            loop {
                line_buf.clear();
                match reader.read_line(&mut line_buf).await {
                    Ok(0) => {
                        warn!(
                            "Worker {} stdout closed (process exited)",
                            handle_for_reader
                        );
                        let mut inner = inner_arc.lock().await;
                        // Drain pending requests, notify callers
                        if let Some(worker) = inner.workers.get_mut(&handle_for_reader) {
                            for (id, sender) in worker.pending.drain() {
                                let _ = sender.send(Err(format!(
                                    "Worker {} exited unexpectedly",
                                    handle_for_reader
                                )));
                                debug!("Cancelled pending request {} due to worker exit", id);
                            }
                        }
                        // Crash detection: remove dead worker from all maps so the
                        // handle is not reachable for future requests. This is a no-op
                        // when the worker was already removed by close_worker().
                        // Only emit the WARN if the worker was still in the registry
                        // (truly unexpected exit). If already removed by close_worker(),
                        // the process exit was expected — no warning needed.
                        if let Some(dead) = inner.workers.remove(&handle_for_reader) {
                            if let Some(path) = &dead.open_path {
                                inner.path_to_handle.remove(&Self::worker_key(
                                    path.clone(),
                                    &dead.tenant_id,
                                ));
                            }
                            // dead.child drops here; kill_on_drop=true handles cleanup
                            if let Some(tokens) = inner.ref_tokens.remove(&handle_for_reader) {
                                for t in &tokens {
                                    inner.token_to_handle.remove(t);
                                }
                            }
                            if inner.active.as_deref() == Some(handle_for_reader.as_str()) {
                                inner.active = inner.workers.keys().next().cloned();
                            }
                            warn!(
                                "Worker {} removed from registry after unexpected exit",
                                handle_for_reader
                            );
                        }
                        break;
                    }
                    Ok(_) => {
                        let trimmed = line_buf.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<RpcResponse>(trimmed) {
                            Ok(resp) => {
                                let mut inner = inner_arc.lock().await;
                                if let Some(worker) = inner.workers.get_mut(&handle_for_reader) {
                                    if let Some(sender) = worker.pending.remove(&resp.id) {
                                        let result = if let Some(result) = resp.result {
                                            Ok(result)
                                        } else if let Some(err) = resp.error {
                                            Err(err.message)
                                        } else {
                                            Ok(serde_json::Value::Null)
                                        };
                                        let _ = sender.send(result);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Worker {} sent non-JSON line: {} (error: {})",
                                    handle_for_reader, trimmed, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!("Worker {} stdout read error: {}", handle_for_reader, e);
                        let mut inner = inner_arc.lock().await;
                        if let Some(worker) = inner.workers.get_mut(&handle_for_reader) {
                            for (id, sender) in worker.pending.drain() {
                                let _ = sender.send(Err(format!(
                                    "Worker {} I/O error: {}",
                                    handle_for_reader, e
                                )));
                                debug!("Cancelled pending request {} due to I/O error", id);
                            }
                        }
                        if let Some(dead) = inner.workers.remove(&handle_for_reader) {
                            if let Some(path) = &dead.open_path {
                                inner.path_to_handle.remove(&Self::worker_key(
                                    path.clone(),
                                    &dead.tenant_id,
                                ));
                            }
                        }
                        if let Some(tokens) = inner.ref_tokens.remove(&handle_for_reader) {
                            for t in &tokens {
                                inner.token_to_handle.remove(t);
                            }
                        }
                        if inner.active.as_deref() == Some(handle_for_reader.as_str()) {
                            inner.active = inner.workers.keys().next().cloned();
                        }
                        warn!(
                            "Worker {} removed from registry after I/O error",
                            handle_for_reader
                        );
                        break;
                    }
                }
            }
        });

        inner.path_to_handle.insert(worker_key, handle.clone());
        inner
            .token_to_handle
            .insert(close_token.clone(), handle.clone());
        let mut init_refs = HashSet::new();
        init_refs.insert(close_token.clone());
        inner.ref_tokens.insert(handle.clone(), init_refs);
        inner.workers.insert(handle.clone(), worker);
        inner.active = Some(handle.clone());

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
        use crate::error::ToolError;

        let target_handle = {
            let inner = self.inner.lock().await;
            if let Some(h) = handle {
                if !inner.workers.contains_key(h) {
                    return Err(ToolError::InvalidParams(format!("Unknown db_handle: {h}")));
                }
                h.to_string()
            } else {
                if inner.workers.len() > 1 {
                    return Err(ToolError::InvalidParams(
                        "db_handle is required when multiple databases are open. \
                         Provide the db_handle returned by open_idb."
                            .to_string(),
                    ));
                }
                inner.active.clone().ok_or(ToolError::NoDatabaseOpen)?
            }
        };

        let req_id = {
            let mut inner = self.inner.lock().await;
            let id = format!("r{}", inner.req_counter);
            inner.req_counter += 1;
            id
        };

        let max_timeout = if method == "open" { 3600 } else { 600 };
        let timeout_secs = params
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(120)
            .min(max_timeout);

        let (tx, rx) = oneshot::channel::<Result<serde_json::Value, String>>();

        {
            let mut inner = self.inner.lock().await;
            let tenant_id = inner
                .workers
                .get(&target_handle)
                .map(|worker| worker.tenant_id.clone())
                .ok_or_else(|| {
                    ToolError::InvalidParams(format!("Worker {} not found", target_handle))
                })?;
            let tenant_pending = inner
                .workers
                .values()
                .filter(|candidate| candidate.tenant_id == tenant_id)
                .map(|candidate| candidate.pending.len())
                .sum::<usize>();
            if tenant_pending >= self.config.max_pending_per_tenant {
                return Err(ToolError::Busy);
            }

            let worker = inner.workers.get_mut(&target_handle).ok_or_else(|| {
                ToolError::InvalidParams(format!("Worker {} not found", target_handle))
            })?;
            if worker.pending.len() >= self.config.max_pending_per_worker {
                return Err(ToolError::Busy);
            }

            let req = RpcRequest::new(&req_id, method, params);
            let json = serde_json::to_string(&req)
                .map_err(|e| ToolError::InvalidParams(format!("Serialize error: {e}")))?;

            worker
                .writer
                .write_all(json.as_bytes())
                .await
                .map_err(|_| ToolError::WorkerClosed)?;
            worker
                .writer
                .write_all(b"\n")
                .await
                .map_err(|_| ToolError::WorkerClosed)?;
            worker
                .writer
                .flush()
                .await
                .map_err(|_| ToolError::WorkerClosed)?;

            worker.pending.insert(req_id.clone(), tx);
            worker.last_active = Instant::now();
        }

        let timeout = std::time::Duration::from_secs(timeout_secs);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(Ok(Err(e))) => Err(ToolError::IdaError(e)),
            Ok(Err(_)) => Err(ToolError::WorkerClosed),
            Err(_) => Err(ToolError::Timeout(timeout_secs)),
        }
    }

    pub async fn close_worker(&self, handle: &str) -> Result<(), crate::error::ToolError> {
        let mut inner = self.inner.lock().await;
        self.warm_pool.lock().await.retain(|_, lease| lease.handle != handle);

        if let Some(mut worker) = inner.workers.remove(handle) {
            if let Some(path) = &worker.open_path {
                inner.path_to_handle.remove(&Self::worker_key(
                    path.clone(),
                    &worker.tenant_id,
                ));
            }
            if let Some(tokens) = inner.ref_tokens.remove(handle) {
                for token in &tokens {
                    inner.token_to_handle.remove(token);
                }
            }
            if inner.active.as_deref() == Some(handle) {
                inner.active = inner.workers.keys().next().cloned();
            }
            for (id, sender) in worker.pending.drain() {
                let _ = sender.send(Err(format!("Worker {handle} closed")));
                debug!("Cancelled pending request {id} due to close_worker");
            }
            drop(worker);
            info!("Closed worker {}", handle);
        }

        Ok(())
    }

    /// Release a reference token. Returns `Some((handle, remaining))` if the token was valid:
    /// `remaining > 0` means other clients still hold refs (do NOT close the worker),
    /// `remaining == 0` means last reference released (caller should close the worker).
    /// Returns `None` if the token was not found (invalid or already released).
    pub async fn release_ref_token(&self, token: &str) -> Option<(DbHandle, usize)> {
        let mut inner = self.inner.lock().await;
        let handle = inner.token_to_handle.remove(token)?;
        let remaining = if let Some(set) = inner.ref_tokens.get_mut(&handle) {
            set.remove(token);
            set.len()
        } else {
            0
        };
        Some((handle, remaining))
    }

    pub async fn handle_for_token(&self, token: &str) -> Option<DbHandle> {
        let inner = self.inner.lock().await;
        inner.token_to_handle.get(token).cloned()
    }

    pub async fn active_handle(&self) -> Option<DbHandle> {
        let inner = self.inner.lock().await;
        inner.active.clone()
    }

    pub async fn all_handles(&self) -> Vec<DbHandle> {
        let inner = self.inner.lock().await;
        inner.workers.keys().cloned().collect()
    }

    pub async fn worker_count(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.workers.len()
    }

    pub async fn status_snapshot(&self) -> RouterStatus {
        let runtime_probe = match self.cached_probe.lock().await.clone() {
            Some(probe) => Some(probe),
            None => {
                let exe_path = {
                    let inner = self.inner.lock().await;
                    inner.exe_path.clone()
                };
                self.probe_worker_backend(&exe_path).await.ok()
            }
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
                    .or_default() += worker.pending.len();
                WorkerStatus {
                    handle: handle.clone(),
                    backend: backend_name,
                    tenant_id: worker.tenant_id.clone(),
                    pid: worker.child.id(),
                    open_path: worker.open_path.as_ref().map(|p| p.display().to_string()),
                    pending_requests: worker.pending.len(),
                    ref_count: inner.ref_tokens.get(handle).map(|s| s.len()).unwrap_or(0),
                    idle_secs: worker.last_active.elapsed().as_secs(),
                    active: inner.active.as_deref() == Some(handle.as_str()),
                }
            })
            .collect();

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
            .filter_map(|task| task_state_json(&task))
            .collect();

        RouterStatus {
            worker_count: inner.workers.len(),
            active_handle: inner.active.clone(),
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
            idb_cache: crate::idb_store::IdbStore::new().stats(),
            response_cache: crate::server::response_cache::stats(),
        }
    }

    pub async fn shutdown_all(&self) {
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let nonce = inner.req_counter;
        inner.req_counter += 1;
        let token = format!("cli-{now:x}-{nonce:x}");

        inner
            .token_to_handle
            .insert(token.clone(), handle.to_string());
        inner
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
        use crate::error::ToolError;
        let tenant_id = Self::normalize_tenant(tenant_id);

        // Resolve sBPF .so → host-native dylib/i64 path for IDA.
        let resolved = resolve_open_path(path);
        let open_path = resolved.open_path.as_deref().unwrap_or(path);

        let canonical =
            std::fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from(path));
        let canonical_open = std::fs::canonicalize(open_path)
            .unwrap_or_else(|_| std::path::PathBuf::from(open_path));
        let worker_key = Self::worker_key(canonical.clone(), &tenant_id);

        let handle = {
            let mut inner = self.inner.lock().await;
            if let Some(h) = inner.path_to_handle.get(&worker_key).cloned() {
                if let Some(worker) = inner.workers.get_mut(&h) {
                    worker.last_active = Instant::now();
                }
                Some(h)
            } else {
                None
            }
        };

        let handle = if let Some(h) = handle {
            h
        } else {
            let (h, initial_token) = self
                .spawn_worker(path, Some(&tenant_id))
                .await
                .map_err(|e| ToolError::IdaError(format!("spawn_worker failed: {e}")))?;

            if let Some(token) = initial_token {
                self.release_ref_token(&token).await;
            }

            let effective_idb_output = explicit_idb_output
                .map(String::from)
                .or(resolved.idb_output_path);
            let open_params = serde_json::json!({
                "path": canonical_open.display().to_string(),
                "idb_output_path": effective_idb_output,
                "auto_analyse": true,
                "timeout_secs": 3600,
            });
            match self.route_request(Some(&h), "open", open_params).await {
                Ok(_) => {
                    if let Some(ref idb_out) = effective_idb_output {
                        let store = crate::idb_store::IdbStore::new();
                        store.record(&canonical, &std::path::PathBuf::from(idb_out));
                    }
                    if is_sbpf_elf(&canonical) {
                        self.detect_and_rename_sbpf_entry(&h).await;
                    }
                }
                Err(e) => {
                    warn!(handle = %h, error = %e, "open failed, cleaning up worker");
                    let _ = self.close_worker(&h).await;
                    return Err(e);
                }
            }
            h
        };

        let ref_token = self.issue_ref_for_handle(&handle).await;

        Ok((handle, ref_token))
    }

    async fn detect_and_rename_sbpf_entry(&self, handle: &str) {
        let ep_addr: Option<u64> = self
            .route_request(
                Some(handle),
                "get_function_by_name",
                serde_json::json!({"name": "entrypoint"}),
            )
            .await
            .ok()
            .and_then(|v| v.get("address")?.as_str().map(String::from))
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());

        let Some(ep_addr) = ep_addr else { return };
        let ep_hex = format!("0x{:x}", ep_addr);

        let cg_val = match self
            .route_request(
                Some(handle),
                "build_callgraph",
                serde_json::json!({"roots": ep_hex, "max_depth": 2, "max_nodes": 256}),
            )
            .await
        {
            Ok(v) => v,
            Err(_) => return,
        };

        let edges = match cg_val.get("edges").and_then(|v| v.as_array()) {
            Some(e) => e.clone(),
            None => return,
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
            return;
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
            return;
        }
        let pi_hex = if c0 > c1 { direct[0] } else { direct[1] };

        let _ = self
            .route_request(
                Some(handle),
                "rename_symbol",
                serde_json::json!({"address": pi_hex, "new_name": "process_instruction"}),
            )
            .await;

        info!(handle = %handle, pi = %pi_hex, "sBPF: renamed process_instruction");
    }

    pub async fn close_by_path(
        &self,
        path: &std::path::Path,
        tenant_id: Option<&str>,
    ) -> Result<(), crate::error::ToolError> {
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
        self.prewarm_path_with_options(path, false, "default")
            .await
    }

    pub async fn prewarm_path_with_options(
        &self,
        path: &str,
        keep_warm: bool,
        tenant_id: &str,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        use crate::error::ToolError;

        let expanded = crate::expand_path(path);
        if !expanded.exists() {
            return Err(ToolError::InvalidPath(format!(
                "File not found: {}",
                expanded.display()
            )));
        }

        let canonical = std::fs::canonicalize(&expanded).unwrap_or_else(|_| expanded.clone());
        let tenant_id = Self::normalize_tenant(Some(tenant_id));
        let already_open = {
            let inner = self.inner.lock().await;
            inner
                .path_to_handle
                .contains_key(&Self::worker_key(canonical.clone(), &tenant_id))
        };

        let store = crate::idb_store::IdbStore::new();
        let cached_before = store.lookup(&canonical).map(|p| p.display().to_string());

        let (handle, ref_token) = self.ensure_worker_with_ref(path, Some(&tenant_id)).await?;
        let backend = {
            let inner = self.inner.lock().await;
            inner
                .workers
                .get(&handle)
                .map(|worker| worker.backend.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        };

        let database_info = self
            .route_request(Some(&handle), "get_database_info", serde_json::json!({}))
            .await
            .ok();

        let cached_after = store.lookup(&canonical).map(|p| p.display().to_string());

        let mut closed_worker = false;
        let mut kept_warm = false;
        if keep_warm {
            self.install_warm_lease(
                canonical.clone(),
                handle.clone(),
                ref_token.clone(),
                tenant_id.to_string(),
                cached_after.as_ref().map(PathBuf::from),
            )
            .await?;
            kept_warm = true;
        } else if !already_open {
            if let Some((_, remaining)) = self.release_ref_token(&ref_token).await {
                if remaining == 0 {
                    self.close_by_path(&canonical, Some(&tenant_id)).await?;
                    closed_worker = true;
                }
            }
        } else {
            self.release_ref_token(&ref_token).await;
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

    async fn install_warm_lease(
        &self,
        canonical_path: PathBuf,
        handle: DbHandle,
        token: String,
        tenant_id: String,
        cache_path: Option<PathBuf>,
    ) -> Result<(), crate::error::ToolError> {
        while self.warm_pool.lock().await.len() >= self.config.max_warm_workers {
            let candidate = {
                self.warm_pool
                    .lock()
                    .await
                    .iter()
                    .min_by_key(|(_, lease)| lease.last_hit)
                    .map(|(path, _)| path.clone())
            };
            let Some(path) = candidate else { break };
            self.release_warm_lease(&path).await?;
        }

        let lease = WarmLease {
            handle,
            token,
            path: canonical_path.clone(),
            cache_path,
            tenant_id,
            pinned_at: Instant::now(),
            last_hit: Instant::now(),
        };
        self.warm_pool.lock().await.insert(canonical_path, lease);
        Ok(())
    }

    async fn release_warm_lease(
        &self,
        path: &PathBuf,
    ) -> Result<(), crate::error::ToolError> {
        if let Some(lease) = self.warm_pool.lock().await.remove(path) {
            if let Some((handle, remaining)) = self.release_ref_token(&lease.token).await {
                if remaining == 0 {
                    self.close_worker(&handle).await?;
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
            Err(existing) => existing,
        };

        if self.task_registry.get(&task_id).is_some() && !queue.active.contains_key(&task_id) {
            queue.queued.push(QueuedRouteTask {
                task_id: task_id.clone(),
                path: path.to_string(),
                method: method.to_string(),
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

    pub fn task_state(&self, task_id: &str) -> Option<TaskState> {
        self.task_registry.get(task_id)
    }

    pub fn list_task_states(&self) -> Vec<TaskState> {
        self.task_registry.list_all()
    }

    pub async fn cancel_task(&self, task_id: &str) -> bool {
        if self.task_registry.cancel(task_id) {
            return true;
        }

        let mut queue = self.route_queue.lock().await;
        if let Some(idx) = queue.queued.iter().position(|task| task.task_id == task_id) {
            queue.queued.remove(idx);
            self.task_registry.fail(task_id, "Cancelled before execution");
            return true;
        }
        false
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
                        queue.tenant_active
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
                let result = async {
                    let (handle, token) =
                        state.ensure_worker_with_ref(&task.path, Some(&task.tenant_id)).await?;
                    let value = state
                        .route_request(Some(&handle), &task.method, task.params.clone())
                        .await?;
                    state.release_ref_token(&token).await;
                    Ok::<serde_json::Value, crate::error::ToolError>(value)
                }
                .await;

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
                    Ok(value) => state.task_registry.complete(&task.task_id, value),
                    Err(err) => state.task_registry.fail(&task.task_id, &err.to_string()),
                }
            });
        }
    }

    async fn prune_caches(&self) {
        let warm_pool = self.warm_pool.lock().await;
        let pinned_groups: HashSet<String> = warm_pool
            .values()
            .filter_map(|lease| lease.cache_path.as_ref())
            .map(|path| path.with_extension("").display().to_string())
            .collect();
        drop(warm_pool);

        let _ = crate::idb_store::IdbStore::new()
            .evict_to_limit(self.config.max_idb_cache_bytes, &pinned_groups);
        let _ = crate::server::response_cache::prune_to_limit(self.config.max_response_cache_bytes);
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
                            let ref_count =
                                inner.ref_tokens.get(*h).map(|set| set.len()).unwrap_or(0);
                            ref_count == 0
                                && w.pending.is_empty()
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

fn task_state_json(state: &TaskState) -> Option<serde_json::Value> {
    let status = match state.status {
        TaskStatus::Running => "running",
        TaskStatus::Completed => "completed",
        TaskStatus::Failed => "failed",
        TaskStatus::Cancelled => "cancelled",
    };
    Some(serde_json::json!({
        "task_id": state.id,
        "status": status,
        "message": state.message,
        "created_at": state.created_at_iso,
        "updated_at": state.updated_at_iso,
        "result": state.result,
    }))
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

struct ResolvedPath {
    /// Path to pass to IDA for opening (may be .i64, .dylib, or the original binary)
    open_path: Option<String>,
    /// Where the .i64 should be saved (centralized path, only when not already cached)
    idb_output_path: Option<String>,
}

fn resolve_open_path(path: &str) -> ResolvedPath {
    let input = crate::expand_path(path);
    let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");

    // Already an IDA database — open directly
    if ext == "i64" || ext == "idb" {
        return ResolvedPath {
            open_path: None,
            idb_output_path: None,
        };
    }

    let store = crate::idb_store::IdbStore::new();

    // Check centralized IDB store first
    if let Some(cached) = store.lookup(&input) {
        info!(path = %cached.display(), "IDB store hit for {}", input.display());
        return ResolvedPath {
            open_path: Some(cached.display().to_string()),
            idb_output_path: None,
        };
    }

    // sBPF ELF handling
    if is_sbpf_elf(&input) {
        let i64_path = store.idb_path(&input);
        if let Some(open_path) = resolve_sbpf_path(&input, &i64_path) {
            return ResolvedPath {
                open_path: Some(open_path),
                idb_output_path: None,
            };
        }
        return ResolvedPath {
            open_path: None,
            idb_output_path: None,
        };
    }

    // Native binary — check for existing .i64 beside it (legacy location)
    let i64_path = input.with_extension("i64");
    let id0_path = input.with_extension("id0");
    if i64_path.exists() {
        info!(path = %i64_path.display(), "Fast-path: existing .i64 for raw binary");
        return ResolvedPath {
            open_path: Some(i64_path.display().to_string()),
            idb_output_path: None,
        };
    }
    if id0_path.exists() {
        info!(path = %input.display(), "Fast-path: existing unpacked .id0 for raw binary");
        return ResolvedPath {
            open_path: Some(input.display().to_string()),
            idb_output_path: None,
        };
    }

    // No existing IDB — will be newly analyzed, store in centralized location
    let idb_output = store.idb_path(&input).display().to_string();
    ResolvedPath {
        open_path: None,
        idb_output_path: Some(idb_output),
    }
}

fn resolve_sbpf_path(input: &std::path::Path, i64_path: &std::path::Path) -> Option<String> {
    info!(path = %input.display(), "Detected sBPF ELF, running sbx aot i64");

    if i64_path.exists() {
        info!(path = %i64_path.display(), "sBPF fast-path: existing .i64");
        return Some(i64_path.display().to_string());
    }

    match crate::sbpf::run_sbx_aot_i64(input, i64_path) {
        Ok(result) => {
            info!(i64 = %result.i64_path.display(), "sbx aot i64 succeeded");
            Some(result.i64_path.display().to_string())
        }
        Err(e) => {
            warn!(error = %e, "sbx aot i64 failed; cannot open sBPF program");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn test_route_request_no_active_fails() {
        let router = RouterState::new().unwrap();
        let result = router
            .route_request(None, "list_functions", serde_json::json!({}))
            .await;
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "requires IDA Pro license and compiled binary"]
    fn test_worker_subprocess_responds() {}

    #[test]
    #[ignore = "requires IDA Pro license and compiled binary"]
    fn test_worker_eof_graceful_shutdown() {}
}
