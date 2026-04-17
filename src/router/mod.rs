//! Multi-IDB Router — manages worker subprocesses.
//!
//! Architecture:
//! - Each open IDB gets a `WorkerProcess` running `ida-cli serve-worker`
//! - Requests are routed to workers via JSON-RPC over stdin/stdout
//! - Router maintains an "active" handle for backward compatibility

pub mod protocol;

use crate::ida::{RuntimeProbeResult, WorkerBackendKind};
use crate::router::protocol::{RpcRequest, RpcResponse};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::Command;
use tokio::process::{Child, ChildStdin};
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, error, info, warn};

pub type DbHandle = String;
pub type ReqId = String;

pub struct WorkerProcess {
    pub backend: WorkerBackendKind,
    pub child: Child,
    pub writer: BufWriter<ChildStdin>,
    pub pending: HashMap<ReqId, oneshot::Sender<Result<serde_json::Value, String>>>,
    pub close_token: Option<String>,
    pub open_path: Option<PathBuf>,
    pub last_active: Instant,
}

#[derive(Clone)]
pub struct RouterState {
    inner: Arc<Mutex<RouterInner>>,
}

impl std::fmt::Debug for RouterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterState").finish_non_exhaustive()
    }
}

struct RouterInner {
    workers: HashMap<DbHandle, WorkerProcess>,
    active: Option<DbHandle>,
    path_to_handle: HashMap<PathBuf, DbHandle>,
    token_to_handle: HashMap<String, DbHandle>,
    ref_tokens: HashMap<DbHandle, HashSet<String>>,
    req_counter: u64,
    exe_path: PathBuf,
}

impl RouterState {
    pub fn new() -> anyhow::Result<Self> {
        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ida-cli"));

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
        exe_path: &std::path::Path,
    ) -> Result<RuntimeProbeResult, anyhow::Error> {
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

        serde_json::from_str::<RuntimeProbeResult>(&stdout).map_err(|e| {
            anyhow::anyhow!(
                "failed to parse probe-runtime output: {e}; stdout={stdout:?}; stderr={stderr:?}"
            )
        })
    }

    /// Spawn a new worker subprocess for the given IDB path.
    /// Returns the db_handle (existing handle if file already open).
    pub async fn spawn_worker(
        &self,
        path: &str,
    ) -> Result<(DbHandle, Option<String>), anyhow::Error> {
        let canonical_path = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));

        let exe_path = {
            let mut inner = self.inner.lock().await;

            if let Some(existing_handle) = inner.path_to_handle.get(&canonical_path).cloned() {
                info!(
                    "Path {:?} already open with handle {}, issuing new ref token",
                    canonical_path, existing_handle
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
        let probe = Self::probe_worker_backend(&exe_path).await?;
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

        let mut inner = self.inner.lock().await;
        if let Some(existing_handle) = inner.path_to_handle.get(&canonical_path).cloned() {
            info!(
                "Path {:?} became active while probing backend; reusing handle {}",
                canonical_path, existing_handle
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
                                inner.path_to_handle.remove(path);
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
                                inner.path_to_handle.remove(path);
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

        inner.path_to_handle.insert(canonical_path, handle.clone());
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
            let worker = inner.workers.get_mut(&target_handle).ok_or_else(|| {
                ToolError::InvalidParams(format!("Worker {} not found", target_handle))
            })?;

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

        if let Some(mut worker) = inner.workers.remove(handle) {
            if let Some(path) = &worker.open_path {
                inner.path_to_handle.remove(path);
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
    ) -> Result<(DbHandle, String), crate::error::ToolError> {
        self.ensure_worker_with_ref_idb(path, None).await
    }

    pub async fn ensure_worker_with_ref_idb(
        &self,
        path: &str,
        explicit_idb_output: Option<&str>,
    ) -> Result<(DbHandle, String), crate::error::ToolError> {
        use crate::error::ToolError;

        // Resolve sBPF .so → host-native dylib/i64 path for IDA.
        let resolved = resolve_open_path(path);
        let open_path = resolved.open_path.as_deref().unwrap_or(path);

        let canonical =
            std::fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from(path));
        let canonical_open = std::fs::canonicalize(open_path)
            .unwrap_or_else(|_| std::path::PathBuf::from(open_path));

        let handle = {
            let mut inner = self.inner.lock().await;
            if let Some(h) = inner.path_to_handle.get(&canonical).cloned() {
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
                .spawn_worker(path)
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
    ) -> Result<(), crate::error::ToolError> {
        let handle = {
            let inner = self.inner.lock().await;
            inner.path_to_handle.get(path).cloned()
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

    /// `auto_exit_grace`: `Some(duration)` → exit when no workers remain for that
    /// long. `None` → disable auto-exit (stdio MCP mode).
    pub fn start_watchdog(
        &self,
        idle_timeout: Duration,
        check_interval: Duration,
        auto_exit_grace: Option<Duration>,
    ) {
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
