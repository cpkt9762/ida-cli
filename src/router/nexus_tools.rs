//! N4 tool wiring. The development-only selector is removed in N9.
mod owner_resources;
use super::{nexus_bridge::BridgeConfig, RouterState};
use crate::{error::ToolError, nexus::*, preprocess::Preparation};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Semaphore};

pub const METHODS: &[&str] = &[
    "wait_owner_exit",
    "get_database_info",
    "get_analysis_status",
    "list_functions",
    "get_function_by_name",
    "get_function_at_address",
    "get_xrefs_to",
    "get_xrefs_from",
    "disassemble",
    "disassemble_function",
    "disassemble_function_at",
    "decompile_function",
    "run_script",
    "batch_decompile",
    "search_pseudocode",
    "run_auto_analysis",
    "list_local_types",
    "declare_c_type",
    "apply_type",
    "infer_type",
    "set_function_prototype",
    "get_function_prototype",
    "get_stack_frame",
    "create_stack_variable",
    "delete_stack_variable",
    "rename_stack_variable",
    "set_stack_variable_type",
    "list_enums",
    "create_enum",
    "set_comment",
    "set_function_comment",
    "rename_symbol",
    "patch_bytes",
    "patch_assembly",
    "rename_local_variable",
    "set_local_variable_type",
    "set_decompiler_comment",
    "read_bytes",
    "read_int",
    "read_string",
    "get_basic_blocks",
    "get_callers",
    "get_callees",
    "build_callgraph",
    "find_control_flow_paths",
    "build_xref_matrix",
    "list_segments",
    "list_imports",
    "list_exports",
    "list_entry_points",
    "list_structs",
    "get_struct_info",
    "read_struct_at_address",
    "get_xrefs_to_struct_field",
    "batch_lookup_functions",
    "export_functions",
    "list_globals",
    "read_global_variable",
    "list_strings",
    "get_xrefs_to_string",
    "get_address_info",
    "scan_memory_table",
    "diff_pseudocode",
    "get_pseudocode_at",
    "load_debug_info",
    "search_bytes",
    "search_text",
    "search_imm",
    "search_instructions",
    "search_instruction_operands",
    "batch_rename",
];
tokio::task_local! { pub(crate) static CURRENT_TASK_ID: TaskId; }

static IDS: AtomicU64 = AtomicU64::new(1);
fn id() -> String {
    format!(
        "n4-{}-{}",
        std::process::id(),
        IDS.fetch_add(1, Ordering::Relaxed)
    )
}
fn diagnostic(error: impl std::fmt::Display) -> ToolError {
    ToolError::IdaError(format!("Nexus: {error}"))
}

#[derive(Clone)]
struct Database {
    path: PathBuf,
    lease: SessionLease,
    idb: String,
    token: String,
    pid: Option<u32>,
    opened_at: Instant,
    last_active: Instant,
    cache_hit: bool,
    client: super::listing::ClientIdentity,
    opener: super::listing::ClientIdentity,
    origin: String,
    opened_wall: std::time::SystemTime,
    _cache_guard: Arc<super::nexus_bridge::cache_lock::CacheGuard>,
}
#[derive(Clone)]
struct CleanupReference {
    handle: String,
    path: PathBuf,
    lease: SessionLease,
    _cache_guard: Option<Arc<super::nexus_bridge::cache_lock::CacheGuard>>,
}
pub struct Tools {
    selected: bool,
    databases: Mutex<HashMap<String, Database>>,
    owner_resources: Mutex<HashMap<String, owner_resources::OwnerResources>>,
    owner_diagnostics: Mutex<HashMap<SessionLease, PathBuf>>,
    cleanup_records: Mutex<HashMap<String, CleanupReference>>,
    capacity: Arc<Semaphore>,
    paths: Mutex<HashMap<PathBuf, std::sync::Weak<tokio::sync::Mutex<()>>>>,
    operations: Mutex<Vec<OperationIdentity>>,
    uncertain_cache: Arc<Mutex<Vec<Arc<RetainedOpen>>>>,
    close_observers: Mutex<HashSet<SessionLease>>,
}
impl Tools {
    pub fn new(capacity: usize) -> anyhow::Result<Self> {
        // N9 MUST DELETE: migration validation only; default keeps the old path.
        let selected = match std::env::var("IDA_CLI_NEXUS_DEV") {
            Err(std::env::VarError::NotPresent) => false,
            Ok(value) if value == "1" => true,
            _ => anyhow::bail!("IDA_CLI_NEXUS_DEV must be unset or 1 (N9 removal)"),
        };
        Ok(Self {
            selected,
            databases: Mutex::new(HashMap::new()),
            owner_resources: Mutex::default(),
            owner_diagnostics: Mutex::default(),
            cleanup_records: Mutex::default(),
            capacity: Arc::new(Semaphore::new(capacity)),
            paths: Mutex::new(HashMap::new()),
            operations: Mutex::new(Vec::new()),
            uncertain_cache: Arc::default(),
            close_observers: Mutex::default(),
        })
    }
    pub fn selected(&self) -> bool {
        self.selected
    }
    fn records(&self) -> std::sync::MutexGuard<'_, HashMap<String, Database>> {
        self.databases.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn handles(&self) -> Vec<String> {
        self.records().keys().cloned().collect()
    }
    pub fn workers(&self, router: &RouterState) -> Vec<super::WorkerStatus> {
        let operations = self
            .operations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let endpoint = router.nexus_endpoint();
        let records = self.records();
        let mut workers = BTreeMap::<String, super::WorkerStatus>::new();
        for (handle, db) in records.iter() {
            let worker = workers
                .entry(db.lease.instance_id.as_str().into())
                .or_insert_with(|| super::WorkerStatus {
                    handle: handle.clone(),
                    backend: "nexus".into(),
                    tenant_id: "default".into(),
                    pid: db.pid,
                    open_path: Some(db.path.display().to_string()),
                    pending_requests: 0,
                    ref_count: 0,
                    idle_secs: db.last_active.elapsed().as_secs(),
                    active: true,
                });
            worker.idle_secs = worker.idle_secs.min(db.last_active.elapsed().as_secs());
            worker.ref_count += 1;
            worker.pending_requests += operations.iter().filter(|identity| identity.lease == db.lease).filter(|identity| {
                match endpoint.transition(|s,_|s.operation_progress(&identity.lease.client_id,identity)) {
                    Ok(snapshot) => !snapshot.status.is_terminal() || !snapshot.execution_stopped,
                    Err(error) => { tracing::warn!(%error,"Nexus status could not confirm tracked operation stopped"); true }
                }
            }).count();
        }
        workers.into_values().collect()
    }
    pub fn set_client(&self, handle: &str, client: &super::listing::ClientIdentity) {
        let mut records = self.records();
        let origin = records
            .get(handle)
            .filter(|db| db.origin == handle)
            .map(|db| db.origin.clone());
        if let Some(db) = records.get_mut(handle) {
            db.client = client.clone();
        }
        if let Some(origin) = origin {
            for db in records.values_mut().filter(|db| db.origin == origin) {
                db.opener = client.clone();
            }
        }
    }

    pub fn list_idbs(
        &self,
        caller: Option<&super::listing::ClientIdentity>,
    ) -> super::listing::IdbListing {
        use super::listing::{DbState, IdbListing, ListedHolder, ListedIdb, ListedWorker};
        let records = self.records();
        let mut groups = BTreeMap::<&str, Vec<(&String, &Database)>>::new();
        for (handle, db) in records.iter() {
            groups
                .entry(db.lease.instance_id.as_str())
                .or_default()
                .push((handle, db));
        }
        let active = records.keys().max();
        let mut idbs = Vec::new();
        for mut group in groups.into_values() {
            group.sort_by_key(|(handle, db)| (db.opened_at, *handle));
            let (handle, db) = group[0];
            let mut holders = BTreeMap::<&str, ListedHolder>::new();
            for (_, lease) in &group {
                holders
                    .entry(lease.client.client_id.as_str())
                    .and_modify(|h| h.refs += 1)
                    .or_insert_with(|| ListedHolder {
                        client: lease.client.clone(),
                        refs: 1,
                        is_caller: caller == Some(&lease.client),
                    });
            }
            idbs.push(ListedIdb {
                db_handle: handle.clone(),
                state: DbState::Open,
                input_path: Some(db.path.display().to_string()),
                idb_path: Some(db.idb.clone()),
                opened_by: db.opener.clone(),
                opened_by_caller: caller == Some(&db.opener),
                opened_at: Some(crate::server::task::iso_from_system_time(db.opened_wall)),
                open_secs: db
                    .opened_wall
                    .elapsed()
                    .ok()
                    .map(|elapsed| elapsed.as_secs()),
                idle_secs: group
                    .iter()
                    .map(|(_, db)| db.last_active)
                    .max()
                    .map_or(0, |activity| activity.elapsed().as_secs()),
                worker: ListedWorker {
                    pid: db.pid,
                    backend: "nexus".into(),
                },
                active: group.iter().any(|(h, _)| Some(*h) == active),
                ref_count: group.len(),
                holders: holders.into_values().collect(),
            });
        }
        idbs.sort_by(|a, b| {
            a.opened_at
                .cmp(&b.opened_at)
                .then_with(|| a.db_handle.cmp(&b.db_handle))
        });
        IdbListing::new(idbs)
    }

    pub fn active(&self) -> Option<String> {
        self.handles().into_iter().max()
    }
    pub fn handle_for_token(&self, token: &str) -> Option<String> {
        self.records()
            .iter()
            .find(|(_, db)| db.token == token)
            .map(|(h, _)| h.clone())
    }
    pub fn cache_hit(&self, handle: &str) -> Result<bool, ToolError> {
        self.records()
            .get(handle)
            .map(|db| db.cache_hit)
            .ok_or(ToolError::NoDatabaseOpen)
    }
    fn path_gate(&self, path: &Path) -> Arc<tokio::sync::Mutex<()>> {
        let mut paths = self.paths.lock().unwrap_or_else(|e| e.into_inner());
        paths.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = paths.get(path).and_then(std::sync::Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        paths.insert(path.to_path_buf(), Arc::downgrade(&gate));
        gate
    }
    async fn bridge(
        router: &RouterState,
    ) -> Result<Arc<super::nexus_bridge::NexusBridge>, ToolError> {
        let required = |name| {
            std::env::var_os(name).map(PathBuf::from).ok_or_else(|| {
                diagnostic(format!("{name} is required for isolated Nexus development"))
            })
        };
        let python = required("IDA_NEXUS_PYTHON")?;
        let ipc = required("IDA_NEXUS_IPC_ROOT")?;
        let script = std::env::var_os("IDA_NEXUS_BRIDGE_SCRIPT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("nexus_bridge/bridge.py")
            });
        let environment: BTreeMap<_, _> = std::env::vars().collect();
        router
            .connect_nexus(BridgeConfig {
                python,
                script,
                directory: ipc.join(id()),
                environment,
            })
            .await
            .map_err(diagnostic)
    }
    pub fn require(method: &str) -> Result<(), ToolError> {
        if METHODS.contains(&method) {
            Ok(())
        } else {
            Err(NexusError::new(
                NexusErrorCode::UnsupportedCapability,
                format!("method {method} is not implemented by Nexus; no legacy fallback"),
            )
            .into())
        }
    }
    pub fn require_tool(method: &str) -> Result<(), ToolError> {
        if method == "list_idbs" {
            return Ok(());
        }
        // These existing MCP adapters generate Python and route run_script.
        // Database execution still passes the same Execute capability check.
        if matches!(method, "decompile_structured" | "search_structs")
            || (method.starts_with("dbg_") && crate::tool_registry::get_tool(method).is_some())
        {
            Self::require("run_script")
        } else if matches!(
            method,
            "read_byte" | "read_word" | "read_dword" | "read_qword"
        ) {
            Self::require("read_int")
        } else {
            Self::require(method)
        }
    }
    pub async fn open(
        self: &Arc<Self>,
        router: &RouterState,
        path: &str,
        preparation: Preparation,
    ) -> Result<(String, String), ToolError> {
        self.open_refresh(router, path, preparation, false).await
    }
    pub async fn open_refresh(
        self: &Arc<Self>,
        router: &RouterState,
        path: &str,
        preparation: Preparation,
        refresh: bool,
    ) -> Result<(String, String), ToolError> {
        if let Some(bridge) = router.nexus_bridge.get() {
            self.consume_released(bridge);
        }
        self.uncertain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|opening| !opening.cleanup_confirmed());
        if self
            .uncertain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
            >= router.config.max_pending_per_tenant
        {
            return Err(diagnostic("cache maintenance guards retained for uncertain opens; restart after owner recovery"));
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| ToolError::Busy)?;
        let router = router.clone();
        let tools = self.clone();
        let path = crate::expand_path(path);
        // A dropped caller still has a bounded supervisor owning its open attempt.
        let mut cancelled = preparation.cancel_on_drop();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let task_id = CURRENT_TASK_ID.try_with(Clone::clone).ok();
        tokio::spawn(async move {
            let _permit = permit;
            let work = tools.open_owned(&router, path, preparation, refresh);
            let result = match task_id {
                Some(task_id) => CURRENT_TASK_ID.scope(task_id, work).await,
                None => work.await,
            };
            if let Err(error) = &result {
                let category = match error {
                    ToolError::Nexus(_) => "nexus",
                    ToolError::Preparation { .. } => "preparation",
                    ToolError::Timeout(_) | ToolError::RequestOutcome { .. } => "deadline",
                    ToolError::Busy => "busy",
                    ToolError::InvalidPath(_) => "invalid_path",
                    _ => "open_failed",
                };
                tracing::warn!(category, reason = %error, "Nexus open supervisor failed");
            }
            let reference = result
                .as_ref()
                .ok()
                .map(|(_, token)| ReferenceGuard::new(router.clone(), token.clone()));
            // The delivery owns its lease even if the receiver disappears
            // between insertion, send and polling the completed open.
            let _ = sender.send((result, reference));
        });
        let (result, mut reference) = receiver.await.map_err(diagnostic)?;
        if let Some(reference) = &mut reference {
            reference.transfer();
        }
        cancelled.disarm();
        result
    }
    async fn open_owned(
        &self,
        router: &RouterState,
        path: PathBuf,
        preparation: Preparation,
        refresh: bool,
    ) -> Result<(String, String), ToolError> {
        let accepted = accepted("open", json!({"timeout_secs":120}), &preparation)?;
        let (canonical, sbpf) = preparation
            .wait(crate::blocking::run(
                crate::blocking::WorkClass::Prepare,
                move || {
                    let canonical = path
                        .canonicalize()
                        .map_err(|e| ToolError::InvalidPath(format!("{}: {e}", path.display())))?;
                    Ok::<_, ToolError>((canonical, super::is_sbpf_elf(&path)))
                },
            ))
            .await??;
        if sbpf {
            return Err(ToolError::NotSupported(
                "Nexus sBPF preparation belongs to N7".into(),
            ));
        }
        let gate = self.path_gate(&canonical);
        let mut path_guard = Some(preparation.wait(async { Ok(gate.lock().await) }).await?);
        let cache_guard =
            super::nexus_bridge::cache_lock::acquire(&crate::idb_store::idb_root(), &preparation)
                .await?;
        self.wait_draining(router, &canonical, &preparation).await?;
        let endpoint = router.nexus_endpoint();
        let mut prepared = super::nexus_bridge::cache::prepare_n7_open(
            canonical.clone(),
            crate::idb_store::idb_root(),
            &preparation,
            refresh,
        )
        .await?;
        let open_guard = super::nexus_bridge::cache_lock::acquire_open(
            &crate::idb_store::idb_root(),
            &prepared.path,
            &preparation,
        )
        .await?;
        let bridge = preparation.wait(Self::bridge(router)).await?;
        let client = ClientId::new(id())?;
        let operation_id = OperationId::new(id())?;
        let mut reply = bridge.open_reply(&operation_id).map_err(diagnostic)?;
        let identity = bridge.endpoint().transition(|s, t| {
            s.open(
                &client,
                accepted,
                OpenSpec {
                    operation_id: operation_id.clone(),
                    path: prepared.path.to_string_lossy().into_owned(),
                    options: prepared.options.clone(),
                },
                t,
            )
        });
        let identity = match identity {
            Ok(identity) => identity,
            Err(error) => {
                bridge.forget_open_reply(&operation_id);
                return Err(error.into());
            }
        };
        prepared.handed_off();
        let mut ownership = OpeningGuard {
            bridge: bridge.clone(),
            identity: identity.clone(),
            transferred: false,
            cache_guard: cache_guard.clone(),
            uncertain_cache: self.uncertain_cache.clone(),
            open_guard: Some(open_guard),
            content_guard: prepared.content_guard.clone(),
            verification: prepared.verification_cleanup.clone(),
        };
        let mut cancelled = false;
        let mut registered = false;
        loop {
            let (acquired, failure) = bridge
                .endpoint()
                .transition(|s, _| s.open_progress(&client, &identity))?;
            if !registered {
                if let Some(lease) = acquired {
                    let phase = endpoint
                        .transition(|s, _| s.status(&lease.client_id, &lease))?
                        .phase;
                    // Reliable custody already protects this physical IDB. The
                    // index must be committed while content EX is held; analysis
                    // must not keep unrelated callers behind these open locks.
                    if matches!(phase, SessionPhase::Preparing | SessionPhase::Active)
                        && failure.is_none()
                    {
                        prepared.publish_verified_input(&preparation).await?;
                    }
                    ownership.open_guard.take();
                    ownership.content_guard.take();
                    prepared.content_guard.take();
                    path_guard.take();
                    registered = true;
                }
            }
            if let Some(error) = failure {
                return Err(error.into());
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(preparation.deadline.into()) => {
                    return Err(diagnostic("open total deadline expired; late acquisition retained for cleanup; never replay"));
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                _ = preparation.cancel.cancelled(), if !cancelled => {
                    let cancellation = bridge.endpoint().transition(|s,_| s.cancel_open(&client, &identity));
                    match cancellation {
                        Ok(_) => {},
                        // N1 may already have acquired the lease before its
                        // reliable reply is polled. Keep responsibility here.
                        Err(error) if error.code == NexusErrorCode::InvalidTransition => {},
                        Err(error) => return Err(error.into()),
                    }
                    cancelled = true;
                }
                event = &mut reply => {
                    let event = event.map_err(diagnostic)?;
                    if event["event"] == "bridge_disconnected" {
                        return Err(diagnostic("bridge disconnected; open outcome retained by N1; never replay"));
                    }
                    match event["event"].as_str() {
                        Some("opened") => {
                            #[cfg(test)]
                            if std::env::var("N4_F2_OPEN_FAULT").as_deref() == Ok("release-busy") {
                                static FIRST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
                                if FIRST.swap(false, Ordering::SeqCst) { preparation.cancel.cancel(); }
                            }
                            let lease: SessionLease = serde_json::from_value(event["lease"].clone()).map_err(diagnostic)?;
                            if cancelled || preparation.check().is_err() {
                                return Err(diagnostic("open cancelled/expired; acquired lease transferred to bridge cleanup"));
                            }
                            if !registered {
                                prepared.publish_verified_input(&preparation).await?;
                            }
                            preparation.check()?;
                            let handle = id();
                            let token = id();
                            let idb = match event["idb_path"].as_str() {
                                Some(path) => path.to_string(),
                                None => return Err(diagnostic("open missing IDB path; lease retained for bridge cleanup")),
                            };
                            let pid = event["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok());
                            let mut records=self.records();
                            let previous=records.values().find(|db|db.lease.instance_id==lease.instance_id);
                            let (opener,origin,opened_wall)=previous.map(|db|(db.opener.clone(),db.origin.clone(),db.opened_wall))
                                .unwrap_or_else(||(super::listing::ClientIdentity::rpc_tenant(None),handle.clone(),std::time::SystemTime::now()));
                            let now = Instant::now();
                            for db in records.values_mut().filter(|db| db.lease.instance_id == lease.instance_id) {
                                db.last_active = now;
                            }
                            records.insert(handle.clone(), Database { path: canonical, lease, idb, token: token.clone(), pid, opened_at: now, last_active: now, cache_hit:prepared.cache_hit, client:super::listing::ClientIdentity::rpc_tenant(None), opener, origin, opened_wall, _cache_guard:cache_guard.clone() });
                            ownership.transferred = true;
                            return Ok((handle,token));
                        }
                        Some("failed" | "uncertain") => {
                            return Err(diagnostic(event["error"].to_string()));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    pub async fn execute(
        self: &Arc<Self>,
        router: &RouterState,
        handle: Option<&str>,
        method: &str,
        mut params: Value,
        preparation: Preparation,
    ) -> Result<Value, ToolError> {
        Self::require(method)?;
        if method == "wait_owner_exit" {
            let reference = params["owner_observation_ref"]
                .as_str()
                .ok_or_else(|| diagnostic("wait_owner_exit requires owner_observation_ref"))?;
            return self.wait_owner_exit(router, reference, preparation).await;
        }
        if matches!(
            method,
            "batch_decompile" | "search_pseudocode" | "run_auto_analysis" | "batch_rename"
        ) {
            params = match method {
                "batch_decompile" => serde_json::to_value(
                    serde_json::from_value::<crate::server::BatchDecompileRequest>(params)
                        .map_err(diagnostic)?,
                )
                .map_err(diagnostic)?,
                "search_pseudocode" => serde_json::to_value(
                    serde_json::from_value::<crate::server::SearchPseudocodeRequest>(params)
                        .map_err(diagnostic)?,
                )
                .map_err(diagnostic)?,
                "batch_rename" => serde_json::to_value(
                    serde_json::from_value::<crate::server::BatchRenameRequest>(params)
                        .map_err(diagnostic)?,
                )
                .map_err(diagnostic)?,
                _ => params,
            };
            // F2/P1: use the same Vec<Value> decoder as the legacy dispatcher.
            // Python must never reinterpret JSON text (numbers/Unicode/depth differ).
            if method == "batch_decompile" {
                let raw = &params["addresses"];
                params["addresses"] = Value::Array(if let Some(array) = raw.as_array() {
                    array.clone()
                } else if let Some(text) = raw.as_str() {
                    serde_json::from_str::<Vec<Value>>(text).unwrap_or_else(|_| vec![raw.clone()])
                } else {
                    vec![raw.clone()]
                });
            }
            // Nested non-address values are echoed only at the external boundary.
            // Avoid adding adapter envelope depth to legacy-valid nested JSON.
            // Null remains invalid to the owner, preserving per-item semantics.
            let batch_addresses = if method == "batch_decompile" {
                let originals = params["addresses"].as_array().cloned();
                if let Some(addresses) = params["addresses"].as_array_mut() {
                    for address in addresses {
                        if address.is_array() || address.is_object() {
                            *address = Value::Null;
                        }
                    }
                }
                originals
            } else {
                None
            };
            params
                .as_object_mut()
                .ok_or_else(|| diagnostic("params must be an object"))?
                .remove("_n5_checkpoint");
            let job = id();
            params["_n5_job"] = json!(job);
            let target = if let Some(handle) = handle {
                handle.to_owned()
            } else {
                let records = self.records();
                let (key, first) = records.iter().next().ok_or(ToolError::NoDatabaseOpen)?;
                if records
                    .values()
                    .any(|db| db.lease.instance_id != first.lease.instance_id)
                {
                    return Err(ToolError::InvalidParams(
                        "db_handle is required when multiple databases are open".into(),
                    ));
                }
                key.clone()
            };
            let mut cleanup = SliceCleanup {
                tools: self.clone(),
                router: router.clone(),
                handle: Some(target.clone()),
                job,
                active: true,
            };
            let mut result = self
                .execute_one(
                    router,
                    Some(&target),
                    method,
                    params,
                    preparation,
                    Some(&mut cleanup.active),
                )
                .await;
            if let (Some(originals), Ok(Value::Array(items))) = (batch_addresses, &mut result) {
                if originals.len() != items.len() {
                    return Err(diagnostic("batch result count differs from accepted input"));
                }
                for (item, address) in items.iter_mut().zip(originals) {
                    item["address"] = address;
                }
            }
            // A normal final slice released its own reference on the owner.
            // Do not race a needless cleanup request against an immediate close.
            if result.is_ok() {
                cleanup.active = false;
            }
            return result;
        }
        self.execute_one(router, handle, method, params, preparation, None)
            .await
    }
    async fn execute_one(
        &self,
        router: &RouterState,
        handle: Option<&str>,
        method: &str,
        mut params: Value,
        preparation: Preparation,
        mut cleanup_pending: Option<&mut bool>,
    ) -> Result<Value, ToolError> {
        if method != "_n5_cleanup" {
            Self::require(method)?;
        }
        preparation.check()?;
        params = normalize(method, params)?;
        if matches!(
            method,
            "search_bytes" | "search_instructions" | "search_instruction_operands"
        ) {
            let raw = &params["patterns"];
            let list = if let Some(values) = raw.as_array() {
                values.clone()
            } else if let Some(text) = raw.as_str() {
                match serde_json::from_str::<Value>(text) {
                    Ok(Value::Array(values)) if text.trim().starts_with('[') => values,
                    _ => vec![raw.clone()],
                }
            } else {
                Vec::new()
            };
            params["patterns"] = json!(list
                .into_iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect::<Vec<_>>());
        }
        if method == "read_global_variable" && !params["query"].is_string() {
            params["query"] = json!(serde_json::to_string(&params["query"]).map_err(diagnostic)?);
        }
        if method == "patch_bytes" {
            params["bytes"] = json!(parse_patch_bytes(&params["bytes"])?);
        }
        if matches!(method, "disassemble" | "decompile_function") {
            params["address"] = normalize_addresses(&params["address"])?;
        }
        let database = {
            let records = self.records();
            if let Some(handle) = handle {
                records.get(handle).cloned().ok_or_else(|| {
                    ToolError::InvalidParams(format!("Unknown db_handle: {handle}"))
                })?
            } else {
                let mut values = records.values();
                let first = values.next().cloned().ok_or(ToolError::NoDatabaseOpen)?;
                if values.any(|db| db.lease.instance_id != first.lease.instance_id) {
                    return Err(ToolError::InvalidParams(
                        "db_handle is required when multiple databases are open".into(),
                    ));
                }
                first
            }
        };
        params
            .as_object_mut()
            .ok_or_else(|| ToolError::InvalidParams("params must be an object".into()))?
            .insert("_database_path".into(), json!(database.idb));
        let request = accepted(method, params, &preparation)?;
        let bridge = preparation.wait(Self::bridge(router)).await?;
        let endpoint = bridge.endpoint();
        let identity = endpoint.transition(|s, _| {
            s.queue(
                &database.lease.client_id,
                &database.lease,
                request,
                OperationId::new(id())?,
            )
        })?;
        // Activity belongs to the owner, so closing the requesting lease must
        // not restore an older idle value from a surviving sibling lease.
        let now = Instant::now();
        for db in self
            .records()
            .values_mut()
            .filter(|db| db.lease.instance_id == database.lease.instance_id)
        {
            db.last_active = now;
        }
        self.operations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(identity.clone());
        let mut guard = CancelOnDrop {
            endpoint: endpoint.clone(),
            identity: Some(identity.clone()),
        };
        let mut events = bridge.subscribe();
        loop {
            let snapshot = endpoint
                .transition(|s, _| s.operation_progress(&database.lease.client_id, &identity))?;
            if snapshot.status == OperationStatus::Queued {
                preparation.check()?;
                match endpoint
                    .transition(|s, t| s.dispatch(&database.lease.client_id, &identity, t))
                {
                    Ok(()) => continue,
                    Err(error) if error.code == NexusErrorCode::Busy => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if snapshot.status.is_terminal() {
                guard.identity.take();
                if snapshot.execution_stopped {
                    self.operations
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .retain(|value| value != &identity);
                }
                if snapshot.status != OperationStatus::Succeeded {
                    return Err(snapshot
                        .error
                        .map(operation_error)
                        .unwrap_or_else(|| diagnostic("operation ended without a result")));
                }
                if let Some(pending) = &mut cleanup_pending {
                    **pending = false;
                }
                let mut result = endpoint
                    .transition(|s, _| {
                        s.take_operation_result(&database.lease.client_id, &identity)
                    })?
                    .ok_or_else(|| diagnostic("operation result missing"))?;
                let value = &mut result["result"];
                if value["ok"] == true {
                    return Ok(value["value"].take());
                }
                return Err(business_error(
                    value["error"]
                        .as_str()
                        .unwrap_or("invalid Nexus business result"),
                ));
            }
            tokio::select! {
                biased;
                _ = preparation.cancel.cancelled() => {
                    cancel_pending(&endpoint, &identity, CancelReason::Client)?;
                    return Err(diagnostic("cancel requested; execution_stopped=false; never replay"));
                }
                _ = tokio::time::sleep_until(preparation.deadline.into()) => {
                    cancel_pending(&endpoint, &identity, CancelReason::Deadline)?;
                    return Err(diagnostic("total deadline expired; execution_stopped=false; never replay"));
                }
                event = events.recv() => { receive(event)?; }
                _ = tokio::time::sleep(Duration::from_millis(20)), if snapshot.status == OperationStatus::Queued => {}
            }
        }
    }
    pub async fn close_token(
        self: &Arc<Self>,
        router: &RouterState,
        token: &str,
    ) -> Result<Option<(String, usize)>, ToolError> {
        let record = self
            .records()
            .iter()
            .find(|(_, db)| db.token == token)
            .map(|(h, db)| CleanupReference {
                handle: h.clone(),
                path: db.path.clone(),
                lease: db.lease.clone(),
                _cache_guard: Some(db._cache_guard.clone()),
            })
            .or_else(|| {
                self.cleanup_records
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(token)
                    .cloned()
            });
        let Some(database) = record else {
            return Ok(None);
        };
        let handle = database.handle.clone();
        self.owner_diagnostics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(database.lease.clone(), database.path.clone());
        let gate = self.path_gate(&database.path);
        let _path = gate.lock().await;
        let bridge = Self::bridge(router).await?;
        if database._cache_guard.is_none()
            && bridge
                .endpoint()
                .transition(|s, _| s.release_members(&database.lease))?
                .len()
                == 1
        {
            return Ok(None);
        }
        // Only this explicit close can renew a proven NotSent child's attempt.
        // The old token remains absent from all business/session lookups.
        for member in bridge
            .endpoint()
            .transition(|s, _| s.release_members(&database.lease))?
            .into_iter()
            .skip(1)
        {
            let not_sent = bridge
                .endpoint()
                .transition(|s, _| s.status(&member.client_id, &member))?
                .control_delivery
                .is_some_and(|d| d.state == DeliveryState::NotSent);
            if not_sent {
                bridge.retry_cleanup(&member);
                bridge
                    .endpoint()
                    .transition(|s, t| s.release(&member.client_id, &member, t))?;
            }
        }
        // Installed before release's first await. Dropping the caller cannot
        // discard responsibility for a successfully published Database.
        let _cleanup = ReleaseCleanup {
            tools: Arc::downgrade(self),
            bridge: bridge.clone(),
            lease: database.lease.clone(),
        };
        release(&bridge, &database.lease).await?;
        self.consume_released(&bridge);
        let records = self.records();
        self.operations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|identity| identity.lease != database.lease);
        let remaining = records
            .values()
            .filter(|db| db.path == database.path)
            .count();
        Ok(Some((handle, remaining)))
    }

    pub async fn close_token_detailed(
        self: &Arc<Self>,
        router: &RouterState,
        token: &str,
    ) -> (Result<Option<(String, usize)>, ToolError>, Option<Value>) {
        let lease = self
            .records()
            .values()
            .find(|db| db.token == token)
            .map(|db| db.lease.clone())
            .or_else(|| {
                self.cleanup_records
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(token)
                    .map(|db| db.lease.clone())
            });
        let result = self.close_token(router, token).await;
        let observation = lease.and_then(|lease| {
            self.owner_status(router)
                .into_iter()
                .find(|value| value["lease"] == json!(lease))
        });
        (result, observation)
    }
    pub async fn close_path(
        self: &Arc<Self>,
        router: &RouterState,
        path: &Path,
    ) -> Result<(), ToolError> {
        let tokens: Vec<_> = self
            .records()
            .values()
            .filter(|db| db.path == path)
            .map(|db| db.token.clone())
            .collect();
        if tokens.len() > 1 {
            return Err(NexusError::new(
                NexusErrorCode::ExclusiveCloseRequired,
                "close requires the opener's close_token while other sessions exist",
            )
            .into());
        }
        let token = tokens.first().ok_or(ToolError::NoDatabaseOpen)?;
        self.close_token(router, token).await?;
        router.warm_pool.lock().await.remove(path);
        Ok(())
    }
    pub async fn shutdown(self: &Arc<Self>, router: &RouterState) -> Result<(), ToolError> {
        let tokens: Vec<_> = self.records().values().map(|db| db.token.clone()).collect();
        for token in tokens {
            self.close_token(router, &token).await?;
        }
        if let Some(bridge) = router.nexus_bridge.get() {
            bridge.shutdown().await.map_err(diagnostic)?;
        }
        Ok(())
    }
    pub fn abandon(router: RouterState, token: String) {
        tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(615);
            loop {
                match router.nexus_close_token(&token).await {
                    Ok(_) => return,
                    Err(ToolError::Nexus(error))
                        if error.code == NexusErrorCode::CancelPending
                            && tokio::time::Instant::now() < deadline =>
                    {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => {
                        tracing::warn!(%error,"abandoned Nexus lease cleanup unconfirmed; tracking retained");
                        return;
                    }
                }
            }
        });
    }
    pub async fn open_details(
        self: &Arc<Self>,
        router: &RouterState,
        handle: &str,
        preparation: Preparation,
    ) -> Result<Value, ToolError> {
        let meta = self
            .execute(
                router,
                Some(handle),
                "get_database_info",
                json!({}),
                preparation.clone(),
            )
            .await?;
        let analysis = self
            .execute(
                router,
                Some(handle),
                "get_analysis_status",
                json!({}),
                preparation,
            )
            .await?;
        let path = self
            .records()
            .get(handle)
            .map(|db| db.idb.clone())
            .ok_or(ToolError::NoDatabaseOpen)?;
        Ok(
            json!({"path":path,"file_type":meta["file_type"],"processor":meta["processor"],"bits":meta["bits"],
            "function_count":meta["function_count"],"debug_info":null,"analysis_status":analysis}),
        )
    }
}

struct ReleaseCleanup {
    tools: std::sync::Weak<Tools>,
    bridge: Arc<super::nexus_bridge::NexusBridge>,
    lease: SessionLease,
}
impl Drop for ReleaseCleanup {
    fn drop(&mut self) {
        let lease = self.lease.clone();
        let bridge = self.bridge.clone();
        let Some(owner) = self.tools.upgrade() else {
            return;
        };
        owner.consume_released(&bridge);
        if !owner
            .close_observers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lease.clone())
        {
            return;
        }
        let tools = owner;
        tokio::spawn(async move {
            let mut retries = 0_u8;
            let mut backoffs = 0_u8;
            let mut next_retry = Instant::now();
            loop {
                tools.consume_released(&bridge);
                let active = tools.records().values().any(|db| db.lease == lease);
                if !active && !tools.owner_pending(&lease) {
                    tools
                        .close_observers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&lease);
                    return;
                }
                if active && retries < 16 && Instant::now() >= next_retry {
                    let not_sent = bridge
                        .endpoint()
                        .transition(|s, _| s.status(&lease.client_id, &lease))
                        .is_ok_and(|s| {
                            s.control_delivery
                                .is_some_and(|d| d.state == DeliveryState::NotSent)
                        });
                    if not_sent
                        && bridge.owner_release_status(&lease)["preflight"]["protection"]
                            ["close_safe"]
                            == false
                    {
                        bridge.cleanup_blocked(&lease, NexusError::new(NexusErrorCode::OperationFailed,
                            "CleanupBlocked: fresh protection unavailable; exact resource retained"));
                        retries = 16;
                    } else if not_sent {
                        // N1 rechecks stop/owner/grant eligibility. A potentially
                        // sent detach never enters this retry branch.
                        let issued: Result<_, NexusError> = bridge.endpoint().transition(|s, t| {
                            let before = s.status(&lease.client_id, &lease)?.control_delivery;
                            let result = s.release(&lease.client_id, &lease, t);
                            let after = s.status(&lease.client_id, &lease)?.control_delivery;
                            Ok((
                                before.map(|d| d.attempt) != after.map(|d| d.attempt),
                                result,
                            ))
                        });
                        let error = match issued {
                            Ok((created, result)) => {
                                if created {
                                    retries += 1;
                                }
                                result.err()
                            }
                            Err(error) => Some(error),
                        };
                        if let Some(error) = error {
                            if matches!(
                                error.code,
                                NexusErrorCode::CancelPending | NexusErrorCode::Busy
                            ) {
                                tracing::debug!(%error,"Nexus background cleanup awaits eligibility");
                            } else {
                                bridge.cleanup_blocked(&lease, error);
                                retries = 16;
                            }
                        }
                        backoffs = backoffs.saturating_add(1);
                        next_retry = Instant::now()
                            + Duration::from_millis(
                                50_u64.saturating_mul(1_u64 << backoffs.min(4)),
                            );
                        if retries == 16 {
                            bridge.cleanup_blocked(&lease, NexusError::new(NexusErrorCode::OperationFailed,
                                "CleanupBlocked: bounded release attempts exhausted; exact resource retained"));
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
    }
}

// Cleanup joins the same instance FIFO; a pending native cancellation therefore
// retains the hook until actual stop evidence permits this command to execute.
struct SliceCleanup {
    tools: Arc<Tools>,
    router: RouterState,
    handle: Option<String>,
    job: String,
    active: bool,
}
impl Drop for SliceCleanup {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let tools = self.tools.clone();
        let router = self.router.clone();
        let handle = self.handle.clone();
        let job = self.job.clone();
        tokio::spawn(async move {
            let result = tools
                .execute_one(
                    &router,
                    handle.as_deref(),
                    "_n5_cleanup",
                    json!({"_n5_job":job,"timeout_secs":600}),
                    Preparation::new(Duration::from_secs(600)),
                    None,
                )
                .await;
            if let Err(error) = result {
                tracing::warn!(%error, "Nexus slice cleanup unconfirmed; lease tracking retained");
            }
        });
    }
}

fn normalize(method: &str, params: Value) -> Result<Value, ToolError> {
    use crate::server::*;
    fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(
        value: Value,
    ) -> Result<Value, ToolError> {
        let request: T = serde_json::from_value(value)
            .map_err(|error| ToolError::InvalidParams(format!("invalid params: {error}")))?;
        serde_json::to_value(request).map_err(diagnostic)
    }
    match method {
        "list_functions" => typed::<ListFunctionsRequest>(params),
        "get_function_by_name" => typed::<ResolveFunctionRequest>(params),
        "get_function_at_address" => typed::<FunctionAtRequest>(params),
        "disassemble_function_at" => typed::<DisasmFunctionAtRequest>(params),
        "disassemble" => typed::<DisasmRequest>(params),
        "disassemble_function" => typed::<DisasmByNameRequest>(params),
        "decompile_function" => typed::<DecompileRequest>(params),
        "get_xrefs_to" | "get_xrefs_from" => typed::<AddressRequest>(params),
        "run_script" => typed::<RunScriptRequest>(params),
        "list_local_types" => typed::<LocalTypesRequest>(params),
        "declare_c_type" => typed::<DeclareTypeRequest>(params),
        "apply_type" => typed::<ApplyTypesRequest>(params),
        "infer_type" => typed::<InferTypesRequest>(params),
        "set_function_prototype" => typed::<SetFunctionPrototypeRequest>(params),
        "get_stack_frame" => typed::<AddressRequest>(params),
        "create_stack_variable" => typed::<DeclareStackRequest>(params),
        "delete_stack_variable" => typed::<DeleteStackRequest>(params),
        "rename_stack_variable" => typed::<RenameStackVariableRequest>(params),
        "set_stack_variable_type" => typed::<SetStackVariableTypeRequest>(params),
        "list_enums" => typed::<ListEnumsRequest>(params),
        "create_enum" => typed::<CreateEnumRequest>(params),
        "set_comment" => typed::<SetCommentsRequest>(params),
        "set_function_comment" => typed::<SetFunctionCommentRequest>(params),
        "rename_symbol" => typed::<RenameRequest>(params),
        "patch_bytes" => typed::<PatchRequest>(params),
        "patch_assembly" => typed::<PatchAsmRequest>(params),
        "rename_local_variable" => typed::<RenameLvarRequest>(params),
        "set_local_variable_type" => typed::<SetLvarTypeRequest>(params),
        "set_decompiler_comment" => typed::<SetDecompilerCommentRequest>(params),
        "read_bytes" => typed::<GetBytesRequest>(params),
        "read_string" => typed::<GetStringRequest>(params),
        "get_basic_blocks" => typed::<AddressRequest>(params),
        "get_callers" => typed::<AddressRequest>(params),
        "get_callees" => typed::<AddressRequest>(params),
        "build_callgraph" => typed::<CallGraphRequest>(params),
        "find_control_flow_paths" => typed::<FindPathsRequest>(params),
        "build_xref_matrix" => typed::<XrefMatrixRequest>(params),
        "list_imports" => typed::<PaginatedRequest>(params),
        "list_exports" => typed::<PaginatedRequest>(params),
        "list_structs" => typed::<StructsRequest>(params),
        "get_struct_info" => typed::<StructInfoRequest>(params),
        "read_struct_at_address" => typed::<ReadStructRequest>(params),
        "get_xrefs_to_struct_field" => typed::<XrefsToFieldRequest>(params),
        "batch_lookup_functions" => typed::<LookupFuncsRequest>(params),
        "export_functions" => typed::<ExportFuncsRequest>(params),
        "list_globals" => typed::<ListGlobalsRequest>(params),
        "read_global_variable" => typed::<GetGlobalValueRequest>(params),
        "get_xrefs_to_string" => typed::<XrefsToStringRequest>(params),
        "get_address_info" => typed::<AddrInfoRequest>(params),
        "scan_memory_table" => typed::<TableScanRequest>(params),
        "diff_pseudocode" => typed::<DiffFunctionsRequest>(params),
        "get_pseudocode_at" => typed::<PseudocodeAtRequest>(params),
        "load_debug_info" => typed::<LoadDebugInfoRequest>(params),
        "search_bytes" => typed::<FindBytesRequest>(params),
        "search_instructions" => typed::<FindInsnsRequest>(params),
        "search_instruction_operands" => typed::<FindInsnOperandsRequest>(params),
        _ => Ok(params),
    }
}

fn parse_patch_bytes(v: &Value) -> Result<Vec<u8>, ToolError> {
    if let Some(arr) = v.as_array() {
        let out: Vec<u8> = arr
            .iter()
            .filter_map(|item| item.as_u64().map(|n| n as u8))
            .collect();
        if out.is_empty() {
            return Err(ToolError::InvalidParams("no bytes provided".to_string()));
        }
        return Ok(out);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if s.is_empty() {
            return Err(ToolError::InvalidParams("no bytes provided".to_string()));
        }
        // Split by common separators (whitespace, comma, colon, dash, underscore)
        let tokens: Vec<&str> = s
            .split(|c: char| c.is_ascii_whitespace() || matches!(c, ',' | ':' | '-' | '_'))
            .filter(|t| !t.is_empty())
            .collect();

        let mut hex_str = String::with_capacity(s.len());
        for token in &tokens {
            // Strip 0x/0X prefix from each token
            let cleaned = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
                .unwrap_or(token);
            for c in cleaned.chars() {
                if !c.is_ascii_hexdigit() {
                    return Err(ToolError::InvalidParams(format!(
                        "invalid hex character: {c}"
                    )));
                }
            }
            hex_str.push_str(cleaned);
        }

        if hex_str.is_empty() {
            return Err(ToolError::InvalidParams("no bytes provided".to_string()));
        }
        if !hex_str.len().is_multiple_of(2) {
            return Err(ToolError::InvalidParams(
                "hex string has odd length".to_string(),
            ));
        }
        let mut out = Vec::with_capacity(hex_str.len() / 2);
        for i in (0..hex_str.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|_| ToolError::InvalidParams("invalid hex byte".to_string()))?;
            out.push(byte);
        }
        return Ok(out);
    }
    Err(ToolError::InvalidParams(
        "bytes must be a hex string or array of integers".to_string(),
    ))
}

fn normalize_addresses(value: &Value) -> Result<Value, ToolError> {
    if let Some(values) = value.as_array() {
        if values.is_empty() {
            return Err(ToolError::InvalidAddress("empty address array".into()));
        }
        let mut addresses = Vec::with_capacity(values.len());
        for (index, value) in values.iter().enumerate() {
            let address = crate::rpc_dispatch::parse_address_value(value).ok_or_else(|| {
                ToolError::InvalidAddress(format!("invalid address at index {index}: {value}"))
            })?;
            addresses.push(json!(address));
        }
        if addresses.len() == 1 {
            return Ok(addresses.remove(0));
        }
        Ok(Value::Array(addresses))
    } else {
        crate::rpc_dispatch::parse_address_value(value)
            .map(|address| json!(address))
            .ok_or_else(|| ToolError::InvalidAddress(format!("invalid address: {value}")))
    }
}

fn operation_error(mut error: NexusError) -> ToolError {
    let mut cause = error.cause.as_deref();
    while let Some(detail) = cause {
        if detail
            .message
            .starts_with("database state abnormal: Root Node")
        {
            error.message = format!("{}; {}", error.message, detail.message);
            break;
        }
        cause = detail.cause.as_deref();
    }
    ToolError::Nexus(error)
}

fn business_error(message: &str) -> ToolError {
    if let Some(message) = message.strip_prefix("Invalid database path: ") {
        return ToolError::InvalidPath(message.into());
    }
    if let Some(message) = message.strip_prefix("Not supported: ") {
        return ToolError::NotSupported(message.into());
    }
    if let Some(message) = message.strip_prefix("IDA error: ") {
        return ToolError::IdaError(message.into());
    }
    if let Some(name) = message.strip_prefix("Function not found: ") {
        return ToolError::FunctionNameNotFound(name.into());
    }
    if let Some(value) = message.strip_prefix("Invalid parameters: ") {
        return ToolError::InvalidParams(value.into());
    }
    if let Some(value) = message.strip_prefix("Invalid address format: ") {
        return ToolError::InvalidAddress(value.into());
    }
    if let Some(value) = message.strip_prefix("Function not found at address 0x") {
        if let Ok(address) = u64::from_str_radix(value, 16) {
            return ToolError::FunctionNotFound(address);
        }
    }
    if let Some(value) = message
        .strip_prefix("Address 0x")
        .and_then(|v| v.strip_suffix(" is outside valid range"))
    {
        if let Ok(address) = u64::from_str_radix(value, 16) {
            return ToolError::AddressOutOfRange(address);
        }
    }
    if message == "Decompiler not available" {
        return ToolError::DecompilerUnavailable;
    }
    ToolError::IdaError(message.into())
}

// AcceptedRequest's public constructor takes a Clock. Preserve the upstream
// Preparation's exact absolute deadline instead of granting a fresh budget.
struct AcceptedAt(Instant);
impl Clock for AcceptedAt {
    fn now(&self) -> Instant {
        self.0
    }
}
fn accepted(
    method: &str,
    params: Value,
    preparation: &Preparation,
) -> Result<AcceptedRequest, ToolError> {
    let maximum = if method == "open" { 3600 } else { 600 };
    let seconds = params
        .get("timeout_secs")
        .and_then(Value::as_u64)
        .unwrap_or(120)
        .min(maximum);
    let start = preparation
        .deadline
        .checked_sub(Duration::from_secs(seconds))
        .ok_or_else(|| diagnostic("acceptance time underflow"))?;
    Ok(AcceptedRequest::new(
        &AcceptedAt(start),
        RequestId::new(id())?,
        CURRENT_TASK_ID.try_with(Clone::clone).ok(),
        method,
        params,
    )?)
}
fn receive(event: Result<Value, broadcast::error::RecvError>) -> Result<Value, ToolError> {
    let event = match event {
        Ok(event) => event,
        Err(broadcast::error::RecvError::Lagged(_)) => return Ok(Value::Null),
        Err(error) => return Err(diagnostic(error)),
    };
    if event["event"] == "bridge_disconnected" {
        return Err(diagnostic("bridge disconnected; never replay"));
    }
    Ok(event)
}
fn cancel_pending(
    endpoint: &super::nexus_transport::NexusEndpoint,
    identity: &OperationIdentity,
    reason: CancelReason,
) -> Result<(), NexusError> {
    endpoint.transition(|s, t| {
        let progress = s.operation_progress(&identity.lease.client_id, identity)?;
        if !progress.status.is_terminal() || !progress.execution_stopped {
            s.cancel(&identity.lease.client_id, identity, reason, t)?;
        }
        Ok(())
    })
}
struct CancelOnDrop {
    endpoint: super::nexus_transport::NexusEndpoint,
    identity: Option<OperationIdentity>,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let Some(identity) = &self.identity else {
            return;
        };
        if let Err(error) = cancel_pending(&self.endpoint, identity, CancelReason::Client) {
            tracing::warn!(%error,"Nexus abandoned request cancellation not confirmed");
        }
    }
}
async fn release(
    bridge: &super::nexus_bridge::NexusBridge,
    lease: &SessionLease,
) -> Result<(), ToolError> {
    let guard_diagnostic = || {
        bridge
            .take_release_error(lease)
            .map_or_else(String::new, |message| {
                format!("; save_guard_error={message}")
            })
    };
    let mut events = bridge.subscribe();
    bridge
        .endpoint()
        .transition(|s, t| s.release(&lease.client_id, lease, t))
        .map_err(|mut error| {
            // Annotate only this caller's owned error; N1 history stays intact.
            error.message.push_str(&guard_diagnostic());
            error
        })?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let state = bridge
                .endpoint()
                .transition(|s, _| s.status(&lease.client_id, lease))?;
            // Public lifetime settles resources independently of this command.
            // Deliver the original terminal before interpreting resource phase.
            if let Some(delivery) = &state.control_delivery {
                if let Some(error) = &delivery.error {
                    let mut error = error.clone();
                    error.message.push_str(&format!(
                        "{}; lease_detached={}; owner_pending={}; never_replay={}",
                        guard_diagnostic(),
                        state.phase == SessionPhase::Released,
                        bridge.owner_release_status(lease)["owner_pending"],
                        delivery.state == DeliveryState::Uncertain
                    ));
                    return Err(ToolError::Nexus(error));
                }
            }
            let terminal = state
                .control_delivery
                .as_ref()
                .is_none_or(|delivery| delivery.state == DeliveryState::Confirmed);
            let auxiliary_error=bridge.owner_release_status(lease)["auxiliary_error"].clone();
            if !auxiliary_error.is_null() {
                return Err(ToolError::Nexus(serde_json::from_value(auxiliary_error)
                    .map_err(|error|diagnostic(format!("invalid retained auxiliary error: {error}")))?));
            }
            if state.phase == SessionPhase::Released && terminal {
                let members = bridge.endpoint().transition(|s, _| s.release_members(lease))?;
                let mut pending_members = false;
                for member in members.iter().filter(|member| *member != lease) {
                    let child = bridge.endpoint().transition(|s, _| s.status(&member.client_id, member))?;
                    if let Some(error) = child.control_delivery.as_ref().and_then(|d| d.error.as_ref()) {
                        let mut error = error.clone();
                        error.message.push_str(&format!("; primary lease detached; auxiliary={}; primary_save_guard_error={:?}; auxiliary_save_guard_error={:?}",
                            member.lease_id.as_str(), bridge.take_release_error(lease), bridge.take_release_error(member)));
                        return Err(ToolError::Nexus(error));
                    }
                    if let Some(message) = bridge.take_release_error(member) {
                        return Err(ToolError::Nexus(NexusError::new(NexusErrorCode::OperationFailed,
                            format!("{message}; primary lease detached; auxiliary={}", member.lease_id.as_str()))));
                    }
                    pending_members |= child.phase != SessionPhase::Released || child.control_delivery.as_ref()
                        .is_some_and(|d| d.state != DeliveryState::Confirmed);
                }
                if pending_members {
                    receive(events.recv().await)?;
                    continue;
                }
                return bridge.take_release_error(lease).map_or(Ok(()), |message| {
                    Err(ToolError::Nexus(NexusError::new(
                        NexusErrorCode::OperationFailed,
                        format!(
                            "{message}; lease detached; owner_pending={}",
                            bridge.owner_release_status(lease)["owner_pending"]
                        ),
                    )))
                });
            }
            let event = receive(events.recv().await)?;
            if event["event"] == "release_unconfirmed"
                && event["attempt"]["target"]["lease"]["lease_id"] == lease.lease_id.as_str()
            {
                return Err(diagnostic(format!(
                    "lease release proof deadline expired; owner retained; new open blocked{}",
                    guard_diagnostic()
                )));
            }
        }
    })
    .await
    .map_err(|_| {
        diagnostic(format!(
            "lease release unconfirmed; lease tracking retained{}",
            guard_diagnostic()
        ))
    })?
}

// Installed before awaiting an opening outcome. Every error/deadline/drop
// transfers cleanup to the bounded N1/bridge lease registry, including late opens.
struct OpeningGuard {
    open_guard: Option<Arc<super::nexus_bridge::cache_lock::CacheGuard>>,
    bridge: Arc<super::nexus_bridge::NexusBridge>,
    identity: OpenIdentity,
    transferred: bool,
    cache_guard: Arc<super::nexus_bridge::cache_lock::CacheGuard>,
    uncertain_cache: Arc<Mutex<Vec<Arc<RetainedOpen>>>>,
    content_guard: Option<Arc<super::nexus_bridge::cache_lock::CacheGuard>>,
    verification: Option<Arc<super::nexus_bridge::verification::Cleanup>>,
}
struct RetainedOpen {
    bridge: Arc<super::nexus_bridge::NexusBridge>,
    identity: OpenIdentity,
    _cache_guard: Arc<super::nexus_bridge::cache_lock::CacheGuard>,
    _open_guard: Option<Arc<super::nexus_bridge::cache_lock::CacheGuard>>,
    _content_guard: Option<Arc<super::nexus_bridge::cache_lock::CacheGuard>>,
    verification: Option<Arc<super::nexus_bridge::verification::Cleanup>>,
}
impl RetainedOpen {
    fn cleanup_confirmed(&self) -> bool {
        let (pending_resources, retired_resources) =
            self.bridge.open_resource_obligations(&self.identity);
        if pending_resources {
            return false;
        }
        let terminal = self.bridge.endpoint().transition(|sessions, _| {
            let Ok((lease, failure)) =
                sessions.open_progress(&self.identity.client_id, &self.identity)
            else {
                return false;
            };
            if let Some(lease) = lease {
                if sessions
                    .resource_retirement(&lease)
                    .is_ok_and(|e| e.is_some())
                {
                    return true;
                }
                return sessions
                    .status(&lease.client_id, &lease)
                    .is_ok_and(|status| status.phase == SessionPhase::Released);
            }
            // N1 wraps every uncertain delivery in UnknownOutcome. A failure
            // without a lease is releasable only when N1 confirms it was not sent
            // or the bridge confirmed acquisition failed.
            retired_resources
                || failure.is_some_and(|error| error.code != NexusErrorCode::UnknownOutcome)
        });
        terminal
            && self.verification.as_ref().is_none_or(|v| {
                v.complete(true).unwrap_or_else(|error| {
                    // The error is also retained for status; guards stay owned.
                    tracing::debug!(%error,"verification cleanup remains blocked");
                    false
                })
            })
    }
}
impl Drop for OpeningGuard {
    fn drop(&mut self) {
        self.bridge.forget_open_reply(&self.identity.operation_id);
        if !self.transferred {
            if let Err(error) = self
                .bridge
                .endpoint()
                .transition(|s, _| s.abandon_open(&self.identity.client_id, &self.identity))
            {
                tracing::error!(%error, "Nexus open cleanup ownership could not be reconciled");
            }
            let retained = Arc::new(RetainedOpen {
                bridge: self.bridge.clone(),
                identity: self.identity.clone(),
                _cache_guard: self.cache_guard.clone(),
                _open_guard: self.open_guard.clone(),
                _content_guard: self.content_guard.clone(),
                verification: self.verification.clone(),
            });
            if retained.cleanup_confirmed() {
                return;
            }
            self.uncertain_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(retained.clone());
            let registry = self.uncertain_cache.clone();
            // One bounded observer per retained opening; no remote work or
            // replay. Accepted cleanup keeps observing its exact proof/file
            // conditions after the caller ends; capped backoff bounds the work.
            tokio::spawn(async move {
                let mut delay = 10;
                loop {
                    if retained.cleanup_confirmed() {
                        registry
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .retain(|item| !Arc::ptr_eq(item, &retained));
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    delay = (delay * 2).min(800);
                }
            });
        }
    }
}

pub struct ReferenceGuard {
    router: RouterState,
    token: Option<String>,
}
impl ReferenceGuard {
    pub fn new(router: RouterState, token: String) -> Self {
        Self {
            router,
            token: Some(token),
        }
    }
    pub fn transfer(&mut self) {
        self.token.take();
    }
}
impl Drop for ReferenceGuard {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            Tools::abandon(self.router.clone(), token);
        }
    }
}

#[cfg(test)]
mod n4_fix_regressions {
    use super::*;
    #[test]
    fn n6_every_registered_tool_and_old_capability_has_an_explicit_path() {
        use crate::ida::{capabilities::supported_methods_for, runtime::WorkerBackendKind};
        let local = [
            "open_idb",
            "close_idb",
            "tool_catalog",
            "tool_help",
            "get_task_status",
            "convert_number",
        ];
        let n7 = ["open_dsc", "dsc_add_dylib", "dsc_add_region"];
        let mut count = 0;
        for tool in crate::tool_registry::all_tools() {
            count += 1;
            for name in std::iter::once(tool.name).chain(tool.aliases.iter().copied()) {
                let primary = crate::tool_registry::primary_name_for(name);
                assert_eq!(primary, tool.name, "alias {name}");
                if local.contains(&primary) {
                    continue;
                }
                let result = Tools::require_tool(primary);
                if n7.contains(&primary) {
                    let error = result.expect_err("N7 must reject before execution");
                    assert!(
                        error.to_string().contains("no legacy fallback"),
                        "{name}: {error}"
                    );
                } else {
                    result.unwrap_or_else(|e| panic!("{name} missing Nexus path: {e}"));
                }
            }
        }
        assert_eq!(count, 107);
        for backend in [
            WorkerBackendKind::NativeLinked,
            WorkerBackendKind::IdatCompat,
        ] {
            for method in supported_methods_for(backend) {
                if !["open", "close", "shutdown"].contains(method) {
                    Tools::require(method).unwrap_or_else(|e| panic!("{backend:?}/{method}: {e}"));
                }
            }
        }
        for method in [
            "unknown_n6",
            "dbg_unknown_n6",
            "open_dsc",
            "dsc_add_dylib",
            "dsc_add_region",
        ] {
            assert!(Tools::require_tool(method).is_err(), "must reject {method}");
        }
    }
    #[tokio::test]
    async fn n4_fix_accepted_request_keeps_background_task_identity() {
        let task = TaskId::new("queued-task-42").unwrap();
        CURRENT_TASK_ID
            .scope(task.clone(), async {
                let request = accepted(
                    "run_script",
                    json!({}),
                    &Preparation::new(Duration::from_secs(120)),
                )
                .unwrap();
                assert_eq!(request.task_id, Some(task));
            })
            .await;
        assert!(accepted(
            "run_script",
            json!({}),
            &Preparation::new(Duration::from_secs(120))
        )
        .unwrap()
        .task_id
        .is_none());
    }
}

#[cfg(test)]
#[path = "../../tests/support/n4_f2_open.rs"]
mod n4_f2_regressions;

#[cfg(feature = "nexus-test-support")]
#[path = "../../tests/support/n7_fix2_publish.rs"]
pub mod n7_fix2_publish;
