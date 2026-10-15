//! N4 tool wiring. The development-only selector is removed in N9.
use super::{nexus_bridge::BridgeConfig, RouterState};
use crate::{error::ToolError, nexus::*, preprocess::Preparation};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Semaphore};

pub const METHODS: &[&str] = &[
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
];
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
}
pub struct Tools {
    selected: bool,
    databases: Mutex<HashMap<String, Database>>,
    capacity: Arc<Semaphore>,
    paths: Mutex<HashMap<PathBuf, std::sync::Weak<tokio::sync::Mutex<()>>>>,
    operations: Mutex<Vec<OperationIdentity>>,
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
            capacity: Arc::new(Semaphore::new(capacity)),
            paths: Mutex::new(HashMap::new()),
            operations: Mutex::new(Vec::new()),
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
                    idle_secs: db.opened_at.elapsed().as_secs(),
                    active: true,
                });
            worker.ref_count += 1;
            worker.pending_requests += operations.iter().filter(|identity| identity.lease == db.lease).filter(|identity| {
                match endpoint.transition(|s,_|s.operation_status(&identity.lease.client_id,identity)) {
                    Ok(snapshot) => !snapshot.status.is_terminal() || !snapshot.execution_stopped,
                    Err(error) => { tracing::warn!(%error,"Nexus status could not confirm tracked operation stopped"); true }
                }
            }).count();
        }
        workers.into_values().collect()
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
                format!("method {method} is not implemented by Nexus N4; no legacy fallback"),
            )
            .into())
        }
    }
    pub async fn open(
        self: &Arc<Self>,
        router: &RouterState,
        path: &str,
        preparation: Preparation,
    ) -> Result<(String, String), ToolError> {
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
        tokio::spawn(async move {
            let _permit = permit;
            let result = tools.open_owned(&router, path, preparation).await;
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
        let _path = preparation.wait(async { Ok(gate.lock().await) }).await?;
        let mut prepared = super::nexus_bridge::cache::prepare_n4_open(
            canonical.clone(),
            crate::idb_store::idb_root(),
            &preparation,
        )
        .await?;
        let bridge = Self::bridge(router).await?;
        let mut events = bridge.subscribe();
        let client = ClientId::new(id())?;
        let identity = bridge.endpoint().transition(|s, t| {
            s.open(
                &client,
                accepted,
                OpenSpec {
                    operation_id: OperationId::new(id())?,
                    path: prepared.path.to_string_lossy().into_owned(),
                    options: prepared.options.clone(),
                },
                t,
            )
        })?;
        prepared.handed_off();
        let mut cancelled = false;
        loop {
            tokio::select! {
                biased;
                _ = preparation.cancel.cancelled(), if !cancelled => {
                    bridge.endpoint().transition(|s,_| s.cancel_open(&client, &identity))?;
                    cancelled = true;
                }
                event = events.recv() => {
                    let event = receive(event)?;
                    if event["attempt"]["target"]["identity"]["operation_id"] != identity.operation_id.as_str() { continue; }
                    match event["event"].as_str() {
                        Some("opened") => {
                            let lease: SessionLease = serde_json::from_value(event["lease"].clone()).map_err(diagnostic)?;
                            if cancelled || preparation.check().is_err() {
                                release(&bridge, &lease).await?;
                                return Err(diagnostic("open cancelled/expired; acquired lease released"));
                            }
                            let handle = id();
                            let token = id();
                            let idb = event["idb_path"].as_str().ok_or_else(|| diagnostic("open missing IDB path"))?.to_string();
                            let pid = event["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok());
                            self.records().insert(handle.clone(), Database { path: canonical, lease, idb, token: token.clone(), pid, opened_at: Instant::now() });
                            return Ok((handle,token));
                        }
                        Some("failed" | "uncertain") => return Err(diagnostic(event["error"].to_string())),
                        _ => {}
                    }
                }
            }
        }
    }
    pub async fn execute(
        &self,
        router: &RouterState,
        handle: Option<&str>,
        method: &str,
        mut params: Value,
        preparation: Preparation,
    ) -> Result<Value, ToolError> {
        Self::require(method)?;
        preparation.check()?;
        params = normalize(method, params)?;
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
        let bridge = Self::bridge(router).await?;
        let endpoint = bridge.endpoint();
        let identity = endpoint.transition(|s, _| {
            s.queue(
                &database.lease.client_id,
                &database.lease,
                request,
                OperationId::new(id())?,
            )
        })?;
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
            let dispatch =
                endpoint.transition(|s, t| s.dispatch(&database.lease.client_id, &identity, t));
            match dispatch {
                Ok(()) => break,
                Err(error) if error.code == NexusErrorCode::Busy => {
                    tokio::select! {
                        _ = preparation.cancel.cancelled() => return Err(diagnostic("queued request cancelled")),
                        _ = tokio::time::sleep_until(preparation.deadline.into()) => return Err(diagnostic("queued request expired")),
                        event = events.recv() => { receive(event)?; }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        loop {
            let snapshot = endpoint
                .transition(|s, _| s.operation_status(&database.lease.client_id, &identity))?;
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
                        .map(ToolError::Nexus)
                        .unwrap_or_else(|| diagnostic("operation ended without a result")));
                }
                let result = snapshot
                    .result
                    .ok_or_else(|| diagnostic("operation result missing"))?;
                let value = &result["result"];
                if value["ok"] == true {
                    return Ok(value["value"].clone());
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
                    endpoint.transition(|s,t| s.cancel(&database.lease.client_id,&identity,CancelReason::Client,t))?;
                    return Err(diagnostic("cancel requested; execution_stopped=false; never replay"));
                }
                _ = tokio::time::sleep_until(preparation.deadline.into()) => {
                    endpoint.transition(|s,t| s.expire(&database.lease.client_id,&identity,t))?;
                    return Err(diagnostic("total deadline expired; execution_stopped=false; never replay"));
                }
                event = events.recv() => { receive(event)?; }
            }
        }
    }
    pub async fn close_token(
        &self,
        router: &RouterState,
        token: &str,
    ) -> Result<Option<(String, usize)>, ToolError> {
        let record = self
            .records()
            .iter()
            .find(|(_, db)| db.token == token)
            .map(|(h, db)| (h.clone(), db.clone()));
        let Some((handle, database)) = record else {
            return Ok(None);
        };
        let gate = self.path_gate(&database.path);
        let _path = gate.lock().await;
        let bridge = Self::bridge(router).await?;
        release(&bridge, &database.lease).await?;
        let mut records = self.records();
        records.remove(&handle);
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
    pub async fn close_path(&self, router: &RouterState, path: &Path) -> Result<(), ToolError> {
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
    pub async fn shutdown(&self, router: &RouterState) -> Result<(), ToolError> {
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
        &self,
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
        _ => Ok(params),
    }
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

fn business_error(message: &str) -> ToolError {
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
        None,
        method,
        params,
    )?)
}
fn receive(event: Result<Value, broadcast::error::RecvError>) -> Result<Value, ToolError> {
    let event = event.map_err(diagnostic)?;
    if event["event"] == "bridge_disconnected" {
        return Err(diagnostic("bridge disconnected; never replay"));
    }
    Ok(event)
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
        if let Err(error) = self.endpoint.transition(|s, t| {
            s.cancel(&identity.lease.client_id, identity, CancelReason::Client, t)
        }) {
            tracing::warn!(%error,"Nexus abandoned request cancellation not confirmed");
        }
    }
}
async fn release(
    bridge: &super::nexus_bridge::NexusBridge,
    lease: &SessionLease,
) -> Result<(), ToolError> {
    let mut events = bridge.subscribe();
    bridge
        .endpoint()
        .transition(|s, t| s.release(&lease.client_id, lease, t))?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let state = bridge
                .endpoint()
                .transition(|s, _| s.status(&lease.client_id, lease))?;
            if state.phase == SessionPhase::Released {
                return Ok(());
            }
            if let Some(error) = state.control_delivery.and_then(|d| d.error) {
                return Err(ToolError::Nexus(error));
            }
            receive(events.recv().await)?;
        }
    })
    .await
    .map_err(|_| diagnostic("lease release unconfirmed; lease tracking retained"))?
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
