//! MCP server implementation with IDA Pro tools.

mod requests;
pub mod task;

pub use requests::*;

use crate::error::ToolError;
use crate::ida::IdaWorker;
use crate::tool_registry::{self, ToolCategory};
use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo, Tool},
    schemars::{schema_for, JsonSchema},
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

/// MCP server for IDA Pro analysis
#[derive(Clone)]
pub struct IdaMcpServer {
    worker: Arc<IdaWorker>,
    tool_mux: ToolMux<IdaMcpServer>,
    mode: ServerMode,
    task_registry: task::TaskRegistry,
}

#[derive(Clone, Debug)]
pub enum ServerMode {
    Stdio,
    Http,
    Router(crate::router::RouterState),
}

#[derive(Clone)]
struct ToolMux<S> {
    call_router: ToolRouter<S>,
}

impl<S> ToolMux<S>
where
    S: Send + Sync + 'static,
{
    fn new(call_router: ToolRouter<S>) -> Self {
        Self { call_router }
    }

    async fn call(
        &self,
        context: ToolCallContext<'_, S>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.call_router.call(context).await
    }

    fn list_all(&self) -> Vec<Tool> {
        let mut tools = Vec::new();
        for info in tool_registry::all_tools() {
            if let Some(route) = self.call_router.map.get(info.name) {
                tools.push(route.attr.clone());
            }
        }
        tools
    }

    fn get(&self, name: &str) -> Option<&Tool> {
        self.call_router.map.get(name).map(|route| &route.attr)
    }
}

/// Parameters for the background DSC loading task.
struct DscBackgroundCtx {
    idat: std::path::PathBuf,
    idat_args: Vec<String>,
    script_path: std::path::PathBuf,
    log_path: Option<std::path::PathBuf>,
    out_i64: std::path::PathBuf,
    module: String,
    frameworks: Vec<String>,
}

impl IdaMcpServer {
    pub fn new(worker: Arc<IdaWorker>, mode: ServerMode) -> Self {
        info!("Creating IDA MCP server");
        let call_router = Self::tool_router();
        Self {
            worker,
            tool_mux: ToolMux::new(call_router),
            mode,
            task_registry: task::TaskRegistry::new(),
        }
    }

    fn close_hint(&self) -> &'static str {
        match self.mode {
            ServerMode::Stdio => {
                "Call close_idb when done to release locks for other sessions."
            }
            ServerMode::Http | ServerMode::Router(_) => {
                "In multi-client (HTTP/SSE) mode, close_idb requires the close_token returned by open_idb; each opener holds one reference, database closes when all references are released."
            }
        }
    }

    fn instructions(&self) -> String {
        format!(
            "IDA Pro headless analysis server for reverse engineering binaries. \
                 \n\nWorkflow: \
                 \n1. open_idb: Open a .i64/.idb file or a raw binary (Mach-O/ELF/PE). Large DBs may take 30+ seconds. \
                 \n   load_debug_info: Optional for existing .i64 to load DWARF/dSYM \
                 \n2. tool_catalog: Discover tools for your task (e.g., 'find callers', 'decompile') \
                 \n3. tool_help: Get full docs for a specific tool \
                 \n4. Use the discovered tools to analyze the binary \
                 \n5. close_idb: Optionally close when done \
                 \n\nNote: tools/list exposes the full tool set by default; use tool_catalog/tool_help to discover usage. \
                 \n{close_hint} \
                 \n\nTool Categories: \
                 \n- core: open/close/discover (open_idb, close_idb, tool_catalog, tool_help, idb_meta) \
                 \n- functions: list, resolve, lookup functions \
                 \n- disassembly: disasm at addresses \
                 \n- decompile: Hex-Rays pseudocode \
                 \n- xrefs: cross-reference analysis \
                 \n- control_flow: CFG, callgraph, paths \
                 \n- memory: read bytes, strings, values \
                 \n- search: find patterns, strings \
                 \n- metadata: segments, imports, exports \
                 \n- types: declare_type, apply_types (addr/stack), infer_types, local_types, stack_frame, declare_stack, delete_stack, structs (list/info/read) \
                \n- editing: comments/rename/patch/patch_asm \
                 \n- scripting: run_script (execute IDAPython code) \
                 \n\nTip: Use tool_catalog(query='what you want to do') to find the right tool. \
                 \nTip: If xrefs/decompile look incomplete, call analysis_status to check auto-analysis.",
            close_hint = self.close_hint()
        )
    }

    fn validate_path(path: &str) -> bool {
        let path = path.trim();
        let expanded = if let Some(stripped) = path.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                std::path::PathBuf::from(home).join(stripped)
            } else {
                return false;
            }
        } else {
            std::path::PathBuf::from(path)
        };
        let p = expanded.as_path();
        // Check: exists, is file, no path traversal
        // IDA can open many formats: .i64, .idb, ELF, Mach-O, PE, raw binaries, etc.
        p.exists() && p.is_file() && !path.contains("..")
    }

    fn parse_address(s: &str) -> Result<u64, ToolError> {
        let mut s = s.trim().to_string();
        s.retain(|c| c != '_');
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).map_err(|_| ToolError::InvalidAddress(s))
        } else if s.starts_with("0b") || s.starts_with("0B") {
            u64::from_str_radix(&s[2..], 2).map_err(|_| ToolError::InvalidAddress(s))
        } else if s.starts_with("0o") || s.starts_with("0O") {
            u64::from_str_radix(&s[2..], 8).map_err(|_| ToolError::InvalidAddress(s))
        } else {
            s.parse()
                .map_err(|_| ToolError::InvalidAddress(s.to_string()))
        }
    }

    fn value_to_strings(value: &Value) -> Result<Vec<String>, ToolError> {
        match value {
            Value::String(s) => {
                let trimmed = s.trim();
                if trimmed.starts_with('[') {
                    if let Ok(Value::Array(arr)) = serde_json::from_str(trimmed) {
                        let mut out = Vec::with_capacity(arr.len());
                        for v in &arr {
                            match v {
                                Value::String(s) => out.push(s.to_string()),
                                Value::Number(n) => out.push(n.to_string()),
                                _ => {
                                    return Err(ToolError::IdaError(
                                        "expected string or number".to_string(),
                                    ))
                                }
                            }
                        }
                        return Ok(out);
                    }
                }
                if trimmed.contains(',') {
                    Ok(trimmed
                        .split(',')
                        .map(|t| t.trim())
                        .filter(|t| !t.is_empty())
                        .map(|t| t.to_string())
                        .collect())
                } else if trimmed.is_empty() {
                    Err(ToolError::IdaError("empty string".to_string()))
                } else {
                    Ok(vec![trimmed.to_string()])
                }
            }
            Value::Number(n) => Ok(vec![n.to_string()]),
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::String(s) => out.push(s.to_string()),
                        Value::Number(n) => out.push(n.to_string()),
                        _ => {
                            return Err(ToolError::IdaError(
                                "expected string or number".to_string(),
                            ))
                        }
                    }
                }
                Ok(out)
            }
            _ => Err(ToolError::IdaError(
                "expected string, number, or array".to_string(),
            )),
        }
    }

    fn value_to_addresses(value: &Value) -> Result<Vec<u64>, ToolError> {
        let strings = Self::value_to_strings(value)?;
        if strings.is_empty() {
            return Err(ToolError::InvalidAddress(
                "no addresses provided".to_string(),
            ));
        }
        strings.iter().map(|s| Self::parse_address(s)).collect()
    }

    fn value_to_single_address(value: &Value) -> Result<u64, ToolError> {
        let addrs = Self::value_to_addresses(value)?;
        addrs
            .into_iter()
            .next()
            .ok_or_else(|| ToolError::InvalidAddress("empty address list".to_string()))
    }

    fn value_to_bytes(value: &Value) -> Result<Vec<u8>, ToolError> {
        match value {
            Value::String(s) => {
                let mut cleaned = String::with_capacity(s.len());
                for c in s.chars() {
                    if c.is_ascii_hexdigit() {
                        cleaned.push(c);
                    } else if c.is_ascii_whitespace()
                        || matches!(c, ',' | '_' | ':' | '-')
                        || c == 'x'
                        || c == 'X'
                    {
                        continue;
                    } else {
                        return Err(ToolError::InvalidParams(format!(
                            "invalid hex character: {c}"
                        )));
                    }
                }
                if cleaned.is_empty() {
                    return Err(ToolError::InvalidParams("no bytes provided".to_string()));
                }
                if !cleaned.len().is_multiple_of(2) {
                    return Err(ToolError::InvalidParams(
                        "hex string has odd length".to_string(),
                    ));
                }
                let mut out = Vec::with_capacity(cleaned.len() / 2);
                for i in (0..cleaned.len()).step_by(2) {
                    let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
                        .map_err(|_| ToolError::InvalidParams("invalid hex byte".to_string()))?;
                    out.push(byte);
                }
                Ok(out)
            }
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::Number(n) => {
                            let byte = n.as_u64().ok_or_else(|| {
                                ToolError::InvalidParams("invalid byte".to_string())
                            })?;
                            if byte > u8::MAX as u64 {
                                return Err(ToolError::InvalidParams(
                                    "byte value out of range".to_string(),
                                ));
                            }
                            out.push(byte as u8);
                        }
                        Value::String(s) => {
                            let val = Self::parse_address(s)?;
                            if val > u8::MAX as u64 {
                                return Err(ToolError::InvalidParams(
                                    "byte value out of range".to_string(),
                                ));
                            }
                            out.push(val as u8);
                        }
                        _ => {
                            return Err(ToolError::InvalidParams(
                                "bytes must be numbers or strings".to_string(),
                            ))
                        }
                    }
                }
                if out.is_empty() {
                    Err(ToolError::InvalidParams("no bytes provided".to_string()))
                } else {
                    Ok(out)
                }
            }
            Value::Number(n) => {
                let byte = n
                    .as_u64()
                    .ok_or_else(|| ToolError::InvalidParams("invalid byte".to_string()))?;
                if byte > u8::MAX as u64 {
                    return Err(ToolError::InvalidParams(
                        "byte value out of range".to_string(),
                    ));
                }
                Ok(vec![byte as u8])
            }
            _ => Err(ToolError::InvalidParams(
                "expected hex string or array of bytes".to_string(),
            )),
        }
    }

    /// Open an existing DSC .i64 synchronously and return db_info.
    async fn open_dsc_i64(
        &self,
        out_i64: &std::path::Path,
        module: &str,
        frameworks: &[String],
    ) -> Result<CallToolResult, McpError> {
        info!(out_i64 = %out_i64.display(), "Opening existing DSC .i64");

        let i64_str = out_i64.display().to_string();
        let open_result = self
            .worker
            .open(&i64_str, false, None, false, false, None, true, Vec::new())
            .await;

        let db_info = match open_result {
            Ok(info) => info,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let close_token = if matches!(self.mode, ServerMode::Http | ServerMode::Router(_)) {
            Some(self.worker.issue_db_ref())
        } else {
            None
        };

        let mut value = match serde_json::to_value(&db_info) {
            Ok(v) => v,
            Err(_) => {
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "{db_info:?}"
                ))]))
            }
        };
        if let Value::Object(map) = &mut value {
            map.insert("module".to_string(), json!(module));
            if !frameworks.is_empty() {
                map.insert("frameworks_loaded".to_string(), json!(frameworks));
            }
            map.insert("close_hint".to_string(), json!(self.close_hint()));
            if let Some(token) = close_token {
                map.insert("close_token".to_string(), json!(token));
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value:?}")),
        )]))
    }

    /// Background task: run idat, then open the resulting .i64 with idalib.
    async fn run_dsc_background(
        task_id: String,
        registry: task::TaskRegistry,
        worker: Arc<IdaWorker>,
        mode: ServerMode,
        ctx: DscBackgroundCtx,
    ) {
        let DscBackgroundCtx {
            idat,
            idat_args,
            script_path,
            log_path,
            out_i64,
            module,
            frameworks,
        } = ctx;

        // Phase 1: run idat subprocess
        info!(task_id = %task_id, "Background: running idat");
        registry.update_message(&task_id, "Running idat to create .i64...");

        let idat_bin = idat;
        let module_env = module.clone();
        let out_i64_clone = out_i64.clone();
        let log_path_clone = log_path.clone();

        let spawn_result = tokio::task::spawn_blocking(move || {
            let mut cmd = std::process::Command::new(&idat_bin);
            cmd.args(&idat_args);
            // Remove env vars that cause license conflicts when our
            // process links idalib and also spawns idat.
            cmd.env_remove("IDADIR");
            cmd.env_remove("DYLD_LIBRARY_PATH");
            cmd.env("IDA_DYLD_CACHE_MODULE", &module_env);
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());

            let output = cmd.output();

            match output {
                Ok(out) => {
                    let code = out.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    (code, stderr.to_string(), out_i64_clone, log_path_clone)
                }
                Err(e) => (
                    -1,
                    format!("Failed to spawn idat: {e}"),
                    out_i64_clone,
                    log_path_clone,
                ),
            }
        })
        .await;

        let (exit_code, stderr, out_path, log_out) = match spawn_result {
            Ok(tuple) => tuple,
            Err(e) => {
                let _ = std::fs::remove_file(&script_path);
                registry.fail(&task_id, &format!("idat task panicked: {e}"));
                return;
            }
        };

        // Clean up the temporary load script (idat is done with it).
        let _ = std::fs::remove_file(&script_path);

        if exit_code != 0 || !out_path.exists() {
            let log_tail = log_out
                .as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|s| {
                    let lines: Vec<&str> = s.lines().collect();
                    let start = lines.len().saturating_sub(20);
                    lines[start..].join("\n")
                });

            let mut msg = format!("idat exited with code {exit_code}.\nstderr: {stderr}");
            if let Some(tail) = log_tail {
                msg.push_str(&format!("\nlog (last 20 lines):\n{tail}"));
            }
            warn!(exit_code, task_id = %task_id, "idat failed");
            registry.fail(&task_id, &msg);
            return;
        }

        info!(task_id = %task_id, "idat completed, opening .i64");
        registry.update_message(&task_id, "Opening database with idalib...");

        // Phase 2: open the .i64 with idalib
        let i64_str = out_i64.display().to_string();
        let open_result = worker
            .open(&i64_str, false, None, false, false, None, true, Vec::new())
            .await;

        let db_info = match open_result {
            Ok(info) => info,
            Err(e) => {
                registry.fail(&task_id, &e.to_string());
                return;
            }
        };

        let close_token = if matches!(mode, ServerMode::Http | ServerMode::Router(_)) {
            Some(worker.issue_db_ref())
        } else {
            None
        };

        let mut value = serde_json::to_value(&db_info)
            .unwrap_or_else(|_| json!({"info": format!("{db_info:?}")}));
        if let Value::Object(map) = &mut value {
            map.insert("module".to_string(), json!(module));
            if !frameworks.is_empty() {
                map.insert("frameworks_loaded".to_string(), json!(frameworks));
            }
            if let Some(token) = close_token {
                map.insert("close_token".to_string(), json!(token));
            }
        }

        info!(task_id = %task_id, "DSC background task completed");
        registry.complete(&task_id, value);
    }

    async fn route_or_err(
        &self,
        router: &crate::router::RouterState,
        handle: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<CallToolResult, McpError> {
        // Enforce db_handle when multiple IDBs are open
        if handle.is_none() {
            let count = router.worker_count().await;
            if count > 1 {
                return Ok(ToolError::InvalidParams(
                    "db_handle is required when multiple databases are open. \
                     Provide the db_handle returned by open_idb."
                        .to_string(),
                )
                .to_tool_result());
            }
        }

        match router.route_request(handle, method, params).await {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| format!("{v:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    async fn open_idb_routed(
        &self,
        router: &crate::router::RouterState,
        req: &OpenIdbRequest,
    ) -> Result<CallToolResult, McpError> {
        let (db_handle, close_token) = match router.spawn_worker(&req.path).await {
            Ok(r) => r,
            Err(e) => return Ok(ToolError::OpenFailed(e.to_string()).to_tool_result()),
        };

        let params = json!({
            "path": req.path,
            "auto_analyse": true,
            "load_debug_info": req.load_debug_info.unwrap_or(false),
            "debug_info_path": req.debug_info_path,
            "debug_info_verbose": req.debug_info_verbose.unwrap_or(false),
            "force": req.force.unwrap_or(false),
            "file_type": req.file_type,
        });

        let result = match router.route_request(Some(&db_handle), "open", params).await {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let mut value = result;
        if let Value::Object(map) = &mut value {
            map.insert("db_handle".to_string(), json!(db_handle));
            if let Some(token) = close_token {
                map.insert("close_token".to_string(), json!(token));
            }
            map.insert("close_hint".to_string(), json!(self.close_hint()));
            map.insert(
                "quick_tools".to_string(),
                json!([
                    "list_functions",
                    "get_function_by_name",
                    "disassemble_function",
                    "decompile_function",
                    "get_xrefs_to",
                    "list_strings",
                    "close_idb"
                ]),
            );
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value:?}")),
        )]))
    }

    async fn close_idb_routed(
        &self,
        router: &crate::router::RouterState,
        req: &CloseIdbRequest,
    ) -> Result<CallToolResult, McpError> {
        let token = match req.token.as_deref() {
            Some(t) => t,
            None => {
                let handle = match router.active_handle().await {
                    Some(h) => h,
                    None => return Ok(ToolError::NoDatabaseOpen.to_tool_result()),
                };
                let _ = router
                    .route_request(Some(&handle), "close", json!({}))
                    .await;
                let _ = router
                    .route_request(Some(&handle), "shutdown", json!({}))
                    .await;
                let _ = router.close_worker(&handle).await;
                info!("Router: closed active worker {}", handle);
                return Ok(CallToolResult::success(vec![Content::text(
                    "Database closed",
                )]));
            }
        };

        match router.release_ref_token(token).await {
            None => Ok(CallToolResult::success(vec![Content::text(
                "close_idb ignored: invalid close_token",
            )])),
            Some((handle, remaining)) if remaining > 0 => {
                info!(
                    remaining,
                    "Router: reference released for {}, {} remaining", handle, remaining
                );
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Reference released ({remaining} client(s) still active, database remains open)"
                ))]))
            }
            Some((handle, _)) => {
                let _ = router
                    .route_request(Some(&handle), "close", json!({}))
                    .await;
                let _ = router
                    .route_request(Some(&handle), "shutdown", json!({}))
                    .await;
                let _ = router.close_worker(&handle).await;
                info!("Router: closed worker {} (last reference released)", handle);
                Ok(CallToolResult::success(vec![Content::text(
                    "Database closed",
                )]))
            }
        }
    }
}

// Tool implementations using the #[tool_router] attribute

#[tool_router]
impl IdaMcpServer {
    #[tool(
        description = "Open an IDA Pro database (.i64/.idb) or a raw binary (Mach-O/ELF/PE). \
        Raw binaries are auto-analyzed and saved as .i64 alongside the input. \
        If opening a raw binary with no existing .i64 and a sibling .dSYM is present, \
        its DWARF debug info is loaded automatically. \
        Set load_debug_info=true to force loading external debug info after open \
        (optionally specify debug_info_path). \
        Call close_idb when finished to release database locks; in multi-client servers, coordinate before closing. \
        In HTTP/SSE mode, open_idb returns a close_token that must be provided to close_idb. \
        NOTE: Opening large databases (like dyld_shared_cache) can take 30+ seconds. \
        The database stays open until close_idb is called, so you can make multiple \
        queries (list_functions, disasm, decompile, etc.) without reopening."
    )]
    #[instrument(skip(self), fields(path = %req.path))]
    async fn open_idb(
        &self,
        Parameters(req): Parameters<OpenIdbRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: open_idb");
        if !Self::validate_path(&req.path) {
            return Ok(ToolError::InvalidPath(req.path).to_tool_result());
        }

        if let ServerMode::Router(ref router) = self.mode {
            return self.open_idb_routed(router, &req).await;
        }

        match self
            .worker
            .open(
                &req.path,
                req.load_debug_info.unwrap_or(false),
                req.debug_info_path.clone(),
                req.debug_info_verbose.unwrap_or(false),
                req.force.unwrap_or(false),
                req.file_type.clone(),
                true,
                Vec::new(),
            )
            .await
        {
            Ok(info) => {
                let close_token = if matches!(self.mode, ServerMode::Http | ServerMode::Router(_)) {
                    Some(self.worker.issue_db_ref())
                } else {
                    None
                };
                let mut value = match serde_json::to_value(&info) {
                    Ok(v) => v,
                    Err(_) => {
                        return Ok(CallToolResult::success(vec![Content::text(format!(
                            "{info:?}"
                        ))]))
                    }
                };
                if let Value::Object(map) = &mut value {
                    map.insert(
                        "quick_tools".to_string(),
                        json!([
                            "list_functions",
                            "get_function_by_name",
                            "disassemble_function",
                            "decompile_function",
                            "get_xrefs_to",
                            "list_strings",
                            "close_idb"
                        ]),
                    );
                    map.insert("close_hint".to_string(), json!(self.close_hint()));
                    if let Some(token) = close_token {
                        map.insert("close_token".to_string(), json!(token));
                    }
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value:?}")),
                )]))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Open a Solana sBPF program (.so) for analysis. \
        Automatically AOT-compiles the sBPF binary to a host-native shared library via sbpf2host \
        (if needed), then opens the result in IDA Pro with full Hex-Rays decompilation support. \
        Fast-path tiers (checked in order): \
          1. <program>.dylib.i64 exists  → open directly, skip sbpf2host (fastest, all renames preserved) \
          2. <program>.dylib.id0 exists  → open unpacked IDA DB, skip sbpf2host \
          3. <program>.dylib exists      → open dylib, skip sbpf2host \
          4. none of the above           → run sbpf2host then open \
        Existing locked databases (live .imcp) are detected and reported as DatabaseLocked. \
        Dead-process lock files (.imcp with stale PID) are cleaned automatically. \
        Debug symbols (.dSYM) are loaded automatically when present. \
        Returns db_handle, close_token, sbpf_source, dylib_path, and compiled=true/false. \
        Requires sbpf2host (cargo install sbpf2host) or SBPF2HOST env var. \
        Example: open_sbpf(path: '~/programs/675kPX9.so')")]
    #[instrument(skip(self), fields(path = %req.path))]
    async fn open_sbpf(
        &self,
        Parameters(req): Parameters<OpenSbpfRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: open_sbpf");

        if !Self::validate_path(&req.path) {
            return Ok(ToolError::InvalidPath(req.path).to_tool_result());
        }

        // Override sbpf2host binary if caller specified an explicit path.
        if let Some(ref explicit) = req.sbpf2host_path {
            // SAFETY: set env only in this process; we're single-threaded at this point.
            // Using a temp env override so find_sbpf2host() picks it up.
            unsafe { std::env::set_var("SBPF2HOST", explicit) };
        }

        let input = crate::expand_path(&req.path);
        let output_dir = req.output_dir.as_deref().map(std::path::Path::new);
        let dump_ir = req.dump_ir.unwrap_or(false);

        // Compute the expected dylib output path (e.g. program.dylib on macOS).
        let dylib_path = crate::sbpf::sbpf2host_output_path(&input, output_dir);
        let dylib_str = dylib_path.display().to_string();

        // IDA replaces the dylib extension with its database extension:
        //   program.dylib  →  program.i64  (packed)
        //   program.dylib  →  program.id0  (unpacked)
        let i64_path = dylib_path.with_extension("i64");
        let id0_path = dylib_path.with_extension("id0");

        // Determine open path and whether sbpf2host compilation is needed.
        // Lock detection (live .imcp) and stale-lock cleanup happen inside handle_open.
        let (open_path_str, compiled, load_debug) = if i64_path.exists() {
            // Fast path 1: packed .i64 exists — skip sbpf2host entirely.
            info!(path = %i64_path.display(), "open_sbpf fast-path: existing .i64");
            (i64_path.display().to_string(), false, false)
        } else if id0_path.exists() {
            // Fast path 2: unpacked .id0 exists — skip sbpf2host.
            // Pass the dylib path; IDA/handle_open will find the adjacent .id0.
            info!(path = %id0_path.display(), "open_sbpf fast-path: existing unpacked .id0");
            (dylib_str.clone(), false, false)
        } else if dylib_path.exists() {
            // Fast path 3: dylib exists but no IDA database — skip sbpf2host.
            let has_dsym = crate::sbpf::sbpf2host_dsym_path(&dylib_path).exists();
            info!(path = %dylib_path.display(), "open_sbpf fast-path: existing dylib (skipping sbpf2host)");
            (dylib_str.clone(), false, has_dsym)
        } else {
            // Full path: compile sBPF → host-native dylib via sbpf2host.
            let result = match crate::sbpf::run_sbpf2host(&input, output_dir, dump_ir) {
                Ok(r) => r,
                Err(e) => return Ok(e.to_tool_result()),
            };
            let has_dsym = result.has_debug_info;
            (result.dylib_path.display().to_string(), true, has_dsym)
        };

        let idb_req = OpenIdbRequest {
            path: open_path_str.clone(),
            load_debug_info: Some(load_debug),
            debug_info_path: None,
            debug_info_verbose: None,
            force: None,
            file_type: None,
        };

        // Delegate to open_idb routing (handles close_token, db_handle, quick_tools).
        let mut result = if let ServerMode::Router(ref router) = self.mode {
            self.open_idb_routed(router, &idb_req).await?
        } else {
            self.open_idb(Parameters(idb_req)).await?
        };

        // Extract db_handle from open result (needed for subsequent queries).
        let db_handle: Option<String> = result.content.first().and_then(|c| match &c.raw {
            rmcp::model::RawContent::Text(t) => serde_json::from_str::<serde_json::Value>(&t.text)
                .ok()
                .and_then(|v| v.get("db_handle")?.as_str().map(String::from)),
            _ => None,
        });

        // Try to resolve the Solana program entrypoint for convenience.
        // The entrypoint!() macro produces a function named "entrypoint"
        // in the AOT-compiled dylib — this is the real program logic entry,
        // NOT the sbpf2host runtime wrapper ("sbpf_entrypoint").
        let entrypoint_json = if let Some(ref handle) = db_handle {
            if let ServerMode::Router(ref router) = self.mode {
                match self
                    .route_or_err(
                        router,
                        Some(handle),
                        "get_function_by_name",
                        json!({"name": "entrypoint"}),
                    )
                    .await
                {
                    Ok(r) if !r.is_error.unwrap_or(false) => {
                        r.content.first().and_then(|c| match &c.raw {
                            rmcp::model::RawContent::Text(t) => {
                                serde_json::from_str::<serde_json::Value>(&t.text).ok()
                            }
                            _ => None,
                        })
                    }
                    _ => None,
                }
            } else {
                self.worker
                    .resolve_function("entrypoint")
                    .await
                    .ok()
                    .map(|info| {
                        json!({
                            "name": info.name,
                            "address": info.address,
                            "size": info.size,
                        })
                    })
            }
        } else {
            None
        };

        // Try to detect process_instruction via callgraph analysis.
        //
        // Solana's entrypoint!() macro expands to exactly 2 calls:
        //   1. deserialize(input)   — parse input buffer into accounts/data
        //   2. process_instruction  — instruction dispatch (many sub-callees)
        //
        // Detection: entrypoint callgraph depth=2, exactly 2 direct callees,
        // the one with more sub-callees is process_instruction.
        // If the pattern doesn't match, we don't guess — return None.
        let mut process_instruction_json: Option<serde_json::Value> = 'pi: {
            let ep_addr = entrypoint_json
                .as_ref()
                .and_then(|ep| ep.get("address"))
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
            let (Some(ep_addr), Some(ref handle)) = (ep_addr, &db_handle) else {
                break 'pi None;
            };

            // Get callgraph from entrypoint (depth=2 to see sub-callees).
            let cg_value: Option<serde_json::Value> =
                if let ServerMode::Router(ref router) = self.mode {
                    match self
                        .route_or_err(
                            router,
                            Some(handle),
                            "build_callgraph",
                            json!({
                                "roots": format!("0x{:x}", ep_addr),
                                "max_depth": 2,
                                "max_nodes": 256,
                            }),
                        )
                        .await
                    {
                        Ok(r) if !r.is_error.unwrap_or(false) => {
                            r.content.first().and_then(|c| match &c.raw {
                                rmcp::model::RawContent::Text(t) => {
                                    serde_json::from_str::<serde_json::Value>(&t.text).ok()
                                }
                                _ => None,
                            })
                        }
                        _ => None,
                    }
                } else {
                    self.worker.callgraph(ep_addr, 2, 256).await.ok()
                };

            let Some(cg) = cg_value else { break 'pi None };
            let Some(edges) = cg.get("edges").and_then(|v| v.as_array()) else {
                break 'pi None;
            };

            let ep_hex = format!("0x{:x}", ep_addr);

            // Direct callees of entrypoint.
            let direct_callees: Vec<&str> = edges
                .iter()
                .filter_map(|e| {
                    if e.get("from")?.as_str()? == ep_hex {
                        e.get("to")?.as_str()
                    } else {
                        None
                    }
                })
                .collect();

            // Must be exactly 2 (deserialize + process_instruction).
            if direct_callees.len() != 2 {
                break 'pi None;
            }

            // Count sub-callees for each direct callee.
            let count0 = edges
                .iter()
                .filter(|e| e.get("from").and_then(|v| v.as_str()) == Some(direct_callees[0]))
                .count();
            let count1 = edges
                .iter()
                .filter(|e| e.get("from").and_then(|v| v.as_str()) == Some(direct_callees[1]))
                .count();

            // process_instruction has more sub-callees (instruction handlers).
            // If counts are equal, we can't distinguish — skip.
            if count0 == count1 {
                break 'pi None;
            }
            let pi_hex = if count0 > count1 {
                direct_callees[0]
            } else {
                direct_callees[1]
            };
            let Some(pi_addr) = u64::from_str_radix(pi_hex.trim_start_matches("0x"), 16).ok()
            else {
                break 'pi None;
            };

            // Get function info for the detected process_instruction.
            if let ServerMode::Router(ref router) = self.mode {
                match self
                    .route_or_err(
                        router,
                        Some(handle),
                        "get_function_at_address",
                        json!({"address": pi_hex}),
                    )
                    .await
                {
                    Ok(r) if !r.is_error.unwrap_or(false) => {
                        r.content.first().and_then(|c| match &c.raw {
                            rmcp::model::RawContent::Text(t) => {
                                serde_json::from_str::<serde_json::Value>(&t.text).ok()
                            }
                            _ => None,
                        })
                    }
                    _ => None,
                }
            } else {
                self.worker
                    .function_at(Some(pi_addr), None, 0)
                    .await
                    .ok()
                    .map(|info| {
                        json!({
                            "name": info.name,
                            "address": info.address,
                            "size": info.size,
                        })
                    })
            }
        };

        // Rename the detected process_instruction in IDA for convenience.
        // Update the JSON name field to reflect the rename.
        if let Some(ref mut pi) = process_instruction_json {
            if let Some(pi_addr_str) = pi.get("address").and_then(|v| v.as_str()).map(String::from)
            {
                let current_name = pi.get("name").and_then(|v| v.as_str()).map(String::from);
                let renamed = if let Some(ref handle) = db_handle {
                    if let ServerMode::Router(ref router) = self.mode {
                        self.route_or_err(
                            router,
                            Some(handle),
                            "rename_symbol",
                            json!({
                                "address": pi_addr_str,
                                "new_name": "process_instruction",
                            }),
                        )
                        .await
                        .is_ok()
                    } else if let Some(addr) =
                        u64::from_str_radix(pi_addr_str.trim_start_matches("0x"), 16).ok()
                    {
                        self.worker
                            .rename(Some(addr), current_name, "process_instruction".into(), 0)
                            .await
                            .is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                };
                if renamed {
                    if let Some(map) = pi.as_object_mut() {
                        map.insert("name".to_string(), json!("process_instruction"));
                    }
                }
            }
        }
        // Annotate response with sBPF-specific fields.
        if let Some(text) = result.content.first_mut().and_then(|c| {
            if let rmcp::model::RawContent::Text(ref mut t) = c.raw {
                Some(t)
            } else {
                None
            }
        }) {
            if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&text.text) {
                if let Some(map) = val.as_object_mut() {
                    map.insert("sbpf_source".to_string(), json!(req.path));
                    map.insert("dylib_path".to_string(), json!(dylib_str));
                    map.insert("compiled".to_string(), json!(compiled));
                    if let Some(ep) = entrypoint_json {
                        map.insert("entrypoint".to_string(), ep);
                    }
                    if let Some(pi) = process_instruction_json {
                        map.insert("process_instruction".to_string(), pi);
                    }
                }
                text.text =
                    serde_json::to_string_pretty(&val).unwrap_or_else(|_| text.text.clone());
            }
        }

        Ok(result)
    }

    #[tool(
        description = "Load external debug info (e.g., DWARF/dSYM) into the current database. \
        If path is omitted, attempts to locate a sibling .dSYM for the currently-open database."
    )]
    #[instrument(skip(self))]
    async fn load_debug_info(
        &self,
        Parameters(req): Parameters<LoadDebugInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: load_debug_info");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "load_debug_info",
                    json!({"path": req.path, "verbose": req.verbose.unwrap_or(false)}),
                )
                .await;
        }
        match self
            .worker
            .load_debug_info(req.path, req.verbose.unwrap_or(false))
            .await
        {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&info).unwrap_or_else(|_| format!("{info:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Report auto-analysis status (auto_is_ok, auto_state). \
        Use this to check whether analysis-dependent tools (xrefs, decompile) are fully ready.")]
    #[instrument(skip(self))]
    async fn get_analysis_status(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_analysis_status");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(router, None, "get_analysis_status", json!({}))
                .await;
        }
        match self.worker.analysis_status().await {
            Ok(status) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&status).unwrap_or_else(|_| format!("{status:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Close the currently open IDA database. \
        Call this when you're done analyzing to free resources. \
        In HTTP/SSE mode, provide the close_token returned by open_idb. \
        The database can also be left open for the duration of the session.")]
    #[instrument(skip(self))]
    async fn close_idb(
        &self,
        Parameters(req): Parameters<CloseIdbRequest>,
    ) -> Result<CallToolResult, McpError> {
        info!("Tool call: close_idb received");

        if let ServerMode::Router(ref router) = self.mode {
            return self.close_idb_routed(router, &req).await;
        }

        if matches!(self.mode, ServerMode::Http) {
            let token = match req.token.as_deref() {
                Some(t) => t,
                None => {
                    info!("close_idb ignored: close_token required in HTTP mode");
                    return Ok(CallToolResult::success(vec![Content::text(
                        "close_idb ignored: close_token required in HTTP mode",
                    )]));
                }
            };
            match self.worker.release_db_ref(token) {
                None => {
                    info!("close_idb: invalid or already-released token");
                    return Ok(CallToolResult::success(vec![Content::text(
                        "close_idb: invalid or expired token",
                    )]));
                }
                Some(remaining) if remaining > 0 => {
                    info!(
                        remaining,
                        "close_idb: reference released, database still open"
                    );
                    return Ok(CallToolResult::success(vec![Content::text(format!(
                        "Reference released ({remaining} client(s) still active, database remains open)"
                    ))]));
                }
                Some(0) => {}
                _ => unreachable!(),
            }
        }

        match self.worker.close().await {
            Ok(()) => {
                self.worker.clear_db_refs();
                info!("Tool call: close_idb completed successfully");
                Ok(CallToolResult::success(vec![Content::text(
                    "Database closed",
                )]))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Discover available tools by query or category. \
        Use this to find the right tool for your task before calling tool_help for full details.")]
    #[instrument(skip(self))]
    async fn tool_catalog(
        &self,
        Parameters(req): Parameters<ToolCatalogRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_catalog");
        let limit = req.limit.unwrap_or(7).min(15);

        // If category specified, list tools in that category
        if let Some(cat_str) = &req.category {
            if let Ok(cat) = cat_str.parse::<ToolCategory>() {
                let tools: Vec<_> = tool_registry::tools_by_category(cat)
                    .take(limit)
                    .map(|t| {
                        json!({
                            "name": t.name,
                            "description": t.short_desc,
                            "category": t.category.as_str(),
                        })
                    })
                    .collect();

                return Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({
                        "category": cat.as_str(),
                        "category_description": cat.description(),
                        "tools": tools,
                        "hint": "Use tool_help(name) for full documentation and examples"
                    }))
                    .unwrap(),
                )]));
            }
        }

        // If query specified, search for matching tools
        if let Some(query) = &req.query {
            let results = tool_registry::search_tools(query, limit);
            let tools: Vec<_> = results
                .iter()
                .map(|(t, keywords)| {
                    json!({
                        "name": t.name,
                        "description": t.short_desc,
                        "category": t.category.as_str(),
                        "matched": keywords,
                    })
                })
                .collect();

            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({
                    "query": query,
                    "tools": tools,
                    "hint": "Use tool_help(name) for full documentation and examples"
                }))
                .unwrap(),
            )]));
        }

        // No query or category - list all categories
        let categories: Vec<_> = ToolCategory::all()
            .iter()
            .map(|c| {
                let count = tool_registry::tools_by_category(*c).count();
                json!({
                    "category": c.as_str(),
                    "description": c.description(),
                    "tool_count": count,
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "categories": categories,
                "hint": "Use tool_catalog(category='...') to list tools in a category, or tool_catalog(query='...') to search. tools/list already includes all tools."
            }))
            .unwrap(),
        )]))
    }

    #[tool(
        description = "Get full documentation for a tool including description, parameters schema, and example."
    )]
    #[instrument(skip(self))]
    async fn tool_help(
        &self,
        Parameters(req): Parameters<ToolHelpRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_help for {}", req.name);

        if let Some(tool) = tool_registry::get_tool(&req.name) {
            let params = tool_params_schema(&req.name);
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({
                    "name": tool.name,
                    "category": tool.category.as_str(),
                    "description": tool.full_desc,
                    "parameters": params,
                    "example": tool.example,
                    "keywords": tool.keywords,
                }))
                .unwrap(),
            )]))
        } else {
            // Suggest similar tools
            let suggestions = tool_registry::search_tools(&req.name, 3);
            let suggestion_names: Vec<_> = suggestions.iter().map(|(t, _)| t.name).collect();

            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({
                    "error": format!("Tool '{}' not found", req.name),
                    "suggestions": suggestion_names,
                    "hint": "Use tool_catalog to discover available tools"
                }))
                .unwrap(),
            )]))
        }
    }

    #[tool(description = "List all functions in the database (paginated). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn list_functions(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_functions");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_functions",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        // Clamp limit to prevent excessive responses
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let filter = req.filter.clone();

        match self
            .worker
            .list_functions(offset, limit, filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List functions (ida-pro-mcp compatible alias). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn list_funcs(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_funcs");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_functions",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let filter = req.filter.clone();

        match self
            .worker
            .list_functions(offset, limit, filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Resolve a function name to its address")]
    #[instrument(skip(self), fields(name = %req.name))]
    async fn get_function_by_name(
        &self,
        Parameters(req): Parameters<ResolveFunctionRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_function_by_name");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_function_by_name",
                    json!({"name": req.name}),
                )
                .await;
        }
        match self.worker.resolve_function(&req.name).await {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&info).unwrap_or_else(|_| format!("{:?}", info)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Get the type/prototype declaration of a function at a given address or name"
    )]
    async fn get_function_prototype(
        &self,
        Parameters(req): Parameters<GetFunctionPrototypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_function_prototype",
                    json!({"address": req.address, "name": req.name}),
                )
                .await;
        }
        let addr = req
            .address
            .as_ref()
            .and_then(crate::rpc_dispatch::parse_address_value);
        match self.worker.get_function_prototype(addr, req.name).await {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| format!("{v:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get address context (segment, function, nearest symbol)")]
    async fn get_address_info(
        &self,
        Parameters(req): Parameters<AddrInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_address_info",
                    json!({"addr": req.address, "name": req.target_name, "offset": req.offset}),
                )
                .await;
        }
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .addr_info(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&info).unwrap_or_else(|_| format!("{:?}", info)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get the function that contains an address")]
    async fn get_function_at_address(
        &self,
        Parameters(req): Parameters<FunctionAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_function_at_address",
                    json!({"addr": req.address, "name": req.target_name, "offset": req.offset}),
                )
                .await;
        }
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .function_at(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&info).unwrap_or_else(|_| format!("{:?}", info)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get disassembly at an address")]
    #[instrument(skip(self), fields(address = %req.address, count = req.count))]
    async fn disassemble(
        &self,
        Parameters(req): Parameters<DisasmRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disassemble");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "disassemble",
                    json!({"address": req.address, "count": req.count}),
                )
                .await;
        }
        // Clamp instruction count
        let count = req.count.unwrap_or(10).min(1000);
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.disasm(addrs[0], count).await {
                Ok(text) => Ok(CallToolResult::success(vec![Content::text(text)])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.disasm(addr, count).await {
                    Ok(text) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "disasm": text
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get disassembly for a function by name")]
    #[instrument(skip(self), fields(name = %req.name, count = req.count))]
    async fn disassemble_function(
        &self,
        Parameters(req): Parameters<DisasmByNameRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disassemble_function");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "disassemble_function",
                    json!({"name": req.name, "count": req.count}),
                )
                .await;
        }
        let count = req.count.unwrap_or(10).min(1000);

        match self.worker.disasm_by_name(&req.name, count).await {
            Ok(text) => Ok(CallToolResult::success(vec![Content::text(text)])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Disassemble the function containing an address")]
    async fn disassemble_function_at(
        &self,
        Parameters(req): Parameters<DisasmFunctionAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "disassemble_function_at",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let count = req.count.unwrap_or(200).min(5000);
        match self
            .worker
            .disasm_function_at(addr, req.target_name.clone(), offset, count)
            .await
        {
            Ok(text) => Ok(CallToolResult::success(vec![Content::text(text)])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Decompile a function using Hex-Rays (if available)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn decompile_function(
        &self,
        Parameters(req): Parameters<DecompileRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: decompile_function");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "decompile_function",
                    json!({"address": req.address}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.decompile(addrs[0]).await {
                Ok(code) => Ok(CallToolResult::success(vec![Content::text(code)])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.decompile(addr).await {
                    Ok(code) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "decompile": code
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(
        description = "Get decompiled pseudocode at a specific address or address range. \
        Unlike 'decompile' which returns the full function, this returns only the statements \
        that correspond to the given address(es). Useful for getting pseudocode for a basic block \
        or specific instruction. If end_address is provided, returns statements covering the range."
    )]
    #[instrument(skip(self), fields(address = %req.address, end_address = ?req.end_address))]
    async fn get_pseudocode_at(
        &self,
        Parameters(req): Parameters<PseudocodeAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_pseudocode_at");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_pseudocode_at",
                    json!({"address": req.address, "end_addr": req.end_address}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let end_addr = if let Some(ref end_str) = req.end_address {
            match Self::parse_address(end_str) {
                Ok(a) => Some(a),
                Err(e) => return Ok(e.to_tool_result()),
            }
        } else {
            None
        };

        if addrs.len() == 1 {
            match self.worker.pseudocode_at(addrs[0], end_addr).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.pseudocode_at(addr, end_addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "pseudocode": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(
        description = "Decompile a function and return structured AST (ctree) as JSON. \
    Unlike 'decompile' which returns plain C pseudocode text, this returns \
    the full Hex-Rays ctree with nodes for every statement and expression \
    (if/while/call/asg/add/var/num/...), local variables with types, \
    and function signature. Useful for programmatic analysis of decompiled code."
    )]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn decompile_structured(
        &self,
        Parameters(req): Parameters<DecompileStructuredRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: decompile_structured");

        let addr = match Self::value_to_single_address(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_depth = req.max_depth.unwrap_or(20).min(50);
        let include_types = req.include_types.unwrap_or(false);
        let include_addresses = req.include_addresses.unwrap_or(true);
        let script = crate::ida::handlers::disasm::decompile_structured_script(
            addr,
            max_depth,
            include_types,
            include_addresses,
        );

        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "run_script",
                    json!({"code": script, "timeout_secs": 120}),
                )
                .await;
        }

        match self.worker.run_script(&script, Some(120)).await {
            Ok(result) => {
                if !run_script_succeeded(&result) {
                    let message = run_script_failure_message(&result);
                    return Ok(ToolError::IdaError(message).to_tool_result());
                }
                let stdout = run_script_field(&result, "stdout").unwrap_or("{}");
                match serde_json::from_str::<Value>(stdout) {
                    Ok(parsed) => {
                        if parsed.get("error").is_some() {
                            return Ok(ToolError::IdaError(
                                parsed["error"].as_str().unwrap_or("unknown").to_string(),
                            )
                            .to_tool_result());
                        }
                        Ok(CallToolResult::success(vec![Content::text(
                            serde_json::to_string_pretty(&parsed).unwrap_or_default(),
                        )]))
                    }
                    Err(_) => Ok(CallToolResult::success(vec![Content::text(stdout)])),
                }
            }
            Err(ToolError::Timeout(secs)) => Ok(ToolError::IdaError(format!(
                "decompile_structured timed out after {}s",
                secs
            ))
            .to_tool_result()),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Decompile multiple functions at once, returning pseudocode for each address"
    )]
    async fn batch_decompile(
        &self,
        Parameters(req): Parameters<BatchDecompileRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: batch_decompile");

        let addrs: Vec<Value> = if let Some(arr) = req.addresses.as_array() {
            arr.clone()
        } else if let Some(s) = req.addresses.as_str() {
            serde_json::from_str(s).unwrap_or_else(|_| vec![req.addresses.clone()])
        } else {
            vec![req.addresses.clone()]
        };

        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "batch_decompile",
                    json!({ "addresses": addrs }),
                )
                .await;
        }

        let mut results = Vec::new();
        for addr_val in &addrs {
            let addr = match Self::value_to_single_address(addr_val) {
                Ok(a) => a,
                Err(e) => {
                    results.push(json!({
                        "address": addr_val,
                        "error": e.to_string(),
                        "success": false,
                    }));
                    continue;
                }
            };

            match self.worker.decompile(addr).await {
                Ok(code) => results.push(json!({
                    "address": addr_val,
                    "pseudocode": code,
                    "success": true,
                })),
                Err(e) => results.push(json!({
                    "address": addr_val,
                    "error": e.to_string(),
                    "success": false,
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&results).unwrap_or_default(),
        )]))
    }

    #[tool(description = "Search all functions' decompiled pseudocode for a text pattern")]
    async fn search_pseudocode(
        &self,
        Parameters(req): Parameters<SearchPseudocodeRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: search_pseudocode");

        let limit = req.limit.unwrap_or(20).min(100);

        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "search_pseudocode",
                    json!({
                        "pattern": req.pattern,
                        "limit": limit,
                        "timeout_secs": req.timeout_secs,
                    }),
                )
                .await;
        }

        let funcs = self
            .worker
            .list_functions(0, 10000, None, req.timeout_secs)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut matches = Vec::new();
        for func in &funcs.functions {
            if matches.len() >= limit {
                break;
            }
            let addr = u64::from_str_radix(func.address.trim_start_matches("0x"), 16).unwrap_or(0);
            if let Ok(result) = self.worker.decompile(addr).await {
                if result.contains(&req.pattern) {
                    matches.push(json!({
                        "address": func.address,
                        "name": func.name,
                        "pseudocode": result,
                    }));
                }
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "pattern": req.pattern,
                "matches": matches,
                "total_searched": funcs.functions.len(),
            }))
            .unwrap_or_default(),
        )]))
    }

    #[tool(description = "Scan a table in memory by reading entries at stride intervals")]
    async fn scan_memory_table(
        &self,
        Parameters(req): Parameters<TableScanRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: scan_memory_table");

        let stride = req.stride.unwrap_or(8).max(1);
        let count = req.count.unwrap_or(16).min(256);

        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "scan_memory_table",
                    json!({
                        "base_address": req.base_address,
                        "stride": stride,
                        "count": count,
                    }),
                )
                .await;
        }

        let base_addr = Self::value_to_single_address(&req.base_address).map_err(|_| {
            McpError::invalid_params("base_address is required and must be a valid address", None)
        })?;

        let mut entries = Vec::new();
        for i in 0..count {
            let offset = (i as u64) * stride;
            let addr = base_addr + offset;
            match self
                .worker
                .get_bytes(Some(addr), None, 0, stride as usize)
                .await
            {
                Ok(r) => {
                    entries.push(json!({
                        "index": i,
                        "address": format!("0x{:x}", addr),
                        "bytes": r.bytes,
                    }));
                }
                Err(e) => {
                    entries.push(json!({
                        "index": i,
                        "address": format!("0x{:x}", addr),
                        "error": e.to_string(),
                    }));
                    break;
                }
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "base_address": format!("0x{:x}", base_addr),
                "stride": stride,
                "count": entries.len(),
                "entries": entries,
            }))
            .unwrap_or_default(),
        )]))
    }

    #[tool(
        description = "Decompile two functions and return a line-by-line diff of their pseudocode"
    )]
    async fn diff_pseudocode(
        &self,
        Parameters(req): Parameters<DiffFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: diff_pseudocode");

        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "diff_pseudocode",
                    json!({
                        "addr1": req.addr1,
                        "addr2": req.addr2,
                    }),
                )
                .await;
        }

        let addr1 = Self::value_to_single_address(&req.addr1).map_err(|_| {
            McpError::invalid_params("addr1 is required and must be a valid address", None)
        })?;
        let addr2 = Self::value_to_single_address(&req.addr2).map_err(|_| {
            McpError::invalid_params("addr2 is required and must be a valid address", None)
        })?;

        let result1 = self.worker.decompile(addr1).await.map_err(|e| {
            McpError::internal_error(format!("Failed to decompile addr1: {}", e), None)
        })?;
        let result2 = self.worker.decompile(addr2).await.map_err(|e| {
            McpError::internal_error(format!("Failed to decompile addr2: {}", e), None)
        })?;

        let lines1: Vec<&str> = result1.lines().collect();
        let lines2: Vec<&str> = result2.lines().collect();

        let mut diff_lines = Vec::new();
        let max_len = lines1.len().max(lines2.len());
        let mut same = 0usize;
        let mut different = 0usize;

        for i in 0..max_len {
            match (lines1.get(i), lines2.get(i)) {
                (Some(l1), Some(l2)) => {
                    if l1 == l2 {
                        diff_lines.push(format!("  {}", l1));
                        same += 1;
                    } else {
                        diff_lines.push(format!("- {}", l1));
                        diff_lines.push(format!("+ {}", l2));
                        different += 1;
                    }
                }
                (Some(l1), None) => {
                    diff_lines.push(format!("- {}", l1));
                    different += 1;
                }
                (None, Some(l2)) => {
                    diff_lines.push(format!("+ {}", l2));
                    different += 1;
                }
                (None, None) => {}
            }
        }

        let total = same + different;
        let similarity = if total == 0 {
            1.0f64
        } else {
            same as f64 / total as f64
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "function1": result1,
                "function2": result2,
                "similarity_ratio": (similarity * 100.0).round() / 100.0,
                "diff_lines": diff_lines,
            }))
            .unwrap_or_default(),
        )]))
    }

    #[tool(description = "List all segments in the database with their permissions and types")]
    #[instrument(skip(self))]
    async fn list_segments(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_segments");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(router, None, "list_segments", json!({}))
                .await;
        }
        match self.worker.segments().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "List or find strings in the database (supports query/exact/case-insensitive options). \
        For large databases, consider setting timeout_secs (default: 120, max: 600)."
    )]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, query = ?req.query, filter = ?req.filter))]
    async fn list_strings(
        &self,
        Parameters(req): Parameters<ListStringsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_strings");
        let query = req.query.or(req.filter);

        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_strings",
                    json!({
                        "query": query,
                        "exact": req.exact,
                        "case_insensitive": req.case_insensitive,
                        "offset": req.offset,
                        "limit": req.limit,
                        "timeout_secs": req.timeout_secs,
                    }),
                )
                .await;
        }

        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        if let Some(q) = query {
            let exact = req.exact.unwrap_or(false);
            let case_insensitive = req.case_insensitive.unwrap_or(true);
            match self
                .worker
                .find_string(q, exact, case_insensitive, offset, limit, req.timeout_secs)
                .await
            {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            match self
                .worker
                .strings(offset, limit, None, req.timeout_secs)
                .await
            {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        }
    }

    #[tool(description = "Find strings and return xrefs to each match. \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    async fn get_xrefs_to_string(
        &self,
        Parameters(req): Parameters<XrefsToStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_xrefs_to_string",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let exact = req.exact.unwrap_or(false);
        let case_insensitive = req.case_insensitive.unwrap_or(true);
        let max_xrefs = req.max_xrefs.unwrap_or(64);
        match self
            .worker
            .xrefs_to_string(
                req.query.clone(),
                exact,
                case_insensitive,
                offset,
                limit,
                max_xrefs,
                req.timeout_secs,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get cross-references TO an address (who references this address)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_xrefs_to(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_xrefs_to");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_xrefs_to",
                    json!({"address": req.address}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.xrefs_to(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.xrefs_to(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "xrefs": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get cross-references FROM an address (what this address references)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_xrefs_from(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_xrefs_from");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_xrefs_from",
                    json!({"address": req.address}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.xrefs_from(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.xrefs_from(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "xrefs": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "List imports (external symbols) with pagination")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn list_imports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_imports");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_imports",
                    json!({"offset": req.offset, "limit": req.limit}),
                )
                .await;
        }
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self.worker.imports(offset, limit).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List exports/names (public symbols) with pagination")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn list_exports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_exports");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_exports",
                    json!({"offset": req.offset, "limit": req.limit}),
                )
                .await;
        }
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self.worker.exports(offset, limit).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get entry point addresses of the binary")]
    #[instrument(skip(self))]
    async fn list_entry_points(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_entry_points");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(router, None, "list_entry_points", json!({}))
                .await;
        }
        match self.worker.entrypoints().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Read raw bytes from an address as hex string")]
    #[instrument(skip(self), fields(size = req.size))]
    async fn read_bytes(
        &self,
        Parameters(req): Parameters<GetBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_bytes");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "read_bytes",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let size = req.size.unwrap_or(256).min(0x10000);
        if let Some(addr_value) = req.address.as_ref() {
            let addrs = match Self::value_to_addresses(addr_value) {
                Ok(a) => a,
                Err(e) => return Ok(e.to_tool_result()),
            };

            if addrs.len() == 1 {
                match self.worker.get_bytes(Some(addrs[0]), None, 0, size).await {
                    Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                        serde_json::to_string_pretty(&result)
                            .unwrap_or_else(|_| format!("{:?}", result)),
                    )])),
                    Err(e) => Ok(e.to_tool_result()),
                }
            } else {
                let mut results = Vec::new();
                for addr in addrs {
                    match self.worker.get_bytes(Some(addr), None, 0, size).await {
                        Ok(result) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "bytes": result
                        })),
                        Err(e) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "error": e.to_string()
                        })),
                    }
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({ "results": results }))
                        .unwrap_or_else(|_| format!("{:?}", results)),
                )]))
            }
        } else if let Some(name) = req.target_name.as_ref() {
            let offset = req.offset.unwrap_or(0);
            match self
                .worker
                .get_bytes(None, Some(name.clone()), offset, size)
                .await
            {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            Ok(ToolError::InvalidParams("address or name required".to_string()).to_tool_result())
        }
    }

    #[tool(description = "Get basic blocks of a function (control flow graph nodes)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_basic_blocks(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_basic_blocks");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_basic_blocks",
                    json!({"address": req.address}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.basic_blocks(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.basic_blocks(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "basic_blocks": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get functions called BY a function (callees/children in call graph)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_callees(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_callees");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_callees",
                    json!({"address": req.address}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.callees(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.callees(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "callees": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get functions that CALL a function (callers/parents in call graph)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_callers(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_callers");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_callers",
                    json!({"address": req.address}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.callers(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.callers(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "callers": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get IDB metadata (ida-pro-mcp compatibility)")]
    #[instrument(skip(self))]
    async fn get_database_info(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_database_info");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(router, None, "get_database_info", json!({}))
                .await;
        }
        match self.worker.idb_meta().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Lookup functions by name or address (batch)")]
    #[instrument(skip(self))]
    async fn batch_lookup_functions(
        &self,
        Parameters(req): Parameters<LookupFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: batch_lookup_functions");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "batch_lookup_functions",
                    json!({"queries": req.queries}),
                )
                .await;
        }
        let queries = match Self::value_to_strings(&req.queries) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.lookup_funcs(queries).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List global names (non-function symbols). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn list_globals(
        &self,
        Parameters(req): Parameters<ListGlobalsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_globals");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_globals",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .list_globals(req.query.clone(), offset, limit, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find byte patterns (ida-pro-mcp compatibility). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self))]
    async fn search_bytes(
        &self,
        Parameters(req): Parameters<FindBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: search_bytes");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "search_bytes",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let timeout_secs = req.timeout_secs;
        let mut results = Vec::new();

        for pattern in patterns {
            let max_results = (offset + limit).min(20000);
            match self
                .worker
                .find_bytes(pattern.clone(), max_results, timeout_secs)
                .await
            {
                Ok(value) => {
                    let matches = value
                        .get("matches")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let total = matches.len();
                    let sliced = matches
                        .into_iter()
                        .skip(offset)
                        .take(limit)
                        .collect::<Vec<_>>();
                    let next_offset = if offset + limit < total {
                        Some(offset + limit)
                    } else {
                        None
                    };
                    results.push(json!({
                        "pattern": pattern,
                        "matches": sliced,
                        "total": total,
                        "next_offset": next_offset
                    }));
                }
                Err(e) => results.push(json!({
                    "pattern": pattern,
                    "error": e.to_string()
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({ "results": results }))
                .unwrap_or_else(|_| format!("{:?}", results)),
        )]))
    }

    #[tool(
        description = "Search for text or immediates (ida-pro-mcp compatibility). \
        For large databases, consider setting timeout_secs (default: 120, max: 600)."
    )]
    #[instrument(skip(self))]
    async fn search_text(
        &self,
        Parameters(req): Parameters<SearchRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: search_text");
        if let ServerMode::Router(ref router) = self.mode {
            let db_handle = req.db_handle.as_deref();
            let kind = req.kind.as_deref().unwrap_or("auto").to_lowercase();
            let targets = match Self::value_to_strings(&req.targets) {
                Ok(v) => v,
                Err(e) => return Ok(e.to_tool_result()),
            };
            let mut results = Vec::new();
            for target in &targets {
                let (method, params) = if kind == "imm" || kind == "immediate" {
                    (
                        "search_imm",
                        json!({"imm": target.parse::<u64>().unwrap_or(0), "max_results": req.limit, "timeout_secs": req.timeout_secs}),
                    )
                } else if kind == "text" || kind == "string" {
                    (
                        "search_text",
                        json!({"text": target, "max_results": req.limit, "timeout_secs": req.timeout_secs}),
                    )
                } else if Self::parse_address(target).is_ok() {
                    (
                        "search_imm",
                        json!({"imm": Self::parse_address(target).unwrap_or(0), "max_results": req.limit, "timeout_secs": req.timeout_secs}),
                    )
                } else {
                    (
                        "search_text",
                        json!({"text": target, "max_results": req.limit, "timeout_secs": req.timeout_secs}),
                    )
                };
                match router.route_request(db_handle, method, params).await {
                    Ok(v) => results.push(json!({"target": target, "result": v})),
                    Err(e) => results.push(json!({"target": target, "error": e.to_string()})),
                }
            }
            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({"results": results})).unwrap_or_default(),
            )]));
        }
        let targets = match Self::value_to_strings(&req.targets) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let timeout_secs = req.timeout_secs;
        let kind = req.kind.as_deref().unwrap_or("auto").to_lowercase();

        let mut results = Vec::new();
        for target in targets {
            let max_results = (offset + limit).min(20000);
            let search_result = if kind == "imm" || kind == "immediate" {
                match Self::parse_address(&target) {
                    Ok(val) => self.worker.search_imm(val, max_results, timeout_secs).await,
                    Err(e) => {
                        results.push(json!({
                            "target": target,
                            "error": e.to_string()
                        }));
                        continue;
                    }
                }
            } else if kind == "text" || kind == "string" {
                self.worker
                    .search_text(target.clone(), max_results, timeout_secs)
                    .await
            } else if let Ok(val) = Self::parse_address(&target) {
                self.worker.search_imm(val, max_results, timeout_secs).await
            } else {
                self.worker
                    .search_text(target.clone(), max_results, timeout_secs)
                    .await
            };

            match search_result {
                Ok(value) => {
                    let matches = value
                        .get("matches")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let total = matches.len();
                    let sliced = matches
                        .into_iter()
                        .skip(offset)
                        .take(limit)
                        .collect::<Vec<_>>();
                    let next_offset = if offset + limit < total {
                        Some(offset + limit)
                    } else {
                        None
                    };
                    results.push(json!({
                        "target": target,
                        "matches": sliced,
                        "total": total,
                        "next_offset": next_offset
                    }));
                }
                Err(e) => results.push(json!({
                    "target": target,
                    "error": e.to_string()
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({ "results": results }))
                .unwrap_or_else(|_| format!("{:?}", results)),
        )]))
    }

    #[tool(description = "Read u8 values at address(es)")]
    #[instrument(skip(self))]
    async fn read_byte(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "read_int",
                    json!({"address": req.address, "size": 1}),
                )
                .await;
        }
        get_int_values(&self.worker, req.address, 1).await
    }

    #[tool(description = "Read u16 values at address(es)")]
    #[instrument(skip(self))]
    async fn read_word(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "read_int",
                    json!({"address": req.address, "size": 2}),
                )
                .await;
        }
        get_int_values(&self.worker, req.address, 2).await
    }

    #[tool(description = "Read u32 values at address(es)")]
    #[instrument(skip(self))]
    async fn read_dword(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "read_int",
                    json!({"address": req.address, "size": 4}),
                )
                .await;
        }
        get_int_values(&self.worker, req.address, 4).await
    }

    #[tool(description = "Read u64 values at address(es)")]
    #[instrument(skip(self))]
    async fn read_qword(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "read_int",
                    json!({"address": req.address, "size": 8}),
                )
                .await;
        }
        get_int_values(&self.worker, req.address, 8).await
    }

    #[tool(description = "Read string(s) at address(es)")]
    #[instrument(skip(self))]
    async fn read_string(
        &self,
        Parameters(req): Parameters<GetStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_string");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "read_string",
                    json!({"address": req.address, "max_len": req.max_len}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_len = req.max_len.unwrap_or(256).min(0x10000);

        if addrs.len() == 1 {
            match self.worker.get_string(addrs[0], max_len).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.get_string(addr, max_len).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "string": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get global value(s) by name or address")]
    #[instrument(skip(self))]
    async fn read_global_variable(
        &self,
        Parameters(req): Parameters<GetGlobalValueRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_global_variable");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "read_global_variable",
                    json!({"query": req.query}),
                )
                .await;
        }
        let queries = match Self::value_to_strings(&req.query) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if queries.len() == 1 {
            match self.worker.get_global_value(queries[0].clone()).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for query in queries {
                match self.worker.get_global_value(query.clone()).await {
                    Ok(result) => results.push(json!({
                        "query": query,
                        "value": result
                    })),
                    Err(e) => results.push(json!({
                        "query": query,
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Find paths between two addresses (CFG)")]
    #[instrument(skip(self))]
    async fn find_control_flow_paths(
        &self,
        Parameters(req): Parameters<FindPathsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_control_flow_paths");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "find_control_flow_paths",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let start = match Self::value_to_single_address(&req.start) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let end = match Self::value_to_single_address(&req.end) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_paths = req.max_paths.unwrap_or(8).min(128);
        let max_depth = req.max_depth.unwrap_or(64).min(2048);

        match self
            .worker
            .find_paths(start, end, max_paths, max_depth)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Build a callgraph rooted at an address")]
    #[instrument(skip(self))]
    async fn build_callgraph(
        &self,
        Parameters(req): Parameters<CallGraphRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: build_callgraph");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "build_callgraph",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let roots = match Self::value_to_addresses(&req.roots) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_depth = req.max_depth.unwrap_or(2).min(16);
        let max_nodes = req.max_nodes.unwrap_or(256).min(10000);

        if roots.len() == 1 {
            match self.worker.callgraph(roots[0], max_depth, max_nodes).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for root in roots {
                match self.worker.callgraph(root, max_depth, max_nodes).await {
                    Ok(result) => results.push(json!({
                        "root": format!("{:#x}", root),
                        "callgraph": result
                    })),
                    Err(e) => results.push(json!({
                        "root": format!("{:#x}", root),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Compute xref matrix for a set of addresses")]
    #[instrument(skip(self))]
    async fn build_xref_matrix(
        &self,
        Parameters(req): Parameters<XrefMatrixRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: build_xref_matrix");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "build_xref_matrix",
                    json!({"addrs": req.addrs}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.addrs) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.xref_matrix(addrs).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Export functions (ida-pro-mcp compatibility)")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn export_functions(
        &self,
        Parameters(req): Parameters<ExportFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: export_functions");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "export_functions",
                    json!({"offset": req.offset, "limit": req.limit}),
                )
                .await;
        }
        if let Some(fmt) = req.format.as_deref() {
            if fmt.to_lowercase() != "json" {
                return Ok(ToolError::NotSupported(format!(
                    "format {} not supported (only json)",
                    fmt
                ))
                .to_tool_result());
            }
        }
        if let Some(addrs) = req.addrs {
            let queries = match Self::value_to_strings(&addrs) {
                Ok(v) => v,
                Err(e) => return Ok(e.to_tool_result()),
            };
            match self.worker.lookup_funcs(queries).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let limit = req.limit.unwrap_or(100).min(10000);
            let offset = req.offset.unwrap_or(0);
            match self.worker.export_funcs(offset, limit).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        }
    }

    #[tool(description = "Convert integers between bases")]
    #[instrument(skip(self))]
    async fn convert_number(
        &self,
        Parameters(req): Parameters<IntConvertRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: convert_number");
        let inputs = match Self::value_to_strings(&req.inputs) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let mut results = Vec::new();
        for input in inputs {
            match Self::parse_address(&input) {
                Ok(value) => {
                    let le = value.to_le_bytes();
                    let be = value.to_be_bytes();
                    let le_trim = trim_bytes_le(&le);
                    let be_trim = trim_bytes_be(&be);
                    results.push(json!({
                        "input": input,
                        "value": value,
                        "dec": value.to_string(),
                        "hex": format!("0x{:x}", value),
                        "bin": format!("0b{:b}", value),
                        "bytes_le": hex_encode(&le_trim),
                        "bytes_be": hex_encode(&be_trim),
                        "ascii": bytes_to_ascii(&le_trim),
                    }));
                }
                Err(e) => results.push(json!({
                    "input": input,
                    "error": e.to_string()
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({ "results": results }))
                .unwrap_or_else(|_| format!("{:?}", results)),
        )]))
    }

    #[tool(description = "List local types")]
    async fn list_local_types(
        &self,
        Parameters(req): Parameters<LocalTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_local_types",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let offset = req.offset.unwrap_or(0);
        let limit = req.limit.unwrap_or(100);
        match self
            .worker
            .local_types(offset, limit, req.filter.clone(), req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get xrefs to a struct field")]
    async fn get_xrefs_to_struct_field(
        &self,
        Parameters(req): Parameters<XrefsToFieldRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_xrefs_to_struct_field",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let limit = req.limit.unwrap_or(1000).min(10000);
        match self
            .worker
            .xrefs_to_field(
                req.ordinal,
                req.name.clone(),
                req.member_index,
                req.member_name.clone(),
                limit,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Set comments at an address")]
    async fn set_comment(
        &self,
        Parameters(req): Parameters<SetCommentsRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "set_comment",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let repeatable = req.repeatable.unwrap_or(false);
        let offset = req.offset.unwrap_or(0);
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .set_comments(
                addr,
                req.target_name.clone(),
                offset,
                req.comment.clone(),
                repeatable,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Set a function-level comment (visible at function entry)")]
    async fn set_function_comment(
        &self,
        Parameters(req): Parameters<SetFunctionCommentRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "set_function_comment",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let addr = req
            .address
            .as_ref()
            .and_then(crate::rpc_dispatch::parse_address_value);
        let repeatable = req.repeatable.unwrap_or(false);
        match self
            .worker
            .set_function_comment(addr, req.name.clone(), req.comment.clone(), repeatable)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Patch instructions with assembly text")]
    async fn patch_assembly(
        &self,
        Parameters(req): Parameters<PatchAsmRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "patch_assembly",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let offset = req.offset.unwrap_or(0);
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .patch_asm(addr, req.target_name.clone(), offset, req.line.clone())
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Declare a type in the local type library")]
    async fn declare_c_type(
        &self,
        Parameters(req): Parameters<DeclareTypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "declare_c_type",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let relaxed = req.relaxed.unwrap_or(false);
        let replace = req.replace.unwrap_or(false);
        let multi = req.multi.unwrap_or(false);
        match self
            .worker
            .declare_type(req.decl.clone(), relaxed, replace, multi)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get stack frame info")]
    async fn get_stack_frame(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_stack_frame",
                    json!({"address": req.address}),
                )
                .await;
        }
        let addr = match Self::value_to_single_address(&req.address) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.stack_frame(addr).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Declare a stack variable in a function frame")]
    async fn create_stack_variable(
        &self,
        Parameters(req): Parameters<DeclareStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "create_stack_variable",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let relaxed = req.relaxed.unwrap_or(false);
        match self
            .worker
            .declare_stack(
                addr,
                req.target_name.clone(),
                req.offset,
                req.var_name.clone(),
                req.decl.clone(),
                relaxed,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Delete a stack variable from a function frame")]
    async fn delete_stack_variable(
        &self,
        Parameters(req): Parameters<DeleteStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "delete_stack_variable",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .delete_stack(
                addr,
                req.target_name.clone(),
                req.offset,
                req.var_name.clone(),
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Rename a stack frame variable in a function")]
    async fn rename_stack_variable(
        &self,
        Parameters(req): Parameters<RenameStackVariableRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "rename_stack_variable",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }

        let func_addr = req
            .func_address
            .as_ref()
            .and_then(crate::rpc_dispatch::parse_address_value);
        match self
            .worker
            .rename_stack_variable(func_addr, req.func_name, req.name, req.new_name)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{result:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Set the type of a stack frame variable")]
    async fn set_stack_variable_type(
        &self,
        Parameters(req): Parameters<SetStackVariableTypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "set_stack_variable_type",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }

        let func_addr = req
            .func_address
            .as_ref()
            .and_then(crate::rpc_dispatch::parse_address_value);
        match self
            .worker
            .set_stack_variable_type(func_addr, req.func_name, req.name, req.type_decl)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{result:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List all enum types in the database")]
    async fn list_enums(
        &self,
        Parameters(req): Parameters<ListEnumsRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_enums",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }

        let offset = req.offset.unwrap_or(0);
        let limit = req.limit.unwrap_or(100);
        match self.worker.list_enums(req.filter, offset, limit).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{result:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Create an enum type from a C declaration")]
    async fn create_enum(
        &self,
        Parameters(req): Parameters<CreateEnumRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "create_enum",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }

        let replace = req.replace.unwrap_or(false);
        match self.worker.create_enum(req.decl, replace).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{result:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "List structs in the database with pagination and optional filter. \
        For large databases, consider setting timeout_secs (default: 120, max: 600)."
    )]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn list_structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_structs");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_structs",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self
            .worker
            .structs(offset, limit, req.filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get info about a struct by ordinal or name")]
    #[instrument(skip(self), fields(ordinal = req.ordinal, name = ?req.name))]
    async fn get_struct_info(
        &self,
        Parameters(req): Parameters<StructInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_struct_info");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "get_struct_info",
                    json!({"ordinal": req.ordinal, "name": req.name}),
                )
                .await;
        }
        match self.worker.struct_info(req.ordinal, req.name).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Read values of a struct instance at an address")]
    #[instrument(skip(self), fields(address = %req.address, ordinal = req.ordinal, name = ?req.name))]
    async fn read_struct_at_address(
        &self,
        Parameters(req): Parameters<ReadStructRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_struct_at_address");
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "read_struct_at_address",
                    json!({"address": req.address, "ordinal": req.ordinal, "name": req.name}),
                )
                .await;
        }
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self
                .worker
                .read_struct(addrs[0], req.ordinal, req.name)
                .await
            {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self
                    .worker
                    .read_struct(addr, req.ordinal, req.name.clone())
                    .await
                {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "struct": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Search structs by name")]
    async fn search_structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "list_structs",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let offset = req.offset.unwrap_or(0);
        let limit = req.limit.unwrap_or(100);
        match self
            .worker
            .structs(offset, limit, req.filter.clone(), req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find instruction sequences by mnemonic")]
    async fn search_instructions(
        &self,
        Parameters(req): Parameters<FindInsnsRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "search_instructions",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        if patterns.is_empty() {
            return Ok(ToolError::InvalidParams("empty patterns".to_string()).to_tool_result());
        }
        let max_results = req.limit.unwrap_or(100);
        let case_insensitive = req.case_insensitive.unwrap_or(false);
        match self
            .worker
            .find_insns(patterns, max_results, case_insensitive, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find instruction operands")]
    async fn search_instruction_operands(
        &self,
        Parameters(req): Parameters<FindInsnOperandsRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "search_instruction_operands",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        if patterns.is_empty() {
            return Ok(ToolError::InvalidParams("empty patterns".to_string()).to_tool_result());
        }
        let max_results = req.limit.unwrap_or(100);
        let case_insensitive = req.case_insensitive.unwrap_or(false);
        match self
            .worker
            .find_insn_operands(patterns, max_results, case_insensitive, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Apply a type to an address")]
    async fn apply_type(
        &self,
        Parameters(req): Parameters<ApplyTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "apply_type",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let relaxed = req.relaxed.unwrap_or(false);
        let delay = req.delay.unwrap_or(false);
        let strict = req.strict.unwrap_or(false);
        match self
            .worker
            .apply_types(
                addr,
                req.target_name.clone(),
                offset,
                req.stack_offset,
                req.stack_name.clone(),
                req.decl.clone(),
                req.type_name.clone(),
                relaxed,
                delay,
                strict,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Apply a C prototype declaration to a function")]
    async fn set_function_prototype(
        &self,
        Parameters(req): Parameters<SetFunctionPrototypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "set_function_prototype",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let addr = req
            .address
            .as_ref()
            .and_then(crate::rpc_dispatch::parse_address_value);
        match self
            .worker
            .set_function_prototype(addr, req.name.clone(), req.prototype.clone())
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Infer/guess type at an address")]
    async fn infer_type(
        &self,
        Parameters(req): Parameters<InferTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "infer_type",
                    json!({"addr": req.address, "name": req.target_name, "offset": req.offset}),
                )
                .await;
        }
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .infer_types(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Analyze functions (not supported)")]
    async fn analyze_funcs(
        &self,
        Parameters(req): Parameters<AnalyzeFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "run_auto_analysis",
                    json!({"timeout_secs": req.timeout_secs}),
                )
                .await;
        }
        match self.worker.analyze_funcs(req.timeout_secs).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Rename symbols")]
    async fn rename_symbol(
        &self,
        Parameters(req): Parameters<RenameRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "rename_symbol",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let flags = req.flags.unwrap_or(0);
        match self
            .worker
            .rename(addr, req.current_name.clone(), req.name.clone(), flags)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Rename multiple symbols at once")]
    async fn batch_rename(
        &self,
        Parameters(req): Parameters<BatchRenameRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "batch_rename",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }

        let entries: Vec<(Option<u64>, Option<String>, String)> = req
            .renames
            .iter()
            .map(|e| {
                let addr = e
                    .address
                    .as_ref()
                    .and_then(crate::rpc_dispatch::parse_address_value);
                (addr, e.current_name.clone(), e.new_name.clone())
            })
            .collect();

        match self.worker.batch_rename(entries).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Rename a local variable in decompiled pseudocode")]
    async fn rename_local_variable(
        &self,
        Parameters(req): Parameters<RenameLvarRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "rename_local_variable",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let func_addr = match Self::value_to_single_address(&req.func_address) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self
            .worker
            .rename_lvar(func_addr, req.lvar_name.clone(), req.new_name.clone())
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Set the type of a local variable in decompiled pseudocode")]
    async fn set_local_variable_type(
        &self,
        Parameters(req): Parameters<SetLvarTypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "set_local_variable_type",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let func_addr = match Self::value_to_single_address(&req.func_address) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self
            .worker
            .set_lvar_type(func_addr, req.lvar_name.clone(), req.type_str.clone())
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Set a comment in decompiled pseudocode")]
    async fn set_decompiler_comment(
        &self,
        Parameters(req): Parameters<SetDecompilerCommentRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "set_decompiler_comment",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let func_addr = match Self::value_to_single_address(&req.func_address) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let addr = match Self::value_to_single_address(&req.address) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let itp = req.itp.unwrap_or(69);
        match self
            .worker
            .set_decompiler_comment(func_addr, addr, itp, req.comment.clone())
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Patch bytes at an address")]
    async fn patch_bytes(
        &self,
        Parameters(req): Parameters<PatchRequest>,
    ) -> Result<CallToolResult, McpError> {
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "patch_bytes",
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
        }
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let bytes = match Self::value_to_bytes(&req.bytes) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self
            .worker
            .patch_bytes(addr, req.target_name.clone(), offset, bytes)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Open a dyld_shared_cache file and load a single module (dylib) for analysis. \
        If the .i64 database already exists, opens it immediately and returns db_info. \
        If the .i64 must be created (first time), spawns idat in the background and returns \
        a task_id immediately. Poll task_status(task_id) to check progress — when completed, \
        the database is already open and ready for analysis tools. \
        Use this instead of open_idb when working with Apple's dyld_shared_cache files. \
        The module parameter specifies which dylib to extract (e.g. '/usr/lib/libobjc.A.dylib'). \
        Additional frameworks can be loaded to resolve cross-module references."
    )]
    #[instrument(skip(self), fields(path = %req.path, arch = %req.arch, module = %req.module))]
    async fn open_dsc(
        &self,
        Parameters(req): Parameters<OpenDscRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: open_dsc");

        if !Self::validate_path(&req.path) {
            return Ok(ToolError::InvalidPath(req.path).to_tool_result());
        }

        let ida_version = req.ida_version.unwrap_or(9);
        if ida_version != 8 && ida_version != 9 {
            return Ok(
                ToolError::InvalidParams("ida_version must be 8 or 9".into()).to_tool_result(),
            );
        }

        let file_type = crate::dsc::dsc_file_type(&req.arch, ida_version);
        let frameworks = req.frameworks.unwrap_or_default();
        let dsc_path = std::path::Path::new(&req.path);
        let out_i64 = dsc_path.with_extension("i64");

        // If .i64 already exists, open synchronously (fast path).
        if out_i64.exists() {
            return self.open_dsc_i64(&out_i64, &req.module, &frameworks).await;
        }

        // .i64 doesn't exist — need to run idat, which takes minutes.
        // Validate idat exists and write the load script before spawning.
        let idat = match crate::dsc::find_idat() {
            Ok(path) => path,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let script = crate::dsc::dsc_load_script(&req.module, &frameworks);
        let script_dir = dsc_path.parent().unwrap_or(std::path::Path::new("/tmp"));
        let script_path = script_dir.join("ida_mcp_dsc_load.py");
        if let Err(e) = std::fs::write(&script_path, &script) {
            return Ok(
                ToolError::InvalidParams(format!("Failed to write DSC load script: {e}"))
                    .to_tool_result(),
            );
        }

        let log_path = req.log_path.map(std::path::PathBuf::from);
        if let Some(ref lp) = log_path {
            if lp.to_string_lossy().contains("..") {
                return Ok(ToolError::InvalidParams(
                    "log_path must not contain '..' path traversal".into(),
                )
                .to_tool_result());
            }
        }
        let idat_args = crate::dsc::idat_dsc_args(
            dsc_path,
            &out_i64,
            &script_path,
            &file_type,
            log_path.as_deref(),
        );

        // Create a background task and return immediately.
        // Use the .i64 path as dedup key to prevent concurrent idat
        // processes writing the same output file.
        let dedup_key = out_i64.display().to_string();
        let task_id = match self
            .task_registry
            .create_keyed(&dedup_key, "Running idat to create .i64 from DSC...")
        {
            Ok(id) => id,
            Err(existing_id) => {
                return Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({
                        "status": "already_running",
                        "task_id": existing_id,
                        "message": "A DSC loading task for this path is already in progress. Poll task_status(task_id) for progress.",
                    }))
                    .unwrap_or_default(),
                )]));
            }
        };

        info!(
            task_id = %task_id,
            idat = %idat.display(),
            module = %req.module,
            "Spawning background idat for DSC loading"
        );

        let registry = self.task_registry.clone();
        let worker = Arc::clone(&self.worker);
        let mode = self.mode.clone();
        let module = req.module.clone();
        let tid = task_id.clone();

        let ctx = DscBackgroundCtx {
            idat,
            idat_args,
            script_path,
            log_path,
            out_i64,
            module,
            frameworks,
        };

        let handle = tokio::spawn(async move {
            Self::run_dsc_background(tid, registry, worker, mode, ctx).await;
        });
        self.task_registry.set_handle(&task_id, handle);

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "status": "started",
                "task_id": task_id,
                "message": "DSC loading started in background. Poll task_status(task_id) for progress.",
            }))
            .unwrap_or_default(),
        )]))
    }

    #[tool(
        description = "Load an additional dylib into an already-open DSC database. \
        Requires a database previously opened via open_dsc. \
        Uses the dscu plugin to incrementally add one module at a time. \
        Runs ObjC type analysis on the newly loaded module but skips \
        full auto-analysis to keep the operation fast. \
        Example: after open_dsc loaded libobjc, use this to add Foundation. \
        If auto-analysis is not ready afterward, call analyze_funcs before relying on xrefs/decompile."
    )]
    #[instrument(skip(self), fields(module = %req.module))]
    async fn dsc_add_dylib(
        &self,
        Parameters(req): Parameters<DscAddDylibRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dsc_add_dylib");
        let module = req.module.trim().to_string();
        if module.is_empty() {
            return Ok(ToolError::InvalidParams("module must not be empty".into()).to_tool_result());
        }
        if !module.starts_with('/') {
            return Ok(ToolError::InvalidParams(
                "module must be an absolute path (start with '/')".into(),
            )
            .to_tool_result());
        }
        if module.contains("..") {
            return Ok(ToolError::InvalidParams(
                "module must not contain '..' path traversal".into(),
            )
            .to_tool_result());
        }

        let timeout = Some(req.timeout_secs.unwrap_or(300).min(600));
        let script = crate::dsc::dsc_add_dylib_script(&module);

        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "run_script",
                    json!({"code": script, "timeout_secs": timeout}),
                )
                .await;
        }

        match self.worker.run_script(&script, timeout).await {
            Ok(result) => {
                if !run_script_succeeded(&result) {
                    let message = run_script_failure_message(&result);
                    warn!(module = %module, error = %message, "dsc_add_dylib failed");
                    return Ok(ToolError::IdaError(message).to_tool_result());
                }
                let stdout = run_script_field(&result, "stdout").unwrap_or_default();
                let analysis_status = match self.worker.analysis_status().await {
                    Ok(status) => Some(status),
                    Err(err) => {
                        warn!(module = %module, error = %err, "failed to fetch analysis_status after dsc_add_dylib");
                        None
                    }
                };
                let analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
                let next_steps = dsc_analysis_next_steps(
                    analysis_ready,
                    "Proceed with xrefs/decompile/list_functions for the newly loaded module.",
                );
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "module": module,
                        "message": format!(
                            "Successfully loaded {module} into the database. \
                             Lightweight ObjC analysis ran; full auto-analysis was not forced."
                        ),
                        "stdout": stdout,
                        "analysis_status": analysis_status,
                        "analysis_ready": analysis_ready,
                        "next_steps": next_steps,
                    }))
                    .unwrap_or_default(),
                )]))
            }
            Err(ToolError::Timeout(secs)) => {
                let message = run_script_timeout_message(secs, &script);
                warn!(module = %module, timeout_secs = secs, "dsc_add_dylib timed out");
                Ok(ToolError::IdaError(message).to_tool_result())
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Load an additional DSC memory region by address into an already-open \
        DSC database. Uses dscu region mode to load data/GOT/stub areas on-demand. \
        Accepts exactly one address per call. \
        Requires a database previously opened via open_dsc. \
        This does not force full auto-analysis; after loading, call analysis_status \
        and run analyze_funcs if auto_is_ok=false before relying on xrefs/decompile."
    )]
    #[instrument(skip(self), fields(address = ?req.address))]
    async fn dsc_add_region(
        &self,
        Parameters(req): Parameters<DscAddRegionRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dsc_add_region");

        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(v) => v,
            Err(ToolError::InvalidAddress(addr)) => {
                return Ok(
                    ToolError::InvalidParams(format!("Invalid address: {addr}")).to_tool_result()
                )
            }
            Err(e) => return Ok(e.to_tool_result()),
        };
        if addrs.len() != 1 {
            return Ok(
                ToolError::InvalidParams("address must contain exactly one value".into())
                    .to_tool_result(),
            );
        }
        let ea = addrs[0];
        let ea_hex = format!("0x{ea:x}");
        let timeout = Some(req.timeout_secs.unwrap_or(300).min(600));
        let script = crate::dsc::dsc_add_region_script(ea);

        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "run_script",
                    json!({"code": script, "timeout_secs": timeout}),
                )
                .await;
        }

        match self.worker.run_script(&script, timeout).await {
            Ok(result) => {
                if !run_script_succeeded(&result) {
                    let message = run_script_failure_message(&result);
                    warn!(
                        address = %ea_hex,
                        error = %message,
                        "dsc_add_region failed"
                    );
                    return Ok(ToolError::IdaError(message).to_tool_result());
                }
                let stdout = run_script_field(&result, "stdout").unwrap_or_default();
                let analysis_status = match self.worker.analysis_status().await {
                    Ok(status) => Some(status),
                    Err(err) => {
                        warn!(
                            address = %ea_hex,
                            error = %err,
                            "failed to fetch analysis_status after dsc_add_region"
                        );
                        None
                    }
                };
                let analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
                let next_steps = dsc_analysis_next_steps(
                    analysis_ready,
                    "Proceed with xrefs/decompile/list_functions for symbols near this region.",
                );
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "address": ea_hex,
                        "address_value": ea,
                        "message": format!(
                            "Successfully loaded DSC region at 0x{ea:x}. \
                             Full auto-analysis was not forced."
                        ),
                        "stdout": stdout,
                        "analysis_status": analysis_status,
                        "analysis_ready": analysis_ready,
                        "next_steps": next_steps,
                    }))
                    .unwrap_or_default(),
                )]))
            }
            Err(ToolError::Timeout(secs)) => {
                let message = run_script_timeout_message(secs, &script);
                warn!(
                    address = %ea_hex,
                    timeout_secs = secs,
                    "dsc_add_region timed out"
                );
                Ok(ToolError::IdaError(message).to_tool_result())
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Check the status of a background task (e.g. DSC loading). \
        Returns the current status: 'running' (with a progress message), \
        'completed' (with the result — database is already open), \
        'failed' (with an error message), or 'cancelled'. \
        Use the task_id returned by open_dsc."
    )]
    #[instrument(skip(self), fields(task_id = %req.task_id))]
    async fn task_status(
        &self,
        Parameters(req): Parameters<TaskStatusRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: task_status");

        let state = match self.task_registry.get(&req.task_id) {
            Some(s) => s,
            None => {
                return Ok(
                    ToolError::InvalidParams(format!("Unknown task_id: {}", req.task_id))
                        .to_tool_result(),
                );
            }
        };

        let elapsed = state.created_at.elapsed().as_secs();
        let status_str = match state.status {
            task::TaskStatus::Running => "running",
            task::TaskStatus::Completed => "completed",
            task::TaskStatus::Failed => "failed",
            task::TaskStatus::Cancelled => "cancelled",
        };

        let mut response = json!({
            "task_id": state.id,
            "status": status_str,
            "message": state.message,
            "elapsed_secs": elapsed,
        });

        if let Some(result) = &state.result {
            if let Value::Object(map) = &mut response {
                map.insert("result".to_string(), result.clone());
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap_or_default(),
        )]))
    }

    #[tool(
        description = "Execute a Python script via IDAPython in the open database. \
        Has full access to all ida_* modules, idc, idautils. \
        stdout and stderr are captured and returned. \
        Provide either 'code' (inline Python) or 'file' (path to a .py file), not both. \
        Use this for custom analysis that goes beyond the built-in tools. \
        API reference: https://python.docs.hex-rays.com"
    )]
    #[instrument(skip(self))]
    async fn run_script(
        &self,
        Parameters(req): Parameters<RunScriptRequest>,
    ) -> Result<CallToolResult, McpError> {
        let code = match (req.code, req.file) {
            (Some(code), None) => code,
            (None, Some(path)) => {
                if !Self::validate_path(&path) {
                    return Ok(ToolError::InvalidPath(path).to_tool_result());
                }
                match std::fs::read_to_string(&path) {
                    Ok(contents) => contents,
                    Err(e) => {
                        return Ok(ToolError::InvalidPath(format!(
                            "Failed to read script file '{}': {}",
                            path, e
                        ))
                        .to_tool_result());
                    }
                }
            }
            (Some(_), Some(_)) => {
                return Ok(ToolError::InvalidParams(
                    "Provide either 'code' or 'file', not both".into(),
                )
                .to_tool_result());
            }
            (None, None) => {
                return Ok(ToolError::InvalidParams(
                    "Provide either 'code' (inline Python) or 'file' (path to .py)".into(),
                )
                .to_tool_result());
            }
        };
        let timeout = req.timeout_secs.map(|t| t.min(600));
        if let ServerMode::Router(ref router) = self.mode {
            return self
                .route_or_err(
                    router,
                    req.db_handle.as_deref(),
                    "run_script",
                    json!({"code": code, "timeout_secs": timeout}),
                )
                .await;
        }
        match self.worker.run_script(&code, timeout).await {
            Ok(result) => {
                if !run_script_succeeded(&result) {
                    let message = run_script_failure_message(&result);
                    warn!(code_len = code.len(), error = %message, "run_script failed");
                    return Ok(ToolError::IdaError(message).to_tool_result());
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )]))
            }
            Err(ToolError::Timeout(timeout_secs)) => {
                let message = run_script_timeout_message(timeout_secs, &code);
                warn!(timeout_secs, code_len = code.len(), "run_script timed out");
                Ok(ToolError::IdaError(message).to_tool_result())
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }
}

const RUN_SCRIPT_PREVIEW_CHARS: usize = 220;
const RUN_SCRIPT_TAIL_LINES: usize = 12;
const RUN_SCRIPT_TAIL_CHARS: usize = 1600;

fn run_script_succeeded(result: &Value) -> bool {
    result.get("success").and_then(Value::as_bool) == Some(true)
}

fn run_script_field<'a>(result: &'a Value, field: &str) -> Option<&'a str> {
    result.get(field).and_then(Value::as_str)
}

fn run_script_last_non_empty_line(text: &str) -> Option<&str> {
    text.lines().rev().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn run_script_truncate_chars(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, ch) in input.chars().enumerate() {
        if count >= max_chars {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

fn run_script_tail_lines(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

fn run_script_error_hint(error_details: &str) -> Option<&'static str> {
    let lowered = error_details.to_ascii_lowercase();
    if lowered.contains("syntaxerror") || lowered.contains("invalid syntax") {
        return Some("Python syntax error detected. Regenerate valid Python and retry.");
    }
    if lowered.contains("nameerror") {
        return Some("NameError detected. Check variable/module names before rerunning.");
    }
    if lowered.contains("attributeerror") {
        return Some("AttributeError detected. Verify IDA API object names/methods.");
    }
    if lowered.contains("importerror") || lowered.contains("modulenotfounderror") {
        return Some("Import failure detected. Ensure the required module exists in IDAPython.");
    }
    if lowered.contains("failed to execute wrapper") {
        return Some(
            "IDAPython wrapper execution failed before user code completed. Check stderr for details.",
        );
    }
    None
}

fn run_script_failure_message(result: &Value) -> String {
    let stderr = run_script_field(result, "stderr").unwrap_or_default();
    let stdout = run_script_field(result, "stdout").unwrap_or_default();
    let summary = run_script_field(result, "error_summary")
        .or_else(|| run_script_field(result, "error"))
        .or_else(|| run_script_last_non_empty_line(stderr))
        .unwrap_or("Unknown IDAPython script failure (no error details captured)");

    let stderr_tail = run_script_truncate_chars(
        &run_script_tail_lines(stderr, RUN_SCRIPT_TAIL_LINES),
        RUN_SCRIPT_TAIL_CHARS,
    );
    let stdout_tail = run_script_truncate_chars(
        &run_script_tail_lines(stdout, RUN_SCRIPT_TAIL_LINES),
        RUN_SCRIPT_TAIL_CHARS,
    );

    let mut parts = vec![format!("IDAPython script execution failed: {summary}")];
    if let Some(kind) = run_script_field(result, "error_kind") {
        parts.push(format!("Error kind: {kind}"));
    }
    if !stderr_tail.is_empty() {
        parts.push(format!("stderr (tail):\n{stderr_tail}"));
    }
    if !stdout_tail.is_empty() {
        parts.push(format!("stdout (tail):\n{stdout_tail}"));
    }
    let combined_details = format!("{summary}\n{stderr_tail}");
    if let Some(hint) = run_script_error_hint(&combined_details) {
        parts.push(format!("Hint: {hint}"));
    }
    parts.join("\n\n")
}

fn run_script_timeout_message(timeout_secs: u64, code: &str) -> String {
    let compact_preview = code
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let preview = if compact_preview.is_empty() {
        "<empty script>".to_string()
    } else {
        run_script_truncate_chars(&compact_preview, RUN_SCRIPT_PREVIEW_CHARS)
    };
    format!(
        "run_script timed out after {timeout_secs} seconds.\n\
         The script may be blocked in a long-running loop or waiting on IDA state.\n\
         Script preview: {preview}\n\
         Hint: while iterating with LLM-generated code, use a smaller timeout_secs and avoid scripts that block indefinitely."
    )
}

fn dsc_analysis_next_steps(
    analysis_ready: Option<bool>,
    ready_message: &'static str,
) -> Vec<String> {
    if analysis_ready == Some(true) {
        vec![ready_message.to_string()]
    } else {
        vec![
            "Call analysis_status to check auto-analysis progress.".to_string(),
            "If auto_is_ok is false, run analyze_funcs and wait for completion before xrefs/decompile."
                .to_string(),
        ]
    }
}

async fn get_int_values(
    worker: &IdaWorker,
    address: Value,
    size: usize,
) -> Result<CallToolResult, McpError> {
    let addrs = match IdaMcpServer::value_to_addresses(&address) {
        Ok(v) => v,
        Err(e) => return Ok(e.to_tool_result()),
    };

    if addrs.len() == 1 {
        match worker.read_int(addrs[0], size).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    } else {
        let mut results = Vec::new();
        for addr in addrs {
            match worker.read_int(addr, size).await {
                Ok(result) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "value": result
                })),
                Err(e) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "error": e.to_string()
                })),
            }
        }
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({ "results": results }))
                .unwrap_or_else(|_| format!("{:?}", results)),
        )]))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn trim_bytes_le(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    while out.len() > 1 && out.last() == Some(&0) {
        out.pop();
    }
    out
}

fn trim_bytes_be(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0usize;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    bytes[start..].to_vec()
}

fn bytes_to_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            let c = *b as char;
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '.'
            }
        })
        .collect()
}

fn tool_params_schema(name: &str) -> Option<Value> {
    let name = crate::tool_registry::primary_name_for(name);

    fn schema<T: JsonSchema>() -> Value {
        serde_json::to_value(schema_for!(T)).unwrap_or_else(|_| json!({}))
    }

    match name {
        // Core
        "open_idb" => Some(schema::<OpenIdbRequest>()),
        "open_dsc" => Some(schema::<OpenDscRequest>()),
        "open_sbpf" => Some(schema::<OpenSbpfRequest>()),
        "dsc_add_dylib" => Some(schema::<DscAddDylibRequest>()),
        "dsc_add_region" => Some(schema::<DscAddRegionRequest>()),
        "close_idb" => Some(schema::<CloseIdbRequest>()),
        "load_debug_info" => Some(schema::<LoadDebugInfoRequest>()),
        "get_analysis_status" => Some(schema::<EmptyParams>()),
        "tool_catalog" => Some(schema::<ToolCatalogRequest>()),
        "tool_help" => Some(schema::<ToolHelpRequest>()),
        "get_database_info" => Some(schema::<EmptyParams>()),

        // Functions
        "list_functions" => Some(schema::<ListFunctionsRequest>()),
        "get_function_by_name" => Some(schema::<ResolveFunctionRequest>()),
        "get_address_info" => Some(schema::<AddrInfoRequest>()),
        "get_function_at_address" => Some(schema::<FunctionAtRequest>()),
        "batch_lookup_functions" => Some(schema::<LookupFuncsRequest>()),
        "run_auto_analysis" => Some(schema::<AnalyzeFuncsRequest>()),

        // Disassembly / Decompile
        "disassemble" => Some(schema::<DisasmRequest>()),
        "disassemble_function" => Some(schema::<DisasmByNameRequest>()),
        "disassemble_function_at" => Some(schema::<DisasmFunctionAtRequest>()),
        "decompile_function" => Some(schema::<DecompileRequest>()),
        "get_pseudocode_at" => Some(schema::<PseudocodeAtRequest>()),
        "decompile_structured" => Some(schema::<DecompileStructuredRequest>()),
        "batch_decompile" => Some(schema::<BatchDecompileRequest>()),
        "search_pseudocode" => Some(schema::<SearchPseudocodeRequest>()),
        "scan_memory_table" => Some(schema::<TableScanRequest>()),
        "diff_pseudocode" => Some(schema::<DiffFunctionsRequest>()),

        // Xrefs / Control flow
        "get_xrefs_to" | "get_xrefs_from" => Some(schema::<AddressRequest>()),
        "build_xref_matrix" => Some(schema::<XrefMatrixRequest>()),
        "get_basic_blocks" | "get_callers" | "get_callees" => Some(schema::<AddressRequest>()),
        "find_control_flow_paths" => Some(schema::<FindPathsRequest>()),
        "build_callgraph" => Some(schema::<CallGraphRequest>()),

        // Memory / Search / Metadata
        "read_bytes" => Some(schema::<GetBytesRequest>()),
        "read_string" => Some(schema::<GetStringRequest>()),
        "read_byte" | "read_word" | "read_dword" | "read_qword" => Some(schema::<AddressRequest>()),
        "read_global_variable" => Some(schema::<GetGlobalValueRequest>()),
        "list_strings" => Some(schema::<ListStringsRequest>()),
        "get_xrefs_to_string" => Some(schema::<XrefsToStringRequest>()),
        "search_bytes" => Some(schema::<FindBytesRequest>()),
        "search_text" => Some(schema::<SearchRequest>()),
        "search_instructions" => Some(schema::<FindInsnsRequest>()),
        "search_instruction_operands" => Some(schema::<FindInsnOperandsRequest>()),
        "list_segments" => Some(schema::<EmptyParams>()),
        "list_imports" | "list_exports" => Some(schema::<PaginatedRequest>()),
        "export_functions" => Some(schema::<ExportFuncsRequest>()),
        "list_entry_points" => Some(schema::<EmptyParams>()),
        "list_globals" => Some(schema::<ListGlobalsRequest>()),
        "convert_number" => Some(schema::<IntConvertRequest>()),

        // Editing
        "set_comment" => Some(schema::<SetCommentsRequest>()),
        "rename_symbol" => Some(schema::<RenameRequest>()),
        "rename_local_variable" => Some(schema::<RenameLvarRequest>()),
        "set_local_variable_type" => Some(schema::<SetLvarTypeRequest>()),
        "patch_bytes" => Some(schema::<PatchRequest>()),
        "patch_assembly" => Some(schema::<PatchAsmRequest>()),
        "set_function_prototype" => Some(schema::<SetFunctionPrototypeRequest>()),
        "set_function_comment" => Some(schema::<SetFunctionCommentRequest>()),
        "batch_rename" => Some(schema::<BatchRenameRequest>()),

        // Types
        "list_structs" => Some(schema::<StructsRequest>()),
        "get_struct_info" => Some(schema::<StructInfoRequest>()),
        "read_struct_at_address" => Some(schema::<ReadStructRequest>()),
        "search_structs" => Some(schema::<StructsRequest>()),
        "list_local_types" => Some(schema::<LocalTypesRequest>()),
        "get_xrefs_to_struct_field" => Some(schema::<XrefsToFieldRequest>()),
        "get_stack_frame" => Some(schema::<AddressRequest>()),
        "declare_c_type" => Some(schema::<DeclareTypeRequest>()),
        "apply_type" => Some(schema::<ApplyTypesRequest>()),
        "infer_type" => Some(schema::<InferTypesRequest>()),
        "create_stack_variable" => Some(schema::<DeclareStackRequest>()),
        "delete_stack_variable" => Some(schema::<DeleteStackRequest>()),
        "get_function_prototype" => Some(schema::<GetFunctionPrototypeRequest>()),
        "rename_stack_variable" => Some(schema::<RenameStackVariableRequest>()),
        "set_stack_variable_type" => Some(schema::<SetStackVariableTypeRequest>()),
        "list_enums" => Some(schema::<ListEnumsRequest>()),
        "create_enum" => Some(schema::<CreateEnumRequest>()),

        // Scripting
        "run_script" => Some(schema::<RunScriptRequest>()),

        _ => None,
    }
}

use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};

/// Convert our internal `TaskState` to the rmcp `Task` model.
fn task_state_to_mcp(state: &task::TaskState) -> rmcp::model::Task {
    let status = match state.status {
        task::TaskStatus::Running => rmcp::model::TaskStatus::Working,
        task::TaskStatus::Completed => rmcp::model::TaskStatus::Completed,
        task::TaskStatus::Failed => rmcp::model::TaskStatus::Failed,
        task::TaskStatus::Cancelled => rmcp::model::TaskStatus::Cancelled,
    };
    rmcp::model::Task {
        task_id: state.id.clone(),
        status,
        status_message: Some(state.message.clone()),
        created_at: state.created_at_iso.clone(),
        last_updated_at: Some(state.updated_at_iso.clone()),
        ttl: Some(task::TASK_RETENTION_TTL_MS),
        poll_interval: Some(5000),
    }
}

fn call_tool_result_to_value(result: &CallToolResult) -> Value {
    serde_json::to_value(result).unwrap_or_else(|_| {
        json!({
            "content": [{
                "type": "text",
                "text": "Failed to serialize CallToolResult"
            }],
            "isError": true
        })
    })
}

fn looks_like_call_tool_result(value: &Value) -> bool {
    serde_json::from_value::<CallToolResult>(value.clone()).is_ok()
}

fn wrap_as_call_tool_result(value: &Value) -> Value {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| format!("{value:?}"));
    call_tool_result_to_value(&CallToolResult::success(vec![Content::text(text)]))
}

fn task_payload_result_value(result: Option<Value>) -> Value {
    match result {
        Some(value) if looks_like_call_tool_result(&value) => value,
        Some(value) => wrap_as_call_tool_result(&value),
        None => wrap_as_call_tool_result(&Value::Null),
    }
}

#[tool_handler(router = self.tool_mux)]
impl ServerHandler for IdaMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_tasks_with(rmcp::model::TasksCapability::server_default())
                .build(),
            instructions: Some(self.instructions()),
            ..Default::default()
        }
    }

    async fn enqueue_task(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CreateTaskResult, McpError> {
        // Delegate to the regular tool handler and wrap the result
        // into the task protocol.  For most tools the call completes
        // inline.  For `open_dsc`, the tool creates a background
        // task and returns a task_id — we re-use that ID.
        let result = self.call_tool(request, context).await?;

        // Check if the result contains a task_id from open_dsc.
        let task_id = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .and_then(|t| serde_json::from_str::<Value>(&t.text).ok())
            .and_then(|v| v.get("task_id")?.as_str().map(String::from));

        if let Some(tid) = task_id {
            let state = self
                .task_registry
                .get(&tid)
                .ok_or_else(|| McpError::internal_error(format!("Task {tid} disappeared"), None))?;
            Ok(CreateTaskResult {
                task: task_state_to_mcp(&state),
            })
        } else {
            // Inline completion — no background work, but still register a completed
            // task so tasks/get and tasks/result remain resolvable for this task_id.
            let payload = call_tool_result_to_value(&result);
            let id = self.task_registry.create_completed("Completed", payload);
            let state = self
                .task_registry
                .get(&id)
                .ok_or_else(|| McpError::internal_error(format!("Task {id} disappeared"), None))?;
            Ok(CreateTaskResult {
                task: task_state_to_mcp(&state),
            })
        }
    }

    async fn list_tasks(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListTasksResult, McpError> {
        let tasks: Vec<rmcp::model::Task> = self
            .task_registry
            .list_all()
            .iter()
            .map(task_state_to_mcp)
            .collect();
        Ok(ListTasksResult {
            tasks,
            next_cursor: None,
            total: None,
        })
    }

    async fn get_task_info(
        &self,
        request: GetTaskInfoParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetTaskInfoResult, McpError> {
        let state = self.task_registry.get(&request.task_id).ok_or_else(|| {
            McpError::invalid_params(
                "Unknown task_id",
                Some(json!({ "task_id": request.task_id })),
            )
        })?;
        Ok(GetTaskInfoResult {
            task: Some(task_state_to_mcp(&state)),
        })
    }

    async fn get_task_result(
        &self,
        request: GetTaskResultParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<TaskResult, McpError> {
        let state = self.task_registry.get(&request.task_id);
        match state {
            Some(s) if s.status == task::TaskStatus::Completed => Ok(TaskResult {
                content_type: "application/json".to_string(),
                value: task_payload_result_value(s.result),
                summary: None,
            }),
            Some(s) if s.status == task::TaskStatus::Failed => {
                Err(McpError::internal_error(s.message, None))
            }
            Some(s) if s.status == task::TaskStatus::Cancelled => {
                Err(McpError::internal_error("Task was cancelled", None))
            }
            Some(_) => Err(McpError::internal_error(
                "Task is still running; poll tasks/get first",
                None,
            )),
            None => Err(McpError::invalid_params(
                "Unknown task_id",
                Some(json!({ "task_id": request.task_id })),
            )),
        }
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        if self.task_registry.cancel(&request.task_id) {
            Ok(())
        } else {
            Err(McpError::invalid_params(
                "Task not found or not running",
                Some(json!({ "task_id": request.task_id })),
            ))
        }
    }
}

/// Wrapper that sanitizes tool schemas by removing `$schema` fields.
///
/// Some MCP clients (like Claude Desktop) choke on the JSON Schema `$schema` field.
/// This wrapper intercepts `list_tools` to remove these fields while delegating
/// all other methods to the inner server.
pub struct SanitizedIdaServer<S>(pub S);

impl<S> std::ops::Deref for SanitizedIdaServer<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Tools that support task-based invocation (SEP-1686).
const TASK_CAPABLE_TOOLS: &[&str] = &["open_dsc"];

/// Strips `$schema` keys from tool input schemas and annotates
/// task-capable tools with `execution.taskSupport = "optional"`.
fn sanitize_tool_schemas(result: &mut ListToolsResult) {
    for tool in &mut result.tools {
        let schema_arc = &mut tool.input_schema;
        if let Some(map) = std::sync::Arc::get_mut(schema_arc) {
            map.remove("$schema");
        } else {
            let mut map = (**schema_arc).clone();
            map.remove("$schema");
            *schema_arc = std::sync::Arc::new(map);
        }

        if TASK_CAPABLE_TOOLS.contains(&&*tool.name) {
            tool.execution = Some(
                rmcp::model::ToolExecution::new()
                    .with_task_support(rmcp::model::TaskSupport::Optional),
            );
        }
    }
}

/// Patch a single tool definition with task support if applicable.
fn annotate_task_support(mut tool: Tool) -> Tool {
    if TASK_CAPABLE_TOOLS.contains(&&*tool.name) {
        tool.execution = Some(
            rmcp::model::ToolExecution::new().with_task_support(rmcp::model::TaskSupport::Optional),
        );
    }
    tool
}

impl<S: ServerHandler + Send + Sync> ServerHandler for SanitizedIdaServer<S> {
    async fn initialize(
        &self,
        params: InitializeRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        self.0.initialize(params, ctx).await
    }

    async fn list_tools(
        &self,
        params: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = self.0.list_tools(params, ctx).await?;
        sanitize_tool_schemas(&mut result);
        Ok(result)
    }

    async fn call_tool(
        &self,
        mut params: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // Log raw arguments BEFORE rmcp's Parameters<T> deserialization.
        // If a -32602 "missing field" error occurs, this entry shows exactly
        // what the client sent, enabling post-mortem diagnosis.
        debug!(
            tool = %params.name,
            arguments = %serde_json::to_string(&params.arguments)
                .unwrap_or_else(|_| "<unserializable>".to_string()),
            "call_tool raw"
        );

        // Resolve backward-compatible aliases before routing (e.g. "idb_meta" → "get_database_info").
        let primary = crate::tool_registry::primary_name_for(&params.name);
        if primary != params.name.as_ref() {
            params.name = primary.to_string().into();
        }

        // Guard against unknown tool names. rmcp's ToolRouter may hang
        // indefinitely when dispatching a tool name that was never registered
        // via #[tool]. Return a clear MCP error instead of blocking the server.
        if self.0.get_tool(&params.name).is_none() {
            warn!(tool = %params.name, "Unknown tool called — not registered in MCP tool router");
            return Ok(ToolError::InvalidToolName(format!(
                "Unknown tool: {}. Use tool_catalog() to discover available tools.",
                params.name
            ))
            .to_tool_result());
        }

        self.0.call_tool(params, ctx).await
    }

    fn get_info(&self) -> ServerInfo {
        self.0.get_info()
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.0.get_tool(name).map(annotate_task_support)
    }

    async fn enqueue_task(
        &self,
        request: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CreateTaskResult, McpError> {
        self.0.enqueue_task(request, ctx).await
    }

    async fn list_tasks(
        &self,
        request: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListTasksResult, McpError> {
        self.0.list_tasks(request, ctx).await
    }

    async fn get_task_info(
        &self,
        request: GetTaskInfoParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<GetTaskInfoResult, McpError> {
        self.0.get_task_info(request, ctx).await
    }

    async fn get_task_result(
        &self,
        request: GetTaskResultParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<TaskResult, McpError> {
        self.0.get_task_result(request, ctx).await
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.0.cancel_task(request, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        run_script_failure_message, run_script_succeeded, run_script_timeout_message,
        run_script_truncate_chars, task_payload_result_value,
    };
    use rmcp::model::CallToolResult;
    use serde_json::json;

    #[test]
    fn run_script_succeeded_only_for_explicit_true() {
        assert!(run_script_succeeded(&json!({ "success": true })));
        assert!(!run_script_succeeded(&json!({ "success": false })));
        assert!(!run_script_succeeded(&json!({})));
    }

    #[test]
    fn run_script_failure_message_adds_syntax_hint() {
        let value = json!({
            "success": false,
            "stdout": "",
            "stderr": "Traceback (most recent call last):\n  File \"<string>\", line 1\nSyntaxError: invalid syntax",
            "error": "invalid syntax"
        });
        let message = run_script_failure_message(&value);
        assert!(message.contains("IDAPython script execution failed"));
        assert!(message.contains("SyntaxError"));
        assert!(message.contains("Hint: Python syntax error detected"));
    }

    #[test]
    fn run_script_timeout_message_includes_preview() {
        let code = "import idaapi\nfor _ in range(1000000000):\n    pass\n";
        let message = run_script_timeout_message(120, code);
        assert!(message.contains("run_script timed out after 120 seconds"));
        assert!(message.contains("Script preview: import idaapi for _ in range(1000000000): pass"));
    }

    #[test]
    fn run_script_truncate_chars_appends_ellipsis() {
        let truncated = run_script_truncate_chars("abcdef", 3);
        assert_eq!(truncated, "abc...");
        let unchanged = run_script_truncate_chars("abc", 10);
        assert_eq!(unchanged, "abc");
    }

    #[test]
    fn task_payload_preserves_valid_call_tool_result() {
        let payload = json!({
            "content": [{"type": "text", "text": "ok"}],
            "isError": false
        });
        let wrapped = task_payload_result_value(Some(payload.clone()));
        let parsed: CallToolResult = serde_json::from_value(wrapped).expect("must parse");
        assert!(!parsed.is_error.unwrap_or(false));
        assert_eq!(parsed.content.len(), 1);
    }

    #[test]
    fn task_payload_wraps_content_array_shape_that_is_not_call_tool_result() {
        let payload = json!([
            {"type": "text", "text": "not-call-tool-result-root"}
        ]);
        let wrapped = task_payload_result_value(Some(payload));
        let parsed: CallToolResult = serde_json::from_value(wrapped).expect("must parse");
        assert_eq!(parsed.content.len(), 1);
    }
}
