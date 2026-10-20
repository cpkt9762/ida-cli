//! MCP server implementation with IDA Pro tools.

pub mod mcp_socket;
mod nexus_dsc;
mod requests;
pub mod response_cache;
pub mod socket_listener;
pub mod task;

pub use requests::*;

use crate::error::ToolError;
use crate::tool_registry::{self, ToolCategory};
use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo, Tool},
    schemars::{schema_for, JsonSchema},
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde_json::{json, Value};
use tracing::{debug, info, instrument, warn};

/// MCP server for IDA Pro analysis
#[derive(Clone)]
pub struct IdaMcpServer {
    tool_mux: ToolMux<IdaMcpServer>,
    router: crate::router::RouterState,
    task_registry: task::TaskRegistry,
    /// Identity of the MCP session this server instance serves. The daemon
    /// builds one instance per session (per request in stateless HTTP mode).
    client: crate::router::listing::ClientIdentity,
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

impl ToolMux<IdaMcpServer> {
    async fn call(
        &self,
        context: ToolCallContext<'_, IdaMcpServer>,
    ) -> Result<CallToolResult, McpError> {
        {
            if !matches!(
                context.name.as_ref(),
                "open_idb"
                    | "list_idbs"
                    | "close_idb"
                    | "tool_catalog"
                    | "tool_help"
                    | "get_task_status"
                    | "convert_number"
            ) {
                if let Err(error) = crate::router::nexus_tools::Tools::require_tool(
                    tool_registry::primary_name_for(&context.name),
                ) {
                    return Ok(error.to_tool_result());
                }
            }
        }
        self.call_router.call(context).await
    }
}

impl IdaMcpServer {
    pub fn new(router: crate::router::RouterState) -> Self {
        info!("Creating IDA MCP server");
        let call_router = Self::tool_router();
        Self {
            tool_mux: ToolMux::new(call_router),
            router,
            task_registry: task::TaskRegistry::new(),
            client: crate::router::listing::ClientIdentity::mcp_session(),
        }
    }

    fn close_hint(&self) -> &'static str {
        "close_idb requires the close_token returned by open_idb; each opener holds one reference, database closes when all references are released."
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
                 \n- core: open/close/discover (open_idb, close_idb, list_idbs, tool_catalog, tool_help, idb_meta) \
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

    async fn route_or_err(
        &self,
        router: &crate::router::RouterState,
        handle: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<CallToolResult, McpError> {
        // Multi-IDB guard is enforced in RouterState::route_request itself.
        let result = if let Some(preparation) = crate::preprocess::current() {
            router
                .route_request_prepared(handle, method, params, preparation)
                .await
        } else {
            router.route_request(handle, method, params).await
        };
        match result {
            Ok(v) => {
                match crate::blocking::response(move || serde_json::to_string_pretty(&v)).await {
                    Ok(Ok(encoded)) => Ok(CallToolResult::success(vec![Content::text(encoded)])),
                    Ok(Err(error)) => Ok(ToolError::IdaError(format!(
                        "MCP response encoding: {error}"
                    ))
                    .to_tool_result()),
                    Err(error) => Ok(error.to_tool_result()),
                }
            }
            Err(e)
                if (method == "load_debug_info"
                    || matches!(
                        method,
                        "patch_assembly"
                            | "rename_local_variable"
                            | "set_local_variable_type"
                            | "set_decompiler_comment"
                    ) && matches!(&e, ToolError::IdaError(_))) =>
            {
                // The legacy MCP adapter wraps the worker's business error.
                // Raw RPC keeps its original error text in nexus_tools.
                Ok(ToolError::IdaError(e.to_string()).to_tool_result())
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    async fn run_debug_script(
        &self,
        db_handle: Option<&str>,
        tool_name: &str,
        script: &str,
        timeout_secs: u64,
        _route_args: Value,
    ) -> Result<CallToolResult, McpError> {
        let outer_timeout = timeout_secs + 5;
        let router = &self.router;

        let params = json!({"code": script, "timeout_secs": outer_timeout});
        return match router.route_request(db_handle, "run_script", params).await {
            Ok(result) => match crate::ida::handlers::debug::parse_debug_output(&result) {
                Ok(data) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&data).unwrap_or_default(),
                )])),
                Err(e) => {
                    warn!(tool = tool_name, error = %e, "debug script parse failed (routed)");
                    Ok(e.to_tool_result())
                }
            },
            Err(e) => Ok(e.to_tool_result()),
        };
    }

    async fn open_idb_routed(
        &self,
        router: &crate::router::RouterState,
        req: &OpenIdbRequest,
    ) -> Result<CallToolResult, McpError> {
        return self.open_idb_nexus(router, req).await;
    }

    async fn open_idb_nexus(
        &self,
        router: &crate::router::RouterState,
        req: &OpenIdbRequest,
    ) -> Result<CallToolResult, McpError> {
        if req.load_debug_info == Some(true)
            || req.debug_info_path.is_some()
            || req.file_type.is_some()
        {
            return Ok(ToolError::NotSupported(
                "Nexus debug-info and custom loader options are not implemented".into(),
            )
            .to_tool_result());
        }
        let preparation = crate::preprocess::current().unwrap_or_else(|| {
            crate::preprocess::Preparation::new(std::time::Duration::from_secs(120))
        });
        let opened = if req.force == Some(true) {
            router
                .refresh_nexus_cache(&req.path, preparation.clone())
                .await
        } else {
            router
                .ensure_worker_prepared(&req.path, None, None, preparation.clone())
                .await
        };
        let (handle, token) = match opened {
            Ok(value) => value,
            Err(error) => return Ok(error.to_tool_result()),
        };
        router.set_nexus_client(&handle, &self.client);
        let mut reference =
            crate::router::nexus_tools::ReferenceGuard::new(router.clone(), token.clone());
        let mut value = match router.nexus_open_details(&handle, preparation).await {
            Ok(value) => value,
            Err(error) => return Ok(error.to_tool_result()),
        };
        value["db_handle"] = json!(handle);
        value["close_token"] = json!(token);
        value["close_hint"] = json!(self.close_hint());
        value["quick_tools"] = json!([
            "list_functions",
            "get_function_by_name",
            "disassemble_function",
            "decompile_function",
            "get_xrefs_to",
            "list_strings",
            "close_idb"
        ]);
        let encoded = match serde_json::to_string_pretty(&value) {
            Ok(encoded) => encoded,
            Err(error) => return Ok(ToolError::IdaError(error.to_string()).to_tool_result()),
        };
        reference.transfer();
        Ok(CallToolResult::success(vec![Content::text(encoded)]))
    }

    async fn close_idb_routed(
        &self,
        router: &crate::router::RouterState,
        req: &CloseIdbRequest,
    ) -> Result<CallToolResult, McpError> {
        let Some(token) = req.token.as_deref() else {
            return Ok(ToolError::InvalidParams(
                "close_idb requires close_token in Nexus mode".into(),
            )
            .to_tool_result());
        };
        let (result, lifecycle) = router.nexus_close_token_detailed(token).await;
        let mut result = match result {
                Ok(None) => CallToolResult::success(vec![Content::text("close_idb ignored: invalid close_token")]),
                Ok(Some((_,remaining))) if remaining > 0 => CallToolResult::success(vec![Content::text(format!("Reference released ({remaining} client(s) still active, database remains open)"))]),
                Ok(Some(_)) => CallToolResult::success(vec![Content::text("Database closed")]),
                Err(error) => error.to_tool_result(),
            };
        if let Some(lifecycle) = lifecycle {
            result
                .meta
                .get_or_insert_with(Default::default)
                .0
                .insert("nexus".into(), json!({"lifecycle":lifecycle}));
        }
        Ok(result)
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

        let router = &self.router;

        return self.open_idb_routed(router, &req).await;
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
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "load_debug_info",
                json!({"path": req.path, "verbose": req.verbose.unwrap_or(false)}),
            )
            .await;
    }

    #[tool(description = "Report auto-analysis status (auto_is_ok, auto_state). \
        Use this to check whether analysis-dependent tools (xrefs, decompile) are fully ready.")]
    #[instrument(skip(self))]
    async fn get_analysis_status(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_analysis_status");
        let router = &self.router;

        return self
            .route_or_err(router, None, "get_analysis_status", json!({}))
            .await;
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

        let router = &self.router;

        return self.close_idb_routed(router, &req).await;
    }

    #[tool(description = "List the databases the daemon currently holds open. \
        Per database: db_handle, the input path and the .i64 it was opened from, an opaque id of \
        the client that opened it, when it was opened, the worker process, whether it is the \
        active database, and which clients still hold references. \
        Use it before rebuilding or replacing an .i64 (for example with idat) to confirm no other \
        client has it open. Returns an empty list when nothing is open. \
        Never returns close tokens; client ids tell clients apart and are not credentials.")]
    #[instrument(skip(self))]
    async fn list_idbs(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_idbs");
        let router = &self.router;
        let listing = router.list_idbs(Some(&self.client)).await;
        let text = match listing
            .to_json()
            .and_then(|v| serde_json::to_string_pretty(&v))
        {
            Ok(text) => text,
            Err(e) => {
                return Ok(
                    ToolError::IdaError(format!("failed to serialize database list: {e}"))
                        .to_tool_result(),
                )
            }
        };
        Ok(CallToolResult::success(vec![Content::text(text)]))
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
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "list_functions",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "List functions (ida-pro-mcp compatible alias). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn list_funcs(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_funcs");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "list_functions",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Resolve a function name to its address")]
    #[instrument(skip(self), fields(name = %req.name))]
    async fn get_function_by_name(
        &self,
        Parameters(req): Parameters<ResolveFunctionRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_function_by_name");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_function_by_name",
                json!({"name": req.name}),
            )
            .await;
    }

    #[tool(
        description = "Get the type/prototype declaration of a function at a given address or name"
    )]
    async fn get_function_prototype(
        &self,
        Parameters(req): Parameters<GetFunctionPrototypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_function_prototype",
                json!({"address": req.address, "name": req.name}),
            )
            .await;
    }

    #[tool(description = "Get address context (segment, function, nearest symbol)")]
    async fn get_address_info(
        &self,
        Parameters(req): Parameters<AddrInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_address_info",
                json!({"addr": req.address, "name": req.target_name, "offset": req.offset}),
            )
            .await;
    }

    #[tool(description = "Get the function that contains an address")]
    async fn get_function_at_address(
        &self,
        Parameters(req): Parameters<FunctionAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_function_at_address",
                json!({"addr": req.address, "name": req.target_name, "offset": req.offset}),
            )
            .await;
    }

    #[tool(description = "Get disassembly at an address")]
    #[instrument(skip(self), fields(address = %req.address, count = req.count))]
    async fn disassemble(
        &self,
        Parameters(req): Parameters<DisasmRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disassemble");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "disassemble",
                json!({"address": req.address, "count": req.count}),
            )
            .await;
    }

    #[tool(description = "Get disassembly for a function by name")]
    #[instrument(skip(self), fields(name = %req.name, count = req.count))]
    async fn disassemble_function(
        &self,
        Parameters(req): Parameters<DisasmByNameRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disassemble_function");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "disassemble_function",
                json!({"name": req.name, "count": req.count}),
            )
            .await;
    }

    #[tool(description = "Disassemble the function containing an address")]
    async fn disassemble_function_at(
        &self,
        Parameters(req): Parameters<DisasmFunctionAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "disassemble_function_at",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(
        description = "Decompile a function using Hex-Rays (if available). With \
        line_addresses=true the answer is JSON {code, lines}: one {line, text, addresses} entry \
        per pseudocode line, where addresses are the IDA addresses Hex-Rays anchored on that line"
    )]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn decompile_function(
        &self,
        Parameters(req): Parameters<DecompileRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: decompile_function");
        let line_addresses = req.line_addresses == Some(true);
        let router = &self.router;

        let mut params = json!({"address": req.address});
        if line_addresses {
            params["line_addresses"] = json!(true);
        }
        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "decompile_function",
                params,
            )
            .await;
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
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_pseudocode_at",
                json!({"address": req.address, "end_addr": req.end_address}),
            )
            .await;
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

        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "run_script",
                json!({"code": script, "timeout_secs": 120}),
            )
            .await;
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

        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "batch_decompile",
                json!({ "addresses": addrs }),
            )
            .await;
    }

    #[tool(description = "Search all functions' decompiled pseudocode for a text pattern")]
    async fn search_pseudocode(
        &self,
        Parameters(req): Parameters<SearchPseudocodeRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: search_pseudocode");

        let limit = req.limit.unwrap_or(20).min(100);

        let router = &self.router;

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

    #[tool(description = "Scan a table in memory by reading entries at stride intervals")]
    async fn scan_memory_table(
        &self,
        Parameters(req): Parameters<TableScanRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: scan_memory_table");

        let stride = req.stride.unwrap_or(8).max(1);
        let count = req.count.unwrap_or(16).min(256);

        let router = &self.router;

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

    #[tool(
        description = "Decompile two functions and return a line-by-line diff of their pseudocode"
    )]
    async fn diff_pseudocode(
        &self,
        Parameters(req): Parameters<DiffFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: diff_pseudocode");

        let router = &self.router;

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

    #[tool(description = "List all segments in the database with their permissions and types")]
    #[instrument(skip(self))]
    async fn list_segments(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_segments");
        let router = &self.router;

        return self
            .route_or_err(router, None, "list_segments", json!({}))
            .await;
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

        let router = &self.router;

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

    #[tool(description = "Find strings and return xrefs to each match. \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    async fn get_xrefs_to_string(
        &self,
        Parameters(req): Parameters<XrefsToStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_xrefs_to_string",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Get cross-references TO an address (who references this address)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_xrefs_to(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_xrefs_to");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_xrefs_to",
                json!({"address": req.address}),
            )
            .await;
    }

    #[tool(description = "Get cross-references FROM an address (what this address references)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_xrefs_from(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_xrefs_from");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_xrefs_from",
                json!({"address": req.address}),
            )
            .await;
    }

    #[tool(description = "List imports (external symbols) with pagination")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn list_imports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_imports");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "list_imports",
                json!({"offset": req.offset, "limit": req.limit}),
            )
            .await;
    }

    #[tool(description = "List exports/names (public symbols) with pagination")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn list_exports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_exports");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "list_exports",
                json!({"offset": req.offset, "limit": req.limit}),
            )
            .await;
    }

    #[tool(description = "Get entry point addresses of the binary")]
    #[instrument(skip(self))]
    async fn list_entry_points(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_entry_points");
        let router = &self.router;

        return self
            .route_or_err(router, None, "list_entry_points", json!({}))
            .await;
    }

    #[tool(description = "Read raw bytes from an address as hex string")]
    #[instrument(skip(self), fields(size = req.size))]
    async fn read_bytes(
        &self,
        Parameters(req): Parameters<GetBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_bytes");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "read_bytes",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Get basic blocks of a function (control flow graph nodes)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_basic_blocks(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_basic_blocks");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_basic_blocks",
                json!({"address": req.address}),
            )
            .await;
    }

    #[tool(description = "Get functions called BY a function (callees/children in call graph)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_callees(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_callees");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_callees",
                json!({"address": req.address}),
            )
            .await;
    }

    #[tool(description = "Get functions that CALL a function (callers/parents in call graph)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn get_callers(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_callers");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_callers",
                json!({"address": req.address}),
            )
            .await;
    }

    #[tool(description = "Get IDB metadata (ida-pro-mcp compatibility)")]
    #[instrument(skip(self))]
    async fn get_database_info(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_database_info");
        let router = &self.router;

        return self
            .route_or_err(router, None, "get_database_info", json!({}))
            .await;
    }

    #[tool(description = "Lookup functions by name or address (batch)")]
    #[instrument(skip(self))]
    async fn batch_lookup_functions(
        &self,
        Parameters(req): Parameters<LookupFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: batch_lookup_functions");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "batch_lookup_functions",
                json!({"queries": req.queries}),
            )
            .await;
    }

    #[tool(description = "List global names (non-function symbols). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn list_globals(
        &self,
        Parameters(req): Parameters<ListGlobalsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_globals");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "list_globals",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Find byte patterns (ida-pro-mcp compatibility). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self))]
    async fn search_bytes(
        &self,
        Parameters(req): Parameters<FindBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: search_bytes");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "search_bytes",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
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
        let router = &self.router;

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
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({"results": results})).unwrap_or_default(),
        )]))
    }

    #[tool(description = "Read u8 values at address(es)")]
    #[instrument(skip(self))]
    async fn read_byte(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "read_int",
                json!({"address": req.address, "size": 1}),
            )
            .await;
    }

    #[tool(description = "Read u16 values at address(es)")]
    #[instrument(skip(self))]
    async fn read_word(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "read_int",
                json!({"address": req.address, "size": 2}),
            )
            .await;
    }

    #[tool(description = "Read u32 values at address(es)")]
    #[instrument(skip(self))]
    async fn read_dword(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "read_int",
                json!({"address": req.address, "size": 4}),
            )
            .await;
    }

    #[tool(description = "Read u64 values at address(es)")]
    #[instrument(skip(self))]
    async fn read_qword(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "read_int",
                json!({"address": req.address, "size": 8}),
            )
            .await;
    }

    #[tool(description = "Read string(s) at address(es)")]
    #[instrument(skip(self))]
    async fn read_string(
        &self,
        Parameters(req): Parameters<GetStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_string");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "read_string",
                json!({"address": req.address, "max_len": req.max_len}),
            )
            .await;
    }

    #[tool(description = "Get global value(s) by name or address")]
    #[instrument(skip(self))]
    async fn read_global_variable(
        &self,
        Parameters(req): Parameters<GetGlobalValueRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_global_variable");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "read_global_variable",
                json!({"query": req.query}),
            )
            .await;
    }

    #[tool(description = "Find paths between two addresses (CFG)")]
    #[instrument(skip(self))]
    async fn find_control_flow_paths(
        &self,
        Parameters(req): Parameters<FindPathsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_control_flow_paths");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "find_control_flow_paths",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Build a callgraph rooted at an address")]
    #[instrument(skip(self))]
    async fn build_callgraph(
        &self,
        Parameters(req): Parameters<CallGraphRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: build_callgraph");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "build_callgraph",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Compute xref matrix for a set of addresses")]
    #[instrument(skip(self))]
    async fn build_xref_matrix(
        &self,
        Parameters(req): Parameters<XrefMatrixRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: build_xref_matrix");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "build_xref_matrix",
                json!({"addrs": req.addrs}),
            )
            .await;
    }

    #[tool(description = "Export functions (ida-pro-mcp compatibility)")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn export_functions(
        &self,
        Parameters(req): Parameters<ExportFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: export_functions");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "export_functions",
                json!({"offset": req.offset, "limit": req.limit}),
            )
            .await;
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
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "list_local_types",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Get xrefs to a struct field")]
    async fn get_xrefs_to_struct_field(
        &self,
        Parameters(req): Parameters<XrefsToFieldRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_xrefs_to_struct_field",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Set comments at an address")]
    async fn set_comment(
        &self,
        Parameters(req): Parameters<SetCommentsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "set_comment",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Set a function-level comment (visible at function entry)")]
    async fn set_function_comment(
        &self,
        Parameters(req): Parameters<SetFunctionCommentRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "set_function_comment",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Patch instructions with assembly text")]
    async fn patch_assembly(
        &self,
        Parameters(req): Parameters<PatchAsmRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "patch_assembly",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Declare a type in the local type library")]
    async fn declare_c_type(
        &self,
        Parameters(req): Parameters<DeclareTypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "declare_c_type",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Get stack frame info")]
    async fn get_stack_frame(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_stack_frame",
                json!({"address": req.address}),
            )
            .await;
    }

    #[tool(description = "Declare a stack variable in a function frame")]
    async fn create_stack_variable(
        &self,
        Parameters(req): Parameters<DeclareStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "create_stack_variable",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Delete a stack variable from a function frame")]
    async fn delete_stack_variable(
        &self,
        Parameters(req): Parameters<DeleteStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "delete_stack_variable",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Rename a stack frame variable in a function")]
    async fn rename_stack_variable(
        &self,
        Parameters(req): Parameters<RenameStackVariableRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "rename_stack_variable",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Set the type of a stack frame variable")]
    async fn set_stack_variable_type(
        &self,
        Parameters(req): Parameters<SetStackVariableTypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "set_stack_variable_type",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "List all enum types in the database")]
    async fn list_enums(
        &self,
        Parameters(req): Parameters<ListEnumsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "list_enums",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Create an enum type from a C declaration")]
    async fn create_enum(
        &self,
        Parameters(req): Parameters<CreateEnumRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "create_enum",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
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
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "list_structs",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Get info about a struct by ordinal or name")]
    #[instrument(skip(self), fields(ordinal = req.ordinal, name = ?req.name))]
    async fn get_struct_info(
        &self,
        Parameters(req): Parameters<StructInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_struct_info");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "get_struct_info",
                json!({"ordinal": req.ordinal, "name": req.name}),
            )
            .await;
    }

    #[tool(description = "Read values of a struct instance at an address")]
    #[instrument(skip(self), fields(address = %req.address, ordinal = req.ordinal, name = ?req.name))]
    async fn read_struct_at_address(
        &self,
        Parameters(req): Parameters<ReadStructRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_struct_at_address");
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "read_struct_at_address",
                json!({"address": req.address, "ordinal": req.ordinal, "name": req.name}),
            )
            .await;
    }

    #[tool(description = "Search structs by name")]
    async fn search_structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "list_structs",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Find instruction sequences by mnemonic")]
    async fn search_instructions(
        &self,
        Parameters(req): Parameters<FindInsnsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "search_instructions",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Find instruction operands")]
    async fn search_instruction_operands(
        &self,
        Parameters(req): Parameters<FindInsnOperandsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "search_instruction_operands",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Apply a type to an address")]
    async fn apply_type(
        &self,
        Parameters(req): Parameters<ApplyTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "apply_type",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Apply a C prototype declaration to a function")]
    async fn set_function_prototype(
        &self,
        Parameters(req): Parameters<SetFunctionPrototypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "set_function_prototype",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Infer/guess type at an address")]
    async fn infer_type(
        &self,
        Parameters(req): Parameters<InferTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "infer_type",
                json!({"addr": req.address, "name": req.target_name, "offset": req.offset}),
            )
            .await;
    }

    #[tool(description = "Analyze functions (not supported)")]
    async fn run_auto_analysis(
        &self,
        Parameters(req): Parameters<AnalyzeFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "run_auto_analysis",
                json!({"timeout_secs": req.timeout_secs}),
            )
            .await;
    }

    #[tool(description = "Rename symbols")]
    async fn rename_symbol(
        &self,
        Parameters(req): Parameters<RenameRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "rename_symbol",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Rename multiple symbols at once")]
    async fn batch_rename(
        &self,
        Parameters(req): Parameters<BatchRenameRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "batch_rename",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Rename a local variable in decompiled pseudocode")]
    async fn rename_local_variable(
        &self,
        Parameters(req): Parameters<RenameLvarRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "rename_local_variable",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Set the type of a local variable in decompiled pseudocode")]
    async fn set_local_variable_type(
        &self,
        Parameters(req): Parameters<SetLvarTypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "set_local_variable_type",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Set a comment in decompiled pseudocode")]
    async fn set_decompiler_comment(
        &self,
        Parameters(req): Parameters<SetDecompilerCommentRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "set_decompiler_comment",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
    }

    #[tool(description = "Patch bytes at an address")]
    async fn patch_bytes(
        &self,
        Parameters(req): Parameters<PatchRequest>,
    ) -> Result<CallToolResult, McpError> {
        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "patch_bytes",
                serde_json::to_value(&req).unwrap_or_default(),
            )
            .await;
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
        self.open_dsc_nexus(&self.router, req).await
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

        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "run_script",
                json!({"code": script, "timeout_secs": timeout}),
            )
            .await;
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
        let timeout = Some(req.timeout_secs.unwrap_or(300).min(600));
        let script = crate::dsc::dsc_add_region_script(ea);

        let router = &self.router;

        return self
            .route_or_err(
                router,
                req.db_handle.as_deref(),
                "run_script",
                json!({"code": script, "timeout_secs": timeout}),
            )
            .await;
    }

    #[tool(
        description = "Check the status of a background task (e.g. DSC loading). \
        Returns the current status: 'running' (with a progress message), \
        'completed' (with the result — database is already open), \
        'failed' (with an error message), or 'cancelled'. \
        Use the task_id returned by open_dsc."
    )]
    #[instrument(skip(self), fields(task_id = %req.task_id))]
    async fn get_task_status(
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
        let preparation = crate::preprocess::current().unwrap_or_else(|| {
            crate::preprocess::Preparation::new(std::time::Duration::from_secs(
                req.timeout_secs.unwrap_or(120).min(600),
            ))
        });
        let _cancellation_guard = preparation.cancel_on_drop();
        let code = match (req.code, req.file) {
            (Some(code), None) => code,
            (None, Some(path)) => {
                let source = path.clone();
                match preparation
                    .wait(crate::blocking::run(
                        crate::blocking::WorkClass::Prepare,
                        move || {
                            if !Self::validate_path(&source) {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "invalid script path",
                                ));
                            }
                            read_script_file(source)
                        },
                    ))
                    .await
                {
                    Ok(Ok(contents)) => contents,
                    Ok(Err(e)) => {
                        return Ok(ToolError::InvalidPath(format!(
                            "Failed to read script file '{}': {}",
                            path, e
                        ))
                        .to_tool_result());
                    }
                    Err(error) => return Ok(error.to_tool_result()),
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
        let router = &self.router;

        return preparation
            .scope(self.route_or_err(
                router,
                req.db_handle.as_deref(),
                "run_script",
                json!({"code": code, "timeout_secs": timeout}),
            ))
            .await;
    }

    #[tool(
        description = "Load a debugger module (e.g. 'mac', 'linux', 'gdb'). Must be called before starting a debug session."
    )]
    #[instrument(skip(self))]
    async fn dbg_load_debugger(
        &self,
        Parameters(req): Parameters<DbgLoadDebuggerRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_load_debugger");
        let timeout = req.timeout_secs.unwrap_or(30).min(600);
        let name = req.debugger_name.as_deref().unwrap_or("mac");
        let is_remote = req.is_remote.unwrap_or(false);
        let dbgsrv = crate::ida::handlers::debug::find_debug_server_path();
        let script = crate::ida::handlers::debug::process::generate_load_debugger_script(
            name,
            is_remote,
            dbgsrv.as_deref(),
        );
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_load_debugger",
            &script,
            timeout,
            json!({"debugger_name": name, "is_remote": is_remote}),
        )
        .await
    }

    #[tool(
        description = "Start a process under the debugger. Auto-loads the native debugger if not already loaded."
    )]
    #[instrument(skip(self))]
    async fn dbg_start_process(
        &self,
        Parameters(req): Parameters<DbgStartProcessRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_start_process");
        let timeout = req.timeout_secs.unwrap_or(60).min(600);
        let dbgsrv = crate::ida::handlers::debug::find_debug_server_path();
        let script = crate::ida::handlers::debug::process::generate_start_process_script(
            req.path.as_deref(),
            req.args.as_deref(),
            req.start_dir.as_deref(),
            timeout,
            dbgsrv.as_deref(),
        );
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_start_process",
            &script,
            timeout,
            json!({"path": req.path, "args": req.args, "start_dir": req.start_dir}),
        )
        .await
    }

    #[tool(description = "Attach the debugger to a running process by PID.")]
    #[instrument(skip(self))]
    async fn dbg_attach_process(
        &self,
        Parameters(req): Parameters<DbgAttachProcessRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_attach_process");
        let timeout = req.timeout_secs.unwrap_or(30).min(600);
        let dbgsrv = crate::ida::handlers::debug::find_debug_server_path();
        let script = crate::ida::handlers::debug::process::generate_attach_process_script(
            req.pid,
            timeout,
            dbgsrv.as_deref(),
        );
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_attach_process",
            &script,
            timeout,
            json!({"pid": req.pid}),
        )
        .await
    }

    #[tool(description = "Detach the debugger from the current process without terminating it.")]
    #[instrument(skip(self))]
    async fn dbg_detach_process(
        &self,
        Parameters(req): Parameters<DbgDetachProcessRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_detach_process");
        let timeout = req.timeout_secs.unwrap_or(30).min(600);
        let script = crate::ida::handlers::debug::process::generate_detach_process_script();
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_detach_process",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(description = "Terminate the debugged process and end the debug session.")]
    #[instrument(skip(self))]
    async fn dbg_exit_process(
        &self,
        Parameters(req): Parameters<DbgExitProcessRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_exit_process");
        let timeout = req.timeout_secs.unwrap_or(30).min(600);
        let script = crate::ida::handlers::debug::process::generate_exit_process_script();
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_exit_process",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(
        description = "Get current debugger and process state (DSTATE_NOTASK/DSTATE_SUSP/DSTATE_RUN)."
    )]
    #[instrument(skip(self))]
    async fn dbg_get_state(
        &self,
        Parameters(req): Parameters<DbgGetStateRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_get_state");
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script = crate::ida::handlers::debug::process::generate_get_state_script();
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_get_state",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(
        description = "Set a breakpoint at the given address. Supports software, hardware, read/write watchpoints."
    )]
    #[instrument(skip(self))]
    async fn dbg_add_breakpoint(
        &self,
        Parameters(req): Parameters<DbgAddBreakpointRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_add_breakpoint");
        let addr = match crate::ida::handlers::parse_address_str(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let size = req.size.unwrap_or(0);
        let bpt_type = req.bpt_type.as_deref().unwrap_or("soft");
        let script = crate::ida::handlers::debug::breakpoint::generate_add_breakpoint_script(
            addr,
            size,
            bpt_type,
            req.condition.as_deref(),
        );
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_add_breakpoint",
            &script,
            timeout,
            json!({"address": req.address, "size": size, "bpt_type": bpt_type}),
        )
        .await
    }

    #[tool(description = "Delete a breakpoint at the given address.")]
    #[instrument(skip(self))]
    async fn dbg_del_breakpoint(
        &self,
        Parameters(req): Parameters<DbgDelBreakpointRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_del_breakpoint");
        let addr = match crate::ida::handlers::parse_address_str(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script = crate::ida::handlers::debug::breakpoint::generate_del_breakpoint_script(addr);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_del_breakpoint",
            &script,
            timeout,
            json!({"address": req.address}),
        )
        .await
    }

    #[tool(description = "Enable or disable a breakpoint at the given address.")]
    #[instrument(skip(self))]
    async fn dbg_enable_breakpoint(
        &self,
        Parameters(req): Parameters<DbgEnableBreakpointRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_enable_breakpoint");
        let addr = match crate::ida::handlers::parse_address_str(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let enable = req.enable.unwrap_or(true);
        let script = crate::ida::handlers::debug::breakpoint::generate_enable_breakpoint_script(
            addr, enable,
        );
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_enable_breakpoint",
            &script,
            timeout,
            json!({"address": req.address, "enable": enable}),
        )
        .await
    }

    #[tool(description = "List all breakpoints in the current IDA database.")]
    #[instrument(skip(self))]
    async fn dbg_list_breakpoints(
        &self,
        Parameters(req): Parameters<DbgListBreakpointsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_list_breakpoints");
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script = crate::ida::handlers::debug::breakpoint::generate_list_breakpoints_script();
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_list_breakpoints",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(
        description = "Continue execution until the next breakpoint or debug event. Process must be suspended."
    )]
    #[instrument(skip(self))]
    async fn dbg_continue(
        &self,
        Parameters(req): Parameters<DbgContinueRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_continue");
        let timeout = req.timeout_secs.unwrap_or(30).min(600);
        let script = crate::ida::handlers::debug::execution::generate_continue_script(timeout);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_continue",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(
        description = "Step into the next instruction (follows calls). Process must be suspended."
    )]
    #[instrument(skip(self))]
    async fn dbg_step_into(
        &self,
        Parameters(req): Parameters<DbgStepIntoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_step_into");
        let timeout = req.timeout_secs.unwrap_or(30).min(600);
        let script = crate::ida::handlers::debug::execution::generate_step_into_script(timeout);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_step_into",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(
        description = "Step over the next instruction (skips calls). Process must be suspended."
    )]
    #[instrument(skip(self))]
    async fn dbg_step_over(
        &self,
        Parameters(req): Parameters<DbgStepOverRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_step_over");
        let timeout = req.timeout_secs.unwrap_or(30).min(600);
        let script = crate::ida::handlers::debug::execution::generate_step_over_script(timeout);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_step_over",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(description = "Step until the current function returns. Process must be suspended.")]
    #[instrument(skip(self))]
    async fn dbg_step_until_ret(
        &self,
        Parameters(req): Parameters<DbgStepUntilRetRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_step_until_ret");
        let timeout = req.timeout_secs.unwrap_or(60).min(600);
        let script =
            crate::ida::handlers::debug::execution::generate_step_until_ret_script(timeout);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_step_until_ret",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(
        description = "Run execution to a specific address. Sets a temporary breakpoint and continues."
    )]
    #[instrument(skip(self))]
    async fn dbg_run_to(
        &self,
        Parameters(req): Parameters<DbgRunToRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_run_to");
        let addr = match crate::ida::handlers::parse_address_str(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let timeout = req.timeout_secs.unwrap_or(60).min(600);
        let script = crate::ida::handlers::debug::execution::generate_run_to_script(addr, timeout);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_run_to",
            &script,
            timeout,
            json!({"address": req.address}),
        )
        .await
    }

    #[tool(
        description = "Read register values from the suspended process. Returns all registers or a filtered subset."
    )]
    #[instrument(skip(self))]
    async fn dbg_get_registers(
        &self,
        Parameters(req): Parameters<DbgGetRegistersRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_get_registers");
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script = crate::ida::handlers::debug::inspect::generate_get_registers_script(
            req.register_names.as_deref(),
        );
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_get_registers",
            &script,
            timeout,
            json!({"register_names": req.register_names}),
        )
        .await
    }

    #[tool(description = "Set a register value in the suspended process.")]
    #[instrument(skip(self))]
    async fn dbg_set_register(
        &self,
        Parameters(req): Parameters<DbgSetRegisterRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_set_register");
        let value = match crate::ida::handlers::parse_address_str(&req.value) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script = crate::ida::handlers::debug::inspect::generate_set_register_script(
            &req.register_name,
            value,
        );
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_set_register",
            &script,
            timeout,
            json!({"register_name": req.register_name, "value": req.value}),
        )
        .await
    }

    #[tool(
        description = "Read raw bytes from the debugged process memory. Process must be suspended. Max 4096 bytes."
    )]
    #[instrument(skip(self))]
    async fn dbg_read_memory(
        &self,
        Parameters(req): Parameters<DbgReadMemoryRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_read_memory");
        let addr = match crate::ida::handlers::parse_address_str(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script =
            crate::ida::handlers::debug::inspect::generate_read_memory_script(addr, req.size);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_read_memory",
            &script,
            timeout,
            json!({"address": req.address, "size": req.size}),
        )
        .await
    }

    #[tool(
        description = "Write bytes to the debugged process memory. Process must be suspended. Data is hex-encoded."
    )]
    #[instrument(skip(self))]
    async fn dbg_write_memory(
        &self,
        Parameters(req): Parameters<DbgWriteMemoryRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_write_memory");
        let addr = match crate::ida::handlers::parse_address_str(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script =
            crate::ida::handlers::debug::inspect::generate_write_memory_script(addr, &req.data);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_write_memory",
            &script,
            timeout,
            json!({"address": req.address, "data": req.data}),
        )
        .await
    }

    #[tool(
        description = "List memory regions of the debugged process (start, end, name, permissions)."
    )]
    #[instrument(skip(self))]
    async fn dbg_get_memory_info(
        &self,
        Parameters(req): Parameters<DbgGetMemoryInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_get_memory_info");
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script = crate::ida::handlers::debug::inspect::generate_get_memory_info_script();
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_get_memory_info",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(description = "List all threads in the debugged process with their IDs and names.")]
    #[instrument(skip(self))]
    async fn dbg_list_threads(
        &self,
        Parameters(req): Parameters<DbgListThreadsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_list_threads");
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script = crate::ida::handlers::debug::inspect::generate_list_threads_script();
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_list_threads",
            &script,
            timeout,
            json!({}),
        )
        .await
    }

    #[tool(
        description = "Select a thread as the current debugging context. Process must be suspended."
    )]
    #[instrument(skip(self))]
    async fn dbg_select_thread(
        &self,
        Parameters(req): Parameters<DbgSelectThreadRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_select_thread");
        let timeout = req.timeout_secs.unwrap_or(10).min(600);
        let script =
            crate::ida::handlers::debug::inspect::generate_select_thread_script(req.thread_id);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_select_thread",
            &script,
            timeout,
            json!({"thread_id": req.thread_id}),
        )
        .await
    }

    #[tool(
        description = "Wait for the next debug event (breakpoint hit, exception, process exit, etc.)."
    )]
    #[instrument(skip(self))]
    async fn dbg_wait_event(
        &self,
        Parameters(req): Parameters<DbgWaitEventRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dbg_wait_event");
        let timeout = req.timeout_secs.unwrap_or(30).min(600);
        let flags = req
            .flags
            .as_deref()
            .and_then(|s| crate::ida::handlers::parse_address_str(s).ok())
            .unwrap_or(0x0001) as u32;
        let script =
            crate::ida::handlers::debug::inspect::generate_wait_event_script(timeout, flags);
        self.run_debug_script(
            req.db_handle.as_deref(),
            "dbg_wait_event",
            &script,
            timeout,
            json!({"flags": req.flags}),
        )
        .await
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
        "list_idbs" => Some(schema::<EmptyParams>()),
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
        last_updated_at: state.updated_at_iso.clone(),
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
    ) -> Result<GetTaskResult, McpError> {
        let state = self.task_registry.get(&request.task_id).ok_or_else(|| {
            McpError::invalid_params(
                "Unknown task_id",
                Some(json!({ "task_id": request.task_id })),
            )
        })?;
        Ok(GetTaskResult {
            meta: None,
            task: task_state_to_mcp(&state),
        })
    }

    async fn get_task_result(
        &self,
        request: GetTaskResultParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetTaskPayloadResult, McpError> {
        let state = self.task_registry.get(&request.task_id);
        match state {
            Some(s) if s.status == task::TaskStatus::Completed => {
                Ok(GetTaskPayloadResult(task_payload_result_value(s.result)))
            }
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
    ) -> Result<CancelTaskResult, McpError> {
        if self.task_registry.cancel(&request.task_id) {
            let state = self
                .task_registry
                .get(&request.task_id)
                .ok_or_else(|| McpError::internal_error("Task disappeared after cancel", None))?;
            Ok(CancelTaskResult {
                meta: None,
                task: task_state_to_mcp(&state),
            })
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
    ) -> Result<GetTaskResult, McpError> {
        self.0.get_task_info(request, ctx).await
    }

    async fn get_task_result(
        &self,
        request: GetTaskResultParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<GetTaskPayloadResult, McpError> {
        self.0.get_task_result(request, ctx).await
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CancelTaskResult, McpError> {
        self.0.cancel_task(request, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::task_payload_result_value;
    use rmcp::model::CallToolResult;
    use serde_json::json;

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

#[cfg(all(test, feature = "nexus-test-support"))]
#[path = "../../tests/support/r2_server.rs"]
mod r2_lifecycle;

fn read_script_file(source: String) -> std::io::Result<String> {
    #[cfg(test)]
    {
        let barrier = SCRIPT_READ_BARRIERS.lock().unwrap().remove(&source);
        if let Some((started, release)) = barrier {
            started.send(()).unwrap();
            release.recv().unwrap();
        }
    }
    std::fs::read_to_string(source)
}
#[cfg(test)]
type ScriptReadBarrier = (
    tokio::sync::oneshot::Sender<()>,
    std::sync::mpsc::Receiver<()>,
);
#[cfg(test)]
static SCRIPT_READ_BARRIERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, ScriptReadBarrier>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
mod list_idbs_tests {
    use super::IdaMcpServer;
    use crate::router::RouterState;
    use serde_json::{json, Value};

    fn server_on(router: &RouterState) -> IdaMcpServer {
        IdaMcpServer::new(router.clone())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nexus_script_file_read_retains_job_and_cannot_send_after_deadline() {
        use super::{Parameters, SCRIPT_READ_BARRIERS};
        use std::sync::Arc;
        use std::time::Duration;
        let base = std::env::temp_dir().join(format!("n9-script-{}", std::process::id()));
        std::fs::create_dir(&base).expect("private script directory");
        let path = base.join("blocked.py");
        std::fs::write(&path, b"print('fixture')").expect("private script");
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        SCRIPT_READ_BARRIERS
            .lock()
            .expect("barriers")
            .insert(path.display().to_string(), (started, released));
        let router = RouterState::new().expect("Nexus router");
        let server = Arc::new(server_on(&router));
        let preparation = crate::preprocess::Preparation::new(Duration::from_millis(150));
        let observed = preparation.clone();
        let request =
            serde_json::from_value(json!({"file":path,"timeout_secs":1})).expect("request");
        let mut task = tokio::spawn(async move {
            preparation
                .scope(server.run_script(Parameters(request)))
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), start)
            .await
            .expect("read admitted")
            .expect("read started");
        let result = tokio::time::timeout(Duration::from_millis(400), &mut task).await;
        let tracked = observed.active_input_jobs();
        release.send(()).expect("release owned read closure");
        assert!(
            result.is_ok(),
            "script read consumes original total deadline"
        );
        assert!(result
            .expect("bounded result")
            .expect("request task")
            .expect("MCP result")
            .is_error
            .unwrap_or(false));
        tokio::time::timeout(Duration::from_secs(1), async {
            while observed.active_input_jobs() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned read finishes");
        assert_eq!(
            tracked, 1,
            "abandoned file closure retains tracking until EOF"
        );
        assert!(
            router.status_snapshot().await.nexus_lifecycle.is_none(),
            "expired file read never starts a bridge"
        );
        assert_eq!(
            router
                .nexus_endpoint()
                .transition(|s, _| s.retention_status())
                .total_used,
            0,
            "expired read reserves no Nexus operation"
        );
        std::fs::remove_dir_all(base).expect("remove owned script");
    }

    async fn call_list_idbs(server: &IdaMcpServer) -> (Value, String) {
        let result = server.list_idbs().await.expect("tool call succeeds");
        assert_ne!(result.is_error, Some(true), "list_idbs reported an error");
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .expect("text content");
        (serde_json::from_str(&text).expect("JSON body"), text)
    }

    #[test]
    fn list_idbs_is_exposed_by_the_mcp_tool_router() {
        let router = RouterState::new().expect("router");
        let server = server_on(&router);
        assert!(server.tool_mux.get("list_idbs").is_some());
        assert!(server
            .tool_mux
            .list_all()
            .iter()
            .any(|tool| tool.name == "list_idbs"));
    }

    #[tokio::test]
    async fn list_idbs_tool_returns_an_empty_list_when_nothing_is_open() {
        let router = RouterState::new().expect("router");
        let server = server_on(&router);
        let (value, _) = call_list_idbs(&server).await;
        assert_eq!(value, json!({"count": 0, "idbs": []}));
    }

    #[tokio::test]
    async fn nexus_listing_groups_leases_and_preserves_caller_and_token_privacy() {
        let router = RouterState::new().expect("router");
        let first = server_on(&router);
        let second = server_on(&router);
        let (_, token_a) = router.register_test_lease("/db/a", &first.client).await;
        let (_, token_b) = router.register_test_lease("/db/a", &second.client).await;
        router.register_test_lease("/db/b", &second.client).await;
        let (value, text) = call_list_idbs(&first).await;
        assert_eq!(value["count"], 2);
        let items = value["idbs"].as_array().expect("listing");
        let shared = items
            .iter()
            .find(|item| item["input_path"] == "/db/a")
            .expect("shared database");
        assert_eq!(shared["ref_count"], 2);
        assert_eq!(shared["worker"]["backend"], "nexus");
        let holders = shared["holders"].as_array().expect("holders");
        assert_eq!(holders.len(), 2);
        assert_eq!(
            holders
                .iter()
                .filter(|item| item["is_caller"] == true)
                .count(),
            1
        );
        assert!(!text.contains(&token_a) && !text.contains(&token_b));
        assert!(!text.contains("close_token"));
        let (other, _) = call_list_idbs(&second).await;
        assert_eq!(other["count"], 2);
    }
}
