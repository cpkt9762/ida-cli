//! RPC dispatch layer.
//!
//! Contains the generic [`dispatch_rpc`] function that routes JSON-RPC
//! requests to the appropriate [`WorkerDispatch`] method, plus helpers.

use crate::error::ToolError;
use crate::ida::worker_trait::WorkerDispatch;
use crate::router::protocol::RpcRequest;
use crate::server::*;
use crate::tool_registry::primary_name_for;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tracing::debug;

/// Parse a JSON value as a u64 address (supports numeric and hex-string forms).
pub fn parse_address_value(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16).ok();
        }
        return s.parse().ok();
    }
    None
}

/// Parse a JSON value as one or more u64 addresses.
/// Accepts a single string/number OR an array of strings/numbers.
fn parse_address_values(v: &Value) -> Result<Vec<u64>, ToolError> {
    if let Some(arr) = v.as_array() {
        let mut addrs = Vec::with_capacity(arr.len());
        for (i, item) in arr.iter().enumerate() {
            addrs.push(parse_address_value(item).ok_or_else(|| {
                ToolError::InvalidAddress(format!("invalid address at index {i}: {item}"))
            })?);
        }
        if addrs.is_empty() {
            return Err(ToolError::InvalidAddress("empty address array".to_string()));
        }
        Ok(addrs)
    } else {
        let addr = parse_address_value(v)
            .ok_or_else(|| ToolError::InvalidAddress(format!("invalid address: {v}")))?;
        Ok(vec![addr])
    }
}

fn parse_params<T: DeserializeOwned>(p: &Value) -> Result<T, ToolError> {
    serde_json::from_value(p.clone())
        .map_err(|e| ToolError::InvalidParams(format!("invalid params: {e}")))
}

fn parse_string_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_patch_bytes(v: &Value) -> Vec<u8> {
    if let Some(arr) = v.as_array() {
        return arr
            .iter()
            .filter_map(|item| item.as_u64().map(|n| n as u8))
            .collect();
    }
    if let Some(hex_str) = v.as_str() {
        return hex_str
            .split_whitespace()
            .filter_map(|s| {
                u8::from_str_radix(
                    s.strip_prefix("0x")
                        .or_else(|| s.strip_prefix("0X"))
                        .unwrap_or(s),
                    16,
                )
                .ok()
            })
            .collect();
    }
    Vec::new()
}

/// Dispatch a JSON-RPC request to the appropriate worker method.
pub async fn dispatch_rpc<W: WorkerDispatch>(
    req: &RpcRequest,
    worker: &W,
) -> Result<Value, ToolError> {
    let p = &req.params;
    debug!(method = %req.method, params = %p, "dispatch_rpc");
    let method = primary_name_for(req.method.as_str());

    match method {
        // ── Database management ──────────────────────────────────────────
        "open" => {
            let path = p["path"].as_str().unwrap_or("").to_string();
            let auto_analyse = p["auto_analyse"].as_bool().unwrap_or(false);
            let load_debug_info = p["load_debug_info"].as_bool().unwrap_or(false);
            let debug_info_path = p["debug_info_path"].as_str().map(String::from);
            let debug_info_verbose = p["debug_info_verbose"].as_bool().unwrap_or(false);
            let force = p["force"].as_bool().unwrap_or(false);
            let file_type = p["file_type"].as_str().map(String::from);
            let extra_args = p["extra_args"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let result = worker
                .open(
                    &path,
                    load_debug_info,
                    debug_info_path,
                    debug_info_verbose,
                    force,
                    file_type,
                    auto_analyse,
                    extra_args,
                )
                .await?;
            Ok(serde_json::to_value(result).unwrap_or(json!(null)))
        }
        "close" => {
            worker.close().await?;
            Ok(json!({"ok": true}))
        }
        "shutdown" => {
            worker.shutdown().await?;
            Ok(json!({"ok": true}))
        }
        "load_debug_info" => {
            let req: LoadDebugInfoRequest = parse_params(p)?;
            let path = req.path;
            let verbose = req.verbose.unwrap_or(false);
            worker.load_debug_info(path, verbose).await
        }
        "get_analysis_status" => {
            let r = worker.analysis_status().await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }

        // ── Functions ────────────────────────────────────────────────────
        "list_functions" => {
            let req: ListFunctionsRequest = parse_params(p)?;
            let offset = req.offset.unwrap_or(0);
            let limit = req.limit.unwrap_or(100);
            let filter = req.filter;
            let timeout = req.timeout_secs;
            let r = worker
                .list_functions(offset, limit, filter, timeout)
                .await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "get_function_by_name" => {
            let req: ResolveFunctionRequest = parse_params(p)?;
            let r = worker.resolve_function(&req.name).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "get_function_prototype" => {
            let addr = parse_address_value(&p["address"]);
            let name = p["name"].as_str().map(String::from);
            worker.get_function_prototype(addr, name).await
        }
        "get_function_at_address" => {
            let req: FunctionAtRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset.unwrap_or(0);
            let r = worker.function_at(addr, name, offset).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "batch_lookup_functions" => {
            let req: LookupFuncsRequest = parse_params(p)?;
            let queries = parse_string_list(&req.queries);
            worker.lookup_funcs(queries).await
        }
        "export_functions" => {
            let req: ExportFuncsRequest = parse_params(p)?;
            let offset = req.offset.unwrap_or(0);
            let limit = req.limit.unwrap_or(100);
            let r = worker.export_funcs(offset, limit).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }

        // ── Disassembly / Decompilation ──────────────────────────────────
        "disassemble" => {
            let req: DisasmRequest = parse_params(p)?;
            let addrs = parse_address_values(&req.address)?;
            let count = req.count.unwrap_or(10);
            if addrs.len() == 1 {
                let r = worker.disasm(addrs[0], count).await?;
                Ok(json!({"disasm": r}))
            } else {
                let mut results = Vec::new();
                for addr in addrs {
                    match worker.disasm(addr, count).await {
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
                Ok(json!({"results": results}))
            }
        }
        "disassemble_function" => {
            let req: DisasmByNameRequest = parse_params(p)?;
            let count = req.count.unwrap_or(10);
            let r = worker.disasm_by_name(&req.name, count).await?;
            Ok(json!({"disasm": r}))
        }
        "disassemble_function_at" => {
            let req: DisasmFunctionAtRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset.unwrap_or(0);
            let count = req.count.unwrap_or(200);
            let r = worker.disasm_function_at(addr, name, offset, count).await?;
            Ok(json!({"disasm": r}))
        }
        "decompile_function" => {
            let req: DecompileRequest = parse_params(p)?;
            let addrs = parse_address_values(&req.address)?;
            if addrs.len() == 1 {
                let r = worker.decompile(addrs[0]).await?;
                Ok(json!({"code": r}))
            } else {
                let mut results = Vec::new();
                for addr in addrs {
                    match worker.decompile(addr).await {
                        Ok(code) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "code": code
                        })),
                        Err(e) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "error": e.to_string()
                        })),
                    }
                }
                Ok(json!({"results": results}))
            }
        }
        "get_pseudocode_at" => {
            let req: PseudocodeAtRequest = parse_params(p)?;
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let end_addr = req
                .end_address
                .as_deref()
                .and_then(|s| parse_address_value(&Value::String(s.to_string())));
            worker.pseudocode_at(addr, end_addr).await
        }

        // ── Segments ─────────────────────────────────────────────────────
        "list_segments" => {
            let r = worker.segments().await?;
            Ok(serde_json::to_value(r).unwrap_or(json!([])))
        }

        // ── Strings ──────────────────────────────────────────────────────
        "list_strings" => {
            let query: Option<String> = p["query"]
                .as_str()
                .map(String::from)
                .or_else(|| p["filter"].as_str().map(String::from));
            let exact = p["exact"].as_bool().unwrap_or(false);
            let case_insensitive = p["case_insensitive"].as_bool().unwrap_or(true);
            let offset = p["offset"].as_u64().unwrap_or(0) as usize;
            let limit = p["limit"].as_u64().unwrap_or(100) as usize;
            let timeout = p["timeout_secs"].as_u64();

            if let Some(q) = query {
                let r = worker
                    .find_string(q, exact, case_insensitive, offset, limit, timeout)
                    .await?;
                Ok(serde_json::to_value(r).unwrap_or(json!(null)))
            } else {
                let r = worker.strings(offset, limit, None, timeout).await?;
                Ok(serde_json::to_value(r).unwrap_or(json!(null)))
            }
        }
        "get_xrefs_to_string" => {
            let req: XrefsToStringRequest = parse_params(p)?;
            let query = req.query;
            let exact = req.exact.unwrap_or(false);
            let case_insensitive = req.case_insensitive.unwrap_or(true);
            let offset = req.offset.unwrap_or(0);
            let limit = req.limit.unwrap_or(100);
            let max_xrefs = req.max_xrefs.unwrap_or(10);
            let timeout = req.timeout_secs;
            let r = worker
                .xrefs_to_string(
                    query,
                    exact,
                    case_insensitive,
                    offset,
                    limit,
                    max_xrefs,
                    timeout,
                )
                .await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }

        // ── Types ────────────────────────────────────────────────────────
        "list_local_types" => {
            let req: LocalTypesRequest = parse_params(p)?;
            let offset = req.offset.unwrap_or(0);
            let limit = req.limit.unwrap_or(100);
            let filter = req.filter;
            let timeout = req.timeout_secs;
            let r = worker.local_types(offset, limit, filter, timeout).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "declare_c_type" => {
            let req: DeclareTypeRequest = parse_params(p)?;
            let decl = req.decl;
            let relaxed = req.relaxed.unwrap_or(false);
            let replace = req.replace.unwrap_or(false);
            let multi = req.multi.unwrap_or(false);
            worker.declare_type(decl, relaxed, replace, multi).await
        }
        "apply_type" => {
            let req: ApplyTypesRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset.unwrap_or(0);
            let stack_offset = req.stack_offset;
            let stack_name = req.stack_name;
            let decl = req.decl;
            let type_name = req.type_name;
            let relaxed = req.relaxed.unwrap_or(false);
            let delay = req.delay.unwrap_or(false);
            let strict = req.strict.unwrap_or(false);
            worker
                .apply_types(
                    addr,
                    name,
                    offset,
                    stack_offset,
                    stack_name,
                    decl,
                    type_name,
                    relaxed,
                    delay,
                    strict,
                )
                .await
        }
        "infer_type" => {
            let req: InferTypesRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset.unwrap_or(0);
            let r = worker.infer_types(addr, name, offset).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "set_function_prototype" => {
            let req: SetFunctionPrototypeRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            worker
                .set_function_prototype(addr, req.name, req.prototype)
                .await
        }
        "rename_stack_variable" => {
            let req: RenameStackVariableRequest = parse_params(p)?;
            let addr = req.func_address.as_ref().and_then(parse_address_value);
            worker
                .rename_stack_variable(addr, req.func_name, req.name, req.new_name)
                .await
        }
        "set_stack_variable_type" => {
            let req: SetStackVariableTypeRequest = parse_params(p)?;
            let addr = req.func_address.as_ref().and_then(parse_address_value);
            worker
                .set_stack_variable_type(addr, req.func_name, req.name, req.type_decl)
                .await
        }
        "list_enums" => {
            let req: ListEnumsRequest = parse_params(p)?;
            let offset = req.offset.unwrap_or(0);
            let limit = req.limit.unwrap_or(100);
            worker.list_enums(req.filter, offset, limit).await
        }
        "create_enum" => {
            let req: CreateEnumRequest = parse_params(p)?;
            let replace = req.replace.unwrap_or(false);
            worker.create_enum(req.decl, replace).await
        }

        // ── Address info ─────────────────────────────────────────────────
        "get_address_info" => {
            let req: AddrInfoRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset.unwrap_or(0);
            let r = worker.addr_info(addr, name, offset).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }

        // ── Stack ────────────────────────────────────────────────────────
        "create_stack_variable" => {
            let req: DeclareStackRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset;
            let var_name = req.var_name;
            let decl = req.decl;
            let relaxed = req.relaxed.unwrap_or(false);
            let r = worker
                .declare_stack(addr, name, offset, var_name, decl, relaxed)
                .await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "delete_stack_variable" => {
            let req: DeleteStackRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset;
            let var_name = req.var_name;
            let r = worker.delete_stack(addr, name, offset, var_name).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "get_stack_frame" => {
            let req: AddressRequest = parse_params(p)?;
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let r = worker.stack_frame(addr).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }

        // ── Structs ──────────────────────────────────────────────────────
        "list_structs" => {
            let req: StructsRequest = parse_params(p)?;
            let offset = req.offset.unwrap_or(0);
            let limit = req.limit.unwrap_or(100);
            let filter = req.filter;
            let timeout = req.timeout_secs;
            let r = worker.structs(offset, limit, filter, timeout).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "get_struct_info" => {
            let req: StructInfoRequest = parse_params(p)?;
            let ordinal = req.ordinal;
            let name = req.name;
            let r = worker.struct_info(ordinal, name).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "read_struct_at_address" => {
            let req: ReadStructRequest = parse_params(p)?;
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let ordinal = req.ordinal;
            let name = req.name;
            let r = worker.read_struct(addr, ordinal, name).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }

        // ── Cross-references ─────────────────────────────────────────────
        "get_xrefs_to" => {
            let req: AddressRequest = parse_params(p)?;
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let r = worker.xrefs_to(addr).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!([])))
        }
        "get_xrefs_from" => {
            let req: AddressRequest = parse_params(p)?;
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let r = worker.xrefs_from(addr).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!([])))
        }
        "get_xrefs_to_struct_field" => {
            let req: XrefsToFieldRequest = parse_params(p)?;
            let ordinal = req.ordinal;
            let name = req.name;
            let member_index = req.member_index;
            let member_name = req.member_name;
            let limit = req.limit.unwrap_or(100);
            let r = worker
                .xrefs_to_field(ordinal, name, member_index, member_name, limit)
                .await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }

        // ── Imports / Exports / Entrypoints ──────────────────────────────
        "list_imports" => {
            let req: PaginatedRequest = parse_params(p)?;
            let offset = req.offset.unwrap_or(0);
            let limit = req.limit.unwrap_or(100);
            let r = worker.imports(offset, limit).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!([])))
        }
        "list_exports" => {
            let req: PaginatedRequest = parse_params(p)?;
            let offset = req.offset.unwrap_or(0);
            let limit = req.limit.unwrap_or(100);
            let r = worker.exports(offset, limit).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!([])))
        }
        "list_entry_points" => {
            let r = worker.entrypoints().await?;
            Ok(serde_json::to_value(r).unwrap_or(json!([])))
        }

        // ── Memory ───────────────────────────────────────────────────────
        "read_bytes" => {
            let req: GetBytesRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset.unwrap_or(0);
            let size = req.size.unwrap_or(16);
            let r = worker.get_bytes(addr, name, offset, size).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!(null)))
        }
        "read_int" => {
            let addr = parse_address_value(&p["address"])
                .or_else(|| parse_address_value(&p["addr"]))
                .unwrap_or(0);
            let size = p["size"].as_u64().unwrap_or(4) as usize;
            worker.read_int(addr, size).await
        }
        "read_string" => {
            let req: GetStringRequest = parse_params(p)?;
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let max_len = req.max_len.unwrap_or(1024);
            worker.get_string(addr, max_len).await
        }
        "read_global_variable" => {
            let req: GetGlobalValueRequest = parse_params(p)?;
            let query = match req.query {
                Value::String(s) => s,
                other => serde_json::to_string(&other)
                    .map_err(|e| ToolError::InvalidParams(format!("invalid query: {e}")))?,
            };
            worker.get_global_value(query).await
        }

        // ── Annotations ──────────────────────────────────────────────────
        "set_comment" => {
            let req: SetCommentsRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset.unwrap_or(0);
            let comment = req.comment;
            let repeatable = req.repeatable.unwrap_or(false);
            worker
                .set_comments(addr, name, offset, comment, repeatable)
                .await
        }
        "set_function_comment" => {
            let req: SetFunctionCommentRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let repeatable = req.repeatable.unwrap_or(false);
            worker
                .set_function_comment(addr, req.name, req.comment, repeatable)
                .await
        }
        "rename_symbol" => {
            let req: RenameRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let current_name = req.current_name;
            let new_name = req.name;
            let flags = req.flags.unwrap_or(0);
            worker.rename(addr, current_name, new_name, flags).await
        }
        "batch_rename" => {
            let req: BatchRenameRequest = parse_params(p)?;
            let entries: Vec<(Option<u64>, Option<String>, String)> = req
                .renames
                .iter()
                .map(|e| {
                    let addr = e.address.as_ref().and_then(parse_address_value);
                    (addr, e.current_name.clone(), e.new_name.clone())
                })
                .collect();
            worker.batch_rename(entries).await
        }

        "rename_local_variable" => {
            let req: RenameLvarRequest = parse_params(p)?;
            let func_addr = parse_address_value(&req.func_address).unwrap_or(0);
            worker
                .rename_lvar(func_addr, req.lvar_name, req.new_name)
                .await
        }

        "set_local_variable_type" => {
            let req: SetLvarTypeRequest = parse_params(p)?;
            let func_addr = parse_address_value(&req.func_address).unwrap_or(0);
            worker
                .set_lvar_type(func_addr, req.lvar_name, req.type_str)
                .await
        }

        "set_decompiler_comment" => {
            let req: SetDecompilerCommentRequest = parse_params(p)?;
            let func_addr = parse_address_value(&req.func_address).unwrap_or(0);
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let itp = req.itp.unwrap_or(69);
            worker
                .set_decompiler_comment(func_addr, addr, itp, req.comment)
                .await
        }

        // ── Patching ─────────────────────────────────────────────────────
        "patch_bytes" => {
            let req: PatchRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset.unwrap_or(0);
            let bytes = parse_patch_bytes(&req.bytes);
            worker.patch_bytes(addr, name, offset, bytes).await
        }
        "patch_assembly" => {
            let req: PatchAsmRequest = parse_params(p)?;
            let addr = req.address.as_ref().and_then(parse_address_value);
            let name = req.target_name;
            let offset = req.offset.unwrap_or(0);
            let line = req.line;
            worker.patch_asm(addr, name, offset, line).await
        }

        // ── Control / Call flow ──────────────────────────────────────────
        "get_basic_blocks" => {
            let req: AddressRequest = parse_params(p)?;
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let r = worker.basic_blocks(addr).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!([])))
        }
        "get_callees" => {
            let req: AddressRequest = parse_params(p)?;
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let r = worker.callees(addr).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!([])))
        }
        "get_callers" => {
            let req: AddressRequest = parse_params(p)?;
            let addr = parse_address_value(&req.address).unwrap_or(0);
            let r = worker.callers(addr).await?;
            Ok(serde_json::to_value(r).unwrap_or(json!([])))
        }
        "build_callgraph" => {
            let req: CallGraphRequest = parse_params(p)?;
            let addr = req
                .roots
                .as_array()
                .and_then(|roots| roots.first())
                .and_then(parse_address_value)
                .or_else(|| parse_address_value(&req.roots))
                .unwrap_or(0);
            let max_depth = req.max_depth.unwrap_or(5);
            let max_nodes = req.max_nodes.unwrap_or(100);
            worker.callgraph(addr, max_depth, max_nodes).await
        }
        "find_control_flow_paths" => {
            let req: FindPathsRequest = parse_params(p)?;
            let start = parse_address_value(&req.start).unwrap_or(0);
            let end = parse_address_value(&req.end).unwrap_or(0);
            let max_paths = req.max_paths.unwrap_or(10);
            let max_depth = req.max_depth.unwrap_or(10);
            worker.find_paths(start, end, max_paths, max_depth).await
        }
        "build_xref_matrix" => {
            let req: XrefMatrixRequest = parse_params(p)?;
            let addrs = req
                .addrs
                .as_array()
                .map(|a| a.iter().filter_map(parse_address_value).collect())
                .unwrap_or_default();
            worker.xref_matrix(addrs).await
        }

        // ── Metadata ─────────────────────────────────────────────────────
        "get_database_info" => worker.idb_meta().await,

        // ── Globals ──────────────────────────────────────────────────────
        "list_globals" => {
            let req: ListGlobalsRequest = parse_params(p)?;
            let query = req.query;
            let offset = req.offset.unwrap_or(0);
            let limit = req.limit.unwrap_or(100);
            let timeout = req.timeout_secs;
            worker.list_globals(query, offset, limit, timeout).await
        }

        // ── Analysis ─────────────────────────────────────────────────────
        "run_auto_analysis" => {
            let req: AnalyzeFuncsRequest = parse_params(p)?;
            let timeout = req.timeout_secs;
            worker.analyze_funcs(timeout).await
        }

        // ── Search ───────────────────────────────────────────────────────
        "search_bytes" => {
            let req: FindBytesRequest = parse_params(p)?;
            let patterns: Vec<String> = if let Some(arr) = req.patterns.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            } else if let Some(s) = req.patterns.as_str() {
                // Check if it's a JSON array string
                if s.trim().starts_with('[') {
                    if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(s) {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    } else {
                        vec![s.to_string()]
                    }
                } else {
                    vec![s.to_string()]
                }
            } else {
                vec![]
            };
            let max_results = req.limit.unwrap_or(100);
            let timeout = req.timeout_secs;

            // Process each pattern and merge results
            if patterns.len() == 1 {
                // Single pattern: return result directly
                worker
                    .find_bytes(patterns.into_iter().next().unwrap(), max_results, timeout)
                    .await
            } else if patterns.is_empty() {
                Ok(json!({"matches": [], "count": 0}))
            } else {
                // Multiple patterns: merge matches
                let mut all_matches = Vec::new();
                for pattern in patterns {
                    if let Ok(result) = worker.find_bytes(pattern, max_results, timeout).await {
                        if let Some(matches) = result.get("matches").and_then(|m| m.as_array()) {
                            all_matches.extend(matches.clone());
                        }
                    }
                }
                let count = all_matches.len();
                Ok(json!({"matches": all_matches, "count": count}))
            }
        }
        "search_text" => {
            let text = p["text"].as_str().unwrap_or("").to_string();
            let max_results = p["max_results"].as_u64().unwrap_or(100) as usize;
            let timeout = p["timeout_secs"].as_u64();
            worker.search_text(text, max_results, timeout).await
        }
        "search_imm" => {
            let imm = p["imm"].as_u64().unwrap_or(0);
            let max_results = p["max_results"].as_u64().unwrap_or(100) as usize;
            let timeout = p["timeout_secs"].as_u64();
            worker.search_imm(imm, max_results, timeout).await
        }
        "search_instructions" => {
            let req: FindInsnsRequest = parse_params(p)?;
            let patterns: Vec<String> = if let Some(arr) = req.patterns.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            } else if let Some(s) = req.patterns.as_str() {
                if s.trim().starts_with('[') {
                    if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(s) {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    } else {
                        vec![s.to_string()]
                    }
                } else {
                    vec![s.to_string()]
                }
            } else {
                vec![]
            };
            let max_results = req.limit.unwrap_or(100);
            let case_insensitive = req.case_insensitive.unwrap_or(true);
            let timeout = req.timeout_secs;
            worker
                .find_insns(patterns, max_results, case_insensitive, timeout)
                .await
        }
        "search_instruction_operands" => {
            let req: FindInsnOperandsRequest = parse_params(p)?;
            let patterns: Vec<String> = if let Some(arr) = req.patterns.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            } else if let Some(s) = req.patterns.as_str() {
                if s.trim().starts_with('[') {
                    if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(s) {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    } else {
                        vec![s.to_string()]
                    }
                } else {
                    vec![s.to_string()]
                }
            } else {
                vec![]
            };
            let max_results = req.limit.unwrap_or(100);
            let case_insensitive = req.case_insensitive.unwrap_or(true);
            let timeout = req.timeout_secs;
            worker
                .find_insn_operands(patterns, max_results, case_insensitive, timeout)
                .await
        }

        // ── IDAPython script ─────────────────────────────────────────────
        "run_script" => {
            let req: RunScriptRequest = parse_params(p)?;
            let code = req.code.unwrap_or_default();
            let timeout = req.timeout_secs;
            worker.run_script(&code, timeout).await
        }

        "batch_decompile" => {
            let req: BatchDecompileRequest = parse_params(p)?;
            let addrs: Vec<Value> = if let Some(arr) = req.addresses.as_array() {
                arr.clone()
            } else if let Some(s) = req.addresses.as_str() {
                serde_json::from_str(s).unwrap_or_else(|_| vec![req.addresses.clone()])
            } else {
                vec![req.addresses.clone()]
            };

            let mut results = Vec::new();
            for addr_val in &addrs {
                let addr = match crate::rpc_dispatch::parse_address_value(addr_val) {
                    Some(a) => a,
                    None => {
                        results.push(json!({
                            "address": addr_val,
                            "error": "invalid address",
                            "success": false,
                        }));
                        continue;
                    }
                };

                match worker.decompile(addr).await {
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
            Ok(json!(results))
        }

        "search_pseudocode" => {
            let req: SearchPseudocodeRequest = parse_params(p)?;
            let pattern = req.pattern;
            let limit = req.limit.unwrap_or(20).min(100);
            let timeout = req.timeout_secs;

            let funcs = worker.list_functions(0, 10000, None, timeout).await?;
            let mut matches = Vec::new();
            for func in &funcs.functions {
                if matches.len() >= limit {
                    break;
                }
                let addr =
                    u64::from_str_radix(func.address.trim_start_matches("0x"), 16).unwrap_or(0);
                if let Ok(result) = worker.decompile(addr).await {
                    if result.contains(&pattern) {
                        matches.push(json!({
                            "address": func.address,
                            "name": func.name,
                            "pseudocode": result,
                        }));
                    }
                }
            }
            Ok(json!({
                "pattern": pattern,
                "matches": matches,
                "total_searched": funcs.functions.len(),
            }))
        }

        "scan_memory_table" => {
            let req: TableScanRequest = parse_params(p)?;
            let base_addr = crate::rpc_dispatch::parse_address_value(&req.base_address)
                .ok_or_else(|| ToolError::InvalidParams("base_address is required".to_string()))?;
            let stride = req.stride.unwrap_or(8).max(1);
            let count = req.count.unwrap_or(16).min(256);

            let mut entries = Vec::new();
            for i in 0..count {
                let offset = (i as u64) * stride;
                let addr = base_addr + offset;
                match worker.get_bytes(Some(addr), None, 0, stride as usize).await {
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
            Ok(json!({
                "base_address": format!("0x{:x}", base_addr),
                "stride": stride,
                "count": entries.len(),
                "entries": entries,
            }))
        }

        "diff_pseudocode" => {
            let req: DiffFunctionsRequest = parse_params(p)?;
            let addr1 = crate::rpc_dispatch::parse_address_value(&req.addr1)
                .ok_or_else(|| ToolError::InvalidParams("addr1 is required".to_string()))?;
            let addr2 = crate::rpc_dispatch::parse_address_value(&req.addr2)
                .ok_or_else(|| ToolError::InvalidParams("addr2 is required".to_string()))?;

            let result1 = worker.decompile(addr1).await?;
            let result2 = worker.decompile(addr2).await?;

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

            Ok(json!({
                "function1": result1,
                "function2": result2,
                "similarity_ratio": (similarity * 100.0).round() / 100.0,
                "diff_lines": diff_lines,
            }))
        }

        // ── Unknown method ───────────────────────────────────────────────
        _ => Err(ToolError::InvalidToolName(format!(
            "Unknown method: {}",
            req.method
        ))),
    }
}

#[cfg(test)]
pub mod mock {
    use crate::error::ToolError;
    use crate::ida::types::*;
    use crate::ida::worker_trait::WorkerDispatch;
    use serde_json::{json, Value};
    use std::sync::Mutex;

    /// A test-only worker that records every call and returns default values.
    ///
    /// Each invocation pushes `(method_name, json!({params}))` into `self.calls`.
    pub struct MockWorker {
        pub calls: Mutex<Vec<(String, Value)>>,
    }

    impl MockWorker {
        pub fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }

        fn record(&self, method: &str, params: Value) {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), params));
        }
    }

    impl Default for MockWorker {
        fn default() -> Self {
            Self::new()
        }
    }

    // Helper: construct default return values for IDA types that don't derive Default.

    fn default_db_info() -> DbInfo {
        DbInfo {
            path: String::new(),
            file_type: String::new(),
            processor: String::new(),
            bits: 0,
            function_count: 0,
            debug_info: None,
            analysis_status: default_analysis_status(),
        }
    }

    fn default_analysis_status() -> AnalysisStatus {
        AnalysisStatus {
            auto_enabled: false,
            auto_is_ok: true,
            auto_state: String::new(),
            auto_state_id: 0,
            analysis_running: false,
        }
    }

    fn default_function_list() -> FunctionListResult {
        FunctionListResult {
            functions: vec![],
            total: 0,
            next_offset: None,
        }
    }

    fn default_function_info() -> FunctionInfo {
        FunctionInfo {
            address: String::new(),
            name: String::new(),
            size: 0,
        }
    }

    fn default_function_range() -> FunctionRangeInfo {
        FunctionRangeInfo {
            address: String::new(),
            name: String::new(),
            start: String::new(),
            end: String::new(),
            size: 0,
        }
    }

    fn default_string_list() -> StringListResult {
        StringListResult {
            strings: vec![],
            total: 0,
            next_offset: None,
        }
    }

    fn default_string_xrefs() -> StringXrefsResult {
        StringXrefsResult {
            strings: vec![],
            total: 0,
            next_offset: None,
        }
    }

    fn default_local_type_list() -> LocalTypeListResult {
        LocalTypeListResult {
            types: vec![],
            total: 0,
            next_offset: None,
        }
    }

    fn default_guess_type() -> GuessTypeResult {
        GuessTypeResult {
            address: String::new(),
            code: 0,
            status: String::new(),
            decl: String::new(),
            kind: String::new(),
        }
    }

    fn default_address_info() -> AddressInfo {
        AddressInfo {
            address: String::new(),
            segment: None,
            function: None,
            symbol: None,
        }
    }

    fn default_stack_var() -> StackVarResult {
        StackVarResult {
            function: String::new(),
            name: String::new(),
            offset: 0,
            code: 0,
            status: String::new(),
        }
    }

    fn default_frame_info() -> FrameInfo {
        FrameInfo {
            address: String::new(),
            frame_size: 0,
            ret_size: 0,
            frsize: 0,
            frregs: 0,
            argsize: 0,
            fpd: 0,
            args_range: FrameRange {
                start: String::new(),
                end: String::new(),
            },
            retaddr_range: FrameRange {
                start: String::new(),
                end: String::new(),
            },
            savregs_range: FrameRange {
                start: String::new(),
                end: String::new(),
            },
            locals_range: FrameRange {
                start: String::new(),
                end: String::new(),
            },
            member_count: 0,
            members: vec![],
        }
    }

    fn default_struct_list() -> StructListResult {
        StructListResult {
            structs: vec![],
            total: 0,
            next_offset: None,
        }
    }

    fn default_struct_info() -> StructInfo {
        StructInfo {
            ordinal: 0,
            name: String::new(),
            size: 0,
            is_union: false,
            member_count: 0,
            members: vec![],
        }
    }

    fn default_struct_read() -> StructReadResult {
        StructReadResult {
            address: String::new(),
            ordinal: 0,
            name: String::new(),
            size: 0,
            members: vec![],
        }
    }

    fn default_xrefs_to_field() -> XrefsToFieldResult {
        XrefsToFieldResult {
            struct_ordinal: 0,
            struct_name: String::new(),
            member_index: 0,
            member_name: String::new(),
            member_type: String::new(),
            member_offset_bits: 0,
            member_size_bits: 0,
            tid: String::new(),
            xrefs: vec![],
            truncated: false,
        }
    }

    fn default_bytes() -> BytesResult {
        BytesResult {
            address: String::new(),
            bytes: String::new(),
            length: 0,
        }
    }

    impl WorkerDispatch for MockWorker {
        async fn open(
            &self,
            path: &str,
            load_debug_info: bool,
            debug_info_path: Option<String>,
            debug_info_verbose: bool,
            force: bool,
            file_type: Option<String>,
            auto_analyse: bool,
            extra_args: Vec<String>,
        ) -> Result<DbInfo, ToolError> {
            self.record(
                "open",
                json!({
                    "path": path,
                    "load_debug_info": load_debug_info,
                    "debug_info_path": debug_info_path,
                    "debug_info_verbose": debug_info_verbose,
                    "force": force,
                    "file_type": file_type,
                    "auto_analyse": auto_analyse,
                    "extra_args": extra_args,
                }),
            );
            Ok(default_db_info())
        }

        async fn close(&self) -> Result<(), ToolError> {
            self.record("close", json!({}));
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), ToolError> {
            self.record("shutdown", json!({}));
            Ok(())
        }

        async fn load_debug_info(
            &self,
            path: Option<String>,
            verbose: bool,
        ) -> Result<Value, ToolError> {
            self.record("load_debug_info", json!({"path": path, "verbose": verbose}));
            Ok(json!({}))
        }

        async fn analysis_status(&self) -> Result<AnalysisStatus, ToolError> {
            self.record("analysis_status", json!({}));
            Ok(default_analysis_status())
        }

        async fn list_functions(
            &self,
            offset: usize,
            limit: usize,
            filter: Option<String>,
            timeout_secs: Option<u64>,
        ) -> Result<FunctionListResult, ToolError> {
            self.record("list_functions", json!({
                "offset": offset, "limit": limit, "filter": filter, "timeout_secs": timeout_secs,
            }));
            Ok(default_function_list())
        }

        async fn resolve_function(&self, name: &str) -> Result<FunctionInfo, ToolError> {
            self.record("resolve_function", json!({"name": name}));
            Ok(default_function_info())
        }

        async fn get_function_prototype(
            &self,
            addr: Option<u64>,
            name: Option<String>,
        ) -> Result<Value, ToolError> {
            self.record(
                "get_function_prototype",
                json!({"addr": addr, "name": name}),
            );
            Ok(json!({}))
        }

        async fn function_at(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: u64,
        ) -> Result<FunctionRangeInfo, ToolError> {
            self.record(
                "function_at",
                json!({"addr": addr, "name": name, "offset": offset}),
            );
            Ok(default_function_range())
        }

        async fn lookup_funcs(&self, queries: Vec<String>) -> Result<Value, ToolError> {
            self.record("lookup_funcs", json!({"queries": queries}));
            Ok(json!({}))
        }

        async fn export_funcs(
            &self,
            offset: usize,
            limit: usize,
        ) -> Result<FunctionListResult, ToolError> {
            self.record("export_funcs", json!({"offset": offset, "limit": limit}));
            Ok(default_function_list())
        }

        async fn disasm(&self, addr: u64, count: usize) -> Result<String, ToolError> {
            self.record("disasm", json!({"addr": addr, "count": count}));
            Ok(String::new())
        }

        async fn disasm_by_name(&self, name: &str, count: usize) -> Result<String, ToolError> {
            self.record("disasm_by_name", json!({"name": name, "count": count}));
            Ok(String::new())
        }

        async fn disasm_function_at(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: u64,
            count: usize,
        ) -> Result<String, ToolError> {
            self.record(
                "disasm_function_at",
                json!({
                    "addr": addr, "name": name, "offset": offset, "count": count,
                }),
            );
            Ok(String::new())
        }

        async fn decompile(&self, addr: u64) -> Result<String, ToolError> {
            self.record("decompile", json!({"addr": addr}));
            Ok(String::new())
        }

        async fn pseudocode_at(
            &self,
            addr: u64,
            end_addr: Option<u64>,
        ) -> Result<Value, ToolError> {
            self.record("pseudocode_at", json!({"addr": addr, "end_addr": end_addr}));
            Ok(json!({}))
        }

        async fn segments(&self) -> Result<Vec<SegmentInfo>, ToolError> {
            self.record("segments", json!({}));
            Ok(vec![])
        }

        async fn strings(
            &self,
            offset: usize,
            limit: usize,
            filter: Option<String>,
            timeout_secs: Option<u64>,
        ) -> Result<StringListResult, ToolError> {
            self.record("strings", json!({
                "offset": offset, "limit": limit, "filter": filter, "timeout_secs": timeout_secs,
            }));
            Ok(default_string_list())
        }

        async fn find_string(
            &self,
            query: String,
            exact: bool,
            case_insensitive: bool,
            offset: usize,
            limit: usize,
            timeout_secs: Option<u64>,
        ) -> Result<StringListResult, ToolError> {
            self.record(
                "find_string",
                json!({
                    "query": query, "exact": exact, "case_insensitive": case_insensitive,
                    "offset": offset, "limit": limit, "timeout_secs": timeout_secs,
                }),
            );
            Ok(default_string_list())
        }

        async fn analyze_strings(
            &self,
            query: Option<String>,
            offset: usize,
            limit: usize,
            timeout_secs: Option<u64>,
        ) -> Result<Value, ToolError> {
            self.record(
                "analyze_strings",
                json!({
                    "query": query, "offset": offset, "limit": limit, "timeout_secs": timeout_secs,
                }),
            );
            Ok(json!({}))
        }

        async fn xrefs_to_string(
            &self,
            query: String,
            exact: bool,
            case_insensitive: bool,
            offset: usize,
            limit: usize,
            max_xrefs: usize,
            timeout_secs: Option<u64>,
        ) -> Result<StringXrefsResult, ToolError> {
            self.record(
                "xrefs_to_string",
                json!({
                    "query": query, "exact": exact, "case_insensitive": case_insensitive,
                    "offset": offset, "limit": limit, "max_xrefs": max_xrefs,
                    "timeout_secs": timeout_secs,
                }),
            );
            Ok(default_string_xrefs())
        }

        async fn local_types(
            &self,
            offset: usize,
            limit: usize,
            filter: Option<String>,
            timeout_secs: Option<u64>,
        ) -> Result<LocalTypeListResult, ToolError> {
            self.record("local_types", json!({
                "offset": offset, "limit": limit, "filter": filter, "timeout_secs": timeout_secs,
            }));
            Ok(default_local_type_list())
        }

        async fn declare_type(
            &self,
            decl: String,
            relaxed: bool,
            replace: bool,
            multi: bool,
        ) -> Result<Value, ToolError> {
            self.record(
                "declare_type",
                json!({
                    "decl": decl, "relaxed": relaxed, "replace": replace, "multi": multi,
                }),
            );
            Ok(json!({}))
        }

        async fn apply_types(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: u64,
            stack_offset: Option<i64>,
            stack_name: Option<String>,
            decl: Option<String>,
            type_name: Option<String>,
            relaxed: bool,
            delay: bool,
            strict: bool,
        ) -> Result<Value, ToolError> {
            self.record(
                "apply_types",
                json!({
                    "addr": addr, "name": name, "offset": offset,
                    "stack_offset": stack_offset, "stack_name": stack_name,
                    "decl": decl, "type_name": type_name,
                    "relaxed": relaxed, "delay": delay, "strict": strict,
                }),
            );
            Ok(json!({}))
        }

        async fn infer_types(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: u64,
        ) -> Result<GuessTypeResult, ToolError> {
            self.record(
                "infer_types",
                json!({"addr": addr, "name": name, "offset": offset}),
            );
            Ok(default_guess_type())
        }

        async fn set_function_prototype(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            prototype: String,
        ) -> Result<Value, ToolError> {
            self.record(
                "set_function_prototype",
                json!({"addr": addr, "name": name, "prototype": prototype}),
            );
            Ok(json!({}))
        }

        async fn list_enums(
            &self,
            filter: Option<String>,
            offset: usize,
            limit: usize,
        ) -> Result<Value, ToolError> {
            self.record(
                "list_enums",
                json!({"filter": filter, "offset": offset, "limit": limit}),
            );
            Ok(json!({}))
        }

        async fn create_enum(&self, decl: String, replace: bool) -> Result<Value, ToolError> {
            self.record("create_enum", json!({"decl": decl, "replace": replace}));
            Ok(json!({}))
        }

        async fn addr_info(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: u64,
        ) -> Result<AddressInfo, ToolError> {
            self.record(
                "addr_info",
                json!({"addr": addr, "name": name, "offset": offset}),
            );
            Ok(default_address_info())
        }

        async fn declare_stack(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: i64,
            var_name: Option<String>,
            decl: String,
            relaxed: bool,
        ) -> Result<StackVarResult, ToolError> {
            self.record(
                "declare_stack",
                json!({
                    "addr": addr, "name": name, "offset": offset,
                    "var_name": var_name, "decl": decl, "relaxed": relaxed,
                }),
            );
            Ok(default_stack_var())
        }

        async fn delete_stack(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: Option<i64>,
            var_name: Option<String>,
        ) -> Result<StackVarResult, ToolError> {
            self.record(
                "delete_stack",
                json!({
                    "addr": addr, "name": name, "offset": offset, "var_name": var_name,
                }),
            );
            Ok(default_stack_var())
        }

        async fn stack_frame(&self, addr: u64) -> Result<FrameInfo, ToolError> {
            self.record("stack_frame", json!({"addr": addr}));
            Ok(default_frame_info())
        }

        async fn rename_stack_variable(
            &self,
            func_addr: Option<u64>,
            func_name: Option<String>,
            old_name: String,
            new_name: String,
        ) -> Result<Value, ToolError> {
            self.record(
                "rename_stack_variable",
                json!({
                    "func_addr": func_addr,
                    "func_name": func_name,
                    "old_name": old_name,
                    "new_name": new_name,
                }),
            );
            Ok(json!({}))
        }

        async fn set_stack_variable_type(
            &self,
            func_addr: Option<u64>,
            func_name: Option<String>,
            var_name: String,
            type_decl: String,
        ) -> Result<Value, ToolError> {
            self.record(
                "set_stack_variable_type",
                json!({
                    "func_addr": func_addr,
                    "func_name": func_name,
                    "var_name": var_name,
                    "type_decl": type_decl,
                }),
            );
            Ok(json!({}))
        }

        async fn structs(
            &self,
            offset: usize,
            limit: usize,
            filter: Option<String>,
            timeout_secs: Option<u64>,
        ) -> Result<StructListResult, ToolError> {
            self.record("structs", json!({
                "offset": offset, "limit": limit, "filter": filter, "timeout_secs": timeout_secs,
            }));
            Ok(default_struct_list())
        }

        async fn struct_info(
            &self,
            ordinal: Option<u32>,
            name: Option<String>,
        ) -> Result<StructInfo, ToolError> {
            self.record("struct_info", json!({"ordinal": ordinal, "name": name}));
            Ok(default_struct_info())
        }

        async fn read_struct(
            &self,
            addr: u64,
            ordinal: Option<u32>,
            name: Option<String>,
        ) -> Result<StructReadResult, ToolError> {
            self.record(
                "read_struct",
                json!({"addr": addr, "ordinal": ordinal, "name": name}),
            );
            Ok(default_struct_read())
        }

        async fn xrefs_to(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
            self.record("xrefs_to", json!({"addr": addr}));
            Ok(vec![])
        }

        async fn xrefs_from(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
            self.record("xrefs_from", json!({"addr": addr}));
            Ok(vec![])
        }

        async fn xrefs_to_field(
            &self,
            ordinal: Option<u32>,
            name: Option<String>,
            member_index: Option<u32>,
            member_name: Option<String>,
            limit: usize,
        ) -> Result<XrefsToFieldResult, ToolError> {
            self.record(
                "xrefs_to_field",
                json!({
                    "ordinal": ordinal, "name": name,
                    "member_index": member_index, "member_name": member_name, "limit": limit,
                }),
            );
            Ok(default_xrefs_to_field())
        }

        async fn imports(&self, offset: usize, limit: usize) -> Result<Vec<ImportInfo>, ToolError> {
            self.record("imports", json!({"offset": offset, "limit": limit}));
            Ok(vec![])
        }

        async fn exports(&self, offset: usize, limit: usize) -> Result<Vec<ExportInfo>, ToolError> {
            self.record("exports", json!({"offset": offset, "limit": limit}));
            Ok(vec![])
        }

        async fn entrypoints(&self) -> Result<Vec<String>, ToolError> {
            self.record("entrypoints", json!({}));
            Ok(vec![])
        }

        async fn get_bytes(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: u64,
            size: usize,
        ) -> Result<BytesResult, ToolError> {
            self.record(
                "get_bytes",
                json!({
                    "addr": addr, "name": name, "offset": offset, "size": size,
                }),
            );
            Ok(default_bytes())
        }

        async fn read_int(&self, addr: u64, size: usize) -> Result<Value, ToolError> {
            self.record("read_int", json!({"addr": addr, "size": size}));
            Ok(json!({}))
        }

        async fn get_string(&self, addr: u64, max_len: usize) -> Result<Value, ToolError> {
            self.record("get_string", json!({"addr": addr, "max_len": max_len}));
            Ok(json!({}))
        }

        async fn get_global_value(&self, query: String) -> Result<Value, ToolError> {
            self.record("get_global_value", json!({"query": query}));
            Ok(json!({}))
        }

        async fn set_comments(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: u64,
            comment: String,
            repeatable: bool,
        ) -> Result<Value, ToolError> {
            self.record(
                "set_comments",
                json!({
                    "addr": addr, "name": name, "offset": offset,
                    "comment": comment, "repeatable": repeatable,
                }),
            );
            Ok(json!({}))
        }

        async fn set_function_comment(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            comment: String,
            repeatable: bool,
        ) -> Result<Value, ToolError> {
            self.record(
                "set_function_comment",
                json!({
                    "addr": addr,
                    "name": name,
                    "comment": comment,
                    "repeatable": repeatable,
                }),
            );
            Ok(json!({}))
        }

        async fn rename(
            &self,
            addr: Option<u64>,
            current_name: Option<String>,
            new_name: String,
            flags: i32,
        ) -> Result<Value, ToolError> {
            self.record("rename", json!({
                "addr": addr, "current_name": current_name, "new_name": new_name, "flags": flags,
            }));
            Ok(json!({}))
        }

        async fn batch_rename(
            &self,
            entries: Vec<(Option<u64>, Option<String>, String)>,
        ) -> Result<Value, ToolError> {
            self.record("batch_rename", json!({"entries": entries}));
            Ok(json!({}))
        }

        async fn rename_lvar(
            &self,
            func_addr: u64,
            lvar_name: String,
            new_name: String,
        ) -> Result<Value, ToolError> {
            self.record(
                "rename_lvar",
                json!({
                    "func_addr": func_addr, "lvar_name": lvar_name, "new_name": new_name,
                }),
            );
            Ok(json!({}))
        }

        async fn set_lvar_type(
            &self,
            func_addr: u64,
            lvar_name: String,
            type_str: String,
        ) -> Result<Value, ToolError> {
            self.record(
                "set_lvar_type",
                json!({
                    "func_addr": func_addr, "lvar_name": lvar_name, "type_str": type_str,
                }),
            );
            Ok(json!({}))
        }

        async fn set_decompiler_comment(
            &self,
            func_addr: u64,
            addr: u64,
            itp: i32,
            comment: String,
        ) -> Result<Value, ToolError> {
            self.record(
                "set_decompiler_comment",
                json!({
                    "func_addr": func_addr, "addr": addr, "itp": itp, "comment": comment,
                }),
            );
            Ok(json!({}))
        }

        async fn patch_bytes(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: u64,
            bytes: Vec<u8>,
        ) -> Result<Value, ToolError> {
            self.record(
                "patch_bytes",
                json!({
                    "addr": addr, "name": name, "offset": offset, "bytes": bytes,
                }),
            );
            Ok(json!({}))
        }

        async fn patch_asm(
            &self,
            addr: Option<u64>,
            name: Option<String>,
            offset: u64,
            line: String,
        ) -> Result<Value, ToolError> {
            self.record(
                "patch_asm",
                json!({
                    "addr": addr, "name": name, "offset": offset, "line": line,
                }),
            );
            Ok(json!({}))
        }

        async fn basic_blocks(&self, addr: u64) -> Result<Vec<BasicBlockInfo>, ToolError> {
            self.record("basic_blocks", json!({"addr": addr}));
            Ok(vec![])
        }

        async fn callees(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
            self.record("callees", json!({"addr": addr}));
            Ok(vec![])
        }

        async fn callers(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
            self.record("callers", json!({"addr": addr}));
            Ok(vec![])
        }

        async fn callgraph(
            &self,
            addr: u64,
            max_depth: usize,
            max_nodes: usize,
        ) -> Result<Value, ToolError> {
            self.record(
                "callgraph",
                json!({
                    "addr": addr, "max_depth": max_depth, "max_nodes": max_nodes,
                }),
            );
            Ok(json!({}))
        }

        async fn find_paths(
            &self,
            start: u64,
            end: u64,
            max_paths: usize,
            max_depth: usize,
        ) -> Result<Value, ToolError> {
            self.record(
                "find_paths",
                json!({
                    "start": start, "end": end, "max_paths": max_paths, "max_depth": max_depth,
                }),
            );
            Ok(json!({}))
        }

        async fn xref_matrix(&self, addrs: Vec<u64>) -> Result<Value, ToolError> {
            self.record("xref_matrix", json!({"addrs": addrs}));
            Ok(json!({}))
        }

        async fn idb_meta(&self) -> Result<Value, ToolError> {
            self.record("idb_meta", json!({}));
            Ok(json!({}))
        }

        async fn list_globals(
            &self,
            query: Option<String>,
            offset: usize,
            limit: usize,
            timeout_secs: Option<u64>,
        ) -> Result<Value, ToolError> {
            self.record(
                "list_globals",
                json!({
                    "query": query, "offset": offset, "limit": limit, "timeout_secs": timeout_secs,
                }),
            );
            Ok(json!({}))
        }

        async fn analyze_funcs(&self, timeout_secs: Option<u64>) -> Result<Value, ToolError> {
            self.record("analyze_funcs", json!({"timeout_secs": timeout_secs}));
            Ok(json!({}))
        }

        async fn find_bytes(
            &self,
            pattern: String,
            max_results: usize,
            timeout_secs: Option<u64>,
        ) -> Result<Value, ToolError> {
            self.record(
                "find_bytes",
                json!({
                    "pattern": pattern, "max_results": max_results, "timeout_secs": timeout_secs,
                }),
            );
            Ok(json!({}))
        }

        async fn search_text(
            &self,
            text: String,
            max_results: usize,
            timeout_secs: Option<u64>,
        ) -> Result<Value, ToolError> {
            self.record(
                "search_text",
                json!({
                    "text": text, "max_results": max_results, "timeout_secs": timeout_secs,
                }),
            );
            Ok(json!({}))
        }

        async fn search_imm(
            &self,
            imm: u64,
            max_results: usize,
            timeout_secs: Option<u64>,
        ) -> Result<Value, ToolError> {
            self.record(
                "search_imm",
                json!({
                    "imm": imm, "max_results": max_results, "timeout_secs": timeout_secs,
                }),
            );
            Ok(json!({}))
        }

        async fn find_insns(
            &self,
            patterns: Vec<String>,
            max_results: usize,
            case_insensitive: bool,
            timeout_secs: Option<u64>,
        ) -> Result<Value, ToolError> {
            self.record(
                "find_insns",
                json!({
                    "patterns": patterns, "max_results": max_results,
                    "case_insensitive": case_insensitive, "timeout_secs": timeout_secs,
                }),
            );
            Ok(json!({}))
        }

        async fn find_insn_operands(
            &self,
            patterns: Vec<String>,
            max_results: usize,
            case_insensitive: bool,
            timeout_secs: Option<u64>,
        ) -> Result<Value, ToolError> {
            self.record(
                "find_insn_operands",
                json!({
                    "patterns": patterns, "max_results": max_results,
                    "case_insensitive": case_insensitive, "timeout_secs": timeout_secs,
                }),
            );
            Ok(json!({}))
        }

        async fn run_script(
            &self,
            code: &str,
            timeout_secs: Option<u64>,
        ) -> Result<Value, ToolError> {
            self.record(
                "run_script",
                json!({"code": code, "timeout_secs": timeout_secs}),
            );
            Ok(json!({}))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn mock_records_calls() {
            let mock = MockWorker::new();
            let _ = mock.analysis_status().await;
            let _ = mock.segments().await;
            let _ = mock.disasm(0x1000, 10).await;

            let calls = mock.calls.lock().unwrap();
            assert_eq!(calls.len(), 3);
            assert_eq!(calls[0].0, "analysis_status");
            assert_eq!(calls[1].0, "segments");
            assert_eq!(calls[2].0, "disasm");
            assert_eq!(calls[2].1["addr"], 0x1000);
            assert_eq!(calls[2].1["count"], 10);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_address_value;
    use super::{dispatch_rpc, mock::MockWorker};
    use crate::error::ToolError;
    use crate::router::protocol::RpcRequest;
    use serde_json::{json, Value};

    async fn run_dispatch(method: &str, params: Value) -> Vec<(String, Value)> {
        let mock = MockWorker::new();
        let req = RpcRequest::new("1", method, params);
        dispatch_rpc(&req, &mock).await.unwrap();
        let calls = mock.calls.lock().unwrap().clone();
        calls
    }

    macro_rules! parse_address_case {
        ($name:ident, $input:tt, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(parse_address_value(&json!($input)), $expected);
            }
        };
    }

    macro_rules! single_call_test {
        ($name:ident, $method:expr, $params:expr, $recorded:expr, $key:expr, $expected:expr) => {
            #[tokio::test]
            async fn $name() {
                let calls = run_dispatch($method, $params).await;
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].0, $recorded);
                assert_eq!(calls[0].1[$key], $expected);
            }
        };
    }

    // -- parse_address_value --
    parse_address_case!(test_parse_address_hex_lowercase, "0x1000", Some(0x1000));
    parse_address_case!(
        test_parse_address_hex_uppercase_prefix,
        "0X1000",
        Some(0x1000)
    );
    parse_address_case!(test_parse_address_hex_mixed_digits, "0xAbCd", Some(0xabcd));
    parse_address_case!(test_parse_address_decimal_string, "4096", Some(4096));
    parse_address_case!(test_parse_address_decimal_with_space, " 4096 ", Some(4096));
    parse_address_case!(test_parse_address_zero_string, "0", Some(0));
    parse_address_case!(test_parse_address_zero_hex, "0x0", Some(0));
    parse_address_case!(test_parse_address_u64_number, 12345u64, Some(12345));
    parse_address_case!(test_parse_address_u32_number, 99u32, Some(99));
    parse_address_case!(
        test_parse_address_large_hex,
        "0xffffffffffffffff",
        Some(u64::MAX)
    );
    parse_address_case!(test_parse_address_invalid_text, "hello", None);
    parse_address_case!(test_parse_address_invalid_hex, "0xxyz", None);
    parse_address_case!(test_parse_address_empty_string, "", None);
    parse_address_case!(test_parse_address_minus_number, "-1", None);
    parse_address_case!(test_parse_address_float_text, "3.14", None);
    parse_address_case!(test_parse_address_bool_true, true, None);
    parse_address_case!(test_parse_address_bool_false, false, None);
    parse_address_case!(test_parse_address_null, null, None);
    parse_address_case!(test_parse_address_array, ["0x10"], None);
    parse_address_case!(test_parse_address_object, {"address": "0x10"}, None);
    parse_address_case!(test_parse_address_space_only, "   ", None);
    parse_address_case!(test_parse_address_leading_zero_decimal, "00042", Some(42));
    parse_address_case!(test_parse_address_hex_with_spaces, " 0x2a ", Some(42));
    parse_address_case!(
        test_parse_address_decimal_max_u32,
        "4294967295",
        Some(4294967295)
    );
    parse_address_case!(
        test_parse_address_decimal_max_i32,
        "2147483647",
        Some(2147483647)
    );
    parse_address_case!(test_parse_address_hex_one, "0x1", Some(1));
    parse_address_case!(test_parse_address_hex_f, "0xf", Some(15));
    parse_address_case!(
        test_parse_address_hex_deadbeef,
        "0xdeadbeef",
        Some(0xdeadbeef)
    );
    parse_address_case!(test_parse_address_decimal_small, "7", Some(7));
    parse_address_case!(test_parse_address_decimal_big, "987654321", Some(987654321));
    parse_address_case!(test_parse_address_non_numeric_suffix, "12abc", None);
    parse_address_case!(test_parse_address_non_numeric_prefix, "abc12", None);
    parse_address_case!(test_parse_address_hex_prefix_only, "0x", None);
    parse_address_case!(test_parse_address_hex_prefix_only_upper, "0X", None);
    parse_address_case!(test_parse_address_plus_sign, "+42", Some(42));
    parse_address_case!(test_parse_address_tabs, "\t0x20\t", Some(32));

    // -- Database management --
    single_call_test!(
        test_dispatch_open,
        "open",
        json!({"path": "/tmp/a.bin", "load_debug_info": true}),
        "open",
        "path",
        json!("/tmp/a.bin")
    );
    single_call_test!(
        test_dispatch_close,
        "close",
        json!({}),
        "close",
        "__dummy__",
        json!(null)
    );
    single_call_test!(
        test_dispatch_shutdown,
        "shutdown",
        json!({}),
        "shutdown",
        "__dummy__",
        json!(null)
    );
    single_call_test!(
        test_dispatch_load_debug_info,
        "load_debug_info",
        json!({"path": "/tmp/symbols.dSYM", "verbose": true}),
        "load_debug_info",
        "verbose",
        json!(true)
    );
    single_call_test!(
        test_dispatch_get_analysis_status,
        "get_analysis_status",
        json!({}),
        "analysis_status",
        "__dummy__",
        json!(null)
    );
    single_call_test!(
        test_dispatch_get_analysis_status_via_old_alias,
        "analysis_status",
        json!({}),
        "analysis_status",
        "__dummy__",
        json!(null)
    );
    single_call_test!(
        test_dispatch_get_database_info,
        "get_database_info",
        json!({}),
        "idb_meta",
        "__dummy__",
        json!(null)
    );
    single_call_test!(
        test_dispatch_get_database_info_via_old_alias,
        "idb_meta",
        json!({}),
        "idb_meta",
        "__dummy__",
        json!(null)
    );

    // -- Functions --
    single_call_test!(
        test_dispatch_list_functions,
        "list_functions",
        json!({"offset": 3, "limit": 5, "filter": "sub_", "timeout_secs": 9}),
        "list_functions",
        "offset",
        json!(3)
    );
    single_call_test!(
        test_dispatch_list_functions_via_old_alias,
        "list_funcs",
        json!({"offset": 3}),
        "list_functions",
        "offset",
        json!(3)
    );
    single_call_test!(
        test_dispatch_get_function_by_name,
        "get_function_by_name",
        json!({"name": "entry"}),
        "resolve_function",
        "name",
        json!("entry")
    );
    single_call_test!(
        test_dispatch_get_function_by_name_via_old_alias,
        "resolve_function",
        json!({"name": "entry"}),
        "resolve_function",
        "name",
        json!("entry")
    );
    single_call_test!(
        test_dispatch_get_function_prototype,
        "get_function_prototype",
        json!({"address": "0x4010"}),
        "get_function_prototype",
        "addr",
        json!(0x4010u64)
    );
    single_call_test!(
        test_dispatch_get_function_prototype_by_name,
        "get_function_prototype",
        json!({"name": "foo"}),
        "get_function_prototype",
        "name",
        json!("foo")
    );
    single_call_test!(
        test_dispatch_get_function_at_address,
        "get_function_at_address",
        json!({"address": "0x5000", "offset": 7}),
        "function_at",
        "addr",
        json!(0x5000u64)
    );
    single_call_test!(
        test_dispatch_get_function_at_address_via_old_alias,
        "function_at",
        json!({"target_name": "foo", "offset": 2}),
        "function_at",
        "name",
        json!("foo")
    );
    single_call_test!(
        test_dispatch_batch_lookup_functions,
        "batch_lookup_functions",
        json!({"queries": ["a", "b"]}),
        "lookup_funcs",
        "queries",
        json!(["a", "b"])
    );
    single_call_test!(
        test_dispatch_batch_lookup_functions_via_old_alias,
        "lookup_funcs",
        json!({"queries": ["entry"]}),
        "lookup_funcs",
        "queries",
        json!(["entry"])
    );
    single_call_test!(
        test_dispatch_export_functions,
        "export_functions",
        json!({"offset": 10, "limit": 11}),
        "export_funcs",
        "limit",
        json!(11)
    );
    single_call_test!(
        test_dispatch_export_functions_via_old_alias,
        "export_funcs",
        json!({"offset": 1, "limit": 2}),
        "export_funcs",
        "offset",
        json!(1)
    );

    // -- Disassembly / Decompilation --
    single_call_test!(
        test_dispatch_disassemble,
        "disassemble",
        json!({"address": "0x1000", "count": 5}),
        "disasm",
        "count",
        json!(5)
    );
    single_call_test!(
        test_dispatch_disassemble_via_old_alias,
        "disasm",
        json!({"address": "0x1000", "count": 5}),
        "disasm",
        "addr",
        json!(0x1000u64)
    );
    #[tokio::test]
    async fn test_dispatch_disassemble_multiple_addresses() {
        let calls = run_dispatch(
            "disassemble",
            json!({"address": ["0x1000", "0x1008"], "count": 3}),
        )
        .await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "disasm");
        assert_eq!(calls[1].0, "disasm");
        assert_eq!(calls[0].1["addr"], json!(0x1000u64));
        assert_eq!(calls[1].1["addr"], json!(0x1008u64));
    }
    single_call_test!(
        test_dispatch_disassemble_function,
        "disassemble_function",
        json!({"name": "sub_main", "count": 9}),
        "disasm_by_name",
        "name",
        json!("sub_main")
    );
    single_call_test!(
        test_dispatch_disassemble_function_via_old_alias,
        "disasm_by_name",
        json!({"name": "sub_main", "count": 9}),
        "disasm_by_name",
        "count",
        json!(9)
    );
    single_call_test!(
        test_dispatch_disassemble_function_at,
        "disassemble_function_at",
        json!({"address": "0x7000", "count": 4}),
        "disasm_function_at",
        "addr",
        json!(0x7000u64)
    );
    single_call_test!(
        test_dispatch_disassemble_function_at_via_old_alias,
        "disasm_function_at",
        json!({"target_name": "sub_a", "count": 4}),
        "disasm_function_at",
        "name",
        json!("sub_a")
    );
    single_call_test!(
        test_dispatch_decompile_function,
        "decompile_function",
        json!({"address": "0x8000"}),
        "decompile",
        "addr",
        json!(0x8000u64)
    );
    single_call_test!(
        test_dispatch_decompile_function_via_old_alias,
        "decompile",
        json!({"address": "0x8000"}),
        "decompile",
        "addr",
        json!(0x8000u64)
    );
    #[tokio::test]
    async fn test_dispatch_decompile_function_multiple_addresses() {
        let calls = run_dispatch("decompile_function", json!({"address": ["0x1", "0x2"]})).await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "decompile");
        assert_eq!(calls[1].0, "decompile");
    }
    single_call_test!(
        test_dispatch_get_pseudocode_at,
        "get_pseudocode_at",
        json!({"address": "0x9000"}),
        "pseudocode_at",
        "addr",
        json!(0x9000u64)
    );
    single_call_test!(
        test_dispatch_get_pseudocode_at_via_old_alias,
        "pseudocode_at",
        json!({"address": "0x9000", "end_address": "0x9010"}),
        "pseudocode_at",
        "end_addr",
        json!(0x9010u64)
    );

    // -- Segments / Strings --
    single_call_test!(
        test_dispatch_list_segments,
        "list_segments",
        json!({}),
        "segments",
        "__dummy__",
        json!(null)
    );
    single_call_test!(
        test_dispatch_list_segments_via_old_alias,
        "segments",
        json!({}),
        "segments",
        "__dummy__",
        json!(null)
    );
    single_call_test!(
        test_dispatch_list_strings_without_query,
        "list_strings",
        json!({"offset": 2, "limit": 3}),
        "strings",
        "offset",
        json!(2)
    );
    single_call_test!(
        test_dispatch_list_strings_via_old_alias,
        "strings",
        json!({"offset": 4, "limit": 8}),
        "strings",
        "limit",
        json!(8)
    );
    single_call_test!(
        test_dispatch_list_strings_with_query,
        "list_strings",
        json!({"query": "malloc", "limit": 7}),
        "find_string",
        "query",
        json!("malloc")
    );
    single_call_test!(
        test_dispatch_list_strings_with_query_via_find_string_alias,
        "find_string",
        json!({"query": "malloc", "exact": true}),
        "find_string",
        "exact",
        json!(true)
    );
    single_call_test!(
        test_dispatch_list_strings_with_query_via_analyze_strings_alias,
        "analyze_strings",
        json!({"query": "malloc", "offset": 1}),
        "find_string",
        "query",
        json!("malloc")
    );
    single_call_test!(
        test_dispatch_get_xrefs_to_string,
        "get_xrefs_to_string",
        json!({"query": "str", "limit": 11}),
        "xrefs_to_string",
        "limit",
        json!(11)
    );
    single_call_test!(
        test_dispatch_get_xrefs_to_string_via_old_alias,
        "xrefs_to_string",
        json!({"query": "str", "max_xrefs": 5}),
        "xrefs_to_string",
        "max_xrefs",
        json!(5)
    );

    // -- Types --
    single_call_test!(
        test_dispatch_list_local_types,
        "list_local_types",
        json!({"offset": 2, "limit": 12, "filter": "my_"}),
        "local_types",
        "filter",
        json!("my_")
    );
    single_call_test!(
        test_dispatch_list_local_types_via_old_alias,
        "local_types",
        json!({"offset": 2, "limit": 12}),
        "local_types",
        "offset",
        json!(2)
    );
    single_call_test!(
        test_dispatch_declare_c_type,
        "declare_c_type",
        json!({"decl": "typedef int T;", "replace": true}),
        "declare_type",
        "decl",
        json!("typedef int T;")
    );
    single_call_test!(
        test_dispatch_declare_c_type_via_old_alias,
        "declare_type",
        json!({"decl": "typedef int T2;", "replace": false}),
        "declare_type",
        "replace",
        json!(false)
    );
    single_call_test!(
        test_dispatch_apply_type,
        "apply_type",
        json!({"address": "0xa000", "decl": "int"}),
        "apply_types",
        "addr",
        json!(0xa000u64)
    );
    single_call_test!(
        test_dispatch_apply_type_via_old_alias,
        "apply_types",
        json!({"target_name": "glob", "decl": "char*"}),
        "apply_types",
        "name",
        json!("glob")
    );
    single_call_test!(
        test_dispatch_infer_type,
        "infer_type",
        json!({"address": "0xb000"}),
        "infer_types",
        "addr",
        json!(0xb000u64)
    );
    single_call_test!(
        test_dispatch_infer_type_via_old_alias,
        "infer_types",
        json!({"target_name": "g_var"}),
        "infer_types",
        "name",
        json!("g_var")
    );
    single_call_test!(
        test_dispatch_set_function_prototype,
        "set_function_prototype",
        json!({"address": "0xc000", "prototype": "int f(void);"}),
        "set_function_prototype",
        "prototype",
        json!("int f(void);")
    );
    single_call_test!(
        test_dispatch_set_function_prototype_by_name,
        "set_function_prototype",
        json!({"name": "f", "prototype": "void f(int);"}),
        "set_function_prototype",
        "name",
        json!("f")
    );
    single_call_test!(
        test_dispatch_rename_stack_variable,
        "rename_stack_variable",
        json!({"func_address": "0xd000", "name": "v1", "new_name": "arg1"}),
        "rename_stack_variable",
        "old_name",
        json!("v1")
    );
    single_call_test!(
        test_dispatch_rename_stack_variable_by_name,
        "rename_stack_variable",
        json!({"func_name": "foo", "name": "v2", "new_name": "len"}),
        "rename_stack_variable",
        "func_name",
        json!("foo")
    );
    single_call_test!(
        test_dispatch_set_stack_variable_type,
        "set_stack_variable_type",
        json!({"func_address": "0xd100", "name": "v1", "type_decl": "size_t"}),
        "set_stack_variable_type",
        "var_name",
        json!("v1")
    );
    single_call_test!(
        test_dispatch_set_stack_variable_type_by_name,
        "set_stack_variable_type",
        json!({"func_name": "foo", "name": "v3", "type_decl": "char*"}),
        "set_stack_variable_type",
        "func_name",
        json!("foo")
    );
    single_call_test!(
        test_dispatch_list_enums,
        "list_enums",
        json!({"filter": "E_", "offset": 1, "limit": 2}),
        "list_enums",
        "filter",
        json!("E_")
    );
    single_call_test!(
        test_dispatch_create_enum,
        "create_enum",
        json!({"decl": "enum E { A=1 };", "replace": true}),
        "create_enum",
        "replace",
        json!(true)
    );

    // -- Address / Stack / Struct / Xref --
    single_call_test!(
        test_dispatch_get_address_info,
        "get_address_info",
        json!({"address": "0xe000", "offset": 4}),
        "addr_info",
        "addr",
        json!(0xe000u64)
    );
    single_call_test!(
        test_dispatch_get_address_info_via_old_alias,
        "addr_info",
        json!({"target_name": "foo", "offset": 4}),
        "addr_info",
        "name",
        json!("foo")
    );
    single_call_test!(
        test_dispatch_create_stack_variable,
        "create_stack_variable",
        json!({"address": "0xf000", "offset": -16, "decl": "int x;"}),
        "declare_stack",
        "offset",
        json!(-16)
    );
    single_call_test!(
        test_dispatch_create_stack_variable_via_old_alias,
        "declare_stack",
        json!({"target_name": "foo", "offset": -8, "decl": "char c;"}),
        "declare_stack",
        "name",
        json!("foo")
    );
    single_call_test!(
        test_dispatch_delete_stack_variable,
        "delete_stack_variable",
        json!({"address": "0xf010", "offset": -16}),
        "delete_stack",
        "addr",
        json!(0xf010u64)
    );
    single_call_test!(
        test_dispatch_delete_stack_variable_via_old_alias,
        "delete_stack",
        json!({"target_name": "foo", "offset": -8}),
        "delete_stack",
        "name",
        json!("foo")
    );
    single_call_test!(
        test_dispatch_get_stack_frame,
        "get_stack_frame",
        json!({"address": "0x11000"}),
        "stack_frame",
        "addr",
        json!(0x11000u64)
    );
    single_call_test!(
        test_dispatch_get_stack_frame_via_old_alias,
        "stack_frame",
        json!({"address": "0x11000"}),
        "stack_frame",
        "addr",
        json!(0x11000u64)
    );
    single_call_test!(
        test_dispatch_list_structs,
        "list_structs",
        json!({"offset": 1, "limit": 10}),
        "structs",
        "limit",
        json!(10)
    );
    single_call_test!(
        test_dispatch_list_structs_via_old_alias,
        "structs",
        json!({"offset": 2, "limit": 3}),
        "structs",
        "offset",
        json!(2)
    );
    single_call_test!(
        test_dispatch_get_struct_info,
        "get_struct_info",
        json!({"name": "MyStruct"}),
        "struct_info",
        "name",
        json!("MyStruct")
    );
    single_call_test!(
        test_dispatch_get_struct_info_via_old_alias,
        "struct_info",
        json!({"ordinal": 3}),
        "struct_info",
        "ordinal",
        json!(3)
    );
    single_call_test!(
        test_dispatch_read_struct_at_address,
        "read_struct_at_address",
        json!({"address": "0x12000", "name": "MyStruct"}),
        "read_struct",
        "addr",
        json!(0x12000u64)
    );
    single_call_test!(
        test_dispatch_read_struct_at_address_via_old_alias,
        "read_struct",
        json!({"address": "0x12010", "ordinal": 2}),
        "read_struct",
        "ordinal",
        json!(2)
    );
    single_call_test!(
        test_dispatch_get_xrefs_to,
        "get_xrefs_to",
        json!({"address": "0x13000"}),
        "xrefs_to",
        "addr",
        json!(0x13000u64)
    );
    single_call_test!(
        test_dispatch_get_xrefs_to_via_old_alias,
        "xrefs_to",
        json!({"address": "0x13000"}),
        "xrefs_to",
        "addr",
        json!(0x13000u64)
    );
    single_call_test!(
        test_dispatch_get_xrefs_from,
        "get_xrefs_from",
        json!({"address": "0x13010"}),
        "xrefs_from",
        "addr",
        json!(0x13010u64)
    );
    single_call_test!(
        test_dispatch_get_xrefs_from_via_old_alias,
        "xrefs_from",
        json!({"address": "0x13010"}),
        "xrefs_from",
        "addr",
        json!(0x13010u64)
    );
    single_call_test!(
        test_dispatch_get_xrefs_to_struct_field,
        "get_xrefs_to_struct_field",
        json!({"name": "MyStruct", "member_name": "field", "limit": 50}),
        "xrefs_to_field",
        "member_name",
        json!("field")
    );
    single_call_test!(
        test_dispatch_get_xrefs_to_struct_field_via_old_alias,
        "xrefs_to_field",
        json!({"ordinal": 1, "member_index": 2}),
        "xrefs_to_field",
        "member_index",
        json!(2)
    );

    // -- Imports / Exports / Entry --
    single_call_test!(
        test_dispatch_list_imports,
        "list_imports",
        json!({"offset": 5, "limit": 6}),
        "imports",
        "offset",
        json!(5)
    );
    single_call_test!(
        test_dispatch_list_imports_via_old_alias,
        "imports",
        json!({"offset": 1, "limit": 2}),
        "imports",
        "limit",
        json!(2)
    );
    single_call_test!(
        test_dispatch_list_exports,
        "list_exports",
        json!({"offset": 7, "limit": 8}),
        "exports",
        "limit",
        json!(8)
    );
    single_call_test!(
        test_dispatch_list_exports_via_old_alias,
        "exports",
        json!({"offset": 7, "limit": 8}),
        "exports",
        "offset",
        json!(7)
    );
    // -- Memory --
    single_call_test!(
        test_dispatch_read_bytes,
        "read_bytes",
        json!({"address": "0x14000", "size": 16}),
        "get_bytes",
        "addr",
        json!(0x14000u64)
    );
    single_call_test!(
        test_dispatch_read_bytes_via_old_alias,
        "get_bytes",
        json!({"address": "0x14000", "size": 8}),
        "get_bytes",
        "size",
        json!(8)
    );
    single_call_test!(
        test_dispatch_read_string,
        "read_string",
        json!({"address": "0x14100", "max_len": 32}),
        "get_string",
        "max_len",
        json!(32)
    );
    single_call_test!(
        test_dispatch_read_string_via_old_alias,
        "get_string",
        json!({"address": "0x14100", "max_len": 12}),
        "get_string",
        "addr",
        json!(0x14100u64)
    );
    single_call_test!(
        test_dispatch_read_global_variable,
        "read_global_variable",
        json!({"query": "gCounter"}),
        "get_global_value",
        "query",
        json!("gCounter")
    );
    single_call_test!(
        test_dispatch_read_global_variable_via_old_alias,
        "get_global_value",
        json!({"query": "gCounter"}),
        "get_global_value",
        "query",
        json!("gCounter")
    );
    single_call_test!(
        test_dispatch_read_int,
        "read_int",
        json!({"address": "0x15000", "size": 8}),
        "read_int",
        "size",
        json!(8)
    );

    // -- Annotations / Rename --
    single_call_test!(
        test_dispatch_set_comment,
        "set_comment",
        json!({"address": "0x16000", "comment": "note"}),
        "set_comments",
        "comment",
        json!("note")
    );
    single_call_test!(
        test_dispatch_set_comment_via_old_alias,
        "set_comments",
        json!({"target_name": "foo", "comment": "note"}),
        "set_comments",
        "name",
        json!("foo")
    );
    single_call_test!(
        test_dispatch_set_function_comment,
        "set_function_comment",
        json!({"address": "0x16010", "comment": "fn note"}),
        "set_function_comment",
        "comment",
        json!("fn note")
    );
    single_call_test!(
        test_dispatch_rename_symbol,
        "rename_symbol",
        json!({"address": "0x17000", "name": "new_name"}),
        "rename",
        "new_name",
        json!("new_name")
    );
    single_call_test!(
        test_dispatch_rename_symbol_via_old_alias,
        "rename",
        json!({"current_name": "old", "name": "new"}),
        "rename",
        "current_name",
        json!("old")
    );
    single_call_test!(
        test_dispatch_batch_rename,
        "batch_rename",
        json!({"renames": [{"address": "0x1000", "new_name": "a"}]}),
        "batch_rename",
        "entries",
        json!([[0x1000u64, null, "a"]])
    );
    single_call_test!(
        test_dispatch_rename_local_variable,
        "rename_local_variable",
        json!({"func_address": "0x18000", "lvar_name": "v1", "new_name": "idx"}),
        "rename_lvar",
        "new_name",
        json!("idx")
    );
    single_call_test!(
        test_dispatch_rename_local_variable_via_old_alias,
        "rename_lvar",
        json!({"func_address": "0x18000", "lvar_name": "v1", "new_name": "idx"}),
        "rename_lvar",
        "func_addr",
        json!(0x18000u64)
    );
    single_call_test!(
        test_dispatch_set_local_variable_type,
        "set_local_variable_type",
        json!({"func_address": "0x18010", "lvar_name": "v2", "type_str": "u32"}),
        "set_lvar_type",
        "type_str",
        json!("u32")
    );
    single_call_test!(
        test_dispatch_set_local_variable_type_via_old_alias,
        "set_lvar_type",
        json!({"func_address": "0x18010", "lvar_name": "v2", "type_str": "u32"}),
        "set_lvar_type",
        "func_addr",
        json!(0x18010u64)
    );
    single_call_test!(
        test_dispatch_set_decompiler_comment,
        "set_decompiler_comment",
        json!({"func_address": "0x18020", "address": "0x18024", "comment": "c"}),
        "set_decompiler_comment",
        "itp",
        json!(69)
    );

    // -- Patching --
    single_call_test!(
        test_dispatch_patch_bytes,
        "patch_bytes",
        json!({"address": "0x19000", "bytes": [144, 145]}),
        "patch_bytes",
        "bytes",
        json!([144, 145])
    );
    single_call_test!(
        test_dispatch_patch_bytes_via_old_alias,
        "patch",
        json!({"address": "0x19000", "bytes": "90 91"}),
        "patch_bytes",
        "addr",
        json!(0x19000u64)
    );
    single_call_test!(
        test_dispatch_patch_assembly,
        "patch_assembly",
        json!({"address": "0x19010", "line": "nop"}),
        "patch_asm",
        "line",
        json!("nop")
    );
    single_call_test!(
        test_dispatch_patch_assembly_via_old_alias,
        "patch_asm",
        json!({"address": "0x19010", "line": "ret"}),
        "patch_asm",
        "line",
        json!("ret")
    );

    // -- Control / Call flow --
    single_call_test!(
        test_dispatch_get_basic_blocks,
        "get_basic_blocks",
        json!({"address": "0x1a000"}),
        "basic_blocks",
        "addr",
        json!(0x1a000u64)
    );
    single_call_test!(
        test_dispatch_get_basic_blocks_via_old_alias,
        "basic_blocks",
        json!({"address": "0x1a000"}),
        "basic_blocks",
        "addr",
        json!(0x1a000u64)
    );
    single_call_test!(
        test_dispatch_get_callees,
        "get_callees",
        json!({"address": "0x1a010"}),
        "callees",
        "addr",
        json!(0x1a010u64)
    );
    single_call_test!(
        test_dispatch_get_callees_via_old_alias,
        "callees",
        json!({"address": "0x1a010"}),
        "callees",
        "addr",
        json!(0x1a010u64)
    );
    single_call_test!(
        test_dispatch_get_callers,
        "get_callers",
        json!({"address": "0x1a020"}),
        "callers",
        "addr",
        json!(0x1a020u64)
    );
    single_call_test!(
        test_dispatch_get_callers_via_old_alias,
        "callers",
        json!({"address": "0x1a020"}),
        "callers",
        "addr",
        json!(0x1a020u64)
    );
    single_call_test!(
        test_dispatch_build_callgraph,
        "build_callgraph",
        json!({"roots": ["0x1a030"], "max_depth": 3, "max_nodes": 7}),
        "callgraph",
        "max_depth",
        json!(3)
    );
    single_call_test!(
        test_dispatch_build_callgraph_via_old_alias,
        "callgraph",
        json!({"roots": "0x1a030", "max_depth": 2}),
        "callgraph",
        "addr",
        json!(0x1a030u64)
    );
    single_call_test!(
        test_dispatch_find_control_flow_paths,
        "find_control_flow_paths",
        json!({"start": "0x1a040", "end": "0x1a050", "max_paths": 2}),
        "find_paths",
        "max_paths",
        json!(2)
    );
    single_call_test!(
        test_dispatch_find_control_flow_paths_via_old_alias,
        "find_paths",
        json!({"start": "0x1a040", "end": "0x1a050", "max_depth": 4}),
        "find_paths",
        "max_depth",
        json!(4)
    );
    single_call_test!(
        test_dispatch_build_xref_matrix,
        "build_xref_matrix",
        json!({"addrs": ["0x1a060", "0x1a070"]}),
        "xref_matrix",
        "addrs",
        json!([0x1a060u64, 0x1a070u64])
    );
    single_call_test!(
        test_dispatch_build_xref_matrix_via_old_alias,
        "xref_matrix",
        json!({"addrs": ["0x1a080"]}),
        "xref_matrix",
        "addrs",
        json!([0x1a080u64])
    );

    // -- Globals / Analysis / Search / Script --
    single_call_test!(
        test_dispatch_list_globals,
        "list_globals",
        json!({"query": "g_", "limit": 20}),
        "list_globals",
        "limit",
        json!(20)
    );
    single_call_test!(
        test_dispatch_run_auto_analysis,
        "run_auto_analysis",
        json!({"timeout_secs": 10}),
        "analyze_funcs",
        "timeout_secs",
        json!(10)
    );
    single_call_test!(
        test_dispatch_run_auto_analysis_via_old_alias,
        "analyze_funcs",
        json!({"timeout_secs": 3}),
        "analyze_funcs",
        "timeout_secs",
        json!(3)
    );
    single_call_test!(
        test_dispatch_search_bytes_single_pattern,
        "search_bytes",
        json!({"patterns": "FD 7B", "limit": 11}),
        "find_bytes",
        "pattern",
        json!("FD 7B")
    );
    single_call_test!(
        test_dispatch_search_bytes_via_old_alias,
        "find_bytes",
        json!({"patterns": "AA BB"}),
        "find_bytes",
        "pattern",
        json!("AA BB")
    );
    #[tokio::test]
    async fn test_dispatch_search_bytes_multiple_patterns() {
        let calls = run_dispatch("search_bytes", json!({"patterns": ["11 22", "33 44"]})).await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "find_bytes");
        assert_eq!(calls[1].0, "find_bytes");
    }
    #[tokio::test]
    async fn test_dispatch_search_bytes_empty_patterns() {
        let mock = MockWorker::new();
        let req = RpcRequest::new("1", "search_bytes", json!({"patterns": null}));
        let v = dispatch_rpc(&req, &mock).await.unwrap();
        assert_eq!(v, json!({"matches": [], "count": 0}));
        assert!(mock.calls.lock().unwrap().is_empty());
    }
    single_call_test!(
        test_dispatch_search_text,
        "search_text",
        json!({"text": "malloc", "max_results": 9}),
        "search_text",
        "text",
        json!("malloc")
    );
    single_call_test!(
        test_dispatch_search_text_via_old_alias,
        "search",
        json!({"text": "free", "max_results": 5}),
        "search_text",
        "max_results",
        json!(5)
    );
    single_call_test!(
        test_dispatch_search_imm,
        "search_imm",
        json!({"imm": 123, "max_results": 4}),
        "search_imm",
        "imm",
        json!(123)
    );
    single_call_test!(
        test_dispatch_search_instructions,
        "search_instructions",
        json!({"patterns": ["bl", "ret"]}),
        "find_insns",
        "patterns",
        json!(["bl", "ret"])
    );
    single_call_test!(
        test_dispatch_search_instructions_via_old_alias,
        "find_insns",
        json!({"patterns": "mov"}),
        "find_insns",
        "patterns",
        json!(["mov"])
    );
    single_call_test!(
        test_dispatch_search_instruction_operands,
        "search_instruction_operands",
        json!({"patterns": ["x0"]}),
        "find_insn_operands",
        "patterns",
        json!(["x0"])
    );
    single_call_test!(
        test_dispatch_search_instruction_operands_via_old_alias,
        "find_insn_operands",
        json!({"patterns": "x1"}),
        "find_insn_operands",
        "patterns",
        json!(["x1"])
    );
    single_call_test!(
        test_dispatch_run_script,
        "run_script",
        json!({"code": "print('ok')", "timeout_secs": 6}),
        "run_script",
        "code",
        json!("print('ok')")
    );

    // -- Compound tools --
    #[tokio::test]
    async fn test_dispatch_batch_decompile() {
        let calls = run_dispatch(
            "batch_decompile",
            json!({"addresses": ["0x2000", "0x2008"]}),
        )
        .await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "decompile");
        assert_eq!(calls[1].0, "decompile");
    }
    #[tokio::test]
    async fn test_dispatch_batch_decompile_single_item() {
        let calls = run_dispatch("batch_decompile", json!({"addresses": "0x2000"})).await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "decompile");
    }
    #[tokio::test]
    async fn test_dispatch_search_pseudocode() {
        let calls = run_dispatch(
            "search_pseudocode",
            json!({"pattern": "malloc", "limit": 5}),
        )
        .await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "list_functions");
    }
    #[tokio::test]
    async fn test_dispatch_scan_memory_table() {
        let calls = run_dispatch(
            "scan_memory_table",
            json!({"base_address": "0x3000", "stride": 8, "count": 3}),
        )
        .await;
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, "get_bytes");
        assert_eq!(calls[2].1["addr"], json!(0x3010u64));
    }
    #[tokio::test]
    async fn test_dispatch_scan_memory_table_via_old_alias() {
        let calls = run_dispatch("table_scan", json!({"base_address": "0x3100", "count": 2})).await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "get_bytes");
    }
    #[tokio::test]
    async fn test_dispatch_diff_pseudocode() {
        let calls = run_dispatch(
            "diff_pseudocode",
            json!({"addr1": "0x4000", "addr2": "0x4010"}),
        )
        .await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "decompile");
        assert_eq!(calls[1].0, "decompile");
    }
    #[tokio::test]
    async fn test_dispatch_diff_pseudocode_via_old_alias() {
        let calls = run_dispatch(
            "diff_functions",
            json!({"addr1": "0x5000", "addr2": "0x5010"}),
        )
        .await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "decompile");
        assert_eq!(calls[1].0, "decompile");
    }

    // -- Alias extra coverage --
    single_call_test!(
        test_dispatch_alias_list_strings_find_string,
        "find_string",
        json!({"query": "x"}),
        "find_string",
        "query",
        json!("x")
    );
    single_call_test!(
        test_dispatch_alias_list_strings_strings,
        "strings",
        json!({}),
        "strings",
        "offset",
        json!(0)
    );
    single_call_test!(
        test_dispatch_alias_export_funcs,
        "export_funcs",
        json!({}),
        "export_funcs",
        "limit",
        json!(100)
    );
    single_call_test!(
        test_dispatch_alias_lookup_funcs,
        "lookup_funcs",
        json!({"queries": ["q"]}),
        "lookup_funcs",
        "queries",
        json!(["q"])
    );
    single_call_test!(
        test_dispatch_alias_function_at,
        "function_at",
        json!({"address": "0x10"}),
        "function_at",
        "addr",
        json!(0x10u64)
    );
    single_call_test!(
        test_dispatch_alias_disasm,
        "disasm",
        json!({"address": "0x10"}),
        "disasm",
        "addr",
        json!(0x10u64)
    );
    single_call_test!(
        test_dispatch_alias_disasm_by_name,
        "disasm_by_name",
        json!({"name": "f"}),
        "disasm_by_name",
        "name",
        json!("f")
    );
    single_call_test!(
        test_dispatch_alias_disasm_function_at,
        "disasm_function_at",
        json!({"address": "0x10"}),
        "disasm_function_at",
        "addr",
        json!(0x10u64)
    );
    single_call_test!(
        test_dispatch_alias_decompile,
        "decompile",
        json!({"address": "0x10"}),
        "decompile",
        "addr",
        json!(0x10u64)
    );
    single_call_test!(
        test_dispatch_alias_pseudocode_at,
        "pseudocode_at",
        json!({"address": "0x10"}),
        "pseudocode_at",
        "addr",
        json!(0x10u64)
    );
    single_call_test!(
        test_dispatch_alias_xrefs_to_string,
        "xrefs_to_string",
        json!({"query": "q"}),
        "xrefs_to_string",
        "query",
        json!("q")
    );
    single_call_test!(
        test_dispatch_alias_local_types,
        "local_types",
        json!({}),
        "local_types",
        "limit",
        json!(100)
    );
    single_call_test!(
        test_dispatch_alias_declare_type,
        "declare_type",
        json!({"decl": "int x;"}),
        "declare_type",
        "decl",
        json!("int x;")
    );
    single_call_test!(
        test_dispatch_alias_apply_types,
        "apply_types",
        json!({"address": "0x22"}),
        "apply_types",
        "addr",
        json!(0x22u64)
    );
    single_call_test!(
        test_dispatch_alias_infer_types,
        "infer_types",
        json!({"address": "0x23"}),
        "infer_types",
        "addr",
        json!(0x23u64)
    );
    single_call_test!(
        test_dispatch_alias_addr_info,
        "addr_info",
        json!({"address": "0x24"}),
        "addr_info",
        "addr",
        json!(0x24u64)
    );
    single_call_test!(
        test_dispatch_alias_declare_stack,
        "declare_stack",
        json!({"address": "0x25", "offset": -4, "decl": "int x;"}),
        "declare_stack",
        "addr",
        json!(0x25u64)
    );
    single_call_test!(
        test_dispatch_alias_delete_stack,
        "delete_stack",
        json!({"address": "0x26"}),
        "delete_stack",
        "addr",
        json!(0x26u64)
    );
    single_call_test!(
        test_dispatch_alias_stack_frame,
        "stack_frame",
        json!({"address": "0x27"}),
        "stack_frame",
        "addr",
        json!(0x27u64)
    );
    single_call_test!(
        test_dispatch_alias_structs,
        "structs",
        json!({}),
        "structs",
        "offset",
        json!(0)
    );
    single_call_test!(
        test_dispatch_alias_struct_info,
        "struct_info",
        json!({"name": "S"}),
        "struct_info",
        "name",
        json!("S")
    );
    single_call_test!(
        test_dispatch_alias_read_struct,
        "read_struct",
        json!({"address": "0x28", "name": "S"}),
        "read_struct",
        "addr",
        json!(0x28u64)
    );
    single_call_test!(
        test_dispatch_alias_xrefs_to,
        "xrefs_to",
        json!({"address": "0x29"}),
        "xrefs_to",
        "addr",
        json!(0x29u64)
    );
    single_call_test!(
        test_dispatch_alias_xrefs_from,
        "xrefs_from",
        json!({"address": "0x30"}),
        "xrefs_from",
        "addr",
        json!(0x30u64)
    );
    single_call_test!(
        test_dispatch_alias_xrefs_to_field,
        "xrefs_to_field",
        json!({"name": "S"}),
        "xrefs_to_field",
        "name",
        json!("S")
    );
    single_call_test!(
        test_dispatch_alias_imports,
        "imports",
        json!({}),
        "imports",
        "limit",
        json!(100)
    );
    single_call_test!(
        test_dispatch_alias_exports,
        "exports",
        json!({}),
        "exports",
        "limit",
        json!(100)
    );
    single_call_test!(
        test_dispatch_alias_get_bytes,
        "get_bytes",
        json!({"address": "0x31"}),
        "get_bytes",
        "addr",
        json!(0x31u64)
    );
    single_call_test!(
        test_dispatch_alias_get_string,
        "get_string",
        json!({"address": "0x32"}),
        "get_string",
        "addr",
        json!(0x32u64)
    );
    single_call_test!(
        test_dispatch_alias_get_global_value,
        "get_global_value",
        json!({"query": "g"}),
        "get_global_value",
        "query",
        json!("g")
    );
    single_call_test!(
        test_dispatch_alias_set_comments,
        "set_comments",
        json!({"address": "0x33", "comment": "c"}),
        "set_comments",
        "addr",
        json!(0x33u64)
    );
    single_call_test!(
        test_dispatch_alias_rename,
        "rename",
        json!({"address": "0x34", "name": "n"}),
        "rename",
        "addr",
        json!(0x34u64)
    );
    single_call_test!(
        test_dispatch_alias_rename_lvar,
        "rename_lvar",
        json!({"func_address": "0x35", "lvar_name": "v", "new_name": "n"}),
        "rename_lvar",
        "func_addr",
        json!(0x35u64)
    );
    single_call_test!(
        test_dispatch_alias_set_lvar_type,
        "set_lvar_type",
        json!({"func_address": "0x36", "lvar_name": "v", "type_str": "i32"}),
        "set_lvar_type",
        "func_addr",
        json!(0x36u64)
    );
    single_call_test!(
        test_dispatch_alias_patch,
        "patch",
        json!({"address": "0x37", "bytes": [1]}),
        "patch_bytes",
        "addr",
        json!(0x37u64)
    );
    single_call_test!(
        test_dispatch_alias_patch_asm,
        "patch_asm",
        json!({"address": "0x38", "line": "nop"}),
        "patch_asm",
        "addr",
        json!(0x38u64)
    );
    single_call_test!(
        test_dispatch_alias_basic_blocks,
        "basic_blocks",
        json!({"address": "0x39"}),
        "basic_blocks",
        "addr",
        json!(0x39u64)
    );
    single_call_test!(
        test_dispatch_alias_callees,
        "callees",
        json!({"address": "0x40"}),
        "callees",
        "addr",
        json!(0x40u64)
    );
    single_call_test!(
        test_dispatch_alias_callers,
        "callers",
        json!({"address": "0x41"}),
        "callers",
        "addr",
        json!(0x41u64)
    );
    single_call_test!(
        test_dispatch_alias_callgraph,
        "callgraph",
        json!({"roots": ["0x42"]}),
        "callgraph",
        "addr",
        json!(0x42u64)
    );
    single_call_test!(
        test_dispatch_alias_find_paths,
        "find_paths",
        json!({"start": "0x43", "end": "0x44"}),
        "find_paths",
        "start",
        json!(0x43u64)
    );
    single_call_test!(
        test_dispatch_alias_xref_matrix,
        "xref_matrix",
        json!({"addrs": ["0x45"]}),
        "xref_matrix",
        "addrs",
        json!([0x45u64])
    );
    single_call_test!(
        test_dispatch_alias_analyze_funcs,
        "analyze_funcs",
        json!({}),
        "analyze_funcs",
        "timeout_secs",
        json!(null)
    );
    single_call_test!(
        test_dispatch_alias_find_bytes,
        "find_bytes",
        json!({"patterns": "aa"}),
        "find_bytes",
        "pattern",
        json!("aa")
    );
    single_call_test!(
        test_dispatch_alias_search_text,
        "search",
        json!({"text": "aa"}),
        "search_text",
        "text",
        json!("aa")
    );
    single_call_test!(
        test_dispatch_alias_find_insns,
        "find_insns",
        json!({"patterns": "aa"}),
        "find_insns",
        "patterns",
        json!(["aa"])
    );
    single_call_test!(
        test_dispatch_alias_find_insn_operands,
        "find_insn_operands",
        json!({"patterns": "aa"}),
        "find_insn_operands",
        "patterns",
        json!(["aa"])
    );

    // -- Unknown --
    #[tokio::test]
    async fn test_dispatch_unknown_method_returns_error() {
        let mock = MockWorker::new();
        let req = RpcRequest::new("1", "nonexistent_tool", json!({}));
        let err = dispatch_rpc(&req, &mock).await.unwrap_err();
        match err {
            ToolError::InvalidToolName(msg) => {
                assert!(msg.contains("Unknown method: nonexistent_tool"));
            }
            other => panic!("expected InvalidToolName, got {other:?}"),
        }
    }
}
