use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::error::ToolError;
use crate::ida::{AnalysisStatus, DbInfo, FunctionListResult};
use crate::idb_store::IdbStore;
use crate::router::protocol::{RpcRequest, RpcResponse};
use crate::tool_registry::primary_name_for;

#[derive(Debug, Clone)]
struct CompatSession {
    database_path: PathBuf,
    info: DbInfo,
}

#[derive(Debug, Default)]
struct CompatWorker {
    session: Option<CompatSession>,
}

impl CompatWorker {
    fn open(
        &mut self,
        path: &str,
        auto_analyse: bool,
        _load_debug_info: bool,
        _debug_info_path: Option<String>,
        _debug_info_verbose: bool,
        _force: bool,
        _file_type: Option<String>,
        _extra_args: Vec<String>,
    ) -> Result<DbInfo, ToolError> {
        let input_path = PathBuf::from(path);
        if !input_path.exists() {
            return Err(ToolError::InvalidPath(format!(
                "File not found: {}",
                input_path.display()
            )));
        }

        let store = IdbStore::new();
        let ext = input_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let is_database = matches!(ext.as_str(), "i64" | "id0" | "idb");

        let database_path = if is_database {
            input_path.clone()
        } else {
            let hint = compat_database_hint(&store, &input_path);
            existing_database_path(&hint).unwrap_or(hint)
        };

        let info = if is_database {
            inspect_database(&database_path)?
        } else {
            create_or_open_database(&input_path, &database_path, auto_analyse)?
        };

        let database_path = if is_database {
            database_path
        } else {
            existing_database_path(&database_path).unwrap_or(database_path)
        };

        if !is_database && database_path.exists() {
            store.record(&input_path, &database_path);
        }

        self.session = Some(CompatSession {
            database_path,
            info: info.clone(),
        });

        Ok(info)
    }

    fn close(&mut self) {
        self.session = None;
    }

    fn analysis_status(&self) -> Result<AnalysisStatus, ToolError> {
        self.session
            .as_ref()
            .map(|session| session.info.analysis_status.clone())
            .ok_or(ToolError::NoDatabaseOpen)
    }

    fn list_functions(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
    ) -> Result<FunctionListResult, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        list_functions_with_idat(&session.database_path, offset, limit, filter.as_deref())
    }

    fn decompile(&self, addr: u64) -> Result<String, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        decompile_with_idat(&session.database_path, addr)
    }

    fn resolve_function(&self, name: &str) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        resolve_function_with_idat(&session.database_path, name)
    }

    fn function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
    ) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        function_at_with_idat(&session.database_path, addr, name, offset)
    }

    fn disasm(&self, addr: u64, count: usize) -> Result<String, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        disasm_with_idat(&session.database_path, addr, count)
    }

    fn disasm_by_name(&self, name: &str, count: usize) -> Result<String, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        disasm_by_name_with_idat(&session.database_path, name, count)
    }

    fn disasm_function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
        count: usize,
    ) -> Result<String, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        disasm_function_at_with_idat(&session.database_path, addr, name, offset, count)
    }

    fn segments(&self) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        segments_with_idat(&session.database_path)
    }

    fn strings(
        &self,
        offset: usize,
        limit: usize,
        query: Option<String>,
    ) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        strings_with_idat(&session.database_path, offset, limit, query.as_deref())
    }

    fn get_bytes(&self, addr: u64, size: usize) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        get_bytes_with_idat(&session.database_path, addr, size)
    }

    fn addr_info(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: u64,
    ) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        addr_info_with_idat(&session.database_path, addr, name, offset)
    }

    fn xrefs_to(&self, addr: u64) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        xrefs_with_idat(&session.database_path, addr, true)
    }

    fn xrefs_from(&self, addr: u64) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        xrefs_with_idat(&session.database_path, addr, false)
    }

    fn imports(&self, offset: usize, limit: usize) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        imports_with_idat(&session.database_path, offset, limit)
    }

    fn exports(&self, offset: usize, limit: usize) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        exports_with_idat(&session.database_path, offset, limit)
    }

    fn entrypoints(&self) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        entrypoints_with_idat(&session.database_path)
    }

    fn database_info(&self) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        database_info_with_idat(&session.database_path)
    }

    fn list_globals(
        &self,
        query: Option<String>,
        offset: usize,
        limit: usize,
    ) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        globals_with_idat(&session.database_path, query.as_deref(), offset, limit)
    }

    fn read_string(&self, addr: u64, max_len: usize) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        read_string_with_idat(&session.database_path, addr, max_len)
    }

    fn read_int(&self, addr: u64, size: usize) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        read_int_with_idat(&session.database_path, addr, size)
    }

    fn search_text(&self, text: String, max_results: usize) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        search_text_with_idat(&session.database_path, &text, max_results)
    }

    fn search_bytes(&self, pattern: String, max_results: usize) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        search_bytes_with_idat(&session.database_path, &pattern, max_results)
    }

    fn run_script(&self, code: &str) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        run_script_with_idat(&session.database_path, code)
    }

    fn pseudocode_at(&self, addr: u64, end_addr: Option<u64>) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        pseudocode_at_with_idat(&session.database_path, addr, end_addr)
    }

    fn batch_decompile(&self, addrs: Vec<Value>) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        batch_decompile_with_idat(&session.database_path, &addrs)
    }

    fn search_pseudocode(&self, pattern: &str, limit: usize) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        search_pseudocode_with_idat(&session.database_path, pattern, limit)
    }

    fn diff_pseudocode(&self, addr1: u64, addr2: u64) -> Result<Value, ToolError> {
        let session = self.session.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        diff_pseudocode_with_idat(&session.database_path, addr1, addr2)
    }
}

pub fn run_worker() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    let mut worker = CompatWorker::default();
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: RpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(err) => {
                let resp = RpcResponse::err("null", -32700, format!("Parse error: {err}"));
                write_response(&mut writer, &resp)?;
                continue;
            }
        };

        let response = dispatch_request(&mut worker, &req);
        write_response(&mut writer, &response)?;

        if req.method == "shutdown" {
            break;
        }
    }

    Ok(())
}

fn dispatch_request(worker: &mut CompatWorker, req: &RpcRequest) -> RpcResponse {
    let method = primary_name_for(req.method.as_str());
    let params = &req.params;

    let result: Result<Value, ToolError> = match method {
        "open" => {
            let path = params["path"].as_str().unwrap_or_default();
            let auto_analyse = params["auto_analyse"].as_bool().unwrap_or(true);
            let load_debug_info = params["load_debug_info"].as_bool().unwrap_or(false);
            let debug_info_path = params["debug_info_path"].as_str().map(String::from);
            let debug_info_verbose = params["debug_info_verbose"].as_bool().unwrap_or(false);
            let force = params["force"].as_bool().unwrap_or(false);
            let file_type = params["file_type"].as_str().map(String::from);
            let extra_args = params["extra_args"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            worker
                .open(
                    path,
                    auto_analyse,
                    load_debug_info,
                    debug_info_path,
                    debug_info_verbose,
                    force,
                    file_type,
                    extra_args,
                )
                .and_then(to_json_value)
        }
        "close" => {
            worker.close();
            Ok(json!({ "ok": true }))
        }
        "shutdown" => {
            worker.close();
            Ok(json!({ "ok": true }))
        }
        "get_analysis_status" => worker.analysis_status().and_then(to_json_value),
        "list_functions" => {
            let offset = params["offset"].as_u64().unwrap_or(0) as usize;
            let limit = params["limit"].as_u64().unwrap_or(100) as usize;
            let filter = params["filter"].as_str().map(ToOwned::to_owned);
            worker
                .list_functions(offset, limit, filter)
                .and_then(to_json_value)
        }
        "get_function_by_name" => {
            let name = params["name"]
                .as_str()
                .ok_or_else(|| ToolError::InvalidParams("missing name".to_string()));
            match name {
                Ok(name) => worker.resolve_function(name),
                Err(err) => Err(err),
            }
        }
        "get_function_at_address" => {
            let addr = params.get("address").and_then(parse_address_value);
            let name = params["target_name"].as_str().map(ToOwned::to_owned);
            let offset = params["offset"].as_u64().unwrap_or(0);
            worker.function_at(addr, name, offset)
        }
        "get_address_info" => {
            let addr = params.get("address").and_then(parse_address_value);
            let name = params["target_name"].as_str().map(ToOwned::to_owned);
            let offset = params["offset"].as_u64().unwrap_or(0);
            worker.addr_info(addr, name, offset)
        }
        "disassemble" => {
            let addr = params
                .get("address")
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing address".to_string()));
            let count = params["count"].as_u64().unwrap_or(10) as usize;
            match addr {
                Ok(addr) => worker
                    .disasm(addr, count)
                    .map(|text| json!({ "disasm": text })),
                Err(err) => Err(err),
            }
        }
        "disassemble_function" => {
            let name = params["name"]
                .as_str()
                .ok_or_else(|| ToolError::InvalidParams("missing name".to_string()));
            let count = params["count"].as_u64().unwrap_or(10) as usize;
            match name {
                Ok(name) => worker
                    .disasm_by_name(name, count)
                    .map(|text| json!({ "disasm": text })),
                Err(err) => Err(err),
            }
        }
        "disassemble_function_at" => {
            let addr = params.get("address").and_then(parse_address_value);
            let name = params["target_name"].as_str().map(ToOwned::to_owned);
            let offset = params["offset"].as_u64().unwrap_or(0);
            let count = params["count"].as_u64().unwrap_or(200) as usize;
            worker
                .disasm_function_at(addr, name, offset, count)
                .map(|text| json!({ "disasm": text }))
        }
        "decompile_function" => {
            let address = params
                .get("address")
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing address".to_string()));
            match address {
                Ok(addr) => worker.decompile(addr).map(|code| json!({ "code": code })),
                Err(err) => Err(err),
            }
        }
        "list_segments" => worker.segments(),
        "list_strings" => {
            let offset = params["offset"].as_u64().unwrap_or(0) as usize;
            let limit = params["limit"].as_u64().unwrap_or(100) as usize;
            let query = params["query"]
                .as_str()
                .map(ToOwned::to_owned)
                .or_else(|| params["filter"].as_str().map(ToOwned::to_owned));
            worker.strings(offset, limit, query)
        }
        "read_bytes" => {
            let addr = params
                .get("address")
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing address".to_string()));
            let size = params["size"].as_u64().unwrap_or(0) as usize;
            match addr {
                Ok(addr) => worker.get_bytes(addr, size),
                Err(err) => Err(err),
            }
        }
        "get_xrefs_to" => {
            let addr = params
                .get("address")
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing address".to_string()));
            match addr {
                Ok(addr) => worker.xrefs_to(addr),
                Err(err) => Err(err),
            }
        }
        "get_xrefs_from" => {
            let addr = params
                .get("address")
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing address".to_string()));
            match addr {
                Ok(addr) => worker.xrefs_from(addr),
                Err(err) => Err(err),
            }
        }
        "list_imports" => {
            let offset = params["offset"].as_u64().unwrap_or(0) as usize;
            let limit = params["limit"].as_u64().unwrap_or(100) as usize;
            worker.imports(offset, limit)
        }
        "list_exports" => {
            let offset = params["offset"].as_u64().unwrap_or(0) as usize;
            let limit = params["limit"].as_u64().unwrap_or(100) as usize;
            worker.exports(offset, limit)
        }
        "list_entry_points" => worker.entrypoints(),
        "get_database_info" => worker.database_info(),
        "list_globals" => {
            let query = params["query"].as_str().map(ToOwned::to_owned);
            let offset = params["offset"].as_u64().unwrap_or(0) as usize;
            let limit = params["limit"].as_u64().unwrap_or(100) as usize;
            worker.list_globals(query, offset, limit)
        }
        "read_string" => {
            let addr = params
                .get("address")
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing address".to_string()));
            let max_len = params["max_len"].as_u64().unwrap_or(1024) as usize;
            match addr {
                Ok(addr) => worker.read_string(addr, max_len),
                Err(err) => Err(err),
            }
        }
        "read_int" => {
            let addr = params
                .get("address")
                .or_else(|| params.get("addr"))
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing address".to_string()));
            let size = params["size"].as_u64().unwrap_or(4) as usize;
            match addr {
                Ok(addr) => worker.read_int(addr, size),
                Err(err) => Err(err),
            }
        }
        "search_text" => {
            let text = params["text"].as_str().unwrap_or_default().to_string();
            let max_results = params["max_results"].as_u64().unwrap_or(100) as usize;
            worker.search_text(text, max_results)
        }
        "search_bytes" => {
            let pattern = params["patterns"]
                .as_str()
                .map(ToOwned::to_owned)
                .or_else(|| params["pattern"].as_str().map(ToOwned::to_owned))
                .unwrap_or_default();
            let max_results = params["limit"]
                .as_u64()
                .or_else(|| params["max_results"].as_u64())
                .unwrap_or(100) as usize;
            worker.search_bytes(pattern, max_results)
        }
        "run_script" => {
            let code = params["code"].as_str().unwrap_or_default();
            worker.run_script(code)
        }
        "get_pseudocode_at" => {
            let addr = params
                .get("address")
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing address".to_string()));
            let end_addr = params.get("end_address").and_then(parse_address_value);
            match addr {
                Ok(addr) => worker.pseudocode_at(addr, end_addr),
                Err(err) => Err(err),
            }
        }
        "batch_decompile" => {
            let addrs = if let Some(arr) = params["addresses"].as_array() {
                arr.clone()
            } else if !params["addresses"].is_null() {
                vec![params["addresses"].clone()]
            } else {
                vec![]
            };
            worker.batch_decompile(addrs)
        }
        "search_pseudocode" => {
            let pattern = params["pattern"].as_str().unwrap_or_default();
            let limit = params["limit"].as_u64().unwrap_or(20).min(100) as usize;
            worker.search_pseudocode(pattern, limit)
        }
        "diff_pseudocode" => {
            let addr1 = params
                .get("addr1")
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing addr1".to_string()));
            let addr2 = params
                .get("addr2")
                .and_then(parse_address_value)
                .ok_or_else(|| ToolError::InvalidAddress("missing addr2".to_string()));
            match (addr1, addr2) {
                (Ok(addr1), Ok(addr2)) => worker.diff_pseudocode(addr1, addr2),
                (Err(err), _) | (_, Err(err)) => Err(err),
            }
        }
        _ => Err(ToolError::NotSupported(format!(
            "backend idat-compat does not support method {method}"
        ))),
    };

    match result {
        Ok(value) => RpcResponse::ok(&req.id, value),
        Err(err) => RpcResponse::err(&req.id, -32000, err.to_string()),
    }
}

fn write_response(
    writer: &mut BufWriter<std::io::StdoutLock<'_>>,
    resp: &RpcResponse,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(resp)?;
    writer.write_all(json.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn to_json_value<T: serde::Serialize>(value: T) -> Result<Value, ToolError> {
    serde_json::to_value(value).map_err(|err| ToolError::IdaError(err.to_string()))
}

fn parse_address_value(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }

    if let Some(text) = value.as_str() {
        let text = text.trim();
        if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16).ok();
        }
        return text.parse::<u64>().ok();
    }

    None
}

fn create_or_open_database(
    input_path: &Path,
    database_path: &Path,
    _auto_analyse: bool,
) -> Result<DbInfo, ToolError> {
    if let Some(existing) = existing_database_path(database_path) {
        return inspect_database(&existing);
    }

    if let Some(parent) = database_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| ToolError::IdaError(format!("failed to create cache dir: {err}")))?;
    }

    let output_path = temp_path("open-db-info", "json");
    let script = format!(
        "{}\n{}",
        python_prelude(&output_path, database_path),
        r#"
result = collect_db_info()
write_result(result)
exit_ok()
"#
    );

    run_idat_script(input_path, Some(database_path), &script)?;
    let _actual_database = existing_database_path(database_path).ok_or_else(|| {
        ToolError::IdaError(format!(
            "idat completed but no database artifact was found for {}",
            database_path.display()
        ))
    })?;
    read_db_info(&output_path)
}

fn inspect_database(database_path: &Path) -> Result<DbInfo, ToolError> {
    let output_path = temp_path("inspect-db-info", "json");
    let script = format!(
        "{}\n{}",
        python_prelude(&output_path, database_path),
        r#"
result = collect_db_info()
write_result(result)
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    read_db_info(&output_path)
}

fn list_functions_with_idat(
    database_path: &Path,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> Result<FunctionListResult, ToolError> {
    let output_path = temp_path("list-functions", "json");
    let filter_literal = filter
        .map(escape_python_string)
        .map(|value| format!("'{value}'"))
        .unwrap_or_else(|| "None".to_string());
    let script = format!(
        "{}\nOFFSET = {offset}\nLIMIT = {limit}\nFILTER = {filter_literal}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_funcs

functions = []
for i in range(ida_funcs.get_func_qty()):
    func = ida_funcs.getn_func(i)
    if not func:
        continue
    name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
    if FILTER and FILTER not in name:
        continue
    functions.append({
        "address": hex(func.start_ea),
        "name": name,
        "size": int(func.end_ea - func.start_ea),
    })

total = len(functions)
page = functions[OFFSET:OFFSET + LIMIT]
next_offset = OFFSET + len(page)
if next_offset >= total:
    next_offset = None

write_result({
    "functions": page,
    "total": total,
    "next_offset": next_offset,
})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    let data = fs::read_to_string(&output_path)
        .map_err(|err| ToolError::IdaError(format!("failed to read list output: {err}")))?;
    serde_json::from_str(&data)
        .map_err(|err| ToolError::IdaError(format!("invalid list_functions json: {err}")))
}

fn resolve_function_with_idat(database_path: &Path, query: &str) -> Result<Value, ToolError> {
    let output_path = temp_path("resolve-function", "json");
    let query_literal = escape_python_string(query);
    let script = format!(
        "{}\nQUERY = '{}'\n{}",
        python_prelude(&output_path, database_path),
        query_literal,
        r#"
import ida_funcs

match = None
for i in range(ida_funcs.get_func_qty()):
    func = ida_funcs.getn_func(i)
    if not func:
        continue
    name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
    if name == QUERY or QUERY in name:
        match = {
            "address": hex(func.start_ea),
            "name": name,
            "size": int(func.end_ea - func.start_ea),
        }
        break

write_result(match if match else {"error": f"Function not found: {QUERY}"})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::FunctionNameNotFound(
            error.replace("Function not found: ", ""),
        ));
    }
    Ok(value)
}

fn function_at_with_idat(
    database_path: &Path,
    addr: Option<u64>,
    name: Option<String>,
    offset: u64,
) -> Result<Value, ToolError> {
    let output_path = temp_path("function-at", "json");
    let addr_literal = addr
        .map(|ea| ea.to_string())
        .unwrap_or_else(|| "None".to_string());
    let name_literal = name
        .as_deref()
        .map(escape_python_string)
        .map(|value| format!("'{value}'"))
        .unwrap_or_else(|| "None".to_string());
    let script = format!(
        "{}\nADDR = {addr_literal}\nNAME = {name_literal}\nOFFSET = {offset}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_funcs

target = ADDR
if target is None and NAME is not None:
    for i in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(i)
        if not func:
            continue
        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        if func_name == NAME or NAME in func_name:
            target = func.start_ea + OFFSET
            break

if target is None:
    write_result({"error": "address or name required"})
    exit_ok()

func = ida_funcs.get_func(target)
if not func:
    write_result({"error": f"Function not found at {hex(target)}"})
    exit_ok()

name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
write_result({
    "address": hex(target),
    "name": name,
    "start": hex(func.start_ea),
    "end": hex(func.end_ea),
    "size": int(func.end_ea - func.start_ea),
})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::IdaError(error.to_string()));
    }
    Ok(value)
}

fn disasm_with_idat(database_path: &Path, addr: u64, count: usize) -> Result<String, ToolError> {
    let output_path = temp_path("disasm", "json");
    let script = format!(
        "{}\nADDR = {addr}\nCOUNT = {count}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import idc

lines = []
ea = ADDR
for _ in range(COUNT):
    text = idc.generate_disasm_line(ea, 0)
    if not text:
        break
    lines.append(f"{hex(ea)}:\t{text}")
    next_ea = idc.next_head(ea)
    if next_ea == idc.BADADDR or next_ea <= ea:
        break
    ea = next_ea

write_result({"disasm": "\n".join(lines)})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    value
        .get("disasm")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ToolError::IdaError("missing disassembly output".to_string()))
}

fn disasm_by_name_with_idat(
    database_path: &Path,
    name: &str,
    count: usize,
) -> Result<String, ToolError> {
    let output_path = temp_path("disasm-name", "json");
    let name_literal = escape_python_string(name);
    let script = format!(
        "{}\nNAME = '{}'\nCOUNT = {count}\n{}",
        python_prelude(&output_path, database_path),
        name_literal,
        r#"
import ida_funcs
import idc

target = None
for i in range(ida_funcs.get_func_qty()):
    func = ida_funcs.getn_func(i)
    if not func:
        continue
    func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
    if func_name == NAME or NAME in func_name:
        target = func.start_ea
        break

if target is None:
    write_result({"error": f"Function not found: {NAME}"})
    exit_ok()

lines = []
ea = target
for _ in range(COUNT):
    text = idc.generate_disasm_line(ea, 0)
    if not text:
        break
    lines.append(f"{hex(ea)}:\t{text}")
    next_ea = idc.next_head(ea)
    if next_ea == idc.BADADDR or next_ea <= ea:
        break
    ea = next_ea

write_result({"disasm": "\n".join(lines)})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::FunctionNameNotFound(
            error.replace("Function not found: ", ""),
        ));
    }
    value
        .get("disasm")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ToolError::IdaError("missing disassembly output".to_string()))
}

fn disasm_function_at_with_idat(
    database_path: &Path,
    addr: Option<u64>,
    name: Option<String>,
    offset: u64,
    count: usize,
) -> Result<String, ToolError> {
    let output_path = temp_path("disasm-function-at", "json");
    let addr_literal = addr
        .map(|ea| ea.to_string())
        .unwrap_or_else(|| "None".to_string());
    let name_literal = name
        .as_deref()
        .map(escape_python_string)
        .map(|value| format!("'{value}'"))
        .unwrap_or_else(|| "None".to_string());
    let script = format!(
        "{}\nADDR = {addr_literal}\nNAME = {name_literal}\nOFFSET = {offset}\nCOUNT = {count}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_funcs
import idc

target = ADDR
if target is None and NAME is not None:
    for i in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(i)
        if not func:
            continue
        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        if func_name == NAME or NAME in func_name:
            target = func.start_ea + OFFSET
            break

if target is None:
    write_result({"error": "address or name required"})
    exit_ok()

func = ida_funcs.get_func(target)
if not func:
    write_result({"error": f"Function not found at {hex(target)}"})
    exit_ok()

lines = []
ea = func.start_ea
while ea != idc.BADADDR and ea < func.end_ea and len(lines) < COUNT:
    text = idc.generate_disasm_line(ea, 0)
    if text:
        lines.append(f"{hex(ea)}:\t{text}")
    next_ea = idc.next_head(ea)
    if next_ea == idc.BADADDR or next_ea <= ea:
        break
    ea = next_ea

write_result({"disasm": "\n".join(lines)})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::IdaError(error.to_string()));
    }
    value
        .get("disasm")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ToolError::IdaError("missing disassembly output".to_string()))
}

fn segments_with_idat(database_path: &Path) -> Result<Value, ToolError> {
    let output_path = temp_path("segments", "json");
    let script = format!(
        "{}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_segment

segments = []
for index in range(ida_segment.get_segm_qty()):
    seg = ida_segment.getnseg(index)
    if not seg:
        continue
    perms = []
    if seg.perm & ida_segment.SEGPERM_READ:
        perms.append("r")
    if seg.perm & ida_segment.SEGPERM_WRITE:
        perms.append("w")
    if seg.perm & ida_segment.SEGPERM_EXEC:
        perms.append("x")
    segments.append({
        "name": ida_segment.get_segm_name(seg) or "",
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "size": int(seg.end_ea - seg.start_ea),
        "permissions": "".join(perms),
        "type": str(seg.type),
        "bitness": 64 if seg.bitness == 2 else (32 if seg.bitness == 1 else 16),
    })

write_result(segments)
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn strings_with_idat(
    database_path: &Path,
    offset: usize,
    limit: usize,
    query: Option<&str>,
) -> Result<Value, ToolError> {
    let output_path = temp_path("strings", "json");
    let query_literal = query
        .map(escape_python_string)
        .map(|value| format!("'{value}'"))
        .unwrap_or_else(|| "None".to_string());
    let script = format!(
        "{}\nOFFSET = {offset}\nLIMIT = {limit}\nQUERY = {query_literal}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import idautils

items = []
for item in idautils.Strings():
    try:
        content = str(item)
    except Exception:
        content = ""
    if QUERY and QUERY not in content:
        continue
    items.append({
        "address": hex(item.ea),
        "content": content,
        "length": int(item.length),
    })

total = len(items)
page = items[OFFSET:OFFSET + LIMIT]
next_offset = OFFSET + len(page)
if next_offset >= total:
    next_offset = None

write_result({
    "strings": page,
    "total": total,
    "next_offset": next_offset,
})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn get_bytes_with_idat(database_path: &Path, addr: u64, size: usize) -> Result<Value, ToolError> {
    let output_path = temp_path("bytes", "json");
    let script = format!(
        "{}\nADDR = {addr}\nSIZE = {size}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_bytes

data = ida_bytes.get_bytes(ADDR, SIZE)
if data is None:
    write_result({"error": f"Address out of range: {hex(ADDR)}"})
else:
    write_result({
        "address": hex(ADDR),
        "bytes": data.hex(),
        "length": len(data),
    })
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::IdaError(error.to_string()));
    }
    Ok(value)
}

fn addr_info_with_idat(
    database_path: &Path,
    addr: Option<u64>,
    name: Option<String>,
    offset: u64,
) -> Result<Value, ToolError> {
    let output_path = temp_path("addr-info", "json");
    let addr_literal = addr
        .map(|ea| ea.to_string())
        .unwrap_or_else(|| "None".to_string());
    let name_literal = name
        .as_deref()
        .map(escape_python_string)
        .map(|value| format!("'{value}'"))
        .unwrap_or_else(|| "None".to_string());
    let script = format!(
        "{}\nADDR = {addr_literal}\nNAME = {name_literal}\nOFFSET = {offset}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_funcs
import ida_name
import ida_segment

target = ADDR
if target is None and NAME is not None:
    for i in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(i)
        if not func:
            continue
        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        if func_name == NAME or NAME in func_name:
            target = func.start_ea + OFFSET
            break

if target is None:
    write_result({"error": "address or name required"})
    exit_ok()

seg = ida_segment.getseg(target)
func = ida_funcs.get_func(target)
symbol_name = ida_name.get_name(target)

segment = None
if seg:
    perms = []
    if seg.perm & ida_segment.SEGPERM_READ:
        perms.append("r")
    if seg.perm & ida_segment.SEGPERM_WRITE:
        perms.append("w")
    if seg.perm & ida_segment.SEGPERM_EXEC:
        perms.append("x")
    segment = {
        "name": ida_segment.get_segm_name(seg) or "",
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "size": int(seg.end_ea - seg.start_ea),
        "permissions": "".join(perms),
        "type": str(seg.type),
        "bitness": 64 if seg.bitness == 2 else (32 if seg.bitness == 1 else 16),
    }

function = None
if func:
    function = {
        "address": hex(target),
        "name": ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}",
        "start": hex(func.start_ea),
        "end": hex(func.end_ea),
        "size": int(func.end_ea - func.start_ea),
    }

symbol = None
if symbol_name:
    symbol = {
        "name": symbol_name,
        "address": hex(target),
        "delta": 0,
        "exact": True,
        "is_public": True,
        "is_weak": False,
    }

write_result({
    "address": hex(target),
    "segment": segment,
    "function": function,
    "symbol": symbol,
})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::IdaError(error.to_string()));
    }
    Ok(value)
}

fn xrefs_with_idat(database_path: &Path, addr: u64, to: bool) -> Result<Value, ToolError> {
    let output_path = temp_path("xrefs", "json");
    let mode = if to { "to" } else { "from" };
    let script = format!(
        "{}\nADDR = {addr}\nMODE = '{}'\n{}",
        python_prelude(&output_path, database_path),
        mode,
        r#"
import idautils

items = []
xrefs = idautils.XrefsTo(ADDR, 0) if MODE == "to" else idautils.XrefsFrom(ADDR, 0)
for xref in xrefs:
    items.append({
        "from": hex(xref.frm),
        "to": hex(xref.to),
        "type": str(xref.type),
        "is_code": bool(getattr(xref, "iscode", False)),
    })

write_result(items)
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn imports_with_idat(
    database_path: &Path,
    offset: usize,
    limit: usize,
) -> Result<Value, ToolError> {
    let output_path = temp_path("imports", "json");
    let script = format!(
        "{}\nOFFSET = {offset}\nLIMIT = {limit}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_nalt

items = []

def collect_imports():
    qty = ida_nalt.get_import_module_qty()
    ordinal_counter = 0
    for idx in range(qty):
        def cb(ea, name, ordinal):
            nonlocal ordinal_counter
            items.append({
                "address": hex(ea),
                "name": name or f"ord_{ordinal}",
                "ordinal": ordinal_counter,
            })
            ordinal_counter += 1
            return True
        ida_nalt.enum_import_names(idx, cb)

collect_imports()
write_result(items[OFFSET:OFFSET + LIMIT])
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn exports_with_idat(
    database_path: &Path,
    offset: usize,
    limit: usize,
) -> Result<Value, ToolError> {
    let output_path = temp_path("exports", "json");
    let script = format!(
        "{}\nOFFSET = {offset}\nLIMIT = {limit}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_entry

items = []
qty = ida_entry.get_entry_qty()
for idx in range(qty):
    ordinal = ida_entry.get_entry_ordinal(idx)
    ea = ida_entry.get_entry(ordinal)
    name = ida_entry.get_entry_name(ordinal) or f"entry_{ordinal}"
    items.append({
        "address": hex(ea),
        "name": name,
        "is_public": True,
    })

write_result(items[OFFSET:OFFSET + LIMIT])
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn entrypoints_with_idat(database_path: &Path) -> Result<Value, ToolError> {
    let output_path = temp_path("entrypoints", "json");
    let script = format!(
        "{}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_entry

items = []
qty = ida_entry.get_entry_qty()
for idx in range(qty):
    ordinal = ida_entry.get_entry_ordinal(idx)
    ea = ida_entry.get_entry(ordinal)
    items.append(hex(ea))

write_result(items)
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn database_info_with_idat(database_path: &Path) -> Result<Value, ToolError> {
    let output_path = temp_path("db-info", "json");
    let script = format!(
        "{}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_funcs
import ida_ida

bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
base_address = None
try:
    base_address = hex(ida_ida.inf_get_baseaddr())
except Exception:
    pass

write_result({
    "file_type": "idat-compat",
    "processor": "metapc",
    "bits": bits,
    "function_count": int(ida_funcs.get_func_qty()),
    "input_file_path": DB_PATH,
    "base_address": base_address,
})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn globals_with_idat(
    database_path: &Path,
    query: Option<&str>,
    offset: usize,
    limit: usize,
) -> Result<Value, ToolError> {
    let output_path = temp_path("globals", "json");
    let query_literal = query
        .map(escape_python_string)
        .map(|value| format!("'{value}'"))
        .unwrap_or_else(|| "None".to_string());
    let script = format!(
        "{}\nQUERY = {query_literal}\nOFFSET = {offset}\nLIMIT = {limit}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_funcs
import idautils

items = []
for ea, name in idautils.Names():
    if ida_funcs.get_func(ea):
        continue
    if QUERY and QUERY.lower() not in name.lower():
        continue
    items.append({
        "address": hex(ea),
        "name": name,
        "is_public": True,
        "is_weak": False,
    })

total = len(items)
page = items[OFFSET:OFFSET + LIMIT]
next_offset = OFFSET + len(page)
if next_offset >= total:
    next_offset = None

write_result({
    "globals": page,
    "total": total,
    "next_offset": next_offset,
})
exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn read_string_with_idat(
    database_path: &Path,
    addr: u64,
    max_len: usize,
) -> Result<Value, ToolError> {
    let output_path = temp_path("read-string", "json");
    let script = format!(
        "{}\nADDR = {addr}\nMAX_LEN = {max_len}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_bytes
import idc

strtype = idc.get_str_type(ADDR)
data = ida_bytes.get_strlit_contents(ADDR, MAX_LEN, strtype)
if data is None:
    data = ida_bytes.get_bytes(ADDR, MAX_LEN)

if data is None:
    write_result({"error": f"Address out of range: {hex(ADDR)}"})
else:
    if isinstance(data, bytes):
        text = data.decode('utf-8', 'replace').rstrip('\x00')
    else:
        text = str(data)
    write_result({
        "address": hex(ADDR),
        "string": text,
        "length": len(text),
    })
exit_ok()
"#
    );
    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::IdaError(error.to_string()));
    }
    Ok(value)
}

fn read_int_with_idat(database_path: &Path, addr: u64, size: usize) -> Result<Value, ToolError> {
    let output_path = temp_path("read-int", "json");
    let script = format!(
        "{}\nADDR = {addr}\nSIZE = {size}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_bytes

data = ida_bytes.get_bytes(ADDR, SIZE)
if data is None:
    write_result({"error": f"Address out of range: {hex(ADDR)}"})
else:
    value = int.from_bytes(data, 'little')
    write_result({
        "address": hex(ADDR),
        "value": value,
        "hex": hex(value),
        "bytes": data.hex(),
    })
exit_ok()
"#
    );
    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::IdaError(error.to_string()));
    }
    Ok(value)
}

fn search_text_with_idat(
    database_path: &Path,
    text: &str,
    max_results: usize,
) -> Result<Value, ToolError> {
    let output_path = temp_path("search-text", "json");
    let query = escape_python_string(text);
    let script = format!(
        "{}\nQUERY = '{}'\nMAX_RESULTS = {max_results}\n{}",
        python_prelude(&output_path, database_path),
        query,
        r#"
import idautils
import idc

matches = []

for item in idautils.Strings():
    if len(matches) >= MAX_RESULTS:
        break
    try:
        content = str(item)
    except Exception:
        content = ""
    if QUERY in content:
        matches.append({"address": hex(item.ea), "text": content, "kind": "string"})

for ea, name in idautils.Names():
    if len(matches) >= MAX_RESULTS:
        break
    if QUERY in name:
        matches.append({"address": hex(ea), "text": name, "kind": "name"})

for func_ea in idautils.Functions():
    if len(matches) >= MAX_RESULTS:
        break
    end = idc.find_func_end(func_ea)
    ea = func_ea
    while ea != idc.BADADDR and ea < end and len(matches) < MAX_RESULTS:
        line = idc.generate_disasm_line(ea, 0) or ""
        if QUERY in line:
            matches.append({"address": hex(ea), "text": line, "kind": "disasm"})
        next_ea = idc.next_head(ea)
        if next_ea == idc.BADADDR or next_ea <= ea:
            break
        ea = next_ea

write_result({"matches": matches, "count": len(matches)})
exit_ok()
"#
    );
    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn search_bytes_with_idat(
    database_path: &Path,
    pattern: &str,
    max_results: usize,
) -> Result<Value, ToolError> {
    let output_path = temp_path("search-bytes", "json");
    let pattern_literal = escape_python_string(pattern);
    let script = format!(
        "{}\nPATTERN = '{}'\nMAX_RESULTS = {max_results}\n{}",
        python_prelude(&output_path, database_path),
        pattern_literal,
        r#"
import ida_bytes
import ida_segment

tokens = [tok for tok in PATTERN.replace(',', ' ').split() if tok]
needle = []
for tok in tokens:
    if tok in ('??', '?'):
        needle.append(None)
    else:
        needle.append(int(tok, 16))

matches = []
for i in range(ida_segment.get_segm_qty()):
    if len(matches) >= MAX_RESULTS:
        break
    seg = ida_segment.getnseg(i)
    if not seg:
        continue
    data = ida_bytes.get_bytes(seg.start_ea, int(seg.end_ea - seg.start_ea))
    if not data:
        continue
    span = len(needle)
    for idx in range(0, len(data) - span + 1):
        if len(matches) >= MAX_RESULTS:
            break
        ok = True
        for j, wanted in enumerate(needle):
            if wanted is not None and data[idx + j] != wanted:
                ok = False
                break
        if ok:
            ea = seg.start_ea + idx
            matches.append({"address": hex(ea), "bytes": data[idx:idx+span].hex()})

write_result({"matches": matches, "count": len(matches)})
exit_ok()
"#
    );
    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn run_script_with_idat(database_path: &Path, code: &str) -> Result<Value, ToolError> {
    let output_path = temp_path("run-script", "json");
    let user_code_path = temp_path("user-script", "py");
    fs::write(&user_code_path, code)
        .map_err(|err| ToolError::IdaError(format!("failed to write user script: {err}")))?;
    let user_code_literal = escape_python_string(&user_code_path.display().to_string());
    let script = format!(
        "{}\nUSER_CODE = r'{}'\n{}",
        python_prelude(&output_path, database_path),
        user_code_literal,
        r#"
import contextlib
import io
import traceback

stdout_buf = io.StringIO()
stderr_buf = io.StringIO()
success = True
error = None
error_summary = None
error_kind = None

try:
    with open(USER_CODE, 'r', encoding='utf-8') as f:
        user_code = f.read()
    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
        exec(compile(user_code, USER_CODE, 'exec'), {})
except Exception as exc:
    success = False
    error = str(exc)
    error_summary = f"{exc.__class__.__name__}: {exc}"
    error_kind = exc.__class__.__name__
    traceback.print_exc(file=stderr_buf)

write_result({
    "success": success,
    "stdout": stdout_buf.getvalue(),
    "stderr": stderr_buf.getvalue(),
    "error": error,
    "error_summary": error_summary,
    "error_kind": error_kind,
})
exit_ok()
"#
    );
    let result =
        run_idat_script(database_path, None, &script).and_then(|_| read_json_value(&output_path));
    let _ = fs::remove_file(&user_code_path);
    result
}

fn pseudocode_at_with_idat(
    database_path: &Path,
    addr: u64,
    end_addr: Option<u64>,
) -> Result<Value, ToolError> {
    let output_path = temp_path("pseudocode-at", "json");
    let end_literal = end_addr
        .map(|ea| ea.to_string())
        .unwrap_or_else(|| "None".to_string());
    let script = format!(
        "{}\nADDR = {addr}\nEND_ADDR = {end_literal}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_funcs
import ida_hexrays

if not ida_hexrays.init_hexrays_plugin():
    write_result({"error": "Decompiler not available"})
    exit_ok()

func = ida_funcs.get_func(ADDR)
if not func:
    write_result({"error": f"Function not found at {hex(ADDR)}"})
    exit_ok()

cfunc = ida_hexrays.decompile(func)
lines = [str(line.line) for line in cfunc.get_pseudocode()]
write_result({
    "function_start": hex(func.start_ea),
    "function_end": hex(func.end_ea),
    "query_start": hex(ADDR),
    "query_end": hex(END_ADDR) if END_ADDR is not None else None,
    "eamap_ready": False,
    "statements": [{
        "address": hex(ADDR),
        "text": str(cfunc),
        "bounds": None,
    }],
    "pseudocode_lines": lines,
})
exit_ok()
"#
    );
    run_idat_script(database_path, None, &script)?;
    let value = read_json_value(&output_path)?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::IdaError(error.to_string()));
    }
    Ok(value)
}

fn batch_decompile_with_idat(database_path: &Path, addrs: &[Value]) -> Result<Value, ToolError> {
    let output_path = temp_path("batch-decompile", "json");
    let addrs_json = serde_json::to_string(addrs)
        .map_err(|err| ToolError::IdaError(format!("failed to encode addresses: {err}")))?;
    let addrs_literal = escape_python_string(&addrs_json);
    let script = format!(
        "{}\nADDRS = json.loads(r\"{}\")\n{}",
        python_prelude(&output_path, database_path),
        addrs_literal,
        r#"
import ida_funcs
import ida_hexrays

results = []
ida_hexrays.init_hexrays_plugin()

for raw in ADDRS:
    if isinstance(raw, str) and raw.lower().startswith('0x'):
        ea = int(raw, 16)
    else:
        ea = int(raw)
    func = ida_funcs.get_func(ea)
    if not func:
        results.append({"address": raw, "error": "function not found", "success": False})
        continue
    try:
        cfunc = ida_hexrays.decompile(func)
        results.append({"address": raw, "pseudocode": str(cfunc), "success": True})
    except Exception as exc:
        results.append({"address": raw, "error": str(exc), "success": False})

write_result(results)
exit_ok()
"#
    );
    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn search_pseudocode_with_idat(
    database_path: &Path,
    pattern: &str,
    limit: usize,
) -> Result<Value, ToolError> {
    let output_path = temp_path("search-pseudocode", "json");
    let pattern_literal = escape_python_string(pattern);
    let script = format!(
        "{}\nPATTERN = '{}'\nLIMIT = {limit}\n{}",
        python_prelude(&output_path, database_path),
        pattern_literal,
        r#"
import ida_funcs
import ida_hexrays

matches = []
total_searched = 0
errors = 0
ida_hexrays.init_hexrays_plugin()

for i in range(ida_funcs.get_func_qty()):
    if len(matches) >= LIMIT:
        break
    func = ida_funcs.getn_func(i)
    if not func:
        continue
    total_searched += 1
    name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
    try:
        cfunc = ida_hexrays.decompile(func)
        code = str(cfunc)
        if PATTERN in code:
            matches.append({"address": hex(func.start_ea), "name": name, "pseudocode": code})
    except Exception:
        errors += 1

write_result({
    "pattern": PATTERN,
    "matches": matches,
    "total_searched": total_searched,
    "decompile_errors": errors,
})
exit_ok()
"#
    );
    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn diff_pseudocode_with_idat(
    database_path: &Path,
    addr1: u64,
    addr2: u64,
) -> Result<Value, ToolError> {
    let output_path = temp_path("diff-pseudocode", "json");
    let script = format!(
        "{}\nADDR1 = {addr1}\nADDR2 = {addr2}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_funcs
import ida_hexrays

ida_hexrays.init_hexrays_plugin()

def decompile_at(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        raise RuntimeError(f"Function not found at {hex(ea)}")
    return str(ida_hexrays.decompile(func))

code1 = decompile_at(ADDR1)
code2 = decompile_at(ADDR2)
lines1 = code1.splitlines()
lines2 = code2.splitlines()
diff_lines = []
same = 0
different = 0
max_len = max(len(lines1), len(lines2))
for i in range(max_len):
    l1 = lines1[i] if i < len(lines1) else None
    l2 = lines2[i] if i < len(lines2) else None
    if l1 is not None and l2 is not None:
        if l1 == l2:
            diff_lines.append("  " + l1)
            same += 1
        else:
            diff_lines.append("- " + l1)
            diff_lines.append("+ " + l2)
            different += 1
    elif l1 is not None:
        diff_lines.append("- " + l1)
        different += 1
    elif l2 is not None:
        diff_lines.append("+ " + l2)
        different += 1

total = same + different
ratio = 1.0 if total == 0 else same / total
write_result({
    "function1": code1,
    "function2": code2,
    "similarity_ratio": round(ratio, 2),
    "diff_lines": diff_lines,
})
exit_ok()
"#
    );
    run_idat_script(database_path, None, &script)?;
    read_json_value(&output_path)
}

fn decompile_with_idat(database_path: &Path, address: u64) -> Result<String, ToolError> {
    let output_path = temp_path("decompile", "json");
    let script = format!(
        "{}\nTARGET_EA = {address}\n{}",
        python_prelude(&output_path, database_path),
        r#"
import ida_funcs
import ida_hexrays

if not ida_hexrays.init_hexrays_plugin():
    write_result({"error": "Decompiler not available"})
    exit_ok()

func = ida_funcs.get_func(TARGET_EA)
if not func:
    write_result({"error": f"Function not found at {hex(TARGET_EA)}"})
    exit_ok()

try:
    cfunc = ida_hexrays.decompile(func)
    write_result({"code": str(cfunc)})
except Exception as exc:
    write_result({"error": str(exc)})

exit_ok()
"#
    );

    run_idat_script(database_path, None, &script)?;
    let data = fs::read_to_string(&output_path)
        .map_err(|err| ToolError::IdaError(format!("failed to read decompile output: {err}")))?;
    let value: Value = serde_json::from_str(&data)
        .map_err(|err| ToolError::IdaError(format!("invalid decompile json: {err}")))?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(ToolError::IdaError(error.to_string()));
    }
    value
        .get("code")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ToolError::IdaError("missing decompile output".to_string()))
}

fn read_db_info(output_path: &Path) -> Result<DbInfo, ToolError> {
    let data = fs::read_to_string(output_path)
        .map_err(|err| ToolError::IdaError(format!("failed to read db info: {err}")))?;
    serde_json::from_str(&data)
        .map_err(|err| ToolError::IdaError(format!("invalid db info json: {err}")))
}

fn read_json_value(output_path: &Path) -> Result<Value, ToolError> {
    let data = fs::read_to_string(output_path)
        .map_err(|err| ToolError::IdaError(format!("failed to read json output: {err}")))?;
    serde_json::from_str(&data)
        .map_err(|err| ToolError::IdaError(format!("invalid json output: {err}")))
}

fn compat_database_hint(store: &IdbStore, input_path: &Path) -> PathBuf {
    let mut path = store.idb_path(input_path);
    path.set_extension("i64");
    path
}

fn existing_database_path(hint: &Path) -> Option<PathBuf> {
    let candidates = [
        hint.to_path_buf(),
        hint.with_extension("id0"),
        hint.with_extension("idb"),
    ];

    candidates.into_iter().find(|path| path.exists())
}

fn run_idat_script(
    target_path: &Path,
    output_database: Option<&Path>,
    script_body: &str,
) -> Result<(), ToolError> {
    let idat = crate::dsc::find_idat()?;
    let script_path = temp_path("idat-script", "py");
    let log_path = temp_path("idat-script", "log");
    fs::write(&script_path, script_body)
        .map_err(|err| ToolError::IdaError(format!("failed to write temp script: {err}")))?;

    let mut cmd = if cfg!(target_os = "macos") {
        let mut cmd = Command::new("/usr/bin/script");
        cmd.arg("-q").arg("/dev/null").arg(&idat);
        cmd
    } else {
        Command::new(&idat)
    };

    cmd.arg("-a-")
        .arg("-A")
        .arg(format!("-S{}", script_path.display()))
        .arg(format!("-L{}", log_path.display()));

    if let Some(output_database) = output_database {
        cmd.arg(format!("-o{}", output_database.display()));
    }

    cmd.arg(target_path);

    let output = cmd
        .output()
        .map_err(|err| ToolError::IdaError(format!("failed to run idat: {err}")))?;

    let _ = fs::remove_file(&script_path);

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let log_tail = fs::read_to_string(&log_path)
        .ok()
        .map(|content| tail_lines(&content, 40))
        .unwrap_or_default();

    let mut message = format!("idat exited with status {}", output.status);
    if !stderr.is_empty() {
        message.push_str(&format!("\nstderr:\n{stderr}"));
    }
    if !stdout.is_empty() {
        message.push_str(&format!("\nstdout:\n{stdout}"));
    }
    if !log_tail.is_empty() {
        message.push_str(&format!("\nlog tail:\n{log_tail}"));
    }

    Err(ToolError::IdaError(message))
}

fn python_prelude(output_path: &Path, database_path: &Path) -> String {
    let output_literal = escape_python_string(&output_path.display().to_string());
    let database_literal = escape_python_string(&database_path.display().to_string());
    format!(
        r#"
import json
import ida_auto
import ida_funcs
import ida_ida
import ida_pro

OUT_PATH = r"{output_literal}"
DB_PATH = r"{database_literal}"

def collect_db_info():
    bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
    return {{
        "path": DB_PATH,
        "file_type": "idat-compat",
        "processor": "metapc",
        "bits": bits,
        "function_count": int(ida_funcs.get_func_qty()),
        "debug_info": None,
        "analysis_status": {{
            "auto_enabled": True,
            "auto_is_ok": True,
            "auto_state": "AU_NONE",
            "auto_state_id": 0,
            "analysis_running": False
        }}
    }}

def write_result(value):
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(value, f)

def exit_ok():
    ida_pro.qexit(0)

ida_auto.auto_wait()
"#
    )
}

fn escape_python_string(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn temp_path(prefix: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "ida-cli-{prefix}-{}-{nanos}.{extension}",
        std::process::id()
    ))
}

fn tail_lines(input: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}
