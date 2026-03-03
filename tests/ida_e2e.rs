use ida_mcp::router::protocol::RpcRequest;
use ida_mcp::rpc_dispatch::dispatch_rpc;
use ida_mcp::{run_ida_loop, IdaWorker, ToolError};
use rstest::{fixture, rstest};
use serde_json::{json, Value};
use std::sync::mpsc;

const REQUEST_QUEUE_CAPACITY: usize = 64;
const ADDR_ADD: &str = "0x100000328";
const ADDR_MAIN: &str = "0x100000348";

fn ida_available() -> bool {
    std::env::var("IDA_TEST").map(|v| v == "1").unwrap_or(false)
}

#[derive(Clone)]
struct SmokeCase {
    method: &'static str,
    params: Value,
    allow_error: bool,
}

#[fixture]
#[once]
fn worker() -> IdaWorker {
    let (tx, rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
    std::thread::spawn(move || {
        run_ida_loop(rx);
    });
    IdaWorker::new(tx)
}

#[fixture]
#[once]
fn open_db(worker: &IdaWorker) -> Value {
    if !ida_available() {
        return json!(null);
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build runtime");

    rt.block_on(async {
        call(
            worker,
            "open",
            json!({
                "path": "test/fixtures/mini.i64",
                "auto_analyse": false,
                "force": true,
            }),
        )
        .await
        .expect("failed to open mini.i64")
    })
}

async fn call(worker: &IdaWorker, method: &str, params: Value) -> Result<Value, ToolError> {
    let req = RpcRequest::new("test", method, params);
    dispatch_rpc(&req, worker).await
}

fn smoke_cases() -> Vec<SmokeCase> {
    vec![
        SmokeCase {
            method: "load_debug_info",
            params: json!({"verbose": false}),
            allow_error: true,
        },
        SmokeCase {
            method: "get_analysis_status",
            params: json!({}),
            allow_error: false,
        },
        SmokeCase {
            method: "list_functions",
            params: json!({"offset": 0, "limit": 20}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_function_by_name",
            params: json!({"name": "_add"}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_function_prototype",
            params: json!({"address": ADDR_ADD}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_function_at_address",
            params: json!({"address": ADDR_ADD}),
            allow_error: false,
        },
        SmokeCase {
            method: "batch_lookup_functions",
            params: json!({"queries": ["_add", ADDR_MAIN]}),
            allow_error: false,
        },
        SmokeCase {
            method: "export_functions",
            params: json!({"offset": 0, "limit": 20}),
            allow_error: false,
        },
        SmokeCase {
            method: "disassemble",
            params: json!({"address": ADDR_ADD, "count": 6}),
            allow_error: false,
        },
        SmokeCase {
            method: "disassemble_function",
            params: json!({"name": "_add", "count": 6}),
            allow_error: false,
        },
        SmokeCase {
            method: "disassemble_function_at",
            params: json!({"address": ADDR_ADD, "count": 6}),
            allow_error: false,
        },
        SmokeCase {
            method: "decompile_function",
            params: json!({"address": ADDR_ADD}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_pseudocode_at",
            params: json!({"address": ADDR_ADD}),
            allow_error: false,
        },
        SmokeCase {
            method: "list_segments",
            params: json!({}),
            allow_error: false,
        },
        SmokeCase {
            method: "list_strings",
            params: json!({"offset": 0, "limit": 10}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_xrefs_to_string",
            params: json!({"query": "add", "limit": 5, "max_xrefs": 5}),
            allow_error: false,
        },
        SmokeCase {
            method: "list_local_types",
            params: json!({"offset": 0, "limit": 10}),
            allow_error: false,
        },
        SmokeCase {
            method: "declare_c_type",
            params: json!({"decl": "struct E2EDecl { int x; };", "replace": true}),
            allow_error: false,
        },
        SmokeCase {
            method: "apply_type",
            params: json!({"address": ADDR_ADD, "decl": "int __fastcall _add(int a, int b)", "relaxed": true}),
            allow_error: false,
        },
        SmokeCase {
            method: "infer_type",
            params: json!({"address": ADDR_ADD}),
            allow_error: false,
        },
        SmokeCase {
            method: "set_function_prototype",
            params: json!({"address": ADDR_ADD, "prototype": "int __fastcall _add(int a, int b)"}),
            allow_error: false,
        },
        SmokeCase {
            method: "rename_stack_variable",
            params: json!({"func_address": ADDR_MAIN, "name": "var_10", "new_name": "var_10"}),
            allow_error: true,
        },
        SmokeCase {
            method: "set_stack_variable_type",
            params: json!({"func_address": ADDR_MAIN, "name": "var_10", "type_decl": "int"}),
            allow_error: true,
        },
        SmokeCase {
            method: "list_enums",
            params: json!({"offset": 0, "limit": 10}),
            allow_error: false,
        },
        SmokeCase {
            method: "create_enum",
            params: json!({"decl": "enum E2EEnum { E2E_A = 1 };", "replace": true}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_address_info",
            params: json!({"address": ADDR_ADD}),
            allow_error: false,
        },
        SmokeCase {
            method: "create_stack_variable",
            params: json!({"address": ADDR_MAIN, "offset": -4, "var_name": "e2e_tmp", "decl": "int"}),
            allow_error: true,
        },
        SmokeCase {
            method: "delete_stack_variable",
            params: json!({"address": ADDR_MAIN, "var_name": "e2e_tmp"}),
            allow_error: true,
        },
        SmokeCase {
            method: "get_stack_frame",
            params: json!({"address": ADDR_MAIN}),
            allow_error: false,
        },
        SmokeCase {
            method: "list_structs",
            params: json!({"offset": 0, "limit": 10}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_struct_info",
            params: json!({"name": "E2EDecl"}),
            allow_error: true,
        },
        SmokeCase {
            method: "read_struct_at_address",
            params: json!({"address": ADDR_ADD, "name": "E2EDecl"}),
            allow_error: true,
        },
        SmokeCase {
            method: "get_xrefs_to",
            params: json!({"address": ADDR_ADD}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_xrefs_from",
            params: json!({"address": ADDR_MAIN}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_xrefs_to_struct_field",
            params: json!({"name": "E2EDecl", "member_name": "x", "limit": 5}),
            allow_error: true,
        },
        SmokeCase {
            method: "list_imports",
            params: json!({"offset": 0, "limit": 20}),
            allow_error: false,
        },
        SmokeCase {
            method: "list_exports",
            params: json!({"offset": 0, "limit": 20}),
            allow_error: false,
        },
        SmokeCase {
            method: "list_entry_points",
            params: json!({}),
            allow_error: false,
        },
        SmokeCase {
            method: "read_bytes",
            params: json!({"address": ADDR_ADD, "size": 8}),
            allow_error: false,
        },
        SmokeCase {
            method: "read_int",
            params: json!({"address": ADDR_ADD, "size": 4}),
            allow_error: false,
        },
        SmokeCase {
            method: "read_string",
            params: json!({"address": "0x100000000", "max_len": 16}),
            allow_error: true,
        },
        SmokeCase {
            method: "read_global_variable",
            params: json!({"query": "_main"}),
            allow_error: true,
        },
        SmokeCase {
            method: "set_comment",
            params: json!({"address": ADDR_ADD, "comment": "ida-e2e", "repeatable": false}),
            allow_error: false,
        },
        SmokeCase {
            method: "set_function_comment",
            params: json!({"address": ADDR_ADD, "comment": "ida-e2e-fn", "repeatable": false}),
            allow_error: false,
        },
        SmokeCase {
            method: "rename_symbol",
            params: json!({"current_name": "_add", "name": "_add", "flags": 0}),
            allow_error: true,
        },
        SmokeCase {
            method: "batch_rename",
            params: json!({"renames": [
                {"current_name": "_add", "new_name": "_add"},
                {"current_name": "_main", "new_name": "_main"}
            ]}),
            allow_error: true,
        },
        SmokeCase {
            method: "rename_local_variable",
            params: json!({"func_address": ADDR_ADD, "lvar_name": "a1", "new_name": "a1"}),
            allow_error: true,
        },
        SmokeCase {
            method: "set_local_variable_type",
            params: json!({"func_address": ADDR_ADD, "lvar_name": "a1", "type_str": "int"}),
            allow_error: true,
        },
        SmokeCase {
            method: "set_decompiler_comment",
            params: json!({"func_address": ADDR_ADD, "address": ADDR_ADD, "itp": 69, "comment": "ida-e2e"}),
            allow_error: true,
        },
        SmokeCase {
            method: "patch_assembly",
            params: json!({"address": ADDR_ADD, "line": "NOP"}),
            allow_error: true,
        },
        SmokeCase {
            method: "get_basic_blocks",
            params: json!({"address": ADDR_ADD}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_callees",
            params: json!({"address": ADDR_MAIN}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_callers",
            params: json!({"address": ADDR_ADD}),
            allow_error: false,
        },
        SmokeCase {
            method: "build_callgraph",
            params: json!({"roots": [ADDR_MAIN], "max_depth": 2, "max_nodes": 16}),
            allow_error: false,
        },
        SmokeCase {
            method: "find_control_flow_paths",
            params: json!({"start": ADDR_MAIN, "end": ADDR_ADD, "max_paths": 2, "max_depth": 8}),
            allow_error: true,
        },
        SmokeCase {
            method: "build_xref_matrix",
            params: json!({"addrs": [ADDR_ADD, ADDR_MAIN]}),
            allow_error: false,
        },
        SmokeCase {
            method: "get_database_info",
            params: json!({}),
            allow_error: false,
        },
        SmokeCase {
            method: "list_globals",
            params: json!({"offset": 0, "limit": 10}),
            allow_error: false,
        },
        SmokeCase {
            method: "run_auto_analysis",
            params: json!({"timeout_secs": 1}),
            allow_error: false,
        },
        SmokeCase {
            method: "search_bytes",
            params: json!({"patterns": "FD 7B", "limit": 5}),
            allow_error: false,
        },
        SmokeCase {
            method: "search_text",
            params: json!({"text": "add", "max_results": 5}),
            allow_error: false,
        },
        SmokeCase {
            method: "search_imm",
            params: json!({"imm": 1, "max_results": 5}),
            allow_error: false,
        },
        SmokeCase {
            method: "search_instructions",
            params: json!({"patterns": ["ADD", "BL"], "limit": 5}),
            allow_error: false,
        },
        SmokeCase {
            method: "search_instruction_operands",
            params: json!({"patterns": ["X0", "#0x1"], "limit": 5}),
            allow_error: false,
        },
        SmokeCase {
            method: "run_script",
            params: json!({"code": "print('ok')", "timeout_secs": 5}),
            allow_error: false,
        },
        SmokeCase {
            method: "batch_decompile",
            params: json!({"addresses": [ADDR_ADD, ADDR_MAIN]}),
            allow_error: false,
        },
        SmokeCase {
            method: "search_pseudocode",
            params: json!({"pattern": "return", "limit": 2}),
            allow_error: false,
        },
        SmokeCase {
            method: "scan_memory_table",
            params: json!({"base_address": ADDR_ADD, "stride": 4, "count": 2}),
            allow_error: false,
        },
        SmokeCase {
            method: "diff_pseudocode",
            params: json!({"addr1": ADDR_ADD, "addr2": ADDR_MAIN}),
            allow_error: false,
        },
    ]
}

fn extract_first_param_name(code: &str) -> Option<String> {
    let sig_line = code
        .lines()
        .find(|line| line.contains('(') && line.contains(')'))?;
    let start = sig_line.find('(')?;
    let end = sig_line[start + 1..].find(')')? + start + 1;
    let inside = sig_line[start + 1..end].trim();
    if inside.is_empty() || inside == "void" {
        return None;
    }

    let first_param = inside.split(',').next()?.trim();
    let mut tokens = first_param
        .split(|c: char| c.is_whitespace() || c == '*' || c == '&')
        .filter(|t| !t.is_empty());
    let mut last = None;
    for token in tokens.by_ref() {
        last = Some(token);
    }
    last.map(str::to_string)
}

#[rstest]
#[tokio::test]
async fn test_e2e_open_and_database_basics(worker: &IdaWorker, open_db: &Value) {
    if !ida_available() {
        return;
    }

    assert!(open_db.get("path").is_some(), "open should return db info");

    let status = call(worker, "get_analysis_status", json!({}))
        .await
        .expect("get_analysis_status failed");
    assert!(status.get("auto_is_ok").is_some());

    let funcs = call(worker, "list_functions", json!({"offset": 0, "limit": 10}))
        .await
        .expect("list_functions failed");
    let list = funcs["functions"]
        .as_array()
        .expect("functions should be array");
    assert!(list.len() >= 2, "mini.i64 should have at least 2 functions");

    let add = call(worker, "get_function_by_name", json!({"name": "_add"}))
        .await
        .expect("get_function_by_name failed");
    let addr = add["address"].as_str().unwrap_or_default();
    assert!(addr.contains("100000328"), "_add address mismatch: {addr}");
}

#[rstest]
#[tokio::test]
async fn test_e2e_patch_bytes_then_read_back(worker: &IdaWorker, open_db: &Value) {
    if !ida_available() {
        return;
    }
    let _ = open_db;

    let before = call(
        worker,
        "read_bytes",
        json!({"address": ADDR_ADD, "size": 4}),
    )
    .await
    .expect("read_bytes before patch failed");
    let before_hex = before["bytes"]
        .as_str()
        .expect("read_bytes should return hex bytes")
        .to_string();

    call(
        worker,
        "patch_bytes",
        json!({
            "address": ADDR_ADD,
            "bytes": "0b080000"
        }),
    )
    .await
    .expect("patch_bytes failed");

    let after = call(
        worker,
        "read_bytes",
        json!({"address": ADDR_ADD, "size": 4}),
    )
    .await
    .expect("read_bytes after patch failed");
    let after_hex = after["bytes"].as_str().unwrap_or_default().to_lowercase();
    assert!(
        after_hex.contains("0b080000") || after_hex.contains("0b 08 00 00"),
        "patched bytes not visible, got: {after_hex}"
    );

    call(
        worker,
        "patch_bytes",
        json!({
            "address": ADDR_ADD,
            "bytes": before_hex,
        }),
    )
    .await
    .expect("failed to restore original bytes");
}

#[rstest]
#[tokio::test]
async fn test_e2e_rename_then_set_type_lvar(worker: &IdaWorker, open_db: &Value) {
    if !ida_available() {
        return;
    }
    let _ = open_db;

    let decomp = call(worker, "decompile_function", json!({"address": ADDR_ADD}))
        .await
        .expect("decompile_function failed");
    let code = decomp["code"].as_str().unwrap_or_default();
    assert!(!code.is_empty(), "decompiled code should not be empty");

    let lvar_name = extract_first_param_name(code).unwrap_or_else(|| "a1".to_string());
    let renamed = "e2e_arg";

    let rename_result = call(
        worker,
        "rename_local_variable",
        json!({
            "func_address": ADDR_ADD,
            "lvar_name": lvar_name,
            "new_name": renamed,
        }),
    )
    .await;

    assert!(
        rename_result.is_ok(),
        "rename_local_variable failed: {:?}",
        rename_result.err()
    );

    let type_result = call(
        worker,
        "set_local_variable_type",
        json!({
            "func_address": ADDR_ADD,
            "lvar_name": renamed,
            "type_str": "int",
        }),
    )
    .await;

    assert!(
        type_result.is_ok(),
        "set_local_variable_type should succeed after rename: {:?}",
        type_result.err()
    );
}

#[rstest]
#[tokio::test]
async fn test_e2e_smoke_dispatch_methods(worker: &IdaWorker, open_db: &Value) {
    if !ida_available() {
        return;
    }
    let _ = open_db;

    let cases = smoke_cases();
    assert_eq!(
        cases.len(),
        69,
        "update this count when adding/removing smoke cases"
    );

    for case in cases {
        let result = call(worker, case.method, case.params.clone()).await;
        if case.allow_error {
            continue;
        }
        assert!(
            result.is_ok(),
            "method {} should not error: {:?}",
            case.method,
            result.err()
        );
    }
}
