use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use tokio::process::Command;
use tokio::sync::{oneshot, OnceCell};

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

struct WorkerClient {
    writer_tx: std_mpsc::Sender<String>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value, String>>>>>,
    counter: AtomicU64,
    child: Mutex<std::process::Child>,
}

fn find_ida_mcp_exe() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    manifest.join("target/debug/ida-mcp")
}

async fn spawn_worker() -> WorkerClient {
    let exe = find_ida_mcp_exe();
    let mut cmd = Command::new(&exe);
    cmd.arg("serve-worker");

    if let Ok(dyld) = std::env::var("DYLD_LIBRARY_PATH") {
        cmd.env("DYLD_LIBRARY_PATH", dyld);
    }
    if let Ok(idadir) = std::env::var("IDADIR") {
        cmd.env("IDADIR", idadir);
    }
    if let Ok(ld) = std::env::var("LD_LIBRARY_PATH") {
        cmd.env("LD_LIBRARY_PATH", ld);
    }
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }

    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);

    let mut std_cmd = cmd.into_std();
    let mut child = std_cmd
        .spawn()
        .expect("failed to spawn ida-mcp serve-worker");
    let stdin = child.stdin.take().expect("failed to capture child stdin");
    let stdout = child.stdout.take().expect("failed to capture child stdout");

    let pending: Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value, String>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let pending_for_reader = pending.clone();
    let pending_for_writer = pending.clone();
    let (writer_tx, writer_rx) = std_mpsc::channel::<String>();

    std::thread::spawn(move || {
        let mut writer = BufWriter::new(stdin);
        while let Ok(line) = writer_rx.recv() {
            if let Err(e) = writer.write_all(line.as_bytes()) {
                let mut map = pending_for_writer.lock().expect("pending mutex poisoned");
                for (_, tx) in map.drain() {
                    let _ = tx.send(Err(format!("worker write error: {e}")));
                }
                break;
            }
            if let Err(e) = writer.flush() {
                let mut map = pending_for_writer.lock().expect("pending mutex poisoned");
                for (_, tx) in map.drain() {
                    let _ = tx.send(Err(format!("worker flush error: {e}")));
                }
                break;
            }
        }
    });

    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    let mut map = pending_for_reader.lock().expect("pending mutex poisoned");
                    for (_, tx) in map.drain() {
                        let _ = tx.send(Err("worker closed".to_string()));
                    }
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    if let Ok(resp) = serde_json::from_str::<Value>(trimmed) {
                        let id = resp
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        if id.is_empty() {
                            continue;
                        }

                        let mut map = pending_for_reader.lock().expect("pending mutex poisoned");
                        if let Some(tx) = map.remove(&id) {
                            if resp.get("error").is_none() || resp["error"].is_null() {
                                let _ =
                                    tx.send(Ok(resp.get("result").cloned().unwrap_or(Value::Null)));
                            } else {
                                let msg = resp["error"]["message"]
                                    .as_str()
                                    .unwrap_or("unknown error")
                                    .to_string();
                                let _ = tx.send(Err(msg));
                            }
                        }
                    }
                }
                Err(e) => {
                    let mut map = pending_for_reader.lock().expect("pending mutex poisoned");
                    for (_, tx) in map.drain() {
                        let _ = tx.send(Err(format!("worker I/O error: {e}")));
                    }
                    break;
                }
            }
        }
    });

    WorkerClient {
        writer_tx,
        pending,
        counter: AtomicU64::new(0),
        child: Mutex::new(child),
    }
}

impl WorkerClient {
    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let id = format!("r{}", self.counter.fetch_add(1, Ordering::SeqCst));
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let (tx, rx) = oneshot::channel();
        let mut map = self.pending.lock().expect("pending mutex poisoned");
        map.insert(id.clone(), tx);
        drop(map);

        let line = serde_json::to_string(&req)
            .map_err(|e| format!("serialize request failed: {e}"))?
            + "\n";
        self.writer_tx
            .send(line)
            .map_err(|_| "worker write channel closed".to_string())?;

        rx.await.map_err(|_| "worker closed".to_string())?
    }

    async fn ensure_running(&self) -> Result<(), String> {
        let mut child = self.child.lock().expect("child mutex poisoned");
        match child.try_wait() {
            Ok(Some(status)) => Err(format!("worker exited unexpectedly: {status}")),
            Ok(None) => Ok(()),
            Err(e) => Err(format!("failed to check worker status: {e}")),
        }
    }
}

static CLIENT: OnceCell<WorkerClient> = OnceCell::const_new();

async fn client() -> &'static WorkerClient {
    CLIENT
        .get_or_init(|| async {
            let c = spawn_worker().await;
            let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test/fixtures/mini.i64");

            c.call(
                "open",
                json!({
                    "path": fixture.to_string_lossy().to_string(),
                    "force": true,
                }),
            )
            .await
            .expect("failed to open mini.i64");

            c
        })
        .await
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
            params: json!({"name": "add"}),
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
            params: json!({"queries": ["add", ADDR_MAIN]}),
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
            params: json!({"name": "add", "count": 6}),
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
            params: json!({"current_name": "add", "name": "add", "flags": 0}),
            allow_error: true,
        },
        SmokeCase {
            method: "batch_rename",
            params: json!({"renames": [
                {"current_name": "add", "new_name": "add"},
                {"current_name": "main", "new_name": "main"}
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

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_open_and_database_basics() {
    if !ida_available() {
        return;
    }

    let c = client().await;
    c.ensure_running().await.expect("worker should be running");

    let db_info = c
        .call("get_database_info", json!({}))
        .await
        .expect("get_database_info failed");
    assert!(db_info.is_object(), "database info should be JSON object");

    let status = c
        .call("get_analysis_status", json!({}))
        .await
        .expect("get_analysis_status failed");
    assert!(status.get("auto_is_ok").is_some());

    let funcs = c
        .call("list_functions", json!({"offset": 0, "limit": 10}))
        .await
        .expect("list_functions failed");
    let list = funcs["functions"]
        .as_array()
        .expect("functions should be array");
    assert!(list.len() >= 2, "mini.i64 should have at least 2 functions");

    let add = match c
        .call("get_function_by_name", json!({"name": "_add"}))
        .await
    {
        Ok(v) => v,
        Err(_) => c
            .call("get_function_by_name", json!({"name": "add"}))
            .await
            .expect("get_function_by_name failed"),
    };
    let addr = add["address"].as_str().unwrap_or_default();
    assert!(addr.contains("100000328"), "_add address mismatch: {addr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_patch_bytes_then_read_back() {
    if !ida_available() {
        return;
    }

    let c = client().await;

    let before = c
        .call("read_bytes", json!({"address": ADDR_ADD, "size": 4}))
        .await
        .expect("read_bytes before patch failed");
    let before_hex = before["bytes"]
        .as_str()
        .expect("read_bytes should return hex bytes")
        .to_string();

    c.call(
        "patch_bytes",
        json!({
            "address": ADDR_ADD,
            "bytes": "0b080000"
        }),
    )
    .await
    .expect("patch_bytes failed");

    let after = c
        .call("read_bytes", json!({"address": ADDR_ADD, "size": 4}))
        .await
        .expect("read_bytes after patch failed");
    let after_hex = after["bytes"].as_str().unwrap_or_default().to_lowercase();
    assert!(
        after_hex.contains("0b080000") || after_hex.contains("0b 08 00 00"),
        "patched bytes not visible, got: {after_hex}"
    );

    c.call(
        "patch_bytes",
        json!({
            "address": ADDR_ADD,
            "bytes": before_hex,
        }),
    )
    .await
    .expect("failed to restore original bytes");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_rename_then_set_type_lvar() {
    if !ida_available() {
        return;
    }

    let c = client().await;

    let decomp = c
        .call("decompile_function", json!({"address": ADDR_ADD}))
        .await
        .expect("decompile_function failed");
    let code = decomp["code"].as_str().unwrap_or_default();
    assert!(!code.is_empty(), "decompiled code should not be empty");

    let lvar_name = extract_first_param_name(code).unwrap_or_else(|| "a1".to_string());
    let renamed = "e2e_arg";

    let rename_result = c
        .call(
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

    let type_result = c
        .call(
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

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_smoke_dispatch_methods() {
    if !ida_available() {
        return;
    }

    let c = client().await;

    let cases = smoke_cases();
    assert_eq!(
        cases.len(),
        69,
        "update this count when adding/removing smoke cases"
    );

    for case in cases {
        let result = c.call(case.method, case.params.clone()).await;
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
