pub mod discovery;
pub mod format;

use crate::router::protocol::{RpcRequest, RpcResponse};
use clap::{Parser, Subcommand};
use format::OutputMode;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::UnixStream;
use tokio::sync::Semaphore;

#[derive(Parser)]
pub struct CliArgs {
    #[arg(long, global = true)]
    socket: Option<String>,

    #[arg(long, global = true)]
    path: Option<String>,

    #[arg(long, global = true)]
    tenant: Option<String>,

    #[arg(long, global = true)]
    json: bool,

    #[arg(long, global = true)]
    compact: bool,

    #[arg(long, global = true, default_value_t = 120)]
    timeout: u64,

    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Subcommand)]
pub enum CliCommand {
    ListFunctions {
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    Decompile {
        #[arg(long)]
        addr: String,
    },
    Disasm {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 20)]
        count: usize,
    },
    XrefsTo {
        #[arg(long)]
        addr: String,
    },
    ListStrings {
        #[arg(long)]
        query: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    ListSegments,
    Prewarm {
        #[arg(long)]
        keep_warm: bool,
        #[arg(long)]
        queue: bool,
        #[arg(long, default_value_t = 0)]
        priority: u8,
        #[arg(long)]
        tenant: Option<String>,
    },
    PrewarmMany {
        list_file: String,
        #[arg(long, default_value_t = 4)]
        jobs: usize,
        #[arg(long)]
        keep_warm: bool,
        #[arg(long)]
        queue: bool,
        #[arg(long, default_value_t = 0)]
        priority: u8,
        #[arg(long)]
        tenant: Option<String>,
    },
    Enqueue {
        method: String,
        #[arg(long, default_value_t = 0)]
        priority: u8,
        #[arg(long)]
        dedupe_key: Option<String>,
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        params: Option<String>,
    },
    TaskStatus {
        task_id: String,
    },
    ListTasks,
    CancelTask {
        task_id: String,
    },
    Close,
    Status,
    Shutdown,
    Raw {
        json_str: String,
    },
    Pipe,
}

pub async fn run(args: CliArgs) -> anyhow::Result<()> {
    let socket_path = match discovery::discover_socket(args.socket.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let output_mode = if args.compact {
        OutputMode::Compact
    } else if args.json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    let timeout = std::time::Duration::from_secs(args.timeout);

    match args.command {
        CliCommand::Pipe => run_pipe(&socket_path, args.path.as_deref(), &output_mode).await,
        CliCommand::PrewarmMany {
            list_file,
            jobs,
            keep_warm,
            queue,
            priority,
            tenant,
        } => {
            run_prewarm_many(
                &socket_path,
                &list_file,
                jobs.max(1),
                keep_warm,
                queue,
                priority,
                tenant,
                &output_mode,
                timeout,
            )
            .await
        }
        CliCommand::Enqueue {
            method,
            priority,
            dedupe_key,
            tenant,
            params,
        } => {
            let mut payload = serde_json::Map::new();
            if let Some(path) = args.path.as_deref() {
                payload.insert("path".to_string(), serde_json::json!(path));
            }
            payload.insert("method".to_string(), serde_json::json!(method));
            payload.insert("priority".to_string(), serde_json::json!(priority));
            if let Some(tenant) = tenant {
                payload.insert("tenant_id".to_string(), serde_json::json!(tenant));
            }
            if let Some(dedupe_key) = dedupe_key {
                payload.insert("dedupe_key".to_string(), serde_json::json!(dedupe_key));
            }
            if let Some(params) = params {
                let value: serde_json::Value = serde_json::from_str(&params)?;
                payload.insert("task_params".to_string(), value);
            }
            let req = RpcRequest::new("1", "enqueue", serde_json::Value::Object(payload));
            let resp = send_request(&socket_path, &req, timeout).await?;
            handle_response(&resp, "enqueue", &output_mode)
        }
        CliCommand::TaskStatus { task_id } => {
            let req = RpcRequest::new("1", "task_status", serde_json::json!({ "task_id": task_id }));
            let resp = send_request(&socket_path, &req, timeout).await?;
            handle_response(&resp, "task_status", &output_mode)
        }
        CliCommand::ListTasks => {
            let req = RpcRequest::new("1", "list_tasks", serde_json::json!({}));
            let resp = send_request(&socket_path, &req, timeout).await?;
            handle_response(&resp, "list_tasks", &output_mode)
        }
        CliCommand::CancelTask { task_id } => {
            let req = RpcRequest::new("1", "cancel_task", serde_json::json!({ "task_id": task_id }));
            let resp = send_request(&socket_path, &req, timeout).await?;
            handle_response(&resp, "cancel_task", &output_mode)
        }
        CliCommand::Raw { json_str } => {
            let req = complete_envelope(&json_str, 1)?;
            let resp = send_request(&socket_path, &req, timeout).await?;
            handle_response(&resp, &req.method, &output_mode)
        }
        cmd => {
            let (method, params) = build_rpc_params(&cmd, args.path.as_deref(), args.tenant.as_deref());
            let req = RpcRequest::new("1", &method, params);
            let resp = send_request(&socket_path, &req, timeout).await?;
            handle_response(&resp, &method, &output_mode)
        }
    }
}

fn build_rpc_params(
    cmd: &CliCommand,
    path: Option<&str>,
    tenant: Option<&str>,
) -> (String, serde_json::Value) {
    let mut params = serde_json::Map::new();
    if let Some(p) = path {
        params.insert("path".to_string(), serde_json::json!(p));
    }
    if let Some(tenant) = tenant {
        params.insert("tenant_id".to_string(), serde_json::json!(tenant));
    }

    let method = match cmd {
        CliCommand::ListFunctions {
            filter,
            limit,
            offset,
        } => {
            params.insert("limit".to_string(), serde_json::json!(limit));
            params.insert("offset".to_string(), serde_json::json!(offset));
            if let Some(f) = filter {
                params.insert("filter".to_string(), serde_json::json!(f));
            }
            "list_functions"
        }
        CliCommand::Decompile { addr } => {
            params.insert("address".to_string(), serde_json::json!(addr));
            "decompile_function"
        }
        CliCommand::Disasm { addr, name, count } => {
            params.insert("count".to_string(), serde_json::json!(count));
            if let Some(a) = addr {
                params.insert("address".to_string(), serde_json::json!(a));
                "disassemble"
            } else if let Some(n) = name {
                params.insert("name".to_string(), serde_json::json!(n));
                "disassemble_function"
            } else {
                eprintln!("Error: disasm requires --addr or --name");
                std::process::exit(1);
            }
        }
        CliCommand::XrefsTo { addr } => {
            params.insert("address".to_string(), serde_json::json!(addr));
            "get_xrefs_to"
        }
        CliCommand::ListStrings { query, limit } => {
            params.insert("limit".to_string(), serde_json::json!(limit));
            if let Some(q) = query {
                params.insert("query".to_string(), serde_json::json!(q));
            }
            "list_strings"
        }
        CliCommand::ListSegments => "list_segments",
        CliCommand::Prewarm {
            keep_warm,
            queue,
            priority,
            tenant,
        } => {
            params.insert("keep_warm".to_string(), serde_json::json!(keep_warm));
            params.insert("queue".to_string(), serde_json::json!(queue));
            params.insert("priority".to_string(), serde_json::json!(priority));
            if let Some(tenant) = tenant {
                params.insert("tenant_id".to_string(), serde_json::json!(tenant));
            }
            "prewarm"
        }
        CliCommand::Close => "close",
        CliCommand::Status => "status",
        CliCommand::Shutdown => "shutdown",
        CliCommand::Enqueue { .. }
        | CliCommand::TaskStatus { .. }
        | CliCommand::ListTasks
        | CliCommand::CancelTask { .. } => unreachable!(),
        CliCommand::PrewarmMany { .. } => unreachable!(),
        _ => unreachable!(),
    };

    (method.to_string(), serde_json::Value::Object(params))
}

fn complete_envelope(raw: &str, seq: u64) -> anyhow::Result<RpcRequest> {
    let mut val: serde_json::Value = serde_json::from_str(raw)?;
    let obj = val
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("JSON must be an object"))?;

    if !obj.contains_key("jsonrpc") {
        obj.insert("jsonrpc".to_string(), serde_json::json!("2.0"));
    }
    if !obj.contains_key("id") {
        obj.insert("id".to_string(), serde_json::json!(seq.to_string()));
    }
    if !obj.contains_key("params") {
        obj.insert("params".to_string(), serde_json::json!({}));
    }

    serde_json::from_value(val).map_err(|e| anyhow::anyhow!("Invalid request: {e}"))
}

async fn send_request(
    socket_path: &PathBuf,
    req: &RpcRequest,
    timeout: std::time::Duration,
) -> anyhow::Result<RpcResponse> {
    let stream = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        UnixStream::connect(socket_path),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("Error: Cannot connect to server: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("Error: Connection timed out");
            std::process::exit(1);
        }
    };

    let (reader, writer) = stream.into_split();
    let mut writer = BufWriter::new(writer);
    let mut reader = BufReader::new(reader);

    let json = serde_json::to_string(req)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    let mut line = String::new();
    match tokio::time::timeout(timeout, reader.read_line(&mut line)).await {
        Ok(Ok(0)) => anyhow::bail!("Server closed connection"),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => anyhow::bail!("Read error: {e}"),
        Err(_) => {
            eprintln!("Error: request timed out after {}s", timeout.as_secs());
            std::process::exit(1);
        }
    }

    serde_json::from_str(line.trim()).map_err(|e| anyhow::anyhow!("Invalid response: {e}"))
}

async fn run_prewarm_many(
    socket_path: &PathBuf,
    list_file: &str,
    jobs: usize,
    keep_warm: bool,
    queue: bool,
    priority: u8,
    tenant: Option<String>,
    output_mode: &OutputMode,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(list_file)?;
    let paths: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect();

    let semaphore = Arc::new(Semaphore::new(jobs));
    let mut handles = Vec::new();

    for (idx, path) in paths.iter().enumerate() {
        let socket_path = socket_path.clone();
        let path = path.clone();
        let semaphore = semaphore.clone();
        let tenant = tenant.clone();
        handles.push(tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await.expect("semaphore closed");
            let req = RpcRequest::new(
                format!("prewarm-{idx}"),
                "prewarm",
                serde_json::json!({
                    "path": path,
                    "keep_warm": keep_warm,
                    "queue": queue,
                    "priority": priority,
                    "tenant_id": tenant,
                }),
            );
            let resp = send_request(&socket_path, &req, timeout).await;
            (path, resp)
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        let (path, resp) = handle.await?;
        match resp {
            Ok(response) => {
                let value = if let Some(error) = response.error {
                    serde_json::json!({ "path": path, "ok": false, "error": error.message })
                } else {
                    serde_json::json!({ "path": path, "ok": true, "result": response.result })
                };
                results.push(value);
            }
            Err(err) => {
                results.push(serde_json::json!({ "path": path, "ok": false, "error": err.to_string() }));
            }
        }
    }

    let output = serde_json::json!({
        "count": results.len(),
        "results": results,
    });
    println!("{}", format::format_response(output_mode, "prewarm_many", &output));
    Ok(())
}

fn handle_response(resp: &RpcResponse, method: &str, mode: &OutputMode) -> anyhow::Result<()> {
    if let Some(ref err) = resp.error {
        eprintln!("Error: {}", err.message);
        std::process::exit(1);
    }

    if let Some(ref result) = resp.result {
        println!("{}", format::format_response(mode, method, result));
    }

    Ok(())
}

async fn run_pipe(
    socket_path: &PathBuf,
    global_path: Option<&str>,
    mode: &OutputMode,
) -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    let mut seq: u64 = 1;
    let timeout = std::time::Duration::from_secs(120);

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let mut req = match complete_envelope(trimmed, seq) {
                    Ok(r) => r,
                    Err(e) => {
                        let err_resp = RpcResponse::err(&seq.to_string(), -32700, e.to_string());
                        println!("{}", serde_json::to_string(&err_resp).unwrap_or_default());
                        seq += 1;
                        continue;
                    }
                };

                if let Some(p) = global_path {
                    if !req.params.get("path").is_some() {
                        if let Some(obj) = req.params.as_object_mut() {
                            obj.insert("path".to_string(), serde_json::json!(p));
                        }
                    }
                }

                match send_request(socket_path, &req, timeout).await {
                    Ok(resp) => {
                        let out = match mode {
                            OutputMode::Compact | OutputMode::Json => {
                                serde_json::to_string(&resp).unwrap_or_default()
                            }
                            OutputMode::Human => serde_json::to_string(&resp).unwrap_or_default(),
                        };
                        println!("{out}");
                    }
                    Err(e) => {
                        let err_resp = RpcResponse::err(&req.id, -32000, e.to_string());
                        println!("{}", serde_json::to_string(&err_resp).unwrap_or_default());
                    }
                }
                seq += 1;
            }
            Err(e) => {
                eprintln!("Error reading stdin: {e}");
                break;
            }
        }
    }
    Ok(())
}
