pub mod discovery;
pub mod format;

use crate::router::protocol::{RpcRequest, RpcResponse, RPC_BRIDGE_LOST_NOT_DISPATCHED};
use clap::{Parser, Subcommand};
use format::OutputMode;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::UnixStream;
use tokio::sync::{OnceCell, Semaphore};

#[derive(Parser)]
#[command(name = "ida-cli", version, about = "Headless IDA CLI and MCP Server")]
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
        /// Also return one {line, text, addresses} entry per pseudocode line
        #[arg(long)]
        line_addresses: bool,
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
    XrefsToString {
        query: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 10)]
        max_xrefs: usize,
        #[arg(long)]
        exact: bool,
        #[arg(long, default_value_t = true)]
        case_insensitive: bool,
    },
    Callers {
        #[arg(long)]
        addr: String,
    },
    Callees {
        #[arg(long)]
        addr: String,
    },
    AddressInfo {
        #[arg(long)]
        addr: String,
    },
    ListImports {
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
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
        federate: bool,
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
    FederationList,
    FederationRegister {
        name: String,
        url: String,
        #[arg(long, default_value_t = 1)]
        weight: u32,
    },
    FederationUnregister {
        name: String,
    },
    FederationHeartbeat {
        name: String,
        url: String,
        #[arg(long, default_value_t = 1)]
        weight: u32,
        #[arg(long)]
        capability: Vec<String>,
        #[arg(long)]
        tenant_allow: Vec<String>,
        #[arg(long)]
        node_id: Option<String>,
    },
    Close,
    Status,
    /// List the databases the daemon holds open and the clients holding them
    /// (run it before rebuilding an .i64 to confirm no other client uses it)
    ListIdbs,
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
    let mut endpoint = Endpoint {
        path: socket_path.clone(),
        pinned: discovery::is_pinned(args.socket.as_deref()),
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
        CliCommand::Pipe => run_pipe(&mut endpoint, args.path.as_deref(), &output_mode).await,
        CliCommand::PrewarmMany {
            list_file,
            jobs,
            keep_warm,
            queue,
            priority,
            tenant,
        } => {
            run_prewarm_many(
                endpoint,
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
            federate,
            params,
        } => {
            let mut payload = serde_json::Map::new();
            if let Some(path) = args.path.as_deref() {
                payload.insert("path".to_string(), serde_json::json!(path));
            }
            payload.insert("method".to_string(), serde_json::json!(method));
            payload.insert("priority".to_string(), serde_json::json!(priority));
            payload.insert("federate".to_string(), serde_json::json!(federate));
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
            let resp = send_recoverable(&mut endpoint, &req, timeout).await?;
            handle_response(&resp, "enqueue", &output_mode)
        }
        CliCommand::TaskStatus { task_id } => {
            let req = RpcRequest::new(
                "1",
                "task_status",
                serde_json::json!({ "task_id": task_id }),
            );
            let resp = send_recoverable(&mut endpoint, &req, timeout).await?;
            handle_response(&resp, "task_status", &output_mode)
        }
        CliCommand::ListTasks => {
            let req = RpcRequest::new("1", "list_tasks", serde_json::json!({}));
            let resp = send_recoverable(&mut endpoint, &req, timeout).await?;
            handle_response(&resp, "list_tasks", &output_mode)
        }
        CliCommand::CancelTask { task_id } => {
            let req = RpcRequest::new(
                "1",
                "cancel_task",
                serde_json::json!({ "task_id": task_id }),
            );
            let resp = send_recoverable(&mut endpoint, &req, timeout).await?;
            handle_response(&resp, "cancel_task", &output_mode)
        }
        CliCommand::FederationList => {
            let body = reqwest_blocking_like("GET", &admin_url("/federationz"), None)?;
            println!("{body}");
            Ok(())
        }
        CliCommand::FederationRegister { name, url, weight } => {
            let body = reqwest_blocking_like(
                "POST",
                &admin_url("/federationz/register"),
                Some(serde_json::json!({
                    "name": name,
                    "url": url,
                    "weight": weight,
                    "enabled": true,
                })),
            )?;
            println!("{body}");
            Ok(())
        }
        CliCommand::FederationUnregister { name } => {
            let body = reqwest_blocking_like(
                "POST",
                &admin_url("/federationz/unregister"),
                Some(serde_json::json!({ "name": name })),
            )?;
            println!("{body}");
            Ok(())
        }
        CliCommand::FederationHeartbeat {
            name,
            url,
            weight,
            capability,
            tenant_allow,
            node_id,
        } => {
            let body = reqwest_blocking_like(
                "POST",
                &admin_url("/federationz/heartbeat"),
                Some(serde_json::json!({
                    "name": name,
                    "url": url,
                    "weight": weight,
                    "enabled": true,
                    "capabilities": capability,
                    "tenant_allow": tenant_allow,
                    "node_id": node_id,
                })),
            )?;
            println!("{body}");
            Ok(())
        }
        CliCommand::Raw { json_str } => {
            let mut req = complete_envelope(&json_str, 1)?;
            // Keep the raw subcommand consistent with pipe: if `--path` /
            // `--tenant` are supplied on the CLI and the request did not
            // already pin them, inject the globals so `raw` behaves like
            // the other direct subcommands.
            if let Some(obj) = req.params.as_object_mut() {
                if let Some(path) = args.path.as_deref() {
                    obj.entry("path".to_string())
                        .or_insert_with(|| serde_json::json!(path));
                }
                if let Some(tenant) = args.tenant.as_deref() {
                    obj.entry("tenant_id".to_string())
                        .or_insert_with(|| serde_json::json!(tenant));
                }
            }
            let resp = send_recoverable(&mut endpoint, &req, timeout).await?;
            handle_response(&resp, &req.method, &output_mode)
        }
        cmd => {
            let (method, params) =
                build_rpc_params(&cmd, args.path.as_deref(), args.tenant.as_deref());
            let req = RpcRequest::new("1", &method, params);
            let resp = send_recoverable(&mut endpoint, &req, timeout).await?;
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
        CliCommand::Decompile {
            addr,
            line_addresses,
        } => {
            params.insert("address".to_string(), serde_json::json!(addr));
            if *line_addresses {
                params.insert("line_addresses".to_string(), serde_json::json!(true));
            }
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
        CliCommand::XrefsToString {
            query,
            limit,
            max_xrefs,
            exact,
            case_insensitive,
        } => {
            params.insert("query".to_string(), serde_json::json!(query));
            params.insert("limit".to_string(), serde_json::json!(limit));
            params.insert("max_xrefs".to_string(), serde_json::json!(max_xrefs));
            params.insert("exact".to_string(), serde_json::json!(exact));
            params.insert(
                "case_insensitive".to_string(),
                serde_json::json!(case_insensitive),
            );
            "get_xrefs_to_string"
        }
        CliCommand::Callers { addr } => {
            params.insert("address".to_string(), serde_json::json!(addr));
            "get_callers"
        }
        CliCommand::Callees { addr } => {
            params.insert("address".to_string(), serde_json::json!(addr));
            "get_callees"
        }
        CliCommand::AddressInfo { addr } => {
            params.insert("address".to_string(), serde_json::json!(addr));
            "get_address_info"
        }
        CliCommand::ListImports { limit, offset } => {
            params.insert("limit".to_string(), serde_json::json!(limit));
            params.insert("offset".to_string(), serde_json::json!(offset));
            "list_imports"
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
        CliCommand::ListIdbs => "list_idbs",
        CliCommand::Shutdown => "shutdown",
        // The variants below are dispatched in `run()` before `build_rpc_params`
        // is ever called, so reaching them here would be a programmer mistake.
        CliCommand::Enqueue { .. }
        | CliCommand::TaskStatus { .. }
        | CliCommand::ListTasks
        | CliCommand::CancelTask { .. }
        | CliCommand::FederationList
        | CliCommand::FederationRegister { .. }
        | CliCommand::FederationUnregister { .. }
        | CliCommand::FederationHeartbeat { .. }
        | CliCommand::PrewarmMany { .. }
        | CliCommand::Raw { .. }
        | CliCommand::Pipe => {
            unreachable!("build_rpc_params called with a command handled directly in run()")
        }
    };

    (method.to_string(), serde_json::Value::Object(params))
}

#[cfg(test)]
mod listing_and_lines_tests {
    use super::{build_rpc_params, CliArgs, CliCommand};
    use clap::Parser;

    #[test]
    fn build_rpc_params_for_cli_surface_methods() {
        let (method, params) = build_rpc_params(
            &CliCommand::ListImports {
                limit: 5,
                offset: 2,
            },
            Some("/tmp/a.bin"),
            None,
        );
        assert_eq!(method, "list_imports");
        assert_eq!(params["path"], "/tmp/a.bin");
        assert_eq!(params["limit"], 5);
        assert_eq!(params["offset"], 2);

        let (method, params) = build_rpc_params(
            &CliCommand::XrefsToString {
                query: "malloc".to_string(),
                limit: 4,
                max_xrefs: 3,
                exact: false,
                case_insensitive: true,
            },
            Some("/tmp/a.bin"),
            None,
        );
        assert_eq!(method, "get_xrefs_to_string");
        assert_eq!(params["query"], "malloc");
        assert_eq!(params["limit"], 4);
        assert_eq!(params["max_xrefs"], 3);
        assert_eq!(params["case_insensitive"], true);

        let (method, params) = build_rpc_params(
            &CliCommand::Callers {
                addr: "0x1000".to_string(),
            },
            None,
            None,
        );
        assert_eq!(method, "get_callers");
        assert_eq!(params["address"], "0x1000");

        let (method, params) = build_rpc_params(
            &CliCommand::AddressInfo {
                addr: "0x2000".to_string(),
            },
            None,
            None,
        );
        assert_eq!(method, "get_address_info");
        assert_eq!(params["address"], "0x2000");
    }

    #[test]
    fn decompile_sends_line_addresses_only_when_asked() {
        let (method, params) = build_rpc_params(
            &CliCommand::Decompile {
                addr: "0x1000".to_string(),
                line_addresses: false,
            },
            Some("/tmp/a.bin"),
            None,
        );
        assert_eq!(method, "decompile_function");
        assert_eq!(params["address"], "0x1000");
        assert!(params.get("line_addresses").is_none());

        let (method, params) = build_rpc_params(
            &CliCommand::Decompile {
                addr: "0x1000".to_string(),
                line_addresses: true,
            },
            Some("/tmp/a.bin"),
            None,
        );
        assert_eq!(method, "decompile_function");
        assert_eq!(params["line_addresses"], true);
    }

    #[test]
    fn decompile_line_addresses_flag_parses() {
        let plain =
            CliArgs::try_parse_from(["ida-cli", "decompile", "--addr", "0x10"]).expect("parse");
        assert!(matches!(
            plain.command,
            CliCommand::Decompile {
                line_addresses: false,
                ..
            }
        ));
        let with =
            CliArgs::try_parse_from(["ida-cli", "decompile", "--addr", "0x10", "--line-addresses"])
                .expect("parse");
        assert!(matches!(
            with.command,
            CliCommand::Decompile {
                line_addresses: true,
                ..
            }
        ));
    }

    #[test]
    fn list_idbs_needs_no_path_and_forwards_the_tenant() {
        let (method, params) = build_rpc_params(&CliCommand::ListIdbs, None, Some("team-a"));
        assert_eq!(method, "list_idbs");
        assert!(params.get("path").is_none());
        assert_eq!(params["tenant_id"], "team-a");
    }
}

fn admin_url(path: &str) -> String {
    let base =
        std::env::var("IDA_CLI_ADMIN_URL").unwrap_or_else(|_| "http://127.0.0.1:9876".to_string());
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn reqwest_blocking_like(
    method: &str,
    url: &str,
    body: Option<serde_json::Value>,
) -> anyhow::Result<String> {
    let uri: hyper::Uri = url.parse()?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("missing host in url"))?;
    let port = uri.port_u16().unwrap_or(80);
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    // Don't rely on the OS TCP timeout: a wrong `--socket` / admin URL would
    // otherwise block the CLI for minutes.
    let connect_timeout = std::time::Duration::from_secs(5);
    let mut stream: Option<TcpStream> = None;
    let mut last_err: Option<std::io::Error> = None;
    use std::net::ToSocketAddrs;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, connect_timeout) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let mut stream = stream.ok_or_else(|| {
        last_err
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("no addresses resolved for {host}:{port}"))
    })?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let body_bytes = body
        .map(|value| serde_json::to_vec(&value))
        .transpose()?
        .unwrap_or_default();

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if !body_bytes.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes())?;
    if !body_bytes.is_empty() {
        stream.write_all(&body_bytes)?;
    }

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("invalid http response"))?;
    Ok(body.to_string())
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

/// How long a client waits for a daemon that lost its Nexus bridge to settle its
/// custody and exit before it gives up and reports the original error.
const BRIDGE_LOSS_EXIT_WAIT: std::time::Duration = std::time::Duration::from_secs(180);

/// The daemon this process talks to. A pinned endpoint (`--socket`,
/// `$IDA_MCP_SOCKET`) is never replaced; an auto-discovered one may be.
pub(crate) struct Endpoint {
    path: std::path::PathBuf,
    pinned: bool,
}

/// The daemon refused before anything reached its lost Nexus bridge: no effect
/// happened, and only this code (never an unknown outcome) allows a retry.
fn refused_before_dispatch(resp: &RpcResponse) -> bool {
    resp.error
        .as_ref()
        .is_some_and(|error| error.code == RPC_BRIDGE_LOST_NOT_DISPATCHED)
}

/// Send once; if the daemon reports a bridge loss that happened before dispatch,
/// wait for it to exit, let discovery start a fresh daemon and resend exactly
/// once. A second refusal, an unknown outcome or a pinned endpoint is returned
/// untouched.
async fn send_recoverable(
    endpoint: &mut Endpoint,
    req: &RpcRequest,
    timeout: std::time::Duration,
) -> anyhow::Result<RpcResponse> {
    send_recoverable_with(endpoint, req, timeout, restart_daemon).await
}

async fn send_recoverable_with(
    endpoint: &mut Endpoint,
    req: &RpcRequest,
    timeout: std::time::Duration,
    restart: impl FnOnce(&Path) -> Result<std::path::PathBuf, String> + Send + 'static,
) -> anyhow::Result<RpcResponse> {
    let resp = send_request(&endpoint.path, req, timeout).await?;
    if endpoint.pinned || !refused_before_dispatch(&resp) {
        return Ok(resp);
    }
    eprintln!(
        "The ida-cli daemon lost its Nexus bridge before running this request; waiting for it to exit, then retrying once on a fresh daemon..."
    );
    match recover_endpoint(endpoint.path.clone(), restart).await {
        Ok(path) => {
            endpoint.path = path;
            send_request(&endpoint.path, req, timeout).await
        }
        Err(_) => Ok(resp),
    }
}

fn restart_daemon(old: &Path) -> Result<std::path::PathBuf, String> {
    discovery::wait_for_daemon_exit(old, BRIDGE_LOSS_EXIT_WAIT)?;
    discovery::discover_socket(None)
}

async fn recover_endpoint(
    old: std::path::PathBuf,
    restart: impl FnOnce(&Path) -> Result<std::path::PathBuf, String> + Send + 'static,
) -> Result<std::path::PathBuf, String> {
    let result = match tokio::task::spawn_blocking(move || restart(&old)).await {
        Ok(result) => result,
        Err(error) => Err(format!("daemon recovery task failed: {error}")),
    };
    if let Err(reason) = &result {
        eprintln!("Cannot recover automatically: {reason}");
    }
    result
}

/// All items share one recovery, including a failed recovery. Only a typed
/// entrance refusal permits replay; transport failures never establish that.
struct BatchEndpoint {
    initial: Endpoint,
    recovery: OnceCell<Result<std::path::PathBuf, String>>,
}

impl BatchEndpoint {
    async fn send(
        &self,
        req: &RpcRequest,
        timeout: std::time::Duration,
        restart: impl FnOnce(&Path) -> Result<std::path::PathBuf, String> + Send + 'static,
    ) -> anyhow::Result<RpcResponse> {
        if let Some(Ok(path)) = self.recovery.get() {
            // Already using the replacement daemon: no second recovery/replay.
            return send_request(path, req, timeout).await;
        }
        let response = send_request(&self.initial.path, req, timeout).await?;
        if self.initial.pinned || !refused_before_dispatch(&response) {
            return Ok(response);
        }
        let recovered = self.recovery.get_or_init(|| async {
            eprintln!("The ida-cli daemon lost its Nexus bridge before running a batch item; waiting for it to exit, then retrying refused items once on a fresh daemon...");
            recover_endpoint(self.initial.path.clone(), restart).await
        }).await;
        match recovered {
            Ok(path) => send_request(path, req, timeout).await,
            Err(_) => Ok(response),
        }
    }
}

async fn send_request(
    socket_path: &Path,
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
        Ok(Err(e)) => anyhow::bail!("Cannot connect to server: {e}"),
        Err(_) => anyhow::bail!("Connection timed out"),
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
        Err(_) => anyhow::bail!("request timed out after {}s", timeout.as_secs()),
    }

    serde_json::from_str(line.trim()).map_err(|e| anyhow::anyhow!("Invalid response: {e}"))
}

// prewarm-many is the top-level CLI entry for batch prewarms; every flag
// is a direct mirror of a request field, so lumping them into a struct
// would only add boilerplate.
#[allow(clippy::too_many_arguments)]
async fn run_prewarm_many(
    endpoint: Endpoint,
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

    let endpoint = Arc::new(BatchEndpoint {
        initial: endpoint,
        recovery: OnceCell::new(),
    });
    let semaphore = Arc::new(Semaphore::new(jobs));
    let mut handles = Vec::new();

    for (idx, path) in paths.iter().enumerate() {
        let endpoint = endpoint.clone();
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
            let resp = endpoint.send(&req, timeout, restart_daemon).await;
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
                results.push(
                    serde_json::json!({ "path": path, "ok": false, "error": err.to_string() }),
                );
            }
        }
    }

    let failed = results.iter().filter(|item| item["ok"] == false).count();
    let output = serde_json::json!({
        "count": results.len(),
        "results": results,
    });
    println!(
        "{}",
        format::format_response(output_mode, "prewarm_many", &output)
    );
    if failed != 0 {
        anyhow::bail!("{failed} prewarm item(s) failed");
    }
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
    endpoint: &mut Endpoint,
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
                        let err_resp = RpcResponse::err(seq.to_string(), -32700, e.to_string());
                        println!("{}", serde_json::to_string(&err_resp).unwrap_or_default());
                        seq += 1;
                        continue;
                    }
                };

                if let Some(p) = global_path {
                    if req.params.get("path").is_none() {
                        if let Some(obj) = req.params.as_object_mut() {
                            obj.insert("path".to_string(), serde_json::json!(p));
                        }
                    }
                }

                match send_recoverable(endpoint, &req, timeout).await {
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

#[cfg(test)]
mod tests {
    use super::{build_rpc_params, CliCommand};

    #[test]
    fn build_rpc_params_for_cli_surface_methods() {
        let (method, params) = build_rpc_params(
            &CliCommand::ListImports {
                limit: 5,
                offset: 2,
            },
            Some("/tmp/a.bin"),
            None,
        );
        assert_eq!(method, "list_imports");
        assert_eq!(params["path"], "/tmp/a.bin");
        assert_eq!(params["limit"], 5);
        assert_eq!(params["offset"], 2);

        let (method, params) = build_rpc_params(
            &CliCommand::XrefsToString {
                query: "malloc".to_string(),
                limit: 4,
                max_xrefs: 3,
                exact: false,
                case_insensitive: true,
            },
            Some("/tmp/a.bin"),
            None,
        );
        assert_eq!(method, "get_xrefs_to_string");
        assert_eq!(params["query"], "malloc");
        assert_eq!(params["limit"], 4);
        assert_eq!(params["max_xrefs"], 3);
        assert_eq!(params["case_insensitive"], true);

        let (method, params) = build_rpc_params(
            &CliCommand::Callers {
                addr: "0x1000".to_string(),
            },
            None,
            None,
        );
        assert_eq!(method, "get_callers");
        assert_eq!(params["address"], "0x1000");

        let (method, params) = build_rpc_params(
            &CliCommand::AddressInfo {
                addr: "0x2000".to_string(),
            },
            None,
            None,
        );
        assert_eq!(method, "get_address_info");
        assert_eq!(params["address"], "0x2000");
    }
}

#[cfg(all(test, unix, feature = "nexus-test-support"))]
pub(crate) async fn test_bridge_loss_response_no_replay(response: RpcResponse) -> (i64, usize) {
    bridge_loss_recovery_tests::check_no_replay(response).await
}

#[cfg(all(test, unix))]
mod bridge_loss_recovery_tests {
    use super::*;
    use crate::router::protocol::RpcError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::UnixListener;

    static CASES: AtomicUsize = AtomicUsize::new(0);

    fn case_dir() -> std::path::PathBuf {
        let dir = std::path::PathBuf::from(format!(
            "/tmp/icr-{}-{}",
            std::process::id(),
            CASES.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("private case dir");
        dir
    }

    fn reply(code: Option<i64>, message: &str) -> RpcResponse {
        RpcResponse {
            jsonrpc: "2.0".into(),
            id: "1".into(),
            result: code.is_none().then(|| serde_json::json!({"ok": true})),
            error: code.map(|code| RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// One-connection-per-request fake daemon that answers every request with
    /// `response` and counts them.
    fn fake_daemon(
        socket: &Path,
        response: RpcResponse,
    ) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = UnixListener::bind(socket).expect("bind fake daemon");
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (reader, mut writer) = stream.into_split();
                let mut line = String::new();
                // Liveness probes connect and close without sending a request.
                match BufReader::new(reader).read_line(&mut line).await {
                    Ok(0) | Err(_) => continue,
                    Ok(_) => {}
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let mut out = serde_json::to_vec(&response).expect("encode");
                out.push(b'\n');
                let _ = writer.write_all(&out).await;
            }
        });
        (seen, task)
    }

    #[cfg(feature = "nexus-test-support")]
    pub(super) async fn check_no_replay(response: RpcResponse) -> (i64, usize) {
        let dir = case_dir();
        let socket = dir.join("continuation");
        let (seen, daemon) = fake_daemon(&socket, response);
        let mut endpoint = Endpoint {
            path: socket,
            pinned: false,
        };
        let restarts = Arc::new(AtomicUsize::new(0));
        let restarted = restarts.clone();
        let response = send_recoverable_with(&mut endpoint, &request(), TIMEOUT, move |_| {
            restarted.fetch_add(1, Ordering::SeqCst);
            Err("unexpected restart".into())
        })
        .await
        .expect("ordinary failure response");
        let code = response.error.expect("continuation error").code;
        let requests = seen.load(Ordering::SeqCst);
        daemon.abort();
        std::fs::remove_dir_all(dir).expect("remove fake endpoint");
        assert_eq!(restarts.load(Ordering::SeqCst), 0, "no CLI restart");
        (code, requests)
    }

    fn request() -> RpcRequest {
        RpcRequest::new("1", "list_functions", serde_json::json!({"path": "/tmp/x"}))
    }

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    #[tokio::test]
    async fn batch_refusals_share_one_recovery_and_retry_each_item_once() {
        for second_refusal in [false, true] {
            let dir = case_dir();
            let old_socket = dir.join("old");
            let new_socket = dir.join("new");
            let listener = UnixListener::bind(&old_socket).expect("old batch daemon");
            let old = tokio::spawn(async move {
                let mut waiting = Vec::new();
                for _ in 0..6 {
                    let (stream, _) = listener.accept().await.expect("batch connection");
                    let (reader, writer) = stream.into_split();
                    let mut line = String::new();
                    BufReader::new(reader)
                        .read_line(&mut line)
                        .await
                        .expect("batch request");
                    waiting.push(writer);
                }
                // All six requests were sent to the old generation before any
                // refusal is released, so recovery must be shared in flight.
                for mut writer in waiting {
                    let response = reply(Some(RPC_BRIDGE_LOST_NOT_DISPATCHED), "entrance refusal");
                    writer
                        .write_all(
                            format!(
                                "{}\n",
                                serde_json::to_string(&response).expect("refusal JSON")
                            )
                            .as_bytes(),
                        )
                        .await
                        .expect("refusal response");
                }
            });
            let (seen, new) = fake_daemon(
                &new_socket,
                reply(
                    second_refusal.then_some(RPC_BRIDGE_LOST_NOT_DISPATCHED),
                    "replacement",
                ),
            );
            let endpoint = Arc::new(BatchEndpoint {
                initial: Endpoint {
                    path: old_socket,
                    pinned: false,
                },
                recovery: OnceCell::new(),
            });
            let restarts = Arc::new(AtomicUsize::new(0));
            let mut items = Vec::new();
            for _ in 0..6 {
                let endpoint = endpoint.clone();
                let restarts = restarts.clone();
                let path = new_socket.clone();
                items.push(tokio::spawn(async move {
                    endpoint
                        .send(&request(), TIMEOUT, move |_| {
                            restarts.fetch_add(1, Ordering::SeqCst);
                            Ok(path)
                        })
                        .await
                        .expect("batch response")
                }));
            }
            for item in items {
                let response = item.await.expect("batch item");
                assert_eq!(refused_before_dispatch(&response), second_refusal);
            }
            old.await.expect("all initial requests refused");
            assert_eq!(
                seen.load(Ordering::SeqCst),
                6,
                "exactly one replay per refusal"
            );
            assert_eq!(restarts.load(Ordering::SeqCst), 1, "one shared restart");
            // A later item uses the recovered endpoint directly, even if that
            // endpoint refuses too; it must not trigger another recovery.
            endpoint
                .send(&request(), TIMEOUT, |_| panic!("second recovery"))
                .await
                .expect("later item");
            assert_eq!(seen.load(Ordering::SeqCst), 7);
            new.abort();
            std::fs::remove_dir_all(dir).expect("remove batch fixture");
        }
    }

    #[tokio::test]
    async fn batch_does_not_replay_unknown_accepted_or_pinned_items() {
        for (pinned, response) in [
            (false, reply(Some(-32000), "UnknownOutcome; never replay")),
            (
                false,
                RpcResponse {
                    result: Some(serde_json::json!({"status":"queued", "task_id":"accepted"})),
                    ..reply(None, "")
                },
            ),
            (
                true,
                reply(Some(RPC_BRIDGE_LOST_NOT_DISPATCHED), "entrance refusal"),
            ),
        ] {
            let dir = case_dir();
            let socket = dir.join("only");
            let (seen, daemon) = fake_daemon(&socket, response.clone());
            let endpoint = BatchEndpoint {
                initial: Endpoint {
                    path: socket,
                    pinned,
                },
                recovery: OnceCell::new(),
            };
            let actual = endpoint
                .send(&request(), TIMEOUT, |_| panic!("unsafe batch replay"))
                .await
                .expect("original response");
            assert_eq!(
                serde_json::to_value(actual).expect("actual JSON"),
                serde_json::to_value(response).expect("expected JSON")
            );
            assert_eq!(seen.load(Ordering::SeqCst), 1);
            daemon.abort();
            std::fs::remove_dir_all(dir).expect("remove batch fixture");
        }
    }

    #[tokio::test]
    async fn batch_shares_failed_recovery_and_never_replays_transport_errors() {
        let dir = case_dir();
        let socket = dir.join("stuck");
        let (seen, daemon) = fake_daemon(
            &socket,
            reply(Some(RPC_BRIDGE_LOST_NOT_DISPATCHED), "refused"),
        );
        let endpoint = BatchEndpoint {
            initial: Endpoint {
                path: socket,
                pinned: false,
            },
            recovery: OnceCell::new(),
        };
        let restarts = Arc::new(AtomicUsize::new(0));
        for _ in 0..6 {
            let restarts = restarts.clone();
            let response = endpoint
                .send(&request(), TIMEOUT, move |_| {
                    restarts.fetch_add(1, Ordering::SeqCst);
                    Err("old daemon has not exited".into())
                })
                .await
                .expect("original refusal");
            assert!(refused_before_dispatch(&response));
        }
        assert_eq!(seen.load(Ordering::SeqCst), 6);
        assert_eq!(restarts.load(Ordering::SeqCst), 1);
        daemon.abort();
        let missing = BatchEndpoint {
            initial: Endpoint {
                path: dir.join("missing"),
                pinned: false,
            },
            recovery: OnceCell::new(),
        };
        let error = missing
            .send(&request(), TIMEOUT, |_| {
                panic!("connection failure cannot replay")
            })
            .await
            .expect_err("missing socket is an item error");
        assert!(error.to_string().contains("Cannot connect"));
        assert!(missing.recovery.get().is_none());
        std::fs::remove_dir_all(dir).expect("remove recovery fixture");
    }

    #[tokio::test]
    async fn batch_transport_timeout_is_an_item_error_without_recovery() {
        let dir = case_dir();
        let socket = dir.join("slow");
        let listener = UnixListener::bind(&socket).expect("slow daemon");
        let daemon = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("connection");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            drop(stream);
        });
        let endpoint = BatchEndpoint {
            initial: Endpoint {
                path: socket,
                pinned: false,
            },
            recovery: OnceCell::new(),
        };
        let error = endpoint
            .send(&request(), std::time::Duration::from_millis(10), |_| {
                panic!("timeout does not prove no dispatch")
            })
            .await
            .expect_err("timeout returned to batch");
        assert!(error.to_string().contains("request timed out"));
        assert!(endpoint.recovery.get().is_none());
        daemon.await.expect("slow connection closed");
        std::fs::remove_dir_all(dir).expect("remove timeout fixture");
    }

    #[tokio::test]
    async fn refused_before_dispatch_waits_for_the_exit_then_retries_exactly_once() {
        let dir = case_dir();
        let (old_socket, new_socket) = (dir.join("old"), dir.join("new"));
        let (old_seen, _old) = fake_daemon(
            &old_socket,
            reply(Some(RPC_BRIDGE_LOST_NOT_DISPATCHED), "bridge lost"),
        );
        let (new_seen, _new) = fake_daemon(&new_socket, reply(None, ""));
        let mut endpoint = Endpoint {
            path: old_socket.clone(),
            pinned: false,
        };
        let restarted = new_socket.clone();
        let resp = send_recoverable_with(&mut endpoint, &request(), TIMEOUT, move |old| {
            assert!(
                old.ends_with("old"),
                "restart is told which daemon was lost"
            );
            Ok(restarted)
        })
        .await
        .expect("recovered request");
        assert!(
            resp.error.is_none(),
            "the retry on the fresh daemon succeeded"
        );
        assert_eq!(
            (
                old_seen.load(Ordering::SeqCst),
                new_seen.load(Ordering::SeqCst)
            ),
            (1, 1)
        );
        assert_eq!(
            endpoint.path, new_socket,
            "later requests use the fresh daemon"
        );
    }

    #[tokio::test]
    async fn a_second_refusal_is_returned_without_a_third_attempt() {
        let dir = case_dir();
        let (old_socket, new_socket) = (dir.join("old"), dir.join("new"));
        let refusal = reply(Some(RPC_BRIDGE_LOST_NOT_DISPATCHED), "bridge lost");
        let (old_seen, _old) = fake_daemon(&old_socket, refusal.clone());
        let (new_seen, _new) = fake_daemon(&new_socket, refusal);
        let mut endpoint = Endpoint {
            path: old_socket,
            pinned: false,
        };
        let restarted = new_socket;
        let resp =
            send_recoverable_with(&mut endpoint, &request(), TIMEOUT, move |_| Ok(restarted))
                .await
                .expect("response");
        assert!(refused_before_dispatch(&resp));
        assert_eq!(
            (
                old_seen.load(Ordering::SeqCst),
                new_seen.load(Ordering::SeqCst)
            ),
            (1, 1)
        );
    }

    #[tokio::test]
    async fn an_unknown_outcome_or_ordinary_error_is_never_replayed() {
        for response in [
            reply(
                Some(-32000),
                "Nexus UnknownOutcome: connection lost after dispatch; do not replay",
            ),
            reply(
                Some(-32000),
                "Nexus: bridge disconnected; open outcome retained by N1; never replay",
            ),
        ] {
            let dir = case_dir();
            let socket = dir.join("only");
            let (seen, _daemon) = fake_daemon(&socket, response);
            let mut endpoint = Endpoint {
                path: socket,
                pinned: false,
            };
            let resp = send_recoverable_with(&mut endpoint, &request(), TIMEOUT, |_| {
                panic!("a dispatched request must never trigger a restart")
            })
            .await
            .expect("response");
            assert_eq!(resp.error.expect("error").code, -32000);
            assert_eq!(seen.load(Ordering::SeqCst), 1, "no replay");
        }
    }

    #[tokio::test]
    async fn a_pinned_socket_is_never_replaced_or_retried() {
        let dir = case_dir();
        let socket = dir.join("pinned");
        let (seen, _daemon) = fake_daemon(
            &socket,
            reply(Some(RPC_BRIDGE_LOST_NOT_DISPATCHED), "bridge lost"),
        );
        let mut endpoint = Endpoint {
            path: socket,
            pinned: true,
        };
        let resp = send_recoverable_with(&mut endpoint, &request(), TIMEOUT, |_| {
            panic!("an explicit --socket / $IDA_MCP_SOCKET never starts or waits for a daemon")
        })
        .await
        .expect("response");
        assert!(refused_before_dispatch(&resp));
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_daemon_that_does_not_exit_leaves_the_original_refusal() {
        let dir = case_dir();
        let socket = dir.join("stuck");
        let (seen, _daemon) = fake_daemon(
            &socket,
            reply(Some(RPC_BRIDGE_LOST_NOT_DISPATCHED), "bridge lost"),
        );
        let mut endpoint = Endpoint {
            path: socket,
            pinned: false,
        };
        let resp = send_recoverable_with(&mut endpoint, &request(), TIMEOUT, |old| {
            discovery::wait_for_daemon_exit(old, std::time::Duration::from_millis(400))?;
            unreachable!("the stuck daemon never exits")
        })
        .await
        .expect("response");
        assert!(refused_before_dispatch(&resp), "original refusal reported");
        assert_eq!(seen.load(Ordering::SeqCst), 1, "nothing was resent");
    }

    #[test]
    fn wait_for_daemon_exit_returns_when_nothing_listens_any_more() {
        let dir = case_dir();
        let socket = dir.join("leaving");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
        let socket_for_thread = socket.clone();
        let leaving = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(listener);
            let _ = std::fs::remove_file(&socket_for_thread);
        });
        discovery::wait_for_daemon_exit(&socket, std::time::Duration::from_secs(5))
            .expect("exit observed");
        leaving.join().expect("leaving thread");
    }
}
