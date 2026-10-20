//! End-to-end test of `list_idbs` against a real daemon.
//!
//! Starts a throwaway `serve-http` daemon under an isolated `IDA_CLI_HOME`,
//! drives it with two independent MCP sessions over its Unix socket plus the
//! `list-idbs` CLI subcommand, and stops it with `shutdown` through the same
//! isolated home. It never touches `~/.ida` or any other daemon.
//!
//! Needs a licensed IDA runtime and a C compiler:
//!
//! ```text
//! IDA_TEST=1 cargo test --test list_idbs_e2e
//! ```
//!
//! `IDA_CLI_E2E_BIN` runs the test against another build of `ida-cli` (for
//! example the release binary); `LIST_IDBS_E2E_OUT` writes the transcript of
//! every `list_idbs` answer to that file.

use ida_mcp::process_spawn::SpawnFenced;
use ida_mcp::process_spawn::StdOutputFenced;
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OPEN_TIMEOUT: Duration = Duration::from_secs(300);
const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(60);
const DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(60);

fn ida_available() -> bool {
    std::env::var("IDA_TEST").is_ok_and(|v| v == "1")
}

fn ida_cli_bin() -> PathBuf {
    std::env::var_os("IDA_CLI_E2E_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_ida-cli")))
}

/// A short, private scratch directory. Unix socket paths are capped near 104
/// bytes on macOS, so this cannot live under a long temp path.
fn scratch_dir(label: &str) -> PathBuf {
    let base = if Path::new("/private/tmp").is_dir() {
        PathBuf::from("/private/tmp")
    } else {
        std::env::temp_dir()
    };
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let dir = base.join(format!("ida-li-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A scratch directory that is removed on drop, also when the test panics.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A daemon on an isolated home. Dropping it stops the process it started and
/// removes the home.
struct Daemon {
    child: Child,
    home: PathBuf,
    bin: PathBuf,
}

impl Daemon {
    fn start(bin: PathBuf) -> Self {
        let home = scratch_dir("home");
        let log = fs::File::create(home.join("daemon.out")).expect("create daemon log");
        let child = Command::new(&bin)
            .args(["serve-http", "--bind", "127.0.0.1:0"])
            .env("IDA_CLI_HOME", &home)
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("clone daemon log"))
            .stderr(log)
            .spawn_fenced()
            .unwrap_or_else(|e| panic!("cannot start {}: {e}", bin.display()));
        let mut daemon = Self { child, home, bin };
        daemon.wait_until_ready();
        daemon
    }

    fn mcp_socket(&self) -> PathBuf {
        self.home.join("mcp.sock")
    }

    fn rpc_socket(&self) -> PathBuf {
        self.home.join("server.sock")
    }

    fn log_tail(&self) -> String {
        let text = fs::read_to_string(self.home.join("daemon.out")).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + DAEMON_START_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll daemon") {
                panic!("daemon exited early ({status}):\n{}", self.log_tail());
            }
            if self.rpc_socket().exists() && UnixStream::connect(self.mcp_socket()).is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "daemon not ready in time:\n{}",
                self.log_tail()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Run the `ida-cli` CLI against this daemon only (explicit socket, same home).
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(&self.bin)
            .env("IDA_CLI_HOME", &self.home)
            .arg("--socket")
            .arg(self.rpc_socket())
            .args(args)
            .stdin(Stdio::null())
            .output_fenced()
            .expect("run ida-cli")
    }

    fn cli_json(&self, args: &[&str]) -> Value {
        let output = self.cli(args);
        assert!(
            output.status.success(),
            "ida-cli {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("CLI prints JSON")
    }

    /// Stop the daemon through its isolated home and wait for it to exit.
    fn shutdown(&mut self) {
        let output = self.cli(&["shutdown"]);
        assert!(
            output.status.success(),
            "shutdown failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let deadline = Instant::now() + DAEMON_STOP_TIMEOUT;
        loop {
            match self.child.try_wait().expect("poll daemon") {
                Some(status) => {
                    assert!(
                        status.success(),
                        "daemon exit: {status}\n{}",
                        self.log_tail()
                    );
                    return;
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "daemon did not stop after shutdown:\n{}",
                        self.log_tail()
                    );
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Only ever our own child, by handle.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = fs::remove_dir_all(&self.home);
    }
}

/// One MCP session over the daemon's Unix socket (newline-delimited JSON-RPC).
struct McpClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl McpClient {
    fn connect(socket: &Path, name: &str) -> Self {
        let stream = UnixStream::connect(socket).expect("connect MCP socket");
        stream
            .set_read_timeout(Some(OPEN_TIMEOUT))
            .expect("set read timeout");
        let mut client = Self {
            reader: BufReader::new(stream.try_clone().expect("clone stream")),
            writer: stream,
            next_id: 1,
        };
        client.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": name, "version": "0"}
            }),
        );
        client.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        client
    }

    fn send(&mut self, message: &Value) {
        let mut line = serde_json::to_vec(message).expect("serialize request");
        line.push(b'\n');
        self.writer.write_all(&line).expect("write request");
    }

    /// Send a request and return its `result`, skipping unrelated messages.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let mut line = String::new();
            let read = self.reader.read_line(&mut line).expect("read response");
            assert_ne!(read, 0, "daemon closed the MCP connection");
            let message: Value = serde_json::from_str(line.trim()).expect("JSON-RPC line");
            if message["id"] != json!(id) {
                continue;
            }
            assert!(
                message.get("error").is_none(),
                "{method} failed: {}",
                message["error"]
            );
            return message["result"].clone();
        }
    }

    /// Call a tool; returns `(is_error, text of the first content block)`.
    fn call_tool(&mut self, name: &str, arguments: Value) -> (bool, String) {
        let result = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let text = result["content"][0]["text"]
            .as_str()
            .expect("text content")
            .to_string();
        (result["isError"] == json!(true), text)
    }

    fn call_tool_json(&mut self, name: &str, arguments: Value) -> (Value, String) {
        let (is_error, text) = self.call_tool(name, arguments);
        assert!(!is_error, "{name} returned an error: {text}");
        (serde_json::from_str(&text).expect("tool prints JSON"), text)
    }

    fn open_idb(&mut self, path: &Path) -> (String, String) {
        let (value, _) = self.call_tool_json("open_idb", json!({"path": path}));
        (
            value["db_handle"].as_str().expect("db_handle").to_string(),
            value["close_token"]
                .as_str()
                .expect("close_token")
                .to_string(),
        )
    }

    fn close_idb(&mut self, token: &str) -> String {
        let (is_error, text) = self.call_tool("close_idb", json!({"token": token}));
        assert!(!is_error, "close_idb returned an error: {text}");
        text
    }

    /// `list_idbs` as this session: the parsed answer and its raw text.
    fn list_idbs(&mut self) -> (Value, String) {
        self.call_tool_json("list_idbs", json!({}))
    }
}

/// Build a tiny native executable for IDA to open as a raw binary.
fn build_fixture(dir: &Path, name: &str, body: &str) -> PathBuf {
    let source = dir.join(format!("{name}.c"));
    let binary = dir.join(name);
    fs::write(&source, body).expect("write fixture source");
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let output = Command::new(&compiler)
        .args(["-O0", "-o"])
        .arg(&binary)
        .arg(&source)
        .output_fenced()
        .unwrap_or_else(|e| panic!("cannot run {compiler}: {e}"));
    assert!(
        output.status.success(),
        "{compiler} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::canonicalize(&binary).expect("canonical fixture path")
}

fn idbs(listing: &Value) -> &Vec<Value> {
    listing["idbs"]
        .as_array()
        .unwrap_or_else(|| panic!("not a list_idbs answer: {listing}"))
}

fn entry<'a>(listing: &'a Value, handle: &str) -> &'a Value {
    idbs(listing)
        .iter()
        .find(|idb| idb["db_handle"] == handle)
        .unwrap_or_else(|| panic!("{handle} is not listed in {listing}"))
}

fn handles(listing: &Value) -> Vec<String> {
    let mut handles: Vec<String> = idbs(listing)
        .iter()
        .map(|idb| idb["db_handle"].as_str().expect("db_handle").to_string())
        .collect();
    handles.sort();
    handles
}

fn sorted(mut handles: Vec<String>) -> Vec<String> {
    handles.sort();
    handles
}

#[test]
fn list_idbs_follows_two_clients_through_a_real_daemon() {
    if !ida_available() {
        eprintln!("skipping list_idbs e2e: set IDA_TEST=1 (needs an IDA runtime)");
        return;
    }

    let work = Scratch(scratch_dir("work"));
    let alpha = build_fixture(&work.0, "alpha", "int main(void) { return 1; }\n");
    let beta = build_fixture(
        &work.0,
        "beta",
        "static int twice(int x) { return x * 2; }\nint main(int argc, char **argv) { return twice(argc); }\n",
    );

    let mut daemon = Daemon::start(ida_cli_bin());
    let home = fs::canonicalize(&daemon.home).expect("canonical home");
    let mut transcript: Vec<Value> = Vec::new();
    let mut record = |step: &str, via: &str, value: &Value| {
        transcript.push(json!({"step": step, "via": via, "list_idbs": value}));
    };

    let mut client_a = McpClient::connect(&daemon.mcp_socket(), "list-idbs-e2e-a");
    let mut client_b = McpClient::connect(&daemon.mcp_socket(), "list-idbs-e2e-b");

    // The tool is advertised next to the existing database tools.
    let tools = client_a.request("tools/list", json!({}));
    let names: Vec<&str> = tools["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for existing in ["open_idb", "close_idb", "get_database_info"] {
        assert!(
            names.contains(&existing),
            "{existing} missing from tools/list"
        );
    }
    assert!(
        names.contains(&"list_idbs"),
        "list_idbs missing from tools/list"
    );

    // Nothing open: an empty list, over MCP and over the CLI socket.
    let (empty, _) = client_a.list_idbs();
    assert_eq!(empty, json!({"count": 0, "idbs": []}));
    record("nothing open", "mcp", &empty);
    let empty_cli = daemon.cli_json(&["--json", "list-idbs"]);
    assert_eq!(empty_cli, empty);
    record("nothing open", "cli", &empty_cli);

    // Two clients each open one database.
    let (handle_a, token_a) = client_a.open_idb(&alpha);
    let (handle_b, token_b) = client_b.open_idb(&beta);
    assert_ne!(handle_a, handle_b);

    let (as_a, text_a) = client_a.list_idbs();
    let (as_b, text_b) = client_b.list_idbs();
    record("a opened alpha, b opened beta", "mcp (as a)", &as_a);
    record("a opened alpha, b opened beta", "mcp (as b)", &as_b);
    assert_eq!(as_a["count"], 2);
    assert_eq!(
        handles(&as_a),
        sorted(vec![handle_a.clone(), handle_b.clone()])
    );
    assert_eq!(handles(&as_b), handles(&as_a));

    let alpha_entry = entry(&as_a, &handle_a);
    let beta_entry = entry(&as_a, &handle_b);
    assert_eq!(alpha_entry["input_path"], json!(alpha));
    assert_eq!(beta_entry["input_path"], json!(beta));
    for (idb_entry, name) in [(alpha_entry, "alpha"), (beta_entry, "beta")] {
        assert_eq!(idb_entry["state"], "open", "{name}");
        let idb_path = idb_entry["idb_path"].as_str().expect("idb_path");
        assert!(idb_path.ends_with(".i64"), "{name}: {idb_path}");
        assert!(
            Path::new(idb_path).starts_with(&home),
            "{name} database must live in the isolated home: {idb_path}"
        );
        let opened_at = idb_entry["opened_at"].as_str().expect("opened_at");
        assert!(
            opened_at.len() == 20 && opened_at.ends_with('Z'),
            "{name}: {opened_at}"
        );
        assert!(idb_entry["worker"]["pid"]
            .as_u64()
            .is_some_and(|pid| pid > 0));
        assert!(idb_entry["worker"]["backend"].as_str().is_some(), "{name}");
        assert_eq!(idb_entry["ref_count"], 1, "{name}");
        assert_eq!(idb_entry["opened_by"]["kind"], "mcp", "{name}");
    }
    assert_ne!(
        alpha_entry["opened_by"]["client_id"], beta_entry["opened_by"]["client_id"],
        "two sessions must get two client ids"
    );
    assert_eq!(alpha_entry["opened_by_caller"], true);
    assert_eq!(beta_entry["opened_by_caller"], false);
    assert_eq!(entry(&as_b, &handle_a)["opened_by_caller"], false);
    assert_eq!(entry(&as_b, &handle_b)["opened_by_caller"], true);
    assert_eq!(
        alpha_entry["holders"][0]["client_id"],
        alpha_entry["opened_by"]["client_id"]
    );
    let active: Vec<&Value> = idbs(&as_a)
        .iter()
        .filter(|idb| idb["active"] == true)
        .collect();
    assert_eq!(active.len(), 1, "exactly one active database");
    assert_eq!(active[0]["db_handle"], json!(handle_b));

    // The same answer over the CLI socket, from a caller that opened nothing.
    let via_cli = daemon.cli_json(&["--json", "list-idbs"]);
    record("a opened alpha, b opened beta", "cli", &via_cli);
    assert_eq!(handles(&via_cli), handles(&as_a));
    for idb in idbs(&via_cli) {
        assert_eq!(idb["opened_by_caller"], false);
    }

    // Close tokens are credentials: never part of a listing.
    let cli_text = serde_json::to_string(&via_cli).expect("render");
    for text in [&text_a, &text_b, &cli_text] {
        for token in [&token_a, &token_b] {
            assert!(
                !text.contains(token.as_str()),
                "close token leaked:\n{text}"
            );
        }
        assert!(
            !text.contains("close_token"),
            "close_token key leaked:\n{text}"
        );
    }

    // One client closes its database: only that entry disappears.
    assert_eq!(client_a.close_idb(&token_a), "Database closed");
    let (after_close, _) = client_b.list_idbs();
    record("a closed alpha", "mcp (as b)", &after_close);
    assert_eq!(after_close["count"], 1);
    assert_eq!(handles(&after_close), vec![handle_b.clone()]);
    let after_close_cli = daemon.cli_json(&["--json", "list-idbs"]);
    assert_eq!(handles(&after_close_cli), vec![handle_b.clone()]);

    // A second client takes a reference on b's database: still one entry, two holders.
    let (shared_handle, shared_token) = client_a.open_idb(&beta);
    assert_ne!(shared_handle, handle_b, "Nexus opens hold distinct lease handles");
    assert_ne!(shared_token, token_b, "independent close authority");
    let (shared, shared_text) = client_b.list_idbs();
    record("a also opened beta", "mcp (as b)", &shared);
    assert_eq!(shared["count"], 1);
    let shared_entry = entry(&shared, &handle_b);
    assert_eq!(shared_entry["ref_count"], 2);
    // A second open of the same input must not change what is reported.
    assert_eq!(shared_entry["idb_path"], beta_entry["idb_path"]);
    assert_eq!(shared_entry["input_path"], json!(beta));
    assert_eq!(shared_entry["opened_at"], beta_entry["opened_at"]);
    assert_eq!(
        shared_entry["opened_by"]["client_id"],
        beta_entry["opened_by"]["client_id"]
    );
    let holders = shared_entry["holders"].as_array().expect("holders");
    assert_eq!(holders.len(), 2);
    assert_eq!(
        holders.iter().filter(|h| h["is_caller"] == true).count(),
        1,
        "only the asking session's own holder is flagged"
    );
    assert!(!shared_text.contains(&shared_token));

    // Releasing one of two references keeps the database listed; the last close removes it.
    let released = client_a.close_idb(&shared_token);
    assert!(released.starts_with("Reference released"), "{released}");
    let (after_release, _) = client_b.list_idbs();
    assert_eq!(after_release["count"], 1);
    assert_eq!(entry(&after_release, &handle_b)["ref_count"], 1);

    assert_eq!(client_b.close_idb(&token_b), "Database closed");
    let (closed_all, _) = client_a.list_idbs();
    record("everything closed", "mcp (as a)", &closed_all);
    assert_eq!(closed_all, json!({"count": 0, "idbs": []}));
    let closed_all_cli = daemon.cli_json(&["--json", "list-idbs"]);
    assert_eq!(closed_all_cli, closed_all);

    drop(client_a);
    drop(client_b);
    daemon.shutdown();
    assert!(
        !daemon.mcp_socket().exists(),
        "daemon must remove its MCP socket on shutdown"
    );

    if let Some(out) = std::env::var_os("LIST_IDBS_E2E_OUT") {
        let rendered = serde_json::to_string_pretty(&transcript).expect("render transcript");
        fs::write(out, rendered).expect("write transcript");
    }
}
