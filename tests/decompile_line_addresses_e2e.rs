//! End-to-end test of `decompile_function` with `line_addresses` against a
//! real daemon.
//!
//! Starts a throwaway `serve-http` daemon under an isolated `IDA_CLI_HOME`,
//! opens a small compiled fixture over MCP and decompiles one function with
//! and without `line_addresses`, over MCP and over the `decompile` CLI
//! subcommand. It stops the daemon with `shutdown` through the same isolated
//! home and never touches `~/.ida` or any other daemon.
//!
//! Needs a licensed IDA runtime with the Hex-Rays decompiler and a C compiler:
//!
//! ```text
//! IDA_TEST=1 cargo test --test decompile_line_addresses_e2e
//! ```
//!
//! `IDA_CLI_E2E_BIN` runs the test against another build of `ida-cli` (for
//! example the release binary); `DECOMPILE_LINES_E2E_OUT` writes the answers
//! to that file.

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

/// A loop with a branch, so the pseudocode has statements on several lines
/// plus lines that carry no address (declarations, braces).
const FIXTURE: &str = r#"
int collatz_steps(unsigned n) {
    int steps = 0;
    while (n != 1) {
        if (n % 2 == 0)
            n /= 2;
        else
            n = 3 * n + 1;
        steps++;
    }
    return steps;
}

int main(int argc, char **argv) {
    (void)argv;
    return collatz_steps((unsigned)argc + 6);
}
"#;

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
    let dir = base.join(format!("ida-dl-{label}-{}-{nanos}", std::process::id()));
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

    /// The CLI's JSON answer; a response-cache stub is replaced by the file it
    /// points to, which holds the full answer.
    fn cli_json(&self, args: &[&str]) -> Value {
        let output = self.cli(args);
        assert!(
            output.status.success(),
            "ida-cli {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).expect("CLI prints JSON");
        if value["cached"] == json!(true) {
            let file = value["file"].as_str().expect("cache file");
            let text = fs::read_to_string(file).expect("read cached answer");
            return serde_json::from_str(&text).expect("cached answer is JSON");
        }
        value
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

    fn call_tool_json(&mut self, name: &str, arguments: Value) -> Value {
        let (is_error, text) = self.call_tool(name, arguments);
        assert!(!is_error, "{name} returned an error: {text}");
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{name} printed no JSON ({e}): {text}"))
    }

    fn open_idb(&mut self, path: &Path) -> String {
        let value = self.call_tool_json("open_idb", json!({"path": path}));
        value["db_handle"].as_str().expect("db_handle").to_string()
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

fn parse_hex(text: &str) -> u64 {
    let digits = text
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("not a 0x address: {text}"));
    u64::from_str_radix(digits, 16).unwrap_or_else(|e| panic!("bad address {text}: {e}"))
}

/// The function whose name contains `needle`: `(address, size)`.
fn find_function(client: &mut McpClient, handle: &str, needle: &str) -> (u64, u64) {
    let listing = client.call_tool_json(
        "list_functions",
        json!({"db_handle": handle, "filter": needle, "limit": 10}),
    );
    let function = listing["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .find(|f| f["name"].as_str().is_some_and(|n| n.contains(needle)))
        .unwrap_or_else(|| panic!("no function named like {needle}: {listing}"));
    (
        parse_hex(function["address"].as_str().expect("address")),
        function["size"].as_u64().expect("size"),
    )
}

/// Check one `lines` array against the plain `code` of the same function.
fn assert_lines_match_code(code: &str, lines: &Value, start: u64, size: u64) -> (usize, usize) {
    let lines = lines.as_array().expect("lines array");
    let code_lines: Vec<&str> = code.split_terminator('\n').collect();
    assert_eq!(
        lines.len(),
        code_lines.len(),
        "one entry per pseudocode line:\n{code}"
    );
    let mut with_addresses = 0;
    let mut all_addresses = 0;
    for (index, (entry, code_line)) in lines.iter().zip(&code_lines).enumerate() {
        assert_eq!(entry["line"], json!(index + 1), "line numbers start at 1");
        assert_eq!(
            entry["text"].as_str().expect("text"),
            *code_line,
            "line {} text differs from the plain pseudocode",
            index + 1
        );
        let addresses: Vec<u64> = entry["addresses"]
            .as_array()
            .expect("addresses array")
            .iter()
            .map(|a| parse_hex(a.as_str().expect("address string")))
            .collect();
        assert!(
            addresses.windows(2).all(|pair| pair[0] < pair[1]),
            "line {}: addresses must be ascending and unique: {addresses:x?}",
            index + 1
        );
        for address in &addresses {
            assert!(
                (start..start + size).contains(address),
                "line {}: {address:#x} is outside the function {start:#x}..{:#x}",
                index + 1,
                start + size
            );
        }
        with_addresses += usize::from(!addresses.is_empty());
        all_addresses += addresses.len();
    }
    (with_addresses, all_addresses)
}

/// Write the answers collected so far to `DECOMPILE_LINES_E2E_OUT`, if set.
fn save_transcript(transcript: &[Value]) {
    if let Some(out) = std::env::var_os("DECOMPILE_LINES_E2E_OUT") {
        fs::write(
            out,
            serde_json::to_string_pretty(transcript).expect("render transcript"),
        )
        .expect("write transcript");
    }
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn decompile_function_returns_line_addresses_through_a_real_daemon() {
    assert!(
        ida_available(),
        "BLOCKED: set IDA_TEST=1 and use an isolated prepared IDA environment"
    );

    let work = Scratch(scratch_dir("work"));
    let fixture = build_fixture(&work.0, "collatz", FIXTURE);

    let mut daemon = Daemon::start(ida_cli_bin());
    let mut transcript: Vec<Value> = Vec::new();
    let mut client = McpClient::connect(&daemon.mcp_socket(), "decompile-lines-e2e");
    let handle = client.open_idb(&fixture);
    let (start, size) = find_function(&mut client, &handle, "collatz_steps");
    let address = format!("{start:#x}");

    // Default: the plain answer, as before the parameter existed.
    let plain = client.call_tool_json(
        "decompile_function",
        json!({"db_handle": handle, "address": address}),
    );
    assert_eq!(
        plain
            .as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>()),
        Some(vec!["code".to_string()]),
        "without line_addresses the answer is only {{code}}: {plain}"
    );
    let code = plain["code"].as_str().expect("code").to_string();
    assert!(code.contains("while"), "unexpected pseudocode:\n{code}");
    let explicitly_off = client.call_tool_json(
        "decompile_function",
        json!({"db_handle": handle, "address": address, "line_addresses": false}),
    );
    assert_eq!(explicitly_off, plain);
    transcript.push(json!({"via": "mcp", "line_addresses": false, "answer": plain}));

    // line_addresses: the same code plus one entry per line.
    let with_lines = client.call_tool_json(
        "decompile_function",
        json!({"db_handle": handle, "address": address, "line_addresses": true}),
    );
    transcript.push(json!({"via": "mcp", "line_addresses": true, "answer": with_lines}));
    save_transcript(&transcript);
    assert_eq!(
        with_lines.as_object().map(|o| {
            let mut keys: Vec<_> = o.keys().cloned().collect();
            keys.sort();
            keys
        }),
        Some(vec!["code".to_string(), "lines".to_string()]),
        "{with_lines}"
    );
    assert_eq!(with_lines["code"], plain["code"], "code must not change");
    let (with_addresses, all_addresses) =
        assert_lines_match_code(&code, &with_lines["lines"], start, size);
    let line_count = with_lines["lines"].as_array().expect("lines").len();
    assert!(
        with_addresses >= 3,
        "at least a few statements carry an address: {with_lines}"
    );
    assert!(
        with_addresses < line_count,
        "declarations and braces carry none: {with_lines}"
    );
    assert!(all_addresses >= with_addresses);

    // Asking twice gives the same answer.
    let again = client.call_tool_json(
        "decompile_function",
        json!({"db_handle": handle, "address": address, "line_addresses": true}),
    );
    assert_eq!(again, with_lines);

    // Spot check against the decompiler's own statement map. Every address on
    // a line must be an address the decompiler maps to statements, and a line
    // that is a statement itself must be among the statements at its
    // addresses. `{`, `}`, `else` and blank lines carry the address of the
    // block or `if` that owns them, so only the first half applies to them.
    let mut statement_lines = 0;
    let mut checked_addresses = 0;
    for entry in with_lines["lines"].as_array().expect("lines") {
        let line_text = normalized(entry["text"].as_str().expect("text"));
        let structural = matches!(line_text.as_str(), "" | "{" | "}" | "else");
        let mut statement_texts: Vec<String> = Vec::new();
        for hex in entry["addresses"].as_array().expect("addresses") {
            let at = client.call_tool_json(
                "get_pseudocode_at",
                json!({"db_handle": handle, "address": hex}),
            );
            let statements = at["statements"].as_array().expect("statements");
            assert!(
                !statements.is_empty(),
                "no statement at {hex} ({line_text})"
            );
            statement_texts.extend(
                statements
                    .iter()
                    .map(|s| normalized(s["text"].as_str().expect("statement text"))),
            );
            checked_addresses += 1;
        }
        if structural || entry["addresses"].as_array().expect("addresses").is_empty() {
            continue;
        }
        // A compound statement (`while`, `if`) prints with its body, so the
        // line is a prefix of the statement; a simple one equals the line.
        assert!(
            statement_texts
                .iter()
                .any(|t| t.contains(line_text.as_str()) || line_text.contains(t.as_str())),
            "statements {statement_texts:?} at the addresses of line {line_text:?} \
             do not include it"
        );
        statement_lines += 1;
    }
    assert!(
        checked_addresses >= 8,
        "only {checked_addresses} addresses checked"
    );
    assert!(
        statement_lines >= 5,
        "only {statement_lines} statement lines checked"
    );

    // Several addresses: each entry carries its own lines.
    let (main_start, main_size) = find_function(&mut client, &handle, "main");
    let both = client.call_tool_json(
        "decompile_function",
        json!({
            "db_handle": handle,
            "address": [address, format!("{main_start:#x}")],
            "line_addresses": true
        }),
    );
    let results = both["results"].as_array().expect("results");
    assert_eq!(results.len(), 2, "{both}");
    assert_eq!(results[0]["address"], json!(address));
    assert_eq!(results[0]["lines"], with_lines["lines"]);
    assert_lines_match_code(
        results[1]["code"].as_str().expect("main code"),
        &results[1]["lines"],
        main_start,
        main_size,
    );

    // The CLI sends the same request: `decompile --line-addresses`.
    let fixture_arg = fixture.to_string_lossy().to_string();
    let cli_plain = daemon.cli_json(&[
        "--json",
        "--path",
        &fixture_arg,
        "decompile",
        "--addr",
        &address,
    ]);
    assert_eq!(cli_plain, plain);
    let cli_lines = daemon.cli_json(&[
        "--json",
        "--path",
        &fixture_arg,
        "decompile",
        "--addr",
        &address,
        "--line-addresses",
    ]);
    assert_eq!(cli_lines, with_lines);
    transcript.push(json!({"via": "cli", "line_addresses": true, "answer": cli_lines}));

    save_transcript(&transcript);

    drop(client);
    daemon.shutdown();
    assert!(
        !daemon.mcp_socket().exists(),
        "daemon must remove its MCP socket on shutdown"
    );
}
