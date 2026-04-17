# Multi-IDB Support (Subprocess Router)

Proposal for opening and querying multiple IDA databases within a single MCP session.

## Motivation

The current server supports exactly one open IDB at a time. When a second `open_idb`
call arrives the first database is closed. This makes cross-binary comparison, library
diffing, and firmware analysis workflows impossible without running separate server
instances on different ports.

## Why Not a Single-Process HashMap

The obvious approach—replacing `Option<IDB>` with `HashMap<DbHandle, IDB>`—does not
work. `idalib` initialises IDA's core via a single `idalib::init_library()` call that
populates process-global data structures (segment table, name table, `inf`, type
system). Constructing a second `IDB` object in the same process would share and
corrupt that state.

**To verify:** see Phase 0 below — a standalone probe binary opens two IDBs without
closing the first and records the failure mode. That output is the upstream evidence
needed in the PR description.

## Architecture: Subprocess Router

```
opencode
    │  stdio (MCP)
    ▼
ida-cli  [router mode, default]
    │
    ├─ db_handle = "abc" ──► ida-cli --mode worker  (IDB: binary1.i64)
    ├─ db_handle = "def" ──► ida-cli --mode worker  (IDB: libc.so.i64)
    └─ db_handle = "xyz" ──► ida-cli --mode worker  (IDB: firmware.i64)
```

The router is a regular MCP server. Every tool gains an optional `db_handle`
parameter. When `open_idb` is called the router spawns a child `ida-cli` process in
worker mode, assigns it a handle, and returns that handle to the caller. Subsequent
tool calls carrying the handle are transparently proxied to the correct child.

A caller that never uses handles gets the previous single-IDB behaviour unchanged
(the router maintains an "active" handle pointing to the most-recently-opened DB).

### Active handle scoping (stdio vs HTTP)

In **stdio mode** (single-client), the router holds a process-global `active: Option<DbHandle>`.
When `db_handle` is omitted from a request, the active handle is used. This preserves
exact backward compatibility with today's single-IDB workflow.

In **HTTP/SSE mode** (multi-client via `StreamableHttpService`), a process-global
`active` would be a correctness hazard: any client's `open_idb` would change
every other client's default target. Two options:

- **Option A (simpler, recommended for v1):** In HTTP mode, `db_handle` is **required**
  on all tool calls. Requests without `db_handle` return a clear error:
  `"db_handle is required in HTTP mode when multiple databases are open"`.
  When only one IDB is open, the active handle is used as a convenience fallback.

- **Option B (future):** Bind `active` to the MCP session ID (the `StreamableHttpService`
  already manages per-session state). Each session tracks its own most-recently-opened
  handle. This requires `RouterState` to become session-aware.

Phase 2 implements Option A. Option B can be added later without API changes.

### Close token ownership (multi-handle)

The current `CloseTokenState` in `src/ida/worker.rs` issues a single process-global
token. With multiple handles, each `WorkerProcess` manages its own close token
independently:

- `open_idb` returns `{ db_handle: "abc", close_token: "tok-abc" }`.
- `close_idb(token="tok-abc")` maps to the correct worker via the token → handle
  lookup, not through a global `active`.
- `close_idb` without a token in HTTP mode requires `db_handle` to identify the
  target (same as the active-handle rule above).

## Wire Protocol (Router ↔ Worker)

Newline-delimited JSON-RPC 2.0 over the child's stdin/stdout. The router owns the
tokio async I/O; the worker's main thread runs the existing `run_ida_loop` unchanged.

```
Request  (router → worker stdin):
  {"jsonrpc":"2.0","id":"r1","method":"decompile","params":{"addr":4096}}\n

Response (worker stdout → router):
  {"jsonrpc":"2.0","id":"r1","result":{"code":"int main(){...}"}}\n
  {"jsonrpc":"2.0","id":"r2","error":{"code":-32000,"message":"no IDB open"}}\n
```

### Important: `IdaRequest` is NOT the wire type

The existing `IdaRequest` enum (`src/ida/request.rs`) contains `resp:
oneshot::Sender<...>` fields which cannot be serialised or sent across process
boundaries. A new serialisable enum `WorkerRpcRequest` must be defined for the wire
protocol:

```rust
// src/router/protocol.rs

/// Serialisable request envelope (no responder channels).
#[derive(Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: &'static str,  // "2.0"
    pub id: String,
    pub method: String,
    pub params: serde_json::Value,
}

/// Serialisable response envelope.
#[derive(Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}
```

The **worker process** receives `RpcRequest`, converts it to a concrete `IdaRequest`
variant (creating a local `oneshot` channel for `resp`), sends it through the existing
`mpsc::SyncSender<IdaRequest>` queue, awaits the response, and writes the result back
as `RpcResponse`. This keeps `run_ida_loop` completely unmodified — only the worker's
stdin/stdout adapter layer is new.

## Source Changes

### 1. `main.rs` — new `serve-worker` subcommand

```rust
// add to Command enum
/// Internal: worker subprocess controlled by a router
ServeWorker,
```

`run_serve_worker()` reads JSON-RPC lines from stdin, dispatches to the existing
worker channel, and writes responses back to stdout. The IDA main-thread loop is
unchanged.

### 2. `src/router/mod.rs` — new module

```
src/router/
    mod.rs      RouterState, spawn_worker(), route_request()
    protocol.rs JsonRpc request/response types + codec
```

```rust
pub struct RouterState {
    workers: HashMap<DbHandle, WorkerProcess>,
    active:  Option<DbHandle>,          // handle used when caller omits db_handle
}

struct WorkerProcess {
    child:       tokio::process::Child,
    writer:      tokio::io::BufWriter<ChildStdin>,
    reader:      tokio::io::BufReader<ChildStdout>,
    pending:     HashMap<ReqId, oneshot::Sender<serde_json::Value>>,
    read_task:   JoinHandle<()>,         // spawned loop that reads worker stdout
}
```

`spawn_worker()`:
1. Spawn `ida-cli serve-worker` as a child process.
2. Generate `db_handle = nanoid(10)` (or `uuid::Uuid::new_v4().to_string()`).
3. Insert into `workers` map and set as `active`.
4. Return handle.

`route_request(handle, method, params)`:
1. Look up `WorkerProcess` by handle (fall back to `active` if handle is `None`).
2. Send JSON-RPC request to child stdin.
3. `await` response from `pending` channel.
4. Return result or forward error.

### 3. `src/ida/request.rs` — NOT modified

`IdaRequest` is an internal enum with non-serialisable `oneshot::Sender` responders.
It stays unchanged. The `db_handle` routing happens **before** the request reaches
`IdaRequest`:

1. MCP handler in `server/mod.rs` reads `db_handle` from the request struct.
2. Router uses it to pick the correct `WorkerProcess`.
3. Router serialises the remaining params as `RpcRequest` and sends to worker stdin.
4. Worker's adapter creates a local `IdaRequest` (with local `oneshot`), sends it
   through the existing `mpsc` channel, and awaits the response.

This keeps `run_ida_loop` and `IdaRequest` completely unmodified.

### 4. `src/server/requests.rs` — add optional `db_handle` to MCP schemas

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecompileRequest {
    pub address: AddressParam,
    /// Optional database handle (from open_idb). Omit to use the active database.
    pub db_handle: Option<String>,
    // ...existing fields...
}
```

Repeat for all ~60 request types. This is mechanical; a sed/ast-grep pass generates
the initial diff.

### 5. `src/server/mod.rs` — `open_idb` returns `db_handle`

```rust
// DbInfo gains a new field (serialised, backward-compatible because it is optional)
pub db_handle: Option<String>,
```

When running in router mode the field is populated; in legacy single-IDB mode it
remains `None` so existing callers are unaffected.

### 6. `src/server/mod.rs` — `ServerMode` gains `Router` variant

`ServerMode` is defined in `src/server/mod.rs` (re-exported via `src/lib.rs`):

```rust
// src/server/mod.rs, line 31
pub enum ServerMode {
    Stdio,
    Http,
    Router,   // new
}
```

Handler dispatch checks `ServerMode::Router` to proxy through `RouterState` instead
of the direct `IdaWorker` channel.

## Backward Compatibility Matrix

| Scenario | Before | After |
|---|---|---|
| Single file, no handle | `open_idb` → use db → `close_idb` | identical; active handle set automatically |
| Single file, explicit handle | n/a | `open_idb` returns handle; all tools accept it |
| Two files simultaneously | impossible | `open_idb` twice → two handles; tools route correctly |
| `close_idb` without handle | closes active IDB | closes active IDB (unchanged) |
| `close_idb` with handle | n/a | kills corresponding worker, removes from map |

All existing integration tests must pass without modification.

## Implementation Phases

### Phase 0 — Confirm idalib constraint (0.5 day)

The test infrastructure relies on `test/fixtures/` which is gitignored (only `*.c`
and `*.py` are allowed through). Fixtures must be created locally before running.

**Step 1: Create two fixture binaries**

```bash
mkdir -p test/fixtures

# Fixture A
cat > test/fixtures/mini.c << 'EOF'
int add(int a, int b) { return a + b; }
int main(void) { return add(1, 2); }
EOF
cc -O0 -g -o test/fixtures/mini test/fixtures/mini.c

# Fixture B (different functions to distinguish from A)
cat > test/fixtures/mini2.c << 'EOF'
int helper(int x) { return x * 2; }
int main(void) { return helper(21); }
EOF
cc -O0 -g -o test/fixtures/mini2 test/fixtures/mini2.c
```

**Step 2: Write probe binary**

```
tests/multi_idb_probe.rs   (standalone binary, requires IDA license)
```

The probe must use `IDBOpenOptions` (not `IDB::open_with`) for raw binaries, matching
the project's existing `open_db_for_probe()` pattern in `src/main.rs`:

```rust
// Run: cargo build --bin multi_idb_probe && ./target/debug/multi_idb_probe
use idalib::{idb::IDBOpenOptions, IDB};
use std::path::PathBuf;

fn open_raw(src: &str, out: &str) -> Result<IDB, idalib::IDAError> {
    let mut opts = IDBOpenOptions::new();
    opts.auto_analyse(true);
    opts.idb(&PathBuf::from(out)).save(false).open(src)
}

fn main() {
    idalib::init_library();

    // First open — should succeed
    let db1 = open_raw("test/fixtures/mini", "/tmp/probe_a.i64")
        .expect("first open should succeed");
    let db1_funcs = db1.function_count();
    println!("db1: {db1_funcs} functions");

    // Second open WITHOUT closing db1 — expect failure or corruption
    match open_raw("test/fixtures/mini2", "/tmp/probe_b.i64") {
        Ok(db2) => {
            let db2_funcs = db2.function_count();
            let db1_after = db1.function_count();
            println!("WARNING: second open succeeded (db2={db2_funcs} funcs)");
            println!("db1 functions after db2 open: {db1_after} (was {db1_funcs})");
            if db1_after != db1_funcs {
                println!("CORRUPTION DETECTED: db1 state changed after db2 open");
            }
        }
        Err(e) => println!("EXPECTED: second open failed: {e}"),
    }
}
```

Add to `Cargo.toml`:

```toml
[[bin]]
name = "multi_idb_probe"
path = "tests/multi_idb_probe.rs"
```

**Step 3: Record evidence**

```bash
cargo build --bin multi_idb_probe
./target/debug/multi_idb_probe 2>&1 | tee test/multi_idb_probe_output.txt
```

Attach `test/multi_idb_probe_output.txt` to the upstream PR. Expected outcomes:
- Segfault or IDA assertion → clear proof
- Second open returns error → acceptable (proves API rejects it)
- Silent state corruption (db1 sees db2's data) → most dangerous, document carefully

### Phase 1 — Worker mode (2–3 days)

- Add `Command::ServeWorker` to `main.rs`.
- Implement `run_serve_worker()`: stdin JSON-RPC → existing `mpsc` channel → stdout.
- Add `src/router/protocol.rs` (JsonRpc types, line codec).
- Unit test: spawn worker subprocess, send a `list_functions` request, assert response.

### Phase 2 — Router core (3–4 days)

- Add `src/router/mod.rs` with `RouterState` and `WorkerProcess`.
- Implement `spawn_worker()`, `route_request()`, and worker stdout reader task.
- Wire `Command::Serve` to use `RouterState` when `--multi` flag is present (opt-in
  first, default later once stable).
- Integration test: open two IDBs, decompile a function from each, verify correct
  results.

### Phase 3 — Handle parameter injection (1–2 days)

- Add `db_handle: Option<String>` to all request structs in `server/requests.rs`.
- `IdaRequest` (src/ida/request.rs) is **not modified** — `db_handle` is consumed by
  the router layer before reaching `IdaRequest`.
- Update `ServerMode::Router` dispatch in `server/mod.rs`: extract `db_handle` from
  the parsed request, route to the correct `WorkerProcess`, serialise remaining params
  as `RpcRequest`.
- In HTTP mode, return error if `db_handle` is missing and multiple IDBs are open.
- Run full test suite; fix any regressions.

### Phase 4 — Error handling & cleanup (1 day)

- Worker process crash: detect EOF on stdout, mark handle as dead, return `ToolError`
  to caller.
- Router shutdown: send `Shutdown` to all workers, wait for child processes to exit.
- `close_idb` with unknown handle: return clear error message.
- Per-handle close tokens: each `WorkerProcess` issues its own close token. Maintain
  a `token_to_handle: HashMap<String, DbHandle>` in `RouterState` for O(1) lookup.
- HTTP mode: enforce `db_handle` requirement when multiple IDBs are open.

### Phase 5 — Make router the default & upstream PR (1 day)

- Remove `--multi` flag; make router mode the default for `serve` and `serve-http`.
- Update `docs/TRANSPORTS.md` with multi-IDB usage examples.
- Submit PR to `pingzi/ida-cli`:
  - PR title: `feat: multi-IDB support via subprocess router`
  - Include Phase 0 test output as evidence for the subprocess model choice.
  - Confirm 100% backward compat via existing test suite.

## Timeline

```
Week 1  Phase 0 + Phase 1 + Phase 2
Week 2  Phase 3 + Phase 4 + Phase 5
```

Estimated total: **10–14 days**.

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| idalib prohibits two `IDB` objects even sequentially | Low | Already handled by subprocess model; sequential open is tested today |
| Worker process startup latency (~1–2 s per `open_idb`) | Medium | Acceptable for interactive use; can add pre-warm pool later |
| Upstream rejects subprocess model as too complex | Low | Provide Phase 0 evidence; propose simpler opencode.json workaround as fallback |
| `nanoid` / `uuid` dependency bump | Low | Use `format!("{:016x}", rand_u64)` to avoid new deps |

## Alternatives Considered

**Multiple MCP entries in `opencode.json`** (`ida-1`, `ida-2`, …) works today with
zero code changes and full native-tool UX. Tools are namespaced as
`mcp_ida-1_decompile`, `mcp_ida-2_decompile`. The LLM can reason about which server
holds which file. Drawback: static instance count, requires manual config per project.
Recommended as the interim workaround while this feature is developed.

**skill_mcp via opencode-lazy-loader** degrades all 60+ tools to a single
`skill_mcp(mcp_name=…, tool_name=…, arguments='…')` call with JSON-string arguments.
This is strictly worse than the multiple-MCP-entry approach and is not recommended.
