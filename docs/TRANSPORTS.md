# Transports

`ida-cli` can be driven in three ways against the same underlying router /
worker backend.

## 1. Flat CLI (default)

```bash
ida-cli --path <file> list-functions --limit 20
ida-cli --path <file> decompile --addr 0x1000
ida-cli --path <file> raw '{"method":"get_xrefs_to","params":{"address":"0x1000"}}'
```

The flat CLI is a JSON-RPC client. It auto-starts a background HTTP server
bound to a random port when none is live and publishes the real socket path
at `/tmp/ida-cli.socket`.

See [`skill/references/cli-tool-reference.md`](../skill/references/cli-tool-reference.md)
for the complete command surface.

## 2. Stdio MCP (single client)

Use this when an agent or tool launches `ida-cli` as a subprocess and speaks
MCP over stdin/stdout.

```bash
./target/release/ida-cli serve
```

## 3. Streamable HTTP MCP (multi client)

Use this when clients connect over HTTP (SSE framing by default).

```bash
./target/release/ida-cli serve-http --bind 127.0.0.1:8765
```

Options (from `serve-http --help`):

- `--sse-keep-alive-secs N` — SSE keep-alive interval; `0` disables
- `--stateless` — POST-only mode (no sessions)
- `--json-response` — with `--stateless`, return `application/json` instead
  of SSE framing
- `--allow-origin a,b,c` — comma-separated Origin allowlist (defaults to
  `http://localhost,http://127.0.0.1`)
- `--max-inflight-requests N` — reject new HTTP requests with 503 past this
  count (default 256)

## Concurrency Model

IDA requires main-thread access. Every database handle runs inside its own
worker subprocess, and the router serialises requests to each handle while
fanning out across handles.

This gives you:

- multiple databases open concurrently
- one worker crashing does not take down the whole server
- backend-specific worker behaviour (`idat-compat` vs `native-linked`)

## Multi-IDB

`open_idb` opens either an `.i64` / `.idb` or a raw binary. Raw binaries are
auto-analysed and cached as `.i64` alongside the input. Each call returns a
`db_handle` and a `close_token`.

Opening multiple databases:

```
open_idb(path: "~/samples/binary1")
# Returns: { "db_handle": "abc123...", ... }

open_idb(path: "~/samples/binary2")
# Returns: { "db_handle": "def456...", ... }
```

Routing requests:

```
list_functions(db_handle: "abc123...")
decompile_function(address: "0x1000", db_handle: "def456...")
```

If `db_handle` is omitted, the most recently opened database is used. When
more than one database is open concurrently, `db_handle` is required to
avoid ambiguity.

Closing:

```
close_idb(token: "<close_token from open_idb>")
```

Each `open_idb` response includes a `close_token` for secure closure.

Notes:

- `open_dsc` (dyld_shared_cache) is not supported in multi-IDB mode.
- Worker processes are cleaned up on server shutdown.
- Opening the same file twice returns the existing handle.

## Admin Endpoints (HTTP only)

`serve-http` exposes plain JSON endpoints next to the MCP surface:

- `GET /healthz` — liveness
- `GET /readyz` — readiness (runtime probe + worker count)
- `GET /statusz` — full router status (federated view)
- `GET /federationz` — federation node statuses
- `GET /metrics` — Prometheus text format
- `GET /tasksz`, `GET /taskz/<task_id>` — background task state
- `POST /enqueuez` — enqueue a routed task
- `POST /federationz/register`, `/heartbeat`, `/unregister` — federation
  plane maintenance

## Shutdown

The server listens for `SIGINT` / `SIGTERM` / `SIGQUIT` and closes every
open database before exiting when possible. From the client side:

```bash
ida-cli shutdown
```
