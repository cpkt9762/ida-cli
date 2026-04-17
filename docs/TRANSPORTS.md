# Transports

## Stdio (default)

- Single-client, simplest setup.
- Use with CLI agents that launch a child process.

```bash
./target/release/ida-cli
```

## Streamable HTTP (multi-client)

- Supports multiple clients over HTTP.
- SSE is used for streaming responses within this transport.
- The server validates Origin headers; defaults allow localhost only.

```bash
./target/release/ida-cli serve-http --bind 127.0.0.1:8765
```

Options:
- `--stateless`: POST-only mode (no sessions)
- `--allow-origin`: comma-separated allowlist
- `--sse-keep-alive-secs`: keep-alive interval (0 disables)

## Concurrency model

IDA requires main-thread access. All IDA operations are serialized through a single
worker loop, while multiple clients can submit requests concurrently.

## Multi-IDB Support

The server supports opening and querying multiple IDA databases simultaneously.
Each database runs in an isolated worker subprocess.

### Opening multiple databases

```
open_idb(path: "~/samples/binary1")
# Returns: { "db_handle": "abc123...", ... }

open_idb(path: "~/samples/binary2")
# Returns: { "db_handle": "def456...", ... }
```

### Querying a specific database

Use the `db_handle` returned by `open_idb` to route requests:

```
list_functions(db_handle: "abc123...")
decompile(address: "0x1000", db_handle: "def456...")
```

If `db_handle` is omitted, the most recently opened database is used (active handle).
When multiple databases are open, `db_handle` is required to avoid ambiguity.

### Closing a database

```
close_idb(token: "<close_token from open_idb>")
```

Each `open_idb` response includes a `close_token` for secure closure.

### Notes

- `open_dsc` (dyld_shared_cache) is not supported in multi-IDB mode
- Worker processes are automatically cleaned up on server shutdown
- Opening the same file twice returns the existing handle

## Shutdown

The server listens for SIGINT/SIGTERM/SIGQUIT and will close the open database
before exiting when possible.
