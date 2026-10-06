# Architecture

## Current Shape

`ida-cli` now has a runtime-adaptive middle layer instead of a single hard-coded IDA backend.

### Layers

1. Frontends
- Flat CLI
- MCP over stdio
- MCP over Streamable HTTP

2. Router
- Spawns per-database workers
- Routes JSON-RPC requests
- Keeps active handle / per-path handle mapping
- Reuses workers when a path is already open

3. Runtime Probe
- Detects the active IDA runtime
- Selects a worker backend before worker startup
- Prevents known crash paths from being entered blindly

4. Worker Backends
- `native-linked`
- `idat-compat`

5. Storage and caches
- Database cache: `~/.ida/idb/`
- Response cache: `/tmp/ida-cli-out/`
- Socket discovery: `/tmp/ida-cli.socket`

## Why This Matters

This split is the foundation for long-running RE server workloads:

- old runtimes and new runtimes no longer share one unsafe code path
- the router can evolve independently from backend implementation details
- IDA database caching is no longer tied to the source binary directory
- backend support can be declared and tested explicitly

## Current Backends

### `native-linked`

Used for IDA 9.3 and 9.5 when the runtime matches the SDK version the binary was built against, so the vendored `idalib` line can safely open databases in-process.

### `idat-compat`

Used for IDA 9.0–9.2, IDA 9.4, and runtimes that differ from the build SDK, where the vendored `idalib` line would crash or lose the decompiler.

This backend:

- shells out to `idat`
- runs short IDAPython snippets
- emits structured JSON back to the router
- reuses cached database artifacts in `~/.ida/idb/`

## Concurrency Model Today

Today the router model is:

- one server process
- many worker subprocesses
- one worker per open database handle

This already supports:

- multiple databases in parallel
- backend-specific worker behavior
- independent worker crashes without taking down the whole server

## What Is Still Needed For “1000 Agents”

The current code is a strong base, but “1000 agents” needs another layer above the router:

1. Request Gateway
- admission control
- auth / tenancy
- global rate limits

2. Job Queue
- durable task scheduling
- retries
- cancellation
- fair sharing across users and binaries

3. Worker Pool Manager
- warm workers
- backend-specific pools
- CPU / memory caps
- queue depth limits

4. Cache Coordinator
- content-addressed database cache
- database lease / pinning
- result cache for expensive reads and decompilation

5. Observability
- structured metrics per backend
- worker crash accounting
- slow-query tracing

## Practical Upgrade Path

The recommended path from the current codebase is:

1. Keep the current router as the local orchestration core.
2. Move worker launch behind a queue / scheduler boundary.
3. Make database cache ownership explicit and lease-based.
4. Add capability-aware routing so unsupported methods never hit the wrong backend.
5. Add backend smoke tests to CI for every supported runtime/backend pair.

## Federation Skeleton

The codebase now includes a minimal federation status layer.

Set:

`IDA_CLI_FEDERATION_CONFIG=/path/to/nodes.json`

Example:

```json
[
  {
    "name": "node-a",
    "url": "http://127.0.0.1:9876",
    "weight": 1,
    "enabled": true
  },
  {
    "name": "node-b",
    "url": "http://127.0.0.1:9976",
    "weight": 2,
    "enabled": true
  }
]
```

Current behavior:

- loads static node config
- probes `/healthz` and `/readyz`
- exposes federation node state through router status

This is a federation status and discovery skeleton, not yet a full remote execution fabric.

## Validation

The repository now includes a 9.x compatibility verification script:

`scripts/verify_9x_compat.py`

It probes the selected backend and runs a worker-level compatibility pass for the currently declared `idat-compat` supported method set.
