# Architecture

## Current Shape

Flat CLI, stdio MCP, HTTP MCP and background jobs share RouterState and the Nexus session coordinator. The Rust binary has no native IDA linkage. A persistent, verified Python bridge uses the fixed public Nexus client, with independent business/control lanes and a separate custody proof helper. IDA itself is owned by Nexus or an attached GUI instance.

Each client receives a lease. Requests carry immutable operation identities and total deadlines; unknown outcomes are never replayed. Close acknowledges lease detach separately from owner lifetime/save completion. Startup, recovery and owner observations retain their existing durable gates, Root Node protection and exact proof rules; see the release protocol.

Cache generations, root/content/open locks, retained failure evidence and conservative GC are shared by all transports. Legacy flat groups remain migration inputs and are never an alternate execution backend. Offline sbx/idat calls only prepare sBPF/DSC artifacts. Runtime and patch mismatches fail explicitly; version rollback invokes a separate frozen executable and a closed backup.

## What Is Still Needed For “1000 Agents”

The current code is a strong base, but “1000 agents” needs another layer above the router:

1. Request Gateway
- admission control
- auth / tenancy
- global rate limits

2. Job Queue
- durable task scheduling
- explicit terminal outcomes without write replay
- cancellation
- fair sharing across users and binaries

3. Worker Pool Manager
- warm workers
- Nexus owner capacity
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

The N1, bridge, CLI/MCP and offline-preparation contracts run against Nexus. Behavioral comparison invokes the independently supplied, hashed N0 binary. Full final E2E and version rollback are separate acceptance gates; see TESTING.md.
