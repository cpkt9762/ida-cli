#!/usr/bin/env bash
# Integration test for the decompile_structured MCP tool.
# Probes idb_meta for hexrays_available; skips gracefully if not present.
set -euo pipefail

SERVER_BIN="${SERVER_BIN:-../target/release/ida-cli}"
RUST_LOG="${RUST_LOG:-ida_mcp=warn}"

if [ ! -x "$SERVER_BIN" ]; then
    echo "❌ Server binary not found: $SERVER_BIN" >&2
    exit 1
fi

# Prefer .i64 (fast open); fall back to raw binary
IDB="${IDB:-fixtures/mini.i64}"
if [ ! -f "$IDB" ]; then
    IDB="fixtures/mini"
fi
if [ ! -f "$IDB" ]; then
    echo "❌ Fixture not found: $IDB (run 'just fixture' or 'just fixture-idb')" >&2
    exit 1
fi

fifo_in="$(mktemp -u).fifo"
mkfifo "$fifo_in"
log="$(mktemp)"

RUST_LOG="$RUST_LOG" "$SERVER_BIN" < "$fifo_in" > "$log" 2>&1 &
server_pid=$!
exec 3>"$fifo_in"

cleanup() {
    exec 3>&- 2>/dev/null || true
    rm -f "$fifo_in" "$log"
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT

send() { echo "$1" >&3; }

wait_response() {
    local target_id="$1"
    local timeout="${2:-30}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        local line
        line=$(grep -m1 "\"id\":${target_id}[,}]" "$log" 2>/dev/null | grep '"jsonrpc"' || true)
        if [ -n "$line" ]; then
            echo "$line"
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + 1))
    done
    echo "❌ Timeout waiting for response id=$target_id" >&2
    cat "$log" >&2
    return 1
}

# Phase 1: Initialize
send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"decompile-structured-test","version":"0.1"},"capabilities":{}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
wait_response 1 10 >/dev/null
echo "   ✓ Initialized"

# Phase 2: Open IDB
send "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"${IDB}\"}}}"
wait_response 2 30 >/dev/null
echo "   ✓ Opened $IDB"

# Phase 3: idb_meta — probe hexrays_available
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"idb_meta","arguments":{}}}'
meta_resp=$(wait_response 3 10)

if echo "$meta_resp" | grep -q 'hexrays_available.*true'; then
    hexrays_available=true
else
    hexrays_available=false
fi

if [ "$hexrays_available" = "false" ]; then
    echo "⏭  Hex-Rays decompiler not available — skipping decompile_structured test"
    exit 0
fi

echo "   ✓ Hex-Rays available"

# Phase 4: decompile_structured on the 'add' function
send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"decompile_structured","arguments":{"address":"add"}}}'
resp4=$(wait_response 4 30)

if echo "$resp4" | grep -q '"isError".*true\|isError.*true'; then
    echo "❌ decompile_structured(add) returned error" >&2
    echo "$resp4" >&2
    exit 1
fi

# Validate response contains expected structured output keys
if ! echo "$resp4" | grep -q '"function"'; then
    echo "❌ decompile_structured response missing 'function' key" >&2
    echo "$resp4" >&2
    exit 1
fi

if ! echo "$resp4" | grep -q '"body"'; then
    echo "❌ decompile_structured response missing 'body' key" >&2
    echo "$resp4" >&2
    exit 1
fi

if ! echo "$resp4" | grep -q '"op"'; then
    echo "❌ decompile_structured response missing 'op' key" >&2
    echo "$resp4" >&2
    exit 1
fi

echo "   ✓ decompile_structured(add) succeeded with expected keys"

# Phase 5: close
send '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 5 10 >/dev/null
echo "   ✓ close_idb"

echo "✅ decompile_structured integration test passed"
