#!/usr/bin/env bash
# Dynamic multi-IDB integration test for ida-cli router mode.
# Tests that two IDB files can be opened simultaneously with isolated routing.
# db_handle values are runtime hex strings — extracted dynamically from responses.
set -euo pipefail

SERVER_BIN="${SERVER_BIN:-../target/release/ida-cli}"
RUST_LOG="${RUST_LOG:-ida_mcp=warn}"

if [ ! -x "$SERVER_BIN" ]; then
    echo "❌ Server binary not found: $SERVER_BIN" >&2
    exit 1
fi

# Require pre-generated .i64 fixtures for fast opens (no analysis wait)
for f in fixtures/mini.i64 fixtures/mini2.i64; do
    if [ ! -f "$f" ]; then
        echo "❌ Missing fixture: $f — run 'just fixture-idb' first" >&2
        exit 1
    fi
done

fifo_in="$(mktemp -u).fifo"
mkfifo "$fifo_in"
log="$(mktemp)"

RUST_LOG="$RUST_LOG" "$SERVER_BIN" serve < "$fifo_in" > "$log" 2>&1 &
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

# Wait for a JSON-RPC response with the given id (reads from log file)
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

# Extract a JSON field value from a response line
# Usage: extract_field <json_line> <field_name>
extract_field() {
    local json="$1"
    local field="$2"
    # Extract escaped JSON text content, then parse the field
    echo "$json" | grep -o "\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed 's/.*"[^"]*"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}

# Phase 1: Initialize
send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"multi-test","version":"0.1"},"capabilities":{}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
wait_response 1 10 >/dev/null
echo "   ✓ Initialized"

# Phase 2: Open mini.i64 → extract handle_A
send '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_idb","arguments":{"path":"fixtures/mini.i64"}}}'
resp_a=$(wait_response 2 15)
# db_handle appears in the escaped JSON text as \"db_handle\":\"<hex>\"
handle_a=$(echo "$resp_a" | grep -o 'db_handle[^,}]*' | grep -oE '[0-9a-f]{16}' | head -1 || true)
if [ -z "$handle_a" ]; then
    echo "❌ Failed to extract db_handle from open_idb(mini.i64)" >&2
    echo "$resp_a" >&2
    exit 1
fi
echo "   ✓ Opened mini.i64 → handle_A=$handle_a"

# Phase 3: Open mini2.i64 → extract handle_B
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"open_idb","arguments":{"path":"fixtures/mini2.i64"}}}'
resp_b=$(wait_response 3 15)
handle_b=$(echo "$resp_b" | grep -o 'db_handle[^,}]*' | grep -oE '[0-9a-f]{16}' | head -1 || true)
if [ -z "$handle_b" ]; then
    echo "❌ Failed to extract db_handle from open_idb(mini2.i64)" >&2
    echo "$resp_b" >&2
    exit 1
fi
echo "   ✓ Opened mini2.i64 → handle_B=$handle_b"

# Verify handles are different
if [ "$handle_a" = "$handle_b" ]; then
    echo "❌ Both IDBs got the same db_handle: $handle_a" >&2
    exit 1
fi
echo "   ✓ Handles are distinct"

# Phase 4: list_functions on handle_A → must contain "add"
send "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"list_functions\",\"arguments\":{\"db_handle\":\"${handle_a}\",\"limit\":20}}}"
resp4=$(wait_response 4 10)
if ! echo "$resp4" | grep -q '"add"'; then
    echo "❌ list_functions(handle_A) missing 'add'" >&2
    echo "$resp4" >&2
    exit 1
fi
echo "   ✓ list_functions(handle_A) contains 'add'"

# Phase 5: list_functions on handle_B → must contain "helper"
send "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"list_functions\",\"arguments\":{\"db_handle\":\"${handle_b}\",\"limit\":20}}}"
resp5=$(wait_response 5 10)
if ! echo "$resp5" | grep -q '"helper"'; then
    echo "❌ list_functions(handle_B) missing 'helper'" >&2
    echo "$resp5" >&2
    exit 1
fi
echo "   ✓ list_functions(handle_B) contains 'helper'"

# Phase 6: Routing isolation — resolve_function "helper" on handle_A must fail
send "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"resolve_function\",\"arguments\":{\"db_handle\":\"${handle_a}\",\"name\":\"helper\"}}}"
resp6=$(wait_response 6 10)
if ! echo "$resp6" | grep -q '"isError"'; then
    echo "❌ resolve_function('helper') on handle_A should have failed (isolation)" >&2
    echo "$resp6" >&2
    exit 1
fi
echo "   ✓ resolve_function('helper') on handle_A correctly fails (isolation)"

# Phase 7: Routing isolation — resolve_function "add" on handle_B must fail
send "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"resolve_function\",\"arguments\":{\"db_handle\":\"${handle_b}\",\"name\":\"add\"}}}"
resp7=$(wait_response 7 10)
if ! echo "$resp7" | grep -q '"isError"'; then
    echo "❌ resolve_function('add') on handle_B should have failed (isolation)" >&2
    echo "$resp7" >&2
    exit 1
fi
echo "   ✓ resolve_function('add') on handle_B correctly fails (isolation)"

# Phase 8: Invalid handle → must return error
send '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"list_functions","arguments":{"db_handle":"deadbeefdeadbeef","limit":5}}}'
resp8=$(wait_response 8 10)
if ! echo "$resp8" | grep -q '"isError"'; then
    echo "❌ Invalid db_handle should return isError" >&2
    echo "$resp8" >&2
    exit 1
fi
echo "   ✓ Invalid db_handle correctly returns error"

# Phase 9: Close handle_A
send "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"close_idb\",\"arguments\":{\"db_handle\":\"${handle_a}\"}}}"
resp9=$(wait_response 9 10)
if ! echo "$resp9" | grep -q 'Database closed\|closed'; then
    echo "❌ close_idb(handle_A) did not confirm closure" >&2
    echo "$resp9" >&2
    exit 1
fi
echo "   ✓ close_idb(handle_A) succeeded"

# Phase 10: Close handle_B
send "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"close_idb\",\"arguments\":{\"db_handle\":\"${handle_b}\"}}}"
resp10=$(wait_response 10 10)
if ! echo "$resp10" | grep -q 'Database closed\|closed'; then
    echo "❌ close_idb(handle_B) did not confirm closure" >&2
    echo "$resp10" >&2
    exit 1
fi
echo "   ✓ close_idb(handle_B) succeeded"

echo "✅ Multi-IDB integration test passed"
