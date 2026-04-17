#!/usr/bin/env bash
# Reference-count integration test in router mode:
# open same IDB twice, close with two tokens, verify ref release then final close.
set -euo pipefail

SERVER_BIN="${SERVER_BIN:-../target/release/ida-cli}"
RUST_LOG="${RUST_LOG:-ida_mcp=warn}"

if [ ! -x "$SERVER_BIN" ]; then
    echo "❌ Server binary not found: $SERVER_BIN" >&2
    exit 1
fi

if [ ! -f "fixtures/mini.i64" ]; then
    echo "❌ Missing fixture: fixtures/mini.i64" >&2
    exit 1
fi

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
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "❌ Timeout waiting for response id=$target_id" >&2
    cat "$log" >&2
    return 1
}

extract_field() {
    local json="$1"
    local field="$2"
    echo "$json" | grep -o "\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed 's/.*"[^"]*"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}

extract_escaped_field() {
    local json="$1"
    local field="$2"
    echo "$json" | sed -nE "s/.*\\\\\"${field}\\\\\"[[:space:]]*:[[:space:]]*\\\\\"([^\\\\\"]+)\\\\\".*/\1/p" | head -1
}

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"ref-count-test","version":"0.1"},"capabilities":{}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
wait_response 1 10 >/dev/null
echo "   ✓ Initialized"

send '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_idb","arguments":{"path":"fixtures/mini.i64"}}}'
resp_open1=$(wait_response 2 15)

send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"open_idb","arguments":{"path":"fixtures/mini.i64"}}}'
resp_open2=$(wait_response 3 15)

handle1=$(echo "$resp_open1" | grep -o 'db_handle[^,}]*' | grep -oE '[0-9a-f]{16}' | head -1 || true)
handle2=$(echo "$resp_open2" | grep -o 'db_handle[^,}]*' | grep -oE '[0-9a-f]{16}' | head -1 || true)

token1=$(extract_escaped_field "$resp_open1" "close_token")
token2=$(extract_escaped_field "$resp_open2" "close_token")

if [ -z "$token1" ]; then
    token1=$(extract_field "$resp_open1" "close_token")
fi
if [ -z "$token2" ]; then
    token2=$(extract_field "$resp_open2" "close_token")
fi

if [ -z "$handle1" ] || [ -z "$handle2" ]; then
    echo "❌ Failed to extract db_handle from open_idb responses" >&2
    echo "$resp_open1" >&2
    echo "$resp_open2" >&2
    exit 1
fi

if [ -z "$token1" ] || [ -z "$token2" ]; then
    echo "❌ Failed to extract close_token from open_idb responses" >&2
    echo "$resp_open1" >&2
    echo "$resp_open2" >&2
    exit 1
fi

if [ "$handle1" != "$handle2" ]; then
    echo "❌ Expected same db_handle for repeated open, got $handle1 and $handle2" >&2
    exit 1
fi

if [ "$token1" = "$token2" ]; then
    echo "❌ Expected different close_token values for repeated open" >&2
    exit 1
fi

echo "   ✓ Opened same IDB twice → shared handle=$handle1"
echo "   ✓ close_token values are distinct"

send "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"close_idb\",\"arguments\":{\"token\":\"${token1}\"}}}"
resp_close1=$(wait_response 9 10)
if ! echo "$resp_close1" | grep -q 'Reference released'; then
    echo "❌ close_idb(token1) must include 'Reference released'" >&2
    echo "$resp_close1" >&2
    exit 1
fi
echo "   ✓ close_idb(token1) returned 'Reference released'"

send "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"close_idb\",\"arguments\":{\"token\":\"${token2}\"}}}"
resp_close2=$(wait_response 10 10)
if ! echo "$resp_close2" | grep -q 'Database closed'; then
    echo "❌ close_idb(token2) must include 'Database closed'" >&2
    echo "$resp_close2" >&2
    exit 1
fi
echo "   ✓ close_idb(token2) returned 'Database closed'"

echo "✅ Ref-count test passed"
