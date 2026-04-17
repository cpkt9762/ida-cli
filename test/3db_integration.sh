#!/usr/bin/env bash
# 3DB concurrent router test: open/query/close three Solana IDBs via db routing.
set -euo pipefail

SERVER_BIN="${SERVER_BIN:-../target/release/ida-cli}"
RUST_LOG="${RUST_LOG:-ida_mcp=warn}"

PUMPFUN_IDB="${PUMPFUN_IDB:?PUMPFUN_IDB is required}"
RAYDIUM_IDB="${RAYDIUM_IDB:?RAYDIUM_IDB is required}"
JUPITER_IDB="${JUPITER_IDB:?JUPITER_IDB is required}"

if [ ! -x "$SERVER_BIN" ]; then
    echo "❌ Server binary not found: $SERVER_BIN" >&2
    exit 1
fi

for f in "$PUMPFUN_IDB" "$RAYDIUM_IDB" "$JUPITER_IDB"; do
    if [ ! -f "$f" ]; then
        echo "❌ Missing fixture: $f" >&2
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

extract_handle() {
    local resp="$1"
    echo "$resp" | grep -o 'db_handle[^,}]*' | grep -oE '[0-9a-f]{16}' | head -1 || true
}

extract_token() {
    local resp="$1"
    echo "$resp" | grep -o 'close_token[^,}]*' | grep -oE '[0-9a-f\-]{10,}' | head -1 || true
}

extract_function_count() {
    local resp="$1"
    # Count \"address\" occurrences in escaped JSON (one per function object)
    echo "$resp" | grep -o '\\"address\\"' | wc -l | tr -d ' ' || echo 0
}

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"3db-test","version":"0.1"},"capabilities":{}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
wait_response 1 10 >/dev/null
echo "   ✓ Initialized"

send "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"${PUMPFUN_IDB}\",\"timeout_secs\":60,\"force\":true}}}"
send "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"${RAYDIUM_IDB}\",\"timeout_secs\":60,\"force\":true}}}"
send "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"${JUPITER_IDB}\",\"timeout_secs\":60,\"force\":true}}}"

resp_a=$(wait_response 2 300)
resp_b=$(wait_response 3 300)
resp_c=$(wait_response 4 300)

handle_a=$(extract_handle "$resp_a")
handle_b=$(extract_handle "$resp_b")
handle_c=$(extract_handle "$resp_c")
token_a=$(extract_token "$resp_a")
token_b=$(extract_token "$resp_b")
token_c=$(extract_token "$resp_c")

if [ -z "$handle_a" ] || [ -z "$handle_b" ] || [ -z "$handle_c" ]; then
    echo "❌ Failed to extract all db_handle values" >&2
    echo "$resp_a" >&2
    echo "$resp_b" >&2
    echo "$resp_c" >&2
    exit 1
fi


if [ "$handle_a" = "$handle_b" ] || [ "$handle_a" = "$handle_c" ] || [ "$handle_b" = "$handle_c" ]; then
    echo "❌ db_handle values are not unique: $handle_a $handle_b $handle_c" >&2
    exit 1
fi
echo "   ✓ Distinct handles: $handle_a $handle_b $handle_c"

send "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"list_functions\",\"arguments\":{\"db_handle\":\"${handle_a}\",\"limit\":10}}}"
send "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"list_functions\",\"arguments\":{\"db_handle\":\"${handle_b}\",\"limit\":10}}}"
send "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"list_functions\",\"arguments\":{\"db_handle\":\"${handle_c}\",\"limit\":10}}}"

resp5=$(wait_response 5 15)
resp6=$(wait_response 6 15)
resp7=$(wait_response 7 15)

count_a=$(extract_function_count "$resp5")
count_b=$(extract_function_count "$resp6")
count_c=$(extract_function_count "$resp7")
if [ -z "$count_a" ] || [ -z "$count_b" ] || [ -z "$count_c" ]; then
    echo "❌ Failed to parse function_count from list_functions" >&2
    echo "$resp5" >&2
    echo "$resp6" >&2
    echo "$resp7" >&2
    exit 1
fi
if [ "$count_a" -le 0 ] || [ "$count_b" -le 0 ] || [ "$count_c" -le 0 ]; then
    echo "❌ function_count must be > 0: $count_a $count_b $count_c" >&2
    exit 1
fi
echo "   ✓ list_functions OK: $count_a / $count_b / $count_c"

send "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"strings\",\"arguments\":{\"db_handle\":\"${handle_a}\",\"limit\":5}}}"
send "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"strings\",\"arguments\":{\"db_handle\":\"${handle_b}\",\"limit\":5}}}"
send "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"strings\",\"arguments\":{\"db_handle\":\"${handle_c}\",\"limit\":5}}}"

resp8=$(wait_response 8 15)
resp9=$(wait_response 9 15)
resp10=$(wait_response 10 15)

if echo "$resp8" | grep -q '"isError"[[:space:]]*:[[:space:]]*true'; then
    echo "❌ strings(handle_a) returned error" >&2
    echo "$resp8" >&2
    exit 1
fi
if echo "$resp9" | grep -q '"isError"[[:space:]]*:[[:space:]]*true'; then
    echo "❌ strings(handle_b) returned error" >&2
    echo "$resp9" >&2
    exit 1
fi
if echo "$resp10" | grep -q '"isError"[[:space:]]*:[[:space:]]*true'; then
    echo "❌ strings(handle_c) returned error" >&2
    echo "$resp10" >&2
    exit 1
fi
echo "   ✓ strings(limit=5) OK on all handles"

send "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"close_idb\",\"arguments\":{\"db_handle\":\"${handle_a}\"}}}"
send "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\",\"params\":{\"name\":\"close_idb\",\"arguments\":{\"db_handle\":\"${handle_b}\"}}}"
send "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"tools/call\",\"params\":{\"name\":\"close_idb\",\"arguments\":{\"db_handle\":\"${handle_c}\"}}}"

resp11=$(wait_response 11 10)
resp12=$(wait_response 12 10)
resp13=$(wait_response 13 10)

if ! echo "$resp11" | grep -q 'Database closed\|closed'; then
    echo "❌ close_idb(handle_a) did not return Database closed" >&2
    echo "$resp11" >&2
    exit 1
fi
if ! echo "$resp12" | grep -q 'Database closed\|closed'; then
    echo "❌ close_idb(handle_b) did not return Database closed" >&2
    echo "$resp12" >&2
    exit 1
fi
if ! echo "$resp13" | grep -q 'Database closed\|closed'; then
    echo "❌ close_idb(handle_c) did not return Database closed" >&2
    echo "$resp13" >&2
    exit 1
fi

echo "✅ 3-DB concurrent test passed"
