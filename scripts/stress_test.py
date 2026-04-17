#!/usr/bin/env python3
"""
ida-cli HTTP stress test — loops common MCP tools to find bugs.

Usage:
  1. Start the server:
     ./target/release/ida-cli serve-http --bind 127.0.0.1:8765
  2. Run this script:
     python3 scripts/stress_test.py [OPTIONS]

Options:
  --url URL             Server URL (default: http://127.0.0.1:8765)
  --idb PATH            IDB path to open (default: test/fixtures/mini2.i64)
  --iterations N        Sequential iterations per tool (default: 100)
  --concurrency N       Concurrent requests per batch (default: 13)
  --batch-rounds N      Concurrent batch rounds (default: 50)
  --timeout SECS        Per-request timeout (default: 60)
  --skip-concurrent     Skip concurrent stress phase
  --skip-sequential     Skip sequential stress phase
"""

import argparse
import json
import logging
import os
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ─── Logging ────────────────────────────────────────────────────────────────

LOG_FMT = "%(asctime)s │ %(levelname)-5s │ %(message)s"
DATE_FMT = "%H:%M:%S"
logging.basicConfig(
    level=logging.INFO, format=LOG_FMT, datefmt=DATE_FMT, stream=sys.stderr
)
log = logging.getLogger("stress")

# ─── Known addresses in mini2.i64 (ARM64 Mach-O) ───────────────────────────

HELPER_ADDR = "0x100000328"
MAIN_ADDR = "0x100000340"

# ─── Stats tracker ──────────────────────────────────────────────────────────


@dataclass
class ToolStats:
    name: str
    ok: int = 0
    fail: int = 0
    errors: list = field(default_factory=list)
    latencies: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.ok + self.fail

    @property
    def avg_ms(self) -> float:
        return (
            (sum(self.latencies) / len(self.latencies) * 1000)
            if self.latencies
            else 0.0
        )

    @property
    def max_ms(self) -> float:
        return max(self.latencies) * 1000 if self.latencies else 0.0

    @property
    def min_ms(self) -> float:
        return min(self.latencies) * 1000 if self.latencies else 0.0

    @property
    def p99_ms(self) -> float:
        if not self.latencies:
            return 0.0
        s = sorted(self.latencies)
        idx = int(len(s) * 0.99)
        return s[min(idx, len(s) - 1)] * 1000


# ─── SSE response parser ───────────────────────────────────────────────────


def parse_sse_response(text: str) -> Optional[dict]:
    """Extract the last JSON-RPC object from an SSE stream."""
    result = None
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("data: "):
            data = line[6:]
            try:
                result = json.loads(data)
            except json.JSONDecodeError:
                continue
    return result


# ─── HTTP MCP client ────────────────────────────────────────────────────────


class McpClient:
    """Minimal MCP client over Streamable HTTP (SSE)."""

    def __init__(
        self, base_url: str, origin: str = "http://localhost", timeout: int = 60
    ):
        self.base_url = base_url.rstrip("/")
        self.origin = origin
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self._req_id = 0

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _post(self, payload: dict) -> dict:
        """POST a JSON-RPC request and parse SSE response."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Origin": self.origin,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        body = json.dumps(payload).encode("utf-8")
        req = Request(self.base_url + "/", data=body, headers=headers, method="POST")

        resp = urlopen(req, timeout=self.timeout)
        # Capture session ID from headers
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid.strip()

        content_type = resp.headers.get("Content-Type", "")

        if "text/event-stream" in content_type:
            # Read SSE line-by-line; return as soon as we get a JSON-RPC result.
            # Do NOT call resp.read() — it blocks forever (server keeps SSE open).
            result = None
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if line.startswith("data: "):
                    data = line[6:]
                    try:
                        obj = json.loads(data)
                        # JSON-RPC result has "id" field; keep-alive pings don't
                        if "id" in obj or "result" in obj or "error" in obj:
                            result = obj
                            break
                    except json.JSONDecodeError:
                        continue
            if result is None:
                raise RuntimeError("SSE stream ended without a JSON-RPC result")
            return result
        else:
            raw = resp.read().decode("utf-8")
            return json.loads(raw)

    def _notify(self, method: str, params: Optional[dict] = None):
        """Send a JSON-RPC notification (no id, no response expected)."""
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Origin": self.origin,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        body = json.dumps(payload).encode("utf-8")
        req = Request(self.base_url + "/", data=body, headers=headers, method="POST")
        try:
            resp = urlopen(req, timeout=self.timeout)
            resp.read()
        except Exception:
            pass  # notifications may return 202 or empty

    def initialize(self):
        """MCP handshake: initialize + notifications/initialized."""
        resp = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "clientInfo": {"name": "stress-test", "version": "1.0"},
                    "capabilities": {},
                },
            }
        )
        if "error" in resp and resp["error"]:
            raise RuntimeError(f"initialize failed: {resp['error']}")
        self._notify("notifications/initialized")
        log.info("MCP session initialized (session_id=%s)", self.session_id)
        return resp

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        """Call an MCP tool and return the result."""
        resp = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        return resp

    def call_tool_result(self, name: str, arguments: Optional[dict] = None) -> Any:
        """Call tool, raise on error, return result content."""
        resp = self.call_tool(name, arguments)
        if "error" in resp and resp["error"]:
            raise RuntimeError(
                f"Tool {name} error: {resp['error'].get('message', resp['error'])}"
            )
        result = resp.get("result", {})
        # MCP wraps in {"content": [...]}
        return result


# ─── Tool test definitions ──────────────────────────────────────────────────


def define_test_cases() -> list[tuple[str, dict]]:
    """Return (tool_name, arguments) pairs for stress testing."""
    return [
        # ── Metadata (no params) ──
        ("idb_meta", {}),
        ("analysis_status", {}),
        ("segments", {}),
        ("entrypoints", {}),
        # ── Function listing & resolution ──
        ("list_functions", {"limit": 10}),
        ("list_functions", {"limit": 50, "filter": "main"}),
        ("resolve_function", {"name": "helper"}),
        ("resolve_function", {"name": "main"}),
        ("addr_info", {"address": HELPER_ADDR}),
        ("function_at", {"address": HELPER_ADDR}),
        ("function_at", {"address": MAIN_ADDR}),
        # ── Disassembly ──
        ("disasm", {"address": HELPER_ADDR, "count": 5}),
        ("disasm", {"address": MAIN_ADDR, "count": 10}),
        ("disasm_by_name", {"name": "helper", "count": 10}),
        ("disasm_by_name", {"name": "main", "count": 20}),
        ("disasm_function_at", {"target_name": "helper"}),
        ("disasm_function_at", {"target_name": "main"}),
        # ── Decompilation ──
        ("decompile", {"address": HELPER_ADDR}),
        ("decompile", {"address": MAIN_ADDR}),
        # ── Cross-references ──
        ("xrefs_to", {"address": HELPER_ADDR}),
        ("xrefs_from", {"address": MAIN_ADDR}),
        ("callers", {"address": HELPER_ADDR}),
        ("callees", {"address": MAIN_ADDR}),
        # ── Control flow ──
        ("basic_blocks", {"address": HELPER_ADDR}),
        ("basic_blocks", {"address": MAIN_ADDR}),
        # ── Strings & search ──
        ("strings", {"limit": 10}),
        ("find_string", {"query": "hello", "limit": 5}),
        # ── Memory ──
        ("get_bytes", {"address": HELPER_ADDR, "size": 16}),
        ("get_bytes", {"address": MAIN_ADDR, "size": 32}),
        # ── Imports/exports ──
        ("imports", {"limit": 10}),
        ("exports", {"limit": 10}),
        # ── Types & structs ──
        ("local_types", {"limit": 5}),
        ("structs", {"limit": 5}),
        ("list_globals", {"limit": 5}),
    ]


# ─── Sequential stress test ────────────────────────────────────────────────


def run_sequential(client: McpClient, iterations: int) -> dict[str, ToolStats]:
    """Run each tool N times sequentially. Returns stats per tool."""
    cases = define_test_cases()
    total_calls = len(cases) * iterations
    stats: dict[str, ToolStats] = {}

    log.info(
        "═══ Sequential phase: %d tools × %d iterations = %d calls ═══",
        len(cases),
        iterations,
        total_calls,
    )

    call_num = 0
    for tool_name, args in cases:
        key = f"{tool_name}({_args_short(args)})"
        st = ToolStats(name=key)
        stats[key] = st

        for i in range(iterations):
            call_num += 1
            t0 = time.monotonic()
            try:
                result = client.call_tool_result(tool_name, args)
                elapsed = time.monotonic() - t0
                st.latencies.append(elapsed)
                st.ok += 1
            except Exception as e:
                elapsed = time.monotonic() - t0
                st.latencies.append(elapsed)
                st.fail += 1
                err_msg = f"iter={i}: {e}"
                st.errors.append(err_msg)
                log.warning("FAIL [%d/%d] %s #%d: %s", call_num, total_calls, key, i, e)

            # Progress every 10% per tool
            if (i + 1) % max(1, iterations // 10) == 0:
                log.info(
                    "  [%d/%d] %s: %d/%d done (ok=%d fail=%d avg=%.0fms)",
                    call_num,
                    total_calls,
                    tool_name,
                    i + 1,
                    iterations,
                    st.ok,
                    st.fail,
                    st.avg_ms,
                )

    return stats


# ─── Concurrent stress test ─────────────────────────────────────────────────


def run_concurrent(
    base_url: str, session_id: str, concurrency: int, rounds: int, timeout: int
) -> dict[str, ToolStats]:
    """Fire concurrent batches of mixed tool calls."""
    cases = define_test_cases()
    total_calls = concurrency * rounds

    log.info(
        "═══ Concurrent phase: %d workers × %d rounds = %d calls ═══",
        concurrency,
        rounds,
        total_calls,
    )

    stats: dict[str, ToolStats] = {}

    def _worker_call(
        tool_name: str, args: dict, round_idx: int
    ) -> tuple[str, float, Optional[str]]:
        """Single tool call in a thread. Returns (key, elapsed, error_or_None)."""
        # Each thread gets its own client to avoid shared state issues
        c = McpClient(base_url, timeout=timeout)
        c.session_id = session_id
        key = f"{tool_name}({_args_short(args)})"
        t0 = time.monotonic()
        try:
            c.call_tool_result(tool_name, args)
            return (key, time.monotonic() - t0, None)
        except Exception as e:
            return (key, time.monotonic() - t0, f"round={round_idx}: {e}")

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for rnd in range(rounds):
            # Pick a diverse mix of tools for this round
            batch = []
            for i in range(concurrency):
                idx = (rnd * concurrency + i) % len(cases)
                tool_name, args = cases[idx]
                batch.append(pool.submit(_worker_call, tool_name, args, rnd))

            for fut in as_completed(batch):
                key, elapsed, err = fut.result()
                if key not in stats:
                    stats[key] = ToolStats(name=key)
                st = stats[key]
                st.latencies.append(elapsed)
                if err:
                    st.fail += 1
                    st.errors.append(err)
                else:
                    st.ok += 1

            # Progress
            done = (rnd + 1) * concurrency
            if (rnd + 1) % max(1, rounds // 10) == 0:
                ok_total = sum(s.ok for s in stats.values())
                fail_total = sum(s.fail for s in stats.values())
                log.info(
                    "  Round %d/%d complete (%d calls, ok=%d fail=%d)",
                    rnd + 1,
                    rounds,
                    done,
                    ok_total,
                    fail_total,
                )

    return stats


# ─── Helpers ────────────────────────────────────────────────────────────────


def _args_short(args: dict) -> str:
    """Short representation of args for display."""
    if not args:
        return ""
    parts = []
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 12:
            v = v[:10] + ".."
        parts.append(f"{k}={v}")
    return ", ".join(parts)


def print_stats_table(title: str, stats: dict[str, ToolStats]):
    """Print a formatted stats table."""
    if not stats:
        return

    print(f"\n{'─' * 110}")
    print(f"  {title}")
    print(f"{'─' * 110}")
    print(
        f"  {'Tool':<45} {'OK':>5} {'FAIL':>5} {'Total':>6}  "
        f"{'Avg':>8} {'Min':>8} {'Max':>8} {'P99':>8}"
    )
    print(
        f"  {'─' * 43}  {'─' * 5} {'─' * 5} {'─' * 6}  "
        f"{'─' * 8} {'─' * 8} {'─' * 8} {'─' * 8}"
    )

    total_ok = 0
    total_fail = 0
    all_latencies = []

    for key in sorted(stats.keys()):
        st = stats[key]
        total_ok += st.ok
        total_fail += st.fail
        all_latencies.extend(st.latencies)
        status = "✓" if st.fail == 0 else "✗"
        print(
            f"  {status} {st.name:<43} {st.ok:>5} {st.fail:>5} {st.total:>6}  "
            f"{st.avg_ms:>7.1f}ms {st.min_ms:>7.1f}ms {st.max_ms:>7.1f}ms "
            f"{st.p99_ms:>7.1f}ms"
        )

    print(
        f"  {'─' * 43}  {'─' * 5} {'─' * 5} {'─' * 6}  "
        f"{'─' * 8} {'─' * 8} {'─' * 8} {'─' * 8}"
    )

    if all_latencies:
        avg_all = sum(all_latencies) / len(all_latencies) * 1000
        max_all = max(all_latencies) * 1000
    else:
        avg_all = max_all = 0.0
    print(
        f"  {'TOTAL':<45} {total_ok:>5} {total_fail:>5} "
        f"{total_ok + total_fail:>6}  {avg_all:>7.1f}ms {'':>8} {max_all:>7.1f}ms"
    )

    # Print errors if any
    has_errors = any(st.errors for st in stats.values())
    if has_errors:
        print(f"\n  ⚠ ERRORS:")
        for key in sorted(stats.keys()):
            st = stats[key]
            if st.errors:
                # Show first 3 unique errors per tool
                unique = list(dict.fromkeys(st.errors))[:3]
                for err in unique:
                    print(f"    [{st.name}] {err}")
                if len(st.errors) > 3:
                    print(f"    [{st.name}] ... and {len(st.errors) - 3} more")


def check_server(url: str, timeout: int = 5) -> bool:
    """Check if the server is reachable."""
    try:
        req = Request(url + "/", method="GET")
        urlopen(req, timeout=timeout)
        return True
    except Exception:
        # Server might return an error for GET, but at least it's up
        try:
            req = Request(
                url + "/",
                data=b'{"jsonrpc":"2.0","id":0,"method":"ping"}',
                headers={
                    "Content-Type": "application/json",
                    "Origin": "http://localhost",
                },
                method="POST",
            )
            urlopen(req, timeout=timeout)
            return True
        except HTTPError:
            return True  # HTTP error = server is up
        except Exception:
            return False


# ─── Main ───────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="ida-cli HTTP stress test")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8765",
        help="Server URL (default: http://127.0.0.1:8765)",
    )
    parser.add_argument(
        "--idb",
        default="test/fixtures/mini2.i64",
        help="IDB path to open (default: test/fixtures/mini2.i64)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="Sequential iterations per tool (default: 100)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=13,
        help="Concurrent requests per batch (default: 13)",
    )
    parser.add_argument(
        "--batch-rounds",
        type=int,
        default=50,
        help="Number of concurrent batch rounds (default: 50)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Per-request timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--skip-sequential", action="store_true", help="Skip sequential stress phase"
    )
    parser.add_argument(
        "--skip-concurrent", action="store_true", help="Skip concurrent stress phase"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("stress").setLevel(logging.DEBUG)

    # ── Check server connectivity ──
    log.info("Checking server at %s ...", args.url)
    if not check_server(args.url):
        log.error("Server not reachable at %s", args.url)
        log.error("Start the server first:")
        log.error("  ./target/release/ida-cli serve-http --bind 127.0.0.1:8765")
        sys.exit(1)
    log.info("Server is reachable")

    # ── Initialize MCP session ──
    client = McpClient(args.url, timeout=args.timeout)
    try:
        client.initialize()
    except Exception as e:
        log.error("MCP initialization failed: %s", e)
        sys.exit(1)

    # ── Open IDB ──
    log.info("Opening IDB: %s", args.idb)
    try:
        open_result = client.call_tool_result("open_idb", {"path": args.idb})
        log.info("IDB opened successfully")
        # Extract content text for info
        if isinstance(open_result, dict):
            content = open_result.get("content", [])
            if isinstance(content, list) and content:
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        text = item["text"]
                        try:
                            info = json.loads(text)
                            log.info(
                                "  file_type=%s, functions=%s, bits=%s",
                                info.get("file_type", "?"),
                                info.get("function_count", "?"),
                                info.get("bits", "?"),
                            )
                        except (json.JSONDecodeError, TypeError):
                            log.info("  %s", text[:200])
                        break
    except Exception as e:
        log.error("Failed to open IDB: %s", e)
        sys.exit(1)

    # ── Extract close_token for later ──
    close_token = None
    try:
        if isinstance(open_result, dict):
            content = open_result.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        info = json.loads(item["text"])
                        close_token = info.get("close_token")
                        break
    except Exception:
        pass

    # ── Run stress tests ──
    overall_start = time.monotonic()
    seq_stats = {}
    conc_stats = {}
    exit_code = 0

    try:
        if not args.skip_sequential:
            seq_start = time.monotonic()
            seq_stats = run_sequential(client, args.iterations)
            seq_elapsed = time.monotonic() - seq_start
            log.info("Sequential phase completed in %.1fs", seq_elapsed)

        if not args.skip_concurrent:
            conc_start = time.monotonic()
            conc_stats = run_concurrent(
                args.url,
                client.session_id,
                args.concurrency,
                args.batch_rounds,
                args.timeout,
            )
            conc_elapsed = time.monotonic() - conc_start
            log.info("Concurrent phase completed in %.1fs", conc_elapsed)

    except KeyboardInterrupt:
        log.warning("Interrupted by user")
    except Exception as e:
        log.error("Stress test error: %s", e)
        traceback.print_exc()
        exit_code = 1

    # ── Close IDB ──
    log.info("Closing IDB...")
    try:
        close_args = {"token": close_token} if close_token else {}
        client.call_tool("close_idb", close_args)
        log.info("IDB closed")
    except Exception as e:
        log.warning("close_idb failed: %s (non-fatal)", e)

    # ── Report ──
    overall_elapsed = time.monotonic() - overall_start

    print(f"\n{'═' * 110}")
    print(f"  IDA MCP STRESS TEST REPORT")
    print(f"  Server: {args.url}  |  IDB: {args.idb}")
    print(f"  Duration: {overall_elapsed:.1f}s")
    print(f"{'═' * 110}")

    if seq_stats:
        print_stats_table(
            f"SEQUENTIAL  ({args.iterations} iterations per tool)", seq_stats
        )

    if conc_stats:
        print_stats_table(
            f"CONCURRENT  ({args.concurrency} workers × {args.batch_rounds} rounds)",
            conc_stats,
        )

    # ── Final verdict ──
    total_ok = sum(s.ok for s in seq_stats.values()) + sum(
        s.ok for s in conc_stats.values()
    )
    total_fail = sum(s.fail for s in seq_stats.values()) + sum(
        s.fail for s in conc_stats.values()
    )

    print(f"\n{'═' * 110}")
    if total_fail == 0:
        print(f"  ✅ ALL PASSED: {total_ok} calls, 0 failures")
    else:
        print(f"  ❌ FAILURES: {total_fail}/{total_ok + total_fail} calls failed")
        exit_code = 1
    print(f"{'═' * 110}\n")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
