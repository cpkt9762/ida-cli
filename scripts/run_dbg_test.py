#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time

IDA_MCP_BIN = os.environ.get(
    "IDA_MCP_BIN",
    os.path.join(os.path.dirname(__file__), "..", "target", "release", "ida-cli"),
)
TARGET_BIN = sys.argv[1] if len(sys.argv) > 1 else IDA_MCP_BIN
TEST_SCRIPT = os.path.join(os.path.dirname(__file__), "test_dbg_headless.py")

_req_id = 0


def next_id():
    global _req_id
    _req_id += 1
    return _req_id


def send(proc, method, params=None):
    msg = {"jsonrpc": "2.0", "id": next_id(), "method": method}
    if params is not None:
        msg["params"] = params
    body = json.dumps(msg)
    frame = f"Content-Length: {len(body)}\r\n\r\n{body}"
    proc.stdin.write(frame.encode())
    proc.stdin.flush()


def send_notification(proc, method, params=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    body = json.dumps(msg)
    frame = f"Content-Length: {len(body)}\r\n\r\n{body}"
    proc.stdin.write(frame.encode())
    proc.stdin.flush()


def recv(proc, timeout=300):
    import fcntl
    import select

    fd = proc.stdout.fileno()
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 1.0)
        if ready:
            try:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                buf += chunk
            except BlockingIOError:
                pass

        while b"\r\n\r\n" in buf:
            header_end = buf.index(b"\r\n\r\n")
            header = buf[:header_end].decode()
            length = None
            for line in header.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":")[1].strip())
            if length is None:
                buf = buf[header_end + 4 :]
                continue
            body_start = header_end + 4
            if len(buf) < body_start + length:
                break
            body = buf[body_start : body_start + length].decode()
            buf = buf[body_start + length :]
            msg = json.loads(body)
            if "id" in msg and "method" not in msg:
                return msg
    return None


def recv_until_id(proc, target_id, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = recv(proc, timeout=max(1, deadline - time.time()))
        if msg is None:
            return None
        if msg.get("id") == target_id:
            return msg
    return None


def main():
    if not os.path.isfile(IDA_MCP_BIN):
        print(f"ida-cli binary not found: {IDA_MCP_BIN}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(TEST_SCRIPT):
        print(f"test script not found: {TEST_SCRIPT}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] ida-cli:    {IDA_MCP_BIN}")
    print(f"[*] target:     {TARGET_BIN}")
    print(f"[*] test script: {TEST_SCRIPT}")

    with open(TEST_SCRIPT) as f:
        test_code = f.read()

    env = os.environ.copy()
    proc = subprocess.Popen(
        [IDA_MCP_BIN],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    try:
        print("[1] Sending initialize...")
        init_id = next_id()
        send(
            proc,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "dbg-test", "version": "0.1"},
            },
        )
        resp = recv_until_id(proc, init_id, timeout=30)
        if resp and "result" in resp:
            print(
                f"    OK: server={resp['result'].get('serverInfo', {}).get('name', '?')}"
            )
        else:
            print(f"    FAIL: {resp}")
            return

        send_notification(proc, "notifications/initialized")
        time.sleep(0.5)

        print(f"[2] Opening IDB for {os.path.basename(TARGET_BIN)}...")
        open_id = next_id()
        send(
            proc,
            "tools/call",
            {
                "name": "open_idb",
                "arguments": {"path": TARGET_BIN, "force_cleanup": True},
            },
        )
        resp = recv_until_id(proc, open_id, timeout=300)
        if resp and "result" not in resp:
            print(f"    FAIL: {json.dumps(resp.get('error', resp), indent=2)}")
            return
        print(f"    OK: database opened")

        print("[3] Running debugger feasibility test...")
        run_id = next_id()
        send(
            proc,
            "tools/call",
            {
                "name": "run_script",
                "arguments": {"code": test_code, "timeout_secs": 60},
            },
        )
        resp = recv_until_id(proc, run_id, timeout=120)
        if resp is None:
            print("    FAIL: timeout waiting for run_script response")
            return

        if "error" in resp:
            print(f"    FAIL: {json.dumps(resp['error'], indent=2)}")
            return

        content = resp.get("result", {}).get("content", [])
        for item in content:
            text = item.get("text", "")
            if text.strip().startswith("{"):
                try:
                    parsed = json.loads(text)
                    stdout = parsed.get("stdout", "")
                    if stdout.strip().startswith("{"):
                        result = json.loads(stdout)
                        print("\n" + "=" * 60)
                        print("DEBUGGER FEASIBILITY TEST RESULTS")
                        print("=" * 60)
                        print(json.dumps(result, indent=2))
                        print("=" * 60)
                        verdict = result.get("summary", {}).get("verdict", "UNKNOWN")
                        print(f"\nVERDICT: {verdict}")
                        return
                    print(f"    stdout: {stdout[:500]}")
                    if parsed.get("stderr"):
                        print(f"    stderr: {parsed['stderr'][:500]}")
                except json.JSONDecodeError:
                    pass
            print(f"    raw: {text[:500]}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
