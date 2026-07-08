#!/usr/bin/env python3
"""ida-cli front-end that forces idat-compat on IDA 9.4+ (native-linked crashes)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REAL_BIN = Path(__file__).resolve().parent / "ida-cli.real"
STATE_DIR = Path.home() / ".ida" / "idat-proxy"
PATH_COMMANDS = {
    "list-functions": "list_functions",
    "decompile": "decompile_function",
    "disasm": "disasm",
    "xrefs-to": "get_xrefs_to",
    "xrefs-to-string": "get_xrefs_to_string",
    "callers": "get_callers",
    "callees": "get_callees",
    "address-info": "get_address_info",
    "list-imports": "list_imports",
    "list-strings": "list_strings",
    "list-segments": "list_segments",
    "raw": None,
    "close": "close",
    "prewarm": "open",
}


def idb_cache_path(binary: Path) -> Path:
    root = Path.home() / ".ida" / "idb"
    matches = sorted(
        root.glob(f"{binary.name}.*.dylib.i64"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if matches:
        return matches[0]

    digest = hashlib.blake2b(binary.read_bytes(), digest_size=12).hexdigest()
    return root / f"{binary.name}.{digest}.dylib.i64"


def run_real(args: list[str]) -> int:
    env = os.environ.copy()
    idadir = env.get("IDADIR")
    if idadir:
        key = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
        env[key] = f"{idadir}:{env[key]}" if key in env else idadir
    proc = subprocess.run([str(REAL_BIN), *args], env=env)
    return proc.returncode


def worker_env() -> dict[str, str]:
    env = os.environ.copy()
    idadir = env.get("IDADIR")
    if not idadir:
        for app in sorted(Path("/Applications").glob("IDA Professional*.app"), reverse=True):
            macos = app / "Contents" / "MacOS"
            if macos.is_dir():
                idadir = str(macos)
                break
    if idadir:
        env["IDADIR"] = idadir
        key = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
        env[key] = f"{idadir}:{env.get(key, '')}".rstrip(":")
    return env


class IdatWorker:
    def __init__(self, binary: Path):
        self.binary = binary.resolve()
        self.proc: subprocess.Popen[str] | None = None
        self.req_id = 0
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.state_file = STATE_DIR / f"{hashlib.sha1(str(self.binary).encode()).hexdigest()}.json"

    def start(self) -> None:
        if self.proc and self.proc.poll() is None:
            return
        idb = idb_cache_path(self.binary)
        open_path = idb if idb.exists() else self.binary
        cmd = [str(REAL_BIN), "serve-worker", "--backend", "idat-compat"]
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=worker_env(),
        )
        assert self.proc.stdin and self.proc.stdout
        open_params: dict[str, Any] = {
            "path": str(open_path),
            "auto_analyse": not idb.exists(),
            "timeout_secs": 3600,
        }
        if not idb.exists():
            open_params["idb_output_path"] = str(idb)
        open_req = {
            "jsonrpc": "2.0",
            "id": "open",
            "method": "open",
            "params": open_params,
        }
        resp = self.request(open_req)
        if "error" in resp and idb.exists() and open_path == idb:
            idb.unlink(missing_ok=True)
            open_params = {
                "path": str(self.binary),
                "auto_analyse": True,
                "idb_output_path": str(idb),
                "timeout_secs": 3600,
            }
            open_req["params"] = open_params
            resp = self.request(open_req)
        if "error" in resp:
            raise RuntimeError(resp["error"].get("message", resp["error"]))
        self.state_file.write_text(json.dumps({"path": str(self.binary), "idb": str(idb)}))

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("worker not started")
        line = json.dumps(payload, separators=(",", ":"))
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        out = self.proc.stdout.readline()
        if not out:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"worker exited: {err}")
        return json.loads(out)

    def rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.req_id += 1
        return self.request(
            {
                "jsonrpc": "2.0",
                "id": str(self.req_id),
                "method": method,
                "params": params,
            }
        )

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.rpc("close", {})
            except Exception:
                pass
            self.proc.terminate()


def parse_cli(argv: list[str]) -> tuple[dict[str, Any], str | None, list[str]]:
    opts: dict[str, Any] = {"json": False, "compact": False, "timeout": 120}
    path: str | None = None
    args = argv[:]
    command: list[str] = []
    while args:
        tok = args[0]
        if tok == "--path" and len(args) > 1:
            path = args[1]
            args = args[2:]
            continue
        if tok == "--json":
            opts["json"] = True
            args = args[1:]
            continue
        if tok == "--compact":
            opts["compact"] = True
            args = args[1:]
            continue
        if tok == "--timeout" and len(args) > 1:
            opts["timeout"] = int(args[1])
            args = args[2:]
            continue
        if tok.startswith("--"):
            command.extend([tok, args[1]] if len(args) > 1 and not args[1].startswith("--") else [tok])
            args = args[2:] if len(args) > 1 and not args[1].startswith("--") else args[1:]
            continue
        command = args
        break
    if not command:
        return opts, path, []
    return opts, path, command


def build_params(cmd: list[str]) -> tuple[str, dict[str, Any]]:
    name = cmd[0].replace("_", "-")
    method = PATH_COMMANDS.get(name)
    if method is None and name == "raw":
        payload = json.loads(cmd[1])
        return payload["method"], payload.get("params", {})
    if method is None:
        raise ValueError(f"unsupported command in idat proxy: {name}")

    params: dict[str, Any] = {}
    i = 1
    while i < len(cmd):
        key = cmd[i].lstrip("-").replace("-", "_")
        if i + 1 < len(cmd) and not cmd[i + 1].startswith("--"):
            val: Any = cmd[i + 1]
            if key in {"limit", "offset", "count", "max_xrefs"}:
                val = int(val)
            if key == "case_insensitive":
                val = val.lower() not in {"0", "false", "no"}
            params[key] = val
            i += 2
        else:
            if key in {"keep_warm", "queue", "exact"}:
                params[key] = True
            i += 1
    if name == "decompile" and "addr" in params:
        params["address"] = params.pop("addr")
    if name == "disasm":
        if "addr" in params:
            params["address"] = params.pop("addr")
        if "name" in params:
            params["name"] = params["name"]
    if name == "xrefs-to" and "addr" in params:
        params["address"] = params.pop("addr")
    if name == "callers" and "addr" in params:
        params["address"] = params.pop("addr")
    if name == "callees" and "addr" in params:
        params["address"] = params.pop("addr")
    if name == "address-info" and "addr" in params:
        params["address"] = params.pop("addr")
    return method, params


def print_result(method: str, result: Any, opts: dict[str, Any]) -> None:
    if opts["compact"]:
        print(json.dumps(result, separators=(",", ":")))
        return
    if opts["json"]:
        print(json.dumps(result, indent=2))
        return
    if method == "list_functions":
        functions = result.get("functions") or result.get("items") or result
        if isinstance(functions, dict):
            functions = functions.get("functions", [])
        for item in functions:
            if isinstance(item, dict):
                print(f"{item.get('address', item.get('addr', '?'))}\t{item.get('name', '?')}")
            else:
                print(item)
        return
    if method == "decompile_function":
        code = result.get("code") or result.get("pseudocode") or result
        print(code if isinstance(code, str) else json.dumps(result, indent=2))
        return
    print(json.dumps(result, indent=2))


def should_proxy(command: list[str], path: str | None) -> bool:
    if not path or not command:
        return False
    name = command[0].replace("_", "-")
    passthrough = {
        "shutdown",
        "status",
        "probe-runtime",
        "serve",
        "serve-http",
        "serve-worker",
        "help",
        "--help",
        "-h",
        "--version",
        "-V",
    }
    return name not in passthrough


def main() -> int:
    if not REAL_BIN.is_file():
        print(f"ida-cli.real not found at {REAL_BIN}", file=sys.stderr)
        return 1

    opts, path, command = parse_cli(sys.argv[1:])
    if command and command[0] in {"--help", "-h"}:
        return run_real(["--help"])
    if command and command[0] in {"--version", "-V"}:
        return run_real(["--version"])

    if not should_proxy(command, path):
        return run_real(sys.argv[1:])

    try:
        method, params = build_params(command)
        worker = IdatWorker(Path(path))
        worker.start()
        resp = worker.rpc(method, params)
        if "error" in resp:
            msg = resp["error"].get("message", resp["error"])
            print(f"Error: {msg}", file=sys.stderr)
            return 1
        print_result(method, resp.get("result", resp), opts)
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
