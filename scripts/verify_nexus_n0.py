#!/usr/bin/env python3
"""N0 readiness, DNS fault reproduction, saved-copy baseline, and owned cleanup."""

import argparse
import faulthandler
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import threading
import types
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tests/support"))
from nexus_env import Environment  # noqa: E402


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dns_probe(env, original, fault):
    """Fault injection is test-only; the delivered dependency uses a bind override."""
    from ida_nexus._http import LocalHTTPServer

    if original:
        result = subprocess.run(["timeout", "3s", "git", "show", "HEAD:ida_nexus/_http.py"],
                                cwd=env.root / "nexus-source", capture_output=True, text=True, check=True)
        module = types.ModuleType("ida_nexus._http_unpatched_n0")
        module.__package__ = "ida_nexus"
        sys.modules[module.__name__] = module
        exec(compile(result.stdout, "upstream-unpatched/_http.py", "exec"), module.__dict__)
        LocalHTTPServer = module.LocalHTTPServer
    if fault:
        def blocked_reverse_lookup(*_):
            print("FAULT: entered socket.gethostbyaddr", flush=True)
            threading.Event().wait(60)
            raise TimeoutError("injected reverse DNS stall")
        socket.gethostbyaddr = blocked_reverse_lookup
    faulthandler.dump_traceback_later(3, repeat=True)
    server = LocalHTTPServer("n0-test-only", lambda *_: None)
    try:
        check(server.server_address[0] == "127.0.0.1", "server must remain loopback-only")
        check(server.port > 0, "server must have an assigned port")
        check(server.server_port == server.port, "HTTP metadata must match TCP binding")
        print(json.dumps({"status": "READY", "original": original, "dns_fault": fault}))
    finally:
        server.server_close()
        faulthandler.cancel_dump_traceback_later()


class LegacyWorker:
    def __init__(self, env, binary):
        self.log = (env.root / "logs/legacy-worker.log").open("w")
        self.process = subprocess.Popen([str(binary), "serve-worker"], env=env.variables(),
                                        cwd=env.root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.log, text=True, bufsize=1)
        env.record(self.process, [str(binary), "serve-worker"])
        self.sequence = 0

    def call(self, method, params=None):
        self.sequence += 1
        request = {"jsonrpc": "2.0", "id": f"n0-{self.sequence}", "method": method,
                   "params": params or {}}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            check(selector.select(20), f"legacy {method} timed out")
        line = self.process.stdout.readline()
        check(line, f"legacy worker exited during {method}; inspect legacy-worker.log")
        response = json.loads(line)
        check(response.get("id") == request["id"], "legacy response ID mismatch")
        check(not response.get("error"), f"legacy {method} failed: {response.get('error')}")
        return response["result"]

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=10)
        self.process.stdout.close()
        self.log.close()


def legacy_baseline(env, binary):
    source = env.root / "fixtures/legacy-mini"
    shutil.copyfile(env.root / "fixtures/mini", source)
    worker = LegacyWorker(env, binary)
    try:
        opened = worker.call("open", {"path": str(source), "auto_analyse": True})
        functions = worker.call("list_functions", {"offset": 0, "limit": 100})
        check(functions["total"] >= 2, "legacy fixture must contain add and main")
        add = next(f for f in functions["functions"] if f["name"] in ("add", "_add"))
        worker.call("set_comment", {"address": add["address"], "comment": "N0 saved legacy baseline"})
        decompiled = worker.call("decompile_function", {"address": add["address"]})
        check(decompiled, "legacy decompiler must return a result")
        worker.call("close")
    finally:
        worker.close()
    databases = list((env.root / "cli-home").rglob("*.i64"))
    check(len(databases) == 1, "expected one saved legacy database in isolated CLI home")
    database = databases[0]
    check(not database.with_suffix(".id0").exists(), "legacy database must be closed before backup")
    backup = env.root / "backups/legacy-mini.i64"
    shutil.copyfile(database, backup)
    expected = sha256(backup)
    reopened = env.root / "fixtures/legacy-reopen.i64"
    shutil.copyfile(backup, reopened)
    worker = LegacyWorker(env, binary)
    try:
        worker.call("open", {"path": str(reopened)})
        actual = worker.call("list_functions", {"offset": 0, "limit": 100})
        check(actual == functions, "legacy saved copy must reopen with identical functions")
        marker = worker.call("run_script", {"code": f"import ida_bytes\nprint(ida_bytes.get_cmt({int(add['address'], 16)}, False))"})
        check("N0 saved legacy baseline" in json.dumps(marker), "legacy annotation must persist")
        worker.call("close")
    finally:
        worker.close()
    check(sha256(backup) == expected, "reopening a copy must not modify the backup")
    result = {"binary": str(binary), "binary_sha256": sha256(binary), "opened": opened,
              "functions": functions, "decompiled": decompiled,
              "backup": str(backup), "backup_sha256": expected, "reopen": "PASS"}
    (env.root / "legacy-baseline.json").write_text(json.dumps(result, indent=2) + "\n")


def nexus_baseline(env):
    import importlib.metadata
    import ida_nexus
    from ida_nexus import _resolver
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions, discover_databases, probe_database_state

    check(Path(ida_nexus.__file__).resolve().is_relative_to(env.root / "venv"), "Nexus must load from isolated venv")
    custom = sys.modules.get("sitecustomize")
    custom_path = Path(custom.__file__).resolve() if custom is not None else None
    check(custom_path is None or custom_path.is_relative_to(Path(sys.base_prefix).resolve()),
          "sitecustomize outside the selected Python installation must not affect verification")
    check(socket.getfqdn.__module__ == "socket", "getfqdn must use the standard implementation")
    check(not discover_databases(), "fresh isolated state must start with no owners")
    variables = env.variables()
    options = DatabaseOpenOptions(startup_timeout=20, worker_env=variables, worker_cwd=env.root)
    handles = []
    original_spawn = _resolver.spawn_worker

    def owned_spawn(*args, **kwargs):
        process, log_path = original_spawn(*args, **kwargs)
        env.record(process, process.args)
        return process, log_path

    def open_owned(path):
        def resolve_owned(*args, **kwargs):
            return _resolver.resolve_instance(*args, **kwargs, spawner=owned_spawn)
        with patch("ida_nexus.handle.resolve_instance", side_effect=resolve_owned):
            handle = DatabaseHandle.open(str(path), options=options)
        handles.append(handle)
        check(Path(handle.instance.idb_path).is_relative_to(env.root), "owner must open a disposable database")
        return handle

    try:
        handle = open_owned(env.root / "fixtures/mini")
        analysis = handle.wait_autoanalysis(timeout=20)
        check(analysis["complete"], "Nexus analysis must complete")
        snapshot_code = ("import ida_bytes, ida_kernwin\n"
                         "{'ida_version': ida_kernwin.get_kernel_version(), "
                         "'functions': [(int(f.start_ea), db.functions.get_name(f)) for f in db.functions.get_all()]} ")
        snapshot = handle.execute_python(snapshot_code, timeout=10)["result"]
        check(len(snapshot["functions"]) >= 2, "Nexus fixture must contain add and main")
        address = next(ea for ea, name in snapshot["functions"] if name in ("add", "_add"))
        changed = handle.execute_python(f"import ida_bytes\nida_bytes.set_cmt({address}, 'N0 saved Nexus baseline', False)", timeout=10)
        check(changed["result"] is True, "Nexus marker write must succeed")
        saved = handle.save_database()
        check(saved["saved"], "Nexus save must report success")
        database = Path(saved["idb_path"])
        instance = {"record_id": handle.instance.record_id, "pid": handle.instance.pid, "path": str(database)}
        handle.close(wait_for_database=True, timeout=15)
        check(probe_database_state(database)["state"] == "packed", "backup requires a closed packed database")
        backup = env.root / "backups/nexus-mini.i64"
        shutil.copyfile(database, backup)
        expected = sha256(backup)
        reopened = env.root / "fixtures/nexus-reopen.i64"
        shutil.copyfile(backup, reopened)
        handle = open_owned(reopened)
        actual = handle.execute_python(snapshot_code, timeout=10)["result"]
        check(actual == snapshot, "Nexus saved copy must reopen with identical functions and version")
        marker = handle.execute_python(f"import ida_bytes\nida_bytes.get_cmt({address}, False)", timeout=10)
        check(marker["result"] == "N0 saved Nexus baseline", "Nexus annotation must persist")
        handle.close(wait_for_database=True, timeout=15)
        check(sha256(backup) == expected, "Nexus backup must remain unchanged")
        check(not discover_databases(), "all owned Nexus instances must be released")
        result = {"status": "PASS", "snapshot": snapshot, "instance": instance,
                  "interpreter_sitecustomize": str(custom_path) if custom_path else None,
                  "versions": {name: importlib.metadata.version(name) for name in ("ida-nexus", "ida-domain", "idapro")},
                  "backup": str(backup), "backup_sha256": expected, "reopen": "PASS"}
        (env.root / "nexus-baseline.json").write_text(json.dumps(result, indent=2) + "\n")
    finally:
        for handle in reversed(handles):
            handle.close(wait_for_database=True, timeout=15)


def startup_timeout(env, budget):
    """Stop this test's new worker before readiness, then account for its cleanup."""
    from ida_nexus import _resolver, DatabaseHandle, DatabaseOpenOptions, WorkerStartError
    source = env.root / "fixtures/stalled-mini"
    check(not source.exists(), "startup fault fixture must be new")
    shutil.copyfile(env.root / "fixtures/mini", source)
    processes = []

    def stopped_spawn(*args, **kwargs):
        process, log = _resolver.spawn_worker(*args, **kwargs)
        processes.append(process)
        env.record(process, process.args)
        os.kill(process.pid, signal.SIGSTOP)
        return process, log

    def resolve_stopped(*args, **kwargs):
        return _resolver.resolve_instance(*args, **kwargs, spawner=stopped_spawn)

    try:
        with patch("ida_nexus.handle.resolve_instance", side_effect=resolve_stopped):
            try:
                handle = DatabaseHandle.open(str(source), options=DatabaseOpenOptions(
                    startup_timeout=budget, worker_env=env.variables(), worker_cwd=env.root))
            except (TimeoutError, WorkerStartError) as error:
                check("timed out" in str(error), "startup must report its finite deadline")
                print(json.dumps({"status": "EXPECTED_TIMEOUT", "error_type": type(error).__name__}))
            else:
                handle.close(wait_for_database=True, timeout=5)
                raise AssertionError("stopped worker unexpectedly became ready")
    finally:
        killed = env.cleanup()
        for process in processes:
            process.wait(timeout=5)
        env.assert_clean()
        (env.root / "startup-timeout-cleanup.json").write_text(json.dumps(
            {"signalled_owned_pids": killed, "owned_workers": [p.pid for p in processes], "clean": True}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--legacy-binary", type=Path)
    parser.add_argument("--original", action="store_true")
    parser.add_argument("--fault", action="store_true")
    parser.add_argument("--startup-budget", type=float, default=1.0)
    parser.add_argument("action", choices=("dns", "baseline", "startup-timeout", "cleanup"))
    args = parser.parse_args()
    env = Environment(args.root)
    with env.exclusive():
        execute(args, env, parser)


def execute(args, env, parser):
    if args.action == "cleanup":
        killed = env.cleanup()
        env.assert_clean()
        print(json.dumps({"status": "CLEAN", "signalled_owned_pids": killed}))
        return
    if Path(sys.executable).parent.resolve() != env.root / "venv/bin":
        parser.error("run with the prepared environment's venv/bin/python")
    variables = env.variables()
    os.environ.clear()
    os.environ.update(variables)
    if args.action == "dns":
        dns_probe(env, args.original, args.fault)
        return
    def interrupted(signum, _frame):
        raise InterruptedError(f"test interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if args.action == "startup-timeout":
        startup_timeout(env, args.startup_budget)
        return
    result = {"status": "FAIL"}
    try:
        if args.legacy_binary:
            legacy_baseline(env, args.legacy_binary.resolve(strict=True))
        nexus_baseline(env)
        env.assert_clean()
        result = {"status": "PASS", "owned_process_count": len(env.entries())}
    finally:
        result["cleanup_signalled_pids"] = env.cleanup()
        env.assert_clean()
        (env.root / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
