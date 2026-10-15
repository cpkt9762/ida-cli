"""Test-only identity instrumentation and an independent public Nexus client."""
import http.client
import importlib.metadata
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import threading
import types
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests/support"))
from nexus_env import Environment

env = Environment(Path(os.environ["N3_ENV_ROOT"]))
# No signal handler changes in the bridge's business threads. Persist creation
# intent before Popen and the exact birth before returning it to Nexus.
real_popen = subprocess.Popen
proxy = types.SimpleNamespace(**vars(subprocess))
def owned_popen(command, **options):
    intent = env._begin_creation(command)
    child = real_popen(command, **options)
    try:
        env._record(child, command)
        env._finish_creation(intent)
    except BaseException:
        child.kill()
        child.wait(timeout=3)
        raise
    env.children.append(child)
    return child
proxy.Popen = owned_popen
# Record even a dependency-failure bridge before importing Nexus.
env._record(types.SimpleNamespace(pid=os.getpid()), [sys.executable, __file__, *sys.argv[1:]])
try:
    import ida_nexus._resolver as resolver
except ImportError:
    if len(sys.argv) > 1 and sys.argv[1] == "external":
        raise
    runpy.run_path(str(REPO / "nexus_bridge/bridge.py"), run_name="__main__")
    raise AssertionError("bridge main must exit")
resolver.subprocess = proxy
# Popen remains owned until waitpid observes exit; the production Nexus client
# deliberately detaches its owner. This test-only observer sends no signals.
def reap_workers():
    while True:
        for child in list(env.children):
            child.poll()
        threading.Event().wait(0.02)
threading.Thread(target=reap_workers, daemon=True).start()

if len(sys.argv) > 1 and sys.argv[1] == "external":
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions
    handle = DatabaseHandle.open(sys.argv[2], options=DatabaseOpenOptions(
        startup_timeout=10, worker_env=env.variables(), worker_cwd=env.root))
    print(json.dumps({"event":"external_opened", "instance_id":handle.instance.record_id,
                      "pid":handle.instance.pid}), flush=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            if request["command"] == "close":
                handle.close(wait_for_database=True, timeout=10)
                print(json.dumps({"event":"external_closed"}), flush=True)
                break
            result = handle.execute_python(request["code"], timeout=None)
            print(json.dumps(result), flush=True)
    finally:
        handle.close(wait_for_database=True, timeout=10)
else:
    if os.environ.get("N3_LEASE_FAULT"):
        from ida_nexus import DatabaseHandle
        original_open_lease = DatabaseHandle._open_lease
        first = [True]
        def open_lease(handle, instance):
            connection, response, stream = original_open_lease(handle, instance)
            if first[0]:
                first[0] = False
                readline = response.readline
                def faulted_readline(*args, **kwargs):
                    line = readline(*args, **kwargs)
                    if (env.root / "lease-fault.inject").exists():
                        (env.root / "lease-fault.observed").touch()
                        raise http.client.RemoteDisconnected("injected isolated first-lease SSE failure")
                    return line
                response.readline = faulted_readline
            return connection, response, stream
        # Fault only one actual HTTP response at its read boundary. Never change
        # the server or restore client fields; sibling SSE/execute sockets remain real.
        DatabaseHandle._open_lease = open_lease
    if os.environ.get("N3_WRONG_VERSION"):
        original_version = importlib.metadata.version
        importlib.metadata.version = lambda name: "0.13.3" if name == "ida-nexus" else original_version(name)
    runpy.run_path(str(REPO / "nexus_bridge/bridge.py"), run_name="__main__")
