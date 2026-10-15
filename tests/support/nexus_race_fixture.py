"""Test-only public client transport and barriers; real bridge and two Unix lanes."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import threading
import time
from types import SimpleNamespace

ROOT = Path(os.environ["F1_ROOT"])
(ROOT / "process.json").write_text(json.dumps({"pid": os.getpid(), "birth": subprocess.check_output(["timeout", "3s", "/bin/ps", "-p", str(os.getpid()), "-o", "lstart="], text=True).strip(), "command": [sys.executable, __file__]}))
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "nexus_bridge"))
import bridge
from ida_nexus import DatabaseHandle
import ida_nexus
import ida_nexus.handle as handle_module


def barrier(name):
    (ROOT / (name + ".arrived")).touch()
    until = time.monotonic() + 4
    while not (ROOT / (name + ".release")).exists():
        if time.monotonic() > until:
            raise TimeoutError("fixture barrier " + name)
        threading.Event().wait(0.005)


DatabaseHandle._open_lease = lambda *_: (None, None, None)
DatabaseHandle._monitor_lease = lambda *_: None
DatabaseHandle._release_remote_lease = lambda *_: False
DatabaseHandle._crashed_database_state = lambda *_: None
handles = []
original_send = bridge.Channel.send


def send(self, event):
    if event.get("event") == "uncertain" and os.environ.get("F1_SCENARIO") == "early-proof":
        barrier("uncertain")
    original_send(self, event)
bridge.Channel.send = send


class Connection:
    status = 200
    def __init__(self, control=False):
        self.control = control
    def request(self, _method, endpoint, **options):
        self.payload = json.loads(options.get("body") or "{}")
        self.endpoint = endpoint
    def getresponse(self):
        return self
    def read(self):
        if self.control:
            op = self.payload["operation_id"]
            index = counts.get(op, 0)
            counts[op] = index + 1
            (ROOT / f"cancel-{op}-{index}").touch()
            # First cancellation registers intent, later requests observe completion.
            return json.dumps({"result": {"cancelled": index == 0}}).encode()
        code = self.payload.get("code", "")
        if code == "unknown":
            if os.environ.get("F1_SCENARIO") == "ack-first":
                barrier("failure")
            raise http.client.RemoteDisconnected("fixture execution stream loss")
        if code == "block":
            barrier("business")
        return json.dumps({"ok": True, "result": {"result": "9.5" if "get_kernel_version" in code else code}}).encode()
    def close(self):
        pass


counts = {}
handle_module.http.client.HTTPConnection = lambda *_a, **_k: Connection(control=True)
DatabaseHandle._rpc_connection_for = lambda *_: Connection()

def opened(path, **_options):
    instance = SimpleNamespace(record_id="shared-owner", pid=os.getpid(), idb_path=str(ROOT / "input.i64"),
                               backend="idalib", managed=True, port=1, _token=os.urandom(16).hex())
    result = DatabaseHandle(path, instance)
    handles.append(result)
    return result
DatabaseHandle.open = opened
ida_nexus.discover_databases = lambda **_k: []
bridge.readiness = lambda: {"ready": True, "capabilities": {
    "runtime": {"ida": [9, 5, 0], "python": [3, 11, 0], "nexus": [0, 13, 4], "domain": [0, 5, 1]},
    "methods": bridge.METHODS}}

def fault():
    while not (ROOT / "disconnect-first").exists():
        threading.Event().wait(0.005)
    handles[0]._mark_disconnected("fixture_sse_failure")
# No private fields are restored. Only test transport/disconnect injection.
threading.Thread(target=fault, daemon=True).start()
os._exit(bridge.main())
