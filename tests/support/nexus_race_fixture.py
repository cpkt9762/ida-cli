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
sys.path.insert(0, os.environ.get("F1_BRIDGE_DIR", str(REPO / "nexus_bridge")))
import bridge
# This harness emulates public HTTP execution, never an IDA owner. Root sampling
# has real-owner coverage in n7_r9_guard.py; retain the exact transport payloads.
bridge.guarded_source = lambda code, _context, refuse=True: code if refuse else 'r9-fixture-release'
from ida_nexus import DatabaseHandle
import ida_nexus
import ida_nexus.handle as handle_module


def barrier(name):
    (ROOT / (name + ".arrived")).touch()
    # File barriers include test-process scheduling/startup, not response latency.
    until = time.monotonic() + (150 if name == 'n7-release-proof' else 15)
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
    if event.get('event') == 'opened' and SCENARIO == 'n7-open-drop':
        barrier('n7-open-proof')
    if event.get('event') == 'released' and SCENARIO in ('n7-close-drop', 'n7-open-drop'):
        barrier('n7-release-proof')
    if event.get("event") == "ack" and SCENARIO == "expired-proof":
        # Shorten only stop-proof admission. The owner must still receive the
        # accepted execution deadline so its new deadline guard runs normally.
        owner = instance_bridge[0]
        with owner.lock:
            for record in owner.executing.values():
                if record["attempt"] == event["attempt"]:
                    record["deadline"] = 0
    if event.get("event") == "local_status" and SCENARIO == "control" and os.environ.get("N4_F2_DELAY"):
        threading.Event().wait(1.5)
    if event.get("event") == "uncertain" and os.environ.get("F1_SCENARIO") == "early-proof":
        barrier("uncertain")
    if event.get("event") == "opened" and SCENARIO == "open-early-event" and len(handles) == 2:
        handles[-1]._mark_disconnected("fixture disconnect before opened delivery")
        barrier("opened")
    if event.get("event") in {"failed", "uncertain"} and SCENARIO == "open-pre-disconnected":
        barrier("open-failed")
    if event.get("event") == "stopped" and SCENARIO == "expired-proof":
        barrier("stopped")
    original_send(self, event)
    if event.get('event') == 'released' and SCENARIO == 'n7-close-drop':
        (ROOT / 'n7-proof-sent').touch()
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
        if self.endpoint == "/release_lease":
            (ROOT / 'default-release-requested').touch()
            return json.dumps({"ok": True, "result": {"released": True, "shutdown_pending": False}}).encode()
        if self.control:
            op = self.payload["operation_id"]
            index = counts.get(op, 0)
            counts[op] = index + 1
            (ROOT / f"cancel-{op}-{index}").touch()
            cancelled_ids.append(op)
            if SCENARIO in {"late-success", "stale-false"}:
                if threading.current_thread().name == "old-false" and index == 0:
                    barrier("old-false")
                    cancelled = False
                elif threading.current_thread().name in {"identity-check", "old-false"}:
                    cancelled = True
                elif index == (1 if SCENARIO == "stale-false" else 0):
                    cancelled = True
                else:
                    barrier("proof")
                    cancelled = False
            elif SCENARIO == "active-fairness":
                cancelled = op != "stale" and index == 0
            else:
                cancelled = index == 0
            return json.dumps({"result": {"cancelled": cancelled}}).encode()
        code = self.payload.get("code", "")
        if code == 'r9-fixture-release':
            return json.dumps({'ok': True, 'result': {'result': {'save_guard_error': None}}}).encode()
        if code.startswith("import time as _n5_time\n"):
            guard, code = code.split("# nexus owner deadline checked\n", 1)
            exec(guard, {})
        if code == "result = None" and SCENARIO in {"late-success", "stale-false"}:
            barrier("proof")
        if code == "unknown":
            if SCENARIO == "stale-false":
                (ROOT / "unknown.arrived").touch()
            if os.environ.get("F1_SCENARIO") == "ack-first":
                barrier("failure")
            raise http.client.RemoteDisconnected("fixture execution stream loss")
        if code == "block":
            barrier("business")
            if SCENARIO == "active-fairness":
                return json.dumps({"error": {"code": "operation_cancelled", "message": "exact operation cancelled"}}).encode()
        return json.dumps({"ok": True, "result": {"result": "9.5" if "get_kernel_version" in code else code}}).encode()
    def close(self):
        pass


counts = {}
SCENARIO = os.environ.get("F1_SCENARIO")
if SCENARIO in ('n7-close-drop', 'n7-open-drop'):
    DatabaseHandle.wait_autoanalysis = lambda *_a, **_k: None
original_loads = json.loads

def causal_loads(raw, *args, **kwargs):
    # _request releases the execution lock before parsing this response. S has
    # already executed, while U can run before S's success is processed.
    if SCENARIO == "late-success" and threading.current_thread().name == "late-success":
        if b'"ok": true' in (raw.encode() if isinstance(raw, str) else raw) and b'late-success-result' in (raw.encode() if isinstance(raw, str) else raw):
            barrier("success")
    return original_loads(raw, *args, **kwargs)
json.loads = causal_loads


def outcome_event(**values):
    while instance_bridge[0] is None:
        threading.Event().wait(0.005)
    instance_bridge[0].control.send({"event": "local_status", "id": "fixture-verdict", **values})

instance_bridge = [None]
original_invoke = bridge.Bridge.invoke

def invoke(self, channel, attempt, command, deadline, public_started):
    instance_bridge[0] = self
    if command["command"] == "execute" and SCENARIO in {"late-success", "stale-false", "active-fairness"}:
        handle = self.handles[command["identity"]["lease"]["lease_id"]][1]
        operation = command["identity"]["operation_id"]
        if SCENARIO == "late-success":
            started = threading.Event()
            done = threading.Event()
            def success():
                handle.execute_python("late-success-result", operation_id="S", timeout=None)
                done.set()
            def start_success():
                while not (ROOT / "start-success").exists():
                    threading.Event().wait(0.005)
                started.set()
                success()
            threading.Thread(target=start_success, name="late-success", daemon=True).start()
            def inspect_success():
                assert started.wait(15), "late success startup marker"
                assert done.wait(5), "late success processing response"
                outcome_event(retained=handle.cancel_operation(operation), operation_id=operation)
            threading.Thread(target=inspect_success, name="identity-check", daemon=True).start()
        elif SCENARIO == "stale-false":
            def old_false():
                while not (ROOT / "old-start").exists():
                    threading.Event().wait(0.005)
                handle.cancel_operation(operation)
                outcome_event(retained=handle.cancel_operation(operation), operation_id=operation)
            threading.Thread(target=old_false, name="old-false", daemon=True).start()
        else:
            try:
                handle.execute_python("unknown", operation_id="stale", timeout=None)
            except ida_nexus.NexusConnectionError:
                pass
            else:
                raise AssertionError("stale unknown fixture must disconnect")
            def active():
                while not (ROOT / "active-check").exists():
                    threading.Event().wait(0.005)
                ack = handle.cancel_active(timeout=0.05)
                outcome_event(accepted=ack, cancelled_ids=list(cancelled_ids), operation_id=operation)
            threading.Thread(target=active, name="active-check", daemon=True).start()
    return original_invoke(self, channel, attempt, command, deadline, public_started)
bridge.Bridge.invoke = invoke
def proof_verdict(self, operation_id):
    if SCENARIO == "expired-proof":
        with self.lock:
            retained = operation_id in self.unknown
        outcome_event(unknown_retained=retained)
if hasattr(bridge.Bridge, "publish_stop"):
    original_publish_stop = bridge.Bridge.publish_stop
    def publish_stop(self, operation_id, record, outcome):
        original_publish_stop(self, operation_id, record, outcome)
        proof_verdict(self, operation_id)
    bridge.Bridge.publish_stop = publish_stop
else:
    # Keep the regression runnable on f56d116 without a missing hook failure.
    original_confirm_stop = bridge.Bridge.confirm_stop
    def confirm_stop(self, operation_id, record):
        original_confirm_stop(self, operation_id, record)
        proof_verdict(self, operation_id)
    bridge.Bridge.confirm_stop = confirm_stop
cancelled_ids = []
handle_module.http.client.HTTPConnection = lambda *_a, **_k: Connection(control=True)
DatabaseHandle._rpc_connection_for = lambda *_: Connection()

def opened(path, **_options):
    instance = SimpleNamespace(record_id="shared-owner", pid=os.getpid(), idb_path=str(ROOT / "input.i64"),
                               backend="idalib", managed=True, port=1, _token=os.urandom(16).hex())
    result = DatabaseHandle(path, instance)
    handles.append(result)
    if SCENARIO == "open-pre-disconnected" and len(handles) == 2:
        result._mark_disconnected("fixture disconnect before callback registration")
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
# F2: stop actual bridge startup at precise lifecycle boundaries.
if SCENARIO and SCENARIO.startswith("startup-"):
    import socket
    stage = SCENARIO.removeprefix("startup-")
    original_bind = socket.socket.bind
    def bind(self, address):
        original_bind(self, address)
        if str(address).endswith("/l") and stage == "lifetime":
            barrier("startup")
    socket.socket.bind = bind
    original_channel_init = bridge.Channel.__init__
    def channel_init(self, address, *args):
        if stage == "ready":
            barrier("startup")
        original_channel_init(self, address, *args)
        if str(address).endswith("/b") and stage == "business":
            barrier("startup")
    bridge.Channel.__init__ = channel_init
    if stage == "spawn":
        barrier("startup")
os._exit(bridge.main())
