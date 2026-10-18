"""Test-only public client transport and barriers; real bridge and two Unix lanes."""
import http.client
import json
import os
from pathlib import Path
import sys
import subprocess
import threading
import time
from types import SimpleNamespace

ROOT = Path(os.environ["F1_ROOT"])
Path(os.environ['IDA_NEXUS_STATE_DIR']).mkdir(mode=0o700, parents=True, exist_ok=True)
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
            if SCENARIO == 'n9-aux-refusal':
                pending = self.payload['lease_id'] != handles[0]._lease_id
                return json.dumps({'ok': True, 'result': {
                    'released': True, 'shutdown_pending': pending}}).encode()
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
        if '_g.close_status()' in code or '_r9_guard.close_status()' in code:
            refusal = 'Root Node missing; saving refused' if SCENARIO == 'n9-aux-refusal' else None
            return json.dumps({'ok': True, 'result': {'result': {
                'close_safe': True, 'save_guard_error': refusal}}}).encode()
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
# These pre-custody transport regressions intentionally mock DatabaseHandle.open
# and owner identity. Freeze their previous acquisition adapter explicitly;
# execute/cancel use the current production bridge and real N1. The release
# wrapper below is an explicit custody boundary double, not helper/proof evidence.
# This fixture cannot establish R3a custody/helper/proof correctness. The separate
# nexus_r3a target uses the formal SDK and verified installation for that claim.
production_invoke = bridge.Bridge.invoke
def legacy_transport_open(self, channel, attempt, command, deadline, public_started):
    from ida_nexus import discover_databases
    from bridge import idb_context, ida_cli_home, open_checked, guarded_source, release_handle, error, database_diagnostics
    import hashlib
    import uuid
    readiness = bridge.readiness
    kind = command["command"]
    if kind == "open":
        # The default diagnostic context uses stat, independently of the
        # owner Root Node protection. Full reads require forensic opt-in.
        metadata_context = {"requested_path": command["path"],
                            "before_open": idb_context(command["path"], deadline),
                            "open_started": time.monotonic()}
        options = dict(command["options"])
        wait_analysis = options.pop("wait_analysis", False)
        verification = options.pop("verification_idb", None)
        snapshot = options.pop("verify_input_snapshot", None)
        attach = options.pop("attach_instance", None)
        options["startup_timeout"] = max(0.001, deadline - time.monotonic())
        options["worker_env"] = dict(os.environ)
        options["worker_cwd"] = str(ida_cli_home())
        if verification is not None:
            original = Path(command["path"])
            copy_hash = hashlib.sha256(Path(verification).read_bytes()).digest()
            if hashlib.sha256(original.read_bytes()).digest() != copy_hash:
                raise ValueError("legacy cache changed during verification copy; refusing reuse")
            expected = hashlib.sha256(Path(snapshot).read_bytes()).hexdigest()
            with self.lock:
                self.verification_probes[verification] = None
            public_started[0] = True
            def track_probe(probe, _context):
                with self.lock:
                    self.verification_probes[verification] = probe

            def release_probe(_probe):
                public_started[0] = False
                with self.lock:
                    self.verification_probes.pop(verification, None)

            probe, _, _ = open_checked(self.Handle, self.Options, str(verification),
                {'auto_analysis': False, 'worker_env': dict(os.environ),
                 'worker_cwd': str(ida_cli_home())}, deadline, guarded_source,
                dict(metadata_context, method='verification-open'), track_probe, release_probe,
                lambda: public_started.__setitem__(0, True))
            try:
                proof = probe.execute_python(guarded_source(
                    "import ida_nalt\nsha = ida_nalt.retrieve_input_file_sha256()\nresult = sha.hex() if sha else None",
                    dict(metadata_context, method='verification-open', record_id=probe.instance.record_id)),
                    timeout=max(0.001, deadline - time.monotonic()))["result"]
            finally:
                self.close_verification(verification, probe, deadline)
            # A confirmed closed probe has no lease or operation left.
            # The following verification rejections are certain failures.
            public_started[0] = False
            if not isinstance(proof, str) or len(proof) != 64 or proof == "0" * 64:
                raise ValueError("legacy cache input SHA256 is unavailable; refusing reuse without changing original")
            if proof != expected:
                raise ValueError("legacy cache input SHA256 mismatch; refusing reuse without changing original")
            if hashlib.sha256(original.read_bytes()).digest() != copy_hash:
                raise ValueError("legacy cache changed during Nexus verification; refusing reuse")
            options["startup_timeout"] = max(0.001, deadline - time.monotonic())
        lease_box = []

        def track_open(handle, context):
            instance = handle.instance
            with self.lock:
                generation = self.generations.setdefault(instance.record_id, 1)
                lease = {"client_id": command["identity"]["client_id"], "lease_id": uuid.uuid4().hex,
                         "instance_id": instance.record_id, "generation": generation,
                         "owner": "gui" if instance.backend == "gui" else "managed"}
                self.handles[lease["lease_id"]] = (lease, handle)
                self.metadata_contexts[lease["lease_id"]] = dict(context, record_id=instance.record_id)
                lease_box[:] = [lease]
            context.update(lease=lease, operation_id=command['identity'].get('operation_id'))
            handle.set_disconnect_callback(lambda _handle, reason: self.disconnected(lease, reason, attempt))

        def release_open(_handle):
            public_started[0] = False
            with self.lock:
                lease = lease_box[0]
                self.handles.pop(lease['lease_id'], None)
                self.metadata_contexts.pop(lease['lease_id'], None)

        if attach:
            instances = [x.instance for x in discover_databases() if x.instance.record_id == attach]
            if len(instances) != 1:
                raise ValueError("attach instance is not available")
            public_started[0] = True
            handle = self.Handle.attach(instances[0], idle_timeout=options.get("idle_timeout"))
            track_open(handle, metadata_context)
        else:
            handle, actual, _ = open_checked(self.Handle, self.Options, command['path'], options,
                deadline, guarded_source, dict(metadata_context, method='open'),
                track_open, release_open, lambda: public_started.__setitem__(0, True))
        instance, lease = handle.instance, lease_box[0]
        # Verify actual owner runtime without importing IDA in this process.
        try:
            if attach:
                actual = handle.execute_python(guarded_source(
                    "import ida_kernwin\nresult = ida_kernwin.get_kernel_version()",
                    dict(metadata_context, method='open', lease=lease_box[0])),
                    timeout=max(0.001, deadline-time.monotonic()))
            if wait_analysis:
                handle.wait_autoanalysis(timeout=max(0.001, deadline - time.monotonic()))
                handle.execute_python(guarded_source('pass', dict(metadata_context,
                    method='open-after-analysis', lease=lease,
                    operation_id=command['identity'].get('operation_id'), record_id=instance.record_id)),
                    timeout=max(0.001, deadline - time.monotonic()))
        except Exception as exc:
            outcome = release_handle(handle, deadline)
            if outcome is None:
                raise TimeoutError("open runtime check cleanup unconfirmed; lease retained") from exc
            with self.lock:
                self.handles.pop(lease["lease_id"], None)
                self.metadata_contexts.pop(lease["lease_id"], None)
            # Close confirmed this unannounced lease is gone. If close
            # itself fails, run() retains the uncertain open outcome.
            channel.send({"event": "failed", "attempt": attempt,
                          "error": error("disconnected", f"open runtime check failed: {exc}; {outcome['save_guard_error'] or ''}"),
                          "save_guard_error": outcome['save_guard_error'],
                          "diagnostics": database_diagnostics(instance.idb_path)})
            return
        caps = readiness()["capabilities"]
        ida = [int(x) for x in actual["result"].split(".")[:3]]
        caps["runtime"]["ida"] = ida + [0] * (3 - len(ida))
        channel.send({"event": "opened", "attempt": attempt, "lease": lease,
                      "capabilities": caps, "pid": instance.pid, "idb_path": instance.idb_path,
                      "recovery": handle.recovery})
        return
    if kind == 'release':
        from release_wrapper import install
        lease = command['lease']
        handle = self.handles[lease['lease_id']][1]
        if lease['lease_id'] not in self.custodians:
            auxiliary = opened(handle.instance.idb_path) if not handle.connected else None
            install(self, lease, handle, auxiliary)
    return production_invoke(self, channel, attempt, command, deadline, public_started)
original_invoke = legacy_transport_open

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
owner_started_at = time.time()
handle_module.http.client.HTTPConnection = lambda *_a, **_k: Connection(control=True)
DatabaseHandle._rpc_connection_for = lambda *_: Connection()

def opened(path, **_options):
    instance = SimpleNamespace(record_id="shared-owner", pid=os.getpid(), idb_path=str(ROOT / "input.i64"),
                               started_at=owner_started_at, backend="idalib", managed=True, port=1, _token=os.urandom(16).hex())
    result = DatabaseHandle(path, instance)
    handles.append(result)
    if SCENARIO == "open-pre-disconnected" and len(handles) == 2:
        result._mark_disconnected("fixture disconnect before callback registration")
    return result
DatabaseHandle.open = opened
ida_nexus.discover_databases = lambda **_k: []
if SCENARIO == 'n9-aux-refusal':
    ida_nexus.discover_databases = lambda **_k: [SimpleNamespace(instance=handles[0].instance)]
    DatabaseHandle.attach = lambda entry: opened(entry.idb_path)
    ida_nexus.wait_database_released = lambda *_a, **_k: True
bridge.readiness = lambda: {"ready": True, "capabilities": {
    "runtime": {"ida": [9, 5, 0], "python": [3, 11, 0], "nexus": [0, 13, 4], "domain": [0, 5, 1]},
    "methods": bridge.METHODS}, "protocol": bridge.admission(), "paths": bridge.startup_paths()}

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
