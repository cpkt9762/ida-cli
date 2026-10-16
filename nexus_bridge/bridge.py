"""Persistent Nexus public client. Separate physical business/control streams."""
import concurrent.futures
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import plistlib
import queue
import socket
import sys
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools import METHODS as TOOL_METHODS
from type_tools import TYPE_METHODS
from edit_tools import EDIT_METHODS, WRITE_METHODS
from analysis_tools import ANALYSIS_METHODS
from struct_tools import STRUCT_METHODS
from query_tools import QUERY_METHODS
from search_tools import SEARCH_METHODS
from lifecycle import database_diagnostics, release_handle
from metadata import idb_context
from open_recovery import open_checked, require_safe_close

GUARD_SOURCE = Path(__file__).with_name('save_guard.py').read_text(encoding='utf-8')


def guarded_source(code, context, refuse=True):
    """Install once per owner, then sample within the same native operation."""
    setup = ("import sys as _r9_sys, types as _r9_types\n"
             "if '_ida_cli_save_guard_v1' not in _r9_sys.modules:\n"
             "    _r9_module = _r9_types.ModuleType('_ida_cli_save_guard_v1')\n"
             f"    exec({GUARD_SOURCE!r}, _r9_module.__dict__)\n"
             "    _r9_sys.modules['_ida_cli_save_guard_v1'] = _r9_module\n"
             "_r9_guard = _r9_sys.modules['_ida_cli_save_guard_v1']\n"
             f"_r9_guard.begin({context!r}, refuse={refuse!r})\n")
    finish = f"_r9_guard.finish({context!r}, refuse={refuse!r})"
    if refuse:
        # A separate compilation preserves module-level future imports in raw
        # execute_python code; a try-indented source would reject them.
        return setup + f"try:\n    exec(compile({code!r}, '<ida-cli owner>', 'exec'), globals())\nfinally:\n    " + finish
    return setup + code + '\nresult = {"save_guard_error": ' + finish + '}\n'

TOOL_METHODS = (*TOOL_METHODS, *TYPE_METHODS, *EDIT_METHODS, *ANALYSIS_METHODS, *STRUCT_METHODS, *QUERY_METHODS, *SEARCH_METHODS, "batch_rename")

HANDLE_SHA = "aa5d7ea42caaa922ef494d7d8a1406396537a4ea88d9e833825e08c8d279025e"
METHODS = {"execute_python": "may_write", "database_info": "read_only",
           "rename_address": "may_write", "read_name": "read_only"}
METHODS.update({method: "may_write" if method in WRITE_METHODS else "read_only"
                for method in TOOL_METHODS})
TOOL_SOURCE = "\n".join(Path(__file__).with_name(name).read_text(encoding="utf-8")
                        for name in ("type_tools.py", "edit_tools.py", "analysis_tools.py", "struct_tools.py", "query_tools.py", "search_tools.py", "tools.py"))
# Both ordinary and sliced execution use this checked installation. The source
# is evaluated anew by the current owner for each request, including reconnects.
METADATA_SOURCE = Path(__file__).with_name("metadata.py").read_text(encoding="utf-8")
TOOL_SOURCE += ("\n_tools_metadata = {}\n"
                + f"exec({METADATA_SOURCE!r}, _tools_metadata)\n"
                + "install_tools(_tools_metadata)\n")
SLICE_SOURCE = Path(__file__).with_name("slices.py").read_text(encoding="utf-8")
SLICE_METHODS = {"batch_decompile", "search_pseudocode", "run_auto_analysis", "batch_rename", "_n5_cleanup"}


def error(code, message):
    return {"code": code, "message": str(message)}


def readiness():
    try:
        import ida_nexus
        versions = [importlib.metadata.version(name) for name in ("ida-nexus", "ida-domain")]
        if versions != ["0.13.4", "0.5.1"]:
            raise ValueError(f"requires pinned Nexus 0.13.4/Domain 0.5.1; got {versions}")
        source = Path(ida_nexus.__file__).parent / "handle.py"
        if hashlib.sha256(source.read_bytes()).hexdigest() != HANDLE_SHA:
            raise ValueError("Nexus client cancellation/close proof patch missing or incompatible handle.py")
    except (ImportError, importlib.metadata.PackageNotFoundError, ValueError, OSError) as exc:
        return {"ready": False, "error": error("dependency_unavailable", exc)}
    try:
        ida_dir = Path(os.environ["IDADIR"]).resolve(strict=True)
        with (ida_dir.parent / "Info.plist").open("rb") as stream:
            version = plistlib.load(stream)["CFBundleShortVersionString"]
        ida = [int(part) for part in version.split(".")[:3]]
        ida += [0] * (3 - len(ida))
        if tuple(ida) < (9, 4, 0) or sys.version_info < (3, 11):
            raise ValueError("Nexus requires IDA >=9.4 and Python >=3.11")
    except (KeyError, ValueError, OSError) as exc:
        return {"ready": False, "error": error("runtime_unavailable", exc)}
    return {"ready": True, "capabilities": {"runtime": {
        "ida": ida, "python": list(sys.version_info[:3]), "nexus": [0, 13, 4], "domain": [0, 5, 1]},
        "methods": METHODS}, "client_cancel_patch": True}


def validate_response_depth(message):
    """Match serde_json's existing 127-container envelope budget before writing."""
    stack = [iter((message,))]
    while stack:
        try:
            value = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        children = value.values() if isinstance(value, dict) else value
        if isinstance(value, (dict, list, tuple)):
            if len(stack) >= 128:
                raise ValueError("response nesting exceeds receiver limit")
            stack.append(iter(children))


class Channel:
    def __init__(self, address, capacity, handler, stopped):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.connect(address)
        self.output = queue.Queue(capacity)
        self.handler = handler
        self.stopped = stopped
        self.writer = threading.Thread(target=self.write, daemon=True)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.writer.start()
        self.reader.start()

    def send(self, message):
        self.output.put(message)

    def write(self):
        try:
            while not self.stopped.is_set():
                message = self.output.get()
                try:
                    validate_response_depth(message)
                    encoded = json.dumps(message, ensure_ascii=False, allow_nan=False).encode("utf-8")
                except (TypeError, ValueError, OverflowError, RecursionError) as exc:
                    # F2/P1: no bytes were written. A returned execute result
                    # proves this native interval ended; fail only that request.
                    # Correlation was validated by Rust before entering the lane.
                    failure = {"event": "remote_error", "attempt": message["attempt"],
                               "remote_code": "response_encoding_failed",
                               "error": error("operation_failed",
                                   f"response encoding failed: {type(exc).__name__}")}
                    encoded = json.dumps(failure, ensure_ascii=True, allow_nan=False).encode("ascii")
                self.socket.sendall(encoded + b"\n")
        except OSError:
            self.stopped.set()

    def read(self):
        try:
            with self.socket.makefile("rb") as stream:
                while not self.stopped.is_set():
                    raw = stream.readline(16 * 1024 * 1024 + 1)
                    if not raw or len(raw) > 16 * 1024 * 1024:
                        break
                    self.handler(self, json.loads(raw))
        except (OSError, ValueError) as exc:
            print(f"bridge IPC failed: {type(exc).__name__}", file=sys.stderr)
        finally:
            self.stopped.set()


class Bridge:
    def __init__(self, business, control, capacity):
        from ida_nexus import DatabaseHandle, DatabaseOpenOptions
        self.Handle = DatabaseHandle
        self.Options = DatabaseOpenOptions
        self.lock = threading.Lock()
        self.handles = {}
        self.metadata_contexts = {}
        self.identity = uuid.uuid4().hex
        self.verification_probes = {}
        self.cleanup_handles = {}
        self.grants = {}
        self.generations = {}
        self.unknown = {}
        self.executing = {}
        self.proof_wakeup = threading.Event()
        self.initialized = threading.Event()
        self.stopped = threading.Event()
        self.business_pool = concurrent.futures.ThreadPoolExecutor(4, thread_name_prefix="nexus-business")
        self.cancel_pool = concurrent.futures.ThreadPoolExecutor(4, thread_name_prefix="nexus-cancel")
        self.release_pool = concurrent.futures.ThreadPoolExecutor(2, thread_name_prefix="nexus-release")
        self.proof_pool = concurrent.futures.ThreadPoolExecutor(2, thread_name_prefix="nexus-proof")
        self.proof_gate = threading.BoundedSemaphore(2)
        self.business_gate = threading.BoundedSemaphore(capacity)
        self.control_gate = threading.BoundedSemaphore(8)
        self.owners = []
        # Adapter-owned lifetime lane, never a Nexus wire protocol. Owner-side
        # watchers use only public Nexus APIs to release our jobs after EOF.
        self.lifetime_path = str(Path(business).with_name("l"))
        self.lifetime_socket = socket.socket(socket.AF_UNIX)
        self.lifetime_socket.bind(self.lifetime_path)
        self.lifetime_inode = Path(self.lifetime_path).lstat().st_ino
        self.lifetime_socket.listen(capacity)
        self.lifetimes = {}
        threading.Thread(target=self.accept_lifetimes, daemon=True).start()
        self.business = Channel(business, capacity, self.receive, self.stopped)
        self.control = Channel(control, 8, self.receive, self.stopped)
        self.initialized.set()
        threading.Thread(target=self.discover, daemon=True).start()
        threading.Thread(target=self.proofs, daemon=True).start()

    def accept_lifetimes(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.lifetime_socket.accept()
                connection.settimeout(2)
                raw = connection.recv(256)
                lease_id = raw.decode("ascii")
                with self.lock:
                    if lease_id not in self.handles:
                        connection.close()
                        continue
                    previous = self.lifetimes.get(lease_id)
                    self.lifetimes[lease_id] = connection
                    if previous is not None:
                        previous.close()
                connection.sendall(b"ok")
                connection.settimeout(None)
            except OSError:
                if not self.stopped.is_set():
                    self.stopped.set()
                return

    def drop_lifetime(self, lease_id):
        with self.lock:
            connection = self.lifetimes.pop(lease_id, None)
        if connection is not None:
            connection.close()

    def discover(self):
        from ida_nexus import discover_databases
        while not self.stopped.is_set():
            try:
                owners = [{"instance_id": item.instance.record_id, "pid": item.instance.pid,
                           "idb_path": item.instance.idb_path, "state": item.state.value}
                          for item in discover_databases(timeout=0.2)]
                with self.lock:
                    self.owners = owners
            except Exception as exc:
                print(f"owner discovery failed: {type(exc).__name__}", file=sys.stderr)
            self.stopped.wait(0.2)

    def receive(self, channel, message):
        self.initialized.wait()
        if "grant" in message:
            with self.lock:
                holder = self.grants.get(message["sequence"])
            if holder is None:
                raise ValueError("unknown grant")
            holder[1].append((message, time.monotonic()))
            holder[0].set()
            return
        if "local_status" in message:
            with self.lock:
                held = [{"lease": item[0], "connected": item[1].connected,
                         "pid": item[1].instance.pid, "idb_path": item[1].instance.idb_path}
                        for item in self.handles.values()]
                owners = list(self.owners)
                verifications = list(self.verification_probes)
            channel.send({"event": "local_status", "id": message["local_status"],
                          "held": held, "owners": owners, "verification_probes": verifications})
            return
        frame = message
        command = frame["payload"]["command"]
        control = command in {"cancel", "release", "shutdown"}
        if (channel is self.control) != control:
            raise ValueError("wrong physical lane")
        gate = self.control_gate if control else self.business_gate
        if not gate.acquire(blocking=False):
            channel.send({"event": "not_sent", "attempt": frame["attempt"],
                          "error": error("busy", "bridge lane capacity exhausted")})
            return
        pool = self.cancel_pool if command == "cancel" else self.release_pool if control else self.business_pool
        pool.submit(self.run, channel, frame, gate)

    def run(self, channel, frame, gate):
        attempt = frame["attempt"]
        key = attempt["sequence"]
        holder = (threading.Event(), [])
        with self.lock:
            self.grants[key] = holder
        public_started = [False]
        try:
            channel.send({"event": "dispatch_ready", "frame": frame})
            while not holder[0].wait(0.05):
                if self.stopped.is_set():
                    return
            grant, received_at = holder[1][0]
            if grant["grant"] is False:
                return
            payload = frame["payload"]
            budget = grant["remaining_ms"] / 1000
            deadline = received_at + budget
            if time.monotonic() >= deadline:
                raise TimeoutError("total deadline expired in bridge queue; not executed")
            self.invoke(channel, attempt, payload, deadline, public_started)
        except Exception as exc:
            from ida_nexus import NexusConnectionError, RemoteError
            details = {}
            if frame["payload"]["command"] == "open":
                command = frame["payload"]
                details['diagnostics'] = database_diagnostics(
                    command.get('options', {}).get('output_database') or command['path'])
            if isinstance(exc, RemoteError):
                channel.send({"event": "remote_error", "attempt": attempt, "remote_code": exc.code,
                              "error": error("operation_failed", str(exc)), **details})
            elif isinstance(exc, NexusConnectionError):
                if frame["payload"]["command"] == "execute":
                    self.mark_unknown(frame["payload"]["identity"]["operation_id"], attempt)
                channel.send({"event": "uncertain", "attempt": attempt,
                              "error": error("disconnected", str(exc)), **details})
            else:
                uncertain = public_started[0]
                if uncertain and frame["payload"]["command"] == "execute":
                    self.mark_unknown(frame["payload"]["identity"]["operation_id"], attempt)
                channel.send({"event": "uncertain" if uncertain else "failed", "attempt": attempt,
                              "error": error("operation_failed", f"{type(exc).__name__}: {exc}"), **details})
        finally:
            with self.lock:
                self.grants.pop(key, None)
                if frame["payload"]["command"] == "execute":
                    operation_id = frame["payload"]["identity"]["operation_id"]
                    if (operation_id not in self.unknown
                            and self.executing.get(operation_id, {}).get("attempt") == attempt):
                        self.executing.pop(operation_id, None)
            gate.release()

    def disconnected(self, lease, reason, attempt):
        # The callback may be replayed synchronously by set_disconnect_callback,
        # before N1 knows this lease. Keep its bounded open correlation intact.
        self.drop_lifetime(lease["lease_id"])
        self.control.send({"event": "disconnected", "lease": lease, "reason": reason,
                           "attempt": attempt})

    def close_verification(self, path, probe, deadline):
        from ida_nexus import wait_database_released
        probe.execute_python(guarded_source('pass', {'method': 'verification-close',
            'requested_path': path, 'record_id': probe.instance.record_id}, refuse=False),
            timeout=max(0.001, deadline - time.monotonic()))
        probe.close(wait_for_database=True, timeout=max(0.001, deadline - time.monotonic()))
        # close() is idempotent after it starts, even if its first call raised.
        # Only the public lifetime-lock observation proves the copy is unused.
        if not wait_database_released(probe.instance, timeout=max(0, deadline - time.monotonic())):
            raise TimeoutError("verification owner release unconfirmed; staging retained")
        Path(path).with_name("closed").touch()
        with self.lock:
            self.verification_probes.pop(path, None)

    def invoke(self, channel, attempt, command, deadline, public_started):
        from ida_nexus import discover_databases
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
            options["worker_cwd"] = os.environ["IDA_CLI_HOME"]
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
                     'worker_cwd': os.environ['IDA_CLI_HOME']}, deadline, guarded_source,
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
                require_safe_close(handle, deadline)
                outcome = handle.close_outcome(wait_for_database=True,
                    timeout=max(0, deadline - time.monotonic()))
                if outcome["status"] not in ("lease_released", "owner_released"):
                    from ida_nexus import wait_database_released
                    if not wait_database_released(handle.instance,
                            timeout=max(0, deadline - time.monotonic())):
                        raise TimeoutError("open runtime check cleanup unconfirmed; lease retained") from exc
                with self.lock:
                    self.handles.pop(lease["lease_id"], None)
                    self.metadata_contexts.pop(lease["lease_id"], None)
                # Close confirmed this unannounced lease is gone. If close
                # itself fails, run() retains the uncertain open outcome.
                channel.send({"event": "failed", "attempt": attempt,
                              "error": error("disconnected", f"open runtime check failed: {exc}"),
                              "diagnostics": database_diagnostics(instance.idb_path)})
                return
            caps = readiness()["capabilities"]
            ida = [int(x) for x in actual["result"].split(".")[:3]]
            caps["runtime"]["ida"] = ida + [0] * (3 - len(ida))
            channel.send({"event": "opened", "attempt": attempt, "lease": lease,
                          "capabilities": caps, "pid": instance.pid, "idb_path": instance.idb_path,
                          "recovery": handle.recovery})
            return
        lease = command.get("lease") or command["identity"]["lease"]
        with self.lock:
            stored = self.handles.get(lease["lease_id"])
        if stored is None or stored[0] != lease:
            raise ValueError("exact lease is not held by this bridge")
        handle = stored[1]
        if kind == "execute":
            method, params = command["method"], command["params"]
            if method == "execute_python":
                code = params["code"]
            elif method == "database_info":
                code = "import ida_ida, ida_name\nresult = {'address': ida_ida.inf_get_min_ea(), 'name': ida_name.get_name(ida_ida.inf_get_min_ea())}"
            elif method == "read_name":
                code = f"import ida_name\nresult = ida_name.get_name({int(params['address'])})"
            elif method == "rename_address":
                code = f"import ida_name\nresult = ida_name.set_name({int(params['address'])}, {str(params['name'])!r}, ida_name.SN_CHECK)"
            elif method in SLICE_METHODS:
                context = [self.identity, lease["lease_id"], lease["instance_id"], lease["generation"], self.lifetime_path]
                code = TOOL_SOURCE + f"\nresult = invoke_slice({method!r}, {params!r}, {context!r}, {SLICE_SOURCE!r})\n"
            elif method in TOOL_METHODS:
                context = dict(self.metadata_contexts.get(lease["lease_id"], {}), deadline=deadline)
                code = TOOL_SOURCE + f"\n_metadata_context = {context!r}\nresult = invoke({method!r}, {params!r})\n"
            else:
                raise ValueError("unsupported bridge method")
            operation_id = command["identity"]["operation_id"]
            # Each confirmed continuation is a new public Nexus operation. A
            # logical ID is never reused for native execution or replay.
            native_id = f"{operation_id}:{attempt['sequence']}" if method in SLICE_METHODS else operation_id
            with self.lock:
                self.executing[operation_id] = {"attempt": attempt, "handle": handle,
                    "native_id": native_id,
                    "deadline": deadline, "unknown": False, "cancel_requested": False,
                    "proving": False, "next": 0, "expired": False}
            channel.send({"event": "ack", "attempt": attempt})
            # Recheck on the owner thread after waiting behind other public
            # clients. Host monotonic time is shared across these local processes.
            code = ("import time as _n5_time\n"
                    f"if _n5_time.monotonic() >= {deadline!r}:\n"
                    "    raise TimeoutError('total deadline expired before owner execution')\n# nexus owner deadline checked\n" + code)
            code = guarded_source(code, dict(self.metadata_contexts.get(lease['lease_id'], {}),
                method=method, operation_id=native_id, lease=lease))
            public_started[0] = True
            result = handle.execute_python(code, timeout=None, operation_id=native_id)
            if method in SLICE_METHODS and result["result"].get("more") is True:
                channel.send({"event": "yielded", "attempt": attempt,
                              "checkpoint": result["result"]["checkpoint"]})
            else:
                channel.send({"event": "completed", "attempt": attempt, "result": result})
        elif kind == "cancel":
            public_started[0] = True
            operation_id = command["identity"]["operation_id"]
            with self.lock:
                native_id = self.executing.get(operation_id, {}).get("native_id", operation_id)
            outcome = handle.cancel_operation_outcome(native_id)
            with self.lock:
                record = self.executing.get(operation_id)
                if record is not None:
                    record["cancel_requested"] = True
                    if outcome["execution_stopped"]:
                        record["stop_proof"] = outcome
            channel.send({"event": "cancel_ack", "attempt": attempt,
                          "accepted": outcome["status"] == "cancelled", "outcome": outcome})
            self.proof_wakeup.set()
        elif kind == "release":
            public_started[0] = True
            context = [self.identity, lease["lease_id"], lease["instance_id"], lease["generation"], self.lifetime_path]
            cleanup_code = ("import sys\nmodule = sys.modules.get('_ida_cli_nexus_slices_v1')\n"
                            f"result = module.release_lease({context!r}) if module else None")
            cleanup_code = guarded_source(cleanup_code,
                dict(self.metadata_contexts.get(lease['lease_id'], {}), method='close',
                     operation_id=command.get('identity', {}).get('operation_id',
                         'release:' + str(attempt['sequence'])), lease=lease), refuse=False)
            guard_error = None
            if handle.connected:
                checked = handle.execute_python(cleanup_code, timeout=max(0.001, deadline - time.monotonic()))
                guard_error = checked['result']['save_guard_error']
            else:
                # This lease cannot execute again. A new public lease can only
                # reclaim our references on the exact surviving instance.
                instances = [item.instance for item in discover_databases()
                             if item.instance.record_id == lease["instance_id"]]
                if instances:
                    with self.lock:
                        cleanup_handle = self.cleanup_handles.get(lease['lease_id'])
                    if cleanup_handle is None:
                        cleanup_handle = self.Handle.attach(instances[0])
                    # Keep the exact auxiliary lease if its guard cannot arm.
                    with self.lock:
                        self.cleanup_handles[lease['lease_id']] = cleanup_handle
                    checked = cleanup_handle.execute_python(cleanup_code,
                        timeout=max(0.001, deadline - time.monotonic()))
                    guard_error = checked['result']['save_guard_error']
                    cleanup_handle.close(wait_for_database=False)
                    with self.lock:
                        self.cleanup_handles.pop(lease['lease_id'], None)
                else:
                    from ida_nexus import wait_database_released
                    if not wait_database_released(handle.instance,
                            timeout=max(0, deadline - time.monotonic())):
                        raise RuntimeError('save protection unavailable; exact lease retained; no default close')
            def publish(name, outcome):
                channel.send({"event": name, "attempt": attempt, "outcome": outcome,
                              "error": error("cancel_pending", "lease release unconfirmed; owner retained")})
            outcome = release_handle(handle, deadline, publish)
            if outcome is None:
                return
            self.drop_lifetime(lease["lease_id"])
            with self.lock:
                self.handles.pop(lease["lease_id"], None)
                self.metadata_contexts.pop(lease["lease_id"], None)
            channel.send({"event": "released", "attempt": attempt, "outcome": outcome,
                          "save_guard_error": guard_error})
        elif kind == "shutdown":
            public_started[0] = True
            handle.execute_python(guarded_source('pass',
                dict(self.metadata_contexts.get(lease['lease_id'], {}),
                     method='shutdown', lease=lease), refuse=command['save']),
                timeout=max(0.001, deadline - time.monotonic()))
            handle.shutdown_database(save=command["save"])
            channel.send({"event": "shutdown_completed", "attempt": attempt})

    def mark_unknown(self, operation_id, attempt):
        with self.lock:
            record = self.executing.get(operation_id)
            # A response/disconnect callback belongs to one physical delivery.
            if record is None or record["attempt"] != attempt:
                return
            self.unknown[operation_id] = attempt
            record["unknown"] = True
        # Also handles a cancel ACK received before the execution stream failed.
        self.proof_wakeup.set()

    def proofs(self):
        while not self.stopped.is_set():
            self.proof_wakeup.wait(0.02)
            self.proof_wakeup.clear()
            expired = []
            proven = []
            with self.lock:
                for operation_id, record in self.executing.items():
                    if not record["unknown"] or not record["cancel_requested"] or record["proving"]:
                        continue
                    # A deadline limits new public probes, never consumption of
                    # authoritative evidence already acquired on another path.
                    if record.get("stop_proof"):
                        record["proving"] = True
                        proven.append((operation_id, record, record["stop_proof"]))
                    elif record["expired"]:
                        continue
                    elif time.monotonic() >= record["deadline"]:
                        record["expired"] = True
                        expired.append(record["attempt"])
                    elif time.monotonic() >= record["next"] and self.proof_gate.acquire(blocking=False):
                        record["proving"] = True
                        self.proof_pool.submit(self.confirm_stop, operation_id, record)
            for operation_id, record, outcome in proven:
                self.publish_stop(operation_id, record, outcome)
            for attempt in expired:
                self.control.send({"event": "stop_unconfirmed", "attempt": attempt,
                                   "error": error("cancel_pending", "stop proof deadline expired; outcome remains unknown")})

    def publish_stop(self, operation_id, record, outcome):
        self.control.send({"event": "stopped", "attempt": record["attempt"],
                           "proof": "causal_cancel_not_pending", "outcome": outcome})
        with self.lock:
            if self.unknown.get(operation_id) == record["attempt"]:
                self.unknown.pop(operation_id, None)
            if self.executing.get(operation_id) is record:
                self.executing.pop(operation_id, None)

    def confirm_stop(self, operation_id, record):
        try:
            outcome = record.get("stop_proof") or record["handle"].cancel_operation_outcome(record.get("native_id", operation_id))
            if outcome["execution_stopped"]:
                self.publish_stop(operation_id, record, outcome)
            elif outcome["status"] == "failed":
                self.control.send({"event": "stop_unconfirmed", "attempt": record["attempt"],
                    "error": error("cancel_pending", outcome["failure"])})
        except Exception as exc:
            self.control.send({"event": "stop_unconfirmed", "attempt": record["attempt"],
                               "error": error("cancel_pending", type(exc).__name__)})
        finally:
            with self.lock:
                record["proving"] = False
                record["next"] = time.monotonic() + 0.02
                # Rotate retryable records so a failed proof cannot monopolize
                # the two reserved slots while other unknowns wait.
                if self.executing.get(operation_id) is record:
                    self.executing.pop(operation_id)
                    self.executing[operation_id] = record
            self.proof_gate.release()

    def close(self):
        self.stopped.set()
        self.proof_wakeup.set()
        with self.lock:
            handles = list(self.handles.values())
            verifications = list(self.verification_probes.items())
            auxiliary = list(self.cleanup_handles.items())
            operations = list(self.executing.items())
        self.lifetime_socket.close()
        # R-sock: unlink only our own socket, never a replacement at that path.
        try:
            if Path(self.lifetime_path).lstat().st_ino == self.lifetime_inode:
                Path(self.lifetime_path).unlink()
        except FileNotFoundError:
            pass  # Parent may already have removed this exact owned endpoint.
        for lease, _handle in handles:
            self.drop_lifetime(lease["lease_id"])
        for operation_id, record in operations:
            try:
                record["handle"].cancel_operation_outcome(record.get("native_id", operation_id))
            except Exception as exc:
                print(f"cancel during cleanup failed: {type(exc).__name__}", file=sys.stderr)
        for key, handle in auxiliary:
            try:
                handle.execute_python(guarded_source('pass', {'method': 'auxiliary-close'},
                    refuse=False), timeout=5)
                handle.close(wait_for_database=True, timeout=5)
                with self.lock:
                    self.cleanup_handles.pop(key, None)
            except Exception as exc:
                print(f'auxiliary lease retained; no default close: {type(exc).__name__}: {exc}', file=sys.stderr)
        for _lease, handle in handles:
            try:
                if handle.connected:
                    handle.execute_python(guarded_source('pass',
                        dict(self.metadata_contexts.get(_lease['lease_id'], {}),
                             method='bridge-close', lease=_lease), refuse=False), timeout=5)
                else:
                    require_safe_close(handle, time.monotonic() + 5)
                handle.close(wait_for_database=True, timeout=5)
            except Exception as exc:
                print(f"lease cleanup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        for path, handle in verifications:
            if handle is None:
                print(f"verification startup unconfirmed; staging retained: {path}", file=sys.stderr)
                continue
            try:
                self.close_verification(path, handle, time.monotonic() + 5)
            except Exception as exc:
                print(f"verification cleanup unconfirmed; staging retained: {path}: {type(exc).__name__}", file=sys.stderr)
        for channel in (self.business, self.control):
            channel.socket.close()
        for pool in (self.business_pool, self.cancel_pool, self.release_pool, self.proof_pool):
            pool.shutdown(wait=False, cancel_futures=True)


def main():
    ready = readiness()
    print(json.dumps(ready), flush=True)
    if not ready["ready"]:
        return 1
    bridge = Bridge(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    def parent_lifetime():
        sys.stdin.buffer.read()
        bridge.stopped.set()
    threading.Thread(target=parent_lifetime, daemon=True).start()
    try:
        bridge.stopped.wait()
    finally:
        bridge.close()
    return 0


if __name__ == "__main__":
    os._exit(main())
