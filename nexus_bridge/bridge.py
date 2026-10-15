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

HANDLE_SHA = "5d60799c1ac7fe6728a5e95ca2b91e421e172bba059a0ff846d6a37fd0819b05"
METHODS = {"execute_python": "may_write", "database_info": "read_only",
           "rename_address": "may_write", "read_name": "read_only"}


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
            raise ValueError("Nexus client cancellation patch missing or incompatible handle.py")
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
                self.socket.sendall(json.dumps(message, ensure_ascii=False).encode() + b"\n")
        except (OSError, ValueError):
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
        self.business = Channel(business, capacity, self.receive, self.stopped)
        self.control = Channel(control, 8, self.receive, self.stopped)
        self.initialized.set()
        threading.Thread(target=self.discover, daemon=True).start()
        threading.Thread(target=self.proofs, daemon=True).start()

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
            holder[1].append(message)
            holder[0].set()
            return
        if "local_status" in message:
            with self.lock:
                held = [{"lease": item[0], "connected": item[1].connected,
                         "pid": item[1].instance.pid, "idb_path": item[1].instance.idb_path}
                        for item in self.handles.values()]
                owners = list(self.owners)
            channel.send({"event": "local_status", "id": message["local_status"],
                          "held": held, "owners": owners})
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
            grant = holder[1][0]
            if grant["grant"] is False:
                return
            payload = frame["payload"]
            budget = grant["remaining_ms"] / 1000
            deadline = time.monotonic() + budget
            self.invoke(channel, attempt, payload, deadline, public_started)
        except Exception as exc:
            from ida_nexus import NexusConnectionError, RemoteError
            if isinstance(exc, RemoteError):
                channel.send({"event": "remote_error", "attempt": attempt, "remote_code": exc.code,
                              "error": error("operation_failed", str(exc))})
            elif isinstance(exc, NexusConnectionError):
                if frame["payload"]["command"] == "execute":
                    self.mark_unknown(frame["payload"]["identity"]["operation_id"], attempt)
                channel.send({"event": "uncertain", "attempt": attempt,
                              "error": error("disconnected", str(exc))})
            else:
                uncertain = public_started[0]
                if uncertain and frame["payload"]["command"] == "execute":
                    self.mark_unknown(frame["payload"]["identity"]["operation_id"], attempt)
                channel.send({"event": "uncertain" if uncertain else "failed", "attempt": attempt,
                              "error": error("operation_failed", f"{type(exc).__name__}: {exc}")})
        finally:
            with self.lock:
                self.grants.pop(key, None)
                if frame["payload"]["command"] == "execute":
                    operation_id = frame["payload"]["identity"]["operation_id"]
                    if operation_id not in self.unknown:
                        self.executing.pop(operation_id, None)
            gate.release()

    def disconnected(self, lease, reason, attempt):
        # The callback may be replayed synchronously by set_disconnect_callback,
        # before N1 knows this lease. Keep its bounded open correlation intact.
        self.control.send({"event": "disconnected", "lease": lease, "reason": reason,
                           "attempt": attempt})

    def invoke(self, channel, attempt, command, deadline, public_started):
        from ida_nexus import discover_databases
        kind = command["command"]
        if kind == "open":
            options = dict(command["options"])
            attach = options.pop("attach_instance", None)
            options["startup_timeout"] = max(0.001, deadline - time.monotonic())
            options["worker_env"] = dict(os.environ)
            options["worker_cwd"] = os.environ["IDA_CLI_HOME"]
            if attach:
                instances = [x.instance for x in discover_databases() if x.instance.record_id == attach]
                if len(instances) != 1:
                    raise ValueError("attach instance is not available")
                public_started[0] = True
                handle = self.Handle.attach(instances[0], idle_timeout=options.get("idle_timeout"))
            else:
                public_started[0] = True
                handle = self.Handle.open(command["path"], options=self.Options(**options))
            instance = handle.instance
            with self.lock:
                generation = self.generations.setdefault(instance.record_id, 1)
                lease = {"client_id": command["identity"]["client_id"], "lease_id": uuid.uuid4().hex,
                         "instance_id": instance.record_id, "generation": generation,
                         "owner": "gui" if instance.backend == "gui" else "managed"}
                self.handles[lease["lease_id"]] = (lease, handle)
            # Verify actual owner runtime without importing IDA in this process.
            try:
                handle.set_disconnect_callback(lambda _handle, reason: self.disconnected(lease, reason, attempt))
                actual = handle.execute_python("import ida_kernwin\nresult = ida_kernwin.get_kernel_version()", timeout=None)
            except Exception as exc:
                handle.close(wait_for_database=True, timeout=5)
                with self.lock:
                    self.handles.pop(lease["lease_id"], None)
                # Close confirmed this unannounced lease is gone. If close
                # itself fails, run() retains the uncertain open outcome.
                channel.send({"event": "failed", "attempt": attempt,
                              "error": error("disconnected", f"open runtime check failed: {type(exc).__name__}")})
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
            else:
                raise ValueError("unsupported bridge method")
            operation_id = command["identity"]["operation_id"]
            with self.lock:
                self.executing[operation_id] = {"attempt": attempt, "handle": handle,
                    "deadline": deadline, "unknown": False, "cancel_requested": False,
                    "proving": False, "next": 0, "expired": False}
            channel.send({"event": "ack", "attempt": attempt})
            public_started[0] = True
            result = handle.execute_python(code, timeout=None, operation_id=command["identity"]["operation_id"])
            channel.send({"event": "completed", "attempt": attempt, "result": result})
        elif kind == "cancel":
            public_started[0] = True
            operation_id = command["identity"]["operation_id"]
            outcome = handle.cancel_operation_outcome(operation_id)
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
            handle.close(wait_for_database=True, timeout=max(0.001, deadline - time.monotonic()))
            with self.lock:
                self.handles.pop(lease["lease_id"], None)
            channel.send({"event": "released", "attempt": attempt})
        elif kind == "shutdown":
            public_started[0] = True
            handle.shutdown_database(save=command["save"])
            channel.send({"event": "shutdown_completed", "attempt": attempt})

    def mark_unknown(self, operation_id, attempt):
        with self.lock:
            self.unknown[operation_id] = attempt
            record = self.executing.get(operation_id)
            if record is not None:
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
            self.unknown.pop(operation_id, None)
            self.executing.pop(operation_id, None)

    def confirm_stop(self, operation_id, record):
        try:
            outcome = record.get("stop_proof") or record["handle"].cancel_operation_outcome(operation_id)
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
                if operation_id in self.executing:
                    self.executing.pop(operation_id)
                    self.executing[operation_id] = record
            self.proof_gate.release()

    def close(self):
        self.stopped.set()
        self.proof_wakeup.set()
        with self.lock:
            handles = list(self.handles.values())
            operations = list(self.executing.items())
        for operation_id, record in operations:
            try:
                record["handle"].cancel_operation_outcome(operation_id)
            except Exception as exc:
                print(f"cancel during cleanup failed: {type(exc).__name__}", file=sys.stderr)
        for _lease, handle in handles:
            try:
                handle.close(wait_for_database=True, timeout=5)
            except Exception as exc:
                print(f"lease cleanup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
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
