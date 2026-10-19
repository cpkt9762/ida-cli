"""Controlled HTTP/SSE input boundary; SDK, resolver and owner guard stay real.

This is an OS/IDA model, not a Nexus server implementation or real IDA evidence.
Only the test's native registry and loopback sockets are used.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import sys
import threading
import time
from types import ModuleType
from urllib.parse import parse_qs, urlsplit

from ida_nexus._registry import InstanceIdentity, InstanceRegistration, REGISTRY_DIR


def install_ida_inputs(path):
    """Only native IDA inputs are modeled; production save_guard runs verbatim."""
    def module(name, **values):
        result = ModuleType(name)
        vars(result).update(values)
        sys.modules[name] = result
        return result
    flags = set()
    module("ida_auto", auto_is_ok=lambda:True, get_auto_state=lambda:0)
    module("ida_funcs")
    module("ida_idaapi", BADADDR=0xFFFFFFFFFFFFFFFF)
    module("idautils")
    module("idc")
    module("ida_kernwin", get_kernel_version=lambda: "9.5")
    module("ida_netnode", netnode=type("Netnode", (), {"exist": staticmethod(lambda _: True)}))
    module("ida_nalt", get_input_file_path=lambda: str(path), retrieve_input_file_size=lambda: 1,
           retrieve_input_file_md5=lambda: b"m" * 16, retrieve_input_file_sha256=lambda: b"s" * 32)
    module("ida_loader", DBFL_TEMP=1, DBFL_KILL=2, DBFL_COMP=4, DBFL_BAK=8,
           PATH_TYPE_CMD=0, PATH_TYPE_IDB=1, PATH_TYPE_ID0=2,
           get_path=lambda _: str(path), is_database_flag=lambda flag: flag in flags,
           set_database_flag=flags.add)
    module("ida_ida", inf_pack_idb=lambda: True, inf_compress_idb=lambda: False, inf_get_lflags=lambda: 0)
    module("ida_idp", IDB_Hooks=type("Hooks", (), {"hook": lambda _: True}))


class Boundary:
    def __init__(self, root, scenario="healthy", *, stub_ida=True):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "tiny.i64"
        self.path.write_bytes(b"R0 external database-state input")
        self.scenario = scenario
        self.requests = []
        self.transitions = []
        self.leases = set()
        self.analysis_failed = False
        self.streams = {}
        self.lock = threading.RLock()
        self.executing = threading.Lock()
        self.stopped = threading.Event()
        self.registration = InstanceRegistration(REGISTRY_DIR,
            InstanceIdentity(str(self.path), str(self.path), "idalib", True), token=secrets.token_hex(24))
        if stub_ida:
            install_ida_inputs(self.path)
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def reply(self, payload, status=200):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                parts = urlsplit(self.path)
                if parts.path != "/health":
                    self.reply({"complete": True})
                    return
                query = parse_qs(parts.query)
                if "sse" not in query:
                    self.reply({"status": "ok", **owner.instance.health_identity()})
                    return
                if owner.scenario == "reject":
                    owner.requests.append({"endpoint":"lease_rejected", "http_status":503})
                    self.reply({"error": "closing"}, 503)
                    return
                lease = query["lease_id"][0]
                with owner.lock:
                    before = sorted(owner.leases)
                    owner.leases.add(lease)
                    owner.transitions.append({'edge':'attach','call':'GET /health?sse',
                        'lease':lease,'before':before,'after':sorted(owner.leases)})
                    owner.streams[lease] = self.connection
                    owner.requests.append({"endpoint": "lease", "lease": lease})
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b": acquired\n\n")
                self.wfile.flush()
                # Real readline in the SDK blocks until its own transport closes.
                try:
                    self.connection.recv(1)
                except OSError:
                    pass
                finally:
                    with owner.lock:
                        owner.streams.pop(lease, None)
                self.close_connection = True

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with owner.lock:
                    owner.requests.append({"endpoint": self.path, **payload})
                if self.path == "/release_lease":
                    with owner.lock:
                        before = sorted(owner.leases)
                        owner.leases.discard(payload["lease_id"])
                        last = not owner.leases and owner.instance.backend != 'gui'
                        owner.transitions.append({'edge':'detach','call':'POST /release_lease',
                            'lease':payload['lease_id'],'before':before,'after':sorted(owner.leases),
                            'ack_kind':'last' if last else 'nonlast',
                            'owner_backend':owner.instance.backend,
                            'ack_delivery':'lost' if owner.scenario in ('lost-ack','early-analysis') else 'parsed'})
                    (owner.root / "release-requested").touch()
                    if owner.scenario in ("lost-ack", "early-analysis"):
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.close_connection = True
                        return
                    self.reply({"ok": True, "result": {"released": True, "shutdown_pending": last}})
                elif self.path == "/execute_python":
                    if owner.analysis_failed:
                        self.reply({"ok": False, "error": {"code":"execution_error", "message":"controlled post-analysis cleanup failure"}})
                        return
                    with owner.executing:
                        namespace = {"__name__": "__r0_external_owner__"}
                        try:
                            exec(compile(payload["code"], "<controlled IDA input>", "exec"), namespace)
                            result = namespace.get("result")
                        except Exception as exc:
                            self.reply({"ok": False, "error": {"code": "execution_error", "message": str(exc)}})
                        else:
                            self.reply({"ok": True, "result": {"result": result, "stdout": "", "stderr": ""}})
                elif self.path == "/wait_autoanalysis" and owner.scenario == "early-analysis":
                    owner.analysis_failed = True
                    self.reply({"ok": False, "error": {"code": "operation_timeout", "message": "controlled analysis failure"}})
                else:
                    self.reply({"ok": True, "result": {"complete": True, "cancelled": False}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.instance = self.registration.publish(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.released = False

    def release_owner(self):
        if not self.released:
            self.registration.release()
            self.released = True

    def close(self):
        self.release_owner()
        with self.lock:
            for stream in tuple(self.streams.values()):
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        if self.thread.is_alive():
            raise RuntimeError("owned HTTP input thread did not stop")
        (self.root / "requests.json").write_text(json.dumps(self.requests, indent=2))

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def barrier(root, name, seconds=20):
    (root / (name + ".arrived")).touch()
    deadline = time.monotonic() + seconds
    while not (root / (name + ".release")).exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("owned transport barrier: " + name)
        threading.Event().wait(.005)
