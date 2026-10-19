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

if '__verified_source__' not in globals():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(0, str(Path(__file__).resolve().parent / "custody"))


def module_source(name, *, custody=False):
    if '__verified_source__' in globals():
        return sys._ida_cli_verified_sources[name]
    path = Path(__file__).parent / ('custody' if custody else '') / name
    return path.read_text(encoding='utf-8')
from tools import METHODS as TOOL_METHODS
from type_tools import TYPE_METHODS
from edit_tools import EDIT_METHODS, WRITE_METHODS
from analysis_tools import ANALYSIS_METHODS
from struct_tools import STRUCT_METHODS
from query_tools import QUERY_METHODS
from search_tools import SEARCH_METHODS
from lifecycle import database_diagnostics, release_handle, release_errors, release_state
from metadata import idb_context
from open_recovery import open_checked
from config import ida_cli_home, startup_paths
from protocol import admission, verify_client
from lifetime import LifetimeListener
from acquisition import Custodian, failure_details
from owner_release import FairReleases, ordinary_release
from bridge_observer import BackupSources, INCARNATION as OBSERVER_INCARNATION

GUARD_SOURCE = module_source('save_guard.py')
OWNER_MODULES_SOURCE = module_source('owner_modules.py')
OWNER_SOURCES = dict(zip(('_ida_cli_save_guard_v1', '_ida_cli_release_protocol_v1',
    '_ida_cli_nexus_slices_v1'), (module_source(name) for name in
    ('save_guard.py', 'lifecycle.py', 'slices.py'))))


def guarded_source(code, context, refuse=True):
    """Install once per owner, then sample within the same native operation."""
    setup = ("import sys as _r9_sys, types as _r9_types\n"
             "_r9_policy = {}\n"
             f"exec({OWNER_MODULES_SOURCE!r}, _r9_policy)\n"
             f"_r9_module_kind = _r9_policy['classify']({OWNER_SOURCES!r}, cleanup={not refuse!r})\n"
             "if '_ida_cli_save_guard_v1' not in _r9_sys.modules:\n"
             "    _r9_module = _r9_types.ModuleType('_ida_cli_save_guard_v1')\n"
             f"    exec({GUARD_SOURCE!r}, _r9_module.__dict__)\n"
             "    _r9_sys.modules['_ida_cli_save_guard_v1'] = _r9_module\n"
             "_r9_guard = _r9_sys.modules['_ida_cli_save_guard_v1']\n"
             "if _r9_module_kind == 'current':\n"
             f"    _r9_guard.begin({context!r}, refuse={refuse!r})\n")
    finish = f"_r9_guard.finish({context!r}, refuse={refuse!r})"
    if refuse:
        # A separate compilation preserves module-level future imports in raw
        # execute_python code; a try-indented source would reject them.
        return setup + f"try:\n    exec(compile({code!r}, '<ida-cli owner>', 'exec'), globals())\nfinally:\n    " + finish
    current = code + '\nresult = {"save_guard_error": ' + finish + '}\n'
    return (setup + "if _r9_module_kind == 'known_v1_cleanup_only':\n"
            "    result = _r9_guard.close_status()\nelse:\n"
            + '\n'.join('    '+line for line in current.splitlines()) + '\n')

TOOL_METHODS = (*TOOL_METHODS, *TYPE_METHODS, *EDIT_METHODS, *ANALYSIS_METHODS, *STRUCT_METHODS, *QUERY_METHODS, *SEARCH_METHODS, "batch_rename")

METHODS = {"execute_python": "may_write", "database_info": "read_only",
           "rename_address": "may_write", "read_name": "read_only"}
METHODS.update({method: "may_write" if method in WRITE_METHODS else "read_only"
                for method in TOOL_METHODS})
TOOL_SOURCE = "\n".join(module_source(name)
                        for name in ("type_tools.py", "edit_tools.py", "analysis_tools.py", "struct_tools.py", "query_tools.py", "search_tools.py", "tools.py"))
# Both ordinary and sliced execution use this checked installation. The source
# is evaluated anew by the current owner for each request, including reconnects.
METADATA_SOURCE = module_source("metadata.py")
TOOL_SOURCE += ("\n_tools_metadata = {}\n"
                + f"exec({METADATA_SOURCE!r}, _tools_metadata)\n"
                + "install_tools(_tools_metadata)\n")
RELEASE_SOURCE = module_source('lifecycle.py')
SLICE_GATE_SOURCES = {name: module_source(name + '.py', custody=True) for name in (
    'target_coordination', 'custody_process_identity', 'origin', 'owner_identity', 'target_journal',
    'durable_records', 'recovery_files', 'recovery_resources', 'recovery_transaction','recovery_legacy')}
SLICE_SOURCE = ("import sys, types\n"
    + f"_target_gate_sources = {SLICE_GATE_SOURCES!r}\n"
    "if '_ida_cli_release_protocol_v1' not in sys.modules:\n"
    "    _release_module = types.ModuleType('_ida_cli_release_protocol_v1')\n"
    f"    exec({RELEASE_SOURCE!r}, _release_module.__dict__)\n"
    "    sys.modules['_ida_cli_release_protocol_v1'] = _release_module\n"
    + module_source("slices.py"))
SLICE_METHODS = {"batch_decompile", "search_pseudocode", "run_auto_analysis", "batch_rename", "_n5_cleanup"}


def error(code, message):
    return {"code": code, "message": str(message)}


def readiness():
    try:
        paths = startup_paths()
        protocol = admission()
        sdk_modules = verify_client()
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
        "methods": METHODS}, "client_cancel_patch": True, "client_sdk_modules": sdk_modules, "protocol": protocol, "paths": paths, "custody_protocol": 1,
        "observer_incarnation":OBSERVER_INCARNATION}


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
        self.custody_acks = set()
        self.ack_condition = threading.Condition()
        self.handler = handler
        self.stopped = stopped
        self.writer = threading.Thread(target=self.write, daemon=True)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.writer.start()
        self.reader.start()

    def send(self, message):
        # A retained receipt can be retransmitted while Rust waits on target
        # EX. Keep one identical ACK queued/in flight so duplicate ACKs cannot
        # block this channel's reader from accepting the custody RPC reply.
        # Tracking is bounded by the output queue plus its current write.
        key = self.custody_ack_key(message)
        if key is not None:
            with self.ack_condition:
                while key not in self.custody_acks and len(self.custody_acks) >= self.output.maxsize + 1:
                    self.ack_condition.wait()
                if key in self.custody_acks:
                    return
                self.custody_acks.add(key)
        self.output.put(message)

    @staticmethod
    def custody_ack_key(message):
        if message.get('event') in ('custody_retired_ack', 'owner_proof_ack'):
            return json.dumps(message, sort_keys=True, allow_nan=False)
        return None

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
                try:
                    self.socket.sendall(encoded + b"\n")
                finally:
                    key = self.custody_ack_key(message)
                    if key is not None:
                        with self.ack_condition:
                            self.custody_acks.discard(key)
                            self.ack_condition.notify_all()
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


class Bridge(LifetimeListener):
    def __init__(self, business, control, capacity):
        startup_paths()
        from ida_nexus import DatabaseHandle, DatabaseOpenOptions
        self.Handle = DatabaseHandle
        self.Options = DatabaseOpenOptions
        self.lock = threading.Lock()
        self.handles = {}
        self.metadata_contexts = {}
        self.identity = uuid.uuid4().hex
        self.verification_probes = {}
        self.verification_cleanup_pending = set()
        self.cleanup_handles = {}
        self.cleanup_requests = set()
        self.grants = {}
        self.custody_requests = {}
        self.custodians = {}
        self.acquisitions = {}
        self.backup_sources = BackupSources(self, capacity)
        self.helper_configuration = None
        self.helper_ready = threading.Event()
        self.generations = {}
        self.unknown = {}
        self.executing = {}
        self.proof_wakeup = threading.Event()
        self.initialized = threading.Event()
        self.stopped = threading.Event()
        self.business_pool = concurrent.futures.ThreadPoolExecutor(4, thread_name_prefix="nexus-business")
        self.cancel_pool = concurrent.futures.ThreadPoolExecutor(2, thread_name_prefix="nexus-cancel")
        self.release_pool = concurrent.futures.ThreadPoolExecutor(2, thread_name_prefix="nexus-release")
        self.proof_pool = concurrent.futures.ThreadPoolExecutor(2, thread_name_prefix="nexus-proof")
        self.preflight_pool = concurrent.futures.ThreadPoolExecutor(2, thread_name_prefix="nexus-preflight")
        self.detach_pool = concurrent.futures.ThreadPoolExecutor(2, thread_name_prefix="nexus-detach")
        self.release_scheduler = FairReleases(self.preflight_pool)
        self.cancel_scheduler = FairReleases(self.cancel_pool)
        self.release_gate = threading.BoundedSemaphore(8)
        self.proof_gate = threading.BoundedSemaphore(2)
        self.business_gate = threading.BoundedSemaphore(capacity)
        self.control_gate = threading.BoundedSemaphore(8)
        self.owners = []
        # Adapter-owned lifetime lane, never a Nexus wire protocol. Owner-side
        # watchers use only public Nexus APIs to release our jobs after EOF.
        self.lifetime_path = str(Path(business).with_name("l"))
        self.init_lifetimes(capacity)
        threading.Thread(target=self.accept_lifetimes, daemon=True).start()
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
        if 'resource_retired' in message:
            receipt = message['resource_retired']
            evidence = receipt['evidence']
            if (evidence.get('scope') != 'host_boot_change'
                    or evidence.get('evidence_type') != 'verified_boot_change_resource_retirement'
                    or evidence.get('lease') != receipt.get('lease')
                    or evidence.get('watch') != receipt['watch']
                    or evidence.get('acquisition') != receipt['acquisition']):
                raise ValueError('ProtocolMismatch: boot resource projection')
            lease = receipt.get('lease')
            retired_verification = None
            with self.lock:
                if lease:
                    custody = self.custodians.get(lease['lease_id'])
                    if custody is not None:
                        if custody.lease != lease or custody.acquisition != receipt['acquisition']:
                            raise ValueError('ProtocolMismatch: retired physical resource')
                        self.custodians.pop(lease['lease_id'])
                        custody.retired = True
                        if getattr(custody, 'verification_path', None):
                            custody.verification_retired = True
                            retired_verification = custody
                    self.handles.pop(lease['lease_id'], None)
                    self.metadata_contexts.pop(lease['lease_id'], None)
            if lease:
                self.drop_lifetime(lease['lease_id'])
            self.backup_sources.retire(receipt['watch'])
            with self.lock:
                parent = receipt['acquisition']['parent']['operation_id']
                custody = self.acquisitions.get(parent)
                if custody is not None and custody.acquisition == receipt['acquisition']:
                    from target_coordination import digest
                    if evidence.get('owner'):
                        custody.originals.pop(digest(evidence['owner']), None)
                    custody.observations.pop(receipt['watch'], None)
                    for suffix, launch in list(custody.launches.items()):
                        if launch['watch'] == receipt['watch']:
                            custody.launches.pop(suffix)
                    if not custody.running and not custody.originals and not custody.launches and custody.recovery_snapshot is None:
                        self.acquisitions.pop(parent)
            if retired_verification is not None and not retired_verification.running:
                self.schedule_verification_cleanup(retired_verification)
            return
        if 'owner_backup_query' in message:
            self.backup_sources.query(message['owner_backup_query'])
            return
        if 'owner_proof_custody' in message:
            receipt = message['owner_proof_custody']
            owner = receipt['owner']
            proof = receipt['proof']['record']
            if proof['owner'] != owner or proof['evidence_type'] != 'public_owner_lifetime':
                raise ValueError('ProtocolMismatch: owner proof custody')
            closed = self.backup_sources.close(receipt)
            with self.lock:
                for custody in dict.fromkeys([*self.acquisitions.values(), *self.custodians.values()]):
                    observation = custody.observations.get(receipt['watch'])
                    if observation is not None:
                        if (observation['owner'] != owner
                                or proof['acquisition'] != custody.acquisition):
                            raise ValueError('ProtocolMismatch: closed acquisition observation')
                        observation['proof'] = receipt['proof']
            self.control.send({'event':'owner_proof_ack', 'owner':owner, 'watch':receipt['watch'],
                               'sha256':receipt['proof']['sha256'], 'consumer':closed})
            return
        if 'custody_retired' in message:
            receipt = message['custody_retired']
            if receipt.get('resource_retirement'):
                self.receive(channel, {'resource_retired':dict(receipt, evidence=receipt['resource_retirement'])})
            with self.lock:
                lease = receipt.get('lease')
                custody = self.custodians.get(lease['lease_id']) if lease else None
                if custody is not None:
                    if (custody.lease != receipt['lease'] or custody.watch != receipt['watch']
                            or custody.acquisition != receipt['acquisition']):
                        raise ValueError('ProtocolMismatch: retired custody identity')
                    self.custodians.pop(receipt['lease']['lease_id'])
                    custody.retired = True
                    held = self.handles.get(receipt['lease']['lease_id'])
                    if held is not None and held[0] == receipt['lease']:
                        self.handles.pop(receipt['lease']['lease_id'])
                        self.metadata_contexts.pop(receipt['lease']['lease_id'], None)
                    parent = custody.acquisition['parent']['operation_id']
                    if (self.acquisitions.get(parent) is custody and custody.acquisition == receipt['acquisition']
                            and not custody.originals and not custody.running and custody.recovery_snapshot is None
                            and not any(c.acquisition['parent'] == custody.acquisition['parent']
                                        for c in self.custodians.values())):
                        self.acquisitions.pop(parent)
                elif lease is None:
                    if receipt.get('acquisition_closed') is True:
                        for primary, child in list(self.cleanup_handles.items()):
                            if child.acquisition == receipt['acquisition'] and child.handle is None:
                                self.cleanup_handles.pop(primary)
                    parent = receipt['acquisition']['parent']['operation_id']
                    custody = self.acquisitions.get(parent)
                    if (custody is not None and custody.acquisition == receipt['acquisition']
                            and not custody.originals and (custody.handle is None or custody.retired) and not custody.running
                            and custody.recovery_snapshot is None):
                        self.acquisitions.pop(parent)
            self.control.send({'event':'custody_retired_ack', 'receipt':receipt})
            self.backup_sources.retire(receipt['watch'])
            if custody is not None and getattr(custody, 'verification_path', None):
                custody.verification_retired = True
                if not custody.running:
                    self.schedule_verification_cleanup(custody)
            return
        if 'helper_configuration' in message:
            if self.helper_configuration is not None and self.helper_configuration != message['helper_configuration']:
                raise ValueError('ProtocolMismatch: helper configuration changed')
            self.helper_configuration = message['helper_configuration']
            self.helper_ready.set()
            return
        if 'custody_reply' in message:
            with self.lock:
                pending = self.custody_requests.get(message['custody_reply'])
                if pending is not None:
                    pending[1].append(message)
                    pending[0].set()
            return
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
                         "pid": item[1].instance.pid, "idb_path": item[1].instance.idb_path,
                         "acquisition":self.custodians[item[0]['lease_id']].acquisition if item[0]['lease_id'] in self.custodians else None,
                         "responsibility":"InFlight" if release_state(item[1])['requested']
                            and not (release_state(item[1]).get('outcome') or {}).get('lease_released') else 'Owned'}
                        for item in self.handles.values()]
                owners = list(self.owners)
                verifications = list(self.verification_probes)
                verification_cleanup = [{'path':path, 'cause':getattr(c, 'verification_cleanup_error', None),
                    'owner_proof_consumed':getattr(c, 'verification_retired', False),
                    'next_action':'inspect_copy_occupancy_and_file_gate' if getattr(c, 'verification_cleanup_error', None)
                                  else 'wait_exact_owner_proof'} for path,c in self.verification_probes.items()]
                recovery_refs=[]
                for custody in self.acquisitions.values():
                    snapshot=(custody.recovery_snapshot[0] if custody.recovery_snapshot is not None
                              else getattr(custody,'file_snapshot',None))
                    if snapshot is not None and (custody.recovery_snapshot is not None
                            or snapshot.data['status'] not in ('restored','opened','archived')):
                        recovery_refs.append((custody.acquisition,snapshot,custody.recovery_error,custody.recovery_blocked))
            recoveries=[]
            for acquisition,snapshot,cause,blocked in recovery_refs:
                try:actual=snapshot.status()
                except Exception as error:
                    actual={'job_id':snapshot.recovery_id,'transaction':str(snapshot.path),
                            'status_error':type(error).__name__+': '+str(error)}
                recoveries.append(dict(actual,acquisition=acquisition,execution_error=cause,blocked=blocked,
                    next_action='inspect_retained_scene' if blocked else 'wait_exact_cleanup_then_restore'))
            channel.send({"event": "local_status", "id": message["local_status"],
                          "held": held, "owners": owners, "verification_probes": verifications,
                          "verification_cleanup":verification_cleanup,
                          "recovery_cleanup":recoveries,
                          "acquisitions":len(self.acquisitions), "custodians":len(self.custodians),
                          "original_instances":len(self.backup_sources.items),
                          "backup_closures":len(getattr(self.backup_sources, 'closed', {})),
                          "lifetime_listener_healthy": self.lifetime_healthy})
            return
        frame = message
        command = frame["payload"]["command"]
        control = command in {"cancel", "release", "shutdown"}
        if (channel is self.control) != control:
            raise ValueError("wrong physical lane")
        gate = self.release_gate if command == "release" else self.control_gate if control else self.business_gate
        if not gate.acquire(blocking=False):
            channel.send({"event": "not_sent", "attempt": frame["attempt"],
                          "error": error("busy", "bridge lane capacity exhausted")})
            return
        pool = self.cancel_pool if command == "cancel" else self.release_pool if control else self.business_pool
        if command == 'release':
            lease = frame['payload']['lease']
            self.release_scheduler.submit((lease['instance_id'], lease['generation']),
                lambda:self.run(channel, frame, gate))
        elif command == 'cancel':
            lease = frame['payload']['identity']['lease']
            self.cancel_scheduler.submit((lease['instance_id'], lease['generation']),
                lambda:self.run(channel, frame, gate))
        else:
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
            no_acquisition = False
            if frame['payload']['command'] == 'open':
                with self.lock:
                    custody = self.acquisitions.get(frame['payload']['identity']['operation_id'])
                if custody is not None and custody.handle is not None:
                    try:
                        custody.fail(exc)
                    except Exception as failure:
                        # A missing IPC ACK cannot authorize local detach or
                        # erase the same handle. Expose both independent errors.
                        channel.send({'event':'uncertain', 'attempt':attempt,
                            'error':error('unknown_outcome', f'{type(exc).__name__}: {exc}; custody failure: {failure}')})
                    return
                if custody is not None:
                    no_acquisition = custody.known_no_acquisition()
                    try:
                        custody.fail(exc)
                        no_acquisition = custody.known_no_acquisition()
                    except Exception as failure:
                        channel.send({'event':'uncertain', 'attempt':attempt,
                            'error':error('unknown_outcome', f'{type(exc).__name__}: {exc}; observation cleanup: {failure}')})
                        return
            if frame["payload"]["command"] == "open":
                command = frame["payload"]
                details['diagnostics'] = database_diagnostics(
                    command.get('options', {}).get('output_database') or command['path'])
                if custody is None and not public_started[0]:
                    channel.send({'event':'not_sent','attempt':attempt,
                        'error':failure_details(exc), **details})
                    return
            if frame["payload"]["command"] == "release":
                key = frame['payload']['lease']['lease_id']
                with self.lock:
                    primary = self.handles.get(key)
                    auxiliary = self.cleanup_handles.get(key)
                participants = ([primary[1]] if primary else []) + ([auxiliary.handle] if auxiliary and auxiliary.handle else [])
                messages = dict.fromkeys(message for member in participants for message in release_errors(member))
                details['save_guard_error'] = '; '.join(messages) or None
                if participants and not any(release_state(member)['requested'] for member in participants):
                    channel.send({'event':'not_sent', 'attempt':attempt,
                        'error':error('operation_failed', f'{type(exc).__name__}: {exc}'), **details})
                    return
            if isinstance(exc, RemoteError):
                channel.send({"event": "remote_error", "attempt": attempt, "remote_code": exc.code,
                              "error": error("operation_failed", str(exc)), **details})
            elif isinstance(exc, NexusConnectionError):
                if frame["payload"]["command"] == "execute":
                    self.mark_unknown(frame["payload"]["identity"]["operation_id"], attempt)
                channel.send({"event": "failed" if no_acquisition else "uncertain", "attempt": attempt,
                              "error": error("disconnected", str(exc)), **details})
            else:
                uncertain = public_started[0] and not no_acquisition
                if uncertain and frame["payload"]["command"] == "execute":
                    self.mark_unknown(frame["payload"]["identity"]["operation_id"], attempt)
                channel.send({"event": "uncertain" if uncertain else "failed", "attempt": attempt,
                              "error": error("operation_failed", f"{type(exc).__name__}: {exc}"), **details})
        finally:
            finished_verification = None
            with self.lock:
                self.grants.pop(key, None)
                if frame['payload']['command'] == 'open' and frame['payload']['identity'].get('operation_id') is not None:
                    parent = frame['payload']['identity']['operation_id']
                    custody = self.acquisitions.get(parent)
                    if custody is not None:
                        custody.running = False
                        if getattr(custody, 'verification_path', None) and custody.verification_retired:
                            finished_verification = custody
                        if ((custody.handle is None or getattr(custody, 'retired', False)) and not custody.originals
                                and not custody.launches and custody.recovery_snapshot is None):
                            self.acquisitions.pop(parent)
                if frame["payload"]["command"] == "execute":
                    operation_id = frame["payload"]["identity"]["operation_id"]
                    if (operation_id not in self.unknown
                            and self.executing.get(operation_id, {}).get("attempt") == attempt):
                        self.executing.pop(operation_id, None)
            try:
                if finished_verification is not None:
                    self.schedule_verification_cleanup(finished_verification)
            finally:
                gate.release()

    def disconnected(self, lease, reason, attempt):
        # The callback may be replayed synchronously by set_disconnect_callback,
        # before N1 knows this lease. Keep its bounded open correlation intact.
        self.drop_lifetime(lease["lease_id"])
        self.control.send({"event": "disconnected", "lease": lease, "reason": reason,
                           "attempt": attempt})

    def accept_cleanup(self, bridge_id, lease_id, *, reply=None):
        with self.lock:
            custody = self.custodians.get(lease_id)
            if bridge_id != self.identity or custody is None or self.stopped.is_set():
                raise ValueError('cleanup parent unavailable')
            duplicate = lease_id in self.cleanup_requests
            if not duplicate:
                if not self.release_gate.acquire(blocking=False):
                    raise RuntimeError('Busy: bounded auxiliary cleanup queue full')
                self.cleanup_requests.add(lease_id)
        if duplicate:
            if reply is not None:
                reply(True)
            return
        deadline = time.monotonic()+15
        def acquire_auxiliary():
            accepted = False
            try:
                # The second slot is reserved by N1 before the public attach;
                # no SDK/helper wait occupies the lifetime accept loop.
                custody.auxiliary(deadline)
                accepted = True
            except Exception as exc:
                try:
                    custody.transact('auxiliary_failed', acquisition=custody.acquisition,
                        lease=custody.lease, error=failure_details(exc))
                except Exception as delivery:
                    print(f'auxiliary cleanup result unconfirmed: {type(delivery).__name__}: {delivery}',file=sys.stderr)
            finally:
                if reply is not None:
                    try:
                        reply(accepted)
                    except Exception as exc:
                        print(f'auxiliary custody acknowledgement lost: {type(exc).__name__}',file=sys.stderr)
                with self.lock:
                    self.cleanup_requests.discard(lease_id)
                self.release_gate.release()
        try:
            self.release_scheduler.submit((custody.lease['instance_id'],custody.lease['generation']),acquire_auxiliary)
        except Exception:
            with self.lock:
                self.cleanup_requests.discard(lease_id)
            self.release_gate.release()
            raise

    def close_verification(self, path, custody, deadline):
        custody.cleanup()
        outcome = custody.release_for_retry(require_ack=False)
        from target_journal import ObservationPending
        while True:
            try:
                self.finish_verification_copy(path)
                break
            except ObservationPending:
                if time.monotonic() >= deadline or self.stopped.wait(.02):
                    raise TimeoutError('verification producer closure pending; copy retained')
        if outcome and outcome.get('save_guard_error'):
            raise RuntimeError(outcome['save_guard_error'])

    def finish_verification_copy(self, path):
        from owner_identity import state_identity
        from target_coordination import Target
        from target_journal import verification_probe_cleanup
        with self.lock:
            custody = self.verification_probes.get(path)
        acquisition = getattr(custody,'acquisition',None)
        if acquisition is None or not isinstance(acquisition.get('parent'),dict):
            raise RuntimeError('VerificationCleanupBlocked: exact copy custodian missing')
        parent = acquisition['parent']
        with Target(path) as target, target.locked(deadline=time.monotonic()+15):
            verification_probe_cleanup(target,state_identity(),parent)

        with self.lock:
            self.verification_probes.pop(path, None)

    def schedule_verification_cleanup(self, custody):
        path = custody.verification_path
        with self.lock:
            if path not in self.verification_probes or path in self.verification_cleanup_pending:
                return
            self.verification_cleanup_pending.add(path)
        def complete():
            try:
                self.finish_verification_copy(path)
            except Exception as exc:
                custody.verification_cleanup_error = type(exc).__name__ + ': ' + str(exc)
            finally:
                with self.lock:
                    self.verification_cleanup_pending.discard(path)
        self.release_scheduler.submit(('verification-copy', path), complete)

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
            options["worker_cwd"] = str(ida_cli_home())
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

            custodian = Custodian(self, attempt, command, deadline, track_open)
            with self.lock:
                self.acquisitions[command['identity']['operation_id']] = custodian
            if verification is not None:
                with self.lock:
                    self.verification_probes[verification] = custodian
                from target_coordination import Target
                from target_journal import verification_scope
                with Target(verification) as copy_target, copy_target.locked(deadline=deadline):
                    verification_scope(copy_target,custodian.acquisition['parent'])
                original = Path(command["path"])
                copy_hash = hashlib.sha256(Path(verification).read_bytes()).digest()
                if hashlib.sha256(original.read_bytes()).digest() != copy_hash:
                    raise ValueError("legacy cache changed during verification copy; refusing reuse")
                expected = hashlib.sha256(Path(snapshot).read_bytes()).hexdigest()
                public_started[0] = True
                probe, _, _ = open_checked(self.Handle, self.Options, str(verification),
                    {'auto_analysis': False, 'worker_env': dict(os.environ),
                     'worker_cwd': str(ida_cli_home())}, deadline, guarded_source,
                    dict(metadata_context, method='verification-open'), track_open, release_open,
                    lambda: public_started.__setitem__(0, True), custodian=custodian)
                with self.lock:
                    self.verification_probes[verification] = custodian
                verification_error = None
                try:
                    proof = custodian.execute('root', guarded_source(
                        "import ida_nalt\nsha = ida_nalt.retrieve_input_file_sha256()\nresult = sha.hex() if sha else None",
                        dict(metadata_context, method='verification-open', record_id=probe.instance.record_id)))["result"]
                except Exception as exc:
                    verification_error = exc
                    raise
                finally:
                    try:
                        self.close_verification(verification, custodian, deadline)
                    except Exception as cleanup_error:
                        if verification_error is not None:
                            raise RuntimeError('verification cleanup pending: ' + str(cleanup_error)) from verification_error
                        raise
                # A confirmed closed probe has no lease or operation left.
                # The following verification rejections are certain failures.
                public_started[0] = False
                if not isinstance(proof, str) or len(proof) != 64 or proof == "0" * 64:
                    raise ValueError("legacy cache input SHA256 is unavailable; refusing reuse without changing original")
                if proof != expected:
                    raise ValueError("legacy cache input SHA256 mismatch; refusing reuse without changing original")
                if hashlib.sha256(original.read_bytes()).digest() != copy_hash:
                    raise ValueError("legacy cache changed during Nexus verification; refusing reuse")
                custodian.next_acquisition()
                options["startup_timeout"] = max(0.001, deadline - time.monotonic())
            if attach:
                instances = [x.instance for x in discover_databases() if x.instance.record_id == attach]
                if len(instances) != 1:
                    raise ValueError("attach instance is not available")
                with custodian.gate(instances[0].idb_path):
                    public_started[0] = True
                    handle = custodian.obtain_attach(self.Handle, instances[0], options, metadata_context)
                check_context = dict(metadata_context, method='open', lease=lease_box[0])
                custodian.execute('guard', guarded_source('pass', check_context))
                custodian.execute('root', guarded_source('pass', check_context))
                actual = custodian.execute('runtime', guarded_source(
                    "import ida_kernwin\nresult = ida_kernwin.get_kernel_version()", check_context))
            else:
                handle, actual, _ = open_checked(self.Handle, self.Options, command['path'], options,
                    deadline, guarded_source, dict(metadata_context, method='open'),
                    track_open, release_open, lambda: public_started.__setitem__(0, True),
                    custodian=custodian)
            instance, lease = handle.instance, lease_box[0]
            if wait_analysis:
                custodian.rpc('analysis', lambda operation_id, timeout:
                    handle.wait_autoanalysis(timeout=timeout, operation_id=operation_id))
                custodian.execute('root', guarded_source('pass', dict(metadata_context,
                    method='open-after-analysis', lease=lease,
                    operation_id=command['identity'].get('operation_id'), record_id=instance.record_id)))
            caps = readiness()["capabilities"]
            ida = [int(x) for x in actual["result"].split(".")[:3]]
            caps["runtime"]["ida"] = ida + [0] * (3 - len(ida))
            custodian.ready(caps, wait_analysis, handle.recovery)
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
            operation_id = command["identity"]["operation_id"]
            with self.lock:
                if self.handles.get(lease['lease_id']) is not stored:
                    raise ValueError('cancel lease changed before public call')
                record = self.executing.get(operation_id)
                if record is not None and record['handle'] is not handle:
                    raise ValueError('cancel execution handle does not match lease')
                native_id = record.get('native_id', operation_id) if record is not None else operation_id
                if record is not None:
                    # Admission observes intent before the public call can
                    # block. Proof retries remain separate until it returns.
                    record['cancel_intent'] = True
                    record['cancel_inflight'] = record.get('cancel_inflight', 0) + 1
                    cancel_gate = record.setdefault('cancel_gate', threading.Lock())
                    # Revoke already acknowledged handshakes even if this
                    # execution record is replaced before their final check.
                    self.lifetime_pending.pop(lease['lease_id'], None)
            public_started[0] = True
            try:
                if record is None:
                    outcome = handle.cancel_operation_outcome(native_id)
                else:
                    with cancel_gate:
                        outcome = handle.cancel_operation_outcome(native_id)
                    with self.lock:
                        if (self.executing.get(operation_id) is record
                                and self.handles.get(lease['lease_id']) is stored
                                and record.get('native_id', operation_id) == native_id
                                and outcome['execution_stopped']):
                            record['stop_proof'] = outcome
            finally:
                with self.lock:
                    if record is not None:
                        record['cancel_inflight'] -= 1
                        record['cancel_requested'] = True
                self.proof_wakeup.set()
            channel.send({"event": "cancel_ack", "attempt": attempt,
                          "accepted": outcome["status"] == "cancelled", "outcome": outcome})
        elif kind == "release":
            with self.lock:
                release_custodian = self.custodians.get(lease['lease_id'])
            public_started[0] = True
            context = getattr(release_custodian, 'cleanup_context',
                [self.identity, lease["lease_id"], lease["instance_id"], lease["generation"], self.lifetime_path])
            cleanup_code = ("import sys\nmodule = sys.modules.get('_ida_cli_nexus_slices_v1')\n"
                            f"result = module.release_lease({context!r}) if module else None")
            cleanup_code = guarded_source(cleanup_code,
                dict(self.metadata_contexts.get(lease['lease_id'], {}), method='close',
                     operation_id=command.get('identity', {}).get('operation_id',
                         'release:' + str(attempt['sequence'])), lease=lease), refuse=False)
            if release_custodian is not None:
                # Use the existing versioned owner code, then a fresh close_status
                # in this same exact N1 operation. No owner-exit wait is involved.
                cleanup_code += ("\nresult = _r9_guard.close_status()\n")
                ordinary_release(self, channel, attempt, lease, handle, release_custodian,
                                 deadline, cleanup_code)
                return
            raise RuntimeError('ProtocolMismatch: owned release has no exact N1 custody; handle retained')
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
                for custody in self.acquisitions.values():
                    if (custody.recovery_snapshot is not None and not custody.recovery_active
                            and not custody.running
                            and time.monotonic() >= custody.recovery_next):
                        custody.recovery_active = True
                        self.release_scheduler.submit(('restore', custody.watch), custody.advance_restore)
                for operation_id, record in self.executing.items():
                    if (not record["unknown"] or not record["cancel_requested"]
                            or record["proving"] or record.get('cancel_inflight')):
                        continue
                    # A deadline limits new public probes, never consumption of
                    # authoritative evidence already acquired on another path.
                    if record.get("stop_proof"):
                        record["proving"] = True
                        proven.append((operation_id, record, record["stop_proof"]))
                    elif record["expired"] and not record.get('cleanup_stop_observation'):
                        continue
                    elif not record["expired"] and time.monotonic() >= record["deadline"]:
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
        with self.lock:
            if self.executing.get(operation_id) is not record:
                return
        self.control.send({"event": "stopped", "attempt": record["attempt"],
                           "proof": "causal_cancel_not_pending", "outcome": outcome})
        with self.lock:
            if self.executing.get(operation_id) is not record:
                return
            if self.unknown.get(operation_id) == record["attempt"]:
                self.unknown.pop(operation_id, None)
            self.executing.pop(operation_id, None)

    def confirm_stop(self, operation_id, record):
        try:
            with self.lock:
                if self.executing.get(operation_id) is not record or record.get('cancel_inflight'):
                    return
                cancel_gate = record.setdefault('cancel_gate', threading.Lock())
            with cancel_gate:
                with self.lock:
                    if self.executing.get(operation_id) is not record or record.get('cancel_inflight'):
                        return
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
                # Accepted cleanup still owns this exact stop obligation after
                # the caller's deadline. Bounded public observation continues;
                # the original deadline/outcome and execution are never reset.
                delay = .8 if record.get('cleanup_stop_observation') and record['expired'] else .02
                record["next"] = time.monotonic() + delay
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
        self.close_lifetime_listener()
        for lease, _handle in handles:
            self.drop_lifetime(lease["lease_id"])
        for operation_id, record in operations:
            try:
                record["handle"].cancel_operation_outcome(record.get("native_id", operation_id))
            except Exception as exc:
                print(f"cancel during cleanup failed: {type(exc).__name__}", file=sys.stderr)
        for key, custody in auxiliary:
            print(f'auxiliary custody pending without N1 cleanup grant: {key}; independent helper retained', file=sys.stderr)
        for _lease, handle in handles:
            try:
                if _lease['lease_id'] in self.custodians:
                    # Once control IPC is gone there is no N1 authority for a
                    # new guard/cleanup RPC. Preserve the durable helper watch;
                    # process/transport exit is not a resource-stop proof.
                    raise RuntimeError('custody cleanup pending without N1 grant; independent helper and target responsibility retained')
                outcome = release_handle(handle, time.monotonic()+5)
                if outcome is None:
                    raise RuntimeError('lease release unconfirmed; exact handle retained')
                if outcome['save_guard_error']:
                    print(outcome['save_guard_error'], file=sys.stderr)
                with self.lock:
                    self.handles.pop(_lease['lease_id'], None)
                    self.metadata_contexts.pop(_lease['lease_id'], None)
            except Exception as exc:
                print(f"lease cleanup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        for path, handle in verifications:
            print(f"verification custody pending; staging retained: {path}", file=sys.stderr)
        for channel in (self.business, self.control):
            channel.socket.close()
        for pool in (self.business_pool, self.cancel_pool, self.release_pool, self.proof_pool, self.preflight_pool, self.detach_pool):
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
