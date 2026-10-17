#!/usr/bin/env python3
"""Build an experimental U1 SDK copy and diff; never edit the prepared SDK."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil

BASE_HASH = "aa5d7ea42caaa922ef494d7d8a1406396537a4ea88d9e833825e08c8d279025e"


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"fixed source anchor mismatch: {old[:80]}")
    return text.replace(old, new)


def build(source, target):
    if hashlib.sha256((source / "ida_nexus/handle.py").read_bytes()).hexdigest() != BASE_HASH:
        raise ValueError("baseline handle hash mismatch")
    shutil.copytree(source, target, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.egg-info", "build"))
    handle_path = target / "ida_nexus/handle.py"
    handle = handle_path.read_text()
    handle = replace(handle, "class DatabaseHandle:\n", '''_ACQUIRED_PENDING = {}


class AcquiredFailure(Exception):
    """A stream exists: custody must receive this exact handle and original cause."""
    def __init__(self, handle, cause):
        super().__init__(str(cause))
        self.handle, self.cause = handle, cause


class LeaseOpenFailure(NexusConnectionError):
    def __init__(self, message, status):
        super().__init__(message)
        self.status = status


class DatabaseHandle:
''')
    # Constructor and attach receive a new optional callback; legacy callers retain signatures/results.
    anchor = '        on_disconnect: Callable[["DatabaseHandle", str], None] | None = None,\n'
    if handle.count(anchor) != 3:
        raise ValueError("unexpected constructor/attach/open callback anchors")
    handle = handle.replace(anchor, anchor + '        on_acquired: Callable[["DatabaseHandle"], None] | None = None,\n')
    # Stage hooks are additive on constructor/attach. open uses its options observer.
    stage_anchor = '        on_acquired: Callable[["DatabaseHandle"], None] | None = None,\n'
    handle = handle.replace(stage_anchor, stage_anchor + '        on_stage=None,\n', 2)
    handle = replace(handle, '        self._on_disconnect = on_disconnect\n',
                     '        self._on_disconnect = on_disconnect\n        self._on_stage = on_stage\n')
    handle = replace(handle, '''        thread = threading.Thread(
            target=self._monitor_lease,
            name=f"ida-nexus-lease-{instance.pid}",
            daemon=True,
        )
        self._lease_thread = thread
        thread.start()
''', '''        try:
            if on_acquired is not None:
                _ACQUIRED_PENDING[id(self)] = self
                on_acquired(self)
            thread = threading.Thread(target=self._monitor_lease,
                name=f"ida-nexus-lease-{instance.pid}", daemon=True)
            self._lease_thread = thread
            thread.start()
            _ACQUIRED_PENDING.pop(id(self), None)
        except Exception as cause:
            if on_acquired is None:
                raise
            raise AcquiredFailure(self, cause) from cause
''')
    handle = replace(handle, '            "keepalive": keepalive,\n            "on_disconnect": on_disconnect,\n',
                     '            "keepalive": keepalive,\n            "on_disconnect": on_disconnect,\n            "on_acquired": on_acquired,\n            "on_stage": on_stage,\n')
    handle = replace(handle, '        constructor_options: dict[str, Any] = {\n',
                     '        if on_stage is not None:\n            on_stage("BeforeAttach", instance)\n        constructor_options: dict[str, Any] = {\n')
    # The second mapping is the open -> attach call.
    handle = replace(handle, '''            "keepalive": options.keepalive,
            "on_disconnect": on_disconnect,
''', '''            "keepalive": options.keepalive,
            "on_disconnect": on_disconnect,
            "on_acquired": on_acquired,
            "on_stage": options.acquisition_observer,
''')
    handle = replace(handle, '''            connection.request(
                "GET",
                lease_path,
''', '''            if self._on_stage is not None:
                self._on_stage("AttachMayBeSent", entry)
            connection.request(
                "GET",
                lease_path,
''')
    handle = replace(handle, '                debug_flags=options.debug_flags,\n',
                     '                debug_flags=options.debug_flags,\n                acquisition_observer=options.acquisition_observer,\n')
    handle = replace(handle, '        instance = resolve()\n', '''        instance = resolve()
        if options.acquisition_observer is not None:
            options.acquisition_observer("Resolved", instance)
''')
    handle = replace(handle, '            replacement = resolve()\n', '''            replacement = resolve()
            if options.acquisition_observer is not None:
                options.acquisition_observer("ReconnectResolved", replacement)
''')
    # Structurally typed rejection, no parsing of message text.
    handle = replace(handle, '''            raise NexusConnectionError(
                f"failed to establish instance lease: HTTP {response.status}: {body}"
            )''', '''            raise LeaseOpenFailure(
                f"failed to establish instance lease: HTTP {response.status}: {body}", response.status
            )''')
    insertion = '''    @classmethod
    def attach_outcome(cls, instance, *, on_acquired=None, **kwargs):
        stage = "BeforeAttach"
        def acquired(handle):
            nonlocal stage
            stage = "Acquired"
            if on_acquired is not None:
                on_acquired(handle)
        def observed(value, _instance):
            nonlocal stage
            stage = value
        try:
            handle = cls.attach(instance, on_acquired=acquired, on_stage=observed, **kwargs)
            return {"stage":"Acquired", "handle":handle, "instance":instance,
                    "failure_kind":None, "cause":None}
        except Exception as error:
            owned = error.handle if isinstance(error, AcquiredFailure) else None
            return {"stage":stage, "handle":owned, "instance":instance,
                    "failure_kind":"cleanup_required" if owned is not None else
                        "lease_absent" if isinstance(error, LeaseOpenFailure) else
                        "not_sent" if stage != "AttachMayBeSent" else "unknown_attach",
                    "http_status":getattr(error, "status", None), "cause":error}

    @classmethod
    def open_outcome(cls, path, *, options=None, observer=None):
        from dataclasses import replace
        options = options or DatabaseOpenOptions()
        events, handles, launches = [], [], []
        def observe(stage, value):
            events.append((stage, value))
            if stage in ("LaunchIntent", "Spawned", "LogReady"):
                launches.append((stage, value))
            if observer is not None:
                observer(stage, value)
        def acquired(handle):
            handles.append(handle)
            observe("Acquired", handle)
        try:
            handle = cls.open(path, options=replace(options, acquisition_observer=observe),
                              on_acquired=acquired)
            cause, failure = None, None
        except Exception as error:
            handle = handles[-1] if handles else None
            cause = error.cause if isinstance(error, AcquiredFailure) else error
            failure = ("cleanup_required" if handle is not None else "lease_absent"
                       if isinstance(error, LeaseOpenFailure) else "resolve_or_attach_unknown")
        resolved = [value for stage, value in events if stage in ("Resolved", "ReconnectResolved")]
        return {"stage":"Acquired" if handle is not None else events[-1][0] if events else "BeforeResolve",
                "handle":handle, "instance":resolved[-1] if resolved else None,
                "first_instance":resolved[0] if resolved else None, "failure_kind":failure,
                "cause":cause, "launches":launches,
                "sdk_reconnect_used":any(stage == "ReconnectResolved" for stage, _ in events)}

    def claim_acquired(self):
        """Explicit custodian takeover after an acquired callback/monitor failure."""
        _ACQUIRED_PENDING.pop(id(self), None)
        return self

'''
    handle = replace(handle, '    @property\n    def instance(self)', insertion + '    @property\n    def instance(self)')
    handle = replace(handle, '        self._closed.set()\n        self._close_outcome =',
                     '        self.claim_acquired()\n        self._closed.set()\n        self._close_outcome =')
    handle = replace(handle, '''            outcome = {"status": "uncertain", "owner_released": False,
                       "lease_released": False, "failure": "cleanup",
                       "failure_type": type(exc).__name__}''', '''            outcome = dict(self._close_outcome or {"status":"uncertain", "owner_released":False,
                       "lease_released":False, "failure":"close_incomplete"})
            outcome.update(cleanup_failure="transport", cleanup_failure_type=type(exc).__name__)''')
    handle = replace(handle, '''                                   lease_released=True, shutdown_pending=result["shutdown_pending"], failure=None)''', '''                                   lease_released=True, shutdown_pending=result["shutdown_pending"], failure=None,
                                   ack_kind="last" if result["shutdown_pending"] else "nonlast")''')
    handle = replace(handle, '''            outcome.update(status="uncertain", lease_released=False,
                           failure="transport" if isinstance(exc, (OSError, http.client.HTTPException)) else "invalid_response")''', '''            if outcome.get("lease_released"):
                outcome.update(cleanup_failure="response", cleanup_failure_type=type(exc).__name__)
            else:
                outcome.update(status="uncertain", lease_released=False,
                    failure="transport" if isinstance(exc, (OSError, http.client.HTTPException)) else "invalid_response")''')
    handle = replace(handle, '''                outcome.update(status="owner_released" if released else "uncertain",
                               owner_released=bool(released),
                               failure=None if released else "lifetime_unconfirmed")''', '''                outcome.update(status="owner_released" if released else
                                      "final_pending" if outcome.get("lease_released") else "uncertain",
                               owner_released=bool(released), owner_pending=not bool(released))''')
    handle = replace(handle, '''        if rpc_connection is not None:
            rpc_connection.close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, min(2.0, deadline - time.monotonic())) if structured else 2.0)
''', '''        try:
            if rpc_connection is not None:
                rpc_connection.close()
        except Exception as exc:
            if not structured:
                raise
            outcome.update(cleanup_failure="rpc", cleanup_failure_type=type(exc).__name__)
        try:
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=max(0.0, min(2.0, deadline - time.monotonic())) if structured else 2.0)
        except Exception as exc:
            if not structured:
                raise
            outcome.update(cleanup_failure="monitor", cleanup_failure_type=type(exc).__name__)
''')
    handle_path.write_text(handle)
    options_path = target / "ida_nexus/options.py"
    options = replace(options_path.read_text(), 'from dataclasses import dataclass\n',
                      'from dataclasses import dataclass, field\n')
    options_path.write_text(replace(options, '    spawn: bool = True\n',
        '    acquisition_observer: object | None = field(default=None, kw_only=True)\n    spawn: bool = True\n'))
    resolver_path = target / "ida_nexus/_resolver.py"
    resolver = resolver_path.read_text()
    resolver = replace(resolver, '    spawner: WorkerSpawner = spawn_worker,\n',
                       '    spawner: WorkerSpawner = spawn_worker,\n    acquisition_observer=None,\n')
    # WorkerLaunchOptions carries callback only inside the client; no wire/server change.
    resolver = replace(resolver, 'from dataclasses import dataclass, replace\n',
                       'from dataclasses import dataclass, field, replace\n')
    resolver = replace(resolver, '    worker_env: Mapping[str, str] | None = None\n',
        '    acquisition_observer: object | None = field(default=None, kw_only=True)\n    worker_env: Mapping[str, str] | None = None\n')
    resolver = replace(resolver, '    launch_options = WorkerLaunchOptions(\n',
                       '    launch_options = WorkerLaunchOptions(\n        acquisition_observer=acquisition_observer,\n')
    resolver = replace(resolver, '    process: subprocess.Popen[bytes]\n', '''    launch = {"suffix":suffix, "source":source, "target":expected_idb, "backend":"idalib"}
    observer = options.acquisition_observer
    if observer is not None:
        observer("LaunchIntent", dict(launch))
    process: subprocess.Popen[bytes]
''')
    resolver = replace(resolver, '    log_path = ensure_private_directory(LOG_DIR) / f"{process.pid}-{suffix}.log"\n', '''    if observer is not None:
        observer("Spawned", dict(launch, process=process, pid=process.pid))
    log_path = ensure_private_directory(LOG_DIR) / f"{process.pid}-{suffix}.log"
    if observer is not None:
        observer("LogReady", dict(launch, pid=process.pid, log_path=str(log_path)))
''')
    resolver_path.write_text(resolver)
    files = ("handle.py", "_resolver.py", "options.py")
    delta = "".join("".join(difflib.unified_diff((source / "ida_nexus" / name).read_text().splitlines(True),
                   (target / "ida_nexus" / name).read_text().splitlines(True),
                   fromfile="a/ida_nexus/" + name, tofile="b/ida_nexus/" + name)) for name in files)
    (target.parent / "sdk-candidate.diff").write_text(delta)
    (target.parent / "sdk-candidate-hashes.json").write_text(json.dumps({
        "baseline_handle":BASE_HASH, "files":{name:hashlib.sha256((target / "ida_nexus" / name).read_bytes()).hexdigest()
                                                for name in files}}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    build(args.source, args.target)


if __name__ == "__main__":
    main()
