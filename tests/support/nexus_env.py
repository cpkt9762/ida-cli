"""Isolated N0 process accounting; no user daemon discovery or global cleanup."""

import json
import hashlib
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import signal
import shutil
import subprocess
import threading
import time
import uuid

from process_identity import identity, same_process, valid_identity

TIMEOUT = shutil.which("timeout")
if TIMEOUT is None:
    raise RuntimeError("shell timeout is required; BLOCKED")


@contextmanager
def deferred_termination():
    """Defer Python exceptions during creation, without changing the child mask."""
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("owned process creation/cleanup requires the main thread")
    pending = []
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}

    def defer(signum, _frame):
        pending.append(signum)

    completed = False
    try:
        for sig in previous:
            signal.signal(sig, defer)
        yield pending
        completed = True
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if completed and pending:
        raise InterruptedError(f"test interrupted by signal {pending[0]}")


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stop_child(child):
    # An unreaped Popen child retains our creation relationship, even when its
    # birth query failed. poll/terminate/kill never act on an already reaped PID.
    if child.poll() is not None:
        return False
    child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)
    return True


def _current_identity(pid):
    current = identity(pid)
    if current is not None and not valid_identity(current):
        raise RuntimeError(f"invalid identity query result for {pid}")
    return current


class Environment:
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        self.manifest = json.loads((self.root / "environment.json").read_text())
        if self.manifest["root"] != str(self.root):
            raise ValueError("environment moved; rebuild it instead of reusing venv paths")
        self.ledger = self.root / "processes.jsonl"
        self.intents = self.root / "process-intents"
        self.children = []

    def client_patch_status(self):
        """Check installed code against the prepared manifest, without loading IDA."""
        import importlib.util
        spec = importlib.util.find_spec("ida_nexus")
        if spec is None or spec.origin is None:
            raise RuntimeError("ida-nexus is missing; BLOCKED")
        source = Path(spec.origin).parent / "handle.py"
        if not source.resolve().is_relative_to(self.root / "venv"):
            raise RuntimeError("Nexus must load from this isolated environment")
        actual = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual != self.manifest.get("client_handle_sha256"):
            raise RuntimeError("installed Nexus client hash differs from environment manifest")
        return {"applied": self.manifest.get("client_cancel_patch_applied", False),
                "handle_sha256": actual}

    @contextmanager
    def exclusive(self):
        with (self.root / ".verification.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RuntimeError("another verifier owns this environment; use a fresh root") from error
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def variables(self) -> dict[str, str]:
        # Preserve the actual home for IDA's existing legal license lookup.
        # No profile, credentials, PYTHONPATH or daemon settings are inherited.
        env = {name: os.environ[name] for name in ("HOME", "USER", "LOGNAME") if name in os.environ}
        env.update({"PATH": os.pathsep.join((str(self.root / "venv/bin"), str(Path(TIMEOUT).parent), os.defpath)),
                    "IDADIR": self.manifest["ida_dir"], "IDAUSR": str(self.root / "profile"),
                    "IDA_CLI_HOME": str(self.root / "cli-home"),
                    "IDAPYTHON_VENV_EXECUTABLE": str(self.root / "venv/bin/python"),
                    "IDA_NEXUS_STATE_DIR": str(self.root / "state"),
                    "TMPDIR": str(self.root / "tmp"), "PYTHONNOUSERSITE": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONUNBUFFERED": "1", "LANG": "C.UTF-8"})
        return env

    def _begin_creation(self, command):
        self.intents.mkdir(mode=0o700, exist_ok=True)
        _sync_directory(self.root)
        intent = self.intents / f"{uuid.uuid4()}.json"
        with intent.open("x") as out:
            out.write(json.dumps({"status": "pending", "command": list(map(str, command))}) + "\n")
            out.flush()
            os.fsync(out.fileno())
        _sync_directory(self.intents)
        return intent

    def _finish_creation(self, intent):
        intent.unlink()
        _sync_directory(self.intents)

    def spawn(self, factory, command):
        """Persist intent before Popen; register or stop+wait before delivering TERM."""
        with deferred_termination() as pending:
            intent = self._begin_creation(command)
            process = None
            try:
                process = factory()
                self.children.append(process)
                self.record(process, command, intent=intent)
                if pending:
                    raise InterruptedError(f"test interrupted by signal {pending[0]}")
                return process
            except BaseException:
                if process is not None:
                    _stop_child(process)
                    if intent.exists():
                        self._finish_creation(intent)
                # With no returned Popen the intent stays unresolved: factory
                # failure or SIGKILL cannot prove that no child was created.
                raise

    def record(self, process: subprocess.Popen, command: list[str], *, intent=None) -> None:
        """Register an already held child, rolling it back on any failure.

        Call spawn for creation-to-registration protection. Direct record is
        retained for callers already holding a Popen, not for detached launch.
        """
        with deferred_termination() as pending:
            if process not in self.children:
                self.children.append(process)
            try:
                if intent is None:
                    intent = self._begin_creation(command)
                self._record(process, command)
                if pending:
                    raise InterruptedError(f"test interrupted by signal {pending[0]}")
                self._finish_creation(intent)
            except BaseException:
                _stop_child(process)
                if intent is not None and intent.exists():
                    self._finish_creation(intent)
                raise

    def _record(self, process, command):
        current = identity(process.pid)
        if not valid_identity(current):
            raise RuntimeError(f"child {process.pid} exited before a precise birth was recorded")
        with self.ledger.open("a") as out:
            out.write(json.dumps({"schema": 2, "pid": process.pid, "identity": current,
                                  "command": list(map(str, command))}) + "\n")
            out.flush()
            os.fsync(out.fileno())
        _sync_directory(self.root)

    def _accounting(self):
        entries, errors = [], []
        if self.ledger.exists():
            try:
                lines = self.ledger.read_text().splitlines(keepends=True)
            except (OSError, UnicodeError) as error:
                errors.append(f"cannot read ledger: {error}")
                lines = []
            for number, line in enumerate(lines, 1):
                try:
                    entry = json.loads(line)
                    if (not line.endswith("\n") or not isinstance(entry, dict)
                            or entry.get("schema") != 2 or type(entry.get("pid")) is not int
                            or entry["pid"] <= 0 or not valid_identity(entry.get("identity"))):
                        raise ValueError("incomplete, invalid or old unconfirmed identity")
                    entries.append(entry)
                except (ValueError, TypeError) as error:
                    errors.append(f"ledger line {number}: {error}")
        try:
            for intent in self.intents.iterdir() if self.intents.exists() else ():
                errors.append(f"unfinished creation intent: {intent.name}")
        except OSError as error:
            errors.append(f"cannot inspect creation intents: {error}")
        return entries, errors

    def entries(self) -> list[dict]:
        entries, errors = self._accounting()
        if errors:
            raise RuntimeError("process accounting unresolved: " + "; ".join(errors))
        return entries

    def cleanup(self) -> list[int]:
        """Visit every held child and confirmed entry; aggregate uncertain failures."""
        killed, errors = [], []
        with deferred_termination():
            for child in self.children:
                try:
                    if _stop_child(child):
                        killed.append(child.pid)
                except (OSError, subprocess.TimeoutExpired) as error:
                    errors.append(f"held child {child.pid}: {error}")
            entries, accounting_errors = self._accounting()
            errors.extend(accounting_errors)
            for entry in entries:
                try:
                    if self._stop_recorded(entry) and entry["pid"] not in killed:
                        killed.append(entry["pid"])
                except (OSError, RuntimeError, ValueError) as error:
                    errors.append(f"recorded PID {entry['pid']}: {error}")
        if errors:
            raise RuntimeError("cleanup incomplete: " + "; ".join(errors))
        return killed

    def _stop_recorded(self, entry):
        pid, original = entry["pid"], entry["identity"]
        if not same_process(_current_identity(pid), original):
            return False
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return False  # Exited between confirmation and signal; continue the batch.
        deadline = time.monotonic() + 3
        while same_process(_current_identity(pid), original) and time.monotonic() < deadline:
            time.sleep(0.05)
        if same_process(_current_identity(pid), original):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # TERM already sent; no live generation remains to kill.
        return True

    def assert_clean(self) -> None:
        deadline = time.monotonic() + 3
        while True:
            live, errors = [], []
            for child in self.children:
                if child.poll() is None:
                    live.append(child.pid)
            entries, accounting_errors = self._accounting()
            errors.extend(accounting_errors)
            for entry in entries:
                try:
                    if same_process(_current_identity(entry["pid"]), entry["identity"]):
                        live.append(entry["pid"])
                except (OSError, RuntimeError, ValueError) as error:
                    errors.append(f"identity unknown for {entry['pid']}: {error}")
            if errors:
                raise AssertionError("process accounting unresolved: " + "; ".join(errors))
            if not live or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        if live:
            raise AssertionError(f"owned processes still alive: {live}")
