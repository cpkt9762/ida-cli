"""Isolated N0 process accounting; no user daemon discovery or global cleanup."""

import json
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import signal
import shutil
import subprocess
import time

TIMEOUT = shutil.which("timeout")
if TIMEOUT is None:
    raise RuntimeError("shell timeout is required; BLOCKED")


def identity(pid: int) -> str:
    result = subprocess.run([TIMEOUT, "3s", "ps", "-p", str(pid), "-o", "lstart=", "-o", "args="],
                            capture_output=True, text=True)
    if result.returncode == 1:
        return ""  # ps documents exit 1 when this PID no longer exists.
    if result.returncode:
        raise RuntimeError(f"process identity check failed: {result.returncode}")
    return result.stdout.strip()


def same_process(current: str, recorded: str) -> bool:
    # ps can initially show just (python3.14) before exec publishes full argv.
    # PID birth time remains stable across that exec; a reused PID has a new one.
    return bool(current and recorded) and current.split()[:5] == recorded.split()[:5]


class Environment:
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        self.manifest = json.loads((self.root / "environment.json").read_text())
        if self.manifest["root"] != str(self.root):
            raise ValueError("environment moved; rebuild it instead of reusing venv paths")
        self.ledger = self.root / "processes.jsonl"
        self.children = []

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

    def record(self, process: subprocess.Popen, command: list[str]) -> None:
        self.children.append(process)
        current = identity(process.pid)
        with self.ledger.open("a") as out:
            out.write(json.dumps({"pid": process.pid, "identity": current,
                                  "command": list(map(str, command))}) + "\n")
            out.flush()
            os.fsync(out.fileno())

    def entries(self) -> list[dict]:
        return [json.loads(line) for line in self.ledger.read_text().splitlines()] if self.ledger.exists() else []

    def cleanup(self) -> list[int]:
        """Signal only this ledger's PIDs with the same recorded birth time."""
        killed = []
        for entry in self.entries():
            pid, original = entry["pid"], entry["identity"]
            for child in self.children:
                child.poll()  # Reap exited children, including detached workers.
            if not same_process(identity(pid), original):
                continue
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 3
            while same_process(identity(pid), original) and time.monotonic() < deadline:
                for child in self.children:
                    child.poll()
                time.sleep(0.05)
            if same_process(identity(pid), original):
                os.kill(pid, signal.SIGKILL)
            for child in self.children:
                if child.pid == pid:
                    child.wait(timeout=3)
            killed.append(pid)
        return killed

    def assert_clean(self) -> None:
        deadline = time.monotonic() + 3
        while True:
            for child in self.children:
                child.poll()
            live = [e["pid"] for e in self.entries() if same_process(identity(e["pid"]), e["identity"])]
            if not live or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        if live:
            raise AssertionError(f"owned processes still alive: {live}")
