"""Build a private SDK worker copy with an explicit post-open/pre-publication gate.

SDK source stays in the prepared environment and private runtime directories.
Only these small insertions belong in the public repository.
"""
import hashlib
import os
from pathlib import Path
import stat
import tempfile

_SDK_SHA256 = "787cfc2cf0e6ad8bc651d8e8bc3b1d0f8b8b261da4e65b3647e1391740538aff"
_PREFIX = "__package__ = 'ida_nexus.cli'\n"
_MAIN = "def main(argv: list[str] | None = None) -> int:\n"
_MAIN_HOOK = "    _test_gate_root = Path(sys.argv.pop(1))\n"
_BEFORE_CLAIM = "    if args.launch_authorization is not None:\n"
_CLAIM_FENCE = '''    # Test-only fence before the single-use permit can be claimed.
    import json
    gate_root = _test_gate_root
    try:
        gate_fd = os.open(gate_root / "claim-gate-used", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(gate_fd)
        (gate_root / "worker-before-claim.json").write_text(json.dumps({
            "pid": os.getpid(), "ppid": os.getppid(), "path": str(input_path),
            "phase": "before_launch_authorization_claim"}))
        os.kill(os.getpid(), signal.SIGSTOP)
'''
_AFTER_OPEN = "        if args.save_after_open:\n"
_FENCE = """        # Test-only fence: Database.open returned; publication has not started.
        import json
        import time
        gate_root = _test_gate_root
        marker = gate_root / "worker-open.json"
        try:
            gate_fd = os.open(gate_root / "gate-used", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(gate_fd)
            marker.write_text(json.dumps({"pid": os.getpid(), "ppid": os.getppid(),
                "time": time.time(), "path": str(input_path),
                "phase": "after_Database.open_before_server.start"}))
            os.kill(os.getpid(), signal.SIGSTOP)
            (gate_root / "worker-resumed").write_text(str(time.time()))
"""


def build_worker(root: Path, *, before_claim: bool = False) -> Path:
    """Generate only under a caller-owned private directory outside the repo."""
    root = Path(root).resolve(strict=True)
    repository = Path(__file__).resolve().parents[2]
    info = root.stat()
    if (root.is_relative_to(repository) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("worker source requires a private directory outside the repository")
    import ida_nexus
    original = (Path(ida_nexus.__file__).resolve().parent / "cli/worker.py").read_bytes()
    if hashlib.sha256(original).hexdigest() != _SDK_SHA256:
        raise RuntimeError("StartupUnconfirmed: fixed SDK worker source hash differs")
    source = original.decode()
    if source.count(_MAIN) != 1 or source.count(_AFTER_OPEN) != 1:
        raise RuntimeError("StartupUnconfirmed: fixed SDK worker gate anchors differ")
    source = _PREFIX + source.replace(_MAIN, _MAIN + _MAIN_HOOK, 1)
    if before_claim:
        if source.count(_BEFORE_CLAIM) != 1:
            raise RuntimeError("StartupUnconfirmed: fixed SDK claim gate anchor differs")
        source = source.replace(_BEFORE_CLAIM, _CLAIM_FENCE + _BEFORE_CLAIM, 1)
    else:
        source = source.replace(_AFTER_OPEN, _FENCE + _AFTER_OPEN, 1)
    private = Path(tempfile.mkdtemp(prefix="worker-open-", dir=root))
    destination = private / "worker.py"
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(source)
        output.flush()
        os.fsync(output.fileno())
    return destination
