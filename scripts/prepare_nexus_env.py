#!/usr/bin/env python3
"""Prepare a fresh, external N0 environment without changing any installation."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
NEXUS_SHA = "d60ff582fde90c59726336c0dbdf3e8286e9df7a"
CANCEL_HANDLE_SHA256 = "4cd1a9c27e969504eed4ae55d7cbd0e2b4b5a6ba67f0c2529ccb6006a8d67b76"
PATCHED_HANDLE_SHA256 = "aa5d7ea42caaa922ef494d7d8a1406396537a4ea88d9e833825e08c8d279025e"
SDK_CONTRACT = json.loads((REPO / "scripts/nexus/client-sdk-contract.json").read_text())


def accepted_eula_entries(data: bytes) -> list[str]:
    """Identify existing accepted records; do not synthesize registry files."""
    if not data.startswith(b"iDa7"):
        raise ValueError("unsupported ida.reg format; prepare a profile manually")
    entries = re.findall(rb"(EULA [0-9]{2,3})\x00\x04\x00\x00\x00\x04\x01\x00\x00\x00", data)
    if not entries:
        raise ValueError("no existing accepted EULA record; BLOCKED")
    return [entry.decode("ascii") for entry in entries]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(root: Path, label: str, args: list[str], *, cwd: Path = REPO, env=None) -> str:
    """Every child, including pip builds and fixture compilation, has shell timeout."""
    command = ["timeout", "30s", *map(str, args)]
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    (root / "logs" / f"{label}.log").write_text(result.stdout + result.stderr)
    with (root / "commands.jsonl").open("a") as out:
        out.write(json.dumps({"command": command, "cwd": str(cwd), "exit": result.returncode}) + "\n")
    if result.returncode:
        raise RuntimeError(f"{label} failed (exit {result.returncode}); see logs/{label}.log")
    return result.stdout.strip()


def prepare(args: argparse.Namespace) -> None:
    root = args.root.expanduser().resolve()
    if root.is_relative_to(REPO) or REPO.is_relative_to(root):
        raise ValueError("environment root must be outside the repository")
    ida = args.ida_dir.expanduser().resolve(strict=True)
    wheel = ida / "idalib/python/idapro-0.0.10-py3-none-any.whl"
    if not wheel.is_file():
        raise FileNotFoundError("selected IDA does not provide idapro 0.0.10; BLOCKED")
    # Read only the registry explicitly selected by the caller, never a license.
    registry = args.eula_registry.expanduser().resolve(strict=True).read_bytes()
    eula = accepted_eula_entries(registry)
    root.mkdir(mode=0o700)  # Refuse reuse, including partially prepared directories.
    for name in ("logs", "wheels", "profile", "state", "cli-home", "fixtures", "tmp", "backups"):
        (root / name).mkdir(mode=0o700)
    # Let IDA serialize the minimal registry using its public registry API.
    # The temporary external copy includes config metadata, never a hexlic file.
    (root / "profile/ida.reg").write_bytes(registry)
    (root / "profile/ida.reg").chmod(0o600)
    (root / "profile/.n0-isolated-profile").touch(mode=0o600)
    run(root, "venv", [sys.executable, "-m", "venv", str(root / "venv")])
    python = root / "venv/bin/python"
    pip = [str(python), "-m", "pip", "--isolated", "--disable-pip-version-check"]
    wheel_source = (["--no-index", "--find-links", str(args.wheels.resolve(strict=True))]
                    if args.wheels else ["--index-url", "https://pypi.org/simple"])
    run(root, "download", [*pip, "download", *wheel_source,
                           "--no-cache-dir", "--no-deps", "--require-hashes", "--only-binary=:all:",
                           "-r", str(REPO / "scripts/nexus/requirements.lock"),
                           "-d", str(root / "wheels")])
    shutil.copyfile(wheel, root / "wheels" / wheel.name)
    run(root, "dependencies", [*pip, "install", "--no-deps", "--require-hashes", "--no-index",
                               "--find-links", str(root / "wheels"), "-r", str(REPO / "scripts/nexus/requirements.lock")])
    run(root, "idapro", [*pip, "install", "--no-deps", "--no-index", str(root / "wheels" / wheel.name)])
    source = root / "nexus-source"
    clone = (["--no-hardlinks", "--local", str(args.source.resolve(strict=True))]
             if args.source else ["--depth", "1", "--branch", "v0.13.4",
                                  "https://github.com/HexRaysSA/ida-nexus.git"])
    run(root, "clone", ["git", "clone", "--quiet", *clone, str(source)])
    sha = run(root, "source-sha", ["git", "rev-parse", "HEAD"], cwd=source)
    if sha != NEXUS_SHA:
        raise RuntimeError("Nexus tag no longer matches pinned SHA; refusing patch")
    patch = REPO / "scripts/nexus/loopback-bind.patch"
    run(root, "patch-check", ["git", "apply", "--check", str(patch)], cwd=source)
    run(root, "patch", ["git", "apply", str(patch)], cwd=source)
    cancel_patch = REPO / "scripts/nexus/client-cancel-unknown.patch"
    cancel_applied = not args.without_client_cancel_patch
    if cancel_applied:
        run(root, "cancel-patch-check", ["git", "apply", "--check", str(cancel_patch)], cwd=source)
        run(root, "cancel-patch", ["git", "apply", str(cancel_patch)], cwd=source)
        if digest(source / "ida_nexus/handle.py") != CANCEL_HANDLE_SHA256:
            raise RuntimeError("client cancellation patch output hash mismatch; BLOCKED")
    close_patch = REPO / "scripts/nexus/client-close-proof.patch"
    close_applied = cancel_applied and not args.without_client_close_patch
    if close_applied:
        run(root, "close-patch-check", ["git", "apply", "--check", str(close_patch)], cwd=source)
        run(root, "close-patch", ["git", "apply", str(close_patch)], cwd=source)
        if digest(source / "ida_nexus/handle.py") != PATCHED_HANDLE_SHA256:
            raise RuntimeError("client close proof patch output hash mismatch; BLOCKED")
    sdk_patch = REPO / "scripts/nexus/client-acquisition.patch"
    sdk_applied = close_applied and args.sdk_baseline is None
    if sdk_applied:
        run(root, "sdk-patch-check", ["git", "apply", "--check", str(sdk_patch)], cwd=source)
        run(root, "sdk-patch", ["git", "apply", str(sdk_patch)], cwd=source)
        for name, expected in SDK_CONTRACT["files"].items():
            if digest(source / "ida_nexus" / name) != expected:
                raise RuntimeError(f"client SDK boundary patch output hash mismatch: {name}; BLOCKED")
    run(root, "nexus-wheel", [*pip, "wheel", "--no-deps", "--no-build-isolation",
                              "--no-cache-dir", "-w", str(root / "wheels"), str(source)])
    run(root, "nexus-install", [*pip, "install", "--no-deps", "--no-index", "--find-links", str(root / "wheels"),
                                "ida-nexus==0.13.4"])
    run(root, "pip-check", [*pip, "check"])
    installed = json.loads(run(root, "installed-sdk", [str(python), "-I", "-B", "-c",
        "import hashlib,importlib,json,sys; from pathlib import Path; "
        "names=('handle','_resolver','options'); "
        "modules={n:Path(importlib.import_module('ida_nexus.'+n).__file__).resolve() for n in names}; "
        "print(json.dumps({n+'.py':{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} "
        "for n,p in modules.items()}))"]))
    for name, module in installed.items():
        if (not Path(module["path"]).is_relative_to(root / "venv")
                or module["sha256"] != digest(source / "ida_nexus" / name)):
            raise RuntimeError(f"installed SDK differs from prepared source: {name}; BLOCKED")
    profile_env = {name: os.environ[name] for name in ("HOME", "USER", "LOGNAME", "PATH") if name in os.environ}
    profile_env.update({"IDADIR": str(ida), "IDAUSR": str(root / "profile"),
                        "IDA_CLI_HOME": str(root / "cli-home"), "IDA_NEXUS_STATE_DIR": str(root / "state"),
                        "TMPDIR": str(root / "tmp"), "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    sanitized = run(root, "profile-sanitize", [str(python), str(REPO / "scripts/nexus/sanitize_profile.py"), *eula],
                    env=profile_env)
    if "PROFILE_SANITIZED" not in sanitized:
        raise RuntimeError("IDA did not complete profile initialization; BLOCKED (even if exit code was zero)")
    if b"Licenses" in (root / "profile/ida.reg").read_bytes():
        raise RuntimeError("profile still contains license config metadata; BLOCKED")
    freeze = run(root, "freeze", [*pip, "freeze", "--all"])
    (root / "requirements.freeze").write_text(freeze + "\n")
    sample = root / "fixtures/mini"
    shutil.copyfile(REPO / "test/fixtures/mini.c", root / "fixtures/mini.c")
    run(root, "fixture", ["clang", "-O0", "-fno-inline", str(root / "fixtures/mini.c"), "-o", str(sample)])
    checksums = {str(p.relative_to(root)): digest(p) for p in (root / "wheels").glob("*.whl")}
    checksums["fixtures/mini"] = digest(sample)
    manifest = {"root": str(root), "ida_dir": str(ida), "nexus_sha": sha,
                "patch_sha256": digest(patch), "python": sys.version,
                "client_cancel_patch_applied": cancel_applied,
                "client_cancel_patch_sha256": digest(cancel_patch) if cancel_applied else None,
                "client_close_patch_applied": close_applied,
                "client_close_patch_sha256": digest(close_patch) if close_applied else None,
                "client_handle_sha256": digest(source / "ida_nexus/handle.py"),
                "client_sdk_patch_applied": sdk_applied,
                "client_sdk_patch_sha256": digest(sdk_patch) if sdk_applied else None,
                "client_sdk_contract": SDK_CONTRACT if sdk_applied else None,
                "client_sdk_modules": installed,
                "experimental_baseline": args.sdk_baseline,
                "eula_entries_copied": len(eula), "checksums": checksums}
    (root / "environment.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": "PREPARED", "root": str(root), "nexus_sha": sha}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="new directory outside the repository")
    parser.add_argument("--ida-dir", type=Path, required=True)
    parser.add_argument("--eula-registry", type=Path, required=True, help="existing legally prepared ida.reg")
    parser.add_argument("--source", type=Path, help="optional local fixed upstream clone (read only)")
    parser.add_argument("--wheels", type=Path, help="optional offline hashed wheel directory (read only)")
    parser.add_argument("--sdk-baseline", choices=("r0",),
                        help="experimental three-patch baseline only; unsupported by production admission")
    parser.add_argument("--without-client-cancel-patch", action="store_true",
                        help="diagnostic red control only; not a supported bridge environment")
    parser.add_argument("--without-client-close-patch", action="store_true",
                        help="diagnostic old cancel-only red control; unsupported bridge environment")
    args = parser.parse_args()
    try:
        prepare(args)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"BLOCKED: {error}\n")


if __name__ == "__main__":
    main()
