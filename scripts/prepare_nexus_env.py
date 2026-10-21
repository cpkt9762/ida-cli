#!/usr/bin/env python3
"""Prepare a pinned Nexus runtime or a fresh isolated N0 test environment."""

import argparse
import hashlib
import json
import os
import plistlib
from pathlib import Path
import re
import shutil
import shlex
import signal
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
NEXUS_SHA = "d60ff582fde90c59726336c0dbdf3e8286e9df7a"
CANCEL_HANDLE_SHA256 = "4cd1a9c27e969504eed4ae55d7cbd0e2b4b5a6ba67f0c2529ccb6006a8d67b76"
PATCHED_HANDLE_SHA256 = "aa5d7ea42caaa922ef494d7d8a1406396537a4ea88d9e833825e08c8d279025e"
RUNTIME_LOCK = json.loads((REPO / "scripts/nexus/runtime-lock.json").read_text())
SDK_CONTRACT = json.loads((REPO / "scripts/nexus/client-sdk-contract.json").read_text())


def launcher_source(root, ida):
    """Freeze installation's selected runtime; an explicit override stays local."""
    return ('#!/usr/bin/env bash\nset -euo pipefail\n'
            'export IDA_NEXUS_PYTHON=' + shlex.quote(str(root / 'nexus/venv/bin/python')) + '\n'
            'DEFAULT_IDADIR=' + shlex.quote(str(ida)) + '\n'
            'IDADIR="${IDADIR:-$DEFAULT_IDADIR}"\n'
            'case "$IDADIR" in "~/"*) IDADIR="$HOME/${IDADIR:2}" ;; esac\n'
            'while [[ "$IDADIR" != / && "$IDADIR" == */ ]]; do IDADIR="${IDADIR%/}"; done\n'
            'case "$IDADIR" in\n'
            '  *.app) IDADIR="$IDADIR/Contents/MacOS" ;;\n'
            '  */Contents) IDADIR="$IDADIR/MacOS" ;;\n'
            'esac\n'
            'export IDADIR\n'
            'exec -a ida-cli ' + shlex.quote(str(root / 'ida-cli.real')) + ' "$@"\n')


def app_version(name):
    """Numeric dotted components; missing/trailing zero components are equal."""
    match = re.match(r'^IDA Professional\s+([0-9]+(?:\.[0-9]+)*)', name)
    parts = [int(part) for part in match.group(1).split('.')] if match else [0]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def discover_ida(environment=None, *, report=None):
    """Explicit runtime wins; auto-selection uses newest numeric app version."""
    environment = os.environ if environment is None else environment

    def normalized(path):
        path = Path(path).expanduser()
        if path.suffix == '.app':
            path = path / 'Contents/MacOS'
        elif path.name == 'Contents':
            path = path / 'MacOS'
        path = path.resolve(strict=True)
        if not path.is_dir():
            raise ValueError('runtime is not a directory: ' + str(path))
        return path

    explicit = environment.get('IDADIR')
    if explicit:
        try:
            selected = normalized(explicit)
            if report is not None:
                print('Selected IDA (explicit IDADIR): ' + str(selected), file=report)
            return selected
        except (OSError, ValueError) as error:
            raise ValueError(f'invalid IDADIR {explicit}: {error}; set IDADIR to an IDA runtime directory') from error
    override = environment.get('IDA_CLI_IDA_SEARCH_ROOTS')
    roots = json.loads(override) if override is not None else [
        '/Applications', str(Path(environment.get('HOME', str(Path.home()))) / 'Applications')]
    if (not isinstance(roots, list) or not roots
            or any(not isinstance(path, str) or not Path(path).is_absolute() for path in roots)):
        raise ValueError('IDA_CLI_IDA_SEARCH_ROOTS must be a JSON array of absolute directories')
    candidates = {}
    for root in map(Path, roots):
        if not root.exists():
            continue
        for app in sorted(root.iterdir()):
            if app.name.startswith('IDA Professional') and app.suffix == '.app' and (app / 'Contents/MacOS').is_dir():
                path = normalized(app)
                candidates[path] = max(candidates.get(path, (0,)), app_version(app.name))
    if candidates:
        newest = max(candidates.values())
        selected = min(path for path, version in candidates.items() if version == newest)
        if report is not None:
            print('Selected IDA (newest numeric app version): ' + str(selected), file=report)
            others = [str(path) for path in sorted(candidates) if path != selected]
            print('Other IDA candidates:\n' + ('\n'.join('  ' + path for path in others) or '  (none)'), file=report)
        return selected
    raise ValueError('no IDA installation\nCandidates:\n  (none)\nSearched:\n'
                     + '\n'.join('  ' + path for path in roots)
                     + '\nset IDADIR to the intended .app, Contents, or runtime directory')


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
    """Bound each owned process group without requiring an external timeout tool."""
    command = list(map(str, args))
    with subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, start_new_session=True) as child:
        expired = False
        try:
            stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            expired = True
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate()
    (root / "logs" / f"{label}.log").write_text(stdout + stderr)
    code = 124 if expired else child.returncode
    with (root / "commands.jsonl").open("a") as out:
        out.write(json.dumps({"command": command, "cwd": str(cwd), "timeout_seconds": 30,
                              "exit": code}) + "\n")
    if code:
        raise RuntimeError(f"{label} failed (exit {code}); see logs/{label}.log")
    return stdout.strip()


def runtime_entry(ida, lock=None):
    lock = RUNTIME_LOCK if lock is None else lock
    with (ida.parent / 'Info.plist').open('rb') as stream:
        version = str(plistlib.load(stream)['CFBundleShortVersionString'])
    parts = version.split('.')
    version = '.'.join(parts[:2])
    if version not in lock['runtimes']:
        raise RuntimeError('unsupported IDA ' + version + '; supported IDA versions: 9.4, 9.5; set IDADIR to a supported candidate')
    return lock['runtimes'][version]


def validate_runtime(ida, lock=None):
    """Select exactly this runtime's locked wheel; never borrow another version."""
    lock = RUNTIME_LOCK if lock is None else lock
    if sys.version_info < (3, 11):
        raise RuntimeError('Nexus requires Python >=3.11')
    entry = runtime_entry(ida, lock)
    wheel = ida / 'idalib/python' / entry['idapro_wheel']
    if not wheel.is_file():
        raise FileNotFoundError('selected IDA does not provide ' + entry['idapro_wheel'])
    for name, expected in lock['assets'].items():
        if digest(REPO / 'scripts/nexus' / name) != expected:
            raise RuntimeError('runtime asset hash mismatch: ' + name)
    if digest(wheel) != entry['idapro_wheel_sha256']:
        raise RuntimeError('selected idapro wheel hash mismatch: ' + str(wheel))
    return wheel


def check_dependencies(root, python, pip, entry):
    # Only the registered 9.4 metadata conflict is accepted, after checking the
    # installed runtime code without importing/initializing native IDA.
    code = "import importlib.util,json,hashlib; from pathlib import Path; p=Path(importlib.util.find_spec('idapro').origin).parent; print(json.dumps({n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ('__init__.py','config.py')}))"
    actual = json.loads(run(root, 'idapro-code', [str(python), '-I', '-B', '-c', code]))
    if actual != entry['code_sha256']:
        raise RuntimeError('installed idapro runtime code hash mismatch')
    exception = entry.get('compatibility', {}).get('pip_check_exception')
    script = ("import subprocess,sys; p=subprocess.run(sys.argv[2:],capture_output=True,text=True); "
              "print(p.stdout,end=''); print(p.stderr,end='',file=sys.stderr); "
              "lines=p.stdout.strip().splitlines(); "
              "sys.exit(0 if (p.returncode==0 or (p.returncode==1 and lines==[sys.argv[1]] and not p.stderr)) else p.returncode)")
    run(root, 'pip-check', [str(python), '-I', '-B', '-c', script, exception or '', *pip, 'check'])


def prepare(args: argparse.Namespace) -> None:
    root = args.root.expanduser().resolve()
    installed_runtime = args.runtime_only and root == REPO / 'nexus'
    if not installed_runtime and (root.is_relative_to(REPO) or REPO.is_relative_to(root)):
        raise ValueError("environment root must be outside the repository")
    ida = discover_ida({"IDADIR": str(args.ida_dir)})
    wheel = validate_runtime(ida)
    entry = runtime_entry(ida)
    registry = None
    eula = []
    if not args.runtime_only:
        if args.eula_registry is None:
            raise ValueError('--eula-registry is required for isolated test preparation')
        registry = args.eula_registry.expanduser().resolve(strict=True).read_bytes()
        eula = accepted_eula_entries(registry)
    root.mkdir(mode=0o700)
    for name in ("home", "logs", "wheels", "profile", "state", "cli-home", "fixtures", "tmp", "backups"):
        (root / name).mkdir(mode=0o700)
    if registry is not None:
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
        authorization_patch = REPO / "scripts/nexus/launch-authorization.patch"
        run(root, "authorization-patch-check", ["git", "apply", "--check", str(authorization_patch)], cwd=source)
        run(root, "authorization-patch", ["git", "apply", str(authorization_patch)], cwd=source)
        for name, expected in SDK_CONTRACT["files"].items():
            if digest(source / "ida_nexus" / name) != expected:
                raise RuntimeError(f"client SDK boundary patch output hash mismatch: {name}; BLOCKED")
    run(root, "nexus-wheel", [*pip, "wheel", "--no-deps", "--no-build-isolation",
                              "--no-cache-dir", "-w", str(root / "wheels"), str(source)])
    run(root, "nexus-install", [*pip, "install", "--no-deps", "--no-index", "--find-links", str(root / "wheels"),
                                "ida-nexus==0.13.4"])
    check_dependencies(root, python, pip, entry)
    installed = json.loads(run(root, "installed-sdk", [str(python), "-I", "-B", "-c",
        "import hashlib,importlib,json,sys; from pathlib import Path; "
        "names=('handle','_resolver','options','cli.worker','_launch_authorization'); "
        "modules={n:Path(importlib.import_module('ida_nexus.'+n).__file__).resolve() for n in names}; "
        "print(json.dumps({n.replace('.', '/')+'.py':{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} "
        "for n,p in modules.items()}))"]))
    for name, module in installed.items():
        if (not Path(module["path"]).is_relative_to(root / "venv")
                or module["sha256"] != digest(source / "ida_nexus" / name)):
            raise RuntimeError(f"installed SDK differs from prepared source: {name}; BLOCKED")
    if not args.runtime_only:
        profile_env = {name: os.environ[name] for name in ("HOME", "USER", "LOGNAME", "PATH") if name in os.environ}
        profile_env.update({"HOME": str(root / "home"), "IDADIR": str(ida), "IDAUSR": str(root / "profile"),
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
    checksums = {str(p.relative_to(root)): digest(p) for p in (root / "wheels").glob("*.whl")}
    if not args.runtime_only:
        sample = root / "fixtures/mini"
        shutil.copyfile(REPO / "test/fixtures/mini.c", root / "fixtures/mini.c")
        run(root, "fixture", ["clang", "-O0", "-fno-inline", str(root / "fixtures/mini.c"), "-o", str(sample)])
        checksums["fixtures/mini"] = digest(sample)
    if sdk_applied:
        for name, expected in RUNTIME_LOCK['installed_files'].items():
            if digest(source / 'ida_nexus' / name) != expected:
                raise RuntimeError('patched runtime hash mismatch: ' + name)
        installed_http = Path(installed['handle.py']['path']).with_name('_http.py')
        if digest(installed_http) != RUNTIME_LOCK['installed_files']['_http.py']:
            raise RuntimeError('installed loopback patch hash mismatch')
    manifest = {"root": str(root), "ida_dir": str(ida), "nexus_sha": sha,
                "runtime_lock": RUNTIME_LOCK, "installed_ida_version": entry["ida_version"], "runtime_only": args.runtime_only,
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
    parser.add_argument("--root", type=Path, help="new directory outside the repository")
    parser.add_argument("--ida-dir", type=Path)
    parser.add_argument("--detect-ida", action="store_true", help="resolve IDADIR or the newest local IDA app version")
    parser.add_argument("--check-runtime", action="store_true", help="validate the detected runtime before installation")
    parser.add_argument("--runtime-only", action="store_true", help="install dependencies without reading a user profile")
    parser.add_argument("--eula-registry", type=Path, help="existing legally prepared ida.reg")
    parser.add_argument("--source", type=Path, help="optional local fixed upstream clone (read only)")
    parser.add_argument("--wheels", type=Path, help="optional offline hashed wheel directory (read only)")
    parser.add_argument("--sdk-baseline", choices=("r0",),
                        help="experimental three-patch baseline only; unsupported by production admission")
    parser.add_argument("--without-client-cancel-patch", action="store_true",
                        help="diagnostic red control only; not a supported bridge environment")
    parser.add_argument("--without-client-close-patch", action="store_true",
                        help="diagnostic old cancel-only red control; unsupported bridge environment")
    args = parser.parse_args()
    if args.runtime_only and (args.sdk_baseline or args.without_client_cancel_patch or args.without_client_close_patch):
        parser.error("runtime installation requires the complete five-patch chain")
    try:
        if args.detect_ida:
            selected = discover_ida(report=sys.stderr)
            if args.check_runtime:
                try:
                    validate_runtime(selected)
                except (OSError, ValueError, RuntimeError) as error:
                    raise RuntimeError(str(error) + '; selection was not changed; see Other IDA candidates above and set IDADIR to one of them') from error
            print(selected)
            return
        if args.check_runtime:
            parser.error('--check-runtime requires --detect-ida')
        if args.root is None or args.ida_dir is None:
            parser.error('--root and --ida-dir are required for environment preparation')
        prepare(args)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"BLOCKED: {error}\n")


if __name__ == "__main__":
    main()
