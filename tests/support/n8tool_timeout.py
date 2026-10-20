"""Deterministic slow-copy and direct-signal tests through the real Rust entrypoint."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time


def interpreter():
    arguments = sys.argv[2:]
    while arguments[0] in ('-I', '-B'):
        arguments.pop(0)
    sys.argv = arguments
    bootstrap = runpy.run_path(arguments[0], run_name='n8_timeout_loader')
    entry = bootstrap['load_entry']()
    ready = Path(os.environ['N8_TIMEOUT_READY'])
    injected = False
    if os.environ['N8_TIMEOUT_CASE'] == 'slow':
        copy = entry.files.copy_verified
        def slow_copy(*args, **kwargs):
            nonlocal injected
            if not injected:
                injected = True
                ready.touch()
                # Intentional slow I/O, with an exact lower bound exceeding
                # the old guard. Success never depends on a scheduling race.
                until = time.monotonic() + 121
                while time.monotonic() < until:
                    if hasattr(entry.files, 'checkpoint'):
                        entry.files.checkpoint()
                    threading.Event().wait(min(0.05, max(0, until-time.monotonic())))
            return copy(*args, **kwargs)
        entry.files.copy_verified = slow_copy
    else:
        apply = entry.apply
        def interrupted_apply(*args, **kwargs):
            def hold(stage):
                if stage == 'after_remove':
                    ready.touch()
                    while True:
                        entry.files.checkpoint()
                        threading.Event().wait(0.01)
            return apply(*args, **kwargs, hook=hold)
        entry.apply = interrupted_apply
    entry.main()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--interpreter':
        interpreter()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True, help='private modified packed IDB fixture directory')
    parser.add_argument('--label', required=True)
    parser.add_argument('--case', choices=('slow', 'signal'), required=True)
    args = parser.parse_args()
    root, binary = args.root.resolve(), args.binary.resolve()
    case = root/args.label
    case.mkdir(mode=0o700)
    home, state, backup = case/'home', case/'state', case/'backup'
    home.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    cache = home/'idb'
    cache.mkdir(mode=0o700)
    source = args.fixture.resolve(strict=True)
    group = next(source.glob('*.i64')).name
    for name in (group, group[:-4], 'index.json'):
        shutil.copyfile(source/name, cache/name)
    original = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in cache.iterdir()}
    environment = root/'environment'
    python = environment/'venv/bin/python'
    wrapper = case/'python-wrapper'
    wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(str(python))+' -I -B '+shlex.quote(str(Path(__file__).resolve()))+' --interpreter "$@"\n')
    wrapper.chmod(0o700)
    ready = case/'copy-or-remove-ready'
    env = {k: os.environ[k] for k in ('PATH', 'USER', 'LOGNAME') if k in os.environ}
    env.update(HOME=str(home), IDA_CLI_HOME=str(home), IDA_NEXUS_STATE_DIR=str(state),
               IDADIR='/Applications/IDA Professional 9.5.app/Contents/MacOS',
               IDAUSR=str(environment/'profile'), IDAPYTHON_VENV_EXECUTABLE=str(python),
               IDA_NEXUS_PYTHON=str(python), TMPDIR=str(root/'tmp'),
               PYTHONDONTWRITEBYTECODE='1', IDA_CLI_LEGACY_TIMEOUT_SECS='150',
               N8_TIMEOUT_READY=str(ready), N8_TIMEOUT_CASE=args.case)
    base = [str(binary), 'cache-legacy', '--root', str(cache), '--mode', 'clean', '--group', group, '--backup', str(backup)]
    before = subprocess.check_output(['uptime'], text=True).strip()
    preview = subprocess.run(['timeout', '30s', *base], env=env, text=True, capture_output=True, check=True)
    (case/'preview.json').write_text(preview.stdout)
    row = json.loads(preview.stdout)
    plan = row['plan']
    evidence = {k: plan[k] for k in ('schema', 'root', 'router_homes', 'state_roots', 'boot_id')}
    evidence.update(plan_sha256=row['plan_sha256'], uid=os.getuid(), operator='private timeout fixture owner',
        exclusion_method='all fixture openers controlled by test; private directories never shared',
        confirmation=row['confirmation'], offline_scope=row['required_offline_scope'],
        started_at=time.time()-1, expires_at=time.time()+240)
    permission = case/'offline.json'
    permission.write_text(json.dumps(evidence))
    permission.chmod(0o600)
    command = [*base, '--apply', '--offline-evidence', str(permission)]
    started = time.monotonic()
    with (case/'apply.stdout').open('w') as out, (case/'apply.stderr').open('w') as err:
        child = subprocess.Popen(command, env=env | {'IDA_NEXUS_PYTHON': str(wrapper)}, stdout=out, stderr=err)
        if args.case == 'signal':
            deadline = time.monotonic()+20
            while not ready.exists():
                assert child.poll() is None, 'maintenance exited before signal barrier'
                assert time.monotonic() < deadline, 'remove barrier not reached'
                threading.Event().wait(0.01)
            assert not (cache/group[:-4]).exists(), 'must interrupt after an actual unlink'
            child.send_signal(signal.SIGTERM)  # signal Rust CLI, not its Python child
        status = child.wait(timeout=175)
    elapsed = time.monotonic()-started
    result = {'case': args.case, 'argv': command, 'exit': status, 'elapsed_seconds': elapsed,
              'uptime_before': before, 'uptime_after': subprocess.check_output(['uptime'], text=True).strip()}
    (case/'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    if args.case == 'slow':
        assert status == 0, (status, (case/'apply.stderr').read_text())
        assert elapsed > 120
        assert not (cache/group).exists()
    else:
        assert status != 0
        assert (backup/'manifest.json').exists()
        assert original == {name: hashlib.sha256((cache/name).read_bytes()).hexdigest() for name in original}
        assert '--mode restore --backup' in (case/'apply.stderr').read_text()
        # Follow the printed instructions with a fresh, unmodified interpreter.
        restore = [str(binary), 'cache-legacy', '--root', str(cache), '--mode', 'restore', '--backup', str(backup)]
        row = json.loads(subprocess.check_output(['timeout', '30s', *restore], env=env, text=True))
        plan = row['plan']
        evidence.update({k: plan[k] for k in ('schema', 'root', 'router_homes', 'state_roots', 'boot_id')})
        evidence.update(plan_sha256=row['plan_sha256'], started_at=time.time()-1, expires_at=time.time()+120)
        permission.write_text(json.dumps(evidence))
        subprocess.run(['timeout', '30s', *restore, '--apply', '--offline-evidence', str(permission)], env=env, check=True)
        assert original == {name: hashlib.sha256((cache/name).read_bytes()).hexdigest() for name in original}
    print('PASS: '+args.case)


if __name__ == '__main__':
    main()
