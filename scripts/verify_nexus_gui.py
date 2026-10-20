#!/usr/bin/env python3
"""E23: one private Qt GUI owner, product attach, visibility and lease release.

Run with IDA_TEST=1 under timeout 180s in a freshly prepared environment.
After interruption use --cleanup on the same root. Never uses user discovery.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import traceback

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / 'tests/support'), str(REPO / 'scripts')]
from nexus_env import Environment
from process_identity import identity, same_process, valid_identity
from compare_nexus_baseline import Candidate


class Blocked(RuntimeError):
    """Missing GUI or authorization prerequisite, never a passing skip."""


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def wait_file(path, child, *, seconds=30):
    deadline = time.monotonic() + seconds
    while not path.exists():
        error = path.parent / 'error.json'
        if error.exists():
            raise AssertionError(json.loads(error.read_text()))
        if child.poll() is not None:
            failure = Blocked if path.name == 'ready.json' else AssertionError
            raise failure(f'GUI exited {child.returncode} before {path.name}; inspect gui.log')
        if time.monotonic() >= deadline:
            failure = Blocked if path.name == 'ready.json' else AssertionError
            raise failure(f'GUI did not reach {path.name}; inspect gui.log and profile authorization')
        time.sleep(.02)  # Poll a named GUI protocol event, not a guessed execution delay.
    return json.loads(path.read_text())


def owner_record(instance):
    # Public discovery object only; never serialize its authentication fields.
    return {name: getattr(instance, name) for name in
            ('record_id', 'pid', 'started_at', 'idb_path', 'backend', 'managed')}


def check_owner(records, expected, pid, database):
    assert len(records) == 1, ('expected exactly one owner in private state', records)
    actual = records[0]
    assert actual['pid'] == pid and actual['idb_path'] == str(database), actual
    assert actual['backend'] == 'gui' and actual['managed'] is False, actual
    if expected is not None:
        assert actual == expected, ('owner changed', expected, actual)
    return actual


def scene(directory):
    """Snapshot actual IDB components; exclude coordination metadata."""
    values = {}
    for suffix in ('.i64', '.idb', '.id0', '.id1', '.id2', '.nam', '.til'):
        path = directory / ('mini' + suffix)
        if path.exists():
            stat = path.stat()
            values[path.name] = {'inode': stat.st_ino, 'size': stat.st_size,
                'mtime_ns': stat.st_mtime_ns, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    assert values, 'GUI must own real database files'
    return values


def gui_request(root, child, action, response, **kwargs):
    temporary = root / 'request.tmp'
    write_json(temporary, {'action': action, 'response': response, **kwargs})
    temporary.replace(root / 'request.json')
    return wait_file(root / response, child, seconds=10)


def native_command(intent):
    """Rust serde OsString uses Unix byte arrays; Python telemetry uses strings."""
    def decode(value):
        if isinstance(value, str):
            return value
        assert isinstance(value, dict) and set(value) == {'Unix'}, 'unknown native argument encoding'
        data = value['Unix']
        assert isinstance(data, list) and all(type(byte) is int and 0 <= byte <= 255 for byte in data)
        return os.fsdecode(bytes(data))
    return [decode(value) for value in [intent['program'], *intent.get('argv', [])]]


def capture_native_processes(env):
    """Import test-only creation identities before failure/timeout cleanup."""
    ledger = env.root / 'native-processes.jsonl'
    if not ledger.exists():
        return []
    lines = ledger.read_text().splitlines(keepends=True)
    assert all(line.endswith('\n') for line in lines), 'incomplete native ledger record'
    rows = [json.loads(line) for line in lines]
    intents = {row['intent']: row for row in rows if row['kind'] == 'intent'}
    started = [row for row in rows if row['kind'] == 'started']
    assert not any(row['kind'] == 'capture_failed' for row in rows), rows
    assert set(intents) == {row['intent'] for row in started}, 'unfinished native creation intent'
    known = {(row['pid'], json.dumps(row['identity'], sort_keys=True)) for row in env.entries()}
    with env.ledger.open('a') as output:
        for row in started:
            assert valid_identity(row['identity']), row
            key = row['pid'], json.dumps(row['identity'], sort_keys=True)
            if key in known:
                continue
            intent = intents[row['intent']]
            output.write(json.dumps({'schema': 2, 'pid': row['pid'], 'identity': row['identity'],
                'command': native_command(intent)}) + '\n')
            known.add(key)
        output.flush()
        os.fsync(output.fileno())
    return started


def run_seed(env, variables, sample):
    code = ("import idapro,ida_auto,ida_loader; "
            f"assert idapro.open_database({str(sample)!r},True)==0; "
            "assert ida_auto.auto_wait(); "
            "assert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB),0); "
            "idapro.close_database(); print('E23_SEED_READY')")
    command = ['timeout', '30s', str(env.root / 'venv/bin/python'), '-B', '-c', code]
    with (env.root / 'gui-seed.log').open('w') as log:
        child = env.spawn(lambda: subprocess.Popen(command, env=variables, stdout=log,
            stderr=subprocess.STDOUT), command)
        assert child.wait(timeout=32) == 0, 'seed preparation failed; see gui-seed.log'
    assert 'E23_SEED_READY' in (env.root / 'gui-seed.log').read_text()


def exercise(env, binary, result):
    from ida_nexus import discover_databases
    variables = env.variables() | {'HOME': str(env.root / 'home')}
    Path(variables['HOME']).mkdir(mode=0o700)
    gui_root = env.root / 'gui'
    gui_root.mkdir(mode=0o700)
    sample = gui_root / 'mini'
    shutil.copyfile(env.root / 'fixtures/mini', sample)
    original = hashlib.sha256(sample.read_bytes()).hexdigest()
    run_seed(env, variables, sample)
    database = sample.with_suffix('.i64')
    assert database.is_file(), 'seed must be packed before GUI opens it'
    shutil.copyfile(env.root / 'nexus-source/ida_nexus_plugin.py', gui_root / 'ida_nexus_plugin.py')
    sites = list((env.root / 'venv/lib').glob('python*/site-packages'))
    assert len(sites) == 1, 'one prepared Python site-packages required'
    variables |= {'N7C_GUI_ROOT': str(gui_root), 'N7C_GUI_SITE': str(sites[0]),
                  'IDA_IS_INTERACTIVE': '1'}
    command = [str(Path(env.manifest['ida_dir']) / 'ida'), '-A',
        '-L' + str(gui_root / 'ida.log'), '-S' + str(REPO / 'tests/support/n7_gui_owner.py'), str(database)]
    log = (gui_root / 'gui.log').open('w')
    gui = env.spawn(lambda: subprocess.Popen(command, env=variables, cwd=gui_root,
        stdout=log, stderr=subprocess.STDOUT), command)
    birth = identity(gui.pid)
    result['gui'] = {'pid': gui.pid, 'identity': birth, 'command': command}
    client = None
    try:
        ready = wait_file(gui_root / 'ready.json', gui)
        assert ready['pid'] == gui.pid and ready['gui'] is True and ready['interactive'] == '1', ready
        assert Path(ready['path']).resolve() == database
        expected = check_owner([owner_record(x.instance) for x in discover_databases()], None, gui.pid, database)
        result['before_attach'] = expected
        client = Candidate(env, binary, database, 'e23', defer_open=True,
            extra={'HOME': variables['HOME']})
        opened = client.mcp('open_idb', {'path': str(database)})
        result['open'] = {'succeeded': 'result' in opened,
            'path': opened.get('result', {}).get('path')}
        assert 'result' in opened, opened
        client.opened = opened['result']
        runtime = client.call('run_script', {'code':
            "import os,ida_loader; print(os.getpid()); print(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))"})['result']
        assert runtime['success'] and runtime['stderr'] == '', runtime
        assert runtime['stdout'].splitlines() == [str(gui.pid), str(database)], runtime
        result['attached_owner'] = check_owner([owner_record(x.instance) for x in discover_databases()], expected, gui.pid, database)
        # GUI timer performs an independent edit; a real flat CLI call reads it.
        gui_edit = gui_request(gui_root, gui, 'write', 'gui-edit.json', comment='E23_GUI_MARKER')
        assert gui_edit['comment'] == 'E23_GUI_MARKER', gui_edit
        code = f"import ida_bytes; print(ida_bytes.get_cmt({ready['address']},False))"
        read = client.direct('run_script', {'code': code})
        assert read['result']['success'] and read['result']['stdout'] == 'E23_GUI_MARKER\n', read
        # Flat CLI modifies the same scene; the GUI timer reads it back.
        code = f"import ida_bytes; assert ida_bytes.set_cmt({ready['address']},'E23_CLI_MARKER',False)"
        edited = client.direct('run_script', {'code': code})
        assert edited['result']['success'] and edited['result']['stderr'] == '', edited
        visible = gui_request(gui_root, gui, 'read', 'cli-visible.json')
        assert visible['comment'] == 'E23_CLI_MARKER', visible
        before = scene(gui_root)
        released = client.mcp('close_idb', {'close_token': client.opened['close_token']})
        assert 'result' in released, released
        client.opened = None
        lifecycle = client.last_close_lifecycle
        assert lifecycle['outcome']['release_acknowledged'] is True, lifecycle
        assert lifecycle['outcome']['ack_kind'] == 'nonlast', lifecycle
        assert lifecycle['lease_detached'] is True and lifecycle['owner_released'] is False, lifecycle
        # The public GUI owner remains after detach; no fabricated owner-exit proof.
        assert gui.poll() is None and same_process(identity(gui.pid), birth)
        after_release = gui_request(gui_root, gui, 'read', 'after-release.json')
        assert after_release['comment'] == 'E23_CLI_MARKER', after_release
        assert scene(gui_root) == before, 'lease release saved or overwrote GUI files'
        result.update(runtime=runtime, gui_to_cli=read, cli_to_gui=visible,
            release=released, lifecycle=lifecycle, after_release=after_release,
            scene_before_release=before, scene_after_release=scene(gui_root),
            surviving_owner=check_owner([owner_record(x.instance) for x in discover_databases()], expected, gui.pid, database))
        result['native_before_cleanup'] = capture_native_processes(env)
        assert result['native_before_cleanup'], 'build with --features nexus-test-support for native accounting'
        assert not any('worker' in x['command'] or 'idalib_worker' in ' '.join(x['command'])
            for x in env.entries()), 'second owner was spawned'
        assert hashlib.sha256(sample.read_bytes()).hexdigest() == original
        # The GUI has fulfilled E23. End only its recorded PID/birth; never
        # request Nexus shutdown or wait for the GUI to exit on lease release.
        entry = next(x for x in env.entries() if x['pid'] == gui.pid)
        assert entry['identity'] == birth
        assert env._stop_recorded(entry), 'dedicated GUI must still be alive before cleanup'
        gui.wait(timeout=5)
        result['gui_exit'] = {'status': gui.returncode, 'method': 'exact PID/birth TERM then bounded KILL'}
        # Public discovery reaps the now-dead GUI registration.
        assert not discover_databases(), 'GUI registration remains after exact cleanup'
        client.stop()
        client = None
    finally:
        # On failure let outer Environment cleanup handle all exact identities;
        # do not wait for owner-exit while the GUI deliberately remains alive.
        log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--cleanup', action='store_true')
    args = parser.parse_args()
    env = Environment(args.root)
    with env.exclusive():
        if args.cleanup:
            capture_native_processes(env)
            stopped = env.cleanup()
            env.assert_clean()
            print(json.dumps({'cleanup': 'PASS', 'stopped': stopped}))
            return 0
        admitted = False
        result = {'case': 'E23', 'status': 'FAIL', 'uptime_before': subprocess.check_output(['uptime'], text=True).strip()}
        try:
            if os.environ.get('IDA_TEST') != '1':
                raise Blocked('explicit IDA_TEST=1 is required')
            if args.binary is None or not args.binary.is_absolute() or not args.binary.is_file():
                raise Blocked('provide this worktree build as absolute --binary')
            if sys.platform != 'darwin':
                raise Blocked('this driver currently qualifies the macOS Qt GUI only')
            if env.ledger.exists() or (env.root / 'gui').exists():
                raise Blocked('use a freshly prepared private environment')
            if not (env.root / 'profile/.n0-isolated-profile').is_file():
                raise Blocked('isolated prepared IDAUSR required')
            patches = env.client_patch_status()
            assert all(patches[name] for name in ('applied', 'close_applied', 'sdk_applied')), patches
            os.environ.update({'IDA_NEXUS_STATE_DIR': str(env.root / 'state'),
                'N3_ENV_ROOT': str(env.root), 'N3_IPC_ROOT': str(env.root / 'ipc'), 'TMPDIR': str(env.root / 'tmp')})
            (env.root / 'native-processes.jsonl').touch(mode=0o600, exist_ok=False)
            admitted = True
            env.test_telemetry['R2_LEDGER'] = str(env.root / 'native-processes.jsonl')
            (env.root / 'ipc').mkdir(mode=0o700)
            write_json(env.root / 'ipc-root.json', str(env.root / 'ipc'))
            result['source_sha'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
            result['binary_sha256'] = hashlib.sha256(args.binary.read_bytes()).hexdigest()
            exercise(env, args.binary, result)
            result['status'] = 'PASS'
        except Blocked as error:
            result.update(status='BLOCKED', error=str(error))
        except (Exception, KeyboardInterrupt) as error:
            result.update(status='FAIL', error=str(error), traceback=traceback.format_exc())
        finally:
            try:
                if admitted:
                    result['native_processes'] = capture_native_processes(env)
                    result['cleanup_signalled'] = env.cleanup()
                    env.assert_clean()
                    result['cleanup'] = 'PASS'
                else:
                    result['cleanup'] = 'not admitted; existing environment untouched'
            except Exception:
                result.update(status='FAIL', cleanup=traceback.format_exc())
            result['uptime_after'] = subprocess.check_output(['uptime'], text=True).strip()
            evidence = env.root / ('e23-result.json' if admitted else f'e23-refused-{time.monotonic_ns()}.json')
            write_json(evidence, result)
        print(json.dumps({'case': 'E23', 'status': result['status'], 'evidence': str(evidence)}))
        return {'PASS': 0, 'FAIL': 1, 'BLOCKED': 2}[result['status']]


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise InterruptedError(f'E23 interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
