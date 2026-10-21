"""Real E24/E25 cases. Every sample and output belongs to one fresh environment."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'scripts'), str(REPO/'tests/support')]
from compare_nexus_baseline import Candidate
from nexus_env import Environment


def e24(env, binary, sample):
    copied = env.root/'fixtures/program.so'
    shutil.copyfile(sample, copied)
    client = Candidate(env, binary, env.root/'fixtures/mini', 'E24',
                       extra={'SBX': shutil.which('sbx') or str(Path.home()/'.cargo/bin/sbx')})
    try:
        response = client.mcp('open_idb', {'path': str(copied)})
        assert 'result' in response, response
        first = response['result']
        runtime = client.control('status')['metadata']['ida_version']
        assert runtime == env.manifest['installed_ida_version'], runtime
        functions = client.mcp('list_functions', {'db_handle': first['db_handle']})
        assert functions['result']['functions'], functions
        entry = client.mcp('get_function_by_name', {'db_handle': first['db_handle'], 'name': 'entrypoint'})
        assert 'result' in entry, entry
        code = client.mcp('decompile_function', {'db_handle': first['db_handle'], 'address': entry['result']['address']})
        assert code['result']['code'].strip(), code
        close = client.mcp('close_idb', {'close_token': first['close_token']})
        assert 'result' in close, close
        lifecycle = client.last_close_lifecycle
        proof = client.control('wait_owner_exit', {'owner_observation_ref': lifecycle['owner_observation_ref'], 'timeout_secs': 20})
        assert proof['owner_released'], proof
        second = client.mcp('open_idb', {'path': str(copied)})
        assert 'result' in second and second['result']['path'] == first['path'], second
        assert client.mcp('close_idb', {'close_token': second['result']['close_token']}).get('result')
        return {'first': first, 'reopen': second, 'entry': entry, 'decompile': code, 'ida_version': runtime}
    finally:
        client.stop()


def wait_until(predicate, seconds=280):
    deadline = time.monotonic() + seconds
    while True:
        value = predicate()
        if value:
            return value
        assert time.monotonic() < deadline, 'special-input barrier deadline'
        time.sleep(.01)


def release(client, opened):
    reply = client.mcp('close_idb', {'close_token': opened['close_token']})
    assert 'result' in reply, reply
    lifecycle = client.last_close_lifecycle
    proof = client.control('wait_owner_exit', {'owner_observation_ref': lifecycle['owner_observation_ref'], 'timeout_secs': 20})
    assert proof['owner_released'], proof


def cache_disk_usage(cache):
    seen = set()
    allocated = logical = payload = 0
    for path in cache.rglob('*'):
        meta = path.lstat()
        if not path.is_file() or path.is_symlink() or (meta.st_dev, meta.st_ino) in seen:
            continue
        seen.add((meta.st_dev, meta.st_ino))
        allocated += meta.st_blocks * 512
        logical += meta.st_size
        if 'dsc-inputs' in path.parts or path.name == 'data' and path.parent.parent.name == 'dsc-members':
            payload += meta.st_size
    return {'unique_file_bytes': logical, 'allocated_file_bytes': allocated, 'unique_member_bytes': payload}


def e25(env, binary, sample):
    module = '/usr/lib/system/libsystem_blocks.dylib'
    client = Candidate(env, binary, env.root/'fixtures/mini', 'E25')
    original_mcp = client.mcp
    def recorded(method, params):
        response = original_mcp(method, params)
        with (env.root/'E25-responses.jsonl').open('a') as out:
            out.write(json.dumps({'method': method, 'params': params, 'response': response})+'\n')
        return response
    client.mcp = recorded
    states = []
    checked_running = set()
    opened = None
    try:
        request = {'path': str(sample), 'arch': 'arm64e', 'module': module}
        build_started = time.monotonic()
        started = client.mcp('open_dsc', request)
        assert started['result']['status'] == 'started', started
        task_id = started['result']['task_id']
        def terminal():
            state = client.mcp('get_task_status', {'task_id': task_id})['result']
            states.append(state)
            assert state['status'] not in ('failed', 'cancelled'), state
            with (env.root/'E25-task-states.jsonl').open('a') as out:
                out.write(json.dumps(state)+'\n')
            if state['status'] == 'running' and task_id not in checked_running:
                healthy = client.mcp('list_functions', {'db_handle': client.opened['db_handle'], 'limit': 1})
                assert 'result' in healthy and healthy['result']['functions'], healthy
                checked_running.add(task_id)
            return state if state['status'] == 'completed' else None
        done = wait_until(terminal)
        build_seconds = time.monotonic() - build_started
        assert task_id in checked_running, 'new DSC build must expose a running task'
        opened = done['result']
        assert opened['db_handle'] != client.opened['db_handle'], opened
        functions = client.mcp('list_functions', {'db_handle': opened['db_handle'], 'limit': 2})
        assert functions['result']['functions'], functions
        added = client.mcp('dsc_add_dylib', {'db_handle': opened['db_handle'], 'module': '/usr/lib/system/libsystem_kernel.dylib', 'timeout_secs': 30})
        assert 'result' in added and added['result']['success'] is True, added
        query = client.mcp('run_script', {'db_handle': opened['db_handle'], 'code': 'import ida_loader, ida_nalt\nprint(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))\nprint(ida_nalt.get_input_file_path())'})
        assert 'result' in query and query['result']['success'] is True, query
        assert '/dsc-inputs/' in query['result']['stdout'], query
        first_path = Path(opened['path'])
        release(client, opened)
        opened = None
        # Existing packed database: no offline build, ordinary Nexus open.
        existing = client.mcp('open_dsc', request | {'path': str(first_path)})
        assert 'result' in existing and 'task_id' not in existing['result'], existing
        opened = existing['result']
        assert Path(opened['path']) == first_path, existing
        assert client.mcp('list_functions', {'db_handle': opened['db_handle'], 'limit': 1})['result']['functions']
        release(client, opened)
        opened = None
        # Same source/module: the original generation is reused.
        reopen_started = time.monotonic()
        reopened = client.mcp('open_dsc', request)
        task_id = reopened['result']['task_id']
        again = wait_until(terminal)
        reopen_seconds = time.monotonic() - reopen_started
        opened = again['result']
        assert Path(opened['path']) == first_path, again
        release(client, opened)
        opened = None
        return {'module': module, 'source': str(sample), 'started': started, 'states': states, 'query': query, 'added': added, 'existing': existing, 'reopen': again,
                'timing': {'new_build_seconds': build_seconds, 'cache_hit_reopen_seconds': reopen_seconds},
                'disk': cache_disk_usage(client.home/'idb')}
    finally:
        if opened:
            release(client, opened)
        client.stop()


def e24_cancel(env, binary, sample):
    copied = env.root/'fixtures/cancel-program.so'
    shutil.copyfile(sample, copied)
    for mode in ('sbx', 'idat'):
        shim = env.root/f'fixtures/{mode}-barrier'
        shim.write_text('#!'+str(env.root/'venv/bin/python')+'\n'
            + 'import runpy, sys\n'
            + f'sys.argv.insert(1, {mode!r})\n'
            + f'runpy.run_path({str(REPO/"tests/support/n7b_offline_barrier.py")!r}, run_name="__main__")\n')
        shim.chmod(0o700)
    os.mkfifo(env.root/'cancel-idat.release', 0o600)
    real_sbx = shutil.which('sbx') or str(Path.home()/'.cargo/bin/sbx')
    client = Candidate(env, binary, env.root/'fixtures/mini', 'E24-cancel', extra={
        'SBX': str(env.root/'fixtures/sbx-barrier'), 'N7B_REAL_SBX': real_sbx,
        'N7B_REAL_IDAT': str(Path(env.manifest['ida_dir'])/'idat')})
    try:
        previous = client.sample
        client.sample = copied
        task = client.direct('enqueue', {'method': 'list_functions'})['result']['task_id']
        client.sample = previous
        wait_until(lambda: (env.root/'cancel-idat.started').exists(), 90)
        sbx = json.loads((env.root/'cancel-sbx.started').read_text())
        idat = json.loads((env.root/'cancel-idat.started').read_text())
        assert client.mcp('list_functions', {'db_handle': client.opened['db_handle'], 'limit': 1})['result']['functions']
        assert 'result' in client.direct('cancel_task', {'task_id': task})
        states = []
        def terminal():
            state = client.direct('task_status', {'task_id': task})['result']
            states.append(state)
            return state if state['status'] in ('cancelled', 'failed', 'completed') else None
        stopped = wait_until(terminal, 20)
        assert stopped['status'] == 'cancelled' and stopped['meta']['execution_stopped'] is True, stopped
        from process_identity import identity
        wait_until(lambda: identity(sbx['pid']) is None and identity(idat['pid']) is None, 15)
        assert not Path(sbx['output']).exists(), sbx
        assert not list((client.home/'idb').rglob('.n2-prepare-*'))
        assert not list((env.root/'tmp').glob('sbpf_emit_i64_*')), 'cancelled sbx must not leak its temp inputs'
        cancelled_database = Path(sbx['output']).parent.parent/'input.i64'
        assert not cancelled_database.exists(), cancelled_database
        assert client.mcp('list_functions', {'db_handle': client.opened['db_handle'], 'limit': 1})['result']['functions']
        return {'sbx': sbx, 'actual_idat': idat, 'terminal': stopped,
                'owned_tree_exited': True, 'unpublished_output': True, 'healthy_database_usable': True}
    finally:
        client.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--case', choices=('E24', 'E24-cancel', 'E25'), required=True)
    parser.add_argument('--sample', type=Path, required=True)
    args = parser.parse_args()
    env = Environment(args.root)
    os.environ.update(N3_IPC_ROOT=str(env.root/'i'), TMPDIR=str(env.root/'tmp'))
    result = {'case': args.case, 'status': 'FAIL'}
    try:
        result['evidence'] = {'E24': e24, 'E24-cancel': e24_cancel, 'E25': e25}[args.case](env, args.binary, args.sample)
        result['status'] = 'PASS'
    finally:
        try:
            env.cleanup()
            env.assert_clean()
            result['cleanup'] = 'CLEAN'
        finally:
            (env.root/f'{args.case}-result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'case': args.case, 'status': result['status']}))


if __name__ == '__main__':
    main()
