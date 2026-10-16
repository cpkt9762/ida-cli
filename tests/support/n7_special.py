"""Real N7a owners, public probes and product cache/preparation paths."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'scripts'), str(REPO/'nexus_bridge'), str(REPO/'tests/support')]
from nexus_env import Environment
from compare_nexus_baseline import Candidate, Lines
from cache_store import Store


def wait_for(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, 'marker deadline'
        time.sleep(.005)


class External:
    def __init__(self, env, path, *, rejected=False):
        variables = env.variables() | {'N3_ENV_ROOT':str(env.root)}
        command = [str(env.root/'venv/bin/python'), str(REPO/'tests/support/nexus_client_fixture.py'), 'external', str(path)]
        self.log = (env.root/f'external-{path.parent.name}-{time.monotonic_ns()}.log').open('w')
        self.child = env.spawn(lambda: subprocess.Popen(command, env=variables,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log), command)
        self.lines = Lines(self.child.stdout)
        if rejected:
            assert self.child.wait(timeout=12) == 1
            self.log.close()
            text = Path(self.log.name).read_text()
            assert 'FileNotFoundError' in text, text
        else:
            assert self.lines.json()['event'] == 'external_opened'

    def close(self):
        if self.child.poll() is None:
            self.child.stdin.write(b'{"command":"close"}\n'); self.child.stdin.flush()
            assert self.lines.json()['event'] == 'external_closed'
            assert self.child.wait(timeout=12) == 0
        self.log.close()


def idb_path(client):
    result = client.call('run_script', {'code':"import ida_loader; print(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))"})['result']
    assert result['success'], result
    return Path(result['stdout'].strip())


def close(client):
    result = client.mcp('close_idb', {'close_token':client.opened['close_token']})
    assert 'result' in result, result
    client.opened = None


def cache_case(env, binary, case):
    client = Candidate(env, binary, env.root/'fixtures/mini', case)
    external = None
    try:
        original = idb_path(client)
        assert original.parent.parent.name == 'generations', original
        close(client)
        initial = hashlib.sha256(original.read_bytes()).hexdigest()
        store = Store(client.home/'idb', grace=.03, epoch=case)
        evidence = []
        if case == 'E21-held':
            external = External(env, original)
            result = store.collect(0)
            assert result['rejected'] and original.exists(), result
            assert hashlib.sha256(original.read_bytes()).hexdigest() == initial
            refreshed = client.mcp('open_idb', {'path':str(client.sample), 'force':True})
            assert 'result' in refreshed, refreshed
            client.opened = refreshed['result']
            fresh = idb_path(client)
            assert fresh != original and original.exists()
            assert hashlib.sha256(original.read_bytes()).hexdigest() == initial
            close(client)
            evidence.append({'held_refusal':result, 'fresh_generation':str(fresh), 'original_sha256':initial})
            external.close(); external = None
        elif case in ('E21-before-rename', 'E21-after-rename', 'E21-before-delete'):
            phase = case.removeprefix('E21-').replace('-', '_')
            def hook(at, source, isolated):
                nonlocal external
                if at != phase:
                    return
                assert hashlib.sha256((source if source.exists() else isolated).joinpath('input.i64').read_bytes()).hexdigest() == initial
                external = External(env, source/'input.i64', rejected=at != 'before_rename')
                evidence.append({'barrier':at, 'opener':'opened' if at == 'before_rename' else 'FileNotFoundError', 'source':str(source)})
            store.hook = hook
            first = store.collect(0)
            if phase == 'before_delete':
                wait_for(lambda: time.time() - json.loads((store.quarantine/original.parent.name/'quarantine.json').read_text())['since'] >= .03)
                store.collect(0)
            if phase == 'before_rename':
                assert original.exists() and first['rejected'], first
            assert len(evidence) == 1, evidence
            if external:
                external.close(); external = None
        else:
            store.collect(0)
            isolated = store.quarantine/original.parent.name
            assert isolated.exists() and not original.exists()
            wait_for(lambda: time.time() - json.loads((isolated/'quarantine.json').read_text())['since'] >= .03)
            result = store.collect(0)
            assert result['evicted_groups'] == 1 and not isolated.exists(), result
            reopened = client.mcp('open_idb', {'path':str(client.sample)})
            assert 'result' in reopened, reopened
            client.opened = reopened['result']
            assert idb_path(client) != original
            evidence.append({'collected':result, 'reopened':True})
        return evidence
    finally:
        if external:
            external.close()
        client.stop()


def cancellation(env, binary):
    processor = env.root/'fixtures/processor'
    processor.write_text('#!' + str(env.root/'venv/bin/python') + '\n' +
        (REPO/'tests/support/n7_input_processor.py').read_text().replace(
            "str(Path(__file__).resolve().parent)", repr(str(REPO/'tests/support'))))
    processor.chmod(0o700)
    blocked = env.root/'fixtures/blocked-native'
    shutil.copyfile(env.root/'fixtures/mini', blocked)
    client = Candidate(env, binary, env.root/'fixtures/mini', 'E19', extra={'IDA_NEXUS_INPUT_PREPROCESSOR':str(processor)})
    try:
        # Socket requests use explicit paths; the real route queue owns Preparation.
        previous = client.sample
        client.sample = blocked
        task = client.direct('enqueue', {'method':'list_functions'})['result']['task_id']
        client.sample = previous
        wait_for(lambda: (env.root/'processor.started').exists() and (env.root/'descendant.ready').exists())
        started = json.loads((env.root/'processor.started').read_text())
        assert client.direct('status', {})['result']['worker_count'] >= 1
        assert client.call('list_functions', {})['result']['functions']
        cancel = client.direct('cancel_task', {'task_id':task})
        assert 'result' in cancel, cancel
        states = []
        def terminal():
            state = client.direct('task_status', {'task_id':task})['result']
            states.append(state)
            return state['status'] in ('cancelled', 'failed', 'completed')
        wait_for(terminal)
        assert states[-1]['status'] == 'cancelled', states[-1]
        def exited(pid):
            from process_identity import identity
            return identity(pid) is None
        wait_for(lambda: exited(started['pid']) and exited(started['descendant']))
        assert not Path(started['output']).exists(), started
        assert client.call('list_functions', {})['result']['functions']
        assert not list((client.home/'idb').glob('.n2-prepare-*'))
        return {'terminal':states[-1], 'owned_tree_exited':True, 'unpublished_output':True}
    finally:
        client.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--case', required=True)
    args = parser.parse_args()
    env = Environment(args.root)
    result = {'case':args.case, 'status':'FAIL'}
    try:
        result['evidence'] = cancellation(env, args.binary) if args.case == 'E19' else cache_case(env, args.binary, args.case)
        result['status'] = 'PASS'
    finally:
        (env.root/f'{args.case}-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
