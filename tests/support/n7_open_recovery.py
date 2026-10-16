"""Real Bridge.invoke red/green tests, including pre-guard recovery corruption."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import threading
import time
import types

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'tests/support'))
from nexus_env import Environment


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--bridge', type=Path, default=REPO/'nexus_bridge/bridge.py')
    args = parser.parse_args()
    env = Environment(args.root)
    os.environ.update(env.variables())
    import ida_nexus._resolver as resolver
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions, wait_database_released
    original = subprocess.Popen
    proxy = types.SimpleNamespace(**vars(subprocess))
    proxy.Popen = lambda command, **kw: env.spawn(lambda: original(command, **kw), command)
    resolver.subprocess = proxy
    runtime = runpy.run_path(str(args.bridge), run_name='recovery_test')
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    rows, handles = {}, []
    trials = env.root/'open-tests'
    trials.mkdir()

    class Channel:
        def __init__(self):
            self.messages = []

        def send(self, value):
            self.messages.append(value)

    def invoke(path, label, losses=0, recovery_corruption=False):
        home = env.root/('home-'+label)
        home.mkdir()
        os.environ['IDA_CLI_HOME'] = str(home)
        bridge = runtime['Bridge'].__new__(runtime['Bridge'])
        bridge.Options, bridge.lock = DatabaseOpenOptions, threading.Lock()
        bridge.handles, bridge.metadata_contexts, bridge.generations = {}, {}, {}
        bridge.verification_probes, bridge.lifetimes = {}, {}
        bridge.control = Channel()
        calls = []

        def opening(path, **kwargs):
            handle = DatabaseHandle.open(path, **kwargs)
            handles.append(handle)
            calls.append(handle.instance.record_id)
            if len(calls) <= losses:
                code = "import ida_netnode\nida_netnode.netnode('Root Node', 0, False).kill()\n"
                if recovery_corruption:
                    # Model E07: malformed packed exists before the adapter guard.
                    code += "import ida_loader\nassert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)\n"
                handle.execute_python(code, timeout=5)
            return handle

        bridge.Handle = types.SimpleNamespace(open=opening)
        channel = Channel()
        try:
            bridge.invoke(channel, {'sequence': 1}, {'command': 'open', 'path': str(path),
                'options': {'auto_analysis': False},
                'identity': {'client_id': 'recovery-test', 'operation_id': label}},
                time.monotonic()+20, [False])
        except Exception as exc:
            channel.send({'event': 'exception', 'error': str(exc)})
        opened = next((m for m in channel.messages if m['event'] == 'opened'), None)
        handle = bridge.handles[opened['lease']['lease_id']][1] if opened else None
        return bridge, channel.messages, handle, calls, home

    def close(handle):
        outcome = handle.close_outcome(wait_for_database=True, timeout=8)
        assert outcome['lease_released'] and wait_database_released(handle.instance, timeout=8), outcome

    def info(handle):
        return handle.execute_python(runtime['guarded_source'](
            "import ida_nalt,ida_netnode\nresult={'root':bool(ida_netnode.netnode.exist('Root Node')),'size':ida_nalt.retrieve_input_file_size(),'path':ida_nalt.get_input_file_path()}",
            {'method': 'read-test'}), timeout=5)['result']

    try:
        # Generate the seed in this environment, through the actual bridge.
        seed_dir = trials/'seed'
        seed_dir.mkdir()
        source = seed_dir/'input'
        shutil.copyfile(env.root/'fixtures/mini', source)
        _, messages, handle, _, _ = invoke(source, 'seed')
        assert handle, messages
        assert info(handle)['root']
        handle.execute_python("import ida_loader\nassert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)", timeout=5)
        close(handle)
        seed = source.with_suffix('.i64')

        for label, losses in (('single', 1), ('three', 3), ('normal', 0)):
            trial = trials/label
            trial.mkdir()
            path = trial/'input.i64'
            shutil.copyfile(seed, path)
            before = digest(path)
            bridge, messages, handle, calls, home = invoke(path, label, losses)
            row = {'messages': messages, 'owners': calls}
            if label == 'three':
                if handle:
                    close(handle)
                row['pass'] = not handle and len(calls) == 3 and '3 attempts' in str(messages) and digest(path) == before
            else:
                row['info'] = info(handle) if handle else None
                row['pass'] = bool(handle and row['info']['root'] and row['info']['size'] > 0)
                row['pass'] &= len(calls) == (2 if losses else 1)
                if handle:
                    close(handle)
                row['pass'] &= not (home/'idb/recovery').exists()
            rows[label] = row

        trial = trials/'mid-session'
        trial.mkdir()
        path = trial/'input.i64'
        shutil.copyfile(seed, path)
        before = digest(path)
        _, messages, handle, calls, _ = invoke(path, 'mid')
        assert handle, messages
        try:
            handle.execute_python(runtime['guarded_source'](
                "import ida_netnode\nida_netnode.netnode('Root Node',0,False).kill()",
                {'method': 'mutation'}), timeout=5)
        except Exception as exc:
            protected = 'Root Node' in str(exc)
        else:
            protected = False
        close(handle)
        rows['mid'] = {'pass': protected and digest(path) == before and len(calls) == 1, 'owners': calls}

        for label, losses in (('recovery', 1), ('recovery-three', 3)):
            trial = trials/label
            trial.mkdir()
            path = trial/'input'
            shutil.copyfile(env.root/'fixtures/mini', path)
            _, messages, handle, _, _ = invoke(path, label+'-setup')
            assert handle, messages
            handle.execute_python('import ida_loader\nida_loader.flush_buffers()', timeout=5)
            instance = handle.instance
            try:
                handle.execute_python('import os\nos._exit(73)', timeout=5)
            except Exception:
                pass
            assert wait_database_released(instance, timeout=8)
            for child in env.children:
                if child.pid == instance.pid:
                    child.wait(timeout=5)
            before = {p.name: digest(p) for p in trial.iterdir() if p.is_file()}
            _, messages, handle, calls, home = invoke(path, label, losses, True)
            row = {'messages': messages, 'owners': calls, 'before': before}
            if label == 'recovery':
                row['info'] = info(handle) if handle else None
                row['pass'] = bool(handle and row['info']['root'] and row['info']['size'] > 0 and len(calls) == 2)
                if handle:
                    close(handle)
            else:
                if handle:
                    close(handle)
                after = {p.name: digest(p) for p in trial.iterdir() if p.is_file()}
                row['after'] = after
                row['pass'] = not handle and len(calls) == 3 and after == before and not path.with_suffix('.i64').exists()
            journals = list((home/'idb/recovery').glob('*/recovery.json'))
            row['snapshots'] = [json.loads(p.read_text()) for p in journals]
            row['pass'] &= len(journals) == 1 and len(list(journals[0].parent.glob('quarantine-*/input.i64'))) == losses
            rows[label] = row
    finally:
        for handle in handles:
            try:
                handle.close_outcome(wait_for_database=True, timeout=2)
            except Exception:
                pass
        env.cleanup()
        env.assert_clean()
        (env.root/'open-recovery-result.json').write_text(json.dumps(rows, indent=2)+'\n')
    print(json.dumps(rows))
    assert len(rows) == 6 and all(row['pass'] for row in rows.values()), rows


if __name__ == '__main__':
    main()
