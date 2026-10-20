"""Prove automatic save/close hooks on private real IDA owners before writeback."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'tests/support'), str(REPO / 'nexus_bridge'),
                str(REPO / 'nexus_bridge/custody')]
from nexus_env import Environment
from bridge import guarded_source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--seed', type=Path, required=True)
    args = parser.parse_args()
    env = Environment(args.root)
    os.environ.update(env.variables())
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions
    original_popen = subprocess.Popen
    import ida_nexus._resolver as resolver
    import types
    proxy = types.SimpleNamespace(**vars(subprocess))
    proxy.Popen = lambda argv, **kw: env.spawn(lambda: original_popen(argv, **kw), argv)
    resolver.subprocess = proxy
    results = []
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    handle = None
    with env.exclusive():
        try:
            for poisoned in (False, True):
                label = 'poisoned' if poisoned else 'healthy'
                path = env.root / 'fixtures' / (label + '.i64')
                trace = env.root / (label + '-hooks.jsonl')
                shutil.copyfile(args.seed, path)
                before = digest(path)
                handle = DatabaseHandle.open(path, options=DatabaseOpenOptions(
                    auto_analysis=False, startup_timeout=30,
                    worker_env=env.variables(), worker_cwd=env.root))
                context = {'method': 'r7a-automatic-hook-probe', 'record_id': handle.instance.record_id}
                assert handle.execute_python(guarded_source('result=True', context), timeout=10)['result'] is True
                code = '''import sys,json,time,ida_loader,ida_bytes,ida_ida,idapro
_guard=sys.modules['_ida_cli_save_guard_v1']
_trace=TRACE

def _record(stage,**extra):
    row={'stage':stage,'monotonic':time.monotonic(),
         'temp':ida_loader.is_database_flag(ida_loader.DBFL_TEMP),
         'kill':ida_loader.is_database_flag(ida_loader.DBFL_KILL)}
    row.update(extra)
    with open(_trace,'a') as output: output.write(json.dumps(row)+'\\n')

_hook_type=type(_guard._state['hook'])
for _name in ('savebase','closebase'):
    def _wrap(name,original):
        def wrapped(self):
            _record(name+'_before')
            value=original(self)
            _record(name+'_after')
            return value
        return wrapped
    setattr(_hook_type,_name,_wrap(_name,getattr(_hook_type,_name)))
_original_close=idapro.close_database
def _close(save=True):
    _record('native_close_enter',save=save)
    value=_original_close(save)
    with open(_trace,'a') as output: output.write(json.dumps({'stage':'native_close_return','monotonic':time.monotonic()})+'\\n')
    return value
idapro.close_database=_close
assert ida_bytes.set_cmt(ida_ida.inf_get_min_ea(),'r7a-hook-write',False)
_record('edited_before_external_loss')
'''.replace('TRACE', repr(str(trace)))
                if poisoned:
                    # A direct external writer bypasses adapter before/after samples.
                    # The subsequent automatic close must independently detect loss.
                    code += "import ida_netnode\nida_netnode.netnode('Root Node',0,False).kill()\n_record('external_loss_before_close')\n"
                code += 'result=True\n'
                assert handle.execute_python(code, timeout=10)['result'] is True
                outcome = handle.close_outcome(wait_for_database=True, timeout=30)
                handle = None
                assert outcome['lease_released'] and outcome['owner_released'], outcome
                events = [json.loads(line) for line in trace.read_text().splitlines()]
                entries = [event for event in events if event['stage'] == 'native_close_enter']
                assert len(entries) == 1 and entries[0]['save'] is True, events
                after = digest(path)
                if poisoned:
                    assert before == after, 'automatic save overwrote the last healthy packed database'
                    loss = next(event for event in events if event['stage'] == 'external_loss_before_close')
                    assert not loss['temp'] and not loss['kill'], events
                    hooks = [event for event in events if event['stage'] in ('savebase_after', 'closebase_after')]
                    assert hooks and all(event['temp'] and event['kill'] for event in hooks), events
                else:
                    assert before != after, 'healthy automatic close failed to persist edit'
                handle = DatabaseHandle.open(path, options=DatabaseOpenOptions(
                    auto_analysis=False, startup_timeout=30, worker_env=env.variables(), worker_cwd=env.root))
                read = handle.execute_python("import ida_ida,ida_bytes\nresult=ida_bytes.get_cmt(ida_ida.inf_get_min_ea(),False)", timeout=10)['result']
                assert (read != 'r7a-hook-write') if poisoned else (read == 'r7a-hook-write'), read
                closed = handle.close_outcome(wait_for_database=True, timeout=30)
                handle = None
                assert closed['lease_released'] and closed['owner_released'], closed
                results.append({'case': label, 'before': before, 'after': after,
                                'events': events, 'read_back': read, 'close': outcome})
        finally:
            if handle is not None:
                handle.close_outcome(wait_for_database=True, timeout=10)
            forced = env.cleanup()
            env.assert_clean()
            (env.root / 'automatic-hooks-result.json').write_text(json.dumps(
                {'cases': results, 'cleanup_signalled': forced}, indent=2) + '\n')
    assert len(results) == 2 and not forced, results
    print(json.dumps({'automatic_hooks': 'PASS', 'cases': len(results)}))


if __name__ == '__main__':
    main()
