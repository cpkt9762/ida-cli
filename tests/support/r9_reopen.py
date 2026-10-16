"""Isolated public-API save/close/new-owner experiment; JSONL keeps all trials."""
import argparse
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import types

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tests/support'))
sys.path.insert(0, str(REPO / 'nexus_bridge'))
from nexus_env import Environment
from process_identity import identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--seed', required=True, type=Path)
    parser.add_argument('--mode', choices=('immediate', 'wait'), required=True)
    parser.add_argument('--start', type=int, default=0)
    parser.add_argument('--count', type=int, default=25)
    parser.add_argument('--raw-first', action='store_true',
                        help='probe public Nexus before installing any adapter guard')
    parser.add_argument('--product-reopen', action='store_true',
                        help='exercise the product initial-open retry and rollback helper')
    args = parser.parse_args()
    if args.product_reopen and args.raw_first:
        parser.error('--raw-first cannot run with the product guard')
    env = Environment(args.root)
    os.environ.update(env.variables())
    import ida_nexus._resolver as resolver
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions, wait_database_released
    from bridge import guarded_source
    from open_recovery import open_checked

    # Account only our resolver's child creation; no client/server semantics change.
    original_popen = subprocess.Popen
    proxy = types.SimpleNamespace(**vars(subprocess))
    def popen(command, **options):
        return env.spawn(lambda: original_popen(command, **options), command)
    proxy.Popen = popen
    resolver.subprocess = proxy
    directory = env.root / 'trials' / (args.mode + '-' + str(args.start))
    directory.mkdir(parents=True, exist_ok=False)
    rows = []
    retry_events = []
    class RetryCapture(logging.Handler):
        def emit(self, record):
            marker = 'Root Node initial-open failure: '
            message = record.getMessage()
            if message.startswith(marker):
                retry_events.append(json.loads(message[len(marker):]))
                with (env.root/'retry-events.jsonl').open('a') as out:
                    out.write(json.dumps(retry_events[-1])+'\n')
    logging.getLogger('ida_cli.open').addHandler(RetryCapture())

    def opening(path):
        options = dict(auto_analysis=False, worker_env=env.variables(), worker_cwd=env.root)
        if args.product_reopen:
            handle, _, attempts = open_checked(DatabaseHandle, DatabaseOpenOptions,
                str(path), options, time.monotonic()+15, guarded_source,
                {'method': 'open-reopen-loop', 'requested_path': str(path)})
            return handle, attempts
        return DatabaseHandle.open(str(path), options=DatabaseOpenOptions(
            startup_timeout=10, **options)), 1

    def snapshot(path, pid=None):
        files = []
        for item in sorted(path.parent.iterdir()):
            try:
                value = item.lstat()
                files.append(dict(name=item.name, size=value.st_size, mtime_ns=value.st_mtime_ns,
                                  inode=value.st_ino, device=value.st_dev))
            except OSError as exc:
                files.append(dict(name=item.name, error=type(exc).__name__))
        child = next((p for p in env.children if p.pid == pid), None)
        return dict(time=time.monotonic(), files=files, previous_pid=pid,
                    previous_identity=identity(pid) if pid else None,
                    previous_exit=child.poll() if child else None)

    def components(path):
        return [p.name for p in path.parent.iterdir() if p.suffix.lower() in
                ('.id0', '.id1', '.id2', '.nam', '.til', '.idb-lock', '.i64-lock')]

    def observe(handle, path, stage, code=''):
        if args.raw_first and stage.startswith('open-'):
            raw = handle.execute_python(
                "import ida_netnode,ida_nalt,threading\n"
                "result={'root':bool(ida_netnode.netnode.exist('Root Node')),"
                "'input':ida_nalt.get_input_file_path(),'size':ida_nalt.retrieve_input_file_size(),"
                "'thread':{'current':threading.get_ident(),'main':threading.main_thread().ident}}", timeout=5)['result']
            # Persist the pre-guard result even if the following fail-closed
            # installation refuses this owner. Never save the raw failed state.
            with (env.root/'raw-first.jsonl').open('a') as out:
                out.write(json.dumps(dict(stage=stage,record_id=handle.instance.record_id,
                                          path=str(path),probe=raw))+'\n')
        source = ("import ida_netnode, ida_nalt\n" + code +
                  "\nresult = {'root': bool(ida_netnode.netnode.exist('Root Node')), "
                  "'input': ida_nalt.get_input_file_path(), 'size': ida_nalt.retrieve_input_file_size(), "
                  "'database': _r9_guard.database_context()}\n")
        return handle.execute_python(guarded_source(source, {
            'method': stage, 'requested_path': str(path),
            'record_id': handle.instance.record_id, 'deadline': time.monotonic()+5}), timeout=6)['result']

    def close(handle, path):
        instance = handle.instance
        handle.execute_python(guarded_source('pass', {'method': 'close',
            'requested_path': str(path), 'record_id': instance.record_id,
            'deadline': time.monotonic()+5}, refuse=False), timeout=6)
        outcome = handle.close_outcome(wait_for_database=True, timeout=10)
        released = wait_database_released(instance, timeout=10)
        assert released, (instance.record_id, outcome)
        return dict(outcome=outcome, released=released, snapshot=snapshot(path, instance.pid))

    try:
        for number in range(args.start, args.start + args.count):
            trial = directory / str(number)
            trial.mkdir()
            path = trial / 'input.i64'
            shutil.copyfile(args.seed, path)
            row = dict(number=number, mode=args.mode, path=str(path), status='ERROR')
            handle = None
            try:
                row['before_a'] = snapshot(path)
                handle, row['a_open_attempts'] = opening(path)
                first_pid = handle.instance.pid
                row['a_pid'] = first_pid
                row['a'] = observe(handle, path, 'open-a')
                row['a_saved'] = observe(handle, path, 'save-a',
                    "import ida_bytes, ida_ida, ida_loader\n"
                    f"assert ida_bytes.set_cmt(ida_ida.inf_get_min_ea(), 'r9 trial {number}', False)\n"
                    "assert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)\n")
                row['a_close'] = close(handle, path)
                handle = None
                if args.mode == 'wait':
                    deadline = time.monotonic() + 5
                    while components(path) or identity(first_pid) is not None:
                        assert time.monotonic() < deadline, 'previous owner/components did not disappear'
                        time.sleep(.005)
                row['before_b'] = snapshot(path, first_pid)
                handle, row['b_open_attempts'] = opening(path)
                row['b_pid'] = handle.instance.pid
                assert row['b_pid'] != first_pid, 'new owner was not created'
                row['b'] = observe(handle, path, 'open-b')
                assert row['b']['root'] and row['b']['size'] > 0, row['b']
                row['b_close'] = close(handle, path)
                handle = None
                row['status'] = 'PASS'
            except Exception as exc:
                row.update(error_type=type(exc).__name__, error=str(exc))
                if handle is not None:
                    try:
                        row['failure'] = handle.execute_python(
                            "import sys\ng=sys.modules.get('_ida_cli_save_guard_v1')\n"
                            "result=g._state['first_failure'] if g else None", timeout=5)['result']
                        raw = handle.execute_python(
                            "import ida_loader\nfrom pathlib import Path\n"
                            "p=Path(ida_loader.get_path(ida_loader.PATH_TYPE_ID0))\n"
                            "result={'path':str(p),'data':p.read_bytes().hex()}", timeout=5)['result']
                        capture = trial/'active-component.id0'
                        capture.write_bytes(bytes.fromhex(raw['data']))
                        row['active_id0_capture'] = {'source':raw['path'],'copy':str(capture),
                            'scope':'on-disk bytes before close; IDA buffers may be unflushed'}
                    except Exception as diagnostic:
                        row['diagnostic_error'] = type(diagnostic).__name__
                    row['status'] = 'ROOT_FAILURE' if row.get('failure') else 'ERROR'
            finally:
                if handle is not None:
                    row['failed_close'] = close(handle, path)
                row['after'] = snapshot(path)
                rows.append(row)
                with (env.root/'reopen-trials.jsonl').open('a') as out:
                    out.write(json.dumps(row)+'\n')
                print(json.dumps({k:row[k] for k in ('number','mode','status')}), flush=True)
    finally:
        for child in env.children:
            child.poll()
        cleanup = env.cleanup()
        env.assert_clean()
        result = dict(mode=args.mode, start=args.start, trials=len(rows),
                      root_failures=sum(r['status']=='ROOT_FAILURE' for r in rows),
                      errors=sum(r['status']=='ERROR' for r in rows), cleanup=cleanup,
                      product_reopen=args.product_reopen,
                      natural_initial_failures=len(retry_events),
                      failures_after_retries=sum(r['status'] != 'PASS' for r in rows),
                      successful_opens=sum('a' in r for r in rows)+sum('b' in r for r in rows))
        (directory/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result), flush=True)
    assert len(rows)==args.count and not result['errors'], result
    if args.product_reopen:
        assert not result['failures_after_retries'], result


if __name__ == '__main__':
    main()
