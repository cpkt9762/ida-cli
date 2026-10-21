"""Real release profile/cache checks; all inputs, processes and sockets are private."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'tests/support'), str(REPO/'scripts')]
from compare_nexus_baseline import Candidate
from nexus_env import Environment
from process_identity import identity


def children(pid):
    """Enumerate children of one recorded PID, never by executable name."""
    lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    lib.proc_listchildpids.restype = ctypes.c_int
    values = (ctypes.c_int * 1024)()
    count = lib.proc_listchildpids(pid, values, ctypes.sizeof(values))
    # The helper returns a PID count, unlike lower-level proc_listpids bytes.
    assert 0 <= count < len(values), (pid, count)
    return [value for value in values[:count] if value > 0]


def capture(env, daemon, ipc):
    assert identity(daemon) is not None, 'recorded daemon exited before capture'
    known = {row['pid'] for row in env.entries()}
    pending, seen = [daemon], set()
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        current = identity(pid)
        if current is None:
            # proc_listchildpids includes zombies. The existing identity API
            # treats SZOMB/ESRCH as exited; require a prior birth, never adopt an
            # unknown vanished process as accounted for.
            assert pid in known, ('process disappeared before birth capture', pid)
            seen.add(pid)
            continue
        seen.add(pid)
        env._record(type('Owned', (), {'pid': pid})(), ['observed-live-descendant', str(daemon), str(pid)])
        pending.extend(children(pid))
    bindings = [(path, daemon) for path in ipc.rglob('*') if path.name in ('b', 'c') and path.is_socket()]
    for path in ipc.rglob('h'):
        state = json.loads((path.parent/'helper-state.json').read_text())
        # The durable file binds the helper incarnation; the public heartbeat
        # supplies the exact process identity below, not a filename guess.
        assert state['helper']
    return seen, bindings


def install_wrapper(env, sbx):
    ledger = env.root/'sbx-calls.jsonl'
    wrapper = env.root/'record-sbx'
    idat = env.root/'record-idat'
    shared = ('import json, os, sys\nfrom pathlib import Path\n'
              f'sys.path.insert(0,{str(REPO/"tests/support")!r})\n'
              'from process_identity import identity\n'
              f'ledger=Path({str(ledger)!r})\n'
              "row={'kind':KIND,'pid':os.getpid(),'identity':identity(os.getpid()),'argv':sys.argv[1:],'cwd':os.getcwd(),'LITESVM_DEX_DIR':os.environ.get('LITESVM_DEX_DIR')}\n"
              'assert row["identity"] is not None\n'
              "with ledger.open('a') as output: output.write(json.dumps(row)+'\\n')\n")
    wrapper.write_text('#!'+str(env.root/'venv/bin/python')+'\nKIND="sbx"\n'+shared+
        'variables=os.environ.copy()\nvariables.pop("IDADIR",None)\n'+
        f'variables["IDAT"]={str(idat)!r}\n'+
        f'os.execve({str(sbx)!r},[{str(sbx)!r},*sys.argv[1:]],variables)\n')
    actual_idat = Path(env.manifest['ida_dir'])/'idat'
    idat.write_text('#!'+str(env.root/'venv/bin/python')+'\nKIND="idat"\n'+shared+
        f'os.execv({str(actual_idat)!r},[{str(actual_idat)!r},*sys.argv[1:]])\n')
    wrapper.chmod(0o700)
    idat.chmod(0o700)
    return wrapper, ledger


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sample', type=Path, required=True)
    parser.add_argument('--sbx', type=Path, required=True)
    parser.add_argument('--profile', choices=('default','analysis-inline','trace','optimized','invalid'), required=True)
    args = parser.parse_args()
    env = Environment(args.root)
    result_path = env.root/f'profile-{args.profile}.json'
    assert not result_path.exists(), 'profile case already used'
    env.assert_clean()
    workspace = env.root/'workspace'
    workspace.mkdir(mode=0o700, exist_ok=True)
    (workspace/'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
    source = env.root/'fixtures/program.so'
    if not source.exists():
        shutil.copyfile(args.sample, source)
    cache = env.root/'profile-cache'
    cache.mkdir(mode=0o700, exist_ok=True)
    wrapper, ledger = install_wrapper(env, args.sbx.resolve(strict=True))
    before = len(rows(ledger))
    profile = 'fast' if args.profile == 'invalid' else args.profile
    extra = {'SBX': str(wrapper)}
    if profile != 'default':
        extra['IDA_CLI_SBX_PROFILE'] = profile
    os.environ.update(N3_IPC_ROOT=str(env.root/'i'), TMPDIR=str(env.root/'tmp'))
    real_popen = subprocess.Popen
    launches = []
    def spawn(argv, *positional, **options):
        if argv[:2] == [str(args.binary), 'serve-http']:
            options['cwd'] = workspace
            options['env'] = dict(options['env'])
            options['env'].pop('IDA_NEXUS_BRIDGE_SCRIPT', None)
            launches.append(str(workspace))
        return real_popen(argv, *positional, **options)
    client = None
    held_tokens = set()
    result = {'profile': args.profile, 'status': 'FAIL', 'server_cwd': str(workspace)}
    try:
        with patch.object(subprocess, 'Popen', spawn):
            client = Candidate(env, args.binary, env.root/'fixtures/mini', args.profile, extra=extra, cache=cache)
        assert launches == [str(workspace)], launches
        daemon = client.process.child.pid
        ipc = Path(client.variables['IDA_NEXUS_IPC_ROOT'])
        seen, bindings = capture(env, daemon, ipc)
        for path, owner in bindings:
            env.record_socket(path, owner)
        first = client.mcp('open_idb', {'path': str(source)})
        if args.profile in ('optimized', 'invalid'):
            assert 'error' in first, first
            needle = 'IDA_CLI_SBX_PROFILE' if args.profile == 'invalid' else 'optimized'
            assert needle in first['error'], first
            assert args.profile == 'invalid' or ('sbx aot i64' in first['error'] and 'stderr:' in first['error']), first
            result['error'] = first
        else:
            assert 'result' in first, first
            opened = first['result']
            held_tokens.add(opened['close_token'])
            functions = client.mcp('list_functions', {'db_handle': opened['db_handle']})
            assert functions['result']['functions'], functions
            entry = client.mcp('get_function_by_name', {'db_handle': opened['db_handle'], 'name':'entrypoint'})
            assert 'result' in entry, entry
            code = client.mcp('decompile_function', {'db_handle':opened['db_handle'], 'address':entry['result']['address']})
            assert code['result']['code'].strip(), code
            more, _ = capture(env, daemon, ipc)
            seen |= more
            assert client.mcp('close_idb', {'close_token':opened['close_token']}).get('result')
            held_tokens.remove(opened['close_token'])
            second = client.mcp('open_idb', {'path':str(source)})
            if 'result' in second:
                held_tokens.add(second['result']['close_token'])
            assert second['result']['path'] == opened['path'], second
            more, _ = capture(env, daemon, ipc)
            seen |= more
            assert client.mcp('close_idb', {'close_token':second['result']['close_token']}).get('result')
            held_tokens.remove(second['result']['close_token'])
            result.update(path=opened['path'], function_count=functions['result']['total'], decompile=code)
            if args.profile == 'default':
                # A later client environment cannot change the running server.
                client.sample = source
                client.variables['IDA_CLI_SBX_PROFILE'] = 'trace'
                assert client.direct('list_functions', {'limit':1})['result']['functions']
                more, _ = capture(env, daemon, ipc)
                seen |= more
                assert client.control('close', {'path':str(source)})['ok'] is True
                client.sample = env.root/'fixtures/mini'
                result['client_environment_cannot_override_server'] = True
        calls = rows(ledger)[before:]
        sbx_calls = [row for row in calls if row['kind']=='sbx']
        assert len(sbx_calls) == (0 if args.profile=='invalid' else 1), calls
        if sbx_calls:
            expected = 'analysis' if args.profile in ('default','analysis-inline') else args.profile
            argv = sbx_calls[0]['argv']
            assert argv[argv.index('--profile')+1] == expected, argv
            assert ('--inline' in argv) == (args.profile=='analysis-inline'), argv
            stage = Path(sbx_calls[0]['cwd'])
            assert stage.is_relative_to(cache) and stage.name.startswith('.n2-prepare-'), sbx_calls
            assert Path(sbx_calls[0]['LITESVM_DEX_DIR']).resolve() == stage/'sbx-cache'
        for row in calls:
            with env.ledger.open('a') as output:
                output.write(json.dumps({'schema':2,'pid':row['pid'],'identity':row['identity'],'command':[row['kind'],*row['argv']]})+'\n')
        result.update(sbx_calls=len(sbx_calls), calls=calls, captured_pids=sorted(seen))
        assert not (workspace/'target-aot').exists()
        client.stop()
        client = None
        env.assert_clean()
        assert not list((env.root/'state/instances').glob('*.json')), 'Nexus registrations remain'
        assert not [p for p in env.root.rglob('*') if stat.S_ISSOCK(p.lstat().st_mode)]
        result['status'] = 'PASS'
    except Exception as error:
        result['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        try:
            if client is not None:
                for token in held_tokens:
                    reply = client.mcp('close_idb', {'close_token':token})
                    assert 'result' in reply, reply
                client.stop()
        finally:
            result_path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'profile':args.profile,'sbx_calls':result['sbx_calls']}))


if __name__ == '__main__':
    main()
