#!/usr/bin/env python3
"""One bounded release case through real product processes in private directories."""
import argparse
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
CARGO = shutil.which('cargo')
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / 'tests'), str(REPO / 'tests/support'), str(REPO / 'scripts')]
from nexus_env import Environment
from process_identity import identity, same_process
from compare_nexus_baseline import BASELINE_SHA, digest, Process, unwrap_cache
from verify_nexus_gui import capture_native_processes
from test_nexus_removed_config import REMOVED


def capture(env):
    deadline=time.monotonic()+3
    while True:
        try:
            rows = capture_native_processes(env, env.native_ledger)
            break
        except AssertionError as error:
            if str(error) != 'unfinished or duplicate native creation intent':raise
            records=[json.loads(line) for line in env.native_ledger.read_text().splitlines()]
            intents={row['intent'] for row in records if row['kind']=='intent'}
            terminals=[row['intent'] for row in records if row['kind'] in ('started','spawn_failed')]
            if len(set(terminals))!=len(terminals) or set(terminals)-intents or time.monotonic()>=deadline:raise
            if intents-set(terminals):time.sleep(.01)  # Wait only for recorded creation intents, never guess successful cleanup.
    sockets=env.root/'sockets.jsonl'
    known={line for line in sockets.read_text().splitlines()} if sockets.exists() else set()
    with sockets.open('a') as output:
        for line in env.native_ledger.read_text().splitlines():
            row=json.loads(line)
            if row['kind']!='socket_bound':continue
            assert Path(row['path']).is_relative_to(env.root), row
            encoded=json.dumps({key:row[key] for key in ('path','dev','ino','pid','identity')})
            if encoded not in known:
                output.write(encoded+'\n');known.add(encoded)
    return rows


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def wait_for(predicate, *, seconds=20):
    deadline = time.monotonic() + seconds
    while True:
        value = predicate()
        if value:
            return value
        assert time.monotonic() < deadline, 'named condition deadline'
        time.sleep(.02)


def dead(rows):
    return all(not same_process(identity(row['pid']), row['identity']) for row in rows)


def no_query_workers(rows):
    """Missing runtime may create no database/legacy query execution process."""
    for row in rows:
        command = row['command']
        assert not any(Path(part).name in ('serve-worker','idalib_worker','idat','idat64','native-linked') for part in command), command
        assert not any(part in ('worker', '_worker') for part in command), command


def negative_witness(label, check):
    try:
        check()
    except AssertionError as error:
        return {'property': label, 'injection_detected': True, 'error': str(error)}
    raise AssertionError('broken property was not detected: ' + label)


def instrument(python):
    # Test-only, private venv. Records actual subprocess births and Unix binds;
    # never changes SDK behavior or product responses.
    site = subprocess.check_output([str(python), '-I', '-B', '-c',
        'import sysconfig; print(sysconfig.get_path("purelib"))'], text=True).strip()
    path = Path(site) / 'n9_release_telemetry.pth'
    source = str(REPO / 'tests/support/r2_process_ledger.py')
    path.write_text('import runpy; runpy.run_path('+repr(source)+')["install"]()\n')


class Product:
    def __init__(self, env, binary, directory, *, python=None):
        self.env, self.binary, self.directory = env, binary, directory
        directory.mkdir(mode=0o700)
        for name in ('home', 'cli', 'state', 'ipc', 'tmp'):
            (directory / name).mkdir(mode=0o700)
        self.variables = env.variables() | {'HOME': str(directory / 'home'),
            'IDA_CLI_HOME': str(directory / 'cli'), 'IDA_NEXUS_STATE_DIR': str(directory / 'state'),
            'IDA_NEXUS_IPC_ROOT': str(directory / 'ipc'), 'TMPDIR': str(directory / 'tmp'),
            'IDA_NEXUS_PYTHON': str(python or env.root / 'venv/bin/python'), 'N3_ENV_ROOT':str(env.root)}
        self.variables.pop('IDA_NEXUS_BRIDGE_SCRIPT', None)
        self.socket_bindings=set()
        self.sequence = 0
        capture(env)
        self.first_entry = len(env.entries())

    def start_call(self, args, *, variables=None):
        self.sequence += 1
        prefix = [] if args and args[0] in ('serve','serve-http','probe-runtime','serve-worker') else ['--compact']
        command = ['timeout', '30s', str(self.binary), *prefix, *map(str, args)]
        child = self.env.spawn(lambda: subprocess.Popen(command, env=variables or self.variables,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.directory), command)
        return child

    def finish(self, child, *, ok=True):
        stdout, stderr = child.communicate(timeout=32)
        row = {'exit': child.returncode, 'stdout': stdout.decode(), 'stderr': stderr.decode()}
        write(self.directory / f'command-{self.sequence}-{child.pid}.json', row)
        if ok:
            assert child.returncode == 0, row
            self.register_sockets()
            value, _ = unwrap_cache(json.loads(stdout), self.directory/'cli')
            return value
        return row

    def register_sockets(self):
        pidfile=self.directory/'cli/server.pid'
        if not pidfile.exists():return
        pid=int(pidfile.read_text())
        capture(self.env)
        exact=[row for row in self.env.entries() if row['pid']==pid and same_process(identity(pid),row['identity'])]
        if not exact:return  # A completed shutdown can leave no live creator.
        paths=[self.directory/'cli/server.sock',self.directory/'cli/mcp.sock']
        for name in ('b','c'):
            paths.extend((self.directory/'ipc').glob(f'n4-{pid}-*/{name}'))
        for path in paths:
            if not path.exists():continue
            info=path.lstat();key=(str(path),info.st_dev,info.st_ino)
            if key not in self.socket_bindings:
                self.env.record_socket(path,pid)
                self.socket_bindings.add(key)

    def call(self, *args, ok=True, variables=None):
        return self.finish(self.start_call(args, variables=variables), ok=ok)

    def raw(self, path, method, params=None):
        return self.call('--path', path, 'raw', json.dumps({'method': method, 'params': params or {}}))

    def script(self, path, code):
        result = self.raw(path, 'run_script', {'code': code})
        assert result['success'] is True and result['stderr'] == '', result
        return result['stdout']

    def settle(self):
        def settled():
            status = self.call('status')
            lifecycle = status['nexus_lifecycle']
            snapshot = lifecycle['helper'].get('snapshot')
            return status if (all(lifecycle[k] == 0 for k in
                ('resources', 'startup_and_pre_attach', 'retirement_acks'))
                and isinstance(snapshot, dict) and all(snapshot[k] == 0 for k in
                ('used', 'parent_count', 'live_ref_bytes'))) else False
        return wait_for(settled)

    def stop(self):
        self.settle()
        result = self.call('shutdown')
        assert result['ok'] is True, result
        return result

    def entries(self):
        capture(self.env)
        return self.env.entries()[self.first_entry:]

    def clean(self, rows, *, allowed_registrations=()):
        wait_for(lambda: dead(rows))
        sockets = list(self.directory.rglob('*'))
        assert not [str(p) for p in sockets if p.is_socket()], 'service-owned sockets remain'
        assert {p.stem for p in (self.directory / 'state/instances').glob('*.json')} <= set(allowed_registrations), 'service-owned registrations remain'
        assert not (self.directory / 'cli/server.sock').exists()
        assert not (self.directory / 'cli/mcp.sock').exists()
        # Durable coordination evidence is retained. It must hold no lease.
        for journal in self.directory.rglob('custody.json'):
            state = json.loads(journal.read_text())
            assert state['entries'] == {} and not state.get('file_intents'), journal


def sample(env, directory, name):
    path = directory / name
    shutil.copyfile(env.root / 'fixtures/mini', path)
    return path


def smoke(product, path, name):
    functions = product.raw(path, 'list_functions')
    assert functions['total'] >= 2, functions
    target = next(row for row in functions['functions'] if row['name'] in ('add', '_add'))
    address = int(target['address'], 16)
    decompile = product.raw(path, 'decompile_function', {'address': target['address']})
    assert decompile, 'empty decompilation'
    code = (f"import ida_name,ida_bytes,ida_loader; assert ida_name.set_name({address},{name!r},ida_name.SN_CHECK); "
            f"assert ida_bytes.set_cmt({address},{name!r},False); "
            "assert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB),0)")
    assert product.script(path, code) == ''
    database = product.script(path, "import ida_loader; print(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))").strip()
    closed = product.raw(path, 'close')
    assert closed['ok'] is True, closed
    product.settle()
    actual = product.script(path, f"import ida_name,ida_bytes; print(ida_name.get_name({address})); print(ida_bytes.get_cmt({address},False))")
    assert actual == name+'\n'+name+'\n', actual
    product.raw(path, 'close')
    product.settle()
    return {'address': address, 'saved_read': actual, 'database': database, 'decompile': decompile}


def e27(env, binary, case, result):
    product = Product(env, binary, case / 'service')
    a = sample(env, case, 'A')
    b = sample(env, case, 'B')
    # The external process uses the public SDK and holds an independent owner.
    variables = product.variables | {'N3_ENV_ROOT': str(env.root)}
    external_code = """import os,sys,json
from ida_nexus import DatabaseHandle,DatabaseOpenOptions
handle=DatabaseHandle.open(sys.argv[1],options=DatabaseOpenOptions(startup_timeout=15,worker_env=dict(os.environ)))
assert handle.wait_autoanalysis(timeout=15)['complete']
print(json.dumps({'event':'external_opened','pid':handle.instance.pid,'instance_id':handle.instance.record_id,'idb_path':handle.instance.idb_path}),flush=True)
try:
 for line in sys.stdin:
  request=json.loads(line)
  if request['command']=='close':
   handle.close(wait_for_database=True,timeout=15)
   print(json.dumps({'event':'external_closed'}),flush=True)
   break
  print(json.dumps(handle.execute_python(request['code'],timeout=10)),flush=True)
finally:handle.close(wait_for_database=True,timeout=15)
"""
    external = Process(env, [str(env.root/'venv/bin/python'), '-I', '-B', '-c', external_code, str(b)], variables, 'e27-external')
    ready = external.lines.json()
    assert ready['event'] == 'external_opened', ready
    external_birth = identity(ready['pid'])
    started, release, continued = (case / name for name in ('started', 'release', 'continued'))
    long = None
    try:
        first = product.call('status')  # Normal CLI autostart, never an in-process Router.
        assert first['metadata']['ida_version'] == env.manifest['installed_ida_version']
        functions = product.raw(a, 'list_functions')['functions']
        target = functions[0]['address']
        owner_a_pid=int(product.script(a,"import os; print(os.getpid())").strip())
        assert owner_a_pid != ready['pid'], 'A and B must be independent database owners'
        result['independent_owner_pids']={'A':owner_a_pid,'B':ready['pid']}
        product.script(a, f"import ida_name,ida_bytes,ida_loader; assert ida_name.set_name({int(target,16)},'E27_SAVED',ida_name.SN_CHECK); assert ida_bytes.set_cmt({int(target,16)},'E27_SAVED',False); assert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB),0)")
        code = ("from pathlib import Path\nimport time\n" + f"with Path({str(started)!r}).open('a') as f: f.write('start\\n')\n"
                + f"while not Path({str(release)!r}).exists(): time.sleep(.01)\n"
                + f"with Path({str(continued)!r}).open('a') as f: f.write('complete\\n')")
        long = product.start_call(['--path', a, 'raw', json.dumps({'method':'run_script','params':{'code':code}})])
        wait_for(started.exists)
        rows = product.entries()
        daemon_pid=int((product.directory/'cli/server.pid').read_text())
        daemon=next(row for row in rows if row['pid']==daemon_pid)
        shutdown = product.call('shutdown', ok=False)
        result['busy_shutdown_terminal'] = shutdown
        assert_busy_shutdown(shutdown, same_process(identity(daemon_pid),daemon['identity']), long.poll() is None)
        assert not release.exists() and not continued.exists(), 'busy shutdown stopped/released the cooperative barrier'
        assert product.call('status')['worker_count'] == 1, 'service remains responsive and owns A'
        def external_query():
            code="import ida_funcs,ida_loader\n{'functions':ida_funcs.get_func_qty(),'path':ida_loader.get_path(ida_loader.PATH_TYPE_IDB)}"
            external.child.stdin.write((json.dumps({'command':'query','code':code})+'\n').encode());external.child.stdin.flush()
            value=external.lines.json()['result']
            assert value['functions'] >= 2 and Path(value['path']).resolve()==Path(ready['idb_path']).resolve(),value
            assert same_process(identity(ready['pid']), external_birth)
        external_query()
        result['busy_refusal_preserved_service_and_operation']=True
        release.touch()
        terminal = product.finish(long)
        long = None
        assert terminal['success'] is True, terminal
        assert started.read_text()=='start\n' and continued.read_text()=='complete\n', 'long operation must execute once'
        result['long_terminal']=terminal
        shutdown = product.call('shutdown')
        assert shutdown['ok'] is True, shutdown
        result['shutdown_terminal']=shutdown
        excluded={ready['pid'],external.child.pid}
        service_rows=[row for row in product.entries() if row['pid'] not in excluded]
        product.clean(service_rows,allowed_registrations={ready['instance_id']})
        external_query()
        # A real additional held child must make the exact-birth exit proof fail.
        command=['/bin/sleep','30']
        extra=env.spawn(lambda:subprocess.Popen(command,env=product.variables),command)
        try:
            entry=next(row for row in env.entries() if row['pid']==extra.pid)
            result['negative_witness']=negative_witness('service exit ledger rejects an extra live birth',
                lambda:assert_dead(service_rows+[entry]))
            result['negative_witness']['injected_process']=entry
        finally:
            extra.terminate();extra.wait(timeout=3)
        restarted = product.call('status')
        assert restarted['worker_count'] == 0 and not product.call('list-tasks')['tasks'], restarted
        assert all(restarted['nexus_lifecycle'][name]==0 for name in ('resources','startup_and_pre_attach','retirement_acks'))
        assert product.script(a, f"import ida_name,ida_bytes; print(ida_name.get_name({int(target,16)})); print(ida_bytes.get_cmt({int(target,16)},False))") == 'E27_SAVED\nE27_SAVED\n'
        assert started.read_text()=='start\n' and continued.read_text()=='complete\n', 'completed operation replayed after restart'
        product.raw(a, 'close');product.stop()
        product.clean([row for row in product.entries() if row['pid'] not in excluded],allowed_registrations={ready['instance_id']})
        external_query()
        result['restarted_saved_edits_and_no_replay']=True
    finally:
        release.touch()
        if long is not None:
            result['long_final_terminal'] = product.finish(long, ok=False)
            assert result['long_final_terminal']['exit'] != 124
            # Cleanup after the failed assertion follows accepted semantics.
            product.raw(a, 'close');product.stop()
        external.child.stdin.write(b'{"command":"close"}\n');external.child.stdin.flush()
        assert external.lines.json()['event'] == 'external_closed'
        external.wait()


def assert_busy_shutdown(terminal, daemon_alive, operation_alive):
    assert terminal['exit'] not in (0,124) and 'CancelPending' in terminal['stderr'], terminal
    assert daemon_alive, 'busy shutdown exited the service'
    assert operation_alive, 'busy shutdown killed the long operation'


def assert_dead(rows):
    assert dead(rows), 'recorded process identity is still live'


def e28(env, binary, baseline, case, result):
    assert env.manifest['installed_ida_version'] == '9.5', 'BLOCKED: N0 links IDA 9.5'
    fixed = case / 'n0'
    shutil.copyfile(baseline, fixed);fixed.chmod(0o700)
    assert digest(fixed) == BASELINE_SHA, 'N0 checksum mismatch'
    home = case / 'old-home';home.mkdir()
    variables = env.variables() | {'HOME':str(home), 'IDA_CLI_HOME':str(home/'cli'),
        'TMPDIR':str(case), 'IDADIR':env.manifest['ida_dir']}
    original = sample(env, case, 'original')
    old_opens=[]
    def old_open(process, path, permitted):
        assert path == permitted and path.is_relative_to(case), 'N0 path outside its approved backup scene'
        old_opens.append(str(path))
        return process.rpc('open',{'path':str(path)})['result']
    old = Process(env, [str(fixed), 'serve-worker'], variables, 'e28-before')
    opened = old_open(old, original, original)
    functions = old.rpc('list_functions')['result']['functions']
    target = next(row for row in functions if row['name'] in ('add','_add'))
    address = int(target['address'],16)
    before = 'E28_PRE_BACKUP'
    old.rpc('run_script', {'code':f"import ida_name,ida_bytes; assert ida_name.set_name({address},{before!r},ida_name.SN_CHECK); assert ida_bytes.set_cmt({address},{before!r},False)"})
    old.rpc('close');old.rpc('shutdown');old.wait()
    backup = case / 'backup.i64';shutil.copyfile(opened['path'], backup)
    backup_hash = digest(backup)
    result.update(backup={'sha256':backup_hash,'created_at':time.time(),'origin':'generated during this case'},
        baseline={'sha256':digest(fixed),'source_sha':'97ec918','runtime':env.manifest['ida_dir']})
    work = case / 'working.i64';shutil.copyfile(backup, work)
    product = Product(env, binary, case/'migration')
    read = f"import ida_name,ida_bytes; print(ida_name.get_name({address})); print(ida_bytes.get_cmt({address},False))"
    assert product.script(work, read) == before+'\n'+before+'\n'
    product.script(work, f"import ida_name,ida_bytes,ida_loader; assert ida_name.set_name({address},'E28_POST_BACKUP',ida_name.SN_CHECK); assert ida_bytes.set_cmt({address},'E28_POST_BACKUP',False); assert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB),0)")
    product.raw(work, 'close');product.stop();product.clean(product.entries())
    retained = case/'retained-migrated.i64';shutil.copyfile(work, retained)
    retained_hash = digest(retained)
    restore = case/'restore';restore.mkdir()
    restored = restore/'restored.i64';shutil.copyfile(backup,restored)
    assert digest(restored) == backup_hash
    restore_home = case/'restore-home';restore_home.mkdir()
    restored_variables = variables | {'HOME':str(restore_home),'IDA_CLI_HOME':str(restore_home/'cli')}
    old = Process(env,[str(fixed),'serve-worker'],restored_variables,'e28-restored')
    assert old_open(old, restored, restored)
    listing = old.rpc('list_functions')['result']
    assert any(f['name'] == before for f in listing['functions']), listing
    assert old.rpc('decompile_function',{'address':target['address']})['result']
    saved = old.rpc('run_script',{'code':read})['result']
    assert saved['success'] and saved['stdout'] == before+'\n'+before+'\n',saved
    assert 'E28_POST_BACKUP' not in json.dumps(listing)+saved['stdout']
    old.rpc('close');old.rpc('shutdown');old.wait()
    assert digest(backup) == backup_hash and digest(retained) == retained_hash, 'preserved scene changed'
    assert str(retained) not in old_opens and str(work) not in old_opens
    result['n0_open_paths']=old_opens
    result.update(backup_unchanged=True, retained={'sha256':retained_hash,'never_opened_by_n0':True}, restored=saved)
    damaged = case/'damaged-backup-control.i64'
    shutil.copyfile(backup,damaged)
    with damaged.open('ab') as stream:stream.write(b'broken backup control')
    result['negative_witness'] = negative_witness('restored backup has recorded bytes',
        lambda: assert_annotations(digest(damaged), backup_hash))


def assert_annotations(actual, expected):
    assert actual == expected, (actual, expected)


def e29(env, binary, case, result):
    assert binary.parent.name == 'release', 'E29 requires the release build'
    archive = case/'bundle.tar.gz'
    command(env, [sys.executable, str(REPO/'scripts/package_release.py'), '--binary', str(binary), '--output',str(archive)])
    bundle = case/'bundle';bundle.mkdir()
    command(env, ['tar','-xzf',str(archive),'-C',str(bundle)])
    prefix = case/'prefix'
    variables = env.variables()
    # Unset IDADIR at 9.5 proves automatic newest selection on this host. Other
    # platforms may supply private injected roots through their prepared env.
    if env.manifest['installed_ida_version'] == '9.5':
        variables.pop('IDADIR',None)
    install = command(env, ['bash',str(bundle/'scripts/install.sh'),'--bundle',str(bundle),
        '--bin-dir',str(prefix/'bin'),'--install-root',str(prefix/'lib'),
        '--nexus-source',str(env.root/'nexus-source'),'--wheels',str(env.root/'wheels')], variables, limit=180)
    result['install_output'] = install
    launcher = prefix/'bin/ida-cli'
    roots = list((prefix/'lib').glob('version.*'));assert len(roots)==1
    root = roots[0]
    instrument(root/'nexus/venv/bin/python')
    links = command(env,['otool','-L',str(root/'ida-cli.real')])
    rpaths = command(env,['otool','-l',str(root/'ida-cli.real')])
    assert not any(word in links+rpaths for word in ('libida','libidalib','IDASDK','idasdk','/Applications/IDA')), links
    assert CARGO is not None, 'BLOCKED: cargo missing'
    tree = command(env,[CARGO,'tree','--locked'], os.environ.copy())
    assert not any(word in tree for word in ('idalib v','idalib-build')), tree
    result['linkage'] = {'libraries':links,'rpath_load_commands':rpaths,'cargo_tree':tree}
    product = Product(env,launcher,case/'installed',python=root/'nexus/venv/bin/python')
    # The launcher supplies the frozen default when IDADIR is absent.
    product.variables.pop('IDADIR',None)
    probe = command(env,[str(launcher),'probe-runtime'],product.variables)
    assert json.loads(probe)['metadata']['ida_version'] == env.manifest['installed_ida_version']
    assert json.loads(probe)['metadata']['installed_ida_version'] == env.manifest['installed_ida_version']
    assert product.call('serve-worker',ok=False)['exit'] != 0
    for name in REMOVED:
        rejected = product.call('status',ok=False,variables=product.variables|{name:''})
        assert rejected['exit'] != 0 and name in rejected['stderr'],rejected
    # Only this private installation is renamed. The launcher continues to name
    # the missing venv; neither product nor test may select another interpreter.
    before = len(env.entries())
    runtime = root/'nexus/venv';missing = root/'nexus/venv.missing';runtime.rename(missing)
    a = sample(env,case,'tools')
    try:
        failures=[]
        for args in (['--path',str(a),'list-functions'],['serve'],['probe-runtime']):
            failure=product.call(*args,ok=False)
            assert failure['exit'] not in (0,124),failure
            assert any(word in failure['stderr'].lower() for word in ('nexus','python','no such file')),failure
            failures.append(failure)
        capture(env)
        rows=env.entries()[before:]
        no_query_workers(rows)
        result['missing_runtime']={'failures':failures,'processes':rows,'no_query_worker':True}
        injected_path = case/'idat'
        injected_path.symlink_to('/bin/sleep')
        injected_argv = [str(injected_path), '30']
        injected = env.spawn(lambda: subprocess.Popen(injected_argv,env=product.variables),injected_argv)
        try:
            injected_entry = next(row for row in env.entries() if row['pid']==injected.pid)
            result['negative_witness']=negative_witness('missing dependency starts no query worker',
                lambda:no_query_workers(rows+[injected_entry]))
            result['negative_witness']['injected_process'] = injected_entry
        finally:
            injected.terminate()
            injected.wait(timeout=3)
    finally:
        missing.rename(runtime)
    result['smoke']=smoke(product,a,'E29_PERSISTED')
    result['daemon_status']=product.call('status')
    for name in REMOVED:
        rejected=product.call('status',ok=False,variables=product.variables|{name:''})
        assert rejected['exit']!=0 and name in rejected['stderr'],rejected
    result['removed_config_with_existing_daemon']=list(REMOVED)
    product.stop();product.clean(product.entries())


def command(env, argv, variables=None, *, limit=30):
    args=['timeout',str(limit)+'s',*argv]
    child=env.spawn(lambda:subprocess.Popen(args,cwd=REPO,env=variables or env.variables(),
        stdout=subprocess.PIPE,stderr=subprocess.PIPE),args)
    stdout,stderr=child.communicate(timeout=limit+2)
    assert child.returncode==0,(argv,child.returncode,stdout.decode(),stderr.decode())
    return stdout.decode()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--baseline',type=Path)
    parser.add_argument('--case',choices=('E27','E28','E29'),required=True)
    args=parser.parse_args()
    env=Environment(args.root)
    case=env.root/args.case;case.mkdir(mode=0o700)
    result={'case':args.case,'status':'FAIL','uptime_before':subprocess.check_output(['uptime'],text=True).strip()}
    env.ledger=case/'processes.jsonl'
    env.intents=case/'process-intents'
    ledger=case/'native-processes.jsonl';ledger.touch(mode=0o600,exist_ok=True)
    env.native_ledger=ledger
    env.test_telemetry['R2_LEDGER']=str(ledger)
    instrument(env.root/'venv/bin/python')
    os.environ.update(env.variables())
    os.environ.update({'N3_ENV_ROOT':str(env.root),'N3_IPC_ROOT':str(case/'ipc')})
    def interrupted(sig,_frame):
        raise InterruptedError(f'case interrupted {sig}')
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,interrupted)
    try:
        assert os.environ.get('IDA_TEST')=='1','BLOCKED: explicit IDA_TEST=1 required'
        if args.case=='E27':e27(env,args.binary,case,result)
        elif args.case=='E28':e28(env,args.binary,args.baseline,case,result)
        else:e29(env,args.binary,case,result)
        capture(env)
        env.assert_clean()
        result['status']='PASS'
    except Exception as error:
        result.update(error=str(error),traceback=traceback.format_exc())
        if 'BLOCKED' in str(error):result['status']='BLOCKED'
    finally:
        try:
            result['owned_processes']=len(capture(env))
            result['cleanup_signalled']=env.cleanup()
            env.assert_clean()
            result['residual_sockets']=[str(p) for p in case.rglob('*') if p.is_socket()]
            assert not result['residual_sockets'],result['residual_sockets']
            result['cleanup']='PASS'
        except Exception:
            result.update(status='FAIL',cleanup=traceback.format_exc())
        result['uptime_after']=subprocess.check_output(['uptime'],text=True).strip()
        write(env.root/(args.case+'-result.json'),result)
    print(json.dumps({'case':args.case,'status':result['status'],'error':result.get('error'),'cleanup':result['cleanup']}))
    return 0 if result['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
