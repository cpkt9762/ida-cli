"""A child delayed before exec survives waitpid; revocation forbids late IDB access.

J_RED_HELPER / J_RED_PROCESS / J_RED_JOURNAL / J_RED_WORKER select baseline sources.
The same safety assertion is used for both runs.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from test_launch_settle import ACQUISITION
from ida_nexus._launch_authorization import create
from proof_helper import Observer

def test_delayed_preexec_child_cannot_open_after_settlement():
    root = Path(tempfile.mkdtemp(prefix='delayed-', dir=os.environ['R3A_CASE_ROOT']))
    os.chmod(root, 0o700)
    source = root/'sample'
    shutil.copyfile(Path(os.environ['N3_ENV_ROOT'])/'fixtures/mini', source)
    target = root/'sample.i64'
    suffix = os.urandom(3).hex()
    grant = root/'grant'
    create(grant, suffix, str(target))
    launch = {'suffix':suffix, 'source':str(source), 'target':str(target),
              'backend':'idalib', 'authorization':str(grant)}
    red_helper = os.environ.get('J_RED_HELPER')
    observer_type = Observer
    if red_helper:
        spec = importlib.util.spec_from_file_location('j_baseline_helper', red_helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        baseline_process = os.environ.get('J_RED_PROCESS')
        if baseline_process:
            process_spec = importlib.util.spec_from_file_location('j_baseline_process', baseline_process)
            process_module = importlib.util.module_from_spec(process_spec)
            process_spec.loader.exec_module(process_module)
            module.process_commands = process_module.process_commands
        observer_type = module.Observer
    from target_coordination import Directory, Target
    from target_journal import Journal
    if red_helper:
        baseline_journal = os.environ['J_RED_JOURNAL']
        journal_spec = importlib.util.spec_from_file_location('j_baseline_journal', baseline_journal)
        journal_module = importlib.util.module_from_spec(journal_spec)
        journal_spec.loader.exec_module(journal_module)
        Journal = journal_module.Journal
    storage = Directory(root)
    observer = observer_type('delayed-helper', 8, storage=storage)
    def call(kind, **fields):
        return observer.receive(dict(kind=kind, protocol=2, helper=observer.incarnation, **fields))
    call('reserve_parent', parent=ACQUISITION['parent'])
    with Target(target) as coordinated:
        with coordinated.locked():
            journal = Journal(coordinated)
            epoch = journal.begin(ACQUISITION, 'delayed', launch=launch)
            receipt = call('launch_intent', watch='delayed', subscription_epoch=epoch,
                target=str(target), coord_key=coordinated.key, acquisition=ACQUISITION, launch=launch)['receipt']
            journal.launch_signed(receipt)
    config = dict(source=str(source), target=str(target), grant=str(grant), suffix=suffix,
                  red_worker=os.environ.get('J_RED_WORKER'))
    (root/'config.json').write_text(json.dumps(config))
    # The trampoline has no suffix in argv until exec. Its parent is the
    # private stand-in bridge which we really kill and waitpid below.
    trampoline = root/'trampoline.py'
    trampoline.write_text('''import json,os,sys,time
from pathlib import Path
r=Path(sys.argv[1]); c=json.loads((r/'config.json').read_text())
(r/'arrived').touch()
while not (r/'release').exists():time.sleep(.01)
from ida_nexus.cli import worker
if c['red_worker']:
    exec(compile(Path(c['red_worker']).read_bytes(),c['red_worker'],'exec'),worker.__dict__)
from ida_domain import Database
original=Database.open.__func__
def traced(cls,*a,**kw):
    result=original(cls,*a,**kw)
    (r/'idb-opened').touch()
    return result
Database.open=classmethod(traced)
code=worker.main([c['source'],'--record-suffix',c['suffix'],'--managed','--lease-grace','0.1','--no-auto-analysis'] + ([] if c['red_worker'] else ['--launch-authorization',c['grant'],'--launch-target',c['target']]))
(r/'child.exit').write_text(str(code))
sys.exit(code)
''')
    parent = root/'parent.py'
    parent.write_text('''import subprocess,sys,time
from pathlib import Path
r=Path(sys.argv[1]); child=subprocess.Popen([sys.executable,str(r/'trampoline.py'),str(r)],start_new_session=True)
(r/'child.pid').write_text(str(child.pid))
while True:time.sleep(.1)
''')
    shutil.copytree(Path(os.environ['N3_ENV_ROOT'])/'profile', root/'profile')
    environment = os.environ | {'IDAUSR':str(root/'profile'),
        'IDA_NEXUS_STATE_DIR':str(root/'state')}
    log = (root/'child.log').open('wb')
    bridge = subprocess.Popen([sys.executable, str(parent), str(root)], env=environment, stdout=log, stderr=log)
    try:
        deadline = time.monotonic()+20
        while not (root/'arrived').exists():
            assert bridge.poll() is None
            assert time.monotonic() < deadline, 'private child reaches pre-exec barrier'
            time.sleep(.01)
        bridge.kill()
        status = bridge.wait(timeout=5)
        reaped = time.monotonic()
        time.sleep(5.2)  # Deliberately exceeds the obsolete five-second margin.
        reply = call('launch_settle', watch='delayed', bridge={
            'pid':bridge.pid, 'status':str(status), 'exited_secs':time.monotonic()-reaped})
        assert reply['state'] == 'abandoned'
        with Target(target) as coordinated:
            with coordinated.locked():
                journal = Journal(coordinated)
                journal.launch_abandoned({'watch':'delayed', 'consumer':reply['consumer']})
                call('retire', watch='delayed', sha256=reply['consumer']['sha256'])
                call('retire_parent', parent=ACQUISITION['parent'])
                journal.settle()
                assert journal.value['entries'] == {}, 'journal is fully settled before the child resumes'
        assert call('heartbeat', summary_only=True)['used'] == 0, 'helper holds no obligation before resume'
        (root/'settled.json').write_text(json.dumps(reply))
        (root/'release').touch()
        deadline = time.monotonic()+40
        child_pid = int((root/'child.pid').read_text())
        from custody_process_identity import identity
        while identity(child_pid) is not None and time.monotonic() < deadline:
            time.sleep(.05)
        assert identity(child_pid) is None, 'worker exits on its own after denial or lease grace'
        (root/'result.json').write_text(json.dumps({'root':str(root), 'opened':(root/'idb-opened').exists(),
            'idb_exists':target.exists(), 'delay':5.2, 'bridge_waitpid':status,
            'worker_exit':int((root/'child.exit').read_text()), 'journal_entries':0, 'helper_obligations':0}))
        assert not (root/'idb-opened').exists(), 'late worker opened IDB after launch was settled'
        assert not target.exists(), 'denied worker must not create database artifacts'
        assert (root/'child.exit').read_text() == '78', 'authorization denial has an identifiable exit code'
    finally:
        if bridge.poll() is None:
            bridge.kill()
            bridge.wait(timeout=5)
        (root/'release').touch()
        storage.close()
        log.close()
