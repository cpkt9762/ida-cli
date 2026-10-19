"""Explicit test operator for NEW private targets; real installed maintenance."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

installation=Path(sys.argv[1]).resolve()
root=Path(os.environ['R3A_CASE_ROOT']).resolve()/'maintenance'
root.mkdir(mode=0o700)
sys.path.insert(0,str(installation))
from r2_process_ledger import install
install()
from open_recovery import Snapshot
from origin import creation_scope
from recovery_files import component_names, inventory
from recovery_maintenance import tree
from recovery_transaction import Transaction
from target_coordination import Target, encoded
from target_journal import Journal
from owner_identity import state_identity

cases=[]
def call(argv, *, cwd=None, env=None):
    command=['timeout','15s',*map(str,argv)]
    before=subprocess.check_output(['uptime'],text=True).strip()
    result=subprocess.run(command,capture_output=True,text=True,cwd=cwd,env=env,check=False)
    row={'argv':command,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,
         'uptime_before':before,'uptime_after':subprocess.check_output(['uptime'],text=True).strip()}
    cases.append(row)
    (root/'runs.json').write_text(json.dumps(cases,indent=2))
    return result

hostile=root/'hostile'
hostile.mkdir(mode=0o700)
sentinel=root/'injection-executed'
(hostile/'sitecustomize.py').write_text(f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n")
(hostile/'open_recovery.py').write_text('raise AssertionError("hostile CWD import")\n')
launcher=installation/'maintenance-launch'
env=dict(os.environ,PYTHONPATH=str(hostile),PYTHONHOME=str(hostile))
for mode in ('ordinary','isolated','safe','envsafe'):
    result=call([launcher,sys.executable,installation,mode,'--help'],cwd=hostile,env=env)
    assert result.returncode==0,result.stderr
    assert 'offline-evidence' in result.stdout
    assert not sentinel.exists(),'injection ran before script bootstrap'

payload=root/'payload'
payload.mkdir(mode=0o700)
target=payload/'input.i64'
shutil.copyfile(os.environ['R3F1_SAMPLE'],target)
target.chmod(0o600)
original=target.read_bytes()
snapshot=Snapshot(root/'irrelevant-home',target,float('inf'))
# This is an explicit synthetic unknown-startup inventory, not a native launch
# or public proof. The TEST operator owns this new target's offline window.
with Target(target) as coordination,coordination.locked():
    journal=Journal(coordination)
    epoch=journal.begin({'parent':dict(client_id='offline',request_id='offline',operation_id='offline',task_id=None),
                         'purpose':'final','ordinal':1},'unknown-startup',launch={'suffix':'test-only-no-native-birth'})
    item=journal.value['entries'][str(epoch)]
    snapshot.requirements=[{k:copy.deepcopy(item.get(k)) for k in ('watch','epoch','acquisition','owner','lease','origin_binding')}]
replacement=payload/'new-save'
replacement.write_bytes(original)
replacement.chmod(0o600)
os.replace(replacement,target)
snapshot.failed(1)
evidence_path=root/'offline-evidence.json'
backup=root/'evidence-copy'
backup.mkdir(mode=0o700)
shutil.copytree(snapshot.path,backup/'transaction')
(backup/'components').mkdir(mode=0o700)
for name in component_names(target):
    if (payload/name).exists():shutil.copy2(payload/name,backup/'components'/name)
with Target(target,create=False) as coordination,coordination.locked(nb=True,recover=False):
    with Transaction(coordination,snapshot.recovery_id,recover=False) as transaction:
        current=inventory(transaction.parent_directory(),coordination.directory)
        components={k:v for k,v in current.items() if k in component_names(target)}
        journal=Journal(coordination,recover=False)
        evidence={'schema':1,'operator':{'uid':os.getuid(),'name':'isolated R4 test driver',
            'confirmation':'I established and maintain this exclusive offline window'},
            'host':creation_scope(coordination.directory.path,'private-offline-test'),
            'window':{'id':'private-test-window','started_at':time.time()-1,'expires_at':time.time()+120},
            'target':coordination.original,'coord_key':coordination.key,'directory':coordination.directory.identity,
            'root_binding':coordination.recovery_root_binding(),'transaction':snapshot.recovery_id,
            'components':components,'retained':tree(transaction.directory),
            'stopped_openers':[{k:copy.deepcopy(item.get(k)) for k in ('watch','epoch','acquisition','owner','lease','launch')}
                               for item in journal.value['entries'].values()],
            'state_roots':[state_identity()],
            'offline_scope':{'all_target_openers_stopped':True,'new_openers_prevented':True,
                             'cross_uid_openers_excluded':True,'remote_writers_excluded':True,'automatic_restarts_prevented':True},
            'backup':{'path':str(backup),'directory':[backup.stat().st_dev,backup.stat().st_ino,os.getuid()]},
            'approved_plan_sha256':None}
def save(value):
    evidence_path.write_bytes(encoded(value))
    evidence_path.chmod(0o600)
def fingerprints():
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in payload.rglob('*') if p.is_file()}
save(evidence)
args=[launcher,sys.executable,installation,'isolated','--maintenance','--offline-evidence',evidence_path,
      '--target',target,'--transaction',snapshot.recovery_id]
before=fingerprints()
result=call([*args,'--dry-run'],cwd=hostile,env=env)
assert result.returncode==0,result.stderr
preview=json.loads(result.stdout)
assert fingerprints()==before,'dry-run wrote payload/journal/marker bytes'
assert preview['public_owner_proof'] is False
assert Path(preview['bridge_dir'])==installation
evidence['approved_plan_sha256']=preview['plan_sha256']
save(evidence)
# Wrong/expired plans reject without changing original bytes.
for key in ('expired','wrong-plan','different-component'):
    bad=copy.deepcopy(evidence)
    if key=='expired':bad['window']['expires_at']=time.time()-1
    elif key=='wrong-plan':bad['approved_plan_sha256']='0'*64
    else:bad['components'][target.name]['inode']+=1
    save(bad)
    result=call(args,cwd=hostile,env=env)
    assert result.returncode!=0 and 'MaintenanceBlocked' in result.stderr,result.stderr
    assert fingerprints()==before,'rejected plan changed scene'
save(evidence)
result=call(args,cwd=hostile,env=env)
assert result.returncode==0,result.stderr
assert target.read_bytes()==original
assert (snapshot.path/'quarantine-1/input.i64').is_file()
with Target(target) as coordination,coordination.locked():
    journal=Journal(coordination)
    journal.gate()
    item=journal.value['entries'][str(epoch)]
    assert journal.manual_closed(item)
    assert item.get('proof') is None and item.get('detach_outcome') is None
    assert item['producer_closed'] is False and item['consumer_closed'] is False
(root/'result.json').write_text(json.dumps({'scope':'actual installed entry; explicit private offline operator; synthetic startup',
    'runs':len(cases),'restored':True,'no_public_proof_forged':True,'dry_run_unchanged':True},indent=2))
