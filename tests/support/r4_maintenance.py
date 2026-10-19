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
    # Both the documented absolute entry and official launcher also work
    # without inherited environment or their caller's working directory.
    result=call(['/usr/bin/env','-i',launcher,sys.executable,installation,mode,'--help'],cwd=hostile)
    assert result.returncode==0,result.stderr
    flags={'ordinary':[],'isolated':['-I'],'safe':['-P'],'envsafe':[]}[mode]
    clean={'PATH':'/opt/homebrew/bin:/usr/bin:/bin'}
    if mode=='envsafe':clean['PYTHONSAFEPATH']='1'
    result=call([sys.executable,*flags,'-B',installation/'open_recovery.py','--help'],cwd=hostile,env=clean)
    assert result.returncode==0,result.stderr

for variant in ('missing','changed','symlink','permissions','manifest','missing-asset'):
    candidate=root/('installation-'+variant)
    shutil.copytree(installation,candidate)
    member=candidate/'recovery_job.py'
    if variant=='missing':member.unlink()
    elif variant=='changed':member.write_bytes(member.read_bytes()+b'\n# mismatched executable bytes\n')
    elif variant=='symlink':
        member.unlink()
        member.symlink_to(installation/'recovery_job.py')
    elif variant=='permissions':member.chmod(0o666)
    elif variant=='manifest':
        manifest=json.loads((candidate/'manifest.json').read_text())
        manifest['schema']=True
        (candidate/'manifest.json').write_text(json.dumps(manifest))
    else:(candidate/'maintenance-launch').unlink()
    result=call([sys.executable,'-I','-B',candidate/'open_recovery.py','--help'],cwd=hostile)
    assert result.returncode!=0 and 'Traceback' in result.stderr,(variant,result.stdout,result.stderr)
    assert not sentinel.exists(),'refused installation executed hostile import'

empty_runtime=root/'missing-dependencies'
result=call([sys.executable,'-m','venv','--without-pip',empty_runtime])
assert result.returncode==0,result.stderr
result=call([launcher,empty_runtime/'bin/python',installation,'isolated','--help'],cwd=hostile,env=env)
assert result.returncode!=0 and ('ida_nexus' in result.stderr or 'ida-nexus' in result.stderr),result.stderr

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

# Prepare both targets before applying either permission. Neither has a
# snapshot or native startup identity; only this explicit private operator may
# close its unknown inventory, without manufacturing public proof/ACK fields.
prepared=[]
for name,has_startup in (('packed-no-snapshot',True),('no-startup-identity',False)):
    directory=root/name
    directory.mkdir(mode=0o700)
    database=directory/'input.i64'
    shutil.copyfile(os.environ['R3F1_SAMPLE'],database)
    database.chmod(0o600)
    recovery_id=__import__('uuid').uuid4().hex
    saved=root/(name+'-evidence-copy')
    saved.mkdir(mode=0o700)
    (saved/'transaction').mkdir(mode=0o700)
    (saved/'components').mkdir(mode=0o700)
    shutil.copy2(database,saved/'components/input.i64')
    with Target(database) as coordination,coordination.locked():
        journal=Journal(coordination)
        if has_startup:
            journal.begin({'parent':{'operation_id':name},'purpose':'final','ordinal':1},name,
                launch={'suffix':'test-only-no-native-identity'})
        else:journal.save()
        pending=copy.deepcopy(journal.value['entries'])
        parent_directory=__import__('target_coordination').Directory(database.parent,private=False)
        try:current=inventory(parent_directory,coordination.directory)
        finally:parent_directory.close()
        permission=copy.deepcopy(evidence)
        permission.update(host=creation_scope(coordination.directory.path,name),target=coordination.original,
            coord_key=coordination.key,directory=coordination.directory.identity,
            root_binding=coordination.recovery_root_binding(),transaction=recovery_id,
            components={k:v for k,v in current.items() if k in component_names(database)},retained={},
            stopped_openers=[{k:copy.deepcopy(item.get(k)) for k in ('watch','epoch','acquisition','owner','lease','launch')}
                            for item in pending.values()],
            backup={'path':str(saved),'directory':[saved.stat().st_dev,saved.stat().st_ino,os.getuid()]},
            approved_plan_sha256=None)
        record_path=coordination.directory.path/'custody.json'
        before=record_path.read_bytes()
        missing=coordination.directory.path/recovery_id
    permission_path=root/(name+'-permission.json')
    permission_path.write_bytes(encoded(permission))
    permission_path.chmod(0o600)
    arguments=[launcher,sys.executable,installation,'isolated','--maintenance','--offline-evidence',permission_path,
        '--target',database,'--transaction',recovery_id]
    output=call([*arguments,'--dry-run'],cwd=hostile,env=env)
    assert output.returncode==0,output.stderr
    assert not missing.exists() and record_path.read_bytes()==before,'snapshotless preview wrote namespace/journal'
    plan=json.loads(output.stdout)
    assert plan['plan']['action']=='archive_without_snapshot'
    permission['approved_plan_sha256']=plan['plan_sha256']
    permission_path.write_bytes(encoded(permission))
    prepared.append((database,recovery_id,arguments,pending,record_path,before))

for index,(database,recovery_id,arguments,pending,record_path,before) in enumerate(prepared):
    output=call(arguments,cwd=hostile,env=env)
    assert output.returncode==0,output.stderr
    assert json.loads(output.stdout)['status']['phase']=='archived'
    with Target(database) as coordination,coordination.locked():
        journal=Journal(coordination)
        journal.gate()
        for key,original_item in pending.items():
            actual=journal.value['entries'][key]
            assert journal.manual_closed(actual)
            assert {k:v for k,v in actual.items() if k!='manual_offline_recovery'}==original_item
    for other in prepared[index+1:]:
        assert other[4].read_bytes()==other[5],'one target permission changed another target'
(root/'snapshotless-result.json').write_text(json.dumps({'targets':2,'no_snapshot':True,
    'unknown_startup_and_absent_identity':True,'dry_run_no_create':True,'cross_target_isolation':True}))

for stage in ('accepted','after_rename'):
    directory=root/('resume-'+stage)
    directory.mkdir(mode=0o700)
    database=directory/'input.i64'
    shutil.copyfile(os.environ['R3F1_SAMPLE'],database)
    database.chmod(0o600)
    original_bytes=database.read_bytes()
    retained=Snapshot(root/'unused-home',database,float('inf'))
    replacement=directory/'replacement'
    replacement.write_bytes(original_bytes)
    replacement.chmod(0o600)
    os.replace(replacement,database)
    retained.failed(1)
    saved=root/('resume-'+stage+'-evidence-copy')
    saved.mkdir(mode=0o700)
    shutil.copytree(retained.path,saved/'transaction')
    (saved/'components').mkdir(mode=0o700)
    shutil.copy2(database,saved/'components/input.i64')
    with Target(database) as coordination,coordination.locked():
        with Transaction(coordination,retained.recovery_id) as transaction:
            current=inventory(transaction.parent_directory(),coordination.directory)
            permission=copy.deepcopy(evidence)
            permission.update(host=creation_scope(coordination.directory.path,stage),target=coordination.original,
                coord_key=coordination.key,directory=coordination.directory.identity,
                root_binding=coordination.recovery_root_binding(),transaction=retained.recovery_id,
                components={k:v for k,v in current.items() if k in component_names(database)},
                retained=tree(transaction.directory),stopped_openers=[],
                backup={'path':str(saved),'directory':[saved.stat().st_dev,saved.stat().st_ino,os.getuid()]},
                approved_plan_sha256=None)
    permission_path=root/('resume-'+stage+'-permission.json')
    permission_path.write_bytes(encoded(permission))
    permission_path.chmod(0o600)
    arguments=[launcher,sys.executable,installation,'isolated','--maintenance','--offline-evidence',permission_path,
        '--target',database,'--transaction',retained.recovery_id]
    output=call([*arguments,'--dry-run'],cwd=hostile,env=env)
    assert output.returncode==0,output.stderr
    permission['approved_plan_sha256']=json.loads(output.stdout)['plan_sha256']
    permission_path.write_bytes(encoded(permission))
    interrupted=call([sys.executable,'-I','-B',Path(__file__).with_name('r4_maintenance_interrupt.py'),
        installation,stage,*arguments[4:]],cwd=hostile,env=dict(os.environ))
    assert interrupted.returncode==99,interrupted.stderr
    before_resume={str(p):p.read_bytes() for p in directory.rglob('*') if p.is_file()}
    output=call([*arguments,'--dry-run'],cwd=hostile,env=env)
    assert output.returncode==0,output.stderr
    assert {str(p):p.read_bytes() for p in directory.rglob('*') if p.is_file()}==before_resume
    output=call(arguments,cwd=hostile,env=env)
    assert output.returncode==0,output.stderr
    assert json.loads(output.stdout)['status']['phase']=='restored'
    assert database.read_bytes()==original_bytes
    assert (retained.path/'quarantine-1/input.i64').exists()
(root/'continuation-result.json').write_text(json.dumps({'accepted_and_after_rename_exits':2,
    'same_operator_permission':True,'preview_no_write':True,'resumed_official_launcher':True}))

legacy_case=root/'legacy-maintenance'
legacy_case.mkdir(mode=0o700)
output=call([sys.executable,'-B',Path(__file__).with_name('r4_legacy_fixture.py'),legacy_case])
assert output.returncode==0,output.stderr
reference=json.loads((legacy_case/'reference.json').read_text())
database=Path(reference['target'])
original_bytes=database.read_bytes()
from recovery_legacy import import_known_home
with Target(database) as coordination,coordination.locked():
    # Production upgrade inventory is deliberately limited to this known home.
    import_known_home(coordination,legacy_case/'oldhome/idb')
    with Transaction(coordination,reference['recovery_id']) as transaction:
        assert transaction.data['imported_v1']['state']=='Complete'
        assert transaction.data['imported_v1']['resources_unqualified'] is True
        retained_path=transaction.directory.path
saved=root/'legacy-evidence-copy'
saved.mkdir(mode=0o700)
shutil.copytree(retained_path,saved/'transaction')
(saved/'components').mkdir(mode=0o700)
shutil.copy2(database,saved/'components/input.i64')
with Target(database) as coordination,coordination.locked():
    with Transaction(coordination,reference['recovery_id']) as transaction:
        current=inventory(transaction.parent_directory(),coordination.directory)
        permission=copy.deepcopy(evidence)
        permission.update(host=creation_scope(coordination.directory.path,'legacy-maintenance'),target=coordination.original,
            coord_key=coordination.key,directory=coordination.directory.identity,
            root_binding=coordination.recovery_root_binding(),transaction=reference['recovery_id'],
            components={k:v for k,v in current.items() if k in component_names(database)},
            retained=tree(transaction.directory),stopped_openers=[],
            backup={'path':str(saved),'directory':[saved.stat().st_dev,saved.stat().st_ino,os.getuid()]},
            approved_plan_sha256=None)
permission_path=root/'legacy-permission.json'
permission_path.write_bytes(encoded(permission))
permission_path.chmod(0o600)
arguments=[launcher,sys.executable,installation,'isolated','--maintenance','--offline-evidence',permission_path,
    '--target',database,'--transaction',reference['recovery_id']]
output=call([*arguments,'--dry-run'],cwd=hostile,env=env)
assert output.returncode==0,output.stderr
permission['approved_plan_sha256']=json.loads(output.stdout)['plan_sha256']
permission_path.write_bytes(encoded(permission))
output=call(arguments,cwd=hostile,env=env)
assert output.returncode==0,output.stderr
assert database.read_bytes()==original_bytes
assert json.loads(output.stdout)['status']['phase']=='restored'
assert Path(reference['legacy']).is_dir(),'legacy source remains retained after import/application'
(root/'result.json').write_text(json.dumps({'scope':'actual installed entry; private explicit operator; synthetic startup',
    'runs':len(cases),'snapshotless_targets':2,'process_exit_continuations':2,'tampered_installations':6,
    'legacy_import_offline_restore':True,'missing_dependencies_rejected':True,
    'no_public_proof_forged':True,'dry_run_unchanged':True},indent=2))
