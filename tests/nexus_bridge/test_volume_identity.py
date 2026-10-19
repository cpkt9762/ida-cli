"""Production metadata/file recovery under explicit OS device/boot inputs.

The kernel locks and bytes are real; device-number changes and boot sources are
controlled inputs, not a claim of an actual remount, reboot, VM or IDA run.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO=Path(os.environ.get('R4_PRODUCT_SOURCE',Path(__file__).resolve().parents[2]))
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge'),str(Path(__file__).parent)]


def inputs(old=False,overrides=None):
    from test_recovery_transaction import no_owner_input
    no_owner_input()
    if old:
        actual_stat,actual_fstat,actual_lstat=os.stat,os.fstat,os.lstat
        class DeviceStat:
            def __init__(self,real):self.real=real
            @property
            def st_dev(self):return self.real.st_dev+1000
            def __getattr__(self,name):return getattr(self.real,name)
            def __getitem__(self,index):return self.st_dev if index==2 else self.real[index]
            def __len__(self):return len(self.real)
        os.stat=lambda *a,**kw:DeviceStat(actual_stat(*a,**kw))
        os.fstat=lambda *a,**kw:DeviceStat(actual_fstat(*a,**kw))
        os.lstat=lambda *a,**kw:DeviceStat(actual_lstat(*a,**kw))
    else:
        import origin
        actual_scope=origin.creation_scope
        def scope(path,incarnation):
            value=actual_scope(path,incarnation)
            if not (overrides or {}).get('sameboot'):
                value['creator']=dict(value['creator'],boot_id='00000000-0000-4000-8000-000000000001')
            for key,item in (overrides or {}).items():
                if key!='sameboot':value[key]=copy.deepcopy(item)
            return value
        origin.creation_scope=scope


def produce(case,managed=False):
    inputs(old=True)
    from open_recovery import Snapshot
    from target_coordination import Target
    payload=case/('cache/generations/g-volume' if managed else 'payload')
    payload.mkdir(mode=0o700,parents=True)
    if managed:
        manifest=payload/'generation.json'
        manifest.write_text(json.dumps({'version':1,'key':'volume-epoch'}))
        manifest.chmod(0o600)
    path=payload/'input.i64'
    original=b'exact original before device epoch'
    path.write_bytes(original)
    snapshot=Snapshot(case/'home',path,float('inf'),owner_probe=lambda _:None)
    path.write_bytes(b'failed complete file')
    snapshot.failed(1)
    with Target(path) as target,target.locked():
        reference={'target':str(path),'recovery_id':snapshot.path.name,'snapshot':str(snapshot.path),'coord_key':target.key,
            'lock_inode':os.fstat(target.target_fd).st_ino,'directory':str(target.directory.path),
            'original_sha256':hashlib.sha256(original).hexdigest()}
    (case/'reference.json').write_text(json.dumps(reference))


def consume(case,overrides):
    inputs(overrides=overrides)
    from target_coordination import Target
    from target_journal import Journal
    from recovery_transaction import Transaction
    reference=json.loads((case/'reference.json').read_text())
    with Target(reference['target']) as target,target.locked():
        assert target.key==reference['coord_key'],'must keep the same logical authority'
        assert os.fstat(target.target_fd).st_ino==reference['lock_inode'],'never replace stable lock'
        with Transaction(target,reference['recovery_id']) as transaction:
            transaction.resume_executor()
            transaction.restore()
            assert transaction.data['status']=='restored'
        Journal(target).gate()
    assert hashlib.sha256(Path(reference['target']).read_bytes()).hexdigest()==reference['original_sha256']


class VolumeEpoch(unittest.TestCase):
    def child(self,case,mode,overrides=None):
        environment=dict(os.environ)
        if mode=='--legacy-produce':
            environment['R4_PRODUCT_SOURCE']=os.environ['R4_BASELINE_SOURCE']
            mode='--produce'
        argv=['timeout','12s',sys.executable,'-B',__file__,mode,str(case.resolve()),json.dumps(overrides or {})]
        before=subprocess.check_output(['uptime'],text=True).strip()
        result=subprocess.run(argv,capture_output=True,text=True,check=False,env=environment)
        with (case/'runs.jsonl').open('a') as output:
            output.write(json.dumps({'argv':argv,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,
                'uptime_before':before,'uptime_after':subprocess.check_output(['uptime'],text=True).strip()})+'\n')
        return result

    def test_interrupted_v1_import_resumes_same_id_after_device_epoch(self):
        case=Path(tempfile.mkdtemp(prefix='legacy-volume-',dir=os.environ['R3A_CASE_ROOT']))
        for mode,expected in (('--legacy-produce',0),('--partial-import',97),('--resume-import',0)):
            result=self.child(case,mode)
            self.assertEqual(result.returncode,expected,result.stderr)

    def scene(self):
        case=Path(tempfile.mkdtemp(prefix='volume-epoch-',dir=os.environ['R3A_CASE_ROOT']))
        result=self.child(case,'--produce')
        self.assertEqual(result.returncode,0,result.stderr)
        return case,json.loads((case/'reference.json').read_text())

    def test_qualified_device_epoch_keeps_identity_lock_and_resumes_exact_bytes(self):
        case,_=self.scene()
        result=self.child(case,'--consume')
        self.assertEqual(result.returncode,0,result.stderr)

    def test_unqualified_device_mapping_never_writes_or_thaws_old_obligation(self):
        for overrides in ({'sameboot':True},{'machine_sha256':'0'*64},{'volume_sha256':'0'*64},
                {'virtualized':True},{'local_internal':False},{'host_domain':'namespace-only'},
                {'file_id':0},{'device':0},{'boot_retirement_capability':'UnsupportedBootScope'}):
            with self.subTest(overrides=overrides):
                case,reference=self.scene()
                directory=Path(reference['directory'])
                before={str(p):p.read_bytes() for p in directory.rglob('*') if p.is_file()}
                result=self.child(case,'--consume',overrides)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('UnsupportedBootScope',result.stderr)
                self.assertEqual({str(p):p.read_bytes() for p in directory.rglob('*') if p.is_file()},before)
                self.assertEqual(Path(reference['target']).read_bytes(),b'failed complete file')


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--produce':produce(Path(sys.argv[2]))
    elif len(sys.argv)>1 and sys.argv[1]=='--produce-managed':produce(Path(sys.argv[2]),True)
    elif len(sys.argv)>1 and sys.argv[1]=='--consume':consume(Path(sys.argv[2]),json.loads(sys.argv[3]))
    elif len(sys.argv)>1 and sys.argv[1] in ('--partial-import','--resume-import'):
        case=Path(sys.argv[2])
        inputs(old=sys.argv[1]=='--partial-import')
        from target_coordination import Target
        from recovery_legacy import import_v1
        import recovery_files
        reference=json.loads((case/'reference.json').read_text())
        def fault(action,stage,_detail):
            if sys.argv[1]=='--partial-import' and action=='copy' and stage=='chunk':os._exit(97)
        recovery_files.boundary=fault
        with Target(reference['target']) as target,target.locked():
            result=import_v1(target,reference['snapshot'])
            assert result['job_id']==reference['recovery_id'] and result['phase']=='failed-owner-held',result
            from recovery_transaction import Transaction
            with Transaction(target,reference['recovery_id']) as transaction:
                assert transaction.data['imported_v1']['state']=='Complete'
                transaction.resume_executor()
                try:transaction.restore()
                except RuntimeError as error:assert 'original resource identity' in str(error),str(error)
                else:raise AssertionError('legacy import cannot manufacture resource proof')
    else:unittest.main(verbosity=2)
