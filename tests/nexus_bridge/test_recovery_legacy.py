"""Fresh frozen-v1 producer, current v2 importer, real process boundaries."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest

REPO=Path(__file__).resolve().parents[2]


def produce(case, phase):
    baseline=Path(os.environ['R4_BASELINE_SOURCE'])
    sys.path[:0]=[str(baseline/'nexus_bridge/custody'),str(baseline/'nexus_bridge')]
    import cache_store
    cache_store.public_owner_probe=lambda _:None
    sys.modules['ida_nexus']=types.SimpleNamespace(probe_database_state=lambda *_a,**_k:{'state':'packed'})
    from open_recovery import Snapshot
    payload=case/'payload'
    payload.mkdir(mode=0o700)
    target=payload/'input.i64'
    original=b'complete original'*160000
    target.write_bytes(original)
    target.chmod(0o640)
    from target_coordination import Target
    with Target(target) as coordination,coordination.locked():
        snapshot=Snapshot(case/'oldhome/idb',target,float('inf'),owner_probe=lambda _:None,coordination=coordination)
        target.write_bytes(b'legitimate changed packed' if phase=='ready' else b'failed packed')
        (case/'reference.json').write_text(json.dumps({'target':str(target),'source':str(snapshot.path),
            'original_sha256':hashlib.sha256(original).hexdigest(),'recovery_id':snapshot.path.name}))
        if phase=='ready':return
        observed=snapshot.failed(1)
        if phase=='failed-owner-held':return
        actual=Path.open
        class ExitOnWrite:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):return self.stream.__exit__(*args)
            def write(self,data):
                self.stream.write(data);self.stream.flush();os.fsync(self.stream.fileno());os._exit(96)
            def __getattr__(self,name):return getattr(self.stream,name)
        def interrupted(path,*args,**kwargs):
            stream=actual(path,*args,**kwargs)
            return ExitOnWrite(stream) if path==target and args and args[0]=='xb' else stream
        Path.open=interrupted
        snapshot.rollback(observed)


def consume(case, fault):
    sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]
    from recovery_legacy import import_v1
    import recovery_legacy
    import recovery_files
    from target_coordination import Target
    reference=json.loads((case/'reference.json').read_text())
    def boundary(action,stage,_detail):
        if action+'.'+stage==fault:os._exit(97)
    recovery_legacy.boundary=boundary
    recovery_files.boundary=boundary
    if fault.startswith('pointer:'):
        import durable_records
        def pointer(directory,name,stage):
            if name=='imported-v2.json' and stage==fault.removeprefix('pointer:'):os._exit(97)
        durable_records.boundary=pointer
    with Target(reference['target']) as target,target.locked():
        if fault=='gate':
            from target_journal import Journal
            from recovery_transaction import Transaction
            error=None
            try:Journal(target).gate()
            except RuntimeError as caught:
                error=str(caught)
                if 'RecoveryBlocked' not in error:raise
            with Transaction(target,reference['recovery_id']) as transaction:
                result=transaction.status()
            result['gate_error']=error
        else:result=import_v1(target,reference['source'])
    (case/'import-result.json').write_text(json.dumps(result))


class LegacyImport(unittest.TestCase):
    def test_archive_pointer_each_internal_boundary_resumes_same_source_and_id(self):
        root=Path(tempfile.mkdtemp(prefix='legacy-pointer-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        coverage=[]
        for phase in ('ready','failed-owner-held','rolling-back'):
            for stage in ('temp_written','file_fsynced','before_rename','after_rename','directory_fsynced'):
                with self.subTest(phase=phase,boundary=stage):
                    case=root/(phase+'-'+stage);case.mkdir(mode=0o700)
                    result=self.child(case,'--produce',phase)
                    self.assertEqual(result.returncode,96 if phase=='rolling-back' else 0,result.stderr)
                    reference=json.loads((case/'reference.json').read_text());source=Path(reference['source'])
                    before={str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*') if p.is_file()}
                    payload=Path(reference['target']).read_bytes()
                    result=self.child(case,'--consume','pointer:'+stage)
                    self.assertEqual(result.returncode,97,result.stderr)
                    result=self.child(case,'--consume','gate')
                    self.assertEqual(result.returncode,0,result.stderr)
                    status=json.loads((case/'import-result.json').read_text())
                    self.assertEqual(status['job_id'],reference['recovery_id'])
                    value=json.loads((Path(status['transaction'])/'recovery.json').read_text())
                    self.assertEqual(value['imported_v1']['state'],'Complete')
                    self.assertEqual(value['status'],'archived' if phase=='ready' else 'failed-owner-held')
                    self.assertEqual(status['gate_error'] is None,phase=='ready')
                    self.assertEqual(Path(reference['target']).read_bytes(),payload)
                    self.assertEqual({str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*')
                        if p.is_file() and p.name!='imported-v2.json'},before)
                    pointer=json.loads((source/'imported-v2.json').read_text())
                    self.assertEqual(pointer['source'],value['imported_v1']['source'])
                    self.assertEqual(pointer['recovery_id'],reference['recovery_id'])
                    self.assertTrue(pointer['never_replay_old_open'])
                    coverage.append(dict(phase=phase,stage=stage,case=str(case),crash=97,gate=0))
                    (root/'coverage.json').write_text(json.dumps(coverage,indent=2))

    def test_pointer_corrupt_foreign_or_replaced_slots_are_never_consumed(self):
        from test_recovery_preview import fingerprints
        root=Path(tempfile.mkdtemp(prefix='legacy-pointer-refuse-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        for variant in ('writer','directory','inode','hash','permissions','json','owner-json',
                        'foreign-new','source-inode','source-content','foreign-binding','owner-schema'):
            with self.subTest(variant=variant):
                case=root/variant;case.mkdir(mode=0o700)
                self.assertEqual(self.child(case,'--produce','ready').returncode,0)
                result=self.child(case,'--consume','pointer:before_rename')
                self.assertEqual(result.returncode,97,result.stderr)
                reference=json.loads((case/'reference.json').read_text());source=Path(reference['source'])
                pending=source/'imported-v2.json.new';owner=source/'imported-v2.json.new.owner'
                if variant in ('writer','directory','owner-schema'):
                    value=json.loads(owner.read_text())
                    if variant=='writer':value['writer']='foreign'
                    elif variant=='directory':value['directory'][1]+=1
                    else:value['schema']=True
                    owner.write_text(json.dumps(value))
                elif variant=='inode':
                    data=pending.read_bytes();pending.unlink();pending.write_bytes(data);pending.chmod(0o600)
                elif variant=='hash':pending.write_bytes(pending.read_bytes()+b' ')
                elif variant=='permissions':pending.chmod(0o666)
                elif variant=='json':pending.write_bytes(b'{')
                elif variant=='owner-json':owner.write_bytes(b'{')
                elif variant=='foreign-new':(source/'foreign.new').write_bytes(b'foreign evidence')
                elif variant=='foreign-binding':
                    value=json.loads(pending.read_text());value['recovery_id']='0'*32
                    from target_coordination import encoded,digest
                    data=encoded(value);pending.write_bytes(data)
                    value=json.loads(owner.read_text());value['new']['sha256']=digest(data);value['new']['size']=len(data)
                    owner.write_bytes(encoded(value))
                elif variant=='source-inode':
                    path=source/'recovery.json';replacement=case/'replacement-journal'
                    replacement.write_bytes(path.read_bytes());replacement.chmod(0o600)
                    self.assertNotEqual(replacement.stat().st_ino,path.stat().st_ino)
                    os.replace(replacement,path)
                else:
                    changed=source/'snapshot/input.i64';changed.chmod(0o600)
                    changed.write_bytes(b'changed retained source')
                coordination=next(Path(reference['target']).parent.glob('.ida-cli-txn-*'))
                before=(fingerprints(source),fingerprints(coordination),Path(reference['target']).read_bytes())
                result=self.child(case,'--consume','gate')
                if result.returncode==0:
                    status=json.loads((case/'import-result.json').read_text())
                    self.assertIsNotNone(status['gate_error'],'untrusted slots must not pass the product gate')
                value=json.loads((coordination/reference['recovery_id']/'recovery.json').read_text())
                self.assertEqual(value['imported_v1']['state'],'Published','refusal must retain the exact old obligation')
                self.assertEqual((fingerprints(source),fingerprints(coordination),Path(reference['target']).read_bytes()),before)

    def child(self,case,mode,value):
        argv=['timeout','12s',sys.executable,'-B',__file__,mode,str(case),value]
        before=subprocess.check_output(['uptime'],text=True).strip()
        result=subprocess.run(argv,capture_output=True,text=True,check=False)
        with (case/'runs.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(argv=argv,exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
                uptime_before=before,uptime_after=subprocess.check_output(['uptime'],text=True).strip()))+'\n')
        return result

    def test_v1_ready_changed_files_archive_and_failed_evidence_import_is_idempotent(self):
        root=Path(tempfile.mkdtemp(prefix='legacy-import-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        for phase in ('ready','failed-owner-held','rolling-back'):
            for fault in ('copy.chunk','legacy_import.published','none'):
                with self.subTest(phase=phase,fault=fault):
                    case=root/(phase+'-'+fault)
                    case.mkdir(mode=0o700)
                    result=self.child(case,'--produce',phase)
                    self.assertEqual(result.returncode,96 if phase=='rolling-back' else 0,result.stderr)
                    reference=json.loads((case/'reference.json').read_text())
                    source=Path(reference['source'])
                    old={str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*') if p.is_file()}
                    payload=Path(reference['target']).read_bytes()
                    result=self.child(case,'--consume',fault)
                    self.assertEqual(result.returncode,0 if fault=='none' else 97,result.stderr)
                    result=self.child(case,'--consume','gate')
                    self.assertEqual(result.returncode,0,result.stderr)
                    gated=json.loads((case/'import-result.json').read_text())
                    self.assertEqual(gated['gate_error'] is None,phase=='ready')
                    result=self.child(case,'--consume','none')
                    self.assertEqual(result.returncode,0,result.stderr)
                    result=self.child(case,'--consume','none')
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(Path(reference['target']).read_bytes(),payload,'import cannot rollback or rewrite payload')
                    self.assertEqual({str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*')
                        if p.is_file() and p.name!='imported-v2.json'},old)
                    self.assertTrue((source/'imported-v2.json').is_file())
                    result=json.loads((case/'import-result.json').read_text())
                    self.assertEqual(result['job_id'],reference['recovery_id'])
                    destination=Path(result['transaction'])
                    self.assertTrue((destination/'legacy-source-root/recovery.json').is_file())
                    record=json.loads((destination/'recovery.json').read_text())
                    self.assertEqual(record['status'],'archived' if phase=='ready' else 'failed-owner-held')
                    self.assertEqual(record['imported_v1']['state'],'Complete')
                    custody=json.loads((destination.parent/'custody.json').read_text())
                    self.assertNotIn(str(source/'recovery.json'),[i['path'] for i in custody.get('file_intents',{}).values()],
                                     'old exact file locator must be transferred after complete v2 publication')
                    if phase!='ready':
                        self.assertEqual(hashlib.sha256((destination/'snapshot/input.i64').read_bytes()).hexdigest(),
                                         reference['original_sha256'])
                        sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]
                        from target_coordination import Target
                        from recovery_transaction import Transaction
                        with Target(reference['target']) as target,target.locked():
                            with Transaction(target,reference['recovery_id']) as transaction:
                                transaction.resume_executor()
                                with self.assertRaisesRegex(RuntimeError,'original resource identity'):
                                    transaction.restore()
                    else:self.assertEqual(payload,b'legitimate changed packed')


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--produce':produce(Path(sys.argv[2]),sys.argv[3])
    elif len(sys.argv)>1 and sys.argv[1]=='--consume':consume(Path(sys.argv[2]),sys.argv[3])
    else:unittest.main(verbosity=2)
