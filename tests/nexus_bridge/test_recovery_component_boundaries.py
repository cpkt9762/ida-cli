"""Per-component reachable file and metadata boundaries, with real exits.

Six supported component names exist in these explicit private byte fixtures.
Each is one chunk. Owner absence is a component input, never a public proof.
Run each test method independently within shell120s, not the combined matrix.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'tests/nexus_bridge'),str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]
from test_recovery_transaction import no_owner_input
from target_coordination import Target
from recovery_transaction import Transaction,recovery_name

EXTENSIONS=('i64','id0','id1','id2','nam','til')
DURABLE=('unbound_created','owner_unbound_created','owner_published',
         'temp_written','file_fsynced','before_rename','after_rename','directory_fsynced')


def record(case,value):
    with (case/'runs.jsonl').open('a') as output:output.write(json.dumps(value)+'\n')


def setup(case,phase):
    no_owner_input()
    from open_recovery import Snapshot
    payload=case/'payload';payload.mkdir(mode=0o700)
    path=payload/'input.i64'
    original={f'input.{ext}':('complete original '+ext).encode()*9 for ext in EXTENSIONS}
    failed={name:('complete failed '+name).encode()*9 for name in original}
    for name,data in original.items():(payload/name).write_bytes(data);(payload/name).chmod(0o640)
    reference={'target':str(path),'original':{k:hashlib.sha256(v).hexdigest() for k,v in original.items()},
               'failed':{k:hashlib.sha256(v).hexdigest() for k,v in failed.items()},'phase':phase}
    if phase!='snapshot':
        snapshot=Snapshot(case/'unused-home',path,float('inf'),owner_probe=lambda _:None)
        reference.update(recovery_id=snapshot.recovery_id,transaction=str(snapshot.path))
        for name,data in failed.items():(payload/name).write_bytes(data)
        if phase=='restore':snapshot.failed(1)
    (case/'reference.json').write_text(json.dumps(reference))


def action(case,fault):
    no_owner_input()
    import recovery_files,durable_records
    reference=json.loads((case/'reference.json').read_text())
    active=[None]
    old_copy=Transaction.copy_file;old_move=Transaction.move
    def copy_file(self,source,name,destination,*args,**kwargs):
        previous=active[0];active[0]=dict(kind='copy',name=name,folder=destination.path.name,transaction=self)
        try:return old_copy(self,source,name,destination,*args,**kwargs)
        finally:active[0]=previous
    def move(self,source,name,destination,*args,**kwargs):
        previous=active[0];active[0]=dict(kind='rename',name=name,folder=self.data['status'],transaction=self)
        try:return old_move(self,source,name,destination,*args,**kwargs)
        finally:active[0]=previous
    Transaction.copy_file=copy_file;Transaction.move=move
    def reached(value):
        if value==fault:
            (case/'reached.json').write_text(json.dumps(value));os._exit(97)
    def files(kind,stage,_detail):
        current=active[0]
        if current is not None:
            reached([current['folder'],current['name'],'file.'+stage])
    def metadata(directory,name,stage):
        current=active[0]
        if current is None or name!='recovery.json' or directory.path != current['transaction'].directory.path:return
        # Before owner publication the prospective bytes are deliberately not
        # authority. Attribute this test hook to the actual caller's in-memory
        # intent; all published boundaries still inspect exact durable bytes.
        if stage in ('unbound_created','owner_unbound_created'):
            value=current['transaction'].data
        else:value,_,_=directory.inspect_record(name)
        if current['kind']=='rename':site='intent' if value['intent'] else 'complete'
        elif value['intent'] is None:site='complete'
        else:
            entry=value['copies'][value['intent']['key']]
            site='intent' if entry['reserved'] is None else 'reserved'
        reached([current['folder'],current['name'],'record.'+site+'.'+stage])
    recovery_files.boundary=files;durable_records.boundary=metadata
    path=Path(reference['target'])
    if reference['phase']=='snapshot':
        if fault:
            from open_recovery import Snapshot
            Snapshot(case/'unused-home',path,float('inf'),owner_probe=lambda _:None)
            raise AssertionError('selected snapshot boundary not reached')
        from target_journal import Journal
        with Target(path) as target,target.locked():Journal(target).gate()
    else:
        with Target(path) as target,target.locked():
            with Transaction(target,reference['recovery_id']) as transaction:
                transaction.resume_executor()
                if reference['phase']=='capture':transaction.capture_failure(1)
                transaction.restore()
            from target_journal import Journal
            Journal(target).gate()
    if fault:raise AssertionError('selected exact component boundary was not reached')


class Components(unittest.TestCase):
    def check_component(self,extension):
        root=Path(tempfile.mkdtemp(prefix='component-'+extension+'-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        name='input.'+extension
        matrix=[]
        for phase,folder in (('snapshot','snapshot'),('capture','failed-files-1'),('restore','staging-1')):
            for stage in ('unbound_created','created','chunk','file_fsynced','directory_fsynced','checkpointed'):
                matrix.append((phase,[folder,name,'file.'+stage]))
            for site in ('intent','reserved','complete'):
                matrix.extend((phase,[folder,name,'record.'+site+'.'+stage]) for stage in DURABLE)
        for folder in ('isolating','publishing'):
            matrix.extend(('restore',[folder,name,'file.'+stage]) for stage in
                          ('before','after','source_fsynced','destination_fsynced'))
            for site in ('intent','complete'):
                matrix.extend(('restore',[folder,name,'record.'+site+'.'+stage]) for stage in DURABLE)
        coverage=[]
        for number,(phase,fault) in enumerate(matrix):
            with self.subTest(component=name,phase=phase,boundary=fault[-1]):
                case=root/f'{number:03d}';case.mkdir(mode=0o700)
                self.child(case,'setup',phase,0)
                self.child(case,'action',json.dumps(fault),97)
                self.assertEqual(json.loads((case/'reached.json').read_text()),fault)
                reference=json.loads((case/'reference.json').read_text())
                for component,expected in reference['original'].items():
                    path=Path(reference['target']).with_name(component)
                    if path.exists():self.assertIn(hashlib.sha256(path.read_bytes()).hexdigest(),
                        (expected,reference['failed'][component]),'a partial component reached a final pathname')
                self.child(case,'action','null',0)
                for component,expected in reference['original'].items():
                    path=Path(reference['target']).with_name(component)
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),expected)
                    self.assertEqual(path.stat().st_mode&0o777,0o640)
                coordination=next(Path(reference['target']).parent.glob('.ida-cli-txn-*'))
                transactions=[p for p in coordination.iterdir() if recovery_name(p.name)]
                self.assertEqual(len(transactions),1,'same obligation must resume, never allocate a successor')
                value=json.loads((transactions[0]/'recovery.json').read_text())
                self.assertEqual(value['status'],'archived' if phase=='snapshot' else 'restored')
                if phase!='snapshot':
                    self.assertEqual(value['recovery_id'],reference['recovery_id'])
                    for component,expected in reference['failed'].items():
                        self.assertEqual(hashlib.sha256((transactions[0]/'failed-files-1'/component).read_bytes()).hexdigest(),expected)
                coverage.append(dict(phase=phase,component=name,boundary=fault,reached=True,crash=97,resumed=0,
                                     case=str(case),chunk_count=1))
                (root/'coverage.json').write_text(json.dumps(coverage,indent=2))

    def child(self,case,mode,value,expected):
        argv=['timeout','8s',sys.executable,'-B',__file__,mode,str(case),value]
        before=subprocess.check_output(['timeout','5s','uptime'],text=True).strip()
        result=subprocess.run(argv,capture_output=True,text=True,check=False)
        record(case,dict(argv=argv,exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
            uptime_before=before,uptime_after=subprocess.check_output(['timeout','5s','uptime'],text=True).strip()))
        self.assertEqual(result.returncode,expected,result.stderr)

    def test_component_i64(self):self.check_component('i64')
    def test_component_id0(self):self.check_component('id0')
    def test_component_id1(self):self.check_component('id1')
    def test_component_id2(self):self.check_component('id2')
    def test_component_nam(self):self.check_component('nam')
    def test_component_til(self):self.check_component('til')


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='setup':setup(Path(sys.argv[2]),sys.argv[3])
    elif len(sys.argv)>1 and sys.argv[1]=='action':action(Path(sys.argv[2]),json.loads(sys.argv[3]))
    else:unittest.main(verbosity=2)
