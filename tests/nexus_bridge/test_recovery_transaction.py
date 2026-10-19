"""Actual v2 file steps under real locks, process exits and fresh executors.

Occupancy is an explicit absent-owner input in this component matrix. Actual
N1/SDK/helper proofs and real IDA are separate integration gates.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest

REPO = Path(os.environ.get('R4_PRODUCT_SOURCE',Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]


def no_owner_input():
    import cache_store
    cache_store.public_owner_probe = lambda _path:None
    sys.modules['ida_nexus'] = types.SimpleNamespace(probe_database_state=lambda *_a,**_kw:{'state':'crashed'})


def isolate_owner_input(test):
    """Restore process-global input adapters before other production suites."""
    import cache_store
    original_probe = cache_store.public_owner_probe
    had_sdk, original_sdk = 'ida_nexus' in sys.modules, sys.modules.get('ida_nexus')
    def restore():
        cache_store.public_owner_probe = original_probe
        if had_sdk:sys.modules['ida_nexus'] = original_sdk
        else:sys.modules.pop('ida_nexus',None)
    test.addCleanup(restore)


def setup(case):
    no_owner_input()
    from open_recovery import Snapshot
    payload = case/'payload'
    payload.mkdir(mode=0o700)
    target = payload/'input.i64'
    files = {'input.i64':b'original packed'*9,'input.id0':b'original id0'*9,'input.id1':b'original id1'*9}
    for name,data in files.items():
        (payload/name).write_bytes(data)
        (payload/name).chmod(0o640)
    snapshot = Snapshot(case/'unused-home',target,float('inf'),owner_probe=lambda _:None)
    for name in files:(payload/name).write_bytes(b'failed scene '+name.encode())
    snapshot.failed(1)
    (case/'reference.json').write_text(json.dumps({'target':str(target),'recovery_id':snapshot.recovery_id,
        'path':str(snapshot.path),'original':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()},
        'failed':{name:hashlib.sha256((payload/name).read_bytes()).hexdigest() for name in files}}))


def restore(case, fault):
    no_owner_input()
    from target_coordination import Target
    from recovery_transaction import Transaction
    import recovery_files
    from target_journal import Journal
    original_intent=Journal.file_intent
    def commit_index(journal,path,status,attempts):
        if fault=='terminal_index' and status=='restored':os._exit(96)
        return original_intent(journal,path,status,attempts)
    Journal.file_intent=commit_index
    reference = json.loads((case/'reference.json').read_text())
    with Target(reference['target']) as target,target.locked():
        with Transaction(target,reference['recovery_id']) as transaction:
            transaction.resume_executor()
            def boundary(action,stage,detail):
                actual = action+'.'+stage
                if action=='rename':actual=transaction.data['status']+'.'+stage
                if fault==actual:os._exit(96)
            recovery_files.boundary = boundary
            # phase's imported hook is intentionally the same fault input.
            import recovery_transaction
            recovery_transaction.boundary = boundary
            transaction.restore()
    from target_journal import Journal
    with Target(reference['target']) as target,target.locked():Journal(target).gate()


def create_snapshot(case,fault):
    no_owner_input()
    from open_recovery import Snapshot
    import recovery_files
    import recovery_transaction
    def boundary(action,stage,_detail):
        if action+'.'+stage==fault:os._exit(96)
    recovery_files.boundary=boundary
    recovery_transaction.boundary=boundary
    Snapshot(case/'home',case/'payload/input.i64',float('inf'),owner_probe=lambda _:None)
    (case/'resolver-entered').touch()


def gate_snapshot(case):
    no_owner_input()
    from target_coordination import Target
    from target_journal import Journal
    from recovery_transaction import inspect_transactions
    with Target(case/'payload/input.i64') as target,target.locked():
        Journal(target).gate()
        records=inspect_transactions(target)
        assert len(records)==1 and records[0]['phase']=='archived',records
        (case/'gate-result.json').write_text(json.dumps(records))


class FileTransaction(unittest.TestCase):
    def test_creation_exits_never_enter_resolver_and_next_gate_archives_same_obligation(self):
        root=Path(tempfile.mkdtemp(prefix='snapshot-creation-',dir=os.environ['R3A_CASE_ROOT']))
        for fault in ('create.intent','create.directory','create.published','phase.snapshotting',
                'copy.created','copy.chunk','copy.file_fsynced','copy.directory_fsynced','phase.ready'):
            with self.subTest(fault=fault):
                case=root/fault
                (case/'payload').mkdir(mode=0o700,parents=True)
                path=case/'payload/input.i64'
                path.write_bytes(b'original pre-resolver packed')
                result=self.child('--create',case,fault)
                self.assertEqual(result.returncode,96,result.stderr)
                self.assertFalse((case/'resolver-entered').exists())
                lock=next(path.parent.glob('.ida-cli-txn-*'))/'lock'
                inode=lock.stat().st_ino
                result=self.child('--creation-gate',case)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(path.read_bytes(),b'original pre-resolver packed')
                self.assertEqual(lock.stat().st_ino,inode)

    def child(self, mode, case, fault='none'):
        argv=['timeout','10s',sys.executable,'-B',__file__,mode,str(case),fault]
        before=subprocess.check_output(['uptime'],text=True).strip()
        result=subprocess.run(argv,capture_output=True,text=True,check=False)
        row=dict(argv=argv,exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
                 uptime_before=before,uptime_after=subprocess.check_output(['uptime'],text=True).strip())
        with (case/'runs.jsonl').open('a') as stream:stream.write(json.dumps(row)+'\n')
        return result

    def test_file_phase_copy_and_rename_exits_resume_without_partial_final_files(self):
        root=Path(tempfile.mkdtemp(prefix='txn-matrix-',dir=os.environ['R3A_CASE_ROOT']))
        faults=['phase.staging','copy.created','copy.chunk','copy.file_fsynced','copy.directory_fsynced',
                'phase.prepared','phase.isolating','isolating.before','isolating.after',
                'isolating.source_fsynced','isolating.destination_fsynced','phase.publishing',
                'publishing.before','publishing.after','publishing.source_fsynced',
                'publishing.destination_fsynced','phase.restored']
        for fault in faults:
            with self.subTest(fault=fault):
                case=root/fault
                case.mkdir(mode=0o700)
                result=self.child('--setup',case)
                self.assertEqual(result.returncode,0,result.stderr)
                result=self.child('--restore',case,fault)
                self.assertEqual(result.returncode,96,result.stderr)
                reference=json.loads((case/'reference.json').read_text())
                for name,expected in reference['original'].items():
                    path=case/'payload'/name
                    if path.exists():
                        self.assertIn(hashlib.sha256(path.read_bytes()).hexdigest(),
                                      (expected,reference['failed'][name]),'partial file exposed at final path')
                result=self.child('--restore',case)
                self.assertEqual(result.returncode,0,result.stderr)
                for name,expected in reference['original'].items():
                    path=case/'payload'/name
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),expected)
                    self.assertEqual(path.stat().st_mode & 0o777,0o640)
                transaction=Path(reference['path'])
                self.assertTrue((transaction/'failed-files-1/input.id0').is_file())
                self.assertTrue((transaction/'quarantine-1/input.id0').is_file())

    def test_gate_finishes_terminal_index_without_replaying_file_actions(self):
        case=Path(tempfile.mkdtemp(prefix='terminal-index-',dir=os.environ['R3A_CASE_ROOT']))
        result=self.child('--setup',case)
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.child('--restore',case,'terminal_index')
        self.assertEqual(result.returncode,96,result.stderr)
        reference=json.loads((case/'reference.json').read_text())
        path=Path(reference['path'])/'recovery.json'
        before=json.loads(path.read_text())
        self.assertEqual(before['status'],'restored')
        files={p.name:(p.stat().st_ino,p.stat().st_mtime_ns,p.read_bytes()) for p in (case/'payload').iterdir() if p.is_file()}
        result=self.child('--gate',case)
        self.assertEqual(result.returncode,0,result.stderr)
        after=json.loads(path.read_text())
        self.assertEqual(after['status'],'restored')
        self.assertEqual(after['moves'],before['moves'],'no second file job or rename replay')
        self.assertEqual({p.name:(p.stat().st_ino,p.stat().st_mtime_ns,p.read_bytes()) for p in (case/'payload').iterdir() if p.is_file()},files)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--setup':setup(Path(sys.argv[2]))
    elif len(sys.argv)>1 and sys.argv[1]=='--create':create_snapshot(Path(sys.argv[2]),sys.argv[3])
    elif len(sys.argv)>1 and sys.argv[1]=='--creation-gate':gate_snapshot(Path(sys.argv[2]))
    elif len(sys.argv)>1 and sys.argv[1]=='--restore':restore(Path(sys.argv[2]),sys.argv[3])
    elif len(sys.argv)>1 and sys.argv[1]=='--gate':
        no_owner_input()
        from target_coordination import Target
        from target_journal import Journal
        reference=json.loads((Path(sys.argv[2])/'reference.json').read_text())
        with Target(reference['target']) as target,target.locked():Journal(target).gate()
    else:unittest.main(verbosity=2)
