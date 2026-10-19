"""Production file intents with controlled errno and real hostile files.

Errno injection is not physical disk exhaustion or a mounted EXDEV platform.
Fresh-process byte recovery is shared with the process-exit transaction suite.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge'),str(Path(__file__).parent)]
from test_recovery_transaction import isolate_owner_input, setup
from recovery_transaction import Transaction
from target_coordination import Target
from recovery_files import file_info


class RecoveryIO(unittest.TestCase):
    def setUp(self):isolate_owner_input(self)

    def scene(self,label):
        case=Path(tempfile.mkdtemp(prefix=label+'-',dir=os.environ['R3A_CASE_ROOT']))
        setup(case)
        return case,json.loads((case/'reference.json').read_text())

    def test_real_retained_bytes_warn_at_80_95_100_and_keep_emergency_closure(self):
        from target_journal import Journal
        for percent in (80,95,100):
            with self.subTest(percent=percent):
                root=Path(tempfile.mkdtemp(prefix='retained-'+str(percent)+'-',dir=os.environ['R3A_CASE_ROOT']))
                path=root/'input.i64'
                path.write_bytes(b'original')
                with Target(path) as target,target.locked():
                    journal=Journal(target)
                    journal.begin({'parent':{'operation_id':'existing'},'purpose':'final','ordinal':1},'existing')
                    retained=target.directory.child('retained')
                    try:
                        limit=journal.accounting()['retained_evidence_limit_bytes']
                        left=limit*percent//100+1024
                        index=0
                        while left:
                            size=min(left,900*1024)
                            retained.durable(str(index)+'.json',{'kind':'ObservationFailed','data':'x'*size})
                            left-=size
                            index+=1
                        actual=sum(p.stat().st_size for p in retained.path.iterdir())
                        stats=journal.accounting()
                        self.assertEqual(stats['retained_evidence_bytes'],actual)
                        self.assertEqual(stats['retained_warning_percent'],percent)
                        if percent==100:
                            with self.assertRaisesRegex(RuntimeError,'RetainedEvidenceFull'):
                                journal.begin({'parent':{'operation_id':'new'},'purpose':'final','ordinal':1},'new')
                        else:
                            journal.begin({'parent':{'operation_id':'new'},'purpose':'final','ordinal':1},'new')
                            journal.abort_unstarted('new')
                        journal.abort_unstarted('existing')
                        self.assertEqual(journal.accounting()['retained_evidence_bytes'],actual)
                        self.assertTrue(all(p.is_file() for p in retained.path.iterdir()))
                    finally:retained.close()

    def test_errno_preserves_all_versions_and_existing_job_finishes_at_full_budget(self):
        for action,stage,code in (('copy','created',errno.EACCES),('copy','chunk',errno.ENOSPC),
            ('copy','file_fsynced',errno.EIO),('rename','before',errno.EXDEV),
            ('rename','after',errno.EIO),('rename','source_fsynced',errno.EIO)):
            with self.subTest(action=action,stage=stage,errno=code):
                case,reference=self.scene(action+'-'+stage)
                path=Path(reference['target'])
                fired=[]
                def boundary(actual,point,_detail):
                    if (actual,point)==(action,stage) and not fired:
                        fired.append(True)
                        raise OSError(code,'controlled file I/O boundary')
                with Target(path) as target,target.locked():
                    with Transaction(target,reference['recovery_id']) as transaction:
                        transaction.resume_executor()
                        with patch('recovery_files.boundary',boundary):
                            with self.assertRaises(OSError) as caught:transaction.restore()
                        self.assertEqual(caught.exception.errno,code)
                        self.assertTrue(fired)
                        for name,original in reference['original'].items():
                            if (path.parent/name).exists():
                                actual=hashlib.sha256((path.parent/name).read_bytes()).hexdigest()
                                self.assertIn(actual,(original,reference['failed'][name]),'no partial final component')
                        snapshot=transaction.directory.child('snapshot',create=False)
                        failed=transaction.directory.child('failed-files-1',create=False)
                        try:
                            for name,original in reference['original'].items():
                                self.assertEqual(file_info(snapshot,name)['sha256'],original)
                                self.assertEqual(file_info(failed,name)['sha256'],reference['failed'][name])
                        finally:snapshot.close();failed.close()
                # A full admission budget refuses a new transaction but may
                # never prevent this already accepted obligation finishing.
                with Target(path) as target,target.locked():
                    with patch('recovery_transaction.FILE_LIMIT',1):
                        with self.assertRaisesRegex(RuntimeError,'RetainedEvidenceFull'):Transaction.allocate(target)
                        with Transaction(target,reference['recovery_id']) as transaction:
                            transaction.resume_executor()
                            transaction.restore()
                            self.assertEqual(transaction.data['status'],'restored')
                for name,original in reference['original'].items():
                    self.assertEqual(hashlib.sha256((path.parent/name).read_bytes()).hexdigest(),original)

    def test_symlink_hardlink_replaced_snapshot_and_unknown_namespace_preserve_scene(self):
        for variant in ('symlink','hardlink','changed-snapshot','foreign-destination','unknown-namespace','extra-snapshot'):
            with self.subTest(variant=variant):
                case,reference=self.scene(variant)
                path=Path(reference['target'])
                snapshot=Path(reference['path'])/'snapshot/input.i64'
                if variant=='symlink':
                    snapshot.unlink()
                    snapshot.symlink_to(path)
                elif variant=='hardlink':
                    snapshot.unlink()
                    os.link(path,snapshot)
                elif variant=='changed-snapshot':
                    snapshot.chmod(0o600)
                    snapshot.write_bytes(b'foreign snapshot')
                elif variant=='unknown-namespace':
                    (Path(reference['path'])/'foreign.json').write_text('unknown evidence must remain')
                elif variant=='extra-snapshot':
                    (snapshot.parent/'foreign').write_text('unknown snapshot must remain')
                else:
                    with Target(path) as target,target.locked():
                        with Transaction(target,reference['recovery_id']) as transaction:
                            transaction.resume_executor()
                            with patch('recovery_files.boundary',side_effect=OSError('pause staging')):
                                with self.assertRaises(OSError):transaction.restore()
                    foreign=Path(reference['path'])/'staging-1/input.i64'
                    foreign.write_bytes(b'foreign destination')
                    foreign.chmod(0o600)
                before={p.name:p.read_bytes() for p in path.parent.iterdir() if p.is_file()}
                with Target(path) as target,target.locked():
                    with self.assertRaises((OSError,RuntimeError)):
                        with Transaction(target,reference['recovery_id']) as transaction:
                            transaction.resume_executor()
                            transaction.restore()
                self.assertEqual({p.name:p.read_bytes() for p in path.parent.iterdir() if p.is_file()},before)


if __name__=='__main__':unittest.main(verbosity=2)
