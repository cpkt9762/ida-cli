"""Actual fixed SDK backup producer and production file classification."""
import os
import fcntl
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]
from open_recovery import Snapshot
from target_coordination import Target
from target_journal import Journal


class Backups(unittest.TestCase):
    def scene(self, packed=True):
        root=Path(tempfile.mkdtemp(prefix='sdk-backup-',dir=os.environ['R3A_CASE_ROOT']))
        target=root/'input.i64'
        if packed:target.write_bytes(b'original packed')
        target.with_suffix('.id0').write_bytes(bytes(18)+b'\x01B-tree v2original component')
        target.with_suffix('.id1').write_bytes(b'original id1')
        for p in root.iterdir():p.chmod(0o600)
        snapshot=Snapshot(root/'home',target,float('inf'),owner_probe=lambda _:None)
        return root,target,snapshot

    def test_sdk_complete_backup_is_retained_with_or_without_packed(self):
        from ida_nexus.database_state import probe_database_state, _backup_unpacked_database
        for packed in (True,False):
            with self.subTest(packed=packed):
                root,target,snapshot=self.scene(packed)
                state=probe_database_state(target)
                self.assertEqual(state['state'],'crashed')
                backup=Path(_backup_unpacked_database(state))
                original={p.name:p.read_bytes() for p in backup.iterdir()}
                target.with_suffix('.id0').write_bytes(bytes(18)+b'\x01B-tree v2failed component')
                observed=snapshot.failed(1)
                snapshot.rollback(observed)
                self.assertEqual(snapshot.data['status'],'restored')
                self.assertIn(backup.name,snapshot.data['backups'])
                self.assertEqual({p.name:p.read_bytes() for p in backup.iterdir()},original)
                self.assertEqual(target.with_suffix('.id0').read_bytes(),original['input.id0'])
                self.assertEqual(target.exists(),packed)

    def test_partial_backup_production_copy_failure_preserves_and_blocks(self):
        from ida_nexus.database_state import probe_database_state, _backup_unpacked_database
        root,target,snapshot=self.scene()
        def interrupted(input_file,output_file,**_kwargs):
            output_file.write(input_file.read(7))
            output_file.flush()
            os.fsync(output_file.fileno())
            raise OSError('controlled SDK backup I/O failure')
        with patch('ida_nexus.database_state.shutil.copyfileobj',interrupted):
            with self.assertRaisesRegex(OSError,'controlled SDK'):
                _backup_unpacked_database(probe_database_state(target))
        backups=list(root.glob('input.i64.crash-*'))
        self.assertEqual(len(backups),1)
        before={p.name:p.read_bytes() for p in backups[0].iterdir()}
        with self.assertRaisesRegex(RuntimeError,'partial|content'):
            snapshot.resolver_failed(no_acquisition=True)
        with Target(target) as coordination,coordination.locked():
            with self.assertRaisesRegex(RuntimeError,'RecoveryBlocked'):
                Journal(coordination).gate()
        self.assertEqual({p.name:p.read_bytes() for p in backups[0].iterdir()},before)
        self.assertTrue(snapshot.path.exists())

    def test_backup_then_resolve_failure_archives_without_rollback(self):
        from ida_nexus.database_state import probe_database_state, _backup_unpacked_database
        root,target,snapshot=self.scene()
        backup=Path(_backup_unpacked_database(probe_database_state(target)))
        before=target.read_bytes()
        snapshot.resolver_failed(no_acquisition=True)
        self.assertEqual(snapshot.data['status'],'archived')
        self.assertEqual(target.read_bytes(),before)
        self.assertTrue(backup.is_dir())

    def test_actual_sdk_lock_on_own_quarantined_id0_blocks_further_publication(self):
        _,target,snapshot=self.scene()
        observed=snapshot.failed(1)
        held=[]
        def after_rename(action,stage,detail):
            if (action=='rename' and stage=='after' and not held
                    and Path(detail['source']).suffix=='.id0'):
                fd=os.open(detail['destination'],os.O_RDONLY)
                fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
                held.append(fd)
        def id0_first(action,stage,_detail):
            if action=='phase' and stage=='isolating':
                transaction=snapshot.active
                record=transaction.data['attempts'][-1]
                original=record['remaining']
                names=sorted(original,key=lambda name:(not name.endswith('.id0'),name))
                record['remaining']={name:original[name] for name in names}
                transaction.save()  # Scheduling order only; all predicates and bindings are unchanged.
        try:
            with patch('recovery_files.boundary',after_rename),patch('recovery_transaction.boundary',id0_first):
                with self.assertRaisesRegex(RuntimeError,'external IDA lock'):
                    snapshot.rollback(observed)
            self.assertEqual(len(held),1,'actual quarantine lock boundary must execute')
            self.assertEqual(snapshot.data['status'],'isolating')
        finally:
            for fd in held:os.close(fd)
        snapshot.rollback(observed)
        self.assertEqual(snapshot.data['status'],'restored')

    def test_unexplained_missing_id0_is_never_an_authorized_split(self):
        _,target,snapshot=self.scene()
        observed=snapshot.failed(1)
        original_id1=target.with_suffix('.id1').read_bytes()
        target.with_suffix('.id0').unlink()  # Explicit unrelated file fault, outside any move intent.
        with self.assertRaisesRegex(RuntimeError,'occupancy is not confirmed'):
            snapshot.rollback(observed)
        self.assertEqual(snapshot.data['status'],'failed-owner-held')
        self.assertEqual(target.with_suffix('.id1').read_bytes(),original_id1)


if __name__=='__main__':unittest.main(verbosity=2)
