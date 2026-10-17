"""Target authority uses private files and real cross-process locks."""
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'nexus_bridge/custody'))
from target_coordination import Target
from target_journal import Journal
from acquisition import Custodian


class TargetCustody(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ['R3A_CASE_ROOT'])
        base.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='t-', dir=base))
        self.path = self.root/'tiny.i64'
        self.path.write_bytes(b'private target input')

    def test_rejected_gate_releases_its_real_lock_and_directory_descriptors(self):
        with Target(self.path) as target:
            with target.locked():
                target.directory.durable('custody.json', {'schema':'corrupt'})
        custody = Custodian.__new__(Custodian)
        custody.target_guard = None
        custody.deadline = time.monotonic()+2
        custody.helper = {'state_root':{}}
        with self.assertRaisesRegex(RuntimeError, 'corrupt custody journal'):
            with custody.gate(self.path):
                self.fail('corrupt journal was accepted')
        self.assertIsNone(custody.target)
        self.assertIsNone(custody.target_guard)
        script = ('from target_coordination import Target; import sys\n'
                  'with Target(sys.argv[1]) as target:\n'
                  ' with target.locked(nb=True): pass\n')
        result = subprocess.run([sys.executable, '-B', '-c', script, str(self.path)],
            env=dict(os.environ, PYTHONPATH=str(REPO/'nexus_bridge/custody')),
            capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_two_homes_use_one_stable_target_lock_and_partial_creation_blocks(self):
        script = '''
import json,sys
from target_coordination import Target
try:
 with Target(sys.argv[1]) as target:
  with target.locked(nb=True):
   info=(target.directory.path/'lock').stat()
   print(json.dumps([info.st_dev,info.st_ino]))
except BlockingIOError:
 sys.exit(17)
'''
        environment = dict(os.environ, HOME=str(self.root/'other-home'),
                           PYTHONPATH=str(REPO/'nexus_bridge/custody'))
        command = [sys.executable, '-B', '-c', script, str(self.path)]
        with Target(self.path) as target:
            with target.locked():
                lock = (target.directory.path/'lock').stat()
                denied = subprocess.run(command, env=environment, capture_output=True, timeout=3)
                self.assertEqual(denied.returncode, 17, denied.stderr)
            granted = subprocess.run(command, env=environment, capture_output=True, timeout=3)
            self.assertEqual(granted.returncode, 0, granted.stderr)
            self.assertEqual(json.loads(granted.stdout), [lock.st_dev, lock.st_ino])
            target.directory.durable('target.json', {'schema':1, 'creation_intent':True})
        with Target(self.path) as target:
            with self.assertRaisesRegex(RuntimeError, 'identity mismatch'):
                with target.locked():
                    self.fail('partial creation was accepted')

    def test_missing_identity_with_existing_responsibility_is_never_recreated(self):
        with Target(self.path) as target:
            with target.locked():
                target.directory.durable('custody.json', {'unknown':'retained'})
            (target.directory.path/'target.json').unlink()
            with self.assertRaisesRegex(RuntimeError, 'existing responsibilities'):
                with target.locked():
                    self.fail('missing identity revived existing journal')
            self.assertTrue((target.directory.path/'custody.json').is_file())

    def test_managed_original_and_quarantine_keep_same_lock_bad_manifest_never_falls_back(self):
        group = self.root/'cache/generations/g-one'
        group.mkdir(parents=True)
        (group/'generation.json').write_text(json.dumps({'version':1,'key':'private'}))
        database = group/'input.i64'
        database.write_bytes(b'payload')
        with Target(database) as target:
            with target.locked():
                original = (target.directory.path/'lock').stat()
        quarantine = self.root/'cache/quarantine/g-one'
        quarantine.parent.mkdir()
        group.rename(quarantine)
        for path in (database, quarantine/'input.i64'):
            with Target(path) as target:
                with target.locked():
                    current = (target.directory.path/'lock').stat()
                    self.assertEqual((current.st_dev,current.st_ino),(original.st_dev,original.st_ino))
        (quarantine/'generation.json').write_text('{corrupt')
        with self.assertRaises(json.JSONDecodeError):
            Target(database)
        self.assertEqual(list(quarantine.glob('.ida-cli-txn-*')), [])

    def test_enospc_keeps_interrupted_write_and_blocks_gate_without_deleting_evidence(self):
        with Target(self.path) as target:
            with target.locked():
                with patch('target_coordination.os.write', side_effect=OSError(errno.ENOSPC, 'injected private disk full')):
                    with self.assertRaises(OSError) as caught:
                        target.directory.durable('custody.json', {'private':'intent'})
                self.assertEqual(caught.exception.errno, errno.ENOSPC)
                partial = target.directory.path/'custody.json.new'
                self.assertTrue(partial.exists())
                with self.assertRaisesRegex(RuntimeError, 'interrupted durable write'):
                    Journal(target).gate()
                self.assertTrue(partial.exists())

    def test_retained_full_refuses_admission_but_preserves_cleanup_writer(self):
        with Target(self.path) as target:
            with target.locked():
                retained = target.directory.child('retained')
                try:
                    for index in range(17):
                        retained.durable(f'{index}.json', {'kind':'ObservationFailed','data':'x'*(1024*1024-100)})
                finally:
                    retained.close()
                journal = Journal(target)
                stats = journal.accounting()
                self.assertEqual(stats['retained_warning_percent'], 100)
                with self.assertRaisesRegex(RuntimeError, 'RetainedEvidenceFull'):
                    journal.begin({'parent':'private'}, 'new-watch')
                # Existing closure/status authority can still durably write;
                # quota admission must not discard the retained evidence.
                journal.save()
                self.assertEqual(journal.accounting()['retained_evidence_bytes'], stats['retained_evidence_bytes'])

    def test_live_and_routine_budgets_keep_unacknowledged_observations_and_emergency_writer(self):
        from target_coordination import LIMIT, RESERVE
        with Target(self.path) as target:
            with target.locked():
                journal = Journal(target)
                for index in range(LIMIT-RESERVE):
                    journal.begin({'parent':f'private-{index}'}, f'pending-{index}')
                journal.settle()
                self.assertEqual(len(journal.value['entries']), LIMIT-RESERVE)
                self.assertTrue(all(i['unacked_events'] for i in journal.value['entries'].values()))
                with self.assertRaisesRegex(RuntimeError, 'Busy: live_refs;'):
                    journal.begin({'parent':'overflow'}, 'overflow')
                journal.save()  # Existing cleanup/status does not require a new slot.
        other = self.root/'routine.i64'
        other.write_bytes(b'private input')
        with Target(other) as target:
            with target.locked():
                observations = target.directory.child('observations')
                producer = observations.child('private-budget')
                try:
                    for index in range(2):
                        producer.durable(f'{index}.json', {'kind':'Subscribed', 'data':'x'*(900*1024)})
                finally:
                    producer.close()
                    observations.close()
                journal = Journal(target)
                with self.assertRaisesRegex(RuntimeError, 'Busy: live_refs routine budget'):
                    journal.begin({'parent':'routine-overflow'}, 'routine-overflow')
                journal.save()
                self.assertEqual(journal.accounting()['retained_evidence_bytes'], 0)


if __name__ == '__main__':
    unittest.main()
