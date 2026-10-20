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
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]
from target_coordination import Target
from target_journal import Journal
from acquisition import Custodian


class TargetCustody(unittest.TestCase):
    def test_large_helper_registry_keeps_target_fact_budget_and_exact_reread(self):
        from target_coordination import Directory, MAX_RECORD
        path = self.root/'private-helper-registry'
        path.mkdir(mode=0o700)
        value = {'private_registry_fixture':'x'*(MAX_RECORD+4096)}
        directory = Directory(path)
        try:
            directory.max_record = MAX_RECORD*2
            directory.retry_immutable('helper-state.json', value, immutable=False)
            self.assertEqual(directory.read('helper-state.json')[0], value)
            facts = directory.child('proof-budget-control')
            try:
                with self.assertRaisesRegex(ValueError, 'invalid immutable fact slot'):
                    facts.retry_immutable('proof.json', value)
                self.assertEqual(list(facts.path.iterdir()), [])
            finally:
                facts.close()
        finally:
            directory.close()
        ordinary = Directory(path)
        try:
            with self.assertRaisesRegex(RuntimeError, 'oversized record'):
                ordinary.read('helper-state.json')
        finally:
            ordinary.close()

    def test_unwritable_actual_parent_refuses_before_public_probe_and_leaves_no_coordination(self):
        from open_recovery import open_checked
        with patch('ida_nexus.probe_database_state',side_effect=AssertionError('probe before writable gate')) as probe:
            self.root.chmod(0o500)
            try:
                with self.assertRaisesRegex(RuntimeError,'FilesystemCapabilitiesRefused') as caught:
                    open_checked(None,None,str(self.path),{},time.monotonic()+2,None,{})
                diagnostic=json.loads(str(caught.exception).split(': ',1)[1])
                self.assertEqual(diagnostic['probe_error']['errno'],errno.EACCES)
                self.assertEqual(diagnostic['cleanup_errors'],[])
                probe.assert_not_called()
                self.assertEqual(set(self.root.iterdir()),{self.path})
            finally:self.root.chmod(0o700)

    def test_capabilities_are_measured_before_coordination_and_cleanup_on_refusal(self):
        from target_coordination import preflight_capabilities
        import recovery_files
        original_link=os.link
        for fault in ('rename','hardlink','write'):
            with self.subTest(fault=fault), patch.dict('target_coordination._capabilities',{},clear=True):
                code=errno.ENOTSUP if fault!='write' else errno.ENOSPC
                def refuse(*_args,**_kwargs):
                    raise OSError(code,'actual filesystem exception injection')
                def link(*args,**kwargs):
                    return refuse() if fault=='hardlink' else original_link(*args,**kwargs)
                with patch.object(recovery_files,'rename_noreplace',refuse) if fault=='rename' else patch.object(os,'link',link), \
                        patch.object(os,'write',refuse) if fault=='write' else patch.object(os,'pread',os.pread):
                    with self.assertRaisesRegex(RuntimeError,'FilesystemCapabilitiesRefused') as caught:
                        preflight_capabilities(self.path)
                diagnostic=json.loads(str(caught.exception).split(': ',1)[1])
                self.assertFalse(diagnostic['supported'])
                self.assertEqual(diagnostic['cleanup_errors'],[])
                self.assertEqual(diagnostic.get('probe_error',{}).get('errno') if fault=='write'
                    else diagnostic['no_replace_rename' if fault=='rename' else 'hardlink']['errno'],code)
                self.assertEqual(set(self.root.iterdir()),{self.path})
                self.assertEqual(self.path.read_bytes(),b'private target input')

    def test_darwin_case_alias_uses_disk_spelling_and_one_stable_exclusion(self):
        if sys.platform!='darwin':
            from target_coordination import folded
            self.assertEqual(folded(self.root/'Foo.i64')==folded(self.root/'foo.i64'),os.name=='nt')
            return
        physical=self.root/'Foo.i64';physical.write_bytes(b'private case alias');physical.chmod(0o600)
        lower=self.root/'foo.i64'
        with Target(lower) as first,first.locked():
            self.assertEqual(first.target.name,'Foo.i64')
            identity=os.fstat(first.target_fd).st_ino
            key=first.key
            with Target(physical) as second:
                self.assertEqual(second.key,key)
                with self.assertRaises(BlockingIOError):
                    with second.locked(nb=True):self.fail('case alias obtained a different lock')
        with Target(lower) as target,target.locked():
            self.assertEqual(target.key,key)
            self.assertEqual(os.fstat(target.target_fd).st_ino,identity)
            self.assertEqual(target.target.name,'Foo.i64')

    def setUp(self):
        from target_coordination import _capabilities
        isolated=patch.dict(_capabilities,{},clear=True)
        isolated.start()
        self.addCleanup(isolated.stop)
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


class VerificationSnapshot(unittest.TestCase):
    def test_replacement_before_first_fstat_retries_without_accepting_an_untrusted_fd(self):
        import target_journal
        from contextlib import closing
        from target_coordination import Directory
        with tempfile.TemporaryDirectory(dir=os.environ['R3A_CASE_ROOT']) as temporary:
            root = Path(temporary)
            with closing(Directory(root)) as directory:
                directory.durable('custody.json', {'revision':1})
                original = os.open
                replaced = []
                def open_record(name, *args, **kwargs):
                    descriptor = original(name, *args, **kwargs)
                    if name == 'custody.json' and kwargs.get('dir_fd') == directory.fd and not replaced:
                        replaced.append(True)
                        replacement = root/'next'
                        replacement.write_text('{"revision":2}')
                        replacement.chmod(0o600)
                        replacement.replace(root/'custody.json')
                    return descriptor
                with patch('target_coordination.os.open', side_effect=open_record):
                    self.assertEqual(target_journal.verification_snapshot(directory)[0], {'revision':2})
                self.assertEqual(replaced, [True], 'actual opened inode was replaced before validation')

    def test_untrusted_record_is_not_reclassified_as_publication_race(self):
        import target_journal
        from contextlib import closing
        from target_coordination import Directory
        with tempfile.TemporaryDirectory(dir=os.environ['R3A_CASE_ROOT']) as temporary:
            root = Path(temporary)
            with closing(Directory(root)) as directory:
                directory.durable('custody.json', {'revision':1})
                os.link(root/'custody.json', root/'extra-link')
                with self.assertRaisesRegex(RuntimeError, 'untrusted type/uid/mode/link identity'):
                    target_journal.verification_snapshot(directory)

    def test_atomic_replacement_is_retried_but_mutating_a_record_never_passes(self):
        from unittest.mock import patch
        import tempfile
        import target_journal
        from target_coordination import Directory
        root = Path(tempfile.mkdtemp(dir=os.environ['R3A_CASE_ROOT'], prefix='verify-snapshot-'))
        from contextlib import closing
        with closing(Directory(root)) as directory:
            directory.durable('custody.json', {'revision':1})
            original = os.stat
            replaced = []
            def stat(name, *args, **kwargs):
                if name == 'custody.json' and kwargs.get('dir_fd') == directory.fd and not replaced:
                    replaced.append(True)
                    temporary = root/'next'
                    temporary.write_text('{"revision":2}')
                    temporary.chmod(0o600)
                    temporary.replace(root/'custody.json')
                return original(name,*args,**kwargs)
            with patch('target_coordination.os.stat', side_effect=stat):
                self.assertEqual(target_journal.verification_snapshot(directory)[0], {'revision':2})
            with patch.object(directory,'read',side_effect=RuntimeError('CoordinationBlocked: record changed during read')) as read:
                with self.assertRaisesRegex(RuntimeError,'record changed during read'):
                    target_journal.verification_snapshot(directory)
                self.assertEqual(read.call_count,8,'verification has a fixed retry bound')
