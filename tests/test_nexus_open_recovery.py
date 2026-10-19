"""Initial-open retry boundaries and recovery rollback ownership/identity vetoes."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'nexus_bridge'))
import open_recovery as recovery
from cache_store import Store


class OpenTests(unittest.TestCase):
    def snapshots(self):
        # v2 authority/evidence belongs to the actual target, not this HOME.
        from target_coordination import Target
        with Target(self.target) as target:
            return sorted(path for path in target.directory.path.iterdir()
                          if path.is_dir() and (path/'recovery.json').is_file())

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root/'user'
        self.source.mkdir()
        self.target = self.source/'input.i64'
        self.target.write_bytes(b'original packed')
        self.calls, self.handles, self.released = [], [], []
        self.losses, self.initial, self.lifetime, self.lease = 0, True, True, True
        self.recovering, self.tamper = False, lambda: None
        self.wait_calls, self.unreadable = 0, False
        self.close_safe = True
        self.backend = 'idalib'
        self.mocks = [patch.dict(os.environ, {'IDA_CLI_HOME': str(self.root/'home')}),
            patch.object(recovery, 'public_owner_probe', return_value=None),
            patch.dict(sys.modules, {'ida_nexus': types.SimpleNamespace(
                get_state_dir=lambda: Path(os.environ['IDA_NEXUS_STATE_DIR']),
                probe_database_state=lambda *a, **kw: {'idb_path': str(self.target),
                    'state': 'crashed' if self.recovering else 'packed'},
                wait_database_released=self.wait)})]
        for mock in self.mocks:
            mock.start()
            self.addCleanup(mock.stop)
        self.Handle = types.SimpleNamespace(open=self.open)

    def wait(self, *_args, **_kwargs):
        self.wait_calls += 1
        self.tamper()
        return self.lifetime

    def open(self, *_args, **_kwargs):
        number = len(self.handles)+1
        self.calls.append('open')
        if self.recovering:
            self.target.write_bytes(b'bad recovered packed')
            self.target.with_suffix('.id0').write_bytes(b'owner modified component')
        parent = self

        class Handle:
            instance = types.SimpleNamespace(record_id='owner-'+str(number), idb_path=str(parent.target),
                                             backend=parent.backend)

            def execute_python(self, source, **_options):
                if source == 'guard':
                    parent.calls.append('guard')
                    if number <= parent.losses:
                        raise RuntimeError('injected guard failure')
                    return {'result': '9.5'}
                if parent.unreadable:
                    raise RuntimeError('disconnected guard query')
                return {'result': {'close_safe': parent.close_safe, 'initial': parent.initial,
                                   'evidence': {'open_attempt': number}}}

            def close_outcome(self, **_options):
                parent.calls.append('close')
                if parent.recovering:
                    parent.target.with_suffix('.id0').unlink(missing_ok=True)
                return {'status': 'lease_released' if parent.lease else 'uncertain',
                        'lease_released': parent.lease, 'shutdown_pending': False}

        handle = Handle()
        self.handles.append(handle)
        return handle

    def run_open(self, deadline=None):
        return recovery.open_checked(self.Handle, lambda **kw: kw, str(self.target), {},
            deadline or time.monotonic()+5, lambda *_: 'guard', {'method': 'open'},
            released=self.released.append)

    def make_crashed(self):
        self.recovering = True
        self.target.unlink()
        self.target.with_suffix('.id0').write_bytes(b'original component')

    def test_one_initial_failure_releases_before_reopen(self):
        self.losses = 1
        _, actual, attempts = self.run_open()
        self.assertEqual((actual, attempts), ({'result': '9.5'}, 2))
        self.assertEqual(self.calls, ['open', 'guard', 'close', 'open', 'guard'])
        self.assertEqual(len(self.released), 1)
        self.assertEqual(self.target.read_bytes(), b'original packed')

    def test_three_failures_report_count_and_keep_original(self):
        self.losses = 3
        with self.assertRaisesRegex(RuntimeError, 'after 3 attempts'):
            self.run_open()
        self.assertEqual(len(self.handles), 3)
        self.assertEqual(self.target.read_bytes(), b'original packed')

    def test_noninitial_loss_never_retries(self):
        self.losses, self.initial, self.lifetime = 1, False, False
        with self.assertRaisesRegex(RuntimeError, 'no initial Root retry'):
            self.run_open()
        self.assertEqual(len(self.handles), 1)
        self.assertEqual(self.wait_calls, 0, 'ordinary failure must not wait on a sibling owner')

    def test_gui_initial_root_failure_only_detaches_its_own_lease(self):
        self.losses, self.backend, self.lifetime = 3, 'gui', False
        with self.assertRaisesRegex(RuntimeError, 'no initial Root retry'):
            self.run_open()
        self.assertEqual(len(self.handles), 1, 'GUI owner must never be automatically reopened')
        self.assertEqual(self.calls.count('close'), 1)
        self.assertEqual(self.wait_calls, 0, 'GUI/shared owner is allowed to remain alive')

    def test_disconnected_guard_query_never_retries_or_waits_on_sibling(self):
        self.losses, self.unreadable, self.lifetime = 1, True, False
        with self.assertRaisesRegex(RuntimeError, 'exact lease retained'):
            self.run_open()
        self.assertEqual(self.calls, ['open', 'guard'])
        self.assertEqual(self.wait_calls, 0)

    def test_normal_does_not_snapshot_or_reopen(self):
        with patch.object(recovery, 'Snapshot', side_effect=AssertionError('unexpected snapshot')):
            self.assertEqual(self.run_open()[2], 1)
        self.assertEqual(self.calls, ['open', 'guard'])

    def test_total_deadline_prevents_any_public_open(self):
        with self.assertRaisesRegex(TimeoutError, 'total deadline'):
            self.run_open(time.monotonic()-1)
        self.assertEqual(self.handles, [])

    def test_recovery_restores_before_next_attempt_and_retains_bad_product(self):
        self.make_crashed()
        self.losses = 3
        with self.assertRaisesRegex(RuntimeError, 'after 3 attempts'):
            self.run_open()
        self.assertFalse(self.target.exists())
        self.assertEqual(self.target.with_suffix('.id0').read_bytes(), b'original component')
        snapshots = self.snapshots()
        self.assertEqual(len(snapshots), 1)
        saved = snapshots[0]/'snapshot/input.id0'
        self.assertEqual(saved.stat().st_mode & 0o777, 0o400)
        self.assertEqual(saved.read_bytes(), b'original component')
        self.assertEqual(len(list(snapshots[0].glob('quarantine-*/input.i64'))), 3)
        data = json.loads((snapshots[0]/'recovery.json').read_text())
        self.assertTrue(data['files']['input.id0']['inode'])
        self.assertEqual(data['status'], 'restored')

    def test_recovery_success_after_rollback(self):
        self.make_crashed()
        self.losses = 1
        self.assertEqual(self.run_open()[2], 2)
        data = json.loads((self.snapshots()[0]/'recovery.json').read_text())
        self.assertEqual(data['status'], 'opened')
        self.assertEqual(len(data['attempts']), 1)

    def test_snapshot_collection_cannot_reuse_earlier_close_proof(self):
        original = recovery.Snapshot.failed
        for fails in (False, True):
            with self.subTest(snapshot_error=fails):
                self.source = self.root/('user-snapshot-' + str(fails))
                self.source.mkdir()
                self.target = self.source/'input.i64'
                self.target.write_bytes(b'original packed')
                self.make_crashed()
                self.losses, self.close_safe = 1, True
                self.handles.clear()
                self.calls.clear()
                def collect(snapshot, number):
                    observed = original(snapshot, number)
                    self.close_safe = False
                    if fails:
                        raise OSError('injected snapshot collection failure')
                    return observed
                with patch.object(recovery.Snapshot, 'failed', collect):
                    with self.assertRaisesRegex(RuntimeError, 'exact lease retained'):
                        self.run_open()
                self.assertNotIn('close', self.calls)
                self.assertEqual(self.released, [])
                self.assertEqual(len(self.handles), 1)
                self.assertEqual(self.target.read_bytes(), b'bad recovered packed')

    def test_no_lifetime_or_no_lease_proof_never_rolls_back(self):
        for lease, lifetime in ((True, False), (False, True)):
            with self.subTest(lease=lease, lifetime=lifetime):
                self.source = self.root/('user-proof-' + str(lease) + str(lifetime))
                self.source.mkdir()
                self.target = self.source/'input.i64'
                self.target.write_bytes(b'original packed')
                self.recovering, self.losses = True, 1
                self.lease, self.lifetime = lease, lifetime
                self.handles.clear()
                with self.assertRaisesRegex(RuntimeError, 'release unconfirmed'):
                    self.run_open()
                self.assertEqual(self.target.read_bytes(), b'bad recovered packed')
                self.assertEqual(len(self.handles), 1)

    def test_identity_change_after_close_refuses_rollback(self):
        self.make_crashed()
        self.losses = 1
        self.tamper = lambda: self.target.write_bytes(b'third party')
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            self.run_open()
        self.assertEqual(self.target.read_bytes(), b'third party')
        self.assertEqual(len(self.handles), 1)

    def test_same_bytes_replaced_inode_refuses_rollback(self):
        self.make_crashed()
        self.losses = 1
        def replace():
            path = self.source/'replacement'
            path.write_bytes(self.target.read_bytes())
            path.replace(self.target)
        self.tamper = replace
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            self.run_open()
        self.assertEqual(len(self.handles), 1)

    def test_new_directory_file_refuses_rollback(self):
        self.make_crashed()
        self.losses = 1
        self.tamper = lambda: (self.source/'external').write_bytes(b'new')
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            self.run_open()
        self.assertEqual(self.target.read_bytes(), b'bad recovered packed')

    def test_external_owner_after_close_refuses_rollback(self):
        self.make_crashed()
        self.losses = 1
        self.tamper = lambda: setattr(self, 'owner', 'external opener')
        with patch.object(recovery, 'public_owner_probe', side_effect=lambda _: getattr(self, 'owner', None)):
            with self.assertRaisesRegex(RuntimeError, 'external opener'):
                self.run_open()
        self.assertEqual(self.target.read_bytes(), b'bad recovered packed')

    def test_external_ida_component_lock_refuses_restore(self):
        self.make_crashed()
        self.losses = 1
        module = sys.modules['ida_nexus']
        def lock_ida():
            module.probe_database_state = lambda *a, **kw: {'state': 'in_use'}
        self.tamper = lock_ida
        with self.assertRaisesRegex(RuntimeError, 'external IDA lock'):
            self.run_open()
        self.assertEqual(self.target.read_bytes(), b'bad recovered packed')

    def test_snapshot_tampering_and_symlinks_refuse_copy(self):
        self.make_crashed()
        snapshot = recovery.Snapshot(self.root/'home/idb', self.target, time.monotonic()+5)
        saved = snapshot.path/'snapshot/input.id0'
        saved.chmod(0o600)
        saved.write_bytes(b'tampered')
        self.target.with_suffix('.id0').unlink()
        with self.assertRaisesRegex(RuntimeError, 'snapshot content changed'):
            snapshot.rollback({})
        (self.source/'link').symlink_to(saved)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            recovery.inventory(self.source, time.monotonic()+5)

    def test_gc_and_root_lock_preserve_snapshots(self):
        self.make_crashed()
        snapshot = recovery.Snapshot(self.root/'home/idb', self.target, time.monotonic()+5)
        cache = self.root/'home/idb'
        result = Store(cache, probe=lambda _: None).collect(0)
        saved = snapshot.path/'snapshot/input.id0'
        self.assertEqual(saved.read_bytes(), b'original component')
        self.assertEqual(saved.stat().st_mode & 0o777, 0o400)
        self.assertFalse((cache/'recovery').exists(), 'HOME must not become the file authority')
        self.assertEqual((result['evicted_groups'],result['evicted_files'],result['evicted_bytes']),(0,0,0))
        with recovery.open_locks(cache, self.target, time.monotonic()+5):
            result = Store(cache, probe=lambda _: None).collect(0)
            self.assertTrue(any('cache lock' in row['reason'] for row in result['rejected']))
            with self.assertRaises(TimeoutError):
                with recovery.open_locks(cache, self.target, time.monotonic()+.01):
                    self.fail('same IDB lock was not exclusive')


if __name__ == '__main__':
    unittest.main()
