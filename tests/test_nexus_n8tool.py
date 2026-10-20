"""Legacy cache governance regressions; all fixtures are private copies."""
import fcntl
import hashlib
import json
import time
from unittest.mock import patch
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO/'nexus_bridge/legacy_cache.py'


class EntryTests(unittest.TestCase):
    def test_dry_run_does_not_mutate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root/'idb'
            cache.mkdir()
            (cache/'sample.abcdef123456.dylib.i64').write_bytes(b'user modifications')
            (cache/'sample.abcdef123456.dylib.id0').write_bytes(b'component')
            (cache/'index.json').write_text('{}')
            before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in cache.iterdir()}
            result = subprocess.run(['timeout', '10s', sys.executable, '-B', str(TOOL),
                                     '--root', str(cache)],
                                    env=os.environ | {'HOME': str(root), 'IDA_CLI_HOME': str(root)},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in cache.iterdir()}
            self.assertEqual(before, after)
            self.assertIn('sample.abcdef123456.dylib.i64', result.stdout)
            self.assertIn('component', result.stdout)

    def test_explicit_timeout_is_visible_in_dry_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root/'idb').mkdir(mode=0o700)
            result = subprocess.run(['timeout', '10s', sys.executable, '-B', str(TOOL), '--root', str(root/'idb')],
                env=os.environ | {'HOME': str(root), 'IDA_CLI_HOME': str(root), 'IDA_CLI_LEGACY_TIMEOUT_SECS': '150'},
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['maintenance_timeout']['seconds'], 150)




# Loading is delayed so the baseline red remains a real entrypoint assertion.
def modules():
    sys.path[:0] = [str(REPO/'nexus_bridge'), str(REPO/'nexus_bridge/custody')]
    import legacy_cache
    return legacy_cache


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.tool = modules()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root/'home'
        self.home.mkdir(mode=0o700)
        self.cache = self.home/'idb'
        self.cache.mkdir(mode=0o700)
        self.state = self.root/'state'
        self.state.mkdir(mode=0o700)
        self.backups = self.root/'backups'
        self.backups.mkdir(mode=0o700)
        self.backup = self.backups/'transaction'
        self.key = 'abcdef123456'
        self.group = 'sample.' + self.key + '.dylib.i64'
        self.input = b'original input snapshot'
        self.edits = b'packed database with user modifications'
        (self.cache/self.group).write_bytes(self.edits)
        (self.cache/self.group[:-4]).write_bytes(self.input)
        self.entry = {'hash': self.key, 'original_path': 'source', 'binary_type': 'native',
                      'size': len(self.input), 'created_at': '1Z', 'last_accessed': '1Z'}
        (self.cache/'index.json').write_text(json.dumps({self.key: self.entry}))
        self.original_index = (self.cache/'index.json').read_bytes()
        self.probe = lambda path, states: {'packed': path.exists(), 'openers': None,
                                          'state': 'packed' if path.exists() else 'missing'}
        self.inspector = lambda *_: {'input_sha256': hashlib.sha256(self.input).hexdigest()}
        env = patch.dict(os.environ, HOME=str(self.home), IDA_CLI_HOME=str(self.home),
                         IDA_NEXUS_STATE_DIR=str(self.state))
        env.start()
        self.addCleanup(env.stop)

    def evidence(self, mode):
        _, digest = self.tool.plan(self.cache, mode, self.group, [self.home], [self.state],
                                   self.backup, probe=self.probe)
        return {'schema': 1, 'plan_sha256': digest, 'root': self.tool.offline.binding(self.cache),
                'router_homes': [self.tool.offline.binding(self.home)],
                'state_roots': [self.tool.offline.binding(self.state)],
                'uid': os.getuid(), 'boot_id': self.tool.offline.boot(),
                'operator': 'private fixture owner', 'exclusion_method': 'all fixture openers owned by test',
                'confirmation': self.tool.offline.CONFIRMATION, 'offline_scope': self.tool.offline.SCOPE,
                'started_at': time.time()-1, 'expires_at': time.time()+60}

    def apply(self, mode, *, evidence=None, hook=lambda _: None):
        return self.tool.apply(self.cache, mode, self.group, [self.home], [self.state], self.backup,
                               self.evidence(mode) if evidence is None else evidence, probe=self.probe,
                               inspect=self.inspector, key_fn=lambda _: self.key, hook=hook)

    def assert_original(self):
        self.assertEqual((self.cache/self.group).read_bytes(), self.edits)
        self.assertEqual((self.cache/self.group[:-4]).read_bytes(), self.input)
        self.assertEqual((self.cache/'index.json').read_bytes(), self.original_index)
        self.assertFalse((self.cache/'nexus-index.json').exists())

    def test_migrate_preserves_bytes_and_uses_gc_manifest(self):
        result = self.apply('migrate')
        generation = self.cache/'generations'/result['generation']
        self.assertEqual((generation/'input.i64').read_bytes(), self.edits)
        self.assertEqual((generation/'input').read_bytes(), self.input)
        self.assertEqual(json.loads((generation/'generation.json').read_bytes()), {'version': 1, 'key': self.key})
        self.assertEqual(json.loads((self.cache/'nexus-index.json').read_bytes())[self.key],
                         str(generation.relative_to(self.cache)/'input.i64'))
        self.assertFalse((self.cache/self.group).exists())
        self.assertEqual((self.backup/'files'/self.group).read_bytes(), self.edits)
        import cache_store
        self.assertIsNone(cache_store.Store(self.cache, probe=lambda _: None).check(generation))
        self.assertEqual(cache_store.Store(self.cache).manifest(generation)['key'], self.key)

    def test_cleanup_and_restore_are_idempotent_and_byte_exact(self):
        self.apply('clean')
        self.assertFalse((self.cache/self.group).exists())
        self.apply('restore')
        self.assert_original()
        self.apply('restore')
        self.assert_original()

    def test_each_mid_operation_failure_restores_original_and_indices(self):
        for mode in ('migrate', 'clean'):
            for barrier in ('after_backup', 'after_generation', 'after_index', 'after_remove'):
                with self.subTest(mode=mode, barrier=barrier):
                    self.backup = self.backups/(mode+'-'+barrier)
                    def fail(stage):
                        if stage == barrier:
                            raise RuntimeError('deterministic failure at '+stage)
                    with self.assertRaisesRegex(RuntimeError, 'deterministic failure'):
                        self.apply(mode, hook=fail)
                    self.assert_original()
                    self.tool.load_manifest(self.backup, self.cache)

    def test_cache_startup_and_target_locks_reject_online_occupancy(self):
        from target_coordination import Target
        with (self.cache/'.cache.lock').open('w') as lock:
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.apply('clean')
        with (self.home/'.startup.lock').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.apply('clean')
        with Target(self.cache/self.group) as target, target.locked(nb=True):
            with self.assertRaises(BlockingIOError):
                self.apply('clean')
        self.assert_original()
        self.assertFalse(self.backup.exists())

    def test_running_daemon_and_public_owner_are_rejected(self):
        (self.home/'server.pid').write_text(str(os.getpid()))
        with self.assertRaisesRegex(RuntimeError, 'router PID'):
            self.apply('clean')
        (self.home/'server.pid').unlink()
        self.probe = lambda *_: {'packed': True, 'openers': 'public owner holds database'}
        with self.assertRaisesRegex(ValueError, 'packed/offline'):
            self.apply('clean')
        self.assert_original()
        self.assertFalse(self.backup.exists())

    def test_unpacked_unknown_symlink_and_existing_generation_are_untouched(self):
        for suffix in ('.id0', '.unknown'):
            path = self.cache/(self.group[:-4]+suffix)
            path.write_bytes(b'component')
            with self.assertRaisesRegex(ValueError, 'component'):
                self.apply('migrate')
            path.unlink()
        link = self.cache/(self.group[:-4]+'.id1')
        link.symlink_to(self.cache/self.group)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.apply('clean')
        link.unlink()
        (self.cache/'nexus-index.json').write_text(json.dumps({self.key: 'generations/healthy/input.i64'}))
        with self.assertRaisesRegex(ValueError, 'already has a generation'):
            self.apply('migrate')
        self.assertEqual(json.loads((self.cache/'nexus-index.json').read_bytes())[self.key], 'generations/healthy/input.i64')
        self.assertEqual((self.cache/self.group).read_bytes(), self.edits)

    def test_requires_continuous_bound_offline_window_not_one_negative_probe(self):
        evidence = self.evidence('clean')
        for key, bad in (('offline_scope', {}), ('boot_id', 'old-boot'), ('expires_at', 0),
                         ('plan_sha256', 'different'), ('state_roots', []), ('exclusion_method', '')):
            with self.subTest(field=key), self.assertRaisesRegex(RuntimeError, 'offline'):
                self.apply('clean', evidence=evidence | {key: bad})
        self.assert_original()
        self.assertFalse(self.backup.exists())

    def test_tampered_backup_or_restore_collision_never_overwrites(self):
        self.apply('clean')
        (self.cache/self.group).write_bytes(b'unknown new file')
        with self.assertRaisesRegex(ValueError, 'collision'):
            self.apply('restore')
        self.assertEqual((self.cache/self.group).read_bytes(), b'unknown new file')
        (self.cache/self.group).unlink()
        (self.backup/'files'/self.group).write_bytes(b'tampered backup')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.apply('restore')
        self.assertFalse((self.cache/self.group).exists())

    def test_backup_verification_failure_keeps_original_indices_and_files(self):
        self.inspector = lambda *_: (_ for _ in ()).throw(RuntimeError('IDA verification failure'))
        with self.assertRaisesRegex(RuntimeError, 'IDA verification failure'):
            self.apply('migrate')
        self.assert_original()

    def test_symlink_idb_never_creates_authority_outside_cache(self):
        outside = self.root/'outside'
        outside.mkdir(mode=0o700)
        target = outside/'database.i64'
        target.write_bytes(self.edits)
        (self.cache/self.group).unlink()
        (self.cache/self.group).symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.apply('clean')
        self.assertEqual([p.name for p in outside.iterdir()], ['database.i64'])
        self.assertEqual(target.read_bytes(), self.edits)

    def test_clean_preserves_healthy_generation_index_byte_for_byte(self):
        raw = ('{ "' + self.key + '" : "generations/healthy/input.i64" }').encode()
        (self.cache/'nexus-index.json').write_bytes(raw)
        self.apply('clean')
        self.assertEqual((self.cache/'nexus-index.json').read_bytes(), raw)
        self.apply('restore')
        self.assertEqual((self.cache/'nexus-index.json').read_bytes(), raw)

    def test_unsettled_or_corrupt_custody_never_authorizes_cleanup(self):
        from target_coordination import Target
        with Target(self.cache/self.group) as target, target.locked(nb=True):
            target.directory.durable('custody.json', {'schema': 'invalid'})
        with self.assertRaisesRegex(RuntimeError, 'journal'):
            self.apply('clean')
        self.assert_original()
        self.assertFalse(self.backup.exists())

    def test_legacy_startup_lock_mode_0644_is_accepted_without_chmod(self):
        lock = self.home/'.startup.lock'
        lock.write_bytes(b'')
        lock.chmod(0o644)
        self.apply('clean')
        self.assertEqual(lock.stat().st_mode & 0o777, 0o644)
        self.assertFalse((self.cache/self.group).exists())

    def test_interrupted_restore_does_not_publish_partial_original(self):
        self.apply('clean')
        copy = self.tool.files.copy_verified
        def interrupted(source, destination, expected):
            if destination.parent == self.cache:
                destination.write_bytes(b'partial restore copy')
                raise self.tool.files.MaintenanceInterrupted('injected restore interrupt')
            return copy(source, destination, expected)
        with patch.object(self.tool.files, 'copy_verified', interrupted):
            with self.assertRaisesRegex(self.tool.files.MaintenanceInterrupted, 'restore interrupt'):
                self.apply('restore')
        self.assertFalse((self.cache/self.group).exists())
        self.assertFalse((self.cache/self.group[:-4]).exists())
        self.apply('restore')
        self.assert_original()

    def test_preexisting_backup_is_never_overwritten(self):
        self.backup.mkdir(mode=0o700)
        (self.backup/'unknown').write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            self.apply('clean')
        self.assertEqual((self.backup/'unknown').read_bytes(), b'keep')
        self.assert_original()


if __name__ == '__main__':
    unittest.main()
