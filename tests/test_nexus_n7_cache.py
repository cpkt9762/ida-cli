"""Deterministic cache maintenance safety, with public probes injected only here."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import types
import sys

SOURCE = Path(__file__).resolve().parents[1] / 'nexus_bridge/cache_store.py'
spec = importlib.util.spec_from_file_location('cache_store', SOURCE)
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        state = self.root/'state'
        state.mkdir()
        environment = patch.dict(os.environ, {'IDA_NEXUS_STATE_DIR': str(state)})
        environment.start()
        self.addCleanup(environment.stop)
        self.group = self.root/'generations/g1'
        self.group.mkdir(parents=True)
        (self.group/'input.i64').write_bytes(b'user edits')
        (self.group/'generation.json').write_text(json.dumps({'version':1, 'key':'abc'}))
        self.busy = set()
        self.clock = 100.0
        self.store = cache.Store(self.root, grace=1, epoch='router-one',
            probe=lambda p: 'busy' if str(p) in self.busy else None,
            clock=lambda: self.clock)

    def tearDown(self):
        self.temp.cleanup()

    def test_occupied_generation_is_never_moved(self):
        self.busy.add(str(self.group/'input.i64'))
        result = self.store.collect(0)
        self.assertTrue(result['rejected'])
        self.assertEqual((self.group/'input.i64').read_bytes(), b'user edits')

    def test_all_three_opener_barriers_restore_or_reject(self):
        for phase in ('before_rename', 'after_rename', 'before_delete'):
            with self.subTest(phase=phase):
                self.busy.clear()
                self.store.hook = lambda at, original, isolated: self.busy.add(
                    str((isolated if phase == 'after_rename' else original)/'input.i64')) if at == phase else None
                self.store.collect(0)
                if phase == 'before_delete':
                    self.clock += 2
                    self.store.collect(0)
                self.assertTrue(self.group.exists(), phase)
                self.assertEqual((self.group/'input.i64').read_bytes(), b'user edits')

    def test_restart_resets_grace_and_requires_new_observations(self):
        self.store.collect(0)
        self.clock += 5
        self.store.epoch = 'router-two'
        self.store.collect(0)
        self.assertTrue((self.root/'quarantine/g1/input.i64').exists())
        self.clock += 2
        self.store.collect(0)
        self.assertFalse((self.root/'quarantine/g1').exists())

    def test_only_after_grace_and_repeated_checks_delete(self):
        self.store.collect(0)
        self.assertFalse(self.group.exists())
        self.store.collect(0)
        self.assertTrue((self.root/'quarantine/g1').exists())
        self.clock += 2
        self.assertEqual(self.store.collect(0)['evicted_groups'], 1)

    def test_recovery_refuses_overwrite_and_malformed_journal(self):
        self.store.collect(0)
        self.group.mkdir()
        (self.group/'input.i64').write_bytes(b'new owner')
        self.busy.add(str(self.group/'input.i64'))
        result = self.store.collect(0)
        self.assertTrue(result['rejected'])
        self.assertEqual((self.group/'input.i64').read_bytes(), b'new owner')
        self.assertEqual((self.root/'quarantine/g1/input.i64').read_bytes(), b'user edits')
        (self.root/'quarantine/g1/quarantine.json').write_text('{')
        self.busy.clear()
        self.clock += 2
        self.assertTrue(self.store.collect(0)['rejected'])
        self.assertTrue((self.root/'quarantine/g1/input.i64').exists())

    def test_public_probe_rejects_unknown_crashed_unpacked_busy_and_errors(self):
        for state in ('in_use', 'unpacked', 'crashed', 'unknown'):
            api = types.SimpleNamespace(find_database_owner=lambda *a, **k: None,
                discover_databases=lambda **k: [],
                get_state_dir=lambda: Path(os.environ['IDA_NEXUS_STATE_DIR']).expanduser(),
                probe_database_state=lambda p: {'state':state, 'unpacked_files':[], 'error':None})
            with patch.dict(sys.modules, {'ida_nexus':api}):
                self.assertTrue(cache.public_probe(self.group/'input.i64'), state)
        api.probe_database_state = lambda p: (_ for _ in ()).throw(OSError('injected discovery failure'))
        with patch.dict(sys.modules, {'ida_nexus':api}):
            self.assertIn('proof failed', cache.public_probe(self.group/'input.i64'))

    def test_symlink_quarantine_never_mutates_external_target(self):
        self.store.quarantine.mkdir()
        external = self.root/'external'
        external.mkdir()
        (external/'quarantine.json').write_text('preserve')
        (self.store.quarantine/'bad').symlink_to(external, target_is_directory=True)
        self.assertTrue(self.store.collect(0)['rejected'])
        self.assertEqual((external/'quarantine.json').read_text(), 'preserve')

    def test_explicit_remove_never_retires_another_key(self):
        self.store.collect(0)
        self.clock += 2
        self.assertEqual(self.store.collect(0, key='different')['evicted_groups'], 0)
        self.assertTrue((self.root/'quarantine/g1/input.i64').exists())
        self.assertEqual(self.store.collect(0, key='abc')['evicted_groups'], 1)


if __name__ == '__main__':
    unittest.main()
