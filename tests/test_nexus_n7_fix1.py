"""N7a review regressions; only private fixtures may hold Nexus lifetime locks."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'nexus_bridge'))
from cache_store import Store, public_probe


class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.now = 100.0

    def tearDown(self):
        self.temp.cleanup()

    def group(self, name, key='key'):
        group = self.root / 'cache' / 'generations' / name
        group.mkdir(parents=True)
        (group / 'input.i64').write_bytes(b'x' * 20000)
        (group / 'generation.json').write_text(json.dumps({'version': 1, 'key': key}))
        return group

    def store(self):
        return Store(self.root / 'cache', grace=60, epoch='one',
                     probe=lambda _: None, clock=lambda: self.now)

    def test_f2_select_only_bytes_needed_across_keys_and_generations(self):
        for name, key, age in [('old', 'a', 1), ('middle', 'a', 2), ('new', 'b', 3)]:
            os.utime(self.group(name, key), (age, age))
        store = self.store()
        store.collect(45000)
        self.assertEqual([p.name for p in store.quarantine.iterdir()], ['old'])
        self.now += 61
        self.assertEqual(store.collect(45000)['evicted_groups'], 1)
        self.assertEqual(sorted(p.name for p in store.generations.iterdir()), ['middle', 'new'])

    def test_f2_final_deletion_obeys_changed_budget(self):
        self.group('old', 'a'); self.group('new', 'b')
        store = self.store()
        store.collect(0)
        self.now += 61
        self.assertEqual(store.collect(30000)['evicted_groups'], 1)
        self.assertEqual(len(list(store.quarantine.iterdir())), 1)

    def test_f7_bad_manifest_is_local_to_candidate(self):
        for n, value in enumerate([[], None, 7, 'text', {'version': True, 'key': 'k'}, {'version': 1, 'key': []}]):
            group = self.group('bad' + str(n))
            (group / 'generation.json').write_text(json.dumps(value))
        good = self.group('good')
        store = self.store()
        result = store.collect(0)
        self.assertEqual(len(result['rejected']), 6)
        self.now += 61
        self.assertEqual(store.collect(0)['evicted_groups'], 1)
        self.assertFalse(good.exists())

    def test_f7_bad_journal_is_local_to_candidate(self):
        bad_values = [[], None, 7, 'text', {'version': 1, 'epoch': [], 'since': 0, 'checks': 1},
                      {'version': 1, 'epoch': 'one', 'since': True, 'checks': True}]
        for n in range(len(bad_values)):
            self.group('bad' + str(n))
        self.group('good')
        store = self.store(); store.collect(0)
        for n, value in enumerate(bad_values):
            if isinstance(value, dict):
                value['name'] = 'bad' + str(n)
            (store.quarantine / ('bad' + str(n)) / 'quarantine.json').write_text(json.dumps(value))
        self.now += 61
        result = store.collect(0)
        self.assertEqual(len(result['rejected']), len(bad_values))
        self.assertEqual(result['evicted_groups'], 1)

    def registry_case(self, *, malformed=False, held=True):
        import ida_nexus._registry as registry
        group = self.group('held')
        directory = self.root / 'state' / 'instances'; directory.mkdir(parents=True, mode=0o700)
        pid = os.getpid() if held else 999999991
        record_id = str(pid) + '-abcdef'
        path = group / 'input.i64'
        identity = str(path).casefold() if sys.platform == 'darwin' else str(path)
        record = directory / (record_id + '.json')
        payload = {'record_id': record_id, 'backend': 'idalib', 'pid': pid, 'port': 1,
                   'token': secrets.token_hex(16), 'version': 9, 'idb_path': str(path),
                   'idb_key': hashlib.sha256(identity.encode()).hexdigest()[:16],
                   'exe_path': '', 'managed': True, 'started_at': 1.0}
        record.write_text('{' if malformed else json.dumps(payload)); record.chmod(0o600)
        with (directory / (record_id + '.lock')).open('w') as guard:
            if held:
                fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(registry, 'REGISTRY_DIR', directory), patch.dict(os.environ, {'IDA_NEXUS_STATE_DIR': str(directory.parent)}):
                reason = public_probe(path)
                store = Store(self.root / 'cache', grace=60, epoch='one', clock=lambda: self.now)
                first = store.collect(0); self.now += 61; second = store.collect(0)
        return group, record, reason, first, second

    def test_f1_valid_blocked_owner_retained(self):
        group, record, reason, first, second = self.registry_case()
        self.assertTrue(reason); self.assertTrue(record.exists()); self.assertTrue(group.exists())
        self.assertTrue(first['rejected']); self.assertEqual(second['evicted_groups'], 0)

    def test_f1_malformed_held_registration_blocks_entire_root(self):
        other = self.group('other', 'other')
        group, record, reason, first, second = self.registry_case(malformed=True)
        self.assertTrue(reason); self.assertTrue(record.exists()); self.assertTrue(group.exists())
        self.assertTrue(other.exists()); self.assertTrue(first['rejected'])
        self.assertEqual(second['evicted_groups'], 0)

    def test_f1_dead_released_registration_can_be_reaped_publicly(self):
        group, record, reason, first, second = self.registry_case(held=False)
        self.assertIsNone(reason); self.assertFalse(record.exists())
        self.assertFalse(group.exists()); self.assertEqual(second['evicted_groups'], 1)

    def test_f1_component_residue_retained(self):
        import ida_nexus._registry as registry
        directory = self.root / 'state' / 'instances'; directory.mkdir(parents=True, mode=0o700)
        group = self.group('components')
        (group / 'input.id0').write_bytes(b'component')
        with patch.object(registry, 'REGISTRY_DIR', directory), patch.dict(os.environ, {'IDA_NEXUS_STATE_DIR': str(directory.parent)}):
            self.assertIsNotNone(public_probe(group / 'input.i64'))
            self.assertTrue(Store(self.root / 'cache').collect(0)['rejected'])
        self.assertTrue(group.exists())


if __name__ == '__main__':
    unittest.main()
