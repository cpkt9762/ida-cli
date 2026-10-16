"""Review residuals: public state resolution and candidate numeric isolation."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('N7_F2_CACHE_SOURCE', Path(__file__).resolve().parents[1]/'nexus_bridge/cache_store.py'))
SPEC = importlib.util.spec_from_file_location('n7_fix2_cache', SOURCE)
cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cache)


def group(root, name):
    path = root/'generations'/name
    path.mkdir(parents=True)
    (path/'input.i64').write_bytes(b'x'*20000)
    (path/'generation.json').write_text(json.dumps({'version': 1, 'key': name}))
    return path


class Residuals(unittest.TestCase):
    def test_r1_public_state_resolution_vetoes_absolute_and_tilde(self):
        from ida_nexus import get_state_dir
        with tempfile.TemporaryDirectory(prefix='n7f2-') as directory:
            root = Path(directory)
            state = root/'state'
            registry = state/'instances'
            registry.mkdir(parents=True, mode=0o700)
            record = registry/'999999991-abcdef.json'
            record.write_text('{')
            record.chmod(0o600)
            with (registry/'999999991-abcdef.lock').open('w') as guard:
                fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
                for index, spelling in enumerate((str(state), '~/'+os.path.relpath(state, Path.home()))):
                    with self.subTest(spelling=index), patch.dict(os.environ, {'IDA_NEXUS_STATE_DIR': spelling}):
                        self.assertEqual(get_state_dir().resolve(), state.resolve())
                        target = group(root/str(index), 'g')/'input.i64'
                        self.assertIsNotNone(cache.public_probe(target))
                        now = [100.0]
                        store = cache.Store(root/str(index), epoch='router', clock=lambda: now[0])
                        store.collect(0)
                        now[0] = 161
                        result = store.collect(0)
                        self.assertEqual(result['evicted_groups'], 0)
                        self.assertTrue(target.is_file())
                        self.assertEqual(record.read_text(), '{')

    def test_r4_bad_numeric_journal_does_not_block_healthy_candidate(self):
        cases = [('since', 10**400), ('since', -1), ('since', float('nan')),
                 ('since', float('inf')), ('since', float('-inf')),
                 ('checks', 10**400), ('checks', -1), ('checks', float('inf')),
                 ('version', 10**400), ('version', -1), ('version', float('nan'))]
        for field, value in cases:
            with self.subTest(field=field, value_type=type(value).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                group(root, 'a-bad')
                group(root, 'z-good')
                now = [100.0]
                store = cache.Store(root, epoch='router', clock=lambda: now[0], probe=lambda _: None)
                store.collect(0)
                journal = root/'quarantine/a-bad/quarantine.json'
                data = json.loads(journal.read_text())
                data[field] = value
                journal.write_text(json.dumps(data))
                now[0] = 161
                result = store.collect(0)
                self.assertEqual(result['evicted_groups'], 1)
                self.assertTrue((journal.parent/'input.i64').exists())
                self.assertFalse((root/'quarantine/z-good').exists())
                self.assertTrue(any('a-bad' in row['path'] for row in result['rejected']))

    def test_r4_bad_numeric_manifest_is_candidate_local(self):
        for version in (10**400, -1, float('nan'), float('inf')):
            with self.subTest(version_type=type(version).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bad = group(root, 'a-bad')
                group(root, 'z-good')
                (bad/'generation.json').write_text(json.dumps({'version': version, 'key': 'a-bad'}))
                now = [100.0]
                store = cache.Store(root, epoch='router', clock=lambda: now[0], probe=lambda _: None)
                store.collect(0)
                now[0] = 161
                result = store.collect(0)
                self.assertEqual(result['evicted_groups'], 1)
                self.assertTrue((bad/'input.i64').exists())
                self.assertFalse((root/'quarantine/z-good').exists())


if __name__ == '__main__':
    unittest.main()
