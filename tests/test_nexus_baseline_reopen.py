"""Bounded N0-only reopen never weakens metadata comparisons."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import compare_nexus_n6 as comparison


class BaselineReopen(unittest.TestCase):
    def exercise(self, responses, *, native=False, bad_seed=False, damage=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, seed, sample, binary = [root / x for x in ('mini', 'seed.i64', 'old.i64', 'baseline')]
            for path in (original, seed, sample, binary):
                path.write_bytes(b'private fixture')
            healthy = {'input_file_path': str(original), 'input_file_size': original.stat().st_size,
                       'md5': hashlib.md5(original.read_bytes()).hexdigest(), 'sha256': comparison.digest(original)}
            missing = dict(healthy, input_file_path='', input_file_size=0, md5='0' * 32, sha256='0' * 64)
            partial = dict(missing, sha256=healthy['sha256'])
            record = {'seed': str(seed), 'copies': [str(sample)], 'sha256': [comparison.digest(seed)],
                      'analyzed_seed_metadata': dict(healthy, input_file_size=0) if bad_seed else healthy}
            (root / 'unit-prebuilt-idb.json').write_text(json.dumps(record))
            clients = []

            class Client:
                def __init__(self, *args, **kwargs):
                    self.index, self.stops = len(clients), 0
                    self.open_result = {'result': {'open': True}}
                    clients.append(self)

                def call(self, method, params):
                    assert method == 'get_database_info'
                    if damage == 'read':
                        sample.write_bytes(b'damaged while opening')
                    return {'result': {'healthy': healthy, 'missing': missing, 'partial': partial}[responses[self.index]]}

                def rpc(self, method, params=None):
                    if method == 'get_database_info':
                        return self.call(method, params)
                    if method == 'close':
                        self.stop()
                    return self.open_result

                def wait(self):
                    pass

                def stop(self):
                    self.stops += 1
                    if damage == 'close':
                        sample.write_bytes(b'damaged at close')

            env = types.SimpleNamespace(root=root, variables=lambda: {})
            failure = None
            with patch.object(comparison, 'BASELINE_SHA', comparison.digest(binary)), \
                    patch.object(comparison, 'Candidate', Client), patch.object(comparison, 'Process', Client), \
                    patch.dict(os.environ, {'TMPDIR': str(root)}):
                try:
                    result = comparison.baseline_prebuilt_open(env, binary, sample, 'test', native=native)
                except AssertionError as exc:
                    failure = str(exc)
                else:
                    self.assertIs(result, clients[-1])
            evidence = root / 'baseline-reopens.jsonl'
            rows = [json.loads(x) for x in evidence.read_text().splitlines()] if evidence.exists() else []
            return clients, rows, failure

    def test_healthy_opens_once_in_both_native_transports(self):
        for native in (False, True):
            clients, rows, failure = self.exercise(['healthy'], native=native)
            self.assertIsNone(failure)
            self.assertEqual(len(clients), 1)
            self.assertFalse(rows[0]['r9_signature'])

    def test_exact_signature_gets_at_most_two_extra_opens_with_raw_evidence(self):
        for native in (False, True):
            clients, rows, failure = self.exercise(['missing', 'missing', 'healthy'], native=native)
            self.assertIsNone(failure)
            self.assertEqual([c.stops for c in clients], [1, 1, 0])
            self.assertEqual([r['attempt'] for r in rows], [0, 1, 2])
            self.assertEqual(sum(r.get('reopen_scheduled', False) for r in rows), 2)
            self.assertTrue(all(r['metadata_response'] and r['time_ns'] and r['uptime'] for r in rows))

    def test_persistent_failure_is_not_accepted(self):
        clients, rows, failure = self.exercise(['missing'] * 3)
        self.assertIn('two extra opens', failure)
        self.assertEqual(len(clients), 3)
        self.assertEqual([c.stops for c in clients], [1, 1, 1])

    def test_partial_signature_does_not_retry_or_rewrite_result(self):
        clients, rows, failure = self.exercise(['partial'])
        self.assertEqual(len(clients), 1)
        self.assertFalse(rows[0]['r9_signature'])
        self.assertEqual(rows[0]['metadata_response']['result']['input_file_size'], 0)

    def test_bad_seed_never_authorizes_retry(self):
        clients, rows, failure = self.exercise(['missing'], bad_seed=True)
        self.assertIsNotNone(failure)
        self.assertFalse(clients)

    def test_changed_disk_never_authorizes_retry(self):
        for stage in ('read', 'close'):
            clients, rows, failure = self.exercise(['missing'], damage=stage)
            self.assertIn('disk', failure)
            self.assertEqual(len(clients), 1)
            self.assertEqual(clients[0].stops, 1)
            self.assertFalse(rows[0].get('reopen_scheduled', False))


if __name__ == '__main__':
    unittest.main()
