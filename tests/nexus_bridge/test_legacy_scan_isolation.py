"""Production open gates isolate home inventory from target obligations."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge/custody'), str(REPO/'nexus_bridge')]
from acquisition import Custodian
from open_recovery import OpenGate
from owner_identity import state_identity


class LegacyScan(unittest.TestCase):
    def test_production_gates_isolate_unattributed_entries_and_keep_matching_failure(self):
        root = Path(tempfile.mkdtemp(prefix='legacy-scan-', dir=os.environ['R3A_CASE_ROOT'])).resolve()
        home = Path(os.environ['IDA_CLI_HOME'])/'idb'
        recovery = home/'recovery'
        recovery.mkdir(mode=0o700, parents=True)
        (recovery/('1'*32)).mkdir(mode=0o700)
        (recovery/'.DS_Store').write_bytes(b'foreign retained bytes')
        for name, raw in (('2'*32, b'{broken'), ('3'*32, json.dumps({'target': str(root/'other.i64')}).encode())):
            entry = recovery/name
            entry.mkdir(mode=0o700)
            (entry/'recovery.json').write_bytes(raw)
            (entry/'recovery.json').chmod(0o600)
        before = {str(p): (p.stat().st_ino, p.read_bytes()) for p in recovery.rglob('*') if p.is_file()}
        path = root/'input.i64'
        path.write_bytes(b'private unrelated target')
        path.chmod(0o600)
        statuses = []
        with OpenGate(home, path, time.monotonic()+3) as gate:
            statuses.append(gate.target.legacy_diagnostics)
        custody = Custodian.__new__(Custodian)
        custody.deadline = time.monotonic()+3
        custody.helper = {'state_root': state_identity()}
        custody.acquisition = None
        with custody.gate(path) as target:
            statuses.append(target.legacy_diagnostics)
        self.assertEqual({str(p): (p.stat().st_ino, p.read_bytes()) for p in recovery.rglob('*') if p.is_file()}, before)
        for status in statuses:
            self.assertEqual({item['kind'] for item in status},
                             {'unrecorded_v1_directory', 'non_v1_entry', 'unattributed_record', 'other_target'})
        # A readable target attribution is sufficient to retain its own error,
        # even when the rest of that target's record is corrupt.
        matching = recovery/('4'*32)
        matching.mkdir(mode=0o700)
        (matching/'recovery.json').write_text(json.dumps({'target': str(path), 'status': 'failed-owner-held'}))
        (matching/'recovery.json').chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'RecoveryBlocked'):
            with OpenGate(home, path, time.monotonic()+3):
                self.fail('matching target failure must block')
        with self.assertRaisesRegex(RuntimeError, 'RecoveryBlocked'):
            with custody.gate(path):
                self.fail('custody must retain matching target obligation')
        (root/'gate-status.json').write_text(json.dumps(statuses, indent=2))


if __name__ == '__main__':
    unittest.main(verbosity=2)
