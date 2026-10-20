"""E23 driver refuses ambiguous owners and unsafe cleanup evidence."""

from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('gui_driver', REPO / 'scripts/verify_nexus_gui.py')
gui_driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gui_driver)


class GuiDriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/private/tmp', prefix='e23-test.')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / 'mini.i64'
        self.owner = {'record_id': 'gui-one', 'pid': 123, 'started_at': 1.0,
            'idb_path': str(self.database), 'backend': 'gui', 'managed': False}

    def test_exact_gui_owner_required(self):
        self.assertEqual(gui_driver.check_owner([self.owner], self.owner, 123, self.database), self.owner)
        for records in ([], [self.owner, self.owner]):
            with self.assertRaises(AssertionError):
                gui_driver.check_owner(records, self.owner, 123, self.database)
        for field, value in [('pid', 124), ('idb_path', '/elsewhere.i64'),
                ('backend', 'idalib'), ('managed', True), ('record_id', 'new-gui'), ('started_at', 2.0)]:
            with self.subTest(field=field), self.assertRaises(AssertionError):
                gui_driver.check_owner([self.owner | {field: value}], self.owner, 123, self.database)

    def test_release_scene_detects_write_and_same_bytes_replacement(self):
        self.database.write_bytes(b'packed private sample')
        before = gui_driver.scene(self.root)
        replacement = self.root / 'replacement'
        replacement.write_bytes(self.database.read_bytes())
        replacement.replace(self.database)
        self.assertNotEqual(gui_driver.scene(self.root), before)
        before = gui_driver.scene(self.root)
        self.database.write_bytes(b'changed')
        self.assertNotEqual(gui_driver.scene(self.root), before)

    def test_native_creation_requires_complete_birth_and_intent(self):
        from types import SimpleNamespace
        env = SimpleNamespace(root=self.root, ledger=self.root / 'processes.jsonl', entries=lambda: [])
        ledger = self.root / 'native-processes.jsonl'
        birth = {'kind': 'macos-libproc-v1', 'boot_id': '00000000-0000-0000-0000-000000000001', 'birth': [1, 2]}
        intent = {'kind': 'intent', 'intent': 'new', 'program': 'private-helper', 'argv': ['private-socket']}
        started = {'kind': 'started', 'intent': 'new', 'pid': 456, 'identity': birth}
        for rows in ([intent], [started], [intent, started | {'identity': None}],
                [intent, {'kind': 'capture_failed', 'intent': 'new'}]):
            ledger.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            with self.subTest(rows=rows), self.assertRaises(AssertionError):
                gui_driver.capture_native_processes(env)
        ledger.write_text(json.dumps(intent))
        with self.assertRaisesRegex(AssertionError, 'incomplete'):
            gui_driver.capture_native_processes(env)
        ledger.write_text(json.dumps(intent) + '\n' + json.dumps(started) + '\n')
        self.assertEqual(gui_driver.capture_native_processes(env), [started])
        imported = json.loads(env.ledger.read_text())
        self.assertEqual(imported['pid'], 456)
        self.assertEqual(imported['identity'], birth)
        self.assertEqual(imported['command'], ['private-helper', 'private-socket'])

    def test_only_missing_initial_gui_readiness_is_blocked(self):
        from types import SimpleNamespace
        child = SimpleNamespace(poll=lambda: None)
        with self.assertRaises(gui_driver.Blocked):
            gui_driver.wait_file(self.root / 'ready.json', child, seconds=0)
        with self.assertRaises(AssertionError):
            gui_driver.wait_file(self.root / 'after-release.json', child, seconds=0)

    def test_native_osstring_arguments_are_decoded_without_losing_worker_detection(self):
        intent = {'program': {'Unix': list(b'ida-nexus')}, 'argv': [{'Unix': list(b'worker')}]}
        self.assertEqual(gui_driver.native_command(intent), ['ida-nexus', 'worker'])
        for value in ({'Windows': [1]}, {'Unix': [256]}, {'Unix': [True]}):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                gui_driver.native_command({'program': value})

    def test_refused_existing_environment_never_signals_its_processes(self):
        from unittest.mock import MagicMock
        env = MagicMock()
        env.root = self.root
        env.ledger = self.root / 'processes.jsonl'
        env.ledger.touch()
        (self.root / 'e23-result.json').write_text('preserve prior evidence')
        env.exclusive.return_value = nullcontext()
        with patch.object(gui_driver, 'Environment', return_value=env), \
                patch.dict(gui_driver.os.environ, {'IDA_TEST': '1'}), \
                patch.object(gui_driver.sys, 'platform', 'darwin'), \
                patch.object(gui_driver.sys, 'argv', ['gui', '--root', str(self.root), '--binary', str(Path(__file__))]):
            self.assertEqual(gui_driver.main(), 2)
        env.cleanup.assert_not_called()
        self.assertEqual((self.root / 'e23-result.json').read_text(), 'preserve prior evidence')
        refused, = self.root.glob('e23-refused-*.json')
        self.assertEqual(json.loads(refused.read_text())['status'], 'BLOCKED')


if __name__ == '__main__':
    unittest.main()
