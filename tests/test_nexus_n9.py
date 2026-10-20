"""N9 regressions use private executables and never require GNU timeout."""
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / 'nexus_bridge'), str(REPO / 'nexus_bridge/custody')]


class NoTimeoutTests(unittest.TestCase):
    def test_content_key_without_timeout_in_path(self):
        import legacy_cache
        with tempfile.TemporaryDirectory() as temporary:
            tool = Path(temporary) / 'tool'
            tool.write_text("#!/bin/sh\nprintf '%s\\n' abcdef123456\n")
            tool.chmod(0o700)
            with patch.dict(os.environ, {'PATH': '', 'IDA_CLI_LEGACY_TOOL': str(tool)}):
                self.assertEqual(legacy_cache.content_key(Path(temporary) / 'sample'), 'abcdef123456')

    def test_native_scope_without_timeout_in_path(self):
        import origin
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {'PATH': ''}):
            scope = origin.native_scope(temporary, Path(temporary).stat().st_dev)
            self.assertIn('machine_sha256', scope)
            self.assertIn('volume_sha256', scope)
            self.assertNotIn('FileNotFoundError', scope.get('unsupported_reason', ''))

    def test_timeouts_keep_maintenance_error_and_retained_copy_contract(self):
        import legacy_cache
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'files').mkdir()
            (root / 'files/input.i64').write_bytes(b'private user edits')
            with patch('legacy_cache.offline.run_child', side_effect=subprocess.TimeoutExpired(['fixture'], 1)):
                with patch.dict(os.environ, {'IDA_CLI_LEGACY_TOOL': '/fixture'}):
                    with self.assertRaisesRegex(RuntimeError, 'content-key verification failed: budget expired'):
                        legacy_cache.content_key(root / 'input')
                with self.assertRaisesRegex(RuntimeError, 'inspection timed out; copy retained'):
                    legacy_cache.inspect_copy(root, 'input.i64')
            copies = list(root.glob('probe-*/probe.i64'))
            self.assertEqual(len(copies), 1)
            self.assertEqual(copies[0].read_bytes(), b'private user edits')

    def test_helper_timeout_kills_and_reaps_owned_group(self):
        import legacy_cache_offline
        with tempfile.TemporaryDirectory() as temporary:
            pidfile = Path(temporary) / 'pid'
            argv = ['/bin/sh', '-c', 'echo $$ > "$1"; exec /bin/sleep 60', 'fixture', str(pidfile)]
            with patch.dict(os.environ, {'PATH': ''}):
                with self.assertRaises(subprocess.TimeoutExpired):
                    legacy_cache_offline.run_child(argv, timeout=0.1)
            pid = int(pidfile.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

    def test_occupancy_without_timeout_in_path_and_explicit_timeout_error(self):
        import recovery_maintenance
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'bootstrap.py').write_text("import json; print(json.dumps({'reason': None}))\n")
            with patch.object(recovery_maintenance, '__file__', str(root / 'recovery_maintenance.py')):
                with patch.dict(os.environ, {'PATH': ''}):
                    self.assertIsNone(recovery_maintenance.occupancy([{}], root / 'sample.i64'))
                (root / 'bootstrap.py').write_text('import time; time.sleep(60)\n')
                with self.assertRaisesRegex(RuntimeError, 'occupancy timed out'):
                    recovery_maintenance.occupancy([{}], root / 'sample.i64')


if __name__ == '__main__':
    unittest.main()
