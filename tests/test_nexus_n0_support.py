"""N0 isolation and DNS regression tests, independent of an IDA license."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests/support"))
sys.path.insert(0, str(REPO / "scripts"))
from nexus_env import Environment, identity, same_process  # noqa: E402
from prepare_nexus_env import accepted_eula_entries  # noqa: E402


class IsolationTests(unittest.TestCase):
    def test_environment_lock_rejects_concurrent_verification_or_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "environment.json").write_text(json.dumps({"root": str(root), "ida_dir": "/test/ida"}))
            first, second = Environment(root), Environment(root)
            with first.exclusive():
                with self.assertRaisesRegex(RuntimeError, "another verifier"):
                    with second.exclusive():
                        self.fail("second verifier acquired the same root")
            with second.exclusive():
                with self.assertRaisesRegex(RuntimeError, "another verifier"):
                    with first.exclusive():
                        self.fail("first verifier reacquired a root still owned by the second")

    def test_exec_argv_change_preserves_birth_identity_but_pid_reuse_does_not(self):
        birth = "Thu Oct 15 01:17:40 2026"
        self.assertTrue(same_process(birth + " (python3.14)", birth + " python worker"))
        self.assertFalse(same_process("Thu Oct 15 01:17:41 2026 python worker", birth + " python worker"))
        self.assertFalse(same_process("", birth + " python worker"))

    def test_eula_extraction_does_not_copy_license_metadata(self):
        accepted = b"EULA 90\x00\x04\x00\x00\x00\x04\x01\x00\x00\x00"
        data = b"iDa7\x01Licenses\x00private license metadata\x00" + accepted + b"SearchBin\x00other state"
        self.assertEqual(accepted_eula_entries(data), ["EULA 90"])

    def test_missing_or_unaccepted_eula_is_an_error(self):
        for data in (b"unknown", b"iDa7\x01", b"iDa7\x01EULA 90\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                accepted_eula_entries(data)

    def test_cleanup_preserves_process_with_changed_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "environment.json").write_text(json.dumps({"root": str(root), "ida_dir": "/test/ida"}))
            env = Environment(root)
            env.ledger.write_text(json.dumps({"pid": 123, "identity": "old identity", "command": ["test"]}) + "\n")
            with patch("nexus_env.identity", return_value="new identity"), patch("nexus_env.os.kill") as kill:
                self.assertEqual(env.cleanup(), [])
                kill.assert_not_called()

    def test_owned_child_cleanup_and_no_unrecorded_signals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "environment.json").write_text(json.dumps({"root": str(root), "ida_dir": "/test/ida"}))
            env = Environment(root)
            command = [sys.executable, "-c", "import time; time.sleep(20)"]
            child = subprocess.Popen(command)
            try:
                env.record(child, command)
                self.assertTrue(identity(child.pid))
                self.assertEqual(env.cleanup(), [child.pid])
                child.wait(timeout=5)
                env.assert_clean()
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)

    def test_environment_excludes_daemon_and_python_injection_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "environment.json").write_text(json.dumps({"root": str(root), "ida_dir": "/test/ida"}))
            with patch.dict(os.environ, {"PYTHONPATH": "/unsafe", "IDA_NEXUS_STATE_DIR": "/user/state", "DAEMON_PASSWORD": "dummy"}):
                values = Environment(root).variables()
            self.assertNotIn("PYTHONPATH", values)
            self.assertNotIn("DAEMON_PASSWORD", values)
            self.assertEqual(values["IDA_NEXUS_STATE_DIR"], str(root / "state"))


class BindRegressionTests(unittest.TestCase):
    def test_patched_nexus_binds_without_reverse_dns(self):
        from ida_nexus._http import LocalHTTPServer
        with patch("socket.gethostbyaddr", side_effect=AssertionError("reverse DNS called")) as lookup:
            server = LocalHTTPServer("n0-test-only", lambda *_: None)
            try:
                self.assertEqual(server.server_name, "127.0.0.1")
                self.assertGreater(server.port, 0)
                self.assertEqual(server.server_port, server.port)
                self.assertEqual(server.allowed_hosts, frozenset({f"127.0.0.1:{server.port}", f"localhost:{server.port}"}))
                lookup.assert_not_called()
            finally:
                server.server_close()


if __name__ == "__main__":
    unittest.main()
