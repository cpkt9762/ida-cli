"""N0 isolation and DNS regression tests, independent of an IDA license."""

import json
from contextlib import contextmanager, redirect_stdout
import ctypes
import errno
import io
import os
from pathlib import Path
import subprocess
import selectors
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests/support"))
sys.path.insert(0, str(REPO / "scripts"))
from nexus_env import Environment, identity, same_process  # noqa: E402
from prepare_nexus_env import accepted_eula_entries  # noqa: E402
import process_identity  # noqa: E402
from verify_nexus_n0 import owned_nexus_spawn, startup_timeout  # noqa: E402

BOOT_ID = "00000000-0000-0000-0000-000000000001"
BIRTH = {"kind": "macos-libproc-v1", "boot_id": BOOT_ID, "birth": [1792000000, 100100]}
REAL_POPEN = subprocess.Popen


@contextmanager
def environment():
    with tempfile.TemporaryDirectory(dir=os.environ.get("N0_TEST_EVIDENCE_DIR")) as directory:
        root = Path(directory).resolve()
        (root / "environment.json").write_text(json.dumps({"root": str(root), "ida_dir": "/test/ida"}))
        (root / "fixtures").mkdir()
        (root / "fixtures/mini").write_bytes(b"mock-only fixture")
        yield Environment(root)


def ledger(env, pids):
    env.ledger.write_text("".join(json.dumps({"schema": 2, "pid": pid,
                                           "identity": BIRTH, "command": ["mock"]}) + "\n"
                                  for pid in pids))


class ChildTests(unittest.TestCase):
    def setUp(self):
        self.owned = []

    def launch(self, command=None, **options):
        options.setdefault("start_new_session", True)
        child = REAL_POPEN(command or [sys.executable, "-c", "import time; time.sleep(20)"], **options)
        self.owned.append((child, process_identity.identity(child.pid)))
        return child

    def tearDown(self):
        for child, birth in self.owned:
            leaked = child.poll() is None
            try:
                if leaked:
                    child.terminate()
                    child.wait(timeout=3)
            finally:
                evidence = os.environ.get("N0_TEST_EVIDENCE_DIR")
                if evidence:
                    with (Path(evidence) / "test-processes.jsonl").open("a") as out:
                        out.write(json.dumps({"test": self.id(), "pid": child.pid, "identity": birth,
                                              "returncode": child.returncode, "leaked": leaked}) + "\n")
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream:
                        stream.close()
            self.assertFalse(leaked, f"test did not clean its own child {child.pid}")


class IsolationTests(ChildTests):
    def test_environment_lock_rejects_concurrent_verification_or_cleanup(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("N0_TEST_EVIDENCE_DIR")) as directory:
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
        self.assertTrue(same_process(dict(BIRTH), BIRTH))
        self.assertFalse(same_process({**BIRTH, "birth": [1792000000, 900900]}, BIRTH))
        self.assertFalse(same_process({**BIRTH, "birth": [1792000001, 100100]}, BIRTH))
        self.assertFalse(same_process(None, BIRTH))
        self.assertFalse(same_process("Thu Oct 15 01:17:40 2026 python worker", BIRTH))

    def test_eula_extraction_does_not_copy_license_metadata(self):
        accepted = b"EULA 90\x00\x04\x00\x00\x00\x04\x01\x00\x00\x00"
        data = b"iDa7\x01Licenses\x00private license metadata\x00" + accepted + b"SearchBin\x00other state"
        self.assertEqual(accepted_eula_entries(data), ["EULA 90"])

    def test_missing_or_unaccepted_eula_is_an_error(self):
        for data in (b"unknown", b"iDa7\x01", b"iDa7\x01EULA 90\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                accepted_eula_entries(data)

    def test_cleanup_preserves_process_with_changed_identity(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("N0_TEST_EVIDENCE_DIR")) as directory:
            root = Path(directory).resolve()
            (root / "environment.json").write_text(json.dumps({"root": str(root), "ida_dir": "/test/ida"}))
            env = Environment(root)
            ledger(env, [123])
            with patch("nexus_env.identity", return_value={**BIRTH, "birth": [1792000000, 900900]}), patch("nexus_env.os.kill") as kill:
                self.assertEqual(env.cleanup(), [])
                kill.assert_not_called()

    def test_owned_child_cleanup_and_no_unrecorded_signals(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("N0_TEST_EVIDENCE_DIR")) as directory:
            root = Path(directory).resolve()
            (root / "environment.json").write_text(json.dumps({"root": str(root), "ida_dir": "/test/ida"}))
            env = Environment(root)
            command = [sys.executable, "-c", "import time; time.sleep(20)"]
            child = env.spawn(lambda: self.launch(command), command)
            try:
                self.assertTrue(identity(child.pid))
                self.assertEqual(env.cleanup(), [child.pid])
                child.wait(timeout=5)
                self.assertIsNotNone(child.returncode)
                env.assert_clean()
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)

    def test_environment_excludes_daemon_and_python_injection_settings(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("N0_TEST_EVIDENCE_DIR")) as directory:
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


class RegistrationTests(ChildTests):
    def test_direct_record_failure_also_reaps_the_already_held_child(self):
        with environment() as env:
            child = self.launch()
            with patch("nexus_env.identity", side_effect=RuntimeError("query failed")):
                with self.assertRaisesRegex(RuntimeError, "query failed"):
                    env.record(child, child.args)
            self.assertIsNotNone(child.returncode)
            env.assert_clean()

    def test_identity_failure_cleans_held_detached_child_and_waits(self):
        with environment() as env, patch("nexus_env.identity", side_effect=RuntimeError("query failed")):
            with self.assertRaisesRegex(RuntimeError, "query failed"):
                env.spawn(self.launch, ["detached-test"])
            self.assertIsNotNone(self.owned[0][0].returncode)
            self.assertEqual(env.cleanup(), [])
            env.assert_clean()
            Environment(env.root).assert_clean()

    def test_ledger_write_and_fsync_failure_clean_child_but_corruption_is_not_clean(self):
        for failure in ("write", "fsync"):
            with self.subTest(failure=failure), environment() as env:
                original = env._record
                original_open = Path.open

                def fail(process, command):
                    if failure == "write":
                        def open_file(path, *args, **kwargs):
                            if path == env.ledger:
                                raise OSError("ledger write failed")
                            return original_open(path, *args, **kwargs)

                        with patch.object(Path, "open", open_file):
                            original(process, command)
                        return
                    with patch("nexus_env.os.fsync", side_effect=OSError("ledger fsync failed")):
                        original(process, command)

                with patch.object(env, "_record", side_effect=fail):
                    with self.assertRaisesRegex(OSError, "ledger .* failed"):
                        env.spawn(self.launch, ["detached-test"])
                self.assertIsNotNone(self.owned[-1][0].returncode)
                env.assert_clean()
                Environment(env.root).assert_clean()

    def test_partial_ledger_write_still_waits_and_independent_cleanup_fails(self):
        with environment() as env:
            def fail(*_):
                env.ledger.write_text('{"schema": 2, "pid":')
                raise OSError("partial ledger write")

            with patch.object(env, "_record", side_effect=fail), self.assertRaisesRegex(OSError, "partial ledger"):
                env.spawn(self.launch, ["detached-test"])
            self.assertIsNotNone(self.owned[-1][0].returncode)
            with self.assertRaisesRegex(RuntimeError, "ledger line"):
                Environment(env.root).cleanup()
            with self.assertRaisesRegex(AssertionError, "ledger line"):
                env.assert_clean()

    def test_sigterm_at_creation_and_registration_boundaries_is_deferred_and_cleaned(self):
        for boundary in ("created", "identity", "durable"):
            with self.subTest(boundary=boundary), environment() as env:
                old_handler = signal.getsignal(signal.SIGTERM)

                def inject():
                    signal.raise_signal(signal.SIGTERM)
                    independent = Environment(env.root)
                    with self.assertRaisesRegex(RuntimeError, "unfinished creation intent"):
                        independent.cleanup()
                    with self.assertRaisesRegex(AssertionError, "unfinished creation intent"):
                        independent.assert_clean()
                    result = subprocess.run(["timeout", "5s", sys.executable, "-B",
                                             str(REPO / "scripts/verify_nexus_n0.py"),
                                             "--root", str(env.root), "cleanup"],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("unfinished creation intent", result.stderr)
                    self.assertNotIn('"CLEAN"', result.stdout)

                def create():
                    child = self.launch()
                    if boundary == "created":
                        inject()
                    return child

                original = env._record

                def register(process, command):
                    if boundary == "identity":
                        inject()
                    original(process, command)
                    if boundary == "durable":
                        # A durable entry can be inspected; no actual external
                        # kill here because this test still owns the Popen.
                        signal.raise_signal(signal.SIGTERM)
                        with self.assertRaisesRegex(AssertionError, "unfinished creation intent"):
                            Environment(env.root).assert_clean()

                with patch.object(env, "_record", side_effect=register), self.assertRaises(InterruptedError):
                    env.spawn(create, ["detached-test"])
                self.assertEqual(signal.getsignal(signal.SIGTERM), old_handler)
                self.assertIsNotNone(self.owned[-1][0].returncode)
                self.assertEqual(env.cleanup(), [])
                Environment(env.root).assert_clean()

    def test_child_does_not_inherit_blocked_sigterm(self):
        command = [sys.executable, "-c", "import signal,time,json; "
                   "print(json.dumps([int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, [])]),flush=True); "
                   "time.sleep(20)"]
        with environment() as env:
            child = env.spawn(lambda: self.launch(command, stdout=subprocess.PIPE, text=True), command)
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(3), "child did not publish its mask")
            self.assertNotIn(int(signal.SIGTERM), json.loads(child.stdout.readline()))
            self.assertEqual(env.cleanup(), [child.pid])
            self.assertEqual(child.returncode, -signal.SIGTERM)

    def test_cleanup_and_assert_clean_include_unregistered_memory_children(self):
        with environment() as env:
            child = self.launch()
            env.children.append(child)
            with patch("nexus_env.time.monotonic", side_effect=[0, 4]):
                with self.assertRaisesRegex(AssertionError, str(child.pid)):
                    env.assert_clean()
            self.assertEqual(env.cleanup(), [child.pid])
            self.assertIsNotNone(child.returncode)

    def test_intent_persists_when_factory_does_not_return_a_child(self):
        with environment() as env:
            with self.assertRaisesRegex(RuntimeError, "factory interrupted"):
                env.spawn(lambda: (_ for _ in ()).throw(RuntimeError("factory interrupted")), ["mock"])
            with self.assertRaisesRegex(RuntimeError, "unfinished creation intent"):
                Environment(env.root).cleanup()
            with self.assertRaisesRegex(AssertionError, "unfinished creation intent"):
                env.assert_clean()

    def test_nexus_error_after_popen_is_already_registered(self):
        from ida_nexus import _resolver
        with environment() as env:
            def spawner():
                _resolver.subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"],
                                           start_new_session=True)
                raise OSError("upstream post-spawn log failure")

            with self.assertRaisesRegex(OSError, "post-spawn"), patch(
                    "verify_nexus_n0.subprocess.Popen", side_effect=self.launch):
                owned_nexus_spawn(env, spawner)
            self.assertEqual(len(env.entries()), 1)
            self.assertEqual(env.cleanup(), [env.children[0].pid])
            env.assert_clean()

    def test_real_exec_keeps_precise_birth(self):
        code = ("import os,sys; print('BEFORE',flush=True); sys.stdin.readline(); "
                "os.execv(sys.executable,[sys.executable,'-c',"
                "\"import time; print('AFTER',flush=True); time.sleep(20)\"])")
        command = [sys.executable, "-c", code]
        with environment() as env:
            child = env.spawn(lambda: self.launch(command, stdin=subprocess.PIPE,
                                                  stdout=subprocess.PIPE, text=True), command)
            before = identity(child.pid)
            for expected in ("BEFORE", "AFTER"):
                if expected == "AFTER":
                    child.stdin.write("exec\n")
                    child.stdin.flush()
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(3), f"missing {expected} exec barrier")
                self.assertEqual(child.stdout.readline().strip(), expected)
            self.assertTrue(same_process(identity(child.pid), before))
            self.assertEqual(env.cleanup(), [child.pid])
            self.assertIsNone(identity(child.pid))


class CleanupFailureTests(unittest.TestCase):
    def test_memory_child_error_does_not_prevent_later_child_cleanup(self):
        from unittest.mock import Mock
        with environment() as env:
            first = Mock(pid=11111)
            first.poll.return_value = None
            first.terminate.side_effect = PermissionError("held child denied")
            second = Mock(pid=22222)
            second.poll.return_value = None
            env.children.extend([first, second])
            with self.assertRaisesRegex(RuntimeError, "held child denied"):
                env.cleanup()
            second.terminate.assert_called_once()
            second.wait.assert_called_once_with(timeout=3)
    def test_esrch_at_kill_escalation_still_visits_later_entry(self):
        with environment() as env:
            ledger(env, [11111, 22222])
            live = {11111, 22222}

            def kill(pid, sig):
                if sig == signal.SIGKILL:
                    live.remove(pid)
                    raise ProcessLookupError(errno.ESRCH, "exited before KILL")
                if pid == 22222:
                    live.remove(pid)

            with patch("nexus_env.identity", side_effect=lambda pid: BIRTH if pid in live else None), patch(
                    "nexus_env.time.monotonic", side_effect=[0, 4, 0]), patch("nexus_env.os.kill", side_effect=kill) as signals:
                self.assertEqual(env.cleanup(), [11111, 22222])
                self.assertEqual([c.args for c in signals.call_args_list],
                                 [(11111, signal.SIGTERM), (11111, signal.SIGKILL), (22222, signal.SIGTERM)])

    def test_esrch_does_not_prevent_later_entry_cleanup(self):
        with environment() as env:
            ledger(env, [11111, 22222])
            live = {11111, 22222}

            def kill(pid, _sig):
                live.remove(pid)
                if pid == 11111:
                    raise ProcessLookupError(errno.ESRCH, "exited after confirmation")

            with patch("nexus_env.identity", side_effect=lambda pid: BIRTH if pid in live else None), patch(
                    "nexus_env.os.kill", side_effect=kill) as signals:
                self.assertEqual(env.cleanup(), [22222])
                self.assertEqual([c.args[0] for c in signals.call_args_list], [11111, 22222])
                env.assert_clean()

    def test_signal_or_identity_error_is_reported_after_later_entry_cleanup(self):
        for failure in ("signal", "identity"):
            with self.subTest(failure=failure), environment() as env:
                ledger(env, [11111, 22222])
                live = {11111, 22222}

                def query(pid):
                    if pid == 11111 and failure == "identity":
                        raise PermissionError("identity denied")
                    return BIRTH if pid in live else None

                def kill(pid, _sig):
                    if pid == 11111:
                        raise PermissionError("signal denied")
                    live.remove(pid)

                with patch("nexus_env.identity", side_effect=query), patch("nexus_env.os.kill", side_effect=kill) as signals:
                    with self.assertRaisesRegex(RuntimeError, f"{failure} denied"):
                        env.cleanup()
                    self.assertNotIn(22222, live)
                    self.assertEqual([c.args[0] for c in signals.call_args_list],
                                     [11111, 22222] if failure == "signal" else [22222])

    def test_corrupt_half_line_or_old_ledger_never_reports_clean(self):
        for bad in ('{"schema":', '{}\n', json.dumps({"schema": 2, "pid": 123, "identity": BIRTH}),
                    json.dumps({"pid": 123, "identity": "Thu Oct 15 01:17:40 2026 worker"}) + '\n'):
            with self.subTest(bad=bad), environment() as env:
                env.ledger.write_text(bad)
                with patch("nexus_env.os.kill") as kill:
                    with self.assertRaisesRegex(RuntimeError, "ledger line"):
                        env.cleanup()
                    with self.assertRaisesRegex(AssertionError, "ledger line"):
                        env.assert_clean()
                    kill.assert_not_called()

    def test_corrupt_ledger_still_cleans_other_valid_entry(self):
        with environment() as env:
            ledger(env, [22222])
            with env.ledger.open("a") as out:
                out.write('{"pid":')
            with patch("nexus_env.identity", side_effect=[BIRTH, None, None]), patch("nexus_env.os.kill") as kill:
                with self.assertRaisesRegex(RuntimeError, "ledger line 2"):
                    env.cleanup()
                kill.assert_called_once_with(22222, signal.SIGTERM)

    def test_identity_failure_is_not_clean_or_authority_to_signal(self):
        with environment() as env:
            ledger(env, [11111])
            with patch("nexus_env.identity", side_effect=OSError("query failed")), patch("nexus_env.os.kill") as kill:
                with self.assertRaisesRegex(RuntimeError, "query failed"):
                    env.cleanup()
                with self.assertRaisesRegex(AssertionError, "identity unknown"):
                    env.assert_clean()
                kill.assert_not_called()

    def test_exited_or_unrecognized_identity_does_not_authorize_signals(self):
        with environment() as env:
            ledger(env, [11111])
            with patch("nexus_env.identity", return_value=None), patch("nexus_env.os.kill") as kill:
                self.assertEqual(env.cleanup(), [])
                env.assert_clean()
                kill.assert_not_called()
            with patch("nexus_env.identity", return_value="unknown"), patch("nexus_env.os.kill") as kill:
                with self.assertRaisesRegex(RuntimeError, "invalid identity query"):
                    env.cleanup()
                with self.assertRaisesRegex(AssertionError, "invalid identity query"):
                    env.assert_clean()
                kill.assert_not_called()


class PlatformIdentityTests(unittest.TestCase):
    def test_macos_layout_and_short_or_failed_query_are_explicit(self):
        from unittest.mock import Mock
        self.assertEqual(ctypes.sizeof(process_identity.ProcBsdInfo), 136)
        self.assertEqual(process_identity.ProcBsdInfo.start_sec.offset, 120)
        self.assertEqual(process_identity.ProcBsdInfo.start_usec.offset, 128)
        for count, code in ((0, errno.ESRCH), (0, errno.EPERM), (120, 0)):
            lib = Mock()

            def query(*_):
                ctypes.set_errno(code)
                return count

            lib.proc_pidinfo.side_effect = query
            with self.subTest(count=count, code=code), patch("process_identity.ctypes.CDLL", return_value=lib):
                if code == errno.ESRCH:
                    self.assertIsNone(process_identity._mac_identity(123))
                else:
                    with self.assertRaises(OSError):
                        process_identity._mac_identity(123)

    def test_linux_stat_handles_spaces_and_parentheses_and_boot_identity(self):
        fields = ["S"] + ["0"] * 18 + ["123456"]
        stat = "123 (worker (exec) name) " + " ".join(fields)

        def read(path):
            return BOOT_ID if str(path).endswith("boot_id") else stat

        with patch.object(Path, "read_text", read):
            first = process_identity._linux_identity(123)
            self.assertEqual(first["birth"], [123456])
            self.assertEqual(first["boot_id"], BOOT_ID)
            self.assertFalse(same_process({**first, "boot_id": "00000000-0000-0000-0000-000000000002"}, first))
        with patch.object(Path, "read_text", side_effect=[BOOT_ID, FileNotFoundError()]):
            self.assertIsNone(process_identity._linux_identity(123))
        with patch.object(Path, "read_text", side_effect=[BOOT_ID, PermissionError()]):
            with self.assertRaises(PermissionError):
                process_identity._linux_identity(123)


class StartupFaultTests(ChildTests):
    def test_registered_worker_without_successful_stop_is_not_pass(self):
        from ida_nexus import _resolver
        import ida_nexus.handle
        with environment() as env:
            def spawner():
                process = _resolver.subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"],
                                                     start_new_session=True)
                return process, env.root / "test.log"

            def resolve(*_, spawner, **_kw):
                spawner()
                raise AssertionError("failed SIGSTOP must propagate before this point")

            original_kill = os.kill

            def kill(pid, sig):
                if sig == signal.SIGSTOP:
                    raise PermissionError("stop denied")
                return original_kill(pid, sig)

            with patch("ida_nexus._resolver.spawn_worker", side_effect=spawner), patch(
                    "ida_nexus._resolver.resolve_instance", side_effect=resolve), patch(
                    "ida_nexus.DatabaseHandle.open", side_effect=lambda *_a, **_kw: ida_nexus.handle.resolve_instance()), patch(
                    "verify_nexus_n0.subprocess.Popen", side_effect=self.launch), patch(
                    "verify_nexus_n0.os.kill", side_effect=kill), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(PermissionError, "stop denied"):
                    startup_timeout(env, 0.1)
            result = json.loads((env.root / "startup-timeout-cleanup.json").read_text())
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["owned_workers"], [self.owned[0][0].pid])
            self.assertEqual(result["stopped_workers"], [])
            self.assertFalse(result["clean"])
            self.assertIsNotNone(self.owned[0][0].returncode)

    def test_timeout_before_spawn_is_failure_not_expected_timeout(self):
        with environment() as env, patch("ida_nexus.DatabaseHandle.open", side_effect=TimeoutError("timed out before spawn")):
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaisesRegex(AssertionError, "before a registered worker"):
                startup_timeout(env, 1e-9)
            self.assertNotIn("EXPECTED_TIMEOUT", output.getvalue())
            result = json.loads((env.root / "startup-timeout-cleanup.json").read_text())
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["owned_workers"], [])
            self.assertFalse(result["clean"])

    def test_registered_stopped_worker_timeout_requires_real_cleanup(self):
        from ida_nexus import _resolver
        import ida_nexus.handle
        with environment() as env:
            def spawner():
                process = _resolver.subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"],
                                                     start_new_session=True)
                return process, env.root / "test.log"

            def resolve(*_, spawner, **_kw):
                spawner()
                raise TimeoutError("timed out waiting for stopped worker")

            with patch("ida_nexus._resolver.spawn_worker", side_effect=spawner), patch(
                    "ida_nexus._resolver.resolve_instance", side_effect=resolve), patch(
                    "ida_nexus.DatabaseHandle.open", side_effect=lambda *_a, **_kw: ida_nexus.handle.resolve_instance()), patch(
                    "verify_nexus_n0.subprocess.Popen", side_effect=self.launch), redirect_stdout(io.StringIO()):
                startup_timeout(env, 0.1)
            result = json.loads((env.root / "startup-timeout-cleanup.json").read_text())
            self.assertEqual(result["status"], "EXPECTED_TIMEOUT")
            self.assertEqual(result["stopped_workers"], result["owned_workers"])
            self.assertEqual(result["signalled_owned_pids"], result["owned_workers"])
            self.assertTrue(result["clean"])
            self.assertIsNotNone(self.owned[0][0].returncode)


if __name__ == "__main__":
    unittest.main()
