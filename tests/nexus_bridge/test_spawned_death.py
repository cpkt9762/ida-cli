"""Same-boot death requires complete native identity, never a failed query."""
import errno
import os
import signal
import json
import socket
import threading
import time
from unittest.mock import patch
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'nexus_bridge/custody'))
import custody_process_identity as processes


class SameBootExit(unittest.TestCase):
    def setUp(self):
        self.recorded = processes.capture(os.getpid())
        self.boot = self.recorded['boot_id']

    def verdict(self, current, recorded=None, boot=None):
        return processes.same_boot_exit(
            self.recorded if recorded is None else recorded,
            read=lambda pid: current, current_boot=lambda: self.boot if boot is None else boot)

    def test_live_and_stopped_birth_is_not_dead(self):
        current = {k:self.recorded[k] for k in ('kind', 'boot_id', 'birth')}
        self.assertIsNone(self.verdict(current))

    def test_reused_pid_with_complete_different_birth_is_dead(self):
        current = {k:self.recorded[k] for k in ('kind', 'boot_id', 'birth')}
        current['birth'] = list(current['birth'])
        current['birth'][0] += 1
        self.assertEqual(self.verdict(current)['reason'], 'pid_reused')

    def test_full_native_zombie_identity_proves_exit(self):
        current = {k:self.recorded[k] for k in ('kind', 'boot_id', 'birth')}
        current['state'] = 'zombie'
        self.assertEqual(self.verdict(current)['reason'], 'zombie')

    def test_definite_esrch_is_dead(self):
        self.assertEqual(self.verdict(None)['reason'], 'esrch')

    def test_bad_or_cross_boot_identity_retains_obligation(self):
        for value in ({}, {'birth': []}, dict(self.recorded, pid=True),
                      dict(self.recorded, birth=[0]), dict(self.recorded, boot_id='broken')):
            with self.subTest(value=value):
                self.assertIsNone(self.verdict(None, recorded=value))
        self.assertIsNone(self.verdict(None, boot='00000000-0000-0000-0000-000000000000'))
        self.assertIsNone(self.verdict({'kind':'macos-libproc-v1', 'boot_id':self.boot, 'birth':[]}))

    def test_query_error_retains_obligation(self):
        def denied(pid):
            raise PermissionError(errno.EPERM, 'controlled denial')
        with self.assertRaises(PermissionError):
            processes.same_boot_exit(self.recorded, read=denied, current_boot=lambda:self.boot)

    def test_real_child_reaped_is_dead(self):
        child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'], stdin=subprocess.PIPE)
        recorded = processes.capture(child.pid)
        try:
            self.assertIsNone(processes.same_boot_exit(recorded))
        finally:
            child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0)
        self.assertEqual(processes.same_boot_exit(recorded)['reason'], 'esrch')

    def test_real_sigstop_retains_obligation(self):
        child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 start_new_session=True)
        recorded = processes.capture(child.pid)
        try:
            self.assertEqual(processes.capture(child.pid), recorded)
            os.kill(child.pid, signal.SIGSTOP)
            self.assertIsNone(processes.same_boot_exit(recorded))
        finally:
            self.assertEqual(processes.capture(child.pid), recorded)
            os.kill(child.pid, signal.SIGCONT)
            child.communicate(timeout=5)

    def test_zombie_has_exited_even_before_reaping(self):
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(write_fd)
            os.read(read_fd, 1)
            os._exit(0)
        os.close(read_fd)
        recorded = processes.capture(pid)
        os.close(write_fd)
        try:
            deadline = time.monotonic() + 5
            while processes.identity(pid) is not None:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            self.assertIn(processes.same_boot_exit(recorded)['reason'], ('esrch', 'zombie'))
        finally:
            os.waitpid(pid, 0)
        self.assertEqual(processes.same_boot_exit(recorded)['reason'], 'esrch')

    def test_native_short_read_and_permission_error_are_not_esrch(self):
        class Lib:
            def __init__(self, count, error):
                def proc(*args):
                    processes.ctypes.set_errno(error)
                    return count
                self.proc_pidinfo = proc
        for count, error in ((0, errno.EPERM), (0, 0), (32, 0)):
            with self.subTest(count=count, error=error), patch.object(
                    processes.ctypes, 'CDLL', return_value=Lib(count, error)):
                with self.assertRaises(OSError):
                    processes.exit_identity(os.getpid())


import test_launch_settle as launch_tests
from target_coordination import Target
from target_journal import Journal
from ida_nexus._launch_authorization import decide


class SpawnedSettlement(unittest.TestCase):
    setUp = launch_tests.LaunchSettle.setUp
    reap = launch_tests.LaunchSettle.reap
    call = launch_tests.LaunchSettle.call
    sign_launch = launch_tests.LaunchSettle.sign_launch
    fake_worker = launch_tests.LaunchSettle.fake_worker

    def spawned(self, *, claimed=True):
        epoch = self.sign_launch()
        worker = self.fake_worker()
        if claimed:
            self.assertTrue(decide(self.launch['authorization'], self.suffix, str(self.target_path), 'claimed'))
        with Target(self.target_path) as target, target.locked():
            receipt = self.call('spawned', watch='startup', launch=self.launch, pid=worker.pid,
                                os_identity=processes.capture(worker.pid))['receipt']
            Journal(target).launch_signed(receipt)
        return epoch, worker

    def test_unclaimed_death_revokes_before_settling_and_denies_late_claim(self):
        epoch, worker = self.spawned(claimed=False)
        worker.kill()
        worker.wait(timeout=5)
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            reply = journal.spawned_dead('startup', epoch)
            self.assertEqual(reply['state'], 'dead')
            self.assertEqual(reply['consumer']['record']['evidence']['authorization_decision'], 'revoked')
            self.assertFalse(decide(self.launch['authorization'], self.suffix, str(self.target_path), 'claimed'))
            self.assertEqual(self.target_path.read_bytes(), b'private input')
            self.assertIsNone(journal.value['entries'][str(epoch)]['owner'])
            self.assertNotIn('proof', journal.value['entries'][str(epoch)])
            self.call('spawned_dead_adopt', watch='startup', consumer=reply['consumer'])
            self.call('retire', watch='startup', sha256=reply['consumer']['sha256'])
            self.call('retire_parent', parent=launch_tests.ACQUISITION['parent'])
            journal.spawned_dead_ack('startup', epoch)
            journal.settle()
            self.assertEqual(journal.value['entries'], {})

    def test_unclaimed_live_stopped_or_unknown_identity_cannot_revoke(self):
        epoch, worker = self.spawned(claimed=False)
        decision = Path(self.launch['authorization'] + '.decision')
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            self.assertEqual(journal.spawned_dead('startup', epoch)['state'], 'pending')
            recorded = processes.capture(worker.pid)
            self.assertEqual(processes.capture(worker.pid), recorded)
            os.kill(worker.pid, signal.SIGSTOP)
            try:
                self.assertEqual(journal.spawned_dead('startup', epoch)['state'], 'pending')
                with patch.object(processes, 'exit_identity', side_effect=PermissionError('denied')):
                    with self.assertRaises(PermissionError):
                        journal.spawned_dead('startup', epoch)
                with patch.object(processes, 'exit_identity', return_value={'birth': []}):
                    self.assertEqual(journal.spawned_dead('startup', epoch)['state'], 'pending')
                self.assertFalse(decision.exists())
                self.assertEqual(journal.value['entries'][str(epoch)]['launch'], self.launch)
            finally:
                self.assertEqual(processes.capture(worker.pid), recorded)
                os.kill(worker.pid, signal.SIGCONT)

    def test_unclaimed_partial_decision_and_read_error_retain_obligation(self):
        epoch, worker = self.spawned(claimed=False)
        worker.kill()
        worker.wait(timeout=5)
        import ida_nexus._launch_authorization as authorization
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            with patch.object(authorization, '_read', side_effect=PermissionError('denied')):
                with self.assertRaises(PermissionError):
                    journal.spawned_dead('startup', epoch)
            decision = Path(self.launch['authorization'] + '.decision')
            self.assertFalse(decision.exists())
            decision.touch(mode=0o600)
            with self.assertRaisesRegex(RuntimeError, 'invalid or incomplete'):
                journal.spawned_dead('startup', epoch)
            self.assertEqual(decision.read_bytes(), b'')
            self.assertEqual(journal.value['entries'][str(epoch)]['launch'], self.launch)

    def test_late_claim_races_revocation_with_exactly_one_winner(self):
        epoch, worker = self.spawned(claimed=False)
        worker.kill()
        worker.wait(timeout=5)
        import ida_nexus._launch_authorization as authorization
        barrier = threading.Barrier(2)
        outcomes, failures = [], []
        real_publish = authorization._publish
        def publish(directory, name, value):
            # Both contenders reach the real O_EXCL boundary; no filesystem or
            # durability operation is replaced. A partial loser read is allowed
            # to fail closed and is retried only after both writers finish.
            if name.endswith('.decision'):
                barrier.wait(timeout=5)
            return real_publish(directory, name, value)
        def claim():
            try:
                outcomes.append(decide(self.launch['authorization'], self.suffix, str(self.target_path), 'claimed'))
            except Exception as exc:
                failures.append(exc)
        with patch.object(authorization, '_publish', side_effect=publish):
            thread = threading.Thread(target=claim)
            thread.start()
            try:
                with Target(self.target_path) as target, target.locked():
                    journal = Journal(target)
                    try:
                        journal.spawned_dead('startup', epoch)
                    except (RuntimeError, ValueError):
                        self.assertIsNotNone(Journal(target).value['entries'][str(epoch)]['launch'])
            finally:
                thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        decision = json.loads(Path(self.launch['authorization'] + '.decision').read_bytes())['decision']
        if decision == 'claimed':
            self.assertEqual((outcomes, failures), ([True], []))
        else:
            self.assertNotIn(True, outcomes)
            self.assertTrue(outcomes == [False] or failures)
        self.assertFalse(decide(self.launch['authorization'], self.suffix, str(self.target_path), 'claimed'))
        with Target(self.target_path) as target, target.locked():
            reply = Journal(target).spawned_dead('startup', epoch)
        self.assertEqual(reply['state'], 'dead')
        evidence = reply['consumer']['record']['evidence']
        self.assertEqual(evidence.get('authorization_decision', 'claimed'), decision)

    def test_dead_spawned_settles_in_restart_gate_and_retains_database(self):
        epoch, worker = self.spawned()
        worker.kill()
        worker.wait(timeout=5)
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            reply = journal.spawned_dead('startup', epoch)
            self.assertEqual(reply['state'], 'dead')
            self.assertEqual(reply['consumer']['record']['kind'], 'SpawnedOwnerDiedUnpublished')
            item = journal.value['entries'][str(epoch)]
            self.assertIsNone(item['launch'])
            self.assertIsNone(item['owner'])
            self.assertNotIn('proof', item)
            self.assertEqual(self.target_path.read_bytes(), b'private input')
            self.assertEqual(journal.spawned_dead('startup', epoch), reply)
            Journal(target).gate()

    def test_live_worker_and_query_failure_retain_launch(self):
        epoch, worker = self.spawned()
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            self.assertEqual(journal.spawned_dead('startup', epoch)['state'], 'pending')
            with patch.object(processes, 'exit_identity', side_effect=PermissionError('denied')):
                with self.assertRaises(PermissionError):
                    journal.spawned_dead('startup', epoch)
            self.assertEqual(journal.value['entries'][str(epoch)]['launch'], self.launch)

    def test_known_owner_never_uses_spawned_death(self):
        epoch, worker = self.spawned()
        worker.kill()
        worker.wait(timeout=5)
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            journal.value['entries'][str(epoch)]['owner'] = {'pid':worker.pid}
            self.assertEqual(journal.spawned_dead('startup', epoch)['state'], 'not_applicable')

    def test_helper_adopts_only_journal_verified_fact_then_full_retirement(self):
        epoch, worker = self.spawned()
        worker.kill()
        worker.wait(timeout=5)
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            reply = journal.spawned_dead('startup', epoch)
            consumer = reply['consumer']
            self.call('spawned_dead_adopt', watch='startup', consumer=consumer)
            self.call('retire', watch='startup', sha256=consumer['sha256'])
            self.assertEqual(self.call('spawned_dead_adopt', watch='startup', consumer=consumer),
                             {'already_absent':True})
            self.call('retire_parent', parent=launch_tests.ACQUISITION['parent'])
            journal.spawned_dead_ack('startup', epoch)
            journal.settle()
            self.assertEqual(journal.value['entries'], {})
            self.assertEqual(journal.spawned_dead('startup', epoch), {'state':'closed'})
            self.assertEqual(journal.spawned_dead_ack('startup', epoch), {'state':'closed'})
        self.assertEqual(self.observer.items, {})
        self.assertEqual(self.observer.parents, {})

    def test_journal_save_failure_reuses_the_same_independent_immutable_fact(self):
        epoch, worker = self.spawned()
        worker.kill()
        worker.wait(timeout=5)
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            with patch.object(journal, 'save', side_effect=OSError('controlled write failure')):
                with self.assertRaisesRegex(OSError, 'controlled write failure'):
                    journal.spawned_dead('startup', epoch)
            restored = Journal(target)
            reply = restored.spawned_dead('startup', epoch)
            self.assertEqual(reply['state'], 'dead')
            self.assertEqual(restored.spawned_dead('startup', epoch), reply)

    def test_unknown_or_malformed_authorization_never_settles(self):
        epoch, worker = self.spawned()
        worker.kill()
        worker.wait(timeout=5)
        Path(self.launch['authorization'] + '.decision').write_bytes(b'{}')
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            with self.assertRaisesRegex(RuntimeError, 'not durably claimed'):
                journal.spawned_dead('startup', epoch)
            self.assertIsNotNone(journal.value['entries'][str(epoch)]['launch'])

    def test_restart_gate_keeps_old_helper_registry_unchanged(self):
        epoch, worker = self.spawned()
        worker.kill()
        worker.wait(timeout=5)
        self.observer.persist()
        before = (self.root/'helper-state.json').read_bytes()
        with Target(self.target_path) as target, target.locked():
            journal = Journal(target)
            journal.gate()
            self.assertIsNone(journal.value['entries'][str(epoch)]['launch'])
            journal.settle()
            self.assertIn(str(epoch), journal.value['entries'], 'live helper prevents premature evidence GC')
        self.assertEqual((self.root/'helper-state.json').read_bytes(), before)

    def test_restart_gate_retires_through_the_original_helpers_rpc(self):
        from proof_helper import bind_private_listener
        endpoint = str(self.root/'old-helper.sock')
        self.observer.endpoint = endpoint
        listener = socket.socket(socket.AF_UNIX)
        bind_private_listener(listener, endpoint)
        listener.listen(4)
        listener.settimeout(.1)
        stop = threading.Event()
        failures = []

        def serve():
            while not stop.is_set():
                try:
                    stream, _ = listener.accept()
                except TimeoutError:
                    continue
                with stream:
                    try:
                        with stream.makefile('rb') as source:
                            message = json.loads(source.readline())
                        reply = self.observer.receive(message)
                        self.observer.persist()
                        stream.sendall(json.dumps(dict(ok=True, protocol=2,
                            helper=self.observer.incarnation, **reply)).encode() + b'\n')
                    except Exception as exc:
                        failures.append(repr(exc))
                        stream.sendall(json.dumps(dict(ok=False, protocol=2,
                            helper=self.observer.incarnation, error=str(exc))).encode() + b'\n')

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            epoch, worker = self.spawned()
            worker.kill()
            worker.wait(timeout=5)
            self.assertTrue(self.observer.parents)
            with Target(self.target_path) as target, target.locked():
                journal = Journal(target)
                journal.gate()
                self.assertIsNone(journal.value['entries'][str(epoch)]['launch'])
            self.assertEqual(failures, [])
            self.assertEqual(self.observer.items, {})
            self.assertEqual(self.observer.parents, {})
            persisted = json.loads((self.root/'helper-state.json').read_text())
            self.assertEqual((persisted['items'], persisted['parents']), ({}, {}))
        finally:
            stop.set()
            thread.join(timeout=2)
            listener.close()
        self.assertFalse(thread.is_alive())


class PrivateWorkerSource(unittest.TestCase):
    def test_runtime_copy_preserves_sdk_except_the_explicit_fence(self):
        import nexus_worker_open_gate as generator
        import ida_nexus
        import hashlib
        import stat
        import tempfile
        with tempfile.TemporaryDirectory(dir=os.environ['R3A_CASE_ROOT']) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            generated = generator.build_worker(root)
            self.assertTrue(generated.is_relative_to(root))
            self.assertFalse(generated.is_relative_to(Path(__file__).resolve().parents[2]))
            self.assertEqual(stat.S_IMODE(generated.stat().st_mode), 0o600)
            source = generated.read_text()
            compile(source, str(generated), 'exec')
            source = source.removeprefix(generator._PREFIX)
            source = source.replace(generator._MAIN_HOOK, '', 1).replace(generator._FENCE, '', 1)
            original = (Path(ida_nexus.__file__).parent/'cli/worker.py').read_text()
            self.assertEqual(source, original)
            self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), generator._SDK_SHA256)

    def test_preclaim_runtime_copy_preserves_sdk_except_the_explicit_fence(self):
        import nexus_worker_open_gate as generator
        import ida_nexus
        import tempfile
        with tempfile.TemporaryDirectory(dir=os.environ['R3A_CASE_ROOT']) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            generated = generator.build_worker(root, before_claim=True)
            source = generated.read_text()
            compile(source, str(generated), 'exec')
            self.assertLess(source.index(generator._CLAIM_FENCE), source.index(generator._BEFORE_CLAIM))
            self.assertNotIn(generator._FENCE, source)
            source = source.removeprefix(generator._PREFIX)
            source = source.replace(generator._MAIN_HOOK, '', 1).replace(generator._CLAIM_FENCE, '', 1)
            self.assertEqual(source, (Path(ida_nexus.__file__).parent/'cli/worker.py').read_text())

    def test_nonprivate_directory_is_rejected_before_copy(self):
        import nexus_worker_open_gate as generator
        import tempfile
        with tempfile.TemporaryDirectory(dir=os.environ['R3A_CASE_ROOT']) as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'private directory outside'):
                generator.build_worker(root)
            self.assertEqual(list(root.iterdir()), [])


class UnclaimedRestartSettlement(unittest.TestCase):
    setUp = SpawnedSettlement.setUp
    reap = SpawnedSettlement.reap
    call = SpawnedSettlement.call
    sign_launch = SpawnedSettlement.sign_launch
    fake_worker = SpawnedSettlement.fake_worker

    def spawned(self):
        return SpawnedSettlement.spawned(self, claimed=False)

    test_gate = SpawnedSettlement.test_dead_spawned_settles_in_restart_gate_and_retains_database
    test_live_helper = SpawnedSettlement.test_restart_gate_keeps_old_helper_registry_unchanged
    test_helper_rpc = SpawnedSettlement.test_restart_gate_retires_through_the_original_helpers_rpc
    test_interrupted_publication = SpawnedSettlement.test_journal_save_failure_reuses_the_same_independent_immutable_fact
