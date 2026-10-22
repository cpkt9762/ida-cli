"""Same-boot death requires complete native identity, never a failed query."""
import errno
import os
import signal
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

    def test_zombie_is_retained_until_reaped(self):
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
            with self.assertRaisesRegex(RuntimeError, 'zombie retained'):
                processes.same_boot_exit(recorded)
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
