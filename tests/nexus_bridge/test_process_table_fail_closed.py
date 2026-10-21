"""Native process enumeration must never turn unreadable rows into absence."""
import ctypes
import errno
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'nexus_bridge/custody'))
from custody_process_identity import ProcBsdInfo, _mac_commands


class ProcessTableFailClosed(unittest.TestCase):
    def library(self, *, got=0, error=errno.EPERM, saturated=False, zombie=False):
        lib = Mock()
        def listing(buffer, size):
            if buffer is None:
                return 1
            buffer[0] = 12345
            return size // ctypes.sizeof(ctypes.c_int) if saturated else 1
        def arguments(*args):
            ctypes.set_errno(errno.EACCES)
            return -1
        def status(pid, flavor, arg, out, size):
            ctypes.set_errno(error)
            if got == ctypes.sizeof(ProcBsdInfo):
                out._obj.pid = pid
                out._obj.status = 5 if zombie else 2
            return got
        lib.proc_listallpids.side_effect = listing
        lib.sysctl.side_effect = arguments
        lib.proc_pidinfo.side_effect = status
        return lib

    def test_permission_denied_status_is_an_error(self):
        with patch('ctypes.CDLL', return_value=self.library()):
            with self.assertRaises(OSError):
                _mac_commands()

    def test_short_process_status_is_an_error(self):
        with patch('ctypes.CDLL', return_value=self.library(got=8, error=0)):
            with self.assertRaises(OSError):
                _mac_commands()

    def test_only_confirmed_esrch_or_zombie_is_skipped(self):
        for lib in (self.library(error=errno.ESRCH), self.library(got=ctypes.sizeof(ProcBsdInfo), zombie=True)):
            with patch('ctypes.CDLL', return_value=lib):
                self.assertEqual(_mac_commands(), [])

    def test_buffer_saturation_is_an_error(self):
        with patch('ctypes.CDLL', return_value=self.library(saturated=True)):
            with self.assertRaisesRegex(RuntimeError, 'buffer saturated'):
                _mac_commands()

    def test_argument_short_read_is_an_error(self):
        lib = self.library()
        def arguments(mib, length, buffer, size, *rest):
            size._obj.value = 2
            return 0
        lib.sysctl.side_effect = arguments
        with patch('ctypes.CDLL', return_value=lib):
            with self.assertRaisesRegex(RuntimeError, 'short or oversized'):
                _mac_commands()
