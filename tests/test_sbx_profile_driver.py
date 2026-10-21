"""PID accounting remains strict while an already-recorded child is a zombie."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent/'support'))
import sbx_profile_real as driver
from process_identity import identity


class Ledger:
    def __init__(self):
        self.rows = []

    def entries(self):
        return self.rows

    def _record(self, process, _command):
        captured = identity(process.pid)
        assert captured is not None
        self.rows.append({'pid':process.pid, 'identity':captured})


class CaptureTests(unittest.TestCase):
    def test_recorded_zombie_is_exited_without_losing_its_birth(self):
        ledger = Ledger()
        with tempfile.TemporaryDirectory(prefix='sbx-pid-') as directory:
            root = Path(directory)
            child = subprocess.Popen([sys.executable,'-c','import sys; sys.stdin.buffer.read(1)'], stdin=subprocess.PIPE)
            try:
                seen, _ = driver.capture(ledger, os.getpid(), root)
                self.assertIn(child.pid, seen)
                child.stdin.write(b'x')
                child.stdin.flush()
                deadline = time.monotonic()+2
                while identity(child.pid) is not None:
                    self.assertLess(time.monotonic(), deadline, 'child must reach actual kernel terminal')
                    time.sleep(.001)
                # Deliberately not reaped: the child list must still name it.
                self.assertIn(child.pid, driver.children(os.getpid()))
                seen, _ = driver.capture(ledger, os.getpid(), root)
                self.assertIn(child.pid, seen)
                self.assertTrue(any(row['pid']==child.pid and row['identity'] for row in ledger.entries()))
            finally:
                child.communicate(input=b'',timeout=3)
            self.assertEqual(child.returncode, 0)

    def test_unknown_disappeared_child_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='sbx-unknown-') as directory:
            with patch.object(driver, 'children', return_value=[2_000_000_000]):
                with self.assertRaisesRegex(AssertionError, 'process disappeared before birth capture'):
                    driver.capture(Ledger(), os.getpid(), Path(directory))


if __name__ == '__main__':
    unittest.main()
