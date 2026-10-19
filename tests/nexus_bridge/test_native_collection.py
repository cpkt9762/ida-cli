"""Neutral native collection; a zombie birth is not execution liveness/proof."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'support'))
from process_identity import identity


class NativeCollection(unittest.TestCase):
    def test_exit_before_wait_keeps_birth_and_records_real_wait_status(self):
        child=subprocess.Popen(['timeout','8s',sys.executable,'-B','-c',
            'import sys; sys.stdin.read(1)'],stdin=subprocess.PIPE)
        try:
            captured=identity(child.pid)
            self.assertIsNotNone(captured)
            child.stdin.write(b'x');child.stdin.flush()
            observed=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT)
            self.assertEqual(observed.si_pid,child.pid)
            self.assertEqual(observed.si_status,0)
            self.assertIsNone(identity(child.pid),'exited process must never pass execution-liveness API')
        finally:
            child.stdin.close()
            code=child.wait(timeout=3)
        self.assertEqual(code,0)
        (Path(os.environ['R3A_CASE_ROOT'])/'native-observation.json').write_text(json.dumps(dict(
            pid=child.pid,birth=captured,waitid_status=observed.si_status,wait_exit=code,
            execution_liveness=False,public_proof=False),indent=2))


if __name__=='__main__':unittest.main(verbosity=2)
