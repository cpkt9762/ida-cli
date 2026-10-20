"""Probe lifecycle checks record exact native births before interpreter exec."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tests/support'))
from process_identity import identity, same_process, valid_identity


class ProbeTests(unittest.TestCase):
    def probe(self, foreign=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        ipc = root / 'ipc'
        ipc.mkdir()
        ledger = root / 'children.jsonl'
        real_python = str(Path(os.environ['N9_PROBE_PYTHON']).absolute())
        wrapper = root / 'python'
        wrapper.write_text(f'''#!{sys.executable}
import json,os,sys
from pathlib import Path
sys.path.insert(0,{str(REPO / 'tests/support')!r})
from process_identity import identity
with open({str(ledger)!r},'a') as output:
 output.write(json.dumps({{'pid':os.getpid(),'identity':identity(os.getpid()),'argv':sys.argv[1:]}})+'\\n')
 output.flush();os.fsync(output.fileno())
if {foreign!r} and 'proof_helper' in sys.argv:
 bootstrap=next(Path(arg) for arg in sys.argv if arg.endswith('/bootstrap.py'))
 (bootstrap.parent.parent/'foreign').write_bytes(b'foreign data must survive')
os.execv({real_python!r},[{real_python!r},*sys.argv[1:]])
''')
        wrapper.chmod(0o700)
        env = os.environ | {'HOME': str(root / 'home'), 'IDA_CLI_HOME': str(root / 'home/cli'),
            'IDA_NEXUS_STATE_DIR': str(root / 'state'), 'IDA_NEXUS_IPC_ROOT': str(ipc),
            'TMPDIR': str(ipc), 'IDA_NEXUS_PYTHON': str(wrapper)}
        env.pop('IDA_NEXUS_BRIDGE_SCRIPT', None)
        result = subprocess.run([os.environ['N9_PROBE_BINARY'], 'probe-runtime'],
                                env=env, capture_output=True, text=True, timeout=30)
        rows = [json.loads(line) for line in ledger.read_text().splitlines()]
        self.assertEqual(len(rows), 2, rows)
        self.assertEqual(sum('proof_helper' in row['argv'] for row in rows), 1)
        self.assertEqual(sum('bridge' in row['argv'] for row in rows), 1)
        for row in rows:
            self.assertTrue(valid_identity(row['identity']), row)
            self.assertFalse(same_process(identity(row['pid']), row['identity']), row)
        self.assertEqual([str(path) for path in ipc.rglob('*') if path.is_socket()], [])
        return result, ipc, rows

    def test_normal_probe_reaps_its_processes_and_removes_owned_directory(self):
        result, ipc, rows = self.probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['backend'], 'nexus')
        self.assertEqual(list(ipc.iterdir()), [], 'probe must explicitly clean its creation records')
        print(json.dumps({'case': 'normal', 'exit': result.returncode,
                          'children': rows, 'ipc_empty': True}))

    def test_foreign_entry_is_retained_after_owned_processes_and_sockets_exit(self):
        result, ipc, rows = self.probe(foreign=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('probe cleanup retained', result.stderr)
        foreign = list(ipc.glob('*/foreign'))
        self.assertEqual(len(foreign), 1)
        self.assertEqual(foreign[0].read_bytes(), b'foreign data must survive')
        self.assertEqual(list(foreign[0].parent.iterdir()), foreign)
        print(json.dumps({'case': 'foreign', 'exit': result.returncode,
                          'children': rows, 'retained': str(foreign[0])}))


if __name__ == '__main__':
    unittest.main()
