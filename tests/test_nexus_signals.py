"""Real daemon signal refusal and retirement, including an uninitialized stdio peer."""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tests/support'))
from nexus_env import Environment
from process_identity import identity, same_process


def wait_for(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError('signal lifecycle barrier expired')
        time.sleep(.01)


class SignalTests(unittest.TestCase):
    def start(self, transport):
        prepared = Path(os.environ['N3_ENV_ROOT'])
        root = Path(tempfile.mkdtemp(prefix='signals-', dir=prepared.parent)).resolve()
        manifest = json.loads((prepared / 'environment.json').read_text())
        manifest['root'] = str(root)
        (root / 'environment.json').write_text(json.dumps(manifest))
        for name in ('venv', 'profile'):
            (root / name).symlink_to(prepared / name, target_is_directory=True)
        for name in ('home', 'state', 'ipc', 'tmp'):
            (root / name).mkdir(mode=0o700)
        env = Environment(root)
        variables = env.variables()
        ledger = root / 'boundary.jsonl'
        ledger.touch(mode=0o600)
        (root / 'native.jsonl').touch(mode=0o600)
        wrapper = root / 'python'
        wrapper.write_text(f'''#!{sys.executable}
import json,os,sys
sys.path.insert(0,{str(REPO / 'tests/support')!r})
from process_identity import identity
with open({str(ledger)!r},'a') as output:
 output.write(json.dumps({{'pid':os.getpid(),'identity':identity(os.getpid())}})+'\\n')
 output.flush();os.fsync(output.fileno())
os.execv({str(root / 'venv/bin/python')!r},[{str(root / 'venv/bin/python')!r},*sys.argv[1:]])
''')
        wrapper.chmod(0o700)
        variables.update(IDA_NEXUS_PYTHON=str(wrapper), IDA_NEXUS_IPC_ROOT=str(root / 'ipc'),
                         R2_LEDGER=str(root / 'native.jsonl'), R2_CASE_ROOT=str(root),
                         R2_TELEMETRY_SOURCE=str(REPO / 'tests/support/r2_process_ledger.py'))
        command = [os.environ['N9_PROBE_BINARY'], 'serve']
        if transport == 'http':
            command = [os.environ['N9_PROBE_BINARY'], 'serve-http', '--bind', '127.0.0.1:0']
        log = (root / 'daemon.log').open('wb')
        self.addCleanup(log.close)
        child = env.spawn(lambda: subprocess.Popen(command, env=variables,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log), command)
        self.addCleanup(child.stdin.close)
        self.addCleanup(child.stdout.close)
        birth = identity(child.pid)
        control = root / 'cli-home/server.sock'

        def rpc(method, params=None):
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(25)
                connection.connect(str(control))
                connection.sendall((json.dumps({'jsonrpc': '2.0', 'id': 'signal',
                    'method': method, 'params': params or {}}) + '\n').encode())
                with connection.makefile('r') as stream:
                    response = json.loads(stream.readline())
            self.assertIn('result', response, response)
            return response['result']

        release = root / 'release'

        def cleanup_failure():
            release.touch()
            if child.poll() is None:
                try:
                    rpc('shutdown')
                    child.wait(timeout=20)
                except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired):
                    if same_process(identity(child.pid), birth):
                        child.kill()
                        child.wait(timeout=5)
        self.addCleanup(cleanup_failure)
        wait_for(lambda: control.exists() or child.poll() is not None)
        self.assertIsNone(child.poll(), (root / 'daemon.log').read_text())
        rpc('status')
        return root, child, birth, rpc, release

    def assert_clean(self, root, child):
        self.assertEqual(child.wait(timeout=25), 0, (root / 'daemon.log').read_text())
        rows = [json.loads(line) for line in (root / 'boundary.jsonl').read_text().splitlines()]
        native = root / 'native.jsonl'
        self.assertTrue(native.is_file(), 'native owner ledger required')
        records = [json.loads(line) for line in native.read_text().splitlines()]
        self.assertFalse(any(row['kind'] == 'capture_failed' for row in records), records)
        self.assertEqual({row['intent'] for row in records if row['kind'] == 'intent'},
                         {row['intent'] for row in records if row['kind'] in ('started', 'spawn_failed')})
        rows += [row for row in records if row['kind'] == 'started']
        self.assertGreaterEqual(len(rows), 2, 'bridge/helper birth ledger required')
        wait_for(lambda: all(not same_process(identity(row['pid']), row['identity']) for row in rows))
        self.assertEqual([str(path) for path in root.rglob('*') if path.is_socket()], [])
        (root / 'signal-result.json').write_text(json.dumps({'status': 'PASS', 'processes': rows}))

    def test_idle_http_term_exits_naturally(self):
        root, child, birth, _, _ = self.start('http')
        self.assertTrue(same_process(identity(child.pid), birth))
        child.send_signal(signal.SIGTERM)
        self.assert_clean(root, child)

    def test_idle_stdio_without_handshake_accepts_both_signals(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig):
                root, child, _, _, _ = self.start('stdio')
                child.send_signal(sig)
                self.assert_clean(root, child)

    def test_busy_signals_refuse_then_can_be_retried_after_completion(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig):
                root, child, birth, rpc, release = self.start('http')
                sample = root / 'mini'
                shutil.copyfile(Path(os.environ['N3_ENV_ROOT']) / 'fixtures/mini', sample)
                started, completed = root / 'started', root / 'completed'
                code = ("from pathlib import Path\nimport time\n"
                    f"Path({str(started)!r}).write_text('started')\n"
                    f"while not Path({str(release)!r}).exists(): time.sleep(.01)\n"
                    f"Path({str(completed)!r}).write_text('completed')\nprint('once')")
                # A separate caller keeps the cooperative script in flight.
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=1) as executor:
                    work = executor.submit(rpc, 'run_script', {'path': str(sample), 'code': code})
                    try:
                        wait_for(started.exists)
                        child.send_signal(sig)
                        wait_for(lambda: 'Signal shutdown refused; service retained' in (root / 'daemon.log').read_text())
                        self.assertTrue(same_process(identity(child.pid), birth), 'busy signal exited daemon')
                        self.assertFalse(work.done(), 'busy signal killed cooperative work')
                        self.assertFalse(completed.exists())
                        self.assertIn('CancelPending', (root / 'daemon.log').read_text())
                        self.assertEqual(rpc('status')['worker_count'], 1)
                    finally:
                        release.touch()
                    terminal = work.result(timeout=20)
                self.assertTrue(terminal['success'], terminal)
                self.assertEqual(terminal['stdout'], 'once\n')
                child.send_signal(sig)
                self.assert_clean(root, child)


if __name__ == '__main__':
    unittest.main()
