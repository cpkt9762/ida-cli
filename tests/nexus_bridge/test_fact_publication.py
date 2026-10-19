"""Independent production fact publisher versus journal namespace readers.

NoAttach is a fixture payload, not a public lifetime proof or SDK result.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge/custody'), str(REPO/'nexus_bridge')]
from target_coordination import Target, digest
from target_journal import Journal


def producer(path, fault):
    from proof_helper import Observer
    with Target(path) as target:
        value = dict(target=str(path), coord_key=target.key, watch='concurrent-fact',
                     acquisition={'parent':'publication-fixture', 'purpose':'final', 'ordinal':1},
                     subscription_epoch=1, owner=None)
    original = os.link

    def pause(*args, **kwargs):
        original(*args, **kwargs)
        print('linked', flush=True)
        if fault == 'exit':
            os._exit(99)
        if sys.stdin.readline().strip() != 'continue':
            raise RuntimeError('test release missing')

    os.link = pause
    Observer('concurrent-helper', 8).publish(value, 'NoAttach')
    print('published', flush=True)


class FactPublication(unittest.TestCase):
    def test_live_publication_is_serialized_and_crashed_pending_bytes_remain(self):
        for kind in ('accounting', 'scan', 'crash'):
            with self.subTest(kind=kind):
                self.check_publication(kind)

    def check_publication(self, kind):
        root = Path(tempfile.mkdtemp(prefix='fact-view-', dir=os.environ['R3A_CASE_ROOT']))
        path = root/'input.i64'
        path.write_bytes(b'private unchanged payload')
        with Target(path) as target, target.locked():
            Journal(target).begin({'parent':'publication-fixture', 'purpose':'final', 'ordinal':1},
                                  'concurrent-fact')
        argv = ['timeout', '10s', sys.executable, '-B', __file__, 'produce', str(path),
                'exit' if kind == 'crash' else 'continue']
        uptime = subprocess.check_output(['uptime'], text=True).strip()
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        self.assertEqual(child.stdout.readline().strip(), 'linked')
        if kind == 'crash':
            self.assertEqual(child.wait(timeout=3), 99)
            timer = None
        else:
            def release():
                child.stdin.write('continue\n')
                child.stdin.flush()
            timer = threading.Timer(.05, release)
            timer.start()
        error, result = None, None
        try:
            with Target(path) as target, target.locked():
                journal = Journal(target)
                if kind == 'scan':
                    result = journal.scan_facts('observations', digest(b'concurrent-fact'))
                else:
                    result = journal.accounting()
        except Exception as caught:
            error = caught
        finally:
            if timer is not None:
                timer.join()
        stdout, stderr = child.communicate(timeout=3)
        (root/'result.json').write_text(json.dumps(dict(argv=argv, error=repr(error), result=result,
            producer_exit=child.returncode, stdout=stdout, stderr=stderr, uptime_before=uptime,
            uptime_after=subprocess.check_output(['uptime'], text=True).strip()), indent=2))
        if kind == 'crash':
            self.assertIsInstance(error, RuntimeError)
            self.assertTrue(list(path.parent.glob('.ida-cli-txn-*/observations/*/*.json.new')),
                            'crashed exact pending evidence must remain')
        else:
            self.assertEqual(child.returncode, 0, stderr)
            self.assertIsNone(error, 'live publication must finish before a consistent namespace read')
            self.assertEqual(len(result) if kind == 'scan' else result['routine_files'], 1)
        self.assertEqual(path.read_bytes(), b'private unchanged payload')


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'produce':
        producer(Path(sys.argv[2]), sys.argv[3])
    else:
        unittest.main(verbosity=2)
