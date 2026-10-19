"""Test-only subprocess telemetry; no SDK outcome or protocol substitution."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from process_identity import identity


def install():
    ledger_path = os.environ.get('R2_LEDGER')
    if not ledger_path or getattr(subprocess.Popen, '_r2_ledger', False):
        return
    original = subprocess.Popen

    def record(value):
        data = (json.dumps(dict(value, parent=os.getpid(), observed_unix_ns=time.time_ns()))+'\n').encode()
        descriptor = os.open(ledger_path, os.O_WRONLY | os.O_APPEND)
        try:
            if os.write(descriptor, data) != len(data):
                raise OSError('partial process ledger write')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    class Recorded(original):
        _r2_ledger = True

        def __init__(self, args, *positional, **options):
            self._r2_intent = 'python-'+uuid.uuid4().hex
            record({'kind':'intent', 'intent':self._r2_intent,
                    'program':str(args[0] if isinstance(args, (list, tuple)) else args)})
            super().__init__(args, *positional, **options)
            captured = identity(self.pid)
            record({'kind':'started', 'intent':self._r2_intent, 'pid':self.pid,
                    'identity':captured, 'already_exited':self.poll() is not None})

        def wait(self, *args, **options):
            result = super().wait(*args, **options)
            if not getattr(self, '_r2_reaped', False):
                record({'kind':'reaped', 'intent':self._r2_intent, 'pid':self.pid, 'exit':result})
                self._r2_reaped = True
            return result

        def poll(self, *args, **options):
            result = super().poll(*args, **options)
            if result is not None and not getattr(self, '_r2_polled', False):
                record({'kind':'polled_exit', 'intent':self._r2_intent,
                        'pid':self.pid, 'exit':result, 'method':'Popen.poll'})
                self._r2_polled = True
            return result

    subprocess.Popen = Recorded


if __name__ == '__main__':
    install()
    script = sys.argv.pop(1)
    sys.argv[0] = script
    runpy.run_path(script, run_name='__main__')
