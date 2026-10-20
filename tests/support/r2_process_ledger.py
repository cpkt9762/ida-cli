"""Test-only subprocess telemetry; no SDK outcome or protocol substitution."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
import uuid
import threading
import atexit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from process_identity import identity


def install():
    ledger_path = os.environ.get('R2_LEDGER')
    if not ledger_path or getattr(subprocess.Popen, '_r2_ledger', False):
        return
    original = subprocess.Popen
    waiters=[]

    def record(value):
        data = (json.dumps(dict(value, parent=os.getpid(), observed_unix_ns=time.time_ns(),
                                case=os.environ.get('R2_CASE_ROOT')))+'\n').encode()
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
            # Observe a retained launcher without consuming its owner's wait.
            # Existing callers may themselves use WNOWAIT before Popen.wait.
            def collect():
                while True:
                    try:observed=os.waitid(os.P_PID,self.pid,os.WEXITED | os.WNOWAIT)
                    except InterruptedError:continue
                    except ChildProcessError:return  # Another actual waiter won; absence is not evidence.
                    if observed is not None and observed.si_pid==self.pid:
                        code=observed.si_status if observed.si_code==os.CLD_EXITED else None
                        signal=observed.si_status if observed.si_code in (os.CLD_KILLED,os.CLD_DUMPED) else None
                        if code is not None or signal is not None:
                            record({'kind':'terminal','intent':self._r2_intent,'pid':self.pid,
                                    'method':'os.waitid.P_PID.WEXITED.WNOWAIT',
                                    'raw_si_code':observed.si_code,'raw_si_status':observed.si_status,
                                    'exit_code':code,'signal':signal,'success':code==0})
                    return
            waiter=threading.Thread(target=collect,daemon=True)
            waiters.append(waiter)
            waiter.start()

        def wait(self, *args, **options):
            result = super().wait(*args, **options)
            if not getattr(self, '_r2_reaped', False):
                record({'kind':'reaped', 'intent':self._r2_intent, 'pid':self.pid, 'exit':result})
                self._r2_reaped = True
            return result

        def _handle_exitstatus(self, status, *args, **options):
            # CPython's _cleanup/__del__ may bypass public poll(). This hook
            # receives an actual waitpid status, unlike _internal_poll's
            # synthetic ECHILD/deadstate returns. Merely calling poll never
            # supplies terminal evidence.
            super()._handle_exitstatus(status, *args, **options)
            if not getattr(self, '_r2_polled', False):
                record({'kind':'polled_exit', 'intent':self._r2_intent,
                        'pid':self.pid, 'exit':self.returncode, 'raw_wait_status':status,
                        'method':'Popen._handle_exitstatus'})
                self._r2_polled = True

    subprocess.Popen = Recorded
    # Test-only bind journal. Even os._exit fault cases leave the creator's
    # native identity and actual inode; a parent may clean only after wait.
    import socket
    import stat
    original_bind = socket.socket.bind
    def bind(endpoint, address):
        result = original_bind(endpoint, address)
        if endpoint.family == socket.AF_UNIX and isinstance(address, str) and address.startswith('/'):
            path = Path(address)
            info = path.lstat()
            captured = identity(os.getpid())
            if not stat.S_ISSOCK(info.st_mode) or captured is None:
                raise RuntimeError('test socket bind identity unavailable')
            row = {'kind':'socket_bound','path':address,'dev':info.st_dev,'ino':info.st_ino,
                   'pid':os.getpid(),'identity':captured}
            record(row)
            root = os.environ.get('N3_ENV_ROOT')
            if root:
                with (Path(root)/'sockets.jsonl').open('a') as output:
                    output.write(json.dumps(row)+'\n');output.flush();os.fsync(output.fileno())
        return result
    socket.socket.bind = bind
    def finish_observers():
        deadline=time.monotonic()+1
        for waiter in waiters:
            waiter.join(max(0,deadline-time.monotonic()))
    atexit.register(finish_observers)


if __name__ == '__main__':
    install()
    script = sys.argv.pop(1)
    sys.argv[0] = script
    runpy.run_path(script, run_name='__main__')
