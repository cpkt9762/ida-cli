"""Disposable, process-group confined sbx/idat replacement; no IDA import."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys

from r2_process_ledger import install
install()

mode, socket_path, marker = sys.argv[1:4]
if mode == 'escaped_pipe':
    if os.environ.get('N4_F2_STARTUP_DELAY'):
        import time
        time.sleep(4)
    control = str(Path(marker).parent / 'escaped.sock')
    script = """import os,socket,sys
with socket.socket(socket.AF_UNIX) as listener:
 listener.bind(sys.argv[1]); listener.listen(2)
 with listener.accept()[0] as ready: ready.sendall(b'R')
 with listener.accept()[0] as release:
  assert release.recv(1)==b'R'
  release.sendall(b'closed\\n')
"""
    escaped = subprocess.Popen([sys.executable, '-c', script, control], start_new_session=True)
    # A regular pipe provides deterministic startup without scanning PIDs.
    import time
    deadline = time.monotonic() + 15
    while not Path(control).exists():
        assert time.monotonic() < deadline
        time.sleep(.001)
    with socket.socket(socket.AF_UNIX) as ready:
        ready.connect(control)
        assert ready.recv(1) == b'R'
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(socket_path)
        connection.sendall((json.dumps({'pid':os.getpid(),'pgid':os.getpgrp(),'child':escaped.pid,'child_pgid':escaped.pid,'kind':'escaped_pipe','directory':str(Path(marker).parent)})+'\n').encode())
        assert connection.recv(1)==b'G'
    sys.exit(0)

child = None
if mode in ('block', 'flood'):
    child = subprocess.Popen([sys.executable, '-c', "import sys,time; from pathlib import Path; print('started',flush=True); time.sleep(2); Path(sys.argv[1]).write_text('late child write'); time.sleep(300)", marker], stdout=subprocess.PIPE)
    assert child.stdout.readline().strip() == b'started'

def stop(_signal, _frame):
    if child is not None:
        child.wait(timeout=2)
    sys.exit(0)

signal.signal(signal.SIGTERM, stop)
with socket.socket(socket.AF_UNIX) as connection:
    connection.connect(socket_path)
    connection.sendall((json.dumps({'pid': os.getpid(), 'pgid': os.getpgrp(), 'child': child.pid if child else None})+'\n').encode())
    if mode == 'success':
        assert connection.recv(1) == b'G'
        Path(marker).write_text('staged result')
    else:
        if mode == 'flood':
            for _ in range(128):
                os.write(1, b'x'*65536)
                os.write(2, b'y'*65536)
            connection.sendall(b'drained\n')
        signal.pause()
