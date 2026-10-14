"""Disposable, process-group confined sbx/idat replacement; no IDA import."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys

mode, socket_path, marker = sys.argv[1:4]
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
