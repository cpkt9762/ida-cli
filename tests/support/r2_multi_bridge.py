"""Independent native IDA/HTTP inputs for release scheduling assertions."""
import json
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import threading
import time

from r2_process_ledger import install
install()


def owner_input(root):
    from r0_transport import Boundary, barrier
    with Boundary(root, 'slow-owner') as boundary:
        original = boundary.server.RequestHandlerClass.do_POST
        guard_calls = []
        pending = set()
        def post(request):
            late = os.environ.get('R2_LATE_STOP') == '1'
            if request.path == '/cancel_operation' and late:
                payload = json.loads(request.rfile.read(int(request.headers['Content-Length'])))
                with boundary.lock:
                    boundary.requests.append({'endpoint':request.path, **payload})
                    running = payload['operation_id'] in pending
                request.reply({'ok':True, 'result':{'cancelled':running}})
                return
            if request.path == '/execute_python' and (root/'guard-block').exists():
                guard_calls.append(time.monotonic())
                (root/'guard-calls.json').write_text(json.dumps(guard_calls))
                if late:
                    raw = request.rfile.read(int(request.headers['Content-Length']))
                    operation = json.loads(raw)['operation_id']
                    with boundary.lock:
                        pending.add(operation)
                    stream = request.rfile
                    request.rfile = io.BytesIO(raw)
                    try:
                        barrier(root, 'guard', seconds=45)
                        return original(request)
                    finally:
                        request.rfile = stream
                        with boundary.lock:
                            pending.remove(operation)
                        (root/'guard.stopped').touch()
                barrier(root, 'guard', seconds=20)
            if request.path == '/cancel_operation' and (root/'guard-block').exists():
                # This input remains executing until its actual HTTP response;
                # a cancel acceptance is deliberately not a stop proof.
                payload = json.loads(request.rfile.read(int(request.headers['Content-Length'])))
                boundary.requests.append({'endpoint':request.path, **payload})
                request.reply({'ok':True, 'result':{'cancelled':True}})
                return
            return original(request)
        boundary.server.RequestHandlerClass.do_POST = post
        (root/'ready').touch()
        deadline = time.monotonic()+50
        while not (root/'owner-release').exists():
            if time.monotonic() >= deadline:
                raise TimeoutError('owned input lifetime deadline')
            if (root/'snapshot-request').exists():
                with boundary.lock:
                    data = json.dumps(boundary.requests)
                temporary = root/'requests.new'
                temporary.write_text(data)
                temporary.replace(root/'requests.json')
            threading.Event().wait(.005)


if len(sys.argv) == 3 and sys.argv[1] == '--owner':
    owner_input(Path(sys.argv[2]))
else:
    root = Path(os.environ['R3A_CASE_ROOT'])
    children = []
    try:
        for name in ('a', 'b'):
            directory = root/name
            directory.mkdir(mode=0o700)
            child = subprocess.Popen([sys.executable, '-B', __file__, '--owner', str(directory)])
            children.append((directory, child))
            deadline = time.monotonic()+3
            while not (directory/'ready').exists():
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('native owner input did not become ready')
                threading.Event().wait(.005)
        installation = Path(os.environ['IDA_CLI_BRIDGE_INSTALLATION'])
        sys.argv = [str(installation/'bootstrap.py'), 'bridge', *sys.argv[1:]]
        runpy.run_path(sys.argv[0], run_name='verified_multi_input')['load_entry']().main()
    finally:
        for directory, child in children:
            (directory/'guard.release').touch()
            (directory/'owner-release').touch()
        for directory, child in children:
            if child.wait(timeout=5) != 0:
                raise RuntimeError('owned native input failed; not a passing teardown')
