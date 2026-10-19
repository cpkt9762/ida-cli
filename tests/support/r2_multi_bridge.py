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
from r4_helper_schedule import install as schedule_parent
install()


def owner_input(root):
    from r0_transport import Boundary, barrier
    with Boundary(root, 'slow-owner') as boundary:
        if root.name=='a' and (os.environ.get('R3F1_CASE')=='f3-owner' or os.environ.get('R3B_CASE','').startswith('verification')):
            from ida_nexus._registry import InstanceIdentity, InstanceRegistration, REGISTRY_DIR
            from r0_transport import install_ida_inputs
            import secrets
            import shutil
            boundary.release_owner()
            boundary.path=root.parent/('copy/probe.i64' if os.environ.get('R3F1_CASE')=='f3-owner' else 'vcopy/probe.i64')
            boundary.path.parent.mkdir(mode=0o700,exist_ok=True)
            if not boundary.path.exists():
                shutil.copyfile(root.parent/'source.i64' if os.environ.get('R3F1_CASE')=='f3-owner' else root/'tiny.i64',boundary.path)
            boundary.registration=InstanceRegistration(REGISTRY_DIR,
                InstanceIdentity(str(boundary.path),str(boundary.path),'idalib',True),token=secrets.token_hex(24))
            boundary.instance=boundary.registration.publish(boundary.server.server_port)
            boundary.released=False
            install_ida_inputs(boundary.path)
        if os.environ.get('R3B_CASE', '').startswith('verification'):
            import hashlib
            import ida_nalt
            ida_nalt.retrieve_input_file_sha256 = lambda: hashlib.sha256(b'verification input').digest()
            if os.environ.get('R3B_CASE') == 'verification-failure' and root.name == 'a':
                def refuse_verification():
                    raise RuntimeError('controlled original verification error')
                ida_nalt.retrieve_input_file_sha256 = refuse_verification
        original = boundary.server.RequestHandlerClass.do_POST
        guard_calls = []
        pending = set()
        release_preflights = [0]
        detach_requests = [0]
        sibling = [None]
        actual_reply = boundary.server.RequestHandlerClass.reply
        def reply(request, payload, status=200):
            scenario = os.environ.get('R3B_CASE', '')
            if request.path == '/release_lease' and root.name == 'a' and detach_requests[0] == 1:
                if scenario == 'auxiliary-sibling-join':
                    from ida_nexus import DatabaseHandle
                    sibling[0] = DatabaseHandle.attach(boundary.instance)
                    sibling[0].execute_python('result=True', operation_id='third-party-member', timeout=2)
                elif scenario == 'auxiliary-sibling-leave' and sibling[0] is not None:
                    third = sibling[0]
                    sibling[0] = None
                    closed = third.close_outcome(wait_for_database=False, timeout=2)
                    assert closed['lease_released'],closed
            return actual_reply(request,payload,status)
        boundary.server.RequestHandlerClass.reply = reply
        def post(request):
            scenario = os.environ.get('R3B_CASE', '')
            if scenario in ('auxiliary-sibling-join','auxiliary-sibling-leave') and request.path == '/release_lease':
                detach_requests[0] += 1
            if (scenario in ('auxiliary-uncertain', 'primary-uncertain') and root.name == 'a'
                    and request.path == '/release_lease'):
                detach_requests[0] += 1
                if detach_requests[0] == (1 if scenario == 'primary-uncertain' else 2):
                    import socket
                    payload = json.loads(request.rfile.read(int(request.headers['Content-Length'])))
                    with boundary.lock:
                        boundary.requests.append({'endpoint':request.path, **payload})
                        before = sorted(boundary.leases)
                        boundary.leases.discard(payload['lease_id'])
                        boundary.transitions.append({'edge':'detach','call':'POST /release_lease',
                            'lease':payload['lease_id'],'before':before,'after':sorted(boundary.leases),
                            'ack_kind':'last' if not boundary.leases else 'nonlast','ack_delivery':'lost'})
                    request.connection.shutdown(socket.SHUT_RDWR)
                    request.close_connection = True
                    return
            if scenario in ('auxiliary-fault','late-auxiliary-fault') and request.path == '/execute_python':
                raw = request.rfile.read(int(request.headers['Content-Length']))
                payload = json.loads(raw)
                if '\nresult = _r9_guard.close_status()' in payload['code']:
                    release_preflights[0] += 1
                    if release_preflights[0] == 2:
                        with boundary.lock:
                            boundary.requests.append({'endpoint':request.path, **payload})
                        request.reply({'ok':False,'error':{'code':'execution_error',
                            'message':'controlled auxiliary save protection failure'}})
                        return
                previous = request.rfile
                request.rfile = io.BytesIO(raw)
                try:
                    return original(request)
                finally:
                    request.rfile = previous
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
                    transitions = json.dumps(boundary.transitions)
                temporary = root/'transitions.new'
                temporary.write_text(transitions)
                temporary.replace(root/'transitions.json')
                temporary = root/'requests.new'
                temporary.write_text(data)
                temporary.replace(root/'requests.json')
                if os.environ.get('R3B_CASE'):
                    with boundary.lock:
                        members = sorted(boundary.leases)
                    stage = root/'leases.new'
                    stage.write_text(json.dumps(members))
                    stage.replace(root/'leases.json')
            if (root/'disconnect-primary').exists() and not (root/'disconnected').exists():
                import socket
                if os.environ.get('R3B_CASE') == 'auxiliary-sibling-leave' and root.name == 'a':
                    from ida_nexus import DatabaseHandle
                    sibling[0] = DatabaseHandle.attach(boundary.instance)
                    sibling[0].execute_python('result=True',operation_id='third-party-member',timeout=2)
                with boundary.lock:
                    first = next(iter(boundary.streams.values()))
                    first.shutdown(socket.SHUT_RDWR)
                (root/'disconnected').touch()
            threading.Event().wait(.005)
        if sibling[0] is not None:
            closed = sibling[0].close_outcome(wait_for_database=False,timeout=2)
            assert closed['lease_released'],closed


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
        if os.environ.get('R3B_CASE') == 'verification-init-failure':
            actual_start = threading.Thread.start
            failed = [False]
            def start_thread(thread, *args, **kwargs):
                if thread.name.startswith('ida-nexus-lease-') and not failed[0]:
                    failed[0] = True
                    (root/'monitor-start-failed').touch()
                    raise RuntimeError('controlled monitor thread start failure')
                return actual_start(thread, *args, **kwargs)
            threading.Thread.start = start_thread
        sys.argv = [str(installation/'bootstrap.py'), 'bridge', *sys.argv[1:]]
        runtime = runpy.run_path(sys.argv[0], run_name='verified_multi_input')['load_entry']()
        from acquisition import Custodian
        schedule_parent(Custodian)
        if os.environ.get('R3B_CASE') == 'auxiliary-deadline':
            import owner_release
            import types
            actual_transact=Custodian.transact
            actual_clock=owner_release.time
            expired=[False]
            def deadline_after_guard(self,action,**fields):
                result=actual_transact(self,action,**fields)
                if action=='release_observation' and self.acquisition['purpose']=='auxiliary' and not expired[0]:
                    expired[0]=True
                    assert fields['outcome']['protection']['close_safe'] is True
                    (root/'deadline-after-guard.json').write_text(json.dumps(fields['outcome']))
                    calls=[0]
                    def tick():
                        calls[0]+=1
                        if calls[0]<=2:return fields['_deadline']+3
                        owner_release.time=actual_clock
                        return actual_clock.monotonic()
                    owner_release.time=types.SimpleNamespace(monotonic=tick)
                return result
            Custodian.transact=deadline_after_guard
        if os.environ.get('R3B_CASE') == 'late-auxiliary-fault':
            original_drop = runtime.Bridge.drop_lifetime
            def expose_owner_cleanup_context(self, lease_id):
                with self.lock:
                    custody = self.custodians.get(lease_id)
                    if custody is not None and custody.acquisition['purpose'] == 'final':
                        (root/'late-cleanup-context.json').write_text(json.dumps(
                            [self.identity,lease_id,self.lifetime_path]))
                return original_drop(self,lease_id)
            runtime.Bridge.drop_lifetime = expose_owner_cleanup_context
        if os.environ.get('R3B_CASE') == 'custody-before-callback':
            from acquisition import Custodian
            original_ack = Custodian.ack_custody
            def delay_acquired(self):
                self.unlock_target()
                marker = root/'custody-dropped.json'
                if not marker.exists():
                    temporary=marker.with_suffix('.json.new')
                    temporary.write_text(json.dumps([self.lease]))
                    temporary.replace(marker)
                    until = time.monotonic()+8
                    while not (root/'acquired-resume').exists():
                        if time.monotonic() >= until:
                            raise TimeoutError('controlled callback custody barrier')
                        threading.Event().wait(.005)
                return original_ack(self)
            Custodian.ack_custody = delay_acquired
        if os.environ.get('R3B_CASE') == 'custody-ack-lost':
            original_receive = runtime.Bridge.receive
            def lose_acquired_ack(self, channel, message):
                decision = message.get('decision', {})
                if 'custody_reply' in message and decision.get('disposition') == 'prepare':
                    with self.lock:
                        leases = [lease for lease, _ in self.handles.values()]
                    marker = root/'custody-dropped.json'
                    if not marker.exists():
                        temporary=marker.with_suffix('.json.new')
                        temporary.write_text(json.dumps(leases))
                        temporary.replace(marker)
                    return
                return original_receive(self, channel, message)
            runtime.Bridge.receive = lose_acquired_ack
        runtime.main()
    finally:
        for directory, child in children:
            (directory/'guard.release').touch()
            (directory/'owner-release').touch()
        for directory, child in children:
            if child.wait(timeout=5) != 0:
                raise RuntimeError('owned native input failed; not a passing teardown')
