"""Production installed bridge over private HTTP/IDA inputs, with real helper."""
import json
import os
from pathlib import Path
import runpy
import sys
import threading
import secrets
import socket
from urllib.parse import parse_qs, urlsplit
from ida_nexus._registry import InstanceIdentity, InstanceRegistration, REGISTRY_DIR

from r0_transport import Boundary

root = Path(os.environ['R3A_CASE_ROOT'])
managed = os.environ.get('R3A_MANAGED') == '1'
owner_root = root/'cache/generations/g-fixed' if managed else root
owner_root.mkdir(parents=True, exist_ok=True)
if managed:
    (owner_root/'generation.json').write_text(json.dumps({'version':1,'key':'r3a-fixed'}))
with Boundary(owner_root, os.environ.get('R3A_SCENARIO', 'healthy')) as boundary:
    if managed:
        from r0_transport import install_ida_inputs
        boundary.release_owner()
        original = boundary.path
        boundary.path = owner_root/'input.i64'
        original.rename(boundary.path)
        boundary.registration = InstanceRegistration(REGISTRY_DIR,
            InstanceIdentity(str(boundary.path), str(boundary.path), 'idalib', True), token=secrets.token_hex(24))
        boundary.instance = boundary.registration.publish(boundary.server.server_port)
        boundary.released = False
        boundary.root = root  # Evidence remains outside collectible payload.
        install_ida_inputs(boundary.path)
    handler = boundary.server.RequestHandlerClass
    original_get = handler.do_GET
    original_post = handler.do_POST
    scenario = os.environ.get('R3A_SCENARIO', 'healthy')
    r9 = scenario.startswith('r9-')
    if r9:
        import ida_netnode
        ida_netnode.netnode.exist = staticmethod(lambda _:False)
    def get_input(request):
        query = parse_qs(urlsplit(request.path).query)
        if 'sse' in query:
            if scenario == 'attach-rejected':
                boundary.requests.append({'endpoint':'lease_rejected', 'http_status':400})
                request.reply({'error':'controlled rejected attach'}, 400)
                return
            if scenario == 'attach-eof':
                with boundary.lock:
                    boundary.leases.add(query['lease_id'][0])
                    boundary.requests.append({'endpoint':'lease_unknown'})
                request.connection.shutdown(socket.SHUT_RDWR)
                request.close_connection = True
                return
            if scenario == 'early-cancel':
                from r0_transport import barrier
                barrier(root, 'attach-response')
        return original_get(request)
    first_preparation = [True]
    def post_input(request):
        if request.path == '/execute_python' and scenario == 'tools-barrier' and first_preparation[0]:
            first_preparation[0] = False
            from r0_transport import barrier
            barrier(root, 'analysis')
        if request.path == '/wait_autoanalysis' and scenario == 'analysis-http-timeout':
            from r0_transport import barrier
            barrier(root, 'analysis-timeout')
        if request.path == '/wait_autoanalysis' and scenario == 'analysis-eof':
            payload = json.loads(request.rfile.read(int(request.headers['Content-Length'])))
            with boundary.lock:
                boundary.requests.append({'endpoint':'/wait_autoanalysis', **payload})
            request.connection.shutdown(socket.SHUT_RDWR)
            request.close_connection = True
            return
        if request.path == '/wait_autoanalysis' and scenario in ('analysis-barrier', 'helper-crash', 'analysis-cancel'):
            from r0_transport import barrier
            barrier(root, 'analysis')
        return original_post(request)
    handler.do_GET, handler.do_POST = get_input, post_input
    original_reply = handler.reply
    def analysis_response(request, payload, status=200):
        if request.path == '/release_lease' and r9 and not (root/'r9-successor').exists():
            boundary.release_owner()
            (root/'r9-public-exit').touch()
            if scenario == 'r9-proof-before-release':
                from r0_transport import barrier
                barrier(root, 'r9-release')
            # Replace only external owner/IDA inputs after real lifetime unlock.
            from r0_transport import install_ida_inputs
            for name in ('_ida_cli_save_guard_v1', '_ida_cli_release_protocol_v1'):
                sys.modules.pop(name, None)
            install_ida_inputs(boundary.path)
            boundary.registration = InstanceRegistration(REGISTRY_DIR,
                InstanceIdentity(str(boundary.path), str(boundary.path), 'idalib', True), token=secrets.token_hex(24))
            boundary.instance = boundary.registration.publish(boundary.server.server_port)
            boundary.released = False
            (root/'release-requested').unlink(missing_ok=True)
            (root/'r9-successor').touch()
        if request.path == '/wait_autoanalysis' and payload.get('ok') is True:
            payload = payload['result']
        return original_reply(request, payload, status)
    handler.reply = analysis_response
    stopped = threading.Event()
    def inputs():
        generation = 0
        gc_serial = 0
        while not stopped.wait(.005):
            if (root / 'owner-release').exists() and not boundary.released:
                boundary.release_owner()
                (root / 'owner-released').touch()
            if (root/'next-owner').exists():
                next_generation = int((root/'next-owner').read_text())
                if next_generation > generation:
                    if not boundary.released or boundary.leases:
                        (root/'input-error').write_text('new owner requested before exact prior cleanup')
                        continue
                    (root/'owner-release').unlink(missing_ok=True)
                    (root/'owner-released').unlink(missing_ok=True)
                    (root/'release-requested').unlink(missing_ok=True)
                    for name in ('_ida_cli_save_guard_v1', '_ida_cli_release_protocol_v1'):
                        sys.modules.pop(name, None)  # Native IDA process input only.
                    boundary.registration = InstanceRegistration(REGISTRY_DIR,
                        InstanceIdentity(str(boundary.path), str(boundary.path), 'idalib', True), token=secrets.token_hex(24))
                    boundary.instance = boundary.registration.publish(boundary.server.server_port)
                    boundary.released = boundary.analysis_failed = False
                    generation = next_generation
                    (root/'owner-generation').write_text(str(generation))
            if (root/'gc-request').exists():
                value = json.loads((root/'gc-request').read_text())
                if value['serial'] > gc_serial:
                    from cache_store import Store
                    result = Store(root/'cache', grace=1, epoch='r3a-fixed', clock=lambda:value['clock']).collect(value['limit'])
                    temporary = root/'gc-result.new'
                    temporary.write_text(json.dumps({'serial':value['serial'],'result':result}))
                    temporary.replace(root/'gc-result')
                    gc_serial = value['serial']
            if (root / 'snapshot-request').exists():
                with boundary.lock:
                    value = {'physical_leases':len(boundary.leases), 'requests':boundary.requests,
                             'analysis_failed':boundary.analysis_failed}
                temporary = root / 'snapshot.json.new'
                temporary.write_text(json.dumps(value))
                temporary.replace(root / 'snapshot.json')
    observer = threading.Thread(target=inputs, daemon=True)
    observer.start()
    installation = Path(os.environ['IDA_CLI_BRIDGE_INSTALLATION'])
    sys.argv = [str(installation / 'bootstrap.py'), 'bridge', *sys.argv[1:]]
    try:
        runtime = vars(runpy.run_path(sys.argv[0], run_name='verified_fixture')['load_entry']())
        if r9:
            from acquisition import Custodian
            original_receive = runtime['Bridge'].receive
            delayed = []
            def retire_input(self, channel, message):
                receipt = message.get('custody_retired')
                if receipt and receipt['acquisition']['ordinal'] == 1:
                    current = next(iter(self.acquisitions.values()), None)
                    ordinal = current.acquisition['ordinal'] if current else None
                    if scenario == 'r9-retire-after' and ordinal == 1:
                        delayed[:] = [message]
                        (root/'r9-retirement-delayed').touch()
                        return
                    original_receive(self, channel, message)
                    (root/'r9-retirement.json').write_text(json.dumps({'current_ordinal':ordinal, 'receipt':receipt}))
                    return
                return original_receive(self, channel, message)
            runtime['Bridge'].receive = retire_input
            send_release = runtime['Channel'].send
            def release_return_input(self, message):
                if message.get('event') == 'released' and not (root/'r9-release-sent').exists():
                    (root/'r9-release-sent').touch()
                    marker = root/('r9-retirement-delayed' if scenario == 'r9-retire-after' else 'r9-retirement.json')
                    deadline = __import__('time').monotonic()+8
                    while not marker.exists():
                        if __import__('time').monotonic() >= deadline:
                            raise TimeoutError('exact prior retirement barrier')
                        threading.Event().wait(.005)
                return send_release(self, message)
            runtime['Channel'].send = release_return_input
            original_obtained = Custodian.obtained
            def obtained_input(self, handle, context):
                original_obtained(self, handle, context)
                if self.acquisition['ordinal'] == 2:
                    (root/'r9-next-ordinal').touch()
                    if delayed:
                        message = delayed.pop()
                        original_receive(self.bridge, None, message)
                        (root/'r9-retirement.json').write_text(json.dumps({'current_ordinal':2, 'receipt':message['custody_retired']}))
                    assert self.bridge.custodians[self.lease['lease_id']] is self
            Custodian.obtained = obtained_input
        if scenario == 'proof-ack-barrier':
            original_receive = runtime['Bridge'].receive
            def proof_acknowledgement_input(self, channel, message):
                if 'owner_proof_custody' in message and not (root/'proof-ack.release').exists():
                    from r0_transport import barrier
                    with self.lock:
                        snapshot = {'proof_path':message['owner_proof_custody']['proof']['path'],
                            'original_instances':sum('instance' in entry for entry in self.backup_sources.items.values()),
                            'custody_originals':sum(len(c.originals) for c in self.acquisitions.values())}
                    (root/'proof-source-snapshot.json').write_text(json.dumps(snapshot))
                    barrier(root,'proof-ack')
                return original_receive(self,channel,message)
            runtime['Bridge'].receive = proof_acknowledgement_input
        if scenario == 'monitor-start':
            original_start = threading.Thread.start
            def monitor_failure(thread):
                if thread.name.startswith('ida-nexus-lease-'):
                    (root/'monitor-start-fault').touch()
                    raise RuntimeError('injected exact lease monitor Thread.start failure')
                return original_start(thread)
            threading.Thread.start = monitor_failure
        if scenario in ('custody-ack-loss', 'custody-ack-loss-cancel', 'callback-ack-error'):
            original_receive = runtime['Bridge'].receive
            injected = [False]
            def acknowledgement_input(self, channel, message):
                if not injected[0] and message.get('decision', {}).get('disposition') == 'prepare':
                    injected[0] = True
                    (root/'custody-ack-fault').write_text(json.dumps(message))
                    if scenario in ('custody-ack-loss', 'custody-ack-loss-cancel'):
                        return
                    message = dict(message, ok=False, error='injected custody callback acknowledgement error')
                return original_receive(self, channel, message)
            runtime['Bridge'].receive = acknowledgement_input
        runtime['main']()
    finally:
        stopped.set()
        observer.join(2)
