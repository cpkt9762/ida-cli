"""Production installed bridge over private HTTP/IDA inputs, with real helper."""
import json
import os
from pathlib import Path
import runpy
import sys
import threading
import secrets
import socket
from r2_process_ledger import install
install()
from urllib.parse import parse_qs, urlsplit
from ida_nexus._registry import InstanceIdentity, InstanceRegistration, REGISTRY_DIR

from r0_transport import Boundary


def write_evidence_json(path, value):
    """Publish a complete trace before a concurrent Rust reader sees its name."""
    temporary=path.with_name(path.name+'.writing')
    with temporary.open('x') as output:
        json.dump(value,output)
        output.flush()
    os.replace(temporary,path)


root = Path(os.environ['R3A_CASE_ROOT'])
managed = os.environ.get('R3A_MANAGED') == '1'
owner_root = root/'cache/generations/g-fixed' if managed else root
owner_root.mkdir(parents=True, exist_ok=True)
if managed:
    (owner_root/'generation.json').write_text(json.dumps({'version':1,'key':'r3a-fixed'}))
with Boundary(owner_root, ('lost-ack' if os.environ.get('R3A_SCENARIO') == 'rf4-uncertain' or os.environ.get('R4_U6_FILE_JOB') else os.environ.get('R3A_SCENARIO', 'healthy'))) as boundary:
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
    if scenario == 'healthy':
        # The fixture writes HTTP headers and body separately. Nagle plus a
        # delayed ACK adds artificial per-RPC stalls to the fixed 128 epochs;
        # use ordinary low-latency loopback framing without changing any input,
        # response, owner barrier or product deadline.
        handler.disable_nagle_algorithm = True
    if scenario == 'r9-restore-held':
        boundary.release_owner()
        boundary.path.with_suffix('.id0').write_bytes(bytes(18)+b'\x01B-tree v2original component')
    r3b_failures = int(os.environ.get('R3B_R9_FAILURES', '0'))
    if scenario in ('r9-gui','gui-reference'):
        boundary.release_owner()
        boundary.registration = InstanceRegistration(REGISTRY_DIR,
            InstanceIdentity(str(boundary.path),str(boundary.path),'gui',False),token=secrets.token_hex(24))
        boundary.instance = boundary.registration.publish(boundary.server.server_port)
        boundary.released = False
    attach_count = [0]
    r9 = scenario.startswith('r9-')
    if r9:
        import ida_netnode
        ida_netnode.netnode.exist = staticmethod(lambda _:False)
    def get_input(request):
        query = parse_qs(urlsplit(request.path).query)
        if 'sse' in query:
            if scenario.startswith('post-exit-'):
                attach_count[0] += 1
                boundary.requests.append({'endpoint':'attach_attempt', 'ordinal':attach_count[0]})
                if attach_count[0] <= 2 or scenario == 'post-exit-final503':
                    request.reply({'error':'controlled closing owner'}, 503)
                    if attach_count[0] == 2:
                        # Only external registry/lifetime inputs change. The
                        # production SDK must consume the real old public True
                        # before its third resolver/attach can reach this owner.
                        boundary.release_owner()
                        boundary.registration = InstanceRegistration(REGISTRY_DIR,
                            InstanceIdentity(str(boundary.path), str(boundary.path), 'idalib', True),
                            token=secrets.token_hex(24))
                        boundary.instance = boundary.registration.publish(boundary.server.server_port)
                        boundary.released = False
                    return
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
    close_barrier_used = [False]
    save_refusals = [0]
    def post_input(request):
        if request.path == '/execute_python' and (root/'save-refuse').exists():
            import ida_loader
            def refuse_save(*_args, **_options):
                save_refusals[0] += 1
                write_evidence_json(root/'save-refusals.json',{'calls':save_refusals[0]})
                raise PermissionError('saving refused: explicit native save rejected')
            ida_loader.save_database = refuse_save
        if (request.path == '/execute_python' and (root/'r6-close.arm').exists()
                and not close_barrier_used[0]):
            close_barrier_used[0] = True
            from r0_transport import barrier
            barrier(root, 'r6-close')
        if (request.path == '/execute_python' and scenario == 'r9-restore-held'
                and not (root/'recovered-product').exists()):
            boundary.path.write_bytes(b'failed recovered packed')
            boundary.path.with_suffix('.id0').write_bytes(bytes(18)+b'\x01B-tree v2failed component')
            (root/'recovered-product').touch()
        if request.path == '/execute_python' and (root/'poison-root').exists():
            import ida_netnode
            ida_netnode.netnode.exist = staticmethod(lambda _:False)
            if scenario in ('r2-protection-failed', 'rf4-notsent'):
                import ida_loader
                def deny_flags(_flag):
                    raise OSError('private IDA close protection flag failure')
                ida_loader.set_database_flag = deny_flags
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
        if scenario == 'healthy' and not (root/'http-framing.json').exists():
            (root/'http-framing.json').write_text(json.dumps({
                'protocol':handler.protocol_version,
                'tcp_nodelay_raw':request.connection.getsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY),
                'tcp_nodelay_enabled':bool(request.connection.getsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY)),
                'split_headers_body':True}))
        failed_releases = sum(r['endpoint'] == '/release_lease' for r in boundary.requests)
        if (request.path == '/release_lease' and r9 and scenario not in ('r9-gui', 'r9-restore-held')
                and (not (root/'r9-successor').exists() or (r3b_failures and failed_releases <= r3b_failures))):
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
            if not (r3b_failures == 3 and failed_releases == 3):
                boundary.registration = InstanceRegistration(REGISTRY_DIR,
                    InstanceIdentity(str(boundary.path), str(boundary.path), 'idalib', True), token=secrets.token_hex(24))
                boundary.instance = boundary.registration.publish(boundary.server.server_port)
                boundary.released = False
                if failed_releases < r3b_failures:
                    import ida_netnode
                    ida_netnode.netnode.exist = staticmethod(lambda _:False)
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
            if scenario == 'post-exit-attach-ack' and (root/'dump-stacks').exists() and not (root/'stacks.log').exists():
                import faulthandler
                with (root/'stacks.log').open('w') as output:
                    faulthandler.dump_traceback(file=output)
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
        if os.environ.get('R6_PUBLICATION')=='1':
            from acquisition import Custodian
            from r0_transport import install_ida_inputs
            admit=Custodian.admit_target
            def publication_input(self,*args,**kwargs):
                result=admit(self,*args,**kwargs)
                if not (root/'publication-native-input').exists():
                    boundary.release_owner()
                    boundary.path=Path(self.target_path)
                    boundary.path.write_bytes(b'packed private publication model')
                    boundary.registration=InstanceRegistration(REGISTRY_DIR,
                        InstanceIdentity(str(boundary.path),str(boundary.path),'idalib',True),token=secrets.token_hex(24))
                    boundary.instance=boundary.registration.publish(boundary.server.server_port)
                    boundary.released=False
                    install_ida_inputs(boundary.path)
                    (root/'publication-native-input').touch()
                return result
            Custodian.admit_target=publication_input
        if scenario == 'observe-handoff-failed':
            from acquisition import Custodian
            original_transfer = Custodian.transact
            failed_transfer = [False]
            def fail_observation_once(self, action, **fields):
                if action == 'observe' and not failed_transfer[0]:
                    failed_transfer[0] = True
                    (root/'observe-handoff-failed').touch()
                    raise RuntimeError('controlled observation handoff NotSent after helper subscribe')
                return original_transfer(self, action, **fields)
            Custodian.transact = fail_observation_once
        if os.environ.get('R4_FILE_GATE_RELOCATE'):
            from acquisition import Custodian
            from r0_transport import install_ida_inputs
            original_admit=Custodian.admit_target
            def publish_only_after_gate(self,*args,**kwargs):
                result=original_admit(self,*args,**kwargs)
                wanted=Path(os.environ['R4_FILE_GATE_RELOCATE']).resolve()
                if Path(self.target_path)!=wanted:
                    raise AssertionError('device-gate fixture targeted an unexpected canonical path')
                if Path(self.target_path)==wanted and not (root/'r4-device-gate-bound').exists():
                    reference=json.loads((root/'reference.json').read_text())
                    record=self.target.directory.path/reference['recovery_id']/'recovery.json'
                    (root/'r4-device-before-attach.json').write_text(record.read_text())
                    boundary.release_owner()
                    boundary.path=wanted
                    boundary.registration=InstanceRegistration(REGISTRY_DIR,
                        InstanceIdentity(str(wanted),str(wanted),'idalib',True),token=secrets.token_hex(24))
                    boundary.instance=boundary.registration.publish(boundary.server.server_port)
                    boundary.released=False
                    install_ida_inputs(wanted)
                    (root/'r4-device-gate-bound').touch()
                return result
            Custodian.admit_target=publish_only_after_gate
        if scenario == 'r9-restore-held':
            import open_recovery
            from acquisition import Custodian
            from r0_transport import barrier
            if os.environ.get('R4_SNAPSHOT_CONSTRUCTOR_FAILURE'):
                def fail_snapshot_copy(self,*args,**kwargs):
                    if os.environ['R4_SNAPSHOT_CONSTRUCTOR_FAILURE']=='changed-source':
                        foreign=self.target.parent/'foreign-component'
                        foreign.write_bytes(b'unknown component before SDK')
                        foreign.chmod(0o600)
                    if os.environ['R4_SNAPSHOT_CONSTRUCTOR_FAILURE']=='saved-component':
                        replacement=self.target.parent/'saved-replacement'
                        replacement.write_bytes(b'independent saved component before SDK')
                        replacement.chmod(0o600)
                        os.replace(replacement,self.target)
                    (root/'snapshot-constructor-failed.json').write_text(json.dumps({'path':str(self.path)}))
                    raise OSError('controlled snapshot constructor copy failure before SDK entry')
                open_recovery.Snapshot.copy=fail_snapshot_copy
            if os.environ.get('R4_FILE_JOB_FAULT'):
                install_file_fault=runpy.run_path(str(Path(__file__).with_name('r4_file_job_faults.py')))['install']
                install_file_fault('source')
            original_transact = Custodian.transact
            def restore_transactions(self, action, **fields):
                try:
                    result = original_transact(self, action, **fields)
                except Exception as exc:
                    result = {'error':str(exc)}
                    raise
                finally:
                    with (root/'restore-transactions.jsonl').open('a') as log:
                        log.write(json.dumps({'action':action,'result':result})+'\n')
                return result
            Custodian.transact = restore_transactions
            original_advance = Custodian.advance_restore
            def deferred_restore(self):
                barrier(root, 'restore', seconds=8)
                if (os.environ.get('R4_U6_FILE_JOB') or os.environ.get('R4_RESUME_RETAINED_FILE')) and (root/'r4-gate.request').exists() and self.recovery_snapshot:
                    from target_coordination import Target
                    from target_journal import Journal
                    with Target(self.target_path) as target,target.locked(nb=True):
                        target.file_job_prepare=self.prepare_file_job
                        Journal(target).gate()
                    (root/'r4-gate.done').touch()
                result=original_advance(self)
                if os.environ.get('R4_U6_FILE_JOB') and self.recovery_blocked:
                    (root/'r4-file-blocked').write_text(str(self.recovery_error))
                return result
            Custodian.advance_restore = deferred_restore
            original_snapshot = open_recovery.Snapshot.__init__
            def snapshot_before_external_owner(self, *args, **kwargs):
                original_snapshot(self, *args, **kwargs)
                boundary.registration = InstanceRegistration(REGISTRY_DIR,
                    InstanceIdentity(str(boundary.path),str(boundary.path),'idalib',True),token=secrets.token_hex(24))
                boundary.instance = boundary.registration.publish(boundary.server.server_port)
                boundary.released = False
                (root/'snapshot-ready').write_text(str(self.path))
            open_recovery.Snapshot.__init__ = snapshot_before_external_owner
        if scenario.startswith('post-exit-') or scenario == 'attach-eof':
            from acquisition import Custodian
            original_stage = Custodian.stage
            stage_lock = threading.Lock()
            def public_stage(self, stage, value):
                # Public observer telemetry only; never substitutes a resolver,
                # result, proof, SDK object or production admission decision.
                if scenario == 'post-exit-reap-before-subscribe' and stage == 'Resolved' and not (root/'resolved-reaped.json').exists():
                    # The SDK has already returned this real public instance,
                    # but no helper/backup subscription has been signed yet.
                    assert self.subscription is None and not self.originals
                    held_record=value.record_id
                    boundary.release_owner()
                    from ida_nexus import wait_database_released
                    assert boundary.registration.registry_path is None
                    assert wait_database_released(value,timeout=0) is True
                    write_evidence_json(root/'resolved-reaped.json',{
                        'record_id':held_record,'helper_signed':False,
                        'public_original_held':True,'native_lifetime_released':True})
                    boundary.registration=InstanceRegistration(REGISTRY_DIR,
                        InstanceIdentity(str(boundary.path),str(boundary.path),'idalib',True),token=secrets.token_hex(24))
                    boundary.instance=boundary.registration.publish(boundary.server.server_port)
                    boundary.released=False
                if scenario == 'post-exit-attach-ack' and self.post_exit_resolve_used and stage == 'AttachMayBeSent':
                    import time
                    # Enter the production stage with a small positive budget;
                    # the actual failure barrier is the later helper ACK.
                    while self.deadline-time.monotonic() > .4:
                        threading.Event().wait(min(.01, self.deadline-time.monotonic()-.4))
                    self._r2_attach_entry = time.monotonic()
                    self._r2_attach_instance = value
                result = original_stage(self, stage, value)
                if scenario == 'post-exit-deadline' and self.post_exit_resolve_used and stage == 'Resolved':
                    import time
                    from r0_transport import barrier
                    (root/'deadline-stage.json').write_text(json.dumps({
                        'remaining':self.deadline-time.monotonic(), 'consumed':self.post_exit_resolve_used,
                        'owner':self.owner, 'watches':list(self.observations), 'launches':list(self.launches),
                        'strong_instances':len(self.originals), 'signed':self.subscription is not None}))
                    barrier(root, 'deadline', seconds=15)
                with stage_lock, (root/'public-stages.jsonl').open('a') as log:
                    log.write(json.dumps({'stage':stage, 'owner':getattr(value,'instance_id',None)})+'\n')
                    log.flush()
                return result
            Custodian.stage = public_stage
        if scenario == 'post-exit-attach-ack':
            from acquisition import Custodian
            from r0_transport import barrier
            import time
            actual_helper_request = Custodian.helper_request
            def final_attach_ack(self, value):
                reply = actual_helper_request(self, value)
                if self.post_exit_resolve_used and value['kind'] in ('attach_attempt', 'no_attach'):
                    with (root/'attach-facts.jsonl').open('a') as log:
                        log.write(json.dumps({'kind':value['kind'], 'watch':value['watch'],
                            'reply':reply})+'\n')
                if (self.post_exit_resolve_used and value['kind'] == 'attach_attempt'
                        and value['attempt']['state'] == 'may_send'):
                    self._r2_attach_watch = value['watch']
                    write_evidence_json(root/'attach-ack-stage.json',{
                        'deadline':self.deadline, 'entry_at':self._r2_attach_entry,
                        'signed_at':time.monotonic(), 'remaining':self.deadline-time.monotonic(),
                        'consumed':self.post_exit_resolve_used, 'watch':value['watch'],
                        'signed':reply['receipt']['record']['attempt'],
                        'strong_instances':len(self.originals), 'launches':list(self.launches)})
                    barrier(root, 'attach-ack', seconds=3)
                    write_evidence_json(root/'attach-ack-return.json',{
                        'returned_at':time.monotonic(), 'deadline':self.deadline})
                return reply
            Custodian.helper_request = final_attach_ack
            actual_obtain = Custodian.obtain
            def record_attach_outcome(self, *args, **kwargs):
                try:
                    return actual_obtain(self, *args, **kwargs)
                finally:
                    if self.outcome is not None:
                        value = self.outcome
                        write_evidence_json(root/'attach-outcome.json',{
                            'failure_kind':value['failure_kind'], 'handle':value['handle'] is not None,
                            'cause':None if value['cause'] is None else type(value['cause']).__name__,
                            'consumed':self.post_exit_resolve_used,
                            'instance_preserved':value['instance'] is getattr(self,'_r2_attach_instance',None),
                            'prior_attempts':[{'attempt':a['attempt'],'failure_kind':a['failure_kind']}
                                for a in value.get('prior_outcome',{}).get('attempts',[])],
                            'attempts':[{'attempt':a['attempt'],'failure_kind':a['failure_kind'],
                                'handle':a['handle'] is not None} for a in value['attempts']],
                            'launches':[stage for stage,_ in value['launches']]})
            Custodian.obtain = record_attach_outcome
        if os.environ.get('R2_BOOT_SOURCE_INPUT'):
            import target_journal
            import origin
            observed_scope = runpy.run_path(str(Path(__file__).with_name('r2_boot_writer.py')))['observed_scope']
            native_scope = target_journal.creation_scope
            target_journal.creation_scope = lambda path, incarnation, **options: observed_scope(native_scope, path, incarnation, **options)
            origin.creation_scope=target_journal.creation_scope
        if scenario == 'r2-save-refused-notsent':
            from acquisition import Custodian
            real_transaction = Custodian.transact
            def receipt_failure(self, action, **fields):
                result = real_transaction(self, action, **fields)
                if action == 'release_observation':
                    raise RuntimeError('controlled local failure after durable saving-refused receipt; detach not called')
                return result
            Custodian.transact = receipt_failure
        if scenario.startswith('rf4-') or scenario == 'u6-late-ack':
            from r0_transport import barrier
            send_terminal = runtime['Channel'].send
            def terminal_barrier(self, message):
                if (message.get('event') in ('not_sent', 'uncertain', 'released', 'failed')
                        and message.get('attempt', {}).get('target', {}).get('kind') == 'release'):
                    barrier(root, 'terminal', seconds=8)
                return send_terminal(self, message)
            runtime['Channel'].send = terminal_barrier
        if r9 and scenario != 'r9-gui':
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
        if scenario == 'r9-expired-after-cleanup':
            import acquisition as acquisition_module
            from types import SimpleNamespace
            actual_next = acquisition_module.Custodian.next_retry
            def expired_next(self):
                original = acquisition_module.time
                (root/'r9-expiry.json').write_text(json.dumps({'original_deadline':self.deadline,
                    'acquisition':self.acquisition,'cleanup_outcome':self.release_outcome}))
                acquisition_module.time = SimpleNamespace(monotonic=lambda:self.deadline)
                try:
                    return actual_next(self)
                finally:
                    acquisition_module.time = original
            acquisition_module.Custodian.next_retry = expired_next
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
