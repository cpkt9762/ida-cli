"""Physical final acquisition custody; N1 grants every preparation RPC."""
from contextlib import contextmanager
import copy
import threading
import time
import uuid

from owner_identity import owner_key, state_identity
from custody_process_identity import capture
from proof_helper import request
from target_coordination import Target, canonical, digest
from target_journal import Journal, OwnerDraining, ObservationPending


class Custodian:
    def __init__(self, bridge, attempt, command, deadline, track):
        self.bridge, self.attempt, self.command = bridge, attempt, command
        self.deadline, self.track = deadline, track
        self.acquisition = {'parent':command['identity'], 'purpose':'final', 'ordinal':1}
        self.handle = self.lease = None
        self.decision = None
        self.watch = uuid.uuid4().hex
        self.subscription = self.owner = None
        self.target = self.target_guard = None
        self.originals = {}
        self.observations = {}
        self.attach_ordinal = 0
        self.launches = {}
        self.release_event = threading.Event()
        self.release_outcome = None
        self.running = True
        self.outcome = None
        self.attach_failures = []
        self.post_exit_resolve_used = False
        if not bridge.helper_ready.wait(max(0, min(2, deadline-time.monotonic()))):
            raise RuntimeError('ObservationFailed: mandatory helper handshake unavailable')
        self.helper = bridge.helper_configuration
        if self.helper['state_root'] != state_identity():
            raise RuntimeError('ProtocolMismatch: bridge/helper state root')
        self.helper_request({'kind':'reserve_parent', 'parent':self.acquisition['parent']})

    def helper_request(self, value):
        return request(self.helper['endpoint'], self.helper['incarnation'], value)

    def transact(self, action, *, _deadline=None, **fields):
        nonce = uuid.uuid4().hex
        pending = (threading.Event(), [])
        with self.bridge.lock:
            self.bridge.custody_requests[nonce] = pending
        try:
            message = dict(event='release_observation' if action == 'release_observation' else 'custody_request',
                nonce=nonce, action=action, **fields)
            expires = min(time.monotonic() + 2, _deadline) if _deadline is not None else time.monotonic() + 2
            while True:
                self.bridge.control.send(message)
                if pending[0].wait(min(.25, max(0, expires-time.monotonic()))):
                    break
                if time.monotonic() >= expires or self.bridge.stopped.is_set():
                    raise TimeoutError('custody IPC acknowledgement missing; exact responsibility retained')
            reply = pending[1][0]
            self.bridge.control.send({'event':'custody_receipt', 'nonce':nonce})
            if not reply['ok']:
                raise RuntimeError(reply.get('error', 'custody request rejected'))
            return reply
        finally:
            with self.bridge.lock:
                self.bridge.custody_requests.pop(nonce, None)

    @contextmanager
    def gate(self, target):
        self.target = Target(target)
        try:
            self.target_path, self.coord_key = str(self.target.target), self.target.key
            self.admit_target()
            yield self.target
        finally:
            self.unlock_target()
            self.target.close()
            self.target = None

    def admit_target(self, acquisition=None):
        while True:
            self.target_guard = self.target.locked(deadline=self.deadline)
            self.target_guard.__enter__()
            self.target.business_admission()
            try:
                Journal(self.target).gate(self.helper['state_root'], acquisition)
                return
            except (OwnerDraining, ObservationPending) as exc:
                self.unlock_target()
                remaining = self.deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('original open budget exhausted; exact pending observation retained') from exc
                self.bridge.stopped.wait(min(.02, remaining))

    def unlock_target(self):
        if self.target_guard is not None:
            self.target_guard.__exit__(None, None, None)
            self.target_guard = None

    def signed_stage(self, action, **fields):
        # The durable helper/target facts protect this stage while earlier
        # control messages finish their own target writes. Never wait for an
        # IPC receipt while holding the lock those messages need.
        self.unlock_target()
        reply = self.transact(action, _deadline=self.deadline, **fields)
        self.admit_target(self.acquisition)
        return reply

    @contextmanager
    def file_gate(self):
        # Compatibility for the existing r9 snapshot path. Never hold EX while
        # waiting for owner lifetime or an analysis/cleanup RPC.
        if self.target_guard is not None:
            yield
        else:
            with self.target.locked(deadline=self.deadline):
                yield

    def stage(self, stage, value):
        if stage == 'BeforeResolve' and value['reconnect']:
            unknown = next((a for a in self.attach_failures
                            if a['failure_kind'] not in ('not_sent', 'lease_absent')), None)
            if unknown is not None:
                # The SDK's legacy retry is conditional on the public typed
                # attach fact. Refuse before the second resolver side effect.
                raise unknown['cause']
        if stage in ('Resolved', 'ReconnectResolved', 'BeforeAttach'):
            if stage == 'BeforeAttach':
                self.attach_ordinal += 1
            owner = owner_key(value)
            if self.owner == owner and self.subscription is not None:
                return
            watch = uuid.uuid4().hex
            # No backup object is allocated until target/byte admission succeeds.
            epoch = Journal(self.target).begin(self.acquisition, watch, owner=owner)
            key = digest(owner)
            subscription = dict(kind='subscribe', watch=watch, subscription_epoch=epoch,
                target=str(self.target.target), coord_key=self.target.key,
                owner=owner, acquisition=self.acquisition)
            helper_started = False
            try:
                self.bridge.backup_sources.subscribe(value, owner, watch)
                self.originals.setdefault(key, value)
                binding = self.bridge.backup_sources.bind(subscription)
                Journal(self.target).bridge_signed(binding)
                self.owner, self.watch = owner, watch
                self.observations[watch] = {'owner':owner, 'receipt':None, 'attempts':{}}
                helper_started = True
                try:
                    reply = self.helper_request(subscription)
                except Exception:
                    # ACK loss after a signed subscribe is not an absent watch.
                    item = self.helper_request({'kind':'lookup', 'watch':watch})['item']
                    if item is None:
                        proof = self.bridge.backup_sources.released_proof(subscription)
                        if proof is None:
                            helper_started = False
                            raise
                        # Exact original public True is already durable. Give
                        # the helper that proof instead of rediscovering a reap.
                        subscription['proof'] = proof
                    reply = self.helper_request(subscription)
                self.subscription = reply['receipt']
                self.observations[watch]['receipt'] = self.subscription
                Journal(self.target).owner_signed(self.subscription)
            except BaseException:
                if not helper_started:
                    self.bridge.backup_sources.abort_unstarted(owner, watch)
                    if not any(o['owner'] == owner for w,o in self.observations.items() if w != watch):
                        self.originals.pop(key, None)
                    self.observations.pop(watch, None)
                    Journal(self.target).abort_unstarted(watch)
                # Unknown helper delivery retains its exact watch and source.
                raise
            # Transfer observation responsibility before any HTTP attach can
            # be sent. Later attempts add obligations; they never erase this
            # watch because another attempt acquired or was rejected.
            # The helper and target already own the signed observation. Let
            # earlier proof consumers take EX while Rust signs this transfer;
            # otherwise their control ACK can block the same control stream
            # that this observer is waiting on. Recheck target admission under
            # EX before returning to the SDK's attach boundary.
            self.unlock_target()
            self.transact('observe', _deadline=self.deadline,
                acquisition=self.acquisition, watch=self.watch,
                owner=owner, receipt=self.subscription, target=self.target_path,
                coord_key=self.coord_key)
            self.admit_target(self.acquisition)
        elif stage == 'AttachMayBeSent':
            self.attach_fact(value, self.attach_ordinal, 'may_send')
        elif stage == 'AttachFailed':
            self.attach_failures.append(value)
            state = 'exact_handle' if value['handle'] is not None else value['failure_kind']
            self.attach_fact(value['instance'], self.attach_ordinal, state)
        elif stage == 'LaunchIntent':
            launch = {k:value[k] for k in ('suffix', 'source', 'target', 'backend')}
            watch = uuid.uuid4().hex
            epoch = Journal(self.target).begin(self.acquisition, watch, launch=launch)
            receipt = self.helper_request({'kind':'launch_intent', 'watch':watch, 'subscription_epoch':epoch,
                'target':str(self.target.target), 'coord_key':self.target.key,
                'launch':launch, 'acquisition':self.acquisition})['receipt']
            self.launches[launch['suffix']] = {'watch':watch, 'launch':launch, 'receipt':receipt}
            Journal(self.target).launch_signed(receipt)
            # Rust signs custody of this durable launch before the observer
            # returns to the SDK's Popen call. A lost ACK retains the intent.
            self.signed_stage('launch', acquisition=self.acquisition, watch=watch,
                launch=launch, receipt=receipt, target=self.target_path, coord_key=self.coord_key)
        elif stage == 'Spawned':
            item = self.launches[value['suffix']]
            item['os_identity'] = capture(value['pid'])
            item['spawned'] = self.helper_request({'kind':'spawned', 'watch':item['watch'],
                'launch':item['launch'], 'pid':value['pid'], 'os_identity':item['os_identity']})['receipt']
            Journal(self.target).launch_signed(item['spawned'])
            self.signed_stage('spawned', acquisition=self.acquisition, watch=item['watch'],
                launch=item['launch'], receipt=item['spawned'], target=self.target_path,
                coord_key=self.coord_key, os_identity=item['os_identity'])

    def attach_fact(self, instance, ordinal, state):
        owner = owner_key(instance)
        observations = [(watch,item) for watch,item in self.observations.items() if item['owner'] == owner]
        if len(observations) != 1 or ordinal < 1:
            raise RuntimeError('ProtocolMismatch: attach attempt lacks exact observation')
        watch, item = observations[0]
        attempt = {'attempt':ordinal, 'owner':owner, 'state':state}
        if item['attempts'].get(ordinal) == attempt:
            # The SDK outcome repeats facts already signed at its public stage.
            # In particular, old proof-closed watches may already be retired.
            return
        reply = self.helper_request({'kind':'attach_attempt', 'watch':watch, 'attempt':attempt})
        item['attempts'][ordinal] = attempt
        return reply

    def reconcile_outcome(self, outcome):
        # The SDK ledger is authoritative even when a stage callback failed.
        # Keep every unknown attempt; a later success never clears an older one.
        for attempt in outcome['attempts']:
            state = 'exact_handle' if attempt['handle'] is not None else attempt['failure_kind']
            self.attach_fact(attempt['instance'], attempt['attempt'], state)
        for watch,item in self.observations.items():
            if item.get('proof'):
                continue
            if any(a['state'] not in ('not_sent', 'lease_absent') for a in item['attempts'].values()):
                continue
            status = self.helper_request({'kind':'lookup', 'watch':watch})['item']
            if status is not None and status.get('proof'):
                continue
            if not item['attempts']:
                self.attach_fact(self.originals[digest(item['owner'])], 1, 'not_sent')
            result = self.bridge.backup_sources.no_attach(item['owner'], watch,
                lambda:self.helper_request({'kind':'no_attach', 'watch':watch})['consumer'])
            if result is None:
                continue
            closed, bridge = result
            with self.file_gate():
                Journal(self.target).no_attach({'watch':watch, 'consumer':closed, 'bridge_consumer':bridge})
            # Authority already wrote the terminal before releasing EX. Rust's
            # next proof tick can now finish it without waiting on this writer.
            self.unlock_target()
            self.transact('no_attach', acquisition=self.acquisition, watch=watch,
                owner=item['owner'], receipt=item['receipt'], consumer=closed,
                bridge_consumer=bridge, target=self.target_path, coord_key=self.coord_key)

    def obtained(self, handle, context):
        if self.handle is not None:
            if self.handle is not handle:
                raise RuntimeError('ProtocolMismatch: acquisition delivered conflicting handle')
            if self.decision is not None:
                return
        self.handle = handle
        with self.bridge.lock:
            already_tracked = any(held is handle for _, held in self.bridge.handles.values())
        if not already_tracked:
            try:
                self.track(handle, context)
            finally:
                with self.bridge.lock:
                    for lease, held in self.bridge.handles.values():
                        if held is handle:
                            self.lease = lease
                            self.bridge.custodians[lease['lease_id']] = self
        with self.bridge.lock:
            lease = next(lease for lease, held in self.bridge.handles.values() if held is handle)
            self.lease = lease
            self.bridge.custodians[lease['lease_id']] = self
        owner = owner_key(handle.instance)
        if owner != self.owner or self.subscription is None:
            raise RuntimeError('ObservationFailed: acquired owner lacks exact prior subscription')
        Journal(self.target).adopt({'watch':self.watch, 'receipt':self.subscription,
            'owner':owner, 'acquisition':self.acquisition, 'lease':lease})
        self.ack_custody()
        # All execution remains gated by N1. Target EX ends once the exact
        # physical lease and prior helper subscription have reliable custody.
        self.unlock_target()

    def ack_custody(self):
        # adopt() already transferred the exact physical lease durably. The
        # control stream may have an earlier proof write waiting for target EX.
        self.unlock_target()
        self.decision = self.transact('acquired', acquisition=self.acquisition, lease=self.lease,
            owner=self.owner, watch=self.watch, receipt=self.subscription,
            target=self.target_path, coord_key=self.coord_key)['decision']

    def obtain(self, Handle, Options, path, options, context):
        outcome = Handle.open_outcome(path, options=Options(**dict(options,
            acquisition_observer=self.stage)), on_acquired=lambda h:self.obtained(h, context))
        if (outcome['cause'] is not None and outcome['handle'] is None
                and outcome.get('http_status') == 503
                and outcome['attempts'] and not outcome['unresolved_attempts']
                and all(a['failure_kind'] in ('not_sent', 'lease_absent')
                        for a in outcome['attempts'])):
            outcome = self.resolve_after_exit(Handle, Options, path, options, context, outcome)
        handle = outcome.get('handle')
        if handle is not None:
            if self.decision is None:
                self.obtained(handle, context)
            handle.claim_acquired()
        self.outcome = outcome
        self.reconcile_outcome(outcome)
        if outcome.get('cause') is not None:
            raise outcome['cause']
        if handle is None:
            raise RuntimeError('acquisition returned no handle without cause')
        if self.decision['disposition'] != 'prepare':
            raise RuntimeError('open cancelled or expired; acquired lease is cleanup-only')
        return handle

    def resolve_after_exit(self, Handle, Options, path, options, context, previous):
        """One post-exit resolver; the original request deadline never resets."""
        self.unlock_target()
        watches = list(self.observations)
        while True:
            for watch in watches:
                item = self.observations[watch]
                self.bridge.backup_sources.query(dict(watch=watch, owner=item['owner'],
                    target=self.target_path, coord_key=self.coord_key, acquisition=self.acquisition,
                    subscription_epoch=item['receipt']['record']['subscription_epoch']))
            remaining = self.deadline-time.monotonic()
            if remaining <= 0:
                return previous
            decision = self.transact('post_exit_resolve', _deadline=self.deadline,
                acquisition=self.acquisition, watches=watches,
                attempts=[{'attempt':a['attempt'], 'owner':owner_key(a['instance']),
                    'failure_kind':a['failure_kind']} for a in previous['attempts']])
            if decision['ready']:
                self.post_exit_resolve_used = True
                break
            self.bridge.stopped.wait(min(.02, remaining))
        # Rust checks the exact durable proofs and N1 admission before signing
        # consumption. Failure still consumes no new resolver and retains cause.
        if self.deadline <= time.monotonic():
            return previous
        self.target_guard = self.target.locked(deadline=self.deadline)
        self.target_guard.__enter__()
        self.target.business_admission()
        Journal(self.target).gate(self.helper['state_root'])
        remaining = self.deadline-time.monotonic()
        if remaining <= 0:
            return previous
        resolved = Handle.resolve_outcome(path, options=Options(**dict(options,
            startup_timeout=remaining, acquisition_observer=self.stage)))
        if resolved['cause'] is not None:
            resolved['prior_outcome'] = previous
            return resolved
        outcome = Handle.attach_outcome(resolved['instance'], path=path,
            keepalive=options.get('keepalive', 0), idle_timeout=options.get('idle_timeout'),
            recovery=resolved['recovery'], on_stage=self.stage,
            on_acquired=lambda h:self.obtained(h, context))
        offset = len(previous['attempts'])
        outcome['attempts'] = previous['attempts'] + [dict(a, attempt=a['attempt']+offset)
                                                    for a in outcome['attempts']]
        outcome['launches'] = previous['launches'] + resolved['launches']
        outcome['prior_outcome'] = previous
        return outcome

    def obtain_attach(self, Handle, instance, options, context):
        self.stage('Resolved', instance)
        outcome = Handle.attach_outcome(instance, idle_timeout=options.get('idle_timeout'),
            on_acquired=lambda h:self.obtained(h, context), on_stage=self.stage)
        self.outcome = outcome
        handle = outcome.get('handle')
        if handle is not None:
            if self.decision is None:
                self.obtained(handle, context)
            handle.claim_acquired()
        self.reconcile_outcome(outcome)
        if outcome.get('cause') is not None:
            raise outcome['cause']
        if handle is None or self.decision['disposition'] != 'prepare':
            raise RuntimeError('attach custody is cleanup-only or unavailable')
        return handle

    def rpc(self, purpose, call, *, cleanup=False, deadline=None):
        if not self.lease or not self.decision:
            raise RuntimeError('custody not acknowledged; preparation forbidden')
        identity = {'lease':self.lease, 'task_id':self.command['identity'].get('task_id'),
                    'request_id':uuid.uuid4().hex, 'operation_id':uuid.uuid4().hex}
        grant = self.transact('rpc', acquisition=self.acquisition, identity=identity,
            purpose='cleanup' if cleanup else purpose, grant_epoch=self.decision['grant_epoch'])
        attempt = grant['attempt']
        limit = grant['remaining_ms'] / 1000
        deadline = min(time.monotonic() + limit, deadline if deadline is not None else
                       (self.deadline if not cleanup else time.monotonic()+limit))
        operation_id = identity['operation_id']
        with self.bridge.lock:
            self.bridge.executing[operation_id] = {'attempt':attempt, 'handle':self.handle,
                'native_id':operation_id, 'deadline':deadline, 'unknown':False,
                'cancel_requested':False, 'proving':False, 'next':0, 'expired':False}
        try:
            # The public client adds its fixed HTTP allowance; do not hide it
            # inside a caller deadline shorter than that allowance.
            timeout = deadline-time.monotonic()-5
            if timeout <= 0:
                self.bridge.control.send({'event':'not_sent', 'attempt':attempt,
                    'error':{'code':'deadline_expired', 'message':'internal RPC has no HTTP allowance'}})
                raise TimeoutError('internal RPC not sent: insufficient HTTP allowance')
            # A grant reserves authority; it does not mean request bytes were
            # sent. Keep NotSent valid until the final local allowance check.
            self.bridge.control.send({'event':'ack', 'attempt':attempt})
            result = call(operation_id, timeout)
        except Exception as exc:
            from ida_nexus import NexusConnectionError, RemoteError
            if isinstance(exc, RemoteError):
                self.bridge.control.send({'event':'remote_error', 'attempt':attempt,
                    'remote_code':exc.code, 'error':{'code':'operation_failed', 'message':str(exc)}})
            elif timeout > 0:
                # An exception without a typed remote return cannot prove stop.
                self.bridge.mark_unknown(operation_id, attempt)
                self.bridge.control.send({'event':'uncertain', 'attempt':attempt,
                    'error':{'code':'disconnected' if isinstance(exc, NexusConnectionError) else 'operation_failed',
                             'message':type(exc).__name__ + ': ' + str(exc)}})
            raise
        else:
            self.bridge.control.send({'event':'completed', 'attempt':attempt, 'result':result})
            return result
        finally:
            with self.bridge.lock:
                if operation_id not in self.bridge.unknown:
                    self.bridge.executing.pop(operation_id, None)

    def execute(self, purpose, code, *, cleanup=False, deadline=None):
        return self.rpc(purpose, lambda operation_id, timeout:self.handle.execute_python(
            code, timeout=timeout, operation_id=operation_id), cleanup=cleanup, deadline=deadline)

    def fail(self, exc):
        if self.lease:
            if self.decision is None:
                self.ack_custody()
            self.decision = self.transact('failed', attempt=self.attempt, acquisition=self.acquisition, lease=self.lease,
                error={'code':'operation_failed', 'message':type(exc).__name__ + ': ' + str(exc)})['decision']
        else:
            # No watch means no SDK side effect was possible. Existing watches
            # keep their reservation until exact settlement by Rust.
            result = self.helper_request({'kind':'retire_parent', 'parent':self.acquisition['parent']})
            if result['retired'] and not self.observations and not self.launches:
                with self.bridge.lock:
                    self.bridge.acquisitions.pop(self.acquisition['parent']['operation_id'], None)

    def known_no_acquisition(self):
        return (self.handle is None and self.outcome is not None
                and self.outcome['failure_kind'] in ('not_sent', 'lease_absent')
                and not self.outcome['unresolved_attempts'] and not self.launches)

    def cleanup(self):
        self.decision = self.transact('cleanup', acquisition=self.acquisition, lease=self.lease)['decision']

    def release_for_retry(self):
        self.cleanup()
        if not self.release_event.wait(max(0, self.deadline-time.monotonic())):
            raise TimeoutError('initial-open cleanup pending; exact custody retained')
        # The release event records actual public evidence. N1 must also consume
        # the ordered terminal before another ordinal can be reserved.
        self.transact('cleanup_status', acquisition=self.acquisition, lease=self.lease)
        # N1 can learn the original release thread's real public lifetime before
        # the independent producer has published it to the target journal.
        # Consume that durable fact before a new owner reaches check_owner.
        delay = .01
        while True:
            with self.file_gate():
                journal = Journal(self.target)
                journal.recover_public_proofs()
                previous = next((i for i in journal.value['entries'].values() if i['watch'] == self.watch), None)
                if previous is None or previous.get('proof'):
                    break
            self.bridge.backup_sources.query({'watch':self.watch, 'target':self.target_path,
                'coord_key':self.coord_key, 'owner':self.owner, 'acquisition':self.acquisition,
                'subscription_epoch':self.subscription['record']['subscription_epoch']})
            remaining = self.deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('r9 target proof custody pending; prior ordinal retained')
            threading.Event().wait(min(delay, remaining))
            delay = min(.2, delay*2)
        return self.release_outcome

    def next_retry(self):
        # A late retirement must still address the old physical ordinal.
        with self.bridge.lock:
            if self.lease and self.bridge.custodians.get(self.lease['lease_id']) is self:
                previous = copy.copy(self)
                previous.running = False
                self.bridge.custodians[self.lease['lease_id']] = previous
        self.acquisition = self.transact('root_retry', parent=self.command['identity'])['acquisition']
        self.helper_request({'kind':'reserve_parent', 'parent':self.acquisition['parent']})
        self.handle = self.lease = self.decision = self.subscription = self.owner = None
        self.release_event = threading.Event()
        self.originals, self.observations, self.launches = {}, {}, {}
        self.outcome = None
        self.attach_ordinal = 0
        self.release_outcome = None
        self.target_guard = self.target.locked(deadline=self.deadline)
        self.target_guard.__enter__()

    def ready(self, capabilities, wait_analysis, recovery):
        return self.transact('ready', attempt=self.attempt, acquisition=self.acquisition,
            lease=self.lease, capabilities=capabilities, wait_analysis=wait_analysis,
            pid=self.handle.instance.pid, idb_path=canonical(self.handle.instance.idb_path), recovery=recovery)
