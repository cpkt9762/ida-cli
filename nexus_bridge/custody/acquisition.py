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


class CleanupPending(TimeoutError):
    """Caller may end while exact accepted cleanup remains independently owned."""


def failure_details(error, depth=0):
    """Preserve typed public errors and explicit exception chaining for callers."""
    source = getattr(error, 'code', None)
    value = {'code':'execution_timeout' if source == 'operation_timeout' else 'operation_failed',
             'message':type(error).__name__ + (f'[{source}]' if source else '') + ': ' + str(error)}
    cause = error.__cause__ or error.__context__
    if cause is not None and cause is not error and depth < 7:
        value['cause'] = failure_details(cause, depth+1)
    return value


class Custodian:
    def __init__(self, bridge, attempt, command, deadline, track, *, acquisition=None):
        self.bridge, self.attempt, self.command = bridge, attempt, command
        self.deadline, self.track = deadline, track
        self.acquisition = {'parent':command['identity'],
            'purpose':'verification' if command.get('options', {}).get('verification_idb') else 'final', 'ordinal':1}
        if acquisition is not None:
            self.acquisition = acquisition
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
        self.verification_path = command.get('options', {}).get('verification_idb') if acquisition is None else None
        self.verification_retired = False
        self.verification_cleanup_error = None
        self.last_auxiliary = None
        self.adopted = False
        self.retired = False
        self.sdk_entered = False
        self.file_gate_admitted = False
        self.absence_confirmed = False
        self.recovery_snapshot = None
        self.file_snapshot = None
        self.recovery_error = None
        self.recovery_active = False
        self.recovery_blocked = False
        self.recovery_next = 0
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
        self.target = Target(target,for_open=True)
        self.target.file_job_prepare = self.prepare_file_job
        try:
            self.target_path, self.coord_key = str(self.target.target), self.target.key
            self.admit_target()
            self.file_gate_admitted = True
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
                cleanup_owner = getattr(self, 'cleanup_owner', None)
                from config import ida_cli_home
                from recovery_legacy import import_known_home
                self.legacy_diagnostics=import_known_home(self.target,ida_cli_home()/'idb')
                Journal(self.target).gate(self.helper['state_root'],
                    self.acquisition if cleanup_owner is not None else acquisition, cleanup_owner=cleanup_owner)
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
    def file_gate(self, *, recovery=False):
        # Compatibility for the existing r9 snapshot path. Never hold EX while
        # waiting for owner lifetime or an analysis/cleanup RPC.
        if self.target is None:
            with Target(self.target_path) as target:
                with target.locked(deadline=time.monotonic()+15):
                    yield target
        elif self.target_guard is not None:
            yield self.target
        else:
            with self.target.locked(deadline=time.monotonic()+15 if recovery else self.deadline):
                yield self.target

    def stage(self, stage, value):
        if stage in ('BeforeResolve', 'LaunchIntent', 'BeforeAttach', 'AttachMayBeSent') and self.deadline <= time.monotonic():
            raise TimeoutError('original open budget exhausted before attach; signed custody retained')
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
                self.observations[watch] = {'owner':owner, 'receipt':None, 'attempts':{}, 'transferred':False}
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
            self.observations[watch]['transferred'] = True
            self.admit_target(self.acquisition)
        elif stage == 'AttachMayBeSent':
            self.attach_fact(value, self.attach_ordinal, 'may_send')
            # Durable pre-send registration is not an HTTP send. The helper
            # round trip can consume the original budget; keep its signed fact
            # and let the SDK report NotSent when this final callback refuses.
            if self.deadline <= time.monotonic():
                raise TimeoutError('original open budget exhausted after attach attempt signing; no attach')
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
            if self.deadline <= time.monotonic():
                raise TimeoutError('original open budget exhausted after launch intent signing; no Popen')
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
        if item.get('proof'):
            if state == 'exact_handle' and self.adopted and owner == self.owner:
                # The public on_acquired callback already journaled this exact
                # physical handle. A retired helper cannot sign another fact;
                # retain the SDK's late result without reopening its watch.
                item['attempts'][ordinal] = attempt
                return
            raise RuntimeError('owner already proved exited; no further attach side effect')
        reply = self.helper_request({'kind':'attach_attempt', 'watch':watch, 'attempt':attempt})
        item['attempts'][ordinal] = attempt
        return reply

    def reconcile_outcome(self, outcome):
        # The SDK ledger is authoritative even when a stage callback failed.
        # Keep every unknown attempt; a later success never clears an older one.
        for attempt in outcome['attempts']:
            state = 'exact_handle' if attempt['handle'] is not None else attempt['failure_kind']
            self.attach_fact(attempt['instance'], attempt['attempt'], state)
        for watch,item in list(self.observations.items()):
            if item.get('proof'):
                continue
            if any(a['state'] not in ('not_sent', 'lease_absent') for a in item['attempts'].values()):
                continue
            status = self.helper_request({'kind':'lookup', 'watch':watch})['item']
            if not item.get('transferred'):
                # A signed helper receipt may precede a lost/failed Rust handoff.
                # Reconcile that exact watch before closing it as NotSent. This
                # transfers cleanup only and never authorizes another attach.
                with self.file_gate(recovery=True) as target:
                    Journal(target).owner_signed(item['receipt'])
                self.unlock_target()
                self.transact('observe', acquisition=self.acquisition, watch=watch,
                    owner=item['owner'], receipt=item['receipt'], target=self.target_path,
                    coord_key=self.coord_key)
                item['transferred'] = True
            if status is not None and status.get('proof'):
                continue
            if not item['attempts']:
                self.attach_fact(self.originals[digest(item['owner'])], 1, 'not_sent')
            result = self.bridge.backup_sources.no_attach(item['owner'], watch,
                lambda:self.helper_request({'kind':'no_attach', 'watch':watch})['consumer'])
            if result is None:
                continue
            closed, bridge = result
            with self.file_gate(recovery=True) as target:
                Journal(target).no_attach({'watch':watch, 'consumer':closed, 'bridge_consumer':bridge})
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
            if self.adopted:
                self.ack_custody()
                self.unlock_target()
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
        self.adopted = True
        self.ack_custody()
        # All execution remains gated by N1. Target EX ends once the exact
        # physical lease and prior helper subscription have reliable custody.
        self.unlock_target()

    def ack_custody(self):
        # adopt() already transferred the exact physical lease durably. The
        # control stream may have an earlier proof write waiting for target EX.
        self.unlock_target()
        reply = self.transact('acquired', acquisition=self.acquisition, lease=self.lease,
            owner=self.owner, watch=self.watch, receipt=self.subscription,
            target=self.target_path, coord_key=self.coord_key)
        self.decision = reply['decision']
        if reply.get('settled'):
            self.retired = True
            with self.bridge.lock:
                held = self.bridge.handles.get(self.lease['lease_id'])
                if held is not None and held[0] == self.lease and held[1] is self.handle:
                    self.bridge.handles.pop(self.lease['lease_id'])
                    self.bridge.metadata_contexts.pop(self.lease['lease_id'], None)
                if self.bridge.custodians.get(self.lease['lease_id']) is self:
                    self.bridge.custodians.pop(self.lease['lease_id'])

    def obtain(self, Handle, Options, path, options, context):
        configured = Options(**dict(options, acquisition_observer=self.stage))
        self.sdk_entered = True
        outcome = Handle.open_outcome(path, options=configured,
            on_acquired=lambda h:self.obtained(h, context))
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
        self.reconcile_finished_outcome(outcome,'acquisition')
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
        if self.target is not None:
            self.target_guard = self.target.locked(deadline=self.deadline)
            self.target_guard.__enter__()
        self.target.business_admission()
        Journal(self.target).gate(self.helper['state_root'])
        remaining = self.deadline-time.monotonic()
        if remaining <= 0:
            return previous
        resolved = Handle.resolve_outcome(path, options=Options(**dict(options,
            startup_timeout=remaining, acquisition_observer=self.stage)))
        if resolved['cause'] is None and self.deadline <= time.monotonic():
            resolved['cause'] = TimeoutError('original open budget exhausted after signed resolve; no attach')
            resolved['failure_kind'] = 'not_sent'
        if resolved['cause'] is not None:
            resolved['prior_outcome'] = previous
            resolved['attempts'] = previous['attempts'] + resolved['attempts']
            resolved['launches'] = previous['launches'] + resolved['launches']
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

    def reconcile_finished_outcome(self,outcome,kind):
        """SDK completion and observation cleanup are independent facts."""
        try:
            self.reconcile_outcome(outcome)
        except Exception as cleanup_error:
            if outcome.get('handle') is None:
                try:self.finish_without_handle()
                except Exception as completion_error:
                    cause=outcome.get('cause')
                    raise RuntimeError(kind+' cleanup unconfirmed: '+str(cleanup_error)
                        +'; SDK completion unconfirmed: '+str(completion_error)) from (
                            cause if cause is not None else cleanup_error)
            if outcome.get('cause') is not None:
                raise RuntimeError(kind+' cleanup unconfirmed: '+str(cleanup_error)) from outcome['cause']
            raise
        try:
            if outcome.get('handle') is None:self.finish_without_handle()
        except Exception as completion_error:
            if outcome.get('cause') is not None:
                raise RuntimeError(kind+' cleanup unconfirmed: '+str(completion_error)) from outcome['cause']
            raise

    def obtain_attach(self, Handle, instance, options, context, *, cleanup=False):
        self.stage('Resolved', instance)
        self.sdk_entered = True
        outcome = Handle.attach_outcome(instance, idle_timeout=options.get('idle_timeout'),
            on_acquired=lambda h:self.obtained(h, context), on_stage=self.stage)
        self.outcome = outcome
        handle = outcome.get('handle')
        if handle is not None:
            if self.decision is None:
                self.obtained(handle, context)
            handle.claim_acquired()
        self.reconcile_finished_outcome(outcome,'attach')
        if outcome.get('cause') is not None:
            raise outcome['cause']
        if handle is None or (self.decision['disposition'] != 'prepare' and not cleanup):
            raise RuntimeError('attach custody is cleanup-only or unavailable')
        return handle

    def auxiliary(self, deadline):
        # Reserve the second tenant slot before any helper/SDK side effect.
        # The child retains its own exact handle even if its acquired ACK fails.
        with self.bridge.lock:
            child = self.bridge.cleanup_handles.get(self.lease['lease_id'])
        if child is not None:
            from lifecycle import release_state
            settled_absence = child.handle is None and self.transact(
                'acquisition_status', acquisition=child.acquisition)['settled']
            closed_handle = child.handle is not None and release_state(child.handle)['requested']
            if settled_absence or closed_handle:
                with self.bridge.lock:
                    if self.bridge.cleanup_handles.get(self.lease['lease_id']) is child:
                        self.bridge.cleanup_handles.pop(self.lease['lease_id'], None)
                child = None
        if child is not None:
            return child
        identity = self.transact('reserve_acquisition', parent=self.acquisition['parent'],
            purpose='auxiliary')['acquisition']
        self.last_auxiliary = identity
        child = None
        try:
            child = Custodian(self.bridge, self.attempt, self.command, deadline, self.track,
                              acquisition=identity)
            child.cleanup_context = [self.bridge.identity, self.lease['lease_id'],
                self.lease['instance_id'], self.lease['generation'], self.bridge.lifetime_path]
            child.cleanup_owner = self.owner
            with self.bridge.lock:
                self.bridge.cleanup_handles[self.lease['lease_id']] = child
            with child.gate(self.owner['canonical_idb_path']):
                from ida_nexus import discover_databases
                candidates = [entry.instance for entry in discover_databases()
                              if owner_key(entry.instance) == self.owner]
                if len(candidates) != 1:
                    raise RuntimeError('CleanupBlocked: exact owner unavailable for auxiliary; no SDK attach')
                child.obtain_attach(self.bridge.Handle, candidates[0], {},
                    {'method':'cleanup-auxiliary', 'parent':self.acquisition['parent']}, cleanup=True)
        except Exception as original:
            if child is not None and child.handle is None and child.outcome is None and child.subscription is not None:
                # Resolved subscription runs before attach_outcome is entered.
                # Its failed handoff therefore has no possible HTTP attach;
                # use the existing signed NoAttach path, never a fake outcome.
                try:
                    child.reconcile_outcome({'attempts':[]})
                    child.finish_without_handle()
                except Exception as cleanup_error:
                    raise RuntimeError('auxiliary observation cleanup unconfirmed: ' + str(cleanup_error)) from original
            if child is None or (child.handle is None and not child.observations and not child.launches):
                self.transact('unstarted_acquisition', acquisition=identity,
                    sdk_entered=False, file_obligation=False)
                with self.bridge.lock:
                    if self.bridge.cleanup_handles.get(self.lease['lease_id']) is child:
                        self.bridge.cleanup_handles.pop(self.lease['lease_id'], None)
            raise
        return child

    def finish_without_handle(self):
        if self.handle is not None:
            raise RuntimeError('ProtocolMismatch: handle must keep physical custody')
        self.transact('acquisition_finished', acquisition=self.acquisition,
            watches=list(self.observations)+[v['watch'] for v in self.launches.values()])
        if self.transact('acquisition_status', acquisition=self.acquisition)['settled']:
            if self.verification_path:
                self.verification_retired = True
            with self.bridge.lock:
                for parent, child in list(self.bridge.cleanup_handles.items()):
                    if child is self:
                        self.bridge.cleanup_handles.pop(parent)

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
                'cancel_requested':False, 'proving':False, 'next':0, 'expired':False,
                'cleanup_stop_observation':cleanup}
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
                error=failure_details(exc))['decision']
        else:
            # No watch means no SDK side effect was possible. Existing watches
            # keep their reservation until exact settlement by Rust.
            result = self.helper_request({'kind':'retire_parent', 'parent':self.acquisition['parent']})
            if result['retired'] and not self.observations and not self.launches:
                if self.sdk_entered or self.recovery_snapshot is not None:
                    return
                if self.file_gate_admitted:
                    with self.file_gate(recovery=True) as target:
                        if Journal(target).value.get('file_intents'):
                            raise RuntimeError('file recovery obligation retained; no unstarted absence') from exc
                self.transact('unstarted_acquisition', acquisition=self.acquisition,
                    sdk_entered=False, file_obligation=False)
                self.absence_confirmed = True
                if self.verification_path:
                    self.verification_retired = True
                else:
                    with self.bridge.lock:
                        parent=self.acquisition['parent']['operation_id']
                        if self.bridge.acquisitions.get(parent) is self:
                            self.bridge.acquisitions.pop(parent)

    def has_file_obligation(self):
        return (self.recovery_snapshot is not None or (self.file_snapshot is not None
            and self.file_snapshot.data['status'] not in ('restored','opened','archived')))

    def known_no_acquisition(self):
        if self.absence_confirmed:
            return True
        if (self.handle is None and not self.sdk_entered and not self.observations
                and not self.launches and not self.file_gate_admitted and self.recovery_snapshot is None):
            return True
        return (self.handle is None and self.outcome is not None
                and self.outcome['failure_kind'] in ('not_sent', 'lease_absent')
                and not self.outcome['unresolved_attempts'] and not self.launches)

    def cleanup(self):
        self.decision = self.transact('cleanup', acquisition=self.acquisition, lease=self.lease)['decision']

    def release_for_retry(self, *, owner_required=True, require_ack=True):
        self.cleanup()
        # Only the caller's wait consumes the original budget. The already
        # accepted N1 release and a failed snapshot retain their own custody.
        while True:
            reply = self.transact('cleanup_status', acquisition=self.acquisition,
                lease=self.lease, require_ack=require_ack, owner_required=owner_required,
                recovery_id=getattr(self,'file_recovery_id',None))
            if reply['ready']:
                break
            if time.monotonic() >= self.deadline or reply.get('parent_terminal'):
                raise CleanupPending('open ended while exact cleanup remains pending; no next acquisition')
            if self.bridge.stopped.wait(.05):
                raise RuntimeError('cleanup interrupted; independent helper and target obligation retained')
        if not owner_required:
            return reply.get('outcome') or self.release_outcome
        # N1 can learn the original release thread's real public lifetime before
        # the independent producer has published it to the target journal.
        # Consume that durable fact before a new owner reaches check_owner.
        delay = .01
        while True:
            with self.file_gate(recovery=True) as target:
                journal = Journal(target)
                journal.recover_public_proofs()
                previous = next((i for i in journal.value['entries'].values() if i['watch'] == self.watch), None)
                if previous is None or previous.get('proof') or previous.get('resource_retirement'):
                    break
            if time.monotonic() >= self.deadline or reply.get('parent_terminal'):
                raise CleanupPending('open ended while durable target proof remains pending; no next acquisition')
            self.bridge.backup_sources.query({'watch':self.watch, 'target':self.target_path,
                'coord_key':self.coord_key, 'owner':self.owner, 'acquisition':self.acquisition,
                'subscription_epoch':self.subscription['record']['subscription_epoch']})
            if self.bridge.stopped.wait(delay):
                raise RuntimeError('r9 proof custody pending; prior ordinal retained')
            delay = min(.2, delay*2)
        if reply.get('resource_retirement'):
            from lifecycle import release_errors
            outcome = dict(reply.get('outcome') or self.release_outcome or {})
            outcome['resource_retirement'] = reply['resource_retirement']
            outcome.setdefault('release_acknowledged', False)
            outcome['save_guard_error'] = outcome.get('save_guard_error') or '; '.join(release_errors(self.handle)) or None
            return outcome
        return reply.get('outcome') or self.release_outcome

    def retain_restore(self, snapshot, observed):
        # Keep the existing Snapshot and a fresh root SH/target reference, not a
        # second lease state machine. The current gate closes on caller return.
        if self.recovery_snapshot is not None:
            if self.recovery_snapshot[0] is not snapshot:
                raise RuntimeError('RecoveryBlocked: conflicting retained file job')
            self.bridge.proof_wakeup.set()
            return
        target = Target(self.target_path)
        target.file_job_prepare = self.prepare_file_job
        snapshot.coordination = target
        self.recovery_snapshot = (snapshot, observed, target)
        self.bridge.proof_wakeup.set()

    def prepare_file_job(self, transaction, reply, identity, nonce):
        from recovery_job import readiness
        return self.transact('file_job_prepare',target=transaction.data['target'],
            coord_key=transaction.target.key,directory=transaction.target.directory.native_identity,
            ready_sha256=digest(readiness(transaction.target,transaction.recovery_id)),
            root_binding=transaction.target.recovery_root_binding(),epoch=transaction.token.epoch,
            recovery_id=transaction.recovery_id,job_nonce=nonce,
            reply_endpoint=str(reply),reply_identity=list(identity))['job']

    def advance_restore(self):
        # One bounded observation per fair turn. Waiting for a target or owner
        # never occupies a business worker or spins in a preflight worker.
        try:
            snapshot, observed, target = self.recovery_snapshot
            if self.retired and not self.originals and not self.launches:
                from recovery_transaction import Transaction
                from target_coordination import digest
                with target.locked(nb=True):
                    with Transaction(target,snapshot.recovery_id,recover=False) as completed:
                        terminal=completed.data['status'] in ('restored','opened','archived')
                        if terminal and completed.data['failure_intent']:
                            if not completed.data['attempts'][-1]['restored']:
                                raise RuntimeError('RecoveryBlocked: terminal file state lacks completed scene')
                            for requirement in completed.data['requirements']:
                                certificate=completed.data['certified_resources'].get(digest(requirement))
                                if certificate is None:
                                    raise RuntimeError('RecoveryBlocked: terminal file resource certificate missing')
                                completed.validate_certificate(requirement,certificate)
                        if terminal:snapshot.data=completed.data
                if terminal:
                    target.close()
                    self.recovery_snapshot=None
                    self.recovery_error=None
                    return
            if self.recovery_blocked:
                return
            reply = self.transact('cleanup_status', acquisition=self.acquisition,
                lease=self.lease, require_ack=True, owner_required=True,
                recovery_id=getattr(self,'file_recovery_id',None))
            if not reply['ready']:
                return
            with target.locked(nb=True):
                journal = Journal(target)
                journal.recover_public_proofs()
                previous = next((i for i in journal.value['entries'].values() if i['watch'] == self.watch), None)
                if previous is not None and not (previous.get('proof') or previous.get('resource_retirement')):
                    return
                try:
                    snapshot.rollback(observed)
                except Exception:
                    # The durable v2 job remains recoverable at the next gate;
                    # this failed observation does not undo accepted file work.
                    self.recovery_blocked = True
                    raise
            target.close()
            self.recovery_snapshot = None
            self.recovery_error = None
        except Exception as exc:
            self.recovery_error = type(exc).__name__ + ': ' + str(exc)
        finally:
            with self.bridge.lock:
                self.recovery_next = time.monotonic()+.2
                self.recovery_active = False
                parent = self.acquisition['parent']['operation_id']
                if (self.recovery_snapshot is None and not self.running and self.retired
                        and not self.originals and not self.launches
                        and self.bridge.acquisitions.get(parent) is self):
                    self.bridge.acquisitions.pop(parent)

    def next_retry(self):
        self.next_acquisition('root_retry')

    def next_acquisition(self, action='reserve_acquisition', purpose='final'):
        # A late retirement must still address the old physical ordinal.
        with self.bridge.lock:
            if self.lease and self.bridge.custodians.get(self.lease['lease_id']) is self:
                previous = copy.copy(self)
                previous.running = False
                self.bridge.custodians[self.lease['lease_id']] = previous
        if time.monotonic() >= self.deadline:
            raise TimeoutError('original open budget exhausted; no next acquisition')
        fields = {'predecessor':self.acquisition} if action == 'root_retry' else {'purpose':purpose}
        self.acquisition = self.transact(action, parent=self.command['identity'], **fields)['acquisition']
        self.helper_request({'kind':'reserve_parent', 'parent':self.acquisition['parent']})
        self.handle = self.lease = self.decision = self.subscription = self.owner = None
        self.release_event = threading.Event()
        self.originals, self.observations, self.launches = {}, {}, {}
        self.outcome = None
        self.attach_ordinal = 0
        self.release_outcome = None
        self.attach_failures = []
        self.verification_retired = False
        self.adopted = False
        self.retired = False
        self.sdk_entered = False
        self.file_gate_admitted = False
        self.absence_confirmed = False
        if purpose == 'final' and action != 'root_retry':
            self.verification_path = None
        if self.target is not None:
            self.target_guard = self.target.locked(deadline=self.deadline)
            self.target_guard.__enter__()

    def ready(self, capabilities, wait_analysis, recovery):
        return self.transact('ready', attempt=self.attempt, acquisition=self.acquisition,
            lease=self.lease, capabilities=capabilities, wait_analysis=wait_analysis,
            pid=self.handle.instance.pid, idb_path=canonical(self.handle.instance.idb_path), recovery=recovery)
