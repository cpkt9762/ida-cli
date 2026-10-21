"""Independent public-lifetime observer. Never attaches, releases or loads IDA.

The target writer owns mutable journals. This process publishes immutable facts
without taking target EX and retains the real instance until durable custody.
"""
import json
import os
import signal
from pathlib import Path
import socket
import stat
import sys
import threading
import time

from owner_identity import owner_key, state_identity, validate_owner
from custody_process_identity import capture, process_commands
from origin import creation_scope
from target_coordination import Directory, Target, canonical, digest, encoded

PROTOCOL = 2
MAX_FRAME = 1024 * 1024
# Exact request families. Reject partial upgrades before any reservation,
# durable fact or public discovery can occur.
REQUEST_FIELDS = {
    'finish':(), 'heartbeat':(), 'reserve_parent':('parent',), 'retire_parent':('parent',),
    'lookup':('watch',), 'attach_attempt':('watch','attempt'), 'no_attach':('watch',),
    'adopt_public_proof':('watch','proof'), 'startup_transfer':('watch','successor'),
    'resource_retired':('watch','evidence'),
    'nonlast_transfer':('watch','successor'),
    'retire':('watch','sha256'), 'proof_custody_ack':('watch','sha256','path'),
    'subscribe':('watch','target','coord_key','acquisition','owner','subscription_epoch'),
    'launch_intent':('watch','target','coord_key','acquisition','launch','subscription_epoch'),
    'spawned':('watch','launch','pid','os_identity'),
    'launch_settle':('watch','bridge'),
}
# A forked child that has not exec'd yet still shows its parent's argv, and a
# dead parent does not stop it from exec'ing. Absence evidence is therefore only
# taken once the exact bridge has been reaped for this long.
LAUNCH_SETTLE_SECONDS = 5


def peer_uid(stream):
    if sys.platform == 'darwin':
        import ctypes
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        library = ctypes.CDLL(None, use_errno=True)
        if library.getpeereid(stream.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
            raise OSError(ctypes.get_errno(), 'helper peer credentials unavailable')
        return uid.value
    if sys.platform.startswith('linux'):
        import struct
        return struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
    raise RuntimeError('helper peer credentials unsupported')


def request(endpoint, incarnation, message, timeout=2):
    path = Path(endpoint)
    before = path.lstat()
    if (not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600):
        raise RuntimeError('ProtocolMismatch: untrusted helper endpoint')
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(timeout)
        stream.connect(str(path))
        after = path.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or peer_uid(stream) != os.getuid():
            raise RuntimeError('ProtocolMismatch: helper endpoint replaced or wrong peer')
        stream.sendall(encoded(dict(message, protocol=PROTOCOL, helper=incarnation)) + b'\n')
        with stream.makefile('rb') as source:
            data = source.readline(MAX_FRAME + 1)
        if not data.endswith(b'\n') or len(data) > MAX_FRAME:
            raise RuntimeError('ProtocolMismatch: helper response framing')
        reply = json.loads(data)
        if reply.get('helper') != incarnation or reply.get('protocol') != PROTOCOL:
            raise RuntimeError('ProtocolMismatch: helper response identity')
        if not reply.get('ok'):
            raise RuntimeError(reply.get('error', 'ObservationFailed'))
        return reply


class Observer:
    def __init__(self, incarnation, capacity, *, clock=time.monotonic, storage=None):
        self.incarnation, self.capacity, self.clock = incarnation, capacity, clock
        self.state = state_identity()
        # Scale the live budget by 32KiB per configured watch, with independent
        # cleanup headroom. A fixed 512KiB pool underfunded these reservations.
        self.live_ref_limit_bytes = max(512*1024, capacity*32768)
        self.lock = threading.RLock()
        self.items = {}
        self.parents = {}
        self.owners = {}
        self.seq = 0
        self.last_router = clock()
        self.exit_blocked = None
        self.orphan_exit = None
        self.finishing = False
        self.identity = capture(os.getpid())
        self.storage = storage
        self.pending_registry = None
        self.recovered = False
        if storage is not None:
            # This mutable registry contains every watch and its cleanup facts.
            # Individual proofs and IPC frames keep their original fixed bound.
            storage.max_record = max(1024*1024, self.live_ref_limit_bytes*4)
            try:
                saved, _, _ = storage.read('helper-state.json')
            except FileNotFoundError:
                self.persist()
            else:
                if (saved.get('schema') != 1 or saved.get('helper') != incarnation
                        or saved.get('state_root') != self.state or saved.get('capacity') != capacity
                        or type(saved.get('seq')) is not int or saved['seq'] < 0
                        or not isinstance(saved.get('items'), dict) or len(saved['items']) > capacity):
                    raise RuntimeError('ObservationRecoveryBlocked: helper registry identity/schema')
                self.seq, self.items = saved['seq'], saved['items']
                self.exit_blocked = saved.get("exit_blocked")
                self.orphan_exit = saved.get("orphan_exit")
                self.finishing = saved.get('finishing', False)
                if type(self.finishing) is not bool or (self.finishing and (self.items or saved.get('parents'))):
                    raise RuntimeError('ObservationRecoveryBlocked: invalid finish tombstone')
                self.parents = saved.get('parents', {})
                if (not isinstance(self.parents, dict) or len(self.parents)*4 > capacity
                        or any(not isinstance(p, dict) or set(p) != {'parent', 'budget'}
                               or p['budget'] != 4 or digest(p['parent']) != k
                               or len(encoded(p['parent'])) > 1024 for k,p in self.parents.items())
                        or any(digest(i.get('acquisition', {}).get('parent')) not in self.parents
                               for i in self.items.values())
                        or any(sum(i.get('acquisition', {}).get('parent') == p['parent']
                                   for i in self.items.values()) > p['budget'] for p in self.parents.values())):
                    raise RuntimeError('ObservationRecoveryBlocked: parent reservation table')
                self.recovered = True
                # A killed heartbeat may leave a duplicate/partial write of the
                # already committed snapshot. Complete only that exact value
                # before restore_facts adds recovery diagnostics. A different
                # pending snapshot remains blocked, never overwritten.
                try:
                    os.stat('helper-state.json.new', dir_fd=storage.fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    storage.retry_immutable('helper-state.json', saved, immutable=False)
                self.restore_facts()

    def persist(self):
        with self.lock:
            if self.storage is None:
                return
            value = {'schema':1, 'helper':self.incarnation,
                     'state_root':self.state, 'capacity':self.capacity, 'seq':self.seq,
                     'parents':self.parents, 'finishing':self.finishing,
                     'exit_blocked':self.exit_blocked, 'orphan_exit':self.orphan_exit,
                     'items':{k:self.public_item(v) for k,v in self.items.items()}}
            # A failed write can only resume the exact snapshot that reserved it.
            # Finish that slot before writing a newer view; never discard .new.
            if self.pending_registry is not None:
                self.storage.retry_immutable('helper-state.json', self.pending_registry, immutable=False)
                self.pending_registry = None
            self.pending_registry = json.loads(encoded(value))
            self.storage.retry_immutable('helper-state.json', self.pending_registry, immutable=False)
            self.pending_registry = None

    def restore_facts(self):
        """Recover only exact immutable facts; absence never discharges a watch."""
        fields = {'Subscribed':'receipt', 'SpawnIntent':'receipt', 'Spawned':'spawned',
                  'StartupOwnerSubscribed':'owner_receipt', 'PublicOwnerLifetime':'proof',
                  'ProducerClosed':'consumer', 'StartupTransferred':'consumer',
                  'ObservationFailed':'failed', 'ObservationAbandoned':'abandoned',
                  'AttachAttempt':'attach_attempt', 'NoAttachClosed':'consumer',
                  'NonlastTransferred':'consumer', 'LaunchAbandonedUnspawned':'consumer'}
        for watch, item in self.items.items():
            if item.get('watch') != watch:
                raise RuntimeError('ObservationRecoveryBlocked: registry watch mismatch')
            with Target(item['target']) as target:
                if target.key != item['coord_key']:
                    raise RuntimeError('ObservationRecoveryBlocked: target identity changed')
                for namespace in ('observations', 'proofs'):
                    key = digest(watch.encode()) if namespace == 'observations' else (
                        digest(item['owner']) if item.get('owner') else None)
                    if key is None:
                        continue
                    try:
                        container = target.directory.child(namespace, create=False)
                    except FileNotFoundError:
                        continue
                    try:
                        try:
                            producer = container.child(key, create=False)
                        except FileNotFoundError:
                            continue
                        try:
                            records = []
                            from recovery_files import visible_names
                            for name in visible_names(producer):
                                record, _, data = producer.read(name)
                                if record.get('watch') != watch or record.get('helper') != self.incarnation:
                                    continue
                                if (record.get('acquisition') != item['acquisition']
                                        or record.get('coord_key') != item['coord_key']
                                        or record.get('state_root') != self.state
                                        or record.get('subscription_epoch') != item['subscription_epoch']
                                        or type(record.get('seq')) is not int or record['seq'] > self.seq):
                                    raise RuntimeError('ObservationRecoveryBlocked: immutable fact binding')
                                records.append((record['seq'], name, record, data))
                            for _, name, record, data in sorted(records):
                                field = fields.get(record['kind'])
                                if field is None:
                                    raise RuntimeError('ObservationRecoveryBlocked: unknown fact kind')
                                item[field] = {'path':str(producer.path/name), 'sha256':digest(data), 'record':record}
                                if record['kind'] == 'AttachAttempt':
                                    attempt = record['attempt']
                                    item.setdefault('attach_attempts', {})[str(attempt['attempt'])] = attempt
                                    reference = item[field]
                                    if reference not in item.setdefault('attach_facts', []):
                                        item['attach_facts'].append(reference)
                                elif record['kind'] == 'NoAttachClosed':
                                    item['no_attach'] = True
                                if field == 'owner_receipt':
                                    item['owner'] = record['owner']
                                if record.get('os_identity') is not None:
                                    item['os_identity'] = record['os_identity']
                        finally:
                            producer.close()
                    finally:
                        container.close()
            if item.get('consumer') or item.get('proof'):
                continue
            item['observation_error'] = 'ObservationRecoveryBlocked: original public source not yet reacquired'
        self.persist()

    def reconnect_sources(self):
        pending = [i for i in self.items.values() if i.get('owner') and not i.get('proof')
                   and not i.get('consumer') and digest(i['owner']) not in self.owners]
        if not pending:
            return
        from ida_nexus import discover_databases
        try:
            discovered = discover_databases(timeout=.2)
            with self.lock:
                for item in pending:
                    matches = [d.instance for d in discovered if owner_key(d.instance, self.state) == item['owner']]
                    if len(matches) == 1:
                        self.watch_owner(item, matches[0])
                        item.pop('observation_error', None)
                self.persist()
        except Exception as exc:
            self.exit_blocked = 'ObservationRecoveryBlocked: ' + type(exc).__name__ + ': ' + str(exc)

    def publish(self, item, kind, **facts):
        # Caller serializes this producer. I/O never needs the target writer's EX.
        pending = item.setdefault('pending_facts', {})
        slot = digest([kind, facts])
        record = pending.get(slot)
        if record is None:
            with Target(item['target']) as target:
                if target.key != item['coord_key']:
                    raise RuntimeError('ObservationFailed: target identity changed')
                if 'origin_binding' not in item:
                    item['origin_binding'] = creation_scope(target.directory.path, self.incarnation)
            self.seq += 1
            record = dict(schema=1, helper=self.incarnation, seq=self.seq,
                          observation_id=f'{self.incarnation}-{self.seq}', kind=kind,
                          state_root=self.state, watch=item['watch'], coord_key=item['coord_key'],
                          owner=item.get('owner'), acquisition=item['acquisition'],
                          launch=item.get('launch'), os_identity=item.get('os_identity'),
                          eligibility=False, subscription_epoch=item.get('subscription_epoch'), **facts)
            record['origin_binding'] = item['origin_binding']
            record['helper_registration'] = {'endpoint':getattr(self, 'endpoint', None),
                'identity':self.identity, 'state_root':self.state}
            pending[slot] = record
        # Reusing the reserved record also handles commit-before-registry/ACK loss.
        self.persist()
        with Target(item['target']) as target:
            if target.key != item['coord_key']:
                raise RuntimeError('ObservationFailed: target identity changed')
            container = target.directory.child('proofs' if kind == 'PublicOwnerLifetime' else 'observations')
            try:
                with container.fact_view():
                    producer = container.child(digest(item['owner']) if kind == 'PublicOwnerLifetime' else digest(item['watch'].encode()))
                    try:
                        name = record['observation_id'] + '.json'
                        with producer.fact_view():
                            producer.retry_immutable(name, record)
                        pending.pop(slot)
                        return {'path':str(producer.path / name), 'sha256':digest(record), 'record':record}
                    finally:
                        producer.close()
            finally:
                container.close()

    def receive(self, value):
        if (not isinstance(value, dict) or type(value.get('protocol')) is not int
                or value.get('protocol') != PROTOCOL or value.get('helper') != self.incarnation):
            raise ValueError('ProtocolMismatch: helper incarnation')
        kind = value.get('kind')
        if not isinstance(kind, str) or kind not in REQUEST_FIELDS:
            raise ValueError('ProtocolMismatch: unknown helper request family')
        required = {'kind', 'protocol', 'helper', *REQUEST_FIELDS[kind]}
        allowed = required | ({'summary_only'} if kind == 'heartbeat' else
                              {'proof'} if kind == 'subscribe' else set())
        if not required <= value.keys() or value.keys() - allowed:
            raise ValueError('ProtocolMismatch: helper request fields')
        if 'summary_only' in value and type(value['summary_only']) is not bool:
            raise ValueError('ProtocolMismatch: heartbeat summary flag')
        if 'watch' in value and (not isinstance(value['watch'], str) or not 0 < len(value['watch']) <= 128):
            raise ValueError('ProtocolMismatch: watch identity')
        if 'subscription_epoch' in value and (type(value['subscription_epoch']) is not int
                or not 0 < value['subscription_epoch'] < 1 << 64):
            raise ValueError('ProtocolMismatch: subscription epoch')
        with self.lock:
            if kind == 'finish':
                if self.items or self.parents:
                    raise RuntimeError('ObservationPending: helper still owns observations')
                self.finishing = True
                try:
                    self.persist()
                except BaseException:
                    self.finishing = False
                    raise
                return {}
            if self.finishing:
                raise RuntimeError('ObservationClosed: helper finish was durably accepted')
            if kind == 'heartbeat':
                self.last_router = self.clock()
                result = {'state_root':self.state, 'identity':self.identity,
                          'watches':list(self.items), 'owner_count':len(self.owners),
                          'used':len(self.items), 'limit':self.capacity,
                          'live_ref_bytes':sum(len(encoded(self.public_item(i))) + 8192 for i in self.items.values()),
                          'live_ref_limit_bytes':self.live_ref_limit_bytes,
                          'reserved':sum(p['budget'] for p in self.parents.values()), 'parent_count':len(self.parents),
                          'exit_blocked':self.exit_blocked, 'recovered':self.recovered,
                          'orphan_after_seconds':300, 'orphan_action':'retain_obligations_and_exit',
                          'orphan_exit':self.orphan_exit,
                          'same_boot_eligibility':False}
                if not value.get('summary_only'):
                    result['items'] = [self.public_item(item) for item in self.items.values()]
                return result
            if kind == 'reserve_parent':
                key = digest(value['parent'])
                old = self.parents.get(key)
                if old is not None:
                    if old['parent'] != value['parent']:
                        raise ValueError('ProtocolMismatch: parent reservation collision')
                    return {'reserved':old['budget']}
                if sum(p['budget'] for p in self.parents.values()) + 4 > self.capacity:
                    raise RuntimeError('Busy: helper parent/watch/startup reservation capacity')
                if len(encoded(value['parent'])) > 1024:
                    raise RuntimeError('Busy: helper parent byte reservation capacity')
                self.parents[key] = {'parent':value['parent'], 'budget':4}
                self.persist()
                return {'reserved':4}
            if kind == 'retire_parent':
                parent = value['parent']
                if any(i['acquisition'].get('parent') == parent for i in self.items.values()):
                    return {'retired':False}
                self.parents.pop(digest(parent), None)
                self.persist()
                return {'retired':True}
            if kind == 'lookup':
                item = self.items.get(value['watch'])
                return {'state_root':self.state, 'item':self.public_item(item) if item is not None else None}
            if kind == 'attach_attempt':
                item = self.items[value['watch']]
                attempt = value['attempt']
                if (item.get('launch') or attempt.get('owner') != item.get('owner')
                        or type(attempt.get('attempt')) is not int or attempt['attempt'] < 1
                        or attempt.get('state') not in ('may_send', 'not_sent', 'lease_absent', 'unknown_attach', 'exact_handle')):
                    raise ValueError('ProtocolMismatch: attach attempt identity/state')
                attempts = item.setdefault('attach_attempts', {})
                key = str(attempt['attempt'])
                old = attempts.get(key)
                if old and old != attempt and old['state'] != 'may_send':
                    raise ValueError('ProtocolMismatch: conflicting terminal attach attempt')
                if old != attempt:
                    attempts[key] = attempt
                    item['attach_attempt'] = self.publish(item, 'AttachAttempt', attempt=attempt)
                    item.setdefault('attach_facts', []).append(item['attach_attempt'])
                return {'receipt':item['attach_attempt']}
            if kind == 'no_attach':
                item = self.items[value['watch']]
                attempts = item.get('attach_attempts', {})
                if (item.get('launch') or item.get('proof') or not attempts
                        or any(a['state'] not in ('not_sent', 'lease_absent') for a in attempts.values())):
                    raise ValueError('ProtocolMismatch: no-attach closure without exact terminal attempts')
                if not item.get('consumer'):
                    item['no_attach'] = True
                    item['consumer'] = self.publish(item, 'NoAttachClosed',
                        attempts=attempts, previous_facts=[item['receipt'], *item.get('attach_facts', [])])
                return {'consumer':item['consumer']}
            if kind == 'resource_retired':
                item = self.items.get(value['watch'])
                if item is None:
                    return {}  # Exact durable target evidence is checked by the caller too.
                evidence = value['evidence']
                with Target(item['target']) as target:
                    journal, _, _ = target.directory.read('custody.json')
                    bound = journal['entries'].get(str(item['subscription_epoch']), {})
                    if (journal['coord_key'] != target.key or bound.get('watch') != item['watch']
                            or bound.get('resource_retirement') != evidence
                            or evidence.get('acquisition') != item['acquisition']
                            or evidence.get('owner') != item.get('owner')
                            or evidence.get('scope') != 'host_boot_change'
                            or evidence.get('evidence_type') != 'verified_boot_change_resource_retirement'):
                        raise ValueError('ProtocolMismatch: resource retirement lacks exact durable authority')
                self.items.pop(item['watch'])
                self.persist()
                key = digest(item.get('owner'))
                entry = self.owners.get(key)
                if entry:
                    entry['watches'].discard(item['watch'])
                    if not entry['watches']:
                        entry['stop'].set()
                        self.owners.pop(key)
                return {}
            if kind == 'adopt_public_proof':
                from target_journal import fact
                item = self.items[value['watch']]
                receipt = value['proof']
                record = receipt['record']
                if (record.get('owner') != item.get('owner')
                        or record.get('acquisition') != item['acquisition']
                        or record.get('subscription_epoch') != item['subscription_epoch']
                        or record.get('evidence_type') != 'public_owner_lifetime'):
                    raise ValueError('ProtocolMismatch: backup public proof identity')
                with Target(item['target']) as target:
                    fact(receipt, target, kind='PublicOwnerLifetime')
                    if item.get('proof') and item['proof'] != receipt:
                        journal, _, _ = target.directory.read('custody.json')
                        bound = journal['entries'].get(str(item['subscription_epoch']), {})
                        selected = bound.get('proof', {})
                        if (bound.get('watch') != item['watch'] or bound.get('owner') != item['owner']
                                or selected.get('path') != receipt['path']
                                or selected.get('sha256') != receipt['sha256']
                                or item.get('consumer')):
                            raise ValueError('ProtocolMismatch: proof differs from durable target selection')
                        item['custody_proof'] = receipt
                        self.persist()
                if not item.get('proof'):
                    item['proof'] = receipt
                return {'proof':item.get('custody_proof', item['proof'])}
            if kind == 'nonlast_transfer':
                item = self.items[value['watch']]
                if item.get('consumer'):
                    record = item['consumer']['record']
                    if record['kind'] != 'NonlastTransferred' or record['successor'] != value['successor']:
                        raise ValueError('ProtocolMismatch: conflicting nonlast producer closure')
                    return {'consumer':item['consumer']}
                successor = self.items[value['successor']]
                if (item.get('proof') or not item.get('owner') or item['owner'] != successor.get('owner')
                        or item['coord_key'] != successor['coord_key'] or successor.get('consumer')
                        or successor['subscription_epoch'] >= item['subscription_epoch']):
                    raise ValueError('ProtocolMismatch: nonlast owner observation successor')
                # Read the writer's durable plan without taking EX. An opener
                # may hold EX while waiting for this helper's subscribe ACK.
                with Target(item['target']) as target:
                    journal, _, _ = target.directory.read('custody.json')
                    bound = journal['entries'][str(item['subscription_epoch'])]
                    anchor = journal['entries'][str(successor['subscription_epoch'])]
                    outcome = bound.get('detach_outcome', {})
                    if (journal['coord_key'] != target.key or bound['watch'] != item['watch']
                            or anchor['watch'] != successor['watch']
                            or bound.get('nonlast_successor') != successor['subscription_epoch']
                            or bound['owner'] != item['owner'] or bound['acquisition'] != item['acquisition']
                            or anchor['owner'] != item['owner'] or anchor.get('nonlast_successor')
                            or outcome.get('lease_released') is not True or outcome.get('ack_kind') != 'nonlast'):
                        raise ValueError('ProtocolMismatch: nonlast transfer without durable parsed ACK')
                item['consumer'] = self.publish(item, 'NonlastTransferred',
                    successor=successor['watch'], successor_receipt=successor['receipt'],
                    previous_facts=[item['receipt'], *item.get('attach_facts', [])])
                self.persist()
                entry = self.owners.get(digest(item['owner']))
                if entry is not None:
                    entry['watches'].discard(item['watch'])
                return {'consumer':item['consumer']}
            if kind == 'startup_transfer':
                item = self.items[value['watch']]
                successor = self.items[value['successor']]
                if (not item.get('launch') or not successor.get('owner')
                        or item['acquisition'] != successor['acquisition']
                        or item['coord_key'] != successor['coord_key']
                        or not successor['owner']['record_id'].endswith('-' + item['launch']['suffix'])
                        or canonical(successor['owner']['canonical_idb_path']) != canonical(item['launch']['target'])):
                    raise ValueError('ProtocolMismatch: startup transfer successor')
                if not item.get('consumer'):
                    item['consumer'] = self.publish(item, 'StartupTransferred',
                        successor=successor['watch'], successor_receipt=successor['receipt'],
                        previous_facts=[item[k] for k in ('receipt', 'spawned', 'owner_receipt', 'proof', 'failed') if k in item])
                    item.pop('instance', None)
                return {'consumer':item['consumer']}
            if kind == 'launch_settle':
                return self.settle_unspawned_launch(value)
            if kind == 'retire':
                item = self.items.get(value['watch'])
                if item is None:
                    # This conveys no proof/closure fact. The consumer must
                    # already have durably adopted ProducerClosed before it can
                    # issue retire. An ACK lost after removal is safe to repeat.
                    return {'already_absent':True}
                if not item.get('consumer') or item['consumer']['sha256'] != value['sha256']:
                    raise ValueError('ProtocolMismatch: retire without matching producer closure')
                del self.items[value['watch']]
                owner = item.get('owner')
                if owner is not None:
                    entry = self.owners.get(digest(owner))
                    if entry is not None:
                        entry['watches'].discard(value['watch'])
                        if not entry['watches']:
                            entry['stop'].set()
                            self.owners.pop(digest(owner), None)
                return {}
            if kind == 'proof_custody_ack':
                item = self.items[value['watch']]
                proof = item.get('custody_proof', item.get('proof'))
                if not proof or proof['sha256'] != value['sha256'] or proof['path'] != value['path']:
                    raise ValueError('ProtocolMismatch: proof custody receipt')
                if not item.get('consumer'):
                    # A receipt is a producer-closed event; it is not permission
                    # to unlink a proof or erase this item's durable references.
                    item['consumer'] = self.publish(item, 'ProducerClosed', proof=proof,
                        previous_facts=item.get('attach_facts', []) +
                            ([item['proof']] if item.get('proof') != proof else []))
                    item.pop('instance', None)
                return {'consumer':item['consumer']}
            if kind in ('subscribe', 'launch_intent'):
                watch = value['watch']
                old = self.items.get(watch)
                fields = ('watch', 'target', 'coord_key', 'acquisition', 'subscription_epoch', 'owner' if kind == 'subscribe' else 'launch')
                if old:
                    if any(old.get(k) != value.get(k) for k in fields):
                        raise ValueError('ProtocolMismatch: conflicting observation identity')
                    if not old.get('receipt'):
                        raise RuntimeError('ObservationRecoveryBlocked: unsigned reserved watch retained')
                    return {'receipt':old['receipt']}
                parent = value['acquisition'].get('parent')
                reservation = self.parents.get(digest(parent))
                if reservation is None or reservation['parent'] != parent:
                    raise RuntimeError('Busy: helper parent budget not reserved before acquisition')
                if sum(i['acquisition'].get('parent') == parent for i in self.items.values()) >= reservation['budget']:
                    raise RuntimeError('Busy: helper parent observation budget exhausted')
                if len(self.items) >= self.capacity:
                    raise RuntimeError('Busy: helper observation capacity')
                if len(encoded(value)) > 8192:
                    raise RuntimeError('Busy: helper subscription byte capacity')
                if (sum(len(encoded(self.public_item(i))) + 8192 for i in self.items.values())
                        + len(encoded(value)) + 8192 > self.live_ref_limit_bytes):
                    raise RuntimeError('Busy: helper live_refs byte capacity; cleanup reserve retained')
                item = {k:value[k] for k in fields}
                item['subscription_epoch'] = value.get('subscription_epoch')
                item['created'] = self.clock()
                if kind == 'subscribe':
                    owner = validate_owner(value['owner'])
                    if 'proof' in value:
                        from target_journal import fact
                        proof = value['proof']
                        record = proof['record']
                        if (record.get('owner') != owner or record.get('watch') != watch
                                or record.get('acquisition') != item['acquisition']
                                or record.get('subscription_epoch') != item['subscription_epoch']
                                or record.get('evidence_type') != 'public_owner_lifetime'):
                            raise ValueError('ProtocolMismatch: reaped subscription proof identity')
                        with Target(item['target']) as target:
                            fact(proof, target, kind='PublicOwnerLifetime')
                        item['proof'] = proof
                        instance = None
                    else:
                        from ida_nexus import discover_databases
                        matches = [x.instance for x in discover_databases(timeout=.2)
                                   if owner_key(x.instance, self.state) == owner]
                        if len(matches) != 1:
                            raise RuntimeError('ObservationFailed: exact public instance unavailable')
                        instance = matches[0]
                    try:
                        item['os_identity'] = capture(owner['pid'])
                    except (OSError, RuntimeError):
                        item['os_identity'] = None
                self.items[watch] = item
                self.persist()
                item['receipt'] = self.publish(item, 'Subscribed' if kind == 'subscribe' else 'SpawnIntent')
                if kind == 'subscribe' and instance is not None:
                    self.watch_owner(item, instance)
                return {'receipt':item['receipt']}
            if kind == 'spawned':
                item = self.items[value['watch']]
                if not item.get('launch') or item['launch'] != value['launch']:
                    raise ValueError('ProtocolMismatch: launch intent')
                captured = capture(value['pid'])
                if value['os_identity'] != captured:
                    raise ValueError('StartupUnconfirmed: process birth changed')
                if item.get('os_identity') and item['os_identity'] != captured:
                    raise ValueError('StartupUnconfirmed: conflicting process birth')
                if item.get('spawned'):
                    return {'receipt':item['spawned']}
                item['os_identity'] = captured
                item['spawned'] = self.publish(item, 'Spawned')
                return {'receipt':item['spawned']}
            raise ValueError('ProtocolMismatch: unknown helper request')

    @staticmethod
    def worker_processes(suffix):
        """Every live process launched with this exact worker record suffix.

        The SDK identifies its worker only by the random `--record-suffix`
        argument; launcher and worker PIDs may differ. An unreadable process
        table is an error, never an empty one.
        """
        table = process_commands()
        return len(table), [pid for pid, argv in table
                            if any(a == '--record-suffix' and b == suffix for a, b in zip(argv, argv[1:]))]

    def settle_unspawned_launch(self, value):
        """Close a signed LaunchIntent whose owner provably does not exist.

        Only after the router reaped the exact bridge: no process can Popen for
        this launch any more, so the set of workers carrying its suffix can only
        shrink. A worker still present (or a published instance) keeps the
        launch on the normal public-lifetime path; absence after the exec
        margin means no live owner exists to observe. The evidence is an
        immutable fact, never a public-lifetime proof.
        """
        item = self.items[value['watch']]
        bridge = value['bridge']
        if (not isinstance(bridge, dict) or set(bridge) != {'pid', 'status', 'exited_secs'}
                or type(bridge['pid']) is not int or not isinstance(bridge['status'], str)
                or type(bridge['exited_secs']) not in (int, float)):
            raise ValueError('ProtocolMismatch: bridge exit evidence')
        closed = item.get('consumer')
        if closed:
            if closed['record']['kind'] != 'LaunchAbandonedUnspawned':
                return {'state':'not_applicable'}
            return {'state':'abandoned', 'consumer':closed}
        if (not item.get('launch') or item.get('owner') or item.get('os_identity')
                or item.get('spawned') or item.get('proof')):
            return {'state':'not_applicable'}
        if bridge['exited_secs'] < LAUNCH_SETTLE_SECONDS:
            return {'state':'settling'}
        evidence = item.get('launch_abandon_evidence')
        if evidence is None:
            from ida_nexus import discover_databases
            suffix = item['launch']['suffix']
            scanned, pids = self.worker_processes(suffix)
            discovered = discover_databases(timeout=.2)
            public = [d.instance for d in discovered if d.instance.record_id.endswith('-' + suffix)]
            if pids or public:
                self.discover_startups()
                return {'state':'owner_present', 'pids':pids,
                        'public':[i.record_id for i in public], 'bound':bool(item.get('owner'))}
            evidence = {'reason':'bridge reaped before Spawned; no worker process or public instance carries the launch suffix',
                        'bridge':bridge, 'settle_seconds':LAUNCH_SETTLE_SECONDS,
                        'suffix':suffix, 'target':item['launch']['target'], 'taken_at_unix':time.time(),
                        'process_table':{'scanned':scanned, 'matches':pids},
                        'public_discovery':{'scanned':len(discovered), 'matches':[]}}
            item['launch_abandon_evidence'] = evidence
        item['consumer'] = self.publish(item, 'LaunchAbandonedUnspawned', evidence=evidence)
        item.pop('instance', None)
        self.persist()
        return {'state':'abandoned', 'consumer':item['consumer']}

    @staticmethod
    def public_item(item):
        return {k:v for k,v in item.items() if k not in ('instance', 'thread')}

    def watch_owner(self, item, instance):
        """One real public lifetime wait per exact OwnerKey in this helper."""
        key = digest(item['owner'])
        entry = self.owners.get(key)
        if entry is None:
            entry = {'instance':instance, 'watches':set(), 'released':False, 'stop':threading.Event()}
            self.owners[key] = entry
        entry['watches'].add(item['watch'])
        if not entry.get('started'):
            thread = threading.Thread(target=self.observe, args=(key, entry), daemon=True)
            entry['thread'] = thread
            try:
                thread.start()
            except Exception as exc:
                item['observation_error'] = 'ObservationFailed: observer Thread.start: ' + str(exc)
                self.owners.pop(key, None)
                self.persist()
                raise
            entry['started'] = True

    def observe(self, key, entry):
        from ida_nexus import wait_database_released
        delay = .05
        while not entry['stop'].is_set():
            try:
                if not entry['released']:
                    released = wait_database_released(entry['instance'], timeout=.2)
                    if released is False:
                        continue
                    if released is not True:
                        raise RuntimeError('public lifetime wait returned without proof')
                    entry['released'] = True
                with self.lock:
                    for watch in entry['watches']:
                        item = self.items[watch]
                        if not item.get('consumer') and not item.get('proof'):
                            item['proof'] = self.publish(item, 'PublicOwnerLifetime', evidence_type='public_owner_lifetime')
                    self.persist()
                    entry['started'] = False
                return
            except Exception as exc:
                with self.lock:
                    for watch in entry['watches']:
                        self.items[watch]['observation_error'] = type(exc).__name__ + ': ' + str(exc)
                    self.exit_blocked = type(exc).__name__ + ': ' + str(exc)
                    try:
                        self.persist()
                    except Exception as write_error:
                        self.exit_blocked = type(write_error).__name__ + ': ' + str(write_error)
                # Original object and the one reserved proof slot remain owned.
                entry['stop'].wait(delay)
                delay = min(1.0, delay * 2)

    def orphan_done(self):
        with self.lock:
            if self.clock() - self.last_router < 300:
                return False
            return self.abandon('router disconnected')

    def abandon(self, cause):
        with self.lock:
            status = 'published'
            try:
                for item in self.items.values():
                    if not item.get('proof') and not item.get('abandoned'):
                        item['abandoned'] = self.publish(item, 'ObservationAbandoned',
                            cause=cause, last_observation=item.get('observation_error'))
            except Exception as exc:
                status = 'publication_failed'
                self.exit_blocked = type(exc).__name__ + ': ' + str(exc)
            # Abandonment is diagnostic, never proof or permission to drop a
            # watch. Keep every item/reservation/pending fact for exact recovery.
            self.orphan_exit = {'status': status, 'cause':cause, 'retained_watches': list(self.items),
                'recovery': 'restore target storage and reconnect the exact helper incarnation',
                'released': False}
            try:
                self.persist()
            except Exception as exc:
                self.exit_blocked = type(exc).__name__ + ': ' + str(exc)
                # Even unavailable registry storage cannot hold a process and
                # listening socket forever. Earlier committed custody is kept.
                import logging
                logging.getLogger(__name__).exception('ObservationRecoveryBlocked: orphan exit registry unavailable; committed obligations retained')
            if self.exit_blocked:
                import logging
                logging.getLogger(__name__).error('ObservationRecoveryBlocked: orphan exiting with retained obligations: %s', self.exit_blocked)
            return True

    def discover_startups(self):
        """Public discovery is additive; absence never retires a launch."""
        with self.lock:
            pending = [i for i in self.items.values() if i.get('launch') and not i.get('owner')
                       and not i.get('consumer')]
        if not pending:
            return
        from ida_nexus import discover_databases
        try:
            discovered = discover_databases(timeout=.2)
            for item in pending:
                matches = [d.instance for d in discovered
                    if d.instance.record_id.endswith('-' + item['launch']['suffix'])
                    and canonical(d.instance.idb_path) == canonical(item['launch']['target'])
                    and d.instance.backend == item['launch']['backend']]
                if len(matches) > 1:
                    raise RuntimeError('StartupUnconfirmed: suffix/target ambiguity')
                if not matches:
                    continue
                with self.lock:
                    item['owner'] = owner_key(matches[0], self.state)
                    item['owner_receipt'] = self.publish(item, 'StartupOwnerSubscribed')
                    self.watch_owner(item, matches[0])
                    self.persist()
        except Exception as exc:
            with self.lock:
                for item in pending:
                    item['observation_error'] = type(exc).__name__ + ': ' + str(exc)



def bind_private_listener(listener, endpoint):
    # Startup only, before owner observation threads: umask is process-wide.
    # Publish a trusted inode at bind, and restore even when bind fails.
    previous = os.umask(0o177)
    try:
        listener.bind(endpoint)
    finally:
        os.umask(previous)


def main():
    terminating = threading.Event()
    # The daemon deliberately ignores TERM. Exec preserves SIG_IGN, so the
    # independent helper must install its own durable-handoff termination path.
    signal.signal(signal.SIGTERM, lambda *_: terminating.set())
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
    endpoint, incarnation, capacity = sys.argv[1:]
    directory = Directory(Path(canonical(endpoint)).parent)
    clock = time.monotonic
    injected = os.environ.get('IDA_CLI_HELPER_TEST_CLOCK')
    if injected:
        # The normal Rust build strips this input. Feature-gated fault tests
        # supply an eight-byte clock offset in their own private state only.
        clock_path = Path(injected)
        fd = os.open(clock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        from target_coordination import checked
        original = checked(fd)
        def injected_clock():
            current = os.fstat(fd)
            if (current.st_dev,current.st_ino) != (original.st_dev,original.st_ino):
                raise RuntimeError('test clock identity changed')
            raw = os.pread(fd,8,0)
            if len(raw) != 8:
                raise RuntimeError('test clock input incomplete')
            return time.monotonic()+int.from_bytes(raw,'big')
        clock = injected_clock
    observer = Observer(incarnation, int(capacity), storage=directory, clock=clock)
    observer.endpoint = str(Path(canonical(endpoint)))
    listener = socket.socket(socket.AF_UNIX)
    # Rust may restart only its exact reaped child. The private directory and
    # protocol incarnation remain fixed; unlink only the old same-uid socket.
    try:
        previous = Path(endpoint).lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(previous.st_mode) or previous.st_uid != os.getuid():
            raise RuntimeError('ObservationRecoveryBlocked: endpoint identity/type')
        Path(endpoint).unlink()
    bind_private_listener(listener, endpoint)
    os.chmod(endpoint, 0o600)
    bound = Path(endpoint).lstat()
    listener.listen(8)
    listener.settimeout(.2)
    try:
        while not observer.finishing:
            if terminating.is_set():
                observer.abandon('termination requested')
                break
            if observer.orphan_done():
                break
            observer.discover_startups()
            observer.reconnect_sources()
            try:
                stream, _ = listener.accept()
            except TimeoutError:
                continue
            with stream:
                stream.settimeout(2)
                try:
                    if peer_uid(stream) != os.getuid():
                        raise ValueError('ProtocolMismatch: helper peer uid')
                    with stream.makefile('rb') as source:
                        data = source.readline(MAX_FRAME + 1)
                    if len(data) > MAX_FRAME or not data.endswith(b'\n'):
                        raise ValueError('ProtocolMismatch: helper request framing')
                    result = observer.receive(json.loads(data))
                    observer.persist()
                    reply = dict(ok=True, **result)
                except Exception as exc:
                    try:
                        observer.persist()
                    except Exception as write_error:
                        observer.exit_blocked = type(write_error).__name__ + ': ' + str(write_error)
                    reply = {'ok':False, 'error':type(exc).__name__ + ': ' + str(exc)}
                try:
                    stream.sendall(encoded(dict(reply, protocol=PROTOCOL, helper=incarnation)) + b'\n')
                except OSError:
                    pass  # Durable observations are replayable after a lost ACK.
    finally:
        listener.close()
        current = Path(endpoint).lstat()
        if (current.st_dev, current.st_ino) == (bound.st_dev, bound.st_ino):
            Path(endpoint).unlink()
        directory.close()


if __name__ == '__main__':
    main()
