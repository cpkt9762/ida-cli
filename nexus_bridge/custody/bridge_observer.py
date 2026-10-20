"""Backup public source retained in the bridge; never reconstructs instances."""
import threading
import uuid

from proof_helper import Observer
from target_coordination import digest, encoded

INCARNATION = 'bridge-' + uuid.uuid4().hex


class BackupSources:
    def __init__(self, bridge, capacity):
        self.bridge, self.capacity = bridge, capacity
        self.items = {}
        self.absent = {}
        self.publisher = Observer(INCARNATION, capacity)

    def reject_closed(self, owner, watch):
        if watch in self.absent:
            if self.absent[watch]['owner'] != digest(owner):
                raise ValueError('ProtocolMismatch: closed watch owner mismatch')
            raise ValueError('ObservationClosed: cannot revive an unregistered watch')

    def subscribe(self, instance, owner, watch=None):
        key = digest(owner)
        with self.bridge.lock:
            self.reject_closed(owner, watch)
            if key in self.items:
                if watch is not None:
                    self.items[key]['watches'].add(watch)
                return
            if (len(self.items) >= self.capacity
                    or sum(len(encoded(i['owner'])) + 8192 for i in self.items.values()) >= 512*1024):
                raise RuntimeError('Busy: bridge original instance live_refs capacity')
            entry = {'instance':instance, 'owner':owner, 'released':False, 'proofs':{}, 'watches':({watch} if watch is not None else set()), 'closed':set(),
                     'stop':threading.Event()}
            self.items[key] = entry
            thread = threading.Thread(target=self.observe, args=(entry,), daemon=True)
            entry['thread'] = thread
            try:
                thread.start()
            except Exception as exc:
                entry['error'] = 'ObservationFailed: bridge public source Thread.start: ' + str(exc)
                self.items.pop(key)  # Thread.start failed before any observation/attach.
                raise

    def register(self, owner, watch):
        with self.bridge.lock:
            self.reject_closed(owner, watch)
            self.items[digest(owner)]['watches'].add(watch)

    def bind(self, value):
        with self.bridge.lock:
            self.reject_closed(value['owner'], value['watch'])
            entry = self.items[digest(value['owner'])]
            watch = value['watch']
            if watch not in entry['watches']:
                raise ValueError('unknown provisional bridge watch')
            bindings = entry.setdefault('bindings', {})
            if watch not in bindings:
                item = entry.setdefault('binding_items', {}).setdefault(watch, dict(value))
                bindings[watch] = self.publisher.publish(item, 'BridgeSubscribed')
            return bindings[watch]

    def abort_unstarted(self, owner, watch):
        """Only the pre-attach caller may revoke this precise provisional source."""
        self.retire(watch)

    def observe(self, entry):
        from ida_nexus import wait_database_released
        try:
            while not entry['stop'].is_set():
                result = wait_database_released(entry['instance'], timeout=.2)
                if result is True:
                    break
                if result is not False:
                    raise RuntimeError('public original wait returned without proof')
            else:
                return
            with self.bridge.lock:
                entry['released'] = True
        except Exception as exc:
            with self.bridge.lock:
                entry['error'] = 'ObservationFailed: bridge public source: ' + type(exc).__name__ + ': ' + str(exc)

    def query(self, value):
        with self.bridge.lock:
            tombstone = self.absent.get(value['watch'])
            if tombstone is not None:
                if tombstone['owner'] != digest(value['owner']):
                    raise ValueError('ProtocolMismatch: closed query owner mismatch')
                return None
            entry = self.items.get(digest(value['owner']))
            if entry is None or not entry['released']:
                return
            watch = value['watch']
            if watch not in entry['watches'] or watch in entry['closed']:
                return
            proof = entry['proofs'].get(watch)
            if proof is None:
                item = entry.setdefault('proof_items', {}).setdefault(watch, dict(value))
                proof = self.publisher.publish(item, 'PublicOwnerLifetime',
                    evidence_type='public_owner_lifetime', source='bridge_original')
                entry['proofs'][watch] = proof
        self.bridge.control.send({'event':'owner_backup_proof', 'watch':watch, 'proof':proof})
        return proof

    def released_proof(self, value):
        """Query the retained original, never rediscover or recreate it."""
        from ida_nexus import wait_database_released
        with self.bridge.lock:
            entry = self.items[digest(value['owner'])]
            instance = entry['instance']
        if wait_database_released(instance, timeout=0) is not True:
            return None
        with self.bridge.lock:
            entry['released'] = True
        return self.query(value)

    def close(self, value):
        """Serialize closure against query so no later backup fact can appear."""
        owner, watch = value['owner'], value['watch']
        with self.bridge.lock:
            entry = self.items.get(digest(owner))
            record = value['proof']['record']
            if (record.get('owner') != owner or record.get('watch') != watch
                    or record.get('kind') != 'PublicOwnerLifetime'
                    or record.get('evidence_type') != 'public_owner_lifetime'):
                raise ValueError('ProtocolMismatch: owner proof custody identity/type')
            if entry is None or watch not in entry['watches']:
                # There was no producer to close. Pin its exact digest so a
                # late subscribe cannot turn absence into a revived observation.
                from target_coordination import Target
                from target_journal import fact
                with Target(value['target']) as target:
                    fact(value['proof'], target, kind='PublicOwnerLifetime')
                tombstone = {'owner':digest(owner), 'receipt':digest(value)}
                previous = self.absent.get(watch)
                if previous is not None and previous != tombstone:
                    raise ValueError('ProtocolMismatch: conflicting absent producer receipt')
                self.absent[watch] = tombstone
                return None
            previous = [proof for key,proof in entry['proofs'].items() if key == watch] if entry is not None else []
            record = value['proof']['record']
            item = {'watch':watch, 'target':value['target'], 'coord_key':record['coord_key'],
                    'owner':owner, 'acquisition':record['acquisition'],
                    'subscription_epoch':record['subscription_epoch']}
            # The receipt itself is replayed on ACK loss, not produced anew.
            cache = getattr(self, 'closed', {})
            closed = cache.get(watch)
            if closed is None:
                closed = self.publisher.publish(item, 'BridgeProducerClosed',
                    proof=value['proof'], previous_facts=previous)
                cache[watch] = closed
                self.closed = cache
            if entry is not None:
                entry['closed'].add(watch)
                if entry['watches'] <= entry['closed']:
                    entry.pop('instance', None)
                    for custodian in dict.fromkeys([*self.bridge.acquisitions.values(), *self.bridge.custodians.values()]):
                        custodian.originals.pop(digest(owner), None)
        return closed

    def nonlast_transfer(self, consumer):
        """Close this watch's producer while retaining the same original owner."""
        from target_coordination import Target
        from target_journal import fact
        record = consumer['record']
        with self.bridge.lock:
            entry = self.items[digest(record['owner'])]
            watch = record['watch']
            closed = getattr(self, 'closed', {}).get(watch)
            if closed is not None:
                if closed['record'].get('consumer') != consumer:
                    raise ValueError('ProtocolMismatch: conflicting nonlast bridge closure')
                return closed
            if watch not in entry['watches'] or record['successor'] not in entry['watches']:
                raise ValueError('ProtocolMismatch: nonlast bridge successor absent')
            binding = entry.get('bindings', {}).get(watch)
            if binding is None:
                raise ValueError('ProtocolMismatch: nonlast bridge source unbound')
            with Target(record['owner']['canonical_idb_path']) as target:
                fact(consumer, target, kind='NonlastTransferred')
                journal, _, _ = target.directory.read('custody.json')
                item = journal['entries'][str(record['subscription_epoch'])]
                if (journal['coord_key'] != target.key or item['watch'] != watch
                        or item.get('nonlast_successor') != record['successor_receipt']['record']['subscription_epoch']
                        or not any(f['sha256'] == consumer['sha256'] and f['path'] == consumer['path'] for f in item['facts'])):
                    raise ValueError('ProtocolMismatch: nonlast transfer not durably adopted')
            value = {k:record[k] for k in ('watch','owner','coord_key','acquisition','subscription_epoch')}
            value['target'] = record['owner']['canonical_idb_path']
            previous = [binding, *([entry['proofs'][watch]] if watch in entry['proofs'] else [])]
            closed = self.publisher.publish(value, 'BridgeNonlastTransferred', consumer=consumer, previous_facts=previous)
            if not hasattr(self, 'closed'):
                self.closed = {}
            self.closed[watch] = closed
            entry['closed'].add(watch)
            for custody in dict.fromkeys([*self.bridge.acquisitions.values(), *self.bridge.custodians.values()]):
                if custody.watch == watch:
                    custody.originals.pop(digest(record['owner']), None)
            return closed

    def no_attach(self, owner, watch, close_observation):
        with self.bridge.lock:
            entry = self.items[digest(owner)]
            if watch not in entry['watches']:
                raise ValueError('ProtocolMismatch: unknown no-attach bridge watch')
            if entry['proofs'].get(watch):
                return None
            consumer = close_observation()
            entry['closed'].add(watch)
            if entry['watches'] <= entry['closed']:
                entry['stop'].set()
                for custody in dict.fromkeys([*self.bridge.acquisitions.values(), *self.bridge.custodians.values()]):
                    custody.originals.pop(digest(owner), None)
            record = consumer['record']
            item = {'watch':watch, 'target':entry['owner']['canonical_idb_path'],
                    'coord_key':record['coord_key'], 'owner':owner,
                    'acquisition':record['acquisition'], 'subscription_epoch':record['subscription_epoch']}
            return consumer, self.publisher.publish(item, 'BridgeNoAttachClosed', consumer=consumer)

    def retire(self, watch):
        # Rust has adopted the closure and all its facts before this message.
        with self.bridge.lock:
            getattr(self, 'closed', {}).pop(watch, None)
            for key,entry in list(self.items.items()):
                if watch in entry['watches']:
                    entry['watches'].remove(watch)
                    entry['proofs'].pop(watch, None)
                    entry.get('bindings', {}).pop(watch, None)
                    entry.get('binding_items', {}).pop(watch, None)
                    entry.get('proof_items', {}).pop(watch, None)
                    entry['closed'].discard(watch)
                    if not entry['watches']:
                        entry['stop'].set()
                        self.items.pop(key)
