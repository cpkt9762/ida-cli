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
        self.publisher = Observer(INCARNATION, capacity)

    def subscribe(self, instance, owner, watch=None):
        key = digest(owner)
        with self.bridge.lock:
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
            self.items[digest(owner)]['watches'].add(watch)

    def bind(self, value):
        with self.bridge.lock:
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
            entry = self.items.get(digest(value['owner']))
            if entry is None or not entry['released']:
                return
            watch = value['watch']
            if watch in entry['closed']:
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
            if entry is None or watch not in entry['watches']:
                raise ValueError('ObservationClosed: closure cannot revive an unregistered watch')
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
