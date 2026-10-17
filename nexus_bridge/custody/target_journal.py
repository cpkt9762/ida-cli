"""Single-writer target responsibility journal and healthy record settlement.

Only callers holding root SH then this target's stable EX may mutate authority.
Immutable helper facts are verified from their exact descriptor before adoption.
"""
import json
import os
from pathlib import Path
import sys
import time

from target_coordination import LIMIT, RESERVE, SUMMARY_BYTES, SUMMARY_LIMIT, Target, digest, encoded
from origin import creation_scope


def fact(receipt, target, *, kind=None):
    path = Path(receipt['path'])
    relative = path.relative_to(target.directory.path)
    if len(relative.parts) != 3 or relative.parts[0] not in ('proofs', 'observations'):
        raise RuntimeError('CoordinationBlocked: receipt outside fixed observation namespace')
    container = target.directory.child(relative.parts[0], create=False)
    producer = None
    try:
        producer = container.child(relative.parts[1], create=False)
        record, info, data = producer.read(relative.name)
        if (record.get('schema') != 1 or not isinstance(record.get('helper'), str)
                or type(record.get('seq')) is not int or record['seq'] < 1
                or record.get('observation_id') != f"{record['helper']}-{record['seq']}"
                or type(record.get('subscription_epoch')) is not int or record['subscription_epoch'] < 1
                or record.get('eligibility') is not False):
            raise RuntimeError('CoordinationBlocked: immutable fact schema/producer/sequence mismatch')
        if digest(data) != receipt['sha256'] or record != receipt['record'] or record['coord_key'] != target.key:
            raise RuntimeError('CoordinationBlocked: immutable receipt content/identity mismatch')
        namespace = 'proofs' if record['kind'] == 'PublicOwnerLifetime' else 'observations'
        key = digest(record['owner']) if namespace == 'proofs' else digest(record['watch'].encode())
        if relative.parts != (namespace, key, record['observation_id'] + '.json'):
            raise RuntimeError('CoordinationBlocked: immutable fact namespace/identity mismatch')
        if kind is not None and record['kind'] != kind:
            raise RuntimeError('CoordinationBlocked: receipt evidence type mismatch')
        return {'path':str(path), 'sha256':digest(data), 'inode':[info.st_dev, info.st_ino], 'kind':record['kind']}
    finally:
        if producer is not None:
            producer.close()
        container.close()


class Journal:
    def __init__(self, target):
        if target.target_fd is None:
            raise RuntimeError('target authority requires stable target EX')
        self.target = target
        try:
            self.value, self.info, self.raw = target.directory.read('custody.json')
        except FileNotFoundError:
            self.value = {'schema':1, 'coord_key':target.key, 'revision':0, 'next_epoch':1,
                          'closed_through':0, 'entries':{}, 'summary':[], 'closed_after_holes':[],
                          'compaction':None}
            self.info = self.raw = None
        v = self.value
        if (v.get('schema') != 1 or v.get('coord_key') != target.key or type(v.get('revision')) is not int
                or type(v.get('next_epoch')) is not int or type(v.get('closed_through')) is not int
                or v['next_epoch'] <= v['closed_through'] or not isinstance(v.get('entries'), dict)
                or len(v['entries']) > LIMIT or not isinstance(v.get('summary'), list)
                or len(v['summary']) > SUMMARY_LIMIT or len(encoded(v['summary'])) > SUMMARY_BYTES
                or not isinstance(v.get('closed_after_holes'), list)):
            raise RuntimeError('CoordinationBlocked: unknown/corrupt custody journal')
        self.validate()
        self.resume_compaction()

    def validate(self):
        v = self.value
        maximum = (1 << 64)-1
        if not (0 <= v['revision'] <= maximum and 0 <= v['closed_through'] < v['next_epoch'] <= maximum):
            raise RuntimeError('CoordinationBlocked: invalid epoch/revision range')
        ranges = v['closed_after_holes']
        previous = v['closed_through']
        if len(ranges) > LIMIT:
            raise RuntimeError('CoordinationBlocked: unbounded closed epoch intervals')
        for pair in ranges:
            if (not isinstance(pair, list) or len(pair) != 2 or any(type(n) is not int for n in pair)
                    or not previous+1 < pair[0] <= pair[1] < v['next_epoch']):
                raise RuntimeError('CoordinationBlocked: noncanonical closed epoch intervals')
            previous = pair[1]
        watches = set()
        for key, item in v['entries'].items():
            if (not isinstance(item, dict) or type(item.get('epoch')) is not int or str(item['epoch']) != key
                    or not 0 < item['epoch'] < v['next_epoch'] or not isinstance(item.get('watch'), str)
                    or not item['watch'] or len(item['watch']) > 128 or item['watch'] in watches
                    or any(type(item.get(n)) is not bool for n in ('producer_closed', 'consumer_closed', 'unacked_events', 'detached'))
                    or not isinstance(item.get('facts'), list) or len(item['facts']) > 32
                    or not isinstance(item.get('acquisition'), dict)
                    or not isinstance(item.get('origin_binding'), dict)
                    or item['origin_binding'].get('same_boot_eligibility') is not False):
                raise RuntimeError('CoordinationBlocked: malformed active observation')
            watches.add(item['watch'])
            for reference in item['facts']:
                self.validate_reference(reference)
            closed = item['epoch'] <= v['closed_through'] or any(a <= item['epoch'] <= b for a,b in ranges)
            if closed and (not v.get('compaction') or item['epoch'] not in v['compaction'].get('epochs', [])):
                raise RuntimeError('CoordinationBlocked: closed epoch has an active reference')
        intents = v.get('file_intents', {})
        if not isinstance(intents, dict) or len(intents) > LIMIT:
            raise RuntimeError('RecoveryBlocked: invalid file intent table')
        for key,item in intents.items():
            if (not isinstance(item, dict) or not isinstance(item.get('path'), str)
                    or not Path(item['path']).is_absolute() or len(key) != 64
                    or item.get('status') not in ('snapshotting', 'failed-owner-held', 'rolling-back')):
                raise RuntimeError('RecoveryBlocked: malformed retained file intent')

    def validate_reference(self, entry):
        if (not isinstance(entry, dict) or set(entry) != {'path', 'sha256', 'inode', 'kind'}
                or not isinstance(entry['path'], str) or not isinstance(entry['sha256'], str)
                or len(entry['sha256']) != 64 or any(c not in '0123456789abcdef' for c in entry['sha256'])
                or not isinstance(entry['inode'], list) or len(entry['inode']) != 2
                or any(type(n) is not int or n < 0 for n in entry['inode'])):
            raise RuntimeError('CoordinationBlocked: malformed immutable reference')
        relative = Path(entry['path']).relative_to(self.target.directory.path)
        if len(relative.parts) != 3 or relative.parts[0] not in ('observations', 'proofs'):
            raise RuntimeError('CoordinationBlocked: immutable reference outside target namespace')

    def accounting(self):
        totals = {'live_refs':len(self.value['entries']), 'routine_bytes':len(encoded(self.value['summary'])),
                  'retained_evidence_bytes':0, 'namespace_bytes':0, 'routine_files':0}
        scanned = [0]
        def scan(directory, namespace, depth=0):
            if depth > 2:
                raise RuntimeError('RetainedEvidenceFull: coordination namespace depth budget')
            for name in os.listdir(directory.fd):
                scanned[0] += 1
                if scanned[0] > 4096:
                    raise RuntimeError('RetainedEvidenceFull: coordination namespace count budget')
                info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                if name.endswith('.new'):
                    raise RuntimeError('RoutineCompactionFailed: interrupted write retained: ' + name)
                if __import__('stat').S_ISDIR(info.st_mode):
                    child = directory.child(name, create=False)
                    try:
                        scan(child, namespace, depth+1)
                    finally:
                        child.close()
                else:
                    record, _, data = directory.read(name)
                    retained = namespace == 'retained' or record.get('kind') in ('ObservationFailed', 'ObservationAbandoned')
                    totals['retained_evidence_bytes' if retained else 'routine_bytes'] += len(data)
                    if not retained:
                        totals['routine_files'] += 1
        for name in ('observations', 'proofs', 'retained'):
            try:
                directory = self.target.directory.child(name, create=False)
            except FileNotFoundError:
                continue
            try:
                scan(directory, name)
            finally:
                directory.close()
        for name in ('lock', 'target.json'):
            try:
                totals['namespace_bytes'] += os.stat(name, dir_fd=self.target.directory.fd, follow_symlinks=False).st_size
            except FileNotFoundError:
                pass
        totals.update(routine_limit_bytes=2*1024*1024, retained_evidence_limit_bytes=16*1024*1024,
                      emergency_bytes=256*1024, live_limit=LIMIT-RESERVE, summary_limit=SUMMARY_LIMIT,
                      summary_bytes=len(encoded(self.value['summary'])), namespace_reclaimable_bytes=0)
        percent = totals['retained_evidence_bytes'] * 100 // totals['retained_evidence_limit_bytes']
        totals['retained_warning_percent'] = next((n for n in (100, 95, 80) if percent >= n), 0)
        return totals

    def save(self):
        if self.info is not None:
            current, info, raw = self.target.directory.read('custody.json')
            if (info.st_dev, info.st_ino, raw) != (self.info.st_dev, self.info.st_ino, self.raw):
                raise RuntimeError('CoordinationBlocked: journal changed outside target writer')
        self.value['revision'] += 1
        self.target.directory.durable('custody.json', self.value)
        _, self.info, self.raw = self.target.directory.read('custody.json')

    def gate(self, state_root=None):
        # Unknown .new and unrecognized recovery files are never ignored.
        for name in os.listdir(self.target.directory.fd):
            if name.endswith('.new'):
                raise RuntimeError('CoordinationBlocked: interrupted durable write retained: ' + name)
            if name not in ('lock', 'target.json', 'custody.json', 'proofs', 'observations', 'retained'):
                raise RuntimeError('RecoveryBlocked: unsupported target coordination entry: ' + name)
        self.recover_public_proofs()
        for item in self.value['entries'].values():
            if item.get('launch') and not item.get('transferred'):
                raise RuntimeError('StartupUnconfirmed: exact launch responsibility pending')
            if item.get('owner') and not item.get('proof'):
                if state_root is None or item['owner']['state_root'] != state_root:
                    raise RuntimeError('ObservationRecoveryBlocked: unresolved owner in another state root')
        if self.value.get('file_intents'):
            raise RuntimeError('RecoveryBlocked: retained file intent requires explicit recovery: '
                               + ','.join(self.value['file_intents']))
        return self.value

    def referenced_record(self, reference):
        relative = Path(reference['path']).relative_to(self.target.directory.path)
        container = self.target.directory.child(relative.parts[0], create=False)
        try:
            directory = container.child(relative.parts[1], create=False)
            try:
                record, info, data = directory.read(relative.name)
                if digest(data) != reference['sha256'] or [info.st_dev, info.st_ino] != reference['inode']:
                    raise RuntimeError('ObservationRecoveryBlocked: authorized source fact replaced')
                fact({'path':reference['path'], 'record':record, 'sha256':reference['sha256']}, self.target)
                return record
            finally:
                directory.close()
        finally:
            container.close()

    def authorized_producers(self, item, kinds):
        records = [self.referenced_record(f) for f in item['facts'] if f['kind'] in kinds]
        for r in records:
            if (r['watch'] != item['watch'] or r['acquisition'] != item['acquisition']
                    or r['subscription_epoch'] != item['epoch'] or r['coord_key'] != self.target.key):
                raise RuntimeError('ObservationRecoveryBlocked: authorized source binding mismatch')
        return {r['helper'] for r in records}

    def scan_facts(self, namespace, key):
        try:
            container = self.target.directory.child(namespace, create=False)
        except FileNotFoundError:
            return []
        try:
            try:
                directory = container.child(key, create=False)
            except FileNotFoundError:
                return []
            try:
                names = os.listdir(directory.fd)
                if len(names) > 4096:
                    raise RuntimeError('ObservationRecoveryBlocked: fact namespace budget')
                result = []
                for name in names:
                    if name.endswith('.new'):
                        raise RuntimeError('ObservationRecoveryBlocked: pending immutable fact retained')
                    record, _, data = directory.read(name)
                    result.append({'path':str(directory.path/name), 'sha256':digest(data), 'record':record})
                return result
            finally:
                directory.close()
        finally:
            container.close()

    def recover_public_proofs(self):
        """Adopt authorized durable facts without closing any old producer."""
        for item in list(self.value['entries'].values()):
            if item.get('launch') and not item.get('owner'):
                authorized = self.authorized_producers(item, ('SpawnIntent', 'Spawned'))
                for receipt in self.scan_facts('observations', digest(item['watch'].encode())):
                    r = receipt['record']
                    if (r.get('kind') == 'StartupOwnerSubscribed' and r.get('helper') in authorized
                            and r.get('watch') == item['watch'] and r.get('acquisition') == item['acquisition']
                            and r.get('subscription_epoch') == item['epoch']):
                        self.startup_owner({'watch':item['watch'], 'receipt':receipt})
            if not item.get('owner') or item.get('proof'):
                continue
            authorized = self.authorized_producers(item, ('Subscribed', 'StartupOwnerSubscribed', 'BridgeSubscribed'))
            for receipt in self.scan_facts('proofs', digest(item['owner'])):
                r = receipt['record']
                if (r.get('kind') == 'PublicOwnerLifetime' and r.get('helper') in authorized
                        and r.get('watch') == item['watch'] and r.get('owner') == item['owner']
                        and r.get('acquisition') == item['acquisition'] and r.get('subscription_epoch') == item['epoch']):
                    self.proof({'watch':item['watch'], 'proof':receipt})
                    break

    def bridge_signed(self, receipt):
        r = receipt['record']
        item = self.item(r['watch'], r['subscription_epoch'])
        if (r['owner'] != item['owner'] or r['acquisition'] != item['acquisition']
                or r['state_root'] != item['owner']['state_root']):
            raise RuntimeError('CoordinationBlocked: bridge producer binding mismatch')
        verified = fact(receipt, self.target, kind='BridgeSubscribed')
        existing = self.authorized_producers(item, ('BridgeSubscribed',))
        if existing and existing != {r['helper']}:
            raise RuntimeError('CoordinationBlocked: conflicting bridge producer')
        if verified not in item['facts']:
            item['facts'].append(verified)
        self.save()

    def abort_unstarted(self, watch):
        item = next(i for i in self.value['entries'].values() if i['watch'] == watch)
        if item['lease'] or item.get('launch') or any(f['kind'] != 'BridgeSubscribed' for f in item['facts']):
            raise RuntimeError('CoordinationBlocked: cannot abort a signed/possibly attached observation')
        item['producer_closed'] = item['consumer_closed'] = item['detached'] = item['bridge_closed'] = True
        item['unacked_events'] = False
        item['no_attach'] = True
        self.save()
        self.settle()

    def file_intent(self, path, status, attempts):
        intents = self.value.setdefault('file_intents', {})
        key = digest(str(path).encode())
        if status in ('opened', 'restored') or (status == 'ready' and not attempts):
            intents.pop(key, None)
        else:
            info = path.lstat()
            intents[key] = {'path':str(path), 'status':status, 'inode':[info.st_dev, info.st_ino],
                            'sha256':digest(path.read_bytes())}
        self.save()

    def check_owner(self, owner):
        for item in self.value['entries'].values():
            if item.get('owner') and not item.get('proof') and item['owner'] != owner:
                raise RuntimeError('ObservationRecoveryBlocked: different owner without exact lifetime proof')

    def begin(self, acquisition, watch, *, owner=None, launch=None):
        self.settle()
        for item in self.value['entries'].values():
            if item['watch'] == watch:
                if item['acquisition'] != acquisition or item.get('owner') != owner or item.get('launch') != launch:
                    raise RuntimeError('CoordinationBlocked: conflicting observation identity')
                return item['epoch']
        if owner is not None:
            self.check_owner(owner)
        if len(self.value['entries']) >= LIMIT-RESERVE:
            raise RuntimeError('Busy: live_refs; healthy history already compacted')
        stats = self.accounting()
        if stats['retained_evidence_bytes'] + 65536 > stats['retained_evidence_limit_bytes']:
            raise RuntimeError('RetainedEvidenceFull: failure evidence retained; new admission refused')
        if stats['routine_bytes'] + stats['emergency_bytes'] + 32768 > stats['routine_limit_bytes']:
            raise RuntimeError('Busy: live_refs routine budget; cleanup/proof emergency reserve retained')
        if self.value['next_epoch'] >= (1 << 64)-1:
            raise RuntimeError('Busy: observation epoch namespace exhausted')
        epoch = self.value['next_epoch']
        self.value['next_epoch'] += 1
        self.value['entries'][str(epoch)] = {'epoch':epoch, 'watch':watch, 'acquisition':acquisition,
            'owner':owner, 'launch':launch, 'facts':[], 'producer_closed':False,
            'consumer_closed':False, 'unacked_events':True, 'lease':None, 'detached':False,
            'origin_binding':creation_scope(self.target.directory.path, 'acquisition-' + digest(acquisition))}
        self.save()
        return epoch

    def item(self, watch, epoch):
        item = self.value['entries'].get(str(epoch))
        if not item or item['watch'] != watch:
            raise RuntimeError('ObservationClosed: old/unknown epoch cannot revive references')
        return item

    def adopt(self, value):
        record = value['receipt']['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        if (item['owner'] != value['owner'] or item['acquisition'] != value['acquisition']
                or record['watch'] != item['watch'] or record['owner'] != item['owner']):
            raise RuntimeError('CoordinationBlocked: custody physical identity mismatch')
        if item['lease'] is not None and item['lease'] != value['lease']:
            raise RuntimeError('CoordinationBlocked: conflicting physical lease')
        verified = fact(value['receipt'], self.target, kind='Subscribed')
        item['lease'] = value['lease']
        item['unacked_events'] = False
        if verified not in item['facts']:
            item['facts'].append(verified)
        self.save()
        return {'epoch':item['epoch'], 'revision':self.value['revision']}

    def launch_signed(self, receipt):
        record = receipt['record']
        item = self.item(record['watch'], record['subscription_epoch'])
        if record['launch'] != item['launch'] or record['acquisition'] != item['acquisition']:
            raise RuntimeError('StartupUnconfirmed: launch receipt mismatch')
        verified = fact(receipt, self.target)
        if verified['kind'] not in ('SpawnIntent', 'Spawned'):
            raise RuntimeError('StartupUnconfirmed: invalid launch fact')
        if verified not in item['facts']:
            item['facts'].append(verified)
        item['unacked_events'] = False
        self.save()

    def owner_signed(self, receipt):
        record = receipt['record']
        item = self.item(record['watch'], record['subscription_epoch'])
        if record['owner'] != item['owner'] or record['acquisition'] != item['acquisition']:
            raise RuntimeError('CoordinationBlocked: pre-attach owner mismatch')
        verified = fact(receipt, self.target, kind='Subscribed')
        if verified not in item['facts']:
            item['facts'].append(verified)
        item['unacked_events'] = False
        self.save()

    def proof(self, value):
        receipt = value['proof']
        record = receipt['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        if (record.get('helper') not in self.authorized_producers(item, ('Subscribed', 'StartupOwnerSubscribed', 'BridgeSubscribed'))
                or record['watch'] != item['watch']
                or record['state_root'] != item['owner']['state_root']
                or record['evidence_type'] != 'public_owner_lifetime' or record['owner'] != item['owner']
                or record['acquisition'] != item['acquisition']):
            raise RuntimeError('CoordinationBlocked: proof owner/acquisition mismatch')
        verified = fact(receipt, self.target, kind='PublicOwnerLifetime')
        if item.get('proof') and item['proof'] != verified:
            raise RuntimeError('CoordinationBlocked: conflicting proof identity')
        item['proof'] = verified
        item['consumer_closed'] = True
        # Public lifetime, unlike absence/EOF, also proves this exact lease is gone.
        item['detached'] = True
        item['unacked_events'] = False
        if verified not in item['facts']:
            item['facts'].append(verified)
        self.save()
        return {'epoch':item['epoch'], 'revision':self.value['revision']}

    def producer_closed(self, value):
        record = value['consumer']['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        if record['owner'] != item['owner'] or not item.get('proof'):
            raise RuntimeError('CoordinationBlocked: producer close without durable proof custody')
        verified = fact(value['consumer'], self.target, kind='ProducerClosed')
        if record['proof']['sha256'] != item['proof']['sha256']:
            raise RuntimeError('CoordinationBlocked: producer closed different proof')
        self.adopt_attempt_facts(item, record.get('previous_facts', []))
        item['producer_closed'] = True
        if verified not in item['facts']:
            item['facts'].append(verified)
        self.save()
        return {'epoch':item['epoch'], 'revision':self.value['revision']}

    def adopt_attempt_facts(self, item, receipts):
        for receipt in receipts:
            record = receipt['record']
            if (record['watch'] != item['watch'] or record['owner'] != item['owner']
                    or record['acquisition'] != item['acquisition'] or record['subscription_epoch'] != item['epoch']):
                raise RuntimeError('CoordinationBlocked: attach fact binding mismatch')
            verified = fact(receipt, self.target)
            if verified['kind'] not in ('Subscribed', 'AttachAttempt'):
                raise RuntimeError('CoordinationBlocked: unexpected attach fact kind')
            if verified not in item['facts']:
                item['facts'].append(verified)

    def no_attach(self, value):
        record = value['consumer']['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        if (item['lease'] is not None or item.get('launch') or item.get('proof')
                or record['owner'] != item['owner'] or record['acquisition'] != item['acquisition']
                or not record.get('attempts')
                or any(a['state'] not in ('not_sent', 'lease_absent') for a in record['attempts'].values())):
            raise RuntimeError('CoordinationBlocked: no-attach closure lacks typed terminal evidence')
        self.adopt_attempt_facts(item, record['previous_facts'])
        helper = fact(value['consumer'], self.target, kind='NoAttachClosed')
        bridge_record = value['bridge_consumer']['record']
        if bridge_record['consumer'] != value['consumer'] or bridge_record['watch'] != item['watch']:
            raise RuntimeError('CoordinationBlocked: no-attach bridge closure mismatch')
        bridge = fact(value['bridge_consumer'], self.target, kind='BridgeNoAttachClosed')
        for reference in (helper, bridge):
            if reference not in item['facts']:
                item['facts'].append(reference)
        item['producer_closed'] = item['consumer_closed'] = item['detached'] = item['bridge_closed'] = True
        item['no_attach'] = True
        item['unacked_events'] = False
        self.save()
        return {}

    def bridge_closed(self, value):
        receipt = value['consumer']
        record = receipt['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        if (not item.get('proof') or record['owner'] != item['owner']
                or record['acquisition'] != item['acquisition']
                or record['proof']['sha256'] != item['proof']['sha256']):
            raise RuntimeError('CoordinationBlocked: bridge closure identity mismatch')
        for previous in record['previous_facts']:
            prior = previous['record']
            if (prior['watch'] != item['watch'] or prior['owner'] != item['owner']
                    or prior['acquisition'] != item['acquisition']):
                raise RuntimeError('CoordinationBlocked: backup fact reference mismatch')
            verified = fact(previous, self.target, kind='PublicOwnerLifetime')
            if verified not in item['facts']:
                item['facts'].append(verified)
        verified = fact(receipt, self.target, kind='BridgeProducerClosed')
        if verified not in item['facts']:
            item['facts'].append(verified)
        item['bridge_closed'] = True
        self.save()
        return {}

    def bridge_process_closed(self, value):
        """Exact waitpid closes only this producer, never an IDA owner/lease."""
        item = next((i for i in self.value['entries'].values() if i['watch'] == value['watch']), None)
        if item is None or not item.get('proof'):
            raise RuntimeError('CoordinationBlocked: bridge exit without adopted public proof')
        for namespace, key in (('proofs', digest(item['owner'])),
                               ('observations', digest(item['watch'].encode()))):
            try:
                container = self.target.directory.child(namespace, create=False)
            except FileNotFoundError:
                continue
            try:
                try:
                    producer = container.child(key, create=False)
                except FileNotFoundError:
                    continue
                try:
                    for name in os.listdir(producer.fd):
                        record, _, data = producer.read(name)
                        if record.get('helper') != value['incarnation'] or record.get('watch') != item['watch']:
                            continue
                        if (record.get('owner') != item['owner'] or record.get('acquisition') != item['acquisition']
                                or record.get('subscription_epoch') != item['epoch']):
                            raise RuntimeError('CoordinationBlocked: exited bridge fact mismatch')
                        receipt = {'path':str(producer.path/name), 'sha256':digest(data), 'record':record}
                        verified = fact(receipt, self.target)
                        if verified not in item['facts']:
                            item['facts'].append(verified)
                finally:
                    producer.close()
            finally:
                container.close()
        item['bridge_closed'] = True
        item['bridge_exit'] = value['exit']
        self.save()
        return {}

    def startup_transfer(self, value):
        record = value['consumer']['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        successor_record = record['successor_receipt']['record']
        successor = self.item(value['successor'], successor_record['subscription_epoch'])
        if (record['kind'] != 'StartupTransferred' or record['launch'] != item['launch']
                or record['acquisition'] != item['acquisition'] or successor['lease'] is None
                or record['successor'] != successor['watch'] or successor['acquisition'] != item['acquisition']):
            raise RuntimeError('StartupUnconfirmed: owner custody transfer mismatch')
        verified = fact(value['consumer'], self.target, kind='StartupTransferred')
        for receipt in record['previous_facts']:
            prior = receipt['record']
            if prior['watch'] != item['watch'] or prior['acquisition'] != item['acquisition']:
                raise RuntimeError('StartupUnconfirmed: transferred producer facts mismatch')
            previous = fact(receipt, self.target)
            if previous not in item['facts']:
                item['facts'].append(previous)
        if verified not in item['facts']:
            item['facts'].append(verified)
        item['transferred'] = True
        item['transferred_to'] = successor['epoch']
        item['producer_closed'] = item['consumer_closed'] = item['detached'] = True
        item['unacked_events'] = False
        self.save()

        return {}

    def startup_owner(self, value):
        record = value['receipt']['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        launch = item.get('launch') or item.get('launch_identity')
        owner = record['owner']
        if (record.get('helper') not in self.authorized_producers(item, ('SpawnIntent', 'Spawned'))
                or record['watch'] != item['watch'] or record.get('launch') != launch
                or record['state_root'] != owner['state_root']
                or record['kind'] != 'StartupOwnerSubscribed' or record['acquisition'] != item['acquisition']
                or not launch or not owner['record_id'].endswith('-' + launch['suffix'])
                or owner['canonical_idb_path'] != launch['target'] or owner['backend'] != launch['backend']):
            raise RuntimeError('StartupUnconfirmed: discovered owner binding mismatch')
        verified = fact(value['receipt'], self.target, kind='StartupOwnerSubscribed')
        if item['owner'] is not None and item['owner'] != owner:
            raise RuntimeError('StartupUnconfirmed: owner changed')
        item['owner'] = owner
        item['launch_identity'] = launch
        item['launch'] = None
        item['transferred'] = True
        if verified not in item['facts']:
            item['facts'].append(verified)
        self.save()
        return {}

    def settle(self):
        if self.value.get('file_intents'):
            return
        eligible = [item for item in self.value['entries'].values()
                    if item['producer_closed'] and item['consumer_closed'] and item['detached']
                    and item.get('bridge_closed')
                    and not item['unacked_events'] and not item.get('failure') and not item.get('launch')]
        closed_epochs = {i['epoch'] for i in eligible}
        eligible += [i for i in self.value['entries'].values() if i.get('transferred_to') in closed_epochs
                     and i['producer_closed'] and i['consumer_closed'] and not i['unacked_events']]
        if not eligible:
            return
        # The durable deletion manifest and its recovery verifier use the
        # same epoch order, including startup predecessors of a final owner.
        eligible.sort(key=lambda item:item['epoch'])
        summary = self.value['summary'] + [{'epoch':i['epoch'], 'owner':digest(i['owner']),
                                           'proof':i.get('proof', {}).get('sha256'),
                                           'transferred_to':i.get('transferred_to')} for i in eligible]
        summary = summary[-SUMMARY_LIMIT:]
        while len(encoded(summary)) > SUMMARY_BYTES:
            summary.pop(0)
        epochs = sorted(i['epoch'] for i in eligible)
        intervals = []
        through = self.value['closed_through']
        ranges = self.value['closed_after_holes'] + [[n, n] for n in epochs]
        for start, end in sorted(ranges):
            if start <= through+1:
                through = max(through, end)
            elif intervals and start <= intervals[-1][1]+1:
                intervals[-1][1] = max(intervals[-1][1], end)
            else:
                intervals.append([start, end])
        files = [f for item in eligible for f in item['facts']]
        self.value['summary'] = summary
        self.value['closed_through'] = through
        self.value['closed_after_holes'] = intervals
        self.value['compaction'] = {'epochs':epochs, 'files':files}
        self.save()  # Summary and complete deletion manifest precede every unlink.
        self.resume_compaction()

    def resume_compaction(self):
        intent = self.value.get('compaction')
        if not intent:
            return
        if (not isinstance(intent, dict) or set(intent) != {'epochs', 'files'}
                or not isinstance(intent['epochs'], list) or len(intent['epochs']) > LIMIT
                or any(type(n) is not int for n in intent['epochs'])
                or len(set(intent['epochs'])) != len(intent['epochs']) or not isinstance(intent['files'], list)):
            raise RuntimeError('RoutineCompactionFailed: malformed durable deletion intent')
        expected = [entry for n in intent['epochs'] for entry in self.value['entries'].get(str(n), {}).get('facts', [])]
        if intent['files'] != expected:
            raise RuntimeError('RoutineCompactionFailed: deletion intent differs from exact closed references')
        for epoch in intent['epochs']:
            item = self.value['entries'].get(str(epoch))
            if not item or not (item['producer_closed'] and item['consumer_closed'] and item['detached']
                                and not item['unacked_events'] and not item.get('failure')):
                raise RuntimeError('RoutineCompactionFailed: live reference appeared')
        for entry in intent['files']:
            relative = Path(entry['path']).relative_to(self.target.directory.path)
            if len(relative.parts) != 3 or relative.parts[0] not in ('observations', 'proofs'):
                raise RuntimeError('RoutineCompactionFailed: unsafe deletion manifest')
            container = self.target.directory.child(relative.parts[0], create=False)
            try:
                producer = container.child(relative.parts[1], create=False)
            except FileNotFoundError:
                container.close()
                continue  # An earlier exact deletion completed this directory.
            try:
                try:
                    _, info, data = producer.read(relative.name)
                except FileNotFoundError:
                    continue  # The durable exact intent authorizes only this name.
                if [info.st_dev, info.st_ino] != entry['inode'] or digest(data) != entry['sha256']:
                    raise RuntimeError('RoutineCompactionFailed: immutable fact changed')
                os.unlink(relative.name, dir_fd=producer.fd)
                os.fsync(producer.fd)
            finally:
                try:
                    if not os.listdir(producer.fd):
                        info = os.stat(relative.parts[1], dir_fd=container.fd, follow_symlinks=False)
                        if [info.st_dev, info.st_ino, info.st_uid] != producer.identity:
                            raise RuntimeError('RoutineCompactionFailed: empty observation directory replaced')
                        container.verify()
                        os.rmdir(relative.parts[1], dir_fd=container.fd)
                        os.fsync(container.fd)
                finally:
                    producer.close()
                    container.close()
        for epoch in intent['epochs']:
            self.value['entries'].pop(str(epoch))
        self.value['compaction'] = None
        self.save()


def main():
    value = json.loads(sys.stdin.buffer.readline(1024*1024+1))
    with Target(value['target']) as target:
        if target.key != value['coord_key']:
            raise RuntimeError('CoordinationBlocked: target writer identity mismatch')
        if value['action'] in ('verify_adopt', 'verify_launch', 'verify_observe'):
            journal, _, _ = target.directory.read('custody.json')
            record = value['receipt']['record']
            item = journal['entries'].get(str(record['subscription_epoch']))
            if (journal.get('schema') != 1 or journal['coord_key'] != target.key or not item
                    or item['watch'] != value['watch'] or item['acquisition'] != value['acquisition']):
                raise RuntimeError('CoordinationBlocked: durable custody binding missing')
            if value['action'] in ('verify_adopt', 'verify_observe'):
                if (item['owner'] != value['owner']
                        or (value['action'] == 'verify_adopt' and item['lease'] != value['lease'])):
                    raise RuntimeError('CoordinationBlocked: durable lease binding mismatch')
                fact(value['receipt'], target, kind='Subscribed')
            else:
                if item['launch'] != value['launch'] or record['kind'] not in ('SpawnIntent', 'Spawned'):
                    raise RuntimeError('StartupUnconfirmed: durable launch binding mismatch')
                fact(value['receipt'], target)
            print(json.dumps({'ok':True, 'epoch':item['epoch'], 'revision':journal['revision']}))
            return
        with target.locked(deadline=time.monotonic()+1.5):
            journal = Journal(target)
            action = value['action']
            if action == 'adopt':
                result = journal.adopt(value)
            elif action == 'proof':
                result = journal.proof(value)
            elif action == 'producer_closed':
                result = journal.producer_closed(value)
            elif action == 'bridge_closed':
                result = journal.bridge_closed(value)
            elif action == 'no_attach':
                result = journal.no_attach(value)
            elif action == 'bridge_process_closed':
                result = journal.bridge_process_closed(value)
            elif action == 'startup_transfer':
                result = journal.startup_transfer(value)
            elif action == 'startup_owner':
                result = journal.startup_owner(value)
            elif action == 'settle':
                journal.settle()
                result = {}
            elif action == 'accounting':
                result = journal.accounting()
            else:
                raise ValueError('unknown journal action')
            print(json.dumps({'ok':True, **result}))


if __name__ == '__main__':
    main()
