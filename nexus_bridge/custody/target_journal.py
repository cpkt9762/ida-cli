"""Single-writer target responsibility journal and healthy record settlement.

Only callers holding root SH then this target's stable EX may mutate authority.
Immutable helper facts are verified from their exact descriptor before adoption.
"""
import json
import hashlib
import stat
import os
from pathlib import Path
import sys
import time

from target_coordination import LIMIT, RESERVE, SUMMARY_BYTES, SUMMARY_LIMIT, Target, digest, encoded
from origin import creation_scope, boot_change
from custody_process_identity import capture


def compaction_boundary(_stage, _detail):
    """Deterministic process-exit fault point; production performs no action."""


class OwnerDraining(RuntimeError):
    """A confirmed last ACK retains its physical owner until public proof."""


class StartupPending(RuntimeError):
    """Another exact launch must finish or settle before a new resolution."""


class ObservationPending(RuntimeError):
    """An immutable producer has not finished publishing its reserved fact."""


class RoutineCompactionFailure(OSError):
    """Preserve the underlying errno while naming the failed routine work."""
    def __init__(self,error):
        super().__init__(error.errno,'RoutineCompactionFailed: '+str(error))


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
        return {'path':str(path), 'sha256':digest(data), 'inode':producer.object_identity(info)[:2], 'kind':record['kind']}
    finally:
        if producer is not None:
            producer.close()
        container.close()


class Journal:
    def __init__(self, target, *, recover=True, compact=True):
        if target.target_fd is None:
            raise RuntimeError('target authority requires stable target EX')
        self.target = target
        self.compact_enabled=compact
        if recover:
            target.directory.recover_record('custody.json')
        try:
            self.value, self.info, self.raw = target.directory.read('custody.json')
        except FileNotFoundError:
            self.value = {'schema':1, 'coord_key':target.key, 'revision':0, 'next_epoch':1,
                          'closed_through':0, 'entries':{}, 'summary':[], 'closed_after_holes':[],
                          'compaction':None}
            self.info = self.raw = None
        self.validate()
        if recover and compact:
            self.resume_compaction()

    def validate(self):
        v = self.value
        if (type(v) is not dict or type(v.get('schema')) is not int or v['schema'] != 1
                or encoded(v.get('coord_key')) != encoded(self.target.key) or type(v.get('revision')) is not int
                or type(v.get('next_epoch')) is not int or type(v.get('closed_through')) is not int
                or v['next_epoch'] <= v['closed_through'] or not isinstance(v.get('entries'), dict)
                or len(v['entries']) > LIMIT*8 or not isinstance(v.get('summary'), list)
                or len(v['summary']) > SUMMARY_LIMIT or len(encoded(v['summary'])) > SUMMARY_BYTES
                or not isinstance(v.get('closed_after_holes'), list)):
            raise RuntimeError('CoordinationBlocked: unknown/corrupt custody journal')
        maximum = (1 << 64)-1
        if not (0 <= v['revision'] <= maximum and 0 <= v['closed_through'] < v['next_epoch'] <= maximum):
            raise RuntimeError('CoordinationBlocked: invalid epoch/revision range')
        if 'verification_scope' in v:
            validate_verification_scope(v['verification_scope'],self.target)
        if type(v.get('verification_cleanup_conflict',False)) is not bool:
            raise RuntimeError('VerificationCleanupBlocked: invalid copy conflict')
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
            successor=item.get('nonlast_successor')
            if successor is not None:
                anchor=v['entries'].get(str(successor))
                if (type(successor) is not int or not 0 < successor < item['epoch']
                        or anchor is None or anchor.get('owner') != item.get('owner')):
                    raise RuntimeError('CoordinationBlocked: malformed nonlast observation successor')
            self.retirement(item)
            self.manual_closed(item)
            for reference in item['facts']:
                self.validate_reference(reference)
            closed = item['epoch'] <= v['closed_through'] or any(a <= item['epoch'] <= b for a,b in ranges)
            if closed and (not v.get('compaction') or item['epoch'] not in v['compaction'].get('epochs', [])):
                raise RuntimeError('CoordinationBlocked: closed epoch has an active reference')
        for entry in v['summary']:
            if entry.get('release_binding') is not None:
                if (type(entry.get('epoch')) is not int or not 0 < entry['epoch'] < v['next_epoch']
                        or type(entry['release_binding']) is not str or len(entry['release_binding']) != 64
                        or any(c not in '0123456789abcdef' for c in entry['release_binding'])
                        or type(entry.get('proof')) is not str or len(entry['proof']) != 64):
                    raise RuntimeError('CoordinationBlocked: corrupt closed release binding')
        intents = v.get('file_intents', {})
        if not isinstance(intents, dict) or len(intents) > LIMIT:
            raise RuntimeError('RecoveryBlocked: invalid file intent table')
        for key,item in intents.items():
            if (not isinstance(item, dict) or not isinstance(item.get('path'), str)
                    or not Path(item['path']).is_absolute() or len(key) != 64
                    or item.get('status') not in ('snapshotting', 'failed-owner-held', 'rolling-back',
                                                  'staging','prepared','isolating','publishing')):
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
        self.validate()
        totals = {'live_refs':sum(not i.get('resource_retirement') and not self.manual_closed(i) for i in self.value['entries'].values()),
                  'routine_bytes':len(encoded(self.value['summary'])),
                  'retained_evidence_bytes':sum(len(encoded(i)) for i in self.value['entries'].values()
                                               if i.get('resource_retirement') or self.manual_closed(i)),
                  'namespace_bytes':0, 'routine_files':0}
        totals['legacy_diagnostics']=getattr(self.target,'legacy_diagnostics',[])
        from recovery_files import unpublished
        root_preparations=unpublished(self.target.directory)
        totals['unpublished_preparations']=sorted(root_preparations)
        totals['retained_evidence_bytes']+=sum(os.stat(name,dir_fd=self.target.directory.fd,follow_symlinks=False).st_size
                                              for name in root_preparations)
        scanned = [0]
        def scan(directory, namespace, depth=0):
            with directory.fact_view(shared=True):
                scan_locked(directory, namespace, depth)

        def scan_locked(directory, namespace, depth):
            if depth > 2:
                raise RuntimeError('RetainedEvidenceFull: coordination namespace depth budget')
            preparations=unpublished(directory)
            for name in os.listdir(directory.fd):
                scanned[0] += 1
                if scanned[0] > 4096:
                    raise RuntimeError('RetainedEvidenceFull: coordination namespace count budget')
                info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                if name in preparations:
                    totals['retained_evidence_bytes']+=info.st_size
                    continue
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
        for name in ('lock', 'root.lock', 'target.json', 'volume.json'):
            try:
                totals['namespace_bytes'] += os.stat(name, dir_fd=self.target.directory.fd, follow_symlinks=False).st_size
            except FileNotFoundError:
                pass
        totals.update(routine_limit_bytes=2*1024*1024, retained_evidence_limit_bytes=16*1024*1024,
                      emergency_bytes=256*1024, live_limit=LIMIT-RESERVE, summary_limit=SUMMARY_LIMIT,
                      summary_bytes=len(encoded(self.value['summary'])), namespace_reclaimable_bytes=0)
        percent = totals['retained_evidence_bytes'] * 100 // totals['retained_evidence_limit_bytes']
        totals['retained_warning_percent'] = next((n for n in (100, 95, 80) if percent >= n), 0)
        from recovery_transaction import accounting as file_accounting
        totals.update(file_accounting(self.target))
        return totals

    def save(self):
        if self.info is not None:
            current, info, raw = self.target.directory.read('custody.json')
            if (info.st_dev, info.st_ino, raw) != (self.info.st_dev, self.info.st_ino, self.raw):
                raise RuntimeError('CoordinationBlocked: journal changed outside target writer')
        self.value['revision'] += 1
        self.target.directory.durable('custody.json', self.value)
        _, self.info, self.raw = self.target.directory.read('custody.json')

    def gate(self, state_root=None, acquisition=None, *, cleanup_owner=None):
        from recovery_transaction import inspect_transactions, recovery_name, finish_creation, resume_at_gate
        if not self.target.root_locked:
            finish_creation(self.target)
            from recovery_legacy import resume_pending_imports
            resume_pending_imports(self.target)
            try:self.value,self.info,self.raw=self.target.directory.read('custody.json')
            except FileNotFoundError:
                if self.info is not None:raise
            self.validate()
        # Unknown .new and unrecognized recovery files are never ignored.
        from recovery_files import visible_names,unpublished
        for name in visible_names(self.target.directory):
            if name.endswith('.new'):
                raise RuntimeError('CoordinationBlocked: interrupted durable write retained: ' + name)
            allowed = {'lock','target.json','volume.json','custody.json','proofs','observations','retained'}
            if self.target.root is None:
                allowed.add('root.lock')
            if recovery_name(name):
                continue
            if name not in allowed:
                raise RuntimeError('RecoveryBlocked: unsupported target coordination entry: ' + name)
        self.recover_public_proofs()
        for startup in list(self.value['entries'].values()):
            if startup.get('launch') and not startup.get('owner'):
                self.spawned_dead(startup['watch'], startup['epoch'])
        resume_at_gate(self.target)
        try:self.value,self.info,self.raw=self.target.directory.read('custody.json')
        except FileNotFoundError:
            if self.info is not None:raise
        self.validate()
        for transaction in inspect_transactions(self.target,recover=False):
            if transaction['phase'] not in ('snapshotting','ready','restored','opened','archived'):
                raise RuntimeError('RecoveryBlocked: accepted file job '+transaction['job_id']
                                   +' requires recovery at '+transaction['transaction'])
        for item in self.value['entries'].values():
            if self.retirement(item) or self.manual_closed(item):
                continue
            cleanup = (cleanup_owner is not None and acquisition is not None
                       and acquisition.get('purpose') == 'auxiliary'
                       and item.get('owner') == cleanup_owner
                       and item['acquisition']['parent'] == acquisition['parent']
                       and cleanup_owner.get('state_root') == state_root)
            if item.get('detach_outcome', {}).get('ack_kind') == 'last' and not item.get('proof') and not cleanup:
                raise OwnerDraining('OwnerDraining: last ACK recorded; public owner proof pending')
            if item.get('launch') and not item.get('transferred') and item['acquisition'] != acquisition:
                raise StartupPending('StartupUnconfirmed: exact launch responsibility pending')
            if item.get('owner') and not item.get('proof'):
                if state_root is None or item['owner']['state_root'] != state_root:
                    raise RuntimeError('ObservationRecoveryBlocked: unresolved owner in another state root')
        if self.value.get('file_intents'):
            raise RuntimeError('RecoveryBlocked: retained file intent requires explicit recovery: '
                               + ','.join(self.value['file_intents']))
        self.legacy_diagnostics=getattr(self.target,'legacy_diagnostics',[])
        self.unpublished_preparations=sorted(unpublished(self.target.directory))
        return self.value

    def referenced_record(self, reference):
        relative = Path(reference['path']).relative_to(self.target.directory.path)
        container = self.target.directory.child(relative.parts[0], create=False)
        try:
            directory = container.child(relative.parts[1], create=False)
            try:
                record, info, data = directory.read(relative.name)
                if digest(data) != reference['sha256'] or directory.object_identity(info)[:2] != reference['inode']:
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
                with directory.fact_view(shared=True):
                    from recovery_files import visible_names
                    names = visible_names(directory)
                    if len(names) > 4096:
                        raise RuntimeError('ObservationRecoveryBlocked: fact namespace budget')
                    result = []
                    for name in names:
                        if name.endswith('.new'):
                            raise ObservationPending('ObservationRecoveryBlocked: pending immutable fact retained')
                        try:
                            record, _, data = directory.read(name)
                        except FileNotFoundError as exc:
                            raise ObservationPending('ObservationRecoveryBlocked: fact publication changed during scan') from exc
                        result.append({'path':str(directory.path/name), 'sha256':digest(data), 'record':record})
                    return result
            finally:
                directory.close()
        finally:
            container.close()

    def recover_public_proofs(self):
        """Adopt authorized durable facts without closing any old producer."""
        self.retire_old_boot()
        for item in list(self.value['entries'].values()):
            if self.retirement(item) or self.manual_closed(item):
                continue
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
        if self.compact_enabled:self.settle()

    def file_intent(self, path, status, attempts):
        intents = self.value.setdefault('file_intents', {})
        key = digest(str(path).encode())
        if status in ('opened', 'restored', 'archived') or (status == 'ready' and not attempts):
            intents.pop(key, None)
        else:
            info = path.lstat()
            intents[key] = {'path':str(path), 'status':status, 'inode':[info.st_dev, info.st_ino],
                            'sha256':digest(path.read_bytes())}
        self.save()

    def check_owner(self, owner):
        for item in self.value['entries'].values():
            if (item.get('owner') and not item.get('proof') and not self.retirement(item)
                    and not item.get('transferred_to') and not self.manual_closed(item)
                    and item['owner'] != owner):
                raise RuntimeError('ObservationRecoveryBlocked: different owner without exact lifetime proof')

    def retirement(self, item):
        """Validate persisted authority before consuming any retirement permission."""
        if 'resource_retirement' not in item:
            return None
        evidence = item['resource_retirement']
        if not isinstance(evidence, dict) or type(evidence.get('schema')) is not int or evidence['schema'] != 1:
            raise RuntimeError('CoordinationBlocked: malformed resource retirement schema')
        current = evidence.get('current')
        expected = boot_change(item['origin_binding'], current)
        expected.update(schema=1, watch=item['watch'], epoch=item['epoch'], acquisition=item['acquisition'],
            owner=item.get('owner'), lease=item.get('lease'), launch=item.get('launch'),
            coord_key=self.target.key, target_binding=self.target.binding)
        expected['sha256'] = digest(expected)
        # Canonical bytes distinguish bool from int as well as extra/missing fields.
        if encoded(evidence) != encoded(expected):
            raise RuntimeError('CoordinationBlocked: resource retirement digest/identity binding mismatch')
        boot_change(item['origin_binding'], creation_scope(self.target.directory.path, 'resource-consumer'))
        return evidence

    def require_live(self, item):
        if self.retirement(item) or self.manual_closed(item):
            raise RuntimeError('ObservationClosed: retired boot epoch cannot change historical facts')
        # Ordinary same-boot callbacks need only a native boot recheck. Full
        # machine/volume qualification is required when that boot differs;
        # repeatedly probing disks on every proof/closure delays live cleanup.
        if item['origin_binding'].get('creator', {}).get('boot_id') != capture(os.getpid())['boot_id']:
            self.retire_old_boot()
            if self.retirement(item):
                raise RuntimeError('ObservationClosed: retired boot epoch cannot change historical facts')

    def retire_old_boot(self):
        if not self.value['entries']:
            return {'retirements':[]}  # No resource exists to qualify or retire.
        current = creation_scope(self.target.directory.path, 'resource-consumer')
        changed = False
        for item in self.value['entries'].values():
            if self.retirement(item) or self.manual_closed(item):
                continue
            binding = item['origin_binding']
            if binding.get('creator', {}).get('boot_id') == current['creator']['boot_id']:
                continue
            # Missing historical bindings cannot be assigned to an old boot.
            evidence = boot_change(binding, current)
            evidence.update(schema=1, watch=item['watch'], epoch=item['epoch'], acquisition=item['acquisition'],
                owner=item.get('owner'), lease=item.get('lease'), launch=item.get('launch'),
                coord_key=self.target.key, target_binding=self.target.binding)
            evidence['sha256'] = digest(evidence)
            item['resource_retirement'] = evidence
            item['failure'] = item.get('failure') or 'historical outcome retained after boot resource retirement'
            changed = True
        if changed:
            self.save()  # Durable before returning any permission to drop guards.
        return {'retirements':[i['resource_retirement'] for i in self.value['entries'].values()
                               if i.get('resource_retirement')]}

    def begin(self, acquisition, watch, *, owner=None, launch=None):
        self.settle()
        for item in self.value['entries'].values():
            if item['watch'] == watch:
                self.require_live(item)
                if item['acquisition'] != acquisition or item.get('owner') != owner or item.get('launch') != launch:
                    raise RuntimeError('CoordinationBlocked: conflicting observation identity')
                return item['epoch']
        if owner is not None:
            self.check_owner(owner)
        if len(self.value['entries']) >= LIMIT*8 or self.accounting()['live_refs'] >= LIMIT-RESERVE:
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
        scope = self.value.get('verification_scope')
        if scope is not None and acquisition['parent'] != scope['parent']:
            self.value['verification_cleanup_conflict'] = True
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
        self.require_live(item)
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

    def release_observation(self, value):
        if (type(value.get('epoch')) is not int or value['epoch'] < 1
                or type(value.get('observation_id')) is not str or not 1 <= len(value['observation_id']) <= 128
                or type(value['attempt'].get('sequence')) is not int or value['attempt']['sequence'] < 1):
            raise RuntimeError('CoordinationBlocked: malformed release observation identity')
        if (value['attempt']['target'] != {'kind':'release', 'lease':value['lease']}
                or value['outcome'].get('detach_called') is not False):
            raise RuntimeError('CoordinationBlocked: release observation identity/stage mismatch')
        item = self.value['entries'].get(str(value['epoch']))
        if item is not None:
            item = self.item(value['watch'], value['epoch'])
            if (item['lease'] != value['lease'] or item['owner'] != value['owner']
                    or item['acquisition'] != value['acquisition']):
                raise RuntimeError('CoordinationBlocked: release observation physical identity mismatch')
        else:
            # A closed target reference is never recreated. The bounded summary
            # retains only a binding made by this authority before compaction;
            # old summaries without it cannot grant a late writer permission.
            binding = digest({key:value[key] for key in ('lease','owner','watch','acquisition')})
            item = next((entry for entry in self.value['summary']
                         if entry['epoch'] == value['epoch'] and entry.get('release_binding') == binding), None)
            if item is None or not item.get('proof'):
                raise RuntimeError('ObservationClosed: exact closed release binding missing')
        observation = {k:value[k] for k in ('observation_id', 'attempt', 'outcome')}
        old = item.get('release_observation')
        if old is not None:
            if old['observation_id'] == observation['observation_id']:
                if old != observation:
                    raise RuntimeError('CoordinationBlocked: conflicting release observation')
                return {}
            if old['attempt']['sequence'] >= observation['attempt']['sequence']:
                raise RuntimeError('CoordinationBlocked: stale release observation')
        item['release_observation'] = observation
        if len(encoded(self.value['summary'])) > SUMMARY_BYTES:
            raise RuntimeError('RetainedEvidenceFull: late release summary byte budget')
        if value['outcome'].get('save_guard_error') and 'facts' in item:
            item['failure'] = value['outcome']['save_guard_error']
        self.save()
        return {'epoch':value['epoch'], 'revision':self.value['revision']}

    def detach_outcome(self, value):
        item = self.item(value['watch'], value['epoch'])
        observation = item.get('release_observation')
        outcome = value['outcome']
        if (not observation or observation['attempt'] != value['attempt']
                or item['lease'] != value['lease'] or item['owner'] != value['owner']
                or type(outcome.get('lease_released')) is not bool
                or (outcome['lease_released'] and outcome.get('ack_kind') not in ('last', 'nonlast'))):
            raise RuntimeError('CoordinationBlocked: detach outcome identity/ACK mismatch')
        if item.get('detach_outcome') is not None and item['detach_outcome'] != outcome:
            raise RuntimeError('CoordinationBlocked: conflicting detach outcome')
        item['detach_outcome'] = outcome
        result = {'epoch':item['epoch']}
        # File recovery still requires its exact per-acquisition public proof.
        from recovery_transaction import pinned_epochs
        pinned = pinned_epochs(self.target)
        if (outcome.get('lease_released') is True and outcome.get('ack_kind') == 'nonlast'
                and pinned is not None and item['epoch'] not in pinned
                and not self.value.get('file_intents')):
            anchors = [i for i in self.value['entries'].values()
                       if i['epoch'] < item['epoch'] and i['owner'] == item['owner']
                       and i.get('lease') is not None
                       and not i.get('nonlast_successor') and not i['producer_closed']
                       and self.authorized_producers(i, ('Subscribed',)) == self.authorized_producers(item, ('Subscribed',))
                       and self.authorized_producers(i, ('BridgeSubscribed',)) == self.authorized_producers(item, ('BridgeSubscribed',))]
            if anchors:
                anchor = min(anchors, key=lambda i:i['epoch'])
                if self.authorized_producers(anchor, ('Subscribed',)):
                    result['successor'] = anchor['watch']
                    # Pin before any producer can close. Public-proof settlement
                    # cannot compact this anchor during the handoff window.
                    item['nonlast_successor'] = anchor['epoch']
        self.save()
        result['revision'] = self.value['revision']
        return result

    def nonlast_transfer(self, value):
        receipt = value['consumer']
        record = receipt['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        outcome = item.get('detach_outcome', {})
        successor_record = record['successor_receipt']['record']
        successor = self.item(record['successor'], successor_record['subscription_epoch'])
        from recovery_transaction import pinned_epochs
        pinned = pinned_epochs(self.target)
        if (outcome.get('lease_released') is not True or outcome.get('ack_kind') != 'nonlast'
                or record['owner'] != item['owner'] or record['acquisition'] != item['acquisition']
                or record['helper'] not in self.authorized_producers(item, ('Subscribed',))
                or successor['owner'] != item['owner'] or successor['epoch'] >= item['epoch']
                or successor.get('nonlast_successor') or self.value.get('file_intents')
                or pinned is None or item['epoch'] in pinned):
            raise RuntimeError('CoordinationBlocked: nonlast transfer lacks exact ACK/owner/closure authority')
        fact(record['successor_receipt'], self.target, kind='Subscribed')
        if successor_record['acquisition'] != successor['acquisition']:
            raise RuntimeError('CoordinationBlocked: nonlast successor acquisition mismatch')
        reference = fact(receipt, self.target, kind='NonlastTransferred')
        self.adopt_attempt_facts(item, record['previous_facts'])
        if item.get('nonlast_successor', successor['epoch']) != successor['epoch']:
            raise RuntimeError('CoordinationBlocked: nonlast successor changed')
        item['nonlast_successor'] = successor['epoch']
        if reference not in item['facts']:
            item['facts'].append(reference)
        self.save()
        return {}

    def nonlast_closed(self, value):
        self.nonlast_transfer(value)
        record = value['consumer']['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        bridge = value['bridge_consumer']
        closed = bridge['record']
        if (closed['consumer'] != value['consumer'] or closed['watch'] != item['watch']
                or closed['owner'] != item['owner'] or closed['acquisition'] != item['acquisition']
                or closed['subscription_epoch'] != item['epoch']
                or closed['helper'] not in self.authorized_producers(item, ('BridgeSubscribed',))):
            raise RuntimeError('CoordinationBlocked: nonlast bridge producer closure mismatch')
        reference = fact(bridge, self.target, kind='BridgeNonlastTransferred')
        for previous in closed['previous_facts']:
            prior = previous['record']
            if (prior['watch'] != item['watch'] or prior['owner'] != item['owner']
                    or prior['acquisition'] != item['acquisition'] or prior['subscription_epoch'] != item['epoch']):
                raise RuntimeError('CoordinationBlocked: nonlast backup fact binding mismatch')
            verified = fact(previous, self.target)
            if verified['kind'] not in ('BridgeSubscribed', 'PublicOwnerLifetime'):
                raise RuntimeError('CoordinationBlocked: unexpected nonlast backup fact')
            if verified not in item['facts']:
                item['facts'].append(verified)
        if reference not in item['facts']:
            item['facts'].append(reference)
        item['producer_closed'] = item['consumer_closed'] = item['bridge_closed'] = item['detached'] = True
        item['unacked_events'] = False
        self.save()
        return {}

    def nonlast_exited(self, value):
        self.nonlast_transfer(value)
        self.bridge_process_closed(value)
        item = self.item(value['watch'], value['consumer']['record']['subscription_epoch'])
        item['producer_closed'] = item['consumer_closed'] = item['detached'] = True
        item['unacked_events'] = False
        self.save()
        return {}

    def recovery_permission(self, value):
        """N1's exact original ACK joins public proof for this file obligation."""
        from recovery_transaction import Transaction
        with Transaction(self.target,value['recovery_id']) as transaction:
            item = self.item(value['watch'],value['epoch'])
            requirement = next((r for r in transaction.data['requirements']
                                if r['watch']==item['watch'] and r['epoch']==item['epoch']),None)
            fields = ('acquisition','owner','lease')
            observation = item.get('release_observation')
            if (requirement is None or any(encoded(item.get(k)) != encoded(value.get(k))
                    or encoded(requirement.get(k)) != encoded(value.get(k)) for k in fields)
                    or not item.get('proof') or self.retirement(item)
                    or not observation or observation['attempt'] != value['attempt']
                    or value['attempt']['target'] != {'kind':'release','lease':value['lease']}
                    or value['outcome'].get('lease_released') is not True
                    or value['outcome'].get('ack_kind') not in ('last','nonlast')):
                raise RuntimeError('RecoveryBlocked: N1 file ACK permission binding mismatch')
            permission = {k:value[k] for k in ('recovery_id','attempt','outcome','acquisition','owner','lease','watch','epoch')}
            old = item.get('file_recovery_ack')
            if old is not None:
                if encoded(old) != encoded(permission):
                    raise RuntimeError('RecoveryBlocked: conflicting N1 file ACK permission')
                return {'revision':self.value['revision']}
            item['file_recovery_ack'] = permission
            self.save()
            return {'revision':self.value['revision']}

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
        # Independent authorized public sources can observe the same lifetime.
        # The first durable target receipt remains canonical; retain every
        # valid producer fact until its own closure, without replacing it.
        item.setdefault('proof', verified)
        item['consumer_closed'] = True
        # Public lifetime, unlike absence/EOF, also proves this exact lease is gone.
        item['detached'] = True
        item['unacked_events'] = False
        if verified not in item['facts']:
            item['facts'].append(verified)
        self.save()
        selected = item['proof']
        return {'epoch':item['epoch'], 'revision':self.value['revision'],
                'proof':{'path':selected['path'], 'sha256':selected['sha256'],
                         'record':self.referenced_record(selected)}}

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
            if (verified['kind'] not in ('Subscribed', 'AttachAttempt', 'PublicOwnerLifetime')
                    or (verified['kind'] == 'PublicOwnerLifetime' and
                        record['helper'] not in self.authorized_producers(item,
                            ('Subscribed', 'StartupOwnerSubscribed', 'BridgeSubscribed')))):
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
        # Publishing a terminal before the IPC receipt is not permission to
        # compact it. Rust independently verifies both producers and signs
        # acceptance before this final reference can be removed.
        item['unacked_events'] = value.get('custody_accepted') is not True
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

    def bridge_absent(self, value):
        record = value['proof']['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        if (not item.get('launch_identity', item.get('launch')) or item['lease'] is not None
                or not item.get('proof') or item['proof']['sha256'] != value['proof']['sha256']
                or item['owner'] != record['owner']
                or item['acquisition'] != record['acquisition']
                or record.get('evidence_type') != 'public_owner_lifetime'
                or self.authorized_producers(item, ('BridgeSubscribed',))
                or not self.authorized_producers(item, ('StartupOwnerSubscribed',))):
            raise RuntimeError('CoordinationBlocked: absent bridge producer lacks startup/public proof')
        fact(value['proof'], self.target, kind='PublicOwnerLifetime')
        absence = {'incarnation':value['incarnation'], 'proof_sha256':value['proof']['sha256']}
        if item.get('bridge_absent', absence) != absence:
            raise RuntimeError('CoordinationBlocked: conflicting absent bridge producer')
        item['bridge_absent'] = absence
        item['bridge_closed'] = True
        self.save()
        return {}

    def bridge_process_closed(self, value):
        """Exact waitpid closes only this producer, never an IDA owner/lease."""
        item = next((i for i in self.value['entries'].values() if i['watch'] == value['watch']), None)
        if item is None or not (item.get('proof') or (item.get('nonlast_successor')
                and any(f['kind'] == 'NonlastTransferred' for f in item['facts']))):
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
                    from recovery_files import visible_names
                    for name in visible_names(producer):
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
        # Discovery may have bound the spawned owner before final acquisition.
        # The immutable launch identity survives that transition.
        launch = item.get('launch') or item.get('launch_identity')
        if (record['kind'] != 'StartupTransferred' or record['launch'] != launch
                or record['acquisition'] != item['acquisition'] or successor['lease'] is None
                or (item.get('owner') is not None and item['owner'] != successor['owner'])
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

    def launch_abandoned(self, value):
        """Close exactly an unclaimed launch with a durable revoked decision."""
        receipt = value['consumer']
        record = receipt['record']
        item = self.item(value['watch'], record['subscription_epoch'])
        existing = item.get('launch_abandoned')
        if existing is not None:
            if existing['sha256'] != receipt['sha256']:
                raise RuntimeError('StartupUnconfirmed: conflicting launch abandonment')
            return {}
        evidence = record.get('evidence')
        launch = item.get('launch')
        if (record.get('kind') != 'LaunchAbandonedUnspawned' or not launch or record.get('launch') != launch
                or record.get('acquisition') != item['acquisition'] or item['lease'] is not None
                or item.get('owner') or item.get('proof') or record.get('owner') is not None
                or record.get('os_identity') is not None
                or any(f['kind'] not in ('SpawnIntent',) for f in item['facts'])
                or record.get('helper') not in self.authorized_producers(item, ('SpawnIntent',))
                or not isinstance(evidence, dict)
                or not launch.get('authorization')
                or evidence.get('authorization') != launch['authorization']
                or evidence.get('decision') != 'revoked'
                or evidence.get('suffix') != launch['suffix'] or evidence.get('target') != launch['target']
                or type(evidence.get('bridge', {}).get('exited_secs')) not in (int, float)
                or evidence['bridge']['exited_secs'] < 0):
            raise RuntimeError('StartupUnconfirmed: launch abandonment lacks exact unspawned evidence')
        from ida_nexus._launch_authorization import revoked
        if not revoked(launch['authorization'], launch['suffix'], launch['target']):
            raise RuntimeError('StartupUnconfirmed: launch authorization is not revoked')
        verified = fact(receipt, self.target, kind='LaunchAbandonedUnspawned')
        item['facts'].append(verified)
        item['launch_abandoned'] = verified
        # Same shape as a transferred startup: the immutable launch identity is
        # kept, the live launch marker is cleared so ordinary compaction applies.
        item['launch_identity'] = launch
        item['launch'] = None
        item['bridge_exit'] = evidence['bridge']
        item['producer_closed'] = item['consumer_closed'] = item['detached'] = item['bridge_closed'] = True
        item['unacked_events'] = False
        self.save()
        return {}

    def spawned_dead(self, watch, epoch):
        """Target EX serializes an independent launch-exit fact, including restart.

        This producer never writes another helper's registry or sequence. Its
        deterministic immutable slot is distinct from every helper's facts.
        """
        item = self.value['entries'].get(str(epoch))
        if item is None:
            if epoch <= self.value['closed_through'] or any(
                    a <= epoch <= b for a, b in self.value['closed_after_holes']):
                return {'state':'closed'}
            raise RuntimeError('StartupUnconfirmed: unknown startup epoch')
        if item['watch'] != watch:
            raise RuntimeError('StartupUnconfirmed: mismatched startup watch')
        if item.get('spawned_death'):
            return {'state':'dead', 'consumer':self.death_receipt(item)}
        if (not item.get('launch') or item.get('owner') or item.get('proof')
                or item.get('lease') or any(f['kind'] not in ('SpawnIntent', 'Spawned') for f in item['facts'])):
            return {'state':'not_applicable'}
        sources = [self.referenced_record(f) for f in item['facts'] if f['kind'] == 'Spawned']
        if len(sources) != 1:
            return {'state':'not_applicable'}
        source = sources[0]
        launch = item['launch']
        if (source.get('watch') != watch or source.get('subscription_epoch') != epoch
                or source.get('acquisition') != item['acquisition'] or source.get('launch') != launch
                or source.get('owner') is not None or not launch.get('authorization')):
            raise RuntimeError('StartupUnconfirmed: incomplete Spawned binding')
        from custody_process_identity import same_boot_exit
        evidence = same_boot_exit(source.get('os_identity'))
        if evidence is None:
            return {'state':'pending'}
        # Read the durable single-use permit independently. It permanently fences
        # a second claimant; no suffix scan or discovery absence grants closure.
        from ida_nexus._launch_authorization import _directory, _read
        name, directory = _directory(launch['authorization'])
        try:
            grant = {'schema':1, 'suffix':launch['suffix'], 'target':launch['target']}
            if (_read(directory, name) != grant
                    or _read(directory, name + '.decision') != dict(grant, decision='claimed')):
                raise RuntimeError('StartupUnconfirmed: launch is not durably claimed')
        finally:
            os.close(directory)
        container = self.target.directory.child('observations')
        try:
            producer = container.child(digest(watch.encode()))
            try:
                with producer.fact_view():
                    from recovery_files import visible_names
                    for name in visible_names(producer):
                        if name.endswith('.new'):
                            raise ObservationPending('StartupUnconfirmed: pending startup publication')
                        record, _, _ = producer.read(name)
                        if (record.get('watch') != watch or record.get('acquisition') != item['acquisition']
                                or record.get('subscription_epoch') != epoch):
                            raise RuntimeError('StartupUnconfirmed: conflicting startup namespace')
                        if record.get('owner') is not None or record.get('kind') in (
                                'StartupOwnerSubscribed', 'StartupTransferred', 'AttachAttempt', 'PublicOwnerLifetime'):
                            return {'state':'not_applicable'}
                    helper = 'target-spawned-death-' + digest(watch.encode())
                    name = helper + '-' + str(epoch) + '.json'
                    try:
                        record, _, _ = producer.read(name)
                    except FileNotFoundError:
                        record = dict(source, helper=helper, seq=epoch,
                            observation_id=helper + '-' + str(epoch),
                            kind='SpawnedOwnerDiedUnpublished', evidence=evidence,
                            source_spawned=digest(source))
                        producer.retry_immutable(name, record)
                    # A prior completed fact may follow a crash before custody.json.
                    saved_evidence = record.get('evidence')
                    expected = dict(source, helper=helper, seq=epoch,
                        observation_id=helper + '-' + str(epoch),
                        kind='SpawnedOwnerDiedUnpublished', evidence=saved_evidence,
                        source_spawned=digest(source))
                    if (encoded(record) != encoded(expected) or not isinstance(saved_evidence, dict)
                            or saved_evidence.get('recorded') != source['os_identity']
                            or same_boot_exit(source['os_identity'],
                                read=lambda pid: saved_evidence.get('current'),
                                current_boot=lambda: saved_evidence.get('boot_id')) != saved_evidence):
                        raise RuntimeError('StartupUnconfirmed: conflicting spawned death fact')
                    receipt = {'path':str(producer.path/name), 'sha256':digest(record), 'record':record}
                    verified = fact(receipt, self.target, kind='SpawnedOwnerDiedUnpublished')
            finally:
                producer.close()
        finally:
            container.close()
        # Publication and adoption are separate durable steps. Native death was
        # rechecked above even when retrying a previously published fact.
        item['facts'].append(verified)
        item['spawned_death'] = verified
        item['spawned_death_pending'] = True
        item['spawned_death_helper'] = source['helper_registration']['identity']
        item['launch_identity'], item['launch'] = launch, None
        item['producer_closed'] = item['consumer_closed'] = item['detached'] = item['bridge_closed'] = True
        item['unacked_events'] = False
        self.save()
        return {'state':'dead', 'consumer':receipt}

    def spawned_dead_ack(self, watch, epoch):
        item = self.value['entries'].get(str(epoch))
        if item is None:
            return self.spawned_dead(watch, epoch)
        if item['watch'] != watch or not item.get('spawned_death'):
            raise RuntimeError('StartupUnconfirmed: death ACK lacks exact journal closure')
        item['spawned_death_pending'] = False
        self.save()
        return {}

    def death_helper_retired(self, item):
        if not item.get('spawned_death_pending'):
            return True
        from custody_process_identity import same_boot_exit
        return same_boot_exit(item.get('spawned_death_helper')) is not None

    def death_receipt(self, item):
        reference = item['spawned_death']
        record = self.referenced_record(reference)
        return {'path':reference['path'], 'sha256':reference['sha256'], 'record':record}

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
        try:return self.settle_closed()
        except RoutineCompactionFailure:raise
        except OSError as error:raise RoutineCompactionFailure(error) from error

    def settle_closed(self):
        if self.value.get('compaction'):
            self.resume_compaction()
        if self.value.get('file_intents'):
            return
        from recovery_transaction import pinned_epochs
        pinned = pinned_epochs(self.target)
        if pinned is None:
            return
        eligible = [item for item in self.value['entries'].values()
                    if item['producer_closed'] and item['consumer_closed'] and item['detached']
                    and item.get('bridge_closed')
                    and not item['unacked_events'] and not item.get('failure') and not item.get('launch')
                    and not item.get('manual_offline_recovery')
                    and self.death_helper_retired(item)
                    and item['epoch'] not in pinned]
        eligible_epochs={i['epoch'] for i in eligible}
        eligible=[item for item in eligible if not any(i.get('nonlast_successor') == item['epoch']
                  and i['epoch'] not in eligible_epochs for i in self.value['entries'].values())]
        closed_epochs = {i['epoch'] for i in eligible}
        eligible += [i for i in self.value['entries'].values() if i.get('transferred_to') in closed_epochs
                     and i['producer_closed'] and i['consumer_closed'] and not i['unacked_events']
                     and not i.get('manual_offline_recovery') and i['epoch'] not in pinned]
        if not eligible:
            return
        # The durable deletion manifest and its recovery verifier use the
        # same epoch order, including startup predecessors of a final owner.
        eligible.sort(key=lambda item:item['epoch'])
        summary = self.value['summary'] + [{'epoch':i['epoch'], 'owner':digest(i['owner']),
                                           'proof':i.get('proof', {}).get('sha256'),
                                           'transferred_to':i.get('transferred_to'),
                                           'release_binding':digest({k:i[k] for k in ('lease','owner','watch','acquisition')})
                                               if i.get('lease') and i.get('proof') else None,
                                           'release_observation':i.get('release_observation'),
                                           'detach_outcome':i.get('detach_outcome')} for i in eligible]
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
        compaction_boundary('intent_durable',self.value['compaction'])
        self.resume_compaction()

    def manual_closed(self, item):
        permission=item.get('manual_offline_recovery')
        if permission is None:
            return False
        if type(permission) is not dict or set(permission) != {'name','sha256'}:
            raise RuntimeError('MaintenanceBlocked: invalid manual resource certificate')
        if permission['name'] != permission['sha256']+'.json':
            raise RuntimeError('MaintenanceBlocked: invalid manual resource certificate name')
        retained=self.target.directory.child('retained',create=False)
        directory=None
        try:
            directory=retained.child('manual',create=False)
            record,_,raw=directory.read(permission['name'])
            original={k:v for k,v in item.items() if k != 'manual_offline_recovery'}
            if (digest(raw) != permission['sha256'] or record.get('schema') != 1
                    or record.get('kind') != 'manual_offline_recovery'
                    or encoded(record.get('coord_key')) != encoded(self.target.key)
                    or record.get('target') != self.target.original
                    or encoded(record.get('resource')) != encoded(original)):
                raise RuntimeError('MaintenanceBlocked: manual resource/target changed')
            plan=record['permission']['plan']
            if (digest(plan) != record['permission']['plan_sha256']
                    or plan['operator']['uid'] != os.getuid()
                    or plan['operator']['confirmation'] != 'I established and maintain this exclusive offline window'
                    or not plan['window']['started_at'] <= record['permission']['applied_at'] < plan['window']['expires_at']):
                raise RuntimeError('MaintenanceBlocked: invalid historical offline operator authorization')
            return True
        finally:
            if directory is not None:directory.close()
            retained.close()

    def complete_manual(self, permission):
        # Called only after the accepted file transaction has restored/archived.
        # The old ACK, operation and public-proof fields are retained verbatim.
        from recovery_transaction import Transaction
        with Transaction(self.target,permission['plan']['transaction'],recover=False) as transaction:
            transaction.validate_manual_permission(permission)
            if transaction.data['status'] not in ('restored','opened','archived'):
                raise RuntimeError('MaintenanceBlocked: file work has not completed')
        expected=permission['plan']['stopped_openers']
        retained=self.target.directory.child('retained')
        directory=None
        try:
            directory=retained.child('manual')
            for identity in expected:
                item=self.value['entries'].get(str(identity['epoch']))
                if item is None or item['watch'] != identity['watch']:
                    raise RuntimeError('MaintenanceBlocked: offline resource disappeared')
                if any(encoded(item.get(k)) != encoded(v) for k,v in identity.items()):
                    raise RuntimeError('MaintenanceBlocked: resource changed before offline completion')
                if self.manual_closed(item):continue
                record={'schema':1,'kind':'manual_offline_recovery','target':self.target.original,
                        'coord_key':self.target.key,'resource':__import__('copy').deepcopy(item),'permission':permission}
                checksum=digest(record)
                name=checksum+'.json'
                directory.recover_record(name)
                try:stored,_,_=directory.read(name)
                except FileNotFoundError:directory.durable(name,record,immutable=True)
                else:
                    if encoded(stored) != encoded(record):
                        raise RuntimeError('MaintenanceBlocked: offline certificate conflict')
                item['manual_offline_recovery']={'name':name,'sha256':checksum}
                self.save()
        finally:
            if directory is not None:directory.close()
            retained.close()

    def resume_compaction(self):
        try:return self.resume_compaction_locked()
        except RoutineCompactionFailure:raise
        except OSError as error:raise RoutineCompactionFailure(error) from error

    def resume_compaction_locked(self):
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
        from recovery_transaction import pinned_epochs
        pinned = pinned_epochs(self.target)
        if self.value.get('file_intents') or pinned is None or set(intent['epochs']) & pinned:
            raise RuntimeError('RoutineCompactionFailed: file recovery acquired a new reference')
        if any(i.get('nonlast_successor') in intent['epochs'] and i['epoch'] not in intent['epochs']
               for i in self.value['entries'].values()):
            raise RuntimeError('RoutineCompactionFailed: nonlast observation successor still referenced')
        for epoch in intent['epochs']:
            item = self.value['entries'].get(str(epoch))
            if not item or not (item['producer_closed'] and item['consumer_closed'] and item['detached']
                                and not item['unacked_events'] and not item.get('failure')
                                and not item.get('manual_offline_recovery')
                    and self.death_helper_retired(item)
                                and (item.get('bridge_closed') or item.get('transferred_to') in intent['epochs'])
                                and (not item.get('launch') or item.get('transferred_to') in intent['epochs'])):
                raise RuntimeError('RoutineCompactionFailed: live reference appeared')
        paths={entry['path'] for entry in intent['files']}
        if any(reference['path'] in paths for key,item in self.value['entries'].items()
               if int(key) not in intent['epochs'] for reference in item['facts']):
            raise RuntimeError('RoutineCompactionFailed: another epoch still references deletion manifest')
        for entry in intent['files']:
            relative = Path(entry['path']).relative_to(self.target.directory.path)
            if len(relative.parts) != 3 or relative.parts[0] not in ('observations', 'proofs'):
                raise RuntimeError('RoutineCompactionFailed: unsafe deletion manifest')
            container = self.target.directory.child(relative.parts[0], create=False)
            try:
                producer = container.child(relative.parts[1], create=False)
            except FileNotFoundError:
                os.fsync(container.fd)
                container.close()
                continue  # An earlier exact deletion completed this directory.
            try:
                try:
                    _, info, data = producer.read(relative.name)
                except FileNotFoundError:
                    os.fsync(producer.fd)
                    continue  # The durable exact intent authorizes only this name.
                except (json.JSONDecodeError,UnicodeDecodeError) as error:
                    raise RuntimeError('RoutineCompactionFailed: immutable fact is corrupt; evidence retained') from error
                if producer.object_identity(info)[:2] != entry['inode'] or digest(data) != entry['sha256']:
                    raise RuntimeError('RoutineCompactionFailed: immutable fact changed')
                compaction_boundary('before_unlink',entry)
                os.unlink(relative.name, dir_fd=producer.fd)
                compaction_boundary('after_unlink',entry)
                os.fsync(producer.fd)
                compaction_boundary('file_directory_fsynced',entry)
            finally:
                try:
                    if not os.listdir(producer.fd):
                        info = os.stat(relative.parts[1], dir_fd=container.fd, follow_symlinks=False)
                        if producer.object_identity(info) != producer.identity:
                            raise RuntimeError('RoutineCompactionFailed: empty observation directory replaced')
                        container.verify()
                        os.rmdir(relative.parts[1], dir_fd=container.fd)
                        compaction_boundary('producer_removed',entry)
                        os.fsync(container.fd)
                        compaction_boundary('container_fsynced',entry)
                finally:
                    producer.close()
                    container.close()
        for epoch in intent['epochs']:
            self.value['entries'].pop(str(epoch))
        self.value['compaction'] = None
        self.save()
        compaction_boundary('committed',{'closed_through':self.value['closed_through']})



def verification_file(path):
    """Bind a private regular payload through the exact descriptor read."""
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022):
        raise RuntimeError('VerificationCleanupBlocked: foreign/link payload retained: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    digest = hashlib.sha256()
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError('VerificationCleanupBlocked: payload replaced before read')
        for chunk in iter(lambda:stream.read(1024*1024), b''):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    signature = lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    if signature(before) != signature(after) or signature(before) != signature(current):
        raise RuntimeError('VerificationCleanupBlocked: payload changed during read')
    return {'identity':[before.st_dev,before.st_ino,before.st_uid],
            'size':before.st_size,'sha256':digest.hexdigest()}


def verification_parent(parent):
    def identifier(value):
        return (type(value) is str and 1 <= len(value) <= 128
                and all(c.isascii() and (c.isalnum() or c in '-_.:') for c in value))
    if (type(parent) is not dict or set(parent) != {'client_id','request_id','operation_id','task_id'}
            or any(not identifier(parent[key]) for key in ('client_id','request_id','operation_id'))
            or (parent['task_id'] is not None and not identifier(parent['task_id']))):
        raise RuntimeError('VerificationCleanupBlocked: invalid exact parent identity')
    return parent


def validate_verification_scope(scope,target):
    if (type(scope) is not dict or set(scope) != {'schema','parent','directory'}
            or type(scope.get('schema')) is not int or scope['schema'] != 1
            or type(scope.get('directory')) is not list or len(scope['directory']) != 3
            or any(type(n) is not int or n < 0 for n in scope['directory'])
            or scope['directory'] != target.key.get('parent')):
        raise RuntimeError('VerificationCleanupBlocked: invalid copy scope')
    verification_parent(scope['parent'])
    return scope


def require_verification_scope(target,parent):
    """Cleanup consumes existing authority; it never initializes or repairs it."""
    verification_parent(parent)
    journal=Journal(target,recover=False)
    if 'verification_scope' not in journal.value:
        raise RuntimeError('VerificationCleanupBlocked: existing copy authority missing')
    scope=validate_verification_scope(journal.value['verification_scope'],target)
    if scope['parent'] != parent:
        raise RuntimeError('VerificationCleanupBlocked: copy ownership changed')
    if journal.value.get('verification_cleanup_conflict'):
        raise RuntimeError('VerificationCleanupBlocked: newer journal responsibility retained')
    def validate_pending(data):
        from copy import copy
        value = json.loads(data)
        candidate = copy(journal)
        candidate.value = value
        candidate.validate()
        scope = validate_verification_scope(value.get('verification_scope'),target)
        if scope['parent'] != parent or value.get('verification_cleanup_conflict',False):
            raise RuntimeError('VerificationCleanupBlocked: pending copy authority changed')
    if target.directory.recover_record('custody.json', validate=validate_pending):
        journal = Journal(target,recover=False)
    journal.resume_compaction()
    return journal


def verification_scope(target,parent,*,reuse=False):
    """Initialize once; explicitly renew only a fully closed verification copy."""
    verification_parent(parent)
    if type(reuse) is not bool:
        raise RuntimeError('VerificationCleanupBlocked: invalid reuse flag')
    journal=Journal(target,recover=False,compact=False)
    if 'verification_scope' in journal.value:
        if reuse:
            scope=validate_verification_scope(journal.value['verification_scope'],target)
            if scope['parent'] != parent:
                verification_reusable(target,journal)
                journal.value['verification_scope']={'schema':1,'parent':parent,'directory':list(target.key['parent'])}
                journal.save()
                return journal
        return require_verification_scope(target,parent)
    if reuse:
        raise RuntimeError('VerificationCleanupBlocked: reuse requires existing copy authority')
    if (journal.info is not None or journal.value['next_epoch'] != 1
            or journal.value['closed_through'] != 0 or journal.value['entries']
            or journal.value['summary'] or journal.value['closed_after_holes']
            or journal.value.get('compaction') or journal.value.get('file_intents')
            or journal.value.get('verification_cleanup_conflict')):
        raise RuntimeError('VerificationCleanupBlocked: late initialization cannot replace authorization history')
    journal.value['verification_scope']={'schema':1,'parent':parent,'directory':list(target.key['parent'])}
    journal.save()
    return journal


def verification_reusable(target,journal):
    """Under root SH and target EX, keep every lock/epoch and reject live refs."""
    value=journal.value
    if (value['entries'] or value.get('compaction') or value.get('file_intents')
            or value.get('verification_cleanup_conflict') or value['closed_after_holes']
            or value['closed_through'] != value['next_epoch']-1):
        raise RuntimeError('VerificationCleanupBlocked: reuse has unsettled obligations')
    allowed={'lock','root.lock','target.json','custody.json','volume.json','observations','proofs','retained'}
    names=set(os.listdir(target.directory.fd))
    if names-allowed:
        raise RuntimeError('VerificationCleanupBlocked: reuse has unknown/pending evidence')
    for name in names & {'observations','proofs','retained'}:
        directory=target.directory.child(name,create=False)
        try:
            with directory.fact_view(shared=True):
                if os.listdir(directory.fd):
                    raise RuntimeError('VerificationCleanupBlocked: reuse has producer/evidence/scratch references')
        finally:
            directory.close()
    if set(os.listdir(target.target.parent))-{'input',target.target.name,target.directory.path.name}:
        raise RuntimeError('VerificationCleanupBlocked: reuse has stale payload/closure receipt')


def verification_probe_cleanup(target, state_root, parent):
    """Delete database payload only here, while current authority holds EX.

    The immutable input remains for Rust publication. The consumer receives
    exact completed-removal facts; it never gains permission to delete a probe.
    """
    from cache_store import public_owner_probe, sync_directory
    from ida_nexus import probe_database_state
    journal = require_verification_scope(target,parent)
    journal.gate(state_root)
    if journal.value.get('verification_cleanup_conflict'):
        raise RuntimeError('VerificationCleanupBlocked: newer journal responsibility retained')
    for item in journal.value['entries'].values():
        if not (item.get('proof') or journal.retirement(item) or item.get('no_attach') or item.get('no_launch')):
            raise ObservationPending('verification exact resource proof still pending')
        if not journal.retirement(item) and not (item['producer_closed'] and item['consumer_closed'] and not item['unacked_events']):
            raise ObservationPending('verification producer/consumer closure still pending')
    journal.settle()
    reason = public_owner_probe(target.target)
    state = probe_database_state(target.target)
    if reason or state['state'] in ('in_use','unknown') or state.get('error'):
        raise RuntimeError('VerificationCleanupBlocked: current owner/file occupancy: ' + str(reason or state))
    directory = target.target.parent
    marker = directory/'closed'
    stem = target.target.stem
    database_names = {target.target.name, *(stem+ext for ext in ('.id0','.id1','.id2','.nam','.til'))}
    names = set(os.listdir(directory))
    allowed = database_names | {'input','closed',target.directory.path.name}
    if names-allowed:
        raise RuntimeError('VerificationCleanupBlocked: unknown namespace retained: ' + ','.join(sorted(names-allowed)))
    binding = {'schema':1,'kind':'verification_probe_cleanup',
        'directory':list(target.key['parent']),'target':str(target.target),'coord_key':target.key,
        'target_sha256':digest((target.directory.path/'target.json').read_bytes()),
        'journal_sha256':digest((target.directory.path/'custody.json').read_bytes())}
    if marker.exists() or marker.is_symlink():
        info = marker.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError('VerificationCleanupBlocked: untrusted closure receipt')
        previous = json.loads(marker.read_bytes())
        if any(previous.get(k) != v for k,v in binding.items()) or names & database_names:
            raise RuntimeError('VerificationCleanupBlocked: stale closure cannot authorize later payload')
        return previous
    if 'input' not in names and not names & database_names:
        return {'payload_absent':True}  # Exact consumer already removed its input/receipt.
    inputs = verification_file(directory/'input') if 'input' in names else None
    payload = [(directory/name,verification_file(directory/name)) for name in sorted(names & database_names)]
    for path, expected in payload:
        if verification_file(path) != expected:
            raise RuntimeError('VerificationCleanupBlocked: payload changed before unlink')
    for path, expected in payload:
        if verification_file(path) != expected:
            raise RuntimeError('VerificationCleanupBlocked: payload replaced at unlink')
        path.unlink()
    sync_directory(directory)
    receipt = dict(binding,input=inputs,removed=[{'name':path.name,'file':value} for path,value in payload])
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,0o600)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(encoded(receipt));stream.flush();os.fsync(stream.fileno())
    sync_directory(directory)
    return receipt


def verification_snapshot(directory):
    # The SDK callback still owns target EX; this verifier must remain read-only.
    # Atomic publisher replacement is retried with all FD/path checks intact.
    for attempt in range(8):
        try:
            return directory.read('custody.json')
        except RuntimeError as error:
            if str(error) != 'CoordinationBlocked: record changed during read' or attempt == 7:
                raise



def main():
    value = json.loads(sys.stdin.buffer.readline(1024*1024+1))
    with Target(value['target']) as target:
        if target.key != value['coord_key']:
            raise RuntimeError('CoordinationBlocked: target writer identity mismatch')
        if value['action'] in ('verify_adopt', 'verify_launch', 'verify_observe'):
            journal, _, _ = verification_snapshot(target.directory)
            record = value['receipt']['record']
            item = journal['entries'].get(str(record['subscription_epoch']))
            if (journal.get('schema') != 1 or journal['coord_key'] != target.key or not item
                    or item['watch'] != value['watch'] or item['acquisition'] != value['acquisition']):
                raise RuntimeError('CoordinationBlocked: durable custody binding missing')
            if 'resource_retirement' in item:
                raise RuntimeError('ObservationClosed: retired epoch cannot authorize new custody')
            if value['action'] in ('verify_adopt', 'verify_observe'):
                if (item['owner'] != value['owner']
                        or (value['action'] == 'verify_adopt' and item['lease'] != value['lease'])):
                    raise RuntimeError('CoordinationBlocked: durable lease binding mismatch')
                fact(value['receipt'], target, kind='Subscribed')
            else:
                if item['launch'] != value['launch'] or record['kind'] not in ('SpawnIntent', 'Spawned'):
                    raise RuntimeError('StartupUnconfirmed: durable launch binding mismatch')
                fact(value['receipt'], target)
            print(json.dumps({'ok':True, 'epoch':item['epoch'], 'revision':journal['revision'],
                              'origin_binding':item['origin_binding'],'native_coord_key':target.native_key}))
            return
        with target.locked(deadline=time.monotonic()+1.5,
                           recover=value['action'] != 'verification_probe_cleanup'):
            action = value['action']
            # Cleanup must validate its existing authority before even a
            # constructor can resume a durable deletion intent.
            if action == 'verification_probe_cleanup':
                result = verification_probe_cleanup(target,value['state_root'],value['parent'])
                print(json.dumps({'ok':True, **result}))
                return
            journal = Journal(target,compact=action in ('settle','accounting'))
            if action == 'adopt':
                result = journal.adopt(value)
            elif action == 'release_observation':
                result = journal.release_observation(value)
            elif action == 'detach_outcome':
                result = journal.detach_outcome(value)
            elif action == 'nonlast_transfer':
                result = journal.nonlast_transfer(value)
            elif action == 'nonlast_closed':
                result = journal.nonlast_closed(value)
            elif action == 'nonlast_exited':
                result = journal.nonlast_exited(value)
            elif action == 'recovery_permission':
                result = journal.recovery_permission(value)
            elif action == 'retire_old_boot':
                result = journal.retire_old_boot()
            elif action == 'proof':
                result = journal.proof(value)
            elif action == 'producer_closed':
                result = journal.producer_closed(value)
            elif action == 'bridge_absent':
                result = journal.bridge_absent(value)
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
            elif action == 'spawned_dead_ack':
                result = journal.spawned_dead_ack(value['watch'], value['epoch'])
            elif action == 'spawned_dead':
                result = journal.spawned_dead(value['watch'], value['epoch'])
            elif action == 'launch_abandoned':
                result = journal.launch_abandoned(value)
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
