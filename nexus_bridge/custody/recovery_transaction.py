"""One target-side v2 file transaction and one epoch-fenced executor.

Lease/delivery/operation state remains in N1. This journal owns only file
intents, retained component evidence and directional executor authorization.
"""
import copy
from functools import wraps
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

from custody_process_identity import capture
from target_coordination import Directory, digest, encoded, identity
from recovery_files import (boundary, compatible, component_names, copy_exact,
                            file_info, inventory, rename_exact, validate_info)

PHASES = frozenset(('snapshotting','ready','failed-owner-held','staging','prepared',
                    'isolating','publishing','restored','opened','archived'))
EXECUTING = frozenset(('LocalExecuting','Accepted','Resumed'))
MAX_TRANSACTIONS = 96
FILE_LIMIT = 2*1024*1024*1024
FINISH_RESERVE = 1024*1024


def serialized(method):
    @wraps(method)
    def run(self, *args, **kwargs):
        if self.token is None:
            raise RuntimeError('RecoveryExecutorStale: no local execution token')
        with self.token.mutex:
            return method(self,*args,**kwargs)
    return run


def recovery_name(value):
    return type(value) is str and len(value) == 32 and all(c in '0123456789abcdef' for c in value)


class ExecutorToken:
    """Unique in-process authority; serializable identities alone grant no I/O."""
    def __init__(self, actor=None, epoch=1):
        self.actor = actor or {'incarnation':uuid.uuid4().hex,'native':capture(os.getpid())}
        self.epoch, self.valid = epoch, True
        self.mutex = threading.RLock()

    def __copy__(self):
        raise TypeError('recovery executor cannot be copied; move it')

    def __deepcopy__(self, _memo):
        raise TypeError('recovery executor cannot be copied; move it')

    def move(self):
        with self.mutex:
            self.check()
            moved = ExecutorToken(self.actor, self.epoch)
            moved.mutex = self.mutex
            self.valid = False
            return moved

    def check(self):
        if not self.valid or self.actor['native'] != capture(os.getpid()):
            raise RuntimeError('RecoveryExecutorStale: moved/frozen/forked executor')


class Transaction:
    def __init__(self, target, recovery_id, *, token=None, recover=True):
        if target.target_fd is None or not recovery_name(recovery_id):
            raise RuntimeError('RecoveryBlocked: target EX and exact RecoveryId required')
        self.target, self.recovery_id, self.token = target, recovery_id, token
        self.directory = target.directory.child(recovery_id, create=False)
        self.parent = None
        try:
            if recover:
                self.directory.recover_record('recovery.json')
            self.data, self.info, self.raw = self.directory.read('recovery.json')
            self.validate()
        except BaseException:
            self.close()
            raise

    @classmethod
    def create(cls, target, *, on_begin=None):
        from origin import creation_scope
        if target.target_fd is None:
            raise RuntimeError('RecoveryBlocked: creation requires target EX')
        if len([name for name in os.listdir(target.directory.fd) if recovery_name(name)]) >= MAX_TRANSACTIONS:
            raise RuntimeError('RetainedEvidenceFull: transaction count budget')
        recovery_id, token = uuid.uuid4().hex, ExecutorToken()
        parent = Directory(target.target.parent, private=False)
        try:
            before = inventory(parent,target.directory)
            files = {name:value for name,value in before.items() if name in component_names(target.target)}
            if any('sha256' not in value for value in files.values()):
                raise RuntimeError('RecoveryBlocked: nonregular database component')
            total = sum(value['size'] for value in files.values())
            usage = accounting(target)
            reservation = total*10+FINISH_RESERVE
            if usage['retained_file_bytes'] + reservation > FILE_LIMIT:
                raise RuntimeError('RetainedEvidenceFull: snapshot and finishing byte reservation')
            data = {'version':2,'recovery_id':recovery_id,'coord_key':target.key,
                    'target':target.original,'directory':None,'parent_identity':parent.identity,
                    'root_binding':target.recovery_root_binding(),
                    'status':'snapshotting','failure_intent':False,'revision':1,'before':before,
                    'files':files,'snapshot_files':{},'attempts':[],'copies':{},'moves':{},
                    'directories':{},'requirements':[],'certified_resources':{},'backups':{},'intent':None,'cause':None,
                    'progress':{'bytes_total':0,'bytes_done':0,'source_bytes':total,'reserved_bytes':reservation},
                    'executor':{'epoch':1,'state':'LocalExecuting','actor':token.actor,'transfer_id':None},
                    'origin_binding':creation_scope(target.directory.path,'recovery-'+recovery_id)}
            target.directory.durable('recovery-create.json',{'schema':1,'record':data},immutable=True)
            boundary('create','intent',{'recovery_id':recovery_id})
            finish_creation(target)
        finally:
            parent.close()
        transaction = cls(target,recovery_id,token=token)
        try:
            with transaction:
                if on_begin is not None:
                    on_begin(transaction)
                transaction.phase('snapshotting')
                snapshot = transaction.child('snapshot')
                try:
                    for name, expected in transaction.data['files'].items():
                        transaction.data['snapshot_files'][name] = transaction.copy(
                            transaction.parent_directory(),name,snapshot,expected,0o400)
                    transaction.expect_unrelated(transaction.data['before'], exact_components=True)
                    transaction.phase('ready')
                finally:
                    snapshot.close()
            return recovery_id, token
        except BaseException:
            transaction.close()
            raise

    def validate(self):
        value = self.data
        required = {'version','recovery_id','coord_key','target','directory','parent_identity','root_binding',
                    'status','failure_intent','revision','before','files','snapshot_files','attempts','copies','moves',
                    'directories','requirements','certified_resources','backups','intent','cause','progress','executor','origin_binding'}
        optional = {'manual_offline_recovery','archived_reason','imported_v1','job','last_error','updated_at'}
        if (type(value) is not dict or not required <= set(value) or set(value)-required-optional
                or type(value['version']) is not int or value['version'] != 2
                or value['recovery_id'] != self.recovery_id or value['target'] != self.target.original
                or encoded(value['coord_key']) != encoded(self.target.key)
                or encoded(value['directory']) != encoded(self.directory.identity) or value['status'] not in PHASES
                or type(value['revision']) is not int or value['revision'] < 1
                or type(value['failure_intent']) is not bool
                or type(value['executor']) is not dict
                or set(value['executor']) != {'epoch','state','actor','transfer_id'}
                or type(value['executor']['epoch']) is not int or value['executor']['epoch'] < 1
                or value['executor']['state'] not in EXECUTING | {'FrozenOffer','Finished'}
                or type(value['attempts']) is not list or len(value['attempts']) > 3
                or type(value['requirements']) is not list or len(value['requirements']) > 96):
            raise RuntimeError('RecoveryBlocked: corrupt/unknown transaction identity/schema')
        for name in ('before','files','snapshot_files','copies','moves','directories','backups','certified_resources'):
            if type(value[name]) is not dict or len(value[name]) > 4096:
                raise RuntimeError('RecoveryBlocked: unbounded/malformed transaction table '+name)
        if set(value['files']) - component_names(self.target.target):
            raise RuntimeError('RecoveryBlocked: transaction contains foreign component')
        for table in ('files','snapshot_files'):
            for file in value[table].values():validate_info(file)
        for requirement in value['requirements']:
            if (type(requirement) is not dict or set(requirement) != {'watch','epoch','acquisition','owner','lease','origin_binding'}
                    or type(requirement['epoch']) is not int or requirement['epoch'] < 1
                    or type(requirement['watch']) is not str or not requirement['watch']):
                raise RuntimeError('RecoveryBlocked: invalid exact file-resource requirement')
        if encoded(self.target.recovery_root_binding()) != encoded(value['root_binding']):
            raise RuntimeError('RecoveryBlocked: root guard identity changed')

    def parent_directory(self):
        if self.parent is None:
            self.parent = Directory(self.target.target.parent,private=False)
        self.parent.verify()
        if encoded(self.parent.identity) != encoded(self.data['parent_identity']):
            raise RuntimeError('RecoveryBlocked: target parent identity changed')
        return self.parent

    def authorize(self):
        if self.target.target_fd is None or self.target.root_fd is None or self.token is None:
            raise RuntimeError('RecoveryExecutorStale: no owned target guard/token')
        self.token.check()
        held = identity(os.fstat(self.target.target_fd))
        at_path = identity(os.stat('lock',dir_fd=self.target.directory.fd,follow_symlinks=False))
        if held != at_path or self.target.recovery_root_binding() != self.data['root_binding']:
            raise RuntimeError('RecoveryExecutorStale: target/root lock identity changed')
        value, _, _ = self.directory.read('recovery.json')
        if (value['executor']['state'] not in EXECUTING
                or value['executor']['epoch'] != self.token.epoch
                or value['executor']['actor'] != self.token.actor):
            raise RuntimeError('RecoveryExecutorStale: frozen/foreign executor epoch')
        self.directory.verify()
        self.target.directory.verify()

    @serialized
    def save(self):
        self.authorize()
        _, info, raw = self.directory.read('recovery.json')
        if (info.st_dev,info.st_ino,raw) != (self.info.st_dev,self.info.st_ino,self.raw):
            raise RuntimeError('RecoveryExecutorStale: transaction changed outside executor')
        self.data['revision'] += 1
        self.data['updated_at'] = time.time()
        self.validate()
        self.directory.durable('recovery.json',self.data)
        _, self.info, self.raw = self.directory.read('recovery.json')

    @serialized
    def phase(self, status):
        self.data['status'] = status
        self.save()
        from target_journal import Journal
        Journal(self.target).file_intent(self.directory.path/'recovery.json',status,self.data['attempts'])
        boundary('phase',status,{'recovery_id':self.recovery_id})

    @serialized
    def child(self, name):
        self.authorize()
        if not name or '/' in name or name in ('.','..'):
            raise RuntimeError('RecoveryBlocked: unsafe transaction directory')
        expected = self.data['directories'].get(name)
        self.data['intent'] = {'kind':'mkdir','name':name,'expected':expected}
        self.save()
        directory = self.directory.child(name,create=expected is None)
        if expected is not None and directory.identity != expected:
            directory.close()
            raise RuntimeError('RecoveryBlocked: evidence/staging directory replaced')
        self.data['directories'][name] = directory.identity
        self.data['intent'] = None
        self.save()
        return directory

    @serialized
    def copy(self, source, name, destination, expected, mode):
        hook = getattr(self,'copy_hook',None)
        if hook is not None:
            return hook(source,name,destination,expected,mode)
        return self.copy_file(source,name,destination,expected,mode)

    @serialized
    def copy_file(self, source, name, destination, expected, mode):
        self.authorize()
        key = digest([str(destination.path),name])
        prior = self.data['copies'].get(key)
        binding = {'source':str(source.path/name),'destination':str(destination.path/name),
                   'expected':expected,'mode':mode}
        if prior is not None and prior['binding'] != binding:
            raise RuntimeError('RecoveryBlocked: conflicting copy intent')
        if prior is None:
            self.data['copies'][key] = {'binding':binding,'reserved':None,'result':None}
            self.data['progress']['bytes_total'] += expected['size']
        self.data['intent'] = {'kind':'copy','key':key}
        self.save()
        if prior is not None and prior['result'] is not None:
            current = file_info(destination,name)
            if not compatible(current,prior['result']):
                raise RuntimeError('RecoveryBlocked: completed copy changed')
            self.data['intent'] = None
            self.save()
            return current
        def checkpoint(reserved):
            self.data['copies'][key]['reserved'] = reserved
            self.save()
        final = copy_exact(source,name,destination,expected,mode,
                           self.data['copies'][key]['reserved'],checkpoint,self.authorize)
        self.data['copies'][key]['result'] = final
        self.data['progress']['bytes_done'] += final['size']
        self.data['intent'] = None
        self.save()
        return final

    @serialized
    def move(self, source, name, destination, expected):
        self.authorize()
        key = digest([str(source.path),str(destination.path),name])
        binding = {'source':str(source.path/name),'destination':str(destination.path/name),'expected':expected}
        prior = self.data['moves'].get(key)
        if prior is not None and prior['binding'] != binding:
            raise RuntimeError('RecoveryBlocked: conflicting rename intent')
        self.data['moves'].setdefault(key,{'binding':binding,'result':None})
        self.data['intent'] = {'kind':'rename','key':key}
        self.save()
        if prior is not None and prior['result'] is not None:
            final = file_info(destination,name)
            if not compatible(final,prior['result']):
                raise RuntimeError('RecoveryBlocked: completed rename changed')
            self.data['intent'] = None
            self.save()
            return final
        final = rename_exact(source,name,destination,name,expected,self.authorize)
        self.data['moves'][key]['result'] = final
        self.data['intent'] = None
        self.save()
        return final

    def expect_unrelated(self, expected, *, exact_components=False):
        current = inventory(self.parent_directory(),self.target.directory)
        expected=copy.deepcopy(expected)
        for name,backup in self.data['backups'].items():
            directory=self.parent_directory().child(name,create=False)
            try:
                if directory.identity != backup['directory'] or inventory(directory) != backup['files']:
                    raise RuntimeError('RecoveryBlocked: exact Nexus crash backup changed')
                expected[name]={'directory':directory.identity,'mode':stat.S_IMODE(os.fstat(directory.fd).st_mode)}
            finally:directory.close()
        names = component_names(self.target.target)
        unrelated = lambda value:{k:v for k,v in value.items() if exact_components or k not in names}
        # Crash backups are separately verified and retained, never prefix-only
        # exemptions. Their directory identities remain in the expected view.
        if unrelated(current) != unrelated(expected):
            raise RuntimeError('RecoveryBlocked: target directory identity changed outside exact component intent')
        return current

    @serialized
    def register_backups(self):
        try:
            return self._register_backups()
        except Exception as error:
            self.data['last_error']='NexusBackupUnconfirmed: '+type(error).__name__+': '+str(error)
            self.save()
            from target_journal import Journal
            Journal(self.target).file_intent(self.directory.path/'recovery.json','snapshotting',self.data['attempts'])
            raise

    def _register_backups(self):
        """The SDK resolver's exact new copies, never a prefix-only exemption."""
        self.authorize()
        parent=self.parent_directory()
        pattern=re.compile(re.escape(self.target.target.name)+r'\.crash-[0-9]{8}T[0-9]{6}Z-([1-9][0-9]*)-[0-9]{6}')
        original={name:value for name,value in self.data['files'].items() if name != self.target.target.name}
        for name in sorted(os.listdir(parent.fd)):
            matched=pattern.fullmatch(name)
            if not matched:
                continue
            directory=parent.child(name,create=False)
            try:
                files=inventory(directory)
                if any('sha256' not in value for value in files.values()):
                    raise RuntimeError('RecoveryBlocked: recursive/unknown Nexus crash backup component')
                prior=self.data['backups'].get(name)
                record={'directory':directory.identity,'files':files,'before':name in self.data['before']}
                if prior is not None and prior != record:
                    raise RuntimeError('RecoveryBlocked: registered Nexus crash backup changed')
                if not record['before']:
                    # The resolver process is the original bridge actor, not
                    # the IDA owner whose PID happens to appear in a registry.
                    creator=self.data['origin_binding']['creator']['pid']
                    if int(matched[1]) != creator or not original or set(files) != set(original):
                        raise RuntimeError('RecoveryBlocked: partial/foreign Nexus crash backup')
                    for component,expected in original.items():
                        if any(files[component][key] != expected[key] for key in ('size','sha256','mode')):
                            raise RuntimeError('RecoveryBlocked: Nexus crash backup content/name mismatch')
                self.data['backups'][name]=record
                self.save()  # Exact recursive identity is durable BEFORE allowing it in a failed scene.
            finally:directory.close()
        self.expect_unrelated(self.data['before'])

    @serialized
    def capture_failure(self, attempt, requirements=(), cause=None):
        if type(attempt) is not int or not 1 <= attempt <= 3:
            raise RuntimeError('RecoveryBlocked: Root attempt budget exceeded')
        self.authorize()
        self.register_backups()
        if self.data['status'] not in ('ready','restored','failed-owner-held'):
            raise RuntimeError('RecoveryBlocked: invalid failure-capture phase')
        current = self.expect_unrelated(self.data['before'])
        previous = next((item for item in self.data['attempts'] if item['attempt']==attempt),None)
        if previous is None:
            self.data['failure_intent'] = True
            self.data['requirements'] = list(copy.deepcopy(requirements))
            self.data['cause'] = cause
            self.data['attempts'].append({'attempt':attempt,'failed':current,'captured':{},'restored':None,
                                          'remaining':None,'staged':{},'isolated':{},'published':{}})
            self.phase('failed-owner-held')
        else:
            if previous['failed'] != current:
                raise RuntimeError('RecoveryBlocked: failed scene changed during capture')
        record = self.data['attempts'][-1]
        failed = self.child('failed-files-'+str(attempt))
        try:
            for name in sorted(set(current) & component_names(self.target.target)):
                record['captured'][name] = self.copy(self.parent_directory(),name,failed,current[name],0o400)
            self.data['intent'] = None
            self.save()
        finally:
            failed.close()
        return current

    def require_resources(self, *, manual=False):
        permission=self.data.get('manual_offline_recovery')
        if permission is not None:
            self.validate_manual_permission(permission)
            from recovery_maintenance import occupancy
            self.owner_probe=lambda path:occupancy(permission['plan']['state_roots'],path)
            return
        if manual:
            raise RuntimeError('MaintenanceBlocked: no accepted offline permission')
        from target_journal import Journal
        journal = Journal(self.target)
        journal.recover_public_proofs()
        from target_journal import fact
        for requirement in sorted(self.data['requirements'],key=lambda item:item['epoch'],reverse=True):
            key = digest(requirement)
            certificate = self.data['certified_resources'].get(key)
            if certificate is not None:
                self.validate_certificate(requirement,certificate)
                continue
            item = journal.value['entries'].get(str(requirement['epoch']))
            fields = ('watch','epoch','acquisition','owner','lease','origin_binding')
            if item is None or any(item.get(k) != requirement.get(k) for k in fields):
                raise RuntimeError('RecoveryBlocked: exact resource evidence missing')
            if journal.retirement(item):
                evidence = {'scope':'verified_boot_change_resource_retirement',
                            'record':journal.retirement(item)}
            elif item.get('transferred_to') is not None:
                successor = next((r for r in self.data['requirements'] if r['epoch']==item['transferred_to']),None)
                if successor is None or digest(successor) not in self.data['certified_resources']:
                    raise RuntimeError('RecoveryBlocked: startup successor proof still pending')
                evidence = {'scope':'startup_transfer','successor':digest(successor),'record':copy.deepcopy(item)}
            elif item.get('launch'):
                raise RuntimeError('StartupUnconfirmed: recovery still has exact launch obligation')
            elif item.get('no_attach') or item.get('no_launch'):
                if not (item['producer_closed'] and item['consumer_closed'] and not item['unacked_events']):
                    raise RuntimeError('RecoveryBlocked: no-acquisition closure pending')
                evidence = {'scope':'no_acquisition','record':copy.deepcopy(item)}
            else:
                permission = item.get('file_recovery_ack',{})
                ack = item.get('detach_outcome',{})
                if permission.get('recovery_id') == self.recovery_id:
                    ack = permission['outcome']
                if not item.get('proof') or (item.get('lease') and
                        ack.get('lease_released') is not True):
                    raise RuntimeError('RecoveryBlocked: sameboot detach/public-owner double proof pending')
                # Verify the original immutable bytes before taking an
                # independent retained copy into this failed transaction.
                proof_record = journal.referenced_record(item['proof'])
                fact(dict(item['proof'],record=proof_record),self.target,kind='PublicOwnerLifetime')
                evidence = {'scope':'public_owner_lifetime','record':copy.deepcopy(item),
                            'proof_record':proof_record,'ack':ack}
            record = {'schema':1,'kind':'FileRecoveryResourceCustody','coord_key':self.target.key,
                      'target':self.target.original,'recovery_id':self.recovery_id,
                      'requirement':requirement,'evidence':evidence,'guard_epoch':self.token.epoch}
            name = 'resource-'+key+'.json'
            prior_intent = self.data['intent']
            if prior_intent and prior_intent.get('kind')=='resource_certificate' and prior_intent.get('name')==name:
                record = prior_intent['record']
            else:
                self.data['intent'] = {'kind':'resource_certificate','name':name,'record':record}
                self.save()
            self.directory.recover_record(name)
            try:
                stored, _, _ = self.directory.read(name)
            except FileNotFoundError:
                self.directory.durable(name,record,immutable=True)
            else:
                if encoded(stored) != encoded(record):
                    raise RuntimeError('RecoveryBlocked: retained resource certificate conflict')
            certificate = {'name':name,'sha256':digest(record)}
            self.data['certified_resources'][key] = certificate
            self.data['intent'] = None
            self.save()
            self.validate_certificate(requirement,certificate)

    def validate_manual_permission(self, permission):
        if (type(permission) is not dict or set(permission) != {'schema','plan_sha256','plan','applied_at'}
                or type(permission['schema']) is not int or permission['schema'] != 1
                or digest(permission['plan']) != permission['plan_sha256']):
            raise RuntimeError('MaintenanceBlocked: corrupt offline permission')
        plan=permission['plan']
        if (plan.get('kind') != 'manual_offline_recovery' or plan.get('target') != self.target.original
                or encoded(plan.get('coord_key')) != encoded(self.target.key)
                or plan.get('directory') != self.target.directory.identity
                or plan.get('transaction') != self.recovery_id
                or plan.get('operator',{}).get('uid') != os.getuid()
                or plan.get('operator',{}).get('confirmation') != 'I established and maintain this exclusive offline window'
                or not plan['window']['started_at'] <= permission['applied_at'] < plan['window']['expires_at']
                or not plan['window']['started_at'] <= time.time() < plan['window']['expires_at']):
            raise RuntimeError('MaintenanceBlocked: accepted offline window no longer valid')

    def validate_certificate(self, requirement, certificate):
        record, _, raw = self.directory.read(certificate['name'])
        if (certificate['name'] != 'resource-'+digest(requirement)+'.json'
                or digest(raw) != certificate['sha256']
                or type(record.get('schema')) is not int or record['schema'] != 1 or record.get('kind') != 'FileRecoveryResourceCustody'
                or encoded(record.get('coord_key')) != encoded(self.target.key)
                or record.get('target') != self.target.original or record.get('recovery_id') != self.recovery_id
                or encoded(record.get('requirement')) != encoded(requirement)):
            raise RuntimeError('RecoveryBlocked: retained file-resource custody binding mismatch')
        evidence = record['evidence']
        if evidence['scope']=='verified_boot_change_resource_retirement':
            from origin import boot_change, creation_scope
            original = evidence['record']
            expected = boot_change(requirement['origin_binding'],original.get('current'))
            expected.update(schema=1,watch=requirement['watch'],epoch=requirement['epoch'],
                acquisition=requirement['acquisition'],owner=requirement['owner'],lease=requirement['lease'],
                launch=original.get('launch'),coord_key=self.target.key,target_binding=self.target.binding)
            expected['sha256'] = digest(expected)
            if encoded(original) != encoded(expected):
                raise RuntimeError('RecoveryBlocked: retained resource retirement certificate changed')
            boot_change(requirement['origin_binding'],creation_scope(self.target.directory.path,'file-recovery-consumer'))
        elif evidence['scope']=='public_owner_lifetime':
            item = evidence['record']
            proof = item.get('proof',{})
            proof_record = evidence['proof_record']
            permission = item.get('file_recovery_ack',{})
            ack = permission.get('outcome') if permission.get('recovery_id') == self.recovery_id else item.get('detach_outcome')
            if (not proof or digest(proof_record) != proof['sha256']
                    or proof_record.get('evidence_type') != 'public_owner_lifetime'
                    or proof_record.get('owner') != requirement['owner']
                    or proof_record.get('watch') != requirement['watch']
                    or proof_record.get('acquisition') != requirement['acquisition']
                    or proof_record.get('subscription_epoch') != requirement['epoch']
                    or encoded(proof_record.get('coord_key')) != encoded(self.target.key)
                    or encoded(ack) != encoded(evidence['ack'])
                    or (requirement['lease'] is not None and (not ack or ack.get('lease_released') is not True))):
                raise RuntimeError('RecoveryBlocked: retained public double proof changed')
        elif evidence['scope']=='startup_transfer':
            successor = next((r for r in self.data['requirements'] if digest(r)==evidence['successor']),None)
            if successor is None or successor['epoch'] <= requirement['epoch']:
                raise RuntimeError('RecoveryBlocked: invalid retained startup successor')
            if evidence['successor'] not in self.data['certified_resources']:
                raise RuntimeError('RecoveryBlocked: retained startup successor missing')
            self.validate_certificate(successor,self.data['certified_resources'][evidence['successor']])
        elif evidence['scope']=='no_acquisition':
            item = evidence['record']
            if (requirement['lease'] is not None or not (item.get('no_attach') or item.get('no_launch'))
                    or not item['producer_closed'] or not item['consumer_closed'] or item['unacked_events']):
                raise RuntimeError('RecoveryBlocked: retained no-acquisition evidence changed')
        else:
            raise RuntimeError('RecoveryBlocked: unsupported file-resource evidence scope')

    def check_occupancy(self):
        from cache_store import public_owner_probe
        from ida_nexus import probe_database_state
        views=[Path(self.data['target'])]
        known_id0=False
        phase=self.data['status']
        if self.data['attempts'] and phase in ('prepared','isolating','publishing'):
            record=self.data['attempts'][-1]
            for prefix,expected in (('staging-',record['staged']),('quarantine-',record['remaining'] or {})):
                name=prefix+str(record['attempt'])
                if name not in self.data['directories']:
                    continue
                directory=self.directory.child(name,create=False)
                try:
                    if directory.identity != self.data['directories'][name]:
                        raise RuntimeError('RecoveryBlocked: occupied component directory replaced')
                    current=inventory(directory)
                    if set(current)-set(expected):
                        raise RuntimeError('RecoveryBlocked: unknown recovery component at occupancy check')
                    for component,actual in current.items():
                        if not compatible(actual,expected[component],renamed=True):
                            raise RuntimeError('RecoveryBlocked: recovery component changed before occupancy check')
                        if prefix=='quarantine-' and component==self.target.target.with_suffix('.id0').name:
                            known_id0=True
                    views.append(directory.path/self.target.target.name)
                finally:directory.close()
        states=[]
        for path in views:
            reason=getattr(self,'owner_probe',public_owner_probe)(path)
            if reason:
                raise RuntimeError('RecoveryBlocked: '+reason)
            state=probe_database_state(path)
            if state.get('state')=='in_use':
                raise RuntimeError('RecoveryBlocked: external IDA lock holds current/recovery component')
            states.append(state)
        for index,state in enumerate(states):
            if state.get('state')!='unknown' and not state.get('error'):
                continue
            own_split=(phase in ('isolating','publishing')
                and state.get('error')=='unpacked database components exist without .id0'
                and (index>0 or known_id0))
            if not own_split:
                raise RuntimeError('RecoveryBlocked: external IDA lock or current database occupancy is not confirmed')

    @serialized
    def restore(self, *, manual=False):
        self.authorize()
        if not self.data['failure_intent']:
            raise RuntimeError('RecoveryBlocked: no failure intent; refusing rollback')
        if self.data['status'] in ('restored','opened','archived'):
            return self.data
        self.require_resources(manual=manual)
        self.check_occupancy()
        record = self.data['attempts'][-1]
        names = component_names(self.target.target)
        if set(record['captured']) != set(record['failed']) & names:
            raise RuntimeError('RecoveryBlocked: failed bytes not fully captured')
        self.expect_unrelated(self.data['before'])
        if self.data['status'] == 'failed-owner-held':
            current = inventory(self.parent_directory(),self.target.directory)
            for name in names & set(current):
                if name not in record['failed'] or not compatible(current[name],record['failed'][name]):
                    raise RuntimeError('RecoveryBlocked: component identity changed after owner close')
            for name in set(record['failed'])-set(current):
                if name not in names or name == self.target.target.name:
                    raise RuntimeError('RecoveryBlocked: unexpected removal before restore')
            record['remaining'] = {name:current[name] for name in names & set(current)}
            self.phase('staging')
        if self.data['status'] == 'staging':
            staging = self.child('staging-'+str(record['attempt']))
            snapshot = self.child('snapshot')
            try:
                for name, expected in self.data['snapshot_files'].items():
                    record['staged'][name] = self.copy(snapshot,name,staging,expected,
                                                      stat.S_IMODE(self.data['files'][name]['mode']))
                self.phase('prepared')
            finally:
                snapshot.close()
                staging.close()
        if self.data['status'] == 'prepared':
            self.check_occupancy()
            self.phase('isolating')
        if self.data['status'] == 'isolating':
            quarantine = self.child('quarantine-'+str(record['attempt']))
            try:
                for name, expected in record['remaining'].items():
                    self.check_occupancy()
                    record['isolated'][name] = self.move(self.parent_directory(),name,quarantine,expected)
                self.phase('publishing')
            finally:
                quarantine.close()
        if self.data['status'] == 'publishing':
            staging = self.child('staging-'+str(record['attempt']))
            try:
                for name, expected in record['staged'].items():
                    self.check_occupancy()
                    record['published'][name] = self.move(staging,name,self.parent_directory(),expected)
                actual = inventory(self.parent_directory(),self.target.directory)
                if set(actual) & names != set(self.data['files']):
                    raise RuntimeError('RecoveryBlocked: restored component set differs')
                for name, expected in self.data['files'].items():
                    if (actual[name]['size'],actual[name]['sha256'],actual[name]['mode']) != (
                            expected['size'],expected['sha256'],expected['mode']):
                        raise RuntimeError('RecoveryBlocked: restored bytes/mode differ')
                self.check_occupancy()
                self.expect_unrelated(self.data['before'])
                os.fsync(self.parent_directory().fd)
                record['restored'] = actual
                self.phase('restored')
            finally:
                staging.close()
        return self.data

    @serialized
    def archive(self, reason):
        if self.data['failure_intent'] and self.data['status'] not in ('restored','opened'):
            raise RuntimeError('RecoveryBlocked: unfinished failure cannot be archived')
        self.data['archived_reason'] = reason
        self.phase('archived')

    @serialized
    def complete(self):
        if self.data['status'] not in ('ready','restored','opened'):
            raise RuntimeError('RecoveryBlocked: open cannot complete unfinished file transaction')
        self.phase('opened')

    def resume_executor(self):
        """Caller already acquired an independent target EX, never an old dup."""
        if getattr(self.target,'transferred',False):
            raise RuntimeError('HandoffBlocked: shared OFD cannot establish a recovery fence')
        token = ExecutorToken(epoch=self.data['executor']['epoch']+1)
        self.data['executor'] = {'epoch':token.epoch,'state':'Resumed','actor':token.actor,'transfer_id':None}
        self.data['revision'] += 1
        self.validate()
        self.directory.durable('recovery.json',self.data)
        self.data, self.info, self.raw = self.directory.read('recovery.json')
        self.token = token
        return token

    @serialized
    def move_executor(self):
        self.authorize()
        target=self.target.move()
        try:
            return target,Transaction(target,self.recovery_id,token=self.token.move(),recover=False)
        except BaseException:
            target.close()
            raise

    def status(self):
        return {'job_id':self.recovery_id,'transaction':str(self.directory.path),
                'phase':self.data['status'],'executor':self.data['executor'],
                'progress':self.data['progress'],'cause':self.data['cause'],
                'last_error':self.data.get('last_error'),'next_action':
                    'inspect_recovery_error' if self.data.get('last_error') else 'continue_file_transaction'}

    def close(self):
        if self.parent is not None:
            self.parent.close()
            self.parent = None
        if self.directory is not None:
            self.directory.close()
            self.directory = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def accounting(target):
    used, transactions = 0, []
    for name in os.listdir(target.directory.fd):
        if not recovery_name(name):
            continue
        directory = target.directory.child(name,create=False)
        try:
            def walk(current, depth=0):
                if depth > 4:
                    raise RuntimeError('RecoveryBlocked: transaction namespace depth exceeded')
                total = 0
                for child in os.listdir(current.fd):
                    info = os.stat(child,dir_fd=current.fd,follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        nested = current.child(child,create=False)
                        try:total += walk(nested,depth+1)
                        finally:nested.close()
                    else:
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                            raise RuntimeError('RecoveryBlocked: unknown recovery accounting entry')
                        total += info.st_size
                return total
            size = walk(directory)
            used += size
            transactions.append({'recovery_id':name,'bytes':size})
        finally:
            directory.close()
    percent = used*100//FILE_LIMIT
    return {'retained_file_bytes':used,'retained_file_limit_bytes':FILE_LIMIT,
            'retained_file_warning_percent':next((v for v in (100,95,80) if percent>=v),0),
            'recovery_transactions':transactions,'recovery_finish_reserve':FINISH_RESERVE}


def inspect_transactions(target):
    """Read target-side locators; completed/ready snapshots never cause rollback."""
    result = []
    for name in os.listdir(target.directory.fd):
        if not recovery_name(name):
            continue
        with Transaction(target,name,recover=not target.root_locked) as transaction:
            if target.root_locked and any(part.endswith(('.new','.new.owner')) for part in os.listdir(transaction.directory.fd)):
                raise RuntimeError('RecoveryBlocked: GC does not resume a pending file writer')
            result.append(transaction.status())
    return result


def resume_at_gate(target):
    """Independent EX fences old/in-flight OFDs before a new job epoch exists."""
    if target.root_locked or target.transferred:
        return
    for name in sorted(os.listdir(target.directory.fd)):
        if not recovery_name(name):
            continue
        with Transaction(target,name) as transaction:
            if transaction.data['status'] in ('restored','opened','archived','ready','snapshotting'):
                continue
            transaction.resume_executor()
            transaction.require_resources()
            from recovery_job import start
            result = start(transaction)
            # The target guard was moved. A new business acquisition must
            # reenter through its ordinary root->target gate, never borrow it.
            raise RuntimeError('RecoveryCompleted: '+str(result['status']['job_id'])
                               +'; reenter target gate for a new acquisition')


def finish_creation(target):
    """Publish the one exact directory recipe before starting snapshot I/O."""
    target.directory.recover_record('recovery-create.json')
    try:
        recipe, _, raw = target.directory.read('recovery-create.json')
    except FileNotFoundError:
        return
    if (type(recipe) is not dict or set(recipe) != {'schema','record'}
            or type(recipe['schema']) is not int or recipe['schema'] != 1):
        raise RuntimeError('RecoveryBlocked: corrupt creation recipe')
    value = copy.deepcopy(recipe['record'])
    if (not recovery_name(value.get('recovery_id')) or value.get('directory') is not None
            or value.get('target') != target.original or value.get('status') != 'snapshotting'
            or value.get('failure_intent') is not False or value.get('attempts') != []
            or encoded(value.get('coord_key')) != encoded(target.key)
            or value.get('root_binding') != target.recovery_root_binding()):
        raise RuntimeError('RecoveryBlocked: foreign/conflicting creation recipe')
    directory = target.directory.child(value['recovery_id'])
    try:
        boundary('create','directory',{'recovery_id':value['recovery_id']})
        value['directory'] = directory.identity
        directory.recover_record('recovery.json')
        try:
            stored, _, _ = directory.read('recovery.json')
        except FileNotFoundError:
            if os.listdir(directory.fd):
                raise RuntimeError('RecoveryBlocked: creation directory contains unknown evidence') from None
            directory.durable('recovery.json',value,immutable=True)
        else:
            if encoded(stored) != encoded(value):
                raise RuntimeError('RecoveryBlocked: creation directory record differs')
        with Transaction(target,value['recovery_id'],recover=False):
            pass
        boundary('create','published',{'recovery_id':value['recovery_id']})
        _, _, current = target.directory.read('recovery-create.json')
        if current != raw:
            raise RuntimeError('RecoveryBlocked: creation recipe changed')
        os.unlink('recovery-create.json',dir_fd=target.directory.fd)
        os.fsync(target.directory.fd)
    finally:
        directory.close()


def pinned_epochs(target):
    """Ready snapshots pin possible failure inputs; certified copies own later refs."""
    pinned = set()
    for name in os.listdir(target.directory.fd):
        if not recovery_name(name):
            continue
        with Transaction(target,name,recover=False) as transaction:
            if transaction.data['status'] in ('snapshotting','ready'):
                return None
            for requirement in transaction.data['requirements']:
                certificate = transaction.data['certified_resources'].get(digest(requirement))
                if certificate is None:
                    pinned.add(requirement['epoch'])
                else:
                    transaction.validate_certificate(requirement,certificate)
    return pinned
