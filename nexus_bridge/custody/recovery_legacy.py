"""Explicit v1 evidence import into the one target-side v2 file executor."""
import json
import os
from pathlib import Path
import re
import stat

from recovery_files import compatible, component_names, file_info, inventory
from recovery_transaction import Transaction, boundary, finish_creation, recovery_name
from target_coordination import Directory, MAX_RECORD, digest, encoded


def legacy_record(source):
    info=file_info(source,'recovery.json')
    if info['size'] > MAX_RECORD:
        raise RuntimeError('RecoveryBlocked: oversized legacy journal')
    fd=os.open('recovery.json',os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=source.fd)
    try:
        chunks=[]
        while chunk:=os.read(fd,65536):chunks.append(chunk)
        raw=b''.join(chunks)
    finally:os.close(fd)
    if digest(raw) != info['sha256'] or file_info(source,'recovery.json') != info:
        raise RuntimeError('RecoveryBlocked: legacy journal changed during read')
    value=json.loads(raw)
    required={'version','target','status','before','parent_identity','files','snapshot_files','attempts'}
    if (type(value) is not dict or set(value) != required
            or type(value['version']) is not int or value['version'] != 1
            or value['status'] not in ('snapshotting','ready','failed-owner-held','rolling-back','restored','opened')
            or any(type(value[k]) is not dict for k in ('before','files','snapshot_files'))
            or type(value['attempts']) is not list or len(value['attempts']) > 3):
        raise RuntimeError('RecoveryBlocked: corrupt/unsupported legacy file transaction')
    previous=0
    for attempt in value['attempts']:
        if (type(attempt) is not dict or not {'attempt','failed'} <= set(attempt)
                or set(attempt)-{'attempt','failed','restored'}
                or type(attempt['attempt']) is not int or not previous < attempt['attempt'] <= 3
                or type(attempt['failed']) is not dict):
            raise RuntimeError('RecoveryBlocked: malformed legacy attempt history')
        previous=attempt['attempt']
    return value,info


def sources(source, target):
    result={'root':{}}
    allowed=component_names(target.target)
    for name in sorted(os.listdir(source.fd)):
        if name=='imported-v2.json':continue
        if name=='recovery.json' or re.fullmatch(r'\.recovery\.json\.[0-9a-f]{32}',name):
            result['root'][name]=file_info(source,name)
            continue
        if name!='snapshot' and not re.fullmatch(r'(failed-files|quarantine)-[123]',name):
            raise RuntimeError('RecoveryBlocked: unknown legacy evidence component: '+name)
        directory=source.child(name,create=False)
        try:
            files=inventory(directory)
            if set(files)-allowed or any('sha256' not in value for value in files.values()):
                raise RuntimeError('RecoveryBlocked: unsafe legacy component tree')
            result[name]=files
        finally:directory.close()
    return result


def publish_pointer(source, binding, target, recovery_id):
    pointer={'schema':1,'kind':'legacy_file_evidence_archived','source':binding,
             'recovery_id':recovery_id,'transaction':str(target.directory.path/recovery_id),
             'coord_key':target.key,'target':target.original,'never_replay_old_open':True}
    source.recover_record('imported-v2.json')
    try:stored,_,_=source.read('imported-v2.json')
    except FileNotFoundError:source.durable('imported-v2.json',pointer,immutable=True)
    else:
        if encoded(stored) != encoded(pointer):
            raise RuntimeError('RecoveryBlocked: legacy archive pointer conflict')
    boundary('legacy_import','archived',{'recovery_id':recovery_id})


def accept_locator_custody(target, transaction):
    imported=transaction.data['imported_v1']
    for folder,entries in imported['source']['manifest'].items():
        name='legacy-source-'+folder
        directory=transaction.directory.child(name,create=False)
        try:
            if directory.identity != transaction.data['directories'].get(name) or set(os.listdir(directory.fd)) != set(entries):
                raise RuntimeError('RecoveryBlocked: imported evidence namespace differs before handoff')
            for component,expected in entries.items():
                actual=file_info(directory,component)
                if actual['mode'] != 0o400 or any(actual[k] != expected[k] for k in ('size','sha256')):
                    raise RuntimeError('RecoveryBlocked: imported evidence bytes differ before handoff')
        finally:directory.close()
    snapshot=transaction.directory.child('snapshot',create=False)
    try:
        if set(os.listdir(snapshot.fd)) != set(transaction.data['snapshot_files']):
            raise RuntimeError('RecoveryBlocked: imported complete snapshot missing')
        for name,expected in transaction.data['snapshot_files'].items():
            if not compatible(file_info(snapshot,name),expected):
                raise RuntimeError('RecoveryBlocked: imported snapshot changed before handoff')
    finally:snapshot.close()
    old=imported['legacy_intent']
    if old:
        from target_journal import Journal
        journal=Journal(target)
        current=journal.value.get('file_intents',{}).get(old['key'])
        if current is not None:
            if encoded(current) != encoded(old['record']):
                raise RuntimeError('RecoveryBlocked: legacy file obligation changed before v2 custody')
            journal.value['file_intents'].pop(old['key'])
            journal.save()


def import_v1(target, path):
    """Source may be on another volume; only verified copies enter target volume."""
    path=Path(path)
    if not recovery_name(path.name):
        raise RuntimeError('RecoveryBlocked: legacy RecoveryId must be retained exactly')
    source=Directory(path)
    snapshot=None
    try:
        value,record_info=legacy_record(source)
        if value['target'] != target.original:
            raise RuntimeError('RecoveryBlocked: legacy target differs from fixed authority')
        current_parent=Directory(target.target.parent,private=False)
        try:
            actual=os.fstat(current_parent.fd)
            identity=value['parent_identity']
            if (type(identity) is not list or len(identity)!=3 or any(type(n) is not int for n in identity)
                    or identity != [actual.st_ino,actual.st_dev,actual.st_mode]):
                raise RuntimeError('RecoveryBlocked: legacy parent identity changed')
        finally:current_parent.close()
        manifest=sources(source,target)
        binding={'path':str(path),'directory':source.identity,'journal':record_info,'manifest':manifest}
        failed=value['status'] in ('failed-owner-held','rolling-back')
        from target_journal import Journal
        journal=Journal(target)
        locators=[(key,item) for key,item in journal.value.get('file_intents',{}).items()
                  if os.path.realpath(item['path'])==str(path/'recovery.json')]
        bound=None
        if len(locators)==1:
            key,item=locators[0]
            if (encoded(item['inode'])==encoded([record_info['device'],record_info['inode']])
                    and item['sha256']==record_info['sha256']):
                bound={'key':key,'record':item}
        fields=('watch','epoch','acquisition','owner','lease','origin_binding')
        requirements=[{k:__import__('copy').deepcopy(item.get(k)) for k in fields}
                      for item in journal.value['entries'].values()] if bound else []
        files,modes={},{}
        if failed:
            if not value['attempts'] or not value['files'] or set(value['files']) != set(value['snapshot_files']):
                raise RuntimeError('RecoveryBlocked: failed legacy transaction has no complete snapshot')
            snapshot=source.child('snapshot',create=False)
            if set(manifest['snapshot']) != set(value['files']):
                raise RuntimeError('RecoveryBlocked: legacy snapshot component set differs')
            for name,original in value['files'].items():
                actual=file_info(snapshot,name)
                old=value['snapshot_files'][name]
                fields=('inode','device','size','mtime_ns','sha256')
                if (any(encoded(actual[k]) != encoded(old.get(k)) for k in fields)
                        or type(old.get('mode')) is not int
                        or actual['mode'] != stat.S_IMODE(old['mode'])
                        or any(actual[k] != original.get(k) for k in ('size','sha256'))
                        or type(original.get('mode')) is not int):
                    raise RuntimeError('RecoveryBlocked: legacy snapshot identity/content changed')
                files[name]=actual
                modes[name]=stat.S_IMODE(original['mode'])
        recovery_id=path.name
        finish_creation(target)
        exists=recovery_id in os.listdir(target.directory.fd)
        if exists:
            with Transaction(target,recovery_id) as transaction:
                if encoded(transaction.data.get('imported_v1',{}).get('source')) != encoded(binding):
                    raise RuntimeError('RecoveryBlocked: legacy RecoveryId/source collision')
                if transaction.data['imported_v1']['state'] in ('Published','Complete'):
                    pending=transaction.data['imported_v1']['state']=='Published'
                    if pending:transaction.resume_executor()
                    accept_locator_custody(target,transaction)
                    publish_pointer(source,binding,target,recovery_id)
                    if pending:
                        transaction.data['imported_v1']['state']='Complete'
                        transaction.phase(transaction.data['status'])
                    return transaction.status()
        else:
            _,token=Transaction.allocate(target,recovery_id=recovery_id,source_files=files,
                extra={'restore_modes':modes,'imported_v1':{'state':'Importing','source':binding,
                    'original_journal':value,'legacy_intent':bound,
                    'requirements':requirements,'resources_unqualified':failed and not requirements}})
        with Transaction(target,recovery_id,token=None if exists else token) as transaction:
            if exists:transaction.resume_executor()
            retained_snapshot=transaction.child('snapshot')
            try:
                for name,expected in files.items():
                    transaction.data['snapshot_files'][name]=transaction.copy_file(
                        snapshot,name,retained_snapshot,expected,0o400,external=True)
                transaction.save()
            finally:retained_snapshot.close()
            for folder,entries in manifest.items():
                source_folder=source if folder=='root' else source.child(folder,create=False)
                destination=transaction.child('legacy-source-'+folder)
                try:
                    for name,expected in entries.items():
                        transaction.copy_file(source_folder,name,destination,expected,0o400,external=True)
                finally:
                    if source_folder is not source:source_folder.close()
                    destination.close()
            # Recheck ALL source bytes before v2 can be the published locator.
            if sources(source,target) != manifest or legacy_record(source)[1] != record_info:
                raise RuntimeError('RecoveryBlocked: legacy evidence changed during import')
            transaction.phase('ready')
            if failed:
                transaction.capture_failure(value['attempts'][-1]['attempt'],
                    transaction.data['imported_v1']['requirements'],
                    cause='legacy failure evidence imported; original history retained')
            transaction.data['imported_v1']['state']='Published'
            if failed:transaction.phase('failed-owner-held')
            else:transaction.archive('legacy no-pending-failure evidence retained without rollback')
            boundary('legacy_import','published',{'recovery_id':recovery_id})
            accept_locator_custody(target,transaction)
            publish_pointer(source,binding,target,recovery_id)
            transaction.data['imported_v1']['state']='Complete'
            transaction.phase(transaction.data['status'])
            return transaction.status()
    finally:
        if snapshot is not None:snapshot.close()
        source.close()


def import_known_home(target, root):
    """Only the explicitly configured home is inventoried, never other homes."""
    path=Path(os.path.realpath(root))/'recovery'
    if not os.path.lexists(path):return
    directory=Directory(path)
    try:
        for name in sorted(os.listdir(directory.fd)):
            if not recovery_name(name):
                raise RuntimeError('RecoveryBlocked: unknown legacy recovery namespace')
            child=directory.child(name,create=False)
            try:value,_=legacy_record(child)
            finally:child.close()
            if value['target']==target.original:import_v1(target,path/name)
    finally:directory.close()


def resume_pending_imports(target):
    """Target-side locator, not a home scan, resumes the same accepted import."""
    if target.root_locked or target.transferred:return
    for name in sorted(os.listdir(target.directory.fd)):
        if not recovery_name(name):continue
        with Transaction(target,name) as transaction:
            imported=transaction.data.get('imported_v1')
            path=imported['source']['path'] if imported and imported.get('state') in ('Importing','Published') else None
        if path is not None:import_v1(target,path)
