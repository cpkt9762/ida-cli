"""Canonical target identities across qualified native volume-device epochs.

Stored identity bytes keep their first device label. Every live FD/path check
uses the actual current device; only a verified host/volume/object boot change
may establish the translation. No resource result or immutable proof is edited.
"""
import copy
import os


def quiescent(target):
    """No recovery, compaction or inferred process absence may clear this gate."""
    from target_journal import Journal
    from recovery_transaction import inspect_transactions, recovery_name
    from recovery_files import unpublished
    journal=Journal(target,recover=False,compact=False)
    if (journal.value['entries'] or journal.value.get('file_intents')
            or journal.value.get('compaction') or journal.value.get('verification_scope')
            or journal.value.get('verification_cleanup_conflict')):
        raise RuntimeError('UnsupportedBootScope: device rebinding has unsettled acquisition/helper/file obligations')
    allowed={'lock','root.lock','target.json','volume.json','custody.json','proofs','observations','retained',
             'volume.json.new','volume.json.new.owner'}
    preparations=unpublished(target.directory)
    for name in os.listdir(target.directory.fd):
        if name not in allowed and not recovery_name(name) and name not in preparations:
            raise RuntimeError('UnsupportedBootScope: device rebinding has unknown or pending target state')
    def pending(directory,depth=0):
        if depth>8:
            raise RuntimeError('UnsupportedBootScope: device rebinding namespace exceeds bound')
        for name in os.listdir(directory.fd):
            if directory is target.directory and name in ('volume.json.new','volume.json.new.owner'):
                continue
            if name.endswith(('.new','.new.owner')):
                raise RuntimeError('UnsupportedBootScope: device rebinding has pending writes')
            info=os.stat(name,dir_fd=directory.fd,follow_symlinks=False)
            if __import__('stat').S_ISDIR(info.st_mode):
                child=directory.child(name,create=False)
                try:pending(child,depth+1)
                finally:child.close()
            elif (not __import__('stat').S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1):
                raise RuntimeError('UnsupportedBootScope: device rebinding has an untrusted namespace object')
    pending(target.directory)
    for item in inspect_transactions(target,recover=False):
        if item['phase'] not in ('restored','opened','archived') or item.get('last_error'):
            raise RuntimeError('UnsupportedBootScope: device rebinding has an unsettled file transaction')


def persist_mapping(target,binding,current,native):
    """Record the exact native-device admission under root SH then target EX."""
    from target_coordination import encoded
    old=binding['scope'].get('volume_sha256')
    new=native.get('volume_sha256')
    if (binding['scope'].get('volume_source')!='diskutil.VolumeUUID'
            or native.get('volume_source')!='diskutil.VolumeUUID'
            or type(old) is not str or len(old)!=64 or any(c not in '0123456789abcdef' for c in old)
            or old!=new):
        raise RuntimeError('UnsupportedBootScope: device rebinding requires the original native volume UUID')
    if binding.get('mapped_device')==current:
        return
    # Constructor-time rebinding is serialized before the target can escape to
    # any caller. In-memory canonical identities do not authorize business I/O.
    owned=target.target_fd is None
    if owned:target.target_fd=target.directory.lock(nb=True,create=False)
    try:
        quiescent(target)
        updated=dict(binding,schema=2,mapped_device=current)
        try:pending,_,_=target.directory.inspect_record('volume.json')
        except FileNotFoundError:raise RuntimeError('CoordinationBlocked: original volume binding disappeared') from None
        if encoded(pending) not in (encoded(binding),encoded(updated)):
            raise RuntimeError('CoordinationBlocked: device rebinding pending identity changed')
        target.directory.durable('volume.json',updated)
    finally:
        if owned:
            os.close(target.target_fd)
            target.target_fd=None


def integer_identity(value,length=3):
    return (type(value) is list and len(value)==length
        and all(type(n) is int and n>=0 for n in value) and value[0]>0 and value[1]>0)


def translated(value,current,canonical):
    result=copy.deepcopy(value)
    fields=('root','parent') if result.get('kind') in ('direct','generation') else ('group','manifest')
    for field in fields:
        if field in result:
            item=result[field]
            if not integer_identity(item,2 if field=='manifest' else 3) or item[0] not in (current,canonical):
                raise RuntimeError('UnsupportedBootScope: target volume/object binding is inconsistent')
            item[0]=canonical
    return result


def load_binding(target):
    from target_coordination import encoded,identity,case_authority
    try:binding,_,_=target.directory.read('volume.json')
    except FileNotFoundError:return
    fields={'schema','device','scope','coordination','root_binding','coord_key','generation','target','lock_identity'}
    if type(binding) is dict and case_authority(binding.get('target'),target.target):
        target.original=binding['target']
    if (type(binding) is not dict or set(binding) not in (fields,fields|{'mapped_device'}) or type(binding['schema']) is not int
            or binding['schema'] not in (1,2) or (binding['schema']==2)!=('mapped_device' in binding)
            or ('mapped_device' in binding and (type(binding['mapped_device']) is not int or binding['mapped_device']<=0))
            or type(binding['device']) is not int or binding['device']<=0
            or not integer_identity(binding['coordination']) or not integer_identity(binding['lock_identity'])
            or type(binding['scope']) is not dict or type(binding['scope'].get('device')) is not int
            or binding['scope']['device']!=binding['device']
            or type(binding['scope'].get('file_id')) is not int or binding['scope']['file_id']!=binding['coordination'][1]
            or type(binding['scope'].get('uid')) is not int or binding['scope']['uid']!=binding['coordination'][2]
            or binding['scope'].get('same_boot_eligibility') is not False
            or binding['target']!=target.original or binding['coordination'][0]!=binding['device']):
        raise RuntimeError('UnsupportedBootScope: invalid stable target volume binding')
    current=target.directory.native_identity[0]
    canonical=binding['device']
    expected_directory=[canonical,*target.directory.native_identity[1:]]
    lock=identity(os.stat('lock',dir_fd=target.directory.fd,follow_symlinks=False))
    expected_lock=[canonical,*lock[1:]]
    key=translated(target.key,current,canonical)
    generation=translated(target.binding,current,canonical) if target.binding is not None else binding['generation']
    if (binding['coordination']!=expected_directory or binding['lock_identity']!=expected_lock
            or encoded(binding['coord_key'])!=encoded(key) or encoded(binding['generation'])!=encoded(generation)):
        raise RuntimeError('UnsupportedBootScope: stable target object/lock/generation changed')
    for directory in target.directories:
        if directory.native_identity[0]==current:
            directory.canonical_device=canonical
            directory.identity=[canonical,*directory.native_identity[1:]]
    target.key=key
    target.binding=generation
    if encoded(target.recovery_root_binding())!=encoded(binding['root_binding']):
        raise RuntimeError('UnsupportedBootScope: stable resource-root binding changed')
    if current!=canonical:
        from origin import boot_change,creation_scope
        native=creation_scope(target.directory.path,'target-volume-consumer',refresh=True)
        if native.get('device')!=current:
            raise RuntimeError('UnsupportedBootScope: OS source and actual mounted device differ')
        old_scope=binding['scope']
        if (old_scope.get('boot_retirement_capability')=='physical_local_apfs_host_v1'
                and native.get('boot_retirement_capability')=='physical_local_apfs_host_v1'
                and old_scope.get('creator',{}).get('boot_id')!=native.get('creator',{}).get('boot_id')):
            boot_change(old_scope,native)
        else:
            persist_mapping(target,binding,current,native)


def ensure_binding(target):
    from origin import creation_scope
    from target_coordination import identity
    target.directory.recover_record('volume.json')
    try:target.directory.read('volume.json')
    except FileNotFoundError:
        if target.directory.native_identity[0]!=target.directory.canonical_device:
            raise RuntimeError('UnsupportedBootScope: missing original volume binding; no device remapping')
        value={'schema':1,'device':target.directory.native_identity[0],
            'scope':creation_scope(target.directory.path,'target-volume',refresh=True),
            'coordination':target.directory.identity,'root_binding':target.recovery_root_binding(),
            'coord_key':target.key,'generation':target.binding,'target':target.original,
            'lock_identity':identity(os.fstat(target.target_fd))}
        # Serialized write-once metadata uses atomic replace, never a linked
        # two-name inode that a receiver might observe before target EX.
        target.directory.durable('volume.json',value)
    load_binding(target)
