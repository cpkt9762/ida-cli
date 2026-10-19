"""Canonical target identities across qualified native volume-device epochs.

Stored identity bytes keep their first device label. Every live FD/path check
uses the actual current device; only a verified host/volume/object boot change
may establish the translation. No resource result or immutable proof is edited.
"""
import copy
import os


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
    from target_coordination import encoded,identity
    try:binding,_,_=target.directory.read('volume.json')
    except FileNotFoundError:return
    fields={'schema','device','scope','coordination','root_binding','coord_key','generation','target','lock_identity'}
    if (type(binding) is not dict or set(binding)!=fields or type(binding['schema']) is not int
            or binding['schema']!=1 or type(binding['device']) is not int or binding['device']<=0
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
    if current!=canonical:
        from origin import boot_change,creation_scope
        native=creation_scope(target.directory.path,'target-volume-consumer')
        if native.get('device')!=current:
            raise RuntimeError('UnsupportedBootScope: OS source and actual mounted device differ')
        boot_change(binding['scope'],native)
    for directory in target.directories:
        if directory.native_identity[0]==current:
            directory.canonical_device=canonical
            directory.identity=[canonical,*directory.native_identity[1:]]
    target.key=key
    target.binding=generation
    if encoded(target.recovery_root_binding())!=encoded(binding['root_binding']):
        raise RuntimeError('UnsupportedBootScope: stable resource-root binding changed')


def ensure_binding(target):
    from origin import creation_scope
    from target_coordination import identity
    target.directory.recover_record('volume.json')
    try:target.directory.read('volume.json')
    except FileNotFoundError:
        if target.directory.native_identity[0]!=target.directory.canonical_device:
            raise RuntimeError('UnsupportedBootScope: missing original volume binding; no device remapping')
        value={'schema':1,'device':target.directory.native_identity[0],
            'scope':creation_scope(target.directory.path,'target-volume'),
            'coordination':target.directory.identity,'root_binding':target.recovery_root_binding(),
            'coord_key':target.key,'generation':target.binding,'target':target.original,
            'lock_identity':identity(os.fstat(target.target_fd))}
        # Serialized write-once metadata uses atomic replace, never a linked
        # two-name inode that a receiver might observe before target EX.
        target.directory.durable('volume.json',value)
    load_binding(target)
