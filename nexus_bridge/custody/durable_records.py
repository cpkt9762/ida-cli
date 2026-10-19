"""Exact, bounded pending writes for a caller serialized by target authority.

The fixed owner slot binds the destination's previous version and the new
inode/content. Unknown, incomplete or replaced slots are never removed.
"""
import json
import os
import stat


def boundary(directory, name, stage):
    """Injection point for process-exit tests; production performs no action."""


def raw(directory, name, *, links=1):
    from target_coordination import MAX_RECORD, identity
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory.fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != links
                or before.st_size > MAX_RECORD):
            raise RuntimeError('DurableWriteBlocked: untrusted pending record')
        pieces, size = [], 0
        while size <= MAX_RECORD:
            piece = os.read(fd, min(65536, MAX_RECORD+1-size))
            if not piece:
                break
            pieces.append(piece)
            size += len(piece)
        data = b''.join(pieces)
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        signature = lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns,v.st_nlink)
        if (signature(before) != signature(after) or identity(before) != identity(current)
                or signature(before) != signature(current) or size != before.st_size):
            raise RuntimeError('DurableWriteBlocked: record changed during read')
        return before, data
    finally:
        os.close(fd)


def version(directory, name):
    from target_coordination import digest, identity
    try:
        info, data = raw(directory, name)
    except FileNotFoundError:
        return None
    return {'identity':identity(info),'sha256':digest(data),'size':len(data)}


def exact_unlink(directory, name, info):
    current = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    if (current.st_dev,current.st_ino,current.st_uid,current.st_mode,current.st_nlink) != (
            info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_nlink):
        raise RuntimeError('DurableWriteBlocked: unlink identity changed')
    directory.verify()
    os.unlink(name, dir_fd=directory.fd)
    os.fsync(directory.fd)


def read_owner(directory, name):
    from target_coordination import MAX_RECORD
    info, data = raw(directory, name+'.new.owner')
    value = json.loads(data)
    if (type(value) is not dict or set(value) != {'schema','writer','target','directory','new','previous','immutable'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['writer'] != 'ida-cli-durable-v2' or value['target'] != name
            or value['directory'] != directory.identity or type(value['immutable']) is not bool
            or type(value['new']) is not dict or set(value['new']) != {'identity','sha256','size'}
            or type(value['new']['size']) is not int or not 0 <= value['new']['size'] <= MAX_RECORD
            or type(value['new']['sha256']) is not str or len(value['new']['sha256']) != 64
            or any(c not in '0123456789abcdef' for c in value['new']['sha256'])
            or type(value['new']['identity']) is not list or len(value['new']['identity']) != 3
            or any(type(n) is not int or n < 0 for n in value['new']['identity'])
            or (value['previous'] is not None and
                (type(value['previous']) is not dict or set(value['previous']) != {'identity','sha256','size'}))):
        raise RuntimeError('DurableWriteBlocked: unrecognized pending ownership')
    return value, info


def resume(directory, name, *, validate=None):
    """Complete a fully bound write. The caller must hold this writer's lock."""
    from target_coordination import digest, identity
    temporary, marker = name+'.new', name+'.new.owner'
    try:
        owner, owner_info = read_owner(directory, name)
    except FileNotFoundError:
        if os.path.lexists(directory.path/temporary):
            raise RuntimeError('DurableWriteBlocked: pending bytes lack durable ownership') from None
        return False
    expected = owner['new']
    try:
        temp_info = os.stat(temporary, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        if version(directory, name) != expected:
            raise RuntimeError('DurableWriteBlocked: published write identity/content conflict') from None
        if validate is not None:
            validate(raw(directory, name)[1])
        os.fsync(directory.fd)
        exact_unlink(directory, marker, owner_info)
        return True
    # Immutable link publication may have completed before the pending name
    # was removed. Only these two names may share the reserved exact inode.
    linked = owner['immutable'] and temp_info.st_nlink == 2
    info, data = raw(directory, temporary, links=2 if linked else 1)
    actual = {'identity':identity(info),'sha256':digest(data),'size':len(data)}
    if actual != expected:
        raise RuntimeError('DurableWriteBlocked: partial/foreign pending bytes retained')
    if validate is not None:
        validate(data)
    directory.verify()
    if linked:
        final_info, final_data = raw(directory, name, links=2)
        if identity(final_info) != identity(info) or final_data != data:
            raise RuntimeError('DurableWriteBlocked: immutable publication link conflict')
        exact_unlink(directory, temporary, info)
    else:
        if version(directory, name) != owner['previous']:
            raise RuntimeError('DurableWriteBlocked: destination changed before publication')
        fd = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory.fd)
        try:
            if identity(os.fstat(fd)) != expected['identity']:
                raise RuntimeError('DurableWriteBlocked: pending inode replaced')
            os.fsync(fd)
        finally:
            os.close(fd)
        boundary(directory, name, 'before_rename')
        if owner['immutable']:
            if owner['previous'] is not None:
                raise RuntimeError('DurableWriteBlocked: immutable destination already exists')
            os.link(temporary, name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd, follow_symlinks=False)
            boundary(directory, name, 'after_rename')
            # A link changes nlink on the same inode; reread the exact pair.
            final_info, final_data = raw(directory, temporary, links=2)
            if identity(final_info) != identity(info) or final_data != data:
                raise RuntimeError('DurableWriteBlocked: linked pending identity changed')
            exact_unlink(directory, temporary, final_info)
        else:
            os.replace(temporary, name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
            boundary(directory, name, 'after_rename')
    os.fsync(directory.fd)
    boundary(directory, name, 'directory_fsynced')
    if version(directory, name) != expected:
        raise RuntimeError('DurableWriteBlocked: publication identity/content changed')
    exact_unlink(directory, marker, owner_info)
    return True


def write(directory, name, value, *, immutable=False):
    from target_coordination import MAX_RECORD, checked, digest, encoded, identity
    if not name or '/' in name or name in ('.','..') or name.endswith(('.new','.owner')):
        raise ValueError('invalid durable record name')
    data = encoded(value)
    if len(data) > MAX_RECORD:
        raise RuntimeError('DurableWriteBlocked: record byte budget exceeded')
    try:
        pending, _ = read_owner(directory, name)
    except FileNotFoundError:
        pending = None
    if pending is not None:
        if pending['new']['sha256'] != digest(data) or pending['immutable'] != immutable:
            raise RuntimeError('DurableWriteBlocked: another value owns pending write')
        resume(directory, name)
        return
    resume(directory, name)
    previous = version(directory, name)
    if immutable and previous is not None:
        raise FileExistsError(str(directory.path/name))
    temporary, marker = name+'.new', name+'.new.owner'
    fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory.fd)
    try:
        info = checked(fd)
        record = {'schema':1,'writer':'ida-cli-durable-v2','target':name,'directory':directory.identity,
                  'new':{'identity':identity(info),'sha256':digest(data),'size':len(data)},
                  'previous':previous,'immutable':immutable}
        owner_fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                           0o600, dir_fd=directory.fd)
        try:
            checked(owner_fd)
            view = memoryview(encoded(record))
            while view:
                count = os.write(owner_fd, view)
                if count <= 0:
                    raise OSError('short durable ownership write')
                view = view[count:]
            os.fsync(owner_fd)
        finally:
            os.close(owner_fd)
        os.fsync(directory.fd)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError('short durable record write')
            view = view[count:]
        boundary(directory, name, 'temp_written')
        os.fsync(fd)
        boundary(directory, name, 'file_fsynced')
    finally:
        os.close(fd)
    resume(directory, name)
