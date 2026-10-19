"""Descriptor-bound component I/O shared by recovery, import and maintenance."""
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys


def boundary(action, stage, detail):
    """Process-exit/OS-error test hook; no production action."""


def safe_name(name):
    if type(name) is not str or not name or Path(name).name != name or name in ('.','..'):
        raise RuntimeError('RecoveryBlocked: invalid component name')
    return name


def component_names(target):
    return {target.name, *(target.with_suffix(ext).name for ext in ('.id0','.id1','.id2','.nam','.til'))}


def metadata(info):
    return {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
            'mode':stat.S_IMODE(info.st_mode),'size':info.st_size,'nlink':info.st_nlink,
            'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}


def compatible(actual, expected, *, renamed=False):
    validate_info(actual)
    validate_info(expected)
    keys = ('device','inode','uid','mode','size','nlink','sha256')
    if not renamed:
        keys += ('mtime_ns','ctime_ns')
    return all(actual.get(k) == expected.get(k) for k in keys)


def validate_info(value):
    integers=('device','inode','uid','mode','size','nlink','mtime_ns','ctime_ns')
    if (type(value) is not dict or set(value) != set(integers) | {'sha256'}
            or any(type(value.get(key)) is not int for key in integers)
            or value['device'] <= 0 or value['inode'] <= 0 or value['uid'] < 0
            or value['size'] < 0 or value['nlink'] != 1 or not 0 <= value['mode'] <= 0o777
            or value['mode'] & 0o022
            or type(value['sha256']) is not str or len(value['sha256']) != 64
            or any(c not in '0123456789abcdef' for c in value['sha256'])):
        raise RuntimeError('RecoveryBlocked: invalid exact component metadata')


def regular(info, device):
    if (not stat.S_ISREG(info.st_mode) or info.st_dev != device or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022):
        raise RuntimeError('RecoveryBlocked: component type/volume/uid/mode/link mismatch')


def file_info(directory, name):
    safe_name(name)
    directory.verify()
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory.fd)
    try:
        before = os.fstat(fd)
        regular(before, directory.identity[0])
        result = metadata(before)
        h = hashlib.sha256()
        while chunk := os.read(fd, 1024*1024):
            h.update(chunk)
        result['sha256'] = h.hexdigest()
        after = os.fstat(fd)
        at_path = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if metadata(before) != metadata(after) or metadata(before) != metadata(at_path):
            raise RuntimeError('RecoveryBlocked: component changed while hashing')
        return result
    finally:
        os.close(fd)


def maybe_info(directory, name):
    try:
        return file_info(directory, name)
    except FileNotFoundError:
        return None


def inventory(directory, coordination=None):
    result = {}
    directory.verify()
    for name in sorted(os.listdir(directory.fd)):
        info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if stat.S_ISREG(info.st_mode):
            result[name] = file_info(directory, name)
        elif stat.S_ISDIR(info.st_mode):
            if info.st_uid != os.getuid() or info.st_dev != directory.identity[0]:
                raise RuntimeError('RecoveryBlocked: foreign directory in target parent')
            result[name] = {'directory':[info.st_dev,info.st_ino,info.st_uid],
                            'mode':stat.S_IMODE(info.st_mode)}
            if coordination is not None and name == coordination.path.name:
                coordination.verify()
                if result[name]['directory'] != coordination.identity:
                    raise RuntimeError('RecoveryBlocked: coordination directory changed')
        else:
            raise RuntimeError('RecoveryBlocked: unknown/link component retained: '+name)
    directory.verify()
    return result


def rename_exact(source, source_name, destination, destination_name, expected, authorize):
    """Only an exact already-journaled rename may be completed or recognized."""
    safe_name(source_name)
    safe_name(destination_name)
    if source.identity[0] != destination.identity[0]:
        raise OSError(errno.EXDEV, 'RecoveryBlocked: cross-volume publication refused')
    current = maybe_info(source, source_name)
    at_destination = maybe_info(destination, destination_name)
    if current is None:
        if at_destination is None or not compatible(at_destination, expected, renamed=True):
            raise RuntimeError('RecoveryBlocked: rename has no exact source or completed destination')
        os.fsync(source.fd)
        os.fsync(destination.fd)
        return at_destination
    if not compatible(current, expected) or at_destination is not None:
        raise RuntimeError('RecoveryBlocked: rename source changed or destination occupied')
    authorize()
    source.verify()
    destination.verify()
    boundary('rename','before',{'source':str(source.path/source_name),'destination':str(destination.path/destination_name)})
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        function, flags = library.renameatx_np, 4
    elif sys.platform.startswith('linux'):
        function, flags = library.renameat2, 1
    else:
        raise RuntimeError('RecoveryBlocked: non-overwriting rename unsupported')
    function.argtypes = (ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(source.fd, os.fsencode(source_name), destination.fd, os.fsencode(destination_name), flags):
        code = ctypes.get_errno()
        raise OSError(code, 'RecoveryBlocked: non-overwriting rename failed')
    boundary('rename','after',{'source':str(source.path/source_name),'destination':str(destination.path/destination_name)})
    os.fsync(source.fd)
    boundary('rename','source_fsynced',{'directory':str(source.path)})
    os.fsync(destination.fd)
    boundary('rename','destination_fsynced',{'directory':str(destination.path)})
    final = file_info(destination, destination_name)
    if not compatible(final, expected, renamed=True):
        raise RuntimeError('RecoveryBlocked: renamed component changed')
    return final


def copy_exact(source, name, destination, expected, mode, binding, checkpoint, authorize, *, external=False):
    """Copy only inside a private evidence/staging directory, never final paths.

    An interrupted bound copy resumes only after its existing prefix matches
    the still-immutable source. An unbound or foreign existing inode blocks.
    """
    safe_name(name)
    current = file_info(source, name)
    if not compatible(current, expected):
        raise RuntimeError('RecoveryBlocked: copy source identity/content changed')
    if not external and source.identity[0] != destination.identity[0]:
        raise OSError(errno.EXDEV, 'RecoveryBlocked: copy destination is not on target volume')
    authorize()
    existing = maybe_info(destination, name)
    if existing is not None and binding is not None:
        if [existing['device'],existing['inode'],existing['uid']] != binding['identity']:
            raise RuntimeError('RecoveryBlocked: reserved copy inode changed')
        if (existing['size'],existing['sha256'],existing['mode']) == (expected['size'],expected['sha256'],mode):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=destination.fd)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(destination.fd)
            return existing
    source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=source.fd)
    output = None
    try:
        if metadata(os.fstat(source_fd)) != {k:v for k,v in expected.items() if k != 'sha256'}:
            raise RuntimeError('RecoveryBlocked: source replaced before copy')
        try:
            output = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=destination.fd)
        except FileExistsError:
            if binding is None:
                raise RuntimeError('RecoveryBlocked: unbound existing copy retained') from None
            output = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=destination.fd)
        else:
            binding = {'identity':[os.fstat(output).st_dev,os.fstat(output).st_ino,os.getuid()]}
            checkpoint(binding)
            os.fsync(destination.fd)
            boundary('copy','created',{'destination':str(destination.path/name),'binding':binding})
        info = os.fstat(output)
        regular(info, destination.identity[0])
        if [info.st_dev,info.st_ino,info.st_uid] != binding['identity'] or info.st_size > expected['size']:
            raise RuntimeError('RecoveryBlocked: interrupted copy identity changed')
        # Do not truncate or replace even a known partial copy.
        os.lseek(output, 0, os.SEEK_SET)
        copied = 0
        while chunk := os.read(output, 1024*1024):
            if os.read(source_fd, len(chunk)) != chunk:
                raise RuntimeError('RecoveryBlocked: interrupted copy prefix differs')
            copied += len(chunk)
        while chunk := os.read(source_fd, 1024*1024):
            authorize()
            view = memoryview(chunk)
            while view:
                count = os.write(output, view)
                if count <= 0:
                    raise OSError(errno.EIO, 'short recovery copy')
                view = view[count:]
                copied += count
            boundary('copy','chunk',{'destination':str(destination.path/name),'bytes':copied})
        os.fchmod(output, mode)
        os.fsync(output)
        boundary('copy','file_fsynced',{'destination':str(destination.path/name)})
        os.fsync(destination.fd)
        boundary('copy','directory_fsynced',{'destination':str(destination.path/name)})
        final = file_info(destination, name)
        if (final['size'],final['sha256'],final['mode']) != (expected['size'],expected['sha256'],mode):
            raise RuntimeError('RecoveryBlocked: copied component verification failed')
        if not compatible(file_info(source,name),expected):
            raise RuntimeError('RecoveryBlocked: source changed during copy')
        return final
    finally:
        if output is not None:
            os.close(output)
        os.close(source_fd)
