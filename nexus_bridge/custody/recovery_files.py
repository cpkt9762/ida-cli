"""Descriptor-bound component I/O shared by recovery, import and maintenance."""
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys
import uuid

PREPARATION_PREFIX = '.ida-cli-unpublished-'


def preparation_name(name):
    return (type(name) is str and name.startswith(PREPARATION_PREFIX)
            and len(name) == len(PREPARATION_PREFIX)+32
            and all(c in '0123456789abcdef' for c in name[len(PREPARATION_PREFIX):]))


def unpublished(directory):
    """Retain uncommitted scratch, never consume it as a file obligation.

    A fixed owner/checkpoint must name an exact inode before a scratch can
    enter a live slot. Abandoned scratch, even foreign bytes in this reserved
    namespace, is never read as authority, unlinked, published or GC'd.
    """
    result=set()
    for name in os.listdir(directory.fd):
        if preparation_name(name):
            info=os.stat(name,dir_fd=directory.fd,follow_symlinks=False)
            regular(info,directory.native_identity[0])
            result.add(name)
    return result


def visible_names(directory):
    return set(os.listdir(directory.fd))-unpublished(directory)


def rename_noreplace(source, name, destination, destination_name):
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        function, flags = library.renameatx_np, 4
    elif sys.platform.startswith('linux'):
        function, flags = library.renameat2, 1
    else:
        raise RuntimeError('RecoveryBlocked: non-overwriting rename unsupported')
    function.argtypes = (ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(source.fd, os.fsencode(name), destination.fd, os.fsencode(destination_name), flags):
        code = ctypes.get_errno()
        raise OSError(code, 'RecoveryBlocked: non-overwriting rename failed')


def probe_capabilities(parent, mounted):
    """Exercise only fresh owned names; never substitute an overwriting rename."""
    from target_coordination import Directory, identity
    result={'filesystem':mounted['filesystem'],'mount':mounted,
        'no_replace_rename':{'supported':False,'errno':None},
        'hardlink':{'supported':False,'errno':None},
        'permission_policy':'private-mode equivalence requires both capabilities'}
    name='.ida-cli-cap-probe-'+uuid.uuid4().hex
    directory=None
    descriptors=[]
    created=False
    created_identity=None
    cleanup=[]
    try:
        parent.verify()
        os.mkdir(name,0o700,dir_fd=parent.fd)
        created=True
        created_identity=identity(os.stat(name,dir_fd=parent.fd,follow_symlinks=False))
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent.fd)
        directory=Directory(parent.path/name,private=False,_fd=fd)
        if (directory.native_identity!=created_identity or directory.native_identity[0]!=parent.native_identity[0]
                or os.fstat(fd).st_uid!=os.getuid()):
            raise RuntimeError('capability probe directory identity changed')
        def create(slot,data):
            fd=os.open(slot,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory.fd)
            descriptors.append(fd)
            if os.write(fd,data)!=len(data):raise OSError(errno.EIO,'short capability probe write')
            return fd
        source=create('source',b'x')
        blocker=create('blocker',b'y')
        moved=False
        try:
            rename_noreplace(directory,'source',directory,'moved')
        except OSError as error:result['no_replace_rename']['errno']=error.errno
        else:
            moved=True
            try:rename_noreplace(directory,'blocker',directory,'moved')
            except FileExistsError:
                if (identity(os.stat('moved',dir_fd=directory.fd,follow_symlinks=False))==identity(os.fstat(source))
                        and identity(os.stat('blocker',dir_fd=directory.fd,follow_symlinks=False))==identity(os.fstat(blocker))
                        and os.pread(source,2,0)==b'x' and os.pread(blocker,2,0)==b'y'):
                    result['no_replace_rename']={'supported':True,'errno':0,'collision_errno':errno.EEXIST}
            except OSError as error:result['no_replace_rename']['errno']=error.errno
        source_name='moved' if moved else 'source'
        try:
            os.link(source_name,'linked',src_dir_fd=directory.fd,dst_dir_fd=directory.fd,follow_symlinks=False)
        except OSError as error:result['hardlink']['errno']=error.errno
        else:
            try:os.link(source_name,'linked',src_dir_fd=directory.fd,dst_dir_fd=directory.fd,follow_symlinks=False)
            except FileExistsError:
                if identity(os.stat('linked',dir_fd=directory.fd,follow_symlinks=False))==identity(os.fstat(source)):
                    result['hardlink']={'supported':True,'errno':0,'collision_errno':errno.EEXIST}
            except OSError as error:result['hardlink']['errno']=error.errno
    except (OSError,RuntimeError) as error:
        result['probe_error']={'message':str(error),'errno':getattr(error,'errno',None)}
    finally:
        if directory is not None:
            owned=[]
            for fd in descriptors:
                try:owned.append(identity(os.fstat(fd)))
                except OSError as error:cleanup.append(str(error))
            try:slots=os.listdir(directory.fd)
            except OSError as error:
                cleanup.append(str(error))
                slots=[]
            for slot in slots:
                try:
                    info=os.stat(slot,dir_fd=directory.fd,follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or identity(info) not in owned:
                        cleanup.append('unrecognized probe entry retained: '+str(directory.path/slot))
                        continue
                    os.unlink(slot,dir_fd=directory.fd)
                except OSError as error:cleanup.append(str(error))
            try:
                parent.verify()
                if identity(os.stat(name,dir_fd=parent.fd,follow_symlinks=False))!=directory.native_identity:
                    cleanup.append('probe directory replacement retained')
                elif not cleanup:os.rmdir(name,dir_fd=parent.fd)
            except (OSError,RuntimeError) as error:cleanup.append(str(error))
            try:directory.close()
            except OSError as error:cleanup.append(str(error))
        elif created:
            try:
                parent.verify()
                if identity(os.stat(name,dir_fd=parent.fd,follow_symlinks=False))!=created_identity:
                    cleanup.append('unverified probe directory replacement retained')
                else:os.rmdir(name,dir_fd=parent.fd)
            except (OSError,RuntimeError) as error:cleanup.append(str(error))
        for fd in descriptors:
            try:os.close(fd)
            except OSError as error:cleanup.append(str(error))
    result['cleanup_errors']=cleanup
    result['supported']=all(result[key]['supported'] for key in ('no_replace_rename','hardlink')) and not cleanup
    unsupported={errno.ENOTSUP,errno.EOPNOTSUPP,errno.ENOSYS}
    result['missing_capabilities']=[key+('_unsupported' if result[key]['errno'] in unsupported else '_unverified')
                                  for key in ('no_replace_rename','hardlink') if not result[key]['supported']]
    return result


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
        regular(before, directory.native_identity[0])
        result = metadata(before)
        result['device']=directory.object_identity(before)[0]
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
    # Capability probes use only this parent-directory lock and release it
    # before target EX. Snapshots cannot record their transient private names.
    with directory.fact_view(shared=True):
        return inventory_locked(directory,coordination)


def inventory_locked(directory, coordination=None):
    result = {}
    directory.verify()
    names=visible_names(directory) if directory.private else os.listdir(directory.fd)
    for name in sorted(names):
        info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if stat.S_ISREG(info.st_mode):
            result[name] = file_info(directory, name)
        elif stat.S_ISDIR(info.st_mode):
            if info.st_uid != os.getuid() or info.st_dev != directory.native_identity[0]:
                raise RuntimeError('RecoveryBlocked: foreign directory in target parent')
            result[name] = {'directory':directory.object_identity(info),
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
    if source.native_identity[0] != destination.native_identity[0]:
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
    rename_noreplace(source,source_name,destination,destination_name)
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
    if not external and source.native_identity[0] != destination.native_identity[0]:
        raise OSError(errno.EXDEV, 'RecoveryBlocked: copy destination is not on target volume')
    authorize()
    existing = maybe_info(destination, name)
    if binding is not None and 'prepared' in binding:
        return publish_copy(destination,name,binding,authorize)
    if binding is None:
        if existing is not None:
            raise RuntimeError('RecoveryBlocked: unbound existing copy retained')
        return prepare_copy(source,name,destination,expected,mode,checkpoint,authorize)
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
        opened=metadata(os.fstat(source_fd))
        opened['device']=source.object_identity(os.fstat(source_fd))[0]
        if opened != {k:v for k,v in expected.items() if k != 'sha256'}:
            raise RuntimeError('RecoveryBlocked: source replaced before copy')
        try:
            output = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=destination.fd)
        except FileExistsError:
            if binding is None:
                raise RuntimeError('RecoveryBlocked: unbound existing copy retained') from None
            output = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=destination.fd)
        else:
            binding = {'identity':destination.object_identity(os.fstat(output))}
            checkpoint(binding)
            os.fsync(destination.fd)
            boundary('copy','created',{'destination':str(destination.path/name),'binding':binding})
        info = os.fstat(output)
        regular(info, destination.native_identity[0])
        if destination.object_identity(info) != binding['identity'] or info.st_size > expected['size']:
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


def publish_copy(destination,name,binding,authorize):
    """Only a complete, fsynced and checkpointed inode enters the live name."""
    prepared=binding['prepared']
    expected=binding['metadata']
    if (not preparation_name(prepared) or binding['identity'] !=
            [expected['device'],expected['inode'],expected['uid']]):
        raise RuntimeError('RecoveryBlocked: invalid prepared copy reservation')
    authorize()
    return rename_exact(destination,prepared,destination,name,expected,authorize)


def prepare_copy(source,name,destination,expected,mode,checkpoint,authorize):
    """Pre-binding crashes retain scratch; they cannot occupy a live slot."""
    prepared=PREPARATION_PREFIX+uuid.uuid4().hex
    input_fd=os.open(name,os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=source.fd)
    output=None
    try:
        opened=metadata(os.fstat(input_fd))
        opened['device']=source.object_identity(os.fstat(input_fd))[0]
        if opened != {k:v for k,v in expected.items() if k!='sha256'}:
            raise RuntimeError('RecoveryBlocked: source replaced before preparation')
        output=os.open(prepared,os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600,dir_fd=destination.fd)
        boundary('copy','unbound_created',{'destination':str(destination.path/prepared)})
        boundary('copy','created',{'destination':str(destination.path/name),'preparation':prepared})
        copied=0
        while chunk:=os.read(input_fd,1024*1024):
            authorize()
            view=memoryview(chunk)
            while view:
                count=os.write(output,view)
                if count<=0:raise OSError(errno.EIO,'short recovery preparation copy')
                view=view[count:];copied+=count
            boundary('copy','chunk',{'destination':str(destination.path/name),'bytes':copied})
        os.fchmod(output,mode)
        os.fsync(output)
        boundary('copy','file_fsynced',{'destination':str(destination.path/name)})
        os.fsync(destination.fd)
        boundary('copy','directory_fsynced',{'destination':str(destination.path/name)})
        final=file_info(destination,prepared)
        if (final['size'],final['sha256'],final['mode']) != (expected['size'],expected['sha256'],mode):
            raise RuntimeError('RecoveryBlocked: prepared copy verification failed')
        if not compatible(file_info(source,name),expected):
            raise RuntimeError('RecoveryBlocked: source changed during preparation')
        binding={'identity':destination.object_identity(os.fstat(output)),'prepared':prepared,'metadata':final}
        checkpoint(binding)
        boundary('copy','checkpointed',{'destination':str(destination.path/name),'binding':binding})
        return publish_copy(destination,name,binding,authorize)
    finally:
        if output is not None:os.close(output)
        os.close(input_fd)
