"""Target-side coordination, immutable observations and bounded healthy epochs.

All target authority changes require root SH followed by the stable target EX.
An unrecognized or torn record is retained and blocks this target.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time

SCHEMA = 1
LIMIT = 96
RESERVE = 8
SUMMARY_LIMIT = 64
SUMMARY_BYTES = 16384
MAX_RECORD = 1024 * 1024
_permission_diagnostics = set()
_capabilities = {}
_capability_lock = threading.Lock()


class FilesystemCapabilityError(RuntimeError):
    """Admission refusal with diagnostics that require no Nexus discovery."""
    def __init__(self, details):
        self.details=json.loads(encoded(details))
        super().__init__('FilesystemCapabilitiesRefused: '+encoded(self.details).decode())


def capability_key(fd, mounted):
    return (os.fstat(fd).st_dev,mounted['filesystem'],mounted['flags'],mounted['owner'],
            tuple(mounted['fsid']),mounted['mounted_on'],mounted['mounted_from'],
            tuple(mounted['root_identity']),mounted['device_epoch'])


def capability_status(fd, mounted=None):
    mounted=mounted or native_mount(fd)
    value=_capabilities.get(capability_key(fd,mounted),{'supported':False,'reason':'not_measured'})
    return json.loads(encoded(value))


def native_device_epoch(source):
    """IORegistry IDs distinguish detach/attach even when BSD names are reused."""
    import ctypes
    if not source.startswith('/dev/'):
        return None
    library=ctypes.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
    match=library.IOBSDNameMatching
    match.argtypes=(ctypes.c_uint32,ctypes.c_uint32,ctypes.c_char_p)
    match.restype=ctypes.c_void_p
    service=library.IOServiceGetMatchingService
    service.argtypes=(ctypes.c_uint32,ctypes.c_void_p)
    service.restype=ctypes.c_uint32
    entry=library.IORegistryEntryGetRegistryEntryID
    entry.argtypes=(ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint64))
    entry.restype=ctypes.c_int
    release=library.IOObjectRelease
    release.argtypes=(ctypes.c_uint32,)
    release.restype=ctypes.c_int
    matching=match(0,0,os.fsencode(source.removeprefix('/dev/')))
    if not matching:
        raise RuntimeError('CoordinationBlocked: native device matching unavailable')
    # IOServiceGetMatchingService consumes the matching dictionary reference.
    handle=service(0,matching)
    if not handle:
        raise RuntimeError('CoordinationBlocked: mounted device instance unavailable')
    try:
        result=ctypes.c_uint64()
        if entry(handle,ctypes.byref(result)) or not result.value:
            raise RuntimeError('CoordinationBlocked: mounted device epoch unavailable')
        return result.value
    finally:release(handle)


def native_mount(fd):
    """Darwin SDK sys/mount.h __DARWIN_STRUCT_STATFS64, queried by FD."""
    import ctypes
    if sys.platform != 'darwin':
        info=os.fstat(fd)
        return {'filesystem':'unvalidated','flags':0,'owner':-1,'fsid':[],
                'mounted_on':'','mounted_from':'','root_identity':identity(info),'device_epoch':None}
    class Statfs(ctypes.Structure):
        _fields_=[('bsize',ctypes.c_uint32),('iosize',ctypes.c_int32),
            ('counts',ctypes.c_uint64*5),('fsid',ctypes.c_int32*2),
            ('owner',ctypes.c_uint32),('type',ctypes.c_uint32),
            ('flags',ctypes.c_uint32),('subtype',ctypes.c_uint32),
            ('filesystem',ctypes.c_char*16),('mounted_on',ctypes.c_char*1024),
            ('mounted_from',ctypes.c_char*1024),('flags_ext',ctypes.c_uint32),
            ('reserved',ctypes.c_uint32*7)]
    if ctypes.sizeof(Statfs)!=2168 or Statfs.owner.offset!=56 or Statfs.filesystem.offset!=72:
        raise RuntimeError('CoordinationBlocked: unvalidated native statfs ABI')
    value=Statfs()
    function=ctypes.CDLL(None,use_errno=True).fstatfs
    function.argtypes=(ctypes.c_int,ctypes.POINTER(Statfs))
    function.restype=ctypes.c_int
    if function(fd,ctypes.byref(value)):
        code=ctypes.get_errno()
        raise OSError(code,'native mounted-volume identity unavailable')
    mounted_on=os.fsdecode(bytes(value.mounted_on))
    root=os.open(mounted_on,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(root)
        if info.st_dev!=os.fstat(fd).st_dev:
            raise RuntimeError('CoordinationBlocked: mounted root changed during identity capture')
        root_identity=[*identity(info),info.st_birthtime]
    finally:os.close(root)
    source=os.fsdecode(bytes(value.mounted_from))
    return {'filesystem':bytes(value.filesystem).decode('ascii'),
            'flags':value.flags,'owner':value.owner,'fsid':list(value.fsid),
            'mounted_on':mounted_on,'mounted_from':source,
            'root_identity':root_identity,'device_epoch':native_device_epoch(source)}


def permission_scope(fd):
    """Only current-user mounted, local permissionless filesystems qualify."""
    mounted=native_mount(fd)
    info=os.fstat(fd)
    candidate=(mounted['filesystem'] in ('exfat','msdos','msdosfs','fat')
        and type(mounted['flags']) is int and bool(mounted['flags'] & 0x1000)
        and type(mounted['owner']) is int and mounted['owner']==os.getuid()
        and info.st_uid==os.getuid())
    capabilities=capability_status(fd,mounted)
    relaxed=candidate and capabilities.get('supported') is True
    result=dict(mounted,relaxed=relaxed,
        reason=('permissionless_local_volume' if relaxed else
                'filesystem_capabilities_not_verified' if candidate else 'strict_unix_mode'),
        capabilities=capabilities,
        basis='statfs filesystem allowlist + MNT_LOCAL + f_owner + st_uid',
        chmod_probe='not run: filesystem type policy; inspection is read-only')
    if candidate:
        import logging
        key=(info.st_dev,tuple(mounted['fsid']),mounted['owner'],mounted['filesystem'],relaxed)
        if key not in _permission_diagnostics:
            _permission_diagnostics.add(key)
            logging.getLogger(__name__).warning('permissionless_local_volume: %s',encoded(result).decode())
    return result


def private_mode(fd, value, *, directory=False):
    if stat.S_IMODE(value.st_mode)==(0o700 if directory else 0o600):
        return True
    return permission_scope(fd)['relaxed']


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else encoded(value)).hexdigest()


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid]


def checked(fd, directory=False):
    value = os.fstat(fd)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(value.st_mode) or value.st_uid != os.getuid()
            or not private_mode(fd,value,directory=directory)
            or (not directory and value.st_nlink != 1)):
        raise RuntimeError('CoordinationBlocked: untrusted type/uid/mode/link identity')
    return value


class Directory:
    def __init__(self, path, *, private=True, _fd=None):
        self.path = Path(path)
        self.private = private
        self.fd = _fd if _fd is not None else self.open_path(self.path)
        value = os.fstat(self.fd)
        try:
            if private:
                checked(self.fd, True)
            elif not stat.S_ISDIR(value.st_mode) or value.st_uid not in (0, os.getuid()):
                raise RuntimeError('CoordinationBlocked: target parent ownership')
            self.identity = identity(value)
            self.native_identity = list(self.identity)
            self.canonical_device = value.st_dev
        except BaseException:
            os.close(self.fd)
            raise

    @staticmethod
    def open_path(path):
        path = Path(path)
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError('absolute coordination path required')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in path.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=fd)
                os.close(fd)
                fd = next_fd
            result, fd = fd, None
            return result
        finally:
            if fd is not None:
                os.close(fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def verify(self):
        if identity(os.stat(self.path, follow_symlinks=False)) != self.native_identity:
            raise RuntimeError('CoordinationBlocked: directory identity changed')

    def object_identity(self, info):
        value=identity(info)
        if value[0] == self.native_identity[0]:value[0]=self.canonical_device
        return value

    def inherit_volume(self, other):
        if self.native_identity[0] == other.native_identity[0]:
            self.canonical_device=other.canonical_device
            self.identity=[self.canonical_device,*self.native_identity[1:]]

    def child(self, name, *, create=True):
        if not name or Path(name).name != name or name in ('.', '..'):
            raise ValueError('unsafe coordination component')
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=self.fd)
                os.fsync(self.fd)
            except FileExistsError:
                pass
        self.verify()
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        result = Directory(self.path / name, _fd=fd)
        result.inherit_volume(self)
        try:
            result.verify()
            self.verify()
            return result
        except BaseException:
            result.close()
            raise

    def read(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            before = checked(fd)
            if before.st_size > MAX_RECORD:
                raise RuntimeError('CoordinationBlocked: oversized record')
            data = os.read(fd, MAX_RECORD + 1)
            after = os.fstat(fd)
            at_path = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or identity(before) != identity(at_path) or len(data) != before.st_size):
                raise RuntimeError('CoordinationBlocked: record changed during read')
            return json.loads(data), before, data
        finally:
            os.close(fd)

    def durable(self, name, value, *, immutable=False):
        from durable_records import write
        write(self, name, value, immutable=immutable)

    @contextmanager
    def fact_view(self, *, shared=False):
        """Serialize a producer's publication with namespace readers.

        This directory OFD is independent of root/target locks. Producers must
        never acquire target EX while holding it; readers may already hold EX.
        No stable lock name is created or removed. A crashed publisher releases
        this lock but leaves its exact pending bytes for the usual rejection.
        """
        deadline = time.monotonic() + .25
        while True:
            try:
                fcntl.flock(self.fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    from target_journal import ObservationPending
                    raise ObservationPending('ObservationPending: immutable publication still active') from None
                time.sleep(.001)
        try:
            self.verify()
            yield
            self.verify()
        finally:
            fcntl.flock(self.fd, fcntl.LOCK_UN)

    def recover_record(self, name, *, validate=None):
        from durable_records import resume
        return resume(self, name, validate=validate)

    def inspect_record(self, name):
        from durable_records import inspect
        return inspect(self, name)

    def retry_immutable(self, name, value, *, immutable=True):
        """Resume only this producer's durably reserved exact immutable slot."""
        data = encoded(value)
        if len(data) > MAX_RECORD or Path(name).name != name:
            raise ValueError('invalid immutable fact slot')
        temporary = name + '.new'
        # Publication can fail between link and unlink. Only the two exact
        # names of this reserved slot may share the completed immutable inode.
        if immutable:
            try:
                final = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                pending = os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if (identity(final) == identity(pending) and final.st_nlink == 2
                        and stat.S_ISREG(final.st_mode) and final.st_uid == os.getuid()
                        and stat.S_IMODE(final.st_mode) == 0o600):
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
                    try:
                        if identity(os.fstat(fd)) != identity(final) or os.read(fd, MAX_RECORD+1) != data:
                            raise RuntimeError('ObservationRecoveryBlocked: linked fact conflict')
                        self.verify()
                        if identity(os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)) != identity(final):
                            raise RuntimeError('ObservationRecoveryBlocked: pending link changed')
                        os.unlink(temporary, dir_fd=self.fd)
                        os.fsync(self.fd)
                    finally:
                        os.close(fd)
        try:
            current, _, raw = self.read(name)
        except FileNotFoundError:
            pass
        else:
            if immutable:
                if raw != data or current != value:
                    raise RuntimeError('ObservationRecoveryBlocked: immutable fact conflict')
                os.fsync(self.fd)
                return
        try:
            fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self.fd)
        except FileExistsError:
            fd = os.open(temporary, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            before = checked(fd)
            prefix = os.read(fd, MAX_RECORD + 1)
            if not data.startswith(prefix) or len(prefix) != before.st_size:
                raise RuntimeError('ObservationRecoveryBlocked: reserved fact partial content conflict')
            self.verify()
            if identity(before) != identity(os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)):
                raise RuntimeError('ObservationRecoveryBlocked: reserved fact inode changed')
            view = memoryview(data)[len(prefix):]
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError('short immutable fact write')
                view = view[count:]
            os.fsync(fd)
            if immutable:
                os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
                os.unlink(temporary, dir_fd=self.fd)
            else:
                os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            os.close(fd)

    def lock(self, name='lock', *, shared=False, deadline=None, nb=False, create=True):
        created = False
        try:
            if not create:
                raise FileExistsError()
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self.fd)
            created = True
        except FileExistsError:
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            value = checked(fd)
            if created:
                os.fsync(fd)
                os.fsync(self.fd)
            while True:
                try:
                    fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if nb or deadline is None or time.monotonic() >= deadline:
                        raise
                    time.sleep(min(.005, max(0, deadline - time.monotonic())))
            if identity(value) != identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False)):
                raise RuntimeError('CoordinationBlocked: stable lock replaced')
            self.verify()
            return fd
        except BaseException:
            os.close(fd)
            raise


def canonical(path):
    return os.path.realpath(os.path.abspath(os.path.expanduser(os.fspath(path))))


def folded(path):
    value = canonical(path)
    return value.casefold() if sys.platform == 'darwin' else os.path.normcase(value) if os.name == 'nt' else value


def physical_case(parent, target):
    """Keep the disk spelling of an existing Darwin case alias."""
    if sys.platform != 'darwin':
        return target
    try:fd=os.open(target.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent.fd)
    except FileNotFoundError:return target
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError('CoordinationBlocked: target is not a regular database')
        # Darwin SDK fcntl.h F_GETPATH; no database bytes are read.
        name=Path(os.fsdecode(fcntl.fcntl(fd,50,bytes(1024)).split(b'\0',1)[0])).name
        if name.casefold()==target.name.casefold():
            if identity(os.stat(name,dir_fd=parent.fd,follow_symlinks=False))!=identity(info):
                raise RuntimeError('CoordinationBlocked: physical case alias changed')
            return target.with_name(name)
        return target  # Preserve the declared Nexus key for non-case Unicode differences.
    finally:os.close(fd)


def preflight_capabilities(path):
    """Before business admission, probe outside the stable coordination tree."""
    from recovery_files import probe_capabilities
    target=Path(canonical(path))
    managed=target.parent.parent.name in ('generations','quarantine')
    probe=Directory(target.parent.parent.parent if managed else target.parent,private=False)
    try:
        # Managed payload selection remains under the constructor's stable
        # root SH, so GC may rename/delete payloads without racing this probe.
        mounted=native_mount(probe.fd)
        key=capability_key(probe.fd,mounted)
        with _capability_lock:
            result=_capabilities.get(key)
            # Capability is a mount property; writability is still a per-parent
            # admission check. A transient write/probe failure never poisons it.
            if result is None or not os.access(probe.path,os.W_OK|os.X_OK):
                with probe.fact_view():
                    result=probe_capabilities(probe,mounted)
                stable_refusal=(not result.get('probe_error') and not result['cleanup_errors']
                    and result['missing_capabilities']
                    and all(reason.endswith('_unsupported') for reason in result['missing_capabilities']))
                if result['supported'] or stable_refusal:
                    _capabilities[key]=json.loads(encoded(result))
        if not result['supported']:
            import logging
            failure=FilesystemCapabilityError(result)
            logging.getLogger(__name__).warning('%s',failure)
            raise failure
        return json.loads(encoded(result))
    finally:
        probe.close()


def case_authority(authority, requested):
    """Nexus case identity cannot merge two distinct existing database files."""
    if type(authority) is not str or Path(authority).parent!=Path(requested).parent:
        return False
    if authority==str(requested):return True
    if folded(authority)!=folded(requested):return False
    observed=[]
    for path in (authority,requested):
        try:observed.append(identity(os.stat(path,follow_symlinks=False)))
        except FileNotFoundError:observed.append(None)
    if all(observed) and observed[0]!=observed[1]:
        raise RuntimeError('CoordinationBlocked: distinct databases share the Nexus case identity')
    return True


class Target:
    def __copy__(self):
        raise TypeError('target ownership cannot be copied; move it')

    def __deepcopy__(self, _memo):
        raise TypeError('target ownership cannot be copied; move it')

    def __init__(self, target, *, root_locked=False, create=True, for_open=False):
        self.target = Path(canonical(target))
        self.root_locked = root_locked
        self.create = create
        self.root = None
        self.directories = []
        self.root_fd = self.target_fd = None
        self.target_guard = None
        self.transferred = False
        self.evidence_path = None
        try:
            locator=self.evidence_locator(self.target)
            if locator is not None:
                directory=Directory(locator)
                try:
                    record,_,_=directory.read('target.json')
                    original=record.get('target')
                    if type(original) is not str or self.evidence_locator(Path(original)) is not None:
                        raise RuntimeError('CoordinationBlocked: invalid evidence back-reference')
                    requested=self.target
                    self.__init__(original,root_locked=root_locked,create=False)
                    directory.inherit_volume(self.directory)
                    if self.directory.identity != directory.identity or encoded(self.key) != encoded(record.get('coord_key')):
                        raise RuntimeError('CoordinationBlocked: evidence back-reference authority mismatch')
                    self.evidence_path=requested
                    return
                finally:directory.close()
            if for_open:
                preflight_capabilities(self.target)
            container = self.target.parent.parent
            self.binding = None
            if container.name in ('generations', 'quarantine'):
                self.root = Directory(container.parent, private=False)
                self.directories.append(self.root)
                if not root_locked:
                    self.root_fd = self.root.lock('.cache.lock', shared=True, create=create)
                gid = self.target.parent.name
                if not gid or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in gid):
                    raise RuntimeError('CoordinationBlocked: invalid generation identity')
                # A rename into quarantine retains exactly the same generation
                # inode/manifest and stable lock. Missing payloads require the
                # already established coordination identity; never make a new one.
                paths = [container.parent / name / gid for name in ('generations', 'quarantine')]
                existing = [p for p in paths if p.exists() or p.is_symlink()]
                if len(existing) > 1:
                    raise RuntimeError('CoordinationBlocked: generation identity collision')
                if existing:
                    parent = Directory(existing[0], private=False)
                    self.directories.append(parent)
                    if parent.native_identity[0]!=self.root.native_identity[0]:
                        raise RuntimeError('CoordinationBlocked: managed payload crosses its resource-root volume')
                    fd = os.open('generation.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent.fd)
                    try:
                        info = os.fstat(fd)
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                                or info.st_nlink != 1 or info.st_size > MAX_RECORD
                                or stat.S_IMODE(info.st_mode) & 0o022):
                            raise RuntimeError('CoordinationBlocked: invalid generation manifest identity')
                        raw = os.read(fd, MAX_RECORD + 1)
                        manifest = json.loads(raw)
                        if (not isinstance(manifest, dict) or type(manifest.get('version')) is not int
                                or manifest['version'] != 1 or not isinstance(manifest.get('key'), str)
                                or not manifest['key'] or len(raw) != info.st_size):
                            raise RuntimeError('CoordinationBlocked: invalid generation manifest')
                        self.binding = {'group':parent.identity, 'manifest':[info.st_dev, info.st_ino],
                                        'sha256':digest(raw)}
                    finally:
                        os.close(fd)
                parent = self.root
                coordination = self.root.child('.nexus-coordination',create=create)
                self.directories.append(coordination)
                generations = coordination.child('generations',create=create)
                self.directories.append(generations)
                self.directory = generations.child(gid, create=create and bool(existing))
                self.key = {'kind':'generation', 'root':self.root.identity, 'gid':gid}
                self.original = str(container.parent / 'generations' / gid / 'input.i64')
            else:
                parent = Directory(self.target.parent, private=False)
                self.directories.append(parent)
                self.target=physical_case(parent,self.target)
                key = digest(folded(self.target).encode())
                self.directory = parent.child('.ida-cli-txn-' + key,create=create)
                self.key = {'kind':'direct', 'parent':parent.identity, 'identity_key':key}
                self.original = str(self.target)
            self.directories.append(self.directory)
            if self.directory.identity[0] != parent.identity[0]:
                raise RuntimeError('CoordinationBlocked: coordination crosses target volume')
            # Managed targets share the actual store's root guard. A direct
            # database has no managed payload root: its stable coordination
            # directory is the file-recovery resource root, independent of HOME.
            self.resource_root = self.root or self.directory
            self.resource_lock = '.cache.lock' if self.root is not None else 'root.lock'
            if self.root is None:
                self.root_fd = self.directory.lock(self.resource_lock, shared=True, create=create)
            self.native_key=json.loads(encoded(self.key))
            from volume_identity import load_binding
            load_binding(self)
        except BaseException:
            self.close()
            raise

    def business_admission(self):
        """Evidence/GC access keeps its identity; business may only use live payload."""
        if self.target_fd is None:
            raise RuntimeError('business admission requires target EX')
        if self.evidence_path is not None:
            raise RuntimeError('CoordinationBlocked: evidence is not a business target; authority='+str(self.directory.path))
        if self.root is not None:
            live = self.root.path / 'generations' / self.key['gid']
            isolated = self.root.path / 'quarantine' / self.key['gid']
            if isolated.exists():
                raise RuntimeError('TargetQuarantined: payload is reserved for GC/evidence')
            if not live.exists():
                raise RuntimeError('TargetRetired: payload is reserved for GC/evidence')
            if self.target.parent.parent.name == 'quarantine':
                raise RuntimeError('TargetQuarantined: quarantine is not a business path')
            if self.root.object_identity(os.stat(live, follow_symlinks=False)) != self.binding['group']:
                raise RuntimeError('CoordinationBlocked: live payload identity changed')

    @staticmethod
    def evidence_locator(path):
        parts=path.parts
        for index,part in enumerate(parts):
            if part.startswith('.ida-cli-txn-'):
                return Path(*parts[:index+1])
            if part=='.nexus-coordination':
                if len(parts) <= index+2 or parts[index+1] != 'generations':
                    raise RuntimeError('CoordinationBlocked: malformed managed evidence path')
                return Path(*parts[:index+3])
        return None

    def recovery_root_binding(self):
        if self.root_fd is None:
            if self.root is None or not self.root_locked:
                raise RuntimeError('RecoveryBlocked: no owned root guard for executor')
            fd = os.open(self.resource_lock,os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self.resource_root.fd)
            try:
                lock_identity = self.resource_root.object_identity(checked(fd))
            finally:
                os.close(fd)
        else:
            info = checked(self.root_fd)
            lock_identity = self.resource_root.object_identity(info)
            current = os.stat(self.resource_lock,dir_fd=self.resource_root.fd,follow_symlinks=False)
            if self.resource_root.object_identity(current) != lock_identity:
                raise RuntimeError('RecoveryBlocked: stable resource root lock replaced')
        self.resource_root.verify()
        return {'path':str(self.resource_root.path),'directory':self.resource_root.identity,
                'lock':self.resource_lock,'lock_identity':lock_identity}

    @contextmanager
    def locked(self, *, deadline=None, nb=False, recover=True, _received=None):
        from recovery_files import visible_names
        if self.target_guard is not None:
            raise RuntimeError('CoordinationBlocked: target guard already owned')
        guard = _received or TransferredTargetGuard(self.directory.lock(deadline=deadline, nb=nb, create=self.create))
        fd = guard.fd
        self.target_guard = guard
        self.transferred = _received is not None
        self.target_fd = fd
        self.lock_deadline=deadline
        try:
            if recover:
                self.directory.recover_record('target.json')
            expected = {'schema':SCHEMA, 'coord_key':self.key, 'target':self.original,
                        'generation':self.binding, 'lock_identity':self.directory.object_identity(os.fstat(fd))}
            try:
                value, _, _ = self.directory.read('target.json')
                if type(value) is dict and case_authority(value.get('target'),self.target):
                    candidate=dict(expected,target=value['target'])
                    if encoded(value) in (encoded(candidate),encoded(dict(candidate,creation_intent=True))):
                        self.original=value['target']
                        expected=candidate
                if self.root is not None and self.binding is None:
                    expected['generation'] = value.get('generation')
                initial = {'lock','target.json'} | ({'root.lock'} if self.root is None else set())
                if (recover and encoded(value) == encoded(dict(expected, creation_intent=True))
                        and visible_names(self.directory) == initial):
                    self.directory.durable('target.json', expected)
                    value = expected
                if encoded(value) != encoded(expected) or (self.root is not None and not expected['generation']):
                    raise RuntimeError('CoordinationBlocked: target identity mismatch')
            except FileNotFoundError:
                if not self.create:
                    raise RuntimeError('CoordinationBlocked: read-only target identity missing') from None
                if self.root is not None and self.binding is None:
                    raise RuntimeError('CoordinationBlocked: missing payload has no stable identity') from None
                if visible_names(self.directory) != ({'lock','root.lock'} if self.root is None else {'lock'}):
                    raise RuntimeError('CoordinationBlocked: missing target identity with existing responsibilities') from None
                # A crash at either durable boundary preserves an explicit
                # uncommitted identity instead of blessing a partial namespace.
                self.directory.durable('target.json', dict(expected, creation_intent=True), immutable=True)
                self.directory.durable('target.json', expected)
            from volume_identity import ensure_binding
            if recover:ensure_binding(self)
            self.lock_binding=encoded(expected)
            yield self
        finally:
            active=self.target_guard
            self.target_fd = None
            self.target_guard = None
            if active is not None and active is not guard:
                active.close()
            guard.close()

    def reacquire_after_transfer(self):
        """New OFD fence after old rights moved; never reenable the old token."""
        if self.root_fd is None or self.target_guard is None or self.target_guard.fd is not None or self.target_fd is not None:
            raise RuntimeError('HandoffBlocked: old target reference must be closed before fence')
        fd=self.directory.lock(nb=True,create=False)
        try:
            value,_,_=self.directory.read('target.json')
            if encoded(value) != self.lock_binding:
                raise RuntimeError('HandoffBlocked: target identity changed before independent fence')
            self.recovery_root_binding()
            self.target_guard=TransferredTargetGuard(fd)
            self.target_fd=fd
            self.transferred=False
        except BaseException:
            os.close(fd)
            raise

    def move_guard(self):
        if self.target_guard is None:
            raise RuntimeError('HandoffBlocked: no owned target guard')
        guard = self.target_guard.move()
        self.target_fd = None
        return guard

    def move(self):
        """Same-process unique move; the old context/future can only close."""
        if self.target_guard is None or self.root_fd is None:
            raise RuntimeError('HandoffBlocked: complete target/root ownership required')
        moved=object.__new__(Target)
        moved.__dict__=dict(self.__dict__)
        moved.target_guard=self.move_guard()
        moved.target_fd=moved.target_guard.fd
        moved.transferred=True  # A move is not an independent OFD recovery fence.
        self.root_fd=None
        self.directories=[]
        return moved

    def close(self):
        if self.target_guard is not None:
            self.target_guard.close()
            self.target_fd=None
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None
        for directory in reversed(self.directories):
            directory.close()
        self.directories.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class TransferredTargetGuard:
    """Unique close-only ownership of a flock OFD, including surplus rights."""
    def __init__(self, fd):
        self.fd = fd

    def __copy__(self):
        raise TypeError('target guard is move-only')

    def __deepcopy__(self, _memo):
        raise TypeError('target guard is move-only')

    def move(self):
        if self.fd is None:
            raise RuntimeError('HandoffBlocked: target guard already moved')
        result = TransferredTargetGuard(self.fd)
        self.fd = None
        return result

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)  # Never LOCK_UN: other received/in-flight OFD refs may exist.

    def __del__(self):
        self.close()
