"""Creation scope for durable obligations; never grants OS retirement authority."""
import hashlib
import logging
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import threading
import uuid

from custody_process_identity import capture

_scopes = {}
_lock = threading.Lock()


def native_scope(directory, device):
    """Collect optional retirement identity without disabling ordinary custody."""
    reasons = []
    scope = {'device': device, 'same_boot_eligibility': False,
        'boot_retirement_capability': 'UnsupportedBootScope'}
    def query(label, argv, decode=lambda data: data):
        try:
            return decode(subprocess.check_output(['timeout', '2s', *argv], stderr=subprocess.PIPE))
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, IndexError) as error:
            reasons.append(label + ' unavailable: ' + type(error).__name__)
            return None
    hardware = query('native machine identity',
        ['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice', '-a'], plistlib.loads)
    mounted = query('mount identity', ['/bin/df', '-P', str(directory)],
        lambda data: data.decode().splitlines()[-1].split()[0])
    volume = query('diskutil volume identity', ['/usr/sbin/diskutil', 'info', '-plist', mounted],
        plistlib.loads) if mounted else None
    machine = (hardware[0].get('IOPlatformUUID') if isinstance(hardware, list) and hardware
        and isinstance(hardware[0], dict) else None)
    volume = volume if isinstance(volume, dict) else {}
    native_volume = volume.get('VolumeUUID')
    for name, value, source in (('machine', machine, 'IOPlatformExpertDevice.IOPlatformUUID'),
            ('volume', native_volume, 'diskutil.VolumeUUID')):
        if isinstance(value, str) and value:
            scope[name+'_source'] = source
            scope[name+'_sha256'] = hashlib.sha256(value.encode()).hexdigest()
        else:
            reasons.append('missing native '+name+' identity')
    virtualized = query('host virtualization identity', ['/usr/sbin/sysctl', '-n', 'kern.hv_vmm_present'])
    scope.update(method='IOPlatformUUID/APFS-VolumeUUID/bootsessionuuid-v1',
        host_domain='Darwin-host-kernel-no-PID-or-time-namespaces',
        virtualized=(virtualized.strip() != b'0') if virtualized is not None else None,
        local_internal=volume.get('Internal') is True)
    from target_coordination import permission_scope
    descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        try:scope['permission_scope']=permission_scope(descriptor)
        except (OSError,RuntimeError) as error:
            reasons.append('mounted permission scope unavailable: '+type(error).__name__)
        else:
            if scope['permission_scope']['relaxed']:
                reasons.append('permissionless_local_volume')
    finally:os.close(descriptor)
    if volume.get('FilesystemType') != 'apfs':
        reasons.append('filesystem '+str(volume.get('FilesystemType', 'unknown'))+' has no validated U6 capability')
    if scope['virtualized'] is not False:
        reasons.append('physical host scope is not established')
    if not scope['local_internal']:
        reasons.append('local internal volume scope is not established')
    if reasons:
        scope['unsupported_reason'] = '; '.join(reasons)
        logging.getLogger(__name__).warning('UnsupportedBootScope: %s',scope['unsupported_reason'])
    else:
        scope['boot_retirement_capability'] = 'physical_local_apfs_host_v1'
    return scope


def creation_scope(path, incarnation, *, refresh=False):
    directory = Path(path)
    device = directory.stat().st_dev
    if sys.platform != 'darwin':
        # Ordinary public lifetime custody remains available on other native
        # platforms. This explicit unsupported binding cannot qualify for U6.
        info = directory.stat()
        return {'incarnation':incarnation, 'creator':capture(os.getpid()),
            'file_id':info.st_ino, 'uid':info.st_uid, 'device':device,
            'same_boot_eligibility':False,
            'boot_retirement_capability':'UnsupportedBootScope',
            'unsupported_reason':'creation binding platform not validated'}
    from target_coordination import capability_key,native_mount
    descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        key=capability_key(descriptor,native_mount(descriptor))
        with _lock:
            if refresh or key not in _scopes:
                _scopes[key] = native_scope(directory, device)
            scope = dict(_scopes[key])
    finally:os.close(descriptor)
    info = directory.stat()
    scope.update(incarnation=incarnation, creator=capture(os.getpid()),
                 file_id=info.st_ino, uid=info.st_uid,
                 same_boot_eligibility=False)
    return scope


def boot_change(binding, current):
    """Validate the host/volume/object scope; PID absence is never an input."""
    required = {'method':'IOPlatformUUID/APFS-VolumeUUID/bootsessionuuid-v1',
        'machine_source':'IOPlatformExpertDevice.IOPlatformUUID',
        'volume_source':'diskutil.VolumeUUID',
        'host_domain':'Darwin-host-kernel-no-PID-or-time-namespaces',
        'boot_retirement_capability':'physical_local_apfs_host_v1'}
    for value in (binding, current):
        if (not isinstance(value, dict) or any(value.get(k) != v for k,v in required.items())
                or value.get('virtualized') is not False or value.get('local_internal') is not True
                or value.get('same_boot_eligibility') is not False
                or not isinstance(value.get('incarnation'), str) or not value['incarnation']
                or type(value.get('file_id')) is not int or value['file_id'] <= 0
                or type(value.get('uid')) is not int or value['uid'] < 0):
            raise RuntimeError('UnsupportedBootScope: incomplete physical host/volume/object binding')
        for key in ('machine_sha256', 'volume_sha256'):
            text = value.get(key)
            if not isinstance(text, str) or len(text) != 64 or any(c not in '0123456789abcdef' for c in text):
                raise RuntimeError('UnsupportedBootScope: missing native machine/volume identity')
        creator = value.get('creator', {})
        if not isinstance(creator, dict) or creator.get('kind') != 'macos-libproc-v1':
            raise RuntimeError('UnsupportedBootScope: unvalidated host boot source')
        try:
            if str(uuid.UUID(creator['boot_id'])) != creator['boot_id']:
                raise ValueError('noncanonical boot identity')
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise RuntimeError('UnsupportedBootScope: invalid host boot identity') from exc
    if any(binding[k] != current[k] for k in ('machine_sha256', 'volume_sha256', 'file_id', 'uid')):
        raise RuntimeError('UnsupportedBootScope: machine, volume or coordination object changed')
    old, new = binding['creator']['boot_id'], current['creator']['boot_id']
    if old == new:
        raise RuntimeError('UnsupportedBootScope: whole host boot has not changed')
    return {'evidence_type':'verified_boot_change_resource_retirement', 'scope':'host_boot_change',
        'old_boot':old, 'new_boot':new, 'binding':binding, 'current':current,
        'resource_disposition':'RetiredByBootChange',
        'current_execution_liveness':'ImpossibleInCurrentBoot', 'never_replay':True}
