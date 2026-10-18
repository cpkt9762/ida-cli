"""Creation scope for durable obligations; never grants OS retirement authority."""
import hashlib
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


def creation_scope(path, incarnation):
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
    with _lock:
        if device not in _scopes:
            def output(argv):
                return subprocess.check_output(['timeout', '2s', *argv], stderr=subprocess.PIPE)
            hardware = plistlib.loads(output(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice', '-a']))
            mounted = output(['/bin/df', '-P', str(directory)]).decode().splitlines()[-1].split()[0]
            volume = plistlib.loads(output(['/usr/sbin/diskutil', 'info', '-plist', mounted]))
            machine = hardware[0].get('IOPlatformUUID')
            native_volume = volume.get('VolumeUUID')
            if not machine or not native_volume or volume.get('FilesystemType') != 'apfs':
                raise RuntimeError('UnsupportedBootScope: incomplete local creation identity')
            _scopes[device] = {'method':'IOPlatformUUID/APFS-VolumeUUID/bootsessionuuid-v1',
                'machine_source':'IOPlatformExpertDevice.IOPlatformUUID',
                'machine_sha256':hashlib.sha256(machine.encode()).hexdigest(),
                'volume_source':'diskutil.VolumeUUID',
                'volume_sha256':hashlib.sha256(native_volume.encode()).hexdigest(),
                'device':device, 'host_domain':'Darwin-host-kernel-no-PID-or-time-namespaces',
                'virtualized':output(['/usr/sbin/sysctl', '-n', 'kern.hv_vmm_present']).strip() != b'0',
                'local_internal':volume.get('Internal') is True}
        scope = dict(_scopes[device])
    info = directory.stat()
    scope.update(incarnation=incarnation, creator=capture(os.getpid()),
                 file_id=info.st_ino, uid=info.st_uid,
                 same_boot_eligibility=False,
                 boot_retirement_capability=('physical_local_apfs_host_v1'
                     if not scope['virtualized'] and scope['local_internal'] else 'UnsupportedBootScope'))
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
