"""Creation scope for durable obligations; never grants OS retirement authority."""
import hashlib
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import threading

from custody_process_identity import capture

_scopes = {}
_lock = threading.Lock()


def creation_scope(path, incarnation):
    directory = Path(path)
    device = directory.stat().st_dev
    with _lock:
        if device not in _scopes:
            if sys.platform != 'darwin':
                raise RuntimeError('UnsupportedBootScope: creation binding platform not validated')
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
    scope.update(incarnation=incarnation, creator=capture(os.getpid()),
                 same_boot_eligibility=False, boot_retirement_capability='NotEnabled')
    return scope
