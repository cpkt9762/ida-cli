"""Precise, exec-stable process births from public macOS/Linux interfaces.

macOS ABI: SDK sys/proc_info.h (proc_bsdinfo, PROC_PIDTBSDINFO) and
libproc.h (proc_pidinfo); XNU proc_info.c returns p_start in microseconds.
Linux ABI: kernel.org filesystems/proc.html, stat field 22 and boot_id.
Unknown platforms, short reads and permission errors fail closed.
"""

import ctypes
import errno
import os
from pathlib import Path
import sys
import uuid


class ProcBsdInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid",
        "ruid", "rgid", "svuid", "svgid", "reserved")]
    _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        "nfiles", "pgid", "pjobc", "tdev", "tpgid")]
    _fields_ += [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64),
                ("start_usec", ctypes.c_uint64)]


def _mac_boot_id(lib):
    value = ctypes.create_string_buffer(64)
    size = ctypes.c_size_t(len(value))
    lib.sysctlbyname.argtypes = [ctypes.c_char_p, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    lib.sysctlbyname.restype = ctypes.c_int
    if lib.sysctlbyname(b"kern.bootsessionuuid", value, ctypes.byref(size), None, 0):
        code = ctypes.get_errno()
        raise OSError(code, "cannot read macOS boot identity")
    if size.value != 37 or value.raw[36] != 0:
        raise RuntimeError("unexpected kern.bootsessionuuid layout")
    return str(uuid.UUID(value.value.decode("ascii")))


def _mac_identity(pid, *, exit_probe=False):
    if (ctypes.sizeof(ProcBsdInfo), ProcBsdInfo.start_sec.offset,
            ProcBsdInfo.start_usec.offset) != (136, 120, 128):
        raise RuntimeError("unsupported proc_bsdinfo ABI")
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                ctypes.c_void_p, ctypes.c_int]
    lib.proc_pidinfo.restype = ctypes.c_int
    info = ProcBsdInfo()
    ctypes.set_errno(0)
    count = lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    code = ctypes.get_errno()
    if count == 0 and code == errno.ESRCH:
        return None
    if count != ctypes.sizeof(info):
        raise OSError(code or errno.EIO, f"proc_pidinfo({pid}) returned {count}, expected 136")
    if info.pid != pid or not info.start_sec or info.start_usec >= 1_000_000:
        raise RuntimeError(f"invalid process birth for {pid}")
    if info.status == 5 and not exit_probe:  # SZOMB: exited, no execution remains.
        return None
    result = {"kind": "macos-libproc-v1", "boot_id": _mac_boot_id(lib),
              "birth": [info.start_sec, info.start_usec]}
    if info.status == 5:
        result['state'] = 'zombie'
    return result


def _linux_identity(pid):
    boot_id = str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    prefix, separator, suffix = stat.rpartition(") ")
    fields = suffix.split()
    if not separator or int(prefix.split("(", 1)[0]) != pid or len(fields) < 20:
        raise RuntimeError(f"invalid /proc/{pid}/stat")
    ticks = int(fields[19])  # First suffix field is field 3 (state).
    if ticks <= 0:
        raise RuntimeError(f"invalid Linux process birth for {pid}")
    if fields[0] in ("Z", "X"):
        return None
    return {"kind": "linux-proc-v1", "boot_id": boot_id, "birth": [ticks]}


def valid_identity(value):
    if not isinstance(value, dict) or set(value) != {"kind", "boot_id", "birth"}:
        return False
    try:
        uuid.UUID(value["boot_id"])
    except (ValueError, TypeError, AttributeError):
        return False
    birth = value["birth"]
    if not isinstance(birth, list) or any(type(n) is not int for n in birth):
        return False
    if value["kind"] == "macos-libproc-v1":
        return len(birth) == 2 and birth[0] > 0 and 0 <= birth[1] < 1_000_000
    if value["kind"] == "linux-proc-v1":
        return len(birth) == 1 and birth[0] > 0
    return False


def identity(pid: int) -> dict | None:
    if type(pid) is not int or pid <= 0:
        raise ValueError("process identity requires a positive PID")
    if sys.platform == "darwin":
        return _mac_identity(pid)
    if sys.platform.startswith("linux"):
        return _linux_identity(pid)
    raise RuntimeError(f"precise process identity unsupported on {sys.platform}; BLOCKED")


def same_process(current, recorded) -> bool:
    # Old ps/lstart strings are evidence only, never authority to send signals.
    return valid_identity(current) and valid_identity(recorded) and current == recorded


def capture(pid):
    """Capture native birth; eligibility is confined to launch observation exit."""
    import os
    current = identity(pid)
    if current is None:
        raise RuntimeError('StartupUnconfirmed: process ended before identity capture')
    current.update(pid=pid, sid=os.getsid(pid), pgid=os.getpgid(pid),
                   eligibility=sys.platform == 'darwin',
                   capability='MacSameBootExitV1' if sys.platform == 'darwin' else 'Unsupported')
    return current


def boot_identity():
    """Independent host boot query, including when the recorded PID is absent."""
    if sys.platform != 'darwin':
        raise RuntimeError('same-boot exit capability unsupported on this platform')
    return _mac_boot_id(ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True))


def exit_identity(pid):
    """Only definite ESRCH returns None; a readable zombie carries its exact birth."""
    if type(pid) is not int or not 0 < pid <= 2_147_483_647:
        raise ValueError('process identity requires a native positive PID')
    if sys.platform != 'darwin':
        raise RuntimeError('same-boot exit capability unsupported on this platform')
    return _mac_identity(pid, exit_probe=True)


def same_boot_exit(recorded, *, read=None, current_boot=None):
    """Prove an exact recorded process is gone, without granting owner release.

    Legacy captures already contain the same native birth. Their diagnostic
    capability flag is not upgraded; this predicate validates its own narrow
    inputs and never changes generic origin/owner retirement eligibility.
    Exceptions remain visible to callers, which must retain the obligation.
    """
    if not isinstance(recorded, dict):
        return None
    required = {'kind', 'boot_id', 'birth', 'pid', 'sid', 'pgid', 'eligibility', 'capability'}
    if (set(recorded) != required or type(recorded['pid']) is not int
            or not 0 < recorded['pid'] <= 2_147_483_647
            or any(type(recorded[k]) is not int or recorded[k] <= 0 for k in ('sid', 'pgid'))
            or type(recorded['eligibility']) is not bool
            or (recorded['eligibility'], recorded['capability']) not in (
                (False, 'Unsupported'), (True, 'MacSameBootExitV1'))):
        return None
    birth = {k:recorded[k] for k in ('kind', 'boot_id', 'birth')}
    if not valid_identity(birth) or birth['kind'] != 'macos-libproc-v1':
        return None
    boot = (current_boot or boot_identity)()
    if boot != birth['boot_id'] or str(uuid.UUID(boot)) != boot:
        return None
    current = (read or exit_identity)(recorded['pid'])
    if current is None:
        return {'reason':'esrch', 'boot_id':boot, 'recorded':recorded, 'current':None}
    observed = current
    zombie = isinstance(current, dict) and current.get('state') == 'zombie'
    if zombie:
        if set(current) != {'kind', 'boot_id', 'birth', 'state'}:
            return None
        current = {k:current[k] for k in ('kind', 'boot_id', 'birth')}
    if (not valid_identity(current) or current['kind'] != birth['kind']
            or current['boot_id'] != boot or (current == birth and not zombie)):
        return None
    return {'reason':'zombie' if zombie and current == birth else 'pid_reused',
            'boot_id':boot, 'recorded':recorded, 'current':observed}


def _mac_commands():
    """argv of every readable process from libproc + sysctl KERN_PROCARGS2.

    SDK sys/sysctl.h: CTL_KERN=1, KERN_PROCARGS2=49; the buffer is a native int
    argc, the exec path, NUL padding, then argc NUL-terminated arguments. A pid
    that vanished is skipped; an unreadable live process of this user is an
    error, never an empty answer.
    """
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    lib.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.proc_listallpids.restype = ctypes.c_int
    lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                ctypes.c_void_p, ctypes.c_int]
    lib.proc_pidinfo.restype = ctypes.c_int
    lib.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                           ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    lib.sysctl.restype = ctypes.c_int
    count = lib.proc_listallpids(None, 0)
    if count <= 0:
        raise OSError(ctypes.get_errno() or errno.EIO, "cannot size the process table")
    capacity = count + 256
    pids = (ctypes.c_int * capacity)()
    listed = lib.proc_listallpids(pids, ctypes.sizeof(pids))
    if listed <= 0:
        raise OSError(ctypes.get_errno() or errno.EIO, "cannot list the process table")
    if listed >= capacity:
        raise RuntimeError("process table buffer saturated; BLOCKED")
    limit = 1 << 20
    rows = []
    for pid in list(pids)[:listed]:
        if pid <= 0:
            continue
        mib = (ctypes.c_int * 3)(1, 49, pid)
        buffer = ctypes.create_string_buffer(limit)
        size = ctypes.c_size_t(limit)
        ctypes.set_errno(0)
        if lib.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
            code = ctypes.get_errno()
            if code == errno.ESRCH:
                continue
            info = ProcBsdInfo()
            ctypes.set_errno(0)
            got = lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
            info_error = ctypes.get_errno()
            if got <= 0 and info_error == errno.ESRCH:
                continue
            if got != ctypes.sizeof(info):
                raise OSError(info_error or errno.EIO, f"process status {pid} unreadable or short")
            if info.pid != pid:
                raise RuntimeError(f"process status {pid} identity mismatch")
            if info.status == 5:
                continue
            raise OSError(code or errno.EIO, f"arguments of live process {pid} unreadable")
        raw = buffer.raw[:size.value]
        if len(raw) < 6 or len(raw) > limit:
            raise RuntimeError(f"process arguments {pid} short or oversized")
        argc = int.from_bytes(raw[:4], sys.byteorder)
        if argc <= 0:
            raise RuntimeError(f"process arguments {pid} invalid argc")
        parts = raw[4:].split(b"\0")
        index = 1  # parts[0] is the exec path.
        while index < len(parts) and parts[index] == b"":
            index += 1
        if len(parts) <= index + argc:
            raise RuntimeError(f"process arguments {pid} truncated")
        rows.append((pid, [part.decode("utf-8", "replace") for part in parts[index:index + argc]]))
    return rows


def _linux_commands():
    uid = os.getuid()
    rows = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            raw = (entry / "cmdline").read_bytes()
        except (FileNotFoundError, ProcessLookupError):
            continue
        rows.append((int(entry.name), [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]))
    return rows


def process_commands() -> list:
    """[(pid, argv)] of every readable live process, without spawning anything."""
    if sys.platform == "darwin":
        return _mac_commands()
    if sys.platform.startswith("linux"):
        return _linux_commands()
    raise RuntimeError(f"process table unsupported on {sys.platform}; BLOCKED")
