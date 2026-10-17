"""Precise, exec-stable process births from public macOS/Linux interfaces.

macOS ABI: SDK sys/proc_info.h (proc_bsdinfo, PROC_PIDTBSDINFO) and
libproc.h (proc_pidinfo); XNU proc_info.c returns p_start in microseconds.
Linux ABI: kernel.org filesystems/proc.html, stat field 22 and boot_id.
Unknown platforms, short reads and permission errors fail closed.
"""

import ctypes
import errno
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


def _mac_identity(pid):
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
    if count <= 0 and code == errno.ESRCH:
        return None
    if count != ctypes.sizeof(info):
        raise OSError(code or errno.EIO, f"proc_pidinfo({pid}) returned {count}, expected 136")
    if info.pid != pid or not info.start_sec or info.start_usec >= 1_000_000:
        raise RuntimeError(f"invalid process birth for {pid}")
    if info.status == 5:  # SZOMB, sys/proc.h: exited, cannot execute or receive a signal.
        return None
    return {"kind": "macos-libproc-v1", "boot_id": _mac_boot_id(lib),
            "birth": [info.start_sec, info.start_usec]}


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
    """Diagnostic birth capture; it never enables same-boot release authority."""
    import os
    current = identity(pid)
    if current is None:
        raise RuntimeError('StartupUnconfirmed: process ended before identity capture')
    current.update(pid=pid, sid=os.getsid(pid), pgid=os.getpgid(pid),
                   eligibility=False, capability='Unsupported')
    return current
