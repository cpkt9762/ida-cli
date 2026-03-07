//! IDAPython script generators for process and debugger loading operations.

/// Python helpers for spawning/killing a remote debug server subprocess.
/// Stored persistently in `idaapi._mcp_dbgsrv` across script invocations.
const DBGSRV_HELPERS: &str = r#"
import subprocess as _sp, socket as _sock, time as _time

def _ensure_dbgsrv(srv_path):
    if hasattr(idaapi, '_mcp_dbgsrv'):
        _info = idaapi._mcp_dbgsrv
        if _info['proc'].poll() is None:
            return _info['port']
    _s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    _s.bind(('127.0.0.1', 0))
    _port = _s.getsockname()[1]
    _s.close()
    _proc = _sp.Popen([srv_path, '-p', str(_port), '-t'],
                      stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    _time.sleep(0.5)
    if _proc.poll() is not None:
        raise RuntimeError(f"Debug server exited immediately (code={_proc.returncode})")
    idaapi._mcp_dbgsrv = {'proc': _proc, 'port': _port}
    return _port

def _kill_dbgsrv():
    if not hasattr(idaapi, '_mcp_dbgsrv'):
        return False
    try:
        idaapi._mcp_dbgsrv['proc'].terminate()
        idaapi._mcp_dbgsrv['proc'].wait(timeout=3)
    except Exception:
        try:
            idaapi._mcp_dbgsrv['proc'].kill()
        except Exception:
            pass
    try:
        del idaapi._mcp_dbgsrv
    except Exception:
        pass
    return True
"#;

/// Generate a script to load a debugger module.
///
/// When `debug_server_path` is provided the script auto-spawns the remote
/// debug server and loads the debugger in remote mode, enabling debugging
/// in headless / idalib environments where local debugging is unavailable.
pub fn generate_load_debugger_script(
    debugger_name: &str,
    is_remote: bool,
    debug_server_path: Option<&str>,
) -> String {
    if let Some(srv_path) = debug_server_path {
        let body = format!(
            r#"
{DBGSRV_HELPERS}
if ida_dbg.dbg_is_loaded():
    make_result(True, {{"already_loaded": True, "debugger": "{debugger_name}"}})
else:
    _port = _ensure_dbgsrv("{srv_path}")
    import platform as _plat
    _fallbacks = ["{debugger_name}"]
    if _plat.machine() == "arm64":
        for _f in ("arm_mac",):
            if _f not in _fallbacks:
                _fallbacks.append(_f)
    else:
        for _f in ("mac",):
            if _f not in _fallbacks:
                _fallbacks.append(_f)
    ok = False
    actual = None
    for _name in _fallbacks:
        ok = ida_dbg.load_debugger(_name, True)
        if ok:
            actual = _name
            break
    if ok:
        ida_dbg.set_remote_debugger("localhost", "", _port)
        ida_dbg.set_debugger_options(0)
        make_result(True, {{"loaded": True, "debugger": actual, "requested": "{debugger_name}", "remote": True, "port": _port}})
    else:
        _kill_dbgsrv()
        make_result(False, error=f"Failed to load remote debugger '{debugger_name}' (tried: {{', '.join(_fallbacks)}})")
"#,
            DBGSRV_HELPERS = DBGSRV_HELPERS,
            debugger_name = debugger_name,
            srv_path = srv_path.replace('"', "\\\""),
        );
        return super::build_script(&body);
    }

    let is_remote_py = if is_remote { "True" } else { "False" };
    let body = format!(
        r#"
import platform as _plat
if ida_dbg.dbg_is_loaded():
    make_result(True, {{"already_loaded": True, "debugger": "{debugger_name}"}})
else:
    _fallbacks = ["{debugger_name}"]
    if _plat.system() == "Darwin" and _plat.machine() == "arm64":
        for _f in ("arm_mac", "gdb"):
            if _f not in _fallbacks:
                _fallbacks.append(_f)
    elif _plat.system() == "Darwin":
        for _f in ("mac", "gdb"):
            if _f not in _fallbacks:
                _fallbacks.append(_f)
    else:
        if "gdb" not in _fallbacks:
            _fallbacks.append("gdb")
    ok = False
    actual = None
    for _name in _fallbacks:
        ok = ida_dbg.load_debugger(_name, {is_remote_py})
        if ok:
            actual = _name
            break
    if ok:
        ida_dbg.set_debugger_options(0)
        make_result(True, {{"loaded": True, "debugger": actual, "requested": "{debugger_name}"}})
    else:
        make_result(False, error=f"Failed to load debugger '{debugger_name}' (tried: {{', '.join(_fallbacks)}})")
"#,
        debugger_name = debugger_name,
        is_remote_py = is_remote_py,
    );
    super::build_script(&body)
}

/// Generate a script to start the process under the debugger.
///
/// When `debug_server_path` is provided, automatically spawns the remote
/// debug server, loads the debugger in remote mode, and sets entry-point
/// breakpoint options (`DOPT_ENTRY_BPT | DOPT_START_BPT`) so the process
/// suspends immediately for inspection.
pub fn generate_start_process_script(
    path: Option<&str>,
    args: Option<&str>,
    start_dir: Option<&str>,
    timeout: u64,
    debug_server_path: Option<&str>,
) -> String {
    let path_py = match path {
        Some(p) => format!("\"{}\"", p.replace('"', "\\\"")),
        None => "None".to_string(),
    };
    let args_py = match args {
        Some(a) => format!("\"{}\"", a.replace('"', "\\\"")),
        None => "None".to_string(),
    };
    let dir_py = match start_dir {
        Some(d) => format!("\"{}\"", d.replace('"', "\\\"")),
        None => "None".to_string(),
    };

    if let Some(srv_path) = debug_server_path {
        let body = format!(
            r#"
{DBGSRV_HELPERS}
_port = _ensure_dbgsrv("{srv_path}")
if not ida_dbg.dbg_is_loaded():
    import platform as _plat
    if _plat.machine() == "arm64":
        _try_dbg = ["arm_mac"]
    else:
        _try_dbg = ["mac"]
    _loaded = False
    for _d in _try_dbg:
        if ida_dbg.load_debugger(_d, True):
            _loaded = True
            break
    if not _loaded:
        _kill_dbgsrv()
        make_result(False, error="Failed to load remote debugger")
        raise SystemExit
ida_dbg.set_remote_debugger("localhost", "", _port)
# Workaround: macOS Sequoia blocks posix_spawn from mac_server_arm
# (Hex-Rays community #670). Launch target with POSIX_SPAWN_START_SUSPENDED
# via ctypes so process is frozen before first instruction, then attach.
import ctypes as _ct, ctypes.util as _ctu, shlex as _shlex, os as _os
_app = {path_py} or ""
_args_str = {args_py} or ""
_sdir = {dir_py} or None
if not _app:
    make_result(False, error="binary path is required for remote start_process")
    raise SystemExit
_libc = _ct.CDLL(_ctu.find_library('c'))
_POSIX_SPAWN_START_SUSPENDED = 0x0080
_attr_p = _ct.c_void_p(0)
_libc.posix_spawnattr_init(_ct.byref(_attr_p))
_libc.posix_spawnattr_setflags(_ct.byref(_attr_p), _ct.c_short(_POSIX_SPAWN_START_SUSPENDED))
_pid_out = _ct.c_int(0)
_argv_parts = [_app] + (_shlex.split(_args_str) if _args_str else [])
_argv_c = (_ct.c_char_p * (len(_argv_parts) + 1))(*[s.encode() for s in _argv_parts], None)
_old_cwd = None
if _sdir:
    _old_cwd = _os.getcwd()
    _os.chdir(_sdir)
_sret = _libc.posix_spawn(_ct.byref(_pid_out), _app.encode(), None, _ct.byref(_attr_p), _argv_c, None)
if _old_cwd:
    _os.chdir(_old_cwd)
_libc.posix_spawnattr_destroy(_ct.byref(_attr_p))
if _sret != 0:
    _kill_dbgsrv()
    make_result(False, error=f"posix_spawn failed: {{_os.strerror(_sret)}}")
    raise SystemExit
_child_pid = _pid_out.value
ida_dbg.set_debugger_options(0)
state = ida_dbg.get_process_state()
if state != 0:
    _os.kill(_child_pid, 9)
    make_result(False, error=f"Cannot attach: process state is {{state}}, need DSTATE_NOTASK(0)")
else:
    ret = ida_dbg.attach_process(_child_pid, -1)
    if ret == 1:
        code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
        ip = safe_hex(ida_dbg.get_ip_val())
        make_result(True, {{"event_code": code, "ip": ip, "pid": _child_pid, "state": ida_dbg.get_process_state(), "remote": True, "port": _port}})
    else:
        _os.kill(_child_pid, 9)
        make_result(False, error=f"attach_process returned {{ret}} for pid {{_child_pid}}")
"#,
            DBGSRV_HELPERS = DBGSRV_HELPERS,
            srv_path = srv_path.replace('"', "\\\""),
            path_py = path_py,
            args_py = args_py,
            dir_py = dir_py,
            timeout = timeout,
        );
        return super::build_script(&body);
    }

    let body = format!(
        r#"
import platform
if not ida_dbg.dbg_is_loaded():
    _sys = platform.system()
    _mach = platform.machine()
    if _sys == "Darwin" and _mach == "arm64":
        _try = ["arm_mac", "mac", "gdb"]
    elif _sys == "Darwin":
        _try = ["mac", "arm_mac", "gdb"]
    elif _sys == "Linux":
        _try = ["linux", "gdb"]
    elif _sys == "Windows":
        _try = ["win32", "gdb"]
    else:
        _try = ["gdb"]
    for _d in _try:
        if ida_dbg.load_debugger(_d, False):
            break
    ida_dbg.set_debugger_options(0)
state = ida_dbg.get_process_state()
if state != 0:
    make_result(False, error=f"Cannot start: process state is {{state}}, need DSTATE_NOTASK(0)")
else:
    ret = ida_dbg.start_process({path_py}, {args_py}, {dir_py})
    if ret == 1:
        code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
        ip = safe_hex(ida_dbg.get_ip_val())
        make_result(True, {{"event_code": code, "ip": ip, "state": ida_dbg.get_process_state()}})
    elif ret == 0:
        make_result(False, error="start_process cancelled")
    else:
        make_result(False, error=f"start_process failed with code {{ret}}")
"#,
        path_py = path_py,
        args_py = args_py,
        dir_py = dir_py,
        timeout = timeout,
    );
    super::build_script(&body)
}

/// Generate a script to attach to a running process by PID.
///
/// When `debug_server_path` is provided, automatically spawns the remote
/// debug server and loads the debugger in remote mode, matching the
/// behaviour of `generate_start_process_script`.
pub fn generate_attach_process_script(
    pid: Option<u64>,
    timeout: u64,
    debug_server_path: Option<&str>,
) -> String {
    let pid_py = match pid {
        Some(p) => p.to_string(),
        None => "None".to_string(),
    };

    if let Some(srv_path) = debug_server_path {
        let body = format!(
            r#"
{DBGSRV_HELPERS}
_pid = {pid_py}
if _pid is None:
    make_result(False, error="PID is required for attach in headless/remote mode")
else:
    _port = _ensure_dbgsrv("{srv_path}")
    if not ida_dbg.dbg_is_loaded():
        import platform as _plat
        if _plat.machine() == "arm64":
            _try_dbg = ["arm_mac"]
        else:
            _try_dbg = ["mac"]
        _loaded = False
        for _d in _try_dbg:
            if ida_dbg.load_debugger(_d, True):
                _loaded = True
                break
        if not _loaded:
            _kill_dbgsrv()
            make_result(False, error="Failed to load remote debugger for attach")
            raise SystemExit
    ida_dbg.set_remote_debugger("localhost", "", _port)
    state = ida_dbg.get_process_state()
    if state != 0:
        make_result(False, error=f"Cannot attach: state={{state}}, need DSTATE_NOTASK(0)")
    else:
        ret = ida_dbg.attach_process(int(_pid), -1)
        if ret == 1:
            code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
            ip = safe_hex(ida_dbg.get_ip_val())
            make_result(True, {{"event_code": code, "ip": ip, "pid": _pid, "remote": True, "port": _port}})
        else:
            make_result(False, error=f"attach_process returned {{ret}}")
"#,
            DBGSRV_HELPERS = DBGSRV_HELPERS,
            pid_py = pid_py,
            srv_path = srv_path.replace('"', "\\\""),
            timeout = timeout,
        );
        return super::build_script(&body);
    }

    let body = format!(
        r#"
import platform
_pid = {pid_py}
if _pid is None:
    make_result(False, error="PID is required in headless mode (no process selection dialog)")
else:
    if not ida_dbg.dbg_is_loaded():
        _sys = platform.system()
        _mach = platform.machine()
        if _sys == "Darwin" and _mach == "arm64":
            _try = ["arm_mac", "mac", "gdb"]
        elif _sys == "Darwin":
            _try = ["mac", "arm_mac", "gdb"]
        elif _sys == "Linux":
            _try = ["linux", "gdb"]
        elif _sys == "Windows":
            _try = ["win32", "gdb"]
        else:
            _try = ["gdb"]
        for _d in _try:
            if ida_dbg.load_debugger(_d, False):
                break
        ida_dbg.set_debugger_options(0)
    state = ida_dbg.get_process_state()
    if state != 0:
        make_result(False, error=f"Cannot attach: state={{state}}, need DSTATE_NOTASK(0)")
    else:
        ret = ida_dbg.attach_process(int(_pid), -1)
        if ret == 1:
            code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
            ip = safe_hex(ida_dbg.get_ip_val())
            make_result(True, {{"event_code": code, "ip": ip, "pid": _pid}})
        else:
            make_result(False, error=f"attach_process returned {{ret}}")
"#,
        pid_py = pid_py,
        timeout = timeout,
    );
    super::build_script(&body)
}

/// Generate a script to detach from the current process.
/// Also kills the auto-spawned debug server if one exists.
pub fn generate_detach_process_script() -> String {
    let body = format!(
        r#"
{DBGSRV_HELPERS}
state = ida_dbg.get_process_state()
if state == 0:
    make_result(False, error="No active process to detach from")
else:
    ok = ida_dbg.detach_process()
    if ok:
        ida_dbg.wait_for_next_event(WFNE_ANY | WFNE_SILENT, 5)
    _srv = _kill_dbgsrv()
    make_result(ok, {{"detached": ok, "server_cleaned": _srv}})
"#,
        DBGSRV_HELPERS = DBGSRV_HELPERS,
    );
    super::build_script(&body)
}

/// Generate a script to terminate the debugged process.
/// Also kills the auto-spawned debug server if one exists.
pub fn generate_exit_process_script() -> String {
    let body = format!(
        r#"
{DBGSRV_HELPERS}
state = ida_dbg.get_process_state()
if state == 0:
    make_result(False, error="No active process to exit")
else:
    ok = ida_dbg.exit_process()
    if ok:
        ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, 5)
    _srv = _kill_dbgsrv()
    make_result(ok, {{"exited": ok, "server_cleaned": _srv}})
"#,
        DBGSRV_HELPERS = DBGSRV_HELPERS,
    );
    super::build_script(&body)
}

/// Generate a script to query current debugger and process state.
pub fn generate_get_state_script() -> String {
    let body = r#"
state = ida_dbg.get_process_state()
state_names = {-1: "DSTATE_SUSP", 0: "DSTATE_NOTASK", 1: "DSTATE_RUN"}
data = {
    "state": state,
    "state_name": state_names.get(state, "unknown"),
    "debugger_loaded": ida_dbg.dbg_is_loaded(),
    "is_debugger_on": ida_dbg.is_debugger_on(),
    "thread_count": ida_dbg.get_thread_qty(),
}
if hasattr(idaapi, '_mcp_dbgsrv'):
    _info = idaapi._mcp_dbgsrv
    data["remote_debug_server"] = {
        "port": _info['port'],
        "alive": _info['proc'].poll() is None,
    }
if state == -1:
    data["ip"] = safe_hex(ida_dbg.get_ip_val())
    data["sp"] = safe_hex(ida_dbg.get_sp_val())
    data["current_thread"] = ida_dbg.get_current_thread()
make_result(True, data)
"#;
    super::build_script(body)
}
