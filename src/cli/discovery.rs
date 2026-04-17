use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

const DISCOVERY_PATH: &str = "/tmp/ida-cli.socket";
const STARTUP_LOCK: &str = "/tmp/ida-cli.startup.lock";

pub fn discover_socket(explicit: Option<&str>) -> Result<PathBuf, String> {
    if let Some(s) = explicit {
        let p = PathBuf::from(s);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("Socket not found: {s}"));
    }

    if let Ok(env_path) = std::env::var("IDA_MCP_SOCKET") {
        let p = PathBuf::from(&env_path);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!(
            "$IDA_MCP_SOCKET points to non-existent path: {env_path}"
        ));
    }

    if let Some(p) = read_discovery_file() {
        return Ok(p);
    }

    auto_start_server()?;

    read_discovery_file().ok_or_else(|| {
        "Server started but socket not found. Check logs: ~/.ida/logs/server.log".into()
    })
}

fn read_discovery_file() -> Option<PathBuf> {
    let content = std::fs::read_to_string(DISCOVERY_PATH).ok()?;
    let p = PathBuf::from(content.trim());
    if p.exists() {
        Some(p)
    } else {
        let _ = std::fs::remove_file(DISCOVERY_PATH);
        None
    }
}

fn flock_exclusive(fd: i32, blocking: bool) -> bool {
    let op = if blocking {
        libc::LOCK_EX
    } else {
        libc::LOCK_EX | libc::LOCK_NB
    };
    unsafe { libc::flock(fd, op) == 0 }
}

fn auto_start_server() -> Result<(), String> {
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(STARTUP_LOCK)
        .map_err(|e| format!("Cannot create lock file: {e}"))?;

    let fd = lock_file.as_raw_fd();

    if !flock_exclusive(fd, false) {
        eprintln!("Another client is starting the server, waiting...");
        if !flock_exclusive(fd, true) {
            return Err("Lock wait failed".into());
        }
        if read_discovery_file().is_some() {
            eprintln!("Server ready (started by another client)");
            return Ok(());
        }
    }

    eprintln!("No running server found, starting one...");
    let exe = std::env::current_exe().map_err(|e| format!("Cannot find own binary: {e}"))?;

    let child = std::process::Command::new(&exe)
        .args(["serve-http", "--bind", "127.0.0.1:0"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start server: {e}"))?;

    eprintln!("Server starting (pid {})...", child.id());

    for i in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if read_discovery_file().is_some() {
            eprintln!("Server ready ({:.1}s)", (i + 1) as f64 * 0.25);
            return Ok(());
        }
    }

    Err("Server did not become ready within 10s".into())
}
