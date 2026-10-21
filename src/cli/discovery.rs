use crate::process_spawn::SpawnFenced;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub fn discover_socket(explicit: Option<&str>) -> Result<PathBuf, String> {
    resolve(
        explicit,
        std::env::var("IDA_MCP_SOCKET").ok(),
        &crate::idb_store::discovery_path(),
        &crate::idb_store::startup_lock_path(),
        spawn_server,
    )
}

fn resolve(
    explicit: Option<&str>,
    env_socket: Option<String>,
    discovery: &Path,
    lock: &Path,
    spawn: impl FnOnce() -> Result<std::process::Child, String>,
) -> Result<PathBuf, String> {
    if let Some(s) = explicit {
        let p = PathBuf::from(s);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("Socket not found: {s}"));
    }

    if let Some(env_path) = env_socket {
        let p = PathBuf::from(&env_path);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!(
            "$IDA_MCP_SOCKET points to non-existent path: {env_path}"
        ));
    }

    match recorded(discovery) {
        Recorded::Live(p) => return Ok(p),
        Recorded::Stale(p) => eprintln!(
            "Recorded server socket {} refuses connections; starting a new server",
            p.display()
        ),
        Recorded::Missing => {}
    }

    auto_start_server(discovery, lock, spawn)?;

    read_discovery_file(discovery).ok_or_else(|| {
        "Server started but socket not found. Check logs: ~/.ida/logs/server.log".into()
    })
}

enum Recorded {
    /// Discovery names a socket that accepts connections (or cannot be probed).
    Live(PathBuf),
    /// Discovery names an existing socket file that nothing listens on.
    Stale(PathBuf),
    Missing,
}

fn recorded(discovery: &Path) -> Recorded {
    match read_discovery_file(discovery) {
        None => Recorded::Missing,
        Some(p) if socket_refuses(&p) => Recorded::Stale(p),
        Some(p) => Recorded::Live(p),
    }
}

/// Only a definite "no listener" answer counts as stale; any other probe error
/// leaves the socket to the caller's own connect so the real error surfaces.
fn socket_refuses(path: &Path) -> bool {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => false,
        Err(error) => matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
        ),
    }
}

fn read_discovery_file(discovery_path: &Path) -> Option<PathBuf> {
    let content = std::fs::read_to_string(discovery_path).ok()?;
    let p = PathBuf::from(content.trim());
    if p.exists() {
        Some(p)
    } else {
        let _ = std::fs::remove_file(discovery_path);
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

fn spawn_server() -> Result<std::process::Child, String> {
    let exe = std::env::current_exe().map_err(|e| format!("Cannot find own binary: {e}"))?;
    std::process::Command::new(&exe)
        .args(["serve-http", "--bind", "127.0.0.1:0"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn_fenced()
        .map_err(|e| format!("Failed to start server: {e}"))
}

fn auto_start_server(
    discovery: &Path,
    startup_lock: &Path,
    spawn: impl FnOnce() -> Result<std::process::Child, String>,
) -> Result<(), String> {
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(startup_lock)
        .map_err(|e| format!("Cannot create lock file: {e}"))?;

    let fd = lock_file.as_raw_fd();

    if !flock_exclusive(fd, false) {
        eprintln!("Another client is starting the server, waiting...");
        if !flock_exclusive(fd, true) {
            return Err("Lock wait failed".into());
        }
    }

    // Decided under the startup lock: a live daemon (possibly started by the
    // client we just waited for) wins; a stale record is retired here so only
    // one contender spawns a replacement.
    match recorded(discovery) {
        Recorded::Live(_) => {
            eprintln!("Server ready (started by another client)");
            return Ok(());
        }
        Recorded::Stale(p) => retire_stale_record(discovery, &p)?,
        Recorded::Missing => {}
    }

    eprintln!("No running server found, starting one...");
    let mut child = spawn()?;

    eprintln!("Server starting (pid {})...", child.id());

    for i in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("Cannot observe Nexus daemon startup: {error}"))?
        {
            return startup_child_exited(status, read_discovery_file(discovery));
        }
        if read_discovery_file(discovery).is_some() {
            eprintln!("Server ready ({:.1}s)", (i + 1) as f64 * 0.25);
            return Ok(());
        }
    }

    Err("Server did not become ready within 10s".into())
}

/// Remove the discovery record only; the replacement daemon rebinds the socket
/// path itself, and a socket that might be live is never unlinked here.
fn retire_stale_record(discovery: &Path, stale: &Path) -> Result<(), String> {
    let unchanged = std::fs::read_to_string(discovery)
        .map(|content| Path::new(content.trim()) == stale)
        .unwrap_or(false);
    if unchanged {
        std::fs::remove_file(discovery).map_err(|error| {
            format!(
                "Cannot retire stale discovery record {}: {error}",
                discovery.display()
            )
        })?;
    }
    Ok(())
}

fn startup_child_exited(
    status: std::process::ExitStatus,
    discovered: Option<PathBuf>,
) -> Result<(), String> {
    if discovered.is_some() {
        return Ok(());
    }
    Err(format!("Nexus daemon exited during startup ({status}); check IDA_NEXUS_PYTHON and its runtime dependencies; see {}",
        crate::idb_store::log_path().display()))
}

#[cfg(all(test, unix))]
mod startup_exit_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn independently_ready_daemon_wins_over_failed_contending_child() {
        let exited = std::process::ExitStatus::from_raw(1 << 8);
        startup_child_exited(exited, Some(PathBuf::from("private-ready-socket")))
            .expect("discovery is rechecked after observing child exit");
        let error = startup_child_exited(exited, None).expect_err("no ready daemon");
        assert!(error.contains("exit status: 1"), "{error}");
        assert!(error.contains("Nexus daemon exited"), "{error}");
    }
}

#[cfg(all(test, unix))]
mod stale_discovery_tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!("dsc-{}-{tag}", std::process::id()));
            std::fs::create_dir_all(&root).expect("fixture dir");
            Self { root }
        }
        fn discovery(&self) -> PathBuf {
            self.root.join("d")
        }
        fn lock(&self) -> PathBuf {
            self.root.join("l")
        }
        /// A socket file that nothing listens on, as left behind by SIGKILL.
        fn dead_socket(&self, name: &str) -> PathBuf {
            let path = self.root.join(name);
            drop(UnixListener::bind(&path).expect("bind"));
            assert!(path.exists(), "dropped listener leaves its socket file");
            path
        }
        fn fake_daemon_spawn<'a>(
            &self,
            socket: &Path,
            spawned: &'a AtomicUsize,
        ) -> impl FnOnce() -> Result<std::process::Child, String> + 'a {
            let script = format!(
                "printf %s '{}' > '{}'; sleep 1",
                socket.display(),
                self.discovery().display()
            );
            move || {
                spawned.fetch_add(1, Ordering::SeqCst);
                std::process::Command::new("sh")
                    .args(["-c", &script])
                    .spawn()
                    .map_err(|e| e.to_string())
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn no_spawn() -> Result<std::process::Child, String> {
        panic!("must not start a server")
    }

    #[test]
    fn stale_discovery_socket_starts_one_new_server() {
        let fx = Fixture::new("stale");
        let dead = fx.dead_socket("dead.sock");
        std::fs::write(fx.discovery(), dead.display().to_string()).expect("discovery");
        let live_path = fx.root.join("live.sock");
        let _live = UnixListener::bind(&live_path).expect("live listener");
        let spawned = AtomicUsize::new(0);
        let found = resolve(
            None,
            None,
            &fx.discovery(),
            &fx.lock(),
            fx.fake_daemon_spawn(&live_path, &spawned),
        )
        .expect("stale record triggers a restart");
        assert_eq!(found, live_path);
        assert_eq!(spawned.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stale_record_with_failing_start_reports_the_start_error() {
        let fx = Fixture::new("fail");
        let dead = fx.dead_socket("dead.sock");
        std::fs::write(fx.discovery(), dead.display().to_string()).expect("discovery");
        let error = resolve(None, None, &fx.discovery(), &fx.lock(), || {
            Err("Failed to start server: boom".into())
        })
        .expect_err("start failure is surfaced");
        assert!(error.contains("boom"), "{error}");
    }

    #[test]
    fn live_discovery_socket_is_used_without_starting() {
        let fx = Fixture::new("live");
        let live_path = fx.root.join("live.sock");
        let _live = UnixListener::bind(&live_path).expect("live listener");
        std::fs::write(fx.discovery(), live_path.display().to_string()).expect("discovery");
        let found = resolve(None, None, &fx.discovery(), &fx.lock(), no_spawn).expect("live");
        assert_eq!(found, live_path);
    }

    #[test]
    fn explicit_and_env_sockets_never_auto_start() {
        let fx = Fixture::new("explicit");
        let dead = fx.dead_socket("dead.sock");
        let text = dead.display().to_string();
        let found = resolve(Some(&text), None, &fx.discovery(), &fx.lock(), no_spawn)
            .expect("explicit path is returned as given");
        assert_eq!(found, dead);
        let found = resolve(None, Some(text), &fx.discovery(), &fx.lock(), no_spawn)
            .expect("env path is returned as given");
        assert_eq!(found, dead);
        let missing = fx.root.join("absent.sock").display().to_string();
        assert!(resolve(Some(&missing), None, &fx.discovery(), &fx.lock(), no_spawn).is_err());
        assert!(resolve(None, Some(missing), &fx.discovery(), &fx.lock(), no_spawn).is_err());
    }
}
