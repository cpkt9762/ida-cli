//! Product maintenance entrypoints must work with no GNU timeout on PATH.
use ida_mcp::process_spawn::{SpawnFenced, StdOutputFenced};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("n9-{}-{name}", std::process::id()));
    std::fs::create_dir(&root).expect("private maintenance fixture");
    root
}

fn first_execution(python: &std::path::Path, root: &std::path::Path) {
    // New script inodes can spend the one-second tested budget before their
    // first statement on macOS. Complete one separately bounded execution of
    // this exact inode before testing maintenance's unchanged one-second limit.
    let marker = root.join("warmup-pid");
    let started = Instant::now();
    let mut child = std::process::Command::new(python)
        .env("N9_PID", &marker)
        .env("PATH", "")
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn_fenced()
        .expect("owned first fixture execution");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut exited = None;
    while !marker.exists() && Instant::now() < deadline {
        exited = child.try_wait().expect("observe first execution");
        if exited.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let reached = marker.exists();
    let elapsed = started.elapsed();
    if exited.is_none() {
        // SAFETY: this unreaped owned Child pins the private process group.
        assert_eq!(
            unsafe { libc::kill(-(child.id() as i32), libc::SIGTERM) },
            0
        );
        let grace = Instant::now() + Duration::from_secs(3);
        while exited.is_none() && Instant::now() < grace {
            exited = child.try_wait().expect("reap first execution");
            if exited.is_none() {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        if exited.is_none() {
            // SAFETY: still-unreaped group leader, no unrelated PID lookup.
            assert_eq!(
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                0
            );
        }
    }
    let status = child.wait().expect("reap first fixture execution");
    assert!(
        reached,
        "first fixture statement did not execute within ten seconds"
    );
    assert!(
        status.success(),
        "first execution must cooperatively finish: {status}"
    );
    assert_eq!(
        std::fs::read_to_string(marker).expect("first PID").trim(),
        child.id().to_string()
    );
    eprintln!(
        "N9 first fixture statement after {} us; exact first child {} reaped",
        elapsed.as_micros(),
        child.id()
    );
}

#[test]
fn legacy_entrypoint_has_no_timeout_dependency_and_reports_expiry_after_reap() {
    let root = root("legacy");
    let python = root.join("python");
    std::fs::write(
        &python,
        "#!/bin/sh\ntrap 'exit 0' TERM\necho $$ > \"$N9_PID\"\nwhile :; do /bin/sleep 1; done\n",
    )
    .expect("private Python boundary");
    std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o700))
        .expect("executable fixture");
    first_execution(&python, &root);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ida-cli"))
        .args(["cache-legacy", "--help"])
        .env("IDA_NEXUS_PYTHON", &python)
        .env("IDA_CLI_LEGACY_TIMEOUT_SECS", "1")
        .env("N9_PID", root.join("pid"))
        .env("IDA_CLI_HOME", root.join("home"))
        .env("TMPDIR", &root)
        .env("PATH", "")
        .output_fenced()
        .expect("execute maintenance without timeout command");
    assert!(
        !output.status.success(),
        "expiry cannot become success after cooperative TERM"
    );
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("expired=true"), "{error}");
    assert!(error.contains("Inspect --backup"), "{error}");
    let pid: i32 = std::fs::read_to_string(root.join("pid"))
        .expect("owned pid")
        .trim()
        .parse()
        .expect("numeric pid");
    // SAFETY: signal zero observes the exact fixture process without signalling it.
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    std::fs::remove_dir_all(root).expect("remove owned fixture");
}

#[test]
fn nexus_gc_uses_python_directly_without_timeout_in_path() {
    let Some(root) = std::env::var_os("N9_GC_ROOT").map(PathBuf::from) else {
        let root = root("gc");
        let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "nexus_gc_uses_python_directly_without_timeout_in_path",
                "--nocapture",
            ])
            .env("N9_GC_ROOT", &root)
            .env("PATH", "")
            .output_fenced()
            .expect("private GC process");
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(String::from_utf8_lossy(&child.stdout).contains("1 passed"));
        assert!(
            root.join("called").is_file(),
            "GC actually invoked its Python maintenance child"
        );
        std::fs::remove_dir_all(root).expect("remove GC fixture");
        return;
    };
    let python = root.join("python");
    std::fs::write(&python, "#!/bin/sh\nprintf called > \"$N9_GC_ROOT/called\"\nprintf '%s\\n' '{\"evicted_groups\":2,\"evicted_files\":3,\"evicted_bytes\":4,\"remaining_bytes\":5}'\n")
        .expect("GC Python boundary");
    std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o700))
        .expect("fixture mode");
    // This exact libtest subprocess is private and single-threaded; no other
    // test shares its environment. Set it before starting any async runtime.
    std::env::set_var("IDA_NEXUS_PYTHON", &python);
    let store = ida_mcp::idb_store::IdbStore::with_root(root.join("cache"));
    let result = store.evict_to_limit(0, &std::collections::HashSet::new());
    assert_eq!(result.evicted_groups, 2);
    assert_eq!(result.evicted_files, 3);
    assert_eq!(result.evicted_bytes, 4);
    assert_eq!(result.remaining_bytes, 5);
}

#[test]
fn stdio_startup_propagates_missing_runtime_error() {
    let root = root("startup");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ida-cli"))
        .arg("serve")
        .env("IDA_NEXUS_PYTHON", root.join("missing-python"))
        .env("IDA_CLI_HOME", root.join("home"))
        .env("TMPDIR", &root)
        .output_fenced()
        .expect("owned stdio startup");
    assert!(
        !output.status.success(),
        "dependency failure must reach process exit"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Nexus Python environment missing"));
    std::fs::remove_dir_all(root).expect("remove startup fixture");
}
