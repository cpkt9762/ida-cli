use super::*;
use std::os::unix::process::CommandExt;
#[test]
fn owner_lock_is_released_even_while_a_forked_child_waits_for_exec() {
    let directory = std::env::temp_dir().join(format!("n4-f2-lock-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("socket");
    let owner = McpSocketOwnerLock::acquire(&path).unwrap();
    let descriptor = owner.file.as_raw_fd();
    // SAFETY: querying flags on our live file descriptor.
    assert_ne!(
        unsafe { libc::fcntl(descriptor, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0,
        "Rust OpenOptions must atomically set CLOEXEC"
    );
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = child.as_raw_fd();
    let metadata = owner.file.metadata().unwrap();
    let mut command = std::process::Command::new("/usr/bin/python3");
    command.args(["-c", "import os,sys\ntry: s=os.fstat(int(sys.argv[1]))\nexcept OSError: pass\nelse: assert (s.st_dev,s.st_ino)!=(int(sys.argv[2]),int(sys.argv[3])), 'owner lock survived exec'"])
        .args([descriptor.to_string(), metadata.dev().to_string(), metadata.ino().to_string()]);
    // SAFETY: only async-signal-safe read/write syscalls in the child.
    unsafe {
        command.pre_exec(move || {
            let byte = b'R';
            if libc::write(fd, (&byte as *const u8).cast(), 1) != 1 {
                return Err(std::io::Error::last_os_error());
            }
            let mut byte = 0u8;
            if libc::read(fd, (&mut byte as *mut u8).cast(), 1) != 1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawned = std::thread::spawn(move || {
        let _child = child;
        let mut child = command.spawn().unwrap();
        crate::preprocess::record_owned_fixture(child.id(), false, "n4-f2-exec-lock-probe");
        child.wait().unwrap()
    });
    parent
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut byte = [0];
    std::io::Read::read_exact(&mut parent, &mut byte).unwrap();
    assert_eq!(byte, [b'R']);
    drop(owner);
    let reacquired = McpSocketOwnerLock::acquire(&path);
    std::io::Write::write_all(&mut parent, b"G").unwrap();
    assert!(spawned.join().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        reacquired.is_ok(),
        "parent drop must release ownership despite fork/exec window: {reacquired:?}"
    );
}
