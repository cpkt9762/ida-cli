//! Close-only SCM_RIGHTS protection. Execution permission remains in Python's
//! durable target journal; an FD/ACK alone never grants file mutation authority.
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;

/// Unlike CacheGuard, this non-Clone owner has no explicit unlock operation.
/// All surplus, rejected, moved and dropped rights only close their own FD.
pub struct TransferredTargetGuard {
    file: File,
}

impl TransferredTargetGuard {
    pub fn from_received(fd: OwnedFd, expected: [u64; 3]) -> io::Result<Self> {
        let file = File::from(fd);
        let metadata = file.metadata()?;
        // SAFETY: getuid has no memory preconditions or ownership effects.
        let uid = u64::from(unsafe { libc::getuid() });
        if !metadata.is_file()
            || metadata.nlink() != 1
            || u64::from(metadata.uid()) != uid
            || metadata.permissions().mode() & 0o777 != 0o600
            || [metadata.dev(), metadata.ino(), uid] != expected
        {
            return Err(io::Error::other("HandoffBlocked: received target identity"));
        }
        close_on_exec(file.as_raw_fd())?;
        Ok(Self { file })
    }

    /// The receiver receives the same target OFD. This method cannot thaw a
    /// FrozenOffer, clone a writer, or transfer the resource root's shared OFD.
    pub fn relay(
        &self,
        channel: &impl AsRawFd,
        directory: &File,
        payload: &[u8],
    ) -> io::Result<()> {
        let rights = [self.file.as_raw_fd(), directory.as_raw_fd()];
        let bytes = size_of::<libc::c_int>() * rights.len();
        // SAFETY: CMSG_SPACE only performs the platform's checked ABI alignment.
        let length = unsafe { libc::CMSG_SPACE(bytes as _) } as usize;
        let mut control = vec![0usize; length.div_ceil(size_of::<usize>())];
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: msghdr is a C POD; all pointers/lengths are populated below.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = length as _;
        // SAFETY: aligned control storage has exactly CMSG_SPACE(two FDs).
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(io::Error::other("HandoffBlocked: ancillary storage"));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(bytes as _) as _;
            std::ptr::copy_nonoverlapping(
                rights.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                bytes,
            );
            let sent = libc::sendmsg(channel.as_raw_fd(), &message, 0);
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            if usize::try_from(sent).ok() != Some(payload.len()) {
                return Err(io::Error::other(
                    "HandoffUncertain: partial rights submission",
                ));
            }
        }
        Ok(())
    }
}

/// Owns the exact received rights. It carries no root guard and no clone API.
pub struct ReceivedTransfer {
    pub guard: TransferredTargetGuard,
    directory: File,
    payload: Vec<u8>,
}

impl ReceivedTransfer {
    pub fn receive(channel: &UnixDatagram) -> io::Result<Self> {
        let (payload, mut files) = receive_rights(channel)?;
        if files.len() != 2 {
            return Err(io::Error::other("HandoffBlocked: unexpected rights count"));
        }
        let binding: serde_json::Value = serde_json::from_slice(&payload)?;
        let expected = identity(&binding["lock_identity"])?;
        let expected_directory = identity(&binding["directory"])?;
        let directory = files
            .pop()
            .ok_or_else(|| io::Error::other("HandoffBlocked: missing directory right"))?;
        let target = files
            .pop()
            .ok_or_else(|| io::Error::other("HandoffBlocked: missing target right"))?;
        let info = directory.metadata()?;
        // SAFETY: getuid has no memory preconditions.
        let uid = u64::from(unsafe { libc::getuid() });
        if !info.is_dir()
            || info.permissions().mode() & 0o777 != 0o700
            || u64::from(info.uid()) != uid
            || [info.dev(), info.ino(), u64::from(info.uid())] != expected_directory
        {
            return Err(io::Error::other(
                "HandoffBlocked: received directory identity",
            ));
        }
        // SAFETY: fstatat writes one POD stat into valid storage. The literal
        // name is relative to our received live directory, with no symlink walk.
        let mut at_path: libc::stat = unsafe { zeroed() };
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                c"lock".as_ptr(),
                &mut at_path,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if [
            at_path.st_dev as u64,
            at_path.st_ino,
            u64::from(at_path.st_uid),
        ] != expected
            || at_path.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err(io::Error::other(
                "HandoffBlocked: lock path differs from received OFD",
            ));
        }
        close_on_exec(directory.as_raw_fd())?;
        Ok(Self {
            guard: TransferredTargetGuard::from_received(target.into(), expected)?,
            directory,
            payload,
        })
    }

    pub fn relay(&self, channel: &impl AsRawFd) -> io::Result<()> {
        self.guard.relay(channel, &self.directory, &self.payload)
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

fn identity(value: &serde_json::Value) -> io::Result<[u64; 3]> {
    let parts = value
        .as_array()
        .filter(|parts| parts.len() == 3)
        .ok_or_else(|| io::Error::other("HandoffBlocked: malformed FD identity"))?;
    let mut result = [0; 3];
    for (output, value) in result.iter_mut().zip(parts) {
        *output = value
            .as_u64()
            .ok_or_else(|| io::Error::other("HandoffBlocked: noninteger FD identity"))?;
    }
    Ok(result)
}

fn close_on_exec(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: fd is owned and live; only its descriptor flags are read/changed.
    let previous = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if previous < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFD accepts exactly the descriptor flags obtained above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, previous | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn receive_rights(channel: &UnixDatagram) -> io::Result<(Vec<u8>, Vec<File>)> {
    let mut payload = vec![0u8; 64 * 1024];
    // More than the permitted two rights is retained solely to close all of it.
    let mut control = vec![0usize; 128];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: msghdr is POD and all referenced buffers live through recvmsg.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = (control.len() * size_of::<usize>()) as _;
    let receive_guard = crate::process_spawn::receive_fence()?;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: all buffers and their capacities are valid and writable. The
    // process fence excludes spawn until every received descriptor is sealed.
    let received = unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, flags) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(all(test, feature = "nexus-test-support"))]
    RECEIVE_WINDOW.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let mut files = Vec::new();
    let mut unexpected = false;
    // SAFETY: CMSG traversal operates only on the kernel-filled msghdr. Each
    // payload range is checked against the allocated aligned buffer below.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        let end = (message.msg_control as usize) + message.msg_controllen as usize;
        while !header.is_null() {
            let data = libc::CMSG_DATA(header);
            let size = (*header).cmsg_len as usize;
            let overhead = libc::CMSG_LEN(0) as usize;
            if size < overhead || (header as usize).checked_add(size).is_none_or(|n| n > end) {
                unexpected = true;
                break;
            }
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let count = (size - overhead) / size_of::<libc::c_int>();
                for index in 0..count {
                    let fd = std::ptr::read_unaligned(data.cast::<libc::c_int>().add(index));
                    if fd < 0 {
                        unexpected = true;
                        continue;
                    }
                    files.push(File::from_raw_fd(fd));
                }
            } else {
                unexpected = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    // Seal all rights, including surplus/rejected ones, before any validation
    // can fail or any concurrent spawn can inherit their open descriptions.
    for file in &files {
        close_on_exec(file.as_raw_fd())?;
    }
    drop(receive_guard);
    if unexpected || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::other(
            "HandoffBlocked: truncated/unexpected ancillary data",
        ));
    }
    let length = usize::try_from(received).map_err(io::Error::other)?;
    payload.truncate(length);
    Ok((payload, files))
}

#[cfg(all(test, feature = "nexus-test-support"))]
thread_local! {
    static RECEIVE_WINDOW: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, feature = "nexus-test-support"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::os::unix::process::CommandExt;
    use std::time::Duration;

    const PRODUCER: &str = r#"
import array,fcntl,json,os,socket,sys
from pathlib import Path
root=Path(sys.argv[2]); variant=sys.argv[3]
with socket.socket(fileno=int(sys.argv[1])) as channel:
 channel.settimeout(4)
 directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 descriptor=os.open(root/'lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  fcntl.flock(descriptor,fcntl.LOCK_EX)
  d=os.fstat(directory); f=os.fstat(descriptor)
  binding={'directory':[d.st_dev,d.st_ino,d.st_uid],'lock_identity':[f.st_dev,f.st_ino,f.st_uid]}
  if variant=='wrong-inode': binding['lock_identity'][1]+=1
  if variant=='hardlink': os.link(root/'lock',root/'alias')
  rights=[descriptor,directory]+([descriptor] if variant=='surplus' else [])
  channel.sendmsg([json.dumps(binding).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',rights))])
  if channel.recv(16)!=b'finish': raise AssertionError('finish marker')
 finally:
  os.close(descriptor); os.close(directory)
"#;

    fn independently_blocked(path: &std::path::Path) -> bool {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path.join("lock"))
            .expect("open independent target OFD");
        // SAFETY: the live owned descriptor receives only a nonblocking probe.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return false;
        }
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        true
    }

    #[test]
    fn concurrent_spawn_cannot_inherit_received_target_ofd() {
        use std::io::{BufRead, Write};
        use std::sync::mpsc;
        let root =
            std::path::PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private case"));
        let lock = root.join("receive-window.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .expect("private lock");
        // SAFETY: exclusive flock on this owned regular file.
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) }, 0);
        let directory = File::open(&root).expect("private directory");
        let (sender, receiver) = UnixDatagram::pair().expect("private transfer channel");
        let source = TransferredTargetGuard { file };
        source
            .relay(&sender, &directory, b"window")
            .expect("real SCM_RIGHTS");
        let (began_tx, began_rx) = mpsc::channel();
        let (spawned_tx, spawned_rx) = mpsc::channel();
        let spawned_rx = std::sync::Arc::new(std::sync::Mutex::new(spawned_rx));
        let window_rx = spawned_rx.clone();
        let (go_tx, go_rx) = mpsc::channel();
        let child_root = root.clone();
        let spawn = std::thread::spawn(move || {
            go_rx
                .recv()
                .expect("recvmsg reached exact publication window");
            let mut command = std::process::Command::new(
                std::env::var_os("R3A_PYTHON").expect("prepared Python"),
            );
            command.args(["-B", "-c", "import json,os,sys; p=os.stat(sys.argv[1]); matches=[]\nfor fd in range(3,1024):\n try:\n  s=os.fstat(fd)\n  if (s.st_dev,s.st_ino)==(p.st_dev,p.st_ino): matches.append(fd)\n except OSError: pass\nprint(json.dumps(matches),flush=True); sys.stdin.readline()"])
                .arg(child_root.join("receive-window.lock"))
                .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
            began_tx.send(()).expect("spawn attempt");
            let mut child = crate::router::nexus_bridge::test_spawn_std_child(&mut command)
                .expect("concurrent real spawn");
            let mut line = String::new();
            std::io::BufReader::new(child.stdout.take().expect("child output"))
                .read_line(&mut line)
                .expect("actual child fstat");
            spawned_tx.send(()).expect("exec marker");
            (child, line)
        });
        RECEIVE_WINDOW.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                go_tx.send(()).expect("open receive window");
                began_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("concurrent spawn entered");
                // The old path completes exec here; a fenced spawn must wait until
                // the receiver has set CLOEXEC. No sleep or scheduler luck opens it.
                let _ = window_rx
                    .lock()
                    .expect("window marker")
                    .recv_timeout(Duration::from_millis(500));
            }))
        });
        let (_, received) = receive_rights(&receiver).expect("actual received rights");
        let (mut child, line) = spawn.join().expect("concurrent spawn worker");
        let inherited: Vec<i32> = serde_json::from_str(&line).expect("exact inherited inode list");
        drop(received);
        drop(source);
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock)
            .expect("independent OFD");
        // SAFETY: independent NB fence; never unlock a transferred OFD.
        let fence = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        child
            .stdin
            .take()
            .expect("child finish input")
            .write_all(b"finish\n")
            .expect("natural finish");
        let pid = child.id();
        let status = child.wait().expect("real child terminal");
        crate::router::nexus_bridge::test_record_child_exit(
            pid,
            &status,
            "Child.wait.receive_window",
        );
        std::fs::write(root.join("receive-window.json"), serde_json::to_vec(&serde_json::json!({"inherited_fds":inherited,"independent_fence":fence,"child_exit":status.code()})).unwrap()).unwrap();
        assert!(status.success());
        assert!(
            inherited.is_empty(),
            "unrelated child inherited exact target EX OFD: {inherited:?}"
        );
        assert_eq!(
            fence, 0,
            "job close must release exclusion while unrelated child lives"
        );
    }

    #[test]
    fn received_guard_move_relay_and_rejections_are_close_only() {
        let base =
            std::path::PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private case root"));
        for variant in ["normal", "wrong-inode", "hardlink", "surplus"] {
            let root = base.join(format!("rust-rights-{variant}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .expect("new private rights case");
            let (parent, child_channel) =
                UnixDatagram::pair().expect("private directional channel");
            parent
                .set_read_timeout(Some(Duration::from_secs(4)))
                .expect("bounded receiver");
            let fd = child_channel.as_raw_fd();
            let mut command = std::process::Command::new("timeout");
            command
                .arg("6s")
                .arg(std::env::var_os("R3A_PYTHON").expect("private prepared Python"))
                .arg("-B")
                .arg("-c")
                .arg(PRODUCER)
                .arg(fd.to_string())
                .arg(&root)
                .arg(variant)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::from(
                    std::fs::File::create(root.join("producer.stderr")).expect("private child log"),
                ));
            // SAFETY: only fcntl is called after fork. It clears CLOEXEC on this
            // one owned channel for the immediately following interpreter exec.
            unsafe {
                command.pre_exec(move || {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = crate::router::nexus_bridge::test_spawn_std_child(&mut command)
                .expect("record the exact producer intent and birth");
            let child_pid = child.id();
            drop(child_channel);
            let received = ReceivedTransfer::receive(&parent);
            assert!(
                independently_blocked(&root),
                "a rejection cannot unlock the source OFD"
            );
            if variant == "normal" {
                let moved = received.expect("actual received rights");
                let (sender, receiver) = UnixDatagram::pair().expect("relay channel");
                moved.relay(&sender).expect("relay the same OFD");
                drop(moved);
                assert!(
                    independently_blocked(&root),
                    "queued relay rights retain exclusion"
                );
                let successor =
                    ReceivedTransfer::receive(&receiver).expect("unique relay receiver");
                parent.send(b"finish").expect("source close marker");
                let status = child.wait().expect("natural source exit");
                crate::router::nexus_bridge::test_record_child_exit(
                    child_pid,
                    &status,
                    "Child.wait.transfer_source",
                );
                assert!(status.success());
                assert!(
                    independently_blocked(&root),
                    "source Drop cannot unlock receiver"
                );
                drop(successor);
            } else {
                assert!(received.is_err(), "malformed identity/rights accepted");
                parent
                    .send(b"finish")
                    .expect("source close after rejection");
                let status = child.wait().expect("natural rejected-source exit");
                crate::router::nexus_bridge::test_record_child_exit(
                    child_pid,
                    &status,
                    "Child.wait.rejected_transfer_source",
                );
                assert!(status.success());
            }
            assert!(
                !independently_blocked(&root),
                "all rights closed, independent fence available"
            );
        }
    }
}
