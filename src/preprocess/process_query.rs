#[cfg(target_os = "macos")]
use super::exited_without_reaping;

#[cfg(target_os = "macos")]
trait ProcessQuery {
    fn list(&self, group: i32, pids: &mut [i32]) -> i32;
    fn member(&self, pid: i32, info: &mut libc::proc_bsdinfo) -> i32;
    fn signal(&self, pid: i32, signal: i32) -> i32;
    fn owned_leader_exited(&self, pid: i32) -> std::io::Result<bool>;
}
#[cfg(target_os = "macos")]
struct KernelQuery;
#[cfg(target_os = "macos")]
impl ProcessQuery for KernelQuery {
    fn owned_leader_exited(&self, pid: i32) -> std::io::Result<bool> {
        exited_without_reaping(pid)
    }
    fn signal(&self, pid: i32, signal: i32) -> i32 {
        // SAFETY: only callers with an unreaped owned leader may signal.
        unsafe { libc::kill(-pid, signal) }
    }
    fn list(&self, group: i32, pids: &mut [i32]) -> i32 {
        // SAFETY: bounded writable PID array; read-only group query.
        unsafe {
            libc::proc_listpids(
                2,
                group as u32,
                pids.as_mut_ptr().cast(),
                std::mem::size_of_val(pids) as i32,
            )
        }
    }
    fn member(&self, pid: i32, info: &mut libc::proc_bsdinfo) -> i32 {
        // SAFETY: exact writable C output storage; read-only process query.
        unsafe {
            libc::proc_pidinfo(
                pid,
                3,
                0,
                (info as *mut libc::proc_bsdinfo).cast(),
                std::mem::size_of_val(info) as i32,
            )
        }
    }
}
#[cfg(target_os = "macos")]
#[derive(PartialEq, Eq)]
pub(super) struct GroupMember {
    pid: i32,
    stopped: bool,
}
#[cfg(target_os = "macos")]
pub(super) fn group_members(pid: i32) -> std::io::Result<Vec<GroupMember>> {
    group_members_with(pid, &KernelQuery)
}
#[cfg(target_os = "macos")]
fn group_members_with(pid: i32, query: &impl ProcessQuery) -> std::io::Result<Vec<GroupMember>> {
    let mut pids = [0i32; 256];
    let count = query.list(pid, &mut pids);
    if count <= 0
        || count as usize >= std::mem::size_of_val(&pids)
        || !(count as usize).is_multiple_of(std::mem::size_of::<i32>())
    {
        let source = std::io::Error::last_os_error();
        return Err(
            if count <= 0 && source.raw_os_error().is_some_and(|code| code != 0) {
                source
            } else {
                std::io::Error::other(format!(
                    "owned process group enumeration ambiguous/truncated ({count} bytes)"
                ))
            },
        );
    }
    let mut members = Vec::new();
    for member in pids
        .into_iter()
        .take(count as usize / std::mem::size_of::<i32>())
        .filter(|p| *p > 0)
    {
        // SAFETY: initialized C output storage for a read-only query.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        if query.member(member, &mut info) != size {
            let error = std::io::Error::last_os_error();
            // Darwin PROC_PIDTBSDINFO excludes some zombies. Only our exact
            // unreaped leader has an independent, positive WNOWAIT stop proof.
            // Missing foreign members are never interpreted as stopped.
            if member == pid
                && error.raw_os_error() == Some(libc::ESRCH)
                && query.owned_leader_exited(pid)?
            {
                members.push(GroupMember {
                    pid: member,
                    stopped: true,
                });
                continue;
            }
            return Err(error);
        }
        if info.pbi_pid != member as u32 || info.pbi_pgid != pid as u32 {
            return Err(std::io::Error::other("owned group identity changed"));
        }
        members.push(GroupMember {
            pid: member,
            stopped: info.pbi_status == 5,
        });
    }
    if members.is_empty() {
        return Err(std::io::Error::other(
            "empty owned group enumeration is ambiguous",
        ));
    }
    members.sort_by_key(|member| member.pid);
    Ok(members)
}
#[cfg(target_os = "macos")]
pub(super) fn signal_group(pid: i32, signal: i32) -> std::io::Result<()> {
    signal_group_with(pid, signal, &KernelQuery)
}
#[cfg(target_os = "macos")]
fn signal_group_with(pid: i32, signal: i32, query: &impl ProcessQuery) -> std::io::Result<()> {
    if query.signal(pid, signal) == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    if error.raw_os_error() == Some(libc::EPERM) {
        let members = group_members_with(pid, query)?;
        if !members.is_empty()
            && members.iter().all(|member| member.stopped)
            && group_members_with(pid, query)? == members
        {
            return Ok(());
        }
    }
    Err(error)
}
#[cfg(not(target_os = "macos"))]
pub(super) fn signal_group(pid: i32, signal: i32) -> std::io::Result<()> {
    // SAFETY: caller still exclusively owns the unreaped group leader.
    if unsafe { libc::kill(-pid, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    if error.raw_os_error() == Some(libc::EPERM)
        && group_members(pid)?.iter().all(|member| member.stopped)
    {
        // Darwin refuses signals to an all-zombie group. Explicit kernel status
        // proves no member can run; EPERM alone is never interpreted as stopped.
        return Ok(());
    }
    Err(error)
}

#[cfg(all(test, target_os = "macos"))]
mod query_regressions {
    use super::*;
    struct Fault {
        count: i32,
        errno: i32,
        member_size: i32,
    }
    impl ProcessQuery for Fault {
        fn owned_leader_exited(&self, _: i32) -> std::io::Result<bool> {
            Err(std::io::Error::from_raw_os_error(libc::ECHILD))
        }
        fn signal(&self, _: i32, _: i32) -> i32 {
            // SAFETY: only thread-local errno is injected. No OS signal sent.
            unsafe {
                *libc::__error() = self.errno;
            }
            -1
        }
        fn list(&self, _: i32, pids: &mut [i32]) -> i32 {
            pids[0] = 123;
            // SAFETY: test-local thread errno, no process state is changed.
            unsafe {
                *libc::__error() = self.errno;
            }
            self.count
        }
        fn member(&self, _: i32, _: &mut libc::proc_bsdinfo) -> i32 {
            self.member_size
        }
    }
    #[test]
    fn zero_errno_and_ambiguous_empty_are_not_stop_evidence() {
        for errno in [libc::EPERM, 0] {
            assert!(
                group_members_with(
                    123,
                    &Fault {
                        count: 0,
                        errno,
                        member_size: 0
                    }
                )
                .is_err(),
                "zero list result errno={errno} must remain unknown"
            );
        }
    }
    #[test]
    fn kill_failure_plus_empty_query_never_proves_zombie_stop() {
        assert!(signal_group_with(
            123,
            libc::SIGKILL,
            &Fault {
                count: 0,
                errno: libc::EPERM,
                member_size: 0
            }
        )
        .is_err());
        assert!(signal_group_with(
            123,
            libc::SIGKILL,
            &Fault {
                count: 4,
                errno: libc::EIO,
                member_size: 0
            }
        )
        .is_err());
        assert!(signal_group_with(
            123,
            libc::SIGKILL,
            &Fault {
                count: 4,
                errno: libc::EPERM,
                member_size: 0
            }
        )
        .is_err());
    }
    #[test]
    fn truncated_misaligned_and_failed_member_are_not_stop_evidence() {
        for count in [1024, 3, 4] {
            assert!(
                group_members_with(
                    123,
                    &Fault {
                        count,
                        errno: libc::EPERM,
                        member_size: 0
                    }
                )
                .is_err(),
                "count={count} must remain unknown"
            );
        }
    }
    #[test]
    fn positive_stop_proof_requires_stable_members_and_exact_unreaped_leader() {
        struct Proof {
            stopped: bool,
            missing: bool,
            own_exited: bool,
            changing: bool,
            lists: std::cell::Cell<usize>,
        }
        impl ProcessQuery for Proof {
            fn list(&self, _: i32, pids: &mut [i32]) -> i32 {
                let n = self.lists.get();
                self.lists.set(n + 1);
                pids[0] = if self.changing && n > 0 { 124 } else { 123 };
                4
            }
            fn member(&self, pid: i32, info: &mut libc::proc_bsdinfo) -> i32 {
                if self.missing {
                    // SAFETY: test-local syscall error, no process mutation.
                    unsafe {
                        *libc::__error() = libc::ESRCH;
                    }
                    return 0;
                }
                info.pbi_pid = pid as u32;
                info.pbi_pgid = 123;
                info.pbi_status = if self.stopped { 5 } else { 2 };
                std::mem::size_of_val(info) as i32
            }
            fn signal(&self, _: i32, _: i32) -> i32 {
                // SAFETY: test-local syscall error, no signal sent.
                unsafe {
                    *libc::__error() = libc::EPERM;
                }
                -1
            }
            fn owned_leader_exited(&self, _: i32) -> std::io::Result<bool> {
                Ok(self.own_exited)
            }
        }
        let proof = |stopped, missing, own_exited, changing| Proof {
            stopped,
            missing,
            own_exited,
            changing,
            lists: std::cell::Cell::new(0),
        };
        assert!(signal_group_with(123, libc::SIGKILL, &proof(true, false, false, false)).is_ok());
        assert!(signal_group_with(123, libc::SIGKILL, &proof(false, false, false, false)).is_err());
        assert!(signal_group_with(123, libc::SIGKILL, &proof(true, false, false, true)).is_err());
        assert!(signal_group_with(123, libc::SIGKILL, &proof(false, true, false, false)).is_err());
        assert!(signal_group_with(123, libc::SIGKILL, &proof(false, true, true, false)).is_ok());
        assert!(
            signal_group_with(123, libc::SIGKILL, &proof(false, true, true, true)).is_err(),
            "owned leader proof cannot authorize missing foreign member"
        );
    }
}
