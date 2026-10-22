use super::*;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

fn root() -> PathBuf {
    static ROOTS: AtomicU64 = AtomicU64::new(1);
    let root = std::env::temp_dir().join(format!(
        "session-allocation-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos(),
        ROOTS.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).expect("new private test root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    root
}

fn snapshot(path: &Path) -> (u64, i64, i64, Vec<u8>) {
    let m = std::fs::symlink_metadata(path).expect("sentinel metadata");
    (
        m.ino(),
        m.mtime(),
        m.mtime_nsec(),
        if m.is_file() {
            std::fs::read(path).expect("sentinel contents")
        } else {
            Vec::new()
        },
    )
}

#[test]
fn collision_preserves_obligations_and_authorizations() {
    let root = root();
    let old = root.join("n4-42-1");
    std::fs::create_dir(&old).expect("old session");
    std::fs::create_dir(old.join("launch-authorizations")).expect("permanent fence");
    std::fs::write(old.join("helper-state.json"), b"pending obligations")
        .expect("obligation sentinel");
    std::fs::write(
        old.join("launch-authorizations/grant"),
        b"permanent authorization",
    )
    .expect("authorization sentinel");
    let paths = [
        &old,
        &old.join("helper-state.json"),
        &old.join("launch-authorizations"),
        &old.join("launch-authorizations/grant"),
    ];
    let before: Vec<_> = paths.iter().map(|p| snapshot(p)).collect();
    assert_eq!(
        reserve(&root, 42, &AtomicU64::new(1), 4).expect("skip old session"),
        root.join("n4-42-2")
    );
    assert_eq!(
        before,
        paths.iter().map(|p| snapshot(p)).collect::<Vec<_>>()
    );
}

#[test]
fn consecutive_collisions_and_symlink_are_skipped() {
    let root = root();
    std::fs::create_dir(root.join("n4-42-1")).expect("first occupied name");
    std::fs::create_dir(root.join("n4-42-2")).expect("second occupied name");
    let target = root.join("target");
    std::fs::create_dir(&target).expect("symlink target");
    let link = root.join("n4-42-3");
    symlink(&target, &link).expect("occupied symlink");
    let before = (snapshot(&target), snapshot(&link));
    assert_eq!(
        reserve(&root, 42, &AtomicU64::new(1), 4).expect("skip occupied names"),
        root.join("n4-42-4")
    );
    assert_eq!(before, (snapshot(&target), snapshot(&link)));
    assert_eq!(
        std::fs::read_dir(&target)
            .expect("target untouched")
            .count(),
        0
    );
    assert_eq!(std::fs::read_link(&link).expect("link unchanged"), target);
}

#[test]
fn missing_parent_reports_path_without_retry() {
    let root = root().join("missing");
    let sequence = AtomicU64::new(1);
    let error = reserve(&root, 42, &sequence, 4).expect_err("missing parent must fail");
    let cause = error.downcast_ref::<std::io::Error>().expect("IO cause");
    assert!(
        error.to_string().contains(&cause.to_string()),
        "CLI display must retain IO cause"
    );
    assert!(format!("{error:#}").contains(root.join("n4-42-1").to_str().expect("UTF-8 fixture")));
    assert_eq!(sequence.load(Ordering::Relaxed), 2);
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .expect("underlying IO error")
            .kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn unwritable_parent_reports_path_without_retry() {
    let root = root();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500))
        .expect("unwritable parent");
    let sequence = AtomicU64::new(1);
    let result = reserve(&root, 42, &sequence, 4);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("restore test root permissions");
    let error = result.expect_err("unwritable parent must fail");
    let cause = error.downcast_ref::<std::io::Error>().expect("IO cause");
    assert!(
        error.to_string().contains(&cause.to_string()),
        "CLI display must retain IO cause"
    );
    assert!(format!("{error:#}").contains(root.join("n4-42-1").to_str().expect("UTF-8 fixture")));
    assert_eq!(sequence.load(Ordering::Relaxed), 2);
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .expect("underlying IO error")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn exhaustion_reports_last_path_and_attempt_count() {
    let root = root();
    for n in 1..=3 {
        std::fs::create_dir(root.join(format!("n4-42-{n}"))).expect("occupied candidate");
    }
    let sequence = AtomicU64::new(1);
    let error = reserve(&root, 42, &sequence, 3)
        .expect_err("bounded exhaustion")
        .to_string();
    assert!(error.contains("3 attempts"), "{error}");
    assert!(
        error.contains(root.join("n4-42-3").to_str().expect("UTF-8 fixture")),
        "{error}"
    );
    assert_eq!(sequence.load(Ordering::Relaxed), 4);
}

#[test]
fn concurrent_allocators_never_share_a_directory() {
    let root = root();
    let barrier = std::sync::Barrier::new(8);
    let paths = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    reserve(&root, 42, &AtomicU64::new(1), 16)
                        .expect("atomic concurrent allocation")
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().expect("allocator thread"))
            .collect::<std::collections::HashSet<_>>()
    });
    assert_eq!(paths.len(), 8);
    assert_eq!(
        std::fs::read_dir(&root)
            .expect("reserved directories")
            .count(),
        8
    );
}
