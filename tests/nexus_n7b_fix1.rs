//! DSC storage sharing through the public preparation entry; no native IDA.
use ida_mcp::{
    preprocess::Preparation,
    router::nexus_bridge::cache::special::{self, DscInput},
};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

struct Fixture {
    root: PathBuf,
    previous: Option<std::ffi::OsString>,
    _gate: tokio::sync::OwnedMutexGuard<()>,
}
impl Fixture {
    async fn new() -> Self {
        static GATE: std::sync::LazyLock<std::sync::Arc<tokio::sync::Mutex<()>>> =
            std::sync::LazyLock::new(|| std::sync::Arc::new(tokio::sync::Mutex::new(())));
        let gate = GATE.clone().lock_owned().await;
        let root = std::env::temp_dir().join(format!("b1-store-{}", std::process::id()));
        std::fs::create_dir(&root).expect("private fixture root");
        std::fs::create_dir(root.join("bin")).expect("private idat directory");
        let idat = root.join("bin/idat");
        std::fs::write(&idat,"#!/usr/bin/python3\nimport sys\nfrom pathlib import Path\noutput=next(v[2:] for v in sys.argv[1:] if v.startswith('-o'))\nPath(output).write_bytes(b'packed offline boundary fixture')\n").expect("controlled offline preparer");
        std::fs::set_permissions(&idat, std::fs::Permissions::from_mode(0o700))
            .expect("executable fixture");
        std::fs::create_dir(root.join("source")).expect("source directory");
        std::fs::write(
            root.join("source/dyld_shared_cache_arm64e"),
            vec![1; 1024 * 1024],
        )
        .expect("primary source");
        std::fs::write(
            root.join("source/dyld_shared_cache_arm64e.01"),
            vec![2; 1024 * 1024],
        )
        .expect("companion source");
        let previous = std::env::var_os("IDADIR");
        // SAFETY: this exact integration target runs one isolated case serially.
        unsafe {
            std::env::set_var("IDADIR", root.join("bin"));
        }
        Self {
            root,
            previous,
            _gate: gate,
        }
    }
    async fn open(&self, module: &str) -> PathBuf {
        let prep = Preparation::new(Duration::from_secs(20));
        let config = DscInput {
            arch: "arm64e".into(),
            module: module.into(),
            frameworks: vec![],
            ida_version: 9,
            log_path: None,
        };
        let prepared = special::prepare(
            self.root.join("source/dyld_shared_cache_arm64e"),
            self.root.join("cache"),
            config,
            &prep,
        )
        .await
        .expect("production DSC preparation");
        prepared
            .publish_verified_input(&prep)
            .await
            .expect("ordinary content index publication");
        prepared.path.clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: restore the isolated test's environment before returning.
        unsafe {
            match self.previous.take() {
                Some(v) => std::env::set_var("IDADIR", v),
                None => std::env::remove_var("IDADIR"),
            }
        }
        std::fs::remove_dir_all(&self.root).expect("private fixture cleanup");
    }
}
fn member(idb: &Path) -> PathBuf {
    idb.parent()
        .expect("generation")
        .join("dsc-inputs/dyld_shared_cache_arm64e")
}
#[tokio::test]
async fn different_module_generations_share_one_read_only_member_inode() {
    let fixture = Fixture::new().await;
    let first = fixture.open("/usr/lib/a.dylib").await;
    let second = fixture.open("/usr/lib/b.dylib").await;
    assert_ne!(
        first, second,
        "module selections retain distinct generation identities"
    );
    let a = std::fs::metadata(member(&first)).expect("first input");
    let b = std::fs::metadata(member(&second)).expect("second input");
    if let Some(destination) = std::env::var_os("N7BF_MEMBER_USAGE") {
        let mut seen = std::collections::HashSet::new();
        let mut unique = 0;
        let mut logical = 0;
        for idb in [&first, &second] {
            for entry in std::fs::read_dir(idb.parent().expect("generation").join("dsc-inputs"))
                .expect("generation bundle")
            {
                let meta = entry
                    .expect("bundle member")
                    .metadata()
                    .expect("bundle metadata");
                logical += meta.len();
                if seen.insert((meta.dev(), meta.ino())) {
                    unique += meta.len();
                }
            }
        }
        std::fs::write(destination,serde_json::to_vec_pretty(&serde_json::json!({"modules":2,"logical_generation_member_bytes":logical,"unique_member_bytes":unique,"private_mode":a.mode()&0o777,"primary_nlink":a.nlink()})).expect("storage evidence JSON")).expect("persist functional disk evidence");
    }
    assert_eq!(
        (a.dev(), a.ino()),
        (b.dev(), b.ino()),
        "one content store, not a byte copy for each module"
    );
    assert_eq!(a.mode() & 0o777, 0o400, "immutable private member");
    assert!(
        a.nlink() >= 3,
        "content store plus both generation references"
    );
    assert_eq!(
        fixture.open("/usr/lib/a.dylib").await,
        first,
        "ordinary cache reopen"
    );
}

#[tokio::test]
async fn unregistered_sha_object_is_never_overwritten() {
    let fixture = Fixture::new().await;
    use sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(vec![1; 1024 * 1024]));
    let store = fixture.root.join("cache/dsc-members");
    std::fs::create_dir_all(&store).expect("private store fixture");
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700))
        .expect("private store mode");
    let unknown = store.join(&digest);
    std::fs::write(&unknown, b"unknown file to preserve").expect("foreign object fixture");
    let config = DscInput {
        arch: "arm64e".into(),
        module: "/usr/lib/a.dylib".into(),
        frameworks: vec![],
        ida_version: 9,
        log_path: None,
    };
    assert!(special::prepare(
        fixture.root.join("source/dyld_shared_cache_arm64e"),
        fixture.root.join("cache"),
        config,
        &Preparation::new(Duration::from_secs(20))
    )
    .await
    .is_err());
    assert_eq!(
        std::fs::read(unknown).expect("preserved unknown object"),
        b"unknown file to preserve"
    );
}
