use super::*;
use crate::process_spawn::StdOutputFenced;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

pub async fn release_result(
    bridge: &super::super::nexus_bridge::NexusBridge,
    lease: &SessionLease,
) -> Result<(), ToolError> {
    super::release(bridge, lease).await
}

async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("deterministic protocol/filesystem barrier");
}
pub async fn released_waiter_retains_content_until_publication_syscall_returns() {
    if std::env::var("N7_FIX2_PROTOCOL").as_deref() != Ok("1") {
        let root = std::env::temp_dir().join(format!("n7p-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let status = std::process::Command::new("timeout")
            .arg("30s")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "released_waiter_retains_content_until_publication_syscall_returns",
                "--nocapture",
            ])
            .env("N7_FIX2_PROTOCOL", "1")
            .env("IDA_CLI_NEXUS_DEV", "1")
            .env("IDA_CLI_HOME", root.join("home"))
            .env("IDA_NEXUS_STATE_DIR", root.join("state"))
            .env("F1_ROOT", &root)
            .env("IDA_NEXUS_IPC_ROOT", root.join("ipc-root"))
            .env(
                "IDA_NEXUS_PYTHON",
                std::env::var_os("F1_PYTHON")
                    .expect("prepared F1_PYTHON required for gate 13 protocol regression"),
            )
            .status_fenced()
            .unwrap();
        assert!(status.success(), "isolated real bridge protocol regression");
        std::fs::remove_dir_all(root).unwrap();
        return;
    }
    let root = PathBuf::from(std::env::var_os("F1_ROOT").expect("short private root"));
    std::fs::create_dir_all(&root).unwrap();
    let cache = crate::idb_store::idb_root();
    std::fs::create_dir_all(&cache).unwrap();
    let fifo = cache.join(".n7-publish-fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: exclusive disposable fixture path, never a user cache.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("F1_SCENARIO".into(), "n7-open-drop".into());
    let router = RouterState::new().unwrap();
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("IDA_NEXUS_PYTHON").unwrap()),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/nexus_race_fixture.py"),
            directory: root.join("ipc"),
            environment,
        })
        .await
        .unwrap();
    let input = root.join("source");
    std::fs::write(&input, b"protocol content identity").unwrap();
    let key = crate::idb_store::IdbStore::try_compute_hash(&input).unwrap();
    let owned = router.clone();
    let path = input.clone();
    let mut task = tokio::spawn(async move {
        owned
            .ensure_worker_prepared(
                path.to_str().unwrap(),
                None,
                None,
                Preparation::new(Duration::from_secs(30)),
            )
            .await
    });
    tokio::select! {
        _ = until(|| root.join("n7-open-proof.arrived").exists()) => {},
        result = &mut task => panic!("open ended before publication barrier: {result:?}"),
    }
    let generation = std::fs::read_dir(cache.join("generations"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    // The transport fixture does not run IDA; model its packed output only.
    std::fs::write(generation.join("input.i64"), b"packed fixture").unwrap();
    std::fs::write(root.join("n7-open-proof.release"), b"").unwrap();
    let mut writer = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
            {
                Ok(file) => break file,
                Err(e) if e.raw_os_error() == Some(libc::ENXIO) => tokio::task::yield_now().await,
                Err(e) => panic!("publication syscall handshake: {e}"),
            }
        }
    })
    .await
    .unwrap();
    // At this point commit arbitration has succeeded and read(2) waits for EOF.
    task.abort();
    let cancelled = task.await.unwrap_err().is_cancelled();
    until(|| root.join("n7-release-proof.arrived").exists()).await;
    std::fs::write(root.join("n7-release-proof.release"), b"").unwrap();
    until(|| {
        router
            .nexus_tools
            .uncertain_cache
            .lock()
            .unwrap()
            .is_empty()
    })
    .await;
    // Waiting for the observer to remove retained guards proves exact Released
    // reached N1. The FIFO syscall is the sole remaining publication owner.
    let prep = Preparation::new(Duration::from_secs(10));
    let lock = super::super::nexus_bridge::cache::prepare_n7_open(
        input.clone(),
        cache.clone(),
        &prep,
        false,
    );
    tokio::pin!(lock);
    let early = tokio::time::timeout(Duration::from_millis(100), &mut lock)
        .await
        .ok();
    let waited = early.is_none();
    drop(early);
    // Always unblock the filesystem before assertions or runtime shutdown.
    writer.write_all(b"release").unwrap();
    drop(writer);
    std::fs::remove_file(&fifo).unwrap();
    let next = if waited {
        Some(lock.await.unwrap())
    } else {
        None
    };
    until(|| cache.join("nexus-index.json").is_file()).await;
    let after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cache.join("nexus-index.json")).unwrap()).unwrap();
    if let Some(next) = &next {
        assert_eq!(
            next.path,
            generation.join("input.i64"),
            "waiting opener sees committed new index"
        );
    }
    drop(next);
    bridge.shutdown().await.unwrap();
    assert!(cancelled);
    assert!(
        waited,
        "same-key opener acquired content right while committed syscall still blocked"
    );
    assert_eq!(
        after[&key],
        generation
            .join("input.i64")
            .strip_prefix(&cache)
            .unwrap()
            .to_str()
            .unwrap()
    );
    let next = super::super::nexus_bridge::cache::prepare_n7_open(
        input,
        cache.clone(),
        &Preparation::new(Duration::from_secs(10)),
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        next.path,
        generation.join("input.i64"),
        "next opener must see committed new index"
    );
}
