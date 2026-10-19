//! One independent observer per fixed state root in this router domain.
use super::BridgeConfig;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

pub(super) struct Helper {
    pub endpoint: PathBuf,
    pub incarnation: String,
    pub state_root: Value,
    child: Mutex<Child>,
    python: PathBuf,
    installation: PathBuf,
    environment: std::collections::BTreeMap<String, String>,
    restarts: std::sync::atomic::AtomicUsize,
    last_heartbeat: std::sync::Mutex<Value>,
    calls: Mutex<()>,
    finished: std::sync::atomic::AtomicBool,
    file_job_slots: Arc<tokio::sync::Semaphore>,
}
impl Helper {
    pub async fn start(
        config: &mut BridgeConfig,
        installation: &Path,
    ) -> anyhow::Result<Arc<Self>> {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(not(feature = "nexus-test-support"))]
        config.environment.remove("IDA_CLI_HELPER_TEST_CLOCK");
        let explicit = config
            .environment
            .get("IDA_NEXUS_STATE_DIR")
            .filter(|s| !s.is_empty());
        let state = if let Some(path) = explicit {
            PathBuf::from(path)
        } else {
            let idausr = config
                .environment
                .get("IDAUSR")
                .and_then(|s| s.split(':').next())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            if let Some(path) = idausr {
                PathBuf::from(path).join("nexus")
            } else {
                PathBuf::from(
                    config
                        .environment
                        .get("HOME")
                        .ok_or_else(|| anyhow::anyhow!("Nexus default state root requires HOME"))?,
                )
                .join(".idapro/nexus")
            }
        };
        let state = if let Some(suffix) = state.to_str().and_then(|p| p.strip_prefix("~/")) {
            PathBuf::from(
                config
                    .environment
                    .get("HOME")
                    .ok_or_else(|| anyhow::anyhow!("state root expansion requires HOME"))?,
            )
            .join(suffix)
        } else {
            state
        };
        let state = std::env::current_dir()?.join(state);
        std::fs::create_dir_all(&state)?;
        let state = state.canonicalize()?;
        config.environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            state.to_string_lossy().into_owned(),
        );
        let incarnation = format!(
            "{}-{}",
            std::process::id(),
            super::super::nexus_transport::monotonic_ns()?
        );
        let endpoint = config.directory.join("h");
        let log = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(config.directory.join("helper.log"))?;
        let mut command = Command::new(&config.python);
        command.arg("-I").arg("-B");
        super::python_ledger(&mut command);
        #[cfg(feature = "nexus-test-support")]
        if config.environment.contains_key("R2_BOOT_SOURCE_INPUT") {
            command
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/r2_boot_writer.py"));
        }
        command
            .arg(installation.join("bootstrap.py"))
            .arg("proof_helper")
            .arg(&endpoint)
            .arg(&incarnation)
            .arg(
                config
                    .environment
                    .get("IDA_CLI_HELPER_CAPACITY")
                    .map(String::as_str)
                    .unwrap_or("256"),
            )
            .env_clear()
            .envs(&config.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        // SAFETY: after fork only the async-signal-safe setsid syscall is used;
        // no allocation, locks or Rust runtime state is accessed in the child.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = super::spawn_child(&mut command)?;
        let mut helper = Self {
            endpoint,
            incarnation,
            state_root: Value::Null,
            child: Mutex::new(child),
            python: config.python.clone(),
            installation: installation.into(),
            environment: config.environment.clone(),
            restarts: std::sync::atomic::AtomicUsize::new(0),
            last_heartbeat: std::sync::Mutex::new(Value::Null),
            calls: Mutex::new(()),
            finished: std::sync::atomic::AtomicBool::new(false),
            file_job_slots: Arc::new(tokio::sync::Semaphore::new(8)),
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match helper
                .call(json!({"kind":"heartbeat", "summary_only":true}))
                .await
            {
                Ok(reply) => {
                    helper.state_root = reply["state_root"].clone();
                    break;
                }
                Err(error) => {
                    if helper.child.lock().await.try_wait()?.is_some() {
                        anyhow::bail!("helper exited before readiness: {error}");
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(error);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        }
        anyhow::ensure!(
            helper.state_root["path"].as_str() == state.to_str(),
            "ProtocolMismatch: helper state root"
        );
        config.environment.insert(
            "IDA_CLI_PROOF_ENDPOINT".into(),
            helper.endpoint.to_string_lossy().into_owned(),
        );
        config.environment.insert(
            "IDA_CLI_PROOF_INCARNATION".into(),
            helper.incarnation.clone(),
        );
        Ok(Arc::new(helper))
    }

    pub async fn call(&self, value: Value) -> anyhow::Result<Value> {
        let _call = tokio::time::timeout(Duration::from_secs(2), self.calls.lock()).await?;
        anyhow::ensure!(
            !self.finished.load(std::sync::atomic::Ordering::Acquire),
            "ObservationClosed: helper has finished; reconnect is forbidden"
        );
        self.exchange(value).await
    }

    async fn exchange(&self, mut value: Value) -> anyhow::Result<Value> {
        self.reconnect().await?;
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments or memory safety preconditions.
        let uid = unsafe { libc::geteuid() };
        value["helper"] = json!(self.incarnation);
        value["protocol"] = json!(2);
        let data = serde_json::to_vec(&value)?;
        anyhow::ensure!(data.len() < 65536, "helper request capacity exceeded");
        let exchange = async {
            // Only retry before connecting/writing any request byte. The exact
            // reaped child's replacement must actually bind before readiness.
            let (mut stream, before) = loop {
                let before = match std::fs::symlink_metadata(&self.endpoint) {
                    Ok(before) => before,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if self.child.lock().await.try_wait()?.is_some() {
                            return Err(error.into());
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                anyhow::ensure!(
                    before.file_type().is_socket()
                        && before.uid() == uid
                        && before.permissions().mode() & 0o777 == 0o600,
                    "untrusted helper endpoint"
                );
                match UnixStream::connect(&self.endpoint).await {
                    Ok(stream) => break (stream, before),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                        ) =>
                    {
                        if self.child.lock().await.try_wait()?.is_some() {
                            return Err(error.into());
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            let after = std::fs::symlink_metadata(&self.endpoint)?;
            anyhow::ensure!(
                after.dev() == before.dev()
                    && after.ino() == before.ino()
                    && stream.peer_cred()?.uid() == uid,
                "helper endpoint replaced during connection"
            );
            stream.write_all(&data).await?;
            stream.write_all(b"\n").await?;
            let mut reader = BufReader::new(stream);
            let line = super::receiver::read_line(&mut reader)
                .await?
                .ok_or_else(|| anyhow::anyhow!("helper EOF"))?;
            let response: Value = serde_json::from_slice(&line)?;
            anyhow::ensure!(
                response["protocol"] == 2 && response["helper"] == self.incarnation,
                "ProtocolMismatch: helper reply"
            );
            anyhow::ensure!(response["ok"] == true, "helper: {}", response["error"]);
            Ok::<_, anyhow::Error>(response)
        };
        let result = tokio::time::timeout(Duration::from_secs(2), exchange)
            .await
            .map_err(anyhow::Error::from)
            .and_then(|reply| reply);
        if value["kind"] == "heartbeat" {
            *self
                .last_heartbeat
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = match &result {
                Ok(reply) => {
                    json!({"snapshot":reply,"observed_monotonic_ns":super::super::nexus_transport::monotonic_ns().ok()})
                }
                Err(error) => json!({"error":error.to_string(),"observation":"blocked"}),
            };
        }
        result
    }

    pub fn status_snapshot(&self) -> Value {
        let mut status = self
            .last_heartbeat
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        status["file_job_capacity"] = json!(8);
        status["file_jobs_pending"] = json!(8 - self.file_job_slots.available_permits());
        status
    }

    fn finish_accepted(&self) -> anyhow::Result<bool> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let path = self.endpoint.with_file_name("helper-state.json");
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        #[cfg(all(test, feature = "nexus-test-support"))]
        tests::after_registry_open();
        let before = file.metadata()?;
        // SAFETY: geteuid has no arguments or memory preconditions.
        let uid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            before.is_file()
                && before.uid() == uid
                && before.nlink() == 1
                && before.permissions().mode() & 0o777 == 0o600
                && before.len() <= 1024 * 1024,
            "ObservationRecoveryBlocked: untrusted helper registry"
        );
        let mut data = Vec::new();
        (&mut file).take(1024 * 1024 + 1).read_to_end(&mut data)?;
        let after = file.metadata()?;
        let current = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.len() == after.len()
                && before.len() == data.len() as u64
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec()
                && before.ino() == current.ino()
                && before.dev() == current.dev(),
            "ObservationRecoveryBlocked: helper registry changed"
        );
        let saved: Value = serde_json::from_slice(&data)?;
        anyhow::ensure!(
            saved["schema"] == 1
                && saved["helper"] == self.incarnation
                && (self.state_root.is_null() || saved["state_root"] == self.state_root),
            "ObservationRecoveryBlocked: helper finish identity mismatch"
        );
        if saved["finishing"] != true {
            return Ok(false);
        }
        anyhow::ensure!(
            saved["items"].as_object().is_some_and(|m| m.is_empty())
                && saved["parents"].as_object().is_some_and(|m| m.is_empty()),
            "ObservationRecoveryBlocked: finish still has responsibility"
        );
        Ok(true)
    }

    async fn reconnect(&self) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut child = self.child.lock().await;
        let Some(status) = child.try_wait()? else {
            // The live helper owns a mutable registry and enforces its own
            // durable finishing fence. Inspect a finish tombstone only after
            // this exact writer has exited, before any possible restart.
            return Ok(());
        };
        if self.finish_accepted()? {
            self.finished
                .store(true, std::sync::atomic::Ordering::Release);
            anyhow::bail!("ObservationClosed: durable helper finish forbids reconnect");
        }
        let count = self.restarts.load(std::sync::atomic::Ordering::Acquire);
        anyhow::ensure!(count < 3, "ObservationRecoveryBlocked: helper restart budget exhausted; durable obligations retained");
        tracing::warn!(%status, restart=count + 1, root=?self.state_root,
            "independent proof helper failed; recovering exact durable watches");
        let log = std::fs::OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.endpoint.with_file_name("helper.log"))?;
        let mut command = Command::new(&self.python);
        command.arg("-I").arg("-B");
        super::python_ledger(&mut command);
        #[cfg(feature = "nexus-test-support")]
        if self.environment.contains_key("R2_BOOT_SOURCE_INPUT") {
            command
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/r2_boot_writer.py"));
        }
        command
            .arg(self.installation.join("bootstrap.py"))
            .arg("proof_helper")
            .arg(&self.endpoint)
            .arg(&self.incarnation)
            .arg(
                self.environment
                    .get("IDA_CLI_HELPER_CAPACITY")
                    .map(String::as_str)
                    .unwrap_or("256"),
            )
            .env_clear()
            .envs(&self.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        // SAFETY: setsid is async-signal-safe and touches no Rust state.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        *child = super::spawn_child(&mut command)?;
        self.restarts
            .store(count + 1, std::sync::atomic::Ordering::Release);
        // Readiness is retried by the bounded proof pump. No absence, process
        // exit or recovered registry entry is interpreted as a lifetime proof.
        Ok(())
    }

    /// A separate target writer takes root SH then target EX. Neither helper
    /// observers nor the N1 short lock wait on that writer's IPC/filesystem I/O.
    pub async fn journal(&self, value: Value) -> anyhow::Result<Value> {
        let mut command = Command::new(&self.python);
        command.arg("-I").arg("-B");
        super::python_ledger(&mut command);
        #[cfg(feature = "nexus-test-support")]
        if self.environment.contains_key("R2_BOOT_SOURCE_INPUT") {
            command
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/r2_boot_writer.py"));
        }
        let mut child = super::spawn_child(
            command
                .arg(self.installation.join("bootstrap.py"))
                .arg("target_journal")
                .env_clear()
                .envs(&self.environment)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true),
        )?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("target writer stdin missing"))?;
        input.write_all(&serde_json::to_vec(&value)?).await?;
        input.write_all(b"\n").await?;
        drop(input);
        let output =
            tokio::time::timeout(Duration::from_secs(2), child.wait_with_output()).await??;
        anyhow::ensure!(
            output.status.success(),
            "target journal: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Value = serde_json::from_slice(&output.stdout)?;
        anyhow::ensure!(response["ok"] == true, "target writer rejected custody");
        Ok(response)
    }

    pub async fn prepare_file_job(&self, request: Value) -> anyhow::Result<Value> {
        let permit = self
            .file_job_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                anyhow::anyhow!(
                    "Busy: file-job supervisors full; existing file obligations retained"
                )
            })?;
        super::file_jobs::prepare(
            self.python.clone(),
            self.installation.clone(),
            self.environment.clone(),
            permit,
            request,
        )
        .await
    }

    pub async fn finish(&self) -> anyhow::Result<()> {
        let _call = tokio::time::timeout(Duration::from_secs(2), self.calls.lock()).await?;
        if self.finished.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        if let Err(error) = self.exchange(json!({"kind":"finish"})).await {
            if !self.finish_accepted()? {
                return Err(error);
            }
            tracing::warn!(%error, "helper finish reply lost; exact durable acceptance recovered");
        }
        // Serialize against every heartbeat/custody request. Once finish was
        // accepted, a late caller must not turn the clean exit into recovery.
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        let status =
            tokio::time::timeout(Duration::from_secs(2), self.child.lock().await.wait()).await??;
        anyhow::ensure!(status.success(), "helper did not exit cleanly");
        Ok(())
    }

    #[cfg(feature = "nexus-test-support")]
    pub async fn wait_injected_orphan(&self) -> anyhow::Result<Value> {
        let _call = tokio::time::timeout(Duration::from_secs(2), self.calls.lock()).await?;
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        let mut child = self.child.lock().await;
        let pid = child.id();
        let status = tokio::time::timeout(Duration::from_secs(3), child.wait()).await??;
        anyhow::ensure!(
            status.success(),
            "injected orphan helper did not exit naturally"
        );
        Ok(json!({"pid":pid,"exit":status.to_string(),"forced":false}))
    }

    #[cfg(feature = "nexus-test-support")]
    pub async fn inject_pause(&self) -> anyhow::Result<Value> {
        let mut child = self.child.lock().await;
        anyhow::ensure!(child.try_wait()?.is_none(), "own helper already exited");
        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("own helper PID missing"))?;
        // SAFETY: the unreaped live Child owns this PID; no process-name scan.
        if unsafe { libc::kill(pid.try_into()?, libc::SIGSTOP) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(json!({"pid":pid,"injected_signal":"SIGSTOP"}))
    }

    #[cfg(feature = "nexus-test-support")]
    pub async fn inject_crash(&self) -> anyhow::Result<Value> {
        let mut child = self.child.lock().await;
        let pid = child.id();
        if let Some(status) = child.try_wait()? {
            return Ok(json!({"pid":pid,"already_exited":status.to_string()}));
        }
        child.kill().await?;
        let status = child.wait().await?;
        Ok(json!({"pid":pid,"injected_signal":"SIGKILL","status":status.to_string()}))
    }
}

#[cfg(all(test, feature = "nexus-test-support"))]
mod tests {
    use super::*;
    use tokio::io::AsyncBufReadExt;

    thread_local! {
        static REGISTRY_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            std::cell::RefCell::new(None);
    }

    pub(super) fn after_registry_open() {
        let hook = REGISTRY_OPEN_HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }

    fn raw_parent_request(endpoint: &Path, incarnation: &str, kind: &str) -> Value {
        use std::io::{BufRead, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(endpoint)
            .expect("independent real helper connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bounded helper response");
        let bytes = serde_json::to_vec(&json!({"protocol":2,"helper":incarnation,
            "kind":kind,"parent":"registry-read-boundary"}))
        .expect("production control frame");
        stream.write_all(&bytes).expect("write real helper control");
        stream.write_all(b"\n").expect("complete helper frame");
        let mut reply = String::new();
        std::io::BufReader::new(stream)
            .read_line(&mut reply)
            .expect("actual helper reply");
        let reply: Value = serde_json::from_str(&reply).expect("actual helper response JSON");
        assert_eq!(
            reply["ok"], true,
            "producer must actually persist its new registry"
        );
        reply
    }

    #[tokio::test]
    async fn live_helper_rpc_never_reads_a_mutable_finish_inode() {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private case"))
            .join("live-registry-boundary");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("private helper root");
        let installation = root.join("installation");
        crate::router::nexus_bridge::installation::create(&installation)
            .expect("closed installation");
        let mut config = BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK interpreter")),
            script: installation.join("bridge.py"),
            directory: root.clone(),
            environment: std::env::vars().collect(),
        };
        config.environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.join("state").display().to_string(),
        );
        let helper = Helper::start(&mut config, &installation)
            .await
            .expect("actual independent helper");
        let initial = helper
            .call(json!({"kind":"heartbeat"}))
            .await
            .expect("helper ready");
        let endpoint = helper.endpoint.clone();
        let incarnation = helper.incarnation.clone();
        let registry = root.join("helper-state.json");
        let before = std::fs::metadata(&registry)
            .expect("initial registry inode")
            .ino();
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = fired.clone();
        REGISTRY_OPEN_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                raw_parent_request(&endpoint, &incarnation, "reserve_parent");
                observed.store(true, std::sync::atomic::Ordering::Release);
            }))
        });
        let heartbeat = helper.call(json!({"kind":"heartbeat"})).await;
        REGISTRY_OPEN_HOOK.with(|slot| {
            slot.borrow_mut().take();
        });
        // Retire only the exact test reservation. Always naturally finish the
        // helper before the decisive assertion, including the frozen red.
        raw_parent_request(&helper.endpoint, &helper.incarnation, "retire_parent");
        let stopped = helper.finish().await;
        std::fs::write(root.join("registry-boundary.json"),serde_json::to_vec_pretty(&json!({
            "initial":initial,"heartbeat":heartbeat.as_ref().ok(),
            "error":heartbeat.as_ref().err().map(ToString::to_string),
            "publication_between_open_and_metadata":fired.load(std::sync::atomic::Ordering::Acquire),
            "before_inode":before,"after_inode":std::fs::metadata(&registry).expect("final registry").ino(),
            "shutdown":format!("{stopped:?}"),"forced":false,
            "scope":"actual Rust/helper writer; no owner or public-proof fixture"})).expect("encode evidence"))
            .expect("write boundary evidence before assertion");
        stopped.expect("helper naturally finishes even for the baseline red");
        heartbeat.expect("a live helper RPC must not interpret a retired finish-record inode");
        assert_eq!(
            helper.restarts.load(std::sync::atomic::Ordering::Acquire),
            0
        );
    }

    #[tokio::test]
    async fn accepted_finish_lost_ipc_reply_is_durably_fenced() {
        use std::os::unix::fs::DirBuilderExt;
        let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("isolated case root"))
            .join(format!(
                "finish-{}",
                crate::router::nexus_transport::monotonic_ns().expect("monotonic nonce")
            ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("private helper case");
        let installation = root.as_path().join("installation");
        crate::router::nexus_bridge::installation::create(&installation)
            .expect("current closed source installation");
        let mut config = BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("fixed SDK interpreter")),
            script: installation.join("bridge.py"),
            directory: root.as_path().into(),
            environment: std::env::vars().collect(),
        };
        config.environment.insert(
            "IDA_NEXUS_STATE_DIR".into(),
            root.as_path().join("state").display().to_string(),
        );
        let mut helper = Helper::start(&mut config, &installation)
            .await
            .expect("real independent helper");
        let initial = helper
            .call(json!({"kind":"heartbeat"}))
            .await
            .expect("initial precise helper birth");
        std::fs::write(
            root.join("q2-initial.json"),
            serde_json::to_vec_pretty(&initial).expect("helper identity JSON"),
        )
        .expect("initial precise birth evidence");
        helper
            .call(json!({"kind":"reserve_parent", "parent":"pending"}))
            .await
            .expect("exact pending responsibility");
        assert!(helper.finish().await.is_err(), "pending finish must reject");
        assert_eq!(
            helper
                .call(json!({"kind":"heartbeat"}))
                .await
                .expect("rejected finish must not fence")["parent_count"],
            1
        );
        helper
            .call(json!({"kind":"retire_parent", "parent":"pending"}))
            .await
            .expect("retire exact parent");
        let actual = helper.endpoint.clone();
        let proxy = root.as_path().join("p");
        let listener =
            tokio::net::UnixListener::bind(&proxy).expect("private real IPC fault relay");
        std::fs::set_permissions(&proxy, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("private relay mode");
        Arc::get_mut(&mut helper)
            .expect("unique helper owner")
            .endpoint = proxy.clone();
        let relay = tokio::spawn(async move {
            let (downstream, _) = listener.accept().await.expect("real finish IPC");
            let mut reader = BufReader::new(downstream);
            let mut request = Vec::new();
            reader
                .read_until(b'\n', &mut request)
                .await
                .expect("read exact request");
            assert_eq!(
                serde_json::from_slice::<Value>(&request).expect("finish request")["kind"],
                "finish"
            );
            let mut upstream = UnixStream::connect(&actual)
                .await
                .expect("actual helper connection");
            upstream
                .write_all(&request)
                .await
                .expect("forward actual finish");
            let mut reader_up = BufReader::new(upstream);
            let mut reply = Vec::new();
            reader_up
                .read_until(b'\n', &mut reply)
                .await
                .expect("actual helper accepted reply");
            let accepted: Value = serde_json::from_slice(&reply).expect("real helper reply");
            assert_eq!(accepted["ok"], true, "finish was actually accepted");
            // Drop the real downstream without delivering any response byte.
            drop(reader);
            accepted
        });
        let finish_result = helper.finish().await;
        tokio::time::timeout(Duration::from_secs(2), helper.child.lock().await.wait())
            .await
            .expect("exact helper exit bound")
            .expect("exact helper exit");
        let accepted = relay.await.expect("fault relay completed");
        assert_eq!(accepted["ok"], true);
        let late = helper.call(json!({"kind":"heartbeat"})).await;
        let late_snapshot = late.as_ref().ok().cloned();
        if late.is_ok() {
            helper
                .finish()
                .await
                .expect("precise cleanup of incorrectly restarted helper");
        }
        std::fs::write(root.join("q2-lost-reply.json"), serde_json::to_vec_pretty(&json!({
            "initial":initial,"accepted_reply_not_delivered":accepted,
            "finish_error":finish_result.as_ref().err().map(ToString::to_string),
            "late_heartbeat":late_snapshot,"restarts":helper.restarts.load(std::sync::atomic::Ordering::Acquire),
            "forced":false,
        })).expect("lost reply evidence JSON")).expect("lost reply evidence");
        finish_result.expect("recover exact durable acceptance despite lost response");
        assert!(late.is_err(), "late heartbeat recreated empty helper");
        let registry = root.as_path().join("helper-state.json");
        let bytes = std::fs::read(&registry).expect("durable helper finish");
        let saved: Value = serde_json::from_slice(&bytes).expect("registry JSON");
        assert_eq!(saved["finishing"], true);
        assert!(
            helper.call(json!({"kind":"heartbeat"})).await.is_err(),
            "late heartbeat revived helper"
        );
        assert_eq!(
            std::fs::read(&registry).expect("unchanged finish tombstone"),
            bytes
        );
        assert_eq!(
            helper.restarts.load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert!(
            !root.as_path().join("h").exists(),
            "accepted helper has not exited"
        );
        // A restarted observer independently honors the same durable tombstone.
        let mut restart = Command::new(&config.python);
        restart.arg("-I").arg("-B");
        crate::router::nexus_bridge::python_ledger(&mut restart);
        restart
            .arg(installation.join("bootstrap.py"))
            .arg("proof_helper")
            .arg(root.as_path().join("h"))
            .arg(&helper.incarnation)
            .arg("256")
            .env_clear()
            .envs(&config.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = crate::router::nexus_bridge::spawn_child(&mut restart)
            .expect("register and spawn exact finished observer");
        let status = tokio::time::timeout(Duration::from_secs(2), child.wait_with_output())
            .await
            .expect("bounded restart")
            .expect("restart exact finished observer");
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        assert!(
            !root.as_path().join("h").exists(),
            "restarted helper recreated endpoint"
        );
        std::fs::write(root.join("q2-evidence.json"), serde_json::to_vec_pretty(&json!({
            "initial":initial,"accepted_reply_not_delivered":accepted,"durable_finish":saved,
            "late_heartbeat_rejected":true,"restart_exit":status.status.to_string(),"restarts":0,
            "forced":false,
        })).expect("finish evidence JSON")).expect("finish evidence");
        std::fs::remove_file(proxy).expect("remove only owned fault relay socket");
    }
}
