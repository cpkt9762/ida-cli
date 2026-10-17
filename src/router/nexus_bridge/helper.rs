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
        command
            .arg("-I")
            .arg("-B")
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
        let child = command.spawn()?;
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

    pub async fn call(&self, mut value: Value) -> anyhow::Result<Value> {
        self.reconnect().await?;
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments or memory safety preconditions.
        let uid = unsafe { libc::geteuid() };
        value["helper"] = json!(self.incarnation);
        value["protocol"] = json!(1);
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
                response["protocol"] == 1 && response["helper"] == self.incarnation,
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
        self.last_heartbeat
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    async fn reconnect(&self) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut child = self.child.lock().await;
        let Some(status) = child.try_wait()? else {
            return Ok(());
        };
        let count = self.restarts.load(std::sync::atomic::Ordering::Acquire);
        anyhow::ensure!(count < 3, "ObservationRecoveryBlocked: helper restart budget exhausted; durable obligations retained");
        tracing::warn!(%status, restart=count + 1, root=?self.state_root,
            "independent proof helper failed; recovering exact durable watches");
        let log = std::fs::OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.endpoint.with_file_name("helper.log"))?;
        let mut command = Command::new(&self.python);
        command
            .arg("-I")
            .arg("-B")
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
        *child = command.spawn()?;
        self.restarts
            .store(count + 1, std::sync::atomic::Ordering::Release);
        // Readiness is retried by the bounded proof pump. No absence, process
        // exit or recovered registry entry is interpreted as a lifetime proof.
        Ok(())
    }

    /// A separate target writer takes root SH then target EX. Neither helper
    /// observers nor the N1 short lock wait on that writer's IPC/filesystem I/O.
    pub async fn journal(&self, value: Value) -> anyhow::Result<Value> {
        let mut child = Command::new(&self.python)
            .arg("-I")
            .arg("-B")
            .arg(self.installation.join("bootstrap.py"))
            .arg("target_journal")
            .env_clear()
            .envs(&self.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
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

    pub async fn finish(&self) -> anyhow::Result<()> {
        self.call(json!({"kind":"finish"})).await?;
        let status =
            tokio::time::timeout(Duration::from_secs(2), self.child.lock().await.wait()).await??;
        anyhow::ensure!(status.success(), "helper did not exit cleanly");
        Ok(())
    }

    #[cfg(feature = "nexus-test-support")]
    pub async fn wait_injected_orphan(&self) -> anyhow::Result<Value> {
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
