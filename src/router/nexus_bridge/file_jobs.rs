//! Bounded process/FD supervision only. The sole file executor and directional
//! authority journal remain in the verified Python recovery modules.
use super::recovery_guard::ReceivedTransfer;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixDatagram as StdDatagram;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::net::UnixDatagram;
use tokio::process::{Child, Command};
use tokio::sync::OwnedSemaphorePermit;

struct Endpoint {
    socket: StdDatagram,
    path: PathBuf,
    identity: (u64, u64),
}

struct Diagnostics {
    file: std::fs::File,
    path: PathBuf,
}
impl Diagnostics {
    fn tail(&self) -> String {
        let result = (|| -> std::io::Result<String> {
            let length = self.file.metadata()?.len();
            let offset = length.saturating_sub(16 * 1024);
            let mut bytes =
                vec![0; usize::try_from(length - offset).map_err(std::io::Error::other)?];
            let count = self.file.read_at(&mut bytes, offset)?;
            bytes.truncate(count);
            Ok(format!(
                "{}{}",
                if offset > 0 {
                    "[stderr tail truncated] "
                } else {
                    ""
                },
                String::from_utf8_lossy(&bytes)
            ))
        })();
        match result {
            Ok(value) => value,
            Err(error) => format!(
                "stderr read failed independently: {error}; path={}",
                self.path.display()
            ),
        }
    }
}
impl AsRawFd for Endpoint {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        let result = (|| -> anyhow::Result<()> {
            let metadata = std::fs::symlink_metadata(&self.path)?;
            anyhow::ensure!(
                metadata.file_type().is_socket()
                    && (metadata.dev(), metadata.ino()) == self.identity,
                "file-job endpoint replaced; unlink refused"
            );
            std::fs::remove_file(&self.path)?;
            Ok(())
        })();
        if let Err(error) = result {
            tracing::error!(%error, path=%self.path.display(), "file-job endpoint cleanup refused");
        }
    }
}

pub(super) async fn prepare(
    python: PathBuf,
    installation: PathBuf,
    environment: BTreeMap<String, String>,
    permit: OwnedSemaphorePermit,
    request: Value,
) -> anyhow::Result<Value> {
    let root = installation
        .parent()
        .ok_or_else(|| anyhow::anyhow!("file-job installation root"))?
        .canonicalize()?;
    let nonce = request["job_nonce"]
        .as_str()
        .filter(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(|| anyhow::anyhow!("invalid directional job nonce"))?;
    let recovery = request["recovery_id"]
        .as_str()
        .filter(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(|| anyhow::anyhow!("invalid exact RecoveryId"))?;
    anyhow::ensure!(
        request["epoch"].as_u64().is_some_and(|e| e > 0),
        "invalid file executor epoch"
    );
    let reply = PathBuf::from(
        request["reply_endpoint"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("file-job reply path"))?,
    );
    anyhow::ensure!(
        reply.parent() == Some(root.as_path())
            && reply
                .file_name()
                .is_some_and(|n| n == format!("j{}s", &nonce[..12]).as_str()),
        "file-job reply outside fixed private bridge directory"
    );
    let source = std::fs::symlink_metadata(&reply)?;
    // SAFETY: getuid has no memory preconditions.
    let uid = unsafe { libc::getuid() };
    anyhow::ensure!(
        source.file_type().is_socket()
            && source.uid() == uid
            && source.permissions().mode() & 0o777 == 0o600
            && request["reply_identity"] == json!([source.dev(), source.ino()]),
        "file-job reply socket identity changed"
    );
    let path = root.join(format!("j{}r", &nonce[..12]));
    let socket = StdDatagram::bind(&path)?;
    let metadata = std::fs::symlink_metadata(&path)?;
    let endpoint = Endpoint {
        socket,
        path,
        identity: (metadata.dev(), metadata.ino()),
    };
    std::fs::set_permissions(&endpoint.path, std::fs::Permissions::from_mode(0o600))?;
    endpoint.socket.connect(&reply)?;
    anyhow::ensure!(
        {
            let m = std::fs::symlink_metadata(&reply)?;
            (m.dev(), m.ino()) == (source.dev(), source.ino())
        },
        "file-job source replaced during connect"
    );
    endpoint.socket.set_nonblocking(true)?;
    let endpoint = AsyncFd::new(endpoint)?;
    let (parent, child_channel) = StdDatagram::pair()?;
    parent.set_nonblocking(true)?;
    let parent = UnixDatagram::from_std(parent)?;
    let child_fd = child_channel.as_raw_fd();
    let log_path = root.join(format!("j{}-stderr.log", &nonce[..12]));
    let log = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&log_path)?;
    let diagnostics = Diagnostics {
        file: log,
        path: log_path,
    };
    let mut command = Command::new(python);
    command.arg("-I").arg("-B");
    super::python_ledger(&mut command);
    #[cfg(feature = "nexus-test-support")]
    if environment.contains_key("R4_FILE_JOB_FAULT") {
        command.arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r4_file_job_faults.py"),
        );
    }
    #[cfg(feature = "nexus-test-support")]
    if environment.contains_key("R2_BOOT_SOURCE_INPUT") {
        command.arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r2_boot_writer.py"),
        );
    }
    command
        .arg(installation.join("bootstrap.py"))
        .arg("recovery_job")
        .arg(child_fd.to_string())
        .arg(
            request["target"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("file target"))?,
        )
        .arg(recovery)
        .env_clear()
        .envs(&environment)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(diagnostics.file.try_clone()?))
        .kill_on_drop(false);
    // SAFETY: only async-signal-safe setsid/fcntl run between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 || libc::fcntl(child_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = super::spawn_child(&mut command)?;
    drop(child_channel);
    let readiness = message(&parent, &mut child, Duration::from_secs(2), &diagnostics).await;
    let hello = match readiness {
        Ok(value) => value,
        Err(error) => {
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = child.wait().await {
                    tracing::error!(%error,"file-job failed-start reap unconfirmed");
                }
            });
            return Err(error);
        }
    };
    if hello["actor"]["native"]["pid"].as_u64() != child.id().map(u64::from)
        || hello["recovery_id"] != request["recovery_id"]
        || hello["target"] != request["target"]
        || hello["coord_key"] != request["coord_key"]
        || hello["directory"] != request["directory"]
        || hello["root_binding"] != request["root_binding"]
    {
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = child.wait().await {
                tracing::error!(%error,"file-job rejected-start reap unconfirmed");
            }
        });
        anyhow::bail!("file-job prepared receiver physical identity mismatch");
    }
    let response = json!({"hello":hello,"endpoint":endpoint.get_ref().path,
        "stderr":diagnostics.path,
        "endpoint_identity":[endpoint.get_ref().identity.0,endpoint.get_ref().identity.1]});
    tokio::spawn(async move {
        let _permit = permit;
        let result = supervise(
            &endpoint,
            &parent,
            &mut child,
            &request,
            &hello,
            &diagnostics,
        )
        .await;
        if let Err(error) = &result {
            tracing::error!(%error, recovery_id=%request["recovery_id"], "file-job relay uncertain; target journal retains authority");
            let reply = json!({"transfer_id":null,"job_nonce":request["job_nonce"],
                "error":format!("HandoffUncertain: {error}"),"status":null});
            match serde_json::to_vec(&reply) {
                Ok(bytes) => {
                    if let Err(error) = endpoint.get_ref().socket.send(&bytes) {
                        tracing::error!(%error, "file-job error delivery failed independently");
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "file-job error serialization failed independently")
                }
            }
        }
        // Never signal or cancel an accepted child. Its file intents survive
        // bridge/router EOF; waiting here merely reaps the original process.
        if let Err(error) = child.wait().await {
            tracing::error!(%error, "file-job process reap unconfirmed");
        }
    });
    Ok(response)
}

async fn receive(endpoint: &AsyncFd<Endpoint>) -> anyhow::Result<ReceivedTransfer> {
    loop {
        let mut ready = endpoint.readable().await?;
        match ready.try_io(|inner| ReceivedTransfer::receive(&inner.get_ref().socket)) {
            Ok(result) => return Ok(result?),
            Err(_) => continue,
        }
    }
}

async fn message(
    channel: &UnixDatagram,
    child: &mut Child,
    budget: Duration,
    diagnostics: &Diagnostics,
) -> anyhow::Result<Value> {
    let mut bytes = vec![0u8; 64 * 1024];
    tokio::select! {
        biased;
        result = tokio::time::timeout(budget, channel.recv(&mut bytes)) => {
            let length = result??;
            Ok(serde_json::from_slice(&bytes[..length])?)
        }
        exit = child.wait() => anyhow::bail!("file-job child exited before message: {:?}; stderr={}; {}",
            exit?,diagnostics.path.display(),diagnostics.tail()),
    }
}

async fn supervise(
    endpoint: &AsyncFd<Endpoint>,
    channel: &UnixDatagram,
    child: &mut Child,
    request: &Value,
    hello: &Value,
    diagnostics: &Diagnostics,
) -> anyhow::Result<()> {
    let received = tokio::select! {
        biased;
        value = tokio::time::timeout(Duration::from_secs(8), receive(endpoint)) => value??,
        exit = child.wait() => anyhow::bail!("file-job receiver ended before rights: {:?}; stderr={}; {}",
            exit?,diagnostics.path.display(),diagnostics.tail()),
    };
    let binding: Value = serde_json::from_slice(received.payload())?;
    anyhow::ensure!(
        binding["receiver"] == hello["actor"]
            && binding["epoch"] == request["epoch"]
            && binding["recovery_id"] == request["recovery_id"]
            && binding["coord_key"] == request["coord_key"],
        "file-job directional rights binding mismatch"
    );
    received.relay(channel)?;
    drop(received); // Close surplus relay references BEFORE the receiver executes files.
    let first = message(channel, child, Duration::from_secs(8), diagnostics).await?;
    let completed = if first["accepted"] == true {
        anyhow::ensure!(
            first["transfer_id"] == binding["transfer_id"],
            "file-job acceptance identity mismatch"
        );
        message(channel, child, Duration::from_secs(600), diagnostics).await?
    } else {
        // Lost ACK is not loss of execution authority. This exact receiver's
        // completed/blocked record may arrive first; it attests durable Accepted
        // in the file domain and never synthesizes a Nexus detach ACK.
        anyhow::ensure!(
            first["status"]["job_id"] == request["recovery_id"]
                && first["status"]["executor"]["state"] == "Accepted"
                && first["status"]["executor"]["actor"] == hello["actor"]
                && first["status"]["executor"]["epoch"] == request["epoch"]
                && first["status"]["executor"]["transfer_id"] == binding,
            "file-job completion lacks exact durable Accepted identity"
        );
        first
    };
    anyhow::ensure!(
        completed["transfer_id"] == binding["transfer_id"],
        "file-job completion identity mismatch"
    );
    endpoint
        .get_ref()
        .socket
        .send(&serde_json::to_vec(&completed)?)?;
    Ok(())
}
