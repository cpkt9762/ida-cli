//! Test-only spawn evidence captured before and immediately after creation.
use serde_json::{json, Value};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(super) fn terminal(pid: Option<u32>, status: &std::process::ExitStatus, method: &str) {
    use std::os::unix::process::ExitStatusExt;
    let Some(pid) = pid else { return };
    if let Err(error) = append(&json!({"kind":"terminal","parent":std::process::id(),
        "pid":pid,"method":method,"exit_code":status.code(),"signal":status.signal(),
        "success":status.success()}))
    {
        tracing::error!(%error,"test native terminal ledger append failed");
    }
}

fn append(value: &Value) -> anyhow::Result<()> {
    let Some(path) = std::env::var_os("R2_LEDGER") else {
        return Ok(());
    };
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    let mut observed = value.clone();
    observed["observed_unix_ns"] = json!(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos());
    let mut bytes = serde_json::to_vec(&observed)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn identity(pid: u32) -> anyhow::Result<Value> {
    let mut info = [0_u64; 17];
    let mut boot = [0_u8; 64];
    let mut size = boot.len();
    // SAFETY: both buffers are aligned, writable, and have their stated size.
    // PROC_PIDTBSDINFO is the fixed 136-byte ABI with birth at offsets 120/128.
    let count = unsafe { libc::proc_pidinfo(pid as i32, 3, 0, info.as_mut_ptr().cast(), 136) };
    anyhow::ensure!(count == 136, "native process birth unavailable for {pid}");
    // SAFETY: sysctl receives a NUL-terminated name and the writable boot buffer.
    let status = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            boot.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    anyhow::ensure!(
        status == 0 && size == 37 && boot[36] == 0,
        "host boot identity unavailable"
    );
    Ok(
        json!({"kind":"macos-libproc-v1", "boot_id":std::str::from_utf8(&boot[..36])?.to_ascii_lowercase(),
        "birth":[info[15],info[16]]}),
    )
}

#[cfg(not(target_os = "macos"))]
fn identity(_pid: u32) -> anyhow::Result<Value> {
    anyhow::bail!("R2 test process ledger platform has not been validated")
}

pub(super) fn spawn(
    command: &mut tokio::process::Command,
) -> anyhow::Result<tokio::process::Child> {
    if std::env::var_os("R2_LEDGER").is_none() {
        return Ok(command.spawn()?);
    }
    let intent = format!(
        "rust-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let native = command.as_std();
    append(
        &json!({"kind":"intent", "intent":intent, "parent":std::process::id(),
        "program":native.get_program(), "argv":native.get_args().collect::<Vec<_>>()}),
    )?;
    let child = command.spawn()?;
    let evidence = match child.id() {
        Some(pid) => match identity(pid) {
            Ok(identity) => json!({"kind":"started","intent":intent,"parent":std::process::id(),
                "pid":pid,"identity":identity}),
            Err(error) => {
                json!({"kind":"capture_failed","intent":intent,"parent":std::process::id(),
                "pid":pid,"error":error.to_string()})
            }
        },
        None => json!({"kind":"capture_failed","intent":intent,"error":"new child has no PID"}),
    };
    // A bookkeeping failure after spawn must never discard the Child. The
    // harness rejects capture_failed/missing records, while normal ownership
    // still guarantees that this exact child can be waited and audited.
    if let Err(error) = append(&evidence) {
        tracing::error!(%error, "R2 process ledger failed after spawn; child custody retained");
    }
    Ok(child)
}

pub(super) fn spawn_std(
    command: &mut std::process::Command,
) -> anyhow::Result<std::process::Child> {
    if std::env::var_os("R2_LEDGER").is_none() {
        return Ok(command.spawn()?);
    }
    let intent = format!(
        "std-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    append(
        &json!({"kind":"intent","intent":intent,"parent":std::process::id(),
        "program":command.get_program(),"argv":command.get_args().collect::<Vec<_>>()}),
    )?;
    let child = command.spawn()?;
    let evidence = match identity(child.id()) {
        Ok(identity) => {
            json!({"kind":"started","intent":intent,"pid":child.id(),"identity":identity})
        }
        Err(error) => {
            json!({"kind":"capture_failed","intent":intent,"pid":child.id(),"error":error.to_string()})
        }
    };
    if let Err(error) = append(&evidence) {
        tracing::error!(%error, "R2 process ledger failed after std spawn; child custody retained");
    }
    Ok(child)
}
