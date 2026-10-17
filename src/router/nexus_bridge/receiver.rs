//! Complete-line protocol rejection is local; framing and physical I/O are fatal.
use super::*;
use tokio::io::AsyncBufRead;

#[derive(Debug, thiserror::Error)]
#[error("bridge physical write: {0}")]
pub(super) struct EventIoError(#[from] pub std::io::Error);

#[derive(Debug)]
pub(super) enum ReceiveOutcome {
    Accepted,
    Dropped(String),
    /// Python still owns this exact handle. No custody/Released is synthesized.
    ResourceRetained(String),
}

pub(super) async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let bytes = reader.fill_buf().await?;
        if bytes.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "partial bridge frame",
                ))
            };
        }
        let count = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |n| n + 1);
        if line.len() + count > super::super::transport::MAX_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bridge frame exceeds 16 MiB",
            ));
        }
        line.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if line.last() == Some(&b'\n') {
            return Ok(Some(line));
        }
    }
}

pub(super) fn rejected(state: &State, event: Option<&Value>, reason: String) -> ReceiveOutcome {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1);
    if count.is_power_of_two() {
        tracing::warn!(count, %reason, "Nexus event rejected; shared connection retained");
    }
    let resource = event
        .filter(|e| e["event"] != "disconnected")
        .and_then(|e| e.get("lease"))
        .cloned()
        .and_then(|lease| serde_json::from_value::<SessionLease>(lease).ok())
        .filter(|lease| {
            state
                .leases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&lease.lease_id)
                != Some(lease)
        });
    if let Some(lease) = &resource {
        let mut retained = state
            .rejected_acquisitions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // No eviction: a malformed resource never authorizes a new acquisition.
        // The physical bridge retains handles; this bounded table is the R5
        // protocol-error boundary, not a custody grant or release proof.
        // Saturation never clears the acquisition block; the rejection event
        // carries every exact identity, including entries beyond this table.
        if retained.len() < state.open_reply_capacity {
            retained.insert(lease.clone());
        }
    }
    let resource = resource.is_some();
    state.emit(
        json!({"event":"event_rejected", "received_event":event.and_then(|e| e["event"].as_str()),
        "attempt":event.and_then(|e| e.get("attempt")), "lease":event.and_then(|e| e.get("lease")),
        "reason":reason, "resource_retained_by_bridge":resource}),
    );
    if resource {
        ReceiveOutcome::ResourceRetained(reason)
    } else {
        ReceiveOutcome::Dropped(reason)
    }
}

pub(super) async fn receive_event(
    event: Value,
    writer: &Writer,
    state: &Arc<State>,
    control: bool,
) -> Result<ReceiveOutcome, EventIoError> {
    // Keep rejection identity without cloning a potentially large business result.
    let context = json!({"event":event.get("event"), "attempt":event.get("attempt"), "lease":event.get("lease")});
    match event_received(event, writer, state, control).await {
        Ok(()) => Ok(ReceiveOutcome::Accepted),
        Err(error) => match error.downcast::<EventIoError>() {
            Ok(error) => Err(error),
            Err(error) => Ok(rejected(state, Some(&context), error.to_string())),
        },
    }
}
