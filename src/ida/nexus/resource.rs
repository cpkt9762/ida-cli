//! Current resource liveness is orthogonal to immutable delivery/result history.
use super::*;
use serde_json::Value;

impl<C: Clock> NexusSessions<C> {
    /// Bind only the target writer's already durable creation incarnation.
    pub fn bind_resource_origin(
        &mut self,
        lease: &SessionLease,
        origin: Value,
    ) -> Result<(), NexusError> {
        self.authorize(&lease.client_id, lease)?;
        if !origin.is_object() || origin["incarnation"].as_str().is_none() {
            return Err(NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "missing durable resource origin",
            ));
        }
        if let Some(old) = self.resource_origins.get(&lease.lease_id) {
            if old != &origin {
                return Err(NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "resource origin changed",
                ));
            }
        } else {
            self.resource_origins.insert(lease.lease_id.clone(), origin);
        }
        Ok(())
    }

    /// The adapter must first validate the target-locked durable U6 evidence.
    /// This function never changes phase, ACK, outcome, or historical stop facts.
    pub fn retire_boot_resource(
        &mut self,
        lease: &SessionLease,
        evidence: Value,
    ) -> Result<(), NexusError> {
        self.authorize(&lease.client_id, lease)?;
        let origin = self.resource_origins.get(&lease.lease_id).ok_or_else(|| {
            NexusError::new(
                NexusErrorCode::InvalidIdentity,
                "historical resource has no creation binding",
            )
        })?;
        validate_retirement(origin, &evidence)?;
        if evidence["lease"]
            != serde_json::to_value(lease)
                .map_err(|e| NexusError::new(NexusErrorCode::InvalidIdentity, e.to_string()))?
        {
            return Err(invalid_resource("boot resource lease mismatch"));
        }
        if let Some(old) = self.resource_retirements.get(&lease.lease_id) {
            if old != &evidence {
                return Err(NexusError::new(
                    NexusErrorCode::InvalidIdentity,
                    "conflicting resource retirement",
                ));
            }
        } else {
            self.resource_retirements
                .insert(lease.lease_id.clone(), evidence);
        }
        Ok(())
    }

    pub fn resource_retirement(&self, lease: &SessionLease) -> Result<Option<Value>, NexusError> {
        self.authorize(&lease.client_id, lease)?;
        Ok(self.resource_retirements.get(&lease.lease_id).cloned())
    }
}

fn invalid_resource(message: &str) -> NexusError {
    NexusError::new(NexusErrorCode::InvalidIdentity, message)
}

fn canonical_boot(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 36
            && s.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
                }
            })
    })
}

fn valid_scope(scope: &Value) -> bool {
    let required = [
        (
            "method",
            "IOPlatformUUID/APFS-VolumeUUID/bootsessionuuid-v1",
        ),
        ("machine_source", "IOPlatformExpertDevice.IOPlatformUUID"),
        ("volume_source", "diskutil.VolumeUUID"),
        (
            "host_domain",
            "Darwin-host-kernel-no-PID-or-time-namespaces",
        ),
        ("boot_retirement_capability", "physical_local_apfs_host_v1"),
    ];
    required.iter().all(|(k, v)| scope[k] == *v)
        && scope["creator"]["kind"] == "macos-libproc-v1"
        && canonical_boot(&scope["creator"]["boot_id"])
        && scope["virtualized"] == false
        && scope["local_internal"] == true
        && scope["same_boot_eligibility"] == false
        && scope["file_id"].as_u64().is_some_and(|n| n > 0)
        && scope["uid"].as_u64().is_some()
        && scope["incarnation"].as_str().is_some_and(|s| !s.is_empty())
        && ["machine_sha256", "volume_sha256"].iter().all(|k| {
            scope[k].as_str().is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
        })
}

fn validate_retirement(origin: &Value, evidence: &Value) -> Result<(), NexusError> {
    let current = &evidence["current"];
    let matching = [
        "machine_sha256",
        "volume_sha256",
        "host_domain",
        "file_id",
        "uid",
    ];
    if !valid_scope(origin)
        || !valid_scope(current)
        || evidence["binding"] != *origin
        || evidence["evidence_type"] != "verified_boot_change_resource_retirement"
        || evidence["scope"] != "host_boot_change"
        || evidence["resource_disposition"] != "RetiredByBootChange"
        || evidence["current_execution_liveness"] != "ImpossibleInCurrentBoot"
        || evidence["never_replay"] != true
        || evidence["old_boot"] != origin["creator"]["boot_id"]
        || evidence["new_boot"] != current["creator"]["boot_id"]
        || evidence["old_boot"] == evidence["new_boot"]
        || matching.iter().any(|k| origin[k] != current[k])
    {
        return Err(invalid_resource(
            "unsupported or mismatched boot resource scope",
        ));
    }
    Ok(())
}

impl<C: Clock> NexusSessions<C> {
    /// Record the durable target authority's startup binding before any spawn.
    pub fn bind_startup_origin(
        &mut self,
        acquisition: &AcquisitionId,
        watch: &str,
        origin: Value,
    ) -> Result<(), NexusError> {
        self.open_progress(&acquisition.parent.client_id, &acquisition.parent)?;
        if watch.is_empty()
            || watch.len() > 128
            || !origin.is_object()
            || origin["incarnation"].as_str().is_none()
        {
            return Err(invalid_resource("missing startup origin"));
        }
        let value = (acquisition.clone(), origin);
        if let Some(old) = self.startup_origins.get(watch) {
            if old != &value {
                return Err(invalid_resource("startup origin changed"));
            }
        } else {
            self.startup_origins.insert(watch.into(), value);
        }
        Ok(())
    }

    /// Retire only this old startup's current liveness, preserving open history.
    pub fn retire_boot_startup(
        &mut self,
        acquisition: &AcquisitionId,
        watch: &str,
        evidence: Value,
    ) -> Result<(), NexusError> {
        let (bound, origin) = self
            .startup_origins
            .get(watch)
            .ok_or_else(|| invalid_resource("startup lacks creation binding"))?;
        validate_retirement(origin, &evidence)?;
        if bound != acquisition
            || evidence["watch"] != watch
            || !evidence["lease"].is_null()
            || evidence["acquisition"]
                != serde_json::to_value(acquisition)
                    .map_err(|e| invalid_resource(&e.to_string()))?
        {
            return Err(invalid_resource("startup retirement identity mismatch"));
        }
        if let Some(old) = self.startup_retirements.get(watch) {
            if old != &evidence {
                return Err(invalid_resource("startup retirement changed"));
            }
        } else {
            self.startup_retirements.insert(watch.into(), evidence);
        }
        Ok(())
    }

    pub(super) fn startup_resources_retired(&self, identity: &OpenIdentity) -> bool {
        let mut found = false;
        for (watch, (acquisition, _)) in &self.startup_origins {
            if acquisition.parent == *identity {
                found = true;
                if !self.startup_retirements.contains_key(watch) {
                    return false;
                }
            }
        }
        found
    }
}
