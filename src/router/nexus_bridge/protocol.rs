//! Exact adapter admission, including the implemented R3a custody boundary.
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CLIENT_HASH: &str = "dd9daf669b6dc55f657dd11b60f9869dcca70cf278cc65bc1d91b4e02b199acd";
pub const CLIENT_MODULES: [(&str, &str); 3] = [
    (
        "handle.py",
        "dd9daf669b6dc55f657dd11b60f9869dcca70cf278cc65bc1d91b4e02b199acd",
    ),
    (
        "_resolver.py",
        "d06a1014c2193a50372f24144200949092cbead48ffd7113221fa7220e9733e8",
    ),
    (
        "options.py",
        "1fbd67a12adee065b8db6fa97a333130986085ccedc7728ba92cb41fa3d9dcfe",
    ),
];
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    wire: u8,
    schema: u8,
    release: u8,
    open: u8,
    owner_observation: u8,
    custody: u8,
    helper: u8,
    target_gate: u8,
    same_boot_exit: u8,
    boot_retirement: u8,
    client_hash: String,
    sdk_boundary: u8,
    client_modules: BTreeMap<String, String>,
    capabilities: Vec<String>,
}
impl Protocol {
    pub fn current() -> Self {
        Self {
            wire: 2,
            schema: 1,
            release: 2,
            open: 1,
            owner_observation: 1,
            custody: 2,
            helper: 2,
            target_gate: 1,
            same_boot_exit: 0,
            boot_retirement: 1,
            client_hash: CLIENT_HASH.into(),
            sdk_boundary: 2,
            client_modules: CLIENT_MODULES
                .into_iter()
                .map(|(name, hash)| (name.into(), hash.into()))
                .collect(),
            capabilities: [
                "absolute_home_v1",
                "ack_cleanup_v1",
                "acquisition_outcome_v1",
                "durable_public_proof_v1",
                "final_preparing_v1",
                "internal_grant_v1",
                "launch_observer_v1",
                "lifetime_handshake_v1",
                "receiver_isolation_v1",
                "release_observation_v1",
                "single_resolution_outcome_v1",
                "target_gate_base_v1",
                "two_phase_release_v1",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
    pub fn validate(value: serde_json::Value) -> anyhow::Result<()> {
        let mut protocol: Self = serde_json::from_value(value)
            .context("ProtocolMismatch: missing or malformed Nexus adapter contract")?;
        protocol.capabilities.sort();
        anyhow::ensure!(
            protocol == Self::current(),
            "ProtocolMismatch: incompatible Nexus adapter contract"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r1_contract_matches_preparer_and_rejects_module_mismatch() {
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../scripts/nexus/client-sdk-contract.json"
        ))
        .expect("SDK contract JSON");
        let current = serde_json::to_value(Protocol::current()).expect("encode protocol");
        assert_eq!(current["client_modules"], manifest["files"]);
        assert_eq!(current["sdk_boundary"], manifest["sdk_boundary"]);
        for name in ["handle.py", "_resolver.py", "options.py"] {
            let mut bad = current.clone();
            bad["client_modules"][name] = serde_json::json!("0".repeat(64));
            assert!(
                Protocol::validate(bad).is_err(),
                "accepts mismatched {name}"
            );
        }
    }

    #[test]
    fn r5_admission_compares_sets_but_rejects_duplicate_capabilities() {
        let mut value = serde_json::to_value(Protocol::current()).expect("encode protocol");
        value["capabilities"]
            .as_array_mut()
            .expect("capabilities")
            .reverse();
        Protocol::validate(value.clone()).expect("capability order is immaterial");
        let duplicate = value["capabilities"][0].clone();
        value["capabilities"]
            .as_array_mut()
            .expect("capabilities")
            .push(duplicate);
        assert!(Protocol::validate(value).is_err());
    }
}
