//! R5 adapter admission. Observation version zero explicitly means unavailable.
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CLIENT_HASH: &str = "e9d57e725b4c0405faf959422720451215a9f7b2bd8f98bf0ad2377383b399ce";
pub const CLIENT_MODULES: [(&str, &str); 3] = [
    (
        "handle.py",
        "e9d57e725b4c0405faf959422720451215a9f7b2bd8f98bf0ad2377383b399ce",
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
            release: 1,
            open: 1,
            owner_observation: 0,
            client_hash: CLIENT_HASH.into(),
            sdk_boundary: 1,
            client_modules: CLIENT_MODULES
                .into_iter()
                .map(|(name, hash)| (name.into(), hash.into()))
                .collect(),
            capabilities: [
                "absolute_home_v1",
                "ack_cleanup_v1",
                "acquisition_outcome_v1",
                "launch_observer_v1",
                "lifetime_handshake_v1",
                "receiver_isolation_v1",
                "release_observation_v1",
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
