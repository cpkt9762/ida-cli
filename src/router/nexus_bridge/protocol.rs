//! R5 adapter admission. Observation version zero explicitly means unavailable.
use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const CLIENT_HASH: &str = "aa5d7ea42caaa922ef494d7d8a1406396537a4ea88d9e833825e08c8d279025e";
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    wire: u8,
    schema: u8,
    release: u8,
    open: u8,
    owner_observation: u8,
    client_hash: String,
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
            capabilities: [
                "absolute_home_v1",
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
