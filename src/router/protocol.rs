//! JSON-RPC 2.0 wire types for router ↔ worker communication.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Serialisable request envelope sent from router to worker stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: Value,
}

/// Serialisable response envelope sent from worker stdout to router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcRequest {
    pub fn new(id: impl Into<String>, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

impl RpcResponse {
    /// Add structured Nexus diagnostics inside the existing error envelope.
    pub fn nexus_error(id: impl Into<String>, error: &crate::ida::nexus::NexusError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: id.into(),
            result: None,
            error: Some(RpcError {
                code: error.rpc_code(),
                message: error.to_string(),
                data: Some(serde_json::json!({"nexus": error.details()})),
            }),
        }
    }

    pub fn ok(id: impl Into<String>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: id.into(),
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: impl Into<String>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: id.into(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

// Reserved internal metadata is attached by the local router, consumed and
// removed before the legacy dispatcher. External timeout_secs remains seconds.
const DEADLINE_KEY: &str = "_ida_cli_deadline_monotonic_ns";
pub(crate) fn attach_deadline(
    params: &mut Value,
    deadline: std::time::Instant,
) -> Result<(), crate::error::ToolError> {
    let expiry = super::nexus_transport::wire_expiry(Some(deadline))
        .map_err(|e| crate::error::ToolError::IdaError(e.to_string()))?;
    let object = params.as_object_mut().ok_or_else(|| {
        crate::error::ToolError::InvalidParams("request params must be an object".into())
    })?;
    object.insert(DEADLINE_KEY.into(), expiry.into());
    Ok(())
}
pub(crate) fn take_deadline(
    params: &mut Value,
    fallback: std::time::Instant,
) -> Result<std::time::Instant, crate::error::ToolError> {
    let Some(value) = params.as_object_mut().and_then(|p| p.remove(DEADLINE_KEY)) else {
        return Ok(fallback);
    };
    let expiry = value.as_u64().ok_or_else(|| {
        crate::error::ToolError::InvalidParams("invalid internal deadline".into())
    })?;
    let now = super::nexus_transport::monotonic_ns()
        .map_err(|e| crate::error::ToolError::IdaError(e.to_string()))?;
    Ok(fallback.min(
        std::time::Instant::now() + std::time::Duration::from_nanos(expiry.saturating_sub(now)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_rpc_request_roundtrip() {
        let req = RpcRequest::new("r1", "decompile", json!({"addr": 4096}));
        let json_str = serde_json::to_string(&req).unwrap();
        let decoded: RpcRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(decoded.id, "r1");
        assert_eq!(decoded.method, "decompile");
        assert_eq!(decoded.jsonrpc, "2.0");
    }

    #[test]
    fn test_rpc_response_ok() {
        let resp = RpcResponse::ok("r1", json!({"code": "int main(){...}"}));
        let json_str = serde_json::to_string(&resp).unwrap();
        let decoded: RpcResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(decoded.id, "r1");
        assert!(decoded.result.is_some());
        assert!(decoded.error.is_none());
    }

    #[test]
    fn test_rpc_response_err() {
        let resp = RpcResponse::err("r2", -32000, "no IDB open");
        let json_str = serde_json::to_string(&resp).unwrap();
        let decoded: RpcResponse = serde_json::from_str(&json_str).unwrap();
        assert!(decoded.result.is_none());
        assert!(decoded.error.is_some());
        assert_eq!(decoded.error.unwrap().message, "no IDB open");
    }

    #[test]
    fn test_optional_fields_not_serialized() {
        let resp = RpcResponse::ok("r1", json!({}));
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(!json_str.contains("\"error\""));
    }
}
