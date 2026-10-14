use super::support::*;
use ida_mcp::nexus::*;
use ida_mcp::router::protocol::{RpcRequest, RpcResponse};
use ida_mcp::server::task::nexus_task_state_json;
use ida_mcp::ToolError;
use serde_json::json;

#[test]
fn timeout_units_caps_zero_invalid_json_and_wire_budget_are_explicit() {
    let clock = TestClock::new();
    for (value, seconds) in [
        (json!(null), 120),
        (json!(-1), 120),
        (json!("3"), 120),
        (json!(1.5), 120),
        (json!(u64::MAX), 600),
    ] {
        let request = accepted(
            &clock,
            "timeout",
            "list_functions",
            json!({"timeout_secs":value}),
        );
        assert_eq!(
            request.remaining(&clock).unwrap().milliseconds(),
            seconds * 1000
        );
    }
    assert_eq!(
        accepted(&clock, "open-cap", "open", json!({"timeout_secs":u64::MAX}))
            .remaining(&clock)
            .unwrap()
            .milliseconds(),
        3_600_000
    );
    assert_eq!(
        accepted(&clock, "zero", "rename_symbol", json!({"timeout_secs":0}))
            .remaining(&clock)
            .unwrap_err()
            .code,
        NexusErrorCode::DeadlineExpired
    );
    for wire in ["0", "3600001", "-1", "1.5", "18446744073709551615"] {
        assert!(
            serde_json::from_str::<RemainingBudget>(wire).is_err(),
            "invalid wire budget {wire}"
        );
    }
    assert!(serde_json::from_str::<LeaseId>("\"\"").is_err());
    assert!(RequestId::new("bad\nidentity").is_err());
}

#[test]
fn legacy_rpc_payload_addresses_pagination_and_mcp_wrappers_stay_compatible() {
    let old = json!({"jsonrpc":"2.0","id":"r1","method":"list_functions","params":{"offset":2,"limit":5}});
    let request: RpcRequest = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(serde_json::to_value(request).unwrap(), old);
    let result = serde_json::to_value(ida_mcp::FunctionListResult {
        functions: vec![ida_mcp::FunctionInfo {
            address: "0x1000".into(),
            name: "main".into(),
            size: 16,
        }],
        total: 7,
        next_offset: Some(3),
    })
    .unwrap();
    assert_eq!(
        result,
        json!({"functions":[{"address":"0x1000","name":"main","size":16}],"total":7,"next_offset":3})
    );
    let empty = ida_mcp::FunctionListResult {
        functions: vec![],
        total: 0,
        next_offset: None,
    };
    assert_eq!(
        serde_json::to_value(empty).unwrap(),
        json!({"functions":[],"total":0})
    );
    let response = RpcResponse::ok("r1", result.clone());
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({"jsonrpc":"2.0","id":"r1","result":result})
    );
    assert_eq!(
        serde_json::to_value(RpcResponse::err("r1", -32000, "old error")).unwrap(),
        json!({"jsonrpc":"2.0","id":"r1","error":{"code":-32000,"message":"old error"}})
    );
    let error = NexusError::new(
        NexusErrorCode::UnknownOutcome,
        "connection lost after write",
    );
    let rpc = serde_json::to_value(RpcResponse::nexus_error("r2", &error)).unwrap();
    assert_eq!(rpc["error"]["code"], -32000);
    assert_eq!(rpc["error"]["data"]["nexus"]["retry"], "never_replay");
    assert_eq!(rpc["error"]["data"]["nexus"]["automatic_replay"], false);
    let mcp = serde_json::to_value(ToolError::from(error).to_tool_result()).unwrap();
    assert_eq!(mcp["isError"], true);
    assert_eq!(mcp["content"][0]["type"], "text");
    assert_eq!(mcp["structuredContent"]["nexus"]["code"], "unknown_outcome");
    let legacy = serde_json::to_value(ToolError::Busy.to_tool_result()).unwrap();
    assert!(legacy.get("structuredContent").is_none());
}

#[test]
fn task_projection_keeps_legacy_running_until_cancel_is_confirmed() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "task-projection", "rename_symbol", 120);
    for expected in [
        OperationStatus::Queued,
        OperationStatus::Running,
        OperationStatus::CancelRequested,
    ] {
        match expected {
            OperationStatus::Running => rig.dispatch(&op),
            OperationStatus::CancelRequested => {
                rig.sessions
                    .cancel(
                        &lease.client_id,
                        &op,
                        CancelReason::Client,
                        &mut rig.backend,
                    )
                    .unwrap();
            }
            _ => {}
        }
        let snapshot = rig.snapshot(&op);
        let value =
            nexus_task_state_json(&snapshot, "2026-10-15T00:00:00Z", "2026-10-15T00:00:01Z")
                .expect("background task projection");
        assert_eq!(value["status"], "running");
        assert_eq!(value["task_id"], "t-task-projection");
        assert_eq!(
            value["meta"]["nexus"]["status"],
            serde_json::to_value(expected).unwrap()
        );
        assert_eq!(
            value["meta"]["nexus"]["identity"]["operation_id"],
            "task-projection"
        );
    }
    rig.sessions.complete(&op, Completion::Cancelled).unwrap();
    assert_eq!(
        nexus_task_state_json(&rig.snapshot(&op), "created", "updated").unwrap()["status"],
        "cancelled"
    );
    let mut short_request = rig.snapshot(&op);
    short_request.identity.task_id = None;
    assert_eq!(
        nexus_task_state_json(&short_request, "created", "updated")
            .unwrap_err()
            .code,
        NexusErrorCode::InvalidIdentity
    );
}

#[test]
fn nexus_command_wire_preserves_identity_and_only_transfers_remaining_duration() {
    let mut rig = Rig::new();
    let lease = rig.connect("a", "instance", 1);
    let op = rig.queue(&lease, "wire", "rename_symbol", 120);
    rig.clock.advance(25);
    rig.dispatch(&op);
    let command = rig.backend.business.last().unwrap();
    let wire = serde_json::to_value(command).unwrap();
    assert_eq!(wire["command"], "execute");
    assert_eq!(wire["identity"]["request_id"], "r-wire");
    assert_eq!(wire["identity"]["lease"]["generation"], 1);
    assert_eq!(wire["remaining_ms"], 119975);
    assert!(wire.get("deadline").is_none());
    assert!(wire.get("instant").is_none());
    let decoded: SessionCommand = serde_json::from_value(wire).unwrap();
    match decoded {
        SessionCommand::Execute(command) => {
            assert_eq!(command.identity, op);
            assert_eq!(command.effect, MethodEffect::MayWrite);
        }
        _ => panic!("execution envelope changed command kind"),
    }
}
