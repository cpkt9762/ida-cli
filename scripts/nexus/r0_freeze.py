#!/usr/bin/env python3
"""Freeze R0 boundaries from the recorded experiments, never manufacture proofs."""
import argparse
import hashlib
import json
from pathlib import Path
from r0_contract import consumer_policy, validate_message_contract

REPO = Path(__file__).resolve().parents[2]


def load(path):
    return json.loads(path.read_text())


def evidence(path):
    return {"path":str(path.resolve()), "sha256":hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--os", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--records", type=Path)
    parser.add_argument("--real", type=Path)
    parser.add_argument("--v1-checks", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    run = load(args.run)
    stages = {k:Path(v) for k,v in run["stages"].items()}
    for stage in ("records", "real", "v1_checks"):
        if getattr(args, stage) is not None:
            stages[stage] = getattr(args, stage)
    real = load(stages["real"] / "result.json")
    platform = load(args.os / "platform.json")
    raw = [args.run, args.os / "platform.json", args.os / "owner-gone.json",
        args.os / "occupancy.json", args.os / "u6.json", args.os / "u6-history.json",
        args.sdk / "ack.json", args.sdk / "attach.json", args.sdk / "spawn.json", args.sdk / "ready.json",
        stages["transfer"] / "transfer-results.json", stages["transfer"] / "both-exit.json",
        stages["records"] / "bounded-results.json", stages["records"] / "quota-results.json", stages["install"] / "install-results.json",
        stages["real"] / "result.json"]
    raw.extend([args.sdk / "ack-matrix.json", args.sdk / "no-ack.json", args.sdk / "attempts.json",
        stages["durable"] / "durable-results.json", stages["durable"] / "durable-rejections.json",
        stages["install"] / "install-rejections.json", stages["v1_checks"] / "v1-results.json",
        stages["v1_checks"] / "interpreter-0.json", stages["v1_checks"] / "interpreter-1.json",
        stages["contract_checks"] / "scope-results.json",
        stages["real"] / "v1-observed.json", stages["real"] / "v1-expected.json"])
    reds = []
    for name in ("slow-owner", "early-analysis", "lost-ack"):
        path = args.rust / name / "rust-result.json"
        red = load(path)
        assert red["scope"] == "current-product-expected-red"
        reds.append(red["fact"])
        raw.append(path)
    assert real["close"]["owner_released"] and not real["remaining_registry"]
    assert real["packed_before"] == real["packed_after"]
    candidate = args.candidate or Path(run["candidate"])
    hashes = load(candidate.parent / "sdk-candidate-hashes.json")
    validations = [json.loads(line) for line in (args.report / "validation.jsonl").read_text().splitlines()]
    required_files = {"os":"r0_os.py", "sdk":"r0_sdk.py", "transfer":"r0_transfer.py",
                      "records":"r0_records.py", "install":"r0_install.py", "real":"r0_real_ida.py",
                      "durable":"r0_durable.py", "v1_checks":"r0_v1_checks.py", "contract_checks":"r0_contract_checks.py"}
    checked = {}
    directories = dict(stages, os=args.os, sdk=args.sdk)
    for stage, filename in required_files.items():
        matches = [entry for entry in validations if entry["exit"] == 0 and
                   any(filename in arg for arg in entry["argv"]) and
                   any(str(directories[stage].resolve()) in arg or
                       str(directories[stage]) in arg for arg in entry["argv"])]
        if not matches:
            raise RuntimeError("missing successful recorded experiment: " + stage)
        checked[stage] = matches[-1]
    rust_records = [entry for entry in validations if entry["exit"] == 0 and "current_product_red_baselines" in entry["argv"] and
                   any(str(args.rust) in arg or str(args.rust.resolve()) in arg for arg in entry["argv"])]
    if not rust_records:
        raise RuntimeError("missing successful exact Rust target record")
    checked["rust"] = rust_records[-1]
    dependencies = {stage:["tests/support/" + filename, "tests/support/r0_common.py"]
                    for stage,filename in required_files.items()}
    dependencies["sdk"] += ["tests/support/r0_transport.py", "scripts/nexus/r0_sdk_candidate.py"]
    dependencies["durable"] += ["tests/support/r0_records.py"]
    dependencies["v1_checks"] += ["tests/support/r0_v1.py"]
    dependencies["real"] += ["tests/support/r0_v1.py"]
    dependencies["contract_checks"] += ["scripts/nexus/r0_contract.py"]
    dependencies["install"] = ["tests/support/r0_install.py", "scripts/nexus/r0_bootstrap.py", "scripts/nexus/r0_maintenance_launch.sh"]
    dependencies["rust"] = ["tests/nexus_r0_prototypes.rs","Cargo.toml","tests/support/r0_bridge_fixture.py","tests/support/r0_transport.py","tests/support/r0_common.py"]
    for stage, paths in dependencies.items():
        for path in paths:
            actual = hashlib.sha256((REPO / path).read_bytes()).hexdigest()
            if checked[stage]["source_sha256"].get(path) != actual:
                raise RuntimeError(f"stale source evidence: {stage}: {path}")
    if (not real["v1_validation"]["passed"] or real["v1_validation"]["comparison"] != "complete-equality"
            or real["v1_validation"]["validator_sha256"] != hashlib.sha256((REPO / "tests/support/r0_v1.py").read_bytes()).hexdigest()):
        raise RuntimeError("missing final complete v1 validation")
    independent = [load(stages["v1_checks"] / f"interpreter-{i}.json") for i in range(2)]
    if independent[0] != independent[1] or independent[0]["key"] != real["v1_compatibility_key"]:
        raise RuntimeError("unstable or unmatched real/independent v1 compatibility keys")
    actual_key = hashlib.sha256(json.dumps(real["loaded_v1"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (real["loaded_v1"] != load(stages["real"] / "v1-observed.json")
            or real["loaded_v1"] != load(stages["real"] / "v1-expected.json")
            or actual_key != real["v1_compatibility_key"]
            or actual_key != real["v1_validation"]["actual_key"]
            or actual_key != real["v1_validation"]["expected_key"]
            or real["loaded_v1"]["ida"] != real["runtime"] or real["runtime"] != "9.5"):
        raise RuntimeError("incomplete or inconsistent real v1 comparison")
    capabilities = {"schema":1,"scope":"R0-experiments-only","production_protocol_changed":False,
        "platform":platform, "supported":[
            "Darwin native birth survives exec", "public last/nonlast ACK and real owner lifetime",
            "SCM_RIGHTS close-only transfer with independent recovery fence",
            "bounded routine compaction and epoch/ref crash model",
            "trusted installation bootstrap in four Python modes",
            "known v1 loaded code/ABI fingerprints on IDA9.5/Python3.14.7"],
        "unsupported":[{"class":"current public managed idalib owner",
            "capability":"same_boot_os_exit_eligibility","reason":real["same_boot_eligibility"]},
            {"class":"arbitrary fork/setsid/FD recipients", "capability":"complete recipient inventory",
             "reason":"native detached-descendant and queued SCM_RIGHTS counterexamples"},
            {"class":"unknown GUI/plugin owner","capability":"same_boot_os_exit_eligibility",
             "reason":"no closed entry/revocation model; default false, not a tested GUI claim"}],
        "not_tested":["real macOS/Nexus cross-boot product chain", "Linux product platform capability",
            "cloned/rolled-back machine identities in a real product environment", "Windows",
            "complete maintenance application", "R1-R7 production integration", ">100MB or full E2E"],
        "injected_only":["U6 machine/volume/namespace/new-owner/journal rejection and resource retirement",
            "cross-helper revocation authority", "compaction ENOSPC/EACCES"],
        "true_r0_api_blockers":[],"production_expected_red":reds,
        "validated_current_source":{stage:{"log":entry["log"],"exit":entry["exit"],"source_sha256":
            {path:entry["source_sha256"][path] for path in dependencies[stage]}} for stage,entry in checked.items()},
        "evidence":[evidence(path) for path in raw]}
    contract = {"schema":1, "contract":"N7a-R-r4-R0", "production_enabled":False,
        "source_plans":[evidence(REPO / "docs/plan/nexus-release-protocol.md"),
                        evidence(REPO / "docs/plan/nexus-backend.md")],
        "sdk":{"version":"0.13.4","source_sha":"d60ff582fde90c59726336c0dbdf3e8286e9df7a",
            "candidate_files":["ida_nexus/handle.py","ida_nexus/_resolver.py","ida_nexus/options.py"],
            "hashes":hashes,"diff":evidence(candidate.parent / "sdk-candidate.diff"),
            "additive_public_api":["attach_outcome","open_outcome","on_acquired","on_stage","acquisition_observer","claim_acquired"],
            "acquisition_fields":["stage","handle","instance","first_instance","failure_kind","cause","launches","sdk_reconnect_used","attempts","unresolved_attempts"],
            "attempt_fields":["attempt","instance","stage","handle","failure_kind","cause","http_status","obligation"],
            "stages":["BeforeResolve","LaunchIntent","Spawned","LogReady","Resolved","BeforeAttach","AttachMayBeSent","Acquired","AttachFailed","AttachSucceeded","ReconnectResolved"],
            "rule":"each internal attach retains original instance and unknown obligation; later rejection/success or local stream close never discharges earlier unknown; callback custody failure retains exact handle until explicit claim/close; no post-acquired reconnect",
            "close_fields":["status","ack_kind","lease_released","shutdown_pending","owner_released","owner_pending","failure","cleanup_failure","cleanup_failure_type","cleanup_failures"],
            "request_rule":"one-shot release; parsed ACK immutable; no unknown replay; operation_id already public"},
        "authority":{"business_result":"Rust N1","physical_custody_and_capacity":"Rust custody table",
            "original_instance_and_observation":"one helper per state root",
            "journal_executor":"one executor_epoch owner under target EX",
            "save_protection":"owner versioned guard","resource_guards":"Tools consumes authoritative dispositions"},
        "message_contract":{"identity_fields":["schema","router_incarnation","acquisition_id","OwnerKey","CoordKey","subscription_epoch","sequence"],
            "kinds":["Preparing","custody_ack","subscribe","subscribe_ack","lease_detached","owner_released","owner_exit_observed","startup_unconfirmed","resource_retired"],
            "consumer_policy":consumer_policy(),
            "payloads":{
                "Preparing":{"operation_id":"exact existing public ID","parent":"AcquisitionId","scope":"primary|verification|auxiliary","deadline":"original monotonic budget","transaction_ref":"optional RecoveryId"},
                "custody_ack":{"acquisition_id":"exact original","disposition":"no_acquisition|acquired|cleanup_required|startup_pending|file_pending","handle_ref":"exact SDK-owned handle when present","launch_refs":"all unresolved LaunchIdentity references"},
                "subscribe":{"owner_ref":"original public SDK instance, never rediscovered replacement","epoch":"monotonic observer epoch","origin_binding":"durable machine/volume/boot incarnation"},
                "subscribe_ack":{"owner_key":"exact original OwnerKey","epoch":"same subscription epoch","durable_record":"pinned journal identity/hash"},
                "lease_detached":{"lease_key":"exact original LeaseKey","ack_kind":"last|nonlast","cleanup_failure":"independent optional error"},
                "owner_released":{"owner_key":"exact original OwnerKey","scope":"public_owner_lifetime","evidence_ref":"producer's public lifetime observation record"},
                "owner_exit_observed":{"owner_key":"exact original OwnerKey","scope":"eligible_same_boot_os_exit","evidence_ref":"eligible native exit observation; Tools resource obligations only, never N1"},
                "startup_unconfirmed":{"launch_ref":"original unresolved intent/child identity","reason":"typed creation/identity/ready/exit observation failure"},
                "resource_retired":{"scope":"verified_boot_change_resource_retirement","old_origin":"durable old-boot binding","disposition":"RetiredByBootChange","liveness":"ImpossibleInCurrentBoot","history_ref":"unchanged UnknownOutcome/ACK/stop record","file_gate":"separate current occupancy/journal decision"}},
            "durability":"helper persists original owner/subscription before ACK; caller retains obligation until acknowledged custody disposition",
            "timeout":"observation timeout is not proof; NotSent requires pre-send fact; may-sent remains UnknownOutcome",
            "scope":"agreed field/ownership contract; wire serialization and version rejection implemented in R5/R1/R3a"},
        "transfer":{"fields":["recovery_id","executor_epoch","sender_incarnation","receiver_incarnation","fd_kind","inode","nonce"],
            "states":["LocalExecuting","FrozenOffer","DefinitelyNotSent","SendMayHaveDelivered","Accepted","Resumed"],
            "rule":"freeze before send; only Accepted receiver writes; duplicates close-only; independent OFD fence only after all own old FDs close"},
        "target_gate":{"order":["root_SH","target_EX"],"gc":["root_EX_NB","target_EX_NB"],
            "layout":"stable namespace/gid and lock inode survive payload deletion; direct paths use canonical sibling coordination"},
        "records":{"classes":["active","routine","retained","namespace"],
            "routine_fields":["epoch","refs","producer_closed","consumer_closed","unacked_events","failure","last_safety_evidence"],
            "summary_fields":["closed_through","closed_after_holes"],
            "closed_after_holes_type":"merged inclusive [first,last] intervals; not individual epoch tombstones",
            "prototype_limits":{"summary_holes":64,"summary_bytes":16384,"routine_slots":96,"finish_reserve":8},
            "pending_write":{"slots":["<name>.new","<name>.new.owner"],
                "binding":["schema","writer","target","inode","device","sha256","uid","mode","nlink"],
                "rule":"target EX single writer; resume only exact bound inode/content; verify published rename before consuming intent; unknown/partial/conflicting slots preserved as explicit errors",
                "tested_internal_exits":["temp_written","file_fsynced","before_rename","after_rename","directory_fsynced"],
                "not_claimed":"automatic recovery inside arbitrary torn syscalls or incomplete ownership-record creation"},
            "rule":"both epochs closed and no refs/events/last safety evidence before unlink; revision and inode/hash pin intents; late closed events never resurrect",
            "errors":["Busy+live_refs","Busy+summary_holes","RoutineCompactionFailed","retained_quota_full","physical_ENOSPC"]},
        "u6":{"binding":["method_version","machine_source","volume_identity","host_domain","old_boot","new_boot","fileid","router_incarnation"],
            "rule":"resource retirement never supplies missing ACK/stop or changes historical UnknownOutcome; file gate still checks journal and current occupancy",
            "product_boot_test_owner":["R4","R7"]},
        "v1_cleanup_only":{"python_abi":real["fingerprint_python_abi"],"ida":real["runtime"],
            "loaded":real["loaded_v1"],"key":real["v1_compatibility_key"],
            "validation":real["v1_validation"],
            "verification":"complete equality of module/function/hook sets, normalized executable code and parameter kinds/order/defaults/kwdefaults/function-default content, canonical dependency binding/version/source; two independent interpreters match real owner; no unknown self-report",
            "allow":"known exact set may cleanup only; never new admission; unknown combination rejects"},
        "bootstrap":{"modes":["ordinary","-I","-P","PYTHONSAFEPATH"],
            "rule":"official env-i launcher excludes startup injection before interpreter initialization; schema1 exact16-member closure, permissions/identity/hash checked; custom loader executes only verified in-memory source bytes, existing bytecode rejected",
            "scope":"entry prototype; maintenance dry-run/apply/restart remain R4"},
        "next_order":["R5","R1","R3a","R2","R3b","R4","R6","R7"],
        "evidence":capabilities["evidence"]}
    validate_message_contract(contract["message_contract"])
    for filename, value in (("capabilities.json", capabilities),("contract-freeze.json",contract)):
        (args.report / filename).write_text(json.dumps(value, indent=2))
    print(json.dumps({"artifacts":["capabilities.json","contract-freeze.json"],"expected_red":[x["id"] for x in reds]}))


if __name__ == "__main__":
    main()
