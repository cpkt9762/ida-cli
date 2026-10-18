//! Private IDA 9.5 verification, save and immediate reopen through production.
#![cfg(feature = "nexus-test-support")]
use ida_mcp::{
    nexus::*,
    preprocess::Preparation,
    router::{
        nexus_bridge::{BridgeConfig, NexusBridge},
        RouterState,
    },
};
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};

async fn seed(bridge: &NexusBridge, root: &std::path::Path) -> anyhow::Result<Value> {
    let client = ClientId::new("r3b-real-seed")?;
    let mut events = bridge.subscribe();
    bridge.endpoint().transition(|s,t|s.open(&client,
        AcceptedRequest::new(&SystemClock,RequestId::new("seed-open")?,None,"open",json!({"timeout_secs":30}))?,
        OpenSpec{operation_id:OperationId::new("seed-open")?,path:root.join("raw").display().to_string(),
            options:json!({"output_database":root.join("seed.i64"),"auto_analysis":false,"wait_analysis":false})},t))?;
    let ready = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            let event = events.recv().await?;
            if event["event"] == "opened" {
                break Ok::<_, anyhow::Error>(event);
            }
            anyhow::ensure!(
                event["event"] != "failed" && event["event"] != "uncertain",
                "seed failed: {event}"
            );
        }
    })
    .await??;
    let lease: SessionLease = serde_json::from_value(ready["lease"].clone())?;
    let identity=bridge.endpoint().transition(|s,t|{
        let identity=s.queue(&client,&lease,AcceptedRequest::new(&SystemClock,RequestId::new("seed-write")?,None,"execute_python",
            json!({"timeout_secs":30,"code":"import ida_ida, ida_bytes\nresult = ida_bytes.set_cmt(ida_ida.inf_get_min_ea(), 'r3b_verified_saved', False)"}))?,OperationId::new("seed-write")?)?;
        s.dispatch(&client,&identity,t)?;Ok::<_,NexusError>(identity)
    })?;
    let wrote = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let event = events.recv().await?;
            if event["event"] == "completed"
                && event["attempt"]["target"]["identity"]["operation_id"]
                    == identity.operation_id.as_str()
            {
                break Ok::<_, anyhow::Error>(event);
            }
        }
    })
    .await??;
    anyhow::ensure!(
        wrote["result"]["result"] == true,
        "actual IDA write: {wrote}"
    );
    bridge
        .endpoint()
        .transition(|s, t| s.release(&client, &lease, t))?;
    tokio::time::timeout(Duration::from_secs(20), async {
        while bridge.lifecycle_status()["resources"] != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    anyhow::ensure!(
        root.join("seed.i64").is_file(),
        "real owner did not save packed seed"
    );
    Ok(json!({"opened":ready,"write":wrote}))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_ida95_legacy_verification_preserves_saved_bytes_and_immediate_reopen() {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    std::fs::create_dir_all(PathBuf::from(
        std::env::var_os("IDA_CLI_HOME").expect("private cwd"),
    ))
    .expect("private worker cwd exists before direct N1 seed");
    std::fs::copy(
        std::env::var_os("R2_REAL_INPUT").expect("private prepared mini"),
        root.join("raw"),
    )
    .expect("sample copy");
    let router = RouterState::new().expect("router");
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("nexus_bridge/bridge.py"),
            directory: root.join("i"),
            environment: std::env::vars().collect(),
        })
        .await
        .expect("production native bridge/helper");
    let mut tokens = Vec::new();
    let result:anyhow::Result<Value>=async {
        let seeded=seed(&bridge,&root).await?;
        let cache=PathBuf::from(std::env::var_os("IDA_CLI_HOME").expect("private home")).join("idb");
        std::fs::create_dir_all(&cache)?;
        let hash=blake3::hash(&std::fs::read(root.join("raw"))?).to_hex()[..12].to_string();
        let legacy=cache.join(format!("legacy.{hash}.dylib.i64"));
        std::fs::copy(root.join("seed.i64"),&legacy)?;
        let before=blake3::hash(&std::fs::read(&legacy)?).to_hex().to_string();
        let mut events=bridge.subscribe();
        let open=||Preparation::new(Duration::from_secs(30));
        let (handle,token)=router.ensure_worker_prepared(root.join("raw").to_str().expect("path"),None,None,open()).await?;
        tokens.push(token.clone());
        let ready=tokio::time::timeout(Duration::from_secs(2),async {
            loop {let event=events.recv().await?;if event["event"]=="opened" {break Ok::<_,anyhow::Error>(event);}}
        }).await??;
        anyhow::ensure!(ready["acquisition"]["purpose"]=="final" && ready["acquisition"]["ordinal"]==2,"actual verification was bypassed: {ready}");
        let code=json!({"code":"import ida_kernwin, ida_ida, ida_bytes\nprint(ida_kernwin.get_kernel_version())\nprint(ida_bytes.get_cmt(ida_ida.inf_get_min_ea(), False))"});
        let read=router.route_request_prepared(Some(&handle),"run_script",code.clone(),open()).await?;
        anyhow::ensure!(read["success"]==true && read["stdout"]=="9.5\nr3b_verified_saved\n","{read}");
        anyhow::ensure!(legacy.with_extension("").is_file(),"verified input was not published");
        router.nexus_close_token(&token).await?;
        let (again,reopen_token)=router.ensure_worker_prepared(root.join("raw").to_str().expect("path"),None,None,open()).await?;
        tokens.push(reopen_token.clone());
        let reread=router.route_request_prepared(Some(&again),"run_script",code,open()).await?;
        anyhow::ensure!(reread["success"]==true && reread["stdout"]==read["stdout"],"saved legacy data changed: {reread}");
        router.nexus_close_token(&reopen_token).await?;
        let directories=std::fs::read_dir(&cache)?.filter_map(Result::ok).filter(|e|e.file_name().to_string_lossy().starts_with(".nexus-verify-")).map(|e|e.path()).collect::<Vec<_>>();
        anyhow::ensure!(directories.len()==1,"verification was repeated after publishing input: {directories:?}");
        anyhow::ensure!(!directories[0].join("probe.i64").exists() && !directories[0].join("input").exists(),"verification payload leaked");
        anyhow::ensure!(std::fs::read_dir(&directories[0])?.any(|e|e.is_ok_and(|e|e.file_name().to_string_lossy().starts_with(".ida-cli-txn-"))),"stable verification coordination was deleted");
        Ok(json!({"seed":seeded,"verification_final":ready,"read":read,"reopen":reread,"legacy_before_hash":before,"coordination":directories}))
    }.await;
    for token in tokens {
        let closed = router.nexus_close_token(&token).await;
        std::fs::write(root.join("last-finally-close.txt"), format!("{closed:?}"))
            .expect("cleanup evidence");
    }
    let settled = tokio::time::timeout(Duration::from_secs(20), async {
        while bridge.lifecycle_status()["resources"] != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let stopped = bridge.shutdown().await;
    std::fs::write(
        root.join("real-verification-result.json"),
        serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),
        "settled":settled.is_ok(),"shutdown":format!("{stopped:?}")}))
        .expect("encode"),
    )
    .expect("evidence");
    settled.expect("actual owner lifetime proof");
    stopped.expect("natural native/helper teardown");
    result.expect("real saved verification and immediate reopen");
}
