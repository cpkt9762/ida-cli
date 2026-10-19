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
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
                if std::env::var("R3F1_CASE").as_deref() == Ok("real-probe-trace") {
                    "tests/support/r3b_fix1_bridge.py"
                } else {
                    "nexus_bridge/bridge.py"
                },
            ),
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

async fn real_open(
    bridge: &NexusBridge,
    events: &mut tokio::sync::broadcast::Receiver<Value>,
    client: &ClientId,
    path: &std::path::Path,
    name: &str,
) -> anyhow::Result<SessionLease> {
    bridge.endpoint().transition(|s, t| {
        s.open(
            client,
            AcceptedRequest::new(
                &SystemClock,
                RequestId::new(name)?,
                None,
                "open",
                json!({"timeout_secs":60}),
            )?,
            OpenSpec {
                operation_id: OperationId::new(name)?,
                path: path.display().to_string(),
                options: json!({"auto_analysis":false,"wait_analysis":false}),
            },
            t,
        )
    })?;
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let event = events.recv().await?;
            if event["event"] == "opened" {
                return Ok(serde_json::from_value(event["lease"].clone())?);
            }
            anyhow::ensure!(
                event["event"] != "failed" && event["event"] != "uncertain",
                "actual open failed: {event}"
            );
        }
    })
    .await?
}

async fn real_execute(
    bridge: &NexusBridge,
    events: &mut tokio::sync::broadcast::Receiver<Value>,
    lease: &SessionLease,
    code: String,
) -> anyhow::Result<Value> {
    let identity = bridge.endpoint().transition(|s, t| {
        let identity = s.queue(
            &lease.client_id,
            lease,
            AcceptedRequest::new(
                &SystemClock,
                RequestId::new("r4-native-copy")?,
                None,
                "execute_python",
                json!({"timeout_secs":30,"code":code}),
            )?,
            OperationId::new("r4-native-copy")?,
        )?;
        s.dispatch(&lease.client_id, &identity, t)?;
        Ok::<_, NexusError>(identity)
    })?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let event = events.recv().await?;
            if event["attempt"]["target"]["identity"]["operation_id"]
                == identity.operation_id.as_str()
            {
                if event["event"] == "completed" {
                    return Ok(event);
                }
                anyhow::ensure!(
                    event["event"] != "failed" && event["event"] != "uncertain",
                    "native copy failed: {event}"
                );
            }
        }
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_ida95_r9_file_job_restores_exact_components_before_retry_and_new_read() {
    let root = PathBuf::from(std::env::var_os("R3A_CASE_ROOT").expect("private root"));
    std::fs::create_dir_all(std::env::var_os("IDA_CLI_HOME").expect("private worker cwd"))
        .expect("private cwd");
    std::fs::copy(
        std::env::var_os("R2_REAL_INPUT").expect("private mini"),
        root.join("raw"),
    )
    .expect("new sample copy");
    let directory = root.join("crashed");
    std::fs::create_dir(&directory).expect("private recovery target");
    let target = directory.join("input.i64");
    let router = RouterState::new().expect("router");
    let mut environment: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("R4_REAL_R9_TARGET".into(), target.display().to_string());
    let bridge = router
        .connect_nexus(BridgeConfig {
            python: PathBuf::from(std::env::var_os("R3A_PYTHON").expect("prepared SDK")),
            script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/r4_real_bridge.py"),
            directory: root.join("i"),
            environment,
        })
        .await
        .expect("actual installed bridge/helper/native runtime");
    let mut tokens = Vec::new();
    let mut source_leases = Vec::new();
    let result:anyhow::Result<Value>=async {
        let seeded=seed(&bridge,&root).await?;
        std::fs::copy(root.join("seed.i64"),&target)?;
        let client=ClientId::new("r4-native-source")?;
        let mut events=bridge.subscribe();
        let source=real_open(&bridge,&mut events,&client,&root.join("seed.i64"),"r4-copy-source").await?;
        source_leases.push(source.clone());
        let code=format!("import ida_loader, pathlib, shutil, os, hashlib\nida_loader.flush_buffers()\ns=pathlib.Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))\nd=pathlib.Path({})\nfiles={{}}\nfor ext in ('.id0','.id1','.id2','.nam','.til'):\n p=s.with_suffix(ext)\n if p.is_file():\n  out=d/('input'+ext)\n  shutil.copyfile(p,out)\n  out.chmod(0o600)\n  f=os.open(out,os.O_RDONLY)\n  os.fsync(f)\n  os.close(f)\n  files[out.name]={{'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'size':out.stat().st_size}}\nresult=files",
            serde_json::to_string(&directory.canonicalize()?.display().to_string())?);
        let copied=real_execute(&bridge,&mut events,&source,code).await?;
        anyhow::ensure!(copied["result"]["result"]["input.id0"].is_object(),"native unpacked copy missing: {copied}");
        bridge.endpoint().transition(|s,t|s.release(&client,&source,t))?;
        tokio::time::timeout(Duration::from_secs(20),async {
            while bridge.lifecycle_status()["resources"]!=0 {tokio::time::sleep(Duration::from_millis(10)).await;}
        }).await?;
        let (handle,token)=router.ensure_worker_prepared(target.to_str().expect("path"),None,None,
            Preparation::new(Duration::from_secs(60))).await?;
        tokens.push(token.clone());
        let restored:Value=serde_json::from_slice(&std::fs::read(root.join("r4-restored-before-next.json"))?)?;
        anyhow::ensure!(restored["record"]["status"]=="restored" && restored["record"]["job"]["state"]=="Completed");
        for (name,metadata) in restored["record"]["snapshot_files"].as_object().expect("snapshot files") {
            anyhow::ensure!(restored["actual_sha256"][name]==metadata["sha256"],"restored component differs: {name}");
        }
        anyhow::ensure!(restored["record"]["attempts"].as_array().expect("attempts").len()==1);
        let code=json!({"code":"import ida_ida, ida_bytes\nprint(ida_bytes.get_cmt(ida_ida.inf_get_min_ea(), False))"});
        let read=router.route_request_prepared(Some(&handle),"run_script",code.clone(),Preparation::new(Duration::from_secs(30))).await?;
        anyhow::ensure!(read["success"]==true && read["stdout"]=="r3b_verified_saved\n","{read}");
        router.nexus_close_token(&token).await?;
        let (again,reopened)=router.ensure_worker_prepared(target.to_str().expect("path"),None,None,
            Preparation::new(Duration::from_secs(30))).await?;
        tokens.push(reopened.clone());
        let reread=router.route_request_prepared(Some(&again),"run_script",code,Preparation::new(Duration::from_secs(30))).await?;
        anyhow::ensure!(reread["success"]==true && reread["stdout"]==read["stdout"],"new request read changed: {reread}");
        router.nexus_close_token(&reopened).await?;
        Ok(json!({"seed":seeded,"native_unpacked":copied,"restored_before_retry":restored,
            "read":read,"new_request_read":reread,"scope":"actual IDA 9.5; one injected Root observation, not natural corruption/reboot"}))
    }.await;
    let mut cleanup = Vec::new();
    for lease in source_leases {
        let closed = bridge
            .endpoint()
            .transition(|s, t| s.release(&lease.client_id, &lease, t));
        cleanup.push(format!("source lease: {closed:?}"));
    }
    for token in tokens {
        let closed = router.nexus_close_token(&token).await;
        cleanup.push(format!("caller lease: {closed:?}"));
    }
    std::fs::write(
        root.join("real-r4-finally-close.json"),
        serde_json::to_vec_pretty(&cleanup).expect("JSON"),
    )
    .expect("cleanup evidence");
    let settled = tokio::time::timeout(Duration::from_secs(20), async {
        while bridge.lifecycle_status()["resources"] != 0
            || bridge.lifecycle_status()["helper"]["file_jobs_pending"] != 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let stopped = bridge.shutdown().await;
    std::fs::write(root.join("real-r4-result.json"),serde_json::to_vec_pretty(&json!({"result":format!("{result:?}"),"actual":result.as_ref().ok(),
        "settled":format!("{settled:?}"),"shutdown":format!("{stopped:?}"),"lifecycle":bridge.lifecycle_status()})).expect("JSON")).expect("evidence");
    settled.expect("native ownership/job natural closure");
    stopped.expect("actual native/helper natural shutdown");
    result.expect("actual native r9 file restore and fresh read");
    if std::env::var_os("R4_PARENT_SCHEDULE").is_some() {
        let reserved: Value = serde_json::from_slice(
            &std::fs::read(root.join("successor-reserved.json"))
                .expect("scheduled successor evidence"),
        )
        .expect("structured reservation evidence");
        assert_eq!(
            reserved["retirement_still_paused"], false,
            "retry reserved before predecessor helper retirement"
        );
        assert_eq!(reserved["acquisition"]["ordinal"], 2);
        assert_eq!(reserved["acquisition"]["purpose"], "initial_root_retry");
    }
}
