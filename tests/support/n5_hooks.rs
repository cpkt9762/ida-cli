//! Hook consistency and lease lifetime acceptance on real IDA.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n5_hooks_external_modifications_and_fail_closed_state_loss() {
    let mut a = Client::new().await;
    let mut b = Client::new().await;
    let (la, _) = a
        .open(&sample("n5-hooks"), json!({"wait_analysis":true}))
        .await;
    let (lb, _) = b
        .open(
            &sample("n5-hooks"),
            json!({"attach_instance":la.instance_id.as_str()}),
        )
        .await;
    let ea = a
        .value(
            &la,
            "execute_python",
            json!({"code":"import ida_funcs\nresult=ida_funcs.getn_func(0).start_ea"}),
        )
        .await
        .as_u64()
        .unwrap();
    assert_eq!(
        a.value(
            &la,
            "execute_python",
            json!({"code":"result=True","n5_subscription":"start"})
        )
        .await,
        true
    );
    let mut checks = Vec::new();
    let mutations=vec![
        ("rename",format!("import ida_name\nresult=ida_name.set_name({ea},'N5_EXTERNAL_NAME',ida_name.SN_CHECK)"),"数据库已变化"),
        ("comment",format!("import ida_bytes\nresult=ida_bytes.set_cmt({ea},'N5_EXTERNAL_COMMENT',False)"),"数据库已变化"),
        ("type",format!("import ida_typeinf\nt=ida_typeinf.tinfo_t()\nassert ida_typeinf.parse_decl(t,None,'long n5_type(long a, long b);',0)\nresult=ida_typeinf.apply_tinfo({ea},t,ida_typeinf.TINFO_DEFINITE)"),"数据库已变化"),
        ("hook-object","import sys\nsys.modules['_ida_cli_nexus_slices_v1'].counter=None\nresult=True".into(),"一致性无法确认"),
        ("installation","import sys\nsys.modules['_ida_cli_nexus_slices_v1'].counter.installation='missing'\nresult=True".into(),"一致性无法确认"),
        ("counter-format","import sys\nsys.modules['_ida_cli_nexus_slices_v1'].counter.revision='invalid'\nresult=True".into(),"一致性无法确认"),
        ("private-module","import sys\nm=sys.modules.pop('_ida_cli_nexus_slices_v1')\nm.counter.unhook()\nresult=True".into(),"一致性无法确认"),
    ];
    for (label, code, expected) in mutations {
        let job = id();
        let long = a.begin(
            &la,
            "batch_decompile",
            json!({"_n5_job":job,"addresses":[ea,ea,ea]}),
        );
        a.event(|v| {
            v["event"] == "yielded"
                && v["attempt"]["target"]["identity"]["operation_id"] == long.operation_id.as_str()
        })
        .await;
        assert_eq!(
            b.value(&lb, "execute_python", json!({"code":code})).await,
            true
        );
        dispatch(&a.bridge, &long);
        let failed = terminal(&a.bridge, &long).await;
        assert_eq!(
            failed.status,
            OperationStatus::Succeeded,
            "{label}: native execution returned a business failure: {failed:?}"
        );
        let business = &failed.result.unwrap()["result"];
        assert_eq!(business["ok"], false, "{label}: {business}");
        assert!(
            business["error"].as_str().unwrap().contains(expected),
            "{label}: expected {expected}: {business}"
        );
        checks.push(label);
        a.value(&la, "_n5_cleanup", json!({"_n5_job":job})).await;
    }
    assert_eq!(
        a.value(
            &la,
            "execute_python",
            json!({"code":"result=True","n5_subscription":"drain"})
        )
        .await,
        true
    );
    assert!(
        std::fs::metadata(root().join("n5-subscription-drained"))
            .unwrap()
            .len()
            > 0,
        "public event stream was intentionally unconsumed during hook checks"
    );
    let job = id();
    let own = a.begin(
        &la,
        "batch_decompile",
        json!({"_n5_job":job,"addresses":[ea,ea,ea,ea]}),
    );
    let result = terminal(&a.bridge, &own).await;
    assert_eq!(
        result.status,
        OperationStatus::Succeeded,
        "self decompilation must not cause false change"
    );
    assert_eq!(
        result.result.unwrap()["result"]["value"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    close(&mut a, &la).await;
    close(&mut b, &lb).await;
    passed("N5-hooks", json!({"aborts":checks,"self_decompile":4}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n5_hooks_shared_references_install_failure_and_lease_release() {
    let mut a = Client::new().await;
    let mut b = Client::new().await;
    let mut inspector = Client::new().await;
    let path = sample("n5-refs");
    let (la, _) = a.open(&path, json!({"wait_analysis":true})).await;
    let (lb, _) = b
        .open(&path, json!({"attach_instance":la.instance_id.as_str()}))
        .await;
    let (li, _) = inspector
        .open(&path, json!({"attach_instance":la.instance_id.as_str()}))
        .await;
    let ea = a
        .value(
            &la,
            "execute_python",
            json!({"code":"import ida_funcs\nresult=ida_funcs.getn_func(0).start_ea"}),
        )
        .await;
    let ja = id();
    let jb = id();
    let oa = a.begin(
        &la,
        "batch_decompile",
        json!({"_n5_job":ja,"addresses":[ea.clone(),ea.clone()]}),
    );
    a.event(|v| v["event"] == "yielded").await;
    let ob = b.begin(
        &lb,
        "batch_decompile",
        json!({"_n5_job":jb,"addresses":[ea.clone(),ea.clone()]}),
    );
    b.event(|v| v["event"] == "yielded").await;
    assert_eq!(inspector.value(&li,"execute_python",json!({"code":"import sys\nm=sys.modules['_ida_cli_nexus_slices_v1']\nresult=[len(m.jobs),m.counter is not None]"})).await,json!([2,true]));
    assert_eq!(cancel(&a.bridge, &oa).status, OperationStatus::Cancelled);
    close(&mut a, &la).await;
    assert_eq!(
        inspector.value(
            &li,
            "execute_python",
            json!({"code":"import sys\nm=sys.modules['_ida_cli_nexus_slices_v1']\nresult=[len(m.jobs),m.counter is not None]"})
        )
        .await,
        json!([1, true])
    );
    assert_eq!(
        terminal(&b.bridge, &ob).await.result.unwrap()["result"]["ok"],
        true
    );
    assert_eq!(
        inspector.value(
            &li,
            "execute_python",
            json!({"code":"import sys\nm=sys.modules['_ida_cli_nexus_slices_v1']\nresult=[len(m.jobs),m.counter is None]"})
        )
        .await,
        json!([0, true])
    );
    b.value(&lb,"execute_python",json!({"code":"import ida_idp\nida_idp._n5_hook_original=ida_idp.IDB_Hooks.hook\nida_idp.IDB_Hooks.hook=lambda self:False\nresult=True"})).await;
    let fail = b.begin(
        &lb,
        "batch_decompile",
        json!({"_n5_job":id(),"addresses":[ea]}),
    );
    let business = terminal(&b.bridge, &fail).await.result.unwrap()["result"].clone();
    assert_eq!(business["ok"], false);
    assert!(business["error"]
        .as_str()
        .unwrap()
        .contains("一致性无法确认"));
    b.value(
        &lb,
        "execute_python",
        json!({"code":"import ida_idp\nida_idp.IDB_Hooks.hook=ida_idp._n5_hook_original\nresult=True"}),
    )
    .await;
    close(&mut b, &lb).await;
    close(&mut inspector, &li).await;
    passed("N5-lifecycle",json!("two leases share counter; releasing cancelled A retains B; last job unhooks; failed installation closes"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n5_hooks_bridge_loss_and_reconnection_reject_old_checkpoint() {
    let mut a = Client::new().await;
    let mut b = Client::new().await;
    let path = sample("n5-reconnect");
    let (la, opened) = a.open(&path, json!({"wait_analysis":true})).await;
    let (lb, _) = b
        .open(&path, json!({"attach_instance":la.instance_id.as_str()}))
        .await;
    let job = id();
    let op = a.begin(
        &la,
        "batch_decompile",
        json!({"_n5_job":job,"addresses":["bad","bad"]}),
    );
    let yielded = a.event(|v| v["event"] == "yielded").await;
    let checkpoint = yielded["checkpoint"].clone();
    let retry = b.begin(
        &lb,
        "batch_decompile",
        json!({"_n5_job":job,"_n5_checkpoint":checkpoint.clone(),"addresses":["bad","bad"]}),
    );
    let failure = terminal(&b.bridge, &retry).await.result.unwrap()["result"].clone();
    assert_eq!(failure["ok"], false);
    assert!(failure["error"]
        .as_str()
        .unwrap()
        .contains("一致性无法确认"));
    assert_eq!(b.value(&lb,"execute_python",json!({"code":"import sys\nm=sys.modules['_ida_cli_nexus_slices_v1']\nresult=len(m.jobs)"})).await,1,"foreign lease cannot release A's reference");
    // Exact owned bridge identity, also registered in the suite process ledger.
    assert_eq!(unsafe { libc::kill(a.bridge.pid as i32, libc::SIGKILL) }, 0);
    a.event(|v| v["event"] == "bridge_disconnected").await;
    assert!(snapshot(&a.bridge, &op).status.is_terminal());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let refs = response(b.value(
            &lb,
            "execute_python",
            json!({"code":"import sys\nm=sys.modules['_ida_cli_nexus_slices_v1']\nresult=[len(m.jobs),m.counter is None,len(m.watchers)]"}),
        ))
        .await;
        if refs == json!([0, true, 0]) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "dead bridge references must release via public queue"
        );
        tokio::task::yield_now().await;
    }
    close(&mut b, &lb).await;
    a.bridge.shutdown().await.unwrap();
    let pid = opened["pid"].as_u64().unwrap() as i32;
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        while unsafe { libc::kill(pid, 0) } == 0 {
            tick.tick().await;
        }
    })
    .await
    .expect("owned owner exit/public lease grace barrier");
    let mut c = Client::new().await;
    let (lc, _) = c.open(&path, json!({})).await;
    assert_ne!(lc.instance_id, la.instance_id, "new owner instance");
    let retry = c.begin(
        &lc,
        "batch_decompile",
        json!({"_n5_job":job,"_n5_checkpoint":checkpoint,"addresses":["bad","bad"]}),
    );
    let result = terminal(&c.bridge, &retry).await.result.unwrap()["result"].clone();
    assert_eq!(result["ok"], false);
    assert!(result["error"].as_str().unwrap().contains("一致性无法确认"));
    close(&mut c, &lc).await;
    passed("N5-reconnect",json!("foreign lease continuation rejected; killed bridge cleans only its jobs; new owner rejects old checkpoint"));
}
