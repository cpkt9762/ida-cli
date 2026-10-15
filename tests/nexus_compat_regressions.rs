use ida_mcp::server::response_cache::guard_response_size;
use serde_json::json;

// Each integration target is a separate process. This test uses only its own
// home and leaves the caller's home and all existing cache entries untouched.
#[tokio::test(flavor = "current_thread")]
async fn cache_failures_preserve_complete_success_and_successful_cache_shape() {
    let directory = std::env::temp_dir().join(format!("n2-f3-cache-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::env::set_var("IDA_CLI_HOME", &directory);
    let responses = directory.join("responses");
    std::fs::write(&responses, "fixture: not a directory").unwrap();
    let value = json!({"stdout":"Unicode 输出🙂\n".repeat(300), "result":{"mutated":true},
        "errors":["script stderr preserved"],"functions":(0..200).map(|i|json!({"name":format!("f{i}")})).collect::<Vec<_>>()});
    let inline = guard_response_size("run_script", value.clone())
        .await
        .unwrap();
    assert_eq!(
        inline, value,
        "directory failure must preserve success exactly"
    );
    std::fs::remove_file(&responses).unwrap();
    let cached = guard_response_size("run_script", value.clone())
        .await
        .unwrap();
    assert_eq!(cached["cached"], true);
    assert_eq!(cached["item_count"], 200);
    let file = std::path::PathBuf::from(cached["file"].as_str().unwrap());
    let bytes = std::fs::read(&file).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        value
    );
    assert_eq!(cached["size_bytes"], bytes.len());
    assert!(cached["summary"]
        .as_str()
        .unwrap()
        .contains(file.to_str().unwrap()));
    std::fs::remove_file(&file).unwrap();
    std::fs::create_dir(&file).unwrap();
    assert_eq!(
        guard_response_size("run_script", value.clone())
            .await
            .unwrap(),
        value,
        "write failure must preserve success exactly"
    );
    std::fs::remove_dir_all(directory).unwrap();
}
