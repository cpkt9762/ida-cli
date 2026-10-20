//! Mixed legacy/generation metadata must be cleaned independently.
use ida_mcp::idb_store::IdbStore;
#[test]
fn mixed_indices_preserve_each_healthy_target() {
    let root = std::env::temp_dir().join(format!("n7f2-store-{}", std::process::id()));
    std::fs::create_dir_all(root.join("generations/live")).unwrap();
    let good = root.join("generations/live/input.i64");
    std::fs::write(&good, b"healthy generation").unwrap();
    let flat = root.join("source.mixed.native.i64");
    std::fs::write(&flat, b"healthy legacy with user edits").unwrap();
    let entry = |key| serde_json::json!({"hash":key,"original_path":"source","binary_type":"native","size":1,"created_at":"1Z","last_accessed":"1Z"});
    let legacy =
        serde_json::json!({"mixed":entry("mixed"),"good":entry("good"),"orphan":entry("orphan")});
    std::fs::write(
        root.join("index.json"),
        serde_json::to_vec(&legacy).unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("nexus-index.json"), br#"{"mixed":"generations/missing/input.i64","good":"generations/live/input.i64","orphan":"generations/gone/input.i64"}"#).unwrap();
    let store = IdbStore::with_root(root.clone());
    let removed = store.clean();
    let legacy_after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("index.json")).unwrap()).unwrap();
    let nexus_after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("nexus-index.json")).unwrap()).unwrap();
    assert_eq!(
        removed.iter().map(|e| e.hash.as_str()).collect::<Vec<_>>(),
        vec!["orphan"]
    );
    assert_eq!(legacy_after, serde_json::json!({"mixed":entry("mixed")}));
    assert_eq!(
        nexus_after,
        serde_json::json!({"good":"generations/live/input.i64"})
    );
    assert_eq!(store.lookup_by_hash("mixed"), Some(flat.clone()));
    assert_eq!(
        std::fs::read(flat).unwrap(),
        b"healthy legacy with user edits"
    );
    assert!(good.is_file());
    assert!(store.clean().is_empty());
    // A stale pointer must be persisted away even when no entire key is removed.
    std::fs::write(
        root.join("nexus-index.json"),
        br#"{"mixed":"generations/missing/input.i64","good":"generations/live/input.i64"}"#,
    )
    .unwrap();
    assert!(store.clean().is_empty());
    let pointers: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("nexus-index.json")).unwrap()).unwrap();
    assert_eq!(
        pointers,
        serde_json::json!({"good":"generations/live/input.i64"})
    );
    std::fs::remove_dir_all(root).unwrap();
}
