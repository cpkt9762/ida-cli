//! Profile selection and cache isolation through the production preparation path.
use ida_mcp::{preprocess::Preparation, router::nexus_bridge::cache::prepare_n7_open};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};

#[tokio::test]
async fn sbpf_profile_arguments_and_cache_identity() {
    use ida_mcp::process_spawn::StdOutputFenced;
    if std::env::var_os("SBX_PROFILE_CASE").is_none() {
        let root = std::env::temp_dir().join(format!("sbx-profile-{}", std::process::id()));
        std::fs::create_dir(&root).expect("private profile fixture");
        let source = root.join("program.so");
        let mut elf = [0; 20];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[18..20].copy_from_slice(&247u16.to_le_bytes());
        std::fs::write(&source, elf).expect("sBPF source snapshot");
        let cache = root.join("cache");
        std::fs::create_dir(&cache).expect("private cache");
        let old = cache.join("generations/old");
        std::fs::create_dir_all(&old).expect("old generation");
        std::fs::write(old.join("input"), elf).expect("old raw snapshot");
        std::fs::write(old.join("input.i64"), b"unknown old profile").expect("old packed IDB");
        let short = blake3::hash(&elf).to_hex()[..12].to_string();
        std::fs::write(
            old.join("generation.json"),
            serde_json::to_vec(&serde_json::json!({"version":1,"key":short}))
                .expect("old manifest JSON"),
        )
        .expect("old manifest");
        std::fs::write(
            cache.join("nexus-index.json"),
            serde_json::to_vec(&serde_json::json!({short.clone():"generations/old/input.i64"}))
                .expect("index JSON"),
        )
        .expect("old index");
        let flat = cache.join(format!("program.so.{short}.dylib"));
        std::fs::write(&flat, elf).expect("old flat source");
        std::fs::write(
            PathBuf::from(format!("{}.i64", flat.display())),
            b"unknown flat profile",
        )
        .expect("old flat database");
        for name in [
            "default",
            "analysis-inline",
            "trace",
            "optimized",
            "",
            "Analysis",
            "inline",
            "optimised",
        ] {
            let mut child =
                std::process::Command::new(std::env::current_exe().expect("test executable"));
            child
                .args([
                    "--exact",
                    "sbpf_profile_arguments_and_cache_identity",
                    "--nocapture",
                ])
                .env("SBX_PROFILE_CASE", name)
                .env("SBX_PROFILE_ROOT", &root);
            if name == "default" {
                child.env_remove("IDA_CLI_SBX_PROFILE");
            } else {
                child.env("IDA_CLI_SBX_PROFILE", name);
            }
            let status = child
                .status_fenced()
                .expect("isolated profile child terminal");
            assert!(
                status.success(),
                "profile {name:?}: {status}; fixture {}",
                root.display()
            );
        }
        let paths = ["default", "analysis-inline", "trace"].map(|name| {
            std::fs::read_to_string(root.join(format!("{name}.path"))).expect("chosen profile path")
        });
        assert_ne!(paths[0], paths[1]);
        assert_ne!(paths[0], paths[2]);
        assert_ne!(paths[1], paths[2]);
        assert_eq!(
            std::fs::read(old.join("input.i64")).expect("preserved old IDB"),
            b"unknown old profile"
        );
        std::fs::remove_dir_all(root).expect("remove only this owned fixture");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let root = PathBuf::from(std::env::var_os("SBX_PROFILE_ROOT").expect("isolated fixture root"));
    let profile = std::env::var("SBX_PROFILE_CASE").expect("case selector");
    let executable = root.join("sbx");
    std::fs::write(
        &executable,
        format!(
            r#"#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with open({:?}, 'a') as out: out.write(json.dumps(sys.argv[1:])+'\n')
if 'optimized' in sys.argv:
    sys.stderr.write('fixture optimized refusal')
    sys.exit(7)
Path(sys.argv[sys.argv.index('--output')+1]).write_bytes(b'profile database')
"#,
            root.join("calls.jsonl").to_str().expect("UTF-8 fixture")
        ),
    )
    .expect("recording sbx fixture");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable mode");
    // Only this child mutates its environment, before spawning any builder.
    unsafe {
        std::env::set_var("SBX", executable);
    }
    let count = || match std::fs::read_to_string(root.join("calls.jsonl")) {
        Ok(text) => text.lines().count(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => panic!("read fixture calls: {error}"),
    };
    let before = count();
    let prep = Preparation::new(Duration::from_secs(10));
    let first = prepare_n7_open(root.join("program.so"), root.join("cache"), &prep, false).await;
    if !matches!(
        profile.as_str(),
        "default" | "analysis-inline" | "trace" | "optimized"
    ) {
        let error = first.err().expect("invalid profile must fail");
        assert!(
            matches!(error, ida_mcp::error::ToolError::InvalidParams(_)),
            "{error}"
        );
        assert!(error.to_string().contains("IDA_CLI_SBX_PROFILE"), "{error}");
        assert_eq!(count(), before, "invalid profile cannot invoke sbx");
        return;
    }
    if profile == "optimized" {
        let error = first.err().expect("sbx rejection must fail");
        assert!(
            error.to_string().contains("fixture optimized refusal"),
            "{error}"
        );
        assert_eq!(count(), before + 1);
        return;
    }
    let first = first.expect("profile database preparation");
    assert_eq!(
        count(),
        before + 1,
        "old profile-less cache must never satisfy a profile open"
    );
    let calls = std::fs::read_to_string(root.join("calls.jsonl")).expect("actual sbx arguments");
    let args: Vec<String> =
        serde_json::from_str(calls.lines().last().expect("one sbx call")).expect("argv JSON");
    let expected = if profile == "trace" {
        "trace"
    } else {
        "analysis"
    };
    assert!(
        args.windows(2).any(|p| p == ["--profile", expected]),
        "explicit {expected}: {args:?}"
    );
    assert_eq!(
        args.iter().any(|a| a == "--inline"),
        profile == "analysis-inline"
    );
    let chosen = first.path.clone();
    first
        .publish_verified_input(&prep)
        .await
        .expect("publish selected profile index");
    drop(first);
    let second = prepare_n7_open(root.join("program.so"), root.join("cache"), &prep, false)
        .await
        .expect("same profile hit");
    assert_eq!(second.path, chosen);
    assert_eq!(count(), before + 1, "same profile cache must not rebuild");
    let index: Value = serde_json::from_slice(
        &std::fs::read(root.join("cache/nexus-index.json")).expect("current index"),
    )
    .expect("index JSON");
    assert!(
        index
            .as_object()
            .expect("index object")
            .keys()
            .any(|k| k.contains(if profile == "default" {
                "analysis"
            } else {
                &profile
            })),
        "profile recorded in generation identity: {index}"
    );
    std::fs::write(
        root.join(format!("{profile}.path")),
        chosen.to_string_lossy().as_bytes(),
    )
    .expect("record profile identity");
    drop(second);
    let manifest = chosen.with_file_name("generation.json");
    let original = std::fs::read(&manifest).expect("profile manifest");
    std::fs::write(&manifest, br#"{"version":1,"key":"unknown-old-profile"}"#)
        .expect("controlled wrong profile binding");
    let refused = prepare_n7_open(root.join("program.so"), root.join("cache"), &prep, false).await;
    let error = refused
        .err()
        .expect("wrong manifest cannot authorize cache hit");
    assert!(
        error.to_string().contains("profile identity mismatch"),
        "{error}"
    );
    assert_eq!(
        count(),
        before + 1,
        "corrupt profile proof is an error, not a rebuild fallback"
    );
    std::fs::write(manifest, original).expect("restore this fixture manifest");
}
