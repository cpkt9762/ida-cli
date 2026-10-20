//! N7b special-input production entry contracts.
use ida_mcp::router::nexus_tools::Tools;
#[test]
fn dsc_tools_have_nexus_paths() {
    for method in ["open_dsc", "dsc_add_dylib", "dsc_add_region"] {
        Tools::require_tool(method).expect("DSC adapter must use Nexus, without legacy fallback");
    }
}
#[test]
fn dsc_initial_builder_refuses_failed_plugin() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let stub = r#"
import sys, types
api = types.ModuleType('idaapi')
class Node:
    def create(self, *_): pass
    def supset(self, *_): pass
api.netnode = Node
sys.modules['idaapi'] = api
idc = types.ModuleType('idc')
idc.load_and_run_plugin = lambda *_: 0
idc.auto_mark_range = lambda *_: None
idc.auto_wait = lambda: None
idc.BADADDR = -1
idc.AU_FINAL = 1
idc.qexit = lambda code: sys.exit(code)
sys.modules['idc'] = idc
"#;
    let mut child = Command::new("timeout")
        .args(["30s", "python3", "-B", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("private Python script regression");
    child
        .stdin
        .take()
        .expect("script stdin")
        .write_all(
            format!(
                "{stub}\n{}",
                ida_mcp::dsc::dsc_load_script("/missing.dylib", &[])
            )
            .as_bytes(),
        )
        .expect("write generated script");
    let output = child.wait_with_output().expect("bounded Python exit");
    assert_eq!(
        output.status.code(),
        Some(1),
        "failed dscu must abort offline build"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("dscu plugin failed"),
        "diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn sbx_temporary_inputs_belong_to_the_cleaned_task_stage() {
    use ida_mcp::sbpf;
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("n7b-sbx-tmp-{}", std::process::id()));
    std::fs::create_dir(&root).expect("private sbx test root");
    let executable = root.join("sbx");
    let report = root.join("child-temp-path");
    std::fs::write(&executable, format!("#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\nroot=Path(os.environ['TMPDIR'])/'sbpf_emit_fixture'\nroot.mkdir()\n(root/'input').write_bytes(b'private temporary input')\nPath({:?}).write_text(str(root))\nPath(sys.argv[-1]).write_bytes(b'offline output fixture')\n", report.to_str().expect("UTF-8 report"))).expect("fake offline builder");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    let input = root.join("program.so");
    std::fs::write(&input, b"input fixture").expect("source fixture");
    let previous = std::env::var_os("SBX");
    // SAFETY: this integration target runs serially; no sibling uses SBX.
    unsafe {
        std::env::set_var("SBX", &executable);
    }
    let result = sbpf::run_sbx_aot_i64(
        &input,
        &root.join("output.i64"),
        ida_mcp::preprocess::Preparation::new(std::time::Duration::from_secs(10)),
    )
    .await;
    // SAFETY: restore the test-local override before assertions.
    unsafe {
        match previous {
            Some(value) => std::env::set_var("SBX", value),
            None => std::env::remove_var("SBX"),
        }
    }
    result.expect("offline builder and cleanup");
    let child_temp = std::path::PathBuf::from(
        std::fs::read_to_string(report).expect("observed builder temporary path"),
    );
    assert!(
        !child_temp.exists(),
        "task-owned temporary inputs leaked: {}",
        child_temp.display()
    );
    assert_eq!(
        std::fs::read(root.join("output.i64")).expect("published output"),
        b"offline output fixture"
    );
    std::fs::remove_dir_all(root).expect("remove private sbx fixture");
}
