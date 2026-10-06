#[path = "shared/ida_install.rs"]
mod ida_install;

use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-env-changed=IDADIR");

    let install_path = ida_install::find_runtime_dir();
    if let Some(path) = install_path.as_ref() {
        env::set_var("IDADIR", path);
    }

    if install_path.is_none() {
        println!("cargo::warning=IDA installation not found, using SDK stubs");
        idalib_build::configure_idasdk_linkage();
    } else {
        // Configure linkage to IDA libraries
        idalib_build::configure_linkage()?;
    }

    // Add detected runtime locations so the binary can find IDA without
    // relying on version-specific hardcoded paths.
    set_rpaths(install_path.as_deref());

    // The native layer hardcodes private IDA layouts per SDK version, so the
    // runtime probe needs to know which SDK this binary was compiled against.
    let sdk_version = sdk_version()?;
    println!("cargo::rustc-env=IDA_CLI_SDK_VERSION={sdk_version}");

    Ok(())
}

fn sdk_version() -> Result<u32, Box<dyn std::error::Error>> {
    let (sdk_path, _, _, _) = idalib_build::idalib_sdk_paths_with(false);
    let pro_h = sdk_path.join("include").join("pro.h");
    println!("cargo::rerun-if-changed={}", pro_h.display());

    let source = std::fs::read_to_string(&pro_h)
        .map_err(|e| format!("cannot read {}: {e}", pro_h.display()))?;
    source
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some("#define"), Some("IDA_SDK_VERSION"), Some(value)) => value.parse().ok(),
                _ => None,
            }
        })
        .ok_or_else(|| format!("IDA_SDK_VERSION not found in {}", pro_h.display()).into())
}

fn set_rpaths(install_path: Option<&Path>) {
    for path in ida_install::runtime_rpath_dirs(install_path) {
        add_rpath(&path);
    }
}

fn add_rpath(path: &Path) {
    println!("cargo::rustc-link-arg=-Wl,-rpath,{}", path.display());
}
