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

    Ok(())
}

fn set_rpaths(install_path: Option<&Path>) {
    for path in ida_install::runtime_rpath_dirs(install_path) {
        add_rpath(&path);
    }
}

fn add_rpath(path: &Path) {
    println!("cargo::rustc-link-arg=-Wl,-rpath,{}", path.display());
}
