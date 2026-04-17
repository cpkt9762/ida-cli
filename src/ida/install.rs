#[path = "../../shared/ida_install.rs"]
mod shared;

pub use shared::{
    candidate_install_dirs, configured_install_dir, find_idat_binary, find_runtime_dir,
    has_runtime_libraries, idat_binary, normalize_install_dir, runtime_rpath_dirs,
};
