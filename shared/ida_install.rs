use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

fn target_os() -> &'static str {
    match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => "macos",
        Ok("linux") => "linux",
        Ok("windows") => "windows",
        _ if cfg!(target_os = "macos") => "macos",
        _ if cfg!(target_os = "linux") => "linux",
        _ if cfg!(target_os = "windows") => "windows",
        _ => "unknown",
    }
}

fn runtime_library_names() -> (&'static str, &'static str) {
    match target_os() {
        "macos" => ("libida.dylib", "libidalib.dylib"),
        "linux" => ("libida.so", "libidalib.so"),
        "windows" => ("ida.dll", "idalib.dll"),
        _ => ("ida", "idalib"),
    }
}

fn idat_name() -> &'static str {
    if target_os() == "windows" {
        "idat.exe"
    } else {
        "idat"
    }
}

fn file_name_eq(path: &Path, name: &str) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(|s| s.eq_ignore_ascii_case(name))
        .unwrap_or(false)
}

pub fn normalize_install_dir(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();

    if path.is_file() {
        return path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.to_path_buf());
    }

    if target_os() == "macos" {
        if path
            .extension()
            .and_then(OsStr::to_str)
            .map(|ext| ext.eq_ignore_ascii_case("app"))
            .unwrap_or(false)
        {
            return path.join("Contents").join("MacOS");
        }

        if file_name_eq(path, "Contents") {
            return path.join("MacOS");
        }
    }

    path.to_path_buf()
}

pub fn configured_install_dir() -> Option<PathBuf> {
    env::var_os("IDADIR")
        .map(PathBuf::from)
        .map(normalize_install_dir)
}

pub fn has_runtime_libraries(path: &Path) -> bool {
    let path = normalize_install_dir(path);
    let (ida, idalib) = runtime_library_names();
    path.join(ida).exists() && path.join(idalib).exists()
}

pub fn idat_binary(path: &Path) -> Option<PathBuf> {
    let path = normalize_install_dir(path);
    let idat = path.join(idat_name());
    idat.exists().then_some(idat)
}

fn version_hint(path: &Path) -> String {
    if target_os() == "macos" && file_name_eq(path, "MacOS") {
        if let Some(app_name) = path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(OsStr::to_str)
        {
            return app_name.to_string();
        }
    }

    path.file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_string()
}

fn version_key(path: &Path) -> Vec<u32> {
    let mut best = Vec::new();
    let mut current = String::new();
    let hint = version_hint(path);

    for ch in hint.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            current.push(ch);
            continue;
        }

        if !current.is_empty() {
            let parsed = current
                .split('.')
                .filter_map(|part| part.parse::<u32>().ok())
                .collect::<Vec<_>>();
            if !parsed.is_empty() && parsed > best {
                best = parsed;
            }
            current.clear();
        }
    }

    if !current.is_empty() {
        let parsed = current
            .split('.')
            .filter_map(|part| part.parse::<u32>().ok())
            .collect::<Vec<_>>();
        if !parsed.is_empty() && parsed > best {
            best = parsed;
        }
    }

    best
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn candidate_install_dirs_in(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return paths;
    };

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }

        let raw_path = entry.path();
        let path = normalize_install_dir(&raw_path);
        if has_runtime_libraries(&path) || idat_binary(&path).is_some() {
            push_unique(&mut paths, path);
        }
    }

    paths
}

pub fn candidate_install_dirs() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(path) = configured_install_dir() {
        push_unique(&mut paths, path);
    }

    match target_os() {
        "macos" => {
            for root in [
                Some(PathBuf::from("/Applications")),
                home_applications_dir(),
            ] {
                for path in root
                    .into_iter()
                    .flat_map(|root| candidate_install_dirs_in(&root))
                {
                    push_unique(&mut paths, path);
                }
            }
        }
        "linux" => {
            let roots = [
                env::var_os("HOME").map(PathBuf::from),
                Some(PathBuf::from("/opt")),
                Some(PathBuf::from("/usr/local")),
            ];
            for root in roots.into_iter().flatten() {
                for path in candidate_install_dirs_in(&root) {
                    push_unique(&mut paths, path);
                }
            }
        }
        "windows" => {
            let roots = [
                env::var_os("ProgramFiles").map(PathBuf::from),
                env::var_os("ProgramFiles(x86)").map(PathBuf::from),
            ];
            for root in roots.into_iter().flatten() {
                for path in candidate_install_dirs_in(&root) {
                    push_unique(&mut paths, path);
                }
            }
        }
        _ => {}
    }

    paths.sort_by(|lhs, rhs| {
        version_key(rhs)
            .cmp(&version_key(lhs))
            .then_with(|| lhs.as_os_str().cmp(rhs.as_os_str()))
    });

    paths
}

fn home_applications_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(|home| PathBuf::from(home).join("Applications"))
}

pub fn find_runtime_dir() -> Option<PathBuf> {
    if let Some(path) = configured_install_dir().filter(|path| has_runtime_libraries(path)) {
        return Some(path);
    }

    candidate_install_dirs()
        .into_iter()
        .find(|path| has_runtime_libraries(path))
}

// `find_idat_binary` is consumed by `src/dsc.rs` and `src/ida/install.rs`,
// but the file is also included (via `#[path]`) into build scripts that do
// not reach those call sites. Without this suppression every build script
// that uses the shared module warns about a stale definition.
#[allow(dead_code)]
pub fn find_idat_binary() -> Option<PathBuf> {
    if let Some(path) = configured_install_dir().and_then(|path| idat_binary(&path)) {
        return Some(path);
    }

    candidate_install_dirs()
        .into_iter()
        .find_map(|path| idat_binary(&path))
}

// Consumed by the top-level build.rs when wiring rpaths for the linked
// binary. Inside idalib-build only `find_runtime_dir` is called, so this
// function is unused from the vendored crate's view; the attribute keeps
// both build graphs quiet.
#[allow(dead_code)]
pub fn runtime_rpath_dirs(primary: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(primary) = primary {
        let primary = normalize_install_dir(primary);
        if has_runtime_libraries(&primary) {
            push_unique(&mut paths, primary);
        }
        return paths;
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::{normalize_install_dir, runtime_rpath_dirs, version_key};
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_versions_from_common_names() {
        assert_eq!(
            version_key(Path::new("IDA Professional 9.1.app")),
            vec![9, 1]
        );
        assert_eq!(version_key(Path::new("ida-pro-9.3")), vec![9, 3]);
        assert_eq!(
            version_key(Path::new("IDA Professional 10.0.app")),
            vec![10, 0]
        );
    }

    #[test]
    fn normalizes_macos_app_paths() {
        assert_eq!(
            normalize_install_dir("/Applications/IDA Professional 9.3.app"),
            Path::new("/Applications/IDA Professional 9.3.app/Contents/MacOS")
        );
        assert_eq!(
            normalize_install_dir("/Applications/IDA Professional 9.3.app/Contents"),
            Path::new("/Applications/IDA Professional 9.3.app/Contents/MacOS")
        );
    }

    #[test]
    fn runtime_rpath_dirs_prefers_primary_only() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ida-install-test-{unique}"));
        fs::create_dir_all(&dir).unwrap();

        #[cfg(target_os = "macos")]
        {
            fs::write(dir.join("libida.dylib"), b"").unwrap();
            fs::write(dir.join("libidalib.dylib"), b"").unwrap();
        }

        #[cfg(target_os = "linux")]
        {
            fs::write(dir.join("libida.so"), b"").unwrap();
            fs::write(dir.join("libidalib.so"), b"").unwrap();
        }

        #[cfg(target_os = "windows")]
        {
            fs::write(dir.join("ida.dll"), b"").unwrap();
            fs::write(dir.join("idalib.dll"), b"").unwrap();
        }

        let rpaths = runtime_rpath_dirs(Some(&dir));
        assert_eq!(rpaths, vec![dir.clone()]);

        let _ = fs::remove_dir_all(dir);
    }
}
