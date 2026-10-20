//! Offline special-input builders; the returned open still uses ordinary N1 custody.
use super::*;
use serde::{Deserialize, Serialize};
mod hashes;
mod storage;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DscInput {
    pub arch: String,
    pub module: String,
    pub frameworks: Vec<String>,
    pub ida_version: u8,
    #[serde(skip)]
    pub log_path: Option<PathBuf>,
}
impl DscInput {
    pub fn validate(&self) -> Result<(), ToolError> {
        if !matches!(self.ida_version, 8 | 9) || self.arch.is_empty() {
            return Err(ToolError::InvalidParams(
                "invalid DSC architecture or IDA version".into(),
            ));
        }
        for module in std::iter::once(&self.module).chain(&self.frameworks) {
            if !module.starts_with('/')
                || module.contains('\0')
                || module.split('/').any(|s| s == "..")
            {
                return Err(ToolError::InvalidParams(
                    "DSC modules must be absolute paths without traversal or NUL".into(),
                ));
            }
        }
        Ok(())
    }
}

pub(super) async fn sbpf(
    mut prepared: PreparedOpen,
    preparation: &Preparation,
) -> Result<PreparedOpen, ToolError> {
    if prepared.path.extension().is_some_and(|e| e == "i64") {
        return Ok(prepared);
    }
    let output = prepared.path.with_extension("i64");
    crate::sbpf::run_sbx_aot_i64(&prepared.path, &output, preparation.clone()).await?;
    prepared.path = output;
    prepared.options = serde_json::json!({"auto_analysis":false});
    Ok(prepared)
}

// Hash every companion, including .symbols when present. Names are part of the
// identity; a different module/framework/loader selection is a different cache key.
fn members(path: &std::path::Path) -> anyhow::Result<Vec<PathBuf>> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("DSC parent missing"))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("DSC name missing"))?
        .to_string_lossy();
    let prefix = format!("{name}.");
    let mut files = vec![path.to_path_buf()];
    for item in std::fs::read_dir(parent)? {
        let item = item?;
        let suffix = item.file_name();
        let suffix = suffix.to_string_lossy();
        if suffix.starts_with(&prefix)
            && !suffix.ends_with(".i64")
            && !suffix.ends_with(".idb")
            && !suffix.ends_with(".map")
            && !suffix.ends_with(".atlas")
        {
            files.push(item.path());
        }
    }
    anyhow::ensure!(files.len() <= 1024, "DSC companion count exceeds 1024");
    files.sort();
    for file in &files {
        anyhow::ensure!(
            file.symlink_metadata()?.file_type().is_file(),
            "DSC member is not a regular file: {}",
            file.display()
        );
    }
    Ok(files)
}
#[cfg(test)]
thread_local! { static HASH_READ_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
fn source_identity(
    files: &[PathBuf],
    config: &DscInput,
    root: &std::path::Path,
    preparation: &Preparation,
) -> anyhow::Result<Vec<u8>> {
    hashes::identity(files, config, root, preparation)
}

fn content_hash(path: &std::path::Path, preparation: &Preparation) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let mut input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    anyhow::ensure!(
        input.metadata()?.is_file(),
        "DSC member is not a regular file"
    );
    let before = storage::Binding::of(&input.metadata()?)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        preparation.check()?;
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        #[cfg(test)]
        HASH_READ_BYTES.with(|n| n.set(n.get() + size));
        hasher.update(&buffer[..size]);
    }
    anyhow::ensure!(
        storage::Binding::of(&input.metadata()?)? == before
            && storage::Binding::of(&std::fs::symlink_metadata(path)?)? == before,
        "DSC file changed during hashing"
    );
    Ok(format!("{:x}", hasher.finalize()))
}
#[cfg(test)]
fn identity(
    files: &[PathBuf],
    config: &DscInput,
    preparation: &Preparation,
) -> anyhow::Result<Vec<u8>> {
    let mut hashes = std::collections::BTreeMap::new();
    for file in files {
        let name = file
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("DSC member name missing"))?;
        hashes.insert(
            name.to_string_lossy().into_owned(),
            content_hash(file, preparation)?,
        );
    }
    Ok(serde_json::to_vec(
        &serde_json::json!({"kind":"dsc-sha256-v1","files":hashes,"loader":config}),
    )?)
}

pub async fn prepare(
    path: PathBuf,
    cache: PathBuf,
    config: DscInput,
    preparation: &Preparation,
) -> Result<PreparedOpen, ToolError> {
    config.validate()?;
    let guard = super::super::cache_lock::acquire(&cache, preparation).await?;
    let original = path.clone();
    let parameters = config.clone();
    let preparing = preparation.clone();
    let hashing_guard = guard.clone();
    let hashing_member_guard = super::super::cache_lock::acquire_content(
        &cache,
        "dsc-shared-member-store-v1",
        preparation,
    )
    .await?;
    let memo_root = cache.clone();
    let (files, bytes) = preparation
        .wait(blocking::run(blocking::WorkClass::Prepare, move || {
            let _guards = (hashing_guard, hashing_member_guard);
            let files = members(&original)?;
            let bytes = source_identity(&files, &parameters, &memo_root, &preparing)?;
            Ok::<_, anyhow::Error>((files, bytes))
        }))
        .await?
        .map_err(|e| ToolError::IdaError(format!("DSC content identity: {e:#}")))?;
    let key = blake3::hash(&bytes).to_hex()[..12].to_string();
    let content_guard =
        super::super::cache_lock::acquire_content(&cache, &key, preparation).await?;
    let member_guard = super::super::cache_lock::acquire_content(
        &cache,
        "dsc-shared-member-store-v1",
        preparation,
    )
    .await?;
    let root = cache.clone();
    let lookup = key.clone();
    let lookup_guard = guard.clone();
    let lookup_content_guard = content_guard.clone();
    let previous = preparation
        .wait(blocking::run(blocking::WorkClass::Prepare, move || {
            let _guards = (lookup_guard, lookup_content_guard);
            super::super::generations::current(&root, &lookup)
        }))
        .await?
        .map_err(|e| ToolError::IdaError(format!("DSC cache lookup: {e:#}")))?;
    if let Some(idb) = previous {
        let input = idb.with_extension("");
        let bundle = idb
            .parent()
            .ok_or_else(|| ToolError::InvalidPath("DSC generation parent missing".into()))?
            .join("dsc-inputs");
        let expected = bytes.clone();
        let cached_config = config.clone();
        let preparing = preparation.clone();
        let validation_guard = guard.clone();
        let validation_content_guard = content_guard.clone();
        let validation_member_guard = member_guard.clone();
        let member_root = cache.clone();
        let valid = preparation
            .wait(blocking::run(blocking::WorkClass::Prepare, move || {
                let _guards = (
                    validation_guard,
                    validation_content_guard,
                    validation_member_guard,
                );
                anyhow::ensure!(
                    std::fs::read(&input)? == expected,
                    "DSC cached input identity changed"
                );
                let manifest_file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                    .open(
                        input
                            .parent()
                            .ok_or_else(|| anyhow::anyhow!("generation parent missing"))?
                            .join("generation.json"),
                    )?;
                anyhow::ensure!(
                    manifest_file.metadata()?.is_file(),
                    "generation manifest is not regular"
                );
                let manifest: serde_json::Value = serde_json::from_reader(manifest_file)?;
                if let Some(version) = manifest.get("dsc_store") {
                    anyhow::ensure!(
                        version.as_u64() == Some(1),
                        "unknown DSC shared-store version"
                    );
                    let hashes = serde_json::from_value(manifest["dsc_inputs"].clone())?;
                    let requested: serde_json::Value = serde_json::from_slice(&expected)?;
                    anyhow::ensure!(
                        manifest["dsc_inputs"] == requested["files"],
                        "DSC shared inventory changed"
                    );
                    storage::validate_links(&member_root, &bundle, &hashes, &preparing)?;
                    Ok::<_, anyhow::Error>(true)
                } else {
                    let cached_members = members(
                        &bundle.join(
                            path.file_name()
                                .ok_or_else(|| anyhow::anyhow!("DSC name missing"))?,
                        ),
                    )?;
                    Ok(
                        source_identity(&cached_members, &cached_config, &member_root, &preparing)?
                            == expected,
                    )
                }
            }))
            .await?
            .map_err(|e| ToolError::IdaError(format!("DSC cached identity: {e}")))?;
        if !valid || !idb.is_file() {
            return Err(ToolError::IdaError(
                "DSC cached generation is incomplete or has a different identity".into(),
            ));
        }
        let mut prepared = PreparedOpen::plain(idb);
        prepared.options = serde_json::json!({"auto_analysis":false});
        prepared.cache_hit = true;
        prepared.cache_guard = Some(guard);
        prepared.content_guard = Some(content_guard);
        return Ok(prepared);
    }
    let preparing = preparation.clone();
    let root = cache.clone();
    let cache_key = key.clone();
    // The blocking job itself owns both guards until copying really stops.
    let retained_guard = guard.clone();
    let retained_content = content_guard.clone();
    let (snapshot, input) = preparation
        .wait(blocking::run(blocking::WorkClass::Prepare, move || {
            let _guards = (retained_guard, retained_content, member_guard);
            let snapshot = StagedArtifact::create(&root.join(".dsc-snapshot"))?;
            std::fs::create_dir(&snapshot.output)?;
            let identity: serde_json::Value = serde_json::from_slice(&bytes)?;
            let hashes = serde_json::from_value(identity["files"].clone())?;
            storage::link_inputs(&files, &hashes, &root, &snapshot, &preparing)?;
            let manifest = snapshot.directory.join("identity.json");
            std::fs::write(&manifest, &bytes)?;
            let input =
                super::super::generations::create(&root, &cache_key, &manifest, &preparing)?;
            let directory = input.parent().ok_or_else(|| anyhow::anyhow!("DSC generation parent missing"))?;
            let bundle = StagedArtifact::create(&directory.join("dsc-inputs"))?;
            std::fs::rename(&snapshot.output, &bundle.output)?;
            bundle.publish_directory(&preparing)?;
            let identity: serde_json::Value = serde_json::from_slice(&bytes)?;
            std::fs::write(directory.join("generation.json"), serde_json::to_vec(&serde_json::json!({"version":1,"key":cache_key,"dsc_inputs":identity["files"],"dsc_store":1}))?)?;
            std::fs::File::open(directory.join("generation.json"))?.sync_all()?;
            std::fs::File::open(directory)?.sync_all()?;
            Ok::<_, anyhow::Error>((snapshot, input))
        }))
        .await?
        .map_err(|e| ToolError::IdaError(format!("DSC snapshot: {e:#}")))?;
    let receipt = snapshot.cleanup_receipt();
    let result = build(&path, &input, &config, preparation).await;
    drop(snapshot);
    receipt.wait().await?;
    result?;
    let idb = input.with_extension("i64");
    let mut prepared = PreparedOpen::plain(idb.clone());
    prepared.options = serde_json::json!({"auto_analysis":false});
    prepared.generation = Some((cache, key, idb));
    prepared.cache_guard = Some(guard);
    prepared.content_guard = Some(content_guard);
    Ok(prepared)
}

async fn build(
    path: &std::path::Path,
    input: &std::path::Path,
    config: &DscInput,
    preparation: &Preparation,
) -> Result<(), ToolError> {
    let stage = StagedArtifact::create(&input.with_extension("i64"))
        .map_err(|e| ToolError::IdaError(format!("DSC output staging: {e}")))?;
    let receipt = stage.cleanup_receipt();
    let result = async {
        let script = stage.directory.join("load.py");
        let code = crate::dsc::dsc_load_script(&config.module, &config.frameworks);
        let destination = script.clone();
        preparation
            .wait(blocking::run(blocking::WorkClass::Prepare, move || {
                std::fs::write(destination, code)
            }))
            .await?
            .map_err(|e| ToolError::IdaError(format!("DSC script: {e}")))?;
        let copied = input
            .parent()
            .ok_or_else(|| ToolError::InvalidPath("DSC generation parent missing".into()))?
            .join("dsc-inputs")
            .join(
                path.file_name()
                    .ok_or_else(|| ToolError::InvalidPath("DSC name missing".into()))?,
            );
        let args = crate::dsc::idat_dsc_args(
            &copied,
            &stage.output,
            &script,
            &crate::dsc::dsc_file_type(&config.arch, config.ida_version),
            config.log_path.as_deref(),
        );
        let output = crate::dsc::run_idat_offline(
            &crate::dsc::find_idat()?,
            &args,
            &config.module,
            preparation.clone(),
        )
        .await?;
        if !output.status.success() {
            return Err(ToolError::IdaError(format!(
                "DSC idat failed ({}): {}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            )));
        }
        let preparing = preparation.clone();
        blocking::run(blocking::WorkClass::Prepare, move || {
            stage.publish(&preparing)
        })
        .await??;
        Ok(())
    }
    .await;
    receipt.wait().await?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dsc_identity_binds_companions_and_loader_but_not_log_destination() {
        let root = std::env::temp_dir().join(format!("n7b-identity-{}", std::process::id()));
        std::fs::create_dir(&root).expect("private DSC identity root");
        let main = root.join("dyld_shared_cache_arm64e");
        let companion = root.join("dyld_shared_cache_arm64e.01");
        std::fs::write(&main, b"primary").expect("primary fixture");
        std::fs::write(&companion, b"companion").expect("companion fixture");
        let config = DscInput {
            arch: "arm64e".into(),
            module: "/usr/lib/a.dylib".into(),
            frameworks: vec![],
            ida_version: 9,
            log_path: None,
        };
        let prep = Preparation::new(std::time::Duration::from_secs(5));
        let first =
            identity(&members(&main).expect("DSC files"), &config, &prep).expect("identity");
        let mut changed = config.clone();
        changed.log_path = Some(root.join("log"));
        assert_eq!(
            first,
            identity(&members(&main).expect("files"), &changed, &prep)
                .expect("log-independent identity")
        );
        changed.module = "/usr/lib/b.dylib".into();
        assert_ne!(
            first,
            identity(&members(&main).expect("files"), &changed, &prep).expect("module identity")
        );
        std::fs::write(companion, b"different").expect("changed companion");
        assert_ne!(
            first,
            identity(&members(&main).expect("files"), &config, &prep).expect("companion identity")
        );
        changed.module = "/usr/lib/../invalid".into();
        assert!(changed.validate().is_err());
        std::fs::remove_dir_all(root).expect("remove private identity fixtures");
    }
}

#[cfg(test)]
mod nb2_regressions {
    use super::*;
    #[test]
    fn stable_source_metadata_avoids_payload_rehash_but_changes_are_rehashed() {
        let root = std::env::temp_dir().join(format!("b1-source-hashes-{}", std::process::id()));
        std::fs::create_dir(&root).expect("private hash-cache root");
        let source = root.join("dyld_shared_cache_arm64e");
        std::fs::write(&source, b"primary file").expect("source fixture");
        let files = vec![source.clone()];
        let config = DscInput {
            arch: "arm64e".into(),
            module: "/usr/lib/a.dylib".into(),
            frameworks: vec![],
            ida_version: 9,
            log_path: None,
        };
        let prep = Preparation::new(std::time::Duration::from_secs(10));
        let first = source_identity(&files, &config, &root, &prep).expect("initial source hash");
        assert_eq!(
            first,
            identity(&files, &config, &prep).expect("unchanged content identity wire format")
        );
        HASH_READ_BYTES.with(|n| n.set(0));
        assert_eq!(
            first,
            source_identity(&files, &config, &root, &prep).expect("cached source hash")
        );
        let eligible = hashes::metadata_reusable(&std::fs::File::open(&source).expect("source fd"))
            .expect("filesystem qualification");
        assert_eq!(HASH_READ_BYTES.with(|n|n.get())==0,eligible,"unchanged qualified metadata avoids rereads; unsupported filesystems still verify bytes");
        let old = source.with_extension("old");
        std::fs::rename(&source, &old).expect("hold old inode");
        std::fs::write(&source, b"another file").expect("replaced source");
        HASH_READ_BYTES.with(|n| n.set(0));
        assert_ne!(
            first,
            source_identity(&files, &config, &root, &prep).expect("replacement rehash")
        );
        assert!(HASH_READ_BYTES.with(|n| n.get()) > 0);
        let current = source_identity(&files, &config, &root, &prep).expect("current identity");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .expect("source timestamp handle");
        let times = std::fs::FileTimes::new()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(3600));
        file.set_times(times)
            .expect("deterministic timestamp change");
        HASH_READ_BYTES.with(|n| n.set(0));
        assert_eq!(
            current,
            source_identity(&files, &config, &root, &prep).expect("timestamp-only rehash")
        );
        assert!(
            HASH_READ_BYTES.with(|n| n.get()) > 0,
            "metadata change must force payload verification"
        );
        let saved_time = source
            .metadata()
            .expect("source metadata")
            .modified()
            .expect("source mtime");
        std::fs::write(&source, b"mutated file").expect("same-size source mutation");
        file.set_times(std::fs::FileTimes::new().set_modified(saved_time))
            .expect("restore original mtime");
        HASH_READ_BYTES.with(|n| n.set(0));
        assert_ne!(
            current,
            source_identity(&files, &config, &root, &prep).expect("ctime detects restored mtime")
        );
        assert!(HASH_READ_BYTES.with(|n| n.get()) > 0);
        let memo = root.join("dsc-source-hashes.json");
        std::fs::remove_file(&memo).expect("replace test ledger");
        std::os::unix::fs::symlink(&old, &memo).expect("foreign symlink memo");
        assert!(
            source_identity(&files, &config, &root, &prep).is_err(),
            "a replaced ledger cannot grant cached digests"
        );
        assert_eq!(
            std::fs::read(&old).expect("foreign target survives"),
            b"primary file"
        );

        std::fs::remove_dir_all(root).expect("remove private hash fixtures");
    }
}
