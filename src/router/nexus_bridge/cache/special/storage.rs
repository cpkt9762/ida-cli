//! Private SHA256 member objects; generations hold hard links, never byte copies.
use super::*;
use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Binding {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub nlink: u64,
    pub uid: u32,
    pub mode: u32,
}
impl Binding {
    pub(super) fn of(meta: &Metadata) -> anyhow::Result<Self> {
        let ns = |seconds: i64, nanos: i64| {
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|v| v.checked_add(nanos))
                .ok_or_else(|| anyhow::anyhow!("file timestamp outside supported range"))
        };
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime_ns: ns(meta.mtime(), meta.mtime_nsec())?,
            ctime_ns: ns(meta.ctime(), meta.ctime_nsec())?,
            nlink: meta.nlink(),
            uid: meta.uid(),
            mode: meta.mode() & 0o7777,
        })
    }
    pub(super) fn same_data(&self, other: &Self) -> bool {
        (
            self.dev,
            self.ino,
            self.size,
            self.mtime_ns,
            self.uid,
            self.mode,
        ) == (
            other.dev,
            other.ino,
            other.size,
            other.mtime_ns,
            other.uid,
            other.mode,
        )
    }
}
#[derive(Serialize, Deserialize)]
pub(super) struct Receipt {
    pub version: u8,
    pub sha256: String,
    pub identity: Binding,
}
fn private_directory(path: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(e) => return Err(e.into()),
    }
    let meta = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid only reads this process's effective user identity.
    let uid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == uid
            && meta.mode() & 0o077 == 0,
        "unsafe private DSC directory: {}",
        path.display()
    );
    Ok(())
}
pub(super) fn open_private(path: &Path, mode: u32) -> anyhow::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid only reads this process's effective user identity.
    let uid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        meta.is_file() && meta.uid() == uid && meta.mode() & 0o7777 == mode,
        "unsafe DSC member or receipt: {}",
        path.display()
    );
    let named = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        named.is_file() && (named.dev(), named.ino()) == (meta.dev(), meta.ino()),
        "DSC member path replaced: {}",
        path.display()
    );
    Ok(file)
}
fn checked_object(
    store: &Path,
    digest: &str,
    prep: &Preparation,
) -> anyhow::Result<(File, Receipt)> {
    let directory = store.join(digest);
    private_directory(&directory)?;
    anyhow::ensure!(
        std::fs::read_dir(&directory)?.count() == 2,
        "unknown DSC object files retained"
    );
    let receipt: Receipt =
        serde_json::from_reader(open_private(&directory.join("verified.json"), 0o600)?)?;
    anyhow::ensure!(
        receipt.version == 1 && receipt.sha256 == digest,
        "unknown DSC object receipt"
    );
    let file = open_private(&directory.join("data"), 0o400)?;
    anyhow::ensure!(
        Binding::of(&file.metadata()?)?.same_data(&receipt.identity),
        "replaced DSC object refused"
    );
    anyhow::ensure!(
        super::content_hash(&directory.join("data"), prep)? == digest,
        "DSC member content changed"
    );
    Ok((file, receipt))
}
fn create_object(
    source: &Path,
    digest: &str,
    store: &Path,
    stage: &StagedArtifact,
    prep: &Preparation,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};
    let directory = stage.directory.join(digest);
    private_directory(&directory)?;
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(source)?;
    anyhow::ensure!(source.metadata()?.is_file(), "DSC source is not regular");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("data"))?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        prep.check()?;
        let size = source.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        output.write_all(&buffer[..size])?;
        hash.update(&buffer[..size]);
    }
    anyhow::ensure!(
        format!("{:x}", hash.finalize()) == digest,
        "DSC source changed while copying member"
    );
    output.set_permissions(std::fs::Permissions::from_mode(0o400))?;
    output.sync_all()?;
    let receipt = Receipt {
        version: 1,
        sha256: digest.into(),
        identity: Binding::of(&output.metadata()?)?,
    };
    let mut certificate = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("verified.json"))?;
    certificate.write_all(&serde_json::to_vec(&receipt)?)?;
    certificate.sync_all()?;
    File::open(&directory)?.sync_all()?;
    stage.publish_owned_directory(&directory, &store.join(digest), prep)?;
    File::open(store)?.sync_all()?;
    Ok(())
}

/// Caller holds root SH and the one shared member-store content EX until completion.
pub(super) fn link_inputs(
    files: &[PathBuf],
    hashes: &BTreeMap<String, String>,
    root: &Path,
    stage: &StagedArtifact,
    prep: &Preparation,
) -> anyhow::Result<()> {
    let store = root.join("dsc-members");
    private_directory(&store)?;
    for source in files {
        prep.check()?;
        let name = source
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| anyhow::anyhow!("DSC filename is not UTF-8"))?;
        let digest = hashes
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("DSC identity member missing"))?;
        anyhow::ensure!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase()),
            "invalid DSC digest"
        );
        let object = store.join(digest);
        let created = match object.symlink_metadata() {
            Ok(_) => false,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                create_object(source, digest, &store, stage, prep)?;
                true
            }
            Err(e) => return Err(e.into()),
        };
        let data = object.join("data");
        let file = if created {
            open_private(&data, 0o400)?
        } else {
            checked_object(&store, digest, prep)?.0
        };
        let before = Binding::of(&file.metadata()?)?;
        let destination = stage.output.join(name);
        std::fs::hard_link(&data, &destination)?;
        let linked = std::fs::symlink_metadata(&destination)?;
        anyhow::ensure!(
            linked.is_file() && before.same_data(&Binding::of(&linked)?),
            "DSC object replaced during link"
        );
    }
    File::open(&stage.output)?.sync_all()?;
    Ok(())
}

pub(super) fn validate_links(
    root: &Path,
    bundle: &Path,
    hashes: &BTreeMap<String, String>,
    prep: &Preparation,
) -> anyhow::Result<()> {
    let store = root.join("dsc-members");
    private_directory(&store)?;
    for (name, digest) in hashes {
        prep.check()?;
        let (file, _) = checked_object(&store, digest, prep)?;
        let linked = open_private(&bundle.join(name), 0o400)?;
        anyhow::ensure!(
            Binding::of(&file.metadata()?)?.same_data(&Binding::of(&linked.metadata()?)?),
            "DSC bundle member is not the verified shared inode"
        );
    }
    Ok(())
}
