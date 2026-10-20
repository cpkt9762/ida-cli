//! Private SHA256 member objects; generations hold hard links, never byte copies.
use super::*;
use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
fn write_receipt(
    directory: &Path,
    receipt: &Receipt,
    expected: &Binding,
    stage: &StagedArtifact,
    prep: &Preparation,
) -> anyhow::Result<()> {
    let destination = directory.join("verified.json");
    let current = open_private(&destination, 0o600)?;
    anyhow::ensure!(
        Binding::of(&current.metadata()?)? == *expected,
        "DSC receipt replaced before update"
    );
    let temporary = stage.directory.join(format!("{}.receipt", receipt.sha256));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(receipt)?)?;
    file.sync_all()?;
    anyhow::ensure!(
        Binding::of(&std::fs::symlink_metadata(&destination)?)? == *expected,
        "DSC receipt changed before update"
    );
    stage.commit(prep, || std::fs::rename(&temporary, &destination))?;
    File::open(directory)?.sync_all()?;
    Ok(())
}
fn checked_object(
    store: &Path,
    digest: &str,
    stage: &StagedArtifact,
    prep: &Preparation,
) -> anyhow::Result<(File, Receipt, Binding)> {
    let directory = store.join(digest);
    private_directory(&directory)?;
    anyhow::ensure!(
        std::fs::read_dir(&directory)?.count() == 2,
        "unknown DSC object files retained"
    );
    let receipt_file = open_private(&directory.join("verified.json"), 0o600)?;
    let mut receipt_binding = Binding::of(&receipt_file.metadata()?)?;
    anyhow::ensure!(
        receipt_binding.nlink == 1 && receipt_binding.size <= 16384,
        "unsafe DSC member receipt"
    );
    let mut receipt: Receipt = serde_json::from_reader(&receipt_file)?;
    anyhow::ensure!(
        receipt.version == 1 && receipt.sha256 == digest,
        "unknown DSC object receipt"
    );
    anyhow::ensure!(
        Binding::of(&std::fs::symlink_metadata(directory.join("verified.json"))?)?
            == receipt_binding,
        "DSC receipt changed while reading"
    );
    let path = directory.join("data");
    let file = open_private(&path, 0o400)?;
    let before = Binding::of(&file.metadata()?)?;
    anyhow::ensure!(
        before.same_data(&receipt.identity),
        "replaced DSC object refused"
    );
    if before != receipt.identity || !super::hashes::metadata_reusable(&file)? {
        anyhow::ensure!(
            super::content_hash(&path, prep)? == digest,
            "DSC member content changed"
        );
        anyhow::ensure!(
            Binding::of(&file.metadata()?)? == before,
            "DSC object changed while rehashing"
        );
        receipt.identity = before.clone();
        write_receipt(&directory, &receipt, &receipt_binding, stage, prep)?;
        receipt_binding =
            Binding::of(&std::fs::symlink_metadata(directory.join("verified.json"))?)?;
    }
    anyhow::ensure!(
        Binding::of(&std::fs::symlink_metadata(&path)?)? == before,
        "DSC object replaced during observation"
    );
    Ok((file, receipt, receipt_binding))
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
        match object.symlink_metadata() {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                create_object(source, digest, &store, stage, prep)?
            }
            Err(e) => return Err(e.into()),
        }
        let data = object.join("data");
        let (file, mut receipt, receipt_binding) = checked_object(&store, digest, stage, prep)?;
        let before = Binding::of(&file.metadata()?)?;
        let destination = stage.output.join(name);
        std::fs::hard_link(&data, &destination)?;
        let linked = std::fs::symlink_metadata(&destination)?;
        anyhow::ensure!(
            linked.is_file() && before.same_data(&Binding::of(&linked)?),
            "DSC object replaced during link"
        );
        let after = Binding::of(&file.metadata()?)?;
        anyhow::ensure!(
            before.same_data(&after)
                && after.nlink == before.nlink + 1
                && Binding::of(&std::fs::symlink_metadata(&data)?)? == after,
            "DSC object changed during authorized link creation"
        );
        // Only our serialized namespace operation changed ctime/nlink; bytes
        // stayed behind the same read-only FD and data/mtime/mode binding.
        receipt.identity = after;
        write_receipt(&object, &receipt, &receipt_binding, stage, prep)?;
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
    let stage = StagedArtifact::create(&root.join(".dsc-member-validation"))?;
    for (name, digest) in hashes {
        prep.check()?;
        let (file, _, _) = checked_object(&store, digest, &stage, prep)?;
        let linked = open_private(&bundle.join(name), 0o400)?;
        anyhow::ensure!(
            Binding::of(&file.metadata()?)?.same_data(&Binding::of(&linked.metadata()?)?),
            "DSC bundle member is not the verified shared inode"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn verified_private_members_reuse_hash_and_reject_replacement_or_restored_mtime_mutation()
    {
        use sha2::{Digest, Sha256};
        let root = std::env::temp_dir().join(format!("b1-private-hashes-{}", std::process::id()));
        std::fs::create_dir(&root).expect("private test root");
        let source = root.join("source");
        std::fs::write(&source, b"private payload").expect("source fixture");
        let digest = format!("{:x}", Sha256::digest(b"private payload"));
        let stage = StagedArtifact::create(&root.join("bundle")).expect("owned bundle stage");
        std::fs::create_dir(&stage.output).expect("bundle directory");
        let hashes = BTreeMap::from([("source".into(), digest.clone())]);
        let prep = Preparation::new(std::time::Duration::from_secs(10));
        link_inputs(&[source], &hashes, &root, &stage, &prep)
            .expect("verified creation and reference");
        super::super::HASH_READ_BYTES.with(|n| n.set(0));
        validate_links(&root, &stage.output, &hashes, &prep)
            .expect("metadata-bound immutable hash");
        let eligible = super::super::hashes::metadata_reusable(
            &std::fs::File::open(stage.output.join("source")).expect("test member fd"),
        )
        .expect("filesystem qualification");
        assert_eq!(
            super::super::HASH_READ_BYTES.with(|n| n.get()) == 0,
            eligible,
            "only qualified unchanged metadata can avoid payload verification"
        );
        let data = root.join("dsc-members").join(digest).join("data");
        std::fs::remove_file(&data).expect("replace private object");
        std::fs::write(&data, b"private payload").expect("same-byte foreign inode");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o400))
            .expect("foreign private mode");
        assert!(
            validate_links(&root, &stage.output, &hashes, &prep).is_err(),
            "same-byte inode replacement must not inherit verification"
        );
        std::fs::remove_file(&data).expect("remove only test replacement");
        std::fs::hard_link(stage.output.join("source"), &data)
            .expect("restore original test inode");
        super::super::HASH_READ_BYTES.with(|n| n.set(0));
        validate_links(&root, &stage.output, &hashes, &prep)
            .expect("unknown namespace change requires rehash");
        assert!(super::super::HASH_READ_BYTES.with(|n| n.get()) > 0);
        let saved_time = data
            .metadata()
            .expect("data stat")
            .modified()
            .expect("data mtime");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o600))
            .expect("test write access");
        std::fs::write(&data, b"changed payload").expect("same-size private mutation");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&data)
            .expect("mtime handle")
            .set_times(std::fs::FileTimes::new().set_modified(saved_time))
            .expect("restored data mtime");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o400))
            .expect("restore read-only mode");
        super::super::HASH_READ_BYTES.with(|n| n.set(0));
        assert!(
            validate_links(&root, &stage.output, &hashes, &prep).is_err(),
            "ctime change must expose the content mutation"
        );
        assert!(super::super::HASH_READ_BYTES.with(|n| n.get()) > 0);
        let cleanup = stage.cleanup_receipt();
        drop(stage);
        cleanup
            .wait()
            .await
            .expect("FIFO cleanup barrier for private stages");
        std::fs::remove_dir_all(root).expect("remove test files");
    }
}
