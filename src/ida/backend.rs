use std::path::Path;

use crate::ida::runtime::{probe_native_runtime, WorkerBackendKind};
use idalib::{IDAError, IDAVersion, IDB};

/// Stable boundary for the native IDA integration layer.
///
/// The current implementation still uses `idalib`, but the rest of the crate
/// should depend on this trait where possible so version-specific or
/// non-native backends can be introduced later.
pub trait IdaBackend {
    type Database;

    fn init_library(&self);
    fn version(&self) -> Result<IDAVersion, IDAError>;
    fn enable_console_messages(&self, enabled: bool);
    fn open_existing_database(
        &self,
        path: &Path,
        auto_analyse: bool,
        save: bool,
    ) -> Result<Self::Database, IDAError>;
    fn open_raw_binary(
        &self,
        path: &Path,
        options: RawDatabaseOptions<'_>,
    ) -> Result<Self::Database, IDAError>;
}

/// Backend-agnostic options for opening a raw binary.
pub struct RawDatabaseOptions<'a> {
    pub auto_analyse: bool,
    pub save: bool,
    pub idb_output: &'a Path,
    pub file_type: Option<&'a str>,
    pub extra_args: &'a [String],
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NativeIdalibBackend;

pub fn native_backend() -> &'static NativeIdalibBackend {
    static BACKEND: NativeIdalibBackend = NativeIdalibBackend;
    &BACKEND
}

impl NativeIdalibBackend {
    fn ensure_runtime_can_open(&self) -> Result<(), IDAError> {
        let probe = probe_native_runtime(self.version()?);
        if !probe.supported {
            return Err(IDAError::ffi_with(
                probe
                    .reason
                    .unwrap_or_else(|| "native backend is not supported".to_string()),
            ));
        }

        Ok(())
    }

    pub fn worker_backend_kind(&self) -> WorkerBackendKind {
        WorkerBackendKind::NativeLinked
    }
}

impl IdaBackend for NativeIdalibBackend {
    type Database = IDB;

    fn init_library(&self) {
        idalib::init_library();
    }

    fn version(&self) -> Result<IDAVersion, IDAError> {
        idalib::version()
    }

    fn enable_console_messages(&self, enabled: bool) {
        idalib::enable_console_messages(enabled);
    }

    fn open_existing_database(
        &self,
        path: &Path,
        auto_analyse: bool,
        save: bool,
    ) -> Result<Self::Database, IDAError> {
        self.ensure_runtime_can_open()?;
        IDB::open_with(path, auto_analyse, save)
    }

    fn open_raw_binary(
        &self,
        path: &Path,
        options: RawDatabaseOptions<'_>,
    ) -> Result<Self::Database, IDAError> {
        self.ensure_runtime_can_open()?;
        let mut open_options = idalib::idb::IDBOpenOptions::new();
        open_options.auto_analyse(options.auto_analyse);

        if let Some(file_type) = options.file_type {
            open_options.file_type(file_type);
        }

        for arg in options.extra_args {
            open_options.arg(arg);
        }

        open_options
            .idb(options.idb_output)
            .save(options.save)
            .open(path)
    }
}
