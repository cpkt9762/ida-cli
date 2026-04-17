use std::fmt::{Display, Formatter};

use clap::ValueEnum;
use idalib::IDAVersion;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdaRuntimeVersion {
    major: i32,
    minor: i32,
    build: i32,
}

impl IdaRuntimeVersion {
    pub fn major(&self) -> i32 {
        self.major
    }

    pub fn minor(&self) -> i32 {
        self.minor
    }

    pub fn build(&self) -> i32 {
        self.build
    }
}

impl From<IDAVersion> for IdaRuntimeVersion {
    fn from(value: IDAVersion) -> Self {
        Self {
            major: value.major(),
            minor: value.minor(),
            build: value.build(),
        }
    }
}

impl Display for IdaRuntimeVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerBackendKind {
    NativeLinked,
    IdatCompat,
}

impl WorkerBackendKind {
    pub fn as_cli_arg(self) -> &'static str {
        match self {
            Self::NativeLinked => "native-linked",
            Self::IdatCompat => "idat-compat",
        }
    }
}

impl Display for WorkerBackendKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_cli_arg())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProbeResult {
    pub runtime: Option<IdaRuntimeVersion>,
    pub backend: Option<WorkerBackendKind>,
    pub supported: bool,
    pub reason: Option<String>,
}

impl RuntimeProbeResult {
    pub fn supported(runtime: IdaRuntimeVersion, backend: WorkerBackendKind) -> Self {
        Self {
            runtime: Some(runtime),
            backend: Some(backend),
            supported: true,
            reason: None,
        }
    }

    pub fn unsupported(runtime: IdaRuntimeVersion, reason: impl Into<String>) -> Self {
        Self {
            runtime: Some(runtime),
            backend: None,
            supported: false,
            reason: Some(reason.into()),
        }
    }

    pub fn error(reason: impl Into<String>) -> Self {
        Self {
            runtime: None,
            backend: None,
            supported: false,
            reason: Some(reason.into()),
        }
    }
}

pub fn select_worker_backend(runtime: &IdaRuntimeVersion) -> RuntimeProbeResult {
    if runtime.major() == 9 && runtime.minor() < 3 {
        return RuntimeProbeResult::supported(runtime.clone(), WorkerBackendKind::IdatCompat);
    }

    if runtime.major() < 9 {
        return RuntimeProbeResult::unsupported(
            runtime.clone(),
            format!("IDA runtime {} is unsupported", runtime),
        );
    }

    RuntimeProbeResult::supported(runtime.clone(), WorkerBackendKind::NativeLinked)
}

pub fn probe_native_runtime(version: IDAVersion) -> RuntimeProbeResult {
    let runtime = IdaRuntimeVersion::from(version);
    select_worker_backend(&runtime)
}
