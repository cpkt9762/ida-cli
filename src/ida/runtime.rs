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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_methods: Option<Vec<String>>,
}

impl RuntimeProbeResult {
    pub fn supported(runtime: IdaRuntimeVersion, backend: WorkerBackendKind) -> Self {
        Self {
            runtime: Some(runtime),
            backend: Some(backend),
            supported: true,
            reason: None,
            supported_methods: Some(
                crate::ida::supported_methods_for(backend)
                    .iter()
                    .map(|method| (*method).to_string())
                    .collect(),
            ),
        }
    }

    pub fn unsupported(runtime: IdaRuntimeVersion, reason: impl Into<String>) -> Self {
        Self {
            runtime: Some(runtime),
            backend: None,
            supported: false,
            reason: Some(reason.into()),
            supported_methods: None,
        }
    }

    pub fn error(reason: impl Into<String>) -> Self {
        Self {
            runtime: None,
            backend: None,
            supported: false,
            reason: Some(reason.into()),
            supported_methods: None,
        }
    }
}

fn forced_worker_backend() -> Option<WorkerBackendKind> {
    match std::env::var("IDA_CLI_WORKER_BACKEND")
        .ok()
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some("native-linked") => Some(WorkerBackendKind::NativeLinked),
        Some("idat-compat") => Some(WorkerBackendKind::IdatCompat),
        Some(other) => {
            tracing::warn!(
                backend = other,
                "ignoring invalid IDA_CLI_WORKER_BACKEND; expected native-linked or idat-compat"
            );
            None
        }
        None => None,
    }
}

pub fn select_worker_backend(runtime: &IdaRuntimeVersion) -> RuntimeProbeResult {
    if let Some(backend) = forced_worker_backend() {
        return RuntimeProbeResult::supported(runtime.clone(), backend);
    }

    if runtime.major() == 9 && runtime.minor() < 3 {
        return RuntimeProbeResult::supported(runtime.clone(), WorkerBackendKind::IdatCompat);
    }

    if runtime.major() < 9 {
        return RuntimeProbeResult::unsupported(
            runtime.clone(),
            format!("IDA runtime {} is unsupported", runtime),
        );
    }

    // Bundled idalib is pinned to 9.3; native-linked crashes on 9.4+ until bindings catch up.
    if runtime.major() == 9 && runtime.minor() >= 4 {
        return RuntimeProbeResult::supported(runtime.clone(), WorkerBackendKind::IdatCompat);
    }

    RuntimeProbeResult::supported(runtime.clone(), WorkerBackendKind::NativeLinked)
}

pub fn probe_native_runtime(version: IDAVersion) -> RuntimeProbeResult {
    let runtime = IdaRuntimeVersion::from(version);
    select_worker_backend(&runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(major: i32, minor: i32) -> IdaRuntimeVersion {
        IdaRuntimeVersion {
            major,
            minor,
            build: 0,
        }
    }

    #[test]
    fn selects_idat_compat_for_ida_94() {
        let probe = select_worker_backend(&runtime(9, 4));
        assert_eq!(probe.backend, Some(WorkerBackendKind::IdatCompat));
        assert!(probe.supported);
    }

    #[test]
    fn selects_native_linked_for_ida_93() {
        let probe = select_worker_backend(&runtime(9, 3));
        assert_eq!(probe.backend, Some(WorkerBackendKind::NativeLinked));
        assert!(probe.supported);
    }
}
