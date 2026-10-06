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

/// `IDA_SDK_VERSION` (e.g. 950 for 9.5) of the SDK this binary was built with.
const BUILD_SDK_VERSION: &str = env!("IDA_CLI_SDK_VERSION");

/// SDK versions whose native layer has been verified end to end against the
/// matching IDA runtime (9.3.260213 and 9.5.261001). 9.4 is left out: the
/// public 9.4 SDK speaks Hex-Rays API magic 5, but the 9.4.260610 build still
/// answers magic 4, so native-linked opens databases there without a decompiler.
const NATIVE_VERIFIED_SDK_VERSIONS: &[i32] = &[930, 950];

pub fn select_worker_backend(runtime: &IdaRuntimeVersion) -> RuntimeProbeResult {
    if let Some(backend) = forced_worker_backend() {
        return RuntimeProbeResult::supported(runtime.clone(), backend);
    }

    let sdk_version = BUILD_SDK_VERSION.parse().unwrap_or_default();
    select_worker_backend_for_sdk(runtime, sdk_version)
}

fn select_worker_backend_for_sdk(
    runtime: &IdaRuntimeVersion,
    sdk_version: i32,
) -> RuntimeProbeResult {
    if runtime.major() == 9 && runtime.minor() < 3 {
        return RuntimeProbeResult::supported(runtime.clone(), WorkerBackendKind::IdatCompat);
    }

    if runtime.major() < 9 {
        return RuntimeProbeResult::unsupported(
            runtime.clone(),
            format!("IDA runtime {} is unsupported", runtime),
        );
    }

    // The vendored idalib calls private IDA structures whose layout is selected
    // at compile time from the SDK version (it changed in 9.4 and again in 9.5).
    // Running native-linked against a different runtime segfaults on open.
    let (sdk_major, sdk_minor) = (sdk_version / 100, sdk_version % 100 / 10);
    if (runtime.major(), runtime.minor()) == (sdk_major, sdk_minor)
        && NATIVE_VERIFIED_SDK_VERSIONS.contains(&sdk_version)
    {
        return RuntimeProbeResult::supported(runtime.clone(), WorkerBackendKind::NativeLinked);
    }

    tracing::info!(
        runtime = %runtime,
        sdk_version,
        "native layer not verified for this runtime/SDK pair; using idat-compat"
    );
    RuntimeProbeResult::supported(runtime.clone(), WorkerBackendKind::IdatCompat)
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
    fn selects_native_linked_when_runtime_matches_verified_sdk() {
        for (major, minor, sdk) in [(9, 3, 930), (9, 5, 950)] {
            let probe = select_worker_backend_for_sdk(&runtime(major, minor), sdk);
            assert_eq!(probe.backend, Some(WorkerBackendKind::NativeLinked));
            assert!(probe.supported);
        }
    }

    #[test]
    fn selects_idat_compat_for_unverified_sdk_even_when_matching() {
        for (major, minor, sdk) in [(9, 4, 940), (9, 6, 960)] {
            let probe = select_worker_backend_for_sdk(&runtime(major, minor), sdk);
            assert_eq!(probe.backend, Some(WorkerBackendKind::IdatCompat));
            assert!(probe.supported);
        }
    }

    #[test]
    fn selects_idat_compat_when_runtime_differs_from_sdk() {
        for (major, minor, sdk) in [(9, 4, 930), (9, 5, 930), (9, 3, 950), (9, 5, 940)] {
            let probe = select_worker_backend_for_sdk(&runtime(major, minor), sdk);
            assert_eq!(probe.backend, Some(WorkerBackendKind::IdatCompat));
            assert!(probe.supported);
        }
    }

    #[test]
    fn selects_idat_compat_before_ida_93() {
        let probe = select_worker_backend_for_sdk(&runtime(9, 2), 920);
        assert_eq!(probe.backend, Some(WorkerBackendKind::IdatCompat));
        assert!(probe.supported);
    }

    #[test]
    fn rejects_runtimes_older_than_ida_9() {
        let probe = select_worker_backend_for_sdk(&runtime(8, 4), 950);
        assert_eq!(probe.backend, None);
        assert!(!probe.supported);
    }
}
