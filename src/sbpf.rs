//! Solana sBPF AOT compilation support via `sbx aot i64`.
//!
//! IDA Pro has no native Hex-Rays decompiler for the sBPF instruction set.
//! `sbx aot i64` AOT-compiles the program to a host-native shared library via
//! LLVM, then runs `idat64 -A` to produce a fully-analysed `.i64` database
//! directly — no intermediate dylib step required on the caller's side.

use std::path::{Path, PathBuf};
use tokio::process::Command;

use crate::error::ToolError;

// ── Binary discovery ──────────────────────────────────────────────────────

pub fn find_sbx() -> Result<PathBuf, ToolError> {
    if let Ok(path) = std::env::var("SBX") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Ok(p);
        }
        return Err(ToolError::InvalidParams(format!(
            "$SBX is set to '{path}' but the file does not exist",
        )));
    }

    if let Some(paths) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&paths) {
            let candidate = directory.join("sbx");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    let candidates: &[&str] = &["~/.cargo/bin/sbx", "~/.local/bin/sbx", "/usr/local/bin/sbx"];
    for raw in candidates {
        let expanded = crate::expand_path(raw);
        if expanded.exists() {
            return Ok(expanded);
        }
    }

    Err(ToolError::InvalidParams(
        "Cannot find sbx. Install it with `cargo install --path crates/sbx --locked` \
         from the sbpf-interpreter workspace, or set the SBX env var to its path."
            .into(),
    ))
}

pub const SBX_PROFILE_ENV: &str = "IDA_CLI_SBX_PROFILE";

/// Explicit code generation identity, independent of the installed sbx default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SbxProfile {
    #[default]
    Analysis,
    AnalysisInline,
    Trace,
    Optimized,
}

impl SbxProfile {
    pub fn parse(value: &str) -> Result<Self, ToolError> {
        match value {
            "analysis" => Ok(Self::Analysis),
            "analysis-inline" => Ok(Self::AnalysisInline),
            "trace" => Ok(Self::Trace),
            "optimized" => Ok(Self::Optimized),
            other => Err(ToolError::InvalidParams(format!(
                "{SBX_PROFILE_ENV}={other:?} is not one of analysis, analysis-inline, trace, optimized"
            ))),
        }
    }

    /// Read the server process environment; only absence selects the default.
    pub fn from_env() -> Result<Self, ToolError> {
        match std::env::var_os(SBX_PROFILE_ENV) {
            None => Ok(Self::default()),
            Some(value) => Self::parse(value.to_str().ok_or_else(|| {
                ToolError::InvalidParams(format!("{SBX_PROFILE_ENV} is not valid UTF-8"))
            })?),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Analysis => "analysis",
            Self::AnalysisInline => "analysis-inline",
            Self::Trace => "trace",
            Self::Optimized => "optimized",
        }
    }

    pub fn sbx_args(self) -> &'static [&'static str] {
        match self {
            Self::Analysis => &["--profile", "analysis"],
            Self::AnalysisInline => &["--profile", "analysis", "--inline"],
            Self::Trace => &["--profile", "trace"],
            Self::Optimized => &["--profile", "optimized"],
        }
    }

    pub(crate) fn cache_key(self, hash: &blake3::Hash) -> String {
        format!("sbpf-v1-{}.sbx-{}", hash.to_hex(), self.name())
    }
}

// ── AOT compilation ───────────────────────────────────────────────────────

pub struct SbxAotResult {
    pub i64_path: PathBuf,
}

pub async fn run_sbx_aot_i64(
    input: &Path,
    output_i64: &Path,
    preparation: crate::preprocess::Preparation,
) -> Result<SbxAotResult, ToolError> {
    run_sbx_aot_i64_with_profile(input, output_i64, SbxProfile::from_env()?, preparation).await
}

pub(crate) async fn run_sbx_aot_i64_with_profile(
    input: &Path,
    output_i64: &Path,
    profile: SbxProfile,
    preparation: crate::preprocess::Preparation,
) -> Result<SbxAotResult, ToolError> {
    let mut cancellation_guard = preparation.cancel_on_drop();
    preparation.check()?;
    let input = input.to_path_buf();
    let destination = output_i64.to_path_buf();
    let (bin, abs_input, stage) = preparation
        .wait(crate::blocking::run(
            crate::blocking::WorkClass::Prepare,
            move || {
                let bin = find_sbx()?
                    .canonicalize()
                    .map_err(|e| ToolError::InvalidParams(format!("sbx executable: {e}")))?;
                let abs_input = std::fs::canonicalize(&input).map_err(|e| {
                    ToolError::InvalidParams(format!("sbx input {}: {e}", input.display()))
                })?;
                let stage = crate::preprocess::StagedArtifact::create(&destination)
                    .map_err(|e| ToolError::IdaError(format!("sbx staging: {e}")))?;
                std::fs::create_dir(stage.directory.join("tmp"))
                    .map_err(|e| ToolError::IdaError(format!("sbx temporary directory: {e}")))?;
                Ok::<_, ToolError>((bin, abs_input, stage))
            },
        ))
        .await??;
    let cleanup = stage.cleanup_receipt();
    let result = async {
        preparation.check()?;
        let mut command = Command::new(&bin);
        command
            .current_dir(&stage.directory)
            .env("TMPDIR", stage.directory.join("tmp"))
            .env_remove("DYLD_LIBRARY_PATH")
            .env("LITESVM_DEX_DIR", stage.directory.join("sbx-cache"))
            .arg("aot")
            .arg("i64")
            .arg("--program")
            .arg(&abs_input)
            .arg("--output")
            .arg(&stage.output)
            .args(profile.sbx_args());
        let output = crate::preprocess::run(command, preparation.clone()).await?;
        if !output.status.success() {
            return Err(ToolError::InvalidParams(format!(
                "sbx aot i64 (profile {}) failed (exit {})\nstderr: {}\nstdout: {}",
                profile.name(),
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            )));
        }
        let publish = preparation.clone();
        crate::blocking::run(crate::blocking::WorkClass::Prepare, move || {
            stage.publish(&publish)
        })
        .await??;
        Ok::<_, ToolError>(())
    }
    .await;
    cleanup.wait().await?;
    result?;
    cancellation_guard.disarm();
    Ok(SbxAotResult {
        i64_path: output_i64.into(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_strict_and_arguments_are_explicit() {
        for (name, profile, args) in [
            (
                "analysis",
                SbxProfile::Analysis,
                &["--profile", "analysis"][..],
            ),
            (
                "analysis-inline",
                SbxProfile::AnalysisInline,
                &["--profile", "analysis", "--inline"][..],
            ),
            ("trace", SbxProfile::Trace, &["--profile", "trace"][..]),
            (
                "optimized",
                SbxProfile::Optimized,
                &["--profile", "optimized"][..],
            ),
        ] {
            assert_eq!(SbxProfile::parse(name).expect("valid profile"), profile);
            assert_eq!(profile.name(), name);
            assert_eq!(profile.sbx_args(), args);
        }
        assert_eq!(SbxProfile::default(), SbxProfile::Analysis);
        for invalid in [
            "",
            "Analysis",
            "TRACE",
            "inline",
            "optimised",
            "analysis --inline",
        ] {
            let error = SbxProfile::parse(invalid).expect_err("invalid must not default");
            assert!(matches!(error, ToolError::InvalidParams(_)));
            assert!(error.to_string().contains(SBX_PROFILE_ENV));
        }
    }

    #[test]
    fn find_sbx_bad_env_var() {
        unsafe { std::env::set_var("SBX", "/nonexistent_sbx_binary") };
        let result = find_sbx();
        unsafe { std::env::remove_var("SBX") };
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("$SBX"), "expected $SBX in error: {msg}");
    }

    #[tokio::test]
    async fn run_sbx_aot_i64_nonexistent_program() {
        let tmp = std::env::temp_dir().join(format!("sbx_test_{}", std::process::id()));
        let result = run_sbx_aot_i64(
            Path::new("/nonexistent_sbx_test_dir/program.so"),
            &tmp.join("out.i64"),
            crate::preprocess::Preparation::new(std::time::Duration::from_secs(1)),
        )
        .await;
        assert!(result.is_err());
    }
}
