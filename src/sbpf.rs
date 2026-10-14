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

// ── AOT compilation ───────────────────────────────────────────────────────

pub struct SbxAotResult {
    pub i64_path: PathBuf,
}

pub async fn run_sbx_aot_i64(
    input: &Path,
    output_i64: &Path,
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
                let bin = find_sbx()?;
                let abs_input = std::fs::canonicalize(&input).map_err(|e| {
                    ToolError::InvalidParams(format!("sbx input {}: {e}", input.display()))
                })?;
                let stage = crate::preprocess::StagedArtifact::create(&destination)
                    .map_err(|e| ToolError::IdaError(format!("sbx staging: {e}")))?;
                Ok::<_, ToolError>((bin, abs_input, stage))
            },
        ))
        .await??;
    preparation.check()?;
    let mut command = Command::new(&bin);
    command
        .arg("aot")
        .arg("i64")
        .arg("--program")
        .arg(&abs_input)
        .arg("--output")
        .arg(&stage.output);
    let output = crate::preprocess::run(command, preparation.clone()).await?;
    if !output.status.success() {
        return Err(ToolError::InvalidParams(format!(
            "sbx aot i64 failed (exit {})\nstderr: {}\nstdout: {}",
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
