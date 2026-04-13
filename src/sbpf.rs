//! Solana sBPF AOT compilation support via `sbx aot i64`.
//!
//! IDA Pro has no native Hex-Rays decompiler for the sBPF instruction set.
//! `sbx aot i64` AOT-compiles the program to a host-native shared library via
//! LLVM, then runs `idat64 -A` to produce a fully-analysed `.i64` database
//! directly — no intermediate dylib step required on the caller's side.

use std::path::{Path, PathBuf};
use std::process::Command;

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

    if let Ok(output) = Command::new("which").arg("sbx").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                let p = PathBuf::from(s);
                if p.exists() {
                    return Ok(p);
                }
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

pub fn run_sbx_aot_i64(input: &Path, output_i64: &Path) -> Result<SbxAotResult, ToolError> {
    let bin = find_sbx()?;

    tracing::info!(
        input = %input.display(),
        output = %output_i64.display(),
        "Running sbx aot i64"
    );

    let abs_input = std::fs::canonicalize(input).unwrap_or_else(|_| input.to_path_buf());

    if let Some(parent) = output_i64.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ToolError::InvalidParams(format!(
                    "Failed to create output directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }
    }

    let output = Command::new(&bin)
        .arg("aot")
        .arg("i64")
        .arg("--program")
        .arg(&abs_input)
        .arg("--output")
        .arg(output_i64)
        .output()
        .map_err(|e| {
            ToolError::InvalidParams(format!("Failed to spawn sbx ({}): {}", bin.display(), e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(ToolError::InvalidParams(format!(
            "sbx aot i64 failed (exit {})\nstderr: {}\nstdout: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim(),
            stdout.trim()
        )));
    }

    if !output_i64.exists() {
        return Err(ToolError::InvalidParams(format!(
            "sbx aot i64 succeeded but output not found: {}",
            output_i64.display()
        )));
    }

    tracing::info!(
        output = %output_i64.display(),
        "sbx aot i64 complete"
    );

    Ok(SbxAotResult {
        i64_path: output_i64.to_path_buf(),
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

    #[test]
    fn run_sbx_aot_i64_nonexistent_program() {
        let tmp = std::env::temp_dir().join(format!("sbx_test_{}", std::process::id()));
        let result = run_sbx_aot_i64(
            Path::new("/nonexistent_sbx_test_dir/program.so"),
            &tmp.join("out.i64"),
        );
        assert!(result.is_err());
    }
}
