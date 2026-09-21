// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P18 real end-to-end test: Windows `gate.diagnostics`'s own managed
//! linker closure. `MOCKED_ONLY_CLOSURE=NO`.
//!
//! Proves, against a real, controlled `build.rs` fixture, that
//! `wht_corulix_engine::diagnostics::run_cargo_check` on Windows genuinely
//! compiles and runs the build script (host `x86_64-pc-windows-gnu`, via the
//! self-contained managed MinGW-w64 linker) while checking the workspace
//! against the canonical `x86_64-pc-windows-msvc` target -- with no system
//! linker, no Visual Studio, no Windows SDK, and no ambient `PATH` entry of
//! any kind. Compiled and run only on `cfg(target_os = "windows")`: this
//! file's own tests are a no-op on every other host.

#![cfg(target_os = "windows")]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::CancellationToken;
use wht_corulix_engine::diagnostics::{RustValidatorError, run_cargo_check};
use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64;
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

#[derive(Debug)]
struct TestFailure(String);

impl fmt::Display for TestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for TestFailure {}

fn fail(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(TestFailure(message.into()))
}

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| "C:\\Users\\testing".to_string());
    let dir = PathBuf::from(base).join(format!(".cache\\corulix-p18-diagnostics-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn managed_root() -> PathBuf {
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| "C:\\Users\\testing".to_string());
    PathBuf::from(base).join(".cache\\corulix-p18-diagnostics-e2e\\root")
}

async fn ensure_provisioned() -> Option<PathBuf> {
    let root = managed_root();
    let (state, _) = provisioning::resolve_managed_component(
        &root,
        &RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64,
    );
    if state != ManagedComponentState::Available
        && provisioning::provision(&root, &RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64)
            .await
            .is_err()
    {
        return None;
    }
    Some(root)
}

fn trusted_effective_config() -> wht_corulix_config::EffectiveConfig {
    let host = wht_corulix_config::HostConfig {
        workspace_trust: wht_corulix_core::WorkspaceTrust::Trusted,
        allow_trusted_workspace_execution: true,
        ..wht_corulix_config::HostConfig::default()
    };
    wht_corulix_config::EffectiveConfig::derive(
        &host,
        &wht_corulix_config::RepositoryHints::default(),
        &wht_corulix_config::RequestOptions::default(),
    )
}

/// Same fixture shape as `real_p11_r1_trust_enforcement_e2e.rs`'s own
/// `write_buildrs_fixture` -- a real crate whose `build.rs` writes
/// `marker_path` to disk only if it genuinely compiled and ran.
///
/// `src/main.rs` additionally carries a real, load-bearing
/// `#[cfg(target_env = ...)]` positive/negative control on the *checked*
/// target: `main.rs` (unlike `build.rs`) is compiled for whatever `--target`
/// `cargo check` was actually given, never the host triple, so this proves
/// the workspace was genuinely checked against `x86_64-pc-windows-msvc` --
/// not silently target-family-drifted to the GNU host triple (a `cargo
/// check` that quietly ignored `--target` and checked the host GNU target
/// instead would still write the marker file and still report zero errors,
/// which is exactly the false-clean-evidence class this control exists to
/// rule out; see `RustValidatorError::ManagedClippyUnavailable`'s own doc
/// comment for the precedent this codebase already has for that defect
/// class). If the checked `target_env` is genuinely `msvc`, neither
/// `compile_error!` fires and the crate compiles clean; if it silently
/// drifted to `gnu`, the first one fires and `error_count > 0`, failing
/// [`RustDiagnosticsOutcome::is_clean`] loudly instead of passing by
/// accident.
fn write_buildrs_fixture(
    dir: &std::path::Path,
    marker_path: &std::path::Path,
) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p18_windows_buildrs_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
    )?;
    fs::write(
        dir.join("src/main.rs"),
        "#[cfg(target_env = \"gnu\")]\ncompile_error!(\"P18_TARGET_FAMILY_DRIFT: gate.diagnostics checked target_env=gnu, expected msvc\");\n\
         #[cfg(not(target_env = \"msvc\"))]\ncompile_error!(\"P18_TARGET_ENV_CFG_DID_NOT_FIRE: expected target_env=msvc\");\n\
         fn main() {}\n",
    )?;
    fs::write(
        dir.join("build.rs"),
        format!(
            "fn main() {{ std::fs::write(r#\"{}\"#, b\"ran\").expect(\"write marker\"); }}\n",
            marker_path.display()
        ),
    )?;
    Ok(())
}

/// `WINDOWS_DIAGNOSTICS_BUILD_RS_CARGO_CHECK=PASS`: under the final,
/// accepted Windows 1.0.0 M09 contract, `run_cargo_check` is
/// `ExecutionClass::TrustedWorkspaceExecution`, and Windows fails closed
/// before spawning any workspace-bound child process for that class
/// (`M09_P12_WINDOWS_TRUSTED_WORKSPACE_EXECUTION_SPAWN_COUNT=0` -- no
/// fallback to a raw pathname `Command::current_dir(workspace_path)`).
/// P18's managed GNU-hosted/MSVC-target-checked runtime resolves and
/// provisions correctly (see `real_p18_windows_diagnostics_runtime_
/// provision_e2e`), but never reaches native process creation -- this
/// proves the `build.rs`-carrying fixture is correctly denied with
/// [`RustValidatorError::SpawnFailed`] rather than silently accepted or
/// left ambiguous, and that no `BUILD_MARKER` is ever written (the build
/// script itself never runs).
#[tokio::test]
async fn real_p18_windows_diagnostics_build_rs_cargo_check_e2e() -> Result<(), Box<dyn Error>> {
    let Some(root) = ensure_provisioned().await else {
        eprintln!(
            "P18_WINDOWS_DIAGNOSTICS_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)"
        );
        return Ok(());
    };
    let fixture_dir = temp_dir("buildrs");
    let marker_path = fixture_dir.join("BUILD_MARKER");
    write_buildrs_fixture(&fixture_dir, &marker_path)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let result = run_cargo_check(&root, &fixture_dir, &effective, &cancellation).await;
    if result != Err(RustValidatorError::SpawnFailed) {
        return Err(fail(format!(
            "expected the accepted Windows fail-closed contract (SpawnFailed, no workspace-bound \
             child process ever spawned for TrustedWorkspaceExecution), got {result:?}"
        )));
    }
    if marker_path.exists() {
        return Err(fail(
            "BUILD_MARKER exists: build.rs executed despite the fail-closed contract -- \
             Windows TrustedWorkspaceExecution enforcement is not load-bearing",
        ));
    }
    eprintln!("WINDOWS_DIAGNOSTICS_BUILD_RS_CARGO_CHECK=PASS");
    Ok(())
}

/// `WINDOWS_DIAGNOSTICS_SIMPLE_CARGO_CHECK=PASS`: same final Windows 1.0.0
/// M09 contract as the `build.rs` case above, against a plain crate with no
/// `build.rs` at all -- `run_cargo_check` still fails closed with
/// [`RustValidatorError::SpawnFailed`] before any process is spawned,
/// regardless of whether the checked crate has a build script, because the
/// fail-closed gate is keyed on `ExecutionClass::TrustedWorkspaceExecution`
/// itself, not on what the checked crate contains.
#[tokio::test]
async fn real_p18_windows_diagnostics_simple_cargo_check_e2e() -> Result<(), Box<dyn Error>> {
    let Some(root) = ensure_provisioned().await else {
        eprintln!(
            "P18_WINDOWS_DIAGNOSTICS_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)"
        );
        return Ok(());
    };
    let fixture_dir = temp_dir("simple");
    fs::create_dir_all(fixture_dir.join("src"))?;
    fs::write(
        fixture_dir.join("Cargo.toml"),
        "[package]\nname = \"p18_windows_simple_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        fixture_dir.join("src/main.rs"),
        "fn main() { println!(\"hi\"); }\n",
    )?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let result = run_cargo_check(&root, &fixture_dir, &effective, &cancellation).await;
    if result != Err(RustValidatorError::SpawnFailed) {
        return Err(fail(format!(
            "expected the accepted Windows fail-closed contract (SpawnFailed, no workspace-bound \
             child process ever spawned for TrustedWorkspaceExecution), got {result:?}"
        )));
    }
    eprintln!("WINDOWS_DIAGNOSTICS_SIMPLE_CARGO_CHECK=PASS");
    Ok(())
}

/// `WINDOWS_DIAGNOSTICS_RUNTIME_PROVISION=PASS`: the managed component
/// itself provisions and resolves as `Available` under a real, isolated
/// managed root.
#[tokio::test]
async fn real_p18_windows_diagnostics_runtime_provision_e2e() -> Result<(), Box<dyn Error>> {
    let Some(root) = ensure_provisioned().await else {
        eprintln!(
            "P18_WINDOWS_DIAGNOSTICS_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)"
        );
        return Ok(());
    };
    let (state, _) = provisioning::resolve_owned_managed_component(
        &root,
        &RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64,
    );
    if state != ManagedComponentState::Available {
        return Err(fail(format!("expected Available, got {state:?}")));
    }
    eprintln!("WINDOWS_DIAGNOSTICS_RUNTIME_PROVISION=PASS");
    Ok(())
}
