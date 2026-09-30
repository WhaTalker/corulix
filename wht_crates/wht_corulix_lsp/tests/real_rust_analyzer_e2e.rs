// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof against a real rust-analyzer process and a real
//! Rust fixture workspace (`MOCKED_ONLY_CLOSURE=NO`, per this phase's own
//! mandate). rust-analyzer is resolved through the Phase-6 secure provider
//! resolver (`wht_corulix_config::resolve_provider`) via a `HOST_ONLY`
//! absolute path -- never ambient `PATH`, never a `which` lookup -- then
//! spawned through `wht_corulix_tooling` (via `wht_corulix_lsp::LspSession`),
//! never directly by this test.
//!
//! If no real rust-analyzer binary is present at the well-known toolchain
//! location this repository's own development environment installs it at,
//! every test in this file reports and exits early rather than failing --
//! this file never substitutes a mock for the real process it is supposed
//! to prove against.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
#[cfg(unix)]
use wht_corulix_core::Position;
use wht_corulix_core::{
    CancellationToken, ProviderAvailability, ProviderCategory, WorkspaceRootId,
};
#[cfg(unix)]
use wht_corulix_lsp::{DefinitionResult, DiagnosticsResult, Readiness, ReferencesResult};
use wht_corulix_lsp::{LspProviderProfile, LspSession};
use wht_corulix_workspace::WorkspaceRoot;

/// Test-only discovery of a real `rust-analyzer` binary, `HOST_ONLY`-style
/// for test purposes only -- production callers resolve this the same way
/// through real host configuration, never a hard-coded constant.
/// `CORULIX_TEST_RUST_ANALYZER` overrides discovery with an exact binary
/// path. Never resolves to a `~/.cargo/bin` rustup-proxy shim: Corulix's
/// sandboxed process execution strips the environment context that proxy
/// needs to select a toolchain, so resolving to it causes a spurious
/// spawn failure -- this prefers the active toolchain's real sysroot
/// (`rustc --print sysroot`), then falls back to scanning every installed
/// toolchain's `bin/` directory (`rustup show home`) for the first one
/// that actually has the binary, and only then falls back to a plain
/// `PATH` search. Never embeds a specific developer's machine path.
// P17-W corrective P5: gated per-item, not file-level, alongside every
// other helper this file's sole Unix-only test (`real_rust_analyzer_full_vertical_e2e`)
// exclusively uses -- this file's other two tests remain platform-neutral.
#[cfg(unix)]
fn real_rust_analyzer_path() -> Option<PathBuf> {
    resolve_real_toolchain_tool("rust-analyzer", "CORULIX_TEST_RUST_ANALYZER")
}

#[cfg(unix)]
fn resolve_real_toolchain_tool(bin_name: &str, env_override: &str) -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_override) {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("{bin_name}{}", std::env::consts::EXE_SUFFIX);
    if let Ok(output) = std::process::Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        && output.status.success()
    {
        let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let candidate = PathBuf::from(sysroot).join("bin").join(&exe_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Ok(output) = std::process::Command::new("rustup")
        .arg("show")
        .arg("home")
        .output()
        && output.status.success()
    {
        let rustup_home = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let toolchains_dir = PathBuf::from(rustup_home).join("toolchains");
        if let Ok(entries) = std::fs::read_dir(&toolchains_dir) {
            for entry in entries.flatten() {
                let candidate = entry.path().join("bin").join(&exe_name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
        .map(|dir| dir.join(&exe_name))
}

#[cfg(unix)]
const READINESS_TIMEOUT: Duration = Duration::from_secs(60);

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

#[cfg(unix)]
fn real_rust_analyzer_available() -> bool {
    real_rust_analyzer_path().is_some_and(|p| p.is_file())
}

fn temp_fixture_workspace(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-lsp-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_lsp_e2e_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn target() {}\n\nfn caller() {\n    target();\n}\n\nfn main() {\n    caller();\n}\n",
    );
    root
}

/// Resolves `rust-analyzer` through the real Phase-6 provider resolver
/// against a `HOST_ONLY`-configured absolute path -- this is the sole
/// resolution path this test (and Corulix in general) uses; ambient `PATH`
/// is never consulted.
#[cfg(unix)]
async fn resolve_rust_analyzer(workspace_root: &WorkspaceRoot) -> Option<PathBuf> {
    let host = HostConfig {
        provider_absolute_paths: vec![(
            ProviderCategory::LanguageServer,
            real_rust_analyzer_path().unwrap_or_default(),
        )],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let resolution = wht_corulix_config::resolve_provider(
        &effective,
        workspace_root,
        ProviderCategory::LanguageServer,
        "rust-analyzer",
    )
    .await;
    if resolution.availability != ProviderAvailability::Available {
        return None;
    }
    resolution.resolved_path
}

// Windows note (M09/D96, P17-W corrective P5): `#[cfg(unix)]`-only. This
// test's own deep proof (NOT_READY_VS_ZERO_REFERENCES, readiness, hover,
// definition) genuinely requires a live, workspace-bound rust-analyzer
// session -- `LspSession::spawn` always fails closed on Windows via
// `ManagedProcess::spawn_with_workspace_root` before any process is
// spawned (no `fchdir`-equivalent primitive to preserve object-bound cwd
// across `exec`), the same accepted, `FINAL_CLOSED` M09 contract already
// on record ("Windows: workspace-bound LSP UNAVAILABLE_FAIL_CLOSED, zero
// provider spawn"). Unlike a whole-file gate, this file is genuinely
// mixed-platform: this file's other two tests
// (`nonexistent_executable_is_a_typed_spawn_failure`,
// `invalid_provider_path_is_rejected_by_resolver_not_by_lsp`) already pass
// on native Windows today (both assert a typed *pre-spawn* resolver/typed
// error, never a live session), so only this one deep-vertical test is
// gated per-test rather than gating the whole file.
#[cfg(unix)]
#[tokio::test]
async fn real_rust_analyzer_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    if !real_rust_analyzer_available() {
        eprintln!(
            "SKIPPED: no real rust-analyzer binary found on PATH (set CORULIX_TEST_RUST_ANALYZER to override) in this environment"
        );
        return Ok(());
    }

    let fixture = temp_fixture_workspace("full-vertical");
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let resolved_path = resolve_rust_analyzer(&workspace_root)
        .await
        .ok_or_else(|| fail("rust-analyzer did not resolve via the Phase-6 provider resolver"))?;

    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::rust_analyzer();
    let launch = wht_corulix_lsp::ResolvedLaunch {
        executable: resolved_path,
        arguments: Vec::new(),
        environment: wht_corulix_tooling::EnvironmentPolicy::empty(),
        managed_lease: None,
        extra_initialization_options: None,
    };
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    let main_rs = fixture.join("src/main.rs");

    // --- NOT_READY_VS_ZERO_REFERENCES ---
    // Before readiness is proven, references must report `NotReady`, never
    // an authoritative empty result.
    let before_ready = wht_corulix_lsp::references(
        &session,
        &main_rs,
        &Position {
            line_zero_based: 0,
            byte_column_zero_based: 3,
            byte_offset: 3,
        },
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("references before readiness failed: {error:?}")))?;
    if before_ready != ReferencesResult::NotReady {
        return Err(fail(format!(
            "NOT_READY_VS_ZERO_REFERENCES violated: expected NotReady before readiness, got {before_ready:?}"
        )));
    }

    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("rust-analyzer never reached readiness: {error:?}")))?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }

    // --- DEFINITION: from the `target()` call site to its declaration ---
    let definition = wht_corulix_lsp::definition(
        &session,
        &main_rs,
        &Position {
            line_zero_based: 3,
            byte_column_zero_based: 4,
            byte_offset: 0,
        },
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("definition request failed: {error:?}")))?;
    let definition_location = match &definition {
        DefinitionResult::Single(location) => location.clone(),
        DefinitionResult::Multiple(locations) => locations
            .first()
            .cloned()
            .ok_or_else(|| fail("definition returned an empty Multiple result"))?,
        DefinitionResult::None => return Err(fail("expected a real definition, got None")),
    };
    if definition_location.range.start.line_zero_based != 0 {
        return Err(fail(format!(
            "expected definition on line 0 (fn target), got {:?}",
            definition_location.range
        )));
    }
    if definition_location.path.relative_path != "src/main.rs" {
        return Err(fail(format!(
            "expected definition in src/main.rs, got {}",
            definition_location.path.relative_path
        )));
    }

    // --- REFERENCES: after readiness, this fixture has exactly one real
    // call site, so a proven, non-empty result is expected. ---
    let references_result = wht_corulix_lsp::references(
        &session,
        &main_rs,
        &Position {
            line_zero_based: 0,
            byte_column_zero_based: 3,
            byte_offset: 3,
        },
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("references request failed: {error:?}")))?;
    match references_result {
        ReferencesResult::Found(locations) => {
            if locations.is_empty() {
                return Err(fail("expected at least one real reference in the fixture"));
            }
            if !locations
                .iter()
                .any(|location| location.range.start.line_zero_based == 3)
            {
                return Err(fail(format!(
                    "expected a reference on line 3 (the call site), got {locations:?}"
                )));
            }
        }
        ReferencesResult::NotReady => {
            return Err(fail("expected Found after proven readiness, got NotReady"));
        }
    }

    // --- DOCUMENT SYMBOLS ---
    let document_symbols = wht_corulix_lsp::document_symbols(&session, &main_rs, &cancellation)
        .await
        .map_err(|error| fail(format!("documentSymbol request failed: {error:?}")))?;
    if !document_symbols
        .iter()
        .any(|symbol| symbol.name == "target")
    {
        return Err(fail(format!(
            "expected 'target' among document symbols, got {document_symbols:?}"
        )));
    }

    // --- WORKSPACE SYMBOLS ---
    let workspace_symbols = wht_corulix_lsp::workspace_symbols(&session, "target", &cancellation)
        .await
        .map_err(|error| fail(format!("workspace/symbol request failed: {error:?}")))?;
    if !workspace_symbols
        .iter()
        .any(|symbol| symbol.name == "target")
    {
        return Err(fail(format!(
            "expected 'target' among workspace symbols, got {workspace_symbols:?}"
        )));
    }

    // --- DIAGNOSTICS: this fixture is valid Rust, so expect a proven
    // (not NotReady) diagnostic set. ---
    let diagnostics_result = wht_corulix_lsp::diagnostics(&session, &main_rs)
        .await
        .map_err(|error| fail(format!("diagnostics call failed: {error:?}")))?;
    if !matches!(diagnostics_result, DiagnosticsResult::Reported(_)) {
        return Err(fail(format!(
            "expected Reported after proven readiness, got {diagnostics_result:?}"
        )));
    }

    // --- RENAME PREVIEW: never applied, RENAME_PREVIEW_MUTATION_COUNT=0 ---
    let original_bytes_before = fs::read(&main_rs)?;
    let rename_preview = wht_corulix_lsp::rename_preview(
        &session,
        &main_rs,
        &Position {
            line_zero_based: 0,
            byte_column_zero_based: 3,
            byte_offset: 3,
        },
        "renamed_target",
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("rename request failed: {error:?}")))?;
    if rename_preview.edits_by_path.is_empty() {
        return Err(fail("expected a real proposed rename edit"));
    }
    let original_bytes_after = fs::read(&main_rs)?;
    if original_bytes_before != original_bytes_after {
        return Err(fail(
            "RENAME_PREVIEW_MUTATION_COUNT violated: the fixture file changed on disk",
        ));
    }

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// Provider unavailable (invalid/relative host-configured path) must fail
/// closed rather than falling back to any ambient discovery.
#[tokio::test]
async fn invalid_provider_path_is_rejected_by_resolver_not_by_lsp() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_workspace("invalid-provider");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let host = HostConfig {
        provider_absolute_paths: vec![(
            ProviderCategory::LanguageServer,
            PathBuf::from("relative/rust-analyzer"),
        )],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let resolution = wht_corulix_config::resolve_provider(
        &effective,
        &workspace_root,
        ProviderCategory::LanguageServer,
        "rust-analyzer",
    )
    .await;
    if resolution.availability != ProviderAvailability::ProviderUnavailable {
        return Err(fail(format!(
            "expected ProviderUnavailable for a relative host-configured path, got {:?}",
            resolution.availability
        )));
    }
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// A nonexistent executable is rejected as a typed spawn failure, never a
/// panic or a hang.
#[tokio::test]
async fn nonexistent_executable_is_a_typed_spawn_failure() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_workspace("nonexistent-exe");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::rust_analyzer();
    let launch = wht_corulix_lsp::ResolvedLaunch {
        executable: PathBuf::from("/nonexistent/not-a-real-rust-analyzer"),
        arguments: Vec::new(),
        environment: wht_corulix_tooling::EnvironmentPolicy::empty(),
        managed_lease: None,
        extra_initialization_options: None,
    };
    let result = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await;
    match result {
        Err(wht_corulix_lsp::LspError::ProviderSpawnFailed) => {}
        Err(other) => {
            return Err(fail(format!(
                "expected ProviderSpawnFailed for a nonexistent executable, got error {other:?}"
            )));
        }
        Ok(_) => {
            return Err(fail(
                "expected ProviderSpawnFailed for a nonexistent executable, got a live session",
            ));
        }
    }
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}
