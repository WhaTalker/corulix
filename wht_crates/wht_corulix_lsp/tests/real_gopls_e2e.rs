// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof against a real gopls process and a real Go
//! fixture module (`MOCKED_ONLY_CLOSURE=NO`, per this phase's own
//! mandate). Both gopls and its `go` auxiliary tool are resolved through
//! the Phase-6 secure provider resolver (`wht_corulix_config::resolve_provider`)
//! via `HOST_ONLY` absolute/approved-directory configuration -- never
//! ambient `PATH` -- then spawned through `wht_corulix_tooling` (via
//! `wht_corulix_lsp::LspSession`), never directly by this test.
//!
//! If no real gopls/`go` binary is present at this development
//! environment's well-known toolchain locations, every test in this file
//! reports and exits early with `GO_LSP_E2E=BLOCKED_PROVIDER_UNAVAILABLE`
//! rather than failing -- this file never substitutes a mock for the real
//! process it is supposed to prove against.
//!
//! gopls has no `experimental/serverStatus`-equivalent readiness extension
//! (proven empirically during this phase's own capability probe against a
//! real gopls process), so this fixture proves
//! `ReadinessStrategy::FirstDiagnosticsPublished` end-to-end rather than
//! reusing rust-analyzer's signal.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, Position, ProviderCategory, WorkspaceRootId};
use wht_corulix_lsp::{
    DefinitionResult, DiagnosticsResult, LspProviderProfile, LspSession, Readiness,
};
use wht_corulix_workspace::WorkspaceRoot;

/// Test-only PATH-based discovery of `gopls`, `HOST_ONLY`-style for test
/// purposes only -- production callers resolve providers the same way
/// through real host configuration, never a hard-coded constant.
/// `CORULIX_TEST_GOPLS` overrides discovery with an exact binary path.
fn real_gopls_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("CORULIX_TEST_GOPLS") {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("gopls{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
        .map(|dir| dir.join(&exe_name))
}

/// This development environment's real Go toolchain directory. This is a
/// well-known, portable standard install location, not a specific
/// developer's machine path.
const REAL_GO_DIRECTORY: &str = "/usr/local/go/bin";

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

fn real_gopls_available() -> bool {
    real_gopls_path().is_some_and(|p| p.is_file())
        && Path::new(REAL_GO_DIRECTORY).join("go").is_file()
}

fn temp_fixture_module(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-lsp-gopls-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix_lsp_gopls_e2e_fixture\n\ngo 1.22\n",
    );
    let _ = fs::write(
        root.join("main.go"),
        "package main\n\nfunc target() {}\n\nfunc caller() {\n\ttarget()\n}\n\nfunc main() {\n\tcaller()\n}\n",
    );
    root
}

/// Resolves gopls through the real Phase-6 provider resolver against a
/// `HOST_ONLY`-configured absolute path, and builds gopls's sanitized child
/// environment via `wht_corulix_lsp::resolve_environment` (which resolves
/// gopls's own `go` auxiliary tool the same way, never ambient `PATH`).
/// Adds ephemeral, test-owned `GOCACHE`/`GOPATH`/`GOMODCACHE` directories so
/// this test never reads or writes the host's real Go module cache.
async fn resolve_gopls(
    workspace_root: &WorkspaceRoot,
    go_cache_dir: &Path,
) -> Option<wht_corulix_lsp::ResolvedLaunch> {
    let host = HostConfig {
        provider_absolute_paths: vec![(
            ProviderCategory::LanguageServer,
            real_gopls_path().unwrap_or_default(),
        )],
        approved_system_directories: vec![PathBuf::from(REAL_GO_DIRECTORY)],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );

    let profile = LspProviderProfile::gopls();
    let launch = wht_corulix_lsp::resolve_launch(&profile, &effective, workspace_root)
        .await
        .ok()?;
    let environment = launch
        .environment
        .with_var(
            "GOCACHE",
            go_cache_dir.join("cache").to_string_lossy().to_string(),
        )
        .with_var(
            "GOPATH",
            go_cache_dir.join("path").to_string_lossy().to_string(),
        )
        .with_var(
            "GOMODCACHE",
            go_cache_dir
                .join("path/pkg/mod")
                .to_string_lossy()
                .to_string(),
        );
    Some(wht_corulix_lsp::ResolvedLaunch {
        environment,
        ..launch
    })
}

#[tokio::test]
async fn real_gopls_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    if !real_gopls_available() {
        eprintln!(
            "GO_LSP_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real gopls found on PATH (set CORULIX_TEST_GOPLS to override) / go binary at {REAL_GO_DIRECTORY} in this environment"
        );
        return Ok(());
    }

    let fixture = temp_fixture_module("full-vertical");
    let go_cache_dir = fixture.join(".corulix-go-cache");
    let _ = fs::create_dir_all(&go_cache_dir);
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let Some(launch) = resolve_gopls(&workspace_root, &go_cache_dir).await else {
        return Err(fail(
            "gopls did not resolve via the Phase-6 provider resolver",
        ));
    };

    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::gopls();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    let main_go = fixture.join("main.go");

    // `ReadinessStrategy::FirstDiagnosticsPublished` is document-scoped:
    // gopls only pushes `publishDiagnostics` once a document has been
    // opened (proven during this phase's capability probe), unlike
    // rust-analyzer's workspace-wide `experimental/serverStatus`. Open the
    // fixture before waiting, exactly as any real caller would before
    // issuing a semantic request against it.
    session
        .ensure_open(&main_go)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("gopls never reached readiness: {error:?}")))?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }

    // --- DEFINITION: from the `target()` call site to its declaration ---
    // `byte_offset` is `position::core_to_lsp`'s sole addressing key (see
    // its doc comment) -- it must name the real byte offset of the `t` in
    // the `target()` call inside `caller`, not just a plausible-looking
    // line/column pair.
    let definition = wht_corulix_lsp::definition(
        &session,
        &main_go,
        &Position {
            line_zero_based: 5,
            byte_column_zero_based: 1,
            byte_offset: 49,
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
    if definition_location.range.start.line_zero_based != 2 {
        return Err(fail(format!(
            "expected definition on line 2 (func target), got {:?}",
            definition_location.range
        )));
    }
    if definition_location.path.relative_path != "main.go" {
        return Err(fail(format!(
            "expected definition in main.go, got {}",
            definition_location.path.relative_path
        )));
    }

    // --- DOCUMENT SYMBOLS ---
    let document_symbols = wht_corulix_lsp::document_symbols(&session, &main_go, &cancellation)
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

    // --- DIAGNOSTICS: this fixture is valid Go, so expect a proven (not
    // NotReady) diagnostic set, proving ReadinessStrategy::FirstDiagnosticsPublished
    // end-to-end. ---
    let diagnostics_result = wht_corulix_lsp::diagnostics(&session, &main_go)
        .await
        .map_err(|error| fail(format!("diagnostics call failed: {error:?}")))?;
    if !matches!(diagnostics_result, DiagnosticsResult::Reported(_)) {
        return Err(fail(format!(
            "expected Reported after proven readiness, got {diagnostics_result:?}"
        )));
    }

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// Provider unavailable (an auxiliary tool -- `go` -- that cannot be
/// resolved, even though gopls itself resolves fine) must fail closed via
/// `resolve_launch`, never silently spawn gopls without it.
#[tokio::test]
async fn missing_auxiliary_go_tool_fails_closed() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_module("missing-go-tool");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let host = HostConfig {
        provider_absolute_paths: vec![(
            ProviderCategory::LanguageServer,
            real_gopls_path().unwrap_or_default(),
        )],
        // Deliberately no approved directory for `go` -- gopls itself
        // resolves, but its auxiliary `go` dependency does not.
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::gopls();
    let result = wht_corulix_lsp::resolve_launch(&profile, &effective, &workspace_root).await;
    match result {
        Err(wht_corulix_lsp::LspError::ProviderSpawnFailed) => {}
        other => {
            return Err(fail(format!(
                "expected ProviderSpawnFailed when `go` cannot be resolved, got {other:?}"
            )));
        }
    }
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}
