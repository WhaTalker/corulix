// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof against a real Pyright (`pyright-langserver`)
//! process and a real Python fixture (`MOCKED_ONLY_CLOSURE=NO`, per this
//! phase's own mandate). Pyright and its Node interpreter are both
//! resolved through the Phase-6 secure provider resolver
//! (`wht_corulix_config::resolve_provider`) via `HOST_ONLY` absolute/
//! approved-directory configuration -- never ambient `PATH` -- then
//! spawned through `wht_corulix_tooling` (via `wht_corulix_lsp::LspSession`),
//! never directly by this test. Pyright's canonical script carries a
//! `#!/usr/bin/env node` shebang that is never read or relied upon (see
//! `wht_corulix_lsp::profile::resolve_launch`): Node is resolved as its
//! own auxiliary tool and invoked directly, with the resolved script path
//! as an explicit `argv[1]`.
//!
//! If no real Node/Pyright binary is discoverable via `PATH` (or the
//! `CORULIX_TEST_NODE_DIR`/`CORULIX_TEST_PYRIGHT_LANGSERVER_JS`
//! overrides), every test in this file reports and exits early with
//! `PYTHON_LSP_E2E=BLOCKED_PROVIDER_UNAVAILABLE` rather than failing.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{
    CancellationToken, Position, ProviderAvailability, ProviderCategory, WorkspaceRootId,
};
use wht_corulix_lsp::{
    DefinitionResult, DiagnosticsResult, LspProviderProfile, LspSession, Readiness,
};
use wht_corulix_workspace::WorkspaceRoot;

/// Test-only PATH-based tool discovery. `CORULIX_TEST_NODE_DIR` overrides
/// discovery when set to an explicit directory; otherwise the directory on
/// `PATH` containing `node` is used. Never embeds a specific developer's
/// machine path.
fn real_node_directory() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("CORULIX_TEST_NODE_DIR") {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("node{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
}

/// Test-only discovery of Pyright's real language-server entry script.
/// `CORULIX_TEST_PYRIGHT_LANGSERVER_JS` overrides discovery with an exact
/// file path; otherwise `pyright-langserver` is resolved from `PATH` and
/// followed through its symlink(s) to the real underlying JS entry point
/// (npm installs this as a shebang script that `readlink -f` resolves to
/// `<pyright package>/langserver.index.js`, matching npm's own layout on
/// any host, not a specific developer's machine path).
fn real_pyright_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("CORULIX_TEST_PYRIGHT_LANGSERVER_JS") {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("pyright-langserver{}", std::env::consts::EXE_SUFFIX);
    let wrapper = std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))?
        .join(&exe_name);
    fs::canonicalize(wrapper).ok()
}

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

fn real_pyright_available() -> bool {
    real_pyright_path().is_some_and(|p| p.is_file())
        && real_node_directory().is_some_and(|dir| dir.join("node").is_file())
}

fn temp_fixture_module(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-lsp-pyright-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("main.py"),
        "def target():\n    pass\n\n\ndef caller():\n    target()\n",
    );
    root
}

/// Resolves Pyright through the real Phase-6 provider resolver against a
/// `HOST_ONLY`-configured absolute path, and builds its sanitized launch
/// (executable/arguments/environment) via
/// `wht_corulix_lsp::resolve_launch` -- which resolves the `node`
/// interpreter the same way, never ambient `PATH`, and never executes
/// Pyright's own script directly.
async fn resolve_pyright(
    workspace_root: &WorkspaceRoot,
) -> Option<wht_corulix_lsp::ResolvedLaunch> {
    let host = HostConfig {
        provider_absolute_paths: vec![(
            ProviderCategory::LanguageServer,
            real_pyright_path().unwrap_or_default(),
        )],
        approved_system_directories: vec![real_node_directory().unwrap_or_default()],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::pyright();
    wht_corulix_lsp::resolve_launch(&profile, &effective, workspace_root)
        .await
        .ok()
}

#[tokio::test]
async fn real_pyright_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    if !real_pyright_available() {
        eprintln!(
            "PYTHON_LSP_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real Node/Pyright binary found on PATH (set CORULIX_TEST_NODE_DIR/CORULIX_TEST_PYRIGHT_LANGSERVER_JS to override)"
        );
        return Ok(());
    }

    let fixture = temp_fixture_module("full-vertical");
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let Some(launch) = resolve_pyright(&workspace_root).await else {
        return Err(fail(
            "pyright did not resolve via the Phase-6 provider resolver",
        ));
    };

    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::pyright();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    let main_py = fixture.join("main.py");

    // `ReadinessStrategy::FirstDiagnosticsPublished` is document-scoped
    // (proven identically for gopls) -- open the fixture before waiting.
    session
        .ensure_open(&main_py)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("pyright never reached readiness: {error:?}")))?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }

    // --- DEFINITION: from the `target()` call site to its declaration ---
    // byte_offset 43 is the `t` of `target()` inside `caller` (`position::
    // core_to_lsp`'s sole addressing key -- see its doc comment).
    let definition = wht_corulix_lsp::definition(
        &session,
        &main_py,
        &Position {
            line_zero_based: 5,
            byte_column_zero_based: 4,
            byte_offset: 43,
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
            "expected definition on line 0 (def target), got {:?}",
            definition_location.range
        )));
    }
    if definition_location.path.relative_path != "main.py" {
        return Err(fail(format!(
            "expected definition in main.py, got {}",
            definition_location.path.relative_path
        )));
    }

    // --- DOCUMENT SYMBOLS ---
    let document_symbols = wht_corulix_lsp::document_symbols(&session, &main_py, &cancellation)
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

    // --- DIAGNOSTICS: this fixture is valid Python, so expect a proven
    // (not NotReady) diagnostic set. ---
    let diagnostics_result = wht_corulix_lsp::diagnostics(&session, &main_py)
        .await
        .map_err(|error| fail(format!("diagnostics call failed: {error:?}")))?;
    if !matches!(diagnostics_result, DiagnosticsResult::Reported(_)) {
        return Err(fail(format!(
            "expected Reported after proven readiness, got {diagnostics_result:?}"
        )));
    }

    // --- RENAME PREVIEW: never applied, RENAME_PREVIEW_MUTATION_COUNT=0 ---
    let original_bytes_before = fs::read(&main_py)?;
    let rename_preview = wht_corulix_lsp::rename_preview(
        &session,
        &main_py,
        &Position {
            line_zero_based: 0,
            byte_column_zero_based: 4,
            byte_offset: 4,
        },
        "renamed_target",
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("rename request failed: {error:?}")))?;
    if rename_preview.edits_by_path.is_empty() {
        return Err(fail("expected a real proposed rename edit"));
    }
    let original_bytes_after = fs::read(&main_py)?;
    if original_bytes_before != original_bytes_after {
        return Err(fail(
            "RENAME_PREVIEW_MUTATION_COUNT violated: the fixture file changed on disk",
        ));
    }

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// Provider unavailable (an auxiliary tool -- `node` -- that cannot be
/// resolved, even though pyright itself resolves fine) must fail closed
/// via `resolve_launch`, never silently spawn pyright without it.
#[tokio::test]
async fn missing_auxiliary_node_interpreter_fails_closed() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_module("missing-node");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let host = HostConfig {
        provider_absolute_paths: vec![(
            ProviderCategory::LanguageServer,
            real_pyright_path().unwrap_or_default(),
        )],
        // Deliberately no approved directory for `node` -- pyright's own
        // resolved script path resolves fine, but its required interpreter
        // does not.
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::pyright();
    let result = wht_corulix_lsp::resolve_launch(&profile, &effective, &workspace_root).await;
    match result {
        Err(wht_corulix_lsp::LspError::ProviderSpawnFailed) => {}
        other => {
            return Err(fail(format!(
                "expected ProviderSpawnFailed when node cannot be resolved, got {other:?}"
            )));
        }
    }
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// A `HOST_ONLY`-configured node directory that does not actually contain
/// `node` is reported `ProviderUnavailable` for the auxiliary tool, not
/// silently substituted with any workspace-local or ambient candidate.
#[tokio::test]
async fn poisoned_workspace_local_node_is_never_selected() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_module("poisoned-node");
    let _ = fs::write(fixture.join("node"), "#!/bin/sh\necho evil\n");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let host = HostConfig {
        // The workspace itself is (deliberately, for this negative test
        // only) declared as an approved system directory, to prove even an
        // explicitly host-approved directory cannot smuggle in a
        // workspace-local executable -- the same precedence step
        // `resolve_launch`'s auxiliary-tool resolution uses.
        approved_system_directories: vec![fixture.clone()],
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
        ProviderCategory::Runtime,
        "node",
    )
    .await;
    if resolution.availability == ProviderAvailability::Available {
        return Err(fail(
            "a workspace-local node candidate must never resolve as Available",
        ));
    }
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}
