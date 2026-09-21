// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof against a real `typescript-language-server`
//! process, for TypeScript and JavaScript separately
//! (`wht_docs/wht_adr/wht_0008-typescript-javascript-lsp-provider.md`).
//!
//! `typescript-language-server` bundles no TypeScript of its own and
//! requires an explicit, `tsserver.js`-capable TypeScript install via
//! `initializationOptions.tsserver.path`. This development environment's
//! only installed TypeScript is the current native/Go-ported compiler
//! rewrite ("tsgo"), which ships no `tsserver.js` at all -- confirmed
//! empirically (see the ADR) -- and no other *host-approved* classic
//! TypeScript install exists on this host (an unrelated IDE's private
//! bundled copy does not count as `HOST_ONLY` configuration; see the ADR
//! for why). Per this phase's mandate ("If an admitted provider/runtime
//! disappears: BLOCKED_PROVIDER_UNAVAILABLE, not auto-install"), this file
//! honestly reports and exits early rather than fabricating a PASS or
//! silently reaching into another application's private directory.
//!
//! `TS_JS_HOST_APPROVED_TSSERVER_PATH` may be set by a CI/host environment
//! that does provision a compatible TypeScript install. As of Phase 7B-C
//! this now yields a real, passing run against a real
//! `typescript-language-server` process. The original discrepancy this
//! module previously attributed to `wht_corulix_tooling::ManagedProcess`
//! (and, in an intermediate investigative pass, to `tokio::process` itself)
//! was neither: it was two missing `initialize` client capabilities.
//! Without `workspace.configuration`, the server never issues its
//! `workspace/configuration` round-trip at all. Without
//! `textDocument.publishDiagnostics`, the server computes diagnostics but
//! never *sends* the `publishDiagnostics` notification this crate's
//! `ReadinessStrategy::FirstDiagnosticsPublished` waits on -- confirmed by
//! a raw probe that declared only the `workspace` half: the
//! `workspace/configuration` round-trip completed correctly, yet no
//! `publishDiagnostics` notification ever followed, across three
//! independent transports (`wht_corulix_tooling::ManagedProcess`, bare
//! `tokio::process`, and bare `std::process` with fully blocking
//! OS-thread I/O) -- which is what had misleadingly pointed at
//! `ManagedProcess`/`tokio` as the culprit before both capabilities were
//! declared together. Both are now declared in
//! `crate::session::initialize_handshake`, generically for every provider
//! (not TS6-specific -- rust-analyzer/gopls/Pyright never depended on the
//! client omitting either).

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, Position, ProviderCategory, WorkspaceRootId};
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

/// Test-only discovery of the real `typescript-language-server` CLI entry
/// script. `CORULIX_TEST_TS_LS_CLI_JS` overrides discovery with an exact
/// file path; otherwise `typescript-language-server` is resolved from
/// `PATH` and followed through its symlink(s) to the real underlying
/// `.mjs` entry point (npm installs this as a shebang script that
/// `readlink -f` resolves to `<package>/lib/cli.mjs`, matching npm's own
/// layout on any host, not a specific developer's machine path).
fn real_ts_ls_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("CORULIX_TEST_TS_LS_CLI_JS") {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("typescript-language-server{}", std::env::consts::EXE_SUFFIX);
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

/// A host-approved, `tsserver.js`-capable TypeScript path, if the current
/// environment provisions one. `None` on this development host (see the
/// module docs) -- never a fallback to an incidentally-discovered path.
fn host_approved_tsserver_path() -> Option<PathBuf> {
    std::env::var_os("TS_JS_HOST_APPROVED_TSSERVER_PATH").map(PathBuf::from)
}

fn real_ts_ls_available() -> bool {
    real_ts_ls_path().is_some_and(|p| p.is_file())
        && real_node_directory().is_some_and(|dir| dir.join("node").is_file())
}

/// `config_file_name` is `tsconfig.json` for the TypeScript fixture and
/// `jsconfig.json` for the JavaScript fixture -- each fixture is its own
/// directory with its own project config (Section 13 of the Phase 7B
/// mandate: TS and JS are certified as separate real fixtures, never one
/// inferred from the other).
fn temp_fixture(
    label: &str,
    file_name: &str,
    text: &str,
    config_file_name: &str,
) -> (PathBuf, PathBuf) {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-lsp-tsls-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join(config_file_name),
        r#"{"compilerOptions":{"target":"es2020"}}"#,
    );
    let file = root.join(file_name);
    let _ = fs::write(&file, text);
    (root, file)
}

async fn resolve_ts_ls(
    profile: &LspProviderProfile,
    workspace_root: &WorkspaceRoot,
) -> Option<wht_corulix_lsp::ResolvedLaunch> {
    let host = HostConfig {
        provider_absolute_paths: vec![(
            ProviderCategory::LanguageServer,
            real_ts_ls_path().unwrap_or_default(),
        )],
        approved_system_directories: vec![real_node_directory().unwrap_or_default()],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    wht_corulix_lsp::resolve_launch(profile, &effective, workspace_root)
        .await
        .ok()
}

async fn run_full_vertical(
    language_label: &str,
    profile_language: LspProviderProfile,
    file_name: &str,
    config_file_name: &str,
    text: &str,
    definition_offset: u64,
    definition_line: u32,
) -> Result<(), Box<dyn Error>> {
    let Some(tsserver_path) = host_approved_tsserver_path() else {
        eprintln!(
            "{language_label}_LSP_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no host-approved tsserver.js on this host (see wht_docs/wht_adr/wht_0008-typescript-javascript-lsp-provider.md); set TS_JS_HOST_APPROVED_TSSERVER_PATH to run this test for real"
        );
        return Ok(());
    };
    if !real_ts_ls_available() {
        eprintln!(
            "{language_label}_LSP_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real typescript-language-server/node binary in this environment"
        );
        return Ok(());
    }

    let (fixture, file) = temp_fixture("full-vertical", file_name, text, config_file_name);
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    // `initialization_options` is `Option<fn() -> Value>`, so the
    // host-approved `tsserver.path` (only known at test time, via the env
    // var this test already validated is present) cannot be baked into a
    // `const fn`-constructed profile the way the production defaults are.
    // `options_from_env` re-reads the same env var; the production
    // security posture (`plugins: []`, `disableAutomaticTypingAcquisition:
    // true`) is preserved verbatim there.
    let _ = &tsserver_path;
    let profile = profile_language.with_initialization_options(options_from_env);

    let Some(launch) = resolve_ts_ls(&profile, &workspace_root).await else {
        return Err(fail(
            "typescript-language-server did not resolve via the Phase-6 provider resolver",
        ));
    };

    let cancellation = CancellationToken::new();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    session
        .ensure_open(&file)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| {
            fail(format!(
                "{language_label} never reached readiness: {error:?}"
            ))
        })?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }

    let definition = wht_corulix_lsp::definition(
        &session,
        &file,
        &Position {
            line_zero_based: definition_line,
            byte_column_zero_based: 2,
            byte_offset: definition_offset,
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
            "expected definition on line 0, got {:?}",
            definition_location.range
        )));
    }

    let document_symbols = wht_corulix_lsp::document_symbols(&session, &file, &cancellation)
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

    let diagnostics_result = wht_corulix_lsp::diagnostics(&session, &file)
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

/// Reads `TS_JS_HOST_APPROVED_TSSERVER_PATH` at call time -- the profile
/// stores this as a plain `fn() -> Value` (matching every other provider's
/// `initialization_options` shape) rather than a capturing closure, since
/// `LspProviderProfile` derives `Clone`/`Debug` over a `#[non_exhaustive]`
/// data shape shared with the production constructors.
fn options_from_env() -> serde_json::Value {
    let tsserver_path = std::env::var("TS_JS_HOST_APPROVED_TSSERVER_PATH").unwrap_or_default();
    serde_json::json!({
        "plugins": [],
        "preferences": { "disableAutomaticTypingAcquisition": true },
        "tsserver": { "path": tsserver_path }
    })
}

#[tokio::test]
async fn real_typescript_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    run_full_vertical(
        "TYPESCRIPT",
        LspProviderProfile::typescript_language_server(),
        "main.ts",
        "tsconfig.json",
        "export function target(): void {}\n\nexport function caller(): void {\n  target();\n}\n",
        // byte_offset of the `t` in the `target()` call site.
        70,
        3,
    )
    .await
}

#[tokio::test]
async fn real_javascript_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    run_full_vertical(
        "JAVASCRIPT",
        LspProviderProfile::typescript_language_server_for_javascript(),
        "main.js",
        "jsconfig.json",
        "function target() {}\n\nfunction caller() {\n  target();\n}\n",
        // byte_offset of the `t` in the `target()` call site.
        44,
        3,
    )
    .await
}
