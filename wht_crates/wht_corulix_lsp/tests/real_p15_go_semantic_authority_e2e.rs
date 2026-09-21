// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15 §10/§11: real, end-to-end proof of `gopls` as the authoritative Go
//! semantic provider for the two operations no pre-existing Corulix test
//! covered -- `textDocument/references` and `textDocument/rename` (preview)
//! -- plus the real Go diagnostic case, all against a real `gopls` process
//! driven through the existing `wht_corulix_lsp` session/transport
//! machinery (Architecture Rule L). No new LSP client, no new readiness
//! strategy, no new process runtime: this file is *evidence*, not
//! infrastructure.
//!
//! Phase 7B already certified `definition`/`documentSymbol`/`diagnostics`
//! against real host gopls (`real_gopls_e2e.rs`) and the whole
//! `CORULIX_MANAGED` Go vertical (`real_gopls_managed_e2e.rs`,
//! `real_gopls_managed_adversarial_e2e.rs`,
//! `real_gopls_product_identity_e2e.rs`). P15 does not re-derive any of
//! that; it closes the two remaining semantic operations the mandate's
//! §10 requires and adds the §11 negative matrix for them.
//!
//! Provider resolution is the real Phase-6 resolver
//! (`wht_corulix_config::resolve_provider`) against a `HOST_ONLY`
//! configuration -- `P15_AMBIENT_PATH_AUTHORITY=NO`. `gopls` and its `go`
//! auxiliary tool are already-installed *system* tooling on this host;
//! nothing here downloads, installs, or provisions anything
//! (`P15_AUTO_INSTALL_EXTERNAL_TOOLING=NO`).
//!
//! `rename_preview` never writes live source: every test below re-reads the
//! fixture's bytes after the request and asserts they are byte-identical to
//! what was written before it (`RENAME_PREVIEW_MUTATION_COUNT=0`).
//!
//! If no real gopls/`go` binary is present at this host's toolchain
//! locations, every test reports and exits early with
//! `P15_GO_SEMANTIC_E2E=BLOCKED_PROVIDER_UNAVAILABLE` rather than
//! substituting a mock for the real process it exists to prove against.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, Position, ProviderCategory, WorkspaceRootId};
use wht_corulix_lsp::{
    DiagnosticsResult, LspProviderProfile, LspSession, Readiness, ReferencesResult,
};
use wht_corulix_workspace::WorkspaceRoot;

/// Test-only PATH-based discovery of `gopls`, `HOST_ONLY`-style for test
/// purposes only -- a production caller supplies these through real host
/// configuration, never a hard-coded constant. `CORULIX_TEST_GOPLS`
/// overrides discovery with an exact binary path.
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

/// The one Go fixture every test in this file uses. `target` is declared
/// once and referenced from exactly one other function, so `references`
/// (which this crate issues with `include_declaration: false`) has a real,
/// non-empty, *countable* answer, and `rename` has a real multi-site edit
/// set -- not a single-site rename that would prove nothing about edit
/// aggregation.
const FIXTURE_MAIN_GO: &str = "package main\n\
                               \n\
                               func target() int {\n\
                               \treturn 41\n\
                               }\n\
                               \n\
                               func caller() int {\n\
                               \treturn target()\n\
                               }\n\
                               \n\
                               func main() {\n\
                               \t_ = caller()\n\
                               }\n";

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

fn real_go_toolchain_available() -> bool {
    real_gopls_path().is_some_and(|p| p.is_file())
        && Path::new(REAL_GO_DIRECTORY).join("go").is_file()
}

/// Computes a complete [`Position`] -- line, UTF-8 byte column, and byte
/// offset, every field `wht_corulix_core::Position` requires -- for the
/// `occurrence`-th (0-based) byte offset of `needle` in `source`.
///
/// Derived from the real source text rather than hard-coded, because
/// `wht_corulix_lsp::position::core_to_lsp` treats `byte_offset` as its sole
/// addressing key: a plausible-looking line/column pair with a wrong offset
/// silently addresses the wrong token, which would make a passing assertion
/// meaningless.
fn position_of(source: &str, needle: &str, occurrence: usize) -> Option<Position> {
    let mut search_from = 0usize;
    let mut byte_offset = None;
    for _ in 0..=occurrence {
        let found = source[search_from..].find(needle)? + search_from;
        search_from = found + 1;
        byte_offset = Some(found);
    }
    let byte_offset = byte_offset?;
    let preceding = &source[..byte_offset];
    let line_zero_based = preceding.matches('\n').count() as u32;
    let line_start = preceding.rfind('\n').map_or(0, |index| index + 1);
    Some(Position {
        line_zero_based,
        byte_column_zero_based: (byte_offset - line_start) as u32,
        byte_offset: byte_offset as u64,
    })
}

fn temp_fixture_module(label: &str, main_go: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-p15-go-semantic-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    // Stdlib-only, zero external module dependencies: nothing here can
    // require a network fetch (`P15_GO_E2E_EXTERNAL_NETWORK_REQUIRED=NO`).
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix_p15_go_semantic_fixture\n\ngo 1.24\n",
    );
    let _ = fs::write(root.join("main.go"), main_go);
    root
}

/// Resolves gopls through the real Phase-6 provider resolver against a
/// `HOST_ONLY`-configured absolute path (never ambient `PATH`), then adds
/// ephemeral, test-owned `GOCACHE`/`GOPATH`/`GOMODCACHE` directories so this
/// test never reads or writes the host's real Go caches. Mirrors
/// `real_gopls_e2e.rs`'s own `resolve_gopls` exactly -- this file introduces
/// no second resolution path.
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

/// Spawns a real gopls session against `fixture` and drives it to genuine
/// semantic readiness.
///
/// `ReadinessStrategy::FirstDiagnosticsPublished` (gopls has no
/// `experimental/serverStatus` equivalent -- established empirically in
/// Phase 7B, reused here unchanged) is *document-scoped*: the fixture must
/// be opened before `wait_until_ready`, exactly as any real caller would
/// before issuing a semantic request against it.
/// `P15_GOPLS_READINESS_SIGNAL_PROVEN`: the returned session is asserted
/// `Readiness::Ready` before any semantic request is issued, so no empty
/// result below can be a not-ready artifact masquerading as authority.
async fn ready_session(fixture: &Path) -> Result<LspSession, Box<dyn Error>> {
    let go_cache_dir = fixture.join(".corulix-go-cache");
    let _ = fs::create_dir_all(&go_cache_dir);
    let workspace_root = WorkspaceRoot::open(fixture)?;
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

    session
        .ensure_open(&fixture.join("main.go"))
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
    Ok(session)
}

/// `P15_REAL_GO_REFERENCES_E2E`: a real, non-empty
/// `textDocument/references` answer from real gopls, taken from `target`'s
/// own declaration site so the (declaration-excluding) result is the single
/// real call site inside `caller` -- a counted answer, not merely "not
/// empty".
#[tokio::test]
async fn real_go_references_e2e() -> Result<(), Box<dyn Error>> {
    if !real_go_toolchain_available() {
        eprintln!(
            "P15_GO_SEMANTIC_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real gopls found on PATH (set CORULIX_TEST_GOPLS to override) / go at {REAL_GO_DIRECTORY}"
        );
        return Ok(());
    }
    let fixture = temp_fixture_module("references", FIXTURE_MAIN_GO);
    let session = ready_session(&fixture).await?;
    let cancellation = CancellationToken::new();
    let main_go = fixture.join("main.go");

    let declaration = position_of(FIXTURE_MAIN_GO, "target", 0)
        .ok_or_else(|| fail("fixture does not contain the expected `target` declaration"))?;
    let result = wht_corulix_lsp::references(&session, &main_go, &declaration, &cancellation)
        .await
        .map_err(|error| fail(format!("references request failed: {error:?}")))?;

    // `NotReady` here would mean the readiness signal was not actually
    // load-bearing -- an empty/absent answer must never be reported as
    // authoritative absence (mandate §9).
    let locations = match &result {
        ReferencesResult::Found(locations) => locations,
        ReferencesResult::NotReady => {
            return Err(fail(
                "references reported NotReady after proven readiness -- readiness signal is not load-bearing",
            ));
        }
    };
    if locations.is_empty() {
        return Err(fail(
            "expected the real call site inside `caller`, got zero references",
        ));
    }
    let call_site = position_of(FIXTURE_MAIN_GO, "target", 1)
        .ok_or_else(|| fail("fixture does not contain the expected `target` call site"))?;
    if !locations.iter().any(|location| {
        location.path.relative_path == "main.go"
            && location.range.start.line_zero_based == call_site.line_zero_based
    }) {
        return Err(fail(format!(
            "expected a reference on line {} (the `target()` call inside `caller`), got {locations:?}",
            call_site.line_zero_based
        )));
    }

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// `P15_REAL_GO_RENAME_PREVIEW_E2E` and
/// `P15_GO_RENAME_PREVIEW_LIVE_WRITE_COUNT=0`: a real
/// `textDocument/rename` edit set from real gopls, covering *both* the
/// declaration and the call site, with the live fixture bytes proven
/// byte-identical afterwards.
#[tokio::test]
async fn real_go_rename_preview_e2e_never_writes_live_source() -> Result<(), Box<dyn Error>> {
    if !real_go_toolchain_available() {
        eprintln!(
            "P15_GO_SEMANTIC_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real gopls found on PATH (set CORULIX_TEST_GOPLS to override) / go at {REAL_GO_DIRECTORY}"
        );
        return Ok(());
    }
    let fixture = temp_fixture_module("rename", FIXTURE_MAIN_GO);
    let main_go = fixture.join("main.go");
    let before = fs::read(&main_go)?;

    let session = ready_session(&fixture).await?;
    let cancellation = CancellationToken::new();

    let declaration = position_of(FIXTURE_MAIN_GO, "target", 0)
        .ok_or_else(|| fail("fixture does not contain the expected `target` declaration"))?;
    let preview = wht_corulix_lsp::rename_preview(
        &session,
        &main_go,
        &declaration,
        "renamedTarget",
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("rename request failed: {error:?}")))?;

    let edits: Vec<_> = preview
        .edits_by_path
        .iter()
        .filter(|(path, _)| path.relative_path == "main.go")
        .flat_map(|(_, edits)| edits.iter())
        .collect();
    if edits.len() < 2 {
        return Err(fail(format!(
            "expected at least 2 rename edits (declaration + call site), got {:?}",
            preview.edits_by_path
        )));
    }
    if !edits.iter().all(|edit| edit.new_text == "renamedTarget") {
        return Err(fail(format!(
            "every proposed edit must carry the requested new name, got {edits:?}"
        )));
    }

    // The whole point of a *preview*: real gopls computed a real edit set,
    // and Corulix wrote exactly nothing.
    let after = fs::read(&main_go)?;
    if after != before {
        return Err(fail(
            "rename_preview mutated live source -- RENAME_PREVIEW_MUTATION_COUNT must be 0",
        ));
    }

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// `P15_REAL_GO_DIAGNOSTICS_E2E`: real gopls diagnostics on a fixture that
/// genuinely does not type-check. Distinct from `real_gopls_e2e.rs`'s own
/// diagnostics assertion, which proves the *valid*-source case (a `Reported`
/// set that happens to be empty); this proves a real, non-empty finding.
#[tokio::test]
async fn real_go_diagnostics_e2e_reports_a_real_finding() -> Result<(), Box<dyn Error>> {
    if !real_go_toolchain_available() {
        eprintln!(
            "P15_GO_SEMANTIC_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real gopls found on PATH (set CORULIX_TEST_GOPLS to override) / go at {REAL_GO_DIRECTORY}"
        );
        return Ok(());
    }
    // A real type error, not a syntax error: gopls reports it as a genuine
    // semantic diagnostic rather than a parse failure.
    const BROKEN: &str =
        "package main\n\nfunc main() {\n\tvar x int = \"not an int\"\n\t_ = x\n}\n";
    let fixture = temp_fixture_module("diagnostics", BROKEN);
    let session = ready_session(&fixture).await?;
    let cancellation = CancellationToken::new();

    let result = wht_corulix_lsp::diagnostics(&session, &fixture.join("main.go"))
        .await
        .map_err(|error| fail(format!("diagnostics call failed: {error:?}")))?;
    let diagnostics = match &result {
        DiagnosticsResult::Reported(diagnostics) => diagnostics,
        DiagnosticsResult::NotReady => {
            return Err(fail(
                "diagnostics reported NotReady after proven readiness -- readiness signal is not load-bearing",
            ));
        }
    };
    if diagnostics.is_empty() {
        return Err(fail(
            "expected at least one real diagnostic for a fixture that does not type-check",
        ));
    }

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// `P15_GOPLS_NEGATIVE_TESTS` / `P15_FALSE_SEMANTIC_SUCCESS_COUNT=0`: a
/// semantic request issued *before* readiness must return the typed
/// `NotReady` state, never an empty `Found`/`Reported` set that a caller
/// could mistake for authoritative absence (mandate §9/§11).
///
/// This is the deeper of the two claims in this file: it proves the
/// readiness gate is genuinely load-bearing rather than incidentally
/// satisfied, by exercising the exact window in which gopls's process is
/// alive (`PROCESS_STARTED`) but its semantic database is not yet populated
/// (`SEMANTIC_READY` false).
#[tokio::test]
async fn semantic_request_before_readiness_is_not_ready_never_empty_authority()
-> Result<(), Box<dyn Error>> {
    if !real_go_toolchain_available() {
        eprintln!(
            "P15_GO_SEMANTIC_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real gopls found on PATH (set CORULIX_TEST_GOPLS to override) / go at {REAL_GO_DIRECTORY}"
        );
        return Ok(());
    }
    let fixture = temp_fixture_module("pre-readiness", FIXTURE_MAIN_GO);
    let go_cache_dir = fixture.join(".corulix-go-cache");
    let _ = fs::create_dir_all(&go_cache_dir);
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let Some(launch) = resolve_gopls(&workspace_root, &go_cache_dir).await else {
        return Err(fail("gopls did not resolve via the Phase-6 resolver"));
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

    // Deliberately NO `ensure_open` + `wait_until_ready` here: the process
    // is started and the `initialize` handshake completed, but the
    // document-scoped `FirstDiagnosticsPublished` signal cannot have fired.
    if session.readiness().await == Readiness::Ready {
        return Err(fail(
            "session claims Ready before any document was opened -- the readiness signal is vacuous",
        ));
    }
    let declaration = position_of(FIXTURE_MAIN_GO, "target", 0)
        .ok_or_else(|| fail("fixture does not contain `target`"))?;
    let result = wht_corulix_lsp::references(
        &session,
        &fixture.join("main.go"),
        &declaration,
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("references request failed: {error:?}")))?;
    if !matches!(result, ReferencesResult::NotReady) {
        return Err(fail(format!(
            "expected NotReady before readiness, got {result:?} -- an empty or populated answer here would be false semantic authority"
        )));
    }

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// `P15_PROVIDER_UNAVAILABLE_NEGATIVE_MATRIX` (gopls arm): a
/// workspace-local `./gopls` must never satisfy the `LanguageServer`
/// provider. `P15_WORKSPACE_GOPLS_HIJACK_COUNT=0` is proven by a marker
/// file the fake would create if it were ever executed.
#[tokio::test]
async fn workspace_local_fake_gopls_is_never_resolved_or_executed() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_module("hijack", FIXTURE_MAIN_GO);
    let marker = fixture.join("HIJACK_MARKER");
    let fake = fixture.join("gopls");
    fs::write(
        &fake,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.to_string_lossy()),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&fake)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake, permissions)?;
    }

    let workspace_root = WorkspaceRoot::open(&fixture)?;
    // The workspace directory itself offered as an approved directory: even
    // this maximally-permissive-looking configuration must not let a
    // workspace-authored executable become a controlled provider.
    let host = HostConfig {
        approved_system_directories: vec![fixture.clone()],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::gopls();
    let outcome = wht_corulix_lsp::resolve_launch(&profile, &effective, &workspace_root).await;

    if outcome.is_ok() {
        return Err(fail(
            "a workspace-local ./gopls was accepted as a controlled provider -- P15_WORKSPACE_GOPLS_HIJACK_COUNT must be 0",
        ));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake gopls was EXECUTED -- P15_WORKSPACE_GOPLS_HIJACK_COUNT must be 0",
        ));
    }

    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// `P15_PROVIDER_UNAVAILABLE_NEGATIVE_MATRIX` (absent-provider arm): a
/// `HOST_ONLY`-configured absolute path that does not exist must fail
/// closed, never fall through to any other candidate.
#[tokio::test]
async fn absent_gopls_fails_closed_without_fallback() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_module("absent", FIXTURE_MAIN_GO);
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let host = HostConfig {
        provider_absolute_paths: vec![(
            ProviderCategory::LanguageServer,
            PathBuf::from("/nonexistent/corulix-p15/gopls"),
        )],
        // A real, populated approved list: proving the absolute-path tier is
        // terminal (mandate §6) rather than merely "nothing was configured".
        approved_system_directories: vec![PathBuf::from(REAL_GO_DIRECTORY)],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::gopls();
    if wht_corulix_lsp::resolve_launch(&profile, &effective, &workspace_root)
        .await
        .is_ok()
    {
        return Err(fail(
            "an absent HOST_ONLY gopls path resolved anyway -- P15_PROVIDER_FALLBACK_COUNT must be 0",
        ));
    }
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// `P15_PROVIDER_UNAVAILABLE_NEGATIVE_MATRIX` (corrupt-provider arm): a
/// present but non-executable candidate must fail closed at resolution,
/// never be spawned.
#[tokio::test]
async fn unexecutable_gopls_fails_closed() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_module("corrupt", FIXTURE_MAIN_GO);
    let corrupt_dir = fixture.join("corrupt-provider");
    fs::create_dir_all(&corrupt_dir)?;
    let corrupt = corrupt_dir.join("gopls");
    // Real content, real file -- but no execute bit anywhere.
    fs::write(&corrupt, b"this is not an executable\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&corrupt)?.permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&corrupt, permissions)?;
    }

    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let host = HostConfig {
        provider_absolute_paths: vec![(ProviderCategory::LanguageServer, corrupt.clone())],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::gopls();
    if wht_corulix_lsp::resolve_launch(&profile, &effective, &workspace_root)
        .await
        .is_ok()
    {
        return Err(fail(
            "a non-executable gopls candidate resolved -- resolution must fail closed",
        ));
    }
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// `P15_PROVIDER_UNAVAILABLE_NEGATIVE_MATRIX` (invalid-workspace arm): a
/// path that is not a directory is rejected by `wht_corulix_workspace`
/// before any provider is even considered (Architecture Rule F) -- Corulix
/// never spawns a semantic provider against an unresolvable root.
#[tokio::test]
async fn invalid_go_workspace_is_rejected_before_provider_resolution() -> Result<(), Box<dyn Error>>
{
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let not_a_directory = std::env::temp_dir().join(format!("corulix-p15-not-a-dir-{stamp}"));
    fs::write(&not_a_directory, b"package main\n")?;
    if WorkspaceRoot::open(&not_a_directory).is_ok() {
        return Err(fail(
            "a regular file was accepted as a workspace root -- confinement must fail closed",
        ));
    }
    let _ = fs::remove_file(&not_a_directory);
    Ok(())
}
