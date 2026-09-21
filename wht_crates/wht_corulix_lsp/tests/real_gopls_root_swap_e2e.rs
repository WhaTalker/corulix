// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09-P8: real end-to-end root-swap proof against a real, genuinely
//! `Ready` gopls session (`MOCKED_ONLY_CLOSURE=NO`) -- reuses the same
//! real-provider resolution pattern as `real_gopls_e2e.rs`, but exercises
//! the scenario that crate's own unit tests (`wht_corulix_lsp::session`)
//! cannot reach: a root-identity mismatch observed at a REQUEST BOUNDARY
//! (Section 16) on a session that already completed `initialize`
//! successfully, this session's resulting one-way invalidation (Section
//! 18: every later call on the SAME session fails closed, never silently
//! resumes trusting the provider), and that an ABA restore (the impostor
//! removed, the original object restored at the original pathname) does
//! NOT un-invalidate the session (Section 25).
//!
//! If no real gopls/`go` binary is present at this development
//! environment's well-known toolchain locations, this test reports and
//! exits early with `GO_LSP_ROOT_SWAP_E2E=BLOCKED_PROVIDER_UNAVAILABLE`
//! rather than failing.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, ProviderCategory, WorkspaceRootId};
use wht_corulix_lsp::{LspError, LspProviderProfile, LspSession, Readiness};
use wht_corulix_workspace::WorkspaceRoot;

fn real_gopls_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("CORULIX_TEST_GOPLS") {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("gopls{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
        .map(|dir| dir.join(&exe_name))
}
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
    let root =
        std::env::temp_dir().join(format!("corulix-lsp-gopls-root-swap-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix_lsp_gopls_root_swap_e2e_fixture\n\ngo 1.22\n",
    );
    let _ = fs::write(
        root.join("main.go"),
        "package main\n\nfunc target() {}\n\nfunc caller() {\n\ttarget()\n}\n\nfunc main() {\n\tcaller()\n}\n",
    );
    root
}

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

/// Sections 16/18/25, end-to-end against a real gopls process: a root
/// swap observed AFTER a session has already reached `Ready` must fail
/// the very next semantic request closed, permanently invalidate that
/// session (every further call -- even after an ABA restore of the
/// original object -- keeps failing), and must never silently resume
/// trusting the provider.
#[tokio::test]
async fn real_gopls_root_swap_after_ready_invalidates_session_permanently()
-> Result<(), Box<dyn Error>> {
    if !real_gopls_available() {
        eprintln!(
            "GO_LSP_ROOT_SWAP_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real gopls/go binary at \
             found on PATH (set CORULIX_TEST_GOPLS to override) / go at {REAL_GO_DIRECTORY} in this environment"
        );
        return Ok(());
    }

    let fixture = temp_fixture_module("after-ready");
    let go_cache_dir = fixture.join(".corulix-go-cache");
    let _ = fs::create_dir_all(&go_cache_dir);
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let Some(launch) = resolve_gopls(&workspace_root, &go_cache_dir).await else {
        return Err(fail(
            "gopls did not resolve via the real Phase-6 provider resolver",
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

    // A real request must succeed while the root is genuinely unmodified --
    // establishes the session is really live before the swap.
    let baseline = wht_corulix_lsp::diagnostics(&session, &main_go).await;
    if baseline.is_err() {
        return Err(fail(format!(
            "baseline diagnostics call must succeed before any swap, got {baseline:?}"
        )));
    }

    // Ordinary-directory replacement at the workspace's own canonical
    // pathname, performed AFTER the session already reached `Ready` --
    // the exact TOCTOU window Section 16's request-boundary guard exists
    // to close.
    let moved_away = std::env::temp_dir().join(format!(
        "corulix-lsp-gopls-root-swap-e2e-moved-{}",
        std::process::id()
    ));
    fs::rename(&fixture, &moved_away)?;
    fs::create_dir_all(&fixture)?;

    let after_swap = wht_corulix_lsp::diagnostics(&session, &main_go).await;
    if !matches!(after_swap, Err(LspError::RootIdentityMismatch)) {
        let _ = fs::remove_dir_all(&fixture);
        let _ = fs::remove_dir_all(&moved_away);
        return Err(fail(format!(
            "expected RootIdentityMismatch immediately after the swap, got {after_swap:?}"
        )));
    }

    // Sticky (Section 18): a second call on the SAME session, still with
    // the impostor directory in place, must short-circuit to
    // `SessionInvalidated` without re-deriving anything from the provider
    // (which this call's own gate never even sends a request to).
    let second_call = wht_corulix_lsp::diagnostics(&session, &main_go).await;
    if !matches!(second_call, Err(LspError::SessionInvalidated)) {
        let _ = fs::remove_dir_all(&fixture);
        let _ = fs::remove_dir_all(&moved_away);
        return Err(fail(format!(
            "expected SessionInvalidated on the second post-swap call, got {second_call:?}"
        )));
    }

    // ABA restore (Section 25): remove the impostor, restore the ORIGINAL
    // object at the original pathname -- identity would once again report
    // a match, yet this session must NEVER silently resume trusting the
    // provider it already terminated.
    fs::remove_dir_all(&fixture)?;
    fs::rename(&moved_away, &fixture)?;

    let after_aba_restore = wht_corulix_lsp::diagnostics(&session, &main_go).await;
    if !matches!(after_aba_restore, Err(LspError::SessionInvalidated)) {
        let _ = fs::remove_dir_all(&fixture);
        return Err(fail(format!(
            "expected SessionInvalidated to persist across an ABA restore, got {after_aba_restore:?}"
        )));
    }

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}
