// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09-P8R Section 21: two simultaneous, real gopls-backed `LspSession`s
//! bound to two DIFFERENT `WorkspaceRoot`s must never cross-contaminate --
//! each retains its own root identity, and a semantic query against one
//! session only ever resolves within its own workspace, never the other's
//! (`MOCKED_ONLY_CLOSURE=NO`).
//!
//! If no real gopls/`go` binary is present at this development
//! environment's well-known toolchain locations, this test reports and
//! exits early with
//! `GO_LSP_MULTI_WORKSPACE_ISOLATION_E2E=BLOCKED_PROVIDER_UNAVAILABLE`
//! rather than failing.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, ProviderCategory, WorkspaceRootId};
use wht_corulix_lsp::{DefinitionResult, LspProviderProfile, LspSession, Readiness};
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

/// Each fixture module declares a function whose name is unique to that
/// module (`target_a`/`target_b`) -- so a cross-session leak would show up
/// as one session resolving a definition into the OTHER fixture's
/// directory tree, which this test can directly detect.
fn temp_fixture_module(label: &str, unique_fn_name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!(
        "corulix-lsp-gopls-multi-ws-isolation-e2e-{label}-{stamp}"
    ));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("go.mod"),
        format!("module corulix_lsp_gopls_multi_ws_isolation_e2e_{label}\n\ngo 1.22\n"),
    );
    let _ = fs::write(
        root.join("main.go"),
        format!(
            "package main\n\nfunc {unique_fn_name}() {{}}\n\nfunc caller() {{\n\t{unique_fn_name}()\n}}\n\nfunc main() {{\n\tcaller()\n}}\n"
        ),
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

async fn spawn_ready_session(
    label: &str,
    unique_fn_name: &str,
    root_id: WorkspaceRootId,
) -> Result<(LspSession, PathBuf, CancellationToken), Box<dyn Error>> {
    let fixture = temp_fixture_module(label, unique_fn_name);
    let go_cache_dir = fixture.join(".corulix-go-cache");
    let _ = fs::create_dir_all(&go_cache_dir);
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let Some(launch) = resolve_gopls(&workspace_root, &go_cache_dir).await else {
        return Err(fail(format!(
            "{label}: gopls did not resolve via the real Phase-6 provider resolver"
        )));
    };

    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::gopls();
    let session = LspSession::spawn(launch, &profile, workspace_root, root_id, &cancellation)
        .await
        .map_err(|error| fail(format!("{label}: spawn/handshake failed: {error:?}")))?;

    let main_go = fixture.join("main.go");
    session
        .ensure_open(&main_go)
        .await
        .map_err(|error| fail(format!("{label}: opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("{label}: gopls never reached readiness: {error:?}")))?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(format!(
            "{label}: session reports not-ready after wait_until_ready succeeded"
        )));
    }
    Ok((session, fixture, cancellation))
}

#[tokio::test]
async fn real_gopls_two_simultaneous_sessions_never_cross_contaminate() -> Result<(), Box<dyn Error>>
{
    if !real_gopls_available() {
        eprintln!(
            "GO_LSP_MULTI_WORKSPACE_ISOLATION_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real gopls/go \
             binary at found on PATH (set CORULIX_TEST_GOPLS to override) / go at {REAL_GO_DIRECTORY} in this environment"
        );
        return Ok(());
    }

    let (session_a, fixture_a, cancellation_a) =
        spawn_ready_session("a", "target_a", WorkspaceRootId(1)).await?;
    let (session_b, fixture_b, cancellation_b) =
        spawn_ready_session("b", "target_b", WorkspaceRootId(2)).await?;

    // Section 21/22: each session must retain its OWN, distinct
    // `WorkspaceRoot`/`WorkspaceRootId` -- never converge on a shared
    // value.
    if session_a.root_id() == session_b.root_id() {
        return Err(fail("both sessions report the same WorkspaceRootId"));
    }
    if session_a.workspace_root() == session_b.workspace_root() {
        return Err(fail("both sessions report the same WorkspaceRoot identity"));
    }

    let main_go_a = fixture_a.join("main.go");
    let main_go_b = fixture_b.join("main.go");

    let definition_a = wht_corulix_lsp::definition(
        &session_a,
        &main_go_a,
        &wht_corulix_core::Position {
            line_zero_based: 5,
            byte_column_zero_based: 1,
            byte_offset: 54, // `target_a` is one byte longer than `target`
        },
        &cancellation_a,
    )
    .await
    .map_err(|error| fail(format!("session A definition request failed: {error:?}")))?;
    let location_a = match &definition_a {
        DefinitionResult::Single(location) => location.clone(),
        DefinitionResult::Multiple(locations) => locations
            .first()
            .cloned()
            .ok_or_else(|| fail("session A definition returned an empty Multiple result"))?,
        DefinitionResult::None => {
            return Err(fail("expected a real definition for session A, got None"));
        }
    };
    // The resolved path is a `WorkspacePath` scoped to session A's own
    // `root_id` -- confirms the result was reconfined against A's root,
    // never silently resolved against B's.
    if location_a.path.root != session_a.root_id() {
        return Err(fail(format!(
            "session A's own definition result carries a foreign root id: {:?}",
            location_a.path.root
        )));
    }

    let definition_b = wht_corulix_lsp::definition(
        &session_b,
        &main_go_b,
        &wht_corulix_core::Position {
            line_zero_based: 5,
            byte_column_zero_based: 1,
            byte_offset: 54,
        },
        &cancellation_b,
    )
    .await
    .map_err(|error| fail(format!("session B definition request failed: {error:?}")))?;
    let location_b = match &definition_b {
        DefinitionResult::Single(location) => location.clone(),
        DefinitionResult::Multiple(locations) => locations
            .first()
            .cloned()
            .ok_or_else(|| fail("session B definition returned an empty Multiple result"))?,
        DefinitionResult::None => {
            return Err(fail("expected a real definition for session B, got None"));
        }
    };
    if location_b.path.root != session_b.root_id() {
        return Err(fail(format!(
            "session B's own definition result carries a foreign root id: {:?}",
            location_b.path.root
        )));
    }
    if location_a.path.root == location_b.path.root {
        return Err(fail(
            "session A and session B's definition results share the same root id",
        ));
    }

    session_a.shutdown(&cancellation_a).await;
    session_b.shutdown(&cancellation_b).await;
    let _ = fs::remove_dir_all(&fixture_a);
    let _ = fs::remove_dir_all(&fixture_b);
    Ok(())
}
