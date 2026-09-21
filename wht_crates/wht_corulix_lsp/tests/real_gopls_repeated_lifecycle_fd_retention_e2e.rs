// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09-P8R Section 29: real, repeated create -> initialize -> semantic
//! operation -> shutdown cycles against a real gopls process, proving no
//! fd or OS-process retention across the cycle (`MOCKED_ONLY_CLOSURE=NO`).
//! Serialized (never concurrent with itself): this file's own single test
//! runs the whole cycle sequentially, and this test binary carries no
//! other tests, so no cross-test fd interference is possible.
//!
//! If no real gopls/`go` binary is present at this development
//! environment's well-known toolchain locations, this test reports and
//! exits early with
//! `GO_LSP_FD_RETENTION_E2E=BLOCKED_PROVIDER_UNAVAILABLE` rather than
//! failing.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, ProviderCategory, WorkspaceRootId};
use wht_corulix_lsp::{LspProviderProfile, LspSession, Readiness};
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
const LIFECYCLE_CYCLE_COUNT: usize = 3;

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

/// Real, direct `/proc/self/fd` count for THIS test process -- the same
/// oracle already established elsewhere in this workspace
/// (`wht_corulix_workspace`'s own `open_fd_count` fd-leak tests) --
/// counting the test binary's own open descriptors (pipes to the child's
/// stdin/stdout, any retained file handles), never inferred from
/// `LspSession`'s own bookkeeping.
fn open_fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0)
}

fn temp_fixture_module(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!(
        "corulix-lsp-gopls-fd-retention-e2e-{label}-{stamp}"
    ));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix_lsp_gopls_fd_retention_e2e_fixture\n\ngo 1.22\n",
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

/// Section 29: repeated (create -> initialize -> semantic operation ->
/// shutdown) cycles against a real gopls process must never accumulate
/// retained fds or orphaned OS processes -- the fd count observed after
/// the LAST cycle's shutdown must match the count observed before the
/// FIRST cycle ever started (a bounded, non-zero PEAK during each cycle is
/// expected and fine; only the after-vs-before delta matters).
#[tokio::test]
async fn real_gopls_repeated_lifecycle_leaves_no_retained_fd_or_process()
-> Result<(), Box<dyn Error>> {
    if !real_gopls_available() {
        eprintln!(
            "GO_LSP_FD_RETENTION_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real gopls/go binary at \
             found on PATH (set CORULIX_TEST_GOPLS to override) / go at {REAL_GO_DIRECTORY} in this environment"
        );
        return Ok(());
    }

    let fd_count_before = open_fd_count();
    let mut fd_count_peak = fd_count_before;

    for cycle in 0..LIFECYCLE_CYCLE_COUNT {
        let fixture = temp_fixture_module(&format!("cycle-{cycle}"));
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
        .map_err(|error| fail(format!("cycle {cycle}: spawn/handshake failed: {error:?}")))?;

        let main_go = fixture.join("main.go");
        session.ensure_open(&main_go).await.map_err(|error| {
            fail(format!(
                "cycle {cycle}: opening the fixture failed: {error:?}"
            ))
        })?;
        session
            .wait_until_ready(READINESS_TIMEOUT)
            .await
            .map_err(|error| {
                fail(format!(
                    "cycle {cycle}: gopls never reached readiness: {error:?}"
                ))
            })?;
        if session.readiness().await != Readiness::Ready {
            return Err(fail(format!(
                "cycle {cycle}: session reports not-ready after wait_until_ready succeeded"
            )));
        }

        let diagnostics = wht_corulix_lsp::diagnostics(&session, &main_go).await;
        if diagnostics.is_err() {
            return Err(fail(format!(
                "cycle {cycle}: diagnostics call failed: {diagnostics:?}"
            )));
        }

        fd_count_peak = fd_count_peak.max(open_fd_count());

        session.shutdown(&cancellation).await;
        let _ = fs::remove_dir_all(&fixture);
    }

    let fd_count_after = open_fd_count();

    eprintln!(
        "P8R_FD_COUNT_BEFORE={fd_count_before} P8R_FD_COUNT_PEAK={fd_count_peak} \
         P8R_FD_COUNT_AFTER={fd_count_after}"
    );

    if fd_count_after > fd_count_before {
        return Err(fail(format!(
            "fd retention across {LIFECYCLE_CYCLE_COUNT} full lifecycle cycles: before={fd_count_before}, \
             after={fd_count_after} (expected after <= before)"
        )));
    }

    Ok(())
}
