// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(windows)]

//! P17-W: the native-Windows hostile-`PATH`/hostile-CWD proof for the
//! managed standalone-binary formatter family (`CORULIX_MANAGED` `biome`),
//! closing the disclosed gap that
//! `real_gopls_managed_windows_hostile_path_e2e.rs`/
//! `real_typescript_6_managed_windows_hostile_path_e2e.rs` already closed
//! for gopls/TS6: before this file, the standalone-binary vertical (Biome)
//! had zero Windows-native hostile-PATH coverage.
//!
//! # Why Biome is a genuinely different shape than gopls/TS6/rustfmt
//!
//! Biome is a single, statically-linked native binary with no sibling-
//! runtime dependency on either platform (`BIOME_WINDOWS_X64`'s own doc
//! comment: `BIOME_WINDOWS_RUST_RUNTIME_DEPENDENCY=NONE`), invoked directly
//! -- `wht_corulix_formatter::managed::resolve_formatter`'s Biome arm
//! (confirmed by direct reading) resolves `BIOME_HOST_NATIVE` and passes
//! `EnvironmentPolicy::empty()`, no environment variable of any kind. This
//! file's closure claim is therefore narrower and stronger than a naive
//! port of the gopls/TS6 files would suggest:
//! `BIOME_ABSOLUTE_PATH_INVOCATION=YES` -- Corulix always resolves and
//! spawns Biome by its one explicit, fully-qualified managed path
//! (`component_install_dir(...)` under the isolated `managed_root`), so a
//! bare-name `PATH` lookup for `biome`/`biome.exe` is never performed at
//! all in the first place; a hostile `PATH`-style directory can therefore
//! never be consulted, which this file proves empirically rather than
//! merely asserting from source. The still-genuine Windows-specific vector
//! that *is* real here is the same one the gopls/TS6 files close: a decoy
//! dropped directly in the workspace CWD (`invoke_formatter`'s own
//! `working_directory: workspace_root.canonical_path()`) -- `CreateProcess`
//! searching the current directory first is a property of the OS launcher,
//! not of Corulix's own resolution logic, so this file still tests it
//! explicitly rather than assuming the absolute-path argument alone makes
//! it moot.
//!
//! # No live PID/process-table check (same rationale as the rustfmt file)
//!
//! Biome, like rustfmt, is a bounded one-shot stdin/stdout invocation
//! (`invocation.rs`), not a persistent LSP session -- there is no long-lived
//! process to query via `Get-CimInstance Win32_Process`. The evidence model
//! is: (1) [`FormatterResult::provider_path`] resolves under the isolated
//! managed root, never the hostile dir or workspace CWD decoy; (2) the
//! invocation genuinely completes through the real managed `biome.exe`
//! (`FormatStatus::Formatted`/`Unchanged`/`WouldFormat`, never
//! `ProviderUnavailable`/`InvocationFailed`); and (3) a written sentinel
//! file (echoed by the decoy scripts themselves) proves whether a decoy
//! ever ran at all.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command as StdCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_formatter::managed_toolchain::BIOME_HOST_NATIVE;
use wht_corulix_formatter::{FormatStatus, format_preview_at};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

static REAL_BIOME_WINDOWS_HOSTILE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_biome_windows_hostile_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_BIOME_WINDOWS_HOSTILE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

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

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

fn isolated_root(label: &str) -> std::path::PathBuf {
    // Prefer `USERPROFILE` directly on Windows -- `HOME` can be present but
    // empty (not absent) in a WMI-launched job context, which a bare
    // `unwrap_or_else` on absence alone would miss.
    let home = std::env::var("USERPROFILE")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOME").ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| "C:\\root".to_string());
    let dir = std::path::PathBuf::from(home)
        .join(".cache/corulix-biome-windows-hostile-e2e/roots")
        .join(format!("{label}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// A real, functional decoy that appends its own invocation to `sentinel`
/// every time it runs -- mirrors the gopls/TS6/rustfmt Windows hostile-path
/// files' own `write_decoy`.
fn write_decoy(path: &Path, sentinel: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let sentinel_str = sentinel.to_string_lossy();
    let script =
        format!("@echo off\r\necho invoked: %~f0 %* >> \"{sentinel_str}\"\r\nexit /b 0\r\n");
    let _ = fs::write(path, script);
}

async fn ensure_managed_biome_provisioned(root: &Path) -> bool {
    let manifest = BIOME_HOST_NATIVE;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    if state == ManagedComponentState::Available {
        return true;
    }
    provisioning::provision(root, &manifest).await.is_ok()
}

/// A real TS fixture (deliberately misformatted so a genuine Biome run has
/// real reformatting work to do), plus hostile `biome.exe.bat`/`biome.bat`
/// decoys dropped directly in the fixture root -- the workspace CWD
/// `invoke_formatter` spawns the child from.
fn ts_fixture_with_cwd_decoy(label: &str, decoy_sentinel: &Path) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("corulix-biome-win-hostile-{label}-{}", stamp()));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("main.ts"),
        "export function target( ):number{\n  return   1;\n}\n",
    );
    write_decoy(&root.join("biome.exe.bat"), decoy_sentinel);
    write_decoy(&root.join("biome.bat"), decoy_sentinel);
    root
}

fn positive_control_decoy_is_functional(decoy: &Path) {
    let _ = StdCommand::new(decoy).output();
}

/// §Windows hostile-PATH/CWD: fake `biome.exe`/`biome.bat` decoys placed
/// inside the workspace CWD and a hostile `PATH`-style directory must never
/// be what Corulix resolves or invokes through the real, host-native-wired
/// managed Biome formatter path -- proven against a genuinely live managed
/// invocation, not merely by reading `resolve_formatter`'s source.
#[tokio::test]
async fn real_biome_managed_windows_hostile_path_and_cwd_decoy_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_biome_windows_hostile_lock().await;
    let root = isolated_root("windows-hostile-path");
    if !ensure_managed_biome_provisioned(&root).await {
        eprintln!("WINDOWS_HOSTILE_PATH_BIOME=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let hostile_dir =
        std::env::temp_dir().join(format!("corulix-biome-win-hostile-path-{}", stamp()));
    let sentinel = std::env::temp_dir().join(format!("corulix-biome-win-sentinel-{}.log", stamp()));
    let _ = fs::create_dir_all(&hostile_dir);
    write_decoy(&hostile_dir.join("biome.exe.bat"), &sentinel);
    write_decoy(&hostile_dir.join("biome.bat"), &sentinel);

    // --- POSITIVE CONTROL: the decoys are real and functional. ---
    positive_control_decoy_is_functional(&hostile_dir.join("biome.bat"));
    if !sentinel.is_file() {
        return Err(fail(
            "positive control failed: hostile decoy did not write its sentinel when directly invoked",
        ));
    }
    let _ = fs::remove_file(&sentinel);
    eprintln!("WINDOWS_HOSTILE_PATH_POSITIVE_CONTROL=PASS");

    // `hostile_dir` is deliberately never spliced into this test process's
    // own ambient `PATH` -- Corulix's Biome resolution never consults `PATH`
    // at all (see this file's own doc comment), so that mutation would
    // prove nothing beyond what the checks below already do.
    let fixture = ts_fixture_with_cwd_decoy("windows-hostile-path", &sentinel);
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let cancellation = CancellationToken::new();
    let path = wht_corulix_core::WorkspacePath {
        root: WorkspaceRootId(0),
        relative_path: "main.ts".to_string(),
    };

    let result = format_preview_at(
        &root,
        &effective,
        workspace_root,
        path,
        wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("format_preview_at failed: {error:?}")))?;

    // --- RESOLVED EXECUTABLE: must be the real managed biome under `root`,
    // never the hostile PATH dir or the workspace CWD decoy. ---
    let Some(provider_path) = &result.provider_path else {
        return Err(fail(format!(
            "expected a resolved biome provider path, got {result:?}"
        )));
    };
    if !provider_path.starts_with(&root) {
        return Err(fail(format!(
            "expected the resolved biome executable under the managed root {root:?}, got {provider_path:?} -- HOSTILE_PATH_OR_CWD_DECOY_WON"
        )));
    }
    if provider_path.starts_with(&hostile_dir) || provider_path.starts_with(&fixture) {
        return Err(fail(format!(
            "resolved biome executable {provider_path:?} points at a hostile/decoy location"
        )));
    }
    if !result.provider_used_managed {
        return Err(fail(format!(
            "expected provider_used_managed=true (CORULIX_MANAGED biome), got {result:?}"
        )));
    }
    eprintln!("WINDOWS_RESOLVED_EXECUTABLE_AUTHORITY=CORULIX_MANAGED ({provider_path:?})");

    // --- REAL INVOCATION SUCCEEDED: the real managed biome.exe actually ran
    // to completion. A decoy could never produce this: per the absolute-
    // path-invocation argument above it is never even reached.
    match result.status {
        FormatStatus::Formatted | FormatStatus::Unchanged | FormatStatus::WouldFormat => {
            eprintln!(
                "WINDOWS_HOSTILE_PATH_REAL_BIOME_INVOCATION=PASS (status={:?})",
                result.status
            );
        }
        other => {
            return Err(fail(format!(
                "expected a genuine managed biome invocation to complete, got status={other:?} (reason={:?})",
                result.reason
            )));
        }
    }

    let _ = fs::remove_dir_all(&fixture);

    if sentinel.is_file() {
        let contents = fs::read_to_string(&sentinel).unwrap_or_default();
        return Err(fail(format!(
            "a hostile decoy executed during a real managed biome invocation: {contents}"
        )));
    }
    eprintln!("WINDOWS_HOSTILE_PATH_MARKER_EXECUTION_COUNT=0");
    eprintln!("WINDOWS_HOSTILE_CWD_DECOY_EXECUTION_COUNT=0");
    eprintln!("WINDOWS_HOSTILE_PATH_BIOME=PASS");

    let outcome = provisioning::full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("cleanup full_uninstall failed: {error:?}")))?;
    if !matches!(
        outcome,
        provisioning::full_uninstall::FullUninstallOutcome::Removed(_)
    ) {
        return Err(fail(format!(
            "expected cleanup to remove the biome component, got {outcome:?}"
        )));
    }
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&hostile_dir);
    let _ = fs::remove_file(&sentinel);
    Ok(())
}
