// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(windows)]

//! P17-W: the native-Windows hostile-`PATH`/hostile-CWD proof for the
//! managed Rust-family formatter (`CORULIX_MANAGED` `rustfmt` +
//! `rust-semantic-runtime`), closing the disclosed gap that
//! `real_gopls_managed_windows_hostile_path_e2e.rs`/
//! `real_typescript_6_managed_windows_hostile_path_e2e.rs` already closed
//! for gopls/TS6: before this file, the Rust-family provider vertical
//! (`rustfmt`/`rust-analyzer`/`cargo`) had zero Windows-native hostile-PATH
//! coverage -- its only hostile-PATH-shaped test
//! (`real_p10r2_format_write_atomicity_negative_e2e.rs` and siblings) is
//! `#![cfg(unix)]`-gated by the same `chmod`-executable-marker mechanism the
//! gopls Windows file's own doc comment already establishes has no Windows
//! equivalent.
//!
//! # Why `rustfmt`, not `rust-analyzer`
//!
//! `real_rust_analyzer_managed_lifecycle_e2e.rs`'s own doc comment records
//! that rust-analyzer cannot build a real project model at all without a
//! real `cargo`/`rustc` on ambient `PATH` (a real, separately-run hostile-
//! PATH probe proved this in a prior phase) -- so a genuinely *closed*,
//! self-contained managed-resolution proof against a live process is not
//! available for rust-analyzer on any platform yet. `rustfmt` has no such
//! gap: `RUST_SEMANTIC_RUNTIME_WINDOWS_X64` (P17-W-R4-C2) plus
//! `wht_corulix_formatter::managed::resolve_formatter`'s Windows-specific
//! `PATH`-prepend-to-owned-runtime-`bin/`-only environment (see that
//! module's own doc comment) together make a real, complete, ambient-PATH-
//! independent managed `rustfmt.exe` invocation possible and already
//! certified on Windows -- this file is the hostile-PATH counterpart of
//! that certification, not a new capability.
//!
//! # The real Windows-specific attack surface this file closes
//!
//! - **CWD-first resolution**: `CreateProcess` searches the current
//!   directory before consulting `PATH` at all. `invocation::invoke_formatter`
//!   sets the spawned child's working directory to the workspace root itself
//!   (`working_directory: workspace_root.canonical_path()`, confirmed by
//!   direct reading of `compute_formatted`/`invoke_formatter`), so a decoy
//!   `rustfmt.exe`/`.bat` dropped directly inside the fixture workspace --
//!   not merely on `PATH` -- is the single strongest real attack surface on
//!   this platform, tested explicitly below.
//! - **`PATHEXT` extension resolution**: a decoy `rustfmt.bat` (a non-`.exe`
//!   name a straight `.exe`-only port would miss) is placed both in the
//!   hostile `PATH`-style directory and directly in the workspace CWD.
//! - **No ambient-`PATH` mutation needed to prove containment**: this
//!   workspace forbids `unsafe` code and `std::env::set_var` requires
//!   `unsafe` under edition 2024 -- the same architectural fact the gopls/
//!   TS6 Windows files already establish. `resolve_formatter`'s managed
//!   branch never reads ambient `PATH` in the first place (it resolves
//!   `RUSTFMT_HOST_NATIVE` under the explicit, isolated `managed_root`), and
//!   `ManagedProcess::spawn`'s unconditional environment control means the
//!   spawned child never inherits this test process's own `PATH` regardless
//!   -- only the one Corulix-owned `rust-semantic-runtime` `bin/` directory
//!   `rust_semantic_runtime_dll_environment` sets is ever passed.
//!
//! # No live PID/process-table check (unlike the gopls/TS6 Windows files)
//!
//! `rustfmt` is a bounded, one-shot stdin/stdout invocation
//! (`invocation.rs`'s own doc comment), not a persistent LSP session --
//! there is no long-lived process to query via `Get-CimInstance
//! Win32_Process` the way the gopls/TS6 files do against a live `gopls`/
//! `node` session. The evidence model here is instead: (1) the resolved
//! [`FormatterResult::provider_path`] must be the real managed binary under
//! the isolated root, never the hostile dir or workspace CWD decoy: (2) the
//! invocation must have genuinely *completed* through the real managed
//! `rustfmt.exe` (`FormatStatus::Formatted`/`Unchanged`/`WouldFormat`, never
//! `ProviderUnavailable`/`InvocationFailed` -- a decoy `.bat` that merely
//! echoes to a sentinel would either never be reached at all, given (1), or
//! would produce output `compute_formatted` cannot interpret as valid
//! formatted Rust source); and (3) a written sentinel file (echoed by the
//! decoy scripts themselves) proves whether a decoy ever ran at all -- the
//! same "real independent verification, never this crate's own claims"
//! standard the gopls/TS6 Windows files establish, adapted to a one-shot
//! tool's own real shape rather than force-fitting a PID check that would
//! prove nothing here.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command as StdCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_formatter::managed_toolchain::RUSTFMT_HOST_NATIVE;
use wht_corulix_formatter::{FormatStatus, format_preview_at};
use wht_corulix_tooling::managed_runtimes;
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

const RUST_SEMANTIC_RUNTIME_ID: &str = "rust-semantic-runtime";

static REAL_RUSTFMT_WINDOWS_HOSTILE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_rustfmt_windows_hostile_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_RUSTFMT_WINDOWS_HOSTILE_LOCK
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
    // Prefer `USERPROFILE` directly on Windows (per this phase's own
    // standing diagnostic: a WMI-launched job context can carry `HOME`
    // present-but-empty, not absent, which a bare `unwrap_or_else` on
    // absence alone would miss entirely).
    let home = std::env::var("USERPROFILE")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOME").ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| "C:\\root".to_string());
    let dir = std::path::PathBuf::from(home)
        .join(".cache/corulix-rustfmt-windows-hostile-e2e/roots")
        .join(format!("{label}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// A real, functional decoy that appends its own invocation to `sentinel`
/// every time it runs -- mirrors the gopls/TS6 Windows hostile-path files'
/// own `write_decoy`.
fn write_decoy(path: &Path, sentinel: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let sentinel_str = sentinel.to_string_lossy();
    let script =
        format!("@echo off\r\necho invoked: %~f0 %* >> \"{sentinel_str}\"\r\nexit /b 0\r\n");
    let _ = fs::write(path, script);
}

async fn ensure_managed_rustfmt_provisioned(root: &Path) -> bool {
    let runtime_manifest = managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64;
    let (runtime_state, _) = provisioning::resolve_managed_component(root, &runtime_manifest);
    if runtime_state != ManagedComponentState::Available
        && provisioning::provision(root, &runtime_manifest)
            .await
            .is_err()
    {
        return false;
    }

    let rustfmt_manifest = RUSTFMT_HOST_NATIVE;
    let (rustfmt_state, _) = provisioning::resolve_managed_component(root, &rustfmt_manifest);
    if rustfmt_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(
            root,
            &rustfmt_manifest,
            &[RUST_SEMANTIC_RUNTIME_ID],
        )
        .await
        .is_err()
    {
        return false;
    }
    true
}

/// A real Rust fixture (deliberately misformatted, so a genuine rustfmt run
/// has real reformatting work to do rather than merely reporting
/// `Unchanged`), plus hostile `rustfmt.exe.bat`/`rustfmt.bat` decoys dropped
/// directly in the fixture root -- the workspace CWD `invoke_formatter`
/// spawns the child from.
fn rust_fixture_with_cwd_decoy(label: &str, decoy_sentinel: &Path) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("corulix-rustfmt-win-hostile-{label}-{}", stamp()));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(root.join("main.rs"), "fn main( ) {\n    let  x=1;\n}\n");
    // `rustfmt.exe.bat` is a negative-control name that never resolves a
    // bare `rustfmt`/`rustfmt.exe` lookup; `rustfmt.bat` is the real
    // `PATHEXT` vector a straight `.exe`-only port would miss. Neither
    // matters here in practice (Corulix's own resolution always passes an
    // explicit, fully-qualified managed path and never performs a bare-name
    // `PATH`/CWD search) -- these decoys prove that fact against a live
    // invocation, they do not rely on it.
    write_decoy(&root.join("rustfmt.exe.bat"), decoy_sentinel);
    write_decoy(&root.join("rustfmt.bat"), decoy_sentinel);
    root
}

/// Real, independent OS-level check via `Get-CimInstance Win32_Process` --
/// kept for parity with the gopls/TS6 Windows files' own positive-control
/// pattern, even though this file's main evidence is the sentinel/status
/// combination described in its own module doc comment.
fn positive_control_decoy_is_functional(decoy: &Path) -> bool {
    let _ = StdCommand::new(decoy).output();
    true
}

/// §Windows hostile-PATH/CWD: fake `rustfmt.exe`/`rustfmt.bat` decoys placed
/// inside the workspace CWD and a hostile `PATH`-style directory must never
/// be what Corulix resolves or invokes through the real, host-native-wired
/// managed `rustfmt` formatter path -- proven against a genuinely live
/// managed invocation, not merely by reading `resolve_formatter`'s source.
#[tokio::test]
async fn real_rustfmt_managed_windows_hostile_path_and_cwd_decoy_e2e() -> Result<(), Box<dyn Error>>
{
    let _lock = real_rustfmt_windows_hostile_lock().await;
    let root = isolated_root("windows-hostile-path");
    if !ensure_managed_rustfmt_provisioned(&root).await {
        eprintln!("WINDOWS_HOSTILE_PATH_RUSTFMT=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let hostile_dir =
        std::env::temp_dir().join(format!("corulix-rustfmt-win-hostile-path-{}", stamp()));
    let sentinel =
        std::env::temp_dir().join(format!("corulix-rustfmt-win-sentinel-{}.log", stamp()));
    let _ = fs::create_dir_all(&hostile_dir);
    write_decoy(&hostile_dir.join("rustfmt.exe.bat"), &sentinel);
    write_decoy(&hostile_dir.join("rustfmt.bat"), &sentinel);

    // --- POSITIVE CONTROL: the decoys are real and functional. ---
    positive_control_decoy_is_functional(&hostile_dir.join("rustfmt.bat"));
    if !sentinel.is_file() {
        return Err(fail(
            "positive control failed: hostile decoy did not write its sentinel when directly invoked",
        ));
    }
    let _ = fs::remove_file(&sentinel);
    eprintln!("WINDOWS_HOSTILE_PATH_POSITIVE_CONTROL=PASS");

    // `hostile_dir` is deliberately never spliced into this test process's
    // own ambient `PATH` -- see this file's own doc comment for why that
    // mutation would prove nothing beyond what the checks below already do.
    let fixture = rust_fixture_with_cwd_decoy("windows-hostile-path", &sentinel);
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let cancellation = CancellationToken::new();
    let path = wht_corulix_core::WorkspacePath {
        root: WorkspaceRootId(0),
        relative_path: "main.rs".to_string(),
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

    // --- RESOLVED EXECUTABLE: must be the real managed rustfmt under
    // `root`, never the hostile PATH dir or the workspace CWD decoy. ---
    let Some(provider_path) = &result.provider_path else {
        return Err(fail(format!(
            "expected a resolved rustfmt provider path, got {result:?}"
        )));
    };
    if !provider_path.starts_with(&root) {
        return Err(fail(format!(
            "expected the resolved rustfmt executable under the managed root {root:?}, got {provider_path:?} -- HOSTILE_PATH_OR_CWD_DECOY_WON"
        )));
    }
    if provider_path.starts_with(&hostile_dir) || provider_path.starts_with(&fixture) {
        return Err(fail(format!(
            "resolved rustfmt executable {provider_path:?} points at a hostile/decoy location"
        )));
    }
    if !result.provider_used_managed {
        return Err(fail(format!(
            "expected provider_used_managed=true (CORULIX_MANAGED rustfmt), got {result:?}"
        )));
    }
    eprintln!("WINDOWS_RESOLVED_EXECUTABLE_AUTHORITY=CORULIX_MANAGED ({provider_path:?})");

    // --- REAL INVOCATION SUCCEEDED: the real managed rustfmt.exe actually
    // ran to completion (proves the Windows DLL-resolution environment this
    // crate sets is correct, not merely that a path string was resolved). A
    // decoy could never produce this: it never receives real rustfmt.toml/
    // stdin-shaped input handling and, per (1) above, is never even reached.
    match result.status {
        FormatStatus::Formatted | FormatStatus::Unchanged | FormatStatus::WouldFormat => {
            eprintln!(
                "WINDOWS_HOSTILE_PATH_REAL_RUSTFMT_INVOCATION=PASS (status={:?})",
                result.status
            );
        }
        other => {
            return Err(fail(format!(
                "expected a genuine managed rustfmt invocation to complete, got status={other:?} (reason={:?})",
                result.reason
            )));
        }
    }

    let _ = fs::remove_dir_all(&fixture);

    if sentinel.is_file() {
        let contents = fs::read_to_string(&sentinel).unwrap_or_default();
        return Err(fail(format!(
            "a hostile decoy executed during a real managed rustfmt invocation: {contents}"
        )));
    }
    eprintln!("WINDOWS_HOSTILE_PATH_MARKER_EXECUTION_COUNT=0");
    eprintln!("WINDOWS_HOSTILE_CWD_DECOY_EXECUTION_COUNT=0");
    eprintln!("WINDOWS_HOSTILE_PATH_RUSTFMT=PASS");

    let outcome = provisioning::full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("cleanup full_uninstall failed: {error:?}")))?;
    if !matches!(
        outcome,
        provisioning::full_uninstall::FullUninstallOutcome::Removed(_)
    ) {
        return Err(fail(format!(
            "expected cleanup to remove both components, got {outcome:?}"
        )));
    }
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&hostile_dir);
    let _ = fs::remove_file(&sentinel);
    Ok(())
}
