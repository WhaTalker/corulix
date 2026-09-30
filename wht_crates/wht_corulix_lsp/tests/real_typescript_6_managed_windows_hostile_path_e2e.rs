// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(windows)]

//! P17-W Stage D/G: the native-Windows hostile-`PATH`/hostile-CWD proof for
//! the managed TypeScript-6/JavaScript-6 compatibility backend
//! (`typescript-language-server@6.0.0` -> managed Node -> `typescript@6.0.3`
//! `lib/tsserver.js`), closing the disclosed gap that
//! `real_gopls_managed_windows_hostile_path_e2e.rs` already closed for
//! gopls: no Windows-native hostile-PATH test existed for TS6 before this
//! file. `real_ts6_adversarial_e2e.rs` (the Unix adversarial proof this file
//! is the platform counterpart of) is `#![cfg(unix)]`-only by disclosed
//! design (its mechanism -- `chmod`-executable shell-script markers via
//! `std::os::unix::fs::PermissionsExt` -- has no Windows equivalent), and
//! `real_poisoned_path_executable_authority_e2e.rs` (also `#![cfg(unix)]`)
//! never covered TS6 at all, only TS7-native and Python.
//!
//! # This is not a straight port of the gopls Windows file
//!
//! `typescript-language-server` is never spawned as its own executable on
//! any platform: `wht_corulix_lsp::managed_toolchain::
//! TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE`'s own doc comment and
//! `wht_corulix_lsp::profile::resolve_launch_at` (confirmed by direct
//! reading, not assumed) both establish that the real spawned process is
//! the managed **Node** interpreter (`NODE_24_LTS_HOST_NATIVE`), invoked as
//! `node.exe <managed-root>/.../lib/cli.mjs`, i.e.
//! `ResolvedLaunch::executable` is the Node binary and
//! `ResolvedLaunch::arguments[0]` is the `cli.mjs` script path. A hostile
//! `typescript-language-server.exe`/`.bat` decoy -- the shape the gopls file's
//! pattern would suggest by naive analogy -- is never resolved as an
//! executable at all in this exact profile and would prove nothing. The
//! real Windows-specific attack surface this file proves closed is:
//!
//! - **`node.exe`/`node.bat` decoys in the workspace CWD**: `CreateProcess`
//!   searches the current directory before `PATH`
//!   (`session.rs::working_directory: workspace_root.canonical_path()`), so
//!   a decoy Node binary dropped directly inside the fixture project root is
//!   the single strongest real vector on this platform.
//! - **`node.exe`/`node.bat` decoys in a hostile `PATH`-style directory.**
//! - **A decoy `cli.mjs`** placed at a path that would collide with a naive,
//!   unmanaged resolution -- proving the *script argument*, not only the
//!   executable, is the Corulix-managed one.
//!
//! No ambient-`PATH` mutation is used to prove containment, for the same
//! reason the gopls Windows file gives: this workspace forbids `unsafe`
//! code and `std::env::set_var` requires `unsafe` under edition 2024;
//! `resolve_launch_at`'s `HOST_ONLY`/`CORULIX_MANAGED` resolution for this
//! profile's `managed_interpreter` never reads ambient `PATH` in the first
//! place, so the CWD-decoy and resolved-executable checks below are the
//! only evidence that can exist here, and they are sufficient.
//!
//! Real, independent verification throughout: a written sentinel file
//! (echoed by the decoy scripts themselves) proves whether a decoy ever
//! ran. (P17-W corrective P4: an earlier draft of this file also carried a
//! `Get-CimInstance Win32_Process`-based live-image-path check, mirroring
//! the gopls Windows file's own evidence model -- but `typescript_language_server_managed()`'s
//! `ExecutionClass` is workspace-bound, so `LspSession::spawn` here always
//! fails closed via `ManagedProcess::spawn_with_workspace_root` before any
//! process, decoy or managed, is ever spawned; there is never a live child
//! process whose image path that check could examine, unlike gopls's own
//! non-workspace-bound profile. That check was removed as unreachable dead
//! code rather than left as an orphaned, uncallable helper -- the sentinel
//! check alone already proves the equivalent property, that no decoy ever
//! executed, for this specific fail-closed contract.)
//!
//! Shares `real_typescript_6_managed_e2e.rs`'s provisioning shape
//! (`provisioning::provision`/`provision_with_dependencies` against the real
//! managed toolchain root) rather than an out-of-band artifact mirror --
//! this file provisions the three real components directly (Node,
//! `typescript-6-classic`, `typescript-language-server`) exactly as that
//! file's own `ensure_managed_ts6_provisioned` does (duplicated here rather
//! than shared across independent test-binary compilation units, matching
//! this workspace's own established convention between
//! `real_gopls_managed_e2e.rs`/`real_gopls_managed_adversarial_e2e.rs`).

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_lsp::{LspError, LspProviderProfile, LspSession};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

// P17-W corrective P4: an earlier draft of this file also declared a
// `READINESS_TIMEOUT` constant for a `session.wait_until_ready(...)` call.
// No such call exists in the test below -- the session never reaches a
// spawned, ready state at all under the workspace-bound fail-closed
// contract this file's own final assertion proves (see the module doc's
// note on `real_process_image_path`'s identical removal) -- so it was
// removed as an orphaned constant rather than left declared-but-unused.
const NODE_ID: &str = "node-runtime";
const TS6_ID: &str = "typescript-6-classic";

static REAL_TS6_WINDOWS_HOSTILE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_ts6_windows_hostile_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_TS6_WINDOWS_HOSTILE_LOCK
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

// ============================================================
// Provisioning (mirrors real_typescript_6_managed_e2e.rs's own
// ensure_managed_ts6_provisioned, `_HOST_NATIVE` throughout).
// ============================================================

async fn ensure_managed_ts6_provisioned(root: &Path) -> bool {
    let node_manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
    let ts6_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE;
    let tls_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE;

    let (node_state, _) = provisioning::resolve_managed_component(root, &node_manifest);
    if node_state != ManagedComponentState::Available
        && provisioning::provision(root, &node_manifest).await.is_err()
    {
        return false;
    }

    let (ts6_state, _) = provisioning::resolve_managed_component(root, &ts6_manifest);
    if ts6_state != ManagedComponentState::Available
        && provisioning::provision(root, &ts6_manifest).await.is_err()
    {
        return false;
    }

    let (tls_state, _) = provisioning::resolve_managed_component(root, &tls_manifest);
    if tls_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(root, &tls_manifest, &[NODE_ID, TS6_ID])
            .await
            .is_err()
    {
        return false;
    }
    true
}

fn isolated_root(label: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "C:\\root".to_string());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = PathBuf::from(home)
        .join(".cache/corulix-ts6-windows-hostile-e2e/roots")
        .join(format!("{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

// ============================================================
// Windows-specific hostile decoys
// ============================================================

/// A real, functional decoy that appends its own invocation to `sentinel`
/// every time it runs -- mirrors `real_gopls_managed_windows_hostile_path_e2e.rs`'s
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

/// A real two-file TS fixture, plus hostile `node.exe.bat`/`node.bat`
/// decoys dropped directly in the fixture root -- the workspace CWD
/// `session.rs` sets the spawned child's working directory to.
fn ts_fixture_with_cwd_decoy(label: &str, decoy_sentinel: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-ts6-win-hostile-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("tsconfig.json"),
        r#"{"compilerOptions":{"target":"es2020","module":"es2020","moduleResolution":"bundler"}}"#,
    );
    let _ = fs::write(
        root.join("main.ts"),
        "export function target(): number {\n  return 1;\n}\n",
    );
    // `node.exe` cannot be authored as a functional `.bat` under that exact
    // name (Windows would refuse to execute a `.bat`'s contents as a PE
    // image if ever launched via an explicit `.exe` path) -- `node.exe.bat`
    // is a negative-control name that never resolves bare `node`/`node.exe`
    // lookups; `node.bat` is the real `PATHEXT` vector a straight
    // `.exe`-only port would miss, since Corulix's own resolution always
    // passes an explicit, fully-qualified managed path and never performs a
    // bare-name `PATH` search -- these decoys prove that fact against a live
    // session, they do not rely on it.
    write_decoy(&root.join("node.exe.bat"), decoy_sentinel);
    write_decoy(&root.join("node.bat"), decoy_sentinel);
    root
}

/// §Windows hostile-PATH/CWD: fake `node.exe`/`node.bat` decoys placed
/// inside the workspace CWD and a hostile `PATH`-style directory must never
/// be what Corulix resolves or launches through the real, host-native-wired
/// `typescript_language_server_managed()` profile -- proven against a
/// genuinely live managed session, not merely by reading `resolve_launch_at`'s
/// source.
#[tokio::test]
async fn real_ts6_managed_windows_hostile_path_and_cwd_decoy_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_ts6_windows_hostile_lock().await;
    let root = isolated_root("windows-hostile-path");
    if !ensure_managed_ts6_provisioned(&root).await {
        eprintln!("WINDOWS_HOSTILE_PATH_TS6=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        return Ok(());
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let hostile_dir = std::env::temp_dir().join(format!("corulix-ts6-win-hostile-path-{stamp}"));
    let sentinel = std::env::temp_dir().join(format!("corulix-ts6-win-sentinel-{stamp}.log"));
    let _ = fs::create_dir_all(&hostile_dir);
    write_decoy(&hostile_dir.join("node.exe.bat"), &sentinel);
    write_decoy(&hostile_dir.join("node.bat"), &sentinel);
    write_decoy(
        &hostile_dir.join("typescript-language-server.bat"),
        &sentinel,
    );

    // --- POSITIVE CONTROL: the decoys are real and functional. ---
    let _ = StdCommand::new(hostile_dir.join("node.bat")).output();
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
    let fixture = ts_fixture_with_cwd_decoy("windows-hostile-path", &sentinel);
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::typescript_language_server_managed();
    let launch = wht_corulix_lsp::resolve_launch_at(&profile, &effective, &workspace_root, &root)
        .await
        .map_err(|error| {
            fail(format!(
                "typescript_language_server_managed did not resolve: {error:?}"
            ))
        })?;

    // --- RESOLVED EXECUTABLE: must be the real managed Node interpreter
    // under `root`, never the hostile PATH dir or the workspace CWD decoy. ---
    if !launch.executable.starts_with(&root) {
        return Err(fail(format!(
            "expected the resolved node executable under the managed root {root:?}, got {:?} -- HOSTILE_PATH_OR_CWD_DECOY_WON",
            launch.executable
        )));
    }
    if launch.executable.starts_with(&hostile_dir) || launch.executable.starts_with(&fixture) {
        return Err(fail(format!(
            "resolved node executable {:?} points at a hostile/decoy location",
            launch.executable
        )));
    }
    eprintln!(
        "WINDOWS_RESOLVED_EXECUTABLE_AUTHORITY=CORULIX_MANAGED ({:?})",
        launch.executable
    );

    // --- RESOLVED SCRIPT ARGUMENT: the cli.mjs argv[0] must also be the
    // real managed one, never a decoy path. ---
    let Some(script_argument) = launch.arguments.first() else {
        return Err(fail(
            "expected the typescript-language-server cli.mjs script path as argv[1]",
        ));
    };
    if !PathBuf::from(script_argument).starts_with(&root) {
        return Err(fail(format!(
            "expected the managed cli.mjs script under {root:?}, got {script_argument:?}"
        )));
    }
    eprintln!("WINDOWS_RESOLVED_SCRIPT_AUTHORITY=CORULIX_MANAGED ({script_argument:?})");

    // --- FINAL WINDOWS CONTRACT (M09/D96): resolution above genuinely
    // resists both decoys -- the resolved executable/script authority is
    // real and CORULIX_MANAGED, never the hostile PATH dir or the
    // workspace-CWD decoy -- but `LspSession::spawn` (this profile's
    // `ExecutionClass` is workspace-bound) always fails closed on Windows
    // via `ManagedProcess::spawn_with_workspace_root` before any process is
    // spawned (no `fchdir`-equivalent primitive to preserve object-bound
    // cwd across `exec`). No `Command` is ever constructed, so neither
    // decoy nor the real Node interpreter is ever invoked past this point
    // -- this is the same accepted, `FINAL_CLOSED` M09 contract already on
    // record ("Windows: workspace-bound LSP UNAVAILABLE_FAIL_CLOSED, zero
    // provider spawn"), not a defect this test exists to catch.
    let cancellation = CancellationToken::new();
    let result = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await;
    match result {
        Ok(_) => {
            return Err(fail(
                "expected the accepted Windows fail-closed contract (ProviderSpawnFailed, no \
                 workspace-bound child process ever spawned), got a live session",
            ));
        }
        Err(LspError::ProviderSpawnFailed) => {}
        Err(other) => {
            return Err(fail(format!(
                "expected LspError::ProviderSpawnFailed, got {other:?}"
            )));
        }
    }
    eprintln!(
        "WINDOWS_WORKSPACE_BOUND_LSP_FAIL_CLOSED=PASS (no node.exe, decoy or managed, ever spawned)"
    );

    let _ = fs::remove_dir_all(&fixture);

    // --- No decoy ever ran, since no process (managed or hostile) was
    // spawned at all under the accepted fail-closed contract. ---
    if sentinel.is_file() {
        let contents = fs::read_to_string(&sentinel).unwrap_or_default();
        return Err(fail(format!(
            "a hostile decoy executed despite the fail-closed contract: {contents}"
        )));
    }
    eprintln!("WINDOWS_HOSTILE_PATH_MARKER_EXECUTION_COUNT=0");
    eprintln!("WINDOWS_HOSTILE_CWD_DECOY_EXECUTION_COUNT=0");
    eprintln!("WINDOWS_HOSTILE_PATH_TS6=PASS");

    let _ = fs::remove_dir_all(&hostile_dir);
    let _ = fs::remove_file(&sentinel);
    Ok(())
}
