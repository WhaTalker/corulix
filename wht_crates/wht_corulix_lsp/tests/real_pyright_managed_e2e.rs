// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof against the real, Corulix-managed Pyright
//! (`pyright@1.1.413`) and Corulix-managed Node (`v24.19.0`) -- both
//! resolved exclusively through `wht_corulix_lsp::resolve_launch`'s live
//! `CORULIX_MANAGED`-first routing (`LspProviderProfile::pyright_managed()`),
//! with **no** `HostConfig` override at all: unlike `real_pyright_e2e.rs`
//! (which configures a `HOST_ONLY` absolute path to this development
//! host's own nvm-installed Pyright), this file proves the managed vertical
//! resolves and runs with zero pre-existing system Python/Node tooling
//! required (`PYTHON_MANAGED_PROVIDER_LIVE_ROUTING=PASS`,
//! `PYRIGHT_SOURCE=CORULIX_MANAGED`, `PYRIGHT_NODE_SOURCE=CORULIX_MANAGED`).
//!
//! Provisions both real artifacts itself (via
//! `wht_corulix_tooling::provisioning::provision_with_dependencies`,
//! recording Pyright's dependency on managed Node) before spawning, then
//! exercises the dependency-aware uninstall contract at the end: uninstall
//! Pyright alone (Node must survive, still depended on if reprovisioned
//! elsewhere is irrelevant here -- this test uninstalls Node too at the
//! very end and proves both are gone).
//!
//! Requires real network access to `registry.npmjs.org`/`nodejs.org` the
//! first time it runs on a given `managed_toolchain_root()`; reports and
//! exits early with `PYTHON_LSP_E2E_MANAGED=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED`
//! otherwise.

// Windows note (M09/D96): `#![cfg(unix)]`-only for this whole file --
// every test's `LspSession::spawn` call always routes through
// `wht_corulix_tooling::ManagedProcess::spawn_with_workspace_root`, which
// fails closed before any process is spawned on Windows (no
// `fchdir`-equivalent primitive to preserve object-bound cwd across
// `exec`) -- the same accepted, `FINAL_CLOSED` M09 contract already on
// record ("Windows: workspace-bound LSP UNAVAILABLE_FAIL_CLOSED, zero
// provider spawn"), mirroring `real_p7b_d_shared_node_two_dependents_active_e2e.rs`'s
// own identical closure. Both tests previously carried their own per-test
// `#[cfg(unix)]`, which left every shared helper/fixture/constant dead
// code on non-Unix targets once neither caller was compiled there
// (P17-W corrective P2); gating the whole file matches this crate's own
// established convention for the same defect class (see e.g.
// `real_typescript_7_native_e2e.rs`, `real_ts6_adversarial_e2e.rs`).
#![cfg(unix)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, Position, WorkspaceRootId};
use wht_corulix_lsp::{
    DefinitionResult, DiagnosticsResult, LspProviderProfile, LspSession, Readiness,
};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState, uninstall};
use wht_corulix_workspace::WorkspaceRoot;

const READINESS_TIMEOUT: Duration = Duration::from_secs(60);

/// This file's two tests both spawn a real Pyright/Node session under the
/// exact same production component ids and both perform a real uninstall
/// of them -- serialized so one test's `uninstall()` (which correctly
/// signals every live lease naming that component) can never stop, or
/// race the provisioning state out from under, the other's session. See
/// `real_typescript_7_native_e2e.rs`'s `REAL_TS7_SESSION_LOCK` for the
/// identical reasoning.
static REAL_PYRIGHT_SESSION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_pyright_session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_PYRIGHT_SESSION_LOCK
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

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir =
        std::env::temp_dir().join(format!("corulix-lsp-pyright-managed-root-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn temp_fixture_module(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root =
        std::env::temp_dir().join(format!("corulix-lsp-pyright-managed-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("main.py"),
        "def target():\n    pass\n\n\ndef caller():\n    target()\n",
    );
    root
}

/// Provisions both real managed artifacts (Pyright + its declared Node
/// dependency) if not already present. Returns `false` -- never an error
/// -- if either cannot be provisioned (e.g. no network), so the caller can
/// honestly report `BLOCKED` rather than fail.
async fn ensure_managed_python_provisioned(root: &std::path::Path) -> bool {
    let node_manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
    let pyright_manifest = wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE;

    let (node_state, _) = provisioning::resolve_managed_component(root, &node_manifest);
    if node_state != ManagedComponentState::Available
        && provisioning::provision(root, &node_manifest).await.is_err()
    {
        return false;
    }

    let (pyright_state, _) = provisioning::resolve_managed_component(root, &pyright_manifest);
    if pyright_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(root, &pyright_manifest, &["node-runtime"])
            .await
            .is_err()
    {
        return false;
    }
    true
}

/// Takes an explicit `managed_root` (via `resolve_launch_at`) so a session
/// this test later tears down via a destructive call against an isolated
/// root is registered under that same root's lease identity -- see
/// `real_ts6_final_residual_certification_e2e.rs`'s `resolve_ts6_managed`
/// doc comment for why the bare `resolve_launch` cannot be used here.
async fn resolve_pyright_managed(
    workspace_root: &WorkspaceRoot,
    managed_root: &std::path::Path,
) -> Option<wht_corulix_lsp::ResolvedLaunch> {
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::pyright_managed();
    wht_corulix_lsp::resolve_launch_at(&profile, &effective, workspace_root, managed_root)
        .await
        .ok()
}

#[tokio::test]
async fn real_pyright_managed_full_vertical_e2e_then_dependency_aware_uninstall()
-> Result<(), Box<dyn Error>> {
    let _lock = real_pyright_session_lock().await;
    // MANAGED_TEST_ISOLATION_DEFECT fix: isolated root for this whole test
    // (provision, spawn, and the dependency-aware uninstall below all use
    // the same one) instead of the real, shared, host-wide
    // `managed_toolchain_root()`.
    let root = temp_dir("pyright-full-vertical-managed-root");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_managed_python_provisioned(&root).await {
        eprintln!(
            "PYTHON_LSP_E2E_MANAGED=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision managed Node/Pyright in this environment (no network and never previously provisioned)"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let fixture = temp_fixture_module("full-vertical");
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let Some(launch) = resolve_pyright_managed(&workspace_root, &root).await else {
        return Err(fail(
            "pyright_managed did not resolve via CORULIX_MANAGED live routing",
        ));
    };
    // Proves the *actual spawn boundary*, not merely the profile's own
    // declared manifests: both the interpreter and the script argv[1] must
    // resolve to paths inside this test's own isolated managed root, never
    // a system nvm/apt install.
    if !launch.executable.starts_with(&root) {
        return Err(fail(format!(
            "expected the managed Node interpreter under {root:?}, got {:?}",
            launch.executable
        )));
    }
    let Some(script_argument) = launch.arguments.first() else {
        return Err(fail("expected the Pyright script path as argv[1]"));
    };
    if !PathBuf::from(script_argument).starts_with(&root) {
        return Err(fail(format!(
            "expected the managed Pyright script under {root:?}, got {script_argument:?}"
        )));
    }

    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::pyright_managed();
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

    session
        .ensure_open(&main_py)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| {
            fail(format!(
                "managed pyright never reached readiness: {error:?}"
            ))
        })?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }

    // --- DEFINITION: from the `target()` call site to its declaration ---
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

    // --- DIAGNOSTICS ---
    let diagnostics_result = wht_corulix_lsp::diagnostics(&session, &main_py)
        .await
        .map_err(|error| fail(format!("diagnostics call failed: {error:?}")))?;
    if !matches!(diagnostics_result, DiagnosticsResult::Reported(_)) {
        return Err(fail(format!(
            "expected Reported after proven readiness, got {diagnostics_result:?}"
        )));
    }

    // --- SHUTDOWN / REAP ---
    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);

    // --- DEPENDENCY-AWARE UNINSTALL: Pyright first (its own removal must
    // succeed even though Node -- its declared dependency -- is still
    // installed), then Node, IF nothing else on this shared,
    // host-wide `managed_toolchain_root()` still depends on it. This file
    // runs on the same shared root every other `managed_toolchain_root()`
    // test file uses (`real_typescript_6_managed_e2e.rs` in particular),
    // so another test's own component (`typescript-language-server`) may
    // legitimately still hold a live dependency edge on Node from an
    // earlier test binary in the same `cargo test` invocation -- that is
    // real, correct, fail-closed production behavior
    // (`StillDependedUpon`), not a defect in this test or in Node's own
    // uninstall path, and this test must not assume it has exclusive
    // ownership of a resource every managed-root test file shares. ---
    let pyright_removed = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    if pyright_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected Pyright uninstall to succeed, got {pyright_removed:?}"
        )));
    }
    let node_removed = uninstall::uninstall(
        &root,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    match node_removed {
        Ok(uninstall::UninstallOutcome::Removed) => {}
        Err(uninstall::UninstallError::StillDependedUpon(dependents))
            if !dependents.contains(&"pyright".to_string()) =>
        {
            eprintln!("PYRIGHT_MANAGED_SHARED_ROOT_FOREIGN_NODE_DEPENDENT={dependents:?}");
        }
        other => {
            return Err(fail(format!(
                "expected Node uninstall to succeed or be blocked only by a foreign (non-pyright) dependent, got {other:?}"
            )));
        }
    }

    let _ = fs::remove_dir_all(&root);
    eprintln!("PYTHON_LSP_E2E_MANAGED=PASS");
    eprintln!("PYRIGHT_MANAGED_UNINSTALL=PASS");
    Ok(())
}

/// Phase 7B-B1-R3-A §8: mirrors `real_typescript_7_active_provider_uninstall_safety_e2e`
/// for the managed Pyright vertical. The session is left genuinely active
/// (no `session.shutdown()` before `uninstall()`) -- `uninstall()`'s ACTIVE
/// EXECUTION DISCOVERY + MANAGED PROCESS SHUTDOWN stage must discover and
/// stop it itself, proven both by the lease reaching `Stopped` and by a
/// post-uninstall request against this session's own transport failing.
#[tokio::test]
async fn real_pyright_managed_active_provider_uninstall_safety_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_pyright_session_lock().await;
    let root = temp_dir("pyright-active-uninstall-safety-managed-root");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_managed_python_provisioned(&root).await {
        eprintln!(
            "PYRIGHT_ACTIVE_PROVIDER_UNINSTALL_SAFETY=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision managed Node/Pyright in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let fixture = temp_fixture_module("active-uninstall-safety");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let Some(launch) = resolve_pyright_managed(&workspace_root, &root).await else {
        return Err(fail(
            "pyright_managed did not resolve via CORULIX_MANAGED live routing",
        ));
    };

    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::pyright_managed();
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
    session
        .ensure_open(&main_py)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| {
            fail(format!(
                "managed pyright never reached readiness: {error:?}"
            ))
        })?;

    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Active) => {}
        other => {
            return Err(fail(format!(
                "expected lease state Active before uninstall, got {other:?}"
            )));
        }
    }

    // Deliberately NO `session.shutdown()` -- left genuinely active.
    let pyright_removed = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    if pyright_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected uninstall to succeed against an active Pyright session (stopping it itself), got {pyright_removed:?}"
        )));
    }

    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Stopped) => {}
        other => {
            return Err(fail(format!(
                "expected lease state Stopped after uninstall stopped this session, got {other:?}"
            )));
        }
    }

    let post_uninstall_request = session
        .transport()
        .request(
            "shutdown",
            serde_json::Value::Null,
            Duration::from_secs(5),
            &cancellation,
        )
        .await;
    if post_uninstall_request.is_ok() {
        return Err(fail(
            "expected the Pyright transport to be closed after uninstall stopped the process, but a request still succeeded",
        ));
    }

    // Node was Pyright's dependency and is still installed (this test only
    // uninstalled Pyright) -- clean it up so this test leaves the managed
    // root in the same "nothing of this test's own left behind" state the
    // vertical test above does, unless another test file's own component
    // sharing this same host-wide `managed_toolchain_root()` still
    // legitimately depends on it (see the vertical test above's own
    // comment for why that is correct, not a defect).
    let node_removed = uninstall::uninstall(
        &root,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    match node_removed {
        Ok(uninstall::UninstallOutcome::Removed) => {}
        Err(uninstall::UninstallError::StillDependedUpon(dependents))
            if !dependents.contains(&"pyright".to_string()) =>
        {
            eprintln!("PYRIGHT_MANAGED_SHARED_ROOT_FOREIGN_NODE_DEPENDENT={dependents:?}");
        }
        other => {
            return Err(fail(format!(
                "expected Node uninstall to succeed or be blocked only by a foreign (non-pyright) dependent, got {other:?}"
            )));
        }
    }

    let _ = fs::remove_dir_all(&fixture);
    let _ = fs::remove_dir_all(&root);
    eprintln!("PYRIGHT_ACTIVE_PROVIDER_UNINSTALL_SAFETY=PASS");
    eprintln!("PYRIGHT_LEASE_LIFECYCLE=PASS");
    Ok(())
}
