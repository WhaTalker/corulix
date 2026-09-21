// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof for the managed Rust semantic runtime (Phase
//! 7B-B1-R1): `rustc` + `cargo` + `rust-std` + `rust-src`, four
//! independently-pinned official `static.rust-lang.org` artifacts merged
//! into one install, plus the real, managed rust-analyzer binary resolved
//! against it -- with **zero** `HostConfig` override and **zero** system
//! Rust toolchain dependency at the actual spawn boundary.
//!
//! `wht_corulix_tooling::managed::spawn`/`execute` call `Command::env_clear`
//! unconditionally before every spawn (see `wht_crates/wht_corulix_tooling/
//! src/lib.rs` and `src/managed.rs`) -- the child process never inherits
//! this test process's own ambient environment/`PATH` at all, regardless of
//! what a real system Rust toolchain this development host happens to have
//! installed (`.cargo/bin`, `rustup`, etc.) puts there. `AMBIENT_HOST_PATH_
//! AUTHORITY=NO` therefore holds structurally, not merely because this test
//! constructs a poisoned decoy `PATH`: there is no ambient `PATH` to poison
//! or fall back to in the first place. A real managed-only run succeeding
//! is direct proof that every `cargo`/`rustc`/`rust-src` resolution
//! rust-analyzer performed came from the explicit `PATH`/`CARGO`/`RUSTC`
//! entries `wht_corulix_lsp::resolve_launch` built from
//! `RUST_SEMANTIC_RUNTIME_LINUX_X64` -- nothing else was reachable.
//!
//! Requires real network access to `static.rust-lang.org`/`github.com` on
//! every run, into this file's own isolated managed root
//! (`MANAGED_TEST_ISOLATION_DEFECT` fix -- the merged runtime alone is
//! roughly 700MB on disk); reports and exits early with
//! `RUST_LSP_E2E_MANAGED=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED`
//! otherwise.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, Position, WorkspaceRootId};
use wht_corulix_lsp::{DefinitionResult, LspProviderProfile, LspSession, Readiness};
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentId, ManagedComponentState, uninstall,
};
use wht_corulix_workspace::WorkspaceRoot;

const READINESS_TIMEOUT: Duration = Duration::from_secs(120);

/// This file's tests both spawn a real managed rust-analyzer session under
/// the exact same production component ids and both perform a real
/// uninstall of them -- serialized so one test's `uninstall()` can never
/// stop, or race the provisioning state out from under, the other's
/// session. See `real_typescript_7_native_e2e.rs`'s `REAL_TS7_SESSION_LOCK`
/// for the identical reasoning.
static REAL_RUST_SESSION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_rust_session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_RUST_SESSION_LOCK
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

/// A real, std-only Cargo package: no third-party crate dependencies at
/// all, so `cargo metadata`/`cargo check` never needs the network
/// regardless of `CARGO_NET_OFFLINE` -- this test proves the semantic
/// runtime itself, not dependency-resolution behavior.
fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!(
        "corulix-lsp-rust-semantic-runtime-managed-root-{label}-{stamp}"
    ));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn temp_fixture_crate(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!(
        "corulix-lsp-rust-semantic-runtime-e2e-{label}-{stamp}"
    ));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_rust_semantic_runtime_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"corulix_rust_semantic_runtime_fixture\"\npath = \"src/main.rs\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn main() {\n    let s = String::new();\n    println!(\"{}\", s.len());\n}\n",
    );
    root
}

/// Provisions both real managed artifacts (the merged Rust semantic
/// runtime + managed rust-analyzer, recording rust-analyzer's dependency on
/// the runtime) if not already present. Returns `false` -- never an error
/// -- if either cannot be provisioned (e.g. no network), so the caller can
/// honestly report `BLOCKED` rather than fail.
async fn ensure_managed_rust_provisioned(root: &std::path::Path) -> bool {
    let runtime_manifest = wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64;
    let rust_analyzer_manifest = wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64;

    let (runtime_state, _) = provisioning::resolve_managed_component(root, &runtime_manifest);
    if runtime_state != ManagedComponentState::Available
        && provisioning::provision(root, &runtime_manifest)
            .await
            .is_err()
    {
        return false;
    }

    let (rust_analyzer_state, _) =
        provisioning::resolve_managed_component(root, &rust_analyzer_manifest);
    if rust_analyzer_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(
            root,
            &rust_analyzer_manifest,
            &["rust-semantic-runtime"],
        )
        .await
        .is_err()
    {
        return false;
    }
    true
}

async fn resolve_rust_analyzer_managed(
    workspace_root: &WorkspaceRoot,
    managed_root: &std::path::Path,
) -> Option<wht_corulix_lsp::ResolvedLaunch> {
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::rust_analyzer_managed();
    wht_corulix_lsp::resolve_launch_at(&profile, &effective, workspace_root, managed_root)
        .await
        .ok()
}

/// Uninstalls `target`, cascading through `StillDependedUpon` exactly once:
/// on that error, uninstalls every reported dependent (resolved against
/// this crate's own known managed-toolchain manifests) and retries.
///
/// `root` is this test's own isolated managed root
/// (`MANAGED_TEST_ISOLATION_DEFECT` fix -- was previously the real, shared,
/// host-wide `managed_toolchain_root()`). The cascade logic is kept general
/// (rather than assuming a closed dependent set) since it is still shared
/// with call sites that could in principle see a real `rustfmt` dependent
/// recorded against this exact root by this same test's own setup.
async fn uninstall_cascading_known_dependents(
    root: &std::path::Path,
    target: ManagedComponentId,
) -> Result<uninstall::UninstallOutcome, Box<dyn Error>> {
    match uninstall::uninstall(root, target, |_| {}).await {
        Err(uninstall::UninstallError::StillDependedUpon(dependents)) => {
            for dependent in &dependents {
                let dependent_id = match dependent.as_str() {
                    "rustfmt" => wht_corulix_formatter::managed_toolchain::RUSTFMT_LINUX_X64.id,
                    other => {
                        return Err(fail(format!(
                            "uninstalling {target:?} reported dependent {other:?}, which this test does not know how to cascade-remove (full dependents: {dependents:?})"
                        )));
                    }
                };
                let removed = uninstall::uninstall(root, dependent_id, |_| {}).await;
                if !matches!(
                    removed,
                    Ok(uninstall::UninstallOutcome::Removed)
                        | Ok(uninstall::UninstallOutcome::AlreadyRemoved)
                ) {
                    return Err(fail(format!(
                        "expected cascading uninstall of dependent {dependent:?} to succeed, got {removed:?}"
                    )));
                }
            }
            uninstall::uninstall(root, target, |_| {}).await.map_err(|error| {
                fail(format!(
                    "{target:?} uninstall still fails after cascading known dependent removal: {error:?}"
                ))
            })
        }
        other => other.map_err(|error| fail(format!("{target:?} uninstall failed: {error:?}"))),
    }
}

#[tokio::test]
async fn real_rust_semantic_runtime_managed_full_vertical_e2e_then_dependency_aware_uninstall()
-> Result<(), Box<dyn Error>> {
    let _lock = real_rust_session_lock().await;
    // MANAGED_TEST_ISOLATION_DEFECT fix: isolated root for this whole test
    // instead of the real, shared, host-wide `managed_toolchain_root()`.
    let root = temp_dir("full-vertical-managed-root");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_managed_rust_provisioned(&root).await {
        eprintln!(
            "RUST_LSP_E2E_MANAGED=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision the managed Rust semantic runtime/rust-analyzer in this environment (no network and never previously provisioned)"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let fixture = temp_fixture_crate("full-vertical");
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let Some(launch) = resolve_rust_analyzer_managed(&workspace_root, &root).await else {
        return Err(fail(
            "rust_analyzer_managed did not resolve via CORULIX_MANAGED live routing",
        ));
    };

    // Proves the actual spawn boundary, not merely the profile's declared
    // manifests: the resolved server binary, the CARGO/RUSTC overrides, and
    // the PATH entry rust-analyzer's own internal `cargo`/`rustc` shells
    // resolve against must all live under this test's own isolated managed
    // root -- never a system rustup/cargo/rustc install, even though this
    // development host has one on its own ambient PATH.
    if !launch.executable.starts_with(&root) {
        return Err(fail(format!(
            "expected the managed rust-analyzer binary under {root:?}, got {:?}",
            launch.executable
        )));
    }
    for label in ["CARGO", "RUSTC"] {
        let Some(value) = launch.environment.get(label) else {
            return Err(fail(format!(
                "expected {label} to be set in the resolved launch environment"
            )));
        };
        if !PathBuf::from(value).starts_with(&root) {
            return Err(fail(format!(
                "expected managed {label}={value:?} under {root:?}"
            )));
        }
    }
    let Some(path_env) = launch.environment.get("PATH") else {
        return Err(fail(
            "expected PATH to be set in the resolved launch environment",
        ));
    };
    for entry in path_env.split(':') {
        if !PathBuf::from(entry).starts_with(&root) {
            return Err(fail(format!(
                "expected every resolved PATH entry under {root:?}, found {entry:?} (RUST_SEMANTIC_RUNTIME_SELF_CONTAINED would be violated by any non-managed entry)"
            )));
        }
    }

    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::rust_analyzer_managed();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    let main_rs = fixture.join("src/main.rs");

    session
        .ensure_open(&main_rs)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| {
            fail(format!(
                "managed rust-analyzer never reached readiness: {error:?}"
            ))
        })?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }

    // --- DEFINITION: `String::new` -> real std source, only resolvable
    // with `rust-src` merged into the managed runtime. This is the
    // decisive assertion: `RUST_SEMANTIC_RUNTIME_SELF_CONTAINED=YES` is
    // false if rust-analyzer reports no definition at all (proven
    // empirically during this phase's research gate -- the identical query
    // against rustc+cargo+rust-std *without* rust-src returns an empty
    // result). The real definition target (`lib/rustlib/src/rust/library/
    // alloc/src/string.rs`, under `managed_toolchain_root()`) is *outside*
    // this fixture's own workspace by construction (Rust's std source is
    // never vendored into a project) -- `wht_corulix_lsp::operations`'s own
    // confinement boundary (Architecture Rule F) therefore rejects it as
    // `LspError::ResultOutsideWorkspace` rather than returning a path
    // Corulix cannot prove is inside the active workspace. That specific
    // error is the positive signal here: it can only occur when
    // rust-analyzer found a *real* definition somewhere real-analyzer
    // resolved, which for `String::new` is only possible once rust-src's
    // source tree is present. `DefinitionResult::None`/`Ok` with an
    // in-workspace location would both be wrong for this exact query and
    // are treated as failures below.
    let fixture_source = fs::read_to_string(&main_rs)
        .map_err(|error| fail(format!("re-reading the fixture failed: {error}")))?;
    let new_call_offset = fixture_source
        .find("String::new")
        .ok_or_else(|| fail("fixture source changed out from under the hardcoded byte offset"))?
        + "String::".len()
        + 1; // land inside "new", not on its leading boundary
    let definition_result = wht_corulix_lsp::definition(
        &session,
        &main_rs,
        &Position {
            line_zero_based: 0,
            byte_column_zero_based: 0,
            byte_offset: new_call_offset as u64,
        },
        &cancellation,
    )
    .await;
    match definition_result {
        Err(wht_corulix_lsp::LspError::ResultOutsideWorkspace) => {
            // Decisive: rust-analyzer found a real definition outside the
            // fixture workspace -- only possible with rust-src merged in.
        }
        Err(error) => {
            return Err(fail(format!("definition request failed: {error:?}")));
        }
        Ok(DefinitionResult::None) => {
            return Err(fail(
                "expected a real definition into rust-src's alloc::string::String::new, got None -- RUST_SEMANTIC_RUNTIME_SELF_CONTAINED=NO",
            ));
        }
        Ok(other) => {
            return Err(fail(format!(
                "expected ResultOutsideWorkspace (std source is never inside the fixture workspace), got {other:?}"
            )));
        }
    }

    // --- SHUTDOWN / REAP ---
    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);

    // --- DEPENDENCY-AWARE UNINSTALL: rust-analyzer first (its own removal
    // must succeed even though the Rust semantic runtime -- its declared
    // dependency -- is still installed), then the runtime (now that
    // nothing depends on it). ---
    let rust_analyzer_removed = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64.id,
        |_| {},
    )
    .await;
    if rust_analyzer_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected rust-analyzer uninstall to succeed, got {rust_analyzer_removed:?}"
        )));
    }
    let runtime_removed = uninstall_cascading_known_dependents(
        &root,
        wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64.id,
    )
    .await?;
    if runtime_removed != uninstall::UninstallOutcome::Removed {
        return Err(fail(format!(
            "expected Rust semantic runtime uninstall to succeed once undepended (after cascading any known dependents), got {runtime_removed:?}"
        )));
    }

    let _ = fs::remove_dir_all(&root);
    eprintln!("RUST_LSP_E2E_MANAGED=PASS");
    eprintln!("RUST_SEMANTIC_RUNTIME_SELF_CONTAINED=YES");
    eprintln!("RUST_MANAGED_INSTALL_USE_UNINSTALL_E2E=PASS");
    Ok(())
}

/// Phase 7B-B1-R3-A §9-10: mirrors `real_typescript_7_active_provider_uninstall_safety_e2e`
/// for the managed rust-analyzer vertical, whose lease binds both
/// `rust-analyzer` (primary) and `rust-semantic-runtime` (dependency). The
/// session is left genuinely active -- `uninstall()` of rust-analyzer must
/// discover and stop it itself, proven by the lease reaching `Stopped` and
/// by a post-uninstall request against this session's own transport
/// failing (the real `rust-analyzer` process, and with it any `cargo`/
/// `rustc` children a flycheck may have spawned, is genuinely gone -- not
/// merely the on-disk component directory).
#[tokio::test]
async fn real_rust_analyzer_active_provider_uninstall_safety_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_rust_session_lock().await;
    let root = temp_dir("active-uninstall-safety-managed-root");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_managed_rust_provisioned(&root).await {
        eprintln!(
            "RUST_ACTIVE_PROVIDER_UNINSTALL_SAFETY=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision the managed Rust semantic runtime/rust-analyzer in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let fixture = temp_fixture_crate("active-uninstall-safety");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let Some(launch) = resolve_rust_analyzer_managed(&workspace_root, &root).await else {
        return Err(fail(
            "rust_analyzer_managed did not resolve via CORULIX_MANAGED live routing",
        ));
    };

    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::rust_analyzer_managed();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    let main_rs = fixture.join("src/main.rs");
    session
        .ensure_open(&main_rs)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| {
            fail(format!(
                "managed rust-analyzer never reached readiness: {error:?}"
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
    let rust_analyzer_removed = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64.id,
        |_| {},
    )
    .await;
    if rust_analyzer_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected uninstall to succeed against an active rust-analyzer session (stopping it itself), got {rust_analyzer_removed:?}"
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
            "expected the rust-analyzer transport to be closed after uninstall stopped the process, but a request still succeeded",
        ));
    }

    let runtime_removed = uninstall_cascading_known_dependents(
        &root,
        wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64.id,
    )
    .await?;
    if runtime_removed != uninstall::UninstallOutcome::Removed {
        return Err(fail(format!(
            "expected Rust semantic runtime uninstall to succeed once undepended (after cascading any known dependents), got {runtime_removed:?}"
        )));
    }

    let _ = fs::remove_dir_all(&fixture);
    let _ = fs::remove_dir_all(&root);
    eprintln!("RUST_ACTIVE_PROVIDER_UNINSTALL_SAFETY=PASS");
    eprintln!("RUST_LEASE_LIFECYCLE=PASS");
    Ok(())
}
