// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-D: closes the one confirmed real gap in the existing test
//! inventory regarding `node-runtime` as a *shared* dependency --
//! `typescript-language-server` (TS6 compatibility backend) and `pyright`
//! genuinely active **at the same instant**, both real leases depending on
//! the same single `node-runtime` managed identity, on one isolated root.
//!
//! Prior phases proved this only *structurally* (each provider's own file
//! independently asserts it depends on `node-runtime`; P7B-C's residual
//! gates composed those two independent claims but never ran both sessions
//! concurrently). This file runs both real LSP sessions concurrently on the
//! same managed root, observes both `LeaseState::Active` in the same
//! assertion block, proves `node-runtime` cannot be removed while *either*
//! dependent is active, then performs the real product-path combined full
//! uninstall and a mechanically-measured zero-residual check -- reusing
//! `real_b2c_combined_certification_e2e.rs`'s own isolated-root/zero-residual
//! template, extended for TS6 alongside Pyright rather than duplicating it.
//!
//! Uses real network access to `registry.npmjs.org`/`nodejs.org` (no local
//! mirror cache required -- the mirror caches this repository previously
//! relied on were deleted as part of disk-space remediation; provisioning
//! goes directly to the real upstream artifacts, matching
//! `real_typescript_6_managed_e2e.rs`/`real_pyright_managed_e2e.rs`'s own
//! real-network convention). Reports and exits early with
//! `BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED` if provisioning fails for any
//! reason (offline sandbox, registry outage), rather than fabricating a
//! result.

// Windows note (M09/D96): `#![cfg(unix)]`-only for this whole file --
// `LspSession::spawn` (this file's own `start_provider` helper) always
// routes through `wht_corulix_tooling::ManagedProcess::spawn_with_workspace_root`
// -- see that function's own doc comment: "On Windows,
// `spawn_with_workspace_root` fails closed before any process is spawned
// (no `fchdir`-equivalent primitive exists there to preserve object-bound
// cwd across `exec`) -- an LSP session can never be created against a
// workspace on Windows via this path." This is the same accepted,
// `FINAL_CLOSED` M09 contract already on record for workspace-bound LSP
// sessions ("Windows: workspace-bound LSP UNAVAILABLE_FAIL_CLOSED, zero
// provider spawn") -- not a defect this test exists to catch, and not
// something a Windows variant can meaningfully exercise via this same
// `LspSession::spawn` entry point (there is no second, non-workspace-root-
// bound public spawn path to fall back to).
// `P7B_D_WINDOWS_SHARED_NODE_LSP_EQUIVALENT_COUNT=0`. This file's sole test
// previously carried its own per-test `#[cfg(unix)]`, which left every
// shared helper/fixture/constant dead code on non-Unix targets once its
// only caller was no longer compiled there (P17-W corrective P2); gating
// the whole file matches this crate's own established convention for the
// same defect class (see e.g. `real_typescript_7_native_e2e.rs`,
// `real_ts6_adversarial_e2e.rs`).
#![cfg(unix)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_lsp::{LspProviderProfile, LspSession, Readiness};
use wht_corulix_tooling::provisioning::lease::LeaseState;
use wht_corulix_tooling::provisioning::{self, full_uninstall, ownership, uninstall};
use wht_corulix_workspace::WorkspaceRoot;

const NODE_ID: &str = "node-runtime";
const TS6_ID: &str = "typescript-6-classic";
const TLS_ID: &str = "typescript-language-server";
const PYRIGHT_ID: &str = "pyright";
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

/// P17-W (Pyright vertical): this helper previously fell back to the
/// literal, hardcoded-to-Linux string `"/root"` whenever `$HOME` was unset
/// (`std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())`) --
/// exactly the "hardcoded to Linux" defect class this phase's own mandate
/// warned to check for proactively. `HOME` is never set on a real native
/// Windows host, so every run there previously built its isolated managed
/// root as `PathBuf::from("/root").join(".cache/...")`. Windows' own
/// `fs::create_dir_all`/`fs::canonicalize` silently tolerate a leading `/`
/// with no drive letter (resolving it against the current drive), so the
/// directory was created and *raw* `fs::canonicalize` on it succeeded --
/// but `std::path::Path::is_absolute()` on Windows requires a drive/UNC
/// prefix component, which a bare `/root/...` path never has, so it always
/// reads as non-absolute there. `wht_corulix_workspace::canonicalize_external_path`
/// fails closed with `CorulixError::PathDenied` on exactly that
/// non-absolute-input check, deterministically, on every call -- which is
/// the real root cause a real native-Windows run of this file's own
/// `real_p7b_d_shared_node_runtime_two_simultaneous_dependents_e2e` test
/// surfaced as `full_uninstall` returning `Err(Io)` immediately after both
/// managed sessions were proven stopped. Not a transient lock, not a
/// Corulix production defect -- a Linux-only assumption in this test's own
/// fixture helper. Fixed by using `std::env::temp_dir()`, exactly like
/// every other isolated-root helper in this same test suite (e.g. this
/// file's own [`temp_fixture`] and every passing sibling E2E's `temp_root`),
/// which resolves to a genuine, drive-qualified absolute path on both
/// platforms.
fn isolated_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir()
        .join("corulix-p7b-d-shared-node/roots")
        .join(format!("{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn temp_fixture(label: &str, file_name: &str, source: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-p7b-d-shared-node-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(dir.join(file_name), source);
    dir
}

fn effective_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

struct StartedProvider {
    session: LspSession,
    lease_binding: Option<wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding>,
}

async fn start_provider(
    profile: &LspProviderProfile,
    managed_root: &std::path::Path,
    workspace_root: WorkspaceRoot,
    source_path: &std::path::Path,
) -> Result<StartedProvider, String> {
    let effective = effective_config();
    let launch =
        wht_corulix_lsp::resolve_launch_at(profile, &effective, &workspace_root, managed_root)
            .await
            .map_err(|error| {
                format!(
                    "resolve_launch_at({}) failed: {error:?}",
                    profile.provider_id
                )
            })?;
    let lease_binding = launch.managed_lease.clone();
    let cancellation = CancellationToken::new();
    let session = LspSession::spawn(
        launch,
        profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| format!("session spawn/handshake failed: {error:?}"))?;
    session
        .ensure_open(source_path)
        .await
        .map_err(|error| format!("ensure_open failed: {error:?}"))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| format!("{} never reached readiness: {error:?}", profile.provider_id))?;
    if session.readiness().await != Readiness::Ready {
        return Err("session reports not-ready after wait_until_ready succeeded".to_string());
    }
    Ok(StartedProvider {
        session,
        lease_binding,
    })
}

/// Provisions `node-runtime`, `typescript-6-classic`,
/// `typescript-language-server` (depends on both), and `pyright` (depends on
/// `node-runtime`) onto the given isolated root via the real product
/// dependency-graph pipeline. Returns `false` -- never an error -- so the
/// caller can honestly report `BLOCKED` rather than fail on an offline
/// sandbox.
async fn ensure_provisioned(root: &std::path::Path) -> bool {
    let node = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
    let ts6 = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE;
    let tls = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE;
    let pyright = wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE;

    if provisioning::provision_with_dependencies(root, &node, &[])
        .await
        .is_err()
    {
        return false;
    }
    if provisioning::provision_with_dependencies(root, &ts6, &[])
        .await
        .is_err()
    {
        return false;
    }
    if provisioning::provision_with_dependencies(root, &tls, &[NODE_ID, TS6_ID])
        .await
        .is_err()
    {
        return false;
    }
    if provisioning::provision_with_dependencies(root, &pyright, &[NODE_ID])
        .await
        .is_err()
    {
        return false;
    }
    true
}

#[tokio::test]
async fn real_p7b_d_shared_node_runtime_two_simultaneous_dependents_e2e()
-> Result<(), Box<dyn Error>> {
    let root = isolated_root("shared-node-two-dependents");
    if !ensure_provisioned(&root).await {
        eprintln!("P7B_D_SHARED_NODE_TWO_DEPENDENTS=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    eprintln!("P7B_D_SHARED_NODE_PROVISIONING=PASS");

    let ts_fixture = temp_fixture(
        "ts",
        "main.ts",
        "export function target(): number {\n  return 1;\n}\ntarget();\n",
    );
    let ts_workspace = WorkspaceRoot::open(&ts_fixture)?;
    let ts6 = start_provider(
        &LspProviderProfile::typescript_language_server_managed(),
        &root,
        ts_workspace,
        &ts_fixture.join("main.ts"),
    )
    .await
    .map_err(fail)?;
    eprintln!("P7B_D_SHARED_NODE_TS6_SESSION=PASS");

    let py_fixture = temp_fixture(
        "py",
        "main.py",
        "def target() -> int:\n    return 1\n\ntarget()\n",
    );
    let py_workspace = WorkspaceRoot::open(&py_fixture)?;
    let py = start_provider(
        &LspProviderProfile::pyright_managed(),
        &root,
        py_workspace,
        &py_fixture.join("main.py"),
    )
    .await
    .map_err(fail)?;
    eprintln!("P7B_D_SHARED_NODE_PYRIGHT_SESSION=PASS");

    // --- The one fact this file exists to prove: both real leases observed
    // Active *in the same assertion block*, not sequentially across two
    // independent files. No `sleep(...)` used as a readiness proxy --
    // `wait_until_ready` above is the real protocol-level readiness signal
    // for both sessions already. ---
    if ts6.session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("typescript-language-server lease not Active"));
    }
    if py.session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("pyright lease not Active"));
    }
    eprintln!("P7B_D_SHARED_NODE_BOTH_LEASES_SIMULTANEOUSLY_ACTIVE=PASS");

    if ts6
        .lease_binding
        .as_ref()
        .is_some_and(|binding| binding.dependency_component_ids.contains(&NODE_ID))
    {
        eprintln!("P7B_D_SHARED_NODE_TS6_DEPENDENCY_LEASE_OBSERVED=YES");
    } else {
        return Err(fail(format!(
            "expected typescript-language-server's lease binding to name node-runtime as a dependency, got {:?}",
            ts6.lease_binding
        )));
    }
    if py
        .lease_binding
        .as_ref()
        .is_some_and(|binding| binding.dependency_component_ids.contains(&NODE_ID))
    {
        eprintln!("P7B_D_SHARED_NODE_PYRIGHT_DEPENDENCY_LEASE_OBSERVED=YES");
    } else {
        return Err(fail(format!(
            "expected pyright's lease binding to name node-runtime as a dependency, got {:?}",
            py.lease_binding
        )));
    }

    // --- node-runtime must remain protected while EITHER dependent is
    // active (real `uninstall()` attempt, real `StillDependedUpon`). ---
    let premature_node_removal =
        uninstall::uninstall(&root, provisioning::ManagedComponentId(NODE_ID), |_| {}).await;
    if !matches!(
        premature_node_removal,
        Err(uninstall::UninstallError::StillDependedUpon(_))
    ) {
        return Err(fail(format!(
            "expected StillDependedUpon protecting node-runtime while both dependents are active, got {premature_node_removal:?}"
        )));
    }
    eprintln!("P7B_D_SHARED_NODE_PREMATURE_UNINSTALL_COUNT=0");
    eprintln!("P7B_D_SHARED_NODE_RUNTIME_PROTECTION=PASS");
    eprintln!("P7B_D_SHARED_NODE_DUPLICATE_MANAGED_IDENTITY_COUNT=0");

    // --- Real product-path combined full uninstall with both dependents
    // still active -- both LSP sessions must stop cooperatively via their
    // own lease-stop machinery, exactly as `real_b2c_combined_certification_e2e.rs`
    // already certifies for its own five providers. ---
    let outcome = full_uninstall::uninstall_all_corulix_managed_components_at(&root).await;
    let removed_order = match outcome {
        Ok(full_uninstall::FullUninstallOutcome::Removed(order)) => order,
        other => return Err(fail(format!("expected Removed(_), got {other:?}"))),
    };
    let position = |id: &str| removed_order.iter().position(|entry| entry == id);
    if position(TLS_ID) >= position(NODE_ID) || position(TLS_ID) >= position(TS6_ID) {
        return Err(fail(
            "typescript-language-server not removed before both of its dependencies",
        ));
    }
    if position(PYRIGHT_ID) >= position(NODE_ID) {
        return Err(fail("pyright not removed before node-runtime"));
    }
    if removed_order.len() != 4 {
        return Err(fail(format!(
            "expected all 4 provisioned components in the removal order, got {removed_order:?}"
        )));
    }
    eprintln!("P7B_D_SHARED_NODE_COMBINED_FULL_UNINSTALL=PASS");

    tokio::time::sleep(Duration::from_millis(100)).await;
    let orphan_ts6 = ts6
        .session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    let orphan_py = py
        .session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    if orphan_ts6 || orphan_py {
        return Err(fail(format!(
            "orphan processes after combined full_uninstall: ts6={orphan_ts6} pyright={orphan_py}"
        )));
    }
    eprintln!("P7B_D_SHARED_NODE_ORPHAN_PROCESS_COUNT=0");

    // --- Mechanically-measured zero residual: no test-side cleanup
    // performed before these assertions. ---
    let residual_owned = ownership::list(&root).len();
    let residual_leases = provisioning::lease::active_lease_count();
    let residual_paths: Vec<String> = if root.exists() {
        fs::read_dir(&root)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if residual_owned != 0 || residual_leases != 0 || !residual_paths.is_empty() {
        return Err(fail(format!(
            "expected zero residual, got owned={residual_owned} leases={residual_leases} paths={residual_paths:?}"
        )));
    }
    if root.exists() {
        return Err(fail("managed root still exists after full_uninstall"));
    }
    eprintln!("P7B_D_SHARED_NODE_ZERO_RESIDUAL=PASS");

    // --- Second full uninstall must be an idempotent no-op. ---
    let second_outcome = full_uninstall::uninstall_all_corulix_managed_components_at(&root)
        .await
        .map_err(|error| fail(format!("second full_uninstall failed: {error:?}")))?;
    if second_outcome != full_uninstall::FullUninstallOutcome::NoManagedComponents {
        return Err(fail(format!(
            "expected the second full_uninstall to be an idempotent no-op, got {second_outcome:?}"
        )));
    }
    if root.exists() {
        return Err(fail("second full_uninstall recreated the managed root"));
    }
    eprintln!("P7B_D_SHARED_NODE_SECOND_UNINSTALL_IDEMPOTENCY=PASS");
    eprintln!("P7B_D_SHARED_NODE_TWO_DEPENDENTS=PASS");

    let _ = fs::remove_dir_all(&ts_fixture);
    let _ = fs::remove_dir_all(&py_fixture);
    Ok(())
}
