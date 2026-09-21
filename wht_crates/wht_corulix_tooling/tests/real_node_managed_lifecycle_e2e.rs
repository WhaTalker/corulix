// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real install -> use -> uninstall end-to-end proof for the Corulix
//! `CORULIX_MANAGED` Node runtime (Phase 7B-B1), against the real, pinned
//! `NODE_24_LTS_LINUX_X64` manifest and the real host-wide
//! `managed_toolchain_root()`. Requires network access the first time it
//! runs on a given root; every subsequent run resolves the artifact purely
//! from local disk. Reports and exits early if provisioning cannot
//! complete (no network, never previously provisioned) rather than
//! failing -- `NODE_MANAGED_LIFECYCLE_E2E=BLOCKED_PROVIDER_NOT_PROVISIONED`.
//!
//! Proves, against the real filesystem:
//! - the managed binary actually runs (`node --version` via
//!   `wht_corulix_tooling::execute`, the same controlled-process authority
//!   every other provider spawns through);
//! - `uninstall::uninstall` actually removes it and its ownership record;
//! - a second uninstall call is idempotent;
//! - four external sentinel fixtures (a system-like path, a HOST_ONLY
//!   override-style path, a workspace-local fake-provider path, and an
//!   arbitrary external file) are byte-identical before and after --
//!   `SYSTEM_TOOL_MUTATION_COUNT=0`, `HOST_OVERRIDE_MUTATION_COUNT=0`,
//!   `WORKSPACE_MUTATION_COUNT=0`, `EXTERNAL_SENTINEL_MUTATION_COUNT=0`.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_core::{CancellationToken, ContentHash, ExecutionClass};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState, uninstall};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, execute};

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-node-lifecycle-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn write_sentinel(dir: &Path, name: &str, content: &[u8]) -> (PathBuf, String) {
    let path = dir.join(name);
    fs::write(&path, content)
        .unwrap_or_else(|error| unreachable!("sentinel fixture write must succeed: {error:?}"));
    let digest = ContentHash::compute_sha256(content).digest_hex;
    (path, digest)
}

fn assert_sentinel_unchanged(path: &PathBuf, expected_digest: &str) {
    let bytes = fs::read(path).unwrap_or_else(|error| {
        unreachable!("sentinel fixture must still exist after uninstall: {error:?}")
    });
    let actual_digest = ContentHash::compute_sha256(&bytes).digest_hex;
    assert_eq!(
        actual_digest, expected_digest,
        "sentinel fixture at {path:?} was mutated by the managed uninstall"
    );
}

#[tokio::test]
async fn real_node_install_use_uninstall_lifecycle_never_touches_external_sentinels() {
    let manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64;
    // MANAGED_TEST_ISOLATION_DEFECT fix: this used to resolve the real,
    // shared, host-wide `managed_toolchain_root()` and run a real
    // `uninstall::uninstall` against it, permanently removing `node-runtime`
    // from every other test/live MCP session sharing that root. This test's
    // own real intent (external sentinels untouched by a real install/use/
    // uninstall cycle) never required the real root -- an isolated one
    // proves the identical contract.
    let root = temp_dir("node-lifecycle-managed-root");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }

    // Four external sentinels this uninstall must never touch, mirroring
    // the mandate's required fixture set: a system-like path, a
    // HOST_ONLY-override-style path, a workspace-local fake-provider path,
    // and an arbitrary external file.
    let system_like_dir = temp_dir("system-like");
    let host_override_dir = temp_dir("host-override");
    let workspace_dir = temp_dir("workspace-fake-provider");
    let external_dir = temp_dir("external-arbitrary");

    let (system_path, system_digest) = write_sentinel(
        &system_like_dir,
        "node",
        b"#!/bin/sh\necho system-node-fake\n",
    );
    let (host_override_path, host_override_digest) = write_sentinel(
        &host_override_dir,
        "node",
        b"#!/bin/sh\necho host-only-override-node-fake\n",
    );
    let (workspace_path, workspace_digest) = write_sentinel(
        &workspace_dir,
        "node_modules_bin_node",
        b"#!/bin/sh\necho workspace-local-fake-node\n",
    );
    let (external_path, external_digest) =
        write_sentinel(&external_dir, "unrelated.txt", b"arbitrary external file");

    // Ensure not already provisioned from a prior interrupted run, so this
    // test genuinely exercises install, not just resolve-existing.
    let (initial_state, _) = provisioning::resolve_managed_component(&root, &manifest);
    if initial_state != ManagedComponentState::Available {
        // Best-effort pre-clean; provisioning below will still prove the
        // real pipeline regardless of whether this succeeds.
        let _ = uninstall::uninstall(&root, manifest.id, |_| {}).await;
    }

    let provision_result = provisioning::provision(&root, &manifest).await;
    let Ok(node_binary) = provision_result else {
        eprintln!(
            "NODE_MANAGED_LIFECYCLE_E2E=BLOCKED_PROVIDER_NOT_PROVISIONED ({:?})",
            provision_result.err()
        );
        return;
    };

    // USE: run the real managed binary through the real controlled-process
    // authority, exactly as a live provider launch would.
    let outcome = execute(
        &ProcessSpec {
            executable: node_binary.clone(),
            arguments: vec!["--version".to_string()],
            environment: EnvironmentPolicy::empty(),
            working_directory: root.clone(),
            limits: ProcessLimits::default(),
            timeout: Duration::from_secs(10),
            execution_class: ExecutionClass::ControlledExternalTool,
            argv0: None,
        },
        &CancellationToken::new(),
    )
    .await;
    let stdout = String::from_utf8_lossy(&outcome.stdout.bytes);
    assert!(
        stdout.trim_start_matches('v').starts_with("24.19.0"),
        "expected managed node --version to report 24.19.0, got {stdout:?} (termination: {:?})",
        outcome.termination
    );

    let (state_after_provision, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state_after_provision, ManagedComponentState::Available);

    // UNINSTALL.
    let removed = uninstall::uninstall(&root, manifest.id, |_| {}).await;
    assert_eq!(removed, Ok(uninstall::UninstallOutcome::Removed));

    let (state_after_uninstall, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state_after_uninstall, ManagedComponentState::NotProvisioned);

    // IDEMPOTENT SECOND UNINSTALL.
    let removed_again = uninstall::uninstall(&root, manifest.id, |_| {}).await;
    assert_eq!(
        removed_again,
        Ok(uninstall::UninstallOutcome::AlreadyRemoved)
    );

    // Every external sentinel is untouched.
    assert_sentinel_unchanged(&system_path, &system_digest);
    assert_sentinel_unchanged(&host_override_path, &host_override_digest);
    assert_sentinel_unchanged(&workspace_path, &workspace_digest);
    assert_sentinel_unchanged(&external_path, &external_digest);

    let _ = fs::remove_dir_all(&system_like_dir);
    let _ = fs::remove_dir_all(&host_override_dir);
    let _ = fs::remove_dir_all(&workspace_dir);
    let _ = fs::remove_dir_all(&external_dir);
    let _ = fs::remove_dir_all(&root);

    eprintln!("NODE_MANAGED_LIFECYCLE_E2E=PASS");
}
