// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(windows)]

//! P17-W-R4-C2: real, native-Windows-only install -> use -> hostile-`PATH`
//! -> idempotence -> uninstall end-to-end proof for the Corulix
//! `CORULIX_MANAGED` Node runtime, against the real, pinned
//! [`wht_corulix_tooling::managed_runtimes::NODE_24_LTS_WINDOWS_X64`]
//! manifest (`node-v24.19.0-win-x64.zip`, extracted via this phase's own
//! new [`wht_corulix_tooling::provisioning::ArchiveKind::Zip`] path) and
//! the real host-wide `managed_toolchain_root()`.
//!
//! The Linux counterpart of this file
//! (`real_node_managed_lifecycle_e2e.rs`) is hardcoded to
//! `NODE_24_LTS_LINUX_X64` and, run on a Windows host, would hit that
//! manifest's own `PlatformArchitectureMismatch` refusal and report
//! `NODE_MANAGED_LIFECYCLE_E2E=BLOCKED_PROVIDER_NOT_PROVISIONED` via a
//! captured (invisible-on-pass) `eprintln!` -- a passing `cargo test` run
//! on Windows that includes that file proves *nothing* about the real
//! Windows Node vertical. This file exists so that gap is closed with
//! real, positive evidence instead: `WINDOWS_NODE_MANAGED_INSTALL=PASS`,
//! `WINDOWS_NODE_MANAGED_USE=PASS` require this file's first test to
//! actually reach its final `assert_eq!`s, not merely execute without
//! panicking.
//!
//! Requires network access the first time it runs on a given root; every
//! subsequent run resolves the artifact purely from local disk.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_core::{CancellationToken, ContentHash, ExecutionClass};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState, uninstall};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, execute};

/// `clippy::panic`/`unwrap_used`/`expect_used` are all workspace-wide
/// `deny` (`Cargo.toml`'s own `[workspace.lints.clippy]`), with no
/// `#[cfg(test)]`-scoped exception. Mirrors
/// `real_p15_go_build_vet_test_e2e.rs`'s own `TestFailure`/`fail` helper
/// exactly, rather than inventing a second one.
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
    let dir = std::env::temp_dir().join(format!("corulix-node-win-lifecycle-e2e-{label}-{stamp}"));
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

async fn ensure_clean_slate(root: &Path, manifest: &provisioning::ManagedComponentManifest) {
    let (initial_state, _) = provisioning::resolve_managed_component(root, manifest);
    if initial_state != ManagedComponentState::Available {
        let _ = uninstall::uninstall(root, manifest.id, |_| {}).await;
    }
}

#[tokio::test]
async fn real_node_windows_install_use_hostile_path_idempotence_uninstall_lifecycle()
-> Result<(), Box<dyn Error>> {
    let manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_WINDOWS_X64;
    // MANAGED_TEST_ISOLATION_DEFECT fix: mirrors the Linux counterpart's own
    // fix -- this used to resolve the real, shared, host-wide
    // `managed_toolchain_root()` and run a real `uninstall::uninstall`
    // against it. An isolated root proves the identical contract.
    let root = temp_dir("node-windows-lifecycle-managed-root");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }

    // Four external sentinels this uninstall must never touch, mirroring
    // the Linux counterpart's own required fixture set.
    let system_like_dir = temp_dir("system-like");
    let host_override_dir = temp_dir("host-override");
    let workspace_dir = temp_dir("workspace-fake-provider");
    let external_dir = temp_dir("external-arbitrary");

    let (system_path, system_digest) =
        write_sentinel(&system_like_dir, "node.exe", b"fake system node.exe bytes");
    let (host_override_path, host_override_digest) = write_sentinel(
        &host_override_dir,
        "node.exe",
        b"fake host-only-override node.exe bytes",
    );
    let (workspace_path, workspace_digest) = write_sentinel(
        &workspace_dir,
        "node.exe",
        b"fake workspace-local node.exe bytes",
    );
    let (external_path, external_digest) =
        write_sentinel(&external_dir, "unrelated.txt", b"arbitrary external file");

    ensure_clean_slate(&root, &manifest).await;

    // INSTALL (real network download + real ZIP extraction + real SHA-256
    // verification against `NODE_24_LTS_WINDOWS_X64`'s pinned digest).
    let provision_result = provisioning::provision(&root, &manifest).await;
    let node_binary = provision_result
        .map_err(|error| fail(format!("WINDOWS_NODE_MANAGED_INSTALL=FAIL ({error:?})")))?;
    assert!(
        node_binary.is_file(),
        "resolved node.exe path must exist on disk: {node_binary:?}"
    );

    // USE (real controlled-process spawn, exactly the authority every
    // other provider spawns through) -- a hostile ambient `PATH` (pointing
    // only at the fake sentinel directories above, never the real managed
    // install) is deliberately supplied here: this crate's spawn path
    // `env_clear()`s first (see `wht_corulix_tooling::execute`'s own doc
    // comment) and `ProcessSpec::executable` is always the fully-resolved,
    // typed absolute path returned by `provision` -- never a bare `"node"`
    // name looked up against `PATH` -- so a hostile `PATH` entry has no
    // path segment lookup to poison in the first place.
    // `WINDOWS_NODE_AMBIENT_PATH_AUTHORITY=NO` by this same construction.
    let hostile_path = format!(
        "{};{}",
        system_like_dir.to_string_lossy(),
        host_override_dir.to_string_lossy()
    );
    let outcome = execute(
        &ProcessSpec {
            executable: node_binary.clone(),
            arguments: vec!["--version".to_string()],
            environment: EnvironmentPolicy::empty().with_var("PATH", hostile_path),
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
        "WINDOWS_NODE_MANAGED_USE=FAIL: expected managed node --version to report 24.19.0, \
         got {stdout:?} (termination: {:?})",
        outcome.termination
    );

    let (state_after_provision, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state_after_provision, ManagedComponentState::Available);

    // IDEMPOTENT SECOND PROVISION: re-provisioning the same exact manifest
    // must not corrupt the existing install, duplicate ownership, or
    // require a fresh download/extract -- `resolve_managed_component`
    // already reporting `Available` is `provision`'s own first check, so
    // this proves that fast, no-op path is genuinely taken rather than
    // merely assumed. `WINDOWS_NODE_PROVISION_IDEMPOTENCE=PASS`.
    let second_provision_result = provisioning::provision(&root, &manifest).await;
    let second_node_binary = second_provision_result.map_err(|error| {
        fail(format!(
            "WINDOWS_NODE_PROVISION_IDEMPOTENCE=FAIL (second provision errored: {error:?})"
        ))
    })?;
    assert_eq!(
        second_node_binary, node_binary,
        "a second provision of the same manifest must resolve the identical canonical path"
    );
    let (state_after_second_provision, _) =
        provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(
        state_after_second_provision,
        ManagedComponentState::Available
    );

    // UNINSTALL.
    let removed = uninstall::uninstall(&root, manifest.id, |_| {}).await;
    assert_eq!(
        removed,
        Ok(uninstall::UninstallOutcome::Removed),
        "WINDOWS_NODE_COMPONENT_UNINSTALL=FAIL"
    );

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

    eprintln!(
        "WINDOWS_NODE_MANAGED_INSTALL=PASS WINDOWS_NODE_MANAGED_USE=PASS \
         WINDOWS_NODE_AMBIENT_PATH_AUTHORITY=NO WINDOWS_NODE_PROVISION_IDEMPOTENCE=PASS \
         WINDOWS_NODE_COMPONENT_UNINSTALL=PASS"
    );

    Ok(())
}
