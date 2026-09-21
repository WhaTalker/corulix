// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real install -> use -> uninstall end-to-end proof for the Corulix
//! `CORULIX_MANAGED` rust-analyzer binary (Phase 7B-B1), against the real,
//! pinned `RUST_ANALYZER_LINUX_X64` manifest -- the first managed component
//! whose upstream artifact is a bare gzip-compressed binary
//! (`ArchiveKind::GzippedBinary`), not a tar archive.
//!
//! This test proves the *provisioning/uninstall lifecycle* only
//! (`RUST_ANALYZER_MANAGED_E2E=PASS`). It deliberately does NOT assert
//! `RUST_LSP_E2E_MANAGED=PASS` or `RUST_SEMANTIC_RUNTIME_SELF_CONTAINED=YES`
//! -- a real, separately-run hostile-PATH probe (documented on the
//! manifest's own doc comment in `managed_toolchain.rs`) proved
//! rust-analyzer cannot build a project model at all without a real
//! `cargo`/`rustc` on `PATH`, so this crate does not claim a managed-only
//! Rust LSP vertical this phase.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_core::{CancellationToken, ExecutionClass};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState, uninstall};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, execute};

fn managed_manifest() -> provisioning::ManagedComponentManifest {
    wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64
}

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!(
        "corulix-lsp-rust-analyzer-managed-root-{label}-{stamp}"
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[tokio::test]
async fn real_rust_analyzer_managed_provision_use_uninstall_lifecycle() {
    let manifest = managed_manifest();
    // MANAGED_TEST_ISOLATION_DEFECT fix: isolated root instead of the real,
    // shared, host-wide `managed_toolchain_root()`.
    let root = temp_dir("lifecycle");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }

    let (initial_state, _) = provisioning::resolve_managed_component(&root, &manifest);
    if initial_state != ManagedComponentState::Available {
        let _ = uninstall::uninstall(&root, manifest.id, |_| {}).await;
    }

    let provision_result = provisioning::provision(&root, &manifest).await;
    let Ok(ra_binary) = provision_result else {
        eprintln!(
            "RUST_ANALYZER_MANAGED_E2E=BLOCKED_PROVIDER_NOT_PROVISIONED ({:?})",
            provision_result.err()
        );
        return;
    };

    let outcome = execute(
        &ProcessSpec {
            executable: ra_binary.clone(),
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
        stdout.contains("rust-analyzer"),
        "expected managed rust-analyzer --version to report its own name, got {stdout:?} (termination: {:?})",
        outcome.termination
    );

    let (state_after_provision, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state_after_provision, ManagedComponentState::Available);

    let removed = uninstall::uninstall(&root, manifest.id, |_| {}).await;
    assert_eq!(removed, Ok(uninstall::UninstallOutcome::Removed));

    let (state_after_uninstall, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state_after_uninstall, ManagedComponentState::NotProvisioned);

    let removed_again = uninstall::uninstall(&root, manifest.id, |_| {}).await;
    assert_eq!(
        removed_again,
        Ok(uninstall::UninstallOutcome::AlreadyRemoved)
    );

    let _ = std::fs::remove_dir_all(&root);
    eprintln!("RUST_ANALYZER_MANAGED_E2E=PASS");
}
