// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof of `wht_corulix_engine::reconciler` (Installation-
//! Contract-V1 §16-21): a genuinely empty, isolated managed root converges
//! to a real, dependency-ordered, owned install after one `reconcile_at`
//! call, and a second call against the same already-converged root is
//! idempotent (no redundant redownload, every entry reports `AlreadyReady`).
//!
//! Real network dependency (rust-semantic-runtime + rustfmt, both real
//! downloads) -- reports `SKIPPED: NO_NETWORK` rather than fabricating a
//! result if the initial reachability probe fails, mirroring this
//! workspace's other real E2E files.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_engine::reconciler::{self, ComponentReconcileStatus};

fn temp_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("corulix-reconciler-e2e-{label}-{pid}-{stamp}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn network_reachable() -> bool {
    Command::new("curl")
        .args(["-sI", "--max-time", "10", "https://static.rust-lang.org/"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn real_reconcile_converges_a_dependency_chain_and_is_idempotent()
-> Result<(), Box<dyn std::error::Error>> {
    if !network_reachable() {
        eprintln!("SKIPPED: NO_NETWORK (static.rust-lang.org unreachable)");
        return Ok(());
    }

    let root = temp_root("rustfmt-chain");
    let desired: BTreeSet<String> = ["rustfmt"].into_iter().map(String::from).collect();

    let first = reconciler::reconcile_at(&root, &desired).await;
    assert!(
        first.ready(),
        "expected a fully-converged report, got: {first:?}"
    );
    let rustfmt_status = first
        .results
        .iter()
        .find(|result| result.id == "rustfmt")
        .map(|result| result.status.clone());
    assert_eq!(rustfmt_status, Some(ComponentReconcileStatus::Acquired));

    // rustfmt's own registry dependency (rust-semantic-runtime) must also
    // have been reconciled, even though it was never named in `desired`
    // directly.
    let runtime_manifest = wht_corulix_engine::registry::find("rust-semantic-runtime")
        .and_then(wht_corulix_engine::registry::ComponentEntry::manifest_for_host)
        .ok_or("rust-semantic-runtime must have a manifest on this host")?;
    let (runtime_state, _) = wht_corulix_tooling::provisioning::resolve_owned_managed_component(
        &root,
        &runtime_manifest,
    );
    assert_eq!(
        runtime_state,
        wht_corulix_tooling::provisioning::ManagedComponentState::Available,
        "rustfmt's own dependency must be genuinely owned after reconciliation"
    );

    // Idempotent re-run: the second call must report AlreadyReady for the
    // now-owned component, not attempt a redundant redownload.
    let second = reconciler::reconcile_at(&root, &desired).await;
    assert!(second.ready());
    let rustfmt_status_again = second
        .results
        .iter()
        .find(|result| result.id == "rustfmt")
        .map(|result| result.status.clone());
    assert_eq!(
        rustfmt_status_again,
        Some(ComponentReconcileStatus::AlreadyReady)
    );

    let _ = wht_corulix_tooling::provisioning::full_uninstall::uninstall_all_corulix_managed_components_at(&root).await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
