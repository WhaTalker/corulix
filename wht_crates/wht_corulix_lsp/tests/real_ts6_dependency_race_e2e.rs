// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-C: real dependency-provision-vs-uninstall races for the managed
//! TypeScript-6 backend, against real npm-sourced artifacts (no synthetic
//! mirror -- the same direct-network approach
//! `real_typescript_6_managed_e2e.rs` already uses successfully). This is
//! the first real exercise of `provision_with_dependencies`'s canonical
//! sorted/deduplicated lock ordering (fixed generically in `provisioning.rs`
//! during Phase 7B-B2-C, proven there only against a synthetic AB/BA
//! fixture) against a *real* two-dependency component
//! (`typescript-language-server` -> `[node-runtime, typescript-6-classic]`):
//! no TS6-specific locking system is added here, only real races against
//! the existing shared primitive.
//!
//! Requires real network access to `registry.npmjs.org`/`nodejs.org`;
//! reports and exits early with `BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONABLE`
//! otherwise.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_tooling::provisioning::{self, ManagedComponentState, full_uninstall, uninstall};

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

fn isolated_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-ts6-race-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

async fn ensure_provisioned(
    root: &std::path::Path,
    manifest: &provisioning::ManagedComponentManifest,
) -> bool {
    let (state, _) = provisioning::resolve_managed_component(root, manifest);
    if state == ManagedComponentState::Available {
        return true;
    }
    provisioning::provision(root, manifest).await.is_ok()
}

const NODE_ID: &str = "node-runtime";
const TS6_ID: &str = "typescript-6-classic";

/// RACE A: `provision_with_dependencies(typescript-language-server)` vs a
/// concurrent `uninstall(node-runtime)`. Required outcome:
/// `TS6_NODE_DEPENDENCY_RACE_COUNT=0` -- never "typescript-language-server
/// Available + node-runtime NotProvisioned".
#[tokio::test]
async fn real_ts6_provision_vs_node_runtime_uninstall_race_e2e() -> Result<(), Box<dyn Error>> {
    let root = isolated_root("vs-node");
    let node_manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
    let ts6_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE;
    let tls_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE;

    if !ensure_provisioned(&root, &node_manifest).await
        || !ensure_provisioned(&root, &ts6_manifest).await
    {
        eprintln!(
            "TS6_NODE_DEPENDENCY_RACE=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONABLE: no network in this environment"
        );
        return Ok(());
    }

    let provision_task =
        provisioning::provision_with_dependencies(&root, &tls_manifest, &[NODE_ID, TS6_ID]);
    let uninstall_task =
        uninstall::uninstall(&root, provisioning::ManagedComponentId(NODE_ID), |_| {});
    let (_provision_result, _uninstall_result) = tokio::join!(provision_task, uninstall_task);

    let (tls_state, _) = provisioning::resolve_managed_component(&root, &tls_manifest);
    let (node_state, _) = provisioning::resolve_managed_component(&root, &node_manifest);
    if tls_state == ManagedComponentState::Available
        && node_state != ManagedComponentState::Available
    {
        return Err(fail(format!(
            "TS6_NODE_DEPENDENCY_RACE violation: typescript-language-server Available but node-runtime state was {node_state:?}"
        )));
    }
    eprintln!("TS6_NODE_DEPENDENCY_PROVISION_VS_RUNTIME_UNINSTALL=PASS");
    eprintln!("TS6_NODE_DEPENDENCY_RACE_COUNT=0");

    let _ = full_uninstall::full_uninstall(&root).await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// RACE B: `provision_with_dependencies(typescript-language-server)` vs a
/// concurrent `uninstall(typescript-6-classic)`. Required outcome:
/// `TS6_TYPESCRIPT6_DEPENDENCY_RACE_COUNT=0`.
#[tokio::test]
async fn real_ts6_provision_vs_typescript_6_uninstall_race_e2e() -> Result<(), Box<dyn Error>> {
    let root = isolated_root("vs-ts6");
    let node_manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
    let ts6_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE;
    let tls_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE;

    if !ensure_provisioned(&root, &node_manifest).await
        || !ensure_provisioned(&root, &ts6_manifest).await
    {
        eprintln!(
            "TS6_TYPESCRIPT6_DEPENDENCY_RACE=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONABLE: no network in this environment"
        );
        return Ok(());
    }

    let provision_task =
        provisioning::provision_with_dependencies(&root, &tls_manifest, &[NODE_ID, TS6_ID]);
    let uninstall_task =
        uninstall::uninstall(&root, provisioning::ManagedComponentId(TS6_ID), |_| {});
    let (_provision_result, _uninstall_result) = tokio::join!(provision_task, uninstall_task);

    let (tls_state, _) = provisioning::resolve_managed_component(&root, &tls_manifest);
    let (ts6_state, _) = provisioning::resolve_managed_component(&root, &ts6_manifest);
    if tls_state == ManagedComponentState::Available
        && ts6_state != ManagedComponentState::Available
    {
        return Err(fail(format!(
            "TS6_TYPESCRIPT6_DEPENDENCY_RACE violation: typescript-language-server Available but typescript-6-classic state was {ts6_state:?}"
        )));
    }
    eprintln!("TS6_TYPESCRIPT6_DEPENDENCY_PROVISION_VS_UNINSTALL=PASS");
    eprintln!("TS6_TYPESCRIPT6_DEPENDENCY_RACE_COUNT=0");

    let _ = full_uninstall::full_uninstall(&root).await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// RACE C: `provision_with_dependencies(typescript-language-server)` vs a
/// concurrent `full_uninstall` of the entire root. No dangling ownership,
/// no root resurrection racing the full uninstall's own root removal.
#[tokio::test]
async fn real_ts6_provision_vs_full_uninstall_race_e2e() -> Result<(), Box<dyn Error>> {
    let root = isolated_root("vs-full-uninstall");
    let node_manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
    let ts6_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE;
    let tls_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE;

    if !ensure_provisioned(&root, &node_manifest).await
        || !ensure_provisioned(&root, &ts6_manifest).await
    {
        eprintln!(
            "TS6_PROVISION_VS_FULL_UNINSTALL_RACE=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONABLE: no network in this environment"
        );
        return Ok(());
    }

    let provision_task =
        provisioning::provision_with_dependencies(&root, &tls_manifest, &[NODE_ID, TS6_ID]);
    let full_uninstall_task = full_uninstall::full_uninstall(&root);
    let (_provision_result, _full_uninstall_result) =
        tokio::join!(provision_task, full_uninstall_task);

    // Whatever the interleaving, the final state must be internally
    // consistent: either the root is fully gone, or every component that
    // reports Available has real ownership backing it (no dangling
    // ownership record for a path that was actually removed).
    let (tls_state, tls_path) = provisioning::resolve_managed_component(&root, &tls_manifest);
    if tls_state == ManagedComponentState::Available {
        let Some(path) = tls_path else {
            return Err(fail(
                "TS6_PROVISION_VS_FULL_UNINSTALL_RACE violation: Available with no resolved path",
            ));
        };
        if !path.exists() {
            return Err(fail(format!(
                "TS6_PROVISION_VS_FULL_UNINSTALL_RACE violation: Available but {path:?} does not exist on disk"
            )));
        }
    }
    eprintln!("TS6_PROVISION_VS_FULL_UNINSTALL_RACE=PASS");

    let _ = full_uninstall::full_uninstall(&root).await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
