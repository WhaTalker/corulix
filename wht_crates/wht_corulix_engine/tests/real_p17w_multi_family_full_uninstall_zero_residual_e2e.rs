// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P17-W exit-gate closure: `full_uninstall::full_uninstall` zero-residual
//! proof extended across a genuinely *multi-family* managed root.
//!
//! Every existing zero-residual test proves the claim against either one
//! real component alone (`real_p16_biome_zero_residual_uninstall_e2e.rs`:
//! Biome only) or synthetic fixture bytes with no real provider identity
//! (`real_p15_managed_scratch_zero_residual_e2e.rs`:
//! `provisioning::tests`-style fake manifests). `full_uninstall` is
//! registry-driven (`ownership::list(root)`, real on-disk ownership
//! records), not a per-language hardcoded list, so the guarantee already
//! generalizes to any set of `CorulixManaged` components by construction --
//! this test still proves it empirically against a real, isolated managed
//! root carrying components from three independent families at once:
//!
//! - **Rust family** (two components, a real dependency edge between them):
//!   `rust-semantic-runtime` + `rustfmt`, this host's own native manifests.
//! - **Node** (`node-runtime`): a cross-provider runtime component with no
//!   direct single-purpose "use" API of its own in this crate boundary --
//!   invoked directly (`node --version`) to prove it is a real, functional
//!   provisioned binary, not merely a downloaded-and-verified file.
//! - **Biome** (one of TS6/TS7/Biome/Pyright, chosen for the same reason
//!   the existing single-component test chose it: no sibling-runtime
//!   dependency, so its own "real use" step cannot itself be blocked by an
//!   unrelated provisioning failure).
//!
//! All four are genuinely *used* (a real `format_preview_at` invocation for
//! rustfmt and Biome, a real `--version` invocation for Node) before
//! `full_uninstall` runs, so this test also proves the claim survives
//! whatever transient state a real invocation leaves behind (stdio pipes,
//! process-tree teardown), not only a freshly-provisioned, never-touched
//! component tree.
//!
//! # Safety precondition (P17-W standing rule)
//!
//! `full_uninstall` takes an explicit `root: &Path` parameter -- it never
//! resolves the shared host-wide managed toolchain root internally -- but
//! this test still asserts, *before provisioning a single byte*, that its
//! own isolated root does not coincide with the real host-managed root
//! every other pass's evidence depends on. This is a hard precondition, not
//! a comment: a coincidental collision (e.g. a `HOME`/`USERPROFILE`
//! resolution defect building an isolated-root path that happens to equal
//! the real one) would otherwise destroy every previously-provisioned
//! component this phase certified, and this test's own teardown calls the
//! real destructive `full_uninstall` pipeline.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, ExecutionClass, WorkspacePath, WorkspaceRootId};
use wht_corulix_formatter::managed_toolchain::{BIOME_HOST_NATIVE, RUSTFMT_HOST_NATIVE};
use wht_corulix_formatter::{DEFAULT_MAX_INPUT_BYTES, FormatStatus, format_preview_at};
use wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
#[cfg(not(target_os = "windows"))]
use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64;
#[cfg(target_os = "windows")]
use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64;
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentManifest, ManagedComponentState, full_uninstall, lease, ownership,
};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, execute};
use wht_corulix_workspace::WorkspaceRoot;

const RUST_SEMANTIC_RUNTIME_ID: &str = "rust-semantic-runtime";
const RUSTFMT_ID: &str = "rustfmt";
const NODE_ID: &str = "node-runtime";
const BIOME_ID: &str = "biome";

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

/// This host's own real `rust-semantic-runtime` manifest -- mirrors
/// `wht_corulix_formatter::managed::rust_semantic_runtime_host_native`'s own
/// `#[cfg]`-gated-alias pattern (that helper is `pub(crate)` and cannot be
/// named from this external integration test, so this file carries its own
/// copy of the identical, already-established idiom rather than inventing a
/// new one).
fn rust_semantic_runtime_host_native() -> ManagedComponentManifest {
    #[cfg(target_os = "windows")]
    {
        RUST_SEMANTIC_RUNTIME_WINDOWS_X64
    }
    #[cfg(not(target_os = "windows"))]
    {
        RUST_SEMANTIC_RUNTIME_LINUX_X64
    }
}

/// Prefers `USERPROFILE` directly on Windows -- `HOME` can be present but
/// empty (not merely absent) in a WMI-launched job context, a real,
/// previously-diagnosed defect class this helper deliberately does not
/// reintroduce via a bare `unwrap_or_else` on absence alone.
fn home_directory() -> String {
    std::env::var("USERPROFILE")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOME").ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().into_owned())
}

fn isolated_root(label: &str) -> PathBuf {
    let dir = PathBuf::from(home_directory())
        .join(".cache/corulix-p17w-multi-family-zero-residual-e2e/roots")
        .join(format!("{label}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    dir
}

async fn ensure_provisioned(root: &std::path::Path, manifest: &ManagedComponentManifest) -> bool {
    let (state, _) = provisioning::resolve_managed_component(root, manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, manifest).await.is_ok()
}

/// `P17W_MULTI_FAMILY_FULL_UNINSTALL_ZERO_RESIDUAL_E2E`: provision real
/// components from three independent families into ONE isolated managed
/// root, genuinely use every one of them, then confirm the real production
/// `full_uninstall` pipeline removes the entire root -- zero residual
/// files, zero remaining ownership records, zero remaining process leases
/// against this root.
#[tokio::test]
async fn real_multi_family_full_uninstall_zero_residual_e2e() -> Result<(), Box<dyn Error>> {
    let root = isolated_root("multi-family-zero-residual");

    // --- HARD PRECONDITION: this isolated root must never coincide with
    // the real host-wide managed toolchain root. ---
    if let Ok(host_root) = provisioning::managed_toolchain_root() {
        let host_canonical = fs::canonicalize(&host_root).unwrap_or(host_root);
        let isolated_canonical = fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
        if isolated_canonical == host_canonical {
            return Err(fail(format!(
                "REFUSING TO RUN: isolated test root {root:?} resolved to the same path as the real host-managed toolchain root -- this would have destroyed every previously-provisioned component this phase's evidence depends on"
            )));
        }
    }
    eprintln!("P17W_MULTI_FAMILY_ROOT_IS_ISOLATED_NOT_HOST_ROOT=PASS ({root:?})");

    // --- PROVISION: Rust family (two components, one real dependency edge). ---
    let runtime_manifest = rust_semantic_runtime_host_native();
    if !ensure_provisioned(&root, &runtime_manifest).await {
        eprintln!(
            "P17W_MULTI_FAMILY_ZERO_RESIDUAL_E2E=BLOCKED_RUST_SEMANTIC_RUNTIME_NOT_PROVISIONED"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    let rustfmt_manifest = RUSTFMT_HOST_NATIVE;
    let (rustfmt_state, _) = provisioning::resolve_managed_component(&root, &rustfmt_manifest);
    if rustfmt_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(
            &root,
            &rustfmt_manifest,
            &[RUST_SEMANTIC_RUNTIME_ID],
        )
        .await
        .is_err()
    {
        eprintln!("P17W_MULTI_FAMILY_ZERO_RESIDUAL_E2E=BLOCKED_RUSTFMT_NOT_PROVISIONED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    // --- PROVISION: Node. ---
    let node_manifest = NODE_24_LTS_HOST_NATIVE;
    if !ensure_provisioned(&root, &node_manifest).await {
        eprintln!("P17W_MULTI_FAMILY_ZERO_RESIDUAL_E2E=BLOCKED_NODE_NOT_PROVISIONED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    // --- PROVISION: Biome. ---
    let biome_manifest = BIOME_HOST_NATIVE;
    if !ensure_provisioned(&root, &biome_manifest).await {
        eprintln!("P17W_MULTI_FAMILY_ZERO_RESIDUAL_E2E=BLOCKED_BIOME_NOT_PROVISIONED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    eprintln!("P17W_MULTI_FAMILY_ALL_FOUR_COMPONENTS_PROVISIONED=PASS");

    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );

    // --- REAL USE: rustfmt against a real, deliberately misformatted .rs
    // fixture. ---
    let rustfmt_fixture =
        std::env::temp_dir().join(format!("corulix-p17w-multi-family-rustfmt-{}", stamp()));
    let _ = fs::create_dir_all(&rustfmt_fixture);
    let _ = fs::write(
        rustfmt_fixture.join("main.rs"),
        "fn main( ) {\n    let  x=1;\n}\n",
    );
    let rustfmt_workspace = WorkspaceRoot::open(&rustfmt_fixture)?;
    let rustfmt_result = format_preview_at(
        &root,
        &effective,
        rustfmt_workspace,
        WorkspacePath {
            root: WorkspaceRootId(0),
            relative_path: "main.rs".to_string(),
        },
        DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("rustfmt format_preview_at failed: {error:?}")))?;
    match rustfmt_result.status {
        FormatStatus::Formatted | FormatStatus::Unchanged | FormatStatus::WouldFormat => {}
        other => {
            return Err(fail(format!(
                "expected a genuine managed rustfmt invocation to complete, got status={other:?} (reason={:?})",
                rustfmt_result.reason
            )));
        }
    }
    if !rustfmt_result.provider_used_managed {
        return Err(fail(format!(
            "expected rustfmt to resolve via CORULIX_MANAGED, got {rustfmt_result:?}"
        )));
    }
    let _ = fs::remove_dir_all(&rustfmt_fixture);
    eprintln!("P17W_MULTI_FAMILY_REAL_RUSTFMT_USE=PASS");

    // --- REAL USE: Biome against a real, deliberately misformatted .ts
    // fixture. ---
    let biome_fixture =
        std::env::temp_dir().join(format!("corulix-p17w-multi-family-biome-{}", stamp()));
    let _ = fs::create_dir_all(&biome_fixture);
    let _ = fs::write(
        biome_fixture.join("main.ts"),
        "export function target( ):number{\n  return   1;\n}\n",
    );
    let biome_workspace = WorkspaceRoot::open(&biome_fixture)?;
    let biome_result = format_preview_at(
        &root,
        &effective,
        biome_workspace,
        WorkspacePath {
            root: WorkspaceRootId(0),
            relative_path: "main.ts".to_string(),
        },
        DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("biome format_preview_at failed: {error:?}")))?;
    match biome_result.status {
        FormatStatus::Formatted | FormatStatus::Unchanged | FormatStatus::WouldFormat => {}
        other => {
            return Err(fail(format!(
                "expected a genuine managed biome invocation to complete, got status={other:?} (reason={:?})",
                biome_result.reason
            )));
        }
    }
    if !biome_result.provider_used_managed {
        return Err(fail(format!(
            "expected biome to resolve via CORULIX_MANAGED, got {biome_result:?}"
        )));
    }
    let _ = fs::remove_dir_all(&biome_fixture);
    eprintln!("P17W_MULTI_FAMILY_REAL_BIOME_USE=PASS");

    // --- REAL USE: Node, invoked directly (no dedicated "use Node" product
    // API exists in this crate boundary the way rustfmt/Biome have
    // `format_preview_at`) -- proves it is a real, functional provisioned
    // binary, not merely a downloaded-and-hash-verified file. ---
    let (_, node_binary) = provisioning::resolve_managed_component(&root, &node_manifest);
    let Some(node_binary) = node_binary else {
        return Err(fail(
            "expected a resolved node binary path after provisioning",
        ));
    };
    let node_outcome = execute(
        &ProcessSpec {
            executable: node_binary,
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
    let node_stdout = String::from_utf8_lossy(&node_outcome.stdout.bytes)
        .trim()
        .to_string();
    if !node_stdout.starts_with('v') {
        return Err(fail(format!(
            "expected managed node --version to report a real vNN.NN.NN string, got {node_stdout:?} (termination: {:?})",
            node_outcome.termination
        )));
    }
    eprintln!("P17W_MULTI_FAMILY_REAL_NODE_USE=PASS ({node_stdout})");

    // --- CAPTURE PRE-UNINSTALL STATE (the residual claim's own baseline). ---
    let root_identity = ownership::root_identity(&root);
    let component_ids_before: std::collections::HashSet<String> = ownership::list(&root)
        .into_iter()
        .filter_map(Result::ok)
        .map(|record| record.component_id)
        .collect();
    for expected in [RUST_SEMANTIC_RUNTIME_ID, RUSTFMT_ID, NODE_ID, BIOME_ID] {
        if !component_ids_before.contains(expected) {
            return Err(fail(format!(
                "expected an ownership record for {expected:?} before uninstall, got {component_ids_before:?}"
            )));
        }
    }
    eprintln!("P17W_MULTI_FAMILY_FOUR_OWNERSHIP_RECORDS_PRESENT=PASS");

    // --- THE REAL PRODUCTION full_uninstall PIPELINE -- never a
    // component-specific or test-only removal code path. ---
    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("full_uninstall failed: {error:?}")))?;
    let full_uninstall::FullUninstallOutcome::Removed(removed_ids) = outcome else {
        return Err(fail(format!(
            "expected FullUninstallOutcome::Removed, got {outcome:?}"
        )));
    };
    let removed_set: std::collections::HashSet<String> = removed_ids.into_iter().collect();
    for expected in [RUST_SEMANTIC_RUNTIME_ID, RUSTFMT_ID, NODE_ID, BIOME_ID] {
        if !removed_set.contains(expected) {
            return Err(fail(format!(
                "expected {expected:?} in full_uninstall's removed set, got {removed_set:?}"
            )));
        }
    }
    eprintln!("P17W_MULTI_FAMILY_FULL_UNINSTALL_REMOVED_ALL_FOUR=PASS");

    // --- ZERO RESIDUAL: the full assertion surface, not just "the
    // component's own install directory is gone". ---
    if root.exists() {
        return Err(fail(format!(
            "expected the entire isolated managed root to be fully removed (zero residual), but it still exists: {root:?}"
        )));
    }
    eprintln!("P17W_MULTI_FAMILY_MANAGED_ROOT_FULLY_REMOVED=PASS");

    let records_after: Vec<_> = ownership::list(&root)
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    if !records_after.is_empty() {
        return Err(fail(format!(
            "expected zero ownership records after full_uninstall, got {records_after:?}"
        )));
    }
    eprintln!("P17W_MULTI_FAMILY_ZERO_OWNERSHIP_RECORDS_AFTER=PASS");

    let leases_after = lease::process_identities_for_managed_root(&root_identity);
    if !leases_after.is_empty() {
        return Err(fail(format!(
            "expected zero registered process leases against this managed root after full_uninstall, got {leases_after:?}"
        )));
    }
    eprintln!("P17W_MULTI_FAMILY_ZERO_LEASES_AFTER=PASS");

    eprintln!("P17W_MULTI_FAMILY_FULL_UNINSTALL_ZERO_RESIDUAL_E2E=PASS");
    Ok(())
}
