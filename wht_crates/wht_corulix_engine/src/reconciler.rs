// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The real desired-state reconciler (Installation-Contract-V1 §16-21):
//! given an explicit set of desired component ids and a managed root,
//! converges that root to have every one of them genuinely
//! `Available`/owned -- classifying, never blindly re-downloading, and
//! never inventing a second acquisition mechanism for a component that
//! already has one.
//!
//! **This module calls the same acquisition primitives production
//! resolution already uses, it does not grow its own.** Every component
//! except `gopls` is acquired through
//! `wht_corulix_tooling::provisioning::resolve_or_acquire_owned` -- the
//! exact function `wht_corulix_lsp::profile::resolve_or_acquire_if_allowed`
//! and `wht_corulix_formatter::managed::resolve_formatter` already call for
//! real on-demand acquisition. `gopls` is acquired through
//! `wht_corulix_tooling::provisioning::provision_go_module_build` -- the
//! exact function `wht_corulix_lsp::profile::resolve_or_acquire_gopls_via_module_build_if_allowed`
//! calls for the identical reason (its manifest's `source.tarball_url` is
//! an inert sentinel; see that module's own doc comment). A reconciled
//! component and a lazily on-demand-acquired one therefore always land in
//! identical on-disk/ownership state -- there is exactly one way any
//! component in this registry ever becomes `Available`, never two that
//! could disagree.
//!
//! This module deliberately does not consult install-profile permission
//! (`ManagedProvisioningPolicy`/`install_profile::grants_intent`) itself --
//! by the time a caller has computed a `desired` set to reconcile (from
//! [`crate::groups`] under an explicit `--only`/`--profile full` choice, or
//! `FIRST_RUN_RECONCILIATION`'s own default-`Full` bootstrap), permission
//! has already been decided; this module's whole job is converging to that
//! already-authorized desired state, not re-deciding whether it is
//! authorized.

use std::collections::BTreeSet;
use std::path::Path;

use wht_corulix_tooling::provisioning::{self, ManagedComponentState, ProvisioningError};

use crate::registry;

/// One component's real reconciliation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentReconcileStatus {
    /// Already `Available`/owned before this call -- no redundant
    /// redownload (§21: `IDEMPOTENT_RERUN_NO_REDUNDANT_ACQUISITION=YES`).
    AlreadyReady,
    /// Not owned before this call; real acquisition just succeeded.
    Acquired,
    /// This component has no real manifest on this host's own platform
    /// (e.g. `gnu-link-runtime` on Windows) -- honestly reported, never
    /// silently dropped from the report (§59).
    NotApplicableOnThisPlatform,
    /// Real acquisition was attempted and failed. `desired`'s own
    /// [`ReconcileReport::ready`] is `false` whenever any entry is this
    /// variant -- `FULL` is `READY` only if every mandatory applicable
    /// component in `desired` is genuinely owned (§30).
    Failed(ProvisioningError),
    /// `id` is not a real registered component at all -- this reconciler
    /// received a `desired` set it did not itself compute from
    /// [`registry::REGISTRY`]/[`crate::groups`]. Reported, never silently
    /// skipped or treated as success.
    UnknownComponent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentReconcileResult {
    pub id: String,
    pub status: ComponentReconcileStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    pub results: Vec<ComponentReconcileResult>,
}

impl ReconcileReport {
    /// `true` iff every component in `desired` reached a genuinely-owned or
    /// honestly-not-applicable state -- `AlreadyReady`/`Acquired`/
    /// `NotApplicableOnThisPlatform` only. A single `Failed`/`UnknownComponent`
    /// makes the whole desired set not-ready, never a partial/best-effort
    /// success (§30).
    #[must_use]
    pub fn ready(&self) -> bool {
        self.results.iter().all(|result| {
            matches!(
                result.status,
                ComponentReconcileStatus::AlreadyReady
                    | ComponentReconcileStatus::Acquired
                    | ComponentReconcileStatus::NotApplicableOnThisPlatform
            )
        })
    }
}

/// Orders `desired` so every component's own registry-declared dependencies
/// are processed before it -- Kahn-style: repeatedly take every remaining
/// id whose dependencies (restricted to `desired` itself; a dependency not
/// in `desired` at all is assumed already satisfied elsewhere and does not
/// gate ordering) are already placed. This registry has no dependency cycle
/// (proved by `registry::tests`/`groups::tests` never needing one), so this
/// always terminates via the ordinary branch; the cycle-guard fallback below
/// exists only so a future registry regression cannot hang this reconciler.
fn dependency_ordered(desired: &BTreeSet<String>) -> Vec<String> {
    let mut ordered: Vec<String> = Vec::with_capacity(desired.len());
    let mut remaining: Vec<String> = desired.iter().cloned().collect();
    while !remaining.is_empty() {
        let mut progressed = false;
        remaining.retain(|id| {
            let ready = registry::find(id).is_none_or(|entry| {
                entry.dependencies.iter().all(|dependency| {
                    !desired.contains(*dependency)
                        || ordered.iter().any(|placed| placed == dependency)
                })
            });
            if ready {
                ordered.push(id.clone());
                progressed = true;
            }
            !ready
        });
        if !progressed {
            ordered.append(&mut remaining);
            break;
        }
    }
    ordered
}

/// The one component whose real acquisition is not the generic download
/// pipeline -- see this module's own doc comment.
const GOPLS_ID: &str = "gopls";
const GOPLS_COMPILER_ID: &str = "go-semantic-runtime";

async fn reconcile_one(root: &Path, id: &str) -> ComponentReconcileStatus {
    let Some(entry) = registry::find(id) else {
        return ComponentReconcileStatus::UnknownComponent;
    };
    let Some(manifest) = entry.manifest_for_host() else {
        return ComponentReconcileStatus::NotApplicableOnThisPlatform;
    };
    let (state, _) = provisioning::resolve_owned_managed_component(root, &manifest);
    if state == ManagedComponentState::Available {
        return ComponentReconcileStatus::AlreadyReady;
    }
    let outcome = if id == GOPLS_ID {
        let Some(compiler_manifest) =
            registry::find(GOPLS_COMPILER_ID).and_then(registry::ComponentEntry::manifest_for_host)
        else {
            return ComponentReconcileStatus::Failed(ProvisioningError::DependencyNotAvailable);
        };
        provisioning::provision_go_module_build(
            root,
            &manifest,
            &wht_corulix_lsp::managed_toolchain::GOPLS_BUILD_SOURCE_HOST_NATIVE,
            &compiler_manifest,
        )
        .await
        .map(|_| ())
    } else {
        provisioning::resolve_or_acquire_owned(root, &manifest, entry.dependencies)
            .await
            .map(|_| ())
    };
    match outcome {
        Ok(()) => ComponentReconcileStatus::Acquired,
        Err(error) => ComponentReconcileStatus::Failed(error),
    }
}

/// Converges `root` toward having every id in `desired` genuinely owned,
/// processing dependencies before dependents. `desired` is expanded to its
/// own full transitive-dependency closure first
/// ([`registry::transitive_closure`], the same expansion
/// [`crate::groups::resolve_group`] already applies) -- this reconciler
/// never assumes a caller has already hydrated dependencies itself; a bare
/// `{"rustfmt"}` reconciles `rust-semantic-runtime` too, not
/// `DependencyNotAvailable`. Never removes/uninstalls anything not in the
/// (expanded) desired set -- that is `full_uninstall`'s/profile
/// transition's own separate, explicit responsibility, not this
/// reconciler's.
pub async fn reconcile_at(root: &Path, desired: &BTreeSet<String>) -> ReconcileReport {
    let expanded = registry::transitive_closure(desired.iter().map(String::as_str));
    let mut results = Vec::with_capacity(expanded.len());
    for id in dependency_ordered(&expanded) {
        let status = reconcile_one(root, &id).await;
        results.push(ComponentReconcileResult { id, status });
    }
    ReconcileReport { results }
}

/// [`reconcile_at`] against this host's real, shared, host-wide
/// `managed_toolchain_root()` -- the canonical entry point every real
/// production caller (`corulix setup`, first-run reconciliation) uses.
pub async fn reconcile(desired: &BTreeSet<String>) -> Result<ReconcileReport, ProvisioningError> {
    let root = provisioning::managed_toolchain_root()?;
    Ok(reconcile_at(&root, desired).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("corulix-reconciler-test-{label}-{stamp}"));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn dependency_ordered_places_dependencies_before_dependents() {
        let desired: BTreeSet<String> = ["rust-analyzer", "rust-semantic-runtime", "rustfmt"]
            .into_iter()
            .map(String::from)
            .collect();
        let ordered = dependency_ordered(&desired);
        let runtime_index = ordered
            .iter()
            .position(|id| id == "rust-semantic-runtime")
            .unwrap_or_else(|| unreachable!("rust-semantic-runtime must be in the ordered list"));
        let analyzer_index = ordered
            .iter()
            .position(|id| id == "rust-analyzer")
            .unwrap_or_else(|| unreachable!("rust-analyzer must be in the ordered list"));
        let rustfmt_index = ordered
            .iter()
            .position(|id| id == "rustfmt")
            .unwrap_or_else(|| unreachable!("rustfmt must be in the ordered list"));
        assert!(runtime_index < analyzer_index);
        assert!(runtime_index < rustfmt_index);
    }

    #[tokio::test]
    async fn reconcile_at_reports_platform_inapplicable_components_honestly() {
        let root = temp_root("platform-inapplicable");
        let desired: BTreeSet<String> = if cfg!(target_os = "windows") {
            ["gnu-link-runtime"].into_iter().map(String::from).collect()
        } else {
            ["rust-semantic-runtime-gnu"]
                .into_iter()
                .map(String::from)
                .collect()
        };
        let report = reconcile_at(&root, &desired).await;
        assert_eq!(report.results.len(), 1);
        assert_eq!(
            report.results[0].status,
            ComponentReconcileStatus::NotApplicableOnThisPlatform
        );
        assert!(report.ready());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn reconcile_at_reports_unknown_component_and_is_not_ready() {
        let root = temp_root("unknown-component");
        let desired: BTreeSet<String> = ["this-component-does-not-exist"]
            .into_iter()
            .map(String::from)
            .collect();
        let report = reconcile_at(&root, &desired).await;
        assert_eq!(report.results.len(), 1);
        assert_eq!(
            report.results[0].status,
            ComponentReconcileStatus::UnknownComponent
        );
        assert!(!report.ready());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn reconcile_at_of_empty_desired_set_is_trivially_ready() {
        let root = temp_root("empty-desired");
        let report = reconcile_at(&root, &BTreeSet::new()).await;
        assert!(report.results.is_empty());
        assert!(report.ready());
        let _ = std::fs::remove_dir_all(&root);
    }
}
