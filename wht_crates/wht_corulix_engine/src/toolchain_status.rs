// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13: the real `toolchain_status` capability behind the
//! `toolchain_status` MCP tool.
//!
//! Distinct from `runtime_identity` (static product/SDK/grammar version
//! fingerprint, unconditional): this reports the compiled-in
//! [`crate::providers::ProviderSnapshot`]'s per-category availability --
//! the same data every gated capability's [`wht_corulix_core::ToolPlan`]
//! reads -- plus the managed Rust semantic runtime version this crate's own
//! [`crate::diagnostics`] module already resolves for `cargo check`/clippy.
//! Purely informational: never derives a `RiskClass`/`ToolPlan`, and never
//! itself gates anything.

use serde::Serialize;
use wht_corulix_core::{ProviderAvailability, ProviderCategory, RuntimeIdentity};

use crate::CorulixEngine;
use crate::providers::ProviderSnapshot;

/// One provider category's real, current availability.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ProviderCategoryStatus {
    pub category: ProviderCategory,
    pub availability: ProviderAvailability,
}

/// The full, real toolchain/provider status snapshot.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ToolchainStatus {
    pub runtime_identity: RuntimeIdentity,
    pub managed_rust_semantic_runtime_version: Option<String>,
    pub providers: Vec<ProviderCategoryStatus>,
}

/// Every [`ProviderCategory`] this phase reports on, in a fixed, stable
/// order -- not derived from an iterator over a private table, so this
/// list's order (and completeness) is auditable at a glance.
const REPORTED_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory::TextSearch,
    ProviderCategory::StructuralParse,
    ProviderCategory::LanguageServer,
    ProviderCategory::Formatter,
    ProviderCategory::Linter,
    ProviderCategory::TypecheckBuild,
    ProviderCategory::TestRunner,
    ProviderCategory::Runtime,
];

impl CorulixEngine {
    /// Builds the real, current toolchain/provider status report. Never
    /// fails: every field is either static build metadata or a bounded,
    /// synchronous snapshot read.
    ///
    /// P-M05-R1 fix: `TypecheckBuild`/`Linter`/`TestRunner` are overlaid
    /// with `crate::diagnostics_readiness::live_diagnostics_availability`'s
    /// real result rather than [`ProviderSnapshot::current`]'s unconditional
    /// `ProviderUnavailable` -- this report previously disagreed with
    /// `validate_change`'s own successful execution for every M05 language,
    /// discovered during the M05 qualification pass. No language parameter
    /// exists on this tool, so `None` is used -- the same convention
    /// `crate::validate_change`'s own dispatch already establishes (`None`
    /// behaves as `Rust`); `Formatter` is unaffected (still `current()`'s
    /// baseline here, exactly as before this fix -- this tool never learns
    /// a target language/file to resolve it live against, mirroring why the
    /// pre-existing F7 overlay was never applied here either).
    #[must_use]
    pub fn toolchain_status(&self) -> ToolchainStatus {
        let effective = self.effective_config(None);
        let (typecheck_build, linter, test_runner) =
            crate::diagnostics_readiness::live_diagnostics_availability(None, &effective);
        let snapshot = ProviderSnapshot::current().with_diagnostics_resolution(
            typecheck_build,
            linter,
            test_runner,
        );
        ToolchainStatus {
            runtime_identity: self.runtime_identity(),
            managed_rust_semantic_runtime_version: Some(
                crate::diagnostics::managed_runtime_version().to_string(),
            ),
            providers: REPORTED_CATEGORIES
                .iter()
                .map(|category| ProviderCategoryStatus {
                    category: *category,
                    availability: snapshot.availability(*category),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wht_corulix_workspace::WorkspaceContext;

    #[test]
    fn toolchain_status_reports_every_category_exactly_once() -> wht_corulix_core::CorulixResult<()>
    {
        let root_dir = std::env::temp_dir().join("corulix-engine-toolchain-status-test");
        let _ = std::fs::create_dir_all(&root_dir);
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = CorulixEngine::open(context);

        let status = engine.toolchain_status();
        assert_eq!(status.providers.len(), REPORTED_CATEGORIES.len());
        assert!(
            status
                .providers
                .iter()
                .any(|entry| entry.category == ProviderCategory::TextSearch
                    && entry.availability == ProviderAvailability::Available)
        );
        assert!(
            status
                .providers
                .iter()
                .any(|entry| entry.category == ProviderCategory::LanguageServer
                    && entry.availability == ProviderAvailability::ProviderUnavailable)
        );

        let _ = std::fs::remove_dir_all(&root_dir);
        Ok(())
    }
}
