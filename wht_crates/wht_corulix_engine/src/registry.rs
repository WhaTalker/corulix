// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The canonical managed-component registry (Installation-Contract-V1 §9).
//!
//! `wht_corulix_tooling::managed_runtimes`, `wht_corulix_lsp::managed_toolchain`,
//! and `wht_corulix_formatter::managed_toolchain` each declare their own
//! `&'static ManagedComponentManifest` constants -- this module is the one
//! place that aggregates all of them into a single, cross-crate, queryable
//! table. It cannot live in `wht_corulix_tooling` itself: that crate sits
//! *below* both `wht_corulix_lsp` and `wht_corulix_formatter` in the
//! dependency graph (they depend on it, never the reverse), so a table
//! naming all three crates' manifests structurally requires a crate that
//! depends on all three -- this one already does (production dependencies
//! for real provisioning/resolution, not merely for tests).
//!
//! This module is pure data plus lookup helpers. It does not provision,
//! acquire, or resolve anything itself (that remains
//! `wht_corulix_tooling::provisioning`'s and each provider crate's own
//! authority, unchanged) -- it only names, categorizes, and cross-references
//! the canonical set every install-group (`registry` §10), CLI `setup`
//! command, and reconciler consults.

use std::collections::BTreeSet;

use wht_corulix_core::ProviderCategory;
use wht_corulix_tooling::provisioning::ManagedComponentManifest;

/// One canonical managed component, platform-scoped. `linux_manifest`/
/// `windows_manifest` are `None` exactly when that platform has no real
/// manifest for this component (e.g. `gnu-link-runtime` is Linux-only,
/// `rust-semantic-runtime-gnu`/`-gnu-diagnostics` are Windows-only) --
/// `None` here means "not applicable on that platform", never "missing
/// data"; a caller must not conflate the two (§59:
/// `PLATFORM_INAPPLICABLE_COMPONENTS_CLASSIFIED_HONESTLY=YES`).
#[derive(Debug, Clone, Copy)]
pub struct ComponentEntry {
    pub id: &'static str,
    pub category: ProviderCategory,
    /// Other registry `id`s this component's real provisioning depends on
    /// (its own manifest's `additional_sources`/build-time compiler, not
    /// this struct's own invention) -- empty for a component with no
    /// managed dependency of its own.
    pub dependencies: &'static [&'static str],
    pub linux_manifest: Option<ManagedComponentManifest>,
    pub windows_manifest: Option<ManagedComponentManifest>,
}

impl ComponentEntry {
    /// This process's own host-native manifest, or `None` when this
    /// component has no real manifest for the platform this process is
    /// actually running on (a distinct, honestly-reported outcome from "the
    /// component id is unknown" -- see [`find`]).
    #[must_use]
    pub const fn manifest_for_host(&self) -> Option<ManagedComponentManifest> {
        if cfg!(target_os = "windows") {
            self.windows_manifest
        } else {
            self.linux_manifest
        }
    }

    /// Whether this component has any real manifest at all on this process's
    /// own host platform.
    #[must_use]
    pub const fn applicable_on_this_host(&self) -> bool {
        self.manifest_for_host().is_some()
    }
}

/// The complete, canonical set: 14 components, aggregated verbatim from the
/// three crates that own their real manifests. Adding a genuinely new
/// managed component elsewhere in this workspace without a corresponding
/// new entry here is itself the defect this table exists to make
/// impossible to miss (the install-group model, CLI `setup`, and reconciler
/// all enumerate this table, never a hand-maintained duplicate list).
pub const REGISTRY: &[ComponentEntry] = &[
    ComponentEntry {
        id: "node-runtime",
        category: ProviderCategory::Runtime,
        dependencies: &[],
        linux_manifest: Some(wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64),
        windows_manifest: Some(wht_corulix_tooling::managed_runtimes::NODE_24_LTS_WINDOWS_X64),
    },
    ComponentEntry {
        id: "rust-semantic-runtime",
        category: ProviderCategory::Runtime,
        dependencies: &[],
        linux_manifest: Some(
            wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64,
        ),
        windows_manifest: Some(
            wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64,
        ),
    },
    ComponentEntry {
        id: "gnu-link-runtime",
        category: ProviderCategory::Runtime,
        dependencies: &[],
        linux_manifest: Some(wht_corulix_tooling::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64),
        windows_manifest: None,
    },
    ComponentEntry {
        id: "rust-semantic-runtime-gnu",
        category: ProviderCategory::Runtime,
        dependencies: &[],
        linux_manifest: None,
        windows_manifest: Some(
            wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64,
        ),
    },
    ComponentEntry {
        id: "rust-semantic-runtime-gnu-diagnostics",
        category: ProviderCategory::Runtime,
        dependencies: &[],
        linux_manifest: None,
        windows_manifest: Some(
            wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64,
        ),
    },
    ComponentEntry {
        id: "go-semantic-runtime",
        category: ProviderCategory::Runtime,
        dependencies: &[],
        linux_manifest: Some(wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64),
        windows_manifest: Some(wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_WINDOWS_X64),
    },
    ComponentEntry {
        id: "typescript-7-native",
        category: ProviderCategory::LanguageServer,
        dependencies: &[],
        linux_manifest: Some(wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64),
        windows_manifest: Some(wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_WINDOWS_X64),
    },
    ComponentEntry {
        id: "rust-analyzer",
        category: ProviderCategory::LanguageServer,
        dependencies: &["rust-semantic-runtime"],
        linux_manifest: Some(wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64),
        windows_manifest: Some(wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_WINDOWS_X64),
    },
    ComponentEntry {
        id: "pyright",
        category: ProviderCategory::LanguageServer,
        dependencies: &["node-runtime"],
        linux_manifest: Some(wht_corulix_lsp::managed_toolchain::PYRIGHT_LINUX_X64),
        windows_manifest: Some(wht_corulix_lsp::managed_toolchain::PYRIGHT_WINDOWS_X64),
    },
    ComponentEntry {
        id: "gopls",
        category: ProviderCategory::LanguageServer,
        // Real acquisition is a Go module build (`provision_go_module_build`),
        // not the generic download pipeline -- see
        // `wht_corulix_lsp::managed_toolchain::GOPLS_LINUX_X64`'s own doc
        // comment and `wht_corulix_lsp::profile::resolve_or_acquire_gopls_via_module_build_if_allowed`.
        // `go-semantic-runtime` is still its real dependency (the build-time
        // compiler), unchanged by that different acquisition mechanism.
        dependencies: &["go-semantic-runtime"],
        linux_manifest: Some(wht_corulix_lsp::managed_toolchain::GOPLS_LINUX_X64),
        windows_manifest: Some(wht_corulix_lsp::managed_toolchain::GOPLS_WINDOWS_X64),
    },
    ComponentEntry {
        id: "typescript-language-server",
        category: ProviderCategory::LanguageServer,
        dependencies: &["node-runtime", "typescript-6-classic"],
        linux_manifest: Some(
            wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_LINUX_X64,
        ),
        windows_manifest: Some(
            wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_WINDOWS_X64,
        ),
    },
    ComponentEntry {
        id: "typescript-6-classic",
        category: ProviderCategory::LanguageServer,
        dependencies: &[],
        linux_manifest: Some(wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_LINUX_X64),
        windows_manifest: Some(wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_WINDOWS_X64),
    },
    ComponentEntry {
        id: "rustfmt",
        category: ProviderCategory::Formatter,
        dependencies: &["rust-semantic-runtime"],
        linux_manifest: Some(wht_corulix_formatter::managed_toolchain::RUSTFMT_LINUX_X64),
        windows_manifest: Some(wht_corulix_formatter::managed_toolchain::RUSTFMT_WINDOWS_X64),
    },
    ComponentEntry {
        id: "biome",
        category: ProviderCategory::Formatter,
        dependencies: &[],
        linux_manifest: Some(wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64),
        windows_manifest: Some(wht_corulix_formatter::managed_toolchain::BIOME_WINDOWS_X64),
    },
    ComponentEntry {
        id: "ruff",
        // Ruff serves both `Formatter` (`ruff format`) and `Linter`
        // (`ruff check`) -- `Formatter` here mirrors this table's existing
        // `biome` precedent (also a dual formatter/linter binary), since this
        // struct's `category` field is a single primary classification for
        // grouping/reporting, not an exhaustive per-category ledger; the real
        // per-category resolution lives in
        // `wht_corulix_engine::python_providers`/`wht_corulix_formatter::managed`,
        // independent of this table.
        category: ProviderCategory::Formatter,
        dependencies: &[],
        linux_manifest: Some(wht_corulix_tooling::managed_runtimes::RUFF_LINUX_X64),
        windows_manifest: Some(wht_corulix_tooling::managed_runtimes::RUFF_WINDOWS_X64),
    },
];

/// The one place every consumer (install groups, CLI `setup`, reconciler)
/// looks up a component by id -- never a duplicated `match`/`if` chain over
/// [`REGISTRY`] elsewhere.
#[must_use]
pub fn find(id: &str) -> Option<&'static ComponentEntry> {
    REGISTRY.iter().find(|entry| entry.id == id)
}

/// Expands `ids` to include every one of their own registry-declared
/// dependencies, recursively -- the one shared closure computation
/// [`crate::groups::resolve_group`] and [`crate::reconciler::reconcile_at`]
/// both use, so "what does group X actually need" and "what does
/// reconciling id Y actually require" can never silently diverge into two
/// different answers. An id with no registry entry is kept as-is (its
/// absence is a caller-facing concern -- `UnknownComponent`/an unrecognized
/// group name -- not something this pure expansion step resolves or drops).
#[must_use]
pub fn transitive_closure<'a>(ids: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    let mut resolved = BTreeSet::new();
    let mut stack: Vec<String> = ids.into_iter().map(String::from).collect();
    while let Some(id) = stack.pop() {
        if !resolved.insert(id.clone()) {
            continue;
        }
        if let Some(entry) = find(&id) {
            for dependency_id in entry.dependencies {
                stack.push((*dependency_id).to_string());
            }
        }
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_exactly_15_components_with_unique_ids() {
        assert_eq!(REGISTRY.len(), 15);
        let mut ids: Vec<&str> = REGISTRY.iter().map(|entry| entry.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 15, "every registry id must be unique");
    }

    #[test]
    fn every_dependency_id_resolves_to_a_real_registry_entry() {
        for entry in REGISTRY {
            for dependency_id in entry.dependencies {
                assert!(
                    find(dependency_id).is_some(),
                    "{}'s declared dependency {dependency_id:?} must itself be a registered \
                     component",
                    entry.id
                );
            }
        }
    }

    #[test]
    fn gnu_link_runtime_is_linux_only() {
        let entry = find("gnu-link-runtime").unwrap_or_else(|| unreachable!("must be registered"));
        assert!(entry.linux_manifest.is_some());
        assert!(entry.windows_manifest.is_none());
    }

    #[test]
    fn rust_semantic_runtime_gnu_variants_are_windows_only() {
        for id in [
            "rust-semantic-runtime-gnu",
            "rust-semantic-runtime-gnu-diagnostics",
        ] {
            let entry = find(id).unwrap_or_else(|| unreachable!("must be registered"));
            assert!(
                entry.linux_manifest.is_none(),
                "{id} must have no Linux manifest"
            );
            assert!(
                entry.windows_manifest.is_some(),
                "{id} must have a Windows manifest"
            );
        }
    }

    #[test]
    fn find_reports_none_for_an_unknown_id() {
        assert!(find("this-component-does-not-exist").is_none());
    }
}
