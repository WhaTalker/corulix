// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The canonical, user-facing install-group model (Installation-Contract-V1
//! §10): `corulix setup --only <group>[,<group>...]` and `--exclude` name
//! these groups, never a raw component id or an invented, unsupported
//! family. Every group name here is derived directly from
//! [`crate::registry::REGISTRY`]'s real data -- this module does not invent
//! a component the registry does not already have a manifest for.

use std::collections::BTreeSet;

use crate::registry;

/// The complete, canonical set of user-facing install groups. `typescript`
/// is a synonym for `typescript7` (the modern native backend Corulix
/// defaults new TypeScript/JavaScript workspaces to,
/// `wht_corulix_lsp::profile::typescript_profile_for_declared_major(None)`'s
/// own precedent) -- `typescript6` names the classic
/// `typescript-language-server`-backed compatibility path explicitly.
/// `javascript` is not a separate language-server family: this registry has
/// no JS-specific language server at all (the same TS7/TS6 backends serve
/// `LanguageId::JavaScript`, per that same module), so `javascript` resolves
/// to Biome plus the default TS7 backend rather than inventing a component
/// that does not exist.
pub const GROUP_NAMES: &[&str] = &[
    "rust",
    "go",
    "typescript",
    "typescript7",
    "typescript6",
    "javascript",
    "biome",
    "python",
];

/// This group's own primary component ids -- not yet expanded to include
/// their transitive dependencies (see [`resolve_group`] for that). A
/// primary id absent from this host's registry entries (i.e.
/// `manifest_for_host() == None`) is filtered out by [`resolve_group`], not
/// here -- this stays pure, platform-independent data.
fn primary_component_ids(group: &str) -> Option<&'static [&'static str]> {
    match group {
        "rust" => Some(&[
            "rust-analyzer",
            "rustfmt",
            "rust-semantic-runtime",
            "gnu-link-runtime",
            "rust-semantic-runtime-gnu",
            "rust-semantic-runtime-gnu-diagnostics",
        ]),
        "go" => Some(&["gopls", "go-semantic-runtime"]),
        "typescript" | "typescript7" => Some(&["typescript-7-native"]),
        "typescript6" => Some(&["typescript-language-server", "typescript-6-classic"]),
        "javascript" => Some(&["biome", "typescript-7-native"]),
        "biome" => Some(&["biome"]),
        // M03 Python managed-auxiliary closure: `ruff` (Formatter + Linter)
        // joins `pyright` (LanguageServer + managed TypecheckBuild CLI) under
        // the same `python` group, so `corulix setup --only python`
        // provisions the complete Python managed auxiliary set in one call.
        "python" => Some(&["pyright", "ruff"]),
        _ => None,
    }
}

/// Resolves `group` into the real, transitively-closed set of component ids:
/// every primary id `primary_component_ids` names, expanded to include
/// each one's own registry-declared dependencies (recursively).
///
/// Deliberately **not** filtered to host-applicable components here. A
/// platform-only primary id (e.g. `rust-semantic-runtime-gnu` on Linux) is
/// still returned -- exactly one place in this codebase ever classifies
/// platform-applicability, [`crate::reconciler`]'s own
/// `manifest_for_host`/`NotApplicableOnThisPlatform` handling, so a group
/// resolved on Linux and the same group resolved on Windows persist and
/// report through the identical shape: `setup --only rust` and `setup
/// --profile full` must produce the same report structure for the same
/// host, never one that silently omits ids the other reports
/// `NotApplicableOnThisPlatform` for. Returns `None` for an unrecognized
/// group name -- the caller (CLI `setup` flag parsing) is responsible for
/// rejecting that before this is ever called, this is a second,
/// defense-in-depth check, not the primary validation.
#[must_use]
pub fn resolve_group(group: &str) -> Option<BTreeSet<String>> {
    let primary = primary_component_ids(group)?;
    Some(registry::transitive_closure(primary.iter().copied()))
}

/// Resolves the union of every named group, for `--only <a>,<b>,...`.
/// `None` if any named group is unrecognized (the caller reports which).
#[must_use]
pub fn resolve_groups<'a>(groups: impl IntoIterator<Item = &'a str>) -> Option<BTreeSet<String>> {
    let mut union = BTreeSet::new();
    for group in groups {
        union.extend(resolve_group(group)?);
    }
    Some(union)
}

/// The full desired-component set for `DEFAULT_INSTALL_PROFILE=FULL`: the
/// union of every group's resolved (host-applicable) component set --
/// deliberately *not* simply "every registry entry applicable on this
/// host", so a future registry addition with no group assigned surfaces as
/// a test failure here rather than silently joining `FULL` unreviewed.
#[must_use]
pub fn full_component_set() -> BTreeSet<String> {
    resolve_groups(GROUP_NAMES.iter().copied()).unwrap_or_else(|| {
        unreachable!("every name in GROUP_NAMES must itself resolve via primary_component_ids")
    })
}

/// Why `corulix setup --only <groups> [--exclude <groups>]` was rejected
/// before any persistence/reconciliation was attempted -- validated
/// up-front so a rejected invocation never leaves partial state (Installation-
/// Contract-V1 §14: reject before persistence, never a half-applied
/// selection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionError {
    /// `only`/`exclude` names a group absent from [`GROUP_NAMES`].
    UnrecognizedGroup { requested: String },
    /// The same group name was requested by `--only` and `--exclude` at once
    /// -- a contradictory selection, rejected outright rather than silently
    /// resolved either way.
    GroupInBothOnlyAndExclude { group: String },
}

fn reject_unrecognized<'a>(
    groups: impl IntoIterator<Item = &'a str>,
) -> Result<(), SelectionError> {
    for group in groups {
        if !GROUP_NAMES.contains(&group) {
            return Err(SelectionError::UnrecognizedGroup {
                requested: group.to_string(),
            });
        }
    }
    Ok(())
}

/// Resolves `--only <groups>` (empty means "the full set") minus `--exclude
/// <groups>` into the final, persistable component-id set -- this is what
/// `corulix setup` must persist as `InstallProfile::Selective { components }`,
/// never the raw group names the user typed, since a later on-demand
/// resolution of an un-named transitive dependency (e.g.
/// `rust-semantic-runtime` under a bare `--only rust-analyzer`-style
/// selection) consults the persisted component set directly, not group
/// membership.
///
/// Validates, before computing anything, that every named group is
/// recognized and that no group appears in both `only` and `exclude`
/// (a contradictory selection is rejected outright, never silently resolved
/// either way).
///
/// **Pruning happens at the primary-id boundary, dependency completion
/// happens once, afterward.** `only`/`exclude` are resolved to each named
/// group's own *primary* ids (`primary_component_ids`, not yet
/// closure-expanded) before any subtraction, and the survivors are expanded
/// through [`registry::transitive_closure`] exactly once at the end -- the
/// same shared closure function [`reconcile_at`](crate::reconciler::reconcile_at)
/// and [`resolve_group`] both use. This makes an inconsistent/"stranded"
/// result structurally unrepresentable rather than something to detect and
/// reject after the fact: a runtime dependency shared by two groups (e.g.
/// `node-runtime`, needed by both `typescript6` and `python`) survives
/// exclusion of one of them for exactly as long as the other sibling group
/// that still needs it is kept, because the closure is recomputed from
/// whichever primaries actually remain -- never from an independently
/// closure-expanded `only` set naively subtracted by an independently
/// closure-expanded `exclude` set, which is what could produce an
/// inconsistent result in the first place.
///
/// **`--exclude <GROUP>` removes that group's own component ids wherever
/// they were contributed from, not only from that group's own membership.**
/// `biome` is both its own group and part of `javascript`'s primary set
/// (`javascript` = biome + the default TypeScript backend, since no
/// JS-specific language server exists -- see [`GROUP_NAMES`]'s own doc
/// comment); excluding `biome` removes it from `kept_primary` regardless of
/// which group(s) contributed it, so `--only javascript --exclude biome`
/// leaves only `typescript-7-native`. This is deliberate: `only`/`exclude`
/// operate on the union of primary ids the named groups contribute, not on
/// a per-group ledger that could keep the same id "excluded from one group,
/// kept via another" -- that finer-grained model would need per-group
/// provenance tracking for one real overlap in this registry, which is not
/// worth the complexity it would add.
pub fn resolve_selection(
    only: &[String],
    exclude: &[String],
) -> Result<BTreeSet<String>, SelectionError> {
    reject_unrecognized(only.iter().map(String::as_str))?;
    reject_unrecognized(exclude.iter().map(String::as_str))?;
    for group in only {
        if exclude.contains(group) {
            return Err(SelectionError::GroupInBothOnlyAndExclude {
                group: group.clone(),
            });
        }
    }

    let owned_only: Vec<&str>;
    let base_groups: &[&str] = if only.is_empty() {
        GROUP_NAMES
    } else {
        owned_only = only.iter().map(String::as_str).collect();
        &owned_only
    };
    Ok(resolve_kept_primary_closure(base_groups, exclude))
}

fn resolve_kept_primary_closure(base_groups: &[&str], exclude: &[String]) -> BTreeSet<String> {
    let mut kept_primary: BTreeSet<&'static str> = BTreeSet::new();
    for group in base_groups {
        if let Some(ids) = primary_component_ids(group) {
            kept_primary.extend(ids.iter().copied());
        }
    }
    for group in exclude {
        if let Some(ids) = primary_component_ids(group) {
            for id in ids {
                kept_primary.remove(id);
            }
        }
    }
    registry::transitive_closure(kept_primary.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_group_name_resolves() {
        for group in GROUP_NAMES {
            assert!(
                resolve_group(group).is_some(),
                "{group} must resolve via primary_component_ids"
            );
        }
    }

    #[test]
    fn unknown_group_resolves_to_none() {
        assert!(resolve_group("not-a-real-group").is_none());
    }

    #[test]
    fn rust_group_includes_its_transitive_runtime_dependency() {
        let resolved = resolve_group("rust").unwrap_or_else(|| unreachable!("rust must resolve"));
        assert!(resolved.contains("rust-analyzer"));
        assert!(resolved.contains("rustfmt"));
        assert!(resolved.contains("rust-semantic-runtime"));
    }

    #[test]
    fn rust_group_names_every_platform_variant_unfiltered() {
        // Platform-applicability filtering is exclusively the reconciler's
        // job (`NotApplicableOnThisPlatform`) -- resolve_group returns every
        // primary id in the "rust" family regardless of which host this
        // test happens to run on, so it always contains all three variants.
        let resolved = resolve_group("rust").unwrap_or_else(|| unreachable!("rust must resolve"));
        assert!(resolved.contains("gnu-link-runtime"));
        assert!(resolved.contains("rust-semantic-runtime-gnu"));
        assert!(resolved.contains("rust-semantic-runtime-gnu-diagnostics"));
    }

    #[test]
    fn typescript_is_a_synonym_for_typescript7() {
        assert_eq!(resolve_group("typescript"), resolve_group("typescript7"));
    }

    #[test]
    fn typescript6_group_includes_its_transitive_node_dependency() {
        let resolved = resolve_group("typescript6")
            .unwrap_or_else(|| unreachable!("typescript6 must resolve"));
        assert!(resolved.contains("typescript-language-server"));
        assert!(resolved.contains("typescript-6-classic"));
        assert!(resolved.contains("node-runtime"));
    }

    #[test]
    fn go_group_includes_gopls_and_its_compiler_dependency() {
        let resolved = resolve_group("go").unwrap_or_else(|| unreachable!("go must resolve"));
        assert!(resolved.contains("gopls"));
        assert!(resolved.contains("go-semantic-runtime"));
    }

    #[test]
    fn javascript_group_is_biome_plus_the_default_typescript_backend() {
        let resolved =
            resolve_group("javascript").unwrap_or_else(|| unreachable!("javascript must resolve"));
        assert!(resolved.contains("biome"));
        assert!(resolved.contains("typescript-7-native"));
    }

    #[test]
    fn python_group_includes_pyright_and_its_node_dependency() {
        let resolved =
            resolve_group("python").unwrap_or_else(|| unreachable!("python must resolve"));
        assert!(resolved.contains("pyright"));
        assert!(resolved.contains("node-runtime"));
    }

    #[test]
    fn python_group_includes_ruff() {
        let resolved =
            resolve_group("python").unwrap_or_else(|| unreachable!("python must resolve"));
        assert!(
            resolved.contains("ruff"),
            "python group must also provision ruff (Formatter + Linter)"
        );
    }

    #[test]
    fn full_component_set_covers_every_registry_entry_applicable_on_this_host() {
        let full = full_component_set();
        for entry in registry::REGISTRY {
            if entry.applicable_on_this_host() {
                assert!(
                    full.contains(entry.id),
                    "{} is applicable on this host but no group resolves it into FULL",
                    entry.id
                );
            }
        }
    }

    #[test]
    fn resolve_selection_with_no_only_defaults_to_the_full_set() {
        let resolved = resolve_selection(&[], &[]).unwrap_or_else(|error| {
            unreachable!("empty only/exclude must always resolve: {error:?}")
        });
        assert_eq!(resolved, full_component_set());
    }

    #[test]
    fn resolve_selection_only_rust_persists_the_expanded_dependency_set() {
        let only = vec!["rust".to_string()];
        let resolved = resolve_selection(&only, &[])
            .unwrap_or_else(|error| unreachable!("--only rust must resolve: {error:?}"));
        assert!(resolved.contains("rust-analyzer"));
        assert!(resolved.contains("rustfmt"));
        assert!(
            resolved.contains("rust-semantic-runtime"),
            "the expanded set persisted for --only rust must include rustfmt's own \
             transitive dependency, not just the group's primary ids"
        );
    }

    #[test]
    fn resolve_selection_rejects_an_unrecognized_group() {
        let only = vec!["not-a-real-group".to_string()];
        assert_eq!(
            resolve_selection(&only, &[]),
            Err(SelectionError::UnrecognizedGroup {
                requested: "not-a-real-group".to_string()
            })
        );
    }

    #[test]
    fn resolve_selection_rejects_a_group_in_both_only_and_exclude() {
        let only = vec!["rust".to_string()];
        let exclude = vec!["rust".to_string()];
        assert_eq!(
            resolve_selection(&only, &exclude),
            Err(SelectionError::GroupInBothOnlyAndExclude {
                group: "rust".to_string()
            })
        );
    }

    #[test]
    fn resolve_selection_keeps_a_dependency_still_needed_by_a_sibling_group() {
        // "typescript6" and "python" both transitively depend on
        // node-runtime (typescript-language-server -> node-runtime; pyright
        // -> node-runtime). Excluding "python" from the implicit full set
        // must still keep node-runtime, since typescript6 (kept) still needs
        // it -- pruning at the primary-id boundary and re-expanding once
        // means shared infrastructure survives as long as *any* kept
        // component needs it, never stranded by an unrelated exclusion.
        let exclude = vec!["python".to_string()];
        let resolved = resolve_selection(&[], &exclude)
            .unwrap_or_else(|error| unreachable!("excluding python must resolve: {error:?}"));
        assert!(
            !resolved.contains("pyright"),
            "python's own primary must be gone"
        );
        assert!(
            resolved.contains("node-runtime"),
            "node-runtime must survive because typescript6 still needs it"
        );
        assert!(resolved.contains("typescript-language-server"));
    }

    #[test]
    fn resolve_selection_excluding_a_wholly_owned_group_never_strands() {
        // "go" bundles gopls with its own compiler dependency in the same
        // group, and nothing else in this registry depends on either --
        // excluding it wholesale from the full set must succeed cleanly.
        let exclude = vec!["go".to_string()];
        let resolved = resolve_selection(&[], &exclude)
            .unwrap_or_else(|error| unreachable!("excluding go must resolve: {error:?}"));
        assert!(!resolved.contains("gopls"));
        assert!(!resolved.contains("go-semantic-runtime"));
    }

    #[test]
    fn resolve_selection_excluding_biome_also_removes_it_from_javascript() {
        // "biome" is both its own group and part of "javascript"'s primary
        // set -- excluding it removes the id wherever it was contributed
        // from, not only from its own standalone group.
        let only = vec!["javascript".to_string()];
        let exclude = vec!["biome".to_string()];
        let resolved = resolve_selection(&only, &exclude)
            .unwrap_or_else(|error| unreachable!("--only javascript --exclude biome: {error:?}"));
        assert!(!resolved.contains("biome"));
        assert!(resolved.contains("typescript-7-native"));
    }
}
