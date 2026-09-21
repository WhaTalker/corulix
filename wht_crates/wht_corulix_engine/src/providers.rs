// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! A fixed, compiled-in snapshot of which [`ProviderCategory`] this phase's
//! Engine can actually call into.
//!
//! This is deliberately **not** a `ProviderRegistry` runtime: there is no
//! `PATH` scan, no binary resolution, no process probing here -- that
//! belongs to a later phase. `TextSearch` (`wht_corulix_search`) and
//! `StructuralParse` (`wht_corulix_syntax`) are genuinely available in this
//! process today.
//!
//! `Formatter`'s [`ProviderSnapshot::current`] baseline is `ProviderUnavailable`, but is
//! no longer the full story: `Formatter` DID ship for real in a later phase
//! (`wht_corulix_formatter`'s Biome/rustfmt support), and this doc comment
//! claiming otherwise went stale without the routing pipeline ever being
//! updated to match -- exactly the
//! `F7_FORMATTER_LIVE_AVAILABILITY_NOT_OVERLAID_IN_ROUTING` defect this
//! comment now records. [`ProviderSnapshot::with_formatter_resolution`] is the F7 fix:
//! a real, live, per-call `Formatter` overlay (`crate::begin_change` is its
//! sole production caller), mirroring
//! [`ProviderSnapshot::with_language_server_resolutions`]'s shape but with a single
//! override field rather than a per-language map (see that method's own
//! doc for why one field is sufficient here).
//!
//! `Linter`/`TypecheckBuild`/`TestRunner`'s [`ProviderSnapshot::current`] baseline is
//! likewise `ProviderUnavailable`, and this doc comment previously claimed
//! "not yet implemented anywhere in the workspace" -- equally stale since
//! P11 (Rust)/P15 (Go)/P16 (TypeScript-family)/P17 (Python) real
//! diagnostics shipped (`crate::validate_change`'s per-language dispatch).
//! [`ProviderSnapshot::with_diagnostics_resolution`] is the generalized fix for this
//! same defect class (`crate::diagnostics_readiness::live_diagnostics_availability`
//! is its sole real-resolution source, `crate::begin_change` and
//! [`crate::CorulixEngine::plan_operation_for_language`] its production
//! callers) -- one overlay method for all three related categories,
//! deliberately not three separate Formatter-shaped one-offs.
//!
//! `LanguageServer` is the one category with real per-language
//! implementations today (`wht_corulix_lsp`'s rust-analyzer and gopls
//! adapters, admitted this phase -- Architecture Rule P): the category-level
//! [`ProviderSnapshot::availability`] this crate's existing `policy`/`planning`/
//! `routing` pipeline reads stays exactly what it always was (a single
//! Rust-only-shaped compiled-in constant, `ProviderUnavailable`, since none
//! of those modules are language-aware yet and rewiring them is out of this
//! phase's scope), but [`ProviderSnapshot::language_server_availability_for`] is the
//! additive, real per-[`LanguageId`] registry Section 19 of this phase's
//! mandate requires: it is genuinely fed from `wht_corulix_lsp`/
//! `wht_corulix_config` resolution results (via
//! [`ProviderSnapshot::with_language_server_resolutions`]) rather than being a second
//! hard-coded Rust-only constant.

use std::collections::HashMap;

use wht_corulix_core::{LanguageId, ProviderAvailability, ProviderCategory};

/// A snapshot of provider availability, one entry per [`ProviderCategory`],
/// plus a real per-[`LanguageId`] overlay for `LanguageServer` specifically
/// (see the module doc for why this one category carries both a
/// category-level and a language-level view).
#[derive(Debug, Clone)]
pub struct ProviderSnapshot {
    text_search: ProviderAvailability,
    structural_parse: ProviderAvailability,
    language_server: ProviderAvailability,
    formatter: ProviderAvailability,
    linter: ProviderAvailability,
    typecheck_build: ProviderAvailability,
    test_runner: ProviderAvailability,
    language_server_by_language: HashMap<LanguageId, ProviderAvailability>,
}

impl ProviderSnapshot {
    /// The real, current, compiled-in snapshot: `TextSearch` and
    /// `StructuralParse` are available (backed by `wht_corulix_search` and
    /// `wht_corulix_syntax` respectively); every other category is
    /// unavailable because no later-phase provider crate exists yet.
    #[must_use]
    pub fn current() -> Self {
        Self {
            text_search: ProviderAvailability::Available,
            structural_parse: ProviderAvailability::Available,
            language_server: ProviderAvailability::ProviderUnavailable,
            formatter: ProviderAvailability::ProviderUnavailable,
            linter: ProviderAvailability::ProviderUnavailable,
            typecheck_build: ProviderAvailability::ProviderUnavailable,
            test_runner: ProviderAvailability::ProviderUnavailable,
            language_server_by_language: HashMap::new(),
        }
    }

    /// The real, per-[`LanguageId`] `LanguageServer` availability this
    /// phase's admitted `wht_corulix_lsp` adapters actually support --
    /// distinct from [`Self::availability`]`(ProviderCategory::LanguageServer)`,
    /// which remains the single Rust-only-shaped category view the existing
    /// `policy`/`planning`/`routing` pipeline reads (see the module doc for
    /// why both views coexist). A language this snapshot has no overlay
    /// entry for is conservatively reported unavailable, never assumed
    /// supported.
    #[must_use]
    pub fn language_server_availability_for(&self, language: LanguageId) -> ProviderAvailability {
        self.language_server_by_language
            .get(&language)
            .copied()
            .unwrap_or(ProviderAvailability::ProviderUnavailable)
    }

    /// Builds a snapshot from real per-language `LanguageServer` resolution
    /// results (e.g. `wht_corulix_config::resolve_provider` calls for
    /// `rust-analyzer` and `gopls` respectively), starting from
    /// [`Self::current`] and overlaying exactly the languages a caller
    /// actually attempted to resolve. This is the genuinely-fed registry
    /// Architecture Rule P requires: unlike [`Self::current`]'s
    /// unconditional `ProviderUnavailable`, a language present here reports
    /// whatever its real resolution attempt found.
    #[must_use]
    pub fn with_language_server_resolutions(
        mut self,
        resolutions: &[(LanguageId, ProviderAvailability)],
    ) -> Self {
        for (language, availability) in resolutions {
            self.language_server_by_language
                .insert(*language, *availability);
        }
        self
    }

    /// F7 fix (`F7_FORMATTER_LIVE_AVAILABILITY_NOT_OVERLAID_IN_ROUTING`):
    /// overlays a real, live `Formatter`-category resolution result onto
    /// this snapshot's category-level view -- the production counterpart
    /// [`Self::with_language_server_resolutions`] never received for
    /// `Formatter` (see the module doc's original claim that `Formatter`
    /// "is not yet implemented anywhere in the workspace", which
    /// `wht_corulix_formatter`'s real, shipped Biome/rustfmt support made
    /// factually stale without this crate ever being updated to match).
    /// Unlike the `LanguageServer` overlay, `Formatter` carries no
    /// per-language `HashMap` here: the caller already knows exactly which
    /// single language it resolved availability for (the same `language`
    /// [`crate::routing::evaluate`] uses for its `LanguageServer` overlay
    /// check), so one override field is sufficient -- adding a second,
    /// unused per-language map would be an unjustified second truth model
    /// for a category that only ever has one relevant language per call.
    /// Starts from [`Self::current`]; a caller that never resolves
    /// `Formatter` (e.g. every pre-F7 call site) leaves this category
    /// exactly as `current()` always reported it, so `toolchain_status`'s
    /// own aggregate view and every other existing caller of
    /// [`Self::availability`]`(ProviderCategory::Formatter)` is completely
    /// unaffected by this addition.
    #[must_use]
    pub fn with_formatter_resolution(mut self, availability: ProviderAvailability) -> Self {
        self.formatter = availability;
        self
    }

    /// The generalized counterpart of [`Self::with_formatter_resolution`]
    /// for `TypecheckBuild`/`Linter`/`TestRunner` together: one overlay
    /// method for all three, fed by
    /// `crate::diagnostics_readiness::live_diagnostics_availability`'s
    /// single real-resolution source, rather than three separate
    /// Formatter-shaped one-off overlays. A caller that never resolves
    /// these categories (e.g. an intent whose policy does not require
    /// `TypecheckBuild`) leaves this snapshot exactly as [`Self::current`]
    /// always reported it.
    #[must_use]
    pub fn with_diagnostics_resolution(
        mut self,
        typecheck_build: ProviderAvailability,
        linter: ProviderAvailability,
        test_runner: ProviderAvailability,
    ) -> Self {
        self.typecheck_build = typecheck_build;
        self.linter = linter;
        self.test_runner = test_runner;
        self
    }

    /// Test-only override, used to exercise routing/planning behavior for a
    /// hypothetical future state (e.g. "if LSP were available") without
    /// this crate ever claiming that state is true in production. Starts
    /// from [`Self::current`] and overrides exactly one category.
    #[must_use]
    #[cfg(test)]
    pub fn with_override(
        mut self,
        category: ProviderCategory,
        availability: ProviderAvailability,
    ) -> Self {
        *self.slot_mut(category) = availability;
        self
    }

    /// Builds a snapshot from real Phase 6 provider-resolution results,
    /// starting from [`Self::current`] (so `TextSearch`/`StructuralParse`
    /// stay exactly what they always are) and overlaying only the
    /// externally-resolved categories a caller actually attempted to
    /// resolve. A resolution for `TextSearch`/`StructuralParse` (which
    /// `wht_corulix_config::resolve_provider` never produces --
    /// see `ReasonCode::ProviderNotExternallyResolvable`) or for any future
    /// unmodeled category is ignored rather than corrupting this snapshot's
    /// truthful in-process categories.
    ///
    /// This constructor implements no provider execution and is not yet
    /// called from any production routing/planning path -- it exists so a
    /// later phase can wire real resolution results in without this crate
    /// inventing a second, ad-hoc snapshot-construction API when that phase
    /// arrives. It is exercised by this module's own tests today.
    #[must_use]
    pub fn from_resolutions(resolutions: &[wht_corulix_config::ProviderResolution]) -> Self {
        let mut snapshot = Self::current();
        for resolution in resolutions {
            match resolution.category {
                ProviderCategory::LanguageServer => {
                    snapshot.language_server = resolution.availability;
                }
                ProviderCategory::Formatter => {
                    snapshot.formatter = resolution.availability;
                }
                ProviderCategory::Linter => {
                    snapshot.linter = resolution.availability;
                }
                ProviderCategory::TypecheckBuild => {
                    snapshot.typecheck_build = resolution.availability;
                }
                ProviderCategory::TestRunner => {
                    snapshot.test_runner = resolution.availability;
                }
                _ => {}
            }
        }
        snapshot
    }

    #[must_use]
    pub fn availability(&self, category: ProviderCategory) -> ProviderAvailability {
        match category {
            ProviderCategory::TextSearch => self.text_search,
            ProviderCategory::StructuralParse => self.structural_parse,
            ProviderCategory::LanguageServer => self.language_server,
            ProviderCategory::Formatter => self.formatter,
            ProviderCategory::Linter => self.linter,
            ProviderCategory::TypecheckBuild => self.typecheck_build,
            ProviderCategory::TestRunner => self.test_runner,
            // `ProviderCategory` is `#[non_exhaustive]`: a future category
            // this snapshot has no field for yet is conservatively reported
            // unavailable rather than failing to compile downstream.
            _ => ProviderAvailability::ProviderUnavailable,
        }
    }

    #[cfg(test)]
    fn slot_mut(&mut self, category: ProviderCategory) -> &mut ProviderAvailability {
        match category {
            ProviderCategory::TextSearch => &mut self.text_search,
            ProviderCategory::StructuralParse => &mut self.structural_parse,
            ProviderCategory::LanguageServer => &mut self.language_server,
            ProviderCategory::Formatter => &mut self.formatter,
            ProviderCategory::Linter => &mut self.linter,
            ProviderCategory::TypecheckBuild => &mut self.typecheck_build,
            ProviderCategory::TestRunner => &mut self.test_runner,
            _ => unreachable!("test-only override used with an unmodeled ProviderCategory"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_snapshot_reports_search_and_syntax_available() {
        let snapshot = ProviderSnapshot::current();
        assert_eq!(
            snapshot.availability(ProviderCategory::TextSearch),
            ProviderAvailability::Available
        );
        assert_eq!(
            snapshot.availability(ProviderCategory::StructuralParse),
            ProviderAvailability::Available
        );
    }

    #[test]
    fn current_snapshot_never_reports_future_providers_available() {
        let snapshot = ProviderSnapshot::current();
        for category in [
            ProviderCategory::LanguageServer,
            ProviderCategory::Formatter,
            ProviderCategory::Linter,
            ProviderCategory::TypecheckBuild,
            ProviderCategory::TestRunner,
        ] {
            assert_eq!(
                snapshot.availability(category),
                ProviderAvailability::ProviderUnavailable,
                "{category:?} must not be reported available until its own phase lands"
            );
        }
    }

    #[test]
    fn override_changes_exactly_one_category() {
        let snapshot = ProviderSnapshot::current().with_override(
            ProviderCategory::LanguageServer,
            ProviderAvailability::Available,
        );
        assert_eq!(
            snapshot.availability(ProviderCategory::LanguageServer),
            ProviderAvailability::Available
        );
        // Every other category is untouched by the override.
        assert_eq!(
            snapshot.availability(ProviderCategory::Formatter),
            ProviderAvailability::ProviderUnavailable
        );
        assert_eq!(
            snapshot.availability(ProviderCategory::TextSearch),
            ProviderAvailability::Available
        );
    }

    #[test]
    fn from_resolutions_overlays_only_externally_resolved_categories() {
        let resolutions = vec![wht_corulix_config::ProviderResolution {
            category: ProviderCategory::Formatter,
            availability: ProviderAvailability::Available,
            resolved_path: None,
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
            reason: None,
        }];
        let snapshot = ProviderSnapshot::from_resolutions(&resolutions);
        assert_eq!(
            snapshot.availability(ProviderCategory::Formatter),
            ProviderAvailability::Available
        );
        // Untouched categories -- including the in-process ones -- remain
        // exactly what `current()` always reports.
        assert_eq!(
            snapshot.availability(ProviderCategory::TextSearch),
            ProviderAvailability::Available
        );
        assert_eq!(
            snapshot.availability(ProviderCategory::Linter),
            ProviderAvailability::ProviderUnavailable
        );
    }

    #[test]
    fn from_resolutions_with_no_input_matches_current() {
        let snapshot = ProviderSnapshot::from_resolutions(&[]);
        for category in [
            ProviderCategory::TextSearch,
            ProviderCategory::StructuralParse,
            ProviderCategory::LanguageServer,
            ProviderCategory::Formatter,
            ProviderCategory::Linter,
            ProviderCategory::TypecheckBuild,
            ProviderCategory::TestRunner,
        ] {
            assert_eq!(
                snapshot.availability(category),
                ProviderSnapshot::current().availability(category)
            );
        }
    }

    #[test]
    fn language_server_availability_defaults_to_unavailable_for_every_language() {
        let snapshot = ProviderSnapshot::current();
        for language in [
            wht_corulix_core::LanguageId::Rust,
            wht_corulix_core::LanguageId::Go,
            wht_corulix_core::LanguageId::TypeScript,
            wht_corulix_core::LanguageId::Python,
        ] {
            assert_eq!(
                snapshot.language_server_availability_for(language),
                ProviderAvailability::ProviderUnavailable
            );
        }
    }

    #[test]
    fn with_language_server_resolutions_overlays_only_named_languages() {
        let snapshot = ProviderSnapshot::current().with_language_server_resolutions(&[
            (
                wht_corulix_core::LanguageId::Rust,
                ProviderAvailability::Available,
            ),
            (
                wht_corulix_core::LanguageId::Go,
                ProviderAvailability::Available,
            ),
        ]);
        assert_eq!(
            snapshot.language_server_availability_for(wht_corulix_core::LanguageId::Rust),
            ProviderAvailability::Available
        );
        assert_eq!(
            snapshot.language_server_availability_for(wht_corulix_core::LanguageId::Go),
            ProviderAvailability::Available
        );
        // A language never resolved stays conservatively unavailable.
        assert_eq!(
            snapshot.language_server_availability_for(wht_corulix_core::LanguageId::Python),
            ProviderAvailability::ProviderUnavailable
        );
        // The pre-existing, category-level view this crate's `policy`/
        // `planning`/`routing` pipeline reads is completely unaffected by
        // the per-language overlay -- Section 19 requires this coexistence,
        // not a replacement of the Phase-4-tested category API.
        assert_eq!(
            snapshot.availability(ProviderCategory::LanguageServer),
            ProviderAvailability::ProviderUnavailable
        );
    }
}
