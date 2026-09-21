// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P-M05-R1 fix: a single, generic, synchronous live-availability check for
//! the three provider categories [`crate::providers::ProviderSnapshot`]
//! reported unconditionally `ProviderUnavailable` (`TypecheckBuild`,
//! `Linter`, `TestRunner`) despite real, shipped implementations existing
//! for all four M05 languages (P11 Rust, P15 Go, P16 TypeScript-family, P17
//! Python) -- the same defect class the pre-existing "F7 fix"
//! (`crate::providers::ProviderSnapshot::with_formatter_resolution`)
//! already found and closed for `Formatter` alone.
//!
//! # Why this is generic, not three copy-pasted Formatter overlays
//!
//! Every one of the four languages' real diagnostics dispatch
//! (`crate::validate_change`) resolves its `TypecheckBuild`/`Linter`
//! managed component via exactly one shared primitive:
//! [`wht_corulix_tooling::provisioning::resolve_owned_managed_component`].
//! This module calls that same primitive for the same manifests, never
//! duplicating any invocation/detection logic of its own -- it answers
//! "is the component present and valid" without ever spawning `cargo`/`go`/
//! `tsc`/`pyright`/`clippy`/`ruff`/`biome`.
//!
//! # Deliberate, disclosed scope narrowing
//!
//! - This checks the `CORULIX_MANAGED` tier only, never a `HOST_ONLY`
//!   fallback (unlike `resolve_formatter_availability`, which already
//!   correctly handles both tiers for `Formatter` and is left untouched by
//!   this fix -- see [`crate::begin_change`]'s own doc comment). A rare
//!   `HOST_ONLY`-resolved Python `pyright`/`pytest` is reported unavailable
//!   here even when it would actually work; this is the fail-closed
//!   direction (never fabricates `Available`), never the dangerous one.
//! - `TestRunner` is always [`wht_corulix_core::ToolApplicability::Optional`]
//!   in every policy entry today, so its value here never changes any
//!   [`crate::routing::evaluate`] `Blocked`/`Unexecutable` verdict -- it
//!   exists only so `toolchain_status`'s own report stops being
//!   unconditionally stale for that category too.
//! - Python's `TestRunner` (`pytest`) is `HOST_ONLY`-only by ADR 0011 §5
//!   design (no managed tier exists for it at all -- see
//!   `crate::python_providers`'s own module doc), so this module reports it
//!   exactly as [`crate::providers::ProviderSnapshot::current`] always has
//!   (`ProviderUnavailable`) rather than fabricating a managed-tier check
//!   that cannot exist for that language/category pair.
//! - TypeScript's declared major (6 vs. 7) is only known once
//!   `validate_change_typescript` reads the target project's own
//!   `package.json` -- unavailable at `begin_change`/`plan_operation` time.
//!   This module checks the default/majority path (`TYPESCRIPT_7_HOST_NATIVE`)
//!   only; a project that declares TypeScript 6 may see a availability
//!   report that does not match its own real TS6 state. Disclosed, not
//!   silently assumed.

use wht_corulix_core::{ExecutionClass, LanguageId, ProviderAvailability};

fn available_if(is_available: bool) -> ProviderAvailability {
    if is_available {
        ProviderAvailability::Available
    } else {
        ProviderAvailability::ProviderUnavailable
    }
}

fn component_present(
    managed_root: &std::path::Path,
    manifest: &wht_corulix_tooling::provisioning::ManagedComponentManifest,
) -> bool {
    let (state, _path) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component(managed_root, manifest);
    state == wht_corulix_tooling::provisioning::ManagedComponentState::Available
}

/// The real, live `(typecheck_build, linter, test_runner)` availability for
/// `language`'s M05 diagnostics providers -- fail-closed on any unresolved
/// precondition (untrusted workspace, unresolvable managed root, missing
/// component), never fabricating `Available` from an unknown state (Section
/// 7's own requirement).
///
/// `None` language mirrors [`crate::validate_change`]'s own established
/// convention (`None | Some(Rust) => validate_change_rust`, see that
/// module's dispatch `match`): checked as Rust.
#[must_use]
pub(crate) fn live_diagnostics_availability(
    language: Option<LanguageId>,
    effective: &wht_corulix_config::EffectiveConfig,
) -> (
    ProviderAvailability,
    ProviderAvailability,
    ProviderAvailability,
) {
    let unavailable = (
        ProviderAvailability::ProviderUnavailable,
        ProviderAvailability::ProviderUnavailable,
        ProviderAvailability::ProviderUnavailable,
    );
    if !effective.is_execution_class_allowed(ExecutionClass::TrustedWorkspaceExecution) {
        return unavailable;
    }
    let Ok(managed_root) = wht_corulix_tooling::provisioning::managed_toolchain_root() else {
        return unavailable;
    };

    match language {
        None | Some(LanguageId::Rust) => {
            let typecheck = crate::diagnostics::resolve_runtime(&managed_root).is_ok();
            let linter = typecheck
                && crate::diagnostics::resolve_clippy_binaries(
                    &managed_root,
                    &crate::diagnostics::rust_semantic_runtime_host_native(),
                )
                .is_ok();
            (
                available_if(typecheck),
                available_if(linter),
                available_if(typecheck),
            )
        }
        Some(LanguageId::Go) => {
            let present = component_present(
                &managed_root,
                &wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_HOST_NATIVE,
            );
            (
                available_if(present),
                available_if(present),
                available_if(present),
            )
        }
        Some(LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript) => {
            let typecheck = component_present(
                &managed_root,
                &wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_HOST_NATIVE,
            );
            let linter = component_present(
                &managed_root,
                &wht_corulix_formatter::managed_toolchain::BIOME_HOST_NATIVE,
            );
            let node_present = component_present(
                &managed_root,
                &wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
            );
            (
                available_if(typecheck),
                available_if(linter),
                available_if(typecheck && node_present),
            )
        }
        Some(LanguageId::Python) => {
            let node_present = component_present(
                &managed_root,
                &wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
            );
            let typecheck = node_present
                && component_present(
                    &managed_root,
                    &wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE,
                );
            let linter = component_present(
                &managed_root,
                &crate::python_providers::managed_ruff_manifest(),
            );
            // `TestRunner` (pytest) is `HOST_ONLY`-only for Python (ADR
            // 0011 §5) -- no managed tier exists to check here, so this
            // stays exactly `ProviderSnapshot::current()`'s own value
            // (`ProviderUnavailable`), never fabricated.
            (
                available_if(typecheck),
                available_if(linter),
                ProviderAvailability::ProviderUnavailable,
            )
        }
        // `LanguageId` is `#[non_exhaustive]`: a future language this
        // module has no real resolver for yet is conservatively reported
        // unavailable, never assumed supported.
        Some(_) => unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn untrusted_effective() -> wht_corulix_config::EffectiveConfig {
        wht_corulix_config::EffectiveConfig::derive(
            &wht_corulix_config::HostConfig::default(),
            &wht_corulix_config::RepositoryHints::default(),
            &wht_corulix_config::RequestOptions::default(),
        )
    }

    fn trusted_effective() -> wht_corulix_config::EffectiveConfig {
        let host = wht_corulix_config::HostConfig {
            workspace_trust: wht_corulix_core::WorkspaceTrust::Trusted,
            allow_trusted_workspace_execution: true,
            ..wht_corulix_config::HostConfig::default()
        };
        wht_corulix_config::EffectiveConfig::derive(
            &host,
            &wht_corulix_config::RepositoryHints::default(),
            &wht_corulix_config::RequestOptions::default(),
        )
    }

    /// R5: an untrusted workspace must never report `Available`, regardless
    /// of what is actually installed on this host -- fail-closed on the
    /// trust precondition alone, before any filesystem check runs.
    #[test]
    fn untrusted_workspace_never_reports_available_for_any_language() {
        for language in [
            None,
            Some(LanguageId::Rust),
            Some(LanguageId::Go),
            Some(LanguageId::TypeScript),
            Some(LanguageId::Tsx),
            Some(LanguageId::JavaScript),
            Some(LanguageId::Python),
        ] {
            let (typecheck, linter, test_runner) =
                live_diagnostics_availability(language, &untrusted_effective());
            assert_eq!(typecheck, ProviderAvailability::ProviderUnavailable);
            assert_eq!(linter, ProviderAvailability::ProviderUnavailable);
            assert_eq!(test_runner, ProviderAvailability::ProviderUnavailable);
        }
    }

    /// R4/R5: a trusted workspace whose managed root cannot be resolved at
    /// all (simulated via an environment this test does not control, so
    /// instead this proves the narrower, always-true invariant: every
    /// language's result is one of the two defined variants, never a
    /// silently-fabricated third state) never panics and never returns
    /// anything but a real `ProviderAvailability` variant.
    #[test]
    fn trusted_workspace_returns_a_real_availability_variant_for_every_language() {
        for language in [
            None,
            Some(LanguageId::Rust),
            Some(LanguageId::Go),
            Some(LanguageId::TypeScript),
            Some(LanguageId::Python),
        ] {
            let (typecheck, linter, test_runner) =
                live_diagnostics_availability(language, &trusted_effective());
            for value in [typecheck, linter, test_runner] {
                assert!(matches!(
                    value,
                    ProviderAvailability::Available | ProviderAvailability::ProviderUnavailable
                ));
            }
        }
    }

    /// Python's `TestRunner` has no managed tier (ADR 0011 §5): must always
    /// stay `ProviderUnavailable` from this function, trusted or not, never
    /// fabricated as `Available`.
    #[test]
    fn python_test_runner_is_never_reported_available_managed() {
        for effective in [untrusted_effective(), trusted_effective()] {
            let (_, _, test_runner) =
                live_diagnostics_availability(Some(LanguageId::Python), &effective);
            assert_eq!(test_runner, ProviderAvailability::ProviderUnavailable);
        }
    }

    /// `None` language must behave exactly like `Some(Rust)` (the
    /// established `validate_change` dispatch convention this module
    /// mirrors).
    #[test]
    fn none_language_matches_rust_dispatch() {
        for effective in [untrusted_effective(), trusted_effective()] {
            assert_eq!(
                live_diagnostics_availability(None, &effective),
                live_diagnostics_availability(Some(LanguageId::Rust), &effective)
            );
        }
    }
}
