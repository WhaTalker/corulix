// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Resolves a policy entry's tool requirements against a [`ProviderSnapshot`]
//! into a [`PlanExecutability`] verdict.
//!
//! This is the one place `ToolApplicability::Required` actually matters at
//! runtime: a `Required` category that is not [`ProviderAvailability::Available`]
//! makes the whole plan `Unexecutable` outright. `Optional`/`Supporting`/
//! `NotApplicable` requirements never affect executability -- their absence
//! can only narrow evidence coverage, which is a concern for a later phase's
//! Evidence model, not this one's executability verdict. Crucially, this
//! module never touches a [`crate::policy::PolicyEntry`]'s `gates` list: a
//! required gate is policy-table data, fixed regardless of provider
//! availability, so "required provider unavailable" and "required gate
//! removed" are structurally two different things and this module only ever
//! computes the former.

use crate::providers::ProviderSnapshot;
use wht_corulix_core::{
    LanguageId, PlanExecutability, ProviderAvailability, ProviderCategory, ReasonCode,
    ToolApplicability, ToolRequirement,
};

/// Determines whether `requirements` can actually be executed against
/// `snapshot`. The first `Required` requirement whose category is not
/// `Available` makes the whole plan unexecutable; if every `Required`
/// requirement is available (including the vacuous case of zero `Required`
/// requirements), the plan is executable.
///
/// `language`, when `Some`, makes a `ProviderCategory::LanguageServer`
/// requirement check `snapshot.language_server_availability_for(language)`
/// (Architecture Rule P, Section 19: `LanguageServer` is no longer modeled
/// as rust-analyzer-only in the live routing path) instead of the
/// category-level `snapshot.availability(LanguageServer)`. `language: None`
/// (every pre-existing caller) preserves the exact category-level check
/// this module has always performed -- Phase 4's required-provider-
/// unavailable coverage is unaffected by this addition.
#[must_use]
pub fn evaluate(
    requirements: &[ToolRequirement],
    snapshot: &ProviderSnapshot,
    language: Option<LanguageId>,
) -> PlanExecutability {
    for requirement in requirements {
        if requirement.applicability != ToolApplicability::Required {
            continue;
        }
        let availability = match (requirement.category, language) {
            (ProviderCategory::LanguageServer, Some(language)) => {
                snapshot.language_server_availability_for(language)
            }
            _ => snapshot.availability(requirement.category),
        };
        if availability != ProviderAvailability::Available {
            return PlanExecutability::Unexecutable {
                reason: ReasonCode::RequiredProviderUnavailable,
            };
        }
    }
    PlanExecutability::Executable
}

#[cfg(test)]
mod tests {
    use super::*;
    use wht_corulix_core::{AuthorityRole, ProviderAvailability, ProviderCategory};

    fn requirement(
        category: ProviderCategory,
        applicability: ToolApplicability,
    ) -> ToolRequirement {
        ToolRequirement {
            category,
            applicability,
            authority: AuthorityRole::Authoritative,
        }
    }

    #[test]
    fn no_requirements_is_executable() {
        let snapshot = ProviderSnapshot::current();
        assert_eq!(
            evaluate(&[], &snapshot, None),
            PlanExecutability::Executable
        );
    }

    #[test]
    fn required_available_provider_is_executable() {
        let snapshot = ProviderSnapshot::current();
        let requirements = [requirement(
            ProviderCategory::TextSearch,
            ToolApplicability::Required,
        )];
        assert_eq!(
            evaluate(&requirements, &snapshot, None),
            PlanExecutability::Executable
        );
    }

    #[test]
    fn required_unavailable_provider_is_unexecutable_with_reason() {
        let snapshot = ProviderSnapshot::current();
        let requirements = [requirement(
            ProviderCategory::LanguageServer,
            ToolApplicability::Required,
        )];
        assert!(matches!(
            evaluate(&requirements, &snapshot, None),
            PlanExecutability::Unexecutable {
                reason: ReasonCode::RequiredProviderUnavailable
            }
        ));
    }

    #[test]
    fn optional_unavailable_provider_does_not_block_execution() {
        let snapshot = ProviderSnapshot::current();
        let requirements = [requirement(
            ProviderCategory::LanguageServer,
            ToolApplicability::Optional,
        )];
        assert_eq!(
            evaluate(&requirements, &snapshot, None),
            PlanExecutability::Executable
        );
    }

    #[test]
    fn supporting_unavailable_provider_does_not_block_execution() {
        let snapshot = ProviderSnapshot::current();
        let requirements = [requirement(
            ProviderCategory::Formatter,
            ToolApplicability::Supporting,
        )];
        assert_eq!(
            evaluate(&requirements, &snapshot, None),
            PlanExecutability::Executable
        );
    }

    #[test]
    fn required_provider_becoming_available_flips_executability() {
        let snapshot = ProviderSnapshot::current().with_override(
            ProviderCategory::LanguageServer,
            ProviderAvailability::Available,
        );
        let requirements = [requirement(
            ProviderCategory::LanguageServer,
            ToolApplicability::Required,
        )];
        assert_eq!(
            evaluate(&requirements, &snapshot, None),
            PlanExecutability::Executable
        );
    }

    #[test]
    fn one_unavailable_required_requirement_blocks_even_with_other_satisfied_requirements() {
        let snapshot = ProviderSnapshot::current();
        let requirements = [
            requirement(ProviderCategory::TextSearch, ToolApplicability::Required),
            requirement(ProviderCategory::Formatter, ToolApplicability::Required),
        ];
        assert!(matches!(
            evaluate(&requirements, &snapshot, None),
            PlanExecutability::Unexecutable {
                reason: ReasonCode::RequiredProviderUnavailable
            }
        ));
    }

    #[test]
    fn language_aware_evaluation_checks_the_named_language_not_the_category() {
        use wht_corulix_core::LanguageId;
        let snapshot = ProviderSnapshot::current()
            .with_language_server_resolutions(&[(LanguageId::Go, ProviderAvailability::Available)]);
        let requirements = [requirement(
            ProviderCategory::LanguageServer,
            ToolApplicability::Required,
        )];
        // Go resolved -> executable.
        assert_eq!(
            evaluate(&requirements, &snapshot, Some(LanguageId::Go)),
            PlanExecutability::Executable
        );
        // Rust never resolved -> unexecutable, even though Go is available
        // in the same snapshot.
        assert!(matches!(
            evaluate(&requirements, &snapshot, Some(LanguageId::Rust)),
            PlanExecutability::Unexecutable {
                reason: ReasonCode::RequiredProviderUnavailable
            }
        ));
        // No language supplied -> falls back to the category-level check,
        // which the per-language overlay never touches.
        assert!(matches!(
            evaluate(&requirements, &snapshot, None),
            PlanExecutability::Unexecutable {
                reason: ReasonCode::RequiredProviderUnavailable
            }
        ));
    }
}
