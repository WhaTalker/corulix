// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic [`ToolPlan`] construction: the single function that
//! combines [`crate::policy`]'s fixed table with [`crate::routing`]'s
//! executability verdict against a [`ProviderSnapshot`].
//!
//! `plan_operation` is a pure function of its three inputs (`intent`,
//! `scope`, `snapshot`) -- no I/O, no process spawning, no randomness, no
//! AI/LLM routing. The same inputs always produce a `ToolPlan` equal by
//! value (`ToolPlan` derives `PartialEq`), which is exactly the
//! determinism the mandate requires and which the test module below proves
//! directly.

use crate::policy::{TargetScope, derive_risk_class, policy_entry};
use crate::providers::ProviderSnapshot;
use crate::routing;
use wht_corulix_core::{
    LanguageId, OperationIntent, PlanExecutability, ReasonCode, RiskClass, ToolPlan,
};

/// Derives a complete, deterministic [`ToolPlan`] for `intent` under the
/// given workspace `scope`, evaluated against `snapshot`'s current provider
/// availability. `language`, when `Some`, makes a required `LanguageServer`
/// requirement check that specific language's real availability (Section 19
/// of the Phase 7B mandate: the live routing path is no longer
/// `LanguageServer == rust-analyzer`-shaped) rather than the single
/// category-level view -- see [`routing::evaluate`]. `language: None`
/// preserves this function's exact pre-existing behavior.
#[must_use]
pub fn plan_operation(
    intent: OperationIntent,
    scope: TargetScope,
    snapshot: &ProviderSnapshot,
    language: Option<LanguageId>,
) -> ToolPlan {
    let Some(entry) = policy_entry(intent) else {
        // Only reachable for a hypothetical future `OperationIntent`
        // variant this phase's policy table has no entry for yet (see
        // `policy::policy_entry`'s own docs) -- fail closed rather than
        // borrowing another intent's policy or guessing at one.
        return ToolPlan {
            intent,
            mutation_kind: None,
            risk_class: Some(RiskClass::Critical),
            requirements: Vec::new(),
            gates: Vec::new(),
            executability: PlanExecutability::Unexecutable {
                reason: ReasonCode::PreconditionNotMet,
            },
        };
    };
    let risk_class = derive_risk_class(entry.base_risk, scope);
    let executability = routing::evaluate(entry.requirements, snapshot, language);

    ToolPlan {
        intent,
        mutation_kind: Some(entry.mutation_kind),
        risk_class: Some(risk_class),
        requirements: entry.requirements.to_vec(),
        gates: entry.gates.to_vec(),
        executability,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wht_corulix_core::{PlanExecutability, ProviderAvailability, ProviderCategory, ReasonCode};

    #[test]
    fn identical_inputs_produce_an_identical_plan() {
        let snapshot = ProviderSnapshot::current();
        let a = plan_operation(
            OperationIntent::TextSearch,
            TargetScope::SingleRoot,
            &snapshot,
            None,
        );
        let b = plan_operation(
            OperationIntent::TextSearch,
            TargetScope::SingleRoot,
            &snapshot,
            None,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn text_search_is_executable_with_the_current_snapshot() {
        let snapshot = ProviderSnapshot::current();
        let plan = plan_operation(
            OperationIntent::TextSearch,
            TargetScope::SingleRoot,
            &snapshot,
            None,
        );
        assert_eq!(plan.executability, PlanExecutability::Executable);
        assert_eq!(plan.gates.len(), 1);
    }

    #[test]
    fn semantic_definition_is_unexecutable_with_the_current_snapshot() {
        // LanguageServer is unconditionally unavailable in this phase, so
        // any operation that requires it is truthfully Unexecutable --
        // this is the expected, correct behavior the mandate calls for,
        // not a defect to work around.
        let snapshot = ProviderSnapshot::current();
        let plan = plan_operation(
            OperationIntent::SemanticDefinition,
            TargetScope::SingleRoot,
            &snapshot,
            None,
        );
        assert!(matches!(
            plan.executability,
            PlanExecutability::Unexecutable {
                reason: ReasonCode::RequiredProviderUnavailable
            }
        ));
        // The required gates remain present in the plan even though it is
        // unexecutable -- a required gate never disappears because its
        // provider is unavailable.
        assert!(!plan.gates.is_empty());
    }

    #[test]
    fn semantic_definition_becomes_executable_once_lsp_is_available() {
        let snapshot = ProviderSnapshot::current().with_override(
            ProviderCategory::LanguageServer,
            ProviderAvailability::Available,
        );
        let plan = plan_operation(
            OperationIntent::SemanticDefinition,
            TargetScope::SingleRoot,
            &snapshot,
            None,
        );
        assert_eq!(plan.executability, PlanExecutability::Executable);
    }

    #[test]
    fn multi_root_scope_raises_the_planned_risk_class() {
        let snapshot = ProviderSnapshot::current();
        let single = plan_operation(
            OperationIntent::TextSearch,
            TargetScope::SingleRoot,
            &snapshot,
            None,
        );
        let multi = plan_operation(
            OperationIntent::TextSearch,
            TargetScope::MultiRoot { root_count: 3 },
            &snapshot,
            None,
        );
        assert!(multi.risk_class > single.risk_class);
    }

    #[test]
    fn single_root_and_multi_root_both_produce_a_plan_for_every_intent() {
        let snapshot = ProviderSnapshot::current();
        for intent in OperationIntent::ALL {
            let single = plan_operation(*intent, TargetScope::SingleRoot, &snapshot, None);
            let multi = plan_operation(
                *intent,
                TargetScope::MultiRoot { root_count: 4 },
                &snapshot,
                None,
            );
            assert_eq!(single.intent, *intent);
            assert_eq!(multi.intent, *intent);
        }
    }

    #[test]
    fn source_delete_plan_includes_post_audit_gate() {
        let snapshot = ProviderSnapshot::current();
        let plan = plan_operation(
            OperationIntent::SourceDelete,
            TargetScope::SingleRoot,
            &snapshot,
            None,
        );
        assert!(
            plan.gates
                .iter()
                .any(|g| g.gate == wht_corulix_core::GateId::PostAudit)
        );
    }

    #[test]
    fn plan_never_contains_a_client_supplied_risk_class() {
        // Structural proof, not just behavioral: `plan_operation` has no
        // `RiskClass` parameter at all, so there is no code path through
        // which a caller could inject an arbitrary risk value -- the only
        // way `risk_class` is ever populated is via `derive_risk_class`.
        let snapshot = ProviderSnapshot::current();
        let plan = plan_operation(
            OperationIntent::TextSearch,
            TargetScope::SingleRoot,
            &snapshot,
            None,
        );
        // TextSearch's fixed policy baseline is `Low`, and `SingleRoot`
        // scope never raises risk -- this is the one, deterministically
        // known value `plan.risk_class` can ever take here.
        assert_eq!(plan.risk_class, Some(RiskClass::Low));
    }
}
