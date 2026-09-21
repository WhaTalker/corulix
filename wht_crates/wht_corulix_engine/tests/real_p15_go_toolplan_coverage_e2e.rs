// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15 §24: deterministic `ToolPlan`/gate coverage for `Language=Go` across
//! every `OperationIntent` the mandate names.
//!
//! # No Go-specific policy table exists, and none was added
//!
//! `P15_GO_POLICY_COVERAGE` is satisfied by *reusing* the existing policy
//! machinery, not by extending it. `wht_corulix_engine::policy`'s table is
//! keyed on [`OperationIntent`] alone and carries no language dimension;
//! `routing::evaluate` was already language-aware before P15
//! (`ProviderSnapshot::with_language_server_resolutions` +
//! `plan_operation(.., Some(language))`, admitted in Phase 7B). Go therefore
//! inherits exactly the same auditable, `const`-checked policy every other
//! language gets.
//!
//! Adding a parallel Go-shaped table would have created a second place a
//! `RiskClass`/gate list could be derived -- precisely what Architecture
//! Rule H forbids. What P15 owes §24 is therefore *coverage evidence*: that
//! the shared table really does produce deterministic, fail-closed Go plans
//! for every named intent. That is what this file provides.

use std::error::Error;
use std::fmt;

use wht_corulix_core::{
    GateApplicability, GateId, LanguageId, OperationIntent, PlanExecutability,
    ProviderAvailability, ProviderCategory, ReasonCode, ToolApplicability,
};
use wht_corulix_engine::planning::plan_operation;
use wht_corulix_engine::policy::TargetScope;
use wht_corulix_engine::providers::ProviderSnapshot;

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

/// Every `OperationIntent` §24 names explicitly.
const P15_COVERED_INTENTS: &[OperationIntent] = &[
    OperationIntent::TextSearch,
    OperationIntent::StructuralInspection,
    OperationIntent::SemanticDefinition,
    OperationIntent::SemanticReferences,
    OperationIntent::SemanticRename,
    OperationIntent::SourceCreate,
    OperationIntent::SourceModify,
    OperationIntent::SourceDelete,
    OperationIntent::SourceMove,
    OperationIntent::SourceRefactor,
    OperationIntent::ValidateChange,
];

/// A snapshot in which every externally-resolvable provider category Go uses
/// is genuinely available, plus Go's `LanguageServer` overlay.
fn all_go_providers_available() -> ProviderSnapshot {
    let resolution = |category| wht_corulix_config::ProviderResolution {
        category,
        availability: ProviderAvailability::Available,
        resolved_path: None,
        provenance: None,
        execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
        reason: None,
    };
    ProviderSnapshot::from_resolutions(&[
        resolution(ProviderCategory::Formatter),
        resolution(ProviderCategory::Linter),
        resolution(ProviderCategory::TypecheckBuild),
        resolution(ProviderCategory::TestRunner),
    ])
    .with_language_server_resolutions(&[(LanguageId::Go, ProviderAvailability::Available)])
}

/// `P15_GO_TOOLPLAN_DETERMINISTIC`: the same `(intent, scope, snapshot,
/// Some(Go))` inputs always produce a `ToolPlan` equal by value. Asserted for
/// every covered intent, in both single- and multi-root scope.
#[test]
fn go_toolplans_are_deterministic_for_every_covered_intent() -> Result<(), Box<dyn Error>> {
    let snapshot = all_go_providers_available();
    for intent in P15_COVERED_INTENTS {
        for scope in [
            TargetScope::SingleRoot,
            TargetScope::MultiRoot { root_count: 3 },
        ] {
            let first = plan_operation(*intent, scope, &snapshot, Some(LanguageId::Go));
            let second = plan_operation(*intent, scope, &snapshot, Some(LanguageId::Go));
            if first != second {
                return Err(fail(format!(
                    "{intent:?} in {scope:?} produced two different Go plans"
                )));
            }
            if first.intent != *intent {
                return Err(fail(format!(
                    "{intent:?} produced a plan for a different intent"
                )));
            }
            if first.risk_class.is_none() {
                return Err(fail(format!("{intent:?} produced no risk class")));
            }
        }
    }
    Ok(())
}

/// `P15_GO_POLICY_COVERAGE`: every covered intent has a real policy entry for
/// Go -- a populated requirement/gate derivation, never a silently-borrowed
/// or empty one.
#[test]
fn every_covered_intent_has_a_real_go_policy_entry() -> Result<(), Box<dyn Error>> {
    let snapshot = all_go_providers_available();
    for intent in P15_COVERED_INTENTS {
        let plan = plan_operation(
            *intent,
            TargetScope::SingleRoot,
            &snapshot,
            Some(LanguageId::Go),
        );
        if plan.mutation_kind.is_none() {
            return Err(fail(format!(
                "{intent:?} has no mutation kind -- it fell through to the fail-closed arm"
            )));
        }
        if plan.gates.is_empty() {
            return Err(fail(format!("{intent:?} derived zero gates for Go")));
        }
        // With every Go provider available, no covered intent may be
        // unexecutable -- otherwise the policy requires something Go can
        // never satisfy.
        if plan.executability != PlanExecutability::Executable {
            return Err(fail(format!(
                "{intent:?} is not executable for Go even with every provider available: {:?}",
                plan.executability
            )));
        }
    }
    Ok(())
}

/// Not every operation receives every provider -- Minimum Sufficient
/// Tooling. `TEXT_SEARCH`/`STRUCTURAL_INSPECTION` must not require a Go
/// language server, a formatter, or a build/test provider.
#[test]
fn cheap_go_operations_require_no_expensive_go_provider() -> Result<(), Box<dyn Error>> {
    let snapshot = all_go_providers_available();
    for intent in [
        OperationIntent::TextSearch,
        OperationIntent::StructuralInspection,
    ] {
        let plan = plan_operation(
            intent,
            TargetScope::SingleRoot,
            &snapshot,
            Some(LanguageId::Go),
        );
        for requirement in &plan.requirements {
            if requirement.applicability != ToolApplicability::Required {
                continue;
            }
            if matches!(
                requirement.category,
                ProviderCategory::LanguageServer
                    | ProviderCategory::Formatter
                    | ProviderCategory::TypecheckBuild
                    | ProviderCategory::TestRunner
                    | ProviderCategory::Linter
            ) {
                return Err(fail(format!(
                    "{intent:?} must not require {:?} for Go -- Minimum Sufficient Tooling",
                    requirement.category
                )));
            }
        }
    }
    Ok(())
}

/// `PLAN_UNEXECUTABLE -> FAIL CLOSED`: removing exactly one genuinely
/// required provider must make every intent that requires it unexecutable,
/// with the stable `RequiredProviderUnavailable` reason -- and must leave
/// every required gate in the plan untouched.
#[test]
fn one_missing_required_go_provider_fails_the_plan_closed() -> Result<(), Box<dyn Error>> {
    // gopls absent, everything else available.
    let without_gopls = {
        let resolution = |category| wht_corulix_config::ProviderResolution {
            category,
            availability: ProviderAvailability::Available,
            resolved_path: None,
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
            reason: None,
        };
        ProviderSnapshot::from_resolutions(&[
            resolution(ProviderCategory::Formatter),
            resolution(ProviderCategory::Linter),
            resolution(ProviderCategory::TypecheckBuild),
            resolution(ProviderCategory::TestRunner),
        ])
        .with_language_server_resolutions(&[(
            LanguageId::Go,
            ProviderAvailability::ProviderUnavailable,
        )])
    };

    for intent in [
        OperationIntent::SemanticDefinition,
        OperationIntent::SemanticReferences,
        OperationIntent::SemanticRename,
        OperationIntent::SourceRefactor,
    ] {
        let plan = plan_operation(
            intent,
            TargetScope::SingleRoot,
            &without_gopls,
            Some(LanguageId::Go),
        );
        match plan.executability {
            PlanExecutability::Unexecutable {
                reason: ReasonCode::RequiredProviderUnavailable,
            } => {}
            other => {
                return Err(fail(format!(
                    "{intent:?} must be Unexecutable with a stable reason when gopls is absent, got {other:?}"
                )));
            }
        }
        // A required gate never disappears because its provider is missing.
        if plan.gates.is_empty() {
            return Err(fail(format!(
                "{intent:?} lost its gates when a provider went missing"
            )));
        }
        if !plan
            .gates
            .iter()
            .any(|gate| gate.applicability == GateApplicability::Required)
        {
            return Err(fail(format!(
                "{intent:?} lost every required gate when a provider went missing"
            )));
        }
    }
    Ok(())
}

/// `P15_GO_REQUIRED_FORMATTER_MISSING_BLOCKS_COMPLETION` (§25) at the plan
/// level: with `gofmt` absent, a Go source create/modify plan is
/// unexecutable, and `gate.format` is still `Required`.
#[test]
fn missing_gofmt_makes_go_source_mutation_unexecutable_without_dropping_the_gate()
-> Result<(), Box<dyn Error>> {
    let without_formatter = {
        let resolution = |category, availability| wht_corulix_config::ProviderResolution {
            category,
            availability,
            resolved_path: None,
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
            reason: None,
        };
        ProviderSnapshot::from_resolutions(&[
            resolution(
                ProviderCategory::Formatter,
                ProviderAvailability::ProviderUnavailable,
            ),
            resolution(
                ProviderCategory::TypecheckBuild,
                ProviderAvailability::Available,
            ),
            resolution(ProviderCategory::Linter, ProviderAvailability::Available),
        ])
        .with_language_server_resolutions(&[(LanguageId::Go, ProviderAvailability::Available)])
    };

    for intent in [OperationIntent::SourceCreate, OperationIntent::SourceModify] {
        let plan = plan_operation(
            intent,
            TargetScope::SingleRoot,
            &without_formatter,
            Some(LanguageId::Go),
        );
        if plan.executability == PlanExecutability::Executable {
            return Err(fail(format!(
                "{intent:?} must not be executable for Go without gofmt"
            )));
        }
        if !plan.gates.iter().any(|gate| {
            gate.gate == GateId::Format && gate.applicability == GateApplicability::Required
        }) {
            return Err(fail(format!(
                "{intent:?} must keep gate.format Required for Go even without gofmt"
            )));
        }
    }
    Ok(())
}

/// Risk strengthens with scope for Go exactly as for any other language --
/// multi-root raises risk by one step, never lowers it, and no
/// caller-supplied value participates.
#[test]
fn go_risk_never_decreases_with_wider_scope() -> Result<(), Box<dyn Error>> {
    let snapshot = all_go_providers_available();
    for intent in P15_COVERED_INTENTS {
        let single = plan_operation(
            *intent,
            TargetScope::SingleRoot,
            &snapshot,
            Some(LanguageId::Go),
        );
        let multi = plan_operation(
            *intent,
            TargetScope::MultiRoot { root_count: 4 },
            &snapshot,
            Some(LanguageId::Go),
        );
        if multi.risk_class < single.risk_class {
            return Err(fail(format!(
                "{intent:?}: wider scope lowered Go's risk class ({:?} -> {:?})",
                single.risk_class, multi.risk_class
            )));
        }
    }
    Ok(())
}

/// A Go plan and a Rust plan for the same intent differ **only** through
/// real per-language provider availability, never through a language-keyed
/// policy branch. With Go available and Rust not, the Go plan is executable
/// and the Rust one is not -- from the identical policy entry.
#[test]
fn go_and_rust_share_one_policy_table_and_differ_only_by_availability() -> Result<(), Box<dyn Error>>
{
    let go_only = all_go_providers_available();
    for intent in [
        OperationIntent::SemanticDefinition,
        OperationIntent::SemanticReferences,
    ] {
        let go_plan = plan_operation(
            intent,
            TargetScope::SingleRoot,
            &go_only,
            Some(LanguageId::Go),
        );
        let rust_plan = plan_operation(
            intent,
            TargetScope::SingleRoot,
            &go_only,
            Some(LanguageId::Rust),
        );
        // Same policy entry: identical requirements, gates, risk, intent.
        if go_plan.requirements != rust_plan.requirements
            || go_plan.gates != rust_plan.gates
            || go_plan.risk_class != rust_plan.risk_class
        {
            return Err(fail(format!(
                "{intent:?}: Go and Rust must derive from one identical policy entry"
            )));
        }
        // Different only in executability, and only because of real
        // availability.
        if go_plan.executability != PlanExecutability::Executable {
            return Err(fail(format!("{intent:?}: Go should be executable")));
        }
        if rust_plan.executability == PlanExecutability::Executable {
            return Err(fail(format!(
                "{intent:?}: Rust must not be executable when only Go resolved"
            )));
        }
    }
    Ok(())
}
