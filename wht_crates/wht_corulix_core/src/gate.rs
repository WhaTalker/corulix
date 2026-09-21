// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The canonical gate catalog domain model.
//!
//! This module defines the stable universe of gates and how an operation
//! may relate to each one; it does not implement the `ChangeSession` state
//! machine that walks a session through them (a later Engine phase).

use crate::provider::ReasonCode;
use serde::{Deserialize, Serialize};

/// One of the seven stable gates in Corulix's canonical governance
/// workflow. `#[non_exhaustive]` for forward extension; [`Self::ALL`]
/// enumerates the full current catalog exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub enum GateId {
    #[serde(rename = "gate.discovery")]
    Discovery,
    #[serde(rename = "gate.semantic_confirm")]
    SemanticConfirm,
    #[serde(rename = "gate.edit")]
    Edit,
    #[serde(rename = "gate.format")]
    Format,
    #[serde(rename = "gate.diagnostics")]
    Diagnostics,
    #[serde(rename = "gate.tests")]
    Tests,
    #[serde(rename = "gate.post_audit")]
    PostAudit,
}

impl GateId {
    /// The full stable gate catalog, exactly once each.
    pub const ALL: &'static [GateId] = &[
        Self::Discovery,
        Self::SemanticConfirm,
        Self::Edit,
        Self::Format,
        Self::Diagnostics,
        Self::Tests,
        Self::PostAudit,
    ];
}

/// Whether a gate applies to a given operation, and how.
///
/// A `ToolPlan`'s ordered gate list is a *subset* of [`GateId::ALL`] --
/// nothing in this type forces every operation to traverse all seven gates.
/// `ForbiddenAsAuthority` covers a gate a tool may support but whose result
/// may never close it (mirrors [`crate::provider::AuthorityRole`], but
/// scoped to a gate rather than a single tool/operation pairing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum GateApplicability {
    Required,
    Optional,
    NotApplicable,
    ForbiddenAsAuthority,
}

/// One entry describing how a specific gate relates to an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GateRequirement {
    pub gate: GateId,
    pub applicability: GateApplicability,
}

/// The truthful lifecycle state of a single gate within a session.
///
/// This is a per-gate outcome record only -- it is not the `ChangeSession`
/// state machine. `Stale` represents evidence that was invalidated because
/// upstream session state changed (e.g. a new edit landed after this gate
/// had already passed); it must be re-earned, never silently reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub enum GateStatus {
    Pending,
    Passed,
    Failed { reason: ReasonCode },
    Stale,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_catalog_has_exactly_seven_stable_gates() {
        assert_eq!(GateId::ALL.len(), 7);
        let mut seen = std::collections::HashSet::new();
        for gate in GateId::ALL {
            assert!(
                seen.insert(*gate),
                "duplicate entry in GateId::ALL: {gate:?}"
            );
        }
    }

    #[test]
    fn gate_requirement_does_not_force_a_universal_seven_gate_walk() {
        // A ToolPlan's gate list is any subset -- constructing a plan with
        // only two required gates and the rest marked NotApplicable is
        // perfectly valid; nothing in the type forces all seven.
        let requirements = [
            GateRequirement {
                gate: GateId::Discovery,
                applicability: GateApplicability::Required,
            },
            GateRequirement {
                gate: GateId::SemanticConfirm,
                applicability: GateApplicability::NotApplicable,
            },
        ];
        assert_eq!(requirements.len(), 2);
    }

    #[test]
    fn gate_status_failed_carries_a_structured_reason() {
        let status = GateStatus::Failed {
            reason: ReasonCode::PreconditionNotMet,
        };
        assert!(matches!(
            status,
            GateStatus::Failed {
                reason: ReasonCode::PreconditionNotMet
            }
        ));
    }
}
