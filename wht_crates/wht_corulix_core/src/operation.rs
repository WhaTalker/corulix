// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Operation intent, mutation kind, and risk classification contracts.
//!
//! None of these types perform derivation. `MutationKind` and `RiskClass`
//! are independent axes: the same `MutationKind` can coexist with any
//! `RiskClass`, and no type-level coupling forces e.g. `Modify == Low` or
//! `Delete == Critical`. A later Engine phase derives the actual risk for a
//! concrete request; Core defines only the vocabulary and its invariants.

use serde::{Deserialize, Serialize};

/// The kind of operation a caller is requesting.
///
/// `#[non_exhaustive]` for forward extension. [`Self::ALL`] enumerates every
/// currently-defined variant exactly once, giving a later deterministic
/// policy router (Phase 4) a coverage mechanism: it can iterate `ALL` and
/// assert every intent has a policy-table entry, without this crate needing
/// to know anything about that table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum OperationIntent {
    TextSearch,
    FileDiscovery,
    StructuralInspection,
    StructuralSearch,
    SemanticDefinition,
    SemanticReferences,
    SemanticDiagnostics,
    SemanticRename,
    SourceCreate,
    SourceModify,
    SourceDelete,
    SourceMove,
    SourceRefactor,
    ConfigModify,
    DocumentationModify,
    ValidateChange,
}

impl OperationIntent {
    /// Every currently-defined `OperationIntent` variant, exactly once.
    /// Deletion ([`Self::SourceDelete`]) and move ([`Self::SourceMove`]) are
    /// explicit, first-class entries -- neither is folded into
    /// [`Self::SourceModify`].
    pub const ALL: &'static [OperationIntent] = &[
        Self::TextSearch,
        Self::FileDiscovery,
        Self::StructuralInspection,
        Self::StructuralSearch,
        Self::SemanticDefinition,
        Self::SemanticReferences,
        Self::SemanticDiagnostics,
        Self::SemanticRename,
        Self::SourceCreate,
        Self::SourceModify,
        Self::SourceDelete,
        Self::SourceMove,
        Self::SourceRefactor,
        Self::ConfigModify,
        Self::DocumentationModify,
        Self::ValidateChange,
    ];
}

/// What kind of mutation occurs. Describes *what*, never risk -- see
/// [`RiskClass`] for the independent risk axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum MutationKind {
    None,
    Create,
    Modify,
    Delete,
    Move,
    SemanticRename,
    Configuration,
    Documentation,
}

/// How risky a concrete operation is, independent of [`MutationKind`].
///
/// Ordered (`Low < Elevated < High < Critical`) because later enforcement
/// logic needs to compare risk levels (e.g. "policy may only raise risk,
/// never lower it"). Core does not infer this value from a request -- a
/// later Engine phase derives it; this type defines only the vocabulary and
/// its ordering.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum RiskClass {
    Low,
    Elevated,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_intent_all_covers_every_variant_exactly_once() {
        assert_eq!(OperationIntent::ALL.len(), 16);
        let mut seen = std::collections::HashSet::new();
        for intent in OperationIntent::ALL {
            assert!(
                seen.insert(*intent),
                "duplicate entry in OperationIntent::ALL: {intent:?}"
            );
        }
    }

    #[test]
    fn deletion_and_move_are_explicit_variants() {
        assert!(OperationIntent::ALL.contains(&OperationIntent::SourceDelete));
        assert!(OperationIntent::ALL.contains(&OperationIntent::SourceMove));
        assert_ne!(OperationIntent::SourceDelete, OperationIntent::SourceModify);
        assert_ne!(OperationIntent::SourceMove, OperationIntent::SourceModify);
    }

    #[test]
    fn risk_class_is_ordered() {
        assert!(RiskClass::Low < RiskClass::Elevated);
        assert!(RiskClass::Elevated < RiskClass::High);
        assert!(RiskClass::High < RiskClass::Critical);
    }

    #[test]
    fn mutation_kind_and_risk_class_are_independent_axes() {
        // No type-level coupling forces a specific RiskClass for a given
        // MutationKind: any pairing must construct without issue.
        let pairs = [
            (MutationKind::Modify, RiskClass::Low),
            (MutationKind::Modify, RiskClass::Critical),
            (MutationKind::Delete, RiskClass::Low),
            (MutationKind::Delete, RiskClass::Critical),
        ];
        for (kind, risk) in pairs {
            // Constructing the tuple at all is the proof: nothing about
            // MutationKind's type constrains which RiskClass may appear
            // alongside it.
            let _ = (kind, risk);
        }
    }
}
