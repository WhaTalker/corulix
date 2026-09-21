// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded confidence, reference evidence, and gate-closing Evidence
//! contracts.
//!
//! These are plain data contracts only: no clock access, no provider calls,
//! no filesystem reads, no Evidence persistence, and no Evidence-acceptance
//! logic. Only a later Engine phase decides whether a given `Evidence`
//! record is authoritative for closing a gate.

use crate::error::{CorulixError, CorulixResult};
use crate::gate::GateId;
use crate::provider::{AuthorityRole, ReasonCode};
use crate::session::ChangeSessionId;
use crate::workspace::WorkspaceIdentity;
use serde::{Deserialize, Serialize};

/// The maximum byte length of an [`EvidenceResultSummary`]. Evidence must
/// never carry raw, unbounded provider stdout/stderr as its canonical
/// result -- this cap makes that a type-level, fail-closed invariant rather
/// than a convention a caller could forget to honor.
pub const EVIDENCE_RESULT_SUMMARY_MAX_BYTES: usize = 4096;

/// A bounded confidence score in the closed range `[0.0, 1.0]`.
///
/// Construction fails closed: `NaN`, `+Infinity`, `-Infinity`, and any value
/// outside `[0.0, 1.0]` are rejected outright. There is no silent clamping
/// (`NaN -> 0`, `1.2 -> 1`, `-0.1 -> 0`) -- an invalid value simply cannot
/// become a `Confidence`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "f32", into = "f32")]
pub struct Confidence(f32);

impl Confidence {
    pub const MIN: Confidence = Confidence(0.0);
    pub const MAX: Confidence = Confidence(1.0);

    pub fn new(value: f32) -> CorulixResult<Self> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(CorulixError::InvalidConfidence);
        }
        Ok(Self(value))
    }

    pub fn value(&self) -> f32 {
        self.0
    }
}

impl TryFrom<f32> for Confidence {
    type Error = CorulixError;

    fn try_from(value: f32) -> CorulixResult<Self> {
        Self::new(value)
    }
}

impl From<Confidence> for f32 {
    fn from(value: Confidence) -> f32 {
        value.0
    }
}

/// How a cross-reference was established, ordered roughly from strongest
/// (structural, from the AST itself) to weakest (heuristic guess). Callers
/// use this to decide how much to trust a reported reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ResolutionKind {
    Structural,
    LexicallyResolved,
    ImportResolved,
    CrossFileResolved,
    Heuristic,
    Unresolved,
}

/// Confidence-scored evidence backing a reported reference.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReferenceEvidence {
    pub resolution_kind: ResolutionKind,
    pub confidence: Confidence,
}

/// A bounded, coarse result summary. Rejects any input longer than
/// [`EVIDENCE_RESULT_SUMMARY_MAX_BYTES`] so `Evidence` can never accidentally
/// carry raw, unbounded provider output as its canonical record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct EvidenceResultSummary(String);

impl TryFrom<String> for EvidenceResultSummary {
    type Error = CorulixError;

    fn try_from(value: String) -> CorulixResult<Self> {
        if value.len() > EVIDENCE_RESULT_SUMMARY_MAX_BYTES {
            return Err(CorulixError::ResourceLimit);
        }
        Ok(Self(value))
    }
}

impl From<EvidenceResultSummary> for String {
    fn from(value: EvidenceResultSummary) -> String {
        value.0
    }
}

impl EvidenceResultSummary {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An opaque, caller-supplied point in time expressed as epoch
/// milliseconds. Core performs no clock access -- the value is always
/// supplied by a later runtime layer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct EvidenceTimestamp(pub u64);

/// Which provider produced a piece of evidence, and under what authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceProvenance {
    pub provider_id: String,
    pub provider_version: Option<String>,
    pub authority: AuthorityRole,
}

/// A single gate-relevant evidence record.
///
/// Plain data only -- no clock access, no provider invocation, no
/// filesystem reads, and no acceptance/persistence logic. Whether a given
/// record is authoritative for closing a gate is decided later, by the
/// Engine, from [`EvidenceProvenance::authority`] and the session/gate
/// context -- never by an unverified narrative claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Evidence {
    pub session_id: ChangeSessionId,
    pub workspace_identity: WorkspaceIdentity,
    pub gate: GateId,
    pub sequence: u64,
    pub provenance: EvidenceProvenance,
    pub scope: Vec<String>,
    pub input_fingerprint: Option<crate::mutation::ContentHash>,
    pub result_summary: EvidenceResultSummary,
    pub reason: Option<ReasonCode>,
    pub truncated: bool,
    pub timestamp: EvidenceTimestamp,
    pub snapshot_id: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_accepts_boundary_and_interior_values() -> CorulixResult<()> {
        assert_eq!(Confidence::new(0.0)?.value(), 0.0);
        assert_eq!(Confidence::new(1.0)?.value(), 1.0);
        assert_eq!(Confidence::new(0.42)?.value(), 0.42);
        Ok(())
    }

    #[test]
    fn confidence_rejects_out_of_range_values() {
        assert!(matches!(
            Confidence::new(-0.1),
            Err(CorulixError::InvalidConfidence)
        ));
        assert!(matches!(
            Confidence::new(1.2),
            Err(CorulixError::InvalidConfidence)
        ));
    }

    #[test]
    fn confidence_rejects_non_finite_values() {
        assert!(matches!(
            Confidence::new(f32::NAN),
            Err(CorulixError::InvalidConfidence)
        ));
        assert!(matches!(
            Confidence::new(f32::INFINITY),
            Err(CorulixError::InvalidConfidence)
        ));
        assert!(matches!(
            Confidence::new(f32::NEG_INFINITY),
            Err(CorulixError::InvalidConfidence)
        ));
    }

    #[test]
    fn confidence_never_silently_clamps() {
        // A rejected construction must not produce a clamped value under a
        // different code path -- there is no such path: `new` is the only
        // constructor, and it always returns `Err` for these inputs.
        for invalid in [-0.1_f32, 1.2, f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert!(Confidence::new(invalid).is_err());
        }
    }

    #[test]
    fn reference_evidence_uses_bounded_confidence() -> CorulixResult<()> {
        let evidence = ReferenceEvidence {
            resolution_kind: ResolutionKind::Structural,
            confidence: Confidence::new(0.75)?,
        };
        assert_eq!(evidence.confidence.value(), 0.75);
        Ok(())
    }

    #[test]
    fn evidence_result_summary_accepts_bounded_input() -> CorulixResult<()> {
        let summary = EvidenceResultSummary::try_from("ok".to_string())?;
        assert_eq!(summary.as_str(), "ok");
        Ok(())
    }

    #[test]
    fn evidence_result_summary_rejects_oversized_input() {
        let oversized = "x".repeat(EVIDENCE_RESULT_SUMMARY_MAX_BYTES + 1);
        assert!(matches!(
            EvidenceResultSummary::try_from(oversized),
            Err(CorulixError::ResourceLimit)
        ));
    }
}
