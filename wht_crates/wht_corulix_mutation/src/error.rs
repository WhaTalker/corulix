// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! This crate's typed error taxonomy. Never a bare string, never a panic:
//! every mutation-input-driven failure mode is one of these variants.

use wht_corulix_core::WorkspacePath;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationError {
    /// A mutation's `expected_precondition_hash`/`expected_source_hash`
    /// did not match the target's actual current content -- the target
    /// was modified out-of-band since the caller last observed it. Raised
    /// either at PREPARE (the original observation) or, since P-M08-R1, at
    /// COMMIT (a final revalidation immediately before the irreversible
    /// filesystem write, catching a change that happened during PREPARE's
    /// remaining work or STAGE).
    StalePreconditionHash { path: WorkspacePath },
    /// P-M08-R1: a caller-supplied `expected_precondition_hash`/
    /// `expected_source_hash` is not a well-formed 64-lowercase-hex-
    /// character SHA-256 digest (wrong length, non-hex characters,
    /// uppercase, or a non-`Sha256` algorithm) -- a caller-input defect,
    /// never a genuine staleness signal. Distinguished from
    /// [`Self::StalePreconditionHash`] so a malformed request is never
    /// misreported as "someone else changed this file".
    MalformedPreconditionHash { path: WorkspacePath },
    /// `CreateFile`'s target already exists.
    CreateCollision { path: WorkspacePath },
    /// `MoveFile`'s destination already exists.
    MoveCollision { destination: WorkspacePath },
    /// An edit's range is out of bounds, not on a UTF-8 boundary, or
    /// otherwise invalid for the target's current content.
    InvalidEditRange { path: WorkspacePath },
    /// Two or more edits in the same `ApplyTextEdits` target overlap.
    OverlappingEdits { path: WorkspacePath },
    /// A target or source path does not resolve inside the active
    /// workspace (Rule F, enforced by `wht_corulix_workspace`).
    ConfinementViolation { path: WorkspacePath },
    /// A hard [`crate::types::MutationLimits`] bound was exceeded.
    ResourceLimitExceeded,
    /// A mutation's target does not exist as the operation expects (e.g.
    /// `DeleteFile`/`ApplyTextEdits`/`ReplaceFile`/`MoveFile`'s source
    /// requires an existing file).
    TargetNotFound { path: WorkspacePath },
    /// PREPARE failed for a reason not captured by a more specific
    /// variant above (e.g. an I/O error reading a target's current
    /// content).
    PrepareFailed,
    /// A commit-time filesystem operation failed, and this batch's
    /// internal partial-commit recovery succeeded in restoring the
    /// pre-transaction state -- no live effect from this transaction
    /// remains, but the batch itself did not complete. `recovered_paths`
    /// lists exactly which paths were touched during recovery (empty if
    /// the failure happened before any item committed).
    CommitFailed { recovered_paths: Vec<WorkspacePath> },
    /// A committed action's post-commit verification did not match the
    /// expected outcome (the underlying syscall reported success, but the
    /// actual on-disk state does not agree) -- recovery was attempted and
    /// succeeded, exactly as for [`Self::CommitFailed`], but the root
    /// cause is distinguished so a caller never conflates "the write
    /// syscall itself failed" with "the syscall said yes but the disk
    /// disagreed".
    VerificationFailed { recovered_paths: Vec<WorkspacePath> },
    /// A commit-time failure occurred after one or more mutations were
    /// already applied, and this batch's internal recovery attempt to
    /// restore the pre-transaction state itself failed. The executor that
    /// produced this is now locked
    /// (`FURTHER_MUTATION_WRITES_DENIED=YES`) until a caller constructs a
    /// fresh executor with explicit knowledge of the manual recovery this
    /// requires -- see `wht_corulix_core::ReasonCode::MutationRecoveryRequired`.
    /// `unrecovered_paths` lists every journaled path recovery did not
    /// confirm undone (manual recovery evidence must cover these).
    RecoveryRequired {
        unrecovered_paths: Vec<WorkspacePath>,
    },
    /// This executor is locked following a prior [`Self::RecoveryRequired`]
    /// outcome; no further mutation writes are accepted from it.
    ExecutorLocked,
}

impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StalePreconditionHash { .. } => write!(f, "stale precondition hash"),
            Self::MalformedPreconditionHash { .. } => write!(f, "malformed precondition hash"),
            Self::CreateCollision { .. } => write!(f, "create target already exists"),
            Self::MoveCollision { .. } => write!(f, "move destination already exists"),
            Self::InvalidEditRange { .. } => write!(f, "invalid edit range"),
            Self::OverlappingEdits { .. } => write!(f, "overlapping edits"),
            Self::ConfinementViolation { .. } => write!(f, "workspace confinement violation"),
            Self::ResourceLimitExceeded => write!(f, "mutation resource limit exceeded"),
            Self::TargetNotFound { .. } => write!(f, "mutation target not found"),
            Self::PrepareFailed => write!(f, "mutation prepare failed"),
            Self::CommitFailed { .. } => write!(f, "mutation commit failed (recovered)"),
            Self::VerificationFailed { .. } => {
                write!(f, "post-commit verification failed (recovered)")
            }
            Self::RecoveryRequired { .. } => write!(f, "mutation recovery required"),
            Self::ExecutorLocked => write!(f, "mutation executor is locked"),
        }
    }
}

impl std::error::Error for MutationError {}
