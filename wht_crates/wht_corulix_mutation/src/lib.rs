// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Sole owner of the canonical governed mutation transaction for
//! WhaTalker Corulix (Architecture Rule M).
//!
//! `MUTATION_MODEL=CORULIX_CONTROLLED`, `HOST_DIRECT_APPLY=FORBIDDEN`: an
//! AI/host proposes a [`MutationBatch`]; only this crate validates and
//! writes it. No other crate may write to the live workspace for a
//! governed mutation -- Search, Syntax, LSP, MCP, and CLI have no direct
//! mutation authority (Rule M), and this crate never duplicates
//! `wht_corulix_workspace`'s path confinement, canonicalization, or
//! symlink protection (Rule F): every target/source this crate touches is
//! resolved through `wht_corulix_workspace::{resolve_confined, confine_target}`.
//!
//! # Canonical transaction
//!
//! ```text
//! PREPARE   -- validate every path/hash/collision/edit/bound; read-only
//!   |
//! STAGE     -- write final bytes to ephemeral, bounded temp files
//!   |
//! COMMIT    -- deterministic (batch) order; the safest atomic primitive
//!   |          each mutation form supports
//! VERIFY    -- rehash/re-check every committed target; never trust a
//!              syscall's `Ok` alone
//! ```
//!
//! If PREPARE fails, `LIVE_WORKSPACE_MUTATION_COUNT=0` -- nothing has been
//! written. If a COMMIT step fails after one or more earlier items in the
//! same batch already committed, this crate attempts internal recovery
//! (undoing already-committed items via its own bounded, ephemeral
//! transaction journal) to restore the pre-transaction state
//! (`MULTIFILE_ATOMICITY=CORULIX_RECOVERY_MODEL` -- there is no portable
//! multi-file atomic OS transaction, so this crate never claims
//! `MULTIFILE_ATOMIC_OS_TRANSACTION=YES`). If recovery itself fails, the
//! executor that ran it is locked (no further mutation writes are
//! accepted from it) and [`error::MutationError::RecoveryRequired`] is
//! returned, corresponding to [`wht_corulix_core::ReasonCode::MutationRecoveryRequired`].
//!
//! `AUTO_REVERT_ON_GATE_FAILURE=NO`: this recovery model exists only to
//! protect one transaction's own atomicity when an internal step fails --
//! it is never triggered because some unrelated later gate (lint/test/
//! format) failed, and this crate implements no Git rollback of any kind.
//!
//! Staging is ephemeral, bounded Corulix-controlled state -- never a
//! long-term backup, never a user-facing backup, never a Git stash, and
//! never an OS sandbox claim.

mod edits;
mod error;
mod executor;
mod journal;
mod prepare;
mod types;

pub use error::MutationError;
/// Real-recovery-failure driver, reachable only under `cfg(test)` (this
/// crate's own tests) or the `test-support` feature (another workspace
/// crate's own dev-dependency-scoped tests, e.g.
/// `wht_corulix_engine`'s real recovery-lock `ChangeSession` E2E) -- never
/// part of this crate's default, released public API surface. See
/// `executor::FailureInjectionPoint`'s own doc comment.
#[cfg(any(test, feature = "test-support"))]
pub use executor::FailureInjectionPoint;
pub use executor::{MutationExecutor, MutationOutcome};
pub use types::{
    DEFAULT_MAX_EDITS_PER_FILE, DEFAULT_MAX_JOURNAL_ENTRIES, DEFAULT_MAX_MUTATION_COUNT,
    DEFAULT_MAX_RECOVERY_CAPTURE_BYTES, DEFAULT_MAX_TOTAL_EDITS, DEFAULT_MAX_TOTAL_INPUT_BYTES,
    DEFAULT_MAX_TOTAL_STAGED_BYTES, Mutation, MutationBatch, MutationLimits, MutationResult,
    TextEdit,
};
