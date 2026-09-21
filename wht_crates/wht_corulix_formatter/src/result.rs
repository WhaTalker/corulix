// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The typed, authoritative formatter result -- provider identity/version,
//! input/output content hashes, changed/unchanged, status, reason, and
//! truncation. Never raw rustfmt stdout text as the canonical result, and
//! never a raw `wht_corulix_tooling` process DTO exposed publicly: this is
//! the sole shape a future `gate.format` evaluator will ever need to
//! consume. This phase does not implement that evaluator (no Phase-10
//! Evidence/state machine) -- it only produces the evidence record such an
//! evaluator would require.

use std::path::PathBuf;
use wht_corulix_core::{ContentHash, ReasonCode, WorkspacePath};

/// What happened when this crate attempted to format one target.
///
/// `ProviderUnavailable` and `InvocationFailed`/`TimedOut`/`Cancelled` are
/// deliberately distinct from a Rust-level error (see `crate::FormatterError`'s
/// own docs): rustfmt was resolved and/or invoked, and this is the typed,
/// non-panicking outcome of that attempt -- exactly the same "the tool ran,
/// here is what happened" shape `wht_corulix_tooling::TerminationReason`
/// already establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatStatus {
    /// rustfmt ran, produced different bytes than the input, and those
    /// bytes were successfully applied through `wht_corulix_mutation`.
    Formatted,
    /// rustfmt ran and reported the input was already correctly formatted
    /// (byte-identical output) -- no mutation was attempted.
    Unchanged,
    /// The `rustfmt` provider could not be resolved
    /// (`wht_corulix_config::resolve_provider` reported unavailable).
    ProviderUnavailable,
    /// rustfmt was spawned but the invocation did not produce a usable
    /// formatted result: a non-zero exit code, a process that could not be
    /// spawned at all, a signal-terminated process, non-UTF-8 output, or
    /// output that exceeded this crate's bounded capture size. A truncated
    /// or otherwise unusable result is never applied as if it were the
    /// real formatted content.
    InvocationFailed,
    /// The configured timeout elapsed before rustfmt exited; the process
    /// was terminated.
    TimedOut,
    /// The caller's `CancellationToken` was observed before rustfmt
    /// exited; the process was terminated.
    Cancelled,
    /// A `CORULIX_MANAGED` uninstall requested this process stop while it
    /// was still genuinely running (Phase 7B-B2-B-R1); the process was
    /// terminated in response. Only reachable when `provider_used_managed`
    /// is `true` -- the `HOST_ONLY`/system path is never leased.
    StoppedForUninstall,
    /// Phase 13 (`format_preview`): rustfmt ran and produced different
    /// bytes than the input, exactly as [`Self::Formatted`] would, but this
    /// call was a read-only preview -- no [`wht_corulix_mutation::MutationExecutor`]
    /// write was attempted, and the live workspace file was never touched.
    /// Distinguishing this from `Formatted` matters for a client: `changed
    /// == true` alone cannot tell it whether the bytes on disk actually
    /// changed.
    WouldFormat,
}

/// The complete, typed outcome of one formatter attempt against one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatterResult {
    pub path: WorkspacePath,
    /// The resolved rustfmt executable's canonicalized path, `None` when
    /// resolution itself failed (`status == ProviderUnavailable`).
    pub provider_path: Option<PathBuf>,
    /// `rustfmt --version`'s reported version string, best-effort -- `None`
    /// if resolution failed or the version probe itself did not succeed.
    pub provider_version: Option<String>,
    /// `true` when `provider_path` was resolved via `CORULIX_MANAGED`
    /// (Phase 7B-B2-B), `false` for the pre-existing `HOST_ONLY`/system
    /// resolution -- always `false` when `provider_path` is `None`. The
    /// evidence record this phase's own `RUST_FORMATTER_AUTHORITY` claim
    /// is checked against.
    pub provider_used_managed: bool,
    /// The target's content hash as observed *before* formatting -- the
    /// same hash this crate passes as `expected_precondition_hash` on the
    /// eventual `MutationBatch`.
    pub input_hash: ContentHash,
    /// rustfmt's output hash, present whenever rustfmt produced a complete,
    /// non-truncated result (`Formatted` or `Unchanged`).
    pub output_hash: Option<ContentHash>,
    /// Whether rustfmt's output differed from the input. Independent from
    /// `status`: only meaningful when `status` is `Formatted` or
    /// `Unchanged`.
    pub changed: bool,
    pub status: FormatStatus,
    /// A structured reason, populated at minimum when `status ==
    /// ProviderUnavailable` (carrying `resolve_provider`'s own reason).
    pub reason: Option<ReasonCode>,
    /// Whether rustfmt's captured stdout hit this crate's bounded capture
    /// limit. A truncated result is always reported with `status ==
    /// InvocationFailed` and `changed == false` -- it is never treated as a
    /// complete, applicable formatted result.
    pub truncated: bool,
}
