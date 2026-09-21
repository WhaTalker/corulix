// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! This crate's typed error taxonomy. Never a bare string, never a panic:
//! every pre-invocation guard failure and every failure surfaced by the
//! final `wht_corulix_mutation` apply step is one of these variants.
//!
//! A failure that happens *after* rustfmt was actually invoked (provider
//! unavailable, non-zero exit, timeout, cancellation, oversized output) is
//! deliberately **not** here -- those are typed, non-exceptional outcomes
//! carried by [`crate::FormatterResult`]/[`crate::FormatStatus`] instead,
//! mirroring `wht_corulix_tooling::ExecutionOutcome`/`TerminationReason`'s
//! own "the tool ran and reported an outcome" pattern. This taxonomy is
//! reserved for guard failures that occur *before* rustfmt ever runs, and
//! for the final `MutationError` this crate never re-encodes but instead
//! reuses directly (Architecture Rule M: only `wht_corulix_mutation` writes
//! the live workspace, and only it owns that error taxonomy).

use wht_corulix_core::WorkspacePath;
use wht_corulix_mutation::MutationError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatterError {
    /// The target path's language, as detected by
    /// `wht_corulix_syntax::detect_language`, has no admitted formatter
    /// authority in [`crate::profile`]'s table -- either the extension is
    /// not a recognized source language at all (`language: None`: Markdown/
    /// JSON/TOML/generated/binary content) or it is a language whose own
    /// phase has not yet admitted a formatter (`language: Some(..)`, e.g.
    /// TypeScript/Python before P16/P17). Refused before any process is
    /// spawned.
    ///
    /// P15 renamed this from `NotRustSource`: with `gofmt` admitted
    /// alongside `rustfmt`, "not Rust source" was no longer a truthful
    /// description of the condition, and keeping a misnamed public variant
    /// would have made the error taxonomy lie about its own meaning.
    UnsupportedLanguage {
        path: WorkspacePath,
        language: Option<wht_corulix_core::LanguageId>,
    },
    /// The target path does not resolve inside the active workspace
    /// (Architecture Rule F, enforced by `wht_corulix_workspace`).
    ConfinementViolation { path: WorkspacePath },
    /// The target file's current content exceeds this crate's bounded
    /// input size before rustfmt is ever invoked.
    OversizedInput { path: WorkspacePath },
    /// Reading the target's current content failed for a reason other than
    /// confinement or size (e.g. the target does not exist as a regular
    /// file).
    ReadFailed { path: WorkspacePath },
    /// The host-wide canonical managed-toolchain root
    /// (`wht_corulix_tooling::provisioning::managed_toolchain_root`) could
    /// not be resolved -- occurs only in [`crate::format_and_apply`]'s own
    /// default-root convenience wrapper, before rustfmt resolution is
    /// attempted at all; a caller supplying its own root via
    /// [`crate::format_and_apply_at`] never hits this.
    ManagedToolchainRootUnavailable,
    /// The final `MutationBatch` apply step failed. Reuses
    /// `wht_corulix_mutation::MutationError` verbatim rather than
    /// re-encoding its variants -- a stale precondition (the target changed
    /// out-of-band between the pre-format hash capture and this apply)
    /// surfaces here as `Mutation(MutationError::StalePreconditionHash)`.
    Mutation(MutationError),
}

impl std::fmt::Display for FormatterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedLanguage { language: None, .. } => {
                write!(f, "target is not recognized source in any known language")
            }
            Self::UnsupportedLanguage {
                language: Some(language),
                ..
            } => write!(f, "no admitted formatter authority for {language}"),
            Self::ConfinementViolation { .. } => write!(f, "workspace confinement violation"),
            Self::OversizedInput { .. } => write!(f, "formatter input exceeds size bound"),
            Self::ReadFailed { .. } => write!(f, "failed to read formatter target"),
            Self::ManagedToolchainRootUnavailable => {
                write!(f, "managed toolchain root unavailable")
            }
            Self::Mutation(error) => write!(f, "formatter apply failed: {error}"),
        }
    }
}

impl std::error::Error for FormatterError {}
