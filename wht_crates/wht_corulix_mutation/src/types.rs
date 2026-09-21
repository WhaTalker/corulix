// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The five canonical typed mutation forms and the hard resource bounds
//! every [`MutationBatch`] is checked against. There is no free-form
//! mutation command: a caller expresses intent only through one of these
//! variants.

use wht_corulix_core::{ContentHash, SourceRange, WorkspacePath};

/// A single proposed text edit, expressed in Corulix's own byte-offset
/// `SourceRange` (never a raw line/character pair) -- reusing the exact
/// shape `wht_corulix_lsp::dto::ProposedTextEdit` already established for a
/// rename preview, so this crate does not invent a second edit contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextEdit {
    pub range: SourceRange,
    pub new_text: String,
}

/// One canonical, typed mutation. Never a free-form command string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Creates a new file. Requires the target to be absent
    /// (`CREATE_OVERWRITE_PATH_COUNT=0`) -- never converts into a replace.
    CreateFile {
        path: WorkspacePath,
        content: Vec<u8>,
    },
    /// Applies a deterministic, non-overlapping set of text edits to an
    /// existing file, gated on `expected_precondition_hash`.
    ApplyTextEdits {
        path: WorkspacePath,
        expected_precondition_hash: ContentHash,
        edits: Vec<TextEdit>,
    },
    /// Replaces an existing file's entire content, gated on
    /// `expected_precondition_hash`.
    ReplaceFile {
        path: WorkspacePath,
        expected_precondition_hash: ContentHash,
        content: Vec<u8>,
    },
    /// Deletes an existing file, gated on `expected_precondition_hash`.
    /// Never a hidden `ReplaceFile` with empty content.
    DeleteFile {
        path: WorkspacePath,
        expected_precondition_hash: ContentHash,
    },
    /// Moves/renames a file. `expected_source_hash` gates the source; the
    /// destination must be absent -- this phase enforces that
    /// unconditionally (`MOVE + DESTINATION_EXISTS => FAIL_CLOSED_COLLISION`,
    /// per this phase's own "no implicit overwrite" rule), so there is no
    /// caller-selectable overwrite path.
    MoveFile {
        source: WorkspacePath,
        destination: WorkspacePath,
        expected_source_hash: ContentHash,
    },
}

/// A batch of mutations applied as one governed transaction: all prepared
/// before any live write, committed in deterministic (batch) order, each
/// verified after commit, with internal recovery on a partial-commit
/// failure. Never a free-form command; never unbounded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MutationBatch {
    pub mutations: Vec<Mutation>,
}

/// Hard resource bounds a [`MutationBatch`] is checked against during
/// PREPARE, before any live write. `UNBOUNDED_MUTATION_BATCH=NO`: every
/// field here is enforced, none is "advisory".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationLimits {
    pub max_mutation_count: usize,
    pub max_total_input_bytes: u64,
    pub max_total_staged_bytes: u64,
    pub max_edits_per_file: usize,
    pub max_total_edits: usize,
    pub max_journal_entries: usize,
    /// Bounds how much pre-mutation ("original") content this batch may
    /// capture for internal recovery purposes across every
    /// replace/edit/delete/move-source target combined. A file whose
    /// current content would exceed the remaining budget fails PREPARE
    /// closed (`ResourceLimitExceeded`) rather than proceeding without a
    /// recovery guarantee.
    pub max_recovery_capture_bytes: u64,
}

pub const DEFAULT_MAX_MUTATION_COUNT: usize = 256;
pub const DEFAULT_MAX_TOTAL_INPUT_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_STAGED_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_EDITS_PER_FILE: usize = 512;
pub const DEFAULT_MAX_TOTAL_EDITS: usize = 2048;
pub const DEFAULT_MAX_JOURNAL_ENTRIES: usize = 256;
pub const DEFAULT_MAX_RECOVERY_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;

impl Default for MutationLimits {
    fn default() -> Self {
        Self {
            max_mutation_count: DEFAULT_MAX_MUTATION_COUNT,
            max_total_input_bytes: DEFAULT_MAX_TOTAL_INPUT_BYTES,
            max_total_staged_bytes: DEFAULT_MAX_TOTAL_STAGED_BYTES,
            max_edits_per_file: DEFAULT_MAX_EDITS_PER_FILE,
            max_total_edits: DEFAULT_MAX_TOTAL_EDITS,
            max_journal_entries: DEFAULT_MAX_JOURNAL_ENTRIES,
            max_recovery_capture_bytes: DEFAULT_MAX_RECOVERY_CAPTURE_BYTES,
        }
    }
}

/// The verified, typed outcome of one committed mutation item, returned to
/// the caller as part of a successful [`crate::executor::MutationOutcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationResult {
    Created {
        path: WorkspacePath,
        hash: ContentHash,
    },
    Replaced {
        path: WorkspacePath,
        hash: ContentHash,
    },
    Deleted {
        path: WorkspacePath,
    },
    Moved {
        source: WorkspacePath,
        destination: WorkspacePath,
        hash: ContentHash,
    },
}
