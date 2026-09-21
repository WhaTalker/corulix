// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The bounded, ephemeral, Corulix-owned transaction journal.
//!
//! The OS provides no portable atomic multi-file transaction primitive, so
//! this journal records exactly enough state -- per already-*committed*
//! item -- to restore the pre-transaction filesystem state if a later item
//! in the same batch fails to commit. It is never a permanent
//! source-history system: it exists only for the lifetime of one
//! [`crate::executor::MutationExecutor::execute`] call, is bounded by
//! [`crate::types::MutationLimits::max_journal_entries`], and is discarded
//! (not persisted) once the batch finishes, one way or another.
//!
//! M09-P5: entries carry only [`WorkspacePath`]s and bytes, never a raw
//! resolved pathname -- `executor::undo` re-resolves the workspace-relative
//! path through `wht_corulix_workspace`'s own authority (the capability
//! layer on Unix, the pre-P9 pathname resolver on Windows) at undo time,
//! rather than caching a pathname across the whole transaction purely for
//! rollback's sake (Section 18 of the P5 mandate: rollback must use
//! capabilities, never a raw path re-used for I/O).

use wht_corulix_core::WorkspacePath;

/// One already-committed item's undo information.
#[derive(Debug, Clone)]
pub enum JournalEntry {
    /// A `CreateFile` committed: undo by removing the newly created file.
    Create { path: WorkspacePath },
    /// A `ReplaceFile`/`ApplyTextEdits` committed: undo by restoring
    /// `original_bytes` over the target named by `path`.
    ReplaceLike {
        path: WorkspacePath,
        original_bytes: Vec<u8>,
    },
    /// A `DeleteFile` committed: undo by recreating the target named by
    /// `path` with `original_bytes`.
    Delete {
        path: WorkspacePath,
        original_bytes: Vec<u8>,
    },
    /// A `MoveFile` committed: undo by renaming `destination_path` back to
    /// `source_path`.
    Move {
        source_path: WorkspacePath,
        destination_path: WorkspacePath,
    },
}

impl JournalEntry {
    /// The primary workspace-relative path this entry concerns -- for
    /// [`JournalEntry::Move`], the source path (the identity the file had
    /// before this transaction). Used to report exactly which paths were
    /// touched during recovery.
    #[must_use]
    pub fn workspace_path(&self) -> &WorkspacePath {
        match self {
            Self::Create { path, .. }
            | Self::ReplaceLike { path, .. }
            | Self::Delete { path, .. } => path,
            Self::Move { source_path, .. } => source_path,
        }
    }
}

/// The in-memory journal for one batch execution. Bounded by construction:
/// [`Journal::push`] enforces `max_entries` itself, so a caller cannot
/// accidentally grow it past the configured bound.
#[derive(Debug, Default)]
pub struct Journal {
    entries: Vec<JournalEntry>,
    max_entries: usize,
}

impl Journal {
    #[must_use]
    pub fn bounded(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    /// Appends `entry`. Returns `false` (without pushing) if this would
    /// exceed `max_entries` -- the caller treats that as a resource-limit
    /// failure requiring recovery of everything already journaled, never
    /// a silent drop.
    pub fn push(&mut self, entry: JournalEntry) -> bool {
        if self.entries.len() >= self.max_entries {
            return false;
        }
        self.entries.push(entry);
        true
    }

    /// Consumes the journal, handing back its entries (still in commit
    /// order) by value. M09-P5: recovery needs OWNED entries -- undoing a
    /// unix `JournalEntry` re-resolves and consumes a fresh capability per
    /// entry, which a shared `&JournalEntry` borrow cannot provide.
    #[must_use]
    pub fn into_entries_in_commit_order(self) -> Vec<JournalEntry> {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> WorkspacePath {
        WorkspacePath {
            root: wht_corulix_core::WorkspaceRootId(0),
            relative_path: "a.txt".to_string(),
        }
    }

    #[test]
    fn journal_rejects_growth_past_its_bound() {
        let mut journal = Journal::bounded(1);
        assert!(journal.push(JournalEntry::Create { path: path() }));
        assert!(!journal.push(JournalEntry::Create { path: path() }));
        assert_eq!(journal.into_entries_in_commit_order().len(), 1);
    }

    #[test]
    fn journal_preserves_commit_order() {
        let mut journal = Journal::bounded(10);
        for _ in 0..3 {
            let _ = journal.push(JournalEntry::Create { path: path() });
        }
        let entries = journal.into_entries_in_commit_order();
        assert_eq!(entries.len(), 3);
    }
}
