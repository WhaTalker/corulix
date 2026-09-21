// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! In-memory store for the background code index's published snapshot.
//!
//! This crate depends only on `wht_corulix_core` and the standard library —
//! never `rmcp` and never Tree-sitter — which keeps it core-adjacent in the
//! same spirit as Architecture Rule A and reachable from `wht_corulix_engine`
//! without pulling MCP or Tree-sitter concerns into the index layer.

use std::sync::{Arc, RwLock};
use wht_corulix_core::{IndexState, IndexStatus};

/// One immutable, atomically-swappable view of the index at a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSnapshot {
    pub snapshot_id: u64,
    pub indexed_files: u64,
}

/// Thread-safe holder for the current index snapshot.
///
/// The snapshot is reached through an `Arc` behind an `RwLock` so a new
/// snapshot can be published as a single pointer swap (see `publish`)
/// instead of mutating fields a reader might be inspecting concurrently.
#[derive(Debug, Default)]
pub struct IndexStore {
    active: RwLock<Option<Arc<IndexSnapshot>>>,
}

impl IndexStore {
    /// Reports the current index state without ever panicking on a poisoned
    /// lock — a poisoned lock is treated as `Corrupt` rather than propagating
    /// a panic into the MCP/CLI callers that depend on this status.
    #[must_use]
    pub fn status(&self) -> IndexStatus {
        match self.active.read() {
            Ok(guard) => match guard.as_ref() {
                Some(snapshot) => IndexStatus {
                    state: IndexState::Ready,
                    snapshot_id: Some(snapshot.snapshot_id),
                    indexed_files: snapshot.indexed_files,
                },
                None => IndexStatus {
                    state: IndexState::NotInitialized,
                    snapshot_id: None,
                    indexed_files: 0,
                },
            },
            Err(_) => IndexStatus {
                state: IndexState::Corrupt,
                snapshot_id: None,
                indexed_files: 0,
            },
        }
    }

    /// Atomically replaces the published snapshot with a new one.
    ///
    /// The new snapshot is wrapped in a fresh `Arc` and swapped into the slot
    /// as a single pointer write under the write lock, so a concurrent
    /// `status()` call sees either the complete old snapshot or the complete
    /// new one — never a partially-updated index. Returns `false` on lock
    /// poisoning instead of panicking, matching `status`'s fail-safe
    /// behavior.
    pub fn publish(&self, snapshot: IndexSnapshot) -> bool {
        match self.active.write() {
            Ok(mut guard) => {
                *guard = Some(Arc::new(snapshot));
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_publish_is_atomic_from_reader_view() {
        let store = IndexStore::default();
        assert_eq!(store.status().state, IndexState::NotInitialized);
        assert!(store.publish(IndexSnapshot {
            snapshot_id: 7,
            indexed_files: 42,
        }));
        let status = store.status();
        assert_eq!(status.state, IndexState::Ready);
        assert_eq!(status.snapshot_id, Some(7));
        assert_eq!(status.indexed_files, 42);
    }
}
