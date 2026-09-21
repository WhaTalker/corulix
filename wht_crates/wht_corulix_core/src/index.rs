// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Background code-index lifecycle contract.

use serde::{Deserialize, Serialize};

/// Lifecycle state of the background code index, reported so a client can
/// distinguish "no index yet" from a corrupted or stale one instead of
/// treating every non-ready state as a generic failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum IndexState {
    NotInitialized,
    Building,
    Ready,
    Stale,
    Degraded,
    Corrupt,
    RebuildRequired,
}

/// Snapshot of the index's current state, exposed identifier, and size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IndexStatus {
    pub state: IndexState,
    pub snapshot_id: Option<u64>,
    pub indexed_files: u64,
}
