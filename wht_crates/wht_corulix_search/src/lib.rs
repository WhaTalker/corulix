// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Sole owner of the embedded ripgrep-family textual search implementation
//! for WhaTalker Corulix (Architecture Rule D).
//!
//! `TEXT_DISCOVERY_AUTHORITY=YES`, `SEMANTIC_AUTHORITY=NO`: this crate finds
//! textual/structural candidates only. It never claims definition,
//! reference, rename, type-correctness, or semantic-diagnostic authority --
//! those belong to a future LSP-backed provider layer.
//!
//! This crate consumes an already-resolved
//! `wht_corulix_workspace::WorkspaceContext` as its sole input authority. It
//! never discovers a workspace, never parses a `.code-workspace`
//! descriptor, never canonicalizes a path, and never implements its own
//! filesystem walker -- every one of those responsibilities remains
//! exclusively `wht_corulix_workspace`'s (Architecture Rule F, unchanged by
//! this crate's existence). Search delegates file enumeration to
//! `confined_walk`/`confined_walk_all` and bounded file bytes to
//! `confined_read`, and depends on nothing beyond `wht_corulix_core` and
//! `wht_corulix_workspace` plus the admitted ripgrep-family crates
//! (`ignore`, `grep-matcher`, `grep-regex`, `grep-searcher`).
//!
//! No external `rg` process is ever spawned: matching runs entirely inside
//! this process via the embedded `grep-regex`/`grep-searcher` crates.

mod bounds;
mod engine;
mod ignore_policy;
mod query;
mod result;

pub use bounds::{
    BINARY_SNIFF_BYTES, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_QUERY_BYTES,
    DEFAULT_MAX_REGEX_DFA_SIZE, DEFAULT_MAX_REGEX_SIZE, DEFAULT_MAX_RESULTS_PER_ROOT,
    DEFAULT_MAX_RESULTS_TOTAL, DEFAULT_MAX_SNIPPET_BYTES, DEFAULT_MAX_TOTAL_BYTES_SCANNED,
    SearchBounds,
};
pub use engine::search;
pub use query::{QueryKind, SearchQuery, SearchScope};
pub use result::{MatchKind, SearchMatch, SearchResults};
