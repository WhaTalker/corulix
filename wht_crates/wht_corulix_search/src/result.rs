// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed search results. Every result is root-qualified: this crate never
//! reports a bare relative path in a `MultiRoot` context, since the same
//! relative path can legitimately exist in more than one member root.
//!
//! These results are facts only -- a matched byte range and a bounded
//! snippet of surrounding text. This crate never claims definition,
//! reference, rename, type, or semantic-diagnostic authority over a match;
//! that authority belongs exclusively to a future LSP-backed provider.

use wht_corulix_core::{SourceRange, WorkspaceRootId};

/// Which matching mode produced a given [`SearchMatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Literal,
    Regex,
}

/// One matched location. `workspace_relative_path` is always paired with
/// `workspace_root_id` -- the pair together is the only way this crate ever
/// names a location, precisely so that identical relative paths in two
/// different member roots remain distinguishable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    pub workspace_root_id: WorkspaceRootId,
    pub workspace_relative_path: String,
    pub range: SourceRange,
    /// Bounded to at most `SearchBounds::max_snippet_bytes`; see
    /// `snippet_truncated`.
    pub snippet: String,
    pub match_kind: MatchKind,
    /// `true` if `snippet` was cut short of the full matched line to stay
    /// within the snippet byte bound -- distinct from
    /// [`SearchResults::truncated`], which reports whether the *result set
    /// itself* is incomplete.
    pub snippet_truncated: bool,
}

/// The full, bounded outcome of one [`crate::search`] call.
#[derive(Debug, Clone, Default)]
pub struct SearchResults {
    /// Deterministically ordered: by `workspace_root_id`, then by
    /// `workspace_relative_path`, then by match position within the file --
    /// never by arbitrary filesystem directory enumeration order.
    pub matches: Vec<SearchMatch>,
    /// `true` if any bound (per-root results, whole-context results, or
    /// whole-context bytes scanned) caused this call to stop before every
    /// candidate file was considered. A bounded, structured result is
    /// returned in that case -- this call never continues scanning
    /// unbounded, and never fails merely because a bound was reached.
    pub truncated: bool,
    pub files_scanned: u64,
    pub files_skipped_binary: u64,
    pub files_skipped_ignored: u64,
    pub files_skipped_too_large: u64,
    pub bytes_scanned: u64,
}
