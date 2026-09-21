// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Named, explicit bounds for every dimension a hostile or merely large
//! search request could otherwise exploit into unbounded work. Every named
//! constant here corresponds to a resource this crate would otherwise
//! accumulate or process without limit; a bound is enforced by returning a
//! `truncated` result or a `CorulixError::ResourceLimit`, never by silently
//! continuing unbounded work.

use wht_corulix_workspace::WalkLimits;

/// Maximum accepted query pattern length in bytes (literal or regex source
/// text, before compilation).
pub const DEFAULT_MAX_QUERY_BYTES: usize = 4096;

/// Maximum approximate compiled-program size accepted for a regex query,
/// passed to `grep_regex::RegexMatcherBuilder::size_limit`. Bounds
/// catastrophic regex compilation (e.g. large bounded repetition) rather
/// than only its matching-time behavior.
pub const DEFAULT_MAX_REGEX_SIZE: usize = 1_000_000;

/// Maximum per-thread DFA cache size accepted for a regex query, passed to
/// `grep_regex::RegexMatcherBuilder::dfa_size_limit`.
pub const DEFAULT_MAX_REGEX_DFA_SIZE: usize = 2_000_000;

/// Maximum number of matches returned for any single member root.
pub const DEFAULT_MAX_RESULTS_PER_ROOT: usize = 1_000;

/// Maximum number of matches returned across the whole `WorkspaceContext`,
/// regardless of how many roots it has -- this is the ceiling that prevents
/// an N-root context from multiplying an unbounded result set purely by
/// having more member roots.
pub const DEFAULT_MAX_RESULTS_TOTAL: usize = 5_000;

/// Maximum bytes retained for a single match's reported snippet. A snippet
/// longer than this is truncated and the match's `truncated` flag is set.
pub const DEFAULT_MAX_SNIPPET_BYTES: usize = 240;

/// Maximum bytes read for any single candidate file. A file whose reported
/// size exceeds this is skipped entirely (never partially read), consistent
/// with `wht_corulix_workspace::confined_read`'s own fail-closed contract.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum total bytes considered across every file in a single search
/// call, independent of the per-file bound above -- this is the
/// whole-context ceiling required in addition to (not instead of) the
/// per-file limit.
pub const DEFAULT_MAX_TOTAL_BYTES_SCANNED: u64 = 200 * 1024 * 1024;

/// Number of leading bytes inspected to decide whether a candidate file is
/// binary. A file is treated as binary, and skipped, if any NUL byte
/// appears within this many leading bytes -- the same deterministic
/// heuristic ripgrep itself uses by default, chosen here explicitly rather
/// than left to a library default so the policy is documented and stable
/// regardless of any dependency upgrade.
pub const BINARY_SNIFF_BYTES: usize = 8192;

/// Every bound a single [`crate::search`] call enforces. Every field has a
/// named default via [`SearchBounds::default`]; callers may tighten (never
/// widen beyond what Workspace traversal itself already bounds) any of
/// them.
#[derive(Debug, Clone)]
pub struct SearchBounds {
    pub max_query_bytes: usize,
    pub max_regex_size: usize,
    pub max_regex_dfa_size: usize,
    pub max_results_per_root: usize,
    pub max_results_total: usize,
    pub max_snippet_bytes: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes_scanned: u64,
    /// Delegated, not reimplemented: the same [`WalkLimits`] type
    /// `wht_corulix_workspace::confined_walk` itself takes, so file
    /// enumeration bounds are defined in exactly one place.
    pub walk_limits: WalkLimits,
}

impl Default for SearchBounds {
    fn default() -> Self {
        Self {
            max_query_bytes: DEFAULT_MAX_QUERY_BYTES,
            max_regex_size: DEFAULT_MAX_REGEX_SIZE,
            max_regex_dfa_size: DEFAULT_MAX_REGEX_DFA_SIZE,
            max_results_per_root: DEFAULT_MAX_RESULTS_PER_ROOT,
            max_results_total: DEFAULT_MAX_RESULTS_TOTAL,
            max_snippet_bytes: DEFAULT_MAX_SNIPPET_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes_scanned: DEFAULT_MAX_TOTAL_BYTES_SCANNED,
            walk_limits: WalkLimits::default(),
        }
    }
}
