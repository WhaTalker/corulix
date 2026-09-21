// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed search request shape: what to look for, and in which member root(s)
//! of a [`wht_corulix_workspace::WorkspaceContext`] to look for it.

use wht_corulix_core::WorkspaceRootId;

/// Whether the query pattern is matched literally (escaped, no regex
/// metacharacters) or as a regular expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind {
    Literal,
    Regex,
}

/// A single search request. Never carries a raw filesystem path -- only a
/// pattern and matching mode; scope is expressed separately via
/// [`SearchScope`], and traversal/confinement always come from the caller's
/// already-resolved `WorkspaceContext`.
#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub pattern: String,
    pub kind: QueryKind,
    pub case_insensitive: bool,
}

impl SearchQuery {
    #[must_use]
    pub fn literal(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            kind: QueryKind::Literal,
            case_insensitive: false,
        }
    }

    #[must_use]
    pub fn regex(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            kind: QueryKind::Regex,
            case_insensitive: false,
        }
    }

    #[must_use]
    pub fn case_insensitive(mut self, case_insensitive: bool) -> Self {
        self.case_insensitive = case_insensitive;
        self
    }
}

/// Which member root(s) of the `WorkspaceContext` a search call targets.
/// There is no "try every root, use first match" mode: [`SearchScope::Root`]
/// always names exactly one [`WorkspaceRootId`], resolved the same way
/// `WorkspaceContext::resolve_root` resolves any other root-scoped
/// operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    AllRoots,
    Root(WorkspaceRootId),
}
