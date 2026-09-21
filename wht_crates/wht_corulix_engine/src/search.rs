// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13: the real, gated `search` capability behind the `search` MCP
//! tool.
//!
//! `ProviderCategory::TextSearch` is genuinely `Available` in
//! [`crate::providers::ProviderSnapshot::current`] -- unlike `semantic`/
//! `format_preview` (gated on `LanguageServer`/`Formatter`, both
//! unconditionally unavailable today), this capability's happy path is
//! actually reachable, so this module wires `wht_corulix_search::search`
//! for real rather than only proving a gate-check.
//!
//! `wht_corulix_mcp` never depends on `wht_corulix_search` directly
//! (Architecture Rule B); this module is the sole translation point between
//! that crate's rich, root-qualified result type and a flat, MCP-safe,
//! `schemars::JsonSchema`-deriving DTO.

use serde::Serialize;
use wht_corulix_core::{OperationIntent, PlanExecutability, ReasonCode};
use wht_corulix_search::{SearchBounds, SearchQuery, SearchScope};

use crate::CorulixEngine;

/// One textual match, flattened for MCP transport.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct SearchMatchOutcome {
    pub root_id: u32,
    pub relative_path: String,
    pub start_line_zero_based: u32,
    pub end_line_zero_based: u32,
    pub snippet: String,
    pub snippet_truncated: bool,
}

/// The full outcome of one `search` call: either the operation was blocked
/// before it ran (`Unavailable`, carrying the same [`ReasonCode`] a
/// [`wht_corulix_core::ToolPlan`] would), or it genuinely executed
/// (`Executed`).
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SearchOutcome {
    Unavailable {
        reason_code: ReasonCode,
    },
    Executed {
        matches: Vec<SearchMatchOutcome>,
        truncated: bool,
        files_scanned: u64,
        files_skipped_binary: u64,
        files_skipped_ignored: u64,
        files_skipped_too_large: u64,
        bytes_scanned: u64,
    },
    /// The plan was executable, but the real search call itself rejected
    /// the request (empty/oversized/invalid-regex pattern, or an unknown
    /// `root_selector`) -- a coarse, stable tag over
    /// [`wht_corulix_core::CorulixError`]'s own variants (which are not
    /// themselves serializable), never a raw error string as sole
    /// authority.
    Error {
        error_code: String,
        message: String,
    },
}

/// Caller-supplied search parameters, already validated at the MCP boundary
/// -- this module performs no client-input validation of its own beyond
/// what `wht_corulix_search::SearchQuery`/`SearchBounds` themselves enforce
/// fail-closed (empty pattern, oversized pattern, invalid regex).
pub struct SearchRequest {
    pub pattern: String,
    pub is_regex: bool,
    pub case_insensitive: bool,
    pub root_selector: Option<String>,
}

impl CorulixEngine {
    /// Runs a real, bounded, in-process text search against this engine's
    /// bound workspace, honoring Architecture Rule H: the executability
    /// gate is derived exactly once, through [`Self::plan_operation`], and
    /// `wht_corulix_mcp` never re-derives or bypasses it.
    pub async fn search(&self, request: SearchRequest) -> SearchOutcome {
        let plan = self.plan_operation(OperationIntent::TextSearch);
        if let PlanExecutability::Unexecutable { reason } = plan.executability {
            return SearchOutcome::Unavailable {
                reason_code: reason,
            };
        }

        let query = if request.is_regex {
            SearchQuery::regex(request.pattern)
        } else {
            SearchQuery::literal(request.pattern)
        }
        .case_insensitive(request.case_insensitive);

        let scope = match &request.root_selector {
            None => SearchScope::AllRoots,
            Some(selector) => match self.resolve_root_id(selector) {
                Ok(id) => SearchScope::Root(id),
                Err(error) => {
                    return SearchOutcome::Error {
                        error_code: crate::corulix_error_code(&error).to_string(),
                        message: error.to_string(),
                    };
                }
            },
        };

        match wht_corulix_search::search(
            self.context_owned(),
            query,
            scope,
            SearchBounds::default(),
        )
        .await
        {
            Ok(results) => SearchOutcome::Executed {
                matches: results
                    .matches
                    .into_iter()
                    .map(|found| SearchMatchOutcome {
                        root_id: found.workspace_root_id.0,
                        relative_path: found.workspace_relative_path,
                        start_line_zero_based: found.range.start.line_zero_based,
                        end_line_zero_based: found.range.end.line_zero_based,
                        snippet: found.snippet,
                        snippet_truncated: found.snippet_truncated,
                    })
                    .collect(),
                truncated: results.truncated,
                files_scanned: results.files_scanned,
                files_skipped_binary: results.files_skipped_binary,
                files_skipped_ignored: results.files_skipped_ignored,
                files_skipped_too_large: results.files_skipped_too_large,
                bytes_scanned: results.bytes_scanned,
            },
            Err(error) => SearchOutcome::Error {
                error_code: crate::corulix_error_code(&error).to_string(),
                message: error.to_string(),
            },
        }
    }
}

/// Test-only helper kept private to this module: matches `QueryKind`'s
/// presence in scope without an unused-import warning when no test in this
/// module directly references it yet.
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::CorulixResult;
    use wht_corulix_workspace::WorkspaceContext;

    fn temp_workspace(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-engine-search-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    #[tokio::test]
    async fn search_finds_a_real_literal_match() -> CorulixResult<()> {
        let root_dir = temp_workspace("literal");
        fs::write(root_dir.join("main.rs"), "fn corulix_marker() {}")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = CorulixEngine::open(context);

        let outcome = engine
            .search(SearchRequest {
                pattern: "corulix_marker".to_string(),
                is_regex: false,
                case_insensitive: false,
                root_selector: None,
            })
            .await;

        let SearchOutcome::Executed { matches, .. } = outcome else {
            unreachable!(
                "search::TextSearch is unconditionally Available in ProviderSnapshot::current()"
            );
        };
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].relative_path, "main.rs");

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    #[tokio::test]
    async fn search_with_no_matches_is_executed_not_unavailable() -> CorulixResult<()> {
        let root_dir = temp_workspace("empty");
        fs::write(root_dir.join("main.rs"), "fn other() {}")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = CorulixEngine::open(context);

        let outcome = engine
            .search(SearchRequest {
                pattern: "does_not_exist_anywhere".to_string(),
                is_regex: false,
                case_insensitive: false,
                root_selector: None,
            })
            .await;

        let SearchOutcome::Executed { matches, .. } = outcome else {
            unreachable!(
                "search::TextSearch is unconditionally Available in ProviderSnapshot::current()"
            );
        };
        assert!(matches.is_empty());

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }
}
