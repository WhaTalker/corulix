// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-root workspace topology contracts.
//!
//! These types describe the *shape* of a resolved logical workspace
//! (single filesystem root, or multiple roots imported from a
//! `.code-workspace` descriptor) without any filesystem I/O, JSON/JSONC
//! parsing, or VS Code awareness -- that parsing lives exclusively in
//! `wht_corulix_workspace`. Core stays filesystem-free.

use serde::{Deserialize, Serialize};

/// Whether a resolved [`WorkspaceContext`](../index.html) (defined in
/// `wht_corulix_workspace`) has one filesystem root or several.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum WorkspaceTopologyKind {
    SingleRoot,
    MultiRoot,
}

/// An opaque, non-secret identifier for one member root within a
/// [`WorkspaceTopologyKind::MultiRoot`] context.
///
/// Not authorization, not authentication -- a display name or path can
/// never resolve to a root on its own; only this identifier (assigned
/// deterministically by enumeration order, stable for the context's
/// process lifetime) may select one.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct WorkspaceRootId(pub u32);

/// A root-qualified, workspace-relative path: which member root, and the
/// path relative to that root's canonical directory.
///
/// Never "try this relative path against every root and use the first
/// hit" -- every `WorkspacePath` names its root explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkspacePath {
    pub root: WorkspaceRootId,
    pub relative_path: String,
}

/// Safe, redacted metadata about one member root -- never the raw
/// canonical absolute path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkspaceRootSummary {
    pub root: WorkspaceRootId,
    pub display_name: String,
}

/// A safe, client-facing summary of an entire resolved workspace's shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkspaceTopologySummary {
    pub topology: WorkspaceTopologyKind,
    pub roots: Vec<WorkspaceRootSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_id_is_distinct_from_display_name() {
        let a = WorkspaceRootSummary {
            root: WorkspaceRootId(0),
            display_name: "api".to_string(),
        };
        let b = WorkspaceRootSummary {
            root: WorkspaceRootId(1),
            display_name: "api".to_string(),
        };
        // Two roots may legitimately share a display name; their IDs must
        // still be distinct -- display name is metadata, never identity.
        assert_ne!(a.root, b.root);
        assert_eq!(a.display_name, b.display_name);
    }

    #[test]
    fn topology_summary_carries_topology_and_roots_together() {
        let summary = WorkspaceTopologySummary {
            topology: WorkspaceTopologyKind::MultiRoot,
            roots: vec![
                WorkspaceRootSummary {
                    root: WorkspaceRootId(0),
                    display_name: "a".to_string(),
                },
                WorkspaceRootSummary {
                    root: WorkspaceRootId(1),
                    display_name: "b".to_string(),
                },
            ],
        };
        assert_eq!(summary.topology, WorkspaceTopologyKind::MultiRoot);
        assert_eq!(summary.roots.len(), 2);
    }
}
