// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! `WorkspaceContext`: the logical, single- or multi-root workspace bound to
//! one Corulix process for its entire lifetime.
//!
//! One `.code-workspace` (or one `--workspace` directory) always produces
//! exactly one `WorkspaceContext`, never one Corulix session per member
//! folder. Confinement itself is unchanged by multi-root support: every
//! operation is always confined against exactly one member
//! [`WorkspaceRoot`], selected explicitly (never guessed) when more than
//! one root exists.

use crate::confine::{ConfinedPath, WalkLimits, WorkspaceRoot, confined_walk};
use std::path::{Path, PathBuf};
use wht_corulix_core::{
    CorulixError, CorulixResult, WorkspaceRootId, WorkspaceRootSummary, WorkspaceTopologyKind,
    WorkspaceTopologySummary,
};

/// Bounded so a pathological multi-root context cannot force unbounded
/// allocation or an unbounded number of confinement checks. Comfortably
/// above the owner's own real 8-folder `.code-workspace` example.
pub const MAX_WORKSPACE_ROOTS: usize = 64;

#[derive(Debug, Clone)]
struct MemberRoot {
    id: WorkspaceRootId,
    root: WorkspaceRoot,
    display_name: String,
}

/// The logical workspace bound to one Corulix process. Immutable for the
/// process's lifetime -- changing workspace requires a new process.
#[derive(Debug, Clone)]
pub struct WorkspaceContext {
    members: Vec<MemberRoot>,
}

impl WorkspaceContext {
    /// A `SingleRoot` context wrapping exactly one already-validated root.
    #[must_use]
    pub fn single_root(root: WorkspaceRoot, display_name: String) -> Self {
        Self {
            members: vec![MemberRoot {
                id: WorkspaceRootId(0),
                root,
                display_name,
            }],
        }
    }

    /// Builds a context from a list of already-validated, already-resolved
    /// `(root, display_name)` pairs (e.g. from a parsed `.code-workspace`
    /// descriptor). Root IDs are assigned by enumeration order (index 0..N),
    /// never derived from display name.
    ///
    /// Fails closed on: zero roots, more than [`MAX_WORKSPACE_ROOTS`],
    /// duplicate canonical roots, and overlapping roots (one root being an
    /// ancestor of another) -- V1 policy prefers rejection over an
    /// undefined-behavior indexing/search story for either case.
    pub fn from_roots(roots: Vec<(WorkspaceRoot, String)>) -> CorulixResult<Self> {
        if roots.is_empty() {
            return Err(CorulixError::InvalidInput(
                "a workspace context requires at least one root".into(),
            ));
        }
        if roots.len() > MAX_WORKSPACE_ROOTS {
            return Err(CorulixError::ResourceLimit);
        }
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                let a = roots[i].0.canonical_path();
                let b = roots[j].0.canonical_path();
                if a == b {
                    return Err(CorulixError::InvalidInput(
                        "duplicate canonical workspace root".into(),
                    ));
                }
                if a.starts_with(b) || b.starts_with(a) {
                    return Err(CorulixError::InvalidInput(
                        "overlapping workspace roots are not permitted".into(),
                    ));
                }
            }
        }
        let members = roots
            .into_iter()
            .enumerate()
            .map(|(index, (root, display_name))| {
                #[allow(clippy::cast_possible_truncation)]
                let id = WorkspaceRootId(index as u32);
                MemberRoot {
                    id,
                    root,
                    display_name,
                }
            })
            .collect();
        Ok(Self { members })
    }

    #[must_use]
    pub fn topology(&self) -> WorkspaceTopologyKind {
        if self.members.len() == 1 {
            WorkspaceTopologyKind::SingleRoot
        } else {
            WorkspaceTopologyKind::MultiRoot
        }
    }

    #[must_use]
    pub fn root_count(&self) -> usize {
        self.members.len()
    }

    #[must_use]
    pub fn summary(&self) -> WorkspaceTopologySummary {
        WorkspaceTopologySummary {
            topology: self.topology(),
            roots: self.root_summaries(),
        }
    }

    #[must_use]
    pub fn root_summaries(&self) -> Vec<WorkspaceRootSummary> {
        self.members
            .iter()
            .map(|member| WorkspaceRootSummary {
                root: member.id,
                display_name: member.display_name.clone(),
            })
            .collect()
    }

    /// Resolves which member root a root-scoped operation should target.
    ///
    /// A `SingleRoot` context always selects its only member, ignoring
    /// `selector` entirely. A `MultiRoot` context requires an explicit,
    /// non-ambiguous selector: `None` fails (no first-root guessing), an
    /// unrecognized name/id fails, and a display name shared by two or more
    /// roots fails as ambiguous -- display names are metadata, never
    /// security identity; only a uniquely-matching name or the opaque
    /// numeric [`WorkspaceRootId`] may select a root.
    pub fn resolve_root(&self, selector: Option<&str>) -> CorulixResult<&WorkspaceRoot> {
        if self.members.len() == 1 {
            return Ok(&self.members[0].root);
        }
        // Every failure branch below is a workspace *selection* problem,
        // not a generic invalid-input or internal error -- `WorkspaceNotFound`
        // is reused deliberately (rather than `InvalidInput`) so callers
        // (the CLI's exit-code classifier) can distinguish "the requested
        // root could not be resolved" from an unrelated operational failure.
        let Some(selector) = selector else {
            return Err(CorulixError::WorkspaceNotFound);
        };
        let name_matches: Vec<&MemberRoot> = self
            .members
            .iter()
            .filter(|member| member.display_name == selector)
            .collect();
        match name_matches.len() {
            1 => return Ok(&name_matches[0].root),
            n if n > 1 => {
                return Err(CorulixError::WorkspaceNotFound);
            }
            _ => {}
        }
        if let Ok(id) = selector.parse::<u32>()
            && let Some(member) = self.members.iter().find(|member| member.id.0 == id)
        {
            return Ok(&member.root);
        }
        Err(CorulixError::WorkspaceNotFound)
    }

    /// Confined, bounded, symlink-safe traversal across every member root.
    /// Filesystem security is delegated entirely to [`confined_walk`] (the
    /// same per-root primitive used everywhere else) -- this coordinator
    /// only iterates roots and tags each result with its
    /// [`WorkspaceRootId`], never reimplementing confinement itself.
    /// Enforces both a per-root limit (via `limits`) and a whole-context
    /// limit (`global_max_entries`).
    ///
    /// `async fn`: each member root's walk awaits [`confined_walk`]'s own
    /// canonical async entry point directly (this coordinator has no CPU
    /// work of its own to bound behind a `spawn_blocking` -- it only
    /// iterates and tags), never blocking an async caller's executor thread
    /// on the underlying directory traversal.
    pub async fn confined_walk_all(
        &self,
        scope: PathBuf,
        limits: WalkLimits,
        global_max_entries: usize,
    ) -> CorulixResult<Vec<(WorkspaceRootId, ConfinedPath)>> {
        let mut all = Vec::new();
        for member in &self.members {
            for path in confined_walk(member.root.clone(), scope.clone(), limits).await? {
                if all.len() >= global_max_entries {
                    return Err(CorulixError::ResourceLimit);
                }
                all.push((member.id, path));
            }
        }
        Ok(all)
    }
}

/// Whether every one of `roots` resolves to a location at or under
/// `boundary`. Used only to police an *auto-discovered* (not explicitly
/// selected) `.code-workspace`: if any referenced root lies outside the
/// descriptor's own directory, auto-discovery must not silently widen the
/// filesystem boundary -- the caller (the resolver) turns a `false` result
/// here into a fail-closed "explicit selection required" outcome. An
/// operator-selected `--workspace-file`/`CORULIX_WORKSPACE_FILE` never calls
/// this check: the operator already explicitly authorized whatever
/// topology that descriptor names.
#[must_use]
pub fn all_roots_within_boundary(boundary: &Path, roots: &[(WorkspaceRoot, String)]) -> bool {
    roots
        .iter()
        .all(|(root, _)| root.canonical_path().starts_with(boundary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-context-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    #[test]
    fn single_root_topology_is_single_root() -> CorulixResult<()> {
        let dir = temp_dir("a");
        let root = WorkspaceRoot::open(&dir)?;
        let context = WorkspaceContext::single_root(root, "project".to_string());
        assert_eq!(context.topology(), WorkspaceTopologyKind::SingleRoot);
        assert_eq!(context.root_count(), 1);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn multi_root_topology_from_two_distinct_roots() -> CorulixResult<()> {
        let a = temp_dir("a");
        let b = temp_dir("b");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "a".to_string()),
            (WorkspaceRoot::open(&b)?, "b".to_string()),
        ])?;
        assert_eq!(context.topology(), WorkspaceTopologyKind::MultiRoot);
        assert_eq!(context.root_count(), 2);
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[test]
    fn duplicate_canonical_roots_are_rejected() -> CorulixResult<()> {
        let a = temp_dir("dup");
        let result = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "one".to_string()),
            (WorkspaceRoot::open(&a)?, "two".to_string()),
        ]);
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&a);
        Ok(())
    }

    #[test]
    fn overlapping_roots_are_rejected() -> CorulixResult<()> {
        let parent = temp_dir("parent");
        let child = parent.join("child");
        let _ = fs::create_dir_all(&child);
        let result = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&parent)?, "parent".to_string()),
            (WorkspaceRoot::open(&child)?, "child".to_string()),
        ]);
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&parent);
        Ok(())
    }

    #[test]
    fn empty_roots_is_rejected() {
        assert!(WorkspaceContext::from_roots(Vec::new()).is_err());
    }

    #[test]
    fn single_root_resolve_ignores_selector() -> CorulixResult<()> {
        let dir = temp_dir("single-resolve");
        let context = WorkspaceContext::single_root(WorkspaceRoot::open(&dir)?, "solo".to_string());
        assert!(context.resolve_root(None).is_ok());
        assert!(context.resolve_root(Some("anything")).is_ok());
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn multi_root_resolve_requires_selector() -> CorulixResult<()> {
        let a = temp_dir("ma");
        let b = temp_dir("mb");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "a".to_string()),
            (WorkspaceRoot::open(&b)?, "b".to_string()),
        ])?;
        assert!(context.resolve_root(None).is_err());
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[test]
    fn multi_root_resolve_by_name_selects_exact_root() -> CorulixResult<()> {
        let a = temp_dir("na");
        let b = temp_dir("nb");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "alpha".to_string()),
            (WorkspaceRoot::open(&b)?, "beta".to_string()),
        ])?;
        let resolved = context.resolve_root(Some("beta"))?;
        assert_eq!(
            resolved.canonical_path(),
            WorkspaceRoot::open(&b)?.canonical_path()
        );
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[test]
    fn multi_root_resolve_unknown_selector_fails() -> CorulixResult<()> {
        let a = temp_dir("ua");
        let b = temp_dir("ub");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "alpha".to_string()),
            (WorkspaceRoot::open(&b)?, "beta".to_string()),
        ])?;
        assert!(context.resolve_root(Some("gamma")).is_err());
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[test]
    fn multi_root_resolve_ambiguous_display_name_fails() -> CorulixResult<()> {
        let a = temp_dir("aa");
        let b = temp_dir("ab");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "same".to_string()),
            (WorkspaceRoot::open(&b)?, "same".to_string()),
        ])?;
        assert!(context.resolve_root(Some("same")).is_err());
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[tokio::test]
    async fn confined_walk_all_tags_entries_with_root_id() -> CorulixResult<()> {
        let a = temp_dir("wa");
        let b = temp_dir("wb");
        let _ = fs::write(a.join("one.rs"), "");
        let _ = fs::write(b.join("two.rs"), "");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "a".to_string()),
            (WorkspaceRoot::open(&b)?, "b".to_string()),
        ])?;
        let results = context
            .confined_walk_all(PathBuf::from("."), WalkLimits::default(), 100)
            .await?;
        assert_eq!(results.len(), 2);
        let mut root_ids: Vec<u32> = results.iter().map(|(id, _)| id.0).collect();
        root_ids.sort_unstable();
        assert_eq!(root_ids, vec![0, 1]);
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[test]
    fn escaping_root_a_into_root_b_is_rejected() -> CorulixResult<()> {
        let a = temp_dir("esc-a");
        let b = temp_dir("esc-b");
        let _ = fs::write(b.join("secret.rs"), "");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "a".to_string()),
            (WorkspaceRoot::open(&b)?, "b".to_string()),
        ])?;
        let root_a = context.resolve_root(Some("a"))?;
        // A relative path that would only resolve inside Root B must still
        // be denied when confined against Root A -- landing inside an
        // authorized sibling root does not make an escape from the
        // requested root acceptable.
        let escape_attempt =
            crate::confine::resolve_confined_blocking(root_a, Path::new("../")).map(|_| ());
        assert!(escape_attempt.is_err());
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[test]
    fn all_roots_within_boundary_detects_external_root() -> CorulixResult<()> {
        let boundary = temp_dir("boundary");
        let outside = temp_dir("outside");
        let roots = vec![(WorkspaceRoot::open(&outside)?, "outside".to_string())];
        assert!(!all_roots_within_boundary(&boundary, &roots));
        let _ = fs::remove_dir_all(&boundary);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn all_roots_within_boundary_accepts_internal_root() -> CorulixResult<()> {
        let boundary = temp_dir("inboundary");
        let nested = boundary.join("nested");
        let _ = fs::create_dir_all(&nested);
        let boundary_canonical = WorkspaceRoot::open(&boundary)?;
        let roots = vec![(WorkspaceRoot::open(&nested)?, "nested".to_string())];
        assert!(all_roots_within_boundary(
            boundary_canonical.canonical_path(),
            &roots
        ));
        let _ = fs::remove_dir_all(&boundary);
        Ok(())
    }
}
