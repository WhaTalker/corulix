// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! One deterministic, repository-local ignore policy.
//!
//! Repository `.gitignore` files are hints, never a security boundary: this
//! module only ever *narrows* the file set that `wht_corulix_workspace`
//! traversal already bounded and confined -- it can never widen scope,
//! discover new roots, or bypass confinement. It reads exactly the
//! `.gitignore` files this crate itself discovers among the *already
//! confined and walked* entries for one root; it never calls
//! `ignore::gitignore::Gitignore::new` or `Gitignore::build_global` (both of
//! which would pull in ambient user/global Git configuration such as
//! `core.excludesFile` or `.git/info/exclude`), and it never constructs the
//! `ignore` crate's own independent recursive directory walker (that would
//! be a second, independent filesystem traversal authority, which
//! Architecture Rule F forbids).
//!
//! Hidden (dot-prefixed) files are not treated as ignored merely for being
//! hidden -- the deterministic policy is exactly "match the accumulated
//! `.gitignore` glob rules", nothing more.
//!
//! Nested-ignore semantics: one [`ignore::gitignore::Gitignore`] matcher is
//! built per directory that contains a `.gitignore`, anchored at that
//! directory (matching real `git`'s own per-directory scoping -- a single
//! shared matcher anchored only at the workspace root cannot correctly
//! confine a nested `.gitignore`'s rules to its own subtree). A candidate
//! path is checked against every anchor that contains it, evaluated
//! shallowest-to-deepest; the deepest anchor with a non-`None` verdict wins,
//! which is what allows a deeper, more specific `.gitignore` to override or
//! negate a shallower one for paths under its own subtree.

use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::{Path, PathBuf};

/// A root's combined, per-directory ignore policy.
pub struct IgnorePolicy {
    /// `(anchor_directory, matcher)` pairs, sorted shallowest-anchor-first.
    anchors: Vec<(PathBuf, Gitignore)>,
}

impl IgnorePolicy {
    /// Whether `absolute_path` (which must live under this policy's root)
    /// is ignored, considering every applicable anchor shallowest-to-deepest.
    #[must_use]
    pub fn is_ignored(&self, absolute_path: &Path, is_dir: bool) -> bool {
        let mut verdict: Match<&ignore::gitignore::Glob> = Match::None;
        for (anchor, matcher) in &self.anchors {
            if !absolute_path.starts_with(anchor) {
                continue;
            }
            let candidate = matcher.matched_path_or_any_parents(absolute_path, is_dir);
            if !matches!(candidate, Match::None) {
                verdict = candidate;
            }
        }
        matches!(verdict, Match::Ignore(_))
    }
}

/// Builds one [`IgnorePolicy`] for a root, from every `.gitignore` file
/// present among `candidates` (already-confined, root-relative entries
/// paired with their confined absolute path). Never touches the filesystem
/// beyond reading the `.gitignore` files themselves -- discovery of which
/// files exist was already performed by the caller's `confined_walk`.
#[must_use]
pub fn build_ignore_policy(candidates: &[(String, PathBuf)]) -> IgnorePolicy {
    let mut gitignore_files: Vec<&PathBuf> = candidates
        .iter()
        .filter(|(relative, _)| relative == ".gitignore" || relative.ends_with("/.gitignore"))
        .map(|(_, confined)| confined)
        .collect();
    // Deterministic order: shallowest anchor directory first (by path
    // length), then lexicographic -- never dependent on filesystem
    // read_dir enumeration order.
    gitignore_files.sort_by(|a, b| {
        let depth_a = a.components().count();
        let depth_b = b.components().count();
        depth_a.cmp(&depth_b).then_with(|| a.cmp(b))
    });

    let mut anchors = Vec::new();
    for gitignore_path in gitignore_files {
        let Some(anchor_dir) = gitignore_path.parent() else {
            continue;
        };
        let mut builder = GitignoreBuilder::new(anchor_dir);
        // `GitignoreBuilder::add` returns `Some(Error)` only for a
        // partially-malformed file (some globs still applied); a hostile or
        // malformed `.gitignore` must never abort or panic the search, so
        // the return value is intentionally not propagated as a hard error.
        let _ = builder.add(gitignore_path);
        if let Ok(matcher) = builder.build() {
            anchors.push((anchor_dir.to_path_buf(), matcher));
        }
    }

    IgnorePolicy { anchors }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("corulix-search-ignore-test-{label}-{stamp}"))
    }

    #[test]
    fn no_gitignore_present_matches_nothing() {
        let root = temp_dir("none");
        let _ = fs::create_dir_all(&root);
        let policy = build_ignore_policy(&[]);
        assert!(!policy.is_ignored(&root.join("anything.rs"), false));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn root_gitignore_ignores_matching_file() {
        let root = temp_dir("root-rule");
        let _ = fs::create_dir_all(&root);
        let gitignore = root.join(".gitignore");
        let _ = fs::write(&gitignore, "target/\n*.log\n");
        let candidates = vec![
            (".gitignore".to_string(), gitignore.clone()),
            ("debug.log".to_string(), root.join("debug.log")),
        ];
        let policy = build_ignore_policy(&candidates);
        assert!(policy.is_ignored(&root.join("debug.log"), false));
        assert!(!policy.is_ignored(&root.join("keep.rs"), false));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nested_gitignore_applies_within_its_subtree() {
        let root = temp_dir("nested-rule");
        let nested = root.join("nested");
        let _ = fs::create_dir_all(&nested);
        let nested_gitignore = nested.join(".gitignore");
        let _ = fs::write(&nested_gitignore, "secret.rs\n");
        let candidates = vec![("nested/.gitignore".to_string(), nested_gitignore.clone())];
        let policy = build_ignore_policy(&candidates);
        assert!(policy.is_ignored(&nested.join("secret.rs"), false));
        // The nested `.gitignore`'s rule must not leak up to the root --
        // this is the failure mode a single root-anchored matcher produces.
        assert!(!policy.is_ignored(&root.join("secret.rs"), false));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn deeper_gitignore_overrides_shallower_one_for_its_own_subtree() {
        let root = temp_dir("override");
        let nested = root.join("nested");
        let _ = fs::create_dir_all(&nested);
        let _ = fs::write(root.join(".gitignore"), "*.log\n");
        let _ = fs::write(nested.join(".gitignore"), "!keep.log\n");
        let candidates = vec![
            (".gitignore".to_string(), root.join(".gitignore")),
            ("nested/.gitignore".to_string(), nested.join(".gitignore")),
        ];
        let policy = build_ignore_policy(&candidates);
        // Outside the nested subtree, the root rule still applies.
        assert!(policy.is_ignored(&root.join("debug.log"), false));
        // Inside the nested subtree, the deeper, more specific negation wins.
        assert!(!policy.is_ignored(&nested.join("keep.log"), false));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn negated_rule_restores_a_file() {
        let root = temp_dir("negated");
        let _ = fs::create_dir_all(&root);
        let gitignore = root.join(".gitignore");
        let _ = fs::write(&gitignore, "*.log\n!important.log\n");
        let candidates = vec![(".gitignore".to_string(), gitignore.clone())];
        let policy = build_ignore_policy(&candidates);
        assert!(policy.is_ignored(&root.join("debug.log"), false));
        assert!(!policy.is_ignored(&root.join("important.log"), false));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn hidden_file_is_not_ignored_merely_for_being_hidden() {
        let root = temp_dir("hidden");
        let _ = fs::create_dir_all(&root);
        let policy = build_ignore_policy(&[]);
        assert!(!policy.is_ignored(&root.join(".env"), false));
        let _ = fs::remove_dir_all(&root);
    }
}
