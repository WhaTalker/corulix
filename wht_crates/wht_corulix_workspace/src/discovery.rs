// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, upward project-root discovery seeded from a starting directory.
//!
//! The process's current working directory is only ever a *seed* for this
//! walk -- it is never treated as a valid workspace root on its own. If no
//! ancestor (including the seed itself) carries a recognized marker within
//! the bound, discovery is exhausted and the caller must fail closed; this
//! module never falls back to returning the raw seed.

use std::path::{Path, PathBuf};

/// Maximum number of ancestor directories walked upward from the seed
/// (inclusive of the seed itself), before discovery gives up. Named and
/// finite so this can never become an unbounded walk to the filesystem
/// root.
pub const MAX_DISCOVERY_DEPTH: u32 = 8;

/// Marker filenames that identify a directory as a recognized project root.
/// `.git` is one optional signal among several, never a mandatory
/// requirement -- this module never shells out to `git` to discover a
/// root.
pub const DISCOVERY_MARKERS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pnpm-workspace.yaml",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    ".git",
];

/// One ancestor directory that carried a recognized marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryCandidate {
    pub directory: PathBuf,
    pub marker: &'static str,
    pub depth: u32,
}

/// The outcome of a bounded upward walk from `seed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryOutcome {
    /// Exactly one ancestor (nearest wins) carried a recognized marker.
    Found(DiscoveryCandidate),
    /// No ancestor within [`MAX_DISCOVERY_DEPTH`] carried any marker.
    Exhausted,
}

/// Walks upward from `seed` (inclusive), stopping at the first ancestor that
/// contains any one [`DISCOVERY_MARKERS`] entry. Multiple different marker
/// files present in the *same* directory still identify exactly one
/// candidate directory (the nearest ancestor wins as a single identity, not
/// once per marker) -- this function never returns more than one candidate.
/// Bounded to [`MAX_DISCOVERY_DEPTH`] ancestors; never walks past the
/// filesystem root.
#[must_use]
pub fn discover_from_seed(seed: &Path) -> DiscoveryOutcome {
    let mut current = Some(seed);
    let mut depth = 0_u32;

    while let Some(directory) = current {
        if depth >= MAX_DISCOVERY_DEPTH {
            break;
        }
        if let Some(marker) = first_marker_present(directory) {
            return DiscoveryOutcome::Found(DiscoveryCandidate {
                directory: directory.to_path_buf(),
                marker,
                depth,
            });
        }
        depth += 1;
        current = directory.parent();
    }

    DiscoveryOutcome::Exhausted
}

fn first_marker_present(directory: &Path) -> Option<&'static str> {
    DISCOVERY_MARKERS
        .iter()
        .copied()
        .find(|marker| directory.join(marker).exists())
}

/// The outcome of a combined, bounded upward walk that looks for a
/// `.code-workspace` descriptor at each ancestor level *before* an ordinary
/// project marker -- a unique descriptor is stronger logical-workspace
/// evidence than a generic marker at the same level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceDiscoveryOutcome {
    /// Exactly one `.code-workspace` file was found at some ancestor level.
    /// Its own external-scope validity is the caller's responsibility to
    /// check next (see `resolver`) -- discovery only reports that it found
    /// a unique candidate.
    Descriptor(PathBuf),
    /// More than one `.code-workspace` file exists at the same ancestor
    /// level -- never resolved by alphabetical/first/newest ranking.
    AmbiguousDescriptors(Vec<PathBuf>),
    /// No `.code-workspace` was found at this level, but an ordinary
    /// project marker was.
    Marker(DiscoveryCandidate),
    /// Neither a descriptor nor a marker was found within the bound.
    Exhausted,
}

/// Non-recursive: every `*.code-workspace` file directly inside `directory`.
fn code_workspace_files_at(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("code-workspace"))
        .collect();
    found.sort();
    found
}

/// Walks upward from `seed` (inclusive, bounded by [`MAX_DISCOVERY_DEPTH`]),
/// checking for `.code-workspace` descriptors before ordinary project
/// markers at each level.
#[must_use]
pub fn discover_workspace_from_seed(seed: &Path) -> WorkspaceDiscoveryOutcome {
    let mut current = Some(seed);
    let mut depth = 0_u32;

    while let Some(directory) = current {
        if depth >= MAX_DISCOVERY_DEPTH {
            break;
        }
        let descriptors = code_workspace_files_at(directory);
        match descriptors.len() {
            0 => {}
            1 => return WorkspaceDiscoveryOutcome::Descriptor(descriptors[0].clone()),
            _ => return WorkspaceDiscoveryOutcome::AmbiguousDescriptors(descriptors),
        }
        if let Some(marker) = first_marker_present(directory) {
            return WorkspaceDiscoveryOutcome::Marker(DiscoveryCandidate {
                directory: directory.to_path_buf(),
                marker,
                depth,
            });
        }
        depth += 1;
        current = directory.parent();
    }

    WorkspaceDiscoveryOutcome::Exhausted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-discovery-test-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    #[test]
    fn seed_itself_with_marker_is_found_at_depth_zero() {
        let dir = temp_dir();
        let _ = fs::write(dir.join("Cargo.toml"), "");
        let outcome = discover_from_seed(&dir);
        assert!(matches!(
            outcome,
            DiscoveryOutcome::Found(DiscoveryCandidate {
                depth: 0,
                marker: "Cargo.toml",
                ..
            })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nested_seed_discovers_ancestor_marker() {
        let dir = temp_dir();
        let nested = dir.join("a/b/c");
        let _ = fs::create_dir_all(&nested);
        let _ = fs::write(dir.join("go.mod"), "");
        let outcome = discover_from_seed(&nested);
        let expected = DiscoveryOutcome::Found(DiscoveryCandidate {
            directory: dir.clone(),
            marker: "go.mod",
            depth: outcome_depth(&outcome),
        });
        assert_eq!(outcome, expected);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiple_markers_in_same_directory_yield_one_candidate() {
        let dir = temp_dir();
        let _ = fs::write(dir.join("Cargo.toml"), "");
        let _ = fs::write(dir.join("package.json"), "");
        // A single call returns exactly one Found candidate for this
        // directory, never a list of per-marker matches.
        let outcome = discover_from_seed(&dir);
        let is_found_here = matches!(
            &outcome,
            DiscoveryOutcome::Found(candidate) if candidate.directory == dir
        );
        assert!(is_found_here);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Test-only helper: extracts the depth from a `Found` outcome, or `u32::MAX`
    /// (which will simply fail the equality assertion) for `Exhausted` -- avoids
    /// `panic!`/`unwrap`/`expect`, all denied by this workspace's lint profile.
    fn outcome_depth(outcome: &DiscoveryOutcome) -> u32 {
        match outcome {
            DiscoveryOutcome::Found(candidate) => candidate.depth,
            DiscoveryOutcome::Exhausted => u32::MAX,
        }
    }

    #[test]
    fn no_marker_within_bound_is_exhausted() {
        // A freshly created temp directory tree has no marker anywhere
        // above it within the bound (assuming the OS temp root itself
        // carries none, which holds in this test environment).
        let dir = temp_dir();
        let nested = dir.join("x/y/z");
        let _ = fs::create_dir_all(&nested);
        assert_eq!(discover_from_seed(&nested), DiscoveryOutcome::Exhausted);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovery_never_walks_past_the_bound() {
        // Build a chain deeper than MAX_DISCOVERY_DEPTH with a marker only
        // beyond the bound; discovery must report Exhausted, not find it.
        let dir = temp_dir();
        let mut nested = dir.clone();
        for i in 0..(MAX_DISCOVERY_DEPTH + 2) {
            nested = nested.join(format!("d{i}"));
        }
        let _ = fs::create_dir_all(&nested);
        let _ = fs::write(dir.join("Cargo.toml"), "");
        assert_eq!(discover_from_seed(&nested), DiscoveryOutcome::Exhausted);
        let _ = fs::remove_dir_all(&dir);
    }
}
