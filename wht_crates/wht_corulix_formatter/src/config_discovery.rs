// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, read-only discovery of a repository's own `rustfmt.toml`/
//! `.rustfmt.toml`, matching real rustfmt behavior rather than invented
//! semantics.
//!
//! # Why this exists (empirically researched, not assumed)
//!
//! Real `rustfmt`'s own upward-ancestor config search only activates when
//! rustfmt is given a real on-disk **file path** to format directly -- and
//! that same code path also forces rustfmt to *read the file's bytes from
//! disk*, ignoring stdin entirely (verified empirically: piping different
//! content via stdin while also passing a real path on argv still produced
//! the on-disk content's formatted result). That is unusable for this
//! crate's staging-only contract, since the bytes to format are Corulix's
//! own already-observed content, not necessarily whatever currently sits on
//! disk.
//!
//! Feeding rustfmt via stdin instead (no positional path argument) is the
//! only way to guarantee `LIVE_WORKSPACE_FORMATTER_WRITE_COUNT=0` by
//! construction, but stdin-mode has no "input file path" for rustfmt's own
//! ancestor search to anchor on. `--config-path` was verified (empirically,
//! against the installed `rustfmt 1.9.0-stable`) to do **no ancestor
//! search of its own** in either form: given a directory, it looks for
//! `rustfmt.toml`/`.rustfmt.toml` **only directly inside that exact
//! directory**; given a file, it parses **that file itself** as the TOML
//! config (regardless of its name), never searching anywhere else. Passing
//! `--config-path <ancestor-directory-that-lacks-a-config-file>` fails the
//! whole invocation outright (`Error: unable to find a config file for the
//! given path`) rather than silently falling through -- so this crate must
//! resolve the exact containing directory itself before ever passing
//! `--config-path`, and must omit the flag entirely when no config file is
//! found anywhere in the confined ancestor chain (letting rustfmt fall back
//! to its own built-in defaults, exactly matching "if not found, rustfmt
//! runs with defaults").
//!
//! This module performs exactly that: a plain, bounded, read-only directory
//! walk **strictly upward from the target's containing directory to the
//! workspace root (inclusive), never above it** -- repository config may
//! influence formatting style only, and this bound keeps it that way; it
//! never expands the search outside the active workspace, never grants
//! executable trust, and never triggers a shell/process invocation of its
//! own.

use std::path::{Path, PathBuf};
use wht_corulix_workspace::WorkspaceRoot;

/// The two config file names real rustfmt recognizes, checked in this
/// order at each directory level.
const RUSTFMT_CONFIG_FILE_NAMES: [&str; 2] = ["rustfmt.toml", ".rustfmt.toml"];

/// The blocking-safe core. Private: the canonical public surface is
/// [`discover_config_directory`] (`.await`), matching this workspace's own
/// "no synchronous public core alongside the async entry point" convention
/// (Rule J).
fn discover_config_directory_blocking(root: &WorkspaceRoot, start_dir: &Path) -> Option<PathBuf> {
    let root_path = root.canonical_path();
    if !start_dir.starts_with(root_path) {
        // Defense in depth: the caller is expected to have already
        // confined `start_dir` inside the workspace before calling this --
        // never search from a directory this module cannot prove is
        // inside the active workspace.
        return None;
    }

    let mut current = start_dir.to_path_buf();
    loop {
        for name in RUSTFMT_CONFIG_FILE_NAMES {
            if current.join(name).is_file() {
                return Some(current);
            }
        }
        if current == root_path {
            return None;
        }
        // `Path::parent` always yields a strictly shorter path (or `None`
        // at a filesystem root) -- this walk is structurally guaranteed to
        // terminate; no artificial iteration cap is needed on top of that.
        let parent = current.parent()?;
        if !parent.starts_with(root_path) {
            // The workspace root itself was already handled by the
            // `current == root_path` check above -- reaching here means
            // `parent` climbed past the root, which must never happen for
            // an ancestor of an already-confined `start_dir`, but this
            // module fails closed (no config found) rather than trusting
            // that invariant silently.
            return None;
        }
        current = parent.to_path_buf();
    }
}

/// Searches upward from `start_dir` (expected to already be a confined,
/// canonical directory inside `root`) through `root` itself, inclusive, for
/// `rustfmt.toml`/`.rustfmt.toml`. Returns the directory containing the
/// first match found (nearest ancestor wins), or `None` if no such file
/// exists anywhere in that bounded chain.
///
/// Runs on Tokio's blocking-task pool via `spawn_blocking`, so an async
/// caller never blocks its own executor thread on the underlying stat
/// syscalls -- mirroring `wht_corulix_workspace`'s own async-entry-point
/// convention for filesystem-touching primitives.
pub(crate) async fn discover_config_directory(
    root: WorkspaceRoot,
    start_dir: PathBuf,
) -> Option<PathBuf> {
    tokio::task::spawn_blocking(move || discover_config_directory_blocking(&root, &start_dir))
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::CorulixResult;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_workspace(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let sequence = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "corulix-formatter-config-test-{label}-{stamp}-{sequence}"
        ));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn open_root(path: &Path) -> CorulixResult<WorkspaceRoot> {
        WorkspaceRoot::open(path)
    }

    /// Test-only helper that reaches the expected canonical form of a
    /// fixture path through this workspace's own canonicalization
    /// dependency (`wht_corulix_workspace::canonicalize_external_path`)
    /// rather than calling `std::fs::canonicalize` directly here --
    /// Architecture Rule F reserves that primitive to `wht_corulix_workspace`
    /// alone, and this test module is not exempt merely because it is
    /// test-only code (mirrors `wht_corulix_config`'s own test helper of
    /// the same name).
    async fn canonical(path: &Path) -> CorulixResult<PathBuf> {
        wht_corulix_workspace::canonicalize_external_path(path.to_path_buf())
            .await
            .map(|(canonical, _)| canonical)
    }

    #[tokio::test]
    async fn finds_config_at_the_exact_starting_directory() -> CorulixResult<()> {
        let workspace = temp_workspace("exact");
        fs::write(workspace.join("rustfmt.toml"), "max_width = 40\n")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = open_root(&workspace)?;
        // The real production caller (`wht_corulix_formatter::lib.rs`)
        // always resolves `start_dir` through
        // `wht_corulix_workspace::resolve_confined`, which canonicalizes it
        // -- so `start_dir` and `root.canonical_path()` are always in the
        // same canonical form (notably, on Windows, both `\\?\`-prefixed or
        // neither). This test must match that calling convention, or
        // `starts_with` inside `discover_config_directory_blocking` fails
        // spuriously on any platform whose `fs::canonicalize` output form
        // differs from a plain joined path (Windows: the `\\?\`
        // verbatim-path prefix).
        let canonical_start = canonical(&workspace).await?;
        let found = discover_config_directory(root.clone(), canonical_start).await;
        assert_eq!(found, Some(canonical(&workspace).await?));
        let _ = fs::remove_dir_all(&workspace);
        Ok(())
    }

    #[tokio::test]
    async fn finds_config_at_an_ancestor_directory() -> CorulixResult<()> {
        let workspace = temp_workspace("ancestor");
        let nested = workspace.join("a/b/c");
        fs::create_dir_all(&nested).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::write(workspace.join("rustfmt.toml"), "max_width = 40\n")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = open_root(&workspace)?;
        let canonical_nested = canonical(&nested).await?;
        let found = discover_config_directory(root.clone(), canonical_nested).await;
        assert_eq!(found, Some(canonical(&workspace).await?));
        let _ = fs::remove_dir_all(&workspace);
        Ok(())
    }

    #[tokio::test]
    async fn finds_dot_prefixed_config_name() -> CorulixResult<()> {
        let workspace = temp_workspace("dotfile");
        fs::write(workspace.join(".rustfmt.toml"), "max_width = 40\n")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = open_root(&workspace)?;
        let canonical_start = canonical(&workspace).await?;
        let found = discover_config_directory(root.clone(), canonical_start).await;
        assert_eq!(found, Some(canonical(&workspace).await?));
        let _ = fs::remove_dir_all(&workspace);
        Ok(())
    }

    #[tokio::test]
    async fn nearest_ancestor_wins_over_a_farther_one() -> CorulixResult<()> {
        let workspace = temp_workspace("nearest");
        let nested = workspace.join("a/b");
        fs::create_dir_all(&nested).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::write(workspace.join("rustfmt.toml"), "max_width = 40\n")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::write(nested.join("rustfmt.toml"), "max_width = 60\n")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = open_root(&workspace)?;
        let canonical_nested = canonical(&nested).await?;
        let found = discover_config_directory(root.clone(), canonical_nested).await;
        assert_eq!(found, Some(canonical(&nested).await?));
        let _ = fs::remove_dir_all(&workspace);
        Ok(())
    }

    #[tokio::test]
    async fn returns_none_when_no_config_exists_anywhere_in_the_workspace() -> CorulixResult<()> {
        let workspace = temp_workspace("absent");
        let nested = workspace.join("a/b");
        fs::create_dir_all(&nested).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = open_root(&workspace)?;
        let found = discover_config_directory(root, nested).await;
        assert_eq!(found, None);
        let _ = fs::remove_dir_all(&workspace);
        Ok(())
    }

    #[tokio::test]
    async fn never_searches_above_the_workspace_root() -> CorulixResult<()> {
        // A config file placed just *outside* the workspace root (in its
        // parent) must never be found -- repository config discovery is
        // bounded strictly to the active workspace.
        let outside = temp_workspace("outside-parent");
        let workspace = outside.join("workspace");
        fs::create_dir_all(&workspace).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::write(outside.join("rustfmt.toml"), "max_width = 40\n")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = open_root(&workspace)?;
        let found = discover_config_directory(root, workspace.clone()).await;
        assert_eq!(found, None);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }
}
