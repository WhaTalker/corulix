// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, deterministic sibling-document priming for whole-project
//! semantic operations (currently: [`crate::operations::references`] and
//! [`crate::operations::rename_preview`]) against TypeScript-family
//! providers running in "inferred project" mode (no
//! `tsconfig.json`/`jsconfig.json` governing the target file).
//!
//! # The defect this closes
//!
//! `crate::session::LspSession::ensure_open` opens exactly one document per
//! call: the operation's own anchor path. For an unconfigured plain-JS/TS
//! workspace, the underlying TypeScript-family language service builds its
//! "inferred project" file set solely from forward-import edges of
//! documents that have already been opened -- it never discovers a file
//! that imports the anchor unless that importing file has *also* been
//! opened at some point in the session's history. Proven directly (Corulix
//! 1.0.0 M03 references root-cause trace): the identical `references` query
//! at the identical anchor position returned an empty set, then a partial
//! set, then a complete set, purely as a function of which unrelated
//! documents earlier calls happened to have opened -- never as a function
//! of the query itself. This module makes that project-visibility
//! deterministic instead of history-dependent, without ever opening more
//! than a small, bounded, same-directory neighborhood, and without touching
//! any workspace that already has a real project config (in which case the
//! provider's own configured-project discovery already covers the whole
//! project on its own).
//!
//! # Why not simpler/bigger alternatives
//!
//! - Opening every file in the entire workspace before any whole-project
//!   query is unbounded and unsafe against real repositories (generated
//!   trees, vendor directories, monorepos with millions of files) -- never
//!   done here.
//! - Reimplementing the provider's own module-resolution algorithm (path
//!   mapping, `node_modules` resolution, aliasing) to compute the *exact*
//!   true reverse-import graph is a much larger undertaking than this fix's
//!   scope, and is not attempted: this module's bound is deliberately
//!   conservative (the anchor's own directory, non-recursive), which closes
//!   the proven defect for the common case (a symbol used by siblings in
//!   the same directory/module) while being honest that a reference living
//!   in a sibling *subdirectory* is not primed by this pass.
//! - Rust/Go/Python are deliberately left untouched
//!   ([`project_priming_for_lsp_language_id`] returns [`ProjectPriming::NotRequired`]
//!   for them): their own providers were never shown to exhibit this
//!   dependency, and extending this mechanism to them without equivalent
//!   proof would be exactly the kind of unjustified generalization this fix
//!   must avoid.

use std::path::{Path, PathBuf};

use crate::session::LspSession;

/// Same-directory sibling files considered, per priming pass, at most.
pub(crate) const MAX_PRIMED_FILES: usize = 64;

/// Aggregate byte ceiling across every sibling opened by one priming pass.
/// Deliberately separate from, and much smaller than,
/// `crate::operations::MAX_LOCATION_SOURCE_BYTES` (which bounds a single
/// already-targeted file's read) -- priming is a best-effort convenience
/// for whole-project discovery, not a location-resolution read.
pub(crate) const MAX_PRIMED_AGGREGATE_BYTES: u64 = 4 * 1024 * 1024;

/// How far upward from the anchor's directory this looks for a real
/// project config before concluding the provider is in inferred-project
/// mode. Mirrors `wht_corulix_workspace::discovery::MAX_DISCOVERY_DEPTH`'s
/// own bound and rationale: never an unbounded walk, and never walks above
/// the session's own workspace root regardless of this bound.
pub(crate) const MAX_CONFIG_SEARCH_DEPTH: u32 = 8;

const TS_FAMILY_CONFIG_MARKERS: &[&str] = &["tsconfig.json", "jsconfig.json"];

/// Directory basenames this pass never primes into. Defense in depth only
/// under the current single-level (non-recursive) design -- these would
/// only ever matter if the anchor file itself already lives inside one of
/// them, since priming never descends into subdirectories at all.
const EXCLUDED_DIR_BASENAMES: &[&str] = &[
    "node_modules",
    ".git",
    "dist",
    "build",
    "out",
    "target",
    "vendor",
    ".next",
    "coverage",
];

/// Which whole-project priming behavior applies to a given LSP session,
/// keyed on the exact `TextDocumentItem.languageId` string `profile.rs`
/// already assigns (`"typescript"`, `"javascript"`, `"typescriptreact"`) --
/// the only families with a *proven* inferred-project per-file dependency
/// (M03 references root-cause trace). Every other language reports
/// [`ProjectPriming::NotRequired`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectPriming {
    NotRequired,
    SameDirectorySourceFiles { extensions: &'static [&'static str] },
}

#[must_use]
pub(crate) fn project_priming_for_lsp_language_id(lsp_language_id: &str) -> ProjectPriming {
    const TS_FAMILY_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs"];
    match lsp_language_id {
        "typescript" | "javascript" | "typescriptreact" => {
            ProjectPriming::SameDirectorySourceFiles {
                extensions: TS_FAMILY_EXTENSIONS,
            }
        }
        _ => ProjectPriming::NotRequired,
    }
}

/// Best-effort, bounded, deterministic sibling-document priming, run
/// immediately before a whole-project semantic request. Never fails the
/// caller: any priming problem (an unreadable sibling, a directory that
/// cannot be listed, a metadata error) is swallowed and simply results in
/// fewer/no documents primed -- never an error surfaced to the real query
/// this exists to support.
///
/// `anchor_absolute` must already be workspace-confined (every caller in
/// `crate::operations` only ever calls this with a path that has already
/// passed through the same confinement `open_and_position`/`ensure_open`
/// themselves require) -- this function performs no confinement of its
/// own beyond staying within `anchor_absolute`'s own parent directory,
/// which is structurally already inside the workspace.
pub(crate) async fn prime_same_project_documents(session: &LspSession, anchor_absolute: &Path) {
    let priming = project_priming_for_lsp_language_id(session.lsp_language_id());
    let ProjectPriming::SameDirectorySourceFiles { extensions } = priming else {
        return;
    };
    let Some(parent) = anchor_absolute.parent() else {
        return;
    };
    if has_excluded_basename(parent) {
        return;
    }
    if has_project_config_upward(parent, session.workspace_root().canonical_path()) {
        // A real tsconfig.json/jsconfig.json governs this file: the
        // provider's own configured-project discovery already covers the
        // whole project without Corulix opening every sibling.
        return;
    }
    let Some(siblings) =
        bounded_same_directory_source_files(parent, anchor_absolute, extensions).await
    else {
        return;
    };
    let mut aggregate_bytes: u64 = 0;
    for (candidate, size) in siblings {
        if aggregate_bytes.saturating_add(size) > MAX_PRIMED_AGGREGATE_BYTES {
            break;
        }
        aggregate_bytes = aggregate_bytes.saturating_add(size);
        // `ensure_open` is idempotent (its check-then-notify-then-insert
        // critical section holds one mutex guard across the whole
        // sequence) and deliberately best-effort here: a single unreadable
        // sibling must never abort the real query this priming supports.
        let _ = session.ensure_open(&candidate).await;
    }
}

fn has_excluded_basename(directory: &Path) -> bool {
    directory
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| EXCLUDED_DIR_BASENAMES.contains(&name))
}

/// Bounded upward walk from `start` (inclusive) up to and including
/// `workspace_root` -- never above it -- checking each ancestor for a real
/// `tsconfig.json`/`jsconfig.json`. Mirrors
/// `wht_corulix_workspace::discovery::discover_from_seed`'s own bounded,
/// deterministic shape, specialized to TS-family config markers instead of
/// that module's generic project-root markers.
fn has_project_config_upward(start: &Path, workspace_root: &Path) -> bool {
    let mut current = Some(start);
    let mut depth = 0_u32;
    while let Some(directory) = current {
        if depth >= MAX_CONFIG_SEARCH_DEPTH {
            return false;
        }
        if TS_FAMILY_CONFIG_MARKERS
            .iter()
            .any(|marker| directory.join(marker).is_file())
        {
            return true;
        }
        if directory == workspace_root {
            return false;
        }
        depth += 1;
        current = directory.parent();
    }
    false
}

/// Non-recursive: every regular file directly inside `directory` whose
/// extension is in `extensions`, excluding `anchor` itself (the caller
/// already opens that one via `ensure_open`), paired with its byte size
/// (gathered in this same blocking pass, so the caller never needs a
/// second blocking hop per candidate), sorted by path for determinism, and
/// capped at [`MAX_PRIMED_FILES`]. Symlinks are skipped entirely, mirroring
/// `wht_corulix_workspace::confine::confined_walk`'s own symlink-safety
/// precedent. Returns `None` only if the directory itself cannot be
/// listed at all -- the caller then primes nothing rather than failing.
async fn bounded_same_directory_source_files(
    directory: &Path,
    anchor: &Path,
    extensions: &[&str],
) -> Option<Vec<(PathBuf, u64)>> {
    let directory = directory.to_path_buf();
    let anchor = anchor.to_path_buf();
    let extensions: Vec<String> = extensions.iter().map(|ext| (*ext).to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let entries = std::fs::read_dir(&directory).ok()?;
        let mut matches: Vec<PathBuf> = Vec::new();
        for entry in entries.filter_map(Result::ok) {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() || !file_type.is_file() {
                continue;
            }
            let path = entry.path();
            if path == anchor {
                continue;
            }
            let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
                continue;
            };
            if extensions.iter().any(|allowed| allowed == ext) {
                matches.push(path);
            }
        }
        matches.sort();
        matches.truncate(MAX_PRIMED_FILES);
        let sized: Vec<(PathBuf, u64)> = matches
            .into_iter()
            .map(|path| {
                let size = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
                (path, size)
            })
            .collect();
        Some(sized)
    })
    .await
    .ok()?
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
        let root =
            std::env::temp_dir().join(format!("corulix-project-priming-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    #[test]
    fn ts_family_lsp_language_ids_get_same_directory_priming() {
        for id in ["typescript", "javascript", "typescriptreact"] {
            assert!(matches!(
                project_priming_for_lsp_language_id(id),
                ProjectPriming::SameDirectorySourceFiles { .. }
            ));
        }
    }

    #[test]
    fn unproven_languages_get_no_priming() {
        for id in ["rust", "go", "python", "something-unknown"] {
            assert_eq!(
                project_priming_for_lsp_language_id(id),
                ProjectPriming::NotRequired
            );
        }
    }

    #[test]
    fn no_config_within_bound_reports_false() {
        let dir = temp_dir("no-config");
        let nested = dir.join("a/b");
        let _ = fs::create_dir_all(&nested);
        assert!(!has_project_config_upward(&nested, &dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tsconfig_at_workspace_root_is_found() {
        let dir = temp_dir("tsconfig-root");
        let nested = dir.join("a/b");
        let _ = fs::create_dir_all(&nested);
        let _ = fs::write(dir.join("tsconfig.json"), "{}");
        assert!(has_project_config_upward(&nested, &dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsconfig_at_intermediate_directory_is_found() {
        let dir = temp_dir("jsconfig-mid");
        let mid = dir.join("a");
        let nested = mid.join("b");
        let _ = fs::create_dir_all(&nested);
        let _ = fs::write(mid.join("jsconfig.json"), "{}");
        assert!(has_project_config_upward(&nested, &dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_above_workspace_root_is_not_found() {
        // A marker that exists only *above* the workspace root must never
        // be discovered -- this walk must never escape the workspace.
        let outer = temp_dir("outside-root");
        let root = outer.join("workspace-root");
        let nested = root.join("a/b");
        let _ = fs::create_dir_all(&nested);
        let _ = fs::write(outer.join("tsconfig.json"), "{}");
        assert!(!has_project_config_upward(&nested, &root));
        let _ = fs::remove_dir_all(&outer);
    }

    #[tokio::test]
    async fn same_directory_listing_excludes_anchor_and_wrong_extensions_and_is_bounded_sorted()
    -> Result<(), String> {
        let dir = temp_dir("listing");
        let anchor = dir.join("anchor.js");
        let _ = fs::write(&anchor, "// anchor");
        let _ = fs::write(dir.join("b_sibling.js"), "// b");
        let _ = fs::write(dir.join("a_sibling.js"), "// a");
        let _ = fs::write(dir.join("notes.md"), "not a source file");
        let _ = fs::create_dir_all(dir.join("subdir"));

        let result = bounded_same_directory_source_files(&dir, &anchor, &["js", "ts"])
            .await
            .ok_or("directory should be listable")?;
        let paths: Vec<PathBuf> = result.iter().map(|(path, _size)| path.clone()).collect();

        assert_eq!(
            paths,
            vec![dir.join("a_sibling.js"), dir.join("b_sibling.js")],
            "must exclude the anchor itself, exclude non-matching extensions, exclude \
             subdirectories, and be sorted for determinism"
        );
        assert!(
            result.iter().all(|(_, size)| *size > 0),
            "each sibling's byte size must be gathered alongside its path"
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn unreadable_directory_returns_none_rather_than_panicking() {
        let missing = std::env::temp_dir().join("corulix-project-priming-test-does-not-exist");
        let result =
            bounded_same_directory_source_files(&missing, &missing.join("x"), &["js"]).await;
        assert!(result.is_none());
    }
}
