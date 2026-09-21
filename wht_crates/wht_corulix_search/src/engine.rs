// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The embedded ripgrep-family search implementation.
//!
//! `TEXT_DISCOVERY_AUTHORITY=YES`, `SEMANTIC_AUTHORITY=NO`: this module
//! finds textual candidates only. It never spawns an external `rg`/shell
//! process, never constructs its own independent recursive filesystem
//! walker, and never canonicalizes a path itself -- every one of those
//! responsibilities belongs exclusively to `wht_corulix_workspace`, which
//! this module calls
//! into for both file enumeration (`confined_walk`) and bounded file bytes
//! (`confined_read`).

use crate::bounds::{BINARY_SNIFF_BYTES, SearchBounds};
use crate::ignore_policy::build_ignore_policy;
use crate::query::{QueryKind, SearchQuery, SearchScope};
use crate::result::{MatchKind, SearchMatch, SearchResults};
use grep_matcher::Matcher;
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use grep_searcher::{Searcher, SearcherBuilder, Sink, SinkMatch};
use std::path::PathBuf;
use std::sync::Arc;
use wht_corulix_core::{CorulixError, CorulixResult, Position, SourceRange, WorkspaceRootId};
use wht_corulix_workspace::{WorkspaceContext, confined_read_and_process, confined_walk};

/// S6: the merged read+match closure's return shape. Kept local to this
/// module (never a public/core type) since it exists solely to carry the
/// binary-sniff/match outcome back out of one `spawn_blocking` hop.
enum FileReadOutcome {
    Binary,
    Matched {
        bytes_len: u64,
        matches: Result<Vec<SearchMatch>, ()>,
    },
}

/// Canonical async entry point -- the sole public name for this operation.
/// Confined traversal and confined reads await `wht_corulix_workspace`'s
/// own canonical async entry points directly (never a private blocking
/// core composed around them, since Workspace exposes no public
/// synchronous bypass to compose one around). The CPU-bound
/// `grep-searcher`/`grep-regex` matching step for one file is isolated in
/// its own `tokio::task::spawn_blocking` call per candidate file, kept
/// separate from the confined-read `.await` immediately above it so the
/// early-break/truncation bookkeeping below (`max_results_total`/
/// `max_results_per_root`/`max_total_bytes_scanned`) still short-circuits
/// *before* reading a file it will not need -- collapsing I/O and matching
/// into one giant blocking region would have forced reading every
/// candidate file's bytes up front, losing that bound.
///
/// # Errors
///
/// Returns `CorulixError::InvalidInput` for an empty query or an invalid
/// regex pattern (never panics on a malformed pattern), and
/// `CorulixError::ResourceLimit` for a query pattern longer than
/// `bounds.max_query_bytes`. Any workspace-selection failure for a
/// [`SearchScope::Root`] scope propagates the same error
/// `WorkspaceContext::resolve_root` itself would return.
pub async fn search(
    context: WorkspaceContext,
    query: SearchQuery,
    scope: SearchScope,
    bounds: SearchBounds,
) -> CorulixResult<SearchResults> {
    if query.pattern.is_empty() {
        return Err(CorulixError::InvalidInput(
            "search query must not be empty".into(),
        ));
    }
    if query.pattern.len() > bounds.max_query_bytes {
        return Err(CorulixError::ResourceLimit);
    }

    let matcher = Arc::new(
        RegexMatcherBuilder::new()
            .fixed_strings(matches!(query.kind, QueryKind::Literal))
            .case_insensitive(query.case_insensitive)
            .size_limit(bounds.max_regex_size)
            .dfa_size_limit(bounds.max_regex_dfa_size)
            .build(&query.pattern)
            .map_err(|_| CorulixError::InvalidInput("invalid search pattern".into()))?,
    );

    let match_kind = match query.kind {
        QueryKind::Literal => MatchKind::Literal,
        QueryKind::Regex => MatchKind::Regex,
    };

    let target_root_ids: Vec<WorkspaceRootId> = match scope {
        SearchScope::AllRoots => context
            .root_summaries()
            .into_iter()
            .map(|summary| summary.root)
            .collect(),
        SearchScope::Root(id) => {
            // Resolving through the numeric selector reuses
            // `WorkspaceContext::resolve_root`'s own selection semantics
            // (including its ambiguity/unknown-id failure modes) instead of
            // this crate reimplementing root lookup.
            context.resolve_root(Some(&id.0.to_string()))?;
            vec![id]
        }
    };

    // S3: with exactly one root in scope, per-root output is already
    // `(path, byte_offset)`-ascending by construction -- `relative_entries`
    // is sorted by path before scanning, and each file's own matches are
    // pushed in increasing byte-offset order (grep-searcher visits a file
    // top-to-bottom). The whole-context sort below is only needed to
    // interleave results *across* roots, whose processing order is not
    // itself root-id-ascending for `SearchScope::AllRoots`.
    let multi_root = target_root_ids.len() > 1;

    let mut results = SearchResults::default();

    'roots: for root_id in target_root_ids {
        let root = context.resolve_root(Some(&root_id.0.to_string()))?.clone();
        let mut per_root_results = 0usize;

        let entries = confined_walk(root.clone(), PathBuf::from("."), bounds.walk_limits).await?;
        let mut relative_entries: Vec<(String, PathBuf)> = entries
            .into_iter()
            .filter_map(|confined| {
                let absolute = confined.into_path_buf();
                let relative = absolute.strip_prefix(root.canonical_path()).ok()?;
                Some((relative.to_string_lossy().into_owned(), absolute))
            })
            .collect();
        // Deterministic ordering by relative path -- never dependent on
        // `read_dir`'s arbitrary enumeration order.
        relative_entries.sort_by(|a, b| a.0.cmp(&b.0));

        let ignore_policy = build_ignore_policy(&relative_entries);

        for (relative, absolute) in relative_entries {
            // S4: `absolute` is the confined walk's own already-resolved
            // absolute path -- reused here for the ignore check only (pure
            // in-memory glob matching, no filesystem I/O), never for the
            // subsequent read below. This does not widen the documented
            // canonicalize-then-read TOCTOU window: reusing a path for an
            // I/O-free check carries none of that window's risk, which is
            // specific to acting on a path between its resolution and the
            // read that follows it.
            if ignore_policy.is_ignored(&absolute, false) {
                results.files_skipped_ignored += 1;
                continue;
            }
            if results.bytes_scanned >= bounds.max_total_bytes_scanned {
                results.truncated = true;
                break 'roots;
            }
            if results.matches.len() >= bounds.max_results_total {
                results.truncated = true;
                break 'roots;
            }
            if per_root_results >= bounds.max_results_per_root {
                results.truncated = true;
                continue;
            }

            let remaining_total = bounds
                .max_results_total
                .saturating_sub(results.matches.len());
            let remaining_root = bounds.max_results_per_root.saturating_sub(per_root_results);
            let per_file_cap = remaining_total.min(remaining_root);
            let max_snippet_bytes = bounds.max_snippet_bytes;

            // S6: read and match merged into one `spawn_blocking` hop via
            // `confined_read_and_process` -- every bound check above this
            // point has already decided this file will be read, so there is
            // no remaining reason to return to the async executor between
            // reading its bytes and matching them (the original two-hop
            // split existed to keep those bound checks running *before* a
            // read, which this preserves exactly: nothing above moved).
            // Binary-sniffing moves inside the merged closure too, since it
            // only needs the bytes this same closure already has.
            let matcher_handle = Arc::clone(&matcher);
            let relative_owned = relative.clone();
            let sniff_bytes = BINARY_SNIFF_BYTES;
            let outcome = confined_read_and_process(
                root.clone(),
                PathBuf::from(&relative),
                bounds.max_file_bytes,
                move |bytes| {
                    let sniff_len = bytes.len().min(sniff_bytes);
                    if bytes[..sniff_len].contains(&0u8) {
                        return FileReadOutcome::Binary;
                    }
                    let matches = match_file(
                        &matcher_handle,
                        root_id,
                        &relative_owned,
                        match_kind,
                        max_snippet_bytes,
                        per_file_cap,
                        &bytes,
                    );
                    FileReadOutcome::Matched {
                        bytes_len: bytes.len() as u64,
                        matches,
                    }
                },
            )
            .await;

            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(CorulixError::FileTooLarge) => {
                    results.files_skipped_too_large += 1;
                    continue;
                }
                Err(_) => continue,
            };

            // Preserves the original ordering exactly: a binary file never
            // contributes to `files_scanned`/`bytes_scanned` (both counters
            // only advance in the `Matched` arm below, exactly as they only
            // advanced past the original binary-check `continue` before).
            let (bytes_len, matches) = match outcome {
                FileReadOutcome::Binary => {
                    results.files_skipped_binary += 1;
                    continue;
                }
                FileReadOutcome::Matched { bytes_len, matches } => (bytes_len, matches),
            };
            results.files_scanned += 1;
            results.bytes_scanned += bytes_len;
            let Ok(file_matches) = matches else {
                continue;
            };

            // A sink that filled its per-file cap may have stopped before
            // exhausting every match in this file -- flag the result set as
            // truncated even though this was the last (or only) candidate
            // file, since the top-of-loop bound checks above only catch
            // exhaustion between files, not mid-file. This is intentionally
            // conservative: a file whose true match count happens to equal
            // the cap exactly is flagged truncated too, but the flag is
            // never wrong in the unsafe direction (claiming complete when
            // it was not).
            if per_file_cap > 0 && file_matches.len() >= per_file_cap {
                results.truncated = true;
            }
            per_root_results += file_matches.len();
            results.matches.extend(file_matches);
        }
    }

    if multi_root {
        results.matches.sort_by(|a, b| {
            (
                a.workspace_root_id,
                &a.workspace_relative_path,
                a.range.start.byte_offset,
            )
                .cmp(&(
                    b.workspace_root_id,
                    &b.workspace_relative_path,
                    b.range.start.byte_offset,
                ))
        });
    }

    Ok(results)
}

/// The CPU-bound per-file matching step, isolated behind `spawn_blocking`
/// in [`search`]. Never called directly from async code -- it borrows
/// nothing async-unsafe and returns a plain `Result`, but it is not a
/// public name, since `search` is the sole canonical entry point for this
/// operation.
#[allow(clippy::too_many_arguments)]
fn match_file(
    matcher: &RegexMatcher,
    root_id: WorkspaceRootId,
    relative_path: &str,
    match_kind: MatchKind,
    max_snippet_bytes: usize,
    cap: usize,
    bytes: &[u8],
) -> Result<Vec<SearchMatch>, ()> {
    let mut sink = MatchSink {
        matcher,
        root_id,
        relative_path,
        match_kind,
        max_snippet_bytes,
        matches: Vec::new(),
        cap,
    };
    let mut searcher_builder = SearcherBuilder::new();
    searcher_builder.line_number(true).multi_line(false);
    let mut searcher: Searcher = searcher_builder.build();
    searcher
        .search_slice(matcher, bytes, &mut sink)
        .map_err(|_| ())?;
    Ok(sink.matches)
}

struct MatchSink<'a> {
    matcher: &'a grep_regex::RegexMatcher,
    root_id: WorkspaceRootId,
    relative_path: &'a str,
    match_kind: MatchKind,
    max_snippet_bytes: usize,
    matches: Vec<SearchMatch>,
    cap: usize,
}

impl Sink for MatchSink<'_> {
    type Error = std::io::Error;

    fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        if self.matches.len() >= self.cap {
            return Ok(false);
        }
        let line_bytes = mat.bytes();
        let line_start_offset = mat.absolute_byte_offset();
        // 1-based from grep-searcher; Core's `Position::line_zero_based` is
        // zero-based, so this is the one deliberate, documented conversion
        // point -- never a second independent coordinate convention.
        let line_number_zero_based = mat.line_number().unwrap_or(1).saturating_sub(1);

        let mut spans = Vec::new();
        let find_result = self.matcher.find_iter(line_bytes, |span| {
            spans.push((span.start(), span.end()));
            true
        });
        if find_result.is_err() {
            return Ok(true);
        }

        // S2: `snippet`/`snippet_truncated` depend only on this line's bytes
        // and `max_snippet_bytes` -- loop-invariant across every match span
        // on this one line, so computed once here rather than once per span
        // as before. Each pushed match still gets its own owned `String`
        // (cloned per match), since `SearchMatch` does not share ownership
        // of the snippet text across matches.
        let snippet_source = &line_bytes[..line_bytes.len().min(self.max_snippet_bytes)];
        let snippet_truncated = line_bytes.len() > self.max_snippet_bytes;
        let snippet = String::from_utf8_lossy(snippet_source)
            .trim_end_matches(['\n', '\r'])
            .to_string();

        for (start, end) in spans {
            if self.matches.len() >= self.cap {
                return Ok(false);
            }
            #[allow(clippy::cast_possible_truncation)]
            let start_column = start as u32;
            #[allow(clippy::cast_possible_truncation)]
            let end_column = end as u32;
            let start_offset = line_start_offset + start as u64;
            let end_offset = line_start_offset + end as u64;

            self.matches.push(SearchMatch {
                workspace_root_id: self.root_id,
                workspace_relative_path: self.relative_path.to_string(),
                range: SourceRange {
                    start: Position {
                        line_zero_based: u32::try_from(line_number_zero_based).unwrap_or(u32::MAX),
                        byte_column_zero_based: start_column,
                        byte_offset: start_offset,
                    },
                    end: Position {
                        line_zero_based: u32::try_from(line_number_zero_based).unwrap_or(u32::MAX),
                        byte_column_zero_based: end_column,
                        byte_offset: end_offset,
                    },
                },
                snippet: snippet.clone(),
                match_kind: self.match_kind,
                snippet_truncated,
            });
        }

        Ok(self.matches.len() < self.cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::SearchBounds;
    use crate::query::{QueryKind, SearchQuery, SearchScope};
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::WorkspaceRootId;
    use wht_corulix_workspace::WorkspaceRoot;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-search-engine-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    fn single_root_context(dir: &Path) -> CorulixResult<WorkspaceContext> {
        Ok(WorkspaceContext::single_root(
            WorkspaceRoot::open(dir)?,
            "root".to_string(),
        ))
    }

    // -----------------------------------------------------------------
    // Dev-only microbench support (Search + Parse AI Efficiency
    // Optimization pass). Isolates S6's variable (spawn_blocking hop count
    // per file) by timing real `search()` calls against a fixed fixture,
    // query, and bounds -- everything except hop count held constant. Not
    // part of release behavior. `#[ignore]`d; run via
    // `cargo test -p wht_corulix_search -- --ignored --nocapture`. Run once
    // now (S2/S3/S4 already applied, hops still separate -- the honest
    // "before S6" baseline) and again after S6 merges the hops, never
    // against the pristine pre-Tier-1 source.
    // -----------------------------------------------------------------
    #[tokio::test]
    #[ignore]
    async fn dev_microbench_s6_hopcount_timing() -> CorulixResult<()> {
        use std::time::Instant;

        // Dev-only fixture root: never a specific developer's machine
        // path. `CORULIX_BENCH_S6_FIXTURE_DIR` must name a real directory
        // containing the fixture files this microbench times against;
        // this microbench gracefully no-ops (rather than failing) when
        // that environment variable is unset, since it is `#[ignore]`d
        // and never part of release behavior.
        const ITERATIONS: usize = 15;
        let Ok(fixture_dir) = std::env::var("CORULIX_BENCH_S6_FIXTURE_DIR") else {
            eprintln!(
                "dev_microbench_s6_hopcount_timing: skipped, set CORULIX_BENCH_S6_FIXTURE_DIR to run"
            );
            return Ok(());
        };

        let root = WorkspaceRoot::open(&fixture_dir)?;
        let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERATIONS);

        for _ in 0..ITERATIONS {
            let context = WorkspaceContext::single_root(root.clone(), "root".to_string());
            let started = Instant::now();
            let _results = search(
                context,
                SearchQuery::literal("CORULIX_MICROBENCH_MARKER_XYZ"),
                SearchScope::AllRoots,
                SearchBounds::default(),
            )
            .await?;
            samples_ns.push(started.elapsed().as_nanos());
        }

        samples_ns.sort_unstable();
        let mean_ns = samples_ns.iter().sum::<u128>() / samples_ns.len() as u128;
        let median_ns = samples_ns[samples_ns.len() / 2];
        let min_ns = *samples_ns.first().unwrap_or(&0);
        let max_ns = *samples_ns.last().unwrap_or(&0);

        // Dev-only diagnostic output: write-failures here are surfaced by a
        // missing/incomplete result file downstream (the microbench
        // aggregation step), never by panicking test code -- matching this
        // codebase's existing test idiom of discarding fallible cleanup/
        // fixture I/O results (`let _ = fs::remove_dir_all(...)`, etc.)
        // rather than `.expect()`/`.unwrap()`/`panic!`, all denied lints.
        let results_dir =
            std::env::temp_dir().join("corulix_optimization_lab/search_parse/results/raw");
        let _ = std::fs::create_dir_all(&results_dir);
        let results_dir = results_dir.display();
        let mut tsv = String::from("iteration\telapsed_ns\n");
        for (i, sample) in samples_ns.iter().enumerate() {
            tsv.push_str(&format!("{i}\t{sample}\n"));
        }
        let _ = std::fs::write(
            format!("{results_dir}/search_s6_hopcount_timing_samples.tsv"),
            tsv,
        );

        let summary = format!(
            "ITERATIONS={}\nMEAN_NS={mean_ns}\nMEDIAN_NS={median_ns}\nMIN_NS={min_ns}\nMAX_NS={max_ns}\n",
            samples_ns.len()
        );
        let _ = std::fs::write(
            format!("{results_dir}/search_s6_hopcount_timing_summary.txt"),
            &summary,
        );
        eprintln!("{summary}");
        Ok(())
    }

    #[tokio::test]
    async fn literal_match_is_found() -> CorulixResult<()> {
        let dir = temp_dir("literal");
        let _ = fs::write(dir.join("a.rs"), "fn needle() {}\nfn other() {}\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].match_kind, MatchKind::Literal);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn literal_query_treats_metacharacters_literally() -> CorulixResult<()> {
        let dir = temp_dir("literal-meta");
        let _ = fs::write(dir.join("a.rs"), "a.b.c\naxbxc\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("a.b.c"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        // A literal `.` must match only a literal `.`, never "any character"
        // as it would under regex semantics -- `axbxc` must not match.
        assert_eq!(results.matches.len(), 1);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn regex_match_is_found() -> CorulixResult<()> {
        let dir = temp_dir("regex");
        let _ = fs::write(dir.join("a.rs"), "fn one() {}\nfn two() {}\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::regex(r"fn (one|two)\("),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 2);
        assert_eq!(results.matches[0].match_kind, MatchKind::Regex);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_regex_is_denied_not_panicked() -> CorulixResult<()> {
        let dir = temp_dir("invalid-regex");
        let context = single_root_context(&dir)?;
        let outcome = search(
            context,
            SearchQuery::regex("(unclosed"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await;
        assert!(matches!(outcome, Err(CorulixError::InvalidInput(_))));
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn empty_query_is_denied() -> CorulixResult<()> {
        let dir = temp_dir("empty-query");
        let context = single_root_context(&dir)?;
        let outcome = search(
            context,
            SearchQuery::literal(""),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await;
        assert!(matches!(outcome, Err(CorulixError::InvalidInput(_))));
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn query_longer_than_bound_is_denied() -> CorulixResult<()> {
        let dir = temp_dir("long-query");
        let context = single_root_context(&dir)?;
        let bounds = SearchBounds {
            max_query_bytes: 4,
            ..SearchBounds::default()
        };
        let outcome = search(
            context,
            SearchQuery::literal("longer than four bytes"),
            SearchScope::AllRoots,
            bounds,
        )
        .await;
        assert!(matches!(outcome, Err(CorulixError::ResourceLimit)));
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn zero_matches_returns_empty_results() -> CorulixResult<()> {
        let dir = temp_dir("zero-matches");
        let _ = fs::write(dir.join("a.rs"), "fn present() {}\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("absent"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert!(results.matches.is_empty());
        assert!(!results.truncated);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn multiple_matches_in_one_file_are_all_found() -> CorulixResult<()> {
        let dir = temp_dir("multi-match");
        let _ = fs::write(dir.join("a.rs"), "needle\nneedle\nneedle\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 3);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn result_ordering_is_deterministic_by_path_then_position() -> CorulixResult<()> {
        let dir = temp_dir("ordering");
        let _ = fs::write(dir.join("z.rs"), "needle\n");
        let _ = fs::write(dir.join("a.rs"), "needle\nneedle\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        let paths: Vec<&str> = results
            .matches
            .iter()
            .map(|m| m.workspace_relative_path.as_str())
            .collect();
        assert_eq!(paths, vec!["a.rs", "a.rs", "z.rs"]);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    /// S3 permanent guard: a single-root search skips the final
    /// whole-context sort entirely (see `multi_root` in [`search`]), relying
    /// on `relative_entries` already being path-sorted before scanning and
    /// each file's own matches already being byte-offset-ascending. This
    /// pins that invariant with nested paths and multiple matches per file
    /// so a future change that breaks either precondition fails here, not
    /// silently in production.
    #[tokio::test]
    async fn single_root_omits_sort_but_stays_ordered_by_construction() -> CorulixResult<()> {
        let dir = temp_dir("s3-guard");
        let _ = fs::create_dir_all(dir.join("nested"));
        let _ = fs::write(dir.join("z_top.rs"), "needle\n");
        let _ = fs::write(dir.join("nested/b_mid.rs"), "needle\nneedle\nneedle\n");
        let _ = fs::write(dir.join("a_top.rs"), "needle\nneedle\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        let paths: Vec<&str> = results
            .matches
            .iter()
            .map(|m| m.workspace_relative_path.as_str())
            .collect();
        // Windows note: the engine builds `workspace_relative_path` by
        // walking real directory entries, so nested components join with
        // the platform's own native separator (`\` on Windows, `/` on
        // Unix) -- never a hardcoded `/` literal. `PathBuf`/`MAIN_SEPARATOR`
        // keep this assertion portable while still proving the same thing:
        // single_root omits the sort but remains deterministically ordered
        // by construction.
        let nested_b_mid = PathBuf::from("nested")
            .join("b_mid.rs")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            paths,
            vec![
                "a_top.rs",
                "a_top.rs",
                nested_b_mid.as_str(),
                nested_b_mid.as_str(),
                nested_b_mid.as_str(),
                "z_top.rs",
            ]
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn single_root_search_ignores_scope_selector() -> CorulixResult<()> {
        let dir = temp_dir("single-root");
        let _ = fs::write(dir.join("a.rs"), "needle\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::Root(WorkspaceRootId(0)),
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 1);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn multi_root_all_roots_search_covers_every_root() -> CorulixResult<()> {
        let a = temp_dir("multi-a");
        let b = temp_dir("multi-b");
        let _ = fs::write(a.join("one.rs"), "needle\n");
        let _ = fs::write(b.join("two.rs"), "needle\n");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "a".to_string()),
            (WorkspaceRoot::open(&b)?, "b".to_string()),
        ])?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 2);
        let mut root_ids: Vec<u32> = results
            .matches
            .iter()
            .map(|m| m.workspace_root_id.0)
            .collect();
        root_ids.sort_unstable();
        assert_eq!(root_ids, vec![0, 1]);
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[tokio::test]
    async fn multi_root_root_scoped_search_covers_only_that_root() -> CorulixResult<()> {
        let a = temp_dir("scoped-a");
        let b = temp_dir("scoped-b");
        let _ = fs::write(a.join("one.rs"), "needle\n");
        let _ = fs::write(b.join("two.rs"), "needle\n");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "a".to_string()),
            (WorkspaceRoot::open(&b)?, "b".to_string()),
        ])?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::Root(WorkspaceRootId(0)),
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].workspace_root_id, WorkspaceRootId(0));
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_root_scope_selector_fails() -> CorulixResult<()> {
        let a = temp_dir("unknown-root-a");
        let b = temp_dir("unknown-root-b");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "a".to_string()),
            (WorkspaceRoot::open(&b)?, "b".to_string()),
        ])?;
        let outcome = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::Root(WorkspaceRootId(99)),
            SearchBounds::default(),
        )
        .await;
        assert!(matches!(outcome, Err(CorulixError::WorkspaceNotFound)));
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[tokio::test]
    async fn same_relative_filename_in_different_roots_is_distinguishable() -> CorulixResult<()> {
        let a = temp_dir("same-name-a");
        let b = temp_dir("same-name-b");
        let _ = fs::write(a.join("main.rs"), "needle\n");
        let _ = fs::write(b.join("main.rs"), "needle\n");
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "a".to_string()),
            (WorkspaceRoot::open(&b)?, "b".to_string()),
        ])?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 2);
        assert_eq!(
            results.matches[0].workspace_relative_path,
            results.matches[1].workspace_relative_path
        );
        assert_ne!(
            results.matches[0].workspace_root_id,
            results.matches[1].workspace_root_id
        );
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    #[tokio::test]
    async fn result_total_limit_truncates_deterministically() -> CorulixResult<()> {
        let dir = temp_dir("result-limit");
        let _ = fs::write(dir.join("a.rs"), "needle\nneedle\nneedle\nneedle\n");
        let context = single_root_context(&dir)?;
        let bounds = SearchBounds {
            max_results_total: 2,
            ..SearchBounds::default()
        };
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            bounds,
        )
        .await?;
        assert_eq!(results.matches.len(), 2);
        assert!(results.truncated);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn snippet_is_bounded_and_flagged_truncated() -> CorulixResult<()> {
        let dir = temp_dir("snippet-limit");
        let long_line = format!("needle{}\n", "x".repeat(500));
        let _ = fs::write(dir.join("a.rs"), &long_line);
        let context = single_root_context(&dir)?;
        let bounds = SearchBounds {
            max_snippet_bytes: 20,
            ..SearchBounds::default()
        };
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            bounds,
        )
        .await?;
        assert_eq!(results.matches.len(), 1);
        assert!(results.matches[0].snippet.len() <= 20);
        assert!(results.matches[0].snippet_truncated);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn oversized_file_is_skipped_not_partially_read() -> CorulixResult<()> {
        let dir = temp_dir("large-file");
        let _ = fs::write(dir.join("big.rs"), "needle".repeat(1000));
        let context = single_root_context(&dir)?;
        let bounds = SearchBounds {
            max_file_bytes: 10,
            ..SearchBounds::default()
        };
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            bounds,
        )
        .await?;
        assert!(results.matches.is_empty());
        assert_eq!(results.files_skipped_too_large, 1);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn binary_file_is_skipped_deterministically() -> CorulixResult<()> {
        let dir = temp_dir("binary");
        let mut bytes = b"needle".to_vec();
        bytes.push(0u8);
        bytes.extend_from_slice(b"more needle bytes");
        let _ = fs::write(dir.join("binary.bin"), bytes);
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert!(results.matches.is_empty());
        assert_eq!(results.files_skipped_binary, 1);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_utf8_content_is_still_searched_via_bytes() -> CorulixResult<()> {
        let dir = temp_dir("invalid-utf8");
        let mut bytes = b"needle ".to_vec();
        bytes.push(0xFFu8); // invalid UTF-8, but not a NUL byte -> not binary-sniffed
        bytes.push(b'\n');
        let _ = fs::write(dir.join("a.rs"), bytes);
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 1);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn unicode_content_produces_correct_byte_column() -> CorulixResult<()> {
        let dir = temp_dir("unicode");
        // "café " is 5 bytes for "caf" + 2-byte 'é' + space = 6 bytes before "needle".
        let _ = fs::write(dir.join("a.rs"), "café needle\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].range.start.byte_column_zero_based, 6);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn multi_line_file_reports_correct_line_numbers() -> CorulixResult<()> {
        let dir = temp_dir("multi-line");
        let _ = fs::write(dir.join("a.rs"), "one\ntwo\nneedle\nfour\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].range.start.line_zero_based, 2);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_content_outside_workspace_is_never_searched() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink-escape");
        let outside = temp_dir("symlink-escape-outside");
        let _ = fs::write(outside.join("secret.rs"), "needle\n");
        let _ = symlink(&outside, dir.join("escape_dir"));
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert!(results.matches.is_empty());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn gitignored_file_is_excluded_from_results() -> CorulixResult<()> {
        let dir = temp_dir("gitignore-exclude");
        let _ = fs::write(dir.join(".gitignore"), "excluded.rs\n");
        let _ = fs::write(dir.join("excluded.rs"), "needle\n");
        let _ = fs::write(dir.join("included.rs"), "needle\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle"),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 1);
        assert_eq!(results.matches[0].workspace_relative_path, "included.rs");
        assert_eq!(results.files_skipped_ignored, 1);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn case_insensitive_flag_is_honored() -> CorulixResult<()> {
        let dir = temp_dir("case-insensitive");
        let _ = fs::write(dir.join("a.rs"), "NEEDLE\n");
        let context = single_root_context(&dir)?;
        let results = search(
            context,
            SearchQuery::literal("needle").case_insensitive(true),
            SearchScope::AllRoots,
            SearchBounds::default(),
        )
        .await?;
        assert_eq!(results.matches.len(), 1);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn query_kind_enum_matches_result_match_kind() {
        assert_eq!(SearchQuery::literal("x").kind, QueryKind::Literal);
        assert_eq!(SearchQuery::regex("x").kind, QueryKind::Regex);
    }
}
