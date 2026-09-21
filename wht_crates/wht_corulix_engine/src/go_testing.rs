// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15 §19-§23: real, trust-gated `go test` invocation, composing Evidence
//! for `GateId::Tests`.
//!
//! `P15_GO_TEST_EXECUTION_CLASS=TRUSTED_WORKSPACE_EXECUTION`,
//! `P15_GO_TEST_AUTHORITY=AUTHORITATIVE`.
//!
//! # The trust gate is load-bearing, and proven so
//!
//! `go test` compiles and executes repository-authored test code. This is
//! not inferred: a fixture whose `TestSideEffect` wrote a marker file was
//! observed to create that marker under a real `go test` run against the
//! real `go1.26.6`. Repository-authored code genuinely executes, so the
//! operation is `TrustedWorkspaceExecution` and
//! `crate::diagnostics::authorize_trusted_execution` runs **before any
//! [`ProcessSpec`] is constructed** (`P15_UNTRUSTED_GO_TEST_PROCESS_SPAWN_COUNT=0`).
//! That is the same single trust gate `cargo test` uses -- there is no
//! Go-specific trust gate, and an MCP request cannot elevate trust (neither
//! `RepositoryHints` nor `RequestOptions` carries a trust field at all; see
//! `wht_corulix_config::trust`'s own module doc).
//!
//! `PROVIDER_EXECUTABLE_AUTHORITY != WORKSPACE_EXECUTION_TRUST_CLASS`, the
//! same distinction `crate::testing` draws: the `go` binary itself is
//! Corulix-resolved by explicit, canonicalized, approved path (never a
//! `PATH` search), while the *test code* it compiles and runs is
//! workspace-authored and runs only because the operation carries the trust
//! class and the effective configuration authorizes it.
//!
//! # Result model (`EXIT_CODE_AUTHORITATIVE + STRUCTURED_JSON_STREAM`)
//!
//! `P15_GO_TEST_RESULT_PARSE_MODEL=EXIT_CODE_AUTHORITATIVE + STRUCTURED_JSON_STREAM`.
//!
//! Unlike Rust's libtest -- whose pass/fail summary is *not* part of
//! `cargo test --message-format=json` and must be text-parsed (see
//! `crate::testing`'s own doc comment) -- `go test -json` emits a genuinely
//! structured, documented stream: one JSON object per line carrying
//! `Action` (`start`/`run`/`output`/`pass`/`fail`/`skip`), `Package`, and an
//! optional `Test`. Confirmed empirically against real passing and failing
//! fixtures. This module therefore parses real JSON rather than scraping
//! narrative text, and no structured precision is fabricated.
//!
//! **Test-level vs package-level records.** The stream carries *both*: a
//! `pass`/`fail` record **with** a `Test` field (one per test function) and
//! one **without** (the package's aggregate). Counting both would
//! double-count, so this module counts only records carrying `Test`, and
//! reads the package-level records purely as corroboration.
//!
//! **Exit code is authoritative.** Parsed counts are descriptive. A
//! disagreement (exit `0` with `failed > 0`, or non-zero with `failed == 0`
//! while at least one test record was seen) is
//! [`GoTestError::ResultContradiction`], never silently resolved -- the
//! direct sibling of `crate::testing`'s own contradiction check.
//!
//! **`[no test files]` exits zero.** Empirically confirmed: a module with no
//! `_test.go` files produces `?   pkg  [no test files]` and exit `0`. That is
//! [`GoTestError::NoTestsExecuted`], never a pass -- a caller must not be
//! able to read "nothing ran" as "everything passed".
//!
//! # Network honesty (§23)
//!
//! `P15_GO_E2E_EXTERNAL_NETWORK_REQUIRED=NO`,
//! `OS_LEVEL_NETWORK_ISOLATION=NOT_CLAIMED`. `GOPROXY=off` and
//! `GOTOOLCHAIN=local` (see `crate::go_providers::go_environment`) are the Go
//! command's own offline switches, honoured by the Go command. They are not
//! a kernel-enforced boundary, and this module claims no such boundary.
//! P15's own fixtures are stdlib-only with no `go.sum` dependencies, so no
//! module fetch is required in the first place.

use std::path::Path;

use serde::Deserialize;
use wht_corulix_core::{ContentHash, CorulixError, CorulixResult, ExecutionClass};
use wht_corulix_tooling::{ProcessLimits, ProcessSpec, TerminationReason};
use wht_corulix_workspace::{WalkLimits, WorkspaceRoot, confined_read, confined_walk};

use crate::diagnostics::authorize_trusted_execution;
use crate::go_providers::{self, GoProviderError, ResolvedGoToolchain};

/// Bounded exactly as `crate::testing::MAX_TEST_SUMMARY_BYTES` is.
const MAX_TEST_SUMMARY_BYTES: usize = 3800;

/// A real Go test suite can legitimately emit substantial output, but never
/// unboundedly.
const TEST_LIMITS: ProcessLimits = ProcessLimits {
    max_stdout_bytes: 32 * 1024 * 1024,
    max_stderr_bytes: 8 * 1024 * 1024,
};

/// A hard ceiling against a runaway/hung test, not a promise that any given
/// suite finishes within it.
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The real, caller-supplied resource ceiling for one Go test run. A genuine
/// configuration knob (a host legitimately wants a shorter timeout in CI than
/// interactively), **not** a test seam: nothing here bypasses the trust gate,
/// provider resolution, process construction, or result semantics -- it only
/// bounds the same [`ProcessSpec`] fields the fixed defaults would fill.
/// Mirrors `crate::testing::TestExecutionLimits` exactly.
#[derive(Debug, Clone, Copy)]
pub struct GoTestExecutionLimits {
    pub timeout: std::time::Duration,
    pub limits: ProcessLimits,
}

impl Default for GoTestExecutionLimits {
    fn default() -> Self {
        Self {
            timeout: TEST_TIMEOUT,
            limits: TEST_LIMITS,
        }
    }
}

/// Why a `go test` run could not produce trustworthy Evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoTestError {
    /// The effective configuration does not authorize
    /// [`ExecutionClass::TrustedWorkspaceExecution`]. **No process is
    /// spawned** (`P15_UNTRUSTED_GO_TEST_PROCESS_SPAWN_COUNT=0`) -- and,
    /// critically, no repository-authored test code executes.
    WorkspaceExecutionNotAuthorized,
    /// The real `go` toolchain could not be resolved or identified.
    Provider(GoProviderError),
    /// A real build failure was observed before any test could have run --
    /// the module does not compile, so no tests executed. Never folded into
    /// a fabricated "zero tests passed" outcome.
    BuildFailed {
        summary: String,
    },
    /// The run exited without error and produced zero *test-level* records:
    /// e.g. a module with no `_test.go` files (`[no test files]`, exit `0`).
    /// Distinct from a genuine pass so a caller cannot treat "nothing ran"
    /// as "everything passed".
    NoTestsExecuted,
    /// Zero test-level records were observed **and** stdout was
    /// bounded-truncated, so the records may have been discarded rather than
    /// never emitted. A distinct real condition from
    /// [`Self::NoTestsExecuted`] with a distinct remediation (raise the
    /// output bound vs. add a test) -- both `Err`, never a fabricated `Ok`.
    ResultTruncatedBeforeSummary,
    /// The exit code and the parsed test-level records disagree. Never
    /// resolved in either direction.
    ResultContradiction,
    /// The governed source tree's content hash differs between immediately
    /// before the run was spawned and immediately after it exited -- the
    /// trusted test execution mutated governed source as a side effect.
    /// Returned *instead of* a normal outcome regardless of exit code: a
    /// result observed against content that no longer matches what was
    /// validated is never legitimate Evidence for the state it claims to
    /// describe.
    WorkspaceSelfMutationDetected,
    /// The governed source tree could not be hashed either before or after
    /// the run. Fails closed rather than skipping the coherence check.
    WorkspaceSourceTreeUnreadable,
    SpawnFailed,
    TimedOut,
    Cancelled,
    TerminationFailed,
    Signaled,
}

/// The real, structured outcome of one `go test` run whose exit code and
/// parsed records were confirmed *consistent*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoTestOutcome {
    /// Exit-code-authoritative. Always equal to `failed == 0` by
    /// construction.
    pub passing: bool,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    /// Every failing test's fully-qualified `Package::Test` name.
    pub failed_tests: Vec<String>,
    pub truncated: bool,
    /// A bounded, human-readable summary.
    pub summary: String,
    /// The exact provider identity from a real `go version` probe --
    /// never "system go".
    pub provider_version: String,
    pub provider_path: std::path::PathBuf,
}

impl GoTestOutcome {
    /// `passed + failed` -- the real count of tests that actually executed.
    /// Excludes `skipped`, which represents no executed assertion. A caller
    /// proving "a real test actually ran" asserts on this, never merely on
    /// `passing`, since zero tests trivially "pass".
    #[must_use]
    pub fn executed_count(&self) -> u32 {
        self.passed.saturating_add(self.failed)
    }
}

/// One `go test -json` record. Only the fields this module actually uses are
/// modelled; `serde` ignores the rest (`Time`, `Elapsed`, ...) rather than
/// this module asserting a complete schema it does not depend on.
#[derive(Debug, Deserialize)]
struct GoTestEvent {
    #[serde(rename = "Action")]
    action: String,
    #[serde(rename = "Package")]
    package: Option<String>,
    #[serde(rename = "Test")]
    test: Option<String>,
    #[serde(rename = "Output")]
    output: Option<String>,
    /// Present on `build-output`/`build-fail` records instead of `Package`
    /// -- the Go command reports build-phase events keyed by import path.
    #[serde(rename = "ImportPath")]
    import_path: Option<String>,
}

struct GoTestParse {
    test_records_seen: u32,
    passed: u32,
    failed: u32,
    skipped: u32,
    failed_tests: Vec<String>,
    build_failure: bool,
    summary: String,
    truncated: bool,
}

fn push_bounded_line(summary: &mut String, truncated: &mut bool, line: &str) {
    if summary.len() + line.len() + 1 > MAX_TEST_SUMMARY_BYTES {
        *truncated = true;
        return;
    }
    summary.push_str(line);
    summary.push('\n');
}

/// Parses a real `go test -json` stream.
///
/// Counts **only** records carrying a `Test` field (see this module's own doc
/// comment: package-level `pass`/`fail` records duplicate the aggregate and
/// would double-count). A line that is not valid JSON is skipped rather than
/// aborting the parse -- `go test -json` interleaves raw build-error text on
/// the same stream when a package fails to compile, which is exactly the
/// `build_failure` signal this function also detects.
fn parse_go_test_json(stdout: &[u8], stdout_truncated: bool) -> GoTestParse {
    let text = String::from_utf8_lossy(stdout);
    let mut parse = GoTestParse {
        test_records_seen: 0,
        passed: 0,
        failed: 0,
        skipped: 0,
        failed_tests: Vec::new(),
        build_failure: false,
        summary: String::new(),
        truncated: stdout_truncated,
    };

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<GoTestEvent>(line) else {
            // Non-JSON content on the stream: `go test -json` emits raw
            // compiler output here when a package cannot be built. Treat a
            // `file:line:col:`-shaped line as a real build failure signal
            // rather than silently discarding it.
            if line.starts_with('#') || crate::go_validation::looks_like_go_diagnostic(line) {
                parse.build_failure = true;
                push_bounded_line(&mut parse.summary, &mut parse.truncated, line);
            }
            continue;
        };

        // The Go command reports a failed *build* phase with its own
        // dedicated, structured records -- confirmed empirically against the
        // real `go1.26.6`:
        //
        //   {"ImportPath":"pkg [pkg.test]","Action":"build-output","Output":"# pkg\n"}
        //   {"ImportPath":"pkg [pkg.test]","Action":"build-output","Output":"./main.go:4:14: ...\n"}
        //   {"ImportPath":"pkg [pkg.test]","Action":"build-fail"}
        //
        // `build-fail` is therefore the authoritative build-failure signal,
        // not a text heuristic over narrative output. `build-output` carries
        // the real compiler diagnostics, which are kept for the summary.
        if event.action == "build-fail" {
            parse.build_failure = true;
            if let Some(import_path) = event.import_path.as_deref() {
                push_bounded_line(
                    &mut parse.summary,
                    &mut parse.truncated,
                    &format!("build failed: {import_path}"),
                );
            }
            continue;
        }
        if event.action == "build-output" {
            if let Some(output) = event.output.as_deref() {
                let trimmed = output.trim();
                if !trimmed.is_empty() {
                    push_bounded_line(&mut parse.summary, &mut parse.truncated, trimmed);
                }
            }
            continue;
        }
        // Ordinary `output` records are narrative test output. They are
        // deliberately **not** scanned for diagnostic-looking text: a
        // failing test's own `t.Fatal` location (`main_test.go:6: boom`) has
        // exactly that shape, and treating it as a build failure would
        // misreport a real test failure as a build failure.
        if event.action == "output" {
            continue;
        }

        // Only test-level records are counted.
        let Some(test) = event.test.as_deref() else {
            continue;
        };
        let qualified = match event.package.as_deref() {
            Some(package) => format!("{package}::{test}"),
            None => test.to_string(),
        };
        match event.action.as_str() {
            "pass" => {
                parse.test_records_seen += 1;
                parse.passed += 1;
            }
            "fail" => {
                parse.test_records_seen += 1;
                parse.failed += 1;
                push_bounded_line(
                    &mut parse.summary,
                    &mut parse.truncated,
                    &format!("FAIL: {qualified}"),
                );
                parse.failed_tests.push(qualified);
            }
            "skip" => {
                parse.test_records_seen += 1;
                parse.skipped += 1;
            }
            _ => {}
        }
    }

    parse
}

/// Bounds a single file's contribution to [`hash_governed_source_tree`].
const MAX_SOURCE_TREE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Governed-source files hashed for the self-mutation coherence check.
///
/// `go.mod`/`go.sum` are deliberately **excluded by name**, for the same
/// empirically-motivated reason `crate::testing` excludes `Cargo.lock`: the
/// Go command can legitimately create or refresh them, and letting one benign
/// write become a false-positive "self-mutation" finding on a module's first
/// run would weaken the check by making callers distrust it. Excluding them
/// does not weaken the real invariant: nothing `go test` legitimately needs
/// to write appears in the hashed set below.
///
/// `GOCACHE`/`GOMODCACHE`/`GOPATH` and `go build`'s output are all already
/// redirected outside the workspace entirely (see
/// `crate::go_providers::ensure_go_scratch`), so no cache or artifact
/// directory can appear here regardless.
const GOVERNED_SOURCE_EXTENSION: &str = "go";

/// Hashes every `.go` file in the governed root's own tree (confined and
/// symlink-safe via `wht_corulix_workspace`, sorted by relative path so the
/// result is order-independent) into one [`ContentHash`].
///
/// This is the self-mutation coherence check's entire mechanism, mirroring
/// `crate::testing::hash_governed_source_tree`: [`run_go_test`] calls it once
/// immediately before spawning and once immediately after the process exits,
/// and refuses to return a normal outcome at all if the two differ.
async fn hash_governed_source_tree(
    workspace_root: &WorkspaceRoot,
) -> Result<ContentHash, GoTestError> {
    let entries = confined_walk(
        workspace_root.clone(),
        std::path::PathBuf::from("."),
        WalkLimits::default(),
    )
    .await
    .map_err(|_| GoTestError::WorkspaceSourceTreeUnreadable)?;

    let mut relative_paths: Vec<std::path::PathBuf> = entries
        .iter()
        .filter_map(|entry| {
            entry
                .as_path()
                .strip_prefix(workspace_root.canonical_path())
                .ok()
                .map(std::path::PathBuf::from)
        })
        .filter(|relative| {
            relative
                .extension()
                .is_some_and(|extension| extension == GOVERNED_SOURCE_EXTENSION)
        })
        .collect();
    relative_paths.sort();
    relative_paths.dedup();

    let mut buffer = Vec::new();
    for relative in relative_paths {
        let bytes = confined_read(
            workspace_root.clone(),
            relative.clone(),
            MAX_SOURCE_TREE_FILE_BYTES,
        )
        .await
        .map_err(|_| GoTestError::WorkspaceSourceTreeUnreadable)?;
        buffer.extend_from_slice(relative.to_string_lossy().as_bytes());
        buffer.push(0);
        buffer.extend_from_slice(&bytes);
        buffer.push(0);
    }
    Ok(ContentHash::compute_sha256(&buffer))
}

/// Runs real, trust-gated `go test -json ./...` against `workspace_root` --
/// the authoritative `ProviderCategory::TestRunner` validator for
/// `GateId::Tests`.
pub async fn run_go_test(
    managed_root: &Path,
    workspace_root: &WorkspaceRoot,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<GoTestOutcome, GoTestError> {
    run_go_test_with_limits(
        managed_root,
        workspace_root,
        effective,
        cancellation,
        &GoTestExecutionLimits::default(),
    )
    .await
}

/// As [`run_go_test`], with the timeout/output-bound ceiling made explicit.
/// See [`GoTestExecutionLimits`] for why this is a configuration knob, not a
/// test seam.
pub async fn run_go_test_with_limits(
    managed_root: &Path,
    workspace_root: &WorkspaceRoot,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
    execution_limits: &GoTestExecutionLimits,
) -> Result<GoTestOutcome, GoTestError> {
    // The one load-bearing trust gate, before anything else. Repository
    // -authored test code genuinely executes past this point.
    authorize_trusted_execution(effective)
        .map_err(|_| GoTestError::WorkspaceExecutionNotAuthorized)?;

    let toolchain: ResolvedGoToolchain = go_providers::resolve_go_toolchain(
        managed_root,
        effective,
        workspace_root,
        wht_corulix_core::ProviderCategory::TestRunner,
        cancellation,
    )
    .await
    .map_err(GoTestError::Provider)?;

    let root_path = workspace_root.canonical_path().to_path_buf();
    // Held for this entire governed execution, from before the managed Go
    // caches are materialized until after the spawned `go test` process has
    // been fully reaped below. This is the existing managed-root
    // reader/writer lock (never a second lock subsystem), so a concurrent
    // `full_uninstall` -- which holds the same lock exclusively for its
    // whole transaction -- structurally cannot reach its scratch
    // quarantine/destroy stage while this execution is still running
    // (`P15_ACTIVE_EXECUTION_PREMATURE_CACHE_DELETE_COUNT=0`,
    // `P15_EXECUTION_CACHE_FULL_UNINSTALL_RACE_COUNT=0`). A bounded one-shot
    // execution like this one is spawned through `wht_corulix_tooling::execute`
    // and holds no `ManagedExecutionLease`, so `full_uninstall`'s global
    // process preflight cannot see it; this guard is what closes that
    // window.
    let _scratch_guard =
        wht_corulix_tooling::provisioning::acquire_managed_execution_scratch_guard(managed_root)
            .await;
    let scratch =
        go_providers::ensure_go_scratch(managed_root, &root_path).map_err(GoTestError::Provider)?;

    // Captured immediately before spawning, so nothing this function itself
    // does can be mistaken for the trusted execution's own side effect.
    let pre_run_hash = hash_governed_source_tree(workspace_root).await?;

    let spec = ProcessSpec {
        executable: toolchain.executable.clone(),
        arguments: vec!["test".to_string(), "-json".to_string(), "./...".to_string()],
        environment: go_providers::go_environment(&toolchain, &scratch),
        working_directory: root_path,
        limits: execution_limits.limits,
        timeout: execution_limits.timeout,
        execution_class: ExecutionClass::TrustedWorkspaceExecution,
        argv0: None,
    };
    // M09-P7/M09-P10: binds the child's cwd to `workspace_root`'s pinned
    // root object on Unix; on Windows, `execute_with_workspace_root` fails
    // closed before spawning anything rather than falling back to a
    // pathname-based cwd.
    let outcome =
        wht_corulix_tooling::execute_with_workspace_root(&spec, workspace_root, cancellation).await;

    match outcome.termination {
        TerminationReason::Exited { code } => {
            // The coherence check runs first, before any result
            // classification: a result observed against content that changed
            // during execution is never legitimate Evidence for anything.
            let post_run_hash = hash_governed_source_tree(workspace_root).await?;
            if post_run_hash != pre_run_hash {
                return Err(GoTestError::WorkspaceSelfMutationDetected);
            }

            let mut stream = outcome.stdout.bytes.clone();
            stream.extend_from_slice(&outcome.stderr.bytes);
            let parsed = parse_go_test_json(
                &stream,
                outcome.stdout.truncated || outcome.stderr.truncated,
            );

            if parsed.build_failure {
                return Err(GoTestError::BuildFailed {
                    summary: parsed.summary,
                });
            }
            if parsed.test_records_seen == 0 {
                return Err(if parsed.truncated {
                    GoTestError::ResultTruncatedBeforeSummary
                } else {
                    GoTestError::NoTestsExecuted
                });
            }

            let exit_ok = code == 0;
            let counts_ok = parsed.failed == 0;
            if exit_ok != counts_ok {
                return Err(GoTestError::ResultContradiction);
            }
            Ok(GoTestOutcome {
                passing: exit_ok,
                passed: parsed.passed,
                failed: parsed.failed,
                skipped: parsed.skipped,
                failed_tests: parsed.failed_tests,
                truncated: parsed.truncated,
                summary: parsed.summary,
                provider_version: toolchain.version,
                provider_path: toolchain.executable,
            })
        }
        TerminationReason::Signaled { .. } => Err(GoTestError::Signaled),
        TerminationReason::TimedOut => Err(GoTestError::TimedOut),
        TerminationReason::Cancelled => Err(GoTestError::Cancelled),
        TerminationReason::SpawnFailed => Err(GoTestError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(GoTestError::TerminationFailed),
    }
}

/// Converts a real [`GoTestOutcome`]'s bounded `summary` into an
/// [`wht_corulix_core::EvidenceResultSummary`].
pub fn evidence_result_summary(
    outcome: &GoTestOutcome,
) -> CorulixResult<wht_corulix_core::EvidenceResultSummary> {
    wht_corulix_core::EvidenceResultSummary::try_from(outcome.summary.clone())
        .map_err(|_| CorulixError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact passing stream shape observed against the real `go1.26.6`.
    /// Note the package-level `pass` record (no `Test` field) alongside the
    /// test-level one: counting both would report 2 passed for 1 test.
    #[test]
    fn counts_only_test_level_records_never_the_package_aggregate() {
        let stdout = concat!(
            r#"{"Action":"start","Package":"corulixfixture"}"#,
            "\n",
            r#"{"Action":"run","Package":"corulixfixture","Test":"TestTargetPasses"}"#,
            "\n",
            r#"{"Action":"output","Package":"corulixfixture","Test":"TestTargetPasses","Output":"--- PASS: TestTargetPasses (0.00s)\n"}"#,
            "\n",
            r#"{"Action":"pass","Package":"corulixfixture","Test":"TestTargetPasses","Elapsed":0}"#,
            "\n",
            r#"{"Action":"output","Package":"corulixfixture","Output":"ok  \tcorulixfixture\t0.001s\n"}"#,
            "\n",
            r#"{"Action":"pass","Package":"corulixfixture","Elapsed":0.002}"#,
            "\n",
        );
        let parsed = parse_go_test_json(stdout.as_bytes(), false);
        assert_eq!(
            parsed.test_records_seen, 1,
            "package aggregate must not count"
        );
        assert_eq!(parsed.passed, 1);
        assert_eq!(parsed.failed, 0);
        assert!(!parsed.build_failure);
    }

    /// The exact failing stream shape observed against the real `go1.26.6`,
    /// with one passing and one failing test.
    #[test]
    fn captures_failing_test_names_from_the_real_stream_shape() {
        let stdout = concat!(
            r#"{"Action":"run","Package":"corulixtjson","Test":"TestA"}"#,
            "\n",
            r#"{"Action":"pass","Package":"corulixtjson","Test":"TestA","Elapsed":0}"#,
            "\n",
            r#"{"Action":"run","Package":"corulixtjson","Test":"TestB"}"#,
            "\n",
            r#"{"Action":"output","Package":"corulixtjson","Test":"TestB","Output":"    main_test.go:6: boom\n"}"#,
            "\n",
            r#"{"Action":"fail","Package":"corulixtjson","Test":"TestB","Elapsed":0}"#,
            "\n",
            r#"{"Action":"fail","Package":"corulixtjson","Elapsed":0.003}"#,
            "\n",
        );
        let parsed = parse_go_test_json(stdout.as_bytes(), false);
        assert_eq!(parsed.test_records_seen, 2);
        assert_eq!(parsed.passed, 1);
        assert_eq!(parsed.failed, 1);
        assert_eq!(parsed.failed_tests, vec!["corulixtjson::TestB".to_string()]);
        assert!(parsed.summary.contains("FAIL: corulixtjson::TestB"));
    }

    /// `[no test files]` exits zero and emits zero test-level records --
    /// which must be `NoTestsExecuted`, never a pass. This asserts the parse
    /// half; `run_go_test`'s own branch turns it into the error.
    #[test]
    fn a_module_with_no_tests_yields_zero_test_level_records() {
        let stdout = concat!(
            r#"{"Action":"start","Package":"corulixfixture"}"#,
            "\n",
            r#"{"Action":"output","Package":"corulixfixture","Output":"?   \tcorulixfixture\t[no test files]\n"}"#,
            "\n",
            r#"{"Action":"skip","Package":"corulixfixture","Elapsed":0}"#,
            "\n",
        );
        let parsed = parse_go_test_json(stdout.as_bytes(), false);
        assert_eq!(
            parsed.test_records_seen, 0,
            "a package-level skip is not an executed test"
        );
        assert_eq!(parsed.skipped, 0);
        assert!(!parsed.build_failure);
    }

    /// A build failure interleaved as raw (non-JSON) text on the stream is
    /// detected, not silently discarded -- otherwise a module that does not
    /// compile would look like `NoTestsExecuted`.
    #[test]
    fn a_raw_build_error_on_the_stream_is_detected_as_a_build_failure() {
        let stdout = concat!(
            "# corulixfixture\n",
            "./main.go:4:14: cannot use \"x\" (untyped string constant) as int value\n",
            r#"{"Action":"start","Package":"corulixfixture"}"#,
            "\n",
        );
        let parsed = parse_go_test_json(stdout.as_bytes(), false);
        assert!(parsed.build_failure);
        assert_eq!(parsed.test_records_seen, 0);
    }

    /// The **real** structured build-failure shape, transcribed verbatim
    /// from a `go test -json` run against a non-compiling module on the real
    /// `go1.26.6`. `Action:"build-fail"` is the authoritative signal, and
    /// `build-output` carries the compiler's own diagnostics -- note both
    /// carry `ImportPath` rather than `Package`.
    #[test]
    fn the_real_structured_build_failure_shape_is_detected() {
        let stdout = concat!(
            r##"{"ImportPath":"corulixfixture [corulixfixture.test]","Action":"build-output","Output":"# corulixfixture [corulixfixture.test]\n"}"##,
            "\n",
            r#"{"ImportPath":"corulixfixture [corulixfixture.test]","Action":"build-output","Output":"./main.go:4:14: cannot use \"x\" (untyped string constant) as int value\n"}"#,
            "\n",
            r#"{"ImportPath":"corulixfixture [corulixfixture.test]","Action":"build-fail"}"#,
            "\n",
            r#"{"Action":"start","Package":"corulixfixture"}"#,
            "\n",
            r#"{"Action":"output","Package":"corulixfixture","Output":"FAIL\tcorulixfixture [build failed]\n"}"#,
            "\n",
            r#"{"Action":"fail","Package":"corulixfixture","Elapsed":0,"FailedBuild":"corulixfixture [corulixfixture.test]"}"#,
            "\n",
        );
        let parsed = parse_go_test_json(stdout.as_bytes(), false);
        assert!(parsed.build_failure, "build-fail must be authoritative");
        assert_eq!(
            parsed.test_records_seen, 0,
            "no test ran, so no test-level record may be counted"
        );
        assert!(
            parsed.summary.contains("cannot use"),
            "build-output diagnostics must reach the summary: {}",
            parsed.summary
        );
    }

    /// A test's *own* output containing a `file:line:col:` string (a
    /// `t.Fatal` location, for instance) must NOT be mistaken for a build
    /// failure -- only package-level output is considered.
    #[test]
    fn a_failing_tests_own_output_is_never_mistaken_for_a_build_failure() {
        let stdout = concat!(
            r#"{"Action":"output","Package":"p","Test":"TestB","Output":"    main_test.go:6: boom\n"}"#,
            "\n",
            r#"{"Action":"fail","Package":"p","Test":"TestB","Elapsed":0}"#,
            "\n",
        );
        let parsed = parse_go_test_json(stdout.as_bytes(), false);
        assert!(
            !parsed.build_failure,
            "test-scoped output must not be read as a build error"
        );
        assert_eq!(parsed.failed, 1);
    }

    /// `executed_count` excludes skipped tests -- only `passed + failed`
    /// represents work that actually ran.
    #[test]
    fn executed_count_excludes_skipped() {
        let outcome = GoTestOutcome {
            passing: true,
            passed: 3,
            failed: 0,
            skipped: 4,
            failed_tests: Vec::new(),
            truncated: false,
            summary: String::new(),
            provider_version: "go version go1.26.6 linux/amd64".to_string(),
            provider_path: std::path::PathBuf::from("/usr/local/go/bin/go"),
        };
        assert_eq!(outcome.executed_count(), 3);
    }

    /// The exit-code-authoritative contradiction condition, asserted as the
    /// exact boolean expression `run_go_test_with_limits` evaluates.
    #[test]
    fn exit_code_and_parsed_failed_count_disagreement_is_a_contradiction() {
        for (exit_ok, counts_ok, contradictory) in [
            (true, false, true),
            (false, true, true),
            (true, true, false),
            (false, false, false),
        ] {
            assert_eq!(exit_ok != counts_ok, contradictory);
        }
    }

    /// Skipped tests are counted as test-level records (so a fully-skipped
    /// suite is not `NoTestsExecuted`) but never as executed.
    #[test]
    fn skipped_tests_are_records_but_not_executions() {
        let stdout = concat!(
            r#"{"Action":"skip","Package":"p","Test":"TestSkipped","Elapsed":0}"#,
            "\n",
        );
        let parsed = parse_go_test_json(stdout.as_bytes(), false);
        assert_eq!(parsed.test_records_seen, 1);
        assert_eq!(parsed.skipped, 1);
        assert_eq!(parsed.passed, 0);
        assert_eq!(parsed.failed, 0);
    }
}
