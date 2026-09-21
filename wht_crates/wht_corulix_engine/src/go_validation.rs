// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15 §15-§18: real, trust-gated `go build` and `go vet` invocation,
//! composing Evidence for `GateId::Diagnostics`.
//!
//! # Reuses the existing trust gate and process runtime -- no second one
//!
//! This module calls `crate::diagnostics::authorize_trusted_execution`
//! directly (a pure `&EffectiveConfig` check with no Rust-specific
//! precondition) and spawns exclusively through
//! `wht_corulix_tooling::execute`. There is no Go-specific trust gate, no
//! Go-specific process runtime, and no Go-specific provider resolver
//! (`crate::go_providers` owns resolution, layered on the same Phase-6
//! resolver). §4 of the P15 mandate forbids duplicating any of the three.
//!
//! # Execution class: `TRUSTED_WORKSPACE_EXECUTION` (§16)
//!
//! `P15_GO_BUILD_EXECUTION_CLASS=TRUSTED_WORKSPACE_EXECUTION` and
//! `P15_GO_VET_EXECUTION_CLASS=TRUSTED_WORKSPACE_EXECUTION`, classified from
//! observed behaviour rather than convenience. Two real vectors were
//! empirically confirmed against the real `go1.26.6` on this host during
//! P15's research gate:
//!
//! 1. **cgo.** With a C compiler reachable on `PATH`, `go build` compiles
//!    *and links* repository-authored C source under repository-controlled
//!    `#cgo CFLAGS`/`LDFLAGS` directives. That is repository-authored code
//!    entering the build. `crate::go_providers::go_environment` sets
//!    `CGO_ENABLED=0`, which makes the vector unreachable today -- but a
//!    classification must describe what the operation is authorized to do,
//!    not what one environment flag currently prevents.
//! 2. **The `toolchain` directive.** A repository-authored `go.mod` carrying
//!    `toolchain go1.99.0` was observed to make the Go command *download and
//!    execute a different toolchain* (`go: downloading go1.99.0 (linux/amd64)`).
//!    `GOTOOLCHAIN=local` refuses it, and that refusal is load-bearing for
//!    `P15_AUTO_INSTALL_EXTERNAL_TOOLING=NO`.
//!
//! `go vet` builds the packages it analyses and loads analyser passes over
//! repository source, so it inherits vector 1 in full; it is classified
//! identically rather than being talked down a tier.
//!
//! Deliberately **not** claimed: any OS-level filesystem or network
//! isolation. `OS_LEVEL_NETWORK_ISOLATION=NOT_CLAIMED`. `GOPROXY=off` and
//! `GOTOOLCHAIN=local` are the Go command's *own* offline switches, honoured
//! by the Go command; they are not a kernel-enforced boundary.
//!
//! # `go build` never writes the governed workspace
//!
//! Empirically confirmed: bare `go build ./...` **writes the compiled
//! binary into the module directory** (a `corulixfixture` executable
//! appeared in the fixture root). `go build -o /dev/null ./...` was
//! confirmed to produce the identical exit status and diagnostics while
//! leaving the module directory byte-for-byte unchanged, and -- unlike
//! `-o <path>` -- it works with a multi-package `./...` pattern, which
//! `-o <file>` rejects. This module therefore always passes
//! `-o /dev/null`: `P15_GO_BUILD_WORKSPACE_ARTIFACT_WRITE_COUNT=0` by
//! construction, not by cleanup.
//!
//! `go vet` was separately confirmed to write nothing to the module
//! directory, so it needs no output redirection.
//!
//! # Authority model (`EXIT_CODE_AUTHORITATIVE + ANCHORED_TEXT_PARSE`)
//!
//! `P15_GO_VALIDATION_RESULT_MODEL=EXIT_CODE_AUTHORITATIVE + ANCHORED_TEXT_PARSE`.
//! Neither `go build` nor `go vet` offers a machine-readable diagnostic
//! stream (unlike `cargo --message-format=json`, and unlike `go test -json`
//! which `crate::go_testing` does use). Both emit diagnostics as
//! `[./]file:line[:col]: message` lines on **stderr**, optionally preceded by
//! a `# package` header line -- both shapes confirmed empirically.
//!
//! This module therefore treats the **process exit code as authoritative**
//! and the parsed findings as **descriptive**. A non-zero exit with zero
//! parsed findings is [`GoValidatorError::FailureWithoutParsedDiagnostics`],
//! never a clean pass (§17's explicit requirement, and the direct sibling of
//! `crate::diagnostics`'s own non-zero-exit-zero-findings fix). A zero exit
//! with parsed error findings is [`GoValidatorError::ResultContradiction`].
//! Neither is silently resolved in either direction.

use std::path::Path;

use wht_corulix_core::{CorulixError, CorulixResult, ExecutionClass};
use wht_corulix_tooling::{ProcessLimits, ProcessSpec, TerminationReason};

use crate::diagnostics::authorize_trusted_execution;
use crate::go_providers::{self, GoProviderError, ResolvedGoToolchain};

/// Bounded well below [`wht_corulix_core::EVIDENCE_RESULT_SUMMARY_MAX_BYTES`],
/// matching `crate::diagnostics`'s own `MAX_SUMMARY_BYTES` bound exactly.
const MAX_SUMMARY_BYTES: usize = 3800;

/// A Go build/vet of a realistic module can legitimately emit substantial
/// output, but never unboundedly.
const VALIDATOR_LIMITS: ProcessLimits = ProcessLimits {
    max_stdout_bytes: 8 * 1024 * 1024,
    max_stderr_bytes: 8 * 1024 * 1024,
};

/// Generous, but a hard ceiling: compiling a large module tree with a cold
/// build cache is genuinely slow. Not a claim that any given module finishes
/// within this window.
const VALIDATOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Which Go validator to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoValidator {
    /// `go build -o /dev/null ./...` -- `ProviderCategory::TypecheckBuild`,
    /// `AuthorityRole::Authoritative`. The authoritative Go type/build-graph
    /// validation.
    Build,
    /// `go vet ./...` -- `ProviderCategory::Linter`,
    /// `AuthorityRole::SupportingOnly`. Genuinely distinct authority from
    /// [`Self::Build`], proven empirically: a `fmt.Printf("%d", "a string")`
    /// fixture passes `go build` and fails `go vet`. Inherits `Linter`'s
    /// workspace-wide never-`Authoritative` invariant -- `go vet` can
    /// supplement `gate.diagnostics` but never close it alone.
    Vet,
}

impl GoValidator {
    /// The [`wht_corulix_core::ProviderCategory`] this validator satisfies.
    /// See [`crate::go_providers`]'s own category-mapping table.
    #[must_use]
    pub fn category(self) -> wht_corulix_core::ProviderCategory {
        match self {
            Self::Build => wht_corulix_core::ProviderCategory::TypecheckBuild,
            Self::Vet => wht_corulix_core::ProviderCategory::Linter,
        }
    }

    /// The exact argv, after `go`. `-o /dev/null` on the build arm is
    /// load-bearing -- see this module's own doc comment.
    fn arguments(self) -> Vec<String> {
        match self {
            Self::Build => vec![
                "build".to_string(),
                "-o".to_string(),
                "/dev/null".to_string(),
                "./...".to_string(),
            ],
            Self::Vet => vec!["vet".to_string(), "./...".to_string()],
        }
    }

    /// A stable, machine-readable tag for Evidence.
    #[must_use]
    pub fn provider_id(self) -> &'static str {
        match self {
            Self::Build => "go build",
            Self::Vet => "go vet",
        }
    }
}

/// Why a Go validator run could not produce trustworthy Evidence. Never a
/// free-form string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoValidatorError {
    /// The effective configuration does not authorize
    /// [`ExecutionClass::TrustedWorkspaceExecution`]. **No process is
    /// spawned** when this is returned
    /// (`P15_UNTRUSTED_GO_PROCESS_SPAWN_COUNT=0`): the check runs before any
    /// [`ProcessSpec`] is constructed.
    WorkspaceExecutionNotAuthorized,
    /// The real `go` toolchain could not be resolved or identified. Carries
    /// [`GoProviderError`] verbatim, including the resolver's own specific
    /// [`wht_corulix_core::ReasonCode`] -- no host fallback is attempted.
    Provider(GoProviderError),
    /// The validator exited non-zero but this module parsed **zero**
    /// diagnostics out of its output. Never converted into a clean pass
    /// (§17) and never into a fabricated finding: the run genuinely failed
    /// and Corulix genuinely cannot say why, which is a different, honestly
    /// distinct condition from either outcome. Carries the bounded raw
    /// summary so a caller can still see what the tool said.
    FailureWithoutParsedDiagnostics { exit_code: i32, summary: String },
    /// The validator exited zero while this module parsed at least one
    /// diagnostic that looks like an error. Fails closed rather than
    /// resolving the contradiction in either direction.
    ResultContradiction,
    /// The child process could not be spawned at all.
    SpawnFailed,
    /// The configured timeout elapsed before the validator exited.
    TimedOut,
    /// The caller's [`wht_corulix_core::CancellationToken`] fired first.
    Cancelled,
    /// Termination of a timed-out/cancelled process tree could not be
    /// confirmed.
    TerminationFailed,
    /// The validator exited with a signal rather than a normal exit code.
    Signaled,
}

/// One parsed Go diagnostic. Deliberately modest: only what the real tools'
/// own output actually provides, never fabricated structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoDiagnostic {
    /// The path exactly as the tool reported it, with any leading `./`
    /// stripped -- workspace-relative in practice, since the Go command runs
    /// with the workspace root as its working directory.
    pub relative_path: String,
    pub line: u32,
    /// `None` when the tool reported a `file:line: message` form with no
    /// column (both forms occur).
    pub column: Option<u32>,
    pub message: String,
}

/// The real, structured outcome of one Go validator run whose exit code and
/// parsed findings were confirmed *consistent*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoValidationOutcome {
    pub validator: GoValidator,
    /// Exit-code-authoritative clean/not-clean. Always equal to
    /// `diagnostics.is_empty()` by construction -- a disagreement is an
    /// `Err`, never an `Ok`.
    pub clean: bool,
    pub diagnostics: Vec<GoDiagnostic>,
    /// A bounded, human-readable summary of the tool's own output.
    pub summary: String,
    /// `true` if the tool's output, or this module's bounded summary
    /// construction, dropped content.
    pub truncated: bool,
    /// The exact provider identity, from a real `go version` probe --
    /// `P15_GO_EVIDENCE_PROVIDER_IDENTITY`, never "system go".
    pub provider_version: String,
    /// The canonicalized, trust-verified `go` executable actually invoked.
    pub provider_path: std::path::PathBuf,
}

impl GoValidationOutcome {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.clean
    }
}

fn push_bounded_line(summary: &mut String, truncated: &mut bool, line: &str) {
    if summary.len() + line.len() + 1 > MAX_SUMMARY_BYTES {
        *truncated = true;
        return;
    }
    summary.push_str(line);
    summary.push('\n');
}

/// Parses `[./]file:line[:col]: message` diagnostic lines out of a real
/// `go build`/`go vet` stream, skipping the `# package` header lines both
/// tools emit and any other unrecognized content.
///
/// Anchored text parsing, never a regex dependency: the leading token must
/// contain a `:`-separated numeric line (and optionally a numeric column)
/// followed by `: `, which is exactly the shape both tools were observed to
/// produce. "Skip, don't abort" on an unrecognized line, matching
/// `crate::diagnostics::parse_cargo_json_stream`'s own stance.
fn parse_go_diagnostics(
    output: &[u8],
    output_truncated: bool,
) -> (Vec<GoDiagnostic>, String, bool) {
    let text = String::from_utf8_lossy(output);
    let mut diagnostics = Vec::new();
    let mut summary = String::new();
    let mut summary_truncated = false;

    for raw_line in text.lines() {
        let line = raw_line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        // `# package/path` header lines carry no location and are not
        // findings in their own right; keep them in the summary for
        // readability but never count them as diagnostics.
        if line.trim_start().starts_with('#') {
            push_bounded_line(&mut summary, &mut summary_truncated, line.trim());
            continue;
        }
        if let Some(diagnostic) = parse_one_diagnostic(line.trim()) {
            push_bounded_line(&mut summary, &mut summary_truncated, line.trim());
            diagnostics.push(diagnostic);
        } else {
            push_bounded_line(&mut summary, &mut summary_truncated, line.trim());
        }
    }

    (diagnostics, summary, output_truncated || summary_truncated)
}

/// Whether `line` has the shape of a real Go tool diagnostic
/// (`file:line[:col]: message`).
///
/// Shared with [`crate::go_testing`], which needs the same recognition to
/// tell a build failure interleaved on `go test -json`'s stream apart from
/// ordinary narrative output -- one definition of "this looks like a Go
/// diagnostic", not two that could drift apart.
pub(crate) fn looks_like_go_diagnostic(line: &str) -> bool {
    parse_one_diagnostic(line.trim()).is_some()
}

/// Parses exactly one `file:line[:col]: message` line, or `None`.
fn parse_one_diagnostic(line: &str) -> Option<GoDiagnostic> {
    // Split off the message at the first `: ` that follows a numeric field,
    // scanning left to right so a `:` inside the message text cannot be
    // mistaken for a field separator.
    let mut segments = line.split(':');
    let path = segments.next()?;
    if path.is_empty() {
        return None;
    }
    let line_number: u32 = segments.next()?.trim().parse().ok()?;
    let third = segments.next()?;
    let (column, message) = match third.trim().parse::<u32>() {
        // `file:line:col: message`
        Ok(column) => {
            let rest: Vec<&str> = segments.collect();
            if rest.is_empty() {
                return None;
            }
            (Some(column), rest.join(":").trim().to_string())
        }
        // `file:line: message` -- the third field is already the message.
        Err(_) => {
            let mut rest = vec![third];
            rest.extend(segments);
            (None, rest.join(":").trim().to_string())
        }
    };
    if message.is_empty() {
        return None;
    }
    Some(GoDiagnostic {
        relative_path: path.strip_prefix("./").unwrap_or(path).trim().to_string(),
        line: line_number,
        column,
        message,
    })
}

/// Runs one real, trust-gated Go validator against `workspace_root`.
///
/// `effective` must authorize [`ExecutionClass::TrustedWorkspaceExecution`]
/// or this returns [`GoValidatorError::WorkspaceExecutionNotAuthorized`]
/// **before spawning anything** -- see this module's own doc comment for why
/// that classification is correct for both validators.
pub async fn run_go_validator(
    validator: GoValidator,
    managed_root: &Path,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<GoValidationOutcome, GoValidatorError> {
    // The one load-bearing trust gate, reused verbatim from
    // `crate::diagnostics` -- runs before any provider resolution and before
    // any `ProcessSpec` is constructed.
    authorize_trusted_execution(effective)
        .map_err(|_| GoValidatorError::WorkspaceExecutionNotAuthorized)?;

    let toolchain: ResolvedGoToolchain = go_providers::resolve_go_toolchain(
        managed_root,
        effective,
        workspace_root,
        validator.category(),
        cancellation,
    )
    .await
    .map_err(GoValidatorError::Provider)?;

    let root_path = workspace_root.canonical_path().to_path_buf();
    // See `crate::go_testing::run_go_test_with_limits`' own guard for the
    // full rationale: the existing managed-root reader/writer lock, held for
    // this whole governed execution, is what keeps a concurrent
    // `full_uninstall` from destroying the Go caches this `go build`/`go vet`
    // is actively writing.
    let _scratch_guard =
        wht_corulix_tooling::provisioning::acquire_managed_execution_scratch_guard(managed_root)
            .await;
    let scratch = go_providers::ensure_go_scratch(managed_root, &root_path)
        .map_err(GoValidatorError::Provider)?;

    let spec = ProcessSpec {
        executable: toolchain.executable.clone(),
        arguments: validator.arguments(),
        environment: go_providers::go_environment(&toolchain, &scratch),
        working_directory: root_path,
        limits: VALIDATOR_LIMITS,
        timeout: VALIDATOR_TIMEOUT,
        execution_class: ExecutionClass::TrustedWorkspaceExecution,
        argv0: None,
    };
    // M09-P7/M09-P10: binds the child's cwd to `workspace_root`'s pinned
    // root object (never a re-resolvable pathname) on Unix; on Windows,
    // `execute_with_workspace_root` fails closed before spawning anything
    // (`TerminationReason::SpawnFailed`, handled below like any other
    // spawn failure) rather than falling back to a pathname-based cwd.
    let outcome =
        wht_corulix_tooling::execute_with_workspace_root(&spec, workspace_root, cancellation).await;

    match outcome.termination {
        TerminationReason::Exited { code } => {
            // Both tools report diagnostics on stderr; stdout is included so
            // nothing the tool said is silently discarded.
            let mut combined = outcome.stderr.bytes.clone();
            combined.extend_from_slice(&outcome.stdout.bytes);
            let (diagnostics, summary, truncated) = parse_go_diagnostics(
                &combined,
                outcome.stderr.truncated || outcome.stdout.truncated,
            );

            let exit_clean = code == 0;
            if exit_clean && !diagnostics.is_empty() {
                return Err(GoValidatorError::ResultContradiction);
            }
            if !exit_clean && diagnostics.is_empty() {
                return Err(GoValidatorError::FailureWithoutParsedDiagnostics {
                    exit_code: code,
                    summary,
                });
            }
            Ok(GoValidationOutcome {
                validator,
                clean: exit_clean,
                diagnostics,
                summary,
                truncated,
                provider_version: toolchain.version,
                provider_path: toolchain.executable,
            })
        }
        TerminationReason::Signaled { .. } => Err(GoValidatorError::Signaled),
        TerminationReason::TimedOut => Err(GoValidatorError::TimedOut),
        TerminationReason::Cancelled => Err(GoValidatorError::Cancelled),
        TerminationReason::SpawnFailed => Err(GoValidatorError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(GoValidatorError::TerminationFailed),
    }
}

/// Converts a real [`GoValidationOutcome`]'s bounded `summary` into an
/// [`wht_corulix_core::EvidenceResultSummary`] -- mirrors
/// `crate::diagnostics::evidence_result_summary` exactly.
pub fn evidence_result_summary(
    outcome: &GoValidationOutcome,
) -> CorulixResult<wht_corulix_core::EvidenceResultSummary> {
    wht_corulix_core::EvidenceResultSummary::try_from(outcome.summary.clone())
        .map_err(|_| CorulixError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact `go build` failure shape observed against the real
    /// `go1.26.6`: a `# package` header followed by a
    /// `./file:line:col: message` finding.
    #[test]
    fn parses_a_real_go_build_failure() {
        let stderr = "# corulixfixture\n./main.go:4:14: cannot use \"not an int\" (untyped string constant) as int value in variable declaration\n";
        let (diagnostics, summary, truncated) = parse_go_diagnostics(stderr.as_bytes(), false);
        assert_eq!(
            diagnostics.len(),
            1,
            "header line must not count as a finding"
        );
        assert_eq!(diagnostics[0].relative_path, "main.go");
        assert_eq!(diagnostics[0].line, 4);
        assert_eq!(diagnostics[0].column, Some(14));
        assert!(diagnostics[0].message.contains("cannot use"));
        assert!(summary.contains("# corulixfixture"));
        assert!(!truncated);
    }

    /// The exact `go vet` failure shape observed against the real
    /// `go1.26.6`: no `./` prefix, and a message that itself contains a
    /// quoted string.
    #[test]
    fn parses_a_real_go_vet_failure() {
        let stderr =
            "main.go:6:14: fmt.Printf format %d has arg \"a string\" of wrong type string\n";
        let (diagnostics, _, _) = parse_go_diagnostics(stderr.as_bytes(), false);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].relative_path, "main.go");
        assert_eq!(diagnostics[0].line, 6);
        assert_eq!(diagnostics[0].column, Some(14));
        assert!(diagnostics[0].message.contains("wrong type string"));
    }

    /// A `file:line: message` form (no column) is parsed, not dropped.
    #[test]
    fn parses_a_diagnostic_without_a_column() {
        let (diagnostics, _, _) =
            parse_go_diagnostics(b"main.go:12: something went wrong\n", false);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, 12);
        assert_eq!(diagnostics[0].column, None);
        assert_eq!(diagnostics[0].message, "something went wrong");
    }

    /// A `:` inside the message must not be mistaken for a field separator.
    #[test]
    fn a_colon_inside_the_message_is_preserved() {
        let (diagnostics, _, _) =
            parse_go_diagnostics(b"main.go:3:1: undefined: helperFunction\n", false);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "undefined: helperFunction");
    }

    /// Clean output produces zero diagnostics -- and a clean run is what the
    /// caller then pairs with a zero exit code.
    #[test]
    fn clean_output_yields_no_diagnostics() {
        let (diagnostics, _, _) = parse_go_diagnostics(b"", false);
        assert!(diagnostics.is_empty());
    }

    /// Non-diagnostic narrative lines are kept in the summary but never
    /// counted as findings -- so they can never make a clean run look dirty.
    #[test]
    fn narrative_output_is_summarized_but_never_counted_as_a_finding() {
        let stderr = "go: warning: \"./...\" matched no packages\n";
        let (diagnostics, summary, _) = parse_go_diagnostics(stderr.as_bytes(), false);
        assert!(diagnostics.is_empty());
        assert!(summary.contains("matched no packages"));
    }

    /// The two categories are genuinely distinct, and `go vet` is mapped to
    /// `Linter` (which the policy table forbids from ever being
    /// `Authoritative`), never to `TypecheckBuild`.
    #[test]
    fn build_and_vet_map_to_distinct_provider_categories() {
        assert_eq!(
            GoValidator::Build.category(),
            wht_corulix_core::ProviderCategory::TypecheckBuild
        );
        assert_eq!(
            GoValidator::Vet.category(),
            wht_corulix_core::ProviderCategory::Linter
        );
        assert_ne!(GoValidator::Build.category(), GoValidator::Vet.category());
    }

    /// `P15_GO_BUILD_WORKSPACE_ARTIFACT_WRITE_COUNT=0` as a structural
    /// assertion on the constructed argv: bare `go build` writes the compiled
    /// binary into the module directory (empirically confirmed), so the
    /// `-o /dev/null` redirection must always be present.
    #[test]
    fn go_build_always_redirects_its_output_away_from_the_workspace() {
        let arguments = GoValidator::Build.arguments();
        let position = arguments.iter().position(|argument| argument == "-o");
        assert!(
            position.is_some(),
            "go build must always pass -o: {arguments:?}"
        );
        assert_eq!(
            arguments
                .get(position.unwrap_or_default() + 1)
                .map(String::as_str),
            Some("/dev/null")
        );
    }

    /// `go vet` needs no output redirection (confirmed: it writes nothing to
    /// the module directory) and must not pretend to build authority by
    /// carrying build flags.
    #[test]
    fn go_vet_argv_is_exactly_vet_over_the_module() {
        assert_eq!(GoValidator::Vet.arguments(), vec!["vet", "./..."]);
    }

    /// The bounded summary never exceeds this module's own cap, matching
    /// `crate::diagnostics`'s bound so an `EvidenceResultSummary` conversion
    /// can never fail on size.
    #[test]
    fn the_summary_is_bounded() {
        let huge = format!("main.go:1:1: {}\n", "x".repeat(MAX_SUMMARY_BYTES * 3));
        let (_, summary, truncated) = parse_go_diagnostics(huge.as_bytes(), false);
        assert!(summary.len() <= MAX_SUMMARY_BYTES);
        assert!(truncated);
    }
}
