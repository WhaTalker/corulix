// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P17 production-routing closure: real `pyright --outputjson <path>`
//! (`ProviderCategory::TypecheckBuild`, `AuthorityRole::Authoritative`) and
//! real `ruff check <staged-copy>` (`ProviderCategory::Linter`,
//! `AuthorityRole::SupportingOnly`) invocation, composing Evidence for
//! `GateId::Diagnostics` -- the Python sibling of [`crate::diagnostics`]
//! (Rust), [`crate::go_validation`] (Go), and [`crate::ts_validation`]
//! (TS/JS). ADR 0011
//! (`wht_docs/wht_adr/wht_0011-python-provider-vertical-p17.md`) is this
//! module's authority for every decision below.
//!
//! # Trust model: `CONTROLLED_EXTERNAL_TOOL`, mirroring TS/JS not Go
//!
//! ADR 0011 §1/§2/§3 classify `ruff format`/`ruff check`/`pyright
//! --outputjson` all `ExecutionClass::ControlledExternalTool`: none of the
//! three executes arbitrary repository-authored code as part of formatting,
//! linting, or type-checking (unlike Go's `go build`/`go vet`, which compile
//! and can link repository-authored code). `wht_corulix_config::
//! EffectiveConfig::is_execution_class_allowed(ControlledExternalTool)` is
//! unconditionally `true`, so -- like [`crate::ts_validation`] and unlike
//! [`crate::go_validation`] -- this module gates nothing on workspace trust
//! before spawning; the real gate is provider *resolution* itself, via
//! [`crate::python_providers::resolve_python_tool`] (`HOST_ONLY`/approved-
//! directory precedence, never ambient `PATH`).
//!
//! # `ruff check` scope: a confined staged copy, never the live workspace path
//!
//! Mirrors [`crate::ts_validation`]'s own Biome-lint discipline exactly
//! (same rationale, same mechanism): this module reads the target's current
//! governed bytes via `wht_corulix_workspace::confined_read` and writes them
//! to a Corulix-owned scratch file under `managed_root` (preserving the
//! `.py`/`.pyi` extension so ruff classifies the content correctly) before
//! invoking `ruff check` against that scratch path --
//! `P17_RUFF_CHECK_LIVE_WORKSPACE_PATH_COUNT=0` by construction. ADR 0011's
//! own research note observed `ruff check --stdin-filename foo.py -` (a
//! stdin/stdout invocation) producing the identical real, structured finding
//! (`F401`); this module uses a staged positional file instead of stdin
//! because this crate has no stdin-capable process invocation of its own
//! (that capability is `wht_corulix_formatter::invocation`'s private,
//! formatter-only implementation) -- the staged-file technique is the
//! already-certified TS/JS pattern, and ruff's own documented behavior
//! accepts a positional path exactly as it accepts stdin.
//!
//! # `pyright --outputjson` scope: the whole session workspace root
//!
//! Unlike `ruff check`'s single-file scope, `pyright --outputjson <path>` is
//! a real *project* typecheck (ADR 0011 §3): it is invoked with the
//! session's own workspace root as its sole positional argument, mirroring
//! [`crate::ts_validation::run_typecheck`]'s `tsc --noEmit` invocation over
//! the whole workspace.
//!
//! # Result model: `EXIT_CODE_AUTHORITATIVE + JSON_PARSE`
//!
//! `pyright --outputjson` emits one JSON object on stdout
//! (`{"summary": {"errorCount": N, "warningCount": N, ...}, ...}`), exit `0`
//! when `errorCount == 0`, non-zero otherwise (pyright's own documented
//! contract). `ruff check` with no `--output-format` flag emits `path:line:
//! col: CODE message` lines on stdout, exit `0` clean / non-zero when any
//! finding is reported (ADR 0011 §2, empirically confirmed). Neither offers
//! a way to reconcile a non-zero exit with zero parsed findings into a clean
//! result: that contradiction fails closed here exactly as
//! [`crate::go_validation`]'s own `FailureWithoutParsedDiagnostics`/
//! `ResultContradiction` pair does.

use std::path::{Path, PathBuf};

use wht_corulix_core::{CorulixError, CorulixResult};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, TerminationReason};

use crate::python_providers::{
    self, PYRIGHT_EXECUTABLE, PythonProviderError, RUFF_EXECUTABLE, ResolvedPyrightCli,
};

const MAX_SUMMARY_BYTES: usize = 3800;

const VALIDATOR_LIMITS: ProcessLimits = ProcessLimits {
    max_stdout_bytes: 8 * 1024 * 1024,
    max_stderr_bytes: 8 * 1024 * 1024,
};

/// Generous but bounded -- a cold `pyright --outputjson` over a realistic
/// project is genuinely slow; this is a hard ceiling, not an expected
/// duration.
const VALIDATOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Which Python validator to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonValidator {
    /// `pyright --outputjson <workspace root>` --
    /// `ProviderCategory::TypecheckBuild`, `AuthorityRole::Authoritative`.
    /// Distinct from `wht_corulix_lsp`'s own long-lived Pyright *session*
    /// (ADR 0011 §3: `P17_PYRIGHT_SEMANTIC_VS_TYPECHECK_AUTHORITY=EXPLICIT`).
    Typecheck,
    /// `ruff check <staged copy>` -- `ProviderCategory::Linter`,
    /// `AuthorityRole::SupportingOnly`.
    Lint,
}

impl PythonValidator {
    #[must_use]
    pub fn category(self) -> wht_corulix_core::ProviderCategory {
        match self {
            Self::Typecheck => wht_corulix_core::ProviderCategory::TypecheckBuild,
            Self::Lint => wht_corulix_core::ProviderCategory::Linter,
        }
    }

    #[must_use]
    pub fn provider_id(self) -> &'static str {
        match self {
            Self::Typecheck => "pyright --outputjson",
            Self::Lint => "ruff check",
        }
    }
}

/// Why a Python validator run could not produce trustworthy Evidence. Never
/// a free-form string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonValidatorError {
    /// The real `pyright`/`ruff` binary could not be resolved or identified.
    /// Carries [`PythonProviderError`] verbatim -- no host fallback.
    Provider(PythonProviderError),
    /// The staged copy `ruff check` must lint could not be read/written.
    StagedCopyUnavailable,
    /// The validator exited non-zero but this module parsed zero findings
    /// out of its output -- never converted into a clean pass, never
    /// fabricated into a finding.
    FailureWithoutParsedDiagnostics {
        exit_code: i32,
        summary: String,
    },
    /// The validator exited zero while this module parsed at least one
    /// finding that looks like an error.
    ResultContradiction,
    SpawnFailed,
    TimedOut,
    Cancelled,
    TerminationFailed,
    Signaled,
}

/// The real, structured outcome of one Python validator run whose exit code
/// and parsed findings were confirmed *consistent*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonValidationOutcome {
    pub validator: PythonValidator,
    pub clean: bool,
    pub finding_count: u32,
    pub summary: String,
    pub truncated: bool,
    pub provider_version: String,
}

impl PythonValidationOutcome {
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

/// Real pyright `--outputjson` shape, deserialized minimally: only the
/// fields this module actually consults.
#[derive(Debug, Clone, serde::Deserialize)]
struct PyrightReport {
    summary: PyrightSummary,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct PyrightSummary {
    #[serde(rename = "errorCount")]
    error_count: u32,
    #[serde(rename = "warningCount")]
    warning_count: u32,
}

/// One real, structured `ruff check --output-format=json` diagnostic --
/// deserialized minimally, but requiring a real field (never an empty `{}`
/// marker type) so a differently-shaped payload fails to parse rather than
/// silently satisfying this type. `severity` is not currently read further:
/// the managed Ruff 0.16.3 binary was empirically confirmed (real fixtures:
/// a single unused-import finding, multiple findings, a syntax-invalid
/// file, and a missing-file invocation failure) to report every diagnostic
/// -- lint violation or invocation-level `io-error` alike -- as
/// `"severity": "error"`, with no observed warnings-only/clean-exit case
/// analogous to Biome's (see `crate::ts_validation`'s own P-M05-R2 fix);
/// this module's exit-code contradiction check therefore uses the parsed
/// array's length directly, not a severity split.
#[derive(Debug, Clone, serde::Deserialize)]
struct RuffDiagnostic {
    #[allow(dead_code)]
    severity: String,
}

/// Whether a completed `ruff check --output-format=json` run's exit code and
/// parsed diagnostic array are mutually consistent -- pure and process-free,
/// so it can be exercised directly by regression tests without spawning
/// Ruff. `run_lint` is the sole real caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuffLintContradiction {
    /// Exit `0` (Ruff's own "no findings" signal) alongside at least one
    /// parsed diagnostic -- a genuine mismatch between Ruff's exit code and
    /// its own JSON output.
    ExitCleanWithFindings,
    /// Exit non-zero (Ruff's own "at least one finding" signal) but this
    /// module could not corroborate a single parsed diagnostic (unparseable
    /// payload, or a genuinely empty array) -- fails closed rather than
    /// presenting an unexamined result as a zero-finding clean pass.
    ExitFailedWithoutFindings,
}

/// P-M05-R2 fix: `finding_count` derives from the real, structured JSON
/// array's length (never the previous line-count heuristic, which could be
/// inflated by any context/pointer/help line in Ruff's undeclared default
/// text format that happened to contain a colon) -- see this module's own
/// defect writeup at
/// `m05_focused_2026-09-09/preflight/DEFECT_LINT_RESULT_MISINTERPRETATION.md`.
/// Ruff's own exit-code contract (empirically confirmed against the real
/// managed Ruff 0.16.3 binary across a clean file, a single finding,
/// multiple findings, a syntax-invalid file, and a missing-file invocation
/// failure) is simpler than Biome's: every observed diagnostic -- lint
/// violation or invocation-level `io-error` alike -- reports
/// `"severity": "error"`, and exit is `0` iff the array is empty; no
/// warnings-only/clean-exit case was ever observed, so (unlike
/// [`crate::ts_validation::interpret_biome_lint_result`]) no severity split
/// is needed here.
fn interpret_ruff_lint_result(
    exit_code: i32,
    diagnostics: Option<&[RuffDiagnostic]>,
) -> Result<(bool, u32), RuffLintContradiction> {
    let exit_clean = exit_code == 0;
    let finding_count = diagnostics.map_or(0, |list| list.len() as u32);

    if exit_clean && finding_count > 0 {
        return Err(RuffLintContradiction::ExitCleanWithFindings);
    }
    if !exit_clean && finding_count == 0 {
        return Err(RuffLintContradiction::ExitFailedWithoutFindings);
    }
    Ok((exit_clean, finding_count))
}

/// Runs the real, project-wide `pyright --outputjson <workspace_root>`,
/// managed-first then `HOST_ONLY`-fallback (M03 Python managed-auxiliary
/// final closure): `python_providers::resolve_pyright_cli` resolves either
/// a managed `node <dist/pyright.js>` invocation or the pre-existing
/// `HOST_ONLY` `pyright` executable, and this function builds the
/// `ProcessSpec` from whichever shape was actually resolved --
/// `ResolvedPyrightCli::executable_and_leading_arguments` is the one place
/// that difference is expressed.
pub async fn run_typecheck(
    managed_root: &Path,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<PythonValidationOutcome, PythonValidatorError> {
    let pyright_cli = python_providers::resolve_pyright_cli(
        managed_root,
        effective,
        workspace_root,
        cancellation,
    )
    .await
    .map_err(PythonValidatorError::Provider)?;

    // The `HOST_ONLY` tier needs a real `node` interpreter, resolved
    // independently and placed on this invocation's own `PATH` -- load-
    // bearing, since a `HOST_ONLY`-resolved `pyright` is a
    // `#!/usr/bin/env node` script (see
    // `crate::python_providers::pyright_invocation_environment`'s own doc
    // comment for why deriving this from pyright's own resolved path is
    // wrong). The managed tier spawns `node` directly with an absolute
    // script path, so it needs no such `PATH` construction.
    let environment = match &pyright_cli {
        ResolvedPyrightCli::HostOnly { .. } => python_providers::pyright_invocation_environment(
            effective,
            workspace_root,
            cancellation,
        )
        .await
        .ok_or(PythonValidatorError::Provider(
            PythonProviderError::ProviderUnavailable(None),
        ))?,
        ResolvedPyrightCli::Managed { .. } => EnvironmentPolicy::empty(),
    };
    let argv0 = match &pyright_cli {
        ResolvedPyrightCli::HostOnly { .. } => Some(PYRIGHT_EXECUTABLE.to_string()),
        ResolvedPyrightCli::Managed { .. } => None,
    };

    let root_path = workspace_root.canonical_path().to_path_buf();
    let (executable, mut arguments) = pyright_cli.executable_and_leading_arguments();
    arguments.push("--outputjson".to_string());
    arguments.push(root_path.to_string_lossy().into_owned());
    let spec = ProcessSpec {
        executable,
        arguments,
        environment,
        working_directory: root_path,
        limits: VALIDATOR_LIMITS,
        timeout: VALIDATOR_TIMEOUT,
        execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
        argv0,
    };
    // M09-P7/M09-P10: binds the child's cwd to `workspace_root`'s pinned
    // root object on Unix; on Windows, `execute_with_workspace_root` fails
    // closed before spawning anything rather than falling back to a
    // pathname-based cwd.
    let outcome =
        wht_corulix_tooling::execute_with_workspace_root(&spec, workspace_root, cancellation).await;

    match outcome.termination {
        TerminationReason::Exited { code } => {
            let stdout_text = String::from_utf8_lossy(&outcome.stdout.bytes);
            let report: Option<PyrightReport> = serde_json::from_str(&stdout_text).ok();

            let mut summary = String::new();
            let mut truncated = outcome.stdout.truncated || outcome.stderr.truncated;
            push_bounded_line(&mut summary, &mut truncated, stdout_text.trim());

            let exit_clean = code == 0;
            let error_count = report
                .as_ref()
                .map_or(0, |report| report.summary.error_count);
            let finding_count = report
                .as_ref()
                .map(|report| {
                    report
                        .summary
                        .error_count
                        .saturating_add(report.summary.warning_count)
                })
                .unwrap_or(0);

            if exit_clean && error_count > 0 {
                return Err(PythonValidatorError::ResultContradiction);
            }
            if !exit_clean && report.is_none() {
                return Err(PythonValidatorError::FailureWithoutParsedDiagnostics {
                    exit_code: code,
                    summary,
                });
            }
            Ok(PythonValidationOutcome {
                validator: PythonValidator::Typecheck,
                clean: exit_clean,
                finding_count,
                summary,
                truncated,
                provider_version: pyright_cli.version().to_string(),
            })
        }
        TerminationReason::Signaled { .. } => Err(PythonValidatorError::Signaled),
        TerminationReason::TimedOut => Err(PythonValidatorError::TimedOut),
        TerminationReason::Cancelled => Err(PythonValidatorError::Cancelled),
        TerminationReason::SpawnFailed => Err(PythonValidatorError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(PythonValidatorError::TerminationFailed),
    }
}

/// Materializes `relative_path`'s current governed bytes into a Corulix-owned
/// scratch file under `managed_root` (never the live workspace path -- see
/// this module's own doc comment), preserving the original extension.
/// Mirrors [`crate::ts_validation`]'s own `stage_file_for_biome_lint` exactly.
async fn stage_file_for_ruff_check(
    managed_root: &Path,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    relative_path: &str,
) -> CorulixResult<PathBuf> {
    const MAX_LINT_TARGET_BYTES: u64 = 8 * 1024 * 1024;
    let bytes = wht_corulix_workspace::confined_read(
        workspace_root.clone(),
        PathBuf::from(relative_path),
        MAX_LINT_TARGET_BYTES,
    )
    .await?;

    let extension = Path::new(relative_path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("py")
        .to_string();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let file_name = format!("staged-{stamp}.{extension}");
    let root = managed_root.to_path_buf();

    // `relative_dir` is joined under `MANAGED_SCRATCH_DIR` ("scratch"), not a
    // bare "ruff-lint" -- `full_uninstall::cleanup_lifecycle_shells_and_root`
    // specifically targets `root.join(MANAGED_SCRATCH_DIR)`, so a staged file
    // living outside that tree would never be reached by zero-residual
    // uninstall (the same convention `crate::ts_validation::
    // stage_file_for_biome_lint` and `crate::go_providers::
    // go_scratch_relative` already follow).
    let relative_dir = format!(
        "{}/ruff-lint",
        wht_corulix_tooling::provisioning::MANAGED_SCRATCH_DIR
    );
    tokio::task::spawn_blocking(move || {
        wht_corulix_tooling::provisioning::write_scratch_file(
            &root,
            &relative_dir,
            &file_name,
            &bytes,
        )
    })
    .await
    .map_err(|_| CorulixError::Internal)?
    .map_err(|_| CorulixError::Internal)
}

/// Runs real, read-only `ruff check` against a confined staged copy of
/// `relative_path`'s current governed content.
pub async fn run_lint(
    managed_root: &Path,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    relative_path: &str,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<PythonValidationOutcome, PythonValidatorError> {
    let toolchain = python_providers::resolve_ruff_tool(
        managed_root,
        effective,
        workspace_root,
        wht_corulix_core::ProviderCategory::Linter,
        cancellation,
    )
    .await
    .map_err(PythonValidatorError::Provider)?;

    let staged_path = stage_file_for_ruff_check(managed_root, workspace_root, relative_path)
        .await
        .map_err(|_| PythonValidatorError::StagedCopyUnavailable)?;
    // The staged file's own parent (`<managed_root>/scratch/ruff-lint/`),
    // never the bare `managed_root` itself -- see the `--no-cache` note
    // immediately below for why this matters even with a scoped working
    // directory.
    let working_directory = staged_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| managed_root.to_path_buf());

    let spec = ProcessSpec {
        executable: toolchain.executable.clone(),
        arguments: vec![
            "check".to_string(),
            // P-M05-R2 fix: real `ruff check` (managed 0.16.3) was
            // empirically confirmed to emit a single top-level JSON array
            // (one object per real diagnostic) under `--output-format=json`
            // on stdout with no interleaved banner text (unlike Biome's
            // `--reporter=json`), and to exit non-zero exactly when that
            // array is non-empty. Without this flag, `ruff check` used its
            // undeclared default (`full`, multi-line-per-finding human text)
            // whose context/pointer/help lines could each independently
            // satisfy a naive per-line heuristic and inflate the finding
            // count -- see this module's own defect writeup at
            // `m05_focused_2026-09-09/preflight/DEFECT_LINT_RESULT_MISINTERPRETATION.md`.
            "--output-format=json".to_string(),
            // `--no-cache`: real `ruff check` was empirically confirmed to
            // write a `.ruff_cache/` directory into its *current working
            // directory* by default -- with `working_directory` set to
            // `managed_root` (this module's pre-fix behavior), that cache
            // landed directly inside the shared, host-wide
            // `managed_toolchain_root()`, outside `MANAGED_SCRATCH_DIR`,
            // where no zero-residual/full_uninstall check ever looks for it
            // (confirmed to trip `wht_corulix_lsp`'s own
            // `real_ts6_active_full_uninstall_process_zero_state_e2e`,
            // which scans the shared managed root for exactly this kind of
            // untracked residual). `--no-cache` closes this at the source,
            // and scoping `working_directory` to the staged file's own
            // scratch subdirectory (never the bare managed root) is a
            // second, independent layer of defense -- the same
            // "scratch path outside MANAGED_SCRATCH_DIR" bug class already
            // found and fixed twice in Go and once in TS/JS.
            "--no-cache".to_string(),
            staged_path.to_string_lossy().into_owned(),
        ],
        environment: EnvironmentPolicy::empty(),
        working_directory,
        limits: VALIDATOR_LIMITS,
        timeout: VALIDATOR_TIMEOUT,
        execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
        argv0: Some(RUFF_EXECUTABLE.to_string()),
    };
    let outcome = wht_corulix_tooling::execute(&spec, cancellation).await;
    let cleanup_path = staged_path.clone();
    let _ = tokio::task::spawn_blocking(move || {
        wht_corulix_tooling::provisioning::remove_scratch_file(&cleanup_path)
    })
    .await;

    match outcome.termination {
        TerminationReason::Exited { code } => {
            let stdout_text = String::from_utf8_lossy(&outcome.stdout.bytes);
            let diagnostics: Option<Vec<RuffDiagnostic>> =
                serde_json::from_str(stdout_text.trim()).ok();

            let mut summary = String::new();
            let mut truncated = outcome.stdout.truncated || outcome.stderr.truncated;
            push_bounded_line(&mut summary, &mut truncated, stdout_text.trim());

            match interpret_ruff_lint_result(code, diagnostics.as_deref()) {
                Ok((clean, finding_count)) => Ok(PythonValidationOutcome {
                    validator: PythonValidator::Lint,
                    clean,
                    finding_count,
                    summary,
                    truncated,
                    provider_version: toolchain.version,
                }),
                Err(RuffLintContradiction::ExitCleanWithFindings) => {
                    Err(PythonValidatorError::ResultContradiction)
                }
                Err(RuffLintContradiction::ExitFailedWithoutFindings) => {
                    Err(PythonValidatorError::FailureWithoutParsedDiagnostics {
                        exit_code: code,
                        summary,
                    })
                }
            }
        }
        TerminationReason::Signaled { .. } => Err(PythonValidatorError::Signaled),
        TerminationReason::TimedOut => Err(PythonValidatorError::TimedOut),
        TerminationReason::Cancelled => Err(PythonValidatorError::Cancelled),
        TerminationReason::SpawnFailed => Err(PythonValidatorError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(PythonValidatorError::TerminationFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typecheck_and_lint_map_to_distinct_provider_categories() {
        assert_eq!(
            PythonValidator::Typecheck.category(),
            wht_corulix_core::ProviderCategory::TypecheckBuild
        );
        assert_eq!(
            PythonValidator::Lint.category(),
            wht_corulix_core::ProviderCategory::Linter
        );
        assert_ne!(
            PythonValidator::Typecheck.category(),
            PythonValidator::Lint.category()
        );
    }

    #[test]
    fn pyright_json_report_deserializes_findings() {
        let raw = r#"{"version":"1.1.413","time":"0","generalDiagnostics":[],"summary":{"filesAnalyzed":1,"errorCount":1,"warningCount":2,"informationCount":0,"timeInSec":0.1}}"#;
        let parsed: Result<PyrightReport, _> = serde_json::from_str(raw);
        assert!(parsed.is_ok(), "expected valid pyright json: {parsed:?}");
        let report = parsed.unwrap_or(PyrightReport {
            summary: PyrightSummary {
                error_count: 0,
                warning_count: 0,
            },
        });
        assert_eq!(report.summary.error_count, 1);
        assert_eq!(report.summary.warning_count, 2);
    }

    #[test]
    fn the_summary_is_bounded() {
        let huge = format!("a.py:1:1: F401 {}\n", "x".repeat(MAX_SUMMARY_BYTES * 3));
        let mut summary = String::new();
        let mut truncated = false;
        for line in huge.lines() {
            push_bounded_line(&mut summary, &mut truncated, line);
        }
        assert!(summary.len() <= MAX_SUMMARY_BYTES);
        assert!(truncated);
    }

    fn ruff_diagnostics(count: usize) -> Vec<RuffDiagnostic> {
        (0..count)
            .map(|_| RuffDiagnostic {
                severity: "error".to_string(),
            })
            .collect()
    }

    /// PY1 CLEAN: an empty structured array, exit `0` -- zero real findings.
    #[test]
    fn py1_ruff_clean_empty_array_is_accepted() {
        let diagnostics = ruff_diagnostics(0);
        let outcome = interpret_ruff_lint_result(0, Some(&diagnostics));
        assert_eq!(outcome, Ok((true, 0)));
    }

    /// PY2 SINGLE FINDING WITH TYPE ANNOTATION: real captured Ruff
    /// `--output-format=json` output for a single genuine `F401`
    /// unused-import finding, whose default (`full`) text rendering
    /// includes a ` --> path:line:col` pointer line and a `help:` line --
    /// both of which the old per-line colon heuristic separately miscounted
    /// (proven live: reported `2`, not `1`). The structured array's length
    /// must be exactly `1`, never `2` or `3`.
    #[test]
    fn py2_single_finding_is_not_inflated_by_pointer_or_help_lines() {
        let raw = r#"[
          {
            "cell": null,
            "code": "F401",
            "end_location": {"column": 10, "row": 1},
            "filename": "/staged/main.py",
            "fix": null,
            "location": {"column": 8, "row": 1},
            "message": "`os` imported but unused",
            "name": "unused-import",
            "noqa_row": 1,
            "severity": "error",
            "url": "https://docs.astral.sh/ruff/rules/unused-import"
          }
        ]"#;
        let parsed: Result<Vec<RuffDiagnostic>, _> = serde_json::from_str(raw);
        assert!(parsed.is_ok(), "expected valid ruff json array: {parsed:?}");
        let diagnostics = parsed.unwrap_or_default();
        let outcome = interpret_ruff_lint_result(1, Some(&diagnostics));
        assert_eq!(outcome, Ok((false, 1)));
    }

    /// PY3 SINGLE FINDING, source line carries a type annotation (`a: int`)
    /// -- real captured Ruff output for a syntax-invalid file whose default
    /// text rendering's source-context line (`def broken(a: int, ...`) was
    /// separately miscounted by the old heuristic (proven live: reported
    /// `3`, not `1`). Structured parsing must remain exactly one diagnostic
    /// regardless of how many colons the underlying source line contains.
    #[test]
    fn py3_single_finding_is_not_inflated_by_type_annotation_colons() {
        let raw = r#"[
          {
            "cell": null,
            "code": "invalid-syntax",
            "end_location": {"column": 1, "row": 2},
            "filename": "/staged/main.py",
            "fix": null,
            "location": {"column": 34, "row": 1},
            "message": "Expected `:`, found newline",
            "name": "invalid-syntax",
            "noqa_row": null,
            "severity": "error",
            "url": null
          }
        ]"#;
        let parsed: Result<Vec<RuffDiagnostic>, _> = serde_json::from_str(raw);
        assert!(parsed.is_ok(), "expected valid ruff json array: {parsed:?}");
        let diagnostics = parsed.unwrap_or_default();
        let outcome = interpret_ruff_lint_result(1, Some(&diagnostics));
        assert_eq!(outcome, Ok((false, 1)));
    }

    /// PY4 MULTIPLE FINDINGS: N real findings must report exactly N, never
    /// inflated or deflated.
    #[test]
    fn py4_multiple_findings_report_exact_count() {
        let diagnostics = ruff_diagnostics(3);
        let outcome = interpret_ruff_lint_result(1, Some(&diagnostics));
        assert_eq!(outcome, Ok((false, 3)));
    }

    /// PY5 SYNTAX / INVALID CASE: a single `invalid-syntax` diagnostic
    /// behaves exactly like any other single finding -- deterministic,
    /// exact count, no special-casing by diagnostic code.
    #[test]
    fn py5_syntax_invalid_reports_deterministic_exact_count() {
        let diagnostics = ruff_diagnostics(1);
        let outcome = interpret_ruff_lint_result(1, Some(&diagnostics));
        assert_eq!(outcome, Ok((false, 1)));
    }

    /// PY6 MALFORMED STRUCTURED OUTPUT: a non-zero exit whose payload could
    /// not be parsed as a JSON array of diagnostics at all (`None`) must
    /// fail closed, never silently become a zero-finding clean-looking
    /// result.
    #[test]
    fn py6_malformed_output_on_non_zero_exit_fails_closed() {
        let outcome = interpret_ruff_lint_result(1, None);
        assert_eq!(
            outcome,
            Err(RuffLintContradiction::ExitFailedWithoutFindings)
        );
    }

    /// PY7 EMPTY VALID STRUCTURED OUTPUT: a genuinely empty array is a real,
    /// legitimate `Ok` outcome, never conflated with defect 6's malformed
    /// case even though both ultimately yield `finding_count: 0`.
    #[test]
    fn py7_empty_valid_structured_output_is_a_real_clean_result() {
        let diagnostics = ruff_diagnostics(0);
        let outcome = interpret_ruff_lint_result(0, Some(&diagnostics));
        assert_eq!(outcome, Ok((true, 0)));
    }

    /// A real contradiction (Ruff's own exit code disagreeing with its own
    /// parsed array) must still fail closed.
    #[test]
    fn exit_clean_with_a_real_finding_is_still_a_contradiction() {
        let diagnostics = ruff_diagnostics(1);
        let outcome = interpret_ruff_lint_result(0, Some(&diagnostics));
        assert_eq!(outcome, Err(RuffLintContradiction::ExitCleanWithFindings));
    }

    /// A non-zero exit with a genuinely empty (but successfully parsed)
    /// array must also fail closed -- symmetric with the malformed-output
    /// case, matching `crate::ts_validation`'s own P-M05-R2 Biome fix.
    #[test]
    fn exit_failed_with_a_valid_empty_array_still_fails_closed() {
        let diagnostics = ruff_diagnostics(0);
        let outcome = interpret_ruff_lint_result(1, Some(&diagnostics));
        assert_eq!(
            outcome,
            Err(RuffLintContradiction::ExitFailedWithoutFindings)
        );
    }
}
