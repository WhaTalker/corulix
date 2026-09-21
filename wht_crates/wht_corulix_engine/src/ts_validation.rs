// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P16 production-routing closure: real, version-routed `tsc --noEmit`
//! (`ProviderCategory::TypecheckBuild`, `AuthorityRole::Authoritative`) and
//! real `biome lint --reporter=json` (`ProviderCategory::Linter`,
//! `AuthorityRole::SupportingOnly`) invocation for the TS-family languages
//! (`TypeScript`/`Tsx`/`JavaScript`), composing Evidence for
//! `GateId::Diagnostics` -- the TS/JS sibling of
//! [`crate::diagnostics`] (Rust) and [`crate::go_validation`] (Go). ADR 0010
//! (`wht_docs/wht_adr/wht_0010-typescript-javascript-provider-vertical-p16.md`)
//! is this module's authority for every decision below; nothing here
//! reopens it.
//!
//! # Trust model: `CONTROLLED_EXTERNAL_TOOL`, not `TRUSTED_WORKSPACE_EXECUTION`
//!
//! Unlike Rust's `cargo check`/clippy and Go's `go build`/`go vet` (both
//! `TrustedWorkspaceExecution`, because they execute repository-authored
//! `build.rs`/`cgo`/analyzer passes), `tsc --noEmit` and `biome lint` do not
//! execute arbitrary repository-authored code as part of type-checking or
//! linting -- ADR 0010's own `TRUST_MODEL` section classifies both as
//! `ControlledExternalTool`, resolved exclusively through their pinned
//! `CORULIX_MANAGED` components. `wht_corulix_config::trust::EffectiveConfig::
//! is_execution_class_allowed(ControlledExternalTool)` is unconditionally
//! `true` (see `trust.rs`'s own match arm), so -- unlike
//! `crate::diagnostics::authorize_trusted_execution` -- this module gates
//! nothing on workspace trust before spawning; the real gate is managed-
//! component *availability*, checked via [`wht_corulix_tooling::provisioning::
//! resolve_owned_managed_component`] (never a bare filesystem-presence check,
//! per `CORULIX_INSTALLS_IT -> CORULIX_OWNS_IT -> CORULIX_TRACKS_IT`).
//!
//! # `tsc` version routing (ADR 0010 `TS_VERSION_ROUTING_POLICY`)
//!
//! `None`/`Some(7)` routes to the TS7-native managed `tsc` (a real, statically
//! linked native executable -- confirmed empirically this pass by extracting
//! the pinned `TYPESCRIPT_7_LINUX_X64` tarball and running it directly; it is
//! not a Node script and needs no interpreter). `Some(6)` routes to the TS6
//! managed-compat `tsc.js`, loaded by the managed Node runtime
//! (`wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE`; P17-W
//! closed this module's own hardcoded-to-Linux defect for both the Node
//! interpreter and the `typescript-6-classic` runtime, routing through
//! `_HOST_NATIVE` instead), exactly as
//! `lib/cli.mjs` already is for the TS6 language server -- this pass closed
//! ADR 0010's disclosed `P16_TS6_TYPECHECK_MANIFEST_GAP` by adding
//! `package/lib/tsc.js` to [`wht_corulix_lsp::managed_toolchain::
//! TYPESCRIPT_6_LINUX_X64`]'s own `required_paths` (same already-pinned,
//! already-hashed tarball; no new component, no new checksum -- the file was
//! already inside the archive this manifest already pins, only its path was
//! previously undeclared; independently re-verified this pass by downloading
//! the exact `tarball_url` and re-hashing the raw bytes against
//! `expected_sha256_hex`, byte-for-byte).
//!
//! # Result model: `EXIT_CODE_AUTHORITATIVE + ANCHORED_TEXT_PARSE` (tsc), `EXIT_CODE_AUTHORITATIVE + JSON_PARSE` (Biome)
//!
//! Both empirically re-verified this pass against the real pinned binaries:
//! `tsc --noEmit` reports `<path>(<line>,<col>): error TSxxxx: <message>` on
//! **stdout** (never stderr), exit `0` clean / non-zero on any reported
//! error. `biome lint --reporter=json <path>` reports a single JSON object on
//! stdout (`{"summary": {...}, "diagnostics": [...]}`), exit `0` clean /
//! non-zero when `diagnostics` is non-empty. Neither offers a way to
//! reconcile a non-zero exit with zero parsed findings into a clean result:
//! that contradiction fails closed here exactly as
//! [`crate::go_validation`]'s own `FailureWithoutParsedDiagnostics`/
//! `ResultContradiction` pair does, never silently resolved either way.
//!
//! # Biome lint scope: a confined staged copy, never the live workspace path
//!
//! ADR 0010's `LINTER_PROVIDER` section is explicit: Biome's linter reads a
//! confined staged copy of the session's own target file, never the live
//! workspace path and never over stdin/stdout. This module reads the file's
//! current governed bytes via `wht_corulix_workspace::confined_read` (the
//! same confinement authority every other read in this workspace uses) and
//! writes them to a Corulix-owned scratch file under `managed_root`
//! (preserving the original extension, so Biome classifies TS/TSX/JS/JSX
//! correctly) before invoking `biome lint` against that scratch path --
//! `P16_BIOME_LINT_LIVE_WORKSPACE_PATH_COUNT=0` by construction.

use std::path::{Path, PathBuf};

use wht_corulix_core::{CorulixError, CorulixResult};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, TerminationReason};

/// Matches [`crate::go_validation::MAX_SUMMARY_BYTES`]/`crate::diagnostics`'s
/// own bound exactly.
const MAX_SUMMARY_BYTES: usize = 3800;

const VALIDATOR_LIMITS: ProcessLimits = ProcessLimits {
    max_stdout_bytes: 8 * 1024 * 1024,
    max_stderr_bytes: 8 * 1024 * 1024,
};

/// Generous but bounded -- a cold `tsc --noEmit` over a realistic project is
/// genuinely slow; this is a hard ceiling, not an expected duration.
const VALIDATOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Which TS/JS validator to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsValidator {
    /// `tsc --noEmit`, version-routed -- `ProviderCategory::TypecheckBuild`,
    /// `AuthorityRole::Authoritative`.
    Typecheck,
    /// `biome lint --reporter=json <staged-copy>` -- `ProviderCategory::Linter`,
    /// `AuthorityRole::SupportingOnly`.
    Lint,
}

impl TsValidator {
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
            Self::Typecheck => "tsc --noEmit",
            Self::Lint => "biome lint",
        }
    }
}

/// Why a TS/JS validator run could not produce trustworthy Evidence. Never
/// a free-form string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsValidatorError {
    /// Neither the TS7-native nor the TS6 managed `tsc` (or Biome) component
    /// is provisioned/owned. No process is spawned.
    ManagedRuntimeUnavailable,
    /// The staged copy Biome must lint could not be read/written (e.g. the
    /// session's scope names no target file, or the confined read failed).
    StagedCopyUnavailable,
    /// The validator exited non-zero but this module parsed zero
    /// diagnostics out of its output -- never converted into a clean pass,
    /// never fabricated into a finding.
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

/// One parsed `tsc` diagnostic (`<path>(<line>,<col>): error TSxxxx: <message>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TscDiagnostic {
    pub relative_path: String,
    pub line: u32,
    pub column: u32,
    pub code: String,
    pub message: String,
}

/// The real, structured outcome of one TS/JS validator run whose exit code
/// and parsed findings were confirmed *consistent*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsValidationOutcome {
    pub validator: TsValidator,
    pub clean: bool,
    pub finding_count: u32,
    pub summary: String,
    pub truncated: bool,
    pub provider_version: String,
}

impl TsValidationOutcome {
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

/// Parses `<path>(<line>,<col>): error TSxxxx: <message>` lines out of a real
/// `tsc --noEmit` stdout stream -- the exact shape empirically confirmed
/// this pass against the real pinned TS7-native `tsc`. Anchored text parsing,
/// never a regex dependency: "skip, don't abort" on an unrecognized line,
/// matching [`crate::go_validation::parse_go_diagnostics`]'s own stance.
fn parse_tsc_diagnostics(
    output: &[u8],
    output_truncated: bool,
) -> (Vec<TscDiagnostic>, String, bool) {
    let text = String::from_utf8_lossy(output);
    let mut diagnostics = Vec::new();
    let mut summary = String::new();
    let mut summary_truncated = false;

    for raw_line in text.lines() {
        let line = raw_line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        push_bounded_line(&mut summary, &mut summary_truncated, line.trim());
        if let Some(diagnostic) = parse_one_tsc_diagnostic(line.trim()) {
            diagnostics.push(diagnostic);
        }
    }
    (diagnostics, summary, output_truncated || summary_truncated)
}

fn parse_one_tsc_diagnostic(line: &str) -> Option<TscDiagnostic> {
    // `<path>(<line>,<col>): error TSxxxx: <message>`
    let open = line.find('(')?;
    let path = &line[..open];
    if path.is_empty() {
        return None;
    }
    let close = line[open..].find(')')? + open;
    let location = &line[open + 1..close];
    let mut location_parts = location.split(',');
    let line_number: u32 = location_parts.next()?.trim().parse().ok()?;
    let column: u32 = location_parts.next()?.trim().parse().ok()?;

    let rest = line[close + 1..]
        .trim_start()
        .trim_start_matches(':')
        .trim();
    // `error TSxxxx: message` or `warning TSxxxx: message`.
    let mut rest_parts = rest.splitn(2, ' ');
    let severity = rest_parts.next()?;
    if severity != "error" && severity != "warning" {
        return None;
    }
    let remainder = rest_parts.next()?;
    let (code, message) = remainder.split_once(':')?;
    if !code.trim().starts_with("TS") {
        return None;
    }
    Some(TscDiagnostic {
        relative_path: path.trim().to_string(),
        line: line_number,
        column,
        code: code.trim().to_string(),
        message: message.trim().to_string(),
    })
}

/// A real, structured Biome `--reporter=json` diagnostic count -- Biome's
/// own JSON shape (`{"summary": {"errors": N, "warnings": N}, "diagnostics": [...]}`),
/// deserialized minimally: only the fields this module actually consults.
#[derive(Debug, Clone, serde::Deserialize)]
struct BiomeLintReport {
    summary: BiomeLintSummary,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BiomeLintSummary {
    errors: u32,
    warnings: u32,
}

/// Whether a completed `biome lint --reporter=json` run's exit code and
/// parsed report are mutually consistent -- pure and process-free, so it can
/// be exercised directly by regression tests without spawning Biome. `run_lint`
/// is the sole real caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BiomeLintContradiction {
    /// Exit `0` (Biome's own "zero errors" signal) alongside at least one
    /// parsed *error* -- a genuine mismatch between Biome's exit code and
    /// its own JSON report. Never raised for a warnings-only result: see
    /// this function's own doc comment.
    ExitCleanWithErrors,
    /// Exit non-zero (Biome's own "at least one error" signal) but this
    /// module could not corroborate a single parsed error (unparseable
    /// report, or a report claiming zero errors) -- fails closed rather
    /// than presenting an unexamined result as a zero-finding clean pass.
    ExitFailedWithoutErrors,
}

/// P-M05-R2 fix: Biome's own exit-code contract is error-only -- it exits
/// `0` whenever zero *errors* are reported, regardless of warning count
/// (empirically confirmed against the real managed Biome 2.5.11 binary: a
/// warnings-only result -- `errors: 0, warnings: N>0` -- exits `0`, exactly
/// like a fully clean result; only `errors > 0` ever produces a non-zero
/// exit). A warnings-only result is therefore Biome's normal, legitimate
/// outcome, never an internal contradiction -- this function is
/// severity-aware (`summary.errors`), never driven by the combined
/// error+warning finding count. See the empirical proof (three real
/// fixtures, captured exit codes) recorded at
/// `m05_focused_2026-09-09/preflight/DEFECT_LINT_RESULT_MISINTERPRETATION.md`.
///
/// Returns `(clean, finding_count)` on a consistent result: `clean` is
/// `errors == 0` (mirrors [`crate::diagnostics::RustDiagnosticsOutcome::
/// is_clean`]'s own `error_count == 0` definition -- warnings never make a
/// clean result "dirty"); `finding_count` stays the combined
/// `errors + warnings` count, matching this tool's existing public
/// `GoRunSummary::finding_count` contract for every other language's
/// `Linter` role.
fn interpret_biome_lint_result(
    exit_code: i32,
    report: Option<&BiomeLintReport>,
) -> Result<(bool, u32), BiomeLintContradiction> {
    let exit_clean = exit_code == 0;
    let error_count = report.map_or(0, |report| report.summary.errors);
    let finding_count = report
        .map(|report| {
            report
                .summary
                .errors
                .saturating_add(report.summary.warnings)
        })
        .unwrap_or(0);

    if exit_clean && error_count > 0 {
        return Err(BiomeLintContradiction::ExitCleanWithErrors);
    }
    if !exit_clean && error_count == 0 {
        return Err(BiomeLintContradiction::ExitFailedWithoutErrors);
    }
    Ok((error_count == 0, finding_count))
}

/// Resolves the version-routed `tsc` executable and how to invoke it
/// (`argv[0]` alone for TS7-native, or `node lib/tsc.js` for TS6-managed).
async fn resolve_tsc_invocation(
    managed_root: &Path,
    declared_major: Option<u32>,
) -> Result<(PathBuf, Vec<String>, String), TsValidatorError> {
    use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

    if declared_major == Some(6) {
        // P17-W: `_HOST_NATIVE` (not `_LINUX_X64` directly), closing this
        // module's own hardcoded-to-Linux defect -- the same defect class
        // already fixed for `GOPLS_HOST_NATIVE`/`TYPESCRIPT_7_HOST_NATIVE`/
        // `LspProviderProfile::typescript_language_server_managed`'s own
        // `managed_component`/`managed_interpreter`/`managed_typescript_6_runtime`
        // fields. Resolved natively on Windows unfixed, `resolve_owned_managed_component`
        // would look up the Linux `linux-x64` install subdirectory
        // (`component_install_dir` keys on `manifest.platform`), which this
        // host's own real provisioning never populates -- failing closed with
        // `TsValidatorError::ManagedRuntimeUnavailable`, not silently passing.
        let (ts6_state, ts6_path) = provisioning::resolve_owned_managed_component(
            managed_root,
            &wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE,
        );
        let (node_state, node_path) = provisioning::resolve_owned_managed_component(
            managed_root,
            &wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
        );
        if ts6_state != ManagedComponentState::Available
            || node_state != ManagedComponentState::Available
        {
            return Err(TsValidatorError::ManagedRuntimeUnavailable);
        }
        // `TYPESCRIPT_6_LINUX_X64`'s `binary_path_in_tarball` is
        // `package/lib/tsserver.js` (the LSP entry point); `tsc.js` is a
        // sibling file within the same owned install directory, already
        // asserted present via this manifest's own `required_paths`
        // (this pass's addition -- see this module's own doc comment).
        let tsserver_path = ts6_path.ok_or(TsValidatorError::ManagedRuntimeUnavailable)?;
        let tsc_js = tsserver_path
            .parent()
            .map(|dir| dir.join("tsc.js"))
            .ok_or(TsValidatorError::ManagedRuntimeUnavailable)?;
        if !tsc_js.is_file() {
            return Err(TsValidatorError::ManagedRuntimeUnavailable);
        }
        let node_executable = node_path.ok_or(TsValidatorError::ManagedRuntimeUnavailable)?;
        return Ok((
            node_executable,
            vec![tsc_js.to_string_lossy().into_owned()],
            "typescript-6-classic (tsc.js, managed Node)".to_string(),
        ));
    }

    // `None`/`Some(7)`: TS7-native default, per ADR 0010's own
    // `TS_VERSION_ROUTING_POLICY`.
    let (ts7_state, ts7_path) = provisioning::resolve_owned_managed_component(
        managed_root,
        &wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64,
    );
    if ts7_state != ManagedComponentState::Available {
        return Err(TsValidatorError::ManagedRuntimeUnavailable);
    }
    let tsc_executable = ts7_path.ok_or(TsValidatorError::ManagedRuntimeUnavailable)?;
    Ok((
        tsc_executable,
        Vec::new(),
        "typescript-7-native".to_string(),
    ))
}

/// Runs the real, version-routed `tsc --noEmit` against `workspace_root`.
/// `--noEmit` is always supplied so no build artifact is ever written --
/// mirrors `crate::go_validation`'s own `-o /dev/null` discipline.
pub async fn run_typecheck(
    managed_root: &Path,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    declared_major: Option<u32>,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<TsValidationOutcome, TsValidatorError> {
    let (executable, mut arguments, provider_version) =
        resolve_tsc_invocation(managed_root, declared_major).await?;
    arguments.push("--noEmit".to_string());

    let spec = ProcessSpec {
        executable,
        arguments,
        environment: EnvironmentPolicy::empty(),
        working_directory: workspace_root.canonical_path().to_path_buf(),
        limits: VALIDATOR_LIMITS,
        timeout: VALIDATOR_TIMEOUT,
        execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
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
            let (diagnostics, summary, truncated) =
                parse_tsc_diagnostics(&outcome.stdout.bytes, outcome.stdout.truncated);
            let exit_clean = code == 0;
            if exit_clean && !diagnostics.is_empty() {
                return Err(TsValidatorError::ResultContradiction);
            }
            if !exit_clean && diagnostics.is_empty() {
                return Err(TsValidatorError::FailureWithoutParsedDiagnostics {
                    exit_code: code,
                    summary,
                });
            }
            Ok(TsValidationOutcome {
                validator: TsValidator::Typecheck,
                clean: exit_clean,
                finding_count: diagnostics.len() as u32,
                summary,
                truncated: truncated || outcome.stderr.truncated,
                provider_version,
            })
        }
        TerminationReason::Signaled { .. } => Err(TsValidatorError::Signaled),
        TerminationReason::TimedOut => Err(TsValidatorError::TimedOut),
        TerminationReason::Cancelled => Err(TsValidatorError::Cancelled),
        TerminationReason::SpawnFailed => Err(TsValidatorError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(TsValidatorError::TerminationFailed),
    }
}

/// Materializes `relative_path`'s current governed bytes into a Corulix-owned
/// scratch file under `managed_root` (never the live workspace path -- see
/// this module's own doc comment), preserving the original extension.
async fn stage_file_for_biome_lint(
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
        .unwrap_or("txt")
        .to_string();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let file_name = format!("staged-{stamp}.{extension}");
    let root = managed_root.to_path_buf();

    // The actual filesystem write happens inside `wht_corulix_tooling::
    // provisioning` (Architecture Rule M/G: that crate is the sole
    // filesystem-write authority for Corulix-owned, non-workspace state) --
    // this module only decides *what* to stage, never writes directly.
    // `relative_dir` is joined under `MANAGED_SCRATCH_DIR` ("scratch"), not
    // a bare "biome-lint" -- `full_uninstall::cleanup_lifecycle_shells_and_root`
    // specifically targets `root.join(MANAGED_SCRATCH_DIR)`, so a staged
    // file living outside that tree would never be reached by zero-residual
    // uninstall (the same convention `crate::go_providers::go_scratch_relative`
    // already follows: `format!("scratch/p15-go/{key}/{leaf}")`).
    let relative_dir = format!(
        "{}/biome-lint",
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

/// Runs real, read-only `biome lint --reporter=json` against a confined
/// staged copy of `relative_path`'s current governed content.
pub async fn run_lint(
    managed_root: &Path,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    relative_path: &str,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<TsValidationOutcome, TsValidatorError> {
    use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

    // Resolved against `BIOME_HOST_NATIVE` (P17-W Stage F), never a
    // hardcoded `BIOME_LINUX_X64` literal -- see `semantic.rs`'s own
    // identical fix and `BIOME_HOST_NATIVE`'s own doc comment for why.
    let (biome_state, biome_path) = provisioning::resolve_owned_managed_component(
        managed_root,
        &wht_corulix_formatter::managed_toolchain::BIOME_HOST_NATIVE,
    );
    if biome_state != ManagedComponentState::Available {
        return Err(TsValidatorError::ManagedRuntimeUnavailable);
    }
    let biome_executable = biome_path.ok_or(TsValidatorError::ManagedRuntimeUnavailable)?;

    let staged_path = stage_file_for_biome_lint(managed_root, workspace_root, relative_path)
        .await
        .map_err(|_| TsValidatorError::StagedCopyUnavailable)?;

    let spec = ProcessSpec {
        executable: biome_executable,
        arguments: vec![
            "lint".to_string(),
            "--reporter=json".to_string(),
            staged_path.to_string_lossy().into_owned(),
        ],
        environment: EnvironmentPolicy::empty(),
        working_directory: managed_root.to_path_buf(),
        limits: VALIDATOR_LIMITS,
        timeout: VALIDATOR_TIMEOUT,
        execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
        argv0: None,
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
            let json_line = stdout_text
                .lines()
                .find(|line| line.trim_start().starts_with('{'));
            let report: Option<BiomeLintReport> =
                json_line.and_then(|line| serde_json::from_str(line).ok());

            let mut summary = String::new();
            let mut truncated = outcome.stdout.truncated || outcome.stderr.truncated;
            push_bounded_line(&mut summary, &mut truncated, stdout_text.trim());

            match interpret_biome_lint_result(code, report.as_ref()) {
                Ok((clean, finding_count)) => Ok(TsValidationOutcome {
                    validator: TsValidator::Lint,
                    clean,
                    finding_count,
                    summary,
                    truncated,
                    provider_version: "biome".to_string(),
                }),
                Err(BiomeLintContradiction::ExitCleanWithErrors) => {
                    Err(TsValidatorError::ResultContradiction)
                }
                Err(BiomeLintContradiction::ExitFailedWithoutErrors) => {
                    Err(TsValidatorError::FailureWithoutParsedDiagnostics {
                        exit_code: code,
                        summary,
                    })
                }
            }
        }
        TerminationReason::Signaled { .. } => Err(TsValidatorError::Signaled),
        TerminationReason::TimedOut => Err(TsValidatorError::TimedOut),
        TerminationReason::Cancelled => Err(TsValidatorError::Cancelled),
        TerminationReason::SpawnFailed => Err(TsValidatorError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(TsValidatorError::TerminationFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_tsc_failure() {
        let stdout =
            b"bad.ts(1,7): error TS2322: Type 'string' is not assignable to type 'number'.\n";
        let (diagnostics, summary, truncated) = parse_tsc_diagnostics(stdout, false);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].relative_path, "bad.ts");
        assert_eq!(diagnostics[0].line, 1);
        assert_eq!(diagnostics[0].column, 7);
        assert_eq!(diagnostics[0].code, "TS2322");
        assert!(diagnostics[0].message.contains("not assignable"));
        assert!(summary.contains("TS2322"));
        assert!(!truncated);
    }

    #[test]
    fn clean_tsc_output_yields_no_diagnostics() {
        let (diagnostics, _, _) = parse_tsc_diagnostics(b"", false);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn a_colon_inside_the_message_is_preserved() {
        let (diagnostics, _, _) = parse_tsc_diagnostics(
            b"a.ts(3,1): error TS2304: Cannot find name: helper.\n",
            false,
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.contains("Cannot find name"));
    }

    #[test]
    fn narrative_output_is_summarized_but_never_counted_as_a_finding() {
        let (diagnostics, summary, _) =
            parse_tsc_diagnostics(b"Compilation complete. Watching for file changes.\n", false);
        assert!(diagnostics.is_empty());
        assert!(summary.contains("Watching for file changes"));
    }

    #[test]
    fn build_and_lint_map_to_distinct_provider_categories() {
        assert_eq!(
            TsValidator::Typecheck.category(),
            wht_corulix_core::ProviderCategory::TypecheckBuild
        );
        assert_eq!(
            TsValidator::Lint.category(),
            wht_corulix_core::ProviderCategory::Linter
        );
        assert_ne!(
            TsValidator::Typecheck.category(),
            TsValidator::Lint.category()
        );
    }

    #[test]
    fn biome_json_report_deserializes_findings() {
        let raw = r#"{"summary":{"changed":0,"unchanged":1,"matches":0,"duration":1,"errors":1,"warnings":0,"infos":0,"skipped":0,"suggestedFixesSkipped":0,"diagnosticsNotPrinted":0,"scannerDuration":1},"diagnostics":[],"command":"lint"}"#;
        let parsed: Result<BiomeLintReport, _> = serde_json::from_str(raw);
        assert!(parsed.is_ok(), "expected valid biome json");
        let report = parsed.unwrap_or(BiomeLintReport {
            summary: BiomeLintSummary {
                errors: 0,
                warnings: 0,
            },
        });
        assert_eq!(report.summary.errors, 1);
        assert_eq!(report.summary.warnings, 0);
    }

    #[test]
    fn the_summary_is_bounded() {
        let huge = format!(
            "a.ts(1,1): error TS9999: {}\n",
            "x".repeat(MAX_SUMMARY_BYTES * 3)
        );
        let (_, summary, truncated) = parse_tsc_diagnostics(huge.as_bytes(), false);
        assert!(summary.len() <= MAX_SUMMARY_BYTES);
        assert!(truncated);
    }

    fn biome_report(errors: u32, warnings: u32) -> BiomeLintReport {
        BiomeLintReport {
            summary: BiomeLintSummary { errors, warnings },
        }
    }

    /// TS1 CLEAN: zero errors, zero warnings, exit `0` -- a real, successful,
    /// fully clean run.
    #[test]
    fn ts1_biome_clean_result_is_accepted() {
        let report = biome_report(0, 0);
        let outcome = interpret_biome_lint_result(0, Some(&report));
        assert_eq!(outcome, Ok((true, 0)));
    }

    /// TS2 WARNINGS_ONLY: the primary regression. Zero errors, one or more
    /// warnings, exit `0` -- Biome's own real, legitimate outcome (proven
    /// against the managed 2.5.11 binary). Must be accepted as a real,
    /// non-contradictory, `ran=true` result, never `ResultContradiction`.
    #[test]
    fn ts2_biome_warnings_only_result_is_accepted_not_a_contradiction() {
        let report = biome_report(0, 1);
        let outcome = interpret_biome_lint_result(0, Some(&report));
        assert_eq!(outcome, Ok((true, 1)));
    }

    /// TS3 ERROR_DIAGNOSTIC: at least one error, exit non-zero -- the
    /// combined `errors + warnings` count is reported, and `clean` reflects
    /// `errors == 0` (here `false`).
    #[test]
    fn ts3_biome_error_diagnostic_reports_combined_finding_count() {
        let report = biome_report(1, 2);
        let outcome = interpret_biome_lint_result(1, Some(&report));
        assert_eq!(outcome, Ok((false, 3)));
    }

    /// TS4 SYNTAX_INVALID: parse errors surface as `summary.errors` exactly
    /// like semantic lint errors (Biome does not distinguish the two in this
    /// field) -- deterministic non-clean result, never a contradiction.
    #[test]
    fn ts4_biome_syntax_invalid_reports_deterministic_non_clean_result() {
        let report = biome_report(7, 0);
        let outcome = interpret_biome_lint_result(1, Some(&report));
        assert_eq!(outcome, Ok((false, 7)));
    }

    /// TS5 MALFORMED_PROVIDER_OUTPUT: a non-zero exit whose JSON could not be
    /// parsed at all (`None`) must fail closed, never silently become a
    /// zero-finding clean-looking result.
    #[test]
    fn ts5_biome_malformed_output_on_non_zero_exit_fails_closed() {
        let outcome = interpret_biome_lint_result(1, None);
        assert_eq!(
            outcome,
            Err(BiomeLintContradiction::ExitFailedWithoutErrors)
        );
    }

    /// TS6 INVOCATION_FAILURE: proven directly against the real managed
    /// Biome binary (missing-file control) -- Biome's own JSON `summary`
    /// under-counts an `internalError/io` diagnostic (`errors: 0`) even
    /// though the process exits non-zero. This module must not silently
    /// treat that as a benign zero-finding clean result: it fails closed
    /// exactly like a fully unparseable payload.
    #[test]
    fn ts6_biome_invocation_failure_with_zero_reported_errors_fails_closed() {
        let report = biome_report(0, 0);
        let outcome = interpret_biome_lint_result(1, Some(&report));
        assert_eq!(
            outcome,
            Err(BiomeLintContradiction::ExitFailedWithoutErrors)
        );
    }

    /// A real contradiction (Biome's own exit code disagreeing with its own
    /// error count) must still fail closed -- this pass narrows the trigger
    /// condition from "any finding" to "any error", it does not remove the
    /// check.
    #[test]
    fn exit_clean_with_a_real_error_is_still_a_contradiction() {
        let report = biome_report(1, 0);
        let outcome = interpret_biome_lint_result(0, Some(&report));
        assert_eq!(outcome, Err(BiomeLintContradiction::ExitCleanWithErrors));
    }
}
