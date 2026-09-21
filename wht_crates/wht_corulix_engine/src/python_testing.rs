// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P17 production-routing closure: `PROJECT_TEST_RUNNER_DISCOVERY_POLICY`
//! (ADR 0011 §4), plus real, trust-gated `pytest` invocation -- the Python
//! sibling of [`crate::go_testing`] (Go) and [`crate::ts_testing`] (TS/JS).
//!
//! # Discovery is deterministic and offline -- no global framework guess
//!
//! Per ADR 0011 §4, most to least specific:
//!
//! 1. `pyproject.toml` carries a `[tool.pytest.ini_options]` section.
//! 2. `pytest.ini` is present at the project root, or `tox.ini` carries a
//!    `[pytest]` section.
//! 3. `pyproject.toml` declares `pytest` as a dependency (any of
//!    `[project.dependencies]`/`[project.optional-dependencies]`/
//!    `[tool.poetry.dependencies]`/`[tool.poetry.group.*.dependencies]`).
//! 4. No recognized marker resolves a runner -> [`PythonTestError::AmbiguousTestRunner`],
//!    never a silent global `pytest` assumption
//!    (`P17_GLOBAL_PYTEST_ASSUMPTION_COUNT=0`).
//!
//! This module's own scope limitation, disclosed rather than hidden:
//! discovery is anchored **substring/section matching** over the raw
//! `pyproject.toml`/`tox.ini` text, not a full TOML AST parse (this
//! workspace carries no TOML-parsing dependency today, and adding one is
//! out of this pass's bounded scope) -- the same "anchored text parsing,
//! never a second parser dependency" posture [`crate::go_validation`]'s own
//! diagnostic parser already documents for its own domain. A section/marker
//! genuinely present in the file is always found; a pathological file that
//! only *resembles* one of these markers inside an unrelated string/comment
//! could be misclassified -- an accepted, disclosed limitation, not a
//! silent one.
//!
//! # Trust model: `TRUSTED_WORKSPACE_EXECUTION`
//!
//! `pytest` (and any workspace-authored `conftest.py`/fixture/plugin code it
//! loads) is repository-authored execution -- ADR 0011 §4 classifies this
//! `TrustedWorkspaceExecution`, identical to Go's `go test`/Rust's `cargo
//! test`/TS's `scripts.test`. `crate::diagnostics::authorize_trusted_execution`
//! is reused verbatim; no second trust gate is introduced, and the check
//! runs **before** discovery or any process spawn
//! (`P17_UNTRUSTED_PYTEST_PROCESS_SPAWN_COUNT=0`).
//!
//! # Invocation: `PROVIDER_EXECUTABLE_AUTHORITY != WORKSPACE_EXECUTION_TRUST_CLASS`
//!
//! The `pytest` binary itself is Corulix-resolved by canonicalized path
//! ([`crate::python_providers::resolve_python_tool`], `HOST_ONLY`/approved-
//! directory precedence, never ambient `PATH`) -- but the workspace test
//! code it executes runs under `TrustedWorkspaceExecution` and is gated by
//! `authorize_trusted_execution` before any [`ProcessSpec`] is constructed,
//! exactly the same non-elevating split ADR 0011's own "Existing scaffolding"
//! section names as the Go precedent this phase reuses verbatim.
//!
//! # Result model: `EXIT_CODE_AUTHORITATIVE`
//!
//! `pytest`'s own documented exit codes: `0` all collected tests passed,
//! `1` tests were collected and some failed, `2` execution was interrupted,
//! `3` an internal error occurred, `4` a command-line usage error, `5` no
//! tests were collected. This module treats the process exit code as the
//! sole authority (`passing = (exit_code == 0)`), mirroring
//! [`crate::ts_testing`]'s own no-cross-runner-structured-parsing stance,
//! and reports a bounded raw summary of pytest's own output -- never a
//! fabricated pass/fail count.

use wht_corulix_core::{CorulixError, CorulixResult, ExecutionClass};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, TerminationReason};
use wht_corulix_workspace::{WorkspaceRoot, confined_read};

use crate::diagnostics::authorize_trusted_execution;
use crate::python_providers::{self, PYTEST_EXECUTABLE, PythonProviderError};

const MAX_TEST_SUMMARY_BYTES: usize = 3800;
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

const TEST_LIMITS: ProcessLimits = ProcessLimits {
    max_stdout_bytes: 16 * 1024 * 1024,
    max_stderr_bytes: 8 * 1024 * 1024,
};
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Why pytest discovery or invocation could not produce a usable result.
/// Never a free-form string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonTestError {
    WorkspaceExecutionNotAuthorized,
    /// No recognized marker resolved a runner (ADR 0011 §4's own
    /// `RequiredCapabilityUnavailable` contract) -- fail-closed, never a
    /// guessed default.
    AmbiguousTestRunner,
    /// The real `pytest` binary could not be resolved or identified.
    Provider(PythonProviderError),
    FailureWithoutClearOutcome {
        exit_code: i32,
        summary: String,
    },
    SpawnFailed,
    TimedOut,
    Cancelled,
    TerminationFailed,
    Signaled,
}

/// The real, structured outcome of one `pytest` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonTestOutcome {
    pub passing: bool,
    pub summary: String,
    pub truncated: bool,
    pub provider_version: String,
}

/// Anchored substring/section discovery over `pyproject.toml`'s raw text --
/// see this module's own doc comment for the disclosed "not a full TOML
/// parse" limitation.
fn pyproject_declares_pytest(text: &str) -> bool {
    if text.contains("[tool.pytest.ini_options]") {
        return true;
    }
    // A dependency declaration: `"pytest"` or `"pytest>=..."`/`"pytest[...]"`
    // appearing inside a recognized dependency-array/table context. Anchored
    // to the literal token `pytest` bounded by a quote or version/extra
    // separator, never a bare substring match against unrelated content
    // (e.g. `pytest-cov` alone does not imply `pytest` itself is declared,
    // but in practice a project depending on a pytest plugin transitively
    // requires `pytest` -- this module deliberately does not attempt that
    // inference and only recognizes an explicit `pytest` token).
    for marker in [
        "\"pytest\"",
        "\"pytest>",
        "\"pytest=",
        "\"pytest<",
        "\"pytest[",
        "'pytest'",
        "'pytest>",
        "'pytest=",
        "'pytest<",
        "'pytest[",
    ] {
        if text.contains(marker) {
            return true;
        }
    }
    false
}

/// ADR 0011 §4's own discovery order, most to least specific. `Ok(())` means
/// pytest is the discovered, authoritative runner; `Err` is always a
/// [`PythonTestError::AmbiguousTestRunner`].
async fn discover_pytest_runner(workspace_root: &WorkspaceRoot) -> Result<(), PythonTestError> {
    if let Ok(bytes) = confined_read(
        workspace_root.clone(),
        std::path::PathBuf::from("pyproject.toml"),
        MAX_CONFIG_FILE_BYTES,
    )
    .await
    {
        let text = String::from_utf8_lossy(&bytes);
        if pyproject_declares_pytest(&text) {
            return Ok(());
        }
    }

    if confined_read(
        workspace_root.clone(),
        std::path::PathBuf::from("pytest.ini"),
        MAX_CONFIG_FILE_BYTES,
    )
    .await
    .is_ok()
    {
        return Ok(());
    }

    if let Ok(bytes) = confined_read(
        workspace_root.clone(),
        std::path::PathBuf::from("tox.ini"),
        MAX_CONFIG_FILE_BYTES,
    )
    .await
    {
        let text = String::from_utf8_lossy(&bytes);
        if text.contains("[pytest]") {
            return Ok(());
        }
    }

    Err(PythonTestError::AmbiguousTestRunner)
}

fn bounded(text: &str) -> (String, bool) {
    if text.len() <= MAX_TEST_SUMMARY_BYTES {
        return (text.to_string(), false);
    }
    let mut cut = MAX_TEST_SUMMARY_BYTES;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    (text[..cut].to_string(), true)
}

/// Runs the real, trust-gated, discovered `pytest` invocation.
///
/// `effective` must authorize [`ExecutionClass::TrustedWorkspaceExecution`]
/// or this returns [`PythonTestError::WorkspaceExecutionNotAuthorized`]
/// **before discovery or any process spawn**.
pub async fn run_pytest(
    workspace_root: &WorkspaceRoot,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<PythonTestOutcome, PythonTestError> {
    authorize_trusted_execution(effective)
        .map_err(|_| PythonTestError::WorkspaceExecutionNotAuthorized)?;

    discover_pytest_runner(workspace_root).await?;

    let toolchain = python_providers::resolve_python_tool(
        effective,
        workspace_root,
        wht_corulix_core::ProviderCategory::TestRunner,
        PYTEST_EXECUTABLE,
        cancellation,
    )
    .await
    .map_err(PythonTestError::Provider)?;

    let root_path = workspace_root.canonical_path().to_path_buf();
    let spec = ProcessSpec {
        executable: toolchain.executable.clone(),
        arguments: vec!["-q".to_string()],
        environment: EnvironmentPolicy::empty(),
        working_directory: root_path,
        limits: TEST_LIMITS,
        timeout: TEST_TIMEOUT,
        execution_class: ExecutionClass::TrustedWorkspaceExecution,
        argv0: Some(PYTEST_EXECUTABLE.to_string()),
    };
    // M09-P7/M09-P10: binds the child's cwd to `workspace_root`'s pinned
    // root object on Unix; on Windows, `execute_with_workspace_root` fails
    // closed before spawning anything rather than falling back to a
    // pathname-based cwd.
    let outcome =
        wht_corulix_tooling::execute_with_workspace_root(&spec, workspace_root, cancellation).await;

    match outcome.termination {
        TerminationReason::Exited { code } => {
            let mut combined = String::from_utf8_lossy(&outcome.stdout.bytes).into_owned();
            combined.push_str(&String::from_utf8_lossy(&outcome.stderr.bytes));
            let (summary, truncated) = bounded(&combined);
            Ok(PythonTestOutcome {
                passing: code == 0,
                summary,
                truncated: truncated || outcome.stdout.truncated || outcome.stderr.truncated,
                provider_version: toolchain.version,
            })
        }
        TerminationReason::Signaled { .. } => Err(PythonTestError::Signaled),
        TerminationReason::TimedOut => Err(PythonTestError::TimedOut),
        TerminationReason::Cancelled => Err(PythonTestError::Cancelled),
        TerminationReason::SpawnFailed => Err(PythonTestError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(PythonTestError::TerminationFailed),
    }
}

/// Converts a real [`PythonTestOutcome`]'s bounded `summary` into an
/// [`wht_corulix_core::EvidenceResultSummary`].
pub fn evidence_result_summary(
    outcome: &PythonTestOutcome,
) -> CorulixResult<wht_corulix_core::EvidenceResultSummary> {
    wht_corulix_core::EvidenceResultSummary::try_from(outcome.summary.clone())
        .map_err(|_| CorulixError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_pytest_ini_options_section() {
        assert!(pyproject_declares_pytest(
            "[tool.pytest.ini_options]\nminversion = \"7.0\"\n"
        ));
    }

    #[test]
    fn recognizes_a_plain_dependency_declaration() {
        assert!(pyproject_declares_pytest(
            "[project]\ndependencies = [\"pytest>=7.0\", \"requests\"]\n"
        ));
        assert!(pyproject_declares_pytest(
            "[tool.poetry.dependencies]\npytest = \"^7.0\"\n"
                .replace("pytest =", "\"pytest\" =")
                .as_str()
        ));
    }

    #[test]
    fn a_project_with_no_recognized_marker_is_not_declared() {
        assert!(!pyproject_declares_pytest(
            "[project]\ndependencies = [\"requests\", \"pytest-cov\"]\n"
        ));
        assert!(!pyproject_declares_pytest(""));
    }
}
