// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P16 production-routing closure: `PROJECT_TEST_RUNNER_DISCOVERY_POLICY`/
//! `PACKAGE_MANAGER_DISCOVERY_POLICY` (ADR 0010), plus real invocation of the
//! discovered `package.json#scripts.test` command -- the TS/JS sibling of
//! [`crate::go_testing`] (Go) and `crate::testing` (Rust).
//!
//! # Discovery is deterministic and offline -- no global framework guess
//!
//! Per ADR 0010, `scripts.test`'s command string is classified against a
//! **finite, named set** of recognized invocation prefixes: `node --test`
//! (Node's own built-in runner, fully offline, zero-install), `jest`,
//! `vitest`, `mocha`, `ava`, `tap`/`node-tap`. An absent, empty, or
//! unrecognized script fails closed
//! (`P16_AMBIGUOUS_TEST_RUNNER_RESULT=RequiredCapabilityUnavailable`) --
//! never a silent default to `npm test`/`jest`
//! (`P16_GLOBAL_TEST_FRAMEWORK_ASSUMPTION_COUNT=0`).
//!
//! Package-manager discovery (`packageManager` field, then lockfile
//! presence, then `RequiredCapabilityUnavailable` on ambiguity/absence) is
//! implemented here too, per ADR 0010's own policy -- this phase makes no
//! practical use of the result beyond the discovery contract itself (no
//! dependency install is ever triggered), exactly as the ADR discloses.
//!
//! # Trust model: `TRUSTED_WORKSPACE_EXECUTION`
//!
//! The resolved `scripts.test` command is repository-authored and is
//! executed verbatim -- ADR 0010's `TRUST_MODEL` section classifies this
//! `TrustedWorkspaceExecution`, identical to Go's `go test`/Rust's
//! `cargo test`. `crate::diagnostics::authorize_trusted_execution` is
//! reused verbatim; no second trust gate is introduced.
//!
//! # Invocation: the classified command is executed exactly as declared
//!
//! For [`RecognizedTestRunner::NodeBuiltin`] (`node --test [args...]`), this
//! module substitutes the managed Node runtime
//! (`wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE`; P17-W
//! closed this module's own hardcoded-to-Linux defect, routing through
//! `_HOST_NATIVE` instead) for the
//! literal `node` token and passes the remaining arguments through
//! unchanged -- fully provable in this environment with zero external
//! dependency install, since Node's built-in test runner ships inside the
//! managed Node runtime itself.
//!
//! For every other recognized runner (`jest`/`vitest`/`mocha`/`ava`/`tap`),
//! Corulix does not manage or install the runner itself (`ADR 0010`
//! discloses no dependency-install authority this phase) -- the declared
//! script is executed via the host's own `/bin/sh -c "<script>"`
//! (`P16_TEST_RUNNER_SHELL_AUTHORITY=SYSTEM_SHELL_REQUIRED_NOT_MANAGED`,
//! mirroring `crate::diagnostics`'s own disclosed
//! `SYSTEM_LINKER_REQUIRED_NOT_MANAGED` precedent for `cargo build`'s system
//! linker dependency), with the workspace's own `node_modules/.bin`
//! prepended to `PATH` alongside the managed Node runtime's own `bin/`
//! directory -- the same shape `npm`/`pnpm`/`yarn` themselves construct when
//! running a package script. A project with no installed runner binary
//! genuinely fails to spawn; this module never fabricates a pass.
//!
//! # Result model: `EXIT_CODE_AUTHORITATIVE`, no cross-runner count parsing
//!
//! Unlike Go's `go test -json`/Rust's `cargo test --message-format=json`,
//! there is no single structured stream shared by every recognized runner
//! (`jest --json`, `vitest --reporter=json`, `mocha --reporter json`, `ava
//! --tap`, `node --test` TAP output all differ). Per-runner structured
//! parsing is out of this phase's bounded scope (ADR 0010 does not require
//! it); this module treats the process **exit code as the sole authority**
//! -- `passing = (exit_code == 0)` -- and reports a bounded raw summary of
//! the runner's own output, never a fabricated pass/fail count.

use std::path::Path;

use wht_corulix_core::{CorulixError, CorulixResult, ExecutionClass};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, TerminationReason};
use wht_corulix_workspace::{WorkspaceRoot, confined_read};

use crate::diagnostics::authorize_trusted_execution;

const MAX_TEST_SUMMARY_BYTES: usize = 3800;
const MAX_PACKAGE_JSON_BYTES: u64 = 1024 * 1024;

const TEST_LIMITS: ProcessLimits = ProcessLimits {
    max_stdout_bytes: 16 * 1024 * 1024,
    max_stderr_bytes: 8 * 1024 * 1024,
};
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The finite, named set of recognized `scripts.test` invocation prefixes.
/// ADR 0010 `PROJECT_TEST_RUNNER_DISCOVERY_POLICY` §1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecognizedTestRunner {
    NodeBuiltin,
    Jest,
    Vitest,
    Mocha,
    Ava,
    Tap,
}

impl RecognizedTestRunner {
    #[must_use]
    pub fn provider_id(self) -> &'static str {
        match self {
            Self::NodeBuiltin => "node --test",
            Self::Jest => "jest",
            Self::Vitest => "vitest",
            Self::Mocha => "mocha",
            Self::Ava => "ava",
            Self::Tap => "tap",
        }
    }
}

/// Classifies `command` (a real `scripts.test` value) against the finite,
/// named set -- a literal-prefix/word match against each runner's
/// *documented* invocation form, never a fuzzy heuristic. Returns `None` for
/// anything unrecognized, which the caller must treat as
/// `RequiredCapabilityUnavailable`, never a silent default.
#[must_use]
pub fn classify_test_script(command: &str) -> Option<RecognizedTestRunner> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return None;
    }
    let first_word = trimmed.split_whitespace().next().unwrap_or_default();
    if first_word == "node" && trimmed.split_whitespace().any(|token| token == "--test") {
        return Some(RecognizedTestRunner::NodeBuiltin);
    }
    match first_word {
        "jest" => Some(RecognizedTestRunner::Jest),
        "vitest" => Some(RecognizedTestRunner::Vitest),
        "mocha" => Some(RecognizedTestRunner::Mocha),
        "ava" => Some(RecognizedTestRunner::Ava),
        "tap" | "node-tap" => Some(RecognizedTestRunner::Tap),
        _ => None,
    }
}

/// ADR 0010 `PACKAGE_MANAGER_DISCOVERY_POLICY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
}

/// Why test-runner or package-manager discovery could not produce a usable
/// result. Never a free-form string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsTestError {
    WorkspaceExecutionNotAuthorized,
    /// `scripts.test` is absent, empty, or does not match a recognized
    /// pattern -- ADR 0010's own `RequiredCapabilityUnavailable` contract,
    /// fail-closed, never a guessed default.
    AmbiguousTestRunner,
    /// `package.json` itself could not be read/parsed at all.
    PackageJsonUnreadable,
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

/// The real, structured outcome of one test-runner invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsTestOutcome {
    pub runner: RecognizedTestRunner,
    pub passing: bool,
    pub summary: String,
    pub truncated: bool,
}

/// Discovers this workspace's declared package manager. ADR 0010 order:
/// `package.json#packageManager` first, then lockfile presence; more than
/// one recognized signal (or neither) is `None` -- fails closed, per policy.
pub async fn discover_package_manager(workspace_root: &WorkspaceRoot) -> Option<PackageManager> {
    if let Ok(bytes) = confined_read(
        workspace_root.clone(),
        std::path::PathBuf::from("package.json"),
        MAX_PACKAGE_JSON_BYTES,
    )
    .await
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(declared) = value.get("packageManager").and_then(|v| v.as_str())
    {
        if declared.starts_with("npm@") {
            return Some(PackageManager::Npm);
        }
        if declared.starts_with("pnpm@") {
            return Some(PackageManager::Pnpm);
        }
        if declared.starts_with("yarn@") {
            return Some(PackageManager::Yarn);
        }
    }

    let root = workspace_root.canonical_path();
    let has_npm = root.join("package-lock.json").is_file();
    let has_pnpm = root.join("pnpm-lock.yaml").is_file();
    let has_yarn = root.join("yarn.lock").is_file();
    match (has_npm, has_pnpm, has_yarn) {
        (true, false, false) => Some(PackageManager::Npm),
        (false, true, false) => Some(PackageManager::Pnpm),
        (false, false, true) => Some(PackageManager::Yarn),
        _ => None,
    }
}

/// Reads `package.json#scripts.test` and classifies it. `Err` is always a
/// [`TsTestError`] a caller should surface as `RequiredCapabilityUnavailable`.
async fn discover_test_script(
    workspace_root: &WorkspaceRoot,
) -> Result<(RecognizedTestRunner, String), TsTestError> {
    let bytes = confined_read(
        workspace_root.clone(),
        std::path::PathBuf::from("package.json"),
        MAX_PACKAGE_JSON_BYTES,
    )
    .await
    .map_err(|_| TsTestError::PackageJsonUnreadable)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| TsTestError::PackageJsonUnreadable)?;
    let script = value
        .get("scripts")
        .and_then(|scripts| scripts.get("test"))
        .and_then(|script| script.as_str())
        .ok_or(TsTestError::AmbiguousTestRunner)?;
    let runner = classify_test_script(script).ok_or(TsTestError::AmbiguousTestRunner)?;
    Ok((runner, script.to_string()))
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

/// Runs the real, trust-gated, discovered `scripts.test` command.
///
/// `effective` must authorize [`ExecutionClass::TrustedWorkspaceExecution`]
/// or this returns [`TsTestError::WorkspaceExecutionNotAuthorized`] **before
/// discovery or any process spawn**.
pub async fn run_test(
    managed_root: &Path,
    workspace_root: &WorkspaceRoot,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<TsTestOutcome, TsTestError> {
    authorize_trusted_execution(effective)
        .map_err(|_| TsTestError::WorkspaceExecutionNotAuthorized)?;

    let (runner, script) = discover_test_script(workspace_root).await?;
    let root_path = workspace_root.canonical_path().to_path_buf();

    let spec = if runner == RecognizedTestRunner::NodeBuiltin {
        // P17-W: `_HOST_NATIVE` (not `_LINUX_X64` directly) -- see this
        // module's own doc comment; the hardcoded Linux constant would fail
        // closed with `TsTestError::SpawnFailed` on native Windows, since
        // `resolve_owned_managed_component` keys the install path on
        // `manifest.platform` and this host's own provisioning never
        // populates the Linux subdirectory.
        let (node_state, node_path) =
            wht_corulix_tooling::provisioning::resolve_owned_managed_component(
                managed_root,
                &wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
            );
        if node_state != wht_corulix_tooling::provisioning::ManagedComponentState::Available {
            return Err(TsTestError::SpawnFailed);
        }
        let node_executable = node_path.ok_or(TsTestError::SpawnFailed)?;
        let arguments: Vec<String> = script
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect();
        ProcessSpec {
            executable: node_executable,
            arguments,
            environment: EnvironmentPolicy::empty(),
            working_directory: root_path,
            limits: TEST_LIMITS,
            timeout: TEST_TIMEOUT,
            execution_class: ExecutionClass::TrustedWorkspaceExecution,
            argv0: None,
        }
    } else {
        // Disclosed, narrow system-shell dependency -- see this module's
        // own doc comment (`SYSTEM_SHELL_REQUIRED_NOT_MANAGED`). `node_modules/.bin`
        // is prepended so a locally-installed runner binary resolves,
        // matching how `npm run test` itself constructs `PATH`.
        let bin_dir = root_path.join("node_modules").join(".bin");
        let path_value = format!("{}:/usr/bin:/bin", bin_dir.to_string_lossy());
        ProcessSpec {
            executable: std::path::PathBuf::from("/bin/sh"),
            arguments: vec!["-c".to_string(), script.clone()],
            environment: EnvironmentPolicy::empty().with_var("PATH", path_value),
            working_directory: root_path,
            limits: TEST_LIMITS,
            timeout: TEST_TIMEOUT,
            execution_class: ExecutionClass::TrustedWorkspaceExecution,
            argv0: None,
        }
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
            Ok(TsTestOutcome {
                runner,
                passing: code == 0,
                summary,
                truncated: truncated || outcome.stdout.truncated || outcome.stderr.truncated,
            })
        }
        TerminationReason::Signaled { .. } => Err(TsTestError::Signaled),
        TerminationReason::TimedOut => Err(TsTestError::TimedOut),
        TerminationReason::Cancelled => Err(TsTestError::Cancelled),
        TerminationReason::SpawnFailed => Err(TsTestError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(TsTestError::TerminationFailed),
    }
}

/// Converts a real [`TsTestOutcome`]'s bounded `summary` into an
/// [`wht_corulix_core::EvidenceResultSummary`].
pub fn evidence_result_summary(
    outcome: &TsTestOutcome,
) -> CorulixResult<wht_corulix_core::EvidenceResultSummary> {
    wht_corulix_core::EvidenceResultSummary::try_from(outcome.summary.clone())
        .map_err(|_| CorulixError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_node_builtin() {
        assert_eq!(
            classify_test_script("node --test"),
            Some(RecognizedTestRunner::NodeBuiltin)
        );
        assert_eq!(
            classify_test_script("node --test test/"),
            Some(RecognizedTestRunner::NodeBuiltin)
        );
    }

    #[test]
    fn classifies_each_named_runner() {
        assert_eq!(
            classify_test_script("jest"),
            Some(RecognizedTestRunner::Jest)
        );
        assert_eq!(
            classify_test_script("vitest run"),
            Some(RecognizedTestRunner::Vitest)
        );
        assert_eq!(
            classify_test_script("mocha"),
            Some(RecognizedTestRunner::Mocha)
        );
        assert_eq!(classify_test_script("ava"), Some(RecognizedTestRunner::Ava));
        assert_eq!(
            classify_test_script("tap test/*.js"),
            Some(RecognizedTestRunner::Tap)
        );
        assert_eq!(
            classify_test_script("node-tap"),
            Some(RecognizedTestRunner::Tap)
        );
    }

    #[test]
    fn unrecognized_or_empty_script_is_ambiguous() {
        assert_eq!(classify_test_script(""), None);
        assert_eq!(classify_test_script("echo no tests configured"), None);
        assert_eq!(classify_test_script("my-custom-runner --fast"), None);
        // Bare `node` with no `--test` is not the built-in runner.
        assert_eq!(classify_test_script("node script.js"), None);
    }

    #[test]
    fn a_node_prefix_without_the_test_flag_is_not_the_builtin_runner() {
        assert_eq!(classify_test_script("nodemon"), None);
    }
}
