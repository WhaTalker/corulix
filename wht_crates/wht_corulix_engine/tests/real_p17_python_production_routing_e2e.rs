// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P17 production-routing closure: real, end-to-end proof that
//! `wht_corulix_mcp::validate_change` -> `CorulixEngine::validate_change`
//! actually reaches `python_validation::run_typecheck`/`run_lint` and
//! `python_testing::run_pytest` for a Python-language `ChangeSession`,
//! driven exclusively through the real production entrypoints
//! `CorulixEngine::begin_change`/`validate_change` -- mirroring
//! `real_p15_go_production_routing_e2e.rs`'s own discipline exactly: **this
//! file never calls `python_validation`/`python_testing` directly**.
//!
//! Real `ruff`/`pyright`/`pytest` are resolved via `PATH` (or the
//! `CORULIX_TEST_PYTHON_TOOLS_DIR`/`CORULIX_TEST_PYRIGHT_DIR` overrides) --
//! the exact versions ADR 0011 observed (`ruff 0.16.1`, `pyright 1.1.413`,
//! `pytest 9.1.1`) when run against this project's own development
//! toolchain. Every test gracefully skips (never fails) when this
//! sandbox's real toolchain is absent, matching the Go/TS precedent.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{
    CancellationToken, ChangeSessionStatus, ConnectionId, GateId, GateStatus, LanguageId,
    OperationIntent, ReasonCode, WorkspaceIdentity,
};
use wht_corulix_engine::session::ChangeSession;
use wht_corulix_engine::validate_change::ValidateChangeOutcome;
use wht_corulix_engine::{CorulixEngine, HostConfig};
use wht_corulix_workspace::WorkspaceContext;

/// Test-only PATH-based tool discovery. An explicit environment-variable
/// override (`CORULIX_TEST_PYTHON_TOOLS_DIR` / `CORULIX_TEST_PYRIGHT_DIR`)
/// takes precedence; otherwise the directory on `PATH` containing
/// `bin_name` is used. Never embeds a specific developer's machine path.
fn resolve_test_tool_dir(bin_name: &str, env_override: &str) -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_override) {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("{bin_name}{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
}

fn real_ruff_pytest_directory() -> Option<PathBuf> {
    resolve_test_tool_dir("ruff", "CORULIX_TEST_PYTHON_TOOLS_DIR")
}
fn real_pyright_directory() -> Option<PathBuf> {
    resolve_test_tool_dir("pyright", "CORULIX_TEST_PYRIGHT_DIR")
}

#[derive(Debug)]
struct TestFailure(String);

impl fmt::Display for TestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for TestFailure {}

fn fail(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(TestFailure(message.into()))
}

fn real_python_tools_available() -> bool {
    let Some(ruff_pytest_dir) = real_ruff_pytest_directory() else {
        return false;
    };
    let Some(pyright_dir) = real_pyright_directory() else {
        return false;
    };
    ruff_pytest_dir.join("ruff").is_file()
        && ruff_pytest_dir.join("pytest").is_file()
        && pyright_dir.join("pyright").is_file()
}

macro_rules! require_python_tools {
    () => {
        if !real_python_tools_available() {
            eprintln!(
                "P17_PYTHON_PRODUCTION_ROUTING_E2E=BLOCKED_PROVIDER_UNAVAILABLE: real ruff/pyright/pytest not found at the expected sandbox paths"
            );
            return Ok(());
        }
    };
}

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

struct Fixture {
    root_dir: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root_dir = std::env::temp_dir().join(format!(
            "corulix-p17-python-production-routing-{label}-{}",
            stamp()
        ));
        let _ = fs::create_dir_all(&root_dir);
        Self { root_dir }
    }

    fn write(&self, name: &str, contents: &str) {
        let _ = fs::write(self.root_dir.join(name), contents);
    }

    fn workspace_root(
        &self,
    ) -> wht_corulix_core::CorulixResult<wht_corulix_workspace::WorkspaceRoot> {
        wht_corulix_workspace::WorkspaceRoot::open(&self.root_dir)
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.root_dir);
    }
}

/// A real `CorulixEngine` bound to `fixture`'s workspace, with real
/// `HOST_ONLY` Python provider authority (both `ruff`/`pytest`'s directory
/// and `pyright`'s separate directory) and the caller's requested trust.
fn python_engine(
    fixture: &Fixture,
    trusted: bool,
) -> wht_corulix_core::CorulixResult<CorulixEngine> {
    let root = fixture.workspace_root()?;
    let context = WorkspaceContext::single_root(root, "root".to_string());
    let host = HostConfig {
        approved_system_directories: vec![
            real_ruff_pytest_directory().unwrap_or_default(),
            real_pyright_directory().unwrap_or_default(),
        ],
        ..HostConfig::default()
    };
    Ok(CorulixEngine::open_with_host_config(context, trusted, host))
}

async fn begin_python_validate_session(
    engine: &CorulixEngine,
) -> wht_corulix_core::CorulixResult<(ChangeSession, WorkspaceIdentity, ConnectionId)> {
    let workspace_identity =
        WorkspaceIdentity::from_opaque_token(format!("wsid-p17-production-routing-{}", stamp()))?;
    let connection_id =
        ConnectionId::from_opaque_token(format!("cid-p17-production-routing-{}", stamp()))?;
    // `ruff check`'s own scope is a single confined staged copy of the
    // session's first bound scope prefix (ADR 0011's own confined-staged-
    // copy discipline, mirroring Biome's) -- unlike `go build`/`go vet`,
    // which operate project-wide with no target file needed. `main.py`
    // names this fixture's own target so lint has a file to stage.
    let session = engine
        .begin_change(
            OperationIntent::ValidateChange,
            Some(LanguageId::Python),
            None,
            vec!["main.py".to_string()],
            workspace_identity.clone(),
            connection_id.clone(),
            0,
        )
        .await?;
    Ok((session, workspace_identity, connection_id))
}

const VALID_MAIN: &str = "def add(a: int, b: int) -> int:\n    return a + b\n";

/// A real pyright *type* error -- assigning a `str` to an `int`-annotated
/// return.
const TYPECHECK_BROKEN_MAIN: &str = "def add(a: int, b: int) -> int:\n    return \"not an int\"\n";

/// Type-checks cleanly under pyright but fails `ruff check` with a real,
/// structured `F401` (unused import) finding -- the Python analog of Go's
/// `VET_BROKEN_MAIN` (builds clean, vets dirty).
const LINT_BROKEN_MAIN: &str = "import os\n\n\ndef add(a: int, b: int) -> int:\n    return a + b\n";

const PYPROJECT_WITH_PYTEST: &str = "[tool.pytest.ini_options]\nminversion = \"7.0\"\n";

const PASSING_TEST: &str = "def test_passes() -> None:\n    assert True\n";
const FAILING_TEST: &str = "def test_fails() -> None:\n    assert False, \"deliberate P17 production-routing-e2e failure\"\n";

fn diagnostics_record(
    session: &ChangeSession,
) -> Option<&wht_corulix_engine::session::EvidenceRecord> {
    session
        .evidence_history()
        .iter()
        .filter(|record| record.evidence.gate == GateId::Diagnostics)
        .max_by_key(|record| record.evidence.sequence)
}

fn tests_record(session: &ChangeSession) -> Option<&wht_corulix_engine::session::EvidenceRecord> {
    session
        .evidence_history()
        .iter()
        .filter(|record| record.evidence.gate == GateId::Tests)
        .max_by_key(|record| record.evidence.sequence)
}

// ---------------------------------------------------------------------
// Real production `pyright --outputjson` pass/failure through
// `validate_change`.
// ---------------------------------------------------------------------

#[tokio::test]
async fn real_production_python_typecheck_pass_e2e() -> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("typecheck-pass");
    fixture.write("main.py", VALID_MAIN);
    let engine = python_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_python_validate_session(&engine).await?;

    let sequence = session.evidence_history().len() as u64 + 1;
    let outcome = engine
        .validate_change(
            &mut session,
            &workspace_identity,
            &connection_id,
            sequence,
            &CancellationToken::new(),
        )
        .await;

    let ValidateChangeOutcome::PythonExecuted {
        typecheck,
        typecheck_evidence_recorded,
        ..
    } = &outcome
    else {
        return Err(fail(format!(
            "expected a real PythonExecuted outcome, got {outcome:?}"
        )));
    };
    if !typecheck.ran || !typecheck.clean {
        return Err(fail(format!(
            "expected a real, clean pyright typecheck, got {typecheck:?}"
        )));
    }
    if !typecheck_evidence_recorded {
        return Err(fail("expected gate.diagnostics Evidence to be recorded"));
    }

    let Some(record) = diagnostics_record(&session) else {
        return Err(fail("expected a real gate.diagnostics Evidence record"));
    };
    if record.status != GateStatus::Passed {
        return Err(fail(format!(
            "expected gate.diagnostics Passed, got {:?}",
            record.status
        )));
    }
    if record.evidence.provenance.provider_version.is_none() {
        return Err(fail(
            "Evidence must carry the real pyright version identity",
        ));
    }

    let status = session.change_status();
    if !status.completion_eligible {
        return Err(fail(format!(
            "expected completion_eligible after a clean typecheck, got {status:?}"
        )));
    }
    session
        .complete_change(&workspace_identity, &connection_id)
        .map_err(|error| {
            fail(format!(
                "expected complete_change to succeed, got {error:?}"
            ))
        })?;
    if session.change_status().status != ChangeSessionStatus::Completed {
        return Err(fail("expected the session to be Completed"));
    }

    fixture.cleanup();
    Ok(())
}

#[tokio::test]
async fn real_production_python_typecheck_failure_e2e() -> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("typecheck-fail");
    fixture.write("main.py", TYPECHECK_BROKEN_MAIN);
    let engine = python_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_python_validate_session(&engine).await?;

    let sequence = session.evidence_history().len() as u64 + 1;
    let outcome = engine
        .validate_change(
            &mut session,
            &workspace_identity,
            &connection_id,
            sequence,
            &CancellationToken::new(),
        )
        .await;

    let ValidateChangeOutcome::PythonExecuted { typecheck, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real PythonExecuted outcome, got {outcome:?}"
        )));
    };
    if typecheck.clean {
        return Err(fail(
            "a fixture with a real type error must never report a clean typecheck",
        ));
    }

    let Some(record) = diagnostics_record(&session) else {
        return Err(fail("expected a real gate.diagnostics Evidence record"));
    };
    if !matches!(record.status, GateStatus::Failed { .. }) {
        return Err(fail(format!(
            "expected gate.diagnostics Failed, got {:?}",
            record.status
        )));
    }

    let denial = session.complete_change(&workspace_identity, &connection_id);
    if denial.is_ok() {
        return Err(fail(
            "complete_change must be denied while gate.diagnostics is Failed",
        ));
    }

    fixture.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------
// Real production `ruff check` pass/failure, folded into the same
// combined `gate.diagnostics` record.
// ---------------------------------------------------------------------

#[tokio::test]
async fn real_production_python_lint_pass_e2e() -> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("lint-pass");
    fixture.write("main.py", VALID_MAIN);
    let engine = python_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_python_validate_session(&engine).await?;

    let sequence = session.evidence_history().len() as u64 + 1;
    let outcome = engine
        .validate_change(
            &mut session,
            &workspace_identity,
            &connection_id,
            sequence,
            &CancellationToken::new(),
        )
        .await;

    let ValidateChangeOutcome::PythonExecuted { lint, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real PythonExecuted outcome, got {outcome:?}"
        )));
    };
    if !lint.ran || !lint.clean {
        return Err(fail(format!(
            "expected a real, clean ruff check, got {lint:?}"
        )));
    }

    fixture.cleanup();
    Ok(())
}

/// A real `ruff check` finding on an otherwise type-clean file makes the
/// *combined* `gate.diagnostics` record `Failed` -- proof that `ruff
/// check`'s `Linter`/`SupportingOnly` finding genuinely reaches production
/// Evidence, and that it can only ever *strengthen* the shared authoritative
/// record, never independently close or override it as a second Evidence
/// item.
#[tokio::test]
async fn real_production_python_lint_failure_e2e() -> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("lint-fail");
    fixture.write("main.py", LINT_BROKEN_MAIN);
    let engine = python_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_python_validate_session(&engine).await?;
    let diagnostics_before = session
        .evidence_history()
        .iter()
        .filter(|record| record.evidence.gate == GateId::Diagnostics)
        .count();

    let sequence = session.evidence_history().len() as u64 + 1;
    let outcome = engine
        .validate_change(
            &mut session,
            &workspace_identity,
            &connection_id,
            sequence,
            &CancellationToken::new(),
        )
        .await;

    let ValidateChangeOutcome::PythonExecuted {
        typecheck, lint, ..
    } = &outcome
    else {
        return Err(fail(format!(
            "expected a real PythonExecuted outcome, got {outcome:?}"
        )));
    };
    if !typecheck.ran || !typecheck.clean {
        return Err(fail(format!(
            "expected pyright itself to be clean (only ruff check should fail), got {typecheck:?}"
        )));
    }
    if !lint.ran || lint.clean {
        return Err(fail(format!(
            "expected a real ruff check F401 finding for an unused import, got {lint:?}"
        )));
    }

    let Some(record) = diagnostics_record(&session) else {
        return Err(fail("expected a real gate.diagnostics Evidence record"));
    };
    if !matches!(record.status, GateStatus::Failed { .. }) {
        return Err(fail(format!(
            "expected the combined gate.diagnostics record to be Failed by ruff check's real finding, got {:?}",
            record.status
        )));
    }
    let diagnostics_after = session
        .evidence_history()
        .iter()
        .filter(|record| record.evidence.gate == GateId::Diagnostics)
        .count();
    if diagnostics_after != diagnostics_before + 1 {
        return Err(fail(format!(
            "expected exactly one new gate.diagnostics Evidence record from this call, went from {diagnostics_before} to {diagnostics_after}"
        )));
    }

    let denial = session.complete_change(&workspace_identity, &connection_id);
    if denial.is_ok() {
        return Err(fail(
            "complete_change must be denied while the combined gate.diagnostics record is Failed",
        ));
    }

    fixture.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------
// Real production `pytest` pass/failure through the distinct, `Optional`
// `gate.tests`.
// ---------------------------------------------------------------------

#[tokio::test]
async fn real_production_python_test_pass_e2e() -> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("test-pass");
    fixture.write("pyproject.toml", PYPROJECT_WITH_PYTEST);
    fixture.write("main.py", VALID_MAIN);
    fixture.write("test_main.py", PASSING_TEST);
    let engine = python_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_python_validate_session(&engine).await?;

    let sequence = session.evidence_history().len() as u64 + 1;
    let outcome = engine
        .validate_change(
            &mut session,
            &workspace_identity,
            &connection_id,
            sequence,
            &CancellationToken::new(),
        )
        .await;

    let ValidateChangeOutcome::PythonExecuted {
        test,
        test_evidence_recorded,
        ..
    } = &outcome
    else {
        return Err(fail(format!(
            "expected a real PythonExecuted outcome, got {outcome:?}"
        )));
    };
    if !test.ran || !test.clean {
        return Err(fail(format!(
            "expected a real, passing pytest run, got {test:?}"
        )));
    }
    if !test_evidence_recorded {
        return Err(fail("expected gate.tests Evidence to be recorded"));
    }

    let Some(record) = tests_record(&session) else {
        return Err(fail("expected a real gate.tests Evidence record"));
    };
    if record.status != GateStatus::Passed {
        return Err(fail(format!(
            "expected gate.tests Passed, got {:?}",
            record.status
        )));
    }
    if record.evidence.provenance.provider_id != "pytest" {
        return Err(fail(format!(
            "expected the real provider_id 'pytest', got {:?}",
            record.evidence.provenance.provider_id
        )));
    }

    fixture.cleanup();
    Ok(())
}

#[tokio::test]
async fn real_production_python_test_failure_e2e() -> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("test-fail");
    fixture.write("pyproject.toml", PYPROJECT_WITH_PYTEST);
    fixture.write("main.py", VALID_MAIN);
    fixture.write("test_main.py", FAILING_TEST);
    let engine = python_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_python_validate_session(&engine).await?;

    let sequence = session.evidence_history().len() as u64 + 1;
    let outcome = engine
        .validate_change(
            &mut session,
            &workspace_identity,
            &connection_id,
            sequence,
            &CancellationToken::new(),
        )
        .await;

    let ValidateChangeOutcome::PythonExecuted { test, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real PythonExecuted outcome, got {outcome:?}"
        )));
    };
    if !test.ran || test.clean {
        return Err(fail(format!(
            "expected a real, failing pytest run, got {test:?}"
        )));
    }

    let Some(record) = tests_record(&session) else {
        return Err(fail("expected a real gate.tests Evidence record"));
    };
    if !matches!(record.status, GateStatus::Failed { .. }) {
        return Err(fail(format!(
            "expected gate.tests Failed, got {:?}",
            record.status
        )));
    }

    fixture.cleanup();
    Ok(())
}

/// No discoverable pytest marker (ADR 0011 §4) must never fall back to a
/// silent global `pytest` assumption -- `gate.tests` records the real,
/// honest `AmbiguousTestRunner` failure instead.
#[tokio::test]
async fn real_production_python_test_without_discovery_marker_is_ambiguous()
-> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("test-no-marker");
    fixture.write("main.py", VALID_MAIN);
    fixture.write("test_main.py", PASSING_TEST);
    let engine = python_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_python_validate_session(&engine).await?;

    let sequence = session.evidence_history().len() as u64 + 1;
    let outcome = engine
        .validate_change(
            &mut session,
            &workspace_identity,
            &connection_id,
            sequence,
            &CancellationToken::new(),
        )
        .await;

    let ValidateChangeOutcome::PythonExecuted { test, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real PythonExecuted outcome, got {outcome:?}"
        )));
    };
    if test.ran {
        return Err(fail(
            "pytest must never run when no discovery marker resolves a runner",
        ));
    }

    fixture.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------
// Trust remains load-bearing for `pytest` through the production path.
// ---------------------------------------------------------------------

/// `P17_PRODUCTION_PYTEST_UNTRUSTED_EXECUTION_COUNT=0`: an untrusted
/// engine's Python `ChangeSession`, run through the real production
/// `validate_change` call, must deny `pytest` execution before any process
/// spawns -- proven by a side-effect marker a real pytest run would have
/// created. Typecheck/lint remain `ControlledExternalTool` (ADR 0011) and
/// are unaffected by workspace trust, matching this dispatcher's own
/// per-category gating.
#[tokio::test]
async fn real_production_python_untrusted_pytest_denied_before_any_execution()
-> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("untrusted");
    let marker = fixture.root_dir.join("MARKER_UNTRUSTED");
    let _ = fs::remove_file(&marker);
    fixture.write("pyproject.toml", PYPROJECT_WITH_PYTEST);
    fixture.write("main.py", VALID_MAIN);
    fixture.write(
        "test_main.py",
        &format!(
            "from pathlib import Path\n\n\ndef test_side_effect() -> None:\n    Path({:?}).write_text(\"ran\")\n",
            marker.to_string_lossy()
        ),
    );
    let engine = python_engine(&fixture, false)?;
    let (mut session, workspace_identity, connection_id) =
        begin_python_validate_session(&engine).await?;

    let sequence = session.evidence_history().len() as u64 + 1;
    let outcome = engine
        .validate_change(
            &mut session,
            &workspace_identity,
            &connection_id,
            sequence,
            &CancellationToken::new(),
        )
        .await;

    // Typecheck/lint are `ControlledExternalTool` and run regardless of
    // workspace trust (ADR 0011) -- only `pytest`'s `TestRunner` gate is
    // trust-sensitive.
    let ValidateChangeOutcome::PythonExecuted { test, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real PythonExecuted outcome (typecheck/lint remain untrusted-independent), got {outcome:?}"
        )));
    };
    if test.ran {
        return Err(fail(
            "pytest must never run under an untrusted workspace through the production path",
        ));
    }
    if test.reason_code != Some(ReasonCode::RequiredProviderUnavailable) {
        return Err(fail(format!(
            "expected RequiredProviderUnavailable for the denied pytest run, got {:?}",
            test.reason_code
        )));
    }
    if marker.exists() {
        return Err(fail(
            "the pytest test code executed under an untrusted workspace through the production path -- the trust gate is not load-bearing here",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_file(&marker);
    Ok(())
}

// ---------------------------------------------------------------------
// Minimum Sufficient Tooling: an unrequired Python provider is never
// spawned through the production path.
// ---------------------------------------------------------------------

#[tokio::test]
async fn real_production_python_unrequired_typecheck_is_never_executed()
-> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("not-required");
    fixture.write("main.py", VALID_MAIN);
    let engine = python_engine(&fixture, true)?;

    let workspace_identity =
        WorkspaceIdentity::from_opaque_token(format!("wsid-p17-not-required-{}", stamp()))?;
    let connection_id =
        ConnectionId::from_opaque_token(format!("cid-p17-not-required-{}", stamp()))?;
    let mut session = engine
        .begin_change(
            OperationIntent::DocumentationModify,
            Some(LanguageId::Python),
            None,
            vec!["main.py".to_string()],
            workspace_identity.clone(),
            connection_id.clone(),
            0,
        )
        .await?;
    if session.tool_plan().requirements.iter().any(|requirement| {
        requirement.category == wht_corulix_core::ProviderCategory::TypecheckBuild
    }) {
        return Err(fail(
            "DocumentationModify's own policy entry must never name TypecheckBuild -- this test's premise is wrong",
        ));
    }

    let sequence = session.evidence_history().len() as u64 + 1;
    let outcome = engine
        .validate_change(
            &mut session,
            &workspace_identity,
            &connection_id,
            sequence,
            &CancellationToken::new(),
        )
        .await;

    if !matches!(outcome, ValidateChangeOutcome::NotRequired) {
        return Err(fail(format!(
            "expected NotRequired for an operation that never asked for TypecheckBuild, got {outcome:?}"
        )));
    }
    if !session.evidence_history().is_empty() {
        return Err(fail(
            "no Evidence may be recorded for a category this operation never required",
        ));
    }

    fixture.cleanup();
    Ok(())
}
