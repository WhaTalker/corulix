// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15 production-routing regression closure: real, end-to-end proof that
//! `wht_corulix_mcp::validate_change` -> `CorulixEngine::validate_change`
//! actually reaches `go_validation::run_go_validator`/`go_testing::run_go_test`
//! for a Go-language `ChangeSession`, driven exclusively through the real
//! production entrypoints `CorulixEngine::begin_change`/`validate_change` --
//! the exact same calls `wht_corulix_mcp`'s `begin_change`/`validate_change`
//! tools make. **This file never calls `go_validation`/`go_testing`
//! directly** -- doing so would reproduce the exact certification weakness
//! this closure fixes (that was `real_p15_go_build_vet_test_e2e.rs`'s own
//! blind spot: a real, passing Go E2E suite that nonetheless never proved
//! production reachability).
//!
//! # The regression this file closes
//!
//! A P16 discovery pass, reading `wht_corulix_engine`'s code while scoping
//! the TypeScript/JavaScript vertical, flagged that `run_go_validator`/
//! `run_go_test` appeared reachable only from their own modules' unit tests
//! and from the direct-call E2E file above -- never from any real dispatch
//! path starting at `validate_change`. Tracing the real call graph from the
//! entrypoint confirmed it: before this closure,
//! `wht_corulix_engine::validate_change::CorulixEngine::validate_change`
//! unconditionally ran `diagnostics::run_cargo_check` regardless of the
//! session's declared language, and `ChangeSession` retained no `language`
//! field at all for a later capability to dispatch on. A Go `ChangeSession`
//! calling the real, production `validate_change` tool therefore either ran
//! `cargo check` against a Go workspace (nonsensical) or never validated
//! anything Go-specific -- `run_go_validator`/`run_go_test` were genuinely
//! dead code from production's perspective. This file's every test drives
//! `begin_change` -> `validate_change` -> `change_status`/`complete_change`,
//! proving the fixed dispatch end to end.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{
    CancellationToken, ChangeSessionStatus, ConnectionId, GateId, GateStatus, LanguageId,
    OperationIntent, ReasonCode, WorkspaceIdentity,
};
use wht_corulix_engine::session::ChangeSession;
use wht_corulix_engine::validate_change::ValidateChangeOutcome;
use wht_corulix_engine::{CorulixEngine, HostConfig};
use wht_corulix_workspace::WorkspaceContext;

/// This host's real Go toolchain directory, confirmed by P15's own discovery
/// pass. A `HOST_ONLY`-style approved directory for test purposes only --
/// production callers supply this through real host configuration.
const REAL_GO_DIRECTORY: &str = "/usr/local/go/bin";

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

fn real_go_available() -> bool {
    Path::new(REAL_GO_DIRECTORY).join("go").is_file()
}

macro_rules! require_go {
    () => {
        if !real_go_available() {
            eprintln!(
                "P15_GO_PRODUCTION_ROUTING_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real go at {REAL_GO_DIRECTORY}"
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

/// `MANAGED_TEST_ISOLATION_DEFECT` closure pass: this file previously ran
/// its real `go build`/`go vet`/`go test` invocations through
/// `CorulixEngine::validate_change`'s production path, which resolves
/// `managed_toolchain_root()` (the real, shared, host-wide root) internally
/// with no injection point, then cleaned up the resulting
/// `scratch/p15-go/<workspace-hash>/...` directory against that live root
/// afterward (`remove_shared_root_go_scratch`, mirroring
/// `wht_corulix_mcp`'s identical, now-fixed pattern). Fixed the same way:
/// re-exec this exact, already-compiled test binary as a real child process
/// (libtest's own `--exact` filter) with `XDG_DATA_HOME` pointed at a fresh
/// isolated directory -- this workspace forbids `unsafe` code
/// (`std::env::set_var` is `unsafe fn`), so a test process cannot redirect
/// its own `XDG_DATA_HOME` in-process. The Go scratch this produces then
/// lives entirely under that isolated directory, removed by the parent
/// afterward -- never the real root.
///
/// Returns `Ok(true)` from the PARENT process: the child already ran and
/// its success is already asserted, so the caller should return `Ok(())`
/// immediately. Returns `Ok(false)` inside the isolated CHILD (the trigger
/// env var is present): the caller should continue running its real test
/// body now, with `managed_toolchain_root()` already resolving to the
/// isolated root via this process's own `XDG_DATA_HOME`.
async fn run_isolated_or_continue(
    trigger_env: &str,
    exact_test_name: &str,
) -> Result<bool, Box<dyn Error>> {
    if std::env::var(trigger_env).ok().as_deref() == Some("1") {
        return Ok(false);
    }
    let isolated_xdg_data_home = std::env::temp_dir().join(format!(
        "corulix-p15-go-production-routing-xdg-{trigger_env}-{}",
        stamp()
    ));
    let _ = fs::create_dir_all(&isolated_xdg_data_home);
    let exe = std::env::current_exe()
        .map_err(|error| fail(format!("current_exe unresolvable: {error}")))?;
    let output = tokio::process::Command::new(&exe)
        .args([
            "--exact",
            exact_test_name,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(trigger_env, "1")
        .env("XDG_DATA_HOME", &isolated_xdg_data_home)
        .output()
        .await
        .map_err(|error| {
            fail(format!(
                "re-exec of the isolated child process failed: {error}"
            ))
        })?;
    let _ = fs::remove_dir_all(&isolated_xdg_data_home);
    if !output.status.success() {
        return Err(fail(format!(
            "isolated child run of {exact_test_name} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(true)
}

/// P17-W-R3-C3 (`CANONICAL_DEFAULT_PARALLEL_TEST_GATE_FLAKINESS` root cause,
/// this file): every test below drives a real `go build`/`go vet`/`go test`
/// invocation through the same **shared, host-wide**
/// `managed_toolchain_root()` scratch tree `remove_shared_root_go_scratch`'s
/// own doc already discloses -- there is no per-test isolation possible for
/// it (the real production path, not a test seam). `cargo test`'s default
/// concurrent execution previously let this file's 8 tests run real,
/// concurrent Go toolchain invocations against that one shared
/// `scratch/p15-go` directory (and let one test's own
/// `remove_shared_root_go_scratch` cleanup delete it out from under a
/// sibling still mid-run) -- confirmed empirically: this file's tests
/// passed reliably under `--test-threads=1` but intermittently reported
/// `ran: false, reason_code: RequiredCapabilityUnavailable` under default
/// parallelism (a fail-closed catch-all this crate's `go_test_error_reason`/
/// `go_validator_error_reason` maps many distinct underlying causes to --
/// `SpawnFailed`, `ResultContradiction`, `WorkspaceSourceTreeUnreadable`,
/// etc. -- any of which a concurrent writer/deleter racing the same
/// directory can plausibly trigger). Every test below now acquires this
/// lock for its entire body, serializing them against each other -- a
/// test-only fix; the underlying shared-root limitation itself remains the
/// already-disclosed, out-of-scope production gap these doc comments
/// describe.
///
/// Update (`MANAGED_TEST_ISOLATION_DEFECT` closure pass): the six tests that
/// drive a real Go toolchain invocation now each run inside their own
/// isolated child process (see `run_isolated_or_continue` above), each with
/// its own private `XDG_DATA_HOME` and therefore its own private `scratch/`
/// tree -- so the original shared-directory race this lock exists for can no
/// longer occur between them. The lock is kept regardless (never proven
/// unnecessary for the two remaining tests that skip isolation, and
/// conservative to keep rather than relax without a dedicated re-verification
/// pass).
static GO_PRODUCTION_ROUTING_TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn go_production_routing_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    GO_PRODUCTION_ROUTING_TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

/// A disposable, real Go module fixture.
struct Fixture {
    root_dir: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root_dir = std::env::temp_dir().join(format!(
            "corulix-p15-go-production-routing-{label}-{}",
            stamp()
        ));
        let _ = fs::create_dir_all(&root_dir);
        let _ = fs::write(
            root_dir.join("go.mod"),
            "module corulix_p15_production_routing_fixture\n\ngo 1.24\n",
        );
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
/// `HOST_ONLY` Go provider authority and the caller's requested trust.
fn go_engine(fixture: &Fixture, trusted: bool) -> wht_corulix_core::CorulixResult<CorulixEngine> {
    let root = fixture.workspace_root()?;
    let context = WorkspaceContext::single_root(root, "root".to_string());
    let host = HostConfig {
        approved_system_directories: vec![PathBuf::from(REAL_GO_DIRECTORY)],
        ..HostConfig::default()
    };
    Ok(CorulixEngine::open_with_host_config(context, trusted, host))
}

/// Opens a real, `OperationIntent::ValidateChange`-scoped, Go-language
/// `ChangeSession` -- the same call `wht_corulix_mcp::begin_change` makes.
/// `ValidateChange`'s own policy entry (`crate::policy::VALIDATE_CHANGE`)
/// carries no `Edit`/`Format` gate at all, so this session lands directly on
/// `GatePending(Diagnostics)` (or `Blocked` if unexecutable) with no
/// `submit_edit` needed -- exactly the production shape a caller uses to
/// validate a Go workspace without also mutating it.
async fn begin_go_validate_session(
    engine: &CorulixEngine,
) -> wht_corulix_core::CorulixResult<(ChangeSession, WorkspaceIdentity, ConnectionId)> {
    let workspace_identity =
        WorkspaceIdentity::from_opaque_token(format!("wsid-p15-production-routing-{}", stamp()))?;
    let connection_id =
        ConnectionId::from_opaque_token(format!("cid-p15-production-routing-{}", stamp()))?;
    let session = engine
        .begin_change(
            OperationIntent::ValidateChange,
            Some(LanguageId::Go),
            None,
            Vec::new(),
            workspace_identity.clone(),
            connection_id.clone(),
            0,
        )
        .await?;
    Ok((session, workspace_identity, connection_id))
}

const VALID_MAIN: &str = "package main\n\nfunc main() {}\n";

/// A real *type* error -- `go build` must fail.
const BUILD_BROKEN_MAIN: &str =
    "package main\n\nfunc main() {\n\tvar x int = \"not an int\"\n\t_ = x\n}\n";

/// Builds cleanly but fails `go vet`: a `Printf` format/argument mismatch.
/// Empirically confirmed (P15 research gate) to pass `go build` and fail
/// `go vet` against the real `go1.26.6` on this host -- proof that `go
/// vet`'s finding genuinely reaches the *same* combined `gate.diagnostics`
/// Evidence this closure's dispatcher produces, not merely that `go vet`
/// runs.
const VET_BROKEN_MAIN: &str =
    "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Printf(\"%d\\n\", \"a string\")\n}\n";

const PASSING_TEST: &str =
    "package main\n\nimport \"testing\"\n\nfunc TestPasses(t *testing.T) {}\n";

const FAILING_TEST: &str = "package main\n\nimport \"testing\"\n\nfunc TestFails(t *testing.T) {\n\tt.Fatal(\"deliberate P15 production-routing-e2e failure\")\n}\n";

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
// §7 -- real production `go build` pass/failure through `validate_change`
// ---------------------------------------------------------------------

/// `P15_PRODUCTION_GO_BUILD_PASS_E2E`: a trusted, valid Go workspace's
/// required `TypecheckBuild` really runs through `begin_change` ->
/// `validate_change`, records `gate.diagnostics` Evidence with the real
/// provider identity, and the session becomes completion-eligible.
#[tokio::test]
async fn real_production_go_build_pass_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    if run_isolated_or_continue(
        "CORULIX_GO_PROD_ROUTING_REAL_PRODUCTION_GO_BUILD_PASS_E2E_CHILD",
        "real_production_go_build_pass_e2e",
    )
    .await?
    {
        return Ok(());
    }
    let _lock = go_production_routing_test_lock().await;
    let fixture = Fixture::new("build-pass");
    fixture.write("main.go", VALID_MAIN);
    let engine = go_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_go_validate_session(&engine).await?;

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

    let ValidateChangeOutcome::GoExecuted {
        build,
        build_evidence_recorded,
        ..
    } = &outcome
    else {
        return Err(fail(format!(
            "expected a real GoExecuted outcome, got {outcome:?}"
        )));
    };
    if !build.ran || !build.clean {
        return Err(fail(format!(
            "expected a real, clean go build, got {build:?}"
        )));
    }
    if !build_evidence_recorded {
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
    if !record
        .evidence
        .provenance
        .provider_version
        .as_deref()
        .unwrap_or_default()
        .starts_with("go version go")
    {
        return Err(fail(format!(
            "Evidence must carry the real go version identity, got {:?}",
            record.evidence.provenance
        )));
    }
    if record.evidence.provenance.provider_id != "go build" {
        return Err(fail(format!(
            "expected the real provider_id 'go build', got {:?}",
            record.evidence.provenance.provider_id
        )));
    }

    let status = session.change_status();
    if !status.completion_eligible {
        return Err(fail(format!(
            "expected completion_eligible after a clean go build, got {status:?}"
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

/// `P15_PRODUCTION_GO_BUILD_FAILURE_E2E`: a real compile error, run through
/// the same production path, records a real `Failed` `gate.diagnostics`
/// Evidence and `complete_change` is denied -- never a silent pass.
#[tokio::test]
async fn real_production_go_build_failure_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    if run_isolated_or_continue(
        "CORULIX_GO_PROD_ROUTING_REAL_PRODUCTION_GO_BUILD_FAILURE_E2E_CHILD",
        "real_production_go_build_failure_e2e",
    )
    .await?
    {
        return Ok(());
    }
    let _lock = go_production_routing_test_lock().await;
    let fixture = Fixture::new("build-fail");
    fixture.write("main.go", BUILD_BROKEN_MAIN);
    let engine = go_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_go_validate_session(&engine).await?;

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

    let ValidateChangeOutcome::GoExecuted { build, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real GoExecuted outcome, got {outcome:?}"
        )));
    };
    if build.clean {
        return Err(fail(
            "a fixture that does not compile must never report a clean build",
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
// §8 -- real production `go vet` pass/failure, folded into the same
// combined `gate.diagnostics` record `go build` produces.
// ---------------------------------------------------------------------

/// `P15_PRODUCTION_GO_VET_PASS_E2E`: a fixture that is clean under both
/// `go build` and `go vet` reports a real, clean `vet` result.
#[tokio::test]
async fn real_production_go_vet_pass_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    if run_isolated_or_continue(
        "CORULIX_GO_PROD_ROUTING_REAL_PRODUCTION_GO_VET_PASS_E2E_CHILD",
        "real_production_go_vet_pass_e2e",
    )
    .await?
    {
        return Ok(());
    }
    let _lock = go_production_routing_test_lock().await;
    let fixture = Fixture::new("vet-pass");
    fixture.write("main.go", VALID_MAIN);
    let engine = go_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_go_validate_session(&engine).await?;

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

    let ValidateChangeOutcome::GoExecuted { vet, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real GoExecuted outcome, got {outcome:?}"
        )));
    };
    if !vet.ran || !vet.clean {
        return Err(fail(format!(
            "expected a real, clean go vet run, got {vet:?}"
        )));
    }

    fixture.cleanup();
    Ok(())
}

/// `P15_PRODUCTION_GO_VET_FAILURE_E2E`: a real `go vet` finding on an
/// otherwise-clean build makes the *combined* `gate.diagnostics` record
/// `Failed` -- proof that `go vet`'s `Linter`/`SupportingOnly` finding
/// genuinely reaches production Evidence, and proof it can only ever
/// *strengthen* the shared authoritative record, never independently close
/// or override it as a second Evidence item (see `validate_change.rs`'s own
/// doc comment).
#[tokio::test]
async fn real_production_go_vet_failure_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    if run_isolated_or_continue(
        "CORULIX_GO_PROD_ROUTING_REAL_PRODUCTION_GO_VET_FAILURE_E2E_CHILD",
        "real_production_go_vet_failure_e2e",
    )
    .await?
    {
        return Ok(());
    }
    let _lock = go_production_routing_test_lock().await;
    let fixture = Fixture::new("vet-fail");
    fixture.write("main.go", VET_BROKEN_MAIN);
    let engine = go_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_go_validate_session(&engine).await?;
    // `begin_change` itself may already have written a synthetic
    // plan-denial record for `gate.diagnostics` (Section 19's `ProviderSnapshot`
    // is not language-aware for `TypecheckBuild` -- a separate, pre-existing,
    // out-of-scope limitation this test must not assume away). What matters
    // here is that this *call* adds exactly one new record, corrective over
    // any prior one, never two independent records for the same gate.
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

    let ValidateChangeOutcome::GoExecuted { build, vet, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real GoExecuted outcome, got {outcome:?}"
        )));
    };
    if !build.ran || !build.clean {
        return Err(fail(format!(
            "expected `go build` itself to be clean (only `go vet` should fail), got {build:?}"
        )));
    }
    if !vet.ran || vet.clean {
        return Err(fail(format!(
            "expected a real go vet finding for a Printf format/argument mismatch, got {vet:?}"
        )));
    }

    let Some(record) = diagnostics_record(&session) else {
        return Err(fail("expected a real gate.diagnostics Evidence record"));
    };
    if !matches!(record.status, GateStatus::Failed { .. }) {
        return Err(fail(format!(
            "expected the combined gate.diagnostics record to be Failed by go vet's real finding, got {:?}",
            record.status
        )));
    }
    // Exactly one *new* Evidence record was written against gate.diagnostics
    // by this call -- `go vet` never gets a second, independent record of
    // its own alongside `go build`'s.
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
// §9 -- real production `go test` pass/failure through the distinct,
// `Optional` `gate.tests`.
// ---------------------------------------------------------------------

/// `P15_PRODUCTION_GO_TEST_PASS_E2E`: a real passing Go test, run through
/// the same production `validate_change` call, records a real `Passed`
/// `gate.tests` Evidence item -- the process genuinely executed (a
/// `passed`/`failed` count from a real `go test -json` stream, not a
/// narrative claim).
#[tokio::test]
async fn real_production_go_test_pass_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    if run_isolated_or_continue(
        "CORULIX_GO_PROD_ROUTING_REAL_PRODUCTION_GO_TEST_PASS_E2E_CHILD",
        "real_production_go_test_pass_e2e",
    )
    .await?
    {
        return Ok(());
    }
    let _lock = go_production_routing_test_lock().await;
    let fixture = Fixture::new("test-pass");
    fixture.write("main.go", VALID_MAIN);
    fixture.write("main_test.go", PASSING_TEST);
    let engine = go_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_go_validate_session(&engine).await?;

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

    let ValidateChangeOutcome::GoExecuted {
        test,
        test_evidence_recorded,
        ..
    } = &outcome
    else {
        return Err(fail(format!(
            "expected a real GoExecuted outcome, got {outcome:?}"
        )));
    };
    if !test.ran || !test.clean {
        return Err(fail(format!(
            "expected a real, passing go test run, got {test:?}"
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
    if record.evidence.provenance.provider_id != "go test" {
        return Err(fail(format!(
            "expected the real provider_id 'go test', got {:?}",
            record.evidence.provenance.provider_id
        )));
    }

    fixture.cleanup();
    Ok(())
}

/// `P15_PRODUCTION_GO_TEST_FAILURE_E2E`: a real failing Go test records a
/// real `Failed` `gate.tests` Evidence item. `gate.tests` is `Optional` in
/// `VALIDATE_CHANGE`'s own policy entry (no `OperationIntent` requires tests
/// today -- P12's own disclosed scope), so this deliberately does **not**
/// assert `complete_change` is denied by it; it asserts the real failure is
/// genuinely recorded, which is what §9 requires.
#[tokio::test]
async fn real_production_go_test_failure_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    if run_isolated_or_continue(
        "CORULIX_GO_PROD_ROUTING_REAL_PRODUCTION_GO_TEST_FAILURE_E2E_CHILD",
        "real_production_go_test_failure_e2e",
    )
    .await?
    {
        return Ok(());
    }
    let _lock = go_production_routing_test_lock().await;
    let fixture = Fixture::new("test-fail");
    fixture.write("main.go", VALID_MAIN);
    fixture.write("main_test.go", FAILING_TEST);
    let engine = go_engine(&fixture, true)?;
    let (mut session, workspace_identity, connection_id) =
        begin_go_validate_session(&engine).await?;

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

    let ValidateChangeOutcome::GoExecuted { test, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real GoExecuted outcome, got {outcome:?}"
        )));
    };
    if !test.ran || test.clean {
        return Err(fail(format!(
            "expected a real, failing go test run, got {test:?}"
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

// ---------------------------------------------------------------------
// §6 -- trust remains load-bearing through the production path.
// ---------------------------------------------------------------------

/// `P15_PRODUCTION_GO_BUILD_UNTRUSTED_EXECUTION_COUNT=0` /
/// `P15_PRODUCTION_GO_TEST_UNTRUSTED_EXECUTION_COUNT=0`: an untrusted
/// engine's Go `ChangeSession`, run through the real production
/// `validate_change` call, must be denied before any process spawns --
/// proven by a side-effect marker a real `go test` run would have created,
/// exactly as `real_p15_go_build_vet_test_e2e.rs`'s own provider-level tests
/// prove it for the direct call, but now proven for the production
/// dispatcher, not only the provider it eventually calls.
#[tokio::test]
async fn real_production_go_untrusted_workspace_is_denied_before_any_execution()
-> Result<(), Box<dyn Error>> {
    require_go!();
    let _lock = go_production_routing_test_lock().await;
    let fixture = Fixture::new("untrusted");
    let marker = fixture.root_dir.join("MARKER_UNTRUSTED");
    let _ = fs::remove_file(&marker);
    fixture.write("main.go", VALID_MAIN);
    fixture.write(
        "main_test.go",
        &format!(
            "package main\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestSideEffect(t *testing.T) {{\n\tif err := os.WriteFile({:?}, []byte(\"ran\"), 0o644); err != nil {{\n\t\tt.Fatalf(\"marker write failed: %v\", err)\n\t}}\n}}\n",
            marker.to_string_lossy()
        ),
    );
    let engine = go_engine(&fixture, false)?;
    let (mut session, workspace_identity, connection_id) =
        begin_go_validate_session(&engine).await?;
    // `begin_change` itself may already have written a synthetic
    // plan-denial record (a separate, pre-existing, out-of-scope limitation
    // -- see the vet-failure test's own comment); what this test must prove
    // is that *this call* records nothing new and spawns nothing.
    let evidence_before = session.evidence_history().len();

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

    let ValidateChangeOutcome::Unavailable { reason_code } = outcome else {
        return Err(fail(format!(
            "expected Unavailable for an untrusted engine, got {outcome:?}"
        )));
    };
    if reason_code != ReasonCode::RequiredProviderUnavailable {
        return Err(fail(format!(
            "expected RequiredProviderUnavailable, got {reason_code:?}"
        )));
    }
    if marker.exists() {
        return Err(fail(
            "the Go test code executed under an untrusted workspace through the production path -- the trust gate is not load-bearing here",
        ));
    }
    if session.evidence_history().len() != evidence_before {
        return Err(fail(
            "no new Evidence may be recorded when the engine denies execution before spawning",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_file(&marker);
    Ok(())
}

// ---------------------------------------------------------------------
// §10 -- Minimum Sufficient Tooling: an unrequired Go provider is never
// spawned through the production path.
// ---------------------------------------------------------------------

/// `P15_UNREQUIRED_GO_PROVIDER_EXECUTION_COUNT=0`: a Go `ChangeSession`
/// opened for an operation whose own policy entry never names
/// `TypecheckBuild` as a requirement (`DocumentationModify`) reports
/// `NotRequired` and records zero Evidence -- proving the *execution*, not
/// merely the resulting Evidence, is skipped (the pre-existing Rust path's
/// own gap: it always ran `cargo check` and let `record_evidence` reject
/// the result afterward; this closure's Go dispatcher checks the
/// requirement *before* spawning anything).
#[tokio::test]
async fn real_production_go_unrequired_typecheck_build_is_never_executed()
-> Result<(), Box<dyn Error>> {
    require_go!();
    let _lock = go_production_routing_test_lock().await;
    let fixture = Fixture::new("not-required");
    fixture.write("main.go", VALID_MAIN);
    let engine = go_engine(&fixture, true)?;

    let workspace_identity =
        WorkspaceIdentity::from_opaque_token(format!("wsid-p15-not-required-{}", stamp()))?;
    let connection_id =
        ConnectionId::from_opaque_token(format!("cid-p15-not-required-{}", stamp()))?;
    let mut session = engine
        .begin_change(
            OperationIntent::DocumentationModify,
            Some(LanguageId::Go),
            None,
            vec!["main.go".to_string()],
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
