// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P16 production-routing closure: real, end-to-end proof that
//! `wht_corulix_mcp::validate_change` -> `CorulixEngine::validate_change`
//! actually reaches `ts_validation::run_typecheck`/`run_lint` for a
//! TypeScript-language `ChangeSession`, driven exclusively through the real
//! production entrypoints `CorulixEngine::begin_change`/`validate_change` --
//! the exact same calls `wht_corulix_mcp`'s `begin_change`/`validate_change`
//! tools make. **This file never calls `ts_validation` directly** -- doing
//! so would reproduce the exact "implemented but zero production callers"
//! defect class P15/P16's own discovery passes already found twice for Go
//! and Rust (`real_p15_go_production_routing_e2e.rs` is this file's direct
//! sibling; same shape, third language).
//!
//! Provisions against the real, shared `managed_toolchain_root()` (same
//! convention `real_p16_typescript_javascript_semantic_e2e.rs` already
//! uses for TS7). Requires real network access to `registry.npmjs.org`/
//! GitHub Releases the first time it runs; reports and exits early with
//! `BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED` otherwise, never substituting
//! a mock.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{
    CancellationToken, ChangeSessionStatus, ConnectionId, GateId, GateStatus, LanguageId,
    OperationIntent, WorkspaceIdentity,
};
use wht_corulix_engine::CorulixEngine;
use wht_corulix_engine::session::ChangeSession;
use wht_corulix_engine::validate_change::ValidateChangeOutcome;
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceContext;

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

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

/// Serializes every test in this file against the real, shared managed
/// root -- mirrors `real_p16_typescript_javascript_semantic_e2e.rs`'s own
/// `REAL_P16_TS_SESSION_LOCK` precedent.
static REAL_P16_TS_VALIDATE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_P16_TS_VALIDATE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

async fn ensure_ts7_provisioned(root: &std::path::Path) -> bool {
    let manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

async fn ensure_biome_provisioned(root: &std::path::Path) -> bool {
    let manifest = wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

async fn ensure_node_provisioned(root: &std::path::Path) -> bool {
    let manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

async fn ensure_ts6_provisioned(root: &std::path::Path) -> bool {
    let ts6 = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_LINUX_X64;
    let (state, _) = provisioning::resolve_managed_component(root, &ts6);
    state == ManagedComponentState::Available || provisioning::provision(root, &ts6).await.is_ok()
}

macro_rules! require_ts_providers {
    ($root:expr) => {
        let ts7_ok = ensure_ts7_provisioned($root).await;
        let biome_ok = ensure_biome_provisioned($root).await;
        if !ts7_ok || !biome_ok {
            eprintln!(
                "P16_TS_PRODUCTION_ROUTING_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (ts7={ts7_ok}, biome={biome_ok})"
            );
            return Ok(());
        }
    };
}

macro_rules! require_node_provider {
    ($root:expr) => {
        let node_ok = ensure_node_provisioned($root).await;
        if !node_ok {
            eprintln!(
                "P16_TS_PRODUCTION_ROUTING_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (node={node_ok})"
            );
            return Ok(());
        }
    };
}

macro_rules! require_ts6_provider {
    ($root:expr) => {
        let ts6_ok = ensure_ts6_provisioned($root).await;
        if !ts6_ok {
            eprintln!(
                "P16_TS_PRODUCTION_ROUTING_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (ts6={ts6_ok})"
            );
            return Ok(());
        }
    };
}

struct Fixture {
    root_dir: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root_dir = std::env::temp_dir().join(format!(
            "corulix-p16-ts-production-routing-{label}-{}",
            stamp()
        ));
        let _ = fs::create_dir_all(&root_dir);
        let _ = fs::write(
            root_dir.join("tsconfig.json"),
            "{\"compilerOptions\":{\"strict\":true,\"noEmit\":true}}\n",
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

fn ts_engine(fixture: &Fixture) -> wht_corulix_core::CorulixResult<CorulixEngine> {
    let root = fixture.workspace_root()?;
    let context = WorkspaceContext::single_root(root, "root".to_string());
    Ok(CorulixEngine::open_with_trust(context, true))
}

async fn begin_ts_validate_session(
    engine: &CorulixEngine,
    target_relative_path: &str,
) -> wht_corulix_core::CorulixResult<(ChangeSession, WorkspaceIdentity, ConnectionId)> {
    let workspace_identity = WorkspaceIdentity::from_opaque_token(format!(
        "wsid-p16-ts-production-routing-{}",
        stamp()
    ))?;
    let connection_id =
        ConnectionId::from_opaque_token(format!("cid-p16-ts-production-routing-{}", stamp()))?;
    let session = engine
        .begin_change(
            OperationIntent::ValidateChange,
            Some(LanguageId::TypeScript),
            None,
            vec![target_relative_path.to_string()],
            workspace_identity.clone(),
            connection_id.clone(),
            0,
        )
        .await?;
    Ok((session, workspace_identity, connection_id))
}

const VALID_TS: &str = "export const answer: number = 42;\n";
const BROKEN_TS: &str = "export const answer: number = \"not a number\";\n";

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

/// `P16_PRODUCTION_TS_TYPECHECK_PASS_E2E`: a valid TypeScript file's required
/// `TypecheckBuild` really runs through `begin_change` -> `validate_change`,
/// records `gate.diagnostics` Evidence, and the session becomes
/// completion-eligible.
#[tokio::test]
async fn real_production_ts_typecheck_pass_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    require_ts_providers!(&managed_root);

    let fixture = Fixture::new("typecheck-pass");
    fixture.write("main.ts", VALID_TS);
    let engine = ts_engine(&fixture)?;
    let (mut session, workspace_identity, connection_id) =
        begin_ts_validate_session(&engine, "main.ts").await?;

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

    let ValidateChangeOutcome::TsExecuted {
        typecheck,
        typecheck_evidence_recorded,
        ..
    } = &outcome
    else {
        return Err(fail(format!(
            "expected a real TsExecuted outcome, got {outcome:?}"
        )));
    };
    if !typecheck.ran || !typecheck.clean {
        return Err(fail(format!(
            "expected a real, clean tsc --noEmit run, got {typecheck:?}"
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
    if record.evidence.provenance.provider_id != "wht_corulix_engine::ts_validation::run_typecheck"
    {
        return Err(fail(format!(
            "expected the real provider_id, got {:?}",
            record.evidence.provenance.provider_id
        )));
    }

    let status = session.change_status();
    if !status.completion_eligible {
        return Err(fail(format!(
            "expected completion_eligible after a clean tsc run, got {status:?}"
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

/// `P16_PRODUCTION_TS_TYPECHECK_FAILURE_E2E`: a real type error, run through
/// the same production path, records a real `Failed` `gate.diagnostics`
/// Evidence and `complete_change` is denied -- never a silent pass.
#[tokio::test]
async fn real_production_ts_typecheck_failure_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    require_ts_providers!(&managed_root);

    let fixture = Fixture::new("typecheck-fail");
    fixture.write("main.ts", BROKEN_TS);
    let engine = ts_engine(&fixture)?;
    let (mut session, workspace_identity, connection_id) =
        begin_ts_validate_session(&engine, "main.ts").await?;

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

    let ValidateChangeOutcome::TsExecuted { typecheck, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real TsExecuted outcome, got {outcome:?}"
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

/// `P16_PRODUCTION_TS_LINT_FOLDS_INTO_DIAGNOSTICS_E2E`: Biome lint's
/// `Linter`/`SupportingOnly` finding on an otherwise type-clean file makes
/// the *combined* `gate.diagnostics` record `Failed` -- proof that Biome's
/// finding genuinely reaches production Evidence via the real dispatch
/// path, and proof it can only ever strengthen the shared authoritative
/// record, never independently close or override it as a second Evidence
/// item.
#[tokio::test]
async fn real_production_ts_lint_folds_into_diagnostics_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    require_ts_providers!(&managed_root);

    let fixture = Fixture::new("lint-fail");
    // Type-clean, but `==` triggers Biome's built-in
    // `lint/suspicious/noDoubleEquals` rule (empirically confirmed this
    // pass against the real pinned `biome@2.5.11`).
    fixture.write(
        "main.ts",
        "export function check(x: number): boolean {\n  return x == 1;\n}\n",
    );
    let engine = ts_engine(&fixture)?;
    let (mut session, workspace_identity, connection_id) =
        begin_ts_validate_session(&engine, "main.ts").await?;

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

    let ValidateChangeOutcome::TsExecuted {
        typecheck, lint, ..
    } = &outcome
    else {
        return Err(fail(format!(
            "expected a real TsExecuted outcome, got {outcome:?}"
        )));
    };
    if !typecheck.clean {
        return Err(fail(format!(
            "this fixture is type-clean; tsc alone must report clean, got {typecheck:?}"
        )));
    }
    if !lint.ran || lint.clean || lint.finding_count == 0 {
        return Err(fail(format!(
            "expected a real, non-clean Biome lint run, got {lint:?}"
        )));
    }

    let Some(record) = diagnostics_record(&session) else {
        return Err(fail("expected a real gate.diagnostics Evidence record"));
    };
    if !matches!(record.status, GateStatus::Failed { .. }) {
        return Err(fail(format!(
            "expected the combined gate.diagnostics to be Failed once Biome's finding is folded in, got {:?}",
            record.status
        )));
    }
    // Biome never gets a *second, independent* gate.diagnostics Evidence
    // record for this validate_change call -- exactly one new record is
    // produced this call (`run_typecheck`'s own provider_id), carrying
    // Biome's finding folded in via `combined_clean`/`combined_summary`,
    // never a standalone Biome-authored record.
    if record.evidence.provenance.provider_id != "wht_corulix_engine::ts_validation::run_typecheck"
    {
        return Err(fail(format!(
            "expected the single combined record's provider_id to be run_typecheck's, got {:?}",
            record.evidence.provenance.provider_id
        )));
    }

    fixture.cleanup();
    Ok(())
}

/// `P16_PRODUCTION_TS_UNREQUIRED_TYPECHECK_IS_NEVER_EXECUTED`: Minimum
/// Sufficient Tooling -- an `OperationIntent` whose policy never names
/// `TypecheckBuild` as a requirement must report `NotRequired` with zero
/// processes spawned, never silently reusing another operation's authority.
#[tokio::test]
async fn real_production_ts_unrequired_typecheck_build_is_never_executed()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let fixture = Fixture::new("unrequired");
    fixture.write("README.md", "# fixture\n");
    let engine = ts_engine(&fixture)?;
    let workspace_identity =
        WorkspaceIdentity::from_opaque_token(format!("wsid-p16-ts-unrequired-{}", stamp()))?;
    let connection_id =
        ConnectionId::from_opaque_token(format!("cid-p16-ts-unrequired-{}", stamp()))?;
    let mut session = engine
        .begin_change(
            OperationIntent::DocumentationModify,
            Some(LanguageId::TypeScript),
            None,
            vec!["README.md".to_string()],
            workspace_identity.clone(),
            connection_id.clone(),
            0,
        )
        .await?;

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
            "expected NotRequired for a DocumentationModify session, got {outcome:?}"
        )));
    }

    fixture.cleanup();
    Ok(())
}

const NODE_TEST_SCRIPT_PACKAGE_JSON: &str = "{\"scripts\":{\"test\":\"node --test\"}}\n";

/// `P16_PRODUCTION_TS_TEST_RUNNER_PASS_E2E`: the real, discovered
/// `scripts.test` command (`node --test`, ADR 0010's own "fully offline,
/// zero-install" case) genuinely runs through `begin_change` ->
/// `validate_change`, records a real, passing `gate.tests` Evidence with
/// the real `provider_id`. Closes the gap this pass's own review found: the
/// three tests above call `validate_change_typescript`, which does invoke
/// `ts_testing::run_test` whenever `TestRunner` is a requirement, but none
/// of them gave the fixture a discoverable `package.json#scripts.test`, so
/// `run_test` always degraded to `PackageJsonUnreadable` there and its real
/// invocation path (managed-Node substitution, argv construction, exit-code
/// handling, `gate.tests` Evidence) had zero coverage -- precisely the
/// "implemented but zero production callers" defect class this phase's own
/// mandate calls out.
#[tokio::test]
async fn real_production_ts_test_runner_pass_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    require_ts_providers!(&managed_root);
    require_node_provider!(&managed_root);

    let fixture = Fixture::new("test-runner-pass");
    fixture.write("main.ts", VALID_TS);
    fixture.write("package.json", NODE_TEST_SCRIPT_PACKAGE_JSON);
    fixture.write(
        "main.test.js",
        "const test = require('node:test');\nconst assert = require('node:assert');\ntest('passes', () => { assert.strictEqual(1 + 1, 2); });\n",
    );
    let engine = ts_engine(&fixture)?;
    let (mut session, workspace_identity, connection_id) =
        begin_ts_validate_session(&engine, "main.ts").await?;

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

    let ValidateChangeOutcome::TsExecuted {
        test,
        test_evidence_recorded,
        ..
    } = &outcome
    else {
        return Err(fail(format!(
            "expected a real TsExecuted outcome, got {outcome:?}"
        )));
    };
    if !test.ran || !test.clean {
        return Err(fail(format!(
            "expected a real, passing node --test run, got {test:?}"
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
    if record.evidence.provenance.provider_id != "node --test" {
        return Err(fail(format!(
            "expected the real provider_id 'node --test', got {:?}",
            record.evidence.provenance.provider_id
        )));
    }

    fixture.cleanup();
    Ok(())
}

/// `P16_PRODUCTION_TS_TEST_RUNNER_FAILURE_E2E`: a real, deliberately failing
/// `node --test` assertion, run through the same production path, records a
/// real `Failed` `gate.tests` Evidence -- never a silent pass.
#[tokio::test]
async fn real_production_ts_test_runner_failure_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    require_ts_providers!(&managed_root);
    require_node_provider!(&managed_root);

    let fixture = Fixture::new("test-runner-fail");
    fixture.write("main.ts", VALID_TS);
    fixture.write("package.json", NODE_TEST_SCRIPT_PACKAGE_JSON);
    fixture.write(
        "main.test.js",
        "const test = require('node:test');\nconst assert = require('node:assert');\ntest('fails', () => { assert.strictEqual(1 + 1, 3, 'deliberate P16 production-routing-e2e failure'); });\n",
    );
    let engine = ts_engine(&fixture)?;
    let (mut session, workspace_identity, connection_id) =
        begin_ts_validate_session(&engine, "main.ts").await?;

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

    let ValidateChangeOutcome::TsExecuted { test, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real TsExecuted outcome, got {outcome:?}"
        )));
    };
    if test.clean {
        return Err(fail(
            "a deliberately failing node --test run must never report clean",
        ));
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

/// `P16_PRODUCTION_TS6_TYPECHECK_ROUTING_E2E`: a workspace declaring
/// TypeScript major 6 (`package.json#devDependencies.typescript: "^6"`)
/// genuinely routes through the managed-Node + `tsc.js` invocation this
/// pass's manifest fix (`package/lib/tsc.js` added to
/// `TYPESCRIPT_6_LINUX_X64`'s `required_paths`) exists to unblock -- not
/// merely that the manifest declares the path present. Asserts the real
/// Evidence's `provider_version` names the TS6 invocation path specifically,
/// proving `Some(6)` genuinely selects TS6 rather than silently falling
/// back to TS7-native.
#[tokio::test]
async fn real_production_ts6_typecheck_routing_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    require_ts6_provider!(&managed_root);
    require_node_provider!(&managed_root);

    let fixture = Fixture::new("ts6-typecheck-routing");
    fixture.write("main.ts", VALID_TS);
    fixture.write(
        "package.json",
        "{\"devDependencies\":{\"typescript\":\"^6.0.3\"}}\n",
    );
    let engine = ts_engine(&fixture)?;
    let (mut session, workspace_identity, connection_id) =
        begin_ts_validate_session(&engine, "main.ts").await?;

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

    let ValidateChangeOutcome::TsExecuted { typecheck, .. } = &outcome else {
        return Err(fail(format!(
            "expected a real TsExecuted outcome, got {outcome:?}"
        )));
    };
    if !typecheck.ran || !typecheck.clean {
        return Err(fail(format!(
            "expected a real, clean TS6 tsc.js --noEmit run, got {typecheck:?}"
        )));
    }

    let Some(record) = diagnostics_record(&session) else {
        return Err(fail("expected a real gate.diagnostics Evidence record"));
    };
    let provider_version = record
        .evidence
        .provenance
        .provider_version
        .as_deref()
        .unwrap_or_default();
    if !provider_version.contains("typescript-6-classic") {
        return Err(fail(format!(
            "expected the real TS6 invocation path's provider_version, got {provider_version:?}"
        )));
    }

    fixture.cleanup();
    Ok(())
}
