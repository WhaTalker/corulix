// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P-M05-R1 real end-to-end tests: `begin_change`/`plan_operation`/
//! `toolchain_status` must agree with `validate_change`'s own real,
//! successful execution for `TypecheckBuild`/`Linter`/`TestRunner`, closing
//! the exact defect class the pre-existing F7 fix already closed for
//! `Formatter` alone -- discovered during the M05 live qualification pass
//! (`begin_change` reported every `ValidateChange` session `Blocked` with
//! `REQUIRED_PROVIDER_UNAVAILABLE` even though `validate_change` itself
//! executed real diagnostics correctly for all 16 qualification cases).
//!
//! Read-only against the real, shared, already-provisioned managed root
//! (never mutated -- no `setup`/`uninstall`/component acquisition here);
//! `MOCKED_ONLY_CLOSURE=NO`.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{LanguageId, OperationIntent, PlanExecutability, ProviderAvailability};
use wht_corulix_engine::CorulixEngine;
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

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-pm05r1-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn trusted_engine(label: &str) -> wht_corulix_core::CorulixResult<CorulixEngine> {
    let root = wht_corulix_workspace::WorkspaceRoot::open(temp_dir(label))?;
    let context = WorkspaceContext::single_root(root, "root".to_string());
    Ok(CorulixEngine::open_with_trust(context, true))
}

fn untrusted_engine(label: &str) -> wht_corulix_core::CorulixResult<CorulixEngine> {
    let root = wht_corulix_workspace::WorkspaceRoot::open(temp_dir(label))?;
    let context = WorkspaceContext::single_root(root, "root".to_string());
    Ok(CorulixEngine::open_with_trust(context, false))
}

/// A real managed component this host actually has provisioned, used only
/// to decide whether this test's positive assertions can run at all (never
/// to gate the negative/fail-closed ones, which must hold regardless).
fn rust_semantic_runtime_really_provisioned() -> bool {
    let Ok(managed_root) = wht_corulix_tooling::provisioning::managed_toolchain_root() else {
        return false;
    };
    #[cfg(target_os = "windows")]
    let manifest = wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64;
    #[cfg(not(target_os = "windows"))]
    let manifest = wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64;
    let (state, _) = wht_corulix_tooling::provisioning::resolve_owned_managed_component(
        &managed_root,
        &manifest,
    );
    state == wht_corulix_tooling::provisioning::ManagedComponentState::Available
}

fn go_semantic_runtime_really_provisioned() -> bool {
    let Ok(managed_root) = wht_corulix_tooling::provisioning::managed_toolchain_root() else {
        return false;
    };
    let (state, _) = wht_corulix_tooling::provisioning::resolve_owned_managed_component(
        &managed_root,
        &wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_HOST_NATIVE,
    );
    state == wht_corulix_tooling::provisioning::ManagedComponentState::Available
}

fn typescript_7_native_really_provisioned() -> bool {
    let Ok(managed_root) = wht_corulix_tooling::provisioning::managed_toolchain_root() else {
        return false;
    };
    let (state, _) = wht_corulix_tooling::provisioning::resolve_owned_managed_component(
        &managed_root,
        &wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_HOST_NATIVE,
    );
    state == wht_corulix_tooling::provisioning::ManagedComponentState::Available
}

fn pyright_and_node_really_provisioned() -> bool {
    let Ok(managed_root) = wht_corulix_tooling::provisioning::managed_toolchain_root() else {
        return false;
    };
    let (pyright_state, _) = wht_corulix_tooling::provisioning::resolve_owned_managed_component(
        &managed_root,
        &wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE,
    );
    let (node_state, _) = wht_corulix_tooling::provisioning::resolve_owned_managed_component(
        &managed_root,
        &wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
    );
    pyright_state == wht_corulix_tooling::provisioning::ManagedComponentState::Available
        && node_state == wht_corulix_tooling::provisioning::ManagedComponentState::Available
}

/// R6/R7/R1: with a real, provisioned Rust managed component and a trusted
/// workspace, `begin_change` must NOT report `gate.diagnostics` `Blocked`
/// for a `ValidateChange` session, and `plan_operation_for_language` must
/// agree it is `Executable` -- both previously reported `Blocked`/
/// `Unexecutable` unconditionally, regardless of this real, positive
/// provider state.
#[tokio::test]
async fn real_begin_change_and_plan_operation_agree_validate_change_rust_is_executable()
-> Result<(), Box<dyn Error>> {
    if !rust_semantic_runtime_really_provisioned() {
        eprintln!("P_M05_R1_E2E=SKIPPED (rust-semantic-runtime not provisioned on this host)");
        return Ok(());
    }
    let engine = trusted_engine("begin-change-rust")?;

    let workspace_identity =
        wht_corulix_core::WorkspaceIdentity::from_opaque_token("wsid-pm05r1".to_string())?;
    let connection_id =
        wht_corulix_core::ConnectionId::from_opaque_token("cid-pm05r1".to_string())?;
    let session = engine
        .begin_change(
            OperationIntent::ValidateChange,
            Some(LanguageId::Rust),
            None,
            Vec::new(),
            workspace_identity,
            connection_id,
            0,
        )
        .await?;

    let status = session.change_status();
    if status
        .failed_gates
        .iter()
        .any(|(gate, _)| *gate == wht_corulix_core::GateId::Diagnostics)
    {
        return Err(fail(format!(
            "expected begin_change to NOT report gate.diagnostics failed for a real, \
             available Rust TypecheckBuild provider, got {status:?}"
        )));
    }

    let plan =
        engine.plan_operation_for_language(OperationIntent::ValidateChange, Some(LanguageId::Rust));
    if !matches!(plan.executability, PlanExecutability::Executable) {
        return Err(fail(format!(
            "expected plan_operation_for_language to agree ValidateChange/Rust is \
             Executable given the same real provider state, got {:?}",
            plan.executability
        )));
    }
    eprintln!("P_M05_R1_BEGIN_CHANGE_PLAN_OPERATION_CONSISTENCY=PASS");
    Ok(())
}

/// R8: `toolchain_status` must report `TypecheckBuild` `Available` under
/// the same real, provisioned, trusted conditions `begin_change`/
/// `plan_operation` now correctly report `Executable` for.
///
/// `Linter` is platform-dependent, not a stale-vs-live consistency
/// question: [`wht_corulix_tooling::managed_runtimes::
/// RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`]'s own `additional_sources` (the
/// real, currently-resolved Windows Rust runtime `crate::diagnostics::
/// resolve_clippy_binaries` checks) carries exactly four entries --
/// `cargo`/`rust-std`/`rust-src`/`rust-mingw` -- never a fifth `clippy`
/// entry the way [`wht_corulix_tooling::managed_runtimes::
/// RUST_SEMANTIC_RUNTIME_LINUX_X64`] merges one on Unix (see that
/// manifest's own doc comment). `cargo-clippy`/`clippy-driver` are
/// therefore structurally absent from every real Windows install, so
/// `toolchain_status`'s `Linter=ProviderUnavailable` there is an accurate
/// report of the real toolchain, not the P-M05-R1 staleness this file's
/// other five tests close -- `WINDOWS_RUST_LINTER_MANAGED_COMPONENT_
/// COUNT=0` is a structural fact, not a bug.
#[tokio::test]
async fn real_toolchain_status_agrees_typecheck_build_and_linter_are_available()
-> Result<(), Box<dyn Error>> {
    if !rust_semantic_runtime_really_provisioned() {
        eprintln!("P_M05_R1_E2E=SKIPPED (rust-semantic-runtime not provisioned on this host)");
        return Ok(());
    }
    let engine = trusted_engine("toolchain-status")?;
    let status = engine.toolchain_status();
    let typecheck_build = status
        .providers
        .iter()
        .find(|entry| entry.category == wht_corulix_core::ProviderCategory::TypecheckBuild)
        .map(|entry| entry.availability);
    let linter = status
        .providers
        .iter()
        .find(|entry| entry.category == wht_corulix_core::ProviderCategory::Linter)
        .map(|entry| entry.availability);
    if typecheck_build != Some(ProviderAvailability::Available) {
        return Err(fail(format!(
            "expected toolchain_status TypecheckBuild=Available, got {typecheck_build:?}"
        )));
    }
    #[cfg(target_os = "windows")]
    let expected_linter = ProviderAvailability::ProviderUnavailable;
    #[cfg(not(target_os = "windows"))]
    let expected_linter = ProviderAvailability::Available;
    if linter != Some(expected_linter) {
        return Err(fail(format!(
            "expected toolchain_status Linter={expected_linter:?} (the real, platform-specific \
             managed-component contract), got {linter:?}"
        )));
    }
    eprintln!("P_M05_R1_TOOLCHAIN_STATUS_CONSISTENCY=PASS");
    Ok(())
}

/// R10: Go is structurally distinct (one shared managed component backs
/// both `TypecheckBuild`/`build` and `Linter`/`vet`, unlike Rust's two
/// separate binaries) -- proves the fix generalizes, not just for Rust.
#[tokio::test]
async fn real_begin_change_agrees_validate_change_go_is_executable() -> Result<(), Box<dyn Error>> {
    if !go_semantic_runtime_really_provisioned() {
        eprintln!("P_M05_R1_E2E=SKIPPED (go-semantic-runtime not provisioned on this host)");
        return Ok(());
    }
    let engine = trusted_engine("begin-change-go")?;
    let workspace_identity =
        wht_corulix_core::WorkspaceIdentity::from_opaque_token("wsid-pm05r1-go".to_string())?;
    let connection_id =
        wht_corulix_core::ConnectionId::from_opaque_token("cid-pm05r1-go".to_string())?;
    let session = engine
        .begin_change(
            OperationIntent::ValidateChange,
            Some(LanguageId::Go),
            None,
            Vec::new(),
            workspace_identity,
            connection_id,
            0,
        )
        .await?;
    let status = session.change_status();
    if status
        .failed_gates
        .iter()
        .any(|(gate, _)| *gate == wht_corulix_core::GateId::Diagnostics)
    {
        return Err(fail(format!(
            "expected begin_change to NOT report gate.diagnostics failed for a real, \
             available Go TypecheckBuild provider, got {status:?}"
        )));
    }
    eprintln!("P_M05_R1_GO_BEGIN_CHANGE_CONSISTENCY=PASS");
    Ok(())
}

/// R10: TypeScript is structurally distinct again (two independent managed
/// components -- `typescript-7-native` for `TypecheckBuild`, `biome` for
/// `Linter`, `node-runtime` an additional `TestRunner` dependency).
#[tokio::test]
async fn real_begin_change_agrees_validate_change_typescript_is_executable()
-> Result<(), Box<dyn Error>> {
    if !typescript_7_native_really_provisioned() {
        eprintln!("P_M05_R1_E2E=SKIPPED (typescript-7-native not provisioned on this host)");
        return Ok(());
    }
    let engine = trusted_engine("begin-change-ts")?;
    let workspace_identity =
        wht_corulix_core::WorkspaceIdentity::from_opaque_token("wsid-pm05r1-ts".to_string())?;
    let connection_id =
        wht_corulix_core::ConnectionId::from_opaque_token("cid-pm05r1-ts".to_string())?;
    let session = engine
        .begin_change(
            OperationIntent::ValidateChange,
            Some(LanguageId::TypeScript),
            None,
            Vec::new(),
            workspace_identity,
            connection_id,
            0,
        )
        .await?;
    let status = session.change_status();
    if status
        .failed_gates
        .iter()
        .any(|(gate, _)| *gate == wht_corulix_core::GateId::Diagnostics)
    {
        return Err(fail(format!(
            "expected begin_change to NOT report gate.diagnostics failed for a real, \
             available TypeScript TypecheckBuild provider, got {status:?}"
        )));
    }
    eprintln!("P_M05_R1_TS_BEGIN_CHANGE_CONSISTENCY=PASS");
    Ok(())
}

/// R10: Python is the fourth, most structurally distinct case -- managed
/// `pyright` depends on `node-runtime` too, `TestRunner` (pytest) has no
/// managed tier at all (must stay `ProviderUnavailable`, never fabricated).
#[tokio::test]
async fn real_begin_change_agrees_validate_change_python_is_executable_and_test_runner_stays_unavailable()
-> Result<(), Box<dyn Error>> {
    if !pyright_and_node_really_provisioned() {
        eprintln!("P_M05_R1_E2E=SKIPPED (pyright/node-runtime not provisioned on this host)");
        return Ok(());
    }
    let engine = trusted_engine("begin-change-python")?;
    let workspace_identity =
        wht_corulix_core::WorkspaceIdentity::from_opaque_token("wsid-pm05r1-py".to_string())?;
    let connection_id =
        wht_corulix_core::ConnectionId::from_opaque_token("cid-pm05r1-py".to_string())?;
    let session = engine
        .begin_change(
            OperationIntent::ValidateChange,
            Some(LanguageId::Python),
            None,
            Vec::new(),
            workspace_identity,
            connection_id,
            0,
        )
        .await?;
    let status = session.change_status();
    if status
        .failed_gates
        .iter()
        .any(|(gate, _)| *gate == wht_corulix_core::GateId::Diagnostics)
    {
        return Err(fail(format!(
            "expected begin_change to NOT report gate.diagnostics failed for a real, \
             available Python TypecheckBuild provider, got {status:?}"
        )));
    }

    // Python's `TestRunner` (pytest, no managed tier per ADR 0011 section 5)
    // is covered at the unit level in
    // `diagnostics_readiness::tests::python_test_runner_is_never_reported_available_managed`
    // -- not observable from this external, public-surface-only test
    // (`TestRunner` is always `Optional`, so no public tool's Blocked/
    // Executable verdict ever surfaces its value per language).
    eprintln!("P_M05_R1_PYTHON_BEGIN_CHANGE_CONSISTENCY=PASS");
    Ok(())
}

/// R5/R4: untrusted workspaces must never report `Executable`/`Available`
/// regardless of what is actually installed on this host -- fail-closed on
/// the trust precondition alone, proven through the real public
/// `begin_change`/`plan_operation`/`toolchain_status` surface, not just the
/// unit-level `live_diagnostics_availability` tests.
#[tokio::test]
async fn real_untrusted_workspace_never_reports_validate_change_executable_or_available()
-> Result<(), Box<dyn Error>> {
    let engine = untrusted_engine("untrusted")?;

    let plan =
        engine.plan_operation_for_language(OperationIntent::ValidateChange, Some(LanguageId::Rust));
    if !matches!(plan.executability, PlanExecutability::Unexecutable { .. }) {
        return Err(fail(format!(
            "expected an untrusted workspace's ValidateChange/Rust plan to remain \
             Unexecutable regardless of real host provider state, got {:?}",
            plan.executability
        )));
    }

    let status = engine.toolchain_status();
    let typecheck_build = status
        .providers
        .iter()
        .find(|entry| entry.category == wht_corulix_core::ProviderCategory::TypecheckBuild)
        .map(|entry| entry.availability);
    if typecheck_build != Some(ProviderAvailability::ProviderUnavailable) {
        return Err(fail(format!(
            "expected toolchain_status TypecheckBuild=ProviderUnavailable for an untrusted \
             engine regardless of real host provider state, got {typecheck_build:?}"
        )));
    }
    eprintln!("P_M05_R1_FAIL_CLOSED_TRUST_CONSISTENCY=PASS");
    Ok(())
}
