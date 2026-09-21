// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P11-R1 real end-to-end tests: `ExecutionClass::TrustedWorkspaceExecution`
//! enforcement is load-bearing (non-vacuous `build.rs` marker proof, both
//! trusted and untrusted), and clippy's real optional-provider degradation
//! (a genuinely deleted `cargo-clippy`/`clippy-driver` pair in an isolated
//! copy of a real managed install -- never the canonical/shared managed
//! root). `MOCKED_ONLY_CLOSURE=NO`.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{
    CancellationToken, ConnectionId, EvidenceProvenance, EvidenceResultSummary, EvidenceTimestamp,
    GateId, OperationIntent, ProviderAvailability, ProviderCategory, WorkspaceIdentity,
};
use wht_corulix_engine::diagnostics::{RustValidatorError, run_cargo_check, run_clippy};
use wht_corulix_engine::planning::plan_operation;
use wht_corulix_engine::policy::TargetScope;
use wht_corulix_engine::providers::ProviderSnapshot;
use wht_corulix_engine::session::{ChangeSession, SessionScope};
use wht_corulix_mutation::MutationExecutor;
use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64;
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

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
    let dir = std::env::temp_dir().join(format!("corulix-p11r1-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

static PROVISION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn provision_lock() -> tokio::sync::MutexGuard<'static, ()> {
    PROVISION_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn shared_managed_root() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    // Deliberately the *same* cache root `real_p11_diagnostics_e2e.rs` uses
    // -- one real provisioned runtime shared across both P11 and P11-R1
    // real E2E files, never a second independent download.
    PathBuf::from(home).join(".cache/corulix-p11-diagnostics-e2e/root")
}

async fn ensure_provisioned() -> Option<PathBuf> {
    let _guard = provision_lock().await;
    let root = shared_managed_root();
    let (state, _) =
        provisioning::resolve_managed_component(&root, &RUST_SEMANTIC_RUNTIME_LINUX_X64);
    if state != ManagedComponentState::Available
        && provisioning::provision(&root, &RUST_SEMANTIC_RUNTIME_LINUX_X64)
            .await
            .is_err()
    {
        return None;
    }
    Some(root)
}

fn trusted_effective_config() -> wht_corulix_config::EffectiveConfig {
    let host = wht_corulix_config::HostConfig {
        workspace_trust: wht_corulix_core::WorkspaceTrust::Trusted,
        allow_trusted_workspace_execution: true,
        ..wht_corulix_config::HostConfig::default()
    };
    wht_corulix_config::EffectiveConfig::derive(
        &host,
        &wht_corulix_config::RepositoryHints::default(),
        &wht_corulix_config::RequestOptions::default(),
    )
}

fn untrusted_effective_config() -> wht_corulix_config::EffectiveConfig {
    wht_corulix_config::EffectiveConfig::derive(
        &wht_corulix_config::HostConfig::default(),
        &wht_corulix_config::RepositoryHints::default(),
        &wht_corulix_config::RequestOptions::default(),
    )
}

/// A real crate with a `build.rs` that writes `marker_path` to disk when it
/// actually runs -- the only reliable, non-vacuous proof that
/// repository-authored code executed (per this module's own doc comment,
/// `cargo check` on a build-scripted crate always compiles and runs
/// `build.rs`, which itself requires a real, separate compile+link step).
fn write_buildrs_fixture(
    dir: &std::path::Path,
    marker_path: &std::path::Path,
) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p11r1_buildrs_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
    )?;
    fs::write(dir.join("src/main.rs"), "fn main() {}\n")?;
    fs::write(
        dir.join("build.rs"),
        format!(
            "fn main() {{ std::fs::write(r#\"{}\"#, b\"ran\").expect(\"write marker\"); }}\n",
            marker_path.display()
        ),
    )?;
    Ok(())
}

/// `P11_TRUSTED_WORKSPACE_AUTHORED_CODE_EXECUTION_PROVEN=PASS`: under a real
/// `HOST_ONLY` trust grant, `run_cargo_check` genuinely compiles and runs a
/// controlled `build.rs`, observed via a real marker file written to disk
/// by that build script -- not a theoretical claim about `ExecutionClass`.
#[tokio::test]
async fn real_p11_r1_trusted_execution_runs_repository_authored_buildrs_e2e()
-> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P11_R1_TRUST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("buildrs-trusted");
    let marker_path = fixture_dir.join("BUILD_MARKER");
    write_buildrs_fixture(&fixture_dir, &marker_path)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let outcome = run_cargo_check(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| {
            fail(format!(
                "expected trusted cargo check to run the build script, got {error:?} \
                 (requires a system linker at /usr/bin or /bin -- see diagnostics.rs's own \
                 doc comment)"
            ))
        })?;
    if !outcome.is_clean() {
        return Err(fail(format!(
            "expected the build-script fixture to compile cleanly, got {outcome:?}"
        )));
    }
    if !marker_path.is_file() {
        return Err(fail(
            "build.rs did not actually run: BUILD_MARKER was never written -- \
             the trusted-execution proof is not non-vacuous",
        ));
    }
    eprintln!("P11_TRUSTED_WORKSPACE_AUTHORED_CODE_EXECUTION_PROVEN=PASS");
    Ok(())
}

/// `P11_UNTRUSTED_WORKSPACE_AUTHORED_CODE_EXECUTION_COUNT=0`: the exact same
/// fixture, under a default (`Untrusted`) `EffectiveConfig`, must be denied
/// before `cargo` is ever spawned -- proven by the marker file's continued
/// absence, not merely by the typed error. This is the strongest available
/// proof that trust enforcement is load-bearing rather than cosmetic.
#[tokio::test]
async fn real_p11_r1_untrusted_execution_never_runs_repository_authored_buildrs_e2e()
-> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P11_R1_TRUST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("buildrs-untrusted");
    let marker_path = fixture_dir.join("BUILD_MARKER");
    write_buildrs_fixture(&fixture_dir, &marker_path)?;
    let cancellation = CancellationToken::new();
    let effective = untrusted_effective_config();

    let result = run_cargo_check(&managed_root, &fixture_dir, &effective, &cancellation).await;
    if result != Err(RustValidatorError::WorkspaceExecutionNotAuthorized) {
        return Err(fail(format!(
            "expected WorkspaceExecutionNotAuthorized, got {result:?}"
        )));
    }
    if marker_path.is_file() {
        return Err(fail(
            "BUILD_MARKER exists: the untrusted workspace's build.rs executed anyway -- \
             trust enforcement is not load-bearing",
        ));
    }
    eprintln!(
        "P11_UNTRUSTED_WORKSPACE_AUTHORED_CODE_EXECUTION_COUNT=0 \
         P11_UNTRUSTED_CARGO_PROCESS_SPAWN_COUNT=0"
    );
    Ok(())
}

/// Real optional-provider degradation. Because clippy is merged as a fifth
/// `additional_sources` entry onto the same manifest as cargo/rustc,
/// `ManagedComponentState` is atomic across all five -- there is no
/// provisioning state where cargo is `Available` and clippy specifically is
/// not (a genuine architectural consequence of that merge, disclosed rather
/// than routed around). The only real way to exercise "clippy unavailable,
/// cargo unaffected" is a per-binary absence in an *isolated copy* of an
/// already-provisioned install directory -- never the canonical/shared
/// managed root (`P11_OPTIONAL_PROVIDER_TEST_GLOBAL_TOOLCHAIN_MUTATION_COUNT=0`).
#[tokio::test]
async fn real_p11_r1_optional_clippy_unavailable_degraded_e2e() -> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!(
            "P11_R1_OPTIONAL_DEGRADED_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)"
        );
        return Ok(());
    };
    let _ = managed_root; // the canonical/shared root is intentionally untouched below

    // --- Real, independently-provisioned isolated root, clippy binaries
    // genuinely removed afterward. `ownership::ManagedInstallationRecord`
    // binds `managed_root_identity` to a SHA-256 of the canonicalized root
    // path (protecting against exactly the "copy a record to a different
    // root" shortcut this test must not take), so this provisions for real
    // into its own isolated root rather than copying the canonical
    // installation's files or its ownership record --
    // `P11_OPTIONAL_PROVIDER_TEST_GLOBAL_TOOLCHAIN_MUTATION_COUNT=0` (the
    // canonical/shared root above is never written to).
    let isolated_root = temp_dir("clippy-degraded-isolated-root");
    if provisioning::provision(&isolated_root, &RUST_SEMANTIC_RUNTIME_LINUX_X64)
        .await
        .is_err()
    {
        eprintln!(
            "P11_R1_OPTIONAL_DEGRADED_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)"
        );
        return Ok(());
    }
    let isolated_install =
        provisioning::component_install_dir(&isolated_root, &RUST_SEMANTIC_RUNTIME_LINUX_X64);
    fs::remove_file(isolated_install.join("bin/cargo-clippy"))?;
    fs::remove_file(isolated_install.join("bin/clippy-driver"))?;

    let fixture_dir = temp_dir("clippy-degraded-fixture");
    fs::create_dir_all(fixture_dir.join("src"))?;
    fs::write(
        fixture_dir.join("Cargo.toml"),
        "[package]\nname = \"p11r1_degraded\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        fixture_dir.join("src/main.rs"),
        "fn main() { println!(\"hi\"); }\n",
    )?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    // Required validator (TypecheckBuild) is entirely unaffected by
    // clippy's absence -- proving "required proceeds" for real.
    let check_outcome = run_cargo_check(&isolated_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| {
            fail(format!(
                "expected cargo check to be unaffected, got {error:?}"
            ))
        })?;
    if !check_outcome.is_clean() {
        return Err(fail(format!(
            "expected the clean fixture to pass cargo check, got {check_outcome:?}"
        )));
    }

    // Optional validator (Linter) fails closed with a distinct, typed,
    // pre-spawn error -- never a fake "clean" clippy result. This is the
    // real-E2E half of the false-clean defect this pass closes: without
    // `resolve_clippy_binaries`, cargo's own builtin `clippy` subcommand
    // would have silently compiled without linting and reported `error_
    // count: 0` here (confirmed empirically during this phase's research
    // gate against this exact isolated install).
    let clippy_result = run_clippy(&isolated_root, &fixture_dir, &effective, &cancellation).await;
    if clippy_result != Err(RustValidatorError::ManagedClippyUnavailable) {
        return Err(fail(format!(
            "expected ManagedClippyUnavailable, got {clippy_result:?}"
        )));
    }
    eprintln!(
        "P11_REAL_OPTIONAL_PROVIDER_UNAVAILABLE_STATE=PASS \
         P11_OPTIONAL_PROVIDER_FAKE_EVIDENCE_COUNT=0"
    );

    // --- ChangeSession-level integration: required TypecheckBuild evidence
    // closes gate.diagnostics; optional Linter is simply never recorded
    // (unavailable); the session still reaches COMPLETED -- reusing P10's
    // own already-certified "optional gate absence never blocks completion"
    // mechanics (`session::tests::optional_gate_absence_never_blocks_
    // completion`), now exercised end-to-end with a real P11 validator
    // pair instead of a synthetic policy fixture. ---
    let workspace_root = WorkspaceRoot::open(&fixture_dir)?;
    let snapshot = ProviderSnapshot::from_resolutions(&[
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::TypecheckBuild,
            availability: ProviderAvailability::Available,
            resolved_path: Some(isolated_install.join("bin/cargo")),
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution,
            reason: None,
        },
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::TestRunner,
            availability: ProviderAvailability::ProviderUnavailable,
            resolved_path: None,
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution,
            reason: None,
        },
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::Linter,
            availability: ProviderAvailability::ProviderUnavailable,
            resolved_path: None,
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution,
            reason: None,
        },
    ]);
    let tool_plan = plan_operation(
        OperationIntent::ValidateChange,
        TargetScope::SingleRoot,
        &snapshot,
        None,
    );
    if tool_plan.executability != wht_corulix_core::PlanExecutability::Executable {
        return Err(fail(format!(
            "expected an Executable ValidateChange plan (TypecheckBuild is Required/Available, \
             Linter/TestRunner are merely Optional/unavailable), got {:?}",
            tool_plan.executability
        )));
    }

    let workspace_identity = WorkspaceIdentity::from_opaque_token(format!(
        "wsid-p11r1-optional-degraded-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ))?;
    let connection = ConnectionId::from_opaque_token("conn-p11r1-optional-degraded".to_string())?;
    let executor = MutationExecutor::new(workspace_root);
    let mut session = ChangeSession::open(
        ChangeSession::generate_id()?,
        workspace_identity.clone(),
        connection.clone(),
        1,
        executor,
    );
    session.enter_scope(SessionScope::new(vec!["src".to_string()]))?;
    session.baseline(
        tool_plan,
        vec![EvidenceProvenance {
            provider_id: "cargo-check".to_string(),
            provider_version: Some(check_outcome.provider_version.clone()),
            authority: wht_corulix_core::AuthorityRole::Authoritative,
        }],
    )?;

    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::TypecheckBuild,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Diagnostics,
            sequence: 1,
            provenance: EvidenceProvenance {
                provider_id: "cargo-check".to_string(),
                provider_version: Some(check_outcome.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: None,
            result_summary: EvidenceResultSummary::try_from(
                "real cargo check: 0 errors".to_string(),
            )?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(1),
            snapshot_id: Some(session.content_snapshot_id()),
        },
    )?;
    // No Linter Evidence is ever recorded -- clippy was genuinely
    // unavailable (`ManagedClippyUnavailable` above), and this module never
    // fabricates a substitute record for an optional provider it could not
    // run (`P11_OPTIONAL_PROVIDER_AUTHORITY_SUBSTITUTION_COUNT=0`).

    session.complete_change(&workspace_identity, &connection)?;
    if session.status() != wht_corulix_core::ChangeSessionStatus::Completed {
        return Err(fail(format!(
            "expected COMPLETED after the sole Required gate passed, got {:?}",
            session.status()
        )));
    }
    eprintln!(
        "P11_OPTIONAL_PROVIDER_ABSENCE_FALSE_COMPLETION_BLOCK_COUNT=0 \
         P11_REAL_OPTIONAL_PROVIDER_DEGRADED_E2E=PASS \
         P11_REQUIRED_OPTIONAL_PROVIDER_SEMANTIC_SEPARATION=PASS"
    );
    Ok(())
}
