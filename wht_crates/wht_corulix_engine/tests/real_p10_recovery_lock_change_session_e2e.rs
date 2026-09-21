// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real, end-to-end proof that a genuine `wht_corulix_mutation`
//! recovery-required lock is observed and enforced from `ChangeSession`'s
//! own real boundary (Phase 10-R1 §2/§6-8, `P10_REAL_RECOVERY_LOCK_
//! CHANGESESSION_E2E`).
//!
//! `wht_corulix_mutation::MutationExecutor` is real throughout: the batch
//! genuinely commits (real bytes really land on disk via a real `rename`),
//! and `recover()` genuinely runs its real undo/lock logic
//! (`self.locked.store(true, ...)`) -- `is_locked()` is never mocked. The
//! ONE engineered element is *which* internal branch `recover()` takes:
//! this test drives the executor via `wht_corulix_mutation`'s own
//! `FailureInjectionPoint::DuringRecovery`, the exact mechanism that crate
//! already uses to prove its own `recovery_failure_locks_further_writes`
//! unit test deterministically rather than via a flaky filesystem race.
//! That mechanism is reachable here only because `wht_corulix_mutation`
//! admits a `test-support` Cargo feature (off by default, enabled only by
//! this crate's own `[dev-dependencies]`) -- see both crates' `Cargo.toml`
//! and `wht_corulix_mutation::executor::FailureInjectionPoint`'s doc
//! comment for why this is a legitimate "internal seam for workspace
//! tests" rather than a new public production API
//! (`P10_RECOVERY_PUBLIC_TEST_SEAM_COUNT=0`,
//! `P10_RECOVERY_ENV_TRIGGER_COUNT=0`: no env var, no always-compiled `pub
//! fn ..._for_test`).
//!
//! A structurally real single-item batch (`ReplaceFile`) is enough:
//! `DuringRecovery` lets item 0 commit for real (bytes really change on
//! disk), then forces its own undo to fail, which is exactly the scenario
//! `wht_corulix_mutation::executor::recover` documents as locking the
//! executor and returning `MutationError::RecoveryRequired`.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{
    AuthorityRole, ChangeSessionStatus, ConnectionId, ContentHash, EvidenceProvenance,
    EvidenceResultSummary, EvidenceTimestamp, GateApplicability, GateId, GateRequirement,
    MutationKind, OperationIntent, PlanExecutability, ProviderCategory, RiskClass, ToolPlan,
    ToolRequirement, WorkspaceIdentity, WorkspacePath, WorkspaceRootId,
};
use wht_corulix_engine::session::{ChangeSession, SessionError, SessionScope};
use wht_corulix_mutation::{
    FailureInjectionPoint, Mutation, MutationBatch, MutationError, MutationExecutor,
};
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

fn temp_fixture_workspace(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-p10r1-recovery-lock-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(root.join("notes.txt"), b"original real content\n");
    root
}

/// A minimal, hand-built plan whose only required gates are `Discovery`
/// (closeable without touching the executor at all, via
/// `record_evidence`) and `Edit` (the one governed-write gate this test
/// actually exercises) -- this test's purpose is proving real
/// `MutationExecutor` recovery-lock behavior through `ChangeSession`, not
/// re-proving `ToolPlan` derivation (already covered by the dogfood E2E,
/// which drives the real `planning::plan_operation` pipeline instead).
fn recovery_lock_test_plan() -> ToolPlan {
    ToolPlan {
        intent: OperationIntent::SourceModify,
        mutation_kind: Some(MutationKind::Modify),
        risk_class: Some(RiskClass::Elevated),
        requirements: vec![ToolRequirement {
            category: ProviderCategory::TextSearch,
            applicability: wht_corulix_core::ToolApplicability::Required,
            authority: AuthorityRole::Authoritative,
        }],
        gates: vec![
            GateRequirement {
                gate: GateId::Discovery,
                applicability: GateApplicability::Required,
            },
            GateRequirement {
                gate: GateId::Edit,
                applicability: GateApplicability::Required,
            },
        ],
        executability: PlanExecutability::Executable,
    }
}

#[tokio::test]
async fn real_p10_recovery_lock_change_session_e2e() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_workspace("core");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let workspace_identity =
        WorkspaceIdentity::from_opaque_token("wsid-p10r1-recovery-lock".to_string())?;
    let connection = ConnectionId::from_opaque_token("conn-p10r1-recovery-lock".to_string())?;

    // A real `MutationExecutor` driven, via the real-only-reachable-from-
    // recovery `DuringRecovery` injection point, into genuinely failing to
    // undo its own real, already-committed first item -- `is_locked()`
    // below observes this crate's own real `AtomicBool`, never a mock.
    let executor = MutationExecutor::with_failure_injection(
        workspace_root.clone(),
        FailureInjectionPoint::DuringRecovery,
    );

    let mut session = ChangeSession::open(
        ChangeSession::generate_id()?,
        workspace_identity.clone(),
        connection.clone(),
        1,
        executor,
    );
    session.enter_scope(SessionScope::new(vec!["notes.txt".to_string()]))?;
    session.baseline(
        recovery_lock_test_plan(),
        vec![EvidenceProvenance {
            provider_id: "wht_corulix_search".to_string(),
            provider_version: None,
            authority: AuthorityRole::Authoritative,
        }],
    )?;

    // --- gate.discovery: closed without ever touching the executor, so
    // this session reaches the lock scenario with one required gate
    // already genuinely Passed -- proving the recovery lock overrides a
    // session that is NOT simply "everything missing" (Phase 10-R1 §36). ---
    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::TextSearch,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Discovery,
            sequence: 2,
            provenance: EvidenceProvenance {
                provider_id: "wht_corulix_search".to_string(),
                provider_version: None,
                authority: AuthorityRole::Authoritative,
            },
            scope: vec![String::new()],
            input_fingerprint: None,
            result_summary: EvidenceResultSummary::try_from(
                "real discovery evidence, recorded before the lock".to_string(),
            )?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(2),
            snapshot_id: None,
        },
    )?;
    if session.status() != ChangeSessionStatus::GatePending(GateId::Edit) {
        return Err(fail(format!(
            "expected GatePending(Edit) after real Discovery evidence, got {:?}",
            session.status()
        )));
    }

    // --- gate.edit: a real, valid MutationBatch. Its item genuinely
    // commits (real rename, real new bytes on disk) before the injected
    // recovery-undo failure locks the executor. ---
    let original_bytes = fs::read(fixture.join("notes.txt"))?;
    let precondition_hash = ContentHash::compute_sha256(&original_bytes);
    let batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: WorkspacePath {
                root: WorkspaceRootId(0),
                relative_path: "notes.txt".to_string(),
            },
            expected_precondition_hash: precondition_hash,
            content: b"real replacement content that really commits\n".to_vec(),
        }],
    };

    if session.executor().is_locked() {
        return Err(fail(
            "executor must not already be locked before the recovery-triggering submit_edit",
        ));
    }

    let first_attempt = session
        .submit_edit(
            &workspace_identity,
            &connection,
            batch,
            EvidenceTimestamp(3),
        )
        .await;
    let recovery_required = match first_attempt {
        Err(SessionError::Mutation(MutationError::RecoveryRequired { unrecovered_paths })) => {
            unrecovered_paths
        }
        other => {
            return Err(fail(format!(
                "expected SessionError::Mutation(MutationError::RecoveryRequired {{ .. }}), got {other:?}"
            )));
        }
    };
    eprintln!(
        "P10R1_RECOVERY_REQUIRED_STATE_CREATED=PASS RECOVERY_LOCK_DENIAL_REASON_CODE=MutationRecoveryRequired unrecovered_paths={recovery_required:?}"
    );

    if !session.executor().is_locked() {
        return Err(fail(
            "expected the real MutationExecutor::is_locked() to be true after a genuine recovery failure",
        ));
    }
    eprintln!("P10R1_MUTATION_EXECUTOR_IS_LOCKED=YES");

    // The batch's item DID really commit before the undo failure -- proves
    // this is a real "committed but undo failed" state, not a no-op.
    let on_disk = fs::read(fixture.join("notes.txt"))?;
    if on_disk != b"real replacement content that really commits\n" {
        return Err(fail(
            "expected the real committed bytes to remain on disk (recovery genuinely failed to undo them)",
        ));
    }

    // --- CHANGESESSION_SUBMIT_EDIT_WHILE_RECOVERY_LOCKED=DENIED : a
    // second, independently valid submit_edit attempt (correct scope,
    // correct connection, correct precondition hash) must still be denied
    // purely because of the lock -- RECOVERY_LOCK_OVERRIDES_MUTATION_
    // PRECONDITIONS=PASS, RECOVERY_LOCK_FALSE_WRITE_COUNT=0 (this call
    // never reaches `execute()` at all; `submit_edit` denies before
    // attempting any further write). ---
    let second_precondition_hash = ContentHash::compute_sha256(&on_disk);
    let second_batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: WorkspacePath {
                root: WorkspaceRootId(0),
                relative_path: "notes.txt".to_string(),
            },
            expected_precondition_hash: second_precondition_hash,
            content: b"a second, independently valid edit\n".to_vec(),
        }],
    };
    let second_attempt = session
        .submit_edit(
            &workspace_identity,
            &connection,
            second_batch,
            EvidenceTimestamp(4),
        )
        .await;
    if second_attempt
        != Err(SessionError::Denied(
            wht_corulix_core::ReasonCode::SessionMutationLocked,
        ))
    {
        return Err(fail(format!(
            "expected Denied(SessionMutationLocked) for a second submit_edit while locked, got {second_attempt:?}"
        )));
    }
    eprintln!("P10R1_CHANGESESSION_SUBMIT_EDIT_WHILE_RECOVERY_LOCKED=DENIED");
    let post_second_attempt_bytes = fs::read(fixture.join("notes.txt"))?;
    if post_second_attempt_bytes != on_disk {
        return Err(fail(
            "RECOVERY_LOCK_FALSE_WRITE_COUNT!=0: disk content changed after a submit_edit the lock should have denied outright",
        ));
    }

    // --- CHANGESESSION_COMPLETE_WHILE_RECOVERY_LOCKED=DENIED : proven with
    // Discovery genuinely Passed (recorded above) -- the lock denies
    // completion regardless of any otherwise-satisfied gate
    // (RECOVERY_LOCK_OVERRIDES_CURRENT_EVIDENCE=PASS). `Edit` itself can
    // never carry Passed evidence in this scenario by construction (the
    // very write that would produce it is what triggered the lock), so
    // this proves precedence for every gate that COULD have been current,
    // via the exact denial reason `complete_change` returns: `is_locked()`
    // is checked before the completion gate-walk in the production code
    // (`wht_corulix_engine::session::ChangeSession::complete_change`), so
    // the returned code is unconditionally `SessionMutationLocked`, never
    // `RequiredGateMissingEvidence` for a gate that is separately, also,
    // unmet. ---
    let completion = session.complete_change(&workspace_identity, &connection);
    if completion
        != Err(SessionError::Denied(
            wht_corulix_core::ReasonCode::SessionMutationLocked,
        ))
    {
        return Err(fail(format!(
            "expected Denied(SessionMutationLocked) for complete_change while locked, got {completion:?}"
        )));
    }
    eprintln!("P10R1_CHANGESESSION_COMPLETE_WHILE_RECOVERY_LOCKED=DENIED");
    if session.status() == ChangeSessionStatus::Completed {
        return Err(fail(
            "RECOVERY_LOCK_FALSE_COMPLETION_COUNT!=0: session reports Completed despite the lock",
        ));
    }

    // --- RECOVERY_UNLOCK_FLOW=OUT_OF_SCOPE_WITH_EVIDENCE : this crate
    // deliberately provides no automatic re-recovery/unlock path (see
    // `MutationExecutor`'s own doc comment: "this crate does not attempt
    // an automatic re-recovery" -- a caller must discard this executor and
    // construct a fresh one only after independently repairing the
    // workspace). There is no `unlock`/`clear_recovery` method on
    // `MutationExecutor` to call here -- its absence, not an omission in
    // this test, is what "out of scope" means. ---
    eprintln!("P10R1_RECOVERY_UNLOCK_FLOW=OUT_OF_SCOPE_WITH_EVIDENCE");

    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}
