// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real Evidence invalidation + revalidation-to-completion end-to-end proof
//! (Phase 10 §33-38, §61-62).
//!
//! Sequence, entirely against real providers (never mocked):
//!
//! 1. `submit_edit` (real `MutationExecutor` write) then a real
//!    `wht_corulix_formatter::format_and_apply` (rustfmt) -> `gate.format`
//!    Evidence recorded `Passed`.
//! 2. A SECOND real, governed `submit_edit` -> per this module's
//!    documented invalidation graph, the prior `gate.format` record must
//!    flip to `Stale` in place (never deleted) and the session must roll
//!    back to `GatePending(Format)`.
//! 3. `complete_change` while that Evidence is `Stale` -> must be
//!    `Err(RequiredGateEvidenceStale)`, never a false `Completed`
//!    (`COMPLETION_WHILE_EVIDENCE_STALE=DENIED`).
//! 4. A real re-run of the invalidated gate (`format_and_apply` again,
//!    against the real post-edit-2 bytes) -> fresh `Passed` Evidence.
//! 5. `complete_change` now succeeds -> `Completed`
//!    (`P10_REAL_REVALIDATION_TO_COMPLETION_E2E=PASS`).
//!
//! Uses `OperationIntent::SourceModify` rather than `SourceRefactor` (the
//! dogfood file's own intent): its real policy entry
//! (`wht_corulix_engine::policy::SOURCE_MODIFY`) needs only `Formatter`
//! availability, keeping this file focused on invalidation/revalidation
//! rather than re-proving the full multi-gate lifecycle the dogfood file
//! already covers.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{
    CancellationToken, ChangeSessionStatus, ConnectionId, ContentHash, EvidenceProvenance,
    EvidenceResultSummary, EvidenceTimestamp, GateId, LanguageId, OperationIntent,
    ProviderAvailability, ProviderCategory, WorkspaceIdentity, WorkspacePath, WorkspaceRootId,
};
use wht_corulix_engine::policy::TargetScope;
use wht_corulix_engine::providers::ProviderSnapshot;
use wht_corulix_engine::session::{ChangeSession, SessionScope};
use wht_corulix_mutation::{Mutation, MutationBatch, MutationExecutor};
use wht_corulix_workspace::WorkspaceRoot;

/// Test-only discovery of a real `rustfmt` binary. `CORULIX_TEST_RUSTFMT`
/// overrides discovery with an exact binary path. Never resolves to a
/// `~/.cargo/bin` rustup-proxy shim: Corulix's sandboxed process execution
/// strips the environment context that proxy needs to select a toolchain,
/// so resolving to it causes a spurious spawn failure -- this prefers the
/// active toolchain's real sysroot (`rustc --print sysroot`), then falls
/// back to scanning every installed toolchain's `bin/` directory
/// (`rustup show home`), and only then falls back to a plain `PATH`
/// search. Never embeds a specific developer's machine path.
fn real_rustfmt_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("CORULIX_TEST_RUSTFMT") {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("rustfmt{}", std::env::consts::EXE_SUFFIX);
    if let Ok(output) = std::process::Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        && output.status.success()
    {
        let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let candidate = PathBuf::from(sysroot).join("bin").join(&exe_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Ok(output) = std::process::Command::new("rustup")
        .arg("show")
        .arg("home")
        .output()
        && output.status.success()
    {
        let rustup_home = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let toolchains_dir = PathBuf::from(rustup_home).join("toolchains");
        if let Ok(entries) = std::fs::read_dir(&toolchains_dir) {
            for entry in entries.flatten() {
                let candidate = entry.path().join("bin").join(&exe_name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
        .map(|dir| dir.join(&exe_name))
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

fn temp_fixture_workspace(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-p10-invalidation-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_p10_invalidation_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    let _ = fs::write(root.join("src/lib.rs"), "pub fn a() {}\n");
    root
}

fn host_only_effective_config() -> EffectiveConfig {
    let host = HostConfig {
        provider_absolute_paths: vec![(
            ProviderCategory::Formatter,
            real_rustfmt_path().unwrap_or_default(),
        )],
        ..HostConfig::default()
    };
    EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

fn evidence_summary(text: &str) -> Result<EvidenceResultSummary, Box<dyn Error>> {
    Ok(EvidenceResultSummary::try_from(text.to_string())?)
}

// Phase 10-R2: no raw `wht_corulix_formatter::format_and_apply(...,
// session.executor(), ...)` call remains anywhere in this file --
// formatting goes exclusively through the one canonical, session-owned
// `ChangeSession::format_and_apply` boundary, which advances current-state
// identity itself. No `session.advance_content_state(...)` call appears
// anywhere in this file either (P10_R2_E2E_MANUAL_ADVANCE_CONTENT_STATE_CALL_COUNT=0).
async fn real_format(
    effective: &EffectiveConfig,
    session: &mut ChangeSession,
    workspace_identity: &WorkspaceIdentity,
    connection: &ConnectionId,
    cancellation: &CancellationToken,
) -> Result<wht_corulix_formatter::FormatterResult, Box<dyn Error>> {
    session
        .format_and_apply(
            workspace_identity,
            connection,
            effective,
            WorkspacePath {
                root: WorkspaceRootId(0),
                relative_path: "src/lib.rs".to_string(),
            },
            wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
            cancellation,
        )
        .await
        .map_err(|error| {
            fail(format!(
                "real ChangeSession::format_and_apply failed: {error}"
            ))
        })
}

#[tokio::test]
async fn real_p10_evidence_invalidation_then_revalidation_to_completion_e2e()
-> Result<(), Box<dyn Error>> {
    if !real_rustfmt_path().is_some_and(|p| p.is_file()) {
        eprintln!(
            "P10_REAL_EVIDENCE_INVALIDATION_E2E=BLOCKED_TOOLCHAIN_ABSENT: no real rustfmt found on PATH (set CORULIX_TEST_RUSTFMT to override) in this environment"
        );
        return Ok(());
    }

    let fixture = temp_fixture_workspace("invalidation");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let cancellation = CancellationToken::new();
    let effective = host_only_effective_config();

    let rustfmt_resolution = wht_corulix_config::resolve_provider(
        &effective,
        &workspace_root,
        ProviderCategory::Formatter,
        "rustfmt",
    )
    .await;
    if rustfmt_resolution.availability != ProviderAvailability::Available {
        return Err(fail(format!(
            "rustfmt did not resolve via the real Phase-6 provider resolver: {rustfmt_resolution:?}"
        )));
    }

    let snapshot = ProviderSnapshot::from_resolutions(&[wht_corulix_config::ProviderResolution {
        category: ProviderCategory::Formatter,
        availability: ProviderAvailability::Available,
        resolved_path: rustfmt_resolution.resolved_path,
        provenance: rustfmt_resolution.provenance,
        execution_class: rustfmt_resolution.execution_class,
        reason: None,
    }]);
    let tool_plan = wht_corulix_engine::planning::plan_operation(
        OperationIntent::SourceModify,
        TargetScope::SingleRoot,
        &snapshot,
        Some(LanguageId::Rust),
    );
    if tool_plan.executability != wht_corulix_core::PlanExecutability::Executable {
        return Err(fail(format!(
            "expected a real Executable SourceModify plan, got {:?}",
            tool_plan.executability
        )));
    }

    let workspace_identity = WorkspaceIdentity::from_opaque_token(format!(
        "wsid-p10-invalidation-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ))?;
    let connection = ConnectionId::from_opaque_token("conn-p10-invalidation".to_string())?;
    let mut session = ChangeSession::open(
        ChangeSession::generate_id()?,
        workspace_identity.clone(),
        connection.clone(),
        1,
        MutationExecutor::new(workspace_root.clone()),
    );
    session.enter_scope(SessionScope::new(vec!["src".to_string()]))?;
    session.baseline(
        tool_plan,
        vec![EvidenceProvenance {
            provider_id: "rustfmt".to_string(),
            provider_version: None,
            authority: wht_corulix_core::AuthorityRole::SupportingOnly,
        }],
    )?;
    if session.status() != ChangeSessionStatus::GatePending(GateId::Edit) {
        return Err(fail(format!(
            "expected GatePending(Edit) at baseline, got {:?}",
            session.status()
        )));
    }

    // --- edit #1: real MutationExecutor write, deliberately unformatted ---
    let original = fs::read(fixture.join("src/lib.rs"))?;
    let batch_1 = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: WorkspacePath {
                root: WorkspaceRootId(0),
                relative_path: "src/lib.rs".to_string(),
            },
            expected_precondition_hash: ContentHash::compute_sha256(&original),
            content: b"pub fn a(  ) { }\n".to_vec(),
        }],
    };
    session
        .submit_edit(
            &workspace_identity,
            &connection,
            batch_1,
            EvidenceTimestamp(2),
        )
        .await
        .map_err(|error| fail(format!("real submit_edit #1 failed: {error}")))?;

    // --- gate.format, first real pass -- `ChangeSession::format_and_apply`
    // (Phase 10-R2) is the one canonical, session-owned boundary: real
    // rustfmt + real MutationExecutor commit + current-state advance as
    // one inseparable operation. No manual `advance_content_state` call
    // here. ---
    let snapshot_after_edit_1 = session.content_snapshot_id();
    let format_1 = real_format(
        &effective,
        &mut session,
        &workspace_identity,
        &connection,
        &cancellation,
    )
    .await?;
    if format_1.status != wht_corulix_formatter::FormatStatus::Formatted || !format_1.changed {
        return Err(fail(format!(
            "expected real rustfmt to change genuinely unformatted bytes on pass 1, got {format_1:?}"
        )));
    }
    let snapshot_after_format_1 = session.content_snapshot_id();
    if snapshot_after_format_1 == snapshot_after_edit_1 {
        return Err(fail(
            "expected a real, changed format to advance current-state identity (B != C)",
        ));
    }
    eprintln!(
        "P10R1_REAL_POST_FORMAT_SNAPSHOT_E2E snapshot_after_edit={snapshot_after_edit_1} snapshot_after_format={snapshot_after_format_1} FORMATTER_ACTUALLY_CHANGED_BYTES=YES"
    );
    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::Formatter,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Format,
            sequence: 3,
            provenance: EvidenceProvenance {
                provider_id: "rustfmt".to_string(),
                provider_version: None,
                authority: wht_corulix_core::AuthorityRole::SupportingOnly,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: format_1.output_hash.clone(),
            result_summary: evidence_summary("real rustfmt pass 1")?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(3),
            snapshot_id: Some(snapshot_after_format_1),
        },
    )?;
    eprintln!("P10R1_FORMAT_EVIDENCE_CURRENT_CONTENT_BINDING=PASS");
    if session.status() != ChangeSessionStatus::ExitEvaluation {
        return Err(fail(format!(
            "expected ExitEvaluation after the real Format pass (Diagnostics is Optional), got {:?}",
            session.status()
        )));
    }
    eprintln!("P10_INVALIDATION_PRE_STATE=format_evidence_passed status=ExitEvaluation");

    // --- edit #2: a SECOND real, governed mutation ---
    let post_format_bytes = fs::read(fixture.join("src/lib.rs"))?;
    let batch_2 = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: WorkspacePath {
                root: WorkspaceRootId(0),
                relative_path: "src/lib.rs".to_string(),
            },
            expected_precondition_hash: ContentHash::compute_sha256(&post_format_bytes),
            content: b"pub fn a() {}\npub fn b(  ) { }\n".to_vec(),
        }],
    };
    session
        .submit_edit(
            &workspace_identity,
            &connection,
            batch_2,
            EvidenceTimestamp(4),
        )
        .await
        .map_err(|error| fail(format!("real submit_edit #2 failed: {error}")))?;

    // --- OLD_DEPENDENT_EVIDENCE_STATE must now be Stale, not silently
    // dropped -- full audit history is still present. ---
    let stale_format_record = session
        .evidence_history()
        .iter()
        .find(|record| record.evidence.gate == GateId::Format && record.evidence.sequence == 3)
        .ok_or_else(|| {
            fail("the original gate.format Evidence record must still be present in history")
        })?;
    if !matches!(
        stale_format_record.status,
        wht_corulix_core::GateStatus::Stale
    ) {
        return Err(fail(format!(
            "expected the pass-1 gate.format Evidence to be Stale after edit #2, got {:?}",
            stale_format_record.status
        )));
    }
    // The Stale record's own `snapshot_id` still names state B -- it was
    // never rewritten in place (`INVALIDATED_EVIDENCE_HISTORY_PRESERVED=
    // YES`) -- and it now genuinely differs from current-state identity
    // (state C, advanced for real by edit #2's own `submit_edit`).
    let snapshot_after_edit_2 = session.content_snapshot_id();
    if stale_format_record.evidence.snapshot_id != Some(snapshot_after_format_1) {
        return Err(fail(format!(
            "expected the Stale record to still carry its original snapshot_id {snapshot_after_format_1:?}, got {:?}",
            stale_format_record.evidence.snapshot_id
        )));
    }
    if snapshot_after_edit_2 == snapshot_after_format_1 {
        return Err(fail(
            "expected edit #2 to genuinely advance current-state identity past the stale record's own snapshot",
        ));
    }
    if session.status() != ChangeSessionStatus::GatePending(GateId::Format) {
        return Err(fail(format!(
            "expected the session to roll back to GatePending(Format), got {:?}",
            session.status()
        )));
    }
    eprintln!(
        "P10_REAL_EVIDENCE_INVALIDATION_E2E=PASS OLD_DEPENDENT_EVIDENCE_STATE=STALE INVALIDATED_EVIDENCE_HISTORY_PRESERVED=YES stale_snapshot={snapshot_after_format_1} current_snapshot={snapshot_after_edit_2}"
    );

    // --- WRONG_SNAPSHOT_EVIDENCE_ACCEPT_COUNT=0 : Evidence for the
    // CURRENTLY pending gate, otherwise entirely valid, but stamped with
    // state B's (now-stale) snapshot_id instead of current state C, must
    // be rejected outright -- this is the exact guard that makes
    // `MIXED_SNAPSHOT_COMPLETION_COUNT=0` structurally true: two gates can
    // never simultaneously hold Evidence for two different snapshot ids,
    // because `record_evidence` refuses to accept a non-current one in the
    // first place. ---
    let wrong_snapshot_attempt = session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::Formatter,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Format,
            sequence: 90,
            provenance: EvidenceProvenance {
                provider_id: "rustfmt".to_string(),
                provider_version: None,
                authority: wht_corulix_core::AuthorityRole::SupportingOnly,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: None,
            result_summary: evidence_summary("claims state B while current state is C")?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(90),
            snapshot_id: Some(snapshot_after_format_1),
        },
    );
    if wrong_snapshot_attempt
        != Err(wht_corulix_engine::session::SessionError::Denied(
            wht_corulix_core::ReasonCode::EvidenceWrongSnapshot,
        ))
    {
        return Err(fail(format!(
            "expected Denied(EvidenceWrongSnapshot) for stale-snapshot Evidence, got {wrong_snapshot_attempt:?}"
        )));
    }
    eprintln!("P10R1_WRONG_SNAPSHOT_EVIDENCE_ACCEPT_COUNT=0 MIXED_SNAPSHOT_COMPLETION_COUNT=0");

    // --- COMPLETION_WITH_STALE_FINGERPRINT=DENIED : Evidence for the
    // currently pending gate carrying pass-1's real `input_fingerprint`
    // (state B's real output hash) instead of the real current expected
    // fingerprint (state C's, i.e. `last_edit_output_hash` after edit #2)
    // must be rejected -- checked independently of `snapshot_id`. ---
    let stale_fingerprint_attempt = session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::Formatter,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Format,
            sequence: 91,
            provenance: EvidenceProvenance {
                provider_id: "rustfmt".to_string(),
                provider_version: None,
                authority: wht_corulix_core::AuthorityRole::SupportingOnly,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: format_1.output_hash.clone(),
            result_summary: evidence_summary("claims state B's real fingerprint on state C")?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(91),
            snapshot_id: None,
        },
    );
    if stale_fingerprint_attempt
        != Err(wht_corulix_engine::session::SessionError::Denied(
            wht_corulix_core::ReasonCode::EvidenceStaleInputFingerprint,
        ))
    {
        return Err(fail(format!(
            "expected Denied(EvidenceStaleInputFingerprint) for stale-fingerprint Evidence, got {stale_fingerprint_attempt:?}"
        )));
    }
    eprintln!("P10R1_COMPLETION_WITH_STALE_FINGERPRINT=DENIED");

    // --- COMPLETION_WITH_SNAPSHOT_A_ON_STATE_B=DENIED : completion itself,
    // while the only Format Evidence on record is the pass-1 (state B)
    // record now marked Stale, must be denied -- proven below by the
    // existing RequiredGateEvidenceStale check, which is reached only
    // because neither rejected attempt above ever got the stale/wrong
    // Evidence into history to begin with. ---
    // --- COMPLETION_WHILE_EVIDENCE_STALE=DENIED ---
    let denial = session.complete_change(&workspace_identity, &connection);
    if denial
        != Err(wht_corulix_engine::session::SessionError::Denied(
            wht_corulix_core::ReasonCode::RequiredGateEvidenceStale,
        ))
    {
        return Err(fail(format!(
            "expected complete_change to be denied with RequiredGateEvidenceStale while Format is Stale, got {denial:?}"
        )));
    }
    eprintln!("COMPLETION_WHILE_EVIDENCE_STALE=DENIED");

    // --- real revalidation: re-run the invalidated gate for real, again
    // through the one canonical `ChangeSession::format_and_apply`
    // boundary -- no manual state advance here either. ---
    let format_2 = real_format(
        &effective,
        &mut session,
        &workspace_identity,
        &connection,
        &cancellation,
    )
    .await?;
    if format_2.status != wht_corulix_formatter::FormatStatus::Formatted || !format_2.changed {
        return Err(fail(format!(
            "expected real rustfmt to change genuinely unformatted bytes on pass 2, got {format_2:?}"
        )));
    }
    let snapshot_after_format_2 = session.content_snapshot_id();
    if snapshot_after_format_2 == snapshot_after_edit_2 {
        return Err(fail(
            "expected the real revalidation format pass to advance current-state identity again",
        ));
    }
    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::Formatter,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Format,
            sequence: 92,
            provenance: EvidenceProvenance {
                provider_id: "rustfmt".to_string(),
                provider_version: None,
                authority: wht_corulix_core::AuthorityRole::SupportingOnly,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: format_2.output_hash.clone(),
            result_summary: evidence_summary("real rustfmt pass 2 (revalidation)")?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(92),
            snapshot_id: Some(snapshot_after_format_2),
        },
    )?;
    eprintln!(
        "P10R1_REAL_CURRENT_STATE_REVALIDATION_E2E=PASS revalidated_snapshot={snapshot_after_format_2}"
    );

    session.complete_change(&workspace_identity, &connection)?;
    if session.status() != ChangeSessionStatus::Completed {
        return Err(fail(format!(
            "expected Completed after real revalidation, got {:?}",
            session.status()
        )));
    }
    eprintln!("P10R1_COMPLETION_COHERENCE_CHECK=PASS COMPLETION_AFTER_CURRENT_REVALIDATION=PASS");
    let status = session.change_status();
    if !status.failed_gates.is_empty() || !status.stale_gates.is_empty() {
        return Err(fail(format!(
            "expected zero failed/stale gates at final completion, got {status:?}"
        )));
    }
    eprintln!("P10_REAL_REVALIDATION_TO_COMPLETION_E2E=PASS");

    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}
