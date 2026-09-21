// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real, negative proof that `ChangeSession::format_and_apply` (Phase
//! 10-R2) never advances current-state identity when the governed format
//! write does not genuinely succeed and change bytes.
//!
//! Two real, non-mocked scenarios:
//!
//! 1. `real_p10r2_format_guard_failure_does_not_advance_state`: the
//!    formatter's own pre-invocation guard rejects a non-Rust target
//!    (`FormatterError::NotRustSource`) before any provider is ever
//!    resolved -- needs no real rustfmt at all, deterministic on every
//!    host. Proves `FORMAT_FAILURE_FALSE_STATE_ADVANCE_COUNT=0`.
//! 2. `real_p10r2_format_commit_failure_does_not_advance_state`: real
//!    rustfmt genuinely reformats a genuinely-unformatted fixture (`changed
//!    == true`), but the real `MutationExecutor` commit is driven, via
//!    that crate's own already-certified `test-support`-feature-gated
//!    `FailureInjectionPoint::AfterCommitAt(0)` (the exact mechanism
//!    Phase 10-R1's recovery-lock E2E already established as legitimate --
//!    see that file's own doc comment), into a genuine, real commit
//!    failure that recovers cleanly (`MutationError::CommitFailed`, not
//!    `RecoveryRequired` -- a deliberately different real scenario from
//!    R1's recovery-lock proof, not a duplicate of it). Proves
//!    `FORMAT_COMMIT_FAILURE_FALSE_STATE_ADVANCE_COUNT=0`.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{
    AuthorityRole, CancellationToken, ConnectionId, GateApplicability, GateId, GateRequirement,
    MutationKind, OperationIntent, PlanExecutability, ProviderCategory, RiskClass, ToolPlan,
    ToolRequirement, WorkspaceIdentity, WorkspacePath, WorkspaceRootId,
};
use wht_corulix_engine::session::{ChangeSession, SessionError, SessionScope};
use wht_corulix_formatter::FormatterError;
use wht_corulix_mutation::{FailureInjectionPoint, MutationError, MutationExecutor};
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

fn temp_fixture_workspace(label: &str, main_rs: &[u8]) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-p10r2-atomicity-neg-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(root.join("main.rs"), main_rs);
    let _ = fs::write(root.join("notes.txt"), b"not rust source\n");
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

fn format_only_test_plan() -> ToolPlan {
    ToolPlan {
        intent: OperationIntent::SourceModify,
        mutation_kind: Some(MutationKind::Modify),
        risk_class: Some(RiskClass::Elevated),
        requirements: vec![ToolRequirement {
            category: ProviderCategory::Formatter,
            applicability: wht_corulix_core::ToolApplicability::Required,
            authority: AuthorityRole::SupportingOnly,
        }],
        gates: vec![GateRequirement {
            gate: GateId::Format,
            applicability: GateApplicability::Required,
        }],
        executability: PlanExecutability::Executable,
    }
}

#[tokio::test]
async fn real_p10r2_format_guard_failure_does_not_advance_state() -> Result<(), Box<dyn Error>> {
    let fixture = temp_fixture_workspace("guard-failure", b"fn a() {}\n");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let workspace_identity =
        WorkspaceIdentity::from_opaque_token("wsid-p10r2-guard-failure".to_string())?;
    let connection = ConnectionId::from_opaque_token("conn-p10r2-guard-failure".to_string())?;
    let cancellation = CancellationToken::new();
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );

    let mut session = ChangeSession::open(
        ChangeSession::generate_id()?,
        workspace_identity.clone(),
        connection.clone(),
        1,
        MutationExecutor::new(workspace_root),
    );
    session.enter_scope(SessionScope::new(vec!["notes.txt".to_string()]))?;
    session.baseline(format_only_test_plan(), Vec::new())?;

    let snapshot_before = session.content_snapshot_id();
    let attempt = session
        .format_and_apply(
            &workspace_identity,
            &connection,
            &effective,
            WorkspacePath {
                root: WorkspaceRootId(0),
                relative_path: "notes.txt".to_string(),
            },
            wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
            &cancellation,
        )
        .await;
    match attempt {
        Err(SessionError::Formatter(FormatterError::UnsupportedLanguage { .. })) => {}
        other => {
            return Err(fail(format!(
                "expected Formatter(NotRustSource), got {other:?}"
            )));
        }
    }
    let snapshot_after = session.content_snapshot_id();
    if snapshot_after != snapshot_before {
        return Err(fail(format!(
            "FORMAT_FAILURE_FALSE_STATE_ADVANCE_COUNT!=0: snapshot moved {snapshot_before} -> {snapshot_after} despite a real pre-invocation guard failure"
        )));
    }
    eprintln!("P10R2_FORMAT_FAILURE_FALSE_STATE_ADVANCE_COUNT=0");

    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

#[tokio::test]
async fn real_p10r2_format_commit_failure_does_not_advance_state() -> Result<(), Box<dyn Error>> {
    if !real_rustfmt_path().is_some_and(|p| p.is_file()) {
        eprintln!(
            "P10R2_REAL_FORMAT_COMMIT_FAILURE_E2E=BLOCKED_TOOLCHAIN_ABSENT: no real rustfmt found on PATH (set CORULIX_TEST_RUSTFMT to override) in this environment"
        );
        return Ok(());
    }

    let fixture = temp_fixture_workspace("commit-failure", b"fn a(  ) { }\n");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let workspace_identity =
        WorkspaceIdentity::from_opaque_token("wsid-p10r2-commit-failure".to_string())?;
    let connection = ConnectionId::from_opaque_token("conn-p10r2-commit-failure".to_string())?;
    let cancellation = CancellationToken::new();
    let effective = host_only_effective_config();

    let rustfmt_resolution = wht_corulix_config::resolve_provider(
        &effective,
        &workspace_root,
        ProviderCategory::Formatter,
        "rustfmt",
    )
    .await;
    if rustfmt_resolution.availability != wht_corulix_core::ProviderAvailability::Available {
        return Err(fail(format!(
            "rustfmt did not resolve via the real Phase-6 provider resolver: {rustfmt_resolution:?}"
        )));
    }

    // Real `MutationExecutor`, driven -- via the same already-certified
    // `test-support` mechanism R1's recovery-lock E2E uses -- into a real
    // commit failure on this format write's own single-item batch
    // (`AfterCommitAt(0)`: the item genuinely commits, then this crate's
    // own real recovery undoes it cleanly -- `CommitFailed`, not
    // `RecoveryRequired`).
    let executor = MutationExecutor::with_failure_injection(
        workspace_root.clone(),
        FailureInjectionPoint::AfterCommitAt(0),
    );
    let mut session = ChangeSession::open(
        ChangeSession::generate_id()?,
        workspace_identity.clone(),
        connection.clone(),
        1,
        executor,
    );
    session.enter_scope(SessionScope::new(vec!["main.rs".to_string()]))?;
    session.baseline(format_only_test_plan(), Vec::new())?;

    let snapshot_before = session.content_snapshot_id();
    let attempt = session
        .format_and_apply(
            &workspace_identity,
            &connection,
            &effective,
            WorkspacePath {
                root: WorkspaceRootId(0),
                relative_path: "main.rs".to_string(),
            },
            wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
            &cancellation,
        )
        .await;
    match attempt {
        Err(SessionError::Formatter(FormatterError::Mutation(MutationError::CommitFailed {
            ..
        }))) => {}
        other => {
            return Err(fail(format!(
                "expected Formatter(Mutation(CommitFailed {{ .. }})), got {other:?}"
            )));
        }
    }
    let snapshot_after = session.content_snapshot_id();
    if snapshot_after != snapshot_before {
        return Err(fail(format!(
            "FORMAT_COMMIT_FAILURE_FALSE_STATE_ADVANCE_COUNT!=0: snapshot moved {snapshot_before} -> {snapshot_after} despite a real recovered commit failure"
        )));
    }
    // The real recovery cleanly undid the commit -- the executor must not
    // be locked (this is `CommitFailed`, not `RecoveryRequired`).
    if session.executor().is_locked() {
        return Err(fail(
            "expected a clean CommitFailed recovery to leave the executor unlocked",
        ));
    }
    eprintln!("P10R2_FORMAT_COMMIT_FAILURE_FALSE_STATE_ADVANCE_COUNT=0");

    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}
