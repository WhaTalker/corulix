// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P16 formatter-governance closure: real, end-to-end proof that Biome is
//! the governed TypeScript/JavaScript formatter authority inside a real
//! `ChangeSession` transaction --
//! `begin_change -> scope -> baseline -> submit_edit -> gate.format (real
//! Biome, real MutationExecutor transaction) -> complete_change` -- mirroring
//! `real_p15_gofmt_governance_e2e.rs`'s own certified shape exactly, one
//! language substitution at a time.
//!
//! Nothing here is mocked: the edit goes through the real mutation
//! transaction and the format step is the real
//! `wht_corulix_engine::session::ChangeSession::format_and_apply`, which
//! itself delegates to the already-certified
//! `wht_corulix_formatter::format_and_apply` -- this file invents no new
//! formatter invocation and no new mutation-write path.
//!
//! Provisions against the real, shared `managed_toolchain_root()`, same
//! convention as this phase's other real E2E suites. Requires real network
//! access to GitHub Releases the first time it runs; reports and exits
//! early with `P16_TS_JS_FORMAT_CHANGESESSION_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED`
//! otherwise, never substituting a mock.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{
    AuthorityRole, CancellationToken, ChangeSessionStatus, ConnectionId, ContentHash,
    EvidenceProvenance, EvidenceTimestamp, GateApplicability, GateId, GateStatus, LanguageId,
    OperationIntent, PlanExecutability, ProviderCategory, WorkspaceIdentity, WorkspacePath,
    WorkspaceRootId,
};
use wht_corulix_engine::policy::TargetScope;
use wht_corulix_engine::providers::ProviderSnapshot;
use wht_corulix_engine::session::{
    ChangeSession, EditRequestKind, SessionScope, single_file_batch,
};
use wht_corulix_mutation::MutationExecutor;
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

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

static REAL_P16_TS_JS_FORMAT_SESSION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_P16_TS_JS_FORMAT_SESSION_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

async fn ensure_biome_provisioned(root: &Path) -> bool {
    let manifest = wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

macro_rules! require_biome {
    ($root:expr) => {
        if !ensure_biome_provisioned($root).await {
            eprintln!(
                "P16_TS_JS_FORMAT_CHANGESESSION_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED"
            );
            return Ok(());
        }
    };
}

fn resolved_biome_path(root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let manifest = wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64;
    let (state, path) = provisioning::resolve_owned_managed_component(root, &manifest);
    if state != ManagedComponentState::Available {
        return Err(fail(
            "biome must be Available for this test to prove anything",
        ));
    }
    path.ok_or_else(|| fail("an Available biome component must carry a resolved path"))
}

fn biome_version(biome_executable: &Path) -> Result<String, Box<dyn Error>> {
    let output = Command::new(biome_executable).arg("--version").output()?;
    if !output.status.success() {
        return Err(fail("`biome --version` failed"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn canonical_biome_format(
    biome_executable: &Path,
    stdin_file_path: &str,
    source: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut child = Command::new(biome_executable)
        .arg("format")
        .arg(format!("--stdin-file-path={stdin_file_path}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| fail("no stdin on the oracle biome process"))?
        .write_all(source.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(fail(format!(
            "the oracle biome invocation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

/// A minimal envelope: the `CORULIX_MANAGED` Biome path never reads
/// `EffectiveConfig`, so this grants nothing.
fn empty_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

fn evidence_summary(text: &str) -> Result<wht_corulix_core::EvidenceResultSummary, Box<dyn Error>> {
    wht_corulix_core::EvidenceResultSummary::try_from(text.to_string())
        .map_err(|_| fail("evidence summary exceeded its bound"))
}

struct Fixture {
    root_dir: PathBuf,
    file_name: &'static str,
}

impl Fixture {
    fn new(label: &str, file_name: &'static str, contents: &str) -> Self {
        let root_dir = std::env::temp_dir().join(format!(
            "corulix-p16-ts-js-format-changesession-{label}-{}",
            stamp()
        ));
        let _ = fs::create_dir_all(root_dir.join("src"));
        let _ = fs::write(root_dir.join("src").join(file_name), contents);
        Self {
            root_dir,
            file_name,
        }
    }

    fn root(&self) -> Result<WorkspaceRoot, Box<dyn Error>> {
        Ok(WorkspaceRoot::open(&self.root_dir)?)
    }

    fn target(&self) -> WorkspacePath {
        WorkspacePath {
            root: WorkspaceRootId(0),
            relative_path: format!("src/{}", self.file_name),
        }
    }

    fn live_bytes(&self) -> Vec<u8> {
        fs::read(self.root_dir.join("src").join(self.file_name)).unwrap_or_default()
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.root_dir);
    }
}

/// One (language, file name, stdin extension, original, badly-formatted
/// replacement) case driven through a real `ChangeSession`.
struct Case {
    label: &'static str,
    language: LanguageId,
    file_name: &'static str,
    stdin_file_path: &'static str,
    original: &'static str,
    unformatted_edit: &'static str,
}

/// `P16_REAL_TS_FORMAT_CHANGESESSION_E2E` and
/// `P16_REAL_JS_FORMAT_CHANGESESSION_E2E`: the complete governed
/// TypeScript/JavaScript source-modify flow through the real `ChangeSession`
/// state machine, one language at a time.
#[tokio::test]
async fn real_ts_and_js_format_change_session_governance_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    require_biome!(&managed_root);
    let biome_executable = resolved_biome_path(&managed_root)?;
    let version = biome_version(&biome_executable)?;
    let effective = empty_config();

    let cases = [
        Case {
            label: "ts",
            language: LanguageId::TypeScript,
            file_name: "main.ts",
            stdin_file_path: "stdin.ts",
            original: "export const answer: number = 42;\n",
            unformatted_edit: "export   const answer:number=42\nconsole.log(answer)\n",
        },
        Case {
            label: "js",
            language: LanguageId::JavaScript,
            file_name: "main.js",
            stdin_file_path: "stdin.js",
            original: "const answer = 42;\n",
            unformatted_edit: "const   answer=42\nconsole.log(answer)\n",
        },
    ];

    for case in cases {
        let fixture = Fixture::new(case.label, case.file_name, case.original);
        let workspace_root = fixture.root()?;

        // --- The real, deterministic ToolPlan for a SOURCE_MODIFY against a
        // --- real Biome (CORULIX_MANAGED) resolution.
        let formatter_resolution = wht_corulix_config::resolve_provider(
            &effective,
            &workspace_root,
            ProviderCategory::Formatter,
            "biome",
        )
        .await;
        // Biome resolves via CORULIX_MANAGED (checked directly by
        // `wht_corulix_formatter::managed::resolve_formatter`, invisible to
        // `resolve_provider` itself), so the plan below is built against a
        // synthetic snapshot asserting Formatter availability rather than
        // against `resolve_provider`'s own (HOST_ONLY-only) resolution --
        // exactly mirroring how a real production caller's `ProviderSnapshot`
        // is populated from the engine's own managed-aware probe, not from
        // `resolve_provider` alone.
        let _ = formatter_resolution;
        let snapshot =
            ProviderSnapshot::from_resolutions(&[wht_corulix_config::ProviderResolution {
                category: ProviderCategory::Formatter,
                availability: wht_corulix_core::ProviderAvailability::Available,
                resolved_path: Some(biome_executable.clone()),
                provenance: None,
                execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
                reason: None,
            }])
            .with_language_server_resolutions(&[(
                case.language,
                wht_corulix_core::ProviderAvailability::ProviderUnavailable,
            )]);
        let tool_plan = wht_corulix_engine::planning::plan_operation(
            OperationIntent::SourceModify,
            TargetScope::SingleRoot,
            &snapshot,
            Some(case.language),
        );
        if tool_plan.executability != PlanExecutability::Executable {
            return Err(fail(format!(
                "[{}] a SOURCE_MODIFY with Biome available must be Executable, got {:?}",
                case.label, tool_plan.executability
            )));
        }
        if !tool_plan.gates.iter().any(|gate| {
            gate.gate == GateId::Format && gate.applicability == GateApplicability::Required
        }) {
            return Err(fail(format!(
                "[{}] gate.format must be Required for a source modify, got {:?}",
                case.label, tool_plan.gates
            )));
        }

        // --- OPENED -> SCOPED -> BASELINED ---
        let workspace_identity = WorkspaceIdentity::from_opaque_token(format!(
            "wsid-p16-{}-format-{}",
            case.label,
            stamp()
        ))?;
        let connection =
            ConnectionId::from_opaque_token(format!("conn-p16-{}-format", case.label))?;
        let executor = MutationExecutor::new(workspace_root.clone());
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
                provider_id: "biome".to_string(),
                provider_version: Some(version.clone()),
                authority: AuthorityRole::SupportingOnly,
            }],
        )?;

        // --- gate.edit: a real mutation transaction writing deliberately
        // --- badly-formatted source. ---
        session
            .submit_edit(
                &workspace_identity,
                &connection,
                single_file_batch(
                    format!("src/{}", case.file_name),
                    EditRequestKind::Replace {
                        expected_precondition_hash_hex: ContentHash::compute_sha256(
                            case.original.as_bytes(),
                        )
                        .digest_hex,
                        content: case.unformatted_edit.as_bytes().to_vec(),
                    },
                ),
                EvidenceTimestamp(2),
            )
            .await?;
        if fixture.live_bytes() != case.unformatted_edit.as_bytes() {
            return Err(fail(format!(
                "[{}] the real edit transaction did not land",
                case.label
            )));
        }

        // --- gate.format: the real Biome invocation, applied through the
        // --- session's own MutationExecutor transaction. ---
        let format_result = session
            .format_and_apply(
                &workspace_identity,
                &connection,
                &effective,
                fixture.target(),
                wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
                &CancellationToken::new(),
            )
            .await?;
        if format_result.status != wht_corulix_formatter::FormatStatus::Formatted {
            return Err(fail(format!(
                "[{}] expected a real applied format, got {:?} (reason {:?})",
                case.label, format_result.status, format_result.reason
            )));
        }
        if !format_result.provider_used_managed {
            return Err(fail(format!(
                "[{}] Biome must have resolved via CORULIX_MANAGED",
                case.label
            )));
        }

        // The live file now holds canonical Biome output -- compared against
        // the real tool invoked independently, not against Corulix's own
        // result.
        let canonical = canonical_biome_format(
            &biome_executable,
            case.stdin_file_path,
            case.unformatted_edit,
        )?;
        if fixture.live_bytes() != canonical {
            return Err(fail(format!(
                "[{}] the applied bytes are not real Biome's canonical output",
                case.label
            )));
        }

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
                    provider_id: "biome".to_string(),
                    provider_version: Some(version.clone()),
                    authority: AuthorityRole::SupportingOnly,
                },
                scope: vec!["src".to_string()],
                input_fingerprint: format_result.output_hash.clone(),
                result_summary: evidence_summary(&format!(
                    "biome applied canonical formatting to src/{}",
                    case.file_name
                ))?,
                reason: None,
                truncated: false,
                timestamp: EvidenceTimestamp(3),
                snapshot_id: Some(session.content_snapshot_id()),
            },
        )?;

        // --- EXIT EVALUATION -> COMPLETED ---
        session.complete_change(&workspace_identity, &connection)?;
        if session.status() != ChangeSessionStatus::Completed {
            return Err(fail(format!(
                "[{}] expected a completed session, got {:?}",
                case.label,
                session.status()
            )));
        }

        let format_evidence = session
            .evidence_history()
            .iter()
            .find(|record| record.evidence.gate == GateId::Format)
            .ok_or_else(|| {
                fail(format!(
                    "[{}] no gate.format Evidence was recorded",
                    case.label
                ))
            })?;
        if format_evidence.status != GateStatus::Passed {
            return Err(fail(format!(
                "[{}] gate.format Evidence must be Passed, got {:?}",
                case.label, format_evidence.status
            )));
        }
        if format_evidence
            .evidence
            .provenance
            .provider_version
            .as_deref()
            != Some(version.as_str())
        {
            return Err(fail(format!(
                "[{}] gate.format Evidence must carry the exact probed Biome identity",
                case.label
            )));
        }

        eprintln!(
            "P16_REAL_{}_FORMAT_CHANGESESSION_E2E=PASS provider={version}",
            case.label.to_uppercase()
        );
        fixture.cleanup();
    }

    Ok(())
}
