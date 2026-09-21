// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P16 mandate §50-53 closure: four distinct full-governance E2Es -- one per
//! TS-family language (`TS7`, `TS6`, `Tsx`, `JavaScript`) -- each driven
//! exclusively through
//! `begin_change -> submit_edit -> validate_change -> change_status ->
//! complete_change`, never calling `wht_corulix_engine::ts_validation`
//! directly.
//!
//! `real_p16_typescript_production_routing_e2e.rs` already certifies that
//! `validate_change` genuinely dispatches to `ts_validation::run_typecheck`/
//! `run_lint`/`run_test` for TypeScript (and that `Some(6)` genuinely routes
//! to TS6), but every one of its tests calls `begin_change ->
//! validate_change` directly -- it never submits a real governed edit first,
//! and it never separately exercises `Tsx`/`JavaScript` as their own
//! language identity. This file closes that gap: each of the four cases
//! below performs a real `submit_edit` mutation transaction (the missing
//! step) before validating, and `Tsx`/`JavaScript` each get their own
//! dedicated case rather than being assumed to behave like `TypeScript`.
//!
//! `OperationIntent::SourceModify` is used throughout, not `ValidateChange`:
//! `ChangeSession::submit_edit` unconditionally calls
//! `advance_after_required_gate(GateId::Edit, Passed)`, which walks
//! `tool_plan.gates` looking for the next `Required` gate after `Edit`.
//! `policy::VALIDATE_CHANGE`'s own `gates` list does not contain `Edit` at
//! all (`mutation_kind: MutationKind::None` -- it was never designed to
//! accept a `submit_edit` call), so driving `submit_edit` through a
//! `ValidateChange`-intent session skips straight past the real
//! `Diagnostics` gate to `ExitEvaluation`, and the later `validate_change`
//! call is then rejected with `InvalidSessionTransition` (`current_pending_
//! or_blocked_gate()` no longer names `Diagnostics`) -- a real, empirically
//! confirmed defect in *this file's own first draft*, not a defect in
//! `ChangeSession` (every existing caller of `submit_edit` already uses a
//! mutation-shaped intent whose `gates` list genuinely contains `Edit`).
//! `policy::SOURCE_MODIFY` does contain `Edit` (Required) and `Format`
//! (Required) and `Diagnostics` (Optional), so this file drives the real,
//! complete walk that policy actually supports: `begin_change -> submit_edit
//! (gate.edit) -> format_and_apply (gate.format, real Biome -- reusing the
//! exact governance path `real_p16_ts_js_format_changesession_e2e.rs`
//! already certifies) -> validate_change (gate.diagnostics) -> change_status
//! -> complete_change`.
//!
//! Provisions against the real, shared `managed_toolchain_root()`, same
//! convention as this phase's other real E2E suites. Requires real network
//! access the first time it runs; reports and exits early with
//! `P16_FULL_GOVERNANCE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED`
//! otherwise, never substituting a mock.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{
    CancellationToken, ChangeSessionStatus, ConnectionId, ContentHash, GateId, GateStatus,
    LanguageId, OperationIntent, WorkspaceIdentity, WorkspacePath, WorkspaceRootId,
};
use wht_corulix_engine::CorulixEngine;
use wht_corulix_engine::session::{ChangeSession, EditRequestKind, single_file_batch};
use wht_corulix_engine::validate_change::ValidateChangeOutcome;
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceContext;

/// The `CORULIX_MANAGED` Biome path never reads `EffectiveConfig`, so this
/// grants nothing -- see `wht_corulix_formatter::managed::resolve_formatter`.
fn empty_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
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

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

static REAL_P16_FULL_GOVERNANCE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_P16_FULL_GOVERNANCE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

async fn ensure_provisioned(
    root: &std::path::Path,
    manifest: wht_corulix_tooling::provisioning::ManagedComponentManifest,
) -> bool {
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

struct Fixture {
    root_dir: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root_dir =
            std::env::temp_dir().join(format!("corulix-p16-full-governance-{label}-{}", stamp()));
        let _ = fs::create_dir_all(&root_dir);
        Self { root_dir }
    }

    fn write(&self, name: &str, contents: &str) {
        let _ = fs::write(self.root_dir.join(name), contents);
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.root_dir.join(name)).unwrap_or_default()
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

fn engine(fixture: &Fixture) -> wht_corulix_core::CorulixResult<CorulixEngine> {
    let root = fixture.workspace_root()?;
    let context = WorkspaceContext::single_root(root, "root".to_string());
    Ok(CorulixEngine::open_with_trust(context, true))
}

fn diagnostics_record(
    session: &ChangeSession,
) -> Option<&wht_corulix_engine::session::EvidenceRecord> {
    session
        .evidence_history()
        .iter()
        .filter(|record| record.evidence.gate == GateId::Diagnostics)
        .max_by_key(|record| record.evidence.sequence)
}

/// One full-governance case: a language, its target file name, the original
/// (baseline) content, and the replacement content a real `submit_edit`
/// writes before `validate_change` runs.
struct Case {
    label: &'static str,
    language: LanguageId,
    file_name: &'static str,
    original: &'static str,
    edited: &'static str,
}

fn resolved_biome(managed_root: &std::path::Path) -> Result<(PathBuf, String), Box<dyn Error>> {
    let manifest = wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64;
    let (state, path) = provisioning::resolve_owned_managed_component(managed_root, &manifest);
    if state != ManagedComponentState::Available {
        return Err(fail(
            "biome must be Available for this test to prove anything",
        ));
    }
    let executable = path.ok_or_else(|| fail("an Available biome must carry a resolved path"))?;
    let output = std::process::Command::new(&executable)
        .arg("--version")
        .output()?;
    if !output.status.success() {
        return Err(fail("`biome --version` failed"));
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok((executable, version))
}

macro_rules! run_case {
    ($case:expr, $managed_root:expr, $prep:expr) => {{
        let case: &Case = &$case;
        let managed_root: &std::path::Path = $managed_root;
        let (_biome_executable, biome_version) = resolved_biome(managed_root)?;
        let fixture = Fixture::new(case.label);
        $prep(&fixture);
        fixture.write(case.file_name, case.original);

        let eng = engine(&fixture)?;
        let workspace_identity = WorkspaceIdentity::from_opaque_token(format!(
            "wsid-p16-full-{}-{}",
            case.label,
            stamp()
        ))?;
        let connection_id =
            ConnectionId::from_opaque_token(format!("cid-p16-full-{}-{}", case.label, stamp()))?;

        // --- begin_change ---
        let mut session = eng
            .begin_change(
                OperationIntent::SourceModify,
                Some(case.language),
                None,
                vec![case.file_name.to_string()],
                workspace_identity.clone(),
                connection_id.clone(),
                0,
            )
            .await?;

        // --- submit_edit: a real governed mutation transaction, the exact
        // --- missing step relative to the pre-existing production-routing
        // --- suite. ---
        let precondition = ContentHash::compute_sha256(case.original.as_bytes());
        session
            .submit_edit(
                &workspace_identity,
                &connection_id,
                single_file_batch(
                    case.file_name.to_string(),
                    EditRequestKind::Replace {
                        expected_precondition_hash_hex: precondition.digest_hex,
                        content: case.edited.as_bytes().to_vec(),
                    },
                ),
                wht_corulix_core::EvidenceTimestamp(2),
            )
            .await?;
        if fixture.read(case.file_name) != case.edited.as_bytes() {
            return Err(fail(format!(
                "[{}] the real submit_edit transaction did not land",
                case.label
            )));
        }
        let edit_record = session
            .evidence_history()
            .iter()
            .filter(|record| record.evidence.gate == GateId::Edit)
            .max_by_key(|record| record.evidence.sequence)
            .ok_or_else(|| {
                fail(format!(
                    "[{}] no gate.edit Evidence was recorded",
                    case.label
                ))
            })?;
        if edit_record.status != GateStatus::Passed {
            return Err(fail(format!(
                "[{}] gate.edit Evidence must be Passed, got {:?}",
                case.label, edit_record.status
            )));
        }

        // --- gate.format: the real Biome invocation, applied through the
        // --- session's own MutationExecutor transaction. `SOURCE_MODIFY`
        // --- requires `Format`, so this step is not optional. ---
        let format_result = session
            .format_and_apply(
                &workspace_identity,
                &connection_id,
                &empty_config(),
                WorkspacePath {
                    root: WorkspaceRootId(0),
                    relative_path: case.file_name.to_string(),
                },
                wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
                &CancellationToken::new(),
            )
            .await?;
        if !matches!(
            format_result.status,
            wht_corulix_formatter::FormatStatus::Formatted
                | wht_corulix_formatter::FormatStatus::Unchanged
        ) {
            return Err(fail(format!(
                "[{}] expected a real Biome format outcome, got {:?} (reason {:?})",
                case.label, format_result.status, format_result.reason
            )));
        }
        session.record_evidence(
            &workspace_identity,
            &connection_id,
            wht_corulix_core::ProviderCategory::Formatter,
            wht_corulix_core::Evidence {
                session_id: session.id().clone(),
                workspace_identity: workspace_identity.clone(),
                gate: GateId::Format,
                sequence: session.evidence_history().len() as u64 + 1,
                provenance: wht_corulix_core::EvidenceProvenance {
                    provider_id: "biome".to_string(),
                    provider_version: Some(biome_version.clone()),
                    authority: wht_corulix_core::AuthorityRole::SupportingOnly,
                },
                scope: vec![case.file_name.to_string()],
                input_fingerprint: format_result.output_hash.clone(),
                result_summary: wht_corulix_core::EvidenceResultSummary::try_from(format!(
                    "biome applied canonical formatting to {}",
                    case.file_name
                ))
                .map_err(|_| fail("evidence summary exceeded its bound"))?,
                reason: None,
                truncated: false,
                timestamp: wht_corulix_core::EvidenceTimestamp(3),
                snapshot_id: Some(session.content_snapshot_id()),
            },
        )?;
        let format_record = session
            .evidence_history()
            .iter()
            .find(|record| record.evidence.gate == GateId::Format)
            .ok_or_else(|| {
                fail(format!(
                    "[{}] no gate.format Evidence was recorded",
                    case.label
                ))
            })?;
        if format_record.status != GateStatus::Passed {
            return Err(fail(format!(
                "[{}] gate.format Evidence must be Passed, got {:?}",
                case.label, format_record.status
            )));
        }

        // --- validate_change: the real production dispatch into
        // --- `ts_validation::run_typecheck`/`run_lint`. ---
        let sequence = session.evidence_history().len() as u64 + 1;
        let outcome = eng
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
                "[{}] expected a real TsExecuted outcome, got {outcome:?}",
                case.label
            )));
        };
        if !typecheck.ran {
            return Err(fail(format!(
                "[{}] expected a real tsc invocation to have run, got {typecheck:?}",
                case.label
            )));
        }
        if !typecheck.clean {
            return Err(fail(format!(
                "[{}] expected a clean tsc run for valid source, got {typecheck:?}",
                case.label
            )));
        }
        let Some(record) = diagnostics_record(&session) else {
            return Err(fail(format!(
                "[{}] expected a real gate.diagnostics Evidence record",
                case.label
            )));
        };
        if record.status != GateStatus::Passed {
            return Err(fail(format!(
                "[{}] expected gate.diagnostics Passed, got {:?}",
                case.label, record.status
            )));
        }

        // --- change_status ---
        let status = session.change_status();
        if !status.completion_eligible {
            return Err(fail(format!(
                "[{}] expected completion_eligible after a clean typecheck run, got {status:?}",
                case.label
            )));
        }

        // --- complete_change ---
        session
            .complete_change(&workspace_identity, &connection_id)
            .map_err(|error| {
                fail(format!(
                    "[{}] expected complete_change to succeed, got {error:?}",
                    case.label
                ))
            })?;
        if session.change_status().status != ChangeSessionStatus::Completed {
            return Err(fail(format!(
                "[{}] expected the session to be Completed",
                case.label
            )));
        }

        eprintln!(
            "P16_REAL_{}_FULL_GOVERNANCE_E2E=PASS",
            case.label.to_uppercase()
        );
        fixture.cleanup();
        Ok::<(), Box<dyn Error>>(())
    }};
}

const VALID_TS: &str = "export const answer: number = 42;\n";
const EDITED_TS: &str = "export const answer: number = 43;\n";
const VALID_TSX: &str = "export function App(): JSX.Element {\n  return <div>{1 + 1}</div>;\n}\n";
const EDITED_TSX: &str = "export function App(): JSX.Element {\n  return <div>{2 + 2}</div>;\n}\n";
const VALID_JS: &str = "const answer = 42;\nmodule.exports = { answer };\n";
const EDITED_JS: &str = "const answer = 43;\nmodule.exports = { answer };\n";

const STRICT_TSCONFIG: &str = "{\"compilerOptions\":{\"strict\":true,\"noEmit\":true}}\n";
const TSX_TSCONFIG: &str =
    "{\"compilerOptions\":{\"strict\":true,\"noEmit\":true,\"jsx\":\"react\"}}\n";
/// A minimal, self-contained *global* (non-module: no `import`/`export`, so
/// `tsc` treats it as an ambient script, not a module) `JSX`/`React`
/// declaration -- this fixture deliberately avoids depending on a real
/// `@types/react`/`react` npm install (no network, no `node_modules`) while
/// still exercising genuine `.tsx` JSX syntax through `tsc --noEmit`'s real
/// type checker. Classic (`jsx: "react"`) transform requires only that
/// `React.createElement` resolve as a value and `JSX.IntrinsicElements`
/// resolve as a type -- both satisfied globally, without a module import,
/// by an ambient ("global script") declaration file.
const TSX_GLOBALS_DTS: &str = "declare namespace JSX {\n  interface IntrinsicElements {\n    [elemName: string]: Record<string, unknown>;\n  }\n  interface Element {\n    readonly brand?: \"jsx-element\";\n  }\n}\ndeclare namespace React {\n  function createElement(...args: unknown[]): JSX.Element;\n}\n";
const JS_TSCONFIG: &str =
    "{\"compilerOptions\":{\"allowJs\":true,\"checkJs\":true,\"noEmit\":true}}\n";
const TS6_PACKAGE_JSON: &str = "{\"devDependencies\":{\"typescript\":\"^6.0.3\"}}\n";

/// `P16_REAL_TS7_FULL_GOVERNANCE_E2E`: a real TS7-native
/// `begin_change -> submit_edit -> validate_change -> change_status ->
/// complete_change` walk.
#[tokio::test]
async fn real_ts7_full_governance_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    let ts7_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64,
    )
    .await;
    let biome_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64,
    )
    .await;
    if !ts7_ok || !biome_ok {
        eprintln!(
            "P16_REAL_TS7_FULL_GOVERNANCE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (ts7={ts7_ok}, biome={biome_ok})"
        );
        return Ok(());
    }

    let case = Case {
        label: "ts7",
        language: LanguageId::TypeScript,
        file_name: "main.ts",
        original: VALID_TS,
        edited: EDITED_TS,
    };
    run_case!(case, &managed_root, |fixture: &Fixture| {
        fixture.write("tsconfig.json", STRICT_TSCONFIG);
    })
}

/// `P16_REAL_TS6_FULL_GOVERNANCE_E2E`: the identical walk, but with
/// `package.json#devDependencies.typescript: "^6.0.3"` declared, genuinely
/// routing through the managed-Node + TS6 `tsc.js` invocation.
#[tokio::test]
async fn real_ts6_full_governance_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    let ts6_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_LINUX_X64,
    )
    .await;
    let node_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64,
    )
    .await;
    let biome_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64,
    )
    .await;
    if !ts6_ok || !node_ok || !biome_ok {
        eprintln!(
            "P16_REAL_TS6_FULL_GOVERNANCE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (ts6={ts6_ok}, node={node_ok}, biome={biome_ok})"
        );
        return Ok(());
    }

    let case = Case {
        label: "ts6",
        language: LanguageId::TypeScript,
        file_name: "main.ts",
        original: VALID_TS,
        edited: EDITED_TS,
    };
    run_case!(case, &managed_root, |fixture: &Fixture| {
        fixture.write("tsconfig.json", STRICT_TSCONFIG);
        fixture.write("package.json", TS6_PACKAGE_JSON);
    })
}

/// `P16_REAL_TSX_FULL_GOVERNANCE_E2E`: the identical walk for a `.tsx`
/// target, proving TSX is exercised as its own language identity, not
/// silently treated as plain `.ts`.
#[tokio::test]
async fn real_tsx_full_governance_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    let ts7_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64,
    )
    .await;
    let biome_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64,
    )
    .await;
    if !ts7_ok || !biome_ok {
        eprintln!(
            "P16_REAL_TSX_FULL_GOVERNANCE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (ts7={ts7_ok}, biome={biome_ok})"
        );
        return Ok(());
    }

    let case = Case {
        label: "tsx",
        language: LanguageId::Tsx,
        file_name: "main.tsx",
        original: VALID_TSX,
        edited: EDITED_TSX,
    };
    run_case!(case, &managed_root, |fixture: &Fixture| {
        fixture.write("tsconfig.json", TSX_TSCONFIG);
        fixture.write("globals.d.ts", TSX_GLOBALS_DTS);
    })
}

/// `P16_REAL_JS_FULL_GOVERNANCE_E2E`: the identical walk for a `.js`
/// target (`allowJs`/`checkJs`, so `tsc --noEmit` genuinely type-checks it
/// rather than silently reporting a vacuous clean pass).
#[tokio::test]
async fn real_js_full_governance_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    let ts7_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64,
    )
    .await;
    let biome_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64,
    )
    .await;
    if !ts7_ok || !biome_ok {
        eprintln!(
            "P16_REAL_JS_FULL_GOVERNANCE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (ts7={ts7_ok}, biome={biome_ok})"
        );
        return Ok(());
    }

    let case = Case {
        label: "js",
        language: LanguageId::JavaScript,
        file_name: "main.js",
        original: VALID_JS,
        edited: EDITED_JS,
    };
    run_case!(case, &managed_root, |fixture: &Fixture| {
        fixture.write("tsconfig.json", JS_TSCONFIG);
    })
}
