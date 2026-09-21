// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15 §12/§13/§24/§25: real, end-to-end proof that `gofmt` is the governed
//! Go formatter authority.
//!
//! Everything here drives the real production path against the real `gofmt`
//! shipped with `go1.26.6` on this host:
//!
//! ```text
//! source bytes -> confined read + precondition hash
//!              -> wht_corulix_formatter::managed::resolve_formatter
//!                 (CORULIX_MANAGED go-semantic-runtime first -- M03
//!                 rename_preview managed auxiliary capability closure --
//!                 then wht_corulix_config::resolve_provider HOST_ONLY, Rule K)
//!              -> wht_corulix_tooling::ManagedProcess (stdin/stdout, Rule G)
//!              -> verified formatted bytes
//!              -> preview (never written)  OR  ChangeSession-authorized
//!                 wht_corulix_mutation::MutationExecutor transaction (Rule M)
//! ```
//!
//! `P15_GOFMT_LIVE_INPLACE_WRITE_COUNT=0` is guaranteed by construction, not
//! by cleanup: `gofmt` is invoked over stdin/stdout with **no positional
//! path and no flags at all** (see
//! `wht_corulix_formatter::profile::FormatterProfile::gofmt`), so gofmt's own
//! process is never given a filesystem path it could write to. The only
//! component with live-write authority anywhere in this flow is
//! `wht_corulix_mutation::MutationExecutor`, and the preview path never
//! constructs one.
//!
//! If no real `gofmt` is present, every test reports and exits early with
//! `P15_GOFMT_E2E=BLOCKED_PROVIDER_UNAVAILABLE` rather than substituting a
//! mock.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
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
use wht_corulix_workspace::WorkspaceRoot;

const REAL_GO_DIRECTORY: &str = "/usr/local/go/bin";

/// Deliberately badly formatted, but syntactically valid, Go. `gofmt` has a
/// single canonical answer for it.
const UNFORMATTED: &str = "package main\nfunc  main( ){\nx:=1\n_ = x\n}\n";

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

fn real_gofmt_available() -> bool {
    Path::new(REAL_GO_DIRECTORY).join("gofmt").is_file()
}

/// This platform's real `go-semantic-runtime` manifest -- mirrors
/// `wht_corulix_engine::go_providers`'s own `#[cfg]`-gated selector (not
/// reachable from this external test crate) so this test can independently
/// determine whether the *managed* tier is genuinely provisioned on this
/// host, without assuming either tier is or is not present.
#[cfg(target_os = "windows")]
fn go_semantic_runtime_manifest_for_this_platform()
-> wht_corulix_tooling::provisioning::ManagedComponentManifest {
    wht_corulix_tooling::managed_runtimes::GO_SEMANTIC_RUNTIME_WINDOWS_X64
}
#[cfg(not(target_os = "windows"))]
fn go_semantic_runtime_manifest_for_this_platform()
-> wht_corulix_tooling::provisioning::ManagedComponentManifest {
    wht_corulix_tooling::managed_runtimes::GO_SEMANTIC_RUNTIME_LINUX_X64
}

#[cfg(target_os = "windows")]
fn gofmt_executable_name() -> &'static str {
    "gofmt.exe"
}
#[cfg(not(target_os = "windows"))]
fn gofmt_executable_name() -> &'static str {
    "gofmt"
}

macro_rules! require_gofmt {
    () => {
        if !real_gofmt_available() {
            eprintln!(
                "P15_GOFMT_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real gofmt at {REAL_GO_DIRECTORY}"
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
    module: PathBuf,
    managed_root: PathBuf,
}

impl Fixture {
    fn new(label: &str, main_go: &str) -> Self {
        let base = std::env::temp_dir().join(format!("corulix-p15-gofmt-{label}-{}", stamp()));
        let module = base.join("module");
        let managed_root = base.join("managed");
        let _ = fs::create_dir_all(module.join("src"));
        let _ = fs::create_dir_all(&managed_root);
        let _ = fs::write(
            module.join("go.mod"),
            "module corulix_p15_gofmt_fixture\n\ngo 1.24\n",
        );
        let _ = fs::write(module.join("src/main.go"), main_go);
        Self {
            module,
            managed_root,
        }
    }

    fn root(&self) -> Result<WorkspaceRoot, Box<dyn Error>> {
        Ok(WorkspaceRoot::open(&self.module)?)
    }

    fn target(&self) -> WorkspacePath {
        WorkspacePath {
            root: WorkspaceRootId(0),
            relative_path: "src/main.go".to_string(),
        }
    }

    fn live_bytes(&self) -> Vec<u8> {
        fs::read(self.module.join("src/main.go")).unwrap_or_default()
    }

    fn cleanup(&self) {
        if let Some(base) = self.module.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }
}

/// A `HOST_ONLY` envelope granting `Formatter` authority for the real Go
/// toolchain directory. Nothing else is granted -- no trust, no other
/// category's absolute path.
fn gofmt_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig {
            approved_system_directories: vec![PathBuf::from(REAL_GO_DIRECTORY)],
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

/// What the real `gofmt` produces for [`UNFORMATTED`], obtained by invoking
/// the real binary directly.
///
/// This is a *test oracle*, deliberately independent of the production path:
/// asserting that Corulix's governed result equals whatever Corulix itself
/// produced would be circular. Comparing against the real tool invoked
/// separately is what makes "canonical gofmt output" a real claim.
fn canonical_gofmt_output(source: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(Path::new(REAL_GO_DIRECTORY).join("gofmt"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| fail("no stdin on the oracle gofmt process"))?
        .write_all(source.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(fail(format!(
            "the oracle gofmt invocation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

// ---------------------------------------------------------------------
// §13 -- gofmt preview
// ---------------------------------------------------------------------

/// `P15_REAL_GOFMT_PREVIEW_E2E` and `P15_GOFMT_LIVE_INPLACE_WRITE_COUNT=0`:
/// unformatted Go source previews as `WouldFormat`, the previewed output hash
/// equals the hash of the **real** `gofmt`'s canonical output, and the live
/// file is byte-identical afterwards.
#[tokio::test]
async fn real_gofmt_preview_e2e_reports_canonical_output_without_writing()
-> Result<(), Box<dyn Error>> {
    require_gofmt!();
    let fixture = Fixture::new("preview", UNFORMATTED);
    let before = fixture.live_bytes();

    let result = wht_corulix_formatter::format_preview_at(
        &fixture.managed_root,
        &gofmt_config(),
        fixture.root()?,
        fixture.target(),
        wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("gofmt preview failed: {error:?}")))?;

    if result.status != wht_corulix_formatter::FormatStatus::WouldFormat {
        return Err(fail(format!(
            "expected WouldFormat for badly formatted Go, got {:?} (reason {:?})",
            result.status, result.reason
        )));
    }
    if !result.changed {
        return Err(fail("WouldFormat must report changed == true"));
    }

    // The governed result really is canonical gofmt output, compared against
    // the real tool invoked independently.
    let canonical = canonical_gofmt_output(UNFORMATTED)?;
    let expected_hash = ContentHash::compute_sha256(&canonical);
    let Some(observed_hash) = result.output_hash.clone() else {
        return Err(fail("WouldFormat must carry an output hash"));
    };
    if observed_hash != expected_hash {
        return Err(fail(
            "the governed preview's output hash does not match real gofmt's canonical output",
        ));
    }

    // §29: the exact provider identity. gofmt has no `--version` flag, so the
    // identity is the Go toolchain that ships it.
    match result.provider_version.as_deref() {
        Some(version) if version.starts_with("go version go") => {}
        other => {
            return Err(fail(format!(
                "expected a real `go version` identity for gofmt, got {other:?}"
            )));
        }
    }
    if result.provider_used_managed {
        return Err(fail(
            "gofmt has no managed component; resolution must report HOST_ONLY",
        ));
    }

    // The whole point of a preview.
    if fixture.live_bytes() != before {
        return Err(fail(
            "format_preview mutated live source -- P15_GOFMT_LIVE_INPLACE_WRITE_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    Ok(())
}

/// `P15_GOFMT_IDEMPOTENCY`: formatting already-canonical Go reports
/// `Unchanged`, and a second pass over the first pass's output produces
/// byte-identical bytes.
#[tokio::test]
async fn real_gofmt_idempotency_e2e() -> Result<(), Box<dyn Error>> {
    require_gofmt!();
    let canonical = canonical_gofmt_output(UNFORMATTED)?;
    let canonical_text = String::from_utf8(canonical.clone())
        .map_err(|_| fail("gofmt produced non-UTF-8 output"))?;

    // Pass 1: already-canonical input must report Unchanged through the
    // governed path.
    let fixture = Fixture::new("idempotent", &canonical_text);
    let result = wht_corulix_formatter::format_preview_at(
        &fixture.managed_root,
        &gofmt_config(),
        fixture.root()?,
        fixture.target(),
        wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("gofmt preview failed: {error:?}")))?;

    if result.status != wht_corulix_formatter::FormatStatus::Unchanged {
        return Err(fail(format!(
            "already-canonical Go must report Unchanged, got {:?}",
            result.status
        )));
    }
    if result.changed {
        return Err(fail("Unchanged must report changed == false"));
    }

    // Pass 2, at the tool level: re-formatting the canonical output yields
    // exactly the same bytes.
    let second = canonical_gofmt_output(&canonical_text)?;
    if second != canonical {
        return Err(fail("gofmt is not idempotent on its own output"));
    }

    fixture.cleanup();
    Ok(())
}

/// A Go file whose content `gofmt` cannot parse must surface as a real,
/// typed invocation failure -- never as a silent "unchanged", and never with
/// gofmt's error text applied as if it were formatted source.
#[tokio::test]
async fn unparseable_go_source_fails_honestly_and_is_never_applied() -> Result<(), Box<dyn Error>> {
    require_gofmt!();
    // Real gofmt exits 2 here with `<standard input>:2:12: expected ')'...`.
    let fixture = Fixture::new("unparseable", "package main\nfunc main( {\n");
    let before = fixture.live_bytes();

    let result = wht_corulix_formatter::format_preview_at(
        &fixture.managed_root,
        &gofmt_config(),
        fixture.root()?,
        fixture.target(),
        wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("expected a typed Ok outcome, got {error:?}")))?;

    if result.status != wht_corulix_formatter::FormatStatus::InvocationFailed {
        return Err(fail(format!(
            "unparseable Go must report InvocationFailed, got {:?}",
            result.status
        )));
    }
    if result.changed {
        return Err(fail(
            "a failed invocation must never report changed == true",
        ));
    }
    if fixture.live_bytes() != before {
        return Err(fail("a failed invocation must never touch live source"));
    }

    fixture.cleanup();
    Ok(())
}

/// `P15_GO_REQUIRED_FORMATTER_MISSING_BLOCKS_COMPLETION` (§25), provider
/// half: with no approved directory granted, `gofmt` genuinely does not
/// resolve, and the formatter reports `ProviderUnavailable` -- never a
/// silent host fallback to an ambient `PATH` gofmt (which is definitely
/// present on this host).
#[tokio::test]
async fn gofmt_without_host_authority_is_provider_unavailable() -> Result<(), Box<dyn Error>> {
    require_gofmt!();
    let fixture = Fixture::new("no-authority", UNFORMATTED);
    let empty_authority = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );

    let result = wht_corulix_formatter::format_preview_at(
        &fixture.managed_root,
        &empty_authority,
        fixture.root()?,
        fixture.target(),
        wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("expected a typed Ok outcome, got {error:?}")))?;

    if result.status != wht_corulix_formatter::FormatStatus::ProviderUnavailable {
        return Err(fail(format!(
            "gofmt must be ProviderUnavailable with no host authority, got {:?} -- ambient PATH must carry no authority",
            result.status
        )));
    }
    fixture.cleanup();
    Ok(())
}

/// A file whose language cannot even be detected (P17 admitted a formatter
/// authority for every currently-existing `LanguageId` variant, including
/// Python -- so this test's own positive case moved to
/// `real_p17_python_production_routing_e2e.rs`'s own coverage; this test's
/// job is now the structurally distinct case of an unrecognized extension)
/// is refused before any process is spawned, and is never routed to another
/// language's formatter.
#[tokio::test]
async fn a_language_without_a_formatter_authority_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("unsupported-language", UNFORMATTED);
    let _ = fs::write(fixture.module.join("src/notes.txt"), "not a source file\n");
    let target = WorkspacePath {
        root: WorkspaceRootId(0),
        relative_path: "src/notes.txt".to_string(),
    };

    let outcome = wht_corulix_formatter::format_preview_at(
        &fixture.managed_root,
        &gofmt_config(),
        fixture.root()?,
        target,
        wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await;

    match outcome {
        Err(wht_corulix_formatter::FormatterError::UnsupportedLanguage {
            language: None, ..
        }) => {}
        other => {
            return Err(fail(format!(
                "an undetectable-language file must be refused as having no admitted formatter authority, got {other:?}"
            )));
        }
    }
    fixture.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------
// §13/§24 -- gofmt inside a real ChangeSession transaction
// ---------------------------------------------------------------------

fn evidence_summary(text: &str) -> Result<wht_corulix_core::EvidenceResultSummary, Box<dyn Error>> {
    wht_corulix_core::EvidenceResultSummary::try_from(text.to_string())
        .map_err(|_| fail("evidence summary exceeded its bound"))
}

/// `P15_REAL_GOFMT_CHANGESESSION_E2E` and `P15_GO_TOOLPLAN_DETERMINISTIC`:
/// the complete governed Go source-modify flow through the real
/// `ChangeSession` state machine --
/// `begin_change -> scope -> baseline -> submit_edit -> gate.format (real
/// gofmt, real MutationExecutor transaction) -> complete_change` -- with real
/// Evidence at every required gate.
///
/// Nothing here is mocked: the `ToolPlan` comes from the real, deterministic
/// `plan_operation` against a real `gofmt` resolution, the edit goes through
/// the real mutation transaction, and the format step is the real
/// `wht_corulix_formatter::format_and_apply`.
#[tokio::test]
async fn real_gofmt_change_session_governance_e2e() -> Result<(), Box<dyn Error>> {
    require_gofmt!();
    let fixture = Fixture::new("change-session", "package main\n\nfunc main() {}\n");
    let workspace_root = fixture.root()?;
    let effective = gofmt_config();

    // --- The real, deterministic ToolPlan for a Go SOURCE_MODIFY, against a
    // --- real gofmt resolution. `SOURCE_MODIFY` requires `Formatter`
    // --- (Required/SupportingOnly), so the plan is only Executable when
    // --- gofmt genuinely resolved.
    let formatter_resolution = wht_corulix_config::resolve_provider(
        &effective,
        &workspace_root,
        ProviderCategory::Formatter,
        "gofmt",
    )
    .await;
    if formatter_resolution.availability != wht_corulix_core::ProviderAvailability::Available {
        return Err(fail(format!(
            "gofmt must resolve for this test to prove anything: {formatter_resolution:?}"
        )));
    }
    let gofmt_path = formatter_resolution
        .resolved_path
        .clone()
        .ok_or_else(|| fail("an available resolution must carry a path"))?;

    let snapshot = ProviderSnapshot::from_resolutions(&[formatter_resolution])
        .with_language_server_resolutions(&[(
            LanguageId::Go,
            wht_corulix_core::ProviderAvailability::ProviderUnavailable,
        )]);
    let tool_plan = wht_corulix_engine::planning::plan_operation(
        OperationIntent::SourceModify,
        TargetScope::SingleRoot,
        &snapshot,
        Some(LanguageId::Go),
    );
    if tool_plan.executability != PlanExecutability::Executable {
        return Err(fail(format!(
            "a Go SOURCE_MODIFY with gofmt available must be Executable, got {:?}",
            tool_plan.executability
        )));
    }
    // Determinism: the identical inputs produce a by-value-equal plan.
    let again = wht_corulix_engine::planning::plan_operation(
        OperationIntent::SourceModify,
        TargetScope::SingleRoot,
        &snapshot,
        Some(LanguageId::Go),
    );
    if again != tool_plan {
        return Err(fail("the Go ToolPlan is not deterministic"));
    }
    // gate.format must be Required for a Go source modification (§25).
    if !tool_plan.gates.iter().any(|gate| {
        gate.gate == GateId::Format && gate.applicability == GateApplicability::Required
    }) {
        return Err(fail(format!(
            "gate.format must be Required for a Go source modify, got {:?}",
            tool_plan.gates
        )));
    }

    // --- OPENED -> SCOPED -> BASELINED ---
    let workspace_identity =
        WorkspaceIdentity::from_opaque_token(format!("wsid-p15-gofmt-{}", stamp()))?;
    let connection = ConnectionId::from_opaque_token("conn-p15-gofmt".to_string())?;
    let executor = MutationExecutor::new(workspace_root.clone());
    let mut session = ChangeSession::open(
        ChangeSession::generate_id()?,
        workspace_identity.clone(),
        connection.clone(),
        1,
        executor,
    );
    session.enter_scope(SessionScope::new(vec!["src".to_string()]))?;

    // The real, probed gofmt provider identity recorded in the session's own
    // provider snapshot -- §29, never "system go".
    let go_version = go_version_identity()?;
    session.baseline(
        tool_plan,
        vec![EvidenceProvenance {
            provider_id: "gofmt".to_string(),
            provider_version: Some(go_version.clone()),
            authority: AuthorityRole::SupportingOnly,
        }],
    )?;

    // --- gate.edit: a real mutation transaction writing deliberately
    // --- badly-formatted Go, so the format gate has real work to do. ---
    let unformatted_edit = "package main\nfunc  main( ){\nx:=1\n_ = x\n}\n";
    session
        .submit_edit(
            &workspace_identity,
            &connection,
            single_file_batch(
                "src/main.go".to_string(),
                EditRequestKind::Replace {
                    expected_precondition_hash_hex: ContentHash::compute_sha256(
                        b"package main\n\nfunc main() {}\n",
                    )
                    .digest_hex,
                    content: unformatted_edit.as_bytes().to_vec(),
                },
            ),
            EvidenceTimestamp(2),
        )
        .await?;
    if fixture.live_bytes() != unformatted_edit.as_bytes() {
        return Err(fail("the real edit transaction did not land"));
    }

    // --- gate.format: the real gofmt invocation, applied through the
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
            "expected a real applied format, got {:?} (reason {:?})",
            format_result.status, format_result.reason
        )));
    }
    // `session.format_and_apply` goes through the real production
    // `wht_corulix_formatter::format_and_apply` -- managed-first (M03
    // rename_preview managed auxiliary capability closure), against the
    // *shared, host-wide* `managed_toolchain_root()`, not this fixture's own
    // isolated `managed_root` (which only the direct semantic/LSP calls
    // elsewhere in this file use). `gofmt_path` above came from a raw
    // `HOST_ONLY`-only `resolve_provider` call used solely to prove the
    // policy/plan layer (`ProviderCategory::Formatter` never resolves
    // managed-first at that layer); it is no longer guaranteed to equal
    // what the real invocation resolves once a managed go-semantic-runtime
    // is genuinely provisioned on this host, so the expected path here is
    // computed the same way: managed-first if available, `HOST_ONLY`
    // otherwise -- never a hardcoded assumption of either tier.
    let real_managed_root = wht_corulix_tooling::provisioning::managed_toolchain_root()
        .map_err(|_| fail("managed_toolchain_root must be resolvable on this host"))?;
    let go_runtime_manifest = go_semantic_runtime_manifest_for_this_platform();
    let (runtime_state, runtime_go_executable) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component(
            &real_managed_root,
            &go_runtime_manifest,
        );
    let expected_gofmt_path = if runtime_state
        == wht_corulix_tooling::provisioning::ManagedComponentState::Available
        && let Some(go_executable) = runtime_go_executable
    {
        go_executable.with_file_name(gofmt_executable_name())
    } else {
        gofmt_path.clone()
    };
    if format_result.provider_path.as_deref() != Some(expected_gofmt_path.as_path()) {
        return Err(fail(format!(
            "the session must have used the resolved gofmt (managed-first if provisioned, \
             else the approved HOST_ONLY one), expected {expected_gofmt_path:?}, got {:?}",
            format_result.provider_path
        )));
    }

    // The live file now holds canonical gofmt output -- compared against the
    // real tool invoked independently, not against Corulix's own result.
    let canonical = canonical_gofmt_output(unformatted_edit)?;
    if fixture.live_bytes() != canonical {
        return Err(fail(
            "the applied bytes are not real gofmt's canonical output",
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
            sequence: 3,
            provenance: EvidenceProvenance {
                provider_id: "gofmt".to_string(),
                provider_version: Some(go_version.clone()),
                authority: AuthorityRole::SupportingOnly,
            },
            scope: vec!["src".to_string()],
            // The content-dependent gate's fingerprint must name the content
            // the Evidence actually describes -- i.e. the bytes that now
            // exist after gofmt's own write, not the pre-format input. The
            // session enforces exactly that (`EvidenceStaleInputFingerprint`),
            // which is what keeps Evidence from outliving the content it was
            // observed against.
            input_fingerprint: format_result.output_hash.clone(),
            result_summary: evidence_summary("gofmt applied canonical formatting to src/main.go")?,
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
            "expected a completed session, got {:?}",
            session.status()
        )));
    }

    // Every required gate really has Current/Passed Evidence.
    let format_evidence = session
        .evidence_history()
        .iter()
        .find(|record| record.evidence.gate == GateId::Format)
        .ok_or_else(|| fail("no gate.format Evidence was recorded"))?;
    if format_evidence.status != GateStatus::Passed {
        return Err(fail(format!(
            "gate.format Evidence must be Passed, got {:?}",
            format_evidence.status
        )));
    }
    // §29: the Evidence carries the exact provider identity.
    if format_evidence
        .evidence
        .provenance
        .provider_version
        .as_deref()
        != Some(go_version.as_str())
    {
        return Err(fail(
            "gate.format Evidence must carry the exact probed gofmt/Go identity",
        ));
    }

    eprintln!("P15_REAL_GOFMT_CHANGESESSION_E2E=PASS provider={go_version}");
    fixture.cleanup();
    Ok(())
}

/// `P15_GO_REQUIRED_FORMATTER_MISSING_BLOCKS_COMPLETION` (§25), governance
/// half: with `gofmt` genuinely unresolvable, the Go `SOURCE_MODIFY` plan is
/// `Unexecutable` and the session is blocked -- the required `gate.format`
/// does **not** disappear because its provider is missing.
#[tokio::test]
async fn missing_required_gofmt_blocks_completion_without_removing_the_gate()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("format-blocked", "package main\n\nfunc main() {}\n");
    let workspace_root = fixture.root()?;

    // No approved directory: gofmt genuinely does not resolve.
    let empty_authority = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let formatter_resolution = wht_corulix_config::resolve_provider(
        &empty_authority,
        &workspace_root,
        ProviderCategory::Formatter,
        "gofmt",
    )
    .await;
    if formatter_resolution.availability == wht_corulix_core::ProviderAvailability::Available {
        return Err(fail(
            "gofmt must be unavailable for this test to prove anything",
        ));
    }

    let snapshot = ProviderSnapshot::from_resolutions(&[formatter_resolution]);
    let tool_plan = wht_corulix_engine::planning::plan_operation(
        OperationIntent::SourceModify,
        TargetScope::SingleRoot,
        &snapshot,
        Some(LanguageId::Go),
    );
    if tool_plan.executability == PlanExecutability::Executable {
        return Err(fail(
            "a Go SOURCE_MODIFY with no gofmt must not be Executable",
        ));
    }
    // The required gate is still present -- an unavailable provider never
    // removes a required gate.
    if !tool_plan.gates.iter().any(|gate| {
        gate.gate == GateId::Format && gate.applicability == GateApplicability::Required
    }) {
        return Err(fail(
            "gate.format must remain Required even when gofmt is unavailable",
        ));
    }

    let workspace_identity =
        WorkspaceIdentity::from_opaque_token(format!("wsid-p15-blocked-{}", stamp()))?;
    let connection = ConnectionId::from_opaque_token("conn-p15-blocked".to_string())?;
    let mut session = ChangeSession::open(
        ChangeSession::generate_id()?,
        workspace_identity.clone(),
        connection.clone(),
        1,
        MutationExecutor::new(workspace_root),
    );
    session.enter_scope(SessionScope::new(vec!["src".to_string()]))?;
    session.baseline(tool_plan, Vec::new())?;

    if !matches!(session.status(), ChangeSessionStatus::Blocked(_)) {
        return Err(fail(format!(
            "an unexecutable plan must block the session at baseline, got {:?}",
            session.status()
        )));
    }
    if session
        .complete_change(&workspace_identity, &connection)
        .is_ok()
    {
        return Err(fail(
            "completion must be denied when a required formatter is unavailable",
        ));
    }

    fixture.cleanup();
    Ok(())
}

/// The real `go version` identity string, probed from the toolchain that
/// ships the resolved `gofmt`. gofmt itself has no version flag (empirically
/// confirmed), so this is the honest identity for it.
fn go_version_identity() -> Result<String, Box<dyn Error>> {
    let output = std::process::Command::new(Path::new(REAL_GO_DIRECTORY).join("go"))
        .arg("version")
        .output()?;
    if !output.status.success() {
        return Err(fail("`go version` failed"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
