// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real, end-to-end dogfood proof for Phase 10's `ChangeSession` + Evidence
//! + gate state machine (`P10_REAL_DOGFOOD_E2E`).
//!
//! Drives one governed session through
//! `discovery -> semantic_confirm -> edit -> format -> diagnostics ->
//! post_audit -> completion` against a real, controlled Rust fixture
//! workspace, using only already-certified providers: real
//! `wht_corulix_search` text discovery, a real spawned rust-analyzer
//! (semantic confirmation + diagnostics + post-audit), a real
//! `wht_corulix_mutation::MutationExecutor` write (the Edit gate), and real
//! `wht_corulix_formatter::format_and_apply` (rustfmt, genuinely changing
//! bytes -- `FORMATTER_ACTUALLY_CHANGED_BYTES=YES`). No mock stands in for
//! any of them (`MOCKED_ONLY_CLOSURE=NO`); the `ToolPlan` this test governs
//! against comes from calling `wht_corulix_engine::planning::plan_operation`
//! itself, the exact same deterministic derivation production code uses --
//! never a hand-built plan skipping that derivation.
//!
//! `GateId::Tests` is absent from `OperationIntent::SourceRefactor`'s own
//! policy entry (`wht_corulix_engine::policy::SOURCE_REFACTOR`) -- this
//! test does not fabricate a required-tests requirement, and does not
//! implement any P12 trusted-build/test-execution capability to satisfy
//! one (Phase 10 §21/§58): `GateId::Tests` genuinely does not appear in
//! this plan's gate list at all, which this test asserts directly rather
//! than assuming.
//!
//! If no real rust-analyzer/rustfmt binary is present at this development
//! environment's well-known toolchain location, this test reports and
//! exits early rather than substituting a mock.

// Windows note (M09/D96, P17-W corrective P6): `#![cfg(unix)]`-only for
// this whole file. This is the file's sole test, and its entire proof --
// every stage from semantic_confirm onward (semantic confirmation,
// diagnostics, post-audit) -- depends on a real, live, workspace-bound
// rust-analyzer session existing throughout the governed lifecycle, not
// merely one narrow assertion. `LspSession::spawn`'s single call site
// (`wht_corulix_lsp::session.rs`) routes unconditionally through
// `wht_corulix_tooling::ManagedProcess::spawn_with_workspace_root`, whose
// `#[cfg(not(unix))]` arm unconditionally returns `Err` before any process
// is spawned -- the same accepted, `FINAL_CLOSED` M09 contract already on
// record ("Windows: workspace-bound LSP UNAVAILABLE_FAIL_CLOSED, zero
// provider spawn"), confirmed via direct production source (P4/P5).
// `P10_WINDOWS_CONTRACT=UNIX_ONLY_FULL_GOVERNED_LIFECYCLE`: unlike
// `real_rust_analyzer_e2e.rs` (P5), this file has no separable
// pre-spawn-only sibling test, so the whole file is gated rather than a
// per-item subset. P5's host-native manifest/HOME/exe-suffix provisioning
// corrections remain unchanged and valid -- they simply become dormant on
// Windows under this gate for now, available for reuse if a future,
// separately-authorized pass adds real Windows LSP process support.
#![cfg(unix)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{
    CancellationToken, ConnectionId, ContentHash, EvidenceProvenance, EvidenceResultSummary,
    EvidenceTimestamp, GateId, LanguageId, OperationIntent, Position, ProviderAvailability,
    ProviderCategory, WorkspaceIdentity, WorkspacePath, WorkspaceRootId,
};
use wht_corulix_engine::policy::TargetScope;
use wht_corulix_engine::providers::ProviderSnapshot;
use wht_corulix_engine::session::{ChangeSession, SessionScope};
use wht_corulix_lsp::{
    DefinitionResult, DiagnosticsResult, LspProviderProfile, LspSession, Readiness,
};
use wht_corulix_mutation::{Mutation, MutationBatch, MutationExecutor};
use wht_corulix_workspace::WorkspaceRoot;

/// Test-only discovery of a real Rust toolchain binary. `env_override`
/// takes precedence when set. Never resolves to a `~/.cargo/bin`
/// rustup-proxy shim: Corulix's sandboxed process execution strips the
/// environment context that proxy needs to select a toolchain, so
/// resolving to it causes a spurious spawn failure -- this prefers the
/// active toolchain's real sysroot (`rustc --print sysroot`), then falls
/// back to scanning every installed toolchain's `bin/` directory
/// (`rustup show home`) for the first one that actually has the binary,
/// and only then falls back to a plain `PATH` search. Never embeds a
/// specific developer's machine path.
fn resolve_test_tool(bin_name: &str, env_override: &str) -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_override) {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("{bin_name}{}", std::env::consts::EXE_SUFFIX);
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
fn real_rust_analyzer_path() -> Option<PathBuf> {
    resolve_test_tool("rust-analyzer", "CORULIX_TEST_RUST_ANALYZER")
}
fn real_rustfmt_path() -> Option<PathBuf> {
    resolve_test_tool("rustfmt", "CORULIX_TEST_RUSTFMT")
}
// P11: `SourceRefactor`'s real policy entry now also requires
// `TypecheckBuild`/`Linter` (Minimum Sufficient Tooling risk-strengthening
// -- see `wht_corulix_engine::policy::SOURCE_REFACTOR`'s own doc comment).
// This test's `ToolPlan` still comes from the real, unmodified
// `plan_operation` pipeline (never hand-relaxed), so its `ProviderSnapshot`
// must now genuinely resolve both. `gate.diagnostics` itself is still
// closed via real `LanguageServer` (rust-analyzer) Evidence below,
// unchanged from before P11; these two paths only need to be `Available`
// for the plan to be `Executable` at all.
//
// P11-R1 (Residual 3): resolved from the real, `CORULIX_MANAGED` runtime
// (the same `RUST_SEMANTIC_RUNTIME_LINUX_X64` manifest the P11 diagnostics
// module itself uses -- see `wht_corulix_engine::diagnostics`), never a
// system `cargo`/`cargo-clippy` path. This was not strictly required for
// correctness -- `wht_corulix_engine::providers::ProviderSnapshot`'s
// availability booleans are provably `METADATA_ONLY_NONAUTHORITATIVE`
// regardless of which identity backs them: `routing::evaluate` (called by
// `plan_operation`) reads only `.availability`, never `.resolved_path`/
// `.provenance`, and the `ProviderSnapshot` type itself never reaches
// `ChangeSession` at all -- `plan_operation` returns a `ToolPlan`, and
// `ChangeSession::baseline` takes a `ToolPlan` plus a separate, unrelated
// `Vec<EvidenceProvenance>` for its own per-provider-id version-pinning
// (`record_evidence`'s `EvidenceProviderSnapshotMismatch` check), never a
// `ProviderSnapshot`. Using the real managed identity here anyway is simply
// the *preferred* final state: it never leaves a system path in a snapshot
// a future reader could misread as authority.
const READINESS_TIMEOUT: Duration = Duration::from_secs(60);

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

fn real_toolchain_available() -> bool {
    real_rust_analyzer_path().is_some_and(|p| p.is_file())
        && real_rustfmt_path().is_some_and(|p| p.is_file())
}

/// P17-W corrective P5: `std::env::var("HOME")` only errors when the
/// variable is *absent*, not when it is *present but empty* -- the same
/// empty-`HOME` defect class already found and fixed in
/// `real_rust_analyzer_managed_lsp_semantic_cycle_e2e.rs`'s own
/// `resolve_home_dir` (P4). This test has no platform gate at all, so
/// unlike that file, it must genuinely resolve a correct absolute path on
/// Windows too (provisioning below needs one even though the later
/// `LspSession::spawn` call has its own separate, accepted Windows
/// fail-closed contract -- see `RUST_ANALYZER_FULL_VERTICAL_CONTRACT`
/// evidence recorded for `real_rust_analyzer_e2e.rs`). Falls back to
/// `USERPROFILE` before the prior Unix-only `/root` default.
fn resolve_home_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home);
    }
    #[cfg(windows)]
    {
        if let Ok(user_profile) = std::env::var("USERPROFILE")
            && !user_profile.is_empty()
        {
            return PathBuf::from(user_profile);
        }
    }
    PathBuf::from("/root")
}

fn managed_root() -> PathBuf {
    let home = resolve_home_dir();
    // The same shared cache `real_p11_diagnostics_e2e.rs`/
    // `real_p11_r1_trust_enforcement_e2e.rs` use -- one real provisioned
    // runtime, never a second independent download for this test alone.
    home.join(".cache")
        .join("corulix-p11-diagnostics-e2e")
        .join("root")
}

/// Host-native `rust-semantic-runtime` manifest (P17-W corrective P5): this
/// test previously hardcoded [`RUST_SEMANTIC_RUNTIME_LINUX_X64`]
/// unconditionally, so on Windows it always attempted to provision a Linux
/// ELF runtime -- a genuine `TEST_DEFECT`, not the "no real internet
/// access" the resulting `BLOCKED_PROVISIONING_FAILED` message speculated.
/// The real Windows counterpart,
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64`],
/// already exists and is used elsewhere in this same test suite.
#[cfg(target_os = "windows")]
fn host_native_rust_semantic_runtime_manifest()
-> wht_corulix_tooling::provisioning::ManagedComponentManifest {
    wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64
}
#[cfg(not(target_os = "windows"))]
fn host_native_rust_semantic_runtime_manifest()
-> wht_corulix_tooling::provisioning::ManagedComponentManifest {
    wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64
}

/// Ensures the real, managed host-native `rust-semantic-runtime` (cargo/
/// rustc/clippy, merged -- P11) is provisioned, returning its install
/// directory. `None` (never a panic) on genuine provisioning failure, so
/// this test can report `BLOCKED` honestly on an environment without real
/// internet access.
async fn ensure_managed_runtime_provisioned() -> Option<PathBuf> {
    let root = managed_root();
    let manifest = host_native_rust_semantic_runtime_manifest();
    let (state, _) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component(&root, &manifest);
    if state != wht_corulix_tooling::provisioning::ManagedComponentState::Available
        && wht_corulix_tooling::provisioning::provision(&root, &manifest)
            .await
            .is_err()
    {
        return None;
    }
    Some(wht_corulix_tooling::provisioning::component_install_dir(
        &root, &manifest,
    ))
}

fn temp_fixture_workspace(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-p10-dogfood-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_p10_dogfood_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn target() {}\n\nfn caller() {\n    target();\n}\n\nfn main() {\n    caller();\n}\n",
    );
    root
}

fn host_only_effective_config() -> EffectiveConfig {
    let host = HostConfig {
        provider_absolute_paths: vec![
            (
                ProviderCategory::LanguageServer,
                real_rust_analyzer_path().unwrap_or_default(),
            ),
            (
                ProviderCategory::Formatter,
                real_rustfmt_path().unwrap_or_default(),
            ),
            // TypecheckBuild/Linter are deliberately absent here -- P11-R1
            // resolves them from the real managed runtime instead (see
            // `ensure_managed_runtime_provisioned`), never a `HOST_ONLY`
            // system path.
        ],
        ..HostConfig::default()
    };
    EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

async fn probe_version(executable: &Path, cancellation: &CancellationToken) -> Option<String> {
    let outcome = wht_corulix_tooling::execute(
        &wht_corulix_tooling::ProcessSpec {
            executable: executable.to_path_buf(),
            arguments: vec!["--version".to_string()],
            environment: wht_corulix_tooling::EnvironmentPolicy::empty(),
            working_directory: std::env::temp_dir(),
            limits: wht_corulix_tooling::ProcessLimits::default(),
            timeout: Duration::from_secs(10),
            execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
            argv0: None,
        },
        cancellation,
    )
    .await;
    let text = String::from_utf8(outcome.stdout.bytes).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn evidence_summary(text: &str) -> Result<EvidenceResultSummary, Box<dyn Error>> {
    Ok(EvidenceResultSummary::try_from(text.to_string())?)
}

#[tokio::test]
async fn real_p10_dogfood_change_session_full_governed_lifecycle_e2e() -> Result<(), Box<dyn Error>>
{
    if !real_toolchain_available() {
        eprintln!(
            "P10_REAL_DOGFOOD_E2E=BLOCKED_TOOLCHAIN_ABSENT: no real rust-analyzer/rustfmt found on PATH (set CORULIX_TEST_RUST_ANALYZER/CORULIX_TEST_RUSTFMT to override) in this environment"
        );
        return Ok(());
    }

    let fixture = temp_fixture_workspace("full-lifecycle");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let cancellation = CancellationToken::new();
    let effective = host_only_effective_config();

    // --- Real provider resolution (Phase 6), never ambient PATH ---
    let rust_analyzer_resolution = wht_corulix_config::resolve_provider(
        &effective,
        &workspace_root,
        ProviderCategory::LanguageServer,
        "rust-analyzer",
    )
    .await;
    if rust_analyzer_resolution.availability != ProviderAvailability::Available {
        return Err(fail(format!(
            "rust-analyzer did not resolve via the real Phase-6 provider resolver: {rust_analyzer_resolution:?}"
        )));
    }
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
    // P11-R1 (Residual 3): TypecheckBuild/Linter resolve from the real
    // `CORULIX_MANAGED` runtime, never `wht_corulix_config::resolve_provider`
    // (which would only ever reach a `HOST_ONLY`/system path here).
    let Some(managed_install_dir) = ensure_managed_runtime_provisioned().await else {
        return Err(fail(
            "P10_DOGFOOD_MANAGED_RUNTIME=BLOCKED_PROVISIONING_FAILED (no real internet access?)",
        ));
    };
    let managed_cargo_path = managed_install_dir
        .join("bin")
        .join(format!("cargo{}", std::env::consts::EXE_SUFFIX));
    let managed_cargo_clippy_path = managed_install_dir
        .join("bin")
        .join(format!("cargo-clippy{}", std::env::consts::EXE_SUFFIX));
    if !managed_cargo_path.is_file() || !managed_cargo_clippy_path.is_file() {
        return Err(fail(format!(
            "expected the real managed runtime to provide both cargo and cargo-clippy, \
             checked {managed_cargo_path:?} / {managed_cargo_clippy_path:?}"
        )));
    }
    let rust_analyzer_path = real_rust_analyzer_path().unwrap_or_default();
    let rustfmt_path = real_rustfmt_path().unwrap_or_default();
    let rust_analyzer_version = probe_version(&rust_analyzer_path, &cancellation)
        .await
        .ok_or_else(|| fail("could not probe a real rust-analyzer --version string"))?;
    let rustfmt_version = probe_version(&rustfmt_path, &cancellation)
        .await
        .ok_or_else(|| fail("could not probe a real rustfmt --version string"))?;

    // --- Real, deterministic ToolPlan derivation -- the exact production
    // pipeline (`wht_corulix_engine::planning::plan_operation`), never a
    // hand-authored plan. `SourceRefactor` is chosen because its real
    // policy entry is the one operation whose required-gate list already
    // spans discovery/semantic_confirm/edit/format/diagnostics/post_audit
    // in one plan (Rust's real, certified provider family), without
    // requiring `gate.tests` (absent from this policy entry -- proven
    // below, not assumed). ---
    let snapshot = ProviderSnapshot::from_resolutions(&[
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::Formatter,
            availability: ProviderAvailability::Available,
            resolved_path: rustfmt_resolution.resolved_path.clone(),
            provenance: rustfmt_resolution.provenance,
            execution_class: rustfmt_resolution.execution_class,
            reason: None,
        },
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::TypecheckBuild,
            availability: ProviderAvailability::Available,
            resolved_path: Some(managed_cargo_path.clone()),
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution,
            reason: None,
        },
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::Linter,
            availability: ProviderAvailability::Available,
            resolved_path: Some(managed_cargo_clippy_path.clone()),
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution,
            reason: None,
        },
    ])
    .with_language_server_resolutions(&[(LanguageId::Rust, ProviderAvailability::Available)]);
    let tool_plan = wht_corulix_engine::planning::plan_operation(
        OperationIntent::SourceRefactor,
        TargetScope::SingleRoot,
        &snapshot,
        Some(LanguageId::Rust),
    );
    if tool_plan.executability != wht_corulix_core::PlanExecutability::Executable {
        return Err(fail(format!(
            "expected a real Executable SourceRefactor plan, got {:?}",
            tool_plan.executability
        )));
    }
    let required_gates: Vec<GateId> = tool_plan
        .gates
        .iter()
        .filter(|requirement| {
            requirement.applicability == wht_corulix_core::GateApplicability::Required
        })
        .map(|requirement| requirement.gate)
        .collect();
    if required_gates.contains(&GateId::Tests) {
        return Err(fail(
            "SourceRefactor's real policy entry must not require gate.tests (P12 is out of P10's scope)",
        ));
    }
    for expected in [
        GateId::Discovery,
        GateId::SemanticConfirm,
        GateId::Edit,
        GateId::Format,
        GateId::Diagnostics,
        GateId::PostAudit,
    ] {
        if !required_gates.contains(&expected) {
            return Err(fail(format!(
                "expected {expected:?} to be Required in the real SourceRefactor plan, got {required_gates:?}"
            )));
        }
    }
    eprintln!("P10_DOGFOOD_PLAN=SourceRefactor required_gates={required_gates:?}");

    // --- OPENED -> SCOPED -> BASELINED ---
    let workspace_identity = WorkspaceIdentity::from_opaque_token(format!(
        "wsid-p10-dogfood-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ))?;
    let connection = ConnectionId::from_opaque_token("conn-p10-dogfood".to_string())?;
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
        vec![
            EvidenceProvenance {
                provider_id: "rust-analyzer".to_string(),
                provider_version: Some(rust_analyzer_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            EvidenceProvenance {
                provider_id: "rustfmt".to_string(),
                provider_version: Some(rustfmt_version.clone()),
                authority: wht_corulix_core::AuthorityRole::SupportingOnly,
            },
        ],
    )?;

    // --- gate.discovery: real wht_corulix_search text discovery ---
    let search_context = wht_corulix_workspace::WorkspaceContext::single_root(
        workspace_root.clone(),
        "root".to_string(),
    );
    let discovery_results = wht_corulix_search::search(
        search_context,
        wht_corulix_search::SearchQuery::literal("target"),
        wht_corulix_search::SearchScope::AllRoots,
        wht_corulix_search::SearchBounds::default(),
    )
    .await?;
    if discovery_results.matches.is_empty() {
        return Err(fail(
            "expected real search to find at least one 'target' match",
        ));
    }
    eprintln!(
        "P10_DOGFOOD_DISCOVERY=PASS matches={}",
        discovery_results.matches.len()
    );
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
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: None,
            result_summary: evidence_summary(&format!(
                "{} real match(es) for 'target'",
                discovery_results.matches.len()
            ))?,
            reason: None,
            truncated: discovery_results.truncated,
            timestamp: EvidenceTimestamp(2),
            snapshot_id: None,
        },
    )?;

    // --- Real rust-analyzer session spawn ---
    let launch = wht_corulix_lsp::ResolvedLaunch {
        executable: rust_analyzer_resolution
            .resolved_path
            .clone()
            .ok_or_else(|| fail("rust-analyzer resolution carried no resolved_path"))?,
        arguments: Vec::new(),
        environment: wht_corulix_tooling::EnvironmentPolicy::empty(),
        managed_lease: None,
        extra_initialization_options: None,
    };
    let profile = LspProviderProfile::rust_analyzer();
    let lsp_session = LspSession::spawn(
        launch,
        &profile,
        workspace_root.clone(),
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("rust-analyzer spawn/handshake failed: {error:?}")))?;
    lsp_session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("rust-analyzer never reached readiness: {error:?}")))?;
    if lsp_session.readiness().await != Readiness::Ready {
        return Err(fail(
            "rust-analyzer reports not-ready after wait_until_ready succeeded",
        ));
    }

    // --- gate.semantic_confirm: real textDocument/definition ---
    let main_rs = fixture.join("src/main.rs");
    let definition = wht_corulix_lsp::definition(
        &lsp_session,
        &main_rs,
        &Position {
            line_zero_based: 3,
            byte_column_zero_based: 4,
            byte_offset: 0,
        },
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("real definition request failed: {error:?}")))?;
    let definition_location = match &definition {
        DefinitionResult::Single(location) => location.clone(),
        DefinitionResult::Multiple(locations) => locations
            .first()
            .cloned()
            .ok_or_else(|| fail("definition returned an empty Multiple result"))?,
        DefinitionResult::None => return Err(fail("expected a real definition, got None")),
    };
    if definition_location.range.start.line_zero_based != 0 {
        return Err(fail(format!(
            "expected a real definition on line 0 (fn target), got {:?}",
            definition_location.range
        )));
    }
    eprintln!("P10_DOGFOOD_SEMANTIC_CONFIRM=PASS definition={definition_location:?}");
    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::LanguageServer,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::SemanticConfirm,
            sequence: 3,
            provenance: EvidenceProvenance {
                provider_id: "rust-analyzer".to_string(),
                provider_version: Some(rust_analyzer_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: None,
            result_summary: evidence_summary("real textDocument/definition resolved fn target")?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(3),
            snapshot_id: None,
        },
    )?;

    // --- gate.edit: real MutationBatch through ChangeSession::submit_edit
    // (the only live-write path this session ever uses). Deliberately
    // mis-formatted so the Format gate below is non-vacuous
    // (`FORMATTER_ACTUALLY_CHANGED_BYTES=YES`). ---
    let original_bytes = fs::read(&main_rs)?;
    let precondition_hash = ContentHash::compute_sha256(&original_bytes);
    let unformatted_content =
        b"fn target(  ) { }\n\nfn caller() {\n    target();\n}\n\nfn main() {\n    caller();\n}\n"
            .to_vec();
    let batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: WorkspacePath {
                root: WorkspaceRootId(0),
                relative_path: "src/main.rs".to_string(),
            },
            expected_precondition_hash: precondition_hash,
            content: unformatted_content,
        }],
    };
    session
        .submit_edit(
            &workspace_identity,
            &connection,
            batch,
            EvidenceTimestamp(4),
        )
        .await
        .map_err(|error| fail(format!("real submit_edit failed: {error}")))?;
    eprintln!("P10_DOGFOOD_EDIT=PASS");

    // --- gate.format: real rustfmt via the one canonical, session-owned
    // `ChangeSession::format_and_apply` boundary (Phase 10-R2) -- real
    // formatting, the real `MutationExecutor` commit, and current-state
    // advancement as one inseparable operation; no raw
    // `wht_corulix_formatter::format_and_apply(..., session.executor(),
    // ...)` call and no manual `advance_content_state` call anywhere in
    // this file (`P10_R2_E2E_MANUAL_ADVANCE_CONTENT_STATE_CALL_COUNT=0`). ---
    let snapshot_after_edit = session.content_snapshot_id();
    let format_result = session
        .format_and_apply(
            &workspace_identity,
            &connection,
            &effective,
            WorkspacePath {
                root: WorkspaceRootId(0),
                relative_path: "src/main.rs".to_string(),
            },
            wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
            &cancellation,
        )
        .await
        .map_err(|error| {
            fail(format!(
                "real ChangeSession::format_and_apply failed: {error}"
            ))
        })?;
    if format_result.status != wht_corulix_formatter::FormatStatus::Formatted
        || !format_result.changed
    {
        return Err(fail(format!(
            "expected real rustfmt to change genuinely unformatted bytes, got {format_result:?}"
        )));
    }
    // State advancement already happened inside `format_and_apply` itself
    // -- proving state B (post-edit) != state C (post-format) for real,
    // non-vacuous bytes, with zero caller-side action required.
    let snapshot_after_format = session.content_snapshot_id();
    if snapshot_after_format == snapshot_after_edit {
        return Err(fail(
            "expected a real, changed format to advance current-state identity (B != C)",
        ));
    }
    eprintln!(
        "P10_DOGFOOD_FORMAT=PASS FORMATTER_ACTUALLY_CHANGED_BYTES=YES snapshot_after_edit={snapshot_after_edit} snapshot_after_format={snapshot_after_format}"
    );
    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::Formatter,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Format,
            sequence: 5,
            provenance: EvidenceProvenance {
                provider_id: "rustfmt".to_string(),
                provider_version: Some(rustfmt_version.clone()),
                authority: wht_corulix_core::AuthorityRole::SupportingOnly,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: format_result.output_hash.clone(),
            result_summary: evidence_summary("real rustfmt reformatted src/main.rs")?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(5),
            snapshot_id: Some(snapshot_after_format),
        },
    )?;

    // --- gate.diagnostics + gate.post_audit: real rust-analyzer
    // diagnostics against the final, formatted bytes. The same real
    // provider call backs both gates -- two distinct governance
    // checkpoints (build/lint cleanliness vs. this specific mutation's own
    // effect), never two independent, redundant LSP round-trips for no
    // reason. ---
    lsp_session.ensure_open(&main_rs).await.map_err(|error| {
        fail(format!(
            "re-opening the reformatted fixture failed: {error:?}"
        ))
    })?;
    // The Edit/Format writes happened out-of-band from rust-analyzer's own
    // document-sync view (through `MutationExecutor`/rustfmt, never
    // `textDocument/didChange`) -- a real file-watcher-driven re-index is
    // expected here, so readiness is re-proven with the same bounded wait
    // used after spawn, never assumed still `Ready` from before the edit.
    lsp_session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| {
            fail(format!(
                "rust-analyzer never reached readiness again after the real out-of-band edit: {error:?}"
            ))
        })?;
    let diagnostics = wht_corulix_lsp::diagnostics(&lsp_session, &main_rs)
        .await
        .map_err(|error| fail(format!("real diagnostics request failed: {error:?}")))?;
    let semantic_diagnostics = match diagnostics {
        DiagnosticsResult::Reported(items) => items,
        DiagnosticsResult::NotReady => {
            return Err(fail(
                "expected Reported diagnostics after proven readiness, got NotReady",
            ));
        }
    };
    let error_count = semantic_diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == wht_corulix_lsp::DiagnosticSeverity::Error)
        .count();
    if error_count != 0 {
        return Err(fail(format!(
            "expected zero real rust-analyzer errors after formatting, got {error_count}: {semantic_diagnostics:?}"
        )));
    }
    eprintln!("P10_DOGFOOD_DIAGNOSTICS=PASS error_count=0");
    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::LanguageServer,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Diagnostics,
            sequence: 6,
            provenance: EvidenceProvenance {
                provider_id: "rust-analyzer".to_string(),
                provider_version: Some(rust_analyzer_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: format_result.output_hash.clone(),
            result_summary: evidence_summary("real rust-analyzer: 0 errors post-format")?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(6),
            snapshot_id: Some(snapshot_after_format),
        },
    )?;
    eprintln!("P10R1_DIAGNOSTIC_EVIDENCE_CURRENT_CONTENT_BINDING=PASS");
    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::LanguageServer,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::PostAudit,
            sequence: 7,
            provenance: EvidenceProvenance {
                provider_id: "rust-analyzer".to_string(),
                provider_version: Some(rust_analyzer_version),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: format_result.output_hash.clone(),
            result_summary: evidence_summary(
                "real post-audit: fn target still resolves, 0 errors",
            )?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(7),
            snapshot_id: Some(snapshot_after_format),
        },
    )?;
    eprintln!("P10R1_POST_AUDIT_CURRENT_CONTENT_BINDING=PASS P10_DOGFOOD_POST_AUDIT=PASS");

    // --- EXIT_EVALUATION -> COMPLETED ---
    session.complete_change(&workspace_identity, &connection)?;
    if session.status() != wht_corulix_core::ChangeSessionStatus::Completed {
        return Err(fail(format!(
            "expected Completed after every required gate passed, got {:?}",
            session.status()
        )));
    }
    let status = session.change_status();
    if !status.failed_gates.is_empty() || !status.stale_gates.is_empty() {
        return Err(fail(format!(
            "expected zero failed/stale gates at completion, got {status:?}"
        )));
    }
    eprintln!(
        "P10_DOGFOOD_COMPLETION=PASS passed_gates={:?}",
        status.passed_gates
    );

    lsp_session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}
