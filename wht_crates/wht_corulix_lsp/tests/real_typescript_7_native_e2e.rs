// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof against the real, Corulix-managed TypeScript 7
//! native LSP (`@typescript/typescript-linux-x64@7.0.2`,
//! `serverInfo.name == "typescript-go"`), never against this development
//! host's own (incomplete) system TypeScript install
//! (`SYSTEM_TYPESCRIPT_REQUIRED=NO`, `AMBIENT_PATH_AUTHORITY=NO`,
//! `WORKSPACE_TYPESCRIPT_AUTHORITY=NO`). Every test in this file
//! provisions the artifact itself via
//! `wht_corulix_tooling::provisioning::provision` (download -> verify hash
//! -> extract -> atomic activate) before resolving/spawning it -- the exact
//! same pipeline `wht_corulix_lsp::profile::resolve_launch`'s
//! `CORULIX_MANAGED` precedence consults at runtime, never a
//! test-only shortcut.
//!
//! This requires real network access to `registry.npmjs.org` the first
//! time it runs on a given `managed_toolchain_root()`; once provisioned,
//! every subsequent test (and every subsequent real session) resolves the
//! artifact purely from local disk. If the network is unavailable and the
//! artifact has never been provisioned before, every test in this file
//! reports and exits early with
//! `TYPESCRIPT_7_LSP_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED` rather
//! than failing.

// Windows note (M09/D96): `#![cfg(unix)]`-only for this whole file --
// `LspSession::spawn` (directly or via this file's own `run_full_vertical`
// helper) always fails closed on Windows via
// `ManagedProcess::spawn_with_workspace_root` before any process is
// spawned -- the same accepted, `FINAL_CLOSED` M09 contract already on
// record ("Windows: workspace-bound LSP UNAVAILABLE_FAIL_CLOSED, zero
// provider spawn"). Every test in this file previously carried its own
// per-test `#[cfg(unix)]`, which left every shared helper/fixture/constant
// dead code on non-Unix targets once none of their callers were compiled
// there; gating the whole file matches this crate's own established
// convention for the same defect class (see e.g.
// `real_ts6_adversarial_e2e.rs`, `real_poisoned_path_executable_authority_e2e.rs`).
#![cfg(unix)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, Position, WorkspaceRootId};
use wht_corulix_lsp::{
    DefinitionResult, DiagnosticsResult, LspProviderProfile, LspSession, Readiness,
    ReferencesResult,
};
use wht_corulix_tooling::provisioning::{self, ManagedComponentManifest, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

const READINESS_TIMEOUT: Duration = Duration::from_secs(60);

/// `ManagedExecutionLease`'s stop-signal registry is process-wide (keyed by
/// component id, not by test), so two of this file's tests spawning a real
/// TS7 session under the exact same production component id at the same
/// time would let one test's `uninstall()` call (which correctly signals
/// *every* live lease naming that component -- that is the whole point of
/// Phase 7B-B1-R3-A) stop a completely unrelated test's session out from
/// under it. This is a real production behavior, not a bug in it -- the
/// fix belongs in test isolation, serializing this file's real-TS7-session
/// tests against each other via this lock, never in the uninstall logic
/// itself.
static REAL_TS7_SESSION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_ts7_session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_TS7_SESSION_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
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

fn managed_manifest() -> Option<ManagedComponentManifest> {
    LspProviderProfile::typescript_7_native().managed_component
}

/// Host-native `tsc` executable file name -- P17-W Stage C real native
/// Windows verification found this test file hardcoded the Linux,
/// extension-less binary name (`"tsc"`) as the sole accepted
/// `launch.executable.file_name()` value, the same "hardcoded to Linux"
/// defect class the gopls/rust-analyzer Windows verification passes
/// already found and fixed in their own test files (see
/// `real_gopls_managed_e2e.rs`'s `GOPLS_HOST_BINARY_NAME`). On a real
/// Windows host the resolved launch's executable is the genuine
/// `TYPESCRIPT_7_WINDOWS_X64` artifact's `tsc.exe` -- a correct result,
/// not a defect in the manifest or provisioning -- so the assertion below
/// must accept the host-native name rather than the Linux one
/// unconditionally.
#[cfg(target_os = "windows")]
const TS7_HOST_TSC_BINARY_NAME: &str = "tsc.exe";
#[cfg(not(target_os = "windows"))]
const TS7_HOST_TSC_BINARY_NAME: &str = "tsc";

/// Ensures the real managed TypeScript 7 native artifact is provisioned
/// under the real, host-wide `managed_toolchain_root()`, provisioning it
/// (real download/verify/extract/activate) if it is not already present.
/// Returns `false` -- never an error -- if provisioning could not complete
/// (e.g. no network on a host where it was never provisioned before), so
/// callers can honestly report `BLOCKED` rather than fail.
async fn ensure_provisioned(manifest: &ManagedComponentManifest) -> bool {
    let Ok(root) = provisioning::managed_toolchain_root() else {
        return false;
    };
    let (state, _) = provisioning::resolve_managed_component(&root, manifest);
    if state == ManagedComponentState::Available {
        return true;
    }
    provisioning::provision(&root, manifest).await.is_ok()
}

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-lsp-ts7-managed-root-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn temp_fixture(label: &str, filename: &str, content: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-lsp-ts7-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(root.join(filename), content);
    root
}

/// The trailing `lifted` line beyond the original `target`/`caller` pair
/// exists solely so `real_typescript_7_full_vertical_e2e`'s diagnostics
/// assertion can be genuinely lib-tree-sensitive (P17-W-R12 Windows
/// certification pass): `Promise` and `Array.prototype.at` are declared in
/// `lib.es2015.promise.d.ts`/`lib.es2022.array.d.ts`, not the language
/// itself, so type-checking this line correctly with zero diagnostics is
/// only possible if the full `package/lib/*.d.ts` tree extracted alongside
/// `tsc.exe`/`tsc` is actually present and resolvable -- a missing lib tree
/// produces a real `Cannot find name 'Promise'` diagnostic instead. Appended
/// *after* every position [`CALL_SITE_POSITION`]/[`DECLARATION_POSITION`]
/// name, so none of those byte offsets change.
const TS_FIXTURE_SOURCE: &str = "export function target(x: number): number {\n  return x + 1;\n}\n\nexport function caller(): number {\n  return target(1);\n}\n\nexport const lifted: Promise<number | undefined> = Promise.resolve(\n  [1, 2, 3].at(0),\n);\n";

const JS_FIXTURE_SOURCE: &str = "function target(x) {\n  return x + 1;\n}\n\nfunction caller() {\n  return target(1);\n}\n\nmodule.exports = { target, caller };\n";

/// Byte offset of the `t` in `target(1)` inside `caller`, identical shape
/// in both fixtures above (computed and cross-checked against the real
/// server during this phase's research probe).
const CALL_SITE_POSITION: Position = Position {
    line_zero_based: 5,
    byte_column_zero_based: 9,
    byte_offset: 107,
};

const DECLARATION_POSITION: Position = Position {
    line_zero_based: 0,
    byte_column_zero_based: 9,
    byte_offset: 9,
};

/// Takes an explicit `managed_root` (via `resolve_launch_at`) so a session
/// this test later tears down via a destructive call against an isolated
/// root is registered under that same root's lease identity -- see
/// `real_ts6_final_residual_certification_e2e.rs`'s own `resolve_ts6_managed`
/// doc comment for why the bare `resolve_launch` cannot be used here.
async fn resolve_ts7(
    workspace_root: &WorkspaceRoot,
    profile: &LspProviderProfile,
    managed_root: &std::path::Path,
) -> Option<wht_corulix_lsp::ResolvedLaunch> {
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    wht_corulix_lsp::resolve_launch_at(profile, &effective, workspace_root, managed_root)
        .await
        .ok()
}

async fn run_full_vertical(
    label: &str,
    filename: &str,
    source: &str,
    profile: LspProviderProfile,
    expected_e2e_flag: &str,
) -> Result<(), Box<dyn Error>> {
    let _lock = real_ts7_session_lock().await;
    let Some(manifest) = managed_manifest() else {
        return Err(fail("typescript_7_native profile has no managed_component"));
    };
    if !ensure_provisioned(&manifest).await {
        eprintln!(
            "{expected_e2e_flag}=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: the managed TypeScript 7 native artifact could not be provisioned in this environment (no network and never previously provisioned)"
        );
        return Ok(());
    }

    let fixture = temp_fixture(label, filename, source);
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root unresolvable: {error:?}")))?;
    let Some(launch) = resolve_ts7(&workspace_root, &profile, &root).await else {
        return Err(fail(
            "typescript-7-native did not resolve via CORULIX_MANAGED precedence",
        ));
    };
    // Never routed through a Node interpreter: this is the native binary
    // itself as `executable`, proving `TS7_NODE_RUNTIME_REQUIRED=NO` holds
    // at the actual spawn boundary, not merely in the profile's own
    // `interpreter: None` declaration.
    if launch.executable.file_name().and_then(|name| name.to_str())
        != Some(TS7_HOST_TSC_BINARY_NAME)
    {
        return Err(fail(format!(
            "expected the native tsc executable itself, got {:?}",
            launch.executable
        )));
    }

    let cancellation = CancellationToken::new();
    let source_path = fixture.join(filename);
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    session
        .ensure_open(&source_path)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("typescript-go never reached readiness: {error:?}")))?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }

    // --- DEFINITION: from the `target(1)` call site to its declaration ---
    let definition =
        wht_corulix_lsp::definition(&session, &source_path, &CALL_SITE_POSITION, &cancellation)
            .await
            .map_err(|error| fail(format!("definition request failed: {error:?}")))?;
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
            "expected definition on line 0 (target's own declaration), got {:?}",
            definition_location.range
        )));
    }
    if definition_location.path.relative_path != filename {
        return Err(fail(format!(
            "expected definition in {filename}, got {}",
            definition_location.path.relative_path
        )));
    }

    // --- REFERENCES: from `target`'s own declaration to its call site ---
    let references =
        wht_corulix_lsp::references(&session, &source_path, &DECLARATION_POSITION, &cancellation)
            .await
            .map_err(|error| fail(format!("references request failed: {error:?}")))?;
    let ReferencesResult::Found(reference_locations) = references else {
        return Err(fail("expected Found after proven readiness, got NotReady"));
    };
    if reference_locations.is_empty() {
        return Err(fail("expected at least one real reference to target"));
    }

    // --- DOCUMENT SYMBOLS ---
    let document_symbols = wht_corulix_lsp::document_symbols(&session, &source_path, &cancellation)
        .await
        .map_err(|error| fail(format!("documentSymbol request failed: {error:?}")))?;
    if !document_symbols
        .iter()
        .any(|symbol| symbol.name == "target")
    {
        return Err(fail(format!(
            "expected 'target' among document symbols, got {document_symbols:?}"
        )));
    }

    // --- WORKSPACE SYMBOLS ---
    let workspace_symbols = wht_corulix_lsp::workspace_symbols(&session, "target", &cancellation)
        .await
        .map_err(|error| fail(format!("workspace/symbol request failed: {error:?}")))?;
    if !workspace_symbols
        .iter()
        .any(|symbol| symbol.name == "target")
    {
        return Err(fail(format!(
            "expected 'target' among workspace symbols, got {workspace_symbols:?}"
        )));
    }

    // --- DIAGNOSTICS: this fixture is valid, so expect a proven Reported
    // set, and (P17-W-R12) genuinely EMPTY, not merely "not NotReady" --
    // for the TypeScript fixture this is a real lib-tree-resolution proof:
    // `TS_FIXTURE_SOURCE`'s trailing `lifted` line references `Promise`/
    // `Array.prototype.at`, both declared only in the platform artifact's
    // own `package/lib/*.d.ts` files (extracted alongside the `tsc`/
    // `tsc.exe` binary via this crate's unfiltered `extract_path_prefixes:
    // &[]`), never the language itself -- a missing/incomplete lib tree on
    // either platform surfaces here as a real, non-empty diagnostic
    // (`Cannot find name 'Promise'`), not a silent pass. The JavaScript
    // fixture carries no such reference, so an empty result there was
    // already implied and remains so.
    let diagnostics_result = wht_corulix_lsp::diagnostics(&session, &source_path)
        .await
        .map_err(|error| fail(format!("diagnostics call failed: {error:?}")))?;
    match &diagnostics_result {
        DiagnosticsResult::Reported(reported) if reported.is_empty() => {}
        DiagnosticsResult::Reported(reported) => {
            return Err(fail(format!(
                "expected zero diagnostics on a valid, lib-resolvable fixture (lib-tree resolution proof), got {reported:?}"
            )));
        }
        other => {
            return Err(fail(format!(
                "expected Reported after proven readiness, got {other:?}"
            )));
        }
    }

    // --- RENAME PREVIEW: proves `prepareRename` -> `rename` never mutates
    // the fixture on disk (RENAME_PREVIEW_MUTATION_COUNT=0), even against a
    // provider whose capabilities declare `renameProvider.prepareProvider`. ---
    let original_bytes_before = fs::read(&source_path)?;
    let rename_preview = wht_corulix_lsp::rename_preview(
        &session,
        &source_path,
        &DECLARATION_POSITION,
        "renamedTarget",
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("rename request failed: {error:?}")))?;
    if rename_preview.edits_by_path.is_empty() {
        return Err(fail("expected a real proposed rename edit"));
    }
    let original_bytes_after = fs::read(&source_path)?;
    if original_bytes_before != original_bytes_after {
        return Err(fail(
            "RENAME_PREVIEW_MUTATION_COUNT violated: the fixture file changed on disk",
        ));
    }

    // --- SHUTDOWN / REAP ---
    session.shutdown(&cancellation).await;

    eprintln!("{expected_e2e_flag}=PASS");
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

#[tokio::test]
async fn real_typescript_7_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    run_full_vertical(
        "typescript",
        "main.ts",
        TS_FIXTURE_SOURCE,
        LspProviderProfile::typescript_7_native(),
        "TYPESCRIPT_7_LSP_E2E",
    )
    .await
}

#[tokio::test]
async fn real_javascript_7_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    run_full_vertical(
        "javascript",
        "main.js",
        JS_FIXTURE_SOURCE,
        LspProviderProfile::typescript_7_native_for_javascript(),
        "JAVASCRIPT_7_LSP_E2E",
    )
    .await
}

/// `UNTRUSTED_TS7_PACKAGE_INSTALL=NO`: opens a bare, config-less JS file
/// requiring an uninstalled package (the exact shape that triggers this
/// server's real, compiled-in Automatic Type Acquisition -- proven during
/// this phase's research gate to genuinely shell out to `npm install`) and
/// confirms the session still reaches ready/diagnostics normally, with no
/// child process ever observable, because `resolve_launch`'s `PATH` for
/// this profile is built exclusively from `auxiliary_tools`/`interpreter`
/// (both empty/`None` for this provider) -- `npm` is never on it,
/// regardless of anything a hostile workspace declares.
#[tokio::test]
async fn ata_never_resolves_npm_even_for_an_inferred_project_requiring_a_missing_package()
-> Result<(), Box<dyn Error>> {
    let _lock = real_ts7_session_lock().await;
    let Some(manifest) = managed_manifest() else {
        return Err(fail("typescript_7_native profile has no managed_component"));
    };
    if !ensure_provisioned(&manifest).await {
        eprintln!(
            "TYPESCRIPT_7_LSP_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: cannot run the ATA security proof without the managed artifact"
        );
        return Ok(());
    }

    let fixture = temp_fixture(
        "ata-untrusted",
        "main.js",
        "const missing = require(\"definitely-not-installed-corulix-fixture-pkg\");\nconsole.log(missing);\n",
    );
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let profile = LspProviderProfile::typescript_7_native_for_javascript();
    let root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root unresolvable: {error:?}")))?;
    let Some(launch) = resolve_ts7(&workspace_root, &profile, &root).await else {
        return Err(fail("typescript-7-native did not resolve"));
    };
    if launch.environment.contains("PATH") {
        return Err(fail(
            "expected no PATH entry for this provider at all (auxiliary_tools/interpreter are both empty/None) -- npm must never be resolvable",
        ));
    }

    let cancellation = CancellationToken::new();
    let source_path = fixture.join("main.js");
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    session
        .ensure_open(&source_path)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("typescript-go never reached readiness: {error:?}")))?;

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// Dedicated TS7 install -> use -> uninstall lifecycle proof
/// (`TS7_MANAGED_UNINSTALL_E2E`, Phase 7B-B1). Every other test in this file
/// proves TS7's own real semantic vertical; this one additionally proves
/// the *managed lifecycle* end to end for this specific component -- not
/// merely "TS7 participates in the same shared `provision`/`uninstall`
/// code path other components exercise" (already true by construction),
/// but a real, standalone provision -> spawn -> ready -> uninstall ->
/// verify-absent -> idempotent-second-call sequence with an external
/// sentinel proven unmutated throughout.
#[tokio::test]
async fn real_typescript_7_managed_install_use_uninstall_lifecycle_e2e()
-> Result<(), Box<dyn Error>> {
    // MANAGED_TEST_ISOLATION_DEFECT fix: this used to resolve+uninstall
    // against the real, shared, host-wide `managed_toolchain_root()` --
    // permanently removing `typescript-7-native` from every other test/live
    // MCP session sharing that root, with no restoration. An isolated root
    // (provisioned fresh here) also closes the cross-test lease-signaling
    // risk `REAL_TS7_SESSION_LOCK`'s doc describes, since no other test can
    // share this exact root's identity.
    let _lock = real_ts7_session_lock().await;
    let manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_HOST_NATIVE;
    let root = temp_dir("ts7-uninstall-lifecycle-managed-root");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    let (initial_state, _) = provisioning::resolve_managed_component(&root, &manifest);
    if initial_state != ManagedComponentState::Available
        && provisioning::provision(&root, &manifest).await.is_err()
    {
        eprintln!(
            "TS7_MANAGED_UNINSTALL_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: the managed TypeScript 7 native artifact could not be provisioned in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let sentinel_dir = temp_fixture("uninstall-sentinel", "sentinel.txt", "do not touch");
    let sentinel_path = sentinel_dir.join("sentinel.txt");
    let before_hash =
        wht_corulix_core::ContentHash::compute_sha256(&fs::read(&sentinel_path)?).digest_hex;

    let fixture = temp_fixture("uninstall-lifecycle", "main.ts", TS_FIXTURE_SOURCE);
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let profile = LspProviderProfile::typescript_7_native();
    let Some(launch) = resolve_ts7(&workspace_root, &profile, &root).await else {
        return Err(fail(
            "typescript-7-native did not resolve for the uninstall lifecycle test",
        ));
    };
    let cancellation = CancellationToken::new();
    let source_path = fixture.join("main.ts");
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;
    session
        .ensure_open(&source_path)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("typescript-go never reached readiness: {error:?}")))?;
    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);

    let removed =
        wht_corulix_tooling::provisioning::uninstall::uninstall(&root, manifest.id, |_| {}).await;
    if removed != Ok(wht_corulix_tooling::provisioning::uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected TS7 uninstall to succeed, got {removed:?}"
        )));
    }
    let (state_after, _) =
        wht_corulix_tooling::provisioning::resolve_managed_component(&root, &manifest);
    if state_after != ManagedComponentState::NotProvisioned {
        return Err(fail(format!(
            "expected NotProvisioned after uninstall, got {state_after:?}"
        )));
    }
    let removed_again =
        wht_corulix_tooling::provisioning::uninstall::uninstall(&root, manifest.id, |_| {}).await;
    if removed_again
        != Ok(wht_corulix_tooling::provisioning::uninstall::UninstallOutcome::AlreadyRemoved)
    {
        return Err(fail(format!(
            "expected idempotent second uninstall, got {removed_again:?}"
        )));
    }

    let after_hash =
        wht_corulix_core::ContentHash::compute_sha256(&fs::read(&sentinel_path)?).digest_hex;
    if before_hash != after_hash {
        return Err(fail(
            "EXTERNAL_SENTINEL_MUTATION_COUNT violated: sentinel file changed during TS7 uninstall",
        ));
    }
    let _ = fs::remove_dir_all(&sentinel_dir);
    let _ = fs::remove_dir_all(&root);

    eprintln!("TS7_MANAGED_UNINSTALL_E2E=PASS");
    Ok(())
}

/// Phase 7B-B1-R3-A §3-7: the real, load-bearing proof this pass exists
/// for. A managed TS7 session is left genuinely *active* -- no
/// `session.shutdown()` call before `uninstall()` -- so uninstall's ACTIVE
/// EXECUTION DISCOVERY + MANAGED PROCESS SHUTDOWN stage is what stops this
/// process, not this test's own cleanup. Proves the real lease lifecycle
/// (`Starting`/`Active` observed before the stop request; `Stopped`
/// afterward -- `TS7_LEASE_LIFECYCLE=PASS`) and that the underlying
/// `tsc --lsp` process is genuinely gone (a request against its transport
/// after uninstall fails, `Transport(Closed)`), never merely that the
/// component directory was removed while a process kept running
/// (`TS7_ACTIVE_PROVIDER_UNINSTALL_SAFETY=PASS`).
#[tokio::test]
async fn real_typescript_7_active_provider_uninstall_safety_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_ts7_session_lock().await;
    let manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_HOST_NATIVE;
    // MANAGED_TEST_ISOLATION_DEFECT fix: isolated root for this whole test
    // (provision, spawn, and the active-session uninstall below all use the
    // same one) -- see the sibling uninstall-lifecycle test's own comment
    // for why.
    let root = temp_dir("ts7-active-uninstall-safety-managed-root");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    let (initial_state, _) = provisioning::resolve_managed_component(&root, &manifest);
    if initial_state != ManagedComponentState::Available
        && provisioning::provision(&root, &manifest).await.is_err()
    {
        eprintln!(
            "TS7_ACTIVE_PROVIDER_UNINSTALL_SAFETY=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: the managed TypeScript 7 native artifact could not be provisioned in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let fixture = temp_fixture("active-uninstall-safety", "main.ts", TS_FIXTURE_SOURCE);
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let profile = LspProviderProfile::typescript_7_native();
    let Some(launch) = resolve_ts7(&workspace_root, &profile, &root).await else {
        return Err(fail(
            "typescript-7-native did not resolve for the active-uninstall-safety test",
        ));
    };
    let cancellation = CancellationToken::new();
    let source_path = fixture.join("main.ts");
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;
    session
        .ensure_open(&source_path)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("typescript-go never reached readiness: {error:?}")))?;

    // Lease lifecycle so far: Starting (at spawn) -> Active (this crate's
    // own `mark_active` call right after the handshake succeeded above).
    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Active) => {}
        other => {
            return Err(fail(format!(
                "expected lease state Active before uninstall, got {other:?}"
            )));
        }
    }

    // Deliberately NO `session.shutdown()` here -- the session is left
    // genuinely active. `uninstall()` must discover and stop it itself.
    let removed =
        wht_corulix_tooling::provisioning::uninstall::uninstall(&root, manifest.id, |_| {}).await;
    if removed != Ok(wht_corulix_tooling::provisioning::uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected uninstall to succeed against an active TS7 session (stopping it itself), got {removed:?}"
        )));
    }

    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Stopped) => {}
        other => {
            return Err(fail(format!(
                "expected lease state Stopped after uninstall stopped this session, got {other:?}"
            )));
        }
    }

    // The real `tsc --lsp` process is gone, not merely the on-disk
    // component directory: a fresh request against this session's own
    // transport must now fail, since `uninstall()`'s stop stage -- not
    // this test -- is what tore it down.
    let post_uninstall_request = session
        .transport()
        .request(
            "shutdown",
            serde_json::Value::Null,
            Duration::from_secs(5),
            &cancellation,
        )
        .await;
    if post_uninstall_request.is_ok() {
        return Err(fail(
            "expected the TS7 transport to be closed after uninstall stopped the process, but a request still succeeded",
        ));
    }

    let _ = fs::remove_dir_all(&fixture);
    let _ = fs::remove_dir_all(&root);
    eprintln!("TS7_ACTIVE_PROVIDER_UNINSTALL_SAFETY=PASS");
    eprintln!("TS7_LEASE_LIFECYCLE=PASS");
    Ok(())
}
