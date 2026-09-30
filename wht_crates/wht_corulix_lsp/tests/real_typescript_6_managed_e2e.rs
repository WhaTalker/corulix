// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof against the real, Corulix-managed TypeScript-6/
//! JavaScript-6 compatibility backend (Phase 7B-C):
//! `typescript-language-server@6.0.0` -> managed Node (`v24.19.0`, the same
//! canonical identity Pyright already shares) -> `typescript@6.0.3`'s own
//! `lib/tsserver.js`, resolved exclusively through
//! `wht_corulix_lsp::resolve_launch`'s live `CORULIX_MANAGED`-first routing
//! (`LspProviderProfile::typescript_language_server_managed()`), with no
//! `HostConfig` override at all -- mirrors `real_pyright_managed_e2e.rs`'s
//! own model exactly, extended for a three-node dependency graph
//! (typescript-language-server -> [node-runtime, typescript-6-classic])
//! rather than Pyright's two-node one.
//!
//! Each fixture is a real two-file project (`lib.ts`/`main.ts`,
//! `lib.js`/`main.js`) with its own `tsconfig.json`/`jsconfig.json`, so
//! `definition` proves real *cross-file* project-model symbol resolution,
//! not merely same-file parsing.
//!
//! Provisions all three real artifacts itself (via
//! `wht_corulix_tooling::provisioning::provision_with_dependencies`) before
//! spawning, then exercises the dependency-aware uninstall contract at the
//! end. Requires real network access to `registry.npmjs.org`/`nodejs.org`
//! the first time it runs on a given `managed_toolchain_root()`; reports and
//! exits early with `BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED` otherwise.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
#[cfg(unix)]
use wht_corulix_core::{CancellationToken, Position, WorkspaceRootId};
#[cfg(unix)]
use wht_corulix_lsp::{
    DefinitionResult, DiagnosticsResult, LspProviderProfile, LspSession, Readiness,
};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState, uninstall};
#[cfg(unix)]
use wht_corulix_workspace::WorkspaceRoot;

// P17-W corrective P5: gated per-item, not file-level -- this file is
// genuinely mixed-platform (P3 census: 3 Unix-only tests + 1
// platform-neutral test, `real_ts6_managed_dependency_aware_uninstall_e2e`,
// which never references any of these five items), so a whole-file
// `#![cfg(unix)]` would incorrectly drop the neutral test on Windows too.
#[cfg(unix)]
const READINESS_TIMEOUT: Duration = Duration::from_secs(60);
const TLS_ID: &str = "typescript-language-server";
const TS6_ID: &str = "typescript-6-classic";
const NODE_ID: &str = "node-runtime";

/// Serializes every test in this file against the shared managed root --
/// same reasoning as `real_pyright_managed_e2e.rs`'s own
/// `REAL_PYRIGHT_SESSION_LOCK`: one test's `uninstall()` must never race
/// another's still-active session or provisioning state.
static REAL_TS6_SESSION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_ts6_session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_TS6_SESSION_LOCK
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

/// A real two-file cross-file project: `lib.<ext>` declares `target`,
/// `main.<ext>` imports and calls it. `config_name` is `tsconfig.json` or
/// `jsconfig.json`.
fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-lsp-ts6-managed-root-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

#[cfg(unix)]
fn temp_fixture_project(label: &str, ext: &str, config_name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-lsp-ts6-managed-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    // `checkJs: true` is required for `jsconfig.json` -- without it,
    // JavaScript-6 semantic diagnostics only cover syntax errors, never
    // module-resolution/type errors (proven empirically: the unresolved
    // `missingExport` import below reported zero diagnostics without this
    // flag). `tsconfig.json` is unaffected by the extra key.
    let _ = fs::write(
        root.join(config_name),
        r#"{"compilerOptions":{"target":"es2020","module":"es2020","moduleResolution":"bundler","checkJs":true}}"#,
    );
    let _ = fs::write(
        root.join(format!("lib.{ext}")),
        "export function target() {\n  return 1;\n}\n",
    );
    // `missingExport` does not exist in `lib.<ext>` -- a real, universally
    // reliable diagnostic (TypeScript flags it via static typing; the
    // JavaScript-6 language service flags it too, since import-resolution
    // checking applies regardless of `checkJs`) that does not depend on any
    // post-open edit or diagnostics-refresh timing.
    let _ = fs::write(
        root.join(format!("main.{ext}")),
        "import { target, missingExport } from './lib';\n\nexport function caller() {\n  target();\n  missingExport();\n}\n",
    );
    root
}

/// Provisions all three real managed artifacts (typescript-language-server
/// and its declared Node and TypeScript-6 dependencies) if not already
/// present. Returns `false` -- never an error -- if any cannot be
/// provisioned, so the caller can honestly report `BLOCKED`.
async fn ensure_managed_ts6_provisioned(root: &std::path::Path) -> bool {
    // P17-W: `_HOST_NATIVE` (not `_LINUX_X64` directly) -- resolved
    // natively on Windows unfixed, this helper would provision the Linux
    // Node install path while `typescript_language_server_managed()`'s own
    // `managed_interpreter` resolves `NODE_24_LTS_HOST_NATIVE` (Windows),
    // so `resolve_launch`/`resolve_launch_at` would never find it
    // provisioned -- `run_full_vertical` would fail with "did not resolve
    // via CORULIX_MANAGED live routing", not silently pass.
    let node_manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
    let ts6_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE;
    let tls_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE;

    let (node_state, _) = provisioning::resolve_managed_component(root, &node_manifest);
    if node_state != ManagedComponentState::Available
        && provisioning::provision(root, &node_manifest).await.is_err()
    {
        return false;
    }

    let (ts6_state, _) = provisioning::resolve_managed_component(root, &ts6_manifest);
    if ts6_state != ManagedComponentState::Available
        && provisioning::provision(root, &ts6_manifest).await.is_err()
    {
        return false;
    }

    let (tls_state, _) = provisioning::resolve_managed_component(root, &tls_manifest);
    if tls_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(root, &tls_manifest, &[NODE_ID, TS6_ID])
            .await
            .is_err()
    {
        return false;
    }
    true
}

#[cfg(unix)]
async fn resolve_ts6_managed(
    profile: &LspProviderProfile,
    workspace_root: &WorkspaceRoot,
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

/// Real, product-path full vertical for one language: spawn, `didOpen`,
/// readiness, cross-file `definition`, `hover`, a raw `textDocument/completion`
/// request (no typed wrapper exists yet -- issued directly through
/// `LspSession::transport`, the same escape hatch
/// `real_pyright_managed_e2e.rs`'s own post-uninstall probe already uses),
/// `documentSymbol`, and `diagnostics`.
#[cfg(unix)]
async fn run_full_vertical(
    language_label: &str,
    profile: LspProviderProfile,
    ext: &str,
    config_name: &str,
    root: &std::path::Path,
) -> Result<(), Box<dyn Error>> {
    let fixture =
        temp_fixture_project(&format!("full-vertical-{language_label}"), ext, config_name);
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let Some(launch) = resolve_ts6_managed(&profile, &workspace_root, root).await else {
        return Err(fail(
            "typescript_language_server_managed did not resolve via CORULIX_MANAGED live routing",
        ));
    };
    if !launch.executable.starts_with(root) {
        return Err(fail(format!(
            "expected the managed Node interpreter under {root:?}, got {:?}",
            launch.executable
        )));
    }
    let Some(script_argument) = launch.arguments.first() else {
        return Err(fail(
            "expected the typescript-language-server script path as argv[1]",
        ));
    };
    if !PathBuf::from(script_argument).starts_with(root) {
        return Err(fail(format!(
            "expected the managed typescript-language-server script under {root:?}, got {script_argument:?}"
        )));
    }
    let Some(extra_options) = &launch.extra_initialization_options else {
        return Err(fail(
            "expected extra_initialization_options carrying tsserver.path",
        ));
    };
    let Some(tsserver_path) = extra_options["tsserver"]["path"].as_str() else {
        return Err(fail("expected tsserver.path to be a string"));
    };
    if !PathBuf::from(tsserver_path).starts_with(root) {
        return Err(fail(format!(
            "expected the managed tsserver.path under {root:?}, got {tsserver_path:?}"
        )));
    }

    let cancellation = CancellationToken::new();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    let main_file = fixture.join(format!("main.{ext}"));
    let lib_file = fixture.join(format!("lib.{ext}"));
    session
        .ensure_open(&lib_file)
        .await
        .map_err(|error| fail(format!("opening lib fixture failed: {error:?}")))?;
    session
        .ensure_open(&main_file)
        .await
        .map_err(|error| fail(format!("opening main fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| {
            fail(format!(
                "{language_label} never reached readiness: {error:?}"
            ))
        })?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }

    // --- CROSS-FILE DEFINITION: from `main.<ext>`'s `target()` call site to
    // its real declaration in the *other* file, `lib.<ext>` -- proves real
    // project-model symbol resolution, not same-file parsing. ---
    let text = fs::read_to_string(&main_file)?;
    let call_offset = text
        .find("target();")
        .ok_or_else(|| fail("fixture text missing target() call"))?;
    let call_line = text[..call_offset].matches('\n').count() as u32;
    let definition = wht_corulix_lsp::definition(
        &session,
        &main_file,
        &Position {
            line_zero_based: call_line,
            byte_column_zero_based: 2,
            byte_offset: call_offset as u64,
        },
        &cancellation,
    )
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
    if !definition_location
        .path
        .relative_path
        .ends_with(&format!("lib.{ext}"))
    {
        return Err(fail(format!(
            "expected cross-file definition landing in lib.{ext}, got {:?}",
            definition_location.path
        )));
    }

    // --- HOVER: supporting evidence only, but must return something real
    // for a symbol with a resolvable type. ---
    let hover = wht_corulix_lsp::hover(
        &session,
        &main_file,
        &Position {
            line_zero_based: call_line,
            byte_column_zero_based: 2,
            byte_offset: call_offset as u64,
        },
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("hover request failed: {error:?}")))?;
    let Some(hover_evidence) = hover else {
        return Err(fail("expected real hover evidence, got None"));
    };
    if hover_evidence.contents.trim().is_empty() {
        return Err(fail("expected non-empty hover contents"));
    }

    // --- COMPLETION: a raw request (no typed wrapper exists yet in this
    // crate) at the end of `target` inside `caller`'s body, right after
    // typing `tar` -- proves genuine completion items, not a parser-only
    // response. ---
    let completion_line = text[..call_offset].matches('\n').count() as u32;
    let completion_params = serde_json::json!({
        "textDocument": { "uri": wht_corulix_lsp_uri_for_test(&main_file) },
        "position": { "line": completion_line, "character": 3 },
    });
    let completion_response = session
        .transport()
        .request(
            "textDocument/completion",
            completion_params,
            wht_corulix_lsp::DEFAULT_REQUEST_TIMEOUT,
            &cancellation,
        )
        .await
        .map_err(|error| fail(format!("completion request failed: {error:?}")))?;
    let has_items = completion_response
        .get("items")
        .and_then(|items| items.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or_else(|| {
            completion_response
                .as_array()
                .map(|items| !items.is_empty())
                .unwrap_or(false)
        });
    if !has_items {
        return Err(fail(format!(
            "expected genuine completion items, got {completion_response:?}"
        )));
    }

    // --- DOCUMENT SYMBOLS ---
    let document_symbols = wht_corulix_lsp::document_symbols(&session, &main_file, &cancellation)
        .await
        .map_err(|error| fail(format!("documentSymbol request failed: {error:?}")))?;
    if !document_symbols
        .iter()
        .any(|symbol| symbol.name == "caller")
    {
        return Err(fail(format!(
            "expected 'caller' among document symbols, got {document_symbols:?}"
        )));
    }

    // --- DIAGNOSTICS: the fixture's own `missingExport` unresolved import
    // must be reported as a real diagnostic. ---
    let diagnostics_result = wht_corulix_lsp::diagnostics(&session, &main_file)
        .await
        .map_err(|error| fail(format!("diagnostics call failed: {error:?}")))?;
    match diagnostics_result {
        DiagnosticsResult::Reported(diags) if !diags.is_empty() => {}
        other => {
            return Err(fail(format!(
                "expected a real reported diagnostic for the unresolved 'missingExport' import, got {other:?}"
            )));
        }
    }

    session.shutdown(&cancellation).await;

    // This test provisions onto the real, *shared* host-wide
    // `managed_toolchain_root()` -- it must remove everything it installed,
    // in dependency order, regardless of libtest's execution order among
    // this file's own tests (proven non-alphabetical-declaration-order in
    // practice: relying on "some other test in this file cleans up last"
    // is exactly the fragile assumption that let a leftover
    // `typescript-language-server` registration break both
    // `real_pyright_managed_e2e.rs`'s and `wht_corulix_tooling`'s own
    // `real_node_managed_lifecycle_e2e.rs`'s independent `node-runtime`
    // uninstall expectations during this same pass's mandatory full-suite
    // sweep -- found and fixed before this file's final version). Every
    // test in this file is therefore self-contained for cleanup, matching
    // `real_pyright_managed_e2e.rs`'s own single-test
    // vertical-then-uninstall precedent.
    let _ = uninstall::uninstall(
        root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    let _ = uninstall::uninstall(
        root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    let _ = uninstall::uninstall(
        root,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64.id,
        |_| {},
    )
    .await;

    let _ = fs::remove_dir_all(&fixture);
    eprintln!("{language_label}_LSP_E2E_MANAGED=PASS");
    Ok(())
}

/// Delegates to the crate's own [`wht_corulix_lsp::path_to_file_uri`]
/// rather than hand-rolling `file://` construction.
///
/// # Why (Phase 17-W-R15 finding)
///
/// The prior local implementation was `format!("file://{}",
/// path.display())`. On Linux this happens to produce a valid URI (an
/// absolute path already starts with `/`, giving the required `file:///`
/// three-slash form), but on Windows `path.display()` renders
/// backslash-separated, undecorated drive-letter paths
/// (`C:\Users\...\main.ts`), so the result
/// (`file://C:\Users\...\main.ts`) is not a well-formed `file://` URI:
/// wrong separators, no percent-encoding, and missing the leading `/`
/// before the drive letter that `path_to_file_uri` adds explicitly.
/// `session::ensure_open`/`session.rs`'s own document-open path already
/// uses `uri::path_to_file_uri` for the exact same fixture path, so the
/// two URIs silently diverged on Windows only: the document was open
/// under the *correct* URI, but this file's own hand-built
/// `textDocument/completion` request addressed the *malformed* one.
/// `typescript-language-server` has no open document under an unknown
/// URI, so it did not error -- it returned a well-formed, genuinely empty
/// `{"isIncomplete": false, "items": []}`, which read at a glance like a
/// real (if surprising) completion-provider defect rather than a
/// URI-construction mismatch confined to this test file. Root-caused by
/// comparing this helper against `uri::path_to_file_uri` (the same
/// function every other passing assertion in this test -- definition,
/// hover -- already goes through internally) rather than assuming the
/// product's completion handling was at fault.
#[cfg(unix)]
fn wht_corulix_lsp_uri_for_test(path: &std::path::Path) -> String {
    let Some(uri) = wht_corulix_lsp::path_to_file_uri(path) else {
        unreachable!("fixture path must be representable as a file:// URI")
    };
    uri.to_string()
}

// Windows note (M09/D96): `#[cfg(unix)]`-only. `run_full_vertical`'s
// `LspSession::spawn` call always fails closed on Windows via
// `ManagedProcess::spawn_with_workspace_root` (no `fchdir`-equivalent
// primitive to preserve object-bound cwd across `exec`) -- the same
// accepted, `FINAL_CLOSED` M09 contract already on record ("Windows:
// workspace-bound LSP UNAVAILABLE_FAIL_CLOSED, zero provider spawn").
#[cfg(unix)]
#[tokio::test]
async fn real_typescript_6_managed_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_ts6_session_lock().await;
    let root = temp_dir("typescript-full-vertical");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_managed_ts6_provisioned(&root).await {
        eprintln!(
            "TYPESCRIPT_LSP_E2E_MANAGED=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision managed Node/TypeScript-6/typescript-language-server in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    let result = run_full_vertical(
        "TYPESCRIPT",
        LspProviderProfile::typescript_language_server_managed(),
        "ts",
        "tsconfig.json",
        &root,
    )
    .await;
    let _ = fs::remove_dir_all(&root);
    result
}

// Windows note (M09/D96): `#[cfg(unix)]`-only, same reason as this file's
// sibling `real_typescript_6_managed_full_vertical_e2e` above -- shares the
// same `run_full_vertical` helper and its `LspSession::spawn` call.
#[cfg(unix)]
#[tokio::test]
async fn real_javascript_6_managed_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_ts6_session_lock().await;
    let root = temp_dir("javascript-full-vertical");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_managed_ts6_provisioned(&root).await {
        eprintln!(
            "JAVASCRIPT_LSP_E2E_MANAGED=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision managed Node/TypeScript-6/typescript-language-server in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    let result = run_full_vertical(
        "JAVASCRIPT",
        LspProviderProfile::typescript_language_server_managed_for_javascript(),
        "js",
        "jsconfig.json",
        &root,
    )
    .await;
    let _ = fs::remove_dir_all(&root);
    result
}

/// Dependency-aware uninstall of the full three-node graph: TLS first (its
/// own removal must succeed even though Node/TypeScript-6 -- its declared
/// dependencies -- are still installed), then TypeScript-6, then Node.
#[tokio::test]
async fn real_ts6_managed_dependency_aware_uninstall_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_ts6_session_lock().await;
    let root = temp_dir("dependency-aware-uninstall");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_managed_ts6_provisioned(&root).await {
        eprintln!(
            "TS6_DEPENDENCY_AWARE_UNINSTALL=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision managed Node/TypeScript-6/typescript-language-server in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let tls_removed = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    if tls_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected typescript-language-server uninstall to succeed, got {tls_removed:?}"
        )));
    }
    let ts6_removed = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    if ts6_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected typescript-6-classic uninstall to succeed once undepended, got {ts6_removed:?}"
        )));
    }
    let node_removed = uninstall::uninstall(
        &root,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64.id,
        |_| {},
    )
    .await;
    if node_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected Node uninstall to succeed once undepended, got {node_removed:?}"
        )));
    }

    // Second uninstall of each must be idempotent -- no root/state
    // recreation, and each must honestly report `AlreadyRemoved`.
    for id in [TLS_ID, TS6_ID, NODE_ID] {
        let second =
            uninstall::uninstall(&root, provisioning::ManagedComponentId(id), |_| {}).await;
        if second != Ok(uninstall::UninstallOutcome::AlreadyRemoved) {
            return Err(fail(format!(
                "expected second uninstall of {id} to report AlreadyRemoved (idempotent), got {second:?}"
            )));
        }
    }

    let _ = fs::remove_dir_all(&root);
    eprintln!("TS6_DEPENDENCY_AWARE_UNINSTALL=PASS");
    eprintln!("TS6_SECOND_UNINSTALL_IDEMPOTENT=PASS");
    Ok(())
}

/// Phase 7B-B1-R3-A §8's active-uninstall-safety model, applied to the
/// managed TS6 backend: the session is left genuinely active (no
/// `session.shutdown()` before `uninstall()`) -- `uninstall()`'s ACTIVE
/// EXECUTION DISCOVERY + MANAGED PROCESS SHUTDOWN stage must discover and
/// stop it itself, proven both by the lease reaching `Stopped` and by a
/// post-uninstall request against this session's own transport failing.
// Windows note (M09/D96): `#[cfg(unix)]`-only -- this test's own direct
// `LspSession::spawn` call always fails closed on Windows, same reason as
// this file's other two Unix-gated tests above.
#[cfg(unix)]
#[tokio::test]
async fn real_ts6_managed_active_provider_uninstall_safety_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_ts6_session_lock().await;
    let root = temp_dir("active-provider-uninstall-safety");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_managed_ts6_provisioned(&root).await {
        eprintln!(
            "TS6_ACTIVE_PROVIDER_UNINSTALL_SAFETY=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision managed Node/TypeScript-6/typescript-language-server in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    let fixture = temp_fixture_project("active-uninstall-safety", "ts", "tsconfig.json");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let profile = LspProviderProfile::typescript_language_server_managed();
    let Some(launch) = resolve_ts6_managed(&profile, &workspace_root, &root).await else {
        return Err(fail(
            "typescript_language_server_managed did not resolve via CORULIX_MANAGED live routing",
        ));
    };

    let cancellation = CancellationToken::new();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;

    let main_file = fixture.join("main.ts");
    session
        .ensure_open(&main_file)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("managed TS6 never reached readiness: {error:?}")))?;

    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Active) => {}
        other => {
            return Err(fail(format!(
                "expected lease state Active before uninstall, got {other:?}"
            )));
        }
    }

    let tls_removed = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    if tls_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected uninstall to succeed against an active TS6 session (stopping it itself), got {tls_removed:?}"
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
            "expected the TS6 transport to be closed after uninstall stopped the process, but a request still succeeded",
        ));
    }

    let ts6_removed = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    if ts6_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected TypeScript-6 uninstall to succeed once undepended, got {ts6_removed:?}"
        )));
    }
    let node_removed = uninstall::uninstall(
        &root,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64.id,
        |_| {},
    )
    .await;
    if node_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected Node uninstall to succeed once undepended, got {node_removed:?}"
        )));
    }

    let _ = fs::remove_dir_all(&fixture);
    let _ = fs::remove_dir_all(&root);
    eprintln!("TS6_ACTIVE_PROVIDER_UNINSTALL_SAFETY=PASS");
    eprintln!("TS6_LEASE_LIFECYCLE=PASS");
    Ok(())
}
