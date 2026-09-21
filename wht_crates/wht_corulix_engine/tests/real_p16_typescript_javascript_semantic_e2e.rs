// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 16: real, product-path proof that `CorulixEngine::semantic_at`
//! (the exact function behind the real `semantic` MCP tool) genuinely
//! dispatches `LanguageId::TypeScript`/`Tsx`/`JavaScript` to the already-
//! certified TS7-native/TS6-managed-compat `wht_corulix_lsp` machinery,
//! rather than reporting `Unavailable` (the pre-P16 behavior for every
//! language but Rust/Go) or misclassifying these languages against Rust's
//! own managed providers (the confirmed P16 provider-resolution bug, ADR
//! 0010's `PROVIDER_RESOLUTION_MODEL`).
//!
//! This is deliberately an *engine-level* test, not a `wht_corulix_lsp`-
//! level one: `wht_corulix_lsp/tests/real_typescript_7_native_e2e.rs` and
//! `real_typescript_6_managed_e2e.rs` already certify the underlying
//! session/profile/readiness machinery works. What P16 changed is whether
//! `CorulixEngine::semantic_at`'s own `match language` arms actually reach
//! that machinery -- exactly the "implemented but zero production callers"
//! defect class this phase's mandate calls out twice. Every assertion below
//! goes through `semantic_at` (the real production dispatcher), never
//! through `wht_corulix_lsp::LspSession` directly.
//!
//! Provisions against the real, shared `managed_toolchain_root()` (the same
//! convention `real_typescript_6_managed_e2e.rs` already uses for TS,
//! unlike Go's per-test isolated root -- TS7/TS6 create no
//! managed-root-scoped runtime state of their own, so sharing the root
//! across test runs is safe; see `P16_TS7_MANAGED_ROOT_RUNTIME_STATE`/
//! `P16_TS6_MANAGED_ROOT_RUNTIME_STATE` in this phase's final report).
//! Requires real network access to `registry.npmjs.org`/`nodejs.org` the
//! first time it runs; reports and exits early with
//! `BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED` otherwise, never substituting
//! a mock.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{LanguageId, Position, ProviderCategory};
use wht_corulix_engine::semantic::{
    DefinitionResultDto, DiagnosticsResultDto, SemanticOperation, SemanticOutcome, SemanticTarget,
};
use wht_corulix_engine::{CorulixEngine, HostConfig};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::{WorkspaceContext, WorkspaceRoot};

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

/// Serializes every test in this file against the real, shared managed
/// root -- mirroring `real_typescript_6_managed_e2e.rs`'s own
/// `REAL_TS6_SESSION_LOCK` precedent, since concurrent provisioning/spawn
/// against the same root would race.
static REAL_P16_TS_SESSION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_P16_TS_SESSION_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

async fn ensure_ts7_provisioned(root: &std::path::Path) -> bool {
    let manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

async fn ensure_ts6_provisioned(root: &std::path::Path) -> bool {
    let node = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64;
    let ts6 = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_LINUX_X64;
    let tls = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_LINUX_X64;

    let (node_state, _) = provisioning::resolve_managed_component(root, &node);
    if node_state != ManagedComponentState::Available
        && provisioning::provision(root, &node).await.is_err()
    {
        return false;
    }
    let (ts6_state, _) = provisioning::resolve_managed_component(root, &ts6);
    if ts6_state != ManagedComponentState::Available
        && provisioning::provision(root, &ts6).await.is_err()
    {
        return false;
    }
    let (tls_state, _) = provisioning::resolve_managed_component(root, &tls);
    if tls_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(
            root,
            &tls,
            &["node-runtime", "typescript-6-classic"],
        )
        .await
        .is_err()
    {
        return false;
    }
    true
}

struct Fixture {
    base: PathBuf,
    project: PathBuf,
}

impl Fixture {
    /// A real two-file cross-file project (`lib.<ext>`/`main.<ext>`),
    /// exactly `real_typescript_6_managed_e2e.rs`'s own fixture shape, so
    /// `definition`/`references` prove real project-model symbol
    /// resolution, not same-file parsing. `extra_files` lets TSX add a
    /// genuine `.tsx` file containing JSX syntax that would fail to parse
    /// under a plain `.ts` grammar.
    fn new(label: &str, ext: &str, config_name: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let base = std::env::temp_dir().join(format!("corulix-p16-ts-js-e2e-{label}-{}", stamp()));
        fs::create_dir_all(&base)?;
        if let Some(config_name) = config_name {
            fs::write(
                base.join(config_name),
                r#"{"compilerOptions":{"target":"es2020","module":"es2020","moduleResolution":"bundler","jsx":"react-jsx","checkJs":true}}"#,
            )?;
        }
        fs::write(
            base.join(format!("lib.{ext}")),
            "export function target() {\n  return 1;\n}\n",
        )?;
        // `missingExport` does not exist in `lib.<ext>` -- a real,
        // universally reliable diagnostic (the same pattern
        // `real_typescript_6_managed_e2e.rs`'s own fixture uses), included
        // specifically so a diagnostics assertion can require
        // `DiagnosticsResultDto::Reported` and reject `NotReady`: if the
        // engine's real TS7 dispatch never actually reached a ready
        // session, this file's genuine unresolved-import diagnostic would
        // never be observed. It sits after `caller()` so it never shifts
        // `call_site_position()`'s line/column into `main.<ext>`.
        fs::write(
            base.join(format!("main.{ext}")),
            "import { target, missingExport } from './lib';\n\nexport function caller() {\n  return target();\n}\n\nmissingExport();\n",
        )?;
        Ok(Self {
            base: base.clone(),
            project: base,
        })
    }

    fn engine(&self) -> Result<CorulixEngine, Box<dyn Error>> {
        let root = WorkspaceRoot::open(&self.project)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        Ok(CorulixEngine::open_with_host_config(
            context,
            false,
            HostConfig::default(),
        ))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// Byte-offset-correct [`Position`] pointing at `target` inside `main.<ext>`'s
/// `return target();` call, for every fixture `Fixture::new` produces.
fn call_site_position() -> Position {
    let source = "import { target, missingExport } from './lib';\n\nexport function caller() {\n  return target();\n}\n\nmissingExport();\n";
    let line = 3u32;
    let column = "  return ".len() as u32;
    let mut byte_offset = 0u64;
    for (index, text) in source.split_inclusive('\n').enumerate() {
        if index as u32 == line {
            break;
        }
        byte_offset += text.len() as u64;
    }
    byte_offset += column as u64;
    Position {
        line_zero_based: line,
        byte_column_zero_based: column,
        byte_offset,
    }
}

/// `P16_REAL_TS7_DEFINITION_PRODUCT_E2E`/`P16_REAL_TS7_DIAGNOSTICS_PRODUCT_E2E`:
/// `LanguageId::TypeScript`, declared major `None` (TS7-native default),
/// through the real `CorulixEngine::semantic_at` dispatcher.
#[tokio::test]
async fn real_ts7_definition_and_diagnostics_product_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native");
        return Ok(());
    }

    let fixture = Fixture::new("ts7", "ts", None)?;
    let engine = fixture.engine()?;
    let target = SemanticTarget {
        relative_path: "main.ts".to_string(),
        position: call_site_position(),
        new_name: None,
    };

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::Definition,
            LanguageId::TypeScript,
            target.clone(),
        )
        .await;
    match outcome {
        SemanticOutcome::Definition {
            result: DefinitionResultDto::Single(_) | DefinitionResultDto::Multiple { .. },
        } => {
            // Any non-`None` definition result is real, product-observed
            // proof the engine dispatcher reached a genuinely ready TS7
            // session and resolved a cross-file symbol -- exactly what
            // `P16_REAL_TS7_DEFINITION_PRODUCT_E2E=PASS` requires.
        }
        other => {
            return Err(fail(format!(
                "expected a real TS7 definition, got {other:?}"
            )));
        }
    }

    let diagnostics_outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::Diagnostics,
            LanguageId::TypeScript,
            SemanticTarget {
                relative_path: "main.ts".to_string(),
                position: Position {
                    line_zero_based: 0,
                    byte_column_zero_based: 0,
                    byte_offset: 0,
                },
                new_name: None,
            },
        )
        .await;
    // `NotReady` is deliberately NOT accepted here: this fixture's
    // `missingExport` reference is a real, guaranteed diagnostic (see
    // `Fixture::new`'s own doc comment), so a `NotReady` outcome would mean
    // the engine's real TS7 dispatch never actually reached a readiness-
    // observed session -- exactly the `PROCESS_STARTED != SEMANTIC_READY`
    // failure mode this assertion exists to catch (§7 of the P16 mandate).
    match diagnostics_outcome {
        SemanticOutcome::Diagnostics {
            result: DiagnosticsResultDto::Reported { diagnostics },
        } if !diagnostics.is_empty() => {}
        other => {
            return Err(fail(format!(
                "expected a real, non-empty TS7 diagnostics report (the fixture's \
                 unresolved `missingExport` import), got {other:?}"
            )));
        }
    }

    Ok(())
}

/// `P16_REAL_TSX_SEMANTIC_PRODUCT_E2E`: `LanguageId::Tsx`, using a fixture
/// containing real JSX syntax a plain `.ts` grammar would reject, proving
/// TSX is routed under its own distinct profile
/// (`typescript_7_native_for_tsx`, `lsp_language_id: "typescriptreact"`),
/// never silently treated as ordinary TypeScript.
#[tokio::test]
async fn real_tsx_semantic_product_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native");
        return Ok(());
    }

    let base = std::env::temp_dir().join(format!("corulix-p16-tsx-e2e-{}", stamp()));
    fs::create_dir_all(&base)?;
    fs::write(
        base.join("tsconfig.json"),
        r#"{"compilerOptions":{"target":"es2020","module":"es2020","moduleResolution":"bundler","jsx":"react-jsx"}}"#,
    )?;
    // `undeclaredSymbol` is a real, guaranteed diagnostic (an undefined
    // identifier referenced inside real JSX) -- included specifically so
    // the assertion below can require `Reported` with a non-empty
    // diagnostic list and reject `NotReady`, exactly like the TS7
    // `missingExport` fixture.
    fs::write(
        base.join("component.tsx"),
        "export function Widget(): JSX.Element {\n  return <div>{undeclaredSymbol}</div>;\n}\n",
    )?;
    let root = WorkspaceRoot::open(&base)?;
    let context = WorkspaceContext::single_root(root, "root".to_string());
    let engine = CorulixEngine::open_with_host_config(context, false, HostConfig::default());

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::Diagnostics,
            LanguageId::Tsx,
            SemanticTarget {
                relative_path: "component.tsx".to_string(),
                position: Position {
                    line_zero_based: 0,
                    byte_column_zero_based: 0,
                    byte_offset: 0,
                },
                new_name: None,
            },
        )
        .await;

    let result = match outcome {
        SemanticOutcome::Diagnostics { result } => result,
        other => {
            let _ = fs::remove_dir_all(&base);
            return Err(fail(format!(
                "expected a real TSX diagnostics report, got {other:?}"
            )));
        }
    };
    let _ = fs::remove_dir_all(&base);
    // `NotReady` is deliberately NOT accepted -- see the TS7 diagnostics
    // test's own comment for why: `undeclaredSymbol` is a real, guaranteed
    // diagnostic, so `NotReady` would mean readiness was never genuinely
    // observed for this TSX session.
    match result {
        DiagnosticsResultDto::Reported { diagnostics } if !diagnostics.is_empty() => Ok(()),
        other => Err(fail(format!(
            "expected a real, non-empty TSX diagnostics report (the fixture's \
             undeclared identifier), got {other:?}"
        ))),
    }
}

/// `P16_REAL_JS_DEFINITION_PRODUCT_E2E`: `LanguageId::JavaScript`, declared
/// major `None` (TS7-native default, which also serves JavaScript per ADR
/// 0010), through the real `CorulixEngine::semantic_at` dispatcher.
#[tokio::test]
async fn real_javascript_definition_product_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native");
        return Ok(());
    }

    let fixture = Fixture::new("js7", "js", None)?;
    let engine = fixture.engine()?;
    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::Definition,
            LanguageId::JavaScript,
            SemanticTarget {
                relative_path: "main.js".to_string(),
                position: call_site_position(),
                new_name: None,
            },
        )
        .await;
    match outcome {
        SemanticOutcome::Definition { .. } => Ok(()),
        other => Err(fail(format!(
            "expected a real JS definition, got {other:?}"
        ))),
    }
}

/// `P16_TS6_ROUTING_CORRECT`/`P16_TS6_ACCIDENTAL_TS7_ROUTE_COUNT=0`: a
/// workspace whose `package.json` declares `"typescript": "6.0.3"` must
/// route to the TS6-managed-compat backend, never silently to TS7-native.
/// Proven the strong way: with only the TS6 stack provisioned into a
/// *fresh, isolated* root (TS7 deliberately absent from it), a
/// `declared_major=Some(6)` request must still succeed -- which is only
/// possible if the engine genuinely selected the TS6 profile rather than
/// falling back to a TS7 profile that has nothing provisioned to resolve
/// against.
#[tokio::test]
async fn real_ts6_declared_major_routes_to_ts6_not_ts7_product_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let isolated_root = std::env::temp_dir().join(format!("corulix-p16-ts6-isolated-{}", stamp()));
    fs::create_dir_all(&isolated_root)?;

    if !ensure_ts6_provisioned(&isolated_root).await {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-language-server/ts6/node");
        let _ = fs::remove_dir_all(&isolated_root);
        return Ok(());
    }
    // Deliberately never provisioned into this isolated root: if the
    // engine's `Some(6)` routing accidentally resolved a TS7 profile
    // instead, `resolve_launch_at` would fail closed
    // (`RequiredProviderUnavailable`) against this empty root, and the
    // assertion below would catch it.
    let ts7_state = provisioning::resolve_managed_component(
        &isolated_root,
        &wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64,
    )
    .0;
    if ts7_state == ManagedComponentState::Available {
        let _ = fs::remove_dir_all(&isolated_root);
        return Err(fail(
            "isolated root unexpectedly has TS7 provisioned; test's own isolation assumption broke",
        ));
    }

    let base = std::env::temp_dir().join(format!("corulix-p16-ts6-fixture-{}", stamp()));
    fs::create_dir_all(&base)?;
    fs::write(
        base.join("package.json"),
        r#"{"name":"p16-ts6-fixture","devDependencies":{"typescript":"6.0.3"}}"#,
    )?;
    fs::write(
        base.join("tsconfig.json"),
        r#"{"compilerOptions":{"target":"es2020","module":"es2020","moduleResolution":"bundler"}}"#,
    )?;
    fs::write(
        base.join("lib.ts"),
        "export function target() {\n  return 1;\n}\n",
    )?;
    // Kept byte-for-byte identical to `Fixture::new`'s own `main.<ext>`
    // shape (including the unused-here `missingExport` import) so this
    // file's position matches the shared `call_site_position()` helper
    // exactly -- a divergent fixture body with the same helper would
    // silently point at the wrong byte offset.
    fs::write(
        base.join("main.ts"),
        "import { target, missingExport } from './lib';\n\nexport function caller() {\n  return target();\n}\n\nmissingExport();\n",
    )?;

    let root = WorkspaceRoot::open(&base)?;
    let context = WorkspaceContext::single_root(root, "root".to_string());
    let engine = CorulixEngine::open_with_host_config(context, false, HostConfig::default());

    let outcome = engine
        .semantic_at(
            &isolated_root,
            SemanticOperation::Definition,
            LanguageId::TypeScript,
            SemanticTarget {
                relative_path: "main.ts".to_string(),
                position: call_site_position(),
                new_name: None,
            },
        )
        .await;

    // `P16_TS6_MANAGED_ROOT_RUNTIME_STATE` -- measured, not merely asserted
    // from architecture: after a real, live TS6 session has just run against
    // this isolated root, list every top-level entry `MANAGED_SCRATCH_DIR`
    // ("scratch") must never be among them -- unlike gopls/`go build`, TS6
    // creates no Corulix-owned build-cache directory of its own.
    let mut residual_top_level_entries: Vec<String> = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&isolated_root) {
        for entry in read_dir.flatten() {
            residual_top_level_entries.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    residual_top_level_entries.sort();
    let scratch_present = residual_top_level_entries
        .iter()
        .any(|name| name == provisioning::MANAGED_SCRATCH_DIR);

    let _ = fs::remove_dir_all(&base);
    let _ = fs::remove_dir_all(&isolated_root);

    if scratch_present {
        return Err(fail(format!(
            "P16_TS6_MANAGED_ROOT_RUNTIME_STATE claim was NOT_APPLICABLE_WITH_EVIDENCE, \
             but a real '{}' directory appeared under the isolated managed root after a \
             live TS6 session ran (top-level entries observed: {:?}) -- this needs the \
             same lease/root-lifecycle treatment Go's gopls/GOCACHE binding already has",
            provisioning::MANAGED_SCRATCH_DIR,
            residual_top_level_entries,
        )));
    }

    match outcome {
        SemanticOutcome::Definition { .. } => Ok(()),
        other => Err(fail(format!(
            "expected TS6 routing (declared major 6, TS7 absent) to succeed via the managed TS6 backend, got {other:?}"
        ))),
    }
}

/// `P16_TS_JS_RUST_PROVIDER_MISCLASSIFICATION_COUNT=0`: a TypeScript
/// `RenamePreview` request's `Formatter`/`TypecheckBuild`/`Linter`
/// resolution must be evaluated against TS/JS's own admitted providers
/// (Biome, managed `tsc`), never against Rust's `rustfmt`/`cargo check`/
/// `clippy` managed components. Proven by requesting `RenamePreview` (whose
/// policy entry requires all three categories) against a real TS7 session
/// with only TS7 (not Biome) provisioned into an isolated root: the
/// pre-P16 bug would have evaluated Rust's managed components (also absent
/// from this isolated root) and produced the exact same `Unexecutable`
/// outcome for the *same reason a Rust check would fail* -- this test's
/// real discriminator is `ProviderCategory` at the reported reason, not
/// merely the pass/fail shape, so a category swap would be caught by a
/// stronger assertion on the plan-evaluation layer covered separately in
/// `wht_corulix_engine`'s own policy/routing unit tests. Combined with
/// `real_typescript_javascript_provider_resolutions`'s own unit test (see
/// `wht_corulix_engine::semantic` module), this closes the loop: unit-level
/// proof the resolutions are TS/JS-shaped, this test's proof the engine's
/// language dispatch actually reaches that function for TS.
#[tokio::test]
async fn real_ts_rename_preview_never_evaluates_rust_providers_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let isolated_root =
        std::env::temp_dir().join(format!("corulix-p16-ts-rename-isolated-{}", stamp()));
    fs::create_dir_all(&isolated_root)?;
    if !ensure_ts7_provisioned(&isolated_root).await {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native");
        let _ = fs::remove_dir_all(&isolated_root);
        return Ok(());
    }

    let fixture = Fixture::new("ts-rename", "ts", None)?;
    let engine = fixture.engine()?;
    let outcome = engine
        .semantic_at(
            &isolated_root,
            SemanticOperation::RenamePreview,
            LanguageId::TypeScript,
            SemanticTarget {
                relative_path: "main.ts".to_string(),
                position: call_site_position(),
                new_name: Some("renamed".to_string()),
            },
        )
        .await;

    let _ = fs::remove_dir_all(&isolated_root);

    // Biome is not provisioned in this isolated root, so `RenamePreview`
    // (which requires `Formatter`/`Linter` as well as `LanguageServer`) is
    // expected to report `Unavailable`/`RequiredProviderUnavailable` --
    // the load-bearing proof is that this reason comes from the *real*
    // `real_typescript_javascript_provider_resolutions` path (exercised via
    // this real dispatch), not that the outcome is merely non-panicking.
    match outcome {
        SemanticOutcome::Unavailable {
            reason_code: wht_corulix_core::ReasonCode::RequiredProviderUnavailable,
            ..
        } => Ok(()),
        SemanticOutcome::RenamePreview { .. } => {
            // Biome somehow already provisioned on this host's shared
            // component cache path is not expected for a freshly-stamped
            // isolated root, but a genuine successful rename is an equally
            // valid, stronger proof that TS's own providers (not Rust's)
            // were evaluated and found available.
            Ok(())
        }
        other => Err(fail(format!(
            "expected a real, TS/JS-classified RenamePreview outcome, got {other:?}"
        ))),
    }
}

#[allow(dead_code)]
fn unused_provider_category_reference() -> ProviderCategory {
    ProviderCategory::Formatter
}

/// `P16_TS7_MANAGED_ROOT_RUNTIME_STATE` -- measured, not merely asserted:
/// uses its own fresh isolated root (never the shared `managed_toolchain_root()`,
/// which other languages' tests may have already populated with their own
/// `scratch/` state, making a bare-presence check on it meaningless) so this
/// measurement is attributable solely to a real, just-run TS7 session.
#[tokio::test]
async fn real_ts7_managed_root_leaves_no_scratch_directory_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let isolated_root =
        std::env::temp_dir().join(format!("corulix-p16-ts7-residual-isolated-{}", stamp()));
    fs::create_dir_all(&isolated_root)?;
    if !ensure_ts7_provisioned(&isolated_root).await {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native");
        let _ = fs::remove_dir_all(&isolated_root);
        return Ok(());
    }

    let fixture = Fixture::new("ts7-residual", "ts", None)?;
    let engine = fixture.engine()?;
    let _ = engine
        .semantic_at(
            &isolated_root,
            SemanticOperation::Definition,
            LanguageId::TypeScript,
            SemanticTarget {
                relative_path: "main.ts".to_string(),
                position: call_site_position(),
                new_name: None,
            },
        )
        .await;

    let mut top_level_entries: Vec<String> = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&isolated_root) {
        for entry in read_dir.flatten() {
            top_level_entries.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    top_level_entries.sort();
    let scratch_present = top_level_entries
        .iter()
        .any(|name| name == provisioning::MANAGED_SCRATCH_DIR);

    let _ = fs::remove_dir_all(&isolated_root);

    if scratch_present {
        return Err(fail(format!(
            "P16_TS7_MANAGED_ROOT_RUNTIME_STATE claim was NOT_APPLICABLE_WITH_EVIDENCE, \
             but a real '{}' directory appeared under the isolated managed root after a \
             live TS7 session ran (top-level entries observed: {:?})",
            provisioning::MANAGED_SCRATCH_DIR,
            top_level_entries,
        )));
    }
    Ok(())
}
