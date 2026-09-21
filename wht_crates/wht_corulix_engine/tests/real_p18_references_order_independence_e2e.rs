// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 18: real, product-path regression proof for the M03 `references`
//! root-cause fix (`wht_corulix_lsp::project_priming`).
//!
//! Root cause (M03 references root-cause trace, JavaScript, inferred-
//! project mode): `LspSession::ensure_open` opened only the query's own
//! anchor file per call, so the underlying TypeScript-family provider's
//! inferred-project file set -- and therefore its `references` answer --
//! silently depended on which unrelated documents earlier, unrelated calls
//! happened to have already opened, rather than on the query itself. Proven
//! directly: the identical declaration-anchored query returned an empty
//! set, then (after other files entered session state) the complete set,
//! with no other input changed.
//!
//! This fixture is deliberately independent of every M03 benchmark file
//! (Section 15 of the fix mandate) -- a fresh three-module JavaScript
//! project (`decl.js`/`refA.js`/`refB.js`) plus one same-name decoy
//! (`decoy.js`), with no `jsconfig.json`, so the provider is genuinely in
//! inferred-project mode (exactly the scenario the fix targets).
//!
//! Every assertion goes through `CorulixEngine::semantic_at` (the real
//! production dispatcher), mirroring
//! `real_p16_typescript_javascript_semantic_e2e.rs`'s own conventions.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{LanguageId, Position};
use wht_corulix_engine::semantic::{
    ReferencesResultDto, SemanticLocationDto, SemanticOperation, SemanticOutcome, SemanticTarget,
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

/// Mirrors `real_p16_typescript_javascript_semantic_e2e.rs`'s own
/// `REAL_P16_TS_SESSION_LOCK` precedent: serializes every test in this file
/// against the real, shared managed root.
static REAL_P18_TS_SESSION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_P18_TS_SESSION_LOCK
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

const DECL_SOURCE: &str = "export function target() {\n  return 1;\n}\n";
const REF_A_SOURCE: &str = "import { target } from './decl';\n\n// target is also mentioned here in a comment, not a real usage.\nconst NOTE = \"target appears in this string too\";\n\nexport function useA() {\n  return target();\n}\n";
const REF_B_SOURCE: &str =
    "import { target } from './decl';\n\nexport function useB() {\n  return target();\n}\n";
const DECOY_SOURCE: &str = "// A same-named, unrelated local function -- a distinct symbol from\n// decl.js's target, never importing it, in its own module scope.\nfunction target() {\n  return 999;\n}\n\nexport function decoyOnly() {\n  return target();\n}\n";

/// Byte-offset-correct [`Position`] for a `needle` occurrence on
/// `line_zero_based` within `source`, computed the same way
/// `real_p16_typescript_javascript_semantic_e2e.rs`'s own
/// `call_site_position` does.
fn position_of(source: &str, line_zero_based: u32, needle: &str) -> Position {
    let mut byte_offset = 0u64;
    for (index, text) in source.split_inclusive('\n').enumerate() {
        if index as u32 == line_zero_based {
            let column = text.find(needle).unwrap_or(0) as u32;
            return Position {
                line_zero_based,
                byte_column_zero_based: column,
                byte_offset: byte_offset + u64::from(column),
            };
        }
        byte_offset += text.len() as u64;
    }
    Position {
        line_zero_based,
        byte_column_zero_based: 0,
        byte_offset,
    }
}

struct ThreeModuleFixture {
    base: PathBuf,
}

impl ThreeModuleFixture {
    /// A real, independent three-module project (declaration + two genuine
    /// call-site references) plus one same-name decoy, no `jsconfig.json`
    /// -- deliberately inferred-project mode, the exact condition the M03
    /// root cause requires.
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let base = std::env::temp_dir().join(format!("corulix-p18-ref-order-{label}-{}", stamp()));
        fs::create_dir_all(&base)?;
        fs::write(base.join("decl.js"), DECL_SOURCE)?;
        fs::write(base.join("refA.js"), REF_A_SOURCE)?;
        fs::write(base.join("refB.js"), REF_B_SOURCE)?;
        fs::write(base.join("decoy.js"), DECOY_SOURCE)?;
        Ok(Self { base })
    }

    fn engine(&self) -> Result<CorulixEngine, Box<dyn Error>> {
        let root = WorkspaceRoot::open(&self.base)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        Ok(CorulixEngine::open_with_host_config(
            context,
            false,
            HostConfig::default(),
        ))
    }
}

impl Drop for ThreeModuleFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// The true, expected reference set once project visibility is
/// deterministic: both genuine call sites (`refA.js`/`refB.js`), never the
/// declaration itself (`include_declaration: false` is hard-coded in
/// `wht_corulix_lsp::operations::references`), never the comment/string
/// mentions in `refA.js`, and never `decoy.js`'s own unrelated local
/// `target`.
fn assert_expected_reference_set(
    outcome: &SemanticOutcome,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    let SemanticOutcome::References {
        result: ReferencesResultDto::Found { locations },
    } = outcome
    else {
        return Err(fail(format!(
            "{context}: expected References::Found, got {outcome:?}"
        )));
    };
    let mut relative_paths: Vec<&str> = locations
        .iter()
        .map(|location: &SemanticLocationDto| location.relative_path.as_str())
        .collect();
    relative_paths.sort_unstable();

    if relative_paths.iter().any(|path| path.contains("decoy")) {
        return Err(fail(format!(
            "{context}: decoy.js's unrelated local target must never appear as a reference, got {relative_paths:?}"
        )));
    }
    if relative_paths.iter().any(|path| path.contains("decl.js")) {
        return Err(fail(format!(
            "{context}: the declaration itself must never appear as a reference, got {relative_paths:?}"
        )));
    }
    if relative_paths != vec!["refA.js", "refB.js"] {
        return Err(fail(format!(
            "{context}: expected exactly [refA.js, refB.js], got {relative_paths:?}"
        )));
    }
    Ok(())
}

/// `REFERENCES_ORDER_INDEPENDENCE_TEST`/`REFERENCES_FRESH_SESSION_COMPLETE`:
/// three fresh sessions, three different anchors (declaration/reference A/
/// reference B), each with zero prior semantic calls of its own. Before the
/// fix, only the declaration anchor (ORDER_A) was even exercised by this
/// scenario shape and it returned an empty set on a truly fresh session
/// (M03 root-cause trace); this test additionally proves ORDER_B/ORDER_C
/// converge on the identical, complete set from a fresh session too.
#[tokio::test]
async fn real_references_order_independence_fresh_sessions_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native");
        return Ok(());
    }

    // ORDER_A: declaration first, on its own fresh session/engine/fixture.
    {
        let fixture = ThreeModuleFixture::new("order-a")?;
        let engine = fixture.engine()?;
        let outcome = engine
            .semantic_at(
                &managed_root,
                SemanticOperation::References,
                LanguageId::JavaScript,
                SemanticTarget {
                    relative_path: "decl.js".to_string(),
                    position: position_of(DECL_SOURCE, 0, "target"),
                    new_name: None,
                },
            )
            .await;
        assert_expected_reference_set(&outcome, "ORDER_A (declaration anchor, fresh session)")?;
    }

    // ORDER_B: reference A first, on its own fresh session/engine/fixture.
    {
        let fixture = ThreeModuleFixture::new("order-b")?;
        let engine = fixture.engine()?;
        let outcome = engine
            .semantic_at(
                &managed_root,
                SemanticOperation::References,
                LanguageId::JavaScript,
                SemanticTarget {
                    relative_path: "refA.js".to_string(),
                    position: position_of(REF_A_SOURCE, 6, "target"),
                    new_name: None,
                },
            )
            .await;
        assert_expected_reference_set(&outcome, "ORDER_B (reference-A anchor, fresh session)")?;
    }

    // ORDER_C: reference B first, on its own fresh session/engine/fixture.
    {
        let fixture = ThreeModuleFixture::new("order-c")?;
        let engine = fixture.engine()?;
        let outcome = engine
            .semantic_at(
                &managed_root,
                SemanticOperation::References,
                LanguageId::JavaScript,
                SemanticTarget {
                    relative_path: "refB.js".to_string(),
                    position: position_of(REF_B_SOURCE, 3, "target"),
                    new_name: None,
                },
            )
            .await;
        assert_expected_reference_set(&outcome, "ORDER_C (reference-B anchor, fresh session)")?;
    }

    Ok(())
}

/// `REFERENCES_IDENTICAL_QUERY_STABLE`: the same anchor, queried twice
/// within the *same* session, with an unrelated `definition` call on a
/// different sibling file in between. Before the fix, this exact pattern
/// (declaration anchor, then other documents entering session state, then
/// the identical declaration anchor again) changed the result from empty to
/// complete (M03 root-cause trace's own decisive confirmatory experiment).
/// After the fix, both calls must already return the identical, complete
/// set -- priming is directory-content-driven, not history-driven, so
/// nothing should change between the two identical queries.
#[tokio::test]
async fn real_references_identical_query_stable_across_intervening_calls_e2e()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native");
        return Ok(());
    }

    let fixture = ThreeModuleFixture::new("stable")?;
    let engine = fixture.engine()?;
    let declaration_target = SemanticTarget {
        relative_path: "decl.js".to_string(),
        position: position_of(DECL_SOURCE, 0, "target"),
        new_name: None,
    };

    let first = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::References,
            LanguageId::JavaScript,
            declaration_target.clone(),
        )
        .await;
    assert_expected_reference_set(&first, "first declaration-anchored query")?;

    // Intervening, unrelated call against a different sibling file -- in
    // the pre-fix world, this is exactly what made the *next* declaration
    // query's result grow.
    let _ = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::Definition,
            LanguageId::JavaScript,
            SemanticTarget {
                relative_path: "refB.js".to_string(),
                position: position_of(REF_B_SOURCE, 3, "target"),
                new_name: None,
            },
        )
        .await;

    let second = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::References,
            LanguageId::JavaScript,
            declaration_target,
        )
        .await;
    assert_expected_reference_set(
        &second,
        "second declaration-anchored query (after intervening call)",
    )?;

    Ok(())
}
