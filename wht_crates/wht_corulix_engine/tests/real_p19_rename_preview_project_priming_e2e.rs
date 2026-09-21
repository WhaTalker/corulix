// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 19: real, product-path regression proof for the M03
//! `rename_preview` project-priming fix
//! (`wht_corulix_lsp::operations::rename_preview` now calls
//! `wht_corulix_lsp::project_priming::prime_same_project_documents`, mirroring
//! `references`'s own pre-existing call).
//!
//! Root cause (M03 TS/TSX rename_preview fresh-session determinism trace):
//! `rename_preview` never primed sibling documents before issuing
//! `textDocument/rename`, so a genuinely fresh session anchored at a
//! symbol's own declaration returned an edit confined to the declaration's
//! own file only -- never the importing file's specifier/call sites --
//! purely because that importing file had not yet been opened in the
//! session's history. Proven directly: the identical declaration-anchored
//! request returned 1 edit/1 file on a fresh session, then 4 edits/2 files
//! once project visibility existed (via a prior, unrelated `references`
//! call) -- with no other input changed. This mirrors the already-fixed
//! `references` defect class exactly (same root cause, same fix
//! mechanism).
//!
//! This fixture is deliberately independent of every M03 benchmark file
//! (same discipline as `real_p18_references_order_independence_e2e.rs`) --
//! a fresh two-module TS/TSX project (`decl.ts` declares, `importer.tsx`
//! imports and calls twice) plus one same-name decoy (`decoy.ts`), no
//! `tsconfig.json`, so the provider is genuinely in inferred-project mode.
//!
//! CANONICAL ANCHOR RESOLUTION (Corulix 1.0.0 M03 rename_preview AST-based
//! anchor classification pass): this file previously documented a SEPARATE,
//! known limitation -- even with full project visibility, anchoring the
//! rename request at a *usage* site in the importing file returned an edit
//! confined to that importing file alone (an aliased local rename), never
//! touching the declaration. That limitation is now closed for the specific
//! case it is safe to close: an ordinary value/call use of an imported
//! symbol, classified via `wht_corulix_syntax::classify_anchor_role` as
//! `AnchorRole::ValueUsage`, is redirected to its unique canonical
//! declaration (via the existing `definition` operation) before the rename
//! is issued, so its edit set is now identical to anchoring directly at the
//! declaration. An anchor placed on the import specifier itself, or on an
//! explicit alias binding, is deliberately NOT redirected -- the provider
//! gives no protocol-level signal distinguishing those positions from an
//! ordinary usage, so only the syntactically-provable case (a plain value/
//! call use) is canonicalized; provider-native local rename intent stays
//! preserved everywhere else. This file's own tests are the regression
//! proof for exactly that boundary -- do not weaken any assertion here
//! without corresponding root-cause evidence for the specific case changed.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{LanguageId, Position};
use wht_corulix_engine::semantic::{SemanticOperation, SemanticOutcome, SemanticTarget};
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

/// Mirrors `real_p18_references_order_independence_e2e.rs`'s own session
/// lock precedent: serializes every test in this file against the real,
/// shared managed root.
static REAL_P19_TS_SESSION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_P19_TS_SESSION_LOCK
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

async fn ensure_biome_provisioned(root: &std::path::Path) -> bool {
    let manifest = wht_corulix_formatter::managed_toolchain::BIOME_HOST_NATIVE;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

const DECL_SOURCE: &str = "export function target(): string {\n  return 'value';\n}\n";
const IMPORTER_SOURCE: &str = "import { target } from './decl';\n\nexport function Widget() {\n  const value = target();\n  return <span>{target()}{value}</span>;\n}\n";
const DECOY_SOURCE: &str = "// A same-named, unrelated local function -- a distinct symbol from\n// decl.ts's target, never importing it, in its own module scope.\nfunction target(): number {\n  return 999;\n}\n\nexport function decoyOnly(): number {\n  return target();\n}\n";
/// A second importer using an explicit alias (`import { target as
/// localTarget }`), for Section 19's explicit-alias-intent proof -- kept as
/// its own file/fixture rather than folding into `IMPORTER_SOURCE` so the
/// plain-shorthand-import tests above stay unaffected by this addition.
const ALIAS_IMPORTER_SOURCE: &str = "import { target as localTarget } from './decl';\n\nexport function AliasWidget() {\n  return localTarget();\n}\n";

/// One `(path, sorted-and-compared edit tuples)` entry per file touched by a
/// rename preview -- semantic content, not just which files were touched
/// (`T4_DECLARATION_USAGE_EDIT_SETS_EQUAL` requires comparing actual edit
/// ranges/text, order-independent within a file, exactly like this crate's
/// own precedent for references order-independence).
type EditSet = Vec<(String, Vec<(u32, u32, u32, u32, String)>)>;

fn rename_edit_set(outcome: &SemanticOutcome) -> Result<EditSet, Box<dyn Error>> {
    let SemanticOutcome::RenamePreview { result } = outcome else {
        return Err(fail(format!(
            "expected SemanticOutcome::RenamePreview, got {outcome:?}"
        )));
    };
    let mut entries: EditSet = result
        .edits_by_path
        .iter()
        .map(|(path, edits)| {
            let mut tuples: Vec<(u32, u32, u32, u32, String)> = edits
                .iter()
                .map(|edit| {
                    (
                        edit.range.start.line_zero_based,
                        edit.range.start.byte_column_zero_based,
                        edit.range.end.line_zero_based,
                        edit.range.end.byte_column_zero_based,
                        edit.new_text.clone(),
                    )
                })
                .collect();
            tuples.sort();
            (path.clone(), tuples)
        })
        .collect();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    Ok(entries)
}

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

struct TwoModuleFixture {
    base: PathBuf,
}

impl TwoModuleFixture {
    /// A real, independent two-module project (declaration + one importer
    /// using the symbol twice) plus one same-name decoy, no
    /// `tsconfig.json` -- deliberately inferred-project mode. Deliberately
    /// does NOT include the alias importer (see
    /// [`Self::new_with_alias_importer`]): every test that does not
    /// exercise the explicit-alias case must see exactly the same two
    /// real importer/declaration files as before that case existed, so its
    /// `[decl.ts, importer.tsx]`-shaped assertions stay valid.
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let base =
            std::env::temp_dir().join(format!("corulix-p19-rename-priming-{label}-{}", stamp()));
        fs::create_dir_all(&base)?;
        fs::write(base.join("decl.ts"), DECL_SOURCE)?;
        fs::write(base.join("importer.tsx"), IMPORTER_SOURCE)?;
        fs::write(base.join("decoy.ts"), DECOY_SOURCE)?;
        Ok(Self { base })
    }

    /// Same fixture as [`Self::new`], plus `alias_importer.tsx` (Section
    /// 19's explicit-alias case) -- used only by the alias-specific tests
    /// so every other test's exact two-file expectations stay unaffected by
    /// this additional real importer.
    fn new_with_alias_importer(label: &str) -> Result<Self, Box<dyn Error>> {
        let fixture = Self::new(label)?;
        fs::write(
            fixture.base.join("alias_importer.tsx"),
            ALIAS_IMPORTER_SOURCE,
        )?;
        Ok(fixture)
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

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.base.join(name)).unwrap_or_default()
    }
}

impl Drop for TwoModuleFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn rename_edit_paths(outcome: &SemanticOutcome) -> Result<Vec<String>, Box<dyn Error>> {
    let SemanticOutcome::RenamePreview { result } = outcome else {
        return Err(fail(format!(
            "expected SemanticOutcome::RenamePreview, got {outcome:?}"
        )));
    };
    let mut paths: Vec<String> = result
        .edits_by_path
        .iter()
        .map(|(path, _)| path.clone())
        .collect();
    paths.sort_unstable();
    Ok(paths)
}

/// `RENAME_PREVIEW_COLD_DECLARATION_ANCHOR_COMPLETE`: a genuinely fresh
/// session (its own engine/fixture, zero prior semantic calls of any kind),
/// anchored at the declaration, must return the complete edit set across
/// BOTH files -- `decl.ts` (the declaration) and `importer.tsx` (the import
/// specifier and both call sites) -- never the decoy. Before the fix this
/// returned only `decl.ts`.
///
/// FILE-LEVEL ONLY (separate finding, not a regression target of this
/// test): this call uses `LanguageId::TypeScript`, matching `decl.ts`'s own
/// extension -- `wht_corulix_engine` caches a separate `LspSession` per
/// `LanguageId`, so the request is served by the plain-TypeScript-profile
/// session even though the edit set it returns also touches the project's
/// `.tsx` file. That plain-TypeScript-session rename was observed (Corulix
/// 1.0.0 M03 rename_preview AST-based anchor classification pass) to omit
/// `importer.tsx` line 4's JSX-expression call site (`{target()}` inside
/// `<span>`) entirely, even though it is a real usage -- this assertion
/// only checks the file-path list, so it does not catch that omission.
/// `real_rename_preview_declaration_and_usage_anchor_edit_sets_are_equal_e2e`
/// (below) uses `LanguageId::Tsx` for both anchors specifically to avoid
/// this session-selection confound and prove the full edit set. Which
/// `LanguageId`/session a real client should pick for a mixed TS+TSX
/// project is a session-selection question outside this pass's scope
/// (canonical anchor classification), not a product defect introduced or
/// fixed here.
#[tokio::test]
async fn real_rename_preview_cold_declaration_anchor_complete_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await
        || !ensure_biome_provisioned(&managed_root).await
    {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native and/or biome");
        return Ok(());
    }

    let fixture = TwoModuleFixture::new("cold-decl")?;
    let engine = fixture.engine()?;
    let before_decl = fixture.read("decl.ts");
    let before_importer = fixture.read("importer.tsx");

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::TypeScript,
            SemanticTarget {
                relative_path: "decl.ts".to_string(),
                position: position_of(DECL_SOURCE, 0, "target"),
                new_name: Some("renamedTarget".to_string()),
            },
        )
        .await;

    let paths = rename_edit_paths(&outcome)?;
    if paths.iter().any(|path| path.contains("decoy")) {
        return Err(fail(format!(
            "decoy.ts's unrelated local target must never appear as an edit target, got {paths:?}"
        )));
    }
    if paths != vec!["decl.ts", "importer.tsx"] {
        return Err(fail(format!(
            "cold declaration-anchored rename_preview must return edits in exactly [decl.ts, importer.tsx] on a fresh session, got {paths:?}"
        )));
    }

    // `RENAME_PREVIEW_MUTATION_COUNT=0`: preview only, never writes to disk.
    assert_eq!(
        before_decl,
        fixture.read("decl.ts"),
        "decl.ts must not be mutated by a preview"
    );
    assert_eq!(
        before_importer,
        fixture.read("importer.tsx"),
        "importer.tsx must not be mutated by a preview"
    );
    Ok(())
}

/// `RENAME_PREVIEW_HISTORY_INDEPENDENT_AT_DECLARATION_ANCHOR`: the fix
/// makes project visibility directory-content-driven, not history-driven --
/// a fresh session already produces the complete set (proven above) with NO
/// prior unrelated call needed. This test proves the complementary half:
/// an unrelated prior call must not change the answer either.
#[tokio::test]
async fn real_rename_preview_declaration_anchor_stable_after_unrelated_call_e2e()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await
        || !ensure_biome_provisioned(&managed_root).await
    {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native and/or biome");
        return Ok(());
    }

    let fixture = TwoModuleFixture::new("stable-decl")?;
    let engine = fixture.engine()?;
    let rename_target = SemanticTarget {
        relative_path: "decl.ts".to_string(),
        position: position_of(DECL_SOURCE, 0, "target"),
        new_name: Some("renamedTarget".to_string()),
    };

    let first = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::TypeScript,
            rename_target.clone(),
        )
        .await;
    assert_eq!(
        rename_edit_paths(&first)?,
        vec!["decl.ts", "importer.tsx"],
        "first (fresh-session) declaration-anchored rename_preview must already be complete"
    );

    // Intervening, unrelated call against the decoy file.
    let _ = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::Definition,
            LanguageId::TypeScript,
            SemanticTarget {
                relative_path: "decoy.ts".to_string(),
                position: position_of(DECOY_SOURCE, 6, "target"),
                new_name: None,
            },
        )
        .await;

    let second = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::TypeScript,
            rename_target,
        )
        .await;
    assert_eq!(
        rename_edit_paths(&second)?,
        vec!["decl.ts", "importer.tsx"],
        "second declaration-anchored rename_preview (after intervening call) must remain identical"
    );
    Ok(())
}

/// `RENAME_PREVIEW_COLD_USAGE_ANCHOR_COMPLETE`: the canonical-anchor
/// redirect closes the previously-documented usage-anchor scope limitation
/// for an ordinary call-site use -- a genuinely fresh session, anchored at
/// `target()`'s call site inside the importing file, must now return the
/// same complete two-file edit set as anchoring at the declaration, and
/// must never touch the unrelated same-name decoy.
#[tokio::test]
async fn real_rename_preview_cold_usage_anchor_complete_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await
        || !ensure_biome_provisioned(&managed_root).await
    {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native and/or biome");
        return Ok(());
    }

    let fixture = TwoModuleFixture::new("usage-anchor")?;
    let engine = fixture.engine()?;
    let before_decl = fixture.read("decl.ts");
    let before_importer = fixture.read("importer.tsx");

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            SemanticTarget {
                relative_path: "importer.tsx".to_string(),
                position: position_of(IMPORTER_SOURCE, 3, "target"),
                new_name: Some("renamedTarget".to_string()),
            },
        )
        .await;

    let paths = rename_edit_paths(&outcome)?;
    if paths.iter().any(|path| path.contains("decoy")) {
        return Err(fail(format!(
            "decoy.ts's unrelated local target must never appear as an edit target, got {paths:?}"
        )));
    }
    if paths != vec!["decl.ts", "importer.tsx"] {
        return Err(fail(format!(
            "cold usage-anchored rename_preview must now return edits in exactly [decl.ts, importer.tsx] (canonical-anchor redirect), got {paths:?}"
        )));
    }

    // `RENAME_PREVIEW_MUTATION_COUNT=0`: preview only, never writes to disk.
    assert_eq!(
        before_decl,
        fixture.read("decl.ts"),
        "decl.ts must not be mutated by a preview"
    );
    assert_eq!(
        before_importer,
        fixture.read("importer.tsx"),
        "importer.tsx must not be mutated by a preview"
    );
    Ok(())
}

/// `TS_RENAME_ANCHOR_INDEPENDENCE`: the declaration-anchored and the
/// usage-anchored rename_preview must not merely touch the same two files --
/// their actual edit sets (ranges + replacement text, order-independent
/// within a file) must be identical, proven by direct semantic comparison
/// rather than inferred from matching path lists alone.
///
/// Both calls deliberately use `LanguageId::Tsx`, even though the
/// declaration anchor itself lives in `decl.ts`: the project contains a
/// `.tsx` file, and `wht_corulix_engine` caches a separate `LspSession` per
/// `LanguageId` (`typescript_lsp_session()` vs `tsx_lsp_session()`).
/// Comparing a `TypeScript`-session declaration anchor against a
/// `Tsx`-session usage anchor would measure two different provider
/// configurations, not two anchors on one session -- an observed confound
/// (a plain-`TypeScript`-session rename touching this same `importer.tsx`
/// omits its JSX-expression call site entirely; see this file's own
/// `real_rename_preview_cold_declaration_anchor_complete_e2e` doc comment).
/// `Tsx` is the session a real client integration would pick for this
/// project regardless of which file the anchor happens to sit in, matching
/// this pass's own root-cause probe (which used
/// `typescript_7_native_for_tsx()` for both anchor kinds).
#[tokio::test]
async fn real_rename_preview_declaration_and_usage_anchor_edit_sets_are_equal_e2e()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await
        || !ensure_biome_provisioned(&managed_root).await
    {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native and/or biome");
        return Ok(());
    }

    let declaration_fixture = TwoModuleFixture::new("anchor-equivalence-decl")?;
    let declaration_engine = declaration_fixture.engine()?;
    let declaration_outcome = declaration_engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            SemanticTarget {
                relative_path: "decl.ts".to_string(),
                position: position_of(DECL_SOURCE, 0, "target"),
                new_name: Some("renamedTarget".to_string()),
            },
        )
        .await;
    let declaration_edits = rename_edit_set(&declaration_outcome)?;

    let usage_fixture = TwoModuleFixture::new("anchor-equivalence-usage")?;
    let usage_engine = usage_fixture.engine()?;
    let usage_outcome = usage_engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            SemanticTarget {
                relative_path: "importer.tsx".to_string(),
                position: position_of(IMPORTER_SOURCE, 3, "target"),
                new_name: Some("renamedTarget".to_string()),
            },
        )
        .await;
    let usage_edits = rename_edit_set(&usage_outcome)?;

    assert_eq!(
        declaration_edits, usage_edits,
        "declaration-anchored and usage-anchored rename_preview must produce semantically identical edit sets"
    );
    Ok(())
}

/// `RENAME_PREVIEW_HISTORY_INDEPENDENT_AT_USAGE_ANCHOR`: mirrors the
/// declaration-anchor history-independence proof above for the usage
/// anchor -- an intervening, unrelated call must not change the (now
/// complete) usage-anchored result either.
#[tokio::test]
async fn real_rename_preview_usage_anchor_stable_after_unrelated_call_e2e()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await
        || !ensure_biome_provisioned(&managed_root).await
    {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native and/or biome");
        return Ok(());
    }

    let fixture = TwoModuleFixture::new("stable-usage")?;
    let engine = fixture.engine()?;
    let rename_target = SemanticTarget {
        relative_path: "importer.tsx".to_string(),
        position: position_of(IMPORTER_SOURCE, 3, "target"),
        new_name: Some("renamedTarget".to_string()),
    };

    let first = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            rename_target.clone(),
        )
        .await;
    assert_eq!(
        rename_edit_paths(&first)?,
        vec!["decl.ts", "importer.tsx"],
        "first (fresh-session) usage-anchored rename_preview must already be complete"
    );

    // Intervening, unrelated call against the decoy file.
    let _ = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::Definition,
            LanguageId::TypeScript,
            SemanticTarget {
                relative_path: "decoy.ts".to_string(),
                position: position_of(DECOY_SOURCE, 6, "target"),
                new_name: None,
            },
        )
        .await;

    let second = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            rename_target,
        )
        .await;
    assert_eq!(
        rename_edit_paths(&second)?,
        vec!["decl.ts", "importer.tsx"],
        "second usage-anchored rename_preview (after intervening call) must remain identical"
    );
    Ok(())
}

/// `SHORTHAND_IMPORT_SPECIFIER_CANONICALIZED=NO`: anchoring directly on the
/// import specifier token itself (`target` in `import { target } from
/// './decl'`) must NOT be redirected to the declaration -- the provider
/// gives no protocol-level signal distinguishing this position from an
/// ordinary call-site use (proven directly: Corulix 1.0.0 M03 rename_preview
/// canonical anchor resolution trace), so only the syntactically-provable
/// value/call-use case is canonicalized. This must stay scoped to the
/// importing file alone, exactly as the provider's own native rename would
/// produce at this anchor.
#[tokio::test]
async fn real_rename_preview_import_specifier_anchor_not_canonicalized_e2e()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await
        || !ensure_biome_provisioned(&managed_root).await
    {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native and/or biome");
        return Ok(());
    }

    let fixture = TwoModuleFixture::new("import-specifier-anchor")?;
    let engine = fixture.engine()?;

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            SemanticTarget {
                relative_path: "importer.tsx".to_string(),
                position: position_of(IMPORTER_SOURCE, 0, "target"),
                new_name: Some("renamedTarget".to_string()),
            },
        )
        .await;

    let paths = rename_edit_paths(&outcome)?;
    if paths != vec!["importer.tsx"] {
        return Err(fail(format!(
            "import-specifier-anchored rename_preview must stay scoped to exactly [importer.tsx] (SHORTHAND_IMPORT_SPECIFIER_CANONICALIZED=NO), got {paths:?}"
        )));
    }
    Ok(())
}

/// `EXPLICIT_LOCAL_ALIAS_BINDING_CANONICALIZED=NO`: anchoring on the local
/// alias name itself (`localTarget` in `import { target as localTarget }`)
/// must preserve the provider's own local-alias rename intent, never
/// redirected to `decl.ts`'s declaration.
#[tokio::test]
async fn real_rename_preview_explicit_alias_binding_not_canonicalized_e2e()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await
        || !ensure_biome_provisioned(&managed_root).await
    {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native and/or biome");
        return Ok(());
    }

    let fixture = TwoModuleFixture::new_with_alias_importer("alias-binding-anchor")?;
    let engine = fixture.engine()?;

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            SemanticTarget {
                relative_path: "alias_importer.tsx".to_string(),
                position: position_of(ALIAS_IMPORTER_SOURCE, 0, "localTarget"),
                new_name: Some("renamedLocal".to_string()),
            },
        )
        .await;

    let paths = rename_edit_paths(&outcome)?;
    if paths != vec!["alias_importer.tsx"] {
        return Err(fail(format!(
            "explicit-alias-binding-anchored rename_preview must stay scoped to exactly [alias_importer.tsx] (EXPLICIT_LOCAL_ALIAS_BINDING_CANONICALIZED=NO), got {paths:?}"
        )));
    }
    Ok(())
}

/// Section 19's companion proof: an ordinary *usage* of an aliased import
/// (`localTarget()`, a ValueUsage occurrence distinct from the alias
/// binding itself) follows the same value/call-use policy as any other
/// usage -- it is eligible for canonical redirect, and must never touch the
/// unrelated same-name decoy regardless of which anchor style resolves it.
///
/// The canonicalized project-wide rename correctly touches all three real
/// files: `decl.ts` (the declaration), `importer.tsx` (the plain-shorthand
/// importer, an unrelated real usage of the same symbol), and
/// `alias_importer.tsx` itself -- specifically its import specifier's own
/// `name` field (`target` in `import { target as localTarget }`), which
/// still refers to the remote declaration and must track its rename even
/// though the specifier's `alias` field (`localTarget`) is untouched.
#[tokio::test]
async fn real_rename_preview_alias_usage_follows_value_usage_policy_e2e()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await
        || !ensure_biome_provisioned(&managed_root).await
    {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native and/or biome");
        return Ok(());
    }

    let fixture = TwoModuleFixture::new_with_alias_importer("alias-usage-anchor")?;
    let engine = fixture.engine()?;

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            SemanticTarget {
                relative_path: "alias_importer.tsx".to_string(),
                position: position_of(ALIAS_IMPORTER_SOURCE, 3, "localTarget"),
                new_name: Some("renamedLocal".to_string()),
            },
        )
        .await;

    let paths = rename_edit_paths(&outcome)?;
    if paths.iter().any(|path| path.contains("decoy")) {
        return Err(fail(format!(
            "decoy.ts's unrelated local target must never appear as an edit target, got {paths:?}"
        )));
    }
    if paths != vec!["alias_importer.tsx", "decl.ts", "importer.tsx"] {
        return Err(fail(format!(
            "alias-usage-anchored rename_preview must return edits in exactly [alias_importer.tsx, decl.ts, importer.tsx], got {paths:?}"
        )));
    }
    Ok(())
}

/// `SHADOWED_LOCAL_DECOY_EDIT_COUNT=0` / `UNRELATED_LOCAL_BINDING_EDIT_COUNT=0`,
/// proven literally rather than inferred: renaming FROM the decoy's own
/// declaration must produce an edit set confined entirely to `decoy.ts`
/// (its own declaration plus its own usage, both real edits of the decoy's
/// distinct local symbol), never redirected to `decl.ts`'s unrelated
/// exported `target` and never touching `importer.tsx`. The decoy's own
/// `definition` resolves to itself (a different location than `decl.ts`'s
/// declaration -- proven directly via the raw-LSP probe this pass), so
/// canonical redirect is harmless here even though the decoy's usage is
/// itself classified `ValueUsage`.
#[tokio::test]
async fn real_rename_preview_shadowed_local_decoy_stays_confined_e2e() -> Result<(), Box<dyn Error>>
{
    let _guard = session_lock().await;
    let Ok(managed_root) = provisioning::managed_toolchain_root() else {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: no managed_toolchain_root");
        return Ok(());
    };
    if !ensure_ts7_provisioned(&managed_root).await
        || !ensure_biome_provisioned(&managed_root).await
    {
        eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: typescript-7-native and/or biome");
        return Ok(());
    }

    let fixture = TwoModuleFixture::new("decoy-confinement")?;
    let engine = fixture.engine()?;

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::TypeScript,
            SemanticTarget {
                relative_path: "decoy.ts".to_string(),
                position: position_of(DECOY_SOURCE, 7, "target"),
                new_name: Some("renamedDecoy".to_string()),
            },
        )
        .await;

    let edits = rename_edit_set(&outcome)?;
    let paths: Vec<&str> = edits.iter().map(|(path, _)| path.as_str()).collect();
    if paths != vec!["decoy.ts"] {
        return Err(fail(format!(
            "decoy-anchored rename_preview must stay confined to exactly [decoy.ts], got {paths:?}"
        )));
    }
    let Some((_, decoy_edits)) = edits.first() else {
        return Err(fail("expected exactly one edited file entry"));
    };
    if decoy_edits.len() != 2 {
        return Err(fail(format!(
            "decoy-anchored rename_preview must produce exactly 2 edits (its own declaration and its own usage), got {decoy_edits:?}"
        )));
    }
    Ok(())
}
