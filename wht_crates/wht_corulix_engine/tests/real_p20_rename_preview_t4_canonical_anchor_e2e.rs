// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 20: real, product-path acceptance proof for the M03 rename_preview
//! AST-based canonical-anchor-resolution pass, run directly against the
//! frozen T4 benchmark fixture pair
//! (`wht_tests/fixtures/typescript/rename_module.ts` /
//! `rename_widget.tsx`) and its frozen oracle
//! (`.corulix_benchmark/m03/oracle/T4_rename_preview_module_widget.json`).
//!
//! This test is read-only against every benchmark artifact: it never
//! writes to the fixture files, the oracle, or any other
//! `.corulix_benchmark/m03` content (`BENCHMARK_CONTENT_MUTATION_COUNT=0`
//! is unaffected by this file existing), and it is not a scored trial --
//! it exists purely to prove, against the real fixture pair the oracle was
//! authored against, that the previously-documented usage-anchor scope
//! limitation (see that oracle's own
//! `empirical_note_not_part_of_scoring` field) is now closed for the
//! syntactically-provable case.
//!
//! Root cause and fix: see
//! `wht_crates/wht_corulix_lsp/src/operations.rs`'s `canonical_rename_anchor`
//! and `wht_crates/wht_corulix_syntax/src/anchor_role.rs`. The synthetic,
//! benchmark-independent regression proof for every individual invariant
//! (declaration/usage equivalence, import-specifier/alias preservation,
//! decoy safety, history independence) lives in
//! `real_p19_rename_preview_project_priming_e2e.rs`; this file is the
//! narrower, real-fixture confirmation that the same fix closes the exact
//! case T4's own oracle documents.

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

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

/// Mirrors `real_p19_rename_preview_project_priming_e2e.rs`'s own session
/// lock precedent, kept as a separate static so this file's tests never
/// serialize against unrelated files' locks.
static REAL_P20_TS_SESSION_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_P20_TS_SESSION_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

async fn ensure_ts7_provisioned(root: &Path) -> bool {
    let manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

async fn ensure_biome_provisioned(root: &Path) -> bool {
    let manifest = wht_corulix_formatter::managed_toolchain::BIOME_HOST_NATIVE;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

fn repo_root() -> Result<PathBuf, Box<dyn Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| fail(format!("repo root must canonicalize: {error:?}")))
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

fn rename_edit_count(outcome: &SemanticOutcome) -> Result<usize, Box<dyn Error>> {
    let SemanticOutcome::RenamePreview { result } = outcome else {
        return Err(fail(format!(
            "expected SemanticOutcome::RenamePreview, got {outcome:?}"
        )));
    };
    Ok(result
        .edits_by_path
        .iter()
        .map(|(_, edits)| edits.len())
        .sum())
}

/// T4's own oracle's required invariant, proven against the real fixture
/// pair it was authored against: a rename anchored at the real call site
/// (`rename_widget.tsx` line 3, `computeLabel(props.name)`) must now return
/// the complete, oracle-matching 4-edit/2-file set -- the declaration in
/// `rename_module.ts` plus the import specifier and both call sites in
/// `rename_widget.tsx` -- never the shadowed local decoy, and never mutate
/// either fixture file.
#[tokio::test]
async fn real_rename_preview_t4_usage_anchor_matches_oracle_e2e() -> Result<(), Box<dyn Error>> {
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

    let root = repo_root()?;
    let module_path = root.join("wht_tests/fixtures/typescript/rename_module.ts");
    let widget_path = root.join("wht_tests/fixtures/typescript/rename_widget.tsx");
    let before_module = std::fs::read(&module_path)?;
    let before_widget = std::fs::read(&widget_path)?;
    let widget_source = String::from_utf8(before_widget.clone())
        .map_err(|error| fail(format!("rename_widget.tsx must be valid UTF-8: {error:?}")))?;

    let workspace_root = WorkspaceRoot::open(&root)?;
    let context = WorkspaceContext::single_root(workspace_root, "root".to_string());
    let engine = CorulixEngine::open_with_host_config(context, false, HostConfig::default());

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            SemanticTarget {
                relative_path: "wht_tests/fixtures/typescript/rename_widget.tsx".to_string(),
                position: position_of(&widget_source, 3, "computeLabel"),
                new_name: Some("formatLabel".to_string()),
            },
        )
        .await;

    // T4's decoy (`unrelatedDecoyHolder`'s shadowed local) lives inside
    // rename_module.ts itself, not a separate file -- so decoy-exclusion is
    // proven by the exact-edit-count assertion below (4, not 6) rather than
    // a separate path check.
    let paths = rename_edit_paths(&outcome)?;
    if paths
        != vec![
            "wht_tests/fixtures/typescript/rename_module.ts".to_string(),
            "wht_tests/fixtures/typescript/rename_widget.tsx".to_string(),
        ]
    {
        return Err(fail(format!(
            "T4 usage-anchored rename_preview must return edits in exactly [rename_module.ts, rename_widget.tsx] (matching the frozen oracle's expected_affected_files), got {paths:?}"
        )));
    }

    let edit_count = rename_edit_count(&outcome)?;
    if edit_count != 4 {
        return Err(fail(format!(
            "T4 usage-anchored rename_preview must return exactly 4 edits total (matching the frozen oracle's expected_edit_count), got {edit_count}"
        )));
    }

    // `RENAME_PREVIEW_MUTATION_COUNT=0` / `actual_mutation_expectation=0`:
    // preview only, the frozen fixture pair must remain byte-identical.
    let after_module = std::fs::read(&module_path)?;
    let after_widget = std::fs::read(&widget_path)?;
    if before_module != after_module {
        return Err(fail("rename_module.ts was mutated by this preview"));
    }
    if before_widget != after_widget {
        return Err(fail("rename_widget.tsx was mutated by this preview"));
    }
    Ok(())
}

/// Companion proof: anchoring at the declaration itself must continue to
/// produce the same oracle-matching 4-edit/2-file set (already true since
/// the M03 project-priming fix) -- proven here again in the same session
/// style as the usage-anchor test above, so both anchors are verified
/// against the exact same real fixture pair in this file.
#[tokio::test]
async fn real_rename_preview_t4_declaration_anchor_matches_oracle_e2e() -> Result<(), Box<dyn Error>>
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

    let root = repo_root()?;
    let module_path = root.join("wht_tests/fixtures/typescript/rename_module.ts");
    let widget_path = root.join("wht_tests/fixtures/typescript/rename_widget.tsx");
    let before_module = std::fs::read(&module_path)?;
    let before_widget = std::fs::read(&widget_path)?;
    let module_source = String::from_utf8(before_module.clone())
        .map_err(|error| fail(format!("rename_module.ts must be valid UTF-8: {error:?}")))?;

    let workspace_root = WorkspaceRoot::open(&root)?;
    let context = WorkspaceContext::single_root(workspace_root, "root".to_string());
    let engine = CorulixEngine::open_with_host_config(context, false, HostConfig::default());

    let outcome = engine
        .semantic_at(
            &managed_root,
            SemanticOperation::RenamePreview,
            LanguageId::Tsx,
            SemanticTarget {
                relative_path: "wht_tests/fixtures/typescript/rename_module.ts".to_string(),
                position: position_of(&module_source, 0, "computeLabel"),
                new_name: Some("formatLabel".to_string()),
            },
        )
        .await;

    let paths = rename_edit_paths(&outcome)?;
    if paths
        != vec![
            "wht_tests/fixtures/typescript/rename_module.ts".to_string(),
            "wht_tests/fixtures/typescript/rename_widget.tsx".to_string(),
        ]
    {
        return Err(fail(format!(
            "T4 declaration-anchored rename_preview must return edits in exactly [rename_module.ts, rename_widget.tsx], got {paths:?}"
        )));
    }
    let edit_count = rename_edit_count(&outcome)?;
    if edit_count != 4 {
        return Err(fail(format!(
            "T4 declaration-anchored rename_preview must return exactly 4 edits total, got {edit_count}"
        )));
    }

    let after_module = std::fs::read(&module_path)?;
    let after_widget = std::fs::read(&widget_path)?;
    if before_module != after_module {
        return Err(fail("rename_module.ts was mutated by this preview"));
    }
    if before_widget != after_widget {
        return Err(fail("rename_widget.tsx was mutated by this preview"));
    }
    Ok(())
}
