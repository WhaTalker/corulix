// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P17 mandate closure item #3: standalone zero-residual proof for the
//! Python provider vertical.
//!
//! # What this file actually proves, traced first rather than assumed
//!
//! Per ADR 0011 §5/§6, `ruff`/`pyright`/`pytest`/`python3` are all resolved
//! `HOST_ONLY`/approved-directory (`wht_corulix_config::resolve_provider`),
//! never `CORULIX_MANAGED` -- unlike Pyright's *pre-existing* managed-Node
//! infrastructure (P7B), P17 introduces no new managed component of its own
//! for any Python-family provider (`rg 'managed_component\s*:\s*Some'
//! wht_crates/wht_corulix_engine/src/python_*.rs` returns no match; the one
//! `wht_corulix_lsp::profile::LspProviderProfile::pyright()` this engine
//! actually calls, in `semantic.rs::ensure_python_lsp_session`, sets
//! `managed_component: None, managed_interpreter: None`, unlike its own
//! sibling `pyright_managed()` constructor).
//!
//! The ONE piece of new Corulix-owned filesystem state P17's own production
//! code writes is `python_validation::run_lint`'s staged copy under
//! `<managed_root>/scratch/ruff-lint/` (`stage_file_for_ruff_check`) --
//! **transient**, not a managed component or persistent cache: it is written
//! immediately before invoking `ruff check` and removed immediately after,
//! unconditionally, regardless of the validator's outcome (`python_validation.rs`'s
//! own `run_lint` calls `remove_scratch_file` right after `execute()` returns,
//! before matching on `outcome.termination` at all). This is the identical,
//! already-certified pattern `crate::ts_validation::stage_file_for_biome_lint`
//! uses for TS/JS Biome-lint staging -- not a new residual-risk shape P17
//! introduced.
//!
//! `ensure_python_lsp_session` (the real Pyright LSP session,
//! `semantic.rs`) sets **no** `managed_root`-relative environment variable at
//! all (no `GOCACHE`/`GOMODCACHE`/`GOPATH`-equivalent for Python -- confirmed
//! by reading `wht_corulix_lsp::profile::LspProviderProfile::pyright()`'s own
//! `literal_environment: &[]` and the absence of any `with_var(...scratch...)`
//! call in `ensure_python_lsp_session`, unlike `ensure_go_lsp_session`'s own
//! `crate::go_providers::ensure_go_scratch` call), so no live-session cache
//! exists under the managed root for Python at all.
//!
//! `P17_ZERO_RESIDUAL_NEW_STATE=NOT_APPLICABLE_WITH_EVIDENCE` for any
//! *persistent* new managed state -- there is none to prove zero-residual
//! for beyond what `full_uninstall`'s own pre-existing, already-certified
//! whole-`scratch`-directory removal (Rule V) already covers unconditionally.
//! This file still proves, empirically, both the transient staging's
//! self-cleanup and `full_uninstall`'s own zero-residual guarantee over
//! whatever Python's providers touched.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::CancellationToken;
use wht_corulix_engine::python_validation;
use wht_corulix_tooling::provisioning::{self, MANAGED_SCRATCH_DIR, full_uninstall};
use wht_corulix_workspace::WorkspaceRoot;

/// Test-only PATH-based tool discovery. `CORULIX_TEST_PYTHON_TOOLS_DIR`
/// overrides discovery when set to an explicit directory; otherwise the
/// directory on `PATH` containing `bin_name` is used. Never embeds a
/// specific developer's machine path.
fn resolve_test_tool_dir(bin_name: &str, env_override: &str) -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_override) {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("{bin_name}{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
}

fn real_ruff_pytest_directory() -> Option<PathBuf> {
    resolve_test_tool_dir("ruff", "CORULIX_TEST_PYTHON_TOOLS_DIR")
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

fn real_ruff_available() -> bool {
    real_ruff_pytest_directory().is_some()
}

macro_rules! require_ruff {
    () => {
        if !real_ruff_available() {
            eprintln!(
                "P17_ZERO_RESIDUAL_E2E=BLOCKED_PROVIDER_UNAVAILABLE: real ruff not found on PATH (set CORULIX_TEST_PYTHON_TOOLS_DIR to override)"
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

/// Recursively counts real files (never following symlinks) under `path`.
fn entry_count(path: &Path) -> usize {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| {
            let child = entry.path();
            if child.is_dir() && !child.is_symlink() {
                entry_count(&child)
            } else {
                1
            }
        })
        .sum()
}

struct Fixture {
    workspace: PathBuf,
    managed_root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "corulix-p17-python-zero-residual-{label}-{}",
            stamp()
        ));
        let workspace = base.join("workspace");
        let managed_root = base.join("managed");
        let _ = fs::create_dir_all(&workspace);
        let _ = fs::create_dir_all(&managed_root);
        Self {
            workspace,
            managed_root,
        }
    }

    fn write(&self, name: &str, contents: &str) {
        let _ = fs::write(self.workspace.join(name), contents);
    }

    fn workspace_root(&self) -> wht_corulix_core::CorulixResult<WorkspaceRoot> {
        WorkspaceRoot::open(&self.workspace)
    }

    fn cleanup(&self) {
        if let Some(base) = self.workspace.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }
}

fn real_provider_authority() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig {
            approved_system_directories: vec![real_ruff_pytest_directory().unwrap_or_default()],
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

/// `P17_RUFF_LINT_STAGED_COPY_SELF_CLEANUP=YES`: after a real `run_lint`
/// call returns -- clean or with findings -- the `ruff-lint` scratch
/// subdirectory holds zero staged files, proving the staged copy is
/// genuinely transient rather than accumulating residual bytes across
/// repeated invocations.
#[tokio::test]
async fn run_lint_leaves_zero_staged_residual_after_clean_and_dirty_runs()
-> Result<(), Box<dyn Error>> {
    require_ruff!();
    let fixture = Fixture::new("staged-cleanup");
    fixture.write("clean.py", "def target() -> int:\n    return 41\n");
    // An unused import: a genuine `ruff check` finding (F401), so the
    // "findings present" path through `run_lint` is exercised too, not only
    // the clean path.
    fixture.write(
        "dirty.py",
        "import os\n\n\ndef target() -> int:\n    return 41\n",
    );
    let workspace_root = fixture.workspace_root()?;
    let effective = real_provider_authority();
    let scratch_ruff_lint = fixture
        .managed_root
        .join(MANAGED_SCRATCH_DIR)
        .join("ruff-lint");

    for (relative_path, expect_clean) in [("clean.py", true), ("dirty.py", false)] {
        let outcome = python_validation::run_lint(
            &fixture.managed_root,
            &effective,
            &workspace_root,
            relative_path,
            &CancellationToken::new(),
        )
        .await
        .map_err(|error| fail(format!("run_lint({relative_path}) failed: {error:?}")))?;
        if outcome.clean != expect_clean {
            return Err(fail(format!(
                "run_lint({relative_path}): expected clean={expect_clean}, got {outcome:?}"
            )));
        }
        let residual = entry_count(&scratch_ruff_lint);
        if residual != 0 {
            return Err(fail(format!(
                "P17_RUFF_LINT_STAGED_COPY_SELF_CLEANUP must be YES: {residual} staged file(s) \
                 remained under {} after run_lint({relative_path}) returned",
                scratch_ruff_lint.display()
            )));
        }
    }

    eprintln!("P17_RUFF_LINT_STAGED_COPY_SELF_CLEANUP=YES");
    fixture.cleanup();
    Ok(())
}

/// `P17_ZERO_RESIDUAL_NEW_STATE=NOT_APPLICABLE_WITH_EVIDENCE`: real
/// end-to-end proof. A real `run_lint` call runs against this isolated
/// managed root (so the scratch tree genuinely exists and has been written
/// to at least once), then the real, product-facing `full_uninstall` runs,
/// and every post-condition the mandate names is measured directly rather
/// than assumed from the outcome enum alone.
#[tokio::test]
async fn full_uninstall_after_python_lint_activity_leaves_zero_residual()
-> Result<(), Box<dyn Error>> {
    require_ruff!();
    let fixture = Fixture::new("full-uninstall");
    fixture.write(
        "main.py",
        "import os\n\n\ndef target() -> int:\n    return 41\n",
    );
    let workspace_root = fixture.workspace_root()?;
    let effective = real_provider_authority();

    // Real Python-provider activity against this isolated managed root, so
    // whatever transient state P17's own code can create has genuinely been
    // created at least once before uninstall runs.
    let _ = python_validation::run_lint(
        &fixture.managed_root,
        &effective,
        &workspace_root,
        "main.py",
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("run_lint failed: {error:?}")))?;

    // The real, product-facing boundary -- not a test-only deletion helper.
    let outcome =
        full_uninstall::uninstall_all_corulix_managed_components_at(&fixture.managed_root)
            .await
            .map_err(|error| fail(format!("full_uninstall must succeed, got {error:?}")))?;
    if outcome != full_uninstall::FullUninstallOutcome::NoManagedComponents {
        return Err(fail(format!(
            "this isolated root holds no managed component (Python's own providers are \
             HOST_ONLY/approved-directory, never CORULIX_MANAGED per ADR 0011), expected \
             NoManagedComponents, got {outcome:?}"
        )));
    }

    let scratch = fixture.managed_root.join(MANAGED_SCRATCH_DIR);
    if scratch.exists() {
        return Err(fail(format!(
            "POST_P17_UNINSTALL_SCRATCH_COUNT must be 0, {} survived",
            scratch.display()
        )));
    }
    if fixture.managed_root.exists() {
        return Err(fail(
            "POST_P17_UNINSTALL_MANAGED_ROOT_EXISTS must be NO after a complete uninstall",
        ));
    }
    // `ownership::list` over the same isolated root: no owned component
    // record survives either (there was never one to begin with, which is
    // the point being proven -- Python's own providers never create one).
    let owned = provisioning::ownership::list(&fixture.managed_root);
    if !owned.is_empty() {
        return Err(fail(format!(
            "POST_P17_UNINSTALL_MANAGED_CACHE_COUNT must be 0, found {} owned component \
             record(s)",
            owned.len()
        )));
    }

    eprintln!("POST_P17_UNINSTALL_MANAGED_CACHE_COUNT=0");
    eprintln!("POST_P17_UNINSTALL_SCRATCH_COUNT=0");
    eprintln!("POST_P17_UNINSTALL_RESIDUAL_PATHS=[]");
    eprintln!(
        "P17_ZERO_RESIDUAL_NEW_STATE=NOT_APPLICABLE_WITH_EVIDENCE (Python providers are \
         HOST_ONLY/approved-directory only; the one transient staged-lint file is self-cleaning, \
         proven by run_lint_leaves_zero_staged_residual_after_clean_and_dirty_runs; \
         full_uninstall's own pre-existing whole-scratch removal still verified zero-residual here)"
    );
    fixture.cleanup();
    Ok(())
}
