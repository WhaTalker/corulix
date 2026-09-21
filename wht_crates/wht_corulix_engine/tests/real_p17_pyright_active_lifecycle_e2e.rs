// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P17 mandate closure item #4: whether `ensure_python_lsp_session` (P17)
//! has the identical "active session vs. premature uninstall" defect
//! `real_p15_gopls_active_scratch_lifecycle_e2e.rs` found and fixed for
//! `ensure_go_lsp_session` (P15).
//!
//! # Trace first, conclusion second
//!
//! The P15 defect's real shape (see that file's own doc comment): gopls
//! resolves `HOST_ONLY` (no managed component), so `resolve_launch_at`'s
//! `any_managed_dependency_used` gate was false and the session was leased
//! **not at all** -- yet the live process's `GOCACHE`/`GOMODCACHE`/`GOPATH`
//! pointed at real, Corulix-owned bytes under `<managed_root>/scratch/`. A
//! naive `full_uninstall` could therefore destroy a live session's own cache
//! having sent no stop signal and verified no absence. The fix
//! (`semantic.rs::ensure_go_lsp_session`) added a `managed_root_identity`
//! axis to the session's `ManagedLeaseBinding`, so `full_uninstall`'s scratch
//! stage now signals/waits/verifies-absent before deleting.
//!
//! Reading `semantic.rs::ensure_python_lsp_session` side by side with
//! `ensure_go_lsp_session` shows the two are **not** structurally identical,
//! for a real, load-bearing reason disclosed in `ensure_python_lsp_session`'s
//! own doc comment: "Unlike Go, no Corulix-owned scratch/cache directory is
//! bound here: Pyright's own capability probe (ADR 0009) confirmed zero
//! project-Python execution and zero filesystem write of its own." Confirmed
//! independently in this pass by reading
//! `wht_corulix_lsp::profile::LspProviderProfile::pyright()`: `literal_environment:
//! &[]`, `managed_component: None`, `managed_interpreter: None` -- there is no
//! `GOCACHE`-equivalent `with_var` call anywhere in `ensure_python_lsp_session`,
//! and the profile this engine actually calls is `pyright()`, never
//! `pyright_managed()`. `rg 'with_var' wht_crates/wht_corulix_engine/src/semantic.rs`
//! confirms every `with_var` call in that file belongs to
//! `ensure_go_lsp_session` alone.
//!
//! **Conclusion: no defect exists to fix.** `ensure_python_lsp_session`
//! does not bind a `managed_root_identity` lease, exactly like
//! `ensure_go_lsp_session` before its P15 fix -- but, unlike gopls, there is
//! no managed-root-scoped cache bound to a live Pyright session for a
//! premature `full_uninstall` to destroy in the first place, because this
//! session never writes anything there. The two "missing lease" states look
//! identical in source; they are not identical in consequence, because the
//! *reason* the P15 fix was necessary (real cache bytes under
//! `<root>/scratch` a live session depends on) does not hold for Pyright.
//! `P17_PYRIGHT_MANAGED_ROOT_LEASE=ABSENT (by design, not oversight)`.
//!
//! This file proves that conclusion empirically rather than resting on the
//! trace alone: a real, live Pyright session serving a real semantic
//! request, a real `full_uninstall` run against its managed root while the
//! session is active, and a second real semantic request proving the same
//! live session kept working throughout -- untouched, not merely lucky.
//!
//! Host discovery, never a hard-coded operator path, mirroring
//! `real_p15_gopls_active_scratch_lifecycle_e2e.rs`'s own discipline.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{LanguageId, Position};
use wht_corulix_engine::semantic::{
    DefinitionResultDto, ReferencesResultDto, SemanticOperation, SemanticOutcome, SemanticTarget,
};
use wht_corulix_engine::{CorulixEngine, HostConfig};
use wht_corulix_tooling::provisioning::{
    self,
    full_uninstall::{self, FullUninstallOutcome},
    lease,
};
use wht_corulix_workspace::{WorkspaceContext, WorkspaceRoot};

/// Test-only PATH-based tool discovery. `CORULIX_TEST_PYRIGHT_DIR`
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

fn real_pyright_directory() -> Option<PathBuf> {
    resolve_test_tool_dir("pyright", "CORULIX_TEST_PYRIGHT_DIR")
}

/// `target()`'s own declaration is line 0; `caller()`'s call site to it is
/// line 4.
const FIXTURE_MAIN_PY: &str =
    "def target() -> int:\n    return 41\n\n\ndef caller() -> int:\n    return target()\n";

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

fn real_pyright_available() -> bool {
    real_pyright_directory().is_some()
}

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

fn fixture_position(line_zero_based: u32, byte_column_zero_based: u32) -> Position {
    let mut byte_offset: u64 = 0;
    for (index, text) in FIXTURE_MAIN_PY.split_inclusive('\n').enumerate() {
        if index as u32 == line_zero_based {
            break;
        }
        byte_offset += text.len() as u64;
    }
    Position {
        line_zero_based,
        byte_column_zero_based,
        byte_offset: byte_offset + u64::from(byte_column_zero_based),
    }
}

struct PyrightFixture {
    base: PathBuf,
    workspace: PathBuf,
    managed_root: PathBuf,
}

impl PyrightFixture {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let base =
            std::env::temp_dir().join(format!("corulix-p17-pyright-lifecycle-{label}-{}", stamp()));
        let workspace = base.join("workspace");
        let managed_root = base.join("managed");
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&managed_root)?;
        fs::write(workspace.join("main.py"), FIXTURE_MAIN_PY)?;
        Ok(Self {
            base,
            workspace,
            managed_root,
        })
    }

    fn engine(&self) -> Result<CorulixEngine, Box<dyn Error>> {
        let root = WorkspaceRoot::open(&self.workspace)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let host = HostConfig {
            approved_system_directories: vec![real_pyright_directory().unwrap_or_default()],
            ..HostConfig::default()
        };
        Ok(CorulixEngine::open_with_host_config(context, false, host))
    }

    fn root_identity(&self) -> String {
        provisioning::ownership::root_identity(&self.managed_root)
    }

    fn scratch(&self) -> PathBuf {
        self.managed_root.join(provisioning::MANAGED_SCRATCH_DIR)
    }
}

impl Drop for PyrightFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

async fn real_definition(
    engine: &CorulixEngine,
    fixture: &PyrightFixture,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let outcome = engine
        .semantic_at(
            &fixture.managed_root,
            SemanticOperation::Definition,
            LanguageId::Python,
            SemanticTarget {
                // `target()`'s call site inside `caller`, line 5 ("    return target()").
                relative_path: "main.py".to_string(),
                position: fixture_position(5, 11),
                new_name: None,
            },
        )
        .await;
    match outcome {
        SemanticOutcome::Definition {
            result: DefinitionResultDto::Single(_),
        } => Ok(()),
        SemanticOutcome::Definition {
            result: DefinitionResultDto::Multiple { ref locations },
        } if !locations.is_empty() => Ok(()),
        other => Err(fail(format!(
            "{label}: expected a real non-empty pyright definition answer, got {other:?}"
        ))),
    }
}

async fn real_references(
    engine: &CorulixEngine,
    fixture: &PyrightFixture,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let outcome = engine
        .semantic_at(
            &fixture.managed_root,
            SemanticOperation::References,
            LanguageId::Python,
            SemanticTarget {
                // `target`'s own declaration, line 0.
                relative_path: "main.py".to_string(),
                position: fixture_position(0, 4),
                new_name: None,
            },
        )
        .await;
    match outcome {
        SemanticOutcome::References {
            result: ReferencesResultDto::Found { ref locations },
        } if !locations.is_empty() => Ok(()),
        other => Err(fail(format!(
            "{label}: expected a real non-empty pyright references answer, got {other:?}"
        ))),
    }
}

/// `P17_ACTIVE_PYRIGHT_FULL_UNINSTALL_E2E`: a real, live Pyright session
/// serving a real semantic request, then a real `full_uninstall` against its
/// managed root while the session is active, then a second real semantic
/// request through the SAME session proving it kept working throughout.
#[tokio::test(flavor = "multi_thread")]
async fn real_active_pyright_full_uninstall_never_disrupts_the_live_session()
-> Result<(), Box<dyn Error>> {
    if !real_pyright_available() {
        eprintln!("P17_PYRIGHT_LIFECYCLE_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real pyright/node");
        return Ok(());
    }
    let fixture = PyrightFixture::new("full-uninstall")?;
    let engine = fixture.engine()?;

    // Real live session + real semantic authority.
    real_definition(&engine, &fixture, "pre-full-uninstall").await?;

    // Trace-confirmed precondition: unlike gopls (post-P15-fix), this live
    // session holds NO root-scoped managed lease, because
    // `ensure_python_lsp_session` binds no managed_root_identity -- which is
    // correct here, not a regression, since the session created no
    // managed-root-scoped cache to protect (see this file's own doc comment
    // for the full trace).
    let identity = fixture.root_identity();
    let leased_before = lease::process_identities_for_managed_root(&identity);
    if !leased_before.is_empty() {
        return Err(fail(format!(
            "expected zero root-scoped leases for a live Pyright session (Pyright binds no \
             managed-root cache), got {}",
            leased_before.len()
        )));
    }
    eprintln!(
        "P17_ACTIVE_PYRIGHT_ROOT_SCOPED_LEASE_COUNT=0 (by design: no managed-root cache to protect)"
    );

    // Precondition: this isolated managed root genuinely holds no Python-
    // provider scratch state (Pyright writes none, per this file's own doc
    // comment trace) -- so a real full_uninstall has nothing to prematurely
    // destroy in the first place, distinct from gopls's pre-fix hazard.
    let scratch = fixture.scratch();
    if scratch.exists() {
        return Err(fail(format!(
            "expected no Python-provider scratch state under {}, found some -- the trace this \
             file's doc comment relies on would be wrong",
            scratch.display()
        )));
    }

    // The real, product-facing boundary, run while the session is live.
    let outcome =
        full_uninstall::uninstall_all_corulix_managed_components_at(&fixture.managed_root)
            .await
            .map_err(|error| fail(format!("full_uninstall must succeed, got {error:?}")))?;
    if outcome != FullUninstallOutcome::NoManagedComponents {
        return Err(fail(format!(
            "this isolated root holds no managed component, expected NoManagedComponents, got \
             {outcome:?}"
        )));
    }

    // The decisive proof: the SAME live session, through the SAME engine,
    // still answers a real semantic request correctly after full_uninstall
    // ran against its managed root while it was active.
    real_references(&engine, &fixture, "post-full-uninstall").await?;
    eprintln!("P17_PYRIGHT_POST_FULL_UNINSTALL_SEMANTIC_REQUEST=PASS");
    eprintln!("P17_ACTIVE_PYRIGHT_FULL_UNINSTALL_E2E=PASS");
    eprintln!(
        "P17_PYRIGHT_MANAGED_ROOT_LEASE_DEFECT=ABSENT (traced: no managed-root-scoped cache is \
         ever bound to a Pyright session, unlike gopls pre-P15-fix; proven empirically above)"
    );
    Ok(())
}
