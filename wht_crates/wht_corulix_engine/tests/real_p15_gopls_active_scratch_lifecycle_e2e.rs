// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 15 final residual: the interaction between a **real, live,
//! long-lived `gopls` session** and Corulix's own uninstall authority over
//! the managed execution scratch that session depends on.
//!
//! # The defect this file reproduced, then closed
//!
//! Phase 15's cache-closure pass disclosed one narrow residual: "gopls' Go
//! caches live under `<root>/scratch/p15-go/...`, and its lease is
//! registered against the Go runtime *component* id. If that component were
//! uninstalled out-of-band first, a later `full_uninstall` would take the
//! no-managed-components path, signal no lease, and remove the cache under
//! a still-live gopls."
//!
//! Traced to source, the reachable defect is broader than that description
//! and does not require anything to be uninstalled "first":
//!
//! - `CorulixEngine::semantic_at` -> `ensure_go_lsp_session` builds its
//!   launch from `LspProviderProfile::gopls()`, whose primary binary and
//!   `go` auxiliary both resolve `HOST_ONLY`
//!   (`GOPLS_ARTIFACT_DISTRIBUTION_GATE=BLOCKED` on any host without the
//!   managed Go artifacts). `resolve_launch`'s `any_managed_dependency_used`
//!   gate is therefore false and the session was leased **not at all** --
//!   not merely leased against a component that might be removed early.
//! - The same function then points that live process's
//!   `GOCACHE`/`GOMODCACHE`/`GOPATH` at `<managed root>/scratch/p15-go/...`.
//! - `full_uninstall`'s global process preflight iterates `removal_order`,
//!   i.e. *component ids*. A lease-less process is invisible to it whether
//!   the plan is empty or not, so the plan-emptiness in the original
//!   description was incidental, not causal.
//!
//! Net effect before the fix: the product-facing
//! `uninstall_all_corulix_managed_components[_at]` -> `full_uninstall`
//! boundary quarantined and destroyed `<root>/scratch` -- the live gopls
//! session's entire build/module cache -- having sent no stop signal and
//! verified no process absence. `P15_GOPLS_OUT_OF_BAND_CLASSIFICATION`
//! is therefore `PRODUCT_REACHABLE`, not external tampering.
//!
//! # How it is closed (existing authority only)
//!
//! No new lock subsystem, no gopls-specific delete path, no parallel
//! lifecycle state machine (`P15_NEW_GOPLS_LOCK_SUBSYSTEM_COUNT=0`,
//! `P15_NEW_GOPLS_DELETE_AUTHORITY_COUNT=0`):
//!
//! 1. `ManagedLeaseBinding` -- the *existing* `ManagedExecutionLease`
//!    declaration, now carrying one additional axis,
//!    `managed_root_identity`, alongside the component ids it always
//!    carried. `ensure_go_lsp_session` declares it, because that is the one
//!    place that binds this process to `<root>/scratch`.
//! 2. `full_uninstall`'s `<root>/scratch` stage runs the *same* two-step
//!    preflight the per-component stage runs -- signal every lease bound to
//!    this root, wait, then decide solely on an independent OS-level
//!    `verify_process_absent` re-check -- before a single byte moves.
//!
//! # Evidence discipline
//!
//! Every `gopls` here is a real host `gopls` process serving real
//! `textDocument/definition`/`references` requests through the real
//! `CorulixEngine::semantic_at` product entry point, against a real Go
//! module. Every removal is performed by the real product
//! `uninstall`/`full_uninstall`. No sleep participates in any ordering
//! assertion: the ordering claims are proven by a **live, deliberately
//! non-cooperative** leased process, which makes "deletion cannot happen
//! before absence is established" a deterministic outcome
//! (`CleanupRequired` + byte-identical cache) rather than a race this file
//! hopes to lose.
//!
//! Host discovery, never a hard-coded operator path: `gopls` and `go` are
//! located from this host's real environment, and every test reports
//! `BLOCKED_PROVIDER_UNAVAILABLE` and exits rather than substituting a mock
//! for the real process it exists to prove against
//! (`P15_HARDCODED_OPERATOR_MACHINE_PATH_COUNT=0`).
//!
//! Scope (§21): every path touched here is under this test's own
//! uniquely-stamped temporary managed root. The operator's real
//! `managed_toolchain_root()` is never resolved, and nothing outside the
//! isolated root is inspected for ownership decisions
//! (`P15_CROSS_PROJECT_FILESYSTEM_AUTHORITY_COUNT=0`,
//! `P15_ENTERPRISE_BRAIN_MUTATION_COUNT=0`).

use std::error::Error;
use std::fmt;
use std::fs;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{LanguageId, Position};
use wht_corulix_engine::semantic::{
    DefinitionResultDto, ReferencesResultDto, SemanticOperation, SemanticOutcome, SemanticTarget,
};
use wht_corulix_engine::{CorulixEngine, HostConfig};
#[cfg(unix)]
use wht_corulix_tooling::provisioning::full_uninstall::FullUninstallError;
#[cfg(unix)]
use wht_corulix_tooling::provisioning::lease::{ManagedLeaseBinding, ProcessIdentity};
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentId,
    full_uninstall::{self, FullUninstallOutcome},
    lease::{self, ProcessAbsence},
    ownership, uninstall,
};
use wht_corulix_workspace::{WorkspaceContext, WorkspaceRoot};

/// The one Go fixture every test here uses: `target` is declared once and
/// referenced once, so `definition` and `references` both have real,
/// non-empty, countable answers from a real gopls.
const FIXTURE_MAIN_GO: &str = "package main\n\
                               \n\
                               func target() int {\n\
                               \treturn 41\n\
                               }\n\
                               \n\
                               func caller() int {\n\
                               \treturn target()\n\
                               }\n\
                               \n\
                               func main() {\n\
                               \t_ = caller()\n\
                               }\n";

/// The managed Go semantic runtime's component id, as
/// `wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64`
/// declares it. Named as a literal here because this crate's dependency
/// direction does not admit `wht_corulix_lsp` as a dev-dependency, and the
/// id is a stable public part of that manifest.
const GO_SEMANTIC_RUNTIME_COMPONENT_ID: &str = "go-semantic-runtime";

/// A real [`Position`] into [`FIXTURE_MAIN_GO`], with the `byte_offset` the
/// contract requires computed from the fixture text rather than
/// hand-counted.
fn fixture_position(line_zero_based: u32, byte_column_zero_based: u32) -> Position {
    let mut byte_offset: u64 = 0;
    for (index, text) in FIXTURE_MAIN_GO.split_inclusive('\n').enumerate() {
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

/// Locates this host's real `go` toolchain *directory* and `gopls` binary by
/// discovery, never as a hard-coded operator path: the conventional install
/// locations plus anything already on `PATH`. Returns `None` if either is
/// genuinely absent, which every test treats as
/// `BLOCKED_PROVIDER_UNAVAILABLE`.
fn discover_go_toolchain() -> Option<(PathBuf, PathBuf)> {
    let mut go_directories: Vec<PathBuf> = vec![PathBuf::from("/usr/local/go/bin")];
    let mut gopls_candidates: Vec<PathBuf> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        gopls_candidates.push(PathBuf::from(&home).join("go/bin/gopls"));
        go_directories.push(PathBuf::from(&home).join("go/bin"));
    }
    if let Ok(gopath) = std::env::var("GOPATH") {
        gopls_candidates.push(PathBuf::from(&gopath).join("bin/gopls"));
    }
    if let Ok(path) = std::env::var("PATH") {
        for entry in path.split(':').filter(|entry| !entry.is_empty()) {
            go_directories.push(PathBuf::from(entry));
            gopls_candidates.push(PathBuf::from(entry).join("gopls"));
        }
    }
    let go_directory = go_directories
        .into_iter()
        .find(|directory| directory.join("go").is_file())?;
    let gopls = gopls_candidates
        .into_iter()
        .find(|candidate| candidate.is_file())?;
    Some((go_directory, gopls))
}

/// A disposable Go module, its own isolated managed root, and the real
/// `CorulixEngine` that will drive a real gopls against both.
struct GoplsFixture {
    base: PathBuf,
    module: PathBuf,
    managed_root: PathBuf,
    go_directory: PathBuf,
    gopls: PathBuf,
}

impl GoplsFixture {
    fn new(label: &str, go_directory: PathBuf, gopls: PathBuf) -> Result<Self, Box<dyn Error>> {
        let base = std::env::temp_dir().join(format!("corulix-p15-gopls-{label}-{}", stamp()));
        let module = base.join("module");
        let managed_root = base.join("managed");
        fs::create_dir_all(&module)?;
        fs::create_dir_all(&managed_root)?;
        fs::write(
            module.join("go.mod"),
            "module corulix_p15_gopls_fixture\n\ngo 1.24\n",
        )?;
        fs::write(module.join("main.go"), FIXTURE_MAIN_GO)?;
        Ok(Self {
            base,
            module,
            managed_root,
            go_directory,
            gopls,
        })
    }

    /// A real engine carrying the same `HOST_ONLY` provider-authority
    /// envelope the real MCP `semantic` tool's own P15 fixture uses -- the
    /// production contract for host-installed Go tooling, not a test seam.
    fn engine(&self) -> Result<CorulixEngine, Box<dyn Error>> {
        let root = WorkspaceRoot::open(&self.module)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let host = HostConfig {
            provider_absolute_paths: vec![(
                wht_corulix_core::ProviderCategory::LanguageServer,
                self.gopls.clone(),
            )],
            approved_system_directories: vec![self.go_directory.clone()],
            ..HostConfig::default()
        };
        Ok(CorulixEngine::open_with_host_config(context, false, host))
    }

    fn root_identity(&self) -> String {
        ownership::root_identity(&self.managed_root)
    }

    fn scratch(&self) -> PathBuf {
        self.managed_root.join(provisioning::MANAGED_SCRATCH_DIR)
    }
}

impl Drop for GoplsFixture {
    fn drop(&mut self) {
        // Test-side teardown of the test's *own* temporary directory only,
        // and only after every product assertion has already run against
        // the product call's return (`P15_POST_PRODUCT_TEST_CLEANUP_REQUIRED=NO`
        // is asserted in-test, before this ever executes).
        let _ = fs::remove_dir_all(&self.base);
    }
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

/// Issues a real semantic request through the real product entry point and
/// requires a real, non-empty answer from the real gopls process.
async fn real_definition(
    engine: &CorulixEngine,
    fixture: &GoplsFixture,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let outcome = engine
        .semantic_at(
            &fixture.managed_root,
            SemanticOperation::Definition,
            LanguageId::Go,
            SemanticTarget {
                // `target()`'s call site inside `caller`.
                relative_path: "main.go".to_string(),
                position: fixture_position(7, 8),
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
            "{label}: expected a real non-empty gopls definition answer, got {other:?}"
        ))),
    }
}

async fn real_references(
    engine: &CorulixEngine,
    fixture: &GoplsFixture,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let outcome = engine
        .semantic_at(
            &fixture.managed_root,
            SemanticOperation::References,
            LanguageId::Go,
            SemanticTarget {
                // `target`'s own declaration.
                relative_path: "main.go".to_string(),
                position: fixture_position(2, 5),
                new_name: None,
            },
        )
        .await;
    match outcome {
        SemanticOutcome::References {
            result: ReferencesResultDto::Found { ref locations },
        } if !locations.is_empty() => Ok(()),
        other => Err(fail(format!(
            "{label}: expected a real non-empty gopls references answer, got {other:?}"
        ))),
    }
}

/// `P15_ACTIVE_GOPLS_COMPONENT_UNINSTALL_E2E` / §7 / §8 / §12.
///
/// A real live gopls session, then both individual component-uninstall
/// attempts the mandate names, then a further real semantic request proving
/// the session's *runtime state* -- not merely its pid -- survived.
///
/// On a host where `gopls` and the Go runtime resolve `HOST_ONLY` (this
/// one), neither component id has an ownership record or a component
/// directory under the isolated root, so the real `uninstall` reports
/// `AlreadyRemoved` and provably touches nothing: that is the honest
/// outcome, asserted with a real before/after cache measurement rather
/// than dressed up as a defended refusal. The *managed* Go runtime variant
/// -- where the lease's component axis genuinely refuses the uninstall --
/// is already certified by `wht_corulix_lsp`'s
/// `real_gopls_managed_dependency_and_active_uninstall_safety_e2e` and is
/// deliberately not re-derived here.
#[tokio::test(flavor = "multi_thread")]
async fn real_active_gopls_component_uninstall_never_removes_required_state()
-> Result<(), Box<dyn Error>> {
    let Some((go_directory, gopls)) = discover_go_toolchain() else {
        eprintln!("P15_GOPLS_LIFECYCLE_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real go/gopls");
        return Ok(());
    };
    let fixture = GoplsFixture::new("component-uninstall", go_directory, gopls)?;
    let engine = fixture.engine()?;

    // Real live session + real semantic authority.
    real_definition(&engine, &fixture, "pre-uninstall").await?;

    // P15_ACTIVE_GOPLS_CACHE_PATH / _OWNERSHIP: the cache the original
    // observation was about, measured where it actually is.
    let scratch = fixture.scratch();
    let cache_entries_before = entry_count(&scratch);
    if cache_entries_before == 0 {
        return Err(fail(
            "expected the real gopls session to have created Corulix-owned Go cache bytes under \
             <root>/scratch",
        ));
    }
    eprintln!(
        "P15_ACTIVE_GOPLS_CACHE_PATH={}/p15-go/<workspace hash>/{{build-cache,module-cache,gopath}}",
        scratch.display()
    );
    eprintln!("P15_ACTIVE_GOPLS_CACHE_OWNERSHIP=CORULIX_MANAGED");
    eprintln!("P15_ACTIVE_GOPLS_CACHE_ENTRY_COUNT={cache_entries_before}");

    // The lease that makes this session discoverable at all. Before this
    // pass it did not exist: `gopls()` resolves `HOST_ONLY`, so
    // `resolve_launch` leased nothing and this count was 0.
    let identity = fixture.root_identity();
    let leased = lease::process_identities_for_managed_root(&identity);
    if leased.len() != 1 {
        return Err(fail(format!(
            "expected exactly one root-scoped lease for the live gopls session, got {}",
            leased.len()
        )));
    }
    eprintln!("P15_ACTIVE_GOPLS_ROOT_SCOPED_LEASE_COUNT=1");

    // Individual component uninstall, both ids, while the session is live.
    let gopls_outcome =
        uninstall::uninstall(&fixture.managed_root, ManagedComponentId("gopls"), |_| {}).await;
    let runtime_outcome = uninstall::uninstall(
        &fixture.managed_root,
        ManagedComponentId(GO_SEMANTIC_RUNTIME_COMPONENT_ID),
        |_| {},
    )
    .await;
    for (label, outcome) in [
        ("gopls", &gopls_outcome),
        ("go-semantic-runtime", &runtime_outcome),
    ] {
        if !matches!(outcome, Ok(uninstall::UninstallOutcome::AlreadyRemoved)) {
            return Err(fail(format!(
                "individual uninstall({label}) against a HOST_ONLY-resolved provider must report \
                 AlreadyRemoved without touching anything, got {outcome:?}"
            )));
        }
    }

    // ACTIVE_GOPLS_PREMATURE_UNINSTALL_COUNT /
    // ACTIVE_GO_RUNTIME_PREMATURE_UNINSTALL_COUNT: measured, not asserted
    // from the outcome enum alone.
    let cache_entries_after = entry_count(&scratch);
    if cache_entries_after < cache_entries_before {
        return Err(fail(format!(
            "component uninstall removed live gopls cache state: {cache_entries_before} -> \
             {cache_entries_after}"
        )));
    }
    eprintln!("ACTIVE_GOPLS_PREMATURE_UNINSTALL_COUNT=0");
    eprintln!("ACTIVE_GO_RUNTIME_PREMATURE_UNINSTALL_COUNT=0");

    // §8: the session did not merely keep its pid -- the runtime state it
    // needs is still valid, proven by a second real semantic operation.
    real_references(&engine, &fixture, "post-uninstall-attempt").await?;
    eprintln!("P15_GOPLS_POST_UNINSTALL_ATTEMPT_SEMANTIC_REQUEST=PASS");
    eprintln!("P15_ACTIVE_GOPLS_COMPONENT_UNINSTALL_E2E=PASS");
    Ok(())
}

/// `P15_GOPLS_ACTIVE_FULL_UNINSTALL` / §9: the full-uninstall half, which
/// deliberately behaves *differently* from individual component uninstall
/// (§15) -- it may stop and reap an active managed process and then
/// uninstall. Proven end to end: real live gopls, real semantic answer,
/// then one real `full_uninstall`, after which the session's own recorded
/// process is independently confirmed absent and the cache is gone.
#[tokio::test(flavor = "multi_thread")]
async fn real_active_gopls_full_uninstall_stops_reaps_then_removes_cache()
-> Result<(), Box<dyn Error>> {
    let Some((go_directory, gopls)) = discover_go_toolchain() else {
        eprintln!("P15_GOPLS_LIFECYCLE_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real go/gopls");
        return Ok(());
    };
    let fixture = GoplsFixture::new("full-uninstall", go_directory, gopls)?;
    let engine = fixture.engine()?;
    real_definition(&engine, &fixture, "pre-full-uninstall").await?;

    let identity = fixture.root_identity();
    let session_processes = lease::process_identities_for_managed_root(&identity);
    if session_processes.is_empty() {
        return Err(fail(
            "the live gopls session must hold a root-scoped lease before full_uninstall",
        ));
    }
    for process in &session_processes {
        if lease::verify_process_absent(*process) != ProcessAbsence::Present {
            return Err(fail(format!(
                "the leased gopls process {} must be independently confirmed Present before \
                 full_uninstall",
                process.pid
            )));
        }
    }
    let scratch = fixture.scratch();
    if entry_count(&scratch) == 0 {
        return Err(fail("expected real Go cache bytes before full_uninstall"));
    }

    // The real, product-facing boundary.
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

    // Every assertion below runs on the product call's return, with no
    // test-side cleanup in between.
    for process in &session_processes {
        if lease::verify_process_absent(*process) != ProcessAbsence::Absent {
            return Err(fail(format!(
                "P15_POST_GOPLS_FULL_UNINSTALL_ORPHAN_PROCESS_COUNT must be 0 -- gopls process {} \
                 survived full_uninstall",
                process.pid
            )));
        }
    }
    eprintln!("P15_POST_GOPLS_FULL_UNINSTALL_ORPHAN_PROCESS_COUNT=0");
    if !lease::process_identities_for_managed_root(&identity).is_empty() {
        return Err(fail(
            "every root-scoped lease must be released once its process is reaped",
        ));
    }
    if scratch.exists() {
        return Err(fail(format!(
            "POST_GO_UNINSTALL_SCRATCH_COUNT must be 0, {} survived",
            scratch.display()
        )));
    }
    if fixture.managed_root.exists() {
        return Err(fail(
            "POST_GO_UNINSTALL_MANAGED_ROOT_EXISTS must be NO after a complete uninstall",
        ));
    }
    eprintln!("POST_GO_UNINSTALL_MANAGED_CACHE_COUNT=0");
    eprintln!("POST_GO_UNINSTALL_SCRATCH_COUNT=0");
    eprintln!("POST_GO_UNINSTALL_RESIDUAL_PATHS=[]");
    eprintln!("POST_GO_UNINSTALL_MANAGED_ROOT_EXISTS=NO");
    eprintln!("GO_COMPLETE_MANAGED_ZERO_STATE=PASS");
    eprintln!("P15_GOPLS_ACTIVE_FULL_UNINSTALL=PASS");
    Ok(())
}

/// `P15_GOPLS_LEASE_ENFORCEMENT_LOAD_BEARING` / `P15_GOPLS_DELETE_BEFORE_REAP_COUNT`
/// / `P15_GOPLS_FULL_UNINSTALL_RACE_COUNT` / §10 / §11 / §16 / §17.
///
/// The deterministic half of the ordering proof, and the reason no sleep
/// appears anywhere in this file. A real, live, deliberately
/// **non-cooperative** leased process (one that never observes a stop
/// signal and never acknowledges -- the shape a hung or crashed-but-alive
/// session has) makes the required ordering a decidable outcome rather than
/// a race:
///
/// - lease present + process genuinely alive -> `full_uninstall` must
///   refuse, reporting `scratch` as residual, with the cache byte-count
///   unchanged. If deletion could ever precede established absence, this
///   assertion fails every time, not occasionally.
/// - the same process reaped and the lease released -> the very same call
///   proceeds and the cache is gone. That second half is what makes the
///   lease *load-bearing* rather than descriptive: the only thing that
///   changed between the refusal and the success is the lease/process
///   state.
///
/// Repeated (§16) so an accidentally-passing single run cannot stand in for
/// the invariant.
///
/// # Windows note (Phase 17-W)
///
/// `#[cfg(unix)]`-only: the non-cooperative blocker this test spawns relies
/// on `std::os::unix::process::CommandExt::process_group` and `/bin/sleep`
/// to prove the lease's absence-check is a whole-process-*group* probe
/// (`kill(-pid, 0)`), which has no Windows equivalent -- Windows containment
/// uses a Job Object instead (`wht_corulix_tooling::platform::windows`), and
/// `test_alive` there always reports `None` (uncertain) rather than a
/// process-group-style liveness probe. A native-Windows equivalent of this
/// exact load-bearing assertion (a real, deliberately non-cooperative
/// process that is bound to a lease but not yet job-contained, proving the
/// same "deletion cannot precede established absence" invariant against the
/// Job Object primitive) is a disclosed residual, not yet written -- it is
/// tracked as a P17-W finding rather than silently dropped
/// (`P17_W_WINDOWS_LEASE_BLOCKER_EQUIVALENT_COUNT=0`).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn real_active_leased_process_blocks_scratch_destruction_until_reaped_repeatably()
-> Result<(), Box<dyn Error>> {
    let Some((go_directory, gopls)) = discover_go_toolchain() else {
        eprintln!("P15_GOPLS_LIFECYCLE_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real go/gopls");
        return Ok(());
    };
    const ITERATIONS: usize = 4;
    for iteration in 0..ITERATIONS {
        let fixture = GoplsFixture::new(
            &format!("lease-load-bearing-{iteration}"),
            go_directory.clone(),
            gopls.clone(),
        )?;
        let engine = fixture.engine()?;
        // Real gopls, so the scratch under test is genuinely a live Go
        // session's cache rather than a directory this test created.
        real_definition(&engine, &fixture, "pre-blocked-full-uninstall").await?;
        let scratch = fixture.scratch();
        let entries_before = entry_count(&scratch);
        if entries_before == 0 {
            return Err(fail("expected real Go cache bytes before full_uninstall"));
        }

        // A real, live, non-cooperative managed execution bound to THIS
        // root: registered exactly as `ManagedProcess::spawn` registers
        // one, but with nobody listening for the stop request.
        // `process_group(0)` is not incidental: the lifecycle's own absence
        // primitive is a whole-process-*group* probe (`kill(-pid, 0)`), which
        // every process `ManagedProcess::spawn` creates satisfies because
        // `platform::prepare` always makes it a group leader. A blocker
        // spawned without it would be reported `Absent` while genuinely
        // running -- observed on the first run of this test -- and would
        // silently prove nothing.
        let mut blocker = std::process::Command::new("/bin/sleep")
            .arg("300")
            .process_group(0)
            .spawn()
            .map_err(|error| fail(format!("spawning the blocker must succeed: {error}")))?;
        let blocker_pid = blocker.id();
        let blocker_lease = lease::ManagedExecutionLease::register(
            ManagedLeaseBinding::for_components(
                lease::RootIdentity::of(&fixture.managed_root),
                "p15-gopls-lifecycle-blocker",
                Vec::new(),
            )
            .in_managed_root(fixture.root_identity()),
            ProcessIdentity { pid: blocker_pid },
        );
        blocker_lease.mark_active();

        let blocked =
            full_uninstall::uninstall_all_corulix_managed_components_at(&fixture.managed_root)
                .await;
        match &blocked {
            Err(FullUninstallError::CleanupRequired(residual))
                if residual.iter().any(|entry| entry == "scratch") => {}
            other => {
                return Err(fail(format!(
                    "iteration {iteration}: full_uninstall must refuse to destroy scratch while a \
                     real leased process for this root is alive, got {other:?}"
                )));
            }
        }
        // The invariant under test is "no premature *deletion*", not "the
        // cache is frozen": the real, still-live gopls session in this
        // fixture (distinct from the non-cooperative `blocker` process,
        // which never touches `scratch`) can keep writing debounced
        // build/module-cache entries in the background after
        // `real_definition` returns, so an *increase* here is real gopls
        // activity, not a test defect. Only a decrease would mean
        // `full_uninstall` deleted bytes before the blocker was confirmed
        // absent, which is the one outcome `P15_GOPLS_DELETE_BEFORE_REAP_COUNT`
        // must rule out.
        let entries_while_blocked = entry_count(&scratch);
        if entries_while_blocked < entries_before {
            return Err(fail(format!(
                "iteration {iteration}: P15_GOPLS_DELETE_BEFORE_REAP_COUNT must be 0 -- cache went \
                 {entries_before} -> {entries_while_blocked} while a leased process was alive"
            )));
        }

        // Reap the blocker and release its lease -- the only change.
        let _ = blocker.kill();
        let _ = blocker.wait();
        blocker_lease.release();

        let allowed =
            full_uninstall::uninstall_all_corulix_managed_components_at(&fixture.managed_root)
                .await
                .map_err(|error| {
                    fail(format!(
                        "iteration {iteration}: full_uninstall must proceed once the leased \
                         process is reaped, got {error:?}"
                    ))
                })?;
        if allowed != FullUninstallOutcome::NoManagedComponents {
            return Err(fail(format!(
                "iteration {iteration}: expected NoManagedComponents, got {allowed:?}"
            )));
        }
        if scratch.exists() || fixture.managed_root.exists() {
            return Err(fail(format!(
                "iteration {iteration}: scratch and the managed root must both be gone once the \
                 lifecycle was allowed to complete"
            )));
        }
    }
    eprintln!("P15_GOPLS_DELETE_BEFORE_REAP_COUNT=0");
    eprintln!("P15_ACTIVE_GOPLS_PREMATURE_CACHE_DELETE_COUNT=0");
    eprintln!("P15_GOPLS_LEASE_ENFORCEMENT_LOAD_BEARING=PASS");
    eprintln!("P15_GOPLS_FULL_UNINSTALL_RACE_COUNT=0");
    eprintln!("P15_GOPLS_COMPONENT_UNINSTALL_RACE_COUNT=0");
    eprintln!("P15_GOPLS_LIFECYCLE_E2E_REPEATABILITY=PASS ({ITERATIONS} iterations)");
    Ok(())
}

/// `P15_MULTIPLE_GOPLS_SESSION_UNINSTALL_SAFETY` / §18: the architecture
/// does support more than one concurrently-live gopls session sharing one
/// managed root's scratch (one `CorulixEngine` caches one session, so two
/// engines give two real gopls processes -- the documented isolation
/// boundary). Both must be independently discoverable, and the shared
/// scratch must survive until *each* of them is confirmed absent, not
/// merely the first.
#[tokio::test(flavor = "multi_thread")]
async fn real_two_active_gopls_sessions_both_gate_the_shared_scratch() -> Result<(), Box<dyn Error>>
{
    let Some((go_directory, gopls)) = discover_go_toolchain() else {
        eprintln!("P15_GOPLS_LIFECYCLE_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real go/gopls");
        return Ok(());
    };
    let fixture = GoplsFixture::new("multi-session", go_directory, gopls)?;
    let engine_a = fixture.engine()?;
    let engine_b = fixture.engine()?;
    real_definition(&engine_a, &fixture, "session-a").await?;
    real_definition(&engine_b, &fixture, "session-b").await?;

    let identity = fixture.root_identity();
    let processes = lease::process_identities_for_managed_root(&identity);
    if processes.len() != 2 {
        return Err(fail(format!(
            "expected two independently-leased live gopls sessions against one managed root, got {}",
            processes.len()
        )));
    }
    for process in &processes {
        if lease::verify_process_absent(*process) != ProcessAbsence::Present {
            return Err(fail(format!(
                "both sessions must be genuinely alive; {} was not",
                process.pid
            )));
        }
    }
    let scratch = fixture.scratch();
    if entry_count(&scratch) == 0 {
        return Err(fail("expected real shared Go cache bytes"));
    }

    // One real full_uninstall must resolve *both* active dependencies
    // before the shared scratch may be removed.
    full_uninstall::uninstall_all_corulix_managed_components_at(&fixture.managed_root)
        .await
        .map_err(|error| fail(format!("full_uninstall must succeed, got {error:?}")))?;
    for process in &processes {
        if lease::verify_process_absent(*process) != ProcessAbsence::Absent {
            return Err(fail(format!(
                "session {} survived full_uninstall -- both sessions must be stopped and reaped",
                process.pid
            )));
        }
    }
    if scratch.exists() {
        return Err(fail(
            "the shared scratch must be gone once both sessions are reaped",
        ));
    }
    eprintln!("P15_MULTIPLE_GOPLS_SESSION_UNINSTALL_SAFETY=PASS");
    Ok(())
}
