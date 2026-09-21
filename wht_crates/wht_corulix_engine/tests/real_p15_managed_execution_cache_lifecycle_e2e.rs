// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 15 cache closure: real managed execution cache creation, then real
//! zero-residual `full_uninstall`, for both governed toolchain verticals.
//!
//! # What "real" means here
//!
//! No fixture asserts against a hand-created directory: every cache in this
//! file is produced by a genuine governed execution of the real toolchain
//! (`go build`/`go vet`/`go test` via
//! `wht_corulix_engine::go_validation`/`go_testing`, `cargo test` via
//! `wht_corulix_engine::testing`) writing real cache bytes, and every removal
//! is performed by the real
//! `wht_corulix_tooling::provisioning::full_uninstall::full_uninstall`. The
//! ownership/quarantine/verify/destroy lifecycle is never bypassed, and no
//! test performs any cleanup of its own between the product call returning
//! and the zero-state assertions (`P15_POST_PRODUCT_TEST_CLEANUP_REQUIRED=NO`).
//!
//! # Why the Go and Rust halves are shaped differently
//!
//! The Go vertical resolves its `go` provider from an *approved host
//! directory* (no Corulix-managed component is installed for it), so its
//! managed root holds only the execution caches this phase is about. The Rust
//! vertical requires a genuinely provisioned managed Rust runtime, so its
//! half provisions one into its own isolated root and then removes both the
//! component and its caches in one transaction -- which is exactly the
//! stronger, mixed-content case.
//!
//! # Isolation (§23)
//!
//! Every test resolves its own uniquely-stamped temporary managed root. The
//! operator's real `managed_toolchain_root()` and the shared, pre-provisioned
//! `~/.cache/corulix-p11-diagnostics-e2e/root` other suites use are never
//! passed to `full_uninstall` here (`P15_TEST_SHARED_HOST_ROOT_MUTATION_COUNT=0`).
//!
//! # Network honesty (§11)
//!
//! `OS_LEVEL_NETWORK_ISOLATION=NOT_CLAIMED`. The Go fixtures are
//! self-contained stdlib-only modules with `GOPROXY=off`/`GOTOOLCHAIN=local`,
//! requiring no download whatsoever. The Rust half does require a real
//! managed-runtime provision (a download), and reports
//! `BLOCKED_PROVISIONING_FAILED` rather than substituting a mock if that is
//! unavailable.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceTrust};
use wht_corulix_engine::go_testing;
use wht_corulix_engine::go_validation::{self, GoValidator};
use wht_corulix_engine::testing::run_cargo_test;
use wht_corulix_tooling::managed_runtimes::{
    GNU_LINK_RUNTIME_LINUX_X64, RUST_SEMANTIC_RUNTIME_LINUX_X64,
};
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentState, full_uninstall,
    ownership::{self, OwnershipClass},
};
use wht_corulix_workspace::WorkspaceRoot;

/// This host's real Go toolchain directory, identical to the constant P15's
/// own build/vet/test E2E suite already uses.
const REAL_GO_DIRECTORY: &str = "/usr/local/go/bin";

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

fn real_go_available() -> bool {
    Path::new(REAL_GO_DIRECTORY).join("go").is_file()
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

fn top_level_names(root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

/// Asserts the complete post-`full_uninstall` zero state for `root`, exactly
/// as Phase 15's §13 contract enumerates it.
fn assert_complete_managed_zero_state(root: &Path, label: &str) -> Result<(), Box<dyn Error>> {
    let scratch = root.join(provisioning::MANAGED_SCRATCH_DIR);
    if scratch.exists() {
        return Err(fail(format!(
            "{label}: POST_UNINSTALL_MANAGED_CACHE_COUNT!=0 -- {} survived with {} entries",
            scratch.display(),
            entry_count(&scratch)
        )));
    }
    for (name, metric) in [
        ("staging", "POST_UNINSTALL_STAGING_COUNT"),
        (".uninstall-txn", "POST_UNINSTALL_QUARANTINE_COUNT"),
        ("ownership", "POST_UNINSTALL_LIVE_OWNERSHIP_RECORD_COUNT"),
        ("components", "POST_UNINSTALL_MANAGED_COMPONENT_COUNT"),
    ] {
        if root.join(name).exists() {
            return Err(fail(format!("{label}: {metric}!=0 -- {name}/ survived")));
        }
    }
    let residual = top_level_names(root);
    if !residual.is_empty() {
        return Err(fail(format!(
            "{label}: POST_UNINSTALL_RESIDUAL_PATHS must be [], got {residual:?}"
        )));
    }
    if root.exists() {
        return Err(fail(format!(
            "{label}: POST_UNINSTALL_MANAGED_ROOT_EXISTS must be NO"
        )));
    }

    // POST_UNINSTALL_LIVE_OWNERSHIP_RECORD_COUNT / _DEPENDENCY_COUNT,
    // measured rather than inferred from the absence of a directory: reading
    // the real ownership authority proves both that no record survives and
    // that no surviving record still declares a dependency edge.
    let records: Vec<_> = ownership::list(root)
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    if !records.is_empty() {
        return Err(fail(format!(
            "{label}: POST_UNINSTALL_LIVE_OWNERSHIP_RECORD_COUNT must be 0, got {}",
            records.len()
        )));
    }
    let dependency_count: usize = records.iter().map(|record| record.dependencies.len()).sum();
    if dependency_count != 0 {
        return Err(fail(format!(
            "{label}: POST_UNINSTALL_DEPENDENCY_COUNT must be 0, got {dependency_count}"
        )));
    }

    // POST_UNINSTALL_ACTIVE_LEASE_COUNT, from the real lease registry. A
    // bounded one-shot governed execution registers no lease, and this
    // suite spawns no `ManagedProcess`, so the whole-registry count is a
    // sound measurement here (unlike inside `wht_corulix_tooling`'s own test
    // binary, where sibling lease tests hold their own fixture leases
    // concurrently).
    let active_leases = provisioning::lease::active_lease_count();
    if active_leases != 0 {
        return Err(fail(format!(
            "{label}: POST_UNINSTALL_ACTIVE_LEASE_COUNT must be 0, got {active_leases}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Go vertical
// ---------------------------------------------------------------------

/// A disposable, stdlib-only Go module plus its own isolated managed root.
struct GoFixture {
    base: PathBuf,
    module: PathBuf,
    managed_root: PathBuf,
}

impl GoFixture {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir().join(format!("corulix-p15-cache-{label}-{}", stamp()));
        let module = base.join("module");
        let managed_root = base.join("managed");
        let _ = fs::create_dir_all(&module);
        let _ = fs::create_dir_all(&managed_root);
        let _ = fs::write(
            module.join("go.mod"),
            "module corulix_p15_cache_fixture\n\ngo 1.24\n",
        );
        Self {
            base,
            module,
            managed_root,
        }
    }

    fn write(&self, name: &str, contents: &str) {
        let _ = fs::write(self.module.join(name), contents);
    }

    fn root(&self) -> Result<WorkspaceRoot, Box<dyn Error>> {
        Ok(WorkspaceRoot::open(&self.module)?)
    }
}

fn go_config() -> EffectiveConfig {
    let host = HostConfig {
        workspace_trust: WorkspaceTrust::Trusted,
        allow_trusted_workspace_execution: true,
        approved_system_directories: vec![PathBuf::from(REAL_GO_DIRECTORY)],
        ..HostConfig::default()
    };
    EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

const VALID_MAIN: &str =
    "package main\n\nfunc target() int {\n\treturn 41\n}\n\nfunc main() {\n\t_ = target()\n}\n";

const PASSING_TEST: &str = "package main\n\nimport \"testing\"\n\nfunc TestTarget(t *testing.T) {\n\tif target() != 41 {\n\t\tt.Fatal(\"unexpected\")\n\t}\n}\n";

/// `P15_REAL_GO_MANAGED_CACHE_CREATION` + `GO_COMPLETE_MANAGED_ZERO_STATE`:
/// real `go build`, `go vet` and `go test` executions create real Go build/
/// module cache bytes under the Corulix-owned managed scratch root, and a
/// single subsequent `full_uninstall` removes every one of them, reaching
/// complete zero state with no test-side cleanup.
#[tokio::test(flavor = "multi_thread")]
async fn real_go_managed_cache_is_created_then_fully_removed_to_zero_state()
-> Result<(), Box<dyn Error>> {
    if !real_go_available() {
        eprintln!(
            "P15_MANAGED_EXECUTION_CACHE_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real go at \
             {REAL_GO_DIRECTORY}"
        );
        return Ok(());
    }
    let fixture = GoFixture::new("go-zero-state");
    fixture.write("main.go", VALID_MAIN);
    fixture.write("main_test.go", PASSING_TEST);
    let root = fixture.root()?;
    let config = go_config();
    let cancellation = CancellationToken::new();

    // Three genuinely distinct governed executions, each of which the real
    // `go` command services partly from (and writes into) the managed cache.
    for validator in [GoValidator::Build, GoValidator::Vet] {
        let outcome = go_validation::run_go_validator(
            validator,
            &fixture.managed_root,
            &root,
            &config,
            &cancellation,
        )
        .await
        .map_err(|error| fail(format!("real go {validator:?} failed: {error:?}")))?;
        if !outcome.is_clean() {
            return Err(fail(format!(
                "fixture must be clean under {validator:?}, got {:?}",
                outcome.diagnostics
            )));
        }
    }
    let test_outcome =
        go_testing::run_go_test(&fixture.managed_root, &root, &config, &cancellation)
            .await
            .map_err(|error| fail(format!("real go test failed: {error:?}")))?;
    if !test_outcome.passing || test_outcome.passed == 0 {
        return Err(fail(format!(
            "the fixture's Go test must pass, got {test_outcome:?}"
        )));
    }

    // P15_GO_MANAGED_CACHE_ENTRY_COUNT_BEFORE_UNINSTALL: real bytes, from a
    // real toolchain, in Corulix-owned scratch -- not an empty shell.
    let scratch = fixture.managed_root.join(provisioning::MANAGED_SCRATCH_DIR);
    let before = entry_count(&scratch);
    if before == 0 {
        return Err(fail(format!(
            "P15_REAL_GO_MANAGED_CACHE_CREATION failed: no cache entries under {}",
            scratch.display()
        )));
    }
    eprintln!("P15_GO_MANAGED_CACHE_ENTRY_COUNT_BEFORE_UNINSTALL={before}");

    // And nothing leaked into the governed workspace itself.
    let mut workspace_entries = top_level_names(&fixture.module);
    workspace_entries.sort();
    if workspace_entries
        != vec![
            "go.mod".to_string(),
            "main_test.go".to_string(),
            "main.go".to_string(),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    {
        return Err(fail(format!(
            "a governed Go execution mutated the workspace: {workspace_entries:?}"
        )));
    }

    let outcome = full_uninstall::full_uninstall(&fixture.managed_root).await;
    if outcome != Ok(full_uninstall::FullUninstallOutcome::NoManagedComponents) {
        return Err(fail(format!(
            "GO_COMPLETE_MANAGED_ZERO_STATE: full_uninstall must succeed, got {outcome:?}"
        )));
    }
    assert_complete_managed_zero_state(&fixture.managed_root, "go")?;

    // §14: a second call recreates nothing.
    let second = full_uninstall::full_uninstall(&fixture.managed_root).await;
    if second != Ok(full_uninstall::FullUninstallOutcome::NoManagedComponents) {
        return Err(fail(format!(
            "P15_SECOND_FULL_UNINSTALL must PASS, got {second:?}"
        )));
    }
    if fixture.managed_root.exists() {
        return Err(fail("P15_SECOND_UNINSTALL_ROOT_RECREATION_COUNT must be 0"));
    }

    let _ = fs::remove_dir_all(&fixture.base);
    Ok(())
}

/// §10/§16/§17: the same real Go cache removal inside a *shared* managed root
/// that also holds recognized, non-Corulix-managed state. The caches must go;
/// the recognized external state must survive byte-identically and keep the
/// root legitimately retained.
#[tokio::test(flavor = "multi_thread")]
async fn real_go_managed_cache_removal_preserves_recognized_shared_root_state()
-> Result<(), Box<dyn Error>> {
    if !real_go_available() {
        eprintln!("P15_MANAGED_EXECUTION_CACHE_E2E=BLOCKED_PROVIDER_UNAVAILABLE");
        return Ok(());
    }
    let fixture = GoFixture::new("go-shared-root");
    fixture.write("main.go", VALID_MAIN);
    let root = fixture.root()?;

    // Recognized, tracked, permanently-preserved external state.
    let host_root = fixture.managed_root.join("p15-host-go");
    fs::create_dir_all(&host_root)?;
    let host_file = host_root.join("host-tool");
    fs::write(&host_file, b"host bytes")?;
    let host_bytes_before = fs::read(&host_file)?;
    let mut record = provisioning::uninstall::build_record(
        &fixture.managed_root,
        provisioning::uninstall::NewInstallation {
            component_id: "p15-host-go",
            version: "9.9.9",
            platform: "linux",
            architecture: "x64",
            canonical_component_root: host_root.clone(),
            dependencies: Vec::new(),
            installation_sequence: 1,
            artifact_digest: "1".repeat(64),
            ownership: OwnershipClass::HostOnlyOverride,
            installed_payload_digest: String::new(),
            installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
            optional_segment_digests: std::collections::BTreeMap::new(),
        },
    );
    ownership::save(&fixture.managed_root, &mut record)
        .map_err(|error| fail(format!("fixture ownership save failed: {error:?}")))?;

    go_validation::run_go_validator(
        GoValidator::Build,
        &fixture.managed_root,
        &root,
        &go_config(),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("real go build failed: {error:?}")))?;

    let scratch = fixture.managed_root.join(provisioning::MANAGED_SCRATCH_DIR);
    if entry_count(&scratch) == 0 {
        return Err(fail("no real Go cache was created in the shared root"));
    }

    let outcome = full_uninstall::full_uninstall(&fixture.managed_root).await;
    if outcome != Ok(full_uninstall::FullUninstallOutcome::NoManagedComponents) {
        return Err(fail(format!(
            "SHARED_ROOT_ZERO_CORULIX_MANAGED_STATE: got {outcome:?}"
        )));
    }
    if scratch.exists() {
        return Err(fail(
            "SHARED_ROOT_ZERO_CORULIX_MANAGED_STATE: the real Go cache survived in a shared root",
        ));
    }
    if !fixture.managed_root.exists() {
        return Err(fail(
            "the shared root must be retained, not removed, while recognized state remains",
        ));
    }
    if fs::read(&host_file)? != host_bytes_before {
        return Err(fail(
            "SHARED_ROOT_EXTERNAL_STATE_PRESERVATION: recognized external bytes changed",
        ));
    }
    if ownership::list(&fixture.managed_root).len() != 1 {
        return Err(fail(
            "SHARED_ROOT_EXTERNAL_STATE_PRESERVATION: the HostOnlyOverride record was removed",
        ));
    }

    let _ = fs::remove_dir_all(&fixture.base);
    Ok(())
}

/// §20, against a real Go cache rather than a synthetic one: substituting a
/// symlink to an external directory for the managed scratch root must fail
/// closed after a genuine governed execution has populated it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_symlink_substituted_for_a_real_go_cache_root_is_never_followed()
-> Result<(), Box<dyn Error>> {
    if !real_go_available() {
        eprintln!("P15_MANAGED_EXECUTION_CACHE_E2E=BLOCKED_PROVIDER_UNAVAILABLE");
        return Ok(());
    }
    let fixture = GoFixture::new("go-symlink");
    fixture.write("main.go", VALID_MAIN);
    let root = fixture.root()?;

    go_validation::run_go_validator(
        GoValidator::Build,
        &fixture.managed_root,
        &root,
        &go_config(),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("real go build failed: {error:?}")))?;

    let scratch = fixture.managed_root.join(provisioning::MANAGED_SCRATCH_DIR);
    if entry_count(&scratch) == 0 {
        return Err(fail("no real Go cache was created"));
    }

    // Adversarial substitution of the whole, genuinely-populated cache root.
    let external = fixture.base.join("external-precious");
    fs::create_dir_all(&external)?;
    let external_file = external.join("precious.bin");
    fs::write(&external_file, b"external bytes that must survive")?;
    let external_bytes_before = fs::read(&external_file)?;
    fs::remove_dir_all(&scratch)?;
    std::os::unix::fs::symlink(&external, &scratch)?;

    let outcome = full_uninstall::full_uninstall(&fixture.managed_root).await;
    match &outcome {
        Err(full_uninstall::FullUninstallError::CleanupRequired(paths)) => {
            if !paths
                .iter()
                .any(|path| path == provisioning::MANAGED_SCRATCH_DIR)
            {
                return Err(fail(format!(
                    "the substituted cache root must be reported as residual, got {paths:?}"
                )));
            }
        }
        other => {
            return Err(fail(format!(
                "P15_CACHE_SYMLINK_ESCAPE_DELETE_COUNT: a substituted cache root must fail \
                 closed, got {other:?}"
            )));
        }
    }
    if !external.exists() || fs::read(&external_file)? != external_bytes_before {
        return Err(fail(
            "P15_OUTSIDE_ROOT_DELETE_COUNT must be 0: the external target was deleted or mutated",
        ));
    }

    let _ = fs::remove_dir_all(&fixture.base);
    Ok(())
}

// ---------------------------------------------------------------------
// Rust vertical (§15 -- the cross-cutting P12 regression)
// ---------------------------------------------------------------------

fn trusted_rust_config() -> EffectiveConfig {
    let host = HostConfig {
        workspace_trust: WorkspaceTrust::Trusted,
        allow_trusted_workspace_execution: true,
        ..HostConfig::default()
    };
    EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

fn write_rust_fixture(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p15_cache_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        dir.join("src/lib.rs"),
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn t_ok() { assert_eq!(add(2, 2), 4); }\n}\n",
    )?;
    Ok(())
}

/// `P15_REAL_RUST_MANAGED_CACHE_CREATION` +
/// `P15_RUST_CACHE_ZERO_RESIDUAL_REGRESSION`: the audit confirmed the P12
/// `CARGO_TARGET_DIR` scratch location (`scratch/p12-cargo-test-target/...`)
/// has the identical untracked shape the Go caches had, so it gets the
/// identical real proof -- a genuinely provisioned managed Rust runtime, a
/// real governed `cargo test` that fills the managed target directory, then
/// one `full_uninstall` that removes the component *and* its cache to
/// complete zero state.
///
/// This is deliberately provisioned into its own isolated root rather than
/// reusing the shared `corulix-p11-diagnostics-e2e` root every other Rust
/// E2E suite depends on: `full_uninstall` genuinely destroys what it is given.
#[tokio::test(flavor = "multi_thread")]
async fn real_rust_managed_cache_is_created_then_fully_removed_to_zero_state()
-> Result<(), Box<dyn Error>> {
    let base = std::env::temp_dir().join(format!("corulix-p15-cache-rust-{}", stamp()));
    let managed_root = base.join("managed");
    let workspace = base.join("fixture");
    fs::create_dir_all(&managed_root)?;
    write_rust_fixture(&workspace)?;

    // Real provisioning into this test's own isolated root.
    for manifest in [
        &RUST_SEMANTIC_RUNTIME_LINUX_X64,
        &GNU_LINK_RUNTIME_LINUX_X64,
    ] {
        let (state, _) = provisioning::resolve_managed_component(&managed_root, manifest);
        if state != ManagedComponentState::Available
            && provisioning::provision(&managed_root, manifest)
                .await
                .is_err()
        {
            eprintln!(
                "P15_MANAGED_EXECUTION_CACHE_E2E=BLOCKED_PROVISIONING_FAILED (no real network \
                 access?) -- the Rust half of the cache regression could not be proven"
            );
            let _ = fs::remove_dir_all(&base);
            return Ok(());
        }
    }

    let outcome = run_cargo_test(
        &managed_root,
        &workspace,
        &trusted_rust_config(),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("real governed cargo test failed: {error:?}")))?;
    if !outcome.passing || outcome.passed == 0 {
        return Err(fail(format!(
            "the fixture's Rust test must pass, got {outcome:?}"
        )));
    }

    let scratch = managed_root.join(provisioning::MANAGED_SCRATCH_DIR);
    let before = entry_count(&scratch);
    if before == 0 {
        return Err(fail(format!(
            "P15_REAL_RUST_MANAGED_CACHE_CREATION failed: no cache entries under {}",
            scratch.display()
        )));
    }
    eprintln!("P15_RUST_MANAGED_CACHE_ENTRY_COUNT_BEFORE_UNINSTALL={before}");

    let managed_before = ownership::list(&managed_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|record| record.ownership == OwnershipClass::CorulixManaged)
        .count();
    if managed_before < 2 {
        return Err(fail(format!(
            "expected both managed Rust components installed, got {managed_before}"
        )));
    }

    let removal = full_uninstall::full_uninstall(&managed_root).await;
    match &removal {
        Ok(full_uninstall::FullUninstallOutcome::Removed(ids)) if ids.len() == managed_before => {}
        other => {
            return Err(fail(format!(
                "P15_RUST_CACHE_ZERO_RESIDUAL_REGRESSION: full_uninstall must remove every \
                 managed component, got {other:?}"
            )));
        }
    }
    assert_complete_managed_zero_state(&managed_root, "rust")?;

    let _ = fs::remove_dir_all(&base);
    Ok(())
}
