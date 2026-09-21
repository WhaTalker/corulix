// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15 §17-§23 and §30-§32: real, end-to-end proof of the Go
//! build/vet/test vertical against the real `go1.26.6` toolchain on this
//! host, plus the provider-security negative matrix.
//!
//! Every test here drives the real production entry points
//! (`wht_corulix_engine::go_validation::run_go_validator`,
//! `wht_corulix_engine::go_testing::run_go_test`) against real, disposable,
//! stdlib-only Go module fixtures. No mocks, no seams, no fabricated
//! outcomes.
//!
//! # Trust is proven with a side-effect marker, not asserted
//!
//! §20 requires proof that the workspace trust gate is genuinely
//! load-bearing rather than incidentally satisfied. The fixtures below use a
//! Go test that writes a marker file when it runs; an untrusted run must
//! leave that marker absent (the repository-authored code never executed)
//! and a trusted run must create it (it really did). Asserting only the
//! returned error would prove nothing about whether the process ran.
//!
//! # Network honesty (§23)
//!
//! `P15_GO_E2E_EXTERNAL_NETWORK_REQUIRED=NO`: every fixture is a
//! self-contained module with stdlib-only imports and no `go.sum`, so no
//! module download is required in the first place. `GOPROXY=off` and
//! `GOTOOLCHAIN=local` (set by `go_providers::go_environment`) are the Go
//! command's own offline switches. `OS_LEVEL_NETWORK_ISOLATION=NOT_CLAIMED`
//! -- nothing here claims a kernel-enforced network boundary.
//!
//! If no real `go` toolchain is present at this host's location, every test
//! reports and exits early with
//! `P15_GO_BUILD_VET_TEST_E2E=BLOCKED_PROVIDER_UNAVAILABLE` rather than
//! substituting a mock.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, ProviderCategory, WorkspaceTrust};
use wht_corulix_engine::go_providers::{self, GoProviderError};
use wht_corulix_engine::go_testing::{self, GoTestError, GoTestExecutionLimits};
use wht_corulix_engine::go_validation::{self, GoValidator, GoValidatorError};
use wht_corulix_workspace::WorkspaceRoot;

/// This host's real Go toolchain directory, confirmed by P15's discovery
/// pass. A `HOST_ONLY`-style approved directory for test purposes only --
/// production callers supply this through real host configuration.
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

fn real_go_available() -> bool {
    Path::new(REAL_GO_DIRECTORY).join("go").is_file()
}

macro_rules! require_go {
    () => {
        if !real_go_available() {
            eprintln!(
                "P15_GO_BUILD_VET_TEST_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real go at {REAL_GO_DIRECTORY}"
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

/// A disposable Go module fixture plus its own isolated, disposable
/// Corulix-managed root (so the Go build/module caches this run creates
/// never touch the shared, host-wide `managed_toolchain_root()` other real
/// E2E suites in this workspace provision into).
struct Fixture {
    module: PathBuf,
    managed_root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir().join(format!("corulix-p15-go-{label}-{}", stamp()));
        let module = base.join("module");
        let managed_root = base.join("managed");
        let _ = fs::create_dir_all(&module);
        let _ = fs::create_dir_all(&managed_root);
        let _ = fs::write(
            module.join("go.mod"),
            "module corulix_p15_fixture\n\ngo 1.24\n",
        );
        Self {
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

    fn cleanup(&self) {
        if let Some(base) = self.module.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }
}

/// A `HOST_ONLY` configuration granting Go provider authority for the real
/// toolchain directory, with workspace trust set as the caller asks.
///
/// `TrustedWorkspaceExecution` requires **both** `workspace_trust ==
/// Trusted` and `allow_trusted_workspace_execution` (see
/// `wht_corulix_config::EffectiveConfig::is_execution_class_allowed`), so an
/// untrusted configuration here is genuinely untrusted -- not merely missing
/// one of the two flags.
fn go_config(trusted: bool) -> EffectiveConfig {
    let host = HostConfig {
        workspace_trust: if trusted {
            WorkspaceTrust::Trusted
        } else {
            WorkspaceTrust::Untrusted
        },
        allow_trusted_workspace_execution: trusted,
        approved_system_directories: vec![PathBuf::from(REAL_GO_DIRECTORY)],
        ..HostConfig::default()
    };
    EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

/// A valid, stdlib-only Go program. `go build` and `go vet` both clean.
const VALID_MAIN: &str =
    "package main\n\nfunc target() int {\n\treturn 41\n}\n\nfunc main() {\n\t_ = target()\n}\n";

/// A Go program with a real *type* error -- `go build` must fail.
const BUILD_BROKEN_MAIN: &str =
    "package main\n\nfunc main() {\n\tvar x int = \"not an int\"\n\t_ = x\n}\n";

/// A Go program that **builds cleanly** but fails `go vet`: a `Printf`
/// format/argument mismatch. This exact pairing is what proves `go vet` has
/// genuinely distinct authority from `go build` rather than being a weaker
/// restatement of it (empirically confirmed against the real `go1.26.6`).
const VET_BROKEN_MAIN: &str =
    "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Printf(\"%d\\n\", \"a string\")\n}\n";

// ---------------------------------------------------------------------
// §17 -- go build authority
// ---------------------------------------------------------------------

/// `P15_REAL_GO_BUILD_PASS_E2E`: a valid fixture builds clean through the
/// real, trust-gated production path, and the Evidence carries the exact
/// provider identity (§29) rather than an ambiguous "system go".
#[tokio::test]
async fn real_go_build_pass_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("build-pass");
    fixture.write("main.go", VALID_MAIN);
    let root = fixture.root()?;

    let outcome = go_validation::run_go_validator(
        GoValidator::Build,
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("go build failed unexpectedly: {error:?}")))?;

    if !outcome.is_clean() {
        return Err(fail(format!(
            "expected a clean build, got {:?}",
            outcome.diagnostics
        )));
    }
    if !outcome.diagnostics.is_empty() {
        return Err(fail("a clean build must report zero diagnostics"));
    }
    // §29: the exact, probed provider identity.
    if !outcome.provider_version.starts_with("go version go") {
        return Err(fail(format!(
            "provider identity must be a real `go version` string, got {:?}",
            outcome.provider_version
        )));
    }
    if outcome.provider_path != Path::new(REAL_GO_DIRECTORY).join("go") {
        return Err(fail(format!(
            "expected the approved toolchain path, got {:?}",
            outcome.provider_path
        )));
    }

    // `P15_GO_BUILD_WORKSPACE_ARTIFACT_WRITE_COUNT=0`: bare `go build` writes
    // the compiled binary into the module directory; the production path
    // redirects it, so the governed workspace must hold exactly the two
    // files this fixture created.
    let mut entries: Vec<String> = fs::read_dir(&fixture.module)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    if entries != vec!["go.mod".to_string(), "main.go".to_string()] {
        return Err(fail(format!(
            "go build left artifacts in the governed workspace: {entries:?}"
        )));
    }

    fixture.cleanup();
    Ok(())
}

/// `P15_REAL_GO_BUILD_FAILURE_E2E`: a real compile error produces an
/// authoritative failure with a real parsed diagnostic -- never a clean
/// PASS, and never a non-zero exit silently swallowed.
#[tokio::test]
async fn real_go_build_failure_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("build-fail");
    fixture.write("main.go", BUILD_BROKEN_MAIN);
    let root = fixture.root()?;

    let outcome = go_validation::run_go_validator(
        GoValidator::Build,
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| {
        fail(format!(
            "a build failure must be a typed Ok(not-clean) outcome with parsed diagnostics, got {error:?}"
        ))
    })?;

    if outcome.is_clean() {
        return Err(fail(
            "a fixture that does not compile must never report a clean build",
        ));
    }
    if outcome.diagnostics.is_empty() {
        return Err(fail(
            "an authoritative build failure must carry at least one parsed diagnostic",
        ));
    }
    let diagnostic = &outcome.diagnostics[0];
    if diagnostic.relative_path != "main.go" {
        return Err(fail(format!(
            "expected the diagnostic against main.go, got {diagnostic:?}"
        )));
    }
    if diagnostic.line != 4 {
        return Err(fail(format!(
            "expected the diagnostic on line 4, got {diagnostic:?}"
        )));
    }

    fixture.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------
// §18 -- go vet authority, genuinely distinct from go build
// ---------------------------------------------------------------------

/// `P15_REAL_GO_VET_CLEAN_E2E`.
#[tokio::test]
async fn real_go_vet_clean_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("vet-clean");
    fixture.write("main.go", VALID_MAIN);
    let root = fixture.root()?;

    let outcome = go_validation::run_go_validator(
        GoValidator::Vet,
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("go vet failed unexpectedly: {error:?}")))?;

    if !outcome.is_clean() || !outcome.diagnostics.is_empty() {
        return Err(fail(format!(
            "expected a clean vet, got {:?}",
            outcome.diagnostics
        )));
    }
    fixture.cleanup();
    Ok(())
}

/// `P15_REAL_GO_VET_FAILURE_E2E`, and the proof that `go vet` carries
/// authority `go build` does not: the *same* fixture builds clean and fails
/// vet. This is why `go vet` maps to `ProviderCategory::Linter` and
/// `go build` to `ProviderCategory::TypecheckBuild` rather than one
/// standing in for the other.
#[tokio::test]
async fn real_go_vet_failure_e2e_on_a_fixture_that_builds_clean() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("vet-fail");
    fixture.write("main.go", VET_BROKEN_MAIN);
    let root = fixture.root()?;
    let config = go_config(true);

    // First: go build is genuinely clean on this fixture.
    let build = go_validation::run_go_validator(
        GoValidator::Build,
        &fixture.managed_root,
        &root,
        &config,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("go build failed unexpectedly: {error:?}")))?;
    if !build.is_clean() {
        return Err(fail(format!(
            "the vet fixture must build clean, otherwise it proves nothing about vet's distinct authority: {:?}",
            build.diagnostics
        )));
    }

    // Then: go vet finds a real defect the build could not.
    let vet = go_validation::run_go_validator(
        GoValidator::Vet,
        &fixture.managed_root,
        &root,
        &config,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| {
        fail(format!(
            "a vet failure must be a typed Ok(not-clean) outcome, got {error:?}"
        ))
    })?;
    if vet.is_clean() {
        return Err(fail("go vet must not report clean on a Printf mismatch"));
    }
    if !vet
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("Printf"))
    {
        return Err(fail(format!(
            "expected a real Printf format diagnostic, got {:?}",
            vet.diagnostics
        )));
    }

    // The two validators are mapped to genuinely different categories.
    if GoValidator::Build.category() == GoValidator::Vet.category() {
        return Err(fail(
            "go build and go vet must not share a provider category",
        ));
    }
    if GoValidator::Vet.category() != ProviderCategory::Linter {
        return Err(fail(
            "go vet must map to Linter, which the policy table forbids from ever being Authoritative",
        ));
    }

    fixture.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------
// §19-§21 -- go test behavioural authority and the trust gate
// ---------------------------------------------------------------------

/// A Go test that writes a marker file when it executes. The marker is how
/// §20's trust proof distinguishes "denied before execution" from "ran and
/// then reported".
fn side_effect_test(marker: &Path) -> String {
    format!(
        "package main\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestSideEffect(t *testing.T) {{\n\tif err := os.WriteFile({:?}, []byte(\"ran\"), 0o644); err != nil {{\n\t\tt.Fatalf(\"marker write failed: %v\", err)\n\t}}\n}}\n",
        marker.to_string_lossy()
    )
}

/// `P15_GO_TEST_UNTRUSTED_DENIED`: an untrusted workspace must be denied
/// **before execution**. Proven by the marker's absence -- the
/// repository-authored test code genuinely never ran.
#[tokio::test]
async fn go_test_untrusted_workspace_is_denied_before_any_execution() -> Result<(), Box<dyn Error>>
{
    require_go!();
    let fixture = Fixture::new("test-untrusted");
    let marker = fixture
        .module
        .parent()
        .unwrap_or(&fixture.module)
        .join("MARKER_UNTRUSTED");
    let _ = fs::remove_file(&marker);
    fixture.write("main.go", VALID_MAIN);
    fixture.write("main_test.go", &side_effect_test(&marker));
    let root = fixture.root()?;

    let outcome = go_testing::run_go_test(
        &fixture.managed_root,
        &root,
        &go_config(false),
        &CancellationToken::new(),
    )
    .await;

    match outcome {
        Err(GoTestError::WorkspaceExecutionNotAuthorized) => {}
        other => {
            return Err(fail(format!(
                "an untrusted workspace must be denied with WorkspaceExecutionNotAuthorized, got {other:?}"
            )));
        }
    }
    if marker.exists() {
        return Err(fail(
            "the Go test code EXECUTED under an untrusted workspace -- P15_UNTRUSTED_GO_TEST_PROCESS_SPAWN_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_file(&marker);
    Ok(())
}

/// `P15_GO_TEST_TRUSTED_EXECUTION` and `P15_REAL_GO_TEST_PASS_E2E`: a
/// trusted workspace really executes the repository-authored test code
/// (marker present), the run passes, and a real test actually ran
/// (`executed_count() > 0` -- never merely `passing`, since zero tests
/// trivially "pass").
#[tokio::test]
async fn go_test_trusted_workspace_really_executes_and_passes() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("test-trusted");
    let marker = fixture
        .module
        .parent()
        .unwrap_or(&fixture.module)
        .join("MARKER_TRUSTED");
    let _ = fs::remove_file(&marker);
    fixture.write("main.go", VALID_MAIN);
    fixture.write("main_test.go", &side_effect_test(&marker));
    let root = fixture.root()?;

    let outcome = go_testing::run_go_test(
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("go test failed unexpectedly: {error:?}")))?;

    if !marker.exists() {
        return Err(fail(
            "the Go test code did NOT execute under a trusted workspace -- the trust gate is not load-bearing, it is simply blocking",
        ));
    }
    if !outcome.passing {
        return Err(fail(format!("expected a passing run, got {outcome:?}")));
    }
    if outcome.executed_count() == 0 {
        return Err(fail("zero executed tests must never be reported as a pass"));
    }
    if outcome.failed != 0 {
        return Err(fail("a passing run must report zero failures"));
    }
    if !outcome.provider_version.starts_with("go version go") {
        return Err(fail(format!(
            "Evidence must carry the exact provider identity, got {:?}",
            outcome.provider_version
        )));
    }

    fixture.cleanup();
    let _ = fs::remove_file(&marker);
    Ok(())
}

/// `P15_REAL_GO_TEST_FAILURE_E2E`: a failing Go test produces an
/// authoritative failure with the failing test's stable, qualified name --
/// never inferred from narrative stdout alone, and never a silent pass.
#[tokio::test]
async fn real_go_test_failure_e2e() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("test-fail");
    fixture.write("main.go", VALID_MAIN);
    fixture.write(
        "main_test.go",
        "package main\n\nimport \"testing\"\n\nfunc TestPasses(t *testing.T) {}\n\nfunc TestFails(t *testing.T) {\n\tt.Fatal(\"deliberate P15 failure\")\n}\n",
    );
    let root = fixture.root()?;

    let outcome = go_testing::run_go_test(
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| {
        fail(format!(
            "a test failure must be a typed Ok(not-passing) outcome, got {error:?}"
        ))
    })?;

    if outcome.passing {
        return Err(fail("a failing Go test must never report passing"));
    }
    if outcome.failed != 1 || outcome.passed != 1 {
        return Err(fail(format!(
            "expected exactly 1 passed and 1 failed, got {outcome:?}"
        )));
    }
    if !outcome
        .failed_tests
        .iter()
        .any(|name| name.ends_with("::TestFails"))
    {
        return Err(fail(format!(
            "expected the failing test's qualified name, got {:?}",
            outcome.failed_tests
        )));
    }

    fixture.cleanup();
    Ok(())
}

/// A module with no test files exits **zero** (empirically confirmed), so it
/// must be reported as `NoTestsExecuted`, never as a pass. This is the
/// defect class §21 warns about: "nothing ran" is not "everything passed".
#[tokio::test]
async fn a_module_with_no_tests_is_never_reported_as_a_pass() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("test-none");
    fixture.write("main.go", VALID_MAIN);
    let root = fixture.root()?;

    let outcome = go_testing::run_go_test(
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await;

    match outcome {
        Err(GoTestError::NoTestsExecuted) => {}
        other => {
            return Err(fail(format!(
                "a module with no tests must be NoTestsExecuted, never a pass: {other:?}"
            )));
        }
    }
    fixture.cleanup();
    Ok(())
}

/// A module that does not compile must report `BuildFailed`, never a
/// fabricated "zero tests" outcome -- no test could have run.
#[tokio::test]
async fn a_module_that_does_not_compile_reports_build_failed() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("test-build-fail");
    fixture.write("main.go", BUILD_BROKEN_MAIN);
    fixture.write(
        "main_test.go",
        "package main\n\nimport \"testing\"\n\nfunc TestAnything(t *testing.T) {}\n",
    );
    let root = fixture.root()?;

    let outcome = go_testing::run_go_test(
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await;

    match outcome {
        Err(GoTestError::BuildFailed { .. }) => {}
        other => {
            return Err(fail(format!(
                "a non-compiling module must be BuildFailed, got {other:?}"
            )));
        }
    }
    fixture.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------
// §22 -- process security integration at the Go boundary
// ---------------------------------------------------------------------

/// `P15_GO_TEST_TIMEOUT_INTEGRATION`: a Go test that sleeps well past the
/// configured ceiling is terminated and reported as `TimedOut` -- never as a
/// pass, and never left running.
#[tokio::test]
async fn go_test_timeout_integration() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("test-timeout");
    fixture.write("main.go", VALID_MAIN);
    fixture.write(
        "main_test.go",
        "package main\n\nimport (\n\t\"testing\"\n\t\"time\"\n)\n\nfunc TestSleeps(t *testing.T) {\n\ttime.Sleep(120 * time.Second)\n}\n",
    );
    let root = fixture.root()?;

    let limits = GoTestExecutionLimits {
        timeout: std::time::Duration::from_secs(20),
        ..GoTestExecutionLimits::default()
    };
    let outcome = go_testing::run_go_test_with_limits(
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
        &limits,
    )
    .await;

    match outcome {
        Err(GoTestError::TimedOut) => {}
        other => {
            return Err(fail(format!(
                "a test sleeping past the ceiling must be TimedOut, got {other:?}"
            )));
        }
    }
    fixture.cleanup();
    Ok(())
}

/// `P15_GO_TEST_CANCELLATION_INTEGRATION`: a cancellation observed while the
/// Go test process is genuinely running terminates it and reports
/// `Cancelled`.
#[tokio::test]
async fn go_test_cancellation_integration() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("test-cancel");
    fixture.write("main.go", VALID_MAIN);
    fixture.write(
        "main_test.go",
        "package main\n\nimport (\n\t\"testing\"\n\t\"time\"\n)\n\nfunc TestSleeps(t *testing.T) {\n\ttime.Sleep(120 * time.Second)\n}\n",
    );
    let root = fixture.root()?;

    let cancellation = CancellationToken::new();
    let cancel_handle = cancellation.clone();
    tokio::spawn(async move {
        // Long enough that the Go toolchain has really started compiling and
        // running, short enough to keep the test fast.
        tokio::time::sleep(std::time::Duration::from_secs(12)).await;
        cancel_handle.cancel();
    });

    let outcome = go_testing::run_go_test(
        &fixture.managed_root,
        &root,
        &go_config(true),
        &cancellation,
    )
    .await;

    match outcome {
        Err(GoTestError::Cancelled) => {}
        other => {
            return Err(fail(format!(
                "a cancelled Go test run must report Cancelled, got {other:?}"
            )));
        }
    }
    fixture.cleanup();
    Ok(())
}

/// `P15_GO_TEST_SECRET_ENV_FORWARD_COUNT=0`: the parent process's
/// environment does not reach the Go child.
///
/// Proven without ever mutating this process's own environment (this
/// workspace forbids `unsafe`, and `std::env::set_var` is `unsafe` in
/// edition 2024): `cargo test` already populates this process with a large,
/// known set of variables (`CARGO_PKG_NAME`, `CARGO_MANIFEST_DIR`, ...). A
/// Go test writes everything it can see to a file; the assertion is that
/// none of those parent-only variables appear, and that the variables that
/// *do* appear are exactly the allowlist
/// `go_providers::go_environment` sets.
#[tokio::test]
async fn go_test_never_receives_the_parent_environment() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("test-env");
    let dump = fixture
        .module
        .parent()
        .unwrap_or(&fixture.module)
        .join("ENVIRONMENT_DUMP");
    let _ = fs::remove_file(&dump);
    fixture.write("main.go", VALID_MAIN);
    fixture.write(
        "main_test.go",
        &format!(
            "package main\n\nimport (\n\t\"os\"\n\t\"strings\"\n\t\"testing\"\n)\n\nfunc TestDumpEnvironment(t *testing.T) {{\n\tif err := os.WriteFile({:?}, []byte(strings.Join(os.Environ(), \"\\n\")), 0o644); err != nil {{\n\t\tt.Fatalf(\"dump failed: %v\", err)\n\t}}\n}}\n",
            dump.to_string_lossy()
        ),
    );
    let root = fixture.root()?;

    go_testing::run_go_test(
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("go test failed unexpectedly: {error:?}")))?;

    let dumped = fs::read_to_string(&dump)
        .map_err(|_| fail("the Go test did not write its environment dump"))?;

    // Variables this process genuinely has (cargo sets them) that must not
    // have crossed the boundary. Confirmed present in the parent below, so
    // this is a real negative, not a vacuous one.
    for leaked in ["CARGO_PKG_NAME", "CARGO_MANIFEST_DIR"] {
        if std::env::var(leaked).is_err() {
            return Err(fail(format!(
                "test precondition: expected {leaked} in the parent environment, so its absence in the child is meaningful"
            )));
        }
        if dumped
            .lines()
            .any(|line| line.starts_with(&format!("{leaked}=")))
        {
            return Err(fail(format!(
                "parent variable {leaked} reached the Go child -- P15_GO_TEST_SECRET_ENV_FORWARD_COUNT must be 0"
            )));
        }
    }

    // Everything the child *does* see must be an allowlisted variable this
    // workspace deliberately set (plus variables the Go toolchain itself
    // injects into its own test child, which are Go's own, not the parent's).
    const ALLOWED_PREFIXES: &[&str] = &[
        "GOROOT",
        "PATH",
        "GOCACHE",
        "GOMODCACHE",
        "GOPATH",
        "GOPROXY",
        "GOFLAGS",
        "GOTOOLCHAIN",
        "GOWORK",
        "CGO_ENABLED",
        "GODEBUG",
        "GOVERSION",
        "GOTRACEBACK",
        // `PWD` is allowed deliberately: it is **not** inherited. The
        // parent's `PWD` is this cargo test's working directory (the
        // repository root); the child's is the fixture's module directory --
        // i.e. the Go toolchain set it freshly from the `ProcessSpec`'s
        // controlled `working_directory`. The check below re-verifies exactly
        // that, so allowing the name does not weaken the claim.
        "PWD",
    ];
    if let Some(child_pwd) = dumped.lines().find_map(|line| line.strip_prefix("PWD=")) {
        let parent_pwd = std::env::var("PWD").unwrap_or_default();
        if child_pwd == parent_pwd {
            return Err(fail(format!(
                "the child's PWD equals the parent's ({parent_pwd}) -- it may have been inherited rather than set from the controlled working_directory"
            )));
        }
        if !Path::new(child_pwd).ends_with("module") {
            return Err(fail(format!(
                "expected the child's PWD to be the controlled fixture module directory, got {child_pwd}"
            )));
        }
    }
    for line in dumped.lines() {
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        if !ALLOWED_PREFIXES
            .iter()
            .any(|prefix| key == *prefix || key.starts_with(prefix))
        {
            return Err(fail(format!(
                "unexpected variable {key} in the Go child environment; full dump:\n{dumped}"
            )));
        }
    }

    fixture.cleanup();
    let _ = fs::remove_file(&dump);
    Ok(())
}

// ---------------------------------------------------------------------
// §30-§32 -- provider security negative matrix
// ---------------------------------------------------------------------

/// `P15_AMBIENT_PATH_AUTHORITY=NO`, proven directly rather than asserted:
/// `go` is unquestionably reachable on this process's own ambient `PATH`
/// (this suite's other tests execute it), yet resolution against an
/// **empty** authority envelope must fail closed. Ambient `PATH` therefore
/// carries exactly zero authority.
#[tokio::test]
async fn ambient_path_grants_no_provider_authority() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("ambient-path");
    fixture.write("main.go", VALID_MAIN);
    let root = fixture.root()?;

    // Precondition: `go` really is on the ambient PATH, so this negative is
    // meaningful rather than vacuous.
    let ambient_path = std::env::var("PATH").unwrap_or_default();
    if !ambient_path
        .split(':')
        .any(|dir| Path::new(dir).join("go").is_file())
    {
        eprintln!(
            "P15_AMBIENT_PATH_AUTHORITY: skipped -- `go` is not on this process's ambient PATH, so the negative would be vacuous"
        );
        fixture.cleanup();
        return Ok(());
    }

    let empty_authority = EffectiveConfig::derive(
        &HostConfig {
            workspace_trust: WorkspaceTrust::Trusted,
            allow_trusted_workspace_execution: true,
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let outcome = go_providers::resolve_go_toolchain(
        &fixture.managed_root,
        &empty_authority,
        &root,
        ProviderCategory::TypecheckBuild,
        &CancellationToken::new(),
    )
    .await;
    match outcome {
        Err(GoProviderError::ProviderUnavailable(_)) => {}
        other => {
            return Err(fail(format!(
                "`go` resolved from ambient PATH with an empty authority envelope: {other:?}"
            )));
        }
    }
    fixture.cleanup();
    Ok(())
}

/// `P15_WORKSPACE_GO_HIJACK_COUNT=0`: a workspace-local `./go` must never
/// satisfy a controlled provider, even when the workspace directory itself
/// is offered as an approved directory. The fake writes a marker if executed.
#[tokio::test]
async fn workspace_local_fake_go_is_never_resolved_or_executed() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("go-hijack");
    fixture.write("main.go", VALID_MAIN);
    let marker = fixture
        .module
        .parent()
        .unwrap_or(&fixture.module)
        .join("GO_HIJACK_MARKER");
    let _ = fs::remove_file(&marker);
    let fake = fixture.module.join("go");
    fs::write(
        &fake,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.to_string_lossy()),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&fake)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake, permissions)?;
    }

    let root = fixture.root()?;
    let host = HostConfig {
        workspace_trust: WorkspaceTrust::Trusted,
        allow_trusted_workspace_execution: true,
        // The governed workspace itself offered as approved: even this must
        // not make a workspace-authored executable a controlled provider.
        approved_system_directories: vec![fixture.module.clone()],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );

    let outcome = go_providers::resolve_go_toolchain(
        &fixture.managed_root,
        &effective,
        &root,
        ProviderCategory::TypecheckBuild,
        &CancellationToken::new(),
    )
    .await;
    if outcome.is_ok() {
        return Err(fail(
            "a workspace-local ./go was accepted as a controlled provider -- P15_WORKSPACE_GO_HIJACK_COUNT must be 0",
        ));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake go was EXECUTED -- P15_WORKSPACE_GO_HIJACK_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_file(&marker);
    Ok(())
}

/// `P15_WORKSPACE_GOFMT_HIJACK_COUNT=0`: the same guarantee for the
/// `Formatter` category and a workspace-local `./gofmt`.
#[tokio::test]
async fn workspace_local_fake_gofmt_is_never_resolved_or_executed() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("gofmt-hijack");
    fixture.write("main.go", VALID_MAIN);
    let marker = fixture
        .module
        .parent()
        .unwrap_or(&fixture.module)
        .join("GOFMT_HIJACK_MARKER");
    let _ = fs::remove_file(&marker);
    let fake = fixture.module.join("gofmt");
    fs::write(
        &fake,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.to_string_lossy()),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&fake)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake, permissions)?;
    }

    let root = fixture.root()?;
    let effective = EffectiveConfig::derive(
        &HostConfig {
            approved_system_directories: vec![fixture.module.clone()],
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let resolution = wht_corulix_config::resolve_provider(
        &effective,
        &root,
        ProviderCategory::Formatter,
        "gofmt",
    )
    .await;
    if resolution.availability == wht_corulix_core::ProviderAvailability::Available {
        return Err(fail(
            "a workspace-local ./gofmt was accepted -- P15_WORKSPACE_GOFMT_HIJACK_COUNT must be 0",
        ));
    }
    if marker.exists() {
        return Err(fail("the workspace-local fake gofmt was EXECUTED"));
    }

    fixture.cleanup();
    let _ = fs::remove_file(&marker);
    Ok(())
}

/// `P15_PROVIDER_UNAVAILABLE_NEGATIVE_MATRIX`: with `go` genuinely absent
/// (a `HOST_ONLY` absolute path that does not exist), every Go validator and
/// the Go test runner must fail closed with a typed provider error -- no
/// silent host fallback, no partial success.
#[tokio::test]
async fn absent_go_fails_every_go_capability_closed() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("go-absent");
    fixture.write("main.go", VALID_MAIN);
    fixture.write(
        "main_test.go",
        "package main\n\nimport \"testing\"\n\nfunc TestAnything(t *testing.T) {}\n",
    );
    let root = fixture.root()?;

    let host = HostConfig {
        workspace_trust: WorkspaceTrust::Trusted,
        allow_trusted_workspace_execution: true,
        provider_absolute_paths: vec![
            (
                ProviderCategory::TypecheckBuild,
                PathBuf::from("/nonexistent/corulix-p15/go"),
            ),
            (
                ProviderCategory::Linter,
                PathBuf::from("/nonexistent/corulix-p15/go"),
            ),
            (
                ProviderCategory::TestRunner,
                PathBuf::from("/nonexistent/corulix-p15/go"),
            ),
        ],
        // A real, populated approved list, proving the absolute-path tier is
        // terminal (§6) rather than merely "nothing was configured".
        approved_system_directories: vec![PathBuf::from(REAL_GO_DIRECTORY)],
        ..HostConfig::default()
    };
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );

    for validator in [GoValidator::Build, GoValidator::Vet] {
        match go_validation::run_go_validator(
            validator,
            &fixture.managed_root,
            &root,
            &effective,
            &CancellationToken::new(),
        )
        .await
        {
            Err(GoValidatorError::Provider(GoProviderError::ProviderUnavailable(_))) => {}
            other => {
                return Err(fail(format!(
                    "{validator:?} with an absent `go` must fail closed, got {other:?}"
                )));
            }
        }
    }
    match go_testing::run_go_test(
        &fixture.managed_root,
        &root,
        &effective,
        &CancellationToken::new(),
    )
    .await
    {
        Err(GoTestError::Provider(GoProviderError::ProviderUnavailable(_))) => {}
        other => {
            return Err(fail(format!(
                "go test with an absent `go` must fail closed, got {other:?}"
            )));
        }
    }

    fixture.cleanup();
    Ok(())
}

/// An untrusted workspace denies `go build` and `go vet` too -- not only
/// `go test`. Both are `TRUSTED_WORKSPACE_EXECUTION` (§16), so both must be
/// refused before any process is constructed.
#[tokio::test]
async fn untrusted_workspace_denies_go_build_and_go_vet() -> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("validators-untrusted");
    fixture.write("main.go", VALID_MAIN);
    let root = fixture.root()?;

    for validator in [GoValidator::Build, GoValidator::Vet] {
        match go_validation::run_go_validator(
            validator,
            &fixture.managed_root,
            &root,
            &go_config(false),
            &CancellationToken::new(),
        )
        .await
        {
            Err(GoValidatorError::WorkspaceExecutionNotAuthorized) => {}
            other => {
                return Err(fail(format!(
                    "{validator:?} must be denied on an untrusted workspace, got {other:?}"
                )));
            }
        }
    }
    fixture.cleanup();
    Ok(())
}

/// §23: the fixtures require no external network. Proven by the fixture
/// having no dependency declarations at all *and* by a real build succeeding
/// with `GOPROXY=off` (which `go_providers::go_environment` always sets).
/// `OS_LEVEL_NETWORK_ISOLATION=NOT_CLAIMED` -- this asserts the Go command's
/// own offline switch was honoured, never a kernel boundary.
#[tokio::test]
async fn go_validation_succeeds_offline_with_no_external_dependencies() -> Result<(), Box<dyn Error>>
{
    require_go!();
    let fixture = Fixture::new("offline");
    fixture.write("main.go", VALID_MAIN);

    // No `go.sum`, and `go.mod` declares no `require` block at all.
    let go_mod = fs::read_to_string(fixture.module.join("go.mod"))?;
    if go_mod.contains("require") {
        return Err(fail("the offline fixture must declare no dependencies"));
    }
    if fixture.module.join("go.sum").exists() {
        return Err(fail("the offline fixture must have no go.sum"));
    }

    let root = fixture.root()?;
    let outcome = go_validation::run_go_validator(
        GoValidator::Build,
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("offline build failed: {error:?}")))?;
    if !outcome.is_clean() {
        return Err(fail("the offline fixture must build clean"));
    }

    fixture.cleanup();
    Ok(())
}

/// §5/§16: a repository-authored `go.mod` `toolchain` directive must not be
/// able to make Corulix download and execute a different Go toolchain.
/// `GOTOOLCHAIN=local` refuses it; this proves the refusal end to end
/// through the real production path.
#[tokio::test]
async fn a_repository_authored_toolchain_directive_never_downloads_a_toolchain()
-> Result<(), Box<dyn Error>> {
    require_go!();
    let fixture = Fixture::new("toolchain-directive");
    // A toolchain the host certainly does not have; without
    // `GOTOOLCHAIN=local` the Go command attempts to download it
    // (empirically confirmed: `go: downloading go1.99.0 (linux/amd64)`).
    let _ = fs::write(
        fixture.module.join("go.mod"),
        "module corulix_p15_fixture\n\ngo 1.24\n\ntoolchain go1.99.0\n",
    );
    fixture.write("main.go", VALID_MAIN);
    let root = fixture.root()?;

    let outcome = go_validation::run_go_validator(
        GoValidator::Build,
        &fixture.managed_root,
        &root,
        &go_config(true),
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| {
        fail(format!(
            "the build should proceed with the LOCAL toolchain, not fail: {error:?}"
        ))
    })?;

    if !outcome.is_clean() {
        return Err(fail(format!(
            "expected a clean build with the local toolchain, got {:?}",
            outcome.diagnostics
        )));
    }
    // The identity really is the host's own toolchain, not a downloaded one.
    if !outcome.provider_version.contains("go1.26.6") {
        return Err(fail(format!(
            "expected the host's own toolchain identity, got {:?}",
            outcome.provider_version
        )));
    }
    if outcome.summary.contains("downloading") {
        return Err(fail(format!(
            "a toolchain download was attempted -- P15_AUTO_INSTALL_EXTERNAL_TOOLING must be NO: {}",
            outcome.summary
        )));
    }

    fixture.cleanup();
    Ok(())
}
