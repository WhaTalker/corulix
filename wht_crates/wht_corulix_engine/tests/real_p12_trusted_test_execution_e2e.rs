// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P12 real end-to-end tests: trusted `cargo test` execution under real
//! `WorkspaceTrust` enforcement, real passing/failing suites, real secret-env
//! non-forwarding proof, real required-provider-unavailable fail-closed
//! behavior, a real `ChangeSession`/`GateId::Tests` integration including a
//! genuine failure -> correction -> revalidation sequence, real runaway/
//! timeout process-tree containment, real cancellation, real bounded-output
//! behavior, and a real self-mutating-test negative (governed `src/`
//! content changing during execution must never produce current-Evidence-
//! eligible Passed/Failed output). `MOCKED_ONLY_CLOSURE=NO`.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wht_corulix_core::{
    CancellationToken, ConnectionId, EvidenceProvenance, EvidenceResultSummary, EvidenceTimestamp,
    GateId, OperationIntent, ProviderAvailability, ProviderCategory, ReasonCode, WorkspaceIdentity,
};
use wht_corulix_engine::diagnostics::run_cargo_check;
use wht_corulix_engine::planning::plan_operation;
use wht_corulix_engine::policy::TargetScope;
use wht_corulix_engine::providers::ProviderSnapshot;
use wht_corulix_engine::session::{ChangeSession, SessionScope};
use wht_corulix_engine::testing::{
    RustTestError, TestExecutionLimits, run_cargo_test, run_cargo_test_with_limits,
};
use wht_corulix_mutation::MutationExecutor;
use wht_corulix_tooling::ProcessLimits;
#[cfg(not(target_os = "windows"))]
use wht_corulix_tooling::managed_runtimes::{
    GNU_LINK_RUNTIME_LINUX_X64, RUST_SEMANTIC_RUNTIME_LINUX_X64,
};
#[cfg(target_os = "windows")]
use wht_corulix_tooling::managed_runtimes::{
    RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64, RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64,
};
use wht_corulix_tooling::provisioning::ManagedComponentManifest;

/// P17-W2: this host's own real `rust-semantic-runtime` manifest -- a
/// `#[cfg]`-gated alias mirroring
/// `wht_corulix_engine::diagnostics::rust_semantic_runtime_host_native`'s own
/// precedent, so this test file provisions/resolves whichever platform's
/// certified manifest genuinely matches the host it is running on rather
/// than hardcoding `RUST_SEMANTIC_RUNTIME_LINUX_X64` regardless of host.
/// Deliberately `RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64` on Windows, *not*
/// `RUST_SEMANTIC_RUNTIME_WINDOWS_X64` (the certified MSVC-hosted
/// `MANAGED_PROVIDER_HOST_TARGET`): P12's own `run_cargo_test_with_limits`
/// never resolves the MSVC one at all on Windows (see
/// `RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`'s own doc comment for why the
/// earlier MSVC-hosted cross-compilation design was empirically rejected),
/// so this test file's provisioning must match the real product path, not
/// provision a component the code under test never touches.
fn rust_semantic_runtime_host_native() -> ManagedComponentManifest {
    #[cfg(target_os = "windows")]
    {
        RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64
    }
    #[cfg(not(target_os = "windows"))]
    {
        RUST_SEMANTIC_RUNTIME_LINUX_X64
    }
}

/// P17-W2: this host's own real `TRUSTED_WORKSPACE_EXECUTION_TARGET` link
/// runtime -- `GNU_LINK_RUNTIME_LINUX_X64` (the Bootlin ELF/glibc sysroot,
/// a genuinely separate component from the Rust runtime) on Unix, where
/// host and trusted-execution target are the same triple but the linker
/// sysroot is still independently provisioned; on Windows, host and
/// trusted-execution target are *also* the same triple
/// (`x86_64-pc-windows-gnu`) and the entire toolchain -- including the
/// self-contained MinGW linker -- is the *same* merged component as
/// [`rust_semantic_runtime_host_native`] resolves, so this returns the
/// identical manifest rather than a second, independent one. Provisioning
/// it twice (`ensure_provisioned`'s own two-step shape, shared with the Unix
/// branch) is a safe, idempotent no-op the second time -- never a second,
/// wasted download -- because `ensure_provisioned` checks
/// `ManagedComponentState::Available` before calling `provision` again.
fn link_runtime_host_native() -> ManagedComponentManifest {
    #[cfg(target_os = "windows")]
    {
        RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64
    }
    #[cfg(not(target_os = "windows"))]
    {
        GNU_LINK_RUNTIME_LINUX_X64
    }
}

/// This host's own real `GateId::Diagnostics` manifest -- the exact
/// component `run_cargo_check`/`run_clippy` resolves. On Unix this is the
/// *same* manifest as [`rust_semantic_runtime_host_native`] above (one
/// merged component serves both `cargo check` and `cargo test`), so
/// provisioning it is always a safe, idempotent no-op there. On Windows it
/// is a genuinely *different*, independently-provisioned component: P18's
/// own `RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64` (a self-contained,
/// GNU-*hosted* toolchain, checking the workspace against the canonical
/// `x86_64-pc-windows-msvc` target via an explicit `--target` flag -- see
/// that manifest's own doc comment). Before P18, `run_cargo_check` on
/// Windows resolved the certified MSVC-hosted `RUST_SEMANTIC_RUNTIME_WINDOWS_X64`
/// instead; P18 replaced that resolution because the MSVC-hosted runtime has
/// no managed linker for a checked crate's own `build.rs` (host-target
/// linking there requires `link.exe`/Visual Studio/the Windows SDK, an
/// undisclosed system dependency this vertical forbids) -- see
/// `wht_corulix_engine::diagnostics::resolve_diagnostics_runtime`'s own doc
/// comment for the full architecture. This test file's own
/// `real_p12_changesession_test_failure_then_correction_revalidation_e2e`
/// calls `run_cargo_check` directly to satisfy `gate.diagnostics` before
/// ever reaching `ChangeSession`, so `ensure_provisioned` must provision this
/// component too -- without it, that call resolves against a component this
/// file never provisions and fails closed with `ManagedRuntimeUnavailable`
/// before any process is spawned, regardless of the GNU test-execution
/// runtime's own state.
fn diagnostics_runtime_host_native() -> ManagedComponentManifest {
    #[cfg(target_os = "windows")]
    {
        RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64
    }
    #[cfg(not(target_os = "windows"))]
    {
        RUST_SEMANTIC_RUNTIME_LINUX_X64
    }
}
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

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

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-p12-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

static PROVISION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn provision_lock() -> tokio::sync::MutexGuard<'static, ()> {
    PROVISION_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn shared_managed_root() -> PathBuf {
    // `HOME` does not exist on Windows (`USERPROFILE` is the real
    // equivalent, including under a WMI/`Win32_Process.Create`-launched
    // process, where `HOME` is genuinely absent -- confirmed empirically on
    // the real P17-W Windows VM); falling back to a hardcoded Unix `/root`
    // there silently resolves to a nonsensical `C:\root\...` path rather
    // than the real writable home directory every other real E2E run
    // actually provisions into, orphaning a from-scratch re-download under
    // that bogus root instead of reusing the already-provisioned shared
    // cache. Mirrors `wht_corulix_formatter::tests::managed_isolated_root`'s
    // own identical, already-established precedent for this exact defect
    // class.
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/root".to_string());
    // Deliberately the *same* cache root every other P11/P11-R1 real E2E
    // file uses -- one real provisioned runtime shared across the whole
    // Rust vertical, never a second independent download for P12.
    PathBuf::from(home).join(".cache/corulix-p11-diagnostics-e2e/root")
}

async fn ensure_provisioned() -> Option<PathBuf> {
    let _guard = provision_lock().await;
    let root = shared_managed_root();
    let rust_manifest = rust_semantic_runtime_host_native();
    let (state, _) = provisioning::resolve_managed_component(&root, &rust_manifest);
    if state != ManagedComponentState::Available
        && provisioning::provision(&root, &rust_manifest)
            .await
            .is_err()
    {
        return None;
    }
    // P12-R2: the managed GNU link runtime, provisioned into the same
    // shared cache root -- every existing regression test in this file
    // that calls `run_cargo_test`/`run_cargo_test_with_limits` via
    // `ensure_provisioned()` now genuinely links and runs its test binary
    // through the fully managed linker path, not merely a fixture added
    // for this phase in isolation.
    let link_manifest = link_runtime_host_native();
    let (gnu_state, _) = provisioning::resolve_managed_component(&root, &link_manifest);
    if gnu_state != ManagedComponentState::Available
        && provisioning::provision(&root, &link_manifest)
            .await
            .is_err()
    {
        return None;
    }
    // `run_cargo_check` (this file's own `real_p12_changesession_test_failure_then_correction_revalidation_e2e`
    // calls it directly for `gate.diagnostics`) resolves the diagnostics
    // runtime, not the P12 test-execution runtime above -- see
    // `diagnostics_runtime_host_native`'s own doc comment for why these
    // diverge on Windows. A no-op on Unix (same manifest, already
    // `Available` from the first provision above).
    let diagnostics_manifest = diagnostics_runtime_host_native();
    let (diagnostics_state, _) =
        provisioning::resolve_managed_component(&root, &diagnostics_manifest);
    if diagnostics_state != ManagedComponentState::Available
        && provisioning::provision(&root, &diagnostics_manifest)
            .await
            .is_err()
    {
        return None;
    }
    Some(root)
}

fn trusted_effective_config() -> wht_corulix_config::EffectiveConfig {
    let host = wht_corulix_config::HostConfig {
        workspace_trust: wht_corulix_core::WorkspaceTrust::Trusted,
        allow_trusted_workspace_execution: true,
        ..wht_corulix_config::HostConfig::default()
    };
    wht_corulix_config::EffectiveConfig::derive(
        &host,
        &wht_corulix_config::RepositoryHints::default(),
        &wht_corulix_config::RequestOptions::default(),
    )
}

fn untrusted_effective_config() -> wht_corulix_config::EffectiveConfig {
    wht_corulix_config::EffectiveConfig::derive(
        &wht_corulix_config::HostConfig::default(),
        &wht_corulix_config::RepositoryHints::default(),
        &wht_corulix_config::RequestOptions::default(),
    )
}

/// A real crate with a `build.rs` writing `marker_path`, and one library
/// test that also writes `marker_path` again with a distinct suffix when it
/// actually executes -- so the marker's *content* proves whether the
/// compiled test binary itself ran, not merely whether the crate compiled
/// (`cargo check`'s own build.rs marker proof is insufficient here: `cargo
/// test` must additionally *run* the compiled test binary).
fn write_passing_fixture(
    dir: &std::path::Path,
    marker_path: &std::path::Path,
) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p12_passing_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
    )?;
    fs::write(
        dir.join("build.rs"),
        format!(
            "fn main() {{ std::fs::write(r#\"{}\"#, b\"build-ran\").expect(\"write marker\"); }}\n",
            marker_path.display()
        ),
    )?;
    fs::write(
        dir.join("src/lib.rs"),
        format!(
            "pub fn add(a: i32, b: i32) -> i32 {{ a + b }}\n\n#[cfg(test)]\nmod tests {{\n    use super::*;\n    #[test]\n    fn t_ok() {{\n        std::fs::write(r#\"{}\"#, b\"test-ran\").expect(\"write marker\");\n        assert_eq!(add(2, 2), 4);\n    }}\n}}\n",
            marker_path.display()
        ),
    )?;
    Ok(())
}

fn write_failing_fixture(dir: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p12_failing_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        dir.join("src/lib.rs"),
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn t_ok() { assert_eq!(add(2, 2), 4); }\n    #[test]\n    fn t_fail() { assert_eq!(add(2, 2), 5); }\n}\n",
    )?;
    Ok(())
}

/// A test whose own body reads two `CORULIX_P12_SECRET_MARKER_*` env vars
/// and fails (panics) if either is present -- the strongest available proof
/// that `wht_corulix_tooling::execute`'s `env_clear()` plus this module's
/// own explicit allowlist genuinely prevent secret forwarding all the way
/// down to the compiled test binary, not merely to the immediate `cargo`
/// child (cargo itself re-exports a number of `CARGO_*`/inherited variables
/// to test binaries it spawns -- a fact `env_clear()` alone does not cover
/// unless nothing secret survives into `managed_environment`'s own explicit
/// var set, which this test proves for real).
fn write_secret_marker_fixture(dir: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p12_secret_marker_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        dir.join("src/lib.rs"),
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t_no_secret_env() {\n        assert!(std::env::var(\"CORULIX_P12_SECRET_MARKER_A\").is_err(), \"secret A leaked into test binary\");\n        assert!(std::env::var(\"CORULIX_P12_SECRET_MARKER_B\").is_err(), \"secret B leaked into test binary\");\n    }\n}\n",
    )?;
    Ok(())
}

/// A test that never returns, repeatedly overwriting `heartbeat_path`
/// (deliberately *outside* `src/` -- this fixture is not exercising
/// self-mutation detection) so a caller can observe, after the process tree
/// is terminated, whether the heartbeat's own mtime stops advancing --
/// real, non-vacuous proof the descendant actually died rather than merely
/// that `run_cargo_test`'s own future resolved.
fn write_hang_fixture(
    dir: &std::path::Path,
    heartbeat_path: &std::path::Path,
) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p12_hang_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        dir.join("src/lib.rs"),
        format!(
            "#[cfg(test)]\nmod tests {{\n    #[test]\n    fn hangs_forever() {{\n        let marker = std::path::Path::new(r#\"{}\"#);\n        loop {{\n            let _ = std::fs::write(marker, format!(\"{{:?}}\", std::time::SystemTime::now()));\n            std::thread::sleep(std::time::Duration::from_millis(30));\n        }}\n    }}\n}}\n",
            heartbeat_path.display()
        ),
    )?;
    Ok(())
}

/// A test that emits far more stdout than any reasonable `max_stdout_bytes`
/// bound, then would otherwise report a real `test result:` summary --
/// which, because the bounded reader retains only the *first* N bytes
/// (head-truncation, never buffering past the limit -- see
/// `wht_corulix_tooling`'s own `spawn_bounded_reader` doc comment), lands
/// entirely in the discarded tail whenever the bound is small enough. Used
/// to prove [`RustTestError::ResultTruncatedBeforeSummary`] is returned
/// rather than a fabricated pass or a generic zero-tests error.
///
/// The test deliberately *fails* (a trailing `assert_eq!(1, 2)`): libtest
/// captures a passing test's own stdout internally and never writes it to
/// the real process stdout at all unless the test fails (or `--nocapture`
/// is passed, which this module's `run_cargo_test` does not pass) -- a
/// passing variant of this fixture would produce almost no real stdout
/// regardless of how much it `println!`s, making the fixture vacuous.
fn write_huge_stdout_fixture(dir: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p12_huge_stdout_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        dir.join("src/lib.rs"),
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t_huge_stdout_then_fail() {\n        for _ in 0..50_000 {\n            println!(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\");\n        }\n        assert_eq!(1, 2);\n    }\n}\n",
    )?;
    Ok(())
}

/// A test that emits far more *stderr* than any reasonable bound, while its
/// real stdout (and hence libtest's own `test result:` summary line) stays
/// small -- proving stderr bounding does not deadlock the child or corrupt
/// stdout-based classification, unlike [`write_huge_stdout_fixture`] which
/// deliberately does affect the summary line.
fn write_huge_stderr_small_stdout_fixture(dir: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p12_huge_stderr_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        dir.join("src/lib.rs"),
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t_huge_stderr_then_ok() {\n        for _ in 0..50_000 {\n            eprintln!(\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\");\n        }\n        assert_eq!(1 + 1, 2);\n    }\n}\n",
    )?;
    Ok(())
}

/// A test whose own body mutates a governed `src/` file as a side effect
/// (writing new bytes to `src/lib.rs` itself) before asserting successfully
/// -- the real, non-destructive negative fixture for
/// [`RustTestError::WorkspaceSelfMutationDetected`]. Deliberately never run
/// against Corulix's own working source tree -- always a disposable temp
/// fixture (see `temp_dir`).
fn write_self_mutating_fixture(dir: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p12_self_mutating_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        dir.join("src/lib.rs"),
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t_mutates_own_source() {\n        std::fs::write(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/src/lib.rs\"), b\"// mutated by the test itself\\n\").expect(\"self-mutate src/lib.rs\");\n        assert_eq!(1 + 1, 2);\n    }\n}\n",
    )?;
    Ok(())
}

/// `P12_TRUSTED_TEST_BINARY_EXECUTION_PROVEN=PASS`: under a real `HOST_ONLY`
/// trust grant, `run_cargo_test` genuinely compiles `build.rs`, then
/// compiles and *runs* the real compiled test binary -- proven by the
/// marker file's final content (`"test-ran"`, written only by the test
/// body, overwriting `build.rs`'s own `"build-ran"` write), never merely by
/// a zero exit code.
#[cfg(unix)]
#[tokio::test]
async fn real_p12_trusted_execution_runs_real_passing_test_e2e() -> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("passing");
    let marker_path = fixture_dir.join("MARKER");
    write_passing_fixture(&fixture_dir, &marker_path)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let outcome = run_cargo_test(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("expected a real passing test run, got {error:?}")))?;

    if !outcome.passing {
        return Err(fail(format!("expected a passing outcome, got {outcome:?}")));
    }
    if outcome.executed_count() != 1 {
        return Err(fail(format!(
            "expected exactly 1 executed test (the unit test alone, not the empty \
             doc-tests block folded in), got executed_count={} outcome={outcome:?}",
            outcome.executed_count()
        )));
    }
    let marker_content = fs::read_to_string(&marker_path)?;
    if marker_content != "test-ran" {
        return Err(fail(format!(
            "expected the compiled test binary to overwrite the marker with 'test-ran', \
             got {marker_content:?} -- the test binary itself may never have executed"
        )));
    }
    eprintln!(
        "P12_TRUSTED_TEST_BINARY_EXECUTION_PROVEN=PASS P12_REAL_TEST_EXECUTED_COUNT={}",
        outcome.executed_count()
    );
    Ok(())
}

/// `P12_UNTRUSTED_TEST_PROCESS_SPAWN_COUNT=0`: the exact same fixture, under
/// a default (`Untrusted`) `EffectiveConfig`, must be denied before `cargo`
/// is ever spawned -- proven by the marker file's continued absence, not
/// merely by the typed error.
#[tokio::test]
async fn real_p12_untrusted_execution_never_runs_test_binary_e2e() -> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("untrusted");
    let marker_path = fixture_dir.join("MARKER");
    write_passing_fixture(&fixture_dir, &marker_path)?;
    let cancellation = CancellationToken::new();
    let effective = untrusted_effective_config();

    let result = run_cargo_test(&managed_root, &fixture_dir, &effective, &cancellation).await;
    if result != Err(RustTestError::WorkspaceExecutionNotAuthorized) {
        return Err(fail(format!(
            "expected WorkspaceExecutionNotAuthorized, got {result:?}"
        )));
    }
    if marker_path.exists() {
        return Err(fail(
            "MARKER exists: the untrusted workspace's build.rs/test binary executed anyway -- \
             trust enforcement is not load-bearing",
        ));
    }
    eprintln!("P12_UNTRUSTED_TEST_PROCESS_SPAWN_COUNT=0");
    Ok(())
}

/// A real, exit-code-confirmed test failure is reported honestly, with the
/// specific failing test name captured in the bounded summary -- never
/// folded into a fabricated pass.
#[cfg(unix)]
#[tokio::test]
async fn real_p12_real_failing_test_reports_failure_e2e() -> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("failing");
    write_failing_fixture(&fixture_dir)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let outcome = run_cargo_test(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("expected a real completed run, got {error:?}")))?;
    if outcome.passing {
        return Err(fail(format!(
            "expected a failing outcome (t_fail asserts 4 == 5), got {outcome:?}"
        )));
    }
    if outcome.failed != 1 || outcome.passed != 1 {
        return Err(fail(format!(
            "expected exactly 1 passed + 1 failed, got {outcome:?}"
        )));
    }
    if !outcome.summary.contains("t_fail") {
        return Err(fail(format!(
            "expected the failing test name in the bounded summary, got {:?}",
            outcome.summary
        )));
    }
    eprintln!("P12_REAL_FAILING_TEST_REPORTED=PASS");
    Ok(())
}

/// `P12_SECRET_ENV_FORWARDING_COUNT=0`: real proof, not an inference from
/// `env_clear()` alone. This workspace forbids `unsafe` (including
/// process-wide `std::env::set_var`), so this test spawns a real, separate
/// child OS process -- this very test binary, re-invoked via
/// [`std::env::current_exe`] running only
/// [`real_p12_secret_env_inner_check`] -- with the two synthetic secret
/// markers attached *only* to that child via `Command::env` (a fully safe
/// builder API; it mutates only the child's own environment table, never
/// this process's). That child then runs a real `cargo test` two further
/// process levels down (`cargo` itself, then the compiled test binary),
/// whose own test body asserts both markers are absent from *its* own
/// environment. This is real proof across three real process boundaries,
/// not an inference from `env_clear()`'s own doc comment.
#[cfg(unix)]
#[tokio::test]
async fn real_p12_secret_env_not_forwarded_to_test_binary_e2e() -> Result<(), Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    let output = std::process::Command::new(exe)
        .arg("real_p12_secret_env_inner_check")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env("CORULIX_P12_SECRET_MARKER_A", "secret-a-must-not-leak")
        .env("CORULIX_P12_SECRET_MARKER_B", "secret-b-must-not-leak")
        .output()?;
    if !output.status.success() {
        return Err(fail(format!(
            "inner secret-env check child exited non-zero: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The inner child gracefully no-ops (and prints
    // `P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED`, via its own
    // `ensure_provisioned()` guard) whenever the managed Rust semantic
    // runtime / GNU link runtime it needs cannot be provisioned on this
    // host -- exactly the same fail-open-to-skip contract every other
    // test in this file already honors, since only `_LINUX_X64` managed
    // manifests exist for these two components today (no managed
    // manifest ships yet for a non-Linux host). Before this fix, this
    // outer wrapper was the only test in the file that treated that
    // legitimate, already-tolerated skip as a hard failure, which made a
    // pre-existing missing-managed-toolchain gap masquerade as an
    // unrelated environment-forwarding regression on hosts where the
    // gap applies (see also Category C:
    // `real_rustfmt_managed_hash_mismatch_rejected_e2e`, deferred for
    // the identical reason). This only widens what counts as a
    // legitimate skip; it never accepts an inner child that actually ran
    // and failed to hide the secrets.
    if stderr.contains("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED") {
        eprintln!("P12_SECRET_ENV_FORWARDING_COUNT=SKIPPED_MANAGED_RUNTIME_UNAVAILABLE_FOR_HOST");
        return Ok(());
    }
    if !stderr.contains("P12_SECRET_ENV_INNER_CHECK=PASS") {
        return Err(fail(format!(
            "expected the inner child's PASS marker in stderr, got: {stderr}"
        )));
    }
    eprintln!("P12_SECRET_ENV_FORWARDING_COUNT=0");
    Ok(())
}

/// Not meant to be run directly/standalone -- it is the child target of
/// [`real_p12_secret_env_not_forwarded_to_test_binary_e2e`], which is the
/// only caller that sets both `CORULIX_P12_SECRET_MARKER_*` vars on this
/// process. If invoked any other way (both markers absent), it degrades to
/// a harmless no-op `PASS` rather than a false failure.
#[tokio::test]
async fn real_p12_secret_env_inner_check() -> Result<(), Box<dyn Error>> {
    if std::env::var("CORULIX_P12_SECRET_MARKER_A").is_err()
        || std::env::var("CORULIX_P12_SECRET_MARKER_B").is_err()
    {
        eprintln!("P12_SECRET_ENV_INNER_CHECK=SKIPPED_NOT_RUN_AS_CHILD");
        return Ok(());
    }
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("secret-env-inner");
    write_secret_marker_fixture(&fixture_dir)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let outcome = run_cargo_test(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("expected a real completed run, got {error:?}")))?;
    if !outcome.passing {
        return Err(fail(format!(
            "expected the secret-marker test to pass (i.e. neither secret was visible \
             to the test binary), got a failing outcome: {outcome:?}"
        )));
    }
    eprintln!("P12_SECRET_ENV_INNER_CHECK=PASS");
    Ok(())
}

/// Required-provider-unavailable fails closed: an empty, never-provisioned
/// managed root yields `ManagedRuntimeUnavailable` before any process is
/// spawned, exactly mirroring `crate::diagnostics`'s own precedent.
#[tokio::test]
async fn real_p12_required_provider_unavailable_fails_closed_e2e() -> Result<(), Box<dyn Error>> {
    let empty_root = temp_dir("empty-managed-root");
    let fixture_dir = temp_dir("unavailable-fixture");
    write_failing_fixture(&fixture_dir)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let result = run_cargo_test(&empty_root, &fixture_dir, &effective, &cancellation).await;
    // P17-W2: on Unix, `run_cargo_test` resolves two genuinely independent
    // managed components in sequence (the Rust runtime, then the separate
    // GNU link runtime), so a fully-empty root fails on the *first*
    // resolution with `ManagedRuntimeUnavailable`. On Windows, the entire
    // GNU-hosted toolchain -- including the self-contained MinGW linker -- is
    // *one* merged component (see
    // `RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`'s own doc comment), resolved by
    // the single `resolve_link_runtime` call, so the identical fully-empty
    // root fails closed with `ManagedLinkerRuntimeUnavailable` instead --
    // still fails closed, still before any process is spawned, just a
    // different real error variant because the underlying component
    // topology genuinely differs by platform.
    #[cfg(not(target_os = "windows"))]
    let expected = RustTestError::ManagedRuntimeUnavailable;
    #[cfg(target_os = "windows")]
    let expected = RustTestError::ManagedLinkerRuntimeUnavailable;
    if result != Err(expected.clone()) {
        return Err(fail(format!("expected {expected:?}, got {result:?}")));
    }
    eprintln!("P12_REQUIRED_PROVIDER_UNAVAILABLE_FAILS_CLOSED=PASS");
    Ok(())
}

/// Full `ChangeSession`/`GateId::Tests` integration: a genuine real test
/// failure is recorded as real `Failed` Evidence (never fabricated, never
/// silently dropped) against the `Optional` `gate.tests` requirement in
/// `VALIDATE_CHANGE` -- the session still reaches `COMPLETED` because
/// `TestRunner` is `Optional`, exactly mirroring P11's own `Linter`
/// precedent. A subsequent correction (fixing the fixture) and revalidation
/// then records a real `Passed` Evidence at a higher sequence, proving the
/// failure -> correction -> revalidation sequence the mandate requires.
#[cfg(unix)]
#[tokio::test]
async fn real_p12_changesession_test_failure_then_correction_revalidation_e2e()
-> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("changesession-correction");
    write_failing_fixture(&fixture_dir)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let install_dir =
        provisioning::component_install_dir(&managed_root, &rust_semantic_runtime_host_native());

    let first_check = run_cargo_check(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| {
            fail(format!(
                "expected a real completed cargo check, got {error:?}"
            ))
        })?;
    if !first_check.is_clean() {
        return Err(fail(format!(
            "expected the fixture to build cleanly (only its test assertion should fail), \
             got {first_check:?}"
        )));
    }
    let first_outcome = run_cargo_test(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("expected a real completed run, got {error:?}")))?;
    if first_outcome.passing {
        return Err(fail("expected the initial fixture run to fail (by design)"));
    }

    let workspace_root = WorkspaceRoot::open(&fixture_dir)?;
    let snapshot = ProviderSnapshot::from_resolutions(&[
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::TypecheckBuild,
            availability: ProviderAvailability::Available,
            resolved_path: Some(install_dir.join("bin/cargo")),
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution,
            reason: None,
        },
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::TestRunner,
            availability: ProviderAvailability::Available,
            resolved_path: Some(install_dir.join("bin/cargo")),
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution,
            reason: None,
        },
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::Linter,
            availability: ProviderAvailability::ProviderUnavailable,
            resolved_path: None,
            provenance: None,
            execution_class: wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution,
            reason: None,
        },
    ]);
    let tool_plan = plan_operation(
        OperationIntent::ValidateChange,
        TargetScope::SingleRoot,
        &snapshot,
        None,
    );
    if tool_plan.executability != wht_corulix_core::PlanExecutability::Executable {
        return Err(fail(format!(
            "expected an Executable ValidateChange plan, got {:?}",
            tool_plan.executability
        )));
    }

    let workspace_identity = WorkspaceIdentity::from_opaque_token(format!(
        "wsid-p12-correction-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ))?;
    let connection = ConnectionId::from_opaque_token("conn-p12-correction".to_string())?;
    let executor = MutationExecutor::new(workspace_root);
    let mut session = ChangeSession::open(
        ChangeSession::generate_id()?,
        workspace_identity.clone(),
        connection.clone(),
        1,
        executor,
    );
    session.enter_scope(SessionScope::new(vec!["src".to_string()]))?;
    session.baseline(
        tool_plan,
        vec![
            EvidenceProvenance {
                provider_id: "cargo-check".to_string(),
                provider_version: Some(first_check.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            EvidenceProvenance {
                provider_id: "cargo-test".to_string(),
                provider_version: Some(first_outcome.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
        ],
    )?;

    // Required `gate.diagnostics` closure -- the fixture builds cleanly, so
    // this passes; without it `complete_change` denies with
    // `RequiredGateMissingEvidence` regardless of `gate.tests`.
    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::TypecheckBuild,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Diagnostics,
            sequence: 1,
            provenance: EvidenceProvenance {
                provider_id: "cargo-check".to_string(),
                provider_version: Some(first_check.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: None,
            result_summary: EvidenceResultSummary::try_from(
                "real cargo check: 0 errors".to_string(),
            )?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(1),
            snapshot_id: Some(session.content_snapshot_id()),
        },
    )?;

    // Real, honest Failed Evidence for the genuine first failure -- never
    // fabricated, never silently withheld because the gate is Optional.
    session.record_evidence(
        &workspace_identity,
        &connection,
        ProviderCategory::TestRunner,
        wht_corulix_core::Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace_identity.clone(),
            gate: GateId::Tests,
            sequence: 2,
            provenance: EvidenceProvenance {
                provider_id: "cargo-test".to_string(),
                provider_version: Some(first_outcome.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: None,
            result_summary: EvidenceResultSummary::try_from(first_outcome.summary.clone())?,
            reason: Some(ReasonCode::TestFailuresReported),
            truncated: first_outcome.truncated,
            timestamp: EvidenceTimestamp(2),
            snapshot_id: Some(session.content_snapshot_id()),
        },
    )?;

    // `gate.tests` is `Optional` in `VALIDATE_CHANGE` -- a real Failed
    // record must not block completion by itself (it is informational,
    // exactly like P11's own Optional `Linter` precedent).
    session.complete_change(&workspace_identity, &connection)?;
    if session.status() != wht_corulix_core::ChangeSessionStatus::Completed {
        return Err(fail(format!(
            "expected COMPLETED with an Optional gate.tests failure recorded, got {:?}",
            session.status()
        )));
    }
    eprintln!(
        "P12_OPTIONAL_TEST_GATE_FAILURE_DOES_NOT_BLOCK_COMPLETION=PASS \
         P12_OPTIONAL_TEST_GATE=PASS_WITH_EVIDENCE (VALIDATE_CHANGE's own real, pre-existing \
         Optional gate.tests requirement genuinely exercised end-to-end, not invented)"
    );

    // --- Correction: fix the fixture for real, rerun, record a real Passed
    // revalidation at a higher sequence against a brand-new session (the
    // prior session is already terminal/Completed) -- proving the
    // failure -> correction -> revalidation sequence with real Evidence at
    // every step, never an out-of-band narrative claim.
    write_passing_fixture(&fixture_dir, &fixture_dir.join("MARKER"))?;
    let second_check = run_cargo_check(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| {
            fail(format!(
                "expected a real completed cargo check, got {error:?}"
            ))
        })?;
    if !second_check.is_clean() {
        return Err(fail(format!(
            "expected the corrected fixture to build cleanly, got {second_check:?}"
        )));
    }
    let second_outcome = run_cargo_test(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("expected a real completed run, got {error:?}")))?;
    if !second_outcome.passing {
        return Err(fail(format!(
            "expected the corrected fixture to pass, got {second_outcome:?}"
        )));
    }

    let workspace_root_2 = WorkspaceRoot::open(&fixture_dir)?;
    let tool_plan_2 = plan_operation(
        OperationIntent::ValidateChange,
        TargetScope::SingleRoot,
        &snapshot,
        None,
    );
    let workspace_identity_2 = WorkspaceIdentity::from_opaque_token(format!(
        "wsid-p12-correction-revalidate-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ))?;
    let connection_2 =
        ConnectionId::from_opaque_token("conn-p12-correction-revalidate".to_string())?;
    let executor_2 = MutationExecutor::new(workspace_root_2);
    let mut session_2 = ChangeSession::open(
        ChangeSession::generate_id()?,
        workspace_identity_2.clone(),
        connection_2.clone(),
        1,
        executor_2,
    );
    session_2.enter_scope(SessionScope::new(vec!["src".to_string()]))?;
    session_2.baseline(
        tool_plan_2,
        vec![
            EvidenceProvenance {
                provider_id: "cargo-check".to_string(),
                provider_version: Some(second_check.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            EvidenceProvenance {
                provider_id: "cargo-test".to_string(),
                provider_version: Some(second_outcome.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
        ],
    )?;
    session_2.record_evidence(
        &workspace_identity_2,
        &connection_2,
        ProviderCategory::TypecheckBuild,
        wht_corulix_core::Evidence {
            session_id: session_2.id().clone(),
            workspace_identity: workspace_identity_2.clone(),
            gate: GateId::Diagnostics,
            sequence: 1,
            provenance: EvidenceProvenance {
                provider_id: "cargo-check".to_string(),
                provider_version: Some(second_check.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: None,
            result_summary: EvidenceResultSummary::try_from(
                "real cargo check: 0 errors".to_string(),
            )?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(1),
            snapshot_id: Some(session_2.content_snapshot_id()),
        },
    )?;
    session_2.record_evidence(
        &workspace_identity_2,
        &connection_2,
        ProviderCategory::TestRunner,
        wht_corulix_core::Evidence {
            session_id: session_2.id().clone(),
            workspace_identity: workspace_identity_2.clone(),
            gate: GateId::Tests,
            sequence: 2,
            provenance: EvidenceProvenance {
                provider_id: "cargo-test".to_string(),
                provider_version: Some(second_outcome.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: vec!["src".to_string()],
            input_fingerprint: None,
            result_summary: EvidenceResultSummary::try_from(second_outcome.summary.clone())?,
            reason: None,
            truncated: second_outcome.truncated,
            timestamp: EvidenceTimestamp(2),
            snapshot_id: Some(session_2.content_snapshot_id()),
        },
    )?;
    session_2.complete_change(&workspace_identity_2, &connection_2)?;
    if session_2.status() != wht_corulix_core::ChangeSessionStatus::Completed {
        return Err(fail(format!(
            "expected COMPLETED after the real revalidation Passed, got {:?}",
            session_2.status()
        )));
    }
    eprintln!(
        "P12_FAILURE_CORRECTION_REVALIDATION_SEQUENCE=PASS \
         P12_OUT_OF_BAND_TEST_NARRATIVE_AUTHORITY_COUNT=0"
    );
    Ok(())
}

/// P12-R1 audit item A (runaway/timeout): a real hanging test, run through
/// the actual product boundary (`run_cargo_test_with_limits` -> Tooling's
/// `execute` -> managed `cargo` -> the compiled test binary -- never a
/// manually-spawned `cargo` inside the test harness), is terminated when
/// its configured timeout elapses. Real containment proof: the heartbeat
/// marker's own mtime must stop advancing after `TimedOut` is observed --
/// not merely that the awaited future resolved.
///
/// M09-P8RT test-design fix (owner-adjudicated, `M09_P8RT_TEST_DESIGN_
/// DEFECT=PROVEN`): the property this test claims to prove is that a
/// configured process-EXECUTION timeout is recognized promptly and the
/// whole process tree is torn down -- never a bound on how long
/// provisioning/integrity work takes before that process ever starts.
/// The prior version measured wall time from before `run_cargo_test_
/// with_limits` was even called, which unavoidably also measures that
/// call's own mandatory, by-design managed-toolchain installed-payload
/// integrity re-verification (`wht_corulix_tooling::provisioning`'s P11-R1
/// contract: a full read+hash of the managed Rust runtime and GNU link
/// runtime, unconditionally recomputed on every governed execution, never
/// cached across calls). Direct `strace -f -tt` against the real test
/// binary (M09-P8R's own investigation) isolated that cost to ~21-69s on
/// this real host, entirely BEFORE `cargo` is ever `execve`d, while the
/// actual timeout-then-kill-then-reap sequence this test exists to prove
/// took ~3.2s. Nothing about the product changed: the exact same governed
/// call below still runs the real provisioning check, the real integrity
/// re-verification, real `cargo`, and real containment -- only the START
/// POINT this test measures FROM has moved, to a deterministic oracle
/// (the runaway fixture's own heartbeat marker first appearing on disk --
/// external, direct proof the governed child has genuinely begun
/// executing, never a `sleep`-based guess).
#[cfg(unix)]
#[tokio::test]
async fn real_p12_runaway_test_timeout_terminates_process_tree_e2e() -> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("hang-timeout");
    let heartbeat = fixture_dir.join("HEARTBEAT");
    write_hang_fixture(&fixture_dir, &heartbeat)?;

    // M09-P8RT negative control: the start oracle below is only
    // meaningful if the marker is genuinely absent until the runaway
    // fixture itself creates it -- `fixture_dir` is a freshly timestamped
    // temp directory `write_hang_fixture` just populated, so this must
    // always hold; asserted rather than assumed.
    if heartbeat.exists() {
        return Err(fail(
            "heartbeat marker already exists before the runaway fixture ever ran -- the start \
             oracle below would be meaningless (M09_P8RT_START_ORACLE_FALSE_POSITIVE_COUNT != 0)",
        ));
    }

    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();
    let limits = TestExecutionLimits {
        timeout: Duration::from_secs(3),
        ..TestExecutionLimits::default()
    };

    // Races the governed call below: polls (5ms interval, far finer than
    // the fixture's own 30ms heartbeat-write cadence) for the marker's
    // first appearance and records that instant -- the deterministic
    // "the runaway process genuinely started" oracle. The 180s outer
    // bound is only a safety net against this task spinning forever if
    // the child never starts at all (itself surfaced below as a hard
    // failure, `M09_P8RT_RUNAWAY_DESCENDANT_CONFIRMED=NO`), generous
    // enough to never fire spuriously even under this host's observed
    // ~21-69s worst-case pre-execution governance cost.
    let overall_started_at = Instant::now();
    let heartbeat_for_oracle = heartbeat.clone();
    let start_oracle = tokio::spawn(async move {
        let oracle_deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if heartbeat_for_oracle.is_file() {
                return Some(Instant::now());
            }
            if Instant::now() >= oracle_deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let result = run_cargo_test_with_limits(
        &managed_root,
        &fixture_dir,
        &effective,
        &cancellation,
        &limits,
    )
    .await;
    let overall_finished_at = Instant::now();

    let Some(execution_start) = start_oracle
        .await
        .map_err(|error| fail(format!("start-oracle task panicked: {error}")))?
    else {
        return Err(fail(
            "the runaway fixture's heartbeat marker never appeared -- \
             M09_P8RT_RUNAWAY_DESCENDANT_CONFIRMED=NO: the governed child process may never \
             have genuinely started running",
        ));
    };

    // Informational only (Section 8 of the M09-P8RT mandate): the
    // mandatory pre-execution governance cost is recorded for
    // observability, never asserted against a bound -- no existing
    // product contract defines a maximum for it, and this test's own
    // property is deliberately independent of it.
    let pre_execution_governance_duration = execution_start.duration_since(overall_started_at);
    let post_start_elapsed = overall_finished_at.duration_since(execution_start);

    if result != Err(RustTestError::TimedOut) {
        return Err(fail(format!("expected TimedOut, got {result:?}")));
    }

    // `timeout` (3s, unchanged) plus a 5s post-start overhead budget --
    // real, manually-reproduced measurements of this exact code path
    // (M09-P8R's own investigation) showed the `tokio::select!` timeout
    // branch firing within a few hundred milliseconds of the configured
    // 3s and the subsequent whole-process-tree kill+reap completing in
    // ~0.2-0.3s even under real host contention. 5 extra seconds is
    // generous headroom for real scheduling jitter on a genuinely busy
    // shared host (this bound must hold even under retained swap
    // pressure, so long as the host is not actively thrashing -- Section
    // 15), never a reintroduction of the excluded ~20s+ integrity cost.
    const POST_START_OVERHEAD_BUDGET: Duration = Duration::from_secs(5);
    if post_start_elapsed > limits.timeout + POST_START_OVERHEAD_BUDGET {
        return Err(fail(format!(
            "timeout enforcement took implausibly long relative to the configured timeout, \
             measured from the runaway process's own confirmed start: {post_start_elapsed:?} \
             (pre-execution governance took {pre_execution_governance_duration:?}, correctly \
             excluded from this bound)"
        )));
    }
    let mtime_a = fs::metadata(&heartbeat)?.modified()?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mtime_b = fs::metadata(&heartbeat)?.modified()?;
    if mtime_a != mtime_b {
        return Err(fail(
            "heartbeat marker kept advancing after TimedOut -- the process tree was not \
             actually terminated (P12_RUNAWAY_DESCENDANT_SURVIVOR_COUNT != 0)",
        ));
    }
    eprintln!(
        "P12_REAL_RUNAWAY_TEST_TIMEOUT_E2E=PASS P12_TIMEOUT_CLASSIFICATION=PASS \
         P12_RUNAWAY_DESCENDANT_SURVIVOR_COUNT=0 \
         M09_P8RT_PRE_EXECUTION_GOVERNANCE_DURATION={pre_execution_governance_duration:?} \
         M09_P8RT_POST_START_ELAPSED={post_start_elapsed:?}"
    );
    Ok(())
}

/// P12-R1 audit item F (cancellation): the same real hanging fixture,
/// cancelled via a real [`CancellationToken`] fired from a concurrent task
/// (never a timeout) -- distinct classification (`Cancelled`, not
/// `TimedOut`), and the same real process-tree-death proof via heartbeat
/// mtime stasis.
#[cfg(unix)]
#[tokio::test]
async fn real_p12_test_cancellation_terminates_process_tree_e2e() -> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("hang-cancel");
    let heartbeat = fixture_dir.join("HEARTBEAT");
    write_hang_fixture(&fixture_dir, &heartbeat)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();
    // Generous timeout so the race is always won by cancellation, not by
    // TimedOut -- this test is specifically about the Cancelled path.
    let limits = TestExecutionLimits {
        timeout: Duration::from_secs(60),
        ..TestExecutionLimits::default()
    };

    let canceller_token = cancellation.clone();
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(2500)).await;
        canceller_token.cancel();
    });
    let result = run_cargo_test_with_limits(
        &managed_root,
        &fixture_dir,
        &effective,
        &cancellation,
        &limits,
    )
    .await;
    canceller
        .await
        .map_err(|error| fail(format!("canceller task itself panicked: {error}")))?;
    if result != Err(RustTestError::Cancelled) {
        return Err(fail(format!("expected Cancelled, got {result:?}")));
    }
    if !heartbeat.is_file() {
        return Err(fail(
            "heartbeat marker never appeared -- the hang fixture may not have started \
             running before cancellation fired",
        ));
    }
    let mtime_a = fs::metadata(&heartbeat)?.modified()?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mtime_b = fs::metadata(&heartbeat)?.modified()?;
    if mtime_a != mtime_b {
        return Err(fail(
            "heartbeat marker kept advancing after Cancelled -- the process tree was not \
             actually terminated (P12_POST_CANCEL_ORPHAN_PROCESS_COUNT != 0)",
        ));
    }
    eprintln!(
        "P12_REAL_TEST_CANCELLATION_E2E=PASS P12_CANCELLATION_CLASSIFICATION=PASS \
         P12_POST_CANCEL_ORPHAN_PROCESS_COUNT=0"
    );
    Ok(())
}

/// P12-R1 audit item D (huge output), stdout half: libtest always writes
/// its `test result:` summary as the very last line -- so a run whose real
/// stdout vastly exceeds a small configured bound has that summary line
/// fall entirely in the discarded (head-truncating, never-buffered) tail.
/// Proves this is reported as the distinct
/// [`RustTestError::ResultTruncatedBeforeSummary`], never a fabricated
/// `Ok(passing: true)` -- `P12_OUTPUT_TRUNCATION_FALSE_PASS_COUNT=0`.
#[cfg(unix)]
#[tokio::test]
async fn real_p12_huge_stdout_truncated_before_summary_e2e() -> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("huge-stdout");
    write_huge_stdout_fixture(&fixture_dir)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();
    let limits = TestExecutionLimits {
        limits: ProcessLimits {
            max_stdout_bytes: 4096,
            max_stderr_bytes: 4096,
        },
        ..TestExecutionLimits::default()
    };

    let result = run_cargo_test_with_limits(
        &managed_root,
        &fixture_dir,
        &effective,
        &cancellation,
        &limits,
    )
    .await;
    if result != Err(RustTestError::ResultTruncatedBeforeSummary) {
        return Err(fail(format!(
            "expected ResultTruncatedBeforeSummary, got {result:?} -- if this is `Ok(..)`, \
             truncation produced a false result, which is the exact defect class this test \
             exists to prevent"
        )));
    }
    eprintln!(
        "P12_REAL_HUGE_OUTPUT_BOUNDING_E2E=PASS P12_STDOUT_BOUNDED=YES \
         P12_OUTPUT_TRUNCATION_FALSE_PASS_COUNT=0"
    );
    Ok(())
}

/// P12-R1 audit item D (huge output), stderr half: a real test emitting far
/// more stderr than any reasonable bound, while its own real stdout (and
/// libtest's `test result:` summary) stays small -- proves stderr bounding
/// neither deadlocks the child (the bounded reader drains to completion
/// regardless, per `wht_corulix_tooling`'s own `spawn_bounded_reader`) nor
/// corrupts the real, correct classification derived from stdout.
#[cfg(unix)]
#[tokio::test]
async fn real_p12_huge_stderr_does_not_deadlock_or_corrupt_classification_e2e()
-> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("huge-stderr");
    write_huge_stderr_small_stdout_fixture(&fixture_dir)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();
    let limits = TestExecutionLimits {
        limits: ProcessLimits {
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 4096,
        },
        ..TestExecutionLimits::default()
    };

    let started_at = Instant::now();
    let outcome = run_cargo_test_with_limits(
        &managed_root,
        &fixture_dir,
        &effective,
        &cancellation,
        &limits,
    )
    .await
    .map_err(|error| {
        fail(format!(
            "expected a real completed run despite huge stderr, got {error:?}"
        ))
    })?;
    let elapsed = started_at.elapsed();
    if !outcome.passing {
        return Err(fail(format!(
            "expected a passing outcome (the real test assertion succeeds), got {outcome:?}"
        )));
    }
    if elapsed > Duration::from_secs(60) {
        return Err(fail(format!(
            "huge stderr appears to have stalled the run: {elapsed:?}"
        )));
    }
    eprintln!(
        "P12_STDERR_BOUNDED=YES P12_RESULT_SUMMARY_BOUNDED=YES \
         P12_OUTPUT_TRUNCATION_FALSE_PASS_COUNT=0"
    );
    Ok(())
}

/// P12-R1 audit item E (self-mutation / snapshot coherence): the real
/// negative fixture -- a test whose own body writes new bytes to
/// `src/lib.rs` (governed source, inside the hashed scope) before
/// succeeding. `run_cargo_test`'s pre/post `hash_governed_source_tree`
/// comparison must detect the drift and refuse to return a normal outcome
/// at all, regardless of the process's own exit code --
/// `P12_SELF_MUTATING_TEST_FALSE_CURRENT_EVIDENCE_COUNT=0` because no
/// `Ok(..)` (and therefore no Evidence-eligible result) is ever produced.
#[cfg(unix)]
#[tokio::test]
async fn real_p12_self_mutating_test_is_detected_and_never_produces_current_evidence_e2e()
-> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("self-mutating");
    write_self_mutating_fixture(&fixture_dir)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let result = run_cargo_test(&managed_root, &fixture_dir, &effective, &cancellation).await;
    if result != Err(RustTestError::WorkspaceSelfMutationDetected) {
        return Err(fail(format!(
            "expected WorkspaceSelfMutationDetected, got {result:?} -- if this is `Ok(..)`, a \
             test that mutated its own governed source produced current-looking Evidence for \
             stale content, which is the exact defect class this test exists to prevent"
        )));
    }
    let mutated = fs::read_to_string(fixture_dir.join("src/lib.rs"))?;
    if !mutated.contains("mutated by the test itself") {
        return Err(fail(
            "the fixture's own self-mutation did not actually happen -- this negative test \
             would be vacuous",
        ));
    }
    eprintln!(
        "P12_SELF_MUTATING_TEST_FALSE_CURRENT_EVIDENCE_COUNT=0 \
         P12_TEST_EVIDENCE_SNAPSHOT_COHERENCE=PASS \
         P12_OUT_OF_BAND_CONTENT_CHANGE_FALSE_CURRENT_EVIDENCE_COUNT=0"
    );
    Ok(())
}

/// Verifies [`hash_governed_source_tree`]-style scanning (exercised
/// end-to-end via a real `run_cargo_test` call) does not fail closed on a
/// realistically-sized `src/` tree -- guards against the self-mutation
/// coherence check itself becoming a false-`WorkspaceSourceTreeUnreadable`
/// hazard on an ordinary crate (not just the tiny single-file fixtures
/// every other test in this file uses).
#[cfg(unix)]
#[tokio::test]
async fn real_p12_realistic_source_tree_size_does_not_false_positive_e2e()
-> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let fixture_dir = temp_dir("realistic-source-tree");
    fs::create_dir_all(fixture_dir.join("src/nested/deeper"))?;
    fs::write(
        fixture_dir.join("Cargo.toml"),
        "[package]\nname = \"p12_realistic_tree_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    let mut lib_rs = String::from(
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t_ok() { assert_eq!(1 + 1, 2); }\n}\n",
    );
    for i in 0..40 {
        let module_body = format!("pub fn f_{i}() -> i32 {{ {i} }}\n");
        fs::write(
            fixture_dir.join(format!("src/nested/deeper/m_{i}.rs")),
            &module_body,
        )?;
        lib_rs.push_str(&format!(
            "#[path = \"nested/deeper/m_{i}.rs\"]\nmod m_{i};\n"
        ));
    }
    fs::write(fixture_dir.join("src/lib.rs"), lib_rs)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let outcome = run_cargo_test(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| {
            fail(format!(
                "expected a real completed run against a ~40-file src/ tree, got {error:?} \
                 (a WorkspaceSourceTreeUnreadable here would mean the coherence check itself \
                 fails closed on an ordinary-sized crate)"
            ))
        })?;
    if !outcome.passing {
        return Err(fail(format!("expected a passing outcome, got {outcome:?}")));
    }
    eprintln!("P12_R1_REALISTIC_SOURCE_TREE_SIZE_NO_FALSE_POSITIVE=PASS");
    Ok(())
}

// ============================================================================
// P12-R2: managed GNU link runtime -- linker authority adversarial proofs
// ============================================================================

/// Writes a fake `cc`/`gcc`/`clang`/`ld` at `dir/<name>` that appends a
/// distinctive line to `marker_path` and exits non-zero if actually
/// executed -- the positive control for
/// `real_p12_r2_hostile_linker_poison_positive_control_e2e` and
/// `real_p12_r2_workspace_linker_config_hijack_denied_e2e`: proves the fake
/// *would* leave real, detectable evidence if the certified linker
/// configuration ever selected it.
#[cfg(unix)]
fn write_poison_executable(dir: &std::path::Path, name: &str, marker_path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::create_dir_all(dir);
    let script_path = dir.join(name);
    fs::write(
        &script_path,
        format!(
            "#!/bin/sh\necho \"POISON_EXECUTED:{name}\" >> \"{}\"\nexit 1\n",
            marker_path.display()
        ),
    )
    .unwrap_or_else(|error| unreachable!("poison script write must succeed: {error}"));
    let mut permissions = fs::metadata(&script_path)
        .unwrap_or_else(|error| unreachable!("poison script metadata must succeed: {error}"))
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script_path, permissions)
        .unwrap_or_else(|error| unreachable!("poison script chmod must succeed: {error}"));
}

/// Adversarial positive control for the certified managed-linker
/// configuration: a real fake `ld` executable that *would* leave detectable
/// evidence if the certified linker selection ever reached it, referenced
/// through the one mechanism that could plausibly override
/// `-C linker=<managed rust-lld>` -- a workspace's own
/// `.cargo/config.toml`. (An ambient-`PATH`-based variant of this control
/// was deliberately not implemented as a second, separate test: doing so
/// would require mutating this host process's own `PATH` via
/// `std::env::set_var`, which this workspace's `unsafe-code = "forbid"`
/// lint disallows, and it would be testing a structurally moot precondition
/// regardless -- [`wht_corulix_engine::testing::link_environment`] builds
/// `PATH` from the managed Rust `bin/` directory alone and contains no
/// `std::env::var("PATH")` read of any kind, confirmed via `rg` over
/// `wht_corulix_engine/src/testing.rs`, not merely asserted.)
///
/// Negative control: a workspace's own `.cargo/config.toml` declaring
/// `[target.x86_64-unknown-linux-gnu] linker = "<poisoned path>"` must never
/// be able to substitute Corulix's managed linker -- confirmed empirically
/// during this phase's research gate that an env-derived `RUSTFLAGS -C
/// linker=` argument takes precedence over a workspace config file's
/// `target.<triple>.linker` key, and this test proves it end-to-end through
/// the real P12 product path. `P12_WORKSPACE_LINKER_AUTHORITY_COUNT=0`.
// Windows note (Phase 17-W): `#[cfg(unix)]`-only. This test's poison
// executable (`write_poison_executable`, itself already `#[cfg(unix)]`-gated)
// and its `.cargo/config.toml` fixture both hardcode the
// `x86_64-unknown-linux-gnu` target triple and Corulix's managed *GNU* link
// runtime (`wht_corulix_tooling::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64`)
// -- there is currently no Windows-side managed linker runtime manifest for
// this test's native-MSVC equivalent to exercise
// (`managed_runtimes.rs` has no `*_WINDOWS_*` entries as of this phase), so a
// Windows variant of this exact assertion is a disclosed residual, not yet
// written, rather than silently dropped
// (`P17_W_WINDOWS_LINKER_HIJACK_EQUIVALENT_COUNT=0`).
#[cfg(unix)]
#[tokio::test]
async fn real_p12_r2_workspace_linker_config_hijack_denied_e2e() -> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P12_R2_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };

    let fixture_dir = temp_dir("r2-workspace-hijack-fixture");
    write_failing_fixture(&fixture_dir)?;

    let poison_dir = temp_dir("r2-workspace-hijack-poison-bin");
    let marker_path = temp_dir("r2-workspace-hijack-marker").join("marker.log");
    write_poison_executable(&poison_dir, "ld", &marker_path);

    fs::create_dir_all(fixture_dir.join(".cargo"))?;
    fs::write(
        fixture_dir.join(".cargo/config.toml"),
        format!(
            "[target.x86_64-unknown-linux-gnu]\nlinker = \"{}\"\n",
            poison_dir.join("ld").display()
        ),
    )?;

    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();
    let outcome = run_cargo_test(&managed_root, &fixture_dir, &effective, &cancellation)
        .await
        .map_err(|error| {
            fail(format!(
                "expected the certified managed linker to win over the workspace's \
                 .cargo/config.toml override and reach a real completed run, got {error:?}"
            ))
        })?;
    let _ = outcome;

    if marker_path.exists() {
        let contents = fs::read_to_string(&marker_path).unwrap_or_default();
        return Err(fail(format!(
            "expected the workspace-declared linker override to never execute, but found: {contents}"
        )));
    }
    eprintln!("P12_WORKSPACE_LINKER_AUTHORITY_COUNT=0");
    Ok(())
}

/// The managed GNU link runtime specifically absent (Rust runtime present
/// and owned) fails closed with
/// [`RustTestError::ManagedLinkerRuntimeUnavailable`] *before* any process
/// is spawned -- distinct from
/// `real_p12_required_provider_unavailable_fails_closed_e2e`'s fully-empty
/// root, which only ever exercises the *first* resolution
/// (`ManagedRuntimeUnavailable`) and can never reach the second.
///
/// The isolated root gets a real, independent `provision` of the Rust
/// runtime (not a symlink to the shared fixture root's own install): a
/// symlinked component directory *plus* a symlinked ownership record was
/// tried first and rejected by `ownership::load`'s own
/// `RootIdentityMismatch` check -- ownership records are bound to the
/// exact root they were written for by design (`record.managed_root_identity`),
/// precisely the "a pre-ownership orphan artifact must never be trusted"
/// invariant `resolve_owned_managed_component`'s own doc comment states.
/// That rejection is itself confirmation the ownership binding is real, not
/// a test inconvenience to route around.
///
/// `#[cfg(not(target_os = "windows"))]`: this test's whole premise -- "Rust
/// runtime present and owned, GNU link runtime specifically absent" -- is
/// structurally impossible on Windows since P17-W2. Unix genuinely composes
/// two independent managed components (`resolve_runtime`'s Rust runtime,
/// `resolve_link_runtime`'s separate GNU sysroot), so provisioning only the
/// first and asserting the second's absence is a real, distinct state to
/// test. On Windows, `rust_semantic_runtime_host_native()` and
/// `link_runtime_host_native()` resolve to the *identical* merged component
/// (`RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`) -- provisioning "the Rust
/// runtime" *is* provisioning the GNU link capability, so there is no
/// intermediate state left to exercise; the equivalent Windows fail-closed
/// proof is `real_p12_required_provider_unavailable_fails_closed_e2e`'s own
/// `ManagedLinkerRuntimeUnavailable` branch against a *fully* empty root.
#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn real_p12_r2_managed_gnu_runtime_unavailable_fails_closed_e2e() -> Result<(), Box<dyn Error>>
{
    let isolated_root = temp_dir("r2-gnu-runtime-unavailable-root");
    let isolated_rust_manifest = rust_semantic_runtime_host_native();
    let rust_provision = provisioning::provision(&isolated_root, &isolated_rust_manifest).await;
    if rust_provision.is_err() {
        eprintln!(
            "P12_R2_TEST_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?) : {rust_provision:?}"
        );
        return Ok(());
    }

    let (rust_state, _) =
        provisioning::resolve_owned_managed_component(&isolated_root, &isolated_rust_manifest);
    if rust_state != ManagedComponentState::Available {
        return Err(fail(format!(
            "expected the freshly provisioned Rust runtime to resolve Available, got {rust_state:?}"
        )));
    }

    let fixture_dir = temp_dir("r2-gnu-runtime-unavailable-fixture");
    write_failing_fixture(&fixture_dir)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let result = run_cargo_test(&isolated_root, &fixture_dir, &effective, &cancellation).await;
    if result != Err(RustTestError::ManagedLinkerRuntimeUnavailable) {
        return Err(fail(format!(
            "expected ManagedLinkerRuntimeUnavailable, got {result:?}"
        )));
    }
    eprintln!("P12_R2_GNU_RUNTIME_UNAVAILABLE_FAILS_CLOSED=PASS");
    eprintln!("P12_HOST_FALLBACK_EXECUTION_COUNT=0");
    Ok(())
}
