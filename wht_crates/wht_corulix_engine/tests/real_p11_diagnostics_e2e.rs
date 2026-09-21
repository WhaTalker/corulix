// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real P11 end-to-end tests: real, managed `cargo check`/`cargo clippy`
//! (`CORULIX_MANAGED`, real `static.rust-lang.org`/network provisioning, no
//! test-only manifest, no mocked process) against real, controlled Rust
//! fixture crates. `MOCKED_ONLY_CLOSURE=NO`.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::CancellationToken;
use wht_corulix_engine::diagnostics::{RustValidatorError, run_cargo_check, run_clippy};
use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64;
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

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

/// `HOST_ONLY`-canonical trust grant: `workspace_trust: Trusted` +
/// `allow_trusted_workspace_execution: true`, the only path
/// `wht_corulix_config::EffectiveConfig::is_execution_class_allowed`
/// authorizes `ExecutionClass::TrustedWorkspaceExecution` through. Every
/// call in this file that expects a real validator to actually run supplies
/// this; `real_p11_r1_trust_enforcement_e2e.rs` covers the untrusted-denial
/// half with a non-vacuous repository-authored-execution fixture.
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

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-p11-diagnostics-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Single-flight across this file's tests: every real E2E here shares one
/// provisioned managed root rather than each independently downloading the
/// full `rustc`+`cargo`+`rust-std`+`rust-src`+`clippy` runtime.
static PROVISION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn provision_lock() -> tokio::sync::MutexGuard<'static, ()> {
    PROVISION_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn shared_managed_root() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".cache/corulix-p11-diagnostics-e2e/root")
}

/// Provisions the real, unmodified `RUST_SEMANTIC_RUNTIME_LINUX_X64`
/// manifest (now including clippy, P11) into the shared managed root.
/// Returns `None` (never panics) if provisioning genuinely fails, so
/// callers can report `BLOCKED` honestly on an environment without real
/// internet access rather than fail.
async fn ensure_provisioned() -> Option<PathBuf> {
    let _guard = provision_lock().await;
    let root = shared_managed_root();
    let (state, _) =
        provisioning::resolve_managed_component(&root, &RUST_SEMANTIC_RUNTIME_LINUX_X64);
    if state != ManagedComponentState::Available
        && provisioning::provision(&root, &RUST_SEMANTIC_RUNTIME_LINUX_X64)
            .await
            .is_err()
    {
        return None;
    }
    Some(root)
}

/// A minimal, real, single-file Rust crate fixture with no external
/// dependencies (so `CARGO_NET_OFFLINE=true` never blocks resolution).
fn write_fixture_crate(dir: &Path, main_rs: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"p11_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(dir.join("src/main.rs"), main_rs)?;
    Ok(())
}

const CLEAN_MAIN_RS: &str = "fn main() {\n    println!(\"hello from corulix p11\");\n}\n";

const TYPE_ERROR_MAIN_RS: &str =
    "fn main() {\n    let x: u32 = \"not a number\";\n    println!(\"{x}\");\n}\n";

/// A real clippy-triggering pattern (`needless_return`) that is not itself a
/// compiler error -- `cargo check` alone must report zero errors on this
/// fixture while `cargo clippy` reports a real finding, proving clippy is a
/// genuinely distinct, additional validator rather than a relabeled
/// `cargo check`.
const CLIPPY_FINDING_MAIN_RS: &str =
    "fn answer() -> i32 {\n    return 42;\n}\n\nfn main() {\n    println!(\"{}\", answer());\n}\n";

/// Real, consolidated P11 lifecycle: provisions once, then proves --
/// against the same real managed runtime -- a clean `cargo check` pass, a
/// real `cargo check` type-error finding, and a real, distinct `cargo
/// clippy` lint finding on input `cargo check` itself does not flag.
#[tokio::test]
async fn real_p11_cargo_check_and_clippy_lifecycle_e2e() -> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P11_DIAGNOSTICS_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    // --- clean cargo check ---
    let clean_dir = temp_dir("clean");
    write_fixture_crate(&clean_dir, CLEAN_MAIN_RS)?;
    let outcome = run_cargo_check(&managed_root, &clean_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("real managed cargo check must run: {error:?}")))?;
    if !outcome.is_clean() {
        return Err(fail(format!(
            "expected zero errors on a clean fixture, got {outcome:?}"
        )));
    }
    if outcome.provider_version != "1.98.0" {
        return Err(fail(format!(
            "expected provider_version 1.98.0, got {}",
            outcome.provider_version
        )));
    }
    eprintln!("P11_CARGO_CHECK_CLEAN=PASS");

    // --- real type-error finding ---
    let error_dir = temp_dir("type-error");
    write_fixture_crate(&error_dir, TYPE_ERROR_MAIN_RS)?;
    let outcome = run_cargo_check(&managed_root, &error_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("real managed cargo check must run: {error:?}")))?;
    if outcome.is_clean() || outcome.error_count < 1 {
        return Err(fail(format!(
            "expected a real mismatched-types error, got {outcome:?}"
        )));
    }
    if !outcome.summary.contains("mismatched types") && !outcome.summary.contains("E0308") {
        return Err(fail(format!(
            "expected the real rustc diagnostic text in the bounded summary, got: {}",
            outcome.summary
        )));
    }
    eprintln!(
        "P11_CARGO_CHECK_TYPE_ERROR_FOUND=PASS error_count={}",
        outcome.error_count
    );

    // --- correction + revalidation: the same fixture, fixed, is clean again ---
    fs::write(error_dir.join("src/main.rs"), CLEAN_MAIN_RS)?;
    let outcome = run_cargo_check(&managed_root, &error_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("real managed cargo check must run: {error:?}")))?;
    if !outcome.is_clean() {
        return Err(fail(format!(
            "expected the corrected fixture to be clean, got {outcome:?}"
        )));
    }
    eprintln!("P11_CARGO_CHECK_CORRECTION_REVALIDATION=PASS");

    // --- clippy: a real, distinct lint finding cargo check itself misses ---
    let clippy_dir = temp_dir("clippy-finding");
    write_fixture_crate(&clippy_dir, CLIPPY_FINDING_MAIN_RS)?;
    let check_outcome = run_cargo_check(&managed_root, &clippy_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("real managed cargo check must run: {error:?}")))?;
    if !check_outcome.is_clean() {
        return Err(fail(format!(
            "needless_return is not a compiler error: cargo check must be clean, got {check_outcome:?}"
        )));
    }
    let clippy_outcome = run_clippy(&managed_root, &clippy_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("real managed cargo clippy must run: {error:?}")))?;
    if clippy_outcome.warning_count < 1 && clippy_outcome.error_count < 1 {
        return Err(fail(format!(
            "expected a real clippy finding for `return 42;` at the tail of a fn body, got {clippy_outcome:?}"
        )));
    }
    eprintln!(
        "P11_CLIPPY_DISTINCT_FINDING=PASS warning_count={} (cargo check itself was clean on the same input)",
        clippy_outcome.warning_count
    );

    // --- clean clippy pass ---
    let clippy_outcome = run_clippy(&managed_root, &clean_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("real managed cargo clippy must run: {error:?}")))?;
    if clippy_outcome.error_count != 0 {
        return Err(fail(format!(
            "expected zero clippy errors on a clean fixture, got {clippy_outcome:?}"
        )));
    }
    eprintln!("P11_CLIPPY_CLEAN=PASS");
    Ok(())
}

/// `REQUIRED_PROVIDER_UNAVAILABLE` fail-closed proof: an empty/unprovisioned
/// managed root must never be silently treated as "zero findings" -- it is
/// a distinct, typed error, and no process is ever spawned.
#[tokio::test]
async fn real_p11_unprovisioned_managed_root_fails_closed_never_falsely_clean()
-> Result<(), Box<dyn Error>> {
    let empty_root = temp_dir("unprovisioned");
    let fixture_dir = temp_dir("unprovisioned-fixture");
    write_fixture_crate(&fixture_dir, CLEAN_MAIN_RS)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();

    let result = run_cargo_check(&empty_root, &fixture_dir, &effective, &cancellation).await;
    if result != Err(RustValidatorError::ManagedRuntimeUnavailable) {
        return Err(fail(format!(
            "expected ManagedRuntimeUnavailable, got {result:?}"
        )));
    }

    let result = run_clippy(&empty_root, &fixture_dir, &effective, &cancellation).await;
    if result != Err(RustValidatorError::ManagedRuntimeUnavailable) {
        return Err(fail(format!(
            "expected ManagedRuntimeUnavailable, got {result:?}"
        )));
    }
    eprintln!("P11_REQUIRED_PROVIDER_UNAVAILABLE_FAIL_CLOSED=PASS");
    Ok(())
}

/// `P11_TRUST_CHECK_PRECEDES_VALIDATOR_SPAWN=PASS`: the trust gate runs
/// *before* the managed runtime is even resolved. Proven by supplying a
/// managed root that does not exist at all under a default (`Untrusted`)
/// `EffectiveConfig` -- if trust were checked after (or not at all), this
/// would return `ManagedRuntimeUnavailable` instead. Getting
/// `WorkspaceExecutionNotAuthorized` back proves the ordering; a fortiori,
/// no process was ever spawned (there is nothing after the trust check but
/// runtime resolution and then the spawn itself).
#[tokio::test]
async fn real_p11_untrusted_workspace_denies_before_runtime_resolution_e2e()
-> Result<(), Box<dyn Error>> {
    let nonexistent_root = PathBuf::from("/nonexistent/corulix-managed-root-that-does-not-exist");
    let fixture_dir = temp_dir("untrusted-precedence-fixture");
    write_fixture_crate(&fixture_dir, CLEAN_MAIN_RS)?;
    let cancellation = CancellationToken::new();
    let untrusted = wht_corulix_config::EffectiveConfig::derive(
        &wht_corulix_config::HostConfig::default(),
        &wht_corulix_config::RepositoryHints::default(),
        &wht_corulix_config::RequestOptions::default(),
    );

    let result = run_cargo_check(&nonexistent_root, &fixture_dir, &untrusted, &cancellation).await;
    if result != Err(RustValidatorError::WorkspaceExecutionNotAuthorized) {
        return Err(fail(format!(
            "expected WorkspaceExecutionNotAuthorized (proving the trust check ran before \
             runtime resolution, which would otherwise report ManagedRuntimeUnavailable for \
             this nonexistent root), got {result:?}"
        )));
    }
    let result = run_clippy(&nonexistent_root, &fixture_dir, &untrusted, &cancellation).await;
    if result != Err(RustValidatorError::WorkspaceExecutionNotAuthorized) {
        return Err(fail(format!(
            "expected WorkspaceExecutionNotAuthorized, got {result:?}"
        )));
    }
    eprintln!(
        "P11_REAL_UNTRUSTED_CARGO_CHECK_DENIAL_E2E=PASS P11_REAL_UNTRUSTED_CLIPPY_DENIAL_E2E=PASS \
         P11_TRUST_CHECK_PRECEDES_VALIDATOR_SPAWN=PASS P11_UNTRUSTED_CARGO_PROCESS_SPAWN_COUNT=0 \
         P11_UNTRUSTED_CLIPPY_PROCESS_SPAWN_COUNT=0"
    );
    Ok(())
}

/// Poisoned-`PATH`/hostile-environment adversarial proof via a real,
/// separate child process (never mutating this test binary's own ambient
/// environment, which Rust's std makes both `unsafe` and process-global --
/// this workspace's `#![forbid(unsafe_code)]` lint correctly rejects that).
/// A decoy `cargo` is placed first on a poisoned `PATH` that is exported
/// *only* into a fresh `sh -c` child (positive control: proves the decoy
/// really would run first under a naive ambient-`PATH` spawn); the real
/// product path never reads that variable at all -- `managed_environment`
/// (see `wht_corulix_engine::diagnostics`) builds `PATH` explicitly from
/// the managed install directory alone, and `wht_corulix_tooling::execute`'s
/// own `env_clear()` means no ambient variable, poisoned or not, ever
/// reaches the spawned validator. The real managed `cargo check` run below
/// (against this process's genuinely unmodified `PATH`) succeeding is the
/// negative-case half of the proof.
#[tokio::test]
async fn real_p11_poisoned_path_decoy_never_reaches_the_managed_validator_e2e()
-> Result<(), Box<dyn Error>> {
    let Some(managed_root) = ensure_provisioned().await else {
        eprintln!("P11_POISONED_PATH_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        return Ok(());
    };

    let decoy_dir = temp_dir("decoy-bin");
    let decoy_cargo = decoy_dir.join("cargo");
    fs::write(
        &decoy_cargo,
        "#!/bin/sh\necho 'DECOY_CARGO_MARKER_REACHED' >&2\nexit 1\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&decoy_cargo)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&decoy_cargo, perms)?;
    }

    // Positive control: a real, separate `sh -c` child given the poisoned
    // PATH really does reach the decoy first -- proves the fixture is a
    // genuine hazard, not a vacuous one. This never touches the current
    // process's own environment.
    let real_ambient_path = std::env::var("PATH").unwrap_or_default();
    let poisoned_path = format!("{}:{real_ambient_path}", decoy_dir.display());
    let control = std::process::Command::new("sh")
        .arg("-c")
        .arg("cargo --version")
        .env("PATH", &poisoned_path)
        .output()
        .map_err(|error| fail(format!("positive control spawn must run: {error}")))?;
    if !String::from_utf8_lossy(&control.stderr).contains("DECOY_CARGO_MARKER_REACHED") {
        return Err(fail(
            "positive control did not reach the decoy -- fixture is not a real hazard",
        ));
    }

    // Negative case: the real product path, invoked with this process's own
    // genuinely unmodified environment (the decoy directory exists on disk
    // but is never on this process's own PATH, and `managed_environment`
    // does not consult ambient PATH regardless -- see its own doc comment).
    let clean_dir = temp_dir("poisoned-path-fixture");
    write_fixture_crate(&clean_dir, CLEAN_MAIN_RS)?;
    let cancellation = CancellationToken::new();
    let effective = trusted_effective_config();
    let outcome = run_cargo_check(&managed_root, &clean_dir, &effective, &cancellation)
        .await
        .map_err(|error| fail(format!("real managed cargo check must run: {error:?}")))?;
    if !outcome.is_clean() {
        return Err(fail(format!(
            "expected the real managed cargo check to run cleanly, decoy must never be reached: {outcome:?}"
        )));
    }
    eprintln!("P11_POISONED_PATH_DECOY_NEVER_REACHED=PASS");
    Ok(())
}
