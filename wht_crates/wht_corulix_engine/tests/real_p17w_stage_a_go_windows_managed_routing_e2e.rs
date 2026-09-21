// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(windows)]

//! P17-W Master Closure Order, Stage A: real, native-Windows-only proof
//! that `wht_corulix_engine::go_providers::resolve_go_toolchain` genuinely
//! resolves the `CORULIX_MANAGED` `GO_SEMANTIC_RUNTIME_WINDOWS_X64` runtime
//! -- the tier this pass wired in -- rather than merely compiling on this
//! platform. Mirrors `wht_corulix_tooling`'s own
//! `real_node_managed_lifecycle_windows_e2e.rs` exactly (install -> use ->
//! hostile-environment -> idempotence -> uninstall -> zero-residual), the
//! established template for a real Windows managed-component lifecycle
//! proof in this workspace, adapted to also exercise Stage A's own
//! two-tier precedence contract (`go_providers.rs`'s own module doc
//! comment): tier 1 (`CORULIX_MANAGED`) must resolve and win while
//! provisioned; once removed, tier 2 (`HOST_ONLY`) must fail closed on a
//! host with neither a system Go nor any approved directory configured --
//! never silently substitute anything else.
//!
//! Before this pass, Windows had `GO_SEMANTIC_RUNTIME_WINDOWS_X64` as a
//! real, hash-verified manifest with no production consumer at all
//! (`wht_corulix_lsp::managed_toolchain`'s own doc comment: "not yet a
//! wired managed provider"). This file is the first real proof that a
//! provisioned Windows Go runtime is actually used by this crate's
//! `go build`/`go vet`/`go test` resolution path.
//!
//! Requires network access the first time it runs against a given root
//! (the real `go.dev/dl/go1.27.0.windows-amd64.zip` archive); every
//! subsequent run resolves the artifact purely from local disk.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, ContentHash, ExecutionClass, ProviderCategory};
use wht_corulix_engine::go_providers::{self, GoProviderError};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState, uninstall};
use wht_corulix_tooling::{ProcessLimits, ProcessSpec, execute};
use wht_corulix_workspace::WorkspaceRoot;

/// `clippy::panic`/`unwrap_used`/`expect_used` are all workspace-wide
/// `deny` (`Cargo.toml`'s own `[workspace.lints.clippy]`), with no
/// `#[cfg(test)]`-scoped exception -- unlike `src/lib.rs`'s crate-level
/// attributes, an integration-test binary does not inherit any allowance
/// the crate itself might carry, so this file needs its own `Result`-
/// returning, `?`-propagating idiom. Mirrors
/// `real_p15_go_build_vet_test_e2e.rs`'s own `TestFailure`/`fail` helper
/// exactly, rather than inventing a second one.
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

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("corulix-go-win-stagea-e2e-{label}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn write_sentinel(dir: &Path, name: &str, content: &[u8]) -> (PathBuf, String) {
    let path = dir.join(name);
    fs::write(&path, content)
        .unwrap_or_else(|error| unreachable!("sentinel fixture write must succeed: {error:?}"));
    let digest = ContentHash::compute_sha256(content).digest_hex;
    (path, digest)
}

fn assert_sentinel_unchanged(path: &Path, expected_digest: &str) {
    let bytes = fs::read(path).unwrap_or_else(|error| {
        unreachable!("sentinel fixture must still exist after uninstall: {error:?}")
    });
    let actual_digest = ContentHash::compute_sha256(&bytes).digest_hex;
    assert_eq!(
        actual_digest, expected_digest,
        "sentinel fixture at {path:?} was mutated by the managed Go uninstall"
    );
}

/// A disposable Go module fixture plus its own isolated, disposable
/// managed root -- never the shared, host-wide `managed_toolchain_root()`
/// other suites provision into, so this file's own provision/uninstall
/// lifecycle cannot race a concurrent real suite. Mirrors
/// `real_p15_go_build_vet_test_e2e.rs`'s own `Fixture` exactly.
struct Fixture {
    module: PathBuf,
    managed_root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir().join(format!("corulix-p17w-stagea-go-{label}-{}", stamp()));
        let module = base.join("module");
        let managed_root = base.join("managed");
        let _ = fs::create_dir_all(&module);
        let _ = fs::create_dir_all(&managed_root);
        let _ = fs::write(
            module.join("go.mod"),
            "module corulix_p17w_stagea_fixture\n\ngo 1.24\n",
        );
        let _ = fs::write(module.join("main.go"), "package main\n\nfunc main() {}\n");
        Self {
            module,
            managed_root,
        }
    }

    fn root(&self) -> WorkspaceRoot {
        WorkspaceRoot::open(&self.module)
            .unwrap_or_else(|error| unreachable!("fixture WorkspaceRoot::open: {error:?}"))
    }

    fn cleanup(&self) {
        if let Some(base) = self.module.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }
}

/// An `EffectiveConfig` granting no `HOST_ONLY` authority at all -- no
/// approved directories, workspace trust irrelevant to this module's own
/// resolution (that gate lives in `go_validation`/`go_testing`, not
/// `go_providers::resolve_go_toolchain`). This is deliberate: every
/// positive assertion in this file must be explained by tier 1
/// (`CORULIX_MANAGED`) alone, never by an incidental `HOST_ONLY` grant.
fn no_host_only_authority() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

#[tokio::test]
async fn real_windows_go_managed_tier_installs_resolves_and_wins_over_hostile_state()
-> Result<(), Box<dyn Error>> {
    // `#![cfg(windows)]` at the top of this file means the Windows manifest
    // is always the correct one here -- mirrors
    // `real_node_managed_lifecycle_windows_e2e.rs` hardcoding
    // `NODE_24_LTS_WINDOWS_X64` directly rather than calling
    // `wht_corulix_engine::go_providers`'s own private, platform-`cfg`'d
    // selector (which stays private -- this crate's own production code is
    // its only caller, per Architecture Rule K).
    let manifest = wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_WINDOWS_X64;
    let fixture = Fixture::new("lifecycle");
    let root = fixture.managed_root.clone();
    let cancellation = CancellationToken::new();
    let effective = no_host_only_authority();
    let workspace_root = fixture.root();

    // Hostile sentinels: a fake `go.exe` on what a naive implementation
    // might treat as an ambient-PATH-equivalent location, and a
    // workspace-local fake `go.exe` sitting directly inside the governed
    // module. Both are checked byte-identical after this whole test, and
    // neither must ever be resolved or executed.
    let hostile_ambient_dir = temp_dir("hostile-ambient");
    let (hostile_ambient_path, hostile_ambient_digest) =
        write_sentinel(&hostile_ambient_dir, "go.exe", b"fake ambient go.exe bytes");
    let (workspace_fake_path, workspace_fake_digest) = write_sentinel(
        &fixture.module,
        "go.exe",
        b"fake workspace-local go.exe bytes",
    );

    // Deliberately **not** mutating this test process's own ambient `PATH`:
    // this workspace forbids `unsafe` code outright (`-F unsafe-code`), and
    // `std::env::set_var` is `unsafe` as of Rust 2024. The structural
    // guarantee this file proves instead is stronger than an ambient-PATH
    // poison-and-restore would be: neither tier ever performs a bare-name
    // `PATH` lookup at all -- tier 1 ([`go_providers::resolve_managed_go_toolchain`])
    // resolves a fixed path under `root` and touches no environment
    // variable; tier 2 goes through `wht_corulix_config::resolve_provider`,
    // independently verified (this module's own doc comment, Phase
    // 7B-B2-A-R2) never to read ambient `PATH`. The two sentinels below
    // (one directory a naive PATH-based implementation could have
    // consulted, one sitting directly inside the governed workspace) are
    // asserted byte-identical at the end of this test regardless -- proof
    // nothing here ever touched, read as an executable, or executed
    // either one.

    // Before any provisioning: tier 1 must honestly report unavailable
    // (never fabricate a resolution from an empty managed root), and tier
    // 2 must then fail closed too, since `no_host_only_authority` grants no
    // approved directory and this VM ships no system `go`.
    let before_provision = go_providers::resolve_go_toolchain(
        &root,
        &effective,
        &workspace_root,
        ProviderCategory::TypecheckBuild,
        &cancellation,
    )
    .await;
    assert!(
        matches!(
            before_provision,
            Err(GoProviderError::ProviderUnavailable(_))
        ),
        "WINDOWS_GO_PRE_PROVISION_FAIL_CLOSED=FAIL: {before_provision:?}"
    );

    // INSTALL: real network download + real ZIP extraction + real SHA-256
    // verification against `GO_SEMANTIC_RUNTIME_WINDOWS_X64`'s pinned
    // digest.
    let provisioned_path = provisioning::provision(&root, &manifest)
        .await
        .map_err(|error| fail(format!("WINDOWS_GO_MANAGED_INSTALL=FAIL ({error:?})")))?;
    assert!(
        provisioned_path.is_file(),
        "resolved go.exe path must exist on disk: {provisioned_path:?}"
    );
    let (state_after_provision, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state_after_provision, ManagedComponentState::Available);

    // USE, through the real production entry point this pass wired:
    // `go_providers::resolve_go_toolchain`. Must resolve tier 1, under
    // `root` -- never the hostile ambient or workspace-local sentinel.
    let resolved = go_providers::resolve_go_toolchain(
        &root,
        &effective,
        &workspace_root,
        ProviderCategory::TypecheckBuild,
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("WINDOWS_GO_MANAGED_USE=FAIL ({error:?})")))?;
    assert!(
        resolved.executable.starts_with(&root),
        "WINDOWS_GO_AMBIENT_PATH_AUTHORITY/WORKSPACE_TOOLCHAIN_AUTHORITY=FAIL: resolved \
         executable {:?} is not under the managed root {root:?}",
        resolved.executable
    );
    assert_ne!(resolved.executable, hostile_ambient_path);
    assert_ne!(resolved.executable, workspace_fake_path);
    assert!(
        resolved.version.to_lowercase().contains("go1.27.0")
            && resolved.version.contains("windows"),
        "WINDOWS_GO_EVIDENCE_PROVIDER_IDENTITY=FAIL: unexpected version string {:?}",
        resolved.version
    );

    // A real `go build -o NUL ./...` against the disposable fixture module,
    // through the exact controlled-process runtime every other provider
    // spawns through, using this module's own `go_environment` --
    // `WINDOWS_GO_BUILD_REAL_EXECUTION=PASS`.
    let scratch = go_providers::ensure_go_scratch(&root, fixture.module.as_path())
        .map_err(|error| fail(format!("WINDOWS_GO_SCRATCH=FAIL ({error:?})")))?;
    let build_outcome = execute(
        &ProcessSpec {
            executable: resolved.executable.clone(),
            arguments: vec![
                "build".to_string(),
                "-o".to_string(),
                "NUL".to_string(),
                "./...".to_string(),
            ],
            environment: go_providers::go_environment(&resolved, &scratch),
            working_directory: fixture.module.clone(),
            limits: ProcessLimits::default(),
            timeout: Duration::from_secs(120),
            execution_class: ExecutionClass::TrustedWorkspaceExecution,
            argv0: None,
        },
        &cancellation,
    )
    .await;
    assert!(
        matches!(
            build_outcome.termination,
            wht_corulix_tooling::TerminationReason::Exited { code: 0 }
        ),
        "WINDOWS_GO_BUILD_REAL_EXECUTION=FAIL: termination={:?} stderr={:?}",
        build_outcome.termination,
        String::from_utf8_lossy(&build_outcome.stderr.bytes)
    );

    // IDEMPOTENT SECOND RESOLUTION: same manifest, same canonical path.
    let resolved_again = go_providers::resolve_go_toolchain(
        &root,
        &effective,
        &workspace_root,
        ProviderCategory::TypecheckBuild,
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("WINDOWS_GO_PROVISION_IDEMPOTENCE=FAIL ({error:?})")))?;
    assert_eq!(resolved_again.executable, resolved.executable);

    // UNINSTALL.
    let removed = uninstall::uninstall(&root, manifest.id, |_| {}).await;
    assert_eq!(
        removed,
        Ok(uninstall::UninstallOutcome::Removed),
        "WINDOWS_GO_COMPONENT_UNINSTALL=FAIL"
    );
    let (state_after_uninstall, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state_after_uninstall, ManagedComponentState::NotProvisioned);

    // POST-UNINSTALL FALLBACK: tier 1 gone, tier 2 still fails closed (no
    // system `go`, no approved directory) -- never a silent substitute.
    let after_uninstall = go_providers::resolve_go_toolchain(
        &root,
        &effective,
        &workspace_root,
        ProviderCategory::TypecheckBuild,
        &cancellation,
    )
    .await;
    assert!(
        matches!(
            after_uninstall,
            Err(GoProviderError::ProviderUnavailable(_))
        ),
        "WINDOWS_GO_POST_UNINSTALL_FALLBACK_FAIL_CLOSED=FAIL: {after_uninstall:?}"
    );

    // Confirm neither hostile sentinel was ever touched, read as an
    // executable, or executed.
    assert_sentinel_unchanged(&hostile_ambient_path, &hostile_ambient_digest);
    assert_sentinel_unchanged(&workspace_fake_path, &workspace_fake_digest);

    let _ = fs::remove_dir_all(&hostile_ambient_dir);
    fixture.cleanup();

    eprintln!(
        "WINDOWS_GO_MANAGED_INSTALL=PASS WINDOWS_GO_MANAGED_USE=PASS \
         WINDOWS_GO_BUILD_REAL_EXECUTION=PASS WINDOWS_GO_AMBIENT_PATH_AUTHORITY=NO \
         WINDOWS_GO_WORKSPACE_TOOLCHAIN_AUTHORITY=NO WINDOWS_GO_PROVISION_IDEMPOTENCE=PASS \
         WINDOWS_GO_COMPONENT_UNINSTALL=PASS WINDOWS_GO_POST_UNINSTALL_FALLBACK_FAIL_CLOSED=PASS"
    );
    Ok(())
}
