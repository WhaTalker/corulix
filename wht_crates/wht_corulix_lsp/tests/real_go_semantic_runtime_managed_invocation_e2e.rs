// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P17-W-R4-C3, Stage C (partial): a real install -> real `go version` ->
//! real `go build`/`go test` -> uninstall proof for the `CORULIX_MANAGED`
//! Go semantic runtime (`go-semantic-runtime`), against the real, pinned
//! `GO_SEMANTIC_RUNTIME_HOST_NATIVE` manifest.
//!
//! # Scope, honestly bounded
//!
//! This file proves the *managed runtime's own* provisioning/invocation
//! lifecycle only (`GO_RUNTIME_MANAGED_INVOCATION=PASS`). It deliberately
//! does **not** claim `WINDOWS_GO_VERTICAL=PASS`:
//! `wht_corulix_engine::go_providers`'s own `go build`/`go vet`/`go test`
//! routing (P15's canonical `SupportingOnly`/authoritative-tests split)
//! does not yet resolve either platform's managed Go runtime at all -- it
//! resolves `go` through the pre-existing `HOST_ONLY`/system provider
//! precedence only. Wiring that routing to a `managed_go_semantic_runtime`-
//! style resolution (the way `LspProviderProfile::gopls_managed()` already
//! does for the LSP path) is real, disclosed follow-up work this file does
//! not perform. This file therefore invokes the managed `go`/`gofmt`
//! binaries directly via `wht_corulix_tooling::execute`, exactly the same
//! evidentiary shape `real_rust_analyzer_managed_lifecycle_e2e.rs` already
//! established for a managed binary's own `--version` proof -- never a
//! bypass of the *provisioning* pipeline, only of the not-yet-built
//! product-routing layer that does not exist yet for Go.
//!
//! Provisions the real, unmodified, real-network production manifest
//! (`go.dev/dl/...`) into an isolated, throwaway managed root -- never the
//! shared host-wide `managed_toolchain_root()`. `MOCKED_ONLY_CLOSURE=NO`.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_core::{CancellationToken, ExecutionClass};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState, uninstall};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, execute};

const GO_RUNTIME_ID: &str = "go-semantic-runtime";

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

/// This host's own real `go-semantic-runtime` manifest. Both arms are the
/// real, unmodified, pinned public constants -- see
/// `real_rust_analyzer_managed_lsp_semantic_cycle_e2e.rs`'s own identical
/// rationale for why this duplicates only the `cfg` selection, not the
/// manifest identity.
#[cfg(target_os = "windows")]
fn host_native_go_runtime_manifest() -> provisioning::ManagedComponentManifest {
    wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_WINDOWS_X64
}
#[cfg(not(target_os = "windows"))]
fn host_native_go_runtime_manifest() -> provisioning::ManagedComponentManifest {
    wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64
}

fn isolated_root(label: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/root".to_string());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = PathBuf::from(home)
        .join(".cache/corulix-go-runtime-managed-invocation-e2e/roots")
        .join(format!("{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// A real, dependency-free Go module: one file, one function, one test --
/// enough to prove `go build`/`go test` genuinely compile and execute
/// through the managed toolchain, not merely that `go version` prints a
/// string.
fn go_module_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!(
        "corulix-go-runtime-managed-invocation-e2e-{label}-{stamp}"
    ));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix.example/go-runtime-managed-invocation-fixture\n\ngo 1.22\n",
    );
    let _ = fs::write(
        root.join("greeting.go"),
        "package main\n\nfunc greeting() string {\n\treturn \"hello\"\n}\n\nfunc main() {\n\tprintln(greeting())\n}\n",
    );
    let _ = fs::write(
        root.join("greeting_test.go"),
        "package main\n\nimport \"testing\"\n\nfunc TestGreeting(t *testing.T) {\n\tif greeting() != \"hello\" {\n\t\tt.Fatalf(\"unexpected greeting: %q\", greeting())\n\t}\n}\n",
    );
    root
}

/// Provision -> environment-authority proof -> real `go version` -> real
/// `go build`/`go test` against a real fixture -> uninstall -> zero
/// residual. No LSP/session involved -- this is the bare managed-runtime
/// vertical, not the (separately, not-yet-wired) `go_providers`/gopls
/// product routing.
#[tokio::test]
async fn real_go_semantic_runtime_managed_provision_invoke_uninstall_lifecycle()
-> Result<(), Box<dyn Error>> {
    let root = isolated_root("invocation");
    let manifest = host_native_go_runtime_manifest();

    let provision_result = provisioning::provision(&root, &manifest).await;
    let Ok(go_binary) = provision_result else {
        eprintln!(
            "GO_RUNTIME_MANAGED_INVOCATION=BLOCKED_PROVIDER_NOT_PROVISIONED ({:?})",
            provision_result.err()
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    };

    // --- ENVIRONMENT AUTHORITY: the resolved go binary must be inside the
    // isolated managed root, never a system path. ---
    if !go_binary.starts_with(&root) {
        return Err(fail(format!(
            "expected the managed go binary under {root:?}, got {go_binary:?}"
        )));
    }
    eprintln!("GO_RUNTIME_PROVIDER_AUTHORITY=CORULIX_MANAGED");

    let bin_dir = go_binary
        .parent()
        .ok_or_else(|| fail("resolved go binary has no parent directory"))?;
    let goroot = bin_dir
        .parent()
        .ok_or_else(|| fail("resolved go bin/ has no parent directory (GOROOT)"))?;
    if !goroot.starts_with(&root) {
        return Err(fail(format!(
            "expected GOROOT under {root:?}, got {goroot:?} -- SYSTEM_GOROOT_AUTHORITY leaked"
        )));
    }
    eprintln!("GOROOT_AUTHORITY=CORULIX_MANAGED");
    eprintln!("SYSTEM_GOROOT_AUTHORITY=NO");

    let scratch_home = root.join(".corulix-scratch-home-go-invocation");
    let scratch_gopath = scratch_home.join("gopath");
    let scratch_gocache = scratch_home.join("gocache");
    let _ = fs::create_dir_all(&scratch_gopath);
    let _ = fs::create_dir_all(&scratch_gocache);
    let env = EnvironmentPolicy::empty()
        .with_var("GOROOT", goroot.to_string_lossy().into_owned())
        .with_var("GOPATH", scratch_gopath.to_string_lossy().into_owned())
        .with_var("GOCACHE", scratch_gocache.to_string_lossy().into_owned())
        .with_var("HOME", scratch_home.to_string_lossy().into_owned())
        .with_var("GOFLAGS", "-mod=mod".to_string())
        .with_var("GOPROXY", "off".to_string())
        .with_var("GOTOOLCHAIN", "local".to_string())
        .with_var("PATH", bin_dir.to_string_lossy().into_owned());

    // --- REAL `go version` ---
    let version_outcome = execute(
        &ProcessSpec {
            executable: go_binary.clone(),
            arguments: vec!["version".to_string()],
            environment: env.clone(),
            working_directory: root.clone(),
            limits: ProcessLimits::default(),
            timeout: Duration::from_secs(20),
            execution_class: ExecutionClass::ControlledExternalTool,
            argv0: None,
        },
        &CancellationToken::new(),
    )
    .await;
    let version_stdout = String::from_utf8_lossy(&version_outcome.stdout.bytes);
    if !version_stdout.contains("go1.27.0") {
        return Err(fail(format!(
            "expected managed 'go version' to report go1.27.0, got {version_stdout:?} (termination: {:?})",
            version_outcome.termination
        )));
    }
    eprintln!(
        "GO_RUNTIME_VERSION_INVOCATION=PASS ({})",
        version_stdout.trim()
    );

    // --- REAL `go build` against a real fixture module ---
    let fixture = go_module_fixture("invocation");
    let build_outcome = execute(
        &ProcessSpec {
            executable: go_binary.clone(),
            arguments: vec!["build".to_string(), "./...".to_string()],
            environment: env.clone(),
            working_directory: fixture.clone(),
            limits: ProcessLimits::default(),
            timeout: Duration::from_secs(120),
            execution_class: ExecutionClass::ControlledExternalTool,
            argv0: None,
        },
        &CancellationToken::new(),
    )
    .await;
    if !matches!(
        build_outcome.termination,
        wht_corulix_tooling::TerminationReason::Exited { code: 0 }
    ) {
        return Err(fail(format!(
            "expected managed 'go build' to exit 0, got termination={:?} stderr={:?}",
            build_outcome.termination,
            String::from_utf8_lossy(&build_outcome.stderr.bytes)
        )));
    }
    eprintln!("GO_RUNTIME_BUILD_INVOCATION=PASS");

    // --- REAL `go test` against the same fixture ---
    let test_outcome = execute(
        &ProcessSpec {
            executable: go_binary.clone(),
            arguments: vec!["test".to_string(), "./...".to_string()],
            environment: env,
            working_directory: fixture.clone(),
            limits: ProcessLimits::default(),
            timeout: Duration::from_secs(120),
            execution_class: ExecutionClass::ControlledExternalTool,
            argv0: None,
        },
        &CancellationToken::new(),
    )
    .await;
    if !matches!(
        test_outcome.termination,
        wht_corulix_tooling::TerminationReason::Exited { code: 0 }
    ) {
        return Err(fail(format!(
            "expected managed 'go test' to exit 0, got termination={:?} stdout={:?} stderr={:?}",
            test_outcome.termination,
            String::from_utf8_lossy(&test_outcome.stdout.bytes),
            String::from_utf8_lossy(&test_outcome.stderr.bytes)
        )));
    }
    let test_stdout = String::from_utf8_lossy(&test_outcome.stdout.bytes);
    if !test_stdout.contains("ok") {
        return Err(fail(format!(
            "expected 'go test' stdout to report ok, got {test_stdout:?}"
        )));
    }
    eprintln!("GO_RUNTIME_TEST_INVOCATION=PASS");
    eprintln!("GO_RUNTIME_MANAGED_INVOCATION=PASS");
    let _ = fs::remove_dir_all(&fixture);

    // --- UNINSTALL / ZERO RESIDUAL ---
    let removed = uninstall::uninstall(
        &root,
        provisioning::ManagedComponentId(GO_RUNTIME_ID),
        |_| {},
    )
    .await;
    if removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected go-semantic-runtime uninstall to succeed, got {removed:?}"
        )));
    }
    let (state_after, _) = provisioning::resolve_managed_component(&root, &manifest);
    if state_after != ManagedComponentState::NotProvisioned {
        return Err(fail(format!(
            "expected NotProvisioned after uninstall, got {state_after:?}"
        )));
    }
    eprintln!("GO_RUNTIME_MANAGED_UNINSTALL=PASS");

    let _ = fs::remove_dir_all(&root);
    Ok(())
}
