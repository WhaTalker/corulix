// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof of the P17-W `gopls` distribution-model migration:
//! `wht_corulix_tooling::provisioning::provision_go_module_build` building a
//! real `gopls@v0.23.0` binary from real Go module source
//! (`golang.org/x/tools/gopls`), via a real, previously-provisioned Corulix
//! managed Go compiler (`GO_SEMANTIC_RUNTIME_HOST_NATIVE`), against the real
//! `proxy.golang.org`/`sum.golang.org` module proxy and checksum database --
//! no local mirror, no synthetic fixture, no `.with_managed_component`
//! override. This supersedes `real_gopls_managed_e2e.rs`'s own
//! download-model premise for the specific claim "gopls is provisionable
//! through its real official distribution model" -- that file's own local
//! HTTP mirror still exercises the *download* pipeline correctly for other
//! components, it is simply no longer how this workspace's own `gopls`
//! product manifest is provisioned.
//!
//! Real network dependency (both `go.dev` for the compiler and
//! `proxy.golang.org`/`sum.golang.org` for the build) -- this file reports
//! `SKIPPED: NO_NETWORK` rather than fabricating a result if the initial
//! reachability probe fails, exactly like this crate's other real E2E files
//! degrade under a genuinely unreachable environment.
//!
//! **Hostile-PATH resistance is not exercised as a live poisoned-environment
//! scenario here.** `provision_go_module_build_blocking`'s child `Command`
//! is built with `env_clear()` followed only by explicit typed `env(...)`
//! calls, and invokes the compiler exclusively by its own already-verified
//! absolute path -- never a `PATH`-based lookup of the literal name
//! `"go"`/`"gopls"` (see that function's own doc comment). This workspace
//! forbids `unsafe` code, and `std::env::set_var` is `unsafe` as of the 2024
//! edition, so this file does not mutate this test process's own ambient
//! `PATH` to "prove" resistance a poisoned *parent* environment could never
//! actually exercise anyway: the child process never inherits or consults
//! it, by construction -- the same rationale
//! `real_poisoned_path_executable_authority_e2e.rs` documents for this
//! crate's other managed providers.
//!
//! This workspace denies `clippy::expect_used`/`clippy::unwrap_used`/
//! `clippy::panic` even in test code, so this test returns
//! `Result<(), Box<dyn Error>>` and propagates every real failure via `?`
//! (`TestFailure`/`fail(...)`, the same idiom this crate's other real E2E
//! files already use), rather than `.expect(...)` or `panic!(...)`.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_lsp::managed_toolchain::{
    GO_SEMANTIC_RUNTIME_HOST_NATIVE, GOPLS_BUILD_SOURCE_HOST_NATIVE, GOPLS_HOST_NATIVE,
};
use wht_corulix_tooling::provisioning::{
    self, GoModuleBuildSource, ManagedComponentState, ProvisioningError, full_uninstall, ownership,
    uninstall,
};

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

fn temp_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!(
        "corulix-gopls-module-build-e2e-{label}-{pid}-{stamp}"
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn network_reachable() -> bool {
    Command::new("curl")
        .args([
            "-sI",
            "--max-time",
            "10",
            "https://proxy.golang.org/golang.org/x/tools/gopls/@v/list",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// One shared, sequential test drives the whole real lifecycle against one
/// isolated root -- provisioning a real ~100MB Go compiler plus a real
/// module build is expensive enough that this file deliberately does not
/// re-provision the compiler per scenario.
#[tokio::test]
async fn real_gopls_module_build_full_lifecycle() -> Result<(), Box<dyn Error>> {
    if !network_reachable() {
        eprintln!("SKIPPED: NO_NETWORK (proxy.golang.org unreachable)");
        return Ok(());
    }

    let root = temp_root("main");

    // STAGE 1: real managed Go compiler, real download from go.dev.
    let go_path = provisioning::provision(&root, &GO_SEMANTIC_RUNTIME_HOST_NATIVE)
        .await
        .map_err(|error| {
            fail(format!(
                "real managed Go compiler must provision: {error:?}"
            ))
        })?;
    if !go_path.is_file() {
        return Err(fail("GOPLS_GO_COMPILER_MISSING"));
    }

    // STAGE 2: real gopls module build against the real, official module
    // proxy + checksum database.
    let gopls_path = provisioning::provision_go_module_build(
        &root,
        &GOPLS_HOST_NATIVE,
        &GOPLS_BUILD_SOURCE_HOST_NATIVE,
        &GO_SEMANTIC_RUNTIME_HOST_NATIVE,
    )
    .await
    .map_err(|error| fail(format!("real gopls module build must succeed: {error:?}")))?;
    if !gopls_path.is_file() {
        return Err(fail("GOPLS_BUILD_OUTPUT_MISSING"));
    }

    // The built binary must be the real thing: spawn it directly (never via
    // PATH) and confirm it reports a real gopls version string.
    let version_output = Command::new(&gopls_path)
        .arg("version")
        .output()
        .map_err(|error| fail(format!("built gopls binary must be spawnable: {error}")))?;
    if !version_output.status.success() {
        return Err(fail("GOPLS_VERSION_SPAWN_FAILED"));
    }
    let version_text = String::from_utf8_lossy(&version_output.stdout).to_lowercase();
    if !version_text.contains("gopls") && !version_text.contains("golang.org/x/tools") {
        return Err(fail(format!(
            "GOPLS_VERSION_OUTPUT_UNEXPECTED: {version_text}"
        )));
    }

    // OWNERSHIP: resolve_owned_managed_component must report Available and
    // this exact path, proving Corulix's own ownership record (not merely
    // filesystem presence) covers the source-built install.
    let (state, owned_path) =
        provisioning::resolve_owned_managed_component(&root, &GOPLS_HOST_NATIVE);
    if state != ManagedComponentState::Available {
        return Err(fail("GOPLS_NOT_OWNED_AVAILABLE"));
    }
    if owned_path.as_deref() != Some(gopls_path.as_path()) {
        return Err(fail("GOPLS_OWNED_PATH_MISMATCH"));
    }

    // IDEMPOTENCE: a second call must short-circuit to the exact same path
    // (no duplicate/corrupt ownership record, no second build).
    let ownership_before = ownership::load(&root, GOPLS_HOST_NATIVE.id)
        .map_err(|error| fail(format!("ownership record must load: {error:?}")))?;
    let gopls_path_again = provisioning::provision_go_module_build(
        &root,
        &GOPLS_HOST_NATIVE,
        &GOPLS_BUILD_SOURCE_HOST_NATIVE,
        &GO_SEMANTIC_RUNTIME_HOST_NATIVE,
    )
    .await
    .map_err(|error| fail(format!("idempotent re-provision must succeed: {error:?}")))?;
    if gopls_path_again != gopls_path {
        return Err(fail("GOPLS_IDEMPOTENCE_PATH_MISMATCH"));
    }
    let ownership_after = ownership::load(&root, GOPLS_HOST_NATIVE.id)
        .map_err(|error| fail(format!("ownership record must still load: {error:?}")))?;
    if ownership_before != ownership_after {
        return Err(fail("GOPLS_IDEMPOTENCE_DUPLICATE_OWNERSHIP_WRITE"));
    }

    // NEGATIVE: invalid/nonexistent module version must fail closed with no
    // ownership residue, against a throwaway root that only has the
    // compiler provisioned.
    let bad_version_root = temp_root("bad-version");
    provisioning::provision(&bad_version_root, &GO_SEMANTIC_RUNTIME_HOST_NATIVE)
        .await
        .map_err(|error| {
            fail(format!(
                "compiler must provision into the negative-matrix root too: {error:?}"
            ))
        })?;
    let bad_recipe = GoModuleBuildSource {
        module_path: "golang.org/x/tools/gopls",
        module_version: "v0.0.0-20000101000000-000000000000",
    };
    let bad_result = provisioning::provision_go_module_build(
        &bad_version_root,
        &GOPLS_HOST_NATIVE,
        &bad_recipe,
        &GO_SEMANTIC_RUNTIME_HOST_NATIVE,
    )
    .await;
    if bad_result != Err(ProvisioningError::BuildFailed) {
        return Err(fail(format!(
            "GOPLS_BAD_VERSION_NOT_REJECTED: {bad_result:?}"
        )));
    }
    let (bad_state, _) =
        provisioning::resolve_managed_component(&bad_version_root, &GOPLS_HOST_NATIVE);
    if bad_state != ManagedComponentState::NotProvisioned {
        return Err(fail("GOPLS_FAILED_BUILD_LEFT_RESIDUE"));
    }
    let bad_ownership =
        ownership::load(&bad_version_root, GOPLS_HOST_NATIVE.id).map_err(|error| {
            fail(format!(
                "ownership load must not error on absence: {error:?}"
            ))
        })?;
    if bad_ownership.is_some() {
        return Err(fail("GOPLS_FAILED_BUILD_WROTE_OWNERSHIP"));
    }

    // NEGATIVE: compiler dependency not available (fresh root, compiler
    // never provisioned) must fail closed before any build attempt.
    let no_compiler_root = temp_root("no-compiler");
    let dep_result = provisioning::provision_go_module_build(
        &no_compiler_root,
        &GOPLS_HOST_NATIVE,
        &GOPLS_BUILD_SOURCE_HOST_NATIVE,
        &GO_SEMANTIC_RUNTIME_HOST_NATIVE,
    )
    .await;
    if dep_result != Err(ProvisioningError::DependencyNotAvailable) {
        return Err(fail(format!(
            "GOPLS_MISSING_COMPILER_NOT_REJECTED: {dep_result:?}"
        )));
    }

    // UNINSTALL: gopls first (dependent), then the compiler -- proving the
    // dependency edge this build recorded is real and enforced.
    uninstall::uninstall(&root, GOPLS_HOST_NATIVE.id, |_| {})
        .await
        .map_err(|error| fail(format!("gopls uninstall must succeed: {error:?}")))?;
    let (post_uninstall_state, _) =
        provisioning::resolve_managed_component(&root, &GOPLS_HOST_NATIVE);
    if post_uninstall_state != ManagedComponentState::NotProvisioned {
        return Err(fail("GOPLS_UNINSTALL_LEFT_RESIDUE"));
    }

    full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("FULL_UNINSTALL_FAILED: {error:?}")))?;

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&bad_version_root);
    let _ = std::fs::remove_dir_all(&no_compiler_root);

    Ok(())
}
