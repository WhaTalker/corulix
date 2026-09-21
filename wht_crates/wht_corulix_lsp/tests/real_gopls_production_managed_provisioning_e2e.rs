// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof that the production `gopls` resolution path --
//! `wht_corulix_lsp::resolve_launch_at` against `LspProviderProfile::gopls_managed()`,
//! never `provisioning::provision_go_module_build` called directly -- now
//! genuinely reaches real managed acquisition (Installation-Contract-V1's
//! own `GOPLS_PRODUCTION_ACQUISITION_UNREACHABLE` fix).
//!
//! **The defect this closes.** `GOPLS_LINUX_X64`/`GOPLS_WINDOWS_X64`'s
//! `source.tarball_url` is an inert sentinel
//! (`"unused:go-module-build-see-GOPLS_BUILD_SOURCE_..."`); the real
//! acquisition mechanism is `provisioning::provision_go_module_build`
//! against `GOPLS_BUILD_SOURCE_HOST_NATIVE`. Before this fix,
//! `resolve_or_acquire_if_allowed` (the one call site every other managed
//! component's production acquisition funnels through) called the generic
//! download pipeline for `gopls` exactly like every other component,
//! guaranteeing failure regardless of install profile or `HostConfig`
//! policy -- gopls could never become `FULL_PROFILE_READY` through any real
//! production code path, only through this crate's own test-only direct
//! call to `provision_go_module_build`
//! (`real_gopls_module_build_lifecycle_e2e.rs`). The fix teaches
//! `resolve_managed_or_system_path` to dispatch `gopls`'s own manifest
//! identity to a dedicated sibling
//! (`resolve_or_acquire_gopls_via_module_build_if_allowed`) that calls the
//! real module-build primitive instead -- this file proves that dispatch is
//! genuinely wired, not merely present in source.
//!
//! Real network dependency (both `go.dev` for the managed Go compiler
//! dependency and `proxy.golang.org`/`sum.golang.org` for the `gopls`
//! module build itself) -- reports `SKIPPED: NO_NETWORK` rather than
//! fabricating a result if the initial reachability probe fails, mirroring
//! `real_gopls_module_build_lifecycle_e2e.rs`'s own convention.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{
    EffectiveConfig, HostConfig, ManagedProvisioningPolicy, RepositoryHints, RequestOptions,
};
use wht_corulix_lsp::LspProviderProfile;
use wht_corulix_tooling::provisioning::full_uninstall;
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

fn temp_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!(
        "corulix-gopls-production-managed-e2e-{label}-{pid}-{stamp}"
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

/// Explicit `Allow` rather than a persisted install profile
/// (`HostConfig::default()`'s `Inherit`): this test proves the acquisition
/// dispatch itself, deterministically, independent of whatever install
/// profile any other test or real invocation happens to have left behind
/// under this isolated root.
fn permissive_effective_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig {
            managed_provisioning_policy: ManagedProvisioningPolicy::Allow,
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

#[tokio::test]
async fn real_gopls_production_resolve_launch_reaches_real_module_build_acquisition()
-> Result<(), Box<dyn Error>> {
    if !network_reachable() {
        eprintln!("SKIPPED: NO_NETWORK (proxy.golang.org unreachable)");
        return Ok(());
    }

    let root = temp_root("managed-root");
    let workspace_dir = temp_root("workspace");
    std::fs::write(
        workspace_dir.join("main.go"),
        "package main\n\nfunc main() {}\n",
    )
    .map_err(|error| fail(format!("fixture write must succeed: {error}")))?;
    let workspace_root = WorkspaceRoot::open(&workspace_dir)
        .map_err(|error| fail(format!("workspace root must open: {error:?}")))?;

    let effective = permissive_effective_config();
    let profile = LspProviderProfile::gopls_managed();

    let launch = wht_corulix_lsp::resolve_launch_at(&profile, &effective, &workspace_root, &root)
        .await
        .map_err(|error| {
            fail(format!(
                "resolve_launch_at(gopls_managed) must reach real production acquisition, got: \
                 {error:?}"
            ))
        })?;

    if !launch.executable.starts_with(&root) {
        return Err(fail(format!(
            "expected the real managed gopls executable under {root:?}, got {:?}",
            launch.executable
        )));
    }
    if !launch.executable.is_file() {
        return Err(fail("GOPLS_PRODUCTION_ACQUISITION_EXECUTABLE_MISSING"));
    }
    if launch.managed_lease.is_none() {
        return Err(fail(
            "expected a managed lease binding for a genuinely CORULIX_MANAGED gopls session",
        ));
    }

    let version_output = Command::new(&launch.executable)
        .arg("version")
        .output()
        .map_err(|error| fail(format!("built gopls binary must be spawnable: {error}")))?;
    if !version_output.status.success() {
        return Err(fail("GOPLS_PRODUCTION_VERSION_SPAWN_FAILED"));
    }
    let version_text = String::from_utf8_lossy(&version_output.stdout).to_lowercase();
    if !version_text.contains("gopls") && !version_text.contains("golang.org/x/tools") {
        return Err(fail(format!(
            "GOPLS_PRODUCTION_VERSION_OUTPUT_UNEXPECTED: {version_text}"
        )));
    }

    eprintln!("GOPLS_PRODUCTION_ACQUISITION_UNREACHABLE=FIXED");

    let _ = full_uninstall::uninstall_all_corulix_managed_components_at(&root).await;
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&workspace_dir);
    Ok(())
}
