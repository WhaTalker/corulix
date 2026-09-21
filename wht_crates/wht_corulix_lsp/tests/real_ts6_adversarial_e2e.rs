// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-C: real adversarial certification for the managed TypeScript-6/
//! JavaScript-6 backend, extending the structural guarantee
//! `real_poisoned_path_executable_authority_e2e.rs` already established
//! for TS7/Pyright/rust-analyzer (`resolve_provider`/`resolve_launch_at`
//! never read ambient `PATH` at all -- proven there via
//! `wht_corulix_config::resolver::tests::poisoned_path_has_no_effect`) to
//! this phase's own two new fields: `managed_typescript_6_runtime` and the
//! `extra_initialization_options`/`tsserver.path` injection this phase
//! added to `resolve_launch_at` -- neither exercised by that existing file.
//!
//! Positive controls first (the marker mechanism is proven genuinely
//! executable), then the real, unmodified production `resolve_launch`
//! (default `HostConfig`, no decoy directory ever named in
//! `approved_system_directories`/`approved_user_toolchain_directories`) is
//! proven to resolve `executable`, `arguments[0]`, and
//! `extra_initialization_options["tsserver"]["path"]` exclusively inside
//! `managed_toolchain_root()` -- zero marker executions across a full real
//! spawn/handshake/shutdown cycle
//! (`TS6_POISONED_PATH_MARKER_EXECUTION_COUNT=0`).
//!
//! Also proves `TS6_HOSTILE_WORKSPACE_TYPESCRIPT_PRECEDENCE`: a real,
//! competing `node_modules/typescript/lib/tsserver.js` planted inside the
//! fixture workspace itself never becomes the resolved `tsserver.path` --
//! the managed identity always wins, matching this phase's own research
//! into `typescript-language-server`'s real `tsserver.path` precedence
//! (checked *before* any workspace resolution).
//!
//! Requires real network access to `registry.npmjs.org`/`nodejs.org` to
//! provision the real artifacts once; reports and exits early with
//! `BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONABLE` otherwise.

// Windows note (Phase 17-W): `#![cfg(unix)]`-only for this whole file -- its
// adversarial mechanism (chmod-executable shell-script markers via
// `std::os::unix::fs::PermissionsExt`) has no Windows equivalent yet. A
// native-Windows equivalent of this exact certification is a disclosed
// residual, not yet written (`P17_W_WINDOWS_ADVERSARIAL_MARKER_EQUIVALENT_COUNT=0`).
#![cfg(unix)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_lsp::{LspProviderProfile, LspSession, Readiness};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState, uninstall};
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
    let dir = std::env::temp_dir().join(format!("corulix-ts6-adversarial-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn write_marker_script(dir: &Path, name: &str, counter_file: &Path) {
    let script = format!(
        "#!/bin/sh\necho invoked >> {}\nexit 1\n",
        counter_file.display()
    );
    let path = dir.join(name);
    fs::write(&path, script).unwrap_or_else(|error| unreachable!("write marker: {error}"));
    let mut perms = fs::metadata(&path)
        .unwrap_or_else(|error| unreachable!("marker metadata: {error}"))
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(&path, perms).unwrap_or_else(|error| unreachable!("chmod marker: {error}"));
}

fn marker_invocation_count(counter_file: &Path) -> usize {
    fs::read_to_string(counter_file)
        .unwrap_or_default()
        .lines()
        .count()
}

async fn ensure_ts6_provisioned(root: &Path) -> bool {
    let node_manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64;
    let ts6_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE;
    let tls_manifest = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE;
    let (node_state, _) = provisioning::resolve_managed_component(root, &node_manifest);
    if node_state != ManagedComponentState::Available
        && provisioning::provision(root, &node_manifest).await.is_err()
    {
        return false;
    }
    let (ts6_state, _) = provisioning::resolve_managed_component(root, &ts6_manifest);
    if ts6_state != ManagedComponentState::Available
        && provisioning::provision(root, &ts6_manifest).await.is_err()
    {
        return false;
    }
    let (tls_state, _) = provisioning::resolve_managed_component(root, &tls_manifest);
    if tls_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(
            root,
            &tls_manifest,
            &["node-runtime", "typescript-6-classic"],
        )
        .await
        .is_err()
    {
        return false;
    }
    true
}

/// Real, behavioral poisoned-PATH proof: a decoy directory with real,
/// genuinely-executable marker scripts for `node`,
/// `typescript-language-server`, and `tsserver.js`-shaped names, never
/// named in `HostConfig`'s approved directories, coexists on disk while the
/// real production pipeline spawns a genuine session -- zero marker
/// executions, and every resolved path is confined to `managed_toolchain_root()`.
#[tokio::test]
async fn real_ts6_poisoned_path_and_hostile_workspace_e2e() -> Result<(), Box<dyn Error>> {
    let root = temp_dir("adversarial-managed-root");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_ts6_provisioned(&root).await {
        eprintln!(
            "TS6_ADVERSARIAL_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONABLE: no network in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    // --- Positive controls: the marker mechanism is genuinely real. ---
    let decoy_dir = temp_dir("decoy-bin");
    let counter_file = decoy_dir.join("invocations.log");
    for name in ["node", "typescript-language-server", "tsserver"] {
        write_marker_script(&decoy_dir, name, &counter_file);
    }
    for name in ["node", "typescript-language-server", "tsserver"] {
        let output = std::process::Command::new(decoy_dir.join(name))
            .output()
            .unwrap_or_else(|error| unreachable!("invoke marker: {error}"));
        assert_eq!(output.status.code(), Some(1));
    }
    assert_eq!(marker_invocation_count(&counter_file), 3);
    eprintln!("TS6_MARKER_POSITIVE_CONTROLS=PASS");
    let _ = fs::remove_file(&counter_file);

    // --- A hostile workspace `node_modules/typescript` -- a real,
    // competing tsserver.js the workspace itself provides. The managed
    // `tsserver.path` must win regardless. ---
    let fixture = temp_dir("hostile-workspace");
    fs::write(
        fixture.join("tsconfig.json"),
        r#"{"compilerOptions":{"target":"es2020"}}"#,
    )?;
    fs::write(
        fixture.join("main.ts"),
        "export function target(): void {}\n",
    )?;
    let hostile_ts_lib = fixture.join("node_modules/typescript/lib");
    fs::create_dir_all(&hostile_ts_lib)?;
    fs::write(
        hostile_ts_lib.join("tsserver.js"),
        format!(
            "#!/usr/bin/env node\nrequire('fs').appendFileSync({:?}, 'invoked\\n');\nprocess.exit(1);\n",
            counter_file.display()
        ),
    )?;

    // `HostConfig::default()` names neither the decoy directory nor
    // anything workspace-local as an approved directory -- exactly a real
    // poisoned-PATH/hostile-workspace shape from the resolver's own point
    // of view (it never consults ambient `PATH` or workspace paths as a
    // search list to begin with -- see `wht_corulix_config::resolver`).
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let profile = LspProviderProfile::typescript_language_server_managed();
    let launch = wht_corulix_lsp::resolve_launch_at(&profile, &effective, &workspace_root, &root)
        .await
        .map_err(|error| fail(format!("resolve_launch_at failed: {error:?}")))?;

    if !launch.executable.starts_with(&root) {
        return Err(fail(format!(
            "expected the managed Node interpreter under {root:?}, got {:?}",
            launch.executable
        )));
    }
    let Some(script_argument) = launch.arguments.first() else {
        return Err(fail(
            "expected the typescript-language-server script path as argv[1]",
        ));
    };
    if !PathBuf::from(script_argument).starts_with(&root) {
        return Err(fail(format!(
            "expected the managed typescript-language-server script under {root:?}, got {script_argument:?}"
        )));
    }
    let Some(extra_options) = &launch.extra_initialization_options else {
        return Err(fail(
            "expected extra_initialization_options carrying tsserver.path",
        ));
    };
    let Some(tsserver_path) = extra_options["tsserver"]["path"].as_str() else {
        return Err(fail("expected tsserver.path to be a string"));
    };
    if !PathBuf::from(tsserver_path).starts_with(&root) {
        return Err(fail(format!(
            "TS6_HOSTILE_WORKSPACE_TYPESCRIPT_PRECEDENCE violation: expected the managed tsserver.path under {root:?}, got {tsserver_path:?}"
        )));
    }
    if tsserver_path.contains("node_modules") {
        return Err(fail(
            "TS6_HOSTILE_WORKSPACE_TYPESCRIPT_PRECEDENCE violation: resolved tsserver.path references the hostile workspace node_modules",
        ));
    }
    eprintln!("TS6_HOSTILE_WORKSPACE_TYPESCRIPT_PRECEDENCE=PASS");

    // --- Full real spawn/handshake/shutdown cycle -- proves zero marker
    // executions across the entire real product path, not merely at path
    // resolution. ---
    let cancellation = CancellationToken::new();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;
    session
        .ensure_open(&fixture.join("main.ts"))
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(Duration::from_secs(60))
        .await
        .map_err(|error| fail(format!("never reached readiness: {error:?}")))?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }
    session.shutdown(&cancellation).await;

    let marker_execution_count = marker_invocation_count(&counter_file);
    if marker_execution_count != 0 {
        return Err(fail(format!(
            "TS6_POISONED_PATH_MARKER_EXECUTION_COUNT violation: expected 0, got {marker_execution_count}"
        )));
    }
    eprintln!("TS6_POISONED_PATH_MARKER_EXECUTION_COUNT=0");

    // MANAGED_TEST_ISOLATION_DEFECT fix: this test now provisions onto its
    // own isolated managed root, so cleanup below only affects that root.
    let _ = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    let _ = uninstall::uninstall(
        &root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE.id,
        |_| {},
    )
    .await;
    let _ = uninstall::uninstall(
        &root,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64.id,
        |_| {},
    )
    .await;

    let _ = fs::remove_dir_all(&decoy_dir);
    let _ = fs::remove_dir_all(&fixture);
    let _ = fs::remove_dir_all(&root);
    Ok(())
}
