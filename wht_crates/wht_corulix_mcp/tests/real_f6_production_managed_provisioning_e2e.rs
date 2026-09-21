// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! F6 fix (`F6_PRODUCTION_MANAGED_PROVISIONING_UNREACHABLE`) + Installation-Contract-V1
//! authority model: real, positive-path proof that a genuine
//! `semantic`/`format_preview` MCP call against a component that is
//! genuinely absent from an isolated managed root triggers real
//! Corulix-managed acquisition -- never a direct, test-only call into
//! `wht_corulix_tooling::provisioning::provision_with_dependencies`.
//!
//! **This is deliberately NOT the same shape as
//! `real_p13_mcp_managed_provider_isolated_e2e.rs`'s own tests**: those
//! pre-provision an isolated root via direct internal calls *before*
//! spawning the MCP process, then prove the MCP tool correctly *resolves*
//! an already-present component -- proving resolution, not acquisition.
//! The two positive tests below spawn the real compiled `corulix mcp stdio`
//! binary against a genuinely empty isolated root and make exactly one real
//! tool call; before the F6 fix, that call returned
//! `REQUIRED_PROVIDER_UNAVAILABLE` immediately (root cause: no production
//! code path called `provision_with_dependencies` at all). After the fix,
//! the same call must genuinely download, verify, and activate the
//! required managed component(s), then succeed.
//!
//! Same real transport as `real_p13_mcp_managed_provider_isolated_e2e.rs`
//! (`cargo run -p corulix -- mcp stdio`, real `rmcp` stdio client, an
//! isolated, disposable directory redirected via `XDG_DATA_HOME`/
//! `LOCALAPPDATA`/`APPDATA` -- see [`spawn_real_corulix_mcp_stdio`]'s own
//! doc comment for why all three, not just `XDG_DATA_HOME` -- so this
//! test's own real network provisioning never pollutes the real, shared,
//! host-wide managed root other tests assume is empty).
//!
//! # Authority model (Installation-Contract-V1)
//!
//! `DEFAULT_INSTALL_PROFILE=FULL`: a real `corulix mcp stdio` process
//! started with no `--host-config` at all runs `FIRST_RUN_RECONCILIATION`
//! at bootstrap (`install_profile::ensure_bootstrapped`), which persists
//! `InstallProfile::Full` the first time it ever sees this isolated managed
//! root -- so the two positive tests below need **no host-config file at
//! all** to prove real acquisition: this *is* the product's advertised
//! default experience, not an opt-in. `HostConfig`'s
//! `ManagedProvisioningPolicy` can still override that default in either
//! direction (`Deny` always wins, `Allow` always wins, `Inherit` is the
//! real default and defers to the persisted profile) -- the negative tests
//! below prove the `Deny` override survives both a bootstrapped `Full`
//! profile and an explicitly persisted `OnDemand` one (`HOST_DENY_FULL_PROFILE`,
//! `HOST_DENY_ON_DEMAND_PROFILE`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use tokio::process::Command;
use wht_corulix_tooling::provisioning::install_profile::{self, InstallProfile};

fn temp_root(label: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-f6-provisioning-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

/// A real `--host-config` file with an explicit `managed_provisioning_policy
/// = "DENY"` -- the one HostConfig setting that must override any persisted
/// install profile, however permissive.
fn host_config_denying_managed_provisioning(dir: &Path) -> PathBuf {
    let path = dir.join("host.toml");
    let _ = std::fs::write(&path, "managed_provisioning_policy = \"DENY\"\n");
    path
}

/// Real, unauthenticated TCP reachability probe -- not a Corulix
/// provisioning attempt of any kind, just proof this environment has real
/// internet access before spending a whole test on a network condition
/// this file does not exist to test. Mirrors the "skip and disclose,
/// never fail" convention every other real-network E2E in this workspace
/// already follows.
fn real_network_reachable() -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = "registry.npmjs.org:443".to_socket_addrs() else {
        return false;
    };
    addrs.any(|addr| std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok())
}

/// Same real spawn recipe as
/// `real_p13_mcp_managed_provider_isolated_e2e.rs::spawn_real_corulix_mcp_stdio`
/// (duplicated rather than shared -- each file under `tests/` compiles as
/// an independent crate). `host_config` is appended as `--host-config
/// <path>` only when given -- its absence is itself the scenario the two
/// positive tests below exist to prove (default `FULL`, no operator opt-in
/// required).
///
/// Isolates the spawned process via `XDG_DATA_HOME`/`LOCALAPPDATA`/`APPDATA`
/// all set to `isolated_data_home`, not `XDG_DATA_HOME` alone:
/// `managed_toolchain_root()` never reads `XDG_DATA_HOME` on Windows
/// (`LOCALAPPDATA`, falling back to `APPDATA`, is that platform's actual
/// resolution) -- a Unix-only override silently falls through to the real,
/// shared, host-wide managed root on native Windows. Confirmed the hard
/// way: a real native Windows run of this exact function, before this fix,
/// persisted a real install-profile write into that shared root (`corulix
/// mcp stdio` startup unconditionally runs `FIRST_RUN_RECONCILIATION`/
/// `ensure_bootstrapped` against whatever root it resolves), which then
/// compounded into the two "genuinely absent" provisioning tests below
/// failing too, since the shared root was no longer in the fresh state they
/// require. All three vars are harmless on platforms that don't consult
/// them.
async fn spawn_real_corulix_mcp_stdio(
    workspace_dir: &std::path::Path,
    isolated_data_home: &std::path::Path,
    host_config: Option<&std::path::Path>,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>, Box<dyn std::error::Error>>
{
    let host_config = host_config.map(Path::to_path_buf);
    let command = Command::new("cargo").configure(|cmd| {
        cmd.arg("run")
            .arg("--quiet")
            .arg("--locked")
            .arg("-p")
            .arg("corulix")
            .arg("--")
            .arg("mcp")
            .arg("stdio")
            .arg("--workspace")
            .arg(workspace_dir)
            .env("XDG_DATA_HOME", isolated_data_home)
            .env("LOCALAPPDATA", isolated_data_home)
            .env("APPDATA", isolated_data_home);
        if let Some(host_config) = &host_config {
            cmd.arg("--host-config").arg(host_config);
        }
    });
    let transport = TokioChildProcess::new(command)?;
    let client_info = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::from_build_env(),
    );
    Ok(client_info.serve(transport).await?)
}

async fn call_real_tool(
    service: &rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>,
    tool_name: &'static str,
    arguments: serde_json::Value,
) -> Result<CallToolResult, Box<dyn std::error::Error>> {
    let serde_json::Value::Object(arguments) = arguments else {
        unreachable!("every call site in this suite passes a JSON object");
    };
    let params = CallToolRequestParams::new(tool_name).with_arguments(arguments);
    Ok(service.call_tool(params).await?)
}

fn structured(result: &CallToolResult) -> &serde_json::Value {
    let Some(value) = result.structured_content.as_ref() else {
        unreachable!("every tool result in this suite carries structuredContent");
    };
    value
}

/// Real, non-vacuous TS6 fixture requiring genuine cross-file resolution
/// (`caller` -> `target` via an `import` from a sibling file) -- the same
/// shape `real_typescript_6_managed_e2e.rs`'s own fixture uses, so a
/// silent TS7 fallback (which has nothing provisioned in this isolated
/// root) cannot accidentally satisfy this call.
fn ts6_fixture() -> PathBuf {
    let root = temp_root("ts6");
    let _ = std::fs::write(
        root.join("package.json"),
        r#"{"name":"corulix-f6-ts6-fixture","private":true,"devDependencies":{"typescript":"6.0.3"}}"#,
    );
    let _ = std::fs::write(
        root.join("tsconfig.json"),
        r#"{"compilerOptions":{"target":"es2020","module":"es2020","moduleResolution":"bundler"}}"#,
    );
    let _ = std::fs::write(
        root.join("lib.ts"),
        "export function target() {\n  return 1;\n}\n",
    );
    let _ = std::fs::write(
        root.join("main.ts"),
        "import { target } from './lib';\n\nexport function caller() {\n  return target();\n}\n",
    );
    root
}

/// Asserts an isolated managed root's `components/` directory is genuinely
/// empty (never pre-provisioned, and never touched by a persisted-profile
/// write, which lives at the managed-root level rather than inside
/// `components/`).
fn assert_components_dir_empty(managed_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        !managed_root.join("components").exists()
            || std::fs::read_dir(managed_root.join("components"))?
                .next()
                .is_none(),
        "F6 test precondition violated: managed root must start empty"
    );
    Ok(())
}

#[tokio::test]
async fn real_f6_ts6_semantic_definition_triggers_production_managed_provisioning_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    if !real_network_reachable() {
        eprintln!(
            "SKIPPED real_f6_ts6_semantic_definition_triggers_production_managed_provisioning_e2e: \
             no real internet access in this environment"
        );
        return Ok(());
    }

    let isolated_data_home = temp_root("ts6-xdg-data-home");
    let managed_root = isolated_data_home.join("corulix").join("managed-toolchain");

    // F6 precondition: genuinely absent, never pre-provisioned by this
    // test -- the whole point is that the MCP call below must be the one
    // real acquisition trigger. No `--host-config` is passed: this proves
    // `DEFAULT_INSTALL_PROFILE=FULL` reaches real acquisition with zero
    // operator configuration, via this process's own `FIRST_RUN_RECONCILIATION`
    // bootstrap.
    assert_components_dir_empty(&managed_root)?;

    let workspace_dir = ts6_fixture();
    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, None).await?;

    let result = call_real_tool(
        &service,
        "semantic",
        serde_json::json!({
            "operation": "definition",
            "language": "type_script",
            "path": "main.ts",
            "line_zero_based": 3,
            "byte_column_zero_based": 9,
            "byte_offset": 69,
        }),
    )
    .await?;

    let payload = structured(&result).clone();
    // Windows note (M09/D96): TypeScript's `semantic(definition)` resolves
    // through the same workspace-bound `typescript-language-server`
    // `LspSession::spawn` path already established to fail closed on
    // Windows (`ManagedProcess::spawn_with_workspace_root`, no
    // `fchdir`-equivalent primitive to preserve object-bound cwd across
    // `exec`) -- the same accepted, `FINAL_CLOSED` M09 contract already on
    // record ("Windows: workspace-bound LSP UNAVAILABLE_FAIL_CLOSED, zero
    // provider spawn"). Real production-managed provisioning (the acquisition
    // this test exists to prove) still runs and still populates the managed
    // root -- provisioning and the later session spawn are separate steps --
    // so the component-acquisition proof below is unaffected; only the
    // operation's own result differs by platform.
    #[cfg(target_os = "windows")]
    {
        assert_eq!(
            result.is_error,
            Some(true),
            "F6/Windows: expected semantic(definition) to fail closed via the accepted \
             workspace-bound LSP contract, got: {payload}"
        );
        assert_eq!(
            payload["operation"], "definition",
            "F6/Windows: expected operation=definition in the fail-closed payload, got: {payload}"
        );
        assert_eq!(
            payload["status"], "unavailable",
            "F6/Windows: expected status=unavailable in the fail-closed payload, got: {payload}"
        );
        assert_eq!(
            payload["reason_code"], "REQUIRED_PROVIDER_UNAVAILABLE",
            "F6/Windows: expected reason_code=REQUIRED_PROVIDER_UNAVAILABLE, got: {payload}"
        );
    }
    #[cfg(not(target_os = "windows"))]
    assert_eq!(
        result.is_error,
        Some(false),
        "F6 regression: expected semantic(definition) to succeed via real production \
         managed provisioning against a genuinely absent TS6 stack, got: {payload}"
    );

    // Real acquisition proof, not merely a non-error response: the exact
    // three components this profile requires must now exist under the
    // isolated managed root that started empty above.
    let components_dir = managed_root.join("components");
    let component_names: Vec<String> = std::fs::read_dir(&components_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    for expected in [
        "typescript-6-classic",
        "typescript-language-server",
        "node-runtime",
    ] {
        assert!(
            component_names.iter().any(|name| name == expected),
            "F6 regression: expected managed component '{expected}' to have been \
             acquired by the semantic call, found: {component_names:?}"
        );
    }

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}

/// Real, non-vacuous Biome fixture: inconsistent spacing and no trailing
/// semicolon give a genuine, non-vacuous `would_format` diff.
fn biome_fixture() -> PathBuf {
    let root = temp_root("biome");
    let _ = std::fs::write(
        root.join("main.js"),
        "function   add(a,b){\nreturn a+b\n}\n\nconsole.log(  add(2,3)  );\n",
    );
    root
}

#[tokio::test]
async fn real_f6_biome_format_preview_triggers_production_managed_provisioning_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    if !real_network_reachable() {
        eprintln!(
            "SKIPPED real_f6_biome_format_preview_triggers_production_managed_provisioning_e2e: \
             no real internet access in this environment"
        );
        return Ok(());
    }

    let isolated_data_home = temp_root("biome-xdg-data-home");
    let managed_root = isolated_data_home.join("corulix").join("managed-toolchain");

    assert_components_dir_empty(&managed_root)?;

    let workspace_dir = biome_fixture();
    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, None).await?;

    let result = call_real_tool(
        &service,
        "format_preview",
        serde_json::json!({ "path": "main.js" }),
    )
    .await?;

    let payload = structured(&result).clone();
    assert_eq!(
        result.is_error,
        Some(false),
        "F6 regression: expected format_preview to succeed via real production managed \
         provisioning against a genuinely absent Biome component, got: {payload}"
    );
    assert_eq!(
        payload["status"],
        serde_json::json!("would_format"),
        "expected a real WouldFormat outcome for genuinely non-canonical input, got: {payload}"
    );
    assert!(
        payload["input_hash"] != payload["output_hash"],
        "a real WouldFormat outcome must report distinct input/output hashes"
    );

    let components_dir = managed_root.join("components");
    let component_names: Vec<String> = std::fs::read_dir(&components_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    assert!(
        component_names.iter().any(|name| name == "biome"),
        "F6 regression: expected managed component 'biome' to have been acquired by the \
         format_preview call, found: {component_names:?}"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}

/// `HOST_DENY_FULL_PROFILE`: the exact same genuinely-absent-Biome scenario
/// as the positive test above, but with an explicit `--host-config`
/// `managed_provisioning_policy = "DENY"`. `FIRST_RUN_RECONCILIATION` still
/// bootstraps a persisted `Full` profile for this isolated root (proven
/// separately by the positive test's own success with no host-config at
/// all) -- this test proves the explicit host veto overrides that `Full`
/// profile's own intent, staying `unavailable` and never attempting network
/// acquisition. Runs fully offline: `Deny` short-circuits before any
/// acquisition call is even reached, so this test needs no
/// `real_network_reachable()` guard.
#[tokio::test]
async fn real_f6_host_deny_overrides_full_profile_e2e() -> Result<(), Box<dyn std::error::Error>> {
    let isolated_data_home = temp_root("biome-host-deny-full-xdg-data-home");
    let managed_root = isolated_data_home.join("corulix").join("managed-toolchain");

    assert_components_dir_empty(&managed_root)?;

    let workspace_dir = biome_fixture();
    let host_config_dir = temp_root("biome-host-deny-full-hostconfig");
    let host_config = host_config_denying_managed_provisioning(&host_config_dir);
    let service =
        spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, Some(&host_config))
            .await?;

    let result = call_real_tool(
        &service,
        "format_preview",
        serde_json::json!({ "path": "main.js" }),
    )
    .await?;

    let payload = structured(&result).clone();
    assert_eq!(
        payload["status"],
        serde_json::json!("unavailable"),
        "HOST_DENY_FULL_PROFILE regression: an explicit HostConfig deny must override even a \
         bootstrapped Full profile's own intent, got: {payload}"
    );

    let acquired_anything = std::fs::read_dir(managed_root.join("components"))
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    assert!(
        !acquired_anything,
        "HOST_DENY_FULL_PROFILE regression: no managed component may be acquired once the host \
         has explicitly denied provisioning"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    let _ = std::fs::remove_dir_all(&host_config_dir);
    Ok(())
}

/// `HOST_DENY_ON_DEMAND_PROFILE`: the same override proof as above, but
/// against an explicitly persisted `InstallProfile::OnDemand` (which, from
/// `install_profile::grants_intent`'s own point of view, grants intent for
/// any component identically to `Full` -- see that module's doc comment) --
/// proving the host veto is unconditional, not merely effective against the
/// bootstrap-default `Full` case. The profile is persisted directly via
/// this crate's own dev-dependency on `wht_corulix_tooling`, mirroring how
/// `--host-config` fixture files are written directly rather than through a
/// CLI round-trip.
#[tokio::test]
async fn real_f6_host_deny_overrides_on_demand_profile_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    let isolated_data_home = temp_root("biome-host-deny-on-demand-xdg-data-home");
    let managed_root = isolated_data_home.join("corulix").join("managed-toolchain");

    assert_components_dir_empty(&managed_root)?;
    install_profile::save(&managed_root, &InstallProfile::OnDemand).map_err(|error| {
        format!("persisting an explicit OnDemand profile must succeed: {error:?}")
    })?;

    let workspace_dir = biome_fixture();
    let host_config_dir = temp_root("biome-host-deny-on-demand-hostconfig");
    let host_config = host_config_denying_managed_provisioning(&host_config_dir);
    let service =
        spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, Some(&host_config))
            .await?;

    let result = call_real_tool(
        &service,
        "format_preview",
        serde_json::json!({ "path": "main.js" }),
    )
    .await?;

    let payload = structured(&result).clone();
    assert_eq!(
        payload["status"],
        serde_json::json!("unavailable"),
        "HOST_DENY_ON_DEMAND_PROFILE regression: an explicit HostConfig deny must override an \
         explicitly persisted OnDemand profile too, got: {payload}"
    );

    // First-run reconciliation must never have overwritten the explicit
    // OnDemand choice back to Full (`EXPLICIT_INSTALL_PROFILE_PERSISTENCE`).
    assert_eq!(
        install_profile::load(&managed_root).ok().flatten(),
        Some(InstallProfile::OnDemand),
        "an explicit OnDemand profile must survive a real process bootstrap unchanged"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    let _ = std::fs::remove_dir_all(&host_config_dir);
    Ok(())
}
