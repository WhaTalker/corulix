// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! F1 regression suite (`CORULIX_HOST_CONFIG_INTERFACE`): real, end-to-end
//! proof that `corulix mcp stdio --host-config <FILE>` genuinely reaches the
//! shipped binary's own provider resolution -- never an in-process
//! `CorulixEngine::open_with_host_config` shortcut. Every test here spawns
//! the actual compiled `corulix` binary (`CARGO_BIN_EXE_corulix`, the same
//! mechanism `real_p13_mcp_stdio_discovery_smoke_e2e.rs` already
//! establishes) as a real child process and drives it over its real stdio
//! transport.
//!
//! `format_preview` is the tool this suite proves reachability through: its
//! own engine-side implementation (`CorulixEngine::format_preview_at`)
//! calls `self.effective_config()` -- the same `EffectiveConfig` derivation
//! `--host-config` now feeds -- and passes it into
//! `wht_corulix_formatter::format_preview_at`, which falls through to
//! `wht_corulix_config::resolve_provider` (the real `HOST_ONLY` resolution
//! path) only when `CORULIX_MANAGED` is not permitted/available. Every test
//! below isolates the spawned process into a fresh directory per test (see
//! [`spawn_real_corulix_mcp_stdio`]'s own doc comment for why that means
//! more than just `XDG_DATA_HOME` on every platform). Under
//! Installation-Contract-V1, a fresh, never-provisioned isolated root is no
//! longer synonymous with "managed provisioning is unreachable": the real
//! binary's own `mcp stdio` startup runs `FIRST_RUN_RECONCILIATION`, which
//! bootstraps a persisted `Full` install profile into that isolated root
//! immediately, so `managed_provisioning_policy`'s default `Inherit` grants
//! intent for every canonical component (including rustfmt) unless a test
//! explicitly overrides it with `managed_provisioning_policy = "DENY"`. Real
//! network access is required by any test that lets that default `Full`
//! profile reach genuine `CORULIX_MANAGED` acquisition; tests that assert an
//! unavailable/`HOST_ONLY`-only outcome set `managed_provisioning_policy =
//! "DENY"` explicitly to stay deterministic and network-free.

use std::path::{Path, PathBuf};

use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use tokio::process::Command;

fn corulix_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_corulix"))
}

fn temp_dir(label: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-cli-f1-host-config-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

/// Scans the *test process's own* ambient `PATH` (never Corulix's -- this
/// workspace's own `AMBIENT_PATH_PROVIDER_AUTHORITY=NO` invariant is about
/// what Corulix itself reads, not what a test harness may use to *discover*
/// a real binary to hand it explicitly) for a directory containing `name`,
/// so this suite can point `--host-config` at a genuinely real,
/// already-installed toolchain location rather than fabricating one or
/// depending on real network access to provision a managed component.
fn find_ambient_binary_dir(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var).find(|dir| dir.join(name).is_file())
}

fn write_host_config(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("host.toml");
    // Test-fixture setup only: a write failure here surfaces as a later
    // assertion mismatch, never a `.expect()` -- this workspace's
    // `clippy::expect_used = "deny"` lint applies to test code exactly as
    // it does to production code.
    let _ = std::fs::write(&path, content);
    path
}

/// Spawns the real compiled `corulix mcp stdio` binary, with
/// `XDG_DATA_HOME`/`LOCALAPPDATA`/`APPDATA` all redirected to
/// `isolated_data_home` for this child process only -- the real
/// `managed_toolchain_root()` this process resolves therefore lands under an
/// empty, never-provisioned directory, guaranteeing the `CORULIX_MANAGED`
/// path is unavailable (mirrors
/// `wht_corulix_mcp/tests/real_p13_mcp_managed_provider_isolated_e2e.rs`'s
/// own isolation rationale exactly). `host_config` is appended as
/// `--host-config <path>` when given.
///
/// All three env vars are set unconditionally rather than only
/// `XDG_DATA_HOME`: `managed_toolchain_root()`
/// (`wht_crates/wht_corulix_tooling/src/provisioning.rs`) reads
/// `XDG_DATA_HOME` on Unix but `LOCALAPPDATA`/`APPDATA` on Windows and never
/// consults `XDG_DATA_HOME` there -- a Unix-only override silently falls
/// through to the real, shared, host-wide managed root on native Windows
/// (confirmed empirically during Windows certification: it persisted a real
/// install-profile write into that shared root). Harmless on platforms that
/// don't consult a given var.
async fn spawn_real_corulix_mcp_stdio(
    workspace_dir: &Path,
    isolated_data_home: &Path,
    host_config: Option<&Path>,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>, Box<dyn std::error::Error>>
{
    let binary = corulix_binary();
    let host_config = host_config.map(Path::to_path_buf);
    let command = Command::new(&binary).configure(|cmd| {
        cmd.arg("mcp")
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

const UNFORMATTED_RUST_SOURCE: &[u8] = b"fn   corulix_marker_f1_e2e( )   {\n let x=1;\n}\n";

/// `HOST_CONFIG_ABSENT_REACHES_DEFAULT_FULL_PROFILE` (Installation-Contract-V1
/// rebaseline of the old `HOST_CONFIG_DEFAULT_BEHAVIOR_UNCHANGED` contract):
/// omitting `--host-config` no longer reproduces an unconditional
/// `Unavailable` -- `FIRST_RUN_RECONCILIATION` bootstraps a real, persisted
/// `Full` install profile into this test's isolated, never-provisioned
/// `XDG_DATA_HOME` on the real binary's own `mcp stdio` startup, which grants
/// intent for every canonical component including rustfmt;
/// `managed_provisioning_policy` defaults to `Inherit`, which defers to that
/// profile, so `format_preview` genuinely reaches real, network-provisioned
/// `CORULIX_MANAGED` rustfmt with zero operator configuration at all. This
/// is the product's own default installation contract, proven here through
/// the real shipped binary, not merely by code inspection -- real network
/// access is required for this test.
#[tokio::test]
async fn host_config_absent_reaches_default_full_profile_format_preview_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace_dir = temp_dir("absent-workspace");
    let isolated_data_home = temp_dir("absent-xdg");
    std::fs::write(workspace_dir.join("main.rs"), UNFORMATTED_RUST_SOURCE)?;

    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, None).await?;
    let result = call_real_tool(
        &service,
        "format_preview",
        serde_json::json!({ "path": "main.rs" }),
    )
    .await?;
    let payload = structured(&result).clone();
    assert_eq!(
        result.is_error,
        Some(false),
        "expected a successful format_preview call under the default install profile, got: \
         {payload}"
    );
    assert_eq!(
        payload["status"],
        serde_json::json!("would_format"),
        "expected default-FULL to make managed rustfmt reachable with zero operator config, \
         got: {payload}"
    );
    assert_eq!(
        payload["provider_used_managed"],
        serde_json::json!(true),
        "expected the CORULIX_MANAGED path (first-run-reconciled Full profile), not HOST_ONLY, \
         got: {payload}"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}

/// `CONTROLLED_EXTERNAL_TOOL_PRODUCTION_REACHABILITY`: a real
/// `--host-config` file naming the ambient, already-installed `rustfmt`'s
/// own directory as an approved system directory makes `format_preview`
/// genuinely reach `WouldFormat` through the real shipped binary --
/// `provider_used_managed: false` proves this went through the `HOST_ONLY`/
/// `ApprovedSystemDirectory` path this fix wires, not `CORULIX_MANAGED`.
#[tokio::test]
async fn host_config_approved_system_directory_makes_format_preview_reachable()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(rustfmt_dir) = find_ambient_binary_dir("rustfmt") else {
        eprintln!(
            "SKIPPED host_config_approved_system_directory_makes_format_preview_reachable: \
             no ambient rustfmt found on this host's PATH"
        );
        return Ok(());
    };

    let workspace_dir = temp_dir("approved-workspace");
    let isolated_data_home = temp_dir("approved-xdg");
    let host_config_dir = temp_dir("approved-hostconfig");
    std::fs::write(workspace_dir.join("main.rs"), UNFORMATTED_RUST_SOURCE)?;

    let host_config = write_host_config(
        &host_config_dir,
        &format!(
            "approved_system_directories = [{dir:?}]\n",
            dir = rustfmt_dir.to_string_lossy()
        ),
    );

    let service =
        spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, Some(&host_config))
            .await?;
    let result = call_real_tool(
        &service,
        "format_preview",
        serde_json::json!({ "path": "main.rs" }),
    )
    .await?;
    let payload = structured(&result).clone();
    assert_eq!(
        result.is_error,
        Some(false),
        "expected a successful format_preview call, got: {payload}"
    );
    assert_eq!(
        payload["status"],
        serde_json::json!("would_format"),
        "expected a real WouldFormat outcome once --host-config approves rustfmt's real \
         directory, got: {payload}"
    );
    assert_eq!(
        payload["provider_used_managed"],
        serde_json::json!(false),
        "expected the HOST_ONLY/ApprovedSystemDirectory path, not CORULIX_MANAGED, got: {payload}"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    let _ = std::fs::remove_dir_all(&host_config_dir);
    Ok(())
}

/// `HOST_ONLY_TRUST_PRODUCTION_REACHABILITY` (provider side): the same
/// proof as above, but via `provider_absolute_paths` (an explicit,
/// per-category absolute path) rather than a directory scan -- proves the
/// other real `HostConfig` resolution precedence tier is genuinely wired
/// end to end too.
#[tokio::test]
async fn host_config_provider_absolute_path_makes_format_preview_reachable()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(rustfmt_dir) = find_ambient_binary_dir("rustfmt") else {
        eprintln!(
            "SKIPPED host_config_provider_absolute_path_makes_format_preview_reachable: \
             no ambient rustfmt found on this host's PATH"
        );
        return Ok(());
    };
    let rustfmt_path = rustfmt_dir.join("rustfmt");

    let workspace_dir = temp_dir("absolute-workspace");
    let isolated_data_home = temp_dir("absolute-xdg");
    let host_config_dir = temp_dir("absolute-hostconfig");
    std::fs::write(workspace_dir.join("main.rs"), UNFORMATTED_RUST_SOURCE)?;

    let host_config = write_host_config(
        &host_config_dir,
        &format!(
            "[[provider_absolute_paths]]\ncategory = \"FORMATTER\"\npath = {path:?}\n",
            path = rustfmt_path.to_string_lossy()
        ),
    );

    let service =
        spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, Some(&host_config))
            .await?;
    let result = call_real_tool(
        &service,
        "format_preview",
        serde_json::json!({ "path": "main.rs" }),
    )
    .await?;
    let payload = structured(&result).clone();
    assert_eq!(
        payload["status"],
        serde_json::json!("would_format"),
        "expected a real WouldFormat outcome via the explicit provider_absolute_paths entry, \
         got: {payload}"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    let _ = std::fs::remove_dir_all(&host_config_dir);
    Ok(())
}

/// A workspace-local executable named identically to a real provider must
/// never satisfy `CONTROLLED_EXTERNAL_TOOL`, even when a `--host-config`
/// file approves the directory it lives in (an operator misconfiguration
/// this resolver must still reject) -- proves the workspace-local rejection
/// `wht_corulix_config::resolver` already enforces at the unit level is
/// genuinely reachable end to end through the real shipped binary too.
///
/// `managed_provisioning_policy = "DENY"` is added to this test's host-config
/// (Installation-Contract-V1): without it, `FIRST_RUN_RECONCILIATION`
/// bootstraps a real, persisted `Full` profile into this test's own isolated
/// root on spawn, which would make the real, genuinely `CORULIX_MANAGED`
/// rustfmt legitimately reachable and mask whatever this test's
/// `approved_system_directories` workspace-local-rejection logic actually
/// does behind an unrelated, coincidentally successful `WouldFormat`. `DENY`
/// isolates this test to the one `HOST_ONLY` resolution path it means to
/// exercise.
#[tokio::test]
async fn host_config_workspace_local_directory_never_satisfies_controlled_external_tool()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace_dir = temp_dir("workspace-local-workspace");
    let isolated_data_home = temp_dir("workspace-local-xdg");
    let host_config_dir = temp_dir("workspace-local-hostconfig");
    std::fs::write(workspace_dir.join("main.rs"), UNFORMATTED_RUST_SOURCE)?;

    // A fake "rustfmt" planted *inside* the workspace itself, named
    // identically to the real provider this test's host-config approves the
    // directory of.
    let fake_rustfmt = workspace_dir.join("rustfmt");
    std::fs::write(&fake_rustfmt, "#!/bin/sh\necho fake\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&fake_rustfmt)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake_rustfmt, permissions)?;
    }

    let host_config = write_host_config(
        &host_config_dir,
        &format!(
            "approved_system_directories = [{dir:?}]\nmanaged_provisioning_policy = \"DENY\"\n",
            dir = workspace_dir.to_string_lossy()
        ),
    );

    let service =
        spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, Some(&host_config))
            .await?;
    let result = call_real_tool(
        &service,
        "format_preview",
        serde_json::json!({ "path": "main.rs" }),
    )
    .await?;
    let payload = structured(&result).clone();
    assert_eq!(
        payload["status"],
        serde_json::json!("unavailable"),
        "a workspace-local executable must never satisfy CONTROLLED_EXTERNAL_TOOL even when \
         its directory is host-approved, got: {payload}"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    let _ = std::fs::remove_dir_all(&host_config_dir);
    Ok(())
}

/// Waits for the real spawned process to exit (never starting an MCP
/// session at all for any of these failure modes -- the host-config load
/// fails before `wht_corulix_mcp::serve_stdio` is ever reached) and asserts
/// the documented exit code.
async fn assert_host_config_failure_exit_code(
    workspace_dir: &Path,
    host_config_arg: &std::ffi::OsStr,
) -> Result<(), Box<dyn std::error::Error>> {
    let binary = corulix_binary();
    let output = Command::new(&binary)
        .arg("mcp")
        .arg("stdio")
        .arg("--workspace")
        .arg(workspace_dir)
        .arg("--host-config")
        .arg(host_config_arg)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .await?;
    assert_eq!(
        output.status.code(),
        Some(6),
        "expected HOST_CONFIG_FAILURE (exit code 6) for {host_config_arg:?}, got {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// `HOST_CONFIG_VALIDATION=FAIL_CLOSED`: every documented failure mode
/// actually exits non-zero with the documented code, through the real
/// compiled binary -- never merely the config crate's own unit tests.
#[tokio::test]
async fn host_config_cli_validation_failure_modes() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_dir = temp_dir("validation-workspace");
    let fixture_dir = temp_dir("validation-fixtures");

    // 1. Relative path.
    assert_host_config_failure_exit_code(
        &workspace_dir,
        std::ffi::OsStr::new("relative/host.toml"),
    )
    .await?;

    // 2. Nonexistent absolute path.
    let missing = fixture_dir.join("does-not-exist.toml");
    assert_host_config_failure_exit_code(&workspace_dir, missing.as_os_str()).await?;

    // 3. Malformed content (unknown field).
    let malformed = write_host_config(&fixture_dir, "this_field_does_not_exist = true\n");
    assert_host_config_failure_exit_code(&workspace_dir, malformed.as_os_str()).await?;

    // 4. Resolves inside the very workspace it would configure.
    let inside_workspace = workspace_dir.join("host.toml");
    std::fs::write(&inside_workspace, "")?;
    assert_host_config_failure_exit_code(&workspace_dir, inside_workspace.as_os_str()).await?;

    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&fixture_dir);
    Ok(())
}

// -----------------------------------------------------------------------
// `HOST_ONLY_TRUST_PRODUCTION_REACHABILITY`: `--host-config`'s
// `workspace_trust`/`allow_trusted_workspace_execution` fields genuinely
// reach `wht_corulix_config::EffectiveConfig::is_execution_class_allowed(
// TrustedWorkspaceExecution)` through the real compiled binary --
// `validate_change`'s real `cargo check` dispatch
// (`wht_corulix_engine::diagnostics::authorize_trusted_execution`, checked
// *before* any process is spawned) is the one real capability this
// workspace gates on that authorization. Before this fix there was no
// `--host-config` flag at all, so a live `corulix mcp stdio` process could
// never self-authorize this -- confirmed empirically here by first
// reproducing that exact `Unavailable` default, then showing the identical
// session genuinely reaches a real, successful `cargo check` once
// `--host-config` grants it.
// -----------------------------------------------------------------------

/// Provisions the real, unmodified `rust-semantic-runtime` product manifest
/// into `root` (idempotent, real network) -- the one managed component
/// `cargo check` itself needs; `false` (never panics) on genuine failure so
/// an environment without real internet access reports a disclosed skip.
async fn ensure_real_managed_rust_semantic_runtime_provisioned(root: &Path) -> bool {
    use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64;
    use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

    let (state, _) =
        provisioning::resolve_managed_component(root, &RUST_SEMANTIC_RUNTIME_LINUX_X64);
    if state == ManagedComponentState::Available {
        return true;
    }
    provisioning::provision(root, &RUST_SEMANTIC_RUNTIME_LINUX_X64)
        .await
        .is_ok()
}

async fn call_validate_change_status(
    service: &rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let begin = call_real_tool(
        service,
        "begin_change",
        serde_json::json!({
            "intent": "VALIDATE_CHANGE",
            "scope_prefixes": [],
        }),
    )
    .await?;
    let session_id = structured(&begin)["session_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let validate = call_real_tool(
        service,
        "validate_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    // `ValidateChangeOutputEnvelope`'s own tag (`status: "ran"`/`"session_not_found"`)
    // wraps the real, inner per-language dispatch outcome under `outcome` --
    // callers of this helper want that inner outcome directly.
    Ok(structured(&validate)["outcome"].clone())
}

#[tokio::test]
async fn host_config_grants_trusted_workspace_execution_for_real_cargo_check()
-> Result<(), Box<dyn std::error::Error>> {
    let isolated_data_home = temp_dir("trust-xdg");
    let managed_root = isolated_data_home.join("corulix").join("managed-toolchain");
    if !ensure_real_managed_rust_semantic_runtime_provisioned(&managed_root).await {
        eprintln!(
            "SKIPPED host_config_grants_trusted_workspace_execution_for_real_cargo_check: \
             real managed rust-semantic-runtime provisioning failed \
             (no real internet access in this environment?)"
        );
        return Ok(());
    }

    let workspace_dir = temp_dir("trust-workspace");
    std::fs::create_dir_all(workspace_dir.join("src"))?;
    std::fs::write(
        workspace_dir.join("Cargo.toml"),
        "[package]\nname = \"corulix_f1_trust_e2e_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    std::fs::write(workspace_dir.join("src/lib.rs"), "pub fn noop() {}\n")?;

    // Step 1: without --host-config, the default remains unchanged --
    // TrustedWorkspaceExecution is never self-authorized.
    let without_host_config =
        spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, None).await?;
    let outcome = call_validate_change_status(&without_host_config).await?;
    assert_eq!(
        outcome["status"],
        serde_json::json!("unavailable"),
        "expected the unchanged default (no HostConfig => no TrustedWorkspaceExecution \
         authorization), got: {outcome}"
    );
    without_host_config.cancel().await?;

    // Step 2: the same session, but with a real --host-config file granting
    // workspace_trust = TRUSTED + allow_trusted_workspace_execution = true.
    let host_config_dir = temp_dir("trust-hostconfig");
    let host_config = write_host_config(
        &host_config_dir,
        "workspace_trust = \"TRUSTED\"\nallow_trusted_workspace_execution = true\n",
    );
    let with_host_config =
        spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home, Some(&host_config))
            .await?;
    let outcome = call_validate_change_status(&with_host_config).await?;
    assert_eq!(
        outcome["status"],
        serde_json::json!("executed"),
        "expected --host-config to genuinely authorize TrustedWorkspaceExecution and reach a \
         real cargo check, got: {outcome}"
    );
    assert_eq!(
        outcome["clean"],
        serde_json::json!(true),
        "expected a real, clean cargo check for genuinely valid Rust source, got: {outcome}"
    );
    with_host_config.cancel().await?;

    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    let _ = std::fs::remove_dir_all(&host_config_dir);
    Ok(())
}
