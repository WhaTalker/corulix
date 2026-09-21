// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Installation-Contract-V1 fix, new failure mode this mandate's own
//! `DEFAULT_INSTALL_PROFILE=FULL` behavior creates and must guard against:
//! a bootstrapped `Full` install profile now makes acquisition *permitted*
//! for every canonical component, which makes it newly possible for a
//! passive, read-only informational tool to accidentally trigger real
//! network acquisition merely by inspecting availability -- something that
//! could never happen before this pass, when acquisition was unconditionally
//! unreachable in production. `toolchain_status` and `plan_operation` are
//! explicitly contracted to stay non-mutating regardless of what an
//! install profile permits (`TOOLCHAIN_STATUS_CAUSES_PROVISIONING=NO`,
//! `PLAN_OPERATION_CAUSES_PROVISIONING=NO`); this file proves it against a
//! genuinely absent TS6 stack under a real, bootstrapped `Full` profile,
//! not merely by code inspection.

use std::path::PathBuf;

use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use tokio::process::Command;

fn temp_root(label: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-f6-passive-tools-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

/// Same real spawn recipe as `real_f6_production_managed_provisioning_e2e.rs`
/// (duplicated rather than shared -- each file under `tests/` compiles as
/// an independent crate). No `--host-config` at all: `FIRST_RUN_RECONCILIATION`
/// bootstraps a real, persisted `Full` profile for this isolated root on its
/// own, which is the exact condition this file needs to prove passive tools
/// stay inert under.
///
/// Isolates via `XDG_DATA_HOME`/`LOCALAPPDATA`/`APPDATA` all set to
/// `isolated_data_home` -- `XDG_DATA_HOME` alone is Unix-only
/// (`managed_toolchain_root()` never reads it on Windows, where
/// `LOCALAPPDATA`/`APPDATA` is the real resolution), so a Unix-only
/// override would silently fall through to the real shared host-wide root
/// on native Windows. All three are harmless on platforms that don't
/// consult a given one.
async fn spawn_real_corulix_mcp_stdio(
    workspace_dir: &std::path::Path,
    isolated_data_home: &std::path::Path,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>, Box<dyn std::error::Error>>
{
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

fn ts6_fixture() -> PathBuf {
    let root = temp_root("workspace");
    let _ = std::fs::write(
        root.join("package.json"),
        r#"{"name":"corulix-passive-tools-fixture","private":true,"devDependencies":{"typescript":"6.0.3"}}"#,
    );
    let _ = std::fs::write(
        root.join("main.ts"),
        "export function target() {\n  return 1;\n}\n",
    );
    root
}

fn components_are_empty(
    managed_root: &std::path::Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let components_dir = managed_root.join("components");
    Ok(!components_dir.exists() || std::fs::read_dir(&components_dir)?.next().is_none())
}

#[tokio::test]
async fn real_f6_toolchain_status_never_provisions_under_full_profile_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    let isolated_data_home = temp_root("toolchain-status-xdg-data-home");
    let managed_root = isolated_data_home.join("corulix").join("managed-toolchain");
    assert!(
        components_are_empty(&managed_root)?,
        "precondition violated: managed root must start empty"
    );

    let workspace_dir = ts6_fixture();
    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home).await?;

    let result = call_real_tool(&service, "toolchain_status", serde_json::json!({})).await?;
    assert_eq!(result.is_error, Some(false));

    assert!(
        components_are_empty(&managed_root)?,
        "TOOLCHAIN_STATUS_CAUSES_PROVISIONING regression: a purely informational \
         toolchain_status call must never trigger real managed acquisition, even under a \
         bootstrapped Full profile"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}

#[tokio::test]
async fn real_f6_plan_operation_never_provisions_under_full_profile_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    let isolated_data_home = temp_root("plan-operation-xdg-data-home");
    let managed_root = isolated_data_home.join("corulix").join("managed-toolchain");
    assert!(
        components_are_empty(&managed_root)?,
        "precondition violated: managed root must start empty"
    );

    let workspace_dir = ts6_fixture();
    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home).await?;

    let result = call_real_tool(
        &service,
        "plan_operation",
        serde_json::json!({
            "intent": "SEMANTIC_DEFINITION",
            "language": "type_script",
        }),
    )
    .await?;
    assert_eq!(result.is_error, Some(false));

    assert!(
        components_are_empty(&managed_root)?,
        "PLAN_OPERATION_CAUSES_PROVISIONING regression: deriving a ToolPlan must never trigger \
         real managed acquisition, even under a bootstrapped Full profile"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}
