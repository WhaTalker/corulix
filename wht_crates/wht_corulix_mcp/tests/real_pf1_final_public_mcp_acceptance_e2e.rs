// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! PF-1: Final Public MCP Acceptance. Proves, through one real, compiled
//! `corulix mcp stdio` binary spawned as a real child process (never a
//! direct in-process Rust call into a private handler method, and never a
//! fabricated transport), that the exact public 14-tool surface is real
//! and reachable end to end: `tools/list` reports exactly 14 tools, and
//! every one of the 14 produces a genuine, structured, non-panicking
//! response from a real engine/workspace -- either a real success or an
//! honestly-reported unavailable/denied outcome, never a crash and never a
//! missing tool. No managed toolchain is provisioned for this pass (no
//! network, no acquisition): `semantic`/`format_preview`/`validate_change`
//! are real, valid MCP calls whether or not a real language-server/rustfmt
//! backend happens to be resolvable in this environment -- their own
//! typed `Unavailable`/`RequestFailed` outcomes are exactly as real an
//! acceptance proof as a positive result would be, and are already proven
//! reachable-when-provisioned by this workspace's other, managed-provider
//! E2E suites.

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
    let root = std::env::temp_dir().join(format!("corulix-pf1-acceptance-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

struct CleanupGuard(PathBuf);
impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Same real spawn recipe as this workspace's other real stdio E2E suites
/// (duplicated rather than shared -- each file under `tests/` compiles as
/// an independent crate). All three of `XDG_DATA_HOME`/`LOCALAPPDATA`/
/// `APPDATA` are set to the same isolated, disposable directory so this
/// pass's own real spawn never touches the real, shared, host-wide managed
/// root -- `managed_toolchain_root()` never reads `XDG_DATA_HOME` on
/// Windows, so a Unix-only override would silently fall through there.
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
    arguments: Option<serde_json::Value>,
) -> Result<CallToolResult, Box<dyn std::error::Error>> {
    let params = match arguments {
        Some(serde_json::Value::Object(arguments)) => {
            CallToolRequestParams::new(tool_name).with_arguments(arguments)
        }
        Some(_) => unreachable!("every call site in this suite passes a JSON object or None"),
        None => CallToolRequestParams::new(tool_name),
    };
    Ok(service.call_tool(params).await?)
}

fn structured(result: &CallToolResult) -> &serde_json::Value {
    result.structured_content.as_ref().unwrap_or_else(|| {
        unreachable!("every one of these 14 calls must return structuredContent")
    })
}

/// The exact, canonical 14-tool public surface -- this is the assertion
/// PF-1 exists to make, so the expected set is spelled out here literally
/// rather than derived from anywhere else in this crate.
const EXPECTED_PUBLIC_TOOLS: [&str; 14] = [
    "abort_change",
    "begin_change",
    "change_status",
    "complete_change",
    "format_preview",
    "parse_file",
    "plan_operation",
    "runtime_identity",
    "search",
    "semantic",
    "submit_edit",
    "toolchain_status",
    "validate_change",
    "workspace_info",
];

#[tokio::test(flavor = "multi_thread")]
async fn real_pf1_final_public_mcp_acceptance_all_14_tools_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace_dir = temp_root("workspace");
    let _workspace_guard = CleanupGuard(workspace_dir.clone());
    let isolated_data_home = temp_root("xdg-data-home");
    let _data_home_guard = CleanupGuard(isolated_data_home.clone());

    std::fs::write(
        workspace_dir.join("marker.rs"),
        "pub fn corulix_pf1_marker() -> i32 {\n    42\n}\n",
    )?;

    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home).await?;

    // 1. Public surface: exactly 14 tools, exactly this set -- the
    // headline PF-1 assertion.
    let tools = service.list_all_tools().await?;
    assert_eq!(
        tools.len(),
        14,
        "PUBLIC_MCP_TOOL_COUNT must be exactly 14, got: {tools:?}"
    );
    let mut real_names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    real_names.sort_unstable();
    let mut expected_names = EXPECTED_PUBLIC_TOOLS;
    expected_names.sort_unstable();
    assert_eq!(
        real_names, expected_names,
        "the real, live tools/list surface must exactly match the canonical 14-tool set"
    );

    // 2. runtime_identity -- no arguments.
    let result = call_real_tool(&service, "runtime_identity", None).await?;
    assert_eq!(result.is_error, Some(false));
    assert!(structured(&result)["binary"].is_string());

    // 3. workspace_info -- no arguments.
    let result = call_real_tool(&service, "workspace_info", None).await?;
    assert_eq!(result.is_error, Some(false));

    // 4. toolchain_status -- no arguments. A real, honest report, whatever
    // it says about this isolated, unprovisioned root.
    let result = call_real_tool(&service, "toolchain_status", None).await?;
    assert_eq!(result.is_error, Some(false));

    // 5. plan_operation -- a real, deterministic plan for a benign intent.
    let result = call_real_tool(
        &service,
        "plan_operation",
        Some(serde_json::json!({ "intent": "SOURCE_CREATE", "language": null })),
    )
    .await?;
    assert_eq!(
        result.is_error,
        Some(false),
        "plan_operation failed, structured={:?} content={:?}",
        result.structured_content,
        result.content
    );
    assert!(
        structured(&result)["plan"]["executability"].is_string()
            || structured(&result)["plan"]["executability"].is_object(),
        "unexpected plan shape: {:?}",
        structured(&result)["plan"]
    );

    // 6. search -- a real query that must find the marker file's own
    // content.
    let result = call_real_tool(
        &service,
        "search",
        Some(serde_json::json!({
            "pattern": "corulix_pf1_marker",
            "is_regex": false,
            "case_insensitive": false
        })),
    )
    .await?;
    assert_eq!(result.is_error, Some(false));
    assert_eq!(structured(&result)["status"], serde_json::json!("executed"));

    // 7. parse_file -- a real parse of the marker file.
    let result = call_real_tool(
        &service,
        "parse_file",
        Some(serde_json::json!({ "path": "marker.rs" })),
    )
    .await?;
    assert_eq!(result.is_error, Some(false));
    assert_eq!(structured(&result)["status"], serde_json::json!("ok"));

    // 8. semantic -- a real call; genuinely reachable regardless of
    // whether a language-server backend happens to be provisioned here
    // (an honest `unavailable` is exactly as valid an acceptance proof).
    let result = call_real_tool(
        &service,
        "semantic",
        Some(serde_json::json!({
            "operation": "definition",
            "language": "rust",
            "path": "marker.rs",
            "line_zero_based": 0,
            "byte_column_zero_based": 0,
            "byte_offset": 0
        })),
    )
    .await?;
    let semantic_payload = structured(&result).clone();
    assert!(
        semantic_payload["status"].is_string(),
        "semantic must return a real, typed status, got: {semantic_payload}"
    );

    // 9. format_preview -- a real call; same reachable-regardless-of
    // -provisioning reasoning as semantic above.
    let result = call_real_tool(
        &service,
        "format_preview",
        Some(serde_json::json!({ "path": "marker.rs" })),
    )
    .await?;
    let format_preview_payload = structured(&result).clone();
    assert!(
        format_preview_payload["status"].is_string(),
        "format_preview must return a real, typed status, got: {format_preview_payload}"
    );

    // 10-14: the real begin_change -> submit_edit -> validate_change ->
    // change_status -> complete_change lifecycle, one real session,
    // exactly as a real client would drive it.
    let result = call_real_tool(
        &service,
        "begin_change",
        Some(serde_json::json!({
            "intent": "SOURCE_CREATE",
            "scope_prefixes": ["pf1_new_file.rs"]
        })),
    )
    .await?;
    assert_eq!(result.is_error, Some(false));
    let begin_payload = structured(&result).clone();
    assert_eq!(begin_payload["outcome"], serde_json::json!("opened"));
    let session_id = begin_payload["session_id"]
        .as_str()
        .ok_or("begin_change must return a real session_id")?
        .to_string();

    let result = call_real_tool(
        &service,
        "submit_edit",
        Some(serde_json::json!({
            "session_id": session_id,
            "relative_path": "pf1_new_file.rs",
            "edit": {
                "kind": "create",
                "content_utf8": "pub fn corulix_pf1_created() {}\n"
            }
        })),
    )
    .await?;
    let submit_payload = structured(&result).clone();
    assert_eq!(
        submit_payload["status"],
        serde_json::json!("committed"),
        "expected a real committed edit, got: {submit_payload}"
    );

    let result = call_real_tool(
        &service,
        "validate_change",
        Some(serde_json::json!({ "session_id": session_id })),
    )
    .await?;
    let validate_payload = structured(&result).clone();
    assert_eq!(
        validate_payload["status"],
        serde_json::json!("ran"),
        "validate_change must genuinely run against the real session, got: {validate_payload}"
    );

    let result = call_real_tool(
        &service,
        "change_status",
        Some(serde_json::json!({ "session_id": session_id })),
    )
    .await?;
    let status_payload = structured(&result).clone();
    assert_eq!(
        status_payload["outcome"],
        serde_json::json!("found"),
        "change_status must find the real, still-open session, got: {status_payload}"
    );

    let result = call_real_tool(
        &service,
        "complete_change",
        Some(serde_json::json!({ "session_id": session_id })),
    )
    .await?;
    let complete_payload = structured(&result).clone();
    assert!(
        complete_payload["status"].is_string(),
        "complete_change must return a real, typed status, got: {complete_payload}"
    );

    // 14. abort_change -- exercised against a SEPARATE, freshly opened
    // session (the one above is already closed by complete_change).
    let result = call_real_tool(
        &service,
        "begin_change",
        Some(serde_json::json!({
            "intent": "SOURCE_CREATE",
            "scope_prefixes": ["."]
        })),
    )
    .await?;
    let second_session_id = structured(&result)["session_id"]
        .as_str()
        .ok_or("second begin_change must return a real session_id")?
        .to_string();

    let result = call_real_tool(
        &service,
        "abort_change",
        Some(serde_json::json!({ "session_id": second_session_id })),
    )
    .await?;
    let abort_payload = structured(&result).clone();
    assert_eq!(
        abort_payload["status"],
        serde_json::json!("aborted"),
        "abort_change must genuinely abort the real, still-open second session, got: {abort_payload}"
    );

    service.cancel().await?;
    Ok(())
}
