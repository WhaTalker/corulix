// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13: the real stdio discovery/invocation smoke test the mandate
//! requires -- `initialize -> tools/list -> one safe read-only call ->
//! clean shutdown`, against the *actual compiled* `corulix` binary spawned
//! as a real child process, speaking real MCP client protocol via `rmcp`'s
//! own `TokioChildProcess` transport (the SDK's genuine client-side test
//! harness for exactly this scenario -- not a mock, not an in-process
//! shortcut).
//!
//! This is deliberately the one place in this workspace that spawns the
//! compiled binary rather than calling library code directly: no other
//! test can prove the real stdio framing/handshake end to end.

use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientInfo, Implementation};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use std::path::PathBuf;
use tokio::process::Command;

fn corulix_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_corulix"))
}

fn temp_workspace(label: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-cli-mcp-smoke-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

/// `initialize -> tools/list -> runtime_identity -> clean shutdown`,
/// against a really-spawned `corulix mcp stdio` child process.
#[tokio::test]
async fn real_stdio_discovery_and_safe_invocation_smoke() -> Result<(), Box<dyn std::error::Error>>
{
    let workspace = temp_workspace("discovery");
    let binary = corulix_binary();

    let command = Command::new(&binary).configure(|cmd| {
        cmd.arg("mcp")
            .arg("stdio")
            .arg("--workspace")
            .arg(&workspace);
    });
    let transport = TokioChildProcess::new(command)?;

    let client_info = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::from_build_env(),
    );

    // `initialize`: the real handshake, against the real spawned process.
    let service = client_info.serve(transport).await?;

    // `tools/list`: proves real discovery of the full canonical surface.
    let tools = service.list_all_tools().await?;
    assert_eq!(
        tools.len(),
        14,
        "a freshly spawned corulix mcp stdio server must advertise exactly \
         14 canonical tools"
    );
    assert!(tools.iter().any(|tool| tool.name == "runtime_identity"));
    assert!(tools.iter().any(|tool| tool.name == "begin_change"));

    // One safe, read-only call: `runtime_identity`. Never a mutating tool
    // in a genuine discovery smoke test.
    let result = service
        .call_tool(CallToolRequestParams::new("runtime_identity"))
        .await?;
    assert_eq!(result.is_error, Some(false));
    let structured = result
        .structured_content
        .as_ref()
        .ok_or("runtime_identity must return structuredContent")?;
    assert_eq!(
        structured["binary"],
        serde_json::json!(wht_corulix_core::BINARY_NAME)
    );

    // Clean shutdown.
    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace);
    Ok(())
}
