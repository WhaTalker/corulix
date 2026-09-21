// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13: the explicit MCP `2026-07-28` discovery/negotiation lifecycle
//! E2E the mandate requires, distinct from
//! `real_p13_mcp_stdio_discovery_smoke_e2e.rs` (which only proves that
//! *some* protocol version negotiates via rmcp 3.0.1's implicit default,
//! `ProtocolVersion::LATEST`, which itself still resolves to
//! `V_2025_11_25` in this SDK version -- see `rmcp-3.0.1/src/model.rs`).
//!
//! This test explicitly requests `ProtocolVersion::V_2026_07_28` on the
//! client's `initialize` request (`ClientInfo::with_protocol_version`, the
//! real rmcp 3.0.1 client-side mechanism -- `ClientInfo` is a type alias
//! for `InitializeRequestParams`, which carries a `protocol_version` field)
//! and asserts the server's negotiated `ServerPeerInfo::protocol_version`
//! literally string-equals `"2026-07-28"`, not merely that a handshake
//! completed. This proves the real compiled `corulix mcp stdio` server
//! genuinely supports the explicit 2026-07-28 lifecycle end to end, against
//! the same real spawned child process transport
//! (`rmcp::transport::TokioChildProcess`) the existing legacy-default smoke
//! test uses -- a different, additive proof, not a replacement.

use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, ClientInfo, Implementation, ProtocolVersion,
};
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
    let root = std::env::temp_dir().join(format!("corulix-cli-mcp-2026-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

/// Explicit `2026-07-28` `initialize` -> `tools/list` -> `runtime_identity`
/// -> clean shutdown, asserting the negotiated protocol version string
/// literally, not merely that negotiation happened.
#[tokio::test]
async fn real_explicit_2026_07_28_discovery_and_invocation()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace = temp_workspace("discovery");
    let binary = corulix_binary();

    let command = Command::new(&binary).configure(|cmd| {
        cmd.arg("mcp")
            .arg("stdio")
            .arg("--workspace")
            .arg(&workspace);
    });
    let transport = TokioChildProcess::new(command)?;

    // Explicitly request 2026-07-28 -- never rely on the SDK's implicit
    // `ProtocolVersion::default()`/`LATEST`, which today still resolves to
    // `V_2025_11_25` in rmcp 3.0.1.
    let client_info = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::from_build_env(),
    )
    .with_protocol_version(ProtocolVersion::V_2026_07_28);

    assert_eq!(
        client_info.protocol_version,
        ProtocolVersion::V_2026_07_28,
        "the client request itself must explicitly carry 2026-07-28, not a default"
    );

    let service = client_info.serve(transport).await?;

    let negotiated = service
        .peer_info()
        .ok_or("server must report peer info (ServerPeerInfo) after initialize")?;
    assert_eq!(
        negotiated.protocol_version,
        ProtocolVersion::V_2026_07_28,
        "server must echo back the explicitly requested 2026-07-28 protocol version"
    );
    assert_eq!(
        negotiated.protocol_version.to_string(),
        "2026-07-28",
        "negotiated protocol version must literally string-equal 2026-07-28"
    );

    let tools = service.list_all_tools().await?;
    assert_eq!(tools.len(), 14);

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

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace);
    Ok(())
}
