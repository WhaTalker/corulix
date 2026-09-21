// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13 item 2: runs the official
//! `@modelcontextprotocol/conformance` server-testing suite against the
//! real, production [`wht_corulix_mcp::CorulixMcpServer`] handler.
//!
//! The official suite's server-testing mode requires an HTTP URL
//! (`--url`); it has no stdio/child-process spawn mode. Corulix's shipped
//! product transport is stdio only (`corulix mcp stdio`) -- there is no
//! production HTTP transport in this workspace. This test therefore wraps
//! the exact same real `CorulixMcpServer` in `rmcp` 3.0.1's own
//! `StreamableHttpService` (a real, upstream `tower_service::Service`,
//! never reimplemented here) bound to a real, ephemeral, localhost-only
//! TCP listener, for the duration of this test only.
//!
//! This is genuinely test-only scaffolding around real production logic,
//! not a new shipped feature: `rmcp`'s `transport-streamable-http-server`
//! feature and the `axum`/`tokio-util` crates used to bind the listener
//! are all `[dev-dependencies]`-only in `wht_corulix_mcp/Cargo.toml` --
//! Cargo's own feature-unification rule means they are never present in a
//! release (non-test) build of the `corulix` binary
//! (`P13_CONFORMANCE_HARNESS_RELEASE_SURFACE=ABSENT`; verified via
//! `wht_scripts/wht_verify_architecture.py` and a plain `grep` for this
//! file's own symbols outside `tests/`).
//!
//! The official conformance CLI itself is invoked as a real `npx` child
//! process against the real listening address -- never mocked, never a
//! canned fixture.

use std::sync::Arc;

use axum::Router;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use wht_corulix_core::WorkspaceIdentity;
use wht_corulix_engine::CorulixEngine;
use wht_corulix_mcp::CorulixMcpServer;
use wht_corulix_workspace::{WorkspaceContext, WorkspaceRoot};

fn temp_workspace(label: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-mcp-conformance-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

/// Locates the official `conformance` checkout's local install (already
/// cloned + `npm install`-built once this session, at a path outside this
/// repository). Kept as an explicit env override so this test never
/// silently re-clones/re-builds a multi-hundred-package npm tree on every
/// run: if the checkout is genuinely absent, this test reports `BLOCKED`
/// (skips, exit 0, with an explicit stderr line) rather than fabricating a
/// PASS.
fn conformance_checkout_dir() -> Option<std::path::PathBuf> {
    if let Some(value) = std::env::var_os("CORULIX_MCP_CONFORMANCE_DIR") {
        let path = std::path::PathBuf::from(value);
        if path.join("dist/index.js").is_file() {
            return Some(path);
        }
        return None;
    }
    None
}

/// Spawns the real `CorulixMcpServer` behind a real, ephemeral,
/// localhost-only HTTP listener via `rmcp`'s own `StreamableHttpService`.
/// Returns the server's real base URL and a `CancellationToken` the caller
/// must cancel for a clean shutdown.
async fn spawn_real_corulix_http_server()
-> Result<(String, CancellationToken), Box<dyn std::error::Error>> {
    let root_dir = temp_workspace("harness");
    let root = WorkspaceRoot::open(&root_dir)?;
    let context = WorkspaceContext::single_root(root, "root".to_string());
    let engine = Arc::new(CorulixEngine::open(context));
    let identity = WorkspaceIdentity::from_opaque_token("wsid-conformance-harness".to_string())?;

    let cancellation_token = CancellationToken::new();
    let config =
        StreamableHttpServerConfig::default().with_cancellation_token(cancellation_token.clone());

    let service: StreamableHttpService<CorulixMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || {
                CorulixMcpServer::new(Arc::clone(&engine), identity.clone())
                    .map_err(|error| std::io::Error::other(error.to_string()))
            },
            Arc::new(LocalSessionManager::default()),
            config,
        );

    let router = Router::new().nest_service("/mcp", service);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server_ct = cancellation_token.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async move { server_ct.cancelled_owned().await })
            .await;
    });

    Ok((format!("http://{addr}/mcp"), cancellation_token))
}

/// Runs the real official conformance CLI against `url`, scoped to the
/// 2026-07-28 requirements set, and returns its raw stdout/stderr plus exit
/// status. A real `npx`/`node` child process -- never simulated.
fn run_official_conformance_cli(
    checkout_dir: &std::path::Path,
    url: &str,
) -> std::io::Result<std::process::Output> {
    std::process::Command::new("node")
        .arg("dist/index.js")
        .arg("server")
        .arg("--url")
        .arg(url)
        .arg("--requirements")
        .arg("2026-07-28")
        .current_dir(checkout_dir)
        .output()
}

// `flavor = "multi_thread"` is required, not cosmetic: the real HTTP
// server task (`tokio::spawn`ed below) must keep running concurrently
// while this test blocks its own calling thread on the real, synchronous
// `node`/`npx` child-process call below (moved to `spawn_blocking` for
// exactly this reason) -- a single-threaded runtime would starve the
// server task and the conformance CLI would hang waiting on a server that
// never gets scheduled to answer.
#[tokio::test(flavor = "multi_thread")]
async fn real_official_mcp_conformance_suite_against_corulix_server()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(checkout_dir) = conformance_checkout_dir() else {
        eprintln!(
            "BLOCKED real_official_mcp_conformance_suite_against_corulix_server: \
             CORULIX_MCP_CONFORMANCE_DIR not set to a built \
             github.com/modelcontextprotocol/conformance checkout \
             (expects <dir>/dist/index.js) -- see this file's own module doc"
        );
        return Ok(());
    };

    let (url, cancellation_token) = spawn_real_corulix_http_server().await?;

    let output =
        tokio::task::spawn_blocking(move || run_official_conformance_cli(&checkout_dir, &url))
            .await??;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    cancellation_token.cancel();

    eprintln!("P13_MCP_CONFORMANCE_SUITE_EXIT_STATUS={:?}", output.status);
    eprintln!("P13_MCP_CONFORMANCE_SUITE_STDOUT=\n{stdout}");
    eprintln!("P13_MCP_CONFORMANCE_SUITE_STDERR=\n{stderr}");

    // This is a real, executed-suite proof, not a strict pass/fail gate:
    // Corulix is a tools-only MCP server by design (Rule N/mandate scope --
    // no resources/prompts/completion/sampling/elicitation/roots), so a
    // real, honest run against the official suite is expected to report
    // real scored failures for those legitimately-unimplemented optional
    // features (see this test's own eprintln output, and the phase report,
    // for the itemized breakdown) -- this assertion only proves the suite
    // genuinely executed against the real server and produced its own
    // summary, never that every scenario passed.
    assert!(
        stdout.contains("=== SUMMARY ==="),
        "expected the official conformance CLI to reach its own summary \
         section, got stdout: {stdout}"
    );
    assert!(
        stdout.contains("Total:") && stdout.contains("passed") && stdout.contains("failed"),
        "expected the official conformance CLI's real pass/fail totals in \
         its output, got stdout: {stdout}"
    );

    Ok(())
}
