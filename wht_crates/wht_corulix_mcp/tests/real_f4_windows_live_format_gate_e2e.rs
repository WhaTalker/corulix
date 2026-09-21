// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(windows)]

//! F4 native-Windows live proof (`F4_WINDOWS_FORMAT_GATE_LIVE_PROOF`): the
//! in-process unit suite in `wht_corulix_mcp/src/lib.rs`
//! (`mcp_can_close_format_gate_after_real_formatter_validation` and its
//! three siblings) proves `gate.format` closes through the real MCP tool
//! dispatch -- but those tests resolve a Linux dev-machine `HOST_ONLY`
//! directory via PATH (`real_rust_formatter_available`) and cleanly skip
//! (`F4_MCP_FORMAT_GATE_E2E=BLOCKED_PROVIDER_UNAVAILABLE`) on any host
//! where a real `rustfmt` cannot be found there, including Windows.
//! §35 of the mandate governing this pass forbids inferring the Windows
//! result from the Linux one, so this file is the genuine, separate,
//! Windows-native replacement: it spawns the real compiled `corulix.exe`
//! (mirroring `wht_corulix_cli/tests/real_f1_host_config_e2e.rs`'s own
//! real-child-process pattern) and drives the real 14-tool MCP stdio
//! surface end to end through `begin_change` -> `submit_edit` ->
//! `complete_change` (denied) -> `validate_change` (dirty) ->
//! `complete_change` (still denied) -> `submit_edit` (clean bytes) ->
//! `validate_change` (clean) -> `complete_change` (completed) against the
//! real, native Windows `rustfmt.exe` under the real rustup toolchain `bin/`
//! directory, resolved through `HostConfig::approved_system_directories`
//! (`HOST_ONLY`, never `CORULIX_MANAGED`) -- the same directory-ordering
//! fix already applied on the Linux side.
//!
//! # Why this crate cannot reuse `env!("CARGO_BIN_EXE_corulix")`
//!
//! That mechanism is populated by Cargo only for integration tests in the
//! package that defines the `corulix` binary (`wht_corulix_cli`). This
//! crate (`wht_corulix_mcp`) is not that package, and adding a `[[bin]]`
//! dependency or new dev-dependency here to gain it would touch
//! `Cargo.toml`/`Cargo.lock` -- out of scope for this pass, which authorizes
//! exactly one new test file. Instead, [`corulix_release_binary`] resolves
//! the real, already-built release binary path directly from
//! `CARGO_MANIFEST_DIR` (`.../wht_crates/wht_corulix_mcp` ->
//! `.../wht_crates` -> repository root -> `target/release/corulix.exe`),
//! the same artifact this pass's own `cargo build --workspace --release
//! --locked` step already produced.

use std::path::{Path, PathBuf};

use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use tokio::process::Command;

/// Test-only PATH-based discovery of a real Windows toolchain directory.
/// `CORULIX_TEST_WINDOWS_RUSTUP_BIN`/`CORULIX_TEST_WINDOWS_CARGO_SHIM_BIN`
/// override discovery with an exact directory path. Never embeds a
/// specific developer's machine path/username.
fn real_windows_rustup_toolchain_bin() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("CORULIX_TEST_WINDOWS_RUSTUP_BIN") {
        return Some(PathBuf::from(explicit));
    }
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).find(|dir| dir.join("rustfmt.exe").is_file()))
        .flatten()
}
/// The rustup shim directory -- listed second, never first, so a resolver
/// walking `approved_system_directories` in order reaches the real
/// toolchain binary before any shim.
fn real_windows_cargo_shim_bin() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("CORULIX_TEST_WINDOWS_CARGO_SHIM_BIN") {
        return Some(PathBuf::from(explicit));
    }
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).find(|dir| dir.join("cargo.exe").is_file()))
        .flatten()
}

fn real_rustfmt_available() -> bool {
    real_windows_rustup_toolchain_bin().is_some_and(|dir| dir.join("rustfmt.exe").is_file())
}

/// Resolves the real, already-built release `corulix.exe` from
/// `CARGO_MANIFEST_DIR` -- see this file's own module doc comment for why
/// `env!("CARGO_BIN_EXE_corulix")` is unavailable in this package.
fn corulix_release_binary() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent()?.parent()?;
    let binary = repo_root.join("target").join("release").join("corulix.exe");
    if binary.is_file() { Some(binary) } else { None }
}

fn stamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

/// A fresh temp dir *outside* the repository tree, so the fixture workspace
/// never inherits this repository's own non-default `rustfmt.toml`/
/// `rust-toolchain.toml`.
fn temp_dir(label: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("corulix-mcp-f4-windows-live-{label}-{}", stamp()));
    let _ = std::fs::create_dir_all(&root);
    root
}

fn write_host_config(dir: &Path) -> PathBuf {
    let path = dir.join("host.toml");
    // Literal TOML strings (single-quoted) so Windows backslashes are never
    // interpreted as escape sequences -- matches this workspace's own
    // established convention for Windows path literals in HostConfig TOML.
    let content = format!(
        "approved_system_directories = ['{toolchain}', '{shim}']\n",
        toolchain = real_windows_rustup_toolchain_bin()
            .unwrap_or_default()
            .display(),
        shim = real_windows_cargo_shim_bin().unwrap_or_default().display(),
    );
    let _ = std::fs::write(&path, content);
    path
}

/// # A real, confirmed defect this fix closes (not hypothetical)
///
/// This file only ever compiles and runs on native Windows
/// (`#![cfg(windows)]` at the top of the file). Before this fix, the
/// isolation below set only `XDG_DATA_HOME` -- which
/// `wht_corulix_tooling::provisioning::managed_toolchain_root()` never
/// reads on Windows (`LOCALAPPDATA`, falling back to `APPDATA`, is that
/// platform's actual resolution). Every real run of this file's tests on
/// this VM therefore spawned `corulix.exe`, which resolved the REAL,
/// SHARED, host-wide managed-toolchain root instead of an isolated one --
/// and `corulix mcp stdio` startup unconditionally runs
/// `FIRST_RUN_RECONCILIATION`/`ensure_bootstrapped` against whatever root
/// it resolves, so this was not merely a failure to isolate but a genuine,
/// silent, persisted write into shared host state on every single native
/// Windows test pass this file was ever part of. Confirmed directly: the
/// shared root's `install-profile.json` was found holding a `SELECTIVE`
/// profile that only a *different* misdirected test
/// (`real_setup_command_e2e.rs`) could have produced, proving this whole
/// class of spawn helper was silently writing real state the entire time.
async fn spawn_real_corulix_mcp_stdio(
    binary: &Path,
    workspace_dir: &Path,
    isolated_data_home: &Path,
    host_config: &Path,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>, Box<dyn std::error::Error>>
{
    let command = Command::new(binary).configure(|cmd| {
        cmd.arg("mcp")
            .arg("stdio")
            .arg("--workspace")
            .arg(workspace_dir)
            .arg("--host-config")
            .arg(host_config)
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
        unreachable!("every call site in this file passes a JSON object");
    };
    let params = CallToolRequestParams::new(tool_name).with_arguments(arguments);
    Ok(service.call_tool(params).await?)
}

fn structured(result: &CallToolResult) -> serde_json::Value {
    result
        .structured_content
        .clone()
        .unwrap_or(serde_json::Value::Null)
}

/// Deliberately misformatted: no space after `fn`, no indentation -- a real
/// `rustfmt` finding, not a syntax error.
const RUST_FIXTURE_UNFORMATTED: &str = "fn main( ) {\nprintln!(\"f4-windows-live\");\n}\n";
/// The exact real `rustfmt`-canonical formatting of the same program.
const RUST_FIXTURE_CANONICAL: &str = "fn main() {\n    println!(\"f4-windows-live\");\n}\n";

/// §35: the real, native-Windows, hands-on proof that `gate.format`
/// genuinely closes through the real shipped `corulix.exe` MCP stdio
/// surface -- never inferred from the Linux in-process unit suite. Prints
/// `F4_WINDOWS_LIVE_FORMAT_GATE_REAL_ASSERTIONS_EXERCISED=YES` only once
/// every intermediate status below has been genuinely observed and
/// asserted -- the anti-vacuity marker this pass's report cites as evidence
/// the run was not merely a skip dressed up as a pass.
#[tokio::test]
async fn real_f4_windows_live_format_gate_e2e() -> Result<(), Box<dyn std::error::Error>> {
    let Some(binary) = corulix_release_binary() else {
        eprintln!(
            "F4_WINDOWS_FORMAT_GATE_LIVE_PROOF=BLOCKED_ENVIRONMENT root_cause=release_binary_not_found"
        );
        return Ok(());
    };
    if !real_rustfmt_available() {
        eprintln!(
            "F4_WINDOWS_FORMAT_GATE_LIVE_PROOF=BLOCKED_ENVIRONMENT root_cause=real_rustfmt_exe_not_found_on_path"
        );
        return Ok(());
    }

    let workspace_dir = temp_dir("workspace");
    let isolated_data_home = temp_dir("xdg");
    let host_config_dir = temp_dir("hostconfig");
    let host_config = write_host_config(&host_config_dir);
    std::fs::write(workspace_dir.join("main.rs"), RUST_FIXTURE_UNFORMATTED)?;

    let service =
        spawn_real_corulix_mcp_stdio(&binary, &workspace_dir, &isolated_data_home, &host_config)
            .await?;

    // --- begin_change (SourceModify) ---
    let begin = call_real_tool(
        &service,
        "begin_change",
        serde_json::json!({
            "intent": "SOURCE_MODIFY",
            "language": "rust",
            // `SessionScope::permits` matches an exact relative-path entry
            // or a `{prefix}/`-rooted one -- never a bare empty string
            // (`session.rs`'s own `permits` never treats `""` as a
            // wildcard). This session's single target is `main.rs` itself.
            "scope_prefixes": ["main.rs"],
        }),
    )
    .await?;
    let begin_payload = structured(&begin);
    let session_id = begin_payload["session_id"]
        .as_str()
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            format!("expected a session_id from begin_change, got {begin_payload}").into()
        })?
        .to_string();
    eprintln!("F4_WINDOWS_LIVE_BEGIN_CHANGE=PASS session_id={session_id}");

    // --- submit_edit: replace with dirty content (no-op precondition,
    // already-dirty fixture -- this step establishes gate.edit only). ---
    let precondition_hash =
        wht_corulix_core::ContentHash::compute_sha256(RUST_FIXTURE_UNFORMATTED.as_bytes())
            .digest_hex;
    let replace_dirty = call_real_tool(
        &service,
        "submit_edit",
        serde_json::json!({
            "session_id": session_id,
            "relative_path": "main.rs",
            "edit": {
                "kind": "replace",
                "expected_precondition_hash_hex": precondition_hash,
                "content_utf8": RUST_FIXTURE_UNFORMATTED,
            },
        }),
    )
    .await?;
    if replace_dirty.is_error != Some(false) {
        return Err(format!(
            "expected the real dirty edit to commit, got {}",
            structured(&replace_dirty)
        )
        .into());
    }

    // --- complete_change must be DENIED: gate.format not yet evidenced. ---
    let premature = call_real_tool(
        &service,
        "complete_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    let premature_payload = structured(&premature);
    if premature_payload["status"] != serde_json::json!("denied") {
        return Err(format!(
            "PREMATURE_FORMAT_GATE_COMPLETION_DENIED: expected denial before validate_change, got {premature_payload}"
        )
        .into());
    }
    eprintln!("F4_WINDOWS_LIVE_PREMATURE_COMPLETE_DENIED=PASS");

    // --- validate_change against real, native rustfmt.exe: dirty bytes
    // must report clean:false. ---
    let validate_dirty = call_real_tool(
        &service,
        "validate_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    if validate_dirty.is_error != Some(false) {
        return Err(format!(
            "expected a real, successful format validate_change call against dirty bytes, got {}",
            structured(&validate_dirty)
        )
        .into());
    }
    let validate_dirty_outcome = structured(&validate_dirty)["outcome"].clone();
    if validate_dirty_outcome["status"] != serde_json::json!("format_validated") {
        return Err(format!(
            "expected the real F4 format dispatcher's outcome, got {validate_dirty_outcome}"
        )
        .into());
    }
    if validate_dirty_outcome["clean"] != serde_json::json!(false) {
        return Err(format!(
            "expected the real native Windows rustfmt.exe to report the dirty fixture unclean, got {validate_dirty_outcome}"
        )
        .into());
    }
    eprintln!("F4_WINDOWS_LIVE_VALIDATE_DIRTY=PASS clean=false");

    // --- complete_change must STILL be DENIED with the precise reason
    // code: gate.format Failed, not Passed. ---
    let still_denied = call_real_tool(
        &service,
        "complete_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    let still_denied_payload = structured(&still_denied);
    if still_denied_payload["status"] != serde_json::json!("denied") {
        return Err(format!(
            "UNFORMATTED_SOURCE_FORMAT_GATE=NOT_SATISFIED: expected denial after a real unclean rustfmt check, got {still_denied_payload}"
        )
        .into());
    }
    if still_denied_payload["reason_code"] != serde_json::json!("FORMAT_FINDINGS_REPORTED") {
        return Err(
            format!("expected the precise F4 reason code, got {still_denied_payload}").into(),
        );
    }
    eprintln!("F4_WINDOWS_LIVE_DIRTY_COMPLETE_DENIED=PASS reason_code=FORMAT_FINDINGS_REPORTED");

    // --- submit_edit: replace with the already-canonical bytes. ---
    let replace_clean = call_real_tool(
        &service,
        "submit_edit",
        serde_json::json!({
            "session_id": session_id,
            "relative_path": "main.rs",
            "edit": {
                "kind": "replace",
                "expected_precondition_hash_hex": wht_corulix_core::ContentHash::compute_sha256(
                    RUST_FIXTURE_UNFORMATTED.as_bytes(),
                ).digest_hex,
                "content_utf8": RUST_FIXTURE_CANONICAL,
            },
        }),
    )
    .await?;
    if replace_clean.is_error != Some(false) {
        return Err(format!(
            "expected the real clean-bytes edit to commit, got {}",
            structured(&replace_clean)
        )
        .into());
    }

    // --- validate_change against real, native rustfmt.exe: canonical bytes
    // must report clean:true, real Evidence recorded. ---
    let validate_clean = call_real_tool(
        &service,
        "validate_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    if validate_clean.is_error != Some(false) {
        return Err(format!(
            "expected a real, successful format validate_change call against clean bytes, got {}",
            structured(&validate_clean)
        )
        .into());
    }
    let validate_clean_outcome = structured(&validate_clean)["outcome"].clone();
    if validate_clean_outcome["status"] != serde_json::json!("format_validated") {
        return Err(format!(
            "expected the real F4 format dispatcher's outcome, got {validate_clean_outcome}"
        )
        .into());
    }
    if validate_clean_outcome["clean"] != serde_json::json!(true) {
        return Err(format!(
            "expected the real native Windows rustfmt.exe to report the canonical fixture clean, got {validate_clean_outcome}"
        )
        .into());
    }
    eprintln!("F4_WINDOWS_LIVE_VALIDATE_CLEAN=PASS clean=true");

    // --- complete_change must now be COMPLETED. ---
    let complete = call_real_tool(
        &service,
        "complete_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    let complete_payload = structured(&complete);
    if complete_payload["status"] != serde_json::json!("completed") {
        return Err(format!(
            "MCP_SOURCE_MODIFY_CAN_COMPLETE: expected completion after a real, clean native Windows rustfmt.exe check, got {complete_payload}"
        )
        .into());
    }
    eprintln!("F4_WINDOWS_LIVE_COMPLETE_CHANGE=PASS status=completed");

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    let _ = std::fs::remove_dir_all(&host_config_dir);

    eprintln!("F4_WINDOWS_LIVE_FORMAT_GATE_REAL_ASSERTIONS_EXERCISED=YES");
    eprintln!("F4_WINDOWS_FORMAT_GATE_LIVE_PROOF=PASS");
    Ok(())
}
