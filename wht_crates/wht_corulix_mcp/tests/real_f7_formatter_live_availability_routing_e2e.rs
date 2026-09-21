// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! F7 (`F7_FORMATTER_LIVE_AVAILABILITY_NOT_OVERLAID_IN_ROUTING`): real,
//! positive- and negative-path `begin_change` E2E proving `gate.edit`'s
//! `Formatter` requirement check now reflects genuinely live, resolvable
//! provider state rather than the pre-F7 hard-coded
//! `ProviderAvailability::ProviderUnavailable`. Driven through the real
//! compiled `corulix mcp stdio` binary as a real child process, exactly
//! the same real client transport
//! (`rmcp::transport::TokioChildProcess`/`spawn_real_corulix_mcp_stdio`'s
//! own precedent) `real_p13_mcp_managed_provider_isolated_e2e.rs` already
//! uses -- never a direct Rust call into a private engine method.
//!
//! Deliberately avoids the `CORULIX_MANAGED` real-network-acquisition path
//! entirely: `managed::resolve_formatter`'s second half (`managed.rs`)
//! falls through to `wht_corulix_config::resolve_provider`, whose
//! `Available`/`ProviderUnavailable` verdict for the `HOST_ONLY`/system
//! tier is a pure filesystem + `HostConfig` decision -- no network, no
//! install-profile `grants_intent` state, no acquisition. A single
//! spawned server, one disposable `approved_system_directories` entry, and
//! copying/removing one real system `rustfmt` binary into/out of it is
//! therefore sufficient to prove the full "becomes available" / "becomes
//! unavailable" cycle deterministically and fast, with
//! `managed_provisioning_policy = "DENY"` closing off any possibility that
//! a genuine removal gets silently self-healed by real acquisition
//! (which would mask exactly the false-negative this suite exists to
//! rule out).

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
    let root = std::env::temp_dir().join(format!("corulix-mcp-f7-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

/// As `real_p13_mcp_managed_provider_isolated_e2e.rs`'s own
/// `spawn_real_corulix_mcp_stdio`, but also passes `--host-config
/// host_config_path` -- this suite's entire point is to control the
/// `HostConfig` (`managed_provisioning_policy`, `approved_system_directories`)
/// a real spawned server resolves `Formatter` against. Also sets an
/// ambient `PATH` pointing at a directory containing a fake, hostile
/// `rustfmt` for the ENTIRE test (never changed mid-run): the resolver
/// module structurally never reads `PATH`
/// (`AMBIENT_PATH_AUTHORITY=NO`, `poisoned_path_has_no_effect`), so this
/// is a continuous negative control across every assertion in this file,
/// not a one-off check -- if it ever had any effect, every other
/// assertion below would also silently break.
async fn spawn_real_corulix_mcp_stdio_with_host_config(
    workspace_dir: &std::path::Path,
    isolated_data_home: &std::path::Path,
    host_config_path: &std::path::Path,
    poisoned_path_dir: &std::path::Path,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>, Box<dyn std::error::Error>>
{
    // Prepended, never a replacement: `Command::new("cargo")` itself
    // relies on a real PATH-based lookup to spawn `cargo` at all, so
    // wiping PATH down to only the poison directory would fail the spawn
    // itself (confirmed the hard way: an earlier draft did exactly that
    // and every run failed with a bare `NotFound` before the resolver
    // was ever reached). Prepending is also the more realistic hostile
    // shape: a real PATH-hijack attempt prepends a malicious directory
    // ahead of the legitimate one, it does not erase the legitimate
    // entries.
    // `std::env::join_paths` -- never a hand-formatted `:`-joined string
    // (Windows uses `;`, not `:`; an earlier draft hardcoded `:` and would
    // have corrupted PATH resolution on Windows exactly as the `cargo`
    // spawn-failure bug this same function's own history already caught).
    let real_path = std::env::var_os("PATH").unwrap_or_default();
    let poisoned_path = std::env::join_paths(
        std::iter::once(poisoned_path_dir.to_path_buf()).chain(std::env::split_paths(&real_path)),
    )?;
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
            .arg("--host-config")
            .arg(host_config_path)
            .env("XDG_DATA_HOME", isolated_data_home)
            .env("LOCALAPPDATA", isolated_data_home)
            .env("APPDATA", isolated_data_home)
            .env("PATH", poisoned_path);
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

/// A real system `rustfmt` this host is known to have (established
/// convention throughout this whole certification arc: the rustup-managed
/// toolchain's own `bin/` directory holds a real rustfmt executable, never
/// a `rustup` proxy shim -- see `corulix_final_e2e_host_config.toml`'s own
/// F5 finding). Genuinely cross-platform (F7 Windows-leg fix: an earlier
/// draft hardcoded a Linux-only `stable-x86_64-unknown-linux-gnu` triple
/// and a bare `rustfmt` filename, which silently made this whole test
/// SKIP on Windows -- `cargo test` reports a skip-and-return-`Ok(())` test
/// identically to a real pass, so this was caught only by re-running with
/// `--nocapture` and reading the `SKIPPED` diagnostic, not by the exit
/// code): scans every installed toolchain directory (rather than assuming
/// a `stable-<triple>` alias exists -- this host's own toolchain is
/// version-pinned, `1.97.1-x86_64-pc-windows-msvc`, no `stable` alias
/// installed) for one whose name ends in this platform's own target
/// triple suffix and whose `bin/` holds the platform-appropriate
/// executable name. Returns `None` (never panics) so this suite can be
/// honestly skipped on a host with no rustup toolchain at all, rather
/// than fail on an environment difference unrelated to F7.
fn real_system_rustfmt() -> Option<PathBuf> {
    #[cfg(windows)]
    const TRIPLE_SUFFIX: &str = "-pc-windows-msvc";
    #[cfg(windows)]
    const RUSTFMT_NAME: &str = "rustfmt.exe";
    #[cfg(not(windows))]
    const TRIPLE_SUFFIX: &str = "-unknown-linux-gnu";
    #[cfg(not(windows))]
    const RUSTFMT_NAME: &str = "rustfmt";

    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()?;
    let toolchains_dir = PathBuf::from(home).join(".rustup").join("toolchains");
    std::fs::read_dir(toolchains_dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(TRIPLE_SUFFIX))
        })
        .map(|toolchain_dir| toolchain_dir.join("bin").join(RUSTFMT_NAME))
        .find(|candidate| candidate.is_file())
}

/// Extracts the reason-code half (index 1) of each `[gate_id, reason_code]`
/// pair in `status_json["failed_gates"]` -- index 0 is the gate id
/// (`"gate.edit"`), never the reason code.
fn abort_reason_codes(status_json: &serde_json::Value) -> Vec<String> {
    status_json["failed_gates"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.as_array())
        .filter_map(|pair| pair.get(1))
        .filter_map(|reason| reason.as_str())
        .map(str::to_string)
        .collect()
}

#[tokio::test]
async fn real_f7_source_create_gate_edit_tracks_live_formatter_availability_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(real_rustfmt) = real_system_rustfmt() else {
        eprintln!(
            "SKIPPED real_f7_source_create_gate_edit_tracks_live_formatter_availability_e2e: \
             no real system rustfmt found at the expected rustup toolchain path on this host"
        );
        return Ok(());
    };

    let isolated_data_home = temp_root("f7-xdg-data-home");
    let workspace_dir = temp_root("f7-workspace");
    let approved_dir = temp_root("f7-approved-system-dir");
    let poisoned_path_dir = temp_root("f7-poisoned-path-dir");
    let workspace_local_dir = workspace_dir.join("bin");
    std::fs::create_dir_all(&workspace_local_dir)?;

    // A hostile, workspace-local "rustfmt" (F7 negative control, mandate
    // §14): if the resolver ever honored a workspace-local candidate, this
    // executable script (which would fail loudly if ever actually
    // invoked) would make this test's assertions pass for the wrong
    // reason. It never should be reached: `approved_system_directories`
    // below never lists `workspace_dir` or any path under it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let hostile = workspace_local_dir.join("rustfmt");
        std::fs::write(
            &hostile,
            "#!/bin/sh\necho HOSTILE_WORKSPACE_RUSTFMT >&2\nexit 1\n",
        )?;
        std::fs::set_permissions(&hostile, std::fs::Permissions::from_mode(0o755))?;

        // A hostile, PATH-only "rustfmt" (F7 negative control, mandate
        // §15): the resolver's `AMBIENT_PATH_AUTHORITY=NO` guarantee means
        // this must never be reached either, for the entire run (`PATH`
        // is set once, at spawn, in
        // `spawn_real_corulix_mcp_stdio_with_host_config`).
        let hostile_path = poisoned_path_dir.join("rustfmt");
        std::fs::write(
            &hostile_path,
            "#!/bin/sh\necho HOSTILE_PATH_RUSTFMT >&2\nexit 1\n",
        )?;
        std::fs::set_permissions(&hostile_path, std::fs::Permissions::from_mode(0o755))?;
    }
    // Same two negative controls on Windows: the resolver's own candidate
    // check (canonicalization + workspace-locality/`PATH`-authority
    // rejection) never actually invokes the candidate, so a real PE
    // executable is not required here -- only a same-named file at each
    // hostile location, matching the platform-appropriate `rustfmt.exe`
    // filename `real_system_rustfmt` itself resolves.
    #[cfg(windows)]
    {
        std::fs::write(
            workspace_local_dir.join("rustfmt.exe"),
            b"HOSTILE_WORKSPACE_RUSTFMT_NOT_A_REAL_EXECUTABLE",
        )?;
        std::fs::write(
            poisoned_path_dir.join("rustfmt.exe"),
            b"HOSTILE_PATH_RUSTFMT_NOT_A_REAL_EXECUTABLE",
        )?;
    }

    let workspace_parent = workspace_dir
        .parent()
        .ok_or("temp_root always has a parent")?;
    let workspace_dir_name = workspace_dir
        .file_name()
        .ok_or("temp_root always has a file name")?
        .to_string_lossy();
    let host_config_path =
        workspace_parent.join(format!("f7_host_config_{workspace_dir_name}.toml"));
    std::fs::write(
        &host_config_path,
        format!(
            "managed_provisioning_policy = \"DENY\"\n\
             approved_system_directories = [\"{}\"]\n",
            approved_dir.to_string_lossy().replace('\\', "\\\\")
        ),
    )?;

    let service = spawn_real_corulix_mcp_stdio_with_host_config(
        &workspace_dir,
        &isolated_data_home,
        &host_config_path,
        &poisoned_path_dir,
    )
    .await?;

    // --- Call 1: `approved_dir` genuinely empty -> Formatter genuinely
    // --- unavailable -> `gate.edit` must fail closed. Mandate baseline
    // --- (the exact repro this whole F7 mandate was opened against).
    let begin_1 = call_real_tool(
        &service,
        "begin_change",
        serde_json::json!({
            "intent": "SOURCE_CREATE",
            "scope_prefixes": ["main.rs"],
        }),
    )
    .await?;
    let payload_1 = structured(&begin_1).clone();
    assert_eq!(
        begin_1.is_error,
        Some(false),
        "begin_change itself is never a protocol-level error, got: {payload_1}"
    );
    assert_eq!(
        payload_1["status"]["status"],
        serde_json::json!({ "Blocked": "gate.edit" }),
        "call 1 (empty approved_dir): expected Blocked(gate.edit), got: {payload_1}"
    );
    assert!(
        abort_reason_codes(&payload_1["status"])
            .iter()
            .any(|code| code == "REQUIRED_PROVIDER_UNAVAILABLE"),
        "call 1: expected REQUIRED_PROVIDER_UNAVAILABLE in failed_gates, got: {payload_1}"
    );

    // --- Call 2: a real rustfmt now genuinely resolvable via
    // --- `approved_system_directories` -> `gate.edit` must now observe
    // --- it, on this SAME running server / SAME CorulixEngine instance
    // --- (no restart, no snapshot rebuild) -- the F7
    // --- FORMATTER_POST_SNAPSHOT_BECOMES_AVAILABLE proof.
    // Reuses `real_rustfmt`'s own file name (`rustfmt.exe` on Windows,
    // `rustfmt` elsewhere) rather than a hardcoded platform-specific
    // literal -- the resolver looks for the platform-appropriate
    // executable name specifically.
    let staged_rustfmt = approved_dir.join(
        real_rustfmt
            .file_name()
            .ok_or("real_rustfmt always has a file name")?,
    );
    std::fs::copy(&real_rustfmt, &staged_rustfmt)?;

    let begin_2 = call_real_tool(
        &service,
        "begin_change",
        serde_json::json!({
            "intent": "SOURCE_CREATE",
            "scope_prefixes": ["main.rs"],
        }),
    )
    .await?;
    let payload_2 = structured(&begin_2).clone();
    assert_eq!(begin_2.is_error, Some(false));
    // The distinguishing signal between an unexecutable and an executable
    // plan is the STATUS TYPE, not which gate is named: `Blocked(gate.edit)`
    // (call 1) means the plan itself is `Unexecutable`; `GatePending
    // (gate.edit)` means the plan is `Executable` and `gate.edit` is simply
    // the first gate now awaiting the caller's own `submit_edit` -- the
    // exact same state the pre-existing, always-passing
    // `begin_change_opens_a_baselined_session` unit test asserts for any
    // healthy session immediately after `begin_change`, before any edit
    // has been submitted. `gate.format` only becomes the pending gate
    // after a real `submit_edit` closes `gate.edit` for real -- this test
    // proves `begin_change`'s live routing decision, not the full
    // lifecycle (which `real_p16_ts_family_full_governance_e2e.rs`
    // already covers).
    assert_eq!(
        payload_2["status"]["status"],
        serde_json::json!({ "GatePending": "gate.edit" }),
        "call 2 (real rustfmt now staged): expected GatePending(gate.edit) -- the plan itself \
         must now be Executable against the live Formatter, not Blocked, got: {payload_2}"
    );
    assert_eq!(
        payload_2["status"]["failed_gates"],
        serde_json::json!([]),
        "call 2: no gate should be failed once the real Formatter resolves, got: {payload_2}"
    );

    // --- Call 3: the real rustfmt removed again -> Formatter genuinely
    // --- unavailable once more -> `gate.edit` must fail closed again, on
    // --- the SAME running server -- the F7
    // --- FORMATTER_POST_SNAPSHOT_BECOMES_UNAVAILABLE proof. With
    // --- `managed_provisioning_policy = "DENY"` in effect, there is no
    // --- code path that can silently re-acquire and mask this.
    std::fs::remove_file(&staged_rustfmt)?;

    let begin_3 = call_real_tool(
        &service,
        "begin_change",
        serde_json::json!({
            "intent": "SOURCE_CREATE",
            "scope_prefixes": ["main.rs"],
        }),
    )
    .await?;
    let payload_3 = structured(&begin_3).clone();
    assert_eq!(begin_3.is_error, Some(false));
    assert_eq!(
        payload_3["status"]["status"],
        serde_json::json!({ "Blocked": "gate.edit" }),
        "call 3 (rustfmt removed again): expected Blocked(gate.edit) again -- no false-positive \
         caching of call 2's Available verdict, got: {payload_3}"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    let _ = std::fs::remove_dir_all(&approved_dir);
    let _ = std::fs::remove_dir_all(&poisoned_path_dir);
    let _ = std::fs::remove_file(&host_config_path);
    Ok(())
}
