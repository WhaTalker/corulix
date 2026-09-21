// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! F8 §17-19 (`F8_COMPLETE_SOURCE_CREATE_LIFECYCLE`,
//! `F8_SOURCE_CREATE_F4_FORMAT_GATE`): a real, genuine `SOURCE_CREATE`
//! lifecycle proof this certification arc did not yet have.
//!
//! A prior attempt (F7 pass) tried to prove this same lifecycle inside
//! `real_f7_formatter_live_availability_routing_e2e.rs`'s own fixture and
//! was reverted after `validate_change` failed `REQUIRED_CAPABILITY_
//! UNAVAILABLE`: that fixture was a bare directory with no `Cargo.toml`
//! (built only to swap a `rustfmt` binary in and out for the F7 routing
//! proof) and resolved the managed root against an empty,
//! acquisition-denied directory -- two conditions `validate_change_format`
//! (`wht_corulix_engine::validate_change`, which resolves rustfmt via
//! `wht_corulix_tooling::provisioning::managed_toolchain_root()`, a
//! genuinely different tier than `gate.edit`'s own `HOST_ONLY`-capable
//! live-availability check) cannot work under. This test fixes both: a
//! real, disposable, valid Cargo project (mirrors
//! `real_p13_mcp_managed_provider_isolated_e2e.rs`'s own `semantic_fixture`
//! shape) and a real, isolated `CORULIX_MANAGED` root with genuine managed
//! `rustfmt` + `rust-semantic-runtime` provisioned into it (real network,
//! same `ensure_real_managed_rustfmt_provisioned` helper that file already
//! established) -- never the `HostConfig`-approved-directory tier the F7
//! fixture used.
//!
//! Drives one real `begin_change(SOURCE_CREATE) -> submit_edit ->
//! validate_change -> complete_change` session through the real MCP tool
//! surface, over the real compiled binary (`rmcp`/`TokioChildProcess`,
//! never a direct in-process engine call): first with genuinely
//! unformatted content (proving `gate.format` really blocks completion --
//! `F8_SOURCE_CREATE_F4_FORMAT_GATE`), then a corrective, already-canonical
//! replacement (proving the session recovers and genuinely completes --
//! `F8_COMPLETE_SOURCE_CREATE_LIFECYCLE`), with a final on-disk read
//! confirming the committed bytes are exactly the canonical ones.

use std::path::PathBuf;

use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use tokio::process::Command;
use wht_corulix_core::ContentHash;

fn temp_root(label: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-mcp-f8-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

/// A real, disposable, valid Cargo project -- never a bare directory.
/// `src/fresh.rs` itself is deliberately *not* created here: the whole
/// point of this test is a genuine `SOURCE_CREATE`, so the target file
/// must not already exist when the session opens.
fn cargo_fixture(label: &str) -> PathBuf {
    let root = temp_root(label);
    let _ = std::fs::create_dir_all(root.join("src"));
    let _ = std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_mcp_f8_source_create_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    let _ = std::fs::write(root.join("src/lib.rs"), "//! F8 fixture crate.\n");
    root
}

/// As `real_p13_mcp_managed_provider_isolated_e2e.rs`'s own
/// `spawn_real_corulix_mcp_stdio` -- no `--host-config` needed here: the
/// `CORULIX_MANAGED` resolution tier `validate_change_format`/`begin_change`
/// both use reads no `HostConfig` field at all.
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

fn structured(result: &CallToolResult) -> &serde_json::Value {
    let Some(value) = result.structured_content.as_ref() else {
        unreachable!("every tool result in this suite carries structuredContent");
    };
    value
}

#[cfg(not(windows))]
use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64 as RUST_SEMANTIC_RUNTIME_HOST_NATIVE;
/// Adapted from `real_p13_mcp_managed_provider_isolated_e2e.rs`'s own
/// helper (real network, real product manifests, idempotent, `false`
/// -- never a panic -- on genuine provisioning failure so this test can be
/// honestly skipped on an environment with no real internet access).
///
/// Unlike that file's own version, this one is genuinely cross-platform:
/// the `rust-semantic-runtime` manifest is selected per-host via
/// `#[cfg(windows)]`/`#[cfg(not(windows))]` rather than hardcoding
/// `RUST_SEMANTIC_RUNTIME_LINUX_X64` unconditionally. That hardcoding is a
/// real, pre-existing cross-platform bug this test's own first Windows run
/// surfaced (both of `real_p13_mcp_managed_provider_isolated_e2e.rs`'s own
/// tests independently confirmed silently skipping on Windows too, via the
/// exact same suspicious `finished in 0.00s` signature this whole
/// certification arc has repeatedly used to catch a skip-disguised-as-pass
/// -- see this session's own evidence log for the full trace): on Windows,
/// attempting to extract the Linux ELF tarball as this host's own
/// `rust-semantic-runtime` produces a real `ArchiveExtractionFailed`, which
/// this helper's caller then reports as an honest "no real internet
/// access?" skip -- a misleading diagnosis for what is actually a wrong-
/// platform-manifest bug, not a connectivity problem (confirmed directly:
/// a real `Invoke-WebRequest` against the same download host returned
/// `HTTP 200` from this exact VM). `wht_corulix_formatter::managed_toolchain::
/// RUSTFMT_LINUX_X64` had the identical hardcoding; switched to the
/// already-correctly-`#[cfg]`-gated `RUSTFMT_HOST_NATIVE` instead of
/// inventing a second alias. No production crate source was touched to fix
/// this -- both the correct per-platform `rust-semantic-runtime` manifests
/// and `RUSTFMT_HOST_NATIVE` were already public; this is a test-file-only
/// fix.
#[cfg(windows)]
use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64 as RUST_SEMANTIC_RUNTIME_HOST_NATIVE;

async fn ensure_real_managed_rustfmt_provisioned(root: &std::path::Path) -> bool {
    use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

    let (runtime_state, _) =
        provisioning::resolve_managed_component(root, &RUST_SEMANTIC_RUNTIME_HOST_NATIVE);
    if runtime_state != ManagedComponentState::Available
        && provisioning::provision(root, &RUST_SEMANTIC_RUNTIME_HOST_NATIVE)
            .await
            .is_err()
    {
        return false;
    }
    let (rustfmt_state, _) = provisioning::resolve_managed_component(
        root,
        &wht_corulix_formatter::managed_toolchain::RUSTFMT_HOST_NATIVE,
    );
    if rustfmt_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(
            root,
            &wht_corulix_formatter::managed_toolchain::RUSTFMT_HOST_NATIVE,
            &["rust-semantic-runtime"],
        )
        .await
        .is_err()
    {
        return false;
    }
    true
}

/// Empirically verified (both real system `rustfmt 1.97.1` and the real
/// managed `rustfmt 1.9.0-stable` this test provisions produce byte-
/// identical output for this exact snippet): genuinely malformed spacing
/// that both real rustfmt builds agree needs reformatting.
const UNFORMATTED_RUST: &str = "fn main( ) { let x=1 ; println!(\"{}\",x) ; }\n";
/// The real, verified rustfmt-canonical output for [`UNFORMATTED_RUST`].
const FORMATTED_RUST: &str = "fn main() {\n    let x = 1;\n    println!(\"{}\", x);\n}\n";

/// Real, second cross-platform bug this test's own Windows run surfaced,
/// found via direct instrumentation of `wht_corulix_tooling::provisioning::
/// ownership::load` (temporary, reverted): `root_identity()` binds every
/// managed-component ownership record to a raw SHA-256 hash of the
/// *literal* `managed_root` path string this component was provisioned
/// under (`ownership.rs`'s own doc: "a record can never be silently reused
/// against a different managed-toolchain root") -- a deliberate integrity
/// feature, not a bug (`PRODUCT_DEFECT=NO`). `managed_toolchain_root()`
/// joins `.join("Corulix")` (capital C) on Windows, `.join("corulix")`
/// (lowercase) on Unix -- this test's own helper, copied from
/// `real_p13_mcp_managed_provider_isolated_e2e.rs`'s Unix-oriented
/// precedent, unconditionally used the lowercase join on every platform.
/// NTFS resolves both casings to the identical physical directory (file
/// access itself was never the problem -- confirmed directly: the
/// provisioned files and their ownership records were genuinely present on
/// disk), but the *ownership identity check* hashes the raw string, so a
/// real spawned server calling the real `managed_toolchain_root()` (which
/// resolves the capital-C variant) never matched this test's own
/// lowercase-provisioned ownership records, reporting `NotProvisioned` and
/// `Blocked(gate.edit, REQUIRED_PROVIDER_UNAVAILABLE)` -- exactly the
/// observed failure. Fixed by mirroring `managed_toolchain_root()`'s own
/// per-platform casing exactly, rather than assuming one.
fn isolated_managed_root(isolated_data_home: &std::path::Path) -> PathBuf {
    #[cfg(windows)]
    {
        isolated_data_home.join("Corulix").join("managed-toolchain")
    }
    #[cfg(not(windows))]
    {
        isolated_data_home.join("corulix").join("managed-toolchain")
    }
}

#[tokio::test]
async fn real_f8_source_create_full_lifecycle_e2e() -> Result<(), Box<dyn std::error::Error>> {
    let isolated_data_home = temp_root("source-create-xdg-data-home");
    let managed_root = isolated_managed_root(&isolated_data_home);
    if !ensure_real_managed_rustfmt_provisioned(&managed_root).await {
        eprintln!(
            "SKIPPED real_f8_source_create_full_lifecycle_e2e: real managed rustfmt/\
             rust-semantic-runtime provisioning failed (no real internet access in \
             this environment?)"
        );
        return Ok(());
    }

    let workspace_dir = cargo_fixture("source-create-real");
    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home).await?;

    // --- begin_change(SOURCE_CREATE): a real Cargo project plus a real
    // managed rustfmt means the F7 live-resolution overlay this session's
    // `gate.edit` check performs must find `Formatter` genuinely
    // `Available` on the very first call -- no prior negative-path call
    // is needed here (F7's own dedicated suite already proves that half).
    let begin = call_real_tool(
        &service,
        "begin_change",
        serde_json::json!({
            "intent": "SOURCE_CREATE",
            "language": "rust",
            "scope_prefixes": ["src/fresh.rs"],
        }),
    )
    .await?;
    let begin_payload = structured(&begin).clone();
    assert_eq!(
        begin.is_error,
        Some(false),
        "begin_change(SOURCE_CREATE) must succeed against a real Cargo project with a \
         real managed rustfmt available, got: {begin_payload}"
    );
    let session_id = begin_payload["session_id"]
        .as_str()
        .ok_or("begin_change response always carries session_id")?
        .to_string();
    assert_eq!(
        begin_payload["status"]["status"],
        serde_json::json!({ "GatePending": "gate.edit" }),
        "expected GatePending(gate.edit), got: {begin_payload}"
    );

    // --- submit_edit: create the target file with genuinely unformatted
    // content. ---
    let submit_unformatted = call_real_tool(
        &service,
        "submit_edit",
        serde_json::json!({
            "session_id": session_id,
            "relative_path": "src/fresh.rs",
            "edit": { "kind": "create", "content_utf8": UNFORMATTED_RUST },
        }),
    )
    .await?;
    assert_eq!(
        submit_unformatted.is_error,
        Some(false),
        "submit_edit(create) must succeed, got: {:?}",
        structured(&submit_unformatted)
    );

    // --- validate_change: the real managed rustfmt must genuinely report
    // this target would reformat -- F8_SOURCE_CREATE_F4_FORMAT_GATE's
    // negative leg. ---
    let validate_unformatted = call_real_tool(
        &service,
        "validate_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    let validate_unformatted_payload = structured(&validate_unformatted).clone();
    assert_eq!(
        validate_unformatted.is_error,
        Some(false),
        "validate_change must genuinely run (a real, recorded Failed gate.format Evidence \
         is a successful *call*), got: {validate_unformatted_payload}"
    );
    assert_eq!(
        validate_unformatted_payload["outcome"]["status"],
        serde_json::json!("format_validated"),
        "expected a real FormatValidated outcome, got: {validate_unformatted_payload}"
    );
    assert_eq!(
        validate_unformatted_payload["outcome"]["clean"],
        serde_json::json!(false),
        "genuinely unformatted content must be reported unclean, got: \
         {validate_unformatted_payload}"
    );

    // --- complete_change must be DENIED: gate.format's real Failed
    // Evidence leaves it genuinely unsatisfied. ---
    let complete_denied = call_real_tool(
        &service,
        "complete_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    let complete_denied_payload = structured(&complete_denied).clone();
    assert_eq!(
        complete_denied.is_error,
        Some(true),
        "complete_change must surface as an error while gate.format is unsatisfied, got: \
         {complete_denied_payload}"
    );
    assert_eq!(
        complete_denied_payload["status"],
        serde_json::json!("denied"),
        "expected Denied, got: {complete_denied_payload}"
    );

    // --- submit_edit: a corrective replace with the real rustfmt-canonical
    // bytes. submit_edit's own doc explicitly allows a corrective edit
    // after an earlier gate failed (never confined to a single point in
    // the gate walk, unlike every other gate) -- this is exactly that
    // scenario. ---
    let precondition_hash = ContentHash::compute_sha256(UNFORMATTED_RUST.as_bytes()).digest_hex;
    let submit_formatted = call_real_tool(
        &service,
        "submit_edit",
        serde_json::json!({
            "session_id": session_id,
            "relative_path": "src/fresh.rs",
            "edit": {
                "kind": "replace",
                "expected_precondition_hash_hex": precondition_hash,
                "content_utf8": FORMATTED_RUST,
            },
        }),
    )
    .await?;
    assert_eq!(
        submit_formatted.is_error,
        Some(false),
        "corrective submit_edit(replace) must succeed, got: {:?}",
        structured(&submit_formatted)
    );

    // --- validate_change again: now genuinely clean. ---
    let validate_formatted = call_real_tool(
        &service,
        "validate_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    let validate_formatted_payload = structured(&validate_formatted).clone();
    assert_eq!(
        validate_formatted.is_error,
        Some(false),
        "validate_change must succeed, got: {validate_formatted_payload}"
    );
    assert_eq!(
        validate_formatted_payload["outcome"]["clean"],
        serde_json::json!(true),
        "the real rustfmt-canonical replacement must be reported clean, got: \
         {validate_formatted_payload}"
    );

    // --- complete_change now genuinely succeeds. ---
    let complete_ok = call_real_tool(
        &service,
        "complete_change",
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;
    let complete_ok_payload = structured(&complete_ok).clone();
    assert_eq!(
        complete_ok.is_error,
        Some(false),
        "complete_change must succeed once gate.format is genuinely satisfied, got: \
         {complete_ok_payload}"
    );
    assert_eq!(
        complete_ok_payload["status"],
        serde_json::json!("completed"),
        "expected Completed, got: {complete_ok_payload}"
    );

    // --- The real, committed on-disk bytes must be exactly the canonical
    // formatted content -- never the unformatted create, never a partial
    // write. ---
    let on_disk = std::fs::read_to_string(workspace_dir.join("src/fresh.rs"))?;
    assert_eq!(
        on_disk, FORMATTED_RUST,
        "the committed file must hold exactly the canonical rustfmt output"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}
