// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13 items 3 and 4: real, positive-path `semantic` and
//! `format_preview` MCP tool E2E tests, driven through the real, compiled
//! `corulix mcp stdio` binary as a real child process -- never a direct
//! Rust call into a private tool-handler method, and never a fabricated
//! transport. This is the exact same real client transport
//! (`rmcp::transport::TokioChildProcess`) `wht_corulix_cli`'s own Phase 13
//! `2026-07-28` lifecycle E2E already uses.
//!
//! These two tests provision real managed `rustfmt`/`rust-analyzer`/
//! `rust-semantic-runtime` components (real network, real product
//! manifests, the same `wht_corulix_tooling::provisioning` path every
//! other managed-provider E2E in this workspace uses) into an isolated,
//! disposable directory, redirected via the real, production env vars
//! `wht_corulix_tooling::provisioning::managed_toolchain_root()` actually
//! honors per platform -- `XDG_DATA_HOME` for real users on Linux,
//! `LOCALAPPDATA`/`APPDATA` on Windows (see
//! [`spawn_real_corulix_mcp_stdio`]'s own doc comment for why this suite
//! sets all three unconditionally rather than `XDG_DATA_HOME` alone). The
//! redirection is a plain `tokio::process::Command::env()` call scoped to
//! the spawned child process only -- this workspace's `[workspace.lints.rust]
//! unsafe_code = "forbid"` applies to every crate and every target with no
//! exceptions, so a process-wide `std::env::set_var` is never an option,
//! here or anywhere else. Spawning the real binary sidesteps that
//! entirely: no `unsafe` is needed, and the isolation is exact (each
//! spawned child process gets its own environment).
//!
//! Without this isolation, these tests' own real network provisioning
//! would leave those components resolvable in the real, shared, host-wide
//! managed root for the rest of a full workspace test run, silently
//! flipping unrelated negative-path tests elsewhere (e.g.
//! `wht_corulix_formatter`'s own `ProviderUnavailable` suite, which
//! assumes nothing is provisioned there) from `ProviderUnavailable` to a
//! real, resolved outcome.

use std::path::PathBuf;

use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;

fn temp_root(label: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-mcp-isolated-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&root);
    root
}

/// The `corulix`/`Corulix`-segment managed root this process's own real
/// provisioning calls must use, under an isolated `isolated_data_home`,
/// matching `wht_corulix_tooling::provisioning::managed_toolchain_root()`'s
/// own per-platform casing EXACTLY (lowercase `corulix` under
/// `XDG_DATA_HOME` on Linux, capitalized `Corulix` under `LOCALAPPDATA` on
/// Windows). An ownership record's `canonical_component_root` is compared
/// as a plain string, so this process provisioning under one casing while
/// the spawned child (which inherits `isolated_data_home` via both
/// `XDG_DATA_HOME` and `LOCALAPPDATA`/`APPDATA`, and resolves its own root
/// through the real production function) resolves under the other would
/// make the child treat an already-provisioned component as unresolvable,
/// even though both paths name the identical directory on disk.
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

/// Spawns the real compiled `corulix mcp stdio` binary against
/// `workspace_dir`, with `XDG_DATA_HOME`/`LOCALAPPDATA`/`APPDATA` all
/// redirected to `isolated_data_home` for this child process only -- the
/// real `managed_toolchain_root()` this process resolves therefore lands
/// under `isolated_data_home`'s platform-appropriate join (`corulix/
/// managed-toolchain` on Unix, `Corulix\managed-toolchain` on Windows),
/// never the real, shared, host-wide root, on any platform
/// `managed_toolchain_root()` supports. Returns the connected real MCP
/// client.
///
/// All three vars are set unconditionally, not `XDG_DATA_HOME` alone:
/// `managed_toolchain_root()` (`wht_crates/wht_corulix_tooling/src/
/// provisioning.rs`) never reads `XDG_DATA_HOME` on Windows -- only
/// `LOCALAPPDATA`, falling back to `APPDATA` -- so a Unix-only override
/// silently falls through to the real shared root there instead. Confirmed
/// the hard way during Windows certification, on the near-identical helper
/// this one was mirrored from (`real_setup_command_e2e.rs`/
/// `real_f6_production_managed_provisioning_e2e.rs`). Harmless on
/// platforms that don't consult a given var.
async fn spawn_real_corulix_mcp_stdio(
    workspace_dir: &std::path::Path,
    isolated_data_home: &std::path::Path,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ClientInfo>, Box<dyn std::error::Error>>
{
    // No stable, non-nightly Cargo mechanism exposes another crate's
    // `CARGO_BIN_EXE_<name>` across a crate boundary (`artifact = "bin"`
    // dependencies require the unstable `-Z bindeps`, unavailable on this
    // workspace's pinned stable toolchain) -- `cargo run -p corulix --`
    // is the real, stable, already-workspace-locked way to spawn the real
    // compiled binary as a real child process instead. Cargo's own build
    // progress goes to its stderr, never stdout, so the MCP JSON-RPC
    // stream this test's client reads over the child's stdout is never
    // polluted.
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
            .env("APPDATA", isolated_data_home)
            // Root-cause observability instrumentation (managed LSP-provider
            // lifecycle): `wht_corulix_cli::main` wires
            // `EnvFilter::from_default_env()` to the real binary's own
            // `tracing_subscriber`, which is silent by default with no
            // `RUST_LOG` set -- meaning the `failure_stage`/
            // `internal_failure_kind` diagnostics added to
            // `wht_corulix_lsp`/`wht_corulix_tooling`/`wht_corulix_engine`
            // would never reach this real child process's stderr during a
            // reproduction run without this. `TokioChildProcess`'s default
            // `stderr: Stdio::inherit()` (confirmed via `rmcp`'s own
            // `TokioChildProcessBuilder::new`) already passes that stderr
            // straight through to this test binary's own stderr -- no
            // additional piping/capture code is needed here, only the
            // filter directive that makes the child actually emit
            // something.
            .env(
                "RUST_LOG",
                "wht_corulix_lsp=warn,wht_corulix_tooling=warn,wht_corulix_engine=warn",
            );
    });
    let transport = TokioChildProcess::new(command)?;
    let client_info = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::from_build_env(),
    );
    Ok(client_info.serve(transport).await?)
}

/// Calls `tool_name` with `arguments` (a real JSON object, matching each
/// tool's real `#[serde(deny_unknown_fields)]` input schema exactly)
/// through the real, connected MCP client -- exactly as a real client
/// would (the params DTOs in `wht_corulix_mcp::dto` are intentionally
/// `Deserialize`-only, so this test builds the wire-level JSON directly
/// rather than adding a `Serialize` impl to production request types
/// purely for test convenience).
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

// -----------------------------------------------------------------
// Phase 13 item 4: real, positive-path `format_preview` E2E -- the real
// MCP tool, driven through the real compiled binary over real stdio, the
// real managed `rustfmt` (provisioned for real, real network, real
// product manifests -- the same `wht_corulix_tooling::provisioning` path
// `wht_corulix_formatter`'s own managed E2E suite already uses), a real
// disposable Rust fixture with real unformatted source. Never the live
// Corulix repository itself. Proves `format_preview` genuinely reaches
// `WouldFormat`/`Unchanged`, not merely the previously-only-reachable
// `Unavailable` gate, and that the live fixture file bytes are provably
// untouched (`format_preview` never constructs a `MutationExecutor`).
// -----------------------------------------------------------------

/// Provisions the real, unmodified `rust-semantic-runtime` + `rustfmt`
/// product manifests into `root` -- idempotent (skips a component already
/// `Available`), real network, no test-only manifest. `false` (never
/// panics) on genuine failure so this test can be honestly skipped rather
/// than fail on an environment without real internet access.
async fn ensure_real_managed_rustfmt_provisioned(root: &std::path::Path) -> bool {
    // Host-native manifest selection (mirrors
    // `wht_corulix_formatter::managed::rust_semantic_runtime_host_native`'s
    // own `#[cfg]`-gated-alias pattern, and
    // `wht_corulix_formatter::managed_toolchain::RUSTFMT_HOST_NATIVE`
    // directly): a hardcoded `_LINUX_X64` manifest here would always fail
    // to provision a usable component when this test runs natively on
    // Windows, since the downloaded artifact would never verify/execute as
    // this host's own real toolchain.
    #[cfg(not(target_os = "windows"))]
    use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64 as RUST_SEMANTIC_RUNTIME_HOST_NATIVE;
    #[cfg(target_os = "windows")]
    use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64 as RUST_SEMANTIC_RUNTIME_HOST_NATIVE;
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

#[tokio::test]
async fn real_format_preview_would_format_via_managed_rustfmt_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    // Isolated data-home, never the real shared managed_toolchain_root():
    // this test's own real network provisioning must not leave rustfmt
    // resolvable for unrelated negative-path tests elsewhere in this
    // workspace (e.g. `wht_corulix_formatter`'s own `ProviderUnavailable`
    // suite) that assume nothing is provisioned. Provisioning happens
    // in-process (this test process), against the same isolated root the
    // spawned child process below will also resolve via its own
    // `XDG_DATA_HOME` override.
    let isolated_data_home = temp_root("format-preview-xdg-data-home");
    let managed_root = isolated_managed_root(&isolated_data_home);
    if !ensure_real_managed_rustfmt_provisioned(&managed_root).await {
        eprintln!(
            "SKIPPED real_format_preview_would_format_via_managed_rustfmt_e2e: \
             real managed rustfmt/rust-semantic-runtime provisioning failed \
             (no real internet access in this environment?)"
        );
        return Ok(());
    }

    let workspace_dir = temp_root("format-preview-real");
    let unformatted = b"fn   corulix_marker_format_preview( )   {\n let x=1;\n}\n".to_vec();
    std::fs::write(workspace_dir.join("main.rs"), &unformatted)?;
    let before = std::fs::read(workspace_dir.join("main.rs"))?;

    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home).await?;

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
        "expected a real WouldFormat outcome for genuinely unformatted input, got: {payload}"
    );
    assert!(
        payload["input_hash"] != payload["output_hash"],
        "a real WouldFormat outcome must report distinct input/output hashes"
    );

    // The live fixture file itself must be provably untouched -- a
    // preview, never a write.
    let after = std::fs::read(workspace_dir.join("main.rs"))?;
    assert_eq!(
        before, after,
        "format_preview must never write to the live workspace file"
    );
    assert_eq!(before, unformatted);

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}

// -----------------------------------------------------------------
// Phase 13 item 3: real, positive-path `semantic` E2E -- the real MCP
// tool, driven through the real compiled binary over real stdio, a real,
// managed-first `rust-analyzer` (+ managed Rust semantic runtime, both
// provisioned for real, real network, real product manifests -- the same
// `wht_corulix_tooling::provisioning` path `wht_corulix_lsp`'s own managed
// lifecycle E2E already uses), one real disposable Rust fixture crate.
// Never the live Corulix repository itself. One real session drives all
// four sub-operations (spawning rust-analyzer is expensive; this mirrors
// how a real client would actually use this tool -- one session, many
// calls -- rather than wastefully re-spawning per assertion).
// -----------------------------------------------------------------

fn semantic_fixture(label: &str) -> PathBuf {
    let root = temp_root(label);
    let _ = std::fs::create_dir_all(root.join("src"));
    let _ = std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_mcp_semantic_e2e_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    let _ = std::fs::write(
        root.join("src/main.rs"),
        "fn target() {}\n\nfn caller() {\n    target();\n}\n\nfn main() {\n    caller();\n}\n",
    );
    root
}

/// Provisions the real, unmodified `rust-semantic-runtime` +
/// `rust-analyzer` product manifests into `root` -- idempotent, real
/// network, no test-only manifest. `false` (never panics) on genuine
/// failure.
async fn ensure_real_managed_rust_analyzer_provisioned(root: &std::path::Path) -> bool {
    use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64;
    use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

    let (runtime_state, _) =
        provisioning::resolve_managed_component(root, &RUST_SEMANTIC_RUNTIME_LINUX_X64);
    if runtime_state != ManagedComponentState::Available
        && provisioning::provision(root, &RUST_SEMANTIC_RUNTIME_LINUX_X64)
            .await
            .is_err()
    {
        return false;
    }
    let (ra_state, _) = provisioning::resolve_managed_component(
        root,
        &wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64,
    );
    if ra_state != ManagedComponentState::Available
        && provisioning::provision(
            root,
            &wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64,
        )
        .await
        .is_err()
    {
        return false;
    }
    true
}

#[tokio::test]
async fn real_semantic_definition_references_diagnostics_rename_preview_via_managed_rust_analyzer_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    // Isolated data-home, never the real shared managed_toolchain_root()
    // -- see the comment on the format_preview E2E test above for why.
    let isolated_data_home = temp_root("semantic-xdg-data-home");
    let managed_root = isolated_managed_root(&isolated_data_home);
    // `SemanticOperation::RenamePreview`'s policy entry (`SEMANTIC_RENAME`
    // in `wht_corulix_engine`'s `policy.rs`) also requires
    // `ProviderCategory::Formatter` (rustfmt) in addition to
    // `LanguageServer` -- `TypecheckBuild`/`Linter` are already covered by
    // the same managed Rust semantic runtime rust-analyzer needs (clippy
    // ships bundled in that one manifest), but rustfmt is a separate
    // managed component and must be provisioned into this same isolated
    // root too, or the real rename_preview call below fails closed with
    // `REQUIRED_PROVIDER_UNAVAILABLE`.
    if !ensure_real_managed_rust_analyzer_provisioned(&managed_root).await
        || !ensure_real_managed_rustfmt_provisioned(&managed_root).await
    {
        eprintln!(
            "SKIPPED real_semantic_..._e2e: real managed rust-analyzer/rustfmt/\
             rust-semantic-runtime provisioning failed \
             (no real internet access in this environment?)"
        );
        return Ok(());
    }

    let workspace_dir = semantic_fixture("semantic-real");
    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home).await?;

    // --- DEFINITION: from the `target()` call site (line 3) to its
    // declaration (line 0). ---
    let definition = call_real_tool(
        &service,
        "semantic",
        serde_json::json!({
            "operation": "definition",
            "language": "rust",
            "path": "src/main.rs",
            "line_zero_based": 3,
            "byte_column_zero_based": 4,
            "byte_offset": 0,
        }),
    )
    .await?;
    let definition_payload = structured(&definition).clone();
    assert_eq!(
        definition.is_error,
        Some(false),
        "expected a real definition outcome, got: {definition_payload}"
    );
    assert_eq!(
        definition_payload["status"],
        serde_json::json!("definition"),
        "expected a real Definition outcome, got: {definition_payload}"
    );

    // --- REFERENCES: on `target` at its own declaration site (line 0,
    // col 3) -- this fixture has exactly one real call site. ---
    let references = call_real_tool(
        &service,
        "semantic",
        serde_json::json!({
            "operation": "references",
            "language": "rust",
            "path": "src/main.rs",
            "line_zero_based": 0,
            "byte_column_zero_based": 3,
            "byte_offset": 3,
        }),
    )
    .await?;
    let references_payload = structured(&references).clone();
    assert_eq!(
        references.is_error,
        Some(false),
        "expected a real references outcome, got: {references_payload}"
    );
    assert_eq!(
        references_payload["status"],
        serde_json::json!("references"),
        "expected a real References outcome, got: {references_payload}"
    );
    assert_eq!(
        references_payload["result"]["kind"],
        serde_json::json!("found"),
        "expected Found (not NotReady) after a real, awaited readiness proof, got: {references_payload}"
    );

    // --- DIAGNOSTICS: this fixture is valid Rust, so expect a real,
    // proven (not NotReady) diagnostic set. ---
    let diagnostics = call_real_tool(
        &service,
        "semantic",
        serde_json::json!({
            "operation": "diagnostics",
            "language": "rust",
            "path": "src/main.rs",
            "line_zero_based": 0,
            "byte_column_zero_based": 0,
            "byte_offset": 0,
        }),
    )
    .await?;
    let diagnostics_payload = structured(&diagnostics).clone();
    assert_eq!(
        diagnostics.is_error,
        Some(false),
        "expected a real diagnostics outcome, got: {diagnostics_payload}"
    );
    assert_eq!(
        diagnostics_payload["result"]["kind"],
        serde_json::json!("reported"),
        "expected Reported (not NotReady), got: {diagnostics_payload}"
    );

    // --- RENAME PREVIEW: never applied (`RENAME_PREVIEW_MUTATION_COUNT=0`)
    // -- the live fixture file must be provably untouched. ---
    let before = std::fs::read(workspace_dir.join("src/main.rs"))?;
    let rename_preview = call_real_tool(
        &service,
        "semantic",
        serde_json::json!({
            "operation": "rename_preview",
            "language": "rust",
            "path": "src/main.rs",
            "line_zero_based": 0,
            "byte_column_zero_based": 3,
            "byte_offset": 3,
            "new_name": "renamed_target",
        }),
    )
    .await?;
    let rename_payload = structured(&rename_preview).clone();
    assert_eq!(
        rename_preview.is_error,
        Some(false),
        "expected a real rename_preview outcome, got: {rename_payload}"
    );
    assert_eq!(
        rename_payload["status"],
        serde_json::json!("rename_preview"),
        "expected a real RenamePreview outcome, got: {rename_payload}"
    );
    assert!(
        !rename_payload["result"]["edits_by_path"]
            .as_array()
            .map(Vec::is_empty)
            .unwrap_or(true),
        "expected at least one real proposed rename edit, got: {rename_payload}"
    );
    let after = std::fs::read(workspace_dir.join("src/main.rs"))?;
    assert_eq!(
        before, after,
        "rename_preview must never write to the live workspace file"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}

// -----------------------------------------------------------------
// M09-P8R Section 17-18: real, public-surface root-swap regression --
// the exact same real compiled binary / real stdio MCP transport / real
// managed rust-analyzer as the positive-path test above, but proving the
// LSP root-identity fail-closed contract through the ACTUAL public route
// a client uses (`CorulixMcpServer::semantic` ->
// `CorulixEngine::semantic`/`semantic_at` -> `ensure_rust_lsp_session` ->
// `wht_corulix_lsp::LspSession`/`diagnostics`), never `LspSession`
// directly. This is the public-surface counterpart to
// `wht_corulix_lsp/tests/real_gopls_root_swap_e2e.rs`, which already
// proves the identical contract one layer down, directly against
// `LspSession`.
// -----------------------------------------------------------------

#[tokio::test]
async fn real_semantic_root_swap_after_ready_fails_closed_via_public_mcp_tool_e2e()
-> Result<(), Box<dyn std::error::Error>> {
    let isolated_data_home = temp_root("semantic-root-swap-xdg-data-home");
    let managed_root = isolated_managed_root(&isolated_data_home);
    if !ensure_real_managed_rust_analyzer_provisioned(&managed_root).await {
        eprintln!(
            "SKIPPED real_semantic_root_swap_after_ready_fails_closed_via_public_mcp_tool_e2e: \
             real managed rust-analyzer/rust-semantic-runtime provisioning failed \
             (no real internet access in this environment?)"
        );
        return Ok(());
    }

    let workspace_dir = semantic_fixture("semantic-root-swap-real");
    let service = spawn_real_corulix_mcp_stdio(&workspace_dir, &isolated_data_home).await?;

    let diagnostics_args = serde_json::json!({
        "operation": "diagnostics",
        "language": "rust",
        "path": "src/main.rs",
        "line_zero_based": 0,
        "byte_column_zero_based": 0,
        "byte_offset": 0,
    });

    // Baseline: a real call must succeed while the root is genuinely
    // unmodified -- establishes the session is really live (spawned,
    // initialized, and Ready) before the swap, through the real public
    // `semantic` tool.
    let baseline = call_real_tool(&service, "semantic", diagnostics_args.clone()).await?;
    let baseline_payload = structured(&baseline).clone();
    assert_eq!(
        baseline.is_error,
        Some(false),
        "baseline diagnostics call must succeed before any swap, got: {baseline_payload}"
    );
    assert_eq!(
        baseline_payload["result"]["kind"],
        serde_json::json!("reported"),
        "expected a real Reported diagnostics outcome before the swap, got: {baseline_payload}"
    );

    // Ordinary-directory replacement at the workspace's own canonical
    // pathname, performed AFTER the session already reached `Ready` --
    // the same real-world TOCTOU window `real_gopls_root_swap_e2e.rs`
    // reproduces one layer down, exercised here through the actual public
    // MCP tool surface a client calls.
    let moved_away = std::env::temp_dir().join(format!(
        "corulix-mcp-semantic-root-swap-e2e-moved-{}",
        std::process::id()
    ));
    std::fs::rename(&workspace_dir, &moved_away)?;
    std::fs::create_dir_all(&workspace_dir)?;

    let after_swap = call_real_tool(&service, "semantic", diagnostics_args.clone()).await?;
    let after_swap_payload = structured(&after_swap).clone();
    assert_eq!(
        after_swap.is_error,
        Some(true),
        "expected a fail-closed outcome immediately after the swap, got: {after_swap_payload}"
    );
    assert_eq!(
        after_swap_payload["status"],
        serde_json::json!("request_failed"),
        "expected RequestFailed after the observed root-identity mismatch, got: {after_swap_payload}"
    );
    assert_eq!(
        after_swap_payload["reason_code"],
        serde_json::json!("REQUIRED_PROVIDER_UNAVAILABLE"),
        "expected RequiredProviderUnavailable as the mapped reason code, got: {after_swap_payload}"
    );

    // Sticky (Section 18), proven through the SAME public tool: a second
    // call, still with the impostor directory in place, must also fail
    // closed -- this session must never be silently reused after an
    // observed mismatch, even via the public route.
    let second_call = call_real_tool(&service, "semantic", diagnostics_args.clone()).await?;
    let second_call_payload = structured(&second_call).clone();
    assert_eq!(
        second_call.is_error,
        Some(true),
        "expected the second post-swap call to also fail closed, got: {second_call_payload}"
    );
    assert_eq!(
        second_call_payload["reason_code"],
        serde_json::json!("REQUIRED_PROVIDER_UNAVAILABLE"),
        "expected the second post-swap call to keep reporting RequiredProviderUnavailable, got: \
         {second_call_payload}"
    );

    service.cancel().await?;
    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&moved_away);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}

// -----------------------------------------------------------------
// Root-cause observability instrumentation: negative control proving the
// real, end-to-end diagnostic pipeline actually surfaces a
// `failure_stage`/`internal_failure_kind` event on this real child
// process's stderr -- never assumed from source inspection alone. The
// unit tests added alongside this instrumentation
// (`wht_corulix_lsp::profile::tests::corrupt_ownership_record_emits_managed_ownership_validation_diagnostic`)
// prove the Rust-level `tracing::warn!` call fires; this test proves the
// separate, real chain a bounded reproduction run actually depends on:
// `RUST_LOG` env var -> `wht_corulix_cli::main`'s
// `EnvFilter::from_default_env()` -> `tracing_subscriber::fmt()` ->
// this real child process's own stderr -> inherited (by default) or
// piped (here, deliberately) to this test's own process. Without this
// test, "zero failure_stage lines across N bounded-reproduction runs"
// would be indistinguishable from "the pipeline is silently broken" --
// this closes exactly that gap.
// -----------------------------------------------------------------

#[tokio::test]
async fn real_corrupt_managed_rust_analyzer_ownership_surfaces_failure_stage_on_real_child_stderr()
-> Result<(), Box<dyn std::error::Error>> {
    let isolated_data_home = temp_root("observability-negative-control");
    let managed_root = isolated_managed_root(&isolated_data_home);

    // Fabricate a present-but-corrupt managed `rust-analyzer` artifact --
    // no real network acquisition needed, mirrors the exact technique
    // already proven at unit level in `wht_corulix_lsp::profile`'s own
    // `corrupt_ownership_record_emits_managed_ownership_validation_diagnostic`.
    let manifest = &wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64;
    let install_dir =
        wht_corulix_tooling::provisioning::component_install_dir(&managed_root, manifest);
    let binary_path = install_dir.join(manifest.source.binary_path_in_tarball);
    std::fs::create_dir_all(binary_path.parent().unwrap_or(&install_dir))?;
    std::fs::write(&binary_path, b"fixture binary contents")?;
    let ownership_dir = managed_root.join("ownership");
    std::fs::create_dir_all(&ownership_dir)?;
    std::fs::write(
        ownership_dir.join(format!("{}.json", manifest.id.0)),
        b"{ not valid json at all",
    )?;

    let workspace_dir = semantic_fixture("observability-negative-control");

    // Deliberately bypasses `spawn_real_corulix_mcp_stdio` (default
    // `stderr: Stdio::inherit()`) to pipe and capture the real child's
    // stderr instead -- everything else (args/env) mirrors that helper
    // exactly.
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
            .arg(&workspace_dir)
            .env("XDG_DATA_HOME", &isolated_data_home)
            .env("LOCALAPPDATA", &isolated_data_home)
            .env("APPDATA", &isolated_data_home)
            .env(
                "RUST_LOG",
                "wht_corulix_lsp=warn,wht_corulix_tooling=warn,wht_corulix_engine=warn",
            );
    });
    let (transport, stderr) = TokioChildProcess::builder(command)
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let captured_stderr = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    if let Some(stderr) = stderr {
        let captured_stderr = captured_stderr.clone();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(mut buffer) = captured_stderr.lock() {
                    buffer.push_str(&line);
                    buffer.push('\n');
                }
            }
        });
    }
    let client_info = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::from_build_env(),
    );
    let service = client_info.serve(transport).await?;

    let outcome = call_real_tool(
        &service,
        "semantic",
        serde_json::json!({
            "operation": "diagnostics",
            "language": "rust",
            "path": "src/main.rs",
            "line_zero_based": 0,
            "byte_column_zero_based": 0,
            "byte_offset": 0,
        }),
    )
    .await?;
    let outcome_payload = structured(&outcome).clone();
    assert_eq!(
        outcome.is_error,
        Some(true),
        "expected the corrupt managed artifact to fail closed, got: {outcome_payload}"
    );
    assert_eq!(
        outcome_payload["reason_code"],
        serde_json::json!("REQUIRED_PROVIDER_UNAVAILABLE"),
        "expected RequiredProviderUnavailable (public contract unchanged), got: {outcome_payload}"
    );

    service.cancel().await?;
    // Give the stderr-draining task a moment to catch up with the
    // already-exited child before reading the buffer.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let stderr_text = captured_stderr
        .lock()
        .map_err(|_| "captured-stderr mutex poisoned")?
        .clone();
    assert!(
        stderr_text.contains("failure_stage=\"MANAGED_OWNERSHIP_VALIDATION\"")
            || stderr_text.contains("failure_stage=MANAGED_OWNERSHIP_VALIDATION"),
        "expected the real child's own stderr to carry the \
         MANAGED_OWNERSHIP_VALIDATION diagnostic proving the real \
         RUST_LOG -> EnvFilter -> tracing_subscriber -> stderr chain is \
         actually wired end-to-end (not just proven at the Rust-unit \
         level) -- captured stderr was:\n{stderr_text}"
    );

    let _ = std::fs::remove_dir_all(&workspace_dir);
    let _ = std::fs::remove_dir_all(&isolated_data_home);
    Ok(())
}
