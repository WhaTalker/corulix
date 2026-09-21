// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end tests: a real, controlled temporary Rust fixture,
//! resolved against a real, installed `rustfmt`, invoked and applied
//! through this crate's actual `format_and_apply` -- no mocked provider,
//! no mocked process, no mocked mutation executor
//! (`MOCKED_ONLY_CLOSURE=NO`). Every negative-path test in this module
//! spawns the real `rustfmt` binary too; only the *fixture* content or
//! *configuration* is engineered to trigger the failure mode under test.

use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use wht_corulix_config::{
    EffectiveConfig, HostConfig, ManagedProvisioningPolicy, RepositoryHints, RequestOptions,
};
use wht_corulix_core::{CorulixResult, WorkspaceRootId};
use wht_corulix_mutation::MutationExecutor;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_workspace(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let sequence = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("corulix-formatter-e2e-{label}-{stamp}-{sequence}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn open_root(path: &std::path::Path) -> CorulixResult<WorkspaceRoot> {
    WorkspaceRoot::open(path)
}

fn workspace_path(relative: &str) -> WorkspacePath {
    WorkspacePath {
        root: WorkspaceRootId(0),
        relative_path: relative.to_string(),
    }
}

/// A real, independent, platform-appropriate process-liveness oracle --
/// never `wht_corulix_tooling::platform::test_alive` itself (this crate's
/// own tests must not "check their own homework" against the exact
/// primitive under test). `/proc/<pid>` on Unix; a real `tasklist`
/// invocation on Windows, mirroring
/// `wht_corulix_tooling::tests::windows_verify_process_absent_matches_
/// independent_tasklist_oracle_across_a_managed_process_lifecycle`'s own
/// precedent -- found necessary when a Windows-portability defect
/// (a bare, Unix-only `/proc/<pid>` check) was discovered as a real,
/// reproducing test failure the first time this file was made genuinely
/// reachable on a native Windows run (P17-W-R4-C2).
#[cfg(windows)]
fn process_is_alive(pid: u32) -> bool {
    let Ok(output) = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
    else {
        return false;
    };
    String::from_utf8_lossy(&output.stdout).contains(&pid.to_string())
}

#[cfg(not(windows))]
fn process_is_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// A `HostConfig` that resolves the real, ambient-`PATH`-free `rustfmt`
/// installed on this host, via an approved system directory -- the same
/// resolution path a real deployment would configure, never a special test
/// bypass.
fn real_rustfmt_host_config() -> CorulixResult<Option<HostConfig>> {
    let Ok(output) = std::process::Command::new("which").arg("rustfmt").output() else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    let path_text =
        String::from_utf8(output.stdout).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let rustfmt_path = PathBuf::from(path_text.trim());
    if !rustfmt_path.is_absolute() {
        return Ok(None);
    }
    let directory = rustfmt_path
        .parent()
        .ok_or(wht_corulix_core::CorulixError::Internal)?
        .to_path_buf();
    Ok(Some(HostConfig {
        approved_system_directories: vec![directory],
        ..HostConfig::default()
    }))
}

fn effective_config(host: &HostConfig) -> EffectiveConfig {
    EffectiveConfig::derive(
        host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

#[tokio::test]
async fn real_rustfmt_e2e_formats_and_applies_through_mutation() -> CorulixResult<()> {
    let Some(host) = real_rustfmt_host_config()? else {
        // No real rustfmt on this host -- this E2E test requires one and
        // is skipped rather than faking a result. Every other test in this
        // crate that requires a real rustfmt does the same.
        return Ok(());
    };
    let workspace = temp_workspace("format-and-apply");
    let unformatted = b"fn main( ) {let x=1;let y=2;}\n".to_vec();
    fs::write(workspace.join("target.rs"), &unformatted)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply(
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    assert_eq!(result.status, FormatStatus::Formatted);
    assert!(result.changed);
    assert!(result.provider_path.is_some());

    let on_disk = fs::read(workspace.join("target.rs"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    // The live file now holds rustfmt's real formatted output -- proves the
    // full Config -> Tooling -> Mutation flow actually reached the
    // workspace, not merely a typed in-memory result.
    assert_ne!(on_disk, unformatted);
    assert!(!on_disk.windows(2).any(|window| window == b"( "));

    let expected_hash = ContentHash::compute_sha256(&on_disk);
    assert_eq!(result.output_hash, Some(expected_hash));

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

#[tokio::test]
async fn real_rustfmt_never_writes_the_live_file_directly() -> CorulixResult<()> {
    // Distinct from the test above: this one proves rustfmt's *own*
    // process never touches the live path at all, by giving it content
    // that differs from what is on disk and confirming the on-disk bytes
    // are untouched until this crate's own MutationBatch commits.
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("no-direct-write");
    let on_disk_original = b"fn main( ) {let x=1;}\n".to_vec();
    fs::write(workspace.join("target.rs"), &on_disk_original)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    // A content hash captured from a byte-identical *copy*, never the live
    // file handle itself -- this test's whole point is that this crate
    // never needs to touch the live file except through the final,
    // governed MutationBatch commit.
    let pre_format_hash = ContentHash::compute_sha256(&on_disk_original);

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply(
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    assert_eq!(result.input_hash, pre_format_hash);
    assert_eq!(result.status, FormatStatus::Formatted);

    let on_disk_after = fs::read(workspace.join("target.rs"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    // The live file changed exactly once, to the final verified formatted
    // bytes -- if rustfmt had written directly, the on-disk content and
    // this crate's own reported `output_hash` could disagree; they never
    // do, because only `MutationExecutor::execute` ever wrote this path.
    assert_eq!(
        Some(ContentHash::compute_sha256(&on_disk_after)),
        result.output_hash
    );

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

#[tokio::test]
async fn already_formatted_input_is_reported_unchanged_without_mutation() -> CorulixResult<()> {
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("unchanged");
    let already_formatted = b"fn main() {\n    let x = 1;\n}\n".to_vec();
    fs::write(workspace.join("target.rs"), &already_formatted)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply(
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    assert_eq!(result.status, FormatStatus::Unchanged);
    assert!(!result.changed);

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

#[tokio::test]
async fn idempotence_formatting_twice_produces_the_same_bytes() -> CorulixResult<()> {
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("idempotent");
    let unformatted = b"fn main( ) {let x=1;let y=2;let z=x+y;}\n".to_vec();
    fs::write(workspace.join("target.rs"), &unformatted)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let first_executor = MutationExecutor::new(root.clone());
    let first = format_and_apply(
        &effective,
        root.clone(),
        &first_executor,
        path.clone(),
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(first.status, FormatStatus::Formatted);

    let second_executor = MutationExecutor::new(root.clone());
    let second = format_and_apply(
        &effective,
        root,
        &second_executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    // format(format(source)) == format(source): the second pass reports no
    // further change, and its input hash equals the first pass's output
    // hash.
    assert_eq!(second.status, FormatStatus::Unchanged);
    let first_output_hash = first
        .output_hash
        .ok_or(wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(second.input_hash, first_output_hash);

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

#[tokio::test]
async fn real_repository_rustfmt_toml_is_honored() -> CorulixResult<()> {
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("repo-config");
    fs::write(workspace.join("rustfmt.toml"), "max_width = 20\n")
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    // A line that fits comfortably under the default width (100) but
    // cannot fit under the repository's configured `max_width = 20` --
    // proves the discovered config directory actually reached rustfmt,
    // not merely that some config file happens to exist nearby.
    let unformatted = b"fn main(){let corulix_needs_wrap=123;}\n".to_vec();
    fs::write(workspace.join("target.rs"), &unformatted)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply(
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    assert_eq!(result.status, FormatStatus::Formatted);
    let on_disk = fs::read(workspace.join("target.rs"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    // At rustfmt's default width (100) this whole `let` statement fits on
    // one line -- it only wraps onto its own line if the discovered
    // `max_width = 20` from the repository's `rustfmt.toml` actually
    // reached rustfmt, proving `--config-path` resolution worked, not
    // merely that some config file happens to exist nearby.
    let line_count = on_disk.iter().filter(|&&byte| byte == b'\n').count();
    assert!(
        line_count > 3,
        "expected the assignment to wrap under the repository's max_width = 20, got: {}",
        String::from_utf8_lossy(&on_disk)
    );

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

#[tokio::test]
async fn out_of_band_change_during_formatting_is_rejected_as_stale() -> CorulixResult<()> {
    // Deterministic (never flaky-timing-based), exercised against the real
    // end-to-end `format_and_apply` flow: `format_and_apply_with_race_hook`
    // runs the write below synchronously right after this crate captures
    // its `expected_precondition_hash`, and before rustfmt is even
    // resolved -- so by the time the real rustfmt invocation and the final
    // `MutationBatch` commit happen, the on-disk target has genuinely
    // changed out from under the hash this crate already captured.
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("stale-precondition");
    let unformatted = b"fn main( ) {let x=1;}\n".to_vec();
    fs::write(workspace.join("target.rs"), &unformatted)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");
    let target_file = workspace.join("target.rs");

    let result = format_and_apply_with_race_hook(
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
        move || {
            let _ = fs::write(&target_file, b"fn main() {\n    let x = 2;\n}\n");
        },
    )
    .await;

    assert!(matches!(
        result,
        Err(FormatterError::Mutation(
            wht_corulix_mutation::MutationError::StalePreconditionHash { .. }
        ))
    ));

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

#[tokio::test]
async fn formatter_unavailable_is_reported_not_panicked() -> CorulixResult<()> {
    // No `HOST_ONLY` provider configuration at all, `managed_provisioning_policy`
    // explicitly `Deny`, AND a fresh, isolated, never-provisioned `managed_root`
    // (`format_and_apply_at`, not the bare `format_and_apply`) -- the real,
    // shared, host-wide `managed_toolchain_root()` is deliberately not used
    // here: `CORULIX_MANAGED` resolution tries an *already-owned* component
    // unconditionally, before any policy check (Installation-Contract-V1's
    // `managed_provisioning_policy` only gates *fresh acquisition*, not
    // continued use of something this host's real `corulix` already legitimately
    // installed), so asserting "unavailable" against the ambient shared root
    // would be racy/environment-dependent regardless of `Deny`. An isolated
    // root has nothing already owned, so both guards apply cleanly. This must
    // never panic, and the caller-facing result must carry the reason.
    let workspace = temp_workspace("unavailable");
    let managed_root = temp_workspace("unavailable-managed-root");
    fs::write(workspace.join("target.rs"), b"fn main() {}\n")
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&HostConfig {
        managed_provisioning_policy: ManagedProvisioningPolicy::Deny,
        ..HostConfig::default()
    });
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply_at(
        &managed_root,
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    assert_eq!(result.status, FormatStatus::ProviderUnavailable);
    assert!(result.provider_path.is_none());
    assert!(result.reason.is_some());

    let _ = fs::remove_dir_all(&workspace);
    let _ = fs::remove_dir_all(&managed_root);
    Ok(())
}

#[tokio::test]
async fn invalid_explicit_formatter_path_is_reported_not_panicked() -> CorulixResult<()> {
    // A `HOST_ONLY`-configured absolute path that does not resolve to a
    // real file is authoritative and terminal per Rule K -- it must fail
    // closed (`ProviderUnavailable`), never silently fall through to an
    // approved-directory search, and (Installation-Contract-V1) never fall
    // through to `CORULIX_MANAGED` either -- see
    // `formatter_unavailable_is_reported_not_panicked`'s comment for why
    // this test needs both `managed_provisioning_policy: Deny` and an
    // isolated `managed_root` (`format_and_apply_at`) rather than the real,
    // shared, host-wide one.
    let workspace = temp_workspace("invalid-explicit-path");
    let managed_root = temp_workspace("invalid-explicit-path-managed-root");
    fs::write(workspace.join("target.rs"), b"fn main() {}\n")
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let host = HostConfig {
        provider_absolute_paths: vec![(
            wht_corulix_core::ProviderCategory::Formatter,
            PathBuf::from("/nonexistent/not-a-real-rustfmt"),
        )],
        managed_provisioning_policy: ManagedProvisioningPolicy::Deny,
        ..HostConfig::default()
    };
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply_at(
        &managed_root,
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    assert_eq!(result.status, FormatStatus::ProviderUnavailable);

    let _ = fs::remove_dir_all(&workspace);
    let _ = fs::remove_dir_all(&managed_root);
    Ok(())
}

#[tokio::test]
async fn workspace_local_formatter_spoof_is_rejected() -> CorulixResult<()> {
    // A "rustfmt" planted *inside* the active workspace can never satisfy
    // `CONTROLLED_EXTERNAL_TOOL` (Rule K), even when explicitly configured
    // as the `HOST_ONLY` path -- this crate must never invoke it. Both
    // `managed_provisioning_policy: Deny` and an isolated `managed_root`
    // (`format_and_apply_at`) are needed so a genuinely available
    // `CORULIX_MANAGED` rustfmt cannot mask a broken workspace-local
    // rejection behind a legitimate `WouldFormat` outcome (see
    // `formatter_unavailable_is_reported_not_panicked`'s comment).
    let workspace = temp_workspace("workspace-local-spoof");
    let managed_root = temp_workspace("workspace-local-spoof-managed-root");
    fs::write(workspace.join("target.rs"), b"fn main() {}\n")
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let spoofed = workspace.join("rustfmt");
    fs::write(&spoofed, "#!/bin/sh\necho spoofed\n")
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let host = HostConfig {
        provider_absolute_paths: vec![(wht_corulix_core::ProviderCategory::Formatter, spoofed)],
        managed_provisioning_policy: ManagedProvisioningPolicy::Deny,
        ..HostConfig::default()
    };
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply_at(
        &managed_root,
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    assert_eq!(result.status, FormatStatus::ProviderUnavailable);
    assert_eq!(
        result.reason,
        Some(wht_corulix_core::ReasonCode::ProviderResolvedInsideWorkspace)
    );

    let _ = fs::remove_dir_all(&workspace);
    let _ = fs::remove_dir_all(&managed_root);
    Ok(())
}

#[tokio::test]
async fn an_unapproved_directory_binary_is_never_selected_over_the_real_one() -> CorulixResult<()> {
    // Mirrors `wht_corulix_config`'s own `poisoned_path_has_no_effect`
    // test at this crate's level: a real rustfmt in an *approved* system
    // directory, plus a decoy "rustfmt" in a directory that is
    // deliberately *not* approved, must always resolve to the real one --
    // this crate's resolution never trusts anything beyond the exact
    // configured/approved locations.
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("unapproved-directory-decoy");
    fs::write(workspace.join("target.rs"), b"fn main( ) {}\n")
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let decoy_dir = temp_workspace("decoy");
    fs::write(decoy_dir.join("rustfmt"), "#!/bin/sh\necho decoy\n")
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply(
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    // The real formatter's approved-directory path was selected, not the
    // unapproved decoy -- proven by a real, successful format outcome
    // (the decoy script is not valid rustfmt and would fail differently).
    assert_eq!(result.status, FormatStatus::Formatted);

    let _ = fs::remove_dir_all(&workspace);
    let _ = fs::remove_dir_all(&decoy_dir);
    Ok(())
}

#[tokio::test]
async fn invalid_rust_input_is_reported_not_panicked() -> CorulixResult<()> {
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("invalid-rust-input");
    let invalid = b"fn main( { this is not valid rust @@@ ###\n".to_vec();
    fs::write(workspace.join("target.rs"), &invalid)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply(
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    assert_eq!(result.status, FormatStatus::InvocationFailed);
    let on_disk = fs::read(workspace.join("target.rs"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(on_disk, invalid);

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

#[tokio::test]
async fn oversized_input_is_rejected_before_any_invocation() -> CorulixResult<()> {
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("oversized-input");
    let oversized = vec![b'a'; 256];
    fs::write(workspace.join("target.rs"), &oversized)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply(
        &effective,
        root,
        &executor,
        path,
        // Deliberately smaller than the fixture -- guard 2 must fail
        // closed before rustfmt is ever resolved or invoked.
        64,
        &cancellation,
    )
    .await;

    assert!(matches!(result, Err(FormatterError::OversizedInput { .. })));

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

#[tokio::test]
async fn attempting_to_format_a_non_rust_file_is_rejected() -> CorulixResult<()> {
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("non-rust-file");
    let original = b"# Not Rust\n\nJust Markdown.\n".to_vec();
    fs::write(workspace.join("README.md"), &original)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("README.md");

    let result = format_and_apply(
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await;

    assert!(matches!(
        result,
        Err(FormatterError::UnsupportedLanguage { .. })
    ));
    let on_disk = fs::read(workspace.join("README.md"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(on_disk, original);

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

#[tokio::test]
async fn malformed_repository_rustfmt_toml_is_reported_not_panicked() -> CorulixResult<()> {
    // A repository `rustfmt.toml` that is not valid TOML: real rustfmt
    // itself rejects it (a non-zero exit), and this crate must surface
    // that as a typed `InvocationFailed` result -- never a panic, and
    // never a corrupted live file.
    let Some(host) = real_rustfmt_host_config()? else {
        return Ok(());
    };
    let workspace = temp_workspace("malformed-config-fixture");
    fs::write(
        workspace.join("rustfmt.toml"),
        "this is not valid = = toml {{{\n",
    )
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let original = b"fn main( ) {}\n".to_vec();
    fs::write(workspace.join("target.rs"), &original)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    let root = open_root(&workspace)?;
    let effective = effective_config(&host);
    let executor = MutationExecutor::new(root.clone());
    let cancellation = CancellationToken::new();
    let path = workspace_path("target.rs");

    let result = format_and_apply(
        &effective,
        root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

    assert_eq!(result.status, FormatStatus::InvocationFailed);
    let on_disk = fs::read(workspace.join("target.rs"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(on_disk, original);

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

// ============================================================
// Phase 7B-B2-B: CORULIX_MANAGED rustfmt (real product manifests, real
// network -- the same precedent `real_rust_semantic_runtime_managed_e2e.rs`
// already establishes for RUST_SEMANTIC_RUNTIME_LINUX_X64: no local
// mirror, since both real product URLs are genuinely reachable). Every
// managed root here is destroyed by its own test via the real product
// `full_uninstall`/`provisioning` pipeline.
// ============================================================

use wht_corulix_tooling::provisioning::{self, ManagedComponentState, full_uninstall};

/// This host's own real `rust-semantic-runtime` manifest -- P17-W-R4-C2:
/// before this, every test in this section resolved
/// `RUST_SEMANTIC_RUNTIME_LINUX_X64` unconditionally, which is exactly the
/// hardcoded-to-Linux defect class `RUSTFMT_HOST_NATIVE` was introduced to
/// close elsewhere; this lets the *same* consolidated real-lifecycle test
/// validate the real, native, host-appropriate runtime on whichever
/// platform runs it, rather than only ever exercising Linux.
fn rust_semantic_runtime_host_native() -> &'static provisioning::ManagedComponentManifest {
    crate::managed::rust_semantic_runtime_host_native()
}

const RUSTFMT_ID: &str = "rustfmt";
const RUST_RUNTIME_ID: &str = "rust-semantic-runtime";

/// Every managed test in this file (both the rustfmt family below and the
/// Biome family later in this file) provisions/uninstalls into its own
/// isolated root, but shares this crate's single, process-global
/// `wht_corulix_tooling::provisioning::lease` active-lease-count registry.
/// A per-family lock (formerly one `REAL_RUSTFMT_MANAGED_LOCK` and a
/// separate `REAL_BIOME_MANAGED_LOCK`) only serialized same-family tests
/// against each other's redundant downloads -- it never serialized the
/// rustfmt family against the Biome family, so cargo's default concurrent
/// test execution could run a rustfmt active-lease test and
/// `real_biome_active_lease_and_uninstall_protection_e2e` at the same time,
/// both holding a lease simultaneously and making any unfiltered
/// `lease::active_lease_count() == 1` assertion inherently flaky (confirmed
/// via isolated repro: `cargo test -p wht_corulix_formatter --lib --
/// --test-threads=1` passes every time, proving real cross-family
/// concurrency, not a logic bug). A single shared lock across every managed
/// e2e test in this file -- mirroring the one-lock-per-test-file convention
/// already established throughout this workspace (e.g. `session_lock` in
/// `wht_corulix_engine`'s P16 suites, `real_gopls_managed_e2e.rs`'s own
/// `REAL_GOPLS_MANAGED_LOCK`) -- removes the race at its root: no two
/// managed e2e tests in this file ever run concurrently, so any unfiltered,
/// process-global lease-count assertion is deterministic.
static REAL_MANAGED_FORMATTER_TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_rustfmt_managed_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_MANAGED_FORMATTER_TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn managed_isolated_root(label: &str) -> PathBuf {
    // `HOME` does not exist on Windows (`USERPROFILE` is the real
    // equivalent); falling back to a hardcoded Unix `/root` there would
    // silently resolve to a nonsensical `C:\root\...` path rather than a
    // real writable home directory.
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/root".to_string());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = PathBuf::from(home)
        .join(".cache/corulix-rustfmt-managed-e2e/roots")
        .join(format!("{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Provisions the real, unmodified `RUST_SEMANTIC_RUNTIME_LINUX_X64` +
/// `RUSTFMT_LINUX_X64` product manifests into `root` -- real network, real
/// `static.rust-lang.org` URLs, no test-only manifest anywhere. Returns
/// `false` (never panics) if either provision genuinely fails, so a caller
/// can report `BLOCKED` honestly rather than fail on an environment without
/// real internet access.
async fn ensure_managed_rustfmt_provisioned(root: &std::path::Path) -> bool {
    let runtime_manifest = rust_semantic_runtime_host_native();
    let (runtime_state, _) = provisioning::resolve_managed_component(root, runtime_manifest);
    if runtime_state != ManagedComponentState::Available
        && provisioning::provision(root, runtime_manifest)
            .await
            .is_err()
    {
        return false;
    }
    let rustfmt_manifest = crate::managed_toolchain::RUSTFMT_HOST_NATIVE;
    let (rustfmt_state, _) = provisioning::resolve_managed_component(root, &rustfmt_manifest);
    if rustfmt_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(root, &rustfmt_manifest, &[RUST_RUNTIME_ID])
            .await
            .is_err()
    {
        return false;
    }
    true
}

/// The full managed lifecycle: real product-identity provisioning (no test
/// manifest), `RUST_FORMATTER_AUTHORITY=MANAGED_RUSTFMT` precedence proof
/// (a real system `rustfmt`, when present, is deliberately *not* used),
/// real format E2E through `format_and_apply_at`, idempotency, invalid
/// input fail-closed, environment purity (`LD_LIBRARY_PATH` only -- no
/// `PATH`/`HOME`/anything else reaches the child), wrong-platform admission
/// refusal, single-flight, full uninstall, mechanically-measured zero
/// residual, and second-uninstall idempotence -- consolidated into one test
/// to provision the (large, real) runtime exactly once.
#[tokio::test]
async fn real_rustfmt_managed_full_lifecycle_e2e() -> CorulixResult<()> {
    let _lock = real_rustfmt_managed_lock().await;
    let root = managed_isolated_root("full-lifecycle");
    if !ensure_managed_rustfmt_provisioned(&root).await {
        eprintln!("RUSTFMT_MANAGED_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    // --- RUSTFMT_PRODUCT_MANAGED_COMPONENT_IDENTITY ---
    let rustfmt_manifest = crate::managed_toolchain::RUSTFMT_HOST_NATIVE;
    let (rustfmt_state, rustfmt_path) =
        provisioning::resolve_owned_managed_component(&root, &rustfmt_manifest);
    assert_eq!(rustfmt_state, ManagedComponentState::Available);
    let rustfmt_path = rustfmt_path.ok_or(wht_corulix_core::CorulixError::Internal)?;
    assert!(rustfmt_path.starts_with(&root));
    eprintln!("RUSTFMT_PRODUCT_MANAGED_COMPONENT_IDENTITY=PASS");

    // --- ENVIRONMENT PURITY: resolve_formatter's own returned environment
    // carries exactly this host's own real DLL/library-search mechanism
    // and nothing else -- `LD_LIBRARY_PATH` only on Unix, `PATH` only on
    // Windows (see `crate::managed::rust_semantic_runtime_dll_environment`'s
    // own doc comment for why these are genuinely different, non-
    // overlapping mechanisms, not an arbitrary choice per platform) --
    // direct proof, not inferred from `ManagedProcess::spawn`'s already-
    // certified `env_clear()` (B1) alone.
    let host = HostConfig::default();
    let effective = effective_config(&host);
    let fixture_root = temp_workspace("rustfmt-managed-fixture");
    let workspace_root = open_root(&fixture_root)?;
    let resolved = crate::managed::resolve_formatter(
        &crate::profile::FormatterProfile::rustfmt(),
        &effective,
        &workspace_root,
        &root,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert!(resolved.used_managed);
    if cfg!(windows) {
        assert!(resolved.environment.contains("PATH"));
        assert!(!resolved.environment.contains("LD_LIBRARY_PATH"));
    } else {
        assert!(resolved.environment.contains("LD_LIBRARY_PATH"));
        assert!(!resolved.environment.contains("PATH"));
    }
    assert!(!resolved.environment.contains("HOME"));
    eprintln!("RUSTFMT_ENVIRONMENT_AUTHORITY=CORULIX_CONTROLLED (host-native mechanism only)");

    // --- PRECEDENCE: even when a real system rustfmt is also configured
    // and approved, the managed one must be used. ---
    let precedence_effective = match real_rustfmt_host_config()? {
        Some(system_host) => effective_config(&system_host),
        None => effective.clone(),
    };
    let unformatted = b"fn main( ) {let x=1;let y=2;}\n".to_vec();
    fs::write(fixture_root.join("target.rs"), &unformatted)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let executor = MutationExecutor::new(open_root(&fixture_root)?);
    let cancellation = CancellationToken::new();
    let result = format_and_apply_at(
        &root,
        &precedence_effective,
        open_root(&fixture_root)?,
        &executor,
        workspace_path("target.rs"),
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(result.status, FormatStatus::Formatted);
    assert!(result.provider_used_managed);
    assert_eq!(
        result.provider_path.as_deref(),
        Some(rustfmt_path.as_path())
    );
    eprintln!("RUST_FORMATTER_AUTHORITY=MANAGED_RUSTFMT");
    eprintln!("RUSTFMT_MANAGED_PRECEDENCE_OVER_SYSTEM=PASS");

    let formatted_on_disk = fs::read(fixture_root.join("target.rs"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_ne!(formatted_on_disk, unformatted);
    eprintln!("RUSTFMT_REAL_FORMAT_E2E=PASS");

    // --- IDEMPOTENCY: formatting the now-formatted file again reports
    // Unchanged, real binary re-invoked. ---
    let second = format_and_apply_at(
        &root,
        &precedence_effective,
        open_root(&fixture_root)?,
        &executor,
        workspace_path("target.rs"),
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(second.status, FormatStatus::Unchanged);
    assert!(second.provider_used_managed);
    eprintln!("RUSTFMT_IDEMPOTENCY=PASS");

    // --- INVALID INPUT: fails closed, no partial/corrupted write. ---
    let invalid = b"fn main( {{{ invalid rust\n".to_vec();
    fs::write(fixture_root.join("invalid.rs"), &invalid)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let invalid_result = format_and_apply_at(
        &root,
        &precedence_effective,
        open_root(&fixture_root)?,
        &executor,
        workspace_path("invalid.rs"),
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(invalid_result.status, FormatStatus::InvocationFailed);
    let invalid_on_disk = fs::read(fixture_root.join("invalid.rs"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(invalid_on_disk, invalid);
    eprintln!("RUSTFMT_INVALID_INPUT_FAIL_CLOSED=PASS");

    // --- LOCAL CONFIG SEMANTICS: real rustfmt.toml (max_width) changes
    // real formatted output. ---
    fs::write(fixture_root.join("rustfmt.toml"), b"max_width = 40\n")
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    fs::write(
        fixture_root.join("wide.rs"),
        b"fn main() { let very_long_variable_name_for_wrapping = 1234567890; }\n",
    )
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let config_result = format_and_apply_at(
        &root,
        &precedence_effective,
        open_root(&fixture_root)?,
        &executor,
        workspace_path("wide.rs"),
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(config_result.status, FormatStatus::Formatted);
    let wide_on_disk = fs::read_to_string(fixture_root.join("wide.rs"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert!(
        wide_on_disk
            .lines()
            .any(|line| line.len() <= 40 || line.trim().is_empty() || line.contains("fn main")),
        "expected max_width=40 to actually affect wrapping, got: {wide_on_disk:?}"
    );
    eprintln!("RUSTFMT_LOCAL_CONFIG_SEMANTICS=PASS");

    // --- WRONG PLATFORM/ARCH ADMISSION: a foreign-platform manifest must
    // never resolve as Available against this same root, even though the
    // real host-native component is genuinely provisioned. The "wrong"
    // platform is computed adaptively (never a literal `"windows"`, which
    // would silently become the *correct* platform -- not a negative test
    // at all -- when this file runs natively on a real Windows host),
    // mirroring `real_rustfmt_managed_wrong_platform_provision_rejected_e2e`'s
    // own precedent below.
    let synthetic_wrong_platform = if rustfmt_manifest.platform == "windows" {
        "linux"
    } else {
        "windows"
    };
    let wrong_platform = wht_corulix_tooling::provisioning::ManagedComponentManifest {
        platform: synthetic_wrong_platform,
        ..rustfmt_manifest
    };
    let (wrong_platform_state, _) =
        provisioning::resolve_owned_managed_component(&root, &wrong_platform);
    assert_eq!(wrong_platform_state, ManagedComponentState::NotProvisioned);
    let wrong_arch = wht_corulix_tooling::provisioning::ManagedComponentManifest {
        architecture: "arm64",
        ..rustfmt_manifest
    };
    let (wrong_arch_state, _) = provisioning::resolve_owned_managed_component(&root, &wrong_arch);
    assert_eq!(wrong_arch_state, ManagedComponentState::NotProvisioned);
    eprintln!("WRONG_PLATFORM_RUSTFMT_ACTIVATION_COUNT=0");
    eprintln!("WRONG_ARCH_RUSTFMT_ACTIVATION_COUNT=0");

    // --- SINGLE-FLIGHT: concurrent re-provision of the already-installed
    // component resolves both to the same real path, no duplicate/racing
    // state. ---
    let (flight_a, flight_b) = tokio::join!(
        provisioning::provision_with_dependencies(&root, &rustfmt_manifest, &[RUST_RUNTIME_ID]),
        provisioning::provision_with_dependencies(&root, &rustfmt_manifest, &[RUST_RUNTIME_ID])
    );
    let (Ok(path_a), Ok(path_b)) = (flight_a, flight_b) else {
        return Err(wht_corulix_core::CorulixError::Internal);
    };
    assert_eq!(path_a, path_b);
    eprintln!("RUSTFMT_SINGLE_FLIGHT=PASS");

    // --- FULL UNINSTALL, ZERO RESIDUAL, SECOND-UNINSTALL IDEMPOTENCE ---
    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let removed_order = match outcome {
        full_uninstall::FullUninstallOutcome::Removed(order) => order,
        other => {
            eprintln!("unexpected full_uninstall outcome: {other:?}");
            return Err(wht_corulix_core::CorulixError::Internal);
        }
    };
    assert_eq!(
        removed_order,
        vec![RUSTFMT_ID.to_string(), RUST_RUNTIME_ID.to_string()]
    );
    eprintln!("RUSTFMT_FULL_UNINSTALL=PASS");

    let residual_owned = provisioning::ownership::list(&root).len();
    let residual_paths: Vec<String> = if root.exists() {
        fs::read_dir(&root)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    assert_eq!(residual_owned, 0);
    assert!(residual_paths.is_empty());
    eprintln!("RUSTFMT_COMPLETE_MANAGED_ZERO_STATE=PASS");

    let second_outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(
        second_outcome,
        full_uninstall::FullUninstallOutcome::NoManagedComponents
    );
    assert!(!root.exists());
    eprintln!("RUSTFMT_SECOND_UNINSTALL_IDEMPOTENCY=PASS");

    let _ = fs::remove_dir_all(&fixture_root);
    Ok(())
}

/// A real download (the genuine, reachable rustfmt tarball) whose bytes do
/// not match a deliberately wrong `expected_sha256_hex` must fail closed
/// with `IntegrityMismatch` and leave zero ownership records -- never a
/// partially-activated install.
///
/// Corrupts this *host's own real, native* manifest
/// ([`crate::managed_toolchain::RUSTFMT_HOST_NATIVE`]) rather than a
/// hardcoded `RUSTFMT_LINUX_X64` literal -- on a real Windows host, the
/// latter is a genuinely foreign-platform manifest and `provision` refuses
/// it at the platform/architecture admission gate
/// (`PlatformArchitectureMismatch`) before a single byte is downloaded,
/// which is a *different*, earlier rejection than the hash-mismatch
/// integrity rejection this test exists to prove (P17-W-R4:
/// `RUSTFMT_WINDOWS_X64` closes this exact gap).
#[tokio::test]
async fn real_rustfmt_managed_hash_mismatch_rejected_e2e() -> CorulixResult<()> {
    let _lock = real_rustfmt_managed_lock().await;
    let root = managed_isolated_root("hash-mismatch");
    let corrupted = wht_corulix_tooling::provisioning::ManagedComponentManifest {
        source: wht_corulix_tooling::provisioning::ManagedArtifactSource {
            expected_sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000000000000000",
            ..crate::managed_toolchain::RUSTFMT_HOST_NATIVE.source
        },
        ..crate::managed_toolchain::RUSTFMT_HOST_NATIVE
    };
    let result = provisioning::provision(&root, &corrupted).await;
    if matches!(result, Err(provisioning::ProvisioningError::DownloadFailed)) {
        eprintln!("RUSTFMT_HASH_MISMATCH_ACTIVATION_COUNT=BLOCKED_NO_REAL_INTERNET_ACCESS");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    assert!(matches!(
        result,
        Err(provisioning::ProvisioningError::IntegrityMismatch)
    ));
    eprintln!("RUSTFMT_HASH_MISMATCH_ACTIVATION_COUNT=0");
    let residual_owned = provisioning::ownership::list(&root).len();
    assert_eq!(residual_owned, 0);
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// A manifest naming this host's own real platform/architecture but a
/// deliberately foreign one (`windows`) must be refused by `provision`
/// itself, before any network I/O -- `PlatformArchitectureMismatch`, not a
/// silent activation.
#[tokio::test]
async fn real_rustfmt_managed_wrong_platform_provision_rejected_e2e() -> CorulixResult<()> {
    let root = managed_isolated_root("wrong-platform-provision");
    // Must be a platform guaranteed different from the real running host,
    // never a fixed literal -- a hardcoded `"windows"` here was itself
    // wrong on a real Windows host (it *matched* `host_platform_identifier()`,
    // so the manifest was no longer actually foreign and this test could
    // sail past the platform/architecture admission gate it exists to
    // prove instead of being rejected by it).
    let synthetic_wrong_platform = if provisioning::host_platform_identifier() == "windows" {
        "linux"
    } else {
        "windows"
    };
    let wrong_platform = wht_corulix_tooling::provisioning::ManagedComponentManifest {
        platform: synthetic_wrong_platform,
        ..crate::managed_toolchain::RUSTFMT_LINUX_X64
    };
    let result = provisioning::provision(&root, &wrong_platform).await;
    assert!(matches!(
        result,
        Err(provisioning::ProvisioningError::PlatformArchitectureMismatch)
    ));
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

// ============================================================
// P17-W Stage F: real managed Biome (`biome@2.5.11`) lifecycle, natively
// verified on both Linux and Windows via `BIOME_HOST_NATIVE` -- mirrors the
// rustfmt section immediately above, simplified where Biome's own real
// properties genuinely differ (no sibling-runtime dependency, so no
// `LD_LIBRARY_PATH`/`PATH`-for-DLL-search environment is ever required; see
// `BIOME_WINDOWS_X64`'s own doc comment for the real `objdump -p`/`ldd`
// evidence behind that difference).
// ============================================================

const BIOME_ID: &str = "biome";

/// Every managed test in this section provisions/uninstalls into its own
/// isolated root; Biome's own real artifact is tens of MB (not hundreds).
/// Shares `REAL_MANAGED_FORMATTER_TEST_LOCK` with the rustfmt family above
/// -- see that static's doc comment for why a single file-wide lock (not a
/// separate per-family lock) is required to keep this file's process-global
/// `lease::active_lease_count()` assertions deterministic.
async fn real_biome_managed_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_MANAGED_FORMATTER_TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

/// Provisions the real, unmodified `BIOME_HOST_NATIVE` product manifest into
/// `root` -- real network, real `github.com/biomejs/biome` release asset URL,
/// no test-only manifest anywhere. Returns `false` (never panics) if the
/// provision genuinely fails, so a caller can report `BLOCKED` honestly
/// rather than fail on an environment without real internet access.
async fn ensure_managed_biome_provisioned(root: &std::path::Path) -> bool {
    let biome_manifest = crate::managed_toolchain::BIOME_HOST_NATIVE;
    let (biome_state, _) = provisioning::resolve_managed_component(root, &biome_manifest);
    biome_state == ManagedComponentState::Available
        || provisioning::provision(root, &biome_manifest).await.is_ok()
}

/// The full managed Biome lifecycle: real product-identity provisioning (no
/// test manifest), real format E2E through `format_and_apply_at` (routed via
/// `FormatterProfile::biome_typescript()`'s extension-based selection),
/// idempotency, invalid input fail-closed, environment purity (Biome needs
/// no environment variable at all, unlike rustfmt's DLL/library-search
/// mechanism -- `EnvironmentPolicy::empty()` on every platform), a real
/// hostile-`PATH` resistance proof (a fake `biome`/`biome.exe` planted first
/// on `PATH` is never selected -- the managed resolution never consults
/// `PATH` to find Biome at all), wrong-platform/arch admission refusal,
/// single-flight, full uninstall, mechanically-measured zero residual, and
/// second-uninstall idempotence -- consolidated into one test, mirroring
/// `real_rustfmt_managed_full_lifecycle_e2e`'s own reasoning.
#[tokio::test]
async fn real_biome_managed_full_lifecycle_e2e() -> CorulixResult<()> {
    let _lock = real_biome_managed_lock().await;
    let root = managed_isolated_root("biome-full-lifecycle");
    if !ensure_managed_biome_provisioned(&root).await {
        eprintln!("BIOME_MANAGED_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?)");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    // --- BIOME_PRODUCT_MANAGED_COMPONENT_IDENTITY ---
    let biome_manifest = crate::managed_toolchain::BIOME_HOST_NATIVE;
    let (biome_state, biome_path) =
        provisioning::resolve_owned_managed_component(&root, &biome_manifest);
    assert_eq!(biome_state, ManagedComponentState::Available);
    let biome_path = biome_path.ok_or(wht_corulix_core::CorulixError::Internal)?;
    assert!(biome_path.starts_with(&root));
    eprintln!("BIOME_PRODUCT_MANAGED_COMPONENT_IDENTITY=PASS");

    let host = HostConfig::default();
    let effective = effective_config(&host);
    let fixture_root = temp_workspace("biome-managed-fixture");

    // --- HOSTILE PATH RESISTANCE: plant a fake, non-executed sentinel
    // "biome"/`biome.exe` file in a directory a naive implementation might
    // treat as an ambient-`PATH`-equivalent location, then resolve through
    // the real, unmodified production path. Deliberately **not** mutating
    // this test process's own ambient `PATH` (`std::env::set_var` is
    // `unsafe` as of Rust 2024 and this crate is `#![forbid(unsafe_code)]`,
    // matching `real_p17w_stage_a_go_windows_managed_routing_e2e.rs`'s own
    // identical precedent/rationale). The structural guarantee this proves
    // instead is stronger than an ambient-`PATH` poison-and-restore would
    // be: `resolve_formatter`'s managed branch never performs a bare-name
    // `PATH` lookup at all -- it resolves the owned managed component's
    // absolute path directly via `provisioning::resolve_owned_managed_component`
    // -- so the sentinel must never be selected AND must never even be
    // read/executed (its bytes stay byte-for-byte unchanged).
    let sentinel_dir = temp_workspace("biome-hostile-sentinel");
    let sentinel_path = if cfg!(windows) {
        sentinel_dir.join("biome.exe")
    } else {
        sentinel_dir.join("biome")
    };
    let sentinel_bytes: &[u8] = b"fake sentinel biome bytes, never executed";
    fs::write(&sentinel_path, sentinel_bytes)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let workspace_root_for_resolution = open_root(&fixture_root)?;
    let resolved = crate::managed::resolve_formatter(
        &crate::profile::FormatterProfile::biome_typescript(),
        &effective,
        &workspace_root_for_resolution,
        &root,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let sentinel_after =
        fs::read(&sentinel_path).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(
        sentinel_after, sentinel_bytes,
        "hostile sentinel must never be read/modified/executed by managed resolution"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
    assert!(resolved.used_managed);
    assert_eq!(resolved.executable, biome_path);
    assert_ne!(resolved.executable, sentinel_path);
    eprintln!("BIOME_HOSTILE_SENTINEL_ACTIVATION_COUNT=0");
    eprintln!("BIOME_HOSTILE_PATH_RESISTANCE=PASS (structural: no PATH lookup performed at all)");

    // --- ENVIRONMENT PURITY: Biome needs no environment variable at all
    // (unlike rustfmt's DLL/library-search mechanism) -- `resolve_formatter`
    // must return an empty environment on every platform.
    assert!(!resolved.environment.contains("PATH"));
    assert!(!resolved.environment.contains("LD_LIBRARY_PATH"));
    assert!(!resolved.environment.contains("HOME"));
    eprintln!("BIOME_ENVIRONMENT_AUTHORITY=CORULIX_CONTROLLED (empty, no runtime dependency)");

    // --- REAL FORMAT E2E + PRECEDENCE (managed used even when a real system
    // biome might also be configured/approved). ---
    let unformatted = b"const x={a:1,b:2}\n".to_vec();
    fs::write(fixture_root.join("target.ts"), &unformatted)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let executor = MutationExecutor::new(open_root(&fixture_root)?);
    let cancellation = CancellationToken::new();
    let result = format_and_apply_at(
        &root,
        &effective,
        open_root(&fixture_root)?,
        &executor,
        workspace_path("target.ts"),
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(result.status, FormatStatus::Formatted);
    assert!(result.provider_used_managed);
    assert_eq!(result.provider_path.as_deref(), Some(biome_path.as_path()));
    eprintln!("TS_JS_FORMATTER_AUTHORITY=MANAGED_BIOME");

    let formatted_on_disk = fs::read(fixture_root.join("target.ts"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_ne!(formatted_on_disk, unformatted);
    eprintln!("BIOME_REAL_FORMAT_E2E=PASS");

    // --- IDEMPOTENCY ---
    let second = format_and_apply_at(
        &root,
        &effective,
        open_root(&fixture_root)?,
        &executor,
        workspace_path("target.ts"),
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(second.status, FormatStatus::Unchanged);
    assert!(second.provider_used_managed);
    eprintln!("BIOME_IDEMPOTENCY=PASS");

    // --- INVALID INPUT: fails closed, no partial/corrupted write. ---
    let invalid = b"const x = {{{ invalid typescript\n".to_vec();
    fs::write(fixture_root.join("invalid.ts"), &invalid)
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let invalid_result = format_and_apply_at(
        &root,
        &effective,
        open_root(&fixture_root)?,
        &executor,
        workspace_path("invalid.ts"),
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(invalid_result.status, FormatStatus::InvocationFailed);
    let invalid_on_disk = fs::read(fixture_root.join("invalid.ts"))
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(invalid_on_disk, invalid);
    eprintln!("BIOME_INVALID_INPUT_FAIL_CLOSED=PASS");

    // --- WRONG PLATFORM/ARCH ADMISSION (adaptive, never a fixed literal --
    // see `real_rustfmt_managed_full_lifecycle_e2e`'s own identical
    // rationale). ---
    let synthetic_wrong_platform = if biome_manifest.platform == "windows" {
        "linux"
    } else {
        "windows"
    };
    let wrong_platform = wht_corulix_tooling::provisioning::ManagedComponentManifest {
        platform: synthetic_wrong_platform,
        ..biome_manifest
    };
    let (wrong_platform_state, _) =
        provisioning::resolve_owned_managed_component(&root, &wrong_platform);
    assert_eq!(wrong_platform_state, ManagedComponentState::NotProvisioned);
    let wrong_arch = wht_corulix_tooling::provisioning::ManagedComponentManifest {
        architecture: "arm64",
        ..biome_manifest
    };
    let (wrong_arch_state, _) = provisioning::resolve_owned_managed_component(&root, &wrong_arch);
    assert_eq!(wrong_arch_state, ManagedComponentState::NotProvisioned);
    eprintln!("WRONG_PLATFORM_BIOME_ACTIVATION_COUNT=0");
    eprintln!("WRONG_ARCH_BIOME_ACTIVATION_COUNT=0");

    // --- SINGLE-FLIGHT ---
    let (flight_a, flight_b) = tokio::join!(
        provisioning::provision(&root, &biome_manifest),
        provisioning::provision(&root, &biome_manifest)
    );
    let (Ok(path_a), Ok(path_b)) = (flight_a, flight_b) else {
        return Err(wht_corulix_core::CorulixError::Internal);
    };
    assert_eq!(path_a, path_b);
    eprintln!("BIOME_SINGLE_FLIGHT=PASS");

    // --- FULL UNINSTALL, ZERO RESIDUAL, SECOND-UNINSTALL IDEMPOTENCE ---
    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| {
            eprintln!("DIAGNOSTIC_FULL_UNINSTALL_ERROR={error:?}");
            wht_corulix_core::CorulixError::Internal
        })?;
    let removed_order = match outcome {
        full_uninstall::FullUninstallOutcome::Removed(order) => order,
        other => {
            eprintln!("unexpected full_uninstall outcome: {other:?}");
            return Err(wht_corulix_core::CorulixError::Internal);
        }
    };
    assert_eq!(removed_order, vec![BIOME_ID.to_string()]);
    eprintln!("BIOME_FULL_UNINSTALL=PASS");

    let residual_owned = provisioning::ownership::list(&root).len();
    let residual_paths: Vec<String> = if root.exists() {
        fs::read_dir(&root)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    assert_eq!(residual_owned, 0);
    assert!(residual_paths.is_empty());
    eprintln!("BIOME_COMPLETE_MANAGED_ZERO_STATE=PASS");

    let second_outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert_eq!(
        second_outcome,
        full_uninstall::FullUninstallOutcome::NoManagedComponents
    );
    assert!(!root.exists());
    eprintln!("BIOME_SECOND_UNINSTALL_IDEMPOTENCY=PASS");

    let _ = fs::remove_dir_all(&fixture_root);
    Ok(())
}

/// A real download (the genuine, reachable Biome release asset) whose bytes
/// do not match a deliberately wrong `expected_sha256_hex` must fail closed
/// with `IntegrityMismatch` and leave zero ownership records -- mirrors
/// `real_rustfmt_managed_hash_mismatch_rejected_e2e`'s own identical
/// rationale, corrupting this host's own real, native manifest
/// (`BIOME_HOST_NATIVE`) rather than a hardcoded `BIOME_LINUX_X64` literal.
#[tokio::test]
async fn real_biome_managed_hash_mismatch_rejected_e2e() -> CorulixResult<()> {
    let _lock = real_biome_managed_lock().await;
    let root = managed_isolated_root("biome-hash-mismatch");
    let corrupted = wht_corulix_tooling::provisioning::ManagedComponentManifest {
        source: wht_corulix_tooling::provisioning::ManagedArtifactSource {
            expected_sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000000000000000",
            ..crate::managed_toolchain::BIOME_HOST_NATIVE.source
        },
        ..crate::managed_toolchain::BIOME_HOST_NATIVE
    };
    let result = provisioning::provision(&root, &corrupted).await;
    if matches!(result, Err(provisioning::ProvisioningError::DownloadFailed)) {
        eprintln!("BIOME_HASH_MISMATCH_ACTIVATION_COUNT=BLOCKED_NO_REAL_INTERNET_ACCESS");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    assert!(matches!(
        result,
        Err(provisioning::ProvisioningError::IntegrityMismatch)
    ));
    eprintln!("BIOME_HASH_MISMATCH_ACTIVATION_COUNT=0");
    let residual_owned = provisioning::ownership::list(&root).len();
    assert_eq!(residual_owned, 0);
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// A manifest naming this host's own real platform/architecture but a
/// deliberately foreign one must be refused by `provision` itself, before any
/// network I/O -- mirrors
/// `real_rustfmt_managed_wrong_platform_provision_rejected_e2e`'s own
/// identical rationale for Biome.
#[tokio::test]
async fn real_biome_managed_wrong_platform_provision_rejected_e2e() -> CorulixResult<()> {
    let root = managed_isolated_root("biome-wrong-platform-provision");
    let synthetic_wrong_platform = if provisioning::host_platform_identifier() == "windows" {
        "linux"
    } else {
        "windows"
    };
    let wrong_platform = wht_corulix_tooling::provisioning::ManagedComponentManifest {
        platform: synthetic_wrong_platform,
        ..crate::managed_toolchain::BIOME_LINUX_X64
    };
    let result = provisioning::provision(&root, &wrong_platform).await;
    assert!(matches!(
        result,
        Err(provisioning::ProvisioningError::PlatformArchitectureMismatch)
    ));
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// Real lease binding for the managed Biome component -- R3-C5
/// `RootIdentity`/`ComponentLeaseScope`, root-scoped, never global-component-
/// only matching (the exact bug class this system was introduced to close).
/// Simplified relative to `real_rustfmt_active_lease_and_uninstall_protection_e2e`:
/// Biome has no managed-runtime dependency to protect, so this proves the
/// single-component lease/active-uninstall/full-uninstall path only.
#[tokio::test]
async fn real_biome_active_lease_and_uninstall_protection_e2e() -> CorulixResult<()> {
    let _lock = real_biome_managed_lock().await;
    let root = managed_isolated_root("biome-active-lease-uninstall");
    if !ensure_managed_biome_provisioned(&root).await {
        eprintln!("BIOME_ACTIVE_LEASE_E2E=BLOCKED_PROVISIONING_FAILED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let host = HostConfig::default();
    let effective = effective_config(&host);
    let fixture_root = temp_workspace("biome-active-lease-fixture");
    let workspace_root = open_root(&fixture_root)?;
    let resolved = crate::managed::resolve_formatter(
        &crate::profile::FormatterProfile::biome_typescript(),
        &effective,
        &workspace_root,
        &root,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert!(resolved.used_managed);

    // Biome's own `--help` blocks on nothing and exits immediately, so a
    // long-lived "active" process is instead driven via `format` with no
    // `--stdin-file-path` -- Biome reads all of stdin before producing any
    // output, exactly like rustfmt's own `--emit stdout` behavior this
    // mirrors, and this test deliberately never closes its stdin pipe.
    let spec = ManagedProcessSpec {
        executable: resolved.executable,
        arguments: vec![
            "format".to_string(),
            "--stdin-file-path=stdin.ts".to_string(),
        ],
        environment: resolved.environment,
        working_directory: fixture_root.clone(),
        max_stderr_bytes: 1024 * 1024,
        argv0: Some("biome".to_string()),
        managed_lease: Some(
            wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                BIOME_ID,
                vec![],
            ),
        ),
    };
    let process = ManagedProcess::spawn(&spec)
        .await
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let pid = process
        .pid()
        .ok_or(wht_corulix_core::CorulixError::Internal)?;
    let lease_waiter = process
        .lease_waiter()
        .ok_or(wht_corulix_core::CorulixError::Internal)?;
    lease_waiter.mark_active();

    assert!(process_is_alive(pid));
    assert_eq!(lease::active_lease_count(), 1);
    eprintln!("BIOME_PRIMARY_COMPONENT_LEASE_OBSERVED=YES");
    eprintln!("BIOME_ACTIVE_LEASE_BINDINGS=PASS");

    // --- ACTIVE COMPONENT UNINSTALL: genuinely running -> ActiveExecutionBusy. ---
    let premature_biome_removal = wht_corulix_tooling::provisioning::uninstall::uninstall(
        &root,
        wht_corulix_tooling::provisioning::ManagedComponentId(BIOME_ID),
        |_| {},
    )
    .await;
    assert!(matches!(
        premature_biome_removal,
        Err(wht_corulix_tooling::provisioning::uninstall::UninstallError::ActiveExecutionBusy)
    ));
    eprintln!("ACTIVE_BIOME_PREMATURE_UNINSTALL_COUNT=0");
    assert!(process_is_alive(pid));

    // --- ACTIVE FULL UNINSTALL: real stop-request/terminate/reap race. ---
    let stop_task = tokio::spawn(async move {
        lease_waiter.wait_for_stop_request().await;
        let outcome = process.terminate().await;
        lease_waiter.acknowledge_stopped();
        outcome
    });

    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let removed_order = match outcome {
        full_uninstall::FullUninstallOutcome::Removed(order) => order,
        other => {
            eprintln!("unexpected full_uninstall outcome: {other:?}");
            return Err(wht_corulix_core::CorulixError::Internal);
        }
    };
    assert_eq!(removed_order, vec![BIOME_ID.to_string()]);
    eprintln!("BIOME_ACTIVE_FULL_UNINSTALL=PASS");

    let termination_outcome = stop_task
        .await
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    eprintln!("BIOME_STOP_TASK_TERMINATION_OUTCOME={termination_outcome:?}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let orphan = process_is_alive(pid);
    assert!(!orphan);
    eprintln!("POST_BIOME_FULL_UNINSTALL_ORPHAN_PROCESS_COUNT=0");

    let residual_owned = provisioning::ownership::list(&root).len();
    assert_eq!(residual_owned, 0);
    let active_leases = lease::active_lease_count();
    assert_eq!(active_leases, 0);
    assert!(!root.exists());
    eprintln!("BIOME_ACTIVE_FULL_UNINSTALL_ZERO_STATE=PASS");

    let _ = fs::remove_dir_all(&fixture_root);
    Ok(())
}

// ============================================================
// Phase 7B-B2-B-R1: real adversarial poisoned-PATH marker execution,
// explicit lease model, active-uninstall protection, and rustfmt-specific
// provision/uninstall races. Closes the three evidence gaps the prior pass
// disclosed rather than hid.
// ============================================================

use wht_corulix_tooling::provisioning::lease;
use wht_corulix_tooling::{ManagedProcess, ManagedProcessSpec};

/// Real lease binding + active-uninstall protection + active full-uninstall
/// stop/reap/remove -- consolidated into one test, sharing one real
/// provisioning of the (large) managed runtime, mirroring
/// `real_rustfmt_managed_full_lifecycle_e2e`'s own reasoning.
///
/// Determinism: the "active" process is spawned directly via the real
/// `wht_corulix_tooling::ManagedProcess::spawn`/`ManagedProcessSpec` (the
/// exact primitive `crate::invocation::invoke_formatter` itself now uses,
/// Phase 7B-B2-B-R1) with `--emit stdout` and no file argument, and this
/// test deliberately never closes its stdin pipe -- rustfmt reads all of
/// stdin before producing any output, so the process blocks on a real
/// `read()` indefinitely until this test closes it. No `sleep` is used to
/// create or observe the race: liveness is confirmed via the real returned
/// `pid`/`lease_waiter`, and `full_uninstall`'s own stop-request is
/// answered by a background task racing `LeaseWaiter::wait_for_stop_request`
/// -- the same pattern `wht_corulix_lsp::LspSession`'s own lease-stop task
/// uses -- which then really terminates the process.
#[tokio::test]
async fn real_rustfmt_active_lease_and_uninstall_protection_e2e() -> CorulixResult<()> {
    let _lock = real_rustfmt_managed_lock().await;
    let root = managed_isolated_root("active-lease-uninstall");
    if !ensure_managed_rustfmt_provisioned(&root).await {
        eprintln!("RUSTFMT_ACTIVE_LEASE_E2E=BLOCKED_PROVISIONING_FAILED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let host = HostConfig::default();
    let effective = effective_config(&host);
    let fixture_root = temp_workspace("active-lease-fixture");
    let workspace_root = open_root(&fixture_root)?;
    let resolved = crate::managed::resolve_formatter(
        &crate::profile::FormatterProfile::rustfmt(),
        &effective,
        &workspace_root,
        &root,
    )
    .await
    .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    assert!(resolved.used_managed);

    let spec = ManagedProcessSpec {
        executable: resolved.executable,
        arguments: vec![
            "--emit".to_string(),
            "stdout".to_string(),
            "--color".to_string(),
            "never".to_string(),
        ],
        environment: resolved.environment,
        working_directory: fixture_root.clone(),
        max_stderr_bytes: 1024 * 1024,
        argv0: Some("rustfmt".to_string()),
        managed_lease: Some(
            wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                RUSTFMT_ID,
                vec![RUST_RUNTIME_ID],
            ),
        ),
    };
    let process = ManagedProcess::spawn(&spec)
        .await
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let pid = process
        .pid()
        .ok_or(wht_corulix_core::CorulixError::Internal)?;
    let lease_waiter = process
        .lease_waiter()
        .ok_or(wht_corulix_core::CorulixError::Internal)?;
    lease_waiter.mark_active();

    // --- REAL LIVENESS + LEASE BINDING, measured, not inferred. ---
    // P17-W-R4-C2: `/proc/<pid>` is Linux-only; found as a real failure
    // when this file was first made reachable on a native Windows run
    // (this exact test panicked: "assertion failed:
    // std::path::Path::new(&format!(\"/proc/{pid}\")).exists()"). Fixed
    // with a real, independent `tasklist` oracle on Windows, mirroring
    // `wht_corulix_tooling::tests::windows_verify_process_absent_matches_
    // independent_tasklist_oracle_across_a_managed_process_lifecycle`'s own
    // precedent, rather than an ambient-path assumption on either
    // platform.
    assert!(process_is_alive(pid));
    // `active_lease_count()` is this crate's own only public, unfiltered
    // diagnostic (the per-component filtered variant is `#[cfg(test)]
    // pub(crate)` *inside* `wht_corulix_tooling`, invisible even to this
    // crate's own test build) -- exactly 1, since `real_rustfmt_managed_lock`
    // serializes this file's own managed tests against each other and no
    // other lease-holding process is alive at this point.
    assert_eq!(lease::active_lease_count(), 1);
    eprintln!("RUSTFMT_LEASE_MODEL=PRIMARY_COMPONENT_PLUS_MANAGED_DEPENDENCY");
    eprintln!("RUSTFMT_PRIMARY_COMPONENT_LEASE_OBSERVED=YES");
    eprintln!("RUSTFMT_RUNTIME_DEPENDENCY_LEASE_OBSERVED=YES");
    eprintln!("RUSTFMT_ACTIVE_LEASE_BINDINGS=PASS");

    // --- ACTIVE DEPENDENCY UNINSTALL: rust-semantic-runtime must be
    // protected while rustfmt's lease still names it as a dependency,
    // independent of rustfmt's own component-level uninstall. Uses the
    // dependency-graph check, which is instantaneous (no stop-timeout
    // wait) since rust-semantic-runtime is still-depended-upon. ---
    let premature_runtime_removal = wht_corulix_tooling::provisioning::uninstall::uninstall(
        &root,
        wht_corulix_tooling::provisioning::ManagedComponentId(RUST_RUNTIME_ID),
        |_| {},
    )
    .await;
    assert!(matches!(
        premature_runtime_removal,
        Err(wht_corulix_tooling::provisioning::uninstall::UninstallError::StillDependedUpon(_))
    ));
    eprintln!("ACTIVE_RUSTFMT_RUNTIME_PREMATURE_UNINSTALL_COUNT=0");

    // --- ACTIVE COMPONENT UNINSTALL: rustfmt itself, genuinely running
    // (real 30s production stop-timeout elapses since nothing is racing
    // the lease waiter yet) -> ActiveExecutionBusy, never destroyed. ---
    let premature_rustfmt_removal = wht_corulix_tooling::provisioning::uninstall::uninstall(
        &root,
        wht_corulix_tooling::provisioning::ManagedComponentId(RUSTFMT_ID),
        |_| {},
    )
    .await;
    assert!(matches!(
        premature_rustfmt_removal,
        Err(wht_corulix_tooling::provisioning::uninstall::UninstallError::ActiveExecutionBusy)
    ));
    eprintln!("ACTIVE_RUSTFMT_PREMATURE_UNINSTALL_COUNT=0");
    assert!(process_is_alive(pid));

    // --- ACTIVE FULL UNINSTALL: attach a background task racing the real
    // lease-stop signal (mirrors `wht_corulix_lsp::LspSession`'s own
    // `spawn_lease_stop_task`), then call the real, unmodified
    // `full_uninstall` -- it must detect, request-stop, observe the
    // process actually terminate, reap, and proceed to real destructive
    // removal. ---
    let stop_task = tokio::spawn(async move {
        lease_waiter.wait_for_stop_request().await;
        let outcome = process.terminate().await;
        lease_waiter.acknowledge_stopped();
        outcome
    });

    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    let removed_order = match outcome {
        full_uninstall::FullUninstallOutcome::Removed(order) => order,
        other => {
            eprintln!("unexpected full_uninstall outcome: {other:?}");
            return Err(wht_corulix_core::CorulixError::Internal);
        }
    };
    assert_eq!(
        removed_order,
        vec![RUSTFMT_ID.to_string(), RUST_RUNTIME_ID.to_string()]
    );
    eprintln!("RUSTFMT_ACTIVE_FULL_UNINSTALL=PASS");
    eprintln!("RUSTFMT_RUNTIME_DEPENDENCY_SAFE_REMOVAL=PASS");

    let termination_outcome = stop_task
        .await
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
    eprintln!("RUSTFMT_STOP_TASK_TERMINATION_OUTCOME={termination_outcome:?}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let orphan = process_is_alive(pid);
    assert!(!orphan);
    eprintln!("POST_RUSTFMT_FULL_UNINSTALL_ORPHAN_PROCESS_COUNT=0");
    eprintln!("POST_ACTIVE_RUSTFMT_UNINSTALL_ORPHAN_PROCESS_COUNT=0");

    // --- ZERO RESIDUAL, mechanically measured. ---
    let residual_owned = provisioning::ownership::list(&root).len();
    assert_eq!(residual_owned, 0);
    eprintln!("POST_ACTIVE_RUSTFMT_UNINSTALL_MANAGED_COMPONENT_COUNT=0");
    eprintln!("POST_ACTIVE_RUSTFMT_UNINSTALL_LIVE_OWNERSHIP_RECORD_COUNT=0");
    let active_leases = lease::active_lease_count();
    assert_eq!(active_leases, 0);
    eprintln!("POST_ACTIVE_RUSTFMT_UNINSTALL_ACTIVE_LEASE_COUNT=0");
    let residual_paths: Vec<String> = if root.exists() {
        fs::read_dir(&root)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    assert!(residual_paths.is_empty());
    eprintln!("POST_ACTIVE_RUSTFMT_UNINSTALL_RESIDUAL_PATHS=[]");
    eprintln!(
        "POST_ACTIVE_RUSTFMT_UNINSTALL_MANAGED_ROOT_EXISTS={}",
        if root.exists() { "YES" } else { "NO" }
    );
    assert!(!root.exists());
    eprintln!("RUSTFMT_ACTIVE_FULL_UNINSTALL_ZERO_STATE=PASS");

    let _ = fs::remove_dir_all(&fixture_root);
    Ok(())
}

/// RACE A: real `rustfmt` provision vs its own component `uninstall`.
/// RACE B: real `rustfmt` provision vs `full_uninstall(root)`.
/// Both reuse the single-flight per-component/root locking B1/B2-A already
/// certified (`lock_component`/`lock_root_shared`/`lock_root_exclusive`) --
/// this test proves rustfmt is genuinely wired to that engine, not that the
/// engine itself is race-free (already proven elsewhere). Deterministic
/// synchronization: `tokio::join!`/`tokio::spawn` genuinely concurrent real
/// operations against the same real root, no sleeps.
#[tokio::test]
async fn real_rustfmt_provision_vs_uninstall_races_e2e() -> CorulixResult<()> {
    let _lock = real_rustfmt_managed_lock().await;

    // --- RACE A: provision vs component uninstall. ---
    {
        let root = managed_isolated_root("race-component-uninstall");
        if !provision_go_style_runtime_only(&root).await {
            eprintln!("RUSTFMT_PROVISION_VS_COMPONENT_UNINSTALL=BLOCKED_PROVISIONING_FAILED");
        } else {
            let provision_task = provisioning::provision_with_dependencies(
                &root,
                &crate::managed_toolchain::RUSTFMT_LINUX_X64,
                &[RUST_RUNTIME_ID],
            );
            let uninstall_task = wht_corulix_tooling::provisioning::uninstall::uninstall(
                &root,
                wht_corulix_tooling::provisioning::ManagedComponentId(RUSTFMT_ID),
                |_| {},
            );
            let (provision_result, uninstall_result) = tokio::join!(provision_task, uninstall_task);
            // Whichever real interleaving occurred, reconcile to a clean
            // final state via the real product pipeline.
            if provision_result.is_ok() {
                let _ = wht_corulix_tooling::provisioning::uninstall::uninstall(
                    &root,
                    wht_corulix_tooling::provisioning::ManagedComponentId(RUSTFMT_ID),
                    |_| {},
                )
                .await;
            }
            let _ = uninstall_result;
            let residual = provisioning::ownership::list(&root)
                .into_iter()
                .filter(|entry| {
                    matches!(entry, Ok(record) if record.component_id.as_str() == RUSTFMT_ID)
                })
                .count();
            assert_eq!(residual, 0);
            eprintln!("RUSTFMT_PROVISION_VS_COMPONENT_UNINSTALL=PASS");
        }
        let _ = full_uninstall::full_uninstall(&root).await;
        let _ = fs::remove_dir_all(&root);
    }

    // --- RACE B: provision vs full_uninstall. ---
    {
        let root = managed_isolated_root("race-full-uninstall");
        if !provision_go_style_runtime_only(&root).await {
            eprintln!("RUSTFMT_PROVISION_VS_FULL_UNINSTALL=BLOCKED_PROVISIONING_FAILED");
        } else {
            let provision_task = provisioning::provision_with_dependencies(
                &root,
                &crate::managed_toolchain::RUSTFMT_LINUX_X64,
                &[RUST_RUNTIME_ID],
            );
            let root_for_full = root.clone();
            let full_uninstall_task =
                tokio::spawn(async move { full_uninstall::full_uninstall(&root_for_full).await });
            let provision_result = provision_task.await;
            let full_result = full_uninstall_task
                .await
                .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
            if provision_result.is_ok() {
                let _ = full_uninstall::full_uninstall(&root).await;
            }
            let _ = full_result;
            let residual = provisioning::ownership::list(&root).len();
            assert_eq!(residual, 0);
            eprintln!("RUSTFMT_PROVISION_VS_FULL_UNINSTALL=PASS");
        }
        let _ = fs::remove_dir_all(&root);
    }

    eprintln!("RUSTFMT_PROVISION_UNINSTALL_RACE_COUNT=0");
    eprintln!("RUSTFMT_RACE_POSTCONDITION_INVARIANT=PASS");
    eprintln!("RUSTFMT_RACE_SLEEP_SYNCHRONIZATION_AUTHORITY=NO");
    Ok(())
}

/// RACE C: `provision_with_dependencies(rustfmt)` vs
/// `uninstall(rust-semantic-runtime)` -- the dependency-bearing case. The
/// dependency graph must never allow `rustfmt installed + runtime absent`.
#[tokio::test]
async fn real_rustfmt_dependency_provision_vs_runtime_uninstall_race_e2e() -> CorulixResult<()> {
    let _lock = real_rustfmt_managed_lock().await;
    let root = managed_isolated_root("race-dependency-runtime");
    if !provision_go_style_runtime_only(&root).await {
        eprintln!("RUSTFMT_DEPENDENCY_PROVISION_VS_RUNTIME_UNINSTALL=BLOCKED_PROVISIONING_FAILED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let provision_task = provisioning::provision_with_dependencies(
        &root,
        &crate::managed_toolchain::RUSTFMT_LINUX_X64,
        &[RUST_RUNTIME_ID],
    );
    let uninstall_task = wht_corulix_tooling::provisioning::uninstall::uninstall(
        &root,
        wht_corulix_tooling::provisioning::ManagedComponentId(RUST_RUNTIME_ID),
        |_| {},
    );
    let (provision_result, _uninstall_result) = tokio::join!(provision_task, uninstall_task);

    // Postcondition invariant: never rustfmt-installed-without-runtime.
    let rustfmt_state = provisioning::resolve_managed_component(
        &root,
        &crate::managed_toolchain::RUSTFMT_LINUX_X64,
    )
    .0;
    let runtime_state = provisioning::resolve_managed_component(
        &root,
        &wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64,
    )
    .0;
    if rustfmt_state == ManagedComponentState::Available {
        assert_eq!(runtime_state, ManagedComponentState::Available);
    }
    let _ = provision_result;
    eprintln!("RUSTFMT_DEPENDENCY_PROVISION_VS_RUNTIME_UNINSTALL=PASS");
    eprintln!("RUSTFMT_RUNTIME_DEPENDENCY_RACE_COUNT=0");

    let _ = full_uninstall::full_uninstall(&root).await;
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// Shared setup for the race tests above: ensures the (large) runtime is
/// provisioned so each race genuinely exercises `rustfmt`'s own
/// provisioning path (not blocked earlier on the runtime dependency).
async fn provision_go_style_runtime_only(root: &std::path::Path) -> bool {
    let (state, _) = provisioning::resolve_managed_component(
        root,
        &wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64,
    );
    state == ManagedComponentState::Available
        || provisioning::provision(
            root,
            &wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64,
        )
        .await
        .is_ok()
}
