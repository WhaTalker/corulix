// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real, behavioral poisoned-`PATH` proof for managed `rustfmt` (Phase
//! 7B-B2-B-R1), closing the gap the prior pass's own structural-only
//! evidence disclosed as insufficient.
//!
//! Lives under `tests/` (an integration test, not `src/tests.rs`)
//! specifically so it can read the ambient `PATH` environment variable to
//! *construct* a hostile child-process environment without tripping this
//! repository's own architecture validator (`wht_scripts/wht_verify_architecture.py`
//! Step 13b), which scans every `.rs` file under each crate's `src/` for
//! `env::var("PATH")` (`AMBIENT_PATH_PROVIDER_AUTHORITY=NO`, Rule K) --
//! that rule is about *product* code never consulting ambient `PATH` for
//! provider resolution, not about a test's own adversarial-environment
//! setup, which is exactly why every other poisoned-PATH adversarial test
//! in this workspace (`wht_corulix_lsp`'s `real_poisoned_path_executable_authority_e2e.rs`)
//! already lives under `tests/` rather than inline in `src/`.
//!
//! # Windows note (Phase 17-W)
//!
//! `#![cfg(unix)]`-only for this whole file: the marker mechanism writes a
//! `#!/bin/sh` shebang script and `chmod`s it executable
//! (`std::os::unix::fs::PermissionsExt::set_mode`), and the hostile `PATH`
//! is built with a `:` separator -- none of which is meaningful on Windows
//! (`.exe`/`.bat`/`.cmd` markers and a `;`-separated `PATH` would be
//! required instead). `POISONED_PATH_RESISTANCE` is a required native
//! Windows scenario per this phase's own mandate (§10); a genuine
//! Windows-native equivalent of this exact marker-execution proof has not
//! yet been written, and is disclosed here as a residual rather than
//! silently skipped (`P17_W_WINDOWS_POISONED_PATH_MARKER_EQUIVALENT_COUNT=0`).

#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspacePath, WorkspaceRootId};
use wht_corulix_formatter::{DEFAULT_MAX_INPUT_BYTES, format_and_apply_at};
use wht_corulix_mutation::MutationExecutor;
use wht_corulix_workspace::WorkspaceRoot;

fn temp_dir(label: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-rustfmt-poisoned-path-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn write_marker_script(dir: &Path, name: &str, counter_file: &Path) {
    let script = format!(
        "#!/bin/sh\necho invoked >> {}\nexit 1\n",
        counter_file.display()
    );
    let path = dir.join(name);
    fs::write(&path, script).unwrap_or_else(|error| unreachable!("write marker: {error}"));
    let mut perms = fs::metadata(&path)
        .unwrap_or_else(|error| unreachable!("marker metadata: {error}"))
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(&path, perms).unwrap_or_else(|error| unreachable!("chmod marker: {error}"));
}

fn marker_invocation_count(counter_file: &Path) -> usize {
    fs::read_to_string(counter_file)
        .unwrap_or_default()
        .lines()
        .count()
}

/// A REAL, standalone `#[tokio::test]` -- not merely a helper function --
/// re-invoked as its own subprocess by
/// [`real_poisoned_path_marker_execution_e2e`] with a hostile `PATH`
/// injected via `Command::env` (never `std::env::set_var`, which every
/// crate in this workspace is forbidden from calling under its own
/// `#![forbid(unsafe_code)]` on this toolchain -- `set_var`/`remove_var`
/// are `unsafe fn` as of this pinned Rust 1.97.1). Runs the real, public
/// `wht_corulix_formatter::format_and_apply_at` end-to-end against a fresh,
/// nothing-provisioned managed root -- forcing the `HOST_ONLY`/system
/// resolution layer (the one that actually could, if buggy, consult
/// ambient `PATH`) to run for real. Also runs standalone (no hostile PATH)
/// under the normal full suite -- harmless there, real evidence either way.
#[tokio::test]
async fn poisoned_path_inner_worker() {
    let workspace = temp_dir("inner-workspace");
    fs::write(workspace.join("target.rs"), b"fn main( ) {}\n")
        .unwrap_or_else(|error| unreachable!("write fixture: {error}"));
    let host = HostConfig::default();
    let effective = EffectiveConfig::derive(
        &host,
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let workspace_root = WorkspaceRoot::open(&workspace)
        .unwrap_or_else(|error| unreachable!("open workspace: {error:?}"));
    let executor = MutationExecutor::new(workspace_root.clone());
    let cancellation = CancellationToken::new();
    let managed_root = temp_dir("inner-managed-root-unprovisioned");
    let path = WorkspacePath {
        root: WorkspaceRootId(0),
        relative_path: "target.rs".to_string(),
    };
    let result = format_and_apply_at(
        &managed_root,
        &effective,
        workspace_root,
        &executor,
        path,
        DEFAULT_MAX_INPUT_BYTES,
        &cancellation,
    )
    .await
    .unwrap_or_else(|error| unreachable!("format_and_apply_at: {error}"));
    eprintln!("POISONED_PATH_INNER_WORKER_STATUS={:?}", result.status);
    let _ = fs::remove_dir_all(&workspace);
    let _ = fs::remove_dir_all(&managed_root);
}

/// Real positive controls (each marker genuinely executes and increments
/// the shared counter file when invoked directly), then the real product
/// path (`poisoned_path_inner_worker`, exercised via a genuine subprocess
/// with a hostile `PATH` prepended ahead of every real location) is proven
/// to invoke none of them --
/// `ALL_RUSTFMT_POISONED_PATH_MARKER_EXECUTION_COUNTS=0`.
#[test]
fn real_poisoned_path_marker_execution_e2e() {
    let hostile_dir = temp_dir("markers");
    let counter_file = hostile_dir.join("invocations.log");
    for name in ["rustfmt", "cargo", "rustc", "rustup"] {
        write_marker_script(&hostile_dir, name, &counter_file);
    }

    // --- POSITIVE CONTROLS: each marker genuinely runs if directly
    // invoked, proving the marker mechanism itself is real -- not merely
    // structural inspection of PATH. ---
    for name in ["rustfmt", "cargo", "rustc", "rustup"] {
        let output = std::process::Command::new(hostile_dir.join(name))
            .output()
            .unwrap_or_else(|error| unreachable!("invoke marker: {error}"));
        assert_eq!(output.status.code(), Some(1));
    }
    assert_eq!(marker_invocation_count(&counter_file), 4);
    eprintln!("RUSTFMT_MARKER_POSITIVE_CONTROL=PASS");
    eprintln!("CARGO_MARKER_POSITIVE_CONTROL=PASS");
    eprintln!("RUSTC_MARKER_POSITIVE_CONTROL=PASS");
    eprintln!("RUSTUP_MARKER_POSITIVE_CONTROL=PASS");
    let _ = fs::remove_file(&counter_file);

    // --- HOSTILE PATH: the real product path re-invoked as a genuine
    // subprocess whose PATH prepends the marker directory ahead of every
    // real location -- `Command::env` sets only the CHILD's environment;
    // this never mutates the running test process's own ambient env. ---
    let test_binary =
        std::env::current_exe().unwrap_or_else(|error| unreachable!("current_exe: {error}"));
    let ambient_path = std::env::var("PATH").unwrap_or_default();
    let hostile_path = format!("{}:{ambient_path}", hostile_dir.display());
    let output = std::process::Command::new(&test_binary)
        .arg("--exact")
        .arg("poisoned_path_inner_worker")
        .arg("--nocapture")
        .env("PATH", &hostile_path)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap_or_else(|error| unreachable!("spawn inner worker: {error}"));
    assert!(
        output.status.success(),
        "inner worker subprocess failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!(
        "POISONED_PATH_SUBPROCESS_STDOUT={}",
        String::from_utf8_lossy(&output.stdout)
    );

    let marker_execution_count = marker_invocation_count(&counter_file);
    assert_eq!(marker_execution_count, 0);
    eprintln!("RUSTFMT_POISONED_PATH_RUSTFMT_MARKER_EXECUTION_COUNT=0");
    eprintln!("RUSTFMT_POISONED_PATH_CARGO_MARKER_EXECUTION_COUNT=0");
    eprintln!("RUSTFMT_POISONED_PATH_RUSTC_MARKER_EXECUTION_COUNT=0");
    eprintln!("RUSTFMT_POISONED_PATH_RUSTUP_MARKER_EXECUTION_COUNT=0");
    eprintln!("ALL_RUSTFMT_POISONED_PATH_MARKER_EXECUTION_COUNTS=0");

    let _ = fs::remove_dir_all(&hostile_dir);
}
