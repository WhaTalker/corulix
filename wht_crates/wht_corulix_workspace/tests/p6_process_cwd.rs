// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09-P6 permanent tests for `WorkspaceRoot::bind_process_cwd` -- the
//! `WorkspaceRoot`-specific object-identity/swap/clone/drop scenarios.
//! The raw `bind_cwd` primitive's own properties (`CLOEXEC`, async-signal-
//! safety, fchdir-failure-fails-closed, multiple independent bindings from
//! a raw fd, `current_dir` interaction) are proven once, generically, in
//! `wht_corulix_process_unix`'s own integration suite -- this file proves
//! only what is specific to `WorkspaceRoot` itself: that pinning survives
//! every kind of pathname replacement this whole M09 effort targets.
//!
//! Every test acquires [`FD_TEST_GUARD`] for its entire body (M09-P6
//! Section 34): several of these tests spawn real child processes with
//! piped stdio, and Rust's default test harness runs every `#[test]` fn in
//! this file on its own thread, in parallel, within this one process --
//! without serialization, one test's `/proc/self/fd` sample could be
//! perturbed by a sibling test's own concurrently in-flight spawn (exactly
//! the flake class `wht_corulix_process_unix`'s own suite hit and fixed
//! the same way).
//!
//! M09-P9 fix: this file exercises `WorkspaceRoot::bind_process_cwd` and
//! `std::os::unix::fs::MetadataExt`, both Unix-only -- it was missing its
//! own `#![cfg(unix)]` guard, so `cargo test`/`cargo check --tests` for a
//! Windows target attempted (and failed) to compile it. This guard changes
//! nothing about the file's behavior on Unix (still compiles and runs
//! identically there); it only stops a Unix-only test file from being
//! attempted on a platform it was never written for. Pre-existing gap,
//! unrelated to P9's own Windows implementation -- discovered only because
//! this phase was the first to actually build/run `cargo test` (not just
//! `cargo check`) against a real Windows target.

#![cfg(unix)]

mod support;

use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_workspace::WorkspaceRoot;

static FD_TEST_GUARD: Mutex<()> = Mutex::new(());

fn fd_test_guard() -> MutexGuard<'static, ()> {
    FD_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn temp_dir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!(
        "corulix-p6-workspace-{label}-{}-{stamp}-{unique}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&root);
    root
}

fn identity_of(path: &Path) -> Result<(u64, u64), String> {
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("metadata({path:?}) failed: {error}"))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn oracle_command() -> Result<Command, String> {
    let exe = support::fixture_binary_path()?;
    let mut command = Command::new(exe);
    command.arg("print-cwd-identity");
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    Ok(command)
}

fn spawn_and_get_identity(mut command: Command) -> Result<(u64, u64), String> {
    let output = command
        .output()
        .map_err(|error| format!("spawn/wait failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "child exited non-zero: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("stdout was not valid UTF-8: {error}"))?;
    let payload: serde_json::Value = serde_json::from_str(text.trim())
        .map_err(|error| format!("invalid JSON {text:?}: {error}"))?;
    let device = payload["device"].as_u64().ok_or("missing device")?;
    let inode = payload["inode"].as_u64().ok_or("missing inode")?;
    Ok((device, inode))
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0)
}

// -- normal pinned-root cwd (Section 4, 35) -------------------------------

#[test]
fn normal_pinned_root_cwd_matches_workspace_root() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("normal");
    let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
    let expected = identity_of(&dir)?;

    let mut command = oracle_command()?;
    root.bind_process_cwd(&mut command);
    let actual = spawn_and_get_identity(command)?;

    assert_eq!(actual, expected);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- root replacement BEFORE bind (Section 14) ----------------------------

#[test]
fn root_normal_replacement_before_bind_does_not_redirect() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("before-bind-normal");
    let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
    let expected = identity_of(&dir)?;

    let moved = temp_dir("before-bind-normal-moved");
    std::fs::remove_dir_all(&moved).map_err(|error| error.to_string())?;
    std::fs::rename(&dir, &moved).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let impostor_identity = identity_of(&dir)?;
    assert_ne!(expected, impostor_identity, "test setup sanity check");

    let mut command = oracle_command()?;
    root.bind_process_cwd(&mut command);
    let actual = spawn_and_get_identity(command)?;

    assert_eq!(
        actual, expected,
        "child must enter the ORIGINAL pinned root object, never the impostor directory now \
         sitting at the old pathname"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&moved);
    Ok(())
}

#[test]
fn root_symlink_replacement_before_bind_does_not_escape() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("before-bind-symlink");
    let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
    let expected = identity_of(&dir)?;
    let outside = temp_dir("before-bind-symlink-outside");

    let moved = temp_dir("before-bind-symlink-moved");
    std::fs::remove_dir_all(&moved).map_err(|error| error.to_string())?;
    std::fs::rename(&dir, &moved).map_err(|error| error.to_string())?;
    symlink(&outside, &dir).map_err(|error| error.to_string())?;

    let mut command = oracle_command()?;
    root.bind_process_cwd(&mut command);
    let actual = spawn_and_get_identity(command)?;

    let outside_identity = identity_of(&outside)?;
    assert_ne!(
        actual, outside_identity,
        "M09_P6_ROOT_SYMLINK_REPLACEMENT_ESCAPE_COUNT must be 0"
    );
    assert_eq!(actual, expected);

    let _ = std::fs::remove_file(&dir);
    let _ = std::fs::remove_dir_all(&moved);
    let _ = std::fs::remove_dir_all(&outside);
    Ok(())
}

// -- root replacement AFTER bind, BEFORE spawn (Section 15) ---------------

#[test]
fn root_replacement_after_bind_before_spawn_does_not_redirect() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("after-bind");
    let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
    let expected = identity_of(&dir)?;

    let mut command = oracle_command()?;
    root.bind_process_cwd(&mut command);

    let outside = temp_dir("after-bind-outside");
    let moved = temp_dir("after-bind-moved");
    std::fs::remove_dir_all(&moved).map_err(|error| error.to_string())?;
    std::fs::rename(&dir, &moved).map_err(|error| error.to_string())?;
    symlink(&outside, &dir).map_err(|error| error.to_string())?;

    let actual = spawn_and_get_identity(command)?;
    assert_eq!(
        actual, expected,
        "the already-configured Command must retain object authority captured at bind time, \
         not merely an fd integer whose meaning depends on WorkspaceRoot/pathname state that \
         has since changed"
    );

    let _ = std::fs::remove_file(&dir);
    let _ = std::fs::remove_dir_all(&moved);
    let _ = std::fs::remove_dir_all(&outside);
    Ok(())
}

// -- WorkspaceRoot drop after bind (Section 16) ----------------------------

#[test]
fn workspace_root_drop_after_bind_does_not_invalidate_command() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("drop-after-bind");
    let expected = identity_of(&dir)?;

    let mut command = oracle_command()?;
    {
        let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
        root.bind_process_cwd(&mut command);
        // `root` drops here -- BEFORE `command` is ever spawned below.
        // `bind_process_cwd` is a plain `&self` method (no borrow of
        // `root` is returned or retained), so this is not merely
        // "possible" by accident of a lenient API -- it is the expected,
        // designed shape: the Command's own cloned `Arc` reference is
        // what keeps the underlying fd valid, never `root`'s own
        // continued existence.
    }

    let actual = spawn_and_get_identity(command)?;
    assert_eq!(
        actual, expected,
        "dropping the WorkspaceRoot value after bind_process_cwd must not dangle the Command's \
         own fd authority"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- clone behavior (Section 17) -------------------------------------------

#[test]
fn workspace_root_clone_binds_the_same_pinned_object() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("clone");
    let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
    let cloned = root.clone();
    let expected = identity_of(&dir)?;

    let outside = temp_dir("clone-outside");
    let moved = temp_dir("clone-moved");
    std::fs::remove_dir_all(&moved).map_err(|error| error.to_string())?;
    std::fs::rename(&dir, &moved).map_err(|error| error.to_string())?;
    symlink(&outside, &dir).map_err(|error| error.to_string())?;

    // Bind from the CLONE (not the original) after the original's own
    // pathname has already been replaced.
    let mut command = oracle_command()?;
    cloned.bind_process_cwd(&mut command);
    let actual = spawn_and_get_identity(command)?;

    assert_eq!(
        actual, expected,
        "a clone must bind the exact same pinned root object as its source, regardless of \
         subsequent pathname replacement"
    );
    drop(root);

    let _ = std::fs::remove_file(&dir);
    let _ = std::fs::remove_dir_all(&moved);
    let _ = std::fs::remove_dir_all(&outside);
    Ok(())
}

// -- ancestor replacement (Section 21) -------------------------------------

#[test]
fn ancestor_replacement_does_not_redirect_the_pinned_workspace() -> Result<(), String> {
    let _guard = fd_test_guard();
    let base = temp_dir("ancestor-base");
    std::fs::create_dir_all(base.join("a/workspace")).map_err(|error| error.to_string())?;
    let workspace = base.join("a/workspace");
    let root = WorkspaceRoot::open(&workspace).map_err(|error| format!("{error:?}"))?;
    let expected = identity_of(&workspace)?;

    let outside = temp_dir("ancestor-outside");
    let a_path = base.join("a");
    let a_moved = temp_dir("ancestor-a-moved");
    std::fs::remove_dir_all(&a_moved).map_err(|error| error.to_string())?;
    std::fs::rename(&a_path, &a_moved).map_err(|error| error.to_string())?;
    symlink(&outside, &a_path).map_err(|error| error.to_string())?;

    let mut command = oracle_command()?;
    root.bind_process_cwd(&mut command);
    let actual = spawn_and_get_identity(command)?;

    assert_eq!(
        actual, expected,
        "M09_P6_ROOT_ANCESTOR_REPLACEMENT_ESCAPE_COUNT must be 0"
    );

    let _ = std::fs::remove_file(&a_path);
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::remove_dir_all(&a_moved);
    let _ = std::fs::remove_dir_all(&outside);
    Ok(())
}

// -- multiple independent Command bindings (Section 22) --------------------

#[test]
fn multiple_command_bindings_from_the_same_workspace_root() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("multi-command");
    let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
    let expected = identity_of(&dir)?;

    let mut command_one = oracle_command()?;
    root.bind_process_cwd(&mut command_one);
    let mut command_two = oracle_command()?;
    root.bind_process_cwd(&mut command_two);

    let actual_one = spawn_and_get_identity(command_one)?;
    let actual_two = spawn_and_get_identity(command_two)?;

    assert_eq!(actual_one, expected);
    assert_eq!(actual_two, expected);

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- Command drop without spawn / fd leak (Section 23, 24) -----------------

#[test]
fn unspawned_bound_command_from_workspace_root_leaks_no_fd() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("unspawned");
    let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
    let before = open_fd_count();

    for _ in 0..100 {
        let mut command = oracle_command()?;
        root.bind_process_cwd(&mut command);
        drop(command);
    }

    let after = open_fd_count();
    assert!(
        after <= before + 4,
        "fd count grew from {before} to {after} after 100 bind+drop-without-spawn cycles"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn repeated_spawn_from_workspace_root_does_not_retain_fds() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("repeated-spawn");
    let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
    let expected = identity_of(&dir)?;
    let before = open_fd_count();

    for _ in 0..30 {
        let mut command = oracle_command()?;
        root.bind_process_cwd(&mut command);
        let actual = spawn_and_get_identity(command)?;
        assert_eq!(actual, expected);
    }

    let after = open_fd_count();
    assert!(
        after <= before + 4,
        "fd count grew from {before} to {after} after 30 bind+spawn+wait cycles"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// -- pre-existing current_dir interaction (Section 28) ---------------------

#[test]
fn preexisting_current_dir_cannot_override_workspace_root_binding() -> Result<(), String> {
    let _guard = fd_test_guard();
    let dir = temp_dir("preexisting-current-dir");
    let root = WorkspaceRoot::open(&dir).map_err(|error| format!("{error:?}"))?;
    let expected = identity_of(&dir)?;
    let impostor = temp_dir("preexisting-current-dir-impostor");
    let impostor_identity = identity_of(&impostor)?;
    assert_ne!(expected, impostor_identity);

    let mut command = oracle_command()?;
    command.current_dir(&impostor);
    root.bind_process_cwd(&mut command);

    let actual = spawn_and_get_identity(command)?;
    assert_eq!(
        actual, expected,
        "M09_P6_PREEXISTING_CURRENT_DIR_REDIRECTION_COUNT must be 0"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&impostor);
    Ok(())
}
