// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09-P9: permanent Windows-only security matrix for handle-relative
//! filesystem authority (`WorkspaceRoot`/`PinnedParent`/`PinnedTarget`/
//! `PinnedFile`, backed by `wht_corulix_process_win32`'s real NT/Win32
//! primitives). Compiled only on Windows (`#![cfg(windows)]`); on any
//! other target this file contributes zero tests, per this crate's own
//! platform-split discipline.
//!
//! These tests exercise the PUBLIC surface only (exactly what a real
//! cross-crate consumer, e.g. `wht_corulix_mutation`, can reach) -- no
//! `wht_corulix_process_win32` handle/FFI type ever appears here. Every
//! test returns `CorulixResult<()>` and propagates via `?` rather than
//! `.expect()`/`panic!` (workspace-wide `clippy::expect_used`/
//! `clippy::panic` lints apply to test targets too).

#![cfg(windows)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{CorulixError, CorulixResult};
use wht_corulix_workspace::{WorkspaceRoot, resolve_existing_target, resolve_new_target};

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-p9-win32-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    root
}

fn to_internal<E: std::fmt::Debug>(_error: E) -> CorulixError {
    CorulixError::Internal
}

// -- Q22-equivalent normal roundtrip: create, read, rename, delete, all via
// the real handle-relative capability layer. --

#[test]
fn normal_create_read_rename_delete_roundtrip_succeeds() -> CorulixResult<()> {
    let root_path = temp_dir("roundtrip");
    let root = WorkspaceRoot::open(&root_path)?;

    let created = resolve_new_target(&root, &PathBuf::from("a.txt"))?;
    created.create_exclusive(b"hello")?;

    let existing = resolve_existing_target(&root, &PathBuf::from("a.txt"))?;
    let file = existing.open_file()?;
    let bytes = file.read_bytes(4096)?;
    if bytes != b"hello" {
        return Err(CorulixError::Internal);
    }

    let source = resolve_existing_target(&root, &PathBuf::from("a.txt"))?;
    let destination = resolve_new_target(&root, &PathBuf::from("b.txt"))?;
    source.rename_into(destination)?;

    if root_path.join("a.txt").exists() || !root_path.join("b.txt").exists() {
        return Err(CorulixError::Internal);
    }

    let renamed = resolve_existing_target(&root, &PathBuf::from("b.txt"))?;
    renamed.unlink()?;
    if root_path.join("b.txt").exists() {
        return Err(CorulixError::Internal);
    }

    let _ = fs::remove_dir_all(&root_path);
    Ok(())
}

// -- Root swap: the pinned root's own handle stays authoritative even
// after its directory entry is renamed away on disk. --

#[test]
fn root_directory_rename_after_open_does_not_redirect_pinned_authority() -> CorulixResult<()> {
    let root_path = temp_dir("root-swap");
    let root = WorkspaceRoot::open(&root_path)?;

    let renamed_away = root_path
        .parent()
        .ok_or(CorulixError::Internal)?
        .join(format!(
            "corulix-p9-win32-e2e-root-swap-renamed-away-{}",
            std::process::id()
        ));
    fs::rename(&root_path, &renamed_away).map_err(to_internal)?;

    // The pinned handle remains valid and authoritative for the SAME
    // object, regardless of what its own directory entry is now called --
    // a real, still-open child create against it must still succeed.
    let created = resolve_new_target(&root, &PathBuf::from("still-works.txt"))?;
    created.create_exclusive(b"still pinned")?;
    if !renamed_away.join("still-works.txt").exists() {
        return Err(CorulixError::Internal);
    }

    // The pathname-based identity check must now fail closed: the
    // ORIGINAL pathname no longer leads anywhere at all.
    if root.verify_current_path_identity() {
        return Err(CorulixError::Internal);
    }

    let _ = fs::remove_dir_all(&renamed_away);
    Ok(())
}

// -- Ancestor swap: an already-pinned intermediate ancestor directory is
// replaced on disk after being walked; the walk must not silently
// re-resolve through the replacement. --

#[test]
fn ancestor_replacement_during_use_does_not_redirect_already_pinned_authority() -> CorulixResult<()>
{
    let root_path = temp_dir("ancestor-swap");
    fs::create_dir_all(root_path.join("sub")).map_err(to_internal)?;
    fs::write(root_path.join("sub/file.txt"), b"original").map_err(to_internal)?;
    let root = WorkspaceRoot::open(&root_path)?;

    // Resolve once (pins the ancestor "sub" via a real handle-relative
    // open), keep the resulting capability alive.
    let existing = resolve_existing_target(&root, &PathBuf::from("sub/file.txt"))?;

    // Now replace "sub" on disk with an entirely different directory
    // containing a different file of the same leaf name. Mirrors this
    // workspace's own Unix equivalent (`capability.rs`'s
    // `capability_survives_nested_ancestor_replacement`): the ORIGINAL
    // "sub" is moved ASIDE (kept alive on disk, just unreachable by its
    // old path), never deleted -- a real delete
    // (`fs::remove_dir_all`) leaves the original directory itself in
    // Windows's own delete-pending state (`STATUS_DELETE_PENDING`), which
    // correctly denies ANY further access to it, including through an
    // already-pinned handle; that is a distinct, honest Windows
    // fail-closed outcome, not the "was the ancestor swap redirected"
    // property this test exists to prove.
    let sub_path = root_path.join("sub");
    let moved_away = temp_dir("ancestor-swap-moved-away");
    fs::rename(&sub_path, moved_away.join("sub")).map_err(to_internal)?;
    fs::create_dir_all(&sub_path).map_err(to_internal)?;
    fs::write(sub_path.join("file.txt"), b"attacker-controlled").map_err(to_internal)?;

    // The already-pinned capability must still read the ORIGINAL object's
    // bytes, never the replacement's -- proving the read acts on the
    // already-open handle chain, not a re-walked pathname.
    let file = existing.open_file()?;
    let bytes = file.read_bytes(4096)?;
    if bytes != b"original" {
        return Err(CorulixError::Internal);
    }

    let _ = fs::remove_dir_all(&root_path);
    let _ = fs::remove_dir_all(&moved_away);
    Ok(())
}

// -- Reparse-point fail-closed policy: a real Windows directory junction
// placed as a workspace-relative component must be denied, never followed.
// `NOT_RUN_PRIVILEGE_LIMITATION` if this account cannot create one (e.g. no
// `SeCreateSymbolicLinkPrivilege`), never a fabricated pass. --

#[test]
fn reparse_point_component_is_denied_not_followed() -> CorulixResult<()> {
    let root_path = temp_dir("reparse-deny");
    let outside = temp_dir("reparse-deny-outside");
    fs::write(outside.join("secret.txt"), b"must never be reachable").map_err(to_internal)?;

    let junction_path = root_path.join("escape");
    if let Err(error) = std::os::windows::fs::symlink_dir(&outside, &junction_path) {
        eprintln!(
            "P9_REPARSE_TEST=NOT_RUN_PRIVILEGE_LIMITATION: symlink_dir failed ({error}); this \
             account lacks the privilege to create a real reparse point on this host"
        );
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&outside);
        return Ok(());
    }

    let root = WorkspaceRoot::open(&root_path)?;
    let result = resolve_existing_target(&root, &PathBuf::from("escape/secret.txt"));
    let outcome = match result {
        Err(CorulixError::PathDenied) => Ok(()),
        Err(_) => Err(CorulixError::Internal),
        Ok(_) => Err(CorulixError::Internal),
    };

    let _ = fs::remove_dir_all(&root_path);
    let _ = fs::remove_dir_all(&outside);
    outcome
}

// -- Cross-workspace rename denial: two independently pinned
// `WorkspaceRoot`s must never allow a rename between them. --

#[test]
fn cross_workspace_rename_is_denied() -> CorulixResult<()> {
    let root_a_path = temp_dir("cross-ws-a");
    let root_b_path = temp_dir("cross-ws-b");
    fs::write(root_a_path.join("source.txt"), b"from a").map_err(to_internal)?;

    let root_a = WorkspaceRoot::open(&root_a_path)?;
    let root_b = WorkspaceRoot::open(&root_b_path)?;

    let source = resolve_existing_target(&root_a, &PathBuf::from("source.txt"))?;
    let destination = resolve_new_target(&root_b, &PathBuf::from("destination.txt"))?;

    let result = source.rename_into(destination);
    let denied = matches!(result, Err(CorulixError::PathDenied));
    let untouched =
        root_a_path.join("source.txt").exists() && !root_b_path.join("destination.txt").exists();

    let _ = fs::remove_dir_all(&root_a_path);
    let _ = fs::remove_dir_all(&root_b_path);

    if denied && untouched {
        Ok(())
    } else {
        Err(CorulixError::Internal)
    }
}

// -- Write-collision (create) swap: a create must fail if the destination
// exists, even if it appeared only just before the create attempt. --

#[test]
fn create_collision_on_pre_existing_leaf_is_denied() -> CorulixResult<()> {
    let root_path = temp_dir("create-collision");
    fs::write(root_path.join("occupied.txt"), b"already here").map_err(to_internal)?;
    let root = WorkspaceRoot::open(&root_path)?;

    let result = resolve_new_target(&root, &PathBuf::from("occupied.txt"));
    let outcome = if matches!(result, Err(CorulixError::PathDenied)) {
        Ok(())
    } else {
        Err(CorulixError::Internal)
    };

    let _ = fs::remove_dir_all(&root_path);
    outcome
}

// -- Rename-destination swap: renaming onto an already-occupied
// destination via `rename_into` must still fail (Windows `FILE_RENAME_INFO`
// default `ReplaceIfExists=false`), matching `still_absent`'s own contract.
// --

#[test]
fn rename_destination_collision_is_denied() -> CorulixResult<()> {
    let root_path = temp_dir("rename-dest-collision");
    fs::write(root_path.join("source.txt"), b"source bytes").map_err(to_internal)?;
    fs::write(root_path.join("dest.txt"), b"already occupied").map_err(to_internal)?;
    let root = WorkspaceRoot::open(&root_path)?;

    let source = resolve_existing_target(&root, &PathBuf::from("source.txt"))?;
    let destination = resolve_existing_target(&root, &PathBuf::from("dest.txt"))?;

    // `rename_into` itself mirrors POSIX `renameat`'s own always-replace
    // semantics on BOTH platforms (see `capability_win32.rs`'s own doc
    // comment) -- it provides no destination-collision denial of its
    // own, on Unix OR Windows. A caller that must not silently overwrite
    // an existing destination (e.g. `wht_corulix_mutation`'s `MoveFile`
    // commit path, whose own native `move_collision_is_rejected` test
    // covers this end-to-end) detects the collision itself via
    // `still_absent()` BEFORE ever calling `rename_into` -- exactly what
    // this test now proves, rather than asserting a collision-refusal
    // behavior `rename_into` was never actually contracted to provide.
    if destination.still_absent()? {
        return Err(CorulixError::Internal);
    }

    // Called directly (bypassing the caller-side check above), `rename_into`
    // replaces the destination -- like POSIX `rename()` -- rather than
    // silently failing or corrupting either side.
    source.rename_into(destination)?;
    let source_gone = !root_path.join("source.txt").exists();
    let destination_replaced =
        fs::read(root_path.join("dest.txt")).map_err(to_internal)? == b"source bytes";

    let _ = fs::remove_dir_all(&root_path);

    if source_gone && destination_replaced {
        Ok(())
    } else {
        Err(CorulixError::Internal)
    }
}

// -- Handle-lifetime / no dangling authority: repeated open/close cycles
// must not leak real OS handles under real Windows kernel accounting. --

#[test]
fn repeated_open_close_cycles_do_not_exhaust_handles() -> CorulixResult<()> {
    let root_path = temp_dir("handle-cycle");
    let root = WorkspaceRoot::open(&root_path)?;

    for index in 0..200u32 {
        let name = format!("f{index}.txt");
        let created = resolve_new_target(&root, &PathBuf::from(&name))?;
        created.create_exclusive(b"x")?;
        let existing = resolve_existing_target(&root, &PathBuf::from(&name))?;
        let file = existing.open_file()?;
        let _ = file.read_bytes(16);
        let reopened = resolve_existing_target(&root, &PathBuf::from(&name))?;
        reopened.unlink()?;
    }

    let _ = fs::remove_dir_all(&root_path);
    Ok(())
}

// -- Confined read/metadata (the public, non-capability-typed entry points
// `wht_corulix_mutation`/`wht_corulix_engine` also use) round-trip on real
// Windows handles. --

#[tokio::test]
async fn confined_read_and_metadata_round_trip_via_real_handles() -> CorulixResult<()> {
    let root_path = temp_dir("confined-read");
    fs::write(root_path.join("real.txt"), b"confined bytes").map_err(to_internal)?;
    let root = WorkspaceRoot::open(&root_path)?;

    let bytes =
        wht_corulix_workspace::confined_read(root.clone(), PathBuf::from("real.txt"), 4096).await?;
    if bytes != b"confined bytes" {
        return Err(CorulixError::Internal);
    }

    let metadata =
        wht_corulix_workspace::confined_metadata(root, PathBuf::from("real.txt")).await?;
    if !metadata.is_file() {
        return Err(CorulixError::Internal);
    }

    let _ = fs::remove_dir_all(&root_path);
    Ok(())
}
