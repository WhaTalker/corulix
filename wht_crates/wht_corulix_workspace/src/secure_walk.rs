// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09 remediation P2: the secure, pinned-directory-fd component walker.
//!
//! Crate-internal only (Architecture Rule F: confinement authority lives
//! solely in this crate) -- nothing here is exported from `lib.rs`. This is
//! the foundation P3's opaque `PinnedParent`/`PinnedFile` capability API
//! will wrap; no other crate touches it, and no consumer inside this crate
//! migrates onto it yet either (P2 scope is the primitive itself).
//!
//! # Security model
//!
//! `WorkspaceRoot::root_fd()` is the ONLY trusted starting point. Every
//! subsequent directory that becomes authoritative is opened with a single
//! path *component* (never a multi-component attacker-controlled string)
//! relative to an already-open directory fd (`openat(cur_fd, component,
//! O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`). Once a hop succeeds, the
//! resulting fd is authority: a later rename/replacement of that
//! component's own pathname, or of any ancestor's pathname, cannot redirect
//! it, because nothing after that point ever re-resolves a pathname to
//! reach it again.
//!
//! Internal symlinks remain supported (existing M09 contract, preserved
//! exactly): when a component turns out to be a symlink, its target text is
//! read once (`readlinkat`, relative to the already-pinned containing
//! directory) and re-injected as new components to resolve -- from the
//! PINNED ROOT fd if the target is absolute (translated to workspace-
//! relative components via a component-boundary-aware, filesystem-I/O-free
//! comparison against `WorkspaceRoot::canonical_path()` -- never a raw
//! string-prefix check, which the sibling-prefix-confusion class of bug
//! specifically exploits), or from the symlink's own containing directory
//! if the target is relative. `..` inside a symlink target is handled by
//! popping an already-pinned fd off this walk's own stack -- never by
//! issuing `openat(fd, "..", ...)`, which would let the kernel re-walk
//! upward through whatever the current filesystem state is, entirely
//! outside this module's own bookkeeping.
//!
//! M09-P3 update: `capability.rs` is now this module's real production
//! consumer (`secure_resolve`/`secure_resolve_parent`/`TerminalMode`/
//! `WalkResult` are all called from its non-test code) -- the P2-era
//! staging `#![allow(dead_code)]` that used to live here has been removed
//! per the P3 mandate's own Section 26.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use wht_corulix_core::{CorulixError, CorulixResult};

use crate::confine::WorkspaceRoot;

/// Frozen by the M09 architecture-freeze pass.
const MAX_SYMLINK_HOPS: u32 = 40;

/// Defensive backstop against any queue-growth pattern this design didn't
/// anticipate -- the symlink hop limit above is the primary, meaningful
/// bound; this is belt-and-braces only and should never be the limit that
/// actually trips in practice.
const MAX_QUEUE_ITERATIONS: u32 = 10_000;

/// One item still waiting to be resolved. Distinct from a plain
/// `OsString` so a symlink target's `..` component can be represented
/// without ever being handed to `openat` as a literal `".."` path
/// argument (Section 6's own requirement).
enum QueueItem {
    Name(OsString),
    Up,
}

/// P2's internal result: a pinned parent directory (owned fd, kept
/// entirely inside this crate) plus the final, syntactically-validated
/// leaf component name. The leaf is deliberately never opened/resolved
/// here -- what a leaf symlink means is operation-specific (Create's
/// `O_EXCL`, Replace/Delete's rename-the-entry-itself semantics), and that
/// belongs to P3/P5, not to path-resolution.
pub(crate) struct WalkResult {
    pub(crate) parent_fd: rustix::fd::OwnedFd,
    pub(crate) leaf: OsString,
}

/// M09-P3: how the walk's FINAL (terminal) component should be treated,
/// once every earlier ancestor has already been resolved exactly as
/// before. Ancestors are never affected by this -- they are always
/// resolved as directories, symlinks always followed, regardless of mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalMode {
    /// P2's original, unchanged behavior (used for `PIN_PARENT_ONLY` and,
    /// as its first step, `NEW_TARGET_REQUIRE_ABSENT_FINAL_ENTRY`): the
    /// final component is returned exactly as named, completely unprobed
    /// -- no `openat`, no `readlinkat`, no I/O against it at all. What it
    /// is (absent, a file, a directory, a symlink) is entirely the
    /// caller's concern.
    ReturnUnprobed,
    /// `EXISTING_TARGET_FOLLOW_SAFE_FINAL_SYMLINK` (Section 7 of the P3
    /// mandate): if the final component turns out to be a symlink, follow
    /// it exactly like an ancestor symlink would be followed (component-
    /// aware absolute-target translation, relative-target resolution from
    /// its own containing directory, same hop budget) and re-evaluate
    /// whatever it resolves to as the new final component -- repeating
    /// until a non-symlink name (or absence) is reached, which is then
    /// the real, bound target. Preserves the historical
    /// canonicalize-based "symlink to inside workspace: ALLOWED, symlink
    /// to outside: DENIED" contract for the FINAL component too, not only
    /// for ancestors.
    FollowIfSymlink,
}

// M09-P2 deterministic component-swap seam: invoked, synchronously, with
// the number of ancestor hops already pinned, immediately before this
// module attempts to resolve the NEXT queued item -- letting a test swap
// an already-pinned ancestor's own pathname (proving the swap cannot
// redirect traversal, since the already-open fd is reused, never a
// pathname), or swap the pathname of the component about to be resolved
// (proving `O_NOFOLLOW` rejects a symlink substituted in that exact
// window), without relying on timing/races. Zero release-build presence,
// matching this crate's established `WorkspaceRoot::open` construction-race
// seam (P1) and `wht_corulix_mutation::MutationExecutor`'s `precommit_hook`.
#[cfg(any(test, feature = "test-support"))]
type WalkSwapHook = Box<dyn Fn(u32)>;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static WALK_SWAP_HOOK: std::cell::RefCell<Option<WalkSwapHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
fn run_walk_swap_hook(hops_pinned: u32) {
    WALK_SWAP_HOOK.with(|cell| {
        if let Some(hook) = cell.borrow().as_ref() {
            hook(hops_pinned);
        }
    });
}

#[cfg(not(any(test, feature = "test-support")))]
fn run_walk_swap_hook(_hops_pinned: u32) {}

/// Opens `"."` relative to `dirfd` -- the portable way to obtain a fresh,
/// independent `OwnedFd` to the exact same directory object a borrowed fd
/// refers to, without a dedicated `dup` syscall wrapper. Never follows a
/// symlink (`"."` cannot be one).
fn reopen_dot(dirfd: rustix::fd::BorrowedFd<'_>) -> CorulixResult<rustix::fd::OwnedFd> {
    rustix::fs::openat(
        dirfd,
        ".",
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| CorulixError::PathDenied)
}

/// Translates a relative `Path` (a symlink target's own relative form, or
/// the workspace-relative remainder of an absolute target once its prefix
/// has already been stripped) into queue items. Rejects any `RootDir`/
/// `Prefix` component defensively (a well-formed relative `Path` never has
/// one) -- fail closed rather than silently ignore something unexpected.
fn components_to_queue_items(path: &Path) -> CorulixResult<Vec<QueueItem>> {
    let mut items = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => items.push(QueueItem::Name(name.to_os_string())),
            Component::ParentDir => items.push(QueueItem::Up),
            Component::RootDir | Component::Prefix(_) => return Err(CorulixError::PathDenied),
        }
    }
    Ok(items)
}

/// Reads a symlink's stored target text (relative to its own, already-
/// pinned containing directory -- never a re-resolved pathname) and
/// returns it as a `PathBuf` for lexical (never filesystem-touching)
/// inspection.
fn read_symlink_target(
    containing_dir: rustix::fd::BorrowedFd<'_>,
    component: &OsStr,
) -> CorulixResult<PathBuf> {
    let raw = rustix::fs::readlinkat(containing_dir, component, Vec::new())
        .map_err(|_| CorulixError::PathDenied)?;
    Ok(PathBuf::from(OsString::from_vec(raw.into_bytes())))
}

/// Component-boundary-aware absolute-symlink-target translation (Section
/// 8): `Path::strip_prefix` compares whole path *components*, never raw
/// string bytes, so `"/workspace-evil/file"` can never be mistaken for a
/// path under `"/workspace"` the way a naive `str::starts_with` would
/// allow -- this is what makes the sibling-prefix-confusion class of bug
/// structurally impossible here, not merely tested against.
///
/// The comparison is purely lexical against `root.canonical_path()`'s
/// cached display string -- no filesystem access happens in this
/// function. That string is used ONLY to decide how to reinterpret the
/// symlink's own stored text; every actual filesystem resolution still
/// happens exclusively through `root.root_fd()`'s pinned identity, so a
/// later replacement of the root's own pathname cannot redirect this
/// translation into touching the wrong object (Section 9).
fn translate_absolute_target(root: &WorkspaceRoot, target: &Path) -> CorulixResult<Vec<QueueItem>> {
    let remainder = target
        .strip_prefix(root.canonical_path())
        .map_err(|_| CorulixError::PathDenied)?;
    components_to_queue_items(remainder)
}

/// The P2 secure component walk, unchanged public shape/behavior:
/// resolves `relative`'s PARENT directory chain from `root`'s pinned fd,
/// following internal symlinks safely, and returns a pinned parent fd
/// plus the validated (but never itself resolved) leaf name. Equivalent
/// to `secure_resolve(root, relative, TerminalMode::ReturnUnprobed)`.
///
/// M09-P5: production use is via `PinnedParent::resolve`
/// (STAGE/`PIN_PARENT_ONLY`), reached from `MutationExecutor` through the
/// `resolve_parent` cross-crate wrapper.
pub(crate) fn secure_resolve_parent(
    root: &WorkspaceRoot,
    relative: &Path,
) -> CorulixResult<WalkResult> {
    secure_resolve(root, relative, TerminalMode::ReturnUnprobed)
}

/// M09-P3: the same walk, parameterized by how the FINAL component is
/// treated (`TerminalMode`) -- ancestors are resolved identically
/// regardless of mode (Section 7/9 of the P3 mandate: only the terminal
/// component's handling differs between resolution modes).
pub(crate) fn secure_resolve(
    root: &WorkspaceRoot,
    relative: &Path,
    terminal_mode: TerminalMode,
) -> CorulixResult<WalkResult> {
    // Step 1/2: identical syntactic validation to `resolve_confined_blocking`/
    // `confine_target_blocking` -- absolute paths and any `ParentDir`/
    // `RootDir`/`Prefix` component in the CALLER's own input are denied
    // before any I/O is attempted. `CurDir` and `Normal` are accepted.
    // `M09_P2_CALLER_PATH_CONTRACT_DELTA=NONE`.
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(CorulixError::PathDenied);
    }
    for component in relative.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CorulixError::PathDenied);
            }
        }
    }

    let leaf = relative
        .file_name()
        .ok_or(CorulixError::PathDenied)?
        .to_os_string();
    let parent_relative = relative
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());

    // Stack of already-pinned directory fds, root-first. Popping (for a
    // symlink's own `..`) reuses an already-open fd from this stack --
    // never a fresh `openat(fd, "..", ...)` call. `M09_P2_KERNEL_PARENTDIR_TRAVERSAL_COUNT=0`.
    let mut stack: Vec<rustix::fd::OwnedFd> = vec![reopen_dot(root.root_fd())?];
    let mut queue: VecDeque<QueueItem> = match parent_relative {
        Some(parent) => components_to_queue_items(parent)?.into(),
        None => VecDeque::new(),
    };
    // The leaf is pushed onto the SAME queue as one final item -- this is
    // what lets `TerminalMode::FollowIfSymlink` treat it with the exact
    // same symlink-following machinery ancestors already use, rather than
    // duplicating that logic in a second pass.
    queue.push_back(QueueItem::Name(leaf));

    let mut hops_pinned: u32 = 0;
    let mut symlink_hops: u32 = 0;
    let mut iterations: u32 = 0;

    while let Some(item) = queue.pop_front() {
        iterations += 1;
        if iterations > MAX_QUEUE_ITERATIONS {
            return Err(CorulixError::PathDenied);
        }
        run_walk_swap_hook(hops_pinned);

        match item {
            QueueItem::Up => {
                // Only ever pops an already-pinned fd this walk itself
                // opened earlier -- depth cannot go negative, and no
                // syscall re-walks anything. `M09_P2_SYMLINK_PARENTDIR_ESCAPE_COUNT=0`.
                if stack.len() <= 1 {
                    return Err(CorulixError::PathDenied);
                }
                stack.pop();
                hops_pinned = hops_pinned.saturating_sub(1);
            }
            QueueItem::Name(component) => {
                let is_last = queue.is_empty();
                if is_last && terminal_mode == TerminalMode::ReturnUnprobed {
                    // P2's original terminal behavior: no I/O against the
                    // final component at all -- return it exactly as
                    // named.
                    let cur = stack.last().ok_or(CorulixError::Internal)?;
                    let parent_fd = reopen_dot(cur.as_fd())?;
                    return Ok(WalkResult {
                        parent_fd,
                        leaf: component,
                    });
                }

                let cur = stack.last().ok_or(CorulixError::Internal)?;
                match rustix::fs::openat(
                    cur,
                    component.as_os_str(),
                    rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                ) {
                    Ok(next_fd) => {
                        if is_last {
                            // Terminal component, `FollowIfSymlink` mode,
                            // and it opened successfully as a directory --
                            // it is a real directory (not a symlink), so
                            // this IS the final answer: return it as the
                            // bound leaf under its current parent, rather
                            // than descending into it as though it were an
                            // ancestor. `next_fd` is discarded (the caller
                            // opens/validates the leaf itself, e.g.
                            // `open_file`'s own regular-file check, which
                            // correctly rejects a directory there).
                            drop(next_fd);
                            let parent_fd = reopen_dot(cur.as_fd())?;
                            return Ok(WalkResult {
                                parent_fd,
                                leaf: component,
                            });
                        }
                        stack.push(next_fd);
                        hops_pinned += 1;
                    }
                    Err(_) => {
                        // Not opened directly -- either it is a symlink
                        // (handled below) or it genuinely cannot be
                        // traversed at all (missing, not a directory,
                        // permission denied). `readlinkat` is the single
                        // probe that distinguishes the two: it succeeds
                        // only for an actual symlink.
                        let cur = stack.last().ok_or(CorulixError::Internal)?;
                        let Ok(target) = read_symlink_target(cur.as_fd(), component.as_os_str())
                        else {
                            // Not a symlink (or genuinely absent/inaccessible).
                            if is_last {
                                // Terminal component, `FollowIfSymlink`
                                // mode (the only mode that reaches this
                                // branch when `is_last`): this is the
                                // real, final answer -- whatever it is
                                // (a regular file, absent, or something
                                // else the caller's own operation-
                                // specific open will judge).
                                let parent_fd = reopen_dot(cur.as_fd())?;
                                return Ok(WalkResult {
                                    parent_fd,
                                    leaf: component,
                                });
                            }
                            // A genuine ancestor that is neither a
                            // directory nor a symlink: dead end.
                            return Err(CorulixError::PathDenied);
                        };

                        symlink_hops += 1;
                        if symlink_hops > MAX_SYMLINK_HOPS {
                            return Err(CorulixError::PathDenied);
                        }

                        if target.is_absolute() {
                            let items = translate_absolute_target(root, &target)?;
                            // Re-anchor at the pinned root -- an absolute
                            // target is honored only via the fd chain,
                            // never via the OS's own absolute-path
                            // resolution. `M09_P2_ABSOLUTE_INTERNAL_SYMLINK_IO_USES_ROOT_FD=YES`.
                            stack.truncate(1);
                            hops_pinned = 0;
                            for new_item in items.into_iter().rev() {
                                queue.push_front(new_item);
                            }
                        } else {
                            let items = components_to_queue_items(&target)?;
                            // Relative: resolved from the symlink's own
                            // containing directory (`cur`, unchanged) --
                            // stack/hops_pinned stay as they are.
                            for new_item in items.into_iter().rev() {
                                queue.push_front(new_item);
                            }
                        }
                    }
                }
            }
        }
    }

    // Only reachable if the leaf itself resolved (via one or more
    // symlink hops) all the way down to being the LAST-remaining
    // ancestor-shaped push with nothing left in the queue after it was
    // itself opened as a directory (e.g. `FollowIfSymlink` on a target
    // whose final symlink chain ends in a directory) -- the stack's top
    // is then the answer, with an empty leaf name being nonsensical here,
    // so this path is guarded structurally: every `Name` branch above
    // returns before falling through except the successful `openat`
    // (directory) case, which loops back to `pop_front` and, when the
    // queue is empty, exits the `while` naturally. Treat that as an
    // internal invariant violation rather than silently fabricating a
    // leaf.
    Err(CorulixError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root =
            std::env::temp_dir().join(format!("corulix-p2-{label}-{}-{stamp}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        root
    }

    fn open_root(path: &Path) -> CorulixResult<WorkspaceRoot> {
        WorkspaceRoot::open(path)
    }

    /// Identity proof helper: the parent fd this walk returns really does
    /// refer to the expected on-disk directory, via `fstat` comparison --
    /// never by re-deriving/trusting a pathname.
    // Cast stays for portability across rustix backends whose `Stat`
    // fields are not always `u64` (see `WorkspaceRootIdentity::from_stat`
    // in `confine.rs` for the same, already-established justification).
    #[allow(clippy::unnecessary_cast)]
    fn same_object(fd: rustix::fd::BorrowedFd<'_>, path: &Path) -> bool {
        let Ok(stat) = rustix::fs::fstat(fd) else {
            return false;
        };
        let Ok(metadata) = fs::metadata(path) else {
            return false;
        };
        use std::os::unix::fs::MetadataExt;
        stat.st_dev as u64 == metadata.dev() && stat.st_ino as u64 == metadata.ino()
    }

    #[test]
    fn normal_multi_component_walk() -> CorulixResult<()> {
        let root_path = temp_dir("normal");
        fs::create_dir_all(root_path.join("a/b")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/b/c.rs"))?;
        assert_eq!(result.leaf, OsStr::new("c.rs"));
        assert!(same_object(
            result.parent_fd.as_fd(),
            &root_path.join("a/b")
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn relative_internal_symlink_alias_is_followed() -> CorulixResult<()> {
        let root_path = temp_dir("rel-alias");
        fs::create_dir_all(root_path.join("real_a")).map_err(|_| CorulixError::Internal)?;
        symlink("real_a", root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"))?;
        assert_eq!(result.leaf, OsStr::new("file.rs"));
        assert!(same_object(
            result.parent_fd.as_fd(),
            &root_path.join("real_a")
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn relative_internal_symlink_sub_path_is_followed() -> CorulixResult<()> {
        let root_path = temp_dir("rel-sub");
        fs::create_dir_all(root_path.join("sub/real_a")).map_err(|_| CorulixError::Internal)?;
        symlink("sub/real_a", root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"))?;
        assert!(same_object(
            result.parent_fd.as_fd(),
            &root_path.join("sub/real_a")
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn relative_symlink_to_allowed_sibling() -> CorulixResult<()> {
        let root_path = temp_dir("rel-sibling");
        fs::create_dir_all(root_path.join("allowed_sibling"))
            .map_err(|_| CorulixError::Internal)?;
        fs::create_dir_all(root_path.join("nested")).map_err(|_| CorulixError::Internal)?;
        symlink("../allowed_sibling", root_path.join("nested/a"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("nested/a/file.rs"))?;
        assert!(same_object(
            result.parent_fd.as_fd(),
            &root_path.join("allowed_sibling")
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn relative_symlink_nested_up_to_real() -> CorulixResult<()> {
        let root_path = temp_dir("rel-nested-up");
        fs::create_dir_all(root_path.join("real")).map_err(|_| CorulixError::Internal)?;
        fs::create_dir_all(root_path.join("nested")).map_err(|_| CorulixError::Internal)?;
        symlink("../real", root_path.join("nested/a")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("nested/a/file.rs"))?;
        assert!(same_object(
            result.parent_fd.as_fd(),
            &root_path.join("real")
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn relative_symlink_attempting_above_root_is_denied() -> CorulixResult<()> {
        let root_path = temp_dir("rel-above-root");
        fs::create_dir_all(root_path.join("nested")).map_err(|_| CorulixError::Internal)?;
        // From `nested/a`, `../../attempt_above_root` needs to climb two
        // levels -- one to `root_path` (fine), one more above it (must be
        // denied): depth after entering `nested` is 1; the symlink itself
        // replaces the second component, so resolving from `nested`'s
        // pinned fd, `..` once reaches the pinned root (depth 0), and the
        // second `..` must fail closed rather than reach the real OS
        // parent of `root_path`.
        symlink("../../attempt_above_root", root_path.join("nested/a"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("nested/a/file.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn absolute_internal_symlink_inside_workspace_is_followed() -> CorulixResult<()> {
        let root_path = temp_dir("abs-inside");
        fs::create_dir_all(root_path.join("real_a")).map_err(|_| CorulixError::Internal)?;
        let canonical_root = fs::canonicalize(&root_path).map_err(|_| CorulixError::Internal)?;
        symlink(canonical_root.join("real_a"), root_path.join("a"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"))?;
        assert!(same_object(
            result.parent_fd.as_fd(),
            &root_path.join("real_a")
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn absolute_symlink_to_outside_is_denied() -> CorulixResult<()> {
        let root_path = temp_dir("abs-outside");
        let outside = temp_dir("abs-outside-target");
        symlink(&outside, root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn absolute_symlink_sibling_prefix_confusion_is_denied() -> CorulixResult<()> {
        let root_path = temp_dir("abs-prefix");
        // A sibling directory whose name has this workspace's own
        // canonical path as a literal STRING prefix, but is a completely
        // different directory -- the exact case a naive `starts_with`
        // string check would wrongly accept.
        let canonical_root = fs::canonicalize(&root_path).map_err(|_| CorulixError::Internal)?;
        let mut evil_name = canonical_root.clone().into_os_string();
        evil_name.push("-evil");
        let sibling_confusable = PathBuf::from(evil_name);
        fs::create_dir_all(&sibling_confusable).map_err(|_| CorulixError::Internal)?;
        symlink(sibling_confusable.join("file.rs"), root_path.join("a"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&sibling_confusable);
        Ok(())
    }

    #[test]
    fn absolute_symlink_after_root_path_replacement_still_resolves_via_fd() -> CorulixResult<()> {
        let root_path = temp_dir("abs-after-replace");
        fs::create_dir_all(root_path.join("real_a")).map_err(|_| CorulixError::Internal)?;
        let canonical_root = fs::canonicalize(&root_path).map_err(|_| CorulixError::Internal)?;
        symlink(canonical_root.join("real_a"), root_path.join("a"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        // Replace the root's own pathname with an unrelated directory.
        // `root`'s fd is already pinned; the symlink translation below
        // uses `root.canonical_path()` only as lexical text (never for
        // I/O), so this must not redirect resolution.
        let moved_away = temp_dir("abs-after-replace-moved");
        fs::rename(&root_path, &moved_away).map_err(|_| CorulixError::Internal)?;
        fs::create_dir_all(&root_path).map_err(|_| CorulixError::Internal)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"))?;
        assert!(same_object(
            result.parent_fd.as_fd(),
            &moved_away.join("real_a")
        ));

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&moved_away);
        Ok(())
    }

    #[test]
    fn internal_symlink_chain_resolves() -> CorulixResult<()> {
        let root_path = temp_dir("chain");
        fs::create_dir_all(root_path.join("real")).map_err(|_| CorulixError::Internal)?;
        symlink("real", root_path.join("c")).map_err(|_| CorulixError::Internal)?;
        symlink("c", root_path.join("b")).map_err(|_| CorulixError::Internal)?;
        symlink("b", root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"))?;
        assert!(same_object(
            result.parent_fd.as_fd(),
            &root_path.join("real")
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn mixed_relative_absolute_chain_resolves() -> CorulixResult<()> {
        let root_path = temp_dir("chain-mixed");
        fs::create_dir_all(root_path.join("real")).map_err(|_| CorulixError::Internal)?;
        let canonical_root = fs::canonicalize(&root_path).map_err(|_| CorulixError::Internal)?;
        symlink("real", root_path.join("c")).map_err(|_| CorulixError::Internal)?;
        symlink(canonical_root.join("c"), root_path.join("b"))
            .map_err(|_| CorulixError::Internal)?;
        symlink("b", root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"))?;
        assert!(same_object(
            result.parent_fd.as_fd(),
            &root_path.join("real")
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn chain_ending_outside_is_denied() -> CorulixResult<()> {
        let root_path = temp_dir("chain-outside");
        let outside = temp_dir("chain-outside-target");
        symlink(&outside, root_path.join("c")).map_err(|_| CorulixError::Internal)?;
        symlink("c", root_path.join("b")).map_err(|_| CorulixError::Internal)?;
        symlink("b", root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn symlink_cycle_fails_closed_deterministically() -> CorulixResult<()> {
        let root_path = temp_dir("cycle");
        symlink("b", root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        symlink("a", root_path.join("b")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn symlink_self_link_fails_closed_deterministically() -> CorulixResult<()> {
        let root_path = temp_dir("self-link");
        symlink("a", root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn hop_limit_is_enforced() -> CorulixResult<()> {
        let root_path = temp_dir("hop-limit");
        fs::create_dir_all(root_path.join("real")).map_err(|_| CorulixError::Internal)?;
        symlink("real", root_path.join("link0")).map_err(|_| CorulixError::Internal)?;
        for index in 1..45 {
            symlink(
                format!("link{}", index - 1),
                root_path.join(format!("link{index}")),
            )
            .map_err(|_| CorulixError::Internal)?;
        }
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("link44/file.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn directory_symlink_component_inside_is_followed() -> CorulixResult<()> {
        let root_path = temp_dir("dir-symlink-inside");
        fs::create_dir_all(root_path.join("real_dir/sub")).map_err(|_| CorulixError::Internal)?;
        symlink("real_dir", root_path.join("linkdir")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("linkdir/sub/file.rs"))?;
        assert!(same_object(
            result.parent_fd.as_fd(),
            &root_path.join("real_dir/sub")
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn directory_symlink_component_outside_is_denied() -> CorulixResult<()> {
        let root_path = temp_dir("dir-symlink-outside");
        let outside = temp_dir("dir-symlink-outside-target");
        fs::create_dir_all(outside.join("sub")).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, root_path.join("linkdir")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = secure_resolve_parent(&root, Path::new("linkdir/sub/file.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn ancestor_swap_after_first_pin_does_not_redirect() -> CorulixResult<()> {
        let root_path = temp_dir("ancestor-swap-1");
        fs::create_dir_all(root_path.join("a/b")).map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("ancestor-swap-1-outside");
        fs::create_dir_all(outside.join("b")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let a_path = root_path.join("a");
        // The original `a` (with its real `b` child, which the walker
        // still needs to reach via the already-pinned `a` fd) is moved
        // aside intact -- never destroyed -- so a symlink can occupy `a`'s
        // OLD pathname without touching the real object the pin refers
        // to. `remove_dir_all` would be wrong here: it would delete the
        // real `b` the test still needs the walk to reach.
        let a_moved_away = temp_dir("ancestor-swap-1-moved");
        let outside_for_hook = outside.clone();
        let a_path_for_hook = a_path.clone();
        let a_moved_away_for_hook = a_moved_away.clone();
        WALK_SWAP_HOOK.with(|cell| {
            *cell.borrow_mut() = Some(Box::new(move |hops_pinned: u32| {
                // Fires before resolving `b` (hops_pinned == 1, i.e. `a`
                // is already pinned) -- swap `a`'s own pathname for a
                // symlink to an outside directory that ALSO has a `b`
                // subdirectory, so a redirection would be silently
                // plausible if it happened.
                if hops_pinned == 1 {
                    let _ = fs::rename(&a_path_for_hook, &a_moved_away_for_hook);
                    let _ = symlink(&outside_for_hook, &a_path_for_hook);
                }
            }));
        });

        let result = secure_resolve_parent(&root, Path::new("a/b/file.rs"));
        WALK_SWAP_HOOK.with(|cell| *cell.borrow_mut() = None);

        let result = result?;
        assert!(
            same_object(result.parent_fd.as_fd(), &a_moved_away.join("b")),
            "traversal must continue via the already-pinned `a` fd (now reachable only at its \
             moved-away pathname), never the swapped pathname"
        );
        assert!(!same_object(result.parent_fd.as_fd(), &outside.join("b")));

        let _ = fs::remove_file(&a_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&a_moved_away);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn nested_ancestor_swap_does_not_redirect() -> CorulixResult<()> {
        let root_path = temp_dir("ancestor-swap-nested");
        fs::create_dir_all(root_path.join("a/b/c")).map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("ancestor-swap-nested-outside");
        let root = open_root(&root_path)?;

        let a_path = root_path.join("a");
        let a_moved_away = temp_dir("ancestor-swap-nested-moved");
        let outside_for_hook = outside.clone();
        let a_path_for_hook = a_path.clone();
        let a_moved_away_for_hook = a_moved_away.clone();
        WALK_SWAP_HOOK.with(|cell| {
            *cell.borrow_mut() = Some(Box::new(move |hops_pinned: u32| {
                // Fires before resolving `c` (hops_pinned == 2, i.e. both
                // `a` and `b` are already pinned) -- swap the ORIGINAL
                // `a` (an ancestor two levels above the current hop, not
                // just the immediate parent) for a symlink to outside,
                // preserving `a`'s real subtree (including `b/c`) intact
                // at its moved-away location.
                if hops_pinned == 2 {
                    let _ = fs::rename(&a_path_for_hook, &a_moved_away_for_hook);
                    let _ = symlink(&outside_for_hook, &a_path_for_hook);
                }
            }));
        });

        let result = secure_resolve_parent(&root, Path::new("a/b/c/d.rs"));
        WALK_SWAP_HOOK.with(|cell| *cell.borrow_mut() = None);

        let result = result?;
        assert!(same_object(
            result.parent_fd.as_fd(),
            &a_moved_away.join("b/c")
        ));

        let _ = fs::remove_file(&a_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&a_moved_away);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn current_component_symlink_swap_cannot_escape() -> CorulixResult<()> {
        let root_path = temp_dir("current-swap");
        fs::create_dir_all(root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("current-swap-outside");
        let root = open_root(&root_path)?;

        let a_path = root_path.join("a");
        let outside_for_hook = outside.clone();
        WALK_SWAP_HOOK.with(|cell| {
            *cell.borrow_mut() = Some(Box::new(move |hops_pinned: u32| {
                // Fires immediately before the FIRST hop is even
                // attempted (hops_pinned == 0): swap `a` itself, right
                // before its own `openat`, for a symlink to outside.
                if hops_pinned == 0 {
                    let _ = fs::remove_dir_all(&a_path);
                    let _ = symlink(&outside_for_hook, &a_path);
                }
            }));
        });

        let result = secure_resolve_parent(&root, Path::new("a/file.rs"));
        WALK_SWAP_HOOK.with(|cell| *cell.borrow_mut() = None);

        assert!(
            matches!(result, Err(CorulixError::PathDenied)),
            "O_NOFOLLOW on the single-component openat must reject a symlink substituted \
             immediately before that exact call"
        );

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }
}
