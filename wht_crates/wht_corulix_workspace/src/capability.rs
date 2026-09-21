// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09 remediation P3: opaque, cross-crate-safe filesystem capabilities.
//!
//! This is the first-party API other crates in this workspace will
//! eventually consume (P4 direct-read, P5 mutation) -- but P3 itself does
//! not migrate any existing consumer. `wht_corulix_workspace` remains the
//! sole crate that ever calls `openat`/`renameat`/`unlinkat`/`readlinkat`/
//! `fstat` (Architecture Rule F): every type here is `pub` so it CAN cross
//! a crate boundary, but every field is private, every constructor goes
//! through [`crate::confine::WorkspaceRoot`]'s own confinement authority
//! (`P1`/`P2`), and no method accepts a consumer-supplied path/leaf --
//! `PinnedTarget`'s bound leaf is produced only by the secure resolver in
//! `secure_walk`, never constructible from an arbitrary `OsStr` (P3
//! mandate Section 6).
//!
//! No `RawFd`/`OwnedFd`/`BorrowedFd`/`RawHandle`/`OwnedHandle` is ever
//! part of this module's public surface.
//!
//! M09-P4 update: `confine.rs`'s migrated `confined_read`/`confined_metadata`
//! are now real, non-test production consumers of `PinnedTarget::
//! resolve_existing`/`open_raw`/`PinnedFile::metadata` -- the P3-era
//! module-level `#![allow(dead_code)]` has been removed per this pass's
//! own Section 29.
//!
//! M09-P5 update: `wht_corulix_mutation`'s `MutationExecutor` is now a
//! real, cross-crate production consumer of every mutation primitive here
//! (`resolve_new`, `create_exclusive`, `unlink`/`unlink_verified`,
//! `rename_into`/`rename_into_verified`, `create_exclusive_temp_sibling`,
//! `still_absent`), reached through the additive `resolve_parent`/
//! `resolve_existing_target`/`resolve_new_target` free functions this pass
//! adds (Section 3 of the P5 mandate: `WorkspaceRoot` + a workspace-
//! relative path in, an opaque capability out -- never a raw leaf/fd/
//! handle). A handful of P3-era accessors (the three `root_identity()`
//! methods) turned out not to be needed by P5's actual design -- each
//! keeps its own narrow, explicitly justified `#[allow(dead_code)]` rather
//! than a blanket module-level one; see each one's own doc comment.
//!
//! M09-P4R remediation: `PinnedFile::read_bytes`'s pre-P4R implementation
//! checked `metadata.len()` once and then ran an entirely unbounded
//! `read_to_end`, so a same-object concurrent writer growing the file
//! between that check and the read could make actual byte acquisition
//! unbounded before the oversize outcome was decided -- a resource-bound
//! defect, not a namespace/confinement escape (the bytes still came from
//! the correctly pinned object). The read itself is now hard-capped via
//! `Read::take(max_bytes.saturating_add(1))`, so the acquired byte count
//! can never exceed `max_bytes + 1` regardless of concurrent growth; the
//! post-read length is re-checked against `max_bytes` so growth observed
//! during the read still yields `FileTooLarge`, never a truncated success.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::{CorulixError, CorulixResult};

use crate::confine::{WorkspaceRoot, WorkspaceRootIdentity};
use crate::secure_walk::{TerminalMode, secure_resolve, secure_resolve_parent};

/// One exact, already-authorized directory object (Section 11 of the P3
/// mandate). A later rename of its own pathname, or of any ancestor's
/// pathname, cannot redirect it -- nothing here ever re-resolves a
/// pathname to reach it again; every operation acts on the pinned fd
/// directly.
///
/// Deliberately not `Clone`: least authority / shortest lifetime (Section
/// 22) -- nothing in this crate's own P3 scope needs a second independent
/// owner of the same capability VALUE. Methods that need to hand out a
/// second reference to the SAME underlying object (e.g. producing a
/// [`PinnedTarget`] beneath this parent) do so internally via a cheap
/// `Arc` clone of the fd, never by re-deriving from a pathname.
pub struct PinnedParent {
    fd: Arc<OwnedFd>,
    root_identity: WorkspaceRootIdentity,
}

/// One exact, already-authorized parent directory PLUS one validated,
/// unforgeable leaf component (Section 5/6). The ONLY way to obtain one is
/// through `PinnedParent::resolve_existing`/`PinnedParent::resolve_new`
/// (crate-internal) -- there is no public constructor taking an arbitrary
/// leaf string, so a consumer holding a `PinnedTarget` can never smuggle
/// `../outside`, a multi-component path, or an absolute path back into a
/// previously-authorized parent.
pub struct PinnedTarget {
    parent_fd: Arc<OwnedFd>,
    leaf: OsString,
    root_identity: WorkspaceRootIdentity,
}

/// One exact, already-opened regular-file object (Section 10). Binds the
/// file the moment it is opened; a later pathname replacement cannot
/// redirect subsequent reads, because they act on the already-open file
/// object, never on a re-resolved path.
///
/// Deliberately not `Clone`, for the same reason as [`PinnedParent`].
pub struct PinnedFile {
    file: fs::File,
}

impl PinnedParent {
    /// `PIN_PARENT_ONLY` resolution mode (Section 9): resolves `relative`'s
    /// parent directory chain and returns a capability bound to it,
    /// discarding whatever the final component's own name was -- this is
    /// exactly what the STAGE primitive below needs (a directory to create
    /// an internally-named temporary sibling inside), and nothing else.
    ///
    /// M09-P5: `MutationExecutor`'s STAGE phase reaches this through the
    /// [`resolve_parent`] cross-crate wrapper below.
    pub(crate) fn resolve(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<Self> {
        let result = secure_resolve_parent(root, relative)?;
        Ok(Self {
            fd: Arc::new(result.parent_fd),
            root_identity: root.identity(),
        })
    }

    /// `SECURE_STAGE` primitive (Section 20-21 of the P3 mandate):
    /// creates an unpredictable, INTERNALLY generated leaf name, exclusively,
    /// inside this pinned directory, and writes `content` to it. The leaf
    /// name is never consumer-suppliable -- generated here, matching the
    /// existing `.corulix-stage-{pid}-{salt}-{nanos}` convention -- and
    /// security never depends on that name staying secret (Section 21):
    /// even a leaf name an attacker already knows cannot be used to redirect
    /// this create anywhere outside `self`'s own pinned directory object,
    /// because the create happens via `openat` relative to that pinned fd,
    /// never via a joined pathname.
    pub fn create_exclusive_temp_sibling(
        &self,
        content: &[u8],
    ) -> CorulixResult<(PinnedTarget, PinnedFile)> {
        for attempt in 0u32..8 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default();
            let leaf = OsString::from(format!(
                ".corulix-stage-{}-{attempt}-{nanos}",
                std::process::id()
            ));
            match create_exclusive_at(self.fd.as_fd(), &leaf, content) {
                Ok(file) => {
                    let target = PinnedTarget {
                        parent_fd: Arc::clone(&self.fd),
                        leaf,
                        root_identity: self.root_identity,
                    };
                    let pinned_file = PinnedFile { file };
                    return Ok((target, pinned_file));
                }
                Err(CorulixError::PathDenied) => continue,
                Err(other) => return Err(other),
            }
        }
        Err(CorulixError::Internal)
    }
}

impl PinnedTarget {
    /// `EXISTING_TARGET_FOLLOW_SAFE_FINAL_SYMLINK` resolution mode (Section
    /// 7): the final component, if a symlink, is followed safely (inside
    /// the workspace: bound to the real object; outside: denied) --
    /// preserving the historical canonicalize-based "symlink to inside:
    /// ALLOWED, symlink to outside: DENIED" contract for the target itself,
    /// not only for ancestors.
    pub(crate) fn resolve_existing(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<Self> {
        let result = secure_resolve(root, relative, TerminalMode::FollowIfSymlink)?;
        Ok(Self {
            parent_fd: Arc::new(result.parent_fd),
            leaf: result.leaf,
            root_identity: root.identity(),
        })
    }

    /// `NEW_TARGET_REQUIRE_ABSENT_FINAL_ENTRY` resolution mode (Section 8):
    /// the final component must be entirely absent -- a regular file,
    /// directory, symlink (dangling or not), all count as a collision and
    /// are never followed, matching M08's existing
    /// `entry_exists`/`symlink_metadata`-based semantics exactly.
    ///
    /// M09-P5: `MutationExecutor`'s Create/Move-destination authority
    /// reaches this through the [`resolve_new_target`] cross-crate wrapper
    /// below.
    pub(crate) fn resolve_new(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<Self> {
        let result = secure_resolve_parent(root, relative)?;
        if entry_exists_no_follow(result.parent_fd.as_fd(), result.leaf.as_os_str())? {
            return Err(CorulixError::PathDenied);
        }
        Ok(Self {
            parent_fd: Arc::new(result.parent_fd),
            leaf: result.leaf,
            root_identity: root.identity(),
        })
    }

    /// M09-P4: opens the bound entry WITHOUT enforcing any particular
    /// entry type -- crate-internal only; [`Self::open_file`] is the safe,
    /// type-checked public primitive built on top of this one.
    /// `confine.rs`'s own migrated `confined_read`/`confined_metadata`
    /// (Section 5 of the P4 mandate: a [`PinnedFile`] is the final read
    /// authority) use this directly so they can apply their OWN, pre-P4
    /// error-variant contract on the same-object metadata this returns,
    /// rather than `open_file`'s generic `PathDenied` (Section 28: do not
    /// change public reason codes unless required -- and it is not,
    /// because this primitive exists precisely to avoid that).
    ///
    /// `O_NONBLOCK` matters here specifically because this open is NOT
    /// type-restricted: without it, an attacker-planted FIFO at the bound
    /// leaf would make this call block indefinitely waiting for a writer
    /// (a real, if narrow, denial-of-service the pre-P4 `fs::metadata`-based
    /// implementation never had, since `stat` never opens anything) --
    /// `O_NONBLOCK` on a FIFO open returns immediately regardless of
    /// writer presence, closing that risk rather than introducing it.
    pub(crate) fn open_raw(&self) -> CorulixResult<PinnedFile> {
        let owned = rustix::fs::openat(
            self.parent_fd.as_fd(),
            self.leaf.as_os_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| CorulixError::PathDenied)?;
        Ok(PinnedFile {
            file: fs::File::from(owned),
        })
    }

    /// Opens the bound entry for reading. Requires it be a regular file
    /// (Section 10) -- a directory or other special file is rejected here,
    /// never silently treated as readable content. `O_NOFOLLOW` (inherited
    /// from `Self::open_raw`) is defense-in-depth: by construction, an
    /// `EXISTING_TARGET`-resolved leaf is already the real, non-symlink
    /// object, so this should never actually trigger, but nothing here
    /// re-trusts that without the flag also being set.
    pub fn open_file(&self) -> CorulixResult<PinnedFile> {
        let pinned = self.open_raw()?;
        let metadata = pinned.metadata().map_err(|_| CorulixError::Internal)?;
        if !metadata.is_file() {
            return Err(CorulixError::PathDenied);
        }
        Ok(pinned)
    }

    /// `SECURE_CREATE` primitive (Section 19): atomic create-if-absent via
    /// `O_EXCL`, relative to the bound parent fd and the bound leaf -- no
    /// pathname re-resolution, no join, ever.
    pub fn create_exclusive(&self, content: &[u8]) -> CorulixResult<PinnedFile> {
        let file = create_exclusive_at(self.parent_fd.as_fd(), self.leaf.as_os_str(), content)?;
        Ok(PinnedFile { file })
    }

    /// `SECURE_UNLINK` primitive (Section 18): removes the bound entry via
    /// `unlinkat(parent_fd, leaf, 0)` -- authorized parent fd plus bound
    /// leaf only, never a raw full pathname. Consumes `self`: once removed,
    /// the capability no longer refers to anything meaningful.
    pub fn unlink(self) -> CorulixResult<()> {
        rustix::fs::unlinkat(
            self.parent_fd.as_fd(),
            self.leaf.as_os_str(),
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|_| CorulixError::PathDenied)
    }

    /// `SECURE_RENAME` primitive (Section 17): takes TWO independently
    /// pre-authorized capabilities (`self` as source, `destination` as
    /// target) and renames via `renameat(source_parent_fd, source_leaf,
    /// dest_parent_fd, dest_leaf)` -- never a raw pathname re-resolved from
    /// process cwd. Fails closed if the two capabilities were derived from
    /// different `WorkspaceRoot`s (Section 34): cross-workspace move is not
    /// silently authorized, checked via opaque root-identity comparison,
    /// never `PathBuf` equality. Consumes both: after a rename, neither
    /// capability's own bound leaf refers to anything meaningful in its
    /// original position.
    pub fn rename_into(self, destination: PinnedTarget) -> CorulixResult<()> {
        if self.root_identity != destination.root_identity {
            return Err(CorulixError::PathDenied);
        }
        rustix::fs::renameat(
            self.parent_fd.as_fd(),
            self.leaf.as_os_str(),
            destination.parent_fd.as_fd(),
            destination.leaf.as_os_str(),
        )
        .map_err(|_| CorulixError::PathDenied)
    }

    /// M09-P5 `SECURE_RENAME` + immediate verification combo: identical
    /// authority to [`Self::rename_into`] (same cross-workspace-identity
    /// check, same `renameat(source_parent_fd, source_leaf, dest_parent_fd,
    /// dest_leaf)`), but additionally confirms -- via the SAME already-
    /// pinned `(parent_fd, leaf)` pairs `self`/`destination` were already
    /// bound to before the rename, never a re-walk -- that `self`'s own
    /// name is now vacated, then reopens `destination`'s bound name for the
    /// caller to verify/hash the freshly-committed bytes.
    ///
    /// This single primitive covers two P5 commit shapes: `ReplaceFile`/
    /// `ApplyTextEdits` (`self` is the ephemeral stage sibling, which must
    /// vacate on a successful rename onto the real target) and `MoveFile`
    /// (`self` is the real source, which must vacate; `destination` is the
    /// new home whose freshly-written bytes the caller hashes for
    /// `MutationResult::Moved`). Neither post-rename check re-resolves any
    /// pathname: both act on the exact fd/leaf pairs already bound at
    /// construction time, so nothing that happened after PREPARE/STAGE can
    /// redirect them (Section 6 of the P5 mandate).
    pub fn rename_into_verified(self, destination: PinnedTarget) -> CorulixResult<PinnedFile> {
        if self.root_identity != destination.root_identity {
            return Err(CorulixError::PathDenied);
        }
        rustix::fs::renameat(
            self.parent_fd.as_fd(),
            self.leaf.as_os_str(),
            destination.parent_fd.as_fd(),
            destination.leaf.as_os_str(),
        )
        .map_err(|_| CorulixError::PathDenied)?;
        match rustix::fs::statat(
            self.parent_fd.as_fd(),
            self.leaf.as_os_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(err) if err == rustix::io::Errno::NOENT => {}
            _ => return Err(CorulixError::Internal),
        }
        destination.open_raw()
    }

    /// M09-P5 `SECURE_UNLINK` + immediate absence verification: identical
    /// authority to [`Self::unlink`], but confirms -- via the SAME already-
    /// pinned `(parent_fd, leaf)` pair, never a re-walk -- that the entry
    /// is genuinely gone immediately afterward. Used by `DeleteFile`'s
    /// commit+verify step.
    pub fn unlink_verified(self) -> CorulixResult<()> {
        rustix::fs::unlinkat(
            self.parent_fd.as_fd(),
            self.leaf.as_os_str(),
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|_| CorulixError::PathDenied)?;
        match rustix::fs::statat(
            self.parent_fd.as_fd(),
            self.leaf.as_os_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(err) if err == rustix::io::Errno::NOENT => Ok(()),
            _ => Err(CorulixError::Internal),
        }
    }

    /// M09-P5: re-checks, via the SAME already-pinned `(parent_fd, leaf)`
    /// this capability was bound to at construction -- never a re-walk --
    /// whether the entry is still absent. `MoveFile`'s commit-time
    /// destination-absence recheck (Section 14 of the P5 mandate): a
    /// destination PREPARE proved absent may have appeared in the
    /// PREPARE-to-COMMIT window; ordinary `rename` semantics would
    /// otherwise silently replace it, so this must be reconfirmed
    /// immediately before the rename, not trusted from PREPARE alone.
    pub fn still_absent(&self) -> CorulixResult<bool> {
        match rustix::fs::statat(
            self.parent_fd.as_fd(),
            self.leaf.as_os_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => Ok(false),
            Err(err) if err == rustix::io::Errno::NOENT => Ok(true),
            Err(_) => Err(CorulixError::PathDenied),
        }
    }
}

// M09-P4R deterministic concurrent-growth seam: invoked, synchronously, on
// the reader's own thread, immediately after the pre-read size check and
// immediately before the hard-bounded read call begins. A test installs a
// closure here that performs (and fully completes) a same-object append
// before returning, so the ordering "check observed old size, then the file
// grew, then the bounded read actually ran" is produced deterministically
// rather than raced. Compiles to a true no-op call in a release build,
// matching this crate's established `CONSTRUCTION_RACE_HOOK`/`WALK_SWAP_HOOK`
// seam pattern (zero release-build presence).
#[cfg(any(test, feature = "test-support"))]
type ReadBoundTestHook = Box<dyn Fn()>;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static READ_BOUND_TEST_HOOK: std::cell::RefCell<Option<ReadBoundTestHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
fn run_read_bound_test_hook() {
    READ_BOUND_TEST_HOOK.with(|cell| {
        if let Some(hook) = cell.borrow().as_ref() {
            hook();
        }
    });
}

#[cfg(not(any(test, feature = "test-support")))]
#[inline]
fn run_read_bound_test_hook() {}

impl PinnedFile {
    /// Reads the file's full contents, bounded by `max_bytes` -- mirrors
    /// `confined_read`'s existing `FileTooLarge` fail-closed bound (reused,
    /// not reinvented: Section 36 forbids inventing new public reason
    /// codes in P3). Acts on the SAME already-open file object every call;
    /// no path is ever re-resolved.
    ///
    /// M09-P4R hard-bound fix: the earlier P3/P4 implementation checked
    /// `metadata.len()` once and then called an entirely unbounded
    /// `read_to_end` -- a same-object concurrent writer growing the file
    /// between that check and (or during) the read could make the actual
    /// acquisition consume an unbounded number of bytes before the oversize
    /// outcome was ever decided. The metadata pre-check above remains as a
    /// cheap optimization (an already-oversized file need not be read at
    /// all), but the guarantee now comes from the read itself: `(&self.
    /// file).take(max_bytes.saturating_add(1))` hard-caps how many bytes
    /// the underlying reader will ever yield to `read_to_end`, regardless
    /// of how much the file grows underneath it. `saturating_add` avoids a
    /// `u64` overflow at the `u64::MAX` boundary (the pathological caller
    /// who names that exact limit gets a still-well-defined, if extremely
    /// generous, cap rather than a panic or wraparound). The buffer length
    /// is re-checked against the real `max_bytes` afterward, so a file that
    /// grew past the limit during the read still resolves to `FileTooLarge`
    /// rather than a silently truncated success.
    pub fn read_bytes(&self, max_bytes: u64) -> CorulixResult<Vec<u8>> {
        let metadata = self.file.metadata().map_err(|_| CorulixError::Internal)?;
        if metadata.len() > max_bytes {
            return Err(CorulixError::FileTooLarge);
        }
        run_read_bound_test_hook();
        let capped_limit = max_bytes.saturating_add(1);
        let mut buffer = Vec::new();
        (&self.file)
            .take(capped_limit)
            .read_to_end(&mut buffer)
            .map_err(|_| CorulixError::Internal)?;
        if buffer.len() as u64 > max_bytes {
            return Err(CorulixError::FileTooLarge);
        }
        Ok(buffer)
    }

    /// The file's current byte length, from the same already-open object.
    pub fn byte_len(&self) -> CorulixResult<u64> {
        Ok(self
            .file
            .metadata()
            .map_err(|_| CorulixError::Internal)?
            .len())
    }

    /// M09-P4: raw `std::fs::Metadata` for the same already-open object --
    /// crate-internal only. `confine.rs`'s migrated `confined_metadata`/
    /// `confined_read` use this directly (via [`PinnedTarget::open_raw`])
    /// so they can apply their own pre-P4 error-variant contract; public
    /// consumers use [`Self::byte_len`] instead.
    pub(crate) fn metadata(&self) -> CorulixResult<fs::Metadata> {
        self.file.metadata().map_err(|_| CorulixError::Internal)
    }
}

/// M09-P5 Section 3: the safe, additive, cross-crate capability-acquisition
/// API. Every function here takes exactly [`WorkspaceRoot`] plus a
/// workspace-relative [`Path`] -- the same two inputs `resolve_confined`/
/// `confine_target` already accepted pre-M09 -- and performs the full
/// lexical validation, secure component walk, and final-symlink policy
/// internally before ever constructing a capability. There is no overload
/// accepting a raw leaf `OsStr`, a raw fd/handle, or a `WalkResult`: a
/// caller in another crate (`wht_corulix_mutation`) can only ever obtain a
/// capability by naming a workspace-relative path and letting this crate's
/// own walker decide what it resolves to (Architecture Rule F).
/// `PIN_PARENT_ONLY` resolution mode, exposed across the crate boundary
/// (Section 3/16 of the P5 mandate): resolves `relative`'s parent
/// directory chain only, discarding the final component's own name --
/// used by `MutationExecutor`'s STAGE phase to create an internally-named
/// temporary sibling.
pub fn resolve_parent(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<PinnedParent> {
    PinnedParent::resolve(root, relative)
}

/// `EXISTING_TARGET_FOLLOW_SAFE_FINAL_SYMLINK` resolution mode, exposed
/// across the crate boundary -- see `PinnedTarget::resolve_existing`.
pub fn resolve_existing_target(
    root: &WorkspaceRoot,
    relative: &Path,
) -> CorulixResult<PinnedTarget> {
    PinnedTarget::resolve_existing(root, relative)
}

/// `NEW_TARGET_REQUIRE_ABSENT_FINAL_ENTRY` resolution mode, exposed across
/// the crate boundary -- see `PinnedTarget::resolve_new`.
pub fn resolve_new_target(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<PinnedTarget> {
    PinnedTarget::resolve_new(root, relative)
}

/// Checks whether ANY entry (file, directory, or symlink -- dangling or
/// not, never followed) exists at `leaf` relative to `dirfd`, without
/// performing any I/O against whatever it might point to. Used only by
/// `NEW_TARGET_REQUIRE_ABSENT_FINAL_ENTRY` collision detection. Fails
/// closed (denies) on any error other than "genuinely absent" (`ENOENT`)
/// -- e.g. a permission error is never silently treated as "absent".
fn entry_exists_no_follow(
    dirfd: rustix::fd::BorrowedFd<'_>,
    leaf: &std::ffi::OsStr,
) -> CorulixResult<bool> {
    match rustix::fs::statat(dirfd, leaf, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(err) if err == rustix::io::Errno::NOENT => Ok(false),
        Err(_) => Err(CorulixError::PathDenied),
    }
}

/// The single, shared `O_CREAT | O_EXCL` primitive both the STAGE
/// primitive and `PinnedTarget::create_exclusive` use -- atomicity comes
/// from `O_EXCL` itself (a kernel-level guarantee), never from a
/// preceding existence check. `O_NOFOLLOW` additionally ensures a
/// dangling symlink placed at the leaf name is never silently created
/// "through" -- `O_EXCL` alone already refuses if ANY entry (symlink
/// included) occupies that name, but `O_NOFOLLOW` is kept as explicit,
/// defense-in-depth documentation of that intent.
fn create_exclusive_at(
    parent: rustix::fd::BorrowedFd<'_>,
    leaf: &std::ffi::OsStr,
    content: &[u8],
) -> CorulixResult<fs::File> {
    let owned = rustix::fs::openat(
        parent,
        leaf,
        rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|err| {
        if err == rustix::io::Errno::EXIST {
            CorulixError::PathDenied
        } else {
            CorulixError::Internal
        }
    })?;
    let mut file = fs::File::from(owned);
    file.write_all(content)
        .map_err(|_| CorulixError::Internal)?;
    file.sync_all().map_err(|_| CorulixError::Internal)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root =
            std::env::temp_dir().join(format!("corulix-p3-{label}-{}-{stamp}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        root
    }

    fn open_root(path: &Path) -> CorulixResult<WorkspaceRoot> {
        WorkspaceRoot::open(path)
    }

    // -- construction is authority-only, no arbitrary-leaf injection ----

    #[test]
    fn opaque_construction_only_through_authority() -> CorulixResult<()> {
        let root_path = temp_dir("construct");
        fs::write(root_path.join("file.rs"), b"hello").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        // The only way to obtain any capability is via a workspace-relative
        // path through the resolver -- there is no public constructor
        // taking a raw fd/handle or an arbitrary leaf string at all; this
        // test's very existence (compiling only via these crate-internal
        // paths) is the proof.
        let target = PinnedTarget::resolve_existing(&root, Path::new("file.rs"))?;
        let bytes = target.open_file()?.read_bytes(4096)?;
        assert_eq!(bytes, b"hello");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn arbitrary_leaf_injection_is_rejected() -> CorulixResult<()> {
        let root_path = temp_dir("leaf-injection");
        fs::create_dir_all(root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("leaf-injection-outside");
        fs::write(outside.join("secret.rs"), b"OUTSIDE").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        // Attempting to smuggle a traversal string as if it were a "leaf"
        // is rejected at the same Step 1/2 syntactic validation every
        // other M09 entry point already applies -- there is no
        // capability-level API that would even accept such a string as a
        // leaf in the first place (PinnedTarget's `leaf` field is private
        // and only ever set by the resolver).
        let outside_name = outside
            .file_name()
            .ok_or(CorulixError::Internal)?
            .to_string_lossy()
            .into_owned();
        let escape = format!("a/../../{outside_name}/secret.rs");
        let result = PinnedTarget::resolve_existing(&root, Path::new(&escape));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    // -- final-symlink matrix (Section 28) -------------------------------

    #[test]
    fn existing_target_normal_regular_file() -> CorulixResult<()> {
        let root_path = temp_dir("final-normal");
        fs::write(root_path.join("real.rs"), b"content").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("real.rs"))?;
        assert_eq!(target.open_file()?.read_bytes(4096)?, b"content");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn existing_target_relative_final_symlink_to_internal_file() -> CorulixResult<()> {
        let root_path = temp_dir("final-rel-internal");
        fs::write(root_path.join("real.rs"), b"content").map_err(|_| CorulixError::Internal)?;
        symlink("real.rs", root_path.join("link.rs")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("link.rs"))?;
        assert_eq!(target.open_file()?.read_bytes(4096)?, b"content");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn existing_target_absolute_final_symlink_to_internal_file() -> CorulixResult<()> {
        let root_path = temp_dir("final-abs-internal");
        fs::write(root_path.join("real.rs"), b"content").map_err(|_| CorulixError::Internal)?;
        let canonical = fs::canonicalize(&root_path).map_err(|_| CorulixError::Internal)?;
        symlink(canonical.join("real.rs"), root_path.join("link.rs"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("link.rs"))?;
        assert_eq!(target.open_file()?.read_bytes(4096)?, b"content");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn existing_target_chain_ending_in_internal_file() -> CorulixResult<()> {
        let root_path = temp_dir("final-chain");
        fs::write(root_path.join("real.rs"), b"content").map_err(|_| CorulixError::Internal)?;
        symlink("real.rs", root_path.join("b.rs")).map_err(|_| CorulixError::Internal)?;
        symlink("b.rs", root_path.join("a.rs")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("a.rs"))?;
        assert_eq!(target.open_file()?.read_bytes(4096)?, b"content");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn existing_target_final_symlink_to_outside_is_denied() -> CorulixResult<()> {
        let root_path = temp_dir("final-outside");
        let outside = temp_dir("final-outside-target");
        fs::write(outside.join("secret.rs"), b"SECRET").map_err(|_| CorulixError::Internal)?;
        symlink(outside.join("secret.rs"), root_path.join("link.rs"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = PinnedTarget::resolve_existing(&root, Path::new("link.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn existing_target_dangling_final_symlink_fails_as_missing() -> CorulixResult<()> {
        let root_path = temp_dir("final-dangling");
        symlink("does-not-exist.rs", root_path.join("link.rs"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        // The symlink lexically stays inside the workspace (its target
        // name never leaves), so resolution itself succeeds (matching the
        // existing contract: this is not an escape attempt); the missing
        // real file is then the *operation's* concern, exactly like the
        // pre-M09 `confine_existing`/`TargetNotFound` split. `open_file`
        // fails because the entry does not exist to open.
        let target = PinnedTarget::resolve_existing(&root, Path::new("link.rs"))?;
        let result = target.open_file();
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn existing_target_final_symlink_cycle_is_bounded() -> CorulixResult<()> {
        let root_path = temp_dir("final-cycle");
        symlink("b.rs", root_path.join("a.rs")).map_err(|_| CorulixError::Internal)?;
        symlink("a.rs", root_path.join("b.rs")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = PinnedTarget::resolve_existing(&root, Path::new("a.rs"));
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    // -- new-target collision matrix (Section 29) ------------------------

    #[test]
    fn new_target_absent_may_be_created() -> CorulixResult<()> {
        let root_path = temp_dir("new-absent");
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_new(&root, Path::new("new.rs"))?;
        target.create_exclusive(b"created")?;
        assert_eq!(
            fs::read(root_path.join("new.rs")).map_err(|_| CorulixError::Internal)?,
            b"created"
        );

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn new_target_existing_regular_file_collides() -> CorulixResult<()> {
        let root_path = temp_dir("new-file-collision");
        fs::write(root_path.join("exists.rs"), b"old").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        assert!(matches!(
            PinnedTarget::resolve_new(&root, Path::new("exists.rs")),
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn new_target_existing_directory_collides() -> CorulixResult<()> {
        let root_path = temp_dir("new-dir-collision");
        fs::create_dir_all(root_path.join("existing_dir")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        assert!(matches!(
            PinnedTarget::resolve_new(&root, Path::new("existing_dir")),
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn new_target_existing_internal_symlink_collides() -> CorulixResult<()> {
        let root_path = temp_dir("new-symlink-collision");
        fs::write(root_path.join("real.rs"), b"x").map_err(|_| CorulixError::Internal)?;
        symlink("real.rs", root_path.join("link.rs")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        assert!(matches!(
            PinnedTarget::resolve_new(&root, Path::new("link.rs")),
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn new_target_existing_outside_symlink_collides() -> CorulixResult<()> {
        let root_path = temp_dir("new-outside-symlink-collision");
        let outside = temp_dir("new-outside-symlink-collision-target");
        symlink(&outside, root_path.join("link.rs")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        assert!(matches!(
            PinnedTarget::resolve_new(&root, Path::new("link.rs")),
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn new_target_dangling_symlink_collides() -> CorulixResult<()> {
        let root_path = temp_dir("new-dangling-collision");
        symlink("does-not-exist.rs", root_path.join("link.rs"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        assert!(matches!(
            PinnedTarget::resolve_new(&root, Path::new("link.rs")),
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    // -- path/parent/root swap after capability creation (Sections 30-32) --

    #[test]
    fn read_survives_parent_swap_after_capability_creation() -> CorulixResult<()> {
        let root_path = temp_dir("swap-read");
        fs::create_dir_all(root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("a/file.rs"), b"original").map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("swap-read-outside");
        fs::create_dir_all(outside.join("_unused")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("a/file.rs"))?;

        let a_path = root_path.join("a");
        let a_moved = temp_dir("swap-read-moved");
        fs::rename(&a_path, &a_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &a_path).map_err(|_| CorulixError::Internal)?;

        let bytes = target.open_file()?.read_bytes(4096)?;
        assert_eq!(
            bytes, b"original",
            "must still read the originally-pinned object"
        );

        let _ = fs::remove_file(&a_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn create_survives_parent_swap_after_capability_creation() -> CorulixResult<()> {
        let root_path = temp_dir("swap-create");
        fs::create_dir_all(root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("swap-create-outside");
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_new(&root, Path::new("a/new.rs"))?;

        let a_path = root_path.join("a");
        let a_moved = temp_dir("swap-create-moved");
        fs::rename(&a_path, &a_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &a_path).map_err(|_| CorulixError::Internal)?;

        target.create_exclusive(b"payload")?;

        assert!(
            !outside.join("new.rs").exists(),
            "outside must never receive the write"
        );
        assert_eq!(
            fs::read(a_moved.join("new.rs")).map_err(|_| CorulixError::Internal)?,
            b"payload"
        );

        let _ = fs::remove_file(&a_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn unlink_survives_parent_swap_after_capability_creation() -> CorulixResult<()> {
        let root_path = temp_dir("swap-unlink");
        fs::create_dir_all(root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("a/gone.rs"), b"x").map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("swap-unlink-outside");
        fs::write(outside.join("gone.rs"), b"OUTSIDE").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("a/gone.rs"))?;

        let a_path = root_path.join("a");
        let a_moved = temp_dir("swap-unlink-moved");
        fs::rename(&a_path, &a_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &a_path).map_err(|_| CorulixError::Internal)?;

        target.unlink()?;

        assert!(
            outside.join("gone.rs").exists(),
            "the outside file must never be touched"
        );
        assert!(
            !a_moved.join("gone.rs").exists(),
            "the real, pinned file must be gone"
        );

        let _ = fs::remove_file(&a_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn rename_survives_source_parent_swap() -> CorulixResult<()> {
        let root_path = temp_dir("swap-rename-src");
        fs::create_dir_all(root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("a/from.rs"), b"payload").map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("swap-rename-src-outside");
        let root = open_root(&root_path)?;

        let source = PinnedTarget::resolve_existing(&root, Path::new("a/from.rs"))?;
        let destination = PinnedTarget::resolve_new(&root, Path::new("to.rs"))?;

        let a_path = root_path.join("a");
        let a_moved = temp_dir("swap-rename-src-moved");
        fs::rename(&a_path, &a_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &a_path).map_err(|_| CorulixError::Internal)?;

        source.rename_into(destination)?;

        assert_eq!(
            fs::read(root_path.join("to.rs")).map_err(|_| CorulixError::Internal)?,
            b"payload"
        );
        assert!(!outside.join("from.rs").exists());

        let _ = fs::remove_file(&a_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn rename_survives_destination_parent_swap() -> CorulixResult<()> {
        let root_path = temp_dir("swap-rename-dst");
        fs::create_dir_all(root_path.join("b")).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("from.rs"), b"payload").map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("swap-rename-dst-outside");
        let root = open_root(&root_path)?;

        let source = PinnedTarget::resolve_existing(&root, Path::new("from.rs"))?;
        let destination = PinnedTarget::resolve_new(&root, Path::new("b/to.rs"))?;

        let b_path = root_path.join("b");
        let b_moved = temp_dir("swap-rename-dst-moved");
        fs::rename(&b_path, &b_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &b_path).map_err(|_| CorulixError::Internal)?;

        source.rename_into(destination)?;

        assert_eq!(
            fs::read(b_moved.join("to.rs")).map_err(|_| CorulixError::Internal)?,
            b"payload"
        );
        assert!(!outside.join("to.rs").exists());

        let _ = fs::remove_file(&b_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&b_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn capability_survives_root_replacement() -> CorulixResult<()> {
        let root_path = temp_dir("swap-root");
        fs::write(root_path.join("file.rs"), b"payload").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("file.rs"))?;

        let root_moved = temp_dir("swap-root-moved");
        fs::rename(&root_path, &root_moved).map_err(|_| CorulixError::Internal)?;
        fs::create_dir_all(&root_path).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("file.rs"), b"IMPOSTOR").map_err(|_| CorulixError::Internal)?;

        let bytes = target.open_file()?.read_bytes(4096)?;
        assert_eq!(
            bytes, b"payload",
            "must read the ORIGINAL object, never the replacement"
        );

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&root_moved);
        Ok(())
    }

    #[test]
    fn capability_survives_nested_ancestor_replacement() -> CorulixResult<()> {
        let root_path = temp_dir("swap-nested");
        fs::create_dir_all(root_path.join("a/b")).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("a/b/file.rs"), b"payload").map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("swap-nested-outside");
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("a/b/file.rs"))?;

        let a_path = root_path.join("a");
        let a_moved = temp_dir("swap-nested-moved");
        fs::rename(&a_path, &a_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &a_path).map_err(|_| CorulixError::Internal)?;

        let bytes = target.open_file()?.read_bytes(4096)?;
        assert_eq!(bytes, b"payload");

        let _ = fs::remove_file(&a_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    // -- source/destination authority independence (Section 33) ---------

    #[test]
    fn rename_source_and_destination_authorities_are_independent() -> CorulixResult<()> {
        let root_path = temp_dir("independent-rename");
        fs::create_dir_all(root_path.join("src_dir")).map_err(|_| CorulixError::Internal)?;
        fs::create_dir_all(root_path.join("dst_dir")).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("src_dir/from.rs"), b"payload")
            .map_err(|_| CorulixError::Internal)?;
        let src_outside = temp_dir("independent-rename-src-outside");
        let dst_outside = temp_dir("independent-rename-dst-outside");
        let root = open_root(&root_path)?;

        let source = PinnedTarget::resolve_existing(&root, Path::new("src_dir/from.rs"))?;
        let destination = PinnedTarget::resolve_new(&root, Path::new("dst_dir/to.rs"))?;

        let src_dir_path = root_path.join("src_dir");
        let src_moved = temp_dir("independent-rename-src-moved");
        fs::rename(&src_dir_path, &src_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&src_outside, &src_dir_path).map_err(|_| CorulixError::Internal)?;

        let dst_dir_path = root_path.join("dst_dir");
        let dst_moved = temp_dir("independent-rename-dst-moved");
        fs::rename(&dst_dir_path, &dst_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&dst_outside, &dst_dir_path).map_err(|_| CorulixError::Internal)?;

        source.rename_into(destination)?;

        assert_eq!(
            fs::read(dst_moved.join("to.rs")).map_err(|_| CorulixError::Internal)?,
            b"payload"
        );
        assert!(!src_outside.join("from.rs").exists());
        assert!(!dst_outside.join("to.rs").exists());

        let _ = fs::remove_file(&src_dir_path);
        let _ = fs::remove_file(&dst_dir_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&src_moved);
        let _ = fs::remove_dir_all(&dst_moved);
        let _ = fs::remove_dir_all(&src_outside);
        let _ = fs::remove_dir_all(&dst_outside);
        Ok(())
    }

    // -- cross-workspace denial (Section 34) -----------------------------

    #[test]
    fn cross_workspace_rename_is_denied() -> CorulixResult<()> {
        let root_a_path = temp_dir("cross-ws-a");
        let root_b_path = temp_dir("cross-ws-b");
        fs::write(root_a_path.join("from.rs"), b"payload").map_err(|_| CorulixError::Internal)?;
        let root_a = open_root(&root_a_path)?;
        let root_b = open_root(&root_b_path)?;

        // `root_a`/`root_b` are two independently-opened, genuinely
        // distinct filesystem objects (separate `temp_dir()` calls) --
        // their differing identity is a given, not something this test
        // needs to re-assert via an internal accessor. The security
        // property under test is entirely OBSERVABLE: `rename_into`'s own
        // internal identity comparison must deny the cross-workspace
        // rename and leave both sides untouched (M09-P8R: the
        // `PinnedTarget`/`PinnedParent`/`PinnedFile::root_identity()`
        // accessors this test previously called were removed as unused
        // dead code with no production consumer -- see that removal's own
        // changelog entry -- and this test now proves the same guarantee
        // purely through `rename_into`'s observable outcome below).
        let source = PinnedTarget::resolve_existing(&root_a, Path::new("from.rs"))?;
        let destination = PinnedTarget::resolve_new(&root_b, Path::new("to.rs"))?;

        let result = source.rename_into(destination);
        assert!(matches!(result, Err(CorulixError::PathDenied)));
        assert!(
            root_a_path.join("from.rs").exists(),
            "a denied cross-workspace rename must not have touched the source"
        );
        assert!(!root_b_path.join("to.rs").exists());

        let _ = fs::remove_dir_all(&root_a_path);
        let _ = fs::remove_dir_all(&root_b_path);
        Ok(())
    }

    // -- resource lifetime / fd leak (Sections 24-25) --------------------

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|entries| entries.filter_map(Result::ok).count())
            .unwrap_or(0)
    }

    #[test]
    fn fd_leak_test() -> CorulixResult<()> {
        let root_path = temp_dir("fd-leak");
        let root = open_root(&root_path)?;
        let baseline = open_fd_count();

        for index in 0..200 {
            let parent = PinnedParent::resolve(&root, Path::new("probe.rs"))?;
            let (target, file) = parent.create_exclusive_temp_sibling(b"x")?;
            let _ = file.byte_len()?;
            target.unlink()?;
            let _ = index;
        }

        let after = open_fd_count();
        assert!(
            after <= baseline + 4,
            "fd count grew from {baseline} to {after} after 200 create/drop cycles -- possible leak"
        );

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    // -- M09-P4R: hard-bounded read (Sections 7-9, 23) -------------------

    #[test]
    fn read_bytes_static_boundary_under_max_succeeds() -> CorulixResult<()> {
        let root_path = temp_dir("p4r-boundary-under");
        fs::write(root_path.join("f.rs"), b"12345").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("f.rs"))?;
        let bytes = target.open_file()?.read_bytes(10)?;
        assert_eq!(bytes, b"12345");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn read_bytes_static_boundary_exactly_at_max_succeeds() -> CorulixResult<()> {
        let root_path = temp_dir("p4r-boundary-exact");
        fs::write(root_path.join("f.rs"), b"1234567890").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("f.rs"))?;
        let bytes = target.open_file()?.read_bytes(10)?;
        assert_eq!(bytes.len(), 10);
        assert_eq!(bytes, b"1234567890");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn read_bytes_static_boundary_over_max_is_file_too_large() -> CorulixResult<()> {
        let root_path = temp_dir("p4r-boundary-over");
        fs::write(root_path.join("f.rs"), b"12345678901").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("f.rs"))?;
        let result = target.open_file()?.read_bytes(10);
        assert!(matches!(result, Err(CorulixError::FileTooLarge)));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn read_bytes_zero_length_file_succeeds_empty() -> CorulixResult<()> {
        let root_path = temp_dir("p4r-zero-length");
        fs::write(root_path.join("empty.rs"), b"").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("empty.rs"))?;
        let bytes = target.open_file()?.read_bytes(10)?;
        assert!(bytes.is_empty());

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[test]
    fn read_bytes_max_bytes_zero_boundary() -> CorulixResult<()> {
        let root_path = temp_dir("p4r-max-zero");
        fs::write(root_path.join("empty.rs"), b"").map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("nonempty.rs"), b"x").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let empty_target = PinnedTarget::resolve_existing(&root, Path::new("empty.rs"))?;
        let bytes = empty_target.open_file()?.read_bytes(0)?;
        assert!(bytes.is_empty());

        let nonempty_target = PinnedTarget::resolve_existing(&root, Path::new("nonempty.rs"))?;
        let result = nonempty_target.open_file()?.read_bytes(0);
        assert!(matches!(result, Err(CorulixError::FileTooLarge)));

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    /// Deterministic proof (P4R mandate Section 8): a same-object writer
    /// completes an append -- via the hook, synchronously, on the reader's
    /// own thread -- strictly after the pre-read size check and strictly
    /// before the hard-bounded read call begins. The bounded read must
    /// never turn this into an oversized success.
    #[test]
    fn read_bytes_concurrent_same_object_growth_never_returns_oversized_success()
    -> CorulixResult<()> {
        let root_path = temp_dir("p4r-concurrent-growth");
        let file_path = root_path.join("growing.rs");
        fs::write(&file_path, vec![b'a'; 8]).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("growing.rs"))?;
        let pinned = target.open_file()?;

        let max_bytes: u64 = 16;
        let append_path = file_path.clone();
        READ_BOUND_TEST_HOOK.with(|cell| {
            *cell.borrow_mut() = Some(Box::new(move || {
                if let Ok(mut appender) = fs::OpenOptions::new().append(true).open(&append_path) {
                    let _ = appender.write_all(&[b'b'; 64]);
                    let _ = appender.sync_all();
                }
            }));
        });

        let result = pinned.read_bytes(max_bytes);
        READ_BOUND_TEST_HOOK.with(|cell| *cell.borrow_mut() = None);

        match result {
            Err(CorulixError::FileTooLarge) => {}
            Ok(bytes) => assert!(
                bytes.len() as u64 <= max_bytes,
                "a successful read must never exceed max_bytes; got {} bytes",
                bytes.len()
            ),
            Err(other) => return Err(other),
        }

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    /// Bounded continuous appender (Section 9): a real background writer
    /// thread appends repeatedly (bounded iteration count, no infinite
    /// loop) while the read runs. The read must terminate promptly -- it
    /// cannot need the writer to stop first -- and must never return more
    /// than `max_bytes` on success.
    #[test]
    fn read_bytes_continuous_appender_terminates_within_bound() -> CorulixResult<()> {
        let root_path = temp_dir("p4r-continuous-appender");
        let file_path = root_path.join("continuous.rs");
        fs::write(&file_path, vec![b'a'; 4]).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("continuous.rs"))?;
        let pinned = target.open_file()?;

        let max_bytes: u64 = 32;
        let writer_path = file_path.clone();
        let writer = std::thread::spawn(move || {
            for _ in 0..100 {
                if let Ok(mut appender) = fs::OpenOptions::new().append(true).open(&writer_path) {
                    let _ = appender.write_all(b"x");
                }
                std::thread::yield_now();
            }
        });

        let result = pinned.read_bytes(max_bytes);
        let _ = writer.join();

        match result {
            Ok(bytes) => assert!(bytes.len() as u64 <= max_bytes),
            Err(CorulixError::FileTooLarge) | Err(CorulixError::Internal) => {}
            Err(other) => return Err(other),
        }

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    /// Same-object authority regression (Section 10): the bounded read
    /// still acts on the SAME pinned file object after a parent-directory
    /// swap -- no pathname is ever re-resolved to read it.
    #[test]
    fn read_bytes_bounded_read_survives_parent_swap_same_object() -> CorulixResult<()> {
        let root_path = temp_dir("p4r-same-object-swap");
        fs::create_dir_all(root_path.join("a")).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("a/file.rs"), b"original").map_err(|_| CorulixError::Internal)?;
        let outside = temp_dir("p4r-same-object-swap-outside");
        let root = open_root(&root_path)?;

        let target = PinnedTarget::resolve_existing(&root, Path::new("a/file.rs"))?;
        let pinned = target.open_file()?;

        let a_path = root_path.join("a");
        let a_moved = temp_dir("p4r-same-object-swap-moved");
        fs::rename(&a_path, &a_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &a_path).map_err(|_| CorulixError::Internal)?;

        let bytes = pinned.read_bytes(4096)?;
        assert_eq!(bytes, b"original");

        let _ = fs::remove_file(&a_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[test]
    fn stage_primitive_security_independent_of_filename_secrecy() -> CorulixResult<()> {
        let root_path = temp_dir("stage-secrecy");
        let root = open_root(&root_path)?;

        let parent = PinnedParent::resolve(&root, Path::new("target.rs"))?;
        let (target, _file) = parent.create_exclusive_temp_sibling(b"staged")?;

        // Even though the test can trivially discover the exact temp leaf
        // name (it's right there on disk), that knowledge grants no
        // additional capability: the ONLY way to act on it is through the
        // `PinnedTarget` value already returned, which is bound to the
        // pinned parent fd, not to the name itself.
        let entries: Vec<_> = fs::read_dir(&root_path)
            .map_err(|_| CorulixError::Internal)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .collect();
        assert!(
            entries
                .iter()
                .any(|name| name.to_string_lossy().starts_with(".corulix-stage-"))
        );

        target.unlink()?;

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }
}
