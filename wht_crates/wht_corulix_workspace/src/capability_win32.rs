// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09-P9: opaque, cross-crate-safe Windows filesystem capabilities --
//! the Windows mirror of `capability.rs`'s Unix `PinnedParent`/
//! `PinnedTarget`/`PinnedFile`, built on genuine NT/Win32 handle-relative
//! primitives (`wht_corulix_process_win32::open_relative`/
//! `rename_relative`/`delete_relative`) rather than `openat`/`renameat`/
//! `unlinkat`.
//!
//! Public API SHAPE is identical to the Unix module (same three types,
//! same three free functions, same method names) -- callers in
//! `wht_corulix_mutation` do not need to know which platform module they
//! are actually linked against; only `confine.rs`'s own `#[cfg(unix)]`/
//! `#[cfg(windows)]` split (and this crate's `lib.rs` module wiring)
//! decides that. No `HANDLE`/`FileHandle` is ever part of this module's own
//! public surface (mirrors the Unix module's "no `RawFd`/`OwnedFd`" rule).
//!
//! Windows reparse-point policy (`M09_P9_WINDOWS_REPARSE_PLATFORM_DELTA`):
//! every relative open in this module fails closed on ANY reparse point
//! (symlink, junction, mount point) -- for both ancestor and terminal
//! components, with no bounded-follow exception. This is enforced
//! entirely inside `wht_corulix_process_win32::open_relative`, so nothing
//! in this module needs its own reparse-tag inspection; see that
//! function's own doc and the P9 final report for the full disclosure of
//! how this differs from Unix's bounded internal-symlink-following
//! contract and from this crate's own pre-P9 Windows behavior
//! (`std::fs::canonicalize`, which transparently followed reparse points).

use std::ffi::OsString;
use std::path::{Component, Path};
use std::sync::Arc;

use wht_corulix_core::{CorulixError, CorulixResult};
use wht_corulix_process_win32::{FileHandle, RelativeOpenKind};

use crate::confine::{WorkspaceRoot, WorkspaceRootIdentity};

/// NT status codes this module treats as "the entry does not exist" when
/// probing for absence -- every other failure status is a real error, not
/// silently treated as absence.
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;

/// One exact, already-authorized directory object. A later rename of its
/// own pathname, or of any ancestor's pathname, cannot redirect it --
/// nothing here ever re-resolves a pathname to reach it again; every
/// operation acts on the pinned handle directly.
pub struct PinnedParent {
    handle: Arc<FileHandle>,
    root_identity: WorkspaceRootIdentity,
}

/// One exact, already-authorized parent directory handle PLUS one
/// validated, unforgeable leaf component. The ONLY way to obtain one is
/// through [`PinnedTarget::resolve_existing`]/[`PinnedTarget::resolve_new`]
/// (crate-internal) -- there is no public constructor taking an arbitrary
/// leaf string.
pub struct PinnedTarget {
    parent_handle: Arc<FileHandle>,
    leaf: OsString,
    root_identity: WorkspaceRootIdentity,
}

/// One exact, already-opened regular-file object. Binds the file the
/// moment it is opened; a later pathname replacement cannot redirect
/// subsequent reads, because they act on the already-open file object,
/// never on a re-resolved path.
pub struct PinnedFile {
    file: std::fs::File,
}

/// Validates `relative` exactly like the Unix walker's own Step 1/2
/// (`secure_walk.rs`): rejects empty/absolute paths and any `ParentDir`/
/// `RootDir`/`Prefix` component before any I/O is attempted.
/// `M09_P9_CALLER_PATH_CONTRACT_DELTA=NONE`.
fn validate_relative(relative: &Path) -> CorulixResult<()> {
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
    Ok(())
}

/// The P9 secure component walk: resolves `relative`'s PARENT directory
/// chain from `root`'s pinned handle -- via a genuine handle-relative
/// `NtCreateFile` hop per component (never a joined/concatenated pathname)
/// -- and returns the final ancestor handle plus the validated (but never
/// itself opened) leaf name. Any reparse point encountered on any hop
/// fails the whole walk closed (propagated from
/// `wht_corulix_process_win32::open_relative`).
fn walk_ancestors(
    root: &WorkspaceRoot,
    relative: &Path,
) -> CorulixResult<(Arc<FileHandle>, OsString)> {
    validate_relative(relative)?;
    let leaf = relative
        .file_name()
        .ok_or(CorulixError::PathDenied)?
        .to_os_string();
    let parent_relative = relative
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());

    let mut current: Arc<FileHandle> = root.root_handle_arc();
    if let Some(parent_relative) = parent_relative {
        for component in parent_relative.components() {
            let name = match component {
                Component::Normal(name) => name,
                Component::CurDir => continue,
                // Already rejected by `validate_relative` above.
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(CorulixError::PathDenied);
                }
            };
            let opened = wht_corulix_process_win32::open_relative(
                &current,
                name,
                RelativeOpenKind::ExistingDirectory,
            )
            .map_err(|_| CorulixError::PathDenied)?;
            current = Arc::new(opened);
        }
    }
    Ok((current, leaf))
}

/// Whether `leaf` exists inside `parent`, without following/caring about
/// its type -- used only by [`PinnedTarget::resolve_new`]'s absence check
/// (mirrors Unix's `entry_exists_no_follow`). A reparse point or a
/// directory both count as "exists" (both correctly block a subsequent
/// exclusive create); only a genuine NT "not found" status counts as
/// absent. Any other failure is a real error, never silently treated as
/// absence.
fn entry_exists(parent: &FileHandle, leaf: &std::ffi::OsStr) -> CorulixResult<bool> {
    match wht_corulix_process_win32::open_relative(parent, leaf, RelativeOpenKind::ExistingFile) {
        Ok(_handle) => Ok(true),
        Err(wht_corulix_process_win32::FsAuthorityError::ReparsePointDenied)
        | Err(wht_corulix_process_win32::FsAuthorityError::UnexpectedEntryType) => Ok(true),
        Err(wht_corulix_process_win32::FsAuthorityError::OpenRelativeFailed { status })
            if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND =>
        {
            Ok(false)
        }
        Err(_) => Err(CorulixError::PathDenied),
    }
}

impl PinnedParent {
    /// `PIN_PARENT_ONLY` resolution mode: resolves `relative`'s parent
    /// directory chain and returns a capability bound to it, discarding
    /// whatever the final component's own name was.
    pub(crate) fn resolve(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<Self> {
        let (handle, _leaf) = walk_ancestors(root, relative)?;
        Ok(Self {
            handle,
            root_identity: root.identity(),
        })
    }

    /// `SECURE_STAGE` primitive: creates an unpredictable, INTERNALLY
    /// generated leaf name, exclusively, inside this pinned directory, and
    /// writes `content` to it. Mirrors the Unix implementation's own
    /// `.corulix-stage-{pid}-{attempt}-{nanos}` naming convention and
    /// retry-on-collision loop exactly.
    pub fn create_exclusive_temp_sibling(
        &self,
        content: &[u8],
    ) -> CorulixResult<(PinnedTarget, PinnedFile)> {
        use std::time::{SystemTime, UNIX_EPOCH};
        for attempt in 0u32..8 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default();
            let leaf = OsString::from(format!(
                ".corulix-stage-{}-{attempt}-{nanos}",
                std::process::id()
            ));
            match wht_corulix_process_win32::open_relative(
                &self.handle,
                &leaf,
                RelativeOpenKind::NewFile,
            ) {
                Ok(handle) => {
                    let mut file = handle.into_file();
                    use std::io::Write;
                    file.write_all(content)
                        .map_err(|_| CorulixError::Internal)?;
                    file.sync_all().map_err(|_| CorulixError::Internal)?;
                    let target = PinnedTarget {
                        parent_handle: Arc::clone(&self.handle),
                        leaf,
                        root_identity: self.root_identity,
                    };
                    return Ok((target, PinnedFile { file }));
                }
                Err(wht_corulix_process_win32::FsAuthorityError::OpenRelativeFailed { .. }) => {
                    continue;
                }
                Err(_) => return Err(CorulixError::PathDenied),
            }
        }
        Err(CorulixError::Internal)
    }
}

impl PinnedTarget {
    /// `EXISTING_TARGET` resolution mode: pins the parent directory chain;
    /// the leaf itself is opened later (by [`Self::open_raw`]/
    /// [`Self::open_file`]), where a reparse-point leaf fails closed
    /// exactly like an ancestor reparse point would.
    pub(crate) fn resolve_existing(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<Self> {
        let (handle, leaf) = walk_ancestors(root, relative)?;
        Ok(Self {
            parent_handle: handle,
            leaf,
            root_identity: root.identity(),
        })
    }

    /// `NEW_TARGET_REQUIRE_ABSENT_FINAL_ENTRY` resolution mode: the final
    /// component must be entirely absent -- a regular file, directory, or
    /// reparse point all count as a collision.
    pub(crate) fn resolve_new(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<Self> {
        let (handle, leaf) = walk_ancestors(root, relative)?;
        if entry_exists(&handle, &leaf)? {
            return Err(CorulixError::PathDenied);
        }
        Ok(Self {
            parent_handle: handle,
            leaf,
            root_identity: root.identity(),
        })
    }

    /// M09-P9: opens the bound entry WITHOUT enforcing any particular
    /// entry type -- crate-internal only; [`Self::open_file`] is the safe,
    /// type-checked public primitive built on top of this one.
    pub(crate) fn open_raw(&self) -> CorulixResult<PinnedFile> {
        let handle = wht_corulix_process_win32::open_relative(
            &self.parent_handle,
            &self.leaf,
            RelativeOpenKind::ExistingFile,
        )
        .map_err(|_| CorulixError::PathDenied)?;
        Ok(PinnedFile {
            file: handle.into_file(),
        })
    }

    /// Opens the bound entry for reading. Requires it be a regular file --
    /// `RelativeOpenKind::ExistingFile` already rejects a directory
    /// (`UnexpectedEntryType`) and any reparse point
    /// (`ReparsePointDenied`) at the FFI layer, so this is defense-in-depth
    /// only, mirroring the Unix implementation's own belt-and-braces
    /// metadata re-check.
    pub fn open_file(&self) -> CorulixResult<PinnedFile> {
        let pinned = self.open_raw()?;
        let metadata = pinned.metadata().map_err(|_| CorulixError::Internal)?;
        if !metadata.is_file() {
            return Err(CorulixError::PathDenied);
        }
        Ok(pinned)
    }

    /// `SECURE_CREATE` primitive: atomic create-if-absent (`FILE_CREATE`
    /// disposition), relative to the bound parent handle and the bound
    /// leaf -- no pathname re-resolution, no join, ever.
    pub fn create_exclusive(&self, content: &[u8]) -> CorulixResult<PinnedFile> {
        let handle = wht_corulix_process_win32::open_relative(
            &self.parent_handle,
            &self.leaf,
            RelativeOpenKind::NewFile,
        )
        .map_err(|_| CorulixError::PathDenied)?;
        let mut file = handle.into_file();
        use std::io::Write;
        file.write_all(content)
            .map_err(|_| CorulixError::Internal)?;
        file.sync_all().map_err(|_| CorulixError::Internal)?;
        Ok(PinnedFile { file })
    }

    /// `SECURE_UNLINK` primitive: removes the bound entry via a
    /// handle-based delete (`delete_relative`) -- authorized parent handle
    /// plus bound leaf only, never a raw full pathname, never
    /// `std::fs::remove_file`. Consumes `self`.
    pub fn unlink(self) -> CorulixResult<()> {
        let handle = wht_corulix_process_win32::open_relative(
            &self.parent_handle,
            &self.leaf,
            RelativeOpenKind::ExistingFile,
        )
        .map_err(|_| CorulixError::PathDenied)?;
        wht_corulix_process_win32::delete_relative(handle).map_err(|_| CorulixError::PathDenied)
    }

    /// `SECURE_RENAME` primitive: takes TWO independently pre-authorized
    /// capabilities (`self` as source, `destination` as target) and
    /// renames via a handle-based `rename_relative(source_handle,
    /// dest_parent_handle, dest_leaf)` -- never a raw pathname
    /// concatenation, never `std::fs::rename`. Fails closed if the two
    /// capabilities were derived from different `WorkspaceRoot`s
    /// (cross-workspace rename denial), checked via opaque root-identity
    /// comparison, never `PathBuf` equality. Consumes both.
    ///
    /// Always passes `replace_if_exists = true` to `rename_relative`,
    /// mirroring `rustix::fs::renameat`'s own POSIX semantics on the Unix
    /// side of this same primitive (Unix's `renameat` unconditionally
    /// replaces an existing destination; there is no separate flag to
    /// withhold that). A "destination must not already exist" policy (the
    /// `MoveFile` shape) is enforced by the CALLER checking
    /// [`PinnedTarget::still_absent`] immediately before calling this --
    /// on both platforms alike -- never by this OS-level primitive's own
    /// collision behavior.
    pub fn rename_into(self, destination: PinnedTarget) -> CorulixResult<()> {
        if self.root_identity != destination.root_identity {
            return Err(CorulixError::PathDenied);
        }
        let source_handle = wht_corulix_process_win32::open_relative(
            &self.parent_handle,
            &self.leaf,
            RelativeOpenKind::ExistingFile,
        )
        .map_err(|_| CorulixError::PathDenied)?;
        wht_corulix_process_win32::rename_relative(
            source_handle,
            &destination.parent_handle,
            &destination.leaf,
            true,
        )
        .map_err(|_| CorulixError::PathDenied)
    }

    /// M09-P9 `SECURE_RENAME` + immediate verification combo: identical
    /// authority to [`Self::rename_into`] (including its
    /// `replace_if_exists = true` policy -- see that method's own doc),
    /// but additionally reopens `destination`'s bound name afterward for
    /// the caller to verify/hash the freshly-committed bytes -- via the
    /// same already-pinned `destination` handle chain, never a re-walk.
    pub fn rename_into_verified(self, destination: PinnedTarget) -> CorulixResult<PinnedFile> {
        if self.root_identity != destination.root_identity {
            return Err(CorulixError::PathDenied);
        }
        let source_handle = wht_corulix_process_win32::open_relative(
            &self.parent_handle,
            &self.leaf,
            RelativeOpenKind::ExistingFile,
        )
        .map_err(|_| CorulixError::PathDenied)?;
        let destination_parent = Arc::clone(&destination.parent_handle);
        let destination_leaf = destination.leaf.clone();
        wht_corulix_process_win32::rename_relative(
            source_handle,
            &destination_parent,
            &destination_leaf,
            true,
        )
        .map_err(|_| CorulixError::PathDenied)?;
        if entry_exists(&self.parent_handle, &self.leaf)? {
            return Err(CorulixError::Internal);
        }
        let reopened = wht_corulix_process_win32::open_relative(
            &destination_parent,
            &destination_leaf,
            RelativeOpenKind::ExistingFile,
        )
        .map_err(|_| CorulixError::PathDenied)?;
        Ok(PinnedFile {
            file: reopened.into_file(),
        })
    }

    /// M09-P9 `SECURE_UNLINK` + immediate absence verification: identical
    /// authority to [`Self::unlink`], but confirms -- via the SAME
    /// already-pinned `(parent_handle, leaf)` pair, never a re-walk -- that
    /// the entry is genuinely gone immediately afterward.
    pub fn unlink_verified(self) -> CorulixResult<()> {
        let handle = wht_corulix_process_win32::open_relative(
            &self.parent_handle,
            &self.leaf,
            RelativeOpenKind::ExistingFile,
        )
        .map_err(|_| CorulixError::PathDenied)?;
        wht_corulix_process_win32::delete_relative(handle).map_err(|_| CorulixError::PathDenied)?;
        if entry_exists(&self.parent_handle, &self.leaf)? {
            return Err(CorulixError::Internal);
        }
        Ok(())
    }

    /// M09-P9: re-checks, via the SAME already-pinned `(parent_handle,
    /// leaf)` this capability was bound to at construction -- never a
    /// re-walk -- whether the entry is still absent.
    pub fn still_absent(&self) -> CorulixResult<bool> {
        Ok(!entry_exists(&self.parent_handle, &self.leaf)?)
    }
}

impl PinnedFile {
    /// Reads the file's full contents, bounded by `max_bytes`. Acts on the
    /// SAME already-open file object every call; no path is ever
    /// re-resolved. Hard-bounded exactly like the Unix implementation's own
    /// M09-P4R fix (`Read::take`, re-checked post-read length) -- a
    /// same-object concurrent writer growing the file cannot make the
    /// actual byte acquisition unbounded before the oversize outcome is
    /// decided.
    pub fn read_bytes(&self, max_bytes: u64) -> CorulixResult<Vec<u8>> {
        use std::io::Read;
        let metadata = self.file.metadata().map_err(|_| CorulixError::Internal)?;
        if metadata.len() > max_bytes {
            return Err(CorulixError::FileTooLarge);
        }
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

    /// Raw `std::fs::Metadata` for the same already-open object --
    /// crate-internal only.
    pub(crate) fn metadata(&self) -> CorulixResult<std::fs::Metadata> {
        self.file.metadata().map_err(|_| CorulixError::Internal)
    }
}

/// `PIN_PARENT_ONLY` resolution mode, exposed across the crate boundary --
/// see [`PinnedParent::resolve`].
pub fn resolve_parent(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<PinnedParent> {
    PinnedParent::resolve(root, relative)
}

/// `EXISTING_TARGET` resolution mode, exposed across the crate boundary --
/// see [`PinnedTarget::resolve_existing`].
pub fn resolve_existing_target(
    root: &WorkspaceRoot,
    relative: &Path,
) -> CorulixResult<PinnedTarget> {
    PinnedTarget::resolve_existing(root, relative)
}

/// `NEW_TARGET_REQUIRE_ABSENT_FINAL_ENTRY` resolution mode, exposed across
/// the crate boundary -- see [`PinnedTarget::resolve_new`].
pub fn resolve_new_target(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<PinnedTarget> {
    PinnedTarget::resolve_new(root, relative)
}
