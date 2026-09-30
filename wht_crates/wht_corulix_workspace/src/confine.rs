// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The canonical workspace root and path-confinement primitive.
//!
//! This is the sole implementation of workspace canonicalization and path
//! confinement in the entire workspace (Architecture Rule F) -- it is moved
//! here verbatim, by security merit, from `wht_corulix_engine::CorulixEngine`,
//! which previously owned this logic and now calls into this crate instead.

use std::{
    fs,
    path::{Component, Path, PathBuf},
};
use wht_corulix_core::{CorulixError, CorulixResult};

#[cfg(unix)]
use std::{os::fd::OwnedFd, sync::Arc};

#[cfg(windows)]
use std::sync::Arc;

/// M09 remediation P1: stable, pathname-independent evidence that a
/// [`WorkspaceRoot`] refers to one specific, already-opened directory
/// object. Never derived from, or compared via, a pathname -- a pathname
/// can be replaced (the root's own directory entry renamed away and a
/// different object put in its place) without this identity changing,
/// which is exactly the property a raw `PathBuf` cannot provide (see the
/// M09 qualification evidence: a fresh confinement operation against a
/// bare canonical path can be fooled by an ordinary-directory replacement
/// at the identical pathname, because a string-prefix check alone cannot
/// tell the replacement apart from the original).
///
/// Deliberately never exposed through MCP or any client-facing type --
/// `(device, inode)` are raw OS identity, not client-safe metadata.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkspaceRootIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl WorkspaceRootIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    // `st_dev`/`st_ino` are already `u64` on this build's rustix backend,
    // but rustix's `Stat` type is backend-dependent across platforms (the
    // `libc` backend's `dev_t`/`ino_t` are not always `u64`) -- the cast
    // stays for portability even though it is a no-op on this specific
    // build.
    #[allow(clippy::unnecessary_cast)]
    fn from_stat(stat: &rustix::fs::Stat) -> Self {
        Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        }
    }
}

/// M09-P9: the Windows equivalent of the Unix [`WorkspaceRootIdentity`]
/// above -- stable, pathname-independent evidence that a [`WorkspaceRoot`]
/// refers to one specific, already-opened directory object, derived from a
/// real handle (`GetFileInformationByHandleEx(FileIdInfo)`: the volume's
/// serial number plus the file system's own 128-bit file id), never from a
/// pathname or `GetFinalPathNameByHandle` text comparison.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkspaceRootIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[cfg(windows)]
impl From<wht_corulix_process_win32::ObjectIdentity> for WorkspaceRootIdentity {
    fn from(identity: wht_corulix_process_win32::ObjectIdentity) -> Self {
        Self {
            volume_serial_number: identity.volume_serial_number,
            file_id: identity.file_id,
        }
    }
}

/// Type-alias only to satisfy `clippy::type_complexity` on the
/// construction-race seam's thread-local storage below -- no behavior
/// change from the equivalent inline type. Unix-only: this seam exists
/// solely for `open_pinned_unix`'s own construction sequence (P1 is
/// Unix-only scope; P9 owns Windows).
#[cfg(all(unix, any(test, feature = "test-support")))]
type ConstructionRaceHook = Box<dyn Fn(&Path)>;

// M09-P1 deterministic construction-race seam: invoked, synchronously,
// with the canonical path immediately after this module captures its
// pre-open identity and immediately before it opens that same path --
// letting a test substitute what lives at that pathname exactly inside
// the window `WorkspaceRoot::open`'s own construction sequence has always
// had (canonicalize/stat, then open), without relying on timing/races.
// Compiles to a true no-op call in a release build (`cfg(not(any(test,
// feature = "test-support")))` below) -- zero release-build presence,
// matching this workspace's established seam pattern
// (`wht_corulix_mutation::MutationExecutor`'s own `precommit_hook`).
#[cfg(all(unix, any(test, feature = "test-support")))]
thread_local! {
    static CONSTRUCTION_RACE_HOOK: std::cell::RefCell<Option<ConstructionRaceHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(unix, any(test, feature = "test-support")))]
fn run_construction_race_hook(path: &Path) {
    CONSTRUCTION_RACE_HOOK.with(|cell| {
        if let Some(hook) = cell.borrow().as_ref() {
            hook(path);
        }
    });
}

#[cfg(all(unix, not(any(test, feature = "test-support"))))]
fn run_construction_race_hook(_path: &Path) {}

/// A canonicalized, validated workspace root.
///
/// The real absolute path is intentionally private: callers that need to
/// perform I/O against it do so through [`resolve_confined`]/
/// [`confined_metadata`], and anything client/MCP-facing must go through
/// Core's `WorkspaceInfo`/`WorkspaceIdentity` (redacted) instead of this
/// type directly.
///
/// M09 remediation P1 (Unix): `canonical` remains display/logging/
/// compatibility metadata ONLY -- it is never, itself, filesystem
/// authority. The pinned `root_fd` (opened once, at construction, with
/// `O_NOFOLLOW`, and identity-verified against what was canonicalized) is
/// the actual authority every later phase's secured operation will consume
/// (P2's component walker, P3's `PinnedParent`/`PinnedFile`, P6's
/// process-cwd binding). `Arc` because this type is cloned pervasively
/// across this workspace's async call sites; cloning duplicates the `Arc`
/// pointer, never reopens the pathname or creates a second, independent
/// authority. M09-P9: Windows now has its own real, pinned handle-based
/// authority (`root_handle`/`identity`, opened via
/// `wht_corulix_process_win32::open_root_directory`), mirroring the Unix
/// `root_fd`/`identity` pair exactly, but through genuine NT/Win32
/// primitives rather than `openat`/`fstat`. Windows process-cwd binding
/// remains out of scope (P10's territory) -- `bind_process_cwd` stays
/// Unix-only.
#[derive(Debug, Clone)]
pub struct WorkspaceRoot {
    canonical: PathBuf,
    // P1 introduces this pinned authority; no consumer migrates onto it
    // until P2 (component walker)/P3 (`PinnedParent`/`PinnedFile`) -- read
    // via the crate-internal `root_fd()` accessor below (exercised by this
    // module's own P1 tests), not yet by any other module. `dead_code`
    // would otherwise fire on a non-test build, since P1 deliberately
    // introduces this field ahead of its scheduled P2/P3 consumers.
    #[cfg(unix)]
    #[allow(dead_code)]
    root_fd: Arc<OwnedFd>,
    #[cfg(unix)]
    identity: WorkspaceRootIdentity,
    // M09-P9: the Windows mirror of the Unix `root_fd`/`identity` pair
    // above -- an owned, pinned NT directory handle (opened once, at
    // construction, via `wht_corulix_process_win32::open_root_directory`)
    // plus its handle-derived object identity. `Arc` for the same reason
    // as Unix's `root_fd`: cloning `WorkspaceRoot` duplicates the `Arc`
    // pointer, never reopens the pathname or creates a second, independent
    // authority.
    #[cfg(windows)]
    root_handle: Arc<wht_corulix_process_win32::FileHandle>,
    #[cfg(windows)]
    identity: WorkspaceRootIdentity,
}

impl WorkspaceRoot {
    /// Canonicalizes and validates `path` as a workspace root: it must
    /// canonicalize successfully and be a directory. This is root
    /// *validity*, not root *trust* -- see
    /// [`wht_corulix_core::WorkspaceTrust`], which this crate never sets.
    ///
    /// M09-P1 (Unix): additionally pins the root's own filesystem-object
    /// identity via the secure-open sequence in `Self::open_pinned_unix`
    /// -- see that function's doc comment for the exact sequence and the
    /// residual construction-time window it closes by verification rather
    /// than by claiming to eliminate.
    pub fn open(path: impl AsRef<Path>) -> CorulixResult<Self> {
        let canonical =
            fs::canonicalize(path.as_ref()).map_err(|_| CorulixError::WorkspaceNotFound)?;
        if !canonical.is_dir() {
            return Err(CorulixError::WorkspaceNotFound);
        }
        #[cfg(unix)]
        {
            Self::open_pinned_unix(canonical)
        }
        #[cfg(windows)]
        {
            Self::open_pinned_windows(canonical)
        }
    }

    /// M09-P1 secure-open sequence (frozen by the M09 architecture-freeze
    /// pass): canonicalize has already happened in [`Self::open`]; this
    /// captures the pre-open identity of that canonical path, opens it
    /// with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` (never following a
    /// symlink substituted at that pathname), `fstat`s the resulting fd,
    /// and requires the pre-open and post-open identities to match before
    /// accepting the root at all.
    ///
    /// This does not claim the pre-open-to-open interval is eliminated --
    /// it is small (a handful of back-to-back syscalls, not "canonicalize
    /// then much later open") but real. What closes it is verification,
    /// not elimination: an ordinary-directory substitution at the
    /// canonical pathname during that interval changes the post-open
    /// identity, which the required match then rejects; a symlink
    /// substitution is rejected by `O_NOFOLLOW` directly, before identity
    /// is even compared. Either way, `WorkspaceRoot::open` fails closed
    /// rather than silently pinning the wrong object.
    #[cfg(unix)]
    fn open_pinned_unix(canonical: PathBuf) -> CorulixResult<Self> {
        let pre_metadata =
            fs::symlink_metadata(&canonical).map_err(|_| CorulixError::WorkspaceNotFound)?;
        let pre_identity = WorkspaceRootIdentity::from_metadata(&pre_metadata);

        run_construction_race_hook(&canonical);

        let root_fd = rustix::fs::open(
            &canonical,
            rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| CorulixError::WorkspaceNotFound)?;

        let post_stat = rustix::fs::fstat(&root_fd).map_err(|_| CorulixError::WorkspaceNotFound)?;
        let post_identity = WorkspaceRootIdentity::from_stat(&post_stat);

        if pre_identity != post_identity {
            return Err(CorulixError::WorkspaceNotFound);
        }

        Ok(Self {
            canonical,
            root_fd: Arc::new(root_fd),
            identity: post_identity,
        })
    }

    /// M09-P9 secure-open sequence: opens `canonical` once, via
    /// `wht_corulix_process_win32::open_root_directory` (the ONE
    /// pathname-based open in this crate's entire Windows authority --
    /// mirrors [`Self::open_pinned_unix`]'s own single pathname-anchored
    /// `rustix::fs::open` exactly), and captures its handle-derived
    /// [`WorkspaceRootIdentity`]. Every later Windows operation
    /// (`PinnedParent`/`PinnedTarget`/`PinnedFile` component walks, reads,
    /// writes, renames, deletes) is relative to this pinned handle or a
    /// descendant opened relative to it -- never a re-resolved pathname.
    ///
    /// Unlike Unix's `O_NOFOLLOW`-based open, this open does NOT reject a
    /// root path whose final component is itself a reparse point (Windows'
    /// `CreateFileW` transparently follows reparse points here, matching
    /// this crate's own pre-P9 Windows behavior for the root itself) --
    /// this is deliberate and narrow: the root is named once, by the
    /// caller/host configuration, not by untrusted input, so what matters
    /// is that EVERY SUBSEQUENT component walked below the root fails
    /// closed on a reparse point (`M09_P9_WINDOWS_REPARSE_PLATFORM_DELTA`,
    /// enforced by `wht_corulix_process_win32::open_relative`), not the
    /// root's own construction.
    #[cfg(windows)]
    fn open_pinned_windows(canonical: PathBuf) -> CorulixResult<Self> {
        let (handle, identity) = wht_corulix_process_win32::open_root_directory(&canonical)
            .map_err(|_| CorulixError::WorkspaceNotFound)?;
        Ok(Self {
            canonical,
            root_handle: Arc::new(handle),
            identity: WorkspaceRootIdentity::from(identity),
        })
    }

    /// The real, canonical absolute path. Internal use only (opening the
    /// engine, performing confined I/O) -- never serialize or expose this
    /// value to a client/MCP response. Display/logging/compatibility
    /// metadata only, per this type's own doc comment -- never itself
    /// filesystem authority.
    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical
    }

    /// The pinned root directory fd -- crate-internal only (Section 13's
    /// "no raw fd public leak" requirement: `RawFd`/`OwnedFd`/`BorrowedFd`
    /// never cross this crate's public boundary). Consumed by
    /// `secure_walk`'s component walker (P2) and, through it,
    /// `capability`'s opaque capability constructors (P3).
    #[cfg(unix)]
    pub(crate) fn root_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.root_fd.as_fd()
    }

    /// The pinned root's own filesystem-object identity -- crate-internal
    /// only. Used by `capability`'s opaque types (P3) to bind each
    /// capability to the exact `WorkspaceRoot` it was derived from
    /// (Section 34/35 of the P3 mandate: cross-workspace operations must
    /// be detectable via object identity, never `PathBuf` comparison).
    #[cfg(unix)]
    pub(crate) fn identity(&self) -> WorkspaceRootIdentity {
        self.identity
    }

    /// M09-P6: configures `command` so that, after `fork` and before
    /// `exec`, the child process's current working directory becomes the
    /// EXACT filesystem object this `WorkspaceRoot` pinned at construction
    /// time (`M09_P6_UNIX_CWD_AUTHORITY=PINNED_ROOT_OBJECT`) -- never a
    /// pathname re-resolved at spawn time. Nothing that happens to
    /// `self.canonical`'s own pathname after this call (a rename, a
    /// replacement with an ordinary directory, a replacement with a
    /// symlink to an entirely different location, or the same happening
    /// to any ancestor) can redirect the child: the actual `fchdir` this
    /// registers operates on the pinned root fd itself, never on a
    /// re-walked path.
    ///
    /// The real unsafe `pre_exec` registration lives in
    /// `wht_corulix_process_unix` (this crate's own `[lints] workspace =
    /// true` inherits `unsafe_code = "forbid"`, which admits no local
    /// override) -- see that crate's own module doc for the full
    /// async-signal-safety/fd-ownership/`CLOEXEC` rationale. This method
    /// clones `self`'s own `Arc<OwnedFd>` (never re-opening the pathname,
    /// never handing out the fd itself) so the registered closure -- and
    /// therefore `command` -- holds an independent reference to the
    /// pinned root object for as long as `command` lives, regardless of
    /// whether this `WorkspaceRoot` value itself is later dropped.
    ///
    /// Infallible: registering a `pre_exec` closure cannot itself fail
    /// (only the eventual `fchdir` call, inside the child, can -- and that
    /// surfaces through `Command::spawn`'s own `io::Result`, per
    /// `wht_corulix_process_unix::bind_cwd`'s own documented contract).
    #[cfg(unix)]
    pub fn bind_process_cwd(&self, command: &mut std::process::Command) {
        wht_corulix_process_unix::bind_cwd(command, Arc::clone(&self.root_fd));
    }

    /// M09-P8: verifies that this root's canonical pathname still resolves
    /// to the exact filesystem object pinned at construction time --
    /// intended for a long-lived consumer (e.g. `wht_corulix_lsp`'s
    /// `LspSession`) that must re-check identity at points *after*
    /// construction (immediately before transmitting `initialize`, and at
    /// each later semantic-request boundary), where `bind_process_cwd`'s
    /// fd-based authority does not itself apply (no new process is being
    /// spawned at those points).
    ///
    /// Deliberately uses `fs::metadata` (follows symlinks), NOT
    /// `fs::symlink_metadata` (which `open_pinned_unix` above uses,
    /// correctly, since that call pairs it with an `O_NOFOLLOW` open that
    /// refuses to follow -- there is no such open here). This method asks
    /// "does this pathname still lead to my pinned object", so it must
    /// follow exactly as far as opening the pathname normally would: a
    /// legitimate root reached through a symlinked ancestor (e.g. a `/tmp`
    /// -> `/private/tmp`-style setup) would otherwise report the
    /// *symlink's* identity forever and never match, permanently failing a
    /// legitimate workspace. Both attack shapes this method exists to
    /// catch -- the pathname's final directory entry replaced with an
    /// ordinary directory, or replaced with a symlink to an unrelated
    /// location -- still resolve, via `fs::metadata`, to the replacement's
    /// real target identity, which still mismatches the pinned one.
    ///
    /// Returns `false` (never panics, never exposes raw `(device, inode)`
    /// to the caller -- Section 13's "no raw device/inode/fd leak past
    /// this crate" requirement) on any identity mismatch OR outright
    /// metadata failure (pathname now missing, permission revoked, an
    /// intervening component no longer a directory, etc.) -- both count as
    /// "no longer safely usable" to this method's caller, which must fail
    /// closed either way.
    #[cfg(unix)]
    #[must_use]
    pub fn verify_current_path_identity(&self) -> bool {
        let Ok(metadata) = fs::metadata(&self.canonical) else {
            return false;
        };
        WorkspaceRootIdentity::from_metadata(&metadata) == self.identity
    }

    /// M09-P9: a fresh, independent `Arc`-shared reference to the pinned
    /// root directory handle -- crate-internal only (mirrors Unix's
    /// `root_fd`; no raw `HANDLE`/`FileHandle` ever crosses this crate's
    /// public boundary). Consumed by `capability_win32`'s component walker
    /// to anchor the very first relative open; cloning the `Arc` never
    /// reopens the pathname or duplicates the underlying kernel handle.
    #[cfg(windows)]
    pub(crate) fn root_handle_arc(&self) -> Arc<wht_corulix_process_win32::FileHandle> {
        Arc::clone(&self.root_handle)
    }

    /// M09-P9: the pinned root's own handle-derived object identity --
    /// crate-internal only. Mirrors Unix's `identity()` accessor; used by
    /// `capability_win32`'s opaque types to bind each capability to the
    /// exact `WorkspaceRoot` it was derived from (cross-workspace rename
    /// denial).
    #[cfg(windows)]
    pub(crate) fn identity(&self) -> WorkspaceRootIdentity {
        self.identity
    }

    /// M09-P9: the Windows mirror of the Unix
    /// `verify_current_path_identity` above -- re-opens the canonical
    /// pathname (via the same `open_root_directory` pathname-anchored open
    /// used at construction, which transparently follows reparse points,
    /// matching `fs::metadata`'s own follow-symlinks semantics on Unix) and
    /// compares its handle-derived identity against the one pinned at
    /// construction. Never itself the confinement authority (that is
    /// exclusively the handle-relative walk in `capability_win32`) --
    /// exactly the "identity-verification, not operative boundary" use the
    /// P9 mandate permits for a pathname-based check.
    ///
    /// Returns `false` (never panics) on any identity mismatch or outright
    /// open failure -- both count as "no longer safely usable."
    #[cfg(windows)]
    #[must_use]
    pub fn verify_current_path_identity(&self) -> bool {
        let Ok((_, identity)) = wht_corulix_process_win32::open_root_directory(&self.canonical)
        else {
            return false;
        };
        WorkspaceRootIdentity::from(identity) == self.identity
    }
}

/// M09-P1 equality contract (frozen by the M09 architecture-freeze pass):
/// on Unix, two [`WorkspaceRoot`] values are equal only if they share both
/// the same canonical display path AND the same pinned filesystem-object
/// identity -- never the canonical path alone, which is exactly the
/// property that would make two genuinely-different root objects (the
/// original, and an ordinary directory later substituted at the identical
/// pathname) compare equal. A clone of one `WorkspaceRoot` is always equal
/// to its source (same `Arc`-shared fd, same captured identity). Windows
/// (pre-P9) compares canonical path only, matching its current, unpinned
/// representation -- not a claim of equivalent security semantics.
#[cfg(unix)]
impl PartialEq for WorkspaceRoot {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical && self.identity == other.identity
    }
}
#[cfg(unix)]
impl Eq for WorkspaceRoot {}

/// M09-P9: Windows equality contract, now mirroring Unix's own -- two
/// [`WorkspaceRoot`] values are equal only if they share both the same
/// canonical display path AND the same pinned handle-derived identity.
/// Pre-P9 this compared the canonical path alone (an unpinned,
/// pathname-only representation); this is a strict strengthening, never a
/// weakening, of the equality contract.
#[cfg(windows)]
impl PartialEq for WorkspaceRoot {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical && self.identity == other.identity
    }
}
#[cfg(windows)]
impl Eq for WorkspaceRoot {}

/// A path proven to resolve inside a [`WorkspaceRoot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedPath(PathBuf);

impl ConfinedPath {
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

/// The blocking-safe confinement core. Private: the canonical public
/// surface for this operation is [`resolve_confined`] (`.await`) -- no
/// other crate may bypass it with a synchronous call, so this core is not
/// exported. Every other crate that previously composed its own
/// `spawn_blocking` boundary around this core (`wht_corulix_search`'s
/// `search`, `wht_corulix_engine`'s `parse_relative_file`) now awaits
/// [`resolve_confined`]/[`confined_metadata`]/[`confined_read`]/
/// [`confined_walk`] directly instead.
///
/// This is the single security boundary standing between untrusted input
/// and the filesystem, so every step below defends against a specific
/// escape technique rather than being an arbitrary validation choice.
///
/// Residual risk (documented, not eliminated): a TOCTOU window exists
/// between this function's canonicalization/containment check and any later
/// I/O a caller performs against the returned path (e.g. a symlink could, in
/// principle, be swapped between the check and a subsequent read). Safe
/// Rust's `std::fs` API does not provide an `openat`/capability-FD-based
/// alternative; closing this window fully would require a larger,
/// platform-specific redesign that is not justified for Phase 2's scope.
pub(crate) fn resolve_confined_blocking(
    root: &WorkspaceRoot,
    relative: &Path,
) -> CorulixResult<ConfinedPath> {
    // Step 1: reject empty and absolute paths up front. An absolute path
    // would bypass joining against the root entirely (e.g. `/etc/passwd`),
    // letting a caller address any file on the host filesystem regardless
    // of workspace.
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(CorulixError::PathDenied);
    }

    // Step 2: reject any `..` (parent-dir), root, or Windows drive-prefix
    // component before the path is ever joined to the root. This blocks
    // classic directory-traversal payloads (e.g. `../../etc/passwd`) that
    // would otherwise walk back out of the workspace once joined. `CurDir`
    // (`.`) and plain `Normal` segments are harmless and allowed.
    for component in relative.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CorulixError::PathDenied);
            }
        }
    }

    // Step 3: join onto the canonical root, then canonicalize the result.
    // Canonicalization resolves symlinks -- a component-level check alone
    // cannot catch a symlink inside the workspace that itself points
    // outside of it, so this step is required even though Step 2 already
    // rejected literal `..` segments.
    let joined = root.canonical_path().join(relative);
    let canonical = fs::canonicalize(&joined).map_err(|_| CorulixError::PathDenied)?;

    // Step 4: verify the fully-resolved path still lives under the
    // canonical workspace root. This is the final containment check that
    // catches any symlink escape (or other resolution surprise) that
    // slipped past the earlier component-based checks.
    if !canonical.starts_with(root.canonical_path()) {
        return Err(CorulixError::PathDenied);
    }
    Ok(ConfinedPath(canonical))
}

/// Confines `relative` under `root`, then returns its filesystem metadata.
///
/// M09-P4 (Unix): migrated onto the P3 capability layer -- resolves via
/// [`crate::capability::PinnedTarget::resolve_existing`] (the same
/// `EXISTING_TARGET_FOLLOW_SAFE_FINAL_SYMLINK` mode `confined_read` uses,
/// preserving the historical "final symlink to inside: allowed, to
/// outside: denied" contract exactly), then opens it and reads metadata
/// from THAT SAME already-open object (`PinnedTarget::open_raw` +
/// `PinnedFile::metadata`) -- never a second, separately-resolved
/// `fs::metadata(path)` call. `M09_P4_READ_PATHNAME_RE_RESOLUTION_COUNT=0`.
///
/// Windows (M09-P9): migrated onto the P9 handle-based capability layer --
/// resolves via [`crate::capability_win32::PinnedTarget::resolve_existing`]
/// (ancestor-walked via handle-relative `NtCreateFile`, fail-closed on any
/// reparse point), then opens it and reads metadata from THAT SAME
/// already-open handle -- never a second, separately-resolved
/// `fs::metadata(path)` call, exactly mirroring the Unix branch's own
/// `M09_P4_READ_PATHNAME_RE_RESOLUTION_COUNT=0` property.
///
/// Private blocking core behind the canonical [`confined_metadata`] (`.await`).
#[cfg(unix)]
fn confined_metadata_blocking(
    root: &WorkspaceRoot,
    relative: &Path,
) -> CorulixResult<fs::Metadata> {
    let target = crate::capability::PinnedTarget::resolve_existing(root, relative)?;
    let file = target.open_raw()?;
    file.metadata()
        .map_err(|_| CorulixError::InvalidInput("file missing".into()))
}

#[cfg(windows)]
fn confined_metadata_blocking(
    root: &WorkspaceRoot,
    relative: &Path,
) -> CorulixResult<fs::Metadata> {
    let target = crate::capability_win32::PinnedTarget::resolve_existing(root, relative)?;
    let file = target.open_raw()?;
    file.metadata()
        .map_err(|_| CorulixError::InvalidInput("file missing".into()))
}

/// Confines `relative` under `root`, then reads its bytes -- bounded by
/// `max_bytes` so a caller can never force an unbounded read merely by
/// naming a large file. This is a provider-neutral primitive (not specific
/// to any one consumer crate): any future provider that needs bounded file
/// bytes under confinement uses this instead of reimplementing bounded I/O
/// against a caller-controlled path.
///
/// Fails closed (`CorulixError::FileTooLarge`) on a file whose reported size
/// already exceeds `max_bytes` -- the read is never attempted, let alone
/// truncated silently -- and rejects a target that is not a regular file
/// (a directory or other non-file entry).
///
/// M09-P4 (Unix): the bytes returned and the metadata used to authorize/
/// bound them belong to the exact same already-opened [`PinnedFile`]
/// object (Section 4/5 of the P4 mandate) -- resolved once via
/// `PinnedTarget::resolve_existing`, opened once via `open_raw`, and both
/// the type/size check and the actual read happen against that one open
/// file. A namespace replacement (root/ancestor rename, symlink
/// substitution) at any point after that open is irrelevant: nothing
/// downstream ever re-resolves a pathname to reach the target again.
/// [`PinnedFile::read_bytes`] re-checks the size bound defensively
/// (Section 8: a file that grows between this function's own check and
/// the call into `read_bytes` is still caught, not merely assumed safe
/// because the earlier `fstat` was under the limit).
///
/// Windows (M09-P9): migrated onto the P9 handle-based capability layer --
/// same disclosure as `confined_metadata_blocking`'s own doc comment
/// above: resolved once, opened once, read from that same already-open
/// handle -- never a second pathname re-resolution.
///
/// Private blocking core behind the canonical [`confined_read`] (`.await`).
#[cfg(unix)]
fn confined_read_blocking(
    root: &WorkspaceRoot,
    relative: &Path,
    max_bytes: u64,
) -> CorulixResult<Vec<u8>> {
    let target = crate::capability::PinnedTarget::resolve_existing(root, relative)?;
    let file = target
        .open_raw()
        .map_err(|_| CorulixError::InvalidInput("file missing".into()))?;
    let metadata = file
        .metadata()
        .map_err(|_| CorulixError::InvalidInput("file missing".into()))?;
    if !metadata.is_file() {
        return Err(CorulixError::InvalidInput(
            "confined_read target is not a regular file".into(),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CorulixError::FileTooLarge);
    }
    file.read_bytes(max_bytes)
}

#[cfg(windows)]
fn confined_read_blocking(
    root: &WorkspaceRoot,
    relative: &Path,
    max_bytes: u64,
) -> CorulixResult<Vec<u8>> {
    let target = crate::capability_win32::PinnedTarget::resolve_existing(root, relative)?;
    let file = target
        .open_raw()
        .map_err(|_| CorulixError::InvalidInput("file missing".into()))?;
    let metadata = file
        .metadata()
        .map_err(|_| CorulixError::InvalidInput("file missing".into()))?;
    if !metadata.is_file() {
        return Err(CorulixError::InvalidInput(
            "confined_read target is not a regular file".into(),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CorulixError::FileTooLarge);
    }
    file.read_bytes(max_bytes)
}

/// Corulix 1.1.0 (ADR 0012): same contract as [`confined_read_blocking`],
/// except a genuinely absent `relative` (the common, expected case for an
/// optional workspace config file that was never authored) is reported as
/// `Ok(None)` instead of an error -- every other failure (permission
/// denied, wrong type, oversize, any ancestor resolution failure) still
/// fails closed exactly like `confined_read_blocking`, never silently
/// treated as "absent, use defaults". This is the primitive
/// `wht_corulix_config::workspace_config` needs to implement its own
/// `WorkspaceConfigError::NotPresent` vs `PathDenied` distinction.
///
/// Private blocking core behind the canonical [`confined_read_optional`]
/// (`.await`).
#[cfg(unix)]
fn confined_read_optional_blocking(
    root: &WorkspaceRoot,
    relative: &Path,
    max_bytes: u64,
) -> CorulixResult<Option<Vec<u8>>> {
    let target = crate::capability::PinnedTarget::resolve_existing(root, relative)?;
    let Some(file) = target.open_raw_or_absent()? else {
        return Ok(None);
    };
    let metadata = file
        .metadata()
        .map_err(|_| CorulixError::InvalidInput("file missing".into()))?;
    if !metadata.is_file() {
        return Err(CorulixError::InvalidInput(
            "confined_read_optional target is not a regular file".into(),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CorulixError::FileTooLarge);
    }
    file.read_bytes(max_bytes).map(Some)
}

#[cfg(windows)]
fn confined_read_optional_blocking(
    root: &WorkspaceRoot,
    relative: &Path,
    max_bytes: u64,
) -> CorulixResult<Option<Vec<u8>>> {
    let target = crate::capability_win32::PinnedTarget::resolve_existing(root, relative)?;
    let Some(file) = target.open_raw_or_absent()? else {
        return Ok(None);
    };
    let metadata = file
        .metadata()
        .map_err(|_| CorulixError::InvalidInput("file missing".into()))?;
    if !metadata.is_file() {
        return Err(CorulixError::InvalidInput(
            "confined_read_optional target is not a regular file".into(),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CorulixError::FileTooLarge);
    }
    file.read_bytes(max_bytes).map(Some)
}

/// Bounds for [`confined_walk`]: a maximum directory depth below the walk's
/// starting point, and a maximum number of file entries returned.
#[derive(Debug, Clone, Copy)]
pub struct WalkLimits {
    pub max_depth: u32,
    pub max_entries: usize,
}

pub const DEFAULT_MAX_WALK_DEPTH: u32 = 64;
pub const DEFAULT_MAX_WALK_ENTRIES: usize = 100_000;

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_WALK_DEPTH,
            max_entries: DEFAULT_MAX_WALK_ENTRIES,
        }
    }
}

/// Confined, bounded, symlink-safe recursive file enumeration under one
/// workspace root.
///
/// `scope` is itself confined via [`resolve_confined_blocking`] before the
/// walk starts, so a caller can never request a walk rooted outside the
/// workspace. Every directory entry that is a symlink (file or directory)
/// is skipped entirely -- never followed, never returned -- which makes a
/// symlink-cycle structurally impossible (a cycle requires following a
/// symlink back to an ancestor, and this walk never follows one) and
/// closes the "unbounded/uncontrolled symlink following" concern by
/// construction rather than by cycle-detection bookkeeping. Exceeding
/// either bound in `limits` fails the walk closed
/// (`CorulixError::ResourceLimit`) rather than silently truncating results.
///
/// Private blocking core behind the canonical [`confined_walk`] (`.await`).
fn confined_walk_blocking(
    root: &WorkspaceRoot,
    scope: &Path,
    limits: &WalkLimits,
) -> CorulixResult<Vec<ConfinedPath>> {
    let start = resolve_confined_blocking(root, scope)?;
    let mut results = Vec::new();
    let mut stack = vec![(start.into_path_buf(), 0u32)];

    while let Some((directory, depth)) = stack.pop() {
        if depth > limits.max_depth {
            return Err(CorulixError::ResourceLimit);
        }
        let entries = fs::read_dir(&directory).map_err(|_| CorulixError::PathDenied)?;
        for entry in entries {
            let entry = entry.map_err(|_| CorulixError::Internal)?;
            let file_type = entry.file_type().map_err(|_| CorulixError::Internal)?;
            // Never follow a symlink, whether it names a file or a
            // directory -- this is the entire symlink-safety mechanism for
            // this walk, and it makes a symlink cycle structurally
            // impossible rather than merely detected.
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if !path.starts_with(root.canonical_path()) {
                // Defense in depth: should be unreachable, since read_dir
                // only ever yields children of an already-confined
                // directory, but never trust a path without checking it.
                continue;
            }
            if file_type.is_dir() {
                stack.push((path, depth + 1));
            } else {
                if results.len() >= limits.max_entries {
                    return Err(CorulixError::ResourceLimit);
                }
                results.push(ConfinedPath(path));
            }
        }
    }

    Ok(results)
}

/// Canonical async entry point for `resolve_confined_blocking`. Runs the
/// blocking confinement check on Tokio's blocking-task pool via
/// `tokio::task::spawn_blocking`, so an async caller never blocks its own
/// executor thread on a canonicalization syscall. This is the only public
/// name this operation has for a caller that is not already inside its own
/// `spawn_blocking` closure -- there is no synchronous `resolve_confined`
/// kept alongside it.
pub async fn resolve_confined(
    root: WorkspaceRoot,
    relative: PathBuf,
) -> CorulixResult<ConfinedPath> {
    tokio::task::spawn_blocking(move || resolve_confined_blocking(&root, &relative))
        .await
        .unwrap_or(Err(CorulixError::Internal))
}

/// Canonical async entry point for `confined_metadata_blocking`. See
/// [`resolve_confined`]'s docs for the blocking-boundary rationale.
pub async fn confined_metadata(
    root: WorkspaceRoot,
    relative: PathBuf,
) -> CorulixResult<fs::Metadata> {
    tokio::task::spawn_blocking(move || confined_metadata_blocking(&root, &relative))
        .await
        .unwrap_or(Err(CorulixError::Internal))
}

/// Canonical async entry point for `confined_read_blocking`. See
/// [`resolve_confined`]'s docs for the blocking-boundary rationale.
pub async fn confined_read(
    root: WorkspaceRoot,
    relative: PathBuf,
    max_bytes: u64,
) -> CorulixResult<Vec<u8>> {
    tokio::task::spawn_blocking(move || confined_read_blocking(&root, &relative, max_bytes))
        .await
        .unwrap_or(Err(CorulixError::Internal))
}

/// Canonical async entry point for `confined_read_optional_blocking`. See
/// [`resolve_confined`]'s docs for the blocking-boundary rationale.
///
/// Corulix 1.1.0 (ADR 0012): `wht_corulix_config::workspace_config` uses
/// this (never `confined_read`) to read the optional
/// `WhaTalker_Corulix_JSON_Config.json` file, so genuine absence
/// (`Ok(None)`) and every other failure (`Err`, fail-closed) are never
/// conflated.
pub async fn confined_read_optional(
    root: WorkspaceRoot,
    relative: PathBuf,
    max_bytes: u64,
) -> CorulixResult<Option<Vec<u8>>> {
    tokio::task::spawn_blocking(move || {
        confined_read_optional_blocking(&root, &relative, max_bytes)
    })
    .await
    .unwrap_or(Err(CorulixError::Internal))
}

/// Merges a confined, bounded file read with a caller-supplied blocking
/// transformation into a single `spawn_blocking` hop, instead of a caller
/// separately awaiting [`confined_read`] and then opening its own second
/// `spawn_blocking` around whatever it does with the bytes.
///
/// This crate stays completely opaque to what `process` does with the
/// bytes (Architecture Rule D/F: a provider-specific transformation, e.g.
/// `wht_corulix_search`'s regex matching, never becomes a dependency of
/// this crate) -- `process` is a plain, generic, caller-supplied closure,
/// so this helper carries no provider-specific type or crate dependency of
/// its own.
///
/// Safe to merge specifically because every caller of this helper already
/// performs its own per-file bound checks (result/byte/count ceilings)
/// *before* deciding to read a given file at all -- this helper only
/// changes how many blocking-pool hops happen *after* that decision is
/// already made, never whether the file is read in the first place. Fails
/// closed with the read-side [`CorulixError`] (unchanged from
/// [`confined_read`], including `FileTooLarge`) if the read itself fails;
/// `process` runs only on a successful read.
pub async fn confined_read_and_process<T, F>(
    root: WorkspaceRoot,
    relative: PathBuf,
    max_bytes: u64,
    process: F,
) -> CorulixResult<T>
where
    F: FnOnce(Vec<u8>) -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let bytes = confined_read_blocking(&root, &relative, max_bytes)?;
        Ok(process(bytes))
    })
    .await
    .unwrap_or(Err(CorulixError::Internal))
}

/// Canonical async entry point for `confined_walk_blocking`. See
/// [`resolve_confined`]'s docs for the blocking-boundary rationale.
pub async fn confined_walk(
    root: WorkspaceRoot,
    scope: PathBuf,
    limits: WalkLimits,
) -> CorulixResult<Vec<ConfinedPath>> {
    tokio::task::spawn_blocking(move || confined_walk_blocking(&root, &scope, &limits))
        .await
        .unwrap_or(Err(CorulixError::Internal))
}

/// Canonicalizes an arbitrary absolute filesystem path that is not
/// necessarily workspace-relative (e.g. a host-configured external provider
/// path), and reports whether the resolved target is a regular file.
///
/// This is a distinct primitive from [`resolve_confined_blocking`]: it does
/// not confine the input to any [`WorkspaceRoot`] and performs no
/// containment check of its own -- callers that need a workspace-membership
/// decision (e.g. rejecting a provider path that resolves inside the active
/// workspace) compare the returned canonical path against
/// [`WorkspaceRoot::canonical_path`] themselves. It still belongs here and
/// only here (Architecture Rule F: this crate is the sole implementation of
/// filesystem canonicalization in the workspace) rather than in any other
/// crate that merely needs to canonicalize a path it did not otherwise
/// obtain through workspace confinement.
///
/// Fails closed with [`CorulixError::PathDenied`] on a non-absolute input or
/// a canonicalization failure (missing target, symlink cycle, permission
/// error) -- never a partial/best-effort path.
fn canonicalize_external_path_blocking(path: &Path) -> CorulixResult<(PathBuf, bool)> {
    if !path.is_absolute() {
        return Err(CorulixError::PathDenied);
    }
    let canonical = fs::canonicalize(path).map_err(|_| CorulixError::PathDenied)?;
    let is_file = fs::metadata(&canonical)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);
    Ok((canonical, is_file))
}

/// Canonical async entry point for `canonicalize_external_path_blocking`.
/// See [`resolve_confined`]'s docs for the blocking-boundary rationale.
pub async fn canonicalize_external_path(path: PathBuf) -> CorulixResult<(PathBuf, bool)> {
    tokio::task::spawn_blocking(move || canonicalize_external_path_blocking(&path))
        .await
        .unwrap_or(Err(CorulixError::Internal))
}

/// Confines a relative path whose **target need not exist yet** -- the
/// primitive [`resolve_confined_blocking`] cannot serve this because it
/// canonicalizes the full joined path (leaf included), which fails for
/// anything not already on disk. This is exactly the primitive a mutation
/// authority needs for `CreateFile`'s target and for a same-directory
/// staging temp file, so it can obtain a safe path without duplicating any
/// confinement logic of its own (Architecture Rule F).
///
/// Only the parent directory is required to exist and canonicalize inside
/// the workspace root; the leaf component is validated syntactically
/// (rejecting `..`/absolute/root/prefix components, exactly like
/// [`resolve_confined_blocking`]'s own Step 1/2) but never itself
/// canonicalized, since doing so would require it to exist. A caller that
/// needs the *fully resolved* path once its target does exist should use
/// [`resolve_confined`] instead -- this primitive is specifically for the
/// "not yet on disk" case.
///
/// Private blocking core behind the canonical [`confine_target`] (`.await`).
fn confine_target_blocking(root: &WorkspaceRoot, relative: &Path) -> CorulixResult<PathBuf> {
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
    let file_name = relative.file_name().ok_or(CorulixError::PathDenied)?;
    let parent_relative = relative
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let canonical_parent = match parent_relative {
        Some(parent_relative) => {
            let joined = root.canonical_path().join(parent_relative);
            fs::canonicalize(&joined).map_err(|_| CorulixError::PathDenied)?
        }
        None => root.canonical_path().to_path_buf(),
    };
    if !canonical_parent.starts_with(root.canonical_path()) {
        return Err(CorulixError::PathDenied);
    }
    Ok(canonical_parent.join(file_name))
}

/// Canonical async entry point for `confine_target_blocking`. See
/// [`resolve_confined`]'s docs for the blocking-boundary rationale.
pub async fn confine_target(root: WorkspaceRoot, relative: PathBuf) -> CorulixResult<PathBuf> {
    tokio::task::spawn_blocking(move || confine_target_blocking(&root, &relative))
        .await
        .unwrap_or(Err(CorulixError::Internal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_workspace() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-workspace-test-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    fn open_root(path: &Path) -> CorulixResult<WorkspaceRoot> {
        WorkspaceRoot::open(path)
    }

    #[tokio::test]
    async fn parent_traversal_is_denied() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("../outside.rs")).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn absolute_path_is_denied() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("/etc/passwd")).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn empty_relative_path_is_denied() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("")).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn root_prefix_component_is_denied() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("/")).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn nonexistent_target_is_denied_not_panicked() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("does-not-exist.rs")).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_symlink_escape_is_denied() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let outside = temp_workspace();
        let outside_file = outside.join("outside.rs");
        let _ = fs::write(&outside_file, "fn outside() {}");
        let link = path.join("escape.rs");
        let _ = symlink(&outside_file, &link);

        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("escape.rs")).await,
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn directory_symlink_escape_is_denied() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let outside = temp_workspace();
        let outside_dir = outside.join("outside_dir");
        let _ = fs::create_dir_all(&outside_dir);
        let _ = fs::write(outside_dir.join("secret.rs"), "fn secret() {}");
        let link = path.join("escape_dir");
        let _ = symlink(&outside_dir, &link);

        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("escape_dir/secret.rs")).await,
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn nested_symlink_escape_is_denied() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let outside = temp_workspace();
        let nested = path.join("a/b");
        let _ = fs::create_dir_all(&nested);
        let outside_file = outside.join("outside.rs");
        let _ = fs::write(&outside_file, "fn outside() {}");
        let link = nested.join("escape.rs");
        let _ = symlink(&outside_file, &link);

        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("a/b/escape.rs")).await,
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_cycle_does_not_hang_or_panic() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let a = path.join("a");
        let b = path.join("b");
        let _ = symlink(&b, &a);
        let _ = symlink(&a, &b);

        let root = open_root(&path)?;
        // std::fs::canonicalize itself detects the cycle and returns an
        // error (ELOOP) rather than hanging -- this proves resolve_confined
        // propagates that as a denial instead of panicking or looping.
        assert!(matches!(
            resolve_confined(root, PathBuf::from("a")).await,
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_file(&a);
        let _ = fs::remove_file(&b);
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn broken_symlink_is_denied_not_panicked() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let link = path.join("broken.rs");
        let _ = symlink(path.join("does-not-exist-target.rs"), &link);

        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("broken.rs")).await,
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relative_symlink_outside_root_is_denied() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let link = path.join("relative_escape.rs");
        // A relative symlink target that walks upward past the workspace
        // root via `..` components.
        let _ = symlink("../../../../../../etc/passwd", &link);

        let root = open_root(&path)?;
        assert!(matches!(
            resolve_confined(root, PathBuf::from("relative_escape.rs")).await,
            Err(CorulixError::PathDenied)
        ));

        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_metadata_returns_regular_file_metadata() -> CorulixResult<()> {
        let path = temp_workspace();
        let _ = fs::write(path.join("real.rs"), "fn real() {}");
        let root = open_root(&path)?;
        let metadata = confined_metadata(root, PathBuf::from("real.rs")).await?;
        assert!(metadata.is_file());
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_read_returns_file_bytes() -> CorulixResult<()> {
        let path = temp_workspace();
        let _ = fs::write(path.join("real.rs"), "fn real() {}");
        let root = open_root(&path)?;
        let bytes = confined_read(root, PathBuf::from("real.rs"), 4096).await?;
        assert_eq!(bytes, b"fn real() {}");
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_read_rejects_oversized_file() -> CorulixResult<()> {
        let path = temp_workspace();
        let _ = fs::write(path.join("big.rs"), vec![b'a'; 100]);
        let root = open_root(&path)?;
        assert!(matches!(
            confined_read(root, PathBuf::from("big.rs"), 10).await,
            Err(CorulixError::FileTooLarge)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_read_rejects_directory_target() -> CorulixResult<()> {
        let path = temp_workspace();
        let _ = fs::create_dir_all(path.join("subdir"));
        let root = open_root(&path)?;
        assert!(matches!(
            confined_read(root, PathBuf::from("subdir"), 4096).await,
            Err(CorulixError::InvalidInput(_))
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_read_rejects_traversal() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            confined_read(root, PathBuf::from("../outside.rs"), 4096).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_walk_finds_nested_files() -> CorulixResult<()> {
        let path = temp_workspace();
        let _ = fs::create_dir_all(path.join("a/b"));
        let _ = fs::write(path.join("a/b/one.rs"), "");
        let _ = fs::write(path.join("top.rs"), "");
        let root = open_root(&path)?;
        let results = confined_walk(root, PathBuf::from("."), WalkLimits::default()).await?;
        assert_eq!(results.len(), 2);
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn confined_walk_never_follows_symlinks() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let outside = temp_workspace();
        let _ = fs::write(outside.join("secret.rs"), "");
        let _ = symlink(&outside, path.join("escape_dir"));
        let _ = fs::write(path.join("real.rs"), "");
        let root = open_root(&path)?;
        let results = confined_walk(root, PathBuf::from("."), WalkLimits::default()).await?;
        // Only the real file is found; the symlinked directory is never
        // descended into, so `secret.rs` (which lives entirely outside the
        // workspace root) can never appear in the results.
        assert_eq!(results.len(), 1);
        assert!(results[0].as_path().ends_with("real.rs"));
        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn confined_walk_respects_max_entries() -> CorulixResult<()> {
        let path = temp_workspace();
        for i in 0..5 {
            let _ = fs::write(path.join(format!("f{i}.rs")), "");
        }
        let root = open_root(&path)?;
        let limits = WalkLimits {
            max_depth: DEFAULT_MAX_WALK_DEPTH,
            max_entries: 3,
        };
        assert!(matches!(
            confined_walk(root, PathBuf::from("."), limits).await,
            Err(CorulixError::ResourceLimit)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_walk_respects_max_depth() -> CorulixResult<()> {
        let path = temp_workspace();
        let nested = path.join("a/b/c/d");
        let _ = fs::create_dir_all(&nested);
        let _ = fs::write(nested.join("deep.rs"), "");
        let root = open_root(&path)?;
        let limits = WalkLimits {
            max_depth: 1,
            max_entries: DEFAULT_MAX_WALK_ENTRIES,
        };
        assert!(matches!(
            confined_walk(root, PathBuf::from("."), limits).await,
            Err(CorulixError::ResourceLimit)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_walk_scope_itself_is_confined() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            confined_walk(root, PathBuf::from("../escape"), WalkLimits::default()).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    /// Proves the blocking-safe composition core behaves identically to the
    /// canonical async entry point -- both must agree, since the async
    /// wrapper does nothing but move the exact same call onto Tokio's
    /// blocking-task pool.
    #[tokio::test]
    async fn blocking_core_and_async_entry_point_agree() -> CorulixResult<()> {
        let path = temp_workspace();
        let _ = fs::write(path.join("real.rs"), "fn real() {}");
        let root = open_root(&path)?;

        let via_blocking = confined_read_blocking(&root, Path::new("real.rs"), 4096)?;
        let via_async = confined_read(root, PathBuf::from("real.rs"), 4096).await?;
        assert_eq!(via_blocking, via_async);

        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_read_and_process_runs_process_on_the_read_bytes() -> CorulixResult<()> {
        let path = temp_workspace();
        let _ = fs::write(path.join("real.rs"), "fn real() {}");
        let root = open_root(&path)?;
        let byte_len =
            confined_read_and_process(root, PathBuf::from("real.rs"), 4096, |bytes| bytes.len())
                .await?;
        assert_eq!(byte_len, "fn real() {}".len());
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confined_read_and_process_propagates_read_side_errors_without_calling_process()
    -> CorulixResult<()> {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let path = temp_workspace();
        let _ = fs::write(path.join("big.rs"), vec![b'a'; 100]);
        let root = open_root(&path)?;
        let process_ran = Arc::new(AtomicBool::new(false));
        let process_ran_handle = Arc::clone(&process_ran);
        let result = confined_read_and_process(root, PathBuf::from("big.rs"), 10, move |_bytes| {
            process_ran_handle.store(true, Ordering::SeqCst);
        })
        .await;
        assert!(matches!(result, Err(CorulixError::FileTooLarge)));
        assert!(
            !process_ran.load(Ordering::SeqCst),
            "process must never run when the read itself fails closed"
        );
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn canonicalize_external_path_rejects_relative_input() {
        assert!(matches!(
            canonicalize_external_path(PathBuf::from("relative/provider")).await,
            Err(CorulixError::PathDenied)
        ));
    }

    #[tokio::test]
    async fn canonicalize_external_path_rejects_missing_target() {
        let path = temp_workspace();
        assert!(matches!(
            canonicalize_external_path(path.join("does-not-exist-provider")).await,
            Err(CorulixError::PathDenied)
        ));
    }

    #[tokio::test]
    async fn canonicalize_external_path_reports_regular_file() -> CorulixResult<()> {
        let path = temp_workspace();
        let file = path.join("provider-binary");
        let _ = fs::write(&file, "binary");
        let (canonical, is_file) = canonicalize_external_path(file.clone()).await?;
        assert!(is_file);
        assert_eq!(
            canonical,
            fs::canonicalize(&file).map_err(|_| CorulixError::PathDenied)?
        );
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn canonicalize_external_path_reports_directory_as_not_file() -> CorulixResult<()> {
        let path = temp_workspace();
        let (_, is_file) = canonicalize_external_path(path.clone()).await?;
        assert!(!is_file);
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confine_target_accepts_a_nonexistent_leaf_in_an_existing_directory()
    -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        let target = confine_target(root, PathBuf::from("does-not-exist-yet.rs")).await?;
        assert_eq!(
            target,
            fs::canonicalize(&path)
                .map_err(|_| CorulixError::PathDenied)?
                .join("does-not-exist-yet.rs")
        );
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confine_target_accepts_a_nonexistent_leaf_in_a_nested_existing_directory()
    -> CorulixResult<()> {
        let path = temp_workspace();
        let _ = fs::create_dir_all(path.join("a/b"));
        let root = open_root(&path)?;
        let target = confine_target(root, PathBuf::from("a/b/new.rs")).await?;
        assert!(target.ends_with("a/b/new.rs"));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confine_target_rejects_traversal() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            confine_target(root, PathBuf::from("../escape.rs")).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confine_target_rejects_absolute_path() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            confine_target(root, PathBuf::from("/etc/passwd")).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn confine_target_rejects_nonexistent_parent_directory() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(matches!(
            confine_target(root, PathBuf::from("no/such/dir/new.rs")).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn confine_target_rejects_parent_directory_symlink_escape() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let outside = temp_workspace();
        let link = path.join("escape_dir");
        let _ = symlink(&outside, &link);
        let root = open_root(&path)?;
        assert!(matches!(
            confine_target(root, PathBuf::from("escape_dir/new.rs")).await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    // -----------------------------------------------------------------
    // M09 Section 20 investigation (read-side TOCTOU). NOT a fix -- this
    // module's own doc comment already discloses the residual this proves
    // reachable: `resolve_confined_blocking` returns an already-resolved
    // `ConfinedPath`, and any *separate* I/O a caller performs against it
    // afterward re-walks the pathname at that later moment, honoring
    // whatever the filesystem looks like then, not what it looked like at
    // the confinement check. This test performs the swap deterministically
    // (no timing/race needed: the check and the later I/O are two
    // sequential statements under the test's own control) between the
    // check and a simulated caller read, exactly reproducing the
    // documented shape. Kept permanently as evidence, per the owner's
    // M09 remediation mandate Section 20 -- investigate only, do not fix.
    #[cfg(unix)]
    #[tokio::test]
    async fn m09_section20_read_toctou_ancestor_swap_after_check_is_reproduced() -> CorulixResult<()>
    {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let outside = temp_workspace();
        fs::write(path.join("real.rs"), b"REAL WORKSPACE CONTENT")
            .map_err(|_| CorulixError::Internal)?;
        fs::write(outside.join("real.rs"), b"IMPOSTOR CONTENT FROM OUTSIDE")
            .map_err(|_| CorulixError::Internal)?;

        let root = open_root(&path)?;
        // Step 1: the confinement check, exactly as any real caller
        // performs it -- proves `real.rs` resolves inside the workspace.
        let confined = resolve_confined_blocking(&root, Path::new("real.rs"))?;
        let initial_read = fs::read(confined.as_path()).map_err(|_| CorulixError::Internal)?;
        assert_eq!(initial_read, b"REAL WORKSPACE CONTENT");

        // Step 2: an attacker (who can write inside the workspace, the same
        // threat-model precondition the write-side TOCTOU already assumes)
        // replaces the workspace root itself with a symlink to an outside
        // directory containing a same-named file. This does not touch
        // `confined`'s own already-resolved `PathBuf` bytes at all.
        fs::remove_dir_all(&path).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &path).map_err(|_| CorulixError::Internal)?;

        // Step 3: the caller's later I/O against the SAME already-checked
        // `ConfinedPath` -- this is not a second confinement check, it is
        // exactly what a real caller (e.g. a second read, or any caller
        // that holds the resolved path across an await point) would do.
        let later_read = fs::read(confined.as_path());
        let escaped =
            later_read.as_deref().ok() == Some(b"IMPOSTOR CONTENT FROM OUTSIDE".as_slice());
        assert!(
            escaped,
            "this test documents a REAL, reproduced read-side TOCTOU (investigation only, \
             not a regression gate -- see M09 Section 20)"
        );

        let _ = fs::remove_file(&path).or_else(|_| fs::remove_dir_all(&path));
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    // -----------------------------------------------------------------
    // M09 remediation P1: WorkspaceRoot pinned object identity. Permanent
    // regression evidence for the frozen P1 contract (architecture-freeze
    // pass + this implementation pass). Unix-only, matching P1's scope --
    // Windows authority is P9's.
    // -----------------------------------------------------------------

    #[cfg(unix)]
    fn identity_of(root: &WorkspaceRoot) -> WorkspaceRootIdentity {
        root.identity
    }

    #[cfg(unix)]
    fn fstat_identity(root: &WorkspaceRoot) -> CorulixResult<WorkspaceRootIdentity> {
        let stat = rustix::fs::fstat(root.root_fd()).map_err(|_| CorulixError::Internal)?;
        Ok(WorkspaceRootIdentity::from_stat(&stat))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p1_normal_open() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;

        let canonical = fs::canonicalize(&path).map_err(|_| CorulixError::WorkspaceNotFound)?;
        assert_eq!(root.canonical_path(), canonical);

        // The fd genuinely points to a directory: `open(..., O_DIRECTORY,
        // ...)` itself would have failed (ENOTDIR) had it not, and the
        // identity-match requirement in `open_pinned_unix` ties that same
        // fd to the exact object `canonical_path()` names.
        let metadata =
            fs::metadata(root.canonical_path()).map_err(|_| CorulixError::WorkspaceNotFound)?;
        assert!(metadata.is_dir());

        // fstat identity equals stored identity.
        assert_eq!(fstat_identity(&root)?, identity_of(&root));

        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p1_clone_after_root_replacement() -> CorulixResult<()> {
        let path = temp_workspace();
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-moved-{}",
            std::process::id()
        ));
        let root = open_root(&path)?;
        let clone = root.clone();
        let original_identity = identity_of(&root);

        // Rename the original workspace directory away, then create a
        // brand-new, unrelated directory at the identical old pathname --
        // a fresh, unpinned re-open at this pathname would authorize the
        // REPLACEMENT (per the already-reconciled M09 evidence); this test
        // proves the ALREADY-OPEN `root`/`clone` do not.
        let _ = fs::rename(&path, &moved_away);
        let _ = fs::create_dir_all(&path);

        // Neither the original nor the clone reopened the pathname: both
        // still report the ORIGINAL fstat identity, not the replacement's.
        let replacement_metadata =
            fs::symlink_metadata(&path).map_err(|_| CorulixError::Internal)?;
        let replacement_identity = WorkspaceRootIdentity::from_metadata(&replacement_metadata);
        assert_ne!(original_identity, replacement_identity);
        assert_eq!(identity_of(&root), original_identity);
        assert_eq!(identity_of(&clone), original_identity);
        assert_eq!(fstat_identity(&root)?, original_identity);
        assert_eq!(fstat_identity(&clone)?, original_identity);

        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&moved_away);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p1_root_equality() -> CorulixResult<()> {
        // A: open the same, unchanged root twice -- equal (same canonical
        // path AND same underlying object identity).
        let path_a = temp_workspace();
        let a1 = open_root(&path_a)?;
        let a2 = open_root(&path_a)?;
        assert_eq!(a1, a2);

        // B: a clone -- equal (same `Arc`-shared fd, same identity).
        let clone = a1.clone();
        assert_eq!(a1, clone);

        // C: open root A, rename it away, create a new directory at the
        // identical pathname, open B against that same pathname -- NOT
        // equal, because the identity differs even though the canonical
        // path string is identical.
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-moved-c-{}",
            std::process::id()
        ));
        let _ = fs::rename(&path_a, &moved_away);
        let _ = fs::create_dir_all(&path_a);
        let b = open_root(&path_a)?;
        assert_ne!(a1, b);
        assert_eq!(a1.canonical_path(), b.canonical_path());

        let _ = fs::remove_dir_all(&path_a);
        let _ = fs::remove_dir_all(&moved_away);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p1_normal_directory_substitution_during_open() -> CorulixResult<()> {
        let path = temp_workspace();
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-race-a-{}",
            std::process::id()
        ));

        // Deterministic construction-race seam: fires exactly between
        // `open_pinned_unix`'s pre-open identity capture and its own
        // `open()` call. Substitutes an ordinary, unrelated directory at
        // the identical pathname.
        let moved_away_for_hook = moved_away.clone();
        CONSTRUCTION_RACE_HOOK.with(|cell| {
            *cell.borrow_mut() = Some(Box::new(move |canonical: &Path| {
                let _ = fs::rename(canonical, &moved_away_for_hook);
                let _ = fs::create_dir_all(canonical);
            }));
        });

        let result = WorkspaceRoot::open(&path);
        CONSTRUCTION_RACE_HOOK.with(|cell| *cell.borrow_mut() = None);

        assert!(
            matches!(result, Err(CorulixError::WorkspaceNotFound)),
            "an ordinary-directory substitution during open must fail closed via the \
             identity-match requirement, not silently pin the replacement"
        );

        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&moved_away);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p1_symlink_substitution_during_open() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-race-b-{}",
            std::process::id()
        ));
        let outside = temp_workspace();

        let moved_away_for_hook = moved_away.clone();
        let outside_for_hook = outside.clone();
        CONSTRUCTION_RACE_HOOK.with(|cell| {
            *cell.borrow_mut() = Some(Box::new(move |canonical: &Path| {
                let _ = fs::rename(canonical, &moved_away_for_hook);
                let _ = symlink(&outside_for_hook, canonical);
            }));
        });

        let result = WorkspaceRoot::open(&path);
        CONSTRUCTION_RACE_HOOK.with(|cell| *cell.borrow_mut() = None);

        assert!(
            matches!(result, Err(CorulixError::WorkspaceNotFound)),
            "O_NOFOLLOW must reject a symlink substituted during open, before identity is \
             even compared"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&moved_away);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p1_pinned_root_survives_path_replacement() -> CorulixResult<()> {
        let path = temp_workspace();
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-survive-{}",
            std::process::id()
        ));
        let root = open_root(&path)?;
        let original_identity = identity_of(&root);

        let _ = fs::rename(&path, &moved_away);
        let _ = fs::create_dir_all(&path);

        // fstat/object identity only -- no P2 path-resolution function
        // used here, per this test's own requirement.
        assert_eq!(fstat_identity(&root)?, original_identity);

        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&moved_away);
        Ok(())
    }

    // -----------------------------------------------------------------
    // M09-P8: `WorkspaceRoot::verify_current_path_identity` regression
    // evidence. Unlike `m09_p1_pinned_root_survives_path_replacement`
    // above (which proves the pinned FD-based authority is immune to a
    // pathname swap), these prove the COMPLEMENTARY pathname-facing check
    // this method provides: it must DETECT the exact same swap shapes,
    // for a long-lived consumer (`wht_corulix_lsp::LspSession`) that has
    // to re-verify identity at points where no new process is being
    // spawned (so `bind_process_cwd`'s fd-binding does not itself apply).
    // -----------------------------------------------------------------

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p8_verify_current_path_identity_passes_on_unmodified_root() -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(root.verify_current_path_identity());
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p8_verify_current_path_identity_detects_normal_directory_replacement()
    -> CorulixResult<()> {
        let path = temp_workspace();
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-p8-normal-swap-{}",
            std::process::id()
        ));
        let root = open_root(&path)?;
        assert!(root.verify_current_path_identity());

        // An ordinary-directory replacement at the identical pathname: the
        // original object is moved aside (still open, still pinned by
        // `root`'s own fd) and a brand new, empty directory is created at
        // the same canonical path.
        fs::rename(&path, &moved_away).map_err(|_| CorulixError::Internal)?;
        fs::create_dir_all(&path).map_err(|_| CorulixError::Internal)?;

        assert!(
            !root.verify_current_path_identity(),
            "an ordinary-directory replacement at the pinned pathname must be detected"
        );

        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&moved_away);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p8_verify_current_path_identity_detects_symlink_replacement() -> CorulixResult<()>
    {
        use std::os::unix::fs::symlink;

        let path = temp_workspace();
        let outside = temp_workspace();
        let root = open_root(&path)?;
        assert!(root.verify_current_path_identity());

        // Replacement by a symlink to an entirely unrelated directory --
        // `fs::metadata` (unlike `fs::symlink_metadata`) follows this
        // straight through to `outside`'s own identity, which still
        // mismatches the pinned one.
        fs::remove_dir_all(&path).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &path).map_err(|_| CorulixError::Internal)?;

        assert!(
            !root.verify_current_path_identity(),
            "a symlink replacement at the pinned pathname must be detected"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p8_verify_current_path_identity_detects_ancestor_replacement() -> CorulixResult<()>
    {
        let parent = temp_workspace();
        let child = parent.join("workspace_root");
        fs::create_dir_all(&child).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&child)?;
        assert!(root.verify_current_path_identity());

        // The root's own leaf directory entry is never touched -- its
        // ANCESTOR is replaced wholesale (moved aside, a fresh ancestor
        // recreated with an identically-named but entirely new child
        // directory inside it). `root.canonical_path()` (`parent/workspace_root`)
        // is unchanged as a string, yet now resolves to a different real
        // object.
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-p8-ancestor-swap-{}",
            std::process::id()
        ));
        fs::rename(&parent, &moved_away).map_err(|_| CorulixError::Internal)?;
        fs::create_dir_all(&child).map_err(|_| CorulixError::Internal)?;

        assert!(
            !root.verify_current_path_identity(),
            "an ancestor-directory replacement must be detected even though the root's own leaf \
             pathname component was recreated identically"
        );

        let _ = fs::remove_dir_all(&parent);
        let _ = fs::remove_dir_all(&moved_away);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p8_verify_current_path_identity_passes_again_after_aba_restore()
    -> CorulixResult<()> {
        let path = temp_workspace();
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-p8-aba-{}",
            std::process::id()
        ));
        let root = open_root(&path)?;
        assert!(root.verify_current_path_identity());

        fs::rename(&path, &moved_away).map_err(|_| CorulixError::Internal)?;
        fs::create_dir_all(&path).map_err(|_| CorulixError::Internal)?;
        assert!(!root.verify_current_path_identity());

        // ABA: remove the impostor and restore the ORIGINAL object at the
        // original pathname. `verify_current_path_identity` itself is
        // stateless per call and correctly reports a match again -- the
        // sticky "never trust this session again" semantics belong to
        // `wht_corulix_lsp::LspSession`'s own one-way `invalidated` latch,
        // a deliberately separate layer this method does not itself
        // implement.
        fs::remove_dir_all(&path).map_err(|_| CorulixError::Internal)?;
        fs::rename(&moved_away, &path).map_err(|_| CorulixError::Internal)?;

        assert!(
            root.verify_current_path_identity(),
            "restoring the exact original object at the original pathname must match again"
        );

        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p8_verify_current_path_identity_fails_closed_when_pathname_removed()
    -> CorulixResult<()> {
        let path = temp_workspace();
        let root = open_root(&path)?;
        assert!(root.verify_current_path_identity());

        fs::remove_dir_all(&path).map_err(|_| CorulixError::Internal)?;

        assert!(
            !root.verify_current_path_identity(),
            "a missing pathname must report false, never panic"
        );
        Ok(())
    }

    /// Section 10 compatibility check: a caller-supplied workspace path
    /// that is ITSELF a symlink to a legitimate directory must continue to
    /// be accepted -- `fs::canonicalize` (in `WorkspaceRoot::open`, before
    /// P1's secure-open sequence even begins) resolves the caller's own
    /// alias to its real target first; P1's `O_NOFOLLOW` applies only to
    /// the already-resolved canonical path used for the authority open,
    /// never to the original alias string.
    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p1_caller_supplied_symlink_alias_is_preserved() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let real_dir = temp_workspace();
        let alias = std::env::temp_dir().join(format!(
            "corulix-workspace-test-alias-{}",
            std::process::id()
        ));
        let _ = symlink(&real_dir, &alias);

        let root = WorkspaceRoot::open(&alias)?;
        let expected = fs::canonicalize(&real_dir).map_err(|_| CorulixError::WorkspaceNotFound)?;
        assert_eq!(root.canonical_path(), expected);

        let _ = fs::remove_file(&alias);
        let _ = fs::remove_dir_all(&real_dir);
        Ok(())
    }

    // -----------------------------------------------------------------
    // M09 remediation P4: direct read authority migration. Permanent
    // regression evidence proving the migrated, capability-backed
    // `confined_read`/`confined_metadata` close the historical read
    // escapes (Cases A/B from the prior investigation pass) while
    // preserving every existing public-facing behavior. Unix-only,
    // matching P4's scope -- Windows keeps its pre-P4, explicitly
    // unmigrated implementation (P9's job).
    // -----------------------------------------------------------------

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p4_root_replaced_by_normal_directory_read_escape_closed() -> CorulixResult<()> {
        let root_path = temp_workspace();
        fs::write(root_path.join("target.rs"), b"ORIGINAL").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        // Historical Case A: rename the original root away, put an
        // ordinary NEW directory at the identical old pathname, with a
        // same-named file containing a unique outside marker.
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-p4-case-a-moved-{}",
            std::process::id()
        ));
        fs::rename(&root_path, &moved_away).map_err(|_| CorulixError::Internal)?;
        fs::create_dir_all(&root_path).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("target.rs"), b"IMPOSTOR REPLACEMENT CONTENT")
            .map_err(|_| CorulixError::Internal)?;

        let result = confined_read(root, PathBuf::from("target.rs"), 4096).await;
        let escaped = matches!(&result, Ok(bytes) if bytes == b"IMPOSTOR REPLACEMENT CONTENT");
        assert!(
            !escaped,
            "migrated confined_read must never return the replacement root's bytes"
        );
        // Either reading the ORIGINAL pinned object or failing closed is
        // acceptable -- both are safe; only the replacement's bytes are
        // forbidden.
        if let Ok(bytes) = &result {
            assert_eq!(bytes, b"ORIGINAL");
        }

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&moved_away);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p4_root_replaced_by_outside_symlink_read_denied() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let root_path = temp_workspace();
        fs::write(root_path.join("target.rs"), b"ORIGINAL").map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let outside = temp_workspace();
        fs::write(outside.join("target.rs"), b"OUTSIDE SYMLINK CONTENT")
            .map_err(|_| CorulixError::Internal)?;

        let moved_away = std::env::temp_dir().join(format!(
            "corulix-workspace-test-p4-case-b-moved-{}",
            std::process::id()
        ));
        fs::rename(&root_path, &moved_away).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &root_path).map_err(|_| CorulixError::Internal)?;

        let result = confined_read(root, PathBuf::from("target.rs"), 4096).await;
        let escaped = matches!(&result, Ok(bytes) if bytes == b"OUTSIDE SYMLINK CONTENT");
        assert!(
            !escaped,
            "outside symlink root replacement must never be read"
        );

        let _ = fs::remove_file(&root_path);
        let _ = fs::remove_dir_all(&moved_away);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p4_parent_swap_before_final_open_read_escape_closed() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let root_path = temp_workspace();
        fs::create_dir_all(root_path.join("a/b")).map_err(|_| CorulixError::Internal)?;
        fs::write(root_path.join("a/b/file.rs"), b"ORIGINAL")
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        // Resolve the parent chain up through P2/P3 by racing the swap in
        // BETWEEN capability resolution and the actual read -- since P4's
        // migration resolves and opens within one `spawn_blocking` call,
        // simulate the "swap after parent pinned" scenario the same way
        // the capability-level tests already proved it structurally: swap
        // `a/b`'s own pathname for an outside symlink before ever calling
        // `confined_read` at all (the read must still only ever succeed
        // against the true object, if it succeeds at all).
        let ab_path = root_path.join("a/b");
        let outside = temp_workspace();
        fs::write(outside.join("file.rs"), b"OUTSIDE").map_err(|_| CorulixError::Internal)?;
        let ab_moved = std::env::temp_dir().join(format!(
            "corulix-workspace-test-p4-parent-swap-moved-{}",
            std::process::id()
        ));
        fs::rename(&ab_path, &ab_moved).map_err(|_| CorulixError::Internal)?;
        symlink(&outside, &ab_path).map_err(|_| CorulixError::Internal)?;

        let result = confined_read(root, PathBuf::from("a/b/file.rs"), 4096).await;
        let escaped = matches!(&result, Ok(bytes) if bytes == b"OUTSIDE");
        assert!(
            !escaped,
            "a swapped parent must never redirect the read outside"
        );

        let _ = fs::remove_file(&ab_path);
        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&ab_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p4_live_relative_internal_final_symlink_read() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let root_path = temp_workspace();
        fs::write(root_path.join("real.rs"), b"REAL CONTENT")
            .map_err(|_| CorulixError::Internal)?;
        symlink("real.rs", root_path.join("link.rs")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let bytes = confined_read(root, PathBuf::from("link.rs"), 4096).await?;
        assert_eq!(bytes, b"REAL CONTENT");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p4_live_absolute_internal_final_symlink_read() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let root_path = temp_workspace();
        fs::write(root_path.join("real.rs"), b"REAL CONTENT")
            .map_err(|_| CorulixError::Internal)?;
        let canonical = fs::canonicalize(&root_path).map_err(|_| CorulixError::Internal)?;
        symlink(canonical.join("real.rs"), root_path.join("link.rs"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let bytes = confined_read(root, PathBuf::from("link.rs"), 4096).await?;
        assert_eq!(bytes, b"REAL CONTENT");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p4_live_chain_internal_final_symlink_read() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let root_path = temp_workspace();
        fs::write(root_path.join("real.rs"), b"REAL CONTENT")
            .map_err(|_| CorulixError::Internal)?;
        symlink("real.rs", root_path.join("b.rs")).map_err(|_| CorulixError::Internal)?;
        symlink("b.rs", root_path.join("a.rs")).map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let bytes = confined_read(root, PathBuf::from("a.rs"), 4096).await?;
        assert_eq!(bytes, b"REAL CONTENT");

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p4_live_outside_final_symlink_denied() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let root_path = temp_workspace();
        let outside = temp_workspace();
        fs::write(outside.join("secret.rs"), b"OUTSIDE SECRET")
            .map_err(|_| CorulixError::Internal)?;
        symlink(outside.join("secret.rs"), root_path.join("link.rs"))
            .map_err(|_| CorulixError::Internal)?;
        let root = open_root(&root_path)?;

        let result = confined_read(root, PathBuf::from("link.rs"), 4096).await;
        assert!(matches!(result, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[tokio::test]
    async fn m09_p4_special_file_fifo_rejected_without_hanging() -> CorulixResult<()> {
        let root_path = temp_workspace();
        let root = open_root(&root_path)?;
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root_path.join("pipe.fifo"),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|_| CorulixError::Internal)?;

        // The critical property under test is that this call RETURNS at
        // all (a FIFO with no writer would hang a plain blocking
        // `O_RDONLY` open forever) -- `tokio::time::timeout` turns a
        // regression into a failed assertion instead of a hung test
        // process.
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            confined_read(root, PathBuf::from("pipe.fifo"), 4096),
        )
        .await;
        let result = outcome.map_err(|_| CorulixError::Internal)?;
        assert!(
            matches!(result, Err(CorulixError::InvalidInput(_))),
            "a FIFO must be rejected as not-a-regular-file, never hang, never be read"
        );

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn m09_p4_repeated_read_fd_leak() -> CorulixResult<()> {
        // M09-P6 corrective closure (mirroring the same fix already applied
        // to `wht_corulix_process_unix`'s own fd-leak test): a raw
        // process-global `/proc/self/fd` COUNT is not isolated from
        // whatever unrelated fds this file's other 56 sibling `#[test]`/
        // `#[tokio::test]` functions -- none of them serialized against
        // this one -- happen to have open at the same instant, since
        // Rust's default test harness runs them concurrently on separate
        // threads within this SAME process. A real, reproduced failure
        // (`fd count grew from 47 to 80`, a delta of 33 against an `+8`
        // tolerance) could never be explained by a real per-call leak in
        // `confined_read`/`open_root` -- 10 isolated reruns and repeated
        // full-suite reruns of this exact test never once failed -- but is
        // fully consistent with concurrent sibling tests transiently
        // opening/closing dozens of files at that moment. This version
        // instead identifies the SPECIFIC filesystem objects this test's
        // own operations touch (the repeatedly-read file and the pinned
        // workspace root directory) by `(device, inode)`, and asserts zero
        // of this process's open fds point at either one after the loop --
        // a check immune to how many unrelated fds sibling tests hold.
        let root_path = temp_workspace();
        let target_path = root_path.join("file.rs");
        fs::write(&target_path, b"content").map_err(|_| CorulixError::Internal)?;

        fn identity_of(path: &Path) -> CorulixResult<(u64, u64)> {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = std::fs::metadata(path).map_err(|_| CorulixError::Internal)?;
            Ok((metadata.dev(), metadata.ino()))
        }

        fn open_fd_count_pointing_at(targets: &[(u64, u64)]) -> usize {
            use std::os::unix::fs::MetadataExt as _;
            let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
                return 0;
            };
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    std::fs::metadata(entry.path())
                        .map(|metadata| targets.contains(&(metadata.dev(), metadata.ino())))
                        .unwrap_or(false)
                })
                .count()
        }

        let target_identity = identity_of(&target_path)?;
        let root_identity = identity_of(&root_path)?;
        let targets = [target_identity, root_identity];

        for _ in 0..200 {
            let root = open_root(&root_path)?;
            let bytes = confined_read(root, PathBuf::from("file.rs"), 4096).await?;
            assert_eq!(bytes, b"content");
        }

        let leaked = open_fd_count_pointing_at(&targets);
        assert_eq!(
            leaked, 0,
            "{leaked} fd(s) still point at the repeatedly-read file or its pinned workspace \
             root after 200 confined_read calls -- possible leak"
        );

        let _ = fs::remove_dir_all(&root_path);
        Ok(())
    }
}
