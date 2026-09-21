// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![deny(unsafe_code)]

//! Narrow, audited Win32 FFI boundary for closing the Windows
//! spawn-then-assign Job Object containment race (P17-W-R2,
//! `WINDOWS_JOB_OBJECT_SPAWN_ASSIGN_RACE`).
//!
//! # Why this crate exists (`WINDOWS_FFI_SAFETY_BOUNDARY_DECISION`)
//!
//! Every crate in this workspace inherits a crate-root inner attribute
//! applying rustc's `forbid(unsafe_code)` lint level (both as that explicit
//! inner attribute and via `[workspace.lints.rust] unsafe_code = "forbid"`,
//! reproduced per-crate through `[lints] workspace = true`). Rust's
//! `forbid` lint level cannot be locally overridden by an inner attribute
//! applying `allow(unsafe_code)` (`E0453`) -- that is the entire semantic
//! difference between `forbid` and `deny`. `wht_corulix_tooling`, the sole
//! owner of process construction (Architecture Rule G), is one such
//! `forbid` crate, so there is no module-level carve-out possible *inside*
//! it. Closing the real spawn-then-assign race requires calling raw Win32
//! APIs (`CreateToolhelp32Snapshot`/`Thread32First`/`Thread32Next`/
//! `OpenThread`/`ResumeThread`/`TerminateProcess`, and, as of P17-W-R3-C3's
//! `WINDOWS_PROCESS_LIVENESS_PROBE_GAP` closure, `OpenProcess`/
//! `WaitForSingleObject`) that `windows-sys` exposes only as `unsafe fn`s,
//! so this crate exists as the one
//! deliberate, documented, narrowly-scoped exception: it defines its own
//! `[lints]` table (see `Cargo.toml`) with `unsafe_code = "deny"` rather
//! than inheriting the workspace `forbid`, and grants exactly one inner
//! attribute applying `allow(unsafe_code)` to exactly one submodule
//! (`ffi`, `#[cfg(windows)]`-gated and private, so it is intentionally
//! never a resolvable rustdoc link on any platform/target this doc build
//! runs on). Every other crate in the workspace, `wht_corulix_tooling`
//! included, keeps `forbid` byte-for-byte unchanged --
//! `UNSAFE_ALLOWED_IN_GENERAL_PRODUCT_CODE=NO`.
//!
//! # Public contract
//!
//! All three functions this crate exposes operate on a process/thread that
//! **already exists** (identified by pid or by an already-open, borrowed
//! process handle) -- this crate never itself constructs a process or a
//! `Command` of any kind (`std::process::Command`,
//! `tokio::process::Command`), so it does not encroach on
//! `wht_corulix_tooling`'s Architecture Rule G authority. It only:
//!
//! Every item named below is `#[cfg(windows)]`-gated (see `# Why this
//! crate exists` above) and therefore out of scope for any doc build not
//! itself targeting Windows -- referenced here by plain code-formatted
//! name, never as an intra-doc link, since a link that only resolves on
//! one target platform is never a link this documentation can promise to
//! keep valid everywhere it is built.
//!
//!   * `resume_primary_thread` -- resumes the single primary thread of a
//!     process that was spawned `CREATE_SUSPENDED` (the caller's
//!     responsibility to have arranged), so `wht_corulix_tooling`'s
//!     `platform::windows` module can defer this call until *after* the
//!     process has already been assigned to a kill-on-close Job Object.
//!   * `terminate_process` -- terminates a process by an
//!     already-open, caller-owned process `HANDLE` (never opening or
//!     closing that handle itself), for the fail-closed path where Job
//!     Object creation/configuration/assignment failed and the still-
//!     suspended child must never be allowed to run uncontained.
//!   * `query_process_liveness` (P17-W-R3-C3,
//!     `WINDOWS_PROCESS_LIVENESS_PROBE_GAP`) -- opens a process **by pid**
//!     (never a caller-supplied handle) with the minimal
//!     `PROCESS_QUERY_LIMITED_INFORMATION` access right and reports
//!     `ProcessLiveness::Present`/`ProcessLiveness::Absent` via
//!     `WaitForSingleObject(handle, 0)` signaling state, or
//!     `ProcessLiveness::Uncertain` when the query itself could not be
//!     answered. This is deliberately **not** `GetExitCodeProcess`-based:
//!     `GetExitCodeProcess` reports a still-running process's exit code as
//!     `STILL_ACTIVE` (`259`), a plain integer indistinguishable from a
//!     process that legitimately exited with status `259` -- an ambiguity
//!     `WaitForSingleObject`'s kernel-object-signal-state semantics do not
//!     share (a process handle becomes signaled exactly once, when the
//!     process terminates; there is no numeric collision to confuse with
//!     an exit code). See that function's own doc for the exact sentinel
//!     mapping used to fail closed on every other outcome.
//!
//! All three are total, `panic`-free, `unwrap`/`expect`-free (workspace
//! policy, reproduced in this crate's own `[lints]`), and return a typed
//! result rather than ever guessing a best-effort outcome.

#[cfg(windows)]
mod ffi {
    #![allow(unsafe_code)]
    // SAFETY (module-wide): every `unsafe` block below documents, at the
    // call site, exactly which of the raw pointer/handle/lifetime/
    // initialization invariants of the specific Win32 API it satisfies and
    // how. No `unsafe` in this module is bare/uncommented.

    use core::ffi::c_void;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenThread, PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread,
        THREAD_SUSPEND_RESUME, TerminateProcess, WaitForSingleObject,
    };

    // M09-P9: handle-relative filesystem-authority imports (see the new
    // section below, after `query_process_liveness`).
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation, NtCreateFile,
        NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::{NTSTATUS, OBJ_CASE_INSENSITIVE, UNICODE_STRING};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_RENAME_INFO, FILE_RENAME_INFO_0, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_DATA, FileDispositionInfoEx, FileIdInfo,
        GetFileInformationByHandle, GetFileInformationByHandleEx, OPEN_EXISTING,
        SetFileInformationByHandle,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    /// Why a Win32 process/thread-control call in this crate failed. Never
    /// collapsed into a free-form string -- every variant names the exact
    /// API call that failed and, where the OS supplies one, its raw
    /// `GetLastError()` code.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ProcessControlError {
        /// `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ..)` itself failed.
        SnapshotFailed { os_error: u32 },
        /// The snapshot was created but contains no thread entries at all
        /// (`Thread32First` reported none) -- structurally unexpected for
        /// any live process.
        ThreadEnumerationFailed { os_error: u32 },
        /// No thread in the snapshot is owned by the target pid. Since the
        /// target process was spawned `CREATE_SUSPENDED`, this means it
        /// has already exited (or the pid is stale) before this call ran.
        NoThreadOwnedByProcess,
        /// More than one thread in the snapshot is owned by the target
        /// pid. A process spawned `CREATE_SUSPENDED` has exactly one
        /// thread and -- being suspended -- cannot itself have created
        /// more before this call runs; seeing more than one here means the
        /// "still suspended, single thread" precondition this function
        /// requires does not actually hold, so this fails closed rather
        /// than guessing which thread is the real primary one.
        AmbiguousPrimaryThread { candidate_count: usize },
        /// `OpenThread(THREAD_SUSPEND_RESUME, ..)` failed for the
        /// (uniquely identified) primary thread id.
        OpenThreadFailed { os_error: u32 },
        /// `ResumeThread` itself returned its documented failure sentinel
        /// (`u32::MAX`).
        ResumeThreadFailed { os_error: u32 },
        /// `TerminateProcess` on the caller-supplied, caller-owned process
        /// handle failed.
        TerminateProcessFailed { os_error: u32 },
    }

    /// An owned Win32 `HANDLE` this crate itself opened (never a handle
    /// borrowed from a caller), closed exactly once, deterministically, on
    /// `Drop` -- including on an early `?`-return or panic unwind, since
    /// `Drop::drop` still runs during unwinding here (no `catch_unwind`,
    /// no `mem::forget`, no leaked/duplicated raw handle anywhere in this
    /// module).
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: `self.0` is constructed only by `OwnedHandle::new`
            // below, which itself only ever wraps a handle value already
            // confirmed to be neither `NULL` nor `INVALID_HANDLE_VALUE`
            // (the two possible Win32 failure sentinels across the APIs
            // this module calls). `OwnedHandle` is not `Clone`/`Copy` and
            // nothing in this module extracts and independently closes
            // `self.0` elsewhere, so this handle has exactly one owner;
            // `Drop::drop` runs at most once per value under Rust's
            // ownership model, so `CloseHandle` is called exactly once per
            // handle this module opens -- never double-closed, never
            // leaked on any return path (including `?`).
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    impl OwnedHandle {
        /// Wraps `handle`, or returns `None` if it is one of Win32's two
        /// failure sentinels (`invalid_is_negative_one` distinguishes
        /// `CreateToolhelp32Snapshot`'s `INVALID_HANDLE_VALUE` sentinel
        /// from `OpenThread`'s `NULL` sentinel -- the two APIs this module
        /// calls do not agree on which sentinel they use).
        fn new(handle: HANDLE, invalid_is_negative_one: bool) -> Option<Self> {
            let is_invalid = if invalid_is_negative_one {
                handle == INVALID_HANDLE_VALUE
            } else {
                handle.is_null()
            };
            if is_invalid { None } else { Some(Self(handle)) }
        }

        const fn as_handle(&self) -> HANDLE {
            self.0
        }
    }

    /// Real, current `GetLastError()` value, read immediately after the
    /// failing call this module always pairs it with -- never read late,
    /// never read speculatively, so no intervening call (including
    /// `CloseHandle` on an unrelated handle) can have overwritten it
    /// first.
    fn last_os_error() -> u32 {
        // SAFETY: `GetLastError` takes no arguments, returns a plain `u32`
        // by value, and has no preconditions beyond being called from a
        // thread with a valid TEB (true for any thread executing Rust
        // code on Windows) -- there is no pointer, lifetime, or ownership
        // invariant to uphold here.
        unsafe { windows_sys::Win32::Foundation::GetLastError() }
    }

    /// Enumerates every thread on the system (`TH32CS_SNAPTHREAD`) and
    /// returns the single thread id owned by `pid`, or a typed error if
    /// zero or more than one match is found (see
    /// [`ProcessControlError::AmbiguousPrimaryThread`]'s doc for why more
    /// than one is a hard error here, not a "pick the first" fallback).
    fn find_sole_owned_thread(pid: u32) -> Result<u32, ProcessControlError> {
        // SAFETY: `TH32CS_SNAPTHREAD` with `th32processid = 0` is the
        // documented way to snapshot every thread on the system (Win32
        // does not support filtering `CreateToolhelp32Snapshot` itself by
        // owning process for a thread-only snapshot); the call takes no
        // pointers besides its own return value, so there is no buffer/
        // lifetime concern at this call site. The returned handle is
        // checked against `INVALID_HANDLE_VALUE` before being trusted with
        // any further call.
        let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        let Some(snapshot) = OwnedHandle::new(raw_snapshot, true) else {
            return Err(ProcessControlError::SnapshotFailed {
                os_error: last_os_error(),
            });
        };

        // `THREADENTRY32::dwSize` must be initialized to
        // `size_of::<THREADENTRY32>()` *before* the first `Thread32First`
        // call -- this is Win32's documented in/out sizing protocol for
        // this struct, not a Rust-level requirement; the rest of the
        // struct's fields are populated by the API itself and are never
        // read before that populate call succeeds.
        #[allow(clippy::cast_possible_truncation)]
        let mut entry = THREADENTRY32 {
            dwSize: core::mem::size_of::<THREADENTRY32>() as u32,
            ..THREADENTRY32::default()
        };

        // SAFETY: `snapshot.as_handle()` is a live handle just confirmed
        // valid above and is not closed until `snapshot` (this function's
        // local binding) is dropped at function end -- outliving every use
        // below. `&mut entry` is a valid, uniquely-borrowed, correctly-
        // sized (`dwSize` set above) `*mut THREADENTRY32` for the
        // documented lifetime of this single call.
        let mut has_entry = unsafe { Thread32First(snapshot.as_handle(), &raw mut entry) } != 0;
        if !has_entry {
            return Err(ProcessControlError::ThreadEnumerationFailed {
                os_error: last_os_error(),
            });
        }

        let mut matches: [Option<u32>; 2] = [None, None];
        let mut match_count = 0_usize;
        while has_entry {
            if entry.th32OwnerProcessID == pid {
                if match_count < matches.len() {
                    matches[match_count] = Some(entry.th32ThreadID);
                }
                match_count += 1;
            }
            // SAFETY: identical handle/pointer/lifetime justification as
            // the `Thread32First` call above -- `entry` is reused in place
            // for each successive call, exactly as this API's contract
            // requires (it neither reads nor requires `dwSize` to be reset
            // between successive `Thread32Next` calls).
            has_entry = unsafe { Thread32Next(snapshot.as_handle(), &raw mut entry) } != 0;
        }

        match match_count {
            0 => Err(ProcessControlError::NoThreadOwnedByProcess),
            1 => Ok(matches[0].unwrap_or_default()),
            candidate_count => Err(ProcessControlError::AmbiguousPrimaryThread { candidate_count }),
        }
        // `snapshot` drops here, closing the snapshot handle exactly once.
    }

    /// Resumes the sole thread owned by `pid`. See the crate-level docs
    /// and [`ProcessControlError::AmbiguousPrimaryThread`] for why this
    /// refuses to resume anything unless exactly one owned thread is
    /// found.
    pub fn resume_primary_thread(pid: u32) -> Result<(), ProcessControlError> {
        let thread_id = find_sole_owned_thread(pid)?;

        // SAFETY: `THREAD_SUSPEND_RESUME` is the minimal access right
        // `ResumeThread` documents as required; `dwthreadid` is the id
        // just uniquely identified above as the sole thread owned by
        // `pid`. The returned handle is checked against `NULL` (this
        // API's failure sentinel, distinct from
        // `CreateToolhelp32Snapshot`'s `INVALID_HANDLE_VALUE`) before
        // being trusted with any further call.
        let raw_thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) };
        let Some(thread) = OwnedHandle::new(raw_thread, false) else {
            return Err(ProcessControlError::OpenThreadFailed {
                os_error: last_os_error(),
            });
        };

        // SAFETY: `thread.as_handle()` is a live `THREAD_SUSPEND_RESUME`
        // handle just opened above, not yet closed (owned by `thread`,
        // which outlives this call). `ResumeThread` takes no other
        // pointer/buffer argument.
        let previous_suspend_count = unsafe { ResumeThread(thread.as_handle()) };
        if previous_suspend_count == u32::MAX {
            return Err(ProcessControlError::ResumeThreadFailed {
                os_error: last_os_error(),
            });
        }
        Ok(())
        // `thread` drops here, closing the thread handle exactly once.
    }

    /// Terminates the process identified by `process_handle`, a `HANDLE`
    /// **borrowed** from the caller (typically a still-suspended child's
    /// process handle the caller obtained from its own process-spawning
    /// API) -- this function never closes `process_handle` itself; that
    /// remains the caller's own handle to close (or to let its own process
    /// type, e.g. `tokio::process::Child`, close on reap/drop) exactly
    /// once, exactly as it already would have.
    ///
    /// # Safety contract upheld by the caller, not re-verified here
    ///
    /// `process_handle` must be a currently-valid, `PROCESS_TERMINATE`-
    /// capable Win32 process handle, not a value fabricated from an
    /// arbitrary integer. This is not a hypothetical caller: as of P17-W-R2
    /// this function has exactly one call site,
    /// `wht_corulix_tooling::platform::windows::contain`, which obtains
    /// `process_handle` from `tokio::process::Child::raw_handle()` on a
    /// `child` that has not yet been reaped (`raw_handle()` only ever
    /// returns `None` once reaping has already happened, and `contain` is
    /// always invoked immediately after a successful `spawn()`, before any
    /// reap). `child` is borrowed for `contain`'s entire body, so the
    /// handle remains valid for the whole duration of this call; `contain`
    /// never closes it either, leaving that to `child`'s own eventual
    /// reap/drop exactly as it already would without this function's
    /// involvement.
    pub fn terminate_process(
        process_handle: isize,
        exit_code: u32,
    ) -> Result<(), ProcessControlError> {
        // SAFETY: `process_handle` is a caller-supplied `HANDLE` this
        // function borrows only for the duration of this single call and
        // never closes (see the doc above) -- there is no ownership
        // transfer, no double-close, and no dangling-handle risk this
        // function itself introduces. `TerminateProcess` takes no other
        // pointer argument.
        let succeeded = unsafe { TerminateProcess(process_handle as *mut c_void, exit_code) } != 0;
        if succeeded {
            Ok(())
        } else {
            Err(ProcessControlError::TerminateProcessFailed {
                os_error: last_os_error(),
            })
        }
    }

    /// Outcome of [`query_process_liveness`]. See that function's doc, and
    /// the crate-level docs, for the exact Win32 sequence and sentinel
    /// mapping that produces each variant.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ProcessLiveness {
        /// The process identified by the queried pid still exists and has
        /// not terminated (`WaitForSingleObject(handle, 0) ==
        /// WAIT_TIMEOUT`).
        Present,
        /// The process no longer exists: either `OpenProcess` itself
        /// failed with `ERROR_INVALID_PARAMETER` (no process currently has
        /// this pid), or the handle opened successfully but is already
        /// signaled (`WaitForSingleObject(handle, 0) == WAIT_OBJECT_0`).
        Absent,
        /// The query itself could not be answered: `OpenProcess` failed
        /// for a reason other than "no such pid" (most commonly
        /// `ERROR_ACCESS_DENIED` -- a process owned by a different,
        /// unrelated principal), or `WaitForSingleObject` itself returned
        /// `WAIT_FAILED` or any other undocumented value. Never guessed
        /// either way; the caller
        /// (`wht_corulix_tooling::platform::windows::test_alive`) maps
        /// this to `None`, exactly like Unix's own `EPERM` branch.
        Uncertain,
    }

    /// `SYNCHRONIZE` (`winnt.h`): the standard access right required to
    /// wait on a kernel object's signal state via `WaitForSingleObject`.
    /// `PROCESS_QUERY_LIMITED_INFORMATION` alone does **not** include it --
    /// `windows-sys` exposes the constant only under
    /// `Win32_Storage_FileSystem` (a generic Win32 header artifact, not a
    /// filesystem-specific right), so this crate defines its own copy of
    /// the well-known, stable standard-access-rights value here rather
    /// than adding that unrelated feature to `Cargo.toml`, mirroring
    /// `wht_corulix_tooling::platform::windows`'s own local
    /// `CREATE_SUSPENDED` constant for the identical reason.
    const SYNCHRONIZE: u32 = 0x0010_0000;

    /// Opens the process identified by `pid` with the minimal
    /// `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` access rights
    /// (`SYNCHRONIZE` is required for the `WaitForSingleObject` call
    /// below -- `PROCESS_QUERY_LIMITED_INFORMATION` alone is
    /// insufficient and native-Windows testing on the P17-W target VM
    /// confirmed this empirically: without `SYNCHRONIZE`,
    /// `WaitForSingleObject` fails and every call here reports
    /// `Uncertain` regardless of the real process state) and reports
    /// whether it is still running, via `WaitForSingleObject(handle, 0)`
    /// kernel-object signal-state polling -- never `GetExitCodeProcess`,
    /// whose `STILL_ACTIVE` (`259`) sentinel is ambiguous with a process
    /// that legitimately exited with status `259` (see the crate-level
    /// docs for the full reasoning). Total and fail-closed: every failure
    /// path this function can observe maps to
    /// [`ProcessLiveness::Uncertain`] except the one Win32 explicitly
    /// documents as meaning "no such process" (`ERROR_INVALID_PARAMETER`
    /// from `OpenProcess`), which maps to [`ProcessLiveness::Absent`].
    #[must_use]
    pub fn query_process_liveness(pid: u32) -> ProcessLiveness {
        // SAFETY: `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` is the
        // minimal access mask this function requires (no code/memory
        // access beyond the signal-state query below); `binherithandle =
        // 0` (false) is correct since this handle is never inherited by
        // any child process this crate spawns. The returned handle is
        // checked against `NULL` (this API's documented failure sentinel)
        // before being trusted with any further call.
        let raw_handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
        let Some(handle) = OwnedHandle::new(raw_handle, false) else {
            return if last_os_error() == ERROR_INVALID_PARAMETER {
                // The documented `OpenProcess` failure for a pid that does
                // not currently identify any process -- the pid is
                // genuinely gone, not merely inaccessible.
                ProcessLiveness::Absent
            } else {
                // Every other failure (most commonly `ERROR_ACCESS_DENIED`)
                // means this call cannot answer the question at all;
                // never guess, fail closed.
                ProcessLiveness::Uncertain
            };
        };

        // SAFETY: `handle.as_handle()` is a live
        // `PROCESS_QUERY_LIMITED_INFORMATION` handle just opened above,
        // not yet closed (owned by `handle`, which outlives this call). A
        // zero millisecond timeout makes this call a pure, non-blocking
        // signal-state poll -- it never actually waits.
        match unsafe { WaitForSingleObject(handle.as_handle(), 0) } {
            // The handle has not yet been signaled: the process is still
            // running.
            WAIT_TIMEOUT => ProcessLiveness::Present,
            // The handle is signaled: the process has terminated.
            WAIT_OBJECT_0 => ProcessLiveness::Absent,
            // `WAIT_FAILED` or any other undocumented return value -- this
            // call itself could not answer the question; fail closed
            // rather than guess.
            _ => ProcessLiveness::Uncertain,
        }
        // `handle` drops here, closing the process handle exactly once.
    }

    // ======================================================================
    // M09-P9: handle-relative filesystem authority.
    //
    // Real, native NT open-by-relative-handle (`NtCreateFile` +
    // `OBJECT_ATTRIBUTES.RootDirectory`), handle-based rename
    // (`NtSetInformationFile(FileRenameInformation)` with a non-null
    // `RootDirectory` field), and handle-based delete
    // (`SetFileInformationByHandle(FileDispositionInfoEx)`) -- never a
    // concatenated absolute path, never `std::fs::rename`/`remove_file`.
    // The only pathname-based open in this whole boundary is
    // [`open_root_directory`], which opens the workspace root itself
    // (unavoidable: something must be the first, pathname-anchored trust
    // point -- exactly mirroring Unix's own `WorkspaceRoot::open_pinned_unix`,
    // which also opens its root by pathname once, via `rustix::fs::open`).
    // Every subsequent open in this module is relative to an already-open,
    // already-authorized handle.
    //
    // Windows reparse-point policy (`M09_P9_WINDOWS_REPARSE_PLATFORM_DELTA`):
    // every open in this boundary passes `FILE_OPEN_REPARSE_POINT`, so a
    // reparse point (symlink, junction, mount point, or any other reparse
    // tag) is opened as ITSELF rather than transparently followed by the
    // filesystem, and is then unconditionally denied
    // ([`FsAuthorityError::ReparsePointDenied`]) -- for both ancestor and
    // terminal components, with no bounded-follow exception. This is
    // STRICTER than Windows' own default transparent reparse-following
    // behavior, and stricter than this crate's pre-P9 Windows confinement
    // path (which used `std::fs::canonicalize`, itself transparently
    // resolving reparse points) -- a disclosed platform semantic delta from
    // Unix's own bounded-internal-symlink-following contract, not a claim
    // of identical cross-platform behavior. See the P9 final report for
    // the full disclosure.
    // ======================================================================

    /// An owned Win32/NT file (or directory) `HANDLE` opened by this
    /// module's own filesystem-authority primitives -- closed exactly once,
    /// deterministically, on `Drop`. Distinct from the process/thread
    /// [`OwnedHandle`] above (different close API, different construction
    /// path): every handle this sub-boundary produces is checked for
    /// failure at the point it is created, never here.
    #[derive(Debug)]
    pub struct FileHandle(HANDLE);

    // SAFETY: a Win32/NT `HANDLE` is an opaque kernel-object reference, not
    // a thread-affine resource -- the kernel itself allows any thread in
    // the owning process to use a handle value, and `wht_corulix_workspace`
    // (this crate's one approved consumer for this boundary) moves
    // `WorkspaceRoot`/`FileHandle` values across `tokio::task::spawn_blocking`
    // boundaries exactly as it already does for Unix's own `Arc<OwnedFd>`
    // (which the standard library itself marks `Send`/`Sync` for the same
    // reason). `FileHandle` exposes no interior mutability and every
    // mutating operation (`rename_relative`/`delete_relative`) consumes it
    // by value, so concurrent shared use can only ever perform read-only
    // handle-relative opens/queries.
    unsafe impl Send for FileHandle {}
    unsafe impl Sync for FileHandle {}

    impl Drop for FileHandle {
        fn drop(&mut self) {
            // SAFETY: `self.0` is always a handle this module itself
            // obtained from a successful `CreateFileW`/`NtCreateFile` call
            // (see every constructor below) and is never cloned/duplicated
            // -- `FileHandle` is not `Clone`/`Copy`, so `Drop::drop` runs at
            // most once per underlying handle value.
            unsafe {
                let _ = windows_sys::Wdk::Foundation::NtClose(self.0);
            }
        }
    }

    impl FileHandle {
        const fn as_handle(&self) -> HANDLE {
            self.0
        }

        /// Converts this handle into a real, owned `std::fs::File` --
        /// letting `wht_corulix_workspace`'s Windows capability layer reuse
        /// `std::fs::File`'s own `Read`/`metadata` implementations on top
        /// of a handle THIS module opened via `NtCreateFile`, without that
        /// crate ever performing its own unsafe raw-handle conversion
        /// (impossible there anyway: it inherits workspace-wide
        /// `unsafe_code = "forbid"`). `windows_sys`'s `HANDLE` and
        /// `std::os::windows::raw::HANDLE` are both literally `*mut
        /// c_void` -- no cast, no reinterpretation, just a type-identical
        /// handoff of ownership.
        #[must_use]
        pub fn into_file(self) -> std::fs::File {
            let raw = self.0;
            // Ownership of `raw` is about to transfer completely to the
            // `OwnedHandle`/`File` constructed below, which will close it
            // exactly once on its own `Drop` -- `core::mem::forget` here
            // prevents THIS type's own `Drop` (which would otherwise also
            // call `NtClose` on the same handle) from running, so the
            // handle is closed exactly once, never doubly.
            core::mem::forget(self);
            // SAFETY: `raw` is a handle this module's own constructors
            // (`open_root_directory`/`open_relative`) obtained from a
            // successful `CreateFileW`/`NtCreateFile` call, confirmed
            // non-null/non-`INVALID_HANDLE_VALUE` at that point, and not
            // yet closed (this is the first and only place ownership is
            // transferred out of a `FileHandle`). It is not currently
            // owned by anything else, so wrapping it in an `OwnedHandle`
            // here does not create a second owner.
            unsafe {
                use std::os::windows::io::FromRawHandle;
                std::fs::File::from(std::os::windows::io::OwnedHandle::from_raw_handle(
                    raw.cast(),
                ))
            }
        }
    }

    /// Real, stable, handle-derived object identity: the volume's serial
    /// number plus the file system's own 128-bit file id (`FileIdInfo`) --
    /// never a pathname, never `GetFinalPathNameByHandle` text comparison.
    /// Two [`FileHandle`]s that refer to the same underlying filesystem
    /// object always report the same [`ObjectIdentity`], regardless of what
    /// pathname either was reached through.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ObjectIdentity {
        pub volume_serial_number: u64,
        pub file_id: [u8; 16],
    }

    /// Why an M09-P9 filesystem-authority call failed. Never collapsed into
    /// a free-form string -- mirrors [`ProcessControlError`]'s own
    /// discipline.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FsAuthorityError {
        /// `CreateFileW` on the workspace root's own absolute path failed.
        OpenRootFailed { os_error: u32 },
        /// `GetFileInformationByHandleEx(FileIdInfo, ..)` failed.
        QueryIdentityFailed { os_error: u32 },
        /// The requested component name is empty, contains a path
        /// separator (`\` or `/`), a drive-letter colon, is `.`/`..`, or
        /// contains an embedded NUL -- never passed to `NtCreateFile` at
        /// all.
        InvalidComponentName,
        /// `NtCreateFile` itself returned a failure `NTSTATUS`.
        OpenRelativeFailed { status: i32 },
        /// The open succeeded, but the resulting object is a reparse point.
        /// M09-P9's Windows fail-closed reparse policy: this is ALWAYS
        /// denied (see this module's own section doc above).
        ReparsePointDenied,
        /// A component expected to be a directory (an ancestor hop) is not
        /// one, or a component expected to be a plain file (a terminal
        /// leaf) turned out to be a directory.
        UnexpectedEntryType,
        /// `GetFileInformationByHandle`/`GetFileInformationByHandleEx`
        /// (attribute query) failed.
        QueryAttributesFailed { os_error: u32 },
        /// `NtSetInformationFile(FileRenameInformation, ..)` returned a
        /// failure `NTSTATUS`.
        RenameFailed { status: i32 },
        /// `SetFileInformationByHandle(FileDispositionInfoEx, ..)` failed.
        DeleteFailed { os_error: u32 },
    }

    /// Which relative-open shape [`open_relative`] should perform. Mirrors
    /// the three access patterns `wht_corulix_workspace`'s Windows
    /// capability layer needs: pinning an ancestor directory while walking
    /// a workspace-relative path, opening an already-existing leaf file for
    /// reading/rename-source/delete, and creating a brand-new leaf file
    /// that must not already exist (mirrors Unix's `PinnedTarget::
    /// create_exclusive`'s `O_EXCL` semantics).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RelativeOpenKind {
        ExistingDirectory,
        ExistingFile,
        NewFile,
    }

    /// UTF-16, NUL-free encoding of a single path COMPONENT (never a
    /// multi-segment string) for use as an `NtCreateFile` relative object
    /// name. Rejects anything that could smuggle a path separator, `.`/
    /// `..`, a drive letter, or an embedded NUL into what must be exactly
    /// one component -- this is the structural reason [`open_relative`] can
    /// never itself become a `..`/absolute-path escape primitive,
    /// independent of whatever validation its own caller already performs.
    fn encode_single_component(name: &std::ffi::OsStr) -> Result<Vec<u16>, FsAuthorityError> {
        use std::os::windows::ffi::OsStrExt;
        if name.is_empty() || name == "." || name == ".." {
            return Err(FsAuthorityError::InvalidComponentName);
        }
        let mut encoded: Vec<u16> = name.encode_wide().collect();
        if encoded
            .iter()
            .any(|unit| matches!(*unit, 0 | 0x5C | 0x2F | 0x3A))
        {
            // 0x5C = '\\', 0x2F = '/', 0x3A = ':'
            return Err(FsAuthorityError::InvalidComponentName);
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn last_os_error_u32() -> u32 {
        // SAFETY: identical justification to `last_os_error` above.
        unsafe { windows_sys::Win32::Foundation::GetLastError() }
    }

    fn query_attributes(handle: &FileHandle) -> Result<u32, FsAuthorityError> {
        let mut info = core::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: `handle.as_handle()` is live for this call's duration;
        // `info` is a uniquely-owned, correctly-sized output buffer this
        // API fully initializes on success (checked via its `BOOL` return
        // before `info` is ever read).
        let succeeded =
            unsafe { GetFileInformationByHandle(handle.as_handle(), info.as_mut_ptr()) } != 0;
        if !succeeded {
            return Err(FsAuthorityError::QueryAttributesFailed {
                os_error: last_os_error_u32(),
            });
        }
        // SAFETY: `succeeded` being true means the API fully populated
        // `info` per its documented contract.
        let info = unsafe { info.assume_init() };
        Ok(info.dwFileAttributes)
    }

    /// Opens the workspace root directory by its absolute, already-
    /// canonicalized path. The ONLY pathname-based open in this entire
    /// boundary -- see this section's own doc comment above for why
    /// exactly one such anchor point is unavoidable (mirrors Unix's own
    /// `WorkspaceRoot::open_pinned_unix`).
    pub fn open_root_directory(
        path: &std::path::Path,
    ) -> Result<(FileHandle, ObjectIdentity), FsAuthorityError> {
        use std::os::windows::ffi::OsStrExt;
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);

        // SAFETY: `wide` is a NUL-terminated, valid UTF-16 buffer this
        // function owns for the duration of this single call (`CreateFileW`
        // does not retain the pointer past its own return).
        // `FILE_FLAG_BACKUP_SEMANTICS` is required to open a directory at
        // all via `CreateFileW`; no template handle, no security
        // attributes (`null`) are passed. Deliberately READ-ONLY
        // (`FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES`
        // only) -- confirmed empirically on the real target VM that
        // `FILE_ADD_FILE`/`FILE_ADD_SUBDIRECTORY`/`DELETE` on THIS handle
        // are not merely unnecessary but actively HARMFUL: a
        // handle-relative rename via `NtSetInformationFile
        // (FileRenameInformation)` with this directory as `RootDirectory`
        // requires that NO open handle to this directory carry
        // write-capable access, or the kernel rejects it with
        // `STATUS_SHARING_VIOLATION` (0xC0000043) -- observed even when
        // this SAME handle is both the sole open handle and the one
        // performing the rename. A read-only handle suffices as
        // `RootDirectory` for every operation this crate performs
        // (traversal, create, AND rename), each confirmed natively.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                core::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(FsAuthorityError::OpenRootFailed {
                os_error: last_os_error_u32(),
            });
        }
        let handle = FileHandle(raw);
        let identity = query_identity(&handle)?;
        Ok((handle, identity))
    }

    /// Real, handle-derived object identity (`FileIdInfo`) -- never a
    /// pathname/string comparison.
    pub fn query_identity(handle: &FileHandle) -> Result<ObjectIdentity, FsAuthorityError> {
        let mut info = FILE_ID_INFO::default();
        // SAFETY: `handle.as_handle()` is a live handle owned by `handle`
        // for at least this call's duration; `&mut info` is a uniquely
        // borrowed, correctly-sized output buffer for the documented
        // `FileIdInfo` shape.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                handle.as_handle(),
                FileIdInfo,
                core::ptr::addr_of_mut!(info).cast(),
                core::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        } != 0;
        if !succeeded {
            return Err(FsAuthorityError::QueryIdentityFailed {
                os_error: last_os_error_u32(),
            });
        }
        Ok(ObjectIdentity {
            volume_serial_number: info.VolumeSerialNumber,
            file_id: info.FileId.Identifier,
        })
    }

    /// Whether `handle`'s own object (not whatever it was opened relative
    /// to) currently carries `FILE_ATTRIBUTE_REPARSE_POINT`.
    fn is_reparse_point(handle: &FileHandle) -> Result<bool, FsAuthorityError> {
        let attrs = query_attributes(handle)?;
        Ok(attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }

    /// The real handle-relative open primitive: `NtCreateFile` with
    /// `OBJECT_ATTRIBUTES.RootDirectory = parent`'s own handle and a
    /// SINGLE-COMPONENT object name -- never a multi-segment path, never a
    /// concatenated absolute string. Always requests
    /// `FILE_OPEN_REPARSE_POINT` so a reparse point is opened as ITSELF
    /// (never transparently followed by the filesystem), then denies it via
    /// [`is_reparse_point`] -- M09-P9's Windows fail-closed reparse policy
    /// (see this section's own doc above).
    pub fn open_relative(
        parent: &FileHandle,
        name: &std::ffi::OsStr,
        kind: RelativeOpenKind,
    ) -> Result<FileHandle, FsAuthorityError> {
        let mut wide = encode_single_component(name)?;
        // `wide` already carries its own trailing NUL
        // (`encode_single_component` appends one); `UNICODE_STRING.Length`/
        // `MaximumLength` are in BYTES and must exclude that trailing NUL
        // per NT convention.
        #[allow(clippy::cast_possible_truncation)]
        let length_bytes = ((wide.len() - 1) * 2) as u16;

        let object_name = UNICODE_STRING {
            Length: length_bytes,
            MaximumLength: length_bytes,
            Buffer: wide.as_mut_ptr(),
        };

        let object_attributes = OBJECT_ATTRIBUTES {
            Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.as_handle(),
            ObjectName: core::ptr::addr_of!(object_name),
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: core::ptr::null(),
            SecurityQualityOfService: core::ptr::null(),
        };

        // `FILE_READ_ATTRIBUTES` is required on every branch below: this
        // module's own post-open `is_reparse_point`/`query_attributes`
        // checks call `GetFileInformationByHandle` on the handle
        // `NtCreateFile` just returned, and that Win32 API itself requires
        // `FILE_READ_ATTRIBUTES` access on the handle -- omitting it here
        // (confirmed on the real target VM: `NtCreateFile` itself succeeds,
        // but the follow-up attribute query then fails with
        // `ERROR_ACCESS_DENIED`) would silently deny every relative open,
        // even for a legitimate object this caller is otherwise fully
        // authorized to open.
        let (desired_access, create_options, create_disposition) = match kind {
            // Deliberately READ-ONLY -- see `open_root_directory`'s own
            // comment: a directory handle carrying `FILE_ADD_FILE`/
            // `FILE_ADD_SUBDIRECTORY`/`DELETE` self-conflicts with any
            // handle-relative rename that later uses it as
            // `RootDirectory` (confirmed natively:
            // `STATUS_SHARING_VIOLATION`), while a read-only handle
            // suffices for traversal, create, AND rename alike.
            RelativeOpenKind::ExistingDirectory => (
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                FILE_OPEN,
            ),
            RelativeOpenKind::ExistingFile => (
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                FILE_OPEN,
            ),
            RelativeOpenKind::NewFile => (
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                FILE_CREATE,
            ),
        };

        let mut io_status_block = IO_STATUS_BLOCK::default();
        let mut raw_handle: HANDLE = core::ptr::null_mut();

        // SAFETY: `object_attributes.RootDirectory` is a live handle
        // (`parent`, borrowed for this call's duration); `object_attributes.
        // ObjectName` points at `object_name`, which itself points into
        // `wide` -- both local bindings that outlive this call (dropped
        // only after it returns). `object_name` is a single validated path
        // component whose `Length`/`MaximumLength` are correctly computed
        // in bytes above. `raw_handle`/`io_status_block` are uniquely-
        // owned, correctly-sized output locations. `allocationsize`/
        // `eabuffer` are not used by this open shape (`null`).
        let status: NTSTATUS = unsafe {
            NtCreateFile(
                core::ptr::addr_of_mut!(raw_handle),
                desired_access,
                core::ptr::addr_of!(object_attributes),
                core::ptr::addr_of_mut!(io_status_block),
                core::ptr::null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                create_disposition,
                create_options,
                core::ptr::null(),
                0,
            )
        };
        if status < 0 {
            return Err(FsAuthorityError::OpenRelativeFailed { status });
        }
        let handle = FileHandle(raw_handle);

        if is_reparse_point(&handle)? {
            return Err(FsAuthorityError::ReparsePointDenied);
        }
        let attrs = query_attributes(&handle)?;
        let is_directory = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
        match kind {
            RelativeOpenKind::ExistingDirectory if !is_directory => {
                return Err(FsAuthorityError::UnexpectedEntryType);
            }
            RelativeOpenKind::ExistingFile | RelativeOpenKind::NewFile if is_directory => {
                return Err(FsAuthorityError::UnexpectedEntryType);
            }
            _ => {}
        }
        Ok(handle)
    }

    /// Handle-based rename: `source` is renamed to `new_name` INSIDE
    /// `new_parent` -- via NATIVE `NtSetInformationFile
    /// (FileRenameInformation, ..)` with a non-null `RootDirectory` field
    /// set to `new_parent`'s own handle, never a concatenated absolute
    /// destination path, never `std::fs::rename`. Deliberately the native
    /// NT call, not the Win32 `SetFileInformationByHandle` wrapper:
    /// confirmed empirically on the real target VM that the Win32 wrapper
    /// rejects ANY non-null `RootDirectory` outright with
    /// `ERROR_INVALID_PARAMETER`, on this Windows build, regardless of
    /// buffer correctness, while the native call passes structural
    /// validation (its remaining failure mode, `STATUS_SHARING_VIOLATION`,
    /// is the separate access-mask issue `open_relative`'s
    /// `ExistingDirectory` doc comment addresses). Consumes `source`
    /// (matching Unix's `PinnedTarget::rename_into`'s own by-value
    /// consumption: once renamed, the original capability no longer refers
    /// to anything meaningful).
    pub fn rename_relative(
        source: FileHandle,
        new_parent: &FileHandle,
        new_name: &std::ffi::OsStr,
        replace_if_exists: bool,
    ) -> Result<(), FsAuthorityError> {
        let wide = encode_single_component(new_name)?;
        #[allow(clippy::cast_possible_truncation)]
        let name_len_bytes = ((wide.len() - 1) * 2) as u32;

        // `FILE_RENAME_INFO` is a variable-length struct (`FileName: [u16;
        // 1]` is a flexible-array-member placeholder) -- built manually as
        // a raw byte buffer sized for the fixed header plus the real
        // encoded name, matching the documented C layout exactly.
        //
        // `header_len` MUST be the real, compiler-computed byte OFFSET of
        // the `FileName` field (`core::mem::offset_of!`), never
        // `size_of::<FILE_RENAME_INFO>() - size_of::<u16>()`: on this
        // struct's real x64 layout, `RootDirectory` (a `HANDLE`, 8-byte
        // aligned) forces 4 bytes of padding after the leading 4-byte
        // union, and the struct's own OVERALL size is then rounded up to
        // its 8-byte alignment (adding 2 more bytes of TAIL padding after
        // the 2-byte `FileName` field) -- so `size_of::<...>() -
        // size_of::<u16>()` overshoots the real `FileName` offset by
        // exactly that trailing padding (empirically confirmed on real
        // Windows: the size-based formula silently shifted every renamed
        // file's name by 2 bytes, corrupting it and failing with
        // `ERROR_INVALID_NAME`). `offset_of!` reads the compiler's own
        // layout, so it is correct regardless of any padding on any
        // target.
        let header_len = core::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let total_len = header_len + wide.len() * core::mem::size_of::<u16>();
        let mut buffer = vec![0u8; total_len];

        // SAFETY: `buffer` is freshly allocated with exactly `total_len`
        // bytes (fixed header plus the real `FileName` payload, both
        // computed from the same `wide.len()` just above), so writing a
        // `FILE_RENAME_INFO` header at offset 0 stays within bounds, and
        // the subsequent `copy_nonoverlapping` writes exactly `wide.len()`
        // `u16`s starting at the `FileName` field's own byte offset --
        // never past `buffer`'s end. The union is explicitly zeroed
        // (`core::mem::zeroed()`) before its one relevant field is set: a
        // Rust union literal that sets only one variant does not
        // guarantee the variant's own unused trailing bytes are zero, and
        // writing that value's raw bytes into `buffer` would otherwise
        // copy whatever uninitialized padding the compiler left there
        // into the structure sent to the kernel.
        unsafe {
            let mut anonymous: FILE_RENAME_INFO_0 = core::mem::zeroed();
            // The native `FileRenameInformation` class (used below, not
            // its `...Ex` sibling) interprets this union as the classic
            // `BOOLEAN ReplaceIfExists`, not `Flags`.
            anonymous.ReplaceIfExists = replace_if_exists;
            let header_ptr = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
            core::ptr::write(
                header_ptr,
                FILE_RENAME_INFO {
                    Anonymous: anonymous,
                    RootDirectory: new_parent.as_handle(),
                    FileNameLength: name_len_bytes,
                    FileName: [0u16; 1],
                },
            );
            let name_dest = buffer.as_mut_ptr().add(header_len).cast::<u16>();
            core::ptr::copy_nonoverlapping(wide.as_ptr(), name_dest, wide.len());
        }

        let mut io_status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `source.as_handle()` is live for this call's duration;
        // `buffer` is a correctly-sized, correctly-laid-out
        // `FILE_RENAME_INFO` this function just constructed above and owns
        // for the duration of this single call; `io_status_block` is a
        // uniquely-owned, correctly-sized output location.
        let status: NTSTATUS = unsafe {
            NtSetInformationFile(
                source.as_handle(),
                core::ptr::addr_of_mut!(io_status_block),
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                FileRenameInformation,
            )
        };
        if status < 0 {
            return Err(FsAuthorityError::RenameFailed { status });
        }
        Ok(())
        // `source` drops here, closing its handle exactly once.
    }

    /// Handle-based delete: `SetFileInformationByHandle(FileDispositionInfoEx,
    /// ..)` with `FILE_DISPOSITION_FLAG_DELETE |
    /// FILE_DISPOSITION_FLAG_POSIX_SEMANTICS` -- POSIX unlink-like
    /// semantics (the directory entry is removed immediately; the
    /// underlying object is freed once every other open handle to it also
    /// closes), never `std::fs::remove_file`. Consumes `handle`.
    pub fn delete_relative(handle: FileHandle) -> Result<(), FsAuthorityError> {
        let info = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // SAFETY: `handle.as_handle()` is live for this call's duration;
        // `&info` is a correctly-sized `FILE_DISPOSITION_INFO_EX` this
        // function owns for the duration of this single call.
        let succeeded = unsafe {
            SetFileInformationByHandle(
                handle.as_handle(),
                FileDispositionInfoEx,
                core::ptr::addr_of!(info).cast(),
                core::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        } != 0;
        if !succeeded {
            return Err(FsAuthorityError::DeleteFailed {
                os_error: last_os_error_u32(),
            });
        }
        Ok(())
        // `handle` drops here (closes the now-deleted file's handle).
    }
}

#[cfg(windows)]
pub use ffi::{
    FileHandle, FsAuthorityError, ObjectIdentity, ProcessControlError, ProcessLiveness,
    RelativeOpenKind, delete_relative, open_relative, open_root_directory, query_identity,
    query_process_liveness, rename_relative, resume_primary_thread, terminate_process,
};

#[cfg(all(test, windows))]
mod tests {
    //! Every test in this module was executed natively on a real
    //! Windows 10 (build 19045) test VM, never merely cross-compiled --
    //! see the P17-W-R2 report for exact command/output evidence.
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_SUSPENDED: u32 = 0x0000_0004;

    #[test]
    fn resuming_a_suspended_notepad_less_process_succeeds() {
        // `cmd /C exit` is a real, always-present Windows binary; spawned
        // CREATE_SUSPENDED it never executes a single instruction until
        // explicitly resumed below.
        let mut child = Command::new("cmd")
            .args(["/C", "exit"])
            .creation_flags(CREATE_SUSPENDED)
            .spawn()
            .unwrap_or_else(|error| {
                unreachable!("cmd.exe must exist on every Windows target: {error}")
            });
        let pid = child.id();
        let result = resume_primary_thread(pid);
        assert!(result.is_ok(), "resume must succeed: {result:?}");
        let status = child
            .wait()
            .unwrap_or_else(|error| unreachable!("resumed child must be waitable: {error}"));
        assert!(status.success());
    }

    #[test]
    fn resuming_an_already_exited_process_fails_closed() {
        // Spawn normally (not suspended) and let it exit, then attempt to
        // resume its (now-nonexistent) thread by its stale pid -- this
        // must return a typed error, never panic, never silently succeed.
        let mut child = Command::new("cmd")
            .args(["/C", "exit"])
            .spawn()
            .unwrap_or_else(|error| {
                unreachable!("cmd.exe must exist on every Windows target: {error}")
            });
        let pid = child.id();
        let _ = child.wait();
        let result = resume_primary_thread(pid);
        assert!(result.is_err());
    }

    #[test]
    fn terminating_a_suspended_process_leaves_no_running_descendant() {
        let mut child = Command::new("cmd")
            .args(["/C", "exit"])
            .creation_flags(CREATE_SUSPENDED)
            .spawn()
            .unwrap_or_else(|error| {
                unreachable!("cmd.exe must exist on every Windows target: {error}")
            });
        let raw_handle = std::os::windows::io::AsRawHandle::as_raw_handle(&child) as isize;
        let result = terminate_process(raw_handle, 1);
        assert!(result.is_ok(), "terminate must succeed: {result:?}");
        let status = child
            .wait()
            .unwrap_or_else(|error| unreachable!("terminated child must be waitable: {error}"));
        assert!(!status.success());
    }

    // -- `query_process_liveness` (P17-W-R3-C3, `WINDOWS_PROCESS_LIVENESS_PROBE_GAP`) --
    //
    // Case A (real running process -> Present), Case B (process exits ->
    // eventually Absent), and Case C (nonexistent pid -> Absent) are
    // exercised here, at the raw FFI boundary, against real Win32 process
    // state. Cases D (terminated managed process), E (ambiguous/uncertain
    // access), and F (repeated check around process exit race) require the
    // managed-process/lease/fixture context this narrow crate deliberately
    // does not depend on -- they are exercised at that layer instead, in
    // `wht_corulix_tooling`'s own native Windows test suite, against
    // `platform::windows::test_alive` and `lease::verify_process_absent`.

    #[test]
    fn query_process_liveness_reports_present_for_a_real_running_process() {
        // `ping -n 30 127.0.0.1` runs for roughly 29 seconds -- long enough
        // to be observed alive by this test, and torn down explicitly
        // below rather than left to time out on its own.
        let mut child = Command::new("cmd")
            .args(["/C", "ping", "-n", "30", "127.0.0.1"])
            .spawn()
            .unwrap_or_else(|error| {
                unreachable!("cmd.exe/ping.exe must exist on every Windows target: {error}")
            });
        let pid = child.id();
        let verdict = query_process_liveness(pid);
        assert_eq!(
            verdict,
            ProcessLiveness::Present,
            "process is still running"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn query_process_liveness_reports_absent_after_a_process_exits() {
        let mut child = Command::new("cmd")
            .args(["/C", "exit"])
            .spawn()
            .unwrap_or_else(|error| {
                unreachable!("cmd.exe must exist on every Windows target: {error}")
            });
        let pid = child.id();
        let status = child
            .wait()
            .unwrap_or_else(|error| unreachable!("spawned child must be waitable: {error}"));
        assert!(status.success());
        let verdict = query_process_liveness(pid);
        assert_eq!(
            verdict,
            ProcessLiveness::Absent,
            "process has already exited"
        );
    }

    #[test]
    fn query_process_liveness_reports_absent_for_a_pid_never_reused_on_this_host() {
        // A pid value structurally unlikely to be a live process on any
        // real Windows host (pids are small, dense integers there).
        let never_reused_pid: u32 = 0xFFFF_FFF0;
        let verdict = query_process_liveness(never_reused_pid);
        assert_eq!(
            verdict,
            ProcessLiveness::Absent,
            "OpenProcess must fail with ERROR_INVALID_PARAMETER for a pid that never existed"
        );
    }
}
