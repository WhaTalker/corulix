// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![deny(unsafe_code)]

//! Narrow, audited Unix FFI boundary for pinning a spawned child
//! process's current working directory to an already-open, pinned
//! directory object -- never a pathname re-resolved at spawn time (M09
//! remediation P6, `M09_P6_UNIX_CWD_AUTHORITY=PINNED_ROOT_OBJECT`).
//!
//! # Why this crate exists (Unix counterpart of `WINDOWS_FFI_SAFETY_BOUNDARY_DECISION`)
//!
//! Every crate in this workspace inherits a crate-root inner attribute
//! applying rustc's `forbid(unsafe_code)` lint level, via
//! `[workspace.lints.rust] unsafe_code = "forbid"` reproduced per-crate
//! through `[lints] workspace = true`. Rust's `forbid` lint level cannot be
//! locally overridden by an inner attribute applying `allow(unsafe_code)`
//! (`E0453`) -- that is the entire semantic difference between `forbid` and
//! `deny`. `wht_corulix_workspace`, the sole owner of workspace
//! canonicalization/confinement (Architecture Rule F), is one such `forbid`
//! crate, so there is no module-level carve-out possible *inside* it.
//! Pinning a child's cwd to an already-open fd (rather than a re-resolved
//! pathname) requires registering a `std::os::unix::process::CommandExt::
//! pre_exec` closure, whose *registration* method is itself `unsafe fn` --
//! so this crate exists as the one deliberate, documented, narrowly-scoped
//! Unix exception, mirroring this workspace's own equivalent Windows Job
//! Object FFI boundary crate's precedent for the identical
//! `forbid`-cannot-be-overridden problem on Windows: it
//! defines its own `[lints]` table (see `Cargo.toml`) with `unsafe_code =
//! "deny"` rather than inheriting the workspace `forbid`, and grants
//! exactly one inner attribute applying `allow(unsafe_code)` to exactly one
//! submodule (`ffi`, private, and therefore never a resolvable rustdoc
//! link -- see [`bind_cwd`] below for this crate's one actual public
//! item). Every other crate in the workspace,
//! `wht_corulix_workspace` included, keeps `forbid` byte-for-byte
//! unchanged -- `UNSAFE_ALLOWED_IN_GENERAL_PRODUCT_CODE=NO`.
//!
//! # Public contract
//!
//! [`bind_cwd`] is the only thing this crate does: given an already-owned,
//! already-open directory `Arc<OwnedFd>` and a `&mut std::process::
//! Command`, it registers a `pre_exec` closure whose entire body is one
//! `fchdir` call and nothing else. This crate:
//!
//!   * never opens, resolves, or confines any pathname itself -- it
//!     receives only the already-pinned fd object the caller (in
//!     practice, `wht_corulix_workspace::WorkspaceRoot::bind_process_cwd`)
//!     already owns, and never becomes a second general confinement
//!     authority (Rule F stays with `wht_corulix_workspace` alone);
//!   * never constructs or spawns a `Command` in production -- it only
//!     *configures* one the caller already owns; production `spawn()`
//!     ownership stays with `wht_corulix_tooling` (Rule G). This crate's
//!     own tests spawn test-only children solely to prove this primitive,
//!     nothing else;
//!   * exposes no shell, no generic callback-execution API, no arbitrary
//!     fd API, and no `RawFd`/`OwnedFd`/`BorrowedFd` to its own callers --
//!     [`bind_cwd`] takes an `Arc<OwnedFd>` it already trusts the caller
//!     to have obtained correctly, and hands nothing fd-shaped back.

#[cfg(unix)]
mod ffi {
    #![allow(unsafe_code)]
    // SAFETY (module-wide): the one `unsafe` block below registers a
    // `pre_exec` closure whose entire body is `fchdir(fd)` plus, on
    // failure, constructing a plain `io::Error` -- both are async-signal-
    // safe: `fchdir` is a direct, fixed-argument syscall with no internal
    // locking, allocation, or TLS-dependent state beyond making the
    // syscall itself (true of both rustix's `linux_raw` backend, which
    // issues the raw syscall directly with no libc involvement at all, and
    // its `libc` backend, where glibc's `fchdir` is itself a thin,
    // POSIX-async-signal-safe syscall wrapper); `std::io::Error::from`
    // (and `from_raw_os_error`) construct a plain, non-allocating value
    // (`Repr::Os(code)`) with no heap allocation, no locking, and no
    // formatting. No allocation, no logging, no locking, no additional
    // pathname resolution, no environment mutation, no formatting, no
    // thread synchronization, and no network I/O occurs anywhere in the
    // closure -- it is exactly the one syscall `pre_exec`'s own safety
    // contract (async-signal-safety of everything that runs between
    // `fork` and `exec`) requires.

    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::process::CommandExt as _;
    use std::process::Command;
    use std::sync::Arc;

    /// Registers a `pre_exec` closure on `command` that binds the
    /// eventual child's current working directory to `root_fd` -- the
    /// EXACT filesystem object `root_fd` refers to, never a pathname.
    ///
    /// # Fd ownership / lifetime
    ///
    /// `root_fd` is moved into the closure by value, so the closure --
    /// and therefore `command`, which owns the closure internally once
    /// registered -- holds its own independent, `'static` reference to
    /// the underlying `OwnedFd` for as long as `command` itself lives.
    /// This has NO dependency on the caller's own object (in practice, a
    /// `WorkspaceRoot`) that originally produced `root_fd` staying alive
    /// until spawn: even if that original owner is dropped immediately
    /// after this call returns, the `Arc`'s refcount (now held by the
    /// closure) keeps the underlying fd open until `command` itself is
    /// dropped or successfully executes. No raw `RawFd` integer is ever
    /// captured on its own, decoupled from an owner.
    ///
    /// No duplication (`dup`/`fcntl(F_DUPFD_CLOEXEC)`) of `root_fd` is
    /// performed or needed: the `Arc` clone the caller passes in is
    /// already a fully independent, owned reference to the same
    /// underlying open file description, and multiple independent
    /// `Command`s may each be bound this way from clones of the same
    /// `Arc` -- `fchdir` only reads the fd to change the calling
    /// process's cwd; it never closes, moves, or otherwise consumes it,
    /// so concurrent/repeated use of the identical fd number across
    /// independently-forked children is safe.
    ///
    /// # `CLOEXEC`
    ///
    /// `root_fd` is expected to have been opened with `O_CLOEXEC` by its
    /// original owner (as `wht_corulix_workspace::WorkspaceRoot`'s own
    /// pinned root fd already is) -- this function does not itself set or
    /// verify that flag, since re-deriving it here would be redundant
    /// with the fd's own construction-time guarantee, and this crate
    /// never constructs the fd itself. `fork()` copies the parent's whole
    /// fd table verbatim (`CLOEXEC` only governs `exec()`, not `fork()`),
    /// so the fd is present in the child for the `pre_exec` closure to
    /// `fchdir` with; a subsequent successful `exec()` then closes it
    /// automatically as part of the image transition, before the new
    /// program image ever runs -- no explicit close call is needed or
    /// made here.
    ///
    /// # Error propagation
    ///
    /// If the closure's `fchdir` call fails (e.g. `root_fd` somehow no
    /// longer refers to a directory), the closure returns `Err`, which
    /// `std` documents as aborting the exec attempt and surfacing the
    /// error through `Command::spawn`'s own `io::Result` -- never a
    /// silent fallback to the parent's inherited cwd or to any pathname
    /// `Command::current_dir` may separately have set.
    pub fn bind_cwd(command: &mut Command, root_fd: Arc<OwnedFd>) {
        // SAFETY: see this module's own doc comment above for the full
        // async-signal-safety justification of the closure body.
        unsafe {
            command.pre_exec(move || {
                rustix::process::fchdir(root_fd.as_fd()).map_err(std::io::Error::from)
            });
        }
    }
}

#[cfg(unix)]
pub use ffi::bind_cwd;
