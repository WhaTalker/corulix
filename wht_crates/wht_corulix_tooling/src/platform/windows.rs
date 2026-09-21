// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Windows process-tree containment via a Job Object
//! (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`): every descendant a contained
//! child spawns is, by default Windows behavior, automatically added to
//! the same job (this module never sets a breakaway-allowed limit), so
//! terminating the job terminates the whole tree, not merely the direct
//! child.
//!
//! # Assign-before-resume: the spawn-then-assign race is closed (P17-W-R2)
//!
//! An earlier phase's implementation assigned the child to the Job Object
//! *after* [`tokio::process::Command::spawn`] had already returned,
//! leaving a real window in which a child could execute user-mode code
//! (and spawn a grandchild) before ever becoming a job member -- see
//! `wht_docs/wht_adr` history for that disclosed, since-superseded gap.
//!
//! This module closes it structurally, not merely narrows it:
//!
//!   1. [`prepare`] spawns the child `CREATE_SUSPENDED`: it exists as an OS
//!      process, but its one and only thread has never executed a single
//!      instruction and (being suspended) cannot itself create any
//!      descendant.
//!   2. [`contain`] creates and configures a Job Object with
//!      `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, then assigns the still-
//!      suspended process to it.
//!   3. **Only if** that assignment succeeds does [`contain`] resume the
//!      child's primary thread (via
//!      [`wht_corulix_process_win32::resume_primary_thread`], the one
//!      approved narrow Win32 FFI boundary this crate's own
//!      `#![forbid(unsafe_code)]` cannot itself host -- see that crate's
//!      module docs for why it is a separate crate at all).
//!
//! If Job Object creation/configuration/assignment fails, or if the
//! resume itself fails, the still-suspended (or just-reassigned-then-
//! immediately-terminated) child is terminated before [`contain`] returns
//! -- it is never left both un-terminated and un-resumed/uncontained. See
//! [`super::ContainOutcome::TerminatedBeforeExecution`] for the exact
//! caller contract this guarantees.
//!
//! There is no `ResumeThread` call anywhere in this module or in
//! `wht_corulix_process_win32` that is reachable before a successful Job
//! Object assignment -- that ordering is what
//! `WINDOWS_CHILD_CREATION_STRUCTURAL_PROOF` in the P17-W-R2 report
//! points to.

use std::os::windows::io::RawHandle;
// NOTE: `Command::creation_flags` below is an inherent method on
// `tokio::process::Command` itself (it delegates to
// `std::os::windows::process::CommandExt` *inside* tokio's own module,
// where that trait is already in scope) -- this module never needs to
// import `CommandExt` itself to call it.
use tokio::process::{Child, Command};
use win32job::Job;

use super::ContainOutcome;

/// `CREATE_SUSPENDED` (`winbase.h`): the child process is created but its
/// primary thread is not scheduled to run until an explicit `ResumeThread`
/// call succeeds.
const CREATE_SUSPENDED: u32 = 0x0000_0004;

/// A sentinel, non-zero exit code used only when this module must
/// terminate a still-suspended child directly (Job Object
/// creation/assignment failed) -- distinguishable, if ever observed via
/// `child.wait()`, from a real `0`/success exit the child itself never
/// had the chance to produce (it never executed).
const TERMINATED_BEFORE_EXECUTION_EXIT_CODE: u32 = 1;

/// Owns the Job Object handle. Dropping this value while any process
/// remains assigned to the job terminates it/them immediately (that is
/// exactly what `limit_kill_on_job_close` means) -- so this value must be
/// kept alive for the entire duration a contained child is allowed to run,
/// and only dropped (via [`terminate`]) once termination is actually
/// intended, or after the child has already exited on its own.
pub struct Containment {
    job: Job,
}

/// Configures the about-to-be-spawned child to start `CREATE_SUSPENDED` --
/// see the module docs: this is the entire pre-spawn half of the
/// assign-before-resume invariant. `tokio::process::Command::creation_flags`
/// delegates directly to `std::os::windows::process::CommandExt`'s stable
/// method of the same name, exactly like Unix's `prepare` delegates to
/// `CommandExt::process_group`.
///
/// Two caveats, both load-bearing for anyone touching this function later:
///
///   * `CommandExt::creation_flags` **sets** the raw flags value, it does
///     not OR into whatever `std` itself would otherwise pass -- so if a
///     future change adds a second call to `creation_flags` anywhere on
///     this same `Command` (e.g. `DETACHED_PROCESS`/`CREATE_NO_WINDOW`),
///     the later call silently replaces `CREATE_SUSPENDED` rather than
///     combining with it, reopening the exact race this module closes,
///     with no test failing to say so. There must only ever be one
///     `creation_flags` call site for a `Command` this module later passes
///     to [`contain`].
///   * `std`'s own Windows process-spawn implementation is believed to
///     additionally OR in `CREATE_UNICODE_ENVIRONMENT` internally
///     regardless of caller-supplied `creation_flags` (never replacing
///     them), based on long-standing, publicly documented `std` behavior
///     -- but this specific claim has not yet been independently verified
///     natively on the P17-W-R2 target VM (e.g. by round-tripping a
///     non-ASCII environment variable through a `CREATE_SUSPENDED` child).
///     Treat it as a documented assumption, not confirmed evidence, until
///     that native check has actually run.
pub fn prepare(command: &mut Command) {
    command.creation_flags(CREATE_SUSPENDED);
}

/// Creates a new Job Object configured to kill every member process when
/// its last handle closes, assigns the still-`CREATE_SUSPENDED` `child` to
/// it, and -- only on success -- resumes the child's primary thread. See
/// the module docs for the full assign-before-resume protocol and
/// [`super::ContainOutcome`] for this function's exact three-way return
/// contract.
///
/// `child.raw_handle()`/`child.id()` (native to `tokio::process::Child`)
/// return `None` only once the child has already been reaped, which
/// cannot yet be true immediately after a successful `spawn()` -- the
/// practically-unreachable `None` case is treated the same as Unix's own
/// practically-unreachable edge case (left uncontained, not terminated),
/// since there is no live handle/pid available here to terminate anything
/// by.
pub fn contain(child: &Child) -> ContainOutcome {
    let (Some(raw_handle), Some(pid)) = (child.raw_handle(), child.id()) else {
        return ContainOutcome::Uncontained;
    };

    match establish_job_containment(raw_handle) {
        Some(job) => match wht_corulix_process_win32::resume_primary_thread(pid) {
            Ok(()) => ContainOutcome::Contained(Containment { job }),
            Err(_resume_error) => {
                // The child was already an unbreakable member of a
                // kill-on-close Job Object when the resume attempt itself
                // failed. Do not rely on dropping `job` alone: the
                // `TerminatedBeforeExecution` contract this function
                // returns is a guarantee, not a best-effort hint, and a
                // resume failure's exact process state is not fully
                // characterized (e.g. a partial `ResumeThread` success
                // before an error was reported). Terminate the process
                // directly first -- through the still-caller-owned handle,
                // the same primitive the sibling `None` branch below
                // uses -- then drop the job's own handle as a second,
                // independent enforcement layer (`limit_kill_on_job_close`
                // would terminate it anyway once the job's last handle
                // closes, but this must not be the *only* mechanism this
                // path depends on).
                #[allow(clippy::cast_possible_wrap)]
                let _ = wht_corulix_process_win32::terminate_process(
                    raw_handle as isize,
                    TERMINATED_BEFORE_EXECUTION_EXIT_CODE,
                );
                drop(job);
                ContainOutcome::TerminatedBeforeExecution
            }
        },
        None => {
            // Job Object creation/configuration/assignment failed while
            // `child` was still suspended (it has executed nothing).
            // Terminate it directly through the still-caller-owned
            // process handle -- never resumed, never left running
            // uncontained. This borrows `raw_handle`; it does not close
            // it (that remains `child`'s own handle to close on reap/
            // drop, exactly as it already would without this module ever
            // touching it).
            #[allow(clippy::cast_possible_wrap)]
            let _ = wht_corulix_process_win32::terminate_process(
                raw_handle as isize,
                TERMINATED_BEFORE_EXECUTION_EXIT_CODE,
            );
            ContainOutcome::TerminatedBeforeExecution
        }
    }
}

/// Creates, configures (`limit_kill_on_job_close`), and assigns
/// `raw_handle` to a fresh Job Object, or `None` if any step fails.
/// Extracted so [`contain`]'s success/failure branching above stays a
/// single, structurally obvious `match` on "was containment
/// established" -- not a chain of early-return `?`s that could
/// accidentally fall through to a resume call before assignment actually
/// succeeded.
fn establish_job_containment(raw_handle: RawHandle) -> Option<Job> {
    let job = Job::create().ok()?;
    let mut info = job.query_extended_limit_info().ok()?;
    info.limit_kill_on_job_close();
    job.set_extended_limit_info(&info).ok()?;
    #[allow(clippy::cast_possible_wrap)]
    job.assign_process(raw_handle as isize).ok()?;
    Some(job)
}

/// Reports whether the process identified by `pid` is still running, via
/// [`wht_corulix_process_win32::query_process_liveness`] (P17-W-R3-C3,
/// `WINDOWS_PROCESS_LIVENESS_PROBE_GAP`) -- the approved narrow Win32 FFI
/// boundary's `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` +
/// `WaitForSingleObject(handle, 0)` probe, never `tasklist`/`wmic`/
/// PowerShell/`cmd.exe` (those remain independent certification-oracle
/// tools only, never a production dependency).
///
/// # Scope: pid liveness, not tree/job-membership liveness
///
/// Unlike Unix's [`super::unix::test_alive`], which answers "does the
/// *process group* this crate placed a contained child's whole descendant
/// tree into still exist" (`kill(-pid, 0)` against the group), this
/// function can only answer "does the *single process* identified by this
/// recorded pid still exist" -- `win32job`/the Win32 Job Object API expose
/// no direct "is any process still assigned to this job" query this crate
/// has adopted (see [`super::contain`]'s module docs), so there is no
/// tree-wide analogue to call here. A caller relying on this for "the
/// entire managed process tree is gone" (rather than "the one pid this
/// crate recorded is gone") is relying on a guarantee this function does
/// not provide; every current caller ([`crate::provisioning::lease::verify_process_absent`]
/// and its `full_uninstall`/`uninstall` consumers) only ever recorded a
/// single top-level pid per lease, so this divergence does not currently
/// under-verify their contract, but it must not be assumed to generalize
/// to a future caller that needs whole-tree absence.
///
/// `Some(true)`/`Some(false)` are a definitive live/dead verdict for that
/// pid; `None` means the query itself could not be answered (e.g.
/// `ERROR_ACCESS_DENIED` -- a process owned by a different, unrelated
/// principal, or `WaitForSingleObject` itself failing) and must be treated
/// as uncertain, never guessed either way -- exactly Unix's own `EPERM`
/// contract.
#[must_use]
pub fn test_alive(pid: u32) -> Option<bool> {
    match wht_corulix_process_win32::query_process_liveness(pid) {
        wht_corulix_process_win32::ProcessLiveness::Present => Some(true),
        wht_corulix_process_win32::ProcessLiveness::Absent => Some(false),
        wht_corulix_process_win32::ProcessLiveness::Uncertain => None,
    }
}

/// Drops the Job Object handle, which -- because [`contain`] set
/// `limit_kill_on_job_close` -- immediately terminates every process still
/// assigned to it.
pub fn terminate(containment: Containment) -> Result<(), ()> {
    drop(containment.job);
    Ok(())
}
