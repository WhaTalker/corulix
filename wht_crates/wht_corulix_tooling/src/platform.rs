// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Platform dispatch: the only place `#[cfg(unix)]`/`#[cfg(windows)]`
//! process-tree containment logic is selected. Both platform modules
//! expose the same four-function shape (`prepare`, `contain`, `terminate`,
//! `test_alive`) so `lib.rs`'s orchestration logic never itself branches
//! on platform. `contain` returns [`ContainOutcome`] (not a plain
//! `Option`) so that Windows's fail-closed "already terminated before it
//! could run uncontained" outcome (P17-W-R2) is a distinct, structurally
//! unmissable case every caller must handle -- not silently collapsed into
//! the same `None` Unix's own (near-unreachable) containment-absent case
//! reports.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{Containment, contain, prepare, terminate, test_alive};
#[cfg(windows)]
pub use windows::{Containment, contain, prepare, terminate, test_alive};

/// Outcome of attempting to place an already-spawned child under
/// process-tree containment. See the module docs for why this is a
/// three-way enum rather than `Option<Containment>`.
#[must_use]
pub enum ContainOutcome {
    /// Containment was established; the child is running (or, on
    /// Windows, has just been resumed from `CREATE_SUSPENDED`) and
    /// contained. Holds the handle later used to terminate the whole
    /// tree.
    Contained(Containment),
    /// No containment could be established, but the child was left
    /// running anyway. Only Unix's practically-unreachable
    /// `Pid::from_raw(0)` edge case (see `unix::contain`'s own doc)
    /// returns this -- callers proceed exactly as they did before
    /// containment support existed, with only the direct-child `wait()`
    /// this crate always performs.
    Uncontained,
    /// Containment could not be established, and -- to guarantee no
    /// user-mode instruction from this child is ever observed running
    /// uncontained -- this call has already terminated it before
    /// returning. Only Windows's assign-before-resume path
    /// (`windows::contain`) returns this: the child is spawned suspended
    /// (`CREATE_SUSPENDED` via `prepare`) and is only ever resumed after a
    /// successful Job Object assignment; if Job Object creation/
    /// configuration/assignment or the resume itself fails, this outcome
    /// guarantees the still-suspended (or, in the resume-failed case,
    /// already re-killed) child was terminated before this function
    /// returned. Callers must not proceed to treat the child as alive or
    /// select on `child.wait()` racing a timeout/cancellation as if it
    /// might still be running -- they still owe it exactly one `wait()`
    /// to reap the now-dead process (never a live/zombie leak), then must
    /// propagate this as a spawn/containment failure.
    // Only ever constructed by `windows::contain` -- on every other target
    // this variant exists purely so the shared, unconditional `match` in
    // `lib.rs`/`managed.rs` stays exhaustive and platform-independent
    // (never itself branching on `cfg(windows)`); rustc's `dead_code` lint
    // cannot see across that cross-platform contract, so it is silenced
    // here rather than by adding a needless per-platform `match` arm at
    // every call site.
    #[cfg_attr(not(windows), allow(dead_code))]
    TerminatedBeforeExecution,
}

/// Neither Unix nor Windows: no process-tree containment mechanism is
/// implemented for this target. `prepare` is a no-op, `contain` always
/// reports no containment handle, and any execution proceeds with only the
/// direct-child `wait()` this crate always performs -- never a claim of
/// tree containment this platform cannot back up.
#[cfg(not(any(unix, windows)))]
mod fallback {
    use super::ContainOutcome;

    pub struct Containment;

    pub fn prepare(_command: &mut tokio::process::Command) {}

    pub fn contain(_child: &tokio::process::Child) -> ContainOutcome {
        ContainOutcome::Uncontained
    }

    pub fn terminate(_containment: Containment) -> Result<(), ()> {
        Err(())
    }

    #[must_use]
    pub fn test_alive(_pid: u32) -> Option<bool> {
        None
    }
}

#[cfg(not(any(unix, windows)))]
pub use fallback::{Containment, contain, prepare, terminate, test_alive};
