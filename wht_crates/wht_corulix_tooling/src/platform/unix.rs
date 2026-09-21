// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Unix process-tree containment: a dedicated process group per controlled
//! child, terminated as a whole via `killpg` (`rustix::process::kill_process_group`)
//! rather than killing only the direct child.
//!
//! Residual risk, disclosed rather than hidden: a process group is a
//! cooperative Unix convention, not a hard security boundary. A
//! sufficiently privileged or deliberately hostile child can call
//! `setpgid`/`setsid` to leave the group this module places it in, and
//! nothing here can prevent that. What this module does guarantee is that
//! *ordinary* descendants -- the common case of a build tool spawning
//! compiler/linker subprocesses that never call `setpgid` themselves --
//! remain in the group and are terminated together with it.

use rustix::{
    io::Errno,
    process::{Pid, Signal, kill_process_group, test_kill_process_group},
};
use tokio::process::{Child, Command};

use super::ContainOutcome;

/// The process-group id of a contained child -- always equal to the
/// child's own pid, since [`prepare`] creates a brand-new group whose
/// leader is the child itself (`process_group(0)`).
pub struct Containment {
    group: Pid,
}

/// Places the about-to-be-spawned child into a brand-new process group
/// (`process_group(0)`: the child becomes its own group leader), rather
/// than inheriting this process's group. This must happen before `spawn`,
/// not after -- there is no way to retroactively change a running
/// process's group membership race-free from this side. `Command::process_group`
/// is available on `tokio::process::Command` because it delegates directly
/// to the same stable `std::os::unix::process::CommandExt` method this
/// crate used before adopting `tokio::process::Command`.
pub fn prepare(command: &mut Command) {
    command.process_group(0);
}

/// Records the contained child's process-group id for later termination.
/// `child.id()` returns `None` only once the child has already been
/// reaped, which cannot yet be true for a child [`contain`] is called on
/// immediately after a successful `spawn()`; a positive pid is otherwise
/// always returned, so this only returns [`ContainOutcome::Uncontained`]
/// in the practically-unreachable case of pid `0` (which `Pid::from_raw`
/// itself rejects) or an already-reaped child. Unlike Windows's
/// `TerminatedBeforeExecution` outcome, this never implies the child was
/// terminated -- it is left running, uncontained.
pub fn contain(child: &Child) -> ContainOutcome {
    #[allow(clippy::cast_possible_wrap)]
    let Some(raw_pid) = child.id().map(|pid| pid as i32) else {
        return ContainOutcome::Uncontained;
    };
    match Pid::from_raw(raw_pid) {
        Some(group) => ContainOutcome::Contained(Containment { group }),
        None => ContainOutcome::Uncontained,
    }
}

/// Checks whether the process group led by `pid` still exists, via
/// `kill(-pid, 0)` (`rustix::process::test_kill_process_group` --
/// validity/permission check only, no signal actually delivered). Takes a
/// raw pid rather than a [`Containment`] so a caller that no longer owns
/// (or never owned) the `Containment` handle -- e.g.
/// `provisioning::lease`'s absence verification, which only ever recorded
/// the pid at registration time -- can still ask this question; group ==
/// pid always holds for a [`contain`]ed child (see [`contain`]'s own doc).
/// `Some(true)`/`Some(false)` are a definitive live/dead verdict; `None`
/// means the check itself could not be answered (e.g. `EPERM` -- a group
/// owned by a different, unrelated user) and must be treated as uncertain,
/// never guessed either way.
#[must_use]
pub fn test_alive(pid: u32) -> Option<bool> {
    #[allow(clippy::cast_possible_wrap)]
    let Some(group) = Pid::from_raw(pid as i32) else {
        return Some(false);
    };
    match test_kill_process_group(group) {
        Ok(()) => Some(true),
        Err(Errno::SRCH) => Some(false),
        Err(_) => None,
    }
}

/// Sends `SIGKILL` to every process in the contained group at once (the
/// `killpg(-pid, SIGKILL)` semantics `kill_process_group` implements) --
/// not merely to the direct child.
pub fn terminate(containment: Containment) -> Result<(), ()> {
    kill_process_group(containment.group, Signal::KILL).map_err(|_| ())
}
