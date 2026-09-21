// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Sole owner of controlled external process construction and process-tree
//! containment for WhaTalker Corulix (Architecture Rule G).
//!
//! No other crate in this workspace may construct a `std::process::Command`,
//! a `tokio::process::Command`, or shell out to `sh -c`/`bash -c`/`cmd /C`/
//! `powershell -Command`. This crate receives an already-selected
//! [`ProcessSpec`] -- it never resolves *which* executable should run (that
//! is Phase 6's provider-resolution responsibility) and never decides
//! policy (that is `wht_corulix_engine`'s, Rule H). It only executes the
//! spec it is handed, under the canonical [`ExecutionClass::ControlledExternalTool`]
//! contract this module implements: typed argv (never a shell string),
//! an explicit environment allowlist (nothing ambient is inherited),
//! a controlled/explicit working directory, independently bounded
//! stdout/stderr capture, a required timeout, explicit cancellation, and
//! whole-process-tree termination (not merely the direct child) -- followed
//! by a wait/reap so no live child or zombie is ever left behind.
//!
//! # Async-first canonical execution
//!
//! [`execute`] is `async fn`, built on `tokio::process::Command`/`Child`
//! rather than `std::process::Command`/`Child`. There is no separate
//! synchronous canonical entry point kept alongside it: this crate has no
//! meaningfully expensive blocking CPU work to hide behind
//! `spawn_blocking` -- process spawn/wait/signal calls are already
//! Tokio's own async process/reactor primitives. Cancellation is served by
//! [`CancellationToken`], the one canonical cancellation primitive this
//! crate's callers (Engine, MCP, CLI) propagate down to; it deliberately
//! stays a plain `Arc<AtomicBool>` rather than adopting `tokio_util::sync::CancellationToken`,
//! since the existing type already satisfies every requirement (cheap,
//! `Clone`, thread-safe, callable from outside the async runtime) without
//! a new dependency.
//!
//! # What this is not
//!
//! This is deliberately **not** called a sandbox anywhere in this crate.
//! `CONTROLLED_EXTERNAL_TOOL` means typed argv, a controlled environment/cwd,
//! bounded output, and process-tree lifecycle management -- it does **not**
//! mean filesystem isolation, network isolation, container isolation, or VM
//! isolation. No OS-level sandbox is implemented or claimed here
//! (`OS_SANDBOX_CLAIMED=NO`), and sanitizing the child's environment is not
//! the same thing as denying it network access
//! (`NETWORK_ISOLATION_CLAIMED=NO`) -- a child process can still open its own
//! sockets unless a future phase adds real OS-level network isolation.
//!
//! # Residual risk (disclosed, not eliminated)
//!
//! On Unix, a child process can deliberately call `setpgid`/`fork`+`setsid`
//! to escape the process group this crate places it in; this crate makes no
//! claim that a hostile, [`ExecutionClass::TrustedWorkspaceExecution`]-class
//! program cannot intentionally escape containment -- only that ordinary
//! descendant processes (the common case: a build tool spawning compiler
//! subprocesses) remain contained and are terminated together.
//!
//! On Windows (P17-W-R2), `platform::windows` spawns the child
//! `CREATE_SUSPENDED`, assigns it to a Job Object with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` while it is still suspended, and
//! only resumes its primary thread once that assignment has succeeded --
//! closing the previously-disclosed spawn-then-assign race structurally,
//! not merely narrowing it. The one remaining Windows caveat is the same
//! kind of cooperative-boundary caveat Unix already has above: nothing
//! prevents a contained *grandchild or deeper descendant*, once running,
//! from itself calling a Windows API that breaks out of its own Job Object
//! membership (Windows historically required explicit
//! `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`/`JOB_OBJECT_LIMIT_BREAKAWAY_OK`
//! for that -- this module sets neither), which is a different, far
//! narrower claim than "the direct child can execute before containment".
//! The narrow Win32 FFI this requires (`ResumeThread` and the thread
//! enumeration needed to find the one suspended thread to resume) lives in
//! the separate `wht_corulix_process_win32` crate -- this crate's own
//! `#![forbid(unsafe_code)]` cannot itself host any `unsafe`, and `forbid`
//! cannot be locally overridden, so no code in this crate ever contains
//! raw Win32 FFI; see that crate's module docs for the full boundary
//! rationale.

mod managed;
pub mod managed_runtimes;
mod platform;
pub mod provisioning;

use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};
use wht_corulix_core::{CancellationToken, ExecutionClass};
use wht_corulix_workspace::WorkspaceRoot;

pub use managed::{
    ManagedProcess, ManagedProcessExit, ManagedProcessSpawnError, ManagedProcessSpec,
};

/// Bytes of leading child output retained before a bound is reached.
pub const DEFAULT_MAX_STDOUT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_STDERR_BYTES: usize = 1024 * 1024;

/// Poll granularity while awaiting cancellation. [`CancellationToken`] is a
/// plain, non-async-aware flag (see its own docs), so honoring `cancel()`
/// promptly means polling it on a short interval rather than blocking
/// indefinitely on an OS-level wakeup this token does not provide. Small
/// enough that cancellation is honored promptly; large enough not to
/// busy-loop the async runtime.
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// An explicit, allowlist-only child environment. The child's environment is
/// built **only** from the variables added here -- the parent's entire
/// ambient environment (including any credentials, tokens, or secrets it
/// happens to hold) is never inherited by default
/// (`CREDENTIAL_FORWARDING_DEFAULT=DENY`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvironmentPolicy {
    allowed: BTreeMap<String, String>,
}

impl EnvironmentPolicy {
    /// No variables forwarded at all -- the strictest, safest default.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Explicitly allows one variable through to the child, overwriting any
    /// prior value set for the same key.
    #[must_use]
    pub fn with_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.allowed.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.allowed.contains_key(key)
    }

    /// The value allowed through for `key`, if any -- lets a caller (e.g. a
    /// real E2E test) inspect exactly what one resolved launch's
    /// environment contains, without exposing the whole allowlist as a
    /// mutable/iterable collection.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.allowed.get(key).map(String::as_str)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.allowed
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

/// Independent byte bounds for captured stdout/stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessLimits {
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
        }
    }
}

/// A fully-specified, ready-to-execute external process. Never a free-form
/// shell command string: `arguments` are separate argv elements, passed to
/// the child directly and never interpreted by a shell.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: EnvironmentPolicy,
    pub working_directory: PathBuf,
    pub limits: ProcessLimits,
    pub timeout: Duration,
    /// Which [`ExecutionClass`] this spec is being executed under. Carried
    /// through for observability/evidence purposes only -- this crate does
    /// not branch its own behavior on this value; trust/class-based policy
    /// decisions belong to `wht_corulix_engine` (Rule H) and a later
    /// Phase 6 trust/config runtime.
    pub execution_class: ExecutionClass,
    /// Overrides the spawned process's own `argv[0]` (Unix only; ignored
    /// elsewhere) without changing which binary is actually executed.
    ///
    /// Some resolved providers are multi-call binaries that dispatch their
    /// behavior by inspecting their own invoked name (e.g. a `rustup`-managed
    /// toolchain, where `rustfmt` is a symlink to the `rustup` binary itself
    /// and `rustup` decides which tool to emulate by looking at `argv[0]`).
    /// `wht_corulix_config::resolve_provider` canonicalizes every resolved
    /// path (Rule K/Rule F) -- correctly, since that is what prevents a
    /// symlink-indirection trust bypass -- so the executable this crate
    /// spawns is the *resolved target*, not the original provider-named
    /// symlink, and a caller that needs proxy dispatch to keep working must
    /// restore the expected name here. This never changes trust or which
    /// file is executed: `Command::new`/`execve` always run the exact path
    /// in `executable`; only the string the child *observes* as its own
    /// `argv[0]` changes.
    pub argv0: Option<String>,
}

/// Captured child output, bounded independently of the other stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundedOutput {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// Why a controlled process's execution ended. Never collapsed into a
/// free-form string -- every variant is a structured, machine-matchable
/// fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    /// The process ran to completion and reported an exit code (`0` for a
    /// normal/successful exit, non-zero otherwise -- callers distinguish
    /// the two by inspecting `code`).
    Exited { code: i32 },
    /// The process was terminated by a signal rather than exiting normally
    /// (Unix only in practice; never produced on Windows).
    Signaled { signal: i32 },
    /// The configured timeout elapsed before the process exited; the whole
    /// process tree was terminated.
    TimedOut,
    /// The caller explicitly cancelled execution before the process
    /// exited; the whole process tree was terminated.
    Cancelled,
    /// The child process could not be spawned at all (e.g. the executable
    /// does not exist or is not executable). No process tree exists to
    /// terminate or reap.
    SpawnFailed,
    /// Termination of a timed-out/cancelled process tree was attempted but
    /// could not be confirmed to have succeeded.
    TerminationFailed,
}

/// The complete, deterministic outcome of one controlled execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub termination: TerminationReason,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
}

/// Executes `spec` under the canonical `CONTROLLED_EXTERNAL_TOOL` contract:
/// no shell, a bounded/allowlisted environment, an explicit working
/// directory, independently bounded stdout/stderr, a required timeout, and
/// whole-process-tree termination with a guaranteed wait/reap. Never
/// panics on a malformed process outcome -- every failure mode is a
/// [`TerminationReason`] variant, never a panic or an unbounded hang.
///
/// This is the canonical, single async entry point for controlled process
/// execution -- there is no separate synchronous `execute()` retained
/// alongside it. Every blocking OS primitive it still relies on
/// (`tokio::process::Command::spawn`'s underlying `fork`/`exec`,
/// `killpg`/Job-Object termination in `platform`) is a fast, bounded
/// syscall wrapped by Tokio's own process driver, not a substantial
/// blocking operation this crate would need to route through
/// `spawn_blocking` itself.
#[must_use]
pub async fn execute(spec: &ProcessSpec, cancellation: &CancellationToken) -> ExecutionOutcome {
    let mut command = Command::new(&spec.executable);
    command.args(&spec.arguments);
    command.current_dir(&spec.working_directory);
    run_prepared_command(command, spec, cancellation).await
}

/// As [`execute`], but binds the child's working directory to
/// `workspace_root`'s pinned root-directory object (M09-P7,
/// `M09_P7_UNIX_CWD_AUTHORITY=PINNED_ROOT_OBJECT`) via
/// [`WorkspaceRoot::bind_process_cwd`], instead of trusting
/// `spec.working_directory` as a re-resolvable pathname. Even if the
/// pathname at `spec.working_directory` is replaced -- by an ordinary
/// directory, a symlink, or an ancestor swap -- after this call, the spawned
/// child's cwd still resolves against the exact filesystem object
/// `workspace_root` pinned at its own construction time, never a re-walked
/// path.
///
/// `spec.working_directory` must equal `workspace_root.canonical_path()`.
/// This is a consistency assertion, never authority derivation --
/// `canonical_path()` remains display/logging metadata only, per
/// [`WorkspaceRoot`]'s own doc comment. A mismatch is a caller programming
/// error (binding a spec to the wrong root); this fails closed by refusing
/// to spawn ([`TerminationReason::SpawnFailed`]) rather than silently
/// executing against whichever directory the mismatched value names.
///
/// This is an additive entry point: [`execute`] and [`ProcessSpec`] are
/// unchanged, so every existing (including external, published) caller is
/// unaffected.
///
/// # M09-P10: no pathname-cwd equivalent on Windows
///
/// Unix binds the child's cwd to `workspace_root`'s pinned filesystem
/// OBJECT (see below) -- there is no Windows primitive that preserves that
/// same object-bound property across `exec` (no `fchdir`-equivalent, and a
/// path reconstructed from a P9 handle via `GetFinalPathNameByHandle` is
/// still just a pathname, re-walked by the OS at spawn time exactly like
/// any other `current_dir()` argument). Rather than silently downgrading
/// `TRUSTED_WORKSPACE_EXECUTION` callers to that weaker pathname-cwd
/// guarantee on Windows, this function fails closed there: it returns
/// [`TerminationReason::SpawnFailed`] before constructing any [`Command`]
/// at all (`M09_P10_WINDOWS_TRUSTED_WORKSPACE_SPAWN_COUNT=0`), reusing the
/// exact outcome/error shape every existing caller already maps to a typed
/// error for the ordinary "could not spawn" case -- no new public
/// vocabulary, no raw OS error, no schema change.
#[must_use]
pub async fn execute_with_workspace_root(
    spec: &ProcessSpec,
    workspace_root: &WorkspaceRoot,
    cancellation: &CancellationToken,
) -> ExecutionOutcome {
    if spec.working_directory.as_path() != workspace_root.canonical_path() {
        return ExecutionOutcome {
            termination: TerminationReason::SpawnFailed,
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
        };
    }
    #[cfg(not(unix))]
    {
        let _ = cancellation;
        ExecutionOutcome {
            termination: TerminationReason::SpawnFailed,
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
        }
    }
    #[cfg(unix)]
    {
        let mut command = Command::new(&spec.executable);
        command.args(&spec.arguments);
        workspace_root.bind_process_cwd(command.as_std_mut());
        run_prepared_command(command, spec, cancellation).await
    }
}

async fn run_prepared_command(
    mut command: Command,
    spec: &ProcessSpec,
    cancellation: &CancellationToken,
) -> ExecutionOutcome {
    #[cfg(unix)]
    if let Some(argv0) = &spec.argv0 {
        command.arg0(argv0);
    }
    // `env_clear` first: the child's environment is built *only* from the
    // explicit allowlist below, never from this process's ambient
    // environment.
    command.env_clear();
    // P17-W-R14: same real, native-Windows-verified `SystemRoot`
    // passthrough requirement as `ManagedProcess::spawn`'s own (see that
    // module's doc comment for the full root-cause evidence) -- this
    // one-shot path is the exact spawn shape `wht_corulix_engine::ts_validation`'s
    // `node lib/tsc.js`/`wht_corulix_engine::ts_testing`'s `node --test`
    // invocations use for TS6-managed `tsc`/Node-builtin test running, both
    // of which would hit the identical Node process-init CSPRNG abort on
    // Windows without this.
    #[cfg(target_os = "windows")]
    if let Ok(system_root) = std::env::var("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    for (key, value) in spec.environment.iter() {
        command.env(key, value);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    // This crate reaps explicitly (below) on every path; Tokio must never
    // race that with its own drop-triggered kill.
    command.kill_on_drop(false);
    platform::prepare(&mut command);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return ExecutionOutcome {
                termination: TerminationReason::SpawnFailed,
                stdout: BoundedOutput::default(),
                stderr: BoundedOutput::default(),
            };
        }
    };

    let mut containment = match platform::contain(&child) {
        platform::ContainOutcome::Contained(handle) => Some(handle),
        platform::ContainOutcome::Uncontained => None,
        platform::ContainOutcome::TerminatedBeforeExecution => {
            // Fail-closed (P17-W-R2): the child has already been
            // terminated before it could execute a single uncontained
            // instruction. Reap it now and report spawn failure directly
            // -- never fall through to the normal wait/timeout/cancel
            // race below, which assumes a potentially-live child.
            let _ = child.wait().await;
            return ExecutionOutcome {
                termination: TerminationReason::SpawnFailed,
                stdout: BoundedOutput::default(),
                stderr: BoundedOutput::default(),
            };
        }
    };

    // Stdout/stderr are drained on their own structured tasks for the
    // entire process lifetime, independently of the wait/timeout/cancel
    // race below, so that a full pipe buffer on one stream can never block
    // the child (and therefore can never deadlock this function) merely
    // because the other stream, or the bound itself, is being handled
    // separately. Both tasks are always joined below before this function
    // returns -- neither is a detached, unowned task.
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_reader = spawn_bounded_reader(stdout_pipe, spec.limits.max_stdout_bytes);
    let stderr_reader = spawn_bounded_reader(stderr_pipe, spec.limits.max_stderr_bytes);

    let termination = tokio::select! {
        status = child.wait() => status_to_termination(&status),
        () = tokio::time::sleep(spec.timeout) => {
            terminate_and_classify(&mut containment, TerminationReason::TimedOut)
        }
        () = await_cancellation(cancellation) => {
            terminate_and_classify(&mut containment, TerminationReason::Cancelled)
        }
    };

    // Whichever branch above won, the child may not be reaped yet: the
    // `wait()` branch already reaped it, but the timeout/cancellation
    // branches only requested termination. Awaiting `wait()` again is a
    // no-op once already resolved and the guaranteed reap step
    // (`WAIT_REAP_REQUIRED`) otherwise -- no execution path returns from
    // this function while the child remains unreaped.
    let _ = child.wait().await;

    let (stdout, stderr) = tokio::join!(stdout_reader, stderr_reader);
    let stdout = stdout.unwrap_or_default();
    let stderr = stderr.unwrap_or_default();

    ExecutionOutcome {
        termination,
        stdout,
        stderr,
    }
}

/// Resolves once `token` reports cancellation, polling on
/// [`CANCELLATION_POLL_INTERVAL`] since [`CancellationToken`] exposes no
/// async-aware wakeup of its own.
async fn await_cancellation(token: &CancellationToken) {
    while !token.is_cancelled() {
        tokio::time::sleep(CANCELLATION_POLL_INTERVAL).await;
    }
}

/// Consumes the containment handle (if any) and attempts to terminate the
/// whole process tree it represents, returning `on_success` if termination
/// was confirmed or `TerminationReason::TerminationFailed` otherwise (no
/// containment handle available, or the platform-specific termination call
/// itself failed).
fn terminate_and_classify(
    containment: &mut Option<platform::Containment>,
    on_success: TerminationReason,
) -> TerminationReason {
    match containment.take() {
        Some(handle) => platform::terminate(handle)
            .map_or(TerminationReason::TerminationFailed, |()| on_success),
        None => TerminationReason::TerminationFailed,
    }
}

fn status_to_termination(status: &std::io::Result<std::process::ExitStatus>) -> TerminationReason {
    match status {
        Ok(status) => {
            if let Some(code) = status.code() {
                TerminationReason::Exited { code }
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    TerminationReason::Signaled {
                        signal: status.signal().unwrap_or(0),
                    }
                }
                #[cfg(not(unix))]
                {
                    TerminationReason::TerminationFailed
                }
            }
        }
        Err(_) => TerminationReason::TerminationFailed,
    }
}

/// Spawns a structured task that drains `pipe` to completion, retaining at
/// most `limit` bytes and discarding (never buffering) anything beyond it.
/// Draining never stops early: a child that keeps writing past the bound
/// must never see its pipe fill up and block, which is what would create
/// exactly the deadlock this design avoids. The caller always joins the
/// returned handle (see [`execute`]) -- this is never a detached,
/// fire-and-forget task.
fn spawn_bounded_reader(
    pipe: Option<impl AsyncReadExt + Unpin + Send + 'static>,
    limit: usize,
) -> tokio::task::JoinHandle<BoundedOutput> {
    tokio::spawn(async move {
        let Some(mut pipe) = pipe else {
            return BoundedOutput::default();
        };
        let mut retained = Vec::new();
        let mut truncated = false;
        let mut discard = [0_u8; 8192];
        loop {
            let read_result = if retained.len() < limit {
                let mut chunk = vec![0_u8; (limit - retained.len()).min(8192)];
                pipe.read(&mut chunk).await.inspect(|&count| {
                    chunk.truncate(count);
                    retained.extend_from_slice(&chunk);
                })
            } else {
                truncated = true;
                pipe.read(&mut discard).await
            };
            match read_result {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        BoundedOutput {
            bytes: retained,
            truncated,
        }
    })
}

#[cfg(test)]
mod fixture_support;
#[cfg(test)]
mod tests;
