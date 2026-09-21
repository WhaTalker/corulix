// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! A controlled, long-lived (persistent) external process, for callers that
//! need a durable stdio session rather than [`crate::execute`]'s one-shot
//! spawn/wait/reap contract -- the LSP provider vertical is the first real
//! caller (a language server is a request/response session over stdio, not
//! a single bounded command invocation).
//!
//! Everything [`crate::execute`] already guarantees still applies here: no
//! shell, an explicit environment allowlist, an explicit working directory,
//! independently bounded stderr capture, whole-process-tree termination
//! (reusing the exact same [`crate::platform`] containment primitives), and
//! a guaranteed wait/reap on every path. This module owns process
//! *lifecycle* only -- it has no knowledge of JSON-RPC, LSP framing, or any
//! other protocol spoken over the pipes it exposes; that is the owning
//! provider crate's responsibility (e.g. `wht_corulix_lsp`).

use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::AsyncReadExt,
    process::{Child, ChildStdin, ChildStdout, Command},
};

use crate::{
    BoundedOutput, EnvironmentPolicy, platform,
    provisioning::lease::{ManagedExecutionLease, ManagedLeaseBinding, ProcessIdentity},
};
use wht_corulix_workspace::WorkspaceRoot;

/// A fully-specified, ready-to-spawn persistent process. Never a free-form
/// shell command string, mirroring [`crate::ProcessSpec`]'s own contract.
#[derive(Debug, Clone)]
pub struct ManagedProcessSpec {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: EnvironmentPolicy,
    pub working_directory: PathBuf,
    pub max_stderr_bytes: usize,
    /// Overrides the spawned process's own `argv[0]` (Unix only). See
    /// [`crate::ProcessSpec::argv0`]'s own docs for why this exists and why
    /// it never changes which binary is actually executed.
    pub argv0: Option<String>,
    /// `Some(binding)` if this process consumes Corulix-managed state for
    /// its entire run -- one or more `CORULIX_MANAGED` components, one
    /// managed root's execution scratch, or both.
    /// [`ManagedProcess::spawn`] registers a [`ManagedExecutionLease`] for
    /// it atomically before returning (Phase 7B-B1-R3-A §3-4).
    ///
    /// `None` for a process that consumes no Corulix-managed state at all
    /// -- a system/`HOST_ONLY` binary reading and writing only host-owned
    /// locations. Note that "resolved `HOST_ONLY`" alone is *not* the test:
    /// a `HOST_ONLY` binary that Corulix points at Corulix-owned scratch
    /// (the Engine's Go semantic session) does consume managed state and
    /// must be leased, which is exactly the Phase 15 gap
    /// [`ManagedLeaseBinding::managed_root_identity`] closes.
    pub managed_lease: Option<ManagedLeaseBinding>,
}

/// Why spawning a [`ManagedProcess`] failed. Never a panic -- an executable
/// that cannot be spawned is a normal, typed outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedProcessSpawnError {
    SpawnFailed,
}

/// How a [`ManagedProcess`] ended, returned by [`ManagedProcess::wait_for_exit`]
/// or [`ManagedProcess::terminate`]. Never collapsed into a free-form
/// string, mirroring [`crate::TerminationReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedProcessExit {
    Exited {
        code: i32,
    },
    Signaled {
        signal: i32,
    },
    /// [`ManagedProcess::wait_for_exit`]'s bound elapsed before the process
    /// exited on its own; the process is still running and was not
    /// terminated by this call.
    StillRunning,
    /// [`ManagedProcess::terminate`] confirmed whole-process-tree
    /// termination.
    Terminated,
    /// Termination was attempted but could not be confirmed to have
    /// succeeded.
    TerminationFailed,
}

/// A controlled, long-lived external process with an owned stdin/stdout
/// pair for an owning provider crate to frame its own protocol over.
/// stderr is drained continuously on its own structured task, bounded
/// exactly like [`crate::execute`]'s stdout/stderr capture, and is always
/// joined (never a detached, fire-and-forget task) by [`Self::wait_for_exit`]
/// or [`Self::terminate`].
pub struct ManagedProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr_task: Option<tokio::task::JoinHandle<BoundedOutput>>,
    containment: Option<platform::Containment>,
    reaped: bool,
    /// `Some` iff `spec.managed_lease` was `Some` at spawn time. Dropping
    /// this field (which happens whenever `self` is dropped -- natural
    /// exit via [`Self::wait_for_exit`] or explicit [`Self::terminate`])
    /// deregisters the lease, so no path through this type can leave a
    /// phantom lease behind.
    lease: Option<ManagedExecutionLease>,
}

impl ManagedProcess {
    /// Spawns `spec` under the same containment contract [`crate::execute`]
    /// uses: no shell, `env_clear` first (nothing ambient is inherited),
    /// the platform-specific process-group/Job-Object containment handle
    /// captured immediately after spawn.
    pub async fn spawn(spec: &ManagedProcessSpec) -> Result<Self, ManagedProcessSpawnError> {
        let mut command = Command::new(&spec.executable);
        command.args(&spec.arguments);
        command.current_dir(&spec.working_directory);
        Self::spawn_prepared(command, spec).await
    }

    /// As [`Self::spawn`], but binds the child's working directory to
    /// `workspace_root`'s pinned root-directory object (M09-P7) via
    /// [`WorkspaceRoot::bind_process_cwd`] instead of trusting
    /// `spec.working_directory` as a re-resolvable pathname -- see
    /// [`crate::execute_with_workspace_root`]'s own doc comment for the full
    /// rationale, which applies identically here. `spec.working_directory`
    /// must equal `workspace_root.canonical_path()` (a consistency
    /// assertion, never authority derivation); a mismatch fails closed as
    /// [`ManagedProcessSpawnError::SpawnFailed`] rather than spawning
    /// against a mismatched directory.
    ///
    /// Additive: [`Self::spawn`] and [`ManagedProcessSpec`] are unchanged.
    ///
    /// # M09-P10: no pathname-cwd equivalent on Windows
    ///
    /// Same rationale as [`crate::execute_with_workspace_root`]: Windows has
    /// no `fchdir`-equivalent primitive that preserves the pinned root's
    /// object identity across `exec`, so this fails closed there --
    /// [`ManagedProcessSpawnError::SpawnFailed`] before any [`Command`] is
    /// constructed (`M09_P10_WINDOWS_TRUSTED_WORKSPACE_SPAWN_COUNT=0`),
    /// reusing the existing spawn-failure vocabulary every caller (LSP
    /// session creation included) already maps to a typed error.
    pub async fn spawn_with_workspace_root(
        spec: &ManagedProcessSpec,
        workspace_root: &WorkspaceRoot,
    ) -> Result<Self, ManagedProcessSpawnError> {
        if spec.working_directory.as_path() != workspace_root.canonical_path() {
            return Err(ManagedProcessSpawnError::SpawnFailed);
        }
        #[cfg(not(unix))]
        {
            Err(ManagedProcessSpawnError::SpawnFailed)
        }
        #[cfg(unix)]
        {
            let mut command = Command::new(&spec.executable);
            command.args(&spec.arguments);
            workspace_root.bind_process_cwd(command.as_std_mut());
            Self::spawn_prepared(command, spec).await
        }
    }

    async fn spawn_prepared(
        mut command: Command,
        spec: &ManagedProcessSpec,
    ) -> Result<Self, ManagedProcessSpawnError> {
        #[cfg(unix)]
        if let Some(argv0) = &spec.argv0 {
            command.arg0(argv0);
        }
        command.env_clear();
        // P17-W-R14: real, native-Windows-verified requirement, the same
        // defect class `provisioning.rs`'s `go install` staging spawn
        // already found and fixed for DNS resolution -- a fully
        // `env_clear()`'d child on Windows with no `SystemRoot` is not
        // merely degraded, it is provably fatal for a managed Node
        // interpreter specifically: isolated by direct, minimal repro
        // against this exact managed-toolchain root's own real
        // `node-runtime`/`typescript-language-server` install
        // (`node.exe lib/cli.mjs --stdio`, piped stdio, no shell) --
        // without `SystemRoot`, Node's own process-init crypto seeding
        // aborts hard (`Assertion failed: ncrypto::CSPRNG(nullptr, 0)`,
        // `node::InitializeOncePerProcessInternal`), which
        // `wht_corulix_lsp::LspSession::spawn` observed only as an
        // immediately-closed transport (`Transport(Closed)`) -- never a
        // parseable error, since the child never reaches its own
        // JSON-RPC loop at all. This is the real root cause of the
        // Windows-native `real_typescript_6_managed_*_full_vertical_e2e`/
        // `real_ts6_managed_windows_hostile_path_and_cwd_decoy_e2e`
        // failures this pass found and closed. `SystemRoot` never
        // contributes executable search locations (unlike `PATH`), only
        // the fixed OS install directory (`C:\Windows`) Windows' own
        // system DLL loader already trusts implicitly -- passing it
        // through is not a containment regression. This applies to every
        // `ManagedProcess` on Windows (present callers: gopls, rust-analyzer,
        // typescript-language-server; future: Pyright), not only the Node
        // interpreter -- native Go/Rust managed servers happened not to
        // need it at process-init time, but nothing here is Node-specific
        // in principle, so the passthrough is unconditional rather than
        // gated on which provider is spawning.
        #[cfg(target_os = "windows")]
        if let Ok(system_root) = std::env::var("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        for (key, value) in spec.environment.iter() {
            command.env(key, value);
        }
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        // This module reaps explicitly on every path (see `wait_for_exit`/
        // `terminate`); Tokio must never race that with its own
        // drop-triggered kill.
        command.kill_on_drop(false);
        platform::prepare(&mut command);

        let mut child = command.spawn().map_err(|error| {
            // Root-cause observability (internal only -- `ManagedProcessSpawnError`'s
            // own public shape, `SpawnFailed` with no payload, is unchanged;
            // every caller up the stack, including `wht_corulix_lsp`'s
            // `LspError::ProviderSpawnFailed`, is unaffected). Before this
            // instrumentation the real `std::io::Error` from the OS-level
            // spawn attempt (e.g. `ENOENT`, `EACCES`, `EMFILE`) was
            // discarded entirely at this exact point.
            tracing::warn!(
                failure_stage = "LSP_PROCESS_SPAWN",
                io_error_kind = ?error.kind(),
                os_error_code = ?error.raw_os_error(),
                "managed process spawn failed"
            );
            ManagedProcessSpawnError::SpawnFailed
        })?;
        let containment = match platform::contain(&child) {
            platform::ContainOutcome::Contained(handle) => Some(handle),
            platform::ContainOutcome::Uncontained => None,
            platform::ContainOutcome::TerminatedBeforeExecution => {
                // Fail-closed (P17-W-R2): the child was already
                // terminated before it could execute a single uncontained
                // instruction. Reap it and report this the same way any
                // other spawn failure is reported -- never construct a
                // `ManagedProcess` around a child that can never actually
                // run.
                let _ = child.wait().await;
                return Err(ManagedProcessSpawnError::SpawnFailed);
            }
        };

        // Register the lease in the same synchronous block as `contain`,
        // immediately after a successful `spawn`, before this function
        // returns control to any other task -- the process is running and
        // the lease is already discoverable in the same breath
        // (`PROCESS_STARTED_WITHOUT_DISCOVERABLE_LEASE_WINDOW=0`, Phase
        // 7B-B1-R3-A §4). `child.id()` returning `None` here (already
        // reaped) is practically unreachable immediately post-spawn; such a
        // process is simply never leased rather than treated as a spawn
        // failure, since the direct child/stderr-drain path below still
        // handles it safely.
        let lease = spec.managed_lease.as_ref().and_then(|binding| {
            child.id().map(|pid| {
                ManagedExecutionLease::register(binding.clone(), ProcessIdentity { pid })
            })
        });

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let stderr_task = Some(spawn_bounded_stderr_reader(
            stderr_pipe,
            spec.max_stderr_bytes,
        ));

        Ok(Self {
            child,
            stdin,
            stdout,
            stderr_task,
            containment,
            reaped: false,
            lease,
        })
    }

    /// This process's registered execution lease, if `spec.managed_lease`
    /// was `Some` at spawn time. An owning provider crate (e.g.
    /// `wht_corulix_lsp::LspSession`) uses this to report readiness
    /// ([`ManagedExecutionLease::mark_active`]) and to race
    /// [`ManagedExecutionLease::wait_for_stop_request`] against its own
    /// protocol work.
    #[must_use]
    pub fn lease(&self) -> Option<&ManagedExecutionLease> {
        self.lease.as_ref()
    }

    /// A cheap, `'static`, cloneable handle to this process's lease (see
    /// `ManagedExecutionLease::waiter`), for a caller that needs to hand
    /// the "wait for a stop request" capability to a background task while
    /// this `ManagedProcess` itself stays elsewhere (e.g. behind a shared
    /// `Mutex` a session's own shutdown path also reaches into). `None` if
    /// this process was never leased.
    #[must_use]
    pub fn lease_waiter(&self) -> Option<crate::provisioning::lease::LeaseWaiter> {
        self.lease.as_ref().map(ManagedExecutionLease::waiter)
    }

    /// This process's own pid, for a caller that needs real OS-level
    /// evidence of the running process/process-group (e.g. a test proving
    /// real descendant containment, not merely asserting against the
    /// lease's opaque state). `None` once the child has already been
    /// reaped -- the same condition under which `Child::id()` itself
    /// returns `None`.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// The child's stdin, for an owning provider crate to write its own
    /// framed protocol messages to. `None` if already taken/the process has
    /// no stdin pipe.
    pub fn stdin(&mut self) -> Option<&mut ChildStdin> {
        self.stdin.as_mut()
    }

    /// The child's stdout, for an owning provider crate to read its own
    /// framed protocol messages from. `None` if already taken/the process
    /// has no stdout pipe.
    pub fn stdout(&mut self) -> Option<&mut ChildStdout> {
        self.stdout.as_mut()
    }

    /// Takes ownership of both stdin/stdout pipes at once, for a caller
    /// (e.g. `wht_corulix_lsp::Transport`) that needs to move them into its
    /// own `'static` background tasks rather than borrowing them. `None`
    /// if either pipe was already taken or is absent.
    pub fn take_io(&mut self) -> Option<(ChildStdin, ChildStdout)> {
        let stdin = self.stdin.take()?;
        let stdout = self.stdout.take()?;
        Some((stdin, stdout))
    }

    /// Awaits the process exiting on its own within `timeout`, without
    /// requesting termination. Used for a graceful-shutdown window (e.g.
    /// after a protocol-level exit notification) before escalating to
    /// [`Self::terminate`]. Reaps the child on a natural exit; leaves it
    /// running (and unreaped) on [`ManagedProcessExit::StillRunning`].
    pub async fn wait_for_exit(&mut self, timeout: Duration) -> ManagedProcessExit {
        if self.reaped {
            return ManagedProcessExit::Exited { code: 0 };
        }
        tokio::select! {
            status = self.child.wait() => {
                self.reaped = true;
                status_to_exit(&status)
            }
            () = tokio::time::sleep(timeout) => ManagedProcessExit::StillRunning,
        }
    }

    /// Terminates the whole process tree (reusing the exact same
    /// platform-specific containment primitives [`crate::execute`] uses),
    /// then performs the guaranteed wait/reap and joins the stderr-drain
    /// task. Consumes `self`: a terminated [`ManagedProcess`] is never
    /// reused.
    pub async fn terminate(mut self) -> ManagedProcessExit {
        let exit = if self.reaped {
            ManagedProcessExit::Terminated
        } else {
            match self.containment.take() {
                Some(handle) => match platform::terminate(handle) {
                    Ok(()) => {
                        let _ = self.child.wait().await;
                        self.reaped = true;
                        ManagedProcessExit::Terminated
                    }
                    Err(()) => ManagedProcessExit::TerminationFailed,
                },
                None => {
                    // No containment handle (already consumed, or the
                    // platform has none) -- still reap the direct child so
                    // no live process/zombie is left behind, even though
                    // whole-tree containment cannot be confirmed here.
                    let _ = self.child.start_kill();
                    let _ = self.child.wait().await;
                    self.reaped = true;
                    ManagedProcessExit::TerminationFailed
                }
            }
        };
        if let Some(task) = self.stderr_task.take() {
            let _ = task.await;
        }
        exit
    }
}

fn status_to_exit(status: &std::io::Result<std::process::ExitStatus>) -> ManagedProcessExit {
    match status {
        Ok(status) => {
            if let Some(code) = status.code() {
                ManagedProcessExit::Exited { code }
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    ManagedProcessExit::Signaled {
                        signal: status.signal().unwrap_or(0),
                    }
                }
                #[cfg(not(unix))]
                {
                    ManagedProcessExit::TerminationFailed
                }
            }
        }
        Err(_) => ManagedProcessExit::TerminationFailed,
    }
}

/// Mirrors [`crate::spawn_bounded_reader`]'s draining/bounding behavior for
/// stderr specifically -- never buffers past `limit`, never stops draining
/// early (so a chatty child can never block on a full pipe), and is always
/// joined by [`ManagedProcess::wait_for_exit`]/[`ManagedProcess::terminate`],
/// never left detached.
fn spawn_bounded_stderr_reader(
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
mod tests {
    use super::*;

    fn spec(executable: &str, arguments: &[&str]) -> ManagedProcessSpec {
        ManagedProcessSpec {
            executable: PathBuf::from(executable),
            arguments: arguments.iter().map(|s| s.to_string()).collect(),
            environment: EnvironmentPolicy::empty(),
            working_directory: std::env::temp_dir(),
            max_stderr_bytes: 4096,
            argv0: None,
            managed_lease: None,
        }
    }

    /// Builds a `ManagedProcessSpec` targeting the cross-platform
    /// `wht_corulix_process_fixture` binary (P17-W-R3-C2), resolved and
    /// built on demand via `escargot` -- replaces the previous hardcoded
    /// `/bin/cat`, `/bin/true`, `/bin/sleep` targets, none of which exist
    /// on Windows.
    fn fixture_spec(fixture_args: &[&str]) -> Result<ManagedProcessSpec, String> {
        let executable = crate::fixture_support::fixture_binary_path()?;
        Ok(ManagedProcessSpec {
            executable,
            arguments: fixture_args.iter().map(|s| s.to_string()).collect(),
            environment: EnvironmentPolicy::empty(),
            working_directory: std::env::temp_dir(),
            max_stderr_bytes: 4096,
            argv0: None,
            managed_lease: None,
        })
    }

    /// Serializes every test that drives `spawn_prepared`'s real
    /// `Command::spawn()` failure path against a bad executable path --
    /// this crate has exactly two (`spawn_failure_is_typed_not_panicked`
    /// here and `spawn_failure_emits_lsp_process_spawn_diagnostic` below).
    /// Both hit the identical `tracing::warn!` callsite inside
    /// `spawn_prepared`'s `map_err`; `tracing`'s callsite `Interest` cache
    /// is a process-global static, and running these two under cargo
    /// test's default parallel harness lets one thread's ambient (no
    /// subscriber installed) invocation permanently cache that callsite as
    /// uninteresting before the other thread's own
    /// `tracing::subscriber::set_default` is ever active -- proven
    /// empirically (3/8 full-crate reruns dropped the diagnostic event
    /// under default parallelism, 0/8 once these two tests were
    /// serialized against each other). A mutex around exactly these two
    /// call sites removes the race mechanically; it never masks a
    /// different root cause, since this crate has no other caller of this
    /// exact failure path.
    static SPAWN_FAILURE_CALLSITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn spawn_failure_is_typed_not_panicked() {
        let _serial = SPAWN_FAILURE_CALLSITE_LOCK.lock().await;
        let result = ManagedProcess::spawn(&spec("/nonexistent/not-a-real-binary", &[])).await;
        assert_eq!(result.err(), Some(ManagedProcessSpawnError::SpawnFailed));
    }

    /// A minimal, hand-rolled [`tracing::Subscriber`] that records only the
    /// `failure_stage` field of every event it observes -- deliberately not
    /// `tracing-subscriber` (not a dependency of this crate) to avoid adding
    /// any new dependency for a diagnostic-verification test. Root-cause
    /// observability instrumentation (managed-process spawn): proves the
    /// internal `LSP_PROCESS_SPAWN` diagnostic actually fires on a real OS
    /// spawn failure, not merely that the code compiles.
    struct FailureStageRecorder {
        stages: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl tracing::field::Visit for FailureStageRecorder {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "failure_stage"
                && let Ok(mut stages) = self.stages.lock()
            {
                stages.push(format!("{value:?}"));
            }
        }
    }

    struct CapturingSubscriber {
        captured: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl tracing::Subscriber for CapturingSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = FailureStageRecorder {
                stages: self.captured.clone(),
            };
            event.record(&mut visitor);
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Diagnostic-observability test (not a provider-functionality test):
    /// proves the internal failure-stage instrumentation added to
    /// `spawn_prepared`'s real `Command::spawn()` error path actually
    /// distinguishes `LSP_PROCESS_SPAWN` as its own tagged failure class,
    /// captured via a real `tracing::Subscriber` -- never inferred from the
    /// public `ManagedProcessSpawnError::SpawnFailed` return value alone,
    /// which carries no internal detail. `#[tokio::test]`'s default
    /// current-thread runtime is required here: `tracing::subscriber::set_default`
    /// is thread-local, and this test's `.await` points must stay on the
    /// same thread that installed the subscriber.
    #[tokio::test]
    async fn spawn_failure_emits_lsp_process_spawn_diagnostic() -> Result<(), String> {
        let _serial = SPAWN_FAILURE_CALLSITE_LOCK.lock().await;
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = tracing::subscriber::set_default(CapturingSubscriber {
            captured: captured.clone(),
        });
        let result = ManagedProcess::spawn(&spec("/nonexistent/not-a-real-binary", &[])).await;
        assert_eq!(result.err(), Some(ManagedProcessSpawnError::SpawnFailed));
        let stages = captured
            .lock()
            .map_err(|_| "captured-stages mutex poisoned".to_string())?;
        assert!(
            stages
                .iter()
                .any(|stage| stage.contains("LSP_PROCESS_SPAWN")),
            "expected a captured tracing event tagging failure_stage=LSP_PROCESS_SPAWN, got: {stages:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stdin_stdout_are_available_after_spawn() -> Result<(), String> {
        // Any long-lived process with real stdio handles proves this
        // contract; the test never writes to or reads from the pipes, it
        // only asserts the handles exist and the process can be
        // terminated -- `sleep-ms` is sufficient and portable.
        let mut process = ManagedProcess::spawn(&fixture_spec(&["sleep-ms", "30000"])?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert!(process.stdin().is_some());
        assert!(process.stdout().is_some());
        let exit = process.terminate().await;
        assert_eq!(exit, ManagedProcessExit::Terminated);
        Ok(())
    }

    #[tokio::test]
    async fn natural_exit_is_observed_by_wait_for_exit() -> Result<(), String> {
        let mut process = ManagedProcess::spawn(&fixture_spec(&["exit-code", "0"])?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        let exit = process.wait_for_exit(Duration::from_secs(5)).await;
        assert_eq!(exit, ManagedProcessExit::Exited { code: 0 });
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_exit_reports_still_running_within_bound() -> Result<(), String> {
        let mut process = ManagedProcess::spawn(&fixture_spec(&["sleep-ms", "5000"])?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        let exit = process.wait_for_exit(Duration::from_millis(50)).await;
        assert_eq!(exit, ManagedProcessExit::StillRunning);
        let terminated = process.terminate().await;
        assert_eq!(terminated, ManagedProcessExit::Terminated);
        Ok(())
    }

    #[tokio::test]
    async fn terminate_kills_a_long_running_process() -> Result<(), String> {
        let process = ManagedProcess::spawn(&fixture_spec(&["sleep-ms", "30000"])?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        let exit = process.terminate().await;
        assert_eq!(exit, ManagedProcessExit::Terminated);
        Ok(())
    }
}
