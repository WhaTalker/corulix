// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Controlled, stdin/stdout-only rustfmt invocation, built exclusively on
//! `wht_corulix_tooling::ManagedProcess` (Architecture Rule G: only Tooling
//! constructs external processes).
//!
//! # Why stdin/stdout, not a file (empirically researched)
//!
//! `rustfmt --emit stdout` was verified (against the installed
//! `rustfmt 1.9.0-stable`) to accept source on stdin when no file argument
//! is given, and to write the formatted result to stdout only -- no
//! filesystem path is ever named, so no filesystem write of any kind can
//! occur on rustfmt's side. This is a *stronger* guarantee than writing to
//! a Corulix-controlled staging directory and pointing rustfmt at that
//! path: there is no path at all for rustfmt to touch. This module never
//! passes a positional file path to rustfmt for that reason (doing so was
//! also verified to force rustfmt to read the file's bytes from disk,
//! silently ignoring stdin -- unusable for formatting proposed bytes that
//! may differ from whatever currently sits on disk).
//!
//! `wht_corulix_tooling::execute` cannot be used here: its `ProcessSpec`
//! hardcodes `stdin(Stdio::null())`, since no prior caller needed to write
//! to a child's stdin. `ManagedProcess` (built for the LSP vertical, but
//! generic over any persistent-stdio process) is reused instead -- this
//! module owns only the read/write *protocol* over the pipes it exposes
//! (write once, close stdin for EOF, drain stdout to a bound), exactly as
//! `wht_corulix_lsp::transport` already does for JSON-RPC framing. No new
//! process runtime is introduced.

use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wht_corulix_core::CancellationToken;
use wht_corulix_tooling::{
    EnvironmentPolicy, ManagedProcess, ManagedProcessExit, ManagedProcessSpec,
};

/// Bytes of leading rustfmt stdout retained before this module stops
/// buffering (and instead discards, flagging `truncated`). A truncated
/// result is never treated as usable formatted output by this crate's
/// caller (see `crate::format_and_apply`).
pub(crate) const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
/// Bound on rustfmt's own stderr capture -- this module never reads it back
/// (`ManagedProcess` exposes no public accessor for the drained bytes), but
/// the bound must still be finite so the internal drain task cannot buffer
/// unboundedly.
pub(crate) const MAX_STDERR_BYTES: usize = 1024 * 1024;
/// Poll granularity while awaiting cancellation, matching
/// `wht_corulix_tooling::execute`'s own interval for the same reason: a
/// plain, non-async-aware flag has no wakeup of its own.
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(25);
/// A short, fixed bound for reaping the process's exit code once its
/// stdout has already reached EOF (rustfmt closes its pipes only when it
/// is exiting) -- deliberately independent of the caller's overall
/// `timeout`, so a slow reap can never silently double the effective
/// timeout budget.
const EXIT_REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// M09-P7 cwd-authority model for one [`invoke_formatter`] call: either a
/// pinned, real workspace object (the real format-and-apply path) or an
/// explicit, deliberately non-workspace host path (this module's own
/// version-probe/unit-test callers, which never claim workspace authority).
/// Never both -- callers construct exactly one variant, never a bare
/// [`Path`] whose authority is otherwise ambiguous.
pub(crate) enum FormatterCwd<'a> {
    /// The real, pinned [`wht_corulix_workspace::WorkspaceRoot`] this
    /// invocation must execute against -- `working_directory` on the
    /// resulting spec must equal this root's own `canonical_path()`,
    /// checked by [`wht_corulix_tooling::ManagedProcess::spawn_with_workspace_root`]
    /// itself.
    /// M09-P10: on Windows this variant's inner root is intentionally never
    /// read (a controlled non-workspace directory is used for cwd instead,
    /// see [`invoke_formatter`]'s own doc comment) -- `dead_code` would
    /// otherwise fire on a Windows build.
    #[cfg_attr(not(unix), allow(dead_code))]
    PinnedWorkspace(&'a wht_corulix_workspace::WorkspaceRoot),
    /// A deliberately non-workspace path (e.g. a temp directory used only
    /// for a version probe or this module's own unit tests) -- never
    /// treated as workspace authority. This crate's real version probe
    /// (`crate::fetch_provider_version`) currently builds its own
    /// `wht_corulix_tooling::ProcessSpec`/`execute` call directly rather than
    /// going through [`invoke_formatter`], so today this variant is
    /// exercised only by this module's own unit tests below -- `dead_code`
    /// would otherwise fire on a non-test build.
    #[allow(dead_code)]
    ExplicitHostPath(&'a Path),
}

impl FormatterCwd<'_> {
    #[cfg(unix)]
    fn as_path(&self) -> &Path {
        match self {
            Self::PinnedWorkspace(root) => root.canonical_path(),
            Self::ExplicitHostPath(path) => path,
        }
    }
}

/// The typed, non-panicking outcome of one rustfmt invocation attempt.
/// Never collapsed into a single "it failed" boolean: each variant is a
/// distinct, machine-matchable fact this module's caller maps onto
/// [`crate::FormatStatus`].
#[derive(Debug)]
pub(crate) enum InvocationOutcome {
    /// rustfmt exited; `stdout` holds up to [`MAX_STDOUT_BYTES`] of its
    /// captured output. A non-zero `exit_code` or `stdout_truncated == true`
    /// both mean the caller must not treat `stdout` as usable formatted
    /// content.
    Completed {
        stdout: Vec<u8>,
        stdout_truncated: bool,
        exit_code: i32,
    },
    /// rustfmt was terminated by a signal rather than exiting normally.
    Signaled,
    /// The rustfmt executable could not be spawned, or its stdin/stdout
    /// pipes were unexpectedly unavailable immediately after spawn.
    SpawnFailed,
    /// The configured timeout elapsed before rustfmt exited; the whole
    /// process tree was terminated.
    TimedOut,
    /// The caller's `CancellationToken` was observed before rustfmt
    /// exited; the whole process tree was terminated.
    Cancelled,
    /// A `CORULIX_MANAGED` uninstall requested this process stop (real
    /// [`wht_corulix_tooling::provisioning::lease::LeaseWaiter::wait_for_stop_request`]
    /// signal, observed while rustfmt was still genuinely running); the
    /// process was terminated in response, exactly as
    /// `wht_corulix_lsp::LspSession`'s own lease-stop task does. Only
    /// reachable when this invocation used a `CORULIX_MANAGED` rustfmt
    /// (`managed_lease: Some(...)`) -- the `HOST_ONLY`/system path is never
    /// leased and can never observe a stop request.
    StoppedForUninstall,
}

/// Spawns `executable` with `arguments` under `working_directory`, writes
/// `input` to its stdin, closes stdin (signaling EOF), and drains stdout to
/// a bound -- all raced against `timeout` and `cancellation`. Never
/// forwards any ambient environment variable to the child beyond what
/// `environment` explicitly allowlists
/// (`CREDENTIAL_FORWARDING_DEFAULT=DENY`) -- the `HOST_ONLY`/system
/// resolution path always passes `EnvironmentPolicy::empty()` exactly as
/// before Phase 7B-B2-B; only a `CORULIX_MANAGED` rustfmt resolution adds
/// `LD_LIBRARY_PATH` (see `crate::managed::resolve_formatter`'s own doc
/// comment for why that specific variable, and only that one, is required).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn invoke_formatter(
    executable: &Path,
    argv0: Option<String>,
    arguments: Vec<String>,
    cwd: FormatterCwd<'_>,
    input: &[u8],
    environment: EnvironmentPolicy,
    managed_lease: Option<wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding>,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> InvocationOutcome {
    // M09-P10: Windows has no `fchdir`-equivalent primitive that preserves
    // `PinnedWorkspace`'s object-bound cwd guarantee across `exec`, so
    // `spawn_with_workspace_root` cannot be used there for this invocation
    // the way it is on Unix. Unlike the `TrustedWorkspaceExecution`
    // engine/LSP call sites, this does not fail closed: rustfmt's actual
    // invocation contract was empirically confirmed cwd-independent for
    // this module's real production caller (`crate::format_and_apply`) --
    // input arrives on stdin, output leaves on stdout (no file path is ever
    // named, so rustfmt cannot read or write anything relative to cwd),
    // and the one cwd-relative behavior rustfmt has by default (repository
    // `rustfmt.toml`/`.rustfmt.toml` discovery) is bypassed entirely: the
    // caller resolves that file itself (`crate::config_discovery`, a pure
    // read, never a process spawn) and passes it explicitly via
    // `--config-path`. Edition resolution was verified the same way,
    // directly against the installed `rustfmt 1.9.0-stable`: with no
    // `--edition` flag (this module never passes one) and no `edition` key
    // in the discovered config, bare `rustfmt` accepted an edition-2018+-only
    // reserved identifier regardless of whether cwd contained a Cargo.toml
    // declaring `edition = "2021"` -- proving bare `rustfmt` (unlike `cargo
    // fmt`) never consults a Cargo.toml for edition, so cwd carries no
    // formatting-relevant authority. A controlled, non-workspace, Corulix
    // process-owned directory is therefore used on Windows in place of the
    // real workspace root (`WINDOWS_FORMATTER_SAFE_NON_WORKSPACE_EXECUTION`)
    // -- this changes only *which* non-authoritative directory the process
    // is told is its cwd, never what rustfmt actually reads or writes.
    #[cfg(unix)]
    let working_directory = cwd.as_path().to_path_buf();
    #[cfg(not(unix))]
    let working_directory = match cwd {
        FormatterCwd::PinnedWorkspace(_) => std::env::temp_dir(),
        FormatterCwd::ExplicitHostPath(path) => path.to_path_buf(),
    };

    let spec = ManagedProcessSpec {
        executable: executable.to_path_buf(),
        arguments,
        environment,
        working_directory,
        max_stderr_bytes: MAX_STDERR_BYTES,
        argv0,
        // `Some((rustfmt, [rust-semantic-runtime]))` iff this invocation
        // resolved a `CORULIX_MANAGED` rustfmt (Phase 7B-B2-B-R1) -- the
        // `HOST_ONLY`/system path passes `None` (Corulix does not own that
        // binary's lifecycle in the uninstall sense, matching every other
        // provider's convention). rustfmt being a one-shot, bounded
        // invocation rather than a persistent session does not exempt it
        // from leasing: a real, genuinely long-running invocation (a
        // pathological/oversized input approaching `DEFAULT_TIMEOUT`) is
        // exactly the window `provisioning::uninstall`/`full_uninstall`'s
        // own `ActiveExecutionBusy`/process-preflight checks exist to
        // protect against, and those checks are inert for any component id
        // with zero registered leases.
        managed_lease,
    };

    // M09-P7: `PinnedWorkspace` binds the child's cwd to the real workspace
    // root object on Unix. On Windows (M09-P10), `working_directory` was
    // already redirected above to a controlled non-workspace directory, so
    // a plain, non-object-bound spawn is correct there -- this invocation
    // does not (and, on Windows, cannot) claim workspace-object cwd
    // authority. An `ExplicitHostPath` invocation (version probes, this
    // module's own unit tests) never claims workspace authority on either
    // platform.
    #[cfg(unix)]
    let spawn_result = match cwd {
        FormatterCwd::PinnedWorkspace(root) => {
            ManagedProcess::spawn_with_workspace_root(&spec, root).await
        }
        FormatterCwd::ExplicitHostPath(_) => ManagedProcess::spawn(&spec).await,
    };
    #[cfg(not(unix))]
    let spawn_result = ManagedProcess::spawn(&spec).await;

    let mut process = match spawn_result {
        Ok(process) => process,
        Err(_) => return InvocationOutcome::SpawnFailed,
    };
    let lease_waiter = process.lease_waiter();
    if let Some(waiter) = &lease_waiter {
        waiter.mark_active();
    }

    let Some((mut stdin, mut stdout)) = process.take_io() else {
        let _ = process.terminate().await;
        return InvocationOutcome::SpawnFailed;
    };

    let input = input.to_vec();
    let write_and_read = async move {
        // A write failure here (e.g. a broken pipe because the child
        // already exited without consuming all of stdin, as a
        // fail-fast tool like `false` does) is not treated as this whole
        // invocation failing -- the child's real exit code, reaped below,
        // is still the authoritative outcome. Only the captured stdout is
        // necessarily incomplete/empty in that case.
        let _ = stdin.write_all(&input).await;
        // Dropping the owned `ChildStdin` closes the write end, which is
        // exactly how a piped-stdin consumer (rustfmt included) is told
        // "no more input" -- there is no other EOF signal available over a
        // pipe.
        drop(stdin);

        let mut retained = Vec::new();
        let mut truncated = false;
        let mut discard = [0_u8; 8192];
        loop {
            let read_result = if retained.len() < MAX_STDOUT_BYTES {
                let mut chunk = vec![0_u8; (MAX_STDOUT_BYTES - retained.len()).min(8192)];
                stdout.read(&mut chunk).await.inspect(|&count| {
                    chunk.truncate(count);
                    retained.extend_from_slice(&chunk);
                })
            } else {
                truncated = true;
                stdout.read(&mut discard).await
            };
            match read_result {
                Ok(0) => break,
                Ok(_) => {}
                // Same reasoning as the write failure above: a read error
                // on stdout does not itself invalidate the invocation --
                // the reaped exit code below remains authoritative.
                Err(_) => break,
            }
        }
        (retained, truncated)
    };

    tokio::select! {
        (stdout_bytes, stdout_truncated) = write_and_read => {
            match process.wait_for_exit(EXIT_REAP_TIMEOUT).await {
                ManagedProcessExit::Exited { code } => InvocationOutcome::Completed {
                    stdout: stdout_bytes,
                    stdout_truncated,
                    exit_code: code,
                },
                ManagedProcessExit::Signaled { .. } => InvocationOutcome::Signaled,
                ManagedProcessExit::StillRunning => {
                    // stdout already reached EOF, but the process itself
                    // did not exit within the short reap bound -- treat
                    // this the same as any other timeout and terminate
                    // the whole tree rather than leaving it running.
                    let _ = process.terminate().await;
                    InvocationOutcome::TimedOut
                }
                ManagedProcessExit::Terminated | ManagedProcessExit::TerminationFailed => {
                    InvocationOutcome::SpawnFailed
                }
            }
        }
        () = tokio::time::sleep(timeout) => {
            let _ = process.terminate().await;
            InvocationOutcome::TimedOut
        }
        () = await_cancellation(cancellation) => {
            let _ = process.terminate().await;
            InvocationOutcome::Cancelled
        }
        () = await_stop_request(&lease_waiter) => {
            let _ = process.terminate().await;
            if let Some(waiter) = &lease_waiter {
                waiter.acknowledge_stopped();
            }
            InvocationOutcome::StoppedForUninstall
        }
    }
}

async fn await_cancellation(token: &CancellationToken) {
    while !token.is_cancelled() {
        tokio::time::sleep(CANCELLATION_POLL_INTERVAL).await;
    }
}

/// Races real [`wht_corulix_tooling::provisioning::lease::LeaseWaiter::wait_for_stop_request`]
/// alongside `invoke_formatter`'s other `select!` arms; never resolves at all
/// when `waiter` is `None` (the `HOST_ONLY`/system path, never leased) --
/// `std::future::pending` rather than an early return, so this arm simply
/// never wins the race for that path, exactly the same technique
/// `await_cancellation`'s sibling arms rely on for their own "only some
/// invocations care about this" inputs.
async fn await_stop_request(
    waiter: &Option<wht_corulix_tooling::provisioning::lease::LeaseWaiter>,
) {
    match waiter {
        Some(waiter) => waiter.wait_for_stop_request().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_support;

    type TestResult = Result<(), String>;

    /// M09-P10 test-only helper: extracts one string field's value out of
    /// the portable fixture's own single-line JSON stdout payload (e.g.
    /// `{"mode":"print-cwd","cwd":"C:\\Users\\...","cwd_hex":"..."}`),
    /// backslash-escape-aware (a Windows path's own `\` is escaped to `\\`
    /// in the fixture's JSON output) -- deliberately not a dependency on a
    /// JSON crate (this crate has no `serde_json` dependency to add just
    /// for one test), only enough hand-rolled parsing for this one known,
    /// narrow, self-controlled payload shape.
    #[cfg(windows)]
    fn extract_json_string_field(json: &str, field: &str) -> Option<String> {
        let needle = format!("\"{field}\":\"");
        let start = json.find(&needle)? + needle.len();
        let mut result = String::new();
        let mut chars = json[start..].chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return Some(result),
                '\\' => match chars.next()? {
                    '\\' => result.push('\\'),
                    '"' => result.push('"'),
                    'n' => result.push('\n'),
                    't' => result.push('\t'),
                    other => result.push(other),
                },
                other => result.push(other),
            }
        }
        None
    }

    #[tokio::test]
    async fn nonexistent_executable_is_spawn_failed() {
        let cancellation = CancellationToken::new();
        let outcome = invoke_formatter(
            Path::new("/nonexistent/not-a-real-rustfmt"),
            None,
            Vec::new(),
            FormatterCwd::ExplicitHostPath(&std::env::temp_dir()),
            b"fn main() {}",
            EnvironmentPolicy::empty(),
            None,
            Duration::from_secs(5),
            &cancellation,
        )
        .await;
        assert!(matches!(outcome, InvocationOutcome::SpawnFailed));
    }

    #[tokio::test]
    async fn cat_echoes_stdin_to_stdout_with_exit_zero() -> TestResult {
        // The `echo-stdin` fixture mode stands in for a well-behaved
        // stdin/stdout tool here (portable across every platform Corulix
        // targets, including native Windows where there is no `/bin/cat`)
        // -- this test proves the write/EOF/drain protocol itself (not
        // rustfmt-specific behavior), which the real rustfmt E2E test
        // elsewhere in this crate covers separately.
        let fixture = fixture_support::fixture_binary_path()?;
        let cancellation = CancellationToken::new();
        let outcome = invoke_formatter(
            &fixture,
            None,
            vec!["echo-stdin".to_string()],
            FormatterCwd::ExplicitHostPath(&std::env::temp_dir()),
            b"hello from corulix formatter",
            EnvironmentPolicy::empty(),
            None,
            Duration::from_secs(5),
            &cancellation,
        )
        .await;
        let InvocationOutcome::Completed {
            stdout,
            stdout_truncated,
            exit_code,
        } = outcome
        else {
            return Err("expected InvocationOutcome::Completed".to_string());
        };
        assert_eq!(exit_code, 0);
        assert!(!stdout_truncated);
        assert_eq!(stdout, b"hello from corulix formatter");
        Ok(())
    }

    #[tokio::test]
    async fn nonzero_exit_is_reported_not_panicked() -> TestResult {
        let fixture = fixture_support::fixture_binary_path()?;
        let cancellation = CancellationToken::new();
        // `exit-code 1` ignores stdin and exits 1 immediately -- the
        // portable stand-in for `/bin/false`.
        let outcome = invoke_formatter(
            &fixture,
            None,
            vec!["exit-code".to_string(), "1".to_string()],
            FormatterCwd::ExplicitHostPath(&std::env::temp_dir()),
            b"irrelevant input",
            EnvironmentPolicy::empty(),
            None,
            Duration::from_secs(5),
            &cancellation,
        )
        .await;
        let InvocationOutcome::Completed { exit_code, .. } = outcome else {
            return Err("expected InvocationOutcome::Completed".to_string());
        };
        assert_ne!(exit_code, 0);
        Ok(())
    }

    #[tokio::test]
    async fn timeout_terminates_a_hanging_process() -> TestResult {
        let fixture = fixture_support::fixture_binary_path()?;
        let cancellation = CancellationToken::new();
        // `sleep-ms 30000` never reads stdin and never exits within the
        // short timeout below -- proves the whole process tree is
        // terminated rather than this call hanging indefinitely. Portable
        // stand-in for `/bin/sleep 30`.
        let outcome = invoke_formatter(
            &fixture,
            None,
            vec!["sleep-ms".to_string(), "30000".to_string()],
            FormatterCwd::ExplicitHostPath(&std::env::temp_dir()),
            b"irrelevant input",
            EnvironmentPolicy::empty(),
            None,
            Duration::from_millis(200),
            &cancellation,
        )
        .await;
        if !matches!(outcome, InvocationOutcome::TimedOut) {
            return Err(format!(
                "expected InvocationOutcome::TimedOut, got {outcome:?}"
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_terminates_a_running_process() -> TestResult {
        let fixture = fixture_support::fixture_binary_path()?;
        let cancellation = CancellationToken::new();
        let token_for_cancel = cancellation.clone();
        let handle = tokio::spawn(async move {
            invoke_formatter(
                &fixture,
                None,
                vec!["sleep-ms".to_string(), "30000".to_string()],
                FormatterCwd::ExplicitHostPath(&std::env::temp_dir()),
                b"irrelevant input",
                EnvironmentPolicy::empty(),
                None,
                Duration::from_secs(30),
                &token_for_cancel,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancellation.cancel();
        let outcome = handle
            .await
            .map_err(|error| format!("invocation task panicked: {error}"))?;
        assert!(matches!(outcome, InvocationOutcome::Cancelled));
        Ok(())
    }

    #[tokio::test]
    async fn oversized_output_is_flagged_truncated_not_silently_applied() -> TestResult {
        // `bounded-stdout <N>` writes exactly the requested byte count
        // regardless of input -- a deterministic, portable way to produce
        // output larger than this module's bound without depending on
        // rustfmt itself or on Unix-only `head -c`/`/dev/zero`.
        let fixture = fixture_support::fixture_binary_path()?;
        let cancellation = CancellationToken::new();
        let over_bound = MAX_STDOUT_BYTES + 4096;
        let outcome = invoke_formatter(
            &fixture,
            None,
            vec!["bounded-stdout".to_string(), over_bound.to_string()],
            FormatterCwd::ExplicitHostPath(&std::env::temp_dir()),
            b"unused",
            EnvironmentPolicy::empty(),
            None,
            Duration::from_secs(10),
            &cancellation,
        )
        .await;
        let InvocationOutcome::Completed {
            stdout,
            stdout_truncated,
            ..
        } = outcome
        else {
            return Err("expected InvocationOutcome::Completed".to_string());
        };
        assert!(stdout_truncated);
        assert_eq!(stdout.len(), MAX_STDOUT_BYTES);
        Ok(())
    }

    /// M09-P10 (owner-authorized), Section 25/26: direct, unambiguous proof
    /// of `M09_P10_WINDOWS_FORMATTER_WORKSPACE_PATH_CWD_COUNT=0` -- uses the
    /// portable fixture's own `print-cwd` mode (in place of real rustfmt) so
    /// the child's ACTUAL working directory is observed from its own
    /// perspective, not inferred. A `PinnedWorkspace` invocation on Windows
    /// must report a cwd equal to the OS temp directory, never the real
    /// workspace root's own canonical path -- `real_rustfmt_managed_full_
    /// lifecycle_e2e`'s `RUSTFMT_LOCAL_CONFIG_SEMANTICS=PASS` elsewhere in
    /// this crate is the complementary functional proof (real managed
    /// rustfmt still honors the repository's `rustfmt.toml` via
    /// `--config-path`, cwd-independent); this test is the structural proof
    /// of exactly which directory the child actually observed.
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_pinned_workspace_cwd_is_redirected_to_a_controlled_non_workspace_directory()
    -> TestResult {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let workspace_dir =
            std::env::temp_dir().join(format!("corulix-p10-formatter-cwd-workspace-{stamp}"));
        std::fs::create_dir_all(&workspace_dir).map_err(|error| error.to_string())?;
        let workspace_root = wht_corulix_workspace::WorkspaceRoot::open(&workspace_dir)
            .map_err(|error| format!("{error:?}"))?;

        let fixture = fixture_support::fixture_binary_path()?;
        let cancellation = CancellationToken::new();
        let outcome = invoke_formatter(
            &fixture,
            None,
            vec!["print-cwd".to_string()],
            FormatterCwd::PinnedWorkspace(&workspace_root),
            b"unused",
            EnvironmentPolicy::empty(),
            None,
            Duration::from_secs(5),
            &cancellation,
        )
        .await;
        let InvocationOutcome::Completed {
            stdout, exit_code, ..
        } = outcome
        else {
            let _ = std::fs::remove_dir_all(&workspace_dir);
            return Err("expected InvocationOutcome::Completed".to_string());
        };
        assert_eq!(exit_code, 0);
        let payload = String::from_utf8(stdout).map_err(|error| error.to_string())?;
        let reported_cwd = extract_json_string_field(&payload, "cwd")
            .ok_or("fixture print-cwd payload missing a cwd field")?;
        // Rule F: filesystem canonicalization authority belongs solely to
        // wht_corulix_workspace, so this comparison is resolved through
        // WorkspaceRoot::open's own pinning canonicalization rather than a
        // direct std::fs::canonicalize call in this crate.
        let reported_cwd_root = wht_corulix_workspace::WorkspaceRoot::open(&reported_cwd)
            .map_err(|error| format!("reported cwd must open as a valid directory: {error:?}"))?;
        let reported_cwd_canonical = reported_cwd_root.canonical_path().to_path_buf();
        let expected_temp_root = wht_corulix_workspace::WorkspaceRoot::open(std::env::temp_dir())
            .map_err(|error| {
            format!("OS temp dir must open as a valid directory: {error:?}")
        })?;
        let expected_temp_dir = expected_temp_root.canonical_path().to_path_buf();

        assert_eq!(
            reported_cwd_canonical, expected_temp_dir,
            "the spawned child's own reported cwd must be the controlled OS temp directory"
        );
        assert_ne!(
            reported_cwd_canonical,
            workspace_root.canonical_path(),
            "M09_P10_WINDOWS_FORMATTER_WORKSPACE_PATH_CWD_COUNT must be 0: the real workspace \
             root's own pathname must never be used as the child's cwd on Windows"
        );

        let _ = std::fs::remove_dir_all(&workspace_dir);
        Ok(())
    }
}
