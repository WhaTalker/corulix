// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(windows)]

//! P17-W-R2: real, native-Windows-only end-to-end evidence that
//! [`wht_corulix_tooling::execute`]'s Windows containment path (spawn
//! `CREATE_SUSPENDED` -> assign to a kill-on-close Job Object -> resume,
//! only on success) actually contains and terminates a whole process tree
//! -- not merely the direct child -- and that a normal, portable
//! (`cmd.exe`-only, no hardcoded Unix path) command completes normally.
//!
//! These tests must be executed natively on real Windows (never merely
//! cross-compiled) -- see the P17-W-R2 phase report for the exact command
//! output this was run against on the target test VM (Windows 10 build
//! 19045).
//!
//! Every executable this file spawns is `cmd.exe` (always present on any
//! Windows target) with typed argv -- never a hardcoded `/bin/*`/`/usr/bin/*`
//! path (the exact portability gap `BLOCKER_2`,
//! `WINDOWS_PROCESS_FIXTURE_PORTABILITY`, tracks separately; this file does
//! not attempt to close that blocker, only to avoid depending on it for its
//! own, narrower Job-Object-containment evidence).

use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::time::Duration;
use wht_corulix_core::{CancellationToken, ExecutionClass};
use wht_corulix_tooling::{
    EnvironmentPolicy, ProcessLimits, ProcessSpec, TerminationReason, execute,
};

fn spec(arguments: &[&str], timeout: Duration) -> ProcessSpec {
    // `cmd.exe` resolves an external command it did not itself receive a
    // full path for (`ping.exe`, `powershell.exe` -- neither is one of
    // cmd's own builtins) via a child-process `SearchPath` that consults
    // *its own* `PATH`/`SystemRoot` environment, which this test explicitly
    // allowlists here -- this crate's own `env_clear()`-first contract
    // (ADR-documented: nothing ambient is inherited by default) otherwise
    // leaves `cmd` unable to find either. This is a test-fixture concern
    // specific to this file's choice of external portable-sleep tools, not
    // a Job-Object-containment concern -- still never the *whole* ambient
    // environment, only these two explicitly allowlisted variables.
    let mut environment = EnvironmentPolicy::empty();
    if let Ok(system_root) = std::env::var("SystemRoot") {
        environment = environment.with_var("SystemRoot", system_root);
    }
    if let Ok(path) = std::env::var("PATH") {
        environment = environment.with_var("PATH", path);
    }
    ProcessSpec {
        executable: PathBuf::from("cmd"),
        arguments: arguments.iter().map(|arg| (*arg).to_string()).collect(),
        environment,
        working_directory: std::env::temp_dir(),
        limits: ProcessLimits::default(),
        timeout,
        execution_class: ExecutionClass::ControlledExternalTool,
        argv0: None,
    }
}

/// Real OS-level check: is any process still alive whose command line
/// contains `needle`? Uses PowerShell's `Get-CimInstance Win32_Process`
/// (never trusting this crate's own internal state) so this is independent
/// evidence of tree termination, not a self-check.
///
/// Excludes `powershell.exe` processes from the match: this helper's own
/// query command line necessarily embeds the literal `needle` text (it is
/// interpolated into the `-Command` script), so without this exclusion the
/// query would always find at least one match -- itself -- exactly the
/// `ps aux | grep foo` self-match pitfall. No real target process this file
/// spawns (`cmd.exe`/`ping.exe`) is ever named `powershell.exe`, so this
/// exclusion never hides a genuine survivor.
fn any_process_command_line_contains(needle: &str) -> bool {
    let output = StdCommand::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like '*{needle}*' -and $_.Name -ne 'powershell.exe' }} | Measure-Object).Count"
            ),
        ])
        .output()
        .unwrap_or_else(|error| unreachable!("powershell query must run: {error}"));
    let count_text = String::from_utf8_lossy(&output.stdout);
    count_text.trim().parse::<u32>().unwrap_or(0) > 0
}

/// A. Normal completion: `cmd /C exit 0` -- proves the assign-before-resume
/// path (spawn suspended, assign to job, resume) does not break ordinary
/// successful execution.
#[tokio::test]
async fn normal_completion_via_cmd_exe_succeeds() {
    let outcome = execute(
        &spec(&["/C", "exit", "0"], Duration::from_secs(10)),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
}

/// B. Non-zero exit is reported with its real code -- the resumed child
/// genuinely ran (it could not have produced this exit code otherwise).
#[tokio::test]
async fn non_zero_exit_via_cmd_exe_is_reported() {
    let outcome = execute(
        &spec(&["/C", "exit", "7"], Duration::from_secs(10)),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 7 });
}

/// Stress evidence (P17-W-R2 §16): repeated real spawn/assign/resume/reap
/// cycles, back to back, on the real target VM -- complementary to (never a
/// substitute for) the structural proof in `platform::windows::contain`
/// that no `resume_primary_thread` call is reachable except through the
/// `Some(job)` (successful-assignment) match arm. A race in the
/// assign-before-resume ordering would be expected to surface here as an
/// occasional wrong exit code, a hang, or an orphaned process -- none of
/// which this loop tolerates silently (every iteration's outcome is
/// asserted, not merely counted).
#[tokio::test]
async fn repeated_spawn_assign_resume_cycles_never_fail_or_hang() {
    const ITERATIONS: u32 = 300;
    for iteration in 0..ITERATIONS {
        let expected_code = (iteration % 128) as i32;
        let outcome = execute(
            &spec(
                &["/C", "exit", &expected_code.to_string()],
                Duration::from_secs(5),
            ),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(
            outcome.termination,
            TerminationReason::Exited {
                code: expected_code
            },
            "iteration {iteration} of {ITERATIONS} produced an unexpected outcome"
        );
    }
}

/// C. Timeout terminates a long-running process promptly -- proves the
/// Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) this crate assigned
/// the resumed child to is real and actually enforced, not merely
/// requested.
#[tokio::test]
async fn timeout_terminates_a_long_running_cmd_exe_process() {
    let started = std::time::Instant::now();
    let outcome = execute(
        // `ping -n 61 127.0.0.1` sleeps roughly 60s using only Windows-native
        // tools (no `/usr/bin/sleep`), redirected to NUL so this test never
        // depends on capturing its (irrelevant) stdout.
        &spec(
            &["/C", "ping -n 61 127.0.0.1 >NUL"],
            Duration::from_millis(300),
        ),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(outcome.termination, TerminationReason::TimedOut);
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "timeout must terminate promptly, not merely at the child's own 61s completion"
    );
}

/// D. Whole-tree containment, the structural point of P17-W-R2: a `cmd.exe`
/// parent uses `start` to launch a *detached* `cmd.exe` grandchild running
/// its own long `ping` sleep, then the parent itself exits almost
/// immediately (`start /B` without `/WAIT` returns right away -- the parent
/// never times out here, it genuinely completes on its own). If this
/// crate's containment only covered the direct child (the old, disclosed
/// spawn-then-assign race's exact failure mode), the detached grandchild
/// would be left running, uncontained, forever once its parent exits.
/// Instead, because Windows automatically adds every descendant of a
/// contained process to the same Job Object (this module never sets a
/// breakaway-allowed limit) and [`execute`] drops its `Containment` when it
/// returns -- which, via `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, terminates
/// every process still assigned to the job at that moment -- the
/// grandchild must already be gone by the time this test observes it,
/// verified independently via `Get-CimInstance Win32_Process`, not via this
/// crate's own internal state.
#[tokio::test]
async fn detached_grandchild_does_not_survive_its_parents_execute_call_returning() {
    let marker = format!(
        "p17wr2-marker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    assert!(
        !any_process_command_line_contains(&marker),
        "marker must be unique before this test starts"
    );

    let command_line = format!("start /B cmd /C \"ping -n 61 127.0.0.1 >NUL & rem {marker}\"");
    let outcome = execute(
        &spec(&["/C", &command_line], Duration::from_secs(10)),
        &CancellationToken::new(),
    )
    .await;
    // The parent (`cmd /C "start /B ..."`) itself completes normally and
    // quickly -- `start /B` launching the grandchild is non-blocking by
    // design, so this is a real natural exit, never a timeout.
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });

    // Give the OS a brief, bounded moment to finish tearing down the job's
    // member processes after `execute` returned (and dropped its
    // `Containment`) before the independent verification query below.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        !any_process_command_line_contains(&marker),
        "the detached grandchild must not still be running once the parent's \
         containing Job Object has been dropped -- a survivor here would mean \
         containment only reached the direct child, exactly the disclosed \
         spawn-then-assign race this phase closes"
    );
}

/// E. Explicit cancellation (not merely a timeout) also terminates the
/// whole tree -- the cancellation path shares the same
/// `terminate_and_classify` -> `platform::terminate` call this crate's
/// timeout path uses, so this is a distinct trigger over the same
/// enforcement mechanism, not a duplicate of test D.
#[tokio::test]
async fn explicit_cancellation_terminates_a_long_running_cmd_exe_process() {
    let token = CancellationToken::new();
    let long_spec = spec(
        &["/C", "ping -n 61 127.0.0.1 >NUL"],
        Duration::from_secs(30),
    );
    let cancel_token = token.clone();
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel_token.cancel();
    });
    let outcome = execute(&long_spec, &token).await;
    let _ = canceller.await;
    assert_eq!(outcome.termination, TerminationReason::Cancelled);
}
