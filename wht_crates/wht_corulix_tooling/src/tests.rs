// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Behavioral tests for the controlled process runtime.
//!
//! These tests spawn real OS processes -- they are genuine runtime
//! evidence, not mocks. As of P17-W-R3-C2
//! (`WINDOWS_PROCESS_FIXTURE_PORTABILITY`), the child executable is the
//! cross-platform `wht_corulix_process_fixture` binary (resolved and built
//! on demand via `super::fixture_support::fixture_binary_path`), never a
//! hardcoded Unix-only path such as `/usr/bin/echo` or `/bin/sh` -- every
//! test below now runs unmodified on native Windows as well as Linux/macOS.
//! Two tests remain genuinely Unix-specific by design (`/proc` and process
//! group semantics) and stay `#[cfg(unix)]`-gated at the bottom of this
//! file; that is a real, disclosed platform difference, not a portability
//! gap this phase leaves unaddressed.

use super::*;
use std::time::Instant;

fn fixture_spec(fixture_args: &[&str]) -> Result<ProcessSpec, String> {
    let executable = super::fixture_support::fixture_binary_path()?;
    Ok(ProcessSpec {
        executable,
        arguments: fixture_args.iter().map(|arg| (*arg).to_string()).collect(),
        environment: EnvironmentPolicy::empty(),
        working_directory: std::env::temp_dir(),
        limits: ProcessLimits::default(),
        timeout: Duration::from_secs(10),
        execution_class: ExecutionClass::ControlledExternalTool,
        argv0: None,
    })
}

async fn run(spec: &ProcessSpec) -> ExecutionOutcome {
    execute(spec, &CancellationToken::new()).await
}

/// Encodes an environment variable *value* the way the fixture's own
/// `os_string_to_bytes` reports it on this platform: raw UTF-8 bytes on
/// Unix, but UTF-16LE code units on Windows, where every environment
/// variable value is natively UTF-16. Used to build the expected hex for
/// an `env_hex` comparison -- never assume UTF-8 unconditionally.
fn native_env_value_bytes(value: &str) -> Vec<u8> {
    #[cfg(windows)]
    {
        value
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }
    #[cfg(not(windows))]
    {
        value.as_bytes().to_vec()
    }
}

/// The single, intentional exception both `environment_allowlist_*` tests
/// below must account for on Windows: `("SystemRoot", <hex of the real
/// ambient value>)` when `SystemRoot` is set (always true on a real
/// Windows host), `None` everywhere else.
///
/// # Why this exists (Phase 17-W-R15 finding)
///
/// `ManagedProcess::spawn`/`execute`'s `env_clear()` is intentionally not
/// absolute on Windows: a prior phase (P17-W-R14, the Node/Windows
/// `SystemRoot`-passthrough fix) made `SystemRoot` pass through
/// unconditionally on `#[cfg(target_os = "windows")]`, because a managed
/// Node child crashes at process-init (`ncrypto::CSPRNG` needs Windows CNG,
/// which needs `SystemRoot`-resolvable system DLL loading) without it --
/// proven via an isolated native-Windows repro before that fix landed, and
/// necessary for every present and future Windows-spawned managed process,
/// not merely TS6. That fix was never previously run against this crate's
/// own unit test suite natively on Windows, so it silently broke both
/// tests below, which encoded the *pre-fix* invariant "an empty/explicit-
/// only `EnvironmentPolicy` produces an exactly empty/exactly-listed child
/// environment" without exception. `SystemRoot`'s presence here is the
/// *correct*, already-shipped, load-bearing behavior -- the tests' own
/// expectations were the stale part, not the product.
fn expected_windows_systemroot_entry() -> Option<(String, String)> {
    #[cfg(windows)]
    {
        std::env::var("SystemRoot").ok().map(|value| {
            (
                "SystemRoot".to_string(),
                hex_encode(&native_env_value_bytes(&value)),
            )
        })
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[tokio::test]
async fn typed_argv_reaches_the_child_as_separate_elements() -> Result<(), String> {
    let outcome = run(&fixture_spec(&["print-argv", "hello", "world"])?).await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    let text = std::str::from_utf8(&outcome.stdout.bytes)
        .map_err(|error| format!("stdout was not valid UTF-8: {error}"))?;
    let payload: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|error| format!("invalid JSON: {error}"))?;
    let argv_hex = payload["argv_hex"]
        .as_array()
        .ok_or("argv_hex missing")?
        .iter()
        .map(|value| value.as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        argv_hex,
        vec![hex_encode(b"hello"), hex_encode(b"world")],
        "typed argv elements must reach the child as separate, unmodified elements"
    );
    Ok(())
}

#[tokio::test]
async fn shell_metacharacters_remain_literal_argv_data() -> Result<(), String> {
    let hostile = "; rm -rf /tmp/should-not-exist; $(echo pwned) | cat && echo done";
    let outcome = run(&fixture_spec(&["print-argv", hostile])?).await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    let text = std::str::from_utf8(&outcome.stdout.bytes)
        .map_err(|error| format!("stdout was not valid UTF-8: {error}"))?;
    let payload: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|error| format!("invalid JSON: {error}"))?;
    let argv_hex = payload["argv_hex"]
        .as_array()
        .ok_or("argv_hex missing")?
        .iter()
        .map(|value| value.as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        argv_hex,
        vec![hex_encode(hostile.as_bytes())],
        "hostile argument must reach the child as one literal argv element, \
         never interpreted as shell syntax"
    );
    Ok(())
}

#[tokio::test]
async fn environment_allowlist_forwards_only_explicit_variables() -> Result<(), String> {
    let mut process_spec = fixture_spec(&["print-env"])?;
    process_spec.environment = EnvironmentPolicy::empty()
        .with_var("WHT_TEST_ALLOWED", "value")
        .with_var("PATH", "/usr/bin:/bin");
    let outcome = run(&process_spec).await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });

    let text = std::str::from_utf8(&outcome.stdout.bytes)
        .map_err(|error| format!("stdout was not valid UTF-8: {error}"))?;
    let payload: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|error| format!("invalid JSON: {error}"))?;
    let mut entries: Vec<(String, String)> = payload["env_hex"]
        .as_array()
        .ok_or("env_hex missing")?
        .iter()
        .map(|entry| {
            let pair = entry.as_array().map(Vec::as_slice).unwrap_or_default();
            (
                pair.first()
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                pair.get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect();
    entries.sort_unstable();
    let mut expected = vec![
        (
            "PATH".to_string(),
            hex_encode(&native_env_value_bytes("/usr/bin:/bin")),
        ),
        (
            "WHT_TEST_ALLOWED".to_string(),
            hex_encode(&native_env_value_bytes("value")),
        ),
    ];
    expected.extend(expected_windows_systemroot_entry());
    expected.sort_unstable();
    assert_eq!(entries, expected);
    Ok(())
}

#[tokio::test]
async fn ambient_variables_never_leak_when_not_allowlisted() -> Result<(), String> {
    // This test process's own environment almost certainly carries HOME,
    // USER, and other ambient variables; none of them are added to the
    // policy below, so none may appear in the child's environment dump --
    // proving `env_clear()` runs before any allowlisted variable is added,
    // not merely that some variables happen to be filtered afterward. The
    // fixture's own mode selection is via `argv[0]`, never an environment
    // variable, precisely so it still dispatches correctly under a policy
    // that forwards nothing.
    //
    // The single declared exception is Windows's own `SystemRoot`
    // passthrough (see `expected_windows_systemroot_entry`'s own doc
    // comment for why `env_clear()` is not absolute there) -- every other
    // ambient variable must still be completely absent.
    let outcome = run(&fixture_spec(&["print-env"])?).await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    let text = std::str::from_utf8(&outcome.stdout.bytes)
        .map_err(|error| format!("stdout was not valid UTF-8: {error}"))?;
    let payload: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|error| format!("invalid JSON: {error}"))?;
    let entries: Vec<(String, String)> = payload["env_hex"]
        .as_array()
        .ok_or("env_hex missing")?
        .iter()
        .map(|entry| {
            let pair = entry.as_array().map(Vec::as_slice).unwrap_or_default();
            (
                pair.first()
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                pair.get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect();
    let expected: Vec<(String, String)> = expected_windows_systemroot_entry().into_iter().collect();
    assert_eq!(
        entries, expected,
        "child environment must contain nothing beyond Windows's own declared \
         SystemRoot exception when the policy allows nothing"
    );
    Ok(())
}

#[tokio::test]
async fn explicit_working_directory_is_honored() -> Result<(), String> {
    let target = std::env::temp_dir();
    let mut process_spec = fixture_spec(&["print-cwd"])?;
    process_spec.working_directory = target.clone();
    let outcome = run(&process_spec).await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    let text = std::str::from_utf8(&outcome.stdout.bytes)
        .map_err(|error| format!("stdout was not valid UTF-8: {error}"))?;
    let payload: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|error| format!("invalid JSON: {error}"))?;
    let reported = payload["cwd"].as_str().ok_or("cwd missing")?;
    // Deliberately not resolved via a canonicalizing call here: that
    // primitive belongs exclusively to `wht_corulix_workspace` (Rule F),
    // and this test's own environment does not use a symlinked temp
    // directory, so a direct comparison is sufficient proof that the
    // requested working directory was honored.
    assert_eq!(PathBuf::from(reported), target);
    Ok(())
}

#[tokio::test]
async fn stdout_is_bounded_and_reports_truncation() -> Result<(), String> {
    let mut process_spec = fixture_spec(&["bounded-stdout", "8192"])?;
    process_spec.limits = ProcessLimits {
        max_stdout_bytes: 4096,
        max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
    };
    let outcome = run(&process_spec).await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    assert_eq!(outcome.stdout.bytes.len(), 4096);
    assert!(outcome.stdout.truncated);
    Ok(())
}

#[tokio::test]
async fn stderr_is_bounded_independently_of_stdout() -> Result<(), String> {
    let mut process_spec = fixture_spec(&["bounded-stderr", "8192"])?;
    process_spec.limits = ProcessLimits {
        max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
        max_stderr_bytes: 4096,
    };
    let outcome = run(&process_spec).await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    assert!(outcome.stdout.bytes.is_empty());
    assert_eq!(outcome.stderr.bytes.len(), 4096);
    assert!(outcome.stderr.truncated);
    Ok(())
}

#[tokio::test]
async fn large_simultaneous_stdout_and_stderr_never_deadlocks() -> Result<(), String> {
    // The fixture's own `dual-stream` mode writes to stdout and stderr
    // concurrently from two threads inside a single portable process --
    // if bounded reading of one stream ever blocked on the other, this
    // would hang instead of returning. This replaces the previous
    // `/usr/bin/sh -c "dd ... & dd ... & wait"` construction, which relied
    // on a Unix shell and two backgrounded `dd` processes to prove the
    // same thing.
    let mut process_spec = fixture_spec(&["dual-stream", "2097152", "2097152"])?;
    process_spec.limits = ProcessLimits {
        max_stdout_bytes: 8192,
        max_stderr_bytes: 8192,
    };
    process_spec.timeout = Duration::from_secs(5);
    let started = Instant::now();
    let outcome = run(&process_spec).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "must not deadlock while draining two saturated pipes at once"
    );
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    assert!(outcome.stdout.truncated);
    assert!(outcome.stderr.truncated);
    Ok(())
}

#[tokio::test]
async fn timeout_terminates_a_long_running_process_promptly() -> Result<(), String> {
    let mut process_spec = fixture_spec(&["sleep-ms", "10000"])?;
    process_spec.timeout = Duration::from_millis(200);
    let started = Instant::now();
    let outcome = run(&process_spec).await;
    assert_eq!(outcome.termination, TerminationReason::TimedOut);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "timeout must terminate the process well before its natural 10s lifetime"
    );
    Ok(())
}

#[tokio::test]
async fn explicit_cancellation_terminates_a_long_running_process_promptly() -> Result<(), String> {
    let process_spec = {
        let mut process_spec = fixture_spec(&["sleep-ms", "10000"])?;
        process_spec.timeout = Duration::from_secs(30);
        process_spec
    };
    let cancellation = CancellationToken::new();
    let cancel_handle = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel_handle.cancel();
    });
    let started = Instant::now();
    let outcome = execute(&process_spec, &cancellation).await;
    assert_eq!(outcome.termination, TerminationReason::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(5));
    Ok(())
}

#[tokio::test]
async fn non_zero_exit_is_reported_with_its_code() -> Result<(), String> {
    let outcome = run(&fixture_spec(&["exit-code", "1"])?).await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 1 });
    Ok(())
}

#[tokio::test]
async fn spawn_failure_is_reported_not_panicked() -> Result<(), String> {
    let outcome = run(&spec_for_nonexistent_executable()).await;
    assert_eq!(outcome.termination, TerminationReason::SpawnFailed);
    assert!(outcome.stdout.bytes.is_empty());
    assert!(outcome.stderr.bytes.is_empty());
    Ok(())
}

fn spec_for_nonexistent_executable() -> ProcessSpec {
    ProcessSpec {
        executable: PathBuf::from("/definitely/does/not/exist/corulix-test-binary"),
        arguments: Vec::new(),
        environment: EnvironmentPolicy::empty(),
        working_directory: std::env::temp_dir(),
        limits: ProcessLimits::default(),
        timeout: Duration::from_secs(10),
        execution_class: ExecutionClass::ControlledExternalTool,
        argv0: None,
    }
}

#[tokio::test]
async fn repeated_execution_does_not_leak_processes_or_hang() -> Result<(), String> {
    let spec = fixture_spec(&["exit-code", "0"])?;
    for _ in 0..50 {
        let outcome = run(&spec).await;
        assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unix_descendant_process_is_terminated_with_the_group() -> Result<(), String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let pid_file = std::env::temp_dir().join(format!("corulix-tooling-descendant-{stamp}.pid"));
    let pid_file_arg = pid_file.to_string_lossy().into_owned();

    let mut process_spec = fixture_spec(&["spawn-child", "30000", &pid_file_arg])?;
    process_spec.timeout = Duration::from_millis(300);
    let outcome = run(&process_spec).await;
    assert_eq!(outcome.termination, TerminationReason::TimedOut);

    // Give the kernel a brief moment to finish reaping/removing the killed
    // descendant's /proc entry before asserting its absence.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let descendant_pid = std::fs::read_to_string(&pid_file)
        .unwrap_or_default()
        .trim()
        .to_string();
    let _ = std::fs::remove_file(&pid_file);
    assert!(
        !descendant_pid.is_empty(),
        "test fixture must have recorded the descendant's pid"
    );
    let proc_path = format!("/proc/{descendant_pid}");
    assert!(
        !std::path::Path::new(&proc_path).exists(),
        "descendant sleep process (pid {descendant_pid}) must be terminated \
         along with the rest of its process group, not left running"
    );
    Ok(())
}

/// M09-P7: `execute_with_workspace_root` must preserve every containment
/// property `execute` already has (whole-process-group termination) WHILE
/// ALSO pinning the child's cwd to the real, OS-level identity of the
/// `WorkspaceRoot` object (device+inode of `/proc/<descendant>/cwd`, not
/// merely a string path) -- proven together on the same spawned command,
/// not as two independent claims, since a defect in how
/// `WorkspaceRoot::bind_process_cwd`'s `pre_exec` registration composes
/// with `platform::prepare`'s `process_group(0)` could plausibly break
/// either property while leaving the other looking fine in isolation.
#[cfg(unix)]
#[tokio::test]
async fn workspace_root_binding_pins_real_cwd_identity_and_preserves_group_containment()
-> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root_dir = std::env::temp_dir().join(format!("corulix-tooling-p7-root-{stamp}"));
    std::fs::create_dir_all(&root_dir)
        .map_err(|error| format!("create_dir_all failed: {error}"))?;
    let workspace_root = WorkspaceRoot::open(&root_dir)
        .map_err(|error| format!("WorkspaceRoot::open failed: {error:?}"))?;
    let expected_metadata = std::fs::metadata(workspace_root.canonical_path())
        .map_err(|error| format!("metadata failed: {error}"))?;

    let pid_file = std::env::temp_dir().join(format!("corulix-tooling-p7-descendant-{stamp}.pid"));
    let pid_file_arg = pid_file.to_string_lossy().into_owned();

    let mut process_spec = fixture_spec(&["spawn-child", "30000", &pid_file_arg])?;
    process_spec.working_directory = workspace_root.canonical_path().to_path_buf();
    process_spec.timeout = Duration::from_millis(400);

    // Polls, concurrently with the bounded/timed-out execution below, for
    // the descendant's own real `/proc/<pid>/cwd` object identity -- proof
    // independent of any string path, and taken from a *different* process
    // (the grandchild `write-pid-file`, which inherits cwd from the direct
    // child `bind_process_cwd` actually bound) than the one this function
    // awaits, so the two properties are genuinely observed on the one
    // command this test spawns, not reconstructed after the fact.
    let pid_file_poll = pid_file.clone();
    let cwd_identity_check: tokio::task::JoinHandle<Result<(u64, u64), String>> =
        tokio::spawn(async move {
            for _ in 0..100 {
                if let Ok(contents) = std::fs::read_to_string(&pid_file_poll) {
                    let pid = contents.trim();
                    if !pid.is_empty() {
                        let cwd_path = format!("/proc/{pid}/cwd");
                        if let Ok(metadata) = std::fs::metadata(&cwd_path) {
                            return Ok((metadata.dev(), metadata.ino()));
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err("descendant pid/cwd never became observable before timeout".to_string())
        });

    let outcome =
        execute_with_workspace_root(&process_spec, &workspace_root, &CancellationToken::new())
            .await;
    assert_eq!(outcome.termination, TerminationReason::TimedOut);

    let (observed_dev, observed_ino) = cwd_identity_check
        .await
        .map_err(|error| format!("cwd poll task panicked: {error}"))??;
    assert_eq!(
        (observed_dev, observed_ino),
        (expected_metadata.dev(), expected_metadata.ino()),
        "the descendant's real /proc cwd object identity must match the pinned \
         WorkspaceRoot, proving bind_process_cwd actually took effect on the real OS \
         process rather than merely being configured on the Command builder"
    );

    // Give the kernel a brief moment to finish reaping/removing the killed
    // descendant's /proc entry before asserting its absence (mirrors
    // `unix_descendant_process_is_terminated_with_the_group` above).
    tokio::time::sleep(Duration::from_millis(200)).await;
    let descendant_pid = std::fs::read_to_string(&pid_file)
        .unwrap_or_default()
        .trim()
        .to_string();
    let _ = std::fs::remove_file(&pid_file);
    let _ = std::fs::remove_dir_all(&root_dir);
    assert!(
        !descendant_pid.is_empty(),
        "test fixture must have recorded the descendant's pid"
    );
    let proc_path = format!("/proc/{descendant_pid}");
    assert!(
        !std::path::Path::new(&proc_path).exists(),
        "descendant sleep process (pid {descendant_pid}) must still be terminated along \
         with the rest of its process group when execute_with_workspace_root's own \
         containment kicks in, exactly like plain execute"
    );
    Ok(())
}

/// M09-P7: `spec.working_directory` must equal `workspace_root.canonical_path()`
/// -- a mismatch is a caller programming error this function fails closed
/// on (never silently executing against whichever directory the
/// mismatched `PathBuf` happens to name).
#[cfg(unix)]
#[tokio::test]
async fn execute_with_workspace_root_refuses_a_mismatched_working_directory() -> Result<(), String>
{
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root_dir = std::env::temp_dir().join(format!("corulix-tooling-p7-mismatch-{stamp}"));
    std::fs::create_dir_all(&root_dir)
        .map_err(|error| format!("create_dir_all failed: {error}"))?;
    let workspace_root = WorkspaceRoot::open(&root_dir)
        .map_err(|error| format!("WorkspaceRoot::open failed: {error:?}"))?;

    let mut process_spec = fixture_spec(&["print-cwd-identity"])?;
    // Deliberately left at `fixture_spec`'s own default (`std::env::temp_dir()`),
    // never updated to `workspace_root`'s own path -- the mismatch under test.
    let outcome =
        execute_with_workspace_root(&process_spec, &workspace_root, &CancellationToken::new())
            .await;
    assert_eq!(outcome.termination, TerminationReason::SpawnFailed);
    assert!(outcome.stdout.bytes.is_empty());
    assert!(outcome.stderr.bytes.is_empty());

    // Sanity control: the same spec, corrected to match, must actually run.
    process_spec.working_directory = workspace_root.canonical_path().to_path_buf();
    let outcome =
        execute_with_workspace_root(&process_spec, &workspace_root, &CancellationToken::new())
            .await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });

    let _ = std::fs::remove_dir_all(&root_dir);
    Ok(())
}

/// Reads a fixture `print-cwd-identity` outcome's `(device, inode)` pair.
#[cfg(unix)]
fn cwd_identity_from_outcome(outcome: &ExecutionOutcome) -> Result<(u64, u64), String> {
    let text = std::str::from_utf8(&outcome.stdout.bytes)
        .map_err(|error| format!("stdout was not valid UTF-8: {error}"))?;
    let payload: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|error| format!("invalid JSON: {error}"))?;
    let device = payload["device"].as_u64().ok_or("device missing")?;
    let inode = payload["inode"].as_u64().ok_or("inode missing")?;
    Ok((device, inode))
}

/// M09-P7 mandatory exit gate: reproduces the historical public
/// `validate_change` root-replacement exploit directly through the new
/// `execute_with_workspace_root` production entry point (not merely the
/// already-certified `WorkspaceRoot::bind_process_cwd` primitive this test
/// module already exercises in `wht_corulix_workspace/tests/p6_process_cwd.rs`)
/// -- an ordinary-directory impostor substituted at the original pathname,
/// after `WorkspaceRoot::open` but before this crate's own spawn, must never
/// receive execution.
#[cfg(unix)]
#[tokio::test]
async fn execute_with_workspace_root_survives_normal_directory_replacement() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let real_dir = std::env::temp_dir().join(format!("corulix-tooling-p7-swap-real-{stamp}"));
    std::fs::create_dir_all(&real_dir).map_err(|error| error.to_string())?;
    let workspace_root = WorkspaceRoot::open(&real_dir)
        .map_err(|error| format!("WorkspaceRoot::open failed: {error:?}"))?;
    let expected_metadata = std::fs::metadata(&real_dir).map_err(|error| error.to_string())?;
    let expected = (expected_metadata.dev(), expected_metadata.ino());

    // Impostor: move the real directory aside, put an ordinary new
    // directory at the exact same pathname `workspace_root` still names.
    let moved_dir = std::env::temp_dir().join(format!("corulix-tooling-p7-swap-moved-{stamp}"));
    std::fs::rename(&real_dir, &moved_dir).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&real_dir).map_err(|error| error.to_string())?;
    let impostor_metadata = std::fs::metadata(&real_dir).map_err(|error| error.to_string())?;
    let impostor = (impostor_metadata.dev(), impostor_metadata.ino());
    assert_ne!(expected, impostor, "test setup sanity check");

    let mut process_spec = fixture_spec(&["print-cwd-identity"])?;
    process_spec.working_directory = workspace_root.canonical_path().to_path_buf();
    let outcome =
        execute_with_workspace_root(&process_spec, &workspace_root, &CancellationToken::new())
            .await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    let actual = cwd_identity_from_outcome(&outcome)?;

    assert_ne!(
        actual, impostor,
        "M09_P7_ROOT_NORMAL_REPLACEMENT_IMPOSTOR_EXECUTION_COUNT must be 0"
    );
    assert_eq!(
        actual, expected,
        "the child must enter the ORIGINAL pinned root object, never the impostor \
         directory now sitting at the old pathname"
    );

    let _ = std::fs::remove_dir_all(&real_dir);
    let _ = std::fs::remove_dir_all(&moved_dir);
    Ok(())
}

/// As above, but the impostor is a symlink to an entirely different
/// directory rather than an ordinary directory -- `M09_P7_ROOT_SYMLINK_REPLACEMENT_ESCAPE_COUNT`
/// must also be 0.
#[cfg(unix)]
#[tokio::test]
async fn execute_with_workspace_root_survives_symlink_replacement() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let real_dir = std::env::temp_dir().join(format!("corulix-tooling-p7-symlink-real-{stamp}"));
    std::fs::create_dir_all(&real_dir).map_err(|error| error.to_string())?;
    let workspace_root = WorkspaceRoot::open(&real_dir)
        .map_err(|error| format!("WorkspaceRoot::open failed: {error:?}"))?;
    let expected_metadata = std::fs::metadata(&real_dir).map_err(|error| error.to_string())?;
    let expected = (expected_metadata.dev(), expected_metadata.ino());

    let outside_dir = std::env::temp_dir().join(format!("corulix-tooling-p7-symlink-out-{stamp}"));
    std::fs::create_dir_all(&outside_dir).map_err(|error| error.to_string())?;
    let moved_dir = std::env::temp_dir().join(format!("corulix-tooling-p7-symlink-moved-{stamp}"));
    std::fs::rename(&real_dir, &moved_dir).map_err(|error| error.to_string())?;
    std::os::unix::fs::symlink(&outside_dir, &real_dir).map_err(|error| error.to_string())?;
    let outside_metadata = std::fs::metadata(&outside_dir).map_err(|error| error.to_string())?;
    let outside = (outside_metadata.dev(), outside_metadata.ino());

    let mut process_spec = fixture_spec(&["print-cwd-identity"])?;
    process_spec.working_directory = workspace_root.canonical_path().to_path_buf();
    let outcome =
        execute_with_workspace_root(&process_spec, &workspace_root, &CancellationToken::new())
            .await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    let actual = cwd_identity_from_outcome(&outcome)?;

    assert_ne!(
        actual, outside,
        "M09_P7_ROOT_SYMLINK_REPLACEMENT_ESCAPE_COUNT must be 0"
    );
    assert_eq!(actual, expected);

    let _ = std::fs::remove_file(&real_dir);
    let _ = std::fs::remove_dir_all(&moved_dir);
    let _ = std::fs::remove_dir_all(&outside_dir);
    Ok(())
}

/// As above, but the substitution replaces an ANCESTOR of the pinned root
/// (a directory two levels up) with an impostor tree that also happens to
/// contain a subdirectory at the identical relative path --
/// `M09_P7_ANCESTOR_REPLACEMENT_IMPOSTOR_EXECUTION_COUNT` must be 0.
#[cfg(unix)]
#[tokio::test]
async fn execute_with_workspace_root_survives_ancestor_replacement() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let ancestor_dir = std::env::temp_dir().join(format!("corulix-tooling-p7-ancestor-{stamp}"));
    let real_dir = ancestor_dir.join("workspace");
    std::fs::create_dir_all(&real_dir).map_err(|error| error.to_string())?;
    let workspace_root = WorkspaceRoot::open(&real_dir)
        .map_err(|error| format!("WorkspaceRoot::open failed: {error:?}"))?;
    let expected_metadata = std::fs::metadata(&real_dir).map_err(|error| error.to_string())?;
    let expected = (expected_metadata.dev(), expected_metadata.ino());

    // Replace the ANCESTOR directory itself with an impostor tree that also
    // has a `workspace` subdirectory at the same relative path.
    let moved_ancestor =
        std::env::temp_dir().join(format!("corulix-tooling-p7-ancestor-moved-{stamp}"));
    std::fs::rename(&ancestor_dir, &moved_ancestor).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&real_dir).map_err(|error| error.to_string())?;
    let impostor_metadata = std::fs::metadata(&real_dir).map_err(|error| error.to_string())?;
    let impostor = (impostor_metadata.dev(), impostor_metadata.ino());
    assert_ne!(expected, impostor, "test setup sanity check");

    let mut process_spec = fixture_spec(&["print-cwd-identity"])?;
    process_spec.working_directory = workspace_root.canonical_path().to_path_buf();
    let outcome =
        execute_with_workspace_root(&process_spec, &workspace_root, &CancellationToken::new())
            .await;
    assert_eq!(outcome.termination, TerminationReason::Exited { code: 0 });
    let actual = cwd_identity_from_outcome(&outcome)?;

    assert_ne!(
        actual, impostor,
        "M09_P7_ANCESTOR_REPLACEMENT_IMPOSTOR_EXECUTION_COUNT must be 0"
    );
    assert_eq!(actual, expected);

    let _ = std::fs::remove_dir_all(&ancestor_dir);
    let _ = std::fs::remove_dir_all(&moved_ancestor);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unix_direct_child_is_reaped_after_timeout_kill() -> Result<(), String> {
    // A second, independent proof alongside the descendant-termination
    // test above: the direct child itself (not only a descendant) is
    // actually waited on and reaped, never left as a zombie, after a
    // timeout-triggered kill.
    let mut process_spec = fixture_spec(&["sleep-ms", "30000"])?;
    process_spec.timeout = Duration::from_millis(200);
    let outcome = run(&process_spec).await;
    assert_eq!(outcome.termination, TerminationReason::TimedOut);
    // `execute` only returns after an explicit `child.wait().await` past
    // the termination race -- reaching this point at all is itself the
    // reap proof; no separate zombie-inspection API is needed.
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn windows_process_tree_through_the_fixture_is_terminated_on_timeout() -> Result<(), String> {
    // Windows counterpart to the two `#[cfg(unix)]` proofs above:
    // `/proc` and process-group semantics have no Windows equivalent, so
    // this uses the fixture's own `spawn-grandchild` mode (parent ->
    // middle child -> grandchild, three real OS processes) through the
    // REAL Corulix `execute()` path, then independently confirms via
    // `tasklist` (never via `lease::verify_process_absent`) that the
    // grandchild's pid is gone after the parent times out -- proving
    // Corulix's own Windows Job Object containment reaches the whole tree,
    // not only the direct child, when the target is the portable fixture
    // rather than `cmd.exe`. This still uses `tasklist` directly (rather
    // than `verify_process_absent`, whose real Windows liveness
    // implementation closed the `WINDOWS_PROCESS_LIVENESS_PROBE_GAP` as of
    // P17-W-R3-C3) because it is asserting *tree-wide* absence -- the
    // grandchild, not the direct child `execute()` itself already reaps --
    // which `test_alive`'s single-pid `OpenProcess`/`WaitForSingleObject`
    // probe cannot answer (see `platform::windows::test_alive`'s own doc
    // on that scope divergence). See
    // `windows_verify_process_absent_matches_independent_tasklist_oracle_across_a_managed_process_lifecycle`
    // below for the single-pid liveness/oracle proof `verify_process_absent`
    // itself now supports.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let pid_file = std::env::temp_dir().join(format!("corulix-tooling-win-tree-{stamp}.pid"));
    let pid_file_arg = pid_file.to_string_lossy().into_owned();

    let mut process_spec = fixture_spec(&["spawn-grandchild", "30000", &pid_file_arg])?;
    process_spec.timeout = Duration::from_millis(400);
    let outcome = run(&process_spec).await;
    assert_eq!(outcome.termination, TerminationReason::TimedOut);

    // Give the OS a brief moment to finish tearing down the Job Object's
    // process tree before asserting the grandchild's absence.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let grandchild_pid = std::fs::read_to_string(&pid_file)
        .unwrap_or_default()
        .trim()
        .to_string();
    let _ = std::fs::remove_file(&pid_file);
    assert!(
        !grandchild_pid.is_empty(),
        "test fixture must have recorded the grandchild's pid before being killed"
    );

    let tasklist_output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {grandchild_pid}"), "/NH"])
        .output()
        .map_err(|error| format!("tasklist invocation failed: {error}"))?;
    let listing = String::from_utf8_lossy(&tasklist_output.stdout);
    assert!(
        !listing.contains(grandchild_pid.as_str()),
        "grandchild process (pid {grandchild_pid}) must be terminated along with \
         the rest of its process tree, not left running: {listing}"
    );
    Ok(())
}

/// Independently confirms, via `tasklist` (a certification oracle only --
/// never a product dependency), that
/// [`provisioning::lease::verify_process_absent`]'s real Windows
/// implementation (P17-W-R3-C3, `WINDOWS_PROCESS_LIVENESS_PROBE_GAP`
/// closure) reports the same verdict the OS itself does, across a real
/// [`ManagedProcess`]/[`provisioning::lease::ManagedExecutionLease`]
/// lifecycle -- not merely a unit test of the underlying
/// `wht_corulix_process_win32::query_process_liveness` FFI helper.
/// Combines P17-W-R3-C3's mandate §10 (Cases A/B/D of the liveness test
/// matrix: a real running process reports `Present`, a reaped process
/// reports `Absent`, a *managed, leased* process specifically exercises
/// the same "active -> reaped" transition `full_uninstall`/`uninstall`
/// depend on) with §11 (the independent OS-level oracle comparison) and
/// §13 (`verify_process_absent`'s real callers, proven against a real
/// managed lease rather than a bare pid). Case C (a pid that never existed
/// -> `Absent`) is already covered directly against the FFI boundary by
/// `wht_corulix_process_win32`'s own
/// `query_process_liveness_reports_absent_for_a_pid_never_reused_on_this_host`
/// test. Case E (`ERROR_ACCESS_DENIED`/an ambiguous access failure ->
/// `Uncertain`) is not exercised here: forcing a real `OpenProcess` access
/// denial deterministically requires a cross-privilege-boundary fixture
/// (e.g. a process owned by a different, unrelated principal) this
/// unprivileged single-user CI/certification session cannot construct --
/// the same class of limitation `provisioning::lease`'s own
/// `#[cfg(test)]`-only `INJECTED_PROBE_OVERRIDE` seam exists to work
/// around on Unix, and which has no Windows-specific test here either.
/// Case F (repeated checks racing a real process exit) is implicitly
/// covered by the two sequential checks below (`Present` while running,
/// `Absent` once reaped) never returning a contradictory or flickering
/// verdict across that transition.
#[cfg(windows)]
#[tokio::test]
async fn windows_verify_process_absent_matches_independent_tasklist_oracle_across_a_managed_process_lifecycle()
-> Result<(), String> {
    fn tasklist_lists_pid(pid: u32) -> Result<bool, String> {
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .map_err(|error| format!("tasklist invocation failed: {error}"))?;
        Ok(String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()))
    }

    let executable = super::fixture_support::fixture_binary_path()?;
    let spec = ManagedProcessSpec {
        executable,
        arguments: vec!["sleep-ms".to_string(), "10000".to_string()],
        environment: EnvironmentPolicy::empty(),
        working_directory: std::env::temp_dir(),
        max_stderr_bytes: 4096,
        argv0: None,
        managed_lease: Some(
            super::provisioning::lease::ManagedLeaseBinding::for_components(
                super::provisioning::lease::RootIdentity::of(&std::env::temp_dir()),
                "test-fixture-windows-liveness-oracle",
                Vec::new(),
            ),
        ),
    };
    let process = ManagedProcess::spawn(&spec)
        .await
        .map_err(|error| format!("spawning the managed process fixture must succeed: {error:?}"))?;
    let pid = process
        .pid()
        .ok_or("a just-spawned managed process must have a live pid")?;
    assert!(
        process.lease().is_some(),
        "spec.managed_lease was Some, so a real lease must have been registered"
    );

    // Case A / §13 WINDOWS_ACTIVE_PROCESS_LIVENESS: the managed process is
    // genuinely still running.
    let oracle_present = tasklist_lists_pid(pid)?;
    assert!(
        oracle_present,
        "tasklist oracle must observe the just-spawned managed process (pid {pid}) as present"
    );
    let product_while_running = super::provisioning::lease::verify_process_absent(
        super::provisioning::lease::ProcessIdentity { pid },
    );
    assert_eq!(
        product_while_running,
        super::provisioning::lease::ProcessAbsence::Present,
        "WINDOWS_PROCESS_LIVENESS_ORACLE_MATCH: verify_process_absent must agree with the \
         tasklist oracle (Present) for pid {pid}"
    );

    // Reap it through the same real `ManagedProcess::terminate` path
    // `full_uninstall`/`uninstall` themselves use, then re-verify.
    let exit = process.terminate().await;
    assert_eq!(exit, ManagedProcessExit::Terminated);

    // Case B/D / §13 WINDOWS_MANAGED_PROCESS_ABSENT_AFTER_REAP: the same
    // pid, now reaped, must independently confirm `Absent` on both sides.
    let oracle_absent = !tasklist_lists_pid(pid)?;
    assert!(
        oracle_absent,
        "tasklist oracle must observe the terminated managed process (pid {pid}) as absent"
    );
    let product_after_reap = super::provisioning::lease::verify_process_absent(
        super::provisioning::lease::ProcessIdentity { pid },
    );
    assert_eq!(
        product_after_reap,
        super::provisioning::lease::ProcessAbsence::Absent,
        "WINDOWS_PROCESS_LIVENESS_ORACLE_MATCH: verify_process_absent must agree with the \
         tasklist oracle (Absent) for pid {pid} after reap"
    );
    Ok(())
}

// =============================================================================
// M09-P10 (owner-authorized): native Windows zero-spawn fail-closed proofs for
// `execute_with_workspace_root`/`ManagedProcess::spawn_with_workspace_root`.
//
// The oracle (Section 22): `wht_corulix_process_fixture`'s own `write-pid-file
// <path> <sleep_ms>` mode writes a marker file as its very first action once
// it is actually running -- so the marker's ABSENCE after a call is direct,
// unambiguous proof that no child process ever executed, and its PRESENCE
// (proven first, via the allowed non-workspace `execute()` path, as a
// sanity/positive control) proves the oracle mechanism itself is live, not
// silently broken. A refusal that returns before `Command` construction can
// never produce this marker; that absence is the whole proof.
//
// RAII cleanup (Section 47 lesson from the P9R disk-pressure incident): every
// scratch directory this module creates is removed on drop, even if an
// assertion panics -- `#[cfg(windows)]`-only, so this can never affect the
// non-Windows scratch-accumulation story.
#[cfg(windows)]
mod p10_windows_fail_closed {
    use super::*;
    use std::path::{Path, PathBuf};

    struct CleanupGuard(PathBuf);
    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn unique_scratch_dir(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("corulix-p10-{label}-{stamp}"))
    }

    fn marker_spec(executable: PathBuf, working_directory: PathBuf, marker: &Path) -> ProcessSpec {
        ProcessSpec {
            executable,
            arguments: vec![
                "write-pid-file".to_string(),
                marker.to_string_lossy().into_owned(),
                "0".to_string(),
            ],
            environment: EnvironmentPolicy::empty(),
            working_directory,
            limits: ProcessLimits::default(),
            timeout: Duration::from_secs(10),
            execution_class: ExecutionClass::TrustedWorkspaceExecution,
            argv0: None,
        }
    }

    /// Section 22/41.1: the core zero-spawn oracle. Proves both halves: the
    /// marker mechanism genuinely fires when a process runs (positive
    /// control, via the allowed non-workspace `execute()` path), and
    /// `execute_with_workspace_root` produces neither the marker nor
    /// anything but `SpawnFailed` when asked to run the identical fixture
    /// against a real, pinned `WorkspaceRoot`.
    #[tokio::test]
    async fn windows_execute_with_workspace_root_is_zero_spawn() -> Result<(), String> {
        let executable = super::super::fixture_support::fixture_binary_path()?;

        // Positive control first -- must be proven BEFORE trusting the
        // later absence as evidence of anything.
        let control_dir = unique_scratch_dir("oracle-control");
        std::fs::create_dir_all(&control_dir).map_err(|error| error.to_string())?;
        let _control_guard = CleanupGuard(control_dir.clone());
        let control_marker = control_dir.join("marker.txt");
        let mut control_spec =
            marker_spec(executable.clone(), std::env::temp_dir(), &control_marker);
        control_spec.execution_class = ExecutionClass::ControlledExternalTool;
        let control_outcome = execute(&control_spec, &CancellationToken::new()).await;
        assert_eq!(
            control_outcome.termination,
            TerminationReason::Exited { code: 0 },
            "oracle sanity: the allowed non-workspace execute() path must genuinely run the \
             fixture"
        );
        assert!(
            control_marker.is_file(),
            "oracle sanity: a real spawn must produce the marker file -- if this fails, the \
             oracle itself is broken and the negative result below proves nothing"
        );

        // The real target: a TRUSTED_WORKSPACE_EXECUTION-shaped spec, cwd
        // set to a real, pinned WorkspaceRoot's own canonical path, exactly
        // as every production caller (diagnostics.rs, testing.rs,
        // go_validation.rs, go_testing.rs, ts_validation.rs, ts_testing.rs,
        // python_validation.rs, python_testing.rs) builds it.
        let workspace_dir = unique_scratch_dir("oracle-workspace");
        std::fs::create_dir_all(&workspace_dir).map_err(|error| error.to_string())?;
        let _workspace_guard = CleanupGuard(workspace_dir.clone());
        let workspace_root =
            WorkspaceRoot::open(&workspace_dir).map_err(|error| format!("{error:?}"))?;
        let marker = workspace_dir.join("should-never-exist.marker");
        let spec = marker_spec(
            executable,
            workspace_root.canonical_path().to_path_buf(),
            &marker,
        );

        let outcome =
            execute_with_workspace_root(&spec, &workspace_root, &CancellationToken::new()).await;
        assert_eq!(
            outcome.termination,
            TerminationReason::SpawnFailed,
            "M09_P10_WINDOWS_TRUSTED_WORKSPACE_SPAWN_COUNT must be 0: execute_with_workspace_root \
             must fail closed on Windows, never fall back to a pathname-cwd spawn"
        );
        assert!(
            !marker.exists(),
            "zero-spawn oracle: marker file must be ABSENT -- its presence would prove a real \
             process actually ran"
        );
        Ok(())
    }

    /// Section 41.5: the `ManagedProcess` persistent-session counterpart
    /// (the primitive `wht_corulix_lsp::LspSession::spawn` itself calls) must
    /// exhibit the identical zero-spawn property.
    #[tokio::test]
    async fn windows_managed_process_spawn_with_workspace_root_is_zero_spawn() -> Result<(), String>
    {
        let executable = super::super::fixture_support::fixture_binary_path()?;
        let workspace_dir = unique_scratch_dir("managed-oracle-workspace");
        std::fs::create_dir_all(&workspace_dir).map_err(|error| error.to_string())?;
        let _workspace_guard = CleanupGuard(workspace_dir.clone());
        let workspace_root =
            WorkspaceRoot::open(&workspace_dir).map_err(|error| format!("{error:?}"))?;
        let marker = workspace_dir.join("should-never-exist-managed.marker");

        let spec = ManagedProcessSpec {
            executable,
            arguments: vec![
                "write-pid-file".to_string(),
                marker.to_string_lossy().into_owned(),
                "0".to_string(),
            ],
            environment: EnvironmentPolicy::empty(),
            working_directory: workspace_root.canonical_path().to_path_buf(),
            max_stderr_bytes: 1024 * 1024,
            argv0: None,
            managed_lease: None,
        };
        let result = ManagedProcess::spawn_with_workspace_root(&spec, &workspace_root).await;
        assert!(
            matches!(result, Err(ManagedProcessSpawnError::SpawnFailed)),
            "M09_P10_WINDOWS_TRUSTED_WORKSPACE_SPAWN_COUNT must be 0: \
             ManagedProcess::spawn_with_workspace_root must fail closed on Windows"
        );
        assert!(
            !marker.exists(),
            "zero-spawn oracle: marker file must be ABSENT for the ManagedProcess path too"
        );
        Ok(())
    }

    /// Section 27/33: repeated calls against the same pinned root remain
    /// stably fail-closed (no first-call-fails-then-unsafe-fallback), and
    /// leave zero orphan fixture processes behind -- checked against a real
    /// `tasklist` count of the fixture's own image name, not merely "the
    /// call returned an error."
    #[tokio::test]
    async fn windows_repeated_execute_with_workspace_root_stays_fail_closed_with_zero_orphans()
    -> Result<(), String> {
        let executable = super::super::fixture_support::fixture_binary_path()?;
        let image_name = executable
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("fixture executable has no file name")?
            .to_string();
        let workspace_dir = unique_scratch_dir("repeated-oracle-workspace");
        std::fs::create_dir_all(&workspace_dir).map_err(|error| error.to_string())?;
        let _workspace_guard = CleanupGuard(workspace_dir.clone());
        let workspace_root =
            WorkspaceRoot::open(&workspace_dir).map_err(|error| format!("{error:?}"))?;

        let pre_count = fixture_process_count(&image_name)?;
        for attempt in 0..5 {
            let marker = workspace_dir.join(format!("repeat-{attempt}.marker"));
            let spec = marker_spec(
                executable.clone(),
                workspace_root.canonical_path().to_path_buf(),
                &marker,
            );
            let outcome =
                execute_with_workspace_root(&spec, &workspace_root, &CancellationToken::new())
                    .await;
            assert_eq!(
                outcome.termination,
                TerminationReason::SpawnFailed,
                "attempt {attempt}: repeated fail-closed calls must remain stably SpawnFailed, \
                 never succeed after a prior refusal"
            );
            assert!(
                !marker.exists(),
                "attempt {attempt}: marker must stay absent"
            );
        }
        let post_count = fixture_process_count(&image_name)?;
        assert_eq!(
            post_count, pre_count,
            "M09_P10_WINDOWS_ORPHAN_PROCESS_COUNT must be 0: repeated fail-closed calls must \
             never leave an orphaned fixture process behind"
        );
        Ok(())
    }

    /// Section 27: replacing the workspace root's pathname with an entirely
    /// different real directory between `WorkspaceRoot::open` and the
    /// execution attempt must still yield zero spawn -- Windows's fail-closed
    /// behavior does not depend on (and is not weakened by) any root-swap
    /// TOCTOU window, unlike the pathname-cwd design it replaces.
    #[tokio::test]
    async fn windows_execute_with_workspace_root_stays_zero_spawn_after_root_path_replacement()
    -> Result<(), String> {
        let executable = super::super::fixture_support::fixture_binary_path()?;
        let original_dir = unique_scratch_dir("swap-original");
        std::fs::create_dir_all(&original_dir).map_err(|error| error.to_string())?;
        let _original_guard = CleanupGuard(original_dir.clone());
        let workspace_root =
            WorkspaceRoot::open(&original_dir).map_err(|error| format!("{error:?}"))?;
        let original_canonical = workspace_root.canonical_path().to_path_buf();

        // Swap the pathname: move the original directory aside, put a fresh,
        // different directory at the same canonical path.
        let moved_aside = unique_scratch_dir("swap-moved-away");
        std::fs::rename(&original_canonical, &moved_aside).map_err(|error| error.to_string())?;
        let _moved_guard = CleanupGuard(moved_aside);
        std::fs::create_dir_all(&original_canonical).map_err(|error| error.to_string())?;
        let _replacement_guard = CleanupGuard(original_canonical.clone());

        let marker = original_canonical.join("should-never-exist-after-swap.marker");
        let spec = marker_spec(executable, original_canonical.clone(), &marker);
        let outcome =
            execute_with_workspace_root(&spec, &workspace_root, &CancellationToken::new()).await;
        assert_eq!(
            outcome.termination,
            TerminationReason::SpawnFailed,
            "root-path replacement must still yield zero spawn on Windows"
        );
        assert!(!marker.exists());
        Ok(())
    }

    /// Section 28: replacing the workspace root's pathname with an NTFS
    /// junction (a reparse point) to an entirely different directory --
    /// rather than an ordinary directory as the previous test uses -- must
    /// still yield zero spawn. Junction creation needs no elevation/
    /// Developer Mode on this host (confirmed empirically via a real
    /// `mklink /J` before writing this test); `cmd /c mklink /J` is used
    /// only as TEST FIXTURE SETUP (constructing the adversarial filesystem
    /// state to test against), never part of the code path under test --
    /// mirrors this file's own existing use of `tasklist`/`cmd`-adjacent
    /// tooling as an external oracle/fixture, not a product dependency.
    #[tokio::test]
    async fn windows_execute_with_workspace_root_stays_zero_spawn_after_junction_root_replacement()
    -> Result<(), String> {
        let executable = super::super::fixture_support::fixture_binary_path()?;
        let original_dir = unique_scratch_dir("junction-original");
        std::fs::create_dir_all(&original_dir).map_err(|error| error.to_string())?;
        let _original_guard = CleanupGuard(original_dir.clone());
        let workspace_root =
            WorkspaceRoot::open(&original_dir).map_err(|error| format!("{error:?}"))?;
        let original_canonical = workspace_root.canonical_path().to_path_buf();

        let junction_target = unique_scratch_dir("junction-target");
        std::fs::create_dir_all(&junction_target).map_err(|error| error.to_string())?;
        let _target_guard = CleanupGuard(junction_target.clone());

        // Free the pinned root's own pathname, then reparse-point it at an
        // entirely different, also-empty directory.
        std::fs::remove_dir(&original_canonical).map_err(|error| error.to_string())?;
        let mklink_status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &original_canonical.to_string_lossy(),
                &junction_target.to_string_lossy(),
            ])
            .status()
            .map_err(|error| format!("mklink invocation failed: {error}"))?;
        assert!(
            mklink_status.success(),
            "test fixture setup: mklink /J must succeed to exercise this scenario at all"
        );
        let _junction_guard = CleanupGuard(original_canonical.clone());

        let marker = junction_target.join("should-never-exist-after-junction-swap.marker");
        let spec = marker_spec(executable, original_canonical.clone(), &marker);
        let outcome =
            execute_with_workspace_root(&spec, &workspace_root, &CancellationToken::new()).await;
        assert_eq!(
            outcome.termination,
            TerminationReason::SpawnFailed,
            "junction/reparse-point root replacement must still yield zero spawn on Windows"
        );
        assert!(!marker.exists());
        Ok(())
    }

    /// Real `tasklist /FI "IMAGENAME eq <name>" /NH` count -- an independent
    /// OS-level oracle, never `wht_corulix_tooling`'s own liveness primitive,
    /// mirroring this file's existing Windows liveness tests.
    fn fixture_process_count(image_name: &str) -> Result<usize, String> {
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {image_name}"), "/NH"])
            .output()
            .map_err(|error| format!("tasklist invocation failed: {error}"))?;
        let listing = String::from_utf8_lossy(&output.stdout);
        Ok(listing
            .lines()
            .filter(|line| {
                line.to_ascii_lowercase()
                    .contains(&image_name.to_ascii_lowercase())
            })
            .count())
    }
}
