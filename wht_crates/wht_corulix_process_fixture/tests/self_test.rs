// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Self-test suite for `wht_corulix_process_fixture` (P17-W-R3-C2,
//! `FIXTURE_SELF_TEST_LINUX`/`FIXTURE_SELF_TEST_WINDOWS`).
//!
//! This is the ONE integration-test site where `CARGO_BIN_EXE_<name>` is
//! Cargo's own native, guaranteed resolution mechanism -- these tests live
//! in this fixture crate's own `tests/` directory, so Cargo builds the
//! `[[bin]]` target and injects `CARGO_BIN_EXE_wht_corulix_process_fixture`
//! before running them (proven empirically in the P17-W-R3-C2 scratch
//! experiment: this exact "same-package integration test" cell was the
//! only one of five cells where the env var was set). Every other
//! consumer of this fixture (a *different* package's tests) uses
//! `escargot` instead -- see `wht_corulix_tooling::fixture_support`.
//!
//! These tests exercise the fixture binary directly with
//! `std::process::Command`, never through `wht_corulix_tooling::execute`
//! -- that real-product-path exercise happens in
//! `wht_corulix_tooling`'s own test suite (`src/tests.rs`) and the Windows
//! process-primitive matrix, not here. This file only proves the fixture
//! itself behaves as specified, independent of Corulix's process layer.

use std::process::Command;

fn fixture_exe() -> &'static str {
    env!("CARGO_BIN_EXE_wht_corulix_process_fixture")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn run_json(args: &[&str]) -> Result<serde_json::Value, String> {
    let output = Command::new(fixture_exe())
        .args(args)
        .output()
        .map_err(|error| format!("failed to spawn fixture: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "fixture exited non-zero ({:?}); stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(text.trim()).map_err(|error| format!("invalid JSON {text:?}: {error}"))
}

#[test]
fn self_test_argv_empty() -> Result<(), String> {
    let payload = run_json(&["print-argv"])?;
    assert_eq!(payload["argv_hex"].as_array().ok_or("missing")?.len(), 0);
    Ok(())
}

#[test]
fn self_test_argv_single_empty_string() -> Result<(), String> {
    let payload = run_json(&["print-argv", ""])?;
    let argv: Vec<String> = payload["argv_hex"]
        .as_array()
        .ok_or("missing")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(argv, vec![hex_encode(b"")]);
    Ok(())
}

#[test]
fn self_test_argv_multiple_and_embedded_space() -> Result<(), String> {
    let payload = run_json(&["print-argv", "a", "b", "a b"])?;
    let argv: Vec<String> = payload["argv_hex"]
        .as_array()
        .ok_or("missing")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        argv,
        vec![hex_encode(b"a"), hex_encode(b"b"), hex_encode(b"a b")]
    );
    Ok(())
}

#[test]
fn self_test_argv_quotes_and_backslashes() -> Result<(), String> {
    let tricky = r#"a"b\c\\d"#;
    let payload = run_json(&["print-argv", tricky])?;
    let argv: Vec<String> = payload["argv_hex"]
        .as_array()
        .ok_or("missing")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(argv, vec![hex_encode(tricky.as_bytes())]);
    Ok(())
}

#[test]
fn self_test_argv_unicode() -> Result<(), String> {
    let unicode = "héllo-🦀-мир";
    let payload = run_json(&["print-argv", unicode])?;
    let argv: Vec<String> = payload["argv_hex"]
        .as_array()
        .ok_or("missing")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(argv, vec![hex_encode(unicode.as_bytes())]);
    Ok(())
}

#[test]
fn self_test_env_dump_matches_child_environment() -> Result<(), String> {
    let output = Command::new(fixture_exe())
        .arg("print-env")
        .env_clear()
        .env("WHT_SELF_TEST_VAR", "value123")
        .output()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(output.status.success());
    let payload: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim())
            .map_err(|error| format!("invalid JSON: {error}"))?;
    let entries = payload["env_hex"].as_array().ok_or("missing")?;
    // The fixture's `os_string_to_bytes` reports raw OS-native bytes: on
    // Unix that is the value's UTF-8 bytes verbatim, but on Windows every
    // environment variable value is natively UTF-16, so the fixture
    // reports UTF-16LE code units -- the expected hex must match whichever
    // native encoding this platform actually uses, not assume UTF-8
    // unconditionally.
    #[cfg(windows)]
    let expected_value_bytes: Vec<u8> = "value123"
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    #[cfg(not(windows))]
    let expected_value_bytes: Vec<u8> = b"value123".to_vec();
    let expected_hex = hex_encode(&expected_value_bytes);
    let found = entries.iter().any(|entry| {
        let pair = entry.as_array().map(|p| p.as_slice()).unwrap_or_default();
        pair.first().and_then(|v| v.as_str()) == Some("WHT_SELF_TEST_VAR")
            && pair.get(1).and_then(|v| v.as_str()) == Some(expected_hex.as_str())
    });
    assert!(found, "expected WHT_SELF_TEST_VAR in dump: {entries:?}");
    Ok(())
}

#[test]
fn self_test_cwd_is_reported() -> Result<(), String> {
    let dir = std::env::temp_dir();
    let output = Command::new(fixture_exe())
        .arg("print-cwd")
        .current_dir(&dir)
        .output()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(output.status.success());
    let payload: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim())
            .map_err(|error| format!("invalid JSON: {error}"))?;
    let reported = payload["cwd"].as_str().ok_or("missing")?;
    assert_eq!(std::path::PathBuf::from(reported), dir);
    Ok(())
}

#[test]
fn self_test_stdout_write() -> Result<(), String> {
    let output = Command::new(fixture_exe())
        .args(["write-stdout-hex", &hex_encode(b"hello-stdout")])
        .output()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"hello-stdout");
    Ok(())
}

#[test]
fn self_test_stderr_write() -> Result<(), String> {
    let output = Command::new(fixture_exe())
        .args(["write-stderr-hex", &hex_encode(b"hello-stderr")])
        .output()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(output.status.success());
    assert_eq!(output.stderr, b"hello-stderr");
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn self_test_echo_stdin() -> Result<(), String> {
    use std::io::Write as _;
    let mut child = Command::new(fixture_exe())
        .arg("echo-stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn failed: {error}"))?;
    let mut stdin = child.stdin.take().ok_or("child stdin was not piped")?;
    stdin
        .write_all(b"hello from corulix formatter")
        .map_err(|error| format!("stdin write failed: {error}"))?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait failed: {error}"))?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"hello from corulix formatter");
    Ok(())
}

#[test]
fn self_test_echo_stdin_empty() -> Result<(), String> {
    let mut child = Command::new(fixture_exe())
        .arg("echo-stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn failed: {error}"))?;
    // Closing stdin immediately (dropping the child's stdin handle) is
    // itself the EOF signal -- no bytes written at all.
    drop(child.stdin.take());
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait failed: {error}"))?;
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn self_test_write_stdout_hex_then_sleep_ms() -> Result<(), String> {
    let start = std::time::Instant::now();
    let output = Command::new(fixture_exe())
        .args([
            "write-stdout-hex-then-sleep-ms",
            &hex_encode(b"partial-frame"),
            "50",
        ])
        .output()
        .map_err(|error| format!("spawn failed: {error}"))?;
    let elapsed = start.elapsed();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"partial-frame");
    assert!(
        elapsed >= std::time::Duration::from_millis(45),
        "expected the process to hold alive for roughly the requested sleep, elapsed={elapsed:?}"
    );
    Ok(())
}

#[test]
fn self_test_write_stdout_hex_then_sleep_ms_is_readable_before_it_exits() -> Result<(), String> {
    use std::io::Read as _;
    let mut child = Command::new(fixture_exe())
        .args([
            "write-stdout-hex-then-sleep-ms",
            &hex_encode(b"Content-Length: 999999999999\r\n\r\n"),
            "5000",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn failed: {error}"))?;
    let mut stdout = child.stdout.take().ok_or("child stdout was not piped")?;
    // The write is flushed before the sleep begins, so the real bytes must
    // be readable well before the process itself exits -- proves this
    // mode's caller (a framing/timeout test) genuinely observes a partial,
    // still-alive child, not merely a process that already exited.
    let mut buffer = vec![0u8; "Content-Length: 999999999999\r\n\r\n".len()];
    stdout
        .read_exact(&mut buffer)
        .map_err(|error| format!("stdout read failed: {error}"))?;
    assert_eq!(buffer, b"Content-Length: 999999999999\r\n\r\n");
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

#[test]
fn self_test_exit_code_zero_and_nonzero() -> Result<(), String> {
    let ok = Command::new(fixture_exe())
        .args(["exit-code", "0"])
        .status()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(ok.success());
    let bad = Command::new(fixture_exe())
        .args(["exit-code", "7"])
        .status()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert_eq!(bad.code(), Some(7));
    Ok(())
}

#[test]
fn self_test_sleep_ms_actually_blocks() -> Result<(), String> {
    let started = std::time::Instant::now();
    let status = Command::new(fixture_exe())
        .args(["sleep-ms", "150"])
        .status()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(status.success());
    assert!(started.elapsed() >= std::time::Duration::from_millis(120));
    Ok(())
}

#[test]
fn self_test_print_pid_matches_os_reported_pid() -> Result<(), String> {
    let child = Command::new(fixture_exe())
        .arg("print-pid")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn failed: {error}"))?;
    let os_pid = child.id();
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait failed: {error}"))?;
    let payload: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim())
            .map_err(|error| format!("invalid JSON: {error}"))?;
    let reported_pid = payload["pid"].as_u64().ok_or("missing pid")?;
    assert_eq!(reported_pid, u64::from(os_pid));
    Ok(())
}

#[test]
fn self_test_bounded_stdout_produces_exact_byte_count() -> Result<(), String> {
    let output = Command::new(fixture_exe())
        .args(["bounded-stdout", "12345"])
        .output()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 12345);
    Ok(())
}

#[test]
fn self_test_dual_stream_writes_both_streams() -> Result<(), String> {
    let output = Command::new(fixture_exe())
        .args(["dual-stream", "50000", "60000"])
        .output()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 50000);
    assert_eq!(output.stderr.len(), 60000);
    Ok(())
}

#[test]
fn self_test_spawn_child_reports_a_real_distinct_pid_and_pidfile() -> Result<(), String> {
    let dir = std::env::temp_dir();
    let pid_file = dir.join(format!(
        "wht-fixture-self-test-child-{}.pid",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&pid_file);
    let mut child = Command::new(fixture_exe())
        .args(["spawn-child", "300", &pid_file.to_string_lossy()])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn failed: {error}"))?;
    let parent_pid = child.id();

    let mut stdout = child.stdout.take().ok_or("no stdout handle")?;
    let mut first_line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = std::io::Read::read(&mut stdout, &mut byte)
            .map_err(|error| format!("read failed: {error}"))?;
        if read == 0 || byte[0] == b'\n' {
            break;
        }
        first_line.push(byte[0]);
    }
    let payload: serde_json::Value = serde_json::from_str(
        std::str::from_utf8(&first_line).map_err(|error| format!("not utf8: {error}"))?,
    )
    .map_err(|error| format!("invalid JSON: {error}"))?;
    let child_pid = payload["child_pid"].as_u64().ok_or("missing child_pid")?;
    assert_ne!(child_pid, u64::from(parent_pid));

    let status = child
        .wait()
        .map_err(|error| format!("wait failed: {error}"))?;
    assert!(status.success());

    let pid_from_file = std::fs::read_to_string(&pid_file)
        .map_err(|error| format!("pid file missing: {error}"))?
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("pid file not numeric: {error}"))?;
    let _ = std::fs::remove_file(&pid_file);
    assert_eq!(pid_from_file, child_pid);
    Ok(())
}

#[test]
fn self_test_spawn_grandchild_forms_a_three_level_tree() -> Result<(), String> {
    let dir = std::env::temp_dir();
    let pid_file = dir.join(format!(
        "wht-fixture-self-test-grandchild-{}.pid",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&pid_file);
    let mut top = Command::new(fixture_exe())
        .args(["spawn-grandchild", "300", &pid_file.to_string_lossy()])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn failed: {error}"))?;

    let mut stdout = top.stdout.take().ok_or("no stdout handle")?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut stdout, &mut buf)
        .map_err(|error| format!("read failed: {error}"))?;
    let status = top
        .wait()
        .map_err(|error| format!("wait failed: {error}"))?;
    assert!(status.success());

    // At least one JSON line was produced by the top-level "spawn-grandchild"
    // announcement of its own (middle) child's pid.
    let first_line = buf
        .split(|byte| *byte == b'\n')
        .find(|line| !line.is_empty())
        .ok_or("no output line")?;
    let payload: serde_json::Value = serde_json::from_str(
        std::str::from_utf8(first_line).map_err(|error| format!("not utf8: {error}"))?,
    )
    .map_err(|error| format!("invalid JSON: {error}"))?;
    assert!(payload["child_pid"].as_u64().is_some());

    let pid_from_file = std::fs::read_to_string(&pid_file)
        .map_err(|error| format!("pid file missing (grandchild never ran): {error}"))?;
    let _ = std::fs::remove_file(&pid_file);
    assert!(!pid_from_file.trim().is_empty());
    Ok(())
}

#[test]
fn self_test_spawn_immediate_child_alias_behaves_like_spawn_child() -> Result<(), String> {
    let dir = std::env::temp_dir();
    let pid_file = dir.join(format!(
        "wht-fixture-self-test-immediate-{}.pid",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&pid_file);
    let status = Command::new(fixture_exe())
        .args(["spawn-immediate-child", "50", &pid_file.to_string_lossy()])
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(status.success());
    let exists = pid_file.exists();
    let _ = std::fs::remove_file(&pid_file);
    assert!(exists, "immediate child must have written its pid file");
    Ok(())
}

#[test]
fn self_test_write_pid_file_and_wait_uses_stdin_independent_lifecycle() -> Result<(), String> {
    // A liveness-audit control: this invocation must terminate on its own
    // (bounded sleep) without requiring any signal on stdin/stdout/stderr,
    // proving the fixture never performs an unbounded wait for an event
    // that might not arrive (UNBOUNDED_TEST_FIXTURE_WAIT_COUNT audit).
    let mut child = Command::new(fixture_exe())
        .args(["sleep-ms", "50"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn failed: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("wait failed: {error}"))?;
    assert!(status.success());
    Ok(())
}

#[test]
fn self_test_unknown_mode_fails_closed_not_silently() -> Result<(), String> {
    let output = Command::new(fixture_exe())
        .arg("this-mode-does-not-exist")
        .output()
        .map_err(|error| format!("spawn failed: {error}"))?;
    assert!(!output.status.success());
    Ok(())
}

/// Exercises the fixture through `wht_corulix_tooling`'s real public
/// `execute` API (not just raw `std::process::Command`), proving the
/// fixture is also a valid target for the actual production process path
/// -- this is the "same-package integration test depends on the public
/// API it's meant to exercise" design named in P17-W-R3-C2 §13, used here
/// as an additional cross-check alongside `wht_corulix_tooling`'s own
/// `src/tests.rs` migration.
#[tokio::test]
async fn self_test_through_real_corulix_process_path() -> Result<(), String> {
    let exe = fixture_exe();
    let spec = wht_corulix_tooling::ProcessSpec {
        executable: std::path::PathBuf::from(exe),
        arguments: vec!["exit-code".to_string(), "0".to_string()],
        environment: wht_corulix_tooling::EnvironmentPolicy::empty(),
        working_directory: std::env::temp_dir(),
        limits: wht_corulix_tooling::ProcessLimits::default(),
        timeout: std::time::Duration::from_secs(5),
        execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
        argv0: None,
    };
    let outcome =
        wht_corulix_tooling::execute(&spec, &wht_corulix_core::CancellationToken::new()).await;
    assert_eq!(
        outcome.termination,
        wht_corulix_tooling::TerminationReason::Exited { code: 0 }
    );
    Ok(())
}
