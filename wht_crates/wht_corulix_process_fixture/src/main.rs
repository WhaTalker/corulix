// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! `wht_corulix_process_fixture` -- deterministic, cross-platform child
//! process for Corulix process-primitive tests (P17-W-R3-C2).
//!
//! This binary is TEST-ONLY infrastructure (see this crate's `Cargo.toml`
//! header comment): it is never published, never a managed provider, never
//! an MCP tool, and never a product runtime dependency. Its sole purpose is
//! to stand in for `/usr/bin/echo`, `/usr/bin/env`, `/usr/bin/pwd`,
//! `/usr/bin/dd`, `/usr/bin/sleep`, `/usr/bin/true`, `/usr/bin/false`, and
//! `/bin/sh` in Corulix's own process-execution tests, on every platform
//! Corulix targets, including native Windows where none of those Unix
//! binaries exist.
//!
//! Mode selection is via `argv[0]` of the arguments this program itself
//! receives (i.e. the first element of `ProcessSpec::arguments`, never the
//! program path) -- never an environment variable -- so a mode still
//! dispatches correctly even under an `EnvironmentPolicy` that forwards
//! nothing (proving ambient-environment isolation does not also break the
//! fixture's own control channel).
//!
//! All structural reporting (argv, environment, cwd, pid) is emitted as one
//! line of JSON to stdout, with every byte string hex-encoded rather than
//! passed through as a lossy UTF-8 `String` -- this is what lets a caller
//! unambiguously distinguish `[]` from `[""]`, `["a","b"]` from `["a b"]`,
//! and literal quotes/backslashes/unpaired-surrogate Windows arguments from
//! their escaped/re-interpreted forms.

#![allow(clippy::print_stdout)]

use std::io::Write as _;
use std::process::ExitCode;

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string: {text:?}"));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let pair = std::str::from_utf8(&bytes[index..index + 2])
            .map_err(|error| format!("invalid hex chunk at {index}: {error}"))?;
        let value = u8::from_str_radix(pair, 16)
            .map_err(|error| format!("invalid hex byte {pair:?}: {error}"))?;
        out.push(value);
        index += 2;
    }
    Ok(out)
}

/// Raw OS-native argument bytes, platform-agnostic.
///
/// On Unix, `OsStr` already exposes raw bytes directly. On Windows, `OsStr`
/// exposes UTF-16 code units (`encode_wide`); those are serialized here as
/// their little-endian byte representation so an unpaired surrogate (never
/// valid UTF-8/UTF-16 as text, but a legal raw Windows command-line unit) is
/// preserved exactly rather than lossily replaced.
fn os_string_to_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        value.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        let mut out = Vec::new();
        for unit in value.encode_wide() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }
    #[cfg(not(any(unix, windows)))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("wht_corulix_process_fixture: {message}");
    ExitCode::from(97)
}

fn parse_arg<T: std::str::FromStr>(args: &[String], index: usize, name: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    args.get(index)
        .ok_or_else(|| format!("missing required argument {index} ({name})"))?
        .parse::<T>()
        .map_err(|error| format!("invalid argument {index} ({name}): {error}"))
}

fn write_bounded(stream: &mut dyn std::io::Write, byte_count: usize) -> std::io::Result<()> {
    const CHUNK: usize = 65536;
    let pattern = [0u8; CHUNK];
    let mut remaining = byte_count;
    while remaining > 0 {
        let take = remaining.min(CHUNK);
        stream.write_all(&pattern[..take])?;
        remaining -= take;
    }
    Ok(())
}

fn current_exe_path() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|error| format!("current_exe failed: {error}"))
}

fn spawn_self(child_args: &[String]) -> Result<std::process::Child, String> {
    let exe = current_exe_path()?;
    std::process::Command::new(exe)
        .args(child_args)
        .spawn()
        .map_err(|error| format!("failed to spawn self as child: {error}"))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().cloned().unwrap_or_default();
    let rest = &args[1.min(args.len())..];

    match mode.as_str() {
        "print-argv" => {
            let argv_hex: Vec<String> = rest.iter().map(|a| hex_encode(a.as_bytes())).collect();
            // Also capture the OS-native argv exactly as the process
            // received it (covers cases where lossy `String` conversion
            // upstream of this binary could not have altered anything,
            // but keeps the raw-bytes path exercised end-to-end).
            let raw_argv_hex: Vec<String> = std::env::args_os()
                .skip(2)
                .map(|a| hex_encode(&os_string_to_bytes(&a)))
                .collect();
            let payload = serde_json::json!({
                "mode": "print-argv",
                "argv_hex": argv_hex,
                "raw_argv_hex": raw_argv_hex,
            });
            println!("{payload}");
            Ok(())
        }
        "print-env" => {
            let mut entries: Vec<(String, String)> = std::env::vars_os()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        hex_encode(&os_string_to_bytes(&v)),
                    )
                })
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let payload = serde_json::json!({
                "mode": "print-env",
                "env_hex": entries,
            });
            println!("{payload}");
            Ok(())
        }
        "print-cwd" => {
            let cwd =
                std::env::current_dir().map_err(|error| format!("current_dir failed: {error}"))?;
            let payload = serde_json::json!({
                "mode": "print-cwd",
                "cwd": cwd.to_string_lossy(),
                "cwd_hex": hex_encode(&os_string_to_bytes(cwd.as_os_str())),
            });
            println!("{payload}");
            Ok(())
        }
        "print-cwd-identity" => {
            // M09-P6: an OBJECT identity oracle for the process's current
            // working directory -- deliberately independent of any
            // printable path text (`print-cwd` above), since a directory
            // that has been renamed/replaced can have a legitimately
            // different printable path while still being (or not being)
            // the correct underlying filesystem object. `(device, inode)`
            // of "." is the same real-object identity
            // `wht_corulix_workspace::WorkspaceRootIdentity` itself is
            // built from.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                let metadata = std::fs::metadata(".")
                    .map_err(|error| format!("metadata(\".\") failed: {error}"))?;
                let payload = serde_json::json!({
                    "mode": "print-cwd-identity",
                    "device": metadata.dev(),
                    "inode": metadata.ino(),
                });
                println!("{payload}");
                Ok(())
            }
            #[cfg(not(unix))]
            {
                Err(
                    "print-cwd-identity is only implemented on unix (device/inode identity \
                     has no equivalent stable meaning requested yet on this platform)"
                        .to_string(),
                )
            }
        }
        "print-fd-count" => {
            // M09-P6: lets a caller confirm, from the CHILD's own
            // post-exec perspective, that a `CLOEXEC`-flagged fd used to
            // bind this process's cwd before exec did NOT survive into
            // this process's own fd table -- `exec()` closes every
            // `CLOEXEC` fd as part of the image transition, before this
            // binary's own `main` ever runs, so this count is expected to
            // be small and stable (stdin/stdout/stderr plus whatever this
            // enumeration itself transiently opens), never inflated by
            // anything the parent bound.
            #[cfg(unix)]
            {
                let mut count = 0_usize;
                let mut entries = Vec::new();
                for entry in std::fs::read_dir("/proc/self/fd")
                    .map_err(|error| format!("read_dir(/proc/self/fd) failed: {error}"))?
                {
                    let entry = entry.map_err(|error| format!("read_dir entry failed: {error}"))?;
                    count += 1;
                    entries.push(entry.file_name().to_string_lossy().into_owned());
                }
                entries.sort();
                let payload = serde_json::json!({
                    "mode": "print-fd-count",
                    "count": count,
                    "fds": entries,
                });
                println!("{payload}");
                Ok(())
            }
            #[cfg(not(unix))]
            {
                Err("print-fd-count is only implemented on unix (/proc/self/fd)".to_string())
            }
        }
        "print-fd-targets" => {
            // M09-P6 corrective closure: `print-fd-count` alone only ever
            // proves a raw count didn't grow -- it cannot name WHICH
            // filesystem object survived exec, so it cannot distinguish
            // "the bound fd leaked" from "this host/container simply opens
            // more baseline descriptors than another host does". This mode
            // resolves each open fd's actual referent (device, inode) via
            // `/proc/self/fd/<n>`, which is a symlink to the real
            // underlying open file description -- `std::fs::metadata`
            // follows that symlink and reports the identity of what it
            // actually points at, the exact same `(dev, ino)` pair
            // `print-cwd-identity` and this crate's own test helpers use
            // to identify a specific directory object. A caller can then
            // assert that a SPECIFIC known object's identity is absent
            // from this list, rather than merely that the list's length
            // didn't change.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                let mut targets = Vec::new();
                for entry in std::fs::read_dir("/proc/self/fd")
                    .map_err(|error| format!("read_dir(/proc/self/fd) failed: {error}"))?
                {
                    let entry = entry.map_err(|error| format!("read_dir entry failed: {error}"))?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let Ok(fd_number) = name.parse::<i64>() else {
                        continue;
                    };
                    // A best-effort resolution: an fd can legitimately
                    // vanish between the directory listing and this stat
                    // (e.g. it was the transient fd this very read_dir
                    // call itself used, now already closed) -- that race
                    // is not a defect to report, just an entry to skip.
                    let Ok(metadata) = std::fs::metadata(entry.path()) else {
                        continue;
                    };
                    targets.push(serde_json::json!({
                        "fd": fd_number,
                        "device": metadata.dev(),
                        "inode": metadata.ino(),
                    }));
                }
                targets.sort_by_key(|value| value["fd"].as_i64().unwrap_or_default());
                let payload = serde_json::json!({
                    "mode": "print-fd-targets",
                    "targets": targets,
                });
                println!("{payload}");
                Ok(())
            }
            #[cfg(not(unix))]
            {
                Err("print-fd-targets is only implemented on unix (/proc/self/fd)".to_string())
            }
        }
        "print-pid" => {
            let payload = serde_json::json!({ "mode": "print-pid", "pid": std::process::id() });
            println!("{payload}");
            Ok(())
        }
        "exit-code" => {
            let code: i32 = parse_arg(rest, 0, "exit_code")?;
            std::process::exit(code);
        }
        "sleep-ms" => {
            let millis: u64 = parse_arg(rest, 0, "sleep_ms")?;
            std::thread::sleep(std::time::Duration::from_millis(millis));
            Ok(())
        }
        "write-stdout-hex" => {
            let hex = rest.first().ok_or("missing stdout hex payload")?;
            let bytes = hex_decode(hex)?;
            std::io::stdout()
                .write_all(&bytes)
                .map_err(|error| format!("stdout write failed: {error}"))?;
            Ok(())
        }
        "echo-stdin" => {
            // Reads all of stdin to EOF and writes it back to stdout
            // verbatim, then exits 0 -- a portable, deterministic stand-in
            // for `/bin/cat` used to prove a caller's write/EOF/drain
            // protocol against a real child process on every platform,
            // including native Windows where no `cat` exists.
            let mut buffer = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut buffer)
                .map_err(|error| format!("stdin read failed: {error}"))?;
            std::io::stdout()
                .write_all(&buffer)
                .map_err(|error| format!("stdout write failed: {error}"))?;
            Ok(())
        }
        "write-stdout-hex-then-sleep-ms" => {
            // Writes (and flushes) a specific, caller-controlled byte
            // sequence to stdout, then holds the process alive for a
            // bounded duration before exiting -- a portable stand-in for a
            // shell one-liner like `printf '...'; sleep 5` (no `/bin/sh`
            // on native Windows), used to prove framing/timeout/
            // cancellation behavior against a real child process that has
            // produced exactly one partial, controlled write and is then
            // genuinely still alive and readable from (not merely queued
            // in an OS pipe buffer never actually flushed).
            let hex = rest.first().ok_or("missing stdout hex payload")?;
            let bytes = hex_decode(hex)?;
            let sleep_ms: u64 = parse_arg(rest, 1, "sleep_ms")?;
            let mut stdout = std::io::stdout();
            stdout
                .write_all(&bytes)
                .map_err(|error| format!("stdout write failed: {error}"))?;
            stdout
                .flush()
                .map_err(|error| format!("stdout flush failed: {error}"))?;
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            Ok(())
        }
        "write-stderr-hex" => {
            let hex = rest.first().ok_or("missing stderr hex payload")?;
            let bytes = hex_decode(hex)?;
            std::io::stderr()
                .write_all(&bytes)
                .map_err(|error| format!("stderr write failed: {error}"))?;
            Ok(())
        }
        "bounded-stdout" => {
            let byte_count: usize = parse_arg(rest, 0, "byte_count")?;
            write_bounded(&mut std::io::stdout(), byte_count)
                .map_err(|error| format!("bounded stdout write failed: {error}"))?;
            Ok(())
        }
        "bounded-stderr" => {
            let byte_count: usize = parse_arg(rest, 0, "byte_count")?;
            write_bounded(&mut std::io::stderr(), byte_count)
                .map_err(|error| format!("bounded stderr write failed: {error}"))?;
            Ok(())
        }
        "dual-stream" => {
            let stdout_bytes: usize = parse_arg(rest, 0, "stdout_bytes")?;
            let stderr_bytes: usize = parse_arg(rest, 1, "stderr_bytes")?;
            let stdout_thread =
                std::thread::spawn(move || write_bounded(&mut std::io::stdout(), stdout_bytes));
            let stderr_thread =
                std::thread::spawn(move || write_bounded(&mut std::io::stderr(), stderr_bytes));
            stdout_thread
                .join()
                .map_err(|_| "stdout writer thread panicked".to_string())?
                .map_err(|error| format!("stdout writer failed: {error}"))?;
            stderr_thread
                .join()
                .map_err(|_| "stderr writer thread panicked".to_string())?
                .map_err(|error| format!("stderr writer failed: {error}"))?;
            Ok(())
        }
        "write-pid-file" => {
            let path: String = parse_arg(rest, 0, "pid_file_path")?;
            let sleep_ms: u64 = parse_arg(rest, 1, "sleep_ms")?;
            std::fs::write(&path, std::process::id().to_string())
                .map_err(|error| format!("failed writing pid file {path:?}: {error}"))?;
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            Ok(())
        }
        "spawn-child" | "spawn-immediate-child" => {
            let sleep_ms: String = parse_arg(rest, 0, "sleep_ms")?;
            let pid_file: String = parse_arg(rest, 1, "pid_file_path")?;
            let mut child = spawn_self(&["write-pid-file".to_string(), pid_file, sleep_ms])?;
            let payload = serde_json::json!({ "mode": mode, "child_pid": child.id() });
            println!("{payload}");
            std::io::stdout()
                .flush()
                .map_err(|error| format!("stdout flush failed: {error}"))?;
            let status = child
                .wait()
                .map_err(|error| format!("failed waiting for child: {error}"))?;
            std::process::exit(status.code().unwrap_or(96));
        }
        "spawn-grandchild" => {
            let sleep_ms: String = parse_arg(rest, 0, "sleep_ms")?;
            let pid_file: String = parse_arg(rest, 1, "pid_file_path")?;
            let mut child = spawn_self(&["spawn-child".to_string(), sleep_ms, pid_file])?;
            let payload =
                serde_json::json!({ "mode": "spawn-grandchild", "child_pid": child.id() });
            println!("{payload}");
            std::io::stdout()
                .flush()
                .map_err(|error| format!("stdout flush failed: {error}"))?;
            let status = child
                .wait()
                .map_err(|error| format!("failed waiting for child: {error}"))?;
            std::process::exit(status.code().unwrap_or(96));
        }
        other => Err(format!(
            "unknown fixture mode {other:?} (argv[0] of the arguments the fixture itself \
             received must be one of: print-argv, print-env, print-cwd, print-cwd-identity, \
             print-fd-count, print-fd-targets, print-pid, exit-code, sleep-ms, \
             write-stdout-hex, write-stderr-hex, bounded-stdout, bounded-stderr, dual-stream, \
             write-pid-file, spawn-child, spawn-immediate-child, spawn-grandchild, \
             echo-stdin, write-stdout-hex-then-sleep-ms)"
        )),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => fail(&message),
    }
}
