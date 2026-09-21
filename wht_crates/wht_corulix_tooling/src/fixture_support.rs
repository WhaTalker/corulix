// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Test-only helper (P17-W-R3-C2, `WINDOWS_PROCESS_FIXTURE_PORTABILITY`):
//! resolves the sibling `wht_corulix_process_fixture` binary path, building
//! it on demand via `escargot`, so a `#[cfg(test)]` unit test module in
//! this crate's own `src/` (which `CARGO_BIN_EXE_<name>` never reaches --
//! that env var is only set by Cargo for the bin-owning package's own
//! `tests/*.rs` integration targets) can exercise a real, cross-platform,
//! deterministic child process instead of a hardcoded Unix-only executable
//! such as `/usr/bin/echo` or `/bin/sh`.
//!
//! `escargot`'s `manifest_path(...)` reaches the fixture crate's
//! `Cargo.toml` directly, via this crate's own `CARGO_MANIFEST_DIR` plus
//! the fixed, versioned-with-source-tree sibling path
//! `../wht_corulix_process_fixture` -- this is not a guess about where
//! Cargo places build output (the forbidden `target/debug` /
//! `current_exe()`-popped heuristic); it only locates a sibling crate's own
//! manifest file, and `escargot` itself invokes `cargo build` and parses
//! its `--message-format=json` output to learn the exact artifact path
//! Cargo actually produced, correctly honoring `CARGO_TARGET_DIR`, the
//! debug/release profile, and the Windows `.exe` suffix.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static FIXTURE_BINARY: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// Resolves (building on demand, once per test process) the path to the
/// `wht_corulix_process_fixture` binary.
///
/// Returns `Err` rather than panicking/unwrapping/expecting on failure --
/// this workspace's lint policy denies `clippy::unwrap_used`,
/// `clippy::expect_used`, and `clippy::panic`, so every test that calls
/// this returns `Result<(), String>` and propagates a resolution failure
/// with `?`, which Cargo reports as a normal test failure.
pub(crate) fn fixture_binary_path() -> Result<PathBuf, String> {
    FIXTURE_BINARY
        .get_or_init(|| {
            let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("wht_corulix_process_fixture")
                .join("Cargo.toml");
            let mut builder = escargot::CargoBuild::new()
                .manifest_path(&manifest_path)
                .bin("wht_corulix_process_fixture");
            // Match the outer test binary's own profile so the fixture is
            // never built in a mismatched profile relative to the test
            // run that depends on it (evaluated explicitly for both debug
            // and release in the P17-W-R3-C2 fixture path resolution
            // prototype).
            if !cfg!(debug_assertions) {
                builder = builder.current_release();
            }
            builder
                .run()
                .map(|run| run.path().to_path_buf())
                .map_err(|error| {
                    format!(
                        "failed to build/resolve wht_corulix_process_fixture \
                         (manifest_path={manifest_path:?}): {error}"
                    )
                })
        })
        .clone()
}
