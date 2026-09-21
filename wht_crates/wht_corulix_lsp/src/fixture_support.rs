// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Test-only helper (P17-W-R3-R2, `LSP_TRANSPORT_WINDOWS_PORTABILITY`):
//! resolves the shared sibling `wht_corulix_process_fixture` binary path,
//! building it on demand via `escargot`, exactly mirroring
//! `wht_corulix_tooling::fixture_support` (that module is `pub(crate)`
//! there, so it cannot be reused directly from this crate -- this is the
//! same, independently-duplicated resolution logic against the same one
//! fixture crate, not a second fixture).
//!
//! Lets `transport.rs`'s `#[cfg(test)] mod tests` exercise real
//! framing/timeout/cancellation behavior against a real, deterministic,
//! cross-platform child process instead of `/bin/sh -c <script>`, which
//! does not exist on native Windows.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static FIXTURE_BINARY: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// Resolves (building on demand, once per test process) the path to the
/// `wht_corulix_process_fixture` binary.
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
