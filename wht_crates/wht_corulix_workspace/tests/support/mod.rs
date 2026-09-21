// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! M09-P6: resolves the sibling `wht_corulix_process_fixture` binary path,
//! building it on demand via `escargot`, for this crate's own `tests/`
//! integration suite -- mirrors the identical pattern already established
//! in `wht_corulix_tooling`/`wht_corulix_formatter`/`wht_corulix_lsp`/
//! `wht_corulix_process_unix`'s own `fixture_support`/`support` helpers.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static FIXTURE_BINARY: OnceLock<Result<PathBuf, String>> = OnceLock::new();

pub fn fixture_binary_path() -> Result<PathBuf, String> {
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
