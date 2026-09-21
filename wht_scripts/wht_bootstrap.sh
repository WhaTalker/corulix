#!/usr/bin/env bash
# =============================================================================
# WhaTalker Corulix -- Isolated Rust Toolchain Bootstrap
#
# Copyright (c) 2026 WhaTalker Inc.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Installs a fully private Rust toolchain (rustup + cargo + the pinned
# 1.97.1 release) under this repository's own .corulix-rust/ directory, so
# building Corulix never touches or depends on any pre-existing global
# ~/.cargo / ~/.rustup installation on the machine.
#
# Usage:
#   source wht_scripts/wht_corulix_env.sh   # sets RUSTUP_HOME/CARGO_HOME first
#   ./wht_scripts/wht_bootstrap.sh
# =============================================================================
set -euo pipefail

# Step 1: Resolve this repository's root regardless of the caller's cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORULIX_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXPECTED_RUST_ENV="$CORULIX_ROOT/.corulix-rust"

# Step 2: Refuse to run unless the isolated environment variables from
# wht_corulix_env.sh are already active in this shell -- this is what
# guarantees every later step stays inside .corulix-rust/, never the
# machine's global Rust installation.
if [ "${RUSTUP_HOME:-}" != "$EXPECTED_RUST_ENV/rustup" ] || [ "${CARGO_HOME:-}" != "$EXPECTED_RUST_ENV/cargo" ]; then
  echo "BLOCKED: isolated environment not sourced." >&2
  echo "Run: source wht_scripts/wht_corulix_env.sh   (from $CORULIX_ROOT)" >&2
  exit 2
fi

# Step 3: Install a private rustup only if one does not already exist under
# CARGO_HOME. Uses the official rustup installer over TLS 1.2+, and never
# modifies ~/.bashrc, ~/.profile, /etc/profile, or any global shell rc file
# (--no-modify-path).
if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
  echo "RUST_ENV_BOOTSTRAPPING: no private rustup found, installing..."
  TMP_INIT="$(mktemp)"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$TMP_INIT"
  sh "$TMP_INIT" --no-modify-path --default-toolchain none -y
  rm -f "$TMP_INIT"
else
  echo "RUST_ENV_BOOTSTRAPPING: private rustup already present, skipping install."
fi

# Step 4: Install the exact pinned toolchain version with the minimal
# component set this project's quality gates require (rustfmt, clippy).
rustup toolchain install 1.97.1 --profile minimal --component rustfmt --component clippy

# Step 5: Print the resolved toolchain identity and generate a fresh
# Cargo.lock so the workspace is immediately ready for `wht_verify.sh`.
rustc --version
cargo --version
cargo generate-lockfile

echo "RUST_ENV_READY"
echo "BOOTSTRAP: PASS"
echo "Cargo.lock generated. Run ./wht_scripts/wht_verify.sh next."
