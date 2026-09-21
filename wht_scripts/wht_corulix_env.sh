#!/usr/bin/env bash
# =============================================================================
# WhaTalker Corulix -- Isolated Rust Environment Loader
#
# Copyright (c) 2026 WhaTalker Inc.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Exports RUSTUP_HOME/CARGO_HOME/CARGO_TARGET_DIR so every Rust command run
# in this shell session stays fully inside this repository's own
# .corulix-rust/ directory, isolated from any pre-existing global
# ~/.cargo / ~/.rustup installation.
#
# Usage: `source wht_scripts/wht_corulix_env.sh` (must be sourced, not executed
# directly). Never add this to a shell rc file (~/.bashrc, ~/.profile,
# /etc/profile) -- it is meant to be opted into per build session only.
# =============================================================================

# Step 1: Refuse to run under `sh script.sh` -- BASH_SOURCE only exists when
# this file is sourced from bash, which is the only supported invocation.
if [ -n "${BASH_SOURCE:-}" ]; then
  CORULIX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
else
  echo "wht_corulix_env.sh must be sourced from bash (BASH_SOURCE unavailable)." >&2
  return 1 2>/dev/null || exit 1
fi

# Step 2: Point the Rust toolchain's home directories at this repository's
# own isolated .corulix-rust/ tree instead of the machine's global ones.
export RUSTUP_HOME="$CORULIX_ROOT/.corulix-rust/rustup"
export CARGO_HOME="$CORULIX_ROOT/.corulix-rust/cargo"
export CARGO_TARGET_DIR="$CORULIX_ROOT/.corulix-rust/target"

# Step 3: Prepend the isolated cargo bin/ to PATH exactly once per shell,
# so `cargo`/`rustc`/`rustup` resolve to this private toolchain first.
case ":$PATH:" in
  *":$CARGO_HOME/bin:"*) ;;
  *) export PATH="$CARGO_HOME/bin:$PATH" ;;
esac

# Step 4: Report the resolved environment and whether the toolchain has
# actually been bootstrapped yet (wht_scripts/wht_bootstrap.sh does that part).
echo "CORULIX_ROOT=$CORULIX_ROOT"
echo "RUSTUP_HOME=$RUSTUP_HOME"
echo "CARGO_HOME=$CARGO_HOME"
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
if [ -x "$CARGO_HOME/bin/rustup" ]; then
  echo "CORULIX_RUST_ENV: RUST_ENV_READY"
else
  echo "CORULIX_RUST_ENV: RUST_ENV_ABSENT (run wht_scripts/wht_bootstrap.sh)"
fi
