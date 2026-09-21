#!/usr/bin/env bash
# =============================================================================
# WhaTalker Corulix -- Full Local Quality Gate
#
# Copyright (c) 2026 WhaTalker Inc.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs every local validation gate a Corulix change must pass: the
# architecture-boundary check, the repository-shape/SPDX/governance check,
# formatting, lints, the full test suite, and a release-profile build.
# Run this before opening a pull request or preparing a release candidate.
#
# Usage: ./wht_scripts/wht_verify.sh   (from the repository root)
# =============================================================================
set -euo pipefail

# Step 1: Structural checks that do not require Cargo at all -- the
# Core/MCP dependency-direction boundary and the repository-shape/SPDX/
# governance-file inventory.
python3 wht_scripts/wht_verify_architecture.py
python3 wht_scripts/wht_verify_repository.py

# Step 2: Require a committed Cargo.lock before any Cargo command below
# runs with --locked, so this gate never silently re-resolves dependencies.
test -f Cargo.lock || {
  echo "FAIL: Cargo.lock is required before release validation." >&2
  exit 3
}

# Step 3: Formatting and lint gates -- fail closed on any warning.
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Step 4: Full test suite across every workspace member and feature.
cargo test --workspace --all-features --locked

# Step 5: Prove the release profile actually builds before calling this
# candidate verified.
cargo build --workspace --release --locked

echo "CORULIX_VERIFY: PASS"
