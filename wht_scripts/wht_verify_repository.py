#!/usr/bin/env python3
"""
WhaTalker Corulix -- Repository Shape, SPDX and Governance Validator

Copyright (c) 2026 WhaTalker Inc.
SPDX-License-Identifier: AGPL-3.0-only

Fail-closed check, independent of Cargo, that this repository:

  1. contains every required governance/provenance/documentation file
     (LICENSE, README, CONTRIBUTING, wht_docs/*, etc.);
  2. declares the expected AGPL-3.0-only license at the workspace level;
  3. carries a correct SPDX license and copyright header in every Rust
     source file under wht_crates/*/src/.
  4. every file PACKAGE_MANIFEST.txt declares (except SHA256SUMS.txt
     itself, which cannot hash itself) has a well-formed, non-duplicate,
     path-safe SHA256SUMS.txt entry whose digest matches the file's
     actual current bytes -- this is the only place in the canonical
     verification architecture that checksum drift (e.g. a public file
     edited without refreshing SHA256SUMS.txt) is detected.

Usage: python3 wht_scripts/wht_verify_repository.py   (from the repository root)
Exit status: 0 on PASS, 1 on FAIL (with each missing/invalid item printed).
"""

from pathlib import Path
import hashlib
import re
import sys
import tomllib

# Step 1: Resolve the repository root relative to this script's own
# location, so this check works regardless of the caller's cwd.
ROOT = Path(__file__).resolve().parents[1]

# SHA256SUMS.txt uses the GNU `sha256sum` text-mode format: a 64-hex-digit
# digest, exactly two spaces, then a `./`-relative path (verifiable
# directly with `sha256sum -c SHA256SUMS.txt`).
_CHECKSUM_LINE_PATTERN = re.compile(r"^([0-9a-f]{64})  (\S.*)$")


def _load_manifest_paths(root: Path) -> list[str]:
    """The canonical public path inventory: every non-comment,
    non-blank line of PACKAGE_MANIFEST.txt, in file order."""
    text = (root / "PACKAGE_MANIFEST.txt").read_text(encoding="utf-8")
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _load_checksum_entries(root: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Parses SHA256SUMS.txt. Returns (entries, malformed-line failures)
    -- a line that doesn't match the exact expected format is reported
    and skipped rather than silently ignored or guessed at."""
    text = (root / "SHA256SUMS.txt").read_text(encoding="utf-8")
    entries: list[tuple[str, str]] = []
    malformed: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = _CHECKSUM_LINE_PATTERN.match(line)
        if not match:
            malformed.append(f"malformed SHA256SUMS.txt line: {line!r}")
            continue
        entries.append((match.group(1), match.group(2)))
    return entries, malformed


def _is_safe_relative_path(path: str) -> bool:
    """Rejects absolute paths and any `..` traversal segment -- every
    checksum entry must resolve strictly inside the repository root."""
    if not path.startswith("./"):
        return False
    rel = path[2:]
    if not rel or rel.startswith("/"):
        return False
    return all(part not in ("", "..") for part in rel.split("/"))


def validate_sha256sums(root: Path) -> list[str]:
    """Fail-closed SHA256SUMS.txt integrity check. Expected coverage is
    derived from PACKAGE_MANIFEST.txt (the canonical path authority)
    minus SHA256SUMS.txt's own established self-exclusion -- there is no
    second, independently-maintained path list to drift out of sync."""
    failures: list[str] = []
    expected_paths = set(_load_manifest_paths(root)) - {"./SHA256SUMS.txt"}
    entries, malformed = _load_checksum_entries(root)
    failures.extend(malformed)

    seen: set[str] = set()
    duplicates: set[str] = set()
    for _, path in entries:
        (duplicates if path in seen else seen).add(path)
    for path in sorted(duplicates):
        failures.append(f"duplicate SHA256SUMS.txt entry: {path}")

    checksum_paths = {path for _, path in entries}
    for path in sorted(checksum_paths):
        if not _is_safe_relative_path(path):
            failures.append(f"unsafe path in SHA256SUMS.txt: {path}")

    for path in sorted(expected_paths - checksum_paths):
        failures.append(f"expected file missing from SHA256SUMS.txt: {path}")
    for path in sorted(checksum_paths - expected_paths):
        failures.append(
            f"unexpected SHA256SUMS.txt entry not in PACKAGE_MANIFEST.txt: {path}"
        )

    for digest, path in entries:
        if path in duplicates or not _is_safe_relative_path(path):
            # Already reported above; do not also report a possibly
            # misleading digest result for an already-invalid entry.
            continue
        target = root / path[2:]
        if not target.is_file():
            failures.append(f"SHA256SUMS.txt references missing file: {path}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != digest:
            failures.append(
                f"SHA256SUMS.txt digest mismatch for {path}: "
                f"recorded={digest} actual={actual}"
            )
    return failures

# Step 2: The exact set of files every Corulix checkout must contain.
REQUIRED = [
    "LICENSE",
    "README.md",
    "wht_docs/wht_architecture.md",
    "SECURITY.md",
    "wht_docs/wht_trademarks.md",
    "wht_docs/wht_provenance.md",
    "wht_docs/wht_clean_room.md",
    "CONTRIBUTING.md",
    "wht_docs/wht_governance.md",
    "wht_docs/wht_cla_policy.md",
    "wht_docs/wht_dco_policy.md",
    "wht_docs/wht_copyright.md",
    "wht_docs/wht_dependencies.md",
    "wht_docs/wht_third_party_notices.md",
    "wht_docs/wht_threat_model.md",
    "wht_docs/wht_iso_alignment.md",
    "wht_docs/wht_mcp_compatibility.md",
    "wht_docs/wht_language_support.md",
    "wht_docs/wht_reproducible_builds.md",
    "wht_docs/wht_releasing.md",
    "wht_docs/wht_supply_chain.md",
    "Cargo.toml",
    "rust-toolchain.toml",
]


def main() -> int:
    # Step 3: Every required file must actually exist.
    failures: list[str] = []
    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            failures.append(f"missing required file: {rel}")

    # Step 4: The workspace-level Cargo.toml must declare the expected license.
    with (ROOT / "Cargo.toml").open("rb") as handle:
        workspace = tomllib.load(handle)

    if workspace.get("workspace", {}).get("package", {}).get("license") != "AGPL-3.0-only":
        failures.append("workspace license is not AGPL-3.0-only")

    # Step 5: Every Rust source file in every crate must carry both the SPDX
    # license tag and the SPDX copyright tag -- no exceptions.
    for crate in (ROOT / "wht_crates").iterdir():
        if not crate.is_dir():
            continue
        for source in (crate / "src").rglob("*.rs"):
            text = source.read_text(encoding="utf-8")
            if "SPDX-License-Identifier: AGPL-3.0-only" not in text:
                failures.append(f"missing SPDX license: {source.relative_to(ROOT)}")
            if "SPDX-FileCopyrightText: 2026 WhaTalker Inc." not in text:
                failures.append(f"missing SPDX copyright: {source.relative_to(ROOT)}")

    # Step 6: SHA256SUMS.txt must be well-formed and byte-accurate for every
    # file PACKAGE_MANIFEST.txt declares -- the only defense against a
    # public file changing without its recorded checksum being refreshed.
    failures.extend(validate_sha256sums(ROOT))

    # Step 7: Report and exit non-zero on any violation; otherwise PASS.
    if failures:
        print("REPOSITORY_VALIDATION: FAIL")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("REPOSITORY_VALIDATION: PASS")
    print("LICENSE: AGPL-3.0-only")
    print("SPDX_HEADERS: PASS")
    print("GOVERNANCE_FILES: PASS")
    print("PROVENANCE_FILES: PASS")
    print("SHA256SUMS: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
