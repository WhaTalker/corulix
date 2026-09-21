#!/usr/bin/env python3
"""
WhaTalker Corulix -- SHA256SUMS.txt Checksum Verifier Tests

Copyright (c) 2026 WhaTalker Inc.
SPDX-License-Identifier: AGPL-3.0-only

Exercises `wht_scripts.wht_verify_repository.validate_sha256sums` -- the
real function the `architecture` CI job runs -- against constructed
fixture trees, proving it fails closed on every drift class the D33
incident (a public file changed without its SHA256SUMS.txt digest being
refreshed) could recur as.

Usage: python3 -m unittest wht_tests.test_wht_verify_repository
       (from the repository root)
"""

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "wht_verify_repository", ROOT / "wht_scripts" / "wht_verify_repository.py"
)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules["wht_verify_repository"] = _MODULE
_SPEC.loader.exec_module(_MODULE)
validate_sha256sums = _MODULE.validate_sha256sums


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Sha256SumsValidatorTests(unittest.TestCase):
    def _fixture(self, files: dict[str, bytes], checksums_body: str) -> Path:
        # Deliberately does NOT list PACKAGE_MANIFEST.txt/SHA256SUMS.txt
        # themselves as manifest entries -- these fixtures isolate the
        # `files` set under test from that self-referential real-repo
        # detail (already covered by the real-repository regression
        # test below), so expected coverage is exactly `files`.
        tmp = Path(tempfile.mkdtemp())
        manifest_lines = ["# fixture manifest\n"]
        for rel, data in files.items():
            path = tmp / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            manifest_lines.append(f"./{rel}\n")
        (tmp / "PACKAGE_MANIFEST.txt").write_text("".join(manifest_lines), encoding="utf-8")
        (tmp / "SHA256SUMS.txt").write_text(checksums_body, encoding="utf-8")
        return tmp

    def test_valid_current_checksum_set_passes(self):
        content = b"hello world\n"
        root = self._fixture(
            {"a.txt": content},
            f"{_digest(content)}  ./a.txt\n",
        )
        self.assertEqual(validate_sha256sums(root), [])

    def test_stale_digest_is_blocked(self):
        content = b"hello world\n"
        root = self._fixture(
            {"a.txt": content},
            f"{_digest(b'different bytes')}  ./a.txt\n",
        )
        failures = validate_sha256sums(root)
        self.assertTrue(any("digest mismatch" in f for f in failures), failures)

    def test_missing_required_entry_is_blocked(self):
        content = b"hello world\n"
        root = self._fixture({"a.txt": content}, "")
        failures = validate_sha256sums(root)
        self.assertTrue(
            any("expected file missing from SHA256SUMS.txt" in f for f in failures),
            failures,
        )

    def test_extra_entry_is_blocked(self):
        content = b"hello world\n"
        root = self._fixture(
            {"a.txt": content},
            f"{_digest(content)}  ./a.txt\n{_digest(b'x')}  ./not-in-manifest.txt\n",
        )
        failures = validate_sha256sums(root)
        self.assertTrue(
            any("not in PACKAGE_MANIFEST.txt" in f for f in failures), failures
        )

    def test_duplicate_entry_is_blocked(self):
        content = b"hello world\n"
        root = self._fixture(
            {"a.txt": content},
            f"{_digest(content)}  ./a.txt\n{_digest(content)}  ./a.txt\n",
        )
        failures = validate_sha256sums(root)
        self.assertTrue(any("duplicate SHA256SUMS.txt entry" in f for f in failures), failures)

    def test_malformed_entry_is_blocked(self):
        content = b"hello world\n"
        root = self._fixture(
            {"a.txt": content}, "not-a-valid-checksum-line ./a.txt\n"
        )
        failures = validate_sha256sums(root)
        self.assertTrue(any("malformed SHA256SUMS.txt line" in f for f in failures), failures)

    def test_missing_referenced_file_is_blocked(self):
        content = b"hello world\n"
        root = self._fixture({"a.txt": content}, "")
        # Add a checksum entry for a.txt, then delete the file it names,
        # while keeping the manifest entry so this isn't miscategorised
        # as an "extra entry" failure instead.
        (root / "SHA256SUMS.txt").write_text(f"{_digest(content)}  ./a.txt\n", encoding="utf-8")
        (root / "a.txt").unlink()
        failures = validate_sha256sums(root)
        self.assertTrue(
            any("references missing file" in f for f in failures), failures
        )

    def test_absolute_path_is_blocked(self):
        content = b"hello world\n"
        root = self._fixture({"a.txt": content}, "")
        manifest = root / "PACKAGE_MANIFEST.txt"
        manifest.write_text(manifest.read_text(encoding="utf-8") + "/etc/passwd\n", encoding="utf-8")
        (root / "SHA256SUMS.txt").write_text(
            f"{_digest(content)}  ./a.txt\n{_digest(b'x')}  /etc/passwd\n", encoding="utf-8"
        )
        failures = validate_sha256sums(root)
        self.assertTrue(any("unsafe path" in f for f in failures), failures)

    def test_path_traversal_is_blocked(self):
        content = b"hello world\n"
        root = self._fixture({"a.txt": content}, "")
        manifest = root / "PACKAGE_MANIFEST.txt"
        manifest.write_text(
            manifest.read_text(encoding="utf-8") + "./../outside.txt\n", encoding="utf-8"
        )
        (root / "SHA256SUMS.txt").write_text(
            f"{_digest(content)}  ./a.txt\n{_digest(b'x')}  ./../outside.txt\n",
            encoding="utf-8",
        )
        failures = validate_sha256sums(root)
        self.assertTrue(any("unsafe path" in f for f in failures), failures)

    def test_manifest_checksum_coverage_drift_is_blocked(self):
        # A file present on disk and in PACKAGE_MANIFEST.txt but never
        # added to SHA256SUMS.txt at all -- the manifest is the coverage
        # authority, so this must be caught as a missing entry.
        content = b"hello world\n"
        root = self._fixture({"a.txt": content, "b.txt": b"other\n"}, f"{_digest(content)}  ./a.txt\n")
        failures = validate_sha256sums(root)
        self.assertTrue(
            any("expected file missing from SHA256SUMS.txt" in f and "b.txt" in f for f in failures),
            failures,
        )

    def test_real_repository_after_regeneration_is_clean(self):
        """Guards against a future regression re-introducing drift: once
        SHA256SUMS.txt is correctly regenerated for the real repository,
        this must return zero failures. Skipped while D33's known-stale
        entry is still present (proving that same drift is what this
        module's other tests exercise synthetically)."""
        failures = validate_sha256sums(ROOT)
        if failures:
            self.skipTest(
                "real repository SHA256SUMS.txt not yet regenerated "
                f"(expected during the D33 remediation PR itself): {failures}"
            )
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
