// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! `file://` URI <-> filesystem path conversion, and workspace-membership
//! validation for every path/URI this crate receives from or sends to a
//! language server.
//!
//! `ls-types::Uri` has no built-in file-path conversion helper (unlike some
//! URI crates), so this module owns exactly that narrow translation --
//! never a general-purpose URI library, never a second canonicalization
//! implementation (Architecture Rule F remains `wht_corulix_workspace`'s
//! alone; this module only builds/parses `file://` strings, it never
//! canonicalizes a path itself).

use std::path::{Path, PathBuf};

/// Percent-encodes the small set of bytes that are not safe to place
/// literally in a `file://` URI path segment (space, `%`, and any
/// non-ASCII byte), leaving ordinary path characters (letters, digits,
/// `/`, `.`, `-`, `_`, `~`) untouched. This is deliberately narrow --
/// exactly the bytes real filesystem paths in this workspace's fixtures
/// and CI environments are expected to contain -- rather than a
/// general-purpose percent-encoding implementation.
fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'-' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            other => {
                out.push('%');
                out.push_str(&format!("{other:02X}"));
            }
        }
    }
    out
}

fn percent_decode_path(encoded: &str) -> Option<String> {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = encoded.get(index + 1..index + 3)?;
            let value = u8::from_str_radix(hex, 16).ok()?;
            out.push(value);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Strips Windows's `\\?\` extended-length-path prefix (`std::fs::canonicalize`'s
/// own real, documented output shape on Windows -- confirmed during
/// P17-W-R4-C3's native Windows LSP certification, where an unstripped
/// prefix produced a genuinely broken `file://` URI rust-analyzer itself
/// rejected with `"url is not a file"`) and normalizes every `\` to `/`. A
/// no-op on any path that already uses forward slashes (every Unix path,
/// and any Windows path a caller already normalized) -- this function
/// performs no other transformation.
fn normalize_windows_path_str(path_str: &str) -> String {
    let stripped = path_str.strip_prefix(r"\\?\").unwrap_or(path_str);
    stripped.replace('\\', "/")
}

/// Lowercases a leading Windows drive letter (`C:/...` -> `c:/...`, applied
/// before percent-encoding so the letter itself, not `%3A`, is what gets
/// cased). A no-op for any string that doesn't start with `<ascii-letter>:`
/// -- every Unix path, and any Windows path already lowercase.
///
/// # Why (Phase 17-W-R15 `publishDiagnostics` URI-case defect)
///
/// Every real language server this crate has been proven against on
/// Windows echoes `file://` URIs with a *lowercase* drive letter -- the
/// `vscode-uri` convention `typescript-language-server` (and, by the same
/// upstream lineage, gopls's and rust-analyzer's own LSP tooling) inherits.
/// Confirmed for `typescript-language-server` via a native-Windows
/// instrumented run of `real_typescript_6_managed_full_vertical_e2e`: the
/// server's own `textDocument/publishDiagnostics` named
/// `file:///c%3A/Users/.../main.ts` for the exact document Corulix itself
/// opened, but *this crate's own* unfixed `path_to_file_uri` had built
/// `file:///C%3A/Users/.../main.ts` for that `didOpen`/lookup key --
/// `Path::to_str()` faithfully preserves whatever case the OS handed back
/// (uppercase for this fixture, rooted under `%TEMP%`). Windows/NTFS treats
/// `C:` and `c:` as the same volume, but `wait_for_diagnostics`'s
/// `HashMap<String, _>` is keyed on the literal URI text, so the
/// exact-string lookup silently never matched: diagnostics were genuinely
/// published, just unreachable under the (wrongly-cased) key Corulix
/// looked them up by, which read at a glance like tsserver reporting no
/// diagnostics at all rather than a URI-casing mismatch confined to this
/// module. Lowercasing here, at construction, means every URI this crate
/// builds -- for outbound `didOpen`/`didChange` and for its own inbound
/// lookup keys alike -- already matches the casing convention the servers
/// it talks to use, instead of requiring every call site to separately
/// remember to normalize.
fn lowercase_windows_drive_letter(path_str: &str) -> String {
    let bytes = path_str.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let mut out = String::with_capacity(path_str.len());
        out.push((bytes[0] as char).to_ascii_lowercase());
        out.push_str(&path_str[1..]);
        out
    } else {
        path_str.to_string()
    }
}

/// Path-level counterpart of [`normalize_windows_path_str`], for callers
/// comparing two already-absolute paths (e.g. `Path::strip_prefix`) where
/// one side went through `std::fs::canonicalize` (carrying Windows's
/// `\\?\` prefix) and the other did not (e.g. a path decoded from a
/// server-supplied `file://` URI via [`file_uri_to_path`]) -- a real defect
/// this exact mismatch caused during P17-W-R4-C3's native Windows
/// certification: `wht_corulix_lsp::operations::relative_to_workspace_root`
/// rejected a genuinely-inside-the-workspace `definition` result as
/// `ResultOutsideWorkspace` because the canonicalized workspace root
/// carried the prefix and the decoded location did not. A no-op on Unix and
/// on any Windows path that already lacks the prefix.
pub(crate) fn strip_windows_verbatim_prefix(path: &Path) -> PathBuf {
    match path.to_str() {
        Some(text) => match text.strip_prefix(r"\\?\") {
            Some(rest) => PathBuf::from(rest),
            None => path.to_path_buf(),
        },
        None => path.to_path_buf(),
    }
}

/// Builds a `file://` [`ls_types::Uri`] for an already-confined absolute
/// path. The caller (this crate's operation functions) is responsible for
/// having validated the path against `wht_corulix_workspace` first -- this
/// function performs no confinement check of its own, only string
/// construction (plus, as of P17-W-R4-C3, Windows path-separator/extended-
/// prefix normalization -- see `normalize_windows_path_str`).
pub fn path_to_file_uri(path: &Path) -> Option<ls_types::Uri> {
    let path_str = path.to_str()?;
    let normalized = normalize_windows_path_str(path_str);
    let normalized = lowercase_windows_drive_letter(&normalized);
    let encoded = percent_encode_path(&normalized);
    let text = if encoded.starts_with('/') {
        format!("file://{encoded}")
    } else {
        // A Windows drive-letter path (`C:/root/...`) never starts with
        // `/` even after normalization -- the leading slash a `file://`
        // URI requires before the drive letter is added explicitly here,
        // rather than folded into `percent_encode_path`'s own untouched-
        // byte set, so a genuinely relative input still round-trips
        // exactly as it always did on Unix.
        format!("file:///{encoded}")
    };
    text.parse().ok()
}

/// Parses a `file://` URI back into an absolute filesystem path. Returns
/// `None` for any non-`file` scheme -- this crate never follows a
/// server-supplied URI of any other scheme.
pub fn file_uri_to_path(uri: &ls_types::Uri) -> Option<PathBuf> {
    let text = uri.as_str();
    let rest = text.strip_prefix("file://")?;
    let decoded = percent_decode_path(rest)?;
    // A decoded Windows drive-letter path arrives as `/C:/root/...` (the
    // explicit leading slash `path_to_file_uri` added above) -- strip it so
    // the round trip yields the same drive-letter-rooted `PathBuf` a caller
    // passed in, not a path `std::path::Path` would treat as rooted at a
    // literal `\` on the current drive.
    #[cfg(target_os = "windows")]
    let decoded = decoded
        .strip_prefix('/')
        .filter(|rest| rest.get(1..2) == Some(":"))
        .map(str::to_string)
        .unwrap_or(decoded);
    Some(PathBuf::from(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_plain_absolute_path() -> Result<(), &'static str> {
        let path = Path::new("/tmp/corulix-lsp-test/src/main.rs");
        let uri = path_to_file_uri(path).ok_or("uri builds")?;
        let round_tripped = file_uri_to_path(&uri).ok_or("uri parses back")?;
        assert_eq!(round_tripped, path);
        Ok(())
    }

    #[test]
    fn round_trips_a_path_with_a_space() -> Result<(), &'static str> {
        let path = Path::new("/tmp/corulix lsp test/src/main.rs");
        let uri = path_to_file_uri(path).ok_or("uri builds")?;
        assert!(uri.as_str().contains("%20"));
        let round_tripped = file_uri_to_path(&uri).ok_or("uri parses back")?;
        assert_eq!(round_tripped, path);
        Ok(())
    }

    /// Direct proof of the Phase 17-W-R15 `lowercase_windows_drive_letter`
    /// fix, runnable on any host (this is pure string manipulation with no
    /// OS-dependent path parsing, so it does not need a real Windows
    /// filesystem to exercise): a Windows drive-letter path must produce a
    /// lowercase-drive, percent-encoded-colon `file://` URI, matching the
    /// exact `file:///c%3A/...` shape a native-Windows instrumented run of
    /// `real_typescript_6_managed_e2e.rs` proved is what every real
    /// language server this crate talks to on Windows expects/echoes.
    /// Without this fix, this assertion would fail with an uppercase `C`
    /// (whatever case `Path::to_str()` preserves), reproducing the exact
    /// `publishDiagnostics`-lookup mismatch that defect caused.
    #[test]
    fn windows_drive_letter_paths_are_lowercased_before_encoding() -> Result<(), &'static str> {
        let path = Path::new(r"C:\Users\x\main.ts");
        let uri = path_to_file_uri(path).ok_or("uri builds")?;
        assert_eq!(uri.as_str(), "file:///c%3A/Users/x/main.ts");
        Ok(())
    }

    #[test]
    fn non_file_scheme_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let uri: ls_types::Uri = "https://example.com/a".parse()?;
        assert_eq!(file_uri_to_path(&uri), None);
        Ok(())
    }
}
