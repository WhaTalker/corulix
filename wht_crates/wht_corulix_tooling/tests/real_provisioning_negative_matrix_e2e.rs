// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-B1-R3-B2-B §17: real multi-artifact negative matrix.
//!
//! A real, local, one-shot HTTP/1.1 server (raw `TcpListener`, no
//! framework, same style as this crate's own
//! `real_provision_vs_full_uninstall_race_e2e.rs`) serves each synthetic
//! tarball this file builds, so every mode below exercises the real
//! `provision`/`provision_blocking` pipeline -- real download, real
//! SHA-256 verification, real gzip/tar extraction, real required-layout
//! verification -- against tiny in-memory fixtures rather than the real
//! multi-hundred-MB production artifacts. No repeated public-network
//! dependency (Section 3 of the mandate).
//!
//! Originally written inside `provisioning.rs`'s own `#[cfg(test)] mod
//! tests` (same crate, private-item access); moved here after
//! `wht_scripts/wht_verify_architecture.py`'s Rule L check (only
//! `wht_corulix_lsp` may implement `"Content-Length:"` framing) flagged a
//! genuine false positive: it text-scans every `src/**/*.rs` file (never
//! `tests/**/*.rs`) for the literal LSP Content-Length framing token, and
//! this file's raw HTTP/1.1 mirror server happens to emit that exact
//! substring in an ordinary HTTP response header, not LSP JSON-RPC
//! framing. Moving the fixture here (using only this crate's already-`pub`
//! `provision`/`resolve_managed_component`/`ManagedComponentManifest`
//! surface, exactly as `real_provision_vs_full_uninstall_race_e2e.rs`
//! already does) resolves the false positive without weakening the real
//! Rule L check.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_tooling::provisioning::{
    self, ArchiveKind, ManagedArtifactSource, ManagedComponentId, ManagedComponentManifest,
    ManagedComponentState, ProvisioningError, SymlinkPolicy,
};

fn temp_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-negative-matrix-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Builds a raw in-memory gzip-compressed tarball via `tar::Builder`.
fn build_tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, *content)
            .unwrap_or_else(|error| unreachable!("in-memory tar append never fails: {error}"));
    }
    let tar_bytes = builder
        .into_inner()
        .unwrap_or_else(|error| unreachable!("in-memory tar finish never fails: {error}"));
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(&tar_bytes)
        .unwrap_or_else(|error| unreachable!("in-memory gzip write never fails: {error}"));
    encoder
        .finish()
        .unwrap_or_else(|error| unreachable!("in-memory gzip finish never fails: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    wht_corulix_core::ContentHash::compute_sha256(bytes).digest_hex
}

/// Serves `body` to exactly one connection, then closes. Mirrors
/// `real_provision_vs_full_uninstall_race_e2e.rs`'s
/// `spawn_gated_http_server` without the gating (nothing in this file
/// needs synchronization beyond "the response is available").
fn spawn_one_shot_mirror(body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| unreachable!("bind must succeed: {error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| unreachable!("local_addr must succeed: {error}"));
    let url = format!("http://{addr}/fixture.tar.gz");
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buffer = [0u8; 4096];
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let Ok(read) = stream.read(&mut buffer) else {
                return;
            };
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
    });
    url
}

/// A one-shot server that always answers `404 Not Found` -- simulates a
/// missing/removed upstream source (mode: "missing source").
fn spawn_one_shot_404() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| unreachable!("bind must succeed: {error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| unreachable!("local_addr must succeed: {error}"));
    let url = format!("http://{addr}/missing.tar.gz");
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buffer = [0u8; 4096];
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let Ok(read) = stream.read(&mut buffer) else {
                return;
            };
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.flush();
    });
    url
}

/// Mode: missing source -- the primary artifact's URL 404s. Must fail
/// closed (`DownloadFailed`) and leave no partial install.
#[tokio::test]
async fn provision_rejects_a_missing_source_and_leaves_no_partial_install() {
    let root = temp_root("negative-missing-source");
    let url = spawn_one_shot_404();
    let manifest = ManagedComponentManifest {
        id: ManagedComponentId("negative-missing-source"),
        version: "1.0.0",
        platform: provisioning::host_platform_identifier(),
        architecture: provisioning::host_architecture_identifier(),
        source: ManagedArtifactSource {
            tarball_url: Box::leak(url.into_boxed_str()),
            expected_sha256_hex: "0",
            binary_path_in_tarball: "bin/tool",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[],
    };
    let result = provisioning::provision(&root, &manifest).await;
    assert_eq!(result, Err(ProvisioningError::DownloadFailed));
    let (state, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state, ManagedComponentState::NotProvisioned);
    let _ = std::fs::remove_dir_all(&root);
}

/// Phase 7B-B1-R3-B2-B1 §15-17: a manifest whose declared `platform`/
/// `architecture` do not match this real running host must be refused
/// (`PlatformArchitectureMismatch`) before any network I/O -- proven here by
/// pointing the mirror at a `404` responder: if the platform/architecture
/// check ran late (or not at all), this test would instead observe
/// `DownloadFailed`, so a wrong error here is itself a real regression
/// signal, not merely "no crash". `WRONG_PLATFORM_MANAGED_COMPONENT_ACTIVATION_COUNT=0`.
#[tokio::test]
async fn provision_rejects_a_foreign_platform_and_architecture_manifest_before_any_download() {
    let root = temp_root("negative-foreign-platform-architecture");
    let url = spawn_one_shot_404();
    assert_ne!(
        "corulix-foreign-platform-marker",
        provisioning::host_platform_identifier(),
        "fixture platform string must actually be foreign to the real host"
    );
    let manifest = ManagedComponentManifest {
        id: ManagedComponentId("negative-foreign-platform-architecture"),
        version: "1.0.0",
        platform: "corulix-foreign-platform-marker",
        architecture: "corulix-foreign-architecture-marker",
        source: ManagedArtifactSource {
            tarball_url: Box::leak(url.into_boxed_str()),
            expected_sha256_hex: "0",
            binary_path_in_tarball: "bin/tool",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[],
    };
    let result = provisioning::provision(&root, &manifest).await;
    assert_eq!(result, Err(ProvisioningError::PlatformArchitectureMismatch));
    let (state, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state, ManagedComponentState::NotProvisioned);
    let _ = std::fs::remove_dir_all(&root);
}

/// Same manifest shape, but only `architecture` is foreign (a real-world
/// case the combined check above cannot distinguish from a fully-foreign
/// manifest on its own) -- proves the comparison is a real AND of both
/// fields, not e.g. an accidental OR that only checks platform.
/// `WRONG_ARCH_MANAGED_COMPONENT_ACTIVATION_COUNT=0`.
#[tokio::test]
async fn provision_rejects_a_foreign_architecture_manifest_with_a_matching_platform() {
    let root = temp_root("negative-foreign-architecture-only");
    let url = spawn_one_shot_404();
    let manifest = ManagedComponentManifest {
        id: ManagedComponentId("negative-foreign-architecture-only"),
        version: "1.0.0",
        platform: provisioning::host_platform_identifier(),
        architecture: "corulix-foreign-architecture-marker",
        source: ManagedArtifactSource {
            tarball_url: Box::leak(url.into_boxed_str()),
            expected_sha256_hex: "0",
            binary_path_in_tarball: "bin/tool",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[],
    };
    let result = provisioning::provision(&root, &manifest).await;
    assert_eq!(result, Err(ProvisioningError::PlatformArchitectureMismatch));
    let (state, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state, ManagedComponentState::NotProvisioned);
    let _ = std::fs::remove_dir_all(&root);
}

/// Mode: missing required-layout entry -- the primary binary is present,
/// but a declared `required_paths` entry is absent from the archive. Must
/// fail closed (`ContentVerificationFailed`) and leave no partial install,
/// even though the primary binary itself extracted successfully.
#[tokio::test]
async fn provision_rejects_a_missing_required_path() {
    let root = temp_root("negative-missing-required-path");
    let tarball = build_tarball(&[("bin/tool", b"real binary")]);
    let expected = sha256_hex(&tarball);
    let url = spawn_one_shot_mirror(tarball);
    let manifest = ManagedComponentManifest {
        id: ManagedComponentId("negative-missing-required-path"),
        version: "1.0.0",
        platform: provisioning::host_platform_identifier(),
        architecture: provisioning::host_architecture_identifier(),
        source: ManagedArtifactSource {
            tarball_url: Box::leak(url.into_boxed_str()),
            expected_sha256_hex: Box::leak(expected.into_boxed_str()),
            binary_path_in_tarball: "bin/tool",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            // Declared but never present in the archive above.
            required_paths: &["lib/companion.so"],
            required_nonempty_dirs: &[],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[],
    };
    let result = provisioning::provision(&root, &manifest).await;
    assert_eq!(result, Err(ProvisioningError::ContentVerificationFailed));
    let (state, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state, ManagedComponentState::NotProvisioned);
    let _ = std::fs::remove_dir_all(&root);
}

/// Mode: empty required semantic directory -- no entry at all lands under
/// the declared directory (simulates a merged multi-artifact runtime whose
/// `rust-src`-equivalent artifact failed to merge as expected). Must fail
/// closed (`ContentVerificationFailed`).
#[tokio::test]
async fn provision_rejects_an_empty_required_nonempty_dir() {
    let root = temp_root("negative-empty-required-dir");
    let tarball = build_tarball(&[("bin/tool", b"real binary")]);
    let expected = sha256_hex(&tarball);
    let url = spawn_one_shot_mirror(tarball);
    let manifest = ManagedComponentManifest {
        id: ManagedComponentId("negative-empty-required-dir"),
        version: "1.0.0",
        platform: provisioning::host_platform_identifier(),
        architecture: provisioning::host_architecture_identifier(),
        source: ManagedArtifactSource {
            tarball_url: Box::leak(url.into_boxed_str()),
            expected_sha256_hex: Box::leak(expected.into_boxed_str()),
            binary_path_in_tarball: "bin/tool",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &["lib/rustlib"],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[],
    };
    let result = provisioning::provision(&root, &manifest).await;
    assert_eq!(result, Err(ProvisioningError::ContentVerificationFailed));
    let (state, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state, ManagedComponentState::NotProvisioned);
    let _ = std::fs::remove_dir_all(&root);
}

/// Mode: wrong `tar_root_prefix` -- the archive is well-formed and
/// hash-verified, but every entry lives under a prefix that does not match
/// what the manifest declares. Every entry is silently skipped (never
/// merged), so the primary binary never lands in staging and the
/// post-extraction layout check fails closed (`ContentVerificationFailed`)
/// rather than activating an empty/incomplete install.
#[tokio::test]
async fn provision_rejects_a_wrong_tar_root_prefix() {
    let root = temp_root("negative-wrong-prefix");
    let tarball = build_tarball(&[("actual-wrapper-dir/bin/tool", b"real binary")]);
    let expected = sha256_hex(&tarball);
    let url = spawn_one_shot_mirror(tarball);
    let manifest = ManagedComponentManifest {
        id: ManagedComponentId("negative-wrong-prefix"),
        version: "1.0.0",
        platform: provisioning::host_platform_identifier(),
        architecture: provisioning::host_architecture_identifier(),
        source: ManagedArtifactSource {
            tarball_url: Box::leak(url.into_boxed_str()),
            expected_sha256_hex: Box::leak(expected.into_boxed_str()),
            binary_path_in_tarball: "bin/tool",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            // Declared prefix does not match the archive's real
            // "actual-wrapper-dir/" wrapper above.
            tar_root_prefix: Some("declared-wrapper-dir/"),
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[],
    };
    let result = provisioning::provision(&root, &manifest).await;
    assert_eq!(result, Err(ProvisioningError::ContentVerificationFailed));
    let (state, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state, ManagedComponentState::NotProvisioned);
    let _ = std::fs::remove_dir_all(&root);
}

/// Mode: one `additional_sources` entry fails integrity (the merged-runtime
/// shape every other mode above exercises only for the primary `source`).
/// The primary artifact extracts successfully into staging first, but the
/// whole component must still never activate, and the staging directory is
/// cleaned up rather than left as a silently-adoptable partial merge.
#[tokio::test]
async fn provision_rejects_when_an_additional_source_fails_integrity() {
    let root = temp_root("negative-additional-source-integrity");
    let primary_tarball = build_tarball(&[("bin/tool", b"real primary binary")]);
    let primary_expected = sha256_hex(&primary_tarball);
    let primary_url = spawn_one_shot_mirror(primary_tarball);

    let additional_tarball = build_tarball(&[("bin/companion", b"real companion binary")]);
    let additional_url = spawn_one_shot_mirror(additional_tarball);

    let manifest = ManagedComponentManifest {
        id: ManagedComponentId("negative-additional-source-integrity"),
        version: "1.0.0",
        platform: provisioning::host_platform_identifier(),
        architecture: provisioning::host_architecture_identifier(),
        source: ManagedArtifactSource {
            tarball_url: Box::leak(primary_url.into_boxed_str()),
            expected_sha256_hex: Box::leak(primary_expected.into_boxed_str()),
            binary_path_in_tarball: "bin/tool",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: Box::leak(Box::new([ManagedArtifactSource {
            tarball_url: Box::leak(additional_url.into_boxed_str()),
            // Deliberately wrong -- the additional artifact's real bytes
            // will not match this digest.
            expected_sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000",
            binary_path_in_tarball: "bin/companion",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        }])),
    };
    let result = provisioning::provision(&root, &manifest).await;
    assert_eq!(result, Err(ProvisioningError::IntegrityMismatch));
    let (state, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(state, ManagedComponentState::NotProvisioned);
    // No staging residue: a partial merge (primary extracted, additional
    // rejected) must not be left as an adoptable-looking directory.
    let components_dir = root.join("components").join(manifest.id.0);
    assert!(
        !components_dir.join(manifest.version).exists(),
        "PARTIAL_RUST_RUNTIME_AVAILABLE_COUNT!=0: an incomplete merge was left activatable"
    );
    let _ = std::fs::remove_dir_all(&root);
}
