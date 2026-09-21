// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Pinned `CORULIX_MANAGED` component manifest for this crate's own
//! provider (Phase 7B-B2-B): managed `rustfmt`. Mirrors the layout/doc
//! convention `wht_corulix_lsp::managed_toolchain` already established for
//! its own single-consumer artifacts.

use wht_corulix_tooling::provisioning::{
    ArchiveKind, ManagedArtifactSource, ManagedComponentId, ManagedComponentManifest, SymlinkPolicy,
};

/// Real official `rustfmt` distribution artifact, resolved from
/// `static.rust-lang.org/dist/2026-08-20/channel-rust-stable.toml`'s
/// `[pkg.rustfmt-preview.target.x86_64-unknown-linux-gnu]` entry -- fetched
/// live during this phase's research gate (`curl`, real `HTTP_STATUS=200`),
/// not assumed. That manifest's `[pkg.rustfmt-preview]` table records
/// `version = "1.9.0"` and `git_commit_hash =
/// "88d9e12ae178fab0fb5cc050a94da85685d449ea"` -- the exact same build as
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64`]'s
/// four artifacts, so `RUSTFMT_RUST_RUNTIME_VERSION_COHERENCE=PASS` by
/// construction (same channel snapshot, same build, not independently
/// paired after the fact). Upstream's package name is still
/// `rustfmt-preview` (a long-standing naming quirk -- the shipped binary
/// itself reports as stable `rustfmt 1.9.0-stable`, confirmed via a real
/// `--version` invocation against the downloaded artifact), but the
/// tarball filename and internal layout use plain `rustfmt`.
///
/// # Dependency on the managed Rust semantic runtime (proven, not assumed)
///
/// A real `ldd` against the downloaded, extracted `rustfmt` binary showed
/// `librustc_driver-28a98848f7a7c026.so => not found` under a fully
/// scrubbed environment (`env -i PATH=/nonexistent HOME=/nonexistent`).
/// `readelf -d` on that same binary shows `RUNPATH: [$ORIGIN/../lib]` -- a
/// relative runpath, resolved against wherever `bin/rustfmt` itself is
/// placed at provisioning time, not a hardcoded absolute path. Extracting
/// the real, already-certified `rustc-1.98.0-x86_64-unknown-linux-gnu.tar.gz`
/// artifact confirms it ships that exact same-named library at
/// `rustc/lib/librustc_driver-28a98848f7a7c026.so` -- the identical build
/// hash, not merely a same-version coincidence. Re-running `rustfmt
/// --version` and a real `--emit stdout` format under the same scrubbed
/// environment, this time with only `LD_LIBRARY_PATH` pointed at that
/// extracted `rustc/lib/` directory, succeeds. `RUSTFMT_DEPENDS_ON_RUST_SEMANTIC_RUNTIME=YES`.
/// Because `rustfmt`'s own `RUNPATH` is relative to its own install
/// location (not to any sibling component's), this dependency cannot be
/// satisfied by simply co-locating the two components' install
/// directories under one merged tree the way
/// `RUST_SEMANTIC_RUNTIME_LINUX_X64`'s own four artifacts are merged --
/// `wht_corulix_formatter`'s managed-first resolution therefore sets
/// `LD_LIBRARY_PATH` explicitly to the resolved rust-semantic-runtime
/// install directory's `lib/` subdirectory whenever it spawns the managed
/// `rustfmt`, exactly the same "environment authority, not directory
/// merge" pattern `wht_corulix_lsp::profile`'s managed Go resolution
/// already uses for `GOROOT`.
pub const RUSTFMT_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("rustfmt"),
    version: "1.98.0",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rustfmt-1.98.0-x86_64-unknown-linux-gnu.tar.gz",
        expected_sha256_hex: "0f425a5e8e9826840f4105d71f2e758f55ff21cb1805670dffd2c93e8e0a9a95",
        binary_path_in_tarball: "bin/rustfmt",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        // `cargo-fmt` is admitted alongside `rustfmt` (both ship in the
        // same tarball) purely as a required-layout completeness check --
        // this crate never invokes it (see `CARGO_FMT_PRODUCT_ROLE` in
        // `crate::managed`'s own doc comment): `wht_corulix_formatter`
        // invokes `rustfmt` directly over stdin/stdout exactly as it
        // already does for the `HOST_ONLY`/system path.
        required_paths: &["bin/cargo-fmt"],
        required_nonempty_dirs: &[],
        tar_root_prefix: Some("rustfmt-1.98.0-x86_64-unknown-linux-gnu/rustfmt-preview/"),
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// Real official `rustfmt` distribution artifact for the P17-W Windows
/// certification target (`x86_64-pc-windows-msvc`), resolved from the exact
/// same `static.rust-lang.org/dist/2026-08-20/channel-rust-stable.toml`
/// channel snapshot as [`RUSTFMT_LINUX_X64`] -- the Windows target's own
/// `[pkg.rustfmt-preview.target.x86_64-pc-windows-msvc]` entry, not a
/// separately-chosen version. Downloaded and independently re-hashed with
/// `sha256sum` during this phase's (P17-W-R4) research gate (not copied from
/// upstream's own published checksum), and its internal layout inspected via
/// a real `tar tzvf`: identical wrapper/`rustfmt-preview/bin/` structure to
/// the Linux artifact, `rustfmt.exe`/`cargo-fmt.exe` (plus non-functional
/// `.pdb` debug-symbol siblings the Linux artifact has no equivalent of, and
/// which this manifest deliberately does not reference), zero symlink/
/// hard-link entries (Windows tar archives from this channel never carry
/// any -- confirmed by inspecting every entry's type flag), so
/// `SymlinkPolicy::Reject` is not a functional restriction here either,
/// exactly like [`RUSTFMT_LINUX_X64`]. `rustfmt-1.98.0-x86_64-pc-windows-msvc/git-commit-hash`
/// extracted and diffed byte-for-byte against the Linux artifact's own:
/// both read `88d9e12ae178fab0fb5cc050a94da85685d449ea` --
/// `RUSTFMT_RUST_RUNTIME_VERSION_COHERENCE=PASS` by construction on Windows
/// too, the same real-build-identity argument [`RUSTFMT_LINUX_X64`]'s own
/// doc comment makes for Linux, not assumed to carry over unverified.
///
/// # Dependency on a managed Rust semantic runtime -- proven, not yet closed
///
/// A real `objdump -p` against the downloaded, extracted `rustfmt.exe`
/// (PE32+, confirmed via `file`) lists `rustc_driver-7a414a5d7a84f668.dll`
/// and `std-f01d16aa207effe6.dll` as required import-table DLLs (alongside
/// ordinary Windows system DLLs: `kernel32.dll`, `shell32.dll`,
/// `combase.dll`, `ntdll.dll`, an `api-ms-win-core-*` forwarder, and a
/// duplicate-cased `KERNEL32.dll` entry). This is the exact same structural
/// dependency [`RUSTFMT_LINUX_X64`]'s own doc comment proved for Linux
/// (there, `librustc_driver-28a98848f7a7c026.so` via `RUNPATH`) -- but the
/// resolution *mechanism* cannot be the same: Linux's fix is an `RUNPATH`-
/// relative `LD_LIBRARY_PATH` override (see `crate::managed`'s own doc
/// comment); Windows has no `LD_LIBRARY_PATH` equivalent -- the loader
/// searches the launching executable's own directory, then configured
/// system directories, then `PATH`. Closing this for real invocation
/// requires (1) a `RUST_SEMANTIC_RUNTIME_WINDOWS_X64` managed-runtime
/// manifest (not yet implemented as of this phase) whose `bin/` directory
/// carries the matching-hash `rustc_driver-*.dll`/`std-*.dll`, and (2) a
/// Windows-specific `PATH`-prepend resolution path in `crate::managed`
/// (not `LD_LIBRARY_PATH`, which Windows does not consult at all) --
/// tracked as an explicit P17-W-R4 continuation item
/// (`RUST_SEMANTIC_RUNTIME_WINDOWS_X64` + Windows DLL-search wiring), not
/// silently assumed solved by this manifest's mere existence. This manifest
/// alone is sufficient for platform-correct admission, integrity
/// verification (including negative/hash-mismatch rejection), install,
/// idempotence, and uninstall lifecycle proofs -- not yet for a real
/// `rustfmt --emit stdout` invocation producing reformatted output on
/// Windows.
pub const RUSTFMT_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("rustfmt"),
    version: "1.98.0",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rustfmt-1.98.0-x86_64-pc-windows-msvc.tar.gz",
        expected_sha256_hex: "d1f21083819659b89cead2530159449321040c0af9809957f5e9c36e9984dea8",
        binary_path_in_tarball: "bin/rustfmt.exe",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        // Mirrors `RUSTFMT_LINUX_X64`'s own `bin/cargo-fmt` completeness
        // check: `cargo-fmt.exe` ships in the same tarball and is admitted
        // as a required-layout proof only -- this crate never invokes it,
        // it spawns `rustfmt.exe` directly, exactly like the Linux path.
        required_paths: &["bin/cargo-fmt.exe"],
        required_nonempty_dirs: &[],
        tar_root_prefix: Some("rustfmt-1.98.0-x86_64-pc-windows-msvc/rustfmt-preview/"),
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// This host's own real, platform-native `rustfmt` product manifest --
/// [`RUSTFMT_LINUX_X64`] on Linux, [`RUSTFMT_WINDOWS_X64`] on Windows.
/// Production resolution (`crate::managed::resolve_formatter`) and any
/// host-native test that must provision/verify *this actual host's* real
/// manifest (as opposed to a test deliberately asserting behavior against a
/// specific, possibly-foreign platform's manifest, e.g.
/// `real_rustfmt_managed_wrong_platform_provision_rejected_e2e`) must
/// resolve through this constant, never a hardcoded `_LINUX_X64`/`_WINDOWS_X64`
/// literal -- that is exactly the bug this constant exists to close: before
/// it existed, every call site hardcoded [`RUSTFMT_LINUX_X64`] regardless of
/// the actual running host, so a real Windows host's own managed-rustfmt
/// resolution was refused at the platform/architecture admission gate
/// before a single byte was downloaded (`ProvisioningError::PlatformArchitectureMismatch`),
/// even though a real, valid, host-native manifest exists.
#[cfg(target_os = "windows")]
pub const RUSTFMT_HOST_NATIVE: ManagedComponentManifest = RUSTFMT_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const RUSTFMT_HOST_NATIVE: ManagedComponentManifest = RUSTFMT_LINUX_X64;

/// `biome@2.5.11`, linux/x64 -- Phase 16's admitted TypeScript/TSX/JavaScript
/// formatter **and** linter authority (ADR 0010: `FORMATTER_PROVIDER`/
/// `LINTER_PROVIDER`; one managed component, two invocations, never two
/// independently-provisioned identities for what is architecturally one
/// binary). `tarball_url` and `expected_sha256_hex` are this exact release's
/// real values: fetched live from GitHub's own Releases API during this
/// phase's research gate (`api.github.com/repos/biomejs/biome/releases/latest`
/// resolved tag `@biomejs/biome@2.5.11`), downloaded, and independently
/// hashed with `sha256sum` against the downloaded bytes -- not copied from
/// a published checksums file. `archive_kind: ArchiveKind::RawBinary`
/// because Biome publishes a bare, uncompressed, statically-named
/// `biome-linux-x64` executable per release (no tar/zip container at all),
/// confirmed via a real `file` probe (`ELF 64-bit LSB pie executable,
/// x86-64, ..., dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2`)
/// against the downloaded artifact.
///
/// Both a real `biome format --stdin-file-path=test.ts < src` and a real
/// `biome lint <path> --reporter=json` were empirically re-verified this
/// phase against this exact downloaded binary (not merely asserted from
/// upstream documentation): the former returned correctly reformatted
/// bytes on stdout with the source file untouched, the latter returned
/// well-formed JSON diagnostics with a correct `severity`/`message`/
/// `category`/`location` shape.
pub const BIOME_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("biome"),
    version: "2.5.11",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://github.com/biomejs/biome/releases/download/%40biomejs/biome%402.5.11/biome-linux-x64",
        expected_sha256_hex: "629a72d30e5b625b70723a651c510c0c2d4adc7c9b7334a690afe848ba4426ce",
        binary_path_in_tarball: "biome",
        archive_kind: ArchiveKind::RawBinary,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &[],
        required_nonempty_dirs: &[],
        tar_root_prefix: None,
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// `biome@2.5.11`, win32/x64 -- P17-W Stage F's Windows counterpart to
/// [`BIOME_LINUX_X64`], resolved from the exact same GitHub Release tag
/// (`@biomejs/biome@2.5.11`) rather than a separately-chosen version. Fetched
/// live during this stage's research gate
/// (`api.github.com/repos/biomejs/biome/releases/tags/%40biomejs%2Fbiome%402.5.11`),
/// which lists this release's real asset name as `biome-win32-x64.exe` (not
/// an assumed `-windows-` naming, unlike the `rustfmt`/`static.rust-lang.org`
/// convention) -- downloaded and independently re-hashed with `sha256sum`
/// against the downloaded bytes, not copied from any published checksums
/// file. `archive_kind: ArchiveKind::RawBinary`, exactly like
/// [`BIOME_LINUX_X64`]: Biome publishes a bare, uncompressed,
/// statically-named executable per platform, no zip/tar container at all --
/// confirmed via a real `file` probe against the downloaded artifact
/// (`PE32+ executable (console) x86-64, for MS Windows`).
///
/// # No Windows sibling-runtime dependency (unlike `rustfmt`)
///
/// A real `objdump -p` against the downloaded `biome-win32-x64.exe` lists
/// only ordinary Windows system/CRT import-table DLLs (`kernel32.dll`,
/// `ntdll.dll`, `advapi32.dll`, `combase.dll`, `shell32.dll`, `bcrypt.dll`,
/// `bcryptprimitives.dll`, `ws2_32.dll`, `VCRUNTIME140.dll`, and the
/// `api-ms-win-core-*`/`api-ms-win-crt-*` forwarders) -- no
/// `rustc_driver-*.dll`/`std-*.dll` equivalent the way `rustfmt.exe` needed.
/// Biome ships as a single statically-linked Rust binary on every platform
/// (the same property [`BIOME_LINUX_X64`]'s own doc comment already
/// establishes for Linux via its `dynamically linked` interpreter line being
/// limited to the libc/loader, never a sibling Corulix-managed component).
/// `BIOME_WINDOWS_RUST_RUNTIME_DEPENDENCY=NONE` -- this manifest alone is
/// therefore sufficient for a real, unblocked `biome format`/`biome lint`
/// invocation on Windows, with no second managed-runtime manifest or
/// process-local `PATH`/DLL-search wiring required, unlike
/// [`RUSTFMT_WINDOWS_X64`]'s still-open runtime-dependency continuation
/// item.
pub const BIOME_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("biome"),
    version: "2.5.11",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://github.com/biomejs/biome/releases/download/%40biomejs/biome%402.5.11/biome-win32-x64.exe",
        expected_sha256_hex: "8bdf679275458a444f7befb8dacc38001625645cc498facf3cc114d77239f1cd",
        binary_path_in_tarball: "biome.exe",
        archive_kind: ArchiveKind::RawBinary,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &[],
        required_nonempty_dirs: &[],
        tar_root_prefix: None,
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// This host's own real, platform-native `biome` product manifest --
/// [`BIOME_LINUX_X64`] on Linux, [`BIOME_WINDOWS_X64`] on Windows. Mirrors
/// [`RUSTFMT_HOST_NATIVE`]'s own `#[cfg]`-gated-alias pattern exactly, for
/// the identical reason: production resolution
/// (`crate::managed::resolve_formatter`, and the TS/JS engine's own
/// `Formatter`/`Linter` availability probe and `run_lint` invocation in
/// `wht_corulix_engine::semantic`/`ts_validation`) and any host-native test
/// that must provision/verify *this actual host's* real manifest must
/// resolve through this constant, never a hardcoded `_LINUX_X64` literal --
/// before this constant existed, every one of those call sites hardcoded
/// [`BIOME_LINUX_X64`] regardless of the actual running host, so a real
/// Windows host's own managed-Biome resolution was refused at the
/// platform/architecture admission gate
/// (`ProvisioningError::PlatformArchitectureMismatch`) before a single byte
/// was downloaded, even though a real, valid, host-native manifest now
/// exists.
#[cfg(target_os = "windows")]
pub const BIOME_HOST_NATIVE: ManagedComponentManifest = BIOME_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const BIOME_HOST_NATIVE: ManagedComponentManifest = BIOME_LINUX_X64;

/// Compile-time-derivable invariants for [`BIOME_WINDOWS_X64`], asserted on
/// every host (this crate is not `#[cfg(windows)]`-gated, so these run in
/// the Linux canonical suite too, giving real, evidence-backed coverage for
/// the Windows manifest's shape without requiring the P17-W VM) -- mirrors
/// [`windows_manifest_tests`]'s own rationale for [`RUSTFMT_WINDOWS_X64`].
#[cfg(test)]
mod biome_windows_manifest_tests {
    use super::*;

    #[test]
    fn biome_windows_x64_platform_architecture_are_windows_x64() {
        assert_eq!(BIOME_WINDOWS_X64.platform, "windows");
        assert_eq!(BIOME_WINDOWS_X64.architecture, "x64");
    }

    #[test]
    fn biome_windows_x64_shares_the_same_component_id_as_linux() {
        // Same logical component across platforms -- `component_install_dir`
        // already segments by platform/architecture, and `crate::lib`'s
        // lease binding keys on `.id.0` alone, so a divergent id here would
        // silently break lease/ownership lookups on Windows.
        assert_eq!(BIOME_WINDOWS_X64.id.0, BIOME_LINUX_X64.id.0);
    }

    #[test]
    fn biome_windows_x64_shares_the_same_pinned_version_as_linux() {
        // Both resolved from the identical `@biomejs/biome@2.5.11` GitHub
        // Release tag -- never independently upgraded per platform.
        assert_eq!(BIOME_WINDOWS_X64.version, BIOME_LINUX_X64.version);
    }

    #[test]
    fn biome_windows_x64_artifact_source_is_pinned_not_floating() {
        let source = BIOME_WINDOWS_X64.source;
        assert!(source.tarball_url.contains("github.com/biomejs/biome"));
        assert!(source.tarball_url.contains("2.5.11"));
        assert!(source.tarball_url.ends_with("biome-win32-x64.exe"));
        assert_eq!(source.expected_sha256_hex.len(), 64);
        assert!(
            source
                .expected_sha256_hex
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
        assert_ne!(
            source.expected_sha256_hex, BIOME_LINUX_X64.source.expected_sha256_hex,
            "Windows and Linux Biome artifacts are genuinely different binaries; an equal hash would prove one was copy-pasted rather than independently downloaded and hashed."
        );
        assert_eq!(source.binary_path_in_tarball, "biome.exe");
        assert_eq!(source.archive_kind, ArchiveKind::RawBinary);
        assert!(matches!(source.symlink_policy, SymlinkPolicy::Reject));
        assert_eq!(source.tar_root_prefix, None);
    }

    #[test]
    fn biome_host_native_matches_this_build_targets_os() {
        // `BIOME_HOST_NATIVE` must always equal the manifest whose
        // `platform` field names this very build's `target_os` -- proves
        // the cfg-aliasing itself is wired correctly on every host this
        // crate is compiled for, not only asserted by inspection.
        #[cfg(target_os = "windows")]
        assert_eq!(BIOME_HOST_NATIVE.platform, "windows");
        #[cfg(not(target_os = "windows"))]
        assert_eq!(BIOME_HOST_NATIVE.platform, "linux");
    }
}

/// Compile-time-derivable invariants for [`RUSTFMT_WINDOWS_X64`], asserted
/// on every host (this crate is not `#[cfg(windows)]`-gated, so these run in
/// the Linux canonical suite too, giving real, evidence-backed coverage for
/// the Windows manifest's shape without requiring the P17-W VM) --
/// P17-W-R4's honest substitute for a native-Windows-only proof of the
/// constant's own field values.
#[cfg(test)]
mod windows_manifest_tests {
    use super::*;

    #[test]
    fn rustfmt_windows_x64_platform_architecture_are_windows_x64() {
        assert_eq!(RUSTFMT_WINDOWS_X64.platform, "windows");
        assert_eq!(RUSTFMT_WINDOWS_X64.architecture, "x64");
    }

    #[test]
    fn rustfmt_windows_x64_shares_the_same_component_id_as_linux() {
        // Same logical component across platforms -- `component_install_dir`
        // already segments by platform/architecture, and `crate::lib`'s
        // lease binding keys on `.id.0` alone, so a divergent id here would
        // silently break lease/ownership lookups on Windows.
        assert_eq!(RUSTFMT_WINDOWS_X64.id.0, RUSTFMT_LINUX_X64.id.0);
    }

    #[test]
    fn rustfmt_windows_x64_shares_the_same_pinned_version_as_linux() {
        // `RUSTFMT_RUST_RUNTIME_VERSION_COHERENCE`: both resolved from the
        // identical `2026-08-20` channel snapshot -- never independently
        // upgraded per platform.
        assert_eq!(RUSTFMT_WINDOWS_X64.version, RUSTFMT_LINUX_X64.version);
    }

    #[test]
    fn rustfmt_windows_x64_artifact_source_is_pinned_not_floating() {
        let source = RUSTFMT_WINDOWS_X64.source;
        assert!(source.tarball_url.contains("static.rust-lang.org"));
        assert!(source.tarball_url.contains("1.98.0"));
        assert!(source.tarball_url.contains("x86_64-pc-windows-msvc"));
        assert_eq!(source.expected_sha256_hex.len(), 64);
        assert!(
            source
                .expected_sha256_hex
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
        assert_eq!(source.binary_path_in_tarball, "bin/rustfmt.exe");
        assert_eq!(source.archive_kind, ArchiveKind::TarGz);
        assert!(matches!(source.symlink_policy, SymlinkPolicy::Reject));
        assert_eq!(source.required_paths, &["bin/cargo-fmt.exe"]);
        assert_eq!(
            source.tar_root_prefix,
            Some("rustfmt-1.98.0-x86_64-pc-windows-msvc/rustfmt-preview/")
        );
    }

    #[test]
    fn rustfmt_host_native_matches_this_build_targets_os() {
        // `RUSTFMT_HOST_NATIVE` must always equal the manifest whose
        // `platform` field names this very build's `target_os` -- proves
        // the cfg-aliasing itself is wired correctly on every host this
        // crate is compiled for, not only asserted by inspection.
        #[cfg(target_os = "windows")]
        assert_eq!(RUSTFMT_HOST_NATIVE.platform, "windows");
        #[cfg(not(target_os = "windows"))]
        assert_eq!(RUSTFMT_HOST_NATIVE.platform, "linux");
    }
}
