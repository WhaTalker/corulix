// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Pinned `CORULIX_MANAGED` manifests for cross-provider *runtimes* --
//! artifacts that back multiple providers rather than being an LSP
//! artifact themselves (Phase 7B-B1). Node is the first: it is not itself
//! a language server, but Pyright's managed launch resolves it as a
//! `ProviderCategory::Runtime` auxiliary tool exactly the same way the
//! pre-existing `HOST_ONLY`/system precedence already models a runtime
//! interpreter (see `wht_docs/wht_language_support.md`'s note on
//! `AuxiliaryToolRequirement`). [`RUST_SEMANTIC_RUNTIME_LINUX_X64`] is the
//! second, generalizing "shared by more than one LSP provider" to "shared
//! across a crate boundary": as of Phase 7B-B2-B it backs both
//! `wht_corulix_lsp` (rust-analyzer/cargo) and `wht_corulix_formatter`
//! (managed `rustfmt`, which was empirically proven via `ldd`/`RUNPATH`
//! inspection to dynamically link against this exact runtime's
//! `librustc_driver-*.so`). LSP-specific, single-consumer artifacts (the
//! TypeScript 7 native binary) remain in `wht_corulix_lsp::managed_toolchain`;
//! Formatter-specific, single-consumer artifacts (`rustfmt` itself) live in
//! `wht_corulix_formatter::managed_toolchain` -- this crate stays the sole
//! owner of the provisioning/uninstall *mechanism*; concrete manifests live
//! wherever their primary consumer does, except for a runtime genuinely
//! shared across more than one consumer, which lives here instead.
//! `wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64`
//! re-exports this module's constant so no existing call site changed.
//!
//! [`GO_SEMANTIC_RUNTIME_LINUX_X64`]/`_WINDOWS_X64` moved here for the same
//! reason (M03 rename_preview managed auxiliary capability closure): what
//! was a single-consumer `gopls` semantic-runtime dependency inside
//! `wht_corulix_lsp::managed_toolchain` became a genuinely shared runtime
//! once `wht_corulix_formatter` also needed its `bin/gofmt` for managed-first
//! `gofmt` resolution. `wht_corulix_lsp::managed_toolchain::
//! GO_SEMANTIC_RUNTIME_LINUX_X64`/`_WINDOWS_X64` re-export this module's
//! constants so no existing call site (including
//! `wht_corulix_engine::go_providers`, which resolved them from that path
//! before this move) changed.

use crate::provisioning::{
    ArchiveKind, ManagedArtifactSource, ManagedComponentId, ManagedComponentManifest, SymlinkPolicy,
};

/// The exact, upstream-verified relative paths of Node's three convenience
/// symlinks (`bin/npm`, `bin/npx`, `bin/corepack`) -- confirmed via a real
/// `tar tvzf` inspection of the pinned `node-v24.19.0-linux-x64.tar.gz`
/// during this phase's research gate (3 symlink entries, no others). Any
/// symlink/hard-link entry not exactly matching one of these three still
/// fails the whole archive closed.
const NODE_ALLOWED_SYMLINKS: &[&str] = &[
    "node-v24.19.0-linux-x64/bin/npm",
    "node-v24.19.0-linux-x64/bin/npx",
    "node-v24.19.0-linux-x64/bin/corepack",
];

/// Official Node.js `v24.19.0` ("Krypton") -- the current Active LTS line
/// at the time of this phase's version-research gate (Phase 7B-B1),
/// selected over the newer `v26.x` Current line specifically because LTS
/// status is the deterministic, non-"latest" selection criterion this
/// mandate requires (a floating "current stable" pointer is exactly the
/// kind of un-pinned resolution `ManagedArtifactSource` forbids). Digest
/// independently verified against
/// `https://nodejs.org/dist/v24.19.0/SHASUMS256.txt`.
///
/// The upstream tarball contains three convenience symlinks (`bin/npm`,
/// `bin/npx`, `bin/corepack`) alongside the real `bin/node` binary this
/// manifest points at; `provisioning::extract_tarball` skips (never
/// creates or follows) symlink/hard-link entries rather than aborting the
/// whole archive -- see that function's doc comment for the evidence
/// trail. Corulix's managed Node therefore never exposes `npm`/`npx` at
/// all, which is a strict security tightening for every provider that
/// resolves Node as a `ProviderCategory::Runtime` auxiliary tool (a
/// managed Pyright launch never has an `npm` to shell out to, mirroring
/// TS7 native's own `UNTRUSTED_TS7_PACKAGE_INSTALL=NO` structural proof).
pub const NODE_24_LTS_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("node-runtime"),
    version: "24.19.0",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.gz",
        expected_sha256_hex: "f625d97cd707df4ff96254916fbc5ff014f09c09effe5a1e0ca8f6d41a8789d4",
        binary_path_in_tarball: "node-v24.19.0-linux-x64/bin/node",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::AllowExactRelativePaths(NODE_ALLOWED_SYMLINKS),
        required_paths: &[],
        required_nonempty_dirs: &[],
        tar_root_prefix: None,
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// P17-W-R4-C2: the Windows counterpart of [`NODE_24_LTS_LINUX_X64`] --
/// same official, pinned, LTS Node.js `v24.19.0` release, `x64`. Unlike
/// every Rust artifact this crate provisions (all `.tar.gz`/`.tar.xz` on
/// every platform including Windows, confirmed directly against
/// `channel-rust-stable.toml`), Node's official Windows x64 build ships as
/// `.zip`/`.7z` only -- no `.tar.gz` alternative exists at
/// `nodejs.org/dist/v24.19.0/` -- which is the real, disclosed reason
/// [`crate::provisioning::ArchiveKind::Zip`] exists at all in this crate:
/// this is its first and, as of this phase, only consumer.
///
/// Digest independently verified against
/// `https://nodejs.org/dist/v24.19.0/SHASUMS256.txt` (`node-v24.19.0-win-x64.zip`),
/// and re-confirmed via a second, independent full re-download and
/// `sha256sum` during this phase's research gate -- not copied from a
/// single source.
///
/// # Real layout (verified via `unzip -l` against the independently
/// re-downloaded archive, not assumed)
///
/// The archive wraps everything in one top-level `node-v24.19.0-win-x64/`
/// directory (`tar_root_prefix` strips it, mirroring the Linux manifest's
/// own tar-based unwrap), containing `node.exe` directly (no `bin/`
/// subdirectory, unlike the Linux tarball layout) alongside `npm`/`npm.cmd`/
/// `npx`/`npx.cmd`/`corepack`/`corepack.cmd` convenience launchers and a
/// bundled `node_modules/corepack` -- none of which any provider that
/// resolves this component as a `ProviderCategory::Runtime` auxiliary tool
/// needs, and [`ManagedArtifactSource::binary_path_in_tarball`] pins only
/// `node.exe` itself as the required, verified artifact, exactly mirroring
/// [`NODE_24_LTS_LINUX_X64`]'s own "never exposes `npm`/`npx`" security
/// posture -- the Windows launchers are plain files (not symlinks; ZIP has
/// no cross-platform symlink concept and this archive uses none), so they
/// are simply extracted alongside `node.exe` and left unreferenced by any
/// resolution path rather than needing a symlink-policy allowlist entry
/// the way the Linux tarball's three real symlink entries do.
pub const NODE_24_LTS_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("node-runtime"),
    version: "24.19.0",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://nodejs.org/dist/v24.19.0/node-v24.19.0-win-x64.zip",
        expected_sha256_hex: "57f71ab3652e797d84acddc79c81cc9ff1c6ddb2a1974cdb83f00fee9bff4c73",
        binary_path_in_tarball: "node.exe",
        archive_kind: ArchiveKind::Zip,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &[],
        required_nonempty_dirs: &[],
        tar_root_prefix: Some("node-v24.19.0-win-x64/"),
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// This host's own real `node-runtime` manifest -- mirrors
/// `wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_HOST_NATIVE`'s own
/// `#[cfg]`-gated-alias pattern exactly. Added P17-W Stage D: before this
/// alias existed, every real consumer of [`NODE_24_LTS_LINUX_X64`]
/// (`wht_corulix_lsp::profile::LspProviderProfile::typescript_language_server_managed`/
/// `::pyright_managed`, plus `wht_corulix_engine::ts_testing`/`ts_validation`)
/// named that Linux-only constant unconditionally regardless of host --
/// the same hardcoded-to-Linux defect class the P17-W-R7 pass already found
/// and fixed for `GO_SEMANTIC_RUNTIME_HOST_NATIVE`/`GOPLS_HOST_NATIVE`, and
/// P17-W-R12 for `TYPESCRIPT_7_HOST_NATIVE` -- which would fail closed with
/// `ProvisioningError::PlatformArchitectureMismatch` (not silently pass) if
/// resolved natively on Windows unfixed. `pub` (not `pub(crate)`) because
/// [`NODE_24_LTS_LINUX_X64`] is already consumed across the
/// `wht_corulix_lsp`/`wht_corulix_engine` crate boundary, exactly the same
/// cross-crate visibility need `GOPLS_HOST_NATIVE` was made `pub` for. Only
/// `wht_corulix_lsp::profile::typescript_language_server_managed`'s
/// `managed_interpreter` field is rewired to this alias this pass (Stage D's
/// own scope); `pyright_managed`'s equivalent hardcoded reference is a
/// pre-existing, separately-scoped defect left for the Pyright stage.
#[cfg(target_os = "windows")]
pub const NODE_24_LTS_HOST_NATIVE: ManagedComponentManifest = NODE_24_LTS_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const NODE_24_LTS_HOST_NATIVE: ManagedComponentManifest = NODE_24_LTS_LINUX_X64;

/// Real official Rust distribution artifact set: `rustc` + `cargo` +
/// `rust-std` + `rust-src`, four independently-pinned, independently
/// hash-verified official `static.rust-lang.org` artifacts merged into one
/// install directory, resolved from
/// `static.rust-lang.org/dist/2026-08-20/channel-rust-stable.toml` (the
/// same tested/supported-combination source `rustup` itself reads -- never
/// a version Corulix chose independently of that channel manifest) during
/// Phase 7B-B1's research gate. All four artifacts share one build
/// (`88d9e12ae178fab0fb5cc050a94da85685d449ea`, `2026-08-20`), so
/// `RUST_VERSION_COMPATIBILITY=PASS` by construction: they are not four
/// independently-newest versions Corulix paired after the fact.
///
/// Relocated here from `wht_corulix_lsp::managed_toolchain` during Phase
/// 7B-B2-B: originally a single-consumer (rust-analyzer/cargo) LSP
/// artifact, it became a genuinely cross-crate-boundary shared runtime once
/// managed `rustfmt` (`wht_corulix_formatter::managed_toolchain::RUSTFMT_LINUX_X64`)
/// was empirically proven (via `ldd`/`RUNPATH` inspection of the real
/// downloaded `rustfmt` binary) to dynamically link against this exact
/// build's `lib/librustc_driver-28a98848f7a7c026.so` -- this module's own
/// doc comment already states the precedent this move follows: "a runtime
/// shared by more than one LSP provider... lives here instead", which
/// generalizes cleanly to a runtime shared across the LSP/Formatter crate
/// boundary. `wht_corulix_lsp::managed_toolchain` re-exports this constant
/// under its original path so no existing call site changed.
///
/// # Why all four, and why merged rather than four sibling components
///
/// A real, controlled experiment during Phase 7B-B1's research gate (see
/// `CHANGELOG.md`'s Phase 7B-B1-R1 entry for the full transcript) proved,
/// against a real Rust fixture and a real rust-analyzer binary under a
/// fully scrubbed `PATH`:
///
/// - `rustc` + `cargo` alone compile and run a std-only fixture
///   (`rustc --print sysroot` resolves correctly relative to the merged
///   `bin/`, confirming rustc's own sysroot-from-executable-path model
///   tolerates the merge), and `cargo metadata`/`cargo check` succeed.
/// - Without `rust-src`, rust-analyzer reports `n_sysroot_crates: 0` --
///   the sysroot has *zero* std/core/alloc crates loaded at all -- and
///   `textDocument/definition` on `String::new` returns an empty result.
///   `rust-std`'s compiled `.rlib`s are sufficient for `rustc`/`cargo` to
///   link and run real code, but rust-analyzer performs source-level HIR
///   analysis, not linking, and has no fallback without real std *source*.
/// - With `rust-src` merged in, `n_sysroot_crates: 26` and
///   `textDocument/definition` on `String::new` correctly resolves to
///   `lib/rustlib/src/rust/library/alloc/src/string.rs`, the real upstream
///   definition site.
///
/// `REQUIRED_RUST_SEMANTIC_COMPONENTS=[rustc, cargo, rust-std, rust-src]`,
/// `NOT_REQUIRED_RUST_COMPONENTS=[]` (no narrower subset was found
/// sufficient for the admitted definition/references/diagnostics
/// capability set). `rustc`/`cargo`/`rust-std` share the confirmed real
/// tar layout `<pkg>-<version>-<target>/<component-dir>/...`; `rust-src`'s
/// is `rust-src-<version>/rust-src/...` (its own tarball is
/// target-independent, hence no `-<target>` suffix). Each artifact's
/// `tar_root_prefix` strips exactly that wrapper directory so the four
/// merge onto one shared prefix exactly as the official `install.sh`
/// scripts (not run themselves) would have copied them.
const RUSTC_1_98_0_LINUX_X64_URL: &str =
    "https://static.rust-lang.org/dist/2026-08-20/rustc-1.98.0-x86_64-unknown-linux-gnu.tar.gz";
const RUSTC_1_98_0_LINUX_X64_SHA256: &str =
    "18ed6559de1b8ea6b77474ea86992b9a507d3a3d134d9ee017d30cf3f406e3ee";
const CARGO_1_98_0_LINUX_X64_URL: &str =
    "https://static.rust-lang.org/dist/2026-08-20/cargo-1.98.0-x86_64-unknown-linux-gnu.tar.gz";
const CARGO_1_98_0_LINUX_X64_SHA256: &str =
    "18bf1598891b30dd5eb52a337d08a92b4456255ddbe4c1ab996ffb578077031c";
const RUST_STD_1_98_0_LINUX_X64_URL: &str =
    "https://static.rust-lang.org/dist/2026-08-20/rust-std-1.98.0-x86_64-unknown-linux-gnu.tar.gz";
const RUST_STD_1_98_0_LINUX_X64_SHA256: &str =
    "8aa6405356392ce50160d1b286e86091c5e14adae3061115699c84ed4394d546";
const RUST_SRC_1_98_0_URL: &str =
    "https://static.rust-lang.org/dist/2026-08-20/rust-src-1.98.0.tar.gz";
const RUST_SRC_1_98_0_SHA256: &str =
    "bd2677a9958187d726b6b99c0f92b063f7b0b2f56ecbe966cb42fc2f81809f2f";
/// P11: clippy, resolved from the *same* `2026-08-20` channel manifest as
/// the four artifacts above (`static.rust-lang.org/dist/2026-08-20/
/// channel-rust-stable.toml`'s own `[pkg.clippy-preview]` entry) --
/// `RUST_VERSION_COMPATIBILITY=PASS` by construction, exactly like the
/// existing four-artifact set's own doc comment argues, never an
/// independently-newest clippy paired after the fact. Independently
/// downloaded and re-hashed against this constant during P11's own
/// research gate (not merely copied from the channel manifest's own
/// `hash` field). `ldd` against the real extracted `clippy-driver` binary
/// confirms `librustc_driver-28a98848f7a7c026.so` as an unresolved dynamic
/// dependency -- the *exact* hash-named library the existing doc comment
/// above already cites for managed `rustfmt`'s own linkage -- direct,
/// empirical proof this is the same build clippy must run against, not an
/// assumption.
const CLIPPY_1_98_0_LINUX_X64_URL: &str =
    "https://static.rust-lang.org/dist/2026-08-20/clippy-1.98.0-x86_64-unknown-linux-gnu.tar.gz";
const CLIPPY_1_98_0_LINUX_X64_SHA256: &str =
    "22a5d1ed834c3b94cd5f5b0a7d1c804ca1124b7c1fadaf25583e452e6426ebd7";

pub const RUST_SEMANTIC_RUNTIME_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("rust-semantic-runtime"),
    version: "1.98.0",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: RUSTC_1_98_0_LINUX_X64_URL,
        expected_sha256_hex: RUSTC_1_98_0_LINUX_X64_SHA256,
        binary_path_in_tarball: "bin/rustc",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        // `bin/cargo` and `bin/rustdoc` only exist once the corresponding
        // additional artifacts below have merged in -- this is the *final
        // merged layout* check, not a check of the primary `rustc` archive
        // in isolation (see `additional_sources`' doc comment).
        required_paths: &[
            "bin/cargo",
            "bin/rustdoc",
            // P11: verified as part of the *final merged* layout, exactly
            // like `bin/cargo`/`bin/rustdoc` above -- these only exist once
            // the clippy `additional_sources` entry below has merged in.
            "bin/clippy-driver",
            "bin/cargo-clippy",
            "lib/rustlib/src/rust/library/alloc/src/string.rs",
            "lib/rustlib/src/rust/library/std/src/lib.rs",
            // P12-R2: the managed `rust-lld` linker driver and its Unix
            // ("gcc-ld") entry point, part of the same official `rustc`
            // archive as `bin/rustc` itself (confirmed via `file`: a real
            // ELF executable, not a stub) -- required now that
            // `wht_corulix_engine::testing::run_cargo_test_with_limits`
            // resolves it explicitly rather than only ever spawning
            // `bin/cargo`/`bin/rustc`. Verified present as part of the
            // *final merged* layout, exactly like the clippy paths above.
            "lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld",
        ],
        // `rust-std`'s compiled artifacts (`libstd-<hash>.rlib` etc.) carry
        // a build-specific hash in their filename that cannot be pinned as
        // an exact `required_paths` entry -- non-emptiness is the
        // strongest content check available without guessing a filename.
        required_nonempty_dirs: &["lib/rustlib/x86_64-unknown-linux-gnu/lib"],
        tar_root_prefix: Some("rustc-1.98.0-x86_64-unknown-linux-gnu/rustc/"),
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[
        ManagedArtifactSource {
            tarball_url: CARGO_1_98_0_LINUX_X64_URL,
            expected_sha256_hex: CARGO_1_98_0_LINUX_X64_SHA256,
            binary_path_in_tarball: "bin/cargo",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: Some("cargo-1.98.0-x86_64-unknown-linux-gnu/cargo/"),
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        ManagedArtifactSource {
            tarball_url: RUST_STD_1_98_0_LINUX_X64_URL,
            expected_sha256_hex: RUST_STD_1_98_0_LINUX_X64_SHA256,
            binary_path_in_tarball: "bin/rustc",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: Some(
                "rust-std-1.98.0-x86_64-unknown-linux-gnu/rust-std-x86_64-unknown-linux-gnu/",
            ),
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        ManagedArtifactSource {
            tarball_url: RUST_SRC_1_98_0_URL,
            expected_sha256_hex: RUST_SRC_1_98_0_SHA256,
            binary_path_in_tarball: "bin/rustc",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: Some("rust-src-1.98.0/rust-src/"),
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        // P11: `clippy-driver` + `cargo-clippy`, merged onto the same `bin/`
        // as `rustc`/`cargo`/`rustdoc` above. Real archive layout confirmed
        // via `tar tvzf` during P11's research gate:
        // `clippy-1.98.0-x86_64-unknown-linux-gnu/clippy-preview/bin/
        // {clippy-driver,cargo-clippy}`, no symlink/hard-link entries (so
        // `SymlinkPolicy::Reject`, matching every other source here, is not
        // a functional restriction -- it simply has nothing to reject).
        ManagedArtifactSource {
            tarball_url: CLIPPY_1_98_0_LINUX_X64_URL,
            expected_sha256_hex: CLIPPY_1_98_0_LINUX_X64_SHA256,
            binary_path_in_tarball: "bin/clippy-driver",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: Some("clippy-1.98.0-x86_64-unknown-linux-gnu/clippy-preview/"),
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
    ],
};

/// P17-W-R4-C2: the Windows counterpart of [`RUST_SEMANTIC_RUNTIME_LINUX_X64`]
/// -- the same real, official `static.rust-lang.org` artifact family
/// (`rustc` + `cargo` + `rust-std` + `rust-src` + `clippy`), independently
/// re-downloaded and re-hashed against `channel-rust-stable.toml` during
/// this phase's research gate, targeting `x86_64-pc-windows-msvc` (the
/// canonical Windows Rust target already fixed by the closed
/// `RUSTFMT_WINDOWS_X64` manifest -- see
/// `wht_corulix_formatter::managed_toolchain`). Same build
/// (`88d9e12ae178fab0fb5cc050a94da85685d449ea`, `2026-08-20`) as the Linux
/// manifest, so `RUST_VERSION_COMPATIBILITY=PASS` here too.
///
/// # Real layout differences from the Linux manifest (verified via `tar
/// tzf` against each independently re-downloaded artifact, not assumed)
///
/// - Every executable carries a `.exe` suffix (`bin/rustc.exe`, `bin/
///   cargo.exe`, `bin/clippy-driver.exe`, `bin/cargo-clippy.exe`).
/// - `rustc`'s own runtime-linked dependencies (`std-<hash>.dll`,
///   `rustc_driver-<hash>.dll`) sit as real PE DLLs directly inside `bin/`
///   alongside `rustc.exe` -- there is no separate Linux-style `lib/`
///   shared-object directory. This is the exact root cause
///   [`crate::managed_runtimes`]'s own Windows DLL resolution mechanism
///   (a process-scoped, Corulix-owned `PATH` prepend to this merged
///   install's `bin/`, set by `wht_corulix_formatter::managed`'s
///   `resolve_formatter` on `cfg(windows)` -- never `LD_LIBRARY_PATH`,
///   which does not exist on Windows, and never the ambient system `PATH`)
///   exists for: Windows has no `RPATH`/`RUNPATH` equivalent, and the
///   managed `rustfmt.exe` (a *separate* component, in a *separate* install
///   directory) has no other way to find these two DLLs at load time.
/// - The linker driver lives at `lib/rustlib/x86_64-pc-windows-msvc/bin/
///   rust-lld.exe` (Unix entry point equivalent:
///   `lib/rustlib/x86_64-pc-windows-msvc/bin/gcc-ld/{ld.lld,lld-link}.exe`)
///   -- present, real, and part of this same official `rustc` archive,
///   exactly like the Linux manifest's own `gcc-ld/ld.lld`. See P12 link
///   authority research (this phase's own `CHANGELOG.md` entry) for why
///   the *linker binary* being managed does not by itself close P12: the
///   Windows import libraries (`kernel32.lib`, `ucrt.lib`/`msvcrt.lib`,
///   `vcruntime.lib`) `rust-lld`/`link.exe` both still require to resolve
///   Windows API symbols are not part of any `static.rust-lang.org`
///   artifact and ship only with Visual Studio Build Tools / the Windows
///   SDK -- a real, disclosed, currently-unmanaged external dependency,
///   not silently assumed.
pub const RUST_SEMANTIC_RUNTIME_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("rust-semantic-runtime"),
    version: "1.98.0",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rustc-1.98.0-x86_64-pc-windows-msvc.tar.gz",
        expected_sha256_hex: "996ed3fa10dd6097149d5feaf727354b412c7da0e063d9326fbb58242def87e1",
        binary_path_in_tarball: "bin/rustc.exe",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &[
            "bin/cargo.exe",
            "bin/rustdoc.exe",
            "bin/clippy-driver.exe",
            "bin/cargo-clippy.exe",
            "lib/rustlib/src/rust/library/alloc/src/string.rs",
            "lib/rustlib/src/rust/library/std/src/lib.rs",
            "lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe",
        ],
        required_nonempty_dirs: &["lib/rustlib/x86_64-pc-windows-msvc/lib"],
        tar_root_prefix: Some("rustc-1.98.0-x86_64-pc-windows-msvc/rustc/"),
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[
        ManagedArtifactSource {
            tarball_url: "https://static.rust-lang.org/dist/2026-08-20/cargo-1.98.0-x86_64-pc-windows-msvc.tar.gz",
            expected_sha256_hex: "c50b54520d2748c60cabbc50c3f45fadb522453f048f77ad6d5f4f1b7e3f300b",
            binary_path_in_tarball: "bin/cargo.exe",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: Some("cargo-1.98.0-x86_64-pc-windows-msvc/cargo/"),
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        ManagedArtifactSource {
            tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rust-std-1.98.0-x86_64-pc-windows-msvc.tar.gz",
            expected_sha256_hex: "e8810c2e914a1f557d8e3760653843afdbcba188714d9c5b7247f53bb049b592",
            binary_path_in_tarball: "bin/rustc.exe",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: Some(
                "rust-std-1.98.0-x86_64-pc-windows-msvc/rust-std-x86_64-pc-windows-msvc/",
            ),
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        ManagedArtifactSource {
            tarball_url: RUST_SRC_1_98_0_URL,
            expected_sha256_hex: RUST_SRC_1_98_0_SHA256,
            binary_path_in_tarball: "bin/rustc.exe",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: Some("rust-src-1.98.0/rust-src/"),
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        ManagedArtifactSource {
            tarball_url: "https://static.rust-lang.org/dist/2026-08-20/clippy-1.98.0-x86_64-pc-windows-msvc.tar.gz",
            expected_sha256_hex: "0dc660c6e37d35fb89e0956259b1bfcd2ed9033abe34cd8bf082b3a9f17a322d",
            binary_path_in_tarball: "bin/clippy-driver.exe",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: Some("clippy-1.98.0-x86_64-pc-windows-msvc/clippy-preview/"),
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
    ],
};

/// Official Go `1.27.0`, linux/x64 (moved here from
/// `wht_corulix_lsp::managed_toolchain` -- M03 rename_preview managed
/// auxiliary capability closure -- once `wht_corulix_formatter` also needed
/// this runtime's `bin/gofmt` for managed-first `gofmt` resolution, making it
/// a genuinely shared runtime rather than a single-consumer `gopls`
/// dependency; see this module's own doc comment).
///
/// `GO_UPSTREAM_DISTRIBUTION_MODEL=OFFICIAL_PREBUILT_ARCHIVE`, the same
/// admission model already used for [`RUST_SEMANTIC_RUNTIME_LINUX_X64`]'s
/// `static.rust-lang.org` artifacts and `wht_corulix_lsp::managed_toolchain`'s
/// `TYPESCRIPT_7_LINUX_X64`/`PYRIGHT_LINUX_X64` npm registry tarballs.
///
/// `expected_sha256_hex` and `source.tarball_url` were independently verified
/// against `go.dev/dl/?mode=json` and a real downloaded-and-hashed copy of
/// the archive during the original P17-W-R4-C3 admission pass.
///
/// `required_paths`/`required_nonempty_dirs` were derived from a real
/// extraction of this exact archive: `bin/go` and `bin/gofmt` are the two
/// executables the archive ships; `VERSION` is the plain-text file the Go
/// toolchain itself reads to self-report its version; `src/runtime/runtime.go`
/// proves the full standard-library *source* tree extracted (modern Go
/// archives ship no precompiled `pkg/<os>_<arch>/std` tree at all; the
/// toolchain compiles `std` into its build cache on first use). The stdlib
/// source tree is required for the same reason `rust-src` is required for
/// [`RUST_SEMANTIC_RUNTIME_LINUX_X64`]: `gopls`/`go/packages` resolve stdlib
/// symbol definitions to real upstream source, not merely compiled
/// interfaces.
pub const GO_SEMANTIC_RUNTIME_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("go-semantic-runtime"),
    version: "1.27.0",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://go.dev/dl/go1.27.0.linux-amd64.tar.gz",
        expected_sha256_hex: "675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685",
        binary_path_in_tarball: "bin/go",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &["bin/gofmt", "VERSION", "src/runtime/runtime.go"],
        required_nonempty_dirs: &["src", "pkg/tool"],
        tar_root_prefix: Some("go/"),
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// The Windows counterpart of [`GO_SEMANTIC_RUNTIME_LINUX_X64`] -- same real,
/// official `go.dev/dl/?mode=json` distribution index, same version
/// (`1.27.0`), fetched and independently re-hashed during the original
/// P17-W-R4-C3 admission pass. A real PKZIP archive (`ArchiveKind::Zip`), not
/// a `.tar.gz`; every executable carries a `.exe` suffix (`go/bin/go.exe`,
/// `go/bin/gofmt.exe`).
pub const GO_SEMANTIC_RUNTIME_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("go-semantic-runtime"),
    version: "1.27.0",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://go.dev/dl/go1.27.0.windows-amd64.zip",
        expected_sha256_hex: "f0c0a0d33ba94f4d2c5dbc887334ce678b21813504ddb3aafcb06e60a5a667c4",
        binary_path_in_tarball: "bin/go.exe",
        archive_kind: ArchiveKind::Zip,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &["bin/gofmt.exe", "VERSION", "src/runtime/runtime.go"],
        required_nonempty_dirs: &["src", "pkg/tool"],
        tar_root_prefix: Some("go/"),
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// The managed Ruff 0.16.3 formatter/linter binary -- lives here rather than
/// in `wht_corulix_formatter` alone because `wht_corulix_engine`'s Python
/// `TypecheckBuild`/`Linter` resolution also needs it (Installation-Contract-V1
/// M03 Python auxiliary closure: Formatter and Linter must resolve the exact
/// same integrity-verified component, never two independently provisioned
/// Ruff copies). Owner-pinned exact version, not `latest` -- see the M03
/// Python managed-closure mandate. Official upstream asset, independently
/// re-downloaded and re-hashed against `astral-sh/ruff`'s own release-asset
/// `.sha256` sidecar during this admission pass; the digest below matches
/// both sources. A single statically-linked executable archive: `ldd` shows
/// only standard glibc runtime libraries, so no sibling semantic-runtime
/// dependency is required (unlike Go/Rust's managed compiler toolchains).
pub const RUFF_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("ruff"),
    version: "0.16.3",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://github.com/astral-sh/ruff/releases/download/0.16.3/ruff-x86_64-unknown-linux-gnu.tar.gz",
        expected_sha256_hex: "7ab3b978d2c0b1c96b2323d4e5c4f35284ae1cdf35d2f7399595c74c805f5fa3",
        binary_path_in_tarball: "ruff",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &[],
        required_nonempty_dirs: &[],
        tar_root_prefix: Some("ruff-x86_64-unknown-linux-gnu/"),
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// The Windows counterpart of [`RUFF_LINUX_X64`] -- same real, official
/// `astral-sh/ruff` `0.16.3` release, independently re-downloaded and
/// re-hashed during this admission pass. Unlike the Linux `.tar.gz`, this
/// `.zip` ships `ruff.exe` directly at the archive root with no wrapper
/// directory (confirmed via direct archive inspection), hence
/// `tar_root_prefix: None`.
pub const RUFF_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("ruff"),
    version: "0.16.3",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://github.com/astral-sh/ruff/releases/download/0.16.3/ruff-x86_64-pc-windows-msvc.zip",
        expected_sha256_hex: "f10c709755b393fd9821506b21070bcca969b9966504edd1e490efd08e3662ba",
        binary_path_in_tarball: "ruff.exe",
        archive_kind: ArchiveKind::Zip,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &[],
        required_nonempty_dirs: &[],
        tar_root_prefix: None,
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// P12-R2: the managed GNU link runtime -- a real, official, reproducible,
/// SHA-256-verified sysroot subset that lets
/// `wht_corulix_engine::testing::run_cargo_test_with_limits` link a real
/// `cargo test` binary on `x86_64-unknown-linux-gnu` without ever invoking a
/// system `cc`/`gcc`/`clang`/`ld`.
///
/// # Source and why
///
/// `x86-64--glibc--stable-2021.11-5` from
/// <https://toolchains.bootlin.com/releases_x86-64.html> -- Bootlin's own
/// long-running, versioned, checksummed cross-toolchain build service (gcc
/// 10.3.0 / binutils 2.36.1 / glibc 2.34, built via Buildroot from upstream
/// sources; full provenance and reproduction steps are the tarball's own
/// bundled `README.txt`, itself pointing at
/// <https://github.com/bootlin/buildroot-toolchains>). Selected over a
/// hand-built sysroot because it is an independently-published, versioned,
/// re-downloadable artifact with its own SHA-256 -- not a Corulix-authored
/// bundle nothing outside this repository can reproduce or audit. The exact
/// tarball bytes were downloaded and their SHA-256 independently verified
/// against Bootlin's own published `.sha256` file during this phase's
/// research gate (`6fe812add925...` -- full digest in
/// `expected_sha256_hex` below), not copied from a third party.
///
/// `2021.11-5` (glibc 2.34) is deliberately the *oldest* of Bootlin's
/// current stable releases (2022.08 through 2025.08 also exist, ranging up
/// to glibc 2.41) -- glibc's forward-compatibility guarantee means a
/// binary linked against an older glibc runs unmodified on any newer one,
/// so the oldest available stable baseline is the most broadly compatible
/// choice, not an arbitrary pin. `P12_GNU_LINK_RUNTIME_GLIBC_BASELINE=2.34`.
///
/// # Why a subset, not the full toolchain
///
/// The upstream tarball is a full gcc/binutils/gdb cross-toolchain
/// (~480 MiB extracted): a C/C++/Fortran compiler, a debugger, LTO/plugin
/// shared objects, and headers Corulix never spawns or reads -- only the
/// sysroot's runtime shared objects, CRT startup objects, and
/// `libgcc.a`/`libgcc_eh.a` are ever touched by the linking flow this
/// component backs (see `wht_corulix_engine::testing`'s own doc comment for
/// the real, empirically-derived link-argument set). `extract_path_prefixes`
/// below keeps only those three subtrees (~37 MiB), the same "don't extract
/// what nothing consumes" reasoning [`ManagedArtifactSource::extract_path_prefixes`]'s
/// own doc comment states.
///
/// # Why the linker binary itself is not part of this component
///
/// This component supplies the *sysroot* (CRT objects, libc/libpthread/
/// libgcc_s shared objects, `libgcc.a`) -- the linker *executable* is
/// `rust-lld` (`lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld`),
/// already part of [`RUST_SEMANTIC_RUNTIME_LINUX_X64`]'s own official
/// `rustc` archive. Two independently-versioned components, each owning
/// exactly the artifact it is the upstream publisher of, composed together
/// at the call site (`wht_corulix_engine::testing::link_environment`) --
/// never a third toolchain, never a Corulix-built linker.
///
/// # Symlink allowlist
///
/// The retained subtrees contain 18 real, relative-path-only symlinks
/// (glibc/libgcc's own standard `libfoo.so -> libfoo.so.N.N.N` versioning
/// convention) for libraries Corulix's own link configuration never
/// references (`libatomic`, `libstdc++`, `libgfortran`, `libquadmath`,
/// `libresolv`, the NSS modules, ...) -- enumerated exactly, confirmed via a
/// real `tar tjvf` inspection of the pinned tarball during this phase's
/// research gate, mirroring [`NODE_ALLOWED_SYMLINKS`]'s own precedent. Any
/// symlink entry not exactly matching one of these fails the whole archive
/// closed.
const GNU_LINK_RUNTIME_ALLOWED_SYMLINKS: &[&str] = &[
    "x86_64-buildroot-linux-gnu/sysroot/lib/libatomic.so",
    "x86_64-buildroot-linux-gnu/sysroot/lib/libatomic.so.1",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libanl.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libc_malloc_debug.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libthread_db.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libcrypt.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libnss_hesiod.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libquadmath.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libstdc++.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libmvec.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libquadmath.so.0",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libstdc++.so.6",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libgfortran.so.5",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libgfortran.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libresolv.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libnss_compat.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libnss_db.so",
    "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libBrokenLocale.so",
];

/// `lib64 -> lib` compatibility symlinks, Corulix-authored (not extracted
/// from the archive at all -- see [`GNU_LINK_RUNTIME_ALLOWED_SYMLINKS`]'s
/// own doc comment: these two paths are deliberately *not* on that
/// allowlist, so an archive-declared `sysroot/lib64`/`sysroot/usr/lib64`
/// entry would fail the whole archive closed rather than silently being
/// trusted). Required, not decorative: several of the kept runtime linker
/// scripts (e.g. `usr/lib/libm.so`'s `GROUP ( /lib64/libm.so.6 ... )`)
/// hardcode an absolute `/lib64/...` target, and `ld.lld --sysroot=` only
/// re-roots that absolute path under the sysroot -- it does not also
/// translate `lib64` to `lib` -- found and fixed via a real failed link
/// during this phase's own research gate (`cannot find /lib64/libm.so.6
/// inside <sysroot>`), not reasoned about in advance.
const GNU_LINK_RUNTIME_POST_EXTRACTION_SYMLINKS: &[(&str, &str)] = &[
    ("x86_64-buildroot-linux-gnu/sysroot/lib64", "lib"),
    ("x86_64-buildroot-linux-gnu/sysroot/usr/lib64", "lib"),
];

const GNU_LINK_RUNTIME_TARBALL_URL: &str = "https://toolchains.bootlin.com/downloads/releases/toolchains/x86-64/tarballs/x86-64--glibc--stable-2021.11-5.tar.bz2";
const GNU_LINK_RUNTIME_SHA256: &str =
    "6fe812add925493ea0841365f1fb7ca17fd9224bab61a731063f7f12f3a621b0";

pub const GNU_LINK_RUNTIME_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("gnu-link-runtime"),
    version: "2021.11-5",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: GNU_LINK_RUNTIME_TARBALL_URL,
        expected_sha256_hex: GNU_LINK_RUNTIME_SHA256,
        // The dynamic loader: a real, standalone ELF executable, and the
        // one file every linked-and-run test binary genuinely depends on
        // at runtime (its `PT_INTERP` entry) -- the honest choice of
        // "primary artifact" for a sysroot component, not an arbitrary
        // pick.
        binary_path_in_tarball: "x86_64-buildroot-linux-gnu/sysroot/lib/ld-linux-x86-64.so.2",
        archive_kind: ArchiveKind::TarBz2,
        symlink_policy: SymlinkPolicy::AllowExactRelativePaths(GNU_LINK_RUNTIME_ALLOWED_SYMLINKS),
        required_paths: &[
            "x86_64-buildroot-linux-gnu/sysroot/lib/libc.so.6",
            "x86_64-buildroot-linux-gnu/sysroot/lib/libpthread.so.0",
            "x86_64-buildroot-linux-gnu/sysroot/lib/libgcc_s.so.1",
            "x86_64-buildroot-linux-gnu/sysroot/usr/lib/crt1.o",
            "x86_64-buildroot-linux-gnu/sysroot/usr/lib/crti.o",
            "x86_64-buildroot-linux-gnu/sysroot/usr/lib/crtn.o",
            "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libc.so",
            "x86_64-buildroot-linux-gnu/sysroot/usr/lib/libc_nonshared.a",
            "lib/gcc/x86_64-buildroot-linux-gnu/10.3.0/libgcc.a",
        ],
        required_nonempty_dirs: &[],
        tar_root_prefix: Some("x86-64--glibc--stable-2021.11-5/"),
        extract_path_prefixes: &[
            "x86_64-buildroot-linux-gnu/sysroot/lib/",
            "x86_64-buildroot-linux-gnu/sysroot/usr/lib/",
            "lib/gcc/x86_64-buildroot-linux-gnu/10.3.0/libgcc",
        ],
        post_extraction_symlinks: GNU_LINK_RUNTIME_POST_EXTRACTION_SYMLINKS,
    },
    additional_sources: &[],
};

/// P17-W: a real, independently-hash-verified, **fully self-contained**
/// `x86_64-pc-windows-gnu`-*hosted* Rust toolchain -- `rustc`/`cargo`
/// themselves run natively as GNU-ABI (MinGW-w64) Windows binaries, not
/// MSVC-ABI ones -- backing `TRUSTED_WORKSPACE_EXECUTION_TARGET` for P12
/// (`wht_corulix_engine::testing::run_cargo_test_with_limits`) alone. A
/// distinct, narrowly-scoped concept from [`RUST_SEMANTIC_RUNTIME_WINDOWS_X64`]
/// (`x86_64-pc-windows-msvc`-hosted), which stays the unconditional
/// `MANAGED_PROVIDER_HOST_TARGET` for Corulix's own binary and every other
/// Windows provider (rustfmt, rust-analyzer, gopls, ...) -- this component is
/// never resolved by any of them.
///
/// # Why a GNU-*hosted* toolchain, not MSVC-hosted cross-compiling to GNU
///
/// An earlier design in this same phase tried the opposite: keep the
/// certified MSVC-hosted [`RUST_SEMANTIC_RUNTIME_WINDOWS_X64`] as `rustc`/
/// `cargo` and cross-compile `--target x86_64-pc-windows-gnu` against a
/// synthetic merged sysroot. That was empirically proven broken during this
/// phase's own real native-Windows test run: **when cargo cross-compiles
/// (`--target` differs from the host triple), `RUSTFLAGS` applies only to
/// the cross-target artifacts, never to host-target artifacts** (`build.rs`,
/// proc macros) -- so a fixture with a real `build.rs` (P12's own
/// `write_passing_fixture`) failed with `error: linker \`link.exe\` not
/// found`, the exact undisclosed-system-dependency failure this whole
/// vertical exists to avoid, because the *host*-target compile silently fell
/// back to expecting a real MSVC linker regardless of any target-side
/// override. A GNU-*hosted* toolchain has no such split: host-target and
/// cross-target compiles are the *same* target
/// (`x86_64-pc-windows-gnu` == `x86_64-pc-windows-gnu`), so `RUSTFLAGS`
/// covers both uniformly, `build.rs`/proc-macro compilation links through
/// the identical self-contained MinGW path as the crate under test, and no
/// `--target` flag or synthetic merged sysroot is needed at all -- `rustc`'s
/// own native sysroot (this component's own install directory) already has
/// everything, exactly mirroring how [`RUST_SEMANTIC_RUNTIME_LINUX_X64`]
/// needs no `--target`/sysroot merge because Linux's host and P12 target are
/// already the same triple.
///
/// # Real, official, self-contained artifact set (five merged archives)
///
/// All five are independently hash-verified against
/// `static.rust-lang.org/dist/2026-08-20/channel-rust-stable.toml`, the same
/// build (`88d9e12ae178fab0fb5cc050a94da85685d449ea`, `2026-08-20`) as every
/// other Rust artifact this crate provisions:
///
/// - `rustc-1.98.0-x86_64-pc-windows-gnu.tar.gz` (primary): real,
///   Windows-native, GNU-ABI `rustc.exe`/`rustdoc.exe`, dynamically linked
///   against `rustc_driver-<hash>.dll`/`std-<hash>.dll`/
///   `libwinpthread-1.dll`/`libgcc_s_seh-1.dll` -- all four co-located
///   directly inside this same archive's own `bin/`, so the Windows PE
///   loader's default same-directory DLL search resolves them without any
///   `PATH` trick (confirmed via `tar tzf`). The real archive also carries
///   `lib/rustlib/x86_64-pc-windows-gnu/bin/rust-lld.exe`/`gcc-ld/*.exe`, but
///   this component's own `extract_path_prefixes` deliberately drops them --
///   see that field's own doc comment on this source for why (in short:
///   `rust-lld.exe` alone is 211 MiB, unneeded because
///   `wht_corulix_engine::testing`'s `link_environment` links via the
///   self-contained `x86_64-w64-mingw32-gcc.exe` below instead, and keeping
///   it would push this one archive's extracted size past
///   `provisioning::MAX_EXTRACTED_BYTES`).
/// - `cargo-1.98.0-x86_64-pc-windows-gnu.tar.gz`: real, Windows-native,
///   GNU-ABI `cargo.exe`.
/// - `rust-std-1.98.0-x86_64-pc-windows-gnu.tar.gz`: this target's compiled
///   `std`/`core`/etc. (`.rlib`/`.rmeta`), plus the CRT startup objects
///   (`lib/self-contained/crt2.o`, `dllcrt2.o`, `lib/rsbegin.o`,
///   `lib/rsend.o`) every linked `x86_64-pc-windows-gnu` binary needs.
/// - `rust-src-1.98.0.tar.gz`: target-independent, shared with every other
///   Rust manifest this crate provisions (`RUST_SRC_1_98_0_URL`/`_SHA256`).
/// - `rust-mingw-1.98.0-x86_64-pc-windows-gnu.tar.gz`: the official,
///   self-contained MinGW-w64 pieces -- a real Windows-native driver
///   (`x86_64-w64-mingw32-gcc.exe`), linker (`ld.exe`), archiver helper
///   (`dlltool.exe`), and the Windows API import libraries as real, plain
///   `.a` archives (`libkernel32.a`, `libmsvcrt.a`, `libuser32.a`, ...) --
///   confirmed via a real `tar tzf` inspection during this phase's research
///   gate (68 entries, no symlinks: `tar tvzf` shows only
///   `-rw-r--r--`/`-rwxr-xr-x`/`drwxr-xr-x` modes; the paired `rust-std`
///   archive is equally symlink-free).
///
/// Merged onto one shared `lib/rustlib/x86_64-pc-windows-gnu/` prefix, these
/// are exactly the on-disk layout `rustup toolchain install
/// x86_64-pc-windows-gnu` itself would produce -- Corulix provisions and
/// hash-verifies them independently rather than shelling out to `rustup`.
///
/// # Confirmed against the official `rustup` book
///
/// (`rust-lang.github.io/rustup/installation/windows-msvc.html`, fetched
/// during this phase's research gate): _"To compile programs into an exe
/// file, Rust requires a linker, libraries and Windows API import
/// libraries. For msvc targets these can be acquired through Visual
/// Studio."_ No `static.rust-lang.org` MSVC-target artifact provides the
/// Windows API import libraries (`kernel32.lib`, `ucrt.lib`/`msvcrt.lib`,
/// `vcruntime.lib`) MSVC-target linking requires -- those ship only with
/// Visual Studio Build Tools / the Windows SDK, an undisclosed system
/// dependency `CORULIX_SYSTEM_DEPENDENCY_REQUIRED=NO` forbids relying on for
/// this vertical. The GNU-hosted route above has no such gap: every artifact
/// it needs, including the linker and the Windows API import libraries, is a
/// real, independently-pinned `static.rust-lang.org` download.
///
/// # Why a *separate* component, not folded into [`RUST_SEMANTIC_RUNTIME_WINDOWS_X64`]
///
/// `RUST_SEMANTIC_RUNTIME_WINDOWS_X64` is the already-certified, hash-pinned
/// `MANAGED_PROVIDER_HOST_TARGET` identity every Windows provider (Corulix's
/// own binary, rustfmt, rust-analyzer) resolves against; growing that
/// manifest for a P12-only concern would conflate two genuinely independent
/// identities (`MANAGED_PROVIDER_HOST_TARGET` vs.
/// `TRUSTED_WORKSPACE_EXECUTION_TARGET`) the calling code must keep apart.
/// Distinct [`ManagedComponentId`] (`"rust-semantic-runtime-gnu"`, not
/// `"rust-semantic-runtime"`) so its install directory can never collide
/// with the certified MSVC identity's own, even though both share
/// `version`/`platform`/`architecture`.
pub const RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64: ManagedComponentManifest =
    ManagedComponentManifest {
        id: ManagedComponentId("rust-semantic-runtime-gnu"),
        version: "1.98.0",
        platform: "windows",
        architecture: "x64",
        source: ManagedArtifactSource {
            tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rustc-1.98.0-x86_64-pc-windows-gnu.tar.gz",
            expected_sha256_hex: "c97a98af7a8c84cee611a9a8a5bba6a804f82b09899a2e451a33b5934d684542",
            binary_path_in_tarball: "bin/rustc.exe",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            // Checked as part of the *final merged* layout (this source plus
            // every `additional_sources` entry below), exactly like
            // `RUST_SEMANTIC_RUNTIME_LINUX_X64`'s own `bin/cargo`/`bin/rustdoc`
            // precedent.
            required_paths: &[
                "bin/cargo.exe",
                "bin/rustdoc.exe",
                "lib/rustlib/src/rust/library/alloc/src/string.rs",
                "lib/rustlib/src/rust/library/std/src/lib.rs",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/crt2.o",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/dllcrt2.o",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/rsbegin.o",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/rsend.o",
                "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/x86_64-w64-mingw32-gcc.exe",
                "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/ld.exe",
                "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/dlltool.exe",
                "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/libwinpthread-1.dll",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libmingw32.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libmingwex.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libmsvcrt.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libkernel32.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libgcc.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libgcc_eh.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libpthread.a",
            ],
            // `rust-std`'s own compiled artifacts (`libstd-<hash>.rlib`, etc.)
            // carry a build-specific hashed filename, mirroring
            // `RUST_SEMANTIC_RUNTIME_LINUX_X64`'s own `required_nonempty_dirs`
            // rationale for the identical reason.
            required_nonempty_dirs: &["lib/rustlib/x86_64-pc-windows-gnu/lib"],
            tar_root_prefix: Some("rustc-1.98.0-x86_64-pc-windows-gnu/rustc/"),
            // The real, un-filtered `rustc-1.98.0-x86_64-pc-windows-gnu.tar.gz`
            // extracts to ~594 MiB (confirmed via a real `tar tzvf` byte-sum
            // during this phase's research gate) -- over
            // `provisioning::MAX_EXTRACTED_BYTES` (512 MiB) on its own, before
            // any `additional_sources` entry is even reached, which this
            // phase's own real native-Windows test run first surfaced as
            // `ProvisioningError::ExtractedContentTooLarge`. The largest single
            // contributor by far is `lib/rustlib/x86_64-pc-windows-gnu/bin/
            // rust-lld.exe` (211 MiB) -- genuinely unneeded here, since this
            // component's own `link_environment` (`wht_corulix_engine::testing`)
            // links via the self-contained `x86_64-w64-mingw32-gcc.exe`
            // (`rust-mingw`'s own driver) exactly as `x86_64-pc-windows-gnu`'s
            // real-world "self-contained" linking mode does, never `rust-lld`.
            // The remaining large entries this filter also drops --
            // `rust-objcopy.exe` (20 MiB), `wasm-component-ld.exe` (7 MiB),
            // `gcc-ld/{wasm-ld,lld-link,ld64.lld}.exe` (~2.5 MiB combined),
            // `libexec/rust-analyzer-proc-macro-srv.exe` (5 MiB),
            // `share/doc/rust/COPYRIGHT*.html` (~17 MiB) -- are real files this
            // component's own consumer (`wht_corulix_engine::testing`) never
            // touches, mirroring `GNU_LINK_RUNTIME_LINUX_X64`'s own "don't
            // extract what nothing consumes" precedent. Kept: `bin/rustc.exe`,
            // `bin/rustdoc.exe`, `bin/rustc_driver-<hash>.dll` (rustc's own
            // runtime dependency), `bin/std-<hash>.dll`, `bin/libwinpthread-1.dll`,
            // `bin/libgcc_s_seh-1.dll` (the other three DLLs `bin/rustc.exe`
            // dynamically links against, confirmed via this same `tar tzvf`
            // inspection -- all four sit directly alongside `rustc.exe` in
            // `bin/`, so the Windows PE loader's default same-directory DLL
            // search resolves them with no `PATH` trick needed).
            extract_path_prefixes: &[
                "bin/rustc.exe",
                "bin/rustdoc.exe",
                "bin/rustc_driver-",
                "bin/std-",
                "bin/libwinpthread-1.dll",
                "bin/libgcc_s_seh-1.dll",
            ],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[
            ManagedArtifactSource {
                tarball_url: "https://static.rust-lang.org/dist/2026-08-20/cargo-1.98.0-x86_64-pc-windows-gnu.tar.gz",
                expected_sha256_hex: "79da7e6bb0c7ac1583b380c702477da298f2dace9ba22f41150698c516533406",
                binary_path_in_tarball: "bin/cargo.exe",
                archive_kind: ArchiveKind::TarGz,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: Some("cargo-1.98.0-x86_64-pc-windows-gnu/cargo/"),
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            ManagedArtifactSource {
                tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rust-std-1.98.0-x86_64-pc-windows-gnu.tar.gz",
                expected_sha256_hex: "47bceabaceabc4de97e20f7470d9973fb20e844986da01b3a31cf28e24596660",
                binary_path_in_tarball: "bin/rustc.exe",
                archive_kind: ArchiveKind::TarGz,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: Some(
                    "rust-std-1.98.0-x86_64-pc-windows-gnu/rust-std-x86_64-pc-windows-gnu/",
                ),
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            ManagedArtifactSource {
                tarball_url: RUST_SRC_1_98_0_URL,
                expected_sha256_hex: RUST_SRC_1_98_0_SHA256,
                binary_path_in_tarball: "bin/rustc.exe",
                archive_kind: ArchiveKind::TarGz,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: Some("rust-src-1.98.0/rust-src/"),
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            ManagedArtifactSource {
                tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rust-mingw-1.98.0-x86_64-pc-windows-gnu.tar.gz",
                expected_sha256_hex: "14fc86abb02d7d0575eb38a738161dcd87aa4032e091cce3424e78321b145e5e",
                binary_path_in_tarball: "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/x86_64-w64-mingw32-gcc.exe",
                archive_kind: ArchiveKind::TarGz,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: Some("rust-mingw-1.98.0-x86_64-pc-windows-gnu/rust-mingw/"),
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
        ],
    };

/// P18: `wht_corulix_engine::diagnostics`'s own Windows `gate.diagnostics`
/// runtime -- a distinct managed component from
/// [`RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`] (P12's `gate.tests`-only
/// runtime), even though the two share every one of their first five
/// sources' bytes/hashes.
///
/// # Why a separate component rather than reusing `..._GNU_X64` unchanged
///
/// `gate.tests` (`crate::testing` in `wht_corulix_engine`) already owns
/// [`RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`] as its
/// `TRUSTED_WORKSPACE_EXECUTION_TARGET` -- host and checked target are both
/// `x86_64-pc-windows-gnu` there, by a deliberate P12 architecture decision
/// (see that manifest's own doc comment) that this phase's own mandate
/// (§27, "do NOT alter `gate.tests` unless a shared primitive genuinely
/// requires a compatible change") forbids re-opening. `gate.diagnostics`
/// cannot adopt that same decision unchanged: unlike `gate.tests` (whose
/// only real contract is "the workspace's own test suite runs"),
/// `gate.diagnostics`'s `cargo check` is the authoritative
/// `ProviderCategory::TypecheckBuild` validator for the *canonical* Windows
/// target every other Windows provider (Corulix's own binary, managed
/// `rustfmt`, managed `rust-analyzer`) is pinned to --
/// `x86_64-pc-windows-msvc` (see [`RUST_SEMANTIC_RUNTIME_WINDOWS_X64`]'s own
/// doc comment). Silently re-targeting `gate.diagnostics` to
/// `x86_64-pc-windows-gnu` would make it stop validating the target Corulix
/// actually ships as -- a real, silent target-family drift `cargo check`'s
/// own contract (`WINDOWS_DIAGNOSTICS_TARGET_CONTRACT=PROVEN`,
/// `DIAGNOSTICS_TARGET_MUST_EQUAL_NATIVE_MSVC=YES`) forbids. This component
/// therefore keeps the *host* toolchain GNU (so `build.rs`/proc-macro
/// compilation -- always compiled for the host triple, never the `--target`
/// triple -- links through the same real, self-contained, hash-verified
/// MinGW-w64 linker [`RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`] already proved
/// out for `gate.tests`) while adding one more `additional_sources` entry:
/// the official `x86_64-pc-windows-msvc` target's own compiled `rust-std`
/// (`.rlib`/`.rmeta`) -- the exact same archive, same hash, already
/// independently verified for [`RUST_SEMANTIC_RUNTIME_WINDOWS_X64`] -- so
/// `cargo check --target x86_64-pc-windows-msvc` has a real target sysroot
/// to type/borrow/trait-check against without ever invoking a linker for
/// that target (`cargo check` never links the `--target` artifacts it
/// checks; only `build.rs`/proc macros, compiled for the *host* triple, are
/// ever linked, and that link is satisfied entirely by this component's own
/// bundled `rust-mingw` self-contained linker -- see
/// `wht_corulix_engine::diagnostics::diagnostics_link_environment`'s own doc
/// comment for the full `CARGO_TARGET_<HOST-TRIPLE>_*`-keyed environment
/// this requires, distinct from `crate::testing::link_environment`'s bare
/// `RUSTFLAGS` because here host and checked target genuinely differ).
///
/// # No Windows API import libraries, no Visual Studio, no Windows SDK
///
/// This component never resolves, requires, or references `link.exe`,
/// `kernel32.lib`, `ucrt.lib`/`msvcrt.lib`, `vcruntime.lib`, or any other
/// Visual-Studio-/Windows-SDK-supplied artifact -- the merged `rust-std`
/// target sysroot this component adds is consumed purely for
/// type/borrow/trait metadata, never linked
/// (`WINDOWS_DIAGNOSTICS_SYSTEM_LINKER_AUTHORITY=NO`).
///
/// # Distinct `ManagedComponentId`, distinct install directory
///
/// `"rust-semantic-runtime-gnu-diagnostics"`, not
/// `"rust-semantic-runtime-gnu"` -- its install directory can never collide
/// with, alias, or mutate `gate.tests`'s own
/// [`RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`] component, satisfying this
/// phase's own "one shared primitive, not a hidden second consumer of the
/// same on-disk state" requirement. Uninstalling this component removes
/// only `gate.diagnostics`'s own state; `gate.tests`'s own component and
/// lease records are untouched (`WINDOWS_DIAGNOSTICS_LINK_RUNTIME_CROSS_ROOT_ISOLATION`).
pub const RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64: ManagedComponentManifest =
    ManagedComponentManifest {
        id: ManagedComponentId("rust-semantic-runtime-gnu-diagnostics"),
        version: "1.98.0",
        platform: "windows",
        architecture: "x64",
        source: ManagedArtifactSource {
            tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rustc-1.98.0-x86_64-pc-windows-gnu.tar.gz",
            expected_sha256_hex: "c97a98af7a8c84cee611a9a8a5bba6a804f82b09899a2e451a33b5934d684542",
            binary_path_in_tarball: "bin/rustc.exe",
            archive_kind: ArchiveKind::TarGz,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[
                "bin/cargo.exe",
                "bin/rustdoc.exe",
                "lib/rustlib/src/rust/library/alloc/src/string.rs",
                "lib/rustlib/src/rust/library/std/src/lib.rs",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/crt2.o",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/dllcrt2.o",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/rsbegin.o",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/rsend.o",
                "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/x86_64-w64-mingw32-gcc.exe",
                "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/ld.exe",
                "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/dlltool.exe",
                "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/libwinpthread-1.dll",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libmingw32.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libmingwex.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libmsvcrt.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libkernel32.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libgcc.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libgcc_eh.a",
                "lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained/libpthread.a",
            ],
            required_nonempty_dirs: &[
                "lib/rustlib/x86_64-pc-windows-gnu/lib",
                "lib/rustlib/x86_64-pc-windows-msvc/lib",
            ],
            tar_root_prefix: Some("rustc-1.98.0-x86_64-pc-windows-gnu/rustc/"),
            extract_path_prefixes: &[
                "bin/rustc.exe",
                "bin/rustdoc.exe",
                "bin/rustc_driver-",
                "bin/std-",
                "bin/libwinpthread-1.dll",
                "bin/libgcc_s_seh-1.dll",
            ],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[
            ManagedArtifactSource {
                tarball_url: "https://static.rust-lang.org/dist/2026-08-20/cargo-1.98.0-x86_64-pc-windows-gnu.tar.gz",
                expected_sha256_hex: "79da7e6bb0c7ac1583b380c702477da298f2dace9ba22f41150698c516533406",
                binary_path_in_tarball: "bin/cargo.exe",
                archive_kind: ArchiveKind::TarGz,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: Some("cargo-1.98.0-x86_64-pc-windows-gnu/cargo/"),
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            ManagedArtifactSource {
                tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rust-std-1.98.0-x86_64-pc-windows-gnu.tar.gz",
                expected_sha256_hex: "47bceabaceabc4de97e20f7470d9973fb20e844986da01b3a31cf28e24596660",
                binary_path_in_tarball: "bin/rustc.exe",
                archive_kind: ArchiveKind::TarGz,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: Some(
                    "rust-std-1.98.0-x86_64-pc-windows-gnu/rust-std-x86_64-pc-windows-gnu/",
                ),
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            ManagedArtifactSource {
                tarball_url: RUST_SRC_1_98_0_URL,
                expected_sha256_hex: RUST_SRC_1_98_0_SHA256,
                binary_path_in_tarball: "bin/rustc.exe",
                archive_kind: ArchiveKind::TarGz,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: Some("rust-src-1.98.0/rust-src/"),
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            ManagedArtifactSource {
                tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rust-mingw-1.98.0-x86_64-pc-windows-gnu.tar.gz",
                expected_sha256_hex: "14fc86abb02d7d0575eb38a738161dcd87aa4032e091cce3424e78321b145e5e",
                binary_path_in_tarball: "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/x86_64-w64-mingw32-gcc.exe",
                archive_kind: ArchiveKind::TarGz,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: Some("rust-mingw-1.98.0-x86_64-pc-windows-gnu/rust-mingw/"),
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            // P18: the `x86_64-pc-windows-msvc` target's own compiled
            // `rust-std` (`.rlib`/`.rmeta`) -- the exact same archive/hash
            // already independently verified for
            // `RUST_SEMANTIC_RUNTIME_WINDOWS_X64` (P17-W-R4-C2's own
            // research gate). Merged onto this GNU-hosted component's own
            // `lib/rustlib/x86_64-pc-windows-msvc/` prefix -- the identical
            // on-disk layout `rustup target add x86_64-pc-windows-msvc`
            // itself would produce against any host toolchain of the same
            // version, since a target's compiled `rust-std` artifacts are
            // host-independent (confirmed against the official rustup
            // book's own cross-compilation model: `rustup target add`
            // merges a target's `rust-std` into whatever host toolchain's
            // sysroot is active, regardless of that host's own ABI).
            // Consumed only for `cargo check --target x86_64-pc-windows-msvc`
            // type/borrow/trait metadata -- never linked, so no Windows API
            // import libraries are required for this source.
            ManagedArtifactSource {
                tarball_url: "https://static.rust-lang.org/dist/2026-08-20/rust-std-1.98.0-x86_64-pc-windows-msvc.tar.gz",
                expected_sha256_hex: "e8810c2e914a1f557d8e3760653843afdbcba188714d9c5b7247f53bb049b592",
                binary_path_in_tarball: "bin/rustc.exe",
                archive_kind: ArchiveKind::TarGz,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: Some(
                    "rust-std-1.98.0-x86_64-pc-windows-msvc/rust-std-x86_64-pc-windows-msvc/",
                ),
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
        ],
    };
