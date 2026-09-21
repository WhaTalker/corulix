// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Pinned `CORULIX_MANAGED` component manifests for this crate's providers
//! (Phase 7B-A). Every field here is a compile-time constant this crate
//! itself pins -- never a "latest" resolution performed at provisioning
//! time, never derived from workspace input.
//!
//! Scope note: TypeScript 7 native, the managed Rust semantic runtime,
//! rust-analyzer, Pyright, the Go semantic runtime archive (Phase
//! 7B-B2-A-R1), and (as of Phase 7B-B2-A-R3A) `gopls` itself all have
//! admitted manifests here. [`GOPLS_LINUX_X64`]'s `tarball_url` names this
//! repository's own intended, not-yet-existing, durable release-asset
//! location -- see that constant's own doc comment for why an unreachable
//! URL does not block admitting the component's identity. Python's
//! *provider* resolution otherwise remains through the existing
//! `wht_corulix_config::resolve_provider` `HOST_ONLY`/system precedence
//! (`managed_component: None` on the still-unmigrated profiles) until a
//! later pass wires that remaining managed manifest to its own provider
//! profile.

use wht_corulix_tooling::provisioning::{
    ArchiveKind, GoModuleBuildSource, ManagedArtifactSource, ManagedComponentId,
    ManagedComponentManifest, SymlinkPolicy,
};

/// Relocated to `wht_corulix_tooling::managed_runtimes` during Phase
/// 7B-B2-B, once managed `rustfmt` (`wht_corulix_formatter::managed_toolchain`)
/// made this runtime a genuinely cross-crate-boundary shared artifact, not
/// an LSP-only one -- see that module's own doc comment for the full
/// rationale and evidence. Re-exported here unchanged so every existing
/// `wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64`
/// call site keeps compiling with no source change.
pub use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64;
/// Windows counterpart of the re-export immediately above -- same
/// rationale, added P17-W-R4-C2.
pub use wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64;

/// `@typescript/typescript-linux-x64@7.0.2`, the real native platform
/// artifact for TypeScript 7's native LSP on `linux`/`x64`. `expected_sha256_hex`
/// is this exact tarball's real SHA-256, computed independently both via
/// this workspace's own `wht_corulix_core::ContentHash::compute_sha256`
/// and cross-checked against the npm registry's own published `dist.shasum`/
/// `dist.integrity` metadata for this exact version during this phase's
/// research gate.
pub const TYPESCRIPT_7_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("typescript-7-native"),
    version: "7.0.2",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://registry.npmjs.org/@typescript/typescript-linux-x64/-/typescript-linux-x64-7.0.2.tgz",
        expected_sha256_hex: "7ecad6f67377e831856367ab062ef394f21506a611405bf8ac0ff039348637d3",
        binary_path_in_tarball: "package/lib/tsc",
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

/// P17-W Stage C: the Windows counterpart of [`TYPESCRIPT_7_LINUX_X64`] --
/// the real official `@typescript/typescript-win32-x64@7.0.2` platform
/// package, confirmed as the genuine Windows sibling by reading the parent
/// `typescript@7.0.2` package's own `optionalDependencies` map (not
/// guessed/pattern-matched from the Linux package name), which lists
/// `@typescript/typescript-win32-x64: "7.0.2"` alongside every other
/// upstream-published platform package for this exact release. Digest
/// independently computed via `sha256sum` against the real downloaded
/// tarball (`61fc4e141d2bc687db580e71bbfa63b9c209f0310645d82ca1b457eb3a24fd19`)
/// and cross-checked against BOTH of npm's own published integrity fields
/// for this exact version -- `dist.shasum` (SHA-1,
/// `cf3b7b0d6ce5635daca4c8e01c189cdcde47ec3c`, reproduced via `sha1sum`) and
/// `dist.integrity` (SHA-512, `sha512-0BQ3HkAHHlKLSp1qRvf3SUhGpGsDuhB/
/// jgFw75guyqbxJqEaS0Cw/VFO8i2nHglJUzQCRtMMR/IBAKE3ETMC4g==`, reproduced via
/// `openssl dgst -sha512 -binary | base64`) -- both matched exactly. The
/// same cross-check method, run against a fresh re-download of
/// [`TYPESCRIPT_7_LINUX_X64`]'s own tarball, reproduced that constant's
/// already-pinned digest byte-for-byte, validating the method itself before
/// trusting this constant's result.
///
/// Real `tar tzf`/`tar tvzf` inspection of the downloaded archive (not
/// assumed from the Linux layout) confirms: a genuine gzip-compressed tar
/// container (`ArchiveKind::TarGz`, NOT a `.zip` the way
/// [`RUST_ANALYZER_WINDOWS_X64`]'s upstream ships -- TypeScript's own
/// release pipeline packages every platform, Windows included, as `.tgz`),
/// zero symlink entries, and the native binary at `package/lib/tsc.exe`
/// (the Linux path with a `.exe` suffix, mirroring
/// [`RUST_ANALYZER_WINDOWS_X64`]'s own established precedent of carrying
/// the platform suffix directly in `binary_path_in_tarball` rather than
/// appending it at provisioning time). `extract_path_prefixes: &[]` (same
/// as the Linux manifest) extracts the full `package/lib/` tree unfiltered,
/// so every `lib.*.d.ts` standard-library declaration file `tsc.exe` needs
/// alongside itself lands next to it exactly as it does for the Linux
/// artifact -- confirmed real, not merely a plausible extraction-logic
/// inference, by this phase's own real Windows LSP cycle in the existing
/// `real_typescript_7_native_e2e.rs::real_typescript_7_full_vertical_e2e`
/// (extended this same pass with a `Promise`/`Array.prototype.at`
/// reference in its fixture -- both declared only in `lib.es2015.promise.
/// d.ts`/`lib.es2022.array.d.ts`, never the language itself -- and a
/// tightened diagnostics assertion requiring a genuinely EMPTY result, not
/// merely "not NotReady") run natively on both platforms: a missing lib
/// tree would have produced a real, non-empty `Cannot find name 'Promise'`
/// diagnostic instead of the proven-empty result both platforms returned.
///
/// `TYPESCRIPT_7_NODE_RUNTIME_REQUIRED=NO` on Windows too: `tsc.exe` is
/// statically linked (same Go-compiled `typescript-go` binary family as
/// the Linux artifact; the parent `typescript` package's `engines.node`
/// field is npm install-context metadata, not a runtime dependency of the
/// compiled binary). No dedicated scrubbed-`PATH` probe was run against
/// this Windows artifact specifically (unlike [`RUST_ANALYZER_WINDOWS_X64`]'s
/// own such probe, noted above); the evidence here is structural plus the
/// same real native test run: this profile's `interpreter`/
/// `managed_interpreter` are both `None` and `auxiliary_tools` is empty, so
/// [`crate::profile::resolve_launch`] adds nothing Node-shaped to the resolved `PATH` on
/// either platform, and `real_typescript_7_full_vertical_e2e`/
/// `real_javascript_7_full_vertical_e2e`/`ata_never_resolves_npm_even_for_
/// an_inferred_project_requiring_a_missing_package` all pass natively on
/// Windows against that unmodified environment -- `managed_interpreter:
/// None` on [`crate::profile::LspProviderProfile::typescript_7_native`] is
/// therefore correct unchanged for both platforms, no Windows-specific
/// Node dependency thread was needed.
pub const TYPESCRIPT_7_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("typescript-7-native"),
    version: "7.0.2",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://registry.npmjs.org/@typescript/typescript-win32-x64/-/typescript-win32-x64-7.0.2.tgz",
        expected_sha256_hex: "61fc4e141d2bc687db580e71bbfa63b9c209f0310645d82ca1b457eb3a24fd19",
        binary_path_in_tarball: "package/lib/tsc.exe",
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

/// This host's own real `typescript-7-native` manifest -- mirrors
/// [`RUST_ANALYZER_HOST_NATIVE`]'s own `#[cfg]`-gated-alias pattern exactly,
/// closing the identical hardcoded-to-Linux defect
/// [`crate::profile::LspProviderProfile::typescript_7_native`] had for its
/// `managed_component` field (it named [`TYPESCRIPT_7_LINUX_X64`]
/// unconditionally regardless of host, found during this phase's own audit
/// of every existing `TYPESCRIPT_7_*` call site before adding the Windows
/// manifest above). `pub` (not `pub(crate)`, unlike [`RUST_ANALYZER_HOST_NATIVE`]/
/// [`RUST_SEMANTIC_RUNTIME_HOST_NATIVE`]) -- mirrors [`GOPLS_HOST_NATIVE`]'s
/// own visibility, because this phase's own audit found six external
/// integration-test files under `wht_corulix_lsp/tests/` (separate crate
/// compilation units) hardcoding `TYPESCRIPT_7_LINUX_X64` directly for real
/// provisioning calls -- the exact same defect class the P17-W-R7 pass
/// found and fixed for `GO_SEMANTIC_RUNTIME_HOST_NATIVE`/`GOPLS_HOST_NATIVE`
/// call sites, and which would fail closed with
/// `PlatformArchitectureMismatch` (not silently pass) if run natively on
/// Windows unfixed.
#[cfg(target_os = "windows")]
pub const TYPESCRIPT_7_HOST_NATIVE: ManagedComponentManifest = TYPESCRIPT_7_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const TYPESCRIPT_7_HOST_NATIVE: ManagedComponentManifest = TYPESCRIPT_7_LINUX_X64;

/// Official rust-analyzer release `2026-08-24`,
/// `rust-analyzer-x86_64-unknown-linux-gnu.gz` -- a bare gzip-compressed
/// executable (`ArchiveKind::GzippedBinary`; unlike TypeScript 7's/Node's
/// artifacts, this upstream ships no tar container at all, confirmed by a
/// real `file`/download probe during this phase's research gate). Pinned
/// to this exact dated GitHub release tag, never the repository's
/// `releases/latest` redirect.
///
/// **Provisioning only, not full semantic self-containment.** A real,
/// hostile-PATH probe against this exact binary (scrubbed `PATH`, no
/// `cargo`/`rustc`/`rustup` resolvable) proved `initialize` still responds,
/// but workspace/project-model loading fails outright:
/// `failed fetching cargo workspace root e=... "cargo" "locate-project" ...
/// failed` -- rust-analyzer shells out to a real `cargo`/`rustc` toolchain
/// to build its crate graph and resolve `std`, and has no fallback when
/// neither is resolvable. `RUST_ANALYZER_EXTERNAL_TOOLCHAIN_REQUIREMENTS=
/// [cargo, rustc, sysroot]`, `RUST_SEMANTIC_RUNTIME_SELF_CONTAINED=NO`.
/// Provisioning/uninstalling this binary through the same managed pipeline
/// as every other component is still real and independently useful (it
/// removes the *download/verification/lifecycle* dependency on a
/// pre-existing rust-analyzer install even where a system Rust toolchain
/// is separately present), but a full, self-contained managed Rust LSP
/// vertical additionally requires Corulix to manage a Rust semantic
/// runtime (rustc + sysroot + std, at minimum) -- out of scope for this
/// pass; see `CHANGELOG.md`'s Phase 7B-B1 entry.
pub const RUST_ANALYZER_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("rust-analyzer"),
    version: "2026-08-24",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-24/rust-analyzer-x86_64-unknown-linux-gnu.gz",
        expected_sha256_hex: "c4d409690b98d84ce98174829362a59214825d72304fe2504f4b906a116b51fe",
        binary_path_in_tarball: "rust-analyzer",
        archive_kind: ArchiveKind::GzippedBinary,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &[],
        required_nonempty_dirs: &[],
        tar_root_prefix: None,
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// P17-W-R4-C2: the Windows counterpart of [`RUST_ANALYZER_LINUX_X64`],
/// same dated GitHub release tag (`2026-08-24`) -- but a genuinely
/// different archive format, confirmed via the real GitHub Releases API
/// (`api.github.com/repos/rust-lang/rust-analyzer/releases/tags/2026-08-24`)
/// during this phase's research gate: unlike every Unix target (bare
/// `.gz`, no container), every Windows target
/// (`x86_64-pc-windows-msvc`/`i686-pc-windows-msvc`/`aarch64-pc-windows-msvc`)
/// ships as a real PKZIP archive (`.zip`) containing exactly two entries,
/// `rust-analyzer.exe` and a `.pdb` debug-symbol file, both Deflate-
/// compressed (method `8`) -- confirmed via a real `unzip -l`/Python
/// `zipfile` inspection of the independently re-downloaded asset, not
/// assumed. `rust-analyzer`'s own upstream release process is therefore a
/// *second*, independent real consumer of [`ArchiveKind::Zip`] (the first
/// being [`wht_corulix_tooling::managed_runtimes::NODE_24_LTS_WINDOWS_X64`]) --
/// further confirmation this is a genuinely shared, central archive format
/// on Windows rather than a single-artifact special case.
///
/// Digest independently computed via `sha256sum` against the real
/// downloaded asset (GitHub Releases publishes no separate checksum file
/// for this repository's assets, unlike `nodejs.org`'s `SHASUMS256.txt` --
/// confirmed by probing for the conventional `.sha256`/`.sha256sum`
/// sibling asset names and finding none, so the archive's own bytes are
/// this manifest's sole integrity source, exactly as
/// [`RUST_ANALYZER_LINUX_X64`]'s own digest already is).
///
/// Same external-toolchain caveat as [`RUST_ANALYZER_LINUX_X64`]:
/// `RUST_ANALYZER_EXTERNAL_TOOLCHAIN_REQUIREMENTS=[cargo, rustc, sysroot]`
/// -- real semantic capability additionally requires
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64`]
/// and, transitively, that runtime's own P12 Windows-linking blocker (see
/// that manifest's doc comment) -- provisioning/uninstalling this binary
/// through the same managed pipeline as every other component is still
/// real and independently useful on its own.
pub const RUST_ANALYZER_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("rust-analyzer"),
    version: "2026-08-24",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-24/rust-analyzer-x86_64-pc-windows-msvc.zip",
        expected_sha256_hex: "f6d80045e6f475606f62d294fa3b618304fd24d2ff86160495440f23d5f7fcdb",
        binary_path_in_tarball: "rust-analyzer.exe",
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

/// This host's own real rust-analyzer manifest -- mirrors
/// `wht_corulix_formatter::managed_toolchain::RUSTFMT_HOST_NATIVE`'s own
/// `#[cfg]`-gated-alias pattern exactly: a build for the "wrong" platform
/// cannot even compile a path that resolves the other platform's manifest,
/// unlike a runtime `if cfg!(...)` branch. Added P17-W-R4-C2 so
/// [`LspProviderProfile::rust_analyzer_managed`] stops hardcoding
/// [`RUST_ANALYZER_LINUX_X64`] regardless of host -- the same
/// hardcoded-to-Linux defect class `RUSTFMT_HOST_NATIVE` was introduced to
/// close for managed `rustfmt`.
#[cfg(target_os = "windows")]
pub(crate) const RUST_ANALYZER_HOST_NATIVE: ManagedComponentManifest = RUST_ANALYZER_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub(crate) const RUST_ANALYZER_HOST_NATIVE: ManagedComponentManifest = RUST_ANALYZER_LINUX_X64;

/// This host's own real `rust-semantic-runtime` manifest, re-exported here
/// under this crate's own naming convention (this crate's copy of
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64`]/
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64`]'s
/// own cross-crate-shared identity) -- same rationale as
/// [`RUST_ANALYZER_HOST_NATIVE`] immediately above, closing the identical
/// hardcoded-to-Linux defect [`LspProviderProfile::rust_analyzer_managed`]
/// previously had for its `managed_rust_semantic_runtime` field.
#[cfg(target_os = "windows")]
pub(crate) const RUST_SEMANTIC_RUNTIME_HOST_NATIVE: ManagedComponentManifest =
    wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub(crate) const RUST_SEMANTIC_RUNTIME_HOST_NATIVE: ManagedComponentManifest =
    wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64;

/// `pyright@1.1.413`, admitted for managed provisioning this phase.
/// `npm view pyright dependencies` shows exactly one dependency,
/// `fsevents` (a macOS-only optional native watcher, gated by npm's own
/// `os` field so it never installs on Linux) -- confirmed by directly
/// extracting the published tarball and finding zero symlink entries and a
/// fully webpack-bundled `dist/` (`pyright-langserver.js`/
/// `pyright-internal.js`/`vendor.js`, plus the bundled `typeshed-fallback`
/// stub tree). A real, hostile-PATH probe (`node dist/pyright-langserver.js
/// --stdio`, scrubbed `PATH`, no sibling `node_modules`) proved the server
/// starts and logs normally with no module-resolution failure --
/// `PYRIGHT_RUNTIME_COMPONENTS=[node-runtime, pyright]`, no further
/// dependency-closure provisioning is required.
pub const PYRIGHT_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("pyright"),
    version: "1.1.413",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://registry.npmjs.org/pyright/-/pyright-1.1.413.tgz",
        expected_sha256_hex: "7322a75188e788f9fe7cbb71891af435a713bf8985141dc0d28e8ca243977bee",
        binary_path_in_tarball: "package/dist/pyright-langserver.js",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        // `package/index.js` + `package/dist/pyright.js` (M03 Python
        // managed-auxiliary final closure, TypecheckBuild): the real
        // `pyright@1.1.413` `package.json`'s own `bin` map
        // (`"pyright": "index.js"`, distinct from
        // `"pyright-langserver": "langserver.index.js"`) confirms a genuine
        // CLI entrypoint bundled alongside the langserver one. `index.js` is
        // the real, required invocation entrypoint -- **not** `dist/pyright.js`
        // directly: `index.js` sets `global.__rootDirectory = __dirname +
        // '/dist/'` before `require('./dist/pyright')`, and this was
        // empirically proven load-bearing (spawning `node dist/pyright.js`
        // directly against a trivial one-file fixture produced 1128 spurious
        // "import could not be resolved" errors -- pyright's own bundled
        // typeshed-stub resolution depends on that global; spawning
        // `node index.js` against the identical fixture produced the correct
        // `errorCount: 0`). `dist/pyright.js` is kept as a required path too
        // since `index.js` itself requires it. Adding both here only
        // tightens *future* fresh-provision layout verification
        // (`required_paths` is checked once, at provisioning time -- see
        // `provisioning::provision_with_dependencies`'s own doc comment --
        // never re-checked against an already-`Available` install, so this
        // cannot invalidate the pre-existing `pyright` ownership record on
        // this host).
        required_paths: &[
            "package/dist/pyright-internal.js",
            "package/dist/vendor.js",
            "package/dist/pyright.js",
            "package/index.js",
        ],
        required_nonempty_dirs: &[],
        tar_root_prefix: None,
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// P17-W: the Windows counterpart of [`PYRIGHT_LINUX_X64`]. Confirmed, not
/// assumed, to be the exact same artifact: the real npm registry metadata
/// for `pyright@1.1.413` (`GET https://registry.npmjs.org/pyright/1.1.413`)
/// carries no `os`/`cpu` fields, only the same macOS-only, npm-`os`-gated
/// `fsevents` dependency/optionalDependency already documented on
/// [`PYRIGHT_LINUX_X64`] -- `pyright@1.1.413` is plain, fully
/// webpack-bundled JavaScript (`dist/pyright-langserver.js`/
/// `dist/pyright-internal.js`/`dist/vendor.js`), loaded by the managed
/// Node interpreter rather than spawned as a native executable, so one
/// universal tarball serves every OS exactly as
/// [`TYPESCRIPT_6_WINDOWS_X64`] does for `typescript@6.0.3`.
/// `tarball_url`/`expected_sha256_hex`/`binary_path_in_tarball`/
/// `required_paths` are therefore byte-for-byte identical to
/// [`PYRIGHT_LINUX_X64`]'s own -- independently re-verified this phase via
/// a fresh `curl` download and `sha256sum` against the live tarball, only
/// `platform` differs.
pub const PYRIGHT_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("pyright"),
    version: "1.1.413",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://registry.npmjs.org/pyright/-/pyright-1.1.413.tgz",
        expected_sha256_hex: "7322a75188e788f9fe7cbb71891af435a713bf8985141dc0d28e8ca243977bee",
        binary_path_in_tarball: "package/dist/pyright-langserver.js",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        // See [`PYRIGHT_LINUX_X64`]'s own doc comment for why
        // `package/dist/pyright.js`/`package/index.js` were added here (M03
        // Python managed-auxiliary final closure).
        required_paths: &[
            "package/dist/pyright-internal.js",
            "package/dist/vendor.js",
            "package/dist/pyright.js",
            "package/index.js",
        ],
        required_nonempty_dirs: &[],
        tar_root_prefix: None,
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// This host's own real `pyright` manifest -- mirrors
/// [`TYPESCRIPT_6_HOST_NATIVE`]'s own `#[cfg]`-gated-alias pattern, closing
/// the identical hardcoded-to-Linux defect
/// [`crate::profile::LspProviderProfile::pyright_managed`] had for its
/// `managed_component` field before this pass. `pub` because Pyright's own
/// managed E2E test files (`real_pyright_managed_e2e.rs` and siblings)
/// reference it directly from outside this crate.
#[cfg(target_os = "windows")]
pub const PYRIGHT_HOST_NATIVE: ManagedComponentManifest = PYRIGHT_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const PYRIGHT_HOST_NATIVE: ManagedComponentManifest = PYRIGHT_LINUX_X64;

/// The managed Go semantic runtime backing a future managed `gopls`
/// provider (Phase 7B-B2-A-R1's supply-chain foundation pass). Real
/// official Go distribution artifact, resolved from `go.dev/dl/?mode=json`
/// (the Go team's own machine-readable release index) during this pass's
/// upstream-research gate -- `GO_UPSTREAM_DISTRIBUTION_MODEL=
/// OFFICIAL_PREBUILT_ARCHIVE`, the same admission model already used for
/// [`RUST_SEMANTIC_RUNTIME_LINUX_X64`]'s `static.rust-lang.org` artifacts
/// and [`TYPESCRIPT_7_LINUX_X64`]/[`PYRIGHT_LINUX_X64`]'s npm registry
/// tarballs.
///
/// `expected_sha256_hex` and `source.tarball_url` were independently
/// verified against the same `go.dev/dl/?mode=json` index this pass
/// re-fetched live (not copied from any candidate version named in a
/// mandate) and against a real downloaded-and-hashed copy of the archive
/// (`sha256sum` on the actual bytes, matching the published digest exactly)
/// during this pass's own certification run.
///
/// `required_paths` and `required_nonempty_dirs` were derived from a real
/// extraction of this exact archive: `bin/go` and `bin/gofmt` are the two
/// executables the archive ships; `VERSION` is the plain-text file the Go
/// toolchain itself reads to self-report its version
/// (`go1.27.0\ntime ...`); `src/runtime/runtime.go` proves the full
/// standard-library *source* tree extracted (not just compiled packages --
/// modern Go archives ship no precompiled `pkg/<os>_<arch>/std` tree at
/// all; the toolchain compiles `std` into its build cache on first use).
/// The stdlib source tree is required for the same reason `rust-src` is
/// required for [`RUST_SEMANTIC_RUNTIME_LINUX_X64`]: `gopls`/`go/packages`
/// resolve stdlib symbol definitions to real upstream source, not merely
/// compiled interfaces.
///
/// **Supply-chain foundation only, not yet a wired managed provider.** This
/// manifest is admitted so a later pass can provision/own/uninstall a real
/// Go runtime through the existing `CORULIX_MANAGED` pipeline exactly like
/// every other component in this file -- `resolve_launch`, `GOROOT`
/// resolution, and any `gopls` provider profile routing to it are
/// deliberately **not** implemented by this constant alone
/// (`ZERO_PRODUCT_BEHAVIOR_CHANGE=YES` for this pass; see `CHANGELOG.md`'s
/// Phase 7B-B2-A-R1 entry). The existing `HOST_ONLY`
/// `LspProviderProfile::gopls()` is untouched and remains the only gopls
/// integration Corulix actually routes to today.
/// Moved to `wht_corulix_tooling::managed_runtimes` (M03 rename_preview
/// managed auxiliary capability closure): `wht_corulix_formatter` now also
/// needs this runtime's `bin/gofmt` for managed-first `gofmt` resolution,
/// making it a genuinely shared runtime rather than a single-consumer
/// `gopls` dependency -- see that module's own doc comment. Re-exported here
/// so no existing call site (including `wht_corulix_engine::go_providers`)
/// changed.
pub use wht_corulix_tooling::managed_runtimes::GO_SEMANTIC_RUNTIME_LINUX_X64;

/// This host's own real `go-semantic-runtime` manifest -- same
/// `#[cfg]`-gated-alias pattern as [`RUST_ANALYZER_HOST_NATIVE`]/
/// [`RUST_SEMANTIC_RUNTIME_HOST_NATIVE`]/[`GOPLS_HOST_NATIVE`]. Added during
/// the Windows-native gopls verification pass after that pass's own real
/// native-Windows test run empirically proved the gap this alias closes:
/// `real_gopls_module_build_lifecycle_e2e.rs` originally referenced
/// [`GO_SEMANTIC_RUNTIME_LINUX_X64`] directly (unconditionally, with no
/// platform selection), which `provisioning::provision` correctly rejected
/// fail-closed with a real `PlatformArchitectureMismatch` error when run on
/// this real Windows host -- not a defect in the fail-closed provisioning
/// path itself, but a missing host-native indirection at the call site.
#[cfg(target_os = "windows")]
pub const GO_SEMANTIC_RUNTIME_HOST_NATIVE: ManagedComponentManifest =
    GO_SEMANTIC_RUNTIME_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const GO_SEMANTIC_RUNTIME_HOST_NATIVE: ManagedComponentManifest = GO_SEMANTIC_RUNTIME_LINUX_X64;

/// P17-W-R4-C3: the Windows counterpart of [`GO_SEMANTIC_RUNTIME_LINUX_X64`]
/// -- the same real, official `go.dev/dl/?mode=json` distribution index
/// (`GO_UPSTREAM_DISTRIBUTION_MODEL=OFFICIAL_PREBUILT_ARCHIVE`), same
/// version (`1.27.0`, `RUST_VERSION_COMPATIBILITY`-style parity with the
/// Linux manifest), fetched fresh and independently re-hashed against a
/// real, separately downloaded copy of the archive during this phase's own
/// research gate (`sha256sum` byte-for-byte match against the published
/// digest, not copied from the JSON index alone).
///
/// # Real layout differences from the Linux manifest (verified via a real
/// `zipfile.ZipFile.namelist()` inspection of the independently
/// re-downloaded archive, not assumed)
///
/// - A real PKZIP archive (`ArchiveKind::Zip`), not a `.tar.gz` -- the same
///   archive format [`RUST_ANALYZER_WINDOWS_X64`] and
///   [`wht_corulix_tooling::managed_runtimes::NODE_24_LTS_WINDOWS_X64`]
///   already admitted, a third independent real consumer.
/// - Every executable carries a `.exe` suffix (`go/bin/go.exe`,
///   `go/bin/gofmt.exe`); the platform-specific prebuilt-tool directory is
///   `go/pkg/tool/windows_amd64/` rather than Linux's `pkg/tool/linux_amd64/`
///   (only `pkg/tool` itself, not the platform-suffixed leaf, is asserted
///   as a `required_nonempty_dirs` entry, matching the Linux manifest's own
///   choice not to hardcode the leaf directory name).
/// - `tar_root_prefix` is unchanged (`"go/"`) -- the archive's own top-level
///   directory name does not vary by platform.
/// - `go/src/runtime/runtime.go` (the stdlib-source-tree proof
///   [`GO_SEMANTIC_RUNTIME_LINUX_X64`]'s own doc comment explains) is
///   present identically; Go's standard library source is not
///   platform-specific packaging, only the compiled toolchain binaries are.
///
/// **Update (P17-W Stage A):** `wht_corulix_engine::go_providers`'s own `go
/// build`/`go vet`/`go test` routing (P15) is now wired to this manifest
/// (via its own `managed_go_runtime_manifest`, an inline
/// `#[cfg(target_os = "windows")]` selector mirroring this crate's
/// `GO_SEMANTIC_RUNTIME_HOST_NATIVE` alias) as tier 1 of a two-tier
/// `CORULIX_MANAGED`-then-`HOST_ONLY` precedence -- see that module's own
/// doc comment for the full rationale. The paragraph below is retained for
/// historical context; the specific "does not yet resolve either
/// platform's managed Go runtime at all" claim it made is superseded.
///
/// **Supply-chain foundation only, not yet a wired managed provider on
/// Windows** (superseded, see above) -- same disclosed scope limit as the
/// Linux manifest's own doc comment: `resolve_launch`/`GOROOT` resolution/
/// any Go provider-profile routing on Windows is deliberately not
/// implemented by this constant alone.
/// Moved to `wht_corulix_tooling::managed_runtimes` alongside
/// [`GO_SEMANTIC_RUNTIME_LINUX_X64`] -- see that constant's own doc comment.
pub use wht_corulix_tooling::managed_runtimes::GO_SEMANTIC_RUNTIME_WINDOWS_X64;

/// `gopls@v0.23.0`, linux/x64.
///
/// # P17-W distribution-model migration (supersedes R1/R3/R3A)
///
/// Phases 7B-B2-A-R1/R3/R3A admitted this component under the same
/// pinned-URL-plus-hash *download* model every other manifest in this file
/// uses (see this file's own git history for that superseded shape), on the
/// theory that Corulix would eventually publish its own GitHub-Release
/// mirror of an out-of-band-built `gopls` binary at
/// `tarball_url`. The owner explicitly rejected that plan during P17-W:
/// `gopls` has no real official prebuilt-binary distribution at all -- its
/// only genuine upstream distribution model is `go install
/// golang.org/x/tools/gopls@<version>`, a real Go-module *source* build,
/// exactly like `go install`ing any other Go tool. Publishing a
/// Corulix-authored, out-of-band-built binary mirror would have made
/// Corulix itself the unaudited supply-chain origin of every `gopls` binary
/// it ever runs, instead of the real upstream Go module system (`GOSUMDB`
/// checksum-database verification against the real `golang.org/x/tools`
/// module) proving that origin. This manifest therefore now names identity
/// only (`id`/`version`/`platform`/`architecture`, plus
/// `source.binary_path_in_tarball`, which still names the real final
/// installed binary's relative path -- `component_install_dir`/
/// `resolve_managed_component`/`resolve_owned_managed_component`, and every
/// `LspProviderProfile::gopls_managed` call site, all resolve identically
/// regardless of which provisioning primitive produced that path).
/// `source.tarball_url`/`expected_sha256_hex`/`archive_kind` are **inert**
/// for this component -- sentinel values only, never fed to
/// [`wht_corulix_tooling::provisioning::provision`]/`provision_with_dependencies`
/// for this id. Real provisioning goes through
/// [`wht_corulix_tooling::provisioning::provision_go_module_build`] with
/// [`GOPLS_BUILD_SOURCE_LINUX_X64`] and [`GO_SEMANTIC_RUNTIME_LINUX_X64`] (as
/// the build-time compiler) -- see that function's own doc comment for the
/// full isolation/integrity contract (`GOSUMDB=sum.golang.org` real
/// checksum-database verification, isolated `GOBIN`/`GOMODCACHE`/`GOCACHE`,
/// no ambient `PATH`, `GOTOOLCHAIN=local`/`GOVCS=off`/`GOENV=off`).
///
/// The `v0.23.0` version and `platform`/`architecture`/`id` identity are
/// unchanged from R1/R3A -- only the acquisition mechanism migrated, not
/// which real component this manifest names.
pub const GOPLS_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("gopls"),
    version: "v0.23.0",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        // Inert for this component -- see the doc comment above. Never
        // passed to the download-based `provision`/`provision_with_dependencies`
        // pipeline for this id.
        tarball_url: "unused:go-module-build-see-GOPLS_BUILD_SOURCE_LINUX_X64",
        expected_sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        binary_path_in_tarball: "gopls",
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

/// Windows counterpart of [`GOPLS_LINUX_X64`] -- same real module identity
/// (`golang.org/x/tools/gopls@v0.23.0`), same P17-W source-build migration
/// rationale. `source.binary_path_in_tarball` is `"gopls.exe"`: the Go
/// toolchain itself appends `.exe` to `GOBIN` output on `GOOS=windows`, not a
/// Corulix naming choice -- `provision_go_module_build_blocking` looks up
/// exactly this name inside its build's own `GOBIN` after a successful
/// `go install`.
pub const GOPLS_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("gopls"),
    version: "v0.23.0",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "unused:go-module-build-see-GOPLS_BUILD_SOURCE_WINDOWS_X64",
        expected_sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        binary_path_in_tarball: "gopls.exe",
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

/// This host's own real `gopls` manifest -- same `#[cfg]`-gated-alias
/// pattern as [`RUST_ANALYZER_HOST_NATIVE`]/[`RUST_SEMANTIC_RUNTIME_HOST_NATIVE`].
#[cfg(target_os = "windows")]
pub const GOPLS_HOST_NATIVE: ManagedComponentManifest = GOPLS_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const GOPLS_HOST_NATIVE: ManagedComponentManifest = GOPLS_LINUX_X64;

/// The real, pinned Go-module build recipe [`GOPLS_LINUX_X64`] resolves
/// through. `module_path`/`module_version` together form the exact
/// `go install golang.org/x/tools/gopls@v0.23.0` target -- the real,
/// official upstream distribution model for this tool (there is no other:
/// `gopls` ships no prebuilt release binary at all, confirmed against the
/// real `golang.org/x/tools` repository's own release process during this
/// phase's research gate). Identical for both platforms: Go module source is
/// not platform-specific, only the compiled output is (Windows gets a
/// `.exe` suffix from the toolchain itself, not from a different module
/// target).
pub const GOPLS_BUILD_SOURCE_LINUX_X64: GoModuleBuildSource = GoModuleBuildSource {
    module_path: "golang.org/x/tools/gopls",
    module_version: "v0.23.0",
};

/// Windows counterpart of [`GOPLS_BUILD_SOURCE_LINUX_X64`] -- same real
/// module identity, paired with [`GOPLS_WINDOWS_X64`] instead.
pub const GOPLS_BUILD_SOURCE_WINDOWS_X64: GoModuleBuildSource = GoModuleBuildSource {
    module_path: "golang.org/x/tools/gopls",
    module_version: "v0.23.0",
};

/// This host's own real `gopls` build-source recipe -- same `#[cfg]`-gated-alias
/// pattern as [`GOPLS_HOST_NATIVE`].
#[cfg(target_os = "windows")]
pub const GOPLS_BUILD_SOURCE_HOST_NATIVE: GoModuleBuildSource = GOPLS_BUILD_SOURCE_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const GOPLS_BUILD_SOURCE_HOST_NATIVE: GoModuleBuildSource = GOPLS_BUILD_SOURCE_LINUX_X64;

/// `typescript-language-server@6.0.0`, admitted this phase (7B-C) as the
/// managed TypeScript-6/JavaScript-6 compatibility backend's own primary
/// component. Real npm tarball, extracted and inspected directly during
/// this phase's research gate: `package.json` declares zero dependencies
/// (a single webpack-bundled `lib/cli.mjs`, `bin: {"typescript-language-server":
/// "lib/cli.mjs"}`), and the extracted tree contains zero symlink entries.
/// `expected_sha256_hex` is this exact tarball's own real SHA-256
/// (`sha256sum` on the downloaded bytes), not copied from any npm
/// `dist.shasum` (which is a SHA-1, a different digest algorithm).
///
/// This component's own `tsserver.path` is never left to its default
/// resolution (workspace `node_modules/typescript`, then a bundled
/// fallback it does not actually ship) -- `wht_corulix_lsp::profile::resolve_launch_at`
/// resolves [`TYPESCRIPT_6_LINUX_X64`] first and injects its `lib/tsserver.js`
/// as `initializationOptions.tsserver.path`, which this phase's own research
/// (extracting and reading `lib/cli.mjs`'s real `findTypescriptVersion`
/// implementation) proved is checked *before* any workspace/bundled
/// resolution -- see [`LspProviderProfile::typescript_language_server_managed`](crate::profile::LspProviderProfile::typescript_language_server_managed).
pub const TYPESCRIPT_LANGUAGE_SERVER_LINUX_X64: ManagedComponentManifest =
    ManagedComponentManifest {
        id: ManagedComponentId("typescript-language-server"),
        version: "6.0.0",
        platform: "linux",
        architecture: "x64",
        source: ManagedArtifactSource {
            tarball_url: "https://registry.npmjs.org/typescript-language-server/-/typescript-language-server-6.0.0.tgz",
            expected_sha256_hex: "6e23b48efc76af4e70928cdfe62ea6e6cfef67ab4c1e7579c4e82dd284fbdfd2",
            binary_path_in_tarball: "package/lib/cli.mjs",
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

/// P17-W Stage D: the Windows counterpart of
/// [`TYPESCRIPT_LANGUAGE_SERVER_LINUX_X64`]. Confirmed, not assumed, to be
/// the exact same artifact rather than a platform-split package: the real
/// npm registry metadata for `typescript-language-server@6.0.0`
/// (`GET https://registry.npmjs.org/typescript-language-server/6.0.0`)
/// carries no `os`/`cpu`/`optionalDependencies` fields at all, unlike
/// [`TYPESCRIPT_7_WINDOWS_X64`]'s Go-compiled-native sibling package --
/// this is a single pure-JavaScript, webpack-bundled `lib/cli.mjs`
/// (confirmed above), so npm ships one universal tarball for every OS.
/// `tarball_url`/`expected_sha256_hex`/`binary_path_in_tarball` are
/// therefore byte-for-byte identical to [`TYPESCRIPT_LANGUAGE_SERVER_LINUX_X64`]'s
/// own -- independently re-verified this phase via a fresh `curl` download
/// and `sha256sum` (not merely copied from the Linux constant), only
/// `platform` differs, exactly mirroring the same "one artifact, two
/// platform manifests" shape [`RUST_SEMANTIC_RUNTIME_LINUX_X64`]/
/// `RUST_SEMANTIC_RUNTIME_WINDOWS_X64` already established for
/// architecture-neutral tarballs in this workspace.
pub const TYPESCRIPT_LANGUAGE_SERVER_WINDOWS_X64: ManagedComponentManifest =
    ManagedComponentManifest {
        id: ManagedComponentId("typescript-language-server"),
        version: "6.0.0",
        platform: "windows",
        architecture: "x64",
        source: ManagedArtifactSource {
            tarball_url: "https://registry.npmjs.org/typescript-language-server/-/typescript-language-server-6.0.0.tgz",
            expected_sha256_hex: "6e23b48efc76af4e70928cdfe62ea6e6cfef67ab4c1e7579c4e82dd284fbdfd2",
            binary_path_in_tarball: "package/lib/cli.mjs",
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

/// This host's own real `typescript-language-server` manifest -- mirrors
/// [`TYPESCRIPT_7_HOST_NATIVE`]'s own `#[cfg]`-gated-alias pattern, closing
/// the identical hardcoded-to-Linux defect
/// [`crate::profile::LspProviderProfile::typescript_language_server_managed`]
/// had for its `managed_component` field before this pass. `pub` (not
/// `pub(crate)`) because this phase's own audit of every existing
/// `TYPESCRIPT_LANGUAGE_SERVER_LINUX_X64`/`TYPESCRIPT_6_LINUX_X64` call site
/// found seven external integration-test files under `wht_corulix_lsp/tests/`
/// (separate crate compilation units) hardcoding the Linux constants
/// directly for real provisioning calls -- the exact same defect class the
/// P17-W-R7/R12 passes found and fixed for `GOPLS_HOST_NATIVE`/
/// `TYPESCRIPT_7_HOST_NATIVE` call sites.
#[cfg(target_os = "windows")]
pub const TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE: ManagedComponentManifest =
    TYPESCRIPT_LANGUAGE_SERVER_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE: ManagedComponentManifest =
    TYPESCRIPT_LANGUAGE_SERVER_LINUX_X64;

/// `typescript@6.0.3`, admitted this phase (7B-C) as the real "classic
/// TypeScript 6" managed runtime backing [`TYPESCRIPT_LANGUAGE_SERVER_LINUX_X64`]'s
/// `tsserver.path`. Real npm tarball, extracted and inspected directly
/// during this phase's research gate: `package.json` declares zero
/// dependencies, `bin: {"tsc": "./bin/tsc", "tsserver": "./bin/tsserver"}`,
/// and the extracted tree contains zero symlink entries.
/// `binary_path_in_tarball` names `lib/tsserver.js` specifically (not
/// `bin/tsserver`) because this component is never spawned as its own
/// process -- it is loaded *by* the managed `typescript-language-server`
/// process, via the exact same `require("...")` entry point a real
/// `tsserver.path` user-setting names; `required_paths` additionally proves
/// `lib/_tsserver.js` (the real backing implementation `lib/tsserver.js`'s
/// own compile-cache shim `require`s) and `lib/typescript.js` (the
/// compiler core) are both present in this exact tarball.
///
/// A real, current-ecosystem alternative exists on the npm registry --
/// `@typescript/typescript6`, a thin wrapper (`bin: {"tsc6": "./bin/tsc6"}`)
/// whose own `package.json` declares exactly one dependency,
/// `"@typescript/old": "npm:typescript@^6"` -- an npm alias that resolves
/// to this exact same `typescript` 6.x package. Extracting and reading
/// both confirmed the alias is a local npm naming convenience for
/// installing TypeScript 6 and 7 side-by-side, not a separately-published
/// artifact; admitting plain `typescript@6.0.3` directly (this constant)
/// is the real artifact either path ultimately resolves to, with one fewer
/// indirection in the managed dependency graph.
pub const TYPESCRIPT_6_LINUX_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("typescript-6-classic"),
    version: "6.0.3",
    platform: "linux",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz",
        expected_sha256_hex: "33cd0ee1beaa8c9e9d15a9da836c62ddea4c34a42d7c2d349dbc80d94165d22a",
        binary_path_in_tarball: "package/lib/tsserver.js",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        // `package/lib/tsc.js` closes ADR 0010's disclosed
        // `P16_TS6_TYPECHECK_MANIFEST_GAP`: this pass independently
        // downloaded this exact tarball (`curl` against the live
        // `tarball_url`), re-hashed the raw bytes (`sha256sum`,
        // byte-for-byte match against `expected_sha256_hex` above -- no new
        // checksum was invented), and extracted it to confirm
        // `package/lib/tsc.js` (the real npm `typescript@6.0.3` compiler
        // CLI entry point, distinct from `package/bin/tsc`, a thin shebang
        // shim around the same file) is present in this already-pinned
        // archive. No second managed component and no new hash were needed
        // -- the file was already inside the tarball this manifest already
        // pins; only its path was previously undeclared. `tsc.js` is loaded
        // by the managed Node runtime (`wht_corulix_tooling::managed_runtimes::
        // NODE_24_LTS_LINUX_X64`) exactly as `cli.mjs` already is for the
        // TS6 language server, never spawned as its own executable --
        // `wht_corulix_engine::ts_validation` resolves it via
        // `component_install_dir(...).join("package/lib/tsc.js")`.
        required_paths: &[
            "package/lib/_tsserver.js",
            "package/lib/typescript.js",
            "package/lib/tsc.js",
        ],
        required_nonempty_dirs: &[],
        tar_root_prefix: None,
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// P17-W Stage D: the Windows counterpart of [`TYPESCRIPT_6_LINUX_X64`].
/// Confirmed, not assumed, to be the exact same artifact: the real npm
/// registry metadata for `typescript@6.0.3`
/// (`GET https://registry.npmjs.org/typescript/6.0.3`) carries no
/// `os`/`cpu`/`optionalDependencies` fields either -- `typescript@6.0.3` is
/// plain JavaScript (`lib/tsserver.js`/`lib/typescript.js`/`lib/tsc.js`),
/// loaded by the managed `typescript-language-server`/managed Node process
/// rather than spawned as a native executable, so one universal tarball
/// serves every OS exactly as it does for
/// [`TYPESCRIPT_LANGUAGE_SERVER_WINDOWS_X64`].
/// `tarball_url`/`expected_sha256_hex`/`binary_path_in_tarball`/
/// `required_paths` are therefore byte-for-byte identical to
/// [`TYPESCRIPT_6_LINUX_X64`]'s own -- independently re-verified this phase
/// via a fresh `curl` download and `sha256sum`, only `platform` differs.
pub const TYPESCRIPT_6_WINDOWS_X64: ManagedComponentManifest = ManagedComponentManifest {
    id: ManagedComponentId("typescript-6-classic"),
    version: "6.0.3",
    platform: "windows",
    architecture: "x64",
    source: ManagedArtifactSource {
        tarball_url: "https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz",
        expected_sha256_hex: "33cd0ee1beaa8c9e9d15a9da836c62ddea4c34a42d7c2d349dbc80d94165d22a",
        binary_path_in_tarball: "package/lib/tsserver.js",
        archive_kind: ArchiveKind::TarGz,
        symlink_policy: SymlinkPolicy::Reject,
        required_paths: &[
            "package/lib/_tsserver.js",
            "package/lib/typescript.js",
            "package/lib/tsc.js",
        ],
        required_nonempty_dirs: &[],
        tar_root_prefix: None,
        extract_path_prefixes: &[],
        post_extraction_symlinks: &[],
    },
    additional_sources: &[],
};

/// This host's own real `typescript-6-classic` manifest -- mirrors
/// [`TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE`]'s own `#[cfg]`-gated-alias
/// pattern, closing the identical hardcoded-to-Linux defect
/// [`crate::profile::LspProviderProfile::typescript_language_server_managed`]
/// had for its `managed_typescript_6_runtime` field before this pass. `pub`
/// for the same seven-external-test-file reason documented on
/// [`TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE`].
#[cfg(target_os = "windows")]
pub const TYPESCRIPT_6_HOST_NATIVE: ManagedComponentManifest = TYPESCRIPT_6_WINDOWS_X64;
#[cfg(not(target_os = "windows"))]
pub const TYPESCRIPT_6_HOST_NATIVE: ManagedComponentManifest = TYPESCRIPT_6_LINUX_X64;
