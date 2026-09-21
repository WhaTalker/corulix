// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! `CORULIX_MANAGED` toolchain provisioning (Phase 7B-A).
//!
//! Owns the state model and download/verify/extract/activate pipeline for
//! externally-sourced language-tooling artifacts (starting with the
//! TypeScript 7 native LSP binary) that Corulix provisions and manages
//! itself, entirely outside any user workspace and independent of ambient
//! `PATH` or a pre-installed system toolchain
//! (`CORULIX_MANAGED_TOOLCHAIN=YES`, `SYSTEM_TOOLCHAIN_REQUIRED=NO`).
//!
//! This module is process/filesystem/network-adjacent work, which is this
//! crate's existing authority (Architecture Rule G: sole owner of
//! controlled external process construction; extended here to sole owner of
//! controlled external *artifact acquisition*, the same "Corulix decides
//! what gets fetched and how it is verified before anything downstream ever
//! runs it" boundary). It does not resolve *which* provider a caller should
//! use for a given category (that remains `wht_corulix_config::resolve_provider`'s
//! job for the `HOST_ONLY`/system/user-toolchain precedence) -- it only
//! answers "is this exact, pinned, Corulix-managed component present and
//! verified on disk, and if not, how do I get it there safely."
//!
//! # Atomic provisioning
//!
//! ```text
//! DOWNLOAD TO TEMP -> VERIFY HASH -> EXTRACT/STAGE -> VERIFY CONTENT ->
//! ATOMIC ACTIVATE -> AVAILABLE
//! ```
//!
//! Every stage before "ATOMIC ACTIVATE" writes only into a process-unique
//! staging directory that is never itself the canonical install path. The
//! final step is a single [`std::fs::rename`] of that staging directory onto
//! the canonical [`component_install_dir`] -- on the same filesystem this is
//! atomic, so [`resolve_managed_component`]'s presence check (`is_file` on
//! the expected binary inside the canonical directory) can never observe a
//! half-written install: either the rename has not happened yet (directory
//! absent) or it has fully happened (directory, and everything inside it,
//! present in one indivisible step). `PARTIAL_INSTALL_AVAILABLE_COUNT=0` by
//! construction, not by a best-effort ordering of writes.
//!
//! # Integrity
//!
//! Every [`ManagedArtifactSource`] pins an exact version, an exact tarball
//! URL (never a floating "latest" redirect Corulix itself constructs), and
//! an exact expected SHA-256 hex digest of the downloaded bytes, verified
//! via `wht_corulix_core::ContentHash::compute_sha256` (this workspace's
//! existing dependency-free SHA-256, reused here rather than admitting a
//! second hashing crate) before a single byte of the archive is extracted.
//!
//! # Archive extraction safety
//!
//! `extract_tarball` rejects, per entry, before writing anything for that
//! entry: any path component that is `..` or an absolute/root component,
//! and any entry type other than a plain file or directory (symlinks and
//! hard links inside the archive are refused outright -- this module has no
//! legitimate need for either, and both are exactly the vector a hostile or
//! corrupted artifact would use to escape the staging directory). Total
//! extracted bytes are bounded by [`MAX_EXTRACTED_BYTES`].

use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use wht_corulix_core::ContentHash;

pub mod full_uninstall;
pub mod install_profile;
pub mod lease;
pub mod ownership;
mod payload_verification_cache;
pub mod uninstall;

/// Process-wide registry of per-component async locks, keyed by
/// [`ManagedComponentId`]. [`lock_component`] is the sole entry point --
/// both [`provision_with_dependencies`] and [`uninstall::uninstall`]
/// acquire the *same* lock for a given component id before mutating
/// anything, so concurrent provisioning of the same component (never two
/// downloads/extracts/activations racing for the same install directory)
/// and a provision-vs-uninstall race against the same component (never a
/// rename racing a delete) are both structurally impossible --
/// `MANAGED_PROVISIONING_SINGLE_FLIGHT=PASS`, `PROVISION_UNINSTALL_RACE_COUNT=0`.
/// Distinct components lock independently (Node provisioning never blocks
/// on Pyright provisioning).
type ComponentLockRegistry = StdMutex<HashMap<&'static str, Arc<tokio::sync::Mutex<()>>>>;

static COMPONENT_LOCKS: OnceLock<ComponentLockRegistry> = OnceLock::new();

/// Acquires (creating if necessary) the single-flight lock for
/// `component_id`, held for the duration of the returned guard's lifetime.
pub(crate) async fn lock_component(component_id: &'static str) -> tokio::sync::OwnedMutexGuard<()> {
    let registry = COMPONENT_LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let handle = {
        let mut guard = registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .entry(component_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    handle.lock_owned().await
}

/// Global, root-scoped `full_uninstall` vs. everything-else serialization
/// (Phase 7B-B1-R3-B1 §3): a [`full_uninstall::full_uninstall`] holds this
/// lock in *write* mode for its entire transaction, while every individual
/// per-component `provision_with_dependencies`/`uninstall`/
/// `uninstall_with_stop_timeout` call holds it in *read* mode for the
/// duration of its own operation. Distinct individual operations therefore
/// still run concurrently against each other exactly as before (Node
/// provisioning never blocks on Pyright provisioning), but no individual
/// operation can start -- and, critically, no `provision` can complete and
/// register a *new* ownership record -- while a full-uninstall transaction
/// holds the write lock, and a full-uninstall cannot begin renaming
/// anything while any individual operation is still in flight.
/// `GLOBAL_MANAGED_LIFECYCLE_SERIALIZATION=PASS`,
/// `FULL_UNINSTALL_PROVISION_RACE_COUNT=0`,
/// `FULL_VS_COMPONENT_UNINSTALL_RACE_COUNT=0`.
type RootLockRegistry = StdMutex<HashMap<String, Arc<tokio::sync::RwLock<()>>>>;

static ROOT_LOCKS: OnceLock<RootLockRegistry> = OnceLock::new();

fn root_lock_handle(root_identity: &str) -> Arc<tokio::sync::RwLock<()>> {
    let registry = ROOT_LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut guard = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .entry(root_identity.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::RwLock::new(())))
        .clone()
}

/// Acquired by every individual (single-component) lifecycle operation.
pub(crate) async fn lock_root_shared(root_identity: &str) -> tokio::sync::OwnedRwLockReadGuard<()> {
    root_lock_handle(root_identity).read_owned().await
}

/// Acquired by [`full_uninstall::full_uninstall`] for its entire transaction.
pub(crate) async fn lock_root_exclusive(
    root_identity: &str,
) -> tokio::sync::OwnedRwLockWriteGuard<()> {
    root_lock_handle(root_identity).write_owned().await
}

/// Live proof that a governed execution is currently using Corulix-owned
/// managed scratch state under one managed root, held for that execution's
/// entire duration.
///
/// This is deliberately **not** a new lock subsystem: it is the *existing*
/// root `RwLock` (see `lock_root_shared`/`lock_root_exclusive`) held in
/// the same *read* mode every individual per-component lifecycle operation
/// already uses. A [`full_uninstall::full_uninstall`] transaction takes the
/// same lock in write mode for its whole run, so it structurally cannot
/// reach its scratch quarantine/destroy stage while any governed execution
/// still holds one of these guards -- and, symmetrically, an execution
/// cannot begin creating scratch state in the middle of a transaction that
/// has already planned its removal
/// (`P15_EXECUTION_CACHE_FULL_UNINSTALL_RACE_COUNT=0`,
/// `P15_EXECUTION_CACHE_COMPONENT_UNINSTALL_RACE_COUNT=0`,
/// `P15_ACTIVE_EXECUTION_PREMATURE_CACHE_DELETE_COUNT=0`).
///
/// # Why bounded one-shot executions need this and LSP sessions do not
///
/// A long-lived managed provider process (`wht_corulix_lsp::LspSession`,
/// e.g. gopls or rust-analyzer) is already discoverable to
/// `full_uninstall`'s global process preflight through its
/// [`lease::ManagedExecutionLease`], which the transaction signals and
/// verifies stopped before renaming anything. A *bounded one-shot* governed
/// execution (`go build`/`go vet`/`go test`/`cargo test`) is spawned through
/// `crate::execute` rather than `crate::ManagedProcess`, holds no lease, and
/// would otherwise be invisible to that preflight while actively writing
/// into `<root>/scratch/`. This guard closes exactly that window, reusing
/// the synchronization authority that already exists rather than inventing
/// a second one.
#[derive(Debug)]
pub struct ManagedExecutionScratchGuard {
    _root_guard: tokio::sync::OwnedRwLockReadGuard<()>,
}

/// Acquires a [`ManagedExecutionScratchGuard`] for `root`. Callers must hold
/// the returned guard for the *entire* governed execution -- from before the
/// first [`ensure_scratch_directory`] call that materializes the execution's
/// managed cache until after the spawned process has been fully reaped.
///
/// # Never nest this under another managed-root lock
///
/// The underlying `tokio::sync::RwLock` is write-preferring and its read
/// guards are therefore **not reentrant**: if a caller already holds a read
/// guard on this same root (a `provision_with_dependencies`/`uninstall` in
/// progress) and a `full_uninstall` is queued for the write lock, a second
/// read acquisition from the same task blocks behind that writer while the
/// task still holds the first read guard -- a real self-deadlock.
///
/// Verified at the time of writing: `run_go_test_with_limits`,
/// `run_go_validator` and `run_cargo_test_with_limits` (the only three
/// callers) have no production caller inside this workspace that holds a
/// managed-root lock, and `lock_root_shared`/`lock_root_exclusive` are
/// `pub(crate)` to this crate, so no other crate can hold one at all. A
/// future change that wires a governed execution *underneath* a provisioning
/// operation must pass the already-held guard down rather than acquiring a
/// second one here.
pub async fn acquire_managed_execution_scratch_guard(root: &Path) -> ManagedExecutionScratchGuard {
    ManagedExecutionScratchGuard {
        _root_guard: lock_root_shared(&ownership::root_identity(root)).await,
    }
}

/// Upper bound on one downloaded artifact's compressed size. The real TS7
/// native platform artifact is on the order of tens of megabytes; this
/// bound exists so a malicious or misbehaving server response cannot exhaust
/// memory/disk, not to accommodate any known-larger legitimate artifact.
pub const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// Upper bound on the sum of all extracted entry sizes for one artifact.
pub const MAX_EXTRACTED_BYTES: u64 = 512 * 1024 * 1024;

/// Current state of one [`ManagedComponentManifest`] on this host. Corulix
/// owns this state; a workspace never influences it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManagedComponentState {
    NotProvisioned,
    Provisioning,
    Available,
    Corrupt,
    Incompatible,
}

/// Stable identity for one managed component (e.g. the TypeScript 7 native
/// LSP binary) -- never a raw filesystem path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedComponentId(pub &'static str);

/// The archive container format one [`ManagedArtifactSource`] is downloaded
/// in. Not every upstream distributes a tarball -- rust-analyzer's official
/// release asset, for example, is a bare gzip-compressed executable with no
/// tar container at all -- so extraction must dispatch on this rather than
/// assuming every artifact is `tar.gz`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveKind {
    /// Gzip-compressed tar archive, extracted entry-by-entry.
    TarGz,
    /// Bzip2-compressed tar archive, extracted entry-by-entry -- same
    /// per-entry path/symlink/size handling as [`ArchiveKind::TarGz`], only
    /// the decompression codec differs. Added for P12-R2's managed GNU link
    /// runtime: Bootlin's older stable toolchain releases (including the
    /// pinned `x86-64--glibc--stable-2021.11-5`) publish `.tar.bz2` only,
    /// not `.tar.gz`. Decoded via `bzip2-rs` (pure Rust, decompressor-only,
    /// no `unsafe`, no C toolchain at build time -- the same purity bar
    /// `flate2`'s `rust_backend` feature already holds this workspace to).
    TarBz2,
    /// A bare gzip-compressed single file (no tar container). Decompressed
    /// directly to `binary_path_in_tarball` inside the staging directory.
    GzippedBinary,
    /// A bare, uncompressed single executable file (no tar container, no
    /// compression). Copied byte-for-byte to `binary_path_in_tarball` inside
    /// the staging directory, so `expected_sha256_hex` is the literal
    /// executable's own digest rather than a compressed wrapper's digest --
    /// use this instead of [`ArchiveKind::GzippedBinary`] whenever the
    /// component's certified identity must remain the raw binary hash.
    RawBinary,
    /// A PKZIP-format archive (local file headers + central directory +
    /// end-of-central-directory record), extracted entry-by-entry from the
    /// central directory (the authoritative index -- never the streamed
    /// local headers, which a hostile/corrupted archive could disagree
    /// with). Added for P17-W-R4-C2's Windows managed-toolchain foundation:
    /// Node's official Windows x64 distribution
    /// (`nodejs.org/dist/vX.Y.Z/node-vX.Y.Z-win-x64.zip`) ships ZIP only --
    /// no `.tar.gz`/`.tar.xz` alternative exists for that platform, unlike
    /// every `static.rust-lang.org` Rust artifact (`rustc`/`cargo`/
    /// `rust-std`/`rust-analyzer-preview`/`rustfmt-preview`), which remain
    /// `.tar.gz`/`.tar.xz` on every target including Windows -- confirmed
    /// directly against `channel-rust-stable.toml` during this phase's
    /// research gate, not assumed. Decoded via this crate's own dependency-
    /// free central-directory parser plus `flate2`'s `rust_backend` raw
    /// DEFLATE decoder (method 8) or a direct byte copy (method 0/Stored);
    /// any other compression method (bzip2/LZMA/zstd/AES-encrypted, method
    /// IDs this workspace has no artifact that uses) fails the whole
    /// archive closed rather than silently skipping or guessing. No
    /// ZIP64 support: an EOCD/central-directory record carrying a ZIP64
    /// sentinel size (`0xFFFFFFFF`) fails closed rather than being
    /// misinterpreted -- every artifact this component set provisions is
    /// well under the 4 GiB non-ZIP64 limit.
    Zip,
}

/// How a [`ArchiveKind::TarGz`] extraction handles symlink/hard-link
/// entries. There is no implicit, artifact-wide "skip all symlinks"
/// behavior: every component must state its own policy, and the default
/// (`Reject`) aborts the whole archive on the first such entry -- exactly
/// the pre-Phase-7B-B1 behavior. Only a component whose upstream artifact
/// is independently verified to ship specific, known, harmless symlinks may
/// declare [`SymlinkPolicy::AllowExactRelativePaths`], and even then any
/// symlink/hard-link entry *not* on that exact allowlist still fails the
/// whole archive closed.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SymlinkPolicy {
    /// Any symlink or hard-link entry aborts the whole archive. The
    /// canonical default; used by every component unless a specific
    /// upstream artifact has been inspected and found to require otherwise.
    Reject,
    /// A symlink/hard-link entry whose in-archive relative path exactly
    /// matches one of these strings is skipped (never created or
    /// followed); any other symlink/hard-link entry still aborts the whole
    /// archive closed.
    AllowExactRelativePaths(&'static [&'static str]),
}

/// Exactly where one managed component's artifact comes from and how its
/// integrity is proven. Every field is a compile-time constant Corulix
/// itself pins -- never derived from workspace input, never a "latest"
/// resolution performed at provisioning time.
#[derive(Debug, Clone, Copy)]
pub struct ManagedArtifactSource {
    /// The exact tarball URL Corulix downloads. Pinned to one exact
    /// registry-published version; never a floating/latest alias.
    pub tarball_url: &'static str,
    /// The exact SHA-256 hex digest the downloaded tarball's bytes must
    /// match before extraction is attempted.
    pub expected_sha256_hex: &'static str,
    /// The path of the component's primary executable *inside* the tarball
    /// (e.g. `"package/lib/tsc"`), used both to build the extraction target
    /// and to verify content post-extraction.
    pub binary_path_in_tarball: &'static str,
    /// The archive container format this artifact is downloaded in.
    pub archive_kind: ArchiveKind,
    /// This artifact's symlink/hard-link handling policy (ignored for
    /// [`ArchiveKind::GzippedBinary`], which contains no entries at all).
    pub symlink_policy: SymlinkPolicy,
    /// Every relative path (in addition to `binary_path_in_tarball`, which
    /// is always implicitly required) that must exist as a regular file in
    /// the staging directory before activation is permitted -- the
    /// required-layout check. Activation is refused
    /// (`ContentVerificationFailed`) if any is missing, so a symlink/entry
    /// skip can never silently produce an incomplete, partially-usable
    /// provider.
    pub required_paths: &'static [&'static str],
    /// Every relative directory that must exist and contain at least one
    /// entry after extraction, checked alongside `required_paths`. Exists
    /// for components (e.g. the merged Rust semantic runtime's `rust-std`
    /// artifact) whose required output files carry a build-specific hashed
    /// filename (`libstd-<hash>.rlib`) that cannot be pinned as an exact
    /// `required_paths` entry -- non-emptiness is the closest content
    /// verification that stays a pinned, non-guessing constant.
    pub required_nonempty_dirs: &'static [&'static str],
    /// When this artifact is one component of a multi-artifact merged
    /// install (see [`ManagedComponentManifest::additional_sources`]),
    /// every archive entry is extracted relative to this prefix and any
    /// entry whose path does not start with it is skipped rather than
    /// written -- this is how e.g. the official `rustc-<version>-<target>/
    /// rustc/` tarball layout collapses onto a shared merged prefix
    /// alongside `cargo-<version>-<target>/cargo/` and
    /// `rust-std-<version>-<target>/rust-std-<target>/` from separate
    /// artifacts. `None` preserves every prior single-artifact component's
    /// exact existing behavior: the full in-archive path is kept as-is.
    pub tar_root_prefix: Option<&'static str>,
    /// Restricts extraction to entries whose (already `tar_root_prefix`-
    /// stripped) relative path starts with one of these string prefixes.
    /// Checked in addition to, not instead of, `tar_root_prefix` --
    /// `tar_root_prefix` re-roots the archive, this filters *which* files
    /// under that new root are actually written to disk. An empty slice
    /// (the value every prior component uses) preserves the exact existing
    /// full-extraction behavior. Introduced for the P12-R2 managed GNU link
    /// runtime: the upstream Bootlin toolchain tarball bundles a full
    /// gcc/binutils/gdb cross-toolchain (~480 MiB extracted) when Corulix
    /// only ever resolves the sysroot's runtime shared objects, CRT
    /// objects, and `libgcc.a`/`libgcc_eh.a` (~50 MiB) -- extracting the
    /// unused C++/Fortran/gdb/plugin subtrees would be real, unjustified
    /// attack surface and disk cost for content nothing in Corulix ever
    /// spawns or reads, not a hypothetical future need. Skipped entries are
    /// silently dropped rather than rejected, mirroring the existing
    /// "outside `tar_root_prefix`" precedent immediately above: the whole
    /// archive's integrity was already proven by the SHA-256 check before
    /// extraction began, so selecting a subtree of an already-trusted
    /// archive is not a security-relevant rejection.
    pub extract_path_prefixes: &'static [&'static str],
    /// Corulix-authored (never archive-derived) relative symlinks to create
    /// once extraction otherwise succeeds: `(link_relative_path,
    /// relative_target)` pairs, both validated confined (no absolute
    /// component, no `..`) before creation. Distinct, deliberately, from
    /// [`SymlinkPolicy::AllowExactRelativePaths`]: that policy *skips*
    /// creating an archive-declared symlink (upstream/attacker-influenced
    /// data Corulix chooses not to trust as a link target) -- this field
    /// *creates* a symlink whose target string is a Corulix-authored
    /// constant in this crate's own source, never taken from the tarball.
    /// Introduced for the managed GNU link runtime's `lib64 -> lib`
    /// compatibility symlinks, which several of its own kept linker scripts
    /// require to actually resolve at link time (see
    /// [`crate::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64`]'s own doc
    /// comment). Empty for every other component.
    pub post_extraction_symlinks: &'static [(&'static str, &'static str)],
}

/// One exact, platform/architecture-scoped managed component. `version`,
/// `platform`, and `architecture` together with [`ManagedComponentId`] form
/// the on-disk install path (see [`component_install_dir`]), so two
/// different versions of the same component never collide.
#[derive(Debug, Clone, Copy)]
pub struct ManagedComponentManifest {
    pub id: ManagedComponentId,
    pub version: &'static str,
    pub platform: &'static str,
    pub architecture: &'static str,
    pub source: ManagedArtifactSource,
    /// Additional artifacts downloaded, independently hash-verified, and
    /// extracted -- in order, after `source` -- into the *same* staging
    /// directory as `source`, so the final activated install is one merged
    /// tree built from N independently-pinned upstream artifacts. Empty for
    /// every single-artifact component. `source.binary_path_in_tarball` and
    /// `source.required_paths`/`required_nonempty_dirs` describe the final
    /// *merged* layout, not `source`'s own archive in isolation -- e.g. the
    /// merged Rust semantic runtime's primary `source` is the `rustc`
    /// artifact, but `required_paths` also names `bin/cargo`, which only
    /// exists after `additional_sources`' `cargo` artifact has merged in.
    pub additional_sources: &'static [ManagedArtifactSource],
}

/// One independently-tracked, independently-degradable sub-capability
/// within an archive-derived component's installed tree (Managed
/// Installed-Payload Integrity, segment-aware model -- P11-R1 conflict
/// resolution). `paths` are relative to `component_install_dir`.
///
/// A segment's files may be legitimately *absent* (its capability is simply
/// unavailable/degraded, never an integrity failure) without affecting the
/// rest of the component: the CORE installed-payload digest boundary
/// (Section 8/9) always excludes every declared segment's `paths`, so a
/// segment's presence or absence never perturbs the core digest, and the
/// core component can stay `Available` regardless. A segment's files being
/// *present but tampered*, however, must never be silently treated as
/// merely absent -- see [`resolve_optional_segment`].
#[derive(Debug, Clone, Copy)]
pub struct OptionalSegment {
    /// Stable identity for this segment, unique within one component
    /// (e.g. `"clippy"`). Never a raw filesystem path.
    pub id: &'static str,
    pub paths: &'static [&'static str],
}

/// The declared [`OptionalSegment`]s for `component_id`, if any. This is the
/// **one, sole, explicitly-scoped** place a specific component's specific
/// degradable sub-capability is named -- every generic resolver function in
/// this module (`compute_installed_payload_digest`,
/// `resolve_owned_managed_component_detailed`, `resolve_optional_segment`)
/// only ever consults this lookup by id; none of them hardcode a
/// Rust/Clippy-specific path or check.
///
/// # Why `rust-semantic-runtime`/`"clippy"` specifically
///
/// `wht_corulix_engine::diagnostics`'s already-shipped
/// `real_p11_r1_optional_clippy_unavailable_degraded_e2e` test (predating
/// this pass) proved empirically that clippy -- merged into the Rust
/// semantic runtime as a fifth `additional_sources` entry -- may have its
/// `bin/cargo-clippy`/`bin/clippy-driver` binaries independently absent
/// while `cargo`/`rustc` remain usable, and that this must continue to work
/// (`P11_R1_DEGRADATION_CONTRACT=PRESERVE`, an explicit owner decision).
/// Both files are declared here as one segment (rather than two) because
/// `resolve_clippy_binaries` already treats them as a single atomic
/// capability -- either both are present and correct, or clippy is
/// unavailable -- so a single segment identity matches the real,
/// already-shipped granularity rather than inventing a finer one nothing
/// else in the codebase distinguishes.
///
/// Every other real managed component today has no independently-
/// degradable sub-capability, so this returns `&[]` for everything else --
/// their CORE installed-payload digest boundary is therefore their whole
/// installed tree, unchanged from before this segment-aware model existed.
#[must_use]
pub fn declared_optional_segments(component_id: &str) -> &'static [OptionalSegment] {
    const CLIPPY_SEGMENT: &[OptionalSegment] = &[OptionalSegment {
        id: "clippy",
        paths: &["bin/cargo-clippy", "bin/clippy-driver"],
    }];
    match component_id {
        "rust-semantic-runtime" => CLIPPY_SEGMENT,
        _ => &[],
    }
}

/// Resolution-time verdict for one declared [`OptionalSegment`] --
/// independent of the owning component's own core
/// [`ManagedComponentState`]/[`ManagedInvalidReason`] verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SegmentState {
    /// Every declared path is present, and -- when a digest was recorded
    /// for this segment at acquisition time -- it verifies.
    Available,
    /// At least one declared path is absent. Degraded, not tampered: the
    /// segment's own capability is simply unavailable
    /// (`OPTIONAL_SEGMENT_ABSENT_AUXILIARY_STATUS=UNAVAILABLE_OR_DEGRADED`),
    /// and this never affects the owning component's own core resolution
    /// (`OPTIONAL_SEGMENT_ABSENT_COMPONENT_CORE_STATUS=AVAILABLE`).
    Absent,
    /// Every declared path is present, but the recorded digest for this
    /// segment -- when one exists -- does not match. Must never be treated
    /// as merely `Absent`, and the capability this segment backs must never
    /// execute (`OPTIONAL_PRESENT_TAMPERED_EXECUTABLE_ALLOWED=NO`).
    Tampered,
}

/// Why a provisioning or resolution step failed. Never a panic -- every
/// failure mode here is a normal, typed outcome a caller can react to
/// (report `BLOCKED`/`MANAGED_PROVIDER_NOT_PROVISIONED`, never silently
/// fall back to an unmanaged provider).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvisioningError {
    ToolchainRootUnresolvable,
    /// `root` was not an absolute path when handed to
    /// [`provision_with_dependencies`]. Refused immediately, before any
    /// network I/O, filesystem mutation, or lock acquisition -- a relative
    /// root would still "work" for ordinary `fs::create_dir_all`/
    /// `fs::rename` calls (which resolve against the process's current
    /// directory), so provisioning could otherwise run an entire session
    /// lifecycle to completion and only surface the mistake much later, as
    /// a confusing `uninstall::UninstallError::PathEscapesManagedRoot` once
    /// [`wht_corulix_workspace::canonicalize_external_path`]'s own
    /// `is_absolute()` guard finally rejects it. A caller-constructed root
    /// (e.g. a test's own isolated scratch root, built from an environment
    /// variable that can legitimately be present-but-empty on some hosts)
    /// must be validated at the point it is first accepted, not discovered
    /// as an oblique confinement failure at uninstall time
    /// (`P17_W_R_MANAGED_ROOT_ABSOLUTE_ADMISSION` defense-in-depth).
    ManagedRootNotAbsolute,
    DownloadFailed,
    DownloadTooLarge,
    IntegrityMismatch,
    ArchiveExtractionFailed,
    PathTraversalRejected,
    UnexpectedSymlinkRejected,
    ExtractedContentTooLarge,
    ContentVerificationFailed,
    ActivationFailed,
    StagingDirectoryUnavailable,
    /// The relative path handed to [`ensure_scratch_directory`] was empty,
    /// absolute, or contained a `..`/root/prefix component -- i.e. it could
    /// have resolved a Corulix-owned scratch directory to somewhere outside
    /// the base root it was asked for. Refused before any `create_dir_all`
    /// (`P15_CACHE_OWNERSHIP_CONFINEMENT=PASS`).
    ScratchPathNotConfined,
    /// The component's persisted ownership record could not be
    /// written/read/verified (see [`ownership::OwnershipError`]).
    OwnershipManifestInvalid,
    /// A prior [`full_uninstall::full_uninstall`] transaction's rollback
    /// failed and left the managed root recovery-locked
    /// (`FURTHER_MANAGED_MUTATION_DENIED=YES`); refused eagerly rather than
    /// racing an operator's manual recovery.
    RecoveryLocked,
    /// `manifest.platform`/`manifest.architecture` do not match the actual
    /// running host (see [`host_platform_identifier`]/
    /// [`host_architecture_identifier`]). Found representable via the public
    /// `crate::LspProviderProfile::with_managed_component` override (not
    /// hypothetical -- that method is `pub` and accepts any caller-built
    /// manifest, so nothing upstream of `provision_blocking` already
    /// guaranteed the manifest names the host Corulix is actually running
    /// on), so this check is real typed admission, not defense-in-depth for
    /// an unreachable case (Phase 7B-B1-R3-B2-B1 Section 15-17). Checked
    /// first, before any network I/O -- a foreign-platform/architecture
    /// manifest is refused before a single byte is downloaded.
    PlatformArchitectureMismatch,
    /// A [`provision_with_dependencies`] call found one of its own declared
    /// dependency ids not currently owned-`Available` while holding that
    /// dependency's lock -- refused before any download/extract/activate/
    /// ownership-write for the primary component, so the primary is never
    /// activated with a dangling dependency-on-a-removed-component edge
    /// recorded against it (Phase 7B-C-R2 -- see `provision_with_dependencies`'s
    /// own doc comment for the exact race this closes).
    DependencyNotAvailable,
    /// A [`ArchiveKind::Zip`] archive's end-of-central-directory record, a
    /// central directory entry, or a local file header could not be parsed
    /// (truncated bytes, a bad signature, a length field pointing past the
    /// buffer, or a ZIP64 sentinel this parser deliberately does not
    /// support) -- the whole archive fails closed rather than being
    /// partially interpreted.
    ZipArchiveMalformed,
    /// A [`ArchiveKind::Zip`] central directory entry declared a
    /// compression method other than `0` (Stored) or `8` (Deflate) --
    /// every real artifact this component set provisions uses only these
    /// two, so anything else (bzip2/LZMA/zstd/AES-encrypted) is refused
    /// rather than silently skipped or guessed at.
    ZipUnsupportedCompressionMethod,
    /// A [`ArchiveKind::Zip`] entry's extracted bytes did not match its own
    /// central-directory-declared CRC-32 -- refused before the entry's
    /// bytes are trusted for anything downstream (required-path check,
    /// executable-bit preservation, activation).
    ZipEntryCrc32Mismatch,
    /// Two [`ArchiveKind::Zip`] central directory entries resolved to the
    /// same in-archive relative path (after prefix stripping/filtering) --
    /// refused rather than silently letting the second entry overwrite the
    /// first, which is exactly the ambiguity a hostile or corrupted
    /// archive would exploit to smuggle a different file in under a name
    /// [`ManagedArtifactSource::required_paths`] already trusts.
    ZipDuplicateEntryPath,
    /// [`provision_go_module_build`]'s invoked Go compiler process could not
    /// be spawned, exited with a non-zero status, or produced no binary at
    /// its expected `GOBIN` output path -- covers every real Go-toolchain
    /// failure mode this pass's negative matrix exercises (invalid module
    /// identity, wrong/nonexistent module version, module-proxy/network
    /// failure, `GOSUMDB` checksum-mismatch rejection, and a genuine compile
    /// failure) under one fail-closed variant: none of them leave a partial
    /// `GOBIN` output treated as a real component, and none of them are
    /// distinguished further because a caller's only correct reaction to any
    /// of them is identical -- report the source-build as failed and leave
    /// no ownership record.
    BuildFailed,
}

/// This host's own platform identifier, in the exact string convention
/// every real [`ManagedComponentManifest::platform`] constant already uses
/// (`"linux"`, `"macos"`, `"windows"` -- see e.g.
/// `wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64`).
/// Never derived from the manifest itself -- this is the independent,
/// compile-time-fixed side of the [`ProvisioningError::PlatformArchitectureMismatch`]
/// [`ProvisioningError::PlatformArchitectureMismatch`] comparison.
#[must_use]
pub const fn host_platform_identifier() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
}

/// This host's own architecture identifier, in the exact string convention
/// every real [`ManagedComponentManifest::architecture`] constant already
/// uses (`"x64"`). See [`host_platform_identifier`] for the platform half of
/// the same admission check.
#[must_use]
pub const fn host_architecture_identifier() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
}

/// Refuses `manifest` up front when its declared `platform`/`architecture`
/// do not match this actual running host -- the real fix for
/// Phase 7B-B1-R3-B2-B1 Section 15-17's `WRONG_PLATFORM`/
/// `WRONG_ARCH_MANAGED_COMPONENT_ACTIVATION` question. Before this check
/// existed, nothing in the provisioning pipeline compared a manifest's
/// declared platform/architecture to the host at all: [`component_install_dir`]
/// only ever used those two fields as install-path segments, and
/// [`resolve_managed_component`]/[`resolve_owned_managed_component`] only
/// ever checked local filesystem presence plus ownership -- a manifest
/// built for a foreign platform/architecture (reachable today only through
/// the public [`crate::LspProviderProfile::with_managed_component`]
/// override, since every one of this crate's own compile-time manifest
/// constants is hardcoded to the real host already) would download,
/// hash-verify, extract, content-verify, and activate exactly as if it were
/// native, and [`resolve_owned_managed_component`] would then report it
/// `Available` for execution.
fn validate_manifest_platform_architecture(
    manifest: &ManagedComponentManifest,
) -> Result<(), ProvisioningError> {
    if manifest.platform == host_platform_identifier()
        && manifest.architecture == host_architecture_identifier()
    {
        Ok(())
    } else {
        Err(ProvisioningError::PlatformArchitectureMismatch)
    }
}

/// Resolves the platform-appropriate Corulix application-data root for
/// managed toolchain artifacts. Never a developer-specific hardcoded path,
/// never a location inside any project (`node_modules`, `.venv`, `vendor`,
/// a project-local `bin`) -- always the OS's own per-user application-data
/// convention, with `Corulix`/`corulix` as Corulix's own leaf component.
pub fn managed_toolchain_root() -> Result<PathBuf, ProvisioningError> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .map(|base| {
                PathBuf::from(base)
                    .join("Corulix")
                    .join("managed-toolchain")
            })
            .ok_or(ProvisioningError::ToolchainRootUnresolvable)
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|home| {
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("Corulix")
                    .join("managed-toolchain")
            })
            .ok_or(ProvisioningError::ToolchainRootUnresolvable)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(xdg).join("corulix").join("managed-toolchain"));
        }
        std::env::var_os("HOME")
            .map(|home| {
                PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("corulix")
                    .join("managed-toolchain")
            })
            .ok_or(ProvisioningError::ToolchainRootUnresolvable)
    }
}

/// The canonical, versioned, platform/architecture-scoped install directory
/// for one manifest under `root`. Never written to directly by extraction --
/// only ever produced by a single atomic rename in [`provision`].
#[must_use]
pub fn component_install_dir(root: &Path, manifest: &ManagedComponentManifest) -> PathBuf {
    root.join("components")
        .join(manifest.id.0)
        .join(manifest.version)
        .join(format!("{}-{}", manifest.platform, manifest.architecture))
}

/// Joins `relative` (a `&'static str` manifest literal such as
/// `"package/lib/tsserver.js"`, always authored with forward slashes for
/// cross-platform readability) onto `base` and returns a path whose string
/// representation uses only the host's native separator.
///
/// # Why this exists (Phase 17-W-R14/R15 `tsserver.path` defect)
///
/// `Path::join` does not re-normalize embedded separators inside the
/// pushed component: on Windows, `base.join("package/lib/tsserver.js")`
/// with a backslash-separated `base` yields a `PathBuf` whose `to_str()`
/// is the *mixed*-separator string
/// `"...\\typescript_6\\package/lib/tsserver.js"` -- valid for every
/// Windows filesystem API (`is_file`, `fs::read`, `CreateProcess`
/// argv/executable, all separator-tolerant), but fatal for exactly one
/// consumer: `typescript-language-server`'s own `getTypeScriptVersion`
/// resolves the module root by `serverPath.split(path.sep)` (Node's
/// `path.sep` is a strict single backslash on Windows) and drops the last
/// two components to locate `package.json`. Any embedded `/` fails that
/// split, `modulePath` comes out wrong, `package.json` is not found,
/// `isValid` is `false`, and the server silently discards the
/// user-supplied `tsserver.path` -- which is exactly the failure this
/// project's Corulix-managed-only, no-bundled-fallback design turns into a
/// hard `initialize` error (`ServerError -32603: Could not find a valid
/// TypeScript installation`) instead of a silent downgrade.
///
/// Root-caused via an isolated external repro (a hand-built `initialize`
/// JSON-RPC request piped directly to the real, unmodified `cli.mjs` on
/// the Windows VM, native separators vs. mixed vs. all-forward-slash):
/// only the fully native-backslash variant returned a genuine `initialize`
/// result; both the mixed-separator variant (matching Corulix's actual
/// unfixed output) and an all-forward-slash variant failed identically.
/// This is the single choke point every managed-component path resolution
/// (`resolve_managed_component`/`resolve_owned_managed_component`, and
/// therefore every `profile::resolve_launch` call site including TS6's
/// `tsserver.path` injection) funnels through, so fixing it here closes
/// the defect class for every present and future manifest-derived path
/// string handed to an external tool's own separator-sensitive parsing
/// (TS6 today; Pyright's managed Node interpreter is the same shape and
/// will inherit this fix automatically). On non-Windows platforms this is
/// a strict no-op: `/` is already the native and only separator, and
/// `Path::join` behaves identically before and after.
fn join_manifest_relative(base: &Path, relative: &str) -> PathBuf {
    #[cfg(windows)]
    {
        base.join(relative.replace('/', "\\"))
    }
    #[cfg(not(windows))]
    {
        base.join(relative)
    }
}

/// Checks whether `manifest` is already provisioned and verified-present
/// under `root`, purely via a local filesystem check -- no network, no
/// state file, no ambient `PATH`. Returns the canonical, ready-to-spawn
/// binary path when [`ManagedComponentState::Available`].
#[must_use]
pub fn resolve_managed_component(
    root: &Path,
    manifest: &ManagedComponentManifest,
) -> (ManagedComponentState, Option<PathBuf>) {
    let binary = join_manifest_relative(
        &component_install_dir(root, manifest),
        manifest.source.binary_path_in_tarball,
    );
    if binary.is_file() {
        (ManagedComponentState::Available, Some(binary))
    } else {
        (ManagedComponentState::NotProvisioned, None)
    }
}

/// The reason [`resolve_owned_managed_component_detailed`] classified a
/// present-on-disk artifact as [`ManagedComponentState::Corrupt`] rather
/// than [`ManagedComponentState::Available`]. Every variant here means the
/// artifact is present but must never be treated as usable *and* must never
/// be treated as merely "not yet provisioned" -- the distinction this type
/// exists to preserve is exactly `INVALID_MANAGED_STATE != NOT_PROVISIONED`
/// (managed-toolchain ownership/integrity hardening pass): a caller that
/// falls back to an explicit, approved `HOST_ONLY` provider on genuine
/// absence must never take that same fallback path for any of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManagedInvalidReason {
    /// The binary is present on disk but no ownership record exists for it
    /// at all -- a pre-ownership orphan artifact (see this function's own
    /// doc comment), indistinguishable from a planted/foreign binary.
    OwnershipMissing,
    /// The ownership record exists but failed to load: unreadable,
    /// unparseable, or its own self-digest (`installation_manifest_digest`)
    /// does not match its recomputed value -- [`ownership::load`]'s
    /// `OwnershipError::CorruptManifest`.
    OwnershipMalformed,
    /// The ownership record loaded and is internally self-consistent, but
    /// its `managed_root_identity` does not match the root it was loaded
    /// from -- [`ownership::load`]'s `OwnershipError::RootIdentityMismatch`.
    RootIdentityMismatch,
    /// The record loaded successfully but its own `component_id` field
    /// disagrees with the manifest identity this resolution was requested
    /// for -- never checked before this pass (a record for one component
    /// could previously satisfy a lookup for a different one, as long as
    /// its `ownership`/`activation_state` fields happened to check out).
    ComponentIdMismatch,
    /// The record's `ownership` field is not `CorulixManaged` (e.g. it was
    /// somehow recorded as `HostOnlyOverride`/`SystemExternal`/
    /// `WorkspaceExternal` under a managed component's own id) -- Corulix
    /// must never treat a resource it does not itself own as an executable
    /// managed artifact.
    OwnershipClassInvalid,
    /// The record's `activation_state` is not `Available` (e.g.
    /// `UninstallPreparing`/`Uninstalling`) -- a component mid-removal must
    /// never be resolved as usable.
    ActivationInvalid,
    /// The resolved executable's own live bytes no longer match the digest
    /// recorded at install time (`artifact_digest`) -- checked only where
    /// that field is proven to be the resolved single file's own *raw,
    /// uncompressed* hash: `ArchiveKind::RawBinary` only (its own doc
    /// comment: "`expected_sha256_hex` is the literal executable's own
    /// digest"), plus module-build components which compute
    /// `artifact_digest` from the produced binary the same way (see
    /// `crate::managed_toolchain::GOPLS_LINUX_X64`'s own `archive_kind`,
    /// itself `RawBinary`). **Not applicable** for
    /// `ArchiveKind::GzippedBinary` (a real, confirmed false-positive this
    /// pass hit against rust-analyzer: `GzippedBinary`'s own digest is "a
    /// compressed wrapper's digest" -- the original `.gz` blob, verified
    /// *before* decompression -- never the decompressed executable's own
    /// hash) nor for multi-file `TarGz`/`TarBz2`/`Zip` archives, where
    /// `artifact_digest` is the original archive's own hash, a different
    /// granularity than any one extracted file. Naively comparing in
    /// either case would mark every such component permanently tampered.
    /// This is a disclosed, real gap for those components, not something
    /// this variant claims to cover.
    ArtifactIntegrityMismatch,
    /// The resolved archive-derived install's *installed payload* (Managed
    /// Installed-Payload Integrity pass: the extracted single file for
    /// `GzippedBinary`, or the whole merged component tree for
    /// `TarGz`/`TarBz2`/`Zip`) no longer matches
    /// `record.installed_payload_digest`. This is exactly the gap
    /// [`ManagedInvalidReason::ArtifactIntegrityMismatch`]'s doc comment discloses as
    /// out-of-scope for `artifact_digest` -- covered here instead, by a
    /// digest of a different granularity computed and persisted at
    /// acquisition time. **Only checked when `installed_payload_digest` is
    /// non-empty** -- a pre-existing legacy record with no such digest
    /// recorded is not treated as a mismatch (never `Corrupt` on this
    /// variant), and is not silently upgraded by hashing its current bytes
    /// either (no Trust-On-First-Use). See
    /// [`resolve_owned_managed_component_detailed`]'s own doc comment for
    /// why that legacy case is deliberately left unenforced this pass
    /// (`ARCHIVE_DERIVED_RUNTIME_INTEGRITY_STATUS=PARTIAL`).
    InstalledPayloadMismatch,
}

/// [`resolve_managed_component`] plus the ownership check that determines
/// whether Corulix may actually *execute* the binary it finds.
///
/// `resolve_managed_component` alone is a pure filesystem-presence check --
/// correct for `provision_with_dependencies`'s own idempotency short-circuit
/// (re-provisioning over a pre-existing directory is itself a safe,
/// self-healing no-op there), but wrong as the sole authority for spawning a
/// child process. `CORULIX_INSTALLS_IT -> CORULIX_OWNS_IT -> CORULIX_TRACKS_IT`
/// means a binary Corulix did not itself install and record ownership of --
/// a pre-ownership orphan artifact left at the expected path by any means
/// other than a completed `provision_with_dependencies` run -- must never be
/// treated as `Available` for execution, even though it is present on disk.
///
/// Every call site that resolves a managed provider/interpreter/runtime path
/// immediately before spawning it (`profile::resolve_launch` and its
/// helpers) must use this function, not [`resolve_managed_component`]
/// directly.
///
/// This is a thin wrapper over [`resolve_owned_managed_component_detailed`]
/// that discards the invalid-reason detail, preserved with its exact
/// pre-existing signature so every caller that only ever checked
/// `state == Available` (the overwhelming majority -- formatter/engine/mcp
/// callers that reject any non-`Available` state identically either way)
/// needed zero changes for this pass's ownership/integrity hardening.
#[must_use]
pub fn resolve_owned_managed_component(
    root: &Path,
    manifest: &ManagedComponentManifest,
) -> (ManagedComponentState, Option<PathBuf>) {
    let (state, path, _reason) = resolve_owned_managed_component_detailed(root, manifest);
    (state, path)
}

/// [`resolve_owned_managed_component`], with the specific
/// [`ManagedInvalidReason`] a `Corrupt` classification carries. Callers that
/// make a fallback decision on a non-`Available` result (today:
/// `wht_corulix_lsp::profile::resolve_managed_or_system_path` and
/// `wht_corulix_engine::go_providers::resolve_managed_go_toolchain`) must
/// use this function, not the plain one, so they can tell a genuinely
/// not-yet-provisioned component (`NotProvisioned`/`Provisioning`, eligible
/// for an explicit approved `HOST_ONLY` fallback) apart from a present but
/// invalid/tampered one (`Corrupt`, which must fail closed with **no**
/// fallback -- `INVALID_MANAGED_STATE_HOST_FALLBACK_COUNT` must stay `0`).
///
/// # Archive-derived installed-payload integrity (Managed Installed-Payload
/// Integrity pass, segment-aware model -- P11-R1 conflict resolution)
///
/// For `GzippedBinary`/`TarGz`/`TarBz2`/`Zip` components, this function also
/// re-verifies `record.installed_payload_digest` against the live installed
/// tree -- **whenever that field is non-empty** (unconditionally, not gated
/// behind an opt-in flag: `PRODUCTION_ARCHIVE_INTEGRITY_ENFORCEMENT_DEFAULT
/// = ON`). A record persisted before this feature existed has an empty
/// `installed_payload_digest` (the same `#[serde(default)]` legacy-evolution
/// mechanism already used for `installation_manifest_digest`); an empty
/// digest is never enforced, since there is nothing recorded to compare
/// against -- that is a disclosed migration gap
/// (`ARCHIVE_DERIVED_RUNTIME_INTEGRITY_STATUS=PARTIAL`), not a silently
/// weakened check.
///
/// The CORE digest this function recomputes deliberately **excludes** every
/// path named by [`declared_optional_segments`] for this component id --
/// see `compute_tree_installed_digest`'s own doc comment. This is what
/// makes unconditional enforcement safe: `wht_corulix_engine`'s
/// already-shipped `real_p11_r1_optional_clippy_unavailable_degraded_e2e`
/// (predating this pass) proved that clippy's
/// `bin/cargo-clippy`/`bin/clippy-driver` -- merged into the Rust semantic
/// runtime as a fifth `additional_sources` entry -- must be allowed to go
/// missing without invalidating `cargo`/`rustc`
/// (`P11_R1_DEGRADATION_CONTRACT=PRESERVE`, an explicit owner decision).
/// Because clippy's own paths are excluded from the CORE boundary, deleting
/// them never perturbs this digest at all -- P11-R1 passes not because
/// enforcement is disabled, but because the CORE identity was never Rust's
/// whole tree to begin with. Clippy's own presence/tamper state is tracked
/// independently by [`resolve_optional_segment`], which
/// `wht_corulix_engine::diagnostics::resolve_clippy_binaries` consults
/// separately before ever invoking `cargo clippy`.
#[must_use]
pub fn resolve_owned_managed_component_detailed(
    root: &Path,
    manifest: &ManagedComponentManifest,
) -> (
    ManagedComponentState,
    Option<PathBuf>,
    Option<ManagedInvalidReason>,
) {
    let (state, path) = resolve_managed_component(root, manifest);
    if state != ManagedComponentState::Available {
        return (state, path, None);
    }
    let Some(path) = path else {
        return (ManagedComponentState::NotProvisioned, None, None);
    };

    let record = match ownership::load(root, manifest.id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return (
                ManagedComponentState::Corrupt,
                None,
                Some(ManagedInvalidReason::OwnershipMissing),
            );
        }
        Err(ownership::OwnershipError::RootIdentityMismatch) => {
            return (
                ManagedComponentState::Corrupt,
                None,
                Some(ManagedInvalidReason::RootIdentityMismatch),
            );
        }
        Err(_) => {
            return (
                ManagedComponentState::Corrupt,
                None,
                Some(ManagedInvalidReason::OwnershipMalformed),
            );
        }
    };

    if record.component_id != manifest.id.0 {
        return (
            ManagedComponentState::Corrupt,
            None,
            Some(ManagedInvalidReason::ComponentIdMismatch),
        );
    }
    if record.ownership != ownership::OwnershipClass::CorulixManaged {
        return (
            ManagedComponentState::Corrupt,
            None,
            Some(ManagedInvalidReason::OwnershipClassInvalid),
        );
    }
    if record.activation_state != ownership::ActivationState::Available {
        return (
            ManagedComponentState::Corrupt,
            None,
            Some(ManagedInvalidReason::ActivationInvalid),
        );
    }

    // M06 payload-verification-cache key: bound to the *whole* ownership
    // record via its own self-digest (`installation_manifest_digest`), plus
    // root/component/path identity for defense in depth -- see
    // `payload_verification_cache`'s own module doc comment for why this
    // alone makes the key sensitive to a reinstall/update/edit. Built once
    // here regardless of which branch below uses it, so both branches share
    // one cache implementation rather than two divergent ones.
    let cache_key = payload_verification_cache::CacheKey {
        managed_root_identity: ownership::root_identity(root),
        component_id: manifest.id.0.to_string(),
        canonical_component_root: record.canonical_component_root.clone(),
        installation_manifest_digest: record.installation_manifest_digest.clone(),
    };

    // Artifact integrity: only meaningful where `artifact_digest` is
    // proven to be the resolved single file's own *raw* hash --
    // `RawBinary` only. `GzippedBinary`'s digest is the compressed `.gz`
    // wrapper's own hash, verified before decompression, never the
    // decompressed executable's -- see
    // `ManagedInvalidReason::ArtifactIntegrityMismatch`'s own doc comment
    // for the real false-positive this pass hit (rust-analyzer) before
    // narrowing this from `RawBinary | GzippedBinary` down to `RawBinary`.
    if manifest.source.archive_kind == ArchiveKind::RawBinary {
        let current_fingerprint = payload_verification_cache::metadata_fingerprint_of_file(&path);
        let matches_recorded_digest = current_fingerprint.is_ok_and(|(fingerprint, modified)| {
            payload_verification_cache::get_or_compute(&cache_key, &fingerprint, || {
                let bytes =
                    fs::read(&path).map_err(|_| ProvisioningError::ContentVerificationFailed)?;
                let digest = ContentHash::compute_sha256(&bytes).digest_hex;
                Ok((fingerprint.clone(), digest, modified))
            })
            .is_ok_and(|digest| digest.eq_ignore_ascii_case(&record.artifact_digest))
        });
        if !matches_recorded_digest {
            return (
                ManagedComponentState::Corrupt,
                None,
                Some(ManagedInvalidReason::ArtifactIntegrityMismatch),
            );
        }
    } else if !record.installed_payload_digest.is_empty() {
        // Archive-derived component with a real installed-payload digest
        // recorded (i.e. acquired after this pass): re-verify it,
        // unconditionally -- see this function's own doc comment for why
        // an *empty* digest (a pre-existing legacy record) never reaches
        // this branch at all, and why the CORE boundary excluding declared
        // optional-segment paths is what makes unconditional enforcement
        // safe (P11-R1 conflict resolution).
        //
        // M06 performance fix: the expensive part -- reading and hashing
        // every byte of every file -- is skipped whenever a cheap,
        // synchronous, metadata-only re-scan (`metadata_fingerprint_of_*`)
        // proves the installed payload has not changed since the last time
        // *this process* proved the SHA-256 digest matched. SHA-256 remains
        // the sole cryptographic authority: a metadata mismatch, a metadata
        // read failure, or a cold (never-yet-verified-this-process) cache
        // key all fall through to exactly the same full recomputation this
        // function always performed before this fix.
        let component_root = component_install_dir(root, manifest);
        let exclude_paths = flattened_segment_paths(manifest.id.0);
        let recomputed = match manifest.source.archive_kind {
            ArchiveKind::GzippedBinary => payload_verification_cache::metadata_fingerprint_of_file(
                &path,
            )
            .and_then(|(fingerprint, modified)| {
                payload_verification_cache::get_or_compute(&cache_key, &fingerprint, || {
                    let digest = compute_single_file_installed_digest(&path)?;
                    Ok((fingerprint.clone(), digest, modified))
                })
            }),
            ArchiveKind::TarGz | ArchiveKind::TarBz2 | ArchiveKind::Zip => {
                payload_verification_cache::metadata_fingerprint_of_tree(
                    &component_root,
                    &exclude_paths,
                )
                .and_then(|(fingerprint, modified)| {
                    payload_verification_cache::get_or_compute(&cache_key, &fingerprint, || {
                        let digest =
                            compute_tree_installed_digest(&component_root, &exclude_paths)?;
                        Ok((fingerprint.clone(), digest, modified))
                    })
                })
            }
            ArchiveKind::RawBinary => {
                unreachable!("RawBinary is handled by the branch above")
            }
        };
        let matches_recorded_digest = recomputed
            .is_ok_and(|digest| digest.eq_ignore_ascii_case(&record.installed_payload_digest));
        if !matches_recorded_digest {
            return (
                ManagedComponentState::Corrupt,
                None,
                Some(ManagedInvalidReason::InstalledPayloadMismatch),
            );
        }
    }

    (ManagedComponentState::Available, Some(path), None)
}

/// Resolution-time verdict for one declared [`OptionalSegment`] of
/// `manifest`'s component, identified by `segment_id` (segment-aware model,
/// P11-R1 conflict resolution) -- independent of the owning component's own
/// core [`ManagedComponentState`] verdict from
/// [`resolve_owned_managed_component_detailed`].
///
/// An unknown `segment_id` (not declared via [`declared_optional_segments`]
/// for this component) reports [`SegmentState::Absent`] rather than
/// panicking -- fails toward "capability unavailable", never crashes a
/// caller over a typo or a stale id.
///
/// A segment whose declared `paths` are not *all* present is
/// [`SegmentState::Absent`] -- this is the "both or neither" granularity
/// `wht_corulix_engine::diagnostics::resolve_clippy_binaries` already
/// established for clippy specifically, generalized here. Only when every
/// declared path is present does this function attempt a digest
/// comparison: a legacy record with no digest recorded for this segment id
/// still reports `Available` (files present, nothing to compare against --
/// the same "empty means unenforced, never Trust-On-First-Use" rule as the
/// CORE digest), while a recorded-but-mismatching digest reports
/// [`SegmentState::Tampered`] -- which a caller like `resolve_clippy_binaries`
/// must never treat as merely `Absent`
/// (`OPTIONAL_PRESENT_TAMPERED_EXECUTABLE_ALLOWED=NO`).
#[must_use]
pub fn resolve_optional_segment(
    root: &Path,
    manifest: &ManagedComponentManifest,
    segment_id: &str,
) -> SegmentState {
    let Some(segment) = declared_optional_segments(manifest.id.0)
        .iter()
        .find(|candidate| candidate.id == segment_id)
    else {
        return SegmentState::Absent;
    };
    let component_root = component_install_dir(root, manifest);
    let all_present = segment
        .paths
        .iter()
        .all(|relative| component_root.join(relative).is_file());
    if !all_present {
        return SegmentState::Absent;
    }
    let Ok(Some(record)) = ownership::load(root, manifest.id) else {
        // No trustworthy ownership record to read a segment digest from --
        // the CORE resolution path already reports this as `Corrupt`
        // independently; from this segment's own narrower question ("is
        // *this* capability safe to use"), the honest answer without a
        // record to consult is "not affirmatively verified", not a
        // fabricated `Available`.
        return SegmentState::Absent;
    };
    let Some(recorded_digest) = record.optional_segment_digests.get(segment_id) else {
        // Legacy / never recorded for this segment -- can't verify, but
        // every declared path is genuinely present: no Trust-On-First-Use
        // upgrade happens here (nothing is written), just an honest
        // "present, unverified" treated as usable, matching the CORE
        // digest's own established empty-digest gate.
        return SegmentState::Available;
    };
    match compute_segment_digest(&component_root, segment.paths) {
        Ok(digest) if digest.eq_ignore_ascii_case(recorded_digest) => SegmentState::Available,
        _ => SegmentState::Tampered,
    }
}

/// The exact directory name Corulix creates for a managed component's own
/// runtime-generated scratch state (managed rust-analyzer's `CARGO_HOME`,
/// managed Go's `GOPATH`/`GOCACHE`/`GOMODCACHE` -- see
/// `wht_corulix_lsp::profile::resolve_launch_at`), always a direct child of
/// that component's own `component_install_dir`. Written *after*
/// installation completes, so it is never part of what was actually
/// installed -- excluded from `compute_tree_installed_digest`'s boundary
/// (Managed Installed-Payload Integrity pass, Section 9): hashing it would
/// make the managed Go/Rust runtimes self-invalidate the very first time
/// they are launched.
pub const COMPONENT_RUNTIME_SCRATCH_DIR_NAME: &str = ".corulix-scratch-home";

/// Deterministic SHA-256 over one installed, extracted file's raw bytes --
/// the `GzippedBinary` counterpart to `RawBinary`'s own `artifact_digest`
/// comparison above (Section 7: single-file installed-payload digest).
fn compute_single_file_installed_digest(path: &Path) -> Result<String, ProvisioningError> {
    let bytes = fs::read(path).map_err(|_| ProvisioningError::ContentVerificationFailed)?;
    Ok(ContentHash::compute_sha256(&bytes).digest_hex)
}

#[cfg(unix)]
fn is_executable_installed_entry(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_installed_entry(_metadata: &fs::Metadata) -> bool {
    false
}

/// Recursively collects every non-scratch entry under `dir` (as a path
/// relative to `root`) into `out`, skipping any relative path present in
/// `exclude` (Section 8/9 segment-aware model: a declared
/// [`OptionalSegment`]'s own paths are excluded from the CORE boundary this
/// way, exactly like [`COMPONENT_RUNTIME_SCRATCH_DIR_NAME`] -- both are
/// "known, separately-accounted-for, not part of the CORE identity"
/// exclusions, just at different granularities). Directories are recursed
/// into (never recorded as their own entry -- their presence is implied by
/// their descendants' relative paths); [`COMPONENT_RUNTIME_SCRATCH_DIR_NAME`]
/// is skipped entirely, wherever it appears, without recursing into it. A
/// symlinked directory is never recursed into
/// ([`std::fs::DirEntry::file_type`] does not follow symlinks), so it is
/// collected as a single leaf entry -- [`compute_tree_installed_digest`]
/// records its target string rather than walking through it.
fn collect_tree_entries(
    root: &Path,
    dir: &Path,
    exclude: &[&str],
    out: &mut Vec<PathBuf>,
) -> Result<(), ProvisioningError> {
    let entries = fs::read_dir(dir).map_err(|_| ProvisioningError::ContentVerificationFailed)?;
    for entry in entries {
        let entry = entry.map_err(|_| ProvisioningError::ContentVerificationFailed)?;
        let path = entry.path();
        if path.file_name().and_then(|name| name.to_str())
            == Some(COMPONENT_RUNTIME_SCRATCH_DIR_NAME)
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|_| ProvisioningError::ContentVerificationFailed)?;
        if file_type.is_dir() {
            collect_tree_entries(root, &path, exclude, out)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| ProvisioningError::ContentVerificationFailed)?
                .to_path_buf();
            if exclude
                .iter()
                .any(|excluded| relative == Path::new(excluded))
            {
                continue;
            }
            out.push(relative);
        }
    }
    Ok(())
}

/// Purely lexical (never touches the filesystem, never canonicalizes --
/// Architecture Rule F reserves real canonicalization to
/// `wht_corulix_workspace::canonicalize_external_path` alone, which is
/// `async` and unusable from this synchronous digest path) containment
/// check for a symlink's raw target. `link_dir` is the symlink's own
/// containing directory, expressed as path components relative to
/// `component_root`; `target` is the exact string [`std::fs::read_link`]
/// returned. Simulates resolving `target` against `link_dir` using only
/// path-component bookkeeping (a directory stack, popped on `..`) and
/// rejects an absolute target or one that pops above `component_root`
/// itself -- fails closed on anything ambiguous rather than guessing.
fn symlink_target_stays_confined(link_dir: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut stack: Vec<&std::ffi::OsStr> = Vec::new();
    for component in link_dir.components() {
        match component {
            std::path::Component::Normal(name) => stack.push(name),
            _ => return false,
        }
    }
    for component in target.components() {
        match component {
            std::path::Component::Normal(name) => stack.push(name),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if stack.pop().is_none() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// Encodes one tree entry (`relative`, resolved against `component_root`)
/// into `canonical_bytes` using the shared canonical per-entry format
/// (relative path, entry kind, executable bit, content-or-symlink-target)
/// -- factored out so [`compute_tree_installed_digest`] (a full recursive
/// walk) and [`compute_segment_digest`] (a fixed, explicit path list) can
/// never drift into two subtly different encodings of the same concept.
fn encode_tree_entry(
    component_root: &Path,
    relative: &Path,
    canonical_bytes: &mut Vec<u8>,
) -> Result<(), ProvisioningError> {
    let absolute = component_root.join(relative);
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|_| ProvisioningError::ContentVerificationFailed)?;
    canonical_bytes.extend_from_slice(relative.to_string_lossy().as_bytes());
    canonical_bytes.push(0);

    if metadata.file_type().is_symlink() {
        let target =
            fs::read_link(&absolute).map_err(|_| ProvisioningError::ContentVerificationFailed)?;
        let link_dir = relative.parent().unwrap_or_else(|| Path::new(""));
        if !symlink_target_stays_confined(link_dir, &target) {
            return Err(ProvisioningError::PathTraversalRejected);
        }
        canonical_bytes.extend_from_slice(b"symlink\0");
        canonical_bytes.extend_from_slice(target.to_string_lossy().as_bytes());
    } else if metadata.is_file() {
        let bytes =
            fs::read(&absolute).map_err(|_| ProvisioningError::ContentVerificationFailed)?;
        let file_digest = ContentHash::compute_sha256(&bytes).digest_hex;
        canonical_bytes.extend_from_slice(b"file\0");
        canonical_bytes.push(u8::from(is_executable_installed_entry(&metadata)));
        canonical_bytes.push(0);
        canonical_bytes.extend_from_slice(file_digest.as_bytes());
    } else {
        return Err(ProvisioningError::ContentVerificationFailed);
    }
    canonical_bytes.push(b'\n');
    Ok(())
}

/// Deterministic SHA-256 over an entire installed component tree rooted at
/// `component_root` (Section 8: multi-file installed-payload digest for
/// `TarGz`/`TarBz2`/`Zip`, including a merged multi-`additional_sources`
/// install such as the Rust semantic runtime) -- independent of directory-
/// traversal order, mtimes, or archive entry order: every regular file and
/// symlink under `component_root` (excluding
/// [`COMPONENT_RUNTIME_SCRATCH_DIR_NAME`] and every path named in
/// `exclude_segment_paths`, Section 9) is visited in deterministic lexical
/// relative-path order, and each entry is folded into one running hash via
/// [`encode_tree_entry`]. Refuses -- rather than silently following or
/// skipping -- a symlink whose target resolves outside `component_root`
/// (`TREE_DIGEST_WORKSPACE_ESCAPE_COUNT=0`), and refuses any entry that is
/// neither a regular file, a directory, nor a symlink (device node, socket,
/// FIFO, ...): both are unsafe/ambiguous input, never something to hash
/// around.
///
/// `exclude_segment_paths` is this component's own
/// [`declared_optional_segments`] paths flattened together -- the CORE
/// boundary this pass's segment-aware model requires (P11-R1 conflict
/// resolution): a declared segment's files are independently tracked by
/// [`compute_segment_digest`]/[`resolve_optional_segment`] instead, so
/// their presence, absence, or tampering never perturbs this digest.
fn compute_tree_installed_digest(
    component_root: &Path,
    exclude_segment_paths: &[&str],
) -> Result<String, ProvisioningError> {
    let mut relative_paths = Vec::new();
    collect_tree_entries(
        component_root,
        component_root,
        exclude_segment_paths,
        &mut relative_paths,
    )?;
    relative_paths.sort();

    let mut canonical_bytes = Vec::new();
    for relative in &relative_paths {
        encode_tree_entry(component_root, relative, &mut canonical_bytes)?;
    }
    Ok(ContentHash::compute_sha256(&canonical_bytes).digest_hex)
}

/// Deterministic SHA-256 over exactly one declared [`OptionalSegment`]'s own
/// `paths`, rooted at `component_root` -- the same canonical per-entry
/// encoding as [`compute_tree_installed_digest`] ([`encode_tree_entry`]),
/// reused so the two can never drift, but scoped to an explicit, fixed path
/// list rather than a full recursive directory walk. `paths` is sorted
/// lexically first (`TREE_DIGEST_DETERMINISTIC=PASS` applies to segments
/// too -- a manifest author's declaration order must not matter).
fn compute_segment_digest(
    component_root: &Path,
    paths: &[&str],
) -> Result<String, ProvisioningError> {
    let mut relative_paths: Vec<&Path> = paths.iter().map(Path::new).collect();
    relative_paths.sort_unstable();
    let mut canonical_bytes = Vec::new();
    for relative in relative_paths {
        encode_tree_entry(component_root, relative, &mut canonical_bytes)?;
    }
    Ok(ContentHash::compute_sha256(&canonical_bytes).digest_hex)
}

/// Every declared [`OptionalSegment`] path for `component_id`, flattened
/// into one list -- the exact `exclude_segment_paths` argument
/// [`compute_tree_installed_digest`] needs to keep the CORE boundary
/// disjoint from every independently-tracked segment.
fn flattened_segment_paths(component_id: &str) -> Vec<&'static str> {
    declared_optional_segments(component_id)
        .iter()
        .flat_map(|segment| segment.paths.iter().copied())
        .collect()
}

/// The full result of computing installed-payload identity for a freshly-
/// activated component (Section 10): the CORE digest/kind (everything
/// except declared optional-segment paths), plus one digest per declared
/// [`OptionalSegment`] that was fully present at acquisition time (a
/// segment not fully present yet -- unusual, since every real segment's
/// paths today are also in `required_paths` and therefore guaranteed
/// present before activation -- is simply left unrecorded, exactly like a
/// legacy record; never an acquisition failure on its own).
#[derive(Debug, PartialEq, Eq)]
struct ComputedInstalledPayload {
    core_digest: String,
    core_kind: ownership::InstalledPayloadKind,
    segment_digests: std::collections::BTreeMap<String, String>,
}

/// Computes the installed-payload digest for a freshly-activated component
/// (Section 10: acquisition-time recording, called from `provision_blocking`
/// before its ownership record is saved). `component_id` is the owning
/// manifest's own id (used only to look up [`declared_optional_segments`] --
/// taken as a plain `&str` rather than a full `&ManagedComponentManifest` so
/// this function's own pure-function tests never need to construct an
/// otherwise-irrelevant manifest just to exercise the digest algorithm).
/// Dispatches on `archive_kind`: `RawBinary` deliberately returns `None`
/// (Section 16 -- already covered by `artifact_digest`, must not be routed
/// through this mechanism at all), `GzippedBinary` uses the single-file
/// digest (segment exclusion is a no-op for a genuinely single-file
/// component -- no real one declares segments today), and
/// `TarGz`/`TarBz2`/`Zip` use the tree digest over `component_root` minus
/// every declared [`OptionalSegment`]'s paths, plus that segment's own
/// digest whenever its paths are all present.
fn compute_installed_payload_digest(
    archive_kind: ArchiveKind,
    component_id: &str,
    resolved_binary_path: &Path,
    component_root: &Path,
) -> Result<Option<ComputedInstalledPayload>, ProvisioningError> {
    match archive_kind {
        ArchiveKind::RawBinary => Ok(None),
        ArchiveKind::GzippedBinary => {
            let core_digest = compute_single_file_installed_digest(resolved_binary_path)?;
            Ok(Some(ComputedInstalledPayload {
                core_digest,
                core_kind: ownership::InstalledPayloadKind::SingleFile,
                segment_digests: std::collections::BTreeMap::new(),
            }))
        }
        ArchiveKind::TarGz | ArchiveKind::TarBz2 | ArchiveKind::Zip => {
            let exclude_paths = flattened_segment_paths(component_id);
            let core_digest = compute_tree_installed_digest(component_root, &exclude_paths)?;
            let mut segment_digests = std::collections::BTreeMap::new();
            for segment in declared_optional_segments(component_id) {
                let all_present = segment
                    .paths
                    .iter()
                    .all(|path| component_root.join(path).is_file());
                if all_present {
                    let digest = compute_segment_digest(component_root, segment.paths)?;
                    segment_digests.insert(segment.id.to_string(), digest);
                }
            }
            Ok(Some(ComputedInstalledPayload {
                core_digest,
                core_kind: ownership::InstalledPayloadKind::Tree,
                segment_digests,
            }))
        }
    }
}

/// The single, canonical, Corulix-exclusive relative location of every
/// *managed-root-level* execution cache/scratch subtree
/// (`<managed root>/scratch/...`).
///
/// # Why a fixed constant is the ownership metadata
///
/// Phase 15's cache closure §19 forbids "simples paths arbitrarios que
/// puedan apuntar fuera del managed root". The strongest available form of
/// that guarantee is not a stored path at all: the location is a compile-time
/// constant relative to the managed root, so there is no persisted string an
/// attacker or a corrupt record could redirect. Ownership is therefore
/// *structural* -- everything under `<root>/scratch/` was, by construction,
/// created by [`ensure_scratch_directory`] (this workspace's sole
/// filesystem-write authority for Corulix's own managed scratch state,
/// Architecture Rules M/G) on behalf of a governed execution, and is
/// consequently `OwnershipClass::CorulixManaged` state that
/// [`full_uninstall::full_uninstall`] must remove.
///
/// This deliberately does **not** introduce a parallel ownership class for
/// caches (§5). It also does not require a per-cache ownership *record*: a
/// record exists to bind a *variable* installed location and version to a
/// component identity, and none of that is variable here.
///
/// Scratch that belongs to one specific managed *component* (e.g. managed
/// rust-analyzer's `CARGO_HOME`/`HOME`, managed Go's `GOCACHE` for the LSP
/// vertical) is deliberately **not** here: it lives inside that component's
/// own `component_install_dir`, covered by the component's existing
/// `owned_paths`, and is removed by the ordinary per-component `uninstall`
/// pipeline. Only cross-component, per-*workspace* execution caches
/// (`go build`/`go test`/`cargo test` build caches, keyed by workspace path
/// rather than by component) live at the managed-root level.
pub const MANAGED_SCRATCH_DIR: &str = "scratch";

/// Ensures `root.join(relative)` exists (creating it and any missing
/// ancestors) and returns it -- a small, generically-named directory-
/// ensure helper for a managed component's own controlled scratch state
/// (e.g. managed rust-analyzer's `CARGO_HOME`/`HOME` scratch directory,
/// never the real user's `$HOME`) that legitimately lives under this
/// crate's sole filesystem-write authority (Architecture Rule M/G) rather
/// than duplicated as an ad hoc `fs::create_dir_all` call in a calling
/// crate.
pub fn ensure_scratch_directory(root: &Path, relative: &str) -> Result<PathBuf, ProvisioningError> {
    // Syntactic confinement BEFORE any filesystem write (Phase 15 cache
    // closure §19): `relative` is a plain `&str` from a calling crate, so
    // nothing upstream of this function already guaranteed it cannot contain
    // `..`, an absolute path, or a root/prefix component. Rejecting it here,
    // before `create_dir_all`, is what makes "a Corulix-owned scratch path is
    // always under the base root it was asked for" a structural property of
    // the single scratch-creation authority rather than a convention each
    // caller is trusted to follow (`P15_CACHE_OWNERSHIP_CONFINEMENT=PASS`).
    //
    // The complementary *canonical* (symlink-resolving) confinement check
    // deliberately lives at deletion time, in
    // `full_uninstall::cleanup_lifecycle_shells_and_root`, not here: this is
    // a synchronous function and only `wht_corulix_workspace` may
    // canonicalize (Architecture Rule F), whose canonicalization primitive
    // is async. More importantly, creation-time canonicalization would be
    // security theater -- an adversary substitutes a symlink *after*
    // creation, so the check that must hold is the one immediately before
    // Corulix removes anything (`P15_CACHE_PATH_CANONICALIZATION=PASS`,
    // `P15_CACHE_SYMLINK_ESCAPE_DELETE_COUNT=0`).
    let relative_path = Path::new(relative);
    if relative_path.as_os_str().is_empty()
        || relative_path.is_absolute()
        || !is_path_confined(relative_path)
    {
        return Err(ProvisioningError::ScratchPathNotConfined);
    }
    let dir = root.join(relative_path);
    fs::create_dir_all(&dir).map_err(|_| ProvisioningError::StagingDirectoryUnavailable)?;
    Ok(dir)
}

/// Writes `bytes` to `root.join(relative_dir).join(file_name)`, creating the
/// directory first via [`ensure_scratch_directory`] -- the write-side
/// counterpart, for a caller (e.g. `wht_corulix_engine::ts_validation`'s
/// Biome-lint staging) that needs to materialize a Corulix-owned scratch
/// *file*, not merely ensure a scratch *directory* exists. Kept in this
/// crate rather than the caller for the identical Architecture Rule M/G
/// reason [`ensure_scratch_directory`] already documents: this crate is the
/// sole filesystem-write authority for Corulix-owned (non-workspace)
/// state. `file_name` is confined the same way `relative` is.
pub fn write_scratch_file(
    root: &Path,
    relative_dir: &str,
    file_name: &str,
    bytes: &[u8],
) -> Result<PathBuf, ProvisioningError> {
    let dir = ensure_scratch_directory(root, relative_dir)?;
    let name_path = Path::new(file_name);
    if name_path.as_os_str().is_empty()
        || name_path.is_absolute()
        || !is_path_confined(name_path)
        || name_path.components().count() != 1
    {
        return Err(ProvisioningError::ScratchPathNotConfined);
    }
    let file_path = dir.join(name_path);
    fs::write(&file_path, bytes).map_err(|_| ProvisioningError::StagingDirectoryUnavailable)?;
    Ok(file_path)
}

/// Removes a single Corulix-owned scratch file previously returned by
/// [`write_scratch_file`]. Best-effort: a caller that only wants cleanup
/// (never load-bearing correctness) should ignore the `Result`, exactly as
/// `wht_corulix_engine::ts_validation::run_lint` does for its own staged
/// copy.
pub fn remove_scratch_file(path: &Path) -> Result<(), ProvisioningError> {
    fs::remove_file(path).map_err(|_| ProvisioningError::StagingDirectoryUnavailable)
}

fn unique_staging_dir(root: &Path, label: &str) -> Result<PathBuf, ProvisioningError> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let dir = root.join("staging").join(format!("{label}-{pid}-{stamp}"));
    fs::create_dir_all(&dir).map_err(|_| ProvisioningError::StagingDirectoryUnavailable)?;
    Ok(dir)
}

/// Downloads `url`'s response body, bounded by [`MAX_DOWNLOAD_BYTES`]. Runs
/// on a blocking thread (`ureq` is a synchronous client) -- callers must
/// invoke this from within `tokio::task::spawn_blocking`, never directly
/// from an async context.
fn download_bounded(url: &str) -> Result<Vec<u8>, ProvisioningError> {
    let response = ureq::get(url)
        .call()
        .map_err(|_| ProvisioningError::DownloadFailed)?;
    if !response.status().is_success() {
        return Err(ProvisioningError::DownloadFailed);
    }
    let body = response.into_body();
    let mut reader = body.into_reader().take(MAX_DOWNLOAD_BYTES + 1);
    let mut buffer = Vec::new();
    reader
        .read_to_end(&mut buffer)
        .map_err(|_| ProvisioningError::DownloadFailed)?;
    if buffer.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(ProvisioningError::DownloadTooLarge);
    }
    Ok(buffer)
}

/// Verifies `bytes` against `expected_sha256_hex` using this workspace's
/// existing dependency-free SHA-256 (`wht_corulix_core::ContentHash`).
fn verify_integrity(bytes: &[u8], expected_sha256_hex: &str) -> Result<(), ProvisioningError> {
    let actual = ContentHash::compute_sha256(bytes);
    if actual.digest_hex.eq_ignore_ascii_case(expected_sha256_hex) {
        Ok(())
    } else {
        Err(ProvisioningError::IntegrityMismatch)
    }
}

/// Returns `true` if `path`'s components contain no parent-directory (`..`)
/// or absolute/root/prefix component -- the two shapes a hostile tar entry
/// would use to write outside `staging_dir`.
fn is_path_confined(path: &Path) -> bool {
    path.components()
        .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

/// Dispatches extraction of `archive_bytes` into `staging_dir` on
/// `source.archive_kind`. Runs on a blocking thread, same contract as
/// [`download_bounded`].
fn extract_archive(
    archive_bytes: &[u8],
    staging_dir: &Path,
    source: &ManagedArtifactSource,
) -> Result<(), ProvisioningError> {
    match source.archive_kind {
        ArchiveKind::TarGz => extract_tar_gz(
            archive_bytes,
            staging_dir,
            source.symlink_policy,
            source.tar_root_prefix,
            source.extract_path_prefixes,
            source.post_extraction_symlinks,
        ),
        ArchiveKind::TarBz2 => extract_tar_bz2(
            archive_bytes,
            staging_dir,
            source.symlink_policy,
            source.tar_root_prefix,
            source.extract_path_prefixes,
            source.post_extraction_symlinks,
        ),
        ArchiveKind::GzippedBinary => {
            extract_gzipped_binary(archive_bytes, staging_dir, source.binary_path_in_tarball)
        }
        ArchiveKind::RawBinary => {
            extract_raw_binary(archive_bytes, staging_dir, source.binary_path_in_tarball)
        }
        ArchiveKind::Zip => extract_zip(
            archive_bytes,
            staging_dir,
            source.symlink_policy,
            source.tar_root_prefix,
            source.extract_path_prefixes,
            source.post_extraction_symlinks,
        ),
    }
}

/// Copies a bare, uncompressed single file directly to
/// `staging_dir.join(relative_path)`. No tar container and no compression,
/// so the only untrusted input is the byte stream itself, bounded by
/// [`MAX_EXTRACTED_BYTES`] -- mirrors [`extract_gzipped_binary`] exactly,
/// minus the `GzDecoder` stage.
fn extract_raw_binary(
    bytes: &[u8],
    staging_dir: &Path,
    relative_path: &str,
) -> Result<(), ProvisioningError> {
    let target = staging_dir.join(relative_path);
    if !is_path_confined(Path::new(relative_path)) || !target.starts_with(staging_dir) {
        return Err(ProvisioningError::PathTraversalRejected);
    }
    if bytes.len() as u64 > MAX_EXTRACTED_BYTES {
        return Err(ProvisioningError::ExtractedContentTooLarge);
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
    }
    fs::write(&target, bytes).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
    Ok(())
}

/// Decompresses a bare gzip-compressed single file directly to
/// `staging_dir.join(relative_path)`. No tar container, so no per-entry
/// path/symlink handling applies -- the only untrusted input is the byte
/// stream itself, bounded by [`MAX_EXTRACTED_BYTES`].
fn extract_gzipped_binary(
    gz_bytes: &[u8],
    staging_dir: &Path,
    relative_path: &str,
) -> Result<(), ProvisioningError> {
    let target = staging_dir.join(relative_path);
    if !is_path_confined(Path::new(relative_path)) || !target.starts_with(staging_dir) {
        return Err(ProvisioningError::PathTraversalRejected);
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
    }
    let mut decoder = flate2::read::GzDecoder::new(gz_bytes);
    let mut out =
        fs::File::create(&target).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
    let copied = std::io::copy(&mut decoder, &mut out)
        .map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
    if copied > MAX_EXTRACTED_BYTES {
        return Err(ProvisioningError::ExtractedContentTooLarge);
    }
    Ok(())
}

/// Extracts `tarball_bytes` (gzip-compressed tar) into `staging_dir`,
/// rejecting per-entry: any non-confined path (see [`is_path_confined`]),
/// and any entry type other than a plain file or directory. Symlink/
/// hard-link entries are handled per `symlink_policy`
/// ([`SymlinkPolicy::Reject`] aborts the whole archive on the first one;
/// [`SymlinkPolicy::AllowExactRelativePaths`] skips only an exact-matching
/// entry and still aborts the whole archive on any other symlink/hard-link
/// entry). Bounds total extracted bytes at [`MAX_EXTRACTED_BYTES`].
fn extract_tar_gz(
    tarball_bytes: &[u8],
    staging_dir: &Path,
    symlink_policy: SymlinkPolicy,
    tar_root_prefix: Option<&str>,
    extract_path_prefixes: &[&str],
    post_extraction_symlinks: &[(&str, &str)],
) -> Result<(), ProvisioningError> {
    let decompressed = flate2::read::GzDecoder::new(tarball_bytes);
    extract_tar_entries(
        decompressed,
        staging_dir,
        symlink_policy,
        tar_root_prefix,
        extract_path_prefixes,
        post_extraction_symlinks,
    )
}

/// Identical contract to [`extract_tar_gz`], decoding a bzip2-compressed tar
/// stream (`bzip2-rs`, pure Rust) instead of gzip. See
/// [`ArchiveKind::TarBz2`]'s own doc comment for why this codec exists.
fn extract_tar_bz2(
    tarball_bytes: &[u8],
    staging_dir: &Path,
    symlink_policy: SymlinkPolicy,
    tar_root_prefix: Option<&str>,
    extract_path_prefixes: &[&str],
    post_extraction_symlinks: &[(&str, &str)],
) -> Result<(), ProvisioningError> {
    let decompressed = bzip2_rs::DecoderReader::new(tarball_bytes);
    extract_tar_entries(
        decompressed,
        staging_dir,
        symlink_policy,
        tar_root_prefix,
        extract_path_prefixes,
        post_extraction_symlinks,
    )
}

/// Shared per-entry extraction loop behind [`extract_tar_gz`]/
/// [`extract_tar_bz2`] -- everything below this point is codec-agnostic:
/// path confinement, prefix re-rooting/filtering, symlink policy
/// enforcement, and the [`MAX_EXTRACTED_BYTES`] bound all operate on the
/// already-decompressed tar entry stream, so a bzip2-compressed archive
/// gets exactly the same security handling as a gzip-compressed one, not a
/// second, independently-maintained copy of it. `post_extraction_symlinks`
/// is applied only after every archive entry has been accepted -- see
/// [`ManagedArtifactSource::post_extraction_symlinks`]'s own doc comment.
fn extract_tar_entries<R: std::io::Read>(
    decompressed: R,
    staging_dir: &Path,
    symlink_policy: SymlinkPolicy,
    tar_root_prefix: Option<&str>,
    extract_path_prefixes: &[&str],
    post_extraction_symlinks: &[(&str, &str)],
) -> Result<(), ProvisioningError> {
    let mut archive = tar::Archive::new(decompressed);
    let entries = archive
        .entries()
        .map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;

    let mut total_bytes: u64 = 0;
    for entry in entries {
        let mut entry = entry.map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
        let entry_type = entry.header().entry_type();
        let raw_relative_path = entry
            .path()
            .map_err(|_| ProvisioningError::ArchiveExtractionFailed)?
            .into_owned();

        if !is_path_confined(&raw_relative_path) {
            return Err(ProvisioningError::PathTraversalRejected);
        }

        // Merged-prefix mode: entries outside `prefix` (e.g. this artifact's
        // top-level `install.sh`/`LICENSE-*`/`components` manifest files,
        // which the merged Rust semantic runtime has no use for) are
        // silently skipped rather than merged -- the archive's own integrity
        // was already proven by the whole-file SHA-256 check before
        // extraction began, so selecting a subtree of an already-trusted
        // archive is not a security-relevant rejection.
        let relative_path = match tar_root_prefix {
            Some(prefix) => match raw_relative_path.strip_prefix(prefix) {
                Ok(stripped) if stripped.as_os_str().is_empty() => continue,
                Ok(stripped) => stripped.to_path_buf(),
                Err(_) => continue,
            },
            None => raw_relative_path,
        };

        // Subtree filter (P12-R2's managed GNU link runtime): when the
        // artifact declares a non-empty allowlist, an entry whose path does
        // not start with any listed prefix is silently skipped -- same
        // "already-trusted archive, selecting a subtree is not a
        // security-relevant rejection" reasoning as the `tar_root_prefix`
        // skip immediately above, just a second, independent filter stage
        // rather than a second re-rooting.
        if !extract_path_prefixes.is_empty() {
            let path_str = relative_path.to_string_lossy();
            let matched = extract_path_prefixes
                .iter()
                .any(|prefix| path_str.starts_with(prefix));
            if !matched {
                continue;
            }
        }

        if entry_type.is_symlink() || entry_type.is_hard_link() {
            let allowed = match symlink_policy {
                SymlinkPolicy::Reject => false,
                SymlinkPolicy::AllowExactRelativePaths(paths) => paths
                    .iter()
                    .any(|allowed_path| relative_path == Path::new(allowed_path)),
            };
            if allowed {
                // Skipped, never created or followed -- an allowlisted
                // convenience symlink this component has no use for.
                continue;
            }
            // Not on the allowlist (or the policy is `Reject` outright):
            // fail the whole archive closed rather than guess.
            return Err(ProvisioningError::UnexpectedSymlinkRejected);
        }

        let target = staging_dir.join(&relative_path);
        if !target.starts_with(staging_dir) {
            return Err(ProvisioningError::PathTraversalRejected);
        }

        if entry_type.is_dir() {
            fs::create_dir_all(&target).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
            continue;
        }

        if !entry_type.is_file() {
            // Anything else (device node, fifo, ...) is refused: this
            // module extracts plain files and directories only.
            return Err(ProvisioningError::UnexpectedSymlinkRejected);
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
        }

        let entry_size = entry.header().size().unwrap_or(0);
        total_bytes = total_bytes.saturating_add(entry_size);
        if total_bytes > MAX_EXTRACTED_BYTES {
            return Err(ProvisioningError::ExtractedContentTooLarge);
        }

        let mut out =
            fs::File::create(&target).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
        std::io::copy(&mut entry, &mut out)
            .map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
        drop(out);
        // Preserve the archive entry's own executable bit. `fs::File::create`
        // writes every entry as a plain, non-executable file regardless of
        // what the tar header declares; a single-executable component (TS7/
        // Pyright/Node/rust-analyzer) papers over this because
        // `provision_blocking` separately `chmod +x`s only its one declared
        // `binary_path_in_tarball` -- but a merged multi-artifact component
        // (the Rust semantic runtime's `bin/cargo`, `bin/rustdoc`, etc.,
        // alongside `bin/rustc`) has more than one real executable, and
        // without this every one of them but the primary stayed mode 644,
        // producing a real `Permission denied (os error 13)` when
        // rust-analyzer tried to spawn the merged `cargo` -- found and fixed
        // during this phase's own real E2E run, not merely reasoned about.
        if let Ok(mode) = entry.header().mode() {
            preserve_executable_bit(&target, mode);
        }
    }

    for (link_relative, target_relative) in post_extraction_symlinks {
        create_post_extraction_symlink(staging_dir, link_relative, target_relative)?;
    }

    Ok(())
}

/// The standard IEEE 802.3 CRC-32 (reflected, polynomial `0xEDB88320`) --
/// the same algorithm ZIP's central directory records per entry. Written
/// dependency-free, table-based, the same "own a well-known, stable
/// algorithm rather than admit a crate for it" choice this workspace
/// already made for SHA-256 (`wht_corulix_core::ContentHash`); the table is
/// built once at first use and cached, never recomputed per entry.
fn crc32(bytes: &[u8]) -> u32 {
    fn table() -> &'static [u32; 256] {
        static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
        TABLE.get_or_init(|| {
            let mut table = [0u32; 256];
            let mut i = 0;
            while i < 256 {
                let mut value = i as u32;
                let mut j = 0;
                while j < 8 {
                    value = if value & 1 != 0 {
                        0xEDB8_8320 ^ (value >> 1)
                    } else {
                        value >> 1
                    };
                    j += 1;
                }
                table[i] = value;
                i += 1;
            }
            table
        })
    }
    let table = table();
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = table[index] ^ (crc >> 8);
    }
    !crc
}

/// Returns `true` if `raw_name` (a ZIP central-directory entry's filename,
/// as stored in the archive -- untrusted bytes, not yet a [`Path`]) is safe
/// to join onto a staging directory on *any* target platform, not only the
/// one this binary happens to run on. [`is_path_confined`] alone is not
/// enough here: it inspects [`Path`]'s own [`Component`] parsing, which is
/// platform-conditional -- on a Unix build (e.g. this crate's own test
/// suite, or a Linux CI runner validating a Windows-targeted manifest)
/// `Path::new("C:\\Windows\\evil.dll")` parses as a single harmless
/// `Normal` component, silently missing the drive-letter/backslash
/// traversal a real Windows extraction host would honor. So this checks
/// the raw archive string directly, textually, independent of the host
/// platform's own path semantics -- the ZIP security contract's exact
/// enumerated shapes (`../` traversal, absolute Windows path, drive-
/// prefixed path, UNC path, verbatim/device `\\?\` path, mixed-separator
/// traversal, a leading `/` root, an embedded NUL).
fn is_zip_entry_path_safe(raw_name: &str) -> bool {
    if raw_name.is_empty() || raw_name.contains('\0') {
        return false;
    }
    // UNC (`\\server\share\...`) and POSIX-root-relative-looking (`//...`)
    // prefixes, and the Windows verbatim/device prefix (`\\?\...`,
    // `\\.\...`), all begin with two consecutive separators.
    if raw_name.starts_with("\\\\") || raw_name.starts_with("//") {
        return false;
    }
    // A leading `/` or `\` is an absolute path on both platforms' own
    // conventions (Windows treats a leading `\` as root-of-current-drive).
    if raw_name.starts_with('/') || raw_name.starts_with('\\') {
        return false;
    }
    // A drive-letter prefix (`C:`, `d:`, ...) anywhere a path segment
    // could start one -- checked as "any `:` at all" rather than only
    // position 1: ZIP filenames have no legitimate use for `:` (NTFS
    // alternate-data-stream syntax is the same character), so this is a
    // strict, not merely drive-letter-shaped, rejection.
    if raw_name.contains(':') {
        return false;
    }
    // Split on *both* separators -- a hostile entry authored on a
    // Unix-style zip tool could embed a literal backslash, which a real
    // Windows extraction host still treats as a path separator even
    // though this parser's own splitting logic (below) only ever splits
    // on `/` per the ZIP spec's own normative separator.
    raw_name
        .split(['/', '\\'])
        .all(|segment| segment != ".." && segment != ".")
}

/// Extracts a PKZIP archive (`archive_bytes`) into `staging_dir` from its
/// central directory -- the authoritative entry index -- never from a
/// streamed pass over local file headers, which a hostile or corrupted
/// archive's local headers could disagree with (a real, structural
/// "confused deputy" vector this parser closes by construction rather than
/// by an extra check). Every entry is validated with
/// [`is_zip_entry_path_safe`] before anything is written, decompressed via
/// Stored (method `0`) or Deflate (method `8`) only, CRC-32-verified
/// against the entry's own central-directory-declared checksum, and bounds
/// total extracted bytes at [`MAX_EXTRACTED_BYTES`] -- the same contract
/// [`extract_tar_entries`] already holds the tar-based archive kinds to.
fn extract_zip(
    archive_bytes: &[u8],
    staging_dir: &Path,
    symlink_policy: SymlinkPolicy,
    root_prefix: Option<&str>,
    extract_path_prefixes: &[&str],
    post_extraction_symlinks: &[(&str, &str)],
) -> Result<(), ProvisioningError> {
    let entries = parse_zip_central_directory(archive_bytes)?;
    let mut seen_paths: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut total_bytes: u64 = 0;

    for entry in entries {
        if !is_zip_entry_path_safe(&entry.name) {
            return Err(ProvisioningError::PathTraversalRejected);
        }

        // A ZIP directory entry's name conventionally ends in `/`; such an
        // entry carries no data (uncompressed size `0`) and only needs its
        // directory created (mirrors the tar `entry_type.is_dir()` arm).
        let is_directory_entry = entry.name.ends_with('/');
        let normalized_name = entry.name.trim_end_matches('/');
        if normalized_name.is_empty() {
            continue;
        }
        let raw_relative_path = PathBuf::from(normalized_name.replace('\\', "/"));

        if !is_path_confined(&raw_relative_path) {
            return Err(ProvisioningError::PathTraversalRejected);
        }

        // Same merged-prefix re-rooting as `extract_tar_entries` -- an
        // artifact whose upstream layout wraps everything in one top-level
        // directory (e.g. `node-v24.19.0-win-x64/`) strips that wrapper so
        // `binary_path_in_tarball` can name the flat, post-extraction path.
        let relative_path = match root_prefix {
            Some(prefix) => match raw_relative_path.strip_prefix(prefix) {
                Ok(stripped) if stripped.as_os_str().is_empty() => continue,
                Ok(stripped) => stripped.to_path_buf(),
                Err(_) => continue,
            },
            None => raw_relative_path,
        };

        if !extract_path_prefixes.is_empty() {
            let path_str = relative_path.to_string_lossy();
            let matched = extract_path_prefixes
                .iter()
                .any(|prefix| path_str.starts_with(*prefix));
            if !matched {
                continue;
            }
        }

        // ZIP's only "symlink-like" representation this parser recognizes:
        // a Unix external-file-attribute mode (high 16 bits of
        // `external_attr`) whose file-type bits are `S_IFLNK` (`0xA000`).
        // No admitted Windows artifact this component set provisions is
        // expected to carry one (Node's official Windows build tool chain
        // never emits Unix mode bits), so `symlink_policy` mirrors the tar
        // contract exactly: `Reject` fails the whole archive closed on the
        // first one; `AllowExactRelativePaths` skips only an exact-matching
        // entry and still fails closed on any other.
        const S_IFLNK: u32 = 0xA000;
        const S_IFMT: u32 = 0xF000;
        let unix_mode = entry.external_attr >> 16;
        if unix_mode & S_IFMT == S_IFLNK {
            let allowed = match symlink_policy {
                SymlinkPolicy::Reject => false,
                SymlinkPolicy::AllowExactRelativePaths(paths) => paths
                    .iter()
                    .any(|allowed_path| relative_path == Path::new(allowed_path)),
            };
            if allowed {
                continue;
            }
            return Err(ProvisioningError::UnexpectedSymlinkRejected);
        }

        let path_key = relative_path.to_string_lossy().into_owned();
        if !seen_paths.insert(path_key) {
            return Err(ProvisioningError::ZipDuplicateEntryPath);
        }

        let target = staging_dir.join(&relative_path);
        if !target.starts_with(staging_dir) {
            return Err(ProvisioningError::PathTraversalRejected);
        }

        if is_directory_entry {
            fs::create_dir_all(&target).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
            continue;
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
        }

        let decompressed = decompress_zip_entry(archive_bytes, &entry)?;
        total_bytes = total_bytes.saturating_add(decompressed.len() as u64);
        if total_bytes > MAX_EXTRACTED_BYTES {
            return Err(ProvisioningError::ExtractedContentTooLarge);
        }
        if crc32(&decompressed) != entry.crc32 {
            return Err(ProvisioningError::ZipEntryCrc32Mismatch);
        }
        fs::write(&target, &decompressed)
            .map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
    }

    for (link_relative, target_relative) in post_extraction_symlinks {
        create_post_extraction_symlink(staging_dir, link_relative, target_relative)?;
    }

    Ok(())
}

/// One parsed ZIP central-directory entry: exactly the fields
/// [`extract_zip`] needs, already validated non-ZIP64 and range-checked
/// against `archive_bytes`'s own length.
struct ZipCentralDirectoryEntry {
    name: String,
    compression_method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
    external_attr: u32,
}

const ZIP_EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const ZIP_LOCAL_FILE_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const ZIP64_SENTINEL_U32: u32 = 0xFFFF_FFFF;

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, ProvisioningError> {
    bytes
        .get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
        .ok_or(ProvisioningError::ZipArchiveMalformed)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, ProvisioningError> {
    bytes
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        .ok_or(ProvisioningError::ZipArchiveMalformed)
}

/// Locates and parses the end-of-central-directory record, returning
/// `(central_directory_offset, central_directory_size, entry_count)`.
/// Scans backward from the end of `bytes` for the EOCD signature (the
/// trailing comment field is variable-length, up to 65535 bytes, so the
/// signature is not at a fixed offset) -- rejects a ZIP64 entry-count/
/// offset sentinel rather than silently truncating it.
fn locate_end_of_central_directory(bytes: &[u8]) -> Result<(u32, u32, u16), ProvisioningError> {
    const EOCD_FIXED_LEN: usize = 22;
    if bytes.len() < EOCD_FIXED_LEN {
        return Err(ProvisioningError::ZipArchiveMalformed);
    }
    let search_start = bytes.len().saturating_sub(EOCD_FIXED_LEN + 65_535);
    let window = &bytes[search_start..];
    let signature_offset = window
        .windows(4)
        .rposition(|candidate| candidate == ZIP_EOCD_SIGNATURE)
        .ok_or(ProvisioningError::ZipArchiveMalformed)?;
    let eocd_offset = search_start + signature_offset;
    let entry_count = read_u16_le(bytes, eocd_offset + 10)?;
    let cd_size = read_u32_le(bytes, eocd_offset + 12)?;
    let cd_offset = read_u32_le(bytes, eocd_offset + 16)?;
    if cd_size == ZIP64_SENTINEL_U32 || cd_offset == ZIP64_SENTINEL_U32 || entry_count == 0xFFFF {
        return Err(ProvisioningError::ZipArchiveMalformed);
    }
    Ok((cd_offset, cd_size, entry_count))
}

/// Parses every central directory entry, in order, validating each header
/// fits within `bytes` before reading its variable-length name and
/// rejecting any ZIP64 size/offset sentinel. Does not read local file
/// header or entry data at all -- that happens lazily, per entry, in
/// [`decompress_zip_entry`], only for entries [`extract_zip`] actually
/// decides to write.
fn parse_zip_central_directory(
    bytes: &[u8],
) -> Result<Vec<ZipCentralDirectoryEntry>, ProvisioningError> {
    let (cd_offset, cd_size, entry_count) = locate_end_of_central_directory(bytes)?;
    let cd_start = cd_offset as usize;
    let cd_end = cd_start
        .checked_add(cd_size as usize)
        .filter(|end| *end <= bytes.len())
        .ok_or(ProvisioningError::ZipArchiveMalformed)?;
    let mut entries = Vec::with_capacity(entry_count as usize);
    let mut offset = cd_start;

    for _ in 0..entry_count {
        const CD_HEADER_FIXED_LEN: usize = 46;
        if offset + CD_HEADER_FIXED_LEN > cd_end {
            return Err(ProvisioningError::ZipArchiveMalformed);
        }
        let signature = &bytes[offset..offset + 4];
        if signature != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
            return Err(ProvisioningError::ZipArchiveMalformed);
        }
        let compression_method = read_u16_le(bytes, offset + 10)?;
        let crc32_value = read_u32_le(bytes, offset + 16)?;
        let compressed_size = read_u32_le(bytes, offset + 20)?;
        let uncompressed_size = read_u32_le(bytes, offset + 24)?;
        let name_len = read_u16_le(bytes, offset + 28)? as usize;
        let extra_len = read_u16_le(bytes, offset + 30)? as usize;
        let comment_len = read_u16_le(bytes, offset + 32)? as usize;
        let external_attr = read_u32_le(bytes, offset + 38)?;
        let local_header_offset = read_u32_le(bytes, offset + 42)?;

        if compressed_size == ZIP64_SENTINEL_U32
            || uncompressed_size == ZIP64_SENTINEL_U32
            || local_header_offset == ZIP64_SENTINEL_U32
        {
            return Err(ProvisioningError::ZipArchiveMalformed);
        }

        let name_start = offset + CD_HEADER_FIXED_LEN;
        let name_end = name_start
            .checked_add(name_len)
            .filter(|end| *end <= cd_end)
            .ok_or(ProvisioningError::ZipArchiveMalformed)?;
        let name_bytes = &bytes[name_start..name_end];
        // ZIP filenames are UTF-8 when the general-purpose bit 11 (EFS) is
        // set; every real artifact this parser handles uses ASCII-only
        // names, so a strict UTF-8 decode (never a lossy fallback that
        // could silently rewrite a hostile non-UTF-8 name into something
        // that then passes [`is_zip_entry_path_safe`] differently than the
        // bytes the archive actually declared) is the fail-closed choice.
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ProvisioningError::ZipArchiveMalformed)?
            .to_string();

        entries.push(ZipCentralDirectoryEntry {
            name,
            compression_method,
            crc32: crc32_value,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            external_attr,
        });

        offset = name_end
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len))
            .filter(|end| *end <= cd_end)
            .ok_or(ProvisioningError::ZipArchiveMalformed)?;
    }

    Ok(entries)
}

/// Reads and decompresses one entry's data, located via its own central-
/// directory-declared `local_header_offset` -- the local file header's
/// *own* name/extra-field lengths are re-read (they need not equal the
/// central directory's, per the ZIP spec) purely to find where the
/// compressed data starts; every size/CRC used for verification comes from
/// the central directory (the authoritative copy), never the local header.
fn decompress_zip_entry(
    bytes: &[u8],
    entry: &ZipCentralDirectoryEntry,
) -> Result<Vec<u8>, ProvisioningError> {
    const LOCAL_HEADER_FIXED_LEN: usize = 30;
    let local_offset = entry.local_header_offset as usize;
    if local_offset + LOCAL_HEADER_FIXED_LEN > bytes.len() {
        return Err(ProvisioningError::ZipArchiveMalformed);
    }
    if bytes[local_offset..local_offset + 4] != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return Err(ProvisioningError::ZipArchiveMalformed);
    }
    let local_name_len = read_u16_le(bytes, local_offset + 26)? as usize;
    let local_extra_len = read_u16_le(bytes, local_offset + 28)? as usize;
    let data_start = local_offset
        .checked_add(LOCAL_HEADER_FIXED_LEN)
        .and_then(|value| value.checked_add(local_name_len))
        .and_then(|value| value.checked_add(local_extra_len))
        .ok_or(ProvisioningError::ZipArchiveMalformed)?;
    let data_end = data_start
        .checked_add(entry.compressed_size as usize)
        .filter(|end| *end <= bytes.len())
        .ok_or(ProvisioningError::ZipArchiveMalformed)?;
    let compressed = &bytes[data_start..data_end];

    match entry.compression_method {
        0 => {
            if compressed.len() as u64 != u64::from(entry.uncompressed_size) {
                return Err(ProvisioningError::ZipArchiveMalformed);
            }
            Ok(compressed.to_vec())
        }
        8 => {
            let mut decoder = flate2::read::DeflateDecoder::new(compressed);
            let mut out = Vec::with_capacity(entry.uncompressed_size as usize);
            let mut limited = (&mut decoder).take(u64::from(entry.uncompressed_size) + 1);
            limited
                .read_to_end(&mut out)
                .map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
            if out.len() as u64 != u64::from(entry.uncompressed_size) {
                return Err(ProvisioningError::ZipArchiveMalformed);
            }
            Ok(out)
        }
        _ => Err(ProvisioningError::ZipUnsupportedCompressionMethod),
    }
}

/// Creates one Corulix-authored, post-extraction compatibility symlink at
/// `staging_dir.join(link_relative)` pointing at the *relative* target
/// `target_relative` -- see
/// [`ManagedArtifactSource::post_extraction_symlinks`]'s own doc comment for
/// why this is a distinct, more trusted operation than the archive-entry
/// symlink handling above (both `link_relative` and `target_relative` are
/// this crate's own compile-time string constants, never archive-supplied
/// bytes). Both paths are confinement-checked exactly like every archive
/// entry (see [`is_path_confined`]) before any filesystem write.
fn create_post_extraction_symlink(
    staging_dir: &Path,
    link_relative: &str,
    target_relative: &str,
) -> Result<(), ProvisioningError> {
    if !is_path_confined(Path::new(link_relative)) || !is_path_confined(Path::new(target_relative))
    {
        return Err(ProvisioningError::PathTraversalRejected);
    }
    let link_path = staging_dir.join(link_relative);
    if !link_path.starts_with(staging_dir) {
        return Err(ProvisioningError::PathTraversalRejected);
    }
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent).map_err(|_| ProvisioningError::ArchiveExtractionFailed)?;
    }
    symlink_relative(target_relative, &link_path)
}

#[cfg(unix)]
fn symlink_relative(target_relative: &str, link_path: &Path) -> Result<(), ProvisioningError> {
    std::os::unix::fs::symlink(target_relative, link_path)
        .map_err(|_| ProvisioningError::ArchiveExtractionFailed)
}

#[cfg(not(unix))]
fn symlink_relative(_target_relative: &str, _link_path: &Path) -> Result<(), ProvisioningError> {
    // No admitted manifest declares `post_extraction_symlinks` on a
    // non-Unix platform today (the GNU link runtime is `platform: "linux"`
    // only, refused up front on any other host by
    // `validate_manifest_platform_architecture`) -- fails closed rather
    // than silently doing nothing if that ever changes.
    Err(ProvisioningError::ArchiveExtractionFailed)
}

/// Runs the full atomic provisioning pipeline for `manifest` under `root`:
/// download -> verify hash -> extract to staging -> verify content ->
/// atomic activate. Returns the canonical, ready-to-spawn binary path on
/// success. Never reports the component available if any stage fails --
/// an interrupted or rejected install leaves no trace in
/// [`component_install_dir`] (staging happens in a sibling directory that
/// is only ever renamed into place on full success, and is left behind
/// otherwise for operator inspection rather than silently retried into a
/// partially-trusted state).
pub async fn provision(
    root: &Path,
    manifest: &ManagedComponentManifest,
) -> Result<PathBuf, ProvisioningError> {
    provision_with_dependencies(root, manifest, &[]).await
}

/// Same pipeline as [`provision`], additionally recording `dependencies`
/// (other components' [`ManagedComponentId`] strings) into the persisted
/// [`ownership::ManagedInstallationRecord`] so [`uninstall::uninstall`] can
/// refuse to remove a shared dependency while a dependent is still
/// installed (e.g. Pyright depending on managed Node).
pub async fn provision_with_dependencies(
    root: &Path,
    manifest: &ManagedComponentManifest,
    dependencies: &[&'static str],
) -> Result<PathBuf, ProvisioningError> {
    if !root.is_absolute() {
        return Err(ProvisioningError::ManagedRootNotAbsolute);
    }
    if full_uninstall::recovery_locked(root) {
        return Err(ProvisioningError::RecoveryLocked);
    }
    // Shared (read) hold on the root-scoped lock: excludes a concurrent
    // `full_uninstall` (which holds it exclusively) for the duration of
    // this call, without serializing against any other individual
    // provision/uninstall of a *different* component id.
    let _root_guard = lock_root_shared(&ownership::root_identity(root)).await;
    // Single-flight: holds this component's lock, and each declared
    // dependency's own lock, for the whole operation, so a concurrent
    // `provision`/`uninstall` of the exact same component id, or of any
    // declared dependency, waits rather than racing the download/extract/
    // activate/ownership-write sequence below (real defect found and
    // fixed, Phase 7B-B2-B-R1: without holding dependency locks too, a
    // concurrent `uninstall` of an *already-installed* dependency could run
    // its `verify_not_depended_upon` scan in the window between this call
    // starting and its own ownership record -- the one that would have
    // declared the dependency -- being written, leaving `<primary>
    // Available + <dependency> NotProvisioned` once this call's own
    // activation completed).
    //
    // All locks this call needs (primary id + every dependency id) are
    // acquired in one fixed, canonical order -- sorted by component id
    // string, deduplicated -- rather than "primary first, then
    // dependencies in call-supplied order" (real second defect found and
    // fixed, Phase 7B-B2-C): the unordered version deadlocks for real. Two
    // concurrent calls `provision_with_dependencies(P, deps=[Q])` and
    // `provision_with_dependencies(Q, deps=[P])` would acquire `lock(P)`
    // then block on `lock(Q)` in one task while the other holds `lock(Q)`
    // and blocks on `lock(P)` -- a classic AB/BA deadlock, reproduced for
    // real (2 of 3 runs hung for a full 180s bounded timeout) by this
    // phase's own adversarial fixture test before this fix. Sorting first
    // guarantees any two calls whose lock sets overlap always acquire the
    // shared ids in the same global order, making a circular wait
    // structurally impossible regardless of which component is "primary"
    // in either call -- the standard total-lock-ordering deadlock
    // prevention technique, not a new locking primitive.
    let mut ids: Vec<&'static str> = Vec::with_capacity(1 + dependencies.len());
    ids.push(manifest.id.0);
    ids.extend(dependencies.iter().copied());
    ids.sort_unstable();
    ids.dedup();
    let _guards: Vec<_> = {
        let mut guards = Vec::with_capacity(ids.len());
        for id in &ids {
            guards.push(lock_component(id).await);
        }
        guards
    };
    // DEPENDENCY AVAILABILITY -- checked while still holding every declared
    // dependency's own lock (acquired immediately above), so no concurrent
    // uninstall of a dependency can complete between this check and this
    // call's own ownership-record write below.
    //
    // Real defect found and fixed here (Phase 7B-C-R2): the doc comment
    // above this block already describes holding dependency locks as
    // closing the "concurrent uninstall races this call's own activation"
    // window, and it does -- but that alone does not stop *this* call from
    // proceeding when a dependency was already removed by an `uninstall`
    // that acquired and released its lock entirely *before* this call
    // acquired its own copy of the same lock. Reproduced for real:
    // `provision_with_dependencies(rust-analyzer, [rust-semantic-runtime])`
    // raced via `tokio::join!` against a concurrent
    // `uninstall(rust-semantic-runtime)` -- when `uninstall` won the lock
    // race and completed first (dependency not yet depended-upon by any
    // ownership record, since this call had not started), this call still
    // went on to activate rust-analyzer and record a dependency on a
    // component that was, at that exact moment, already `NotProvisioned`
    // -- producing `rust-analyzer Available + rust-semantic-runtime
    // NotProvisioned`, silently violating the exact invariant
    // `provision_with_dependencies` exists to guarantee. Found via this
    // workspace's own mandatory full-suite sweep
    // (`real_b2c_dependency_race_matrix_e2e`), not dismissed as flaky per
    // that sweep's own governing instruction. Fixed by re-verifying every
    // declared dependency is genuinely owned-`Available` while still
    // holding its lock, before any download/extract/activate/ownership-
    // write for the primary component below -- fails closed
    // (`DependencyNotAvailable`) rather than silently recording a dangling
    // dependency edge.
    for dependency_id in &ids {
        if *dependency_id == manifest.id.0 {
            continue;
        }
        let dependency_owned_available = matches!(
            ownership::load(root, ManagedComponentId(dependency_id)),
            Ok(Some(record))
                if record.ownership == ownership::OwnershipClass::CorulixManaged
                    && record.activation_state == ownership::ActivationState::Available
        );
        if !dependency_owned_available {
            return Err(ProvisioningError::DependencyNotAvailable);
        }
    }
    // Double-checked: a concurrent call for this exact component may have
    // completed provisioning while this call waited for the lock. Without
    // this re-check, a second full download/extract/activate would still
    // run and its final `fs::rename` onto an already-populated
    // `install_dir` would fail (`ActivationFailed`) purely from losing a
    // race that single-flight locking is supposed to make impossible to
    // observe -- reported and fixed after a real, reproducible failure
    // observed running this crate's own concurrent real E2E tests.
    let (state, existing_path) = resolve_managed_component(root, manifest);
    if state == ManagedComponentState::Available
        && let Some(existing_path) = existing_path
    {
        return Ok(existing_path);
    }
    let root = root.to_path_buf();
    let manifest = *manifest;
    let dependencies: Vec<String> = dependencies.iter().map(|d| (*d).to_string()).collect();
    tokio::task::spawn_blocking(move || provision_blocking(&root, &manifest, &dependencies))
        .await
        .map_err(|_| ProvisioningError::ActivationFailed)?
}

/// F6 fix (`F6_PRODUCTION_MANAGED_PROVISIONING_UNREACHABLE`): resolves
/// `manifest` via [`resolve_owned_managed_component`] -- the strict,
/// ownership-record-verified check, never the weaker
/// [`resolve_managed_component`] a caller could use to decide whether an
/// unowned/corrupt artifact is safe to execute -- and, only if not
/// `Available`, attempts real managed acquisition via
/// [`provision_with_dependencies`] before re-resolving with the exact same
/// strict check.
///
/// This is the one production-reachable primitive that closes the gap
/// between [`provision_with_dependencies`] (fully implemented --
/// dependency-aware, single-flight, transactional -- but previously called
/// only from this workspace's own tests) and every real MCP-reachable
/// resolution path (`wht_corulix_lsp::profile::resolve_launch_at`/
/// `resolve_managed_or_system_path`,
/// `wht_corulix_formatter::managed::resolve_formatter`), which previously
/// only ever checked availability and failed closed without ever
/// attempting acquisition. Never trusts
/// [`provision_with_dependencies`]'s own `Ok` return as proof of a usable
/// component by itself -- the post-provision re-resolve is what proves the
/// newly-activated component is genuinely owned and available, matching
/// this product's own "verify integrity and ownership, then re-resolve"
/// contract for managed acquisition rather than trusting the acquisition
/// pipeline's exit status alone.
pub async fn resolve_or_acquire_owned(
    root: &Path,
    manifest: &ManagedComponentManifest,
    dependencies: &[&'static str],
) -> Result<PathBuf, ProvisioningError> {
    let (state, path) = resolve_owned_managed_component(root, manifest);
    if state == ManagedComponentState::Available
        && let Some(path) = path
    {
        return Ok(path);
    }
    provision_with_dependencies(root, manifest, dependencies).await?;
    let (state, path) = resolve_owned_managed_component(root, manifest);
    if state == ManagedComponentState::Available
        && let Some(path) = path
    {
        return Ok(path);
    }
    Err(ProvisioningError::ActivationFailed)
}

fn next_installation_sequence() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn provision_blocking(
    root: &Path,
    manifest: &ManagedComponentManifest,
    dependencies: &[String],
) -> Result<PathBuf, ProvisioningError> {
    // PLATFORM/ARCHITECTURE ADMISSION -- checked first, before any network
    // I/O or filesystem mutation, so a foreign-platform/architecture
    // manifest never reaches the download/extract/activate pipeline at all
    // (Phase 7B-B1-R3-B2-B1 Section 15-17).
    validate_manifest_platform_architecture(manifest)?;

    fs::create_dir_all(root).map_err(|_| ProvisioningError::ToolchainRootUnresolvable)?;

    // DOWNLOAD TO TEMP + VERIFY HASH, primary artifact
    let tarball_bytes = download_bounded(manifest.source.tarball_url)?;
    verify_integrity(&tarball_bytes, manifest.source.expected_sha256_hex)?;

    // EXTRACT/STAGE, primary artifact
    let staging_dir = unique_staging_dir(root, manifest.id.0)?;
    let extraction_result = extract_archive(&tarball_bytes, &staging_dir, &manifest.source);
    if let Err(error) = extraction_result {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(error);
    }

    // DOWNLOAD + VERIFY + EXTRACT every additional artifact into the *same*
    // staging directory, in declared order -- each one is independently
    // hash-verified before a single byte of it is extracted, exactly like
    // the primary artifact above.
    for additional in manifest.additional_sources {
        let additional_bytes = download_bounded(additional.tarball_url);
        let additional_bytes = match additional_bytes {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(error);
            }
        };
        if let Err(error) = verify_integrity(&additional_bytes, additional.expected_sha256_hex) {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(error);
        }
        if let Err(error) = extract_archive(&additional_bytes, &staging_dir, additional) {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(error);
        }
    }

    // VERIFY CONTENT (required-layout verification, against the final
    // *merged* staging directory): the primary binary, every declared
    // `required_paths` entry, and every declared `required_nonempty_dirs`
    // directory must exist. A skipped/absent entry -- or an additional
    // artifact that failed to merge as expected -- can therefore never
    // silently produce an incomplete, partially-usable provider; activation
    // is refused rather than guessed at.
    let staged_binary = staging_dir.join(manifest.source.binary_path_in_tarball);
    if !staged_binary.is_file() {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(ProvisioningError::ContentVerificationFailed);
    }
    for required in manifest.source.required_paths {
        if !staging_dir.join(required).is_file() {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(ProvisioningError::ContentVerificationFailed);
        }
    }
    for required_dir in manifest.source.required_nonempty_dirs {
        let dir = staging_dir.join(required_dir);
        let has_entry = fs::read_dir(&dir).is_ok_and(|mut entries| entries.next().is_some());
        if !has_entry {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(ProvisioningError::ContentVerificationFailed);
        }
    }
    set_executable(&staged_binary).map_err(|_| {
        let _ = fs::remove_dir_all(&staging_dir);
        ProvisioningError::ActivationFailed
    })?;

    // ATOMIC ACTIVATE
    let install_dir = component_install_dir(root, manifest);
    if let Some(parent) = install_dir.parent() {
        fs::create_dir_all(parent).map_err(|_| ProvisioningError::ActivationFailed)?;
    }
    fs::rename(&staging_dir, &install_dir).map_err(|_| {
        let _ = fs::remove_dir_all(&staging_dir);
        ProvisioningError::ActivationFailed
    })?;

    // COMPUTE INSTALLED-PAYLOAD DIGEST (Managed Installed-Payload Integrity
    // pass, Section 10): from the just-activated, trusted extraction --
    // content-identical to the staging directory an instant ago, since
    // `fs::rename` moves bytes, never mutates them -- and strictly *before*
    // the ownership record below stamps `activation_state: Available`.
    // `RawBinary` is deliberately excluded (Section 16: already covered by
    // `artifact_digest` re-verification; must not be routed through this
    // mechanism at all).
    let resolved_binary = install_dir.join(manifest.source.binary_path_in_tarball);
    let (installed_payload_digest, installed_payload_kind, optional_segment_digests) =
        match compute_installed_payload_digest(
            manifest.source.archive_kind,
            manifest.id.0,
            &resolved_binary,
            &install_dir,
        )? {
            Some(computed) => (
                computed.core_digest,
                computed.core_kind,
                computed.segment_digests,
            ),
            None => (
                String::new(),
                ownership::InstalledPayloadKind::SingleFile,
                std::collections::BTreeMap::new(),
            ),
        };

    // RECORD OWNERSHIP -- the freshly-activated install is now eligible for
    // uninstall::uninstall to remove; without this record it would be a
    // filesystem-present but ownership-unaccounted artifact, which
    // uninstall's fail-closed model treats as "not Corulix's to delete".
    let mut record = uninstall::build_record(
        root,
        uninstall::NewInstallation {
            component_id: manifest.id.0,
            version: manifest.version,
            platform: manifest.platform,
            architecture: manifest.architecture,
            canonical_component_root: install_dir.clone(),
            dependencies: dependencies.to_vec(),
            installation_sequence: next_installation_sequence(),
            artifact_digest: manifest.source.expected_sha256_hex.to_string(),
            ownership: ownership::OwnershipClass::CorulixManaged,
            installed_payload_digest,
            installed_payload_kind,
            optional_segment_digests,
        },
    );
    ownership::save(root, &mut record).map_err(|_| ProvisioningError::OwnershipManifestInvalid)?;
    // M06 payload-verification-cache hygiene: a fresh install's own
    // `installation_manifest_digest` already differs from any prior
    // installation's, so the new record's cache key can never collide with
    // an old attestation on its own -- this explicit invalidation exists so
    // a superseded attestation from a *previous* install of this exact
    // component id is dropped immediately rather than lingering, unused,
    // in the process-local cache for the rest of the process's lifetime.
    payload_verification_cache::invalidate_component(
        &ownership::root_identity(root),
        manifest.id.0,
    );

    // AVAILABLE
    Ok(install_dir.join(manifest.source.binary_path_in_tarball))
}

/// If `mode`'s owner-executable bit is set (the archive entry declared
/// itself executable), applies `0o755` to the already-extracted `path` --
/// best-effort, silently ignored on failure (never fails the whole
/// extraction over a permission-preservation step; the required-layout
/// verification and any later `execute()` spawn attempt are the real
/// enforcement points for "this file must actually be runnable").
#[cfg(unix)]
fn preserve_executable_bit(path: &Path, mode: u32) {
    const OWNER_EXECUTE_BIT: u32 = 0o100;
    if mode & OWNER_EXECUTE_BIT != 0 {
        let _ = set_executable(path);
    }
}

#[cfg(not(unix))]
fn preserve_executable_bit(_path: &Path, _mode: u32) {}

#[cfg(unix)]
fn set_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Recursively removes `dir`, first restoring owner-write permission on
/// every directory entry underneath it.
///
/// Real Go module cache (`GOMODCACHE`) entries are written by the Go
/// toolchain itself with directories mode `0555` (read-only,
/// corruption-protection by design -- the same reason the real `go clean
/// -modcache` command exists rather than a plain recursive delete being
/// sufficient)
/// -- a plain [`fs::remove_dir_all`] silently fails partway through such a
/// tree on Unix (permission denied descending into a `0555` directory),
/// which [`provision_go_module_build_blocking`]'s own best-effort cleanup
/// calls would otherwise swallow via `let _ = ...`, leaving real orphaned
/// `GOMODCACHE` bytes under `<root>/staging/` -- reproduced for real by this
/// crate's own `real_gopls_module_build_lifecycle_e2e` test, which failed
/// `full_uninstall`'s `CleanupRequired(["staging"])` residue check before
/// this helper existed. Best-effort by design (matches every other cleanup
/// call site in this module): a permission-restore failure on one entry does
/// not abort the walk, since the removal attempt immediately after this call
/// is itself already best-effort and any genuine residue still surfaces
/// through `full_uninstall`'s own residual-path enumeration rather than
/// being silently hidden.
fn remove_dir_all_best_effort(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fn restore_write_permissions(path: &Path) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };
            if metadata.is_symlink() {
                return;
            }
            if metadata.is_dir() {
                let mut permissions = metadata.permissions();
                let mode = permissions.mode() | 0o700;
                permissions.set_mode(mode);
                let _ = fs::set_permissions(path, permissions);
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        restore_write_permissions(&entry.path());
                    }
                }
            }
        }
        restore_write_permissions(dir);
    }
    let _ = fs::remove_dir_all(dir);
}

// ============================================================
// Managed source-build provisioning (P17-W gopls migration)
// ============================================================
//
// Real `go.dev`/npm/`static.rust-lang.org` distributions ship one file this
// crate can hash-verify byte-for-byte before extraction (see
// [`ManagedArtifactSource`]). `gopls` has no such artifact at all: its only
// real, official distribution model is `go install <module>@<version>`, a
// *source* build performed by a real Go toolchain -- there is no upstream
// prebuilt `gopls` binary Corulix could pin a hash against without either
// building one itself out-of-band (the abandoned R1/R3 model this pass
// migrates away from -- see `wht_corulix_lsp::managed_toolchain::GOPLS_LINUX_X64`'s
// own doc comment) or publishing its own unofficial mirror. This section adds
// a second, genuinely different provisioning primitive for that real
// distribution model, composed with -- not layered onto -- the existing
// download/extract/activate pipeline: same locking, same
// `ManagedComponentState`/`ownership`/`full_uninstall` machinery, same atomic
// rename-onto-`component_install_dir` activation, only the "how do the bytes
// that get activated come to exist" step differs.

/// One pinned Go module build recipe: the exact `<module_path>@<module_version>`
/// `go install` target this component's identity resolves to.
/// [`ManagedComponentManifest::source`]`.binary_path_in_tarball` on the
/// *same* manifest passed alongside this recipe names the output binary's
/// expected relative path (e.g. `"gopls"`/`"gopls.exe"`) -- deliberately not
/// duplicated onto this struct, so a manifest's install-path identity has
/// exactly one authority regardless of which provisioning primitive produced
/// it. This struct carries no `expected_sha256_hex`-equivalent: source-build
/// integrity is proven by the real Go module system itself (`GOSUMDB`
/// checksum-database verification against every module the build transitively
/// depends on, performed by the invoked `go` compiler during the build, not
/// re-implemented here) rather than by Corulix pinning one pre-known compiled-
/// binary digest -- compiled-binary reproducibility across environments is a
/// real, separate, harder guarantee this pass does not claim.
#[derive(Debug, Clone, Copy)]
pub struct GoModuleBuildSource {
    /// The Go module's import path, e.g. `"golang.org/x/tools/gopls"`.
    pub module_path: &'static str,
    /// The exact pinned module version `go install` resolves, e.g.
    /// `"v0.23.0"` -- never `"latest"` or a floating branch/tag.
    pub module_version: &'static str,
}

/// Builds and activates `manifest` from `build_source`'s pinned Go module
/// identity, using `compiler`'s own already-provisioned, owned-`Available`
/// managed Go toolchain as the build-time compiler -- never an ambient/system
/// `go`. Mirrors [`provision_with_dependencies`]'s locking, recovery-lock,
/// idempotency-short-circuit, and atomic-activate/ownership-record structure
/// exactly; only the "acquire the bytes to activate" step differs (a real
/// `go install` invocation instead of download+archive-extraction).
///
/// # Compiler dependency
///
/// `compiler` must already be `CorulixManaged`+`Available` on `root` (checked
/// under both components' locks, same "verified while holding the lock" fix
/// [`provision_with_dependencies`]'s own doc comment describes for its own
/// dependency check) -- this call never provisions the compiler itself.
/// `compiler.id.0` is recorded as this installation's own dependency, so
/// [`uninstall::uninstall`] refuses to remove the managed Go runtime while a
/// source-built component still depends on it, exactly like any other
/// declared dependency.
///
/// # Build isolation and supply-chain integrity
///
/// The invoked `go install` process:
/// - Runs with `Command::env_clear()` plus an explicit, minimal, typed
///   environment -- never inherits this process's own real environment,
///   never reads a hostile `$HOME/.netrc`/ambient credential.
/// - Resolves `go` by this call's own already-verified absolute
///   [`component_install_dir`] path, never by a `PATH` lookup of the name
///   `"go"` -- a hostile executable named `go`/`gopls` placed anywhere on an
///   ambient system `PATH` structurally cannot be invoked as the compiler,
///   because no `PATH`-based lookup of the compiler itself ever occurs.
/// - Sets `PATH` to *only* the managed compiler's own `bin/` directory --
///   Go's toolchain internally execs its own `compile`/`link`/`asm`
///   sub-tools via `GOROOT`, not `PATH`, but this is set anyway as
///   defense-in-depth against any Go-internal helper that does consult
///   `PATH`, and so a hostile `go.exe`/`gopls.exe` placed earlier on any
///   ambient `PATH` the parent process might otherwise have inherited can
///   never win even indirectly.
/// - Isolates `GOBIN`/`GOMODCACHE`/`GOCACHE`/`GOPATH`/`HOME` to fresh
///   subdirectories of a process-unique staging directory -- never the real
///   user's `$HOME`/`$GOPATH`, and never shared, racy state across
///   concurrent builds (each staging directory is single-flight-locked and
///   unique per invocation).
/// - Sets `GOPROXY=https://proxy.golang.org` and `GOSUMDB=sum.golang.org`
///   (the real official Go module proxy and checksum database -- module
///   fetch and per-module checksum verification are real network operations
///   here, not disabled/bypassed) -- never `GOSUMDB=off`, `GONOSUMCHECK`, an
///   insecure/mirror proxy, or `GOPROXY=direct` (which would additionally
///   permit a direct-VCS fallback outside the proxy+sumdb verification path
///   entirely).
/// - Sets `GOFLAGS=-mod=mod` (there is no pre-existing `go.mod` in this
///   ad hoc single-package install -- `go install pkg@version` operates
///   outside any local module at all, so `-mod=readonly`, which requires an
///   existing `go.mod`/`go.sum` to enforce readonly-ness against, does not
///   apply the way it does for [`crate`]-external callers analyzing a real
///   workspace's own module).
/// - Sets `GOTOOLCHAIN=local` (never let a hostile/newer module's own
///   `go.mod`/`toolchain` directive trigger an automatic download of a
///   *different* Go toolchain version than the one Corulix itself
///   provisioned and is invoking) and `GOVCS=off` (denies the Go command's
///   own direct-VCS-fetch fallback for any import path not satisfied by the
///   module proxy) and `GOENV=off` (a hostile `$HOME/.config/go/env` must
///   never be read -- the isolated `HOME` above already prevents this
///   structurally, `GOENV=off` closes the flag-level path too) and
///   `CGO_ENABLED=0` (`gopls` needs no cgo; this also removes any implicit
///   dependency on a system C compiler being resolvable at all).
///
/// # Errors
///
/// [`ProvisioningError::PlatformArchitectureMismatch`] if `manifest` does not
/// name this host; [`ProvisioningError::DependencyNotAvailable`] if
/// `compiler` is not currently owned-`Available`;
/// [`ProvisioningError::BuildFailed`] if the compiler process could not be
/// spawned, exited non-zero (invalid module identity, wrong/nonexistent
/// version, network/proxy failure, `GOSUMDB` checksum rejection, or a genuine
/// compile failure), or produced no binary at its expected `GOBIN` output
/// path; [`ProvisioningError::ActivationFailed`]/[`ProvisioningError::OwnershipManifestInvalid`]
/// for the same activation/ownership-write failure modes
/// [`provision_with_dependencies`] already reports. Every failure path
/// removes the staging directory before returning -- no partial `GOBIN`
/// output, module cache, or isolated `HOME` is left behind.
pub async fn provision_go_module_build(
    root: &Path,
    manifest: &ManagedComponentManifest,
    build_source: &GoModuleBuildSource,
    compiler: &ManagedComponentManifest,
) -> Result<PathBuf, ProvisioningError> {
    if full_uninstall::recovery_locked(root) {
        return Err(ProvisioningError::RecoveryLocked);
    }
    let _root_guard = lock_root_shared(&ownership::root_identity(root)).await;

    // Same fixed, sorted, deduplicated lock-acquisition order as
    // `provision_with_dependencies` -- deadlock-free regardless of which
    // component id is "primary" in any concurrent call.
    let mut ids: Vec<&'static str> = vec![manifest.id.0, compiler.id.0];
    ids.sort_unstable();
    ids.dedup();
    let _guards: Vec<_> = {
        let mut guards = Vec::with_capacity(ids.len());
        for id in &ids {
            guards.push(lock_component(id).await);
        }
        guards
    };

    // COMPILER AVAILABILITY -- checked while still holding the compiler's own
    // lock, so no concurrent `uninstall` of the compiler can complete between
    // this check and this call's own ownership-record write below (the exact
    // race `provision_with_dependencies`'s own dependency check closes).
    let compiler_owned_available = matches!(
        ownership::load(root, compiler.id),
        Ok(Some(record))
            if record.ownership == ownership::OwnershipClass::CorulixManaged
                && record.activation_state == ownership::ActivationState::Available
    );
    if !compiler_owned_available {
        return Err(ProvisioningError::DependencyNotAvailable);
    }

    // Idempotency short-circuit -- a concurrent build of this exact component
    // may have completed while this call waited for the lock.
    let (state, existing_path) = resolve_managed_component(root, manifest);
    if state == ManagedComponentState::Available
        && let Some(existing_path) = existing_path
    {
        return Ok(existing_path);
    }

    let root_owned = root.to_path_buf();
    let manifest_owned = *manifest;
    let build_source_owned = *build_source;
    let compiler_owned = *compiler;
    let dependencies = vec![compiler.id.0.to_string()];
    tokio::task::spawn_blocking(move || {
        provision_go_module_build_blocking(
            &root_owned,
            &manifest_owned,
            &build_source_owned,
            &compiler_owned,
            &dependencies,
        )
    })
    .await
    .map_err(|_| ProvisioningError::ActivationFailed)?
}

fn provision_go_module_build_blocking(
    root: &Path,
    manifest: &ManagedComponentManifest,
    build_source: &GoModuleBuildSource,
    compiler: &ManagedComponentManifest,
    dependencies: &[String],
) -> Result<PathBuf, ProvisioningError> {
    validate_manifest_platform_architecture(manifest)?;
    fs::create_dir_all(root).map_err(|_| ProvisioningError::ToolchainRootUnresolvable)?;

    // Re-resolve the compiler's real, already-verified binary path from disk
    // (never trust a caller-supplied path string) -- availability was already
    // proven under lock by the caller immediately above.
    let (compiler_state, compiler_binary) = resolve_managed_component(root, compiler);
    let compiler_binary = match (compiler_state, compiler_binary) {
        (ManagedComponentState::Available, Some(path)) => path,
        _ => return Err(ProvisioningError::DependencyNotAvailable),
    };
    let compiler_bin_dir = match compiler_binary.parent() {
        Some(parent) => parent.to_path_buf(),
        None => return Err(ProvisioningError::ActivationFailed),
    };
    let compiler_root = component_install_dir(root, compiler);

    // ISOLATED BUILD WORKSPACE -- everything the invoked Go toolchain writes
    // lives inside one process-unique staging directory; never the real
    // user's `$HOME`/`$GOPATH`.
    let staging_dir = unique_staging_dir(root, manifest.id.0)?;
    let gobin = staging_dir.join("gobin");
    let gomodcache = staging_dir.join("gomodcache");
    let gocache = staging_dir.join("gocache");
    let gopath = staging_dir.join("gopath");
    let isolated_home = staging_dir.join("home");
    for dir in [&gobin, &gomodcache, &gocache, &gopath, &isolated_home] {
        if fs::create_dir_all(dir).is_err() {
            remove_dir_all_best_effort(&staging_dir);
            return Err(ProvisioningError::StagingDirectoryUnavailable);
        }
    }

    let module_spec = format!(
        "{}@{}",
        build_source.module_path, build_source.module_version
    );

    let mut command = std::process::Command::new(&compiler_binary);
    command.env_clear();
    command.arg("install").arg(&module_spec);
    command.env("GOROOT", &compiler_root);
    command.env("GOBIN", &gobin);
    command.env("GOMODCACHE", &gomodcache);
    command.env("GOCACHE", &gocache);
    command.env("GOPATH", &gopath);
    command.env("HOME", &isolated_home);
    command.env("GOPROXY", "https://proxy.golang.org");
    command.env("GOSUMDB", "sum.golang.org");
    command.env("GOFLAGS", "-mod=mod");
    command.env("GOTOOLCHAIN", "local");
    command.env("GOVCS", "off");
    command.env("GOENV", "off");
    command.env("GO111MODULE", "on");
    command.env("CGO_ENABLED", "0");
    // Only the managed compiler's own `bin/` -- never ambient PATH.
    command.env("PATH", &compiler_bin_dir);
    // Real, native-Windows-verified requirement (P17-W gopls Windows
    // certification pass): a fully `env_clear()`'d child process on Windows
    // cannot resolve DNS at all -- `go install`'s real module-proxy fetch
    // failed with `getaddrinfow: A non-recoverable error occurred during a
    // database lookup` under this exact isolated environment on a real
    // native Windows host, empirically isolated (via a minimal repro against
    // the same managed compiler and staging layout) to the single missing
    // `SystemRoot` variable -- Windows' `GetAddrInfoW`/WinSock resolver
    // chain needs `SystemRoot` present to load its own system network
    // provider DLLs, unlike Linux's glibc resolver, which needs no
    // equivalent passthrough for `env_clear()`'d children. This has no
    // Linux/macOS analogue and is not a PATH/hostile-environment
    // regression: `SystemRoot` never contributes executable search
    // locations, only carries the fixed OS install directory
    // (`C:\Windows`) the resolver's own DLL loading already trusts
    // implicitly.
    #[cfg(target_os = "windows")]
    if let Ok(system_root) = std::env::var("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    command.current_dir(&isolated_home);

    let output = command.output();
    let output = match output {
        Ok(output) => output,
        Err(_) => {
            remove_dir_all_best_effort(&staging_dir);
            return Err(ProvisioningError::BuildFailed);
        }
    };
    if !output.status.success() {
        remove_dir_all_best_effort(&staging_dir);
        return Err(ProvisioningError::BuildFailed);
    }

    // `go install <module>@<version>` writes the built binary into `GOBIN`,
    // named after the package's own last import-path element (Windows: the
    // Go toolchain itself appends `.exe`) -- `manifest.source.binary_path_in_tarball`
    // is the single authority for that expected name, matching every other
    // provisioning primitive's own final layout.
    let built_binary = gobin.join(manifest.source.binary_path_in_tarball);
    if !built_binary.is_file() {
        remove_dir_all_best_effort(&staging_dir);
        return Err(ProvisioningError::BuildFailed);
    }
    set_executable(&built_binary).map_err(|_| {
        remove_dir_all_best_effort(&staging_dir);
        ProvisioningError::ActivationFailed
    })?;

    // ATOMIC ACTIVATE -- `gobin` itself becomes the canonical install
    // directory via a single rename, identical in kind to
    // `provision_blocking`'s own staging-directory rename (same filesystem,
    // same atomicity guarantee: `resolve_managed_component` can never observe
    // a half-written install).
    let install_dir = component_install_dir(root, manifest);
    if let Some(parent) = install_dir.parent()
        && fs::create_dir_all(parent).is_err()
    {
        remove_dir_all_best_effort(&staging_dir);
        return Err(ProvisioningError::ActivationFailed);
    }
    if fs::rename(&gobin, &install_dir).is_err() {
        remove_dir_all_best_effort(&staging_dir);
        return Err(ProvisioningError::ActivationFailed);
    }
    // The remainder of the staging directory (module cache, build cache,
    // isolated GOPATH/HOME) is build-time scratch only, never part of the
    // activated install -- removed now that the real output has been
    // relocated out of it.
    remove_dir_all_best_effort(&staging_dir);

    // RECORD OWNERSHIP. `artifact_digest` is the real produced binary's own
    // SHA-256, computed *after* the build (there is no pre-known upstream
    // digest to compare against for a source build) -- this is an honest
    // record of exactly what was activated, not a pre-pinned identity check.
    let activated_binary = install_dir.join(manifest.source.binary_path_in_tarball);
    let activated_bytes =
        fs::read(&activated_binary).map_err(|_| ProvisioningError::ActivationFailed)?;
    let artifact_digest = ContentHash::compute_sha256(&activated_bytes).digest_hex;

    let mut record = uninstall::build_record(
        root,
        uninstall::NewInstallation {
            component_id: manifest.id.0,
            version: manifest.version,
            platform: manifest.platform,
            architecture: manifest.architecture,
            canonical_component_root: install_dir.clone(),
            dependencies: dependencies.to_vec(),
            installation_sequence: next_installation_sequence(),
            artifact_digest,
            ownership: ownership::OwnershipClass::CorulixManaged,
            installed_payload_digest: String::new(),
            installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
            optional_segment_digests: std::collections::BTreeMap::new(),
        },
    );
    ownership::save(root, &mut record).map_err(|_| ProvisioningError::OwnershipManifestInvalid)?;

    Ok(activated_binary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Direct proof of the Phase 17-W-R15 `join_manifest_relative` fix.
    /// `Path::join` does not renormalize embedded separators inside the
    /// pushed component, so joining a native-separator base with a
    /// `&'static str` manifest literal always authored with forward
    /// slashes (e.g. `"package/lib/tsserver.js"`) would otherwise produce
    /// a mixed-separator string on Windows -- harmless to every Windows
    /// filesystem/`CreateProcess` API, but fatal to exactly one real
    /// consumer: `typescript-language-server`'s own `getTypeScriptVersion`
    /// resolves its module root via a strict `path.sep`-keyed split, which
    /// silently discards a `tsserver.path` containing any embedded `/`
    /// (root-caused via an isolated external repro against the real,
    /// unmodified `cli.mjs` before this fix was written). This test proves
    /// the join is fully native-separator on Windows and a strict no-op on
    /// every other platform (where `/` is already the only separator).
    #[test]
    fn join_manifest_relative_produces_native_separators_only() {
        let base = if cfg!(windows) {
            PathBuf::from(r"C:\managed\components\typescript-6-classic\6.0.3\windows-x64")
        } else {
            PathBuf::from("/managed/components/typescript-6-classic/6.0.3/linux-x64")
        };
        let joined = join_manifest_relative(&base, "package/lib/tsserver.js");
        let Some(joined_str) = joined.to_str() else {
            unreachable!("utf8 path")
        };
        if cfg!(windows) {
            assert!(
                !joined_str.contains('/'),
                "expected zero forward slashes in a Windows-joined manifest path, got {joined_str:?}"
            );
            assert!(joined_str.ends_with(r"windows-x64\package\lib\tsserver.js"));
        } else {
            assert!(joined_str.ends_with("linux-x64/package/lib/tsserver.js"));
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("corulix-provisioning-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    /// Direct proof of the P17-W Windows `PathEscapesManagedRoot` defect's
    /// real root cause: a caller-constructed managed root that is not
    /// absolute (e.g. produced by a caller's own environment-variable
    /// fallback bug, as `real_rust_analyzer_managed_lsp_semantic_cycle_e2e`
    /// hit on a Windows VM where `HOME` was present but empty) must be
    /// refused immediately, before any network I/O or filesystem mutation
    /// -- not allowed to silently resolve against the process's current
    /// directory for an entire provision/session/shutdown lifecycle and
    /// only surface as a confusing `uninstall::UninstallError::
    /// PathEscapesManagedRoot` once `uninstall()`'s own confinement
    /// re-check finally rejects it.
    #[tokio::test]
    async fn provision_with_dependencies_rejects_non_absolute_root() {
        let relative_root = PathBuf::from("relative-managed-root-should-be-rejected");
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("provisioning-non-absolute-root-test"),
            version: "1.0.0",
            platform: host_platform_identifier(),
            architecture: host_architecture_identifier(),
            source: ManagedArtifactSource {
                tarball_url: "https://example.invalid/artifact.tar.gz",
                expected_sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000",
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
        let result = provision_with_dependencies(&relative_root, &manifest, &[]).await;
        assert_eq!(result, Err(ProvisioningError::ManagedRootNotAbsolute));
    }

    /// Builds a raw in-memory tarball via [`tar::Builder::append`] (the
    /// low-level, unvalidated write path) with the path written directly
    /// into the header's raw name bytes -- unlike `append_data`/
    /// `append_path`, this performs none of the crate's own defensive
    /// path-sanitization, so it accurately simulates a hostile or corrupted
    /// archive's raw on-wire bytes for the extraction-safety tests below,
    /// which exist precisely to prove `extract_tarball` rejects what the
    /// crate's higher-level, cooperative API would refuse to construct in
    /// the first place.
    fn build_tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            {
                let name_field = header.as_old_mut().name.as_mut();
                let bytes = path.as_bytes();
                let copy_len = bytes.len().min(name_field.len());
                name_field[..copy_len].copy_from_slice(&bytes[..copy_len]);
            }
            header.set_cksum();
            builder
                .append(&header, *content)
                .unwrap_or_else(|_| unreachable!("in-memory tar append never fails in this test"));
        }
        let tar_bytes = builder
            .into_inner()
            .unwrap_or_else(|_| unreachable!("in-memory tar finish never fails in this test"));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder
            .write_all(&tar_bytes)
            .unwrap_or_else(|_| unreachable!("in-memory gzip write never fails in this test"));
        encoder
            .finish()
            .unwrap_or_else(|_| unreachable!("in-memory gzip finish never fails in this test"))
    }

    #[test]
    fn resolve_managed_component_reports_not_provisioned_when_absent() {
        let root = temp_root("absent");
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("does-not-exist"),
            version: "0.0.0",
            platform: "linux",
            architecture: "x64",
            source: ManagedArtifactSource {
                tarball_url: "https://example.invalid/does-not-matter.tgz",
                expected_sha256_hex: "0",
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
        let (state, path) = resolve_managed_component(&root, &manifest);
        assert_eq!(state, ManagedComponentState::NotProvisioned);
        assert_eq!(path, None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_managed_component_reports_available_once_activated() {
        let root = temp_root("activated");
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("fixture"),
            version: "1.0.0",
            platform: "linux",
            architecture: "x64",
            source: ManagedArtifactSource {
                tarball_url: "https://example.invalid/does-not-matter.tgz",
                expected_sha256_hex: "0",
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
        let install_dir = component_install_dir(&root, &manifest);
        let binary_path = install_dir.join("package/lib/tsc");
        let _ = fs::create_dir_all(binary_path.parent().unwrap_or(&install_dir));
        let _ = fs::write(&binary_path, b"fixture binary");
        let (state, path) = resolve_managed_component(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Available);
        assert_eq!(path, Some(binary_path));
        let _ = fs::remove_dir_all(&root);
    }

    /// R3-B §21: a pre-ownership orphan artifact -- present on disk at the
    /// exact expected path, but with no ownership record, exactly as if
    /// some means other than a completed `provision_with_dependencies` run
    /// (a partially-failed prior install crashed after activation but
    /// before `ownership::save`, or a byte-identical file placed there by
    /// something other than Corulix) had put it there -- must never be
    /// treated as executable-`Available`. `resolve_managed_component` alone
    /// (the pure filesystem check other tests above exercise) *does* report
    /// `Available` here; `resolve_owned_managed_component` is the execution-
    /// authority function every real spawn call site must use instead, and
    /// must refuse it.
    #[test]
    fn resolve_owned_managed_component_refuses_a_pre_ownership_orphan_artifact() {
        let root = temp_root("orphan-no-ownership");
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("fixture-orphan"),
            version: "1.0.0",
            platform: "linux",
            architecture: "x64",
            source: ManagedArtifactSource {
                tarball_url: "https://example.invalid/does-not-matter.tgz",
                expected_sha256_hex: "0",
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
        let install_dir = component_install_dir(&root, &manifest);
        let binary_path = install_dir.join("package/lib/tsc");
        let _ = fs::create_dir_all(binary_path.parent().unwrap_or(&install_dir));
        let _ = fs::write(&binary_path, b"orphan binary -- no ownership record exists");

        // The pure filesystem check alone would (correctly, for its own
        // purpose) call this Available.
        let (raw_state, _) = resolve_managed_component(&root, &manifest);
        assert_eq!(raw_state, ManagedComponentState::Available);

        // The execution-authority check must refuse it: no ownership record
        // was ever written for this component id under this root. Managed-
        // toolchain ownership/integrity hardening pass: this is now
        // `Corrupt`, not `NotProvisioned` -- an orphan artifact is a
        // present-but-invalid state, indistinguishable from a planted
        // foreign binary, and must never be treated as merely "not yet
        // provisioned" (which would make it eligible for an explicit
        // approved `HOST_ONLY` fallback at a caller like
        // `wht_corulix_lsp::profile::resolve_managed_or_system_path`).
        let (owned_state, owned_path, reason) =
            resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(owned_state, ManagedComponentState::Corrupt);
        assert_eq!(owned_path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::OwnershipMissing));

        let _ = fs::remove_dir_all(&root);
    }

    /// The positive counterpart: once a genuine `CorulixManaged` ownership
    /// record is on disk for the same component, execution authority is
    /// granted.
    #[test]
    fn resolve_owned_managed_component_allows_a_genuinely_owned_artifact() {
        let root = temp_root("orphan-with-ownership");
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("fixture-owned"),
            version: "1.0.0",
            platform: "linux",
            architecture: "x64",
            source: ManagedArtifactSource {
                tarball_url: "https://example.invalid/does-not-matter.tgz",
                expected_sha256_hex: "0",
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
        let install_dir = component_install_dir(&root, &manifest);
        let binary_path = install_dir.join("package/lib/tsc");
        let _ = fs::create_dir_all(binary_path.parent().unwrap_or(&install_dir));
        let _ = fs::write(&binary_path, b"owned binary");

        let mut record = uninstall::build_record(
            &root,
            uninstall::NewInstallation {
                component_id: manifest.id.0,
                version: manifest.version,
                platform: manifest.platform,
                architecture: manifest.architecture,
                canonical_component_root: install_dir.clone(),
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest: "0".to_string(),
                ownership: ownership::OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        assert!(
            ownership::save(&root, &mut record).is_ok(),
            "ownership record must save"
        );

        let (owned_state, owned_path) = resolve_owned_managed_component(&root, &manifest);
        assert_eq!(owned_state, ManagedComponentState::Available);
        assert_eq!(owned_path, Some(binary_path));

        let _ = fs::remove_dir_all(&root);
    }

    /// Managed-toolchain ownership/integrity hardening pass, regression
    /// matrix (Section 12): builds one genuinely valid, owned component
    /// under its own disposable, uniquely-stamped isolated `root` (never
    /// the real `managed_toolchain_root()` -- Section 13), then returns
    /// enough to let each test corrupt exactly one aspect and confirm it
    /// fails closed as `Corrupt` with the specific `ManagedInvalidReason`,
    /// never as `NotProvisioned` (which would make it eligible for an
    /// explicit approved `HOST_ONLY` fallback at a caller like
    /// `wht_corulix_lsp::profile::resolve_managed_or_system_path`).
    fn install_valid_component(
        label: &str,
        archive_kind: ArchiveKind,
        binary_bytes: &[u8],
    ) -> (PathBuf, ManagedComponentManifest, PathBuf) {
        let root = temp_root(label);
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("fixture-hardening"),
            version: "1.0.0",
            platform: "linux",
            architecture: "x64",
            source: ManagedArtifactSource {
                tarball_url: "https://example.invalid/does-not-matter.tgz",
                expected_sha256_hex: "0",
                binary_path_in_tarball: "bin/tool",
                archive_kind,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: None,
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            additional_sources: &[],
        };
        let install_dir = component_install_dir(&root, &manifest);
        let binary_path = install_dir.join("bin/tool");
        let _ = fs::create_dir_all(binary_path.parent().unwrap_or(&install_dir));
        let _ = fs::write(&binary_path, binary_bytes);

        let artifact_digest = ContentHash::compute_sha256(binary_bytes).digest_hex;
        let mut record = uninstall::build_record(
            &root,
            uninstall::NewInstallation {
                component_id: manifest.id.0,
                version: manifest.version,
                platform: manifest.platform,
                architecture: manifest.architecture,
                canonical_component_root: install_dir,
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest,
                ownership: ownership::OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        assert!(
            ownership::save(&root, &mut record).is_ok(),
            "ownership record must save"
        );
        (root, manifest, binary_path)
    }

    /// Case A (regression matrix baseline): a genuinely valid, owned
    /// component -- including a `RawBinary` component whose digest matches
    /// -- resolves `Available`, never `Corrupt`. The digest check
    /// introduced by this pass must not produce false positives against a
    /// real, untampered installation.
    #[test]
    fn regression_matrix_a_valid_raw_binary_component_resolves_available() {
        let (root, manifest, binary_path) =
            install_valid_component("hardening-a-valid", ArchiveKind::RawBinary, b"real tool v1");
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Available);
        assert_eq!(path, Some(binary_path));
        assert_eq!(reason, None);
        let _ = fs::remove_dir_all(&root);
    }

    /// Case C: the ownership record file exists but is not valid JSON.
    /// Must fail closed as `Corrupt`/`OwnershipMalformed`, never
    /// `NotProvisioned`.
    #[test]
    fn regression_matrix_c_malformed_ownership_file_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, _binary_path) =
            install_valid_component("hardening-c-malformed", ArchiveKind::TarGz, b"real tool v1");
        let record_path = root.join("ownership").join("fixture-hardening.json");
        fs::write(&record_path, b"{ not valid json at all")?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::OwnershipMalformed));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Case D: the ownership record's own `managed_root_identity` no longer
    /// matches the root it is being loaded from (e.g. copied from a
    /// different managed root). Must fail closed as
    /// `Corrupt`/`RootIdentityMismatch`, never `NotProvisioned`.
    #[test]
    fn regression_matrix_d_root_identity_mismatch_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, _binary_path) = install_valid_component(
            "hardening-d-root-mismatch",
            ArchiveKind::TarGz,
            b"real tool v1",
        );
        let record_path = root.join("ownership").join("fixture-hardening.json");
        let bytes = fs::read(&record_path)?;
        let mut record: ownership::ManagedInstallationRecord = serde_json::from_slice(&bytes)?;
        record.managed_root_identity = "deliberately-wrong-root-identity".to_string();
        assert!(
            ownership::save(&root, &mut record).is_ok(),
            "corrupted-identity record must still save (re-stamps its own manifest digest)"
        );
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::RootIdentityMismatch));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Case E: the ownership record loads fine and is internally
    /// self-consistent, but its own `component_id` disagrees with the
    /// manifest identity this resolution was requested for. Never checked
    /// before this pass. Must fail closed as `Corrupt`/`ComponentIdMismatch`,
    /// never silently accepted as `Available`.
    #[test]
    fn regression_matrix_e_component_id_mismatch_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, _binary_path) = install_valid_component(
            "hardening-e-component-mismatch",
            ArchiveKind::TarGz,
            b"real tool v1",
        );
        // `ownership::save` derives its target filename from the record's
        // own `component_id` field, so saving through it after mutating
        // that field would write a *second* file
        // (`a-completely-different-component.json`), leaving
        // `fixture-hardening.json` -- the file this resolution actually
        // reads -- untouched. Writing directly to the known path (mirroring
        // `digest_of`'s exact algorithm: blank the digest field, hash the
        // canonical JSON, restamp it) is what genuinely exercises "the file
        // this manifest resolves to contains a mismatched identity".
        let record_path = root.join("ownership").join("fixture-hardening.json");
        let bytes = fs::read(&record_path)?;
        let mut record: ownership::ManagedInstallationRecord = serde_json::from_slice(&bytes)?;
        record.component_id = "a-completely-different-component".to_string();
        record.installation_manifest_digest = String::new();
        let for_digest = serde_json::to_vec(&record)?;
        record.installation_manifest_digest = ContentHash::compute_sha256(&for_digest).digest_hex;
        fs::write(&record_path, serde_json::to_vec_pretty(&record)?)?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::ComponentIdMismatch));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Case F: the ownership record is otherwise fully valid, but its
    /// `activation_state` is not `Available` (e.g. mid-`full_uninstall`).
    /// Must fail closed as `Corrupt`/`ActivationInvalid`, never
    /// `NotProvisioned`.
    #[test]
    fn regression_matrix_f_activation_state_invalid_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, _binary_path) = install_valid_component(
            "hardening-f-activation-invalid",
            ArchiveKind::TarGz,
            b"real tool v1",
        );
        let record_path = root.join("ownership").join("fixture-hardening.json");
        let bytes = fs::read(&record_path)?;
        let mut record: ownership::ManagedInstallationRecord = serde_json::from_slice(&bytes)?;
        record.activation_state = ownership::ActivationState::Uninstalling;
        assert!(
            ownership::save(&root, &mut record).is_ok(),
            "activation-invalid record must still save"
        );
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::ActivationInvalid));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Case G: the resolved binary's own bytes were mutated after
    /// installation (a `RawBinary`-kind component, where `artifact_digest`
    /// is proven to be the resolved file's own hash -- see
    /// `ManagedInvalidReason::ArtifactIntegrityMismatch`'s own doc
    /// comment). Must fail closed as `Corrupt`/`ArtifactIntegrityMismatch`,
    /// never `NotProvisioned`, and never resolve `Available`.
    #[test]
    fn regression_matrix_g_tampered_raw_binary_artifact_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, binary_path) = install_valid_component(
            "hardening-g-tampered",
            ArchiveKind::RawBinary,
            b"real tool v1",
        );
        fs::write(
            &binary_path,
            b"tampered bytes -- not the installed artifact",
        )?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(
            reason,
            Some(ManagedInvalidReason::ArtifactIntegrityMismatch)
        );
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Negative control, Case G's own scope disclosure re: `artifact_digest`
    /// (unchanged by the Managed Installed-Payload Integrity pass): a
    /// `TarGz` component's `artifact_digest` is the original archive's own
    /// hash, not any single extracted file's, so tampering with the one
    /// resolved file must NOT be (falsely) reported as an `artifact_digest`
    /// mismatch. This same fixture also demonstrates the *new* pass's own
    /// deliberately-gated legacy behavior: [`install_valid_component`] never
    /// populates `installed_payload_digest` (it builds records the way this
    /// crate always has, matching every real pre-pass installation), so this
    /// tamper is not caught by the new mechanism either -- not because the
    /// new digest is inapplicable to `TarGz` (it is: see
    /// `payload_integrity_b_tree_tamper_fails_closed` below for the same
    /// tamper genuinely detected once a real digest is recorded), but
    /// because an *empty* `installed_payload_digest` is a legacy record this
    /// pass deliberately does not enforce against yet (see
    /// `resolve_owned_managed_component_detailed`'s own doc comment,
    /// `ARCHIVE_DERIVED_RUNTIME_INTEGRITY_STATUS=PARTIAL`).
    #[test]
    fn regression_matrix_g_archive_based_component_digest_check_is_not_applicable()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, binary_path) = install_valid_component(
            "hardening-g-archive-not-applicable",
            ArchiveKind::TarGz,
            b"real tool v1",
        );
        fs::write(
            &binary_path,
            b"tampered bytes -- not the installed artifact",
        )?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(
            state,
            ManagedComponentState::Available,
            "a legacy TarGz record with no installed_payload_digest is not (yet) enforced -- \
             the disclosed, gated gap, not a regression"
        );
        assert_eq!(path, Some(binary_path));
        assert_eq!(reason, None);
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Builds a genuinely valid, owned archive-derived component *with* a
    /// real `installed_payload_digest` recorded (i.e. simulating a
    /// component acquired after the Managed Installed-Payload Integrity
    /// pass, via the same product functions `provision_blocking` itself
    /// uses) -- as opposed to [`install_valid_component`], which
    /// deliberately leaves it empty to model a pre-pass legacy record.
    /// `files` are written relative to the component root in the given
    /// order (deliberately not pre-sorted, so callers can also use this to
    /// prove order-independence by passing the same set in a different
    /// order).
    fn install_valid_component_with_installed_payload_digest(
        label: &str,
        archive_kind: ArchiveKind,
        files: &'static [(&'static str, &'static [u8])],
    ) -> (PathBuf, ManagedComponentManifest, PathBuf) {
        let root = temp_root(label);
        let primary_relative = files
            .first()
            .map(|(relative, _)| *relative)
            .unwrap_or("bin/tool");
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("fixture-hardening"),
            version: "1.0.0",
            platform: "linux",
            architecture: "x64",
            source: ManagedArtifactSource {
                tarball_url: "https://example.invalid/does-not-matter.tgz",
                expected_sha256_hex: "0",
                binary_path_in_tarball: primary_relative,
                archive_kind,
                symlink_policy: SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: None,
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            additional_sources: &[],
        };
        let install_dir = component_install_dir(&root, &manifest);
        for (relative, bytes) in files {
            let target = install_dir.join(relative);
            let _ = fs::create_dir_all(target.parent().unwrap_or(&install_dir));
            let _ = fs::write(&target, bytes);
        }
        let resolved_binary = install_dir.join(primary_relative);
        let computed = compute_installed_payload_digest(
            archive_kind,
            manifest.id.0,
            &resolved_binary,
            &install_dir,
        )
        .unwrap_or_else(|error| {
            unreachable!("test fixture digest computation must succeed: {error:?}")
        })
        .unwrap_or_else(|| {
            unreachable!("test fixture archive_kind must be archive-derived, not RawBinary")
        });
        let mut record = uninstall::build_record(
            &root,
            uninstall::NewInstallation {
                component_id: manifest.id.0,
                version: manifest.version,
                platform: manifest.platform,
                architecture: manifest.architecture,
                canonical_component_root: install_dir,
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest: "0".repeat(64),
                ownership: ownership::OwnershipClass::CorulixManaged,
                installed_payload_digest: computed.core_digest,
                installed_payload_kind: computed.core_kind,
                optional_segment_digests: computed.segment_digests,
            },
        );
        assert!(
            ownership::save(&root, &mut record).is_ok(),
            "ownership record must save"
        );
        (root, manifest, resolved_binary)
    }

    /// Single-file archive (`GzippedBinary`) Case A: a genuinely valid
    /// installation with a real `installed_payload_digest` recorded resolves
    /// `Available` -- the new mechanism must not false-positive against an
    /// untampered install.
    #[test]
    fn payload_integrity_single_file_a_valid_component_resolves_available() {
        let (root, manifest, binary_path) = install_valid_component_with_installed_payload_digest(
            "payload-single-a-valid",
            ArchiveKind::GzippedBinary,
            &[("bin/tool", b"real single-file tool v1")],
        );
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Available);
        assert_eq!(path, Some(binary_path));
        assert_eq!(reason, None);
        let _ = fs::remove_dir_all(&root);
    }

    /// Single-file archive Case B: the extracted file's bytes are mutated
    /// after acquisition. Must fail closed as `Corrupt`/
    /// `InstalledPayloadMismatch` -- this is exactly the gap `RawBinary`-only
    /// `artifact_digest` re-verification could never cover for
    /// `GzippedBinary` (see `ManagedInvalidReason::ArtifactIntegrityMismatch`'s
    /// own doc comment on the real rust-analyzer false-positive that forced
    /// that narrowing).
    #[test]
    fn payload_integrity_single_file_b_tamper_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, binary_path) = install_valid_component_with_installed_payload_digest(
            "payload-single-b-tamper",
            ArchiveKind::GzippedBinary,
            &[("bin/tool", b"real single-file tool v1")],
        );
        fs::write(&binary_path, b"tampered bytes, different length even")?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::InstalledPayloadMismatch));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Single-file archive Case D: a legacy record (no `installed_payload_digest`
    /// recorded, matching every real pre-pass installation) is not enforced
    /// against by this new check even when its file happens to have been
    /// tampered with -- the deliberately-gated migration state, proven for
    /// `GzippedBinary` specifically (the negative control above,
    /// `regression_matrix_g_archive_based_component_digest_check_is_not_applicable`,
    /// already proves the same for `TarGz`).
    #[test]
    fn payload_integrity_single_file_d_legacy_record_not_enforced()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, binary_path) =
            install_valid_component("payload-single-d-legacy", ArchiveKind::GzippedBinary, b"v1");
        fs::write(&binary_path, b"tampered, but this is a legacy record")?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(
            state,
            ManagedComponentState::Available,
            "a legacy GzippedBinary record with no installed_payload_digest must not be \
             enforced against -- migration-required, not a live regression"
        );
        assert_eq!(path, Some(binary_path));
        assert_eq!(reason, None);
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Multi-file tree (`TarGz`) Case A: a genuinely valid, merged
    /// multi-file installation with a real tree `installed_payload_digest`
    /// resolves `Available`.
    #[test]
    fn payload_integrity_tree_a_valid_component_resolves_available() {
        let (root, manifest, binary_path) = install_valid_component_with_installed_payload_digest(
            "payload-tree-a-valid",
            ArchiveKind::TarGz,
            &[
                ("bin/tool", b"real tool binary"),
                ("lib/helper.so", b"real shared helper"),
                ("share/doc/readme.txt", b"real docs"),
            ],
        );
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Available);
        assert_eq!(path, Some(binary_path));
        assert_eq!(reason, None);
        let _ = fs::remove_dir_all(&root);
    }

    /// Multi-file tree Case B: a single byte in one non-primary tree file is
    /// mutated after acquisition. Must fail closed as `Corrupt`/
    /// `InstalledPayloadMismatch` -- proving the tree digest actually covers
    /// the *whole* merged install, not only the one file
    /// `binary_path_in_tarball` names.
    #[test]
    fn payload_integrity_tree_b_single_byte_tamper_in_non_primary_file_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, _binary_path) = install_valid_component_with_installed_payload_digest(
            "payload-tree-b-tamper",
            ArchiveKind::TarGz,
            &[
                ("bin/tool", b"real tool binary"),
                ("lib/helper.so", b"real shared helper"),
            ],
        );
        let install_dir = component_install_dir(&root, &manifest);
        fs::write(install_dir.join("lib/helper.so"), b"tampered shared helper")?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::InstalledPayloadMismatch));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Multi-file tree Case C: an unexpected extra file is added to an
    /// otherwise-untampered install after acquisition. Must fail closed --
    /// the tree digest's identity includes the full file *set*, not just
    /// each individual file's own bytes, so a planted addition is detected
    /// exactly like a mutation.
    #[test]
    fn payload_integrity_tree_c_added_file_fails_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, manifest, _binary_path) = install_valid_component_with_installed_payload_digest(
            "payload-tree-c-added",
            ArchiveKind::TarGz,
            &[("bin/tool", b"real tool binary")],
        );
        let install_dir = component_install_dir(&root, &manifest);
        fs::write(
            install_dir.join("bin/planted"),
            b"not part of the real install",
        )?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::InstalledPayloadMismatch));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Multi-file tree Case D: an installed file is removed after
    /// acquisition. Must fail closed for the same reason as Case C -- the
    /// file *set* is part of the identity.
    #[test]
    fn payload_integrity_tree_d_removed_file_fails_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, manifest, _binary_path) = install_valid_component_with_installed_payload_digest(
            "payload-tree-d-removed",
            ArchiveKind::TarGz,
            &[
                ("bin/tool", b"real tool binary"),
                ("lib/helper.so", b"real shared helper"),
            ],
        );
        let install_dir = component_install_dir(&root, &manifest);
        fs::remove_file(install_dir.join("lib/helper.so"))?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::InstalledPayloadMismatch));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Multi-file tree Case E: a symlink's target string is mutated after
    /// acquisition (still pointing safely inside the component root, so this
    /// is not a path-escape case -- see Case F for that). Proves the tree
    /// digest actually incorporates symlink target strings, not just
    /// regular-file content.
    #[cfg(unix)]
    #[test]
    fn payload_integrity_tree_e_symlink_target_tamper_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, _binary_path) = install_valid_component_with_installed_payload_digest(
            "payload-tree-e-symlink-tamper",
            ArchiveKind::TarGz,
            &[
                ("bin/tool", b"real tool binary"),
                ("bin/real-target-a", b"target a"),
                ("bin/real-target-b", b"target b"),
            ],
        );
        let install_dir = component_install_dir(&root, &manifest);
        std::os::unix::fs::symlink("real-target-a", install_dir.join("bin/link"))?;
        let computed = compute_installed_payload_digest(
            ArchiveKind::TarGz,
            manifest.id.0,
            &install_dir.join("bin/tool"),
            &install_dir,
        )
        .map_err(|error| format!("{error:?}"))?
        .ok_or("expected Some digest for TarGz")?;
        let record_path = root.join("ownership").join("fixture-hardening.json");
        let bytes = fs::read(&record_path)?;
        let mut record: ownership::ManagedInstallationRecord = serde_json::from_slice(&bytes)?;
        record.installed_payload_digest = computed.core_digest;
        record.installed_payload_kind = computed.core_kind;
        record.optional_segment_digests = computed.segment_digests;
        ownership::save(&root, &mut record).map_err(|error| format!("{error:?}"))?;

        // Confirm the freshly-recorded digest (with the symlink present)
        // resolves cleanly before tampering with it.
        let (state, _path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Available);
        assert_eq!(reason, None);

        fs::remove_file(install_dir.join("bin/link"))?;
        std::os::unix::fs::symlink("real-target-b", install_dir.join("bin/link"))?;
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::InstalledPayloadMismatch));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Builds a genuinely valid, owned `rust-semantic-runtime` component
    /// (the one real component with a declared [`OptionalSegment`], the
    /// `"clippy"` segment) with a real, computed `installed_payload_digest`
    /// AND real per-segment digests recorded -- via the same product
    /// function `provision_blocking` itself uses -- so the segment-aware
    /// regression matrix below (Section 16) exercises the real registered
    /// segment definition end-to-end, not a synthetic stand-in. `files`
    /// should include `bin/tool` (standing in for `bin/rustc`, this
    /// fixture's `binary_path_in_tarball`) plus, when the test wants a
    /// present-and-valid clippy segment, `bin/cargo-clippy`/
    /// `bin/clippy-driver`.
    fn install_rust_semantic_runtime_fixture(
        label: &str,
        files: &'static [(&'static str, &'static [u8])],
    ) -> (PathBuf, ManagedComponentManifest, PathBuf) {
        let root = temp_root(label);
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("rust-semantic-runtime"),
            version: "1.0.0",
            platform: "linux",
            architecture: "x64",
            source: ManagedArtifactSource {
                tarball_url: "https://example.invalid/does-not-matter.tgz",
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
        let install_dir = component_install_dir(&root, &manifest);
        for (relative, bytes) in files {
            let target = install_dir.join(relative);
            let _ = fs::create_dir_all(target.parent().unwrap_or(&install_dir));
            let _ = fs::write(&target, bytes);
        }
        let resolved_binary = install_dir.join("bin/tool");
        let computed = compute_installed_payload_digest(
            ArchiveKind::TarGz,
            manifest.id.0,
            &resolved_binary,
            &install_dir,
        )
        .unwrap_or_else(|error| {
            unreachable!("test fixture digest computation must succeed: {error:?}")
        })
        .unwrap_or_else(|| unreachable!("TarGz must produce Some digest"));
        let mut record = uninstall::build_record(
            &root,
            uninstall::NewInstallation {
                component_id: manifest.id.0,
                version: manifest.version,
                platform: manifest.platform,
                architecture: manifest.architecture,
                canonical_component_root: install_dir,
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest: "0".repeat(64),
                ownership: ownership::OwnershipClass::CorulixManaged,
                installed_payload_digest: computed.core_digest,
                installed_payload_kind: computed.core_kind,
                optional_segment_digests: computed.segment_digests,
            },
        );
        assert!(
            ownership::save(&root, &mut record).is_ok(),
            "ownership record must save"
        );
        (root, manifest, resolved_binary)
    }

    /// P11 Test A (Section 16): a fresh, valid `rust-semantic-runtime`
    /// component with the real `bin/rustc` stand-in plus a fully-present,
    /// valid `"clippy"` segment resolves core `Available`, and the segment
    /// itself resolves `SegmentState::Available`.
    #[test]
    fn p11_segment_a_fresh_valid_component_core_and_clippy_available() {
        let (root, manifest, binary_path) = install_rust_semantic_runtime_fixture(
            "p11-segment-a-valid",
            &[
                ("bin/tool", b"real rustc-equivalent"),
                ("bin/cargo-clippy", b"real cargo-clippy"),
                ("bin/clippy-driver", b"real clippy-driver"),
            ],
        );
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Available);
        assert_eq!(path, Some(binary_path));
        assert_eq!(reason, None);
        assert_eq!(
            resolve_optional_segment(&root, &manifest, "clippy"),
            SegmentState::Available
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// P11 Test B (Section 16, the real P11-R1 scenario itself): deleting
    /// only `bin/cargo-clippy`/`bin/clippy-driver` after acquisition must
    /// leave the core component `Available` (clippy's paths are excluded
    /// from the CORE digest boundary) while the segment itself reports
    /// `Absent` -- `P11_R1_DEGRADATION_CONTRACT=PRESERVED`.
    #[test]
    fn p11_segment_b_clippy_deleted_core_available_segment_absent() {
        let (root, manifest, binary_path) = install_rust_semantic_runtime_fixture(
            "p11-segment-b-clippy-deleted",
            &[
                ("bin/tool", b"real rustc-equivalent"),
                ("bin/cargo-clippy", b"real cargo-clippy"),
                ("bin/clippy-driver", b"real clippy-driver"),
            ],
        );
        let install_dir = component_install_dir(&root, &manifest);
        let _ = fs::remove_file(install_dir.join("bin/cargo-clippy"));
        let _ = fs::remove_file(install_dir.join("bin/clippy-driver"));
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(
            state,
            ManagedComponentState::Available,
            "P11-R1: deleting clippy's own binaries must never invalidate cargo/rustc"
        );
        assert_eq!(path, Some(binary_path));
        assert_eq!(reason, None);
        assert_eq!(
            resolve_optional_segment(&root, &manifest, "clippy"),
            SegmentState::Absent
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// P11 Test C (Section 16): clippy's binaries are present but tampered.
    /// Core stays `Available` (still excluded from its digest boundary),
    /// but the segment must report `Tampered`, never `Absent` --
    /// `OPTIONAL_PRESENT_TAMPERED_EXECUTABLE_ALLOWED=NO`.
    #[test]
    fn p11_segment_c_clippy_tampered_core_available_segment_tampered() {
        let (root, manifest, binary_path) = install_rust_semantic_runtime_fixture(
            "p11-segment-c-clippy-tampered",
            &[
                ("bin/tool", b"real rustc-equivalent"),
                ("bin/cargo-clippy", b"real cargo-clippy"),
                ("bin/clippy-driver", b"real clippy-driver"),
            ],
        );
        let install_dir = component_install_dir(&root, &manifest);
        let _ = fs::write(install_dir.join("bin/clippy-driver"), b"tampered bytes");
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(
            state,
            ManagedComponentState::Available,
            "clippy tamper must never invalidate cargo/rustc's own core resolution"
        );
        assert_eq!(path, Some(binary_path));
        assert_eq!(reason, None);
        assert_eq!(
            resolve_optional_segment(&root, &manifest, "clippy"),
            SegmentState::Tampered,
            "a present-but-tampered segment must never be reported as merely Absent"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// P11 Test D (Section 16): tampering a CORE (non-segment) file --
    /// standing in for `bin/cargo`/`bin/rustdoc` -- must still fail closed,
    /// exactly like any other archive-derived component's tree digest.
    #[test]
    fn p11_segment_d_core_file_tampered_fails_closed() {
        let (root, manifest, _binary_path) = install_rust_semantic_runtime_fixture(
            "p11-segment-d-core-tampered",
            &[
                ("bin/tool", b"real rustc-equivalent"),
                ("lib/core-support.so", b"real core support library"),
                ("bin/cargo-clippy", b"real cargo-clippy"),
                ("bin/clippy-driver", b"real clippy-driver"),
            ],
        );
        let install_dir = component_install_dir(&root, &manifest);
        let _ = fs::write(
            install_dir.join("lib/core-support.so"),
            b"tampered core support library",
        );
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::InstalledPayloadMismatch));
        let _ = fs::remove_dir_all(&root);
    }

    /// P11 Test E (Section 16): removing a CORE (non-segment) file must
    /// also fail closed -- the file *set* is part of the CORE identity,
    /// same as [`payload_integrity_tree_d_removed_file_fails_closed`], now
    /// proven specifically against the real segment-bearing component.
    #[test]
    fn p11_segment_e_core_file_removed_fails_closed() {
        let (root, manifest, _binary_path) = install_rust_semantic_runtime_fixture(
            "p11-segment-e-core-removed",
            &[
                ("bin/tool", b"real rustc-equivalent"),
                ("lib/core-support.so", b"real core support library"),
                ("bin/cargo-clippy", b"real cargo-clippy"),
                ("bin/clippy-driver", b"real clippy-driver"),
            ],
        );
        let install_dir = component_install_dir(&root, &manifest);
        let _ = fs::remove_file(install_dir.join("lib/core-support.so"));
        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Corrupt);
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::InstalledPayloadMismatch));
        let _ = fs::remove_dir_all(&root);
    }

    /// `resolve_optional_segment` against an unknown segment id reports
    /// `Absent` rather than panicking.
    #[test]
    fn resolve_optional_segment_unknown_id_is_absent() {
        let (root, manifest, _binary_path) = install_rust_semantic_runtime_fixture(
            "p11-segment-unknown-id",
            &[("bin/tool", b"real rustc-equivalent")],
        );
        assert_eq!(
            resolve_optional_segment(&root, &manifest, "not-a-real-segment"),
            SegmentState::Absent
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A component with no declared optional segments at all (every real
    /// component except `rust-semantic-runtime` today) reports `Absent` for
    /// any segment id -- generalizes cleanly, never assumes a segment
    /// exists.
    #[test]
    fn resolve_optional_segment_component_with_no_segments_is_absent() {
        let (root, manifest, _binary_path) = install_valid_component_with_installed_payload_digest(
            "payload-no-segments-declared",
            ArchiveKind::TarGz,
            &[("bin/tool", b"real tool binary")],
        );
        assert_eq!(
            resolve_optional_segment(&root, &manifest, "clippy"),
            SegmentState::Absent
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// Multi-file tree Case F: a symlink whose target resolves *outside*
    /// the component root is rejected by [`compute_tree_installed_digest`]
    /// itself (`PathTraversalRejected`), never silently followed or hashed
    /// as if safe (`TREE_DIGEST_WORKSPACE_ESCAPE_COUNT=0`).
    #[cfg(unix)]
    #[test]
    fn payload_integrity_tree_f_symlink_escape_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = temp_root("payload-tree-f-escape");
        let install_dir = root.join("component-root");
        fs::create_dir_all(install_dir.join("bin"))?;
        fs::write(install_dir.join("bin/tool"), b"real tool binary")?;
        let outside = temp_root("payload-tree-f-escape-outside");
        fs::write(outside.join("secret"), b"outside the component root")?;
        std::os::unix::fs::symlink(outside.join("secret"), install_dir.join("bin/escape"))?;

        let result = compute_installed_payload_digest(
            ArchiveKind::TarGz,
            "fixture-generic",
            &install_dir.join("bin/tool"),
            &install_dir,
        );
        assert_eq!(result, Err(ProvisioningError::PathTraversalRejected));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    /// Multi-file tree Case G: the identical file set, written to disk in a
    /// different order and under a different root, produces an identical
    /// digest -- `TREE_DIGEST_DETERMINISTIC=PASS`, independent of directory-
    /// traversal/creation order.
    #[test]
    fn payload_integrity_tree_g_enumeration_order_independent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root_a = temp_root("payload-tree-g-order-a");
        let dir_a = root_a.join("component-root");
        fs::create_dir_all(dir_a.join("share/doc"))?;
        fs::write(dir_a.join("bin_tool_placeholder"), b"placeholder")?;
        fs::write(dir_a.join("share/doc/readme.txt"), b"real docs")?;
        fs::create_dir_all(dir_a.join("lib"))?;
        fs::write(dir_a.join("lib/helper.so"), b"real shared helper")?;
        fs::write(dir_a.join("bin_tool_placeholder"), b"real tool binary")?;
        let digest_a = compute_installed_payload_digest(
            ArchiveKind::TarGz,
            "fixture-generic",
            &dir_a.join("bin_tool_placeholder"),
            &dir_a,
        )
        .map_err(|error| format!("{error:?}"))?
        .ok_or("expected Some digest")?
        .core_digest;

        let root_b = temp_root("payload-tree-g-order-b");
        let dir_b = root_b.join("component-root");
        fs::create_dir_all(dir_b.join("lib"))?;
        fs::write(dir_b.join("lib/helper.so"), b"real shared helper")?;
        fs::create_dir_all(dir_b.join("share/doc"))?;
        fs::write(dir_b.join("bin_tool_placeholder"), b"real tool binary")?;
        fs::write(dir_b.join("share/doc/readme.txt"), b"real docs")?;
        let digest_b = compute_installed_payload_digest(
            ArchiveKind::TarGz,
            "fixture-generic",
            &dir_b.join("bin_tool_placeholder"),
            &dir_b,
        )
        .map_err(|error| format!("{error:?}"))?
        .ok_or("expected Some digest")?
        .core_digest;

        assert_eq!(
            digest_a, digest_b,
            "identical file sets written in different creation order must digest identically"
        );
        let _ = fs::remove_dir_all(&root_a);
        let _ = fs::remove_dir_all(&root_b);
        Ok(())
    }

    /// Section 9: runtime-generated scratch state written *after*
    /// installation (the exact directory Corulix creates for managed
    /// rust-analyzer's `CARGO_HOME`/managed Go's `GOPATH`/`GOCACHE`/
    /// `GOMODCACHE`, see [`COMPONENT_RUNTIME_SCRATCH_DIR_NAME`]'s own doc
    /// comment) must never be part of the installed-payload digest boundary
    /// -- a runtime write there must not change the digest, or a managed
    /// Go/Rust runtime would self-invalidate the first time it is actually
    /// launched.
    #[test]
    fn payload_integrity_tree_excludes_runtime_scratch_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("payload-tree-scratch-exclusion");
        let install_dir = root.join("component-root");
        fs::create_dir_all(install_dir.join("bin"))?;
        fs::write(install_dir.join("bin/tool"), b"real tool binary")?;
        let digest_before = compute_installed_payload_digest(
            ArchiveKind::TarGz,
            "fixture-generic",
            &install_dir.join("bin/tool"),
            &install_dir,
        )
        .map_err(|error| format!("{error:?}"))?
        .ok_or("expected Some digest")?
        .core_digest;

        let scratch_dir = install_dir
            .join(COMPONENT_RUNTIME_SCRATCH_DIR_NAME)
            .join("gocache");
        fs::create_dir_all(&scratch_dir)?;
        fs::write(
            scratch_dir.join("some-build-artifact"),
            b"runtime-generated bytes",
        )?;
        let digest_after = compute_installed_payload_digest(
            ArchiveKind::TarGz,
            "fixture-generic",
            &install_dir.join("bin/tool"),
            &install_dir,
        )
        .map_err(|error| format!("{error:?}"))?
        .ok_or("expected Some digest")?
        .core_digest;

        assert_eq!(
            digest_before, digest_after,
            "writing into the runtime scratch directory must not change the installed-payload \
             digest"
        );
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// `RawBinary` is deliberately excluded from the new installed-payload
    /// mechanism entirely (Section 16): it already has a correct, working
    /// digest check via `artifact_digest`, and must not be routed through
    /// this new mechanism, single-file or tree.
    #[test]
    fn payload_integrity_raw_binary_is_excluded_from_the_new_mechanism()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("payload-raw-binary-excluded");
        let install_dir = root.join("component-root");
        fs::create_dir_all(&install_dir)?;
        fs::write(install_dir.join("tool"), b"real tool binary")?;
        let result = compute_installed_payload_digest(
            ArchiveKind::RawBinary,
            "fixture-generic",
            &install_dir.join("tool"),
            &install_dir,
        )
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(result, None);
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Sets `path`'s own `modified()` timestamp `seconds_ago` seconds into
    /// the past -- simulates a real, long-installed component (whose files
    /// are days or weeks old) so the M06 payload-verification cache's
    /// settledness guard grants an immediate cache hit on the very first
    /// resolution, exactly as it would for a genuine pre-existing
    /// installation, rather than exercising only the "just written"
    /// unsettled path every other fixture in this module produces.
    fn backdate(path: &Path, seconds_ago: u64) {
        if let Ok(handle) = fs::File::open(path) {
            let past = SystemTime::now() - std::time::Duration::from_secs(seconds_ago);
            let _ = handle.set_modified(past);
        }
    }

    /// M06 payload-verification cache, through the real production entry
    /// point (not the cache module's own unit tests): a `RawBinary`
    /// component that was already settled (long-installed) resolves
    /// `Available` on a cache-warming first call, then -- corrupted with a
    /// forged mtime, no ownership-record change at all -- must never be
    /// reported `Available` again. This is mandate Section 13's CRITICAL
    /// scenario (isolated root, provision, verify, warm cache, corrupt one
    /// byte, resolve again) exercised end to end.
    #[test]
    fn m06_cache_raw_binary_warm_then_corrupted_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, binary_path) = install_valid_component(
            "m06-raw-binary-warm-corrupt",
            ArchiveKind::RawBinary,
            b"genuine raw binary v1",
        );
        backdate(&binary_path, 3600);

        let (warm_state, warm_path, warm_reason) =
            resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(warm_state, ManagedComponentState::Available);
        assert_eq!(warm_path, Some(binary_path.clone()));
        assert_eq!(warm_reason, None);

        let original_mtime = fs::symlink_metadata(&binary_path)?.modified()?;
        fs::write(&binary_path, b"HACKED after cache warm")?;
        if let Ok(handle) = fs::File::open(&binary_path) {
            let _ = handle.set_modified(original_mtime);
        }

        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(
            state,
            ManagedComponentState::Corrupt,
            "SECURITY_BLOCKER: a warm-cache attestation must never survive a post-warm \
             payload corruption"
        );
        assert_eq!(path, None);
        assert_eq!(
            reason,
            Some(ManagedInvalidReason::ArtifactIntegrityMismatch)
        );
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// The archive-derived (tree) counterpart of the test above: a `TarGz`
    /// component with a real `installed_payload_digest`, already settled,
    /// resolves `Available` on the cache-warming call, then a single-byte
    /// tamper to a non-primary tree file -- again with no ownership-record
    /// change -- must still be rejected. Proves the tree-digest branch of
    /// the cache is equally safe, not only the single-file branch.
    #[test]
    fn m06_cache_archive_tree_warm_then_corrupted_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let files: &[(&str, &[u8])] = &[
            ("bin/tool", b"real tool binary"),
            ("lib/helper.so", b"real shared helper"),
        ];
        let (root, manifest, _binary_path) = install_valid_component_with_installed_payload_digest(
            "m06-tree-warm-corrupt",
            ArchiveKind::TarGz,
            files,
        );
        let install_dir = component_install_dir(&root, &manifest);
        for (relative, _) in files {
            backdate(&install_dir.join(relative), 3600);
        }

        let (warm_state, _warm_path, _warm_reason) =
            resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(warm_state, ManagedComponentState::Available);

        let helper_path = install_dir.join("lib/helper.so");
        let original_mtime = fs::symlink_metadata(&helper_path)?.modified()?;
        fs::write(&helper_path, b"HACKED shared helper")?;
        if let Ok(handle) = fs::File::open(&helper_path) {
            let _ = handle.set_modified(original_mtime);
        }

        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(
            state,
            ManagedComponentState::Corrupt,
            "SECURITY_BLOCKER: a warm-cache tree attestation must never survive a post-warm \
             payload corruption"
        );
        assert_eq!(path, None);
        assert_eq!(reason, Some(ManagedInvalidReason::InstalledPayloadMismatch));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Lifecycle invalidation, through the real production `uninstall`:
    /// warm the cache for a component, uninstall it (which must invalidate
    /// any cached attestation), then "reinstall" a genuinely different
    /// payload at the same canonical path under a fresh ownership record.
    /// The very next resolution must reflect the NEW payload -- never a
    /// stale digest carried over from the pre-uninstall attestation.
    #[tokio::test]
    async fn m06_cache_uninstall_then_reinstall_requires_fresh_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, binary_path) = install_valid_component(
            "m06-uninstall-reinstall",
            ArchiveKind::RawBinary,
            b"genuine v1",
        );
        backdate(&binary_path, 3600);

        let (warm_state, _warm_path, _warm_reason) =
            resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(warm_state, ManagedComponentState::Available);

        let outcome = uninstall::uninstall(&root, manifest.id, |_| {}).await;
        assert_eq!(outcome, Ok(uninstall::UninstallOutcome::Removed));

        let install_dir = component_install_dir(&root, &manifest);
        let binary_path_v2 = install_dir.join("bin/tool");
        let _ = fs::create_dir_all(binary_path_v2.parent().unwrap_or(&install_dir));
        let v2_bytes: &[u8] = b"genuine v2, totally different content";
        fs::write(&binary_path_v2, v2_bytes)?;
        backdate(&binary_path_v2, 3600);
        let mut record = uninstall::build_record(
            &root,
            uninstall::NewInstallation {
                component_id: manifest.id.0,
                version: manifest.version,
                platform: manifest.platform,
                architecture: manifest.architecture,
                canonical_component_root: install_dir,
                dependencies: Vec::new(),
                installation_sequence: 2,
                artifact_digest: ContentHash::compute_sha256(v2_bytes).digest_hex,
                ownership: ownership::OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        assert!(
            ownership::save(&root, &mut record).is_ok(),
            "reinstalled record must save"
        );

        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Available);
        assert_eq!(path, Some(binary_path_v2));
        assert_eq!(reason, None);
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Lifecycle invalidation via `full_uninstall`: a single owned component
    /// (no dependents) is fully removed; the cache must not retain any
    /// attestation that a subsequent, independent reinstall could collide
    /// with.
    #[tokio::test]
    async fn m06_cache_full_uninstall_invalidates_before_reinstall()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, manifest, binary_path) = install_valid_component(
            "m06-full-uninstall-reinstall",
            ArchiveKind::RawBinary,
            b"genuine full-uninstall v1",
        );
        backdate(&binary_path, 3600);

        let (warm_state, _warm_path, _warm_reason) =
            resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(warm_state, ManagedComponentState::Available);

        let outcome = full_uninstall::full_uninstall(&root).await;
        assert!(
            matches!(
                outcome,
                Ok(full_uninstall::FullUninstallOutcome::Removed(_))
            ),
            "full_uninstall must succeed on a single owned component, got {outcome:?}"
        );
        assert!(
            !binary_path.exists(),
            "full_uninstall must actually remove the on-disk payload"
        );

        let install_dir = component_install_dir(&root, &manifest);
        let v2_bytes: &[u8] = b"genuine post-full-uninstall v2";
        let _ = fs::create_dir_all(binary_path.parent().unwrap_or(&install_dir));
        fs::write(&binary_path, v2_bytes)?;
        backdate(&binary_path, 3600);
        let mut record = uninstall::build_record(
            &root,
            uninstall::NewInstallation {
                component_id: manifest.id.0,
                version: manifest.version,
                platform: manifest.platform,
                architecture: manifest.architecture,
                canonical_component_root: install_dir,
                dependencies: Vec::new(),
                installation_sequence: 2,
                artifact_digest: ContentHash::compute_sha256(v2_bytes).digest_hex,
                ownership: ownership::OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        assert!(
            ownership::save(&root, &mut record).is_ok(),
            "post-full-uninstall reinstall record must save"
        );

        let (state, path, reason) = resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Available);
        assert_eq!(path, Some(binary_path));
        assert_eq!(reason, None);
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// `N` concurrent first-resolutions of the identical, already-settled
    /// component state must never race, panic, or disagree with each other
    /// -- every thread must observe the same, correct `Available` verdict.
    /// The cache module's own unit test
    /// (`single_flight_lock_serializes_same_component_never_different_ones`)
    /// already proves the lock registry itself is per-component; this test
    /// proves the production entry point behaves correctly under real
    /// concurrent access, not merely that the lock primitive is correct in
    /// isolation.
    #[test]
    fn m06_cache_concurrent_first_resolution_never_races_or_disagrees() {
        let (root, manifest, binary_path) = install_valid_component(
            "m06-concurrent-single-flight",
            ArchiveKind::RawBinary,
            b"genuine concurrent v1",
        );
        backdate(&binary_path, 3600);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let root = root.clone();
                std::thread::spawn(move || {
                    resolve_owned_managed_component_detailed(&root, &manifest)
                })
            })
            .collect();
        for handle in handles {
            let (state, path, reason) = handle
                .join()
                .unwrap_or_else(|_| unreachable!("resolution thread must not panic"));
            assert_eq!(state, ManagedComponentState::Available);
            assert_eq!(path, Some(binary_path.clone()));
            assert_eq!(reason, None);
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// Concurrent verification-vs-mutation safety: while several threads
    /// repeatedly resolve a component, a concurrent writer corrupts its
    /// payload (no ownership-record update). The invariant this proves is a
    /// strict happens-before one: any `resolve()` call whose *entire
    /// execution* -- start to finish -- occurred after the writer's mutation
    /// had already completed must never report `Available`. A call that
    /// merely *overlaps* the write is deliberately excluded from the
    /// assertion (its outcome is genuinely ambiguous, a property of
    /// concurrent filesystem access in general, not of this cache); using an
    /// independent, unsynchronized second read to "double check" a
    /// concurrent call's result was tried first and produces exactly this
    /// kind of false positive (a torn read racing the confirmation read
    /// itself, not the resolver) -- which is why this version brackets each
    /// call against a single atomic flag the writer flips, with proper
    /// acquire/release ordering, instead.
    #[test]
    fn m06_cache_concurrent_resolution_never_reports_false_available_after_a_completed_mutation() {
        let (root, manifest, binary_path) = install_valid_component(
            "m06-concurrent-verify-mutate-race",
            ArchiveKind::RawBinary,
            b"genuine race v1, sixteen bytes",
        );
        backdate(&binary_path, 3600);

        // Warm the cache first so most reader iterations exercise the fast
        // cache-hit path, the realistic condition this race must be safe
        // under.
        let (warm_state, _warm_path, _warm_reason) =
            resolve_owned_managed_component_detailed(&root, &manifest);
        assert_eq!(warm_state, ManagedComponentState::Available);

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mutation_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let false_available_after_mutation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut reader_handles = Vec::new();
        for _ in 0..4 {
            let root = root.clone();
            let stop = Arc::clone(&stop);
            let mutation_done = Arc::clone(&mutation_done);
            let false_available_after_mutation = Arc::clone(&false_available_after_mutation);
            reader_handles.push(std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let already_mutated_before_this_call =
                        mutation_done.load(std::sync::atomic::Ordering::Acquire);
                    let (state, _path, _reason) =
                        resolve_owned_managed_component_detailed(&root, &manifest);
                    if already_mutated_before_this_call && state == ManagedComponentState::Available
                    {
                        false_available_after_mutation
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }));
        }

        let writer_path = binary_path.clone();
        let mutation_done_writer = Arc::clone(&mutation_done);
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let _ = fs::write(&writer_path, b"genuine race v2!");
            mutation_done_writer.store(true, std::sync::atomic::Ordering::Release);
        });
        writer
            .join()
            .unwrap_or_else(|_| unreachable!("writer thread must not panic"));
        std::thread::sleep(std::time::Duration::from_millis(50));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for handle in reader_handles {
            handle
                .join()
                .unwrap_or_else(|_| unreachable!("reader thread must not panic"));
        }

        assert!(
            !false_available_after_mutation.load(std::sync::atomic::Ordering::Relaxed),
            "SECURITY_BLOCKER: a resolve() call whose entire execution began only after the \
             mutation had already completed still reported Available"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn different_versions_never_collide_on_disk() {
        let root = temp_root("versions");
        let base = ManagedComponentManifest {
            id: ManagedComponentId("fixture"),
            version: "1.0.0",
            platform: "linux",
            architecture: "x64",
            source: ManagedArtifactSource {
                tarball_url: "https://example.invalid/one.tgz",
                expected_sha256_hex: "0",
                binary_path_in_tarball: "bin",
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
        let other = ManagedComponentManifest {
            version: "2.0.0",
            ..base
        };
        assert_ne!(
            component_install_dir(&root, &base),
            component_install_dir(&root, &other)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn integrity_mismatch_is_rejected_before_extraction() {
        let bytes = b"not the real artifact";
        let wrong_hash = "0".repeat(64);
        assert_eq!(
            verify_integrity(bytes, &wrong_hash),
            Err(ProvisioningError::IntegrityMismatch)
        );
    }

    #[test]
    fn integrity_match_succeeds() {
        let bytes = b"exact bytes";
        let hash = ContentHash::compute_sha256(bytes);
        assert_eq!(verify_integrity(bytes, &hash.digest_hex), Ok(()));
    }

    #[test]
    fn corrupt_truncated_artifact_fails_extraction_not_panics() {
        let root = temp_root("truncated");
        let staging = root.join("staging-truncated");
        let _ = fs::create_dir_all(&staging);
        let corrupt_bytes = vec![0x1f, 0x8b, 0x00];
        let result = extract_tar_gz(
            &corrupt_bytes,
            &staging,
            SymlinkPolicy::Reject,
            None,
            &[],
            &[],
        );
        assert_eq!(result, Err(ProvisioningError::ArchiveExtractionFailed));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn path_traversal_entry_is_rejected() {
        let root = temp_root("traversal");
        let staging = root.join("staging-traversal");
        let _ = fs::create_dir_all(&staging);
        let tarball = build_tarball(&[("../../etc/passwd-fake", b"malicious")]);
        let result = extract_tar_gz(&tarball, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::PathTraversalRejected));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn absolute_path_entry_is_rejected() {
        let root = temp_root("absolute");
        let staging = root.join("staging-absolute");
        let _ = fs::create_dir_all(&staging);
        let tarball = build_tarball(&[("/etc/passwd-fake", b"malicious")]);
        let result = extract_tar_gz(&tarball, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::PathTraversalRejected));
        let _ = fs::remove_dir_all(&root);
    }

    /// Builds a two-entry tar.gz: one symlink entry at `link_path` first,
    /// then one real file at `file_path` -- symlink-first so a rejected
    /// symlink aborts extraction before the real file entry is ever
    /// reached, letting tests assert the real file was never written on
    /// the reject path. The symlink's target is never followed regardless
    /// of policy.
    fn build_tarball_with_symlink(file_path: &str, content: &[u8], link_path: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        {
            let mut link_header = tar::Header::new_gnu();
            link_header.set_entry_type(tar::EntryType::Symlink);
            link_header.set_size(0);
            link_header.set_cksum();
            let _ = builder.append_link(&mut link_header, link_path, "/etc/passwd-fake");
        }
        {
            let mut file_header = tar::Header::new_gnu();
            file_header.set_size(content.len() as u64);
            file_header.set_mode(0o644);
            {
                let name_field = file_header.as_old_mut().name.as_mut();
                let bytes = file_path.as_bytes();
                name_field[..bytes.len()].copy_from_slice(bytes);
            }
            file_header.set_cksum();
            builder
                .append(&file_header, content)
                .unwrap_or_else(|_| unreachable!("in-memory tar append never fails in this test"));
        }
        let tar_bytes = builder
            .into_inner()
            .unwrap_or_else(|_| unreachable!("in-memory tar finish never fails in this test"));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let _ = encoder.write_all(&tar_bytes);
        encoder
            .finish()
            .unwrap_or_else(|_| unreachable!("in-memory gzip finish never fails in this test"))
    }

    #[test]
    fn symlink_entry_aborts_the_whole_archive_under_the_default_reject_policy() {
        let root = temp_root("symlink-default-reject");
        let staging = root.join("staging-symlink-default-reject");
        let _ = fs::create_dir_all(&staging);
        let tarball = build_tarball_with_symlink("package/bin/node", b"real content", "evil-link");
        let result = extract_tar_gz(&tarball, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::UnexpectedSymlinkRejected));
        assert!(!staging.join("evil-link").exists());
        // Whole-archive fail-closed: even the sibling real file is not
        // left behind on a rejected archive.
        assert!(!staging.join("package/bin/node").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn allowlisted_symlink_is_skipped_and_sibling_real_file_still_extracts() {
        let root = temp_root("symlink-allowlisted");
        let staging = root.join("staging-symlink-allowlisted");
        let _ = fs::create_dir_all(&staging);
        let tarball =
            build_tarball_with_symlink("package/bin/node", b"real content", "package/bin/npm");
        let result = extract_tar_gz(
            &tarball,
            &staging,
            SymlinkPolicy::AllowExactRelativePaths(&["package/bin/npm"]),
            None,
            &[],
            &[],
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            fs::read(staging.join("package/bin/node"))
                .unwrap_or_else(|_| unreachable!("extraction proven Ok above")),
            b"real content"
        );
        assert!(!staging.join("package/bin/npm").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn symlink_not_on_the_allowlist_still_aborts_the_whole_archive() {
        let root = temp_root("symlink-not-allowlisted");
        let staging = root.join("staging-symlink-not-allowlisted");
        let _ = fs::create_dir_all(&staging);
        let tarball =
            build_tarball_with_symlink("package/bin/node", b"real content", "package/bin/evil");
        let result = extract_tar_gz(
            &tarball,
            &staging,
            SymlinkPolicy::AllowExactRelativePaths(&["package/bin/npm"]),
            None,
            &[],
            &[],
        );
        assert_eq!(result, Err(ProvisioningError::UnexpectedSymlinkRejected));
        assert!(!staging.join("package/bin/evil").exists());
        assert!(!staging.join("package/bin/node").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn well_formed_archive_extracts_confined_to_staging() {
        let root = temp_root("wellformed");
        let staging = root.join("staging-wellformed");
        let _ = fs::create_dir_all(&staging);
        let tarball = build_tarball(&[("package/lib/tsc", b"binary contents")]);
        let result = extract_tar_gz(&tarball, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Ok(()));
        let extracted = fs::read(staging.join("package/lib/tsc"))
            .unwrap_or_else(|_| unreachable!("extraction proven Ok above"));
        assert_eq!(extracted, b"binary contents");
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn provision_fails_closed_on_wrong_checksum_and_leaves_no_partial_install() {
        let root = temp_root("wrong-checksum");
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("checksum-fixture"),
            version: "1.0.0",
            platform: host_platform_identifier(),
            architecture: host_architecture_identifier(),
            source: ManagedArtifactSource {
                // A real, small, reachable file whose actual hash will not
                // match the deliberately wrong expected digest below.
                tarball_url: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                expected_sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000",
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
        let result = provision(&root, &manifest).await;
        assert!(matches!(
            result,
            Err(ProvisioningError::IntegrityMismatch) | Err(ProvisioningError::DownloadFailed)
        ));
        let (state, _) = resolve_managed_component(&root, &manifest);
        assert_eq!(state, ManagedComponentState::NotProvisioned);
        let _ = fs::remove_dir_all(&root);
    }

    /// Regression test for a real, reproducible race found by running this
    /// crate's own concurrent real E2E test binaries: N concurrent
    /// `provision()` calls for the *same* component must single-flight
    /// rather than race each other's download/extract/atomic-activate
    /// pipeline. Before the `lock_component` fix, the losing calls'
    /// `fs::rename` onto an already-populated `install_dir` failed with
    /// `ActivationFailed` purely from losing the race -- every call here
    /// must succeed, and must all agree on the same final binary path.
    #[tokio::test]
    async fn concurrent_provision_calls_for_the_same_component_never_race() {
        let root = temp_root("concurrent-provision");
        let manifest = ManagedComponentManifest {
            id: ManagedComponentId("left-pad-concurrency-fixture"),
            version: "1.3.0",
            platform: host_platform_identifier(),
            architecture: host_architecture_identifier(),
            source: ManagedArtifactSource {
                tarball_url: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                expected_sha256_hex: "870c0fe1096223a58d4f8832d08a7e651ea2fcadb8e6877b2fdc26b662d481dd",
                binary_path_in_tarball: "package/index.js",
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

        let mut handles = Vec::new();
        for _ in 0..5 {
            let root = root.clone();
            handles.push(tokio::spawn(
                async move { provision(&root, &manifest).await },
            ));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(
                handle
                    .await
                    .unwrap_or_else(|_| unreachable!("spawned task never panics in this test")),
            );
        }

        let network_unavailable = results
            .iter()
            .any(|result| matches!(result, Err(ProvisioningError::DownloadFailed)));
        if network_unavailable {
            // Honest early-exit: no network in this environment. Every
            // other assertion below assumes at least one real success.
            let _ = fs::remove_dir_all(&root);
            return;
        }

        for result in &results {
            assert!(
                result.is_ok(),
                "expected every concurrent provision() call to succeed via single-flight, got {result:?}"
            );
        }
        let paths: std::collections::HashSet<_> = results
            .into_iter()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(
            paths.len(),
            1,
            "expected every concurrent call to agree on the same final binary path"
        );
        let (state, _) = resolve_managed_component(&root, &manifest);
        assert_eq!(state, ManagedComponentState::Available);
        let _ = fs::remove_dir_all(&root);
    }

    /// `write_scratch_file` genuinely writes a real, readable-back file
    /// under the requested scratch subdirectory -- the happy path, proven
    /// before the negative confinement tests below (a confinement check
    /// that only ever rejects is not proof it also accepts a legitimate
    /// call).
    #[test]
    fn write_scratch_file_writes_a_real_readable_back_file() {
        let root = temp_root("write-scratch-happy-path");
        let result =
            write_scratch_file(&root, "scratch/biome-lint", "staged-1.ts", b"const x = 1;");
        assert!(
            result.is_ok(),
            "a confined relative_dir and a single-component file_name must succeed: {result:?}"
        );
        let path = result.unwrap_or_default();
        assert_eq!(fs::read(&path).unwrap_or_default(), b"const x = 1;");
        assert!(path.starts_with(root.join(MANAGED_SCRATCH_DIR).join("biome-lint")));
        let _ = remove_scratch_file(&path);
        assert!(!path.is_file());
        let _ = fs::remove_dir_all(&root);
    }

    /// `P16_SCRATCH_FILE_NAME_CONFINEMENT=PASS`: a `file_name` that embeds a
    /// path traversal/separator must be rejected before any write, mirroring
    /// `ensure_scratch_directory`'s own `P15_CACHE_OWNERSHIP_CONFINEMENT`
    /// discipline -- proven by test, not merely asserted from the source
    /// reading the check.
    #[test]
    fn write_scratch_file_rejects_a_traversal_file_name() {
        let root = temp_root("write-scratch-traversal");
        let result = write_scratch_file(&root, "biome-lint", "../../etc/passwd", b"hostile");
        assert_eq!(result, Err(ProvisioningError::ScratchPathNotConfined));
        assert!(
            !root
                .parent()
                .map(|parent| parent.join("etc").join("passwd").is_file())
                .unwrap_or(false)
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A `file_name` containing an embedded path separator (not merely
    /// `..`) must also be rejected -- `write_scratch_file` requires exactly
    /// one path component, never a nested subpath smuggled in as a "file
    /// name".
    #[test]
    fn write_scratch_file_rejects_a_multi_component_file_name() {
        let root = temp_root("write-scratch-multi-component");
        let result = write_scratch_file(&root, "biome-lint", "nested/staged.ts", b"hostile");
        assert_eq!(result, Err(ProvisioningError::ScratchPathNotConfined));
        let _ = fs::remove_dir_all(&root);
    }

    /// An absolute `file_name` must also be rejected -- it could otherwise
    /// escape the scratch directory entirely regardless of `relative_dir`.
    #[test]
    fn write_scratch_file_rejects_an_absolute_file_name() {
        let root = temp_root("write-scratch-absolute");
        let result = write_scratch_file(&root, "biome-lint", "/etc/passwd", b"hostile");
        assert_eq!(result, Err(ProvisioningError::ScratchPathNotConfined));
        let _ = fs::remove_dir_all(&root);
    }

    // ---------------------------------------------------------------
    // P17-W-R4-C2: ArchiveKind::Zip -- central archive provisioning and
    // its fail-closed security matrix (WINDOWS_ZIP_PROVISIONING_SECURITY,
    // ZIP_FAIL_CLOSED_MATRIX).
    // ---------------------------------------------------------------

    /// Hand-assembles a minimal, valid, Stored-only (compression method
    /// `0`) PKZIP archive byte-for-byte -- local file header + data,
    /// repeated per entry, followed by the central directory and the
    /// end-of-central-directory record -- rather than depending on any
    /// third-party zip-writing crate. `raw_name` is written directly into
    /// both the local and central directory headers with none of this
    /// module's own sanitization, exactly mirroring [`build_tarball`]'s own
    /// "simulate a hostile/corrupted archive's raw on-wire bytes" contract
    /// for the negative tests below.
    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central_directory = Vec::new();
        let mut offsets = Vec::new();

        for (name, content) in entries {
            offsets.push(out.len() as u32);
            let name_bytes = name.as_bytes();
            let crc = crc32(content);
            out.extend_from_slice(&ZIP_LOCAL_FILE_HEADER_SIGNATURE);
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // method: Stored
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(content.len() as u32).to_le_bytes()); // compressed size
            out.extend_from_slice(&(content.len() as u32).to_le_bytes()); // uncompressed size
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(content);
        }

        for ((name, content), local_offset) in entries.iter().zip(offsets.iter()) {
            let name_bytes = name.as_bytes();
            let crc = crc32(content);
            central_directory.extend_from_slice(&ZIP_CENTRAL_DIRECTORY_SIGNATURE);
            central_directory.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central_directory.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central_directory.extend_from_slice(&0u16.to_le_bytes()); // flags
            central_directory.extend_from_slice(&0u16.to_le_bytes()); // method: Stored
            central_directory.extend_from_slice(&0u16.to_le_bytes()); // mod time
            central_directory.extend_from_slice(&0u16.to_le_bytes()); // mod date
            central_directory.extend_from_slice(&crc.to_le_bytes());
            central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
            central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
            central_directory.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            central_directory.extend_from_slice(&0u16.to_le_bytes()); // extra len
            central_directory.extend_from_slice(&0u16.to_le_bytes()); // comment len
            central_directory.extend_from_slice(&0u16.to_le_bytes()); // disk number start
            central_directory.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            central_directory.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            central_directory.extend_from_slice(&local_offset.to_le_bytes());
            central_directory.extend_from_slice(name_bytes);
        }

        let cd_offset = out.len() as u32;
        let cd_size = central_directory.len() as u32;
        out.extend_from_slice(&central_directory);
        out.extend_from_slice(&ZIP_EOCD_SIGNATURE);
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // disk with start of CD
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out
    }

    #[test]
    fn valid_zip_extracts_and_matches_declared_bytes() {
        let root = temp_root("zip-valid");
        let staging = root.join("staging-zip-valid");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[
            ("node.exe", b"fake-node-binary-bytes"),
            ("LICENSE", b"license text"),
        ]);
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Ok(()));
        assert_eq!(
            fs::read(staging.join("node.exe")).unwrap_or_default(),
            b"fake-node-binary-bytes"
        );
        assert_eq!(
            fs::read(staging.join("LICENSE")).unwrap_or_default(),
            b"license text"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn valid_zip_with_root_prefix_strips_it() {
        let root = temp_root("zip-root-prefix");
        let staging = root.join("staging-zip-root-prefix");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("node-v24.19.0-win-x64/node.exe", b"fake-node")]);
        let result = extract_zip(
            &archive,
            &staging,
            SymlinkPolicy::Reject,
            Some("node-v24.19.0-win-x64/"),
            &[],
            &[],
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            fs::read(staging.join("node.exe")).unwrap_or_default(),
            b"fake-node"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_traversal_dot_dot_entry_is_rejected() {
        let root = temp_root("zip-traversal");
        let staging = root.join("staging-zip-traversal");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("../../etc/passwd-fake", b"malicious")]);
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::PathTraversalRejected));
        assert!(!staging.join("../../etc/passwd-fake").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_absolute_unix_path_entry_is_rejected() {
        let root = temp_root("zip-absolute-unix");
        let staging = root.join("staging-zip-absolute-unix");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("/etc/passwd-fake", b"malicious")]);
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::PathTraversalRejected));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_drive_prefixed_windows_path_entry_is_rejected() {
        let root = temp_root("zip-drive-path");
        let staging = root.join("staging-zip-drive-path");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("C:\\Windows\\evil.dll", b"malicious")]);
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::PathTraversalRejected));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_unc_path_entry_is_rejected() {
        let root = temp_root("zip-unc-path");
        let staging = root.join("staging-zip-unc-path");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("\\\\attacker-host\\share\\evil.dll", b"malicious")]);
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::PathTraversalRejected));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_verbatim_device_path_entry_is_rejected() {
        let root = temp_root("zip-verbatim-path");
        let staging = root.join("staging-zip-verbatim-path");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("\\\\?\\C:\\Windows\\evil.dll", b"malicious")]);
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::PathTraversalRejected));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_mixed_separator_traversal_entry_is_rejected() {
        let root = temp_root("zip-mixed-separator");
        let staging = root.join("staging-zip-mixed-separator");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("subdir\\..\\..\\evil.dll", b"malicious")]);
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::PathTraversalRejected));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_wrong_root_prefix_yields_no_extracted_files() {
        let root = temp_root("zip-wrong-prefix");
        let staging = root.join("staging-zip-wrong-prefix");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("node-v24.19.0-win-x64/node.exe", b"fake-node")]);
        // Declares a prefix that does not match any entry in the archive:
        // every entry is silently skipped (same "already-trusted archive,
        // selecting a subtree" reasoning as `extract_tar_entries`), so
        // extraction succeeds but produces zero files -- the caller's own
        // required-path verification (not this function) is what turns
        // that into a refused activation.
        let result = extract_zip(
            &archive,
            &staging,
            SymlinkPolicy::Reject,
            Some("wrong-prefix/"),
            &[],
            &[],
        );
        assert_eq!(result, Ok(()));
        assert!(!staging.join("node.exe").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_zip_missing_eocd_is_rejected() {
        let root = temp_root("zip-corrupt");
        let staging = root.join("staging-zip-corrupt");
        let _ = fs::create_dir_all(&staging);
        let mut archive = build_zip(&[("node.exe", b"fake-node")]);
        archive.truncate(archive.len() - 10); // sever the EOCD record
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::ZipArchiveMalformed));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_bad_crc32_is_rejected() {
        let root = temp_root("zip-bad-crc");
        let staging = root.join("staging-zip-bad-crc");
        let _ = fs::create_dir_all(&staging);
        let mut archive = build_zip(&[("node.exe", b"fake-node-binary-bytes")]);
        // Corrupt one data byte in place without touching any length field
        // -- the central directory's declared CRC-32 no longer matches the
        // (still correctly-sized) extracted bytes.
        let data_offset = archive
            .windows(b"fake-node-binary-bytes".len())
            .position(|window| window == b"fake-node-binary-bytes")
            .unwrap_or_else(|| {
                unreachable!("test fixture data must be present in the built archive")
            });
        archive[data_offset] = b'X';
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::ZipEntryCrc32Mismatch));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_unsupported_compression_method_is_rejected() {
        let root = temp_root("zip-unsupported-method");
        let staging = root.join("staging-zip-unsupported-method");
        let _ = fs::create_dir_all(&staging);
        let mut archive = build_zip(&[("node.exe", b"fake-node")]);
        // Flip the local *and* central directory method fields (offset 8
        // within each fixed header) from Stored (`0`) to bzip2 (`12`) --
        // neither this archive's data nor its CRC is otherwise touched, so
        // this isolates "declares an unsupported method" from "corrupt
        // data".
        let local_method_offset = 8;
        archive[local_method_offset] = 12;
        let cd_signature_offset = archive
            .windows(4)
            .rposition(|window| window == ZIP_CENTRAL_DIRECTORY_SIGNATURE)
            .unwrap_or_else(|| unreachable!("central directory entry must be present"));
        archive[cd_signature_offset + 10] = 12;
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(
            result,
            Err(ProvisioningError::ZipUnsupportedCompressionMethod)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_duplicate_entry_path_is_rejected() {
        let root = temp_root("zip-duplicate");
        let staging = root.join("staging-zip-duplicate");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("node.exe", b"first"), ("node.exe", b"second")]);
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Err(ProvisioningError::ZipDuplicateEntryPath));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_directory_entry_creates_directory_only() {
        let root = temp_root("zip-directory-entry");
        let staging = root.join("staging-zip-directory-entry");
        let _ = fs::create_dir_all(&staging);
        let archive = build_zip(&[("node_modules/", b""), ("node_modules/corepack/x.js", b"y")]);
        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Ok(()));
        assert!(staging.join("node_modules").is_dir());
        assert_eq!(
            fs::read(staging.join("node_modules/corepack/x.js")).unwrap_or_default(),
            b"y"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_deflate_entry_round_trips() {
        let root = temp_root("zip-deflate");
        let staging = root.join("staging-zip-deflate");
        let _ = fs::create_dir_all(&staging);
        let payload = b"a real deflate-compressed payload, repeated repeated repeated";
        let mut deflated = Vec::new();
        {
            let mut encoder =
                flate2::write::DeflateEncoder::new(&mut deflated, flate2::Compression::default());
            encoder
                .write_all(payload)
                .unwrap_or_else(|_| unreachable!("in-memory deflate write never fails"));
            encoder
                .finish()
                .unwrap_or_else(|_| unreachable!("in-memory deflate finish never fails"));
        }
        let name = "node.exe";
        let crc = crc32(payload);
        let mut archive = Vec::new();
        let local_offset = 0u32;
        archive.extend_from_slice(&ZIP_LOCAL_FILE_HEADER_SIGNATURE);
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&8u16.to_le_bytes()); // method: Deflate
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&crc.to_le_bytes());
        archive.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(name.as_bytes());
        archive.extend_from_slice(&deflated);
        let cd_start = archive.len();
        archive.extend_from_slice(&ZIP_CENTRAL_DIRECTORY_SIGNATURE);
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&8u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&crc.to_le_bytes());
        archive.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&local_offset.to_le_bytes());
        archive.extend_from_slice(name.as_bytes());
        let cd_size = (archive.len() - cd_start) as u32;
        archive.extend_from_slice(&ZIP_EOCD_SIGNATURE);
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&cd_size.to_le_bytes());
        archive.extend_from_slice(&(cd_start as u32).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());

        let result = extract_zip(&archive, &staging, SymlinkPolicy::Reject, None, &[], &[]);
        assert_eq!(result, Ok(()));
        assert_eq!(
            fs::read(staging.join("node.exe")).unwrap_or_default(),
            payload.to_vec()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_entry_path_safety_matrix() {
        assert!(is_zip_entry_path_safe("node.exe"));
        assert!(is_zip_entry_path_safe("node-v24.19.0-win-x64/node.exe"));
        assert!(!is_zip_entry_path_safe(""));
        assert!(!is_zip_entry_path_safe("../evil"));
        assert!(!is_zip_entry_path_safe("a/../../evil"));
        assert!(!is_zip_entry_path_safe("/etc/passwd"));
        assert!(!is_zip_entry_path_safe("\\etc\\passwd"));
        assert!(!is_zip_entry_path_safe("C:\\evil.dll"));
        assert!(!is_zip_entry_path_safe("\\\\host\\share\\evil.dll"));
        assert!(!is_zip_entry_path_safe("//host/share/evil.dll"));
        assert!(!is_zip_entry_path_safe("\\\\?\\C:\\evil.dll"));
        assert!(!is_zip_entry_path_safe("a/b\0c"));
    }

    #[test]
    fn crc32_matches_known_vector() {
        // "123456789" -> 0xCBF43926 is the standard CRC-32/ISO-HDLC test
        // vector every implementation of this exact algorithm is checked
        // against.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
