// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Process-local installed-payload verification cache (M06 performance
//! residual closure).
//!
//! # The problem this closes
//!
//! [`super::resolve_owned_managed_component_detailed`] unconditionally
//! re-verifies a managed component's installed-payload SHA-256 digest on
//! *every* call whenever `installed_payload_digest`/`artifact_digest` is
//! recorded -- confirmed by direct measurement (M06 qualification pass) to
//! cost ~1.9-2.0 seconds per call for the merged Rust semantic runtime
//! (3,804 files), with **zero** speedup on an immediate repeat call (no
//! cache existed at all). Since this function is on the hot path of
//! essentially every diagnostics/LSP/formatter resolution, this cost is
//! paid repeatedly within a single `validate_change`/`begin_change` round
//! trip.
//!
//! # What this module does, and does not, change
//!
//! **SHA-256 remains the sole cryptographic trust authority.** This cache
//! never substitutes a cheaper check *for* the SHA-256 comparison that
//! [`super::resolve_owned_managed_component_detailed`] already performs --
//! it only decides, cheaply, whether that comparison's *previous result in
//! this exact process* can be trusted to still hold, by re-proving (not
//! assuming) that nothing on disk has changed since. A cache miss, or any
//! ambiguity in the re-proof, always falls through to the exact same full
//! recursive SHA-256 recomputation this module existed to skip when safe.
//!
//! # Design
//!
//! **Process-local only.** [`invalidate_component`]/[`invalidate_root`] are
//! only ever called by this process's own provisioning/uninstall
//! mutations, never persisted to disk: a fresh Corulix process starts with
//! an empty cache and must perform a full verification on its first
//! resolution of any component, exactly as today.
//!
//! **Cache key.** [`CacheKey`] binds an attestation to
//! `managed_root_identity` + `component_id` + `canonical_component_root` +
//! the ownership record's own `installation_manifest_digest` (a SHA-256
//! over the *entire* record: version, platform, architecture,
//! dependencies, `artifact_digest`, `installed_payload_digest`,
//! `activation_state`, `ownership` class, `optional_segment_digests`). Any
//! reinstall, update, version change, or ownership-record edit produces a
//! different record and therefore a different key -- a stale attestation
//! for a superseded record can never be looked up, let alone reused.
//!
//! **Change detection.** [`metadata_fingerprint_of_tree`]/
//! [`metadata_fingerprint_of_file`] compute a deterministic digest over
//! *filesystem metadata only* (no content bytes read) for every entry a
//! full verification would otherwise hash: relative path, entry kind,
//! executable bit, size, modification time, and (platform-strongest
//! available identity) Unix `(dev, ino, ctime, ctime_nsec)`. This is
//! deliberately **not** mtime-only: `ctime` changes on *any* inode-level
//! mutation, including a content rewrite that preserves size and forges
//! `mtime`, which a pure size+mtime check would miss. A cache hit is
//! granted only when this cheap re-scan, performed synchronously on every
//! call (never an asynchronous watcher an attacker could race or
//! overflow), proves byte-for-byte identical metadata to what was captured
//! at the moment the cached SHA-256 digest was last computed. See the
//! module's own `#[cfg(test)]` block for the property-by-property proof
//! (content-replace, delete, create, rename, mode-change, symlink-swap all
//! change this fingerprint).
//!
//! **Platform policy: this fast path is `cfg(unix)`-only.** Windows's
//! `std` metadata API exposes no field with `ctime`'s "any metadata
//! mutation moves this value, and it cannot be forged through the normal
//! file API" guarantee -- `creation_time` and `file_attributes` (the only
//! extra fields available there) do not change on an in-place, same-size
//! content rewrite whose `last_write_time` has been restored via
//! `SetFileTime`. Rather than accept a weaker, forgeable fast path on that
//! platform, [`get_or_compute`] disables caching there entirely (see
//! [`platform_has_trustworthy_change_detection`]): every resolution on a
//! platform without a trustworthy signal performs the exact same full
//! SHA-256 verification this cache exists to skip when safe. **Security
//! parity across platforms is required for 1.0.0; performance parity is
//! not** -- a Windows-native change-detection signal strong enough to
//! re-enable the fast path there is future work, not a 1.0.0 blocker.
//!
//! **Single-flight, per component.** A per-`(managed_root_identity,
//! component_id)` `std::sync::Mutex` (mirroring
//! [`super::COMPONENT_LOCKS`]'s own per-component-id registry pattern,
//! synchronous rather than `tokio`-async because
//! [`super::resolve_owned_managed_component_detailed`] itself is
//! synchronous) is held for the full duration of a cache lookup + miss-path
//! recompute, so concurrent callers resolving the *same* component never
//! race a redundant full hash; callers for *different* components never
//! block on each other.
//!
//! # What this module deliberately does NOT do
//!
//! Never trusts `mtime` alone (`MTIME_ONLY_CACHE_VALIDATION=NO`). Never
//! persists an attestation to disk or across process restarts. Never
//! treats a metadata read failure, an unexpected entry type, or any other
//! ambiguity as "unchanged" -- [`metadata_fingerprint_of_tree`] propagates
//! the same [`super::ProvisioningError::ContentVerificationFailed`] the
//! full content-digest walk already uses for the same conditions, which
//! the caller treats as a cache miss (falls through to full verification),
//! never as a false "Available". Never widens or narrows the existing
//! [`super::declared_optional_segments`] CORE-boundary exclusion -- the
//! same `exclude_segment_paths` list is threaded through the metadata walk
//! exactly as the content walk already requires.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, OnceLock},
};

use wht_corulix_core::ContentHash;

use super::{COMPONENT_RUNTIME_SCRATCH_DIR_NAME, ProvisioningError};

/// Identity an [`Attestation`] is bound to. Constructed fresh by the caller
/// on every resolution attempt from the just-loaded, just-validated
/// ownership record -- never cached or reused across calls itself, so it
/// always reflects the record on disk *right now*.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct CacheKey {
    pub managed_root_identity: String,
    pub component_id: String,
    pub canonical_component_root: PathBuf,
    /// The ownership record's own whole-record self-digest
    /// (`ManagedInstallationRecord::installation_manifest_digest`) -- see
    /// this module's own doc comment for why this alone makes the key
    /// sensitive to every field a reinstall/update/edit could change.
    pub installation_manifest_digest: String,
}

/// One process-local, already-SHA-256-verified attestation: the exact
/// metadata fingerprint observed at verification time, and the content
/// digest that was proven correct against it in that same pass.
///
/// `captured_at`/`was_settled_at_capture` together implement a "racy cache"
/// guard (the same technique Git's own index uses for its analogous
/// same-second `mtime`-collision problem): a component whose files were
/// modified suspiciously close to the wall-clock moment this attestation
/// was captured cannot be trusted purely on a matching fingerprint, because
/// two *different* file states can produce byte-identical
/// `metadata_fingerprint_of_*` output if both states existed within the
/// same filesystem timestamp tick (empirically reproduced on at least one
/// real environment during this fix's own test development: two
/// successive same-size content replacements, microseconds apart, left
/// `mtime`/`ctime`/size/dev/ino all byte-identical). See
/// [`is_safe_to_reuse`] for the exact rule. `SystemTime` (wall clock, used to
/// judge settledness against a file's own `modified()` value) and
/// `std::time::Instant` (monotonic, used to judge how long ago *this
/// process* captured the attestation) are deliberately never compared to
/// each other directly -- they are different clocks with no defined
/// conversion -- so the settledness verdict is computed once, at capture
/// time, entirely in `SystemTime` terms, and stored as a plain `bool`.
#[derive(Debug, Clone)]
struct Attestation {
    metadata_fingerprint: String,
    verified_content_digest: String,
    /// Monotonic instant (never affected by wall-clock adjustments) at which
    /// this attestation was captured -- used only to measure how much real
    /// time has elapsed *since*, never compared against a `SystemTime`.
    captured_at: std::time::Instant,
    /// Whether, at the moment of capture, every entry's latest `modified()`
    /// timestamp already predated that capture by at least
    /// [`RACY_SETTLE_MARGIN`] -- i.e. the files were already settled/stable
    /// when verified, so no same-tick collision was possible at that moment.
    was_settled_at_capture: bool,
}

/// How much wall-clock time must separate a component's own latest
/// recorded file-modification timestamp from the moment this module
/// verifies it before that verification's attestation may be reused
/// without re-checking its age on every subsequent lookup. Deliberately
/// generous (comfortably larger than the ~1ms granularity measured on this
/// development environment, and larger than the coarser ~1s granularity
/// some real filesystems -- e.g. FAT-family -- are known to have for
/// modification times) rather than tuned to the fastest environment
/// observed.
const RACY_SETTLE_MARGIN: std::time::Duration = std::time::Duration::from_secs(2);

type CacheTable = HashMap<CacheKey, Attestation>;
type ComponentVerificationLockRegistry = StdMutex<HashMap<(String, String), Arc<StdMutex<()>>>>;

static CACHE: OnceLock<StdMutex<CacheTable>> = OnceLock::new();
static VERIFICATION_LOCKS: OnceLock<ComponentVerificationLockRegistry> = OnceLock::new();

fn cache() -> &'static StdMutex<CacheTable> {
    CACHE.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// Acquires (creating if necessary) the single-flight lock for
/// `(managed_root_identity, component_id)`. Distinct components (or the
/// same component under a different root) never block on each other --
/// only two calls resolving the *identical* component under the *identical*
/// root ever contend.
fn verification_lock(managed_root_identity: &str, component_id: &str) -> Arc<StdMutex<()>> {
    let registry = VERIFICATION_LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut guard = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .entry((managed_root_identity.to_string(), component_id.to_string()))
        .or_insert_with(|| Arc::new(StdMutex::new(())))
        .clone()
}

/// Removes every cached attestation for `component_id` under
/// `managed_root_identity`, regardless of which
/// `installation_manifest_digest` it was keyed under. Called by every
/// production mutation path for that component (provision, reinstall,
/// single uninstall) so a superseded attestation can never be looked up
/// again even in the (already-impossible, since the key includes the
/// record digest) case of a digest collision.
pub(super) fn invalidate_component(managed_root_identity: &str, component_id: &str) {
    let mut table = cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    table.retain(|key, _| {
        !(key.managed_root_identity == managed_root_identity && key.component_id == component_id)
    });
}

/// Removes every cached attestation bound to `managed_root_identity`,
/// regardless of component. Called by `full_uninstall` (which may remove
/// or invalidate several components' identities at once) rather than
/// requiring it to enumerate every component id itself.
pub(super) fn invalidate_root(managed_root_identity: &str) {
    let mut table = cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    table.retain(|key, _| key.managed_root_identity != managed_root_identity);
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

/// Encodes one entry's *metadata only* (never its content bytes) into
/// `bytes`, using the strongest per-platform identity/change signal
/// available from `std` alone (no new dependency): on Unix, device +
/// inode + `ctime` (bumped on any inode mutation, including a
/// same-size/forged-mtime content rewrite -- the reason this is not
/// merely `mtime`); on other platforms, creation time + file attributes +
/// modified time -- computed uniformly on every platform for a stable,
/// single code path, but on a platform where
/// [`platform_has_trustworthy_change_detection`] returns `false` this
/// fingerprint is never actually consulted for a cache-hit decision (see
/// [`get_or_compute`]'s own doc comment). Mirrors [`super::encode_tree_entry`]'s own structure
/// (relative path, kind, executable bit, symlink target) so the two can
/// never silently drift on what counts as "one entry". Also folds this
/// entry's own `modified()` timestamp into `latest_modified` (kept as the
/// maximum seen across the whole walk) -- the raw signal
/// [`is_safe_to_reuse`]'s racy-cache guard needs, independent of and in
/// addition to this function's own byte-level fingerprint.
fn encode_entry_metadata(
    component_root: &Path,
    relative: &Path,
    bytes: &mut Vec<u8>,
    latest_modified: &mut std::time::SystemTime,
) -> Result<(), ProvisioningError> {
    let absolute = component_root.join(relative);
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|_| ProvisioningError::ContentVerificationFailed)?;
    bytes.extend_from_slice(relative.to_string_lossy().as_bytes());
    bytes.push(0);

    if metadata.file_type().is_symlink() {
        let target =
            fs::read_link(&absolute).map_err(|_| ProvisioningError::ContentVerificationFailed)?;
        bytes.extend_from_slice(b"symlink\0");
        bytes.extend_from_slice(target.to_string_lossy().as_bytes());
    } else if metadata.is_file() {
        bytes.extend_from_slice(b"file\0");
        bytes.push(u8::from(is_executable(&metadata)));
        bytes.push(0);
        bytes.extend_from_slice(&metadata.len().to_le_bytes());
        if let Ok(modified) = metadata.modified() {
            *latest_modified = (*latest_modified).max(modified);
            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                bytes.extend_from_slice(&duration.as_nanos().to_le_bytes());
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            bytes.extend_from_slice(&metadata.dev().to_le_bytes());
            bytes.extend_from_slice(&metadata.ino().to_le_bytes());
            bytes.extend_from_slice(&metadata.ctime().to_le_bytes());
            bytes.extend_from_slice(&metadata.ctime_nsec().to_le_bytes());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            bytes.extend_from_slice(&metadata.creation_time().to_le_bytes());
            bytes.extend_from_slice(&metadata.file_attributes().to_le_bytes());
        }
    } else {
        return Err(ProvisioningError::ContentVerificationFailed);
    }
    bytes.push(b'\n');
    Ok(())
}

/// The metadata-only counterpart of
/// [`super::compute_tree_installed_digest`]: same deterministic, sorted,
/// recursive walk (same exclusions -- the runtime scratch directory and
/// every declared `OptionalSegment` path), but hashing only
/// [`encode_entry_metadata`]'s cheap per-entry metadata rather than reading
/// and hashing every file's content. `O(file count)` `stat`-class syscalls,
/// zero content reads. Returns the fingerprint alongside the latest
/// `modified()` timestamp observed across the whole tree (for
/// [`is_safe_to_reuse`]'s racy-cache guard).
pub(super) fn metadata_fingerprint_of_tree(
    component_root: &Path,
    exclude_segment_paths: &[&str],
) -> Result<(String, std::time::SystemTime), ProvisioningError> {
    let mut relative_paths = Vec::new();
    collect_metadata_entries(
        component_root,
        component_root,
        exclude_segment_paths,
        &mut relative_paths,
    )?;
    relative_paths.sort();

    let mut bytes = Vec::new();
    let mut latest_modified = std::time::UNIX_EPOCH;
    for relative in &relative_paths {
        encode_entry_metadata(component_root, relative, &mut bytes, &mut latest_modified)?;
    }
    Ok((
        ContentHash::compute_sha256(&bytes).digest_hex,
        latest_modified,
    ))
}

/// Metadata-only walk mirroring [`super::collect_tree_entries`] exactly
/// (same scratch-directory/segment exclusions, same directory recursion,
/// same non-following-symlink-as-leaf behavior) -- kept as an independent
/// copy rather than a shared generic so a future change to one walk's
/// content-hashing behavior can never accidentally alter the other's
/// metadata-only behavior (or vice versa) without an explicit edit to both.
fn collect_metadata_entries(
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
            collect_metadata_entries(root, &path, exclude, out)?;
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

/// The metadata-only counterpart of a single-file content digest
/// (`compute_single_file_installed_digest`/the `RawBinary` artifact-digest
/// check) -- one entry's worth of [`encode_entry_metadata`]. Returns the
/// fingerprint alongside that one file's own `modified()` timestamp (for
/// [`is_safe_to_reuse`]'s racy-cache guard).
pub(super) fn metadata_fingerprint_of_file(
    path: &Path,
) -> Result<(String, std::time::SystemTime), ProvisioningError> {
    let mut bytes = Vec::new();
    let mut latest_modified = std::time::UNIX_EPOCH;
    // A bare file has no meaningful "relative path" of its own for this
    // purpose (there is exactly one entry); an empty relative path still
    // participates in the same encoding so this stays one code path with
    // the tree variant's `encode_entry_metadata`.
    encode_entry_metadata(
        path.parent().unwrap_or(path),
        Path::new(path.file_name().unwrap_or_default()),
        &mut bytes,
        &mut latest_modified,
    )?;
    Ok((
        ContentHash::compute_sha256(&bytes).digest_hex,
        latest_modified,
    ))
}

/// Decides whether `attestation` may be reused for a lookup happening right
/// now, given that its `metadata_fingerprint` already matched. This is the
/// "racy cache" guard described on [`Attestation`]: a fingerprint match
/// alone is not sufficient when the component's own files were modified
/// suspiciously close (in wall-clock terms) to the moment the attestation
/// was captured, because two genuinely different file states can collide on
/// an identical fingerprint if both existed within the same filesystem
/// timestamp tick.
///
/// The attestation is safe to reuse when EITHER of two independent proofs
/// holds:
///
/// 1. `was_settled_at_capture` -- the component's files were already
///    settled/stable (their latest modification predated verification by at
///    least [`RACY_SETTLE_MARGIN`]) at the moment they were verified, so no
///    tick-level collision was possible at capture time; or
/// 2. Enough real wall-clock time has now elapsed since capture
///    (`captured_at.elapsed() >= RACY_SETTLE_MARGIN`, measured on the
///    monotonic clock so it can never be fooled by a wall-clock adjustment)
///    that any tampering which happened after capture would necessarily
///    land in a filesystem timestamp tick distinguishable from the one
///    captured, and therefore would already have changed the fingerprint
///    this call just matched.
///
/// When neither holds, the attestation is treated exactly like a miss (falls
/// through to a fresh full recompute) -- never as a false hit.
fn is_safe_to_reuse(attestation: &Attestation) -> bool {
    attestation.was_settled_at_capture || attestation.captured_at.elapsed() >= RACY_SETTLE_MARGIN
}

/// Computes [`Attestation::was_settled_at_capture`] at the moment of
/// capture: `true` only when `latest_entry_modified`'s own age (relative to
/// "now", i.e. capture time) is already at least [`RACY_SETTLE_MARGIN`].
/// A `modified()` timestamp in the future (clock skew) or one that cannot be
/// compared at all is treated as NOT settled -- fails closed into requiring
/// [`is_safe_to_reuse`]'s second, elapsed-time-based proof instead.
fn was_already_settled(latest_entry_modified: std::time::SystemTime) -> bool {
    std::time::SystemTime::now()
        .duration_since(latest_entry_modified)
        .is_ok_and(|age| age >= RACY_SETTLE_MARGIN)
}

/// Whether the current platform's [`encode_entry_metadata`] fingerprint
/// carries a change-detection field with the same non-forgeable, "any
/// metadata mutation moves this value" guarantee POSIX `ctime` provides.
///
/// `true` on every `cfg(unix)` target: Linux, macOS, and other BSD-family
/// systems alike all implement `std::os::unix::fs::MetadataExt`, whose
/// `ctime`/`ctime_nsec` map directly to the POSIX `st_ctime`/`st_ctime_nsec`
/// fields -- a POSIX-conformant filesystem is required to bump these on
/// *any* inode metadata change, content rewrites included, and a caller
/// cannot forge them back through the normal file API the way `mtime` can
/// be restored via `utimes`. This is a structural, standards-based
/// guarantee, not merely "the same code path as Linux" -- macOS's own
/// filesystems (APFS, HFS+) are POSIX-conformant for this field exactly as
/// Linux's are.
///
/// `false` on Windows (and any other non-`unix` target): `std`'s Windows
/// metadata API exposes no equivalent field. `creation_time` and
/// `file_attributes` -- the only additional fields [`encode_entry_metadata`]
/// can read there -- do not change on an in-place, same-size content
/// rewrite whose `last_write_time` has been restored via `SetFileTime`, so
/// there is no trustworthy signal this cache's fast path could rely on.
/// Rather than accept that weaker guarantee for a performance win, this
/// module disables its own fast path entirely wherever this returns
/// `false` -- see [`get_or_compute`]. **Security parity across platforms
/// is required for 1.0.0; performance parity is not.**
#[cfg(unix)]
const fn platform_has_trustworthy_change_detection() -> bool {
    true
}

#[cfg(not(unix))]
const fn platform_has_trustworthy_change_detection() -> bool {
    false
}

/// Returns the already-verified content digest for `key` if a cached
/// attestation exists, `current_metadata_fingerprint` (computed by the
/// caller, via [`metadata_fingerprint_of_tree`]/[`metadata_fingerprint_of_file`],
/// *before* calling this) still matches it byte-for-byte, AND
/// [`is_safe_to_reuse`] confirms the match cannot be a same-tick collision;
/// otherwise calls `compute_fresh` -- which must perform the real, full
/// content-digest computation and return `(fresh_metadata_fingerprint,
/// fresh_content_digest, fresh_latest_entry_modified)` captured from one
/// single verification pass -- and caches its result before returning it.
///
/// Holds this component's single-flight lock for the entire call, including
/// while `compute_fresh` runs: a second concurrent caller resolving the
/// *same* `(managed_root_identity, component_id)` blocks here until the
/// first caller's `compute_fresh` (if it ran one) has completed and been
/// stored, then observes the fresh attestation as a hit itself -- never a
/// second redundant full hash for the same component state. A caller for a
/// *different* component never blocks on this one (`verification_lock`
/// keys per component, not globally).
///
/// On a platform without a trustworthy change-detection signal (see
/// [`platform_has_trustworthy_change_detection`]), this never consults or
/// populates the cache at all -- every call performs the full
/// `compute_fresh` verification, exactly as every platform did before this
/// cache existed.
pub(super) fn get_or_compute<F>(
    key: &CacheKey,
    current_metadata_fingerprint: &str,
    compute_fresh: F,
) -> Result<String, ProvisioningError>
where
    F: FnOnce() -> Result<(String, String, std::time::SystemTime), ProvisioningError>,
{
    get_or_compute_with_capability(
        key,
        current_metadata_fingerprint,
        platform_has_trustworthy_change_detection(),
        compute_fresh,
    )
}

/// The real logic behind [`get_or_compute`], parameterized on whether the
/// current platform's fingerprint is trustworthy -- factored out so the
/// `fast_cache_supported = false` branch (Windows's actual production
/// behavior) is directly unit-testable on any development platform,
/// without requiring an actual Windows host to prove the logic (see
/// [`tests::platform_without_trustworthy_change_detection_never_uses_the_cache`]).
fn get_or_compute_with_capability<F>(
    key: &CacheKey,
    current_metadata_fingerprint: &str,
    fast_cache_supported: bool,
    compute_fresh: F,
) -> Result<String, ProvisioningError>
where
    F: FnOnce() -> Result<(String, String, std::time::SystemTime), ProvisioningError>,
{
    if !fast_cache_supported {
        // No trustworthy, non-forgeable change-detection signal exists on
        // this platform. SHA-256 remains not merely the cryptographic
        // authority but the ONLY verification ever performed here: never
        // looks at the cache table, never stores into it.
        let (_fingerprint, digest, _latest_modified) = compute_fresh()?;
        return Ok(digest);
    }

    let lock = verification_lock(&key.managed_root_identity, &key.component_id);
    let _single_flight_guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    {
        let table = cache()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(attestation) = table.get(key)
            && attestation.metadata_fingerprint == current_metadata_fingerprint
            && is_safe_to_reuse(attestation)
        {
            return Ok(attestation.verified_content_digest.clone());
        }
        // Table lock released here (end of block) before running the
        // potentially slow `compute_fresh` -- the per-component
        // `_single_flight_guard` above is what actually provides
        // single-flight; the short-lived table lock only ever protects the
        // `HashMap` itself, never gates the expensive computation.
    }

    let (fresh_fingerprint, fresh_digest, fresh_latest_modified) = compute_fresh()?;
    let mut table = cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    table.insert(
        key.clone(),
        Attestation {
            metadata_fingerprint: fresh_fingerprint,
            verified_content_digest: fresh_digest.clone(),
            captured_at: std::time::Instant::now(),
            was_settled_at_capture: was_already_settled(fresh_latest_modified),
        },
    );
    Ok(fresh_digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(path, contents).unwrap_or_else(|error| {
            unreachable!("test fixture write to {path:?} failed: {error:?}")
        });
    }

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("corulix-payload-cache-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn fingerprint(root: &Path, exclude: &[&str], label: &str) -> String {
        metadata_fingerprint_of_tree(root, exclude)
            .unwrap_or_else(|error| {
                unreachable!("{label} fingerprint computation failed: {error:?}")
            })
            .0
    }

    #[test]
    fn unchanged_tree_produces_an_identical_fingerprint() {
        let root = temp_dir("unchanged");
        write_file(&root.join("a.txt"), b"hello");
        write_file(&root.join("sub/b.txt"), b"world");
        let first = fingerprint(&root, &[], "first");
        let second = fingerprint(&root, &[], "second");
        assert_eq!(first, second);
        let _ = fs::remove_dir_all(&root);
    }

    /// NOTE on scope: this proves the fingerprint reacts to a same-size,
    /// forged-mtime content replacement whenever the replacement is
    /// separated from the original write by real (if tiny) wall-clock time
    /// -- it deliberately does **not** claim anything about a zero-delay,
    /// same-tick replacement, which this environment was empirically proven
    /// (during this fix's own development) to leave `ctime` unchanged for.
    /// That harder, adversarially-relevant case is proven separately and
    /// explicitly by
    /// [`post_settle_corruption_with_forged_mtime_is_detected_via_ctime`]
    /// (the real Section 13 scenario: attestation already trust-eligible,
    /// *then* corrupted) and by
    /// [`warm_cache_rejects_same_tick_corruption_even_when_the_fingerprint_collides`]
    /// (the cache-layer guard that fires when even `ctime` cannot
    /// discriminate). This test's own original name implied a
    /// fingerprint-level guarantee this environment cannot actually give at
    /// zero delay -- renamed to state only what is actually proven here.
    ///
    /// `#[cfg(unix)]`: this specific scenario (same-size content
    /// replacement, mtime successfully forged back, discriminated only via
    /// `ctime`) is structurally Unix-only -- `ctime` has no Windows
    /// equivalent (see [`platform_has_trustworthy_change_detection`]'s own
    /// doc comment). On Windows a genuinely successful same-size
    /// content+forged-mtime+unchanged-attributes replacement produces an
    /// identical fingerprint, by design: `get_or_compute`'s Windows branch
    /// never consults this fingerprint for a cache decision at all (every
    /// call performs a full, real content-digest `compute_fresh`), so this
    /// is not a security gap, only a scope this Unix-oriented fingerprint
    /// test does not extend to.
    #[cfg(unix)]
    #[test]
    fn content_replacement_is_detected_when_writes_are_separated_by_real_time() {
        let root = temp_dir("content-replace");
        let file = root.join("a.txt");
        write_file(&file, b"hello");
        let before = fingerprint(&root, &[], "before");

        let Ok(original_metadata) = fs::symlink_metadata(&file) else {
            unreachable!("fixture file must exist");
        };
        let Ok(original_mtime) = original_metadata.modified() else {
            unreachable!("fixture file must report a modified time");
        };
        std::thread::sleep(std::time::Duration::from_millis(5));
        write_file(&file, b"olleh");
        if let Ok(handle) = fs::OpenOptions::new().write(true).open(&file) {
            let _ = handle.set_modified(original_mtime);
        }

        let after = fingerprint(&root, &[], "after");
        assert_ne!(
            before, after,
            "content replacement with forged mtime, separated by real time, must still be detected"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// The real Section 13 scenario, proven end to end through the actual
    /// cache API (not just the bare fingerprint function): provision
    /// (write) a component, perform a full verification that warms the
    /// cache, wait until the attestation is genuinely trust-eligible (past
    /// [`RACY_SETTLE_MARGIN`], exactly as a real installed component --
    /// untouched for seconds, minutes, or longer -- would be on its very
    /// next resolution), corrupt one payload byte with a forged mtime, then
    /// resolve again. The cached digest MUST NOT be returned for the
    /// corrupted state.
    ///
    /// This is the test that actually discriminates whether `ctime`-based
    /// detection works once real time has elapsed since capture, as
    /// distinct from [`warm_cache_rejects_same_tick_corruption_even_when_the_fingerprint_collides`],
    /// which only proves the racy window itself is refused (it would pass
    /// even if `ctime` never changed at all, since the settledness guard
    /// alone forces the recompute there). If this test failed, it would be
    /// a `SECURITY_BLOCKER`: it would mean the 2-second margin is not
    /// actually sufficient for `ctime` to have moved to a distinguishable
    /// value, and the cache design would need a stronger, non-timestamp
    /// change signal.
    #[test]
    fn post_settle_corruption_with_forged_mtime_is_detected_via_ctime() {
        let root = temp_dir("post-settle-corrupt");
        let file = root.join("a.txt");
        write_file(&file, b"hello");
        let (fingerprint_before, modified_before) = metadata_fingerprint_of_tree(&root, &[])
            .unwrap_or_else(|error| unreachable!("fingerprint computation failed: {error:?}"));
        let key = CacheKey {
            managed_root_identity: "root-post-settle".to_string(),
            component_id: "comp-post-settle".to_string(),
            canonical_component_root: root.clone(),
            installation_manifest_digest: "digest-post-settle".to_string(),
        };

        let warm = expect_ok(
            get_or_compute(&key, &fingerprint_before, || {
                Ok((
                    fingerprint_before.clone(),
                    "genuine-content-digest".to_string(),
                    modified_before,
                ))
            }),
            "warm the cache",
        );
        assert_eq!(warm, "genuine-content-digest");

        // Wait past the settle margin so the attestation becomes genuinely
        // trust-eligible on fingerprint match alone -- the realistic state
        // of a long-installed, untouched component.
        std::thread::sleep(RACY_SETTLE_MARGIN + std::time::Duration::from_millis(200));

        let Ok(original_metadata) = fs::symlink_metadata(&file) else {
            unreachable!("fixture file must exist");
        };
        let Ok(original_mtime) = original_metadata.modified() else {
            unreachable!("fixture file must report a modified time");
        };
        write_file(&file, b"HACKED");
        if let Ok(handle) = fs::OpenOptions::new().write(true).open(&file) {
            let _ = handle.set_modified(original_mtime);
        }

        let (fingerprint_after, modified_after) = metadata_fingerprint_of_tree(&root, &[])
            .unwrap_or_else(|error| unreachable!("fingerprint computation failed: {error:?}"));
        assert_ne!(
            fingerprint_before, fingerprint_after,
            "SECURITY_BLOCKER: ctime did not move on a corrupting write separated by \
             RACY_SETTLE_MARGIN from the warmed attestation -- the settle margin is not \
             sufficient on this environment and the cache design must not rely on ctime alone"
        );

        let mut recomputed = false;
        let resolved = expect_ok(
            get_or_compute(&key, &fingerprint_after, || {
                recomputed = true;
                Ok((
                    fingerprint_after.clone(),
                    "corrupted-content-digest".to_string(),
                    modified_after,
                ))
            }),
            "resolve after post-settle corruption",
        );
        assert!(
            recomputed,
            "a changed fingerprint must never be served from a stale attestation"
        );
        assert_eq!(
            resolved, "corrupted-content-digest",
            "the cache must never keep serving the pre-corruption digest"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// The CRITICAL warm-cache-corruption property (mandate Section 13):
    /// even in the pathological case where a same-size content replacement
    /// with a forged mtime lands in the exact same filesystem timestamp
    /// tick as the cached attestation (so the metadata fingerprint itself
    /// collides -- reproduced directly here via a zero-delay replacement),
    /// the cache must still refuse to serve the stale digest. It is
    /// [`is_safe_to_reuse`]'s settledness guard -- not the fingerprint's own
    /// collision-resistance -- that closes this gap: a just-captured,
    /// just-modified attestation is never trusted until it either was
    /// already settled at capture or enough wall-clock time has elapsed
    /// since.
    #[test]
    fn warm_cache_rejects_same_tick_corruption_even_when_the_fingerprint_collides() {
        let root = temp_dir("warm-corrupt-same-tick");
        let file = root.join("a.txt");
        write_file(&file, b"hello");
        let (fingerprint_before, modified_before) = metadata_fingerprint_of_tree(&root, &[])
            .unwrap_or_else(|error| unreachable!("fingerprint computation failed: {error:?}"));
        let key = CacheKey {
            managed_root_identity: "root-corrupt".to_string(),
            component_id: "comp-corrupt".to_string(),
            canonical_component_root: root.clone(),
            installation_manifest_digest: "digest-corrupt".to_string(),
        };

        // Warm the cache with the genuine, verified digest.
        let mut compute_calls = 0;
        let warm = expect_ok(
            get_or_compute(&key, &fingerprint_before, || {
                compute_calls += 1;
                Ok((
                    fingerprint_before.clone(),
                    "genuine-content-digest".to_string(),
                    modified_before,
                ))
            }),
            "warm the cache",
        );
        assert_eq!(warm, "genuine-content-digest");
        assert_eq!(compute_calls, 1);

        // Corrupt: same-size content replacement, forged mtime, zero delay
        // -- the pathological same-tick case.
        let Ok(original_metadata) = fs::symlink_metadata(&file) else {
            unreachable!("fixture file must exist");
        };
        let Ok(original_mtime) = original_metadata.modified() else {
            unreachable!("fixture file must report a modified time");
        };
        write_file(&file, b"HACKED");
        if let Ok(handle) = fs::OpenOptions::new().write(true).open(&file) {
            let _ = handle.set_modified(original_mtime);
        }
        let (fingerprint_after, modified_after) = metadata_fingerprint_of_tree(&root, &[])
            .unwrap_or_else(|error| unreachable!("fingerprint computation failed: {error:?}"));

        // Resolve again with whatever the current fingerprint now is
        // (whether or not it happens to collide with the cached one is
        // exactly the property under test -- the cache must reject the
        // stale attestation regardless).
        let mut recomputed = false;
        let resolved = expect_ok(
            get_or_compute(&key, &fingerprint_after, || {
                recomputed = true;
                Ok((
                    fingerprint_after.clone(),
                    "corrupted-content-digest".to_string(),
                    modified_after,
                ))
            }),
            "resolve after corruption",
        );
        assert!(
            recomputed,
            "a just-warmed, just-modified attestation must never be trusted on a bare fingerprint match"
        );
        assert_eq!(
            resolved, "corrupted-content-digest",
            "the cache must never keep serving the pre-corruption digest"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn file_deletion_changes_the_fingerprint() {
        let root = temp_dir("delete");
        let file = root.join("a.txt");
        write_file(&file, b"hello");
        let before = fingerprint(&root, &[], "before");
        let _ = fs::remove_file(&file);
        let after = metadata_fingerprint_of_tree(&root, &[]);
        // Either an explicit error (the collector cannot stat a vanished
        // entry it already listed) or, if listed fresh, a differing digest
        // (the file is simply absent from the walk) -- either outcome is a
        // correct "not a cache hit", never a silent match.
        if let Ok((digest, _latest_modified)) = after {
            assert_ne!(before, digest);
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn new_file_changes_the_fingerprint() {
        let root = temp_dir("create");
        write_file(&root.join("a.txt"), b"hello");
        let before = fingerprint(&root, &[], "before");
        write_file(&root.join("b.txt"), b"new");
        let after = fingerprint(&root, &[], "after");
        assert_ne!(before, after);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_changes_the_fingerprint() {
        let root = temp_dir("rename");
        let original = root.join("a.txt");
        write_file(&original, b"hello");
        let before = fingerprint(&root, &[], "before");
        if fs::rename(&original, root.join("renamed.txt")).is_err() {
            unreachable!("fixture rename must succeed");
        }
        let after = fingerprint(&root, &[], "after");
        assert_ne!(before, after);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn executable_mode_change_changes_the_fingerprint() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_dir("mode");
        let file = root.join("a.txt");
        write_file(&file, b"hello");
        let before = fingerprint(&root, &[], "before");
        let Ok(existing) = fs::metadata(&file) else {
            unreachable!("fixture file must exist");
        };
        let mut permissions = existing.permissions();
        permissions.set_mode(permissions.mode() | 0o111);
        let _ = fs::set_permissions(&file, permissions);
        let after = fingerprint(&root, &[], "after");
        assert_ne!(before, after);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_replacement_changes_the_fingerprint() {
        let root = temp_dir("symlink");
        write_file(&root.join("target-a"), b"a");
        write_file(&root.join("target-b"), b"b");
        let _ = std::os::unix::fs::symlink(root.join("target-a"), root.join("link"));
        let before = fingerprint(&root, &[], "before");
        let _ = fs::remove_file(root.join("link"));
        let _ = std::os::unix::fs::symlink(root.join("target-b"), root.join("link"));
        let after = fingerprint(&root, &[], "after");
        assert_ne!(before, after);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn excluded_segment_paths_are_never_part_of_the_fingerprint() {
        let root = temp_dir("segment");
        write_file(&root.join("core.txt"), b"core");
        write_file(&root.join("optional.txt"), b"optional");
        let with_segment_present = fingerprint(&root, &["optional.txt"], "fp1");
        let _ = fs::remove_file(root.join("optional.txt"));
        let with_segment_absent = fingerprint(&root, &["optional.txt"], "fp2");
        assert_eq!(
            with_segment_present, with_segment_absent,
            "an excluded segment path's presence/absence must never affect the CORE fingerprint"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn single_flight_lock_serializes_same_component_never_different_ones() {
        let lock_a1 = verification_lock("root-1", "component-a");
        let lock_a2 = verification_lock("root-1", "component-a");
        let lock_b = verification_lock("root-1", "component-b");
        assert!(
            Arc::ptr_eq(&lock_a1, &lock_a2),
            "same identity must share one lock"
        );
        assert!(
            !Arc::ptr_eq(&lock_a1, &lock_b),
            "different components must never share a lock"
        );
    }

    fn expect_ok(result: Result<String, ProvisioningError>, label: &str) -> String {
        result.unwrap_or_else(|error| unreachable!("{label} must succeed, got {error:?}"))
    }

    /// A `SystemTime` comfortably older than [`RACY_SETTLE_MARGIN`], for
    /// tests that seed a `compute_fresh` result and want to exercise the
    /// ordinary steady-state hit path rather than the racy-window guard.
    fn long_settled_time() -> std::time::SystemTime {
        std::time::SystemTime::now() - std::time::Duration::from_secs(3600)
    }

    /// Test-only direct insert, bypassing `get_or_compute`'s lock dance --
    /// used only to seed "already cached" state before exercising the real
    /// hit/miss/invalidation logic. Always seeds `was_settled_at_capture:
    /// true` (a component that was already stable long before this test
    /// started) so these tests exercise the ordinary steady-state hit path
    /// rather than the racy-window guard, which has its own dedicated tests.
    fn store_for_test(key: CacheKey, metadata_fingerprint: &str, verified_content_digest: &str) {
        let mut table = cache()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        table.insert(
            key,
            Attestation {
                metadata_fingerprint: metadata_fingerprint.to_string(),
                verified_content_digest: verified_content_digest.to_string(),
                captured_at: std::time::Instant::now(),
                was_settled_at_capture: true,
            },
        );
    }

    #[test]
    fn cache_hit_only_when_fingerprint_matches_and_miss_otherwise() {
        let key = CacheKey {
            managed_root_identity: "root-x".to_string(),
            component_id: "comp-x".to_string(),
            canonical_component_root: PathBuf::from("/tmp/does-not-matter"),
            installation_manifest_digest: "digest-1".to_string(),
        };
        let mut compute_calls = 0;
        // This test exercises the CACHING logic itself (hit/miss on
        // fingerprint match), which only exists when
        // `fast_cache_supported = true` -- so it selects that capability
        // explicitly, exactly as
        // `platform_with_trustworthy_change_detection_still_uses_the_cache`
        // already does, rather than depending on the host platform's own
        // `platform_has_trustworthy_change_detection()` dispatch (which is
        // `false` on Windows by design and would make every assertion below
        // about a cache HIT fail there for a reason unrelated to what this
        // test actually verifies).
        let result = expect_ok(
            get_or_compute_with_capability(&key, "fingerprint-1", true, || {
                compute_calls += 1;
                Ok((
                    "fingerprint-1".to_string(),
                    "content-digest-1".to_string(),
                    long_settled_time(),
                ))
            }),
            "first call",
        );
        assert_eq!(result, "content-digest-1");
        assert_eq!(
            compute_calls, 1,
            "first call for an uncached key must compute"
        );

        let result = expect_ok(
            get_or_compute_with_capability(&key, "fingerprint-1", true, || {
                compute_calls += 1;
                Ok((
                    "fingerprint-1".to_string(),
                    "SHOULD_NOT_BE_USED".to_string(),
                    long_settled_time(),
                ))
            }),
            "second call",
        );
        assert_eq!(
            result, "content-digest-1",
            "an unchanged fingerprint must reuse the cached digest"
        );
        assert_eq!(
            compute_calls, 1,
            "an unchanged fingerprint must never recompute"
        );

        let result = expect_ok(
            get_or_compute_with_capability(&key, "fingerprint-2", true, || {
                compute_calls += 1;
                Ok((
                    "fingerprint-2".to_string(),
                    "content-digest-2".to_string(),
                    long_settled_time(),
                ))
            }),
            "third call",
        );
        assert_eq!(result, "content-digest-2");
        assert_eq!(
            compute_calls, 2,
            "a changed fingerprint must force a recompute"
        );
    }

    #[test]
    fn a_different_installation_manifest_digest_is_a_different_key() {
        let base = CacheKey {
            managed_root_identity: "root-y".to_string(),
            component_id: "comp-y".to_string(),
            canonical_component_root: PathBuf::from("/tmp/does-not-matter"),
            installation_manifest_digest: "digest-a".to_string(),
        };
        store_for_test(base.clone(), "fp", "content-a");
        let mut reinstalled = base;
        reinstalled.installation_manifest_digest = "digest-b".to_string();
        let mut computed_fresh = false;
        let result = expect_ok(
            get_or_compute(&reinstalled, "fp", || {
                computed_fresh = true;
                Ok((
                    "fp".to_string(),
                    "content-b".to_string(),
                    long_settled_time(),
                ))
            }),
            "reinstalled key",
        );
        assert!(
            computed_fresh,
            "a reinstalled component's new record digest must never reuse the old attestation"
        );
        assert_eq!(result, "content-b");
    }

    #[test]
    fn invalidate_component_removes_only_that_components_entries() {
        let key_a = CacheKey {
            managed_root_identity: "root-z".to_string(),
            component_id: "comp-a".to_string(),
            canonical_component_root: PathBuf::from("/tmp/a"),
            installation_manifest_digest: "d1".to_string(),
        };
        let key_b = CacheKey {
            managed_root_identity: "root-z".to_string(),
            component_id: "comp-b".to_string(),
            canonical_component_root: PathBuf::from("/tmp/b"),
            installation_manifest_digest: "d2".to_string(),
        };
        store_for_test(key_a.clone(), "fp-a", "content-a");
        store_for_test(key_b.clone(), "fp-b", "content-b");
        invalidate_component("root-z", "comp-a");

        // Explicit `true`: this test verifies invalidation against the
        // CACHING branch specifically (see the capability-selection note on
        // `cache_hit_only_when_fingerprint_matches_and_miss_otherwise`).
        let mut a_recomputed = false;
        let a_result = expect_ok(
            get_or_compute_with_capability(&key_a, "fp-a", true, || {
                a_recomputed = true;
                Ok((
                    "fp-a".to_string(),
                    "content-a-fresh".to_string(),
                    long_settled_time(),
                ))
            }),
            "component a",
        );
        assert!(a_recomputed, "invalidated component must recompute");
        assert_eq!(a_result, "content-a-fresh");

        let mut b_recomputed = false;
        let b_result = expect_ok(
            get_or_compute_with_capability(&key_b, "fp-b", true, || {
                b_recomputed = true;
                Ok((
                    "fp-b".to_string(),
                    "SHOULD_NOT_BE_USED".to_string(),
                    long_settled_time(),
                ))
            }),
            "component b",
        );
        assert!(!b_recomputed, "untouched component must still hit");
        assert_eq!(b_result, "content-b");
    }

    #[test]
    fn invalidate_root_removes_every_component_under_that_root_only() {
        let key_root1 = CacheKey {
            managed_root_identity: "root-1".to_string(),
            component_id: "comp".to_string(),
            canonical_component_root: PathBuf::from("/tmp/1"),
            installation_manifest_digest: "d1".to_string(),
        };
        let key_root2 = CacheKey {
            managed_root_identity: "root-2".to_string(),
            component_id: "comp".to_string(),
            canonical_component_root: PathBuf::from("/tmp/2"),
            installation_manifest_digest: "d2".to_string(),
        };
        store_for_test(key_root1.clone(), "fp", "content-1");
        store_for_test(key_root2.clone(), "fp", "content-2");
        invalidate_root("root-1");

        // Explicit `true`: same capability-selection reason as the sibling
        // invalidation test above.
        let mut r1_recomputed = false;
        let r1_result = expect_ok(
            get_or_compute_with_capability(&key_root1, "fp", true, || {
                r1_recomputed = true;
                Ok((
                    "fp".to_string(),
                    "content-1-fresh".to_string(),
                    long_settled_time(),
                ))
            }),
            "root 1",
        );
        assert!(r1_recomputed);
        assert_eq!(r1_result, "content-1-fresh");

        let mut r2_recomputed = false;
        let r2_result = expect_ok(
            get_or_compute_with_capability(&key_root2, "fp", true, || {
                r2_recomputed = true;
                Ok((
                    "fp".to_string(),
                    "SHOULD_NOT_BE_USED".to_string(),
                    long_settled_time(),
                ))
            }),
            "root 2",
        );
        assert!(!r2_recomputed);
        assert_eq!(r2_result, "content-2");
    }

    #[test]
    fn freshly_modified_component_is_not_immediately_trusted_across_the_racy_window() {
        let root = temp_dir("racy-window");
        write_file(&root.join("a.txt"), b"hello");
        let (real_fingerprint, real_latest_modified) = metadata_fingerprint_of_tree(&root, &[])
            .unwrap_or_else(|error| {
                unreachable!("fixture tree fingerprint computation failed: {error:?}")
            });
        let key = CacheKey {
            managed_root_identity: "root-racy".to_string(),
            component_id: "comp-racy".to_string(),
            canonical_component_root: root.clone(),
            installation_manifest_digest: "digest-racy".to_string(),
        };

        let mut compute_calls = 0;
        let first = expect_ok(
            get_or_compute(&key, &real_fingerprint, || {
                compute_calls += 1;
                Ok((
                    real_fingerprint.clone(),
                    "content-racy-1".to_string(),
                    real_latest_modified,
                ))
            }),
            "first (just-written file) call",
        );
        assert_eq!(first, "content-racy-1");
        assert_eq!(compute_calls, 1);

        // The file's own `modified()` is only microseconds old (well inside
        // `RACY_SETTLE_MARGIN`) and essentially no wall-clock time has
        // elapsed since `captured_at` either -- neither of
        // `is_safe_to_reuse`'s two proofs can hold yet, so even though the
        // fingerprint is unchanged, this must still recompute rather than
        // risk a same-tick collision.
        let second = expect_ok(
            get_or_compute(&key, &real_fingerprint, || {
                compute_calls += 1;
                Ok((
                    real_fingerprint.clone(),
                    "content-racy-2".to_string(),
                    real_latest_modified,
                ))
            }),
            "second (immediate repeat) call",
        );
        assert_eq!(
            second, "content-racy-2",
            "a not-yet-settled attestation must not be trusted"
        );
        assert_eq!(
            compute_calls, 2,
            "an immediate repeat on a freshly-modified component must still force a recompute"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn already_stable_component_gets_an_immediate_cache_hit() {
        let root = temp_dir("stable-hit");
        let file = root.join("a.txt");
        write_file(&file, b"hello");
        // Back-date the file's own mtime well past `RACY_SETTLE_MARGIN` so
        // it looks like a component that has been installed and untouched
        // for a long time -- the realistic, common case this cache exists
        // to speed up. Must be opened with write access: on Windows,
        // `set_modified` requires `FILE_WRITE_ATTRIBUTES`, which a
        // read-only `File::open` handle does not carry, so the backdate
        // silently failed there (this test's own assertion is the only one
        // in this module that actually depends on the backdate landing).
        let old_mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        if let Ok(handle) = fs::OpenOptions::new().write(true).open(&file) {
            let _ = handle.set_modified(old_mtime);
        }
        let (real_fingerprint, real_latest_modified) = metadata_fingerprint_of_tree(&root, &[])
            .unwrap_or_else(|error| {
                unreachable!("fixture tree fingerprint computation failed: {error:?}")
            });
        let key = CacheKey {
            managed_root_identity: "root-stable".to_string(),
            component_id: "comp-stable".to_string(),
            canonical_component_root: root.clone(),
            installation_manifest_digest: "digest-stable".to_string(),
        };

        // Explicit `true`: same capability-selection reason as
        // `cache_hit_only_when_fingerprint_matches_and_miss_otherwise`.
        let mut compute_calls = 0;
        let first = expect_ok(
            get_or_compute_with_capability(&key, &real_fingerprint, true, || {
                compute_calls += 1;
                Ok((
                    real_fingerprint.clone(),
                    "content-stable-1".to_string(),
                    real_latest_modified,
                ))
            }),
            "first call",
        );
        assert_eq!(first, "content-stable-1");

        let second = expect_ok(
            get_or_compute_with_capability(&key, &real_fingerprint, true, || {
                compute_calls += 1;
                Ok((
                    real_fingerprint.clone(),
                    "SHOULD_NOT_BE_USED".to_string(),
                    real_latest_modified,
                ))
            }),
            "second call",
        );
        assert_eq!(second, "content-stable-1");
        assert_eq!(
            compute_calls, 1,
            "an already-settled, unchanged component must hit immediately, with no age penalty"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// Windows's real production behavior, proven on any development
    /// platform: a platform without a trustworthy change-detection signal
    /// (`fast_cache_supported = false`) must perform full verification on
    /// *every* call, even with an identical fingerprint presented twice in
    /// a row -- never trusting a cached digest at all. This is the
    /// discriminating test for the 1.0.0 Windows security policy: it would
    /// fail if `get_or_compute_with_capability` ever consulted or
    /// populated the cache table while `fast_cache_supported` is `false`.
    #[test]
    fn platform_without_trustworthy_change_detection_never_uses_the_cache() {
        let key = CacheKey {
            managed_root_identity: "root-no-fast-cache".to_string(),
            component_id: "comp-no-fast-cache".to_string(),
            canonical_component_root: PathBuf::from("/tmp/does-not-matter-no-fast-cache"),
            installation_manifest_digest: "digest-no-fast-cache".to_string(),
        };
        let mut compute_calls = 0;

        let first = expect_ok(
            get_or_compute_with_capability(&key, "fp-constant", false, || {
                compute_calls += 1;
                Ok((
                    "fp-constant".to_string(),
                    "digest-1".to_string(),
                    long_settled_time(),
                ))
            }),
            "first call, unsupported platform",
        );
        assert_eq!(first, "digest-1");
        assert_eq!(compute_calls, 1);

        let second = expect_ok(
            get_or_compute_with_capability(&key, "fp-constant", false, || {
                compute_calls += 1;
                Ok((
                    "fp-constant".to_string(),
                    "digest-2".to_string(),
                    long_settled_time(),
                ))
            }),
            "second call, unsupported platform, identical fingerprint",
        );
        assert_eq!(
            second, "digest-2",
            "a platform without trustworthy change detection must never reuse a cached \
             digest, even when the fingerprint is unchanged"
        );
        assert_eq!(
            compute_calls, 2,
            "every resolution must perform full verification on a platform without \
             trustworthy change detection"
        );
    }

    /// Sanity check for the dispatch in [`get_or_compute_with_capability`]
    /// itself: the `fast_cache_supported = true` branch (Linux/macOS's real
    /// production behavior) still behaves like the ordinary steady-state
    /// hit path already proven by
    /// [`cache_hit_only_when_fingerprint_matches_and_miss_otherwise`],
    /// called here through the same capability-parameterized entry point
    /// the `false` branch above uses, so both branches are proven side by
    /// side against the identical harness.
    #[test]
    fn platform_with_trustworthy_change_detection_still_uses_the_cache() {
        let key = CacheKey {
            managed_root_identity: "root-fast-cache-supported".to_string(),
            component_id: "comp-fast-cache-supported".to_string(),
            canonical_component_root: PathBuf::from("/tmp/does-not-matter-fast-cache-supported"),
            installation_manifest_digest: "digest-fast-cache-supported".to_string(),
        };
        let mut compute_calls = 0;

        let first = expect_ok(
            get_or_compute_with_capability(&key, "fp-constant", true, || {
                compute_calls += 1;
                Ok((
                    "fp-constant".to_string(),
                    "digest-1".to_string(),
                    long_settled_time(),
                ))
            }),
            "first call, supported platform",
        );
        assert_eq!(first, "digest-1");

        let second = expect_ok(
            get_or_compute_with_capability(&key, "fp-constant", true, || {
                compute_calls += 1;
                Ok((
                    "fp-constant".to_string(),
                    "SHOULD_NOT_BE_USED".to_string(),
                    long_settled_time(),
                ))
            }),
            "second call, supported platform, identical fingerprint",
        );
        assert_eq!(second, "digest-1");
        assert_eq!(
            compute_calls, 1,
            "a platform with trustworthy change detection must still cache on an \
             unchanged fingerprint"
        );
    }
}
