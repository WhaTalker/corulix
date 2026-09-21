// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Ownership records for `CORULIX_MANAGED` components (Phase 7B-B1).
//!
//! A [`ManagedInstallationRecord`] is the *only* authority `provisioning`
//! consults before it ever deletes anything. It answers two questions a
//! destructive removal must never guess at: "did Corulix itself install
//! this" ([`OwnershipClass::CorulixManaged`], the sole class eligible for
//! automatic removal) and "what exactly, on disk, did that installation
//! create" (`owned_paths`, always relative and always re-validated to
//! canonicalize inside `canonical_component_root` before deletion -- see
//! `provisioning::uninstall`).
//!
//! # Fail-closed integrity
//!
//! Every persisted record carries `installation_manifest_digest`, a SHA-256
//! over the record's own canonical JSON (computed with that field held
//! empty). [`load`] recomputes the digest on every read and refuses
//! ([`OwnershipError::CorruptManifest`]) rather than guess if it does not
//! match -- a corrupted or hand-edited manifest must block, never be
//! silently trusted or silently repaired.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use wht_corulix_core::ContentHash;

use super::{ManagedComponentId, ProvisioningError};

/// Who owns a filesystem resource Corulix observed or used. Only
/// [`OwnershipClass::CorulixManaged`] is ever eligible for automatic
/// removal -- every other class exists so provisioning/uninstall code can
/// *recognize* system/user/workspace resources it must never delete, not so
/// it can act on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OwnershipClass {
    /// Installed by Corulix, under `managed_toolchain_root()`, and fully
    /// described by this record. The only class [`uninstall`](super::uninstall)
    /// may ever remove.
    CorulixManaged,
    /// A host operator explicitly pinned an absolute path outside the
    /// managed root (`HOST_ONLY` provider override). Corulix may use it,
    /// never delete it.
    HostOnlyOverride,
    /// A system-installed toolchain Corulix detected or used as a fallback
    /// (system Node, rustup, nvm, ...). Never deleted.
    SystemExternal,
    /// A workspace-local resource (`node_modules`, `.venv`, `vendor`, a
    /// project-local `bin`). Never deleted.
    WorkspaceExternal,
}

/// Lifecycle state of one managed component's installation, independent of
/// [`super::ManagedComponentState`] (which is a pure filesystem presence
/// check) -- this is the ownership-manifest's own authoritative state,
/// updated only by `provisioning`/`uninstall` as each stage completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ActivationState {
    Available,
    UninstallPreparing,
    Uninstalling,
}

/// The shape of a persisted [`ManagedInstallationRecord::installed_payload_digest`]
/// (Managed Installed-Payload Integrity pass): whether it was computed over
/// one extracted file or over an entire merged multi-file component tree.
/// Selects which digest function a resolution-time re-verification must use
/// -- never a behavior switch beyond that. Meaningless while
/// `installed_payload_digest` is empty (a pre-existing legacy record; see
/// that field's own doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum InstalledPayloadKind {
    #[default]
    SingleFile,
    Tree,
}

impl InstalledPayloadKind {
    /// Used only as this field's `serde(skip_serializing_if = ...)`
    /// predicate -- see [`ManagedInstallationRecord::installed_payload_kind`]'s
    /// own doc comment for why omitting the default value on serialization
    /// is load-bearing for self-digest stability across a legacy record,
    /// not merely a smaller JSON file.
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// The full, persisted ownership record for one installed `CORULIX_MANAGED`
/// component. One record file per component id under
/// `<managed_toolchain_root>/ownership/<component_id>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedInstallationRecord {
    pub component_id: String,
    pub version: String,
    pub platform: String,
    pub architecture: String,
    /// SHA-256 hex of the canonicalized `managed_toolchain_root()` path this
    /// record was written under. [`load`] refuses a record whose identity
    /// does not match the root it was loaded from -- protects against a
    /// record silently reused after being copied to a different root.
    pub managed_root_identity: String,
    /// Canonical, absolute install directory for this component
    /// (`component_install_dir`). Every entry in `owned_paths` must
    /// canonicalize to a path inside this directory.
    pub canonical_component_root: PathBuf,
    /// Paths (relative to `canonical_component_root`) this installation is
    /// known to own. For the simple single-artifact components provisioned
    /// so far this is just the component root itself (`"."`), but the field
    /// exists so a future multi-artifact component does not need a format
    /// change.
    pub owned_paths: Vec<PathBuf>,
    /// Component ids this installation depends on (e.g. Pyright depends on
    /// managed Node). Consulted by `uninstall`'s dependency-graph resolution
    /// so a shared dependency is never removed while another installed
    /// component still needs it.
    pub dependencies: Vec<String>,
    /// Monotonic install ordering, assigned by the provisioning caller.
    /// Used only as removal-order tie-breaking evidence, never as security
    /// authority.
    pub installation_sequence: u64,
    /// SHA-256 hex of the original downloaded artifact bytes (matches
    /// `ManagedArtifactSource::expected_sha256_hex` at install time).
    pub artifact_digest: String,
    pub activation_state: ActivationState,
    pub ownership: OwnershipClass,
    /// SHA-256 hex over this record's own canonical JSON, computed with
    /// this field held as `""`. Populated by [`save`], verified by [`load`].
    #[serde(default)]
    pub installation_manifest_digest: String,
    /// SHA-256 hex over the *installed, extracted* payload actually
    /// resolved/launched (Managed Installed-Payload Integrity pass) --
    /// distinct from `artifact_digest` (the original downloaded source
    /// artifact's own hash: a different granularity for every archive-derived
    /// kind except `RawBinary`; see
    /// `super::ManagedInvalidReason::ArtifactIntegrityMismatch`'s doc
    /// comment). Computed from the trusted staging extraction and persisted
    /// *before* `activation_state` becomes `Available`
    /// (`AVAILABLE_BEFORE_INSTALLED_DIGEST_PERSISTED=NO`).
    ///
    /// Empty on every record persisted before this field existed (the
    /// `#[serde(default)]` legacy-evolution mechanism this crate already
    /// established for `installation_manifest_digest`). An empty value must
    /// be treated as an explicit, disclosed "not yet verifiable this way"
    /// state -- never as a match, and never silently upgraded by hashing
    /// whatever bytes are currently on disk and blessing them as trusted
    /// (no Trust-On-First-Use: `LEGACY_TRUST_ON_FIRST_USE=NO`). Safe
    /// migration requires a genuinely trusted source (a re-verified source
    /// artifact still available, or a fresh managed reacquisition), which
    /// this pass's resolution-time check deliberately does not attempt on
    /// its own -- see `super::resolve_owned_managed_component_detailed`'s own
    /// doc comment for the disclosed `ARCHIVE_DERIVED_RUNTIME_INTEGRITY_STATUS
    /// = PARTIAL` gap this leaves open.
    ///
    /// `skip_serializing_if` (not merely `#[serde(default)]`) is load-bearing
    /// here, not cosmetic: `digest_of` hashes this whole struct's canonical
    /// JSON, so a plain `#[serde(default)]` field that *always* serializes
    /// (even at its default) would still change the byte sequence
    /// `digest_of` hashes for every record persisted before this field
    /// existed -- and every real managed component already installed on any
    /// host predates it. That is a real regression this pass found and fixed
    /// by re-verifying against this crate's own real-installation fixtures
    /// (`ARCHIVE_INTEGRITY_SCHEMA_MIGRATION_SELF_DIGEST_REGRESSION_COUNT` was
    /// briefly `1`, not `0`, before this field gained
    /// `skip_serializing_if`): omitting an empty digest reproduces the exact
    /// pre-this-field JSON byte-for-byte, so a legacy record's
    /// `installation_manifest_digest` (computed before this field existed)
    /// still verifies correctly, while a record with a genuinely recorded
    /// digest serializes it and folds it into the self-digest as normal.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub installed_payload_digest: String,
    /// How `installed_payload_digest` was computed. Meaningless while
    /// `installed_payload_digest` is empty. `skip_serializing_if` for the
    /// same self-digest-stability reason as `installed_payload_digest`'s own
    /// doc comment explains.
    #[serde(default, skip_serializing_if = "InstalledPayloadKind::is_default")]
    pub installed_payload_kind: InstalledPayloadKind,
    /// SHA-256 hex digests for each declared
    /// `super::OptionalSegment` of this component's install (segment-aware
    /// model, P11-R1 conflict resolution), keyed by segment id -- e.g. the
    /// Rust semantic runtime's `"clippy"` segment. Recorded only for a
    /// segment whose declared paths were all present at acquisition time;
    /// absent from this map (not merely empty-stringed) for every other
    /// segment and for every legacy record. `BTreeMap` (not `HashMap`) for
    /// deterministic JSON key order, the same self-digest-stability reason
    /// `skip_serializing_if` matters for the other two fields above.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub optional_segment_digests: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnershipError {
    Io,
    CorruptManifest,
    RootIdentityMismatch,
    Serialization,
}

fn ownership_dir(root: &Path) -> PathBuf {
    root.join("ownership")
}

fn record_path(root: &Path, component_id: ManagedComponentId) -> PathBuf {
    ownership_dir(root).join(format!("{}.json", component_id.0))
}

/// Stable, order-independent identity for `root`, bound into every record
/// written under it so a record can never be silently reused against a
/// different managed-toolchain root.
#[must_use]
pub fn root_identity(root: &Path) -> String {
    ContentHash::compute_sha256(root.to_string_lossy().as_bytes()).digest_hex
}

fn digest_of(record: &ManagedInstallationRecord) -> Result<String, OwnershipError> {
    let mut for_digest = record.clone();
    for_digest.installation_manifest_digest = String::new();
    let bytes = serde_json::to_vec(&for_digest).map_err(|_| OwnershipError::Serialization)?;
    Ok(ContentHash::compute_sha256(&bytes).digest_hex)
}

/// Persists `record` under `root`, stamping its integrity digest first.
/// Writes to a sibling temp file and renames onto the final path so a
/// crash mid-write can never leave a half-written, undetectably-corrupt
/// manifest in place of a good one.
pub fn save(root: &Path, record: &mut ManagedInstallationRecord) -> Result<(), OwnershipError> {
    record.installation_manifest_digest = digest_of(record)?;
    let dir = ownership_dir(root);
    fs::create_dir_all(&dir).map_err(|_| OwnershipError::Io)?;
    let final_path = record_path(
        root,
        ManagedComponentId(leak_component_id(&record.component_id)),
    );
    let tmp_path = dir.join(format!("{}.json.tmp", record.component_id));
    let bytes = serde_json::to_vec_pretty(record).map_err(|_| OwnershipError::Serialization)?;
    fs::write(&tmp_path, &bytes).map_err(|_| OwnershipError::Io)?;
    fs::rename(&tmp_path, &final_path).map_err(|_| OwnershipError::Io)?;
    Ok(())
}

/// Leaks `id` into a `'static str` for the duration of the process. Record
/// component ids are a small, bounded, Corulix-defined vocabulary (never
/// derived from untrusted workspace input), so this is a fixed, negligible
/// amount of intentional leakage, not an unbounded one -- avoids widening
/// `ManagedComponentId` to an owned `String` across the whole module for a
/// single internal path-building call.
fn leak_component_id(id: &str) -> &'static str {
    Box::leak(id.to_string().into_boxed_str())
}

/// Loads and verifies the ownership record for `component_id` under `root`.
/// Fails closed (`CorruptManifest`) on any digest mismatch or malformed
/// content rather than guessing at the record's intent, and fails closed
/// (`RootIdentityMismatch`) if the record's bound root identity does not
/// match `root` itself. Returns `Ok(None)` only when no record file exists
/// at all (the ordinary "not installed" case).
pub fn load(
    root: &Path,
    component_id: ManagedComponentId,
) -> Result<Option<ManagedInstallationRecord>, OwnershipError> {
    let path = record_path(root, component_id);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|_| OwnershipError::CorruptManifest)?;
    let record: ManagedInstallationRecord =
        serde_json::from_slice(&bytes).map_err(|_| OwnershipError::CorruptManifest)?;
    let expected_digest = digest_of(&record)?;
    if !expected_digest.eq_ignore_ascii_case(&record.installation_manifest_digest) {
        return Err(OwnershipError::CorruptManifest);
    }
    if record.managed_root_identity != root_identity(root) {
        return Err(OwnershipError::RootIdentityMismatch);
    }
    Ok(Some(record))
}

/// Lists every persisted ownership record under `root`. A record that fails
/// to load (corrupt/foreign) is reported as an error entry rather than
/// silently skipped -- callers building a full dependency graph must see
/// every failure, since silently omitting a corrupt record could let
/// `uninstall` misjudge a still-depended-upon component as absent.
pub fn list(root: &Path) -> Vec<Result<ManagedInstallationRecord, OwnershipError>> {
    let dir = ownership_dir(root);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let component_id = leak_component_id(stem);
        results.push(
            load(root, ManagedComponentId(component_id))
                .and_then(|record| record.ok_or(OwnershipError::CorruptManifest)),
        );
    }
    results
}

/// Removes the on-disk ownership record for `component_id`. Callers must
/// invoke this only as the *last* step of a successful uninstall --
/// ownership metadata is the authority that a component is still owned, so
/// removing it before the underlying files are gone would leave those files
/// orphaned with no record proving Corulix may finish cleaning them up.
pub fn remove(root: &Path, component_id: ManagedComponentId) -> Result<(), OwnershipError> {
    let path = record_path(root, component_id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(OwnershipError::Io),
    }
}

impl From<OwnershipError> for ProvisioningError {
    fn from(_: OwnershipError) -> Self {
        ProvisioningError::OwnershipManifestInvalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("corulix-ownership-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn ok_or_panic<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("test fixture setup must succeed: {error:?}"))
    }

    fn some_or_panic<T>(value: Option<T>) -> T {
        value.unwrap_or_else(|| unreachable!("test fixture expected a present value"))
    }

    fn fixture_record(root: &Path, id: &str) -> ManagedInstallationRecord {
        ManagedInstallationRecord {
            component_id: id.to_string(),
            version: "1.0.0".to_string(),
            platform: "linux".to_string(),
            architecture: "x64".to_string(),
            managed_root_identity: root_identity(root),
            canonical_component_root: root.join("components").join(id).join("1.0.0"),
            owned_paths: vec![PathBuf::from(".")],
            dependencies: Vec::new(),
            installation_sequence: 1,
            artifact_digest: "0".repeat(64),
            activation_state: ActivationState::Available,
            ownership: OwnershipClass::CorulixManaged,
            installation_manifest_digest: String::new(),
            installed_payload_digest: String::new(),
            installed_payload_kind: InstalledPayloadKind::SingleFile,
            optional_segment_digests: BTreeMap::new(),
        }
    }

    #[test]
    fn round_trips_and_verifies_digest() {
        let root = temp_root("roundtrip");
        let mut record = fixture_record(&root, "fixture-a");
        ok_or_panic(save(&root, &mut record));
        let loaded = some_or_panic(ok_or_panic(load(&root, ManagedComponentId("fixture-a"))));
        assert_eq!(loaded, record);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn absent_record_loads_as_none() {
        let root = temp_root("absent");
        let result = load(&root, ManagedComponentId("does-not-exist"));
        assert_eq!(result, Ok(None));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn tampered_digest_is_rejected_as_corrupt() {
        let root = temp_root("tampered-digest");
        let mut record = fixture_record(&root, "fixture-b");
        ok_or_panic(save(&root, &mut record));
        let path = record_path(&root, ManagedComponentId("fixture-b"));
        let mut on_disk: ManagedInstallationRecord =
            ok_or_panic(serde_json::from_slice(&ok_or_panic(fs::read(&path))));
        on_disk.version = "9.9.9".to_string(); // mutate content, leave stale digest
        ok_or_panic(fs::write(
            &path,
            ok_or_panic(serde_json::to_vec_pretty(&on_disk)),
        ));
        let result = load(&root, ManagedComponentId("fixture-b"));
        assert_eq!(result, Err(OwnershipError::CorruptManifest));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn malformed_json_is_rejected_as_corrupt_not_a_panic() {
        let root = temp_root("malformed");
        let dir = ownership_dir(&root);
        ok_or_panic(fs::create_dir_all(&dir));
        ok_or_panic(fs::write(dir.join("fixture-c.json"), b"{ not json"));
        let result = load(&root, ManagedComponentId("fixture-c"));
        assert_eq!(result, Err(OwnershipError::CorruptManifest));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn record_copied_to_a_different_root_is_rejected() {
        let root_a = temp_root("root-a");
        let root_b = temp_root("root-b");
        let mut record = fixture_record(&root_a, "fixture-d");
        ok_or_panic(save(&root_a, &mut record));
        let path_a = record_path(&root_a, ManagedComponentId("fixture-d"));
        let dir_b = ownership_dir(&root_b);
        ok_or_panic(fs::create_dir_all(&dir_b));
        ok_or_panic(fs::copy(&path_a, dir_b.join("fixture-d.json")));
        let result = load(&root_b, ManagedComponentId("fixture-d"));
        assert_eq!(result, Err(OwnershipError::RootIdentityMismatch));
        let _ = fs::remove_dir_all(&root_a);
        let _ = fs::remove_dir_all(&root_b);
    }

    #[test]
    fn remove_is_idempotent() {
        let root = temp_root("remove-idempotent");
        let mut record = fixture_record(&root, "fixture-e");
        ok_or_panic(save(&root, &mut record));
        ok_or_panic(remove(&root, ManagedComponentId("fixture-e")));
        ok_or_panic(remove(&root, ManagedComponentId("fixture-e")));
        assert_eq!(load(&root, ManagedComponentId("fixture-e")), Ok(None));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_reports_corrupt_entries_rather_than_skipping_them() {
        let root = temp_root("list-corrupt");
        let mut good = fixture_record(&root, "fixture-f");
        ok_or_panic(save(&root, &mut good));
        let dir = ownership_dir(&root);
        ok_or_panic(fs::write(dir.join("fixture-g.json"), b"not json"));
        let results = list(&root);
        assert_eq!(results.len(), 2);
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        let err_count = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(ok_count, 1);
        assert_eq!(err_count, 1);
        let _ = fs::remove_dir_all(&root);
    }
}
