// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Transactional, fail-closed uninstall for `CORULIX_MANAGED` components
//! (Phase 7B-B1).
//!
//! # Canonical stage order
//!
//! ```text
//! LOAD OWNERSHIP MANIFEST
//!   -> VALIDATE MANIFEST INTEGRITY (ownership::load's digest check)
//!   -> VALIDATE MANAGED-ROOT IDENTITY (ownership::load's identity check)
//!   -> RESOLVE DEPENDENCY GRAPH (reject if another installed component still needs this one)
//!   -> BUILD REMOVAL PLAN (this component's owned_paths)
//!   -> CANONICALIZE EVERY TARGET (reject anything that resolves outside the managed root)
//!   -> VERIFY CorulixOwned (reject HostOnlyOverride/SystemExternal/WorkspaceExternal)
//!   -> VERIFY INSIDE MANAGED ROOT (covered by canonicalize step)
//!   -> VERIFY NOT SYSTEM/HOST-OVERRIDE/WORKSPACE (covered by ownership check)
//!   -> STOP MANAGED PROCESSES (caller-supplied hook, see [`uninstall`])
//!   -> STAGE UNINSTALL TRANSACTION (atomic rename into a quarantine dir)
//!   -> REMOVE IN DEPENDENCY-SAFE ORDER (quarantine deleted last)
//!   -> VERIFY REMOVAL
//!   -> REMOVE OWNED CACHES/STAGING
//!   -> VERIFY NO OWNED COMPONENT REMAINS
//!   -> REMOVE OWNERSHIP METADATA LAST
//!   -> UNINSTALL_COMPLETED
//! ```
//!
//! # Transaction model: quarantine-by-rename
//!
//! The component's owned root is moved with one [`std::fs::rename`] into
//! `<managed_toolchain_root>/.uninstall-txn/<txid>/<component_id>` --
//! *inside* the managed root, deliberately never under
//! [`std::env::temp_dir`], because `fs::rename` is only atomic within one
//! filesystem and a managed root's own tree is guaranteed to share a
//! filesystem with itself. Only after that single atomic move succeeds does
//! this module perform the actual destructive [`std::fs::remove_dir_all`],
//! and only against the quarantine copy. An uninstall interrupted after
//! quarantine but before final deletion leaves the quarantined tree
//! recoverable by an operator (rename it back), rather than a half-deleted
//! live install; an uninstall interrupted before quarantine has mutated
//! nothing at all. `UNINSTALL_TRANSACTION_MODEL=QUARANTINE_BY_RENAME`.
//!
//! # Path confinement
//!
//! Every path this module deletes is canonicalized first via
//! `wht_corulix_workspace::confine::canonicalize_external_path` (Rule F's
//! own primitive -- this module does not hand-roll a second canonicalizer)
//! and rejected unless the canonical result is a descendant of the
//! canonicalized managed root. No shell `rm`/`rmdir` string construction
//! exists anywhere in this module; every deletion is a typed
//! [`std::fs::remove_dir_all`]/[`std::fs::remove_file`] call against an
//! already-verified [`PathBuf`].

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::ManagedComponentId;
use super::lease;
use super::ownership::{self, ManagedInstallationRecord, OwnershipClass, OwnershipError};

/// Bound for the ACTIVE EXECUTION DISCOVERY + MANAGED PROCESS SHUTDOWN
/// stage (Phase 7B-B1-R3 §5-6): how long `uninstall()` waits for every
/// [`lease::ManagedExecutionLease`] naming this component to confirm
/// stopped before refusing to quarantine it. Generous relative to a normal
/// LSP graceful-shutdown window (a few seconds) because a managed
/// rust-analyzer session may still be running a `cargo check` flycheck.
pub(crate) const ACTIVE_EXECUTION_STOP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UninstallError {
    /// The ownership manifest failed its own integrity/root-identity check.
    /// Always blocks -- never treated as "not installed".
    CorruptManifest,
    /// This component is not `OwnershipClass::CorulixManaged`. Uninstall
    /// refuses to touch it under any circumstances.
    NotCorulixManaged,
    /// At least one other installed `CorulixManaged` component still
    /// declares a dependency on this one.
    StillDependedUpon(Vec<String>),
    /// An owned path did not canonicalize to a location inside the managed
    /// root -- refused rather than deleted.
    PathEscapesManagedRoot,
    /// The quarantine (stage) rename failed; nothing was deleted.
    QuarantineFailed,
    /// The final destructive removal of the quarantined copy failed after
    /// staging succeeded. The quarantined tree is left in place for manual
    /// recovery/inspection -- `UNINSTALL_STATUS=BLOCKED`,
    /// `MANUAL_RECOVERY_EVIDENCE_REQUIRED=YES`.
    RemovalFailedAfterQuarantine(PathBuf),
    /// The post-removal verification still finds a live artifact.
    VerificationFailed,
    /// No ownership record exists for this component, but a component
    /// directory under `root/components/<component_id>/` does. This is a
    /// recovery-required state (e.g. `provision()`'s post-activation
    /// `ownership::save` failed), never treated as `AlreadyRemoved` --
    /// reporting success here would leave an unaccounted, undeletable
    /// artifact on disk (`PARTIAL_UNINSTALL_SUCCESS_FALSE_POSITIVE_COUNT`
    /// would no longer be `0`).
    OrphanedComponentWithoutOwnership(PathBuf),
    /// At least one [`lease::ManagedExecutionLease`] names this component
    /// (as primary or dependency) and did not confirm stopped within
    /// `ACTIVE_EXECUTION_STOP_TIMEOUT`. Nothing was quarantined or
    /// deleted -- `LIVE_RENAME_COUNT=0`, `LIVE_DELETE_COUNT=0`.
    ActiveExecutionBusy,
    /// A lease naming this component reported `Stopped`, but this module's
    /// own independent OS-level re-verification (never the lease's
    /// self-report alone -- `FALSE_STOPPED_LEASE_DELETE_COUNT=0`) could not
    /// produce a definitive live/dead verdict for its recorded process
    /// (e.g. no platform absence-check primitive, or a permission error).
    /// Fails closed rather than guessing --
    /// `UNKNOWN_PROCESS_STATE_DELETE_COUNT=0`.
    ProcessStateUncertain,
    /// A prior [`super::full_uninstall::full_uninstall`] transaction's
    /// rollback failed and left the managed root recovery-locked
    /// (`FURTHER_MANAGED_MUTATION_DENIED=YES`); refused eagerly rather
    /// than racing an operator's manual recovery.
    RecoveryLocked,
    Io,
}

impl From<OwnershipError> for UninstallError {
    fn from(error: OwnershipError) -> Self {
        match error {
            OwnershipError::CorruptManifest | OwnershipError::RootIdentityMismatch => {
                UninstallError::CorruptManifest
            }
            OwnershipError::Io | OwnershipError::Serialization => UninstallError::Io,
        }
    }
}

/// Outcome of one [`uninstall`] call. Both are success outcomes -- a second
/// call against an already-removed component is not an error
/// (`UNINSTALL_IDEMPOTENT=YES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallOutcome {
    Removed,
    AlreadyRemoved,
}

/// Canonicalizes `candidate` via `wht_corulix_workspace`'s own external-path
/// primitive (Architecture Rule F: sole owner of the raw canonicalize call; this
/// module deliberately does not hand-roll a second canonicalizer) and
/// rejects the result unless it is a descendant of `managed_root_canonical`.
pub(crate) async fn canonicalize_confined(
    managed_root_canonical: &Path,
    candidate: &Path,
) -> Result<PathBuf, UninstallError> {
    let (canonical, _is_file) =
        wht_corulix_workspace::canonicalize_external_path(candidate.to_path_buf())
            .await
            .map_err(|_| UninstallError::PathEscapesManagedRoot)?;
    if !canonical.starts_with(managed_root_canonical) {
        return Err(UninstallError::PathEscapesManagedRoot);
    }
    Ok(canonical)
}

/// Verifies no other `CorulixManaged` record under `root` (other than
/// `component_id` itself) still lists `component_id` as a dependency.
/// Corrupt sibling records are treated as a dependency block, not skipped
/// -- an unreadable record could be hiding a real dependency, so this
/// fails closed rather than proceeding on incomplete information.
fn verify_not_depended_upon(root: &Path, component_id: &str) -> Result<(), UninstallError> {
    let mut dependents = Vec::new();
    for entry in ownership::list(root) {
        let record = entry.map_err(|_| UninstallError::CorruptManifest)?;
        if record.component_id == component_id {
            continue;
        }
        if record.ownership == OwnershipClass::CorulixManaged
            && record.dependencies.iter().any(|dep| dep == component_id)
        {
            dependents.push(record.component_id);
        }
    }
    if dependents.is_empty() {
        Ok(())
    } else {
        Err(UninstallError::StillDependedUpon(dependents))
    }
}

fn quarantine_dir(root: &Path) -> Result<PathBuf, UninstallError> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let dir = root
        .join(".uninstall-txn")
        .join(format!("txn-{pid}-{stamp}"));
    fs::create_dir_all(&dir).map_err(|_| UninstallError::QuarantineFailed)?;
    Ok(dir)
}

/// Runs the full transactional uninstall of `component_id` under `root`.
///
/// `before_remove` is invoked once, with the component's canonical install
/// root, immediately before quarantine -- this is the STOP MANAGED
/// PROCESSES stage. This module owns no ambient registry of live
/// `ManagedProcess` instances (those are owned by whichever crate spawned
/// them, e.g. `wht_corulix_lsp::LspSession`), so that responsibility is a
/// required parameter rather than a silently-skipped stage: a caller that
/// knows of no live process for this component passes a no-op closure
/// explicitly, which is a documented decision, not an omission.
pub async fn uninstall<F: FnOnce(&Path)>(
    root: &Path,
    component_id: ManagedComponentId,
    before_remove: F,
) -> Result<UninstallOutcome, UninstallError> {
    uninstall_with_stop_timeout(
        root,
        component_id,
        ACTIVE_EXECUTION_STOP_TIMEOUT,
        before_remove,
    )
    .await
}

/// Same as [`uninstall`], with an explicit stop-wait bound instead of
/// [`ACTIVE_EXECUTION_STOP_TIMEOUT`]. Exposed at `pub(crate)` visibility
/// purely so this module's own tests can exercise the
/// [`UninstallError::ActiveExecutionBusy`] path without a real 30-second
/// wait; production callers always go through [`uninstall`].
pub(crate) async fn uninstall_with_stop_timeout<F: FnOnce(&Path)>(
    root: &Path,
    component_id: ManagedComponentId,
    stop_timeout: Duration,
    before_remove: F,
) -> Result<UninstallOutcome, UninstallError> {
    if super::full_uninstall::recovery_locked(root) {
        return Err(UninstallError::RecoveryLocked);
    }
    // Shared (read) hold on the root-scoped lock: excludes a concurrent
    // `full_uninstall::full_uninstall` (which holds it exclusively) for the
    // duration of this call -- `FULL_VS_COMPONENT_UNINSTALL_RACE_COUNT=0`.
    let _root_guard = super::lock_root_shared(&ownership::root_identity(root)).await;
    // Single-flight: the same per-component lock `provision`/
    // `provision_with_dependencies` acquire, so an uninstall can never
    // race a concurrent provision (or a second concurrent uninstall) of
    // the exact same component -- `PROVISION_UNINSTALL_RACE_COUNT=0`.
    let _guard = super::lock_component(component_id.0).await;

    // LOAD OWNERSHIP MANIFEST + VALIDATE MANIFEST INTEGRITY + VALIDATE
    // MANAGED-ROOT IDENTITY (all inside ownership::load).
    let record = match ownership::load(root, component_id)? {
        Some(record) => record,
        None => {
            // No record does not automatically mean "nothing to remove" --
            // an orphaned component directory (e.g. from a provision()
            // call whose post-activation ownership::save failed) must
            // block rather than be silently reported as already clean.
            // A merely-*present-but-empty* leftover directory (e.g. a
            // version-scoped parent a prior successful uninstall could not
            // remove because a sibling version still exists) is not an
            // orphan -- only non-empty content is treated as one.
            let orphan_root = root.join("components").join(component_id.0);
            let has_content = fs::read_dir(&orphan_root)
                .map(|mut entries| entries.next().is_some())
                .unwrap_or(false);
            if has_content {
                return Err(UninstallError::OrphanedComponentWithoutOwnership(
                    orphan_root,
                ));
            }
            return Ok(UninstallOutcome::AlreadyRemoved);
        }
    };

    // VERIFY CorulixOwned / NOT SYSTEM/HOST-OVERRIDE/WORKSPACE.
    if record.ownership != OwnershipClass::CorulixManaged {
        return Err(UninstallError::NotCorulixManaged);
    }

    // RESOLVE DEPENDENCY GRAPH.
    verify_not_depended_upon(root, &record.component_id)?;

    // BUILD REMOVAL PLAN + CANONICALIZE EVERY TARGET + VERIFY INSIDE
    // MANAGED ROOT.
    let (managed_root_canonical, _) =
        wht_corulix_workspace::canonicalize_external_path(root.to_path_buf())
            .await
            .map_err(|_| UninstallError::PathEscapesManagedRoot)?;
    let component_root_canonical =
        canonicalize_confined(&managed_root_canonical, &record.canonical_component_root).await?;
    for owned in &record.owned_paths {
        let candidate = record.canonical_component_root.join(owned);
        let canonical_owned = if candidate.is_dir() || candidate.is_file() {
            canonicalize_confined(&managed_root_canonical, &candidate).await?
        } else {
            // Already absent -- nothing to canonicalize/delete for this
            // entry, but its declared location must still resolve under
            // the component root textually so a malformed record cannot
            // point elsewhere.
            let joined = record.canonical_component_root.join(owned);
            if !joined.starts_with(&record.canonical_component_root) {
                return Err(UninstallError::PathEscapesManagedRoot);
            }
            continue;
        };
        if !canonical_owned.starts_with(&component_root_canonical)
            && canonical_owned != component_root_canonical
        {
            return Err(UninstallError::PathEscapesManagedRoot);
        }
    }

    // ACTIVE EXECUTION DISCOVERY + MANAGED PROCESS SHUTDOWN. Every live
    // `ManagedExecutionLease` naming this component (as primary or
    // dependency) is signalled and awaited before anything is renamed --
    // filesystem presence is never treated as process-state authority
    // (Phase 7B-B1-R3 §2, §5-6). A component nobody ever leased (e.g. it
    // was provisioned but never used this process lifetime) reports
    // `NoActiveLease` immediately and uninstall proceeds unchanged from the
    // pre-R3 behavior.
    // The `StopOutcome` itself is only ever used to *signal* -- it is
    // deliberately never the deciding authority. A lease belonging to a
    // crashed session has nobody left to observe the signal and will
    // always time out, but that must not block uninstall forever
    // (`STALE_LEASE_RECONCILIATION=PASS`, Phase 7B-B1-R3-A §15); the
    // independent process-identity check immediately below is what
    // actually decides, in every `StopOutcome` case alike.
    // Root-scoped (P17-W-R3-C5, `TS6_LEASE_STOP_ROOT_SCOPING_DEFECT`): this
    // `root` is the one `uninstall()` was invoked against, so only a lease
    // that itself declared belonging to this exact root can ever be
    // signalled here -- a same-named component in a different managed root
    // (a completely independent Corulix installation on the same host,
    // `CORULIX_SINGLE_MACHINE_ASSUMPTION=NO`) must never be woken by this
    // call.
    let owning_root = lease::RootIdentity::of(root);
    let _ = lease::request_stop_for_component(
        lease::ComponentLeaseScope {
            root: &owning_root,
            component_id: record.component_id.as_str(),
        },
        stop_timeout,
    )
    .await;

    // Lease state (`Stopped`, or a timed-out stop signal) is a cooperative
    // claim, not process-state authority (Phase 7B-B1-R3-A §14):
    // independently re-verify every recorded process identity is actually
    // gone before proceeding. A still-live process refuses the uninstall;
    // an inconclusive check fails closed rather than guessing either way
    // (`UNKNOWN_PROCESS_STATE_DELETE_COUNT=0`).
    for identity in lease::process_identities_for_component(lease::ComponentLeaseScope {
        root: &owning_root,
        component_id: record.component_id.as_str(),
    }) {
        match lease::verify_process_absent(identity) {
            lease::ProcessAbsence::Absent => {}
            lease::ProcessAbsence::Present => return Err(UninstallError::ActiveExecutionBusy),
            lease::ProcessAbsence::Uncertain => {
                return Err(UninstallError::ProcessStateUncertain);
            }
        }
    }

    // STOP MANAGED PROCESSES (caller-supplied hook, for a caller that has
    // its own stop mechanism distinct from `ManagedExecutionLease`).
    before_remove(&component_root_canonical);

    // STAGE UNINSTALL TRANSACTION (quarantine-by-rename, same filesystem).
    let quarantine_root = quarantine_dir(root)?;
    let quarantine_target = quarantine_root.join(component_id.0);
    if component_root_canonical.exists() {
        fs::rename(&component_root_canonical, &quarantine_target)
            .map_err(|_| UninstallError::QuarantineFailed)?;
    }

    // REMOVE IN DEPENDENCY-SAFE ORDER (single component: just the
    // quarantined copy) + VERIFY REMOVAL.
    if quarantine_target.exists() {
        fs::remove_dir_all(&quarantine_target)
            .map_err(|_| UninstallError::RemovalFailedAfterQuarantine(quarantine_target.clone()))?;
    }
    let _ = fs::remove_dir(&quarantine_root); // best-effort: only removes if now empty

    // VERIFY NO OWNED COMPONENT REMAINS.
    if component_root_canonical.exists() {
        return Err(UninstallError::VerificationFailed);
    }

    // Best-effort: remove now-empty version-scoped parent directories
    // (e.g. `components/<id>/<version>/` once its `<platform>-<arch>` leaf
    // is gone) so a fully-removed component leaves no leftover directory
    // tree behind. Never fails the uninstall if a sibling version's
    // directory is still present (`remove_dir` only succeeds when empty).
    let mut ancestor = component_root_canonical.parent();
    while let Some(dir) = ancestor {
        if dir == managed_root_canonical || fs::remove_dir(dir).is_err() {
            break;
        }
        ancestor = dir.parent();
    }

    // REMOVE OWNERSHIP METADATA LAST.
    ownership::remove(root, component_id)?;
    // M06 payload-verification-cache: this component's record no longer
    // exists, so nothing could ever look up its old attestation again
    // anyway (the cache key is built from a *loaded* record, and there is
    // none) -- this explicit invalidation exists so the entry is dropped
    // immediately (never lingers for the rest of this process's lifetime)
    // rather than relying on that structural argument alone.
    super::payload_verification_cache::invalidate_component(
        &ownership::root_identity(root),
        component_id.0,
    );

    Ok(UninstallOutcome::Removed)
}

/// Every field a fresh, successful `provision()` call already knows,
/// grouped so [`build_record`] takes one parameter instead of nine.
pub struct NewInstallation<'a> {
    pub component_id: &'a str,
    pub version: &'a str,
    pub platform: &'a str,
    pub architecture: &'a str,
    pub canonical_component_root: PathBuf,
    pub dependencies: Vec<String>,
    pub installation_sequence: u64,
    pub artifact_digest: String,
    pub ownership: OwnershipClass,
    /// SHA-256 hex over the installed, extracted payload (Managed
    /// Installed-Payload Integrity pass) -- empty when the archive kind is
    /// `RawBinary` (already covered by `artifact_digest` re-verification) or
    /// when the caller has no trusted extraction to hash from. Never
    /// computed by [`build_record`] itself -- callers must compute it from
    /// their own staging directory *before* calling this, since this
    /// function has no filesystem access of its own.
    pub installed_payload_digest: String,
    pub installed_payload_kind: ownership::InstalledPayloadKind,
    /// SHA-256 hex digests for each declared `super::OptionalSegment` of
    /// this component (segment-aware model, P11-R1 conflict resolution) --
    /// empty for every component with no declared optional segments. See
    /// [`ownership::ManagedInstallationRecord::optional_segment_digests`]'s
    /// own doc comment.
    pub optional_segment_digests: std::collections::BTreeMap<String, String>,
}

/// Convenience: constructs the [`ManagedInstallationRecord`] a successful
/// `provision()` call should persist, given the artifact digest it already
/// verified. Kept here (not in `ownership`) because only `uninstall`'s
/// module boundary needs `installation_sequence` bookkeeping today.
#[must_use]
pub fn build_record(root: &Path, installation: NewInstallation<'_>) -> ManagedInstallationRecord {
    ManagedInstallationRecord {
        component_id: installation.component_id.to_string(),
        version: installation.version.to_string(),
        platform: installation.platform.to_string(),
        architecture: installation.architecture.to_string(),
        managed_root_identity: ownership::root_identity(root),
        canonical_component_root: installation.canonical_component_root,
        owned_paths: vec![PathBuf::from(".")],
        dependencies: installation.dependencies,
        installation_sequence: installation.installation_sequence,
        artifact_digest: installation.artifact_digest,
        activation_state: ownership::ActivationState::Available,
        ownership: installation.ownership,
        installation_manifest_digest: String::new(),
        installed_payload_digest: installation.installed_payload_digest,
        installed_payload_kind: installation.installed_payload_kind,
        optional_segment_digests: installation.optional_segment_digests,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning::ownership::save;

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("corulix-uninstall-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn ok_or_panic<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("test fixture setup must succeed: {error:?}"))
    }

    /// `lease::set_probe_override` is one process-wide test-only seam: any
    /// test that sets it would otherwise leak it into a sibling test
    /// running concurrently in the same binary (`cargo test`'s default
    /// concurrent execution), the same cross-test-interference class
    /// already found and fixed twice elsewhere in this arc
    /// (`ManagedExecutionLease`'s registry, `full_uninstall`'s
    /// `INJECTED_FAULT`). Every test in this module that reaches
    /// `verify_process_absent` (directly or via `uninstall`/
    /// `uninstall_with_stop_timeout`) acquires this same lock first -- see
    /// `uninstall_test_lock`.
    ///
    /// P17-W-R3-C3 (`CANONICAL_DEFAULT_PARALLEL_TEST_GATE_FLAKINESS` root
    /// cause): this used to be a lock local to this module alone, which
    /// left `provisioning::lease`'s own direct `verify_process_absent`
    /// callers -- compiled into the same test binary as this crate's only
    /// other tests, and run concurrently with these by `cargo test`'s
    /// default parallelism -- completely unserialized against this
    /// module's override-setting tests. `uninstall_test_lock` now simply
    /// delegates to [`lease::probe_override_test_lock`], the one crate-wide
    /// lock every reader and writer of the shared override must hold.
    async fn uninstall_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
        lease::probe_override_test_lock().await
    }

    struct ProbeOverrideGuard<'a>(#[allow(dead_code)] tokio::sync::MutexGuard<'a, ()>);
    impl Drop for ProbeOverrideGuard<'_> {
        fn drop(&mut self) {
            lease::set_probe_override(None);
        }
    }

    async fn set_probe_override_scoped(
        result: lease::ProcessAbsence,
    ) -> ProbeOverrideGuard<'static> {
        let guard = uninstall_test_lock().await;
        lease::set_probe_override(Some(result));
        ProbeOverrideGuard(guard)
    }

    fn install_fixture(root: &Path, id: &'static str, deps: Vec<String>) -> PathBuf {
        let component_root = root.join("components").join(id).join("1.0.0");
        ok_or_panic(fs::create_dir_all(&component_root));
        ok_or_panic(fs::write(component_root.join("bin"), b"fixture binary"));
        let mut record = build_record(
            root,
            NewInstallation {
                component_id: id,
                version: "1.0.0",
                platform: "linux",
                architecture: "x64",
                canonical_component_root: component_root.clone(),
                dependencies: deps,
                installation_sequence: 1,
                artifact_digest: "0".repeat(64),
                ownership: OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        ok_or_panic(save(root, &mut record));
        component_root
    }

    #[tokio::test]
    async fn uninstall_of_absent_component_is_idempotent_success() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("absent");
        let outcome = uninstall(&root, ManagedComponentId("nope"), |_| {}).await;
        assert_eq!(outcome, Ok(UninstallOutcome::AlreadyRemoved));
        let outcome_again = uninstall(&root, ManagedComponentId("nope"), |_| {}).await;
        assert_eq!(outcome_again, Ok(UninstallOutcome::AlreadyRemoved));
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_refuses_to_report_success_over_an_orphaned_component() {
        let _lock = uninstall_test_lock().await;
        // Simulates the exact defect this test guards against: a component
        // directory exists on disk (e.g. because `provision()`'s
        // post-activation `ownership::save` failed after the atomic
        // rename) but no ownership record does. Reporting `AlreadyRemoved`
        // here would be a false-positive success leaving an unaccounted,
        // undeletable artifact on disk.
        let root = temp_root("orphan");
        let orphan_root = root.join("components").join("orphan-fixture").join("1.0.0");
        ok_or_panic(fs::create_dir_all(&orphan_root));
        ok_or_panic(fs::write(orphan_root.join("bin"), b"orphaned binary"));
        let outcome = uninstall(&root, ManagedComponentId("orphan-fixture"), |_| {}).await;
        assert_eq!(
            outcome,
            Err(UninstallError::OrphanedComponentWithoutOwnership(
                root.join("components").join("orphan-fixture")
            ))
        );
        assert!(orphan_root.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_removes_component_and_ownership_record() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("basic");
        let component_root = install_fixture(&root, "fixture-a", Vec::new());
        let outcome = uninstall(&root, ManagedComponentId("fixture-a"), |_| {}).await;
        assert_eq!(outcome, Ok(UninstallOutcome::Removed));
        assert!(!component_root.exists());
        assert_eq!(
            ownership::load(&root, ManagedComponentId("fixture-a")),
            Ok(None)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn second_uninstall_call_is_idempotent_after_first_succeeds() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("double");
        install_fixture(&root, "fixture-b", Vec::new());
        let first = uninstall(&root, ManagedComponentId("fixture-b"), |_| {}).await;
        assert_eq!(first, Ok(UninstallOutcome::Removed));
        let second = uninstall(&root, ManagedComponentId("fixture-b"), |_| {}).await;
        assert_eq!(second, Ok(UninstallOutcome::AlreadyRemoved));
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_refuses_a_non_corulix_managed_record() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("host-only");
        let component_root = root.join("components").join("fixture-c").join("1.0.0");
        ok_or_panic(fs::create_dir_all(&component_root));
        let mut record = build_record(
            &root,
            NewInstallation {
                component_id: "fixture-c",
                version: "1.0.0",
                platform: "linux",
                architecture: "x64",
                canonical_component_root: component_root.clone(),
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest: "0".repeat(64),
                ownership: OwnershipClass::HostOnlyOverride,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        ok_or_panic(save(&root, &mut record));
        let outcome = uninstall(&root, ManagedComponentId("fixture-c"), |_| {}).await;
        assert_eq!(outcome, Err(UninstallError::NotCorulixManaged));
        assert!(component_root.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_refuses_when_another_component_still_depends_on_it() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("dependency-blocked");
        install_fixture(&root, "node-fixture", Vec::new());
        install_fixture(&root, "pyright-fixture", vec!["node-fixture".to_string()]);
        let outcome = uninstall(&root, ManagedComponentId("node-fixture"), |_| {}).await;
        assert_eq!(
            outcome,
            Err(UninstallError::StillDependedUpon(vec![
                "pyright-fixture".to_string()
            ]))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_succeeds_once_the_dependent_is_removed_first() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("dependency-ordered");
        install_fixture(&root, "node-fixture2", Vec::new());
        install_fixture(&root, "pyright-fixture2", vec!["node-fixture2".to_string()]);
        let dependent = uninstall(&root, ManagedComponentId("pyright-fixture2"), |_| {}).await;
        assert_eq!(dependent, Ok(UninstallOutcome::Removed));
        let dependency = uninstall(&root, ManagedComponentId("node-fixture2"), |_| {}).await;
        assert_eq!(dependency, Ok(UninstallOutcome::Removed));
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_refuses_a_record_pointing_outside_the_managed_root() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("escape");
        let outside = temp_root("escape-outside-target");
        let mut record = build_record(
            &root,
            NewInstallation {
                component_id: "fixture-escape",
                version: "1.0.0",
                platform: "linux",
                architecture: "x64",
                canonical_component_root: outside.clone(),
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest: "0".repeat(64),
                ownership: OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        ok_or_panic(save(&root, &mut record));
        let outcome = uninstall(&root, ManagedComponentId("fixture-escape"), |_| {}).await;
        assert_eq!(outcome, Err(UninstallError::PathEscapesManagedRoot));
        assert!(outside.exists());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[tokio::test]
    async fn uninstall_refuses_a_symlink_substituted_component_root() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("symlink-substitution");
        let real_component_root = root.join("components").join("fixture-h").join("1.0.0");
        ok_or_panic(fs::create_dir_all(&real_component_root));
        let outside_target = temp_root("symlink-substitution-target");
        ok_or_panic(fs::write(outside_target.join("sentinel"), b"external file"));

        let mut record = build_record(
            &root,
            NewInstallation {
                component_id: "fixture-h",
                version: "1.0.0",
                platform: "linux",
                architecture: "x64",
                canonical_component_root: real_component_root.clone(),
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest: "0".repeat(64),
                ownership: OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        ok_or_panic(save(&root, &mut record));

        // Replace the real component root with a symlink pointing outside
        // the managed root, simulating a post-install tamper.
        ok_or_panic(fs::remove_dir_all(&real_component_root));
        #[cfg(unix)]
        ok_or_panic(std::os::unix::fs::symlink(
            &outside_target,
            &real_component_root,
        ));

        #[cfg(unix)]
        {
            let outcome = uninstall(&root, ManagedComponentId("fixture-h"), |_| {}).await;
            assert_eq!(outcome, Err(UninstallError::PathEscapesManagedRoot));
            assert!(outside_target.join("sentinel").exists());
        }
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&real_component_root);
        let _ = fs::remove_dir_all(&outside_target);
    }

    #[tokio::test]
    async fn uninstall_refuses_a_component_with_an_active_unstoppable_lease() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("active-lease-busy");
        let component_root = install_fixture(&root, "fixture-lease-busy", Vec::new());
        // A real, still-running process -- the independent
        // `verify_process_absent` re-check (not the lease's own claim)
        // is what must refuse this uninstall (`FALSE_STOPPED_LEASE_DELETE_COUNT=0`
        // is proven by a *different* test; this one proves the plain busy
        // path: never even acknowledged, and genuinely still alive).
        // P17-W-R3-C2 (`WINDOWS_PROCESS_FIXTURE_PORTABILITY`): the target is
        // the cross-platform `wht_corulix_process_fixture` binary in
        // `sleep-ms` mode, never the previous hardcoded `/bin/sleep`.
        let fixture = crate::fixture_support::fixture_binary_path().unwrap_or_else(|error| {
            unreachable!("resolving the process fixture must succeed: {error}")
        });
        let mut command = tokio::process::Command::new(fixture);
        command.args(["sleep-ms", "30000"]);
        crate::platform::prepare(&mut command);
        let mut child = command.spawn().unwrap_or_else(|error| {
            unreachable!("spawning the process fixture must succeed: {error:?}")
        });
        let pid = child
            .id()
            .unwrap_or_else(|| unreachable!("just-spawned child must have a pid"));

        // Registered but never listens for the stop request -- simulates a
        // hung/unresponsive managed session.
        let lease = super::lease::ManagedExecutionLease::register(
            super::lease::ManagedLeaseBinding::for_components(
                super::lease::RootIdentity::of(&root),
                "fixture-lease-busy",
                Vec::new(),
            ),
            super::lease::ProcessIdentity { pid },
        );
        let outcome = uninstall_with_stop_timeout(
            &root,
            ManagedComponentId("fixture-lease-busy"),
            Duration::from_millis(50),
            |_| {},
        )
        .await;
        assert_eq!(outcome, Err(UninstallError::ActiveExecutionBusy));
        assert!(
            component_root.exists(),
            "must not quarantine a busy component"
        );
        lease.release();
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_reconciles_a_stale_lease_whose_process_already_exited() {
        let _lock = uninstall_test_lock().await;
        // Simulates a crashed session: a lease still claims Starting (never
        // acknowledged, nobody left to observe the stop signal) but its
        // recorded process is already gone. Must not block uninstall
        // forever (`STALE_LEASE_RECONCILIATION=PASS`).
        let root = temp_root("active-lease-stale");
        let component_root = install_fixture(&root, "fixture-lease-stale", Vec::new());
        let lease = super::lease::ManagedExecutionLease::register(
            super::lease::ManagedLeaseBinding::for_components(
                super::lease::RootIdentity::of(&root),
                "fixture-lease-stale",
                Vec::new(),
            ),
            super::lease::ProcessIdentity { pid: 999_999 },
        );
        let outcome = uninstall_with_stop_timeout(
            &root,
            ManagedComponentId("fixture-lease-stale"),
            Duration::from_millis(50),
            |_| {},
        )
        .await;
        assert_eq!(outcome, Ok(UninstallOutcome::Removed));
        assert!(!component_root.exists());
        lease.release();
    }

    #[tokio::test]
    async fn uninstall_refuses_a_lease_that_falsely_claims_stopped_while_its_real_process_still_lives()
     {
        let _lock = uninstall_test_lock().await;
        // `FALSE_STOPPED_LEASE_DELETE_COUNT=0`: unlike
        // `uninstall_refuses_a_component_with_an_active_unstoppable_lease`
        // (never even acknowledges) and
        // `uninstall_reconciles_a_stale_lease_whose_process_already_exited`
        // (acknowledges honestly, process already gone), this test's lease
        // *dishonestly* self-reports `Stopped` via `acknowledge_stopped()`
        // while its recorded process is a real, still-running child. Only
        // the independent OS-level `verify_process_absent` re-check --
        // never the lease's own claim -- may decide; this proves uninstall
        // still refuses even though the cooperative signal says stopped.
        let root = temp_root("active-lease-false-stopped");
        let component_root = install_fixture(&root, "fixture-lease-false-stopped", Vec::new());
        // P17-W-R3-C2 (`WINDOWS_PROCESS_FIXTURE_PORTABILITY`): the target is
        // the cross-platform `wht_corulix_process_fixture` binary in
        // `sleep-ms` mode, never the previous hardcoded `/bin/sleep`.
        let fixture = crate::fixture_support::fixture_binary_path().unwrap_or_else(|error| {
            unreachable!("resolving the process fixture must succeed: {error}")
        });
        let mut command = tokio::process::Command::new(fixture);
        command.args(["sleep-ms", "30000"]);
        crate::platform::prepare(&mut command);
        let mut child = command.spawn().unwrap_or_else(|error| {
            unreachable!("spawning the process fixture must succeed: {error:?}")
        });
        let pid = child
            .id()
            .unwrap_or_else(|| unreachable!("just-spawned child must have a pid"));

        let lease = super::lease::ManagedExecutionLease::register(
            super::lease::ManagedLeaseBinding::for_components(
                super::lease::RootIdentity::of(&root),
                "fixture-lease-false-stopped",
                Vec::new(),
            ),
            super::lease::ProcessIdentity { pid },
        );
        // Falsely acknowledges stopped while the real process (`pid`) is
        // still alive -- the exact disagreement this test targets.
        lease.acknowledge_stopped();

        let outcome = uninstall_with_stop_timeout(
            &root,
            ManagedComponentId("fixture-lease-false-stopped"),
            Duration::from_millis(50),
            |_| {},
        )
        .await;
        assert_eq!(outcome, Err(UninstallError::ActiveExecutionBusy));
        assert!(
            component_root.exists(),
            "must not quarantine a component whose lease falsely claims stopped \
             while its real process is still alive"
        );

        lease.release();
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_reconciles_a_lease_after_a_real_external_process_crash() {
        let _lock = uninstall_test_lock().await;
        // `MANAGED_PROVIDER_CRASH_RECONCILIATION=PASS` at the Tooling
        // process-lifecycle layer: a real child is spawned and its lease is
        // marked `Active` (a genuinely running managed session, not merely
        // `Starting`), then the process is killed directly from outside any
        // Corulix shutdown path (`child.kill()` -- the same shape a crash or
        // an operator's `kill -9` would produce), never through
        // `lease.acknowledge_stopped()`/`lease.release()`. The lease is left
        // exactly as a crashed session would leave it: still registered,
        // still claiming its process, nobody left to ever observe a stop
        // signal. Proves the OS process is independently confirmed gone and
        // uninstall reconciles and succeeds rather than deadlocking forever
        // on a lease nobody will ever cooperate with again. (Scoped to this
        // crate's process-lifecycle primitives; a live LSP session
        // restarting successfully afterward is a `wht_corulix_lsp`-level
        // concern this test does not exercise.)
        let root = temp_root("active-lease-real-crash");
        let component_root = install_fixture(&root, "fixture-lease-real-crash", Vec::new());
        // P17-W-R3-C2 (`WINDOWS_PROCESS_FIXTURE_PORTABILITY`): the target is
        // the cross-platform `wht_corulix_process_fixture` binary in
        // `sleep-ms` mode, never the previous hardcoded `/bin/sleep`.
        let fixture = crate::fixture_support::fixture_binary_path().unwrap_or_else(|error| {
            unreachable!("resolving the process fixture must succeed: {error}")
        });
        let mut command = tokio::process::Command::new(fixture);
        command.args(["sleep-ms", "30000"]);
        crate::platform::prepare(&mut command);
        let mut child = command.spawn().unwrap_or_else(|error| {
            unreachable!("spawning the process fixture must succeed: {error:?}")
        });
        let pid = child
            .id()
            .unwrap_or_else(|| unreachable!("just-spawned child must have a pid"));

        let lease = super::lease::ManagedExecutionLease::register(
            super::lease::ManagedLeaseBinding::for_components(
                super::lease::RootIdentity::of(&root),
                "fixture-lease-real-crash",
                Vec::new(),
            ),
            super::lease::ProcessIdentity { pid },
        );
        lease.mark_active();

        // The real, external, abnormal exit -- not a Corulix shutdown path.
        let _ = child.kill().await;
        let _ = child.wait().await;

        let outcome = uninstall_with_stop_timeout(
            &root,
            ManagedComponentId("fixture-lease-real-crash"),
            Duration::from_millis(50),
            |_| {},
        )
        .await;
        assert_eq!(outcome, Ok(UninstallOutcome::Removed));
        assert!(!component_root.exists());

        lease.release();
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_fails_closed_when_the_process_probe_reports_uncertain() {
        // §16-18: the real `EPERM` branch `platform::test_alive` can return
        // (a process owned by a different real OS user) cannot be
        // deterministically forced in this unprivileged, single-user
        // sandbox. `lease::set_probe_override` is a `#[cfg(test)]`-only
        // seam inside `verify_process_absent` for exactly this -- never a
        // production-reachable knob, never user/workspace-configurable.
        let _override_guard = set_probe_override_scoped(lease::ProcessAbsence::Uncertain).await;

        let root = temp_root("unknown-process-state");
        let component_root = install_fixture(&root, "fixture-unknown-state", Vec::new());
        let lease = lease::ManagedExecutionLease::register(
            super::lease::ManagedLeaseBinding::for_components(
                super::lease::RootIdentity::of(&root),
                "fixture-unknown-state",
                Vec::new(),
            ),
            lease::ProcessIdentity { pid: 999_999 },
        );
        lease.mark_active();

        let outcome = uninstall_with_stop_timeout(
            &root,
            ManagedComponentId("fixture-unknown-state"),
            Duration::from_millis(50),
            |_| {},
        )
        .await;
        assert_eq!(outcome, Err(UninstallError::ProcessStateUncertain));
        assert!(
            component_root.exists(),
            "UNKNOWN_PROCESS_STATE_RENAME_COUNT must be 0 -- an uncertain probe result \
             must never be treated as a live/dead verdict"
        );
        assert!(
            ownership::load(&root, ManagedComponentId("fixture-unknown-state"))
                .ok()
                .flatten()
                .is_some(),
            "ownership must be retained, never removed, on a fail-closed refusal"
        );

        lease.release();
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn uninstall_proceeds_once_the_lease_acknowledges_stopped() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("active-lease-cooperative");
        let component_root = install_fixture(&root, "fixture-lease-ok", Vec::new());
        let lease = super::lease::ManagedExecutionLease::register(
            super::lease::ManagedLeaseBinding::for_components(
                super::lease::RootIdentity::of(&root),
                "fixture-lease-ok",
                Vec::new(),
            ),
            super::lease::ProcessIdentity { pid: 999_999 },
        );

        let uninstall_task = tokio::spawn(async move {
            uninstall(&root, ManagedComponentId("fixture-lease-ok"), |_| {}).await
        });

        lease.wait_for_stop_request().await;
        lease.acknowledge_stopped();
        lease.release();

        let outcome = uninstall_task
            .await
            .unwrap_or_else(|error| unreachable!("uninstall task must not panic: {error:?}"));
        assert_eq!(outcome, Ok(UninstallOutcome::Removed));
        assert!(!component_root.exists());
    }

    #[tokio::test]
    async fn uninstall_never_deletes_paths_outside_managed_root_even_on_success() {
        let _lock = uninstall_test_lock().await;
        let root = temp_root("sentinel-safety");
        let sentinel_dir = temp_root("sentinel-safety-external");
        let sentinel_file = sentinel_dir.join("do-not-touch.txt");
        ok_or_panic(fs::write(&sentinel_file, b"external sentinel"));
        let before_hash =
            wht_corulix_core::ContentHash::compute_sha256(&ok_or_panic(fs::read(&sentinel_file)));

        install_fixture(&root, "fixture-i", Vec::new());
        let outcome = uninstall(&root, ManagedComponentId("fixture-i"), |_| {}).await;
        assert_eq!(outcome, Ok(UninstallOutcome::Removed));

        let after_hash =
            wht_corulix_core::ContentHash::compute_sha256(&ok_or_panic(fs::read(&sentinel_file)));
        assert_eq!(before_hash.digest_hex, after_hash.digest_hex);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sentinel_dir);
    }

    /// THE CALLER-LEVEL COUNTERPART OF `lease::tests::cross_root_same_component_isolation`
    /// (P17-W-R3-C5, §16 `CONCURRENT_MANAGED_ROOT_ISOLATION`): the lease
    /// primitive being root-scoped is necessary but not sufficient -- this
    /// proves the actual production caller, `uninstall()`, passes the right
    /// root. Two independent managed roots (`ROOT_A`, `ROOT_B`) each install
    /// the *same-named* component and each hold a real, live, leased
    /// process. `ROOT_A`'s lease cooperates (a background task races the
    /// stop signal, acknowledges, and kills its real child); `ROOT_B`'s
    /// never does -- nobody is listening for its stop request at all, and
    /// its process is left running for the whole test.
    ///
    /// `uninstall_with_stop_timeout(&root_a, ..)` must succeed, and `ROOT_B`
    /// must be completely untouched: its real process still alive
    /// (`verify_process_absent(pid_b) == Present`, the same independent
    /// OS-level check `uninstall` itself uses) and its ownership record and
    /// component directory both still present.
    ///
    /// This is a genuine discriminator against the pre-fix code, not merely
    /// against a hypothetical: before this pass's root-scoping fix,
    /// `process_identities_for_component("concurrent-root-isolation")`
    /// returned *both* pids process-wide, so `ROOT_A`'s own uninstall would
    /// have iterated over `ROOT_B`'s still-`Present` process and refused
    /// with `ActiveExecutionBusy` -- a completely unrelated root blocking
    /// this root's uninstall, the same defect in its other direction (never
    /// blocking is the failure mode `lease::tests::cross_root_same_component_isolation`
    /// covers; wrongly blocking is the failure mode this test covers).
    #[tokio::test]
    async fn concurrent_managed_root_isolation_uninstall_never_touches_an_unrelated_root() {
        let _lock = uninstall_test_lock().await;
        const SHARED_COMPONENT_ID: &str = "concurrent-root-isolation";

        let root_a = temp_root("concurrent-root-a");
        let root_b = temp_root("concurrent-root-b");
        let component_root_a = install_fixture(&root_a, SHARED_COMPONENT_ID, Vec::new());
        let component_root_b = install_fixture(&root_b, SHARED_COMPONENT_ID, Vec::new());

        let fixture = crate::fixture_support::fixture_binary_path().unwrap_or_else(|error| {
            unreachable!("resolving the process fixture must succeed: {error}")
        });

        // ROOT_A: a real, cooperative session.
        let mut command_a = tokio::process::Command::new(&fixture);
        command_a.args(["sleep-ms", "30000"]);
        crate::platform::prepare(&mut command_a);
        let mut child_a = command_a.spawn().unwrap_or_else(|error| {
            unreachable!("spawning ROOT_A's fixture process must succeed: {error:?}")
        });
        let pid_a = child_a
            .id()
            .unwrap_or_else(|| unreachable!("just-spawned ROOT_A child must have a pid"));
        let lease_a = super::lease::ManagedExecutionLease::register(
            super::lease::ManagedLeaseBinding::for_components(
                super::lease::RootIdentity::of(&root_a),
                SHARED_COMPONENT_ID,
                Vec::new(),
            ),
            super::lease::ProcessIdentity { pid: pid_a },
        );
        let waiter_a = lease_a.waiter();
        let cooperative_task = tokio::spawn(async move {
            waiter_a.wait_for_stop_request().await;
            // Real shutdown order, matching production
            // (`wht_corulix_lsp::LspSession`): actually terminate the
            // process first, then acknowledge -- `uninstall`'s independent
            // `verify_process_absent` re-check must find it genuinely gone,
            // never trust the acknowledgment alone.
            let _ = child_a.kill().await;
            let _ = child_a.wait().await;
            waiter_a.acknowledge_stopped();
        });

        // ROOT_B: a real, live, deliberately non-cooperative session --
        // nobody ever observes its stop request, and its process is never
        // killed by this test until the final cleanup.
        let mut command_b = tokio::process::Command::new(&fixture);
        command_b.args(["sleep-ms", "30000"]);
        crate::platform::prepare(&mut command_b);
        let mut child_b = command_b.spawn().unwrap_or_else(|error| {
            unreachable!("spawning ROOT_B's fixture process must succeed: {error:?}")
        });
        let pid_b = child_b
            .id()
            .unwrap_or_else(|| unreachable!("just-spawned ROOT_B child must have a pid"));
        let lease_b = super::lease::ManagedExecutionLease::register(
            super::lease::ManagedLeaseBinding::for_components(
                super::lease::RootIdentity::of(&root_b),
                SHARED_COMPONENT_ID,
                Vec::new(),
            ),
            super::lease::ProcessIdentity { pid: pid_b },
        );

        let outcome = uninstall_with_stop_timeout(
            &root_a,
            ManagedComponentId(SHARED_COMPONENT_ID),
            Duration::from_secs(5),
            |_| {},
        )
        .await;
        assert_eq!(
            outcome,
            Ok(UninstallOutcome::Removed),
            "ROOT_A's own uninstall must succeed once its own cooperative lease stops -- \
             it must never be blocked by ROOT_B's unrelated, still-live, same-named lease"
        );
        cooperative_task
            .await
            .unwrap_or_else(|error| unreachable!("cooperative task must not panic: {error:?}"));
        assert!(!component_root_a.exists());

        // ROOT_B must be completely untouched: real process still alive,
        // ownership record and component directory both still present.
        assert_eq!(
            super::lease::verify_process_absent(super::lease::ProcessIdentity { pid: pid_b }),
            super::lease::ProcessAbsence::Present,
            "ROOT_B's real process must still be alive -- ROOT_A's uninstall must never have \
             signalled, let alone reaped, a process belonging to a different managed root"
        );
        assert!(
            component_root_b.exists(),
            "ROOT_B's component directory must be untouched by ROOT_A's uninstall"
        );
        assert!(
            ownership::load(&root_b, ManagedComponentId(SHARED_COMPONENT_ID))
                .ok()
                .flatten()
                .is_some(),
            "ROOT_B's ownership record must be untouched by ROOT_A's uninstall"
        );

        lease_b.release();
        let _ = child_b.kill().await;
        let _ = child_b.wait().await;
        let _ = fs::remove_dir_all(&root_a);
        let _ = fs::remove_dir_all(&root_b);
    }
}
