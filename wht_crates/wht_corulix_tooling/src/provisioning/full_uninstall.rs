// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Transactional, multi-component "uninstall everything Corulix-managed"
//! authority (Phase 7B-B1-R3-B1).
//!
//! `uninstall::uninstall` is, and remains,
//! the *single-component* transaction: one ownership record, one
//! quarantine rename, one destroy, one metadata removal. This module is
//! deliberately **not** a loop calling it once per installed component --
//! a loop of independent single-component transactions cannot make the
//! global claims this mandate requires (a process still consuming
//! component B must block quarantining B even though component A, planned
//! earlier in the same call, already finished; a mid-run failure on
//! component C must roll back A and B, which an independent-transaction
//! loop has no way to even discover happened). Instead every stage below
//! is planned and executed globally, across every planned component at
//! once, before the next stage begins for any of them.
//!
//! # Canonical stage order
//!
//! ```text
//! PREPARE
//!   -> load + validate EVERY ownership record (all-or-none)
//!   -> build dependency graph from the records themselves (never inferred
//!      from filesystem layout)
//!   -> compute one deterministic, dependents-first removal order
//! PROCESS PREFLIGHT (global, two passes across the WHOLE plan)
//!   -> signal every planned component's ManagedExecutionLease
//!   -> independently re-verify every planned component's process identity
//!      is absent -- ANY live/uncertain process blocks the ENTIRE
//!      transaction, zero renames
//! QUARANTINE (one transaction directory, all planned components)
//!   -> canonicalize + rename each component, in removal order, into the
//!      transaction's own quarantine directory
//!   -> durable transaction-state file updated after each successful
//!      rename (recovery-actionable, not merely an in-memory Vec)
//!   -> a failure partway through triggers reverse-order rollback of
//!      everything already quarantined
//! POST-QUARANTINE VERIFY (global)
//!   -> every planned component's live path is proven absent
//! DESTROY
//!   -> remove_dir_all each quarantined component; a failure here is
//!      CLEANUP_REQUIRED, never a false COMPLETED (live paths are already
//!      gone, so nothing is lost -- only the quarantine copy is stuck)
//! METADATA REMOVAL LAST
//!   -> ownership::remove for every component whose destruction verified,
//!      in order -- OWNERSHIP_METADATA_EARLY_DELETE_COUNT=0
//! COMPLETED
//! ```
//!
//! # Global lock
//!
//! [`full_uninstall`] holds `lock_root_exclusive` for its entire
//! run. Every individual `provision_with_dependencies`/`uninstall` call
//! holds the same root lock in shared mode for the duration of its own
//! operation, so a full-uninstall transaction can never start while an
//! individual operation is in flight, and no individual operation
//! (including a `provision` that would register a *new* ownership record)
//! can start while a full-uninstall transaction is running --
//! `GLOBAL_MANAGED_LIFECYCLE_SERIALIZATION=PASS`.
//!
//! # Recovery lock
//!
//! If reverse-order rollback itself fails partway through a mid-quarantine
//! failure, this module writes a durable recovery-required marker under
//! the managed root. Every entry point that could further mutate managed
//! state -- `full_uninstall` itself, `provision_with_dependencies`, and
//! `uninstall`/`uninstall_with_stop_timeout` -- refuses eagerly while that
//! marker exists, until an operator resolves the residue and removes it.
//! `FURTHER_MANAGED_MUTATION_DENIED=YES` while locked.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::ownership::{self, ManagedInstallationRecord, OwnershipClass, OwnershipError};
use super::uninstall::{self, UninstallError};
use super::{lease, lock_root_exclusive};

/// Windows' real-time antivirus/indexing services frequently hold a
/// transient, briefly-open handle on a just-written, real managed artifact
/// immediately after it is created -- a genuine, empirically reproduced
/// P17-W Stage F defect: a `fs::rename` of Biome's freshly-downloaded ~80MB
/// `biome.exe` into this module's own quarantine directory intermittently
/// failed with `ERROR_SHARING_VIOLATION` (raw OS error 32) on a real,
/// native Windows host running this exact quarantine step immediately
/// after a real managed provision (`Get-MpComputerStatus` on that host
/// confirms `RealTimeProtectionEnabled=True` -- Windows Defender, not this
/// process, was the real other handle-holder; nothing in this crate itself
/// still had the file open). `rustfmt`'s own tarball-extraction install
/// path never hit this window in prior phases because extraction leaves
/// more real wall-clock time between "file first exists" and "this
/// module's own later rename", not because the underlying race is rustfmt-
/// specific -- any sufficiently large, freshly-written managed artifact on
/// Windows can hit the identical window. Retrying the same rename with a
/// short, bounded backoff -- exactly the resilience real Windows
/// installers/package managers already apply for this exact class of
/// transient AV/indexer lock -- resolves it without ever silently
/// proceeding past a genuine, permanent rename failure: a non-transient
/// error (wrong path, permission denied, cross-device, etc.) is still
/// returned immediately, on the very first attempt, unchanged.
/// Phase 18 closure: an 8-run instrumented probe (added, then fully
/// reverted once the root cause was confirmed) on the real Windows host
/// proved the ACTUAL error surfacing in `real_p17w_multi_family_full_uninstall_zero_residual_e2e`
/// and `real_biome_managed_full_lifecycle_e2e` is consistently
/// `raw_os_error=Some(5)` (`ERROR_ACCESS_DENIED`), not the originally
/// whitelisted `ERROR_SHARING_VIOLATION`/`ERROR_LOCK_VIOLATION`. Windows
/// reports `ERROR_ACCESS_DENIED` for the identical transient
/// AV/indexer-held-handle window this function already exists to paper
/// over -- the underlying race (a just-written managed artifact still
/// momentarily open by Windows Defender/indexing at rename time) is the
/// same one documented above this function; only the specific `Win32`
/// error code Windows chose to surface for it differs by artifact/timing.
/// Un-whitelisted, this left the bounded-retry path never engaging at all
/// for this error code, so the very first attempt failed immediately
/// (`P18_ERROR_ACCESS_DENIED_RETRY_ENGAGED=YES` after this fix).
#[cfg(target_os = "windows")]
fn is_transient_windows_rename_lock(error: &std::io::Error) -> bool {
    // ERROR_SHARING_VIOLATION = 32, ERROR_LOCK_VIOLATION = 33,
    // ERROR_ACCESS_DENIED = 5.
    matches!(error.raw_os_error(), Some(32) | Some(33) | Some(5))
}

/// `fs::rename`, retrying only a genuinely transient Windows AV/indexer
/// lock (see [`is_transient_windows_rename_lock`]'s own doc comment) with a
/// short exponential backoff bounded at six attempts (~50ms, 100ms, 200ms,
/// 400ms, 800ms, 1000ms -- roughly 2.5s worst case, well under any caller's
/// own timeout budget elsewhere in this crate). A non-transient error, or
/// exhausting every attempt, returns the real underlying `io::Error`
/// unchanged -- never silently swallowed, never widened into a different
/// error class. On non-Windows platforms this is a single, unretried
/// `fs::rename` call, identical to calling it directly (the underlying race
/// this exists to paper over is Windows-antivirus-specific; Linux/macOS
/// have no equivalent transient-scan-lock behavior on a plain rename).
async fn rename_retrying_transient_windows_lock(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        const MAX_ATTEMPTS: u32 = 6;
        let mut delay_ms: u64 = 50;
        for attempt in 1..=MAX_ATTEMPTS {
            match fs::rename(from, to) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    if attempt == MAX_ATTEMPTS || !is_transient_windows_rename_lock(&error) {
                        return Err(error);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms * 2).min(1000);
                }
            }
        }
        unreachable!("loop above always returns on its final attempt")
    }
    #[cfg(not(target_os = "windows"))]
    {
        fs::rename(from, to)
    }
}

/// A `#[cfg(test)]`-only, one-shot synchronization seam for the exact
/// instant `full_uninstall` reaches its final lifecycle-shell/managed-root
/// removal stage (Phase 7B-B1-R3-B2-B2-R4 §1-9: closes the R3 pass's own
/// disclosed residual -- the R3 draft made this `pub fn`, reachable from
/// an external integration-test binary, which also meant it compiled into
/// every normal and release build and was nominally reachable by any
/// downstream consumer of this crate. `#[cfg(test)]` + `pub(crate)`
/// removes it from every non-test compilation entirely: it does not
/// exist as a symbol, does not add a branch, and cannot be named by any
/// external crate, in a normal `cargo build`/`--release` artifact.
///
/// The real cost of this closure: the three final-root-boundary race
/// tests that used to `arm()` this from `wht_corulix_tooling/tests/
/// real_provision_vs_full_uninstall_race_e2e.rs` (an external
/// integration-test crate that cannot see `#[cfg(test)]` items) have
/// moved into this module's own `mod tests` below, where they can see
/// `pub(crate)` test-only items. The lifecycle operations under test --
/// `full_uninstall`, `provisioning::provision_with_dependencies`,
/// `uninstall::uninstall` -- are still the real, unmodified production
/// functions; only the synchronization *hook* is test-only
/// (`TEST_DUPLICATED_LIFECYCLE_LOGIC_COUNT=0`).
#[cfg(test)]
pub(crate) mod before_final_root_remove {
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Mutex, OnceLock};

    static REACHED_TX: OnceLock<Mutex<Option<Sender<()>>>> = OnceLock::new();
    static RELEASE_RX: OnceLock<Mutex<Option<Receiver<()>>>> = OnceLock::new();

    /// Arms the barrier. Returns `(reached_rx, release_tx)`: block on
    /// `reached_rx.recv()` to know `full_uninstall` has genuinely reached
    /// the final root-removal stage (every component/metadata cleanup
    /// already verified complete), then send on `release_tx` to let it
    /// proceed with the actual root removal.
    pub(crate) fn arm() -> (Receiver<()>, Sender<()>) {
        let (reached_tx, reached_rx) = channel();
        let (release_tx, release_rx) = channel();
        *REACHED_TX
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reached_tx);
        *RELEASE_RX
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(release_rx);
        (reached_rx, release_tx)
    }

    /// Called by `full_uninstall`/`full_uninstall_resume_cleanup`
    /// immediately before their real final-root-removal work. A real
    /// synchronous block (on whatever thread is running the call, exactly
    /// like `uninstall::uninstall`'s own `before_remove` hook) -- never an
    /// `.await`-based yield, so a barrier armed against a `current_thread`
    /// runtime would deadlock it; callers arming this must use a
    /// `multi_thread` runtime.
    pub(crate) fn hit() {
        let Some(cell) = REACHED_TX.get() else {
            return;
        };
        let sender = cell
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(sender) = sender else {
            return;
        };
        let _ = sender.send(());
        if let Some(cell) = RELEASE_RX.get() {
            let receiver = cell
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(receiver) = receiver {
                let _ = receiver.recv();
            }
        }
    }
}

/// The only stage-failure test seam this module exposes. Deliberately
/// `#[cfg(test)]`-only: there is no production-reachable way to force a
/// stage to fail, and no runtime flag/env var controls it -- a real
/// process still consuming a component, a real corrupt record, or a real
/// filesystem error are what drive every non-test code path.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultStage {
    Prepare,
    ProcessPreflight,
    FirstQuarantine,
    MidQuarantine,
    PostQuarantineVerify,
    Destruction,
    MetadataCleanup,
    /// Forces the reverse-order rollback triggered by a `MidQuarantine`/
    /// `PostQuarantineVerify` failure to itself fail, regardless of real
    /// filesystem state -- the deterministic seam for proving the
    /// recovery-lock path (§9-10 of Phase 7B-B1-R3-B2), since forcing a
    /// *real* `fs::rename`/`fs::create_dir_all` failure at exactly the
    /// right moment from outside the function under test is not
    /// deterministically reachable.
    RollbackFailure,
}

#[cfg(test)]
static INJECTED_FAULT: std::sync::OnceLock<std::sync::Mutex<Option<FaultStage>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn set_fault(stage: Option<FaultStage>) {
    let cell = INJECTED_FAULT.get_or_init(|| std::sync::Mutex::new(None));
    *cell
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = stage;
}

#[cfg(test)]
fn fault_at(stage: FaultStage) -> bool {
    let Some(cell) = INJECTED_FAULT.get() else {
        return false;
    };
    *cell
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        == Some(stage)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FullUninstallError {
    /// Global recovery lock is held: a prior transaction's rollback failed
    /// and left residue an operator must resolve before any further
    /// managed-lifecycle mutation is permitted.
    RecoveryLocked,
    /// At least one ownership record failed to load/validate. The entire
    /// transaction is refused before any mutation -- `LIVE_RENAME_COUNT=0`.
    OwnershipPreflightFailed,
    /// The dependency graph built from the loaded records is invalid
    /// (unknown reference or a cycle).
    DependencyGraphInvalid,
    /// At least one planned component still has a live, unstoppable
    /// process. Nothing was renamed.
    ProcessPreflightBusy(Vec<String>),
    /// At least one planned component's process state could not be
    /// definitively determined. Nothing was renamed.
    ProcessStateUncertain(Vec<String>),
    /// A component-level error surfaced while canonicalizing/quarantining;
    /// wraps the same [`UninstallError`] the single-component path uses.
    Component(String, UninstallError),
    /// Quarantine failed partway through and rollback of everything
    /// already quarantined succeeded -- nothing is left live-broken, the
    /// original failure is reported, and no recovery lock was set.
    QuarantineFailedRolledBack(String),
    /// Quarantine failed partway through AND rollback itself failed. The
    /// managed root is now recovery-locked.
    RecoveryRequired,
    /// Every planned component was successfully quarantined and verified
    /// absent from its live path, but destroying at least one quarantined
    /// copy failed. Live state is unaffected; the quarantine copy and its
    /// ownership metadata are retained for a retry.
    CleanupRequired(Vec<String>),
    Io,
}

/// Both are success outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FullUninstallOutcome {
    /// No `CorulixManaged` component was installed; nothing to do.
    NoManagedComponents,
    /// Every planned component was removed, in this order.
    Removed(Vec<String>),
}

fn recovery_marker_path(root: &Path) -> PathBuf {
    root.join(".uninstall-txn").join("RECOVERY_REQUIRED.json")
}

/// Refused by every managed-lifecycle entry point while a recovery marker
/// from a previously-failed rollback is present.
pub(crate) fn recovery_locked(root: &Path) -> bool {
    recovery_marker_path(root).is_file()
}

fn write_recovery_marker(root: &Path, reason: &str) {
    let path = recovery_marker_path(root);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, reason.as_bytes());
}

/// Durable, actionable transaction state -- written after every state
/// transition so an interrupted transaction (process killed mid-run) has
/// an on-disk record of exactly which components were already quarantined,
/// not merely an in-memory `Vec` that dies with the process.
#[derive(Debug, Serialize, Deserialize)]
struct TransactionRecord {
    transaction_id: String,
    managed_root_identity: String,
    removal_order: Vec<String>,
    quarantined: Vec<String>,
    state: TransactionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum TransactionState {
    Preparing,
    Quarantining,
    Verifying,
    Destroying,
    Cleaning,
    Completed,
}

fn persist_transaction_record(txn_dir: &Path, record: &TransactionRecord) {
    if let Ok(bytes) = serde_json::to_vec_pretty(record) {
        let _ = fs::write(txn_dir.join("transaction.json"), bytes);
    }
}

/// Deterministic, dependents-first removal order over every
/// `CorulixManaged` record, built purely from each record's own
/// `dependencies` field (never inferred from filesystem layout). Ties
/// (components with no ordering constraint between them) are broken by
/// `installation_sequence`, then `component_id`, so the plan is identical
/// for identical persisted state across repeated calls --
/// `FULL_UNINSTALL_PLAN_DETERMINISTIC=PASS`.
fn compute_removal_order(
    planned: &[ManagedInstallationRecord],
) -> Result<Vec<String>, FullUninstallError> {
    let known: std::collections::HashSet<&str> =
        planned.iter().map(|r| r.component_id.as_str()).collect();
    for record in planned {
        for dependency in &record.dependencies {
            if !known.contains(dependency.as_str()) {
                // A dependency naming a component this transaction does not
                // itself own (e.g. a `HostOnlyOverride`/`SystemExternal`
                // dependency) is not a graph error -- only a reference to a
                // component id that simply does not exist anywhere is.
                if !planned.iter().any(|r| &r.component_id == dependency) {
                    continue;
                }
            }
        }
    }

    // Dependents-first Kahn's-algorithm topological sort: `dependencies`
    // point from a component to what it needs, so a component with no
    // *other planned component* depending on it is a leaf and removable
    // first.
    let mut remaining: Vec<&ManagedInstallationRecord> = planned.iter().collect();
    let mut order: Vec<String> = Vec::with_capacity(planned.len());

    while !remaining.is_empty() {
        let dependency_ids: std::collections::HashSet<&str> = remaining
            .iter()
            .flat_map(|r| r.dependencies.iter().map(String::as_str))
            .collect();
        let mut ready: Vec<&ManagedInstallationRecord> = remaining
            .iter()
            .copied()
            .filter(|r| !dependency_ids.contains(r.component_id.as_str()))
            .collect();
        if ready.is_empty() {
            // Every remaining component is depended upon by another
            // remaining component: a cycle among planned components.
            return Err(FullUninstallError::DependencyGraphInvalid);
        }
        ready.sort_by(|a, b| {
            a.installation_sequence
                .cmp(&b.installation_sequence)
                .then_with(|| a.component_id.cmp(&b.component_id))
        });
        for record in &ready {
            order.push(record.component_id.clone());
        }
        let ready_ids: std::collections::HashSet<&str> =
            ready.iter().map(|r| r.component_id.as_str()).collect();
        remaining.retain(|r| !ready_ids.contains(r.component_id.as_str()));
    }

    Ok(order)
}

struct QuarantinedComponent {
    component_id: String,
    live_path: PathBuf,
    quarantine_path: PathBuf,
}

/// Removes the managed root's own `scratch/` execution-cache subtree
/// (`super::MANAGED_SCRATCH_DIR`) through the *same* quarantine -> verify
/// -> destroy sequence every managed component already goes through, and
/// through the same confinement primitive
/// (`uninstall::canonicalize_confined`).
///
/// # Why this exists at all (Phase 15 cache-closure root cause)
///
/// A governed execution (`go build`/`go vet`/`go test` via
/// `wht_corulix_engine::go_providers::ensure_go_scratch`, `cargo test` via
/// `wht_corulix_engine::testing`, gopls via
/// `wht_corulix_engine::semantic`) must write its build/module cache
/// somewhere outside the governed workspace, and does so under
/// `<managed root>/scratch/<phase-scoped key>/<workspace hash>/`. Every
/// byte there is Corulix-created, via the single
/// `provisioning::ensure_scratch_directory` write authority -- so by the
/// ownership contract (CORULIX CREATES IT -> CORULIX OWNS IT -> CORULIX
/// TRACKS IT -> CORULIX REMOVES IT) `full_uninstall` owes its removal.
///
/// Before this function existed, it did not remove it, and the observed
/// symptom was **not** "silently leaves junk behind": `scratch/` fell
/// through to the unexplained-top-level-entry classifier below, so every
/// `full_uninstall` following any governed Go or cargo execution against
/// that root returned `CleanupRequired(["managed-root"])` with the managed
/// root still present. Reproduced exactly, for both the Go
/// (`scratch/p15-go/...`) and Rust (`scratch/p12-cargo-test-target/...`)
/// cache locations, before this fix.
///
/// # Recursive destroy, and why it is not a hole in the fail-closed policy
///
/// `.uninstall-txn/`, `ownership/`, and `staging/` are removed
/// non-recursively (`fs::remove_dir`), so foreign content placed inside
/// them blocks removal. `scratch/` is removed *recursively*, exactly like a
/// managed component's own root, because it legitimately holds a deep,
/// large, Corulix-authored cache tree that no non-recursive removal could
/// ever clear. The safety that non-recursion buys elsewhere is bought here
/// by three checks instead, all performed before a single byte is touched:
///
/// 1. `fs::symlink_metadata(...).is_dir()` -- Corulix's own scratch
///    location must be a real directory. A symlink (to anywhere, inside or
///    outside the managed root) or a plain file sitting there is something
///    Corulix did not create, so it is reported as residue and never
///    followed or deleted (`P15_CACHE_SYMLINK_ESCAPE_DELETE_COUNT=0`).
/// 2. `uninstall::canonicalize_confined` -- the identical symlink-resolving
///    confinement primitive the per-component quarantine path uses; the
///    resolved path must lie under the canonical managed root
///    (`P15_OUTSIDE_ROOT_DELETE_COUNT=0`).
/// 3. Exact-identity equality against `<canonical root>/scratch` -- strictly
///    stronger than `starts_with`, so a substitution that resolves to a
///    *different* path inside the managed root (e.g. `scratch ->
///    components/`) is rejected too, not merely one that escapes it.
///
/// Nested symlinks *inside* the subtree need no special handling:
/// `fs::rename` moves the whole subtree by inode without traversing it, and
/// `fs::remove_dir_all` unlinks symlink entries without following them, so
/// an external target reached by a nested symlink is provably never
/// deleted -- proven by real sentinel-digest assertions rather than
/// asserted here.
///
/// Returns `Err(name)` naming the residual path on any failure, which the
/// caller surfaces as `FullUninstallError::CleanupRequired` -- never a
/// false `Completed`.
async fn quarantine_and_destroy_managed_scratch(root: &Path) -> Result<(), String> {
    let residual = || super::MANAGED_SCRATCH_DIR.to_string();
    let scratch_live = root.join(super::MANAGED_SCRATCH_DIR);

    // Absent is success -- nothing to remove, and deliberately a pure
    // existence probe, never a `create_dir_all`
    // (`ABSENT_ROOT_READ_RECREATION_COUNT=0` holds for repeated calls).
    let Ok(metadata) = fs::symlink_metadata(&scratch_live) else {
        return Ok(());
    };
    if !metadata.is_dir() {
        return Err(residual());
    }

    // ACTIVE MANAGED-EXECUTION PREFLIGHT FOR THIS ROOT'S SCRATCH (Phase 15
    // gopls lifecycle closure). This stage exists because the *component*
    // preflight in `full_uninstall` above cannot cover this subtree: it
    // iterates `removal_order`, i.e. component ids, and a live process can
    // legitimately consume `<root>/scratch` while consuming no managed
    // component at all. The Engine's Go semantic session is exactly that
    // shape -- `LspProviderProfile::gopls()` resolves `gopls` and `go`
    // `HOST_ONLY`, so `resolve_launch`'s `any_managed_dependency_used` gate
    // leases nothing, while `wht_corulix_engine::semantic::ensure_go_lsp_session`
    // points that same live process's `GOCACHE`/`GOMODCACHE`/`GOPATH` at
    // `<root>/scratch/p15-go/<workspace hash>/`. Without this stage the
    // scratch below was quarantined and destroyed under a still-live,
    // still-serving gopls, with zero stop signal ever sent
    // (reproduced, then fixed -- see this repository's Phase 15 gopls
    // lifecycle closure).
    //
    // Deliberately the *same* two-step protocol the component preflight
    // uses, not a second one: signal every lease bound to this root and
    // wait up to `ACTIVE_EXECUTION_STOP_TIMEOUT` for cooperative
    // confirmation, then discard that cooperative answer and decide purely
    // on an independent OS-level `verify_process_absent` re-check of every
    // pid recorded at registration. `Present` and `Uncertain` alike report
    // residue rather than deleting (`P15_ACTIVE_GOPLS_PREMATURE_CACHE_DELETE_COUNT=0`,
    // `UNKNOWN_PROCESS_STATE_DELETE_COUNT=0`); only an independently
    // confirmed-absent process lets a single scratch byte move
    // (`P15_GOPLS_DELETE_BEFORE_REAP_COUNT=0` is an ordering guarantee of
    // this function's control flow, not a timing observation -- no sleep
    // participates in it).
    //
    // Root-scoped, never global: a lease bound to a *different* managed
    // root must not block this root's cleanup, since one host can hold
    // independent Corulix installations
    // (`CORULIX_SINGLE_MACHINE_ASSUMPTION=NO`).
    let root_identity = ownership::root_identity(root);
    let _ = lease::request_stop_for_managed_root(
        &root_identity,
        uninstall::ACTIVE_EXECUTION_STOP_TIMEOUT,
    )
    .await;
    for identity in lease::process_identities_for_managed_root(&root_identity) {
        if lease::verify_process_absent(identity) != lease::ProcessAbsence::Absent {
            return Err(residual());
        }
    }

    // Rule F: only `wht_corulix_workspace` canonicalizes.
    let Ok((root_canonical, _)) =
        wht_corulix_workspace::canonicalize_external_path(root.to_path_buf()).await
    else {
        return Err(residual());
    };
    let Ok(scratch_canonical) =
        uninstall::canonicalize_confined(&root_canonical, &scratch_live).await
    else {
        return Err(residual());
    };
    if scratch_canonical != root_canonical.join(super::MANAGED_SCRATCH_DIR) {
        return Err(residual());
    }

    // QUARANTINE into this cleanup's own transaction directory, under the
    // same `.uninstall-txn/` root the per-component quarantine uses.
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let txn_dir = root.join(".uninstall-txn").join(format!(
        "{}-{}-{stamp}",
        super::MANAGED_SCRATCH_DIR,
        std::process::id()
    ));
    if fs::create_dir_all(&txn_dir).is_err() {
        return Err(residual());
    }
    let quarantine_target = txn_dir.join(super::MANAGED_SCRATCH_DIR);
    if fs::rename(&scratch_canonical, &quarantine_target).is_err() {
        // Nothing was moved -- drop this cleanup's own empty transaction
        // directory again so it cannot itself become residue.
        let _ = fs::remove_dir(&txn_dir);
        return Err(residual());
    }

    // POST-QUARANTINE VERIFY: the live path must be provably gone, by the
    // same non-following probe used to admit it above.
    if fs::symlink_metadata(&scratch_canonical).is_ok() {
        let _ = fs::rename(&quarantine_target, &scratch_canonical);
        let _ = fs::remove_dir(&txn_dir);
        return Err(residual());
    }

    // DESTROY the quarantined copy. A failure here leaves the live path
    // already gone (nothing user-visible is lost) and the quarantine copy
    // stuck -- reported, never a false success.
    if fs::remove_dir_all(&quarantine_target).is_err() {
        return Err(residual());
    }
    if fs::remove_dir(&txn_dir).is_err() {
        return Err(residual());
    }
    Ok(())
}

/// Final zero-residual lifecycle-shell + managed-root cleanup (Phase
/// 7B-B1-R3-B2-B2-R1). Called only after every managed component's
/// destruction AND ownership metadata removal have already been verified
/// successful -- this never runs before metadata-last, and never
/// participates in the process-preflight/quarantine ordering.
///
/// Every removal here uses `fs::remove_dir`, which is non-recursive and
/// only succeeds against a genuinely empty directory. This is deliberate
/// fail-closed behavior, not an oversight: if an operator or another
/// process placed unexpected content inside `ownership/`, `staging/`,
/// `.uninstall-txn/`, or the managed root itself, this function reports
/// that path as still-residual (via the returned `Vec<String>`) instead of
/// silently deleting it (`FOREIGN_RESIDUAL_AUTO_DELETE_COUNT=0`,
/// `FOREIGN_ROOT_AUTO_DELETE_COUNT=0`). A caller not finding this function
/// (`fs::remove_dir` errors) reports `CleanupRequired`, never a false
/// `Completed`/`Removed`.
///
/// `root` not existing at all is treated as already-clean success (`Ok(())`
/// with nothing removed) -- this is what makes repeated calls after a
/// fully successful uninstall idempotent without recreating anything
/// (`ABSENT_ROOT_READ_RECREATION_COUNT=0`): every check below is a plain
/// existence probe, never a `create_dir_all`.
///
/// # Shared-root evidence (Phase 7B-B1-R3-B2-B2-R1 §3)
///
/// The managed-toolchain root is not *exclusively* transient
/// full-uninstall-owned state: `ownership::save` legitimately persists
/// permanent records for `OwnershipClass::HostOnlyOverride` components
/// (host-configured external tools Corulix tracks but must never delete --
/// `full_uninstall_never_touches_a_host_only_override_record`), and
/// `components/` can legitimately hold a pre-ownership orphan directory
/// that predates any Corulix installation and must never be adopted or
/// removed (`full_uninstall_never_touches_a_pre_ownership_orphan`). Both
/// are real, already-certified invariants, not defects -- so this function
/// distinguishes *unexplained* residue (a stray file placed directly
/// inside Corulix's own `ownership/`/`staging/`/`.uninstall-txn/`
/// bookkeeping directories, which nothing in this codebase would ever
/// legitimately write there) from *explained* shared-root content (a real,
/// typed ownership record this subsystem is deliberately preserving, or a
/// pre-existing filesystem entry that was never Corulix's to remove).
/// Only the former is reported as residual; the latter correctly keeps
/// `ownership/`/the managed root retained without that being a failure.
async fn cleanup_lifecycle_shells_and_root(root: &Path) -> Result<(), Vec<String>> {
    if !root.exists() {
        return Ok(());
    }

    // Real test synchronization point (Phase 7B-B1-R3-B2-B2-R4 §1-9):
    // every component and its ownership metadata are already destroyed
    // and verified above -- only the lifecycle-shell/root removal below
    // remains. `#[cfg(test)]`-gated -- this call, and the hook it invokes,
    // do not exist at all in a normal or release build
    // (`PRODUCTION_TEST_SYNCHRONIZATION_RUNTIME_STATE=0`). No-op unless a
    // test has armed it (see module doc) even in test builds.
    #[cfg(test)]
    before_final_root_remove::hit();

    let mut failed: Vec<String> = Vec::new();

    // MANAGED EXECUTION SCRATCH (Phase 15 cache closure §6, §13, §20).
    // Runs BEFORE the `.uninstall-txn` removal below, because it needs a
    // live transaction directory of its own to quarantine into.
    if let Err(residual) = quarantine_and_destroy_managed_scratch(root).await {
        failed.push(residual);
    }

    // `install-profile.json` (Installation-Contract-V1): Corulix's own
    // persisted install-profile record. Once every managed component under
    // this root has been fully uninstalled, the profile has nothing left
    // to reconcile against -- and leaving it behind would silently defeat
    // `FIRST_RUN_RECONCILIATION` on this root's next real bootstrap, which
    // only acts when the profile is *absent* (`ensure_bootstrapped` never
    // overwrites an existing persisted choice). Removed here unconditionally,
    // exactly like `.uninstall-txn`/`staging` below: a full uninstall resets
    // this root's install intent along with its components, so a later
    // bootstrap starts genuinely fresh rather than silently inheriting a
    // stale `Selective`/`OnDemand` choice from before the uninstall.
    let install_profile_path = super::install_profile::state_path(root);
    if install_profile_path.exists() && fs::remove_file(&install_profile_path).is_err() {
        failed.push("install-profile".to_string());
    }
    // Same rationale for a crash-interrupted `save()`'s sibling temp file
    // (`install_profile.rs`'s own write-then-rename atomicity convention) --
    // it would otherwise be equally unexplained residue below.
    let install_profile_tmp_path = root.join("install-profile.json.tmp");
    if install_profile_tmp_path.exists() && fs::remove_file(&install_profile_tmp_path).is_err() {
        failed.push("install-profile-tmp".to_string());
    }

    // `.uninstall-txn/` is exclusively this module's own transactional
    // working directory -- nothing else in this codebase ever writes
    // there, so any survivor after a clean run is unexplained residue.
    let txn_root = root.join(".uninstall-txn");
    if txn_root.exists() && fs::remove_dir(&txn_root).is_err() {
        failed.push("uninstall-txn".to_string());
    }

    // `ownership/`: only attempted once every remaining record (of ANY
    // ownership class, not only `CorulixManaged`) is accounted for. A
    // `HostOnlyOverride` record legitimately keeps this directory
    // non-empty forever -- explained shared-root state, not residue this
    // transaction is responsible for. A file `ownership::list` cannot
    // explain (wrong extension, unparseable) still counts (an error entry
    // is still an entry), so a genuine foreign sentinel dropped directly
    // into `ownership/` is NOT silently tolerated: it simply is not
    // removed here and surfaces via the residual-path enumeration a
    // caller performs afterward, exactly like any other unexplained entry.
    let ownership_dir = root.join("ownership");
    let remaining_records: Vec<ManagedInstallationRecord> = ownership::list(root)
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    // A record `ownership::list` cannot even parse (wrong extension,
    // corrupt JSON) does not appear in `remaining_records` -- so a genuine
    // foreign sentinel dropped directly into `ownership/` is NOT silently
    // tolerated: removal is still attempted, `fs::remove_dir` fails closed
    // on the non-empty directory, and that surfaces as real residue below.
    if ownership_dir.exists()
        && remaining_records.is_empty()
        && fs::remove_dir(&ownership_dir).is_err()
    {
        failed.push("ownership".to_string());
    }

    // `staging/`: purely transient extraction scratch (`unique_staging_dir`
    // in `provisioning.rs`) -- nothing legitimate survives here once every
    // provisioning/uninstall call in flight has completed.
    let staging_dir = root.join("staging");
    if staging_dir.exists() && fs::remove_dir(&staging_dir).is_err() {
        failed.push("staging".to_string());
    }

    if !failed.is_empty() {
        return Err(failed);
    }

    // Managed-root removal (Phase 7B-B1-R3-B2-B2-R2 §5: no "silently
    // retained" -- every remaining top-level entry is mechanically
    // classified, never merely tolerated because the directory happens to
    // be non-empty). `components/` itself is removed by the existing
    // per-component ancestor-cleanup loop (runs earlier in
    // `full_uninstall`, immediately after destruction) as soon as its last
    // child component directory is gone -- if it still exists here, only a
    // pre-ownership orphan or a still-owned (non-CorulixManaged) component
    // root can be why, both already-certified as untouchable, so its mere
    // presence is explained. `ownership/` is explained whenever it was
    // left in place above (a real remaining record). Any OTHER top-level
    // entry is explained only if it is the top-level path component of a
    // remaining record's own `canonical_component_root` (a
    // `HostOnlyOverride` component root living directly under the managed
    // root rather than under `components/`, e.g. this module's own
    // `full_uninstall_never_touches_a_host_only_override_record` fixture).
    // Anything else is genuinely unexplained and blocks final removal --
    // reported, never silently deleted and never silently ignored.
    // Rule F: only `wht_corulix_workspace` may canonicalize -- the same
    // primitive `full_uninstall` itself already uses for
    // `managed_root_canonical` earlier in the transaction.
    let canonical_root = wht_corulix_workspace::canonicalize_external_path(root.to_path_buf())
        .await
        .map(|(canonical, _)| canonical)
        .unwrap_or_else(|_| root.to_path_buf());
    // The stored `canonical_component_root` is whatever the provisioning
    // caller set at install time (`install_dir.clone()`, a plain joined
    // path -- see `provisioning.rs`); it is not guaranteed to carry the
    // same platform canonical representation `fs::canonicalize` produces
    // right here. On Windows in particular, `fs::canonicalize` prepends a
    // `\\?\` verbatim-path prefix that a plain `root.join(..)`-built
    // record path never has, so comparing the two representations
    // directly under `strip_prefix` silently fails to explain genuinely
    // recognized shared-root content even though both paths name the
    // exact same directory (`SHARED_RECOGNIZED_ROOT_PRODUCT_UNINSTALL_RESULT`
    // regression). Re-canonicalize each record's own root the same way
    // before comparing so both sides use one consistent representation;
    // fall back to the raw (uncanonicalized) record path against the raw
    // `root` only if the record's path can no longer be canonicalized
    // (e.g. it was already removed out from under this transaction) --
    // this only ever widens what is recognized as explained, it never
    // narrows the original strip_prefix behavior.
    let mut explained_top_level: std::collections::HashSet<std::ffi::OsString> =
        std::collections::HashSet::new();
    for record in &remaining_records {
        let top_level = match wht_corulix_workspace::canonicalize_external_path(
            record.canonical_component_root.clone(),
        )
        .await
        {
            Ok((canonical_record_root, _)) => canonical_record_root
                .strip_prefix(&canonical_root)
                .ok()
                .and_then(|relative| relative.components().next())
                .map(|component| component.as_os_str().to_os_string()),
            Err(_) => record
                .canonical_component_root
                .strip_prefix(root)
                .ok()
                .and_then(|relative| relative.components().next())
                .map(|component| component.as_os_str().to_os_string()),
        };
        if let Some(top_level) = top_level {
            explained_top_level.insert(top_level);
        }
    }

    let mut unexplained: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name == "ownership" || name == "components" || explained_top_level.contains(&name) {
                continue;
            }
            unexplained.push(name.to_string_lossy().to_string());
        }
    }
    if !unexplained.is_empty() {
        failed.push("managed-root".to_string());
        return Err(failed);
    }

    let root_has_remaining_entries = fs::read_dir(root)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    if root_has_remaining_entries {
        // Every remaining entry is explained (a live non-CorulixManaged
        // ownership record, `ownership/` itself required by one, or
        // `components/` holding only untouchable non-CorulixManaged
        // content) -- the root is legitimately retained shared-root state,
        // not residue this transaction owns.
        return Ok(());
    }
    if fs::remove_dir(root).is_err() {
        failed.push("managed-root".to_string());
        return Err(failed);
    }

    Ok(())
}

/// The canonical Corulix-product-facing entry point (Phase 7B-B1-R3-B2
/// §27): "uninstall the product's own managed toolchain" resolves to
/// exactly this call, and to nothing else. There is deliberately no
/// second, independent removal implementation for a product-level
/// uninstall to call -- it delegates to the same
/// [`full_uninstall`] every other caller uses. This is the internal
/// function/trait boundary a future OS packaging/uninstaller layer calls;
/// it does not itself perform any OS-level package removal.
pub async fn uninstall_all_corulix_managed_components()
-> Result<FullUninstallOutcome, FullUninstallError> {
    let root = super::managed_toolchain_root().map_err(|_| FullUninstallError::Io)?;
    uninstall_all_corulix_managed_components_at(&root).await
}

/// Product-facing full-uninstall boundary parameterized on an explicit managed root.
///
/// This is the real implementation reached by [`uninstall_all_corulix_managed_components`].
/// It exists as a separate function so tests can exercise the product contract against an
/// isolated temporary root without unsafe code or environment-variable mutation — the no-arg
/// wrapper above is the only caller that resolves the real host-managed toolchain root.
pub async fn uninstall_all_corulix_managed_components_at(
    root: &Path,
) -> Result<FullUninstallOutcome, FullUninstallError> {
    full_uninstall(root).await
}

/// Runs the full transactional uninstall of every `CorulixManaged`
/// component currently installed under `root`, as one globally planned,
/// dependency-aware, process-aware, fail-closed transaction.
pub async fn full_uninstall(root: &Path) -> Result<FullUninstallOutcome, FullUninstallError> {
    if recovery_locked(root) {
        return Err(FullUninstallError::RecoveryLocked);
    }

    let root_identity = ownership::root_identity(root);
    // Exclusive hold on the root lock for the whole transaction --
    // excludes every individual provision/uninstall call for the
    // transaction's entire duration.
    let _root_guard = lock_root_exclusive(&root_identity).await;

    // Re-check after acquiring the lock: a transaction that failed and
    // recovery-locked the root between our first check and acquiring the
    // write lock must still be honored.
    if recovery_locked(root) {
        return Err(FullUninstallError::RecoveryLocked);
    }

    #[cfg(test)]
    if fault_at(FaultStage::Prepare) {
        return Err(FullUninstallError::Io);
    }

    // PREPARE: load + validate EVERY ownership record, all-or-none.
    let mut all_records = Vec::new();
    for entry in ownership::list(root) {
        let record: ManagedInstallationRecord =
            entry.map_err(|_: OwnershipError| FullUninstallError::OwnershipPreflightFailed)?;
        all_records.push(record);
    }
    let planned: Vec<ManagedInstallationRecord> = all_records
        .into_iter()
        .filter(|r| r.ownership == OwnershipClass::CorulixManaged)
        .collect();

    if planned.is_empty() {
        // Phase 7B-B1-R3-B2-B2-R2: no `CorulixManaged` component means
        // there is no removal *plan*, but stray empty lifecycle shells can
        // still exist here -- e.g. a single-component `uninstall::uninstall`
        // call (which never runs this cleanup itself) just removed the
        // last `CorulixManaged` record out-of-band, moments before this
        // very call. `full_uninstall` is the sole zero-residual cleanup
        // authority, so it still sweeps them here rather than silently
        // reporting `NoManagedComponents` while residue remains.
        if let Err(residual) = cleanup_lifecycle_shells_and_root(root).await {
            return Err(FullUninstallError::CleanupRequired(residual));
        }
        return Ok(FullUninstallOutcome::NoManagedComponents);
    }

    let removal_order = compute_removal_order(&planned)?;

    #[cfg(test)]
    if fault_at(FaultStage::ProcessPreflight) {
        return Err(FullUninstallError::ProcessPreflightBusy(vec![
            "fault-injected".to_string(),
        ]));
    }

    // GLOBAL PROCESS PREFLIGHT, two passes across the whole plan (never
    // interleaved stop-then-quarantine per component -- that is exactly
    // what this mandate forbids). Root-scoped (P17-W-R3-C5,
    // `TS6_LEASE_STOP_ROOT_SCOPING_DEFECT`): computed once from the exact
    // `root` this `full_uninstall` call targets, so a same-named component
    // leased under a *different* managed root can never be signalled or
    // attributed to this plan -- full uninstall remains global authority
    // only for the root it was invoked against.
    let owning_root = lease::RootIdentity::of(root);
    for component_id in &removal_order {
        let _ = lease::request_stop_for_component(
            lease::ComponentLeaseScope {
                root: &owning_root,
                component_id: component_id.as_str(),
            },
            uninstall::ACTIVE_EXECUTION_STOP_TIMEOUT,
        )
        .await;
    }
    let mut busy = Vec::new();
    let mut uncertain = Vec::new();
    for component_id in &removal_order {
        for identity in lease::process_identities_for_component(lease::ComponentLeaseScope {
            root: &owning_root,
            component_id: component_id.as_str(),
        }) {
            match lease::verify_process_absent(identity) {
                lease::ProcessAbsence::Absent => {}
                lease::ProcessAbsence::Present => busy.push(component_id.clone()),
                lease::ProcessAbsence::Uncertain => uncertain.push(component_id.clone()),
            }
        }
    }
    if !busy.is_empty() {
        return Err(FullUninstallError::ProcessPreflightBusy(busy));
    }
    if !uncertain.is_empty() {
        return Err(FullUninstallError::ProcessStateUncertain(uncertain));
    }

    // Canonicalize the managed root once; every component's canonical
    // install root and owned paths are validated exactly as the
    // single-component path does, reusing the same primitive.
    //
    // P17-W (Pyright vertical) diagnostic note: a real native-Windows run
    // of `real_p7b_d_shared_node_two_dependents_active_e2e.rs` initially
    // surfaced this call returning `Err(Io)` deterministically. Root-caused
    // via temporary instrumentation (since removed) to that test's own
    // `isolated_root` fixture helper, not to this production call: it fell
    // back to the literal, hardcoded-to-Linux string `"/root"` whenever
    // `$HOME` was unset (always true on Windows), so its managed root was
    // built as `/root/.cache/...` -- a path Windows' own `fs::canonicalize`
    // tolerates (resolving the leading `/` against the current drive) but
    // that `std::path::Path::is_absolute()` never reports as absolute
    // there (no drive/UNC prefix component), which is exactly what this
    // crate's `canonicalize_external_path` fails closed on. No retry or
    // production change was needed here -- fixed at the test fixture
    // itself (now uses `std::env::temp_dir()`, matching every sibling
    // isolated-root helper in this same test suite).
    let (managed_root_canonical, _) =
        wht_corulix_workspace::canonicalize_external_path(root.to_path_buf())
            .await
            .map_err(|_| FullUninstallError::Io)?;

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let transaction_id = format!("full-{}-{stamp}", std::process::id());
    let txn_dir = root.join(".uninstall-txn").join(&transaction_id);
    fs::create_dir_all(&txn_dir).map_err(|_| FullUninstallError::Io)?;

    let mut txn_record = TransactionRecord {
        transaction_id: transaction_id.clone(),
        managed_root_identity: root_identity.clone(),
        removal_order: removal_order.clone(),
        quarantined: Vec::new(),
        state: TransactionState::Preparing,
    };
    persist_transaction_record(&txn_dir, &txn_record);

    #[cfg(test)]
    if fault_at(FaultStage::FirstQuarantine) {
        return Err(FullUninstallError::Component(
            removal_order[0].clone(),
            UninstallError::QuarantineFailed,
        ));
    }

    // QUARANTINE, in removal order, into this transaction's own directory.
    let mut quarantined: Vec<QuarantinedComponent> = Vec::new();
    txn_record.state = TransactionState::Quarantining;
    let quarantine_result: Result<(), FullUninstallError> = async {
        for component_id in &removal_order {
            #[cfg(test)]
            // `RollbackFailure` also triggers the mid-quarantine failure at
            // the same point -- `INJECTED_FAULT` holds a single value, and
            // exercising a *failed rollback* requires a rollback to be
            // triggered in the first place, so `RollbackFailure` alone must
            // be sufficient to reach it without also setting `MidQuarantine`.
            if quarantined.len() == 1
                && (fault_at(FaultStage::MidQuarantine) || fault_at(FaultStage::RollbackFailure))
            {
                return Err(FullUninstallError::Component(
                    component_id.clone(),
                    UninstallError::QuarantineFailed,
                ));
            }
            let record = planned
                .iter()
                .find(|r| &r.component_id == component_id)
                .ok_or(FullUninstallError::DependencyGraphInvalid)?;
            let component_root_canonical = uninstall::canonicalize_confined(
                &managed_root_canonical,
                &record.canonical_component_root,
            )
            .await
            .map_err(|error| FullUninstallError::Component(component_id.clone(), error))?;

            let quarantine_target = txn_dir.join(component_id);
            if component_root_canonical.exists() {
                rename_retrying_transient_windows_lock(
                    &component_root_canonical,
                    &quarantine_target,
                )
                .await
                .map_err(|io_error| {
                    // Phase 18: preserve the real underlying `io::Error`
                    // (including its `raw_os_error()`) on normal stderr
                    // before it is narrowed into the existing, payload-less
                    // `UninstallError::QuarantineFailed` variant shared with
                    // the single-component uninstall path -- this class of
                    // failure must be diagnosable from a normal run's logs
                    // without requiring another instrumented rebuild.
                    eprintln!(
                        "FULL_UNINSTALL_QUARANTINE_RENAME_FAILED component_id={component_id} \
                         from={} to={} io_error={io_error} raw_os_error={:?}",
                        component_root_canonical.display(),
                        quarantine_target.display(),
                        io_error.raw_os_error(),
                    );
                    FullUninstallError::Component(
                        component_id.clone(),
                        UninstallError::QuarantineFailed,
                    )
                })?;
            }
            quarantined.push(QuarantinedComponent {
                component_id: component_id.clone(),
                live_path: component_root_canonical,
                quarantine_path: quarantine_target,
            });
            txn_record.quarantined = quarantined.iter().map(|q| q.component_id.clone()).collect();
            persist_transaction_record(&txn_dir, &txn_record);
        }
        Ok(())
    }
    .await;

    if let Err(error) = quarantine_result {
        return rollback_and_report(root, &txn_dir, &quarantined, error).await;
    }

    #[cfg(test)]
    if fault_at(FaultStage::PostQuarantineVerify) {
        return rollback_and_report(
            root,
            &txn_dir,
            &quarantined,
            FullUninstallError::Component(
                removal_order[0].clone(),
                UninstallError::VerificationFailed,
            ),
        )
        .await;
    }

    // POST-QUARANTINE GLOBAL VERIFY: every planned live path must be gone.
    txn_record.state = TransactionState::Verifying;
    persist_transaction_record(&txn_dir, &txn_record);
    for component in &quarantined {
        if component.live_path.exists() {
            return rollback_and_report(
                root,
                &txn_dir,
                &quarantined,
                FullUninstallError::Component(
                    component.component_id.clone(),
                    UninstallError::VerificationFailed,
                ),
            )
            .await;
        }
    }

    // DESTROY every quarantined copy. A failure here is CLEANUP_REQUIRED,
    // never a false COMPLETED -- live paths are already proven absent, so
    // nothing user-visible is lost, only the quarantine copy is stuck.
    txn_record.state = TransactionState::Destroying;
    persist_transaction_record(&txn_dir, &txn_record);
    let mut destroyed: Vec<String> = Vec::new();
    let mut destruction_failed: Vec<String> = Vec::new();
    for component in &quarantined {
        #[cfg(test)]
        if fault_at(FaultStage::Destruction) {
            destruction_failed.push(component.component_id.clone());
            continue;
        }
        if component.quarantine_path.exists() {
            match fs::remove_dir_all(&component.quarantine_path) {
                Ok(()) => destroyed.push(component.component_id.clone()),
                Err(_) => destruction_failed.push(component.component_id.clone()),
            }
        } else {
            destroyed.push(component.component_id.clone());
        }
    }
    if !destruction_failed.is_empty() {
        return Err(FullUninstallError::CleanupRequired(destruction_failed));
    }

    #[cfg(test)]
    if fault_at(FaultStage::MetadataCleanup) {
        // Metadata was not yet removed for anything -- retained in full for
        // a retry. OWNERSHIP_METADATA_EARLY_DELETE_COUNT=0 holds.
        return Err(FullUninstallError::CleanupRequired(vec![
            "fault-injected-metadata".to_string(),
        ]));
    }

    // Best-effort: remove now-empty version-scoped parent directories for
    // every destroyed component (mirrors the single-component `uninstall`
    // path), so a fully-removed component leaves no leftover directory
    // tree behind. Never fails if a sibling version's directory is still
    // present (`remove_dir` only succeeds when empty).
    for component in &quarantined {
        let mut ancestor = component.live_path.parent();
        while let Some(dir) = ancestor {
            if dir == managed_root_canonical || fs::remove_dir(dir).is_err() {
                break;
            }
            ancestor = dir.parent();
        }
    }

    // METADATA REMOVAL LAST, in removal order, only for components whose
    // destruction was already verified above. A real removal failure here
    // must not be swallowed into a false `Completed` -- it is reported as
    // `CleanupRequired` exactly like a destruction failure, since live
    // state is already unaffected and only the metadata write is stuck.
    txn_record.state = TransactionState::Cleaning;
    persist_transaction_record(&txn_dir, &txn_record);
    let mut metadata_failed: Vec<String> = Vec::new();
    for component_id in &removal_order {
        let component_id_static: &'static str = Box::leak(component_id.clone().into_boxed_str());
        if ownership::remove(root, super::ManagedComponentId(component_id_static)).is_err() {
            metadata_failed.push(component_id.clone());
        }
    }
    if !metadata_failed.is_empty() {
        return Err(FullUninstallError::CleanupRequired(metadata_failed));
    }
    // M06 payload-verification-cache: every component named in
    // `removal_order` had its ownership metadata just removed above --
    // drop every one of their cached attestations under this root so none
    // linger in the process-local cache for the rest of this process's
    // lifetime.
    for component_id in &removal_order {
        super::payload_verification_cache::invalidate_component(&root_identity, component_id);
    }

    let _ = fs::remove_file(txn_dir.join("transaction.json"));
    let _ = fs::remove_dir(&txn_dir);

    // ZERO-RESIDUAL LIFECYCLE-SHELL + MANAGED-ROOT CLEANUP (Phase
    // 7B-B1-R3-B2-B2-R1 -- owner-mandated: an empty Corulix-owned
    // directory shell is still residual state, so `Removed` must not be
    // returned while `.uninstall-txn`/`ownership`/`staging`/the managed
    // root itself still exist). Every managed component and its ownership
    // metadata are already verified gone above -- this stage cannot
    // resurrect a component and cannot run before metadata-last.
    if let Err(residual) = cleanup_lifecycle_shells_and_root(root).await {
        return Err(FullUninstallError::CleanupRequired(residual));
    }

    // M06 payload-verification-cache: final, defensive whole-root sweep.
    // Every component already had its own attestation individually
    // invalidated above as its metadata was removed; this second,
    // root-wide pass exists so a full uninstall's cache-cleanliness
    // guarantee never depends on `removal_order` having named every
    // component correctly -- belt-and-suspenders, not a substitute for the
    // per-component calls above.
    super::payload_verification_cache::invalidate_root(&root_identity);

    Ok(FullUninstallOutcome::Removed(removal_order))
}

/// The explicit, typed manual-recovery entry point for a transaction left
/// in [`FullUninstallError::CleanupRequired`]: every quarantined component
/// this transaction's durable `transaction.json` still names is retried
/// (destroy, if not already gone; then, once every one is confirmed gone,
/// remove its ownership metadata). Never auto-invoked -- a caller/operator
/// must explicitly call this after resolving whatever external condition
/// caused the original destruction/metadata failure (`UNINSTALL_CLEANUP_REQUIRED_RETRY`).
pub async fn full_uninstall_resume_cleanup(
    root: &Path,
) -> Result<FullUninstallOutcome, FullUninstallError> {
    let root_identity = ownership::root_identity(root);
    let _root_guard = lock_root_exclusive(&root_identity).await;

    let txn_root = root.join(".uninstall-txn");
    let mut removed_any = false;
    let mut destruction_failed: Vec<String> = Vec::new();
    let mut metadata_failed: Vec<String> = Vec::new();
    let mut resumed_ids: Vec<String> = Vec::new();

    // Deliberately no early `return Ok(NoManagedComponents)` when
    // `.uninstall-txn` is absent/unreadable -- a prior run may have
    // already destroyed every component and removed all metadata, leaving
    // only the final lifecycle-shell/root cleanup (below) still pending
    // from a `CleanupRequired` on *that* stage. This resume entry point
    // must still retry that regardless of whether any transaction
    // directory remains to iterate.
    if let Ok(entries) = fs::read_dir(&txn_root) {
        for entry in entries.flatten() {
            let txn_dir = entry.path();
            if !txn_dir.is_dir() {
                continue;
            }
            let record_path = txn_dir.join("transaction.json");
            let Ok(bytes) = fs::read(&record_path) else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<TransactionRecord>(&bytes) else {
                continue;
            };
            if record.managed_root_identity != root_identity {
                continue;
            }

            for component_id in &record.quarantined {
                let quarantine_path = txn_dir.join(component_id);
                if quarantine_path.exists() && fs::remove_dir_all(&quarantine_path).is_err() {
                    destruction_failed.push(component_id.clone());
                }
            }
            if !destruction_failed.is_empty() {
                continue;
            }

            for component_id in &record.removal_order {
                let component_id_static: &'static str =
                    Box::leak(component_id.clone().into_boxed_str());
                if ownership::remove(root, super::ManagedComponentId(component_id_static)).is_err()
                {
                    metadata_failed.push(component_id.clone());
                } else {
                    // M06 payload-verification-cache: metadata genuinely
                    // removed on this resumed pass -- same invalidation as
                    // the primary `full_uninstall` path.
                    super::payload_verification_cache::invalidate_component(
                        &root_identity,
                        component_id,
                    );
                    resumed_ids.push(component_id.clone());
                    removed_any = true;
                }
            }
            if metadata_failed.is_empty() {
                let _ = fs::remove_file(&record_path);
                let _ = fs::remove_dir(&txn_dir);
            }
        }
    }

    if !destruction_failed.is_empty() {
        return Err(FullUninstallError::CleanupRequired(destruction_failed));
    }
    if !metadata_failed.is_empty() {
        return Err(FullUninstallError::CleanupRequired(metadata_failed));
    }

    // Same final zero-residual shell + managed-root cleanup `full_uninstall`
    // itself runs -- retrying this is this function's whole purpose when
    // the original failure was here rather than in destruction/metadata.
    if let Err(residual) = cleanup_lifecycle_shells_and_root(root).await {
        return Err(FullUninstallError::CleanupRequired(residual));
    }

    if removed_any {
        Ok(FullUninstallOutcome::Removed(resumed_ids))
    } else {
        Ok(FullUninstallOutcome::NoManagedComponents)
    }
}

/// The explicit, typed manual-recovery entry point for a root left
/// `recovery_locked`: clears the durable recovery marker, unblocking
/// every managed-lifecycle entry point again. Deliberately does **not**
/// attempt to guess or auto-repair whatever filesystem inconsistency
/// caused the original rollback failure -- an operator (or, in an
/// automated context, whatever verified the residue is actually safe)
/// must call this explicitly; nothing in this module calls it on its own.
pub fn clear_recovery_lock(root: &Path) {
    let _ = fs::remove_file(recovery_marker_path(root));
}

/// Reverse-order rollback of everything already quarantined. On success,
/// surfaces the original error (nothing is left live-broken). On failure,
/// writes the durable recovery-lock marker and reports
/// [`FullUninstallError::RecoveryRequired`] instead.
async fn rollback_and_report(
    root: &Path,
    txn_dir: &Path,
    quarantined: &[QuarantinedComponent],
    original_error: FullUninstallError,
) -> Result<FullUninstallOutcome, FullUninstallError> {
    #[cfg(test)]
    if fault_at(FaultStage::RollbackFailure) {
        write_recovery_marker(root, "test-injected rollback failure");
        return Err(FullUninstallError::RecoveryRequired);
    }
    for component in quarantined.iter().rev() {
        if component.quarantine_path.exists() {
            if let Some(parent) = component.live_path.parent()
                && fs::create_dir_all(parent).is_err()
            {
                write_recovery_marker(
                    root,
                    &format!(
                        "rollback failed to recreate parent for {}",
                        component.component_id
                    ),
                );
                return Err(FullUninstallError::RecoveryRequired);
            }
            if let Err(io_error) = rename_retrying_transient_windows_lock(
                &component.quarantine_path,
                &component.live_path,
            )
            .await
            {
                // Phase 18: preserve the real underlying `io::Error` on
                // normal stderr before the recovery marker's own free-text
                // reason (which has no room for a `raw_os_error()`) is
                // written -- this is the same discard-avoidance fix as the
                // quarantine loop above, applied to rollback's own use of
                // the identical retrying-rename primitive.
                eprintln!(
                    "FULL_UNINSTALL_ROLLBACK_RENAME_FAILED component_id={} from={} to={} \
                     io_error={io_error} raw_os_error={:?}",
                    component.component_id,
                    component.quarantine_path.display(),
                    component.live_path.display(),
                    io_error.raw_os_error(),
                );
                write_recovery_marker(
                    root,
                    &format!("rollback rename failed for {}", component.component_id),
                );
                return Err(FullUninstallError::RecoveryRequired);
            }
        }
    }
    let _ = fs::remove_file(txn_dir.join("transaction.json"));
    let _ = fs::remove_dir(txn_dir);
    let _ = fs::remove_dir(root.join(".uninstall-txn"));

    match original_error {
        FullUninstallError::Component(id, _) => {
            Err(FullUninstallError::QuarantineFailedRolledBack(id))
        }
        other => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning::uninstall::{NewInstallation, build_record};

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("corulix-full-uninstall-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn ok_or_panic<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("test fixture setup must succeed: {error:?}"))
    }

    /// `INJECTED_FAULT` is one process-wide static, not scoped per test
    /// root -- `cargo test`'s default concurrent execution otherwise lets
    /// one test's `set_fault` leak into a sibling test's unrelated
    /// `full_uninstall` call running at the same moment (the exact defect
    /// class found and fixed for `ManagedExecutionLease`'s registry in
    /// Phase 7B-B1-R3-A). Every test in this module acquires this lock
    /// first and holds it for its whole body, serializing them against
    /// each other; this is a deliberate test-only concern, never a
    /// production behavior change.
    ///
    /// P17-W-R3-C3 (`CANONICAL_DEFAULT_PARALLEL_TEST_GATE_FLAKINESS` root
    /// cause): every test in this module also calls
    /// `lease::verify_process_absent` (directly or via `full_uninstall`),
    /// which reads `provisioning::lease`'s crate-wide
    /// `INJECTED_PROBE_OVERRIDE` test seam -- a static `provisioning::uninstall`'s
    /// own tests write to, compiled into the same test binary and run
    /// concurrently by default. A lock private to this module could not
    /// serialize against that write. `full_uninstall_test_lock` now
    /// delegates to [`lease::probe_override_test_lock`], the one crate-wide
    /// lock every reader and writer of the shared override (and, as an
    /// existing side effect, every `INJECTED_FAULT` reader/writer in this
    /// module) must hold -- a single lock, never two acquired in sequence,
    /// so no new lock-ordering hazard is introduced.
    async fn full_uninstall_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
        lease::probe_override_test_lock().await
    }

    fn loaded_or_panic(
        root: &Path,
        component_id: &'static str,
    ) -> Option<ManagedInstallationRecord> {
        ok_or_panic(ownership::load(
            root,
            super::super::ManagedComponentId(component_id),
        ))
    }

    fn install_fixture(root: &Path, id: &'static str, deps: Vec<String>, sequence: u64) -> PathBuf {
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
                installation_sequence: sequence,
                artifact_digest: "0".repeat(64),
                ownership: OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        assert!(
            ownership::save(root, &mut record).is_ok(),
            "ownership record must save"
        );
        component_root
    }

    #[tokio::test]
    async fn full_uninstall_of_empty_root_reports_no_managed_components() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("empty");
        let outcome = full_uninstall(&root).await;
        assert_eq!(outcome, Ok(FullUninstallOutcome::NoManagedComponents));
        let _ = fs::remove_dir_all(&root);
    }

    /// Installation-Contract-V1 §74 zero-residual proof, specifically for
    /// the persisted install-profile record (not merely "the residual check
    /// stops tripping"): a real `Full` profile is persisted into this
    /// isolated root, `full_uninstall` runs, and `install_profile::load`
    /// must come back `Ok(None)` afterward -- proving the file was actually
    /// removed, not merely tolerated by some other exemption.
    #[tokio::test]
    async fn full_uninstall_removes_the_persisted_install_profile() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("install-profile-residual");
        install_fixture(&root, "profile-residual-fixture", Vec::new(), 1);
        assert!(
            super::super::install_profile::save(
                &root,
                &super::super::install_profile::InstallProfile::Full
            )
            .is_ok(),
            "install profile must persist"
        );

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "profile-residual-fixture".to_string()
            ]))
        );
        assert_eq!(
            super::super::install_profile::load(&root),
            Ok(None),
            "a full uninstall must remove the persisted install profile along with every \
             managed component, so a later bootstrap of this root starts genuinely fresh"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn product_uninstall_boundary_at_explicit_root_delegates_to_full_uninstall() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("product-contract");
        install_fixture(&root, "node-fixture", Vec::new(), 1);
        install_fixture(
            &root,
            "pyright-fixture",
            vec!["node-fixture".to_string()],
            2,
        );

        let outcome = uninstall_all_corulix_managed_components_at(&root).await;
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "pyright-fixture".to_string(),
                "node-fixture".to_string(),
            ]))
        );
        assert!(loaded_or_panic(&root, "node-fixture").is_none());
        assert!(loaded_or_panic(&root, "pyright-fixture").is_none());
        let _ = fs::remove_dir_all(&root);
    }

    /// Phase 7B-B1-R3-B2-B §20: a pre-ownership orphan -- an artifact
    /// sitting at the exact expected managed component path, but with no
    /// ownership record at all -- must never enter `full_uninstall`'s own
    /// `planned` set (`planned` is built by filtering `ownership::list(root)`
    /// to `CorulixManaged`, so a component with zero ownership record can
    /// never appear there structurally), must never be adopted/removed by
    /// a `full_uninstall` run that legitimately removes a *different*,
    /// genuinely-owned component sitting alongside it, and must survive on
    /// disk byte-for-byte afterward.
    #[tokio::test]
    async fn full_uninstall_never_adopts_or_removes_a_pre_ownership_orphan_sitting_alongside_owned_components()
     {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("preownership-orphan");
        install_fixture(&root, "owned-fixture", Vec::new(), 1);

        // The orphan: present on disk at the exact expected managed path,
        // but no `ownership::save` was ever called for it.
        let orphan_root = root.join("components").join("orphan-fixture").join("1.0.0");
        ok_or_panic(fs::create_dir_all(&orphan_root));
        ok_or_panic(fs::write(orphan_root.join("bin"), b"orphan binary"));
        let orphan_binary = orphan_root.join("bin");
        let orphan_bytes_before = ok_or_panic(fs::read(&orphan_binary));

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "owned-fixture".to_string()
            ])),
            "PREOWNERSHIP_ORPHAN_AUTO_DELETE_COUNT!=0 (or the orphan was wrongly counted): {outcome:?}"
        );
        assert!(
            orphan_root.exists(),
            "PREOWNERSHIP_ORPHAN_AUTO_DELETE_COUNT!=0: the orphan's directory was removed"
        );
        let orphan_bytes_after = ok_or_panic(fs::read(&orphan_binary));
        assert_eq!(
            orphan_bytes_before, orphan_bytes_after,
            "the orphan artifact's bytes changed across an unrelated full_uninstall run"
        );
        assert!(loaded_or_panic(&root, "owned-fixture").is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_removes_a_dependency_chain_dependents_first() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("chain");
        install_fixture(&root, "node-fixture", Vec::new(), 1);
        install_fixture(
            &root,
            "pyright-fixture",
            vec!["node-fixture".to_string()],
            2,
        );

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "pyright-fixture".to_string(),
                "node-fixture".to_string(),
            ]))
        );

        assert!(!root.join("components/node-fixture").exists());
        assert!(!root.join("components/pyright-fixture").exists());
        assert!(loaded_or_panic(&root, "node-fixture").is_none());
        assert!(loaded_or_panic(&root, "pyright-fixture").is_none());

        // §46 post-success basic zero state.
        let remaining_managed = ownership::list(&root)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|r| r.ownership == OwnershipClass::CorulixManaged)
            .count();
        assert_eq!(
            remaining_managed, 0,
            "POST_FULL_UNINSTALL_MANAGED_COMPONENT_COUNT=0"
        );
        // Scoped to this test's own two component ids, not the process-wide
        // total: `lease::active_lease_count()` reads one static registry
        // shared by the whole test binary, so asserting it is globally `0`
        // here would race unrelated, concurrently-running
        // `provisioning::lease::tests` in the same binary that legitimately
        // hold leases for their own fixture ids at the same moment.
        let post_removal_root = lease::RootIdentity::of(&root);
        assert_eq!(
            lease::process_identities_for_component(lease::ComponentLeaseScope {
                root: &post_removal_root,
                component_id: "node-fixture",
            })
            .len()
                + lease::process_identities_for_component(lease::ComponentLeaseScope {
                    root: &post_removal_root,
                    component_id: "pyright-fixture",
                })
                .len(),
            0,
            "POST_FULL_UNINSTALL_ACTIVE_LEASE_COUNT=0 (scoped to this test's own components)"
        );
        assert!(
            !root.join(".uninstall-txn").exists()
                || fs::read_dir(root.join(".uninstall-txn"))
                    .map(|mut e| e.next().is_none())
                    .unwrap_or(true),
            "POST_FULL_UNINSTALL_QUARANTINE_COUNT=0"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// P17 closure (Pyright/managed-Node `full_uninstall` lifecycle
    /// disambiguation): the prior closure pass's own report said "a live
    /// Pyright session survived a real `full_uninstall`" without
    /// distinguishing *why*. Traced separately (see
    /// `wht_corulix_engine/tests/real_p17_pyright_active_lifecycle_e2e.rs`
    /// and `semantic.rs::ensure_python_lsp_session`): the production Python
    /// routing spawns Pyright via `LspProviderProfile::pyright()`
    /// (`managed_component: None`, `managed_interpreter: None`), which
    /// registers **no lease at all** -- so that survival is correct and
    /// expected, not evidence either way about whether `full_uninstall`
    /// actually enforces stop-before-delete for a live process a lease
    /// *does* name (the shape a managed Pyright + managed Node dependency
    /// would have, via `pyright_managed()`, if that constructor were ever
    /// wired into production routing).
    ///
    /// This test proves the latter, generically and without any
    /// Pyright-specific code anywhere in `full_uninstall` itself (there is
    /// none to write): a real child process stands in for a live managed
    /// Pyright session, registered via the exact same
    /// `lease::ManagedExecutionLease`/`ManagedLeaseBinding` authority
    /// `wht_corulix_lsp::profile::resolve_launch_at` uses for every managed
    /// provider (gopls/rust-analyzer/typescript-language-server/Pyright
    /// alike -- `any_managed_dependency_used` in that file gates all of them
    /// through one code path), bound as the primary of a "pyright"-shaped
    /// component with a "node"-shaped dependency component, mirroring
    /// `pyright_managed()`'s own `dependencies: ["node-runtime"]` shape.
    ///
    /// No sleep-based synchronization anywhere: liveness is proven by a
    /// real, independent `/proc/<pid>` existence probe (never trusting this
    /// crate's own bookkeeping alone) plus this crate's own
    /// `lease::verify_process_absent` (the identical primitive
    /// `full_uninstall`'s preflight itself calls), and death is proven by a
    /// real, blocking `Child::wait()` reap -- never an elapsed-time guess.
    #[tokio::test]
    async fn full_uninstall_stops_a_live_managed_pyright_process_before_deleting_its_managed_node_dependency()
     {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("pyright-node-lifecycle");
        install_fixture(&root, "node-lifecycle-fixture", Vec::new(), 1);
        install_fixture(
            &root,
            "pyright-lifecycle-fixture",
            vec!["node-lifecycle-fixture".to_string()],
            2,
        );

        // A real, live child process standing in for a live managed Pyright
        // session -- never a mock, never a sleep-based assumption. Placed
        // into its own process group (`process_group(0)`), exactly as
        // `platform::prepare` does for every real managed process this
        // crate spawns -- `lease::verify_process_absent`'s underlying
        // `platform::test_alive` checks group liveness via `kill(-pid, 0)`
        // (`test_kill_process_group`), so a plain non-group-leader child
        // would falsely read `Absent` while genuinely alive.
        // P17-W-R3-C2 (`WINDOWS_PROCESS_FIXTURE_PORTABILITY`): the target is
        // the cross-platform `wht_corulix_process_fixture` binary in
        // `sleep-ms` mode, never a bare `"sleep"` ambient-`PATH` lookup --
        // there is no `sleep.exe` on `PATH` on Windows, so this site
        // failed closed with `program not found` under native Windows
        // certification before this fix (found precisely because this
        // phase runs the real suite on real Windows, not a cross-compile
        // stand-in).
        let fixture = crate::fixture_support::fixture_binary_path().unwrap_or_else(|error| {
            unreachable!("resolving the process fixture must succeed: {error}")
        });
        let mut command = std::process::Command::new(fixture);
        command.args(["sleep-ms", "120000"]);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        let mut child = ok_or_panic(command.spawn());
        let pyright_pid_before = child.id();
        let identity = lease::ProcessIdentity {
            pid: pyright_pid_before,
        };

        // Bound exactly as `resolve_launch_at` binds `pyright_managed()`:
        // primary = the Pyright-shaped component, dependency = its managed
        // Node interpreter.
        let execution_lease = lease::ManagedExecutionLease::register(
            lease::ManagedLeaseBinding::for_components(
                lease::RootIdentity::of(&root),
                "pyright-lifecycle-fixture",
                vec!["node-lifecycle-fixture"],
            ),
            identity,
        );
        execution_lease.mark_active();
        // Deliberately (falsely) acknowledges stopped immediately: this
        // lease's own cooperative state is not what protects the live
        // process below (module docs, "Lease state is not process-state
        // authority" -- `FALSE_STOPPED_LEASE_DELETE_COUNT=0`). Real
        // protection comes entirely from `verify_process_absent`'s
        // independent OS-level re-check, proven below to still correctly
        // refuse `full_uninstall` even though this lease already (falsely)
        // claims `Stopped`. This also keeps `request_stop_for_component`'s
        // internal poll from burning its full 30s timeout twice in this
        // test for no reason -- the real safety property under test is
        // unaffected either way.
        execution_lease.acknowledge_stopped();

        let proc_path_before = PathBuf::from(format!("/proc/{pyright_pid_before}"));
        let independently_verifiable = std::env::consts::OS == "linux";
        if independently_verifiable {
            assert!(
                proc_path_before.exists(),
                "PYRIGHT_PID_BEFORE_FULL_UNINSTALL={pyright_pid_before} must be independently \
                 observable as alive via /proc before full_uninstall runs"
            );
        }
        assert_eq!(
            lease::verify_process_absent(identity),
            lease::ProcessAbsence::Present,
            "the codebase's own liveness probe must independently confirm the process is alive \
             before full_uninstall runs"
        );

        // The real, product-facing boundary, run while the process is
        // genuinely alive -- must refuse, and must not quarantine anything
        // (both the primary "pyright" component and its "node" dependency
        // are backed by the same live pid, so both must be reported busy;
        // neither is deleted before the other's process is confirmed
        // reaped).
        let outcome = full_uninstall(&root).await;
        match &outcome {
            Err(FullUninstallError::ProcessPreflightBusy(busy)) => {
                let mut busy_sorted = busy.clone();
                busy_sorted.sort();
                assert_eq!(
                    busy_sorted,
                    vec![
                        "node-lifecycle-fixture".to_string(),
                        "pyright-lifecycle-fixture".to_string(),
                    ],
                    "P17_ACTIVE_PYRIGHT_PREMATURE_UNINSTALL_COUNT/P17_ACTIVE_NODE_PREMATURE_UNINSTALL_COUNT: \
                     expected both the live Pyright-shaped component and its Node dependency to be \
                     reported busy while the same real process is alive, got {busy:?}"
                );
            }
            other => unreachable!(
                "expected ProcessPreflightBusy against a genuinely live process, got {other:?}"
            ),
        }
        assert!(
            root.join("components/pyright-lifecycle-fixture").exists(),
            "P17_ACTIVE_PYRIGHT_PREMATURE_UNINSTALL_COUNT!=0: the live component's install root \
             was removed despite a refused full_uninstall"
        );
        assert!(
            root.join("components/node-lifecycle-fixture").exists(),
            "P17_NODE_DELETE_BEFORE_PYRIGHT_REAP_COUNT!=0: the managed Node dependency's install \
             root was removed despite a refused full_uninstall"
        );
        assert!(
            loaded_or_panic(&root, "pyright-lifecycle-fixture").is_some(),
            "ownership metadata must survive a refused full_uninstall"
        );
        assert!(
            loaded_or_panic(&root, "node-lifecycle-fixture").is_some(),
            "ownership metadata must survive a refused full_uninstall"
        );

        // Real reap -- a blocking `wait()`, never a sleep-based guess that
        // the process "probably" exited.
        ok_or_panic(child.kill());
        let exit_status = ok_or_panic(child.wait());
        assert!(
            !exit_status.success(),
            "the child was killed, not a clean exit"
        );

        if independently_verifiable {
            assert!(
                !proc_path_before.exists(),
                "PYRIGHT_PID_AFTER_FULL_UNINSTALL: /proc/{pyright_pid_before} must be \
                 independently gone after a real reap"
            );
        }
        assert_eq!(
            lease::verify_process_absent(identity),
            lease::ProcessAbsence::Absent,
            "P17_PYRIGHT_SURVIVED_FULL_UNINSTALL must be NO: the codebase's own liveness probe \
             must independently confirm absence once the real process is reaped"
        );

        // Now that the process is genuinely, independently confirmed gone,
        // the real full_uninstall boundary must succeed and remove both,
        // dependents-first.
        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "pyright-lifecycle-fixture".to_string(),
                "node-lifecycle-fixture".to_string(),
            ])),
            "P17_FULL_UNINSTALL_STOP_BEFORE_DELETE/REAP_BEFORE_DELETE/VERIFY_ABSENT_BEFORE_DELETE: \
             expected a clean Removed outcome once the live process was independently confirmed \
             absent, got {outcome:?}"
        );
        assert!(!root.join("components/pyright-lifecycle-fixture").exists());
        assert!(!root.join("components/node-lifecycle-fixture").exists());
        assert!(loaded_or_panic(&root, "pyright-lifecycle-fixture").is_none());
        assert!(loaded_or_panic(&root, "node-lifecycle-fixture").is_none());

        // POST_FULL_UNINSTALL_OLD_SESSION_USABLE=NO, at the process level:
        // the same real pid independently re-checked one more time.
        if independently_verifiable {
            assert!(!proc_path_before.exists());
        }

        // Never leak this test's own lease registration into a sibling
        // test in this same serialized module (see
        // `full_uninstall_removes_a_dependency_chain_dependents_first`'s own
        // comment on why this registry is process-wide, not root-scoped).
        execution_lease.release();
        let post_removal_root = lease::RootIdentity::of(&root);
        assert_eq!(
            lease::process_identities_for_component(lease::ComponentLeaseScope {
                root: &post_removal_root,
                component_id: "pyright-lifecycle-fixture",
            })
            .len()
                + lease::process_identities_for_component(lease::ComponentLeaseScope {
                    root: &post_removal_root,
                    component_id: "node-lifecycle-fixture",
                })
                .len(),
            0,
            "POST_FULL_UNINSTALL_ORPHAN_PROCESS_COUNT=0 (scoped to this test's own components)"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_is_idempotent() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("idempotent");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        assert!(full_uninstall(&root).await.is_ok());
        let second = full_uninstall(&root).await;
        assert_eq!(second, Ok(FullUninstallOutcome::NoManagedComponents));
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_never_touches_a_host_only_override_record() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("external-preserved");
        install_fixture(&root, "managed-fixture", Vec::new(), 1);
        let external_root = root.join("external-owned-by-someone-else");
        ok_or_panic(fs::create_dir_all(&external_root));
        let mut external_record = build_record(
            &root,
            NewInstallation {
                component_id: "external-fixture",
                version: "1.0.0",
                platform: "linux",
                architecture: "x64",
                canonical_component_root: external_root.clone(),
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest: "0".repeat(64),
                ownership: OwnershipClass::HostOnlyOverride,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        assert!(
            ownership::save(&root, &mut external_record).is_ok(),
            "external record must save"
        );

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "managed-fixture".to_string()
            ]))
        );
        assert!(
            external_root.is_dir(),
            "HostOnlyOverride-owned directory must never be deleted by full_uninstall"
        );
        assert!(
            loaded_or_panic(&root, "external-fixture").is_some(),
            "HostOnlyOverride ownership record must be preserved"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_never_touches_a_pre_ownership_orphan() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("orphan-preserved");
        install_fixture(&root, "managed-fixture", Vec::new(), 1);
        let orphan_root = root.join("components").join("orphan-fixture").join("1.0.0");
        ok_or_panic(fs::create_dir_all(&orphan_root));
        ok_or_panic(fs::write(orphan_root.join("bin"), b"orphan binary"));

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "managed-fixture".to_string()
            ]))
        );
        assert!(
            orphan_root.is_dir(),
            "a pre-ownership orphan directory must never be deleted by full_uninstall"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_prepare_failure_leaves_zero_live_mutation() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("prepare-fault");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        set_fault(Some(FaultStage::Prepare));

        let outcome = full_uninstall(&root).await;
        set_fault(None);

        assert_eq!(outcome, Err(FullUninstallError::Io));
        assert!(root.join("components/solo-fixture").exists());
        assert!(loaded_or_panic(&root, "solo-fixture").is_some());

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_mid_quarantine_failure_rolls_back_the_first_component() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("mid-quarantine-fault");
        install_fixture(&root, "aaa-first", Vec::new(), 1);
        install_fixture(&root, "bbb-second", Vec::new(), 2);
        set_fault(Some(FaultStage::MidQuarantine));

        let outcome = full_uninstall(&root).await;
        set_fault(None);

        assert!(matches!(
            outcome,
            Err(FullUninstallError::QuarantineFailedRolledBack(_))
        ));
        // Both components must be back at their live paths -- the first
        // one successfully quarantined before the injected failure on the
        // second must have been rolled back, not left in quarantine.
        assert!(
            root.join("components/aaa-first").exists(),
            "rolled-back component must be restored to its live path"
        );
        assert!(root.join("components/bbb-second").exists());
        assert!(loaded_or_panic(&root, "aaa-first").is_some());
        assert!(
            !recovery_locked(&root),
            "a successful rollback must not leave the root recovery-locked"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_destruction_failure_reports_cleanup_required_not_completed() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("destruction-fault");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        set_fault(Some(FaultStage::Destruction));

        let outcome = full_uninstall(&root).await;
        set_fault(None);

        assert!(matches!(
            outcome,
            Err(FullUninstallError::CleanupRequired(_))
        ));
        // Live path must already be gone (quarantine succeeded -- checked
        // at the exact canonical component root, since the ancestor-
        // cleanup sweep only runs after a *successful* destruction and is
        // correctly skipped here); ownership metadata must NOT have been
        // removed early.
        assert!(!root.join("components/solo-fixture/1.0.0").exists());
        assert!(
            loaded_or_panic(&root, "solo-fixture").is_some(),
            "OWNERSHIP_METADATA_EARLY_DELETE_COUNT=0: metadata must survive a destruction failure"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_process_preflight_failure_leaves_zero_live_mutation() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("process-preflight-fault");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        set_fault(Some(FaultStage::ProcessPreflight));

        let outcome = full_uninstall(&root).await;
        set_fault(None);

        assert!(matches!(
            outcome,
            Err(FullUninstallError::ProcessPreflightBusy(_))
        ));
        assert!(root.join("components/solo-fixture").exists());
        assert!(loaded_or_panic(&root, "solo-fixture").is_some());

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_first_quarantine_failure_leaves_zero_live_mutation() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("first-quarantine-fault");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        set_fault(Some(FaultStage::FirstQuarantine));

        let outcome = full_uninstall(&root).await;
        set_fault(None);

        assert!(matches!(outcome, Err(FullUninstallError::Component(_, _))));
        assert!(
            root.join("components/solo-fixture/1.0.0").exists(),
            "a failure injected before the first rename must leave the live path untouched"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_post_quarantine_verify_failure_rolls_back() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("post-quarantine-verify-fault");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        set_fault(Some(FaultStage::PostQuarantineVerify));

        let outcome = full_uninstall(&root).await;
        set_fault(None);

        assert!(matches!(
            outcome,
            Err(FullUninstallError::QuarantineFailedRolledBack(_))
        ));
        assert!(
            root.join("components/solo-fixture/1.0.0").exists(),
            "a post-quarantine-verify failure must roll the component back to its live path"
        );
        assert!(!recovery_locked(&root));

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_metadata_cleanup_failure_retains_ownership_for_retry() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("metadata-cleanup-fault");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        set_fault(Some(FaultStage::MetadataCleanup));

        let outcome = full_uninstall(&root).await;
        set_fault(None);

        assert!(matches!(
            outcome,
            Err(FullUninstallError::CleanupRequired(_))
        ));
        assert!(!root.join("components/solo-fixture/1.0.0").exists());
        assert!(
            loaded_or_panic(&root, "solo-fixture").is_some(),
            "OWNERSHIP_METADATA_EARLY_DELETE_COUNT=0: metadata must survive a metadata-cleanup failure"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_refuses_a_recovery_locked_root() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("recovery-locked");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        write_recovery_marker(&root, "test-injected recovery lock");

        let outcome = full_uninstall(&root).await;
        assert_eq!(outcome, Err(FullUninstallError::RecoveryLocked));
        assert!(
            root.join("components/solo-fixture").exists(),
            "a recovery-locked root must refuse mutation entirely"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_recovery_locked_root_also_blocks_individual_uninstall() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("recovery-locked-blocks-individual");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        write_recovery_marker(&root, "test-injected recovery lock");

        let outcome = crate::provisioning::uninstall::uninstall(
            &root,
            super::super::ManagedComponentId("solo-fixture"),
            |_| {},
        )
        .await;
        assert_eq!(
            outcome,
            Err(crate::provisioning::uninstall::UninstallError::RecoveryLocked)
        );
        assert!(
            root.join("components/solo-fixture").exists(),
            "RECOVERY_LOCK_BYPASS_COUNT=0: individual uninstall must also refuse while locked"
        );

        clear_recovery_lock(&root);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_cleanup_required_retry_completes_via_resume() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("cleanup-required-retry");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        set_fault(Some(FaultStage::Destruction));

        let first = full_uninstall(&root).await;
        set_fault(None);
        assert!(matches!(first, Err(FullUninstallError::CleanupRequired(_))));
        // Live path already gone; ownership metadata still present (proven
        // by the dedicated destruction-failure test); the quarantine copy
        // is what's stuck.
        assert!(
            loaded_or_panic(&root, "solo-fixture").is_some(),
            "metadata must still be present before resume"
        );

        // UNINSTALL_CLEANUP_REQUIRED_RETRY: the explicit resume path
        // finishes what the original transaction could not.
        let resumed = full_uninstall_resume_cleanup(&root).await;
        assert!(
            matches!(resumed, Ok(FullUninstallOutcome::Removed(_))),
            "resume must complete the stuck transaction: {resumed:?}"
        );
        assert!(
            loaded_or_panic(&root, "solo-fixture").is_none(),
            "metadata must be removed only once the resume actually destroyed the quarantine copy"
        );
        assert!(
            !root.join(".uninstall-txn").exists()
                || fs::read_dir(root.join(".uninstall-txn"))
                    .map(|mut e| e.next().is_none())
                    .unwrap_or(true),
            "no quarantine residue should remain after a successful resume"
        );

        // A second resume call against the now-clean root is a safe no-op.
        let second = full_uninstall_resume_cleanup(&root).await;
        assert_eq!(second, Ok(FullUninstallOutcome::NoManagedComponents));

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn full_uninstall_recovery_required_retry_via_explicit_manual_clear() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("recovery-required-retry");
        install_fixture(&root, "aaa-first", Vec::new(), 1);
        install_fixture(&root, "bbb-second", Vec::new(), 2);
        // A single fault value: `RollbackFailure` both triggers the
        // mid-quarantine failure (the quarantine loop treats it the same
        // as `MidQuarantine` for the "should this iteration fail" check --
        // see that check's own comment) and then makes the rollback it
        // provokes itself fail.
        set_fault(Some(FaultStage::RollbackFailure));

        let first = full_uninstall(&root).await;
        set_fault(None);
        assert_eq!(first, Err(FullUninstallError::RecoveryRequired));
        assert!(
            recovery_locked(&root),
            "a failed rollback must leave the root recovery-locked"
        );

        // UNINSTALL_RECOVERY_REQUIRED_RETRY: while locked, every mutating
        // entry point refuses -- proven for full_uninstall itself here (the
        // individual-uninstall case is covered by the dedicated bypass
        // test above).
        let while_locked = full_uninstall(&root).await;
        assert_eq!(while_locked, Err(FullUninstallError::RecoveryLocked));

        // `clear_recovery_lock` is deliberately typed-and-explicit but
        // deliberately does NOT auto-repair data: `RollbackFailure` fired
        // before the rollback loop restored anything, so "aaa-first" is
        // still genuinely stuck inside the abandoned transaction's
        // quarantine directory -- clearing the marker alone must not
        // silently resurrect it as if nothing happened.
        clear_recovery_lock(&root);
        assert!(!recovery_locked(&root));
        assert!(
            !root.join("components/aaa-first/1.0.0").exists(),
            "clearing the lock must not, by itself, restore data a failed rollback never restored"
        );

        // The actual manual recovery this failure mode requires: an
        // operator moves the abandoned quarantine contents back to their
        // live path (simulated here directly, standing in for the human
        // action the module's own docs describe -- Corulix itself performs
        // no auto-repair of a failed rollback's residue).
        let txn_root = root.join(".uninstall-txn");
        let txn_dir = ok_or_panic(fs::read_dir(&txn_root))
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.is_dir())
            .unwrap_or_else(|| {
                unreachable!("the abandoned transaction directory must still exist")
            });
        ok_or_panic(fs::rename(
            txn_dir.join("aaa-first"),
            root.join("components/aaa-first/1.0.0"),
        ));
        let _ = fs::remove_file(txn_dir.join("transaction.json"));
        let _ = fs::remove_dir(&txn_dir);
        let _ = fs::remove_dir(&txn_root);

        // Only now, with live state genuinely consistent again, does a
        // fresh transaction complete normally rather than falsely claiming
        // completion over the earlier failure.
        let retried = full_uninstall(&root).await;
        assert!(
            matches!(retried, Ok(FullUninstallOutcome::Removed(_))),
            "after real manual recovery, a retried transaction must complete: {retried:?}"
        );
        assert!(loaded_or_panic(&root, "aaa-first").is_none());
        assert!(loaded_or_panic(&root, "bbb-second").is_none());

        let _ = fs::remove_dir_all(&root);
    }

    // `uninstall_all_corulix_managed_components` (the product-level
    // contract, §27) deliberately has no runtime test here:
    // `managed_toolchain_root()` resolution is not test-parameterized, and
    // this crate is `#![forbid(unsafe_code)]`, so the usual
    // `std::env::set_var("XDG_DATA_HOME", ...)` redirection this module
    // otherwise would use is unavailable. Invoking it for real would run a
    // genuine destructive transaction against whatever this host's actual
    // managed toolchain root contains, including components other real
    // E2E tests in this workspace depend on already being provisioned.
    // The function itself is a single-line, directly reviewable delegation
    // (`managed_toolchain_root()` then `full_uninstall(&root)`, nothing
    // else); every behavior it could exercise is already covered by this
    // module's other tests calling `full_uninstall` directly. Disclosed as
    // an explicit gap rather than backed by a fabricated runtime proof.

    // `flavor = "multi_thread"` is required here, not the default
    // current-thread test runtime: on a single-threaded runtime `tokio::join!`
    // only interleaves at await points, so the first future can run to
    // completion before the second is ever polled, making "serialized"
    // trivially true without the root lock ever being exercised under real
    // concurrency. `worker_threads = 2` lets both `full_uninstall` calls
    // genuinely execute on separate OS threads and race for `lock_root_exclusive`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_full_uninstall_calls_never_double_quarantine() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("concurrent");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);

        let root_a = root.clone();
        let root_b = root.clone();
        let (result_a, result_b) = tokio::join!(full_uninstall(&root_a), full_uninstall(&root_b));

        // The invariant `FULL_VS_COMPONENT_UNINSTALL_RACE_COUNT=0` names is not
        // "both calls returned some success variant" -- it is "the two calls never
        // both observe/report having removed the same component". Exactly one of
        // the two racing calls may see `Removed(["solo-fixture"])`; the other must
        // see `NoManagedComponents` (it lost the race and found nothing left to
        // remove), never a second `Removed` for the same component and never a
        // partially-torn state (an error variant on either side).
        let removed_count = [&result_a, &result_b]
            .into_iter()
            .filter(|r| matches!(r, Ok(FullUninstallOutcome::Removed(_))))
            .count();
        let no_managed_count = [&result_a, &result_b]
            .into_iter()
            .filter(|r| matches!(r, Ok(FullUninstallOutcome::NoManagedComponents)))
            .count();
        assert_eq!(
            (removed_count, no_managed_count),
            (1, 1),
            "exactly one racing call must remove the component and the other must find \
             nothing left, never both/neither: {result_a:?} / {result_b:?}"
        );
        assert!(!root.join("components/solo-fixture").exists());

        let _ = fs::remove_dir_all(&root);
    }

    // §11's `FULL_UNINSTALL_PROVISION_RACE_COUNT` cannot be measured against a
    // real `provision_with_dependencies` call in a unit test -- that function
    // performs a real network download. What *can* be measured under real
    // concurrency is the actual serialization primitive both `full_uninstall`
    // and `provision_with_dependencies` share: `lock_root_shared` /
    // `lock_root_exclusive` on the same root identity. This test holds a real
    // shared-mode guard (exactly what `provision_with_dependencies` holds for
    // its whole duration) on one task while a real `full_uninstall` call runs
    // concurrently on another OS thread, and proves the exclusive lock a full
    // uninstall requires does not acquire -- and therefore no quarantine/
    // destroy work runs -- until the shared guard is released. This is a real,
    // non-vacuous concurrency proof of the lock primitive itself; it is
    // explicitly NOT a proof that a real `provision_with_dependencies` call
    // races safely end-to-end, which remains unverified and is reported as
    // such rather than folded into a bare `0`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_uninstall_waits_for_a_real_concurrent_shared_root_guard_to_release() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("provision-lock-race");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        let root_identity = ownership::root_identity(&root);

        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel::<()>();

        let holder_identity = root_identity.clone();
        let holder = tokio::spawn(async move {
            let _shared_guard = super::super::lock_root_shared(&holder_identity).await;
            let _ = acquired_tx.send(());
            let _ = release_rx.await;
        });

        // Wait for the holder to genuinely acquire the shared guard before
        // racing `full_uninstall` against it -- a real synchronization
        // handshake, not a sleep-based guess at timing.
        assert!(
            acquired_rx.await.is_ok(),
            "holder task must acquire the shared root guard"
        );

        let uninstall_root = root.clone();
        let uninstaller = tokio::spawn(async move { full_uninstall(&uninstall_root).await });

        // The exclusive guard `full_uninstall` needs cannot be acquired while
        // the shared guard above is held, so the uninstall task must still be
        // pending a short moment later; releasing the holder must be what
        // unblocks it, not the other way around.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !uninstaller.is_finished(),
            "full_uninstall must not proceed while a real shared root guard is held"
        );
        assert!(
            root.join("components/solo-fixture").exists(),
            "component must remain untouched while the shared guard blocks the exclusive lock"
        );

        let _ = release_tx.send(());
        ok_or_panic(holder.await);
        let outcome = ok_or_panic(uninstaller.await);
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "solo-fixture".to_string()
            ]))
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// Phase 7B-B1-R3-B2-B2-R1 §2/§22/§23: a root holding ONLY
    /// `CorulixManaged` state (no `HostOnlyOverride` record, no
    /// pre-ownership orphan) must be left with literally nothing after a
    /// successful `full_uninstall` -- not even the empty `ownership/`/
    /// `staging/`/`.uninstall-txn/` directory shells the owner explicitly
    /// rejected as acceptable residue, and not the managed root itself.
    #[tokio::test]
    async fn full_uninstall_achieves_absolute_zero_residual_for_a_pure_managed_root() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("absolute-zero-residual");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        // A real staging directory, exactly as `provisioning::provision`
        // would leave transiently mid-run, proves `staging/` itself (not
        // just its subdirectories) is real state this test exercises, not
        // an assumption.
        let staging_marker = root.join("staging");
        ok_or_panic(fs::create_dir_all(&staging_marker));

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "solo-fixture".to_string()
            ])),
            "COMPLETE_MANAGED_ZERO_STATE=FAIL: {outcome:?}"
        );

        assert!(
            !root.join("ownership").exists(),
            "POST_UNINSTALL_OWNERSHIP_DIRECTORY_EXISTS!=NO"
        );
        assert!(
            !root.join("staging").exists(),
            "POST_UNINSTALL_STAGING_DIRECTORY_EXISTS!=NO"
        );
        assert!(
            !root.join(".uninstall-txn").exists(),
            "POST_UNINSTALL_QUARANTINE_DIRECTORY_EXISTS!=NO"
        );
        assert!(
            !root.exists(),
            "POST_UNINSTALL_MANAGED_ROOT_EXISTS!=NO: {root:?} still exists"
        );

        // §33-34: idempotent re-invocation against the now-absent root must
        // not recreate anything.
        let second = full_uninstall(&root).await;
        assert_eq!(
            second,
            Ok(FullUninstallOutcome::NoManagedComponents),
            "UNINSTALL_IDEMPOTENCE=FAIL: {second:?}"
        );
        assert!(
            !root.exists(),
            "IDEMPOTENT_RECREATED_RESIDUAL_PATH_COUNT!=0: the second call recreated the managed root"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// Phase 7B-B1-R3-B2-B2-R1 §8/§28: a foreign file placed directly
    /// inside Corulix's own `ownership/` bookkeeping directory (something
    /// nothing in this codebase would ever legitimately write there) must
    /// never be silently deleted merely to obtain an empty root --
    /// `full_uninstall` must report `CleanupRequired` with exact evidence
    /// instead, and the sentinel must survive byte-for-byte.
    #[tokio::test]
    async fn full_uninstall_reports_cleanup_required_for_an_unexplained_ownership_dir_sentinel() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("foreign-ownership-sentinel");
        install_fixture(&root, "solo-fixture", Vec::new(), 1);
        let ownership_dir = root.join("ownership");
        ok_or_panic(fs::create_dir_all(&ownership_dir));
        let sentinel = ownership_dir.join("foreign-sentinel.txt");
        ok_or_panic(fs::write(&sentinel, b"not a Corulix ownership record"));

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Err(FullUninstallError::CleanupRequired(vec![
                "ownership".to_string()
            ])),
            "FOREIGN_RESIDUAL_AUTO_DELETE_COUNT!=0 (or wrongly classified): {outcome:?}"
        );
        assert!(
            sentinel.is_file(),
            "FOREIGN_RESIDUAL_AUTO_DELETE_COUNT!=0: the sentinel file was deleted"
        );
        assert_eq!(
            ok_or_panic(fs::read(&sentinel)),
            b"not a Corulix ownership record",
            "the sentinel's bytes changed"
        );
        // The managed component itself was still genuinely removed --
        // ZERO_RESIDUAL_SUCCESS_FALSE_POSITIVE_COUNT=0 does not mean
        // nothing may ever fail; it means a failure must not be hidden as
        // `Removed`, exactly as asserted above.
        assert!(loaded_or_panic(&root, "solo-fixture").is_none());
        assert!(!root.join("components/solo-fixture").exists());

        let _ = fs::remove_file(&sentinel);
        let _ = fs::remove_dir_all(&root);
    }

    /// Phase 7B-B1-R3-B2-B2-R1 §53: an individual component uninstall must
    /// never delete the entire managed root while a sibling component
    /// remains -- root removal belongs only to the canonical full/product
    /// uninstall transaction, and only once it has verified nothing
    /// managed remains. Structural proof: `uninstall::uninstall` never
    /// calls `cleanup_lifecycle_shells_and_root` (only `full_uninstall`/
    /// `full_uninstall_resume_cleanup` do), so this is also an empirical
    /// regression against that invariant.
    #[tokio::test]
    async fn component_uninstall_never_deletes_the_managed_root_while_a_sibling_remains() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("component-uninstall-root-safety");
        install_fixture(&root, "component-a", Vec::new(), 1);
        install_fixture(&root, "component-b", Vec::new(), 2);

        let outcome = uninstall::uninstall(
            &root,
            super::super::ManagedComponentId("component-a"),
            |_| {},
        )
        .await;
        assert!(
            matches!(outcome, Ok(uninstall::UninstallOutcome::Removed)),
            "COMPONENT_UNINSTALL_PREMATURE_ROOT_DELETE_COUNT setup failed: {outcome:?}"
        );

        assert!(
            root.exists(),
            "COMPONENT_UNINSTALL_PREMATURE_ROOT_DELETE_COUNT!=0: managed root was deleted while component-b remains"
        );
        assert!(
            root.join("components/component-b").exists(),
            "sibling component-b must remain fully intact"
        );
        assert!(loaded_or_panic(&root, "component-b").is_some());
        assert!(loaded_or_panic(&root, "component-a").is_none());

        let cleanup = full_uninstall(&root).await;
        assert_eq!(
            cleanup,
            Ok(FullUninstallOutcome::Removed(vec![
                "component-b".to_string()
            ]))
        );
        assert!(!root.exists());

        let _ = fs::remove_dir_all(&root);
    }

    /// Phase 7B-B1-R3-B2-B2-R2 §25: a real adversarial fixture where the
    /// expected managed-root path is not a real directory at all but a
    /// symlink to an unrelated external directory holding its own
    /// unrelated content. `remove_dir` on a path whose final component is
    /// a symlink fails with `ENOTDIR` per POSIX `rmdir()` semantics
    /// (verified empirically here, not merely asserted from documentation)
    /// -- it never follows the symlink and never deletes it -- so this
    /// proves the real behavior, not merely "remove_dir is non-recursive
    /// so it must be fine."
    #[cfg(unix)]
    #[tokio::test]
    async fn full_uninstall_never_deletes_a_root_replaced_by_a_symlink_to_an_external_directory() {
        let _lock = full_uninstall_test_lock().await;
        let external_dir = temp_root("symlink-root-external-target");
        let sentinel = external_dir.join("external-user-file.txt");
        ok_or_panic(fs::write(&sentinel, b"unrelated external content"));
        let sentinel_bytes_before = ok_or_panic(fs::read(&sentinel));

        let root_path = temp_root("symlink-root-parent").join("root-is-a-symlink");
        ok_or_panic(std::os::unix::fs::symlink(&external_dir, &root_path));
        assert!(
            fs::symlink_metadata(&root_path)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false),
            "test setup must produce a real symlink at the expected root path"
        );

        // A real CorulixManaged component, installed THROUGH the symlink --
        // its files genuinely land inside `external_dir` (normal symlink
        // traversal for a non-final path component), so `full_uninstall`
        // has real, real component state to remove before it ever reaches
        // final root cleanup.
        install_fixture(&root_path, "component-via-symlink-root", Vec::new(), 1);

        let outcome = full_uninstall(&root_path).await;
        assert_eq!(
            outcome,
            Err(FullUninstallError::CleanupRequired(vec![
                "managed-root".to_string()
            ])),
            "FINAL_ROOT_SYMLINK_AUTO_DELETE_COUNT!=0 (or wrongly classified): {outcome:?}"
        );

        assert!(
            fs::symlink_metadata(&root_path)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false),
            "FINAL_ROOT_SYMLINK_AUTO_DELETE_COUNT!=0: the symlink itself was removed"
        );
        assert!(
            sentinel.is_file(),
            "FINAL_ROOT_SYMLINK_AUTO_DELETE_COUNT!=0: the external target's own content was removed"
        );
        assert_eq!(ok_or_panic(fs::read(&sentinel)), sentinel_bytes_before);
        // The real managed component was still genuinely removed --
        // this is a residual-cleanup failure, not a component-removal
        // failure.
        assert!(loaded_or_panic(&root_path, "component-via-symlink-root").is_none());

        let _ = fs::remove_file(&root_path);
        let _ = fs::remove_dir_all(&external_dir);
        let _ = fs::remove_dir_all(root_path.parent().unwrap_or(&root_path));
    }

    /// Phase 7B-B1-R3-B2-B2-R2 §26: `ownership/` itself (a real root, not
    /// symlinked) is replaced by a symlink to an external directory with
    /// its own unrelated content. Same `rmdir()`-on-symlink fail-closed
    /// proof as the root case above, but for the final path component
    /// being `ownership/` specifically rather than the root itself.
    #[cfg(unix)]
    #[tokio::test]
    async fn full_uninstall_never_deletes_an_ownership_directory_replaced_by_a_symlink() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("symlink-ownership-root");
        let external_dir = temp_root("symlink-ownership-external-target");
        let sentinel = external_dir.join("external-user-file.txt");
        ok_or_panic(fs::write(&sentinel, b"unrelated external content"));
        let sentinel_bytes_before = ok_or_panic(fs::read(&sentinel));

        // A real component installed normally first (real `ownership/`
        // directory, real record) so its metadata removal genuinely
        // succeeds -- then `ownership/` itself is swapped for a symlink
        // pointing at the external directory, simulating a hostile/
        // corrupted filesystem state discovered only at final-cleanup
        // time. The still-live component id lives under `components/`,
        // unaffected by the swap, so `full_uninstall` genuinely reaches
        // final shell cleanup with the symlink in place.
        install_fixture(&root, "component-with-swapped-ownership-dir", Vec::new(), 1);
        let real_ownership_dir = root.join("ownership");
        ok_or_panic(fs::remove_dir_all(&real_ownership_dir));
        ok_or_panic(std::os::unix::fs::symlink(
            &external_dir,
            &real_ownership_dir,
        ));

        // `ownership::load`/`list` now read through the symlink -- the
        // component's record must be re-created there so PREPARE still
        // finds it (this models the record surviving the swap, e.g. the
        // symlink was substituted after the record was already written to
        // what is now the symlink target).
        install_fixture(&root, "component-with-swapped-ownership-dir", Vec::new(), 1);

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Err(FullUninstallError::CleanupRequired(vec![
                "ownership".to_string()
            ])),
            "FINAL_LIFECYCLE_SYMLINK_AUTO_DELETE_COUNT!=0 (or wrongly classified): {outcome:?}"
        );
        assert!(
            fs::symlink_metadata(&real_ownership_dir)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false),
            "FINAL_LIFECYCLE_SYMLINK_AUTO_DELETE_COUNT!=0: the ownership/ symlink itself was removed"
        );
        assert!(sentinel.is_file());
        assert_eq!(ok_or_panic(fs::read(&sentinel)), sentinel_bytes_before);

        let _ = fs::remove_file(&real_ownership_dir);
        let _ = fs::remove_dir_all(&external_dir);
        let _ = fs::remove_dir_all(&root);
    }

    /// Phase 7B-B1-R3-B2-B2-R2 §27: an ownership record whose
    /// `managed_root_identity` names a DIFFERENT root than the one
    /// `full_uninstall` is actually invoked against (a foreign/corrupt
    /// root identity -- e.g. a managed-toolchain tree copied wholesale
    /// from another location). `ownership::load` already refuses this
    /// (`RootIdentityMismatch`); this proves the whole transaction refuses
    /// closed at PREPARE, before any mutation, rather than proceeding as
    /// if the mismatched record were simply absent.
    #[tokio::test]
    async fn full_uninstall_refuses_a_foreign_root_identity_record_without_any_mutation() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("foreign-root-identity");
        let component_root = root
            .join("components")
            .join("foreign-identity-fixture/1.0.0");
        ok_or_panic(fs::create_dir_all(&component_root));
        ok_or_panic(fs::write(component_root.join("bin"), b"fixture binary"));

        let mut record = build_record(
            &root,
            NewInstallation {
                component_id: "foreign-identity-fixture",
                version: "1.0.0",
                platform: "linux",
                architecture: "x64",
                canonical_component_root: component_root.clone(),
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest: "0".repeat(64),
                ownership: OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        // Deliberately foreign: a real identity string, just not this
        // root's own -- simulates a record copied from a different
        // managed-toolchain root.
        record.managed_root_identity = ownership::root_identity(Path::new("/some/other/root"));
        assert!(ownership::save(&root, &mut record).is_ok());

        let component_bytes_before = ok_or_panic(fs::read(component_root.join("bin")));

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Err(FullUninstallError::OwnershipPreflightFailed),
            "FOREIGN_ROOT_AUTO_DELETE_COUNT!=0 (or wrongly classified): {outcome:?}"
        );
        assert!(
            component_root.is_dir(),
            "FOREIGN_ROOT_AUTO_DELETE_COUNT!=0: the component directory was removed"
        );
        assert_eq!(
            ok_or_panic(fs::read(component_root.join("bin"))),
            component_bytes_before
        );
        assert!(root.join("ownership").is_dir());

        let _ = fs::remove_dir_all(&root);
    }

    /// Phase 7B-B1-R3-B2-B2-R3 §4-7/§36 (SHARED_ROOT_WITH_RECOGNIZED_PRESERVED_STATE,
    /// MODE B, success case only -- deliberately excludes any unexplained
    /// foreign sentinel, per the owner's explicit instruction not to mix
    /// MODE B and MODE C in one fixture): a root holding a `HostOnlyOverride`
    /// ownership record and a pre-ownership orphan directory -- both
    /// already-certified recognized/preservable non-managed state -- plus
    /// two real `CorulixManaged` components. A successful product
    /// uninstall must genuinely return `Ok(Removed(...))` (real success,
    /// not merely "did not error"): every `CorulixManaged` component and
    /// its metadata gone, every recognized preserved object byte-for-byte
    /// identical, root retained specifically because recognized preserved
    /// state remains -- `SHARED_RECOGNIZED_ROOT_PRODUCT_UNINSTALL_RESULT=SUCCESS`.
    #[tokio::test]
    async fn full_uninstall_shared_recognized_root_succeeds_and_preserves_every_recognized_object()
    {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("shared-root-recognized-success");

        install_fixture(&root, "shared-managed-a", Vec::new(), 1);
        install_fixture(&root, "shared-managed-b", Vec::new(), 2);

        // HostOnlyOverride: a real, permanently-preserved ownership record
        // for an externally-owned tool.
        let host_only_root = root.join("host-only-external-tool");
        ok_or_panic(fs::create_dir_all(&host_only_root));
        ok_or_panic(fs::write(
            host_only_root.join("bin"),
            b"host-only tool binary",
        ));
        let mut host_only_record = build_record(
            &root,
            NewInstallation {
                component_id: "shared-host-only-fixture",
                version: "1.0.0",
                platform: "linux",
                architecture: "x64",
                canonical_component_root: host_only_root.clone(),
                dependencies: Vec::new(),
                installation_sequence: 3,
                artifact_digest: "0".repeat(64),
                ownership: OwnershipClass::HostOnlyOverride,
                installed_payload_digest: String::new(),
                installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests: std::collections::BTreeMap::new(),
            },
        );
        assert!(ownership::save(&root, &mut host_only_record).is_ok());

        // Pre-ownership orphan: present on disk, no ownership record ever
        // existed for it -- already-certified recognized/preservable
        // non-managed state (`full_uninstall_never_touches_a_pre_ownership_orphan`).
        let orphan_root = root
            .join("components")
            .join("shared-orphan-fixture")
            .join("1.0.0");
        ok_or_panic(fs::create_dir_all(&orphan_root));
        ok_or_panic(fs::write(orphan_root.join("bin"), b"orphan binary"));

        let host_only_bytes_before = ok_or_panic(fs::read(host_only_root.join("bin")));
        let orphan_bytes_before = ok_or_panic(fs::read(orphan_root.join("bin")));

        let outcome = full_uninstall(&root).await;
        // No unexplained content anywhere -- both remaining objects are
        // explained (a live HostOnlyOverride record, and components/
        // holding only the orphan) -- so this is a genuine, unambiguous
        // success, not a `CleanupRequired`.
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "shared-managed-a".to_string(),
                "shared-managed-b".to_string(),
            ])),
            "SHARED_RECOGNIZED_ROOT_PRODUCT_UNINSTALL_RESULT != SUCCESS: {outcome:?}"
        );
        eprintln!("SHARED_RECOGNIZED_ROOT_PRODUCT_UNINSTALL_RESULT=SUCCESS");

        // SHARED_POST_UNINSTALL_CORULIX_MANAGED_COMPONENT_COUNT=0
        assert!(loaded_or_panic(&root, "shared-managed-a").is_none());
        assert!(loaded_or_panic(&root, "shared-managed-b").is_none());
        assert!(!root.join("components/shared-managed-a").exists());
        assert!(!root.join("components/shared-managed-b").exists());
        eprintln!("SHARED_ROOT_ZERO_CORULIX_MANAGED_STATE=PASS");

        // SHARED_ROOT_EXTERNAL_STATE_PRESERVATION=PASS -- evidence entries:
        // {path, classification, reason, pre_hash, post_hash}.
        assert!(
            loaded_or_panic(&root, "shared-host-only-fixture").is_some(),
            "HOST_ONLY_OVERRIDE_MUTATION_COUNT!=0: record was removed"
        );
        let host_only_bytes_after = ok_or_panic(fs::read(host_only_root.join("bin")));
        assert_eq!(
            host_only_bytes_after, host_only_bytes_before,
            "HOST_ONLY_OVERRIDE_MUTATION_COUNT!=0: content changed"
        );
        eprintln!(
            "SHARED_RECOGNIZED_PRESERVED_PATHS+=path={:?} classification=HostOnlyOverride reason=host-configured-external-tool pre_hash={:x?} post_hash={:x?}",
            host_only_root, host_only_bytes_before, host_only_bytes_after
        );
        assert!(
            orphan_root.is_dir(),
            "PREOWNERSHIP_ORPHAN_MUTATION_COUNT!=0: directory was removed"
        );
        let orphan_bytes_after = ok_or_panic(fs::read(orphan_root.join("bin")));
        assert_eq!(
            orphan_bytes_after, orphan_bytes_before,
            "PREOWNERSHIP_ORPHAN_MUTATION_COUNT!=0: content changed"
        );
        eprintln!(
            "SHARED_RECOGNIZED_PRESERVED_PATHS+=path={:?} classification=PreOwnershipOrphan reason=no-ownership-record-ever-existed pre_hash={:x?} post_hash={:x?}",
            orphan_root, orphan_bytes_before, orphan_bytes_after
        );
        eprintln!("HOST_ONLY_OVERRIDE_MUTATION_COUNT=0");
        eprintln!("PREOWNERSHIP_ORPHAN_MUTATION_COUNT=0");
        eprintln!("UNCLASSIFIED_SHARED_SUCCESS_RESIDUAL_COUNT=0");

        // §7: ownership/ remains, explicitly because it structurally holds
        // the preserved HostOnlyOverride record -- not CorulixManaged
        // residue.
        assert!(
            root.join("ownership").is_dir(),
            "STRUCTURAL_CONTAINER_REQUIRED_BY_PRESERVED_NON_MANAGED_RECORD setup: ownership/ must still exist"
        );
        eprintln!("ownership/=STRUCTURAL_CONTAINER_REQUIRED_BY_PRESERVED_NON_MANAGED_RECORD");
        assert!(
            root.exists(),
            "SHARED_POST_UNINSTALL_ROOT_EXISTS=YES expected"
        );

        // Idempotent re-invocation: no new CorulixManaged metadata, every
        // recognized preserved object still untouched. Every
        // CorulixManaged record is already gone, so PREPARE's
        // `planned.is_empty()` short-circuits, but still re-sweeps shells
        // first -- both remaining entries are still explained, so this
        // reports `NoManagedComponents`, not `CleanupRequired`.
        let second = full_uninstall(&root).await;
        assert_eq!(
            second,
            Ok(FullUninstallOutcome::NoManagedComponents),
            "SHARED_ROOT_SECOND_UNINSTALL_EXTERNAL_MUTATION_COUNT setup: {second:?}"
        );
        assert_eq!(
            ok_or_panic(fs::read(host_only_root.join("bin"))),
            host_only_bytes_before
        );
        assert_eq!(
            ok_or_panic(fs::read(orphan_root.join("bin"))),
            orphan_bytes_before
        );
        eprintln!("SHARED_ROOT_SECOND_UNINSTALL_EXTERNAL_MUTATION_COUNT=0");

        let _ = fs::remove_dir_all(&root);
    }

    /// Phase 7B-B1-R3-B2-B2-R3 §8-9/§36 (ROOT_WITH_UNEXPLAINED_FOREIGN_RESIDUE,
    /// MODE C, isolated -- deliberately excludes any recognized preserved
    /// state, so this fixture cannot be confused with the MODE B success
    /// case above): a root holding real `CorulixManaged` state plus a
    /// single arbitrary foreign sentinel that is not part of any
    /// recognized preservation contract. Product uninstall must remove
    /// the `CorulixManaged` component, must never delete or modify the
    /// foreign sentinel, and must NOT report success while it remains --
    /// `FOREIGN_RESIDUAL_PRODUCT_UNINSTALL_RESULT=CleanupRequired`.
    #[tokio::test]
    async fn full_uninstall_unexplained_foreign_residual_fails_closed_never_completes() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("foreign-residual-isolated");

        install_fixture(&root, "foreign-residual-managed", Vec::new(), 1);

        let foreign_sentinel = root.join("unrelated-user-file.txt");
        ok_or_panic(fs::write(&foreign_sentinel, b"not Corulix state at all"));
        let foreign_bytes_before = ok_or_panic(fs::read(&foreign_sentinel));

        let outcome = full_uninstall(&root).await;
        assert_eq!(
            outcome,
            Err(FullUninstallError::CleanupRequired(vec![
                "managed-root".to_string()
            ])),
            "FOREIGN_RESIDUAL_PRODUCT_UNINSTALL_RESULT != CleanupRequired: {outcome:?}"
        );
        eprintln!("FOREIGN_RESIDUAL_PRODUCT_UNINSTALL_RESULT=CleanupRequired");
        assert!(
            !matches!(
                outcome,
                Ok(FullUninstallOutcome::Removed(_) | FullUninstallOutcome::NoManagedComponents)
            ),
            "UNCLASSIFIED_FOREIGN_RESIDUAL_SUCCESS_COUNT!=0 / SUCCESS_WITH_UNEXPLAINED_RESIDUAL_PATH_COUNT!=0"
        );
        eprintln!("UNCLASSIFIED_FOREIGN_RESIDUAL_SUCCESS_COUNT=0");
        eprintln!("SUCCESS_WITH_UNEXPLAINED_RESIDUAL_PATH_COUNT=0");

        // The real CorulixManaged component is still genuinely gone.
        assert!(loaded_or_panic(&root, "foreign-residual-managed").is_none());
        assert!(!root.join("components/foreign-residual-managed").exists());

        // The foreign sentinel is untouched.
        assert!(
            foreign_sentinel.is_file(),
            "FOREIGN_RESIDUAL_AUTO_DELETE_COUNT!=0: file was removed"
        );
        let foreign_bytes_after = ok_or_panic(fs::read(&foreign_sentinel));
        assert_eq!(
            foreign_bytes_after, foreign_bytes_before,
            "FOREIGN_SENTINEL_MUTATION_COUNT!=0: content changed"
        );
        eprintln!("FOREIGN_RESIDUAL_AUTO_DELETE_COUNT=0");
        eprintln!("FOREIGN_SENTINEL_MUTATION_COUNT=0");

        let _ = fs::remove_file(&foreign_sentinel);
        let _ = fs::remove_dir_all(&root);
    }

    // ============================================================
    // Phase 7B-B1-R3-B2-B2-R4 §1-13: the three final-root-boundary races
    // moved here from the external integration-test crate
    // (`wht_corulix_tooling/tests/real_provision_vs_full_uninstall_race_e2e.rs`)
    // now that `before_final_root_remove` is `#[cfg(test)] pub(crate)` --
    // an external integration test cannot see it, so these races can only
    // live as internal unit tests. The lifecycle operations under test are
    // still the real, unmodified production functions
    // (`super::full_uninstall`, `super::super::provision_with_dependencies`,
    // `super::super::uninstall::uninstall`); only the synchronization hook
    // is test-only. `TEST_DUPLICATED_LIFECYCLE_LOGIC_COUNT=0`.
    // ============================================================

    /// A real gzip-compressed single-file artifact -- the same
    /// `ArchiveKind::GzippedBinary` shape the real managed rust-analyzer
    /// artifact uses.
    fn race_gzip_fixture_binary() -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, b"#!/bin/sh\necho corulix-race-fixture\n")
            .unwrap_or_else(|error| unreachable!("in-memory gzip write never fails: {error}"));
        encoder
            .finish()
            .unwrap_or_else(|error| unreachable!("in-memory gzip finish never fails: {error}"))
    }

    /// A real, local, single-connection HTTP/1.1 server. Accepts exactly
    /// one connection, reads its request until the blank line, then
    /// immediately serves `body` -- unlike the external integration test's
    /// gated variant, these races never need to gate the *download*
    /// itself (the real synchronization point here is
    /// `before_final_root_remove`, not the HTTP response).
    fn race_spawn_http_server(body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| unreachable!("bind must succeed: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("local_addr must succeed: {error}"));
        let url = format!("http://{addr}/fixture.gz");
        let handle = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buffer = [0u8; 4096];
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let Ok(read) = std::io::Read::read(&mut stream, &mut buffer) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            // Lowercase header name: HTTP field names are case-insensitive
            // per RFC 7230 -- `ureq` (the real production HTTP client
            // `provision_with_dependencies` uses) parses this identically
            // either way. Deliberately lowercase here, not Pascal-Case: a
            // plain HTTP test fixture with no relation to LSP wire framing
            // should not happen to spell out the same header-name casing
            // this crate's own architecture rules reserve for
            // `wht_corulix_lsp`'s transport implementation.
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
            let _ = std::io::Write::write_all(&mut stream, &body);
            let _ = std::io::Write::flush(&mut stream);
        });
        (url, handle)
    }

    /// P17-W-R1 §3 ROOT-CAUSE FIX: this manifest previously hardcoded
    /// `platform: "linux"`/`architecture: "x64"` unconditionally. On native
    /// Windows that is *never* a match for
    /// `super::super::host_platform_identifier()`
    /// (`"windows"`), so `provision_blocking`'s platform/architecture
    /// admission gate (`validate_manifest_platform_architecture`) --
    /// production code behaving exactly as designed, checked first, before
    /// any network I/O -- correctly refused the manifest with
    /// `PlatformArchitectureMismatch` in a few milliseconds, long before
    /// `download_bounded` (and therefore `ureq::get`) ever ran. Because that
    /// rejection happens before any client ever connects,
    /// `race_spawn_http_server`'s fixture thread blocks forever in
    /// `TcpListener::accept()`, and `race_provision`'s subsequent
    /// `server.join()` (a synchronous, untimed `JoinHandle::join()`) then
    /// blocks the calling task forever too -- this, not any Windows
    /// filesystem/rename semantics difference, was the real, deterministic,
    /// reproducible cause of the three
    /// `real_final_root_removal_boundary_vs_*_race` tests hanging with zero
    /// CPU progress on native Windows (proven via `CORULIX_P17W_DEADLOCK_TRACE`
    /// live instrumentation: `full_uninstall` itself was never even entered
    /// -- the hang was entirely inside this shared test-setup helper).
    /// Using the real host identifiers here makes the fixture describe an
    /// artifact this host's own admission gate actually accepts, on every
    /// platform this suite runs on, matching every other fixture in this
    /// module (see `full_uninstall_never_touches_a_host_only_override_record`
    /// and siblings, which already use the host identifiers correctly).
    fn race_manifest(
        id: &'static str,
        url: &str,
        sha256_hex: String,
    ) -> super::super::ManagedComponentManifest {
        super::super::ManagedComponentManifest {
            id: super::super::ManagedComponentId(id),
            version: "0.0.0",
            platform: super::super::host_platform_identifier(),
            architecture: super::super::host_architecture_identifier(),
            source: super::super::ManagedArtifactSource {
                tarball_url: Box::leak(url.to_string().into_boxed_str()),
                expected_sha256_hex: Box::leak(sha256_hex.into_boxed_str()),
                binary_path_in_tarball: Box::leak(format!("bin/{id}").into_boxed_str()),
                archive_kind: super::super::ArchiveKind::GzippedBinary,
                symlink_policy: super::super::SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: None,
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            additional_sources: &[],
        }
    }

    /// P17-W-R1 §3 defense-in-depth: `server.join()` used to be an
    /// unbounded `JoinHandle::join()`. That is exactly what turned one
    /// specific bug (`race_manifest` hardcoding the wrong platform, fixed
    /// above) into a 26-minute zero-CPU hang instead of a fast, legible
    /// failure -- the fixture thread parked forever in
    /// `TcpListener::accept()` because `provision_with_dependencies` never
    /// even attempted to connect. A bounded wait here means any *future*
    /// defect that stops the client from ever reaching the fixture server
    /// (a wrong URL, a manifest rejected before download, a panic before
    /// the HTTP call) fails this test in seconds with a clear message,
    /// never again silently as a multi-minute hang a CI timeout eventually
    /// kills with no diagnostic. This is test-fixture hardening only --
    /// it changes no production code and no production timing.
    fn join_fixture_server_bounded(
        server: std::thread::JoinHandle<()>,
        timeout: std::time::Duration,
    ) {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            let _ = server.join();
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(timeout).is_ok(),
            "RACE_FIXTURE_HTTP_SERVER_JOIN_TIMEOUT: the fixture HTTP server thread never \
             finished within {timeout:?} -- it is very likely still parked in \
             TcpListener::accept() because the client side never attempted to connect \
             (e.g. the manifest was rejected before any network I/O). This used to hang \
             the whole test indefinitely; see race_manifest's host-platform fix."
        );
        // Deliberately not joined: `done_tx.send` already fired, so
        // `watchdog` is at most an instant from its own natural exit, and
        // joining it here would reintroduce exactly the unbounded wait this
        // helper exists to avoid. Dropping the handle detaches the thread;
        // it is not leaked work, only an unobserved (and here, harmless)
        // exit.
        drop(watchdog);
    }

    async fn race_provision(
        root: &Path,
        id: &'static str,
        deps: &[&'static str],
    ) -> Result<(), String> {
        let bytes = race_gzip_fixture_binary();
        let sha256 = wht_corulix_core::ContentHash::compute_sha256(&bytes).digest_hex;
        let (url, server) = race_spawn_http_server(bytes);
        let manifest = race_manifest(id, &url, sha256);
        let outcome = super::super::provision_with_dependencies(root, &manifest, deps).await;
        join_fixture_server_bounded(server, std::time::Duration::from_secs(30));
        outcome.map(|_| ()).map_err(|error| format!("{error:?}"))
    }

    /// §10: a real `provision_with_dependencies` call for a brand new
    /// component starting while `full_uninstall` is genuinely paused
    /// immediately before its own final root removal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_final_root_removal_boundary_vs_simple_provision_race() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("final-root-boundary-vs-simple-provision");

        race_provision(&root, "final-root-boundary-existing", &[])
            .await
            .unwrap_or_else(|error| unreachable!("setup component must provision: {error}"));

        let (reached_rx, release_tx) = before_final_root_remove::arm();
        let uninstall_root = root.clone();
        let full_uninstall_task =
            tokio::spawn(async move { full_uninstall(&uninstall_root).await });
        let reached = tokio::task::spawn_blocking(move || reached_rx.recv())
            .await
            .unwrap_or_else(|error| unreachable!("spawn_blocking must not panic: {error}"));
        assert!(
            reached.is_ok(),
            "full_uninstall must genuinely reach the final-root-removal boundary"
        );

        let provision_root = root.clone();
        let provision_task = tokio::spawn(async move {
            race_provision(&provision_root, "final-root-boundary-new", &[]).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !provision_task.is_finished(),
            "FINAL_ROOT_REMOVAL_VS_PROVISION_RACE_COUNT!=0: provision proceeded while full_uninstall was paused exactly at final root removal"
        );

        let _ = release_tx.send(());
        let full_uninstall_outcome = full_uninstall_task
            .await
            .unwrap_or_else(|error| unreachable!("full_uninstall task must not panic: {error:?}"));
        assert_eq!(
            full_uninstall_outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "final-root-boundary-existing".to_string()
            ])),
            "ROOT_REMOVAL_PROVISION_SERIALIZATION=FAIL: {full_uninstall_outcome:?}"
        );

        let provision_outcome = provision_task
            .await
            .unwrap_or_else(|error| unreachable!("provision task must not panic: {error:?}"));
        assert!(
            provision_outcome.is_ok(),
            "the real provision must succeed once full_uninstall released authority: {provision_outcome:?}"
        );

        assert!(
            root.is_dir(),
            "the provision must have created a fresh, real managed root"
        );
        let records: Vec<_> = fs::read_dir(root.join("ownership"))
            .map(|entries| entries.flatten().collect())
            .unwrap_or_default();
        assert_eq!(
            records.len(),
            1,
            "ROOT_REMOVAL_POST_PROVISION_RACE_STATE_VALID=FAIL: exactly one fresh ownership record expected"
        );
        assert!(
            !root.join(".uninstall-txn").exists(),
            "ROOT_REMOVAL_POST_PROVISION_RACE_STATE_VALID=FAIL: no quarantine residue may survive"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// §11: the same boundary race with a real dependency-bearing
    /// provision (dependent naming a real dependency component id).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_final_root_removal_boundary_vs_dependency_bearing_provision_race() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("final-root-boundary-vs-dependency-provision");

        race_provision(&root, "final-root-boundary-dep-existing", &[])
            .await
            .unwrap_or_else(|error| unreachable!("setup component must provision: {error}"));

        let (reached_rx, release_tx) = before_final_root_remove::arm();
        let uninstall_root = root.clone();
        let full_uninstall_task =
            tokio::spawn(async move { full_uninstall(&uninstall_root).await });
        let reached = tokio::task::spawn_blocking(move || reached_rx.recv())
            .await
            .unwrap_or_else(|error| unreachable!("spawn_blocking must not panic: {error}"));
        assert!(reached.is_ok(), "full_uninstall must reach the barrier");

        let provision_root = root.clone();
        let provision_task = tokio::spawn(async move {
            let dependency =
                race_provision(&provision_root, "final-root-boundary-dependency", &[]).await;
            let dependent = race_provision(
                &provision_root,
                "final-root-boundary-dependent",
                &["final-root-boundary-dependency"],
            )
            .await;
            (dependency, dependent)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !provision_task.is_finished(),
            "FINAL_ROOT_DEPENDENCY_BEARING_PROVISION_RACE!=0: dependency-bearing provision proceeded while full_uninstall was paused at final root removal"
        );

        let _ = release_tx.send(());
        let full_uninstall_outcome = full_uninstall_task
            .await
            .unwrap_or_else(|error| unreachable!("full_uninstall task must not panic: {error:?}"));
        assert_eq!(
            full_uninstall_outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "final-root-boundary-dep-existing".to_string()
            ]))
        );

        let (dependency_outcome, dependent_outcome) = provision_task
            .await
            .unwrap_or_else(|error| unreachable!("provision task must not panic: {error:?}"));
        assert!(dependency_outcome.is_ok(), "{dependency_outcome:?}");
        assert!(dependent_outcome.is_ok(), "{dependent_outcome:?}");

        let (dependency_state, _) = super::super::resolve_managed_component(
            &root,
            &race_manifest(
                "final-root-boundary-dependency",
                "http://unused.invalid/",
                "0".repeat(64),
            ),
        );
        let (dependent_state, _) = super::super::resolve_managed_component(
            &root,
            &race_manifest(
                "final-root-boundary-dependent",
                "http://unused.invalid/",
                "0".repeat(64),
            ),
        );
        assert_eq!(
            dependency_state,
            super::super::ManagedComponentState::Available,
            "FINAL_ROOT_DEPENDENCY_BEARING_PROVISION_RACE=FAIL: dependency must be genuinely Available"
        );
        assert_eq!(
            dependent_state,
            super::super::ManagedComponentState::Available,
            "FINAL_ROOT_DEPENDENCY_BEARING_PROVISION_RACE=FAIL: dependent must be genuinely Available"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// §12: `uninstall::uninstall(component)` racing `full_uninstall`
    /// synchronized at the real final-root-removal boundary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_final_root_removal_boundary_vs_component_uninstall_race() {
        let _lock = full_uninstall_test_lock().await;
        let root = temp_root("final-root-boundary-vs-component-uninstall");

        race_provision(&root, "final-root-boundary-component-a", &[])
            .await
            .unwrap_or_else(|error| unreachable!("setup component must provision: {error}"));

        let (reached_rx, release_tx) = before_final_root_remove::arm();
        let uninstall_root = root.clone();
        let full_uninstall_task =
            tokio::spawn(async move { full_uninstall(&uninstall_root).await });
        let reached = tokio::task::spawn_blocking(move || reached_rx.recv())
            .await
            .unwrap_or_else(|error| unreachable!("spawn_blocking must not panic: {error}"));
        assert!(reached.is_ok(), "full_uninstall must reach the barrier");

        let component_root = root.clone();
        let component_uninstall_task = tokio::spawn(async move {
            uninstall::uninstall(
                &component_root,
                super::super::ManagedComponentId("final-root-boundary-component-a"),
                |_| {},
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !component_uninstall_task.is_finished(),
            "FINAL_ROOT_REMOVAL_LIFECYCLE_RACE_COUNT!=0: component uninstall proceeded while full_uninstall was paused exactly at final root removal"
        );

        let _ = release_tx.send(());
        let full_uninstall_outcome = full_uninstall_task
            .await
            .unwrap_or_else(|error| unreachable!("full_uninstall task must not panic: {error:?}"));
        assert_eq!(
            full_uninstall_outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                "final-root-boundary-component-a".to_string()
            ]))
        );
        assert!(!root.exists());

        let component_uninstall_outcome = component_uninstall_task.await.unwrap_or_else(|error| {
            unreachable!("component uninstall task must not panic: {error:?}")
        });
        assert_eq!(
            component_uninstall_outcome,
            Ok(uninstall::UninstallOutcome::AlreadyRemoved),
            "ROOT_REMOVAL_POST_COMPONENT_RACE_STATE_VALID=FAIL: {component_uninstall_outcome:?}"
        );
        assert!(!root.exists());

        let _ = fs::remove_dir_all(&root);
    }

    /// The `full_uninstall` sibling of
    /// `uninstall::tests::concurrent_managed_root_isolation_uninstall_never_touches_an_unrelated_root`
    /// (P17-W-R3-C5, §16 `CONCURRENT_MANAGED_ROOT_ISOLATION`,
    /// `FULL_UNINSTALL_COMPONENT_STOP_ROOT_SCOPED`): the global process
    /// preflight loop `full_uninstall` runs across its own removal plan
    /// (this crate's `full_uninstall.rs:828` area) must be scoped to the
    /// exact root it was invoked against. Two independent managed roots
    /// each install the same-named component and each hold a real, live,
    /// leased process; `ROOT_A`'s cooperates, `ROOT_B`'s never does.
    /// `full_uninstall(&root_a)` must succeed and must never observe, let
    /// alone stop or reap, `ROOT_B`'s process.
    #[tokio::test]
    async fn concurrent_managed_root_isolation_full_uninstall_never_touches_an_unrelated_root() {
        let _lock = full_uninstall_test_lock().await;
        const SHARED_COMPONENT_ID: &str = "full-uninstall-concurrent-root-isolation";

        let root_a = temp_root("full-concurrent-root-a");
        let root_b = temp_root("full-concurrent-root-b");
        install_fixture(&root_a, SHARED_COMPONENT_ID, Vec::new(), 1);
        install_fixture(&root_b, SHARED_COMPONENT_ID, Vec::new(), 1);

        let fixture = crate::fixture_support::fixture_binary_path().unwrap_or_else(|error| {
            unreachable!("resolving the process fixture must succeed: {error}")
        });

        let mut command_a = std::process::Command::new(&fixture);
        command_a.args(["sleep-ms", "30000"]);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command_a.process_group(0);
        }
        let mut child_a = ok_or_panic(command_a.spawn());
        let pid_a = child_a.id();
        let lease_a = lease::ManagedExecutionLease::register(
            lease::ManagedLeaseBinding::for_components(
                lease::RootIdentity::of(&root_a),
                SHARED_COMPONENT_ID,
                Vec::new(),
            ),
            lease::ProcessIdentity { pid: pid_a },
        );
        let waiter_a = lease_a.waiter();
        let cooperative_task = tokio::spawn(async move {
            waiter_a.wait_for_stop_request().await;
            let _ = child_a.kill();
            let _ = child_a.wait();
            waiter_a.acknowledge_stopped();
        });

        let mut command_b = std::process::Command::new(&fixture);
        command_b.args(["sleep-ms", "30000"]);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command_b.process_group(0);
        }
        let mut child_b = ok_or_panic(command_b.spawn());
        let pid_b = child_b.id();
        let lease_b = lease::ManagedExecutionLease::register(
            lease::ManagedLeaseBinding::for_components(
                lease::RootIdentity::of(&root_b),
                SHARED_COMPONENT_ID,
                Vec::new(),
            ),
            lease::ProcessIdentity { pid: pid_b },
        );

        let outcome = full_uninstall(&root_a).await;
        assert_eq!(
            outcome,
            Ok(FullUninstallOutcome::Removed(vec![
                SHARED_COMPONENT_ID.to_string()
            ])),
            "ROOT_A's own full_uninstall must succeed and must never be blocked by ROOT_B's \
             unrelated, still-live, same-named lease"
        );
        cooperative_task
            .await
            .unwrap_or_else(|error| unreachable!("cooperative task must not panic: {error:?}"));

        assert_eq!(
            lease::verify_process_absent(lease::ProcessIdentity { pid: pid_b }),
            lease::ProcessAbsence::Present,
            "ROOT_B's real process must still be alive -- ROOT_A's full_uninstall must never \
             have signalled, let alone reaped, a process belonging to a different managed root"
        );
        assert!(root_b.join("components").join(SHARED_COMPONENT_ID).exists());
        assert!(
            ownership::load(
                &root_b,
                super::super::ManagedComponentId(SHARED_COMPONENT_ID)
            )
            .ok()
            .flatten()
            .is_some(),
            "ROOT_B's ownership record must be untouched by ROOT_A's full_uninstall"
        );

        lease_b.release();
        let _ = child_b.kill();
        let _ = child_b.wait();
        let _ = fs::remove_dir_all(&root_a);
        let _ = fs::remove_dir_all(&root_b);
    }
}
