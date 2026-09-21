// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 15 cache closure: the managed-execution-cache ownership and
//! zero-residual `full_uninstall` matrix.
//!
//! # What this file proves, and why it is fixture-driven rather than
//! toolchain-driven
//!
//! The *real* Go and cargo cache creation/removal end-to-end proofs live in
//! `wht_corulix_engine`'s own
//! `real_p15_managed_execution_cache_lifecycle_e2e.rs`, where the real
//! `go`/`cargo` toolchains are reachable. This file covers the parts of the
//! contract that must hold on *every* host regardless of which toolchains
//! happen to be installed -- the shared-root preservation contract, the
//! adversarial symlink-substitution matrix, the unexplained-residue
//! fail-closed contract, and the concurrency contract -- so none of them can
//! silently degrade to `BLOCKED_PROVIDER_UNAVAILABLE`.
//!
//! Every test drives the real production entry points
//! (`provisioning::full_uninstall::full_uninstall`,
//! `provisioning::full_uninstall::full_uninstall_resume_cleanup`,
//! `provisioning::uninstall::uninstall`,
//! `provisioning::ensure_scratch_directory`,
//! `provisioning::acquire_managed_execution_scratch_guard`). There is no
//! test-only cleanup after a product call returns
//! (`P15_POST_PRODUCT_TEST_CLEANUP_REQUIRED=NO`): where a test does remove
//! its fixture at the end, it is only for a case whose *expected* outcome is
//! deliberately-retained residue, and every such removal happens strictly
//! after all assertions.
//!
//! `OS_LEVEL_NETWORK_ISOLATION=NOT_CLAIMED`; nothing here touches the
//! network, and nothing here mutates the operator's real managed toolchain
//! root -- every fixture root is a freshly-created, uniquely-stamped
//! temporary directory (`P15_TEST_SHARED_HOST_ROOT_MUTATION_COUNT=0`).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_tooling::provisioning::{
    self, ManagedComponentId, full_uninstall,
    ownership::{self, OwnershipClass},
    uninstall::{self, NewInstallation, build_record},
};

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

fn temp_root(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("corulix-p15-scratch-{label}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("test fixture setup must succeed: {error:?}"))
}

/// Installs a real `CorulixManaged` ownership record plus its on-disk
/// component root, exactly as `provision` would leave them.
fn install_managed_component(root: &Path, id: &'static str) -> PathBuf {
    let component_root = root.join("components").join(id).join("1.0.0");
    ok(fs::create_dir_all(&component_root));
    ok(fs::write(component_root.join("bin"), b"fixture binary"));
    let mut record = build_record(
        root,
        NewInstallation {
            component_id: id,
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
    ok(ownership::save(root, &mut record));
    component_root
}

/// Installs a `HostOnlyOverride` record: recognized, tracked, permanently
/// preserved external state living directly under the managed root. This is
/// the already-certified shared-root shape
/// (`SHARED_ROOT_WITH_RECOGNIZED_PRESERVED_STATE`).
fn install_host_only_override(root: &Path, id: &'static str) -> PathBuf {
    let component_root = root.join(id);
    ok(fs::create_dir_all(&component_root));
    ok(fs::write(component_root.join("host-tool"), b"host bytes"));
    let mut record = build_record(
        root,
        NewInstallation {
            component_id: id,
            version: "9.9.9",
            platform: "linux",
            architecture: "x64",
            canonical_component_root: component_root.clone(),
            dependencies: Vec::new(),
            installation_sequence: 2,
            artifact_digest: "1".repeat(64),
            ownership: OwnershipClass::HostOnlyOverride,
            installed_payload_digest: String::new(),
            installed_payload_kind: ownership::InstalledPayloadKind::SingleFile,
            optional_segment_digests: std::collections::BTreeMap::new(),
        },
    );
    ok(ownership::save(root, &mut record));
    component_root
}

/// Materializes a realistic, multi-level managed execution cache through the
/// real production authority -- both phase-scoped shapes the audit found
/// (`scratch/p15-go/<hash>/...` for Go, `scratch/p12-cargo-test-target/<hash>`
/// for cargo), with real bytes in real files, never an empty directory shell.
fn create_managed_execution_caches(root: &Path) -> Vec<PathBuf> {
    let mut created = Vec::new();
    for relative in [
        "scratch/p15-go/00feedface00/build-cache/aa",
        "scratch/p15-go/00feedface00/module-cache",
        "scratch/p15-go/00feedface00/gopath",
        "scratch/p15-go/00feedface00/build-output",
        "scratch/p12-cargo-test-target/00cafebabe00/debug/deps",
    ] {
        let dir = ok(provisioning::ensure_scratch_directory(root, relative));
        ok(fs::write(dir.join("cache-entry.bin"), b"real cache bytes"));
        created.push(dir);
    }
    created
}

/// Recursively counts every file under `path` -- the real "managed cache
/// entry count" measurement, never a mere directory-exists probe.
fn entry_count(path: &Path) -> usize {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| {
            let child = entry.path();
            if child.is_dir() && !child.is_symlink() {
                entry_count(&child)
            } else {
                1
            }
        })
        .sum()
}

fn top_level_names(root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

fn managed_record_count(root: &Path) -> usize {
    ownership::list(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|record| record.ownership == OwnershipClass::CorulixManaged)
        .count()
}

fn live_record_count(root: &Path) -> usize {
    ownership::list(root).len()
}

fn trusted_digest(path: &Path) -> Vec<u8> {
    ok(fs::read(path))
}

// ---------------------------------------------------------------------------
// §13/§14: zero residual, then a genuinely idempotent second uninstall
// ---------------------------------------------------------------------------

/// The exact defect this phase closes, as a permanent regression test.
///
/// Before the fix, this call returned `CleanupRequired(["managed-root"])`
/// with `<root>/scratch` still on disk and the managed root still present --
/// reproduced empirically against both the Go and cargo cache shapes.
#[tokio::test(flavor = "multi_thread")]
async fn managed_execution_cache_is_owned_tracked_and_removed_to_zero_residual() {
    let root = temp_root("zero-residual");
    install_managed_component(&root, "p15-scratch-component");
    let caches = create_managed_execution_caches(&root);

    let scratch_root = root.join(provisioning::MANAGED_SCRATCH_DIR);
    let before = entry_count(&scratch_root);
    assert!(
        before > 0,
        "P15_MANAGED_CACHE_ENTRY_COUNT_BEFORE_UNINSTALL must be >0, got {before}"
    );
    for cache in &caches {
        assert!(cache.is_dir(), "cache dir {} must exist", cache.display());
    }

    let outcome = full_uninstall::full_uninstall(&root).await;

    assert_eq!(
        outcome,
        Ok(full_uninstall::FullUninstallOutcome::Removed(vec![
            "p15-scratch-component".to_string()
        ])),
        "GO_COMPLETE_MANAGED_ZERO_STATE: full_uninstall must report Removed, got {outcome:?}"
    );
    // NO test-side cleanup before these assertions --
    // `P15_POST_PRODUCT_TEST_CLEANUP_REQUIRED=NO`.
    assert!(
        !scratch_root.exists(),
        "POST_UNINSTALL_MANAGED_CACHE_COUNT!=0: {} survived",
        scratch_root.display()
    );
    assert!(
        !root.join("staging").exists(),
        "POST_UNINSTALL_STAGING_COUNT!=0"
    );
    assert!(
        !root.join(".uninstall-txn").exists(),
        "POST_UNINSTALL_QUARANTINE_COUNT!=0"
    );
    assert!(
        !root.join("ownership").exists(),
        "POST_UNINSTALL_LIVE_OWNERSHIP_RECORD_COUNT!=0"
    );
    assert_eq!(
        top_level_names(&root),
        Vec::<String>::new(),
        "POST_UNINSTALL_RESIDUAL_PATHS must be []"
    );
    assert!(
        !root.exists(),
        "POST_UNINSTALL_MANAGED_ROOT_EXISTS must be NO"
    );
}

/// §14: a second `full_uninstall` against an already-fully-removed root
/// must recreate nothing -- not the root, not `ownership/`, not `scratch/`.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_full_uninstall_recreates_neither_the_root_nor_any_managed_cache() {
    let root = temp_root("second-uninstall");
    install_managed_component(&root, "p15-second-component");
    create_managed_execution_caches(&root);

    assert!(full_uninstall::full_uninstall(&root).await.is_ok());
    assert!(!root.exists(), "first uninstall must remove the root");

    let second = full_uninstall::full_uninstall(&root).await;
    assert_eq!(
        second,
        Ok(full_uninstall::FullUninstallOutcome::NoManagedComponents),
        "P15_SECOND_FULL_UNINSTALL must PASS, got {second:?}"
    );
    assert!(
        !root.exists(),
        "P15_SECOND_UNINSTALL_ROOT_RECREATION_COUNT must be 0"
    );
    assert!(
        !root.join(provisioning::MANAGED_SCRATCH_DIR).exists(),
        "the second uninstall recreated a managed cache directory"
    );
}

/// The same zero-residual contract must hold through the manual-recovery
/// entry point, not only the happy path -- `full_uninstall_resume_cleanup`
/// shares the one cleanup authority rather than reimplementing it.
#[tokio::test(flavor = "multi_thread")]
async fn resume_cleanup_shares_the_same_managed_cache_removal_authority() {
    let root = temp_root("resume-cleanup");
    create_managed_execution_caches(&root);
    let scratch_root = root.join(provisioning::MANAGED_SCRATCH_DIR);
    assert!(entry_count(&scratch_root) > 0);

    let outcome = full_uninstall::full_uninstall_resume_cleanup(&root).await;
    assert!(
        outcome.is_ok(),
        "resume_cleanup must reach zero residual, got {outcome:?}"
    );
    assert!(
        !scratch_root.exists(),
        "resume_cleanup left a managed cache"
    );
    assert!(!root.exists(), "resume_cleanup left the managed root");
}

// ---------------------------------------------------------------------------
// §16/§17: shared root -- remove all CORULIX_MANAGED state, preserve
// recognized external state byte-identically
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_shared_root_loses_every_managed_cache_and_keeps_recognized_external_state_byte_identical()
 {
    let root = temp_root("shared-root");
    install_managed_component(&root, "p15-shared-managed");
    let host_root = install_host_only_override(&root, "p15-host-override");
    let host_file = host_root.join("host-tool");
    let host_bytes_before = trusted_digest(&host_file);

    // A pre-ownership orphan: on disk at the exact expected managed path,
    // never owned by Corulix, must survive untouched.
    let orphan = root.join("components").join("p15-orphan").join("1.0.0");
    ok(fs::create_dir_all(&orphan));
    ok(fs::write(orphan.join("bin"), b"orphan bytes"));
    let orphan_bytes_before = trusted_digest(&orphan.join("bin"));

    create_managed_execution_caches(&root);
    let scratch_root = root.join(provisioning::MANAGED_SCRATCH_DIR);
    assert!(entry_count(&scratch_root) > 0);

    let outcome = full_uninstall::full_uninstall(&root).await;
    assert_eq!(
        outcome,
        Ok(full_uninstall::FullUninstallOutcome::Removed(vec![
            "p15-shared-managed".to_string()
        ])),
        "SHARED_ROOT_ZERO_CORULIX_MANAGED_STATE: got {outcome:?}"
    );

    // Managed state: gone, including the cache. Scratch must be
    // explained-and-*removed*, never explained-and-preserved.
    assert_eq!(
        managed_record_count(&root),
        0,
        "SHARED_ROOT_ZERO_CORULIX_MANAGED_STATE!=PASS"
    );
    assert!(
        !scratch_root.exists(),
        "POST_UNINSTALL_MANAGED_CACHE_COUNT!=0 in shared-root mode"
    );

    // Recognized external state: byte-identical, and the root correctly
    // retained rather than removed.
    assert!(root.exists(), "the shared root must be retained");
    assert_eq!(
        trusted_digest(&host_file),
        host_bytes_before,
        "P15_HOST_ONLY_OVERRIDE_MUTATION_COUNT must be 0"
    );
    assert_eq!(
        trusted_digest(&orphan.join("bin")),
        orphan_bytes_before,
        "P15_PREOWNERSHIP_ORPHAN_MUTATION_COUNT must be 0"
    );
    assert_eq!(
        live_record_count(&root),
        1,
        "SHARED_ROOT_EXTERNAL_STATE_PRESERVATION: the HostOnlyOverride record must survive"
    );

    // Expected-retained fixture; removed only after every assertion.
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// §18: unexplained residue -> preserved, and NOT a successful Completed
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn unexplained_foreign_residue_is_preserved_and_never_reported_as_a_clean_completion() {
    let root = temp_root("unexplained-residue");
    install_managed_component(&root, "p15-residue-component");
    create_managed_execution_caches(&root);

    // Deliberate residue that is neither Corulix-owned nor recognized: a
    // foreign directory at the managed root's own top level.
    let foreign = root.join("p15-foreign-unrecognized");
    ok(fs::create_dir_all(&foreign));
    let foreign_file = foreign.join("sentinel.bin");
    ok(fs::write(&foreign_file, b"foreign sentinel bytes"));
    let foreign_bytes_before = trusted_digest(&foreign_file);

    let outcome = full_uninstall::full_uninstall(&root).await;

    match &outcome {
        Err(full_uninstall::FullUninstallError::CleanupRequired(paths)) => {
            assert!(
                paths.iter().any(|path| path == "managed-root"),
                "P15_UNEXPLAINED_RESIDUE_RESULT must name the residual root, got {paths:?}"
            );
        }
        other => unreachable!(
            "P15_UNEXPLAINED_RESIDUE_RESULT must be CleanupRequired, never a successful \
             Completed/Removed -- got {other:?}"
        ),
    }
    assert!(
        foreign.exists(),
        "P15_UNEXPLAINED_RESIDUE_AUTO_DELETE_COUNT must be 0"
    );
    assert_eq!(
        trusted_digest(&foreign_file),
        foreign_bytes_before,
        "P15_EXTERNAL_CACHE_SENTINEL_MUTATION_COUNT must be 0"
    );
    assert!(root.exists(), "the root must be retained alongside residue");

    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// §20: adversarial symlink substitution
// ---------------------------------------------------------------------------

/// The managed scratch root itself replaced by a symlink pointing at an
/// external directory. Uninstall must fail closed: the external target's
/// bytes untouched, the symlink itself never deleted, and no successful
/// completion reported.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_symlink_substituted_for_the_managed_scratch_root_is_never_followed_or_deleted() {
    let root = temp_root("symlink-scratch-root");
    let external = temp_root("symlink-scratch-root-external");
    let external_file = external.join("precious.bin");
    ok(fs::write(
        &external_file,
        b"external bytes that must survive",
    ));
    let external_bytes_before = trusted_digest(&external_file);

    install_managed_component(&root, "p15-symlink-component");
    let scratch_root = root.join(provisioning::MANAGED_SCRATCH_DIR);
    ok(std::os::unix::fs::symlink(&external, &scratch_root));

    let outcome = full_uninstall::full_uninstall(&root).await;

    match &outcome {
        Err(full_uninstall::FullUninstallError::CleanupRequired(paths)) => {
            assert!(
                paths
                    .iter()
                    .any(|path| path == provisioning::MANAGED_SCRATCH_DIR),
                "the substituted scratch root must be reported as residual, got {paths:?}"
            );
        }
        other => unreachable!(
            "a symlink-substituted managed scratch root must fail closed, got {other:?}"
        ),
    }
    assert!(
        external.exists(),
        "P15_OUTSIDE_ROOT_DELETE_COUNT must be 0: the external target directory was removed"
    );
    assert_eq!(
        trusted_digest(&external_file),
        external_bytes_before,
        "P15_CACHE_SYMLINK_ESCAPE_DELETE_COUNT must be 0: external bytes changed"
    );
    assert!(
        fs::symlink_metadata(&scratch_root).is_ok(),
        "the substituted symlink itself must be preserved, not silently unlinked"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&external);
}

/// The managed scratch root replaced by a symlink pointing at a *different
/// directory inside the same managed root*. `starts_with`-style confinement
/// alone would accept this and delete `components/`; the exact-identity
/// check refuses it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_scratch_root_symlinked_elsewhere_inside_the_managed_root_is_still_refused() {
    let root = temp_root("symlink-inside-root");
    let component_root = install_managed_component(&root, "p15-inside-component");
    let victim = root.join("p15-victim-directory");
    ok(fs::create_dir_all(&victim));
    let victim_file = victim.join("victim.bin");
    ok(fs::write(&victim_file, b"must not be deleted"));
    let victim_bytes_before = trusted_digest(&victim_file);

    let scratch_root = root.join(provisioning::MANAGED_SCRATCH_DIR);
    ok(std::os::unix::fs::symlink(&victim, &scratch_root));

    let outcome = full_uninstall::full_uninstall(&root).await;
    assert!(
        outcome.is_err(),
        "an in-root symlink substitution must not report success, got {outcome:?}"
    );
    assert!(
        victim.exists(),
        "P15_OUTSIDE_ROOT_DELETE_COUNT: victim removed"
    );
    assert_eq!(
        trusted_digest(&victim_file),
        victim_bytes_before,
        "the symlink target's bytes were mutated"
    );
    // The component itself was already quarantined/destroyed before this
    // cleanup stage runs, which is correct and expected -- the point is only
    // that the substituted target was not.
    assert!(!component_root.exists());

    let _ = fs::remove_dir_all(&root);
}

/// A *nested* symlink deep inside the managed cache subtree, pointing at an
/// external directory. Unlike the scratch-root substitution above, this must
/// **succeed**: `fs::rename` moves the subtree by inode without traversing
/// it, and `fs::remove_dir_all` unlinks symlink entries without following
/// them -- so the cache is fully removed while the external target survives
/// byte-identically. Asserting `CleanupRequired` here would be wrong.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_nested_cache_symlink_is_unlinked_without_ever_deleting_its_external_target() {
    let root = temp_root("symlink-nested");
    let external = temp_root("symlink-nested-external");
    let external_file = external.join("precious.bin");
    ok(fs::write(
        &external_file,
        b"external bytes that must survive",
    ));
    let external_bytes_before = trusted_digest(&external_file);

    install_managed_component(&root, "p15-nested-component");
    create_managed_execution_caches(&root);

    // Adversarial substitution of a real nested cache directory.
    let nested = root.join("scratch/p15-go/00feedface00/build-cache");
    ok(fs::remove_dir_all(&nested));
    ok(std::os::unix::fs::symlink(&external, &nested));
    // And an extra dangling-into-external symlink alongside it.
    ok(std::os::unix::fs::symlink(
        &external_file,
        root.join("scratch/p15-go/00feedface00/module-cache/escape-link"),
    ));

    let outcome = full_uninstall::full_uninstall(&root).await;
    assert_eq!(
        outcome,
        Ok(full_uninstall::FullUninstallOutcome::Removed(vec![
            "p15-nested-component".to_string()
        ])),
        "a nested cache symlink must not block zero-residual cleanup, got {outcome:?}"
    );
    assert!(
        !root.exists(),
        "the managed root must still reach zero state"
    );
    assert!(
        external.exists(),
        "P15_OUTSIDE_ROOT_DELETE_COUNT must be 0: the nested symlink was followed"
    );
    assert_eq!(
        trusted_digest(&external_file),
        external_bytes_before,
        "P15_CACHE_SYMLINK_ESCAPE_DELETE_COUNT must be 0: external bytes changed"
    );

    let _ = fs::remove_dir_all(&external);
}

/// A plain *file* sitting at Corulix's own managed scratch location is not
/// something `ensure_scratch_directory` could have created, so it fails
/// closed exactly like a symlink rather than being deleted.
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_file_at_the_managed_scratch_location_fails_closed() {
    let root = temp_root("scratch-is-a-file");
    install_managed_component(&root, "p15-file-component");
    let scratch_root = root.join(provisioning::MANAGED_SCRATCH_DIR);
    ok(fs::write(&scratch_root, b"not a directory"));
    let bytes_before = trusted_digest(&scratch_root);

    let outcome = full_uninstall::full_uninstall(&root).await;
    assert!(
        outcome.is_err(),
        "a foreign file at the scratch location must not report success, got {outcome:?}"
    );
    assert_eq!(
        trusted_digest(&scratch_root),
        bytes_before,
        "the foreign file was mutated or removed"
    );

    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// §19: creation-time confinement of the single scratch-write authority
// ---------------------------------------------------------------------------

#[test]
fn the_scratch_write_authority_refuses_every_unconfined_relative_path() {
    let root = temp_root("confinement");
    for hostile in [
        "../escape",
        "scratch/../../escape",
        "/absolute/escape",
        "scratch/p15-go/../../../escape",
        "",
    ] {
        let result = provisioning::ensure_scratch_directory(&root, hostile);
        assert!(
            result.is_err(),
            "P15_CACHE_OWNERSHIP_CONFINEMENT: {hostile:?} was accepted as a scratch path"
        );
    }
    // And nothing was created outside the root by the rejected attempts.
    assert_eq!(
        top_level_names(&root),
        Vec::<String>::new(),
        "a rejected scratch path still created state"
    );
    // A legitimate path still works, so the check is not over-broad.
    let good = ok(provisioning::ensure_scratch_directory(
        &root,
        "scratch/p15-go/abc/build-cache",
    ));
    assert!(good.starts_with(&root) && good.is_dir());

    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// §21/§22: concurrency and active-execution protection, through the existing
// managed-root lock -- never a sleep as the synchronization authority
// ---------------------------------------------------------------------------

/// A live governed execution holding its managed-execution scratch guard
/// must block a concurrent `full_uninstall` from destroying the cache it is
/// still writing. Synchronization is by real channels: the "execution" task
/// signals that it holds the guard and has written cache bytes, the uninstall
/// task is only started then, and the guard is released only after the test
/// has *proved* the uninstall had not yet removed anything.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_execution_scratch_guard_blocks_full_uninstall_until_the_execution_finishes() {
    let root = temp_root("race-full-uninstall");
    install_managed_component(&root, "p15-race-component");

    let (holding_tx, holding_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (observed_tx, observed_rx) = std::sync::mpsc::channel::<bool>();

    let execution_root = root.clone();
    let execution = tokio::spawn(async move {
        let _guard = provisioning::acquire_managed_execution_scratch_guard(&execution_root).await;
        let cache = ok(provisioning::ensure_scratch_directory(
            &execution_root,
            "scratch/p15-go/00race00/build-cache",
        ));
        ok(fs::write(cache.join("in-flight.bin"), b"live cache bytes"));
        let _ = holding_tx.send(());
        // Blocks until the test has verified the concurrent uninstall did
        // not delete this cache out from under the execution.
        let _ = release_rx.recv();
        let still_present = cache.join("in-flight.bin").is_file();
        let _ = observed_tx.send(still_present);
    });

    ok(holding_rx.recv());
    let uninstall_root = root.clone();
    let uninstaller =
        tokio::spawn(async move { full_uninstall::full_uninstall(&uninstall_root).await });

    // The uninstall is now genuinely contending for the same root lock. Give
    // it a real, bounded opportunity to (incorrectly) proceed; the assertion
    // authority is the guard, not this bound -- if the guard were absent this
    // window is far more than enough for the transaction to complete, which
    // is exactly what makes a violation observable rather than merely
    // hypothetical.
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert!(
        root.join("scratch/p15-go/00race00/build-cache/in-flight.bin")
            .is_file(),
        "P15_ACTIVE_EXECUTION_PREMATURE_CACHE_DELETE_COUNT must be 0: the live execution's \
         cache was destroyed while its guard was held"
    );
    assert!(
        root.join("components/p15-race-component").exists(),
        "P15_EXECUTION_CACHE_FULL_UNINSTALL_RACE_COUNT must be 0: the transaction quarantined \
         a component while a governed execution held the root lock"
    );

    let _ = release_tx.send(());
    assert!(
        ok(observed_rx.recv()),
        "the execution observed its own cache disappear mid-run"
    );
    ok(execution.await);

    // Only now may the transaction proceed -- and it must then reach full
    // zero residual, cache included.
    let outcome = ok(uninstaller.await);
    assert_eq!(
        outcome,
        Ok(full_uninstall::FullUninstallOutcome::Removed(vec![
            "p15-race-component".to_string()
        ])),
        "the deferred transaction must still complete cleanly, got {outcome:?}"
    );
    assert!(
        !root.exists(),
        "POST_UNINSTALL_MANAGED_ROOT_EXISTS must be NO after the race resolves"
    );
}

/// The same contract against a *single-component* `uninstall` rather than a
/// full transaction (§21's second required race): both take the same root
/// lock, so neither can interleave with a live governed execution.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_execution_scratch_guard_serializes_against_a_single_component_uninstall() {
    let root = temp_root("race-component-uninstall");
    install_managed_component(&root, "p15-component-race");

    let (holding_tx, holding_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

    let execution_root = root.clone();
    let execution = tokio::spawn(async move {
        let _guard = provisioning::acquire_managed_execution_scratch_guard(&execution_root).await;
        let cache = ok(provisioning::ensure_scratch_directory(
            &execution_root,
            "scratch/p15-go/00race02/build-cache",
        ));
        ok(fs::write(cache.join("in-flight.bin"), b"live cache bytes"));
        let _ = holding_tx.send(());
        let _ = release_rx.recv();
        cache.join("in-flight.bin").is_file()
    });

    ok(holding_rx.recv());
    let uninstall_root = root.clone();
    let component_uninstall = tokio::spawn(async move {
        uninstall::uninstall(
            &uninstall_root,
            ManagedComponentId("p15-component-race"),
            |_: &Path| {},
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        root.join("scratch/p15-go/00race02/build-cache/in-flight.bin")
            .is_file(),
        "P15_EXECUTION_CACHE_COMPONENT_UNINSTALL_RACE_COUNT must be 0"
    );

    let _ = release_tx.send(());
    assert!(
        ok(execution.await),
        "the execution observed its own cache disappear mid-run"
    );
    let outcome = ok(component_uninstall.await);
    assert!(
        outcome.is_ok(),
        "the deferred single-component uninstall must still succeed, got {outcome:?}"
    );

    // A single-component `uninstall` is deliberately NOT the zero-residual
    // authority (`full_uninstall` is), so the cache legitimately remains
    // here; the follow-up full_uninstall is what must clear it.
    assert!(root.join(provisioning::MANAGED_SCRATCH_DIR).exists());
    let final_outcome = full_uninstall::full_uninstall(&root).await;
    assert_eq!(
        final_outcome,
        Ok(full_uninstall::FullUninstallOutcome::NoManagedComponents),
        "got {final_outcome:?}"
    );
    assert!(
        !root.exists(),
        "POST_UNINSTALL_MANAGED_ROOT_EXISTS must be NO"
    );
}

// ---------------------------------------------------------------------------
// §23: the operator's real managed root is never mutated by this suite
// ---------------------------------------------------------------------------

/// Every fixture above resolves its own uniquely-stamped temporary root, and
/// nothing in this file calls `managed_toolchain_root()`. This test states
/// that as a real, checked invariant rather than a comment: the operator's
/// real managed root's own top-level listing (or its continued absence) is
/// identical before and after the suite's fixture work.
#[tokio::test(flavor = "multi_thread")]
async fn the_real_host_managed_root_is_never_mutated_by_this_suite() {
    let real_root = provisioning::managed_toolchain_root()
        .unwrap_or_else(|_| PathBuf::from("/nonexistent-corulix-managed-root"));
    let before_exists = real_root.exists();
    let before = top_level_names(&real_root);

    // A full fixture lifecycle, in its own isolated root.
    let isolated = temp_root("host-sentinel");
    install_managed_component(&isolated, "p15-sentinel-component");
    create_managed_execution_caches(&isolated);
    assert!(full_uninstall::full_uninstall(&isolated).await.is_ok());

    assert_eq!(
        real_root.exists(),
        before_exists,
        "P15_TEST_SHARED_HOST_ROOT_MUTATION_COUNT must be 0: the real managed root's existence \
         changed"
    );
    assert_eq!(
        top_level_names(&real_root),
        before,
        "P15_TEST_SHARED_HOST_ROOT_MUTATION_COUNT must be 0"
    );
}
