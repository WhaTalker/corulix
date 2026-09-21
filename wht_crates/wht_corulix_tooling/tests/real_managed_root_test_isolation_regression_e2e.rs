// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! `MANAGED_TEST_ISOLATION_DEFECT` regression closure.
//!
//! A real, reproduced data-loss defect was found and fixed in
//! `wht_corulix_lsp/tests/real_ts6_final_residual_certification_e2e.rs`:
//! `real_ts6_active_full_uninstall_process_zero_state_e2e` called the
//! production `provisioning::managed_toolchain_root()` resolver directly and
//! ran the real, whole-root-destroying `full_uninstall` against it. Because
//! `full_uninstall` is (by design) a whole-managed-root transaction, this
//! silently deleted every *other* component's ownership record sitting in
//! that same real, shared, host-wide directory (`biome`, `rustfmt`, `ruff`,
//! `go-semantic-runtime`, ...) as collateral damage whenever that test ran
//! as part of a full `cargo test --workspace` invocation -- confirmed to
//! have recurred across separate M03 and M04 gate-verification passes.
//!
//! This file proves the general invariant the fix restores, using only
//! synthetic fixture components (no real network/toolchain download
//! required, so this suite runs deterministically on every host):
//!
//! - R1/R6: a full install-then-`full_uninstall` lifecycle, entirely
//!   confined to one isolated, uniquely-stamped temporary root, reaches
//!   zero residual (the root itself no longer exists) without ever
//!   resolving or touching the real `managed_toolchain_root()`.
//! - R2: the real host managed root's own top-level listing (or continued
//!   absence) is byte-identical before and after that isolated lifecycle --
//!   mirrors the same proven pattern already established in
//!   `real_p15_managed_scratch_zero_residual_e2e.rs`, applied here
//!   specifically alongside a synthetic formatter-like sentinel component to
//!   directly represent the exact defect class this closure fixes.
//! - R3/R5: two independently-created isolated test roots never share
//!   ownership state -- installing a component in one and running
//!   `full_uninstall` against it never touches, lists, or otherwise
//!   observes the other's independently-installed component.
//! - R4: the destructive entry points this suite (and the fixed TS6 test)
//!   use, `full_uninstall::full_uninstall`/`uninstall::uninstall`, take a
//!   mandatory `root: &Path` argument with no zero-argument/default-root
//!   overload -- there is no calling convention by which omitting an
//!   explicit isolated root could silently fall through to the live one.
//!   This is a structural (type-signature) guarantee, verified here by
//!   successfully driving both through only ever-explicit, independently
//!   constructed isolated roots. (The one zero-argument production
//!   convenience wrapper that does resolve the live root internally,
//!   `full_uninstall::uninstall_all_corulix_managed_components`, is a
//!   deliberate operator-facing entry point -- confirmed by direct source
//!   inspection to have no test call site anywhere in this workspace -- and
//!   is intentionally out of scope for a test-only isolation fix.)
//! - R7 is proved by this same pass's full `cargo test --workspace` run,
//!   not a test in this file.
//!
//! `MANAGED_ROOT_TEST_ISOLATION_LIVE_HOST_MUTATION_COUNT=0`: every fixture
//! root below is a freshly-created, uniquely-stamped temporary directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_tooling::provisioning::{
    self, full_uninstall,
    ownership::{self, OwnershipClass},
    uninstall::{self, NewInstallation, build_record},
};

fn stamp() -> u128 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    nanos + u128::from(unique)
}

fn isolated_root(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "corulix-managed-root-isolation-{label}-{}",
        stamp()
    ));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("test fixture setup must succeed: {error:?}"))
}

/// Installs a real `CorulixManaged` ownership record plus its on-disk
/// component root -- exactly the shape `provision` would leave behind for
/// a real formatter component (`biome`/`rustfmt`/`ruff`/`go-semantic-runtime`),
/// standing in for one without any real network download.
fn install_sentinel_component(root: &Path, id: &'static str) -> PathBuf {
    let component_root = root.join("components").join(id).join("9.9.9");
    ok(fs::create_dir_all(&component_root));
    ok(fs::write(
        component_root.join("bin"),
        b"sentinel formatter binary",
    ));
    let mut record = build_record(
        root,
        NewInstallation {
            component_id: id,
            version: "9.9.9",
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

fn owned_component_ids(root: &Path) -> Vec<String> {
    let mut ids: Vec<String> = ownership::list(root)
        .into_iter()
        .filter_map(Result::ok)
        .map(|record| record.component_id)
        .collect();
    ids.sort();
    ids
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

/// R1/R4/R6: a full install-then-`full_uninstall` lifecycle stays entirely
/// inside its own isolated root and reaches zero residual, never resolving
/// (or needing to resolve) the real `managed_toolchain_root()`.
#[tokio::test(flavor = "multi_thread")]
async fn destructive_lifecycle_stays_confined_to_its_isolated_root_and_reaches_zero_residual() {
    let root = isolated_root("r1-r6-lifecycle");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "R4: an isolated test root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }

    install_sentinel_component(&root, "isolation-regression-sentinel");
    assert_eq!(
        owned_component_ids(&root),
        vec!["isolation-regression-sentinel"]
    );

    let outcome = full_uninstall::full_uninstall(&root).await;
    assert!(
        outcome.is_ok(),
        "R6: full_uninstall must succeed inside the isolated test root: {outcome:?}"
    );
    assert!(
        !root.exists(),
        "R6: full_uninstall must reach zero residual (the isolated root itself removed) \
         inside the TEST root"
    );
}

/// R2: mirrors the proven `real_p15_managed_scratch_zero_residual_e2e.rs`
/// invariant, using a sentinel component named after the exact defect class
/// this closure fixes (a formatter-family managed component) so this test
/// directly represents the symptom that was actually observed (biome/
/// rustfmt/ruff/go-semantic-runtime ownership records disappearing from the
/// real host root).
#[tokio::test(flavor = "multi_thread")]
async fn real_host_managed_root_formatter_sentinel_survives_isolated_destructive_lifecycle() {
    let real_root = provisioning::managed_toolchain_root()
        .unwrap_or_else(|_| PathBuf::from("/nonexistent-corulix-managed-root"));
    let before_exists = real_root.exists();
    let before = top_level_names(&real_root);
    let before_owned = if before_exists {
        owned_component_ids(&real_root)
    } else {
        Vec::new()
    };

    let isolated = isolated_root("r2-host-sentinel");
    install_sentinel_component(&isolated, "biome-like-formatter-sentinel");
    install_sentinel_component(&isolated, "rustfmt-like-formatter-sentinel");
    assert!(full_uninstall::full_uninstall(&isolated).await.is_ok());

    assert_eq!(
        real_root.exists(),
        before_exists,
        "MANAGED_ROOT_TEST_ISOLATION_LIVE_HOST_MUTATION_COUNT must be 0: the real managed \
         root's existence changed"
    );
    assert_eq!(
        top_level_names(&real_root),
        before,
        "MANAGED_ROOT_TEST_ISOLATION_LIVE_HOST_MUTATION_COUNT must be 0: the real managed \
         root's top-level listing changed"
    );
    if before_exists {
        assert_eq!(
            owned_component_ids(&real_root),
            before_owned,
            "MANAGED_ROOT_TEST_ISOLATION_LIVE_HOST_MUTATION_COUNT must be 0: the real managed \
             root's ownership records changed"
        );
    }
}

/// R3/R5: two independently-created isolated test roots never share
/// ownership state. Destroying one via `full_uninstall` must never touch,
/// list, or otherwise affect the other's independently-installed component.
#[tokio::test(flavor = "multi_thread")]
async fn two_independent_isolated_test_roots_never_share_ownership_state() {
    let root_a = isolated_root("r3-r5-context-a");
    let root_b = isolated_root("r3-r5-context-b");
    assert_ne!(
        root_a, root_b,
        "two independently-created test contexts must be distinct roots"
    );

    install_sentinel_component(&root_a, "context-a-only-sentinel");
    install_sentinel_component(&root_b, "context-b-only-sentinel");
    assert_eq!(
        owned_component_ids(&root_a),
        vec!["context-a-only-sentinel"]
    );
    assert_eq!(
        owned_component_ids(&root_b),
        vec!["context-b-only-sentinel"]
    );

    assert!(full_uninstall::full_uninstall(&root_a).await.is_ok());

    assert!(
        !root_a.exists(),
        "context A's own isolated root must reach zero residual after its own full_uninstall"
    );
    assert!(
        root_b.exists(),
        "context B's independent isolated root must be completely unaffected by context A's \
         full_uninstall"
    );
    assert_eq!(
        owned_component_ids(&root_b),
        vec!["context-b-only-sentinel"],
        "context B's ownership records must be byte-identical to before context A's destructive \
         operation -- no shared ownership state between independently-created test contexts"
    );

    let _ = fs::remove_dir_all(&root_b);
}

/// R3 (single-component variant): the narrower `uninstall::uninstall`
/// (single-component removal, not the whole-root `full_uninstall`) must
/// likewise never reach across isolated roots.
#[tokio::test(flavor = "multi_thread")]
async fn single_component_uninstall_never_reaches_across_isolated_roots() {
    let root_a = isolated_root("r3-single-component-a");
    let root_b = isolated_root("r3-single-component-b");

    install_sentinel_component(&root_a, "single-uninstall-target");
    install_sentinel_component(&root_b, "single-uninstall-target");

    let component_id = provisioning::ManagedComponentId("single-uninstall-target");
    let removed = uninstall::uninstall(&root_a, component_id, |_| {}).await;
    assert!(
        removed.is_ok(),
        "single-component uninstall must succeed in its own root: {removed:?}"
    );

    assert!(
        owned_component_ids(&root_a).is_empty(),
        "root A must no longer own the uninstalled component"
    );
    assert_eq!(
        owned_component_ids(&root_b),
        vec!["single-uninstall-target"],
        "root B's identically-named component must be completely unaffected by root A's \
         single-component uninstall"
    );

    let _ = fs::remove_dir_all(&root_a);
    let _ = fs::remove_dir_all(&root_b);
}
