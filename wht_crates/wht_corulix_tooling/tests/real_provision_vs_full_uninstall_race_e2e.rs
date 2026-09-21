// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real `provision_with_dependencies` vs. `full_uninstall` concurrency
//! proof (Phase 7B-B1-R3-B2-A2 §14-16). The prior pass's
//! `FULL_UNINSTALL_PROVISION_RACE_COUNT=0` was measured only against the
//! shared `lock_root_shared`/`lock_root_exclusive` primitive directly --
//! never against a real call into the production provisioning state
//! machine, since a real provision normally requires a network download.
//!
//! This test closes that gap without a new dependency and without any
//! network access: it runs a tiny local, single-connection HTTP server
//! (raw `std::net::TcpListener`, no framework) serving a real gzip-
//! compressed fixture binary, and points a real, hand-built
//! `ManagedComponentManifest` at it (`tarball_url: "http://127.0.0.1:<port>/..."`).
//! `provision_with_dependencies` is invoked exactly as production code
//! calls it -- same locking, same download/verify/extract/activate
//! pipeline (`ureq::get`, real SHA-256 verification, real gzip
//! decompression) -- the only substitution is the artifact's origin.
//!
//! The server intentionally blocks mid-response until explicitly released,
//! giving a real, non-sleep synchronization point: by the time the
//! server's `accept()` returns, `provision_with_dependencies` has already
//! acquired both `lock_root_shared` and its per-component lock (both
//! happen before the blocking download call in `provision_blocking`), so
//! a concurrent `full_uninstall(root)` racing for `lock_root_exclusive` at
//! that moment is racing against a real, in-flight provision -- not a
//! bare lock guard.
//!
//! Phase 7B-B1-R3-B2-B2-R4: the three real races synchronized specifically
//! at `full_uninstall`'s final-root-removal boundary (as opposed to the
//! generic lock-acquisition races this file still covers) now live as
//! internal `#[cfg(test)]` unit tests inside
//! `wht_corulix_tooling::provisioning::full_uninstall`'s own `mod tests`,
//! not here -- the synchronization hook they need
//! (`before_final_root_remove`) is `#[cfg(test)] pub(crate)`, deliberately
//! invisible to this external integration-test crate, so it never compiles
//! into a normal or release build and is never reachable by any downstream
//! consumer.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_tooling::provisioning::{
    self, ArchiveKind, ManagedArtifactSource, ManagedComponentId, ManagedComponentManifest,
    ManagedComponentState, SymlinkPolicy, full_uninstall, uninstall,
};

fn temp_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-provision-race-e2e-{label}-{stamp}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// A real gzip-compressed single-file artifact -- the same
/// `ArchiveKind::GzippedBinary` shape the real managed rust-analyzer
/// artifact uses, so `extract_gzipped_binary` runs unmodified production
/// code against it.
fn gzip_fixture_binary() -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(b"#!/bin/sh\necho corulix-race-fixture\n")
        .unwrap_or_else(|error| unreachable!("in-memory gzip write never fails: {error}"));
    encoder
        .finish()
        .unwrap_or_else(|error| unreachable!("in-memory gzip finish never fails: {error}"))
}

/// Starts a real, local, single-connection HTTP/1.1 server on an
/// OS-assigned loopback port. Accepts exactly one connection, reads its
/// request until the blank line, signals `accepted_tx` (the real
/// synchronization point this test relies on), blocks until `release_rx`
/// fires, then writes `body` as a `200 OK` response and closes.
fn spawn_gated_http_server(
    body: Vec<u8>,
    accepted_tx: std::sync::mpsc::Sender<()>,
    release_rx: std::sync::mpsc::Receiver<()>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
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
            let Ok(read) = stream.read(&mut buffer) else {
                return;
            };
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
        }

        let _ = accepted_tx.send(());
        let _ = release_rx.recv();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
    });

    (url, handle)
}

fn race_manifest(url: &str, sha256_hex: String) -> ManagedComponentManifest {
    race_manifest_with_id("race-fixture-component", url, sha256_hex)
}

fn race_manifest_with_id(
    id: &'static str,
    url: &str,
    sha256_hex: String,
) -> ManagedComponentManifest {
    ManagedComponentManifest {
        id: ManagedComponentId(id),
        version: "0.0.0",
        // Must match the real running host, not a fixed literal: this
        // manifest is fed straight into the real, unmodified
        // `provision_with_dependencies` pipeline, whose platform/
        // architecture admission gate (`validate_manifest_platform_architecture`
        // in `provisioning.rs`) fails closed -- correctly -- before any
        // network I/O whenever the manifest declares a foreign platform.
        // A hardcoded `"linux"` here made every real race in this file
        // fail immediately with `PlatformArchitectureMismatch` on a
        // non-Linux host, and for
        // `real_provision_in_flight_full_uninstall_does_not_observe_or_remove_it_early`
        // specifically, that early return meant the local HTTP server's
        // `accept()` never received the connection whose receipt this
        // test unconditionally blocks on (`accepted_rx.recv()`) -- an
        // unbounded, deterministic hang on any host where the literal
        // did not match, not a scheduling flake.
        platform: provisioning::host_platform_identifier(),
        architecture: provisioning::host_architecture_identifier(),
        source: ManagedArtifactSource {
            tarball_url: Box::leak(url.to_string().into_boxed_str()),
            expected_sha256_hex: Box::leak(sha256_hex.into_boxed_str()),
            binary_path_in_tarball: Box::leak(format!("bin/{id}").into_boxed_str()),
            archive_kind: ArchiveKind::GzippedBinary,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[],
    }
}

#[tokio::test]
async fn real_provision_in_flight_full_uninstall_does_not_observe_or_remove_it_early() {
    let root = temp_root("provision-inflight");
    let fixture_bytes = gzip_fixture_binary();
    let sha256_hex = wht_corulix_core::ContentHash::compute_sha256(&fixture_bytes).digest_hex;

    let (accepted_tx, accepted_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (url, server) = spawn_gated_http_server(fixture_bytes, accepted_tx, release_rx);
    let manifest = race_manifest(&url, sha256_hex);

    let provision_root = root.clone();
    let provision_task = tokio::spawn(async move {
        provisioning::provision_with_dependencies(&provision_root, &manifest, &[]).await
    });

    // Real synchronization: waits for the real HTTP server to observe the
    // real `ureq` request `provision_with_dependencies` issued, which can
    // only happen once `provision_blocking` -- and therefore both
    // `lock_root_shared` and the per-component lock -- has already run.
    // No sleep timing. Bounded (not an arbitrary substitute for the real
    // fix above -- `race_manifest_with_id` now always matches the real
    // host, so this receive is expected to succeed quickly): defense in
    // depth only, so any future regression that again prevents the
    // provision task from ever reaching the network fails this test
    // loudly and fast instead of hanging the suite indefinitely.
    let accepted =
        tokio::task::spawn_blocking(move || accepted_rx.recv_timeout(Duration::from_secs(30)))
            .await
            .unwrap_or_else(|error| unreachable!("spawn_blocking must not panic: {error}"));
    assert!(
        accepted.is_ok(),
        "the real local HTTP server must observe the real provision request"
    );

    let uninstall_root = root.clone();
    let full_uninstall_task =
        tokio::spawn(async move { full_uninstall::full_uninstall(&uninstall_root).await });

    // The exclusive root lock `full_uninstall` needs cannot be acquired
    // while the real in-flight provision holds the shared root lock (the
    // HTTP response is still gated), so it must still be pending here.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !full_uninstall_task.is_finished(),
        "full_uninstall must not proceed while a real provision is genuinely in flight"
    );

    // Release the real download; the real provision completes for real.
    let _ = release_tx.send(());
    let provision_outcome = provision_task
        .await
        .unwrap_or_else(|error| unreachable!("provision task must not panic: {error:?}"));
    assert!(
        provision_outcome.is_ok(),
        "the real provision must succeed once its real download is released: {provision_outcome:?}"
    );

    let full_uninstall_outcome = full_uninstall_task
        .await
        .unwrap_or_else(|error| unreachable!("full_uninstall task must not panic: {error:?}"));

    // Outcome invariant (mandate §16): either the provision finished before
    // full_uninstall acquired authority (so it is discovered and removed),
    // or full_uninstall owned authority first (so provision would have
    // waited/failed typed). Here the provision's real download was gated
    // to finish only after full_uninstall was already blocked waiting on
    // the exclusive lock, so the provision is guaranteed to complete and
    // publish its ownership record before full_uninstall can proceed --
    // the only outcome consistent with the real, deterministic ordering
    // this test enforces is that full_uninstall discovers and removes it.
    // What is checked either way, and is the actual forbidden case this
    // test exists to rule out: the component must never end up
    // `Available` after full_uninstall reports completion (never escapes
    // the transaction it started).
    let (state_after, _) = provisioning::resolve_managed_component(
        &root,
        &race_manifest("http://unused.invalid/", "0".repeat(64)),
    );
    assert_ne!(
        state_after,
        ManagedComponentState::Available,
        "the raced component must never remain Available once full_uninstall completes: \
         provision={provision_outcome:?} full_uninstall={full_uninstall_outcome:?}"
    );

    let _ = server.join();
    let _ = std::fs::remove_dir_all(&root);
}

/// §9-11 of Phase 7B-B1-R3-B2-A3: the prior test used a single, no-
/// dependency component. This proves the same real race for a
/// dependency-bearing manifest -- a real `provision_with_dependencies`
/// call for a *dependent* component naming a real, already-provisioned
/// *dependency* component id, racing a real `full_uninstall`. Both the
/// dependency and the dependent pass through the real download/integrity/
/// staging/activation/ownership pipeline; only the dependency's own
/// provisioning is left ungated (it must exist before the race begins),
/// while the dependent's download is the real synchronization point.
#[tokio::test]
async fn real_dependency_bearing_provision_race_never_leaves_either_component_escaped() {
    let root = temp_root("dependency-bearing-race");

    // Dependency, provisioned for real first (ungated -- released
    // immediately once the real HTTP request lands, no race needed here).
    let dependency_bytes = gzip_fixture_binary();
    let dependency_sha256 =
        wht_corulix_core::ContentHash::compute_sha256(&dependency_bytes).digest_hex;
    let (dep_accepted_tx, _dep_accepted_rx) = std::sync::mpsc::channel::<()>();
    let (dep_release_tx, dep_release_rx) = std::sync::mpsc::channel::<()>();
    let _ = dep_release_tx.send(());
    let (dependency_url, dependency_server) =
        spawn_gated_http_server(dependency_bytes, dep_accepted_tx, dep_release_rx);
    let dependency_manifest = race_manifest_with_id(
        "race-fixture-dependency",
        &dependency_url,
        dependency_sha256,
    );
    let dependency_outcome =
        provisioning::provision_with_dependencies(&root, &dependency_manifest, &[]).await;
    assert!(
        dependency_outcome.is_ok(),
        "the real dependency must provision successfully before the race begins: {dependency_outcome:?}"
    );
    let _ = dependency_server.join();

    // Dependent, real download gated for the actual race.
    let dependent_bytes = gzip_fixture_binary();
    let dependent_sha256 =
        wht_corulix_core::ContentHash::compute_sha256(&dependent_bytes).digest_hex;
    let (accepted_tx, accepted_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (dependent_url, dependent_server) =
        spawn_gated_http_server(dependent_bytes, accepted_tx, release_rx);
    let dependent_manifest =
        race_manifest_with_id("race-fixture-dependent", &dependent_url, dependent_sha256);

    let provision_root = root.clone();
    let provision_task = tokio::spawn(async move {
        provisioning::provision_with_dependencies(
            &provision_root,
            &dependent_manifest,
            &["race-fixture-dependency"],
        )
        .await
    });

    // Bounded for the same defense-in-depth reason as the single-component
    // race test above -- see that test's comment.
    let accepted =
        tokio::task::spawn_blocking(move || accepted_rx.recv_timeout(Duration::from_secs(30)))
            .await
            .unwrap_or_else(|error| unreachable!("spawn_blocking must not panic: {error}"));
    assert!(
        accepted.is_ok(),
        "the real local HTTP server must observe the real dependent-component provision request"
    );

    let uninstall_root = root.clone();
    let full_uninstall_task =
        tokio::spawn(async move { full_uninstall::full_uninstall(&uninstall_root).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !full_uninstall_task.is_finished(),
        "full_uninstall must not proceed while a real dependency-bearing provision is in flight"
    );

    let _ = release_tx.send(());
    let dependent_outcome = provision_task
        .await
        .unwrap_or_else(|error| unreachable!("provision task must not panic: {error:?}"));
    assert!(
        dependent_outcome.is_ok(),
        "the real dependent provision must succeed once released: {dependent_outcome:?}"
    );

    let full_uninstall_outcome = full_uninstall_task
        .await
        .unwrap_or_else(|error| unreachable!("full_uninstall task must not panic: {error:?}"));

    // Forbidden outcome this test exists to rule out: either the dependency
    // or the dependent escapes -- remains `Available` -- after
    // full_uninstall reports completion, regardless of which side won
    // lifecycle authority first.
    let (dependency_state_after, _) =
        provisioning::resolve_managed_component(&root, &dependency_manifest);
    let (dependent_state_after, _) =
        provisioning::resolve_managed_component(&root, &dependent_manifest);
    assert_ne!(
        dependency_state_after,
        ManagedComponentState::Available,
        "the dependency must never remain Available once full_uninstall completes: \
         dependent={dependent_outcome:?} full_uninstall={full_uninstall_outcome:?}"
    );
    assert_ne!(
        dependent_state_after,
        ManagedComponentState::Available,
        "the dependent must never remain Available once full_uninstall completes: \
         dependent={dependent_outcome:?} full_uninstall={full_uninstall_outcome:?}"
    );

    let _ = dependent_server.join();
    let _ = std::fs::remove_dir_all(&root);
}

/// Phase 7B-B1-R3-B2-B2-R2 §20-21: the real production single-component
/// `uninstall::uninstall` racing a real `full_uninstall` on the same root
/// -- not merely a bare `lock_root_shared`/`lock_root_exclusive` guard.
/// `uninstall`'s public `before_remove` hook (invoked once, after the real
/// shared root lock and per-component lock are already held, and after
/// real ownership/process-liveness validation has already passed, but
/// before the real quarantine rename) is the deterministic, non-sleep
/// synchronization point: it blocks on a real channel receive until this
/// test explicitly releases it, so a concurrent `full_uninstall` racing
/// for the exclusive root lock at that moment is racing a genuinely
/// in-flight, real component uninstall -- proving
/// `FINAL_ROOT_REMOVAL_VS_COMPONENT_UNINSTALL_REAL_E2E` and
/// `FINAL_ROOT_REMOVAL_LIFECYCLE_RACE_COUNT=0` with real production calls,
/// not a lock-only substitute.
// `before_remove` below blocks its own OS thread synchronously (a real,
// non-sleep synchronization point, not an `.await`) -- a `current_thread`
// runtime (this file's other tests' default) would deadlock the whole
// runtime on that call, since nothing else could run concurrently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_component_uninstall_in_flight_full_uninstall_race_never_produces_invalid_state() {
    let root = temp_root("component-uninstall-vs-full-uninstall-race");

    // Real component, provisioned for real first (ungated -- released
    // immediately once the real HTTP request lands; the race itself needs
    // no gate on provisioning, only on the uninstall that follows).
    let fixture_bytes = gzip_fixture_binary();
    let sha256_hex = wht_corulix_core::ContentHash::compute_sha256(&fixture_bytes).digest_hex;
    let (setup_accepted_tx, _setup_accepted_rx) = std::sync::mpsc::channel::<()>();
    let (setup_release_tx, setup_release_rx) = std::sync::mpsc::channel::<()>();
    let _ = setup_release_tx.send(());
    let (setup_url, setup_server) =
        spawn_gated_http_server(fixture_bytes, setup_accepted_tx, setup_release_rx);
    let manifest =
        race_manifest_with_id("race-component-vs-full-uninstall", &setup_url, sha256_hex);
    let provision_outcome = provisioning::provision_with_dependencies(&root, &manifest, &[]).await;
    assert!(
        provision_outcome.is_ok(),
        "the real component must provision successfully before the race begins: {provision_outcome:?}"
    );
    let _ = setup_server.join();

    let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

    let uninstall_root = root.clone();
    let uninstall_task = tokio::spawn(async move {
        uninstall::uninstall(
            &uninstall_root,
            ManagedComponentId("race-component-vs-full-uninstall"),
            move |_component_root| {
                // Real synchronous block, on the real task executing
                // `uninstall::uninstall`, while it already holds the real
                // shared root lock -- not a bare lock guard held directly
                // by the test.
                let _ = reached_tx.send(());
                let _ = release_rx.recv();
            },
        )
        .await
    });

    // Bounded for the same defense-in-depth reason as the provision-race
    // tests above -- see `real_provision_in_flight_full_uninstall_does_not_observe_or_remove_it_early`'s
    // comment.
    let reached =
        tokio::task::spawn_blocking(move || reached_rx.recv_timeout(Duration::from_secs(30)))
            .await
            .unwrap_or_else(|error| unreachable!("spawn_blocking must not panic: {error}"));
    assert!(
        reached.is_ok(),
        "the real component uninstall must reach its before_remove hook"
    );

    let full_uninstall_root = root.clone();
    let full_uninstall_task =
        tokio::spawn(async move { full_uninstall::full_uninstall(&full_uninstall_root).await });

    // The exclusive root lock `full_uninstall` needs cannot be acquired
    // while the real in-flight component uninstall holds the shared root
    // lock (still blocked in its own `before_remove` hook), so it must
    // still be pending here.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !full_uninstall_task.is_finished(),
        "full_uninstall must not proceed while a real component uninstall is genuinely in flight"
    );

    let _ = release_tx.send(());
    let uninstall_outcome = uninstall_task
        .await
        .unwrap_or_else(|error| unreachable!("uninstall task must not panic: {error:?}"));
    assert!(
        matches!(uninstall_outcome, Ok(uninstall::UninstallOutcome::Removed)),
        "the real component uninstall must succeed once released: {uninstall_outcome:?}"
    );

    let full_uninstall_outcome = full_uninstall_task
        .await
        .unwrap_or_else(|error| unreachable!("full_uninstall task must not panic: {error:?}"));
    // §21 ROOT_REMOVAL_POST_RACE_STATE_VALID: the component uninstall
    // genuinely completed (proven above) before `full_uninstall` could
    // acquire the exclusive lock, so `full_uninstall` must find nothing
    // CorulixManaged left to plan -- never a stale/partial view of a
    // component the concurrent uninstall already fully removed.
    assert_eq!(
        full_uninstall_outcome,
        Ok(full_uninstall::FullUninstallOutcome::NoManagedComponents),
        "FINAL_ROOT_REMOVAL_LIFECYCLE_RACE_COUNT!=0: full_uninstall observed inconsistent state: {full_uninstall_outcome:?}"
    );

    // No impossible post-race combination: component genuinely absent from
    // both the filesystem and ownership metadata, and the root itself
    // (now empty) was removed by `full_uninstall`'s own final cleanup --
    // real evidence, not inferred from the return value alone.
    let (state_after, _) = provisioning::resolve_managed_component(&root, &manifest);
    assert_ne!(
        state_after,
        ManagedComponentState::Available,
        "ROOT_REMOVAL_POST_RACE_STATE_VALID=FAIL: component remained Available after both real operations completed"
    );
    assert!(
        !root.exists(),
        "ROOT_REMOVAL_POST_RACE_STATE_VALID=FAIL: managed root survived a full_uninstall that found the root already empty of managed state"
    );

    let _ = std::fs::remove_dir_all(&root);
}
