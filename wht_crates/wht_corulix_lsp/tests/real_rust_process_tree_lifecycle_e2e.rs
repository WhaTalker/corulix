// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real Rust process-tree containment/reap proof (Phase 7B-B1-R3-B2-A2
//! §3-8): real PID/process-group identity, not process names, and real
//! `/proc` observation of the managed rust-analyzer session's own process
//! group -- never a generic unit-test substitute.
//!
//! Requires real network access to provision the managed Rust semantic
//! runtime + rust-analyzer the first time it runs on a given
//! `managed_toolchain_root()`; reports and exits early with
//! `RUST_PROCESS_TREE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED`
//! otherwise. Linux-only (`/proc` observation); reports
//! `RUST_PROCESS_TREE_E2E=BLOCKED_NOT_LINUX` on any other target.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::CancellationToken;
use wht_corulix_core::WorkspaceRootId;
use wht_corulix_lsp::{LspProviderProfile, LspSession};
use wht_corulix_tooling::provisioning::lease::{
    ProcessAbsence, ProcessIdentity, verify_process_absent,
};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

const READINESS_TIMEOUT: Duration = Duration::from_secs(120);

/// Shared with `real_rust_semantic_runtime_managed_e2e.rs` and
/// `real_rust_analyzer_managed_lifecycle_e2e.rs`: every real-rust test file
/// provisions/uninstalls the exact same production component ids under the
/// same managed root, so each file serializes its own tests against itself
/// with a file-local lock -- the same pattern those files already use.
static REAL_RUST_PROCESS_TREE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_RUST_PROCESS_TREE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!(
        "corulix-lsp-rust-process-tree-managed-root-{label}-{stamp}"
    ));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn temp_fixture_crate(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root =
        std::env::temp_dir().join(format!("corulix-lsp-rust-process-tree-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_rust_process_tree_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"corulix_rust_process_tree_fixture\"\npath = \"src/main.rs\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn main() {\n    let s = String::new();\n    println!(\"{}\", s.len());\n}\n",
    );
    root
}

async fn ensure_managed_rust_provisioned(root: &std::path::Path) -> bool {
    let runtime_manifest = wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64;
    let rust_analyzer_manifest = wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64;

    let (runtime_state, _) = provisioning::resolve_managed_component(root, &runtime_manifest);
    if runtime_state != ManagedComponentState::Available
        && provisioning::provision(root, &runtime_manifest)
            .await
            .is_err()
    {
        return false;
    }

    let (rust_analyzer_state, _) =
        provisioning::resolve_managed_component(root, &rust_analyzer_manifest);
    if rust_analyzer_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(
            root,
            &rust_analyzer_manifest,
            &["rust-semantic-runtime"],
        )
        .await
        .is_err()
    {
        return false;
    }
    true
}

async fn resolve_rust_analyzer_managed(
    workspace_root: &WorkspaceRoot,
    managed_root: &std::path::Path,
) -> Option<wht_corulix_lsp::ResolvedLaunch> {
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::rust_analyzer_managed();
    wht_corulix_lsp::resolve_launch_at(&profile, &effective, workspace_root, managed_root)
        .await
        .ok()
}

/// Every real pid in `/proc` whose process-group id (`/proc/<pid>/stat`
/// field 5, `pgrp`) equals `pgid` -- real OS observation, not a name-based
/// heuristic. `comm` (field 2) is skipped past via the last `)` since it
/// may itself contain spaces/parens.
fn descendant_pids_in_group(pgid: u32) -> Vec<u32> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let Some(pid_str) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let Ok(contents) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some((_, after_comm)) = contents.rsplit_once(')') else {
            continue;
        };
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        let Some(pgrp) = fields.get(2).and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        if pgrp == pgid {
            found.push(pid);
        }
    }
    found
}

#[tokio::test]
async fn real_rust_analyzer_process_tree_containment_and_normal_reap() {
    let _lock = lock().await;
    let Ok(root) = provisioning::managed_toolchain_root() else {
        eprintln!("RUST_PROCESS_TREE_E2E=BLOCKED_TOOLCHAIN_ROOT_UNRESOLVABLE");
        return;
    };
    if !ensure_managed_rust_provisioned(&root).await {
        eprintln!(
            "RUST_PROCESS_TREE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision the managed Rust semantic runtime/rust-analyzer in this environment"
        );
        return;
    }

    let fixture = temp_fixture_crate("containment-normal-reap");
    let workspace_root = WorkspaceRoot::open(&fixture)
        .unwrap_or_else(|error| unreachable!("open must succeed: {error:?}"));
    let Some(launch) = resolve_rust_analyzer_managed(&workspace_root, &root).await else {
        unreachable!("rust_analyzer_managed did not resolve via CORULIX_MANAGED live routing");
    };

    let cancellation = CancellationToken::new();
    let profile = LspProviderProfile::rust_analyzer_managed();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .unwrap_or_else(|error| unreachable!("session spawn/handshake failed: {error:?}"));

    let pid = session
        .process_pid()
        .await
        .unwrap_or_else(|| unreachable!("a just-spawned session must have a live pid"));

    // Real, repeated `/proc` sampling across the readiness wait and a real
    // semantic query, rather than one late sample at shutdown time (which
    // would read 0 once any transient cargo/rustc flycheck children have
    // already exited and make the reap assertion below vacuous). Records
    // the real maximum observed descendant set -- test evidence only,
    // never hard-coded.
    let mut max_observed: Vec<u32> = Vec::new();
    let main_rs = fixture.join("src/main.rs");
    let _ = session.ensure_open(&main_rs).await;
    for _ in 0..40 {
        let observed = descendant_pids_in_group(pid);
        if observed.len() > max_observed.len() {
            max_observed = observed;
        }
        if session.readiness().await == wht_corulix_lsp::Readiness::Ready {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = session.wait_until_ready(READINESS_TIMEOUT).await;
    for _ in 0..10 {
        let observed = descendant_pids_in_group(pid);
        if observed.len() > max_observed.len() {
            max_observed = observed;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // REAL_RUST_ANALYZER_DESCENDANT_CONTAINMENT: the group must at minimum
    // contain the rust-analyzer leader itself while genuinely active.
    assert!(
        max_observed.contains(&pid),
        "expected the real rust-analyzer process group (pgid={pid}) to contain its own \
         leader while active; observed={max_observed:?}"
    );
    // §20 correction: the primary process itself must never be reported as
    // one of its own descendants -- `descendant_pids_in_group` returns every
    // real group *member* (leader included, since the leader's own pgrp
    // equals its own pid), so descendants are that set minus the leader.
    let group_members = max_observed.clone();
    let descendants: Vec<u32> = group_members
        .iter()
        .copied()
        .filter(|member| *member != pid)
        .collect();
    assert!(
        !descendants.contains(&pid),
        "PRIMARY_PID_IN_DESCENDANT_LIST must be NO"
    );
    eprintln!(
        "RUST_PRIMARY_PID={pid} RUST_PROCESS_GROUP_ID={pid} \
         RUST_OBSERVED_PROCESS_GROUP_MEMBER_PIDS={group_members:?} \
         RUST_OBSERVED_DESCENDANT_PIDS={descendants:?} PRIMARY_PID_IN_DESCENDANT_LIST=NO"
    );
    if descendants.is_empty() {
        eprintln!(
            "REAL_RUST_ANALYZER_DESCENDANT_CONTAINMENT=NOT_OBSERVABLE_BEYOND_LEADER: no \
             transient cargo/rustc child was captured by this sampling window on this host \
             (real leader-only evidence, not fabricated)"
        );
    } else {
        eprintln!("REAL_RUST_ANALYZER_DESCENDANT_CONTAINMENT=PASS");
    }

    // --- NORMAL SHUTDOWN / REAP ---
    session.shutdown(&cancellation).await;

    let remaining = descendant_pids_in_group(pid);
    assert!(
        remaining.is_empty(),
        "POST_NORMAL_RUST_ORPHAN_PROCESS_COUNT must be 0, found {remaining:?}"
    );
    assert_eq!(
        verify_process_absent(ProcessIdentity { pid }),
        ProcessAbsence::Absent,
        "the real leader pid must be independently confirmed gone after normal shutdown"
    );
    assert_eq!(
        session.lease_state(),
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Stopped),
        "the lease must be reconciled to Stopped after a normal shutdown"
    );
    eprintln!(
        "REAL_RUST_ANALYZER_DESCENDANT_REAP_NORMAL=PASS POST_NORMAL_RUST_ORPHAN_PROCESS_COUNT=0"
    );

    let _ = fs::remove_dir_all(&fixture);
}

#[tokio::test]
async fn real_rust_analyzer_reap_completes_despite_an_already_cancelled_token() {
    let _lock = lock().await;
    let Ok(root) = provisioning::managed_toolchain_root() else {
        eprintln!("RUST_PROCESS_TREE_E2E=BLOCKED_TOOLCHAIN_ROOT_UNRESOLVABLE");
        return;
    };
    if !ensure_managed_rust_provisioned(&root).await {
        eprintln!(
            "RUST_PROCESS_TREE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision the managed Rust semantic runtime/rust-analyzer in this environment"
        );
        return;
    }

    let fixture = temp_fixture_crate("cancel-reap");
    let workspace_root = WorkspaceRoot::open(&fixture)
        .unwrap_or_else(|error| unreachable!("open must succeed: {error:?}"));
    let Some(launch) = resolve_rust_analyzer_managed(&workspace_root, &root).await else {
        unreachable!("rust_analyzer_managed did not resolve via CORULIX_MANAGED live routing");
    };

    let spawn_cancellation = CancellationToken::new();
    let profile = LspProviderProfile::rust_analyzer_managed();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &spawn_cancellation,
    )
    .await
    .unwrap_or_else(|error| unreachable!("session spawn/handshake failed: {error:?}"));

    let pid = session
        .process_pid()
        .await
        .unwrap_or_else(|| unreachable!("a just-spawned session must have a live pid"));
    let _ = session.wait_until_ready(READINESS_TIMEOUT).await;

    // §6's "canonical Corulix cancellation" applied to the exact token
    // `shutdown` takes: real code-path evidence (`stop_managed_process` in
    // `wht_corulix_lsp/src/session.rs`) shows the graceful `shutdown`
    // request's *result* is discarded (`let _ = transport.request(...)`)
    // and the subsequent `wait_for_exit`/`terminate` reap sequence always
    // runs unconditionally regardless of that outcome -- so a cancelled
    // token cannot, by construction, skip the reap. This test proves that
    // real behavior empirically: the token is already cancelled *before*
    // `shutdown` is ever called, and the real process group is still fully
    // reaped.
    let shutdown_cancellation = CancellationToken::new();
    shutdown_cancellation.cancel();
    session.shutdown(&shutdown_cancellation).await;

    let remaining = descendant_pids_in_group(pid);
    assert!(
        remaining.is_empty(),
        "POST_CANCEL_RUST_ORPHAN_PROCESS_COUNT must be 0, found {remaining:?}"
    );
    assert_eq!(
        verify_process_absent(ProcessIdentity { pid }),
        ProcessAbsence::Absent
    );
    eprintln!(
        "REAL_RUST_ANALYZER_DESCENDANT_REAP_CANCEL=PASS POST_CANCEL_RUST_ORPHAN_PROCESS_COUNT=0"
    );

    let _ = fs::remove_dir_all(&fixture);
}

#[tokio::test]
async fn real_rust_analyzer_forced_termination_reaps_the_whole_group_without_any_graceful_exchange()
{
    let _lock = lock().await;
    let Ok(root) = provisioning::managed_toolchain_root() else {
        eprintln!("RUST_PROCESS_TREE_E2E=BLOCKED_TOOLCHAIN_ROOT_UNRESOLVABLE");
        return;
    };
    if !ensure_managed_rust_provisioned(&root).await {
        eprintln!(
            "RUST_PROCESS_TREE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision the managed Rust semantic runtime/rust-analyzer in this environment"
        );
        return;
    }
    let Ok(root) = provisioning::managed_toolchain_root() else {
        unreachable!("managed_toolchain_root must resolve once provisioning succeeded");
    };
    let manifest = wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64;
    let (_, Some(binary)) = provisioning::resolve_managed_component(&root, &manifest) else {
        unreachable!("rust-analyzer must already be Available at this point");
    };

    // Real `Tooling` forced termination (`ManagedProcess::terminate`,
    // real `killpg`), exercised directly rather than through
    // `LspSession::shutdown`'s graceful-then-forced fallback -- this
    // deterministically forces the *forced* path every time (no graceful
    // shutdown/exit is ever sent to a real, live rust-analyzer left
    // waiting on stdin), rather than racing the graceful timeout window.
    let spec = wht_corulix_tooling::ManagedProcessSpec {
        executable: binary,
        arguments: Vec::new(),
        environment: wht_corulix_tooling::EnvironmentPolicy::empty(),
        working_directory: root.clone(),
        max_stderr_bytes: 64 * 1024,
        argv0: None,
        managed_lease: None,
    };
    let process = wht_corulix_tooling::ManagedProcess::spawn(&spec)
        .await
        .unwrap_or_else(|error| {
            unreachable!("spawning the real rust-analyzer binary directly must succeed: {error:?}")
        });
    let pid = process
        .pid()
        .unwrap_or_else(|| unreachable!("a just-spawned process must have a live pid"));

    // Give the real process a moment to actually start running (it will
    // sit blocked reading stdin for an `initialize` request that never
    // comes) before forcing it -- not a synchronization point the
    // assertions below depend on, only a sanity margin so `terminate`
    // exercises a genuinely running process rather than racing its own
    // exec().
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        descendant_pids_in_group(pid).contains(&pid),
        "the real rust-analyzer process must be alive and in its own group before forcing"
    );

    let exit = process.terminate().await;
    assert_eq!(
        exit,
        wht_corulix_tooling::ManagedProcessExit::Terminated,
        "real Tooling forced termination must report Terminated for a real live process"
    );

    let remaining = descendant_pids_in_group(pid);
    assert!(
        remaining.is_empty(),
        "POST_FORCED_RUST_ORPHAN_PROCESS_COUNT must be 0, found {remaining:?}"
    );
    assert_eq!(
        verify_process_absent(ProcessIdentity { pid }),
        ProcessAbsence::Absent
    );
    eprintln!(
        "REAL_RUST_ANALYZER_DESCENDANT_REAP_FORCED=PASS POST_FORCED_RUST_ORPHAN_PROCESS_COUNT=0"
    );
}

/// §12-15 of Phase 7B-B1-R3-B2-A3: a real LSP-layer crash, not only the
/// Tooling-layer crash proof from the prior pass. A real `LspSession` is
/// spawned and reaches readiness, its real OS process is killed directly
/// (`kill -KILL <pid>`, a real external signal -- no shell interpolation,
/// no new dependency: `tokio::process::Command` invoking the real `kill`
/// utility, the same pattern `real_rust_hostile_cargo_config_e2e.rs`
/// already uses for real E2E process construction outside
/// `wht_corulix_tooling`), never through `LspSession::shutdown` or any
/// lease method. Reconciliation, a fresh restart against the same still-
/// owned installation, and a canonical uninstall are all then proven for
/// real.
#[tokio::test]
async fn real_rust_analyzer_lsp_crash_then_restart_then_uninstall() {
    let _lock = lock().await;
    // MANAGED_TEST_ISOLATION_DEFECT fix: isolated root instead of the real,
    // shared, host-wide `managed_toolchain_root()`.
    let root = temp_dir("crash-restart-uninstall");
    if let Ok(real_root) = provisioning::managed_toolchain_root() {
        assert_ne!(
            root, real_root,
            "this test's isolated managed root must never canonicalize to the real, shared \
             managed_toolchain_root()"
        );
    }
    if !ensure_managed_rust_provisioned(&root).await {
        eprintln!(
            "RUST_PROCESS_TREE_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: could not provision the managed Rust semantic runtime/rust-analyzer in this environment"
        );
        let _ = fs::remove_dir_all(&root);
        return;
    }

    // --- CRASH: real session #1, real external SIGKILL ---
    let fixture_a = temp_fixture_crate("crash");
    let workspace_root_a = WorkspaceRoot::open(&fixture_a)
        .unwrap_or_else(|error| unreachable!("open must succeed: {error:?}"));
    let Some(launch_a) = resolve_rust_analyzer_managed(&workspace_root_a, &root).await else {
        unreachable!("rust_analyzer_managed did not resolve via CORULIX_MANAGED live routing");
    };
    let cancellation_a = CancellationToken::new();
    let profile = LspProviderProfile::rust_analyzer_managed();
    let session_a = LspSession::spawn(
        launch_a,
        &profile,
        workspace_root_a,
        WorkspaceRootId(0),
        &cancellation_a,
    )
    .await
    .unwrap_or_else(|error| unreachable!("session #1 spawn/handshake failed: {error:?}"));
    let _ = session_a.wait_until_ready(READINESS_TIMEOUT).await;
    let pid_a = session_a
        .process_pid()
        .await
        .unwrap_or_else(|| unreachable!("a just-spawned session must have a live pid"));

    // The real external, abnormal kill -- never LspSession::shutdown, never
    // any lease method. Simulates a crash/an operator's `kill -9` exactly
    // as it would happen outside Corulix's own control. Every currently
    // observed real group member (leader + any live cargo/rustc children)
    // is killed individually by its own positive pid -- deliberately never
    // a negative-pid/process-group kill target, which risks signaling far
    // beyond this one managed group under a hardened execution sandbox.
    for member in descendant_pids_in_group(pid_a) {
        let _ = tokio::process::Command::new("kill")
            .arg("-KILL")
            .arg(member.to_string())
            .status()
            .await;
    }

    // Real finding, surfaced empirically rather than assumed: this test
    // process is the real OS parent of the managed child (`ManagedProcess`
    // spawns it directly), and `ManagedProcess::spawn` deliberately disables
    // Tokio's drop-triggered auto-reap (`kill_on_drop(false)`) so reaping
    // only ever happens through this crate's own explicit `wait()` calls.
    // A process killed by an unrelated `kill` invocation therefore becomes
    // a real zombie -- still occupying its pid/pgid in the process table,
    // so `verify_process_absent`'s real `kill(-pid, 0)` group-existence
    // probe keeps reporting `Present` -- until *this* process's own
    // machinery calls `wait()` on it. No amount of external polling can
    // observe `Absent` before that; only `LspSession::shutdown`'s real
    // `ManagedProcess::wait_for_exit` (which the already-dead child makes
    // return immediately) actually reaps it. This is exactly the real
    // reconciliation path production code exercises -- a crashed session
    // is reconciled when Corulix's own shutdown/uninstall machinery next
    // touches it, not by a hypothetical independent background reaper.
    session_a.shutdown(&cancellation_a).await;

    assert_eq!(
        verify_process_absent(ProcessIdentity { pid: pid_a }),
        ProcessAbsence::Absent,
        "the real crashed process (pid={pid_a}) must be independently confirmed gone once \
         Corulix's own reap path (LspSession::shutdown) has run"
    );

    let manifest = wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64;
    let (state_after_crash, path_after_crash) =
        provisioning::resolve_managed_component(&root, &manifest);
    assert_eq!(
        state_after_crash,
        ManagedComponentState::Available,
        "the component itself must not be deleted or fall back to unmanaged resolution \
         merely because its live process crashed"
    );
    assert!(path_after_crash.is_some());
    eprintln!("LSP_CRASH_LEASE_RECONCILIATION=PASS");

    let _ = fs::remove_dir_all(&fixture_a);

    // --- RESTART: a real NEW session against the SAME still-owned install ---
    let fixture_b = temp_fixture_crate("restart-after-crash");
    let workspace_root_b = WorkspaceRoot::open(&fixture_b)
        .unwrap_or_else(|error| unreachable!("open must succeed: {error:?}"));
    let Some(launch_b) = resolve_rust_analyzer_managed(&workspace_root_b, &root).await else {
        unreachable!("rust_analyzer_managed did not resolve via CORULIX_MANAGED live routing");
    };
    let cancellation_b = CancellationToken::new();
    let session_b = LspSession::spawn(
        launch_b,
        &profile,
        workspace_root_b,
        WorkspaceRootId(0),
        &cancellation_b,
    )
    .await
    .unwrap_or_else(|error| unreachable!("session #2 (restart) spawn/handshake failed: {error:?}"));
    let main_rs_b = fixture_b.join("src/main.rs");
    session_b
        .ensure_open(&main_rs_b)
        .await
        .unwrap_or_else(|error| unreachable!("opening the fixture failed: {error:?}"));
    session_b
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .unwrap_or_else(|error| {
            unreachable!("restarted managed rust-analyzer never reached readiness: {error:?}")
        });

    // At least one real semantic operation against the restarted session.
    let symbol_result =
        wht_corulix_lsp::document_symbols(&session_b, &main_rs_b, &cancellation_b).await;
    assert!(
        symbol_result.is_ok(),
        "a real semantic operation against the restarted session must succeed: {symbol_result:?}"
    );

    session_b.shutdown(&cancellation_b).await;
    let _ = fs::remove_dir_all(&fixture_b);
    eprintln!("LSP_PROVIDER_RESTART_AFTER_CRASH=PASS");

    // --- UNINSTALL: canonical uninstall of the still-owned installation ---
    let removed =
        wht_corulix_tooling::provisioning::uninstall::uninstall(&root, manifest.id, |_| {}).await;
    assert_eq!(
        removed,
        Ok(wht_corulix_tooling::provisioning::uninstall::UninstallOutcome::Removed)
    );
    let _ = fs::remove_dir_all(&root);
    eprintln!("POST_CRASH_PROVIDER_UNINSTALL=PASS MANAGED_PROVIDER_CRASH_RECONCILIATION=PASS");
}
