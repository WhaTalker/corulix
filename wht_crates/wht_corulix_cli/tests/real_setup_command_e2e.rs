// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real, end-to-end proof of `corulix setup` (Installation-Contract-V1
//! §13-15): every test here spawns the actual compiled `corulix` binary
//! (`CARGO_BIN_EXE_corulix`, the same mechanism `real_f1_host_config_e2e.rs`
//! already establishes) as a real child process with `XDG_DATA_HOME`/
//! `LOCALAPPDATA`/`APPDATA` all redirected to a fresh, isolated directory
//! (see [`run_setup`]'s own doc comment) -- this suite never touches the
//! real shared host-wide managed-toolchain root, on any platform
//! `managed_toolchain_root()` supports (a native Windows certification run
//! of this file, before this fix, proved that `XDG_DATA_HOME` alone is
//! Unix-only and silently falls through to the real shared root on
//! Windows).
//!
//! `setup` is a plain CLI command, not an MCP tool -- these tests read the
//! spawned process's own stdout/stderr/exit status directly rather than
//! speaking MCP client protocol over stdio.
//!
//! **This file is also the §46 `--ignore-scripts` first-run recovery
//! proof.** Every test here spawns the real binary directly against a
//! fresh, never-bootstrapped `XDG_DATA_HOME` with no npm postinstall script
//! (`wht_packages/npm/corulix/postinstall.js`) ever having run against it --
//! exactly the state a consumer who ran `npm install --ignore-scripts`
//! would be in. That the binary still bootstraps
//! (`ensure_bootstrapped`/`FIRST_RUN_RECONCILIATION`) and reconciles
//! correctly from nothing in every test below is the direct evidence that
//! postinstall is never load-bearing, not a separate, redundant test.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn corulix_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_corulix"))
}

fn temp_data_home(label: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("corulix-cli-setup-e2e-{label}-{pid}-{stamp}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Mirrors `wht_corulix_tooling::provisioning::managed_toolchain_root()`'s
/// own per-platform join exactly (Unix: `<data_home>/corulix/managed-toolchain`;
/// Windows: `<data_home>\Corulix\managed-toolchain`, capitalized) -- see the
/// doc comment on [`run_setup`] for why `data_home` alone does not isolate
/// the spawned process on Windows without the accompanying env overrides.
fn managed_root_under(data_home: &Path) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        data_home.join("Corulix").join("managed-toolchain")
    }
    #[cfg(not(target_os = "windows"))]
    {
        data_home.join("corulix").join("managed-toolchain")
    }
}

/// Isolates the spawned `corulix` process into `data_home` for every
/// platform `managed_toolchain_root()` supports, not just Unix.
/// `XDG_DATA_HOME` alone is a Unix-only isolation mechanism -- Windows's own
/// `managed_toolchain_root()` (`wht_crates/wht_corulix_tooling/src/
/// provisioning.rs`) never reads it, resolving via `LOCALAPPDATA` (falling
/// back to `APPDATA`) instead. Setting `XDG_DATA_HOME` alone therefore
/// silently falls through to the REAL, SHARED, host-wide managed-toolchain
/// root on native Windows -- confirmed the hard way: a real native Windows
/// test run of this exact function persisted a `SELECTIVE` install profile
/// into the real shared root, contaminating it for other tests/processes on
/// that host. All three env vars are set unconditionally (harmless on
/// platforms that don't consult them) so this isolation is genuinely
/// platform-complete rather than Unix-only.
fn run_setup(data_home: &Path, args: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(corulix_binary());
    command
        .arg("setup")
        .args(args)
        .env("XDG_DATA_HOME", data_home)
        .env("LOCALAPPDATA", data_home)
        .env("APPDATA", data_home);
    Ok(command.output()?)
}

fn network_reachable() -> bool {
    Command::new("curl")
        .args(["-sI", "--max-time", "10", "https://static.rust-lang.org/"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `InstallProfileError` does not implement `std::error::Error` (it is a
/// plain, closed diagnostic enum, matching this workspace's own convention
/// for provisioning-layer errors) -- this wraps it for this suite's
/// `Box<dyn Error>`-returning tests, mirroring
/// `real_f6_production_managed_provisioning_e2e.rs`'s own `map_err` idiom.
fn load_profile(
    root: &Path,
) -> Result<
    Option<wht_corulix_tooling::provisioning::install_profile::InstallProfile>,
    Box<dyn std::error::Error>,
> {
    wht_corulix_tooling::provisioning::install_profile::load(root)
        .map_err(|error| format!("loading the persisted install profile failed: {error:?}").into())
}

/// `--only python` must reach real, dependency-ordered reconciliation and
/// persist the *expanded* component set (`pyright` + its own transitive
/// `node-runtime` dependency), never the raw group name "python" -- this is
/// the exact fix a later `grants_intent(root, "node-runtime")` check below
/// depends on: if the CLI persisted `{"python"}` literally instead of the
/// expanded ids, this check would fail closed even though pyright is fully
/// provisioned and owned.
#[tokio::test]
async fn real_setup_only_python_persists_expanded_set_and_reconciles()
-> Result<(), Box<dyn std::error::Error>> {
    if !network_reachable() {
        eprintln!("SKIPPED: NO_NETWORK (static.rust-lang.org unreachable)");
        return Ok(());
    }

    let data_home = temp_data_home("only-python");
    let output = run_setup(&data_home, &["--only", "python"])?;
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "expected success, got status {:?}, stdout: {out}, stderr: {}",
        output.status,
        stderr(&output)
    );
    assert!(out.contains("SETUP_STATUS=READY"), "stdout: {out}");
    assert!(out.contains("COMPONENT=pyright"), "stdout: {out}");
    assert!(out.contains("COMPONENT=node-runtime"), "stdout: {out}");

    let managed_root = managed_root_under(&data_home);
    let persisted = load_profile(&managed_root)?
        .ok_or("expected a persisted install profile after `setup --only python`")?;
    let wht_corulix_tooling::provisioning::install_profile::InstallProfile::Selective {
        components,
    } = persisted
    else {
        return Err("expected a Selective profile after --only python".into());
    };
    assert!(components.contains("pyright"));
    assert!(
        components.contains("node-runtime"),
        "the persisted set must be the *expanded* closure, not the raw group name -- \
         a later on-demand resolution of node-runtime consults this set directly"
    );
    assert!(
        wht_corulix_tooling::provisioning::install_profile::grants_intent(
            &managed_root,
            "node-runtime"
        ),
        "grants_intent must see the expanded dependency as persisted, not just \"python\""
    );

    let _ = wht_corulix_tooling::provisioning::full_uninstall::uninstall_all_corulix_managed_components_at(&managed_root).await;
    let _ = std::fs::remove_dir_all(&data_home);
    Ok(())
}

/// `--profile on-demand` persists without ever attempting reconciliation --
/// no network access required, deterministic.
#[test]
fn real_setup_on_demand_persists_without_reconciling() -> Result<(), Box<dyn std::error::Error>> {
    let data_home = temp_data_home("on-demand");
    let output = run_setup(&data_home, &["--profile", "on-demand"])?;
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "stdout: {out}, stderr: {}",
        stderr(&output)
    );
    assert!(out.contains("INSTALL_PROFILE=ON_DEMAND"), "stdout: {out}");
    assert!(
        out.contains("RECONCILIATION_STATUS=SKIPPED_ON_DEMAND"),
        "stdout: {out}"
    );

    let managed_root = managed_root_under(&data_home);
    let persisted = load_profile(&managed_root)?;
    assert_eq!(
        persisted,
        Some(wht_corulix_tooling::provisioning::install_profile::InstallProfile::OnDemand)
    );

    let _ = std::fs::remove_dir_all(&data_home);
    Ok(())
}

/// `--profile on-demand` combined with `--only`/`--exclude` is a
/// contradictory selection: rejected before any persistence, exit code 7,
/// nothing written to disk.
#[test]
fn real_setup_rejects_on_demand_combined_with_only() -> Result<(), Box<dyn std::error::Error>> {
    let data_home = temp_data_home("conflict-on-demand-only");
    let output = run_setup(&data_home, &["--profile", "on-demand", "--only", "rust"])?;
    assert_eq!(output.status.code(), Some(7), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("SETUP_STATUS=REJECTED"));

    let managed_root = managed_root_under(&data_home);
    assert_eq!(
        load_profile(&managed_root)?,
        None,
        "a rejected invocation must persist nothing"
    );

    let _ = std::fs::remove_dir_all(&data_home);
    Ok(())
}

/// An unrecognized group name is rejected with the valid-group list named in
/// the diagnostic, exit code 7, nothing persisted.
#[test]
fn real_setup_rejects_an_unrecognized_group() -> Result<(), Box<dyn std::error::Error>> {
    let data_home = temp_data_home("unrecognized-group");
    let output = run_setup(&data_home, &["--only", "not-a-real-group"])?;
    assert_eq!(output.status.code(), Some(7), "stderr: {}", stderr(&output));
    let err = stderr(&output);
    assert!(err.contains("not-a-real-group"), "stderr: {err}");
    assert!(err.contains("VALID_GROUPS="), "stderr: {err}");

    let managed_root = managed_root_under(&data_home);
    assert_eq!(load_profile(&managed_root)?, None);

    let _ = std::fs::remove_dir_all(&data_home);
    Ok(())
}

/// A bare `corulix setup` (no profile-selecting flag at all) must never
/// overwrite an already-persisted explicit choice -- only
/// `ensure_bootstrapped`'s own "absent -> Full" default applies when nothing
/// has ever been chosen. Proven here by persisting `on-demand` first, then
/// invoking bare `setup` and confirming the profile is untouched.
#[test]
fn real_setup_bare_invocation_never_overwrites_an_explicit_prior_choice()
-> Result<(), Box<dyn std::error::Error>> {
    let data_home = temp_data_home("bare-preserves-explicit");
    let first = run_setup(&data_home, &["--profile", "on-demand"])?;
    assert!(first.status.success(), "stderr: {}", stderr(&first));

    let second = run_setup(&data_home, &[])?;
    let out = stdout(&second);
    assert!(
        second.status.success(),
        "stdout: {out}, stderr: {}",
        stderr(&second)
    );
    assert!(
        out.contains("INSTALL_PROFILE=ON_DEMAND"),
        "bare `setup` must report the already-persisted OnDemand choice, not overwrite it \
         to FULL: stdout: {out}"
    );
    assert!(out.contains("RECONCILIATION_STATUS=SKIPPED_ON_DEMAND"));

    let managed_root = managed_root_under(&data_home);
    assert_eq!(
        load_profile(&managed_root)?,
        Some(wht_corulix_tooling::provisioning::install_profile::InstallProfile::OnDemand)
    );

    let _ = std::fs::remove_dir_all(&data_home);
    Ok(())
}

/// Profile-transition safety across two real, sequential `setup`
/// invocations against the same managed root (Installation-Contract-V1
/// §32): growing the selection must not redundantly re-acquire an
/// already-owned overlap, and shrinking it back must not delete a component
/// that dropped out of the persisted set -- the reconciler's own doc
/// comment claims "never removes/uninstalls anything not in the desired
/// set"; this proves that claim through the real CLI path rather than
/// leaving it as an unverified comment.
#[tokio::test]
async fn real_setup_growing_then_shrinking_the_selection_never_redownloads_or_deletes()
-> Result<(), Box<dyn std::error::Error>> {
    if !network_reachable() {
        eprintln!("SKIPPED: NO_NETWORK (static.rust-lang.org unreachable)");
        return Ok(());
    }

    let data_home = temp_data_home("transition");
    let managed_root = managed_root_under(&data_home);

    // Step 1: `--only python` acquires pyright + node-runtime.
    let step1 = run_setup(&data_home, &["--only", "python"])?;
    assert!(step1.status.success(), "stderr: {}", stderr(&step1));

    // Step 2: grow to `--only rust,python`. The python overlap must be
    // reported AlreadyReady (no redundant redownload); the newly-added rust
    // components must be Acquired.
    let step2 = run_setup(&data_home, &["--only", "rust,python"])?;
    let out2 = stdout(&step2);
    assert!(
        step2.status.success(),
        "stdout: {out2}, stderr: {}",
        stderr(&step2)
    );
    assert!(
        out2.contains("COMPONENT=pyright STATUS=ALREADY_READY"),
        "growing the selection must not redundantly re-acquire the python overlap: {out2}"
    );
    assert!(
        out2.contains("COMPONENT=node-runtime STATUS=ALREADY_READY"),
        "stdout: {out2}"
    );
    assert!(
        out2.contains("COMPONENT=rust-analyzer STATUS=ACQUIRED"),
        "stdout: {out2}"
    );
    assert!(
        out2.contains("COMPONENT=rustfmt STATUS=ACQUIRED"),
        "stdout: {out2}"
    );

    // Step 3: shrink back to `--only python`. Persisted set drops the rust
    // components, but their ownership records must still be present on
    // disk -- reconciling toward a smaller desired set is not an uninstall.
    let step3 = run_setup(&data_home, &["--only", "python"])?;
    let out3 = stdout(&step3);
    assert!(
        step3.status.success(),
        "stdout: {out3}, stderr: {}",
        stderr(&step3)
    );
    assert!(
        out3.contains("COMPONENT=pyright STATUS=ALREADY_READY"),
        "stdout: {out3}"
    );
    assert!(
        !out3.contains("rust-analyzer") && !out3.contains("rustfmt"),
        "rust components dropped out of the persisted set must not even be visited by \
         reconciliation: {out3}"
    );

    let persisted = load_profile(&managed_root)?
        .ok_or("expected a persisted profile after the third invocation")?;
    let wht_corulix_tooling::provisioning::install_profile::InstallProfile::Selective {
        components,
    } = persisted
    else {
        return Err("expected a Selective profile".into());
    };
    assert!(
        !components.contains("rust-analyzer"),
        "the persisted set must have shrunk back down"
    );

    let rust_analyzer_manifest = wht_corulix_engine::registry::find("rust-analyzer")
        .and_then(wht_corulix_engine::registry::ComponentEntry::manifest_for_host)
        .ok_or("rust-analyzer must have a manifest on this host")?;
    let (rust_analyzer_state, _) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component(
            &managed_root,
            &rust_analyzer_manifest,
        );
    assert_eq!(
        rust_analyzer_state,
        wht_corulix_tooling::provisioning::ManagedComponentState::Available,
        "rust-analyzer dropped out of the persisted Selective set, but its real ownership \
         record must still exist on disk -- shrinking the selection is not an uninstall"
    );

    let _ = wht_corulix_tooling::provisioning::full_uninstall::uninstall_all_corulix_managed_components_at(&managed_root).await;
    let _ = std::fs::remove_dir_all(&data_home);
    Ok(())
}
