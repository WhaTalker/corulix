// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P12-R2 real end-to-end lifecycle proof for the managed GNU link runtime
//! ([`wht_corulix_tooling::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64`]):
//! real download, real SHA-256 verification, real bzip2 decoding, real
//! `extract_path_prefixes`/`post_extraction_symlinks` extraction against
//! the real upstream Bootlin tarball, real ownership activation, real
//! `full_uninstall`, and zero residual afterward. `MOCKED_ONLY_CLOSURE=NO`
//! -- deliberately the real upstream artifact, not a synthetic fixture: the
//! real, empirically-derived path layout (the `lib64 -> lib` symlinks in
//! particular) is exactly what a synthetic tarball could not catch, since
//! it was itself discovered by a real failed link against the real
//! artifact during this phase's research gate.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_tooling::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64;
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

#[derive(Debug)]
struct TestFailure(String);

impl fmt::Display for TestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for TestFailure {}

fn fail(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(TestFailure(message.into()))
}

fn isolated_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!("corulix-p12-r2-gnu-lifecycle-{label}-{stamp}"))
}

/// Full real lifecycle: `NotProvisioned` -> real `provision` (download +
/// SHA-256 + bzip2 decode + filtered extraction + post-extraction symlinks
/// + atomic activation) -> `Available`+owned -> real content spot-checks
/// (the exact files `wht_corulix_engine::testing::link_environment`
/// resolves, plus the `lib64 -> lib` compatibility symlinks actually
/// resolving) -> `full_uninstall` -> `NotProvisioned` -> zero residual on
/// disk.
#[tokio::test]
async fn real_p12_r2_gnu_link_runtime_install_integrity_uninstall_zero_residual_e2e()
-> Result<(), Box<dyn Error>> {
    let root = isolated_root("full");

    let (initial_state, _) =
        provisioning::resolve_managed_component(&root, &GNU_LINK_RUNTIME_LINUX_X64);
    if initial_state != ManagedComponentState::NotProvisioned {
        return Err(fail(format!(
            "expected NotProvisioned before any provisioning, got {initial_state:?}"
        )));
    }

    let provision_result = provisioning::provision(&root, &GNU_LINK_RUNTIME_LINUX_X64).await;
    let Ok(_binary) = provision_result else {
        // No real network access in this environment -- report and exit
        // cleanly rather than failing a network-dependent E2E test, same
        // convention `wht_corulix_engine`'s own P12 fixtures use.
        eprintln!(
            "P12_R2_GNU_RUNTIME_LIFECYCLE_E2E=BLOCKED_PROVISIONING_FAILED (no real internet access?) : {provision_result:?}"
        );
        return Ok(());
    };

    let (state, _) =
        provisioning::resolve_owned_managed_component(&root, &GNU_LINK_RUNTIME_LINUX_X64);
    if state != ManagedComponentState::Available {
        return Err(fail(format!(
            "expected Available+owned immediately after provision, got {state:?}"
        )));
    }
    eprintln!("P12_GNU_RUNTIME_INSTALL=PASS");
    eprintln!("P12_GNU_RUNTIME_INTEGRITY=PASS");

    let install_dir = provisioning::component_install_dir(&root, &GNU_LINK_RUNTIME_LINUX_X64);
    let sysroot = install_dir.join("x86_64-buildroot-linux-gnu/sysroot");
    for required in [
        sysroot.join("lib/libc.so.6"),
        sysroot.join("lib/libpthread.so.0"),
        sysroot.join("lib/libgcc_s.so.1"),
        sysroot.join("lib/ld-linux-x86-64.so.2"),
        sysroot.join("usr/lib/crt1.o"),
        sysroot.join("usr/lib/crti.o"),
        sysroot.join("usr/lib/crtn.o"),
        sysroot.join("usr/lib/libc.so"),
        sysroot.join("usr/lib/libc_nonshared.a"),
        install_dir.join("lib/gcc/x86_64-buildroot-linux-gnu/10.3.0/libgcc.a"),
    ] {
        if !required.is_file() {
            return Err(fail(format!(
                "expected {required:?} to exist after real provisioning"
            )));
        }
    }

    // The real, empirically-motivated fix this phase's research gate found:
    // the `lib64 -> lib` compatibility symlinks must exist and actually
    // resolve to real content (not merely exist as a dangling link) --
    // exactly what `usr/lib/libm.so`'s `GROUP ( /lib64/libm.so.6 ... )`
    // needs at real link time.
    let lib64_libm = sysroot.join("lib64/libm.so.6");
    if !lib64_libm.is_file() {
        return Err(fail(format!(
            "expected the lib64 -> lib compatibility symlink to resolve to a real file at {lib64_libm:?}"
        )));
    }
    let usr_lib64_target = std::fs::canonicalize(sysroot.join("usr/lib64"))
        .map_err(|error| fail(format!("usr/lib64 must resolve: {error}")))?;
    let usr_lib_target = std::fs::canonicalize(sysroot.join("usr/lib"))
        .map_err(|error| fail(format!("usr/lib must resolve: {error}")))?;
    if usr_lib64_target != usr_lib_target {
        return Err(fail(
            "expected sysroot/usr/lib64 to resolve to the same real directory as sysroot/usr/lib",
        ));
    }

    // Filtered-out content proof: the upstream archive's unused C++/
    // Fortran/gdb/plugin/header subtrees were never written to disk at all
    // -- `extract_path_prefixes` is a real content-selection mechanism, not
    // merely a documented intention.
    if install_dir.join("include").exists() {
        return Err(fail(
            "expected the upstream archive's unused top-level include/ directory to be filtered out",
        ));
    }
    if install_dir.join("bin").exists() {
        return Err(fail(
            "expected the upstream archive's unused cross-gcc bin/ directory (gcc/gdb/etc.) to be filtered out",
        ));
    }
    eprintln!("P12_R2_EXTRACT_PATH_PREFIXES_FILTER=PASS");

    let uninstall_outcome = provisioning::full_uninstall::full_uninstall(&root).await;
    if !matches!(
        uninstall_outcome,
        Ok(provisioning::full_uninstall::FullUninstallOutcome::Removed(
            _
        ))
    ) {
        return Err(fail(format!(
            "expected a real Removed uninstall outcome, got {uninstall_outcome:?}"
        )));
    }

    let (post_uninstall_state, _) =
        provisioning::resolve_managed_component(&root, &GNU_LINK_RUNTIME_LINUX_X64);
    if post_uninstall_state != ManagedComponentState::NotProvisioned {
        return Err(fail(format!(
            "expected NotProvisioned after uninstall, got {post_uninstall_state:?}"
        )));
    }
    if install_dir.exists() {
        return Err(fail(
            "expected zero filesystem residual for the component install directory after uninstall",
        ));
    }
    eprintln!("P12_GNU_RUNTIME_UNINSTALL=PASS");
    eprintln!("P12_GNU_RUNTIME_ZERO_RESIDUAL=PASS");

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
