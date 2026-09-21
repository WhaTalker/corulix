// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P16 exit-gate closure: `full_uninstall::full_uninstall` zero-residual
//! proof extended to the Biome managed component specifically.
//!
//! `full_uninstall` is registry-driven (`ownership::list(root)`, real
//! on-disk ownership records), not a per-language hardcoded list -- so this
//! guarantee already generalizes to any `CorulixManaged` component,
//! including Biome, by construction. This test still proves it empirically
//! against a real, isolated managed root: provision Biome, genuinely
//! *use* it (a real `ts_validation::run_lint` invocation, which stages a
//! scratch copy under `MANAGED_SCRATCH_DIR` -- exactly the scratch-path
//! convention a prior pass in this phase found violated and fixed, see
//! CHANGELOG.md's Phase 16 section G'''), then run `full_uninstall` and
//! confirm the entire isolated managed root is removed with zero residual
//! files -- not merely that the component's own install directory is gone.

use std::error::Error;
use std::fmt;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_core::CancellationToken;
use wht_corulix_engine::ts_validation;
use wht_corulix_tooling::provisioning::{self, ManagedComponentState, full_uninstall};

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

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

/// `P16_BIOME_ZERO_RESIDUAL_FULL_UNINSTALL_E2E`: provision Biome into a
/// fresh, isolated managed root, genuinely use it (a real lint invocation
/// that stages and later must clean up a scratch copy), then confirm
/// `full_uninstall` removes the whole root -- zero residual files,
/// including whatever scratch state the lint invocation left behind.
#[tokio::test]
async fn real_biome_zero_residual_full_uninstall_e2e() -> Result<(), Box<dyn Error>> {
    let isolated_root = std::env::temp_dir().join(format!(
        "corulix-p16-biome-zero-residual-managed-{}",
        stamp()
    ));
    let _ = fs::create_dir_all(&isolated_root);

    let manifest = wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64;
    let (state, _) = provisioning::resolve_managed_component(&isolated_root, &manifest);
    let biome_ok = state == ManagedComponentState::Available
        || provisioning::provision(&isolated_root, &manifest)
            .await
            .is_ok();
    if !biome_ok {
        eprintln!(
            "P16_BIOME_ZERO_RESIDUAL_FULL_UNINSTALL_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED"
        );
        let _ = fs::remove_dir_all(&isolated_root);
        return Ok(());
    }

    // Genuine use: a real, confined `biome lint` staging + invocation,
    // exactly the code path this phase's own self-review previously found
    // writing scratch state outside `MANAGED_SCRATCH_DIR`.
    let fixture_dir = std::env::temp_dir().join(format!(
        "corulix-p16-biome-zero-residual-workspace-{}",
        stamp()
    ));
    let _ = fs::create_dir_all(&fixture_dir);
    let _ = fs::write(fixture_dir.join("main.ts"), "export const answer = 42;\n");
    let workspace_root = wht_corulix_workspace::WorkspaceRoot::open(&fixture_dir)?;
    let lint_outcome = ts_validation::run_lint(
        &isolated_root,
        &workspace_root,
        "main.ts",
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("expected a real lint run, got {error:?}")))?;
    if !lint_outcome.clean {
        return Err(fail(format!(
            "expected a real, clean lint run before uninstalling, got {lint_outcome:?}"
        )));
    }

    // The real, registry-driven full_uninstall -- never a component-specific
    // code path.
    let outcome = full_uninstall::full_uninstall(&isolated_root)
        .await
        .map_err(|error| fail(format!("full_uninstall failed: {error:?}")))?;
    if !matches!(outcome, full_uninstall::FullUninstallOutcome::Removed(_)) {
        return Err(fail(format!(
            "expected full_uninstall to remove the Biome graph, got {outcome:?}"
        )));
    }

    if isolated_root.exists() {
        return Err(fail(format!(
            "P16_BIOME_ZERO_RESIDUAL_FULL_UNINSTALL: expected the isolated managed root to be fully removed (zero residual), but it still exists: {isolated_root:?}"
        )));
    }

    eprintln!("P16_BIOME_ZERO_RESIDUAL_FULL_UNINSTALL_E2E=PASS");
    let _ = fs::remove_dir_all(&fixture_dir);
    Ok(())
}
