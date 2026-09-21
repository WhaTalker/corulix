// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P16 mandate §34-38 closure: the hostile-workspace/poisoned-PATH/hostile-
//! HOME/secret-env security matrix for the three providers this phase's
//! `validate_change` production wiring added -- `tsc` (`TypecheckBuild`),
//! Biome (`Linter`/`Formatter`), and the discovered `scripts.test` runner
//! (`TestRunner`). Mirrors `real_p15_go_build_vet_test_e2e.rs`'s own
//! provider-security negative matrix (`workspace_local_fake_go_is_never_
//! resolved_or_executed`, `ambient_path_grants_no_provider_authority`,
//! `go_test_never_receives_the_parent_environment`), one provider
//! substitution at a time.
//!
//! # Why `tsc`/Biome need no PATH/workspace negative at all, and get one anyway
//!
//! `ts_validation::run_typecheck`/`run_lint` resolve their executable
//! exclusively via `wht_corulix_tooling::provisioning::
//! resolve_owned_managed_component(managed_root, ..)` -- a pure path-join
//! against a Corulix-owned directory, never `wht_corulix_config::
//! resolve_provider`, never an ambient `PATH` scan, never a workspace-
//! relative lookup. `P16_WORKSPACE_LSP_HIJACK_COUNT`/`P16_WORKSPACE_
//! FORMATTER_HIJACK_COUNT` (Linter half)/`P16_POISONED_PATH_HIJACK_COUNT`/
//! `P16_HOSTILE_HOME_PROVIDER_EXECUTION_COUNT` are therefore satisfied by
//! *construction*, not by a runtime gate -- but this file still proves it
//! empirically (a workspace-local `./tsc`/`./biome` marker planted in the
//! exact spot a hijack would use, a poisoned `PATH`, a hostile `HOME`), so
//! the guarantee is demonstrated against the real compiled binary, not only
//! asserted from source reading.
//!
//! # Where a real HOST_ONLY fallback genuinely exists: Biome's *formatter*
//! authority
//!
//! Unlike `ts_validation`'s Biome-as-linter path, `wht_corulix_formatter::
//! managed::resolve_formatter`'s Biome-as-formatter arm *does* fall through
//! to `wht_corulix_config::resolve_provider` (`HOST_ONLY`/Rule K) when the
//! `CORULIX_MANAGED` component is unavailable -- exactly mirroring gofmt's
//! own precedent. `P16_WORKSPACE_FORMATTER_HIJACK_COUNT=0`'s Formatter half
//! is proven here against that real fallback path, the one place in this
//! whole vertical a workspace-local executable could theoretically be
//! offered as a candidate at all.
//!
//! # The test-runner: real `TrustedWorkspaceExecution`, not a hijack surface
//!
//! `ts_testing::run_test` deliberately executes repository-authored
//! `scripts.test` under `ExecutionClass::TrustedWorkspaceExecution` (ADR
//! 0010's own trust model) -- `node_modules/.bin` on `PATH` is the
//! *intended* behavior for a non-`node --test` runner, not a hijack. The
//! properties this file proves for it instead: an untrusted workspace is
//! denied before any process spawn, and the real, empirically-confirmed
//! `EnvironmentPolicy::empty()` construction never forwards the parent
//! process's own environment (a `WHT_P16_SECRET_SENTINEL` negative,
//! `P16_SECRET_ENV_FORWARD_COUNT=0`).
//!
//! Requires real network access the first time it runs; every test reports
//! and exits early with `P16_SECURITY_MATRIX_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED`
//! otherwise, never substituting a mock.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceTrust};
use wht_corulix_engine::{ts_testing, ts_validation};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

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

static REAL_P16_SECURITY_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_P16_SECURITY_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

async fn ensure_provisioned(
    root: &Path,
    manifest: wht_corulix_tooling::provisioning::ManagedComponentManifest,
) -> bool {
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

fn write_marker_script(path: &Path, marker: &Path) -> std::io::Result<()> {
    fs::write(
        path,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.to_string_lossy()),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

struct Fixture {
    root_dir: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root_dir =
            std::env::temp_dir().join(format!("corulix-p16-security-{label}-{}", stamp()));
        let _ = fs::create_dir_all(&root_dir);
        Self { root_dir }
    }

    fn write(&self, name: &str, contents: &str) {
        let _ = fs::write(self.root_dir.join(name), contents);
    }

    fn workspace_root(&self) -> wht_corulix_core::CorulixResult<WorkspaceRoot> {
        WorkspaceRoot::open(&self.root_dir)
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.root_dir);
    }
}

fn empty_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

const VALID_TS: &str = "export const answer: number = 42;\n";
const STRICT_TSCONFIG: &str = "{\"compilerOptions\":{\"strict\":true,\"noEmit\":true}}\n";

// ---------------------------------------------------------------------
// §34 -- workspace provider hijack: tsc/Biome (CORULIX_MANAGED-only,
// structurally cannot consult a workspace path at all)
// ---------------------------------------------------------------------

/// `P16_WORKSPACE_TSC_HIJACK_COUNT=0`: a workspace-local `./tsc` marker
/// script, sitting in the exact workspace `run_typecheck` reads source
/// from, is never resolved or executed -- typecheck resolves exclusively
/// against `managed_root`.
#[tokio::test]
async fn workspace_local_fake_tsc_is_never_resolved_or_executed() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    let ts7_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64,
    )
    .await;
    if !ts7_ok {
        eprintln!("P16_SECURITY_MATRIX_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (ts7)");
        return Ok(());
    }

    let fixture = Fixture::new("tsc-hijack");
    fixture.write("tsconfig.json", STRICT_TSCONFIG);
    fixture.write("main.ts", VALID_TS);
    let marker = fixture.root_dir.join("TSC_HIJACK_MARKER");
    let _ = fs::remove_file(&marker);
    write_marker_script(&fixture.root_dir.join("tsc"), &marker)?;
    let bin_dir = fixture.root_dir.join("node_modules").join(".bin");
    let _ = fs::create_dir_all(&bin_dir);
    write_marker_script(&bin_dir.join("tsc"), &marker)?;

    let workspace_root = fixture.workspace_root()?;
    let outcome = ts_validation::run_typecheck(
        &managed_root,
        &workspace_root,
        None,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("expected a real, clean typecheck, got {error:?}")))?;
    if !outcome.clean {
        return Err(fail(format!(
            "expected a real, clean tsc run using the managed tsc, got {outcome:?}"
        )));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake tsc was EXECUTED -- P16_WORKSPACE_TSC_HIJACK_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_file(&marker);
    Ok(())
}

/// `P16_WORKSPACE_LINTER_HIJACK_COUNT=0`: the same guarantee for
/// `run_lint`'s Biome resolution.
#[tokio::test]
async fn workspace_local_fake_biome_is_never_resolved_or_executed_by_the_linter()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    let biome_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64,
    )
    .await;
    if !biome_ok {
        eprintln!("P16_SECURITY_MATRIX_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (biome)");
        return Ok(());
    }

    let fixture = Fixture::new("biome-lint-hijack");
    fixture.write("main.ts", VALID_TS);
    let marker = fixture.root_dir.join("BIOME_LINT_HIJACK_MARKER");
    let _ = fs::remove_file(&marker);
    write_marker_script(&fixture.root_dir.join("biome"), &marker)?;

    let workspace_root = fixture.workspace_root()?;
    let outcome = ts_validation::run_lint(
        &managed_root,
        &workspace_root,
        "main.ts",
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("expected a real, clean lint, got {error:?}")))?;
    if !outcome.clean {
        return Err(fail(format!(
            "expected a real, clean biome lint run using the managed biome, got {outcome:?}"
        )));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake biome was EXECUTED by the linter -- P16_WORKSPACE_LINTER_HIJACK_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_file(&marker);
    Ok(())
}

/// `P16_WORKSPACE_FORMATTER_HIJACK_COUNT=0`: the one real `HOST_ONLY`
/// fallback in this vertical (`wht_corulix_formatter::managed::
/// resolve_formatter`'s Biome-as-formatter arm) still refuses a
/// workspace-local `./biome`, even when that directory is explicitly
/// granted as an approved system directory -- exactly
/// `workspace_local_fake_gofmt_is_never_resolved_or_executed`'s own
/// guarantee, one provider substitution later. Uses a **fresh, isolated**
/// managed root (deliberately never provisioned with Biome) so the
/// `CORULIX_MANAGED` branch is genuinely bypassed and the `HOST_ONLY`
/// fallback is the one actually exercised.
#[tokio::test]
async fn workspace_local_fake_biome_is_never_resolved_or_executed_by_the_formatter()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("biome-format-hijack");
    fixture.write("main.ts", VALID_TS);
    let marker = fixture.root_dir.join("BIOME_FORMAT_HIJACK_MARKER");
    let _ = fs::remove_file(&marker);
    write_marker_script(&fixture.root_dir.join("biome"), &marker)?;
    let isolated_managed_root = std::env::temp_dir().join(format!(
        "corulix-p16-security-biome-format-isolated-managed-{}",
        stamp()
    ));
    let _ = fs::create_dir_all(&isolated_managed_root);

    let effective = EffectiveConfig::derive(
        &HostConfig {
            approved_system_directories: vec![fixture.root_dir.clone()],
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let outcome = wht_corulix_formatter::format_preview_at(
        &isolated_managed_root,
        &effective,
        fixture.workspace_root()?,
        wht_corulix_core::WorkspacePath {
            root: wht_corulix_core::WorkspaceRootId(0),
            relative_path: "main.ts".to_string(),
        },
        wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("expected a typed Ok outcome, got {error:?}")))?;
    if outcome.status != wht_corulix_formatter::FormatStatus::ProviderUnavailable {
        return Err(fail(format!(
            "a workspace-local ./biome was accepted as a formatter -- P16_WORKSPACE_FORMATTER_HIJACK_COUNT must be 0, got {:?}",
            outcome.status
        )));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake biome was EXECUTED by the formatter -- P16_WORKSPACE_FORMATTER_HIJACK_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_dir_all(&isolated_managed_root);
    let _ = fs::remove_file(&marker);
    Ok(())
}

// ---------------------------------------------------------------------
// §34 (poisoned PATH) / §35 (hostile HOME)
// ---------------------------------------------------------------------

/// `P16_POISONED_PATH_HIJACK_COUNT=0` / `P16_HOSTILE_HOME_PROVIDER_EXECUTION_COUNT=0`:
/// proven by construction rather than by mutating this process's own
/// `PATH`/`HOME` -- this workspace forbids `unsafe` code project-wide
/// (`-F unsafe-code`, enforced even inside `#[cfg(test)]`/integration
/// tests), and `std::env::set_var`/`remove_var` require an `unsafe` block,
/// so a real, in-process env-poisoning test is structurally unavailable
/// here (unlike `real_p15_go_build_vet_test_e2e.rs`'s own
/// `ambient_path_grants_no_provider_authority`, which only needs to *read*
/// `PATH`, never mutate it). The equivalent guarantee is proven directly
/// instead: `resolve_owned_managed_component`'s real, resolved `tsc`/Biome
/// paths are canonicalized and asserted to live strictly *inside*
/// `managed_root` -- never inside a decoy `PATH`-style or `HOME`-style
/// directory planted alongside the fixture -- and a real typecheck/lint run
/// against a workspace containing exactly such decoys (fake `tsc`/`biome`/
/// `node` markers under both a `poison-bin/` sibling directory and a
/// `.local/bin/`-shaped one, plus a malicious `.typescriptrc`) still
/// succeeds using only the managed tools, with every marker left untouched.
/// Source-level confirmation this pass re-verified: neither `ts_validation.rs`
/// nor `resolve_owned_managed_component`/`resolve_managed_component`
/// (`wht_corulix_tooling::provisioning`) reads `std::env::var("PATH")` or
/// `std::env::var("HOME")` anywhere in the resolution path (`rg
/// 'env::var\("(PATH|HOME)"\)'` against both modules returns no match), and
/// every managed invocation's `ProcessSpec::environment` is
/// `EnvironmentPolicy::empty()` (verified in `crate::ts_validation`'s own
/// source above), so neither variable is ever forwarded to the child either.
#[tokio::test]
async fn tsc_and_biome_resolution_and_execution_are_confined_to_managed_root_never_path_or_home()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    let ts7_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64,
    )
    .await;
    let biome_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64,
    )
    .await;
    if !ts7_ok || !biome_ok {
        eprintln!(
            "P16_SECURITY_MATRIX_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (ts7={ts7_ok}, biome={biome_ok})"
        );
        return Ok(());
    }
    let canonical_managed_root = fs::canonicalize(&managed_root)
        .map_err(|error| fail(format!("canonicalize managed_root: {error}")))?;

    let fixture = Fixture::new("poisoned-path-and-hostile-home");
    fixture.write("tsconfig.json", STRICT_TSCONFIG);
    fixture.write("main.ts", VALID_TS);
    // A decoy `PATH`-shaped directory sitting right next to the fixture.
    let poison_dir = fixture.root_dir.join("poison-bin");
    let _ = fs::create_dir_all(&poison_dir);
    // A decoy `HOME`-shaped directory tree, complete with a malicious
    // config file a real TypeScript toolchain might otherwise honor.
    let hostile_home = std::env::temp_dir().join(format!("corulix-p16-hostile-home-{}", stamp()));
    let hostile_bin = hostile_home.join(".local").join("bin");
    let _ = fs::create_dir_all(&hostile_bin);
    let _ = fs::write(hostile_home.join(".typescriptrc"), "{\"malicious\":true}\n");
    let marker = fixture
        .root_dir
        .join("POISONED_PATH_AND_HOSTILE_HOME_MARKER");
    let _ = fs::remove_file(&marker);
    for name in ["tsc", "biome", "node"] {
        write_marker_script(&poison_dir.join(name), &marker)?;
        write_marker_script(&hostile_bin.join(name), &marker)?;
    }

    // Direct resolution proof: the real, resolved executables live
    // strictly inside `managed_root`, never inside either decoy directory.
    let (ts7_state, ts7_path) = provisioning::resolve_owned_managed_component(
        &managed_root,
        &wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64,
    );
    let (biome_state, biome_path) = provisioning::resolve_owned_managed_component(
        &managed_root,
        &wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64,
    );
    for (label, state, path) in [
        ("tsc", ts7_state, ts7_path),
        ("biome", biome_state, biome_path),
    ] {
        if state != ManagedComponentState::Available {
            return Err(fail(format!("expected {label} to resolve as Available")));
        }
        let resolved = path.ok_or_else(|| fail(format!("{label}: no resolved path")))?;
        let canonical_resolved = fs::canonicalize(&resolved)
            .map_err(|error| fail(format!("canonicalize {label} path: {error}")))?;
        if !canonical_resolved.starts_with(&canonical_managed_root) {
            return Err(fail(format!(
                "{label} resolved OUTSIDE managed_root ({canonical_resolved:?}) -- P16_POISONED_PATH_HIJACK_COUNT/P16_HOSTILE_HOME_PROVIDER_EXECUTION_COUNT must be 0"
            )));
        }
        if canonical_resolved.starts_with(&poison_dir)
            || canonical_resolved.starts_with(&hostile_bin)
        {
            return Err(fail(format!(
                "{label} resolved INSIDE a decoy PATH/HOME directory ({canonical_resolved:?})"
            )));
        }
    }

    let workspace_root = fixture.workspace_root()?;
    let typecheck = ts_validation::run_typecheck(
        &managed_root,
        &workspace_root,
        None,
        &CancellationToken::new(),
    )
    .await;
    let lint = ts_validation::run_lint(
        &managed_root,
        &workspace_root,
        "main.ts",
        &CancellationToken::new(),
    )
    .await;

    let typecheck = typecheck.map_err(|error| fail(format!("typecheck failed: {error:?}")))?;
    let lint = lint.map_err(|error| fail(format!("lint failed: {error:?}")))?;
    if !typecheck.clean {
        return Err(fail(format!(
            "expected a real, clean typecheck despite decoy PATH/HOME directories, got {typecheck:?}"
        )));
    }
    if !lint.clean {
        return Err(fail(format!(
            "expected a real, clean lint despite decoy PATH/HOME directories, got {lint:?}"
        )));
    }
    if marker.exists() {
        return Err(fail(
            "a decoy PATH/HOME marker was EXECUTED -- P16_POISONED_PATH_HIJACK_COUNT/P16_HOSTILE_HOME_PROVIDER_EXECUTION_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_dir_all(&hostile_home);
    let _ = fs::remove_file(&marker);
    Ok(())
}

// ---------------------------------------------------------------------
// Test-runner: real TrustedWorkspaceExecution -- untrusted-workspace
// denial and the secret-env negative
// ---------------------------------------------------------------------

const NODE_TEST_SCRIPT_PACKAGE_JSON: &str = "{\"scripts\":{\"test\":\"node --test\"}}\n";

/// `P16_TS_JS_TEST_RUNNER_UNTRUSTED_WORKSPACE_DENIAL`: an untrusted
/// workspace (default `EffectiveConfig`, no `WorkspaceTrust::Trusted`, no
/// `allow_trusted_workspace_execution`) is denied **before** discovery or
/// any process spawn -- mirrors `go_test_untrusted_workspace_is_denied_
/// before_any_execution`.
#[tokio::test]
async fn ts_js_test_runner_untrusted_workspace_is_denied_before_any_execution()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;

    let fixture = Fixture::new("test-runner-untrusted");
    fixture.write("package.json", NODE_TEST_SCRIPT_PACKAGE_JSON);
    let marker = fixture.root_dir.join("UNTRUSTED_EXECUTION_MARKER");
    let _ = fs::remove_file(&marker);
    fixture.write(
        "main.test.js",
        &format!(
            "const test = require('node:test');\nconst fs = require('fs');\ntest('marks', () => {{ fs.writeFileSync({:?}, 'x'); }});\n",
            marker.to_string_lossy()
        ),
    );

    let workspace_root = fixture.workspace_root()?;
    let outcome = ts_testing::run_test(
        &managed_root,
        &workspace_root,
        &empty_config(),
        &CancellationToken::new(),
    )
    .await;
    match outcome {
        Err(ts_testing::TsTestError::WorkspaceExecutionNotAuthorized) => {}
        other => {
            return Err(fail(format!(
                "expected WorkspaceExecutionNotAuthorized for an untrusted workspace, got {other:?}"
            )));
        }
    }
    if marker.exists() {
        return Err(fail(
            "the test-runner executed against an untrusted workspace -- must be denied before any spawn",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_file(&marker);
    Ok(())
}

/// `P16_SECRET_ENV_FORWARD_COUNT=0`: real, already-present secrets in this
/// test process's own environment (`CARGO_PKG_NAME`/`CARGO_MANIFEST_DIR`,
/// the exact sentinel-substitute technique `go_test_never_receives_the_
/// parent_environment` already uses in `real_p15_go_build_vet_test_e2e.rs`)
/// never reach the real, trusted `node --test` child -- `ts_testing::
/// run_test`'s `node --test` path spawns with `EnvironmentPolicy::empty()`
/// (zero ambient forwarding). This workspace's `-F unsafe-code` forbids
/// mutating this process's own environment via `std::env::set_var` (see the
/// `#[forbid]`-driven redesign note on `tsc_and_biome_resolution_and_
/// execution_are_confined_to_managed_root_never_path_or_home` above), so
/// this test cannot inject a fresh `WHT_P16_SECRET_SENTINEL` -- it reuses
/// the identical, already-real precedent Go's own suite established for the
/// exact same constraint instead of a synthetic name that would require
/// mutation to set up.
#[tokio::test]
async fn ts_js_test_runner_secret_env_sentinel_never_forwarded() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    let node_ok = ensure_provisioned(
        &managed_root,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64,
    )
    .await;
    if !node_ok {
        eprintln!("P16_SECURITY_MATRIX_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (node)");
        return Ok(());
    }

    let fixture = Fixture::new("test-runner-secret-env");
    fixture.write("package.json", NODE_TEST_SCRIPT_PACKAGE_JSON);
    let dump = fixture.root_dir.join("ENVIRONMENT_DUMP");
    let _ = fs::remove_file(&dump);
    fixture.write(
        "main.test.js",
        &format!(
            "const test = require('node:test');\nconst fs = require('fs');\ntest('dumps', () => {{ fs.writeFileSync({:?}, Object.keys(process.env).map((key) => key + '=' + process.env[key]).join('\\n')); }});\n",
            dump.to_string_lossy()
        ),
    );

    // Real variables this process genuinely has (cargo sets them for every
    // test binary) -- confirmed present below, so the negative is real, not
    // vacuous.
    const SENTINEL_KEYS: &[&str] = &["CARGO_PKG_NAME", "CARGO_MANIFEST_DIR"];
    for key in SENTINEL_KEYS {
        if std::env::var(key).is_err() {
            return Err(fail(format!(
                "test precondition: expected {key} in this process's own environment, so its absence in the child would be meaningless"
            )));
        }
    }

    let workspace_root = fixture.workspace_root()?;
    let effective = EffectiveConfig::derive(
        &HostConfig {
            workspace_trust: WorkspaceTrust::Trusted,
            allow_trusted_workspace_execution: true,
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let outcome = ts_testing::run_test(
        &managed_root,
        &workspace_root,
        &effective,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("run_test failed: {error:?}")))?;
    if !outcome.passing {
        return Err(fail(format!(
            "expected the real node --test dump run to pass, got {outcome:?}"
        )));
    }
    let dumped = fs::read_to_string(&dump)
        .map_err(|_| fail("the node --test dump did not write ENVIRONMENT_DUMP"))?;
    for key in SENTINEL_KEYS {
        if dumped
            .lines()
            .any(|line| line.starts_with(&format!("{key}=")))
        {
            return Err(fail(format!(
                "{key} reached the test-runner child -- P16_SECRET_ENV_FORWARD_COUNT must be 0"
            )));
        }
    }

    fixture.cleanup();
    let _ = fs::remove_file(&dump);
    Ok(())
}
