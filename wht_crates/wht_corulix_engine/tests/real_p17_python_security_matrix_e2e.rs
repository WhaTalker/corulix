// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P17 mandate closure item #2: the hostile-workspace/poisoned-PATH/
//! hostile-HOME/secret-env security matrix for the Python provider vertical
//! (`ruff format`/`ruff check` -- `Formatter`/`Linter`, `pyright
//! --outputjson` -- `TypecheckBuild`, `pytest` -- `TestRunner`). Mirrors
//! `real_p15_go_build_vet_test_e2e.rs`'s own provider-security negative
//! matrix (`workspace_local_fake_go_is_never_resolved_or_executed`,
//! `ambient_path_grants_no_provider_authority`,
//! `go_test_never_receives_the_parent_environment`) one provider
//! substitution at a time -- **not** `real_p16_ts_js_security_matrix_e2e.rs`'s
//! `CORULIX_MANAGED`/`managed_root`-confinement technique, because ADR 0011
//! §5 is explicit that every Python-family provider resolves through
//! `wht_corulix_config::resolve_provider`'s `HOST_ONLY`/approved-directory
//! chain (Rule K) -- the exact same resolution model Go uses, never a
//! Corulix-managed download path.
//!
//! # Untrusted-workspace test-execution denial: already proven, cited not
//! duplicated
//!
//! `real_p17_python_production_routing_e2e.rs`'s own
//! `real_production_python_untrusted_pytest_denied_before_any_execution`
//! already proves, through the real `CorulixEngine::begin_change`/
//! `validate_change` production path, that an untrusted workspace is denied
//! before any `pytest` process spawns (a harmless marker a real pytest run
//! would create is confirmed absent). This file does not re-derive that
//! proof; it adds the remaining three matrix cells ADR 0011 introduces:
//! workspace-provider-hijack, poisoned-PATH/hostile-HOME confinement, and
//! secret-env non-forwarding.
//!
//! Requires the real `ruff`/`pyright`/`pytest` toolchain this sandbox
//! provisions at the paths named below (the exact versions ADR 0011
//! observed: `ruff 0.16.1`, `pyright 1.1.413`, `pytest 9.1.1`). Every test
//! reports and exits early with
//! `P17_SECURITY_MATRIX_E2E=BLOCKED_PROVIDER_UNAVAILABLE` otherwise, never
//! substituting a mock.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, ProviderCategory, WorkspaceTrust};
use wht_corulix_engine::{python_providers, python_testing, python_validation};
use wht_corulix_workspace::WorkspaceRoot;

/// Test-only PATH-based tool discovery. An explicit environment-variable
/// override (`CORULIX_TEST_PYTHON_TOOLS_DIR` / `CORULIX_TEST_PYRIGHT_DIR`)
/// takes precedence; otherwise the directory on `PATH` containing
/// `bin_name` is used. Never embeds a specific developer's machine path.
fn resolve_test_tool_dir(bin_name: &str, env_override: &str) -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_override) {
        return Some(PathBuf::from(explicit));
    }
    let exe_name = format!("{bin_name}{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
}

/// This host's real `ruff`/`pytest` directory and Pyright's separate
/// directory -- identical to `real_p17_python_production_routing_e2e.rs`'s
/// own resolution, so both files exercise the exact same real toolchain.
fn real_ruff_pytest_directory() -> Option<PathBuf> {
    resolve_test_tool_dir("ruff", "CORULIX_TEST_PYTHON_TOOLS_DIR")
}
fn real_pyright_directory() -> Option<PathBuf> {
    resolve_test_tool_dir("pyright", "CORULIX_TEST_PYRIGHT_DIR")
}

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

fn real_python_tools_available() -> bool {
    let Some(ruff_pytest_dir) = real_ruff_pytest_directory() else {
        return false;
    };
    let Some(pyright_dir) = real_pyright_directory() else {
        return false;
    };
    ruff_pytest_dir.join("ruff").is_file()
        && ruff_pytest_dir.join("pytest").is_file()
        && pyright_dir.join("pyright").is_file()
}

macro_rules! require_python_tools {
    () => {
        if !real_python_tools_available() {
            eprintln!(
                "P17_SECURITY_MATRIX_E2E=BLOCKED_PROVIDER_UNAVAILABLE: real ruff/pyright/pytest not found at the expected sandbox paths"
            );
            return Ok(());
        }
    };
}

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

struct Fixture {
    root_dir: PathBuf,
    managed_root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let base =
            std::env::temp_dir().join(format!("corulix-p17-python-security-{label}-{}", stamp()));
        let root_dir = base.join("workspace");
        let managed_root = base.join("managed");
        let _ = fs::create_dir_all(&root_dir);
        let _ = fs::create_dir_all(&managed_root);
        Self {
            root_dir,
            managed_root,
        }
    }

    fn write(&self, name: &str, contents: &str) {
        let _ = fs::write(self.root_dir.join(name), contents);
    }

    fn workspace_root(&self) -> wht_corulix_core::CorulixResult<WorkspaceRoot> {
        WorkspaceRoot::open(&self.root_dir)
    }

    fn cleanup(&self) {
        if let Some(base) = self.root_dir.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }
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

const CLEAN_PY: &str = "def target() -> int:\n    return 41\n";

fn real_provider_authority(extra_approved: &[PathBuf], trusted: bool) -> EffectiveConfig {
    let mut approved = vec![
        real_ruff_pytest_directory().unwrap_or_default(),
        real_pyright_directory().unwrap_or_default(),
    ];
    approved.extend_from_slice(extra_approved);
    EffectiveConfig::derive(
        &HostConfig {
            workspace_trust: if trusted {
                WorkspaceTrust::Trusted
            } else {
                WorkspaceTrust::Untrusted
            },
            allow_trusted_workspace_execution: trusted,
            approved_system_directories: approved,
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

// ---------------------------------------------------------------------
// Workspace provider hijack: ruff (formatter/linter path), pyright
// (typecheck), pytest (test runner)
// ---------------------------------------------------------------------

/// `P17_WORKSPACE_RUFF_LINT_HIJACK_COUNT=0`: a workspace-local `./ruff`
/// marker script, sitting in the exact workspace `run_lint` reads source
/// from -- and even when that workspace directory is itself offered as an
/// approved system directory -- is never resolved or executed. `run_lint`
/// must still resolve the real, approved-directory `ruff`.
#[tokio::test]
async fn workspace_local_fake_ruff_is_never_resolved_or_executed_by_the_linter()
-> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("ruff-lint-hijack");
    fixture.write("main.py", CLEAN_PY);
    let marker = fixture.root_dir.join("RUFF_LINT_HIJACK_MARKER");
    let _ = fs::remove_file(&marker);
    write_marker_script(&fixture.root_dir.join("ruff"), &marker)?;
    let workspace_root = fixture.workspace_root()?;

    // The load-bearing negative, mirroring Go's own
    // `workspace_local_fake_gofmt_is_never_resolved_or_executed` exactly:
    // with the workspace directory as the SOLE approved directory (no real
    // ruff directory granted at all), resolution must outright refuse --
    // proving rejection, not merely preference for a competing real
    // candidate.
    let sole_workspace_authority = EffectiveConfig::derive(
        &HostConfig {
            approved_system_directories: vec![fixture.root_dir.clone()],
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let sole_outcome = python_providers::resolve_python_tool(
        &sole_workspace_authority,
        &workspace_root,
        ProviderCategory::Linter,
        "ruff",
        &CancellationToken::new(),
    )
    .await;
    if sole_outcome.is_ok() {
        return Err(fail(
            "a workspace-local ./ruff was accepted as a controlled provider when it was the SOLE \
             approved directory -- P17_WORKSPACE_RUFF_LINT_HIJACK_COUNT must be 0",
        ));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake ruff was EXECUTED during sole-authority resolution",
        ));
    }

    // The governed workspace itself offered as approved *alongside* the real
    // directory: even this must not make a workspace-authored executable a
    // controlled provider (mirrors Go's
    // `workspace_local_fake_go_is_never_resolved_or_executed`).
    let effective = real_provider_authority(std::slice::from_ref(&fixture.root_dir), true);
    let outcome = python_validation::run_lint(
        &fixture.managed_root,
        &effective,
        &workspace_root,
        "main.py",
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("expected a real, clean lint, got {error:?}")))?;
    if !outcome.clean {
        return Err(fail(format!(
            "expected a real, clean ruff check using the real approved-directory ruff, got {outcome:?}"
        )));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake ruff was EXECUTED -- P17_WORKSPACE_RUFF_LINT_HIJACK_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    Ok(())
}

/// `P17_WORKSPACE_PYRIGHT_HIJACK_COUNT=0`: the same guarantee for
/// `run_typecheck`'s Pyright resolution.
#[tokio::test]
async fn workspace_local_fake_pyright_is_never_resolved_or_executed_by_the_typechecker()
-> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("pyright-hijack");
    fixture.write("main.py", CLEAN_PY);
    let marker = fixture.root_dir.join("PYRIGHT_HIJACK_MARKER");
    let _ = fs::remove_file(&marker);
    write_marker_script(&fixture.root_dir.join("pyright"), &marker)?;
    let workspace_root = fixture.workspace_root()?;

    // Sole-authority rejection, mirroring Go's own
    // `workspace_local_fake_gofmt_is_never_resolved_or_executed`.
    let sole_workspace_authority = EffectiveConfig::derive(
        &HostConfig {
            approved_system_directories: vec![fixture.root_dir.clone()],
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let sole_outcome = python_providers::resolve_python_tool(
        &sole_workspace_authority,
        &workspace_root,
        ProviderCategory::TypecheckBuild,
        "pyright",
        &CancellationToken::new(),
    )
    .await;
    if sole_outcome.is_ok() {
        return Err(fail(
            "a workspace-local ./pyright was accepted as a controlled provider when it was the \
             SOLE approved directory -- P17_WORKSPACE_PYRIGHT_HIJACK_COUNT must be 0",
        ));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake pyright was EXECUTED during sole-authority resolution",
        ));
    }

    let effective = real_provider_authority(std::slice::from_ref(&fixture.root_dir), true);
    let outcome = python_validation::run_typecheck(
        &fixture.managed_root,
        &effective,
        &workspace_root,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("expected a real, clean typecheck, got {error:?}")))?;
    if !outcome.clean {
        return Err(fail(format!(
            "expected a real, clean pyright run using the real approved-directory pyright, got {outcome:?}"
        )));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake pyright was EXECUTED -- P17_WORKSPACE_PYRIGHT_HIJACK_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    Ok(())
}

/// `P17_WORKSPACE_PYTEST_HIJACK_COUNT=0`: the same guarantee for
/// `run_pytest`'s test-runner resolution -- a discoverable `pytest.ini`
/// marker is present (ADR 0011 §4) and the workspace is genuinely trusted,
/// so the resolution step is really reached; the workspace-local `./pytest`
/// must still never be resolved or executed.
#[tokio::test]
async fn workspace_local_fake_pytest_is_never_resolved_or_executed_by_the_test_runner()
-> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("pytest-hijack");
    fixture.write("pytest.ini", "[pytest]\n");
    fixture.write("test_main.py", "def test_ok():\n    assert True\n");
    let marker = fixture.root_dir.join("PYTEST_HIJACK_MARKER");
    let _ = fs::remove_file(&marker);
    write_marker_script(&fixture.root_dir.join("pytest"), &marker)?;
    let workspace_root = fixture.workspace_root()?;

    // Sole-authority rejection, mirroring Go's own
    // `workspace_local_fake_gofmt_is_never_resolved_or_executed`. Calls
    // `resolve_python_tool` directly (bypassing `run_pytest`'s own ADR 0011
    // §4 discovery gate, already proven elsewhere) so this negative isolates
    // the provider-resolution property specifically.
    let sole_workspace_authority = EffectiveConfig::derive(
        &HostConfig {
            approved_system_directories: vec![fixture.root_dir.clone()],
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let sole_outcome = python_providers::resolve_python_tool(
        &sole_workspace_authority,
        &workspace_root,
        ProviderCategory::TestRunner,
        "pytest",
        &CancellationToken::new(),
    )
    .await;
    if sole_outcome.is_ok() {
        return Err(fail(
            "a workspace-local ./pytest was accepted as a controlled provider when it was the \
             SOLE approved directory -- P17_WORKSPACE_PYTEST_HIJACK_COUNT must be 0",
        ));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake pytest was EXECUTED during sole-authority resolution",
        ));
    }

    let effective = real_provider_authority(std::slice::from_ref(&fixture.root_dir), true);
    let outcome =
        python_testing::run_pytest(&workspace_root, &effective, &CancellationToken::new())
            .await
            .map_err(|error| fail(format!("expected a real pytest run, got {error:?}")))?;
    if !outcome.passing {
        return Err(fail(format!(
            "expected the real approved-directory pytest run to pass, got {outcome:?}"
        )));
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake pytest was EXECUTED -- P17_WORKSPACE_PYTEST_HIJACK_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    Ok(())
}

/// `P17_WORKSPACE_PYTHON3_RUNTIME_HIJACK_COUNT=0`: the same guarantee for
/// `ProviderCategory::Runtime`'s `python3` resolution
/// (`python_providers::resolve_python_runtime`) -- named explicitly by ADR
/// 0011 §5 alongside `ruff`/`pyright`/`pytest`, even though no P17 validator
/// invokes the resolved runtime directly (see `python_providers`'s own doc
/// comment).
///
/// A plain `Err` from an `approved_system_directories`-only grant would be
/// ambiguous by itself -- equally consistent with "the resolver genuinely
/// found and rejected the workspace candidate" and "nothing was found at
/// all, so the fake `./python3` was never even examined" (that resolution
/// path's own `CandidateOutcome::WorkspaceLocal` is silently skipped by
/// `try_directory_candidates`, falling through to the same
/// `RequiredProviderUnavailable` a genuinely absent provider would produce
/// -- confirmed empirically when a first draft of this test asserted a
/// specific reason code there and failed with exactly that generic reason).
/// The `HOST_ONLY` absolute-path-override path (`resolve_provider`'s own
/// step 1) does not have this ambiguity: when the configured override
/// itself resolves to a workspace-local candidate, it returns the specific
/// `ReasonCode::ProviderResolvedInsideWorkspace` -- proof the resolver
/// examined this exact path and rejected it for being workspace-local, not
/// merely that nothing existed. This test uses that path deliberately, to
/// make the negative genuinely load-bearing rather than merely consistent.
#[tokio::test]
async fn workspace_local_fake_python3_runtime_is_never_resolved_or_executed()
-> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let fixture = Fixture::new("python3-runtime-hijack");
    let marker = fixture.root_dir.join("PYTHON3_RUNTIME_HIJACK_MARKER");
    let _ = fs::remove_file(&marker);
    let fake_python3 = fixture.root_dir.join("python3");
    write_marker_script(&fake_python3, &marker)?;
    let workspace_root = fixture.workspace_root()?;

    // A HOST_ONLY absolute-path override pointing directly at the
    // workspace-local fake -- the one resolution path that returns a
    // specific, disambiguating reason code for this exact rejection.
    let host_only_workspace_override = EffectiveConfig::derive(
        &HostConfig {
            provider_absolute_paths: vec![(ProviderCategory::Runtime, fake_python3.clone())],
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let outcome = python_providers::resolve_python_runtime(
        &host_only_workspace_override,
        &workspace_root,
        &CancellationToken::new(),
    )
    .await;
    match outcome {
        Err(python_providers::PythonProviderError::ProviderUnavailable(Some(
            wht_corulix_core::ReasonCode::ProviderResolvedInsideWorkspace,
        ))) => {}
        other => {
            return Err(fail(format!(
                "expected the resolver to genuinely find and reject the workspace-local \
                 ./python3 (ReasonCode::ProviderResolvedInsideWorkspace), got {other:?} -- \
                 P17_WORKSPACE_PYTHON3_RUNTIME_HIJACK_COUNT must be 0"
            )));
        }
    }
    if marker.exists() {
        return Err(fail(
            "the workspace-local fake python3 was EXECUTED -- \
             P17_WORKSPACE_PYTHON3_RUNTIME_HIJACK_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------
// Ambient PATH grants no authority
// ---------------------------------------------------------------------

/// `P17_AMBIENT_PATH_AUTHORITY=NO`, proven directly rather than asserted:
/// `ruff` is unquestionably reachable on this process's own ambient `PATH`
/// (every other real E2E test in this suite executes it), yet resolution
/// against an **empty** authority envelope must fail closed.
#[tokio::test]
async fn ambient_path_grants_no_python_provider_authority() -> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let ambient_path = std::env::var("PATH").unwrap_or_default();
    if !ambient_path
        .split(':')
        .any(|dir| Path::new(dir).join("ruff").is_file())
    {
        eprintln!(
            "P17_AMBIENT_PATH_AUTHORITY: skipped -- `ruff` is not on this process's ambient PATH, so the negative would be vacuous"
        );
        return Ok(());
    }

    let fixture = Fixture::new("ambient-path");
    fixture.write("main.py", CLEAN_PY);
    let workspace_root = fixture.workspace_root()?;
    let empty_authority = EffectiveConfig::derive(
        &HostConfig {
            workspace_trust: WorkspaceTrust::Trusted,
            allow_trusted_workspace_execution: true,
            ..HostConfig::default()
        },
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let outcome = python_providers::resolve_python_tool(
        &empty_authority,
        &workspace_root,
        ProviderCategory::Linter,
        "ruff",
        &CancellationToken::new(),
    )
    .await;
    match outcome {
        Err(python_providers::PythonProviderError::ProviderUnavailable(_)) => {}
        other => {
            return Err(fail(format!(
                "`ruff` resolved from ambient PATH with an empty authority envelope: {other:?}"
            )));
        }
    }
    fixture.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------
// Poisoned-PATH / hostile-HOME confinement
// ---------------------------------------------------------------------

/// `P17_POISONED_PATH_HIJACK_COUNT=0` / `P17_HOSTILE_HOME_PROVIDER_EXECUTION_COUNT=0`:
/// proven the same way `real_p16_ts_js_security_matrix_e2e.rs` proves it for
/// TS/JS (this workspace forbids `unsafe` code project-wide, so
/// `std::env::set_var`/`remove_var` are structurally unavailable for a real
/// env-mutation test) -- direct resolution proof that the real, resolved
/// `ruff`/`pyright`/`pytest` executables canonicalize strictly *inside* one
/// of the real approved directories, never inside a decoy `PATH`-style or
/// `HOME`-style directory planted alongside the fixture, and a real
/// lint/typecheck/test run against a workspace containing exactly such
/// decoys still succeeds using only the approved-directory tools, with every
/// decoy marker left untouched.
#[tokio::test]
async fn python_provider_resolution_and_execution_are_confined_to_approved_directories_never_path_or_home()
-> Result<(), Box<dyn Error>> {
    require_python_tools!();
    let ruff_pytest_dir = real_ruff_pytest_directory().unwrap_or_default();
    let pyright_dir = real_pyright_directory().unwrap_or_default();
    let canonical_ruff_pytest_dir = fs::canonicalize(&ruff_pytest_dir)
        .map_err(|error| fail(format!("canonicalize real ruff/pytest directory: {error}")))?;
    // Pyright's *canonicalized* resolution follows its `bin/pyright` symlink
    // all the way to the real target file deep inside
    // `.../lib/node_modules/pyright/index.js` (see
    // `python_providers::pyright_invocation_environment`'s own doc comment
    // for the identical observation about the `node` sibling-binary lookup)
    // -- not the resolved Pyright `bin/` directory itself. The containment
    // check below therefore anchors on the shared nvm version root that
    // contains both `bin/` and `lib/`, not the `bin/` directory alone.
    let canonical_pyright_dir = fs::canonicalize(&pyright_dir)
        .map_err(|error| fail(format!("canonicalize real pyright directory: {error}")))?
        .parent()
        .ok_or_else(|| fail("real pyright directory has no parent"))?
        .to_path_buf();

    let fixture = Fixture::new("poisoned-path-and-hostile-home");
    fixture.write("main.py", CLEAN_PY);
    fixture.write("pytest.ini", "[pytest]\n");
    fixture.write("test_main.py", "def test_ok():\n    assert True\n");

    // A decoy `PATH`-shaped directory sitting right next to the fixture.
    let poison_dir = fixture
        .root_dir
        .parent()
        .unwrap_or(&fixture.root_dir)
        .join("poison-bin");
    let _ = fs::create_dir_all(&poison_dir);
    // A decoy `HOME`-shaped directory tree, complete with a malicious config
    // file a real Python toolchain might otherwise honor.
    let hostile_home =
        std::env::temp_dir().join(format!("corulix-p17-python-hostile-home-{}", stamp()));
    let hostile_bin = hostile_home.join(".local").join("bin");
    let _ = fs::create_dir_all(&hostile_bin);
    let _ = fs::write(
        hostile_home.join("pyrightconfig.json"),
        "{\"pythonPath\":\"/bin/false\"}\n",
    );
    let marker = fixture
        .root_dir
        .parent()
        .unwrap_or(&fixture.root_dir)
        .join("POISONED_PATH_AND_HOSTILE_HOME_MARKER");
    let _ = fs::remove_file(&marker);
    for name in ["ruff", "pyright", "pytest", "python3"] {
        write_marker_script(&poison_dir.join(name), &marker)?;
        write_marker_script(&hostile_bin.join(name), &marker)?;
    }

    let workspace_root = fixture.workspace_root()?;
    let effective = real_provider_authority(&[], true);

    // Direct resolution proof: the real, resolved executables live strictly
    // inside one of the real approved directories, never inside either
    // decoy directory.
    for (label, category, provider_id, expected_dir) in [
        (
            "ruff",
            ProviderCategory::Linter,
            "ruff",
            &canonical_ruff_pytest_dir,
        ),
        (
            "pyright",
            ProviderCategory::TypecheckBuild,
            "pyright",
            &canonical_pyright_dir,
        ),
        (
            "pytest",
            ProviderCategory::TestRunner,
            "pytest",
            &canonical_ruff_pytest_dir,
        ),
    ] {
        let resolved = python_providers::resolve_python_tool(
            &effective,
            &workspace_root,
            category,
            provider_id,
            &CancellationToken::new(),
        )
        .await
        .map_err(|error| fail(format!("{label}: expected real resolution, got {error:?}")))?;
        let canonical_resolved = fs::canonicalize(&resolved.executable)
            .map_err(|error| fail(format!("canonicalize {label} path: {error}")))?;
        if !canonical_resolved.starts_with(expected_dir) {
            return Err(fail(format!(
                "{label} resolved OUTSIDE its approved directory ({canonical_resolved:?}) -- \
                 P17_POISONED_PATH_HIJACK_COUNT/P17_HOSTILE_HOME_PROVIDER_EXECUTION_COUNT must be 0"
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

    // Real execution proof: lint/typecheck/test all still succeed using only
    // the approved-directory tools, with every decoy marker left untouched.
    let lint = python_validation::run_lint(
        &fixture.managed_root,
        &effective,
        &workspace_root,
        "main.py",
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("lint failed: {error:?}")))?;
    let typecheck = python_validation::run_typecheck(
        &fixture.managed_root,
        &effective,
        &workspace_root,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("typecheck failed: {error:?}")))?;
    let test = python_testing::run_pytest(&workspace_root, &effective, &CancellationToken::new())
        .await
        .map_err(|error| fail(format!("test run failed: {error:?}")))?;

    if !lint.clean {
        return Err(fail(format!(
            "expected a real, clean lint despite decoy PATH/HOME directories, got {lint:?}"
        )));
    }
    if !typecheck.clean {
        return Err(fail(format!(
            "expected a real, clean typecheck despite decoy PATH/HOME directories, got {typecheck:?}"
        )));
    }
    if !test.passing {
        return Err(fail(format!(
            "expected a real, passing test run despite decoy PATH/HOME directories, got {test:?}"
        )));
    }
    if marker.exists() {
        return Err(fail(
            "a decoy PATH/HOME marker was EXECUTED -- P17_POISONED_PATH_HIJACK_COUNT/P17_HOSTILE_HOME_PROVIDER_EXECUTION_COUNT must be 0",
        ));
    }

    fixture.cleanup();
    let _ = fs::remove_dir_all(&hostile_home);
    let _ = fs::remove_file(&marker);
    Ok(())
}

// ---------------------------------------------------------------------
// Secret-env non-forwarding (pytest, TrustedWorkspaceExecution)
// ---------------------------------------------------------------------

/// `P17_SECRET_ENV_FORWARD_COUNT=0`: real, already-present variables in this
/// test process's own environment (`CARGO_PKG_NAME`/`CARGO_MANIFEST_DIR`,
/// the same sentinel-substitute technique
/// `go_test_never_receives_the_parent_environment` and
/// `ts_js_test_runner_secret_env_sentinel_never_forwarded` both use for the
/// identical `-F unsafe-code` constraint) never reach the real, trusted
/// `pytest` child -- `python_testing::run_pytest` spawns with
/// `EnvironmentPolicy::empty()` (zero ambient forwarding), confirmed here
/// against the real process rather than only asserted from source reading.
#[tokio::test]
async fn python_test_runner_secret_env_sentinel_never_forwarded() -> Result<(), Box<dyn Error>> {
    require_python_tools!();
    const SENTINEL_KEYS: &[&str] = &["CARGO_PKG_NAME", "CARGO_MANIFEST_DIR"];
    for key in SENTINEL_KEYS {
        if std::env::var(key).is_err() {
            return Err(fail(format!(
                "test precondition: expected {key} in this process's own environment, so its absence in the child would be meaningless"
            )));
        }
    }

    let fixture = Fixture::new("test-runner-secret-env");
    fixture.write("pytest.ini", "[pytest]\n");
    let dump = fixture.root_dir.join("ENVIRONMENT_DUMP");
    let _ = fs::remove_file(&dump);
    fixture.write(
        "test_dump_environment.py",
        &format!(
            "import os\n\ndef test_dump():\n    with open({:?}, 'w') as handle:\n        handle.write('\\n'.join(f'{{key}}={{value}}' for key, value in os.environ.items()))\n",
            dump.to_string_lossy()
        ),
    );

    let effective = real_provider_authority(&[], true);
    let workspace_root = fixture.workspace_root()?;
    let outcome =
        python_testing::run_pytest(&workspace_root, &effective, &CancellationToken::new())
            .await
            .map_err(|error| fail(format!("run_pytest failed: {error:?}")))?;
    if !outcome.passing {
        return Err(fail(format!(
            "expected the real pytest dump run to pass, got {outcome:?}"
        )));
    }
    let dumped = fs::read_to_string(&dump)
        .map_err(|_| fail("the pytest dump did not write ENVIRONMENT_DUMP"))?;
    for key in SENTINEL_KEYS {
        if dumped
            .lines()
            .any(|line| line.starts_with(&format!("{key}=")))
        {
            return Err(fail(format!(
                "{key} reached the pytest child -- P17_SECRET_ENV_FORWARD_COUNT must be 0"
            )));
        }
    }

    fixture.cleanup();
    let _ = fs::remove_file(&dump);
    Ok(())
}
