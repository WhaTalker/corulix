// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P17: the single place this crate resolves the real Python-family
//! providers (`ruff`, `pyright`, `pytest`, `python3`) named by ADR 0011
//! (`wht_docs/wht_adr/wht_0011-python-provider-vertical-p17.md`).
//!
//! # M03 update: `ruff`/Pyright-CLI are now managed-first, `pytest`/`python3` are not
//!
//! ADR 0011 §5/§6 originally made Python's entire runtime/interpreter/
//! formatter/linter/typechecker/test-runner authority resolve exclusively
//! through `wht_corulix_config::resolve_provider`'s `HOST_ONLY`/approved-
//! directory precedence (Rule K) -- the same resolver Go already uses. The
//! owner has since narrowly superseded that stance for the `SemanticRename`
//! auxiliary tier specifically (see ADR 0011's own M03 update note at the top
//! of that document): `resolve_ruff_tool` (Formatter + Linter) and
//! `resolve_pyright_cli` (TypecheckBuild) now resolve `CORULIX_MANAGED`
//! first -- mirroring `crate::go_providers::resolve_go_toolchain`'s own
//! two-tier shape exactly -- falling through to the pre-existing `HOST_ONLY`
//! [`resolve_python_tool`] only when genuinely not provisioned.
//! `pytest`/`python3` are **unaffected**: both continue to call
//! [`resolve_python_tool`] directly, and ADR 0011's original `HOST_ONLY`-only
//! authority for them remains unmodified.
//!
//! `P17_AMBIENT_PATH_AUTHORITY=NO`: `resolve_provider` never reads ambient
//! `PATH`, and this module adds no lookup of its own. A workspace-local
//! `./ruff`/`./pyright`/`./pytest`/`./python3` (or a `.venv`-installed one,
//! per ADR 0011 §6) can never satisfy a controlled provider
//! (`ReasonCode::ProviderResolvedInsideWorkspace`). The managed tier is
//! likewise never ambient: it resolves a fixed, versioned path under
//! `managed_root`, never PATH.
//!
//! # Category mapping (no new policy entries)
//!
//! ```text
//! ProviderCategory::TypecheckBuild -> pyright --outputjson   (Authoritative)
//! ProviderCategory::Linter         -> ruff check              (SupportingOnly)
//! ProviderCategory::Formatter      -> ruff format             (wht_corulix_formatter's own profile)
//! ProviderCategory::TestRunner     -> pytest                  (Authoritative for gate.tests, discovered per ADR 0011 §4)
//! ProviderCategory::Runtime        -> python3                 (never itself invoked by this phase's validators -- see below)
//! ProviderCategory::LanguageServer -> pyright-langserver       (wht_corulix_lsp's own profile, ADR 0009)
//! ```
//!
//! `python3` (`ProviderCategory::Runtime`) is resolved and version-probed by
//! this module for completeness with ADR 0011 §5, but no P17 validator
//! invokes it directly: `ruff`/`pyright`/`pytest` are each standalone,
//! self-contained executables that do not require this crate to launch a
//! Python interpreter of its own to run them (confirmed empirically: none of
//! the three has a `.py`-script entry point on this host -- each is a
//! platform-native or self-contained binary).

use std::path::{Path, PathBuf};

use wht_corulix_core::{CancellationToken, ProviderCategory, ReasonCode};
use wht_corulix_tooling::provisioning::{ManagedComponentManifest, ManagedComponentState};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, TerminationReason};

/// The `ruff` binary name, as looked for inside approved directories. Serves
/// both `ProviderCategory::Formatter` (`ruff format`, resolved by
/// `wht_corulix_formatter`'s own profile table) and `ProviderCategory::Linter`
/// (`ruff check`, resolved here) -- one binary, two categories, never two
/// independently-resolved identities.
pub(crate) const RUFF_EXECUTABLE: &str = "ruff";
/// The one-shot, `--outputjson` typecheck identity -- distinct from
/// `wht_corulix_lsp`'s own `pyright-langserver` provider id (ADR 0011 §3).
pub(crate) const PYRIGHT_EXECUTABLE: &str = "pyright";
pub(crate) const PYTEST_EXECUTABLE: &str = "pytest";
/// ADR 0011 §5's own `python3` runtime identity. No P17 validator invokes
/// this directly (see this module's own doc comment), but
/// [`resolve_python_runtime`] resolves and version-probes it for real,
/// standalone runtime-availability reporting (mirroring
/// `crate::go_providers::resolve_go_toolchain`'s own `Runtime`-category
/// completeness) -- never dead policy, exercised by this module's own test.
pub(crate) const PYTHON_EXECUTABLE: &str = "python3";

/// Why a real Python-family tool could not be resolved or identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonProviderError {
    /// `wht_corulix_config::resolve_provider` reported the provider
    /// unavailable. Carries the resolver's own specific [`ReasonCode`]
    /// verbatim -- `P17_PROVIDER_FALLBACK_COUNT=0`.
    ProviderUnavailable(Option<ReasonCode>),
    /// The resolved executable did not answer `--version` with a usable
    /// identity string. Fails closed: Evidence must carry the *exact*
    /// provider identity, never an ambiguous placeholder.
    IdentityUnavailable,
    /// The `CORULIX_MANAGED` component (Ruff, or Pyright's managed CLI/Node
    /// dependency) is present on disk but classified
    /// `ManagedComponentState::Corrupt`/`Incompatible` (managed-toolchain
    /// ownership/integrity hardening pass: missing/malformed/mismatched
    /// ownership record, or a tampered artifact). Fails closed here, before
    /// the `HOST_ONLY` fallback tier is ever consulted -- mirrors
    /// `crate::go_providers::GoProviderError::ManagedComponentInvalid`
    /// exactly: an invalid managed installation must never fall through to
    /// an explicit approved `HOST_ONLY` tool, which would silently mask it.
    ManagedComponentInvalid,
}

/// A resolved, identified Python-family tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPythonTool {
    /// The canonicalized `resolve_provider`-approved executable.
    pub executable: PathBuf,
    /// Real `<tool> --version` output, verbatim and trimmed. Never a
    /// hard-coded constant.
    pub version: String,
}

/// Resolves `provider_id` for `category` through the Phase-6 secure provider
/// resolver, then probes its real identity via `<tool> --version`
/// (empirically confirmed for `ruff`/`pyright`/`pytest`/`python3` alike --
/// see ADR 0011's own version-identity-probe rows).
///
/// Pyright specifically also needs a real `node` interpreter resolved and
/// placed on the probe's own `PATH` -- see `pyright_invocation_environment`'s
/// own doc comment for why. Every other provider probes with an empty
/// environment, exactly as before.
pub async fn resolve_python_tool(
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    category: ProviderCategory,
    provider_id: &'static str,
    cancellation: &CancellationToken,
) -> Result<ResolvedPythonTool, PythonProviderError> {
    let resolution =
        wht_corulix_config::resolve_provider(effective, workspace_root, category, provider_id)
            .await;
    if resolution.availability != wht_corulix_core::ProviderAvailability::Available {
        return Err(PythonProviderError::ProviderUnavailable(resolution.reason));
    }
    let Some(executable) = resolution.resolved_path else {
        return Err(PythonProviderError::ProviderUnavailable(resolution.reason));
    };

    let environment = if provider_id == PYRIGHT_EXECUTABLE {
        pyright_invocation_environment(effective, workspace_root, cancellation)
            .await
            .ok_or(PythonProviderError::IdentityUnavailable)?
    } else {
        EnvironmentPolicy::empty()
    };
    let version = probe_version(&executable, provider_id, environment, cancellation)
        .await
        .ok_or(PythonProviderError::IdentityUnavailable)?;
    Ok(ResolvedPythonTool {
        executable,
        version,
    })
}

/// This platform's `ruff` managed-component manifest (M03 Python
/// managed-auxiliary final closure, owner-pinned Ruff 0.16.3) -- the exact
/// same manifest `wht_corulix_formatter`'s own `ruff_host_native` resolves
/// for the Formatter category. Reused verbatim, mirroring
/// `crate::go_providers::managed_go_runtime_manifest`'s own precedent: one
/// component, one lifecycle, shared by Formatter and Linter alike, never two
/// independently-provisioned copies.
#[must_use]
pub(crate) fn managed_ruff_manifest() -> ManagedComponentManifest {
    #[cfg(target_os = "windows")]
    {
        wht_corulix_tooling::managed_runtimes::RUFF_WINDOWS_X64
    }
    #[cfg(not(target_os = "windows"))]
    {
        wht_corulix_tooling::managed_runtimes::RUFF_LINUX_X64
    }
}

/// Tier 1 of [`resolve_ruff_tool`]: resolves the managed Ruff component,
/// purely from local, already-verified state. `Ok(None)` on a genuinely
/// not-yet-provisioned state (the caller falls through to `HOST_ONLY`);
/// `Err(ManagedComponentInvalid)` on a present-but-invalid installation
/// (fails closed, never falls through). Mirrors
/// `crate::go_providers::resolve_managed_go_toolchain` exactly.
async fn resolve_managed_ruff(
    managed_root: &Path,
    cancellation: &CancellationToken,
) -> Result<Option<ResolvedPythonTool>, PythonProviderError> {
    let manifest = managed_ruff_manifest();
    let (state, executable, _reason) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component_detailed(
            managed_root,
            &manifest,
        );
    match state {
        ManagedComponentState::Available => {}
        ManagedComponentState::Corrupt | ManagedComponentState::Incompatible => {
            return Err(PythonProviderError::ManagedComponentInvalid);
        }
        ManagedComponentState::NotProvisioned | ManagedComponentState::Provisioning | _ => {
            return Ok(None);
        }
    }
    let Some(executable) = executable else {
        return Ok(None);
    };
    let Some(version) = probe_version(
        &executable,
        RUFF_EXECUTABLE,
        EnvironmentPolicy::empty(),
        cancellation,
    )
    .await
    else {
        return Ok(None);
    };
    Ok(Some(ResolvedPythonTool {
        executable,
        version,
    }))
}

/// Resolves the real `ruff` executable for `category` (`Formatter` or
/// `Linter`), managed-first then `HOST_ONLY`-fallback -- the M03 Python
/// managed-auxiliary final closure narrowly supersedes ADR 0011 §1 for this
/// one tool, exactly as `crate::go_providers::resolve_go_toolchain` already
/// does for `go`. Two ordered tiers:
///
/// 1. `CORULIX_MANAGED` ([`resolve_managed_ruff`]), tried first.
/// 2. `HOST_ONLY`/approved-directory, via the pre-existing
///    [`resolve_python_tool`] (unchanged) -- tried only when tier 1 reports a
///    genuinely not-yet-provisioned state.
///
/// `pytest`/`python3` are unaffected: they continue to call
/// [`resolve_python_tool`] directly, never this function, and ADR 0011's
/// original `HOST_ONLY`-only authority for them stays unmodified.
pub(crate) async fn resolve_ruff_tool(
    managed_root: &Path,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    category: ProviderCategory,
    cancellation: &CancellationToken,
) -> Result<ResolvedPythonTool, PythonProviderError> {
    if let Some(managed) = resolve_managed_ruff(managed_root, cancellation).await? {
        return Ok(managed);
    }
    resolve_python_tool(
        effective,
        workspace_root,
        category,
        RUFF_EXECUTABLE,
        cancellation,
    )
    .await
}

/// A resolved, ready-to-invoke Pyright CLI (`TypecheckBuild`). Unlike every
/// other Python-family tool, the managed and `HOST_ONLY` tiers have
/// genuinely different invocation shapes: a `HOST_ONLY` `pyright` is a
/// self-contained executable (or a shebang script the OS resolves on its
/// own), while the managed component's CLI entrypoint (`package/index.js`,
/// **not** `package/dist/pyright.js` -- see [`resolve_managed_pyright_cli`]'s
/// own doc comment for why `index.js` is load-bearing) is a plain Node
/// script and must be spawned as `node <index.js> [args]` -- `node` is the
/// executable, the script path is the first argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedPyrightCli {
    HostOnly {
        executable: PathBuf,
        version: String,
    },
    Managed {
        node_executable: PathBuf,
        cli_script: PathBuf,
        version: String,
    },
}

impl ResolvedPyrightCli {
    #[must_use]
    pub(crate) fn version(&self) -> &str {
        match self {
            Self::HostOnly { version, .. } | Self::Managed { version, .. } => version,
        }
    }

    /// The `ProcessSpec` executable/leading-arguments pair for this
    /// resolution: `HostOnly` spawns `pyright` directly with no leading
    /// argument; `Managed` spawns `node` with the CLI script path prepended
    /// to whatever arguments the caller appends.
    #[must_use]
    pub(crate) fn executable_and_leading_arguments(&self) -> (PathBuf, Vec<String>) {
        match self {
            Self::HostOnly { executable, .. } => (executable.clone(), Vec::new()),
            Self::Managed {
                node_executable,
                cli_script,
                ..
            } => (
                node_executable.clone(),
                vec![cli_script.to_string_lossy().into_owned()],
            ),
        }
    }
}

/// Runs `node <script> --version` through the controlled process runtime and
/// returns its trimmed combined stdout+stderr. `None` on any failure -- the
/// caller fails closed with [`PythonProviderError::IdentityUnavailable`]
/// rather than fabricating an identity. Separate from [`probe_version`]
/// because the managed Pyright CLI is invoked as `node <script> [args]`, a
/// two-token argument shape `probe_version`'s own single-argument `--version`
/// probe cannot express.
async fn probe_node_script_version(
    node_executable: &Path,
    script: &Path,
    cancellation: &CancellationToken,
) -> Option<String> {
    let spec = ProcessSpec {
        executable: node_executable.to_path_buf(),
        arguments: vec![
            script.to_string_lossy().into_owned(),
            "--version".to_string(),
        ],
        environment: EnvironmentPolicy::empty(),
        working_directory: std::env::temp_dir(),
        limits: ProcessLimits::default(),
        timeout: std::time::Duration::from_secs(10),
        execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
        argv0: None,
    };
    let outcome = wht_corulix_tooling::execute(&spec, cancellation).await;
    if !matches!(outcome.termination, TerminationReason::Exited { code: 0 }) {
        return None;
    }
    let mut combined = outcome.stdout.bytes;
    combined.extend_from_slice(&outcome.stderr.bytes);
    let text = String::from_utf8(combined).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Tier 1 of [`resolve_pyright_cli`]: resolves the managed Node runtime and
/// the managed Pyright component's real CLI entrypoint, `package/index.js`
/// (**not** `package/dist/pyright.js` directly -- `index.js` sets
/// `global.__rootDirectory` before requiring the `dist/pyright` bundle, and
/// pyright's own bundled typeshed-stub resolution depends on that global;
/// empirically proven by direct comparison: invoking `dist/pyright.js`
/// directly against a trivial one-file fixture produced 1128 spurious
/// "import could not be resolved" errors, while invoking `index.js` against
/// the identical fixture produced the correct `errorCount: 0`). Both
/// `package/index.js` and `package/dist/pyright.js` are `required_paths` on
/// this manifest (see
/// `wht_corulix_lsp::managed_toolchain::PYRIGHT_LINUX_X64`'s own doc
/// comment), so both are already covered by this component's installed-
/// payload integrity. `Ok(None)` when either dependency is genuinely not yet
/// provisioned (falls through to `HOST_ONLY`); `Err(ManagedComponentInvalid)`
/// when either is present but invalid (fails closed).
async fn resolve_managed_pyright_cli(
    managed_root: &Path,
    cancellation: &CancellationToken,
) -> Result<Option<ResolvedPyrightCli>, PythonProviderError> {
    let node_manifest = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
    let (node_state, node_executable, _reason) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component_detailed(
            managed_root,
            &node_manifest,
        );
    let node_executable = match node_state {
        ManagedComponentState::Available => match node_executable {
            Some(executable) => executable,
            None => return Ok(None),
        },
        ManagedComponentState::Corrupt | ManagedComponentState::Incompatible => {
            return Err(PythonProviderError::ManagedComponentInvalid);
        }
        ManagedComponentState::NotProvisioned | ManagedComponentState::Provisioning | _ => {
            return Ok(None);
        }
    };

    let pyright_manifest = wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE;
    let (pyright_state, _langserver_path, _reason) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component_detailed(
            managed_root,
            &pyright_manifest,
        );
    let cli_script = match pyright_state {
        ManagedComponentState::Available => {
            // `package/index.js`, **not** `package/dist/pyright.js` directly:
            // `index.js` sets `global.__rootDirectory = __dirname + '/dist/'`
            // before `require('./dist/pyright')`, and pyright's own bundled
            // typeshed-stub resolution depends on that global being set
            // (empirically proven: invoking `dist/pyright.js` directly
            // against a trivial one-file fixture produced 1128 spurious
            // "import could not be resolved" errors; invoking `index.js`
            // against the identical fixture produced the correct
            // `errorCount: 0`). Derived from `component_install_dir`, not
            // from the resolved langserver path's own directory, since
            // `index.js` sits one level above `dist/` -- both
            // `package/index.js` and `package/dist/pyright.js` are `required_paths`
            // on this manifest (see [`wht_corulix_lsp::managed_toolchain::PYRIGHT_LINUX_X64`]'s
            // own doc comment), so both are already covered by this
            // component's installed-payload integrity.
            let candidate = wht_corulix_tooling::provisioning::component_install_dir(
                managed_root,
                &pyright_manifest,
            )
            .join("package/index.js");
            if candidate.is_file() {
                candidate
            } else {
                return Ok(None);
            }
        }
        ManagedComponentState::Corrupt | ManagedComponentState::Incompatible => {
            return Err(PythonProviderError::ManagedComponentInvalid);
        }
        ManagedComponentState::NotProvisioned | ManagedComponentState::Provisioning | _ => {
            return Ok(None);
        }
    };

    let Some(version) =
        probe_node_script_version(&node_executable, &cli_script, cancellation).await
    else {
        return Ok(None);
    };
    Ok(Some(ResolvedPyrightCli::Managed {
        node_executable,
        cli_script,
        version,
    }))
}

/// Resolves the real Pyright CLI for `ProviderCategory::TypecheckBuild`,
/// managed-first then `HOST_ONLY`-fallback -- mirrors
/// [`resolve_ruff_tool`]/`crate::go_providers::resolve_go_toolchain` exactly.
/// `wht_corulix_lsp`'s own `pyright-langserver` `LanguageServer` resolution
/// (ADR 0009) is untouched by this: this function resolves a wholly separate
/// process invocation (the one-shot `--outputjson` CLI), never the long-lived
/// LSP session.
pub(crate) async fn resolve_pyright_cli(
    managed_root: &Path,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    cancellation: &CancellationToken,
) -> Result<ResolvedPyrightCli, PythonProviderError> {
    if let Some(managed) = resolve_managed_pyright_cli(managed_root, cancellation).await? {
        return Ok(managed);
    }
    let host_only = resolve_python_tool(
        effective,
        workspace_root,
        ProviderCategory::TypecheckBuild,
        PYRIGHT_EXECUTABLE,
        cancellation,
    )
    .await?;
    Ok(ResolvedPyrightCli::HostOnly {
        executable: host_only.executable,
        version: host_only.version,
    })
}

/// Runs `<executable> --version` through the controlled process runtime and
/// returns its trimmed output. `None` on any failure -- the caller fails
/// closed with [`PythonProviderError::IdentityUnavailable`] rather than
/// fabricating an identity.
///
/// `ExecutionClass::ControlledExternalTool`: a bare version probe reads no
/// repository content and executes no repository-authored code, so it
/// legitimately needs no trust grant, mirroring
/// `crate::go_providers::probe_go_version`'s identical reasoning.
async fn probe_version(
    executable: &Path,
    argv0: &str,
    environment: EnvironmentPolicy,
    cancellation: &CancellationToken,
) -> Option<String> {
    let spec = ProcessSpec {
        executable: executable.to_path_buf(),
        arguments: vec!["--version".to_string()],
        environment,
        working_directory: std::env::temp_dir(),
        limits: ProcessLimits::default(),
        timeout: std::time::Duration::from_secs(10),
        execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
        argv0: Some(argv0.to_string()),
    };
    let outcome = wht_corulix_tooling::execute(&spec, cancellation).await;
    if !matches!(outcome.termination, TerminationReason::Exited { code: 0 }) {
        return None;
    }
    // `pytest --version` prints to stderr on some builds, stdout on others
    // (observed: `pytest 9.1.1` on stdout on this host) -- combine both
    // rather than assuming one stream, never fabricating a version from
    // neither.
    let mut combined = outcome.stdout.bytes;
    combined.extend_from_slice(&outcome.stderr.bytes);
    let text = String::from_utf8(combined).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// A `PATH` naming exactly the real, resolved `node` interpreter's own
/// directory -- `None` when `node` cannot itself be resolved
/// (`ProviderCategory::Runtime`).
///
/// Load-bearing for `pyright`: it is a `#!/usr/bin/env node` script, and its
/// *canonicalized* resolution (what `wht_corulix_config::resolve_provider`
/// returns, and what `fs::canonicalize` always fully resolves a symlink to)
/// is the real target file deep inside
/// `.../lib/node_modules/pyright/index.js` -- **not** the `bin/pyright`
/// symlink's own directory, which is the one that actually contains a
/// sibling `node` binary. Deriving `PATH` from the *executable*'s own parent
/// (a naive "sibling" approach) therefore fails empirically confirmed on
/// this host: `env: 'node': No such file or directory`. Resolving `node`
/// itself, independently, through the same `ProviderCategory::Runtime`
/// authority ADR 0011 §5 already names is the correct fix, and mirrors
/// `wht_corulix_lsp::profile::LspProviderProfile::pyright`'s own
/// `interpreter: Some(AuxiliaryToolRequirement { provider_name: "node", .. })`
/// declaration for the identical dependency in the LSP session path.
pub(crate) async fn pyright_invocation_environment(
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    cancellation: &CancellationToken,
) -> Option<EnvironmentPolicy> {
    let node_resolution = wht_corulix_config::resolve_provider(
        effective,
        workspace_root,
        ProviderCategory::Runtime,
        "node",
    )
    .await;
    if node_resolution.availability != wht_corulix_core::ProviderAvailability::Available {
        return None;
    }
    let node_executable = node_resolution.resolved_path?;
    let _ = cancellation; // reserved for a future cancellable resolution step
    let bin_dir = node_executable
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    Some(EnvironmentPolicy::empty().with_var("PATH", bin_dir.to_string_lossy().into_owned()))
}

/// Resolves and version-probes the real `python3` runtime
/// (`ProviderCategory::Runtime`), per ADR 0011 §5. Standalone availability
/// reporting only -- see this module's own doc comment for why no P17
/// validator invokes the result directly.
pub async fn resolve_python_runtime(
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    cancellation: &CancellationToken,
) -> Result<ResolvedPythonTool, PythonProviderError> {
    resolve_python_tool(
        effective,
        workspace_root,
        ProviderCategory::Runtime,
        PYTHON_EXECUTABLE,
        cancellation,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_executable_names_are_stable() {
        assert_eq!(RUFF_EXECUTABLE, "ruff");
        assert_eq!(PYRIGHT_EXECUTABLE, "pyright");
        assert_eq!(PYTEST_EXECUTABLE, "pytest");
        assert_eq!(PYTHON_EXECUTABLE, "python3");
    }

    /// `ProviderCategory::Runtime` is real host-resolved authority for
    /// `python3`, exercised against this host's own real toolchain --
    /// `real_python3_available` guards the case where this sandbox has no
    /// approved directory granting it (never asserting a fabricated
    /// success).
    #[tokio::test]
    async fn resolve_python_runtime_uses_the_runtime_category()
    -> wht_corulix_core::CorulixResult<()> {
        let root_dir = std::env::temp_dir().join(format!(
            "corulix-python-providers-runtime-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::create_dir_all(&root_dir);
        let workspace_root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        // No approved directories granted: this must fail closed, never
        // silently succeed via ambient PATH.
        let context = wht_corulix_workspace::WorkspaceContext::single_root(
            workspace_root.clone(),
            "root".to_string(),
        );
        let engine = crate::CorulixEngine::open_with_trust(context, true);
        let effective = engine.effective_config(engine.root_id_for(&workspace_root));
        let cancellation = CancellationToken::new();
        let result = resolve_python_runtime(&effective, &workspace_root, &cancellation).await;
        assert!(
            matches!(result, Err(PythonProviderError::ProviderUnavailable(_))),
            "expected ProviderUnavailable with no approved directory granted, got {result:?}"
        );
        let _ = std::fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// M03 Python managed-auxiliary final closure: this crate's managed
    /// Ruff selection must be the exact same manifest identity
    /// (`id`/`version`/`expected_sha256_hex`) `wht_corulix_formatter`'s own
    /// `ruff_host_native` resolves for the Formatter category -- both point
    /// at the single `pub const RUFF_LINUX_X64`/`RUFF_WINDOWS_X64` declared
    /// once in `wht_corulix_tooling::managed_runtimes`, so this test pins
    /// this crate's own selector to that shared source of truth (mirrors
    /// `crate::go_providers::managed_go_runtime_manifest_matches_the_lsp_crates_own_identity_for_this_platform`).
    #[test]
    fn managed_ruff_manifest_matches_the_shared_tooling_constant_for_this_platform() {
        let manifest = managed_ruff_manifest();
        assert_eq!(manifest.id.0, "ruff");
        assert_eq!(manifest.version, "0.16.3");
        #[cfg(target_os = "windows")]
        {
            let reference = wht_corulix_tooling::managed_runtimes::RUFF_WINDOWS_X64;
            assert_eq!(manifest.platform, "windows");
            assert_eq!(
                manifest.source.expected_sha256_hex,
                reference.source.expected_sha256_hex
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            let reference = wht_corulix_tooling::managed_runtimes::RUFF_LINUX_X64;
            assert_eq!(manifest.platform, "linux");
            assert_eq!(
                manifest.source.expected_sha256_hex,
                reference.source.expected_sha256_hex
            );
        }
    }

    /// Negative control, no real Ruff required: an empty `managed_root`
    /// (nothing ever provisioned into it) must make [`resolve_managed_ruff`]
    /// report `Ok(None)` -- a clean "not available", never an error, so the
    /// caller falls through to the `HOST_ONLY` tier. Mirrors
    /// `crate::go_providers::managed_tier_reports_unavailable_against_an_empty_managed_root`.
    #[tokio::test]
    async fn resolve_managed_ruff_reports_unavailable_against_an_empty_managed_root() {
        let temp = std::env::temp_dir().join(format!(
            "corulix-ruff-providers-empty-root-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&temp);
        let cancellation = CancellationToken::new();
        let resolved = resolve_managed_ruff(&temp, &cancellation).await;
        assert!(
            matches!(resolved, Ok(None)),
            "an empty managed_root must never resolve a managed Ruff or error: {resolved:?}"
        );
        let _ = std::fs::remove_dir_all(&temp);
    }

    /// Real, positive proof against this host's own shared managed-toolchain
    /// root: once `corulix setup --only python` has provisioned Ruff (this
    /// test suite's own CI/dev environment does so as part of the M03 Python
    /// managed-auxiliary final closure), [`resolve_managed_ruff`] must
    /// resolve it as `Available` with a real, independently re-probed
    /// `ruff 0.16.3` identity -- never a fabricated version string. Skips
    /// (rather than fails) when this host genuinely has not provisioned
    /// Ruff yet, mirroring this module's own tolerance for an unprovisioned
    /// sandbox elsewhere (`resolve_python_runtime_uses_the_runtime_category`).
    #[tokio::test]
    async fn resolve_managed_ruff_resolves_the_real_provisioned_component_when_available() {
        let Ok(managed_root) = wht_corulix_tooling::provisioning::managed_toolchain_root() else {
            return;
        };
        let cancellation = CancellationToken::new();
        let resolved = resolve_managed_ruff(&managed_root, &cancellation).await;
        match resolved {
            Ok(Some(tool)) => {
                assert!(
                    tool.version.contains("0.16.3"),
                    "expected the real pinned Ruff 0.16.3 identity, got {:?}",
                    tool.version
                );
            }
            Ok(None) => {
                // Genuinely not provisioned on this host -- acceptable, not
                // this test's concern (provisioning is exercised via the
                // canonical `corulix setup --only python` path, not here).
            }
            Err(error) => unreachable!("expected Available or NotProvisioned, got Err({error:?})"),
        }
    }

    /// Same negative control as
    /// [`resolve_managed_ruff_reports_unavailable_against_an_empty_managed_root`],
    /// for the Pyright CLI's own two-component (Node + Pyright) managed
    /// resolution.
    #[tokio::test]
    async fn resolve_managed_pyright_cli_reports_unavailable_against_an_empty_managed_root() {
        let temp = std::env::temp_dir().join(format!(
            "corulix-pyright-cli-empty-root-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&temp);
        let cancellation = CancellationToken::new();
        let resolved = resolve_managed_pyright_cli(&temp, &cancellation).await;
        assert!(
            matches!(resolved, Ok(None)),
            "an empty managed_root must never resolve a managed Pyright CLI or error: {resolved:?}"
        );
        let _ = std::fs::remove_dir_all(&temp);
    }

    /// Real, positive proof: once Node + Pyright are provisioned (this host's
    /// own state after `corulix setup --only python`),
    /// [`resolve_managed_pyright_cli`] must resolve the real CLI entrypoint
    /// (`package/index.js`, not `dist/pyright.js` directly) and independently
    /// re-probe its real `node <script> --version` identity -- proving
    /// `PYRIGHT_CLI_ENTRYPOINT_COVERED_BY_INSTALLED_PAYLOAD_INTEGRITY` in
    /// practice, not merely by manifest inspection. Skips when this host has
    /// not provisioned either dependency.
    #[tokio::test]
    async fn resolve_managed_pyright_cli_resolves_the_real_provisioned_component_when_available() {
        let Ok(managed_root) = wht_corulix_tooling::provisioning::managed_toolchain_root() else {
            return;
        };
        let cancellation = CancellationToken::new();
        let resolved = resolve_managed_pyright_cli(&managed_root, &cancellation).await;
        match resolved {
            Ok(Some(ResolvedPyrightCli::Managed {
                cli_script,
                version,
                ..
            })) => {
                assert!(
                    cli_script.ends_with("index.js"),
                    "expected the real CLI entrypoint (index.js), got {cli_script:?}"
                );
                assert!(
                    version.contains("1.1.413"),
                    "expected the real pinned Pyright 1.1.413 identity, got {version:?}"
                );
            }
            Ok(Some(ResolvedPyrightCli::HostOnly { .. })) => {
                unreachable!("resolve_managed_pyright_cli must never return a HostOnly variant")
            }
            Ok(None) => {
                // Genuinely not provisioned on this host -- acceptable.
            }
            Err(error) => unreachable!("expected Available or NotProvisioned, got Err({error:?})"),
        }
    }
}
