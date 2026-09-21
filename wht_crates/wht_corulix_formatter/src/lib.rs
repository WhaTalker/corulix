// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Sole owner of controlled, staging-only source formatter governance for
//! WhaTalker Corulix (Architecture Rule N).
//!
//! `RUSTFMT_FORMATTING_AUTHORITY=YES`, `P15_GOFMT_AUTHORITY=AUTHORITATIVE`,
//! `LSP_FORMATTING_AUTHORITY=NO`: rustfmt is the sole formatting authority
//! for Rust source and gofmt is the sole formatting authority for Go source;
//! `wht_corulix_lsp`'s `textDocument/formatting` capability (whether
//! rust-analyzer or gopls advertises one) is never treated as authoritative
//! anywhere in this workspace.
//!
//! Which formatter is authoritative for which language -- and its argv,
//! config-discovery behavior, managed pinning, and version-identity probe --
//! is [`profile`]'s single table. P15 added Go by parameterizing exactly
//! that provider detail; the governance path below (bounded confined read,
//! pre-format precondition hash, stdin/stdout-only invocation, verified
//! output bytes, one `wht_corulix_mutation` apply) is language-independent
//! and unchanged from its Phase 9/10/10-R2 certified form.
//!
//! # Canonical flow
//!
//! ```text
//! caller observes current bytes + precondition hash (read-only)
//!   |
//! wht_corulix_config::resolve_provider  -- rustfmt executable resolution (Rule K)
//!   |
//! wht_corulix_tooling::ManagedProcess   -- controlled stdin/stdout invocation (Rule G)
//!   |
//! verified formatted bytes (never raw, unverified stdout)
//!   |
//! wht_corulix_mutation::MutationExecutor -- ReplaceFile, gated on the ORIGINAL
//!   |                                       precondition hash (Rule M)
//! live workspace
//! ```
//!
//! rustfmt itself never performs a direct in-place write to the live
//! workspace: it is invoked exclusively over stdin/stdout (see
//! `invocation`'s own docs for the empirical research behind that choice),
//! so there is no filesystem path for rustfmt's own process to touch at
//! all. The only component in this whole flow with live-write authority is
//! `wht_corulix_mutation::MutationExecutor`, invoked here exactly as any
//! other caller would invoke it -- this crate never bypasses
//! `expected_precondition_hash`/PREPARE/STAGE/COMMIT/VERIFY, and an
//! out-of-band change to the target between the pre-format hash capture and
//! this crate's own `MutationBatch` apply surfaces as the same
//! `MutationError::StalePreconditionHash` any other caller would see.
//!
//! # What this phase does not implement
//!
//! No `ChangeSession`/Evidence state machine, no `gate.format` evaluator (a
//! later Engine phase reads `FormatterResult` and closes/fails that gate),
//! no MCP `format_preview` surface, no linter/build/test governance, and no
//! implicit repository-wide formatting -- scope is always exactly the one
//! [`wht_corulix_core::WorkspacePath`] the caller names.

mod config_discovery;
mod error;
mod invocation;
mod managed;
pub mod managed_toolchain;
pub mod profile;
mod result;

pub use error::FormatterError;
pub use result::{FormatStatus, FormatterResult};

use std::path::PathBuf;
use std::time::Duration;
use wht_corulix_config::EffectiveConfig;
use wht_corulix_core::{
    CancellationToken, ContentHash, CorulixError, LanguageId, ProviderAvailability, WorkspacePath,
};
use wht_corulix_mutation::{Mutation, MutationBatch, MutationExecutor};
use wht_corulix_workspace::WorkspaceRoot;

/// Bound on a target's current content this crate will ever read before
/// attempting to format it. A file exceeding this fails closed
/// (`FormatterError::OversizedInput`) before rustfmt is ever invoked.
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
/// The bound on how long one rustfmt invocation may run before this crate
/// terminates it and reports `FormatStatus::TimedOut`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The `go` executable's name, looked for as a *sibling* of an already
/// trust-verified `gofmt` when deriving Go's provider version identity --
/// see [`profile::VersionProbe::SiblingGoVersion`] for why gofmt has no
/// version flag of its own and why this is not an ambient `PATH` lookup.
const GO_SIBLING_EXECUTABLE: &str = "go";

/// Formats exactly `path` (never an implicit repository-wide scope) and, if
/// rustfmt reports different bytes than the input, applies the verified
/// result through [`wht_corulix_mutation::MutationExecutor`].
///
/// `executor` is a caller-owned [`MutationExecutor`] -- this crate never
/// constructs one of its own, matching every other caller of that type.
/// `input_max_bytes` lets a caller narrow (never widen) this crate's own
/// [`DEFAULT_MAX_INPUT_BYTES`] bound.
///
/// Returns `Err` only for a guard failure that occurs *before* rustfmt is
/// invoked, or for the final mutation-apply step's own error (see
/// [`FormatterError`]'s docs). Every outcome where rustfmt was actually
/// resolved and/or invoked -- including "unavailable", "already
/// formatted", "non-zero exit", "timed out", "cancelled" -- is a typed
/// `Ok(FormatterResult)`, never an exception.
pub async fn format_and_apply(
    effective: &EffectiveConfig,
    workspace_root: WorkspaceRoot,
    executor: &MutationExecutor,
    path: WorkspacePath,
    input_max_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<FormatterResult, FormatterError> {
    let managed_root = wht_corulix_tooling::provisioning::managed_toolchain_root()
        .map_err(|_| FormatterError::ManagedToolchainRootUnavailable)?;
    format_and_apply_at(
        &managed_root,
        effective,
        workspace_root,
        executor,
        path,
        input_max_bytes,
        cancellation,
    )
    .await
}

/// The real resolution/formatting logic behind [`format_and_apply`],
/// parameterized on an explicit `managed_root` rather than resolving the
/// host-wide canonical root internally -- the exact same `_at(root)`
/// precedent `wht_corulix_lsp::resolve_launch`/`resolve_launch_at` already
/// establish, for the same reason: an isolated, explicit managed-root test
/// context can exercise the real production `CORULIX_MANAGED`-first
/// resolution and formatting path without touching the shared, host-wide
/// `managed_toolchain_root()`.
pub async fn format_and_apply_at(
    managed_root: &std::path::Path,
    effective: &EffectiveConfig,
    workspace_root: WorkspaceRoot,
    executor: &MutationExecutor,
    path: WorkspacePath,
    input_max_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<FormatterResult, FormatterError> {
    format_and_apply_impl(
        managed_root,
        effective,
        workspace_root,
        executor,
        path,
        input_max_bytes,
        cancellation,
        None,
    )
    .await
}

/// Test-only variant of [`format_and_apply`] that runs `on_input_observed`
/// synchronously right after this crate captures the pre-format
/// `expected_precondition_hash`, and before rustfmt is resolved/invoked.
/// This is the deterministic (never flaky-timing-based) mechanism this
/// crate's own test suite uses to prove the mandatory "out-of-band change
/// during formatting -> stale precondition -> reject" negative test against
/// the real, end-to-end `format_and_apply` flow, mirroring
/// `wht_corulix_mutation`'s own `#[cfg(test)]`-only `FailureInjectionPoint`
/// convention for proving a race deterministically rather than via timing.
#[cfg(test)]
pub(crate) async fn format_and_apply_with_race_hook(
    effective: &EffectiveConfig,
    workspace_root: WorkspaceRoot,
    executor: &MutationExecutor,
    path: WorkspacePath,
    input_max_bytes: u64,
    cancellation: &CancellationToken,
    on_input_observed: impl FnOnce() + Send + 'static,
) -> Result<FormatterResult, FormatterError> {
    let managed_root = wht_corulix_tooling::provisioning::managed_toolchain_root()
        .map_err(|_| FormatterError::ManagedToolchainRootUnavailable)?;
    format_and_apply_impl(
        &managed_root,
        effective,
        workspace_root,
        executor,
        path,
        input_max_bytes,
        cancellation,
        Some(Box::new(on_input_observed)),
    )
    .await
}

/// The result of [`compute_formatted`]: either a terminal outcome that
/// needs no further step (unavailable, unchanged, failed, timed out,
/// cancelled), or a genuinely different formatted result whose caller must
/// still decide whether to apply it live ([`format_and_apply_impl`]) or
/// merely report it without writing ([`format_preview_impl`]).
enum ComputeOutcome {
    Terminal(FormatterResult),
    Changed {
        path: WorkspacePath,
        provider_path: PathBuf,
        provider_version: Option<String>,
        provider_used_managed: bool,
        input_hash: ContentHash,
        output_hash: ContentHash,
        formatted_bytes: Vec<u8>,
    },
}

/// The shared resolution/invocation core behind both
/// [`format_and_apply_impl`] (Phase 10-R2, applies via
/// [`wht_corulix_mutation::MutationExecutor`]) and [`format_preview_impl`]
/// (Phase 13, `format_preview` -- read-only, never applies): every step up
/// to and including the real rustfmt invocation is identical for "format
/// and apply" and "preview only", so this function performs that work
/// exactly once and lets its two callers decide what happens with a
/// genuinely different result.
#[allow(clippy::too_many_arguments)]
async fn compute_formatted(
    managed_root: &std::path::Path,
    effective: &EffectiveConfig,
    workspace_root: WorkspaceRoot,
    path: WorkspacePath,
    input_max_bytes: u64,
    cancellation: &CancellationToken,
    on_input_observed: Option<Box<dyn FnOnce() + Send>>,
) -> Result<ComputeOutcome, FormatterError> {
    let relative = PathBuf::from(&path.relative_path);

    // Guard 1: the target's language must have an admitted formatter
    // authority in `profile`'s table -- never Markdown/JSON/TOML/generated/
    // binary content, and never a language whose own phase has not admitted
    // one yet. Language detection is reused rather than reinvented (Rule C:
    // only `wht_corulix_syntax` owns it), and the profile lookup fails
    // closed (`profile::profile_for` returns `None` rather than borrowing
    // another language's formatter).
    let detected = wht_corulix_syntax::detect_language(&relative);
    let Some(formatter_profile) = detected.and_then(profile::profile_for) else {
        return Err(FormatterError::UnsupportedLanguage {
            path,
            language: detected,
        });
    };

    // Guard 2: read the target's current bytes under workspace confinement
    // (Rule F). `confined_read`'s own bound enforces the oversized-input
    // guarantee -- this crate does not duplicate that check.
    let original_bytes = wht_corulix_workspace::confined_read(
        workspace_root.clone(),
        relative.clone(),
        input_max_bytes,
    )
    .await
    .map_err(|error| map_read_error(error, &path))?;
    let input_hash = ContentHash::compute_sha256(&original_bytes);

    if let Some(hook) = on_input_observed {
        hook();
    }

    // Resolve rustfmt: `CORULIX_MANAGED` first, then the pre-existing
    // `HOST_ONLY`/system precedence unchanged (Rule K: only
    // `wht_corulix_config` decides `HOST_ONLY`/system trust/provider
    // identity -- `managed::resolve_formatter` only decides whether to try
    // the managed path first, exactly as `wht_corulix_lsp::profile` already
    // does for its own providers). Zero ambient PATH authority either way;
    // a workspace-local candidate can never satisfy `CONTROLLED_EXTERNAL_TOOL`.
    let resolved = match managed::resolve_formatter(
        &formatter_profile,
        effective,
        &workspace_root,
        managed_root,
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(reason) => {
            return Ok(ComputeOutcome::Terminal(FormatterResult {
                path,
                provider_path: None,
                provider_version: None,
                provider_used_managed: false,
                input_hash,
                output_hash: None,
                changed: false,
                status: FormatStatus::ProviderUnavailable,
                reason,
                truncated: false,
            }));
        }
    };
    let provider_path = resolved.executable;
    let formatter_environment = resolved.environment;
    let provider_used_managed = resolved.used_managed;
    let managed_primary_component_id = resolved.managed_primary_component_id;
    let managed_dependency_component_ids = resolved.managed_dependency_component_ids;

    let provider_version = fetch_provider_version(
        &formatter_profile,
        &provider_path,
        &formatter_environment,
        cancellation,
    )
    .await;

    let mut arguments: Vec<String> = formatter_profile
        .fixed_arguments
        .iter()
        .map(|argument| (*argument).to_string())
        .collect();

    // Real repository formatter-config discovery, bounded to the active
    // workspace -- influences style only, and only for a profile that
    // actually has a configuration file to discover (see
    // `profile::ConfigDiscovery` and `config_discovery`'s own docs for the
    // empirical research behind the exact mechanism; `gofmt` reads no
    // configuration file of any kind, so its arm skips this entirely rather
    // than inventing semantics the real tool does not have).
    if formatter_profile.config_discovery == profile::ConfigDiscovery::RustfmtToml {
        let start_dir = relative
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let confined_start_dir = wht_corulix_workspace::resolve_confined(
            workspace_root.clone(),
            if start_dir.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                start_dir
            },
        )
        .await
        .map(wht_corulix_workspace::ConfinedPath::into_path_buf)
        .unwrap_or_else(|_| workspace_root.canonical_path().to_path_buf());
        if let Some(dir) =
            config_discovery::discover_config_directory(workspace_root.clone(), confined_start_dir)
                .await
        {
            arguments.push("--config-path".to_string());
            arguments.push(dir.to_string_lossy().into_owned());
        }
    }

    let outcome = invocation::invoke_formatter(
        &provider_path,
        Some(formatter_profile.argv0.to_string()),
        arguments,
        invocation::FormatterCwd::PinnedWorkspace(&workspace_root),
        &original_bytes,
        formatter_environment.clone(),
        // Managed-component leasing applies only when the resolved provider
        // genuinely came from `CORULIX_MANAGED`. `managed_primary_component_id`/
        // `managed_dependency_component_ids` name whichever component
        // `managed::resolve_formatter` actually resolved (rustfmt, biome, or
        // the shared go-semantic-runtime) -- never a hardcoded rustfmt pair
        // regardless of which provider was really used (a real gap this
        // pass closed: adding a second managed formatter without this fix
        // would have leased rustfmt's own components while a Go managed
        // resolution's real go-semantic-runtime dependency went unleased).
        provider_used_managed
            .then_some(managed_primary_component_id)
            .flatten()
            .map(|primary_component_id| {
                wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                    wht_corulix_tooling::provisioning::lease::RootIdentity::of(managed_root),
                    primary_component_id,
                    managed_dependency_component_ids,
                )
            }),
        DEFAULT_TIMEOUT,
        cancellation,
    )
    .await;

    match outcome {
        invocation::InvocationOutcome::Completed {
            stdout,
            stdout_truncated: false,
            exit_code: 0,
        } => {
            let output_hash = ContentHash::compute_sha256(&stdout);
            let changed = stdout != original_bytes;
            if !changed {
                return Ok(ComputeOutcome::Terminal(FormatterResult {
                    path,
                    provider_path: Some(provider_path),
                    provider_version,
                    provider_used_managed,
                    input_hash,
                    output_hash: Some(output_hash),
                    changed: false,
                    status: FormatStatus::Unchanged,
                    reason: None,
                    truncated: false,
                }));
            }

            Ok(ComputeOutcome::Changed {
                path,
                provider_path,
                provider_version,
                provider_used_managed,
                input_hash,
                output_hash,
                formatted_bytes: stdout,
            })
        }
        invocation::InvocationOutcome::Completed {
            stdout_truncated, ..
        } => Ok(ComputeOutcome::Terminal(FormatterResult {
            path,
            provider_path: Some(provider_path),
            provider_version,
            provider_used_managed,
            input_hash,
            output_hash: None,
            changed: false,
            status: FormatStatus::InvocationFailed,
            reason: None,
            truncated: stdout_truncated,
        })),
        invocation::InvocationOutcome::Signaled | invocation::InvocationOutcome::SpawnFailed => {
            Ok(ComputeOutcome::Terminal(FormatterResult {
                path,
                provider_path: Some(provider_path),
                provider_version,
                provider_used_managed,
                input_hash,
                output_hash: None,
                changed: false,
                status: FormatStatus::InvocationFailed,
                reason: None,
                truncated: false,
            }))
        }
        invocation::InvocationOutcome::TimedOut => Ok(ComputeOutcome::Terminal(FormatterResult {
            path,
            provider_path: Some(provider_path),
            provider_version,
            provider_used_managed,
            input_hash,
            output_hash: None,
            changed: false,
            status: FormatStatus::TimedOut,
            reason: None,
            truncated: false,
        })),
        invocation::InvocationOutcome::Cancelled => Ok(ComputeOutcome::Terminal(FormatterResult {
            path,
            provider_path: Some(provider_path),
            provider_version,
            provider_used_managed,
            input_hash,
            output_hash: None,
            changed: false,
            status: FormatStatus::Cancelled,
            reason: None,
            truncated: false,
        })),
        invocation::InvocationOutcome::StoppedForUninstall => {
            Ok(ComputeOutcome::Terminal(FormatterResult {
                path,
                provider_path: Some(provider_path),
                provider_version,
                provider_used_managed,
                input_hash,
                output_hash: None,
                changed: false,
                status: FormatStatus::StoppedForUninstall,
                reason: None,
                truncated: false,
            }))
        }
    }
}

/// Applies [`compute_formatted`]'s result live through
/// [`wht_corulix_mutation::MutationExecutor`] when it found a genuine
/// difference; a terminal outcome (unavailable/unchanged/failed/timed out/
/// cancelled) passes through unchanged. This is the real body behind
/// [`format_and_apply`]/[`format_and_apply_at`].
#[allow(clippy::too_many_arguments)]
async fn format_and_apply_impl(
    managed_root: &std::path::Path,
    effective: &EffectiveConfig,
    workspace_root: WorkspaceRoot,
    executor: &MutationExecutor,
    path: WorkspacePath,
    input_max_bytes: u64,
    cancellation: &CancellationToken,
    on_input_observed: Option<Box<dyn FnOnce() + Send>>,
) -> Result<FormatterResult, FormatterError> {
    match compute_formatted(
        managed_root,
        effective,
        workspace_root,
        path,
        input_max_bytes,
        cancellation,
        on_input_observed,
    )
    .await?
    {
        ComputeOutcome::Terminal(result) => Ok(result),
        ComputeOutcome::Changed {
            path,
            provider_path,
            provider_version,
            provider_used_managed,
            input_hash,
            output_hash,
            formatted_bytes,
        } => {
            let batch = MutationBatch {
                mutations: vec![Mutation::ReplaceFile {
                    path: path.clone(),
                    expected_precondition_hash: input_hash.clone(),
                    content: formatted_bytes,
                }],
            };
            executor
                .execute(batch)
                .await
                .map(|_outcome| FormatterResult {
                    path: path.clone(),
                    provider_path: Some(provider_path),
                    provider_version,
                    provider_used_managed,
                    input_hash,
                    output_hash: Some(output_hash),
                    changed: true,
                    status: FormatStatus::Formatted,
                    reason: None,
                    truncated: false,
                })
                .map_err(FormatterError::Mutation)
        }
    }
}

/// Reports [`compute_formatted`]'s result without ever applying it: a
/// genuine difference is reported as [`FormatStatus::WouldFormat`], never
/// written through [`wht_corulix_mutation::MutationExecutor`]. This is the
/// real body behind [`format_preview`]/[`format_preview_at`] (Phase 13,
/// `format_preview` MCP tool) -- the one entry point this crate previously
/// documented as out of its own scope ("no MCP `format_preview` surface").
async fn format_preview_impl(
    managed_root: &std::path::Path,
    effective: &EffectiveConfig,
    workspace_root: WorkspaceRoot,
    path: WorkspacePath,
    input_max_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<FormatterResult, FormatterError> {
    match compute_formatted(
        managed_root,
        effective,
        workspace_root,
        path,
        input_max_bytes,
        cancellation,
        None,
    )
    .await?
    {
        ComputeOutcome::Terminal(result) => Ok(result),
        ComputeOutcome::Changed {
            path,
            provider_path,
            provider_version,
            provider_used_managed,
            input_hash,
            output_hash,
            formatted_bytes: _,
        } => Ok(FormatterResult {
            path,
            provider_path: Some(provider_path),
            provider_version,
            provider_used_managed,
            input_hash,
            output_hash: Some(output_hash),
            changed: true,
            status: FormatStatus::WouldFormat,
            reason: None,
            truncated: false,
        }),
    }
}

/// Formats exactly `path` in preview mode: every real resolution/invocation
/// step [`format_and_apply`] performs, but never applies a genuine
/// difference through [`wht_corulix_mutation::MutationExecutor`] -- the
/// live workspace file is never touched (Phase 13, `format_preview`).
pub async fn format_preview(
    effective: &EffectiveConfig,
    workspace_root: WorkspaceRoot,
    path: WorkspacePath,
    input_max_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<FormatterResult, FormatterError> {
    let managed_root = wht_corulix_tooling::provisioning::managed_toolchain_root()
        .map_err(|_| FormatterError::ManagedToolchainRootUnavailable)?;
    format_preview_at(
        &managed_root,
        effective,
        workspace_root,
        path,
        input_max_bytes,
        cancellation,
    )
    .await
}

/// The same explicit-`managed_root` precedent as [`format_and_apply_at`],
/// for [`format_preview`].
pub async fn format_preview_at(
    managed_root: &std::path::Path,
    effective: &EffectiveConfig,
    workspace_root: WorkspaceRoot,
    path: WorkspacePath,
    input_max_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<FormatterResult, FormatterError> {
    format_preview_impl(
        managed_root,
        effective,
        workspace_root,
        path,
        input_max_bytes,
        cancellation,
    )
    .await
}

/// F7 fix (`F7_FORMATTER_LIVE_AVAILABILITY_NOT_OVERLAID_IN_ROUTING`): reports
/// whether a real formatter is genuinely resolvable for `language` right
/// now, without invoking it and without applying any mutation -- the
/// resolution-only counterpart to `compute_formatted`'s own "Guard 1 +
/// resolve" steps, extracted so a caller that only needs an availability
/// verdict (Engine's `gate.edit` routing check) shares the exact same
/// authority [`format_and_apply`]/[`format_preview`] use, rather than
/// re-deriving a second, parallel "is it available" predicate. Delegates
/// directly to `profile::profile_for` and `managed::resolve_formatter`
/// -- the identical calls `compute_formatted` makes before it ever reads
/// the target's bytes or spawns a process -- so a language with no admitted
/// formatter authority (`profile_for` returns `None`) and a language whose
/// real resolution genuinely fails both report [`ProviderAvailability::
/// ProviderUnavailable`], matching `compute_formatted`'s own fail-closed
/// behavior exactly. `managed::resolve_formatter`'s own F6 on-demand
/// acquisition path is reached exactly as it would be from a real format
/// operation -- this function performs no execution of its own, but it does
/// not artificially suppress the same lazy-provisioning attempt a real
/// [`format_and_apply`]/[`format_preview`] call would make either.
pub async fn resolve_formatter_availability(
    language: LanguageId,
    effective: &EffectiveConfig,
    workspace_root: &WorkspaceRoot,
    managed_root: &std::path::Path,
) -> ProviderAvailability {
    let Some(formatter_profile) = profile::profile_for(language) else {
        return ProviderAvailability::ProviderUnavailable;
    };
    match managed::resolve_formatter(&formatter_profile, effective, workspace_root, managed_root)
        .await
    {
        Ok(_resolved) => ProviderAvailability::Available,
        Err(_reason) => ProviderAvailability::ProviderUnavailable,
    }
}

fn map_read_error(error: CorulixError, path: &WorkspacePath) -> FormatterError {
    match error {
        CorulixError::FileTooLarge => FormatterError::OversizedInput { path: path.clone() },
        CorulixError::PathDenied => FormatterError::ConfinementViolation { path: path.clone() },
        _ => FormatterError::ReadFailed { path: path.clone() },
    }
}

/// Best-effort provider-version probe, dispatched on the profile's own
/// [`profile::VersionProbe`] (P15 §29: Evidence must carry the *exact*
/// provider identity, never an ambiguous "system go"). `None` on any
/// failure: a missing version string never blocks formatting itself, and is
/// always reported honestly as unknown rather than substituted.
async fn fetch_provider_version(
    formatter_profile: &profile::FormatterProfile,
    executable: &std::path::Path,
    environment: &wht_corulix_tooling::EnvironmentPolicy,
    cancellation: &CancellationToken,
) -> Option<String> {
    let (probe_executable, arguments, argv0) = match formatter_profile.version_probe {
        profile::VersionProbe::SelfVersionFlag => (
            executable.to_path_buf(),
            vec!["--version".to_string()],
            formatter_profile.argv0.to_string(),
        ),
        profile::VersionProbe::SiblingGoVersion => {
            // The `go` executable sitting in the *same* directory as the
            // already-canonicalized, trust-verified `gofmt`
            // `wht_corulix_config::resolve_provider` returned. Never an
            // ambient `PATH` lookup, and never a directory the resolver did
            // not already approve -- if the sibling is absent, this yields
            // `None` rather than searching anywhere else.
            let sibling = executable.parent()?.join(GO_SIBLING_EXECUTABLE);
            if !sibling.is_file() {
                return None;
            }
            (
                sibling,
                vec!["version".to_string()],
                GO_SIBLING_EXECUTABLE.to_string(),
            )
        }
    };

    let spec = wht_corulix_tooling::ProcessSpec {
        executable: probe_executable,
        arguments,
        environment: environment.clone(),
        working_directory: std::env::temp_dir(),
        limits: wht_corulix_tooling::ProcessLimits::default(),
        timeout: Duration::from_secs(5),
        execution_class: wht_corulix_core::ExecutionClass::ControlledExternalTool,
        argv0: Some(argv0),
    };
    let outcome = wht_corulix_tooling::execute(&spec, cancellation).await;
    if !matches!(
        outcome.termination,
        wht_corulix_tooling::TerminationReason::Exited { code: 0 }
    ) {
        return None;
    }
    let text = String::from_utf8(outcome.stdout.bytes).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod fixture_support;
#[cfg(test)]
mod tests;
