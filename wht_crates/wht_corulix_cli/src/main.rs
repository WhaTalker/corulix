// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]
// This binary deliberately writes normal successful command output to
// stdout (Enterprise CLI Help mandate, stdout/stderr contract): errors and
// diagnostics still go to stderr, and stdout is reserved exclusively for
// the MCP protocol stream once `mcp stdio` starts. The workspace-wide
// `clippy::print_stdout = "deny"` lint exists to keep every *other* crate
// (which have no legitimate reason to ever write to stdout, since `mcp
// stdio`'s own protocol stream goes through `rmcp`'s transport, not
// `println!`) from accidentally corrupting a future MCP session -- this
// crate is the sole, intentional, documented exception.
#![allow(clippy::print_stdout)]

//! Command-line entry point for `corulix`.
//!
//! This binary wires the CLI surface (defined exclusively in [`cli`],
//! Architecture Rule I) to `wht_corulix_engine`/`wht_corulix_workspace` and, for
//! the `mcp stdio` subcommand, to `wht_corulix_mcp`. It never imports
//! `tree_sitter` directly, only through `wht_corulix_engine`/`wht_corulix_mcp`,
//! keeping Rule C's boundary intact all the way up to the binary, and it
//! implements no workspace canonicalization/confinement/discovery/descriptor-
//! parsing logic of its own (Architecture Rule F) -- workspace resolution is
//! delegated entirely to `wht_corulix_workspace`.
//!
//! Stdout discipline: normal human-facing command output goes to stdout;
//! diagnostics and errors go to stderr; once `mcp stdio` starts, stdout is
//! reserved exclusively for the MCP protocol stream.

mod cli;
mod help;

use clap::Parser;
use cli::{
    Cli, Command, LanguagesCommand, McpCommand, SetupProfileArg, ToolchainCommand,
    WorkspaceCommand, WorkspaceSelection,
};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};
use tracing_subscriber::EnvFilter;
use wht_corulix_engine::CorulixEngine;
use wht_corulix_workspace::{
    CORULIX_WORKSPACE_ENV_VAR, CORULIX_WORKSPACE_FILE_ENV_VAR, ResolvedWorkspace, WorkspaceContext,
    WorkspaceResolutionFailure, WorkspaceResolutionInputs, resolve_workspace,
};

/// Stable, documented CLI exit-code categories (see `corulix --help`) --
/// separate from clap's own usage-error exit code (2), which clap emits
/// itself for malformed invocations before any of this code runs.
mod exit_code {
    pub const SUCCESS: u8 = 0;
    pub const INTERNAL_ERROR: u8 = 1;
    pub const WORKSPACE_RESOLUTION_FAILURE: u8 = 3;
    pub const PATH_DENIED: u8 = 4;
    pub const UNSUPPORTED_OR_TOO_LARGE: u8 = 5;
    /// F1 fix: `--host-config` was given but could not be loaded (relative
    /// path, nonexistent/unreadable file, malformed content, unknown field,
    /// unrecognized value, or a path resolving inside the active
    /// workspace). Distinct from [`WORKSPACE_RESOLUTION_FAILURE`] -- this is
    /// a host-configuration failure, not a workspace-selection one.
    pub const HOST_CONFIG_FAILURE: u8 = 6;
    /// Installation-Contract-V1: `corulix setup` rejected a contradictory
    /// flag combination (`--profile on-demand` with `--only`/`--exclude`,
    /// the same group in both `--only` and `--exclude`) or an unrecognized
    /// group name -- rejected before any persistence or reconciliation ever
    /// runs, so this process's exit alone is proof nothing was mutated.
    pub const SETUP_FLAG_CONFLICT: u8 = 7;
    /// Installation-Contract-V1: `corulix setup` persisted the requested
    /// profile and ran real reconciliation, but at least one desired
    /// component did not reach a ready state (`Failed`/`UnknownComponent`) --
    /// distinct from [`SETUP_FLAG_CONFLICT`], which never reaches
    /// persistence/reconciliation at all.
    pub const SETUP_RECONCILIATION_INCOMPLETE: u8 = 8;
}

/// Builds the resolver inputs for one workspace-selecting command
/// invocation. Performs no I/O itself beyond reading the two environment
/// variables and the process's current directory -- never invoked while
/// parsing `--help`/`--version`/`help`, since those terminate inside
/// `Cli::parse()` before `main`'s own body runs.
///
/// `WorkspaceResolutionInputs` owns its data (Enterprise Async-First
/// Canonical Rebaseline) rather than borrowing, so this function no longer
/// needs to leak environment-variable strings to satisfy a borrowed
/// lifetime the way it did before that rebaseline.
fn resolution_inputs(selection: &WorkspaceSelection, cwd: &Path) -> WorkspaceResolutionInputs {
    WorkspaceResolutionInputs {
        explicit_workspace: selection.workspace.clone(),
        explicit_workspace_file: selection.workspace_file.clone(),
        environment_workspace: std::env::var(CORULIX_WORKSPACE_ENV_VAR).ok(),
        environment_workspace_file: std::env::var(CORULIX_WORKSPACE_FILE_ENV_VAR).ok(),
        discovery_seed: cwd.to_path_buf(),
    }
}

/// `async fn`: [`resolve_workspace`] performs real filesystem I/O
/// (canonicalization, descriptor reads, bounded discovery) on Tokio's
/// blocking-task pool, so every caller awaits it rather than calling a
/// synchronous alternative.
async fn resolve_or_report(selection: &WorkspaceSelection) -> Result<WorkspaceContext, u8> {
    let cwd = match std::env::current_dir() {
        Ok(value) => value,
        Err(_) => {
            eprintln!("WORKSPACE_RESOLUTION_STATUS=FAILED");
            eprintln!("REASON=unable to read the process's current working directory");
            return Err(exit_code::WORKSPACE_RESOLUTION_FAILURE);
        }
    };
    let inputs = resolution_inputs(selection, &cwd);
    match resolve_workspace(inputs).await {
        Ok(resolved) => Ok(clone_context(&resolved)),
        Err(failure) => {
            report_resolution_failure(&failure);
            Err(exit_code::WORKSPACE_RESOLUTION_FAILURE)
        }
    }
}

/// Phase 13: as [`resolve_or_report`], but additionally returns the real
/// [`wht_corulix_core::WorkspaceIdentity`] `resolve_workspace` already
/// generates as part of resolution -- `mcp stdio` is the one caller that
/// needs it (to bind every `ChangeSession` `begin_change` opens), so this
/// is a second, explicit function rather than widening every other
/// subcommand's `resolve_or_report` call site with a value they never use.
async fn resolve_or_report_with_identity(
    selection: &WorkspaceSelection,
) -> Result<(WorkspaceContext, wht_corulix_core::WorkspaceIdentity), u8> {
    let cwd = match std::env::current_dir() {
        Ok(value) => value,
        Err(_) => {
            eprintln!("WORKSPACE_RESOLUTION_STATUS=FAILED");
            eprintln!("REASON=unable to read the process's current working directory");
            return Err(exit_code::WORKSPACE_RESOLUTION_FAILURE);
        }
    };
    let inputs = resolution_inputs(selection, &cwd);
    match resolve_workspace(inputs).await {
        Ok(resolved) => {
            let identity = resolved.identity().clone();
            Ok((clone_context(&resolved), identity))
        }
        Err(failure) => {
            report_resolution_failure(&failure);
            Err(exit_code::WORKSPACE_RESOLUTION_FAILURE)
        }
    }
}

fn clone_context(resolved: &ResolvedWorkspace) -> WorkspaceContext {
    resolved.context().clone()
}

fn report_resolution_failure(failure: &WorkspaceResolutionFailure) {
    eprintln!("WORKSPACE_RESOLUTION_STATUS=FAILED");
    eprintln!("WORKSPACE_SOURCE={:?}", failure.source());
    eprintln!("WORKSPACE_STATUS={:?}", failure.status());
    match failure {
        WorkspaceResolutionFailure::ExplicitFlagInvalid => {
            eprintln!("REASON=--workspace does not canonicalize to an existing directory");
        }
        WorkspaceResolutionFailure::ExplicitWorkspaceFileInvalid => {
            eprintln!("REASON=--workspace-file is unreadable, malformed, or names an invalid root");
        }
        WorkspaceResolutionFailure::EnvironmentInvalid => {
            eprintln!(
                "REASON={CORULIX_WORKSPACE_ENV_VAR} does not canonicalize to an existing directory"
            );
        }
        WorkspaceResolutionFailure::EnvironmentWorkspaceFileInvalid => {
            eprintln!(
                "REASON={CORULIX_WORKSPACE_FILE_ENV_VAR} is unreadable, malformed, or names an invalid root"
            );
        }
        WorkspaceResolutionFailure::BothEnvironmentVariablesPresent => {
            eprintln!(
                "REASON=both {CORULIX_WORKSPACE_ENV_VAR} and {CORULIX_WORKSPACE_FILE_ENV_VAR} are set"
            );
            eprintln!("REMEDY=unset one of the two environment variables");
        }
        WorkspaceResolutionFailure::AmbiguousDescriptors => {
            eprintln!("REASON=multiple .code-workspace files found at the same directory level");
            eprintln!("REMEDY=pass --workspace-file <PATH> to select one explicitly");
        }
        WorkspaceResolutionFailure::ExternalScopeRequiresExplicitSelection => {
            eprintln!(
                "REASON=an automatically discovered .code-workspace references a root outside its own directory"
            );
            eprintln!(
                "REMEDY=pass --workspace-file <the detected file> if that topology is intentional"
            );
        }
        WorkspaceResolutionFailure::DiscoveryExhausted => {
            eprintln!(
                "REASON=no project-root marker or .code-workspace found within the bounded upward search"
            );
            eprintln!(
                "REMEDY=pass --workspace/--workspace-file or set CORULIX_WORKSPACE/CORULIX_WORKSPACE_FILE"
            );
        }
        WorkspaceResolutionFailure::InternalSummaryConstructionFailed => {
            eprintln!("REASON=internal workspace-resolution invariant violation");
        }
    }
}

/// Dispatches the CLI's subcommands. Tracing is initialized to write only to
/// stderr up front, before any subcommand runs, so that even the non-MCP
/// commands keep stdout reserved for their own structured output (and, for
/// `mcp stdio`, for the MCP protocol stream itself).
///
/// `Cli::parse()` itself handles `--help`/`-h`/`--version`/the built-in
/// `help` subcommand and exits before returning in those cases -- no
/// workspace resolution, engine construction, or provider probing ever runs
/// for a help/version request.
#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init()
        .ok();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Toolchain {
            command: ToolchainCommand::Status { workspace },
        } => run_toolchain_status(&workspace).await,
        Command::Languages {
            command: LanguagesCommand::List { workspace },
        } => run_languages_list(&workspace).await,
        Command::Workspace {
            command: WorkspaceCommand::Detect { workspace },
        } => run_workspace_detect(&workspace).await,
        Command::Workspace {
            command: WorkspaceCommand::Inspect { workspace, root },
        } => run_workspace_inspect(&workspace, root.workspace_root.as_deref()).await,
        Command::Parse {
            file,
            workspace,
            root,
        } => run_parse(&workspace, root.workspace_root.as_deref(), &file).await,
        Command::Mcp {
            command:
                McpCommand::Stdio {
                    workspace,
                    host_config,
                },
        } => run_mcp_stdio(&workspace, host_config.as_deref()).await,
        Command::Setup {
            profile,
            only,
            exclude,
        } => run_setup(profile, &only, &exclude).await,
    };

    match result {
        Ok(()) => ExitCode::from(exit_code::SUCCESS),
        Err(code) => ExitCode::from(code),
    }
}

/// Every subcommand handler is `async fn`, dispatched from the single
/// top-level `#[tokio::main]` runtime in [`main`] (Enterprise Async-First
/// Canonical Rebaseline, `CLI_RUNTIME_COUNT=1`): workspace resolution and
/// every Engine filesystem operation now awaits a canonical async
/// boundary rather than calling a synchronous alternative. Help/version
/// remain side-effect-free -- `Cli::parse()` exits before any of these
/// handlers ever runs for a `--help`/`--version`/`help` invocation.
async fn run_toolchain_status(selection: &WorkspaceSelection) -> Result<(), u8> {
    let context = resolve_or_report(selection).await?;
    let engine = Arc::new(CorulixEngine::open(context));
    print_json_or_internal_error(&engine.runtime_identity())
}

async fn run_languages_list(selection: &WorkspaceSelection) -> Result<(), u8> {
    let context = resolve_or_report(selection).await?;
    let engine = Arc::new(CorulixEngine::open(context));
    for (language, grammar) in engine.language_descriptors() {
        println!("{language}\t{grammar}");
    }
    Ok(())
}

async fn run_workspace_detect(selection: &WorkspaceSelection) -> Result<(), u8> {
    let cwd = std::env::current_dir().map_err(|_| exit_code::WORKSPACE_RESOLUTION_FAILURE)?;
    let inputs = resolution_inputs(selection, &cwd);
    match resolve_workspace(inputs).await {
        Ok(resolved) => print_json_or_internal_error(&resolved.topology_summary()),
        Err(failure) => {
            report_resolution_failure(&failure);
            // `detect` is diagnostic: a resolution failure is truthfully
            // reported, not a CLI usage error, but it is still not
            // `SUCCESS` -- the caller could not determine a workspace.
            Err(exit_code::WORKSPACE_RESOLUTION_FAILURE)
        }
    }
}

async fn run_workspace_inspect(
    selection: &WorkspaceSelection,
    root_selector: Option<&str>,
) -> Result<(), u8> {
    let context = resolve_or_report(selection).await?;
    let engine = Arc::new(CorulixEngine::open(context));
    match root_selector {
        None => print_json_or_internal_error(&engine.topology_summary()),
        Some(selector) => {
            // Reuse the same root-resolution authority the engine uses for
            // every other root-scoped operation, rather than re-implementing
            // selector matching here.
            match engine
                .resolve_confined(PathBuf::from("."), Some(selector.to_string()))
                .await
            {
                Ok(_) => print_json_or_internal_error(&engine.topology_summary()),
                Err(error) => {
                    eprintln!("WORKSPACE_ROOT_STATUS=ERROR");
                    eprintln!("REASON={error}");
                    Err(exit_code::WORKSPACE_RESOLUTION_FAILURE)
                }
            }
        }
    }
}

async fn run_parse(
    selection: &WorkspaceSelection,
    root_selector: Option<&str>,
    file: &str,
) -> Result<(), u8> {
    let context = resolve_or_report(selection).await?;
    let engine = Arc::new(CorulixEngine::open(context));
    match engine
        .parse_relative_file(PathBuf::from(file), root_selector.map(String::from))
        .await
    {
        Ok((summary, _outline)) => print_json_or_internal_error(&summary),
        Err(error) => {
            eprintln!("PARSE_STATUS=ERROR");
            if matches!(error, wht_corulix_core::CorulixError::WorkspaceNotFound) {
                eprintln!("REASON=--workspace-root selector missing, unknown, or ambiguous");
            } else {
                eprintln!("REASON={error}");
            }
            Err(classify_engine_error_exit_code(&error))
        }
    }
}

/// F1 fix: every member workspace root's real, canonical absolute path, for
/// [`wht_corulix_config::load_host_config_file`]'s own
/// workspace-containment rejection check. This CLI is the one legitimate
/// place in this workspace outside `wht_corulix_workspace` itself that
/// reads a raw canonical root path for this purpose (Rule F still owns
/// canonicalization itself -- `WorkspaceRoot::canonical_path` is a plain
/// accessor, not a second canonicalization implementation). Always succeeds
/// for a `WorkspaceContext` that itself resolved successfully -- every id
/// [`wht_corulix_workspace::WorkspaceContext::summary`] reports is, by
/// construction, resolvable via that same context's own
/// [`wht_corulix_workspace::WorkspaceContext::resolve_root`].
fn workspace_root_boundaries(context: &WorkspaceContext) -> Result<Vec<PathBuf>, u8> {
    let mut boundaries = Vec::new();
    for root_summary in context.summary().roots {
        let root = context
            .resolve_root(Some(&root_summary.root.0.to_string()))
            .map_err(|_| exit_code::INTERNAL_ERROR)?;
        boundaries.push(root.canonical_path().to_path_buf());
    }
    Ok(boundaries)
}

async fn run_mcp_stdio(
    selection: &WorkspaceSelection,
    host_config_path: Option<&Path>,
) -> Result<(), u8> {
    let (context, workspace_identity) = resolve_or_report_with_identity(selection).await?;

    // F1 fix: `--host-config` is the one real, host/operator-only path to a
    // non-default `HostConfig` the shipped binary now has. Absent, this
    // reproduces today's exact, unchanged behavior byte-for-byte
    // (`HostConfig::default()`, `trusted = false`) -- see this crate's own
    // `tests/real_f1_host_config_e2e.rs::host_config_absent_reproduces_default_unavailable_format_preview`,
    // which spawns the real compiled binary with no `--host-config` and
    // proves this explicitly against a live `format_preview` call, rather
    // than by inspection alone.
    let (trusted, host_config) = match host_config_path {
        None => (false, wht_corulix_config::HostConfig::default()),
        Some(path) => {
            let boundaries = workspace_root_boundaries(&context)?;
            let boundary_refs: Vec<&Path> = boundaries.iter().map(PathBuf::as_path).collect();
            match wht_corulix_config::load_host_config_file(path, &boundary_refs).await {
                Ok(parsed) => {
                    // `workspace_trust`/`allow_trusted_workspace_execution`
                    // are read here, from the host-authored file alone, and
                    // fed into the separate `trusted` parameter
                    // `CorulixEngine::open_with_host_config` has always
                    // required -- `CorulixEngine::effective_config` itself
                    // still ignores those same two fields on the
                    // `HostConfig` value it stores, so a provider-path
                    // configuration alone can never smuggle trust in
                    // (unchanged invariant). This is the only place in this
                    // workspace `TrustedWorkspaceExecution` can be
                    // authorized from: never an MCP request field, never a
                    // `.code-workspace` file, never a repository hint --
                    // none of those three sources have any field or code
                    // path that reaches this value.
                    let trusted = parsed.workspace_trust
                        == wht_corulix_core::WorkspaceTrust::Trusted
                        && parsed.allow_trusted_workspace_execution;
                    (trusted, parsed)
                }
                Err(error) => {
                    eprintln!("HOST_CONFIG_STATUS=FAILED");
                    eprintln!("REASON={error}");
                    return Err(exit_code::HOST_CONFIG_FAILURE);
                }
            }
        }
    };

    // Installation-Contract-V1 fix (`FIRST_RUN_RECONCILIATION`): real
    // process bootstrap is the one legitimate place this runs -- never the
    // passive per-call acquisition gate, which must stay side-effect-free.
    // A failure here is diagnostic-only and never blocks MCP startup: the
    // worst case is that provisioning-permission checks continue to see "no
    // profile persisted" (the safe, fail-closed default), not that the
    // server fails to start.
    if let Ok(managed_root) = wht_corulix_tooling::provisioning::managed_toolchain_root()
        && let Err(error) =
            wht_corulix_tooling::provisioning::install_profile::ensure_bootstrapped(&managed_root)
    {
        eprintln!("INSTALL_PROFILE_BOOTSTRAP_STATUS=FAILED");
        eprintln!("REASON={error:?}");
    }

    // From this point forward stdout belongs exclusively to RMCP stdio.
    let engine = Arc::new(CorulixEngine::open_with_host_config(
        context,
        trusted,
        host_config,
    ));
    wht_corulix_mcp::serve_stdio(engine, workspace_identity)
        .await
        .map_err(|_| exit_code::INTERNAL_ERROR)
}

/// Host/operator-only maintenance command (Installation-Contract-V1 §13-15):
/// persists this host's install-profile choice and reconciles the managed
/// root toward it. Never an MCP tool -- no workspace is resolved, no
/// `CorulixEngine` is opened, and no MCP request/workspace file/repository
/// content can trigger any of this.
///
/// All flag-conflict/unrecognized-group validation happens before any
/// persistence or reconciliation call (`SETUP_FLAG_CONFLICT`, exit 7) --
/// a rejected invocation is guaranteed to have mutated nothing.
async fn run_setup(
    profile: Option<SetupProfileArg>,
    only: &[String],
    exclude: &[String],
) -> Result<(), u8> {
    use wht_corulix_tooling::provisioning::install_profile::InstallProfile;

    let selecting_groups = !only.is_empty() || !exclude.is_empty();
    if profile == Some(SetupProfileArg::OnDemand) && selecting_groups {
        eprintln!("SETUP_STATUS=REJECTED");
        eprintln!("REASON=--profile on-demand cannot be combined with --only/--exclude");
        return Err(exit_code::SETUP_FLAG_CONFLICT);
    }

    let managed_root = match wht_corulix_tooling::provisioning::managed_toolchain_root() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("SETUP_STATUS=FAILED");
            eprintln!("REASON=managed toolchain root unresolvable: {error:?}");
            return Err(exit_code::INTERNAL_ERROR);
        }
    };

    // Resolve which profile to persist and which component set to reconcile
    // toward. Only the bare `corulix setup` (no profile-selecting flag at
    // all) goes through `ensure_bootstrapped`, which never overwrites an
    // existing explicit choice -- every other arm below persists directly,
    // deliberately overwriting a prior choice, since the operator just
    // named an explicit new one.
    let (persisted, desired, must_persist_directly) = if selecting_groups {
        match wht_corulix_engine::groups::resolve_selection(only, exclude) {
            Ok(components) => (
                InstallProfile::Selective {
                    components: components.clone(),
                },
                components,
                true,
            ),
            Err(error) => {
                report_selection_error(&error);
                return Err(exit_code::SETUP_FLAG_CONFLICT);
            }
        }
    } else {
        match profile {
            Some(SetupProfileArg::OnDemand) => (
                InstallProfile::OnDemand,
                std::collections::BTreeSet::new(),
                true,
            ),
            Some(SetupProfileArg::Full) => (
                InstallProfile::Full,
                wht_corulix_engine::groups::full_component_set(),
                true,
            ),
            None => {
                match wht_corulix_tooling::provisioning::install_profile::ensure_bootstrapped(
                    &managed_root,
                ) {
                    Ok(bootstrapped) => {
                        let desired = desired_set_for(&bootstrapped);
                        (bootstrapped, desired, false)
                    }
                    Err(error) => {
                        eprintln!("SETUP_STATUS=FAILED");
                        eprintln!("REASON=install profile bootstrap failed: {error:?}");
                        return Err(exit_code::INTERNAL_ERROR);
                    }
                }
            }
        }
    };

    if must_persist_directly
        && let Err(error) =
            wht_corulix_tooling::provisioning::install_profile::save(&managed_root, &persisted)
    {
        eprintln!("SETUP_STATUS=FAILED");
        eprintln!("REASON=persisting the install profile failed: {error:?}");
        return Err(exit_code::INTERNAL_ERROR);
    }

    println!("SETUP_STATUS=PROFILE_PERSISTED");
    println!("INSTALL_PROFILE={}", describe_profile(&persisted));

    if desired.is_empty() {
        println!("RECONCILIATION_STATUS=SKIPPED_ON_DEMAND");
        return Ok(());
    }

    let report = wht_corulix_engine::reconciler::reconcile_at(&managed_root, &desired).await;
    for result in &report.results {
        println!(
            "COMPONENT={} STATUS={}",
            result.id,
            describe_reconcile_status(&result.status)
        );
    }
    if report.ready() {
        println!("SETUP_STATUS=READY");
        Ok(())
    } else {
        println!("SETUP_STATUS=NOT_READY");
        Err(exit_code::SETUP_RECONCILIATION_INCOMPLETE)
    }
}

fn desired_set_for(
    profile: &wht_corulix_tooling::provisioning::install_profile::InstallProfile,
) -> std::collections::BTreeSet<String> {
    use wht_corulix_tooling::provisioning::install_profile::InstallProfile;
    match profile {
        InstallProfile::Full => wht_corulix_engine::groups::full_component_set(),
        InstallProfile::Selective { components } => components.clone(),
        InstallProfile::OnDemand => std::collections::BTreeSet::new(),
    }
}

fn describe_profile(
    profile: &wht_corulix_tooling::provisioning::install_profile::InstallProfile,
) -> String {
    use wht_corulix_tooling::provisioning::install_profile::InstallProfile;
    match profile {
        InstallProfile::Full => "FULL".to_string(),
        InstallProfile::OnDemand => "ON_DEMAND".to_string(),
        InstallProfile::Selective { components } => {
            format!(
                "SELECTIVE({})",
                components.iter().cloned().collect::<Vec<_>>().join(",")
            )
        }
    }
}

fn describe_reconcile_status(
    status: &wht_corulix_engine::reconciler::ComponentReconcileStatus,
) -> String {
    use wht_corulix_engine::reconciler::ComponentReconcileStatus;
    match status {
        ComponentReconcileStatus::AlreadyReady => "ALREADY_READY".to_string(),
        ComponentReconcileStatus::Acquired => "ACQUIRED".to_string(),
        ComponentReconcileStatus::NotApplicableOnThisPlatform => {
            "NOT_APPLICABLE_ON_THIS_PLATFORM".to_string()
        }
        ComponentReconcileStatus::UnknownComponent => "UNKNOWN_COMPONENT".to_string(),
        ComponentReconcileStatus::Failed(error) => format!("FAILED({error:?})"),
    }
}

fn report_selection_error(error: &wht_corulix_engine::groups::SelectionError) {
    use wht_corulix_engine::groups::SelectionError;
    eprintln!("SETUP_STATUS=REJECTED");
    match error {
        SelectionError::UnrecognizedGroup { requested } => {
            eprintln!("REASON=unrecognized install group: {requested}");
            eprintln!(
                "VALID_GROUPS={}",
                wht_corulix_engine::groups::GROUP_NAMES.join(",")
            );
        }
        SelectionError::GroupInBothOnlyAndExclude { group } => {
            eprintln!("REASON=group named in both --only and --exclude: {group}");
        }
    }
}

fn classify_engine_error_exit_code(error: &wht_corulix_core::CorulixError) -> u8 {
    match error {
        // A multi-root selector that could not be resolved (missing,
        // unknown, or ambiguous) is a workspace *selection* failure, not an
        // operational one -- `WorkspaceContext::resolve_root` deliberately
        // returns this variant for exactly that reason.
        wht_corulix_core::CorulixError::WorkspaceNotFound => {
            exit_code::WORKSPACE_RESOLUTION_FAILURE
        }
        wht_corulix_core::CorulixError::PathDenied => exit_code::PATH_DENIED,
        wht_corulix_core::CorulixError::FileTooLarge
        | wht_corulix_core::CorulixError::LanguageUnsupported
        | wht_corulix_core::CorulixError::UnsupportedEncoding => {
            exit_code::UNSUPPORTED_OR_TOO_LARGE
        }
        _ => exit_code::INTERNAL_ERROR,
    }
}

/// Serializes `value` to stdout as pretty JSON (this is normal, successful
/// human-facing command output, so it uses stdout, not stderr), or reports
/// a structured internal-error diagnostic on stderr if serialization itself
/// somehow fails.
fn print_json_or_internal_error<T: serde::Serialize>(value: &T) -> Result<(), u8> {
    match serde_json::to_string_pretty(value) {
        Ok(rendered) => {
            println!("{rendered}");
            Ok(())
        }
        Err(_) => {
            eprintln!("STATUS=INTERNAL_ERROR");
            eprintln!("REASON=response serialization failed");
            Err(exit_code::INTERNAL_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cli::WorkspaceSelection;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::CorulixError;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-cli-main-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    #[test]
    fn exit_code_model_distinguishes_categories() {
        assert_eq!(
            classify_engine_error_exit_code(&CorulixError::WorkspaceNotFound),
            exit_code::WORKSPACE_RESOLUTION_FAILURE
        );
        assert_eq!(
            classify_engine_error_exit_code(&CorulixError::PathDenied),
            exit_code::PATH_DENIED
        );
        assert_eq!(
            classify_engine_error_exit_code(&CorulixError::FileTooLarge),
            exit_code::UNSUPPORTED_OR_TOO_LARGE
        );
        assert_eq!(
            classify_engine_error_exit_code(&CorulixError::LanguageUnsupported),
            exit_code::UNSUPPORTED_OR_TOO_LARGE
        );
        assert_eq!(
            classify_engine_error_exit_code(&CorulixError::Internal),
            exit_code::INTERNAL_ERROR
        );
    }

    #[tokio::test]
    async fn explicit_workspace_selection_resolves() {
        let dir = temp_dir("explicit");
        let selection = WorkspaceSelection {
            workspace: Some(dir.clone()),
            workspace_file: None,
        };
        assert!(resolve_or_report(&selection).await.is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn invalid_explicit_workspace_returns_resolution_failure_code() {
        let nonexistent = std::env::temp_dir().join("corulix-cli-main-test-does-not-exist");
        let selection = WorkspaceSelection {
            workspace: Some(nonexistent),
            workspace_file: None,
        };
        assert!(matches!(
            resolve_or_report(&selection).await,
            Err(code) if code == exit_code::WORKSPACE_RESOLUTION_FAILURE
        ));
    }

    #[tokio::test]
    async fn multi_root_parse_without_selector_fails_with_resolution_exit_code()
    -> std::io::Result<()> {
        let dir = temp_dir("multi-parse");
        fs::create_dir_all(dir.join("a"))?;
        fs::create_dir_all(dir.join("b"))?;
        fs::write(dir.join("a/main.rs"), "fn main() {}")?;
        let descriptor = dir.join("root.code-workspace");
        fs::write(
            &descriptor,
            r#"{ "folders": [ { "path": "a" }, { "path": "b" } ] }"#,
        )?;
        let selection = WorkspaceSelection {
            workspace: None,
            workspace_file: Some(descriptor),
        };
        assert_eq!(
            run_parse(&selection, None, "main.rs").await,
            Err(exit_code::WORKSPACE_RESOLUTION_FAILURE)
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn multi_root_parse_with_valid_selector_succeeds() -> std::io::Result<()> {
        let dir = temp_dir("multi-parse-ok");
        fs::create_dir_all(dir.join("a"))?;
        fs::create_dir_all(dir.join("b"))?;
        fs::write(dir.join("a/main.rs"), "fn main() {}")?;
        let descriptor = dir.join("root.code-workspace");
        fs::write(
            &descriptor,
            r#"{ "folders": [ { "path": "a", "name": "a" }, { "path": "b" } ] }"#,
        )?;
        let selection = WorkspaceSelection {
            workspace: None,
            workspace_file: Some(descriptor),
        };
        assert_eq!(run_parse(&selection, Some("a"), "main.rs").await, Ok(()));
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
