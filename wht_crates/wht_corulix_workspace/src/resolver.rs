// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The canonical workspace resolver.
//!
//! Precedence: explicit `--workspace-file` -> explicit `--workspace` ->
//! environment configuration (`CORULIX_WORKSPACE`/`CORULIX_WORKSPACE_FILE`,
//! both present is fail-closed-ambiguous) -> bounded, cwd-seeded discovery
//! (a `.code-workspace` descriptor takes precedence over an ordinary
//! project marker at the same ancestor level) -> fail closed.
//!
//! No MCP Roots stage exists (Roots is deprecated per SEP-2577; see the
//! rebaseline plan's ADR-WORKSPACE). No stage ever falls back to a raw,
//! unvalidated `cwd`, and an explicit, authoritative source (flag or
//! environment) that fails validation is terminal, never silently
//! downgraded to a lower-precedence source. An **auto-discovered**
//! `.code-workspace` (found by discovery, not explicitly named) must not
//! silently widen the filesystem boundary: if it references any root
//! outside its own containing directory, resolution fails closed and asks
//! the operator to pass `--workspace-file` explicitly if that topology is
//! intentional. An **explicitly** selected `--workspace-file`/
//! `CORULIX_WORKSPACE_FILE` carries no such restriction -- the operator
//! already authorized whatever topology it names.

use crate::confine::WorkspaceRoot;
use crate::context::{WorkspaceContext, all_roots_within_boundary};
use crate::descriptor::parse_descriptor;
use crate::discovery::{WorkspaceDiscoveryOutcome, discover_workspace_from_seed};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use wht_corulix_core::{
    WorkspaceIdentity, WorkspaceResolutionStatus, WorkspaceResolutionSummary, WorkspaceSourceKind,
    WorkspaceTopologySummary, WorkspaceTrust,
};

/// Single-root selection, consulted at stage 3 if no explicit flag/file won.
pub const CORULIX_WORKSPACE_ENV_VAR: &str = "CORULIX_WORKSPACE";
/// Multi-root descriptor selection, consulted at stage 3 alongside
/// [`CORULIX_WORKSPACE_ENV_VAR`] -- both present is fail-closed-ambiguous.
pub const CORULIX_WORKSPACE_FILE_ENV_VAR: &str = "CORULIX_WORKSPACE_FILE";

/// Inputs to [`resolve_workspace`]. Callers (the CLI) are responsible for
/// gathering these from `--workspace`/`--workspace-file`, `std::env::var`,
/// and `std::env::current_dir` respectively -- this module performs no I/O
/// to collect them itself, only to validate/discover from them. `--workspace`
/// and `--workspace-file` are mutually exclusive at the CLI parser level
/// (`clap` `conflicts_with`); this type does not re-validate that.
///
/// Owns its data (no lifetime parameter) rather than borrowing, so it can
/// move directly into [`resolve_workspace`]'s `tokio::task::spawn_blocking`
/// closure (Enterprise Async-First Canonical Rebaseline) -- a borrowed
/// `WorkspaceResolutionInputs<'a>` could not satisfy `spawn_blocking`'s
/// `'static` requirement. This also removes the CLI's prior need to leak
/// environment-variable strings to satisfy a borrowed lifetime.
#[derive(Debug, Clone)]
pub struct WorkspaceResolutionInputs {
    pub explicit_workspace: Option<PathBuf>,
    pub explicit_workspace_file: Option<PathBuf>,
    pub environment_workspace: Option<String>,
    pub environment_workspace_file: Option<String>,
    pub discovery_seed: PathBuf,
}

/// A successfully resolved workspace: the real, internal-only context used
/// to open the engine, plus a client/MCP-safe identity and diagnostic
/// summaries.
#[derive(Debug, Clone)]
pub struct ResolvedWorkspace {
    context: WorkspaceContext,
    identity: WorkspaceIdentity,
    summary: WorkspaceResolutionSummary,
}

impl ResolvedWorkspace {
    /// The real, internal logical workspace. Internal use only -- never
    /// serialize this directly to a client/MCP response.
    #[must_use]
    pub fn context(&self) -> &WorkspaceContext {
        &self.context
    }

    #[must_use]
    pub fn identity(&self) -> &WorkspaceIdentity {
        &self.identity
    }

    /// The client/MCP-safe resolution summary: source, status, identity,
    /// and trust (always [`WorkspaceTrust::Untrusted`] here -- trust
    /// authorization is Phase 6's responsibility, never invented at
    /// resolution time).
    #[must_use]
    pub fn summary(&self) -> &WorkspaceResolutionSummary {
        &self.summary
    }

    /// The client/MCP-safe topology summary: single- vs multi-root, and
    /// each member root's opaque ID and safe display name.
    #[must_use]
    pub fn topology_summary(&self) -> WorkspaceTopologySummary {
        self.context.summary()
    }
}

/// Why resolution did not select a workspace. Carries enough structured
/// information for a caller (the CLI's `workspace detect`) to report a
/// truthful [`WorkspaceResolutionSummary`] even on failure, without needing
/// a raw path to do so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceResolutionFailure {
    ExplicitFlagInvalid,
    ExplicitWorkspaceFileInvalid,
    EnvironmentInvalid,
    EnvironmentWorkspaceFileInvalid,
    /// `CORULIX_WORKSPACE` and `CORULIX_WORKSPACE_FILE` were both set --
    /// never silently prefer either.
    BothEnvironmentVariablesPresent,
    /// Bounded discovery found more than one `.code-workspace` file at the
    /// same ancestor level -- never resolved by alphabetical/first/newest
    /// ranking.
    AmbiguousDescriptors,
    /// An auto-discovered (not explicitly selected) `.code-workspace`
    /// referenced a root outside its own containing directory. Auto-discovery
    /// never silently widens the filesystem boundary; rerun with
    /// `--workspace-file <the detected file>` if that topology is intentional.
    ExternalScopeRequiresExplicitSelection,
    DiscoveryExhausted,
    /// A resolved, valid workspace could not be finalized into a
    /// [`ResolvedWorkspace`] because constructing its internal
    /// [`WorkspaceResolutionSummary`] failed. Not reachable in practice --
    /// `finalize` always supplies `Selected` with both `identity` and
    /// `trust` present, which always satisfies that type's own invariant --
    /// but this crate propagates the possibility through the ordinary
    /// `Result` path rather than asserting it away with `unwrap`/`expect`/
    /// `panic!`.
    InternalSummaryConstructionFailed,
}

impl WorkspaceResolutionFailure {
    #[must_use]
    pub fn source(&self) -> WorkspaceSourceKind {
        match self {
            Self::ExplicitFlagInvalid | Self::ExplicitWorkspaceFileInvalid => {
                WorkspaceSourceKind::ExplicitFlag
            }
            Self::EnvironmentInvalid
            | Self::EnvironmentWorkspaceFileInvalid
            | Self::BothEnvironmentVariablesPresent => WorkspaceSourceKind::Environment,
            Self::AmbiguousDescriptors
            | Self::ExternalScopeRequiresExplicitSelection
            | Self::DiscoveryExhausted
            | Self::InternalSummaryConstructionFailed => WorkspaceSourceKind::DiscoverySeeded,
        }
    }

    #[must_use]
    pub fn status(&self) -> WorkspaceResolutionStatus {
        match self {
            Self::ExplicitFlagInvalid
            | Self::ExplicitWorkspaceFileInvalid
            | Self::EnvironmentInvalid
            | Self::EnvironmentWorkspaceFileInvalid
            | Self::ExternalScopeRequiresExplicitSelection => WorkspaceResolutionStatus::Invalid,
            Self::BothEnvironmentVariablesPresent | Self::AmbiguousDescriptors => {
                WorkspaceResolutionStatus::Ambiguous
            }
            Self::DiscoveryExhausted | Self::InternalSummaryConstructionFailed => {
                WorkspaceResolutionStatus::Exhausted
            }
        }
    }
}

/// The blocking-safe resolution core. Private: the canonical public
/// surface is [`resolve_workspace`] (`.await`) -- no other crate may
/// bypass it with a synchronous call. Uses the canonical precedence
/// documented on this module.
fn resolve_workspace_blocking(
    inputs: &WorkspaceResolutionInputs,
) -> Result<ResolvedWorkspace, WorkspaceResolutionFailure> {
    // Stage 1: explicit --workspace-file.
    if let Some(file) = inputs.explicit_workspace_file.as_deref() {
        let context = load_descriptor(file, None)
            .map_err(|_| WorkspaceResolutionFailure::ExplicitWorkspaceFileInvalid)?;
        return finalize(WorkspaceSourceKind::ExplicitFlag, context);
    }

    // Stage 2: explicit --workspace.
    if let Some(dir) = inputs.explicit_workspace.as_deref() {
        return match WorkspaceRoot::open(dir) {
            Ok(root) => finalize(
                WorkspaceSourceKind::ExplicitFlag,
                WorkspaceContext::single_root(root, display_name_for(dir)),
            ),
            Err(_) => Err(WorkspaceResolutionFailure::ExplicitFlagInvalid),
        };
    }

    // Stage 3: environment configuration.
    let env_dir = non_empty(inputs.environment_workspace.as_deref());
    let env_file = non_empty(inputs.environment_workspace_file.as_deref());
    match (env_dir, env_file) {
        (Some(_), Some(_)) => {
            return Err(WorkspaceResolutionFailure::BothEnvironmentVariablesPresent);
        }
        (None, Some(file)) => {
            let context = load_descriptor(Path::new(file), None)
                .map_err(|_| WorkspaceResolutionFailure::EnvironmentWorkspaceFileInvalid)?;
            return finalize(WorkspaceSourceKind::Environment, context);
        }
        (Some(dir), None) => {
            return match WorkspaceRoot::open(dir) {
                Ok(root) => finalize(
                    WorkspaceSourceKind::Environment,
                    WorkspaceContext::single_root(root, display_name_for(Path::new(dir))),
                ),
                Err(_) => Err(WorkspaceResolutionFailure::EnvironmentInvalid),
            };
        }
        (None, None) => {}
    }

    // Stages 4+5: bounded discovery (descriptor takes precedence over an
    // ordinary marker at the same ancestor level).
    match discover_workspace_from_seed(&inputs.discovery_seed) {
        WorkspaceDiscoveryOutcome::AmbiguousDescriptors(_) => {
            Err(WorkspaceResolutionFailure::AmbiguousDescriptors)
        }
        WorkspaceDiscoveryOutcome::Descriptor(file) => {
            let boundary = file.parent().map(Path::to_path_buf);
            let context = load_descriptor(&file, boundary.as_deref())
                .map_err(|_| WorkspaceResolutionFailure::ExternalScopeRequiresExplicitSelection)?;
            finalize(WorkspaceSourceKind::DiscoverySeeded, context)
        }
        WorkspaceDiscoveryOutcome::Marker(candidate) => {
            match WorkspaceRoot::open(&candidate.directory) {
                Ok(root) => finalize(
                    WorkspaceSourceKind::DiscoverySeeded,
                    WorkspaceContext::single_root(root, display_name_for(&candidate.directory)),
                ),
                // A marker-bearing directory that itself fails root validation
                // (e.g. removed between the marker check and here) is treated
                // as discovery having found nothing usable -- fail closed the
                // same as exhaustion, never silently fall back further.
                Err(_) => Err(WorkspaceResolutionFailure::DiscoveryExhausted),
            }
        }
        WorkspaceDiscoveryOutcome::Exhausted => Err(WorkspaceResolutionFailure::DiscoveryExhausted),
    }
}

/// Canonical async entry point for `resolve_workspace_blocking`. Runs
/// resolution (canonicalization, descriptor reads, bounded discovery -- all
/// real filesystem I/O) on Tokio's blocking-task pool via
/// `tokio::task::spawn_blocking`. There is no synchronous `resolve_workspace`
/// kept alongside it; this is the one public name for this operation from
/// async code.
pub async fn resolve_workspace(
    inputs: WorkspaceResolutionInputs,
) -> Result<ResolvedWorkspace, WorkspaceResolutionFailure> {
    tokio::task::spawn_blocking(move || resolve_workspace_blocking(&inputs))
        .await
        .unwrap_or(Err(
            WorkspaceResolutionFailure::InternalSummaryConstructionFailed,
        ))
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

fn display_name_for(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("workspace")
        .to_string()
}

/// Parses `file` and resolves every `folders[]` entry relative to `file`'s
/// own containing directory. If `auto_discovery_boundary` is `Some`, this
/// is an auto-discovered (not explicitly selected) descriptor: every
/// resolved root must lie at or under that boundary, or the whole load
/// fails (see [`all_roots_within_boundary`]). `None` means the descriptor
/// was explicitly selected by the operator (`--workspace-file` or
/// `CORULIX_WORKSPACE_FILE`) and no such restriction applies.
fn load_descriptor(
    file: &Path,
    auto_discovery_boundary: Option<&Path>,
) -> wht_corulix_core::CorulixResult<WorkspaceContext> {
    let contents = std::fs::read_to_string(file).map_err(|_| {
        wht_corulix_core::CorulixError::InvalidInput("unreadable .code-workspace file".into())
    })?;
    let descriptor = parse_descriptor(&contents)?;
    let descriptor_dir: PathBuf = file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut roots = Vec::with_capacity(descriptor.folders.len());
    for folder in descriptor.folders {
        let joined = descriptor_dir.join(&folder.path);
        let root = WorkspaceRoot::open(&joined)?;
        let display_name = folder
            .name
            .unwrap_or_else(|| display_name_for(root.canonical_path()));
        roots.push((root, display_name));
    }

    if let Some(boundary) = auto_discovery_boundary {
        let canonical_boundary = WorkspaceRoot::open(boundary)?;
        if !all_roots_within_boundary(canonical_boundary.canonical_path(), &roots) {
            return Err(wht_corulix_core::CorulixError::InvalidInput(
                "auto-discovered .code-workspace references a root outside its own directory; \
                 rerun with --workspace-file to select it explicitly"
                    .into(),
            ));
        }
    }

    // Corulix 1.1.0 (ADR 0012): pin the descriptor's own containing
    // directory as a real, canonicalized WorkspaceRoot -- the same
    // validity check (`fs::canonicalize` + `is_dir()`) every member root
    // already goes through -- so a later, safe descriptor-sibling read of
    // `WhaTalker_Corulix_JSON_Config.json` can reuse the existing
    // TOCTOU-safe `confined_read` machinery instead of a second primitive.
    // Fails closed identically to any other root-validity failure if
    // `descriptor_dir` no longer exists or isn't a directory.
    let descriptor_location = WorkspaceRoot::open(&descriptor_dir)?;
    WorkspaceContext::from_roots(roots)
        .map(|context| context.with_descriptor_location(descriptor_location))
}

fn finalize(
    source: WorkspaceSourceKind,
    context: WorkspaceContext,
) -> Result<ResolvedWorkspace, WorkspaceResolutionFailure> {
    let identity = generate_opaque_identity()
        .map_err(|_| WorkspaceResolutionFailure::InternalSummaryConstructionFailed)?;
    let summary = WorkspaceResolutionSummary::new(
        source,
        WorkspaceResolutionStatus::Selected,
        Some(identity.clone()),
        Some(WorkspaceTrust::Untrusted),
    )
    .map_err(|_| WorkspaceResolutionFailure::InternalSummaryConstructionFailed)?;
    Ok(ResolvedWorkspace {
        context,
        identity,
        summary,
    })
}

/// Generates an opaque token identifying this resolved workspace for the
/// current process's lifetime.
///
/// **Honesty note:** this uses `std::collections::hash_map::RandomState`
/// (part of `std`, already relied on by every `HashMap` in this codebase)
/// as a source of process-local randomness -- it introduces no new
/// dependency, and is adequate for this phase's purely diagnostic use
/// (`workspace_info`/`workspace detect` output, cross-referencing evidence
/// records to a workspace). It is **not** a certified cryptographic RNG.
/// Any later phase needing genuine unpredictability for a
/// security-relevant identifier (e.g. `ChangeSessionId`) must independently
/// evaluate and, if needed, formally admit a dedicated CSPRNG-backed
/// dependency -- this mechanism's adequacy here is not inherited by that
/// decision.
fn generate_opaque_identity() -> wht_corulix_core::CorulixResult<WorkspaceIdentity> {
    let high = RandomState::new().build_hasher().finish();
    let low = RandomState::new().build_hasher().finish();
    // A token built from two 64-bit hex-formatted values is never empty
    // (always exactly 37 bytes: "wsid-" + 16 + 16 hex digits), so this can
    // never actually return `Err` -- the `Result` is still propagated
    // honestly through the ordinary error path rather than asserted away.
    WorkspaceIdentity::from_opaque_token(format!("wsid-{high:016x}{low:016x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-resolver-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    fn base_inputs(seed: &Path) -> WorkspaceResolutionInputs {
        WorkspaceResolutionInputs {
            explicit_workspace: None,
            explicit_workspace_file: None,
            environment_workspace: None,
            environment_workspace_file: None,
            discovery_seed: seed.to_path_buf(),
        }
    }

    #[tokio::test]
    async fn explicit_flag_takes_precedence_over_env_and_discovery() {
        let explicit = temp_dir("explicit");
        let env_dir = temp_dir("env");
        let mut inputs = base_inputs(&env_dir);
        inputs.explicit_workspace = Some(explicit.clone());
        inputs.environment_workspace = env_dir.to_str().map(String::from);
        let result = resolve_workspace(inputs).await;
        let selected_explicit = matches!(
            &result,
            Ok(resolved) if resolved.summary().source() == WorkspaceSourceKind::ExplicitFlag
        );
        assert!(selected_explicit);
        let _ = fs::remove_dir_all(&explicit);
        let _ = fs::remove_dir_all(&env_dir);
    }

    #[tokio::test]
    async fn explicit_workspace_file_takes_precedence_over_explicit_workspace()
    -> std::io::Result<()> {
        let dir = temp_dir("file-precedence");
        let member = dir.join("member");
        fs::create_dir_all(&member)?;
        let descriptor = dir.join("root.code-workspace");
        fs::write(&descriptor, r#"{ "folders": [ { "path": "member" } ] }"#)?;
        let unrelated = temp_dir("unrelated");

        let mut inputs = base_inputs(&dir);
        inputs.explicit_workspace = Some(unrelated.clone());
        inputs.explicit_workspace_file = Some(descriptor);
        let result = resolve_workspace(inputs).await;
        assert!(result.is_ok());

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&unrelated);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_explicit_flag_fails_closed_without_fallthrough() {
        let nonexistent = std::env::temp_dir().join("corulix-does-not-exist-explicit");
        let env_dir = temp_dir("env2");
        let mut inputs = base_inputs(&env_dir);
        inputs.explicit_workspace = Some(nonexistent);
        inputs.environment_workspace = env_dir.to_str().map(String::from);
        assert!(matches!(
            resolve_workspace(inputs).await,
            Err(WorkspaceResolutionFailure::ExplicitFlagInvalid)
        ));
        let _ = fs::remove_dir_all(&env_dir);
    }

    #[tokio::test]
    async fn invalid_explicit_workspace_file_fails_closed() {
        let seed = temp_dir("invalid-file-seed");
        let nonexistent = seed.join("does-not-exist.code-workspace");
        let mut inputs = base_inputs(&seed);
        inputs.explicit_workspace_file = Some(nonexistent);
        assert!(matches!(
            resolve_workspace(inputs).await,
            Err(WorkspaceResolutionFailure::ExplicitWorkspaceFileInvalid)
        ));
        let _ = fs::remove_dir_all(&seed);
    }

    #[tokio::test]
    async fn env_takes_precedence_over_discovery() {
        let env_dir = temp_dir("env3");
        let discovery_dir = temp_dir("disc3");
        let mut inputs = base_inputs(&discovery_dir);
        inputs.environment_workspace = env_dir.to_str().map(String::from);
        let result = resolve_workspace(inputs).await;
        let selected_env = matches!(
            &result,
            Ok(resolved) if resolved.summary().source() == WorkspaceSourceKind::Environment
        );
        assert!(selected_env);
        let _ = fs::remove_dir_all(&env_dir);
        let _ = fs::remove_dir_all(&discovery_dir);
    }

    #[tokio::test]
    async fn invalid_env_fails_closed_without_fallthrough() {
        let discovery_dir = temp_dir("disc4");
        let _ = fs::write(discovery_dir.join("Cargo.toml"), "");
        let mut inputs = base_inputs(&discovery_dir);
        inputs.environment_workspace = Some("/corulix/does/not/exist/env".to_string());
        assert!(matches!(
            resolve_workspace(inputs).await,
            Err(WorkspaceResolutionFailure::EnvironmentInvalid)
        ));
        let _ = fs::remove_dir_all(&discovery_dir);
    }

    #[tokio::test]
    async fn both_environment_variables_present_fails_closed() {
        let discovery_dir = temp_dir("disc-both-env");
        let mut inputs = base_inputs(&discovery_dir);
        inputs.environment_workspace = Some("/some/dir".to_string());
        inputs.environment_workspace_file = Some("/some/file.code-workspace".to_string());
        assert!(matches!(
            resolve_workspace(inputs).await,
            Err(WorkspaceResolutionFailure::BothEnvironmentVariablesPresent)
        ));
        let _ = fs::remove_dir_all(&discovery_dir);
    }

    #[tokio::test]
    async fn cwd_seeded_discovery_selects_when_flag_and_env_absent() {
        let discovery_dir = temp_dir("disc5");
        let _ = fs::write(discovery_dir.join("Cargo.toml"), "");
        let inputs = base_inputs(&discovery_dir);
        let result = resolve_workspace(inputs).await;
        let selected_discovery = matches!(
            &result,
            Ok(resolved) if resolved.summary().source() == WorkspaceSourceKind::DiscoverySeeded
        );
        assert!(selected_discovery);
        let _ = fs::remove_dir_all(&discovery_dir);
    }

    #[tokio::test]
    async fn raw_cwd_without_marker_is_not_accepted() {
        let discovery_dir = temp_dir("disc6");
        let inputs = base_inputs(&discovery_dir);
        assert!(matches!(
            resolve_workspace(inputs).await,
            Err(WorkspaceResolutionFailure::DiscoveryExhausted)
        ));
        let _ = fs::remove_dir_all(&discovery_dir);
    }

    #[tokio::test]
    async fn discovery_exhausted_fails_closed() {
        let discovery_dir = temp_dir("disc7");
        let inputs = base_inputs(&discovery_dir);
        assert!(matches!(
            resolve_workspace(inputs).await,
            Err(WorkspaceResolutionFailure::DiscoveryExhausted)
        ));
        let _ = fs::remove_dir_all(&discovery_dir);
    }

    #[tokio::test]
    async fn selected_workspace_is_always_untrusted() {
        let discovery_dir = temp_dir("disc8");
        let _ = fs::write(discovery_dir.join("Cargo.toml"), "");
        let inputs = base_inputs(&discovery_dir);
        let result = resolve_workspace(inputs).await;
        let untrusted = matches!(
            &result,
            Ok(resolved) if resolved.summary().trust() == Some(WorkspaceTrust::Untrusted)
        );
        assert!(untrusted);
        let _ = fs::remove_dir_all(&discovery_dir);
    }

    #[tokio::test]
    async fn empty_env_var_is_treated_as_absent_not_invalid() {
        let discovery_dir = temp_dir("disc9");
        let _ = fs::write(discovery_dir.join("Cargo.toml"), "");
        let mut inputs = base_inputs(&discovery_dir);
        inputs.environment_workspace = Some(String::new());
        let result = resolve_workspace(inputs).await;
        let selected_discovery = matches!(
            &result,
            Ok(resolved) if resolved.summary().source() == WorkspaceSourceKind::DiscoverySeeded
        );
        assert!(selected_discovery);
        let _ = fs::remove_dir_all(&discovery_dir);
    }

    #[tokio::test]
    async fn auto_discovered_descriptor_with_internal_roots_binds() -> std::io::Result<()> {
        let dir = temp_dir("auto-internal");
        let member = dir.join("member");
        fs::create_dir_all(&member)?;
        fs::write(
            dir.join("root.code-workspace"),
            r#"{ "folders": [ { "path": "member" } ] }"#,
        )?;
        let inputs = base_inputs(&dir);
        let result = resolve_workspace(inputs).await;
        assert!(matches!(
            &result,
            Ok(resolved) if resolved.summary().source() == WorkspaceSourceKind::DiscoverySeeded
        ));
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn auto_discovered_descriptor_with_external_root_requires_explicit_selection()
    -> std::io::Result<()> {
        let dir = temp_dir("auto-external");
        let outside = temp_dir("auto-external-sibling");
        fs::write(
            dir.join("root.code-workspace"),
            format!(
                r#"{{ "folders": [ {{ "path": {:?} }} ] }}"#,
                outside.to_str().unwrap_or("")
            ),
        )?;
        let inputs = base_inputs(&dir);
        assert!(matches!(
            resolve_workspace(inputs).await,
            Err(WorkspaceResolutionFailure::ExternalScopeRequiresExplicitSelection)
        ));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn explicit_workspace_file_may_reference_external_roots() -> std::io::Result<()> {
        let dir = temp_dir("explicit-external");
        let outside = temp_dir("explicit-external-sibling");
        let descriptor = dir.join("root.code-workspace");
        fs::write(
            &descriptor,
            format!(
                r#"{{ "folders": [ {{ "path": {:?} }} ] }}"#,
                outside.to_str().unwrap_or("")
            ),
        )?;
        let mut inputs = base_inputs(&dir);
        inputs.explicit_workspace_file = Some(descriptor);
        assert!(resolve_workspace(inputs).await.is_ok());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn ambiguous_descriptors_at_same_level_fail_closed() -> std::io::Result<()> {
        let dir = temp_dir("ambiguous-descriptors");
        fs::write(
            dir.join("one.code-workspace"),
            r#"{ "folders": [ { "path": "." } ] }"#,
        )?;
        fs::write(
            dir.join("two.code-workspace"),
            r#"{ "folders": [ { "path": "." } ] }"#,
        )?;
        let inputs = base_inputs(&dir);
        assert!(matches!(
            resolve_workspace(inputs).await,
            Err(WorkspaceResolutionFailure::AmbiguousDescriptors)
        ));
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn multi_root_descriptor_yields_multi_root_topology() -> std::io::Result<()> {
        let dir = temp_dir("multi-root-topology");
        fs::create_dir_all(dir.join("a"))?;
        fs::create_dir_all(dir.join("b"))?;
        let descriptor = dir.join("root.code-workspace");
        fs::write(
            &descriptor,
            r#"{ "folders": [ { "path": "a" }, { "path": "b" } ] }"#,
        )?;
        let mut inputs = base_inputs(&dir);
        inputs.explicit_workspace_file = Some(descriptor);
        let resolved = resolve_workspace(inputs)
            .await
            .map_err(|_| std::io::Error::other("resolution failed"))?;
        assert_eq!(
            resolved.topology_summary().topology,
            wht_corulix_core::WorkspaceTopologyKind::MultiRoot
        );
        assert_eq!(resolved.topology_summary().roots.len(), 2);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
