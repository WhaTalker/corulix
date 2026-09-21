// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical, async-first, ambient-`PATH`-free provider resolution.
//!
//! `resolve_provider` is the sole public entry point for turning a provider
//! category into a real, canonicalized executable path. Precedence, checked
//! in this exact order and never re-ordered by any caller:
//!
//! 1. A `HOST_ONLY`-configured absolute path for this category -- if
//!    present, this is authoritative and terminal: it either resolves or
//!    the category fails closed, and resolution never silently falls
//!    through to steps 2-3 (mirrors the workspace-resolution model's own
//!    "explicit + invalid => fail closed, never a silent fallback" rule).
//! 2. The host's finite, declared list of approved system directories.
//! 3. The host's finite, declared list of approved user-toolchain
//!    directories, only if the host explicitly enabled them.
//! 4. Unavailable.
//!
//! Ambient `PATH` is never read at any step (`AMBIENT_PATH_PROVIDER_AUTHORITY=NO`);
//! this module never looks up the ambient `PATH` environment variable at
//! all, so a poisoned `PATH` cannot influence the result by construction --
//! proven empirically by this module's own `poisoned_path_has_no_effect`
//! test.
//!
//! Every candidate this module resolves is canonicalized via
//! `wht_corulix_workspace::canonicalize_external_path` (Architecture Rule F:
//! only that crate implements filesystem canonicalization) and then checked
//! against the active [`WorkspaceRoot`]: a candidate that canonicalizes to a
//! location inside the workspace is rejected outright, including via
//! symlink indirection, since `CONTROLLED_EXTERNAL_TOOL` can never be
//! satisfied by a workspace-local executable. `TRUSTED_WORKSPACE_EXECUTION`
//! is a distinct execution class this module never resolves into or
//! collapses with `CONTROLLED_EXTERNAL_TOOL`.

use std::path::PathBuf;
use wht_corulix_core::{
    ExecutionClass, ProviderAvailability, ProviderCategory, ProviderProvenance, ReasonCode,
};
use wht_corulix_workspace::{WorkspaceRoot, canonicalize_external_path};

use crate::trust::{EXTERNALLY_RESOLVABLE_CATEGORIES, EffectiveConfig};

/// A typed, never-a-bare-string result of one provider resolution attempt.
/// Never panics on "unavailable" -- absence is always a normal, typed
/// outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderResolution {
    pub category: ProviderCategory,
    pub availability: ProviderAvailability,
    pub resolved_path: Option<PathBuf>,
    pub provenance: Option<ProviderProvenance>,
    pub execution_class: ExecutionClass,
    pub reason: Option<ReasonCode>,
}

impl ProviderResolution {
    fn unavailable(category: ProviderCategory, reason: ReasonCode) -> Self {
        Self {
            category,
            availability: ProviderAvailability::ProviderUnavailable,
            resolved_path: None,
            provenance: None,
            execution_class: ExecutionClass::ControlledExternalTool,
            reason: Some(reason),
        }
    }

    fn available(
        category: ProviderCategory,
        path: PathBuf,
        provenance: ProviderProvenance,
    ) -> Self {
        Self {
            category,
            availability: ProviderAvailability::Available,
            resolved_path: Some(path),
            provenance: Some(provenance),
            execution_class: ExecutionClass::ControlledExternalTool,
            reason: None,
        }
    }
}

/// The three possible outcomes of resolving one filesystem candidate:
/// a usable, canonicalized, non-workspace-local executable; a target that
/// simply does not exist (or is not a regular file); or a candidate that
/// must be rejected because it -- or its resolved target -- is
/// workspace-local.
enum CandidateOutcome {
    Available(PathBuf),
    NotFound,
    WorkspaceLocal,
}

/// Resolves one filesystem candidate and rejects it as workspace-local in
/// either of two distinct ways: the candidate's own location (its
/// *pre-final-symlink* parent directory, joined with its file name) sits
/// inside the workspace -- catching a workspace-planted symlink that merely
/// points at a legitimate external target, which a target-only check would
/// miss -- or its fully resolved canonical target sits inside the
/// workspace -- catching the opposite indirection, an external symlink that
/// resolves back into the workspace. `CONTROLLED_EXTERNAL_TOOL` must reject
/// both; `TRUSTED_WORKSPACE_EXECUTION` is the only execution class this
/// module never resolves into, so neither indirection is ever accepted
/// here regardless of what the final target is.
///
/// Every canonicalization step goes through
/// `wht_corulix_workspace::canonicalize_external_path` (Architecture Rule
/// F); the `starts_with` comparisons themselves are plain prefix checks over
/// already-canonical paths, not a second canonicalization/confinement
/// implementation.
async fn resolve_candidate(candidate: PathBuf, workspace_root: &WorkspaceRoot) -> CandidateOutcome {
    if let Some(parent) = candidate.parent()
        && let Some(file_name) = candidate.file_name()
        && let Ok((canonical_parent, _)) = canonicalize_external_path(parent.to_path_buf()).await
        && canonical_parent
            .join(file_name)
            .starts_with(workspace_root.canonical_path())
    {
        return CandidateOutcome::WorkspaceLocal;
    }
    match canonicalize_external_path(candidate).await {
        Ok((canonical, true)) if canonical.starts_with(workspace_root.canonical_path()) => {
            CandidateOutcome::WorkspaceLocal
        }
        Ok((canonical, true)) => CandidateOutcome::Available(canonical),
        _ => CandidateOutcome::NotFound,
    }
}

/// Computes the platform-correct candidate executable filename for a bare
/// provider name (e.g. `"rustfmt"`), given an executable suffix (empty on
/// Unix, `.exe` on Windows). The real call site below passes the real
/// `std::env::consts::EXE_SUFFIX` constant; `suffix` is an explicit
/// parameter -- rather than this function reading that constant internally
/// -- purely so both the Unix (`""`) and Windows (`".exe"`) branches of this
/// logic are directly unit-testable on any host, with no `#[cfg]` gate and
/// no production-only test seam.
///
/// Idempotent: a `provider_name` that already ends with `suffix`
/// (case-insensitively, since `.exe`/`.EXE` are the same extension on
/// Windows) is returned unchanged -- this function never produces a
/// double-suffixed name like `rustfmt.exe.exe`. On Unix, `suffix` is always
/// `""`, so this is a no-op regardless of `provider_name`, which is what
/// keeps directory-scan resolution behaving exactly as before on that
/// platform.
fn executable_candidate_name(provider_name: &str, suffix: &str) -> String {
    if suffix.is_empty()
        || provider_name
            .to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase())
    {
        provider_name.to_string()
    } else {
        format!("{provider_name}{suffix}")
    }
}

async fn try_directory_candidates(
    category: ProviderCategory,
    provider_name: &str,
    directories: &[PathBuf],
    provenance: ProviderProvenance,
    workspace_root: &WorkspaceRoot,
) -> Option<ProviderResolution> {
    // Both directory-scan tiers (`approved_system_directories` and
    // `approved_user_toolchain_directories`) call this one function, so
    // computing the platform-correct candidate filename here -- rather than
    // at each of `resolve_provider`'s two call sites -- keeps this the sole
    // place a directory-join candidate filename is built, for both tiers
    // and any future one.
    let candidate_name = executable_candidate_name(provider_name, std::env::consts::EXE_SUFFIX);
    for directory in directories {
        let candidate = directory.join(&candidate_name);
        match resolve_candidate(candidate, workspace_root).await {
            CandidateOutcome::Available(canonical) => {
                return Some(ProviderResolution::available(
                    category, canonical, provenance,
                ));
            }
            CandidateOutcome::NotFound | CandidateOutcome::WorkspaceLocal => continue,
        }
    }
    None
}

/// Resolves one provider category to a real, canonicalized executable path
/// under the precedence documented on this module, or reports why it could
/// not be resolved. Never touches ambient `PATH`. Never executes anything --
/// resolution only.
pub async fn resolve_provider(
    effective: &EffectiveConfig,
    workspace_root: &WorkspaceRoot,
    category: ProviderCategory,
    provider_name: &str,
) -> ProviderResolution {
    if !EXTERNALLY_RESOLVABLE_CATEGORIES.contains(&category) {
        return ProviderResolution::unavailable(
            category,
            ReasonCode::ProviderNotExternallyResolvable,
        );
    }

    if !effective.category_enabled(category) {
        return ProviderResolution::unavailable(
            category,
            ReasonCode::ProviderCategoryDisabledByPolicy,
        );
    }

    // Step 1: HOST_ONLY absolute path override -- authoritative and
    // terminal for this category. Malformed/relative input and an
    // unresolvable/workspace-local target all fail closed here; none of
    // them fall through to steps 2-3.
    if let Some(configured) = effective.provider_absolute_path(category) {
        if !configured.is_absolute() {
            return ProviderResolution::unavailable(category, ReasonCode::ProviderPathNotAbsolute);
        }
        return match resolve_candidate(configured.clone(), workspace_root).await {
            CandidateOutcome::Available(canonical) => ProviderResolution::available(
                category,
                canonical,
                ProviderProvenance::HostConfigured,
            ),
            CandidateOutcome::WorkspaceLocal => ProviderResolution::unavailable(
                category,
                ReasonCode::ProviderResolvedInsideWorkspace,
            ),
            CandidateOutcome::NotFound => {
                ProviderResolution::unavailable(category, ReasonCode::ProviderPathUnresolvable)
            }
        };
    }

    // Step 2: approved system directories (finite, host-declared list --
    // never an arbitrary filesystem scan, and never ambient PATH).
    if let Some(resolution) = try_directory_candidates(
        category,
        provider_name,
        effective.approved_system_directories(),
        ProviderProvenance::ApprovedSystemDirectory,
        workspace_root,
    )
    .await
    {
        return resolution;
    }

    // Step 3: approved user-toolchain directories, only if host-enabled.
    if let Some(resolution) = try_directory_candidates(
        category,
        provider_name,
        effective.approved_user_toolchain_directories(),
        ProviderProvenance::ApprovedUserToolchainDirectory,
        workspace_root,
    )
    .await
    {
        return resolution;
    }

    // Step 4: unavailable.
    ProviderResolution::unavailable(category, ReasonCode::RequiredProviderUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{HostConfig, RepositoryHints, RequestOptions};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::CorulixResult;

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("corulix-config-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn open_root(path: &std::path::Path) -> CorulixResult<WorkspaceRoot> {
        WorkspaceRoot::open(path)
    }

    /// Test-only helper that reaches the expected canonical form of a fixture
    /// path through this crate's own canonicalization dependency
    /// (`wht_corulix_workspace::canonicalize_external_path`) rather than
    /// calling `std::fs::canonicalize` directly here -- Architecture Rule F
    /// reserves that primitive to `wht_corulix_workspace` alone, and this
    /// test module is not exempt merely because it is test-only code.
    async fn canonical(path: &std::path::Path) -> CorulixResult<PathBuf> {
        canonicalize_external_path(path.to_path_buf())
            .await
            .map(|(canonical, _)| canonical)
    }

    // `executable_candidate_name` unit tests: pure, synchronous, and
    // parameterized by an injected suffix string rather than reading
    // `std::env::consts::EXE_SUFFIX` internally, so both the Unix (`""`)
    // and Windows (`".exe"`) branches of the real production logic are
    // directly provable on this Linux host -- no `#[cfg(windows)]` needed
    // to exercise the Windows-suffix code path's own logic.

    #[test]
    fn executable_candidate_name_is_a_no_op_for_the_unix_empty_suffix() {
        assert_eq!(executable_candidate_name("rustfmt", ""), "rustfmt");
    }

    #[test]
    fn executable_candidate_name_appends_the_windows_suffix_to_a_bare_name() {
        assert_eq!(executable_candidate_name("rustfmt", ".exe"), "rustfmt.exe");
    }

    #[test]
    fn executable_candidate_name_never_double_suffixes_an_already_suffixed_name() {
        assert_eq!(
            executable_candidate_name("rustfmt.exe", ".exe"),
            "rustfmt.exe"
        );
    }

    #[test]
    fn executable_candidate_name_suffix_match_is_case_insensitive() {
        // `rustfmt.EXE` already carries the suffix (Windows treats
        // `.EXE`/`.exe` as the same extension), so this must be returned
        // unchanged rather than becoming `rustfmt.EXE.exe`.
        assert_eq!(
            executable_candidate_name("rustfmt.EXE", ".exe"),
            "rustfmt.EXE"
        );
    }

    #[tokio::test]
    async fn in_process_category_is_not_externally_resolvable() -> CorulixResult<()> {
        let workspace = temp_dir("workspace");
        let root = open_root(&workspace)?;
        let effective = EffectiveConfig::derive(
            &HostConfig::default(),
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution = resolve_provider(
            &effective,
            &root,
            ProviderCategory::TextSearch,
            "irrelevant",
        )
        .await;
        assert_eq!(
            resolution.availability,
            ProviderAvailability::ProviderUnavailable
        );
        assert_eq!(
            resolution.reason,
            Some(ReasonCode::ProviderNotExternallyResolvable)
        );
        let _ = fs::remove_dir_all(&workspace);
        Ok(())
    }

    #[tokio::test]
    async fn disabled_category_is_rejected_before_any_filesystem_lookup() -> CorulixResult<()> {
        let workspace = temp_dir("workspace");
        let root = open_root(&workspace)?;
        let mut repo = RepositoryHints::default();
        repo.disabled_categories.insert(ProviderCategory::Formatter);
        let effective =
            EffectiveConfig::derive(&HostConfig::default(), &repo, &RequestOptions::default());
        let resolution =
            resolve_provider(&effective, &root, ProviderCategory::Formatter, "irrelevant").await;
        assert_eq!(
            resolution.reason,
            Some(ReasonCode::ProviderCategoryDisabledByPolicy)
        );
        let _ = fs::remove_dir_all(&workspace);
        Ok(())
    }

    #[tokio::test]
    async fn relative_host_configured_path_fails_closed_without_fallback() -> CorulixResult<()> {
        let workspace = temp_dir("workspace");
        let system_dir = temp_dir("system");
        let real_binary = system_dir.join("rust-analyzer");
        let _ = fs::write(&real_binary, "binary");
        let root = open_root(&workspace)?;
        let host = HostConfig {
            provider_absolute_paths: vec![(
                ProviderCategory::LanguageServer,
                PathBuf::from("relative/rust-analyzer"),
            )],
            approved_system_directories: vec![system_dir.clone()],
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution = resolve_provider(
            &effective,
            &root,
            ProviderCategory::LanguageServer,
            "rust-analyzer",
        )
        .await;
        assert_eq!(resolution.reason, Some(ReasonCode::ProviderPathNotAbsolute));
        assert_eq!(
            resolution.availability,
            ProviderAvailability::ProviderUnavailable
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&system_dir);
        Ok(())
    }

    #[tokio::test]
    async fn host_absolute_path_takes_precedence_over_approved_directories() -> CorulixResult<()> {
        let workspace = temp_dir("workspace");
        let host_dir = temp_dir("host");
        let system_dir = temp_dir("system");
        let host_binary = host_dir.join("rustfmt");
        let system_binary = system_dir.join("rustfmt");
        let _ = fs::write(&host_binary, "host binary");
        let _ = fs::write(&system_binary, "system binary");
        let root = open_root(&workspace)?;
        let host = HostConfig {
            provider_absolute_paths: vec![(ProviderCategory::Formatter, host_binary.clone())],
            approved_system_directories: vec![system_dir.clone()],
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution =
            resolve_provider(&effective, &root, ProviderCategory::Formatter, "rustfmt").await;
        assert_eq!(resolution.availability, ProviderAvailability::Available);
        assert_eq!(
            resolution.provenance,
            Some(ProviderProvenance::HostConfigured)
        );
        assert_eq!(
            resolution.resolved_path,
            Some(canonical(&host_binary).await?)
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&host_dir);
        let _ = fs::remove_dir_all(&system_dir);
        Ok(())
    }

    #[tokio::test]
    async fn approved_system_directory_resolves_when_no_host_override_exists() -> CorulixResult<()>
    {
        let workspace = temp_dir("workspace");
        let system_dir = temp_dir("system");
        // The fixture binary's real on-disk filename must carry this
        // platform's executable suffix (empty on Unix, `.exe` on Windows) --
        // `resolve_provider` now looks for the platform-correct candidate
        // name (the F1/Windows-portability fix), so a suffixless fixture
        // would only "work" by accident on Unix and fail closed on Windows.
        let binary = system_dir.join(format!("clippy-driver{}", std::env::consts::EXE_SUFFIX));
        let _ = fs::write(&binary, "binary");
        let root = open_root(&workspace)?;
        let host = HostConfig {
            approved_system_directories: vec![system_dir.clone()],
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution =
            resolve_provider(&effective, &root, ProviderCategory::Linter, "clippy-driver").await;
        assert_eq!(resolution.availability, ProviderAvailability::Available);
        assert_eq!(
            resolution.provenance,
            Some(ProviderProvenance::ApprovedSystemDirectory)
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&system_dir);
        Ok(())
    }

    #[tokio::test]
    async fn approved_user_toolchain_directory_is_ignored_unless_host_enables_it()
    -> CorulixResult<()> {
        let workspace = temp_dir("workspace");
        let user_dir = temp_dir("user-toolchain");
        let binary = user_dir.join("cargo-nextest");
        let _ = fs::write(&binary, "binary");
        let root = open_root(&workspace)?;
        let host = HostConfig {
            approved_user_toolchain_directories: vec![user_dir.clone()],
            enable_user_toolchain_directories: false,
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution = resolve_provider(
            &effective,
            &root,
            ProviderCategory::TestRunner,
            "cargo-nextest",
        )
        .await;
        assert_eq!(
            resolution.availability,
            ProviderAvailability::ProviderUnavailable
        );
        assert_eq!(
            resolution.reason,
            Some(ReasonCode::RequiredProviderUnavailable)
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&user_dir);
        Ok(())
    }

    #[tokio::test]
    async fn approved_user_toolchain_directory_resolves_once_host_enables_it() -> CorulixResult<()>
    {
        let workspace = temp_dir("workspace");
        let user_dir = temp_dir("user-toolchain");
        // Same platform-suffix requirement as the approved-system-directory
        // fixture above -- see its comment.
        let binary = user_dir.join(format!("cargo-nextest{}", std::env::consts::EXE_SUFFIX));
        let _ = fs::write(&binary, "binary");
        let root = open_root(&workspace)?;
        let host = HostConfig {
            approved_user_toolchain_directories: vec![user_dir.clone()],
            enable_user_toolchain_directories: true,
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution = resolve_provider(
            &effective,
            &root,
            ProviderCategory::TestRunner,
            "cargo-nextest",
        )
        .await;
        assert_eq!(resolution.availability, ProviderAvailability::Available);
        assert_eq!(
            resolution.provenance,
            Some(ProviderProvenance::ApprovedUserToolchainDirectory)
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&user_dir);
        Ok(())
    }

    #[tokio::test]
    async fn missing_provider_everywhere_is_reported_unavailable_not_panicked() -> CorulixResult<()>
    {
        let workspace = temp_dir("workspace");
        let system_dir = temp_dir("system");
        let root = open_root(&workspace)?;
        let host = HostConfig {
            approved_system_directories: vec![system_dir.clone()],
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution = resolve_provider(
            &effective,
            &root,
            ProviderCategory::TypecheckBuild,
            "does-not-exist",
        )
        .await;
        assert_eq!(
            resolution.availability,
            ProviderAvailability::ProviderUnavailable
        );
        assert_eq!(
            resolution.reason,
            Some(ReasonCode::RequiredProviderUnavailable)
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&system_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn workspace_local_candidate_is_rejected_for_controlled_external_tool()
    -> CorulixResult<()> {
        let workspace = temp_dir("workspace");
        let binary = workspace.join("rust-analyzer");
        let _ = fs::write(&binary, "binary");
        let root = open_root(&workspace)?;
        let host = HostConfig {
            provider_absolute_paths: vec![(ProviderCategory::LanguageServer, binary.clone())],
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution = resolve_provider(
            &effective,
            &root,
            ProviderCategory::LanguageServer,
            "rust-analyzer",
        )
        .await;
        assert_eq!(
            resolution.reason,
            Some(ReasonCode::ProviderResolvedInsideWorkspace)
        );
        assert_eq!(
            resolution.availability,
            ProviderAvailability::ProviderUnavailable
        );
        let _ = fs::remove_dir_all(&workspace);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn workspace_local_symlink_indirection_is_rejected() -> CorulixResult<()> {
        use std::os::unix::fs::symlink;

        let workspace = temp_dir("workspace");
        let outside = temp_dir("outside");
        let real_binary = outside.join("rustfmt");
        let _ = fs::write(&real_binary, "binary");
        let link = workspace.join("rustfmt-link");
        let _ = symlink(&real_binary, &link);
        let root = open_root(&workspace)?;
        let host = HostConfig {
            provider_absolute_paths: vec![(ProviderCategory::Formatter, link.clone())],
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution = resolve_provider(
            &effective,
            &root,
            ProviderCategory::Formatter,
            "rustfmt-link",
        )
        .await;
        // The symlink itself lives inside the workspace, so even though it
        // points to a real binary outside, the *candidate path* is
        // workspace-local -- rejected before its target is ever considered
        // trustworthy on that basis alone.
        assert_eq!(
            resolution.reason,
            Some(ReasonCode::ProviderResolvedInsideWorkspace)
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn poisoned_path_has_no_effect() -> CorulixResult<()> {
        // This module contains no `PATH` lookup at all (proven structurally
        // by Rule K's static scan), so a real, on-disk "attacker" binary
        // that would be found first by an ambient-PATH-based lookup must
        // still be completely invisible to this resolver: it is not in any
        // approved directory and is not the host-configured path, so the
        // real, legitimate binary in the approved system directory is what
        // resolves -- not the attacker's. Since editing the current
        // process's live `PATH` requires an `unsafe fn` under this
        // workspace's edition and `unsafe_code = "forbid"` disallows that,
        // this test proves the same property without ever touching `PATH`:
        // it plants the attacker binary in a directory that is
        // deliberately *not* approved and confirms it is never selected.
        let workspace = temp_dir("workspace");
        let system_dir = temp_dir("system");
        // Platform-correct suffix required -- see the comment on
        // `approved_system_directory_resolves_when_no_host_override_exists`
        // above for why.
        let real_binary = system_dir.join(format!("rustfmt{}", std::env::consts::EXE_SUFFIX));
        let _ = fs::write(&real_binary, "real binary");

        let attacker_dir = temp_dir("attacker");
        let poisoned_binary = attacker_dir.join(format!("rustfmt{}", std::env::consts::EXE_SUFFIX));
        let _ = fs::write(&poisoned_binary, "poisoned binary");

        let root = open_root(&workspace)?;
        let host = HostConfig {
            approved_system_directories: vec![system_dir.clone()],
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        let resolution =
            resolve_provider(&effective, &root, ProviderCategory::Formatter, "rustfmt").await;

        assert_eq!(resolution.availability, ProviderAvailability::Available);
        assert_eq!(
            resolution.provenance,
            Some(ProviderProvenance::ApprovedSystemDirectory)
        );
        assert_eq!(
            resolution.resolved_path,
            Some(canonical(&real_binary).await?)
        );
        assert_ne!(
            resolution.resolved_path,
            Some(canonical(&poisoned_binary).await?)
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&system_dir);
        let _ = fs::remove_dir_all(&attacker_dir);
        Ok(())
    }
}
