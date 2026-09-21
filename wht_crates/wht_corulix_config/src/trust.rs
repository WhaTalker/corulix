// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The three-tier configuration source model and its monotonic merge into
//! one [`EffectiveConfig`].
//!
//! Trust and security-floor authority flow in exactly one direction:
//! `HostConfig` (`HOST_ONLY`, owner/operator-authored) may only be
//! *tightened* by `RepositoryHints` (`REPOSITORY_HINT`, repository-authored)
//! and further *narrowed* by `RequestOptions` (`REQUEST_SCOPED`,
//! per-request). Neither `RepositoryHints` nor `RequestOptions` carries a
//! [`WorkspaceTrust`] field, an execution-class-allowance field, or a
//! provider-path field at all -- this is a structural, not merely
//! behavioral, guarantee that a repository or a single request can never
//! elevate trust or widen provider resolution
//! (`REPOSITORY_TRUST_ELEVATION_PATH_COUNT=0`,
//! `REQUEST_TRUST_ELEVATION_PATH_COUNT=0`). `ADMIN_ONLY` is deliberately not
//! modeled: no authenticated remote admin plane exists yet, and inventing
//! one here would be a premature, unauthenticated implementation of a
//! configuration source this phase does not own.

use std::collections::HashSet;
use std::path::PathBuf;
use wht_corulix_core::{ExecutionClass, ProviderCategory, WorkspaceTrust};

/// The finite set of provider categories this crate ever resolves
/// externally. `TextSearch` and `StructuralParse` are compiled-in,
/// in-process capabilities (see `wht_corulix_engine::providers::ProviderSnapshot`)
/// with no executable path to resolve, so they are intentionally excluded
/// here -- resolving them through this list would misrepresent an
/// in-process capability as an external one.
pub const EXTERNALLY_RESOLVABLE_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory::LanguageServer,
    ProviderCategory::Formatter,
    ProviderCategory::Linter,
    ProviderCategory::TypecheckBuild,
    ProviderCategory::TestRunner,
    ProviderCategory::Runtime,
];

/// Installation-Contract-V1 fix (`HOSTCONFIG_AUTHORITY_MODEL_AMBIGUITY`):
/// the host's own stance on real, network-triggered `CORULIX_MANAGED`
/// acquisition, kept structurally distinct from *whether* acquisition is
/// desired at all -- that latter question belongs to the persisted install
/// profile (`wht_corulix_tooling`'s install-profile/reconciler subsystem),
/// never to `HostConfig`.
///
/// A bare `bool` cannot represent "the host has no opinion, defer to
/// whatever the install profile already intends" without conflating it with
/// an explicit deny -- which is exactly the defect this type replaces (the
/// prior `allow_managed_provisioning: bool` defaulted to `false`, which was
/// indistinguishable from an operator explicitly forbidding provisioning,
/// and broke the owner's `DEFAULT_INSTALL_PROFILE=FULL` contract: a
/// never-configured host must not silently block the product's own default
/// behavior).
///
/// - `Inherit` (the default): defer entirely to the persisted install
///   profile's own granted intent for the component in question.
/// - `Allow`: unconditionally permits acquisition regardless of profile
///   state -- an escape hatch for a host that does not want to engage with
///   the profile system at all.
/// - `Deny`: an unconditional host-level veto that no profile, however
///   permissive, can override.
///
/// See [`EffectiveConfig::managed_provisioning_permitted`] for the single
/// production combinator every acquisition call site must use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ManagedProvisioningPolicy {
    #[default]
    Inherit,
    Allow,
    Deny,
}

/// `HOST_ONLY` configuration: the owner/operator security envelope. This is
/// the only configuration source that may set [`WorkspaceTrust`], allow
/// `TRUSTED_WORKSPACE_EXECUTION`, configure an absolute provider path, or
/// declare an approved system/user-toolchain directory list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostConfig {
    /// Never anything but the value the host explicitly set; the type's own
    /// `Default` (via [`WorkspaceTrust::default`]) is `Untrusted`, and
    /// nothing in this crate ever infers or self-declares `Trusted`.
    pub workspace_trust: WorkspaceTrust,
    /// Whether `TRUSTED_WORKSPACE_EXECUTION` may be authorized at all, even
    /// when `workspace_trust == Trusted`. Both conditions are required --
    /// see [`EffectiveConfig::is_execution_class_allowed`].
    pub allow_trusted_workspace_execution: bool,
    /// An explicit absolute path for a specific provider category. Presence
    /// here makes host configuration authoritative and terminal for that
    /// category: resolution either succeeds against this exact path or
    /// fails closed, and never silently falls through to the approved
    /// system/user-toolchain directories below it in precedence.
    pub provider_absolute_paths: Vec<(ProviderCategory, PathBuf)>,
    /// A finite, host-declared list of directories resolution may search
    /// for a provider binary by name. Never an arbitrary filesystem scan --
    /// only these exact directories are ever consulted.
    pub approved_system_directories: Vec<PathBuf>,
    /// A finite, host-declared list of user-toolchain directories. Consulted
    /// only when `enable_user_toolchain_directories` is `true`.
    pub approved_user_toolchain_directories: Vec<PathBuf>,
    /// Disabled by default -- user-toolchain directories are a weaker trust
    /// tier than approved system directories and require explicit host
    /// opt-in.
    pub enable_user_toolchain_directories: bool,
    /// The host's stance on real `CORULIX_MANAGED` acquisition -- see
    /// [`ManagedProvisioningPolicy`]'s own doc comment. Defaults to
    /// `Inherit`, never `Deny`: an operator who has never configured this
    /// field must not silently block the product's own
    /// `DEFAULT_INSTALL_PROFILE=FULL` behavior. Passive resolution of an
    /// already-owned managed component (via `resolve_owned_managed_component`)
    /// is never gated by this policy at all -- only the network-triggering
    /// acquisition step is, and only when `Inherit` defers to a persisted
    /// profile that does not grant intent, or `Deny` is set explicitly.
    pub managed_provisioning_policy: ManagedProvisioningPolicy,
}

impl HostConfig {
    #[must_use]
    pub fn provider_absolute_path(&self, category: ProviderCategory) -> Option<&PathBuf> {
        self.provider_absolute_paths
            .iter()
            .find(|(candidate, _)| *candidate == category)
            .map(|(_, path)| path)
    }
}

/// `REPOSITORY_HINT` configuration: repository-authored, and only ever able
/// to *narrow* the `HostConfig` envelope. Deliberately has no trust,
/// execution-class, or provider-path field -- there is structurally no way
/// for a repository to elevate trust or widen provider resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepositoryHints {
    /// Provider categories this repository asks to be disabled. Merge is
    /// monotonic: a category absent from `HostConfig`'s allowance cannot be
    /// re-enabled here, and a category present may only be turned off, never
    /// added.
    pub disabled_categories: HashSet<ProviderCategory>,
}

/// `REQUEST_SCOPED` configuration: per-request, and only ever able to
/// *narrow* further. Deliberately has no trust, execution-class, or
/// provider-path field, for the same structural reason as
/// [`RepositoryHints`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestOptions {
    /// `None` means "no additional narrowing"; `Some(set)` restricts
    /// resolution to the intersection of this set with whatever `HostConfig`
    /// and `RepositoryHints` already allow.
    pub requested_categories: Option<HashSet<ProviderCategory>>,
}

/// The deterministic merge of `HostConfig` → `RepositoryHints` →
/// `RequestOptions`. Every field not related to category enablement is
/// copied verbatim from `HostConfig` -- neither hint source ever contributes
/// a security-floor value, since neither type carries one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveConfig {
    workspace_trust: WorkspaceTrust,
    allow_trusted_workspace_execution: bool,
    provider_absolute_paths: Vec<(ProviderCategory, PathBuf)>,
    approved_system_directories: Vec<PathBuf>,
    approved_user_toolchain_directories: Vec<PathBuf>,
    enable_user_toolchain_directories: bool,
    managed_provisioning_policy: ManagedProvisioningPolicy,
    enabled_categories: HashSet<ProviderCategory>,
}

impl EffectiveConfig {
    /// Derives the effective configuration. Monotonic by construction: the
    /// enabled-category set starts at `EXTERNALLY_RESOLVABLE_CATEGORIES` and
    /// every subsequent step only removes members, never adds any -- so no
    /// combination of `repo`/`request` input can ever enable a category
    /// `host` did not already allow.
    #[must_use]
    pub fn derive(host: &HostConfig, repo: &RepositoryHints, request: &RequestOptions) -> Self {
        let mut enabled: HashSet<ProviderCategory> =
            EXTERNALLY_RESOLVABLE_CATEGORIES.iter().copied().collect();
        enabled.retain(|category| !repo.disabled_categories.contains(category));
        if let Some(requested) = &request.requested_categories {
            enabled.retain(|category| requested.contains(category));
        }
        Self {
            workspace_trust: host.workspace_trust,
            allow_trusted_workspace_execution: host.allow_trusted_workspace_execution,
            provider_absolute_paths: host.provider_absolute_paths.clone(),
            approved_system_directories: host.approved_system_directories.clone(),
            approved_user_toolchain_directories: host.approved_user_toolchain_directories.clone(),
            enable_user_toolchain_directories: host.enable_user_toolchain_directories,
            managed_provisioning_policy: host.managed_provisioning_policy,
            enabled_categories: enabled,
        }
    }

    #[must_use]
    pub fn workspace_trust(&self) -> WorkspaceTrust {
        self.workspace_trust
    }

    #[must_use]
    pub fn category_enabled(&self, category: ProviderCategory) -> bool {
        self.enabled_categories.contains(&category)
    }

    #[must_use]
    pub fn provider_absolute_path(&self, category: ProviderCategory) -> Option<&PathBuf> {
        self.provider_absolute_paths
            .iter()
            .find(|(candidate, _)| *candidate == category)
            .map(|(_, path)| path)
    }

    #[must_use]
    pub fn approved_system_directories(&self) -> &[PathBuf] {
        &self.approved_system_directories
    }

    #[must_use]
    pub fn approved_user_toolchain_directories(&self) -> &[PathBuf] {
        if self.enable_user_toolchain_directories {
            &self.approved_user_toolchain_directories
        } else {
            &[]
        }
    }

    /// Only `TrustedWorkspaceExecution` is gated here: it requires both
    /// `workspace_trust == Trusted` *and* explicit host opt-in via
    /// `allow_trusted_workspace_execution`. Every other execution class is
    /// structurally always allowed by this check -- their own resolution or
    /// invocation logic is where any further gating belongs, not this
    /// generic floor.
    /// The host's raw [`ManagedProvisioningPolicy`], copied verbatim from
    /// `HostConfig` -- neither `RepositoryHints` nor `RequestOptions` carries
    /// a field capable of setting or narrowing this, mirroring every other
    /// security-floor field on this struct. Most callers want
    /// [`Self::managed_provisioning_permitted`] instead of reading this
    /// directly.
    #[must_use]
    pub fn managed_provisioning_policy(&self) -> ManagedProvisioningPolicy {
        self.managed_provisioning_policy
    }

    /// The single production authority check every real-acquisition call
    /// site must use (Installation-Contract-V1, `HOSTCONFIG_AUTHORITY_MODEL_AMBIGUITY`).
    /// `profile_grants_intent` is the caller's own answer -- computed against
    /// the persisted install profile's desired-component graph, entirely
    /// outside this crate's knowledge -- to "does the currently active
    /// install profile (FULL/SELECTIVE/ON_DEMAND) intend this specific
    /// component to be provisioned?" `Deny` always wins regardless of that
    /// answer; `Allow` always wins regardless of that answer; `Inherit` (the
    /// default) defers to it entirely. This is deliberately the *only* path
    /// by which a profile's intent becomes a real permission -- `HostConfig`
    /// never learns which component is being asked about, only whether it
    /// occupies a hard veto/override stance.
    #[must_use]
    pub fn managed_provisioning_permitted(&self, profile_grants_intent: bool) -> bool {
        match self.managed_provisioning_policy {
            ManagedProvisioningPolicy::Deny => false,
            ManagedProvisioningPolicy::Allow => true,
            ManagedProvisioningPolicy::Inherit => profile_grants_intent,
        }
    }

    #[must_use]
    pub fn is_execution_class_allowed(&self, class: ExecutionClass) -> bool {
        match class {
            ExecutionClass::TrustedWorkspaceExecution => {
                self.workspace_trust == WorkspaceTrust::Trusted
                    && self.allow_trusted_workspace_execution
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_workspace_trust_is_untrusted() {
        let host = HostConfig::default();
        assert_eq!(host.workspace_trust, WorkspaceTrust::Untrusted);
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert_eq!(effective.workspace_trust(), WorkspaceTrust::Untrusted);
    }

    #[test]
    fn repository_hint_cannot_elevate_trust() {
        let host = HostConfig::default();
        let repo = RepositoryHints::default();
        let request = RequestOptions::default();
        let effective = EffectiveConfig::derive(&host, &repo, &request);
        // RepositoryHints has no field capable of setting trust at all --
        // this assertion proves the merge result is untouched regardless of
        // hint content, and the type itself proves there is no path to try.
        assert_eq!(effective.workspace_trust(), WorkspaceTrust::Untrusted);
    }

    #[test]
    fn request_cannot_elevate_trust() {
        let host = HostConfig::default();
        let repo = RepositoryHints::default();
        let mut requested = HashSet::new();
        requested.insert(ProviderCategory::Formatter);
        let request = RequestOptions {
            requested_categories: Some(requested),
        };
        let effective = EffectiveConfig::derive(&host, &repo, &request);
        assert_eq!(effective.workspace_trust(), WorkspaceTrust::Untrusted);
    }

    #[test]
    fn trusted_workspace_execution_requires_both_trust_and_host_opt_in() {
        let mut host = HostConfig {
            workspace_trust: WorkspaceTrust::Trusted,
            ..HostConfig::default()
        };
        let effective_without_opt_in = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert!(
            !effective_without_opt_in
                .is_execution_class_allowed(ExecutionClass::TrustedWorkspaceExecution)
        );

        host.allow_trusted_workspace_execution = true;
        let effective_with_opt_in = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert!(
            effective_with_opt_in
                .is_execution_class_allowed(ExecutionClass::TrustedWorkspaceExecution)
        );
    }

    #[test]
    fn untrusted_workspace_never_allows_trusted_workspace_execution() {
        let host = HostConfig {
            allow_trusted_workspace_execution: true,
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert!(!effective.is_execution_class_allowed(ExecutionClass::TrustedWorkspaceExecution));
    }

    #[test]
    fn other_execution_classes_are_always_allowed_by_this_floor() {
        let host = HostConfig::default();
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert!(effective.is_execution_class_allowed(ExecutionClass::ReadOnlyInProcess));
        assert!(effective.is_execution_class_allowed(ExecutionClass::ControlledExternalTool));
        assert!(effective.is_execution_class_allowed(ExecutionClass::ManagedFuture));
    }

    #[test]
    fn repository_hint_can_only_narrow_never_widen_categories() {
        let host = HostConfig::default();
        let mut repo = RepositoryHints::default();
        repo.disabled_categories.insert(ProviderCategory::Formatter);
        let effective = EffectiveConfig::derive(&host, &repo, &RequestOptions::default());
        assert!(!effective.category_enabled(ProviderCategory::Formatter));
        assert!(effective.category_enabled(ProviderCategory::Linter));
    }

    #[test]
    fn request_can_only_narrow_further_than_repository_hint() {
        let host = HostConfig::default();
        let repo = RepositoryHints::default();
        let mut requested = HashSet::new();
        requested.insert(ProviderCategory::Linter);
        let request = RequestOptions {
            requested_categories: Some(requested),
        };
        let effective = EffectiveConfig::derive(&host, &repo, &request);
        assert!(effective.category_enabled(ProviderCategory::Linter));
        assert!(!effective.category_enabled(ProviderCategory::Formatter));
    }

    #[test]
    fn request_cannot_re_enable_a_category_the_repository_disabled() {
        let host = HostConfig::default();
        let mut repo = RepositoryHints::default();
        repo.disabled_categories.insert(ProviderCategory::Formatter);
        let mut requested = HashSet::new();
        requested.insert(ProviderCategory::Formatter);
        let request = RequestOptions {
            requested_categories: Some(requested),
        };
        let effective = EffectiveConfig::derive(&host, &repo, &request);
        assert!(!effective.category_enabled(ProviderCategory::Formatter));
    }

    #[test]
    fn managed_provisioning_policy_defaults_to_inherit_not_deny() {
        let host = HostConfig::default();
        assert_eq!(
            host.managed_provisioning_policy,
            ManagedProvisioningPolicy::Inherit
        );
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert_eq!(
            effective.managed_provisioning_policy(),
            ManagedProvisioningPolicy::Inherit
        );
    }

    #[test]
    fn inherit_defers_entirely_to_profile_intent() {
        let host = HostConfig::default();
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert!(!effective.managed_provisioning_permitted(false));
        assert!(effective.managed_provisioning_permitted(true));
    }

    #[test]
    fn explicit_host_deny_overrides_profile_intent() {
        let host = HostConfig {
            managed_provisioning_policy: ManagedProvisioningPolicy::Deny,
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert!(!effective.managed_provisioning_permitted(true));
        assert!(!effective.managed_provisioning_permitted(false));
    }

    #[test]
    fn explicit_host_allow_overrides_absent_profile_intent() {
        let host = HostConfig {
            managed_provisioning_policy: ManagedProvisioningPolicy::Allow,
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert!(effective.managed_provisioning_permitted(true));
        assert!(effective.managed_provisioning_permitted(false));
    }

    #[test]
    fn user_toolchain_directories_are_hidden_unless_host_enables_them() {
        let host = HostConfig {
            approved_user_toolchain_directories: vec![PathBuf::from("/home/user/.local/bin")],
            enable_user_toolchain_directories: false,
            ..HostConfig::default()
        };
        let effective = EffectiveConfig::derive(
            &host,
            &RepositoryHints::default(),
            &RequestOptions::default(),
        );
        assert!(effective.approved_user_toolchain_directories().is_empty());
    }
}
