// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Persisted install-profile state (Installation-Contract-V1 fix,
//! `CORULIX_INSTALLATION_CONTRACT_V1`): the durable, `CORULIX_MANAGED`-owned
//! record of *what the operator wants installed*, kept structurally
//! distinct from `wht_corulix_config::HostConfig`'s
//! `ManagedProvisioningPolicy` (the host's security veto/override -- see
//! that type's own doc comment). Neither a workspace nor an MCP request can
//! ever read or influence this file; it is written only by real bootstrap
//! entry points ([`ensure_bootstrapped`]) or an explicit `corulix setup`
//! invocation.
//!
//! # The three canonical profiles
//!
//! - [`InstallProfile::Full`]: every canonical `CORULIX_MANAGED` component
//!   grants intent. This is the product default -- an operator who runs
//!   `corulix setup` with no flags, or who never runs `setup` at all and
//!   simply starts using Corulix, ends up here via [`ensure_bootstrapped`].
//! - [`InstallProfile::Selective`]: only the explicitly resolved component
//!   set (already expanded from user-facing group names plus their
//!   mandatory dependencies by the `setup` CLI layer -- this module stores
//!   the resolved id set, never raw group names, so this check never needs
//!   the group model itself) grants intent.
//! - [`InstallProfile::OnDemand`]: grants intent for anything a legitimate
//!   production operation asks for, identically to `Full` from this
//!   module's own point of view -- the distinction between the two only
//!   matters to a *proactive* `corulix setup` reconciliation pass (which
//!   downloads everything up front for `Full` but nothing up front for
//!   `OnDemand`), not to this runtime permission check.
//!
//! # Profile-absent is not profile-on-demand
//!
//! [`grants_intent`] treats "no profile has ever been persisted" as *not
//! granted* -- deliberately different from `OnDemand`, which always grants.
//! This is the asymmetry that keeps an isolated, never-bootstrapped managed
//! root fail-closed: a component absent from disk and absent from the
//! ownership ledger must never be silently acquired just because no one
//! has expressed an opinion yet. [`ensure_bootstrapped`] exists precisely
//! so this transient state never persists in real production use -- it is
//! called once, at real process bootstrap (`corulix mcp stdio` startup,
//! `corulix setup` startup), never from this passive per-call check.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::ownership::root_identity;

/// The operator's persisted installation intent. See the module doc
/// comment for the semantics of each variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "profile", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallProfile {
    Full,
    Selective {
        /// Canonical component ids already resolved (group names expanded,
        /// mandatory dependencies included) by the `setup` CLI layer at the
        /// time this profile was chosen -- never raw, unexpanded group
        /// names.
        components: std::collections::BTreeSet<String>,
    },
    OnDemand,
}

impl InstallProfile {
    /// Whether this profile grants intent for real, network-triggered
    /// acquisition of `component_id`. See the module doc comment for why
    /// `Full`/`OnDemand` both grant unconditionally here and only
    /// `Selective` performs a real membership check.
    #[must_use]
    pub fn grants_intent(&self, component_id: &str) -> bool {
        match self {
            Self::Full | Self::OnDemand => true,
            Self::Selective { components } => components.contains(component_id),
        }
    }
}

/// Every way loading or saving persisted install-profile state fails
/// closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallProfileError {
    Io,
    CorruptState,
    /// The persisted state was written under a different managed root and
    /// must never be silently reused against this one -- mirrors
    /// `OwnershipError::RootIdentityMismatch`'s own rationale.
    RootIdentityMismatch,
    Serialization,
}

#[derive(Serialize, Deserialize)]
struct PersistedInstallProfileState {
    managed_root_identity: String,
    profile: InstallProfile,
}

/// `pub(crate)` (not private): `full_uninstall`'s own root-cleanup step
/// needs this exact path to remove the persisted profile as part of a full
/// uninstall, matching `recovery_locked`'s own cross-submodule visibility
/// precedent in this same `provisioning` module tree.
pub(crate) fn state_path(root: &Path) -> PathBuf {
    root.join("install-profile.json")
}

/// Loads the persisted install profile under `root`. A pure, passive read
/// that never writes anything -- mirrors
/// [`super::ownership::load`]'s own "`Ok(None)` means nothing has ever been
/// persisted" contract. Fails closed (`CorruptState`/`RootIdentityMismatch`)
/// on malformed content or a foreign root rather than guessing at intent.
pub fn load(root: &Path) -> Result<Option<InstallProfile>, InstallProfileError> {
    let path = state_path(root);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|_| InstallProfileError::Io)?;
    let state: PersistedInstallProfileState =
        serde_json::from_slice(&bytes).map_err(|_| InstallProfileError::CorruptState)?;
    if state.managed_root_identity != root_identity(root) {
        return Err(InstallProfileError::RootIdentityMismatch);
    }
    Ok(Some(state.profile))
}

/// Persists `profile` under `root`. Writes to a sibling temp file and
/// renames onto the final path so a crash mid-write can never leave a
/// half-written, undetectably-corrupt state file in place of a good one --
/// the same atomicity convention [`super::ownership::save`] already
/// establishes.
pub fn save(root: &Path, profile: &InstallProfile) -> Result<(), InstallProfileError> {
    fs::create_dir_all(root).map_err(|_| InstallProfileError::Io)?;
    let state = PersistedInstallProfileState {
        managed_root_identity: root_identity(root),
        profile: profile.clone(),
    };
    let bytes =
        serde_json::to_vec_pretty(&state).map_err(|_| InstallProfileError::Serialization)?;
    let final_path = state_path(root);
    let tmp_path = root.join("install-profile.json.tmp");
    fs::write(&tmp_path, &bytes).map_err(|_| InstallProfileError::Io)?;
    fs::rename(&tmp_path, &final_path).map_err(|_| InstallProfileError::Io)?;
    Ok(())
}

/// Mandatory first-run reconciliation (`FIRST_RUN_RECONCILIATION`): if no
/// profile has ever been persisted under `root`, defaults to
/// [`InstallProfile::Full`] and persists it immediately; otherwise returns
/// the already-persisted profile untouched. Never silently overwrites an
/// explicit `Selective`/`OnDemand` choice back to `Full`
/// (`EXPLICIT_INSTALL_PROFILE_PERSISTENCE`).
///
/// Callers: real process bootstrap only (`corulix mcp stdio` startup,
/// `corulix setup` startup). Never call this from the passive per-call
/// acquisition gate -- that check must stay side-effect-free, exactly like
/// every other passive resolution check in this workspace.
pub fn ensure_bootstrapped(root: &Path) -> Result<InstallProfile, InstallProfileError> {
    match load(root)? {
        Some(profile) => Ok(profile),
        None => {
            let profile = InstallProfile::Full;
            save(root, &profile)?;
            Ok(profile)
        }
    }
}

/// The single production authority check every real-acquisition call site
/// uses to answer "does the persisted install profile grant intent for
/// `component_id`?" -- see the module doc comment's "Profile-absent is not
/// profile-on-demand" section for why a load failure or absent profile
/// resolves to `false`, never a silent `true`.
#[must_use]
pub fn grants_intent(root: &Path, component_id: &str) -> bool {
    load(root)
        .ok()
        .flatten()
        .is_some_and(|profile| profile.grants_intent(component_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir =
            std::env::temp_dir().join(format!("corulix-install-profile-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    /// This workspace's `clippy::expect_used = "deny"` lint applies to test
    /// code exactly as it does to production code -- mirrors
    /// `full_uninstall.rs`'s own `ok_or_panic` test-fixture helper.
    fn ok_or_panic<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("test fixture setup must succeed: {error:?}"))
    }

    #[test]
    fn absent_profile_grants_nothing() {
        let root = temp_root("absent");
        assert_eq!(load(&root), Ok(None));
        assert!(!grants_intent(&root, "rustfmt"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn full_grants_any_component() {
        let root = temp_root("full");
        ok_or_panic(save(&root, &InstallProfile::Full));
        assert!(grants_intent(&root, "rustfmt"));
        assert!(grants_intent(&root, "anything-at-all"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn on_demand_grants_any_component_like_full() {
        let root = temp_root("on-demand");
        ok_or_panic(save(&root, &InstallProfile::OnDemand));
        assert!(grants_intent(&root, "rustfmt"));
        assert!(grants_intent(&root, "biome"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn selective_grants_only_resolved_components() {
        let root = temp_root("selective");
        let profile = InstallProfile::Selective {
            components: ["rustfmt", "rust-semantic-runtime"]
                .into_iter()
                .map(String::from)
                .collect(),
        };
        ok_or_panic(save(&root, &profile));
        assert!(grants_intent(&root, "rustfmt"));
        assert!(!grants_intent(&root, "biome"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_bootstrapped_defaults_to_full_when_absent() {
        let root = temp_root("bootstrap-absent");
        assert_eq!(load(&root), Ok(None));
        let profile = ok_or_panic(ensure_bootstrapped(&root));
        assert_eq!(profile, InstallProfile::Full);
        assert_eq!(load(&root), Ok(Some(InstallProfile::Full)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_bootstrapped_never_overwrites_an_explicit_choice() {
        let root = temp_root("bootstrap-explicit");
        ok_or_panic(save(&root, &InstallProfile::OnDemand));
        let profile = ok_or_panic(ensure_bootstrapped(&root));
        assert_eq!(profile, InstallProfile::OnDemand);
        assert_eq!(load(&root), Ok(Some(InstallProfile::OnDemand)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn foreign_root_identity_is_rejected() {
        let root = temp_root("foreign");
        let other_root = temp_root("foreign-other");
        let state = PersistedInstallProfileState {
            managed_root_identity: root_identity(&other_root),
            profile: InstallProfile::Full,
        };
        ok_or_panic(fs::create_dir_all(&root));
        let bytes = ok_or_panic(serde_json::to_vec_pretty(&state));
        ok_or_panic(fs::write(state_path(&root), bytes));
        assert_eq!(load(&root), Err(InstallProfileError::RootIdentityMismatch));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&other_root);
    }

    #[test]
    fn corrupt_state_file_is_rejected_not_panicked() {
        let root = temp_root("corrupt");
        ok_or_panic(fs::create_dir_all(&root));
        ok_or_panic(fs::write(state_path(&root), b"not json"));
        assert_eq!(load(&root), Err(InstallProfileError::CorruptState));
        let _ = fs::remove_dir_all(&root);
    }
}
