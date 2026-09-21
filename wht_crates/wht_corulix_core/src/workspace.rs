// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Workspace identity, resolution, and trust contracts.
//!
//! These types describe *what a workspace is* and *how it was resolved*;
//! they carry no filesystem I/O, no canonicalization logic, and no MCP Roots
//! concept (Roots is deprecated per SEP-2577 and is not part of the 1.0.0
//! canonical workspace model). The runtime resolver that actually walks the
//! filesystem and produces these values is implemented in a later phase.

use crate::error::{CorulixError, CorulixResult};
use serde::{Deserialize, Serialize};

/// Public-facing description of the active workspace root.
///
/// `root_label` is deliberately just the final path component, and
/// `root_redacted` records that the full absolute path is never exposed --
/// this keeps local filesystem layout out of MCP responses and logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkspaceInfo {
    pub schema_version: u32,
    pub root_label: String,
    pub root_redacted: bool,
    pub read_only: bool,
}

/// An opaque, protocol-agnostic identifier bound to a resolved workspace.
///
/// This is deliberately **not** an absolute path, a relative path, a
/// deterministic hash of a path, an unsalted path fingerprint, or a trust
/// decision -- it is an opaque token a later runtime layer generates once a
/// workspace is bound to a process. Core defines only the type and its
/// construction invariant (non-empty); it performs no entropy generation and
/// carries no `uuid`/`getrandom`/CSPRNG dependency.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct WorkspaceIdentity(String);

impl WorkspaceIdentity {
    /// Constructs this identity from an already-generated opaque token. This
    /// type performs no entropy generation itself -- the caller (a later
    /// runtime phase that actually binds a workspace) is responsible for
    /// producing an unpredictable token before constructing this value.
    pub fn from_opaque_token(token: String) -> CorulixResult<Self> {
        if token.is_empty() {
            return Err(CorulixError::InvalidInput(
                "workspace identity token must not be empty".into(),
            ));
        }
        Ok(Self(token))
    }

    /// The opaque token backing this identity. Not a path, not a hash of a
    /// path -- callers must not attempt to derive filesystem semantics from
    /// this value.
    pub fn as_opaque_token(&self) -> &str {
        &self.0
    }
}

/// Which resolver source produced a workspace candidate.
///
/// Deliberately excludes an MCP Roots variant: Roots (`roots/list`) is
/// deprecated in the official MCP specification itself (SEP-2577, protocol
/// version `2026-07-28`), and new implementations are advised to use
/// ordinary tool parameters instead of that back-channel. Corulix 1.0.0
/// resolves a workspace once per process from an explicit flag, an
/// environment variable, or bounded discovery seeded from the process's
/// current working directory -- never from a raw, unvalidated `cwd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum WorkspaceSourceKind {
    ExplicitFlag,
    Environment,
    DiscoverySeeded,
}

/// What happened while resolving a workspace candidate from a given source.
///
/// Deliberately a separate type from [`WorkspaceSourceKind`]: the source
/// answers *where a candidate came from*, this answers *what happened while
/// resolving it*. An explicit, authoritative source (flag/env) that resolves
/// to `Invalid` or `Ambiguous` must fail closed -- it must never be silently
/// treated as `Absent` so resolution falls through to a lower-precedence
/// source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum WorkspaceResolutionStatus {
    Absent,
    Selected,
    Invalid,
    Ambiguous,
    Exhausted,
}

/// Authorization to execute workspace-authored code, independent of whether
/// the workspace root itself is a valid, resolvable directory.
///
/// `VALID_WORKSPACE != TRUSTED_WORKSPACE`: a workspace can canonicalize and
/// resolve perfectly well while remaining `Untrusted` for execution
/// purposes. No Core contract lets a client request self-elevate this value;
/// only a later host/config/security layer may authorize `Trusted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum WorkspaceTrust {
    Untrusted,
    Trusted,
}

impl Default for WorkspaceTrust {
    /// The default is always `Untrusted` -- trust is never inferred or
    /// self-declared.
    fn default() -> Self {
        Self::Untrusted
    }
}

/// A resolver's report for one workspace source: where the candidate came
/// from, what happened while resolving it, and -- only when resolution
/// actually selected a workspace -- its identity and trust.
///
/// Fields are private and only constructible through [`Self::new`], which
/// enforces the invariant that `identity`/`trust` are present if and only if
/// `status` is [`WorkspaceResolutionStatus::Selected`] -- this makes the
/// otherwise-representable illegal state (`Selected` with no identity, or
/// `Absent` with an identity) unreachable through the public API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkspaceResolutionSummary {
    source: WorkspaceSourceKind,
    status: WorkspaceResolutionStatus,
    identity: Option<WorkspaceIdentity>,
    trust: Option<WorkspaceTrust>,
}

impl WorkspaceResolutionSummary {
    pub fn new(
        source: WorkspaceSourceKind,
        status: WorkspaceResolutionStatus,
        identity: Option<WorkspaceIdentity>,
        trust: Option<WorkspaceTrust>,
    ) -> CorulixResult<Self> {
        let selected = matches!(status, WorkspaceResolutionStatus::Selected);
        let carries_selection_data = identity.is_some() && trust.is_some();
        let carries_no_selection_data = identity.is_none() && trust.is_none();
        if selected && !carries_selection_data {
            return Err(CorulixError::InvalidInput(
                "a Selected workspace resolution summary must carry identity and trust".into(),
            ));
        }
        if !selected && !carries_no_selection_data {
            return Err(CorulixError::InvalidInput(
                "a non-Selected workspace resolution summary must not carry identity or trust"
                    .into(),
            ));
        }
        Ok(Self {
            source,
            status,
            identity,
            trust,
        })
    }

    pub fn source(&self) -> WorkspaceSourceKind {
        self.source
    }

    pub fn status(&self) -> WorkspaceResolutionStatus {
        self.status
    }

    pub fn identity(&self) -> Option<&WorkspaceIdentity> {
        self.identity.as_ref()
    }

    pub fn trust(&self) -> Option<WorkspaceTrust> {
        self.trust
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_identity_rejects_empty_token() {
        assert!(matches!(
            WorkspaceIdentity::from_opaque_token(String::new()),
            Err(CorulixError::InvalidInput(_))
        ));
    }

    #[test]
    fn workspace_identity_accepts_nonempty_token() -> CorulixResult<()> {
        let identity = WorkspaceIdentity::from_opaque_token("wsid-abc123".to_string())?;
        assert_eq!(identity.as_opaque_token(), "wsid-abc123");
        Ok(())
    }

    #[test]
    fn workspace_trust_default_is_untrusted() {
        assert_eq!(WorkspaceTrust::default(), WorkspaceTrust::Untrusted);
    }

    #[test]
    fn source_kind_and_resolution_status_are_independent_axes() -> CorulixResult<()> {
        // The same source kind can coexist with every resolution status --
        // proving these are two separate axes, not one conflated concept.
        for status in [
            WorkspaceResolutionStatus::Absent,
            WorkspaceResolutionStatus::Invalid,
            WorkspaceResolutionStatus::Ambiguous,
            WorkspaceResolutionStatus::Exhausted,
        ] {
            let summary = WorkspaceResolutionSummary::new(
                WorkspaceSourceKind::ExplicitFlag,
                status,
                None,
                None,
            )?;
            assert_eq!(summary.status(), status);
            assert_eq!(summary.source(), WorkspaceSourceKind::ExplicitFlag);
        }
        Ok(())
    }

    #[test]
    fn selected_without_identity_and_trust_is_rejected() {
        assert!(
            WorkspaceResolutionSummary::new(
                WorkspaceSourceKind::Environment,
                WorkspaceResolutionStatus::Selected,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn non_selected_with_identity_is_rejected() -> CorulixResult<()> {
        let identity = WorkspaceIdentity::from_opaque_token("wsid-xyz".to_string())?;
        assert!(
            WorkspaceResolutionSummary::new(
                WorkspaceSourceKind::Environment,
                WorkspaceResolutionStatus::Absent,
                Some(identity),
                Some(WorkspaceTrust::Untrusted),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn selected_with_identity_and_trust_succeeds() -> CorulixResult<()> {
        let identity = WorkspaceIdentity::from_opaque_token("wsid-ok".to_string())?;
        let summary = WorkspaceResolutionSummary::new(
            WorkspaceSourceKind::DiscoverySeeded,
            WorkspaceResolutionStatus::Selected,
            Some(identity.clone()),
            Some(WorkspaceTrust::Untrusted),
        )?;
        assert_eq!(summary.identity(), Some(&identity));
        assert_eq!(summary.trust(), Some(WorkspaceTrust::Untrusted));
        Ok(())
    }
}
