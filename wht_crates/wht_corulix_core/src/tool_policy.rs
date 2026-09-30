// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Corulix 1.1.0: the single, canonical authority for the 14 MCP tool
//! names, the 6-member mutation-lifecycle family, and the pure semantic
//! rules a workspace-authored tool-exposure policy must satisfy.
//!
//! This module is deliberately the *only* place these 14 names, the 6
//! mutation-family names, and their dependency rules are declared anywhere
//! in this workspace (ADR 0012). The config-file validation layer, the
//! `config schema` CLI's emitted enum, and the transport layer's own
//! server-construction/tool-declaration count (checked by
//! `wht_scripts/wht_verify_architecture.py` Rule S) all consume this
//! authority; none of them may declare a second literal copy of the
//! tool-name list.
//!
//! Per Architecture Rule A this module performs no filesystem I/O, spawns
//! no process, and depends on no transport-protocol or JSON-RPC type -- it
//! is pure, protocol-agnostic validation logic over plain strings.

use std::collections::BTreeSet;

use thiserror::Error;

/// The 14 canonical, compile-time-declared MCP tool names -- must always
/// match, byte-for-byte, the 14 `#[tool(...)]`-annotated method names the
/// transport layer declares (cross-checked by a dedicated test there; see
/// `TOOL-016` in the 1.1.0 implementation plan).
pub const CANONICAL_MCP_TOOL_NAMES: [&str; 14] = [
    "runtime_identity",
    "workspace_info",
    "toolchain_status",
    "plan_operation",
    "search",
    "parse_file",
    "semantic",
    "format_preview",
    "begin_change",
    "submit_edit",
    "validate_change",
    "change_status",
    "complete_change",
    "abort_change",
];

/// The 6 tools that make up the governed mutation lifecycle. `begin_change`
/// is the family head: per [`ToolPolicyValidationError::MutationFamilyIncomplete`],
/// disabling it requires disabling every other member of this set too.
pub const MUTATION_FAMILY_MCP_TOOL_NAMES: [&str; 6] = [
    "begin_change",
    "submit_edit",
    "validate_change",
    "change_status",
    "complete_change",
    "abort_change",
];

/// Every way a workspace-authored `toolPolicy.disabledTools` list can fail
/// semantic validation. `#[non_exhaustive]` from its first release (this
/// crate's own established convention, see [`crate::CorulixError`]) so a
/// future variant is never itself a SemVer break for a downstream matcher.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ToolPolicyValidationError {
    /// A name in `disabledTools` does not match any of the
    /// [`CANONICAL_MCP_TOOL_NAMES`], byte-for-byte. Never silently ignored --
    /// a typo in a security-relevant deny-list must be a hard error.
    #[error("unknown tool name in tool policy: {0}")]
    UnknownToolName(String),
    /// The same tool name appeared more than once in `disabledTools`. Never
    /// silently deduplicated -- a config author who wrote a duplicate almost
    /// certainly made a mistake.
    #[error("duplicate tool name in tool policy: {0}")]
    DuplicateToolInPolicy(String),
    /// `begin_change` is disabled while one or more of the 5 downstream
    /// mutation-lifecycle tools remain enabled -- a misleading capability
    /// advertisement (those tools would be permanently `SessionNotFound`,
    /// since no session could ever exist to operate on). Carries every tool
    /// name left enabled.
    #[error("begin_change disabled while downstream mutation tool(s) remain enabled: {0:?}")]
    MutationFamilyIncomplete(Vec<&'static str>),
    /// `complete_change` is enabled while `validate_change` is disabled --
    /// advertises a commit path whose safe precondition (checking gate
    /// status before attempting completion) is unobservable to the caller.
    #[error("complete_change enabled without validate_change visible")]
    UnsafeMutationWithoutGateVisibility,
    /// `submit_edit` is enabled while `begin_change`, `validate_change`, or
    /// `complete_change` is not -- would allow a workspace mutation to occur
    /// with no visible, governed path to validated completion (abort is
    /// terminal and never auto-restores edited bytes).
    #[error("submit_edit enabled without a visible validation/completion path")]
    UnsafeEditWithoutCompletionPath,
    /// Every one of the 14 canonical tools was named in `disabledTools`, and
    /// the real MCP runtime this policy would be enforced under does not
    /// support an empty tool catalog (Phase D's empirical protocol probe,
    /// frozen once and reused thereafter -- never re-guessed per policy).
    #[error("all 14 canonical tools disabled, which the current MCP runtime does not support")]
    EmptyToolCatalogUnsupported,
}

/// The immutable, validated result of resolving a workspace's
/// `toolPolicy.disabledTools` against [`CANONICAL_MCP_TOOL_NAMES`] and the
/// static lifecycle rules in [`validate_tool_policy`]. Always a subset of
/// the canonical 14 -- this type has no constructor that could ever name a
/// 15th tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveToolSet {
    disabled: BTreeSet<&'static str>,
}

impl EffectiveToolSet {
    /// The default, no-workspace-policy-configured set: all 14 canonical
    /// tools enabled. This is Corulix 1.1.0's exact 1.0.0-compatible
    /// behavior when no `WhaTalker_Corulix_JSON_Config.json` is present, or
    /// its `toolPolicy` section is absent/empty.
    #[must_use]
    pub fn all_enabled() -> Self {
        Self {
            disabled: BTreeSet::new(),
        }
    }

    /// `true` if `name` is present and not disabled by this set. An
    /// unrecognized name (not one of the canonical 14) is treated as not
    /// enabled -- this method is never the authority for "is this a real
    /// tool name," only for "is this canonical tool currently visible."
    #[must_use]
    pub fn is_enabled(&self, name: &str) -> bool {
        CANONICAL_MCP_TOOL_NAMES.contains(&name) && !self.disabled.contains(name)
    }

    /// Every canonical tool name this set disables, in canonical-catalog
    /// iteration order. Consumed by the transport layer's own effective
    /// router construction -- never exposed directly over the wire
    /// (`workspace_info`'s introspection fields are count-only by design,
    /// see the 1.1.0 plan's Section 6.F).
    pub fn disabled_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        CANONICAL_MCP_TOOL_NAMES
            .iter()
            .copied()
            .filter(move |name| self.disabled.contains(name))
    }

    /// Always `14` -- the compile-time-declared canonical count
    /// (`wht_scripts/wht_verify_architecture.py` Rule S's own invariant),
    /// independent of any workspace policy.
    #[must_use]
    pub fn canonical_tool_count() -> u32 {
        u32::try_from(CANONICAL_MCP_TOOL_NAMES.len()).unwrap_or(u32::MAX)
    }

    /// `canonical_tool_count() - disabled().len()`, always `0..=14`.
    #[must_use]
    pub fn effective_visible_tool_count(&self) -> u32 {
        Self::canonical_tool_count() - u32::try_from(self.disabled.len()).unwrap_or(0)
    }

    /// `true` if this set disables at least one canonical tool -- i.e. a
    /// non-default, workspace-authored policy is in effect.
    #[must_use]
    pub fn is_reduced(&self) -> bool {
        !self.disabled.is_empty()
    }
}

/// Validates a workspace-authored `toolPolicy.disabledTools` list against
/// [`CANONICAL_MCP_TOOL_NAMES`] and the static lifecycle rules, returning an
/// immutable [`EffectiveToolSet`] on success.
///
/// `empty_catalog_supported` is Phase D's own empirically-determined,
/// frozen answer to "does the real, admitted MCP SDK/protocol permit a
/// zero-tool `tools/list` response" -- this function never guesses it and
/// never re-derives it per call; the caller supplies the one, already-proven
/// answer every time.
///
/// This is the **single** semantic authority `corulix config validate`,
/// `corulix config inspect`, and `CorulixMcpServer` construction all call --
/// none of them may reimplement any part of this logic separately (the
/// invariant this exists to guarantee: `config validate` must never report
/// PASS for a policy that MCP construction would later refuse).
///
/// # Errors
///
/// Returns the first applicable [`ToolPolicyValidationError`], checked in a
/// fixed order: unknown name, duplicate name, mutation-family completeness
/// (D.1), gate visibility (D.2), edit-closure (D.3), then the empty-catalog
/// protocol constraint (D.5) -- this order is itself part of the contract
/// (an unknown/duplicate name is always reported before any deeper semantic
/// rule, since a semantic check over an unresolved name would be
/// meaningless).
pub fn validate_tool_policy(
    disabled_tools: &[String],
    empty_catalog_supported: bool,
) -> Result<EffectiveToolSet, ToolPolicyValidationError> {
    let mut seen_authored: BTreeSet<&str> = BTreeSet::new();
    for name in disabled_tools {
        if !seen_authored.insert(name.as_str()) {
            return Err(ToolPolicyValidationError::DuplicateToolInPolicy(
                name.clone(),
            ));
        }
    }

    let mut disabled: BTreeSet<&'static str> = BTreeSet::new();
    for name in disabled_tools {
        let canonical = CANONICAL_MCP_TOOL_NAMES
            .iter()
            .find(|candidate| **candidate == name.as_str())
            .ok_or_else(|| ToolPolicyValidationError::UnknownToolName(name.clone()))?;
        disabled.insert(canonical);
    }

    let enabled = |name: &str| -> bool { !disabled.contains(name) };

    // D.1 -- mutation-family head: begin_change disabled forces every
    // downstream lifecycle tool disabled too.
    if !enabled("begin_change") {
        let still_enabled: Vec<&'static str> = MUTATION_FAMILY_MCP_TOOL_NAMES
            .iter()
            .copied()
            .filter(|name| *name != "begin_change" && enabled(name))
            .collect();
        if !still_enabled.is_empty() {
            return Err(ToolPolicyValidationError::MutationFamilyIncomplete(
                still_enabled,
            ));
        }
    }

    // D.2 -- completion gate visibility. (begin_change is already guaranteed
    // enabled here whenever complete_change is enabled, by D.1 above --
    // checked again explicitly below for defense-in-depth, not because D.1
    // could have let it through.)
    if enabled("complete_change") && (!enabled("validate_change") || !enabled("begin_change")) {
        return Err(ToolPolicyValidationError::UnsafeMutationWithoutGateVisibility);
    }

    // D.3 -- edit closure. (Also already guaranteed by D.1/D.2 in every
    // reachable case; stated explicitly because it is its own named,
    // independently-tested rule per the approved plan.)
    if enabled("submit_edit")
        && !(enabled("begin_change") && enabled("validate_change") && enabled("complete_change"))
    {
        return Err(ToolPolicyValidationError::UnsafeEditWithoutCompletionPath);
    }

    // D.5 -- empty-catalog protocol constraint.
    if disabled.len() == CANONICAL_MCP_TOOL_NAMES.len() && !empty_catalog_supported {
        return Err(ToolPolicyValidationError::EmptyToolCatalogUnsupported);
    }

    Ok(EffectiveToolSet { disabled })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn canonical_catalog_has_exactly_14_unique_names() {
        assert_eq!(CANONICAL_MCP_TOOL_NAMES.len(), 14);
        let unique: BTreeSet<&str> = CANONICAL_MCP_TOOL_NAMES.iter().copied().collect();
        assert_eq!(unique.len(), 14);
    }

    #[test]
    fn mutation_family_is_exactly_6_and_subset_of_canonical() {
        assert_eq!(MUTATION_FAMILY_MCP_TOOL_NAMES.len(), 6);
        for name in MUTATION_FAMILY_MCP_TOOL_NAMES {
            assert!(CANONICAL_MCP_TOOL_NAMES.contains(&name));
        }
    }

    #[test]
    fn empty_policy_is_all_enabled() -> Result<(), ToolPolicyValidationError> {
        let effective = validate_tool_policy(&[], false)?;
        assert_eq!(effective, EffectiveToolSet::all_enabled());
        assert_eq!(effective.effective_visible_tool_count(), 14);
        assert!(!effective.is_reduced());
        for name in CANONICAL_MCP_TOOL_NAMES {
            assert!(effective.is_enabled(name));
        }
        Ok(())
    }

    #[test]
    fn unknown_tool_name_is_rejected() {
        let result = validate_tool_policy(&names(&["delete_repo"]), false);
        assert_eq!(
            result,
            Err(ToolPolicyValidationError::UnknownToolName(
                "delete_repo".to_string()
            ))
        );
    }

    #[test]
    fn duplicate_tool_name_is_rejected() {
        let result = validate_tool_policy(&names(&["search", "search"]), false);
        assert_eq!(
            result,
            Err(ToolPolicyValidationError::DuplicateToolInPolicy(
                "search".to_string()
            ))
        );
    }

    #[test]
    fn valid_reduced_set_disables_only_named_tools() -> Result<(), ToolPolicyValidationError> {
        let effective = validate_tool_policy(&names(&["semantic", "format_preview"]), false)?;
        assert!(!effective.is_enabled("semantic"));
        assert!(!effective.is_enabled("format_preview"));
        assert!(effective.is_enabled("search"));
        assert_eq!(effective.effective_visible_tool_count(), 12);
        assert_eq!(
            effective.disabled_names().collect::<Vec<_>>(),
            vec!["semantic", "format_preview"]
        );
        Ok(())
    }

    #[test]
    fn runtime_identity_and_workspace_info_are_individually_disableable()
    -> Result<(), ToolPolicyValidationError> {
        let effective =
            validate_tool_policy(&names(&["runtime_identity", "workspace_info"]), false)?;
        assert!(!effective.is_enabled("runtime_identity"));
        assert!(!effective.is_enabled("workspace_info"));
        assert_eq!(effective.effective_visible_tool_count(), 12);
        Ok(())
    }

    #[test]
    fn begin_change_disabled_alone_fails_mutation_family_incomplete() {
        let result = validate_tool_policy(&names(&["begin_change"]), false);
        assert!(matches!(
            result,
            Err(ToolPolicyValidationError::MutationFamilyIncomplete(_))
        ));
        if let Err(ToolPolicyValidationError::MutationFamilyIncomplete(still_enabled)) = result {
            assert_eq!(
                still_enabled,
                vec![
                    "submit_edit",
                    "validate_change",
                    "change_status",
                    "complete_change",
                    "abort_change"
                ]
            );
        }
    }

    #[test]
    fn all_six_mutation_tools_disabled_together_is_the_read_only_mode()
    -> Result<(), ToolPolicyValidationError> {
        let effective = validate_tool_policy(
            &names(&[
                "begin_change",
                "submit_edit",
                "validate_change",
                "change_status",
                "complete_change",
                "abort_change",
            ]),
            false,
        )?;
        assert_eq!(effective.effective_visible_tool_count(), 8);
        for name in MUTATION_FAMILY_MCP_TOOL_NAMES {
            assert!(!effective.is_enabled(name));
        }
        Ok(())
    }

    #[test]
    fn complete_change_without_validate_change_fails_gate_visibility() {
        let result = validate_tool_policy(&names(&["validate_change"]), false);
        assert!(matches!(
            result,
            Err(ToolPolicyValidationError::UnsafeMutationWithoutGateVisibility)
        ));
    }

    #[test]
    fn submit_edit_without_completion_path_fails_edit_closure() {
        let result = validate_tool_policy(&names(&["validate_change", "complete_change"]), false);
        assert!(matches!(
            result,
            Err(ToolPolicyValidationError::UnsafeEditWithoutCompletionPath)
        ));
    }

    #[test]
    fn all_14_disabled_rejected_when_empty_catalog_unsupported() {
        let all: Vec<String> = CANONICAL_MCP_TOOL_NAMES
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        let result = validate_tool_policy(&all, false);
        assert_eq!(
            result,
            Err(ToolPolicyValidationError::EmptyToolCatalogUnsupported)
        );
    }

    #[test]
    fn all_14_disabled_accepted_when_empty_catalog_supported()
    -> Result<(), ToolPolicyValidationError> {
        let all: Vec<String> = CANONICAL_MCP_TOOL_NAMES
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        let effective = validate_tool_policy(&all, true)?;
        assert_eq!(effective.effective_visible_tool_count(), 0);
        Ok(())
    }
}
