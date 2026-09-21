// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The fixed, deterministic policy table: one auditable entry per
//! [`OperationIntent`], and the pure risk-derivation function.
//!
//! Architecture Rule H: this module, and this crate, are the sole place a
//! `RiskClass` or a gate/tool-requirement list may be *derived* for a
//! concrete operation. Every entry below is `const` data checked in at
//! compile time -- there is no discovery-order dependency, no random
//! selection, no AI/LLM routing, and no runtime table mutation. The same
//! `(OperationIntent, TargetScope)` pair always produces the same
//! `PolicyEntry`/risk output.

use wht_corulix_core::{
    AuthorityRole, GateApplicability, GateId, GateRequirement, MutationKind, OperationIntent,
    ProviderCategory, RiskClass, ToolApplicability, ToolRequirement,
};

/// The size (single- vs multi-root, and how many roots) of the workspace an
/// operation targets. Derived from `wht_corulix_workspace::WorkspaceContext`
/// by the caller (see `CorulixEngine::plan_operation`) -- this module has no
/// filesystem/workspace dependency of its own, keeping risk derivation a
/// pure function of already-resolved facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetScope {
    SingleRoot,
    MultiRoot { root_count: usize },
}

/// One immutable policy entry: what an [`OperationIntent`] means in terms of
/// mutation shape, baseline risk, required/optional/supporting tool
/// categories (with their authority), and the ordered gate subset it
/// requires.
///
/// `gates` is deliberately independent of provider availability: nothing in
/// this type, and nothing in [`crate::routing`], removes or downgrades a
/// gate because the provider behind it happens to be unavailable right now
/// -- that is the exact "required gate never disappears" invariant the
/// mandate requires, enforced here simply by never touching `gates` when
/// computing [`crate::routing`]'s executability verdict.
#[derive(Debug, Clone, Copy)]
pub struct PolicyEntry {
    pub mutation_kind: MutationKind,
    pub base_risk: RiskClass,
    pub requirements: &'static [ToolRequirement],
    pub gates: &'static [GateRequirement],
}

const fn req(
    category: ProviderCategory,
    applicability: ToolApplicability,
    authority: AuthorityRole,
) -> ToolRequirement {
    ToolRequirement {
        category,
        applicability,
        authority,
    }
}

const fn gate(gate: GateId, applicability: GateApplicability) -> GateRequirement {
    GateRequirement {
        gate,
        applicability,
    }
}

const NO_REQUIREMENTS: &[ToolRequirement] = &[];

const TEXT_SEARCH: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::None,
    base_risk: RiskClass::Low,
    requirements: &[req(
        ProviderCategory::TextSearch,
        ToolApplicability::Required,
        AuthorityRole::Authoritative,
    )],
    gates: &[gate(GateId::Discovery, GateApplicability::Required)],
};

const FILE_DISCOVERY: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::None,
    base_risk: RiskClass::Low,
    // Pure `wht_corulix_workspace` traversal -- no `ProviderCategory` models
    // Workspace itself, since filesystem enumeration is not a pluggable
    // provider in the Rule H sense.
    requirements: NO_REQUIREMENTS,
    gates: &[gate(GateId::Discovery, GateApplicability::Required)],
};

const STRUCTURAL_INSPECTION: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::None,
    base_risk: RiskClass::Low,
    requirements: &[req(
        ProviderCategory::StructuralParse,
        ToolApplicability::Required,
        AuthorityRole::Authoritative,
    )],
    gates: &[gate(GateId::Discovery, GateApplicability::Required)],
};

const STRUCTURAL_SEARCH: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::None,
    base_risk: RiskClass::Low,
    requirements: &[
        req(
            ProviderCategory::StructuralParse,
            ToolApplicability::Required,
            AuthorityRole::Authoritative,
        ),
        // Text search may narrow candidates but never itself close a
        // structural-authority gate.
        req(
            ProviderCategory::TextSearch,
            ToolApplicability::Supporting,
            AuthorityRole::ForbiddenAsAuthority,
        ),
    ],
    gates: &[gate(GateId::Discovery, GateApplicability::Required)],
};

const SEMANTIC_DEFINITION: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::None,
    base_risk: RiskClass::Elevated,
    requirements: &[
        req(
            ProviderCategory::LanguageServer,
            ToolApplicability::Required,
            AuthorityRole::Authoritative,
        ),
        // Neither Search nor Syntax may pretend to be LSP for a semantic
        // operation: both participate as supporting evidence only, and both
        // are explicitly forbidden from ever closing the semantic-authority
        // gate themselves.
        req(
            ProviderCategory::StructuralParse,
            ToolApplicability::Supporting,
            AuthorityRole::ForbiddenAsAuthority,
        ),
        req(
            ProviderCategory::TextSearch,
            ToolApplicability::Supporting,
            AuthorityRole::ForbiddenAsAuthority,
        ),
    ],
    gates: &[
        gate(GateId::Discovery, GateApplicability::Required),
        gate(GateId::SemanticConfirm, GateApplicability::Required),
    ],
};

const SEMANTIC_REFERENCES: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::None,
    base_risk: RiskClass::Elevated,
    requirements: &[
        req(
            ProviderCategory::LanguageServer,
            ToolApplicability::Required,
            AuthorityRole::Authoritative,
        ),
        // The mandate's own worked example: both Search and Syntax
        // participate as supporting evidence only, and neither can ever
        // become the authority for a semantic-references answer.
        req(
            ProviderCategory::TextSearch,
            ToolApplicability::Supporting,
            AuthorityRole::ForbiddenAsAuthority,
        ),
        req(
            ProviderCategory::StructuralParse,
            ToolApplicability::Supporting,
            AuthorityRole::ForbiddenAsAuthority,
        ),
    ],
    gates: &[
        gate(GateId::Discovery, GateApplicability::Required),
        gate(GateId::SemanticConfirm, GateApplicability::Required),
    ],
};

/// Live LSP diagnostics for one file (Phase 13's `semantic.diagnostics`
/// variant) -- distinct from `gate.diagnostics`'s `cargo check`/clippy
/// evidence inside a `ChangeSession`: this is a stateless, read-only query
/// against rust-analyzer's own live diagnostic set, never itself a gate
/// closure. Same authority shape as `SEMANTIC_DEFINITION`/
/// `SEMANTIC_REFERENCES`: LSP is the sole authority, Search/Syntax are
/// forbidden-as-authority supporting evidence only.
const SEMANTIC_DIAGNOSTICS: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::None,
    base_risk: RiskClass::Elevated,
    requirements: &[
        req(
            ProviderCategory::LanguageServer,
            ToolApplicability::Required,
            AuthorityRole::Authoritative,
        ),
        req(
            ProviderCategory::StructuralParse,
            ToolApplicability::Supporting,
            AuthorityRole::ForbiddenAsAuthority,
        ),
        req(
            ProviderCategory::TextSearch,
            ToolApplicability::Supporting,
            AuthorityRole::ForbiddenAsAuthority,
        ),
    ],
    gates: &[
        gate(GateId::Discovery, GateApplicability::Required),
        gate(GateId::SemanticConfirm, GateApplicability::Required),
    ],
};

const SEMANTIC_RENAME: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::SemanticRename,
    base_risk: RiskClass::High,
    requirements: &[
        req(
            ProviderCategory::LanguageServer,
            ToolApplicability::Required,
            AuthorityRole::Authoritative,
        ),
        req(
            ProviderCategory::Formatter,
            ToolApplicability::Required,
            AuthorityRole::SupportingOnly,
        ),
        // P11 Minimum Sufficient Tooling: `High` risk requires the stronger
        // `cargo check` build-graph authority in addition to LSP's own
        // semantic diagnostics, plus lint evidence as supporting-only --
        // deliberately a wider validator set than `SOURCE_CREATE`/
        // `SOURCE_MODIFY`'s `Elevated`-tier optional `TypecheckBuild` alone,
        // proving risk-strengthening rather than a flat validator set.
        req(
            ProviderCategory::TypecheckBuild,
            ToolApplicability::Required,
            AuthorityRole::Authoritative,
        ),
        req(
            ProviderCategory::Linter,
            ToolApplicability::Required,
            AuthorityRole::SupportingOnly,
        ),
    ],
    gates: &[
        gate(GateId::Discovery, GateApplicability::Required),
        gate(GateId::SemanticConfirm, GateApplicability::Required),
        gate(GateId::Edit, GateApplicability::Required),
        gate(GateId::Format, GateApplicability::Required),
        gate(GateId::Diagnostics, GateApplicability::Required),
        gate(GateId::PostAudit, GateApplicability::Required),
    ],
};

const SOURCE_CREATE: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::Create,
    base_risk: RiskClass::Elevated,
    requirements: &[
        req(
            ProviderCategory::Formatter,
            ToolApplicability::Required,
            AuthorityRole::SupportingOnly,
        ),
        // P11: closes a real unclosable-optional-gate defect Phase 11's own
        // discovery found -- before this entry existed, `gate.diagnostics`
        // below was `Optional` with *no* non-forbidden authority wired for
        // it at all, so a caller could never legitimately close it even
        // when it wanted to. `cargo check` (`TypecheckBuild`) is the
        // Minimum Sufficient Tooling choice for this risk tier: fast,
        // authoritative Rust type/build-graph validation, without the
        // heavier lint pass `SEMANTIC_RENAME`/`SOURCE_REFACTOR` require
        // below at their higher risk tier.
        req(
            ProviderCategory::TypecheckBuild,
            ToolApplicability::Optional,
            AuthorityRole::Authoritative,
        ),
    ],
    gates: &[
        gate(GateId::Edit, GateApplicability::Required),
        gate(GateId::Format, GateApplicability::Required),
        gate(GateId::Diagnostics, GateApplicability::Optional),
    ],
};

const SOURCE_MODIFY: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::Modify,
    base_risk: RiskClass::Elevated,
    requirements: &[
        req(
            ProviderCategory::Formatter,
            ToolApplicability::Required,
            AuthorityRole::SupportingOnly,
        ),
        // Same P11 fix, same reasoning, as `SOURCE_CREATE` above.
        req(
            ProviderCategory::TypecheckBuild,
            ToolApplicability::Optional,
            AuthorityRole::Authoritative,
        ),
    ],
    gates: &[
        gate(GateId::Edit, GateApplicability::Required),
        gate(GateId::Format, GateApplicability::Required),
        gate(GateId::Diagnostics, GateApplicability::Optional),
    ],
};

const SOURCE_DELETE: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::Delete,
    base_risk: RiskClass::High,
    // F3 fix (`SOURCE_DELETE_COMMITTED_UNCOMPLETABLE_STATE`): before this
    // requirement existed, this entry's `requirements` was `NO_REQUIREMENTS`
    // -- an empty list -- while `gate.post_audit` below is `Required`. That
    // combination made `gate.post_audit` structurally unclosable: Engine's
    // `ChangeSession::requirement_authority` returns `None` for every
    // category against an empty requirements list, and
    // `ChangeSession::record_evidence` treats `None` identically to
    // `AuthorityRole::ForbiddenAsAuthority` (denies with
    // `EvidenceForbiddenAsAuthority`) -- so no category could ever have
    // closed this gate, regardless of what Evidence a caller obtained.
    // `TextSearch` is the real, already-`AVAILABLE`, in-process authority
    // `CorulixEngine::validate_change`'s new delete-kind post-audit path
    // uses to prove no other in-scope file still references the deleted
    // path's text -- see `crate::validate_change`'s own module doc for the
    // full real-audit design this requirement makes closable.
    requirements: &[req(
        ProviderCategory::TextSearch,
        ToolApplicability::Required,
        AuthorityRole::Authoritative,
    )],
    gates: &[
        gate(GateId::Edit, GateApplicability::Required),
        gate(GateId::PostAudit, GateApplicability::Required),
    ],
};

const SOURCE_MOVE: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::Move,
    base_risk: RiskClass::High,
    // This entry shares `SOURCE_DELETE`'s pre-F3 defect shape exactly (an
    // empty `requirements` list against a `Required` `gate.post_audit`
    // structurally unclosable by any category). It is deliberately left
    // unfixed this pass: `submit_edit`'s public MCP schema
    // (`EditRequestParams`) exposes only `create`/`replace`/`delete`, never
    // `MoveFile` -- there is no live-reachable way to commit a `SOURCE_MOVE`
    // mutation through the current 14-tool surface at all, so a real
    // post-audit design for it cannot be built or proven today without
    // inventing a wire contract this pass's mandate does not authorize.
    requirements: NO_REQUIREMENTS,
    gates: &[
        gate(GateId::Edit, GateApplicability::Required),
        gate(GateId::PostAudit, GateApplicability::Required),
    ],
};

const SOURCE_REFACTOR: PolicyEntry = PolicyEntry {
    // No dedicated `MutationKind::Refactor` variant exists in Core (Phase 1
    // deliberately did not add one); a refactor is, at the mutation-taxonomy
    // level, a (possibly multi-file) `Modify` -- its broader blast radius is
    // expressed through `base_risk` and the mandatory post-audit gate below,
    // not through a separate `MutationKind`.
    mutation_kind: MutationKind::Modify,
    base_risk: RiskClass::Critical,
    requirements: &[
        req(
            ProviderCategory::LanguageServer,
            ToolApplicability::Required,
            AuthorityRole::Authoritative,
        ),
        // Real defect found and fixed by Phase 10 (`ChangeSession` +
        // Evidence + gate state machine): before this requirement existed,
        // `gate.discovery` above was `Required` with no `ToolRequirement`
        // whose `AuthorityRole` was not `ForbiddenAsAuthority` -- no
        // Evidence could ever legitimately close it, an unclosable-gate
        // defect invisible until Phase 10 first enforced real gate-
        // closability against requirement authority. `SupportingOnly`
        // mirrors `Formatter`'s own role in this same entry: RG-found
        // candidate call sites support discovery for a refactor, but never
        // substitute for rust-analyzer's own semantic authority.
        req(
            ProviderCategory::TextSearch,
            ToolApplicability::Required,
            AuthorityRole::SupportingOnly,
        ),
        req(
            ProviderCategory::Formatter,
            ToolApplicability::Required,
            AuthorityRole::SupportingOnly,
        ),
        // P11 Minimum Sufficient Tooling, same reasoning as `SEMANTIC_RENAME`
        // above: `Critical` risk requires `cargo check` authority plus
        // supporting lint evidence, on top of LSP's semantic confirmation.
        req(
            ProviderCategory::TypecheckBuild,
            ToolApplicability::Required,
            AuthorityRole::Authoritative,
        ),
        req(
            ProviderCategory::Linter,
            ToolApplicability::Required,
            AuthorityRole::SupportingOnly,
        ),
    ],
    gates: &[
        gate(GateId::Discovery, GateApplicability::Required),
        gate(GateId::SemanticConfirm, GateApplicability::Required),
        gate(GateId::Edit, GateApplicability::Required),
        gate(GateId::Format, GateApplicability::Required),
        gate(GateId::Diagnostics, GateApplicability::Required),
        gate(GateId::PostAudit, GateApplicability::Required),
    ],
};

const CONFIG_MODIFY: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::Configuration,
    base_risk: RiskClass::Elevated,
    requirements: NO_REQUIREMENTS,
    gates: &[
        gate(GateId::Edit, GateApplicability::Required),
        gate(GateId::PostAudit, GateApplicability::Optional),
    ],
};

const DOCUMENTATION_MODIFY: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::Documentation,
    base_risk: RiskClass::Low,
    requirements: NO_REQUIREMENTS,
    gates: &[gate(GateId::Edit, GateApplicability::Required)],
};

const VALIDATE_CHANGE: PolicyEntry = PolicyEntry {
    mutation_kind: MutationKind::None,
    base_risk: RiskClass::Elevated,
    requirements: &[
        req(
            ProviderCategory::TypecheckBuild,
            ToolApplicability::Required,
            AuthorityRole::Authoritative,
        ),
        // P12: `TestRunner` is the real authority for `gate.tests` -- it was
        // `SupportingOnly` here before P12, meaning `gate.tests` (Optional
        // below) could never actually be legitimately closed by anything,
        // the same unclosable-gate defect class P11 found and closed for
        // `Linter`/`TypecheckBuild`. `Optional` applicability is unchanged
        // (Minimum Sufficient Tooling: no `OperationIntent` requires tests
        // today, and P12 does not invent one -- see `crate::testing`'s own
        // doc comment), but the category can now genuinely close the gate
        // when a caller runs real `cargo test` Evidence through it.
        req(
            ProviderCategory::TestRunner,
            ToolApplicability::Optional,
            AuthorityRole::Authoritative,
        ),
        req(
            ProviderCategory::LanguageServer,
            ToolApplicability::Optional,
            AuthorityRole::SupportingOnly,
        ),
        // P11: clippy supplements `cargo check`'s authoritative diagnostics
        // with lint evidence, but never substitutes for it -- `Optional`
        // applicability (an unavailable managed clippy must not block an
        // otherwise-passing `cargo check`) and `SupportingOnly` authority
        // (clippy alone can never close `gate.diagnostics`).
        req(
            ProviderCategory::Linter,
            ToolApplicability::Optional,
            AuthorityRole::SupportingOnly,
        ),
    ],
    gates: &[
        gate(GateId::Diagnostics, GateApplicability::Required),
        gate(GateId::Tests, GateApplicability::Optional),
    ],
};

/// The auditable, exhaustive policy table. Every one of the 15 *canonical*
/// [`OperationIntent`] variants has exactly one named arm -- none of them
/// falls through to a wildcard or shares another intent's entry.
///
/// A trailing `_ => None` arm is present only because `OperationIntent` is
/// declared `#[non_exhaustive]` in `wht_corulix_core` specifically so a
/// future phase can add a 16th variant there without an immediate breaking
/// change here; Rust's exhaustiveness checker requires *some* arm for that
/// hypothetical case when matching from a different crate, even though no
/// such variant exists today (there is no way to construct one, so this arm
/// is unreachable in every current test). Returning `None` -- rather than
/// aliasing the new variant to an existing entry -- is the fail-closed
/// choice: see [`crate::planning::plan_operation`], which turns `None` into
/// an unconditionally `Unexecutable` plan, never a silently-borrowed policy
/// from an unrelated intent.
#[must_use]
pub fn policy_entry(intent: OperationIntent) -> Option<PolicyEntry> {
    Some(match intent {
        OperationIntent::TextSearch => TEXT_SEARCH,
        OperationIntent::FileDiscovery => FILE_DISCOVERY,
        OperationIntent::StructuralInspection => STRUCTURAL_INSPECTION,
        OperationIntent::StructuralSearch => STRUCTURAL_SEARCH,
        OperationIntent::SemanticDefinition => SEMANTIC_DEFINITION,
        OperationIntent::SemanticReferences => SEMANTIC_REFERENCES,
        OperationIntent::SemanticDiagnostics => SEMANTIC_DIAGNOSTICS,
        OperationIntent::SemanticRename => SEMANTIC_RENAME,
        OperationIntent::SourceCreate => SOURCE_CREATE,
        OperationIntent::SourceModify => SOURCE_MODIFY,
        OperationIntent::SourceDelete => SOURCE_DELETE,
        OperationIntent::SourceMove => SOURCE_MOVE,
        OperationIntent::SourceRefactor => SOURCE_REFACTOR,
        OperationIntent::ConfigModify => CONFIG_MODIFY,
        OperationIntent::DocumentationModify => DOCUMENTATION_MODIFY,
        OperationIntent::ValidateChange => VALIDATE_CHANGE,
        _ => return None,
    })
}

/// Derives the final [`RiskClass`] for an operation from its policy baseline
/// and workspace scope -- the only two facts this phase's policy uses.
///
/// A `MultiRoot` scope raises risk by exactly one step (never more, never
/// fewer), saturating at [`RiskClass::Critical`] -- risk may only be raised
/// by scope, never lowered, and no caller-supplied value participates in
/// this computation (there is no parameter through which a client or
/// request DTO could inject an arbitrary `RiskClass`).
#[must_use]
pub fn derive_risk_class(base_risk: RiskClass, scope: TargetScope) -> RiskClass {
    match scope {
        TargetScope::SingleRoot => base_risk,
        TargetScope::MultiRoot { .. } => match base_risk {
            RiskClass::Low => RiskClass::Elevated,
            RiskClass::Elevated => RiskClass::High,
            RiskClass::High | RiskClass::Critical => RiskClass::Critical,
            // `RiskClass` is `#[non_exhaustive]`: a hypothetical future
            // variant this arm doesn't know the correct one-step bump for
            // saturates straight to `Critical` -- the fail-closed choice,
            // never a silent no-op that would leave a wider-scope operation
            // under-classified.
            _ => RiskClass::Critical,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use wht_corulix_core::{CorulixError, CorulixResult};

    #[test]
    fn every_operation_intent_has_exactly_one_policy_entry() {
        let mut seen = HashSet::new();
        for intent in OperationIntent::ALL {
            // Every *canonical* intent must resolve to `Some` -- only a
            // hypothetical, currently-unconstructable future variant would
            // ever see the `None` (Rule H fail-closed) branch.
            assert!(
                policy_entry(*intent).is_some(),
                "canonical intent {intent:?} has no policy entry"
            );
            assert!(seen.insert(*intent), "duplicate intent in ALL: {intent:?}");
        }
        assert_eq!(OperationIntent::ALL.len(), 16);
        assert_eq!(seen.len(), 16);
    }

    #[test]
    fn multi_root_scope_raises_risk_by_exactly_one_step() {
        assert_eq!(
            derive_risk_class(RiskClass::Low, TargetScope::MultiRoot { root_count: 2 }),
            RiskClass::Elevated
        );
        assert_eq!(
            derive_risk_class(RiskClass::High, TargetScope::MultiRoot { root_count: 2 }),
            RiskClass::Critical
        );
    }

    #[test]
    fn multi_root_scope_saturates_at_critical() {
        assert_eq!(
            derive_risk_class(
                RiskClass::Critical,
                TargetScope::MultiRoot { root_count: 5 }
            ),
            RiskClass::Critical
        );
    }

    #[test]
    fn single_root_scope_never_raises_risk() {
        for base in [
            RiskClass::Low,
            RiskClass::Elevated,
            RiskClass::High,
            RiskClass::Critical,
        ] {
            assert_eq!(derive_risk_class(base, TargetScope::SingleRoot), base);
        }
    }

    #[test]
    fn source_delete_move_and_refactor_require_post_audit() {
        for entry in [SOURCE_DELETE, SOURCE_MOVE, SOURCE_REFACTOR] {
            assert!(
                entry.gates.iter().any(|g| g.gate == GateId::PostAudit
                    && g.applicability == GateApplicability::Required)
            );
        }
    }

    #[test]
    fn any_source_mutation_requires_edit_gate() {
        for entry in [
            SOURCE_CREATE,
            SOURCE_MODIFY,
            SOURCE_DELETE,
            SOURCE_MOVE,
            SOURCE_REFACTOR,
            SEMANTIC_RENAME,
        ] {
            assert!(
                entry
                    .gates
                    .iter()
                    .any(|g| g.gate == GateId::Edit
                        && g.applicability == GateApplicability::Required)
            );
        }
    }

    fn find_requirement(
        entry: &PolicyEntry,
        category: ProviderCategory,
    ) -> CorulixResult<ToolRequirement> {
        entry
            .requirements
            .iter()
            .copied()
            .find(|r| r.category == category)
            .ok_or(CorulixError::Internal)
    }

    #[test]
    fn search_is_forbidden_as_authority_for_a_semantic_entry() -> CorulixResult<()> {
        for entry in [SEMANTIC_DEFINITION, SEMANTIC_REFERENCES] {
            let requirement = find_requirement(&entry, ProviderCategory::TextSearch)?;
            assert_eq!(requirement.authority, AuthorityRole::ForbiddenAsAuthority);
            assert_eq!(requirement.applicability, ToolApplicability::Supporting);
        }
        Ok(())
    }

    #[test]
    fn structural_parse_is_forbidden_as_authority_for_a_semantic_entry() -> CorulixResult<()> {
        for entry in [SEMANTIC_DEFINITION, SEMANTIC_REFERENCES] {
            let requirement = find_requirement(&entry, ProviderCategory::StructuralParse)?;
            assert_eq!(requirement.authority, AuthorityRole::ForbiddenAsAuthority);
            assert_eq!(requirement.applicability, ToolApplicability::Supporting);
        }
        Ok(())
    }

    #[test]
    fn search_is_authoritative_for_text_search() -> CorulixResult<()> {
        let requirement = find_requirement(&TEXT_SEARCH, ProviderCategory::TextSearch)?;
        assert_eq!(requirement.applicability, ToolApplicability::Required);
        assert_eq!(requirement.authority, AuthorityRole::Authoritative);
        Ok(())
    }

    #[test]
    fn syntax_is_authoritative_for_structural_operations() -> CorulixResult<()> {
        for entry in [STRUCTURAL_INSPECTION, STRUCTURAL_SEARCH] {
            let requirement = find_requirement(&entry, ProviderCategory::StructuralParse)?;
            assert_eq!(requirement.applicability, ToolApplicability::Required);
            assert_eq!(requirement.authority, AuthorityRole::Authoritative);
        }
        Ok(())
    }

    #[test]
    fn lsp_is_authoritative_for_every_semantic_operation() -> CorulixResult<()> {
        for entry in [SEMANTIC_DEFINITION, SEMANTIC_REFERENCES, SEMANTIC_RENAME] {
            let requirement = find_requirement(&entry, ProviderCategory::LanguageServer)?;
            assert_eq!(requirement.applicability, ToolApplicability::Required);
            assert_eq!(requirement.authority, AuthorityRole::Authoritative);
        }
        Ok(())
    }

    #[test]
    fn no_provider_pretends_to_be_another_for_any_policy_entry() -> CorulixResult<()> {
        // Structural invariant across the whole table: TextSearch and
        // StructuralParse may never be Authoritative wherever LanguageServer
        // is also Required -- i.e. neither Search nor Syntax ever closes a
        // gate that belongs to LSP's semantic authority.
        for intent in OperationIntent::ALL {
            let entry = policy_entry(*intent).ok_or(CorulixError::Internal)?;
            let has_required_lsp = entry.requirements.iter().any(|r| {
                r.category == ProviderCategory::LanguageServer
                    && r.applicability == ToolApplicability::Required
            });
            if !has_required_lsp {
                continue;
            }
            for requirement in entry.requirements {
                if requirement.category == ProviderCategory::TextSearch
                    || requirement.category == ProviderCategory::StructuralParse
                {
                    assert_ne!(
                        requirement.authority,
                        AuthorityRole::Authoritative,
                        "{:?}: {:?} must never be authoritative alongside a required LSP requirement",
                        intent,
                        requirement.category
                    );
                }
            }
        }
        Ok(())
    }

    /// P11: `ProviderCategory::Linter` (clippy) never closes a gate by
    /// itself anywhere in the table -- it only ever supplements an
    /// authoritative `TypecheckBuild`/`LanguageServer` requirement. Guards
    /// against a future edit silently promoting clippy to authority.
    #[test]
    fn linter_is_never_authoritative_anywhere_in_the_table() -> CorulixResult<()> {
        for intent in OperationIntent::ALL {
            let entry = policy_entry(*intent).ok_or(CorulixError::Internal)?;
            for requirement in entry.requirements {
                if requirement.category == ProviderCategory::Linter {
                    assert_eq!(
                        requirement.authority,
                        AuthorityRole::SupportingOnly,
                        "{intent:?}: Linter must never be Authoritative"
                    );
                }
            }
        }
        Ok(())
    }

    /// P11: every entry whose `gate.diagnostics` applicability is `Required`
    /// or `Optional` has *some* non-`ForbiddenAsAuthority` requirement that
    /// could close it. Before P11, `SOURCE_CREATE`/`SOURCE_MODIFY` failed
    /// this invariant silently (an `Optional` gate with zero legitimate
    /// authority) -- this test makes that defect class structurally
    /// unreachable going forward, for both `Required` and `Optional`
    /// applicability.
    #[test]
    fn every_applicable_diagnostics_gate_has_a_legitimate_authority() -> CorulixResult<()> {
        for intent in OperationIntent::ALL {
            let entry = policy_entry(*intent).ok_or(CorulixError::Internal)?;
            let diagnostics_applicability = entry
                .gates
                .iter()
                .find(|g| g.gate == GateId::Diagnostics)
                .map(|g| g.applicability);
            if !matches!(
                diagnostics_applicability,
                Some(GateApplicability::Required) | Some(GateApplicability::Optional)
            ) {
                continue;
            }
            let has_legitimate_authority = entry
                .requirements
                .iter()
                .any(|r| !matches!(r.authority, AuthorityRole::ForbiddenAsAuthority));
            assert!(
                has_legitimate_authority,
                "{intent:?}: gate.diagnostics is applicable but no requirement can close it"
            );
        }
        Ok(())
    }

    /// P12: the same structural-closure invariant as
    /// `every_applicable_diagnostics_gate_has_a_legitimate_authority`,
    /// applied to `gate.tests`. Before P12, `VALIDATE_CHANGE` carried
    /// `gate.tests` as `Optional` while `ProviderCategory::TestRunner` was
    /// `SupportingOnly` -- an unclosable gate of the same defect class P11
    /// found for `gate.diagnostics`. Guards against that regressing.
    #[test]
    fn every_applicable_tests_gate_has_a_legitimate_authority() -> CorulixResult<()> {
        for intent in OperationIntent::ALL {
            let entry = policy_entry(*intent).ok_or(CorulixError::Internal)?;
            let tests_applicability = entry
                .gates
                .iter()
                .find(|g| g.gate == GateId::Tests)
                .map(|g| g.applicability);
            if !matches!(
                tests_applicability,
                Some(GateApplicability::Required) | Some(GateApplicability::Optional)
            ) {
                continue;
            }
            let has_legitimate_authority = entry
                .requirements
                .iter()
                .any(|r| !matches!(r.authority, AuthorityRole::ForbiddenAsAuthority));
            assert!(
                has_legitimate_authority,
                "{intent:?}: gate.tests is applicable but no requirement can close it"
            );
        }
        Ok(())
    }

    /// P11 Minimum Sufficient Tooling risk-strengthening proof: the
    /// `TypecheckBuild` requirement set genuinely differs between the
    /// `Elevated`-risk source-mutation entries (optional) and the
    /// `High`/`Critical`-risk semantic-mutation entries (required, plus a
    /// supporting lint requirement neither `Elevated` entry carries) --
    /// higher risk never receives a *weaker* or merely equal validator set.
    #[test]
    fn typecheck_build_strengthens_from_optional_at_elevated_to_required_at_high_and_critical()
    -> CorulixResult<()> {
        for entry in [SOURCE_CREATE, SOURCE_MODIFY] {
            assert_eq!(entry.base_risk, RiskClass::Elevated);
            let requirement = find_requirement(&entry, ProviderCategory::TypecheckBuild)?;
            assert_eq!(requirement.applicability, ToolApplicability::Optional);
            assert!(
                entry
                    .requirements
                    .iter()
                    .all(|r| r.category != ProviderCategory::Linter),
                "Elevated-risk entries must not require the stronger Linter validator"
            );
        }
        for entry in [SEMANTIC_RENAME, SOURCE_REFACTOR] {
            assert!(matches!(
                entry.base_risk,
                RiskClass::High | RiskClass::Critical
            ));
            let typecheck = find_requirement(&entry, ProviderCategory::TypecheckBuild)?;
            assert_eq!(typecheck.applicability, ToolApplicability::Required);
            assert_eq!(typecheck.authority, AuthorityRole::Authoritative);
            let linter = find_requirement(&entry, ProviderCategory::Linter)?;
            assert_eq!(linter.applicability, ToolApplicability::Required);
            assert_eq!(linter.authority, AuthorityRole::SupportingOnly);
        }
        Ok(())
    }

    #[test]
    fn not_every_operation_receives_every_gate() {
        // FileDiscovery is deliberately a single-gate entry, proving the
        // gate list is a genuine subset, not a forced seven-gate walk.
        assert_eq!(FILE_DISCOVERY.gates.len(), 1);
    }
}
