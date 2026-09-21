// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Provider category/capability contracts and the deterministic `ToolPlan`
//! domain model.
//!
//! `ToolPlan` is plain, deterministic domain data -- it is never mutable
//! orchestration runtime. It carries no function pointers, closures,
//! process handles, executable paths, or MCP/LSP objects, and this crate
//! never invokes a tool. A later Engine phase (Phase 4) derives a concrete
//! `ToolPlan` for a request; Core defines only the shape a plan can take.

use crate::gate::GateRequirement;
use crate::language::CapabilityState;
use crate::operation::{MutationKind, OperationIntent, RiskClass};
use serde::{Deserialize, Serialize};

/// A technology-neutral category of external capability a `ToolPlan` may
/// require. Deliberately generic -- no rust-analyzer-specific (or any other
/// concrete provider's) state is represented here; a specific provider's
/// identity/version is runtime data attached later (see
/// `EvidenceProvenance`), not part of this category vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ProviderCategory {
    TextSearch,
    StructuralParse,
    LanguageServer,
    Formatter,
    Linter,
    TypecheckBuild,
    TestRunner,
    /// A language runtime/interpreter an admitted provider needs to run
    /// itself (e.g. Node.js for a script-based `LanguageServer` provider).
    /// Deliberately distinct from `LanguageServer` even when the runtime
    /// exists solely to execute an LSP provider: `HostConfig::
    /// provider_absolute_paths` is keyed by category alone, so resolving a
    /// runtime under the *same* category as the provider it launches would
    /// let a `HOST_ONLY` absolute-path override configured for that
    /// provider silently answer for the runtime too (admitted this phase,
    /// Architecture Rule P, after this exact collision was found
    /// empirically while wiring the TypeScript/Python auxiliary Node
    /// launcher).
    Runtime,
}

/// Whether a tool may/should participate in a given operation. Independent
/// from [`AuthorityRole`]: a tool can be applicable as supporting evidence
/// while remaining forbidden from closing the relevant gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ToolApplicability {
    Required,
    Optional,
    Supporting,
    NotApplicable,
}

/// Whether a tool's evidence may close the relevant gate. Independent from
/// [`ToolApplicability`] -- e.g. RG can be `Supporting` for a semantic
/// operation while its `AuthorityRole` remains `ForbiddenAsAuthority`, since
/// a textual match is a candidate, never a definition/reference by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AuthorityRole {
    Authoritative,
    SupportingOnly,
    ForbiddenAsAuthority,
}

/// One entry in a [`ToolPlan`]: which provider category is needed, whether
/// it is required for this operation, and whether its evidence may be
/// authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolRequirement {
    pub category: ProviderCategory,
    pub applicability: ToolApplicability,
    pub authority: AuthorityRole,
}

/// A provider's capability for a specific requirement.
///
/// Reuses the existing [`CapabilityState`] tri-state (the same
/// Supported/Partial/NotSupported vocabulary already used by
/// `LanguageCapabilities`) rather than introducing a second, near-identical
/// enum for the same underlying concept.
pub type ProviderCapability = CapabilityState;

/// A provider's current runtime availability, independent of its
/// capability. Distinguishes at minimum: the provider being entirely
/// absent, a specific capability being absent even though the provider
/// exists, the provider being fully available, and semantic/provider
/// readiness not yet having been achieved (e.g. an LSP server still
/// indexing) -- this last state is never conflated with "zero results",
/// since an empty answer from a not-yet-ready provider is not proof of
/// absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ProviderAvailability {
    Available,
    ProviderUnavailable,
    CapabilityUnavailable,
    ReadinessPending,
}

/// Which configured source category actually satisfied a real,
/// externally-resolved provider lookup (Phase 6). Distinct from
/// `ProviderAvailability::Available` alone -- provenance records *why* a
/// resolved path was trusted, not merely that one was found. Never includes
/// ambient `PATH` as a source: `wht_corulix_config`'s resolver has zero
/// ambient-`PATH` authority by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ProviderProvenance {
    /// A Corulix-owned managed toolchain artifact: downloaded, integrity-
    /// verified, and atomically activated by Corulix itself under its own
    /// application-data root, outside any workspace and independent of
    /// ambient `PATH`/system installation. This is the first-checked,
    /// highest-precedence provenance for a provider that declares a managed
    /// component (Phase 7B-A) -- `HostConfigured`/`ApprovedSystemDirectory`/
    /// `ApprovedUserToolchainDirectory` remain a distinct, separately
    /// resolved fallback path, never merged with this one.
    CorulixManaged,
    /// An absolute path explicitly configured by `HOST_ONLY` policy for
    /// this exact provider category.
    HostConfigured,
    /// A host-declared, finite list of approved system directories.
    ApprovedSystemDirectory,
    /// A host-declared, finite list of approved user toolchain
    /// directories -- disabled by default; only consulted when `HOST_ONLY`
    /// policy explicitly enables it.
    ApprovedUserToolchainDirectory,
}

/// A structured, machine-authoritative classification of why an operation,
/// gate, or plan could not proceed. No free-form string is ever the
/// authority for this classification; `#[non_exhaustive]` allows later
/// phases to add categories without a second, parallel error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ReasonCode {
    RequiredProviderUnavailable,
    RequiredCapabilityUnavailable,
    PreconditionNotMet,
    /// A `HOST_ONLY`-configured provider path was not absolute. Fails
    /// closed with a typed rejection; resolution never silently falls back
    /// to system/user-toolchain directories when the host's own explicit
    /// configuration is malformed.
    ProviderPathNotAbsolute,
    /// A configured or candidate provider path could not be canonicalized
    /// (missing target, symlink cycle, permission error).
    ProviderPathUnresolvable,
    /// A candidate provider path canonicalized to a location inside the
    /// active workspace. `CONTROLLED_EXTERNAL_TOOL` providers are never
    /// satisfied by a workspace-local executable, including via symlink
    /// indirection.
    ProviderResolvedInsideWorkspace,
    /// The requested provider category was disabled by the merged
    /// (`HostConfig` → `RepositoryHints` → `RequestOptions`) effective
    /// configuration before resolution was attempted.
    ProviderCategoryDisabledByPolicy,
    /// The requested provider category is an in-process, compiled-in
    /// capability (e.g. text search, structural parse) and is never
    /// resolved externally -- there is no executable path to resolve.
    ProviderNotExternallyResolvable,
    /// A `MutationBatch` commit failed part-way through, internal recovery
    /// to the pre-transaction filesystem state was attempted, and that
    /// recovery itself failed. The mutation authority that produced this
    /// reason establishes a recovery-locked condition denying further
    /// mutation writes until manual recovery evidence is provided (a later
    /// `ChangeSession` phase's concern; this reason code exists so that
    /// phase, and any caller, has a stable, typed signal to react to today).
    MutationRecoveryRequired,

    // -- Phase 10 (`ChangeSession` + Evidence + gate state machine) --
    /// A caller attempted a `ChangeSession` state transition not valid from
    /// its current status (e.g. `OPENED -> COMPLETED`, or any mutation
    /// attempt against a terminal `COMPLETED`/`ABORTED` session).
    InvalidSessionTransition,
    /// A caller supplied a `ChangeSessionId` that does exist, but the
    /// request's [`crate::WorkspaceIdentity`] does not match the identity
    /// the session was bound to at creation. A session id is never
    /// sufficient authorization by itself.
    SessionWorkspaceMismatch,
    /// As [`Self::SessionWorkspaceMismatch`], but for the host/MCP
    /// connection identity the session was created under
    /// (`SESSION_ID_ONLY_AUTHORIZATION=NO`).
    SessionConnectionMismatch,
    /// A requested mutation/evidence target falls outside the
    /// `ChangeSession`'s bound scope.
    SessionScopeViolation,
    /// A required gate has no Evidence at all yet.
    RequiredGateMissingEvidence,
    /// A required gate's most recent Evidence records `GateStatus::Failed`.
    RequiredGateFailed,
    /// A required gate's Evidence exists but is `Stale`/superseded without
    /// a replacement -- an upstream mutation invalidated it and it has not
    /// been re-earned.
    RequiredGateEvidenceStale,
    /// Evidence was offered for a gate/category combination whose
    /// [`AuthorityRole`] is [`AuthorityRole::ForbiddenAsAuthority`] for the
    /// governing `ToolPlan` requirement -- it can never close that gate,
    /// however plausible the result looks.
    EvidenceForbiddenAsAuthority,
    /// Evidence's `input_fingerprint` does not match the session's current
    /// observed content state for the target it describes.
    EvidenceStaleInputFingerprint,
    /// Evidence's `snapshot_id` does not correspond to the snapshot the
    /// governing gate operation actually ran against.
    EvidenceWrongSnapshot,
    /// Evidence was produced under a different `ChangeSessionId` than the
    /// one being completed/inspected.
    EvidenceWrongSession,
    /// Evidence's `workspace_identity` does not match the session's own.
    EvidenceWrongWorkspace,
    /// Evidence's `sequence` is not strictly greater than the highest
    /// sequence already recorded for this session (duplicate or
    /// regressive).
    EvidenceSequenceInvalid,
    /// Evidence's provider identity/version does not match the
    /// `ChangeSession`'s bound provider snapshot for that category.
    EvidenceProviderSnapshotMismatch,
    /// A client attempted to declare a gate `NOT_APPLICABLE` directly --
    /// applicability is Engine/`ToolPlan`-derived only.
    ClientGateApplicabilityOverrideDenied,
    /// `complete_change` was requested while this executor/session is
    /// locked by an unresolved [`Self::MutationRecoveryRequired`]
    /// condition -- no further writes, and no completion, until manual
    /// recovery evidence is provided.
    SessionMutationLocked,
    /// `complete_change`/`submit_edit`/`validate_change` was requested
    /// against a session already in a terminal state
    /// (`COMPLETED`/`ABORTED`).
    SessionAlreadyTerminal,
    /// An Evidence record's own `result_summary` would exceed
    /// [`crate::EVIDENCE_RESULT_SUMMARY_MAX_BYTES`] -- fails closed rather
    /// than silently truncating an audit record's content out of order
    /// with its own `truncated` flag.
    EvidenceResultSummaryOversized,

    // -- Phase 11 (diagnostics/lint/typecheck gates) --
    /// A `TypecheckBuild`/`Linter` provider ran successfully (the process
    /// itself did not fail to spawn/timeout/get cancelled) and reported at
    /// least one real error/warning finding against the current content --
    /// the finding itself, not a tooling failure, is why the gate did not
    /// pass. Distinguishes a genuine `cargo check`/clippy finding from
    /// [`Self::RequiredProviderUnavailable`] (the tool never ran at all).
    DiagnosticsFindingsReported,

    // -- Phase 12 (trusted build/test execution) --
    /// A `TestRunner` provider ran successfully (the process itself did not
    /// fail to spawn/timeout/get cancelled, and the build compiled cleanly)
    /// and reported at least one real, exit-code-confirmed test failure
    /// against the current content -- the failure itself, not a tooling
    /// failure, is why the gate did not pass. Distinguishes a genuine
    /// `cargo test` failure from [`Self::RequiredProviderUnavailable`] (the
    /// tool never ran at all) and from [`Self::DiagnosticsFindingsReported`]
    /// (a compile-time finding, not a behavioral test failure).
    TestFailuresReported,

    // -- F2 fix (reason-code collapse at the client-facing tool boundary) --
    // `wht_corulix_mutation::MutationError`/`wht_corulix_formatter::FormatterError`
    // each carry several distinct real failure shapes that used to collapse
    // into the generic `RequiredCapabilityUnavailable` reported to a client
    // -- the same fallback used for a genuinely missing external provider.
    // These give each a precise, stable, client-actionable code instead.
    /// `MutationError::CreateCollision`/`MutationError::MoveCollision`: the
    /// mutation's target (a `CreateFile` target, or a `MoveFile`
    /// destination) already exists. A real collision, not a stale
    /// precondition and not a missing capability -- the client's remedy is
    /// to re-check the target's existence, not to retry with a fresher hash.
    MutationTargetAlreadyExists,
    /// `MutationError::TargetNotFound`: a mutation's target/source does not
    /// exist as the operation expects (e.g. `DeleteFile`/`ReplaceFile`'s
    /// target, or `MoveFile`'s source).
    MutationTargetNotFound,
    /// `MutationError::ConfinementViolation`/`FormatterError::ConfinementViolation`:
    /// the resolved target does not live inside the active workspace (a
    /// real workspace-confinement rejection, e.g. an absent immediate
    /// parent directory for a `CreateFile` target, or a path that resolves
    /// outside the workspace root). Distinct from
    /// [`Self::SessionScopeViolation`], which is the shallower, textual
    /// `SessionScope` allow-list check -- this is the deeper, real
    /// filesystem-confinement authority (`wht_corulix_workspace`) rejecting
    /// the resolved path outright; widening `scope_prefixes` would never fix
    /// this.
    MutationTargetConfinementViolation,
    /// `MutationError::InvalidEditRange`: an `ApplyTextEdits` range is out of
    /// bounds, not on a UTF-8 boundary, or otherwise invalid for the
    /// target's current content. Not reachable through the current
    /// `submit_edit` MCP schema (`ApplyTextEdits` is not one of its exposed
    /// edit kinds), but the mapping stays exhaustive and honest for the real
    /// `wht_corulix_mutation` domain model.
    MutationInvalidEditRange,
    /// `MutationError::OverlappingEdits`: two or more edits in the same
    /// `ApplyTextEdits` target overlap. Same MCP-surface-reachability caveat
    /// as [`Self::MutationInvalidEditRange`].
    MutationOverlappingEdits,
    /// `MutationError::ResourceLimitExceeded`: a hard `MutationLimits` bound
    /// was exceeded during PREPARE, before any live write.
    MutationResourceLimitExceeded,
    /// `MutationError::PrepareFailed`: PREPARE failed for a reason not
    /// captured by a more specific variant (e.g. an I/O error reading a
    /// target's current content that is not itself a confinement or
    /// not-found condition).
    MutationPrepareFailed,
    /// `MutationError::CommitFailed`: a commit-time filesystem operation
    /// failed and this batch's internal partial-commit recovery succeeded in
    /// restoring the pre-transaction state -- no live effect remains, but
    /// the batch itself did not complete.
    MutationCommitFailedRecovered,
    /// `MutationError::VerificationFailed`: a committed action's post-commit
    /// verification did not match the expected outcome, and recovery
    /// succeeded (mirrors [`Self::MutationCommitFailedRecovered`], but
    /// distinguishes "the syscall itself failed" from "the syscall said yes
    /// but the disk disagreed").
    MutationVerificationFailedRecovered,
    /// `MutationError::MalformedPreconditionHash` (P-M08-R1): a caller-
    /// supplied `expected_precondition_hash`/`expected_source_hash` is not
    /// a well-formed 64-lowercase-hex-character SHA-256 digest -- a
    /// caller-input defect, never a genuine staleness signal. Distinct
    /// from [`Self::PreconditionNotMet`], which remains reserved for a
    /// well-formed hash that simply does not match the target's current
    /// content.
    MutationPreconditionMalformed,

    // -- F3 fix (`SOURCE_DELETE` real post-audit) --
    /// A delete-kind `ChangeSession`'s real post-audit re-check found a
    /// previously-deleted target still present on the filesystem -- the
    /// commit itself, or a later external change, contradicts this
    /// session's own recorded deletion. A genuine, real re-verification
    /// finding, never a fabricated one.
    PostAuditTargetStillPresent,
    /// A delete-kind `ChangeSession`'s real post-audit search
    /// (`ProviderCategory::TextSearch`) found at least one other in-scope
    /// file whose content still contains a deleted target's literal
    /// relative-path text -- a real, found dangling reference, not a
    /// tooling failure.
    PostAuditDanglingReferenceFound,

    // -- F4 fix (`gate.format` closure) --
    /// A real, approved formatter ran successfully (the process itself did
    /// not fail to spawn/timeout/get cancelled) against this session's
    /// modified target(s) and reported that at least one target's current
    /// bytes are not the canonical formatted output -- the finding itself,
    /// not a tooling failure, is why `gate.format` did not pass. Mirrors
    /// [`Self::DiagnosticsFindingsReported`]'s exact distinction from
    /// [`Self::RequiredProviderUnavailable`] (the formatter never ran at
    /// all).
    FormatFindingsReported,
    /// `begin_change` rejected the requested `OperationIntent` outright,
    /// before any `ChangeSession` was opened and before any mutation was
    /// possible -- the intent's own policy entry requires a gate
    /// (`GateId::Discovery`/`GateId::SemanticConfirm`) for which no
    /// production Evidence-recording path exists anywhere in this
    /// workspace today, which would otherwise leave a committed mutation
    /// permanently uncompletable (`SemanticRename`/`SourceRefactor` as of
    /// F4). Distinct from every other `RequiredProviderUnavailable`-style
    /// code: this is a structural product-support boundary, not a missing
    /// external tool.
    OperationNotSupported,
}

/// Whether a [`ToolPlan`] can actually be executed.
///
/// A required provider being unavailable makes a plan unexecutable outright
/// -- it must never be silently converted into merely a higher risk score.
/// Optional/supporting-provider absence does not appear here; it only
/// affects evidence coverage, handled by the later phase that derives a
/// plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub enum PlanExecutability {
    Executable,
    Unexecutable { reason: ReasonCode },
}

/// A deterministic, ordered plan of tool requirements for one operation.
///
/// Plain data: no function pointers, no closures, no process objects, no
/// executable paths, no MCP/LSP objects. This crate does not derive plans
/// and does not invoke tools -- both belong to the later Engine phase
/// (Architecture Rule H: only `wht_corulix_engine` derives a `ToolPlan`).
///
/// `gates` is an ordered *subset* of [`crate::GateId::ALL`] -- nothing about
/// this shape forces every operation through all seven canonical gates, and
/// a gate's presence here is independent of whether the provider it depends
/// on is currently available (see [`PlanExecutability`]): a required gate
/// never disappears from this list merely because a required provider is
/// unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolPlan {
    pub intent: OperationIntent,
    pub mutation_kind: Option<MutationKind>,
    pub risk_class: Option<RiskClass>,
    pub requirements: Vec<ToolRequirement>,
    pub gates: Vec<GateRequirement>,
    pub executability: PlanExecutability,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_applicability_and_authority_role_are_independent() {
        // RG-for-semantic-operations: applicable only as supporting
        // evidence, but never authoritative for closing the gate. Supporting
        // evidence cannot masquerade as gate-closing authority in the type
        // system -- these are two separate fields, not one collapsed value.
        let requirement = ToolRequirement {
            category: ProviderCategory::TextSearch,
            applicability: ToolApplicability::Supporting,
            authority: AuthorityRole::ForbiddenAsAuthority,
        };
        assert_eq!(requirement.applicability, ToolApplicability::Supporting);
        assert_eq!(requirement.authority, AuthorityRole::ForbiddenAsAuthority);
    }

    #[test]
    fn required_provider_unavailable_makes_plan_unexecutable() {
        let plan = ToolPlan {
            intent: OperationIntent::SemanticDefinition,
            mutation_kind: None,
            risk_class: None,
            requirements: vec![ToolRequirement {
                category: ProviderCategory::LanguageServer,
                applicability: ToolApplicability::Required,
                authority: AuthorityRole::Authoritative,
            }],
            gates: Vec::new(),
            executability: PlanExecutability::Unexecutable {
                reason: ReasonCode::RequiredProviderUnavailable,
            },
        };
        assert!(matches!(
            plan.executability,
            PlanExecutability::Unexecutable {
                reason: ReasonCode::RequiredProviderUnavailable
            }
        ));
    }

    #[test]
    fn provider_capability_reuses_capability_state() {
        let capability: ProviderCapability = CapabilityState::Partial;
        assert_eq!(capability, CapabilityState::Partial);
    }
}
