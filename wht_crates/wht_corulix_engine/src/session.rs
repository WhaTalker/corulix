// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The `ChangeSession` + Evidence + gate state machine (Phase 10).
//!
//! This module turns the already-certified building blocks --
//! [`wht_corulix_core::ToolPlan`] derivation (Phase 4), the governed
//! [`wht_corulix_mutation::MutationExecutor`] transaction (Phase 8),
//! formatter governance (Phase 9), and the admitted LSP/managed-toolchain
//! providers (Phase 7B) -- into one governed, end-to-end workflow. It
//! implements no new provider and no new mutation-write path: every gate
//! this module closes is closed by Evidence a caller obtained from one of
//! those already-certified components, never by this module inventing its
//! own semantic authority. [`ChangeSession::format_and_apply`] (Phase
//! 10-R2) is the one exception to "no new invocation site" -- it is a thin,
//! session-owned wrapper around the already-certified Phase 9
//! `wht_corulix_formatter::format_and_apply`, added specifically so a
//! successful governed format write and this session's own current-state
//! advancement become one inseparable operation, never two steps a caller
//! could complete only one of.
//!
//! # Engine authority (invariant)
//!
//! Only [`ChangeSession`]'s own methods derive [`ChangeSessionStatus`],
//! accept [`wht_corulix_core::Evidence`] as authoritative, or decide
//! completion (`ENGINE_COMPLETION_AUTHORITY=YES`; `CLIENT_*_AUTHORITY=NO`
//! for risk, gate override, and completion; `PROVIDER_COMPLETION_AUTHORITY=NO`;
//! `AI_COMPLETION_AUTHORITY=NO`). A caller supplies raw provider output
//! (a definition result, a `FormatterResult`, a diagnostics report) and
//! this module's binding/authority/staleness checks decide whether that
//! output may close a gate -- there is no code path through which a
//! narrative claim ("tests passed") becomes `Evidence` on its own.
//!
//! # `ChangeSession` binding
//!
//! A session is bound, at creation, to a [`WorkspaceIdentity`], a
//! [`ConnectionId`], a [`SessionScope`], a [`ToolPlan`], and a snapshot of
//! the provider identities/versions it will accept evidence from. Every
//! mutating call ([`ChangeSession::record_evidence`],
//! [`ChangeSession::submit_edit`], [`ChangeSession::complete_change`],
//! [`ChangeSession::abort`]) re-checks the caller's claimed workspace and
//! connection identity against that binding -- a valid [`ChangeSessionId`]
//! alone is never sufficient authorization
//! (`SESSION_ID_ONLY_AUTHORIZATION=NO`).
//!
//! # State machine
//!
//! ```text
//! Opened -> Scoped -> Baselined -> GatePending(gate_i)
//!   GatePending(gate_i) --Evidence Passed--> next required gate, or ExitEvaluation
//!   GatePending(gate_i) --Evidence Failed --> Blocked(gate_i)
//!   Blocked(gate_i)     --corrective Evidence Passed--> next required gate, or ExitEvaluation
//! ExitEvaluation --complete_change, all required gates current+Passed--> Completed
//! ExitEvaluation --complete_change, otherwise--> Blocked(<first offending gate>)
//! any nonterminal state --abort--> Aborted
//! Completed / Aborted: terminal, immutable (no further writes, no reopen)
//! ```
//!
//! # Evidence invalidation graph (documented, not ad hoc -- Phase 10 §34)
//!
//! Exactly one rule: every time [`ChangeSession::submit_edit`] commits a
//! new [`wht_corulix_mutation::MutationBatch`], every `Current`
//! [`wht_corulix_core::GateStatus::Passed`] record for
//! [`GateId::Format`]/[`GateId::Diagnostics`]/[`GateId::Tests`]/
//! [`GateId::PostAudit`] is flipped in place to
//! [`wht_corulix_core::GateStatus::Stale`] -- those four gates' truth
//! depends on the file's current bytes, and a new edit means the bytes a
//! prior passing record described no longer exist.
//! [`GateId::Discovery`]/[`GateId::SemanticConfirm`] evidence is not
//! invalidated by a later edit: it already did its job informing that
//! edit, and does not claim anything about post-edit bytes. No Evidence
//! record is ever deleted -- staleness is a status transition on the
//! stored record, preserving full audit history
//! (`INVALIDATED_EVIDENCE_HISTORY_PRESERVED=YES`).

use std::collections::HashMap;

use wht_corulix_core::{
    CancellationToken, ChangeSessionId, ChangeSessionStatus, ConnectionId, ContentHash, Evidence,
    EvidenceProvenance, GateApplicability, GateId, GateStatus, LanguageId, PlanExecutability,
    ProviderCategory, ReasonCode, ToolPlan, WorkspaceIdentity, WorkspacePath,
};
use wht_corulix_formatter::{FormatterError, FormatterResult};
use wht_corulix_mutation::{
    Mutation, MutationBatch, MutationError, MutationExecutor, MutationOutcome,
};

/// The four gates whose truth depends on the file's *current* bytes --
/// exactly the set [`submit_edit`](ChangeSession::submit_edit) invalidates
/// on every new edit. See the module doc's "Evidence invalidation graph"
/// section for the rationale.
const CONTENT_DEPENDENT_GATES: [GateId; 4] = [
    GateId::Format,
    GateId::Diagnostics,
    GateId::Tests,
    GateId::PostAudit,
];

/// A `ChangeSession`'s bound mutation scope: the finite set of
/// workspace-relative path prefixes this session may target. Never a raw
/// glob/regex -- an exact relative path, or an exact directory prefix
/// (`"src/"` permits `"src/lib.rs"` and `"src/a/b.rs"`, never `"src2/x"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionScope(Vec<String>);

impl SessionScope {
    #[must_use]
    pub fn new(allowed_prefixes: Vec<String>) -> Self {
        Self(allowed_prefixes)
    }

    #[must_use]
    pub fn permits(&self, relative_path: &str) -> bool {
        self.0.iter().any(|allowed| {
            relative_path == allowed
                || (!allowed.is_empty() && relative_path.starts_with(&format!("{allowed}/")))
        })
    }

    /// The bound allow-listed path prefixes, verbatim, read-only. P16:
    /// language-specific `validate_change` dispatchers (`crate::ts_validation`)
    /// need this session's own target file(s) -- e.g. to locate the nearest
    /// `tsconfig.json` or the file Biome should lint -- rather than a
    /// hardcoded workspace-wide default.
    #[must_use]
    pub fn prefixes(&self) -> &[String] {
        &self.0
    }
}

/// One historical Evidence record and its current [`GateStatus`]. Never
/// removed once inserted -- invalidation flips `status` to
/// [`GateStatus::Stale`] in place; the underlying [`Evidence`] is
/// preserved byte-for-byte as an audit trail entry.
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub evidence: Evidence,
    pub status: GateStatus,
}

/// Every denial this module can produce, each carrying the stable
/// [`ReasonCode`] a caller should surface -- never a bare string as the
/// only machine-readable authority (`P10_UNSTRUCTURED_MACHINE_ERROR_COUNT=0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    Denied(ReasonCode),
    Mutation(MutationError),
    /// A [`ChangeSession::format_and_apply`]-driven governed format write
    /// failed -- wraps [`FormatterError`] verbatim (Phase 10-R2 §58: no
    /// bare-string re-encoding), exactly mirroring how [`Self::Mutation`]
    /// already wraps [`MutationError`] verbatim for
    /// [`ChangeSession::submit_edit`].
    Formatter(FormatterError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(reason) => write!(f, "change session denied: {reason:?}"),
            Self::Mutation(error) => write!(f, "change session mutation failed: {error}"),
            Self::Formatter(error) => write!(f, "change session format write failed: {error}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// F2 fix: precise, per-variant [`MutationError`] -> [`ReasonCode`] mapping.
///
/// Before this fix, every variant here collapsed into the generic
/// `ReasonCode::RequiredCapabilityUnavailable` at the MCP boundary (the same
/// fallback used for a genuinely missing external provider) -- empirically
/// reproduced for `StalePreconditionHash` (a `replace` with a stale
/// `expected_precondition_hash_hex`), `CreateCollision` (a `create` onto an
/// already-existing path), and `ConfinementViolation` (a `create` whose
/// immediate parent directory does not exist -- `wht_corulix_workspace::
/// confine_target` rejects this as a confinement failure, not a distinct
/// "missing parent" variant). Each real failure shape now gets its own
/// stable, client-actionable code.
///
/// `MoveCollision`/`InvalidEditRange`/`OverlappingEdits` are not reachable
/// through the current `submit_edit` MCP schema (`EditRequestParams` exposes
/// only `create`/`replace`/`delete`, never `MoveFile`/`ApplyTextEdits`) --
/// this match still covers them precisely and exhaustively (never a
/// wildcard arm) so the real `wht_corulix_mutation` domain model never
/// silently degrades if/when a future MCP surface reaches them.
fn mutation_error_reason(error: &MutationError) -> ReasonCode {
    match error {
        MutationError::StalePreconditionHash { .. } => ReasonCode::PreconditionNotMet,
        MutationError::MalformedPreconditionHash { .. } => {
            ReasonCode::MutationPreconditionMalformed
        }
        MutationError::CreateCollision { .. } | MutationError::MoveCollision { .. } => {
            ReasonCode::MutationTargetAlreadyExists
        }
        MutationError::TargetNotFound { .. } => ReasonCode::MutationTargetNotFound,
        MutationError::ConfinementViolation { .. } => {
            ReasonCode::MutationTargetConfinementViolation
        }
        MutationError::InvalidEditRange { .. } => ReasonCode::MutationInvalidEditRange,
        MutationError::OverlappingEdits { .. } => ReasonCode::MutationOverlappingEdits,
        MutationError::ResourceLimitExceeded => ReasonCode::MutationResourceLimitExceeded,
        MutationError::PrepareFailed => ReasonCode::MutationPrepareFailed,
        MutationError::CommitFailed { .. } => ReasonCode::MutationCommitFailedRecovered,
        MutationError::VerificationFailed { .. } => ReasonCode::MutationVerificationFailedRecovered,
        // Reuses the existing, already-precise code Phase 10 defined for
        // exactly this condition -- `record_evidence`'s docs already name
        // it, and `submit_edit` itself already returns this same code via
        // its own `self.executor.is_locked()` pre-check, so a stray
        // `ExecutorLocked` surfacing here (defensive-only: `submit_edit`
        // never lets a live call reach the executor while locked) stays
        // consistent with what a caller would have seen from that pre-check.
        MutationError::RecoveryRequired { .. } => ReasonCode::MutationRecoveryRequired,
        MutationError::ExecutorLocked => ReasonCode::SessionMutationLocked,
    }
}

/// F2 fix: precise [`FormatterError`] -> [`ReasonCode`] mapping.
///
/// `Mutation(inner)` delegates to [`mutation_error_reason`] verbatim -- the
/// final `MutationBatch` apply step failing during a governed format write
/// is exactly the same real failure shape `ChangeSession::submit_edit`
/// itself can produce, and deserves the same precision.
/// `ConfinementViolation` reuses the same
/// `ReasonCode::MutationTargetConfinementViolation` code
/// [`mutation_error_reason`] uses for the mutation-layer equivalent: both
/// mean "the resolved target does not live inside the active workspace",
/// and a caller should not have to learn two different codes for one real
/// condition depending on which crate happened to detect it.
///
/// The remaining four variants (`UnsupportedLanguage`, `OversizedInput`,
/// `ReadFailed`, `ManagedToolchainRootUnavailable`) are all genuinely "the
/// formatter capability itself could not process this input" -- this is
/// `RequiredCapabilityUnavailable`'s real, documented meaning, not a
/// collapse of otherwise-distinguishable cases, so they are deliberately
/// left as-is rather than each inventing a bespoke code with no
/// distinguishing client-actionable value.
///
/// Not reachable through the current 14-tool MCP surface today: the
/// canonical tool set exposes `format_preview` (read-only) but no
/// formatter-*apply* tool, so `ChangeSession::format_and_apply` (the only
/// producer of a real [`FormatterError`]) is not yet callable from any MCP
/// tool. The mapping stays exhaustive and honest regardless, exactly like
/// [`mutation_error_reason`]'s own MCP-unreachable variants.
fn formatter_error_reason(error: &FormatterError) -> ReasonCode {
    match error {
        FormatterError::ConfinementViolation { .. } => {
            ReasonCode::MutationTargetConfinementViolation
        }
        FormatterError::Mutation(inner) => mutation_error_reason(inner),
        FormatterError::UnsupportedLanguage { .. }
        | FormatterError::OversizedInput { .. }
        | FormatterError::ReadFailed { .. }
        | FormatterError::ManagedToolchainRootUnavailable => {
            ReasonCode::RequiredCapabilityUnavailable
        }
    }
}

impl SessionError {
    /// The stable [`ReasonCode`] a caller-facing surface (today, exclusively
    /// `wht_corulix_mcp`) should report for this error. `Denied` already
    /// carries its own precise code; `Mutation`/`Formatter` are mapped
    /// precisely via `mutation_error_reason`/`formatter_error_reason`
    /// (the F2 fix) rather than collapsing into one generic fallback code.
    /// Lives here, not in `wht_corulix_mcp`, because that crate depends only
    /// on `wht_corulix_core`/`wht_corulix_engine` (Architecture Rule B/S) and
    /// must never reference `wht_corulix_mutation`/`wht_corulix_formatter`
    /// directly.
    #[must_use]
    pub fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Denied(reason) => *reason,
            Self::Mutation(error) => mutation_error_reason(error),
            Self::Formatter(error) => formatter_error_reason(error),
        }
    }
}

fn denied(reason: ReasonCode) -> SessionError {
    SessionError::Denied(reason)
}

/// An audit-safe, structured snapshot of a session's current state --
/// backs `change_status` (Phase 10 §64). Never exposes a raw workspace
/// path or secret; `pending_gate`/`failed_gates`/`stale_gates` are derived
/// read-only views over the evidence store.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct ChangeStatusView {
    pub session_id: ChangeSessionId,
    pub status: ChangeSessionStatus,
    pub required_gates: Vec<GateId>,
    pub passed_gates: Vec<GateId>,
    pub failed_gates: Vec<(GateId, ReasonCode)>,
    pub stale_gates: Vec<GateId>,
    pub completion_eligible: bool,
}

/// The governed `ChangeSession` state machine (Phase 10).
///
/// Owns exactly one [`MutationExecutor`] (Rule M: no second write path is
/// created here -- every live write this session ever performs goes
/// through that executor, `submit_edit` is the only method that touches
/// it). Holds its full Evidence history for the session's lifetime
/// (`INVALIDATED_EVIDENCE_HISTORY_PRESERVED=YES`).
pub struct ChangeSession {
    id: ChangeSessionId,
    workspace_identity: WorkspaceIdentity,
    connection_id: ConnectionId,
    scope: SessionScope,
    creation_sequence: u64,
    tool_plan: ToolPlan,
    provider_snapshot: HashMap<String, EvidenceProvenance>,
    status: ChangeSessionStatus,
    evidence: Vec<EvidenceRecord>,
    highest_sequence_seen: u64,
    content_snapshot_id: u64,
    last_edit_output_hash: Option<ContentHash>,
    executor: MutationExecutor,
    /// The source language this session was opened for, when the caller
    /// declared one via `begin_change`'s own `language` parameter. `None`
    /// preserves this crate's pre-P15 default (Rust-implicit dispatch).
    /// Retained purely so a later capability -- today, only
    /// [`crate::CorulixEngine::validate_change`] -- can route to the
    /// correct language's real validators instead of hardcoding Rust; it is
    /// never consulted by `ToolPlan` derivation itself (that already
    /// happened, in `plan_operation_for_language`, before this field is
    /// set) and it never gains its own authority over gates or Evidence.
    language: Option<LanguageId>,
    /// F3 fix: every workspace-relative target this session has genuinely
    /// deleted, across the session's whole lifetime (never cleared, mirrors
    /// [`Self::evidence`]'s own "never removed" audit-history discipline).
    /// Populated exclusively from [`Self::submit_edit`]'s own real,
    /// committed [`wht_corulix_mutation::MutationResult::Deleted`] outcomes
    /// -- never from a caller-declared path, and never from anything this
    /// session merely *intended* to delete. This is the one piece of state
    /// a delete-kind session's real post-audit
    /// (`CorulixEngine::validate_change`'s `MutationKind::Delete` branch)
    /// needs to prove (a) every deleted target is genuinely still absent and
    /// (b) no other in-scope file still references its path text -- see
    /// `crate::validate_change`'s own module doc.
    deleted_targets: Vec<WorkspacePath>,
    /// F4 fix: every workspace-relative target this session has genuinely
    /// created or replaced, across the session's whole lifetime (never
    /// cleared -- mirrors [`Self::deleted_targets`]'s own discipline
    /// exactly). Populated exclusively from [`Self::submit_edit`]'s own
    /// real, committed [`wht_corulix_mutation::MutationResult::Created`]/
    /// [`wht_corulix_mutation::MutationResult::Replaced`] outcomes -- never
    /// from a caller-declared path. This is the state
    /// `CorulixEngine::validate_change`'s format-gate check needs: the exact
    /// set of files whose bytes this session actually changed, and
    /// therefore the only files a real formatter check must run against
    /// (`gate.format` has no opinion about files this session never
    /// touched).
    modified_targets: Vec<WorkspacePath>,
}

impl ChangeSession {
    /// Generates a CSPRNG-backed [`ChangeSessionId`] (`uuid` v4, backed by
    /// `getrandom` real OS entropy -- never
    /// `std::collections::hash_map::RandomState`, which
    /// `wht_corulix_workspace`'s own `WorkspaceIdentity` generation
    /// explicitly documents as inadequate for a security-relevant
    /// identifier). `CHANGE_SESSION_ID_PREDICTABLE=NO`.
    ///
    /// Returns `CorulixResult` rather than asserting infallibility: a
    /// `uuid::Uuid::new_v4().to_string()` is always exactly 36 bytes of
    /// hyphenated hex (never empty), so `from_opaque_token`'s `Err` path is
    /// unreachable here in practice -- but this crate follows the same
    /// "propagate honestly, never `.unwrap()`/`.expect()` away an
    /// unreachable case" convention `wht_corulix_workspace::resolver::generate_opaque_identity`
    /// already established for its own opaque-identity constructor.
    pub fn generate_id() -> wht_corulix_core::CorulixResult<ChangeSessionId> {
        ChangeSessionId::from_opaque_token(uuid::Uuid::new_v4().to_string())
    }

    /// Generates a CSPRNG-backed [`ConnectionId`], for a caller (e.g.
    /// `wht_corulix_mcp`) that has no `uuid` dependency of its own
    /// (Architecture Rule B) but needs a real connection identity to bind
    /// every `ChangeSession` it opens against for the process's lifetime --
    /// exactly one per stdio process, per this type's own doc comment.
    /// Same entropy source and same honest-propagation convention as
    /// [`Self::generate_id`].
    pub fn generate_connection_id() -> wht_corulix_core::CorulixResult<ConnectionId> {
        ConnectionId::from_opaque_token(uuid::Uuid::new_v4().to_string())
    }

    /// Opens a new session (`OPENED`). `executor` is caller-owned and
    /// caller-constructed against the exact [`wht_corulix_workspace::WorkspaceRoot`]
    /// this session governs -- this module never constructs one of its own
    /// (Rule M).
    #[must_use]
    pub fn open(
        id: ChangeSessionId,
        workspace_identity: WorkspaceIdentity,
        connection_id: ConnectionId,
        creation_sequence: u64,
        executor: MutationExecutor,
    ) -> Self {
        Self {
            id,
            workspace_identity,
            connection_id,
            scope: SessionScope::new(Vec::new()),
            creation_sequence,
            tool_plan: ToolPlan {
                intent: wht_corulix_core::OperationIntent::ValidateChange,
                mutation_kind: None,
                risk_class: None,
                requirements: Vec::new(),
                gates: Vec::new(),
                executability: PlanExecutability::Unexecutable {
                    reason: ReasonCode::RequiredCapabilityUnavailable,
                },
            },
            provider_snapshot: HashMap::new(),
            status: ChangeSessionStatus::Opened,
            evidence: Vec::new(),
            highest_sequence_seen: 0,
            content_snapshot_id: 0,
            last_edit_output_hash: None,
            executor,
            language: None,
            deleted_targets: Vec::new(),
            modified_targets: Vec::new(),
        }
    }

    #[must_use]
    pub fn id(&self) -> &ChangeSessionId {
        &self.id
    }

    /// This session's declared source language, when the caller named one
    /// at `begin_change` time. `None` for every pre-P15 call site (Rust
    /// default) and for a caller that genuinely did not declare one.
    #[must_use]
    pub fn language(&self) -> Option<LanguageId> {
        self.language
    }

    /// Sets this session's declared language. Not part of [`Self::open`]'s
    /// own constructor signature -- that would have forced every existing
    /// (Rust-implicit) call site across this crate's own test suite to
    /// change -- so this is `pub(crate)`, called exactly once by
    /// [`crate::begin_change`] immediately after `open`, before
    /// `enter_scope`/`baseline`.
    pub(crate) fn set_language(&mut self, language: Option<LanguageId>) {
        self.language = language;
    }

    #[must_use]
    pub fn status(&self) -> ChangeSessionStatus {
        self.status
    }

    #[must_use]
    pub fn tool_plan(&self) -> &ToolPlan {
        &self.tool_plan
    }

    #[must_use]
    pub fn creation_sequence(&self) -> u64 {
        self.creation_sequence
    }

    /// `OPENED -> SCOPED`. Fails closed on any transition attempted from a
    /// state other than `OPENED` (`INVALID_CHANGESESSION_TRANSITION_ACCEPT_COUNT=0`).
    pub fn enter_scope(&mut self, scope: SessionScope) -> Result<(), SessionError> {
        match self.status {
            ChangeSessionStatus::Opened => {
                self.scope = scope;
                self.status = ChangeSessionStatus::Scoped;
                Ok(())
            }
            _ => Err(denied(ReasonCode::InvalidSessionTransition)),
        }
    }

    /// `SCOPED -> BASELINED -> GatePending(first required gate)`, or
    /// straight to `Blocked(first required gate)` if `tool_plan` is
    /// [`PlanExecutability::Unexecutable`] -- a required-provider-missing
    /// plan is functionally identical to that gate having already failed
    /// (Phase 10 §16: `REQUIRED_PROVIDER_SILENT_DOWNGRADE_COUNT=0`, never
    /// silently converted into a lower-severity state). Only from `SCOPED`.
    pub fn baseline(
        &mut self,
        tool_plan: ToolPlan,
        provider_snapshot: Vec<EvidenceProvenance>,
    ) -> Result<(), SessionError> {
        if self.status != ChangeSessionStatus::Scoped {
            return Err(denied(ReasonCode::InvalidSessionTransition));
        }
        self.provider_snapshot = provider_snapshot
            .into_iter()
            .map(|provenance| (provenance.provider_id.clone(), provenance))
            .collect();
        let first_required = first_required_gate(&tool_plan);
        self.tool_plan = tool_plan;
        self.status = match (first_required, self.tool_plan.executability) {
            (Some(gate), PlanExecutability::Unexecutable { reason }) => {
                // Record the plan-level denial as a Failed record for the
                // first required gate so `change_status`/`complete_change`
                // see one coherent, auditable reason rather than an
                // unexplained permanent block.
                let sequence = self.next_sequence();
                self.evidence.push(EvidenceRecord {
                    evidence: synthetic_plan_denial_evidence(
                        &self.id,
                        &self.workspace_identity,
                        gate,
                        reason,
                        sequence,
                    )?,
                    status: GateStatus::Failed { reason },
                });
                ChangeSessionStatus::Blocked(gate)
            }
            (Some(gate), PlanExecutability::Executable) => ChangeSessionStatus::GatePending(gate),
            (None, _) => ChangeSessionStatus::ExitEvaluation,
            // `PlanExecutability` is `#[non_exhaustive]`: a hypothetical
            // future variant this arm doesn't know the correct handling for
            // fails closed to `Blocked`, never a silent `GatePending` that
            // would treat an unrecognized executability as "fine".
            (Some(gate), _) => {
                let sequence = self.next_sequence();
                self.evidence.push(EvidenceRecord {
                    evidence: synthetic_plan_denial_evidence(
                        &self.id,
                        &self.workspace_identity,
                        gate,
                        ReasonCode::RequiredCapabilityUnavailable,
                        sequence,
                    )?,
                    status: GateStatus::Failed {
                        reason: ReasonCode::RequiredCapabilityUnavailable,
                    },
                });
                ChangeSessionStatus::Blocked(gate)
            }
        };
        Ok(())
    }

    fn next_sequence(&mut self) -> u64 {
        self.highest_sequence_seen += 1;
        self.highest_sequence_seen
    }

    fn check_binding(
        &self,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
    ) -> Result<(), SessionError> {
        if matches!(
            self.status,
            ChangeSessionStatus::Completed | ChangeSessionStatus::Aborted
        ) {
            return Err(denied(ReasonCode::SessionAlreadyTerminal));
        }
        if requester_workspace != &self.workspace_identity {
            return Err(denied(ReasonCode::SessionWorkspaceMismatch));
        }
        if requester_connection != &self.connection_id {
            return Err(denied(ReasonCode::SessionConnectionMismatch));
        }
        Ok(())
    }

    fn current_pending_or_blocked_gate(&self) -> Option<GateId> {
        match self.status {
            ChangeSessionStatus::GatePending(gate) | ChangeSessionStatus::Blocked(gate) => {
                Some(gate)
            }
            _ => None,
        }
    }

    /// Whether `category` is a real, named requirement of this session's
    /// own bound [`ToolPlan`], and if so, under what [`AuthorityRole`] its
    /// Evidence may close a gate. `None` when `category` is not a
    /// requirement of this plan at all -- distinct from
    /// `Some(AuthorityRole::ForbiddenAsAuthority)`, which means the category
    /// *is* named but may never be authoritative.
    ///
    /// `pub(crate)` (not merely private) so a validator dispatcher outside
    /// this module -- [`crate::validate_change`] -- can decide *whether to
    /// spawn a provider at all* from the session's own plan (Minimum
    /// Sufficient Tooling: an unrequired provider must not run), rather than
    /// running it unconditionally and discovering irrelevance only when
    /// `record_evidence` rejects the result.
    pub(crate) fn requirement_authority(
        &self,
        category: ProviderCategory,
    ) -> Option<wht_corulix_core::AuthorityRole> {
        self.tool_plan
            .requirements
            .iter()
            .find(|requirement| requirement.category == category)
            .map(|requirement| requirement.authority)
    }

    fn gate_applicability(&self, gate: GateId) -> Option<GateApplicability> {
        self.tool_plan
            .gates
            .iter()
            .find(|requirement| requirement.gate == gate)
            .map(|requirement| requirement.applicability)
    }

    /// Records one [`Evidence`] item against `category`'s governing
    /// [`wht_corulix_core::ToolRequirement`], applying every binding/
    /// authority/staleness check before it can close (or fail) the gate it
    /// names. Never accepts an out-of-band narrative claim: the caller
    /// must have obtained `evidence` from a real provider call this
    /// module did not perform itself.
    pub fn record_evidence(
        &mut self,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        category: ProviderCategory,
        evidence: Evidence,
    ) -> Result<(), SessionError> {
        self.check_binding(requester_workspace, requester_connection)?;

        if &evidence.session_id != self.id() {
            return Err(denied(ReasonCode::EvidenceWrongSession));
        }
        if evidence.workspace_identity != self.workspace_identity {
            return Err(denied(ReasonCode::EvidenceWrongWorkspace));
        }
        if evidence.sequence <= self.highest_sequence_seen {
            return Err(denied(ReasonCode::EvidenceSequenceInvalid));
        }

        let applicability = self
            .gate_applicability(evidence.gate)
            .ok_or(denied(ReasonCode::ClientGateApplicabilityOverrideDenied))?;
        if matches!(applicability, GateApplicability::NotApplicable) {
            return Err(denied(ReasonCode::ClientGateApplicabilityOverrideDenied));
        }

        let authority = self
            .requirement_authority(category)
            .unwrap_or(wht_corulix_core::AuthorityRole::ForbiddenAsAuthority);
        if matches!(
            authority,
            wht_corulix_core::AuthorityRole::ForbiddenAsAuthority
        ) {
            return Err(denied(ReasonCode::EvidenceForbiddenAsAuthority));
        }

        if let Some(bound) = self.provider_snapshot.get(&evidence.provenance.provider_id)
            && bound.provider_version != evidence.provenance.provider_version
        {
            return Err(denied(ReasonCode::EvidenceProviderSnapshotMismatch));
        }

        if let Some(snapshot_id) = evidence.snapshot_id
            && snapshot_id != self.content_snapshot_id
        {
            return Err(denied(ReasonCode::EvidenceWrongSnapshot));
        }

        if matches!(applicability, GateApplicability::Required) {
            let current_gate = self.current_pending_or_blocked_gate();
            if current_gate != Some(evidence.gate) {
                return Err(denied(ReasonCode::InvalidSessionTransition));
            }
            if CONTENT_DEPENDENT_GATES.contains(&evidence.gate)
                && let Some(fingerprint) = &evidence.input_fingerprint
                && Some(fingerprint) != self.last_edit_output_hash.as_ref()
            {
                return Err(denied(ReasonCode::EvidenceStaleInputFingerprint));
            }
        }

        self.highest_sequence_seen = evidence.sequence;
        let gate = evidence.gate;
        let status = match evidence.reason {
            Some(reason) => GateStatus::Failed { reason },
            None => GateStatus::Passed,
        };
        self.evidence.push(EvidenceRecord { evidence, status });

        if matches!(applicability, GateApplicability::Required) {
            self.advance_after_required_gate(gate, status);
        }
        Ok(())
    }

    fn advance_after_required_gate(&mut self, gate: GateId, status: GateStatus) {
        match status {
            GateStatus::Passed => {
                self.status = match next_required_gate_after(&self.tool_plan, gate) {
                    Some(next) => ChangeSessionStatus::GatePending(next),
                    None => ChangeSessionStatus::ExitEvaluation,
                };
            }
            _ => {
                self.status = ChangeSessionStatus::Blocked(gate);
            }
        }
    }

    /// Applies `batch` through this session's own governed
    /// [`MutationExecutor`] -- the only live-write path this module ever
    /// uses (Rule M: `CHANGESESSION_DIRECT_HOST_WRITE_PATH_COUNT=0`).
    /// Requires the current gate to be [`GateId::Edit`], every target path
    /// to fall inside this session's bound [`SessionScope`]
    /// (`CHANGESESSION_SCOPE_ESCAPE_COUNT=0`), and the executor to be
    /// unlocked (a prior [`MutationError::RecoveryRequired`] permanently
    /// denies further writes from this session, per §48). On success,
    /// records the resulting `gate.edit` Evidence itself (the executor's
    /// own verified outcome *is* the evidence -- never a second, narrative
    /// claim about what the executor did) and invalidates every
    /// content-dependent gate's stale-now Evidence (see the module doc's
    /// invalidation graph).
    pub async fn submit_edit(
        &mut self,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        batch: MutationBatch,
        timestamp: wht_corulix_core::EvidenceTimestamp,
    ) -> Result<MutationOutcome, SessionError> {
        self.check_binding(requester_workspace, requester_connection)?;
        if self.executor.is_locked() {
            return Err(denied(ReasonCode::SessionMutationLocked));
        }
        // Unlike every other gate, `gate.edit` is not confined to a single
        // point in the walk: a session may legitimately submit a
        // *corrective* edit after later gates already passed (that is
        // exactly the scenario the invalidation graph below exists to
        // handle) or after an earlier gate failed. It is denied only
        // before baselining (`OPENED`/`SCOPED` -- no `ToolPlan`/scope is
        // bound yet) and while nonterminal is false (checked already by
        // `check_binding`'s terminal-state rejection).
        if matches!(
            self.status,
            ChangeSessionStatus::Opened | ChangeSessionStatus::Scoped
        ) {
            return Err(denied(ReasonCode::InvalidSessionTransition));
        }
        for path in batch.mutations.iter().flat_map(mutation_paths) {
            if !self.scope.permits(&path.relative_path) {
                return Err(denied(ReasonCode::SessionScopeViolation));
            }
        }

        let outcome = self
            .executor
            .execute(batch)
            .await
            .map_err(SessionError::Mutation)?;

        // F3 fix: retain every genuinely deleted target from this real,
        // committed outcome -- never from the caller's request, and never
        // from a mutation kind other than `Deleted` -- so a delete-kind
        // session's post-audit (`CorulixEngine::validate_change`) has real
        // state to check absence/dangling-references against.
        for result in &outcome.results {
            match result {
                wht_corulix_mutation::MutationResult::Deleted { path } => {
                    self.deleted_targets.push(path.clone());
                }
                // F4 fix: real, committed `Created`/`Replaced` outcomes are
                // exactly the set of files whose bytes this session actually
                // changed -- the only files `gate.format`'s real formatter
                // check needs to examine. `Moved` carries no new content
                // (its `hash` is the source's own unchanged bytes at the
                // destination path -- a move is not a rewrite), so it is
                // deliberately not tracked here: mirrors [`result_hash`]'s
                // own treatment of `Moved` as real but content-unchanged.
                wht_corulix_mutation::MutationResult::Created { path, .. }
                | wht_corulix_mutation::MutationResult::Replaced { path, .. } => {
                    self.modified_targets.push(path.clone());
                }
                wht_corulix_mutation::MutationResult::Moved { .. } => {}
            }
        }

        // The executor's own verified outcome *is* the Edit evidence --
        // never a second, narrative re-statement of what it did. A real
        // governed write always advances current-state identity (unlike
        // `advance_content_state`'s other caller, `submit_edit` never skips
        // this: `execute()` returning `Ok` already means the batch
        // genuinely committed).
        self.advance_content_state(outcome.results.iter().find_map(result_hash).cloned());
        let summary = wht_corulix_core::EvidenceResultSummary::try_from(format!(
            "{} mutation(s) committed and verified",
            outcome.results.len()
        ))
        .map_err(|_| denied(ReasonCode::EvidenceResultSummaryOversized))?;
        let sequence = self.next_sequence();
        self.evidence.push(EvidenceRecord {
            evidence: Evidence {
                session_id: self.id.clone(),
                workspace_identity: self.workspace_identity.clone(),
                gate: GateId::Edit,
                sequence,
                provenance: EvidenceProvenance {
                    provider_id: "wht_corulix_mutation::MutationExecutor".to_string(),
                    provider_version: None,
                    authority: wht_corulix_core::AuthorityRole::Authoritative,
                },
                scope: self.scope.0.clone(),
                input_fingerprint: self.last_edit_output_hash.clone(),
                result_summary: summary,
                reason: None,
                truncated: false,
                timestamp,
                snapshot_id: Some(self.content_snapshot_id),
            },
            status: GateStatus::Passed,
        });
        self.advance_after_required_gate(GateId::Edit, GateStatus::Passed);

        Ok(outcome)
    }

    /// The one canonical, session-owned governed format-write boundary
    /// (Phase 10-R2): `FORMAT + GOVERNED WORKSPACE WRITE + CHANGESESSION
    /// CONTENT-STATE ADVANCE` as one inseparable product operation, closing
    /// the gap where a caller could successfully commit formatted bytes
    /// through `session.executor()` directly and simply forget to call
    /// [`Self::advance_content_state`] afterward.
    ///
    /// Delegates the actual formatting/apply to the already-certified
    /// Phase 9 `wht_corulix_formatter::format_and_apply` -- this method
    /// invents no new formatter invocation and no new mutation-write path
    /// (`CHANGESESSION_DIRECT_FILESYSTEM_WRITE_COUNT=0`; the real write
    /// still happens exclusively inside `MutationExecutor`, reached here
    /// only via `self.executor.workspace_root()`/`&self.executor`, the same
    /// executor every other session write goes through). The formatter
    /// itself never establishes current-state identity
    /// (`FORMATTER_PROVIDER_STATE_AUTHORITY=NO`): only after
    /// `format_and_apply` returns `Ok` is its real, verified
    /// `output_hash` handed to [`Self::advance_content_state`] --
    /// `FORMAT_STATE_ADVANCE_HASH_SOURCE=VERIFIED_COMMITTED_MUTATION_OUTCOME`,
    /// never a caller-supplied, pre-format, or staged-but-uncommitted hash.
    ///
    /// State only ever advances on a genuine content change
    /// (`result.changed`) -- covers both a real invocation failure (every
    /// non-`Formatted`/`Unchanged` `FormatStatus` carries `changed: false`)
    /// and a genuine no-op (`FormatStatus::Unchanged`, already-formatted
    /// input) without a caller having to distinguish the two
    /// (`FORMAT_FAILURE_FALSE_STATE_ADVANCE_COUNT=0`,
    /// `NOOP_FORMAT_FALSE_STATE_ADVANCE_COUNT=0`). A commit-time
    /// `MutationError` (including `RecoveryRequired`) surfaces as
    /// `Err(SessionError::Formatter(FormatterError::Mutation(..)))` before
    /// this method ever reaches the advance step, so a failed or
    /// recovery-locked commit can never falsely advance state either
    /// (`FORMAT_COMMIT_FAILURE_FALSE_STATE_ADVANCE_COUNT=0`). This method
    /// records no Evidence itself (unlike [`Self::submit_edit`]'s tightly-
    /// coupled `gate.edit` record) -- the caller still records `gate.format`
    /// Evidence afterward via [`Self::record_evidence`], but by the time it
    /// does, [`Self::content_snapshot_id`] already reflects reality with no
    /// further action required.
    pub async fn format_and_apply(
        &mut self,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        effective: &wht_corulix_config::EffectiveConfig,
        path: WorkspacePath,
        input_max_bytes: u64,
        cancellation: &CancellationToken,
    ) -> Result<FormatterResult, SessionError> {
        self.check_binding(requester_workspace, requester_connection)?;
        if self.executor.is_locked() {
            return Err(denied(ReasonCode::SessionMutationLocked));
        }
        if matches!(
            self.status,
            ChangeSessionStatus::Opened | ChangeSessionStatus::Scoped
        ) {
            return Err(denied(ReasonCode::InvalidSessionTransition));
        }
        if !self.scope.permits(&path.relative_path) {
            return Err(denied(ReasonCode::SessionScopeViolation));
        }

        let workspace_root = self.executor.workspace_root().clone();
        let result = wht_corulix_formatter::format_and_apply(
            effective,
            workspace_root,
            &self.executor,
            path,
            input_max_bytes,
            cancellation,
        )
        .await
        .map_err(SessionError::Formatter)?;

        if result.changed {
            self.advance_content_state(result.output_hash.clone());
        }

        Ok(result)
    }

    /// Flips every `Current` [`GateStatus::Passed`] record for
    /// [`CONTENT_DEPENDENT_GATES`] to [`GateStatus::Stale`] in place. See
    /// the module doc's "Evidence invalidation graph" section. This method
    /// only marks records stale -- it does not itself decide the session's
    /// resulting status. Called exclusively from [`Self::advance_content_state`]
    /// (the one canonical state-advance path, Phase 10-R1 §13), so every
    /// real content-changing write invalidates in lockstep with advancing
    /// current-state identity, whether the write came from
    /// [`Self::submit_edit`] (which always follows with
    /// [`Self::advance_after_required_gate`]`(Edit, Passed)` -- whose
    /// `next_required_gate_after(Edit)` is, by construction, the earliest
    /// content-dependent gate in every current policy entry, since `Edit`
    /// is always immediately followed by `Format` where both are Required
    /// -- a second, independent "roll back to the earliest invalidated
    /// gate" computation here would only ever agree with that and risk
    /// silently diverging from it for a future policy shape) or from a
    /// formatter-driven caller (which records fresh `gate.format` Evidence
    /// itself afterward via [`Self::record_evidence`]).
    fn invalidate_content_dependent_evidence(&mut self) {
        for record in &mut self.evidence {
            if CONTENT_DEPENDENT_GATES.contains(&record.evidence.gate)
                && matches!(record.status, GateStatus::Passed)
            {
                record.status = GateStatus::Stale;
            }
        }
    }

    /// `EXIT_EVALUATION -> COMPLETED`, only if every `Required` gate in
    /// this session's `ToolPlan` has `Current` `Passed` Evidence bound to
    /// this exact session/workspace (Phase 10 §41-42's completion denial
    /// matrix). Otherwise the session is left/returned to `Blocked(gate)`
    /// naming the first offending gate, and `Err` names why
    /// (`COMPLETION_FALSE_SUCCESS_COUNT=0`: this method never returns `Ok`
    /// unless that full check passed).
    pub fn complete_change(
        &mut self,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
    ) -> Result<(), SessionError> {
        self.check_binding(requester_workspace, requester_connection)?;
        if self.executor.is_locked() {
            return Err(denied(ReasonCode::SessionMutationLocked));
        }
        if !matches!(
            self.status,
            ChangeSessionStatus::ExitEvaluation
                | ChangeSessionStatus::GatePending(_)
                | ChangeSessionStatus::Blocked(_)
        ) {
            return Err(denied(ReasonCode::InvalidSessionTransition));
        }

        for requirement in self.tool_plan.gates.clone() {
            if requirement.applicability != GateApplicability::Required {
                continue;
            }
            let latest = self
                .evidence
                .iter()
                .filter(|record| record.evidence.gate == requirement.gate)
                .max_by_key(|record| record.evidence.sequence);
            let reason = match latest {
                None => Some(ReasonCode::RequiredGateMissingEvidence),
                Some(record) => match record.status {
                    GateStatus::Passed => None,
                    GateStatus::Failed { reason } => Some(reason),
                    GateStatus::Stale => Some(ReasonCode::RequiredGateEvidenceStale),
                    GateStatus::Pending => Some(ReasonCode::RequiredGateMissingEvidence),
                    _ => Some(ReasonCode::RequiredGateMissingEvidence),
                },
            };
            if let Some(reason) = reason {
                self.status = ChangeSessionStatus::Blocked(requirement.gate);
                return Err(denied(reason));
            }
        }

        self.status = ChangeSessionStatus::Completed;
        Ok(())
    }

    /// Any nonterminal state `-> ABORTED` (terminal;
    /// `AUTO_RESTORE_BASELINE=NO` -- this performs no filesystem
    /// restoration of any kind, per Phase 10 §14).
    pub fn abort(
        &mut self,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
    ) -> Result<(), SessionError> {
        self.check_binding(requester_workspace, requester_connection)?;
        self.status = ChangeSessionStatus::Aborted;
        Ok(())
    }

    /// An audit-safe structured view of this session's current state
    /// (Phase 10 §64) -- never exposes a raw workspace path or secret.
    #[must_use]
    pub fn change_status(&self) -> ChangeStatusView {
        let required_gates: Vec<GateId> = self
            .tool_plan
            .gates
            .iter()
            .filter(|requirement| requirement.applicability == GateApplicability::Required)
            .map(|requirement| requirement.gate)
            .collect();
        let mut passed_gates = Vec::new();
        let mut failed_gates = Vec::new();
        let mut stale_gates = Vec::new();
        for gate in &required_gates {
            let latest = self
                .evidence
                .iter()
                .filter(|record| record.evidence.gate == *gate)
                .max_by_key(|record| record.evidence.sequence);
            match latest.map(|record| record.status) {
                Some(GateStatus::Passed) => passed_gates.push(*gate),
                Some(GateStatus::Failed { reason }) => failed_gates.push((*gate, reason)),
                Some(GateStatus::Stale) => stale_gates.push(*gate),
                _ => {}
            }
        }
        let completion_eligible = required_gates.len() == passed_gates.len()
            && !self.executor.is_locked()
            && !matches!(
                self.status,
                ChangeSessionStatus::Completed | ChangeSessionStatus::Aborted
            );
        ChangeStatusView {
            session_id: self.id.clone(),
            status: self.status,
            required_gates,
            passed_gates,
            failed_gates,
            stale_gates,
            completion_eligible,
        }
    }

    /// The full, never-truncated Evidence history for this session,
    /// including every `Stale`/`Failed` record -- audit history is
    /// preserved, never deleted (Phase 10 §33).
    #[must_use]
    pub fn evidence_history(&self) -> &[EvidenceRecord] {
        &self.evidence
    }

    /// This session's own governed [`MutationExecutor`] -- the ONE live
    /// write path this session ever uses. Exposed read-only, primarily for
    /// `is_locked()` observability (e.g. a caller checking recovery-lock
    /// state before attempting further work). As of Phase 10-R2, normal
    /// governed formatting no longer goes through this accessor at all --
    /// [`Self::format_and_apply`] is the one canonical, session-owned
    /// format-write boundary, and it reaches
    /// `wht_corulix_formatter::format_and_apply` internally without ever
    /// handing a raw executor reference to caller code
    /// (`PRODUCTION_CHANGESESSION_RAW_FORMAT_AND_APPLY_BYPASS_COUNT=0`).
    /// This accessor still does not itself create a second write path: it
    /// is read-only, and every write through the returned reference would
    /// still update the one shared `locked` flag [`Self::submit_edit`] and
    /// [`Self::format_and_apply`] both observe.
    #[must_use]
    pub fn executor(&self) -> &MutationExecutor {
        &self.executor
    }

    /// This session's bound [`SessionScope`], read-only. See
    /// [`SessionScope::prefixes`]'s own doc comment for why a
    /// language-specific `validate_change` dispatcher needs this.
    #[must_use]
    pub fn scope(&self) -> &SessionScope {
        &self.scope
    }

    /// This session's current governed-content-state identity -- the
    /// authority every `snapshot_id`-bearing [`wht_corulix_core::Evidence`]
    /// must match to be accepted as current (Phase 10-R1 §9-10: current
    /// content-state identity is owned exclusively by `ChangeSession`/
    /// Engine, never by a formatter, provider, or client).
    #[must_use]
    pub fn content_snapshot_id(&self) -> u64 {
        self.content_snapshot_id
    }

    /// The output hash of the most recent content-changing write this
    /// session recorded (`submit_edit`/`format_and_apply`), if any. Phase
    /// 13's `validate_change` reads this to stamp its own `gate.diagnostics`
    /// Evidence's `input_fingerprint` -- the same field
    /// [`Self::record_evidence`] itself checks content-dependent Evidence
    /// against (see `CONTENT_DEPENDENT_GATES`).
    #[must_use]
    pub fn last_edit_output_hash(&self) -> Option<&ContentHash> {
        self.last_edit_output_hash.as_ref()
    }

    /// F3 fix: every workspace-relative target this session has genuinely
    /// deleted so far, in commit order. See [`Self::deleted_targets`]'s own
    /// field doc for provenance/invariants. `CorulixEngine::validate_change`'s
    /// delete-kind post-audit path reads this to know what to re-verify.
    #[must_use]
    pub fn deleted_targets(&self) -> &[WorkspacePath] {
        &self.deleted_targets
    }

    /// F4 fix: every workspace-relative target this session has genuinely
    /// created or replaced so far, in commit order. See
    /// [`Self::modified_targets`]'s own field doc for provenance/invariants.
    /// `CorulixEngine::validate_change`'s format-gate check reads this to
    /// know which files a real formatter must examine.
    #[must_use]
    pub(crate) fn modified_targets(&self) -> &[WorkspacePath] {
        &self.modified_targets
    }

    /// The single canonical state-advance API (Phase 10-R1 §13/§43; made
    /// internal-only by Phase 10-R2 §13): every governed write that
    /// genuinely changes this session's tracked source bytes advances
    /// current-state identity through this one method, never a second,
    /// parallel snapshot mechanism. `output_hash` carries whatever
    /// content-identity metadata the real write's own outcome provided
    /// (`None` is a legitimate value, e.g. a delete-only batch has no
    /// resulting file bytes to hash); it is stored as
    /// `last_edit_output_hash` and checked verbatim against any future
    /// Evidence's `input_fingerprint`.
    ///
    /// As of Phase 10-R2, this method has exactly two callers, both inside
    /// this module: [`Self::submit_edit`] (always, since a successful
    /// `MutationExecutor::execute` is definitionally a real committed
    /// write) and [`Self::format_and_apply`] (only when the formatter's own
    /// real outcome reports a genuine content change --
    /// `MANUAL_FORMAT_STATE_ADVANCE_REQUIRED_BY_PRODUCT_CALLER=NO`: no
    /// external caller need invoke this directly for the format workflow
    /// any more; use [`Self::format_and_apply`] instead). It remains `pub`
    /// only because a primitive this fundamental may have a legitimate
    /// future governed-write caller beyond formatting -- not because the
    /// format workflow still needs external access to it.
    ///
    /// The formatter (or any other governed-write component) never calls
    /// this itself and never declares its own result "current" -- per
    /// Phase 10-R1 §10/§41, only Engine/`ChangeSession` may establish
    /// current-state identity; a provider's role ends at returning a real,
    /// verified outcome for the *caller* to hand to this method
    /// (`FORMAT_STATE_ADVANCE_HASH_SOURCE=VERIFIED_COMMITTED_MUTATION_OUTCOME`).
    ///
    /// Every currently-`Passed` content-dependent gate
    /// (`CONTENT_DEPENDENT_GATES`) is invalidated to `Stale` as part of
    /// this same call -- the invalidation graph and the state-identity
    /// mechanism both fire together on every real advance.
    pub fn advance_content_state(&mut self, output_hash: Option<ContentHash>) -> u64 {
        self.content_snapshot_id += 1;
        self.last_edit_output_hash = output_hash;
        self.invalidate_content_dependent_evidence();
        self.content_snapshot_id
    }
}

fn result_hash(result: &wht_corulix_mutation::MutationResult) -> Option<&ContentHash> {
    match result {
        wht_corulix_mutation::MutationResult::Created { hash, .. }
        | wht_corulix_mutation::MutationResult::Replaced { hash, .. }
        | wht_corulix_mutation::MutationResult::Moved { hash, .. } => Some(hash),
        wht_corulix_mutation::MutationResult::Deleted { .. } => None,
    }
}

fn mutation_paths(mutation: &Mutation) -> Vec<&WorkspacePath> {
    match mutation {
        Mutation::CreateFile { path, .. }
        | Mutation::ApplyTextEdits { path, .. }
        | Mutation::ReplaceFile { path, .. }
        | Mutation::DeleteFile { path, .. } => vec![path],
        Mutation::MoveFile {
            source,
            destination,
            ..
        } => vec![source, destination],
    }
}

fn first_required_gate(plan: &ToolPlan) -> Option<GateId> {
    plan.gates
        .iter()
        .find(|requirement| requirement.applicability == GateApplicability::Required)
        .map(|requirement| requirement.gate)
}

fn gate_index(plan: &ToolPlan, gate: GateId) -> usize {
    plan.gates
        .iter()
        .position(|requirement| requirement.gate == gate)
        .unwrap_or(usize::MAX)
}

fn next_required_gate_after(plan: &ToolPlan, gate: GateId) -> Option<GateId> {
    let position = gate_index(plan, gate);
    plan.gates
        .iter()
        .skip(position.saturating_add(1))
        .find(|requirement| requirement.applicability == GateApplicability::Required)
        .map(|requirement| requirement.gate)
}

fn synthetic_plan_denial_evidence(
    session_id: &ChangeSessionId,
    workspace_identity: &WorkspaceIdentity,
    gate: GateId,
    reason: ReasonCode,
    sequence: u64,
) -> Result<Evidence, SessionError> {
    let summary = wht_corulix_core::EvidenceResultSummary::try_from(
        "ToolPlan unexecutable at baseline: required provider unavailable".to_string(),
    )
    .map_err(|_| denied(ReasonCode::EvidenceResultSummaryOversized))?;
    Ok(Evidence {
        session_id: session_id.clone(),
        workspace_identity: workspace_identity.clone(),
        gate,
        sequence,
        provenance: EvidenceProvenance {
            provider_id: "wht_corulix_engine::session::baseline".to_string(),
            provider_version: None,
            authority: wht_corulix_core::AuthorityRole::Authoritative,
        },
        scope: Vec::new(),
        input_fingerprint: None,
        result_summary: summary,
        reason: Some(reason),
        truncated: false,
        timestamp: wht_corulix_core::EvidenceTimestamp(0),
        snapshot_id: None,
    })
}

/// Phase 13: the kind of single-file edit `wht_corulix_mcp`'s `submit_edit`
/// tool may request -- deliberately a small, closed, MCP-safe vocabulary
/// (never a raw client-supplied `Mutation` variant name) that
/// [`single_file_batch`] translates into a real [`Mutation`].
#[derive(Debug, Clone)]
pub enum EditRequestKind {
    /// [`Mutation::CreateFile`]: the target must not already exist.
    Create { content: Vec<u8> },
    /// [`Mutation::ReplaceFile`], gated on `expected_precondition_hash_hex`
    /// (a hex-encoded SHA-256 digest of the target's current bytes).
    Replace {
        expected_precondition_hash_hex: String,
        content: Vec<u8>,
    },
    /// [`Mutation::DeleteFile`], gated on `expected_precondition_hash_hex`.
    Delete {
        expected_precondition_hash_hex: String,
    },
}

/// Builds a single-mutation [`MutationBatch`] from MCP-safe primitives --
/// the one place `wht_corulix_mcp`'s `submit_edit` tool constructs a real
/// `MutationBatch`/`Mutation` without depending on `wht_corulix_mutation`
/// directly (Architecture Rule B). Always targets [`wht_corulix_core::WorkspaceRootId`]`(0)`:
/// Phase 13 scopes `submit_edit` to the session's own single bound root,
/// mirroring `begin_change`'s own single-root-selector scope -- true
/// multi-root-scoped mutation targeting through the MCP surface is a
/// distinct, later piece of work.
#[must_use]
pub fn single_file_batch(relative_path: String, kind: EditRequestKind) -> MutationBatch {
    let path = WorkspacePath {
        root: wht_corulix_core::WorkspaceRootId(0),
        relative_path,
    };
    let mutation = match kind {
        EditRequestKind::Create { content } => Mutation::CreateFile { path, content },
        EditRequestKind::Replace {
            expected_precondition_hash_hex,
            content,
        } => Mutation::ReplaceFile {
            path,
            expected_precondition_hash: ContentHash {
                algorithm: wht_corulix_core::ContentHashAlgorithm::Sha256,
                digest_hex: expected_precondition_hash_hex,
            },
            content,
        },
        EditRequestKind::Delete {
            expected_precondition_hash_hex,
        } => Mutation::DeleteFile {
            path,
            expected_precondition_hash: ContentHash {
                algorithm: wht_corulix_core::ContentHashAlgorithm::Sha256,
                digest_hex: expected_precondition_hash_hex,
            },
        },
    };
    MutationBatch {
        mutations: vec![mutation],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::{
        AuthorityRole, EvidenceResultSummary, EvidenceTimestamp, GateRequirement, MutationKind,
        OperationIntent, RiskClass, ToolApplicability, ToolRequirement,
    };
    use wht_corulix_workspace::WorkspaceRoot;

    fn temp_workspace_root(label: &str) -> Result<WorkspaceRoot, Box<dyn Error>> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!("corulix-p10-session-test-{label}-{stamp}"));
        fs::create_dir_all(&path)?;
        Ok(WorkspaceRoot::open(&path)?)
    }

    fn workspace_identity(token: &str) -> Result<WorkspaceIdentity, Box<dyn Error>> {
        Ok(WorkspaceIdentity::from_opaque_token(token.to_string())?)
    }

    fn connection_id(token: &str) -> Result<ConnectionId, Box<dyn Error>> {
        Ok(ConnectionId::from_opaque_token(token.to_string())?)
    }

    /// One representative `ToolPlan`: `Discovery`/`Edit`/`Format` are
    /// `Required` (mirroring `SOURCE_MODIFY`'s real policy shape),
    /// `Diagnostics` is `Optional`, `PostAudit` is `NotApplicable` --
    /// deliberately covering all three non-Required applicability states
    /// in one plan, plus a `Supporting`/`ForbiddenAsAuthority` requirement
    /// (`StructuralParse`) that must never be able to close a gate.
    fn test_tool_plan() -> ToolPlan {
        ToolPlan {
            intent: OperationIntent::SourceModify,
            mutation_kind: Some(MutationKind::Modify),
            risk_class: Some(RiskClass::Elevated),
            requirements: vec![
                ToolRequirement {
                    category: ProviderCategory::TextSearch,
                    applicability: ToolApplicability::Required,
                    authority: AuthorityRole::Authoritative,
                },
                ToolRequirement {
                    category: ProviderCategory::Formatter,
                    applicability: ToolApplicability::Required,
                    authority: AuthorityRole::SupportingOnly,
                },
                ToolRequirement {
                    category: ProviderCategory::StructuralParse,
                    applicability: ToolApplicability::Supporting,
                    authority: AuthorityRole::ForbiddenAsAuthority,
                },
            ],
            gates: vec![
                GateRequirement {
                    gate: GateId::Discovery,
                    applicability: GateApplicability::Required,
                },
                GateRequirement {
                    gate: GateId::Edit,
                    applicability: GateApplicability::Required,
                },
                GateRequirement {
                    gate: GateId::Format,
                    applicability: GateApplicability::Required,
                },
                GateRequirement {
                    gate: GateId::Diagnostics,
                    applicability: GateApplicability::Optional,
                },
                GateRequirement {
                    gate: GateId::PostAudit,
                    applicability: GateApplicability::NotApplicable,
                },
            ],
            executability: PlanExecutability::Executable,
        }
    }

    fn passing_evidence(
        session: &ChangeSession,
        workspace: &WorkspaceIdentity,
        gate: GateId,
        category: ProviderCategory,
        sequence: u64,
    ) -> Result<Evidence, Box<dyn Error>> {
        let _ = category;
        Ok(Evidence {
            session_id: session.id().clone(),
            workspace_identity: workspace.clone(),
            gate,
            sequence,
            provenance: EvidenceProvenance {
                provider_id: "test-provider".to_string(),
                provider_version: None,
                authority: AuthorityRole::Authoritative,
            },
            scope: Vec::new(),
            input_fingerprint: None,
            result_summary: EvidenceResultSummary::try_from("ok".to_string())?,
            reason: None,
            truncated: false,
            timestamp: EvidenceTimestamp(1),
            snapshot_id: None,
        })
    }

    /// Opens, scopes, and baselines a session against [`test_tool_plan`] in
    /// one call -- every test below starts from this exact state
    /// (`GatePending(Discovery)`).
    fn opened_baselined_session(
        label: &str,
    ) -> Result<(ChangeSession, WorkspaceIdentity, ConnectionId), Box<dyn Error>> {
        let root = temp_workspace_root(label)?;
        let workspace = workspace_identity(&format!("wsid-{label}"))?;
        let connection = connection_id(&format!("conn-{label}"))?;
        let mut session = ChangeSession::open(
            ChangeSession::generate_id()?,
            workspace.clone(),
            connection.clone(),
            1,
            MutationExecutor::new(root),
        );
        session.enter_scope(SessionScope::new(vec![String::new()]))?;
        session.baseline(test_tool_plan(), Vec::new())?;
        Ok((session, workspace, connection))
    }

    #[test]
    fn generated_session_ids_are_distinct() -> Result<(), Box<dyn Error>> {
        let a = ChangeSession::generate_id()?;
        let b = ChangeSession::generate_id()?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn opened_session_is_not_gate_pending() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace_root("opened")?;
        let session = ChangeSession::open(
            ChangeSession::generate_id()?,
            workspace_identity("wsid-opened")?,
            connection_id("conn-opened")?,
            1,
            MutationExecutor::new(root),
        );
        assert_eq!(session.status(), ChangeSessionStatus::Opened);
        Ok(())
    }

    #[test]
    fn scope_before_baseline_is_the_only_valid_first_transition() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace_root("scope-order")?;
        let mut session = ChangeSession::open(
            ChangeSession::generate_id()?,
            workspace_identity("wsid-scope-order")?,
            connection_id("conn-scope-order")?,
            1,
            MutationExecutor::new(root),
        );
        // BASELINED attempted before SCOPED must fail closed.
        assert_eq!(
            session.baseline(test_tool_plan(), Vec::new()),
            Err(SessionError::Denied(ReasonCode::InvalidSessionTransition))
        );
        session.enter_scope(SessionScope::new(Vec::new()))?;
        assert_eq!(session.status(), ChangeSessionStatus::Scoped);
        // SCOPED attempted a second time must also fail closed.
        assert_eq!(
            session.enter_scope(SessionScope::new(Vec::new())),
            Err(SessionError::Denied(ReasonCode::InvalidSessionTransition))
        );
        Ok(())
    }

    #[test]
    fn baseline_lands_on_first_required_gate() -> Result<(), Box<dyn Error>> {
        let (session, ..) = opened_baselined_session("baseline-first-gate")?;
        assert_eq!(
            session.status(),
            ChangeSessionStatus::GatePending(GateId::Discovery)
        );
        Ok(())
    }

    #[test]
    fn unexecutable_plan_blocks_at_baseline_without_downgrading_severity()
    -> Result<(), Box<dyn Error>> {
        let root = temp_workspace_root("unexecutable")?;
        let mut session = ChangeSession::open(
            ChangeSession::generate_id()?,
            workspace_identity("wsid-unexecutable")?,
            connection_id("conn-unexecutable")?,
            1,
            MutationExecutor::new(root),
        );
        session.enter_scope(SessionScope::new(Vec::new()))?;
        let mut plan = test_tool_plan();
        plan.executability = PlanExecutability::Unexecutable {
            reason: ReasonCode::RequiredProviderUnavailable,
        };
        session.baseline(plan, Vec::new())?;
        assert_eq!(
            session.status(),
            ChangeSessionStatus::Blocked(GateId::Discovery)
        );
        let status = session.change_status();
        assert_eq!(
            status.failed_gates,
            vec![(GateId::Discovery, ReasonCode::RequiredProviderUnavailable)]
        );
        Ok(())
    }

    #[test]
    fn invalid_transitions_are_denied() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("invalid-transition")?;
        // COMPLETED attempted while still GatePending(Discovery) with no
        // Evidence at all must be denied -- via the completion denial
        // matrix, not a bare state-machine short-circuit, but denied
        // either way.
        assert!(session.complete_change(&workspace, &connection).is_err());
        session.abort(&workspace, &connection)?;
        assert_eq!(session.status(), ChangeSessionStatus::Aborted);
        Ok(())
    }

    #[tokio::test]
    async fn terminal_session_rejects_every_further_mutation() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("terminal-immutable")?;
        session.abort(&workspace, &connection)?;

        assert_eq!(
            session.abort(&workspace, &connection),
            Err(SessionError::Denied(ReasonCode::SessionAlreadyTerminal))
        );
        assert_eq!(
            session.complete_change(&workspace, &connection),
            Err(SessionError::Denied(ReasonCode::SessionAlreadyTerminal))
        );
        let evidence = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            2,
        )?;
        assert_eq!(
            session.record_evidence(
                &workspace,
                &connection,
                ProviderCategory::TextSearch,
                evidence
            ),
            Err(SessionError::Denied(ReasonCode::SessionAlreadyTerminal))
        );
        let outcome = session
            .submit_edit(
                &workspace,
                &connection,
                MutationBatch::default(),
                EvidenceTimestamp(1),
            )
            .await;
        assert_eq!(
            outcome,
            Err(SessionError::Denied(ReasonCode::SessionAlreadyTerminal))
        );
        Ok(())
    }

    #[test]
    fn workspace_identity_mismatch_is_denied() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("workspace-mismatch")?;
        let evidence = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            2,
        )?;
        let wrong_workspace = workspace_identity("wsid-attacker")?;
        assert_eq!(
            session.record_evidence(
                &wrong_workspace,
                &connection,
                ProviderCategory::TextSearch,
                evidence
            ),
            Err(SessionError::Denied(ReasonCode::SessionWorkspaceMismatch))
        );
        Ok(())
    }

    #[test]
    fn connection_identity_mismatch_is_denied() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, _connection) =
            opened_baselined_session("connection-mismatch")?;
        let evidence = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            2,
        )?;
        let attacker_connection = connection_id("conn-attacker")?;
        assert_eq!(
            session.record_evidence(
                &workspace,
                &attacker_connection,
                ProviderCategory::TextSearch,
                evidence
            ),
            Err(SessionError::Denied(ReasonCode::SessionConnectionMismatch))
        );
        Ok(())
    }

    #[test]
    fn evidence_from_a_different_session_is_rejected() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("wrong-session")?;
        let mut evidence = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            2,
        )?;
        evidence.session_id = ChangeSession::generate_id()?;
        assert_eq!(
            session.record_evidence(
                &workspace,
                &connection,
                ProviderCategory::TextSearch,
                evidence
            ),
            Err(SessionError::Denied(ReasonCode::EvidenceWrongSession))
        );
        Ok(())
    }

    #[test]
    fn evidence_for_a_different_workspace_is_rejected() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("wrong-workspace")?;
        let mut evidence = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            2,
        )?;
        evidence.workspace_identity = workspace_identity("wsid-elsewhere")?;
        assert_eq!(
            session.record_evidence(
                &workspace,
                &connection,
                ProviderCategory::TextSearch,
                evidence
            ),
            Err(SessionError::Denied(ReasonCode::EvidenceWrongWorkspace))
        );
        Ok(())
    }

    #[test]
    fn duplicate_and_regressive_evidence_sequences_are_rejected() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("evidence-sequence")?;
        let first = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            5,
        )?;
        session.record_evidence(&workspace, &connection, ProviderCategory::TextSearch, first)?;

        let duplicate = passing_evidence(
            &session,
            &workspace,
            GateId::Edit,
            ProviderCategory::TextSearch,
            5,
        )?;
        assert_eq!(
            session.record_evidence(
                &workspace,
                &connection,
                ProviderCategory::TextSearch,
                duplicate
            ),
            Err(SessionError::Denied(ReasonCode::EvidenceSequenceInvalid))
        );

        let regressive = passing_evidence(
            &session,
            &workspace,
            GateId::Edit,
            ProviderCategory::TextSearch,
            3,
        )?;
        assert_eq!(
            session.record_evidence(
                &workspace,
                &connection,
                ProviderCategory::TextSearch,
                regressive
            ),
            Err(SessionError::Denied(ReasonCode::EvidenceSequenceInvalid))
        );
        Ok(())
    }

    #[test]
    fn forbidden_as_authority_evidence_can_never_close_a_gate() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) =
            opened_baselined_session("forbidden-as-authority")?;
        let evidence = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::StructuralParse,
            2,
        )?;
        assert_eq!(
            session.record_evidence(
                &workspace,
                &connection,
                ProviderCategory::StructuralParse,
                evidence
            ),
            Err(SessionError::Denied(
                ReasonCode::EvidenceForbiddenAsAuthority
            ))
        );
        Ok(())
    }

    #[test]
    fn client_cannot_submit_evidence_for_a_not_applicable_gate() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("not-applicable")?;
        let evidence = passing_evidence(
            &session,
            &workspace,
            GateId::PostAudit,
            ProviderCategory::TextSearch,
            2,
        )?;
        assert_eq!(
            session.record_evidence(
                &workspace,
                &connection,
                ProviderCategory::TextSearch,
                evidence
            ),
            Err(SessionError::Denied(
                ReasonCode::ClientGateApplicabilityOverrideDenied
            ))
        );
        Ok(())
    }

    #[test]
    fn evidence_out_of_gate_order_is_denied() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("out-of-order")?;
        // Session is GatePending(Discovery); offering Edit evidence first
        // must be denied, never silently accepted out of ToolPlan order.
        let evidence = passing_evidence(
            &session,
            &workspace,
            GateId::Edit,
            ProviderCategory::TextSearch,
            2,
        )?;
        assert_eq!(
            session.record_evidence(
                &workspace,
                &connection,
                ProviderCategory::TextSearch,
                evidence
            ),
            Err(SessionError::Denied(ReasonCode::InvalidSessionTransition))
        );
        Ok(())
    }

    #[test]
    fn required_gate_missing_evidence_blocks_completion() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("missing-evidence")?;
        assert_eq!(
            session.complete_change(&workspace, &connection),
            Err(SessionError::Denied(
                ReasonCode::RequiredGateMissingEvidence
            ))
        );
        assert_eq!(
            session.status(),
            ChangeSessionStatus::Blocked(GateId::Discovery)
        );
        Ok(())
    }

    #[test]
    fn required_gate_failure_blocks_and_corrective_retry_recovers() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("corrective-retry")?;
        let mut failing = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            2,
        )?;
        failing.reason = Some(ReasonCode::RequiredCapabilityUnavailable);
        session.record_evidence(
            &workspace,
            &connection,
            ProviderCategory::TextSearch,
            failing,
        )?;
        assert_eq!(
            session.status(),
            ChangeSessionStatus::Blocked(GateId::Discovery)
        );

        // A corrective retry for the SAME gate, now Passed, must recover
        // and advance -- the failed gate never vanishes on its own, but a
        // valid replacement Evidence is accepted (§39: corrective mutation
        // retry flow).
        let corrected = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            3,
        )?;
        session.record_evidence(
            &workspace,
            &connection,
            ProviderCategory::TextSearch,
            corrected,
        )?;
        assert_eq!(
            session.status(),
            ChangeSessionStatus::GatePending(GateId::Edit)
        );
        Ok(())
    }

    #[test]
    fn optional_gate_absence_never_blocks_completion() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("optional-gate")?;
        for (gate, category, sequence) in [
            (GateId::Discovery, ProviderCategory::TextSearch, 2),
            (GateId::Edit, ProviderCategory::TextSearch, 3),
            (GateId::Format, ProviderCategory::Formatter, 4),
        ] {
            let evidence = passing_evidence(&session, &workspace, gate, category, sequence)?;
            session.record_evidence(&workspace, &connection, category, evidence)?;
        }
        // GateId::Diagnostics is Optional and GateId::PostAudit is
        // NotApplicable -- neither has any Evidence, and completion must
        // still succeed (`OPTIONAL_GATE_ESCALATED_TO_REQUIRED_COUNT=0`).
        assert_eq!(session.status(), ChangeSessionStatus::ExitEvaluation);
        session.complete_change(&workspace, &connection)?;
        assert_eq!(session.status(), ChangeSessionStatus::Completed);
        Ok(())
    }

    #[test]
    fn full_happy_path_completes() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("happy-path")?;
        for (gate, category, sequence) in [
            (GateId::Discovery, ProviderCategory::TextSearch, 2),
            (GateId::Edit, ProviderCategory::TextSearch, 3),
            (GateId::Format, ProviderCategory::Formatter, 4),
            (GateId::Diagnostics, ProviderCategory::TextSearch, 5),
        ] {
            let evidence = passing_evidence(&session, &workspace, gate, category, sequence)?;
            session.record_evidence(&workspace, &connection, category, evidence)?;
        }
        session.complete_change(&workspace, &connection)?;
        assert_eq!(session.status(), ChangeSessionStatus::Completed);
        let status = session.change_status();
        assert!(status.failed_gates.is_empty());
        assert!(status.stale_gates.is_empty());
        assert_eq!(status.passed_gates.len(), 3);
        Ok(())
    }

    /// `complete_change` must name the actual first offending Required gate
    /// found while walking the ordered `ToolPlan`, not merely repeat the
    /// session's original entry gate. With `Discovery` already Passed, the
    /// blocking gate must be `Edit` -- proving the denial matrix reports the
    /// gate an operator actually needs to act on, not a misleading one.
    #[test]
    fn blocked_gate_names_the_actual_offending_gate_not_the_first_gate()
    -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("offending-gate")?;
        let discovery = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            2,
        )?;
        session.record_evidence(
            &workspace,
            &connection,
            ProviderCategory::TextSearch,
            discovery,
        )?;
        assert_eq!(
            session.status(),
            ChangeSessionStatus::GatePending(GateId::Edit)
        );

        assert_eq!(
            session.complete_change(&workspace, &connection),
            Err(SessionError::Denied(
                ReasonCode::RequiredGateMissingEvidence
            ))
        );
        assert_eq!(session.status(), ChangeSessionStatus::Blocked(GateId::Edit));
        // `Edit` has no Evidence at all (missing, not failed), so it is
        // absent from both `passed_gates` and `failed_gates` -- the
        // `Blocked(gate)` status itself is the authority on which gate is
        // offending, which is exactly what this test verifies.
        let status = session.change_status();
        assert!(!status.passed_gates.contains(&GateId::Edit));
        assert!(status.failed_gates.is_empty());
        Ok(())
    }

    /// `COMPLETED` is terminal (§69: `POST_COMPLETION_SESSION_MUTATION_COUNT
    /// =0`) -- mirrors `terminal_session_rejects_every_further_mutation`,
    /// which only covers post-`ABORTED`.
    #[tokio::test]
    async fn completed_session_rejects_every_further_mutation() -> Result<(), Box<dyn Error>> {
        let (mut session, workspace, connection) = opened_baselined_session("post-completion")?;
        for (gate, category, sequence) in [
            (GateId::Discovery, ProviderCategory::TextSearch, 2),
            (GateId::Edit, ProviderCategory::TextSearch, 3),
            (GateId::Format, ProviderCategory::Formatter, 4),
            (GateId::Diagnostics, ProviderCategory::TextSearch, 5),
        ] {
            let evidence = passing_evidence(&session, &workspace, gate, category, sequence)?;
            session.record_evidence(&workspace, &connection, category, evidence)?;
        }
        session.complete_change(&workspace, &connection)?;
        assert_eq!(session.status(), ChangeSessionStatus::Completed);

        assert_eq!(
            session.complete_change(&workspace, &connection),
            Err(SessionError::Denied(ReasonCode::SessionAlreadyTerminal))
        );
        assert_eq!(
            session.abort(&workspace, &connection),
            Err(SessionError::Denied(ReasonCode::SessionAlreadyTerminal))
        );
        let extra = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            6,
        )?;
        assert_eq!(
            session.record_evidence(&workspace, &connection, ProviderCategory::TextSearch, extra),
            Err(SessionError::Denied(ReasonCode::SessionAlreadyTerminal))
        );
        let outcome = session
            .submit_edit(
                &workspace,
                &connection,
                MutationBatch::default(),
                EvidenceTimestamp(7),
            )
            .await;
        assert_eq!(
            outcome,
            Err(SessionError::Denied(ReasonCode::SessionAlreadyTerminal))
        );
        assert_eq!(session.status(), ChangeSessionStatus::Completed);
        Ok(())
    }

    #[tokio::test]
    async fn submit_edit_outside_scope_is_denied() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace_root("scope-violation")?;
        fs::create_dir_all(root.canonical_path().join("src"))?;
        fs::write(root.canonical_path().join("src/lib.rs"), b"fn a() {}\n")?;
        let workspace = workspace_identity("wsid-scope-violation")?;
        let connection = connection_id("conn-scope-violation")?;
        let mut session = ChangeSession::open(
            ChangeSession::generate_id()?,
            workspace.clone(),
            connection.clone(),
            1,
            MutationExecutor::new(root),
        );
        // Scope permits only "docs/" -- src/lib.rs falls outside it.
        session.enter_scope(SessionScope::new(vec!["docs".to_string()]))?;
        session.baseline(test_tool_plan(), Vec::new())?;
        let discovery = passing_evidence(
            &session,
            &workspace,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            2,
        )?;
        session.record_evidence(
            &workspace,
            &connection,
            ProviderCategory::TextSearch,
            discovery,
        )?;

        let batch = MutationBatch {
            mutations: vec![Mutation::ReplaceFile {
                path: WorkspacePath {
                    root: wht_corulix_core::WorkspaceRootId(0),
                    relative_path: "src/lib.rs".to_string(),
                },
                expected_precondition_hash: ContentHash::compute_sha256(b"fn a() {}\n"),
                content: b"fn a() { }\n".to_vec(),
            }],
        };
        let outcome = session
            .submit_edit(&workspace, &connection, batch, EvidenceTimestamp(2))
            .await;
        assert_eq!(
            outcome,
            Err(SessionError::Denied(ReasonCode::SessionScopeViolation))
        );
        Ok(())
    }

    #[test]
    fn session_scope_permits_exact_and_prefixed_paths_only() {
        let scope = SessionScope::new(vec!["src".to_string(), "README.md".to_string()]);
        assert!(scope.permits("src/lib.rs"));
        assert!(scope.permits("README.md"));
        assert!(!scope.permits("src2/lib.rs"));
        assert!(!scope.permits("secrets/token.txt"));
    }

    /// Session isolation (§67): two independent `ChangeSession`s share no
    /// mutable state -- each owns its own `evidence: Vec<EvidenceRecord>`,
    /// `status`, and `MutationExecutor` by value, with no global/static
    /// registry anywhere in this module. Aborting/evidencing one must
    /// leave the other's state byte-for-byte untouched.
    #[test]
    fn independent_sessions_never_observe_each_others_mutations() -> Result<(), Box<dyn Error>> {
        let (mut session_a, workspace_a, connection_a) = opened_baselined_session("isolation-a")?;
        let (session_b, _workspace_b, connection_b) = opened_baselined_session("isolation-b")?;

        let evidence_a = passing_evidence(
            &session_a,
            &workspace_a,
            GateId::Discovery,
            ProviderCategory::TextSearch,
            2,
        )?;
        session_a.record_evidence(
            &workspace_a,
            &connection_a,
            ProviderCategory::TextSearch,
            evidence_a,
        )?;
        let status_b_before = session_b.change_status().status;
        assert_eq!(
            session_a.status(),
            ChangeSessionStatus::GatePending(GateId::Edit)
        );
        assert_eq!(
            status_b_before,
            ChangeSessionStatus::GatePending(GateId::Discovery)
        );
        assert!(session_b.evidence_history().is_empty());

        session_a.abort(&workspace_a, &connection_a)?;
        assert_eq!(session_a.status(), ChangeSessionStatus::Aborted);
        // Session B is completely unaffected by A's abort.
        assert_eq!(
            session_b.status(),
            ChangeSessionStatus::GatePending(GateId::Discovery)
        );
        assert_ne!(session_a.id(), session_b.id());
        let _ = (connection_b,);
        Ok(())
    }
}
