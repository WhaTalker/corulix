// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13: the real `validate_change` capability behind the
//! `validate_change` MCP tool.
//!
//! This is a thin orchestration on top of already-existing, already-tested
//! primitives -- it introduces no new authority: real `cargo check`
//! ([`crate::diagnostics::run_cargo_check`], `ProviderCategory::
//! TypecheckBuild`, `Authoritative` for `gate.diagnostics` per
//! `crate::policy`) is run against the session's own bound workspace root,
//! and its real outcome is fed into [`ChangeSession::record_evidence`] --
//! the exact same session-owned gate machinery `submit_edit`/
//! `format_and_apply` already use. This module never records a narrative
//! claim it did not itself observe from a real process outcome.
//!
//! Requires [`CorulixEngine::open_with_trust`]`(_, true)`: `cargo check`
//! is [`wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution`], and
//! an engine opened via the plain [`CorulixEngine::open`] (untrusted by
//! default) deterministically reports [`ValidateChangeOutcome::Unavailable`]
//! before any process is spawned -- see `crate::CorulixEngine::effective_config`.
//!
//! # P15 production-routing closure: language-aware dispatch
//!
//! A P16 discovery pass flagged that `crate::go_validation::run_go_validator`
//! and `crate::go_testing::run_go_test` -- P15's real, trust-gated `go
//! build`/`go vet`/`go test` invocations -- were reachable only from their
//! own modules' unit tests and a standalone E2E test file, never from this
//! capability. Traced from the real entrypoint (`wht_corulix_mcp::validate_change`
//! -> [`CorulixEngine::validate_change`]), that was true: this function
//! unconditionally ran `diagnostics::run_cargo_check` regardless of the
//! session's declared language. [`CorulixEngine::validate_change`] is the fix:
//! it reads `ChangeSession::language` (retained since `begin_change`, P15
//! production routing closure) and routes to the language's own real
//! validators. TypeScript/Tsx/JavaScript/Python remain out of scope for P16
//! (still paused): they fall through to the same
//! [`ValidateChangeOutcome::Unavailable`] a caller already sees today, never
//! a newly-admitted provider.
//!
//! # Rust production-routing closure (this pass): clippy and cargo test join cargo check
//!
//! The same discovery pass that found Go's gap disclosed -- but left out of
//! scope -- the identical shape of gap on the Rust side: [`diagnostics::run_clippy`]
//! and [`testing::run_cargo_test`] were fully implemented, trust-gated, and
//! individually unit-tested, but `Self::validate_change_rust` called only
//! [`diagnostics::run_cargo_check`], unconditionally, with no
//! `ChangeSession::requirement_authority` consultation at all
//! (`RUST_HARDCODED_VALIDATE_CHANGE_POLICY_COUNT` was `1` before this pass).
//! `crate::policy::VALIDATE_CHANGE` already names `ProviderCategory::Linter`
//! (`Optional`/`SupportingOnly`) and `ProviderCategory::TestRunner`
//! (`Optional`/`Authoritative`) as real requirements of every `ValidateChange`
//! `ToolPlan` -- the policy table already modeled this; only the Engine-side
//! dispatcher never read it. This pass extends `Self::validate_change_rust`
//! to mirror `Self::validate_change_go`'s own pattern exactly: `clippy`
//! folds its `SupportingOnly` finding into the *same* single
//! `gate.diagnostics` Evidence record `cargo check` produces (never a
//! second, independent record against that gate -- clippy can only ever make
//! an already-clean check's combined verdict *stricter*, and structurally
//! cannot close or fail `gate.diagnostics` on its own); `cargo test` targets
//! the distinct, `Optional` `gate.tests` with its own real, independent
//! Evidence record, `Authoritative` per policy. Both run only when this
//! session's own bound `ToolPlan` names the category as a requirement
//! (`RUST_UNREQUIRED_PROVIDER_EXECUTION_COUNT=0` by the same "checked before
//! spawning, not discovered via a rejected result" construction Go already
//! uses). `cargo build` is not added here: no `ProviderCategory` models a
//! distinct "build" validator, no `PolicyEntry` in `crate::policy` requires
//! one, and `diagnostics`'s own module doc already discloses this as a
//! deliberate scope decision (`P11_CARGO_BUILD_LINKER_AUTHORITY=
//! SYSTEM_LINKER_REQUIRED_NOT_MANAGED`) -- inventing a policy-level
//! distinction between "cargo check required" and "cargo build required"
//! that no canonical plan currently demands would be exactly the kind of
//! architecture-for-its-own-sake this closure's own mandate forbids (see
//! `RUST_CARGO_BUILD_PRODUCT_REACHABLE` in this pass's final report).
//!
//! Go additionally proves Minimum Sufficient Tooling (§10 of this closure's
//! mandate) itself: the Go dispatch checks
//! `ChangeSession::requirement_authority` before spawning anything, so a
//! Go session whose `ToolPlan` never named `TypecheckBuild` as a requirement
//! (`DocumentationModify`, `SourceDelete`, `SourceMove`, ...) reports
//! [`ValidateChangeOutcome::NotRequired`] with zero processes spawned --
//! `P15_UNREQUIRED_GO_PROVIDER_EXECUTION_COUNT=0` by construction, not by
//! `record_evidence` rejecting a result that already ran. `go vet`'s
//! `Linter`/`SupportingOnly` result is folded into the *same* single
//! `gate.diagnostics` Evidence record `go build` produces (never a second,
//! independent record against that gate): this is the concrete meaning of
//! "supplements but never substitutes for" `TypecheckBuild`'s authority --
//! `go vet` can only ever make an already-clean build's combined verdict
//! *stricter*, and it structurally cannot close (or, on its own, fail)
//! `gate.diagnostics` by itself, since no `record_evidence` call is ever made
//! for it in isolation. `go test`'s `TestRunner`/`Authoritative` result
//! targets the distinct, `Optional` `gate.tests` -- its own real,
//! independent Evidence record. `Self::validate_change_rust` now mirrors
//! this exact pattern for clippy/cargo test, the same reused dispatcher
//! (Architecture Rule H: no second `ToolPlan`/gate/Evidence authority).
//!
//! # F4 fix: `gate.format` closure precedes the language dispatch
//!
//! Before this pass, no production code path ever ran a real formatter and
//! called [`ChangeSession::record_evidence`] for `GateId::Format`, so any
//! session whose `ToolPlan` required `gate.format` (`SourceCreate`/
//! `SourceModify`) was structurally uncompletable through the MCP surface --
//! `gate.format` blocked every subsequent gate forever, including the
//! language dispatch this module already ran. [`CorulixEngine::validate_change`] now
//! calls `Self::validate_change_format` first, before the `match
//! session.language()` dispatch this section otherwise describes: while
//! `gate.format` is genuinely this session's current pending/blocked gate
//! (per `ChangeSession::status`), that call runs the real formatter
//! read-only against every target this session created or replaced
//! (`ChangeSession::modified_targets`) via the same
//! [`CorulixEngine::format_preview_at`] the `format_preview` MCP tool uses,
//! records real `gate.format` Evidence, and returns its outcome directly --
//! the language-specific dispatch below is not reached on that call. Once
//! `gate.format` is current+passed (or the session's `ToolPlan` never
//! required it), `Self::validate_change_format` returns `None` and control
//! falls through to the language dispatch exactly as before this pass. A
//! caller driving a full `SourceCreate`/`SourceModify` lifecycle therefore
//! makes one additional `validate_change` call to close `gate.format`,
//! mirroring the existing `gate.edit` -> `gate.format` -> `gate.diagnostics`
//! ordering the gate catalog already enforces -- see
//! [`ValidateChangeOutcome::FormatValidated`] and
//! `Self::validate_change_format`'s own doc comments for the exact
//! skip/run/fail-closed predicate.

use serde::Serialize;
use wht_corulix_core::{
    AuthorityRole, ChangeSessionStatus, ConnectionId, Evidence, EvidenceProvenance,
    EvidenceResultSummary, EvidenceTimestamp, GateId, LanguageId, MutationKind, ProviderCategory,
    ReasonCode, WorkspaceIdentity,
};

use crate::CorulixEngine;
use crate::diagnostics::{self, RustDiagnosticsOutcome, RustValidatorError};
use crate::format_preview::FormatPreviewOutcome;
use crate::go_testing::{self, GoTestError};
use crate::go_validation::{self, GoValidator, GoValidatorError};
use crate::python_testing::{self, PythonTestError};
use crate::python_validation::{self, PythonValidatorError};
use crate::search::{SearchOutcome, SearchRequest};
use crate::session::{ChangeSession, SessionError};
use crate::testing::{self, RustTestError};
use crate::ts_testing::{self, TsTestError};
use crate::ts_validation::{self, TsValidatorError};

/// One real Go validator/test run's contribution to a [`ValidateChangeOutcome::GoExecuted`]
/// report. Deliberately modest -- only what the real tool run actually
/// established, never a narrative summary.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct GoRunSummary {
    /// Whether this validator/test genuinely ran to a real, exit-code-
    /// confirmed conclusion. `false` means it was skipped (category not
    /// required by this session's `ToolPlan`) or could not run at all
    /// (`reason_code` explains why) -- never conflated with "ran clean".
    pub ran: bool,
    pub clean: bool,
    pub finding_count: u32,
    pub reason_code: Option<ReasonCode>,
}

impl GoRunSummary {
    const fn skipped() -> Self {
        Self {
            ran: false,
            clean: true,
            finding_count: 0,
            reason_code: None,
        }
    }

    const fn unavailable(reason_code: ReasonCode) -> Self {
        Self {
            ran: false,
            clean: true,
            finding_count: 0,
            reason_code: Some(reason_code),
        }
    }
}

/// The outcome of one `validate_change` call.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ValidateChangeOutcome {
    /// The session's declared language's real validator could not be run at
    /// all (untrusted engine, managed/host toolchain unavailable,
    /// spawn/timeout/cancellation) -- no Evidence was recorded.
    Unavailable { reason_code: ReasonCode },
    /// `cargo check` ran to completion; its real, exit-code-confirmed
    /// finding counts were recorded as `gate.diagnostics` Evidence via
    /// [`ChangeSession::record_evidence`]. Rust only (`None`/`Some(Rust)`
    /// language).
    ///
    /// `clean`/`error_count`/`warning_count` are `cargo check`'s own fields,
    /// unchanged in shape since before this closure. `clippy`/`test` are
    /// this pass's addition: `clippy`'s `SupportingOnly` finding is folded
    /// into the *same* `gate.diagnostics` Evidence record `cargo check`
    /// produces (so `clippy.ran == false` whenever this session's `ToolPlan`
    /// never named `ProviderCategory::Linter` as a requirement, or whenever
    /// clippy itself could not run -- never conflated with "no findings");
    /// `test` is `cargo test`'s own real, independent `gate.tests` record,
    /// run and recorded only when this session's `ToolPlan` names
    /// `ProviderCategory::TestRunner` as a requirement (mirrors
    /// [`Self::GoExecuted`]'s `vet`/`test` split exactly).
    Executed {
        clean: bool,
        error_count: u32,
        warning_count: u32,
        clippy: GoRunSummary,
        test: GoRunSummary,
        test_evidence_recorded: bool,
    },
    /// The real validator ran and produced a real outcome, but the session
    /// rejected the resulting Evidence (wrong binding, gate not current,
    /// stale input fingerprint, etc.) -- the real, structured
    /// [`SessionError`] reason is reported, never silently swallowed.
    EvidenceRejected { reason_code: ReasonCode },
    /// The session's own bound `ToolPlan` does not name `TypecheckBuild` as
    /// a requirement at all for this session's language -- Minimum
    /// Sufficient Tooling (§10): no validator was spawned, and no Evidence
    /// was (or could be) recorded, because this operation never asked for
    /// one.
    NotRequired,
    /// `go build`/`go vet`/`go test` ran through the real, trust-gated Go
    /// validators. `build` folds in `vet`'s `Linter`/`SupportingOnly`
    /// finding as a single combined `gate.diagnostics` Evidence record;
    /// `test` is the distinct, `Optional` `gate.tests` record, run only when
    /// this session's `ToolPlan` names `TestRunner` as a requirement.
    GoExecuted {
        build: GoRunSummary,
        vet: GoRunSummary,
        test: GoRunSummary,
        build_evidence_recorded: bool,
        test_evidence_recorded: bool,
    },
    /// P16 production-routing closure: `tsc --noEmit` (+ Biome lint, folded
    /// into the same `gate.diagnostics` record) ran for `TypeScript`/`Tsx`/
    /// `JavaScript` sessions, mirroring [`Self::GoExecuted`]'s own shape
    /// exactly. `test` is the discovered `scripts.test` runner's own real
    /// `gate.tests` record (ADR 0010 `PROJECT_TEST_RUNNER_DISCOVERY_POLICY`),
    /// run only when this session's `ToolPlan` names `TestRunner` as a
    /// requirement.
    TsExecuted {
        typecheck: GoRunSummary,
        lint: GoRunSummary,
        test: GoRunSummary,
        typecheck_evidence_recorded: bool,
        test_evidence_recorded: bool,
    },
    /// P17 production-routing closure: `pyright --outputjson` (+ `ruff
    /// check`, folded into the same `gate.diagnostics` record) ran for a
    /// `Python` session, mirroring [`Self::TsExecuted`]'s own shape exactly.
    /// `test` is the discovered `pytest` runner's own real `gate.tests`
    /// record (ADR 0011 §4 `PROJECT_TEST_RUNNER_DISCOVERY_POLICY`), run only
    /// when this session's `ToolPlan` names `TestRunner` as a requirement.
    PythonExecuted {
        typecheck: GoRunSummary,
        lint: GoRunSummary,
        test: GoRunSummary,
        typecheck_evidence_recorded: bool,
        test_evidence_recorded: bool,
    },
    /// F3 fix (`SOURCE_DELETE_COMMITTED_UNCOMPLETABLE_STATE`): this session's
    /// bound `ToolPlan` names `MutationKind::Delete` -- a real,
    /// language-independent post-audit ran instead of any
    /// language-specific typecheck/build dispatch. Proves, via a real
    /// workspace-confined filesystem check, that every target this session
    /// has genuinely deleted ([`ChangeSession::deleted_targets`]) is still
    /// absent, and, via the already-available in-process
    /// `ProviderCategory::TextSearch` capability, that no other in-scope
    /// file's content still contains a deleted target's literal
    /// relative-path text. `checked_targets == 0` is never reachable here --
    /// see `CorulixEngine::validate_change_post_audit_delete`'s own doc for
    /// why that case returns [`Self::Unavailable`] instead of a vacuous
    /// pass.
    PostAuditExecuted {
        checked_targets: u32,
        clean: bool,
        still_present_count: u32,
        dangling_reference_count: u32,
        evidence_recorded: bool,
    },
    /// F4 fix (`F4_MCP_FORMAT_GATE_UNCLOSABLE`): a real, read-only formatter
    /// check ran against every target this session has genuinely created or
    /// replaced (`ChangeSession::modified_targets`) -- the same
    /// [`CorulixEngine::format_preview_at`] the `format_preview` MCP tool
    /// itself uses, never a duplicated formatter invocation and never a
    /// mutating one. `clean == true` means every checked target's current
    /// bytes are already the formatter's own canonical output; real
    /// `gate.format` `Passed` Evidence was recorded. `clean == false` means
    /// at least one target would still change under the formatter; real
    /// `gate.format` `Failed` Evidence (`ReasonCode::FormatFindingsReported`)
    /// was recorded, leaving the gate genuinely, honestly unsatisfied --
    /// never a false pass. `checked_targets == 0` is never reachable here:
    /// mirrors [`Self::PostAuditExecuted`]'s own "never a vacuous pass"
    /// contract exactly (see `CorulixEngine::validate_change_format`'s own
    /// doc for why that case returns [`Self::Unavailable`] instead).
    FormatValidated {
        clean: bool,
        checked_targets: u32,
        provider_used_managed: bool,
        provider_version: Option<String>,
    },
}

impl ValidateChangeOutcome {
    /// Whether this outcome should surface as an MCP tool-call error.
    /// Historically (pre-P16-closure): only `Unavailable`/`EvidenceRejected`
    /// counted as an error -- a validator that genuinely ran and recorded
    /// real Evidence is a successful *call*, whatever its `clean`/`passing`
    /// verdict says (that verdict lives in the gate, not the call's own
    /// success). `NotRequired` is likewise not a call error: correctly
    /// skipping an unrequired provider is the intended behavior, not a
    /// failure.
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Self::Unavailable { .. } | Self::EvidenceRejected { .. }
        )
    }
}

fn validator_error_reason(error: RustValidatorError) -> ReasonCode {
    match error {
        RustValidatorError::WorkspaceExecutionNotAuthorized => {
            ReasonCode::RequiredProviderUnavailable
        }
        RustValidatorError::ManagedRuntimeUnavailable
        | RustValidatorError::ManagedClippyUnavailable
        | RustValidatorError::ManagedClippyTampered => ReasonCode::RequiredProviderUnavailable,
        RustValidatorError::ValidatorInvocationFailed
        | RustValidatorError::SpawnFailed
        | RustValidatorError::Signaled
        | RustValidatorError::TerminationFailed => ReasonCode::RequiredCapabilityUnavailable,
        RustValidatorError::TimedOut | RustValidatorError::Cancelled => {
            ReasonCode::RequiredCapabilityUnavailable
        }
    }
}

fn go_validator_error_reason(error: &GoValidatorError) -> ReasonCode {
    match error {
        GoValidatorError::WorkspaceExecutionNotAuthorized => {
            ReasonCode::RequiredProviderUnavailable
        }
        GoValidatorError::Provider(_) => ReasonCode::RequiredProviderUnavailable,
        GoValidatorError::FailureWithoutParsedDiagnostics { .. }
        | GoValidatorError::ResultContradiction
        | GoValidatorError::SpawnFailed
        | GoValidatorError::Signaled
        | GoValidatorError::TerminationFailed
        | GoValidatorError::TimedOut
        | GoValidatorError::Cancelled => ReasonCode::RequiredCapabilityUnavailable,
    }
}

fn go_test_error_reason(error: &GoTestError) -> ReasonCode {
    match error {
        GoTestError::WorkspaceExecutionNotAuthorized => ReasonCode::RequiredProviderUnavailable,
        GoTestError::Provider(_) => ReasonCode::RequiredProviderUnavailable,
        GoTestError::BuildFailed { .. }
        | GoTestError::NoTestsExecuted
        | GoTestError::ResultTruncatedBeforeSummary
        | GoTestError::ResultContradiction
        | GoTestError::WorkspaceSelfMutationDetected
        | GoTestError::WorkspaceSourceTreeUnreadable
        | GoTestError::SpawnFailed
        | GoTestError::TimedOut
        | GoTestError::Cancelled
        | GoTestError::TerminationFailed
        | GoTestError::Signaled => ReasonCode::RequiredCapabilityUnavailable,
    }
}

fn ts_validator_error_reason(error: &TsValidatorError) -> ReasonCode {
    match error {
        TsValidatorError::ManagedRuntimeUnavailable => ReasonCode::RequiredProviderUnavailable,
        TsValidatorError::StagedCopyUnavailable
        | TsValidatorError::FailureWithoutParsedDiagnostics { .. }
        | TsValidatorError::ResultContradiction
        | TsValidatorError::SpawnFailed
        | TsValidatorError::TimedOut
        | TsValidatorError::Cancelled
        | TsValidatorError::TerminationFailed
        | TsValidatorError::Signaled => ReasonCode::RequiredCapabilityUnavailable,
    }
}

fn ts_test_error_reason(error: &TsTestError) -> ReasonCode {
    match error {
        TsTestError::WorkspaceExecutionNotAuthorized => ReasonCode::RequiredProviderUnavailable,
        TsTestError::AmbiguousTestRunner
        | TsTestError::PackageJsonUnreadable
        | TsTestError::FailureWithoutClearOutcome { .. }
        | TsTestError::SpawnFailed
        | TsTestError::TimedOut
        | TsTestError::Cancelled
        | TsTestError::TerminationFailed
        | TsTestError::Signaled => ReasonCode::RequiredCapabilityUnavailable,
    }
}

fn python_validator_error_reason(error: &PythonValidatorError) -> ReasonCode {
    match error {
        PythonValidatorError::Provider(_) => ReasonCode::RequiredProviderUnavailable,
        PythonValidatorError::StagedCopyUnavailable
        | PythonValidatorError::FailureWithoutParsedDiagnostics { .. }
        | PythonValidatorError::ResultContradiction
        | PythonValidatorError::SpawnFailed
        | PythonValidatorError::TimedOut
        | PythonValidatorError::Cancelled
        | PythonValidatorError::TerminationFailed
        | PythonValidatorError::Signaled => ReasonCode::RequiredCapabilityUnavailable,
    }
}

fn python_test_error_reason(error: &PythonTestError) -> ReasonCode {
    match error {
        PythonTestError::WorkspaceExecutionNotAuthorized => ReasonCode::RequiredProviderUnavailable,
        PythonTestError::Provider(_) => ReasonCode::RequiredProviderUnavailable,
        PythonTestError::AmbiguousTestRunner
        | PythonTestError::FailureWithoutClearOutcome { .. }
        | PythonTestError::SpawnFailed
        | PythonTestError::TimedOut
        | PythonTestError::Cancelled
        | PythonTestError::TerminationFailed
        | PythonTestError::Signaled => ReasonCode::RequiredCapabilityUnavailable,
    }
}

/// As [`go_test_error_reason`], for [`RustTestError`] -- `cargo test`'s own
/// real error taxonomy (`testing::run_cargo_test`).
fn rust_test_error_reason(error: &RustTestError) -> ReasonCode {
    match error {
        RustTestError::WorkspaceExecutionNotAuthorized => ReasonCode::RequiredProviderUnavailable,
        RustTestError::ManagedRuntimeUnavailable
        | RustTestError::ManagedLinkerRuntimeUnavailable
        | RustTestError::ScratchDirUnavailable => ReasonCode::RequiredProviderUnavailable,
        RustTestError::BuildFailed(_)
        | RustTestError::NoTestsExecuted
        | RustTestError::ResultTruncatedBeforeSummary
        | RustTestError::ResultContradiction
        | RustTestError::WorkspaceSelfMutationDetected
        | RustTestError::WorkspaceSourceTreeUnreadable
        | RustTestError::SpawnFailed
        | RustTestError::TimedOut
        | RustTestError::Cancelled
        | RustTestError::TerminationFailed
        | RustTestError::Signaled => ReasonCode::RequiredCapabilityUnavailable,
    }
}

/// Bounds a combined build+vet (or a test) summary string to
/// [`wht_corulix_core::EVIDENCE_RESULT_SUMMARY_MAX_BYTES`], truncating on a
/// UTF-8 boundary rather than rejecting outright -- the two source summaries
/// are already individually bounded by `go_validation`/`go_testing`'s own
/// limits, so this is a defensive backstop, not the primary bound.
fn bounded_summary(text: &str) -> (EvidenceResultSummary, bool) {
    if let Ok(summary) = EvidenceResultSummary::try_from(text.to_string()) {
        return (summary, false);
    }
    let mut cut = wht_corulix_core::EVIDENCE_RESULT_SUMMARY_MAX_BYTES;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let truncated = text[..cut].to_string();
    match EvidenceResultSummary::try_from(truncated) {
        Ok(summary) => (summary, true),
        Err(_) => (
            EvidenceResultSummary::try_from(String::new())
                .unwrap_or_else(|_| unreachable!("an empty string is always within bounds")),
            true,
        ),
    }
}

impl CorulixEngine {
    /// Runs `session`'s own declared language's real validator(s) against
    /// its bound workspace root and records the result(s) as Evidence.
    /// `sequence` must be strictly greater than every sequence already
    /// recorded for this session at the moment this call begins (the same
    /// invariant [`ChangeSession::record_evidence`] itself enforces) --
    /// callers typically pass `session.evidence_history().len() as u64 + 1`.
    /// A Go session that records more than one Evidence item in this same
    /// call (`gate.diagnostics` then `gate.tests`) derives each later
    /// sequence itself from the session's own updated history, never
    /// reusing `sequence` verbatim for a second record.
    ///
    /// F3 fix: dispatches on [`ChangeSession::tool_plan`]'s own
    /// `mutation_kind` *before* any language routing at all --
    /// `MutationKind::Delete` runs `Self::validate_change_post_audit_delete`
    /// unconditionally, regardless of [`ChangeSession::language`]. This is
    /// deliberately not a language-specific validator: `SOURCE_DELETE`'s
    /// real post-audit only ever needs the in-process
    /// `ProviderCategory::TextSearch` capability (never a per-language
    /// typecheck/build tool), and `crate::policy::SOURCE_DELETE` has no
    /// `TypecheckBuild` requirement at all for any language -- routing a
    /// delete-kind session into the language dispatch below would
    /// unconditionally report `NotRequired` (as it did before this fix) and
    /// never reach a real audit.
    ///
    /// Otherwise dispatches on [`ChangeSession::language`]: `None`/
    /// `Some(LanguageId::Rust)` runs real `cargo check` exactly as before
    /// this closure (unchanged behavior, unchanged `Executed` shape);
    /// `Some(LanguageId::Go)` runs `Self::validate_change_go`. Every other
    /// [`LanguageId`] is not yet wired to any production validator
    /// (`TypeScript`/`Tsx`/`JavaScript`/`Python` remain P16/P17 territory,
    /// explicitly paused) and reports the same `Unavailable` a caller
    /// already saw before this closure.
    pub async fn validate_change(
        &self,
        session: &mut ChangeSession,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        sequence: u64,
        cancellation: &wht_corulix_core::CancellationToken,
    ) -> ValidateChangeOutcome {
        if session.tool_plan().mutation_kind == Some(MutationKind::Delete) {
            return self
                .validate_change_post_audit_delete(
                    session,
                    requester_workspace,
                    requester_connection,
                    sequence,
                )
                .await;
        }
        // F4 fix: `gate.format`'s real closure runs before any
        // language-specific diagnostics dispatch, and only while it is
        // genuinely this session's due gate -- see
        // [`Self::validate_change_format`]'s own doc comment for the exact
        // skip/run predicate. Returning its outcome directly (rather than
        // folding it into whatever the language dispatch below produces)
        // keeps this pass's change additive: a caller who wants both
        // `gate.format` closed and `gate.diagnostics` evidence makes two
        // `validate_change` calls, exactly as the existing `gate.edit` ->
        // `gate.format` -> `gate.diagnostics` walk already requires separate
        // `submit_edit`/`validate_change` calls today.
        if let Some(outcome) = self
            .validate_change_format(session, requester_workspace, requester_connection, sequence)
            .await
        {
            return outcome;
        }
        match session.language() {
            None | Some(LanguageId::Rust) => {
                self.validate_change_rust(
                    session,
                    requester_workspace,
                    requester_connection,
                    sequence,
                    cancellation,
                )
                .await
            }
            Some(LanguageId::Go) => {
                self.validate_change_go(
                    session,
                    requester_workspace,
                    requester_connection,
                    cancellation,
                )
                .await
            }
            Some(LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript) => {
                self.validate_change_typescript(
                    session,
                    requester_workspace,
                    requester_connection,
                    cancellation,
                )
                .await
            }
            Some(LanguageId::Python) => {
                self.validate_change_python(
                    session,
                    requester_workspace,
                    requester_connection,
                    cancellation,
                )
                .await
            }
            // `LanguageId` is `#[non_exhaustive]`, so a hypothetical future
            // variant this arm does not yet know how to route fails closed
            // here, never silently borrowing Rust's/Go's/TS's/Python's
            // dispatch.
            Some(_) => ValidateChangeOutcome::Unavailable {
                reason_code: ReasonCode::RequiredProviderUnavailable,
            },
        }
    }

    /// F4 fix (`F4_MCP_FORMAT_GATE_UNCLOSABLE`): the real, language-agnostic
    /// `gate.format` closure path.
    ///
    /// # Why this is language-agnostic, not a Rust-specific hack
    ///
    /// This method never inspects [`ChangeSession::language`]. It delegates
    /// entirely to [`CorulixEngine::format_preview_at`] -- the exact same
    /// real, read-only, already-certified formatter-resolution path the
    /// `format_preview` MCP tool itself calls, which already dispatches by
    /// each target's own file extension/language internally. Adding a
    /// second language (Biome for TypeScript/JavaScript, when provisioned)
    /// requires no change here at all.
    ///
    /// # Skip conditions (returns `None`: caller falls through to its own
    /// language dispatch)
    ///
    /// - This session's own bound `ToolPlan` never named `Formatter` as a
    ///   requirement at all (Minimum Sufficient Tooling -- e.g.
    ///   `DocumentationModify`, `SOURCE_DELETE`).
    /// - `gate.format` is not this session's current pending/blocked gate --
    ///   checked via the exact same predicate
    ///   [`ChangeSession::record_evidence`] itself enforces for `Required`
    ///   gates (`self.status` matching `GatePending(Format)`/
    ///   `Blocked(Format)`), so the two can never disagree. Covers both "this
    ///   gate already has Current Passed Evidence, nothing to do" and "this
    ///   session's `ToolPlan` never names `Format` `Required` at all", and
    ///   correctly re-runs after a corrective edit re-opens the gate (the old
    ///   Passed record is already `Stale` by then -- see
    ///   [`crate::session::ChangeSession`]'s own "Evidence invalidation
    ///   graph" module doc).
    ///
    /// # Why `checked_targets == 0` never produces a vacuous pass
    ///
    /// If [`ChangeSession::modified_targets`] is empty -- this session's
    /// `ToolPlan` requires `Formatter`, but no real create/replace has
    /// actually committed through it yet -- this method records **no**
    /// Evidence at all and returns [`ValidateChangeOutcome::Unavailable`]
    /// with [`ReasonCode::PreconditionNotMet`]. Mirrors
    /// [`Self::validate_change_post_audit_delete`]'s own identical
    /// precedent and rationale exactly: recording a trivially-"clean"
    /// `Passed` record for zero real checks would let a session close
    /// `gate.format` having never actually formatted anything.
    ///
    /// # Fail-closed on an unresolvable/erroring formatter
    ///
    /// A [`crate::format_preview::FormatPreviewOutcome::Unavailable`]/
    /// [`crate::format_preview::FormatPreviewOutcome::InvocationFailed`]
    /// result for any target returns
    /// [`ValidateChangeOutcome::Unavailable`] immediately, for that whole
    /// call -- no Evidence is recorded (`FORMAT_PROVIDER_UNAVAILABLE_FALSE_PASS_COUNT=0`).
    async fn validate_change_format(
        &self,
        session: &mut ChangeSession,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        sequence: u64,
    ) -> Option<ValidateChangeOutcome> {
        session.requirement_authority(ProviderCategory::Formatter)?;
        if !matches!(
            session.status(),
            ChangeSessionStatus::GatePending(GateId::Format)
                | ChangeSessionStatus::Blocked(GateId::Format)
        ) {
            return None;
        }

        let targets = session.modified_targets().to_vec();
        if targets.is_empty() {
            return Some(ValidateChangeOutcome::Unavailable {
                reason_code: ReasonCode::PreconditionNotMet,
            });
        }

        let managed_root = match wht_corulix_tooling::provisioning::managed_toolchain_root() {
            Ok(root) => root,
            Err(_) => {
                return Some(ValidateChangeOutcome::Unavailable {
                    reason_code: ReasonCode::RequiredProviderUnavailable,
                });
            }
        };

        let mut all_clean = true;
        let mut provider_used_managed = false;
        let mut provider_version: Option<String> = None;

        for target in &targets {
            let relative = std::path::PathBuf::from(&target.relative_path);
            let outcome = self
                .format_preview_at(&managed_root, relative, Some(target.root.0.to_string()))
                .await;
            match outcome {
                FormatPreviewOutcome::Unchanged {
                    provider_used_managed: managed,
                    provider_version: version,
                    ..
                } => {
                    provider_used_managed = managed;
                    provider_version = version;
                }
                FormatPreviewOutcome::WouldFormat {
                    provider_used_managed: managed,
                    provider_version: version,
                    ..
                } => {
                    all_clean = false;
                    provider_used_managed = managed;
                    provider_version = version;
                }
                FormatPreviewOutcome::Unavailable { reason_code } => {
                    return Some(ValidateChangeOutcome::Unavailable { reason_code });
                }
                FormatPreviewOutcome::InvocationFailed { reason } => {
                    return Some(ValidateChangeOutcome::Unavailable {
                        reason_code: reason.unwrap_or(ReasonCode::RequiredCapabilityUnavailable),
                    });
                }
            }
        }

        let checked_targets = targets.len() as u32;
        let (result_summary, truncated) = bounded_summary(&format!(
            "format check: {checked_targets} modified target(s) checked, {}",
            if all_clean {
                "all already canonical"
            } else {
                "at least one target would reformat"
            }
        ));

        let evidence = Evidence {
            session_id: session.id().clone(),
            workspace_identity: requester_workspace.clone(),
            gate: GateId::Format,
            sequence,
            provenance: EvidenceProvenance {
                provider_id: "wht_corulix_engine::validate_change::validate_change_format"
                    .to_string(),
                provider_version: provider_version.clone(),
                // Mirrors `crate::policy`'s own declared authority for
                // `ProviderCategory::Formatter` on every intent that
                // requires `gate.format` (`SupportingOnly`, not
                // `Authoritative`) -- `record_evidence` only ever rejects
                // `ForbiddenAsAuthority`, so `SupportingOnly` is fully
                // sufficient to close this gate; this field stays honest
                // about which authority tier actually closed it rather than
                // overclaiming `Authoritative`.
                authority: AuthorityRole::SupportingOnly,
            },
            scope: Vec::new(),
            // Never the formatter's own `input_hash`: `advance_content_state`
            // only ever stamps `last_edit_output_hash` from the *first*
            // hashed result in a multi-target batch, so a later target's own
            // input hash would spuriously trip `EvidenceStaleInputFingerprint`
            // at `record_evidence`. Matches every other gate's evidence in
            // this module exactly.
            input_fingerprint: session.last_edit_output_hash().cloned(),
            result_summary,
            reason: if all_clean {
                None
            } else {
                Some(ReasonCode::FormatFindingsReported)
            },
            truncated,
            timestamp: EvidenceTimestamp(sequence),
            snapshot_id: Some(session.content_snapshot_id()),
        };

        match session.record_evidence(
            requester_workspace,
            requester_connection,
            ProviderCategory::Formatter,
            evidence,
        ) {
            Ok(()) => {}
            Err(SessionError::Denied(reason_code)) => {
                return Some(ValidateChangeOutcome::EvidenceRejected { reason_code });
            }
            Err(SessionError::Mutation(_) | SessionError::Formatter(_)) => {
                return Some(ValidateChangeOutcome::EvidenceRejected {
                    reason_code: ReasonCode::RequiredCapabilityUnavailable,
                });
            }
        }

        Some(ValidateChangeOutcome::FormatValidated {
            clean: all_clean,
            checked_targets,
            provider_used_managed,
            provider_version,
        })
    }

    /// F3 fix (`SOURCE_DELETE_COMMITTED_UNCOMPLETABLE_STATE=IMPOSSIBLE`): the
    /// real, language-independent `gate.post_audit` closure path for a
    /// delete-kind `ChangeSession`.
    ///
    /// # Why this exists
    ///
    /// `crate::policy::SOURCE_DELETE` marks `gate.post_audit` `Required`.
    /// Before this fix its `requirements` list was empty, which made that
    /// gate structurally unclosable (`ChangeSession::requirement_authority`
    /// returns `None` for every category against an empty list, and
    /// `ChangeSession::record_evidence` treats `None` exactly like
    /// `AuthorityRole::ForbiddenAsAuthority`) -- no MCP tool could ever
    /// legitimately advance a `SOURCE_DELETE` session past `ExitEvaluation`
    /// into `Completed`. `crate::policy::SOURCE_DELETE` now names
    /// `ProviderCategory::TextSearch` (already unconditionally `Available`,
    /// in-process, independent of this fix) as a real `Authoritative`
    /// requirement, which is what makes the `record_evidence` call at the
    /// end of this function acceptable instead of rejected.
    ///
    /// # What is genuinely checked (and what is not)
    ///
    /// For every target [`ChangeSession::deleted_targets`] lists (every real,
    /// committed [`wht_corulix_mutation::MutationResult::Deleted`] outcome
    /// this session has produced via [`ChangeSession::submit_edit`]):
    ///
    /// 1. **Absence**: a real, workspace-confined filesystem check
    ///    ([`wht_corulix_workspace::confined_metadata`]) re-resolves the
    ///    target. `Ok` means something now exists there again (the commit
    ///    itself or a later external change contradicts the recorded
    ///    deletion) -- a genuine, real re-verification finding, counted in
    ///    `still_present_count`.
    /// 2. **No dangling in-scope reference**: a real, in-process
    ///    [`Self::search`] call (`ProviderCategory::TextSearch`, scoped to
    ///    this session's own bound workspace root) looks for the deleted
    ///    target's literal relative-path text. A match is counted only when
    ///    it also falls inside this session's own declared
    ///    [`crate::session::SessionScope`] (`ChangeSession::scope`) --
    ///    exactly the "in-scope" qualifier the mandate requires, so an
    ///    unrelated out-of-scope coincidental match is never reported as a
    ///    dangling reference.
    ///
    /// This is a real, honest, but bounded check, not a semantic proof: it
    /// is a literal substring search over file content, so it can miss a
    /// reference expressed in a different form (a module path, a
    /// re-exported symbol name, a different relative spelling) and can
    /// over-count a coincidental textual match that is not really a
    /// reference to the deleted file at all. `TEXT_SEARCH`/
    /// `STRUCTURAL_PARSE` are the only capabilities this check is
    /// authorized to use (both `AVAILABLE` independent of `HostConfig`/F1);
    /// nothing here waits on or depends on `CONTROLLED_EXTERNAL_TOOL`
    /// resolution.
    ///
    /// # Why `checked_targets == 0` never produces a vacuous pass
    ///
    /// If [`ChangeSession::deleted_targets`] is empty -- `validate_change`
    /// was called against a delete-kind session before any real delete has
    /// actually been committed through it -- this function records **no**
    /// Evidence at all and returns [`ValidateChangeOutcome::Unavailable`].
    /// Recording a trivially-"clean" `Passed` record for zero real checks
    /// would let a `SOURCE_DELETE` session reach `Completed` having never
    /// actually deleted anything (nothing else in this crate enforces that a
    /// session's committed mutations match its declared intent) -- exactly
    /// the "synthesizes fake evidence" failure mode this fix must not
    /// introduce. Leaving the gate genuinely without Evidence keeps
    /// `complete_change` correctly denying with
    /// `ReasonCode::RequiredGateMissingEvidence` until a real delete is
    /// submitted and this function is called again.
    async fn validate_change_post_audit_delete(
        &self,
        session: &mut ChangeSession,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        sequence: u64,
    ) -> ValidateChangeOutcome {
        if session
            .requirement_authority(ProviderCategory::TextSearch)
            .is_none()
        {
            // Minimum Sufficient Tooling: this session's own bound `ToolPlan`
            // never named `TextSearch` as a requirement at all (should not
            // occur for a real `SOURCE_DELETE` plan today, but this session
            // could in principle have been baselined against a future/other
            // policy entry that also happens to declare `MutationKind::Delete`
            // without this requirement) -- no audit is spawned.
            return ValidateChangeOutcome::NotRequired;
        }

        let targets = session.deleted_targets().to_vec();
        if targets.is_empty() {
            // See this method's own doc comment: never a vacuous pass.
            return ValidateChangeOutcome::Unavailable {
                reason_code: ReasonCode::PreconditionNotMet,
            };
        }

        let mut still_present_count: u32 = 0;
        for target in &targets {
            let root = session.executor().workspace_root().clone();
            let relative = std::path::PathBuf::from(&target.relative_path);
            if wht_corulix_workspace::confined_metadata(root, relative)
                .await
                .is_ok()
            {
                still_present_count = still_present_count.saturating_add(1);
            }
        }

        let mut dangling_reference_count: u32 = 0;
        for target in &targets {
            let outcome = self
                .search(SearchRequest {
                    pattern: target.relative_path.clone(),
                    is_regex: false,
                    case_insensitive: false,
                    root_selector: Some(target.root.0.to_string()),
                })
                .await;
            match outcome {
                SearchOutcome::Executed { matches, .. } => {
                    for found in &matches {
                        if found.root_id == target.root.0
                            && session.scope().permits(&found.relative_path)
                        {
                            dangling_reference_count = dangling_reference_count.saturating_add(1);
                        }
                    }
                }
                SearchOutcome::Unavailable { reason_code } => {
                    // `TextSearch` is unconditionally `Available` in
                    // `ProviderSnapshot::current()` -- reaching this arm
                    // would mean this engine's own plan derivation disagrees
                    // with itself. Fail closed rather than silently treating
                    // an unrun check as a clean one.
                    return ValidateChangeOutcome::Unavailable { reason_code };
                }
                SearchOutcome::Error { .. } => {
                    return ValidateChangeOutcome::Unavailable {
                        reason_code: ReasonCode::RequiredCapabilityUnavailable,
                    };
                }
            }
        }

        let clean = still_present_count == 0 && dangling_reference_count == 0;
        let reason = if still_present_count > 0 {
            Some(ReasonCode::PostAuditTargetStillPresent)
        } else if dangling_reference_count > 0 {
            Some(ReasonCode::PostAuditDanglingReferenceFound)
        } else {
            None
        };

        let (result_summary, truncated) = bounded_summary(&format!(
            "post-audit: {} deleted target(s) checked, {still_present_count} still present, \
             {dangling_reference_count} in-scope dangling reference(s)",
            targets.len()
        ));

        let evidence = Evidence {
            session_id: session.id().clone(),
            workspace_identity: requester_workspace.clone(),
            gate: GateId::PostAudit,
            sequence,
            provenance: EvidenceProvenance {
                provider_id: "wht_corulix_engine::validate_change::post_audit_delete".to_string(),
                provider_version: None,
                authority: AuthorityRole::Authoritative,
            },
            scope: session.scope().prefixes().to_vec(),
            // Never `Some(..)` here: a delete has no resulting content to
            // hash (`session::result_hash` already maps every `Deleted`
            // outcome to `None`), so `last_edit_output_hash` is always
            // `None` for a delete-only session -- matching that verbatim
            // keeps this Evidence honest without inventing a fingerprint a
            // deleted file cannot have.
            input_fingerprint: session.last_edit_output_hash().cloned(),
            result_summary,
            reason,
            truncated,
            timestamp: EvidenceTimestamp(sequence),
            snapshot_id: Some(session.content_snapshot_id()),
        };

        match session.record_evidence(
            requester_workspace,
            requester_connection,
            ProviderCategory::TextSearch,
            evidence,
        ) {
            Ok(()) => {}
            Err(SessionError::Denied(reason_code)) => {
                return ValidateChangeOutcome::EvidenceRejected { reason_code };
            }
            // `record_evidence` itself only ever returns `Denied` -- see its
            // own body -- but `SessionError` is a plain, non-`#[non_exhaustive]`
            // local enum with three variants, so this match must still name
            // them: fail closed with a generic capability-unavailable reason
            // rather than `unreachable!()`/`.expect()`.
            Err(SessionError::Mutation(_) | SessionError::Formatter(_)) => {
                return ValidateChangeOutcome::EvidenceRejected {
                    reason_code: ReasonCode::RequiredCapabilityUnavailable,
                };
            }
        }

        ValidateChangeOutcome::PostAuditExecuted {
            checked_targets: targets.len() as u32,
            clean,
            still_present_count,
            dangling_reference_count,
            evidence_recorded: true,
        }
    }

    /// The real Rust dispatch (this pass's closure): `cargo check` (+
    /// clippy, folded into the same record) for `gate.diagnostics`, then
    /// `cargo test` for the distinct `gate.tests`, each spawned only when
    /// this session's own bound `ToolPlan` actually names the category as a
    /// requirement (`ChangeSession::requirement_authority`) -- exactly
    /// [`Self::validate_change_go`]'s own pattern, reused rather than
    /// duplicated. See [`Self::validate_change`]'s own doc comment for the
    /// full rationale, including why `cargo build` is not added here.
    async fn validate_change_rust(
        &self,
        session: &mut ChangeSession,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        sequence: u64,
        cancellation: &wht_corulix_core::CancellationToken,
    ) -> ValidateChangeOutcome {
        if session
            .requirement_authority(ProviderCategory::TypecheckBuild)
            .is_none()
        {
            // Minimum Sufficient Tooling: this operation never asked for a
            // build/typecheck validator at all. No process is spawned --
            // mirrors `Self::validate_change_go`'s own identical guard.
            return ValidateChangeOutcome::NotRequired;
        }

        let effective = self.effective_config();
        let managed_root = match wht_corulix_tooling::provisioning::managed_toolchain_root() {
            Ok(root) => root,
            Err(_) => {
                return ValidateChangeOutcome::Unavailable {
                    reason_code: ReasonCode::RequiredProviderUnavailable,
                };
            }
        };
        // M09-P7: an owned clone of the real, pinned `WorkspaceRoot` (cheap,
        // `Arc`-backed) -- threaded into every validator below by object
        // identity, not a re-resolvable pathname, so a root-object swap
        // after this point cannot redirect any of these spawns.
        let workspace_root = session.executor().workspace_root().clone();

        let check_outcome = diagnostics::run_cargo_check_with_workspace_root(
            &managed_root,
            &workspace_root,
            &effective,
            cancellation,
        )
        .await;
        let check_outcome: RustDiagnosticsOutcome = match check_outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                return ValidateChangeOutcome::Unavailable {
                    reason_code: validator_error_reason(error),
                };
            }
        };

        // Clippy supplements the same `gate.diagnostics` record -- never
        // submitted as a second, independent Evidence item against that
        // gate (see this module's own doc comment: `Linter`'s
        // `SupportingOnly` authority must never be able to close or fail
        // `gate.diagnostics` on its own). Optional: an unavailable/erroring
        // clippy never blocks an otherwise-passing `cargo check`.
        let mut combined_clean = check_outcome.is_clean();
        let mut combined_summary = check_outcome.summary.clone();
        let mut combined_truncated = check_outcome.truncated;
        let clippy_summary = if session
            .requirement_authority(ProviderCategory::Linter)
            .is_some()
        {
            match diagnostics::run_clippy_with_workspace_root(
                &managed_root,
                &workspace_root,
                &effective,
                cancellation,
            )
            .await
            {
                Ok(clippy_outcome) => {
                    combined_clean = combined_clean && clippy_outcome.is_clean();
                    combined_truncated = combined_truncated || clippy_outcome.truncated;
                    if !clippy_outcome.summary.is_empty() {
                        combined_summary.push_str("\n--- cargo clippy ---\n");
                        combined_summary.push_str(&clippy_outcome.summary);
                    }
                    GoRunSummary {
                        ran: true,
                        clean: clippy_outcome.is_clean(),
                        finding_count: clippy_outcome
                            .error_count
                            .saturating_add(clippy_outcome.warning_count),
                        reason_code: None,
                    }
                }
                Err(error) => GoRunSummary::unavailable(validator_error_reason(error)),
            }
        } else {
            GoRunSummary::skipped()
        };

        let (result_summary, summary_truncated) = bounded_summary(&combined_summary);
        let evidence = Evidence {
            session_id: session.id().clone(),
            workspace_identity: requester_workspace.clone(),
            gate: GateId::Diagnostics,
            sequence,
            provenance: EvidenceProvenance {
                provider_id: "wht_corulix_engine::diagnostics::run_cargo_check".to_string(),
                provider_version: Some(check_outcome.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: Vec::new(),
            input_fingerprint: session.last_edit_output_hash().cloned(),
            result_summary,
            reason: if combined_clean {
                None
            } else {
                Some(ReasonCode::DiagnosticsFindingsReported)
            },
            truncated: combined_truncated || summary_truncated,
            timestamp: EvidenceTimestamp(sequence),
            snapshot_id: Some(session.content_snapshot_id()),
        };

        let clean = check_outcome.is_clean();
        let error_count = check_outcome.error_count;
        let warning_count = check_outcome.warning_count;

        match session.record_evidence(
            requester_workspace,
            requester_connection,
            ProviderCategory::TypecheckBuild,
            evidence,
        ) {
            Ok(()) => {}
            Err(SessionError::Denied(reason_code)) => {
                return ValidateChangeOutcome::EvidenceRejected { reason_code };
            }
            // `record_evidence` itself only ever returns `Denied` (see its
            // body) -- `Mutation`/`Formatter` are unreachable from this
            // call site, but `SessionError` is a plain, non-`#[non_exhaustive]`
            // local enum with three variants, so this match must still
            // name them: fail closed with a generic capability-unavailable
            // reason rather than `unreachable!()`/`.expect()`.
            Err(SessionError::Mutation(_) | SessionError::Formatter(_)) => {
                return ValidateChangeOutcome::EvidenceRejected {
                    reason_code: ReasonCode::RequiredCapabilityUnavailable,
                };
            }
        }

        // `cargo test` targets the distinct, `Optional` `gate.tests` -- run
        // only when this session's `ToolPlan` names `TestRunner` as a
        // requirement, and never allowed to block the call even when it
        // cannot run (Optional: an unavailable test runner must not deny an
        // otherwise-passing check).
        let (test_summary, test_evidence_recorded) = if session
            .requirement_authority(ProviderCategory::TestRunner)
            .is_some()
        {
            match testing::run_cargo_test_with_workspace_root(
                &managed_root,
                &workspace_root,
                &effective,
                cancellation,
            )
            .await
            {
                Ok(test_outcome) => {
                    let (result_summary, truncated) = bounded_summary(&test_outcome.summary);
                    let test_sequence = session.evidence_history().len() as u64 + 1;
                    let test_evidence = Evidence {
                        session_id: session.id().clone(),
                        workspace_identity: requester_workspace.clone(),
                        gate: GateId::Tests,
                        sequence: test_sequence,
                        provenance: EvidenceProvenance {
                            provider_id: "wht_corulix_engine::testing::run_cargo_test".to_string(),
                            provider_version: Some(test_outcome.provider_version.clone()),
                            authority: wht_corulix_core::AuthorityRole::Authoritative,
                        },
                        scope: Vec::new(),
                        input_fingerprint: session.last_edit_output_hash().cloned(),
                        result_summary,
                        reason: if test_outcome.passing {
                            None
                        } else {
                            Some(ReasonCode::TestFailuresReported)
                        },
                        truncated: test_outcome.truncated || truncated,
                        timestamp: EvidenceTimestamp(test_sequence),
                        snapshot_id: Some(session.content_snapshot_id()),
                    };
                    let recorded = session
                        .record_evidence(
                            requester_workspace,
                            requester_connection,
                            ProviderCategory::TestRunner,
                            test_evidence,
                        )
                        .is_ok();
                    (
                        GoRunSummary {
                            ran: true,
                            clean: test_outcome.passing,
                            finding_count: test_outcome.failed,
                            reason_code: None,
                        },
                        recorded,
                    )
                }
                Err(error) => (
                    GoRunSummary::unavailable(rust_test_error_reason(&error)),
                    false,
                ),
            }
        } else {
            (GoRunSummary::skipped(), false)
        };

        ValidateChangeOutcome::Executed {
            clean,
            error_count,
            warning_count,
            clippy: clippy_summary,
            test: test_summary,
            test_evidence_recorded,
        }
    }

    /// The P15 production-routing closure's real Go dispatch: `go build`
    /// (+`go vet`, folded into the same record) for `gate.diagnostics`, then
    /// `go test` for the distinct `gate.tests`, each spawned only when this
    /// session's own bound `ToolPlan` actually names the category as a
    /// requirement (`ChangeSession::requirement_authority`) --
    /// `P15_UNREQUIRED_GO_PROVIDER_EXECUTION_COUNT=0`.
    async fn validate_change_go(
        &self,
        session: &mut ChangeSession,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        cancellation: &wht_corulix_core::CancellationToken,
    ) -> ValidateChangeOutcome {
        if session
            .requirement_authority(ProviderCategory::TypecheckBuild)
            .is_none()
        {
            // Minimum Sufficient Tooling: this operation never asked for a
            // build/typecheck validator at all -- e.g. a Go
            // `DocumentationModify` session. No process is spawned.
            return ValidateChangeOutcome::NotRequired;
        }

        let effective = self.effective_config();
        let managed_root = match wht_corulix_tooling::provisioning::managed_toolchain_root() {
            Ok(root) => root,
            Err(_) => {
                return ValidateChangeOutcome::Unavailable {
                    reason_code: ReasonCode::RequiredProviderUnavailable,
                };
            }
        };
        let workspace_root = session.executor().workspace_root().clone();

        let build_outcome = go_validation::run_go_validator(
            GoValidator::Build,
            &managed_root,
            &workspace_root,
            &effective,
            cancellation,
        )
        .await;
        let build_outcome = match build_outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                return ValidateChangeOutcome::Unavailable {
                    reason_code: go_validator_error_reason(&error),
                };
            }
        };

        // `go vet` supplements the same `gate.diagnostics` record -- it is
        // never submitted as a second, independent Evidence item against
        // that gate (see this module's own doc comment for why: `Linter`'s
        // `SupportingOnly` authority must never be able to close or fail
        // `gate.diagnostics` on its own). Optional: an unavailable/erroring
        // `go vet` never blocks an otherwise-passing `go build`.
        let mut combined_clean = build_outcome.clean;
        let mut combined_summary = build_outcome.summary.clone();
        let mut combined_truncated = build_outcome.truncated;
        let vet_summary = if session
            .requirement_authority(ProviderCategory::Linter)
            .is_some()
        {
            match go_validation::run_go_validator(
                GoValidator::Vet,
                &managed_root,
                &workspace_root,
                &effective,
                cancellation,
            )
            .await
            {
                Ok(vet_outcome) => {
                    combined_clean = combined_clean && vet_outcome.clean;
                    combined_truncated = combined_truncated || vet_outcome.truncated;
                    if !vet_outcome.summary.is_empty() {
                        combined_summary.push_str("\n--- go vet ---\n");
                        combined_summary.push_str(&vet_outcome.summary);
                    }
                    GoRunSummary {
                        ran: true,
                        clean: vet_outcome.clean,
                        finding_count: vet_outcome.diagnostics.len() as u32,
                        reason_code: None,
                    }
                }
                Err(error) => GoRunSummary::unavailable(go_validator_error_reason(&error)),
            }
        } else {
            GoRunSummary::skipped()
        };

        let (result_summary, summary_truncated) = bounded_summary(&combined_summary);
        let build_sequence = session.evidence_history().len() as u64 + 1;
        let build_evidence = Evidence {
            session_id: session.id().clone(),
            workspace_identity: requester_workspace.clone(),
            gate: GateId::Diagnostics,
            sequence: build_sequence,
            provenance: EvidenceProvenance {
                provider_id: GoValidator::Build.provider_id().to_string(),
                provider_version: Some(build_outcome.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: Vec::new(),
            input_fingerprint: session.last_edit_output_hash().cloned(),
            result_summary,
            reason: if combined_clean {
                None
            } else {
                Some(ReasonCode::DiagnosticsFindingsReported)
            },
            truncated: combined_truncated || summary_truncated,
            timestamp: EvidenceTimestamp(build_sequence),
            snapshot_id: Some(session.content_snapshot_id()),
        };

        let build_summary = GoRunSummary {
            ran: true,
            clean: build_outcome.clean,
            finding_count: build_outcome.diagnostics.len() as u32,
            reason_code: None,
        };

        let build_evidence_recorded = match session.record_evidence(
            requester_workspace,
            requester_connection,
            ProviderCategory::TypecheckBuild,
            build_evidence,
        ) {
            Ok(()) => true,
            Err(SessionError::Denied(reason_code)) => {
                return ValidateChangeOutcome::EvidenceRejected { reason_code };
            }
            Err(SessionError::Mutation(_) | SessionError::Formatter(_)) => {
                return ValidateChangeOutcome::EvidenceRejected {
                    reason_code: ReasonCode::RequiredCapabilityUnavailable,
                };
            }
        };

        // `go test` targets the distinct, `Optional` `gate.tests` -- run
        // only when this session's `ToolPlan` names `TestRunner` as a
        // requirement, and never allowed to block the call even when it
        // cannot run (Optional: an unavailable test runner must not deny an
        // otherwise-passing build).
        let (test_summary, test_evidence_recorded) = if session
            .requirement_authority(ProviderCategory::TestRunner)
            .is_some()
        {
            match go_testing::run_go_test(&managed_root, &workspace_root, &effective, cancellation)
                .await
            {
                Ok(test_outcome) => {
                    let (result_summary, truncated) = bounded_summary(&test_outcome.summary);
                    let test_sequence = session.evidence_history().len() as u64 + 1;
                    let test_evidence = Evidence {
                        session_id: session.id().clone(),
                        workspace_identity: requester_workspace.clone(),
                        gate: GateId::Tests,
                        sequence: test_sequence,
                        provenance: EvidenceProvenance {
                            provider_id: "go test".to_string(),
                            provider_version: Some(test_outcome.provider_version.clone()),
                            authority: wht_corulix_core::AuthorityRole::Authoritative,
                        },
                        scope: Vec::new(),
                        input_fingerprint: session.last_edit_output_hash().cloned(),
                        result_summary,
                        reason: if test_outcome.passing {
                            None
                        } else {
                            Some(ReasonCode::TestFailuresReported)
                        },
                        truncated: test_outcome.truncated || truncated,
                        timestamp: EvidenceTimestamp(test_sequence),
                        snapshot_id: Some(session.content_snapshot_id()),
                    };
                    let recorded = session
                        .record_evidence(
                            requester_workspace,
                            requester_connection,
                            ProviderCategory::TestRunner,
                            test_evidence,
                        )
                        .is_ok();
                    (
                        GoRunSummary {
                            ran: true,
                            clean: test_outcome.passing,
                            finding_count: test_outcome.failed,
                            reason_code: None,
                        },
                        recorded,
                    )
                }
                Err(error) => (
                    GoRunSummary::unavailable(go_test_error_reason(&error)),
                    false,
                ),
            }
        } else {
            (GoRunSummary::skipped(), false)
        };

        ValidateChangeOutcome::GoExecuted {
            build: build_summary,
            vet: vet_summary,
            test: test_summary,
            build_evidence_recorded,
            test_evidence_recorded,
        }
    }

    /// The P16 production-routing closure's real TS/JS dispatch: `tsc
    /// --noEmit` (+ Biome lint, folded into the same `gate.diagnostics`
    /// record) for `TypecheckBuild`, then the discovered
    /// `scripts.test` runner for the distinct `gate.tests`, each spawned
    /// only when this session's own bound `ToolPlan` actually names the
    /// category as a requirement -- exactly [`Self::validate_change_go`]'s
    /// own pattern, reused for the third language rather than duplicated
    /// afresh. See [`crate::ts_validation`]/[`crate::ts_testing`] for the
    /// real invocation/parsing this dispatches to, and ADR 0010 for the
    /// governing decisions.
    async fn validate_change_typescript(
        &self,
        session: &mut ChangeSession,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        cancellation: &wht_corulix_core::CancellationToken,
    ) -> ValidateChangeOutcome {
        if session
            .requirement_authority(ProviderCategory::TypecheckBuild)
            .is_none()
        {
            // Minimum Sufficient Tooling: this operation never asked for a
            // typecheck validator at all. No process is spawned.
            return ValidateChangeOutcome::NotRequired;
        }

        let effective = self.effective_config();
        let managed_root = match wht_corulix_tooling::provisioning::managed_toolchain_root() {
            Ok(root) => root,
            Err(_) => {
                return ValidateChangeOutcome::Unavailable {
                    reason_code: ReasonCode::RequiredProviderUnavailable,
                };
            }
        };
        let workspace_root = session.executor().workspace_root().clone();

        let declared_major =
            crate::semantic::detect_declared_typescript_major(&workspace_root).await;

        let typecheck_outcome = ts_validation::run_typecheck(
            &managed_root,
            &workspace_root,
            declared_major,
            cancellation,
        )
        .await;
        let typecheck_outcome = match typecheck_outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                return ValidateChangeOutcome::Unavailable {
                    reason_code: ts_validator_error_reason(&error),
                };
            }
        };

        // Biome lint supplements the same `gate.diagnostics` record -- never
        // submitted as a second, independent Evidence item (see this
        // module's own doc comment: `Linter`'s `SupportingOnly` authority
        // must never be able to close or fail `gate.diagnostics` on its
        // own). Optional: an unavailable/erroring lint never blocks an
        // otherwise-passing typecheck. Targets this session's own first
        // bound scope prefix, per ADR 0010's `LINTER_PROVIDER` section
        // (a confined staged copy of the target file, never project-wide).
        let mut combined_clean = typecheck_outcome.is_clean();
        let mut combined_summary = typecheck_outcome.summary.clone();
        let mut combined_truncated = typecheck_outcome.truncated;
        let lint_summary = if session
            .requirement_authority(ProviderCategory::Linter)
            .is_some()
        {
            match session.scope().prefixes().first() {
                Some(relative_path) => {
                    match ts_validation::run_lint(
                        &managed_root,
                        &workspace_root,
                        relative_path,
                        cancellation,
                    )
                    .await
                    {
                        Ok(lint_outcome) => {
                            combined_clean = combined_clean && lint_outcome.is_clean();
                            combined_truncated = combined_truncated || lint_outcome.truncated;
                            if !lint_outcome.summary.is_empty() {
                                combined_summary.push_str("\n--- biome lint ---\n");
                                combined_summary.push_str(&lint_outcome.summary);
                            }
                            GoRunSummary {
                                ran: true,
                                clean: lint_outcome.is_clean(),
                                finding_count: lint_outcome.finding_count,
                                reason_code: None,
                            }
                        }
                        Err(error) => GoRunSummary::unavailable(ts_validator_error_reason(&error)),
                    }
                }
                None => GoRunSummary::unavailable(ReasonCode::RequiredCapabilityUnavailable),
            }
        } else {
            GoRunSummary::skipped()
        };

        let (result_summary, summary_truncated) = bounded_summary(&combined_summary);
        let typecheck_sequence = session.evidence_history().len() as u64 + 1;
        let typecheck_evidence = Evidence {
            session_id: session.id().clone(),
            workspace_identity: requester_workspace.clone(),
            gate: GateId::Diagnostics,
            sequence: typecheck_sequence,
            provenance: EvidenceProvenance {
                provider_id: "wht_corulix_engine::ts_validation::run_typecheck".to_string(),
                provider_version: Some(typecheck_outcome.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: Vec::new(),
            input_fingerprint: session.last_edit_output_hash().cloned(),
            result_summary,
            reason: if combined_clean {
                None
            } else {
                Some(ReasonCode::DiagnosticsFindingsReported)
            },
            truncated: combined_truncated || summary_truncated,
            timestamp: EvidenceTimestamp(typecheck_sequence),
            snapshot_id: Some(session.content_snapshot_id()),
        };

        let typecheck_summary = GoRunSummary {
            ran: true,
            clean: typecheck_outcome.is_clean(),
            finding_count: typecheck_outcome.finding_count,
            reason_code: None,
        };

        let typecheck_evidence_recorded = match session.record_evidence(
            requester_workspace,
            requester_connection,
            ProviderCategory::TypecheckBuild,
            typecheck_evidence,
        ) {
            Ok(()) => true,
            Err(SessionError::Denied(reason_code)) => {
                return ValidateChangeOutcome::EvidenceRejected { reason_code };
            }
            Err(SessionError::Mutation(_) | SessionError::Formatter(_)) => {
                return ValidateChangeOutcome::EvidenceRejected {
                    reason_code: ReasonCode::RequiredCapabilityUnavailable,
                };
            }
        };

        // The discovered `scripts.test` runner targets the distinct,
        // `Optional` `gate.tests` -- run only when this session's `ToolPlan`
        // names `TestRunner` as a requirement, and never allowed to block
        // the call even when it cannot run.
        let (test_summary, test_evidence_recorded) = if session
            .requirement_authority(ProviderCategory::TestRunner)
            .is_some()
        {
            match ts_testing::run_test(&managed_root, &workspace_root, &effective, cancellation)
                .await
            {
                Ok(test_outcome) => {
                    let (result_summary, truncated) = bounded_summary(&test_outcome.summary);
                    let test_sequence = session.evidence_history().len() as u64 + 1;
                    let test_evidence = Evidence {
                        session_id: session.id().clone(),
                        workspace_identity: requester_workspace.clone(),
                        gate: GateId::Tests,
                        sequence: test_sequence,
                        provenance: EvidenceProvenance {
                            provider_id: test_outcome.runner.provider_id().to_string(),
                            provider_version: None,
                            authority: wht_corulix_core::AuthorityRole::Authoritative,
                        },
                        scope: Vec::new(),
                        input_fingerprint: session.last_edit_output_hash().cloned(),
                        result_summary,
                        reason: if test_outcome.passing {
                            None
                        } else {
                            Some(ReasonCode::TestFailuresReported)
                        },
                        truncated: test_outcome.truncated || truncated,
                        timestamp: EvidenceTimestamp(test_sequence),
                        snapshot_id: Some(session.content_snapshot_id()),
                    };
                    let recorded = session
                        .record_evidence(
                            requester_workspace,
                            requester_connection,
                            ProviderCategory::TestRunner,
                            test_evidence,
                        )
                        .is_ok();
                    (
                        GoRunSummary {
                            ran: true,
                            clean: test_outcome.passing,
                            finding_count: u32::from(!test_outcome.passing),
                            reason_code: None,
                        },
                        recorded,
                    )
                }
                Err(error) => (
                    GoRunSummary::unavailable(ts_test_error_reason(&error)),
                    false,
                ),
            }
        } else {
            (GoRunSummary::skipped(), false)
        };

        ValidateChangeOutcome::TsExecuted {
            typecheck: typecheck_summary,
            lint: lint_summary,
            test: test_summary,
            typecheck_evidence_recorded,
            test_evidence_recorded,
        }
    }

    /// The P17 production-routing closure's real Python dispatch: `pyright
    /// --outputjson` (+ `ruff check`, folded into the same `gate.diagnostics`
    /// record) for `TypecheckBuild`, then the discovered `pytest` runner for
    /// the distinct `gate.tests`, each spawned only when this session's own
    /// bound `ToolPlan` actually names the category as a requirement --
    /// exactly [`Self::validate_change_typescript`]'s own pattern, reused for
    /// the fourth language rather than duplicated afresh. See
    /// [`crate::python_validation`]/[`crate::python_testing`] for the real
    /// invocation/parsing this dispatches to, and ADR 0011 for the governing
    /// decisions.
    async fn validate_change_python(
        &self,
        session: &mut ChangeSession,
        requester_workspace: &WorkspaceIdentity,
        requester_connection: &ConnectionId,
        cancellation: &wht_corulix_core::CancellationToken,
    ) -> ValidateChangeOutcome {
        if session
            .requirement_authority(ProviderCategory::TypecheckBuild)
            .is_none()
        {
            // Minimum Sufficient Tooling: this operation never asked for a
            // typecheck validator at all. No process is spawned.
            return ValidateChangeOutcome::NotRequired;
        }

        let effective = self.effective_config();
        let workspace_root = session.executor().workspace_root().clone();

        // Resolved once, up front: both the managed-first Pyright CLI
        // (`TypecheckBuild`, M03 Python managed-auxiliary final closure) and
        // `ruff check`'s confined staged copy (below) need this same
        // Corulix-owned managed root.
        let managed_root = match wht_corulix_tooling::provisioning::managed_toolchain_root() {
            Ok(root) => root,
            Err(_) => {
                return ValidateChangeOutcome::Unavailable {
                    reason_code: ReasonCode::RequiredProviderUnavailable,
                };
            }
        };

        let typecheck_outcome = python_validation::run_typecheck(
            &managed_root,
            &effective,
            &workspace_root,
            cancellation,
        )
        .await;
        let typecheck_outcome = match typecheck_outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                return ValidateChangeOutcome::Unavailable {
                    reason_code: python_validator_error_reason(&error),
                };
            }
        };

        // `ruff check` supplements the same `gate.diagnostics` record --
        // never submitted as a second, independent Evidence item (see this
        // module's own doc comment: `Linter`'s `SupportingOnly` authority
        // must never be able to close or fail `gate.diagnostics` on its
        // own). Optional: an unavailable/erroring lint never blocks an
        // otherwise-passing typecheck. Targets this session's own first
        // bound scope prefix, per ADR 0011's own confined-staged-copy
        // discipline (never project-wide).
        let mut combined_clean = typecheck_outcome.is_clean();
        let mut combined_summary = typecheck_outcome.summary.clone();
        let mut combined_truncated = typecheck_outcome.truncated;
        let lint_summary = if session
            .requirement_authority(ProviderCategory::Linter)
            .is_some()
        {
            match session.scope().prefixes().first() {
                Some(relative_path) => {
                    match python_validation::run_lint(
                        &managed_root,
                        &effective,
                        &workspace_root,
                        relative_path,
                        cancellation,
                    )
                    .await
                    {
                        Ok(lint_outcome) => {
                            combined_clean = combined_clean && lint_outcome.is_clean();
                            combined_truncated = combined_truncated || lint_outcome.truncated;
                            if !lint_outcome.summary.is_empty() {
                                combined_summary.push_str("\n--- ruff check ---\n");
                                combined_summary.push_str(&lint_outcome.summary);
                            }
                            GoRunSummary {
                                ran: true,
                                clean: lint_outcome.is_clean(),
                                finding_count: lint_outcome.finding_count,
                                reason_code: None,
                            }
                        }
                        Err(error) => {
                            GoRunSummary::unavailable(python_validator_error_reason(&error))
                        }
                    }
                }
                None => GoRunSummary::unavailable(ReasonCode::RequiredCapabilityUnavailable),
            }
        } else {
            GoRunSummary::skipped()
        };

        let (result_summary, summary_truncated) = bounded_summary(&combined_summary);
        let typecheck_sequence = session.evidence_history().len() as u64 + 1;
        let typecheck_evidence = Evidence {
            session_id: session.id().clone(),
            workspace_identity: requester_workspace.clone(),
            gate: GateId::Diagnostics,
            sequence: typecheck_sequence,
            provenance: EvidenceProvenance {
                provider_id: "wht_corulix_engine::python_validation::run_typecheck".to_string(),
                provider_version: Some(typecheck_outcome.provider_version.clone()),
                authority: wht_corulix_core::AuthorityRole::Authoritative,
            },
            scope: Vec::new(),
            input_fingerprint: session.last_edit_output_hash().cloned(),
            result_summary,
            reason: if combined_clean {
                None
            } else {
                Some(ReasonCode::DiagnosticsFindingsReported)
            },
            truncated: combined_truncated || summary_truncated,
            timestamp: EvidenceTimestamp(typecheck_sequence),
            snapshot_id: Some(session.content_snapshot_id()),
        };

        let typecheck_summary = GoRunSummary {
            ran: true,
            clean: typecheck_outcome.is_clean(),
            finding_count: typecheck_outcome.finding_count,
            reason_code: None,
        };

        let typecheck_evidence_recorded = match session.record_evidence(
            requester_workspace,
            requester_connection,
            ProviderCategory::TypecheckBuild,
            typecheck_evidence,
        ) {
            Ok(()) => true,
            Err(SessionError::Denied(reason_code)) => {
                return ValidateChangeOutcome::EvidenceRejected { reason_code };
            }
            Err(SessionError::Mutation(_) | SessionError::Formatter(_)) => {
                return ValidateChangeOutcome::EvidenceRejected {
                    reason_code: ReasonCode::RequiredCapabilityUnavailable,
                };
            }
        };

        // The discovered `pytest` runner targets the distinct, `Optional`
        // `gate.tests` -- run only when this session's `ToolPlan` names
        // `TestRunner` as a requirement, and never allowed to block the call
        // even when it cannot run.
        let (test_summary, test_evidence_recorded) = if session
            .requirement_authority(ProviderCategory::TestRunner)
            .is_some()
        {
            match python_testing::run_pytest(&workspace_root, &effective, cancellation).await {
                Ok(test_outcome) => {
                    let (result_summary, truncated) = bounded_summary(&test_outcome.summary);
                    let test_sequence = session.evidence_history().len() as u64 + 1;
                    let test_evidence = Evidence {
                        session_id: session.id().clone(),
                        workspace_identity: requester_workspace.clone(),
                        gate: GateId::Tests,
                        sequence: test_sequence,
                        provenance: EvidenceProvenance {
                            provider_id: "pytest".to_string(),
                            provider_version: Some(test_outcome.provider_version.clone()),
                            authority: wht_corulix_core::AuthorityRole::Authoritative,
                        },
                        scope: Vec::new(),
                        input_fingerprint: session.last_edit_output_hash().cloned(),
                        result_summary,
                        reason: if test_outcome.passing {
                            None
                        } else {
                            Some(ReasonCode::TestFailuresReported)
                        },
                        truncated: test_outcome.truncated || truncated,
                        timestamp: EvidenceTimestamp(test_sequence),
                        snapshot_id: Some(session.content_snapshot_id()),
                    };
                    let recorded = session
                        .record_evidence(
                            requester_workspace,
                            requester_connection,
                            ProviderCategory::TestRunner,
                            test_evidence,
                        )
                        .is_ok();
                    (
                        GoRunSummary {
                            ran: true,
                            clean: test_outcome.passing,
                            finding_count: u32::from(!test_outcome.passing),
                            reason_code: None,
                        },
                        recorded,
                    )
                }
                Err(error) => (
                    GoRunSummary::unavailable(python_test_error_reason(&error)),
                    false,
                ),
            }
        } else {
            (GoRunSummary::skipped(), false)
        };

        ValidateChangeOutcome::PythonExecuted {
            typecheck: typecheck_summary,
            lint: lint_summary,
            test: test_summary,
            typecheck_evidence_recorded,
            test_evidence_recorded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::OperationIntent;
    use wht_corulix_workspace::WorkspaceContext;

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!(
            "corulix-engine-validate-change-test-{label}-{stamp}"
        ));
        let _ = fs::create_dir_all(&root);
        root
    }

    /// An untrusted (default) engine must never spawn `cargo check` at all
    /// -- `validate_change` reports `Unavailable` deterministically,
    /// exactly matching `authorize_trusted_execution`'s own fail-closed
    /// contract, before this module even resolves a managed toolchain root.
    #[tokio::test]
    async fn untrusted_engine_never_runs_cargo_check() -> wht_corulix_core::CorulixResult<()> {
        let root_dir = temp_root("untrusted");
        let workspace_root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(workspace_root.clone(), "root".to_string());
        let engine = CorulixEngine::open(context);
        assert!(!engine.effective_config().is_execution_class_allowed(
            wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution
        ));

        let executor = wht_corulix_mutation::MutationExecutor::new(workspace_root);
        let session_id = ChangeSession::generate_id()?;
        let workspace_identity =
            WorkspaceIdentity::from_opaque_token("test-workspace".to_string())?;
        let connection = ConnectionId::from_opaque_token("test-connection".to_string())?;
        let mut session = ChangeSession::open(
            session_id,
            workspace_identity.clone(),
            connection.clone(),
            0,
            executor,
        );
        // A real `ValidateChange`-shaped `ToolPlan` *is* needed here (unlike
        // before this closure): `validate_change_rust` now consults
        // `ChangeSession::requirement_authority(TypecheckBuild)` before
        // resolving a managed toolchain root at all (Minimum Sufficient
        // Tooling, mirroring `validate_change_go`'s own guard) -- an empty,
        // never-baselined `ToolPlan` would report `NotRequired` here, never
        // reaching the untrusted-execution check this test exists to prove.
        session
            .enter_scope(crate::session::SessionScope::new(Vec::new()))
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let plan = engine.plan_operation(OperationIntent::ValidateChange);
        session
            .baseline(plan, Vec::new())
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

        let cancellation = wht_corulix_core::CancellationToken::new();
        let outcome = engine
            .validate_change(
                &mut session,
                &workspace_identity,
                &connection,
                1,
                &cancellation,
            )
            .await;

        let ValidateChangeOutcome::Unavailable { reason_code } = outcome else {
            unreachable!(
                "an untrusted engine's EffectiveConfig never authorizes TrustedWorkspaceExecution"
            );
        };
        assert_eq!(reason_code, ReasonCode::RequiredProviderUnavailable);

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }
}
