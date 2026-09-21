// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13: request/response DTOs for the 14 canonical MCP tools.
//!
//! Every request DTO is `#[serde(deny_unknown_fields)]` (fail-closed: an
//! unexpected field is rejected, never silently ignored) and carries no
//! field through which a caller could supply/override a `RiskClass`,
//! `ToolPlan`, gate requirement, `EnforcementLevel`, or `WorkspaceTrust` --
//! those are exclusively derived server-side (Architecture Rule H). Every
//! response DTO reuses an already-`schemars::JsonSchema`-deriving
//! `wht_corulix_core`/`wht_corulix_engine` type wherever one exists; a
//! handful of small local response enums exist only where no such type
//! exists yet (e.g. `parse_file`'s error path, `submit_edit`'s outcome).

use rmcp::schemars;
use serde::{Deserialize, Serialize};
use wht_corulix_core::{
    CompactSymbol, GateId, LanguageId, OperationIntent, ReasonCode, ToolPlan, WorkspaceInfo,
    WorkspaceTopologySummary,
};
use wht_corulix_engine::format_preview::FormatPreviewOutcome;
use wht_corulix_engine::search::SearchOutcome;
use wht_corulix_engine::semantic::{SemanticOperation, SemanticOutcome};
use wht_corulix_engine::session::ChangeStatusView;
use wht_corulix_engine::toolchain_status::ToolchainStatus;
use wht_corulix_engine::validate_change::ValidateChangeOutcome;

// ---------------------------------------------------------------------
// 1-3: runtime_identity / workspace_info / toolchain_status -- no input.
// ---------------------------------------------------------------------

/// All three take no parameters; `rmcp`'s `#[tool]` macro accepts a plain
/// `fn(&self)` for those, so no request DTO is needed for them.
pub type NoInput = ();

// ---------------------------------------------------------------------
// 4: plan_operation
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanOperationParams {
    #[schemars(description = "The operation intent to derive a ToolPlan for")]
    pub intent: OperationIntent,
    #[schemars(description = "Optional language scope for a language-aware plan")]
    pub language: Option<LanguageId>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct PlanOperationOutput {
    pub plan: ToolPlan,
}

// ---------------------------------------------------------------------
// 5: search
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchParams {
    #[schemars(description = "Literal or regex pattern to search for")]
    pub pattern: String,
    #[serde(default)]
    #[schemars(description = "Whether `pattern` is a regex (default: literal)")]
    pub is_regex: bool,
    #[serde(default)]
    #[schemars(description = "Case-insensitive matching (default: false)")]
    pub case_insensitive: bool,
    #[serde(default)]
    #[schemars(description = "Workspace root selector; omit for a single-root workspace")]
    pub root_selector: Option<String>,
}

// ---------------------------------------------------------------------
// 6: parse_file
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParseFileParams {
    #[schemars(description = "Workspace-relative path only")]
    pub path: String,
    #[serde(default)]
    #[schemars(description = "Workspace root selector; omit for a single-root workspace")]
    pub root_selector: Option<String>,
}

/// Maximum number of [`CompactSymbol`] entries `parse_file`'s success output
/// will include. This is an MCP-contract bound, not a Parse-extraction bound
/// -- `wht_corulix_syntax` continues to extract and return every symbol it
/// finds (`INTERNAL_PARSE_INFORMATION_LOSS=NO`); this cap and its
/// `truncated` flag are applied only when projecting the AI-facing compact
/// DTO, one layer up. A capped-but-unflagged result would misrepresent a
/// large file as if it had no more symbols; `truncated: true` makes that
/// state explicit and deterministic instead.
pub const PARSE_COMPACT_SYMBOLS_MAX: usize = 500;

/// `parse_file`'s outcome. Distinct from every other tool's outcome shape
/// because [`wht_corulix_engine::CorulixEngine::parse_relative_file`]
/// returns a plain `CorulixResult`, not a self-describing outcome enum --
/// this is the one, explicit translation point. `error_code` is a stable,
/// coarse tag over [`wht_corulix_core::CorulixError`]'s own variants
/// (which are not themselves serializable); it is deliberately not a
/// [`ReasonCode`], which is reserved for `ToolPlan`/gate-derived reasons.
///
/// `Ok`'s fields are the ONE canonical, compact, AI-facing Parse MCP
/// contract (Parse MCP structured_content canonicalization pass): every
/// field here is `structured_content` -- there is no second, differently
/// shaped Parse contract anywhere else (`PARSE_PUBLIC_OUTPUT_VARIANT_
/// COUNT=1`). The richer internal `ParseSummary`/`Symbol` model
/// (AST-derived byte ranges, `language_specific_kind`, `root_kind`,
/// `schema_version`, ...) remains available to internal Rust callers
/// (`wht_corulix_cli`, `wht_corulix_engine::parse_relative_file`'s own
/// first return value) but is deliberately NOT part of this MCP contract --
/// see this module's own top-level doc comment on the Internal-Model-vs-
/// MCP-Contract distinction.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ParseFileOutput {
    Ok {
        language: LanguageId,
        /// `true` when Tree-sitter reported no syntax error for this file
        /// (`!ParseSummary::has_syntax_error`) -- named positively so a
        /// caller does not have to double-negate to check parse health.
        syntax_ok: bool,
        symbols: Vec<CompactSymbol>,
        /// `true` only when the real symbol count exceeded
        /// [`PARSE_COMPACT_SYMBOLS_MAX`] and `symbols` was capped --
        /// `false` (never omitted) otherwise, so this field is always a
        /// reliable, explicit completeness signal.
        truncated: bool,
    },
    Error {
        error_code: String,
        message: String,
    },
}

// ---------------------------------------------------------------------
// 7: semantic
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticParams {
    #[schemars(description = "definition | references | diagnostics | rename_preview")]
    pub operation: SemanticOperation,
    #[schemars(description = "Language to scope the semantic provider lookup to")]
    pub language: LanguageId,
    #[schemars(description = "Workspace-relative path the operation targets")]
    pub path: String,
    #[schemars(description = "Zero-based line the operation targets")]
    pub line_zero_based: u32,
    #[schemars(description = "Zero-based UTF-8 byte column the operation targets")]
    pub byte_column_zero_based: u32,
    #[schemars(description = "Zero-based UTF-8 byte offset into the file the operation targets")]
    pub byte_offset: u64,
    #[serde(default)]
    #[schemars(description = "New identifier name; required for rename_preview only")]
    pub new_name: Option<String>,
}

// ---------------------------------------------------------------------
// 8: format_preview
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FormatPreviewParams {
    #[schemars(description = "Workspace-relative path to one supported source file.")]
    pub path: String,
    #[serde(default)]
    #[schemars(description = "Workspace root selector; omit for a single-root workspace")]
    pub root_selector: Option<String>,
}

// ---------------------------------------------------------------------
// 9: begin_change
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BeginChangeParams {
    #[schemars(description = "The operation intent this change session governs")]
    pub intent: OperationIntent,
    /// P15: the language this change session governs, when the caller knows
    /// it.
    ///
    /// A **field on an existing tool**, not a new tool
    /// (`FINAL_MCP_TOOL_COUNT` stays 14,
    /// `P15_MCP_SURFACE_GROWTH_COUNT=0`). Before P15, `begin_change` passed
    /// `language: None` unconditionally, so a required `LanguageServer`
    /// requirement was always evaluated against the category-level view --
    /// which meant an MCP caller could not express "this session governs Go"
    /// at all, and any language-scoped semantic intent was reported
    /// `Unexecutable` for a reason unrelated to the real per-language
    /// provider state.
    ///
    /// This carries no authority of its own: it only selects *which*
    /// language's real, already-resolved provider availability
    /// `wht_corulix_engine::routing::evaluate` consults (Architecture Rule
    /// H's derivation stays entirely in the Engine). A caller naming a
    /// language whose providers are unavailable gets a truthful
    /// `Unexecutable` plan, never an elevated one -- a request cannot widen
    /// provider resolution (see `wht_corulix_config::trust`'s own module
    /// doc: `RequestOptions` structurally carries no provider field).
    #[serde(default)]
    #[schemars(
        description = "Language this change session governs; omit when not language-scoped"
    )]
    pub language: Option<wht_corulix_core::LanguageId>,
    #[serde(default)]
    #[schemars(description = "Workspace root selector; omit for a single-root workspace")]
    pub root_selector: Option<String>,
    #[schemars(
        description = "Workspace-relative path prefixes this session's edits are confined to"
    )]
    pub scope_prefixes: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BeginChangeOutput {
    Opened {
        session_id: String,
        status: ChangeStatusView,
    },
    Denied {
        reason_code: ReasonCode,
        message: String,
    },
}

// ---------------------------------------------------------------------
// 10: submit_edit
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EditRequestParams {
    Create {
        content_utf8: String,
    },
    Replace {
        #[schemars(
            description = "Exact lowercase-hex SHA-256 digest (64 characters) of the target's current bytes; a mismatch (stale or malformed) rejects the edit before any write",
            regex(pattern = "^[0-9a-f]{64}$")
        )]
        expected_precondition_hash_hex: String,
        content_utf8: String,
    },
    Delete {
        #[schemars(
            description = "Exact lowercase-hex SHA-256 digest (64 characters) of the target's current bytes; a mismatch (stale or malformed) rejects the edit before any write",
            regex(pattern = "^[0-9a-f]{64}$")
        )]
        expected_precondition_hash_hex: String,
    },
}

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubmitEditParams {
    #[schemars(description = "The change session id returned by begin_change")]
    pub session_id: String,
    #[schemars(description = "Workspace-relative path this edit targets")]
    pub relative_path: String,
    #[schemars(description = "The edit to apply")]
    pub edit: EditRequestParams,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SubmitEditOutput {
    Committed { mutations_applied: usize },
    Denied { reason_code: ReasonCode },
    SessionNotFound,
}

// ---------------------------------------------------------------------
// 11: validate_change
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidateChangeParams {
    #[schemars(description = "The change session id returned by begin_change")]
    pub session_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ValidateChangeOutputEnvelope {
    Ran { outcome: ValidateChangeOutcome },
    SessionNotFound,
}

// ---------------------------------------------------------------------
// 12: change_status
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeStatusParams {
    #[schemars(description = "The change session id returned by begin_change")]
    pub session_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ChangeStatusOutput {
    Found { status: ChangeStatusView },
    SessionNotFound,
}

// ---------------------------------------------------------------------
// 13: complete_change
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompleteChangeParams {
    #[schemars(description = "The change session id returned by begin_change")]
    pub session_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CompleteChangeOutput {
    Completed,
    Denied { reason_code: ReasonCode },
    SessionNotFound,
}

// ---------------------------------------------------------------------
// 14: abort_change
// ---------------------------------------------------------------------

// Contract Validation Gate: `Serialize` is added alongside the pre-existing
// `Deserialize` solely so `contract_gate::validate_input` can re-serialize
// an already-typed params value back to `Value` for defense-in-depth JSON
// Schema validation. This changes no field, no shape, and no generated
// schema (`schemars::JsonSchema`'s derive is independent of `Serialize`) --
// every request DTO's wire format is unaffected.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AbortChangeParams {
    #[schemars(description = "The change session id returned by begin_change")]
    pub session_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AbortChangeOutput {
    Aborted,
    Denied { reason_code: ReasonCode },
    SessionNotFound,
}

// ---------------------------------------------------------------------
// Shared response shapes for tools 1-3.
// ---------------------------------------------------------------------

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct WorkspaceInfoOutput(pub WorkspaceInfo);

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct TopologyOutput(pub WorkspaceTopologySummary);

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ToolchainStatusOutput(pub ToolchainStatus);

// Silence "never constructed"/unused-import concerns for types only used as
// generic bounds/annotations in this module's own doc comments.
#[allow(dead_code)]
fn _unused_type_anchors(_: GateId, _: SearchOutcome, _: SemanticOutcome, _: FormatPreviewOutcome) {}
