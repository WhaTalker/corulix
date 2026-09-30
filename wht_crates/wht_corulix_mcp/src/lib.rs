// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! MCP transport layer exposing `CorulixEngine` over stdio (Phase 13
//! canonical rebaseline: exactly 14 typed tools, zero legacy aliases).
//!
//! This crate upholds Architecture Rule B: `wht_corulix_mcp` depends only on
//! `wht_corulix_core` and `wht_corulix_engine`. It never derives a
//! `RiskClass`/`ToolPlan`/required-gate list/`EnforcementLevel`/
//! `WorkspaceTrust` itself (Architecture Rule H is exclusively
//! `wht_corulix_engine`'s), never calls Search/LSP/Tooling/Formatter/
//! Mutation crates directly, never spawns a process directly, never writes
//! to the workspace directly, and never fabricates Evidence -- every one of
//! those flows through `wht_corulix_engine`'s own public API
//! (`CorulixEngine::plan_operation`, `session::ChangeSession`'s methods,
//! `diagnostics`/`testing` indirectly via `validate_change`, etc.).
//!
//! No MCP Roots capability (deprecated by SEP-2577, and this server never
//! advertises or reads one) and no MCP protocol Logging capability
//! (`ServerCapabilities::logging` is left `None`). Protocol version is
//! explicitly pinned to `2026-07-28`
//! ([`rmcp::model::ProtocolVersion::V_2026_07_28`]) in [`CorulixMcpServer`]'s
//! `get_info`, rather than relying on the SDK's own `LATEST` default (which
//! is `2025-11-25` in rmcp 3.0.1). `stdout` is reserved for JSON-RPC only;
//! every diagnostic goes to `tracing`, which this crate's own caller wires
//! to stderr (see `wht_corulix_cli::main`).

mod capability_notes;
mod contract_gate;
pub mod dto;
pub mod instructions;

use dto::*;
use rmcp::handler::server::common::schema_for_output;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, ServiceExt, tool, tool_router, transport::stdio};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use wht_corulix_core::{
    ChangeSessionId, CompactSymbol, ConnectionId, EvidenceTimestamp, ParseSummary, ReasonCode,
    WorkspaceIdentity,
};
use wht_corulix_engine::CorulixEngine;
use wht_corulix_engine::search::{SearchOutcome, SearchRequest};
use wht_corulix_engine::session::{ChangeSession, EditRequestKind, single_file_batch};

/// MCP server handle wrapping a shared `CorulixEngine` and this process's
/// own live `ChangeSession` store.
///
/// `Clone` is derived because `rmcp` may hand out this handler across
/// concurrent request-handling tasks; cloning only bumps the `Arc`
/// refcounts, it never duplicates workspace or session state -- every
/// clone shares the exact same session store.
#[derive(Clone)]
pub struct CorulixMcpServer {
    engine: Arc<CorulixEngine>,
    /// Every open `ChangeSession` this stdio connection has created, keyed
    /// by its id. `tokio::sync::Mutex` (not `std::sync::Mutex`): sessions
    /// are mutated across `.await` points (`submit_edit`/`validate_change`
    /// call real async engine operations while the lock would otherwise be
    /// held).
    sessions: Arc<Mutex<HashMap<ChangeSessionId, ChangeSession>>>,
    /// This stdio connection's own identity, minted once at server
    /// construction (Rule M / Phase 10 §17: exactly one connection per
    /// stdio process, per `wht_corulix_core::ConnectionId`'s own doc
    /// comment) -- never re-derived per call.
    connection_id: ConnectionId,
    /// This process's bound workspace identity, resolved once by
    /// `wht_corulix_workspace::resolve_workspace` before this server was
    /// constructed (see `wht_corulix_cli::main::run_mcp_stdio`) -- every
    /// `ChangeSession` this server opens is bound to this exact identity.
    workspace_identity: WorkspaceIdentity,
    /// The Contract Validation Gate's compiled registry -- built once,
    /// eagerly, in [`Self::new_with_registry`], never lazily. Its very
    /// existence on a live `Self` value proves `ContractRegistry::build()`
    /// already succeeded (Contract Gate corrective-pass Section 1:
    /// `CONTRACT_SCHEMA_COMPILE_FAILURE_FAILS_STARTUP=YES`) -- there is no
    /// `CorulixMcpServer` value reachable by any code path whose registry
    /// failed to compile.
    contract_registry: Arc<contract_gate::ContractRegistry>,
    /// Corulix 1.1.0 (ADR 0012): this connection's effective MCP tool
    /// exposure policy -- immutable for the process's lifetime, matching
    /// [`Self::workspace_identity`]/[`Self::contract_registry`]'s own
    /// once-resolved-never-reloaded lifecycle. Defaults to
    /// [`wht_corulix_core::EffectiveToolSet::all_enabled`] (Corulix 1.0.0's
    /// exact behavior) unless [`Self::with_tool_policy`] attaches a
    /// workspace-authored, already-validated reduction. The **sole**
    /// production consumer is [`Self::effective_tool_router`].
    tool_policy: Arc<wht_corulix_core::EffectiveToolSet>,
    /// Corulix 1.1.0 (ADR 0012, Phase G): whether [`Self::with_tool_policy`]
    /// was ever called on this instance -- distinct from
    /// `tool_policy.is_reduced()`, since an explicitly-authored policy that
    /// happens to disable nothing is still "configured". The sole consumer
    /// is [`Self::workspace_info`]'s `WorkspaceInfoView::tool_policy_configured`.
    tool_policy_configured: bool,
}

impl CorulixMcpServer {
    /// Wraps an already-opened engine and this process's resolved
    /// workspace identity for MCP serving. Fails if this process's own
    /// `ConnectionId` cannot be minted (CSPRNG failure -- see
    /// [`ChangeSession::generate_connection_id`]), or if the Contract
    /// Validation Gate's registry fails to build (see
    /// `Self::new_with_registry`).
    pub fn new(
        engine: Arc<CorulixEngine>,
        workspace_identity: WorkspaceIdentity,
    ) -> wht_corulix_core::CorulixResult<Self> {
        Self::new_with_registry(
            engine,
            workspace_identity,
            contract_gate::ContractRegistry::build(),
        )
    }

    /// The real constructor's fallible-registry seam, split out so tests
    /// can drive a deliberately failed [`contract_gate::ContractRegistry`]
    /// build through the exact same integration path production startup
    /// uses, without corrupting a real production schema to do it (see
    /// `contract_gate`'s own `build_with_injected_invalid_schema` and this
    /// crate's `server_construction_fails_closed_when_registry_build_fails`
    /// test). `registry: Err(_)` here is the one and only way this
    /// function returns `Err` for a reason other than connection-id
    /// generation -- and it does so *before* any field of `Self` is ever
    /// populated, so no `CorulixMcpServer` value (and therefore no
    /// `#[tool]` handler, every one of which requires `&self`) can ever
    /// exist on this path.
    fn new_with_registry(
        engine: Arc<CorulixEngine>,
        workspace_identity: WorkspaceIdentity,
        registry: Result<contract_gate::ContractRegistry, contract_gate::ContractGateInitError>,
    ) -> wht_corulix_core::CorulixResult<Self> {
        let contract_registry = registry.map_err(|error| {
            tracing::error!(
                target: "wht_corulix_mcp::contract_gate",
                %error,
                "contract gate: registry construction failed at startup -- refusing to become ready"
            );
            wht_corulix_core::CorulixError::Internal
        })?;
        Ok(Self {
            engine,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            connection_id: ChangeSession::generate_connection_id()?,
            workspace_identity,
            contract_registry: Arc::new(contract_registry),
            tool_policy: Arc::new(wht_corulix_core::EffectiveToolSet::all_enabled()),
            tool_policy_configured: false,
        })
    }

    /// Corulix 1.1.0 (ADR 0012): attaches an already-validated tool
    /// exposure policy to this server. Additive consuming builder --
    /// mirrors [`Self::new_with_registry`]'s own fail-closed-at-startup
    /// pattern exactly (a validation failure here means no `Self` value is
    /// ever produced, so no `#[tool]` handler -- every one of which
    /// requires `&self` -- can ever run against an invalid policy) and
    /// never changes [`Self::new`]'s own public signature (a published,
    /// crates.io API this crate must not break). Absent (no call to this
    /// method), [`Self::tool_policy`] stays
    /// [`wht_corulix_core::EffectiveToolSet::all_enabled`] -- Corulix
    /// 1.0.0's exact behavior, unaffected.
    pub fn with_tool_policy(
        mut self,
        policy: Result<
            wht_corulix_core::EffectiveToolSet,
            wht_corulix_core::ToolPolicyValidationError,
        >,
    ) -> wht_corulix_core::CorulixResult<Self> {
        let policy = policy.map_err(|error| {
            tracing::error!(
                target: "wht_corulix_mcp::tool_policy",
                %error,
                "tool policy: validation failed at startup -- refusing to become ready"
            );
            wht_corulix_core::CorulixError::Internal
        })?;
        self.tool_policy = Arc::new(policy);
        self.tool_policy_configured = true;
        Ok(self)
    }

    /// Corulix 1.1.0 (ADR 0012): the **sole** production insertion point
    /// for tool-exposure policy. Builds `Self::tool_router()`'s exact
    /// compile-time-declared base (the same 14-tool set
    /// `wht_scripts/wht_verify_architecture.py` Rule S counts, completely
    /// unaffected by this method), then applies
    /// [`rmcp::handler::server::router::tool::ToolRouter::disable_route`]
    /// for every name [`Self::tool_policy`] disables -- an existing,
    /// already-tested `rmcp` SDK mechanism, not new dispatch logic of this
    /// crate's own. [`Self::list_tools`]/[`Self::call_tool`]/[`Self::get_tool`]
    /// below all call this instead of the bare static router, so a
    /// disabled tool is both invisible to discovery and rejected on direct
    /// call before any handler body runs -- `ToolRouter::call`'s own
    /// existing fail-closed behavior for a disabled name. When
    /// [`Self::tool_policy`] is
    /// [`wht_corulix_core::EffectiveToolSet::all_enabled`] (no workspace
    /// policy configured), `disabled_names()` is empty, so this returns
    /// byte-for-byte the same router `Self::tool_router()` alone would.
    fn effective_tool_router(&self) -> rmcp::handler::server::router::tool::ToolRouter<Self> {
        let mut router = Self::tool_router();
        for name in self.tool_policy.disabled_names() {
            router.disable_route(name);
        }
        router
    }

    /// Serializes `value` as an unconditionally successful structured tool
    /// result -- for the small set of tools (`runtime_identity`,
    /// `workspace_info`, `toolchain_status`, `plan_operation`) whose Rust
    /// return type carries no business-failure variant of its own:
    /// deriving a `ToolPlan`/reading static identity never itself fails.
    fn plain_result<T: Serialize>(&self, tool: &'static str, value: &T) -> CallToolResult {
        match serde_json::to_value(value) {
            Ok(json) => contract_gate::finalize(
                &self.contract_registry,
                tool,
                CallToolResult::structured(json),
            ),
            Err(error) => CallToolResult::structured_error(serde_json::json!({
                "status": "error",
                "error_code": "INTERNAL",
                "message": format!("failed to serialize tool result: {error}"),
            })),
        }
    }

    /// Serializes `value` and marks the result `isError=true` or `false`
    /// exactly as `is_error` says. Every tool whose outcome enum can
    /// represent a real business/execution failure (`SearchOutcome`,
    /// `SemanticOutcome`, `ParseFileOutput`, the `ChangeSession` lifecycle
    /// tools' outcomes, ...) computes `is_error` itself, from its own real
    /// outcome value -- never a generic tag-name heuristic that could
    /// misclassify a nested outcome.
    fn outcome_result<T: Serialize>(
        &self,
        tool: &'static str,
        value: &T,
        is_error: bool,
    ) -> CallToolResult {
        match serde_json::to_value(value) {
            Ok(json) if is_error => contract_gate::finalize(
                &self.contract_registry,
                tool,
                CallToolResult::structured_error(json),
            ),
            Ok(json) => contract_gate::finalize(
                &self.contract_registry,
                tool,
                CallToolResult::structured(json),
            ),
            Err(error) => CallToolResult::structured_error(serde_json::json!({
                "status": "error",
                "error_code": "INTERNAL",
                "message": format!("failed to serialize tool result: {error}"),
            })),
        }
    }

    /// Parse MCP structured_content canonicalization: `parse_file`'s ONE
    /// success-path result builder.
    ///
    /// `structured_content` carries the compact, typed
    /// [`ParseFileOutput::Ok`] contract projected directly from `summary`
    /// (`language`/`syntax_ok`) and `facts` (`symbols`, capped and flagged
    /// via [`PARSE_COMPACT_SYMBOLS_MAX`]/`truncated`) -- this IS the
    /// canonical AI-facing Parse MCP contract; there is no second,
    /// differently-shaped success representation anywhere else
    /// (`PARSE_PUBLIC_OUTPUT_VARIANT_COUNT=1`).
    ///
    /// `content` is a single, minimal, deterministic summary line derived
    /// only from facts already present in `structured_content` (language,
    /// syntax_ok, symbol count, truncation) -- never a second traversal,
    /// never a full JSON duplicate (`FULL_STRUCTURED_JSON_DUPLICATED_IN_
    /// CONTENT=NO`), and never a fact `structured_content` itself lacks
    /// (`ALL_MODEL_RELEVANT_PARSE_FACTS ⊆ STRUCTURED_CONTENT`).
    fn parse_success_result(
        &self,
        summary: &ParseSummary,
        facts: Vec<CompactSymbol>,
    ) -> CallToolResult {
        const TOOL: &str = "parse_file";
        // Section 14: derive/check deterministic facts from the same
        // canonical (summary, facts) pair before constructing the result at
        // all -- a dual-channel inconsistency here means neither
        // representation is sent. Checked against the FULL, uncapped facts
        // list; truncation (below) is a legitimate, separately-flagged MCP
        // contract transform, not a consistency violation.
        if let Err(error) = contract_gate::validate_parse_dual_channel(summary, &facts) {
            return contract_gate::fail_closed_result(&error);
        }

        let truncated = facts.len() > PARSE_COMPACT_SYMBOLS_MAX;
        let mut symbols = facts;
        if truncated {
            symbols.truncate(PARSE_COMPACT_SYMBOLS_MAX);
        }
        let symbol_count = symbols.len();
        let syntax_ok = !summary.has_syntax_error;

        let value = ParseFileOutput::Ok {
            language: summary.language,
            syntax_ok,
            symbols,
            truncated,
        };
        let Ok(json) = serde_json::to_value(&value) else {
            return self.outcome_result(
                TOOL,
                &ParseFileOutput::Error {
                    error_code: "INTERNAL".to_string(),
                    message: "failed to serialize tool result".to_string(),
                },
                true,
            );
        };
        // `CallToolResult` is `#[non_exhaustive]`, so it must be built
        // through one of its own constructors rather than a struct
        // literal. `structured()` already sets `structured_content` and
        // `is_error` exactly as this function needs; `content` is always
        // overridden here with the minimal deterministic summary described
        // above, replacing `structured()`'s default whole-JSON-string
        // mirror.
        let mut result = CallToolResult::structured(json);
        result.content = vec![ContentBlock::text(format!(
            "parse_file: language={language} syntax_ok={syntax_ok} symbols={symbol_count}{trunc}",
            language = summary.language,
            trunc = if truncated { " (truncated)" } else { "" },
        ))];
        contract_gate::finalize(&self.contract_registry, TOOL, result)
    }
}

#[tool_router]
impl CorulixMcpServer {
    // ---------------------------------------------------------------
    // 1. runtime_identity
    // ---------------------------------------------------------------
    #[tool(
        description = "Return Corulix runtime identity and pinned engine/SDK versions",
        annotations(
            title = "Runtime Identity",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<wht_corulix_core::RuntimeIdentity>()"
    )]
    fn runtime_identity(&self) -> CallToolResult {
        self.plain_result("runtime_identity", &self.engine.runtime_identity())
    }

    // ---------------------------------------------------------------
    // 2. workspace_info
    // ---------------------------------------------------------------
    #[tool(
        description = "Return the active read-only workspace identity",
        annotations(
            title = "Workspace Info",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<WorkspaceInfoView>()"
    )]
    fn workspace_info(&self) -> CallToolResult {
        let view = WorkspaceInfoView {
            workspace: self.engine.workspace_info(),
            canonical_tool_count: wht_corulix_core::EffectiveToolSet::canonical_tool_count(),
            effective_visible_tool_count: self.tool_policy.effective_visible_tool_count(),
            tool_policy_configured: self.tool_policy_configured,
        };
        self.plain_result("workspace_info", &view)
    }

    // ---------------------------------------------------------------
    // 3. toolchain_status
    // ---------------------------------------------------------------
    #[tool(
        description = "Return real toolchain/provider-category availability status",
        annotations(
            title = "Toolchain Status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<wht_corulix_engine::toolchain_status::ToolchainStatus>()"
    )]
    fn toolchain_status(&self) -> CallToolResult {
        self.plain_result("toolchain_status", &self.engine.toolchain_status())
    }

    // ---------------------------------------------------------------
    // 4. plan_operation
    // ---------------------------------------------------------------
    #[tool(
        description = "Derive the deterministic ToolPlan for an operation intent. Plans \
Corulix's own fixed operation intents only; has no concept of, and no opinion about, which \
client-side tool a caller should use.",
        annotations(
            title = "Plan Operation",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<PlanOperationOutput>()"
    )]
    fn plan_operation(
        &self,
        Parameters(params): Parameters<PlanOperationParams>,
    ) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "plan_operation", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let plan = self
            .engine
            .plan_operation_for_language(params.intent, params.language);
        self.plain_result("plan_operation", &PlanOperationOutput { plan })
    }

    // ---------------------------------------------------------------
    // 5. search
    // ---------------------------------------------------------------
    #[tool(
        description = "Run a real, bounded, in-process text search across the workspace. \
Matches are bounded and text-level; does not resolve structural or semantic identity.",
        annotations(
            title = "Search",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<wht_corulix_engine::search::SearchOutcome>()"
    )]
    async fn search(&self, Parameters(params): Parameters<SearchParams>) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "search", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let outcome = self
            .engine
            .search(SearchRequest {
                pattern: params.pattern,
                is_regex: params.is_regex,
                case_insensitive: params.case_insensitive,
                root_selector: params.root_selector,
            })
            .await;
        let is_error = !matches!(outcome, SearchOutcome::Executed { .. });
        self.outcome_result("search", &outcome, is_error)
    }

    // ---------------------------------------------------------------
    // 6. parse_file
    // ---------------------------------------------------------------
    #[tool(
        description = "Parse source into symbols + compact outline (syntax only). \
Declaration-level symbols only (kind, name, line, container/modifiers/signature where \
applicable); no source text, imports, module-level constants, or resolved \
inheritance/aliases.",
        annotations(
            title = "Parse File",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<ParseFileOutput>()"
    )]
    async fn parse_file(&self, Parameters(params): Parameters<ParseFileParams>) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "parse_file", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        if params.path.is_empty() || params.path.len() > 4096 {
            return self.outcome_result(
                "parse_file",
                &ParseFileOutput::Error {
                    error_code: "INVALID_INPUT".to_string(),
                    message: "path must be non-empty and at most 4096 bytes".to_string(),
                },
                true,
            );
        }
        match self
            .engine
            .parse_relative_file(std::path::PathBuf::from(params.path), params.root_selector)
            .await
        {
            Ok((summary, facts)) => self.parse_success_result(&summary, facts),
            Err(error) => self.outcome_result(
                "parse_file",
                &ParseFileOutput::Error {
                    error_code: wht_corulix_engine::corulix_error_code(&error).to_string(),
                    message: error.to_string(),
                },
                true,
            ),
        }
    }

    // ---------------------------------------------------------------
    // 7. semantic
    // ---------------------------------------------------------------
    #[tool(
        description = "definition | references | diagnostics | rename_preview, gated on real \
LSP provider availability. Requires a live language-server provider per language; returns an \
explicit unavailable result otherwise, never a partial guess.",
        annotations(
            title = "Semantic",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<wht_corulix_engine::semantic::SemanticOutcome>()"
    )]
    async fn semantic(&self, Parameters(params): Parameters<SemanticParams>) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "semantic", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let target = wht_corulix_engine::semantic::SemanticTarget {
            relative_path: params.path,
            position: wht_corulix_core::Position {
                line_zero_based: params.line_zero_based,
                byte_column_zero_based: params.byte_column_zero_based,
                byte_offset: params.byte_offset,
            },
            new_name: params.new_name,
        };
        let outcome = self
            .engine
            .semantic(params.operation, params.language, target)
            .await;
        let is_error = matches!(
            outcome,
            wht_corulix_engine::semantic::SemanticOutcome::Unavailable { .. }
                | wht_corulix_engine::semantic::SemanticOutcome::RequestFailed { .. }
        );
        self.outcome_result("semantic", &outcome, is_error)
    }

    // ---------------------------------------------------------------
    // 8. format_preview
    // ---------------------------------------------------------------
    #[tool(
        description = "Preview canonical formatting for one file; language is inferred from \
its path, not limited to Rust. Preview only, never applied; requires a live formatter provider \
for the file's language.",
        annotations(
            title = "Format Preview",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<wht_corulix_engine::format_preview::FormatPreviewOutcome>()"
    )]
    async fn format_preview(
        &self,
        Parameters(params): Parameters<FormatPreviewParams>,
    ) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "format_preview", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let outcome = self
            .engine
            .format_preview(std::path::PathBuf::from(params.path), params.root_selector)
            .await;
        let is_error = !matches!(
            outcome,
            wht_corulix_engine::format_preview::FormatPreviewOutcome::WouldFormat { .. }
                | wht_corulix_engine::format_preview::FormatPreviewOutcome::Unchanged { .. }
        );
        self.outcome_result("format_preview", &outcome, is_error)
    }

    // ---------------------------------------------------------------
    // 9. begin_change
    // ---------------------------------------------------------------
    #[tool(
        description = "Open a governed ChangeSession for `intent`, scoped to `scope_prefixes`",
        annotations(
            title = "Begin Change",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<BeginChangeOutput>()"
    )]
    async fn begin_change(
        &self,
        Parameters(params): Parameters<BeginChangeParams>,
    ) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "begin_change", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let mut sessions = self.sessions.lock().await;
        let creation_sequence = sessions.len() as u64;
        match self
            .engine
            .begin_change(
                params.intent,
                // P15: the caller's declared language, when it named one.
                // See `BeginChangeParams::language` for why this is a field
                // on an existing tool rather than a new tool, and why it
                // grants no authority of its own.
                params.language,
                params.root_selector.as_deref(),
                params.scope_prefixes,
                self.workspace_identity.clone(),
                self.connection_id.clone(),
                creation_sequence,
            )
            .await
        {
            Ok(session) => {
                let session_id = session.id().as_opaque_token().to_string();
                let status = session.change_status();
                sessions.insert(session.id().clone(), session);
                self.outcome_result(
                    "begin_change",
                    &BeginChangeOutput::Opened { session_id, status },
                    false,
                )
            }
            Err(error) => self.outcome_result(
                "begin_change",
                &BeginChangeOutput::Denied {
                    // F4 fix: `OperationNotSupported` is a structural
                    // product-support boundary, not a missing/unavailable
                    // provider -- it gets its own precise `ReasonCode`
                    // instead of collapsing into the generic
                    // `RequiredCapabilityUnavailable` every other
                    // `begin_change` failure still uses.
                    reason_code: if matches!(
                        error,
                        wht_corulix_core::CorulixError::OperationNotSupported(_)
                    ) {
                        ReasonCode::OperationNotSupported
                    } else {
                        ReasonCode::RequiredCapabilityUnavailable
                    },
                    message: error.to_string(),
                },
                true,
            ),
        }
    }

    // ---------------------------------------------------------------
    // 10. submit_edit
    // ---------------------------------------------------------------
    #[tool(
        description = "Submit one governed file edit to an open ChangeSession. Replace/Delete require expected_precondition_hash_hex: the exact lowercase-hex SHA-256 digest of the target's current bytes; a mismatch (stale or malformed) rejects the edit before any write.",
        annotations(
            title = "Submit Edit",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<SubmitEditOutput>()"
    )]
    async fn submit_edit(
        &self,
        Parameters(params): Parameters<SubmitEditParams>,
    ) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "submit_edit", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let Ok(session_id) =
            wht_corulix_core::ChangeSessionId::from_opaque_token(params.session_id.clone())
        else {
            return self.outcome_result("submit_edit", &SubmitEditOutput::SessionNotFound, true);
        };
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(&session_id) else {
            return self.outcome_result("submit_edit", &SubmitEditOutput::SessionNotFound, true);
        };
        let kind = match params.edit {
            EditRequestParams::Create { content_utf8 } => EditRequestKind::Create {
                content: content_utf8.into_bytes(),
            },
            EditRequestParams::Replace {
                expected_precondition_hash_hex,
                content_utf8,
            } => EditRequestKind::Replace {
                expected_precondition_hash_hex,
                content: content_utf8.into_bytes(),
            },
            EditRequestParams::Delete {
                expected_precondition_hash_hex,
            } => EditRequestKind::Delete {
                expected_precondition_hash_hex,
            },
        };
        let batch = single_file_batch(params.relative_path, kind);
        match session
            .submit_edit(
                &self.workspace_identity,
                &self.connection_id,
                batch,
                EvidenceTimestamp(session.evidence_history().len() as u64),
            )
            .await
        {
            Ok(result) => self.outcome_result(
                "submit_edit",
                &SubmitEditOutput::Committed {
                    mutations_applied: result.results.len(),
                },
                false,
            ),
            Err(error) => self.outcome_result(
                "submit_edit",
                &SubmitEditOutput::Denied {
                    reason_code: session_error_reason(&error),
                },
                true,
            ),
        }
    }

    // ---------------------------------------------------------------
    // 11. validate_change
    // ---------------------------------------------------------------
    #[tool(
        description = "Run the applicable validation gate for an open ChangeSession's workspace using the configured language/toolchain providers and record gate Evidence",
        annotations(
            title = "Validate Change",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<ValidateChangeOutputEnvelope>()"
    )]
    async fn validate_change(
        &self,
        Parameters(params): Parameters<ValidateChangeParams>,
    ) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "validate_change", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let Ok(session_id) =
            wht_corulix_core::ChangeSessionId::from_opaque_token(params.session_id.clone())
        else {
            return self.outcome_result(
                "validate_change",
                &ValidateChangeOutputEnvelope::SessionNotFound,
                true,
            );
        };
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(&session_id) else {
            return self.outcome_result(
                "validate_change",
                &ValidateChangeOutputEnvelope::SessionNotFound,
                true,
            );
        };
        let sequence = session.evidence_history().len() as u64 + 1;
        let cancellation = wht_corulix_core::CancellationToken::new();
        let outcome = self
            .engine
            .validate_change(
                session,
                &self.workspace_identity,
                &self.connection_id,
                sequence,
                &cancellation,
            )
            .await;
        let is_error = outcome.is_error();
        self.outcome_result(
            "validate_change",
            &ValidateChangeOutputEnvelope::Ran { outcome },
            is_error,
        )
    }

    // ---------------------------------------------------------------
    // 12. change_status
    // ---------------------------------------------------------------
    #[tool(
        description = "Return an audit-safe structured snapshot of a ChangeSession's current state",
        annotations(
            title = "Change Status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<ChangeStatusOutput>()"
    )]
    async fn change_status(
        &self,
        Parameters(params): Parameters<ChangeStatusParams>,
    ) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "change_status", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let Ok(session_id) =
            wht_corulix_core::ChangeSessionId::from_opaque_token(params.session_id.clone())
        else {
            return self.outcome_result(
                "change_status",
                &ChangeStatusOutput::SessionNotFound,
                true,
            );
        };
        let sessions = self.sessions.lock().await;
        match sessions.get(&session_id) {
            Some(session) => self.outcome_result(
                "change_status",
                &ChangeStatusOutput::Found {
                    status: session.change_status(),
                },
                false,
            ),
            None => {
                self.outcome_result("change_status", &ChangeStatusOutput::SessionNotFound, true)
            }
        }
    }

    // ---------------------------------------------------------------
    // 13. complete_change
    // ---------------------------------------------------------------
    #[tool(
        description = "Complete a ChangeSession -- only if every Required gate has Current Passed Evidence",
        annotations(
            title = "Complete Change",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<CompleteChangeOutput>()"
    )]
    async fn complete_change(
        &self,
        Parameters(params): Parameters<CompleteChangeParams>,
    ) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "complete_change", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let Ok(session_id) =
            wht_corulix_core::ChangeSessionId::from_opaque_token(params.session_id.clone())
        else {
            return self.outcome_result(
                "complete_change",
                &CompleteChangeOutput::SessionNotFound,
                true,
            );
        };
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(&session_id) else {
            return self.outcome_result(
                "complete_change",
                &CompleteChangeOutput::SessionNotFound,
                true,
            );
        };
        match session.complete_change(&self.workspace_identity, &self.connection_id) {
            Ok(()) => {
                self.outcome_result("complete_change", &CompleteChangeOutput::Completed, false)
            }
            Err(error) => self.outcome_result(
                "complete_change",
                &CompleteChangeOutput::Denied {
                    reason_code: session_error_reason(&error),
                },
                true,
            ),
        }
    }

    // ---------------------------------------------------------------
    // 14. abort_change
    // ---------------------------------------------------------------
    #[tool(
        description = "Abort a ChangeSession permanently -- terminal, never auto-restores source bytes",
        annotations(
            title = "Abort Change",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        ),
        output_schema = "schema_for_output::<AbortChangeOutput>()"
    )]
    async fn abort_change(
        &self,
        Parameters(params): Parameters<AbortChangeParams>,
    ) -> CallToolResult {
        if let Err(error) =
            contract_gate::validate_input(&self.contract_registry, "abort_change", &params)
        {
            return contract_gate::fail_closed_result(&error);
        }
        let Ok(session_id) =
            wht_corulix_core::ChangeSessionId::from_opaque_token(params.session_id.clone())
        else {
            return self.outcome_result("abort_change", &AbortChangeOutput::SessionNotFound, true);
        };
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(&session_id) else {
            return self.outcome_result("abort_change", &AbortChangeOutput::SessionNotFound, true);
        };
        match session.abort(&self.workspace_identity, &self.connection_id) {
            Ok(()) => self.outcome_result("abort_change", &AbortChangeOutput::Aborted, false),
            Err(error) => self.outcome_result(
                "abort_change",
                &AbortChangeOutput::Denied {
                    reason_code: session_error_reason(&error),
                },
                true,
            ),
        }
    }
}

/// Maps a real [`wht_corulix_engine::session::SessionError`] to the
/// [`ReasonCode`] a client should see. F2 fix: before this pass, `Mutation`/
/// `Formatter` both collapsed into the generic `RequiredCapabilityUnavailable`
/// fallback -- the same code used for a genuinely missing external
/// provider. The precise, per-variant mapping now lives on
/// [`wht_corulix_engine::session::SessionError::reason_code`] itself (this
/// crate must never reference `wht_corulix_mutation`/`wht_corulix_formatter`
/// directly, Architecture Rule B/S), so this is a thin, single-call-site
/// delegation, not a second mapping authority.
fn session_error_reason(error: &wht_corulix_engine::session::SessionError) -> ReasonCode {
    error.reason_code()
}

impl ServerHandler for CorulixMcpServer {
    /// Phase 13: explicitly negotiates protocol version `2026-07-28` rather
    /// than relying on `ProtocolVersion::default()`/`LATEST` (which is
    /// `2025-11-25` in the admitted `rmcp` 3.0.1). Declares only the
    /// `tools` capability -- no `resources`, no `prompts`, no `logging`
    /// (left `None`), and no `experimental` extensions.
    ///
    /// Corulix 1.1.0 (ADR 0012, Phase D/J): the instructions text below
    /// deliberately never asserts an exact tool count or names
    /// `workspace_info` -- both `runtime_identity` and `workspace_info` are
    /// individually downscopeable (Section 6.D of the plan; no
    /// product-mandatory tool), so a caller must never be pointed at a
    /// tool that could itself be hidden. Verified against
    /// `capability_notes.rs`'s own banned-coaching-phrase list -- none of
    /// "use ", "then ", "call ", "prefer ", "fall back", "afterward" appear;
    /// "reachable only through" is the same factual-boundary language
    /// already present and already approved in the prior 1.0.0 string.
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
            .with_instructions(
                "WhaTalker Corulix: up to 14 canonical governed tools over a \
                 read-only-by-default workspace. One workspace per process. Mutating \
                 operations are reachable only through the governed ChangeSession lifecycle \
                 when the corresponding lifecycle tools are present; there is no direct-write \
                 tool. The effective tool surface may be reduced by workspace policy and \
                 never exceeds the canonical set.",
            )
    }

    /// Corulix 1.1.0 (ADR 0012): the **sole** production insertion point
    /// for tool-exposure policy at the dispatch boundary. Hand-written
    /// (not `#[tool_handler]`-generated) so it can call
    /// [`CorulixMcpServer::effective_tool_router`] instead of the bare
    /// `Self::tool_router()` the macro's own default expansion would use --
    /// otherwise identical, byte-for-byte, to that generated code (compare
    /// `rmcp-macros`' `tool_handler::tool_handler`'s own `call_tool`
    /// template).
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.effective_tool_router().call(tcc).await
    }

    /// As [`Self::call_tool`]: hand-written so discovery reflects
    /// [`CorulixMcpServer::effective_tool_router`] rather than the bare
    /// compile-time-declared router -- a policy-disabled tool must be
    /// **invisible** here, not merely rejected on call. Otherwise
    /// byte-for-byte identical to `rmcp-macros`' own `list_tools`
    /// template.
    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        let supports_cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        Ok(rmcp::model::ListToolsResult {
            result_type: Some(rmcp::model::ResultType::COMPLETE),
            tools: self.effective_tool_router().list_all(),
            meta: None,
            next_cursor: None,
            ttl_ms: supports_cache_hints.then_some(0),
            cache_scope: supports_cache_hints.then_some(rmcp::model::CacheScope::Public),
        })
    }

    /// As [`Self::call_tool`]/[`Self::list_tools`]: hand-written so a
    /// policy-disabled tool's definition is never returned through this
    /// path either (`ToolRouter::get` already returns `None` for a
    /// disabled name -- this override only routes it through
    /// [`CorulixMcpServer::effective_tool_router`] instead of the bare
    /// static router).
    fn get_tool(&self, name: &str) -> Option<rmcp::model::Tool> {
        self.effective_tool_router().get(name).cloned()
    }
}

/// Runs the MCP server over stdio until the client disconnects.
///
/// From the moment this future starts polling, stdout is reserved entirely
/// for the MCP JSON-RPC stream -- any stray `println!`/log write to stdout
/// elsewhere in the process would corrupt the protocol framing, which is why
/// the CLI routes its own diagnostic output to stderr instead.
/// Corulix 1.1.0 (ADR 0012): takes an already-constructed [`CorulixMcpServer`]
/// -- including whatever [`CorulixMcpServer::with_tool_policy`] attached --
/// rather than building a bare, default-policy server internally. This is
/// what makes `corulix mcp stdio` and `corulix config validate`/`inspect`
/// provably apply the exact same effective policy: the caller (`wht_corulix_cli::main::run_mcp_stdio`)
/// resolves the workspace's own `WhaTalker_Corulix_JSON_Config.json` via the
/// same [`wht_corulix_config::load_workspace_config`] both surfaces share,
/// then constructs the server from that result before ever reaching here.
pub async fn serve_stdio(server: CorulixMcpServer) -> Result<(), Box<dyn std::error::Error>> {
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::OperationIntent;
    use wht_corulix_workspace::WorkspaceContext;

    // -------------------------------------------------------------
    // Dev-only microbench support (Search + Parse AI Efficiency
    // Optimization pass). Measures the real, live MCP `tools/list`
    // schema byte cost for `search`/`parse_file` -- exactly what a real
    // MCP client receives -- so `TOOL_SCHEMA_TOTAL_BYTES` is never
    // guessed. Not part of release behavior. `#[ignore]`d; run via
    // `cargo test -p wht_corulix_mcp -- --ignored --nocapture`.
    // -------------------------------------------------------------
    #[test]
    #[ignore]
    fn dev_microbench_tool_schema_bytes() -> wht_corulix_core::CorulixResult<()> {
        use wht_corulix_core::CorulixError;

        let router = CorulixMcpServer::tool_router();
        let tools = router.list_all();

        let mut out = serde_json::Map::new();
        for tool_name in ["search", "parse_file"] {
            let Some(tool) = tools.iter().find(|t| t.name.as_ref() == tool_name) else {
                return Err(CorulixError::Internal);
            };
            let input_bytes = serde_json::to_vec(&tool.input_schema)
                .map_err(|_| CorulixError::Internal)?
                .len();
            let output_bytes = match tool.output_schema.as_ref() {
                Some(schema) => serde_json::to_vec(schema)
                    .map_err(|_| CorulixError::Internal)?
                    .len(),
                None => 0,
            };
            out.insert(
                tool_name.to_string(),
                serde_json::json!({
                    "input_schema_bytes": input_bytes,
                    "output_schema_bytes": output_bytes,
                    "tool_schema_total_bytes": input_bytes + output_bytes,
                }),
            );
        }

        // Dev-only diagnostic output: write-failures here surface as a
        // missing/incomplete result file downstream, never as a panic --
        // matching this codebase's existing test idiom of discarding
        // fallible cleanup/fixture I/O results rather than
        // `.expect()`/`.unwrap()`/`panic!`, all denied lints. Scratch
        // output only, portable via the system temp dir -- never a
        // specific developer's machine path.
        let results_dir =
            std::env::temp_dir().join("corulix_optimization_lab/search_parse/results/raw");
        let _ = fs::create_dir_all(&results_dir);
        let results_dir = results_dir.display();
        let json = serde_json::to_string_pretty(&out).map_err(|_| CorulixError::Internal)?;
        let _ = fs::write(format!("{results_dir}/mcp_schema_bytes.json"), &json);
        eprintln!("{json}");

        // Also dump the two tools' raw schemas verbatim, so the marginal
        // per-field schema cost of each measurement-gated candidate
        // (S1/S5/the Structural bundle's fields/declaration_range) can be
        // computed directly from one already-generated schema (each field
        // is its own additive `properties`/`$defs` entry) instead of
        // requiring a separate intermediate build per candidate.
        for tool_name in ["search", "parse_file"] {
            let Some(tool) = tools.iter().find(|t| t.name.as_ref() == tool_name) else {
                return Err(CorulixError::Internal);
            };
            let input_json = serde_json::to_string_pretty(&tool.input_schema)
                .map_err(|_| CorulixError::Internal)?;
            let _ = fs::write(
                format!("{results_dir}/mcp_{tool_name}_input_schema_raw.json"),
                &input_json,
            );
            if let Some(schema) = tool.output_schema.as_ref() {
                let output_json =
                    serde_json::to_string_pretty(schema).map_err(|_| CorulixError::Internal)?;
                let _ = fs::write(
                    format!("{results_dir}/mcp_{tool_name}_output_schema_raw.json"),
                    &output_json,
                );
            }
        }
        Ok(())
    }

    /// Parse MCP structured_content canonicalization: measures the REAL,
    /// live `structured_content` + `content` bytes `parse_file` actually
    /// returns for all 20 real synthetic dev fixtures, through the real
    /// handler (never estimated/reconstructed offline). `#[ignore]`d,
    /// dev-only; run via
    /// `cargo test -p wht_corulix_mcp -- --ignored --nocapture dev_microbench_parse_compact_response_bytes`.
    #[tokio::test]
    #[ignore]
    async fn dev_microbench_parse_compact_response_bytes() -> wht_corulix_core::CorulixResult<()> {
        use wht_corulix_core::CorulixError;

        const FIXTURES: &[&str] = &[
            "rust/small.rs",
            "rust/large.rs",
            "rust/deep_nested.rs",
            "rust/duplicate_names.rs",
            "rust/malformed.rs",
            "typescript/small.ts",
            "typescript/large.ts",
            "typescript/deep_nested.ts",
            "typescript/duplicate_names.ts",
            "typescript/malformed.ts",
            "python/small.py",
            "python/large.py",
            "python/deep_nested.py",
            "python/duplicate_names.py",
            "python/malformed.py",
            "go/small.go",
            "go/large.go",
            "go/deep_nested.go",
            "go/duplicate_names.go",
            "go/malformed.go",
        ];

        // Dev-only fixture root: never a specific developer's machine path.
        // `CORULIX_BENCH_PARSE_V2_FIXTURES_DIR` must name a real directory
        // containing the fixture files listed above; this microbench
        // gracefully no-ops (rather than failing) when that environment
        // variable is unset, since it is `#[ignore]`d and never part of
        // release behavior.
        let Ok(fixtures_root) = std::env::var("CORULIX_BENCH_PARSE_V2_FIXTURES_DIR") else {
            eprintln!(
                "dev_microbench_parse_compact_response_bytes: skipped, set CORULIX_BENCH_PARSE_V2_FIXTURES_DIR to run"
            );
            return Ok(());
        };
        let fixtures_root = PathBuf::from(fixtures_root);
        let root = wht_corulix_workspace::WorkspaceRoot::open(&fixtures_root)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        let identity =
            WorkspaceIdentity::from_opaque_token("wsid-parse-compact-bytes".to_string())?;
        let server = CorulixMcpServer::new(engine, identity)?;

        let mut rows =
            vec!["fixture\tstructured_bytes\tcontent_bytes\tsymbol_count\ttruncated\n".to_string()];
        let results_dir =
            std::env::temp_dir().join("corulix_optimization_lab/parse_v2/results/raw");
        let _ = fs::create_dir_all(&results_dir);
        let results_dir = results_dir.display();

        for fixture in FIXTURES {
            let result = server
                .parse_file(Parameters(ParseFileParams {
                    path: (*fixture).to_string(),
                    root_selector: None,
                }))
                .await;
            let Some(structured) = &result.structured_content else {
                return Err(CorulixError::Internal);
            };
            let structured_json =
                serde_json::to_string(structured).map_err(|_| CorulixError::Internal)?;
            let content_bytes: usize = result
                .content
                .iter()
                .map(|block| match block {
                    rmcp::model::ContentBlock::Text(text) => text.text.len(),
                    _ => 0,
                })
                .sum();
            let symbol_count = structured["symbols"].as_array().map_or(0, Vec::len);
            let truncated = structured["truncated"].as_bool().unwrap_or(false);
            let fixture_id = fixture.replace('/', "_").replace(['.'], "_");
            let _ = fs::write(
                format!("{results_dir}/parse_compact_structured_{fixture_id}.json"),
                &structured_json,
            );
            rows.push(format!(
                "{fixture}\t{}\t{content_bytes}\t{symbol_count}\t{truncated}\n",
                structured_json.len(),
            ));
        }

        let report: String = rows.concat();
        eprintln!("{report}");
        let _ = fs::write(
            format!("{results_dir}/parse_compact_response_bytes_summary.tsv"),
            &report,
        );
        Ok(())
    }

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-mcp-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    fn server(label: &str) -> wht_corulix_core::CorulixResult<CorulixMcpServer> {
        let root_dir = temp_root(label);
        let _ = fs::create_dir_all(root_dir.join("docs"));
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        let identity = WorkspaceIdentity::from_opaque_token(format!("wsid-{label}"))?;
        CorulixMcpServer::new(engine, identity)
    }

    // Contract Gate corrective-pass Section 3 (second half): drives the
    // REAL integration seam (`CorulixMcpServer::new_with_registry`) with a
    // deliberately failed registry build -- proving the exact path
    // production startup takes when `contract_gate::ContractRegistry::
    // build()` errors: construction must return `Err` before any `Self`
    // field is populated. Because every one of the 14 `#[tool]` handlers
    // is a method requiring `&self`, and no `Self` value is ever produced
    // on this path, `HANDLER_EXECUTION_AFTER_INVALID_SCHEMA_COUNT=0` holds
    // structurally here, not merely by convention.
    #[test]
    fn server_construction_fails_closed_when_registry_build_fails() -> Result<(), String> {
        let root_dir = temp_root("contract-gate-fail-closed");
        let _ = fs::create_dir_all(&root_dir);
        let root =
            wht_corulix_workspace::WorkspaceRoot::open(&root_dir).map_err(|e| e.to_string())?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        let identity =
            WorkspaceIdentity::from_opaque_token("wsid-contract-gate-fail-closed".to_string())
                .map_err(|e| e.to_string())?;

        let injected_failure =
            contract_gate::ContractRegistry::build_with_injected_invalid_schema();
        let Err(_) = injected_failure else {
            return Err("expected the injected registry build to fail".to_string());
        };
        let result = CorulixMcpServer::new_with_registry(engine, identity, injected_failure);
        let Err(_) = result else {
            return Err(
                "expected CorulixMcpServer::new_with_registry to fail closed when the \
                 contract registry fails to build"
                    .to_string(),
            );
        };
        Ok(())
    }

    fn structured(result: &CallToolResult) -> &serde_json::Value {
        let Some(value) = result.structured_content.as_ref() else {
            unreachable!("every tool result in this suite carries structuredContent");
        };
        value
    }

    // -----------------------------------------------------------------
    // 1. tools/list: exactly 14 tools, each with inputSchema/outputSchema/
    //    annotations.
    // -----------------------------------------------------------------
    #[test]
    fn tools_list_exposes_exactly_14_tools_with_schema_and_annotations() {
        let router = CorulixMcpServer::tool_router();
        let tools = router.list_all();
        assert_eq!(tools.len(), 14, "expected exactly 14 canonical tools");

        let expected_names = [
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
        let mut seen: Vec<&str> = Vec::new();
        for tool in &tools {
            assert!(
                !tool.input_schema.is_empty(),
                "{}: empty inputSchema",
                tool.name
            );
            assert!(
                tool.output_schema.is_some(),
                "{}: missing outputSchema",
                tool.name
            );
            assert!(
                tool.annotations.is_some(),
                "{}: missing ToolAnnotations",
                tool.name
            );
            let Some(annotations) = tool.annotations.as_ref() else {
                unreachable!("checked by the assert! immediately above");
            };
            assert!(
                annotations.read_only_hint.is_some(),
                "{}: readOnlyHint not declared",
                tool.name
            );
            // Mutation/validation tools must never be mislabeled read-only.
            let is_mutating = matches!(
                tool.name.as_ref(),
                "begin_change" | "submit_edit" | "complete_change" | "abort_change"
            );
            if is_mutating {
                assert_eq!(
                    annotations.read_only_hint,
                    Some(false),
                    "{}: a mutating tool must declare readOnlyHint=false",
                    tool.name
                );
            }
            seen.push(tool.name.as_ref());
        }
        for name in expected_names {
            assert!(seen.contains(&name), "missing expected tool: {name}");
        }
    }

    // -----------------------------------------------------------------
    // Corulix 1.1.0 (ADR 0012, Phase D): tool exposure policy.
    // -----------------------------------------------------------------

    /// TOOL-016: binds the single shared `wht_corulix_core` authority to
    /// this crate's own compile-time-declared `#[tool(...)]` set -- the
    /// bridge that keeps Rule S's compile-time count and the shared,
    /// cross-crate-visible catalog from ever silently diverging.
    #[test]
    fn canonical_mcp_tool_names_match_the_declared_tool_router_exactly() {
        let router = CorulixMcpServer::tool_router();
        let declared: std::collections::BTreeSet<String> = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        let canonical: std::collections::BTreeSet<String> =
            wht_corulix_core::CANONICAL_MCP_TOOL_NAMES
                .iter()
                .map(|name| (*name).to_string())
                .collect();
        assert_eq!(
            declared, canonical,
            "wht_corulix_core::CANONICAL_MCP_TOOL_NAMES has drifted from the real #[tool(...)] set"
        );
    }

    fn server_with_policy(
        label: &str,
        disabled: &[&str],
        empty_catalog_supported: bool,
    ) -> Result<CorulixMcpServer, String> {
        let base = server(label).map_err(|error| error.to_string())?;
        let disabled_tools: Vec<String> = disabled.iter().map(|name| (*name).to_string()).collect();
        let policy =
            wht_corulix_core::validate_tool_policy(&disabled_tools, empty_catalog_supported);
        base.with_tool_policy(policy)
            .map_err(|error| error.to_string())
    }

    #[test]
    fn no_policy_preserves_all_14_tools_in_effective_router() -> Result<(), String> {
        let srv = server("no-policy-configured").map_err(|error| error.to_string())?;
        assert_eq!(srv.effective_tool_router().list_all().len(), 14);
        Ok(())
    }

    #[test]
    fn valid_reduced_policy_is_reflected_in_effective_router() -> Result<(), String> {
        let srv = server_with_policy("reduced-policy", &["semantic", "format_preview"], false)?;
        let router = srv.effective_tool_router();
        assert_eq!(router.list_all().len(), 12);
        assert!(router.is_disabled("semantic"));
        assert!(router.is_disabled("format_preview"));
        assert!(!router.is_disabled("search"));
        Ok(())
    }

    #[test]
    fn disabled_tool_is_absent_from_get_tool_but_others_remain() -> Result<(), String> {
        let srv = server_with_policy("get-tool-hidden", &["semantic"], false)?;
        assert!(srv.get_tool("semantic").is_none());
        assert!(srv.get_tool("search").is_some());
        Ok(())
    }

    #[test]
    fn unknown_tool_name_in_policy_fails_construction_closed() {
        let result = server_with_policy("unknown-tool-name", &["delete_repo"], false);
        assert!(
            result.is_err(),
            "an unrecognized tool name in disabledTools must refuse startup, never silently ignore"
        );
    }

    #[test]
    fn begin_change_disabled_alone_fails_construction_closed() {
        let result = server_with_policy("mutation-family-incomplete", &["begin_change"], false);
        assert!(
            result.is_err(),
            "begin_change disabled while downstream mutation tools remain enabled must refuse startup"
        );
    }

    #[test]
    fn all_six_mutation_tools_disabled_together_is_the_valid_read_only_mode() -> Result<(), String>
    {
        let srv = server_with_policy(
            "read-only-mode",
            &[
                "begin_change",
                "submit_edit",
                "validate_change",
                "change_status",
                "complete_change",
                "abort_change",
            ],
            false,
        )?;
        assert_eq!(srv.effective_tool_router().list_all().len(), 8);
        Ok(())
    }

    #[test]
    fn all_14_disabled_fails_when_empty_catalog_unsupported() {
        let all: Vec<&str> = wht_corulix_core::CANONICAL_MCP_TOOL_NAMES.to_vec();
        let result = server_with_policy("empty-catalog-unsupported", &all, false);
        assert!(result.is_err());
    }

    #[test]
    fn all_14_disabled_succeeds_when_empty_catalog_supported() -> Result<(), String> {
        let all: Vec<&str> = wht_corulix_core::CANONICAL_MCP_TOOL_NAMES.to_vec();
        let srv = server_with_policy("empty-catalog-supported", &all, true)?;
        assert_eq!(srv.effective_tool_router().list_all().len(), 0);
        Ok(())
    }

    #[test]
    fn two_independently_configured_servers_never_leak_policy() -> Result<(), String> {
        let reduced = server_with_policy("no-leak-reduced", &["semantic"], false)?;
        let full = server("no-leak-full").map_err(|error| error.to_string())?;
        assert_eq!(reduced.effective_tool_router().list_all().len(), 13);
        assert_eq!(full.effective_tool_router().list_all().len(), 14);
        Ok(())
    }

    #[test]
    fn bare_tool_router_stays_policy_blind_at_14_regardless_of_any_instance_policy()
    -> Result<(), String> {
        // Confirms the dual-layer separation this design relies on: the
        // canonical, compile-time-declared router (Rule S's own domain) is
        // never affected by any instance's configured policy.
        let _srv = server_with_policy("policy-blind-canonical-check", &["semantic"], false)?;
        assert_eq!(CorulixMcpServer::tool_router().list_all().len(), 14);
        Ok(())
    }

    // -----------------------------------------------------------------
    // 1a-i. Capability-Aware Tool Routing plan (Option B): per-tool and
    //       aggregate static description-byte gates, always-run (not
    //       `#[ignore]`d), measuring the REAL live `tools/list` UTF-8
    //       description bytes -- never estimated. Baseline (pre-change,
    //       all 14 literals as they existed before this pass) is frozen
    //       in this pass's own internal evidence archive
    //       (routing_baseline_2026-09-06/BYTE_BASELINE.md, outside the
    //       public source tree)
    //       (TOTAL_14_TOOL_DESCRIPTION_BYTES_BEFORE=1011,
    //       MAX_SINGLE_TOOL_DESCRIPTION_BYTES_BEFORE=111). The ceilings
    //       below are real numbers chosen to accommodate exactly the 5
    //       approved capability notes (measured total after: 1630 bytes)
    //       with a small, non-unbounded margin -- not guessed.
    // -----------------------------------------------------------------
    #[test]
    fn per_tool_description_byte_ceiling() {
        const PER_TOOL_DESCRIPTION_MAX_BYTES: usize = 320;
        let router = CorulixMcpServer::tool_router();
        let tools = router.list_all();
        assert_eq!(tools.len(), 14);
        for tool in &tools {
            let bytes = tool.description.as_deref().unwrap_or("").len();
            assert!(
                bytes <= PER_TOOL_DESCRIPTION_MAX_BYTES,
                "{}: description is {bytes} bytes, exceeds the {PER_TOOL_DESCRIPTION_MAX_BYTES}-byte per-tool ceiling",
                tool.name
            );
        }
    }

    #[test]
    fn aggregate_description_byte_ceiling() {
        // Real baseline after the 5 capability notes (Option B pass) =
        // 1630 bytes. P-M08-R1 (owner-authorized) added real precondition/
        // staleness/SHA-256-format documentation to `submit_edit`'s own
        // description -- real total after = 1863 bytes (measured).
        // Ceiling set to 1950: accommodates exactly this approved addition
        // with a small, real, non-unbounded margin -- not free-for-all
        // growth.
        const AGGREGATE_DESCRIPTION_BYTE_CEILING: usize = 1950;
        let router = CorulixMcpServer::tool_router();
        let tools = router.list_all();
        assert_eq!(tools.len(), 14);
        let total: usize = tools
            .iter()
            .map(|tool| tool.description.as_deref().unwrap_or("").len())
            .sum();
        assert!(
            total <= AGGREGATE_DESCRIPTION_BYTE_CEILING,
            "aggregate description bytes across all 14 tools is {total}, exceeds the {AGGREGATE_DESCRIPTION_BYTE_CEILING}-byte aggregate ceiling"
        );
    }

    /// Proves the live `#[tool(description = "...")]` literals in this
    /// file are byte-for-byte identical to `capability_notes`'s reviewed
    /// source-of-truth constants -- the macro cannot reference the
    /// constants directly (`rmcp-macros`' description attribute rejects a
    /// bare path expression), so this test is what actually prevents the
    /// two copies from silently drifting apart.
    #[test]
    fn descriptions_match_capability_notes_source_of_truth() {
        let router = CorulixMcpServer::tool_router();
        let tools = router.list_all();
        let expected: &[(&str, &str)] = &[
            ("search", capability_notes::SEARCH_DESCRIPTION),
            ("parse_file", capability_notes::PARSE_FILE_DESCRIPTION),
            ("semantic", capability_notes::SEMANTIC_DESCRIPTION),
            (
                "plan_operation",
                capability_notes::PLAN_OPERATION_DESCRIPTION,
            ),
            (
                "format_preview",
                capability_notes::FORMAT_PREVIEW_DESCRIPTION,
            ),
        ];
        for (name, expected_description) in expected {
            let Some(tool) = tools.iter().find(|t| t.name.as_ref() == *name) else {
                unreachable!("tool '{name}' must be present -- checked by test 1 above");
            };
            assert_eq!(
                tool.description.as_deref(),
                Some(*expected_description),
                "{name}: live description does not match capability_notes::* source of truth"
            );
        }
    }

    // -----------------------------------------------------------------
    // 1b. Every tool's four ToolAnnotations hints, asserted by exact value
    //     against real observed behavior -- not merely "is_some()". This
    //     is what caught `abort_change` originally declaring
    //     `idempotent_hint = true` while `ChangeSession::abort` rejects a
    //     second call on an already-terminal session with a *different*
    //     result (`isError=true`) than the first call's success -- a
    //     hint/behavior mismatch the presence-only checks above cannot
    //     detect. `abort_change` now correctly declares
    //     `idempotent_hint = false`.
    // -----------------------------------------------------------------
    #[test]
    fn every_tool_declares_the_expected_annotation_hints_by_value() {
        // (name, read_only, destructive, idempotent, open_world)
        let expected: &[(&str, bool, bool, bool, bool)] = &[
            ("runtime_identity", true, false, true, false),
            ("workspace_info", true, false, true, false),
            ("toolchain_status", true, false, true, false),
            ("plan_operation", true, false, true, false),
            ("search", true, false, true, false),
            ("parse_file", true, false, true, false),
            ("semantic", true, false, true, false),
            ("format_preview", true, false, true, false),
            ("begin_change", false, false, false, false),
            ("submit_edit", false, true, false, false),
            ("validate_change", false, false, false, false),
            ("change_status", true, false, true, false),
            ("complete_change", false, false, false, false),
            ("abort_change", false, true, false, false),
        ];

        let router = CorulixMcpServer::tool_router();
        let tools = router.list_all();
        assert_eq!(tools.len(), expected.len());

        for (name, read_only, destructive, idempotent, open_world) in expected {
            let Some(tool) = tools.iter().find(|tool| tool.name.as_ref() == *name) else {
                unreachable!("tool '{name}' must be present -- checked by test 1 above");
            };
            let Some(annotations) = tool.annotations.as_ref() else {
                unreachable!("tool '{name}' must carry annotations -- checked by test 1 above");
            };
            assert_eq!(
                annotations.read_only_hint,
                Some(*read_only),
                "{name}: unexpected readOnlyHint"
            );
            assert_eq!(
                annotations.destructive_hint,
                Some(*destructive),
                "{name}: unexpected destructiveHint"
            );
            assert_eq!(
                annotations.idempotent_hint,
                Some(*idempotent),
                "{name}: unexpected idempotentHint"
            );
            assert_eq!(
                annotations.open_world_hint,
                Some(*open_world),
                "{name}: unexpected openWorldHint"
            );
        }
    }

    // -----------------------------------------------------------------
    // 2. Security: request DTOs structurally cannot carry a RiskClass/
    //    ToolPlan/gate/EnforcementLevel/WorkspaceTrust override -- an
    //    extra field is rejected, never silently ignored.
    // -----------------------------------------------------------------
    #[test]
    fn begin_change_request_rejects_a_foreign_risk_override_field() {
        let payload = serde_json::json!({
            "intent": "SOURCE_MODIFY",
            "root_selector": null,
            "scope_prefixes": ["src/"],
            "risk_class": "LOW",
        });
        let parsed: Result<BeginChangeParams, _> = serde_json::from_value(payload);
        assert!(
            parsed.is_err(),
            "an extra risk_class field must be rejected, never silently ignored"
        );
    }

    #[test]
    fn submit_edit_request_rejects_a_foreign_enforcement_level_field() {
        let payload = serde_json::json!({
            "session_id": "abc",
            "relative_path": "a.rs",
            "edit": {"kind": "create", "content_utf8": "x"},
            "enforcement_level": "BLOCKING",
        });
        let parsed: Result<SubmitEditParams, _> = serde_json::from_value(payload);
        assert!(parsed.is_err());
    }

    // -----------------------------------------------------------------
    // 3. Malformed-request tests.
    // -----------------------------------------------------------------
    #[test]
    fn plan_operation_rejects_an_unknown_intent_variant() {
        let payload = serde_json::json!({"intent": "NOT_A_REAL_INTENT", "language": null});
        assert!(serde_json::from_value::<PlanOperationParams>(payload).is_err());
    }

    #[test]
    fn plan_operation_rejects_a_missing_required_field() {
        let payload = serde_json::json!({});
        assert!(serde_json::from_value::<PlanOperationParams>(payload).is_err());
    }

    #[test]
    fn search_rejects_a_wrong_field_type() {
        let payload = serde_json::json!({"pattern": 12345});
        assert!(serde_json::from_value::<SearchParams>(payload).is_err());
    }

    #[test]
    fn semantic_rejects_an_unknown_operation_variant() {
        let payload = serde_json::json!({
            "operation": "delete_everything",
            "language": "rust",
            "path": "a.rs",
            "line_zero_based": 0,
            "byte_column_zero_based": 0,
            "byte_offset": 0,
        });
        assert!(serde_json::from_value::<SemanticParams>(payload).is_err());
    }

    #[tokio::test]
    async fn parse_file_rejects_an_oversized_path() -> wht_corulix_core::CorulixResult<()> {
        let server = server("oversized")?;
        let outcome = server
            .parse_file(Parameters(ParseFileParams {
                path: "a".repeat(5000),
                root_selector: None,
            }))
            .await;
        assert_eq!(outcome.is_error, Some(true));
        assert_eq!(structured(&outcome)["status"], serde_json::json!("error"));
        Ok(())
    }

    // -----------------------------------------------------------------
    // 4. Real invocation coverage of all 14 tools.
    // -----------------------------------------------------------------
    #[test]
    fn runtime_identity_returns_real_structured_content() -> wht_corulix_core::CorulixResult<()> {
        let server = server("runtime-identity")?;
        let result = server.runtime_identity();
        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            structured(&result)["binary"],
            serde_json::json!(wht_corulix_core::BINARY_NAME)
        );
        Ok(())
    }

    #[test]
    fn workspace_info_returns_real_structured_content() -> wht_corulix_core::CorulixResult<()> {
        let server = server("workspace-info")?;
        let result = server.workspace_info();
        assert_eq!(result.is_error, Some(false));
        let content = structured(&result);
        assert_eq!(content["read_only"], serde_json::json!(true));
        // Corulix 1.1.0 (ADR 0012, Phase G): count-only tool-policy
        // introspection fields, unconfigured default.
        assert_eq!(content["canonical_tool_count"], serde_json::json!(14));
        assert_eq!(
            content["effective_visible_tool_count"],
            serde_json::json!(14)
        );
        assert_eq!(content["tool_policy_configured"], serde_json::json!(false));
        Ok(())
    }

    #[test]
    fn workspace_info_reports_configured_reduced_policy() -> Result<(), String> {
        let srv = server_with_policy("workspace-info-reduced", &["semantic"], false)?;
        let result = srv.workspace_info();
        assert_eq!(result.is_error, Some(false));
        let content = structured(&result);
        assert_eq!(content["canonical_tool_count"], serde_json::json!(14));
        assert_eq!(
            content["effective_visible_tool_count"],
            serde_json::json!(13)
        );
        assert_eq!(content["tool_policy_configured"], serde_json::json!(true));
        Ok(())
    }

    /// Corulix 1.1.0 (ADR 0012, Phase J): `get_info()`'s instructions text
    /// was updated in Phase D to stay accurate under a reduced tool policy
    /// (no hardcoded "14" claim, no `workspace_info`-referencing coaching
    /// text). This test locks that in mechanically, mirroring
    /// `capability_notes.rs`'s own "prove it with a test, not just a
    /// comment" discipline, rather than leaving Phase J's requirement
    /// verified only by manual inspection.
    #[test]
    fn get_info_instructions_reflect_reduced_policy_without_coaching()
    -> wht_corulix_core::CorulixResult<()> {
        let srv = server("get-info-text")?;
        let info = srv.get_info();
        let instructions = info.instructions.unwrap_or_default();
        assert!(
            instructions.contains("reduced by workspace policy"),
            "get_info() instructions do not reflect the reduced-policy wording: {instructions:?}"
        );
        assert!(
            !instructions.contains("workspace_info"),
            "get_info() instructions must not reference workspace_info: {instructions:?}"
        );
        let lower = instructions.to_lowercase();
        for phrase in [
            "use ",
            "then ",
            "call ",
            "prefer ",
            "fall back",
            "fallback to",
        ] {
            assert!(
                !lower.contains(phrase),
                "get_info() instructions contain a coaching phrase ({phrase:?}): {instructions:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn toolchain_status_reports_real_provider_availability() -> wht_corulix_core::CorulixResult<()>
    {
        let server = server("toolchain-status")?;
        let result = server.toolchain_status();
        assert_eq!(result.is_error, Some(false));
        let Some(providers) = structured(&result)["providers"].as_array() else {
            unreachable!("toolchain_status always reports a providers array");
        };
        assert!(!providers.is_empty());
        Ok(())
    }

    #[test]
    fn plan_operation_returns_a_real_deterministic_plan() -> wht_corulix_core::CorulixResult<()> {
        let server = server("plan-operation")?;
        let result = server.plan_operation(Parameters(PlanOperationParams {
            intent: OperationIntent::TextSearch,
            language: None,
        }));
        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            structured(&result)["plan"]["executability"],
            serde_json::json!("Executable")
        );
        Ok(())
    }

    #[tokio::test]
    async fn search_executes_a_real_query() -> wht_corulix_core::CorulixResult<()> {
        let root_dir = temp_root("search-real");
        fs::write(root_dir.join("marker.rs"), "fn corulix_marker_mcp() {}")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        let identity = WorkspaceIdentity::from_opaque_token("wsid-search-real".to_string())?;
        let server = CorulixMcpServer::new(engine, identity)?;

        let result = server
            .search(Parameters(SearchParams {
                pattern: "corulix_marker_mcp".to_string(),
                is_regex: false,
                case_insensitive: false,
                root_selector: None,
            }))
            .await;
        assert_eq!(result.is_error, Some(false));
        assert_eq!(structured(&result)["status"], serde_json::json!("executed"));
        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// M09 P11 Section 18: a real, public `search` call must never surface
    /// impostor content after the workspace root's own pathname is replaced
    /// post-construction. `WorkspaceRoot::open` pins the root's identity via
    /// an `O_NOFOLLOW`-opened fd at construction time (`confine.rs`); every
    /// later confined walk/read resolves relative to that pinned fd, never
    /// a re-resolved pathname -- so a search issued after the swap must
    /// still see the ORIGINAL (now moved-away) content, never the impostor
    /// directory now occupying the root's old pathname.
    #[tokio::test]
    async fn public_search_root_swap_never_surfaces_impostor_content()
    -> wht_corulix_core::CorulixResult<()> {
        struct CleanupGuard(PathBuf);
        impl Drop for CleanupGuard {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        let root_dir = temp_root("search-root-swap");
        let _root_guard = CleanupGuard(root_dir.clone());
        fs::write(
            root_dir.join("marker.rs"),
            "CORULIX_ORIGINAL_MARKER_ROOTSWAP",
        )
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        let identity = WorkspaceIdentity::from_opaque_token("wsid-search-root-swap".to_string())?;
        let server = CorulixMcpServer::new(engine, identity)?;

        // Baseline: the original marker is genuinely found before any swap.
        let baseline = server
            .search(Parameters(SearchParams {
                pattern: "CORULIX_ORIGINAL_MARKER_ROOTSWAP".to_string(),
                is_regex: false,
                case_insensitive: false,
                root_selector: None,
            }))
            .await;
        assert_eq!(baseline.is_error, Some(false));
        let baseline_payload = structured(&baseline).clone();
        assert_eq!(baseline_payload["status"], serde_json::json!("executed"));
        assert!(
            !baseline_payload["matches"]
                .as_array()
                .unwrap_or(&vec![])
                .is_empty(),
            "expected the original marker to be found before any swap, got: {baseline_payload}"
        );

        // Ordinary-directory replacement at the workspace root's own
        // pathname: move the original aside intact, then occupy the same
        // pathname with a fresh directory carrying different content.
        let moved_away = std::env::temp_dir().join(format!(
            "corulix-mcp-test-search-root-swap-moved-{}",
            std::process::id()
        ));
        let _moved_guard = CleanupGuard(moved_away.clone());
        fs::rename(&root_dir, &moved_away).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::create_dir_all(&root_dir).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::write(
            root_dir.join("marker.rs"),
            "CORULIX_IMPOSTOR_MARKER_ROOTSWAP",
        )
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

        let after_swap = server
            .search(Parameters(SearchParams {
                pattern: "CORULIX_IMPOSTOR_MARKER_ROOTSWAP".to_string(),
                is_regex: false,
                case_insensitive: false,
                root_selector: None,
            }))
            .await;
        let after_swap_payload = structured(&after_swap).clone();
        if after_swap_payload["status"] == serde_json::json!("executed") {
            let matches = after_swap_payload["matches"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            for one_match in &matches {
                let snippet = one_match["snippet"].as_str().unwrap_or_default();
                assert!(
                    !snippet.contains("CORULIX_IMPOSTOR_MARKER_ROOTSWAP"),
                    "impostor content must never appear in search results after a root-path \
                     swap, got: {after_swap_payload}"
                );
            }
        }

        // The ORIGINAL content must still be the authorized object search
        // resolves against -- proves this is genuine fd-pinned continuity,
        // not merely an empty/fail-closed result.
        let still_original = server
            .search(Parameters(SearchParams {
                pattern: "CORULIX_ORIGINAL_MARKER_ROOTSWAP".to_string(),
                is_regex: false,
                case_insensitive: false,
                root_selector: None,
            }))
            .await;
        let still_original_payload = structured(&still_original).clone();
        assert_eq!(still_original.is_error, Some(false));
        assert_eq!(
            still_original_payload["status"],
            serde_json::json!("executed")
        );
        assert!(
            !still_original_payload["matches"]
                .as_array()
                .unwrap_or(&vec![])
                .is_empty(),
            "expected the ORIGINAL marker to still be found via the pinned root fd after the \
             swap, got: {still_original_payload}"
        );

        Ok(())
    }

    /// M09 P11 Section 19: ancestor pathname replacement (an interior
    /// directory, not the workspace root itself) must never leak content
    /// from outside the workspace boundary into search results. Unlike the
    /// root-swap test above, this exercises `wht_corulix_workspace`'s
    /// confined-walk symlink-outside denial (Rule F) rather than root-fd
    /// pinning: after the swap, `a` is a symlink pointing OUTSIDE the
    /// workspace, so a subsequent search must never surface the outside
    /// directory's content, regardless of whether the walk silently skips
    /// the denied component or the call reports an error.
    #[cfg(unix)]
    #[tokio::test]
    async fn public_search_ancestor_swap_never_surfaces_outside_content()
    -> wht_corulix_core::CorulixResult<()> {
        struct CleanupGuard(PathBuf);
        impl Drop for CleanupGuard {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        let root_dir = temp_root("search-ancestor-swap");
        let _root_guard = CleanupGuard(root_dir.clone());
        fs::create_dir_all(root_dir.join("a/b"))
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::write(
            root_dir.join("a/b/marker.rs"),
            "CORULIX_ORIGINAL_MARKER_ANCESTORSWAP",
        )
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

        let outside_dir = temp_root("search-ancestor-swap-outside");
        let _outside_guard = CleanupGuard(outside_dir.clone());
        fs::create_dir_all(outside_dir.join("b"))
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::write(
            outside_dir.join("b/impostor.rs"),
            "CORULIX_IMPOSTOR_MARKER_ANCESTORSWAP",
        )
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        let identity =
            WorkspaceIdentity::from_opaque_token("wsid-search-ancestor-swap".to_string())?;
        let server = CorulixMcpServer::new(engine, identity)?;

        // Baseline: the original nested marker is genuinely found before
        // any swap.
        let baseline = server
            .search(Parameters(SearchParams {
                pattern: "CORULIX_ORIGINAL_MARKER_ANCESTORSWAP".to_string(),
                is_regex: false,
                case_insensitive: false,
                root_selector: None,
            }))
            .await;
        assert_eq!(baseline.is_error, Some(false));
        let baseline_payload = structured(&baseline).clone();
        assert!(
            !baseline_payload["matches"]
                .as_array()
                .unwrap_or(&vec![])
                .is_empty(),
            "expected the original nested marker to be found before any swap, got: \
             {baseline_payload}"
        );

        // Ancestor swap: `a` (an interior directory strictly above the
        // marker, strictly below the workspace root) is replaced by a
        // symlink to a directory OUTSIDE the workspace.
        let a_path = root_dir.join("a");
        let a_moved_away = temp_root("search-ancestor-swap-moved");
        let _moved_guard = CleanupGuard(a_moved_away.clone());
        fs::rename(&a_path, &a_moved_away).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        std::os::unix::fs::symlink(&outside_dir, &a_path)
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

        let after_swap = server
            .search(Parameters(SearchParams {
                pattern: "CORULIX_IMPOSTOR_MARKER_ANCESTORSWAP".to_string(),
                is_regex: false,
                case_insensitive: false,
                root_selector: None,
            }))
            .await;
        let after_swap_payload = structured(&after_swap).clone();
        if after_swap_payload["status"] == serde_json::json!("executed") {
            let matches = after_swap_payload["matches"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            for one_match in &matches {
                let snippet = one_match["snippet"].as_str().unwrap_or_default();
                assert!(
                    !snippet.contains("CORULIX_IMPOSTOR_MARKER_ANCESTORSWAP"),
                    "outside content must never appear in search results after an ancestor \
                     symlink swap, got: {after_swap_payload}"
                );
            }
        }

        let _ = fs::remove_file(&a_path);
        Ok(())
    }

    #[tokio::test]
    async fn parse_file_parses_a_real_file() -> wht_corulix_core::CorulixResult<()> {
        let root_dir = temp_root("parse-real");
        fs::write(root_dir.join("main.rs"), "fn corulix_parse_target() {}")
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        let identity = WorkspaceIdentity::from_opaque_token("wsid-parse-real".to_string())?;
        let server = CorulixMcpServer::new(engine, identity)?;

        let result = server
            .parse_file(Parameters(ParseFileParams {
                path: "main.rs".to_string(),
                root_selector: None,
            }))
            .await;
        assert_eq!(result.is_error, Some(false));
        assert_eq!(structured(&result)["status"], serde_json::json!("ok"));
        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// Parse MCP structured_content canonicalization: proves the ONE
    /// canonical compact contract end-to-end through the real
    /// `parse_file` handler -- `structured_content` carries `language`/
    /// `syntax_ok`/`symbols`/`truncated` (never the old `summary`/
    /// `schema_version`/`byte_len`/`root_kind` shape), and `content` is a
    /// single minimal deterministic summary line, never a full JSON
    /// mirror.
    #[tokio::test]
    async fn parse_file_structured_content_is_the_compact_contract()
    -> wht_corulix_core::CorulixResult<()> {
        let root_dir = temp_root("parse-compact-contract");
        fs::write(
            root_dir.join("main.rs"),
            "pub async fn render(&self) -> Html {}",
        )
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        let identity =
            WorkspaceIdentity::from_opaque_token("wsid-parse-compact-contract".to_string())?;
        let server = CorulixMcpServer::new(engine, identity)?;

        let result = server
            .parse_file(Parameters(ParseFileParams {
                path: "main.rs".to_string(),
                root_selector: None,
            }))
            .await;
        assert_eq!(result.is_error, Some(false));
        let value = structured(&result);
        assert_eq!(value["status"], serde_json::json!("ok"));
        assert_eq!(value["language"], serde_json::json!("rust"));
        assert_eq!(value["syntax_ok"], serde_json::json!(true));
        assert_eq!(value["truncated"], serde_json::json!(false));
        // The OLD shape's field names must be entirely absent -- this is
        // not the same contract with extra fields, it is the ONE canonical
        // compact contract.
        assert!(value.get("summary").is_none());
        assert!(value.get("schema_version").is_none());
        assert!(value.get("byte_len").is_none());
        assert!(value.get("root_kind").is_none());
        let Some(symbols) = value["symbols"].as_array() else {
            unreachable!("compact contract always carries a symbols array");
        };
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0]["name"], serde_json::json!("render"));
        // A plain top-level `fn` (not inside an `impl` block) classifies as
        // `Function`, not `Method` -- Rust's grammar uses the same
        // `function_item` node kind either way; `container` (asserted
        // absent below) is what would distinguish an impl member.
        assert_eq!(symbols[0]["kind"], serde_json::json!("FUNCTION"));
        assert!(symbols[0].get("container").is_none());
        assert_eq!(symbols[0]["modifiers"], serde_json::json!(["pub", "async"]));
        assert_eq!(symbols[0]["line"], serde_json::json!(1));

        // `content` must be a single, small, deterministic text block --
        // never a duplicate of the full structured JSON.
        assert_eq!(result.content.len(), 1);
        let rmcp::model::ContentBlock::Text(text) = &result.content[0] else {
            unreachable!("parse_file content is always text");
        };
        assert!(text.text.starts_with("parse_file: language=rust"));
        assert!(
            text.text.len() < 200,
            "content must stay a minimal summary, not a JSON mirror: {} bytes",
            text.text.len()
        );
        assert!(!text.text.contains('{'), "content must not embed JSON");

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// Section 19/20: proves `PARSE_COMPACT_SYMBOLS_MAX` is enforced
    /// end-to-end, deterministically, through the real handler -- a file
    /// with more real symbols than the cap must report exactly the capped
    /// count plus an explicit `truncated: true`, never a silently
    /// incomplete list.
    #[tokio::test]
    async fn parse_file_truncates_and_flags_over_cap_symbol_counts()
    -> wht_corulix_core::CorulixResult<()> {
        let root_dir = temp_root("parse-truncation");
        let mut source = String::new();
        for i in 0..(dto::PARSE_COMPACT_SYMBOLS_MAX + 50) {
            source.push_str(&format!("fn corulix_generated_{i}() {{}}\n"));
        }
        fs::write(root_dir.join("main.rs"), &source)
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        let identity = WorkspaceIdentity::from_opaque_token("wsid-parse-truncation".to_string())?;
        let server = CorulixMcpServer::new(engine, identity)?;

        let result = server
            .parse_file(Parameters(ParseFileParams {
                path: "main.rs".to_string(),
                root_selector: None,
            }))
            .await;
        assert_eq!(result.is_error, Some(false));
        let value = structured(&result);
        assert_eq!(value["truncated"], serde_json::json!(true));
        let Some(symbols) = value["symbols"].as_array() else {
            unreachable!("compact contract always carries a symbols array");
        };
        assert_eq!(symbols.len(), dto::PARSE_COMPACT_SYMBOLS_MAX);

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    #[tokio::test]
    async fn go_semantic_is_unavailable_without_host_provider_authority()
    -> wht_corulix_core::CorulixResult<()> {
        let server = server("semantic")?;
        let result = server
            .semantic(Parameters(SemanticParams {
                operation: wht_corulix_engine::semantic::SemanticOperation::Definition,
                // P15: Go *is* now a wired language, so what this test proves
                // changed meaning -- it is no longer "Go is unwired" but
                // "a bare server, whose engine carries no `HOST_ONLY` Go
                // provider authority, resolves nothing and says so". The
                // positive counterpart, against a server whose engine was
                // opened with real Go authority, is
                // `real_go_semantic_via_the_canonical_mcp_semantic_tool`.
                // Ambient `PATH` must never rescue this call even though
                // `gopls`/`go` are genuinely installed on this host.
                language: wht_corulix_core::LanguageId::Go,
                path: "main.rs".to_string(),
                line_zero_based: 0,
                byte_column_zero_based: 0,
                byte_offset: 0,
                new_name: None,
            }))
            .await;
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            structured(&result)["status"],
            serde_json::json!("unavailable")
        );
        Ok(())
    }

    #[tokio::test]
    async fn format_preview_is_unavailable_with_nothing_provisioned()
    -> wht_corulix_core::CorulixResult<()> {
        // `server()`'s bare `HostConfig::default()` is not sufficient here
        // (Installation-Contract-V1): its `Inherit` policy defers to this
        // host's real, shared, host-wide `managed_toolchain_root()`'s
        // persisted install profile, which is no longer unconditionally
        // "nothing is provisioned" once this host's `corulix` has ever
        // bootstrapped for real -- see
        // `mcp_cannot_close_format_gate_when_provider_is_unavailable`'s own
        // comment for the same reasoning and its residual caveat (`Deny`
        // gates fresh acquisition only, not an already-owned component;
        // this crate exposes no isolated-`managed_root` override).
        let root_dir = temp_root("format-preview-nothing-provisioned");
        let _ = fs::create_dir_all(root_dir.join("docs"));
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open_with_host_config(
            context,
            false,
            wht_corulix_engine::HostConfig {
                managed_provisioning_policy: wht_corulix_engine::ManagedProvisioningPolicy::Deny,
                ..wht_corulix_engine::HostConfig::default()
            },
        ));
        let identity = WorkspaceIdentity::from_opaque_token(
            "wsid-format-preview-nothing-provisioned".to_string(),
        )?;
        let server = CorulixMcpServer::new(engine, identity)?;
        let result = server
            .format_preview(Parameters(FormatPreviewParams {
                path: "main.rs".to_string(),
                root_selector: None,
            }))
            .await;
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            structured(&result)["status"],
            serde_json::json!("unavailable")
        );
        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    // -----------------------------------------------------------------
    // 5. Full ChangeSession lifecycle: begin_change -> submit_edit ->
    //    validate_change -> change_status -> complete_change.
    // -----------------------------------------------------------------
    #[tokio::test]
    async fn full_change_session_lifecycle_completes() -> wht_corulix_core::CorulixResult<()> {
        let server = server("lifecycle")?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::DocumentationModify,
                language: None,
                root_selector: None,
                scope_prefixes: vec!["docs".to_string()],
            }))
            .await;
        assert_eq!(begin.is_error, Some(false));
        let Some(session_id) = structured(&begin)["session_id"].as_str() else {
            unreachable!("begin_change's Opened outcome always carries a session_id");
        };
        let session_id = session_id.to_string();

        let submit = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "docs/readme.md".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: "# hello".to_string(),
                },
            }))
            .await;
        assert_eq!(submit.is_error, Some(false));
        assert_eq!(
            structured(&submit)["mutations_applied"],
            serde_json::json!(1)
        );

        // `DocumentationModify` has no `gate.diagnostics` applicability at
        // all, and (Rust production-routing closure) `validate_change_rust`
        // now consults `ChangeSession::requirement_authority(TypecheckBuild)`
        // before attempting anything -- `None` here, so this reports
        // `NotRequired` (Minimum Sufficient Tooling): a genuinely successful
        // call that correctly recognized no validator was ever asked for,
        // never fabricating Evidence for a gate the session's own `ToolPlan`
        // never named. Before this closure, `validate_change_rust`
        // unconditionally attempted `cargo check` regardless of policy and
        // was rejected downstream by `record_evidence` (a real call error);
        // that was the pre-existing regression this closure fixes, not the
        // correct contract.
        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(validate.is_error, Some(false));
        assert_eq!(
            structured(&validate)["outcome"]["status"],
            serde_json::json!("not_required")
        );

        let status = server
            .change_status(Parameters(ChangeStatusParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(status.is_error, Some(false));
        assert!(
            structured(&status)["status"]["completion_eligible"]
                .as_bool()
                .unwrap_or(false)
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(complete.is_error, Some(false));
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("completed")
        );

        // A subsequent write against a terminal (`COMPLETED`) session must
        // be denied.
        let after_complete = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id,
                relative_path: "docs/second.md".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: "# second".to_string(),
                },
            }))
            .await;
        assert_eq!(after_complete.is_error, Some(true));
        Ok(())
    }

    // -----------------------------------------------------------------
    // F2 regression suite: `session_error_reason` no longer collapses every
    // real `MutationError` into `RequiredCapabilityUnavailable`. Reproduces
    // the three empirically-found cases through the real, live
    // `submit_edit` MCP tool (in-process server, but the identical
    // production tool-handler code path -- never a unit test of the
    // mapping function alone).
    // -----------------------------------------------------------------

    /// F2 case 2 (stale/wrong precondition hash on `replace`) ->
    /// `PRECONDITION_NOT_MET`. Before this fix: `REQUIRED_CAPABILITY_UNAVAILABLE`.
    #[tokio::test]
    async fn f2_stale_precondition_hash_reports_precondition_not_met()
    -> wht_corulix_core::CorulixResult<()> {
        let server = server("f2-stale-hash")?;
        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::DocumentationModify,
                language: None,
                root_selector: None,
                scope_prefixes: vec!["docs".to_string()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let create = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "docs/f2-stale.md".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: "# original".to_string(),
                },
            }))
            .await;
        assert_eq!(create.is_error, Some(false));

        let replace_with_wrong_hash = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id,
                relative_path: "docs/f2-stale.md".to_string(),
                edit: EditRequestParams::Replace {
                    expected_precondition_hash_hex: wht_corulix_core::ContentHash::compute_sha256(
                        b"this is definitely not the real current content",
                    )
                    .digest_hex,
                    content_utf8: "# replaced".to_string(),
                },
            }))
            .await;
        assert_eq!(replace_with_wrong_hash.is_error, Some(true));
        assert_eq!(
            structured(&replace_with_wrong_hash)["reason_code"],
            serde_json::json!("PRECONDITION_NOT_MET"),
            "expected a precise stale-precondition-hash reason, got: {}",
            structured(&replace_with_wrong_hash)
        );
        Ok(())
    }

    /// F2 case 3 (`create` onto an already-existing path) ->
    /// `MUTATION_TARGET_ALREADY_EXISTS`. Before this fix:
    /// `REQUIRED_CAPABILITY_UNAVAILABLE`.
    #[tokio::test]
    async fn f2_create_collision_reports_mutation_target_already_exists()
    -> wht_corulix_core::CorulixResult<()> {
        let server = server("f2-create-collision")?;
        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::DocumentationModify,
                language: None,
                root_selector: None,
                scope_prefixes: vec!["docs".to_string()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let first_create = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "docs/f2-collision.md".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: "# first".to_string(),
                },
            }))
            .await;
        assert_eq!(first_create.is_error, Some(false));

        let second_create = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id,
                relative_path: "docs/f2-collision.md".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: "# second, colliding".to_string(),
                },
            }))
            .await;
        assert_eq!(second_create.is_error, Some(true));
        assert_eq!(
            structured(&second_create)["reason_code"],
            serde_json::json!("MUTATION_TARGET_ALREADY_EXISTS"),
            "expected a precise create-collision reason, got: {}",
            structured(&second_create)
        );
        Ok(())
    }

    /// F2 case 1 (`create` whose immediate parent directory does not
    /// exist) -> `MUTATION_TARGET_CONFINEMENT_VIOLATION`. Before this fix:
    /// `REQUIRED_CAPABILITY_UNAVAILABLE`. The session's own declared scope
    /// prefix (`docs`) genuinely exists as a directory; only the file's own
    /// immediate parent subdirectory (`docs/missing-parent`) is absent --
    /// isolating this from a `SESSION_SCOPE_VIOLATION`, which would instead
    /// fire for a path outside the declared scope entirely.
    #[tokio::test]
    async fn f2_missing_parent_directory_reports_mutation_target_confinement_violation()
    -> wht_corulix_core::CorulixResult<()> {
        let server = server("f2-missing-parent")?;
        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::DocumentationModify,
                language: None,
                root_selector: None,
                scope_prefixes: vec!["docs".to_string()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let create = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id,
                relative_path: "docs/missing-parent/file.md".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: "# unreachable parent".to_string(),
                },
            }))
            .await;
        assert_eq!(create.is_error, Some(true));
        assert_eq!(
            structured(&create)["reason_code"],
            serde_json::json!("MUTATION_TARGET_CONFINEMENT_VIOLATION"),
            "expected a precise confinement-violation reason for an absent immediate parent \
             directory, got: {}",
            structured(&create)
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // F3 regression suite (`SOURCE_DELETE_COMMITTED_UNCOMPLETABLE_STATE`):
    // a `SOURCE_DELETE` `ChangeSession` now has a real, callable path to
    // `COMPLETED` -- through the real, live `submit_edit`/`validate_change`/
    // `complete_change` MCP tools, never an in-process shortcut around
    // `ChangeSession::record_evidence`.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn f3_source_delete_session_reaches_completed_via_real_post_audit()
    -> wht_corulix_core::CorulixResult<()> {
        let server = server("f3-source-delete")?;
        let root_dir = server.engine.resolve_workspace_root(None)?;
        let target_relative = "docs/f3-delete-target.md";
        let target_content = b"# will genuinely be deleted";
        fs::write(
            root_dir.canonical_path().join(target_relative),
            target_content,
        )
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let target_absolute = root_dir.canonical_path().join(target_relative);
        assert!(
            target_absolute.exists(),
            "test fixture setup must genuinely create the file before the delete session begins"
        );

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::SourceDelete,
                language: None,
                root_selector: None,
                scope_prefixes: vec!["docs".to_string()],
            }))
            .await;
        assert_eq!(
            begin.is_error,
            Some(false),
            "expected SourceDelete to open (TextSearch is unconditionally Available), got: {}",
            structured(&begin)
        );
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let submit = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: target_relative.to_string(),
                edit: EditRequestParams::Delete {
                    expected_precondition_hash_hex: wht_corulix_core::ContentHash::compute_sha256(
                        target_content,
                    )
                    .digest_hex,
                },
            }))
            .await;
        assert_eq!(
            submit.is_error,
            Some(false),
            "expected the real delete to commit, got: {}",
            structured(&submit)
        );
        assert!(
            !target_absolute.exists(),
            "the real committed delete must genuinely remove the file from disk"
        );

        // `validate_change`: the real post-audit path this fix wires --
        // before this fix, `SOURCE_DELETE`'s `gate.post_audit` was
        // structurally unclosable and this call would have reported
        // `NotRequired` (falling through the old, unconditional
        // `TypecheckBuild`-only dispatch) with no real Evidence ever
        // recorded for that gate.
        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            validate.is_error,
            Some(false),
            "expected a real, successful post-audit call, got: {}",
            structured(&validate)
        );
        assert_eq!(
            structured(&validate)["outcome"]["status"],
            serde_json::json!("post_audit_executed"),
            "expected the real F3 post-audit dispatch, got: {}",
            structured(&validate)
        );
        assert_eq!(
            structured(&validate)["outcome"]["clean"],
            serde_json::json!(true),
            "expected a clean post-audit (genuinely absent, no dangling reference), got: {}",
            structured(&validate)
        );
        assert_eq!(
            structured(&validate)["outcome"]["checked_targets"],
            serde_json::json!(1)
        );

        let status = server
            .change_status(Parameters(ChangeStatusParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert!(
            structured(&status)["status"]["completion_eligible"]
                .as_bool()
                .unwrap_or(false),
            "expected gate.post_audit to have real Current Passed Evidence, got: {}",
            structured(&status)
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams { session_id }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("completed"),
            "SOURCE_DELETE_COMMITTED_UNCOMPLETABLE_STATE must now be IMPOSSIBLE, got: {}",
            structured(&complete)
        );

        // The delete's own effect is still real and permanent -- completion
        // never resurrects the target.
        assert!(!target_absolute.exists());
        let _ = fs::remove_dir_all(root_dir.canonical_path());
        Ok(())
    }

    /// F3 regression: a delete-kind session that never actually commits a
    /// real delete must never reach `Completed` -- `validate_change`
    /// records no Evidence at all for an empty `deleted_targets` (never a
    /// vacuous "clean" pass), so `complete_change` still correctly denies
    /// with `RequiredGateMissingEvidence`.
    #[tokio::test]
    async fn f3_source_delete_without_a_real_delete_never_completes()
    -> wht_corulix_core::CorulixResult<()> {
        let server = server("f3-source-delete-empty")?;
        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::SourceDelete,
                language: None,
                root_selector: None,
                scope_prefixes: vec!["docs".to_string()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        // No `submit_edit` call at all -- `deleted_targets` stays empty.
        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            validate.is_error,
            Some(true),
            "an empty deleted_targets must never produce a vacuous pass, got: {}",
            structured(&validate)
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams { session_id }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("denied"),
            "completion must still be denied with no real delete ever committed, got: {}",
            structured(&complete)
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // 6. Abort flow: begin_change -> abort_change -> status ABORTED -> a
    //    subsequent write is denied; no auto-restore of source bytes.
    // -----------------------------------------------------------------
    #[tokio::test]
    async fn abort_flow_denies_further_writes_and_never_restores()
    -> wht_corulix_core::CorulixResult<()> {
        let server = server("abort")?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::DocumentationModify,
                language: None,
                root_selector: None,
                scope_prefixes: vec!["docs".to_string()],
            }))
            .await;
        let Some(session_id) = structured(&begin)["session_id"].as_str() else {
            unreachable!("begin_change's Opened outcome always carries a session_id");
        };
        let session_id = session_id.to_string();

        // A real edit before abort, so there is real content whose
        // non-restoration this test can assert on directly.
        let submit = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "docs/pre-abort.md".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: "# pre-abort content".to_string(),
                },
            }))
            .await;
        assert_eq!(submit.is_error, Some(false));

        let abort = server
            .abort_change(Parameters(AbortChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(abort.is_error, Some(false));
        assert_eq!(structured(&abort)["status"], serde_json::json!("aborted"));

        let status = server
            .change_status(Parameters(ChangeStatusParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            structured(&status)["status"]["status"],
            serde_json::json!("Aborted")
        );

        // A subsequent write attempt is denied -- abort is terminal.
        let after_abort = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id,
                relative_path: "docs/post-abort.md".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: "# should never land".to_string(),
                },
            }))
            .await;
        assert_eq!(after_abort.is_error, Some(true));

        // `AUTO_RESTORE_BASELINE=NO`: abort performs no filesystem
        // restoration -- the real file `submit_edit` committed before
        // abort must still exist with its real committed content, exactly
        // as `abort`'s own contract promises (Phase 10 §14/§16).
        let root_dir = server.engine.resolve_workspace_root(None)?;
        let committed = fs::read_to_string(root_dir.canonical_path().join("docs/pre-abort.md"))
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        assert_eq!(committed, "# pre-abort content");
        Ok(())
    }

    // -----------------------------------------------------------------
    // 7. begin_change/submit_edit/change_status/complete_change/
    //    abort_change against an unknown session id.
    // -----------------------------------------------------------------
    #[tokio::test]
    async fn unknown_session_id_is_reported_not_found_everywhere()
    -> wht_corulix_core::CorulixResult<()> {
        let server = server("unknown-session")?;
        let unknown = "does-not-exist".to_string();

        let submit = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: unknown.clone(),
                relative_path: "a.rs".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: "x".to_string(),
                },
            }))
            .await;
        assert_eq!(submit.is_error, Some(true));
        assert_eq!(
            structured(&submit)["status"],
            serde_json::json!("session_not_found")
        );

        let status = server
            .change_status(Parameters(ChangeStatusParams {
                session_id: unknown.clone(),
            }))
            .await;
        assert_eq!(
            structured(&status)["outcome"],
            serde_json::json!("session_not_found")
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams {
                session_id: unknown.clone(),
            }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("session_not_found")
        );

        let abort = server
            .abort_change(Parameters(AbortChangeParams {
                session_id: unknown,
            }))
            .await;
        assert_eq!(
            structured(&abort)["status"],
            serde_json::json!("session_not_found")
        );
        Ok(())
    }

    // =================================================================
    // P15 -- Go through the real, unchanged 14-tool MCP surface
    // =================================================================

    /// Test-only PATH-based discovery of `gopls`, `HOST_ONLY`-style for test
    /// purposes only. `CORULIX_TEST_GOPLS` overrides discovery with an
    /// exact binary path. Never embeds a specific developer's machine path.
    fn real_gopls_path() -> Option<PathBuf> {
        if let Ok(explicit) = std::env::var("CORULIX_TEST_GOPLS") {
            return Some(PathBuf::from(explicit));
        }
        let exe_name = format!("gopls{}", std::env::consts::EXE_SUFFIX);
        std::env::var_os("PATH")
            .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
            .map(|dir| dir.join(&exe_name))
    }
    /// This development environment's real Go toolchain directory. This is
    /// a well-known, portable standard install location, not a specific
    /// developer's machine path.
    const REAL_GO_DIRECTORY: &str = "/usr/local/go/bin";

    /// `MANAGED_TEST_ISOLATION_DEFECT` closure pass.
    ///
    /// # The defect this replaces
    ///
    /// `CorulixMcpServer::semantic`/`validate_change` call into
    /// `CorulixEngine`, which resolves the host-wide managed root by design
    /// -- that is the production path. The Go session's build caches
    /// therefore used to land in the **real, shared** root as
    /// `scratch/p15-go/<workspace-hash>/...`, and this module previously
    /// cleaned that up with `remove_shared_root_go_scratch` (deleting
    /// `scratch/p15-go` and, if now empty, `scratch/` -- directly against
    /// live host state) so it wouldn't be misclassified as unexplained
    /// residue by an unrelated suite's zero-residual sweep
    /// (`provisioning::full_uninstall`'s sweep only knows `ownership/`,
    /// `staging/`, `.uninstall-txn/`; anything else is deliberately left
    /// alone, `FOREIGN_RESIDUAL_AUTO_DELETE_COUNT=0`).
    ///
    /// # The fix
    ///
    /// Rather than cleaning up a live-root mutation after the fact, isolate
    /// the root so the mutation never reaches it. `managed_toolchain_root()`
    /// is resolved process-wide with no injection point at this layer, and
    /// this workspace forbids `unsafe` code (`std::env::set_var` is
    /// `unsafe fn`), so a test process cannot redirect its own
    /// `XDG_DATA_HOME`. This re-execs the exact, already-compiled test
    /// binary as a real child process (libtest's own `--exact` filter) with
    /// `XDG_DATA_HOME` pointed at a fresh isolated directory -- the same
    /// pattern already used by `mcp_cannot_close_format_gate_when_provider_is_unavailable`
    /// above and `real_ts6_hostile_environment_behavioral_e2e`
    /// (`wht_corulix_lsp/tests/real_ts6_final_residual_certification_e2e.rs`).
    /// The Go scratch this produces then lives entirely under that isolated
    /// directory, which the parent removes afterward -- never the real root.
    ///
    /// Returns `Ok(true)` when called from the PARENT process: the child has
    /// already run and its success already asserted, so the caller should
    /// return `Ok(())` immediately. Returns `Ok(false)` when called from
    /// inside the isolated CHILD (the trigger env var is present): the
    /// caller should continue running its real test body now, with
    /// `managed_toolchain_root()` already resolving to the isolated root via
    /// this process's own `XDG_DATA_HOME`.
    async fn run_isolated_or_continue(
        trigger_env: &str,
        exact_test_name: &str,
    ) -> wht_corulix_core::CorulixResult<bool> {
        if std::env::var(trigger_env).ok().as_deref() == Some("1") {
            return Ok(false);
        }
        let isolated_xdg_data_home = temp_root(&format!("isolated-xdg-data-home-{trigger_env}"));
        let exe = std::env::current_exe()
            .map_err(|error| wht_corulix_core::CorulixError::InvalidInput(error.to_string()))?;
        let output = tokio::process::Command::new(&exe)
            .args([
                "--exact",
                exact_test_name,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(trigger_env, "1")
            .env("XDG_DATA_HOME", &isolated_xdg_data_home)
            .output()
            .await
            .map_err(|error| wht_corulix_core::CorulixError::InvalidInput(error.to_string()))?;
        let _ = fs::remove_dir_all(&isolated_xdg_data_home);
        assert!(
            output.status.success(),
            "isolated child run of {exact_test_name} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(true)
    }

    /// P17-W-R3-C3 (`CANONICAL_DEFAULT_PARALLEL_TEST_GATE_FLAKINESS`): every
    /// test in this module that calls `remove_shared_root_go_scratch` drives
    /// a real Go toolchain invocation through the same shared, host-wide
    /// `managed_toolchain_root()` scratch tree that function's own doc
    /// discloses -- the identical shared-resource shape
    /// `wht_corulix_engine`'s `real_p15_go_production_routing_e2e.rs` was
    /// confirmed to flake on under `cargo test`'s default concurrency (see
    /// that file's own `go_production_routing_test_lock` for the full
    /// empirical root-cause evidence: reliable under `--test-threads=1`,
    /// intermittent `RequiredCapabilityUnavailable` under default
    /// parallelism). Every test below acquires this lock for its entire
    /// body for the same reason, before that same class of flake is
    /// observed here too.
    static GO_SCRATCH_TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
        std::sync::OnceLock::new();

    async fn go_scratch_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
        GO_SCRATCH_TEST_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await
    }

    fn real_go_toolchain_available() -> bool {
        real_gopls_path().is_some_and(|p| p.is_file())
            && std::path::Path::new(REAL_GO_DIRECTORY).join("go").is_file()
            && std::path::Path::new(REAL_GO_DIRECTORY)
                .join("gofmt")
                .is_file()
    }

    /// A real, disposable Go module workspace plus an MCP server whose engine
    /// carries genuine `HOST_ONLY` Go provider authority
    /// (`CorulixEngine::open_with_host_config` -- exactly the contract P15
    /// added for this, since Go tooling is host-installed and P15 may not
    /// introduce a download path for it).
    ///
    /// Nothing about the MCP surface itself is altered or bypassed: this is
    /// the same `CorulixMcpServer::new(engine, identity)` the real
    /// `corulix mcp stdio` process constructs, differing only in the host
    /// configuration its engine was opened with -- which is precisely the
    /// owner/operator decision `HOST_ONLY` configuration exists to express.
    fn go_server(
        label: &str,
        main_go: &str,
    ) -> wht_corulix_core::CorulixResult<(CorulixMcpServer, PathBuf)> {
        let root_dir = temp_root(label);
        let _ = fs::create_dir_all(root_dir.join("src"));
        let _ = fs::write(
            root_dir.join("go.mod"),
            "module corulix_p15_mcp_fixture\n\ngo 1.24\n",
        );
        let _ = fs::write(root_dir.join("src/main.go"), main_go);

        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let host = wht_corulix_engine::HostConfig {
            provider_absolute_paths: vec![(
                wht_corulix_core::ProviderCategory::LanguageServer,
                real_gopls_path().unwrap_or_default(),
            )],
            approved_system_directories: vec![PathBuf::from(REAL_GO_DIRECTORY)],
            ..wht_corulix_engine::HostConfig::default()
        };
        let engine = Arc::new(CorulixEngine::open_with_host_config(context, false, host));
        let identity = WorkspaceIdentity::from_opaque_token(format!("wsid-p15-mcp-{label}"))?;
        Ok((CorulixMcpServer::new(engine, identity)?, root_dir))
    }

    /// As [`go_server`], but with the engine opened *trusted*
    /// (`CorulixEngine::open_with_host_config(_, true, _)`) -- required for
    /// the P15 production-routing closure's real `go build`/`go vet`/`go
    /// test` calls, which are `TrustedWorkspaceExecution`. `main_go` is
    /// written at the workspace root (not under `src/`) since a
    /// `ValidateChange`-intent session carries no `Edit`/`Format` gate and
    /// therefore no scope restriction is exercised.
    fn go_validate_server(
        label: &str,
        main_go: &str,
    ) -> wht_corulix_core::CorulixResult<(CorulixMcpServer, PathBuf)> {
        let root_dir = temp_root(label);
        let _ = fs::write(
            root_dir.join("go.mod"),
            "module corulix_p15_mcp_validate_fixture\n\ngo 1.24\n",
        );
        let _ = fs::write(root_dir.join("main.go"), main_go);

        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let host = wht_corulix_engine::HostConfig {
            approved_system_directories: vec![PathBuf::from(REAL_GO_DIRECTORY)],
            ..wht_corulix_engine::HostConfig::default()
        };
        let engine = Arc::new(CorulixEngine::open_with_host_config(context, true, host));
        let identity =
            WorkspaceIdentity::from_opaque_token(format!("wsid-p15-mcp-validate-{label}"))?;
        Ok((CorulixMcpServer::new(engine, identity)?, root_dir))
    }

    /// P15 production-routing regression closure, §13: one complete real Go
    /// flow through the actual, unchanged 14-tool MCP surface --
    /// `begin_change` -> `validate_change` -> `change_status` ->
    /// `complete_change`. Never calls `run_go_validator`/`run_go_test`
    /// directly (that would reproduce the exact certification weakness this
    /// closure fixes); drives only the same tools a real MCP client calls.
    #[tokio::test]
    async fn real_go_changesession_e2e_through_validate_change_mcp_tool()
    -> wht_corulix_core::CorulixResult<()> {
        if !real_go_toolchain_available() {
            eprintln!("P15_MCP_GO_E2E=BLOCKED_PROVIDER_UNAVAILABLE");
            return Ok(());
        }
        if run_isolated_or_continue(
            "CORULIX_GO_CHANGESESSION_CHILD",
            "tests::real_go_changesession_e2e_through_validate_change_mcp_tool",
        )
        .await?
        {
            return Ok(());
        }
        let _lock = go_scratch_test_lock().await;
        let (server, root_dir) =
            go_validate_server("changesession", "package main\n\nfunc main() {}\n")?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::ValidateChange,
                language: Some(wht_corulix_core::LanguageId::Go),
                root_selector: None,
                scope_prefixes: Vec::new(),
            }))
            .await;
        assert_eq!(
            structured(&begin)["outcome"],
            serde_json::json!("opened"),
            "expected a Go ValidateChange session to open, got {}",
            structured(&begin)
        );
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            validate.is_error,
            Some(false),
            "expected a real, successful Go validate_change call, got {}",
            structured(&validate)
        );
        let outcome = &structured(&validate)["outcome"];
        assert_eq!(
            outcome["status"],
            serde_json::json!("go_executed"),
            "expected the real Go dispatcher's outcome, got {outcome}"
        );
        assert_eq!(
            outcome["build"]["clean"],
            serde_json::json!(true),
            "expected a real, clean go build through MCP, got {outcome}"
        );

        let status = server
            .change_status(Parameters(ChangeStatusParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert!(
            structured(&status)["status"]["completion_eligible"]
                .as_bool()
                .unwrap_or(false),
            "expected completion_eligible after a real clean go build, got {}",
            structured(&status)
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("completed"),
            "expected the real Go ValidateChange session to complete, got {}",
            structured(&complete)
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// The one Go fixture the MCP semantic tests use: `target` declared once
    /// and referenced once, so `references` has a real countable answer and
    /// `rename` a real multi-site edit set.
    const GO_FIXTURE: &str = "package main\n\nfunc target() int {\n\treturn 41\n}\n\nfunc caller() int {\n\treturn target()\n}\n\nfunc main() {\n\t_ = caller()\n}\n";

    /// `P15_REAL_GO_DEFINITION_E2E` / `P15_REAL_GO_REFERENCES_E2E` /
    /// `P15_REAL_GO_DIAGNOSTICS_E2E` / `P15_REAL_GO_RENAME_PREVIEW_E2E`
    /// **through the real MCP `semantic` tool** -- the canonical, unchanged
    /// tool from the 14-tool surface, never a `go_definition`/`go_references`
    /// tool of Go's own (`P15_MCP_SURFACE_GROWTH_COUNT=0`).
    ///
    /// Before P15 this exact call reported `unavailable` for Go (see this
    /// module's own pre-P15 `semantic_is_gated_unavailable_for_an_unwired_language`,
    /// which P15 repointed at a genuinely unwired language). It now drives a
    /// real gopls session through the real Engine -> ProviderRegistry ->
    /// `wht_corulix_lsp` routing.
    #[tokio::test]
    async fn real_go_semantic_via_the_canonical_mcp_semantic_tool()
    -> wht_corulix_core::CorulixResult<()> {
        if !real_go_toolchain_available() {
            eprintln!(
                "P15_MCP_GO_E2E=BLOCKED_PROVIDER_UNAVAILABLE: no real go/gopls/gofmt on this host"
            );
            return Ok(());
        }
        if run_isolated_or_continue(
            "CORULIX_GO_SEMANTIC_CHILD",
            "tests::real_go_semantic_via_the_canonical_mcp_semantic_tool",
        )
        .await?
        {
            return Ok(());
        }
        let _lock = go_scratch_test_lock().await;
        let (server, root_dir) = go_server("go-semantic", GO_FIXTURE)?;

        // Byte offsets derived from the fixture text itself: `byte_offset` is
        // `wht_corulix_lsp`'s sole addressing key, so a plausible-looking
        // line/column pair with a wrong offset would silently address the
        // wrong token and make a passing assertion meaningless.
        let Some(declaration_offset) = GO_FIXTURE.find("target") else {
            unreachable!("the compiled-in fixture always contains `target`");
        };
        let preceding = &GO_FIXTURE[..declaration_offset];
        let line = preceding.matches('\n').count() as u32;
        let line_start = preceding.rfind('\n').map_or(0, |index| index + 1);
        let column = (declaration_offset - line_start) as u32;

        // --- definition ---
        let definition = server
            .semantic(Parameters(SemanticParams {
                operation: wht_corulix_engine::semantic::SemanticOperation::Definition,
                language: wht_corulix_core::LanguageId::Go,
                path: "src/main.go".to_string(),
                line_zero_based: line,
                byte_column_zero_based: column,
                byte_offset: declaration_offset as u64,
                new_name: None,
            }))
            .await;
        let payload = structured(&definition);
        assert_ne!(
            payload["status"],
            serde_json::json!("unavailable"),
            "Go semantic must no longer be gated unavailable through MCP: {payload}"
        );
        assert_eq!(
            payload["status"],
            serde_json::json!("definition"),
            "expected a real definition result, got {payload}"
        );

        // --- references ---
        let references = server
            .semantic(Parameters(SemanticParams {
                operation: wht_corulix_engine::semantic::SemanticOperation::References,
                language: wht_corulix_core::LanguageId::Go,
                path: "src/main.go".to_string(),
                line_zero_based: line,
                byte_column_zero_based: column,
                byte_offset: declaration_offset as u64,
                new_name: None,
            }))
            .await;
        let payload = structured(&references);
        assert_eq!(
            payload["status"],
            serde_json::json!("references"),
            "expected a real references result, got {payload}"
        );
        // `NotReady` here would mean the readiness gate is not load-bearing.
        assert_eq!(
            payload["result"]["kind"],
            serde_json::json!("found"),
            "references must be a proven Found set, never NotReady, after readiness: {payload}"
        );

        // --- diagnostics ---
        let diagnostics = server
            .semantic(Parameters(SemanticParams {
                operation: wht_corulix_engine::semantic::SemanticOperation::Diagnostics,
                language: wht_corulix_core::LanguageId::Go,
                path: "src/main.go".to_string(),
                line_zero_based: line,
                byte_column_zero_based: column,
                byte_offset: declaration_offset as u64,
                new_name: None,
            }))
            .await;
        let payload = structured(&diagnostics);
        assert_eq!(
            payload["status"],
            serde_json::json!("diagnostics"),
            "expected a real diagnostics result, got {payload}"
        );
        assert_eq!(
            payload["result"]["kind"],
            serde_json::json!("reported"),
            "diagnostics must be Reported, never NotReady, after readiness: {payload}"
        );

        // --- rename_preview: never writes live source ---
        let before = fs::read(root_dir.join("src/main.go")).unwrap_or_default();
        let rename = server
            .semantic(Parameters(SemanticParams {
                operation: wht_corulix_engine::semantic::SemanticOperation::RenamePreview,
                language: wht_corulix_core::LanguageId::Go,
                path: "src/main.go".to_string(),
                line_zero_based: line,
                byte_column_zero_based: column,
                byte_offset: declaration_offset as u64,
                new_name: Some("renamedTarget".to_string()),
            }))
            .await;
        let payload = structured(&rename);
        assert_eq!(
            payload["status"],
            serde_json::json!("rename_preview"),
            "expected a real rename preview, got {payload}"
        );
        assert_eq!(
            fs::read(root_dir.join("src/main.go")).unwrap_or_default(),
            before,
            "rename_preview must never write live source"
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// Real Go `format_preview` through the canonical MCP `format_preview`
    /// tool: `gofmt` resolved via `HOST_ONLY`, a real `WouldFormat` verdict,
    /// and the live file untouched.
    #[tokio::test]
    async fn real_go_format_preview_via_the_canonical_mcp_tool()
    -> wht_corulix_core::CorulixResult<()> {
        if !real_go_toolchain_available() {
            eprintln!("P15_MCP_GO_E2E=BLOCKED_PROVIDER_UNAVAILABLE");
            return Ok(());
        }
        let _lock = go_scratch_test_lock().await;
        let unformatted = "package main\nfunc  main( ){\nx:=1\n_ = x\n}\n";
        let (server, root_dir) = go_server("go-format", unformatted)?;
        let before = fs::read(root_dir.join("src/main.go")).unwrap_or_default();

        let result = server
            .format_preview(Parameters(FormatPreviewParams {
                path: "src/main.go".to_string(),
                root_selector: None,
            }))
            .await;
        let payload = structured(&result);
        assert_eq!(
            payload["status"],
            serde_json::json!("would_format"),
            "expected a real gofmt WouldFormat verdict through MCP, got {payload}"
        );
        // §29: the exact provider identity, never an ambiguous "system go".
        let version = payload["provider_version"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            version.starts_with("go version go"),
            "expected the real `go version` identity for gofmt, got {version:?}"
        );
        // `MANAGED_TEST_ISOLATION_DEFECT` closure pass, stale-assertion
        // correction: gofmt is a sibling binary bundled with the managed
        // `go-semantic-runtime` component (already established by the M04
        // qualification pass's own `GO_FORMATTER_PROVIDER=gofmt` finding,
        // reconfirmed empirically here), so once `go-semantic-runtime` is
        // owned on the resolved managed root (as it is on this host),
        // `resolve_formatter` correctly reports `CORULIX_MANAGED` -- this
        // test's `go_server` fixture pins only `ProviderCategory::LanguageServer`
        // (gopls) to `HOST_ONLY`; it never pins the formatter category, so
        // there never was a `HOST_ONLY` guarantee for gofmt to assert here.
        // The assertion below was stale, not the product.
        assert_eq!(
            payload["provider_used_managed"],
            serde_json::json!(true),
            "expected gofmt to resolve via CORULIX_MANAGED (sibling of go-semantic-runtime)"
        );
        assert_eq!(
            fs::read(root_dir.join("src/main.go")).unwrap_or_default(),
            before,
            "format_preview must never write live source"
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// A Go-language-scoped `begin_change` really reaches the language-aware
    /// routing path (P15's `BeginChangeParams::language`), and the governed
    /// `submit_edit` mutation transaction works against a Go workspace
    /// through the canonical MCP tools.
    #[tokio::test]
    async fn go_language_scoped_change_session_through_mcp() -> wht_corulix_core::CorulixResult<()>
    {
        if !real_go_toolchain_available() {
            eprintln!("P15_MCP_GO_E2E=BLOCKED_PROVIDER_UNAVAILABLE");
            return Ok(());
        }
        let original = "package main\n\nfunc main() {}\n";
        let (server, root_dir) = go_server("go-session", original)?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::DocumentationModify,
                language: Some(wht_corulix_core::LanguageId::Go),
                root_selector: None,
                scope_prefixes: vec!["src".to_string()],
            }))
            .await;
        let payload = structured(&begin);
        assert_eq!(
            payload["outcome"],
            serde_json::json!("opened"),
            "expected a Go-scoped session to open, got {payload}"
        );
        let session_id = payload["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        // A real governed mutation transaction against Go source.
        let submit = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "src/main.go".to_string(),
                edit: EditRequestParams::Replace {
                    expected_precondition_hash_hex: wht_corulix_core::ContentHash::compute_sha256(
                        original.as_bytes(),
                    )
                    .digest_hex,
                    content_utf8: "package main\n\n// governed edit\nfunc main() {}\n".to_string(),
                },
            }))
            .await;
        assert_eq!(
            structured(&submit)["status"],
            serde_json::json!("committed"),
            "expected a committed governed edit, got {}",
            structured(&submit)
        );
        assert!(
            fs::read_to_string(root_dir.join("src/main.go"))
                .unwrap_or_default()
                .contains("governed edit"),
            "the real mutation transaction did not land"
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("completed"),
            "expected the Go-scoped session to complete, got {}",
            structured(&complete)
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// `P15_MCP_SURFACE_GROWTH_COUNT=0` / `FINAL_MCP_TOOL_COUNT=14`, asserted
    /// again *after* P15's Go work: Go is reachable entirely through the
    /// pre-existing canonical tools, and no `go_definition`/`go_references`/
    /// `go_build`/`go_test`/`go_format` tool was introduced.
    #[test]
    fn p15_introduces_no_go_specific_mcp_tool() {
        let tools = CorulixMcpServer::tool_router().list_all();
        assert_eq!(
            tools.len(),
            14,
            "the canonical MCP surface must remain exactly 14 tools"
        );
        for tool in &tools {
            let name = tool.name.as_ref();
            assert!(
                !name.starts_with("go_") && !name.contains("gopls") && !name.contains("gofmt"),
                "P15 must not add a Go-specific MCP tool, found {name}"
            );
        }
        // The canonical tools Go is routed through really are present.
        for expected in [
            "semantic",
            "format_preview",
            "plan_operation",
            "begin_change",
        ] {
            assert!(
                tools.iter().any(|tool| tool.name.as_ref() == expected),
                "expected the canonical {expected} tool to still exist"
            );
        }
    }

    /// F4 fix (`F4_MCP_FORMAT_GATE_UNCLOSABLE=FIXED`): this host's real
    /// `rustfmt`, `HOST_ONLY`-resolved via test-only PATH discovery exactly
    /// like [`real_gopls_path`]/[`REAL_GO_DIRECTORY`] above -- test-only
    /// resolution, not a HostConfig this crate ships. Never embeds a
    /// specific developer's machine path; `CORULIX_TEST_CARGO_BIN_DIR`
    /// overrides discovery with an exact directory. On any host where a
    /// real `rustfmt` cannot be found on `PATH`, including native Windows,
    /// [`real_rust_formatter_available`] -- the same skip-if-absent guard
    /// [`real_go_toolchain_available`] already established for the Go
    /// fixtures above -- reports `false` rather than letting a test assert
    /// against a formatter that was never really resolved.
    fn real_cargo_bin_directory() -> Option<PathBuf> {
        if let Ok(explicit) = std::env::var("CORULIX_TEST_CARGO_BIN_DIR") {
            return Some(PathBuf::from(explicit));
        }
        let exe_name = format!("rustfmt{}", std::env::consts::EXE_SUFFIX);
        // Never resolve to a `~/.cargo/bin` rustup-proxy shim: Corulix's
        // sandboxed process execution strips the environment context that
        // proxy needs to select a toolchain, so resolving to it causes a
        // spurious spawn failure -- prefer the active toolchain's real
        // sysroot (`rustc --print sysroot`), then fall back to scanning
        // every installed toolchain's `bin/` directory (`rustup show
        // home`), and only then fall back to a plain `PATH` search.
        if let Ok(output) = std::process::Command::new("rustc")
            .arg("--print")
            .arg("sysroot")
            .output()
            && output.status.success()
        {
            let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let candidate = PathBuf::from(sysroot).join("bin");
            if candidate.join(&exe_name).is_file() {
                return Some(candidate);
            }
        }
        if let Ok(output) = std::process::Command::new("rustup")
            .arg("show")
            .arg("home")
            .output()
            && output.status.success()
        {
            let rustup_home = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let toolchains_dir = PathBuf::from(rustup_home).join("toolchains");
            if let Ok(entries) = std::fs::read_dir(&toolchains_dir) {
                for entry in entries.flatten() {
                    let candidate = entry.path().join("bin");
                    if candidate.join(&exe_name).is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
        std::env::var_os("PATH")
            .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join(&exe_name).is_file()))
    }

    /// Mirrors [`real_go_toolchain_available`] exactly: a real Rust toolchain
    /// win/lose predicate, never a narrative assumption. Only the four F4
    /// tests that genuinely dispatch through [`rust_server`] into a real
    /// `validate_change` formatter check need this guard --
    /// `mcp_cannot_close_format_gate_when_provider_is_unavailable`
    /// deliberately never names a `HOST_ONLY` directory at all, and
    /// `mcp_semantic_rename_and_source_refactor_rejected_before_mutation`
    /// never calls `validate_change`, so neither one ever resolves this path
    /// and neither needs the guard.
    fn real_rust_formatter_available() -> bool {
        real_cargo_bin_directory().is_some_and(|dir| {
            dir.join(format!("rustfmt{}", std::env::consts::EXE_SUFFIX))
                .is_file()
        })
    }

    /// A real, single-root Rust `ChangeSession` fixture server: `Cargo.toml`
    /// at the workspace root, `src/main.rs` holding `main_rs`, `Formatter`
    /// resolved via `HOST_ONLY` `approved_system_directories` (never the
    /// `CORULIX_MANAGED` path -- this module's F4 tests do not depend on
    /// real network provisioning, mirroring [`go_server`]'s own `HOST_ONLY`-
    /// only precedent exactly). `TrustedWorkspaceExecution` is not granted
    /// (`false`): F4's `gate.format` closure needs only `Formatter`, never
    /// `TypecheckBuild`, so these tests never spawn `cargo`.
    fn rust_server(
        label: &str,
        main_rs: &str,
    ) -> wht_corulix_core::CorulixResult<(CorulixMcpServer, PathBuf)> {
        let root_dir = temp_root(label);
        let _ = fs::create_dir_all(root_dir.join("src"));
        let _ = fs::write(
            root_dir.join("Cargo.toml"),
            "[package]\nname = \"corulix_f4_mcp_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        let _ = fs::write(root_dir.join("src/main.rs"), main_rs);

        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let host = wht_corulix_engine::HostConfig {
            approved_system_directories: vec![real_cargo_bin_directory().unwrap_or_default()],
            ..wht_corulix_engine::HostConfig::default()
        };
        let engine = Arc::new(CorulixEngine::open_with_host_config(context, false, host));
        let identity = WorkspaceIdentity::from_opaque_token(format!("wsid-f4-mcp-{label}"))?;
        Ok((CorulixMcpServer::new(engine, identity)?, root_dir))
    }

    /// The exact, real `rustfmt`-canonical formatting of a trivial `fn main`
    /// -- shared by every F4 test below so "already formatted" and "would
    /// reformat" fixtures never drift from what `rustfmt` genuinely
    /// produces.
    const RUST_FIXTURE_CANONICAL: &str = "fn main() {\n    println!(\"f4\");\n}\n";
    /// Same program, deliberately misformatted (no space after `fn`, no
    /// indentation) -- a real `rustfmt` finding, not a syntax error.
    const RUST_FIXTURE_UNFORMATTED: &str = "fn main() {\nprintln!(\"f4\");\n}\n";

    /// §15/§19/§42: `MCP_SOURCE_MODIFY_CAN_COMPLETE=YES`,
    /// `PREMATURE_FORMAT_GATE_COMPLETION_DENIED=YES`. Drives only the real,
    /// unchanged 14-tool MCP surface: `begin_change` -> `submit_edit` ->
    /// `complete_change` (denied, `gate.format` not yet validated) ->
    /// `validate_change` (real `rustfmt` check, already-canonical bytes,
    /// `gate.format` `Passed`) -> `complete_change` (now `completed`).
    #[tokio::test]
    async fn mcp_can_close_format_gate_after_real_formatter_validation()
    -> wht_corulix_core::CorulixResult<()> {
        if !real_rust_formatter_available() {
            eprintln!("F4_MCP_FORMAT_GATE_E2E=BLOCKED_PROVIDER_UNAVAILABLE");
            return Ok(());
        }
        let (server, root_dir) = rust_server("format-gate-close", RUST_FIXTURE_UNFORMATTED)?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::SourceModify,
                language: Some(wht_corulix_core::LanguageId::Rust),
                root_selector: None,
                scope_prefixes: vec!["src".to_string()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let replace = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "src/main.rs".to_string(),
                edit: EditRequestParams::Replace {
                    expected_precondition_hash_hex: wht_corulix_core::ContentHash::compute_sha256(
                        RUST_FIXTURE_UNFORMATTED.as_bytes(),
                    )
                    .digest_hex,
                    content_utf8: RUST_FIXTURE_CANONICAL.to_string(),
                },
            }))
            .await;
        assert_eq!(
            replace.is_error,
            Some(false),
            "expected the real edit to commit, got {}",
            structured(&replace)
        );

        // §19: `complete_change` must remain denied before `gate.format` has
        // any Evidence at all -- `gate.edit` passed, but `gate.format` is
        // still `GatePending`.
        let premature = server
            .complete_change(Parameters(CompleteChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            structured(&premature)["status"],
            serde_json::json!("denied"),
            "PREMATURE_FORMAT_GATE_COMPLETION_DENIED: expected denial before validate_change, got {}",
            structured(&premature)
        );

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            validate.is_error,
            Some(false),
            "expected a real, successful format validate_change call, got {}",
            structured(&validate)
        );
        let outcome = &structured(&validate)["outcome"];
        assert_eq!(
            outcome["status"],
            serde_json::json!("format_validated"),
            "expected the real F4 format dispatcher's outcome, got {outcome}"
        );
        assert_eq!(
            outcome["clean"],
            serde_json::json!(true),
            "expected the already-canonical bytes to report clean, got {outcome}"
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams { session_id }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("completed"),
            "MCP_SOURCE_MODIFY_CAN_COMPLETE: expected completion after a real, clean rustfmt check, got {}",
            structured(&complete)
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// §13/§24: `UNFORMATTED_SOURCE_FORMAT_GATE=NOT_SATISFIED`. Submitting
    /// bytes `rustfmt` would still change must leave `gate.format`
    /// unsatisfied and deny completion -- never a false pass.
    #[tokio::test]
    async fn mcp_cannot_close_format_gate_when_formatter_would_change_bytes()
    -> wht_corulix_core::CorulixResult<()> {
        if !real_rust_formatter_available() {
            eprintln!("F4_MCP_FORMAT_GATE_E2E=BLOCKED_PROVIDER_UNAVAILABLE");
            return Ok(());
        }
        let (server, root_dir) = rust_server("format-gate-dirty", RUST_FIXTURE_CANONICAL)?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::SourceModify,
                language: Some(wht_corulix_core::LanguageId::Rust),
                root_selector: None,
                scope_prefixes: vec!["src".to_string()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let replace = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "src/main.rs".to_string(),
                edit: EditRequestParams::Replace {
                    expected_precondition_hash_hex: wht_corulix_core::ContentHash::compute_sha256(
                        RUST_FIXTURE_CANONICAL.as_bytes(),
                    )
                    .digest_hex,
                    content_utf8: RUST_FIXTURE_UNFORMATTED.to_string(),
                },
            }))
            .await;
        assert_eq!(replace.is_error, Some(false));

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(validate.is_error, Some(false));
        let outcome = &structured(&validate)["outcome"];
        assert_eq!(outcome["status"], serde_json::json!("format_validated"));
        assert_eq!(
            outcome["clean"],
            serde_json::json!(false),
            "expected the real rustfmt finding to report unclean, got {outcome}"
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams { session_id }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("denied"),
            "UNFORMATTED_SOURCE_FORMAT_GATE=NOT_SATISFIED: expected denial, got {}",
            structured(&complete)
        );
        assert_eq!(
            structured(&complete)["reason_code"],
            serde_json::json!("FORMAT_FINDINGS_REPORTED"),
            "expected the precise F4 reason code, got {}",
            structured(&complete)
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// §16/§42: `MCP_SOURCE_CREATE_CAN_COMPLETE=YES` -- the same real closure
    /// exercised for `SourceCreate` rather than `SourceModify`.
    #[tokio::test]
    async fn mcp_source_create_can_complete_after_real_formatter_validation()
    -> wht_corulix_core::CorulixResult<()> {
        if !real_rust_formatter_available() {
            eprintln!("F4_MCP_FORMAT_GATE_E2E=BLOCKED_PROVIDER_UNAVAILABLE");
            return Ok(());
        }
        let (server, root_dir) = rust_server("format-gate-create", "")?;
        let _ = fs::remove_file(root_dir.join("src/main.rs"));

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::SourceCreate,
                language: Some(wht_corulix_core::LanguageId::Rust),
                root_selector: None,
                scope_prefixes: vec!["src".to_string()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let create = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "src/main.rs".to_string(),
                edit: EditRequestParams::Create {
                    content_utf8: RUST_FIXTURE_CANONICAL.to_string(),
                },
            }))
            .await;
        assert_eq!(create.is_error, Some(false));

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        let outcome = &structured(&validate)["outcome"];
        assert_eq!(outcome["status"], serde_json::json!("format_validated"));
        assert_eq!(outcome["clean"], serde_json::json!(true));

        let complete = server
            .complete_change(Parameters(CompleteChangeParams { session_id }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("completed"),
            "MCP_SOURCE_CREATE_CAN_COMPLETE: got {}",
            structured(&complete)
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// `MANAGED_TEST_ISOLATION_DEFECT`: this test needs rustfmt genuinely
    /// absent/not-owned for the duration of one assertion, and
    /// `CorulixEngine`/`session::format_and_apply` expose no isolated-
    /// `managed_root` override the way `wht_corulix_formatter::format_and_apply_at`
    /// does for that crate's own unit tests -- `managed_toolchain_root()` is
    /// resolved process-wide, internally, with no injection point. This
    /// previously meant checking whether rustfmt was already owned on the
    /// REAL, shared host-wide root and, if so, uninstalling it for the
    /// test's duration and restoring it afterward via a `Drop`-based guard
    /// (`RestoreRustfmtIfOwnedGuard`) -- a real, temporary destructive
    /// mutation of live host state on every run where rustfmt happened to
    /// already be provisioned.
    ///
    /// Fixed by isolating the *root* instead of guarding a live mutation:
    /// this workspace forbids `unsafe` code (`std::env::set_var` is
    /// `unsafe fn` under the pinned toolchain), so this test process cannot
    /// set the relevant environment variable on itself. It re-execs this
    /// exact, already-compiled test binary as a real child process (via
    /// `std::env::current_exe()` + libtest's own `--exact` filter) with
    /// that variable pointed at a fresh, guaranteed-empty isolated
    /// directory -- the same established pattern already used by
    /// `real_ts6_hostile_environment_behavioral_e2e`
    /// (`wht_corulix_lsp/tests/real_ts6_final_residual_certification_e2e.rs`).
    /// Inside that isolated root rustfmt can never already be owned, so the
    /// entire uninstall-then-restore dance is no longer needed at all.
    ///
    /// P17-W corrective P5: `managed_toolchain_root()` resolves via a
    /// different environment variable per host OS (`provisioning.rs`) --
    /// `XDG_DATA_HOME` only on non-macOS Unix, `LOCALAPPDATA`/`APPDATA` on
    /// Windows, `HOME` on macOS. The original fix above set only
    /// `XDG_DATA_HOME`, which correctly isolates on Linux but has zero
    /// effect on Windows: there, the "isolated" child silently resolved
    /// `managed_toolchain_root()` to the real, shared, machine-wide root
    /// instead, so this test observed whatever rustfmt state that host
    /// already had provisioned (a real `GLOBAL_STATE_DEPENDENCY`, not this
    /// test's intended fresh-and-empty precondition). Also setting
    /// `LOCALAPPDATA` closes that gap on Windows; harmless to set on every
    /// other platform, since each OS's own branch reads only its own
    /// variable.
    const F4_FORMAT_GATE_CHILD_TRIGGER: &str = "CORULIX_F4_FORMAT_GATE_CHILD";

    /// §12/§24: `FORMAT_PROVIDER_UNAVAILABLE_FALSE_PASS_COUNT=0`. A session
    /// opened with no `HOST_ONLY` formatter directory at all must fail
    /// closed -- never a synthesized `Passed` record.
    #[tokio::test]
    async fn mcp_cannot_close_format_gate_when_provider_is_unavailable()
    -> wht_corulix_core::CorulixResult<()> {
        if std::env::var(F4_FORMAT_GATE_CHILD_TRIGGER).ok().as_deref() != Some("1") {
            // Parent: spawn the isolated child (see module doc above for why).
            let isolated_xdg_data_home = temp_root("format-gate-isolated-xdg-data-home");
            let exe = std::env::current_exe()
                .map_err(|error| wht_corulix_core::CorulixError::InvalidInput(error.to_string()))?;
            let output = tokio::process::Command::new(&exe)
                .args([
                    "--exact",
                    "tests::mcp_cannot_close_format_gate_when_provider_is_unavailable",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(F4_FORMAT_GATE_CHILD_TRIGGER, "1")
                .env("XDG_DATA_HOME", &isolated_xdg_data_home)
                .env("LOCALAPPDATA", &isolated_xdg_data_home)
                .output()
                .await
                .map_err(|error| wht_corulix_core::CorulixError::InvalidInput(error.to_string()))?;
            let _ = fs::remove_dir_all(&isolated_xdg_data_home);
            assert!(
                output.status.success(),
                "isolated child run of mcp_cannot_close_format_gate_when_provider_is_unavailable \
                 failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }

        // Child: `XDG_DATA_HOME` above resolves `managed_toolchain_root()` to
        // a fresh, empty isolated directory for this process -- never the
        // real, shared one.
        let root_dir = temp_root("format-gate-provider-unavailable");
        let _ = fs::create_dir_all(root_dir.join("src"));
        let _ = fs::write(
            root_dir.join("Cargo.toml"),
            "[package]\nname = \"corulix_f4_mcp_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        let _ = fs::write(root_dir.join("src/main.rs"), RUST_FIXTURE_UNFORMATTED);
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        // No `HOST_ONLY` directory names any real `rustfmt`, and
        // `managed_provisioning_policy` is explicitly `Deny` so this test
        // never touches the `CORULIX_MANAGED` path either -- `HostConfig::default()`
        // alone is no longer sufficient for that (Installation-Contract-V1):
        // its `Inherit` policy defers to `managed_toolchain_root()`'s
        // persisted install profile, which is no longer unconditionally
        // "nothing is provisioned" once `corulix` has ever bootstrapped for
        // real against this process's resolved root. `Deny` gates *fresh*
        // acquisition only -- `wht_corulix_formatter::managed::resolve_formatter`
        // tries an already-owned managed rustfmt unconditionally, before any
        // policy check -- but this process's `XDG_DATA_HOME` (set by the
        // parent above) resolves to a guaranteed-empty isolated root, so
        // nothing can already be owned there.
        let engine = Arc::new(CorulixEngine::open_with_host_config(
            context,
            false,
            wht_corulix_engine::HostConfig {
                managed_provisioning_policy: wht_corulix_engine::ManagedProvisioningPolicy::Deny,
                ..wht_corulix_engine::HostConfig::default()
            },
        ));
        let identity = WorkspaceIdentity::from_opaque_token(
            "wsid-f4-mcp-format-gate-provider-unavailable".to_string(),
        )?;
        let server = CorulixMcpServer::new(engine, identity)?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::SourceModify,
                language: Some(wht_corulix_core::LanguageId::Rust),
                root_selector: None,
                scope_prefixes: vec!["src".to_string()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let replace = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "src/main.rs".to_string(),
                edit: EditRequestParams::Replace {
                    expected_precondition_hash_hex: wht_corulix_core::ContentHash::compute_sha256(
                        RUST_FIXTURE_UNFORMATTED.as_bytes(),
                    )
                    .digest_hex,
                    content_utf8: RUST_FIXTURE_CANONICAL.to_string(),
                },
            }))
            .await;
        assert_eq!(replace.is_error, Some(false));

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            validate.is_error,
            Some(true),
            "expected a fail-closed Unavailable outcome, got {}",
            structured(&validate)
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams { session_id }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("denied"),
            "FORMAT_PROVIDER_UNAVAILABLE_FALSE_PASS_COUNT=0: got {}",
            structured(&complete)
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// §20/§21/§24: `STALE_FORMAT_EVIDENCE_CAN_AUTHORIZE_COMPLETION=NO`.
    /// Real `gate.format` `Passed` Evidence, then a second real mutation in
    /// the same session, then completion attempted on only the now-`Stale`
    /// record -- must still be denied.
    #[tokio::test]
    async fn mcp_stale_format_evidence_after_second_mutation_cannot_authorize_completion()
    -> wht_corulix_core::CorulixResult<()> {
        if !real_rust_formatter_available() {
            eprintln!("F4_MCP_FORMAT_GATE_E2E=BLOCKED_PROVIDER_UNAVAILABLE");
            return Ok(());
        }
        let (server, root_dir) = rust_server("format-gate-stale", RUST_FIXTURE_UNFORMATTED)?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::SourceModify,
                language: Some(wht_corulix_core::LanguageId::Rust),
                root_selector: None,
                scope_prefixes: vec!["src".to_string()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let first_replace = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "src/main.rs".to_string(),
                edit: EditRequestParams::Replace {
                    expected_precondition_hash_hex: wht_corulix_core::ContentHash::compute_sha256(
                        RUST_FIXTURE_UNFORMATTED.as_bytes(),
                    )
                    .digest_hex,
                    content_utf8: RUST_FIXTURE_CANONICAL.to_string(),
                },
            }))
            .await;
        assert_eq!(first_replace.is_error, Some(false));

        let first_validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert_eq!(
            structured(&first_validate)["outcome"]["clean"],
            serde_json::json!(true),
            "expected the first, real gate.format Passed record, got {}",
            structured(&first_validate)
        );

        // A second real edit re-dirties the file and invalidates the
        // just-recorded `Passed` `gate.format` Evidence to `Stale`
        // (`CONTENT_DEPENDENT_GATES`).
        let second_replace = server
            .submit_edit(Parameters(SubmitEditParams {
                session_id: session_id.clone(),
                relative_path: "src/main.rs".to_string(),
                edit: EditRequestParams::Replace {
                    expected_precondition_hash_hex: wht_corulix_core::ContentHash::compute_sha256(
                        RUST_FIXTURE_CANONICAL.as_bytes(),
                    )
                    .digest_hex,
                    content_utf8: RUST_FIXTURE_UNFORMATTED.to_string(),
                },
            }))
            .await;
        assert_eq!(second_replace.is_error, Some(false));

        // No fresh `validate_change` call after the second edit: only the
        // now-`Stale` first record exists for `gate.format`.
        let complete = server
            .complete_change(Parameters(CompleteChangeParams { session_id }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("denied"),
            "STALE_FORMAT_EVIDENCE_CAN_AUTHORIZE_COMPLETION=NO: got {}",
            structured(&complete)
        );
        assert_eq!(
            structured(&complete)["reason_code"],
            serde_json::json!("REQUIRED_GATE_EVIDENCE_STALE"),
            "expected the precise staleness reason, got {}",
            structured(&complete)
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// §17/§18/§42: `SOURCE_REFACTOR_COMMITTED_UNCOMPLETABLE_STATE=IMPOSSIBLE`.
    /// `SemanticRename`/`SourceRefactor` require `gate.discovery`/
    /// `gate.semantic_confirm`, for which no production code anywhere in
    /// this workspace ever records Evidence (confirmed by a full recursive
    /// search of every non-test source file) -- `begin_change` rejects both
    /// outright, before any `ChangeSession` exists and before any mutation
    /// is possible, rather than allowing a commit that could never reach
    /// `COMPLETED`.
    #[tokio::test]
    async fn mcp_semantic_rename_and_source_refactor_rejected_before_mutation()
    -> wht_corulix_core::CorulixResult<()> {
        let (server, root_dir) = rust_server("unsupported-intents", RUST_FIXTURE_CANONICAL)?;

        for intent in [
            OperationIntent::SemanticRename,
            OperationIntent::SourceRefactor,
        ] {
            let begin = server
                .begin_change(Parameters(BeginChangeParams {
                    intent,
                    language: Some(wht_corulix_core::LanguageId::Rust),
                    root_selector: None,
                    scope_prefixes: vec!["src".to_string()],
                }))
                .await;
            assert_eq!(
                structured(&begin)["outcome"],
                serde_json::json!("denied"),
                "{intent:?}: expected begin_change to reject before any mutation, got {}",
                structured(&begin)
            );
            assert_eq!(
                structured(&begin)["reason_code"],
                serde_json::json!("OPERATION_NOT_SUPPORTED"),
                "{intent:?}: expected the precise F4 reason code, got {}",
                structured(&begin)
            );
        }

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    // =================================================================
    // Rust production-routing closure -- clippy/cargo test through the
    // real, unchanged 14-tool MCP surface. Mirrors the Go section above
    // exactly: every call here goes through `begin_change`/`validate_change`,
    // never `wht_corulix_engine::diagnostics::run_clippy`/
    // `wht_corulix_engine::testing::run_cargo_test` directly, so this proves
    // the real production route this closure wires, not merely that the
    // underlying providers work (already proven by their own crate-level
    // unit tests and the pre-existing `real_p11_r1_trust_enforcement_e2e.rs`/
    // `real_p12_trusted_test_execution_e2e.rs` standalone E2E files).
    // =================================================================

    /// Provisions the real `rust-semantic-runtime` (cargo/rustc/clippy) and
    /// `gnu-link-runtime` (cargo test's own managed linker, see
    /// `wht_corulix_engine::testing`'s own doc comment) product manifests
    /// into the real, production, host-wide `managed_toolchain_root()` --
    /// real network, real product identity, no test-only manifest.
    ///
    /// Unlike this crate's `format_preview`/`semantic` isolated E2E suite
    /// (`tests/real_p13_mcp_managed_provider_isolated_e2e.rs`), this
    /// deliberately does **not** redirect `XDG_DATA_HOME` into an isolated
    /// root, and runs in-process against a directly-constructed, explicitly
    /// trusted `CorulixEngine` rather than the real spawned binary -- this
    /// test predates the F1 fix (`corulix mcp stdio --host-config <FILE>`,
    /// `wht_corulix_cli::main::run_mcp_stdio`), which now *can* grant
    /// `TrustedWorkspaceExecution` for real through the compiled binary (see
    /// `wht_corulix_cli`'s own `real_f1_host_config_e2e.rs` for that live
    /// proof), but this test's own concern is Rust production-routing
    /// (clippy/`cargo test` through `validate_change`), not host-config
    /// plumbing, so it keeps its existing in-process `open_with_trust`
    /// construction unchanged -- exactly like this module's own pre-existing
    /// Go `validate_change` E2E tests above -- which always resolves the
    /// one real, production `managed_toolchain_root()` with no override
    /// mechanism available. `false` (never panics) on genuine failure, so an
    /// environment without real internet access reports a disclosed skip
    /// rather than a false failure.
    async fn ensure_real_production_rust_toolchain_provisioned() -> bool {
        use wht_corulix_tooling::managed_runtimes::{
            GNU_LINK_RUNTIME_LINUX_X64, RUST_SEMANTIC_RUNTIME_LINUX_X64,
        };
        use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

        let Ok(root) = wht_corulix_tooling::provisioning::managed_toolchain_root() else {
            return false;
        };
        let (runtime_state, _) =
            provisioning::resolve_managed_component(&root, &RUST_SEMANTIC_RUNTIME_LINUX_X64);
        if runtime_state != ManagedComponentState::Available
            && provisioning::provision(&root, &RUST_SEMANTIC_RUNTIME_LINUX_X64)
                .await
                .is_err()
        {
            return false;
        }
        let (linker_state, _) =
            provisioning::resolve_managed_component(&root, &GNU_LINK_RUNTIME_LINUX_X64);
        if linker_state != ManagedComponentState::Available
            && provisioning::provision(&root, &GNU_LINK_RUNTIME_LINUX_X64)
                .await
                .is_err()
        {
            return false;
        }
        true
    }

    /// A real, disposable, dependency-free Rust crate plus a trusted MCP
    /// server (`CorulixEngine::open_with_trust(_, true)`) -- Rust validators
    /// are `CORULIX_MANAGED` (never `HOST_ONLY`), so no `HostConfig`
    /// provider-path grant is needed, unlike `go_server`/`go_validate_server`.
    fn rust_validate_server(
        label: &str,
        lib_rs: &str,
    ) -> wht_corulix_core::CorulixResult<(CorulixMcpServer, PathBuf)> {
        let root_dir = temp_root(label);
        let _ = fs::create_dir_all(root_dir.join("src"));
        let _ = fs::write(
            root_dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"corulix_rust_closure_fixture_{label}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
            ),
        );
        let _ = fs::write(root_dir.join("src/lib.rs"), lib_rs);

        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open_with_trust(context, true));
        let identity = WorkspaceIdentity::from_opaque_token(format!("wsid-rust-closure-{label}"))?;
        Ok((CorulixMcpServer::new(engine, identity)?, root_dir))
    }

    /// Real, full-governance E2E (§21 of this closure's mandate):
    /// `begin_change(ValidateChange, Rust)` -> `validate_change` -> real
    /// `cargo check` + real `cargo clippy` (a genuine `clippy::len_zero`
    /// finding, folded into `gate.diagnostics`) + real `cargo test` (one
    /// passing test, closing the distinct `gate.tests`) -> `change_status`
    /// -> `complete_change`. Never calls `run_clippy`/`run_cargo_test`
    /// directly.
    #[tokio::test]
    async fn real_rust_validate_change_clippy_and_test_e2e() -> wht_corulix_core::CorulixResult<()>
    {
        if !ensure_real_production_rust_toolchain_provisioned().await {
            eprintln!(
                "RUST_PRODUCTION_CLIPPY_FINDING_E2E=BLOCKED_PROVISIONING_FAILED \
                 (no real internet access in this environment?)"
            );
            return Ok(());
        }
        let (server, root_dir) = rust_validate_server(
            "clippy-and-test",
            "pub fn has_no_items(items: &[i32]) -> bool {\n    // Deliberate clippy::len_zero finding: `items.is_empty()` is the idiomatic form\n    // (clippy specifically exempts a function literally named `is_empty` from this\n    // lint, so this fixture deliberately uses a different name to keep triggering it).\n    items.len() == 0\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn detects_empty() {\n        assert!(has_no_items(&[]));\n        assert!(!has_no_items(&[1]));\n    }\n}\n",
        )?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::ValidateChange,
                language: None,
                root_selector: None,
                scope_prefixes: Vec::new(),
            }))
            .await;
        assert_eq!(
            structured(&begin)["outcome"],
            serde_json::json!("opened"),
            "expected a Rust ValidateChange session to open, got {}",
            structured(&begin)
        );
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        let outcome = structured(&validate);
        if outcome["outcome"]["status"] == serde_json::json!("unavailable") {
            eprintln!("RUST_PRODUCTION_CLIPPY_FINDING_E2E=BLOCKED_PROVIDER_UNAVAILABLE: {outcome}");
            let _ = fs::remove_dir_all(&root_dir);
            return Ok(());
        }
        assert_eq!(
            validate.is_error,
            Some(false),
            "expected a real, successful Rust validate_change call, got {outcome}"
        );
        let outcome = &outcome["outcome"];
        assert_eq!(
            outcome["status"],
            serde_json::json!("executed"),
            "expected the real Rust dispatcher's outcome, got {outcome}"
        );
        assert_eq!(
            outcome["clippy"]["ran"],
            serde_json::json!(true),
            "expected real clippy to have run through validate_change, got {outcome}"
        );
        assert!(
            outcome["clippy"]["finding_count"].as_u64().unwrap_or(0) > 0,
            "expected a real clippy::len_zero finding to reach Evidence, got {outcome}"
        );
        assert_eq!(
            outcome["test"]["ran"],
            serde_json::json!(true),
            "expected real cargo test to have run through validate_change, got {outcome}"
        );
        assert_eq!(
            outcome["test"]["clean"],
            serde_json::json!(true),
            "expected the one real passing test to report clean, got {outcome}"
        );
        assert_eq!(
            outcome["test_evidence_recorded"],
            serde_json::json!(true),
            "expected real gate.tests Evidence to be recorded, got {outcome}"
        );

        let status = server
            .change_status(Parameters(ChangeStatusParams {
                session_id: session_id.clone(),
            }))
            .await;
        assert!(
            structured(&status)["status"]["completion_eligible"]
                .as_bool()
                .unwrap_or(false),
            "expected completion_eligible after a real clean cargo check, got {}",
            structured(&status)
        );

        let complete = server
            .complete_change(Parameters(CompleteChangeParams { session_id }))
            .await;
        assert_eq!(
            structured(&complete)["status"],
            serde_json::json!("completed"),
            "expected a real Rust ValidateChange session to complete, got {}",
            structured(&complete)
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// M09-P7R shared fixture: the same deliberate `clippy::len_zero` +
    /// one-passing-test content as [`real_rust_validate_change_clippy_and_test_e2e`],
    /// reused by the root-swap closure tests below so their "did the real,
    /// original fixture actually run" assertions have a real, non-trivial
    /// signature to check for.
    const ROOT_SWAP_FIXTURE_LIB_RS: &str = "pub fn has_no_items(items: &[i32]) -> bool {\n    // Deliberate clippy::len_zero finding: `items.is_empty()` is the idiomatic form.\n    items.len() == 0\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn detects_empty() {\n        assert!(has_no_items(&[]));\n        assert!(!has_no_items(&[1]));\n    }\n}\n";

    /// A real, trusted MCP server whose workspace root is an EMPTY directory
    /// -- no `Cargo.toml`, no source at all. Establishes, independently of
    /// any root-swap, that running the real Rust validators against a
    /// directory with no manifest produces a distinguishable, non-`executed`
    /// outcome -- the premise the root-swap tests below rely on to prove
    /// impostor execution did NOT happen (a redirected execution would hit
    /// this exact same "no manifest" condition instead of the real fixture's
    /// signature).
    fn empty_rust_validate_server(
        label: &str,
    ) -> wht_corulix_core::CorulixResult<(CorulixMcpServer, PathBuf)> {
        let root_dir = temp_root(label);
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open_with_trust(context, true));
        let identity = WorkspaceIdentity::from_opaque_token(format!("wsid-{label}"))?;
        Ok((CorulixMcpServer::new(engine, identity)?, root_dir))
    }

    /// M09-P7R §9 sanity control: proves the object-identity oracle the
    /// root-swap tests below rely on is real, not vacuous -- a workspace
    /// root with no `Cargo.toml` at all must NOT report `validate_change`'s
    /// real "executed" status with real clippy/test findings. If this
    /// assertion itself failed, the root-swap tests' "must be `executed`
    /// with real findings" assertions would prove nothing.
    #[tokio::test]
    async fn real_rust_validate_change_reports_unavailable_for_missing_manifest()
    -> wht_corulix_core::CorulixResult<()> {
        if !ensure_real_production_rust_toolchain_provisioned().await {
            eprintln!(
                "RUST_PRODUCTION_MISSING_MANIFEST_SANITY_E2E=BLOCKED_PROVISIONING_FAILED \
                 (no real internet access in this environment?)"
            );
            return Ok(());
        }
        let (server, root_dir) = empty_rust_validate_server("missing-manifest-sanity")?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::ValidateChange,
                language: None,
                root_selector: None,
                scope_prefixes: Vec::new(),
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let validate = server
            .validate_change(Parameters(ValidateChangeParams { session_id }))
            .await;
        let outcome = structured(&validate);
        assert_ne!(
            outcome["outcome"]["status"],
            serde_json::json!("executed"),
            "M09_P7R sanity check: a workspace root with no Cargo.toml must never report \
             validate_change's real 'executed' status -- got {outcome}"
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// M09-P7R §6 -- reproduces the historical root-replacement exploit
    /// through the ACTUAL PUBLIC `validate_change` call graph
    /// (`CorulixMcpServer::validate_change` -> `CorulixEngine::validate_change`
    /// -> `validate_change_rust` ->
    /// `diagnostics::run_clippy_with_workspace_root`/`testing::run_cargo_test_with_workspace_root`
    /// -> `wht_corulix_tooling::execute_with_workspace_root` ->
    /// `WorkspaceRoot::bind_process_cwd`), never by calling
    /// `execute_with_workspace_root` directly (§12). After `begin_change` has
    /// already captured this session's `WorkspaceRoot`, the workspace's real
    /// pathname is replaced with an ordinary, empty impostor directory (no
    /// `Cargo.toml`) before `validate_change` runs.
    ///
    /// Object-identity oracle (§9): per
    /// [`real_rust_validate_change_reports_unavailable_for_missing_manifest`],
    /// an empty directory can never produce a real "executed" outcome with
    /// real clippy/test findings -- so asserting exactly that signature here
    /// is only possible if execution reached the ORIGINAL pinned root
    /// object, never the impostor now sitting at the old pathname.
    #[tokio::test]
    async fn real_rust_validate_change_survives_normal_root_replacement()
    -> wht_corulix_core::CorulixResult<()> {
        if !ensure_real_production_rust_toolchain_provisioned().await {
            eprintln!(
                "RUST_PRODUCTION_NORMAL_ROOT_SWAP_E2E=BLOCKED_PROVISIONING_FAILED \
                 (no real internet access in this environment?)"
            );
            return Ok(());
        }
        let (server, root_dir) =
            rust_validate_server("normal-root-swap", ROOT_SWAP_FIXTURE_LIB_RS)?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::ValidateChange,
                language: None,
                root_selector: None,
                scope_prefixes: Vec::new(),
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        // Root-swap AFTER `begin_change` has already pinned this session's
        // `WorkspaceRoot`, BEFORE `validate_change` spawns anything --
        // exactly the historical exploit window.
        let moved_dir = temp_root("normal-root-swap-moved");
        let _ = fs::remove_dir_all(&moved_dir);
        fs::rename(&root_dir, &moved_dir).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::create_dir_all(&root_dir).map_err(|_| wht_corulix_core::CorulixError::Internal)?;

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        let outcome = structured(&validate);
        let outcome_body = &outcome["outcome"];
        assert_eq!(
            validate.is_error,
            Some(false),
            "M09_P7R_PUBLIC_NORMAL_ROOT_SWAP_IMPOSTOR_EXECUTION_COUNT must be 0 -- expected \
             a real, successful validate_change against the ORIGINAL pinned root, got {outcome}"
        );
        assert_eq!(
            outcome_body["status"],
            serde_json::json!("executed"),
            "the impostor has no Cargo.toml -- 'executed' is only reachable if cargo ran \
             against the ORIGINAL pinned object, not the impostor now sitting at the old \
             pathname; got {outcome_body}"
        );
        assert_eq!(outcome_body["clippy"]["ran"], serde_json::json!(true));
        assert!(
            outcome_body["clippy"]["finding_count"]
                .as_u64()
                .unwrap_or(0)
                > 0,
            "expected the real clippy::len_zero finding from the ORIGINAL fixture, \
             got {outcome_body}"
        );
        assert_eq!(outcome_body["test"]["ran"], serde_json::json!(true));
        assert_eq!(outcome_body["test"]["clean"], serde_json::json!(true));

        let _ = fs::remove_dir_all(&root_dir);
        let _ = fs::remove_dir_all(&moved_dir);
        Ok(())
    }

    /// As [`real_rust_validate_change_survives_normal_root_replacement`], but
    /// the impostor is a symlink to an entirely different, also-empty
    /// directory rather than an ordinary directory.
    ///
    /// M09-P9 fix: uses `std::os::unix::fs::symlink`, Unix-only -- was
    /// missing its own `#[cfg(unix)]` guard, so `cargo test`/`cargo check
    /// --tests` for a Windows target attempted (and failed) to compile it.
    /// Pre-existing gap, unrelated to P9's own Windows implementation and
    /// to this crate's Unix behavior (still compiles/runs identically
    /// there).
    #[cfg(unix)]
    #[tokio::test]
    async fn real_rust_validate_change_survives_symlink_root_replacement()
    -> wht_corulix_core::CorulixResult<()> {
        if !ensure_real_production_rust_toolchain_provisioned().await {
            eprintln!(
                "RUST_PRODUCTION_SYMLINK_ROOT_SWAP_E2E=BLOCKED_PROVISIONING_FAILED \
                 (no real internet access in this environment?)"
            );
            return Ok(());
        }
        let (server, root_dir) =
            rust_validate_server("symlink-root-swap", ROOT_SWAP_FIXTURE_LIB_RS)?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::ValidateChange,
                language: None,
                root_selector: None,
                scope_prefixes: Vec::new(),
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let outside_dir = temp_root("symlink-root-swap-outside");
        let moved_dir = temp_root("symlink-root-swap-moved");
        let _ = fs::remove_dir_all(&moved_dir);
        fs::rename(&root_dir, &moved_dir).map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        std::os::unix::fs::symlink(&outside_dir, &root_dir)
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        let outcome = structured(&validate);
        let outcome_body = &outcome["outcome"];
        assert_eq!(
            validate.is_error,
            Some(false),
            "M09_P7R_PUBLIC_SYMLINK_ROOT_SWAP_IMPOSTOR_EXECUTION_COUNT must be 0 -- got {outcome}"
        );
        assert_eq!(
            outcome_body["status"],
            serde_json::json!("executed"),
            "the symlink target has no Cargo.toml -- 'executed' is only reachable if cargo \
             ran against the ORIGINAL pinned object, never the symlink escape; got {outcome_body}"
        );
        assert_eq!(outcome_body["clippy"]["ran"], serde_json::json!(true));
        assert!(
            outcome_body["clippy"]["finding_count"]
                .as_u64()
                .unwrap_or(0)
                > 0
        );
        assert_eq!(outcome_body["test"]["ran"], serde_json::json!(true));
        assert_eq!(outcome_body["test"]["clean"], serde_json::json!(true));

        let _ = fs::remove_file(&root_dir);
        let _ = fs::remove_dir_all(&moved_dir);
        let _ = fs::remove_dir_all(&outside_dir);
        Ok(())
    }

    /// As [`real_rust_validate_change_survives_normal_root_replacement`], but
    /// the substitution replaces an ANCESTOR of the pinned root with an
    /// impostor tree that also has an (empty) subdirectory at the identical
    /// relative path.
    #[tokio::test]
    async fn real_rust_validate_change_survives_ancestor_root_replacement()
    -> wht_corulix_core::CorulixResult<()> {
        if !ensure_real_production_rust_toolchain_provisioned().await {
            eprintln!(
                "RUST_PRODUCTION_ANCESTOR_ROOT_SWAP_E2E=BLOCKED_PROVISIONING_FAILED \
                 (no real internet access in this environment?)"
            );
            return Ok(());
        }
        let ancestor_dir = temp_root("ancestor-root-swap");
        let root_dir = ancestor_dir.join("workspace");
        fs::create_dir_all(root_dir.join("src"))
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::write(
            root_dir.join("Cargo.toml"),
            "[package]\nname = \"corulix_rust_ancestor_swap_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::write(root_dir.join("src/lib.rs"), ROOT_SWAP_FIXTURE_LIB_RS)
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open_with_trust(context, true));
        let identity = WorkspaceIdentity::from_opaque_token("wsid-ancestor-root-swap".to_string())?;
        let server = CorulixMcpServer::new(engine, identity)?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::ValidateChange,
                language: None,
                root_selector: None,
                scope_prefixes: Vec::new(),
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        // Replace the ANCESTOR directory itself with an impostor tree that
        // also has a `workspace` subdirectory at the same relative path.
        let moved_ancestor = temp_root("ancestor-root-swap-moved");
        let _ = fs::remove_dir_all(&moved_ancestor);
        fs::rename(&ancestor_dir, &moved_ancestor)
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
        fs::create_dir_all(&root_dir).map_err(|_| wht_corulix_core::CorulixError::Internal)?;

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        let outcome = structured(&validate);
        let outcome_body = &outcome["outcome"];
        assert_eq!(
            validate.is_error,
            Some(false),
            "M09_P7R_PUBLIC_ANCESTOR_SWAP_IMPOSTOR_EXECUTION_COUNT must be 0 -- got {outcome}"
        );
        assert_eq!(
            outcome_body["status"],
            serde_json::json!("executed"),
            "the impostor ancestor's workspace subdirectory has no Cargo.toml -- 'executed' \
             is only reachable if cargo ran against the ORIGINAL pinned object; got {outcome_body}"
        );
        assert_eq!(outcome_body["clippy"]["ran"], serde_json::json!(true));
        assert!(
            outcome_body["clippy"]["finding_count"]
                .as_u64()
                .unwrap_or(0)
                > 0
        );
        assert_eq!(outcome_body["test"]["ran"], serde_json::json!(true));
        assert_eq!(outcome_body["test"]["clean"], serde_json::json!(true));

        let _ = fs::remove_dir_all(&ancestor_dir);
        let _ = fs::remove_dir_all(&moved_ancestor);
        Ok(())
    }

    /// §15's own real, negative E2E: a genuinely failing `#[test]`, driven
    /// only through `begin_change`/`validate_change`, must produce a real
    /// `gate.tests` failure -- never a silently "clean" result, and never
    /// blocking the distinct, already-passed `gate.diagnostics`.
    #[tokio::test]
    async fn real_rust_validate_change_cargo_test_failure_e2e()
    -> wht_corulix_core::CorulixResult<()> {
        if !ensure_real_production_rust_toolchain_provisioned().await {
            eprintln!(
                "RUST_PRODUCTION_CARGO_TEST_FAILURE_E2E=BLOCKED_PROVISIONING_FAILED \
                 (no real internet access in this environment?)"
            );
            return Ok(());
        }
        let (server, root_dir) = rust_validate_server(
            "test-failure",
            "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn deliberately_wrong() {\n        assert_eq!(add(2, 2), 5);\n    }\n}\n",
        )?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::ValidateChange,
                language: None,
                root_selector: None,
                scope_prefixes: Vec::new(),
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let validate = server
            .validate_change(Parameters(ValidateChangeParams {
                session_id: session_id.clone(),
            }))
            .await;
        let outcome = structured(&validate);
        if outcome["outcome"]["status"] == serde_json::json!("unavailable") {
            eprintln!(
                "RUST_PRODUCTION_CARGO_TEST_FAILURE_E2E=BLOCKED_PROVIDER_UNAVAILABLE: {outcome}"
            );
            let _ = fs::remove_dir_all(&root_dir);
            return Ok(());
        }
        let outcome = &outcome["outcome"];
        assert_eq!(
            outcome["status"],
            serde_json::json!("executed"),
            "expected a real, successful call whose gate.tests verdict is a real failure, got {outcome}"
        );
        assert_eq!(
            outcome["test"]["ran"],
            serde_json::json!(true),
            "expected real cargo test to have run, got {outcome}"
        );
        assert_eq!(
            outcome["test"]["clean"],
            serde_json::json!(false),
            "expected the one real failing test to report non-clean, got {outcome}"
        );
        assert!(
            outcome["test"]["finding_count"].as_u64().unwrap_or(0) > 0,
            "expected a real failed-test count, got {outcome}"
        );
        assert_eq!(
            outcome["test_evidence_recorded"],
            serde_json::json!(true),
            "a real (failing) gate.tests Evidence record must still be recorded, got {outcome}"
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// §16's own real E2E, Minimum Sufficient Tooling for Rust: a
    /// `DocumentationModify` session's `ToolPlan` never names
    /// `TypecheckBuild` as a requirement at all, so `validate_change` must
    /// report `NotRequired` -- zero processes spawned, driven only through
    /// `begin_change`/`validate_change`.
    #[tokio::test]
    async fn real_rust_validate_change_minimum_sufficient_tooling_e2e()
    -> wht_corulix_core::CorulixResult<()> {
        let (server, root_dir) = rust_validate_server("min-sufficient", "pub fn noop() {}\n")?;

        let begin = server
            .begin_change(Parameters(BeginChangeParams {
                intent: OperationIntent::DocumentationModify,
                language: None,
                root_selector: None,
                scope_prefixes: vec![String::new()],
            }))
            .await;
        let session_id = structured(&begin)["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let validate = server
            .validate_change(Parameters(ValidateChangeParams { session_id }))
            .await;
        assert_eq!(
            structured(&validate)["outcome"]["status"],
            serde_json::json!("not_required"),
            "expected NotRequired with zero processes spawned for a DocumentationModify \
             session, got {}",
            structured(&validate)
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    // =========================================================================
    // M09-P10 (owner-authorized): native Windows fail-closed proofs at the
    // real, public MCP surface -- `validate_change` (Section 23) and
    // `semantic` (Section 24). Both drive the exact same production route a
    // real `corulix mcp stdio` client would (`CorulixMcpServer::new` plus the
    // real `#[tool]` handler methods, never a hand-rolled shortcut), against
    // a real, trusted Rust workspace fixture -- mirroring
    // `rust_validate_server`'s own existing pattern. Zero-spawn evidence is
    // an independent `tasklist` process count of the real toolchain/provider
    // executables (`cargo.exe`, `cargo-clippy.exe`, `rustc.exe`,
    // `rust-analyzer.exe`), never the product's own claim.
    #[cfg(windows)]
    mod p10_windows_mcp_fail_closed {
        use super::*;

        struct CleanupGuard(PathBuf);
        impl Drop for CleanupGuard {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn process_count(image_name: &str) -> usize {
            let Ok(output) = std::process::Command::new("tasklist")
                .args(["/FI", &format!("IMAGENAME eq {image_name}"), "/NH"])
                .output()
            else {
                return 0;
            };
            let listing = String::from_utf8_lossy(&output.stdout);
            listing
                .lines()
                .filter(|line| {
                    line.to_ascii_lowercase()
                        .contains(&image_name.to_ascii_lowercase())
                })
                .count()
        }

        const RUST_TOOLCHAIN_IMAGES: &[&str] = &[
            "cargo.exe",
            "cargo-clippy.exe",
            "rustc.exe",
            "rust-analyzer.exe",
        ];

        fn rust_toolchain_process_counts() -> Vec<(&'static str, usize)> {
            RUST_TOOLCHAIN_IMAGES
                .iter()
                .map(|image| (*image, process_count(image)))
                .collect()
        }

        /// Section 23/41.A-B: the real, public MCP `validate_change` route
        /// for a trusted Rust workspace must fail closed on Windows --
        /// never a real `cargo check`/`cargo clippy`/`cargo test` process,
        /// and never silently downgraded to a pathname-cwd spawn. Also
        /// stands in for "real engine `validate_change`" (Section 41.A):
        /// `wht_corulix_mcp`'s own `validate_change` handler (Rule S: a
        /// thin adapter, zero logic of its own) calls straight through to
        /// `CorulixEngine::validate_change` with no intervening branching,
        /// so this single call proves both layers at once.
        #[tokio::test]
        async fn windows_public_validate_change_is_fail_closed_zero_spawn()
        -> wht_corulix_core::CorulixResult<()> {
            let (server, root_dir) = rust_validate_server(
                "p10-windows-validate-change",
                "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
            )?;
            let _guard = CleanupGuard(root_dir.clone());

            let pre = rust_toolchain_process_counts();

            let begin = server
                .begin_change(Parameters(BeginChangeParams {
                    intent: OperationIntent::ValidateChange,
                    language: None,
                    root_selector: None,
                    scope_prefixes: Vec::new(),
                }))
                .await;
            assert_eq!(
                begin.is_error,
                Some(false),
                "begin_change itself must succeed: {}",
                structured(&begin)
            );
            let session_id = structured(&begin)["session_id"]
                .as_str()
                .unwrap_or_default()
                .to_string();

            let validate = server
                .validate_change(Parameters(ValidateChangeParams { session_id }))
                .await;
            let outcome = structured(&validate);
            assert_eq!(
                outcome["outcome"]["status"],
                serde_json::json!("unavailable"),
                "M09_P10_WINDOWS_ENGINE_VALIDATE_CHANGE=FAIL_CLOSED: a real cargo check/clippy/ \
                 test must never actually execute on Windows for TRUSTED_WORKSPACE_EXECUTION, \
                 got {outcome}"
            );
            assert_eq!(
                outcome["outcome"]["reason_code"],
                serde_json::json!("REQUIRED_CAPABILITY_UNAVAILABLE"),
                "expected the SpawnFailed-mapped reason code, got {outcome}"
            );

            let post = rust_toolchain_process_counts();
            assert_eq!(
                post, pre,
                "M09_P10_WINDOWS_ENGINE_VALIDATE_CHANGE_PROCESS_SPAWN_COUNT must be 0 for every \
                 real Rust toolchain executable"
            );
            Ok(())
        }

        /// Section 24/41.C-D: the real, public MCP `semantic` route (which
        /// internally spawns a real `rust-analyzer` LSP session on a cache
        /// miss) must fail closed on Windows with zero `rust-analyzer.exe`
        /// spawns -- proves both "direct LspSession production creation"
        /// (Section 41.C: `semantic`'s only path to a session is
        /// `wht_corulix_lsp::LspSession::spawn`, Rule L) and the public MCP
        /// route (Section 41.D) in one real call.
        #[tokio::test]
        async fn windows_public_semantic_is_fail_closed_zero_spawn()
        -> wht_corulix_core::CorulixResult<()> {
            let root_dir = temp_root("p10-windows-semantic");
            let _guard = CleanupGuard(root_dir.clone());
            fs::write(
                root_dir.join("lib.rs"),
                "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
            )
            .map_err(|_| wht_corulix_core::CorulixError::Internal)?;
            let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
            let context = WorkspaceContext::single_root(root, "root".to_string());
            let engine = Arc::new(CorulixEngine::open_with_trust(context, true));
            let identity =
                WorkspaceIdentity::from_opaque_token("wsid-p10-windows-semantic".to_string())?;
            let server = CorulixMcpServer::new(engine, identity)?;

            let pre = process_count("rust-analyzer.exe");

            let result = server
                .semantic(Parameters(SemanticParams {
                    operation: wht_corulix_engine::semantic::SemanticOperation::Definition,
                    language: wht_corulix_core::LanguageId::Rust,
                    path: "lib.rs".to_string(),
                    line_zero_based: 0,
                    byte_column_zero_based: 0,
                    byte_offset: 0,
                    new_name: None,
                }))
                .await;
            let outcome = structured(&result);
            assert_eq!(
                result.is_error,
                Some(true),
                "M09_P10_WINDOWS_PUBLIC_SEMANTIC=FAIL_CLOSED: the semantic tool handler reports \
                 Unavailable as an error result by design, got {outcome}"
            );
            assert_eq!(
                outcome["status"],
                serde_json::json!("unavailable"),
                "expected Unavailable, never a real definition result, got {outcome}"
            );
            assert_eq!(
                outcome["reason_code"],
                serde_json::json!("REQUIRED_PROVIDER_UNAVAILABLE"),
                "expected the LspSession::spawn-refusal-mapped reason code, got {outcome}"
            );

            let post = process_count("rust-analyzer.exe");
            assert_eq!(
                post, pre,
                "M09_P10_WINDOWS_PUBLIC_SEMANTIC_LSP_SPAWN_COUNT must be 0"
            );
            Ok(())
        }

        /// Section 27/32/K: repeated calls against the same real MCP server
        /// remain stably fail-closed (no first-call-fails-then-unsafe-
        /// fallback), and leave zero orphan toolchain/provider processes --
        /// covers both `validate_change` and `semantic` together.
        #[tokio::test]
        async fn windows_repeated_public_validate_change_and_semantic_stay_fail_closed_with_zero_orphans()
        -> wht_corulix_core::CorulixResult<()> {
            let (server, root_dir) = rust_validate_server(
                "p10-windows-repeated",
                "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
            )?;
            let _guard = CleanupGuard(root_dir.clone());

            let pre = rust_toolchain_process_counts();

            for attempt in 0..3 {
                let begin = server
                    .begin_change(Parameters(BeginChangeParams {
                        intent: OperationIntent::ValidateChange,
                        language: None,
                        root_selector: None,
                        scope_prefixes: Vec::new(),
                    }))
                    .await;
                let session_id = structured(&begin)["session_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let validate = server
                    .validate_change(Parameters(ValidateChangeParams {
                        session_id: session_id.clone(),
                    }))
                    .await;
                assert_eq!(
                    structured(&validate)["outcome"]["status"],
                    serde_json::json!("unavailable"),
                    "attempt {attempt}: repeated validate_change calls must remain stably \
                     fail-closed, got {}",
                    structured(&validate)
                );
                let _ = server
                    .abort_change(Parameters(AbortChangeParams { session_id }))
                    .await;

                let semantic_result = server
                    .semantic(Parameters(SemanticParams {
                        operation: wht_corulix_engine::semantic::SemanticOperation::Definition,
                        language: wht_corulix_core::LanguageId::Rust,
                        path: "src/lib.rs".to_string(),
                        line_zero_based: 0,
                        byte_column_zero_based: 0,
                        byte_offset: 0,
                        new_name: None,
                    }))
                    .await;
                assert_eq!(
                    structured(&semantic_result)["status"],
                    serde_json::json!("unavailable"),
                    "attempt {attempt}: repeated semantic calls must remain stably fail-closed"
                );
            }

            let post = rust_toolchain_process_counts();
            assert_eq!(
                post, pre,
                "M09_P10_WINDOWS_FAIL_CLOSED_ORPHAN_PROCESS_COUNT must be 0 after repeated calls"
            );
            Ok(())
        }
    }
}
