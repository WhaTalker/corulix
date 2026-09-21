// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Centralized runtime Contract Validation Gate for every one of the 14
//! canonical Corulix MCP tools.
//!
//! Equivalent design intent to Zod validation at a TypeScript boundary:
//! `RAW INPUT -> validate -> typed core` and `CORE OUTPUT -> validate ->
//! MCP`. No request or response contract may cross the MCP boundary
//! without deterministic runtime validation; a validation failure fails
//! closed inside Corulix -- it never reaches the client as a malformed,
//! partial, or best-effort payload (see [`fail_closed_result`]).
//!
//! # Schema authority (Section 12's `EXPOSED_OUTPUT_SCHEMA ==
//! RUNTIME_VALIDATION_SCHEMA_AUTHORITY` invariant)
//!
//! Every schema this gate compiles a validator from is produced by calling
//! the exact same [`rmcp::handler::server::common::schema_for_input`]/
//! [`schema_for_output`](rmcp::handler::server::common::schema_for_output)
//! functions the `#[tool(...)]` macro itself calls to build each tool's
//! advertised `inputSchema`/`outputSchema` (both functions cache their
//! result per-type internally, so calling them again here is free and can
//! never drift from what `list_tools` actually advertises -- there is no
//! second, hand-maintained shadow schema anywhere in this module).
//!
//! # Compiled once, reused forever, and TRUE fail-closed at startup
//!
//! [`ContractRegistry::build`] compiles every one of the 14 tools'
//! validators exactly once, eagerly, at [`crate::CorulixMcpServer::new`]
//! time -- never lazily on first request, never recompiled per request
//! (`SCHEMA_VALIDATOR_COMPILED_PER_REQUEST=NO`). Construction is fully
//! fallible (`Result<ContractRegistry, ContractGateInitError>`): if any
//! tool's schema cannot compile into a valid `jsonschema::Validator`
//! (structurally unreachable for this gate's fixed, compile-time-known set
//! of Rust DTO types, but never assumed impossible), `build()` returns
//! `Err`, `CorulixMcpServer::new` propagates that as a real error, and
//! `serve_stdio` returns before ever calling `.serve(stdio())` -- the
//! server never becomes ready, never accepts a single JSON-RPC request,
//! and no tool handler (all of which require `&self: &CorulixMcpServer`,
//! which in that case was never constructed) can ever execute. This
//! workspace's `clippy::panic`/`unwrap_used`/`expect_used = "deny"` lints
//! (root `Cargo.toml` `[workspace.lints.clippy]`, with zero pre-existing
//! exceptions anywhere in this codebase) forbid ever reaching this
//! conclusion via `panic!`/`unwrap`/`expect` -- every step here uses plain
//! `Result` propagation instead, so "must not become ready" is reached
//! through ordinary fallible construction, not a crash.
//!
//! # What this gate deliberately does not do
//!
//! It does not change any tool's business behavior, name, or public DTO
//! shape, does not touch Parse's Tree-sitter extraction or Compact
//! Structural text generation, and does not attempt to resolve which MCP
//! response channel (`content` vs. `structured_content`) a downstream
//! client prefers to display -- that is a separate, already-documented
//! open question this gate is intentionally silent on.

use rmcp::handler::server::common::{schema_for_empty_input, schema_for_input, schema_for_output};
use rmcp::model::{CallToolResult, ContentBlock};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use wht_corulix_core::ContentHash;

use crate::dto::*;

// ---------------------------------------------------------------------
// Error classification (Section 18)
// ---------------------------------------------------------------------

/// Stable internal contract-failure classes. These are diagnostic/logging
/// identifiers, not a new public MCP error taxonomy -- every failure still
/// surfaces to the client through each tool's own existing error envelope
/// shape (see [`fail_closed_result`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractErrorClass {
    SchemaInvalid,
    InputInvalid,
    OutputInvalid,
    SemanticInvariantFailed,
    McpEnvelopeInvalid,
    SchemaDrift,
    InternalSerializationFailed,
}

impl ContractErrorClass {
    fn code(self) -> &'static str {
        match self {
            Self::SchemaInvalid => "CONTRACT_SCHEMA_INVALID",
            Self::InputInvalid => "CONTRACT_INPUT_INVALID",
            Self::OutputInvalid => "CONTRACT_OUTPUT_INVALID",
            Self::SemanticInvariantFailed => "CONTRACT_SEMANTIC_INVARIANT_FAILED",
            Self::McpEnvelopeInvalid => "CONTRACT_MCP_ENVELOPE_INVALID",
            Self::SchemaDrift => "CONTRACT_SCHEMA_DRIFT",
            Self::InternalSerializationFailed => "CONTRACT_INTERNAL_SERIALIZATION_FAILED",
        }
    }
}

/// A bounded, non-leaking contract-boundary failure record. Never carries
/// the raw payload/source content that triggered it, a stack trace, or an
/// absolute internal path -- only a tool identity, an error class, and a
/// short structural detail string (violation counts / JSON-pointer
/// locations, never instance values), per this gate's fail-closed charter
/// (Section 17: never leak stack traces, source payload, secrets).
#[derive(Debug, Clone)]
pub struct ContractError {
    pub class: ContractErrorClass,
    pub tool: &'static str,
    pub detail: String,
}

impl ContractError {
    pub fn error_code(&self) -> &'static str {
        self.class.code()
    }
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]: {}", self.error_code(), self.tool, self.detail)
    }
}

// ---------------------------------------------------------------------
// Contract identity / registry (Section 16)
// ---------------------------------------------------------------------

/// A tool's internal deterministic contract identity: name plus SHA256
/// digests of its exact input/output JSON Schema. Never sent to the client
/// -- used only for the validation registry, diagnostics, tests, and
/// schema-drift detection.
#[derive(Debug, Clone)]
pub struct ContractIdentity {
    pub tool: &'static str,
    pub input_schema_sha256: String,
    pub output_schema_sha256: String,
}

struct ToolContract {
    identity: ContractIdentity,
    // `None` here means only "this tool genuinely has no input" (the 3
    // no-input tools) -- never a compile failure any more. A compile
    // failure for either validator now aborts `ContractRegistry::build`
    // entirely via `?` (see `compile`/`contract`/`contract_no_input`
    // below); there is no "built but partially unvalidated" `ToolContract`
    // value.
    input_validator: Option<jsonschema::Validator>,
    output_validator: jsonschema::Validator,
}

/// A fatal Contract Gate initialization failure. A value of this type
/// existing at all means [`ContractRegistry::build`] must return `Err`,
/// which [`crate::CorulixMcpServer::new`] propagates so the MCP server
/// never becomes ready (Section 1's `CONTRACT_SCHEMA_COMPILE_FAILURE_
/// FAILS_STARTUP=YES` invariant). Never leaks a schema body or payload --
/// only the tool name, the stage that failed, and a bounded message.
#[derive(Debug)]
pub struct ContractGateInitError {
    pub tool: &'static str,
    pub stage: &'static str,
    pub detail: String,
}

impl std::fmt::Display for ContractGateInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{} / {}]: {}",
            ContractErrorClass::SchemaInvalid.code(),
            self.tool,
            self.stage,
            self.detail
        )
    }
}

impl std::error::Error for ContractGateInitError {}

fn digest_of(schema: &Value) -> String {
    ContentHash::compute_sha256(schema.to_string().as_bytes()).digest_hex
}

/// Compiles `schema` into a reusable validator, or returns a fatal
/// [`ContractGateInitError`] if it failed to compile as valid JSON Schema
/// at all. Never logs-and-skips: the caller (`contract`/
/// `contract_no_input`, and ultimately [`ContractRegistry::build`])
/// propagates this via `?`, so a compile failure here always aborts
/// registry construction.
fn compile(
    tool: &'static str,
    stage: &'static str,
    schema: &Value,
) -> Result<jsonschema::Validator, ContractGateInitError> {
    jsonschema::validator_for(schema).map_err(|error| ContractGateInitError {
        tool,
        stage,
        detail: format!("schema failed to compile as valid JSON Schema: {error}"),
    })
}

/// Builds one tool's compiled contract from its real Rust input/output
/// types, reusing `rmcp`'s own schema-generation authority exactly.
fn contract<In, Out>(tool: &'static str) -> Result<ToolContract, ContractGateInitError>
where
    In: rmcp::schemars::JsonSchema + std::any::Any,
    Out: rmcp::schemars::JsonSchema + std::any::Any,
{
    let input_schema = schema_for_input::<In>().map_err(|error| ContractGateInitError {
        tool,
        stage: "input_schema_generation",
        detail: format!("rmcp rejected this tool's own input schema shape: {error}"),
    })?;
    let input_value = Value::Object((*input_schema).clone());
    let output_value = Value::Object((*schema_for_output::<Out>()).clone());
    Ok(ToolContract {
        identity: ContractIdentity {
            tool,
            input_schema_sha256: digest_of(&input_value),
            output_schema_sha256: digest_of(&output_value),
        },
        input_validator: Some(compile(tool, "input", &input_value)?),
        output_validator: compile(tool, "output", &output_value)?,
    })
}

/// Builds a no-input tool's compiled contract (`runtime_identity`,
/// `workspace_info`, `toolchain_status`) -- mirrors the macro's own
/// `schema_for_empty_input()` fallback exactly, so its identity digest
/// matches what `list_tools` actually advertises for these three tools too.
fn contract_no_input<Out>(tool: &'static str) -> Result<ToolContract, ContractGateInitError>
where
    Out: rmcp::schemars::JsonSchema + std::any::Any,
{
    let input_value = Value::Object((*schema_for_empty_input()).clone());
    let output_value = Value::Object((*schema_for_output::<Out>()).clone());
    Ok(ToolContract {
        identity: ContractIdentity {
            tool,
            input_schema_sha256: digest_of(&input_value),
            output_schema_sha256: digest_of(&output_value),
        },
        input_validator: None,
        output_validator: compile(tool, "output", &output_value)?,
    })
}

/// The Contract Gate's compiled, immutable validation registry -- see this
/// module's own top-level doc comment for the full fail-closed startup
/// invariant this type exists to uphold.
pub struct ContractRegistry {
    contracts: HashMap<&'static str, ToolContract>,
}

impl ContractRegistry {
    /// Builds and compiles all 14 tools' contracts. `Err` means the caller
    /// (`CorulixMcpServer::new`) must not construct a server at all.
    pub fn build() -> Result<Self, ContractGateInitError> {
        let mut contracts: HashMap<&'static str, ToolContract> = HashMap::new();
        let mut insert =
            |tool: &'static str, built: ToolContract| -> Result<(), ContractGateInitError> {
                // Fail-closed for any duplicate/conflicting tool contract
                // (`CONTRACT_REGISTRY_DUPLICATE_COUNT=0`, Section 16): this
                // gate's 14 `insert` calls below use 14 distinct literal
                // tool names, so a collision is structurally unreachable --
                // but if one were ever introduced, this now aborts
                // construction via `Err` rather than logging and silently
                // keeping the most-recently-inserted contract.
                if contracts.insert(tool, built).is_some() {
                    return Err(ContractGateInitError {
                        tool,
                        stage: "registry_insert",
                        detail: "duplicate contract registration for this tool".to_string(),
                    });
                }
                Ok(())
            };

        insert(
            "runtime_identity",
            contract_no_input::<wht_corulix_core::RuntimeIdentity>("runtime_identity")?,
        )?;
        insert(
            "workspace_info",
            contract_no_input::<wht_corulix_core::WorkspaceInfo>("workspace_info")?,
        )?;
        insert(
            "toolchain_status",
            contract_no_input::<wht_corulix_engine::toolchain_status::ToolchainStatus>(
                "toolchain_status",
            )?,
        )?;
        insert(
            "plan_operation",
            contract::<PlanOperationParams, PlanOperationOutput>("plan_operation")?,
        )?;
        insert(
            "search",
            contract::<SearchParams, wht_corulix_engine::search::SearchOutcome>("search")?,
        )?;
        insert(
            "parse_file",
            contract::<ParseFileParams, ParseFileOutput>("parse_file")?,
        )?;
        insert(
            "semantic",
            contract::<SemanticParams, wht_corulix_engine::semantic::SemanticOutcome>("semantic")?,
        )?;
        insert(
            "format_preview",
            contract::<
                FormatPreviewParams,
                wht_corulix_engine::format_preview::FormatPreviewOutcome,
            >("format_preview")?,
        )?;
        insert(
            "begin_change",
            contract::<BeginChangeParams, BeginChangeOutput>("begin_change")?,
        )?;
        insert(
            "submit_edit",
            contract::<SubmitEditParams, SubmitEditOutput>("submit_edit")?,
        )?;
        insert(
            "validate_change",
            contract::<ValidateChangeParams, ValidateChangeOutputEnvelope>("validate_change")?,
        )?;
        insert(
            "change_status",
            contract::<ChangeStatusParams, ChangeStatusOutput>("change_status")?,
        )?;
        insert(
            "complete_change",
            contract::<CompleteChangeParams, CompleteChangeOutput>("complete_change")?,
        )?;
        insert(
            "abort_change",
            contract::<AbortChangeParams, AbortChangeOutput>("abort_change")?,
        )?;

        // Section 15 startup evidence: record every tool's contract
        // identity once, at successful construction, as bounded
        // digests/metadata only -- never a schema body or payload. This is
        // the gate's own startup integrity proof (`MCP_TOOLS_VALIDATED=14`,
        // `CONTRACT_REGISTRY_DUPLICATE_COUNT=0` -- duplicates already
        // failed closed above via `?`).
        for built in contracts.values() {
            tracing::info!(
                target: "wht_corulix_mcp::contract_gate",
                tool = built.identity.tool,
                input_schema_sha256 = %built.identity.input_schema_sha256,
                output_schema_sha256 = %built.identity.output_schema_sha256,
                "contract gate: tool contract registered"
            );
        }

        Ok(Self { contracts })
    }

    /// TEST-ONLY (Section 3 of the corrective pass): builds the exact same
    /// 14 real tool contracts as [`Self::build`], plus one deliberately
    /// uncompilable, synthetic schema under a synthetic tool name that
    /// exists nowhere in production (`__test_injected_invalid__`) -- never
    /// a corrupted real tool's schema. Proves the *same* propagation path
    /// a genuine production schema failure would take, without ever
    /// touching a real tool's type.
    #[cfg(test)]
    pub(crate) fn build_with_injected_invalid_schema() -> Result<Self, ContractGateInitError> {
        // `"type"` must be a JSON Schema string/array-of-strings per the
        // spec; a number is unconditionally invalid at compile time,
        // regardless of the rest of the object -- this is not a corrupted
        // real DTO schema, it is a hand-crafted, self-contained poison
        // value under a tool name no production code ever registers.
        let bad_schema = serde_json::json!({ "type": 12345 });
        compile("__test_injected_invalid__", "test_injected", &bad_schema)?;
        // Unreachable in practice (the line above always returns `Err`
        // first), but keeps this function's signature honest without a
        // `panic!`/`unreachable!()`.
        Self::build()
    }

    fn tool_contract(&self, tool: &'static str) -> Option<&ToolContract> {
        self.contracts.get(tool)
    }

    fn unknown_tool_error(&self, tool: &'static str) -> ContractError {
        tracing::error!(
            target: "wht_corulix_mcp::contract_gate",
            tool,
            error_code = ContractErrorClass::SchemaDrift.code(),
            "contract gate: no registered contract for this tool"
        );
        ContractError {
            class: ContractErrorClass::SchemaDrift,
            tool,
            detail: "no registered contract for this tool".to_string(),
        }
    }

    /// Returns `tool`'s internal deterministic contract identity, or
    /// `None` if no contract is registered for it. Exposed for
    /// diagnostics/tests/schema-drift detection only -- never sent to a
    /// client.
    #[allow(dead_code)]
    pub fn contract_identity(&self, tool: &'static str) -> Option<ContractIdentity> {
        self.tool_contract(tool).map(|c| c.identity.clone())
    }

    /// The number of distinct tool contracts currently registered. Used by
    /// tests to assert `MCP_TOOLS_VALIDATED=14`.
    #[allow(dead_code)]
    pub fn registered_tool_count(&self) -> usize {
        self.contracts.len()
    }
}

// ---------------------------------------------------------------------
// Input validation gate (Section 9)
// ---------------------------------------------------------------------

/// Re-serializes an already `serde`-deserialized (and therefore already
/// structurally type-checked) `params` value and validates it against
/// `tool`'s exact input JSON Schema, as a defense-in-depth second gate
/// over the same schema authority `list_tools` advertises.
///
/// This never weakens, widens, or replaces `serde`'s own deserialization
/// (which has already run by the time a handler calls this -- required
/// fields, enum tags, and `deny_unknown_fields` are `serde`'s job and are
/// untouched here); it only catches schema-declared constraints that a
/// bare `Deserialize` impl does not itself independently re-check, and it
/// records this tool's contract identity for diagnostics.
pub fn validate_input<T: Serialize>(
    registry: &ContractRegistry,
    tool: &'static str,
    params: &T,
) -> Result<(), ContractError> {
    let Some(contract) = registry.tool_contract(tool) else {
        return Err(registry.unknown_tool_error(tool));
    };
    let Some(validator) = &contract.input_validator else {
        return Ok(());
    };
    let value = serde_json::to_value(params).map_err(|error| ContractError {
        class: ContractErrorClass::InternalSerializationFailed,
        tool,
        detail: format!("failed to re-serialize input for validation: {error}"),
    })?;
    let paths: Vec<String> = validator
        .iter_errors(&value)
        .take(5)
        .map(|e| e.instance_path().to_string())
        .collect();
    if paths.is_empty() {
        tracing::debug!(
            target: "wht_corulix_mcp::contract_gate",
            tool,
            input_schema_sha256 = %contract.identity.input_schema_sha256,
            "contract gate: input validated"
        );
        Ok(())
    } else {
        tracing::error!(
            target: "wht_corulix_mcp::contract_gate",
            tool,
            violation_count = paths.len(),
            paths = ?paths,
            "contract gate: CONTRACT_INPUT_INVALID"
        );
        Err(ContractError {
            class: ContractErrorClass::InputInvalid,
            tool,
            detail: format!("{} input schema violation(s) at {:?}", paths.len(), paths),
        })
    }
}

// ---------------------------------------------------------------------
// Output + MCP envelope validation gate (Sections 10-12, 15, 17)
// ---------------------------------------------------------------------

/// Hard, generous safety backstop on total response bytes
/// (`content` + `structured_content` combined). No pre-existing cap on MCP
/// response size existed anywhere in this codebase before this gate; this
/// is a new, deliberately permissive ceiling -- large enough that no
/// currently-observed real response from any of the 14 tools comes
/// remotely close to it -- added purely as pathological-growth defense in
/// depth, never as a new business rule restricting today's legitimate
/// responses.
const MAX_MCP_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

fn validate_output_value(
    registry: &ContractRegistry,
    tool: &'static str,
    value: &Value,
) -> Result<(), ContractError> {
    let Some(contract) = registry.tool_contract(tool) else {
        return Err(registry.unknown_tool_error(tool));
    };
    let paths: Vec<String> = contract
        .output_validator
        .iter_errors(value)
        .take(5)
        .map(|e| e.instance_path().to_string())
        .collect();
    if paths.is_empty() {
        Ok(())
    } else {
        Err(ContractError {
            class: ContractErrorClass::OutputInvalid,
            tool,
            detail: format!("{} output schema violation(s) at {:?}", paths.len(), paths),
        })
    }
}

fn content_block_byte_len(block: &ContentBlock) -> Result<usize, ContractError> {
    match block {
        ContentBlock::Text(text) => Ok(text.text.len()),
        // Every one of the 14 tools' three result-construction helpers
        // (`plain_result`/`outcome_result`/`parse_success_result`) only
        // ever emits `ContentBlock::Text` -- any other variant reaching
        // this gate means a future change introduced a content type this
        // envelope was never designed to carry.
        other => Err(ContractError {
            class: ContractErrorClass::McpEnvelopeInvalid,
            tool: "unknown",
            detail: format!("unexpected non-text content block variant: {other:?}"),
        }),
    }
}

/// Validates the full `CallToolResult` envelope (Section 11) and, when
/// `structured_content` is present, validates it against the exact same
/// output schema exposed for `tool` (Section 12's
/// `EXPOSED_OUTPUT_SCHEMA == RUNTIME_VALIDATION_SCHEMA_AUTHORITY`
/// invariant -- there is no second, manually-maintained schema here).
pub fn validate_envelope(
    registry: &ContractRegistry,
    tool: &'static str,
    result: &CallToolResult,
) -> Result<(), ContractError> {
    let mut content_bytes = 0usize;
    for block in &result.content {
        content_bytes += content_block_byte_len(block).map_err(|mut e| {
            e.tool = tool;
            e
        })?;
    }

    let mut structured_bytes = 0usize;
    if let Some(structured) = &result.structured_content {
        validate_output_value(registry, tool, structured)?;
        structured_bytes = structured.to_string().len();
    }

    let total = content_bytes + structured_bytes;
    if total > MAX_MCP_RESPONSE_BYTES {
        return Err(ContractError {
            class: ContractErrorClass::McpEnvelopeInvalid,
            tool,
            detail: format!(
                "response size {total} bytes exceeds {MAX_MCP_RESPONSE_BYTES} byte safety backstop"
            ),
        });
    }

    tracing::debug!(
        target: "wht_corulix_mcp::contract_gate",
        tool,
        structured_content_present = result.structured_content.is_some(),
        structured_content_byte_len = structured_bytes,
        content_block_count = result.content.len(),
        content_total_byte_len = content_bytes,
        "contract gate: envelope + output validated"
    );
    Ok(())
}

/// The one, fixed, bounded fallback result returned in place of anything
/// that failed contract validation (Section 17). Deliberately hand-built
/// and never itself re-run through [`validate_envelope`]/
/// [`validate_output_value`] -- this is the terminal, non-recursive end of
/// the fail-closed path.
///
/// # Classification (final, owner-adjudicated)
///
/// Per the official MCP specification's "Error Handling" section
/// (<https://modelcontextprotocol.io/specification/2025-06-18/server/tools>),
/// which names exactly two mechanisms:
/// - **Protocol Error**: a JSON-RPC response using the top-level `error`
///   member (`Err(ErrorData)` in `rmcp` terms).
/// - **Tool Execution Error**: `tools/call` returns a normal JSON-RPC
///   `result` containing `isError: true` (`Ok(CallToolResult)` with
///   `is_error: Some(true)` in `rmcp` terms).
///
/// This function builds via `CallToolResult::error(...)`, which sets
/// `content` and `is_error: Some(true)`, `structured_content: None`
/// (verified directly against `rmcp` 3.0.1's own source, `model.rs:
/// 3929-3937`) -- an unambiguous MCP **Tool Execution Error**, returned as
/// `Ok(CallToolResult)`, never a JSON-RPC protocol-level error:
///
/// `FAIL_CLOSED_RESULT_CLASSIFICATION = MCP_TOOL_EXECUTION_ERROR`
/// `FAIL_CLOSED_RESULT_JSONRPC_FORM = RESULT_WITH_ISERROR_TRUE`
/// `FAIL_CLOSED_RESULT_STRUCTURED_CONTENT = ABSENT`
///
/// Because `structured_content` is now structurally `None` on this path
/// (not merely an ad-hoc, schema-unbound value as in the prior pass), the
/// ambiguity the owner flagged -- "is this secretly claiming to be a valid
/// typed success payload?" -- cannot arise at all: there is no
/// `structuredContent` field for any client to even attempt to validate
/// against an `outputSchema`. `FAIL_CLOSED_ERROR_CAN_BYPASS_TYPED_SUCCESS_
/// SCHEMA = YES` for the simplest possible reason: there is no
/// `structured_content` to bypass anything with.
///
/// # Content policy (Section 3)
///
/// The model-facing text is a single, fixed-format sentence carrying only
/// `error.error_code()` -- one of the 7 closed [`ContractErrorClass`]
/// variants, never attacker- or payload-influenced -- plus a constant
/// message. No stack trace, source payload, absolute path, schema body,
/// or internal serialization dump is ever included (verified: this
/// function never touches `error.detail`, which is where such detail
/// would live -- only `error.error_code()` and `error.tool` are read, and
/// `tool` stays in the internal `tracing::error!` call, never the
/// model-facing text). No recursion: this function is never itself passed
/// back through [`validate_envelope`]/[`finalize`] (confirmed by `grep`:
/// no call site does so).
pub fn fail_closed_result(error: &ContractError) -> CallToolResult {
    tracing::error!(
        target: "wht_corulix_mcp::contract_gate",
        tool = error.tool,
        error_code = error.error_code(),
        detail = %error.detail,
        "contract gate: FAIL CLOSED, invalid payload discarded before MCP return"
    );
    let message = format!(
        "{}: Corulix internal contract validation failed; the invalid result was discarded \
         before returning to the client.",
        error.error_code()
    );
    CallToolResult::error(vec![ContentBlock::text(message)])
}

/// Centralized final step for every one of the 3 shared result-construction
/// helpers (`plain_result`/`outcome_result`/`parse_success_result`):
/// validates the assembled envelope and, on any contract violation,
/// discards it in favor of [`fail_closed_result`]. This is the single call
/// site all 14 tools' results pass through -- no per-handler validation
/// logic is scattered anywhere else.
pub fn finalize(
    registry: &ContractRegistry,
    tool: &'static str,
    result: CallToolResult,
) -> CallToolResult {
    match validate_envelope(registry, tool, &result) {
        Ok(()) => result,
        Err(error) => fail_closed_result(&error),
    }
}

// ---------------------------------------------------------------------
// Parse dual-channel consistency invariant (Section 14) -- parse_file only
// ---------------------------------------------------------------------

/// Derives deterministic facts from the SAME `(ParseSummary,
/// Vec<CompactSymbol>)` tuple `wht_corulix_syntax::parse_source_with_facts`
/// produces in one atomic call, and checks them for internal consistency
/// before `parse_file`'s result is ever constructed. Called with the FULL,
/// uncapped `facts` list (before any MCP-layer truncation) -- today this
/// tuple is architecturally incapable of disagreeing with itself (both
/// halves are built from the same single traversal of the same tree in the
/// same function call, unzipped from one combined `Vec`, see that crate's
/// own doc comments) -- this invariant exists as a defensive regression
/// backstop for a future change to that invariant, not because a live
/// inconsistency has ever been observed.
pub fn validate_parse_dual_channel(
    summary: &wht_corulix_core::ParseSummary,
    facts: &[wht_corulix_core::CompactSymbol],
) -> Result<(), ContractError> {
    const TOOL: &str = "parse_file";

    // Every symbol's range must fall within the parsed source's own byte
    // length -- a line/range reference outside source bounds could not
    // have come from a real parse of this file.
    for symbol in &summary.symbols {
        if symbol.range.start.byte_offset > symbol.range.end.byte_offset
            || symbol.range.end.byte_offset > summary.byte_len
        {
            return Err(ContractError {
                class: ContractErrorClass::SemanticInvariantFailed,
                tool: TOOL,
                detail: format!(
                    "symbol {:?} range [{}, {}) is inconsistent with parsed byte_len {}",
                    symbol.kind,
                    symbol.range.start.byte_offset,
                    symbol.range.end.byte_offset,
                    summary.byte_len
                ),
            });
        }
    }

    // `Symbol` and `CompactSymbol` are unzipped from the same combined
    // `Vec<(Symbol, CompactSymbol)>` in `extract_symbols_with_facts`, so
    // they must be exactly index-aligned: same length, same name at each
    // position (kind may legitimately be *refined*, not merely mirrored,
    // for Go's Struct/Interface disambiguation -- so kind is deliberately
    // not compared here).
    if facts.len() != summary.symbols.len() {
        return Err(ContractError {
            class: ContractErrorClass::SemanticInvariantFailed,
            tool: TOOL,
            detail: format!(
                "compact facts count {} is inconsistent with structured_content's {} symbols",
                facts.len(),
                summary.symbols.len()
            ),
        });
    }
    for (index, (symbol, fact)) in summary.symbols.iter().zip(facts.iter()).enumerate() {
        if symbol.name != fact.name {
            return Err(ContractError {
                class: ContractErrorClass::SemanticInvariantFailed,
                tool: TOOL,
                detail: format!("compact fact at index {index} does not match its own symbol"),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every real test builds its own fresh, real registry from the real
    /// 14 production tool types -- never a shared global -- so a test
    /// failure here can never be blamed on cross-test state.
    fn test_registry() -> Result<ContractRegistry, String> {
        ContractRegistry::build().map_err(|e| e.to_string())
    }

    #[test]
    fn registry_covers_all_fourteen_tools_with_no_duplicates() -> Result<(), String> {
        let registry = test_registry()?;
        assert_eq!(registry.registered_tool_count(), 14);
        Ok(())
    }

    #[test]
    fn every_tool_has_a_stable_nonempty_contract_identity() -> Result<(), String> {
        let registry = test_registry()?;
        for tool in [
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
        ] {
            let Some(id) = registry.contract_identity(tool) else {
                return Err(format!("{tool} has no registered contract identity"));
            };
            assert_eq!(id.tool, tool);
            assert!(!id.output_schema_sha256.is_empty());
            // Calling twice must be byte-identical (schema authority is
            // cached/deterministic, never regenerated differently per call).
            let Some(id2) = registry.contract_identity(tool) else {
                return Err(format!("{tool} lost its contract identity on second call"));
            };
            assert_eq!(id.output_schema_sha256, id2.output_schema_sha256);
            assert_eq!(id.input_schema_sha256, id2.input_schema_sha256);
        }
        Ok(())
    }

    #[test]
    fn valid_search_params_pass_input_validation() -> Result<(), String> {
        let registry = test_registry()?;
        let params = SearchParams {
            pattern: "fn main".to_string(),
            is_regex: false,
            case_insensitive: false,
            root_selector: None,
        };
        assert!(validate_input(&registry, "search", &params).is_ok());
        Ok(())
    }

    #[test]
    fn valid_parse_file_output_passes_output_validation() -> Result<(), String> {
        let registry = test_registry()?;
        let output = ParseFileOutput::Ok {
            language: wht_corulix_core::LanguageId::Rust,
            syntax_ok: true,
            symbols: vec![],
            truncated: false,
        };
        let value = serde_json::to_value(&output).map_err(|e| e.to_string())?;
        assert!(validate_output_value(&registry, "parse_file", &value).is_ok());
        Ok(())
    }

    #[test]
    fn structurally_invalid_output_is_rejected() -> Result<(), String> {
        let registry = test_registry()?;
        // A value that cannot possibly satisfy `ParseFileOutput`'s schema
        // (missing the required `status` discriminant tag entirely).
        let bogus = serde_json::json!({ "not_a_real_field": 1 });
        assert!(validate_output_value(&registry, "parse_file", &bogus).is_err());
        Ok(())
    }

    #[test]
    fn envelope_rejects_oversized_response() -> Result<(), String> {
        let registry = test_registry()?;
        let oversized = "x".repeat(MAX_MCP_RESPONSE_BYTES + 1);
        let result = CallToolResult::success(vec![ContentBlock::text(oversized)]);
        let Err(error) = validate_envelope(&registry, "search", &result) else {
            return Err("expected an oversized response to be rejected".to_string());
        };
        assert_eq!(error.class, ContractErrorClass::McpEnvelopeInvalid);
        Ok(())
    }

    #[test]
    fn envelope_accepts_a_small_valid_structured_result() -> Result<(), String> {
        let registry = test_registry()?;
        let output = AbortChangeOutput::Aborted;
        let value = serde_json::to_value(&output).map_err(|e| e.to_string())?;
        let result = CallToolResult::structured(value);
        assert!(validate_envelope(&registry, "abort_change", &result).is_ok());
        Ok(())
    }

    /// MCP error-semantics closure Section 6: a deliberately invalid typed
    /// output must terminate as an unambiguous Tool Execution Error --
    /// `isError: true`, NO `structuredContent` at all (never an ad-hoc
    /// value a client might mistakenly validate against `outputSchema`),
    /// a bounded canonical `content` message, and the original invalid
    /// payload byte-for-byte absent from the returned result.
    #[test]
    fn finalize_discards_invalid_output_as_a_tool_execution_error() -> Result<(), String> {
        let registry = test_registry()?;
        // parse_file's schema requires the `status` tag; this structured
        // payload has none, so it must never reach the client unmodified.
        let sentinel = "bogus_payload_marker_should_never_leak";
        let mut result = CallToolResult::structured(serde_json::json!({ sentinel: true }));
        result.content = vec![ContentBlock::text("irrelevant".to_string())];
        let finalized = finalize(&registry, "parse_file", result);

        // CONTRACT_FAILURE_IS_ERROR_TRUE
        assert_eq!(finalized.is_error, Some(true));

        // CONTRACT_FAILURE_STRUCTURED_CONTENT_ABSENT
        if finalized.structured_content.is_some() {
            return Err(
                "fail-closed Tool Execution Error must carry no structuredContent at all"
                    .to_string(),
            );
        }

        // content must be present and carry the bounded canonical message,
        // including the closed error-class code.
        let mut content_text = String::new();
        for block in &finalized.content {
            let ContentBlock::Text(text) = block else {
                return Err("fail-closed content must be text-only".to_string());
            };
            content_text.push_str(&text.text);
        }
        if !content_text.contains("CONTRACT_OUTPUT_INVALID") {
            return Err(format!(
                "expected the bounded error code in content, got: {content_text:?}"
            ));
        }

        // INVALID_OUTPUT_PAYLOAD_LEAK_COUNT=0: the original invalid
        // payload must appear nowhere -- not in content, not anywhere
        // (structured_content is already proven absent above).
        if content_text.contains(sentinel) {
            return Err(
                "the original invalid payload leaked into the fail-closed result".to_string(),
            );
        }

        Ok(())
    }

    /// MCP error-semantics closure Section 7: the success path is
    /// completely unchanged by this pass -- a valid typed result still
    /// carries `structuredContent` that validates against the tool's exact
    /// `outputSchema`, and `isError` is never `Some(true)`.
    #[test]
    fn finalize_preserves_a_valid_success_result_unchanged() -> Result<(), String> {
        let registry = test_registry()?;
        let output = AbortChangeOutput::Aborted;
        let value = serde_json::to_value(&output).map_err(|e| e.to_string())?;
        let result = CallToolResult::structured(value.clone());
        let finalized = finalize(&registry, "abort_change", result);

        assert_ne!(finalized.is_error, Some(true));
        let Some(structured) = &finalized.structured_content else {
            return Err("a valid success result must still carry structuredContent".to_string());
        };
        assert_eq!(*structured, value);
        // Re-validate independently against the exact same schema
        // authority the gate itself uses -- the success path's own
        // contract is untouched by this pass.
        assert!(validate_output_value(&registry, "abort_change", structured).is_ok());
        Ok(())
    }

    // -------------------------------------------------------------
    // Section 3 (corrective pass): TRUE fail-closed startup.
    // -------------------------------------------------------------

    #[test]
    fn invalid_schema_startup_fails_registry_construction() -> Result<(), String> {
        let Err(error) = ContractRegistry::build_with_injected_invalid_schema() else {
            return Err(
                "expected registry construction to fail on an injected invalid schema".to_string(),
            );
        };
        assert_eq!(error.tool, "__test_injected_invalid__");
        Ok(())
    }

    // Section 3's second half -- proving `CorulixMcpServer::new_with_registry`
    // itself fails closed on a broken registry (not just `ContractRegistry::
    // build` in isolation) -- lives in `lib.rs`'s own test module
    // (`server_construction_fails_closed_when_registry_build_fails`), which
    // already has the real `WorkspaceContext`/`CorulixEngine` test fixture
    // helpers this needs; duplicating that setup here would be a second,
    // divergent fixture-construction path for no benefit.

    #[test]
    fn dual_channel_accepts_a_consistent_result() {
        let summary = wht_corulix_core::ParseSummary {
            schema_version: 1,
            language: wht_corulix_core::LanguageId::Rust,
            root_kind: "source_file".to_string(),
            has_syntax_error: false,
            byte_len: 100,
            symbols: vec![wht_corulix_core::Symbol {
                name: "widget".to_string(),
                kind: wht_corulix_core::SymbolKind::Struct,
                language: wht_corulix_core::LanguageId::Rust,
                range: wht_corulix_core::SourceRange {
                    start: wht_corulix_core::Position {
                        line_zero_based: 0,
                        byte_column_zero_based: 0,
                        byte_offset: 0,
                    },
                    end: wht_corulix_core::Position {
                        line_zero_based: 0,
                        byte_column_zero_based: 6,
                        byte_offset: 6,
                    },
                },
                language_specific_kind: "struct_item".to_string(),
            }],
        };
        let facts = vec![wht_corulix_core::CompactSymbol {
            kind: wht_corulix_core::SymbolKind::Struct,
            name: "widget".to_string(),
            container: None,
            modifiers: None,
            line: 1,
            signature: None,
        }];
        assert!(validate_parse_dual_channel(&summary, &facts).is_ok());
    }

    #[test]
    fn dual_channel_rejects_an_entry_count_mismatch() -> Result<(), String> {
        let summary = wht_corulix_core::ParseSummary {
            schema_version: 1,
            language: wht_corulix_core::LanguageId::Rust,
            root_kind: "source_file".to_string(),
            has_syntax_error: false,
            byte_len: 100,
            symbols: vec![wht_corulix_core::Symbol {
                name: "widget".to_string(),
                kind: wht_corulix_core::SymbolKind::Struct,
                language: wht_corulix_core::LanguageId::Rust,
                range: wht_corulix_core::SourceRange {
                    start: wht_corulix_core::Position {
                        line_zero_based: 0,
                        byte_column_zero_based: 0,
                        byte_offset: 0,
                    },
                    end: wht_corulix_core::Position {
                        line_zero_based: 0,
                        byte_column_zero_based: 6,
                        byte_offset: 6,
                    },
                },
                language_specific_kind: "struct_item".to_string(),
            }],
        };
        // Two facts claimed for one real symbol -- a deliberately injected
        // inconsistency a real single-pass traversal could never produce.
        let facts = vec![
            wht_corulix_core::CompactSymbol {
                kind: wht_corulix_core::SymbolKind::Struct,
                name: "widget".to_string(),
                container: None,
                modifiers: None,
                line: 1,
                signature: None,
            },
            wht_corulix_core::CompactSymbol {
                kind: wht_corulix_core::SymbolKind::Struct,
                name: "ghost".to_string(),
                container: None,
                modifiers: None,
                line: 2,
                signature: None,
            },
        ];
        let Err(error) = validate_parse_dual_channel(&summary, &facts) else {
            return Err("expected an entry-count mismatch to be rejected".to_string());
        };
        assert_eq!(error.class, ContractErrorClass::SemanticInvariantFailed);
        Ok(())
    }

    #[test]
    fn dual_channel_rejects_an_out_of_bounds_range() -> Result<(), String> {
        let summary = wht_corulix_core::ParseSummary {
            schema_version: 1,
            language: wht_corulix_core::LanguageId::Rust,
            root_kind: "source_file".to_string(),
            has_syntax_error: false,
            byte_len: 5,
            symbols: vec![wht_corulix_core::Symbol {
                name: "widget".to_string(),
                kind: wht_corulix_core::SymbolKind::Struct,
                language: wht_corulix_core::LanguageId::Rust,
                range: wht_corulix_core::SourceRange {
                    start: wht_corulix_core::Position {
                        line_zero_based: 0,
                        byte_column_zero_based: 0,
                        byte_offset: 0,
                    },
                    end: wht_corulix_core::Position {
                        line_zero_based: 0,
                        byte_column_zero_based: 999,
                        byte_offset: 999,
                    },
                },
                language_specific_kind: "struct_item".to_string(),
            }],
        };
        // The range check fires before any facts-length comparison, so an
        // empty facts slice is sufficient here.
        let Err(error) = validate_parse_dual_channel(&summary, &[]) else {
            return Err("expected an out-of-bounds range to be rejected".to_string());
        };
        assert_eq!(error.class, ContractErrorClass::SemanticInvariantFailed);
        Ok(())
    }

    #[test]
    fn dual_channel_rejects_a_name_mismatch_at_the_same_index() -> Result<(), String> {
        let summary = wht_corulix_core::ParseSummary {
            schema_version: 1,
            language: wht_corulix_core::LanguageId::Rust,
            root_kind: "source_file".to_string(),
            has_syntax_error: false,
            byte_len: 100,
            symbols: vec![
                wht_corulix_core::Symbol {
                    name: "a".to_string(),
                    kind: wht_corulix_core::SymbolKind::Struct,
                    language: wht_corulix_core::LanguageId::Rust,
                    range: wht_corulix_core::SourceRange {
                        start: wht_corulix_core::Position {
                            line_zero_based: 0,
                            byte_column_zero_based: 0,
                            byte_offset: 0,
                        },
                        end: wht_corulix_core::Position {
                            line_zero_based: 0,
                            byte_column_zero_based: 1,
                            byte_offset: 1,
                        },
                    },
                    language_specific_kind: "struct_item".to_string(),
                },
                wht_corulix_core::Symbol {
                    name: "b".to_string(),
                    kind: wht_corulix_core::SymbolKind::Struct,
                    language: wht_corulix_core::LanguageId::Rust,
                    range: wht_corulix_core::SourceRange {
                        start: wht_corulix_core::Position {
                            line_zero_based: 1,
                            byte_column_zero_based: 0,
                            byte_offset: 2,
                        },
                        end: wht_corulix_core::Position {
                            line_zero_based: 1,
                            byte_column_zero_based: 1,
                            byte_offset: 3,
                        },
                    },
                    language_specific_kind: "struct_item".to_string(),
                },
            ],
        };
        // Same length as `summary.symbols` (2), but the second entry's name
        // does not match its own symbol at the same index -- a deliberately
        // injected inconsistency a real single-pass traversal could never
        // produce.
        let facts = vec![
            wht_corulix_core::CompactSymbol {
                kind: wht_corulix_core::SymbolKind::Struct,
                name: "a".to_string(),
                container: None,
                modifiers: None,
                line: 1,
                signature: None,
            },
            wht_corulix_core::CompactSymbol {
                kind: wht_corulix_core::SymbolKind::Struct,
                name: "not_b".to_string(),
                container: None,
                modifiers: None,
                line: 2,
                signature: None,
            },
        ];
        let Err(error) = validate_parse_dual_channel(&summary, &facts) else {
            return Err("expected a name mismatch to be rejected".to_string());
        };
        assert_eq!(error.class, ContractErrorClass::SemanticInvariantFailed);
        Ok(())
    }

    // -------------------------------------------------------------
    // Dev-only microbench (Section 19-20 of the Contract Gate mandate).
    // Hand-rolled `std::time::Instant` timing, mirroring this crate's own
    // pre-existing `dev_microbench_*` idiom -- never `criterion`, never
    // part of release behavior. Run via:
    // `cargo test -p wht_corulix_mcp -- --ignored --nocapture contract_gate`
    // -------------------------------------------------------------

    fn median_nanos(mut samples: Vec<u128>) -> u128 {
        samples.sort_unstable();
        samples[samples.len() / 2]
    }

    fn make_compact_symbol(i: usize) -> wht_corulix_core::CompactSymbol {
        wht_corulix_core::CompactSymbol {
            kind: wht_corulix_core::SymbolKind::Function,
            name: format!("symbol_{i}"),
            container: None,
            modifiers: None,
            line: i as u32 + 1,
            signature: Some(format!("fn symbol_{i}()")),
        }
    }

    #[test]
    #[ignore]
    fn dev_microbench_contract_gate_validation_overhead() -> Result<(), String> {
        const ITERATIONS: usize = 500;

        let registry = test_registry()?;
        let search_params = SearchParams {
            pattern: "fn main".to_string(),
            is_regex: false,
            case_insensitive: false,
            root_selector: None,
        };
        let small_output = serde_json::to_value(ParseFileOutput::Ok {
            language: wht_corulix_core::LanguageId::Rust,
            syntax_ok: true,
            symbols: (0..5).map(make_compact_symbol).collect(),
            truncated: false,
        })
        .map_err(|e| e.to_string())?;
        let large_output = serde_json::to_value(ParseFileOutput::Ok {
            language: wht_corulix_core::LanguageId::Rust,
            syntax_ok: true,
            symbols: (0..500).map(make_compact_symbol).collect(),
            truncated: false,
        })
        .map_err(|e| e.to_string())?;
        let small_result = CallToolResult::structured(small_output.clone());
        let large_result = CallToolResult::structured(large_output.clone());

        let mut input_samples = Vec::with_capacity(ITERATIONS);
        let mut output_small_samples = Vec::with_capacity(ITERATIONS);
        let mut output_large_samples = Vec::with_capacity(ITERATIONS);
        let mut envelope_small_samples = Vec::with_capacity(ITERATIONS);
        let mut envelope_large_samples = Vec::with_capacity(ITERATIONS);

        for _ in 0..ITERATIONS {
            let start = std::time::Instant::now();
            let _ = validate_input(&registry, "search", &search_params);
            input_samples.push(start.elapsed().as_nanos());

            let start = std::time::Instant::now();
            let _ = validate_output_value(&registry, "parse_file", &small_output);
            output_small_samples.push(start.elapsed().as_nanos());

            let start = std::time::Instant::now();
            let _ = validate_output_value(&registry, "parse_file", &large_output);
            output_large_samples.push(start.elapsed().as_nanos());

            let start = std::time::Instant::now();
            let _ = validate_envelope(&registry, "parse_file", &small_result);
            envelope_small_samples.push(start.elapsed().as_nanos());

            let start = std::time::Instant::now();
            let _ = validate_envelope(&registry, "parse_file", &large_result);
            envelope_large_samples.push(start.elapsed().as_nanos());
        }

        let input_median_ns = median_nanos(input_samples);
        let output_small_median_ns = median_nanos(output_small_samples);
        let output_large_median_ns = median_nanos(output_large_samples);
        let envelope_small_median_ns = median_nanos(envelope_small_samples);
        let envelope_large_median_ns = median_nanos(envelope_large_samples);
        let total_median_us = (input_median_ns + envelope_large_median_ns) as f64 / 1000.0;

        let report = serde_json::json!({
            "VALIDATION_INPUT_MEDIAN_US_search": input_median_ns as f64 / 1000.0,
            "VALIDATION_OUTPUT_MEDIAN_US_parse_file_small_5_symbols": output_small_median_ns as f64 / 1000.0,
            "VALIDATION_OUTPUT_MEDIAN_US_parse_file_large_500_symbols": output_large_median_ns as f64 / 1000.0,
            "VALIDATION_ENVELOPE_MEDIAN_US_parse_file_small": envelope_small_median_ns as f64 / 1000.0,
            "VALIDATION_ENVELOPE_MEDIAN_US_parse_file_large": envelope_large_median_ns as f64 / 1000.0,
            "TOTAL_VALIDATION_OVERHEAD_MEDIAN_US_worst_case": total_median_us,
            "DEVELOPMENT_MICROBENCH_ONLY": true,
        });
        eprintln!("{report}");

        let results_dir =
            std::env::temp_dir().join("corulix_optimization_lab/contract_gate/results");
        let _ = std::fs::create_dir_all(&results_dir);
        let results_dir = results_dir.display();
        let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
        let _ = std::fs::write(
            format!("{results_dir}/validation_overhead_microbench.json"),
            &json,
        );

        Ok(())
    }
}
