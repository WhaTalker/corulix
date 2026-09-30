// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Corulix-owned domain types shared across every other crate in the workspace.
//!
//! This crate upholds Architecture Rule A: `wht_corulix_core` must never depend on
//! the MCP Rust SDK, JSON-RPC/MCP protocol types, MCP tool schemas, transports,
//! MCP lifecycle code, LSP wire messages, Tree-sitter or any grammar crate,
//! ripgrep/search implementation, filesystem I/O, process spawning, or any
//! provider/runtime concept. Every type defined here is a plain,
//! protocol-agnostic DTO so that downstream crates (including the MCP
//! transport layer and every future provider crate) can share one vocabulary
//! without pulling those concerns down into the core. Core owns types and
//! invariants; other layers compute, populate, and use them.
//!
//! Client-controllable-field audit (Enterprise Canonical Core Rebaseline,
//! Phase 1): as of this phase, Core defines no client-request-shaped DTO at
//! all, so there is no existing surface through which a caller could supply
//! or lower [`WorkspaceTrust`], [`RiskClass`], [`EnforcementLevel`], a
//! mandatory [`GateRequirement`], [`ChangeSessionStatus::Completed`], or
//! Evidence-authoritative status. Every one of those values is either
//! server-derived data ([`ToolPlan`], [`Evidence`]) or a value type with no
//! setter that could accept caller input. A later phase that introduces an
//! actual client-request DTO (e.g. an MCP `begin_change` request) must
//! preserve this property: such a DTO may carry `intent`/`scope`/`target`
//! only, never a security-sensitive classification directly.

mod cancellation;
mod diagnostics;
mod error;
mod evidence;
mod execution;
mod gate;
mod index;
mod language;
mod mutation;
mod operation;
mod provider;
mod runtime;
mod session;
mod tool_policy;
mod topology;
mod workspace;

pub use cancellation::CancellationToken;
pub use diagnostics::{DiagnosticSummary, FormattingStatus};
pub use error::{CorulixError, CorulixResult};
pub use evidence::{
    Confidence, EVIDENCE_RESULT_SUMMARY_MAX_BYTES, Evidence, EvidenceProvenance,
    EvidenceResultSummary, EvidenceTimestamp, ReferenceEvidence, ResolutionKind,
};
pub use execution::{EnforcementLevel, ExecutionClass};
pub use gate::{GateApplicability, GateId, GateRequirement, GateStatus};
pub use index::{IndexState, IndexStatus};
pub use language::{
    CapabilityState, CompactSymbol, LanguageCapabilities, LanguageId, ParseSummary, Position,
    SourceRange, Symbol, SymbolKind,
};
pub use mutation::{ContentHash, ContentHashAlgorithm, MutationBatchId, MutationProposalId};
pub use operation::{MutationKind, OperationIntent, RiskClass};
pub use provider::{
    AuthorityRole, PlanExecutability, ProviderAvailability, ProviderCapability, ProviderCategory,
    ProviderProvenance, ReasonCode, ToolApplicability, ToolPlan, ToolRequirement,
};
pub use runtime::RuntimeIdentity;
pub use session::{ChangeSessionId, ChangeSessionStatus, ConnectionId};
pub use tool_policy::{
    CANONICAL_MCP_TOOL_NAMES, EffectiveToolSet, MUTATION_FAMILY_MCP_TOOL_NAMES,
    ToolPolicyValidationError, validate_tool_policy,
};
pub use topology::{
    WorkspacePath, WorkspaceRootId, WorkspaceRootSummary, WorkspaceTopologyKind,
    WorkspaceTopologySummary,
};
pub use workspace::{
    WorkspaceIdentity, WorkspaceInfo, WorkspaceResolutionStatus, WorkspaceResolutionSummary,
    WorkspaceSourceKind, WorkspaceTrust,
};

pub const PRODUCT_NAME: &str = "WhaTalker Corulix";
pub const BRAND_NAME: &str = "Corulix";
pub const BINARY_NAME: &str = "corulix";
pub const SCHEMA_VERSION: u32 = 1;
pub const INDEX_SCHEMA_VERSION: u32 = 1;
