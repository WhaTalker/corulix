// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Corulix-owned semantic result DTOs. Raw `ls_types` values never cross
//! this crate's public boundary (Architecture Rule L) -- every operation in
//! `crate::operations` translates a language-server response into one of
//! these types before returning it.

use wht_corulix_core::{SourceRange, SymbolKind, WorkspacePath};

/// A location Corulix has proven resolves inside the active workspace.
/// Never carries a raw, unvalidated path or URI -- `crate::operations`
/// rejects any server-supplied result whose URI would resolve outside
/// [`wht_corulix_workspace`]'s confinement before this type is ever
/// constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticLocation {
    pub path: WorkspacePath,
    pub range: SourceRange,
}

/// The result of a `textDocument/definition` request. `Multiple` covers
/// both a genuine LSP location array and location-link array response
/// shape -- callers that only care about "where do I jump to" can treat
/// both uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionResult {
    None,
    Single(SemanticLocation),
    Multiple(Vec<SemanticLocation>),
}

/// The result of a `textDocument/references` request, distinguishing
/// "the server has not finished analysis yet" from "the server, once
/// ready, reported zero references" -- see `crate::readiness`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferencesResult {
    NotReady,
    Found(Vec<SemanticLocation>),
}

/// One document or workspace symbol, translated into Corulix's own
/// vocabulary. `container_name` is `None` for a top-level symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticSymbol {
    pub name: String,
    pub kind: SymbolKind,
    pub container_name: Option<String>,
    pub location: SemanticLocation,
    pub children: Vec<SemanticSymbol>,
}

/// A diagnostic reported by the language server. This is semantic LSP
/// evidence only -- it never replaces a future dedicated clippy/`cargo
/// check`/`cargo build` authority (Architecture Rule H's provider-authority
/// model still governs which provider is authoritative for a given
/// operation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticDiagnostic {
    pub range: SourceRange,
    pub severity: DiagnosticSeverity,
    pub message: String,
    pub source: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Information,
    Hint,
}

/// The result of a `textDocument/diagnostic` (or `publishDiagnostics`,
/// whichever mode is actually proven -- see `crate::operations::diagnostics`
/// for which one this crate implements) request, distinguishing
/// not-yet-ready from a proven-empty diagnostic set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticsResult {
    NotReady,
    Reported(Vec<SemanticDiagnostic>),
}

/// A proposed text edit within one file, never applied by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedTextEdit {
    pub range: SourceRange,
    pub new_text: String,
}

/// A proposed rename across one or more files -- a *preview* only.
/// `RENAME_PREVIEW_MUTATION_COUNT=0`: nothing in this crate ever writes
/// these edits to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameEditPreview {
    pub edits_by_path: Vec<(WorkspacePath, Vec<ProposedTextEdit>)>,
}

/// Hover text, supporting evidence only
/// (`HOVER_AUTHORITY=SUPPORTING_ONLY`) -- never used by this crate to
/// satisfy definition/references/rename/diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoverEvidence {
    pub contents: String,
    pub range: Option<SourceRange>,
}
