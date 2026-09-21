// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Language identity, parse results, and source-position contracts.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Identifies a source language Corulix knows how to parse.
///
/// `#[non_exhaustive]` so new languages can be added without breaking
/// downstream `match` exhaustiveness across crate boundaries.
///
/// Parse Optimization V2 (Candidate B): the `schemars` description below is
/// deliberately shorter than this doc comment -- the full doc comment stays
/// for human Rust readers, while the MCP-exposed schema description is
/// compressed to reduce `parse_file`'s static schema bytes without changing
/// field names, types, or validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(description = "Source language Corulix can parse.")]
#[non_exhaustive]
pub enum LanguageId {
    TypeScript,
    Tsx,
    JavaScript,
    Python,
    Rust,
    Go,
}

impl fmt::Display for LanguageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::JavaScript => "javascript",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Go => "go",
        };
        f.write_str(value)
    }
}

/// How completely a language adapter implements a given analysis capability.
///
/// Callers use this to decide whether to trust a result outright, treat it as
/// a best-effort hint, or skip the feature for that language entirely. Also
/// reused as [`crate::ProviderCapability`] so Core does not carry two
/// near-identical tri-state enums for the same underlying concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum CapabilityState {
    Supported,
    Partial,
    NotSupported,
}

/// Per-language feature matrix reported to clients so they never assume a
/// capability that the current language adapter does not actually provide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LanguageCapabilities {
    pub parsing: CapabilityState,
    pub definitions: CapabilityState,
    pub lexical_scopes: CapabilityState,
    pub references: CapabilityState,
    pub imports: CapabilityState,
    pub exports: CapabilityState,
    pub calls: CapabilityState,
    pub cross_file_resolution: CapabilityState,
}

/// Coarse classification of a definition site (function, class, struct, ...)
/// used for cross-language filtering; see `Symbol::language_specific_kind`
/// for the exact Tree-sitter node kind that produced it.
///
/// Parse Optimization V2 (Candidate B): see [`LanguageId`]'s doc comment for
/// why the `schemars` description below is shorter than this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[schemars(description = "Coarse kind of a definition site (function, class, struct, etc).")]
#[non_exhaustive]
pub enum SymbolKind {
    Module,
    Namespace,
    Class,
    Interface,
    Trait,
    Struct,
    Enum,
    Type,
    Function,
    Method,
    Constructor,
    Variable,
    Constant,
    Property,
    Field,
    Parameter,
    Import,
    Export,
    Macro,
    Unknown,
}

/// A zero-based location in a source file, kept in three coordinate systems
/// at once (line, byte column, byte offset) so consumers can pick whichever
/// one their editor/protocol expects without recomputing it from the others.
///
/// Parse Optimization V2 (Candidate B): see [`LanguageId`]'s doc comment for
/// why the `schemars` description below is shorter than this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(description = "A zero-based source location (line, byte column, byte offset).")]
pub struct Position {
    pub line_zero_based: u32,
    pub byte_column_zero_based: u32,
    pub byte_offset: u64,
}

/// A half-open `[start, end)` span of source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SourceRange {
    pub start: Position,
    pub end: Position,
}

/// A single named definition site discovered while parsing a file.
///
/// Parse Optimization V2 (Candidate B): see [`LanguageId`]'s doc comment for
/// why the `schemars` description below is shorter than this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(description = "A named definition site found while parsing.")]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub language: LanguageId,
    pub range: SourceRange,
    pub language_specific_kind: String,
}

/// The full result of parsing one file: language, syntax health, and every
/// symbol extracted from it. `schema_version` lets external consumers detect
/// a breaking shape change without guessing from field presence.
///
/// Parse Optimization V2 (Candidate B): see [`LanguageId`]'s doc comment for
/// why the `schemars` description below is shorter than this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(description = "Full parse result: language, syntax health, and every symbol found.")]
pub struct ParseSummary {
    pub schema_version: u32,
    pub language: LanguageId,
    pub root_kind: String,
    pub has_syntax_error: bool,
    pub byte_len: u64,
    pub symbols: Vec<Symbol>,
}

/// One symbol's AI-facing structural facts -- the Parse MCP contract's
/// canonical, compact, typed unit. Projected directly from the same
/// single Tree-sitter traversal that produces [`Symbol`] (never a second
/// parse, never a second traversal, never derived by re-parsing rendered
/// text): `wht_corulix_syntax` computes `container`/`modifiers`/
/// `signature` once per classified symbol and now retains them here as
/// typed data instead of discarding them after formatting a display
/// string. `kind` already reflects any language-specific refinement
/// (e.g. Go's `type_spec` resolved to `Struct`/`Interface`/`Type`) that a
/// generic `Symbol.kind` alone cannot express without a second, semantic
/// declaration lookup -- see `wht_corulix_syntax`'s own resolution logic.
///
/// Every `Option` field is `None` on legitimate absence (no container, no
/// modifiers, no capturable signature) -- never a placeholder empty
/// string/array standing in for "unknown".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(
    description = "One symbol's AI-facing structural facts: kind, name, container, modifiers, line, and exact signature."
)]
pub struct CompactSymbol {
    pub kind: SymbolKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modifiers: Option<Vec<String>>,
    /// 1-based source line -- matches common editor/IDE line numbering
    /// (unlike `Position::line_zero_based`, which this compact contract
    /// deliberately does not expose).
    pub line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_display_is_stable() {
        assert_eq!(LanguageId::Rust.to_string(), "rust");
        assert_eq!(LanguageId::TypeScript.to_string(), "typescript");
    }
}
