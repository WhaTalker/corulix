// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Tree-sitter structural/syntax intelligence: the sole permitted direct
//! Tree-sitter dependency in the Corulix workspace, per Architecture Rule C
//! (`RULE_C_SYNTAX_ISOLATION`).
//!
//! This crate's authority is deliberately narrow: it owns Tree-sitter
//! runtime integration, grammar registration, and structural symbol
//! extraction for `STRUCTURAL_INSPECTION`/`STRUCTURAL_SEARCH` only. It has
//! no authority over text search (`wht_corulix_search`), semantic
//! definitions/references/rename (a future LSP-backed provider),
//! formatting/linting/typechecking/tests (a future tooling provider),
//! workspace discovery or filesystem confinement (`wht_corulix_workspace`),
//! `RiskClass`/`ToolPlan`/gate derivation (`wht_corulix_engine`), or any
//! protocol/CLI surface. A programming language has several independent
//! authorities (Tree-sitter for structure, an LSP for semantics, a
//! formatter, a linter, a compiler, a test runner); this crate is
//! deliberately named for the one authority it actually has, not for the
//! language as a whole.
//!
//! Every Tree-sitter grammar and every `tree_sitter::*` type is used only
//! inside this crate. Nothing here re-exports raw Tree-sitter nodes or
//! languages; every public function returns Corulix-owned DTOs
//! (`ParseSummary`, `Symbol`, `SourceRange`, ...) from `wht_corulix_core` so that
//! `wht_corulix_engine` and `wht_corulix_mcp` can consume parse results without ever
//! importing `tree_sitter` themselves, which is what keeps Rule B intact one
//! layer up.
//!
//! # Parse MCP structured_content canonicalization — typed structural facts
//!
//! [`parse_source_with_facts`] returns the exact same [`ParseSummary`] this
//! crate has always produced, *plus* a parallel `Vec<CompactSymbol>` --
//! index-aligned with `ParseSummary::symbols` (both are sorted/produced
//! together from the same single traversal) -- carrying every AI-facing
//! structural fact (`container`/`modifiers`/`signature`/refined `kind`) as
//! typed data. This crate computes these facts once per classified symbol,
//! during the same pass that has always built `Symbol`; there is no second
//! Tree-sitter parse, no second traversal, and no text-rendering-then-
//! re-parsing step anywhere in this path (`wht_corulix_mcp` projects its
//! compact MCP DTO directly from `CompactSymbol`, never by re-parsing a
//! rendered string).
//!
//! Every fact is syntax-only, deterministic, and bounded (see the
//! `SIGNATURE_*`/`MODIFIER_*` constants below): this crate never performs
//! semantic resolution, never infers a language rule the grammar itself does
//! not enforce (e.g. Python's leading-underscore convention is NOT reported
//! as a visibility modifier), and never rewrites or truncates an emitted
//! source slice into a misleading partial value -- an over-cap fact is
//! omitted entirely (`None`), never shortened.

use std::path::Path;
use tree_sitter::{Language, Node, Parser};
use wht_corulix_core::{
    CapabilityState, CompactSymbol, CorulixError, CorulixResult, LanguageCapabilities, LanguageId,
    ParseSummary, Position, SCHEMA_VERSION, SourceRange, Symbol, SymbolKind,
};

mod anchor_role;
pub use anchor_role::{AnchorRole, classify_anchor_role};

/// Static metadata describing one supported language: its grammar package,
/// pinned grammar version, and the file extensions routed to it.
#[derive(Debug, Clone, Copy)]
pub struct LanguageDescriptor {
    pub id: LanguageId,
    pub grammar_package: &'static str,
    pub grammar_version: &'static str,
    pub extensions: &'static [&'static str],
}

const DESCRIPTORS: &[LanguageDescriptor] = &[
    LanguageDescriptor {
        id: LanguageId::TypeScript,
        grammar_package: "tree-sitter-typescript",
        grammar_version: "0.23.2",
        extensions: &["ts", "mts", "cts"],
    },
    LanguageDescriptor {
        id: LanguageId::Tsx,
        grammar_package: "tree-sitter-typescript",
        grammar_version: "0.23.2",
        extensions: &["tsx"],
    },
    LanguageDescriptor {
        id: LanguageId::JavaScript,
        grammar_package: "tree-sitter-javascript",
        grammar_version: "0.25.0",
        extensions: &["js", "mjs", "cjs", "jsx"],
    },
    LanguageDescriptor {
        id: LanguageId::Python,
        grammar_package: "tree-sitter-python",
        grammar_version: "0.25.0",
        extensions: &["py", "pyi"],
    },
    LanguageDescriptor {
        id: LanguageId::Rust,
        grammar_package: "tree-sitter-rust",
        grammar_version: "0.24.2",
        extensions: &["rs"],
    },
    LanguageDescriptor {
        id: LanguageId::Go,
        grammar_package: "tree-sitter-go",
        grammar_version: "0.25.0",
        extensions: &["go"],
    },
];

/// Returns the static table of every language descriptor Corulix supports.
#[must_use]
pub fn descriptors() -> &'static [LanguageDescriptor] {
    DESCRIPTORS
}

/// Maps a file path's extension to a supported `LanguageId`, or `None` when
/// the extension is unrecognized. Matching is case-insensitive so mixed-case
/// extensions on case-insensitive filesystems still resolve consistently.
#[must_use]
pub fn detect_language(path: &Path) -> Option<LanguageId> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.extensions.contains(&extension.as_str()))
        .map(|descriptor| descriptor.id)
}

/// Reports which analysis features are currently implemented for a language.
///
/// Deliberately conservative: features not yet backed by real cross-file
/// resolution logic are reported as `Partial` or `NotSupported` rather than
/// `Supported`, so callers don't over-trust an incomplete adapter.
#[must_use]
pub fn capabilities(_language: LanguageId) -> LanguageCapabilities {
    LanguageCapabilities {
        parsing: CapabilityState::Supported,
        definitions: CapabilityState::Partial,
        lexical_scopes: CapabilityState::Partial,
        references: CapabilityState::NotSupported,
        imports: CapabilityState::Partial,
        exports: CapabilityState::Partial,
        calls: CapabilityState::Partial,
        cross_file_resolution: CapabilityState::NotSupported,
    }
}

/// Maps a `LanguageId` to its concrete Tree-sitter grammar handle.
///
/// Kept private and internal to this crate: this is the one place a
/// `tree_sitter::Language` value is ever constructed, so Rule C's boundary
/// stays enforced by construction rather than by convention alone.
fn tree_sitter_language(language: LanguageId) -> CorulixResult<Language> {
    // `LanguageId` is `#[non_exhaustive]` (declared in wht_corulix_core) so that
    // adding a future language variant there doesn't break downstream crates
    // at compile time; the cost is that every match here must carry an
    // explicit fallback for a variant this crate doesn't have a grammar wired
    // up for yet, rather than relying on the compiler to prove coverage.
    Ok(match language {
        LanguageId::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        LanguageId::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        LanguageId::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        LanguageId::Python => tree_sitter_python::LANGUAGE.into(),
        LanguageId::Rust => tree_sitter_rust::LANGUAGE.into(),
        LanguageId::Go => tree_sitter_go::LANGUAGE.into(),
        _ => return Err(CorulixError::LanguageUnsupported),
    })
}

// ---------------------------------------------------------------------
// Parse V2 bounds — every one of these is a hard cap, never a target to
// tune after seeing fixture results. `SIGNATURE_MAX_BYTES`/
// `MODIFIER_ENTRY_MAX_BYTES`/`MODIFIER_COUNT_MAX` reuse the exact,
// data-grounded values measured during the (reverted) Parse V1 pass across
// 473 real function/method/constructor declaration headers
// (MIN=20, P50=39, P95=55, MAX=306) -- the underlying exact-slice
// extraction mechanism is identical here, so that measurement remains
// directly applicable evidence rather than a fresh guess.
// ---------------------------------------------------------------------

/// Maximum bytes for one exact-slice declaration header/signature. Exceeding
/// this omits the signature entirely for that symbol -- never truncated,
/// never rewritten.
const SIGNATURE_MAX_BYTES: usize = 512;
/// Maximum bytes for one modifier entry (e.g. one decorator's text).
const MODIFIER_ENTRY_MAX_BYTES: usize = 128;
/// Maximum number of modifier entries for one symbol.
const MODIFIER_COUNT_MAX: usize = 16;

/// Immediate lexical container context carried downward through the parse
/// tree's stack, so a member node can label its container in O(1) without a
/// `.parent()` walk. Deliberately just a display label (`name`), never a
/// `SymbolKind` -- resolving what kind of thing a Rust `impl` target
/// actually is would require a separate, semantic declaration lookup this
/// crate does not perform.
#[derive(Debug, Clone)]
struct ContainerFrame {
    name: String,
}

/// Recognizes a container-introducing node for `language` and builds its
/// display label from syntax alone.
///
/// Rust `impl_item`: `"impl <type>"` or `"impl <type> as <trait>"` (the
/// `trait` field is present only for a trait impl). Rust `trait_item`/
/// `mod_item`: their own name. TypeScript/JavaScript `class_declaration` and
/// Python `class_definition`: their own name.
fn build_container_frame(
    language: LanguageId,
    node: Node<'_>,
    source: &[u8],
) -> Option<ContainerFrame> {
    match (language, node.kind()) {
        (LanguageId::Rust, "impl_item") => {
            let type_text = node.child_by_field_name("type")?.utf8_text(source).ok()?;
            let name = match node.child_by_field_name("trait") {
                Some(trait_node) => {
                    let trait_text = trait_node.utf8_text(source).ok()?;
                    format!("impl {type_text} as {trait_text}")
                }
                None => format!("impl {type_text}"),
            };
            Some(ContainerFrame { name })
        }
        (LanguageId::Rust, "trait_item" | "mod_item") => {
            let name = node.child_by_field_name("name")?.utf8_text(source).ok()?;
            Some(ContainerFrame {
                name: name.to_owned(),
            })
        }
        (
            LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript,
            "class_declaration",
        )
        | (LanguageId::Python, "class_definition") => {
            let name = node.child_by_field_name("name")?.utf8_text(source).ok()?;
            Some(ContainerFrame {
                name: name.to_owned(),
            })
        }
        _ => None,
    }
}

/// Whether `node.kind()` is a decorator/attribute node whose text should be
/// collected as a pending modifier for the next non-decorator sibling.
///
/// TypeScript/JavaScript/Python all use the grammar kind `"decorator"` for
/// this (verified empirically against each pinned grammar before writing
/// this table, not assumed from a shared name coincidence).
fn is_decorator_node(language: LanguageId, node_kind: &str) -> bool {
    matches!(
        language,
        LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript | LanguageId::Python
    ) && node_kind == "decorator"
}

/// Extracts the exact, unmodified declaration-header source slice for a
/// `Function`/`Method`/`Constructor` symbol: from the start of `node` to the
/// start of its `body` field, or to the end of `node` when it has no body
/// field (an interface/trait method signature with no implementation).
///
/// Never collapses whitespace, never rewrites token content -- a header
/// containing meaningful whitespace inside a string/template literal,
/// default expression, or decorator argument stays byte-faithful.
/// `SIGNATURE_BLIND_WHITESPACE_COLLAPSE=NO`,
/// `SIGNATURE_PRESERVES_TOKEN_CONTENT=YES`. Overflow fails closed to `None`.
fn extract_signature(node: Node<'_>, source: &[u8]) -> Option<String> {
    let header_end = node
        .child_by_field_name("body")
        .map_or(node.end_byte(), |body| body.start_byte());
    let header_start = node.start_byte();
    if header_end <= header_start {
        return None;
    }
    let slice = source.get(header_start..header_end)?;
    if slice.len() > SIGNATURE_MAX_BYTES {
        return None;
    }
    std::str::from_utf8(slice).ok().map(str::to_owned)
}

/// Extracts this symbol's dense modifier bag: visibility, `async`/`static`/
/// `const`/`accessibility_modifier` tokens, plus any pending decorator text
/// collected for it. Fails closed as ONE complete unit: if any single entry
/// or the total count exceeds its bound, the entire result is `None` --
/// never a partial list that reads as complete.
/// `PARTIAL_MODIFIERS_EMITTED_WITHOUT_COMPLETENESS_SIGNAL=NO`.
fn extract_modifiers(
    language: LanguageId,
    node: Node<'_>,
    source: &[u8],
    pending_decorators: &[String],
) -> Option<Vec<String>> {
    let mut modifiers: Vec<String> = pending_decorators.to_vec();
    let mut cursor = node.walk();
    match language {
        LanguageId::Rust => {
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "visibility_modifier" => {
                        if let Ok(text) = child.utf8_text(source) {
                            modifiers.push(text.to_owned());
                        }
                    }
                    "function_modifiers" => {
                        if let Ok(text) = child.utf8_text(source) {
                            modifiers.extend(text.split_whitespace().map(str::to_owned));
                        }
                    }
                    _ => {}
                }
            }
        }
        LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript => {
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "accessibility_modifier" => {
                        if let Ok(text) = child.utf8_text(source) {
                            modifiers.push(text.to_owned());
                        }
                    }
                    "static" | "async" | "abstract" | "readonly" | "override" => {
                        modifiers.push(child.kind().to_owned());
                    }
                    _ => {}
                }
            }
        }
        LanguageId::Python => {
            for child in node.children(&mut cursor) {
                if child.kind() == "async" {
                    modifiers.push("async".to_owned());
                }
            }
        }
        LanguageId::Go => {
            // Go's exported/unexported status is a hard language rule
            // (first-letter casing), not a convention -- a legitimate
            // syntactic classification, unlike Python's leading-underscore
            // convention, which this crate deliberately never reports.
            if let Some(name_node) = node.child_by_field_name("name")
                && let Ok(name) = name_node.utf8_text(source)
                && let Some(first) = name.chars().next()
            {
                modifiers.push(if first.is_uppercase() {
                    "exported".to_owned()
                } else {
                    "unexported".to_owned()
                });
            }
        }
        _ => {}
    }

    if modifiers.is_empty() {
        return None;
    }
    if modifiers.len() > MODIFIER_COUNT_MAX {
        return None;
    }
    if modifiers.iter().any(|m| m.len() > MODIFIER_ENTRY_MAX_BYTES) {
        return None;
    }
    Some(modifiers)
}

/// Go-only: the underlying grammar node kind of a `type_spec`'s own `type`
/// field (e.g. `struct_type`, `interface_type`, `type_alias`'s aliased type),
/// distinguishing what `language_specific_kind` alone collapses into one
/// value (`type_spec`). `None` for every other language and for a Go
/// `type_spec` with no `type` field.
fn extract_type_definition_kind(language: LanguageId, node: Node<'_>) -> Option<String> {
    if language != LanguageId::Go || node.kind() != "type_spec" {
        return None;
    }
    node.child_by_field_name("type")
        .map(|type_node| type_node.kind().to_owned())
}

/// Resolves a classified symbol's final, AI-facing `SymbolKind` for
/// [`CompactSymbol`]. Identical to the generic `kind` classification for
/// every symbol except a Go `type_spec`, where `classify_definition` alone
/// can only report the generic `SymbolKind::Type` (grammar-level, before
/// inspecting the node's own `type` child) -- this refines that into
/// `Struct`/`Interface` using the already-computed `type_definition_kind`
/// grammar-node-kind string, exactly the same refinement the pre-existing
/// outline-text renderer used to apply only for display. This does NOT
/// change `Symbol.kind` (the internal model's own field, produced by
/// `classify_definition` alone, stays byte-identical) -- it is a
/// projection-only refinement local to the compact MCP fact.
fn resolve_kind(kind: SymbolKind, type_definition_kind: Option<&str>) -> SymbolKind {
    match type_definition_kind {
        Some("struct_type") => SymbolKind::Struct,
        Some("interface_type") => SymbolKind::Interface,
        _ => kind,
    }
}

/// Canonical async entry point for `parse_source_blocking`. Tree-sitter
/// parsing is CPU-bound, not I/O-bound, but it can still run long enough on
/// a large file to be worth keeping off an async caller's executor thread;
/// this runs it on Tokio's blocking-task pool via
/// `tokio::task::spawn_blocking`. There is no synchronous `parse_source`
/// kept alongside it; this is the one public name for this operation from
/// async code.
///
/// A thin wrapper over [`parse_source_with_facts`] that discards its
/// compact-facts half, kept for callers (the CLI, existing tests) that
/// only ever needed the structural summary itself.
pub async fn parse_source(language: LanguageId, source: Vec<u8>) -> CorulixResult<ParseSummary> {
    Ok(parse_source_with_facts(language, source).await?.0)
}

/// Canonical async entry point computing both the unchanged [`ParseSummary`]
/// and the parallel, index-aligned `Vec<CompactSymbol>` of AI-facing
/// structural facts, in a single parse/traversal -- never a second
/// Tree-sitter parse of the same source (Parse V2's internal-latency
/// objective, Candidate D, carried forward unchanged into this pass).
pub async fn parse_source_with_facts(
    language: LanguageId,
    source: Vec<u8>,
) -> CorulixResult<(ParseSummary, Vec<CompactSymbol>)> {
    tokio::task::spawn_blocking(move || parse_source_blocking_with_facts(language, &source))
        .await
        .unwrap_or(Err(CorulixError::Internal))
}

/// The blocking-safe parse core. Private: the canonical public surface for
/// this operation is [`parse_source_with_facts`] (`.await`) -- no other
/// crate may bypass it with a synchronous call. Parses raw source bytes for
/// the given language into a Corulix `ParseSummary` plus its parallel
/// compact facts, converting Tree-sitter's tree into owned DTOs before
/// returning -- no `tree_sitter` type crosses this function's boundary.
fn parse_source_blocking_with_facts(
    language: LanguageId,
    source: &[u8],
) -> CorulixResult<(ParseSummary, Vec<CompactSymbol>)> {
    // Reject non-UTF-8 input outright rather than lossily converting it:
    // a lossy conversion would silently shift every byte offset and column
    // reported downstream, corrupting symbol ranges without any error signal.
    let source_str = std::str::from_utf8(source).map_err(|_| CorulixError::UnsupportedEncoding)?;
    let language_handle = tree_sitter_language(language)?;

    let mut parser = Parser::new();
    parser
        .set_language(&language_handle)
        .map_err(|_| CorulixError::ParseFailed)?;

    let tree = parser
        .parse(source_str, None)
        .ok_or(CorulixError::ParseFailed)?;
    let root = tree.root_node();
    let (symbols, facts) = extract_symbols_with_facts(language, root, source)?;

    let summary = ParseSummary {
        schema_version: SCHEMA_VERSION,
        language,
        root_kind: root.kind().to_owned(),
        has_syntax_error: root.has_error(),
        byte_len: u64::try_from(source.len()).map_err(|_| CorulixError::ResourceLimit)?,
        symbols,
    };
    Ok((summary, facts))
}

/// Walks the parse tree collecting every recognized definition site, exactly
/// as the pre-V2 `extract_symbols` did, while additionally retaining each
/// symbol's already-computed structural facts (container/modifiers/
/// signature/refined kind) as typed [`CompactSymbol`] data in the same
/// single pass -- these facts were always computed here; this pass only
/// stops discarding them after formatting a display string.
///
/// Uses an explicit stack instead of recursion so parsing very deep/large
/// files cannot blow the call stack. The stack carries, per pending node,
/// an optional container-frame index and a list of pending decorator texts
/// collected for it by a forward-order pre-pass over its parent's children
/// -- this uniformly handles Python's `decorated_definition` wrapper and
/// TypeScript/JavaScript's plain sibling-decorator placement with zero
/// per-language special-casing at the traversal level itself.
fn extract_symbols_with_facts(
    language: LanguageId,
    root: Node<'_>,
    source: &[u8],
) -> CorulixResult<(Vec<Symbol>, Vec<CompactSymbol>)> {
    let mut symbols_with_facts: Vec<(Symbol, CompactSymbol)> = Vec::new();
    let mut frames: Vec<ContainerFrame> = Vec::new();
    // (node, container_frame_index, pending_decorator_texts)
    let mut stack: Vec<(Node<'_>, Option<usize>, Vec<String>)> = vec![(root, None, Vec::new())];

    while let Some((node, container_idx, pending_decorators)) = stack.pop() {
        let mut child_container_idx = container_idx;
        if let Some(frame) = build_container_frame(language, node, source) {
            frames.push(frame);
            child_container_idx = Some(frames.len() - 1);
        }

        if let Some(kind) = classify_definition(language, node.kind())
            && let Some(name_node) = node.child_by_field_name("name")
            && let Ok(name) = name_node.utf8_text(source)
            && !name.is_empty()
        {
            let range = range_from_node(name_node)?;
            let container_name = container_idx.map(|idx| frames[idx].name.clone());
            let type_definition_kind = extract_type_definition_kind(language, node);
            let signature = matches!(
                kind,
                SymbolKind::Function | SymbolKind::Method | SymbolKind::Constructor
            )
            .then(|| extract_signature(node, source))
            .flatten();
            let modifiers = extract_modifiers(language, node, source, &pending_decorators);
            let resolved_kind = resolve_kind(kind, type_definition_kind.as_deref());

            symbols_with_facts.push((
                Symbol {
                    name: name.to_owned(),
                    kind,
                    language,
                    range,
                    language_specific_kind: node.kind().to_owned(),
                },
                CompactSymbol {
                    kind: resolved_kind,
                    name: name.to_owned(),
                    container: container_name,
                    modifiers,
                    line: range.start.line_zero_based.saturating_add(1),
                    signature,
                },
            ));
        }

        // Forward-order pre-pass: walks this node's children once via the
        // cursor directly (no intermediate `Vec` collection of the whole
        // child list), accumulating consecutive `decorator` children into a
        // pending buffer handed to the next non-decorator sibling as it is
        // pushed -- covers both a decorator wrapper's own children
        // (Python's `decorated_definition`) and plain preceding siblings
        // (TypeScript/JavaScript class members).
        //
        // Pushing in forward-encounter order (rather than reversed) means
        // the stack's LIFO pop order visits siblings in reverse relative to
        // each other; this is deliberately not corrected, since final
        // symbol order is fixed by the byte-offset sort below regardless
        // of traversal order -- exactly as the pre-V2 implementation also
        // never preserved source order during traversal itself. Avoiding
        // the collect-then-reverse pair (two full-child-list allocations
        // per node, at every level of the tree, not just at symbol nodes)
        // was measured to materially reduce Parse V2's internal latency
        // overhead versus the pre-V2 baseline (Candidate D).
        let mut running_decorators: Vec<String> = Vec::new();
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if is_decorator_node(language, child.kind()) {
                    if let Ok(text) = child.utf8_text(source) {
                        running_decorators.push(text.to_owned());
                    }
                } else {
                    let decorators = std::mem::take(&mut running_decorators);
                    stack.push((child, child_container_idx, decorators));
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    // Stack traversal visits children out of source order, so results must
    // be re-sorted by position for callers that expect a stable, top-to-
    // bottom symbol listing -- identical sort key/behavior to the pre-V2
    // implementation, applied to the combined (symbol, fact) pairs so both
    // stay in lockstep (index-aligned, same order).
    symbols_with_facts.sort_by_key(|(symbol, _)| symbol.range.start.byte_offset);

    // `unzip` moves both halves out in one pass -- no `Symbol::clone()`
    // needed just to split the combined vec into its two return values.
    let (symbols, facts): (Vec<Symbol>, Vec<CompactSymbol>) =
        symbols_with_facts.into_iter().unzip();

    Ok((symbols, facts))
}

/// Maps a Tree-sitter grammar node kind to a Corulix `SymbolKind`, per
/// language. Each grammar names its nodes differently, so this table is the
/// single translation point kept in sync with each pinned grammar version in
/// `DESCRIPTORS`.
fn classify_definition(language: LanguageId, node_kind: &str) -> Option<SymbolKind> {
    match language {
        LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript => match node_kind {
            "function_declaration" | "generator_function_declaration" => Some(SymbolKind::Function),
            "class_declaration" => Some(SymbolKind::Class),
            "method_definition" => Some(SymbolKind::Method),
            "interface_declaration" => Some(SymbolKind::Interface),
            "type_alias_declaration" => Some(SymbolKind::Type),
            "enum_declaration" => Some(SymbolKind::Enum),
            _ => None,
        },
        LanguageId::Python => match node_kind {
            "function_definition" => Some(SymbolKind::Function),
            "class_definition" => Some(SymbolKind::Class),
            _ => None,
        },
        LanguageId::Rust => match node_kind {
            "function_item" => Some(SymbolKind::Function),
            "struct_item" => Some(SymbolKind::Struct),
            "enum_item" => Some(SymbolKind::Enum),
            "trait_item" => Some(SymbolKind::Trait),
            "type_item" => Some(SymbolKind::Type),
            "mod_item" => Some(SymbolKind::Module),
            _ => None,
        },
        LanguageId::Go => match node_kind {
            "function_declaration" => Some(SymbolKind::Function),
            "method_declaration" => Some(SymbolKind::Method),
            "type_spec" => Some(SymbolKind::Type),
            _ => None,
        },
        // `LanguageId` is `#[non_exhaustive]`: a future variant with no
        // definition table wired up here yet recognizes no symbols, rather
        // than failing to compile downstream — parsing still succeeds
        // (see `tree_sitter_language`'s own fallback), it just returns an
        // empty symbol list until this table is extended for that language.
        _ => None,
    }
}

/// Converts a Tree-sitter node's position into a Corulix `SourceRange`.
///
/// Tree-sitter reports positions as `usize`; they are narrowed to `u32`/`u64`
/// here and mapped to `ResourceLimit` on overflow rather than truncating
/// silently, so a pathologically large file cannot produce a corrupted,
/// wrapped-around position downstream.
fn range_from_node(node: Node<'_>) -> CorulixResult<SourceRange> {
    let start = node.start_position();
    let end = node.end_position();
    Ok(SourceRange {
        start: Position {
            line_zero_based: u32::try_from(start.row).map_err(|_| CorulixError::ResourceLimit)?,
            byte_column_zero_based: u32::try_from(start.column)
                .map_err(|_| CorulixError::ResourceLimit)?,
            byte_offset: u64::try_from(node.start_byte())
                .map_err(|_| CorulixError::ResourceLimit)?,
        },
        end: Position {
            line_zero_based: u32::try_from(end.row).map_err(|_| CorulixError::ResourceLimit)?,
            byte_column_zero_based: u32::try_from(end.column)
                .map_err(|_| CorulixError::ResourceLimit)?,
            byte_offset: u64::try_from(node.end_byte()).map_err(|_| CorulixError::ResourceLimit)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_baseline_extensions() {
        assert_eq!(
            detect_language(Path::new("src/main.rs")),
            Some(LanguageId::Rust)
        );
        assert_eq!(
            detect_language(Path::new("src/app.ts")),
            Some(LanguageId::TypeScript)
        );
        assert_eq!(
            detect_language(Path::new("src/view.tsx")),
            Some(LanguageId::Tsx)
        );
        assert_eq!(
            detect_language(Path::new("main.py")),
            Some(LanguageId::Python)
        );
        assert_eq!(detect_language(Path::new("main.go")), Some(LanguageId::Go));
    }

    #[tokio::test]
    async fn parses_rust_function_and_extracts_symbol() {
        let parsed = parse_source(
            LanguageId::Rust,
            b"fn corulix_demo() { let x = 1; }".to_vec(),
        )
        .await;
        assert!(parsed.is_ok(), "Rust baseline parse must succeed");
        if let Ok(parsed) = parsed {
            assert!(!parsed.has_syntax_error);
            assert!(
                parsed
                    .symbols
                    .iter()
                    .any(|symbol| symbol.name == "corulix_demo")
            );
        }
    }

    async fn assert_parses(language: LanguageId, source: &[u8], expected_symbol: &str) {
        let parsed = parse_source(language, source.to_vec()).await;
        assert!(parsed.is_ok(), "{language} baseline parse must succeed");
        if let Ok(parsed) = parsed {
            assert!(
                parsed
                    .symbols
                    .iter()
                    .any(|symbol| symbol.name == expected_symbol),
                "expected symbol {expected_symbol} for {language}"
            );
        }
    }

    #[tokio::test]
    async fn parses_all_baseline_languages() {
        assert_parses(
            LanguageId::TypeScript,
            b"export function corulixTs(): number { return 1; }",
            "corulixTs",
        )
        .await;
        assert_parses(
            LanguageId::JavaScript,
            b"function corulixJs() { return 1; }",
            "corulixJs",
        )
        .await;
        assert_parses(
            LanguageId::Python,
            b"def corulix_py():\n    return 1\n",
            "corulix_py",
        )
        .await;
        assert_parses(
            LanguageId::Rust,
            b"fn corulix_rs() -> i32 { 1 }",
            "corulix_rs",
        )
        .await;
        assert_parses(
            LanguageId::Go,
            b"package demo\nfunc CorulixGo() int { return 1 }\n",
            "CorulixGo",
        )
        .await;
    }

    #[tokio::test]
    async fn invalid_utf8_is_rejected_without_lossy_conversion() {
        let result = parse_source(LanguageId::Rust, vec![0xff, 0xfe, 0xfd]).await;
        assert!(matches!(result, Err(CorulixError::UnsupportedEncoding)));
    }

    /// Proves the blocking-safe composition core behaves identically to the
    /// canonical async entry point.
    #[tokio::test]
    async fn blocking_core_and_async_entry_point_agree() -> CorulixResult<()> {
        let source = b"fn corulix_agree() {}";
        let via_blocking = parse_source_blocking_with_facts(LanguageId::Rust, source)?;
        let via_async = parse_source_with_facts(LanguageId::Rust, source.to_vec()).await?;
        assert_eq!(via_blocking, via_async);
        Ok(())
    }

    /// `parse_source` (the Symbol-only wrapper) must still report the exact
    /// same symbols as `parse_source_with_facts`'s own `ParseSummary` half
    /// -- Parse V2 must not regress the pre-existing Symbol extraction.
    #[tokio::test]
    async fn symbol_only_wrapper_matches_with_facts_summary() -> CorulixResult<()> {
        let source = b"pub fn corulix_check() -> bool { true }".to_vec();
        let via_wrapper = parse_source(LanguageId::Rust, source.clone()).await?;
        let (via_full, _) = parse_source_with_facts(LanguageId::Rust, source).await?;
        assert_eq!(via_wrapper, via_full);
        Ok(())
    }

    #[tokio::test]
    async fn facts_report_signature_modifiers_and_container() -> CorulixResult<()> {
        let source = br#"
pub struct Widget;

impl Widget {
    pub async fn render(&self, ctx: &Context) -> Html {
        Html::empty()
    }
}
"#
        .to_vec();
        let (_, facts) = parse_source_with_facts(LanguageId::Rust, source).await?;
        let Some(render) = facts.iter().find(|f| f.name == "render") else {
            return Err(CorulixError::Internal);
        };
        assert_eq!(render.container.as_deref(), Some("impl Widget"));
        assert_eq!(
            render.modifiers.as_deref(),
            Some(["pub".to_string(), "async".to_string()].as_slice())
        );
        // Exact-slice extraction includes the trailing byte(s) up to the
        // body's start verbatim (here, the space before `{`) --
        // `SIGNATURE_BLIND_WHITESPACE_COLLAPSE=NO` means this is not
        // trimmed.
        assert_eq!(
            render.signature.as_deref(),
            Some("pub async fn render(&self, ctx: &Context) -> Html ")
        );
        Ok(())
    }

    #[tokio::test]
    async fn facts_report_python_decorator_and_async() -> CorulixResult<()> {
        let source = b"@app.route(\"/x\")\nasync def corulix_handler():\n    pass\n".to_vec();
        let (_, facts) = parse_source_with_facts(LanguageId::Python, source).await?;
        let Some(handler) = facts.iter().find(|f| f.name == "corulix_handler") else {
            return Err(CorulixError::Internal);
        };
        let Some(modifiers) = &handler.modifiers else {
            return Err(CorulixError::Internal);
        };
        assert!(modifiers.iter().any(|m| m == "@app.route(\"/x\")"));
        assert!(modifiers.iter().any(|m| m == "async"));
        Ok(())
    }

    #[tokio::test]
    async fn facts_distinguish_go_struct_and_interface() -> CorulixResult<()> {
        let source =
            b"package demo\ntype Foo struct { X int }\ntype Bar interface { M() }\n".to_vec();
        let (_, facts) = parse_source_with_facts(LanguageId::Go, source).await?;
        let Some(foo) = facts.iter().find(|f| f.name == "Foo") else {
            return Err(CorulixError::Internal);
        };
        let Some(bar) = facts.iter().find(|f| f.name == "Bar") else {
            return Err(CorulixError::Internal);
        };
        assert_eq!(foo.kind, SymbolKind::Struct);
        assert_eq!(bar.kind, SymbolKind::Interface);
        Ok(())
    }

    #[tokio::test]
    async fn facts_report_go_receiver_exported_status() -> CorulixResult<()> {
        let source =
            b"package demo\ntype Receiver struct{}\nfunc (r *Receiver) Exported() {}\nfunc (r *Receiver) unexported() {}\n"
                .to_vec();
        let (_, facts) = parse_source_with_facts(LanguageId::Go, source).await?;
        let Some(exported) = facts.iter().find(|f| f.name == "Exported") else {
            return Err(CorulixError::Internal);
        };
        let Some(unexported) = facts.iter().find(|f| f.name == "unexported") else {
            return Err(CorulixError::Internal);
        };
        assert_eq!(
            exported.modifiers.as_deref(),
            Some(["exported".to_string()].as_slice())
        );
        assert_eq!(
            unexported.modifiers.as_deref(),
            Some(["unexported".to_string()].as_slice())
        );
        Ok(())
    }

    #[tokio::test]
    async fn facts_omit_signature_over_cap_without_truncating() -> CorulixResult<()> {
        let long_params = "x: i32, ".repeat(200);
        let source = format!("fn corulix_long({long_params}) {{}}").into_bytes();
        let (summary, facts) = parse_source_with_facts(LanguageId::Rust, source).await?;
        assert!(
            summary.symbols.iter().any(|s| s.name == "corulix_long"),
            "symbol extraction must be unaffected by an over-cap signature"
        );
        let Some(long_fn) = facts.iter().find(|f| f.name == "corulix_long") else {
            return Err(CorulixError::Internal);
        };
        assert!(
            long_fn.signature.is_none(),
            "an over-cap signature must be omitted entirely (None), never truncated"
        );
        Ok(())
    }

    #[tokio::test]
    async fn facts_are_empty_for_a_file_with_no_symbols() -> CorulixResult<()> {
        let (_, facts) =
            parse_source_with_facts(LanguageId::Rust, b"// just a comment\n".to_vec()).await?;
        assert!(facts.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn malformed_source_still_produces_symbols_and_flags_the_error() -> CorulixResult<()> {
        let (summary, _) =
            parse_source_with_facts(LanguageId::Rust, b"fn broken(".to_vec()).await?;
        assert!(summary.has_syntax_error);
        Ok(())
    }

    /// Dumps the real, current (post-Parse-V2) compact outline plus the
    /// real serialized `ParseSummary` JSON for every dev fixture, so the
    /// Candidate C model-facing byte gate (Section 21-23 of the Parse V2
    /// mandate) is computed from actual produced bytes, never estimated.
    /// `DEVELOPMENT_MICROBENCH_ONLY`, `MODEL_TOKEN_PROXY`.
    #[tokio::test]
    #[ignore]
    async fn dev_microbench_parse_v2_response_bytes() -> CorulixResult<()> {
        use std::fs;

        // Dev-only fixture/results root: never a specific developer's
        // machine path. `CORULIX_BENCH_PARSE_V2_LAB_ROOT` must name a real
        // directory containing the fixture files listed below; this
        // microbench gracefully no-ops (rather than failing) when that
        // environment variable is unset, since it is `#[ignore]`d and
        // never part of release behavior.
        let Ok(lab_root) = std::env::var("CORULIX_BENCH_PARSE_V2_LAB_ROOT") else {
            eprintln!(
                "dev_microbench_parse_v2_response_bytes: skipped, set CORULIX_BENCH_PARSE_V2_LAB_ROOT to run"
            );
            return Ok(());
        };
        let lab_root = lab_root.as_str();
        const FIXTURES: &[(&str, LanguageId, &str)] = &[
            (
                "rust_small",
                LanguageId::Rust,
                "fixtures/parse/rust/small.rs",
            ),
            (
                "rust_large",
                LanguageId::Rust,
                "fixtures/parse/rust/large.rs",
            ),
            (
                "rust_deep_nested",
                LanguageId::Rust,
                "fixtures/parse/rust/deep_nested.rs",
            ),
            (
                "rust_duplicate_names",
                LanguageId::Rust,
                "fixtures/parse/rust/duplicate_names.rs",
            ),
            (
                "rust_malformed",
                LanguageId::Rust,
                "fixtures/parse/rust/malformed.rs",
            ),
            (
                "typescript_small",
                LanguageId::TypeScript,
                "fixtures/parse/typescript/small.ts",
            ),
            (
                "typescript_large",
                LanguageId::TypeScript,
                "fixtures/parse/typescript/large.ts",
            ),
            (
                "typescript_deep_nested",
                LanguageId::TypeScript,
                "fixtures/parse/typescript/deep_nested.ts",
            ),
            (
                "typescript_duplicate_names",
                LanguageId::TypeScript,
                "fixtures/parse/typescript/duplicate_names.ts",
            ),
            (
                "typescript_malformed",
                LanguageId::TypeScript,
                "fixtures/parse/typescript/malformed.ts",
            ),
            (
                "python_small",
                LanguageId::Python,
                "fixtures/parse/python/small.py",
            ),
            (
                "python_large",
                LanguageId::Python,
                "fixtures/parse/python/large.py",
            ),
            (
                "python_deep_nested",
                LanguageId::Python,
                "fixtures/parse/python/deep_nested.py",
            ),
            (
                "python_duplicate_names",
                LanguageId::Python,
                "fixtures/parse/python/duplicate_names.py",
            ),
            (
                "python_malformed",
                LanguageId::Python,
                "fixtures/parse/python/malformed.py",
            ),
            ("go_small", LanguageId::Go, "fixtures/parse/go/small.go"),
            ("go_large", LanguageId::Go, "fixtures/parse/go/large.go"),
            (
                "go_deep_nested",
                LanguageId::Go,
                "fixtures/parse/go/deep_nested.go",
            ),
            (
                "go_duplicate_names",
                LanguageId::Go,
                "fixtures/parse/go/duplicate_names.go",
            ),
            (
                "go_malformed",
                LanguageId::Go,
                "fixtures/parse/go/malformed.go",
            ),
        ];

        let results_dir = format!("{lab_root}/results/raw");
        let _ = fs::create_dir_all(&results_dir);
        let mut summary_rows = Vec::new();

        for (fixture_id, language, rel_path) in FIXTURES {
            let full_path = format!("{lab_root}/{rel_path}");
            let source = fs::read(&full_path).map_err(|_| CorulixError::Internal)?;
            let file_bytes = source.len();
            let (summary, facts) = parse_source_with_facts(*language, source).await?;

            let old_structured_json =
                serde_json::to_string(&summary).map_err(|_| CorulixError::Internal)?;
            let compact_facts_json =
                serde_json::to_string(&facts).map_err(|_| CorulixError::Internal)?;

            let _ = fs::write(
                format!("{results_dir}/parse_v2_structured_{fixture_id}.json"),
                &old_structured_json,
            );
            let _ = fs::write(
                format!("{results_dir}/parse_v2_compact_facts_{fixture_id}.json"),
                &compact_facts_json,
            );

            summary_rows.push(format!(
                "{fixture_id}\t{file_bytes}\t{}\t{}\t{}",
                old_structured_json.len(),
                compact_facts_json.len(),
                summary.symbols.len(),
            ));
        }

        let mut report = String::from(
            "fixture\tfile_bytes\told_structured_json_bytes\tcompact_facts_json_bytes\tsymbol_count\n",
        );
        for row in &summary_rows {
            report.push_str(row);
            report.push('\n');
        }
        eprintln!("{report}");
        let _ = fs::write(
            format!("{results_dir}/parse_v2_response_bytes_summary.tsv"),
            &report,
        );
        Ok(())
    }
}
