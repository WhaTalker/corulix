// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Anchor-role classification for TypeScript-family rename-anchor
//! canonicalization (Corulix 1.0.0 M03 rename_preview AST-based anchor
//! classification pass).
//!
//! This module answers exactly one question, from real parsed syntax only
//! (never a textual/line-based heuristic -- `TEXTUAL_HEURISTIC_AUTHORITY_USED=NO`):
//! what syntactic role does the identifier-like token at a given byte
//! offset occupy? [`crate::classify_definition`] (this crate's existing,
//! `parse_file`-facing table) only recognizes declaration-introducing node
//! kinds for building the top-level symbol outline; it has no reason to
//! know about import/export specifiers or alias-binding positions, so this
//! module is deliberately a separate, additional classifier rather than an
//! extension of that table -- it answers a different question (the role of
//! an arbitrary *occurrence*, not "is this node a definition site").
//!
//! Reuses this crate's one existing grammar-registration point
//! ([`crate::tree_sitter_language`]) rather than duplicating it, so every
//! pinned grammar version stays declared in exactly one place
//! ([`crate::DESCRIPTORS`]).
//!
//! Structural-only, exactly like the rest of this crate (Architecture Rule
//! C/L): this module never resolves what a symbol *means* or where else it
//! is used -- it only classifies the syntax immediately around one
//! position. Semantic resolution (`textDocument/definition`) and the
//! decision of whether to act on that resolution remain `wht_corulix_lsp`'s
//! authority alone.

use tree_sitter::Node;
use wht_corulix_core::{CorulixError, CorulixResult, LanguageId};

/// The syntactic role of one identifier-like occurrence, used to decide
/// whether TypeScript-family `rename_preview` may safely redirect the
/// request to a canonical declaration before issuing the rename, or must
/// preserve the provider's own rename intent at the original anchor.
///
/// `#[non_exhaustive]`: a future grammar refinement may need a new variant
/// without breaking an existing exhaustive match downstream.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorRole {
    /// An ordinary value/call use of a symbol (a `call_expression`'s
    /// function identifier, a bare reference, a JSX-expression identifier,
    /// ...). The only role eligible for canonical-declaration redirect.
    ValueUsage,
    /// The name of a declaration site itself (function/class/method/
    /// interface/type-alias/enum/variable-declarator/parameter). Renaming
    /// here is already a declaration-anchored rename; never redirected.
    DeclarationBinding,
    /// An import specifier's original/remote name, a default-import
    /// binding, or a namespace-import binding. Preserves the provider's
    /// own local rename intent.
    ImportBinding,
    /// An import specifier's local alias name (`import { x as local }`,
    /// the `local` token). Preserves the provider's own local-alias rename
    /// intent -- distinct from `ImportBinding` because Section 10's
    /// explicit-alias-intent question depends on telling these two apart.
    ImportAliasBinding,
    /// An export specifier's local or exported-as name. Preserves the
    /// provider's own local rename intent, mirroring `ImportBinding`.
    ExportBinding,
    /// A type-position identifier (a type annotation/type reference).
    /// Not proven safe to canonicalize this pass; preserves provider-native
    /// behavior.
    TypePosition,
    /// The classifier could not place the anchor in any of the above
    /// categories (an out-of-range offset, or a grammar node kind this
    /// module does not recognize). Fail-safe: never canonicalized.
    Unknown,
}

impl AnchorRole {
    /// Whether this role is eligible for canonical-declaration redirect --
    /// the single decision point the mandate's classification policy hinges
    /// on, kept as one authoritative method rather than repeating the same
    /// match at every call site.
    #[must_use]
    pub fn eligible_for_canonical_redirect(self) -> bool {
        matches!(self, AnchorRole::ValueUsage)
    }
}

/// Grammar node kinds whose `name`/`pattern` field is itself a declaration
/// site, shared verbatim across the TypeScript/TSX/JavaScript grammars
/// (verified empirically against the pinned grammars -- see
/// `scratch_ast_grammar_shape_probe` -- not assumed from a shared name
/// coincidence, mirroring this crate's own existing
/// `is_decorator_node` precedent for that same verification discipline).
const DECLARATION_NAME_HOLDERS: &[&str] = &[
    "function_declaration",
    "class_declaration",
    "method_definition",
    "interface_declaration",
    "type_alias_declaration",
    "enum_declaration",
    "variable_declarator",
    "required_parameter",
    "optional_parameter",
];

/// Returns whether `child` occupies field `field_name` on `parent`,
/// compared by stable node identity (`Node::id`) rather than relying on
/// `Node`'s `PartialEq` semantics, so this stays correct regardless of
/// exactly how that trait is implemented.
fn is_field(parent: Node<'_>, field_name: &str, child: Node<'_>) -> bool {
    parent
        .child_by_field_name(field_name)
        .is_some_and(|found| found.id() == child.id())
}

/// Classifies the syntactic role of the identifier-like node at
/// `byte_offset` in `source`, parsed as `language`.
///
/// Returns [`AnchorRole::Unknown`] (never an error) for an offset that does
/// not land inside a recognized identifier token, so callers always have a
/// fail-safe, non-canonicalizing answer rather than needing to handle a
/// missing classification separately from a deliberately unknown one.
///
/// Only meaningful for the TypeScript-family grammars this classifier has
/// been proven against (`TypeScript`/`Tsx`/`JavaScript`); returns
/// `Err(CorulixError::LanguageUnsupported)` for any other `language` so a
/// caller cannot silently misuse this against a language this module was
/// never validated for (`NON_TS_LANGUAGE_BEHAVIOR_MUTATED=NO` -- Rust,
/// Python, and Go rename behavior must stay byte-identical to before this
/// module existed).
pub fn classify_anchor_role(
    language: LanguageId,
    source: &str,
    byte_offset: u64,
) -> CorulixResult<AnchorRole> {
    if !matches!(
        language,
        LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript
    ) {
        return Err(CorulixError::LanguageUnsupported);
    }
    let language_handle = crate::tree_sitter_language(language)?;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language_handle)
        .map_err(|_| CorulixError::ParseFailed)?;
    let tree = parser
        .parse(source, None)
        .ok_or(CorulixError::ParseFailed)?;

    let offset = usize::try_from(byte_offset).map_err(|_| CorulixError::ResourceLimit)?;
    let Some(end) = offset.checked_add(1) else {
        return Ok(AnchorRole::Unknown);
    };
    if end > source.len() {
        return Ok(AnchorRole::Unknown);
    }

    let root = tree.root_node();
    let Some(node) = root.named_descendant_for_byte_range(offset, end) else {
        return Ok(AnchorRole::Unknown);
    };
    Ok(classify_node(node))
}

/// The pure, tree-only classification core, isolated from parsing/offset
/// validation so it can be unit-tested directly against a hand-built
/// position without re-deriving a byte offset each time.
fn classify_node(node: Node<'_>) -> AnchorRole {
    match node.kind() {
        "type_identifier" => return AnchorRole::TypePosition,
        "identifier" => {}
        // Deliberately conservative: a `property_identifier` (member-access
        // property, e.g. the `name` in `props.name`),
        // `shorthand_property_identifier` (object-literal shorthand), or any
        // other node kind this module has not proven a safe role for is
        // reported `Unknown` rather than defaulted to `ValueUsage` -- this
        // pass only proves the plain-identifier cases exercised by Section 7.
        _ => return AnchorRole::Unknown,
    }

    let Some(parent) = node.parent() else {
        return AnchorRole::ValueUsage;
    };

    match parent.kind() {
        "import_specifier" if is_field(parent, "alias", node) => AnchorRole::ImportAliasBinding,
        "import_specifier" => AnchorRole::ImportBinding,
        "namespace_import" | "import_clause" => AnchorRole::ImportBinding,
        "export_specifier" => AnchorRole::ExportBinding,
        kind if DECLARATION_NAME_HOLDERS.contains(&kind)
            && (is_field(parent, "name", node) || is_field(parent, "pattern", node)) =>
        {
            AnchorRole::DeclarationBinding
        }
        _ => AnchorRole::ValueUsage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role_at(source: &str, needle: &str) -> CorulixResult<AnchorRole> {
        let Some(offset) = source.find(needle) else {
            return Err(CorulixError::Internal);
        };
        classify_anchor_role(LanguageId::Tsx, source, offset as u64)
    }

    #[test]
    fn classifies_declaration_name() -> CorulixResult<()> {
        assert_eq!(
            role_at(
                "export function computeLabel(v: string) { return v; }",
                "computeLabel"
            )?,
            AnchorRole::DeclarationBinding
        );
        Ok(())
    }

    #[test]
    fn classifies_call_site_usage() -> CorulixResult<()> {
        assert_eq!(
            role_at("computeLabel(props.name);", "computeLabel")?,
            AnchorRole::ValueUsage
        );
        Ok(())
    }

    #[test]
    fn classifies_shorthand_import_specifier() -> CorulixResult<()> {
        assert_eq!(
            role_at("import { computeLabel } from \"./m\";", "computeLabel")?,
            AnchorRole::ImportBinding
        );
        Ok(())
    }

    #[test]
    fn classifies_explicit_alias_original_and_local_sides() -> CorulixResult<()> {
        let source = "import { computeLabel as localLabel } from \"./m\";";
        assert_eq!(role_at(source, "computeLabel")?, AnchorRole::ImportBinding);
        assert_eq!(
            role_at(source, "localLabel")?,
            AnchorRole::ImportAliasBinding
        );
        Ok(())
    }

    #[test]
    fn classifies_alias_usage_as_value_usage() -> CorulixResult<()> {
        assert_eq!(
            role_at(
                "import { computeLabel as localLabel } from \"./m\";\nlocalLabel(1);\n",
                "localLabel(1)"
            )?,
            AnchorRole::ValueUsage
        );
        Ok(())
    }

    #[test]
    fn classifies_default_import_binding() -> CorulixResult<()> {
        assert_eq!(
            role_at("import computeLabel from \"./m\";", "computeLabel")?,
            AnchorRole::ImportBinding
        );
        Ok(())
    }

    #[test]
    fn classifies_namespace_import_binding() -> CorulixResult<()> {
        assert_eq!(
            role_at("import * as mod from \"./m\";", "mod")?,
            AnchorRole::ImportBinding
        );
        Ok(())
    }

    #[test]
    fn classifies_export_specifier() -> CorulixResult<()> {
        assert_eq!(
            role_at(
                "const computeLabel = 1;\nexport { computeLabel };\n",
                "computeLabel };"
            )?,
            AnchorRole::ExportBinding
        );
        Ok(())
    }

    #[test]
    fn classifies_shadowed_local_decoy_declaration_and_usage() -> CorulixResult<()> {
        let source = "function other() {\n  const computeLabel = 1;\n  return computeLabel;\n}\n";
        assert_eq!(
            role_at(source, "computeLabel = 1")?,
            AnchorRole::DeclarationBinding
        );
        assert_eq!(role_at(source, "computeLabel;\n}")?, AnchorRole::ValueUsage);
        Ok(())
    }

    #[test]
    fn out_of_range_offset_is_unknown() -> CorulixResult<()> {
        let role = classify_anchor_role(LanguageId::Tsx, "const x = 1;", 9_999)?;
        assert_eq!(role, AnchorRole::Unknown);
        Ok(())
    }

    #[test]
    fn non_ts_family_language_is_rejected() {
        let result = classify_anchor_role(LanguageId::Rust, "fn x() {}", 0);
        assert!(matches!(result, Err(CorulixError::LanguageUnsupported)));
    }
}
