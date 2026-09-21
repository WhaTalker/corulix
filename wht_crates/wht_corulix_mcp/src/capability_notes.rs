// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

// `rmcp-macros`' `#[tool(description = ...)]` attribute parser rejects a
// bare path expression (confirmed empirically: "Unexpected type `path`"),
// so the live `#[tool(description = "...")]` literals in `lib.rs` cannot
// reference these constants directly -- they are copied verbatim instead,
// with `lib.rs`'s own test module asserting the live schema text matches
// these constants exactly (see `descriptions_match_capability_notes_source_of_truth`),
// so drift between the two copies fails a test rather than going unnoticed.
// This makes every constant here consumed only from test code, hence the
// module-wide allow below -- intentional, not a defect.
#![allow(dead_code)]

//! Capability-boundary text for the five MCP tools whose output is a
//! partial/gated view of something larger (`search`, `parse_file`,
//! `semantic`, `plan_operation`, `format_preview`). Each tool's
//! `*_DESCRIPTION` constant here is referenced directly by that tool's
//! `#[tool(description = ...)]` attribute in `lib.rs` (a plain path
//! expression -- `rmcp-macros`' `description` field is `Expr`-typed, see
//! `rmcp-macros-3.1.2/src/tool.rs:87`), so the exact bytes reviewed here
//! are the exact bytes a calling model sees in `tools/list`.
//!
//! Each `*_DESCRIPTION` is the tool's original one-line description plus
//! one boundary sentence (kept separately as `*_NOTE` for standalone
//! review/testing; a test below asserts every `*_DESCRIPTION` contains
//! its `*_NOTE` verbatim, so the two can never silently drift apart).
//!
//! Architectural role (Capability-Aware Tool Routing plan, Option B):
//! this module makes each tool's capability envelope explicit enough for
//! a calling model to reason about tool sufficiency on its own. Each note
//! states only what its own tool's output *is* and *is not* -- never what
//! a caller should do about what it isn't. A note must never name
//! another tool (Corulix's or the calling client's), never contain an
//! action verb directing next steps ("use", "then", "call", "prefer",
//! "fall back to"), and never reference a specific language or a specific
//! benchmark. The test module below enforces this mechanically (a small,
//! auditable forbidden-token scan -- not an NLP classifier).
//!
//! Every clause is traceable to a real DTO field or handler behavior (see
//! the frozen capability matrix, preserved in this pass's own internal
//! evidence archive: `routing_baseline_2026-09-06/CAPABILITY_MATRIX.md`,
//! outside the public source tree) -- never independently invented
//! wording. The 9 other tools (identity/
//! lifecycle tools) have no comparable "there is more you are not seeing"
//! boundary and therefore carry no note.

/// `search`'s boundary: text-level, bounded matches only -- confirmed
/// against `SearchOutcome`'s own shape (match location/snippet, never a
/// structural or semantic classification of what was matched).
pub(crate) const SEARCH_NOTE: &str =
    "Matches are bounded and text-level; does not resolve structural or semantic identity.";

pub(crate) const SEARCH_DESCRIPTION: &str = "Run a real, bounded, in-process text search across \
the workspace. Matches are bounded and text-level; does not resolve structural or semantic \
identity.";

/// `parse_file`'s boundary: declaration-level `CompactSymbol` facts only
/// (`kind`/`name`/`line`/`container`/`modifiers`/`signature`, each
/// `Option` failing closed to `None` rather than a partial value) --
/// confirmed against `ParseFileOutput::Ok`'s exact field list. Never
/// source text, never import/constant declarations, never resolved
/// inheritance/alias targets, and limited to whatever declaration
/// categories the per-language classification table recognizes.
pub(crate) const PARSE_FILE_NOTE: &str = "Declaration-level symbols only (kind, name, line, \
container/modifiers/signature where applicable); no source text, imports, module-level \
constants, or resolved inheritance/aliases.";

pub(crate) const PARSE_FILE_DESCRIPTION: &str = "Parse source into symbols + compact outline \
(syntax only). Declaration-level symbols only (kind, name, line, container/modifiers/signature \
where applicable); no source text, imports, module-level constants, or resolved \
inheritance/aliases.";

/// `semantic`'s boundary: entirely gated on live language-server
/// provider availability -- confirmed against `SemanticOutcome`'s
/// `Unavailable` variant, which the handler returns explicitly rather
/// than approximating an answer.
pub(crate) const SEMANTIC_NOTE: &str = "Requires a live language-server provider per language; \
returns an explicit unavailable result otherwise, never a partial guess.";

pub(crate) const SEMANTIC_DESCRIPTION: &str = "definition | references | diagnostics | \
rename_preview, gated on real LSP provider availability. Requires a live language-server \
provider per language; returns an explicit unavailable result otherwise, never a partial guess.";

/// `plan_operation`'s boundary: plans only Corulix's own fixed
/// `OperationIntent` vocabulary (16 variants, none representing a
/// client-side file-read operation) -- confirmed against
/// `planning::plan_operation`'s pure, deterministic, Corulix-internal
/// `ProviderCategory` lookup. It has no vocabulary for, and expresses no
/// opinion about, which tool a calling client should choose.
pub(crate) const PLAN_OPERATION_NOTE: &str = "Plans Corulix's own fixed operation intents only; \
has no concept of, and no opinion about, which client-side tool a caller should use.";

pub(crate) const PLAN_OPERATION_DESCRIPTION: &str = "Derive the deterministic ToolPlan for an \
operation intent. Plans Corulix's own fixed operation intents only; has no concept of, and no \
opinion about, which client-side tool a caller should use.";

/// `format_preview`'s boundary: preview only, gated on live formatter
/// provider availability -- confirmed against `FormatPreviewOutcome`'s
/// shape (`WouldFormat`/`Unchanged` on success, an explicit unavailable
/// outcome otherwise; never applies the change itself).
pub(crate) const FORMAT_PREVIEW_NOTE: &str =
    "Preview only, never applied; requires a live formatter provider for the file's language.";

pub(crate) const FORMAT_PREVIEW_DESCRIPTION: &str = "Preview canonical formatting for one \
file; language is inferred from its path, not limited to Rust. Preview only, never applied; \
requires a live formatter provider for the file's language.";

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_NOTES: [&str; 5] = [
        SEARCH_NOTE,
        PARSE_FILE_NOTE,
        SEMANTIC_NOTE,
        PLAN_OPERATION_NOTE,
        FORMAT_PREVIEW_NOTE,
    ];

    const ALL_DESCRIPTION_NOTE_PAIRS: [(&str, &str); 5] = [
        (SEARCH_DESCRIPTION, SEARCH_NOTE),
        (PARSE_FILE_DESCRIPTION, PARSE_FILE_NOTE),
        (SEMANTIC_DESCRIPTION, SEMANTIC_NOTE),
        (PLAN_OPERATION_DESCRIPTION, PLAN_OPERATION_NOTE),
        (FORMAT_PREVIEW_DESCRIPTION, FORMAT_PREVIEW_NOTE),
    ];

    /// Mechanical backstop for the "facts, not coaching" invariant
    /// (routing plan Section 20/R5): no note may pair an action verb
    /// with a tool name, and no note may name another tool at all.
    /// Deliberately small and auditable -- not an NLP classifier.
    ///
    /// Deliberately excludes `search` and `semantic`: both are ordinary
    /// English words a capability description legitimately needs
    /// ("semantic identity", "structural search"), and a bare-word match
    /// on them produces exactly the false positive this check must avoid
    /// (confirmed: `SEARCH_NOTE` legitimately uses "semantic" as an
    /// adjective, not a cross-reference to the `semantic` tool). The
    /// remaining tool names are distinctive, multi-word/snake_case
    /// identifiers that do not collide with ordinary prose.
    const FORBIDDEN_TOOL_NAMES: &[&str] = &[
        "Read",
        "read_file",
        "parse_file",
        "plan_operation",
        "format_preview",
        "begin_change",
        "submit_edit",
        "validate_change",
        "change_status",
        "complete_change",
        "abort_change",
        "Grep",
        "Glob",
        "Bash",
    ];
    const FORBIDDEN_COACHING_PHRASES: &[&str] = &[
        "use ",
        "then ",
        "call ",
        "prefer ",
        "fall back",
        "fallback to",
        "afterward",
    ];

    fn assert_note_is_boundary_fact_not_coaching(note: &str) {
        for name in FORBIDDEN_TOOL_NAMES {
            assert!(
                !note.contains(name),
                "capability note references another tool by name ({name:?}): {note:?}"
            );
        }
        let lower = note.to_lowercase();
        for phrase in FORBIDDEN_COACHING_PHRASES {
            assert!(
                !lower.contains(phrase),
                "capability note contains a coaching phrase ({phrase:?}): {note:?}"
            );
        }
    }

    #[test]
    fn all_capability_notes_are_boundary_facts_not_coaching() {
        for note in ALL_NOTES {
            assert_note_is_boundary_fact_not_coaching(note);
        }
    }

    /// No note may mention a specific language or a specific benchmark
    /// module name -- the "could this have been written before any
    /// particular benchmark ever ran" invariant, checked mechanically
    /// for the terms that would most obviously violate it.
    #[test]
    fn all_capability_notes_are_language_and_benchmark_neutral() {
        const FORBIDDEN_TERMS: &[&str] = &[
            "Rust",
            "TypeScript",
            "Python",
            "Go ",
            "M02",
            "M01",
            "benchmark",
        ];
        for note in ALL_NOTES {
            for term in FORBIDDEN_TERMS {
                assert!(
                    !note.contains(term),
                    "capability note references a specific language/benchmark ({term:?}): {note:?}"
                );
            }
        }
    }

    /// Each tool's full `*_DESCRIPTION` (the one actually spliced into
    /// `#[tool(description = ...)]`) must contain its `*_NOTE` verbatim,
    /// so the reviewed boundary text and the live MCP-facing text can
    /// never silently drift apart.
    #[test]
    fn each_description_embeds_its_own_note_verbatim() {
        for (description, note) in ALL_DESCRIPTION_NOTE_PAIRS {
            assert!(
                description.contains(note),
                "description does not embed its own note verbatim.\ndescription: {description:?}\nnote: {note:?}"
            );
        }
    }
}
