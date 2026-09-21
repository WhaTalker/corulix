// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15 §33: Tree-sitter Go regression.
//!
//! Tree-sitter Go was already integrated before P15 (`wht_corulix_syntax`'s
//! own descriptor table and grammar map). P15 **does not rewrite it** -- this
//! file exists to prove the pre-existing integration still behaves correctly
//! now that Go has become a fully-governed vertical, and to pin the
//! structural-inspection and hostile/bounded-input behaviour the mandate
//! names explicitly.
//!
//! `P15_TREE_SITTER_GO_REGRESSION`. Everything here is real parsing through
//! the real, canonical `wht_corulix_syntax::parse_source` entry point --
//! Architecture Rule C keeps `tree_sitter` itself entirely inside that crate,
//! and no `tree_sitter` type crosses this boundary.

use wht_corulix_core::{CorulixError, LanguageId, SymbolKind};
use wht_corulix_syntax::{capabilities, descriptors, detect_language, parse_source};

/// Real, valid, multi-construct Go: functions, a method with a receiver, a
/// struct type, an interface, a constant, and a variable -- enough for
/// structural inspection to have real work to do rather than a single
/// trivial function.
const REAL_GO: &str = r#"package main

import "fmt"

const Answer = 41

var counter int

type Shape struct {
	Width  int
	Height int
}

type Describer interface {
	Describe() string
}

func (s Shape) Area() int {
	return s.Width * s.Height
}

func target() int {
	return Answer
}

func main() {
	shape := Shape{Width: 2, Height: 3}
	fmt.Println(shape.Area(), target(), counter)
}
"#;

/// Go is a registered language with a pinned grammar, and `.go` files are
/// detected as Go -- the registration P15 relies on and never re-created.
#[test]
fn go_is_a_registered_language_with_a_pinned_grammar() -> Result<(), CorulixError> {
    assert_eq!(
        detect_language(std::path::Path::new("src/main.go")),
        Some(LanguageId::Go)
    );
    let descriptor = descriptors()
        .iter()
        .find(|descriptor| descriptor.id == LanguageId::Go)
        .ok_or(CorulixError::LanguageUnsupported)?;
    assert!(
        descriptor.grammar_package.contains("go"),
        "expected a Go grammar package, got {}",
        descriptor.grammar_package
    );
    assert!(
        !descriptor.grammar_version.is_empty(),
        "the Go grammar version must be pinned, not blank"
    );
    Ok(())
}

/// Real Go parses cleanly, with the expected root node kind and no syntax
/// error.
#[tokio::test]
async fn valid_go_parses_without_syntax_error() -> Result<(), CorulixError> {
    let summary = parse_source(LanguageId::Go, REAL_GO.as_bytes().to_vec()).await?;
    assert_eq!(summary.language, LanguageId::Go);
    assert!(
        !summary.has_syntax_error,
        "valid Go must parse without a syntax error"
    );
    assert_eq!(summary.root_kind, "source_file");
    assert_eq!(summary.byte_len, REAL_GO.len() as u64);
    Ok(())
}

/// Structural inspection finds the real definition sites -- this is the
/// capability `OperationIntent::StructuralInspection` routes to for Go, and
/// the one Search/Syntax may support but never claim semantic authority for.
#[tokio::test]
async fn structural_inspection_finds_real_go_definitions() -> Result<(), CorulixError> {
    let summary = parse_source(LanguageId::Go, REAL_GO.as_bytes().to_vec()).await?;
    let names: Vec<&str> = summary
        .symbols
        .iter()
        .map(|symbol| symbol.name.as_str())
        .collect();

    for expected in ["target", "main", "Shape", "Describer"] {
        assert!(
            names.contains(&expected),
            "expected `{expected}` among the extracted Go symbols, got {names:?}"
        );
    }

    // Ranges must be real and self-consistent, not placeholder zeros --
    // a downstream semantic/mutation caller addresses source by these.
    let target = summary
        .symbols
        .iter()
        .find(|symbol| symbol.name == "target")
        .ok_or(CorulixError::Internal)?;
    assert!(
        target.range.end.byte_offset > target.range.start.byte_offset,
        "symbol ranges must be real, got {:?}",
        target.range
    );
    assert_eq!(
        target.kind,
        SymbolKind::Function,
        "`func target()` must be classified as a function"
    );
    Ok(())
}

/// Go's declared capability matrix is honest: parsing is supported, and
/// cross-file resolution is **not** claimed by the syntax layer (that is
/// gopls's authority, admitted separately in P15). A syntax layer that
/// claimed cross-file resolution would be claiming semantic authority.
#[test]
fn go_capabilities_never_claim_semantic_cross_file_authority() {
    let go = capabilities(LanguageId::Go);
    assert_eq!(
        go.parsing,
        wht_corulix_core::CapabilityState::Supported,
        "Go parsing must be reported Supported"
    );
    assert_eq!(
        go.cross_file_resolution,
        wht_corulix_core::CapabilityState::NotSupported,
        "the syntax layer must never claim cross-file resolution for Go"
    );
}

/// Syntactically broken Go is reported as `has_syntax_error`, never as a
/// silent clean parse and never as a panic.
#[tokio::test]
async fn broken_go_is_reported_as_a_syntax_error_not_a_panic() -> Result<(), CorulixError> {
    let summary = parse_source(LanguageId::Go, b"package main\n\nfunc main( {\n".to_vec()).await?;
    assert!(
        summary.has_syntax_error,
        "unbalanced Go must be reported as a syntax error"
    );
    Ok(())
}

/// Non-UTF-8 bytes are rejected outright rather than lossily converted --
/// a lossy conversion would silently shift every byte offset downstream,
/// corrupting the ranges a mutation or semantic caller depends on.
#[tokio::test]
async fn non_utf8_go_input_is_rejected_rather_than_lossily_converted() {
    let outcome = parse_source(LanguageId::Go, vec![0x70, 0x6b, 0xff, 0xfe, 0x0a]).await;
    assert!(
        matches!(outcome, Err(CorulixError::UnsupportedEncoding)),
        "non-UTF-8 input must be rejected with UnsupportedEncoding, got {outcome:?}"
    );
}

/// Hostile, pathologically-nested Go must not blow the call stack: the
/// extractor walks with an explicit stack rather than recursion, precisely
/// so an attacker- or accident-supplied file cannot cause a stack overflow.
/// Deep nesting is a real, cheap adversarial input to construct.
#[tokio::test]
async fn deeply_nested_go_does_not_overflow_the_stack() -> Result<(), CorulixError> {
    // 2,000 nested blocks inside one function.
    const DEPTH: usize = 2_000;
    let mut source = String::from("package main\n\nfunc main() {\n");
    for _ in 0..DEPTH {
        source.push_str("{\n");
    }
    for _ in 0..DEPTH {
        source.push_str("}\n");
    }
    source.push_str("}\n");

    let summary = parse_source(LanguageId::Go, source.into_bytes()).await?;
    assert_eq!(summary.language, LanguageId::Go);
    // The point is that this returned at all rather than overflowing; the
    // grammar's own nesting limits may or may not flag an error, so the
    // assertion deliberately does not constrain `has_syntax_error`.
    assert!(summary.byte_len > DEPTH as u64);
    Ok(())
}

/// A very long single line of Go is handled without unbounded blowup --
/// the other common shape of hostile input alongside deep nesting.
#[tokio::test]
async fn a_pathologically_long_go_line_is_handled() -> Result<(), CorulixError> {
    let mut source = String::from("package main\n\nvar x = \"");
    source.push_str(&"a".repeat(512 * 1024));
    source.push_str("\"\n");
    let expected_len = source.len() as u64;

    let summary = parse_source(LanguageId::Go, source.into_bytes()).await?;
    assert_eq!(summary.byte_len, expected_len);
    assert!(!summary.has_syntax_error);
    Ok(())
}

/// Empty input is a clean, empty parse -- never an error and never a panic.
#[tokio::test]
async fn empty_go_input_parses_to_an_empty_summary() -> Result<(), CorulixError> {
    let summary = parse_source(LanguageId::Go, Vec::new()).await?;
    assert_eq!(summary.byte_len, 0);
    assert!(summary.symbols.is_empty());
    Ok(())
}

/// Determinism: the same Go source always yields the same structural
/// summary. A structural authority that varied run to run could not support
/// a reproducible gate.
#[tokio::test]
async fn go_parsing_is_deterministic() -> Result<(), CorulixError> {
    let first = parse_source(LanguageId::Go, REAL_GO.as_bytes().to_vec()).await?;
    let second = parse_source(LanguageId::Go, REAL_GO.as_bytes().to_vec()).await?;
    assert_eq!(first.root_kind, second.root_kind);
    assert_eq!(first.has_syntax_error, second.has_syntax_error);
    assert_eq!(first.symbols.len(), second.symbols.len());
    for (left, right) in first.symbols.iter().zip(second.symbols.iter()) {
        assert_eq!(left.name, right.name);
        assert_eq!(left.range, right.range);
        assert_eq!(left.kind, right.kind);
    }
    Ok(())
}
