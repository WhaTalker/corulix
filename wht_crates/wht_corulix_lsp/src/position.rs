// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure, synchronous position/range conversion between Corulix's own
//! `wht_corulix_core::Position` (line + byte column + byte offset) and
//! LSP's `line`/`character` (UTF-16 code units), by walking file text. No
//! I/O happens here -- callers supply the already-read source text.
//!
//! This is exactly the "pure DTO/range transformation" this phase's own
//! async-first rule permits to stay synchronous (there is no `.await`-able
//! work in a text scan).

use wht_corulix_core::{Position, SourceRange};

/// Converts a Corulix [`Position`] (byte-offset-addressed) into an LSP
/// [`ls_types::Position`] (UTF-16-code-unit-addressed) by walking `text`.
/// Returns `None` if `position.byte_offset` does not fall within `text`.
#[must_use]
pub fn core_to_lsp(text: &str, position: &Position) -> Option<ls_types::Position> {
    let mut line = 0_u32;
    let mut utf16_units_in_line = 0_u32;
    let mut byte_offset = 0_u64;

    if position.byte_offset == 0 {
        return Some(ls_types::Position::new(0, 0));
    }

    for ch in text.chars() {
        if byte_offset == position.byte_offset {
            return Some(ls_types::Position::new(line, utf16_units_in_line));
        }
        if ch == '\n' {
            line += 1;
            utf16_units_in_line = 0;
        } else {
            utf16_units_in_line += ch.len_utf16() as u32;
        }
        byte_offset += u64::from(ch.len_utf8() as u32);
    }

    if byte_offset == position.byte_offset {
        Some(ls_types::Position::new(line, utf16_units_in_line))
    } else {
        None
    }
}

/// Converts an LSP [`ls_types::Position`] into a Corulix [`Position`] by
/// walking `text`. Per the LSP specification, a `character` value beyond
/// the addressed line's length is clamped to the line's end rather than
/// rejected. Returns `None` only if `position.line` itself is beyond the
/// end of `text`.
#[must_use]
pub fn lsp_to_core(text: &str, position: &ls_types::Position) -> Option<Position> {
    let target_line = position.line;
    let target_units = position.character;

    let mut line = 0_u32;
    let mut utf16_units_in_line = 0_u32;
    let mut byte_column_in_line = 0_u32;
    let mut byte_offset = 0_u64;

    for ch in text.chars() {
        if line == target_line && utf16_units_in_line == target_units {
            return Some(Position {
                line_zero_based: line,
                byte_column_zero_based: byte_column_in_line,
                byte_offset,
            });
        }
        if ch == '\n' {
            if line == target_line {
                // `character` pointed past the end of this line; clamp.
                return Some(Position {
                    line_zero_based: line,
                    byte_column_zero_based: byte_column_in_line,
                    byte_offset,
                });
            }
            line += 1;
            utf16_units_in_line = 0;
            byte_column_in_line = 0;
            byte_offset += 1;
            continue;
        }
        let char_utf16_len = ch.len_utf16() as u32;
        if line == target_line && utf16_units_in_line + char_utf16_len > target_units {
            return Some(Position {
                line_zero_based: line,
                byte_column_zero_based: byte_column_in_line,
                byte_offset,
            });
        }
        utf16_units_in_line += char_utf16_len;
        let char_byte_len = ch.len_utf8() as u32;
        byte_column_in_line += char_byte_len;
        byte_offset += u64::from(char_byte_len);
    }

    if line == target_line {
        Some(Position {
            line_zero_based: line,
            byte_column_zero_based: byte_column_in_line,
            byte_offset,
        })
    } else {
        None
    }
}

/// Converts an LSP [`ls_types::Range`] into a Corulix [`SourceRange`].
#[must_use]
pub fn lsp_range_to_core(text: &str, range: &ls_types::Range) -> Option<SourceRange> {
    Some(SourceRange {
        start: lsp_to_core(text, &range.start)?,
        end: lsp_to_core(text, &range.end)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_round_trips() -> Result<(), &'static str> {
        let text = "fn target() {}\n\nfn caller() {\n    target();\n}\n";
        let lsp_position = ls_types::Position::new(3, 4);
        let core_position = lsp_to_core(text, &lsp_position).ok_or("converts")?;
        assert_eq!(core_position.line_zero_based, 3);
        let back = core_to_lsp(text, &core_position).ok_or("converts back")?;
        assert_eq!(back, lsp_position);
        Ok(())
    }

    #[test]
    fn multi_byte_character_is_counted_correctly() -> Result<(), &'static str> {
        // "é" is one char, one UTF-16 unit, two UTF-8 bytes.
        let text = "let é = 1;\ntarget();\n";
        let position = ls_types::Position::new(1, 0);
        let core_position = lsp_to_core(text, &position).ok_or("converts")?;
        // Line 1 starts right after "let é = 1;\n" -- 12 bytes in (10 ASCII
        // + 2 for "é"'s UTF-8 encoding).
        assert_eq!(core_position.byte_offset, 12);
        Ok(())
    }

    #[test]
    fn character_past_end_of_line_clamps() -> Result<(), &'static str> {
        let text = "abc\ndef\n";
        let position = ls_types::Position::new(0, 100);
        let core_position = lsp_to_core(text, &position).ok_or("clamps rather than failing")?;
        assert_eq!(core_position.byte_column_zero_based, 3);
        Ok(())
    }

    #[test]
    fn line_past_end_of_text_is_none() {
        let text = "abc\n";
        let position = ls_types::Position::new(10, 0);
        assert_eq!(lsp_to_core(text, &position), None);
    }
}
