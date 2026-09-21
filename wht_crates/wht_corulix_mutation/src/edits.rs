// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure, synchronous text-edit validation and deterministic application --
//! no I/O here, exactly the "hash comparisons, edit ordering, collision
//! classification" this phase's own async-first rule permits to stay
//! synchronous. Edits are expressed in Corulix's own byte-offset
//! `SourceRange` (traced from the existing canonical position/range
//! contracts already used by `wht_corulix_lsp::dto::ProposedTextEdit`
//! rather than inventing a second line/character-vs-byte semantics).

use wht_corulix_core::WorkspacePath;

use crate::{error::MutationError, types::TextEdit};

/// Validates every edit's range against `current` (UTF-8 safety,
/// in-bounds, non-overlapping) and applies them deterministically --
/// ordered by ascending start offset, with original batch order as the
/// tiebreak for two zero-length edits at the same offset -- returning the
/// final content. Fails closed on the first invalid/overlapping edit found
/// rather than applying any subset of the list.
pub fn apply_text_edits(
    path: &WorkspacePath,
    current: &[u8],
    edits: &[TextEdit],
) -> Result<Vec<u8>, MutationError> {
    let text = std::str::from_utf8(current)
        .map_err(|_| MutationError::InvalidEditRange { path: path.clone() })?;

    let mut ordered: Vec<(usize, usize, usize, &str)> = Vec::with_capacity(edits.len());
    for (original_index, edit) in edits.iter().enumerate() {
        let start = usize::try_from(edit.range.start.byte_offset)
            .map_err(|_| MutationError::InvalidEditRange { path: path.clone() })?;
        let end = usize::try_from(edit.range.end.byte_offset)
            .map_err(|_| MutationError::InvalidEditRange { path: path.clone() })?;
        if start > end
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            return Err(MutationError::InvalidEditRange { path: path.clone() });
        }
        ordered.push((start, end, original_index, edit.new_text.as_str()));
    }

    ordered.sort_by_key(|&(start, _end, original_index, _)| (start, original_index));

    let mut previous_end = 0_usize;
    for &(start, end, _, _) in &ordered {
        if start < previous_end {
            return Err(MutationError::OverlappingEdits { path: path.clone() });
        }
        previous_end = end.max(previous_end);
    }

    let mut result = String::with_capacity(text.len());
    let mut cursor = 0_usize;
    for &(start, end, _, new_text) in &ordered {
        result.push_str(&text[cursor..start]);
        result.push_str(new_text);
        cursor = end;
    }
    result.push_str(&text[cursor..]);

    Ok(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wht_corulix_core::{Position, SourceRange, WorkspaceRootId};

    fn path() -> WorkspacePath {
        WorkspacePath {
            root: WorkspaceRootId(0),
            relative_path: "src/main.rs".to_string(),
        }
    }

    fn range(start: u64, end: u64) -> SourceRange {
        SourceRange {
            start: Position {
                line_zero_based: 0,
                byte_column_zero_based: 0,
                byte_offset: start,
            },
            end: Position {
                line_zero_based: 0,
                byte_column_zero_based: 0,
                byte_offset: end,
            },
        }
    }

    #[test]
    fn single_edit_applies_correctly() -> Result<(), MutationError> {
        let current = b"fn target() {}";
        let edits = vec![TextEdit {
            range: range(3, 9),
            new_text: "renamed".to_string(),
        }];
        let result = apply_text_edits(&path(), current, &edits)?;
        assert_eq!(result, b"fn renamed() {}");
        Ok(())
    }

    #[test]
    fn multiple_non_overlapping_edits_apply_in_order() -> Result<(), MutationError> {
        let current = b"aaa bbb ccc";
        let edits = vec![
            TextEdit {
                range: range(8, 11),
                new_text: "ZZZ".to_string(),
            },
            TextEdit {
                range: range(0, 3),
                new_text: "XXX".to_string(),
            },
        ];
        let result = apply_text_edits(&path(), current, &edits)?;
        assert_eq!(result, b"XXX bbb ZZZ");
        Ok(())
    }

    #[test]
    fn overlapping_edits_are_rejected() {
        let current = b"aaaaaaaaaa";
        let edits = vec![
            TextEdit {
                range: range(0, 5),
                new_text: "X".to_string(),
            },
            TextEdit {
                range: range(3, 8),
                new_text: "Y".to_string(),
            },
        ];
        assert_eq!(
            apply_text_edits(&path(), current, &edits),
            Err(MutationError::OverlappingEdits { path: path() })
        );
    }

    #[test]
    fn out_of_bounds_range_is_rejected() {
        let current = b"short";
        let edits = vec![TextEdit {
            range: range(0, 100),
            new_text: "x".to_string(),
        }];
        assert_eq!(
            apply_text_edits(&path(), current, &edits),
            Err(MutationError::InvalidEditRange { path: path() })
        );
    }

    #[test]
    fn non_utf8_boundary_range_is_rejected() {
        // "é" is a two-byte UTF-8 sequence starting at byte 0; byte offset
        // 1 falls inside it, not on a character boundary.
        let current = "é".as_bytes();
        let edits = vec![TextEdit {
            range: range(1, 2),
            new_text: "x".to_string(),
        }];
        assert_eq!(
            apply_text_edits(&path(), current, &edits),
            Err(MutationError::InvalidEditRange { path: path() })
        );
    }

    #[test]
    fn inverted_range_is_rejected() {
        let current = b"hello";
        let edits = vec![TextEdit {
            range: range(3, 1),
            new_text: "x".to_string(),
        }];
        assert_eq!(
            apply_text_edits(&path(), current, &edits),
            Err(MutationError::InvalidEditRange { path: path() })
        );
    }

    #[test]
    fn empty_edit_list_returns_content_unchanged() -> Result<(), MutationError> {
        let current = b"unchanged";
        let result = apply_text_edits(&path(), current, &[])?;
        assert_eq!(result, current);
        Ok(())
    }

    #[test]
    fn adjacent_touching_edits_are_not_overlapping() -> Result<(), MutationError> {
        let current = b"abcdef";
        let edits = vec![
            TextEdit {
                range: range(0, 3),
                new_text: "XYZ".to_string(),
            },
            TextEdit {
                range: range(3, 6),
                new_text: "123".to_string(),
            },
        ];
        let result = apply_text_edits(&path(), current, &edits)?;
        assert_eq!(result, b"XYZ123");
        Ok(())
    }
}
