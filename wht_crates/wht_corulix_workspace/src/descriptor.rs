// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! VS Code `.code-workspace` descriptor parsing.
//!
//! This is the sole parser for this format anywhere in the workspace
//! (Architecture Rule F). It reads only `folders[].path` and
//! `folders[].name` -- confirmed against the official VS Code source
//! (`configurationExtensionPoint.ts`'s `workspaceConfig` schema and
//! `platform/workspaces/common/workspaces.ts`) to be exactly the
//! topology-relevant fields. `settings`/`tasks`/`launch`/`extensions` and
//! every other top-level key are never read, trusted, or executed -- they
//! carry zero Corulix security authority.
//!
//! VS Code's own schema declares `allowComments: true` and
//! `allowTrailingCommas: true` for this file, and its runtime uses a
//! fault-tolerant JSONC scanner rather than strict `JSON.parse` -- a
//! strict JSON parser is therefore not sufficient here, which is why this
//! module uses the admitted `jsonc-parser` dependency instead of `serde_json`.

use crate::context::MAX_WORKSPACE_ROOTS;
use jsonc_parser::JsonValue;
use wht_corulix_core::{CorulixError, CorulixResult};

/// One `folders[]` entry's topology-relevant fields, exactly as VS Code
/// defines `IRawFileWorkspaceFolder`. URI-based folders (`folders[].uri`,
/// used for remote workspaces) are not supported -- Corulix only imports
/// local filesystem topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorFolder {
    pub path: String,
    pub name: Option<String>,
}

/// The topology-relevant contents of a parsed `.code-workspace` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDescriptor {
    pub folders: Vec<DescriptorFolder>,
}

/// Parses `contents` (the raw bytes of a `.code-workspace` file, as text)
/// into its topology-relevant fields only.
pub fn parse_descriptor(contents: &str) -> CorulixResult<WorkspaceDescriptor> {
    let parsed = jsonc_parser::parse_to_value(contents, &jsonc_parser::ParseOptions::default())
        .map_err(|_| CorulixError::InvalidInput("malformed .code-workspace document".into()))?;
    let Some(JsonValue::Object(root)) = parsed else {
        return Err(CorulixError::InvalidInput(
            ".code-workspace document must be a JSON object".into(),
        ));
    };

    let Some(JsonValue::Array(folders)) = root.get("folders") else {
        return Err(CorulixError::InvalidInput(
            ".code-workspace document missing required 'folders' array".into(),
        ));
    };
    let folders = folders.clone().take_inner();

    if folders.is_empty() {
        return Err(CorulixError::InvalidInput(
            ".code-workspace 'folders' must not be empty".into(),
        ));
    }
    if folders.len() > MAX_WORKSPACE_ROOTS {
        return Err(CorulixError::ResourceLimit);
    }

    let mut result = Vec::with_capacity(folders.len());
    for folder in folders {
        let JsonValue::Object(folder) = folder else {
            return Err(CorulixError::InvalidInput(
                ".code-workspace 'folders[]' entry must be an object".into(),
            ));
        };
        let path = match folder.get("path") {
            Some(JsonValue::String(value)) => value.to_string(),
            Some(_) => {
                return Err(CorulixError::InvalidInput(
                    ".code-workspace 'folders[].path' must be a string".into(),
                ));
            }
            None => {
                return Err(CorulixError::InvalidInput(
                    ".code-workspace 'folders[]' entry missing required 'path' \
                     ('uri'-based remote folders are not supported)"
                        .into(),
                ));
            }
        };
        let name = match folder.get("name") {
            None => None,
            Some(JsonValue::String(value)) => Some(value.to_string()),
            Some(_) => {
                return Err(CorulixError::InvalidInput(
                    ".code-workspace 'folders[].name' must be a string".into(),
                ));
            }
        };
        result.push(DescriptorFolder { path, name });
    }

    Ok(WorkspaceDescriptor { folders: result })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_valid_descriptor() -> CorulixResult<()> {
        let descriptor = parse_descriptor(r#"{ "folders": [ { "path": "." } ] }"#)?;
        assert_eq!(descriptor.folders.len(), 1);
        assert_eq!(descriptor.folders[0].path, ".");
        assert_eq!(descriptor.folders[0].name, None);
        Ok(())
    }

    #[test]
    fn parses_comments_and_trailing_commas() -> CorulixResult<()> {
        let text = r#"{
            // this is a comment, per VS Code's documented JSONC support
            "folders": [
                { "path": "." },
                { "path": "../sibling", "name": "Sibling", },
            ],
            "settings": {},
        }"#;
        let descriptor = parse_descriptor(text)?;
        assert_eq!(descriptor.folders.len(), 2);
        assert_eq!(descriptor.folders[1].name.as_deref(), Some("Sibling"));
        Ok(())
    }

    #[test]
    fn ignores_settings_tasks_and_other_non_topology_keys() -> CorulixResult<()> {
        let text = r#"{
            "folders": [ { "path": "." } ],
            "settings": { "editor.tabSize": 2 },
            "tasks": { "version": "2.0.0", "tasks": [] },
            "launch": {},
            "extensions": { "recommendations": ["rust-lang.rust-analyzer"] }
        }"#;
        let descriptor = parse_descriptor(text)?;
        // Only folders[] is ever read; this test's very success (no error,
        // no attempt to interpret tasks/launch/extensions) is the proof.
        assert_eq!(descriptor.folders.len(), 1);
        Ok(())
    }

    #[test]
    fn rejects_malformed_syntax() {
        assert!(parse_descriptor("{ not valid json").is_err());
    }

    #[test]
    fn rejects_missing_folders() {
        assert!(parse_descriptor(r#"{ "settings": {} }"#).is_err());
    }

    #[test]
    fn rejects_empty_folders() {
        assert!(parse_descriptor(r#"{ "folders": [] }"#).is_err());
    }

    #[test]
    fn rejects_folder_missing_path() {
        assert!(parse_descriptor(r#"{ "folders": [ { "name": "no-path" } ] }"#).is_err());
    }

    #[test]
    fn rejects_non_string_path() {
        assert!(parse_descriptor(r#"{ "folders": [ { "path": 5 } ] }"#).is_err());
    }

    #[test]
    fn rejects_uri_only_folder() {
        assert!(parse_descriptor(r#"{ "folders": [ { "uri": "vscode-remote://x" } ] }"#).is_err());
    }

    #[test]
    fn rejects_too_many_roots() {
        let mut text = String::from(r#"{ "folders": ["#);
        for i in 0..(MAX_WORKSPACE_ROOTS + 1) {
            if i > 0 {
                text.push(',');
            }
            text.push_str(&format!(r#"{{"path":"./d{i}"}}"#));
        }
        text.push_str("] }");
        assert!(matches!(
            parse_descriptor(&text),
            Err(CorulixError::ResourceLimit)
        ));
    }
}
