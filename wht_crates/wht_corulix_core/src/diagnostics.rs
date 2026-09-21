// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Diagnostic and formatting-status summary contracts.

use serde::{Deserialize, Serialize};

/// A coarse rollup of diagnostic counts, never raw compiler/linter text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiagnosticSummary {
    pub error_count: u32,
    pub warning_count: u32,
    pub info_count: u32,
}

/// Whether a file is already canonically formatted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum FormattingStatus {
    Clean,
    WouldReformat,
    Unavailable,
}
