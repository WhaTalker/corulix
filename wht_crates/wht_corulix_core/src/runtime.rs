// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Static build/runtime identity contract.

use serde::{Deserialize, Serialize};

/// Static build/runtime fingerprint returned by the `runtime_identity` tool,
/// used by clients to confirm which pinned SDK/grammar/toolchain versions
/// produced a given response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RuntimeIdentity {
    pub product: String,
    pub brand: String,
    pub binary: String,
    pub version: String,
    pub rust_toolchain: String,
    pub mcp_sdk: String,
    pub mcp_protocol: String,
    pub tree_sitter_runtime: String,
    pub index_schema_version: u32,
}
