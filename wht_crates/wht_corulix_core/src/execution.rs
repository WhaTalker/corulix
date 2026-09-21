// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Execution-class and enforcement-level contracts.
//!
//! Neither type implements any execution. `ExecutionClass` deliberately
//! does not use a name like `SANDBOXED_TOOL`: no OS-level sandboxing is
//! implemented or proven anywhere in this crate, and a misleading name
//! would overclaim a guarantee Core cannot make.

use serde::{Deserialize, Serialize};

/// The execution-risk category of a capability, without implying an OS
/// sandbox guarantee that has not been proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ExecutionClass {
    ReadOnlyInProcess,
    ControlledExternalTool,
    TrustedWorkspaceExecution,
    ManagedFuture,
}

/// How strongly a policy decision is enforced.
///
/// Ordered (`Advisory < Blocking`) so a later floor rule can express "policy
/// may only raise enforcement, never lower it". No Core-defined,
/// client-facing request contract may set or lower this value; only a later
/// host/config layer authorizes it, and Core does not claim `Blocking`
/// mechanically prevents anything by itself -- that proof belongs to the
/// runtime phase that actually implements the mechanism.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum EnforcementLevel {
    Advisory,
    Blocking,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforcement_level_is_ordered_advisory_below_blocking() {
        assert!(EnforcementLevel::Advisory < EnforcementLevel::Blocking);
    }
}
