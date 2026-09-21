// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical error set shared across every crate boundary.

use thiserror::Error;

/// Canonical error set returned across engine and MCP boundaries.
///
/// Variants are deliberately coarse and free of raw filesystem/parser error
/// text so that internal details (paths, OS error codes, parser internals)
/// never leak to MCP clients or logs; `#[non_exhaustive]` allows new failure
/// modes to be added without an API break for downstream matchers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CorulixError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("workspace not found")]
    WorkspaceNotFound,
    #[error("path denied by workspace security policy")]
    PathDenied,
    #[error("language unsupported")]
    LanguageUnsupported,
    #[error("file exceeds configured size limit")]
    FileTooLarge,
    #[error("unsupported file encoding")]
    UnsupportedEncoding,
    #[error("parse failed")]
    ParseFailed,
    #[error("index not ready")]
    IndexNotReady,
    #[error("resource limit exceeded")]
    ResourceLimit,
    /// A confidence value was not finite or fell outside the closed `[0.0,
    /// 1.0]` range. Construction fails closed; no NaN/Infinity/out-of-range
    /// value is ever silently clamped into range.
    #[error("confidence value must be finite and within [0.0, 1.0]")]
    InvalidConfidence,
    #[error("internal operation failed")]
    Internal,
    /// F4 fix: `begin_change` rejected an `OperationIntent` whose own
    /// policy entry requires a gate (`GateId::Discovery`/
    /// `GateId::SemanticConfirm`) with no production Evidence-recording
    /// path in this workspace -- opening the session would let a mutation
    /// commit into a permanently uncompletable state
    /// (`SOURCE_CHANGE_COMMITTED_UNCOMPLETABLE_STATE`). Rejected before any
    /// `ChangeSession` exists and before any mutation is possible, never
    /// discovered later at `complete_change`.
    #[error("operation intent not supported: {0}")]
    OperationNotSupported(&'static str),
}

/// Shorthand result alias used consistently across every crate so error
/// handling stays uniform at every crate boundary.
pub type CorulixResult<T> = Result<T, CorulixError>;
