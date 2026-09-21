// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Sole owner of LSP transport/client protocol and semantic intelligence
//! for WhaTalker Corulix (Architecture Rule L).
//!
//! ```text
//! SEARCH  = textual intelligence     (wht_corulix_search)
//! SYNTAX  = structural intelligence  (wht_corulix_syntax)
//! LSP     = semantic intelligence    (this crate)
//! ```
//!
//! No other crate may construct/parse LSP JSON-RPC messages, and no other
//! crate may spawn a language-server process directly -- process
//! construction remains `wht_corulix_tooling`'s exclusive authority (Rule
//! G); this crate spawns rust-analyzer only through
//! [`wht_corulix_tooling::ManagedProcess`]. Formatting is **not**
//! authoritative here: `rustfmt` (a future phase) remains the sole
//! formatter authority regardless of what a language server's
//! `documentFormattingProvider` capability might claim.
//!
//! # Readiness (`SEMANTIC_NOT_READY != ZERO_RESULTS`)
//!
//! `initialize` completing does not mean rust-analyzer's semantic database
//! is populated. Before [`readiness::Readiness::Ready`] is observed (via
//! the `experimental/serverStatus` signal, empirically validated against a
//! real rust-analyzer process during this phase's research gate), an empty
//! references/definition/diagnostics result is never treated as an
//! authoritative zero -- see [`operations::references`] and
//! [`operations::diagnostics`].
//!
//! # No mutation
//!
//! [`operations::rename_preview`] returns a proposed [`dto::RenameEditPreview`]
//! only. Nothing in this crate ever writes an edit to disk
//! (`RENAME_PREVIEW_MUTATION_COUNT=0`); applying a rename is a future
//! MutationBatch-phase concern.

pub mod dto;
mod error;
#[cfg(test)]
mod fixture_support;
pub mod managed_toolchain;
mod operations;
mod position;
pub mod profile;
mod project_priming;
mod readiness;
mod session;
mod transport;
mod uri;

pub use dto::{
    DefinitionResult, DiagnosticSeverity, DiagnosticsResult, HoverEvidence, ProposedTextEdit,
    ReferencesResult, RenameEditPreview, SemanticDiagnostic, SemanticLocation, SemanticSymbol,
};
pub use error::{LspError, NotReadyCause};
pub use operations::{
    definition, diagnostics, document_symbols, hover, references, rename_preview, workspace_symbols,
};
pub use profile::{
    AuxiliaryToolRequirement, LspProviderProfile, ReadinessStrategy, ResolvedLaunch,
    javascript_profile_for_declared_major, resolve_launch, resolve_launch_at,
    typescript_profile_for_declared_major,
};
pub use readiness::Readiness;
pub use session::{DEFAULT_REQUEST_TIMEOUT, LspSession};
pub use transport::{InboundNotification, TransportError};
pub use uri::path_to_file_uri;
