// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Sole owner of workspace canonicalization, path confinement, confined
//! traversal, root discovery, and `.code-workspace` descriptor parsing for
//! WhaTalker Corulix (Architecture Rule F).
//!
//! No other crate in this workspace may independently implement
//! canonicalization, path confinement, root-discovery, or VS Code
//! multi-root descriptor parsing -- `wht_corulix_engine` and every future
//! provider crate call into this crate instead. This crate depends only on
//! `wht_corulix_core` (plus the admitted `jsonc-parser` dependency for
//! descriptor parsing) and performs no MCP/rmcp, LSP, Tree-sitter,
//! process-spawning, or CLI-parsing work of its own.
//!
//! Residual risk, disclosed rather than hidden: a TOCTOU window exists
//! between [`resolve_confined`]'s canonicalization/containment check and any
//! later I/O a caller performs against the returned path. Safe Rust's
//! `std::fs` API provides no `openat`/capability-FD-based alternative;
//! closing this fully would require a larger, platform-specific redesign
//! not justified for this phase's scope.

mod confine;
mod context;
mod descriptor;
mod discovery;
mod resolver;
// M09-P2: the secure, pinned-directory-fd component walker. Unix-only;
// crate-internal only -- nothing here is re-exported, and no consumer
// migrates onto it until P3+. Windows's own, much simpler component walk
// (no internal-symlink-following: M09-P9's fail-closed reparse policy
// needs no hop-budget/target-translation machinery) lives inline in
// `capability_win32`'s own `walk_ancestors`, not a separate module.
#[cfg(unix)]
mod secure_walk;
// M09-P3 (Unix) / M09-P9 (Windows): opaque, cross-crate-safe filesystem
// capabilities. `pub` (first-party workspace crates consume these) but
// every field stays private and every constructor stays crate-internal
// (Architecture Rule F) -- see each module's own doc comment. Same public
// type/function names on both platforms (Architecture Rule F: exactly one
// of these two modules is ever compiled into a given build).
#[cfg(unix)]
mod capability;
#[cfg(windows)]
mod capability_win32;

#[cfg(unix)]
pub use capability::{
    PinnedFile, PinnedParent, PinnedTarget, resolve_existing_target, resolve_new_target,
    resolve_parent,
};
#[cfg(windows)]
pub use capability_win32::{
    PinnedFile, PinnedParent, PinnedTarget, resolve_existing_target, resolve_new_target,
    resolve_parent,
};
pub use confine::{
    ConfinedPath, DEFAULT_MAX_WALK_DEPTH, DEFAULT_MAX_WALK_ENTRIES, WalkLimits, WorkspaceRoot,
    canonicalize_external_path, confine_target, confined_metadata, confined_read,
    confined_read_and_process, confined_read_optional, confined_walk, resolve_confined,
};
pub use context::{MAX_WORKSPACE_ROOTS, WorkspaceContext, all_roots_within_boundary};
pub use descriptor::{DescriptorFolder, WorkspaceDescriptor, parse_descriptor};
pub use discovery::{
    DISCOVERY_MARKERS, DiscoveryCandidate, DiscoveryOutcome, MAX_DISCOVERY_DEPTH,
    WorkspaceDiscoveryOutcome, discover_from_seed, discover_workspace_from_seed,
};
pub use resolver::{
    CORULIX_WORKSPACE_ENV_VAR, CORULIX_WORKSPACE_FILE_ENV_VAR, ResolvedWorkspace,
    WorkspaceResolutionFailure, WorkspaceResolutionInputs, resolve_workspace,
};
