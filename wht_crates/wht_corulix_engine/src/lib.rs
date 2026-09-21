// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Orchestration layer that owns workspace access and dispatch to the index
//! and syntax (structural/Tree-sitter) adapter.
//!
//! `wht_corulix_engine` sits between `wht_corulix_mcp` and the lower-level crates:
//! it depends on `wht_corulix_core`, `wht_corulix_workspace`, `wht_corulix_index`, and
//! `wht_corulix_syntax` (including, transitively, Tree-sitter through
//! `wht_corulix_syntax`), which is exactly what Architecture Rule B relies on —
//! `wht_corulix_mcp` never imports Tree-sitter directly because this crate is the
//! sanctioned indirection point in between.
//!
//! This crate no longer implements canonicalization, path confinement, root
//! discovery, or `.code-workspace` descriptor parsing itself (Architecture
//! Rule F): that security boundary is owned exclusively by
//! `wht_corulix_workspace`. This crate consumes an already-resolved
//! [`WorkspaceContext`], which may be single-root or multi-root, and calls
//! into `wht_corulix_workspace` for every filesystem-security decision.
//!
//! Architecture Rule H (Enterprise Canonical Core Rebaseline, Phase 4): only
//! this crate may derive a [`wht_corulix_core::RiskClass`], a
//! [`wht_corulix_core::ToolPlan`], or a required-gate list for a concrete
//! operation. That derivation lives in four small, single-purpose modules:
//! [`policy`] (the fixed, auditable per-`OperationIntent` table and pure
//! risk derivation), [`providers`] (a fixed, compiled-in snapshot of which
//! provider categories this phase can actually call into -- no `PATH`
//! scanning, no binary resolution, no process probing), [`routing`]
//! (resolves a policy entry's tool requirements against a snapshot into a
//! `PlanExecutability` verdict), and [`planning`] (combines the three into
//! one deterministic `ToolPlan`). No CLI/MCP/provider crate may derive any
//! of this independently -- see [`CorulixEngine::plan_operation`], the sole
//! public entry point.
//!
//! This crate's existing workspace-binding responsibility (opening a
//! resolved [`WorkspaceContext`], parsing files, resolving confined paths)
//! remains in this top-level module; it is not split into a separate file
//! merely to match a module-naming template. `sessions`/`evidence`/
//! `mutation` module boundaries are deliberately **not** created in this
//! phase: Phase 4 derives a `ToolPlan` and stops there, and nothing it
//! produces is consumed by a session/evidence/mutation type yet (those
//! types already exist in `wht_corulix_core` from Phase 1, unused by any
//! runtime until Phases 8/10 implement the `ChangeSession` state machine
//! and Evidence acceptance) -- creating empty module files for them now
//! would be exactly the architecture theater this phase's mandate forbids.
//!
//! # Async orchestration boundary
//!
//! [`CorulixEngine::parse_relative_file`] and [`CorulixEngine::resolve_confined`]
//! are this crate's async-first orchestration boundaries: both `&self`
//! `async fn`s that await `wht_corulix_workspace`'s and
//! `wht_corulix_syntax`'s own canonical async entry points directly, so an
//! async caller (MCP, CLI) never blocks its own executor thread on a
//! confinement syscall, a confined read, or a Tree-sitter parse. This crate
//! composes no private `spawn_blocking` core of its own for either
//! operation -- Workspace and Syntax expose no public synchronous bypass to
//! compose one around, by design (see each crate's own docs). There is no
//! synchronous `parse_relative_file`/`resolve_confined` kept alongside
//! either -- each is the one public name for its operation. [`policy`],
//! [`providers`], [`routing`], and [`planning`] stay synchronous on
//! purpose: they are pure, deterministic, I/O-free derivations, and giving
//! them an `async fn` signature would add an await point with nothing to
//! actually await -- the "fake async" this crate's async-first rebaseline
//! explicitly rejects. See [`concurrency`] for the bounded-concurrency
//! primitive available to a future operational orchestration path.

use std::sync::Arc;
use wht_corulix_core::{
    CorulixResult, OperationIntent, ParseSummary, ProviderCategory, RuntimeIdentity,
    SCHEMA_VERSION, ToolApplicability, ToolPlan, WorkspaceInfo, WorkspaceTopologySummary,
};
use wht_corulix_index::IndexStore;
use wht_corulix_syntax::{descriptors, detect_language, parse_source_with_facts};
use wht_corulix_workspace::WorkspaceContext;

pub mod begin_change;
pub mod concurrency;
pub mod diagnostics;
pub mod diagnostics_readiness;
pub mod format_preview;
pub mod go_providers;
pub mod go_testing;
pub mod go_validation;
pub mod groups;
pub mod planning;
pub mod policy;
pub mod providers;
pub mod python_providers;
pub mod python_testing;
pub mod python_validation;
pub mod reconciler;
pub mod registry;
pub mod routing;
pub mod search;
pub mod semantic;
pub mod session;
pub mod testing;
pub mod toolchain_status;
pub mod ts_testing;
pub mod ts_validation;
pub mod validate_change;

use diagnostics_readiness::live_diagnostics_availability;
use policy::{TargetScope, policy_entry};
use providers::ProviderSnapshot;

/// P15: re-exported so a caller that must not depend on `wht_corulix_config`
/// directly (Architecture Rule B -- `wht_corulix_mcp` depends only on
/// `wht_corulix_core` and this crate) can still name the `HOST_ONLY`
/// provider-authority envelope [`CorulixEngine::open_with_host_config`]
/// requires.
///
/// This crate is the sanctioned indirection point for exactly this kind of
/// pass-through (the same role its module doc already describes for
/// Tree-sitter): re-exporting the type does **not** re-export any
/// configuration *authority* -- `HostConfig`'s trust fields are ignored by
/// `CorulixEngine::effective_config`, and `wht_corulix_config` remains the
/// sole owner of provider resolution and `HOST_ONLY` trust semantics (Rule
/// K).
pub use wht_corulix_config::HostConfig;

/// Same re-export rationale as [`HostConfig`] immediately above: a caller
/// that must not depend on `wht_corulix_config` directly still needs to name
/// `ManagedProvisioningPolicy::Deny`/`Allow` explicitly to construct a
/// deterministic `HostConfig` fixture for a test that must not depend on
/// whatever install profile this host's real, shared managed-toolchain root
/// happens to carry (Installation-Contract-V1: `HostConfig::default()`'s
/// `Inherit` policy defers to that persisted profile, which is no longer
/// unconditionally "nothing is provisioned" once this host's `corulix` has
/// ever bootstrapped for real).
pub use wht_corulix_config::ManagedProvisioningPolicy;

pub const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// A coarse, stable, `SCREAMING_SNAKE_CASE` tag over one
/// [`wht_corulix_core::CorulixError`] variant, for a capability outcome
/// enum (`search::SearchOutcome::Error`, `parse_file`'s own MCP-side
/// outcome, ...) that needs a serializable machine-readable code alongside
/// the error's `Display` text -- `CorulixError` itself is not
/// `Serialize`/`schemars::JsonSchema` (Architecture Rule A: Core stays
/// free of any serialization-format opinion), and this is deliberately not
/// a [`wht_corulix_core::ReasonCode`], which is reserved for
/// `ToolPlan`/gate-derived reasons, not generic I/O/validation failures.
/// `#[non_exhaustive]`-safe: a future `CorulixError` variant this match
/// doesn't know about yet still gets a stable code (`"INTERNAL"`), never a
/// compile error and never a silently blank tag.
#[must_use]
pub fn corulix_error_code(error: &wht_corulix_core::CorulixError) -> &'static str {
    match error {
        wht_corulix_core::CorulixError::InvalidInput(_) => "INVALID_INPUT",
        wht_corulix_core::CorulixError::WorkspaceNotFound => "WORKSPACE_NOT_FOUND",
        wht_corulix_core::CorulixError::PathDenied => "PATH_DENIED",
        wht_corulix_core::CorulixError::LanguageUnsupported => "LANGUAGE_UNSUPPORTED",
        wht_corulix_core::CorulixError::FileTooLarge => "FILE_TOO_LARGE",
        wht_corulix_core::CorulixError::UnsupportedEncoding => "UNSUPPORTED_ENCODING",
        wht_corulix_core::CorulixError::ParseFailed => "PARSE_FAILED",
        wht_corulix_core::CorulixError::IndexNotReady => "INDEX_NOT_READY",
        wht_corulix_core::CorulixError::ResourceLimit => "RESOURCE_LIMIT",
        wht_corulix_core::CorulixError::InvalidConfidence => "INVALID_CONFIDENCE",
        wht_corulix_core::CorulixError::Internal | _ => "INTERNAL",
    }
}

/// Owns one opened, read-only logical workspace (single- or multi-root):
/// its resolved [`WorkspaceContext`], file-size policy, and background
/// index.
pub struct CorulixEngine {
    context: WorkspaceContext,
    max_file_bytes: u64,
    index: Arc<IndexStore>,
    /// Phase 13: whether this engine instance is authorized to perform
    /// `ExecutionClass::TrustedWorkspaceExecution` (real `cargo check`/
    /// `cargo clippy` invocation for `validate_change`). `false` by
    /// default (see [`Self::open`]) -- there is no live, production
    /// host-config-file-loading path anywhere in this workspace yet (that
    /// remains a distinct, larger Phase 6 concern), so this flag is the
    /// one explicit, caller-supplied trust signal this phase introduces,
    /// never inferred from ambient state. See [`Self::effective_config`].
    trusted: bool,
    /// P15: the explicit, caller-supplied `HOST_ONLY` provider-authority
    /// envelope this engine derives its [`Self::effective_config`] from.
    ///
    /// Before P15 this crate hard-coded `..HostConfig::default()`, which
    /// grants **no** approved system directories and **no** absolute
    /// provider paths -- correct for Rust, whose whole vertical is
    /// `CORULIX_MANAGED` (downloaded, SHA-256-verified components that read
    /// no `EffectiveConfig` directory field at all), but structurally
    /// impossible for Go: `go`/`gopls`/`gofmt` are already-installed system
    /// tooling and `P15_AUTO_INSTALL_EXTERNAL_TOOLING=NO` forbids P15 from
    /// introducing a download path for them. Without a way for a host to
    /// declare their approved location, the Go vertical could only ever
    /// report `PROVIDER_UNAVAILABLE`.
    ///
    /// This is **not** a test seam (§36): it bypasses no gate and weakens no
    /// check. Every resolution still runs the full Phase-6 resolver, which
    /// canonicalizes, verifies authority, and rejects a workspace-local
    /// candidate exactly as before -- this only supplies the `HOST_ONLY`
    /// tier §6 of the mandate names as precedence 1-3. `WorkspaceTrust` and
    /// `allow_trusted_workspace_execution` continue to come from
    /// [`Self::trusted`] and are never read from this value, so a host
    /// cannot smuggle a trust elevation in through a provider-path field.
    host_provider_authority: wht_corulix_config::HostConfig,
    /// Phase 13 item 3: this engine's own cached, real, ready Rust
    /// `wht_corulix_lsp::LspSession`, lazily spawned on first `semantic`
    /// call and reused thereafter (spawning/readying rust-analyzer per call
    /// would be prohibitively slow) -- see `semantic::CorulixEngine::
    /// ensure_rust_lsp_session`. `LspSession` carries no `Debug` impl (owns
    /// live process/transport handles), so this type has a hand-written
    /// [`std::fmt::Debug`] below instead of a derive.
    rust_lsp_session: tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>>,
    /// P15: the same lazily-spawned, cached-per-engine session slot as
    /// [`Self::rust_lsp_session`], for Go's own `gopls` session. A separate
    /// slot rather than a shared one because the two are different processes
    /// with different provider profiles and different readiness strategies;
    /// a single slot would silently return a rust-analyzer session to a Go
    /// caller (or vice versa) depending on which language happened to be
    /// requested first.
    go_lsp_session: tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>>,
    /// P16: the same lazily-spawned, cached-per-engine session slot
    /// pattern as [`Self::rust_lsp_session`]/[`Self::go_lsp_session`], one
    /// per TS-family [`wht_corulix_core::LanguageId`]
    /// (`TypeScript`/`Tsx`/`JavaScript`). Three separate slots -- never one
    /// shared slot -- because each opens documents under a distinct LSP
    /// `languageId` (`"typescript"`/`"typescriptreact"`/`"javascript"`); a
    /// shared slot would silently hand a TypeScript caller a session
    /// opened for TSX (or vice versa) depending on request order.
    typescript_lsp_session: tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>>,
    tsx_lsp_session: tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>>,
    javascript_lsp_session: tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>>,
    /// P17: the same lazily-spawned, cached-per-engine session slot pattern
    /// as [`Self::rust_lsp_session`]/[`Self::go_lsp_session`], for Python's
    /// own Pyright session (ADR 0009's `LanguageServer` identity, distinct
    /// from ADR 0011's one-shot `pyright --outputjson` typecheck authority --
    /// see `python_validation`'s own module doc).
    python_lsp_session: tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>>,
}

impl std::fmt::Debug for CorulixEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CorulixEngine")
            .field("context", &self.context)
            .field("max_file_bytes", &self.max_file_bytes)
            .field("trusted", &self.trusted)
            .finish_non_exhaustive()
    }
}

impl CorulixEngine {
    /// Wraps an already-resolved, already-validated [`WorkspaceContext`].
    /// Validation (canonicalization, directory checks, descriptor parsing,
    /// duplicate/overlap/external-scope checks) happened once, in
    /// `wht_corulix_workspace`, when the context was resolved -- this
    /// constructor is infallible because a `WorkspaceContext` cannot exist
    /// without already having passed those checks.
    ///
    /// Never authorizes `TrustedWorkspaceExecution` (see `Self::trusted`);
    /// use [`Self::open_with_trust`] to construct an engine that may run
    /// `validate_change`'s real `cargo check`/`cargo clippy` invocation.
    #[must_use]
    pub fn open(context: WorkspaceContext) -> Self {
        Self::open_with_trust(context, false)
    }

    /// As [`Self::open`], but explicitly marks this engine instance as
    /// trusted (or not) for `ExecutionClass::TrustedWorkspaceExecution`.
    /// This is a deliberate, explicit, caller-supplied signal -- never
    /// derived from an ambient environment variable, a file on disk, or a
    /// guess -- exactly mirroring `wht_corulix_config::HostConfig::
    /// workspace_trust`'s own fail-closed-by-default posture.
    #[must_use]
    pub fn open_with_trust(context: WorkspaceContext, trusted: bool) -> Self {
        Self::open_with_host_config(context, trusted, wht_corulix_config::HostConfig::default())
    }

    /// As [`Self::open_with_trust`], but with the explicit `HOST_ONLY`
    /// provider-authority envelope this engine resolves external providers
    /// against (P15) -- see `Self::host_provider_authority` for why this
    /// exists and why it is not a test seam.
    ///
    /// `trusted` remains a separate parameter and remains the *only* source
    /// of `WorkspaceTrust`/`allow_trusted_workspace_execution`: whatever
    /// those two fields hold in `host_provider_authority` is deliberately
    /// ignored (see `Self::effective_config`). A caller therefore cannot
    /// grant trusted workspace execution by way of a provider-path
    /// configuration, only by the same explicit `trusted` flag
    /// [`Self::open_with_trust`] has always required.
    ///
    /// `[`Self::open`]`/[`Self::open_with_trust`] delegate here with a
    /// default (empty) envelope, so every pre-P15 caller's behavior is
    /// byte-for-byte unchanged.
    #[must_use]
    pub fn open_with_host_config(
        context: WorkspaceContext,
        trusted: bool,
        host_provider_authority: wht_corulix_config::HostConfig,
    ) -> Self {
        Self {
            context,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            index: Arc::new(IndexStore::default()),
            trusted,
            host_provider_authority,
            rust_lsp_session: tokio::sync::Mutex::new(None),
            go_lsp_session: tokio::sync::Mutex::new(None),
            typescript_lsp_session: tokio::sync::Mutex::new(None),
            tsx_lsp_session: tokio::sync::Mutex::new(None),
            javascript_lsp_session: tokio::sync::Mutex::new(None),
            python_lsp_session: tokio::sync::Mutex::new(None),
        }
    }

    /// Derives this engine's [`wht_corulix_config::EffectiveConfig`] from
    /// its own [`Self::trusted`] flag -- the sole, crate-internal source of
    /// trust configuration `validate_change` reads. No repository hints or
    /// per-request options are modeled yet (both default), matching this
    /// phase's narrow scope: authorizing (or not) real `cargo check`/
    /// `cargo clippy` invocation, nothing else.
    pub(crate) fn effective_config(&self) -> wht_corulix_config::EffectiveConfig {
        // The provider-authority envelope contributes provider paths and
        // approved directories only; `workspace_trust` and
        // `allow_trusted_workspace_execution` are overwritten from
        // `self.trusted` unconditionally, so a caller-supplied `HostConfig`
        // can never elevate trust by way of a provider configuration
        // (`P15_PROVIDER_CONFIG_TRUST_ELEVATION_PATH_COUNT=0`).
        let host = wht_corulix_config::HostConfig {
            workspace_trust: if self.trusted {
                wht_corulix_core::WorkspaceTrust::Trusted
            } else {
                wht_corulix_core::WorkspaceTrust::Untrusted
            },
            allow_trusted_workspace_execution: self.trusted,
            ..self.host_provider_authority.clone()
        };
        wht_corulix_config::EffectiveConfig::derive(
            &host,
            &wht_corulix_config::RepositoryHints::default(),
            &wht_corulix_config::RequestOptions::default(),
        )
    }

    /// Returns a redacted description of the workspace safe to hand to an
    /// MCP client: only a display label is exposed, never a raw absolute
    /// root. For richer single/multi-root topology detail (root count,
    /// per-root opaque IDs and display names), see
    /// [`Self::topology_summary`].
    #[must_use]
    pub fn workspace_info(&self) -> WorkspaceInfo {
        let summary = self.context.summary();
        // Keyed on root count rather than matching `WorkspaceTopologyKind`
        // directly: that enum is `#[non_exhaustive]`, and root count is the
        // authoritative signal for this label regardless of how many
        // topology kinds exist in the future.
        let root_label = match summary.roots.as_slice() {
            [only] => only.display_name.clone(),
            roots => format!("workspace ({} roots)", roots.len()),
        };
        WorkspaceInfo {
            schema_version: SCHEMA_VERSION,
            root_label,
            root_redacted: true,
            read_only: true,
        }
    }

    /// Returns the full, safe single/multi-root topology summary: whether
    /// this is a single- or multi-root workspace, and each member root's
    /// opaque ID and display name.
    #[must_use]
    pub fn topology_summary(&self) -> WorkspaceTopologySummary {
        self.context.summary()
    }

    /// Returns the static product/version/SDK fingerprint, exposed so MCP
    /// clients can confirm compatibility before relying on other tools.
    #[must_use]
    pub fn runtime_identity(&self) -> RuntimeIdentity {
        RuntimeIdentity {
            product: wht_corulix_core::PRODUCT_NAME.to_owned(),
            brand: wht_corulix_core::BRAND_NAME.to_owned(),
            binary: wht_corulix_core::BINARY_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            rust_toolchain: "1.97.1".to_owned(),
            mcp_sdk: "rmcp 3.0.1".to_owned(),
            mcp_protocol: "2026-07-28 (SDK compatibility also supports earlier releases)"
                .to_owned(),
            tree_sitter_runtime: "0.26.11".to_owned(),
            index_schema_version: wht_corulix_core::INDEX_SCHEMA_VERSION,
        }
    }

    /// Lists every supported language paired with its grammar package and
    /// pinned version, for the CLI `languages` command and diagnostics.
    #[must_use]
    pub fn language_descriptors(&self) -> Vec<(String, String)> {
        descriptors()
            .iter()
            .map(|descriptor| {
                (
                    descriptor.id.to_string(),
                    format!(
                        "{} {}",
                        descriptor.grammar_package, descriptor.grammar_version
                    ),
                )
            })
            .collect()
    }

    /// The blocking-safe core behind [`Self::parse_relative_file`]. Not
    /// `pub`: nothing outside this crate composes Engine's own operations
    /// inside another blocking closure, so unlike the equivalent primitives
    /// in `wht_corulix_workspace`/`wht_corulix_syntax`, this one has no
    /// reason to be public.
    ///
    /// Parses one workspace-relative file after confining and validating it.
    ///
    /// `root_selector` selects which member root to operate against: a
    /// single-root context ignores it; a multi-root context requires an
    /// explicit, unambiguous selector (see
    /// `wht_corulix_workspace::WorkspaceContext::resolve_root`) -- there is
    /// no "try every root and use the first hit" behavior.
    ///
    /// This is this crate's async orchestration boundary: it awaits
    /// `wht_corulix_workspace`'s and `wht_corulix_syntax`'s own canonical
    /// async entry points directly, in cheap-to-expensive order (a
    /// metadata check, then a size check, then the confined read and
    /// parse), rather than composing a private blocking core of its own.
    /// Neither Workspace nor Syntax exposes a public synchronous bypass for
    /// this crate to call instead -- a private blocking core here would
    /// have no non-`spawn_blocking`-wrapped primitive left to call. The
    /// derivation logic itself -- [`policy`], [`providers`], [`routing`],
    /// [`planning`] -- stays deliberately synchronous: those are pure,
    /// deterministic functions with no I/O, and wrapping them here would be
    /// exactly the "fake async" this boundary exists to avoid, not genuine
    /// async-first design. There is no synchronous `parse_relative_file`
    /// kept alongside it; this is the one public name for this operation.
    /// Language detection runs on the caller-supplied relative path's own
    /// extension (never the confined absolute path) -- canonicalization
    /// changes a path's location, never its filename, so this needs no
    /// confinement check of its own.
    /// Returns the unchanged `ParseSummary` alongside a parallel,
    /// index-aligned `Vec<CompactSymbol>` of AI-facing structural facts
    /// (Parse MCP structured_content canonicalization). `CompactSymbol`
    /// carries no new field anywhere `ParseSummary`/`Symbol` themselves --
    /// it is a separate, additive type in `wht_corulix_core`, so the
    /// internal parse model stays byte-identical; only the MCP layer
    /// projects a new compact DTO from it. See
    /// `wht_corulix_syntax::parse_source_with_facts`'s own doc comment for
    /// the exact bounds/semantics each fact is computed under.
    pub async fn parse_relative_file(
        &self,
        relative: std::path::PathBuf,
        root_selector: Option<String>,
    ) -> CorulixResult<(ParseSummary, Vec<wht_corulix_core::CompactSymbol>)> {
        let root = self.context.resolve_root(root_selector.as_deref())?.clone();
        let metadata =
            wht_corulix_workspace::confined_metadata(root.clone(), relative.clone()).await?;
        if !metadata.is_file() {
            return Err(wht_corulix_core::CorulixError::InvalidInput(
                "path is not a regular file".into(),
            ));
        }
        // Enforce the byte cap before reading the file into memory, not
        // after, so a client cannot force an unbounded allocation by
        // requesting a huge file.
        if metadata.len() > self.max_file_bytes {
            return Err(wht_corulix_core::CorulixError::FileTooLarge);
        }

        let language = detect_language(&relative)
            .ok_or(wht_corulix_core::CorulixError::LanguageUnsupported)?;
        let source =
            wht_corulix_workspace::confined_read(root, relative, self.max_file_bytes).await?;
        parse_source_with_facts(language, source).await
    }

    /// Resolves a client-supplied relative path to a canonical, in-workspace
    /// absolute path against the selected member root, or rejects it.
    /// Delegates entirely to `wht_corulix_workspace::resolve_confined`
    /// (Architecture Rule F) -- this crate implements no confinement logic
    /// of its own. `async fn` for the same reason as
    /// [`Self::parse_relative_file`]: canonicalization is a real syscall,
    /// awaited through Workspace's own canonical async entry point rather
    /// than run directly on an async caller's executor thread.
    pub async fn resolve_confined(
        &self,
        relative: std::path::PathBuf,
        root_selector: Option<String>,
    ) -> CorulixResult<std::path::PathBuf> {
        let root = self.context.resolve_root(root_selector.as_deref())?.clone();
        wht_corulix_workspace::resolve_confined(root, relative)
            .await
            .map(wht_corulix_workspace::ConfinedPath::into_path_buf)
    }

    /// Resolves a caller-supplied root selector to an owned, cloned
    /// [`wht_corulix_workspace::WorkspaceRoot`] -- Phase 13's
    /// `begin_change` needs exactly this to construct the
    /// [`wht_corulix_mutation::MutationExecutor`] a new [`session::ChangeSession`]
    /// owns (Rule M: `wht_corulix_mcp` never constructs a `WorkspaceRoot`
    /// itself, and never bypasses this crate's own root-selection
    /// semantics to get one).
    pub fn resolve_workspace_root(
        &self,
        root_selector: Option<&str>,
    ) -> CorulixResult<wht_corulix_workspace::WorkspaceRoot> {
        Ok(self.context.resolve_root(root_selector)?.clone())
    }

    /// Returns a shared handle to the workspace's background index store.
    #[must_use]
    pub fn index(&self) -> Arc<IndexStore> {
        Arc::clone(&self.index)
    }

    /// Crate-private accessor to this engine's bound [`WorkspaceContext`],
    /// for sibling modules ([`search`], [`session`]) that need read access
    /// to root resolution/selection without this becoming a second public
    /// workspace-access surface alongside [`Self::resolve_confined`]/
    /// [`Self::parse_relative_file`].
    pub(crate) fn context(&self) -> &WorkspaceContext {
        &self.context
    }

    /// As [`Self::context`], but an owned clone -- `WorkspaceContext` is
    /// `Clone` (cheap: it holds no open file handles, only resolved root
    /// paths and display names), and some downstream APIs
    /// (`wht_corulix_search::search`) take it by value.
    pub(crate) fn context_owned(&self) -> WorkspaceContext {
        self.context().clone()
    }

    /// Crate-private accessor to this engine's configured file-size cap,
    /// for sibling modules (`format_preview`) that must pass the same
    /// bound this crate already enforces in [`Self::parse_relative_file`]
    /// through to another crate's own bounded-read entry point, rather
    /// than each defining a second, potentially-divergent constant.
    pub(crate) fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }

    /// Crate-private accessor to this engine's cached-Rust-LSP-session
    /// slot, for `semantic`'s own `ensure_rust_lsp_session` -- kept on
    /// `CorulixEngine` itself (rather than a private static/thread-local in
    /// `semantic.rs`) so the cache's lifetime is tied to this engine
    /// instance's own lifetime, exactly like `Self::index`.
    pub(crate) fn rust_lsp_session(
        &self,
    ) -> &tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>> {
        &self.rust_lsp_session
    }

    /// As [`Self::rust_lsp_session`], for P15's own `gopls` session slot.
    pub(crate) fn go_lsp_session(
        &self,
    ) -> &tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>> {
        &self.go_lsp_session
    }

    /// As [`Self::rust_lsp_session`], for P16's own TypeScript session slot
    /// (TS7 native or TS6 managed-compat, per the session's declared major).
    pub(crate) fn typescript_lsp_session(
        &self,
    ) -> &tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>> {
        &self.typescript_lsp_session
    }

    /// As [`Self::rust_lsp_session`], for P16's own TSX session slot.
    pub(crate) fn tsx_lsp_session(
        &self,
    ) -> &tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>> {
        &self.tsx_lsp_session
    }

    /// As [`Self::rust_lsp_session`], for P16's own JavaScript session slot.
    pub(crate) fn javascript_lsp_session(
        &self,
    ) -> &tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>> {
        &self.javascript_lsp_session
    }

    /// As [`Self::rust_lsp_session`], for P17's own Python (Pyright) session
    /// slot.
    pub(crate) fn python_lsp_session(
        &self,
    ) -> &tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>> {
        &self.python_lsp_session
    }

    /// Crate-private [`TargetScope`] derivation, shared by
    /// [`Self::plan_operation_for_language`] and `semantic`'s own real,
    /// per-call [`ProviderSnapshot`] derivation -- single- vs multi-root,
    /// exactly this engine's own bound [`WorkspaceContext`] root count.
    pub(crate) fn target_scope(&self) -> TargetScope {
        match self.context.root_count() {
            1 => TargetScope::SingleRoot,
            root_count => TargetScope::MultiRoot { root_count },
        }
    }

    /// Resolves a caller-supplied root selector (display name or numeric
    /// [`wht_corulix_core::WorkspaceRootId`] string) to the concrete id, for
    /// capability modules ([`search`]) whose downstream API is scoped by id
    /// rather than by [`wht_corulix_workspace::WorkspaceRoot`] reference.
    /// Mirrors `WorkspaceContext::resolve_root`'s own selection semantics
    /// (unique display-name match, else numeric id match, else fail closed
    /// with `CorulixError::WorkspaceNotFound` -- never a first-match guess)
    /// without this crate reimplementing confinement or trust logic: this
    /// only picks an id, it never bypasses `wht_corulix_workspace`'s own
    /// confinement checks for any subsequent operation against that root.
    pub(crate) fn resolve_root_id(
        &self,
        selector: &str,
    ) -> CorulixResult<wht_corulix_core::WorkspaceRootId> {
        let summaries = self.context().root_summaries();
        if summaries.len() == 1 {
            return Ok(summaries[0].root);
        }
        let name_matches: Vec<_> = summaries
            .iter()
            .filter(|summary| summary.display_name == selector)
            .collect();
        if name_matches.len() == 1 {
            return Ok(name_matches[0].root);
        }
        if let Ok(id) = selector.parse::<u32>()
            && let Some(summary) = summaries.iter().find(|summary| summary.root.0 == id)
        {
            return Ok(summary.root);
        }
        Err(wht_corulix_core::CorulixError::WorkspaceNotFound)
    }

    /// Derives a deterministic [`ToolPlan`] for `intent` against this
    /// engine's bound workspace (Architecture Rule H -- the sole place a
    /// `ToolPlan`/`RiskClass`/required-gate list is derived).
    ///
    /// Scope is computed from this engine's own [`WorkspaceContext`]
    /// (single- vs multi-root, and root count); provider availability comes
    /// from the fixed, compiled-in [`ProviderSnapshot::current`] -- no
    /// filesystem access, no process spawning, and no randomness are
    /// involved, so this call is infallible given the engine's
    /// already-resolved state (see [`Self::plan_operation_for_language`]'s
    /// own doc for the one case, `TypecheckBuild`-requiring intents, where a
    /// bounded, synchronous filesystem check now runs -- the P-M05-R1 fix).
    /// `language: None`: this compiled-in snapshot carries no per-language
    /// `LanguageServer` resolutions yet (a later phase wires real
    /// `wht_corulix_lsp`/`wht_corulix_config` resolution results in via
    /// [`ProviderSnapshot::with_language_server_resolutions`]); use
    /// [`Self::plan_operation_for_language`] once a caller knows which
    /// language an operation targets.
    #[must_use]
    pub fn plan_operation(&self, intent: OperationIntent) -> ToolPlan {
        self.plan_operation_for_language(intent, None)
    }

    /// The same derivation as [`Self::plan_operation`], but a required
    /// `LanguageServer` requirement is checked against `language`'s real,
    /// per-language availability (Section 19 of the Phase 7B mandate: the
    /// live routing path is no longer `LanguageServer == rust-analyzer`-
    /// shaped) rather than the single category-level view -- see
    /// [`planning::plan_operation`]/[`routing::evaluate`].
    ///
    /// P-M05-R1 fix: when `intent`'s policy lists `TypecheckBuild` as
    /// `Required`, this also overlays the real, live
    /// `TypecheckBuild`/`Linter`/`TestRunner` availability
    /// `diagnostics_readiness::live_diagnostics_availability` resolves for
    /// `language` -- the same synchronous, `CORULIX_MANAGED`-tier-only check
    /// [`Self::begin_change`] uses, so the public `plan_operation` MCP tool
    /// and `begin_change`'s own gate/status verdict agree
    /// (`PROVIDER_AVAILABILITY_SINGLE_SOURCE_OF_TRUTH`). Any other intent
    /// (no `TypecheckBuild` requirement) still reads exactly
    /// [`ProviderSnapshot::current`]'s unchanged baseline -- no filesystem
    /// access for a caller that never needed it.
    #[must_use]
    pub fn plan_operation_for_language(
        &self,
        intent: OperationIntent,
        language: Option<wht_corulix_core::LanguageId>,
    ) -> ToolPlan {
        let mut snapshot = ProviderSnapshot::current();
        let typecheck_build_required = policy_entry(intent).is_some_and(|entry| {
            entry.requirements.iter().any(|requirement| {
                requirement.category == ProviderCategory::TypecheckBuild
                    && requirement.applicability == ToolApplicability::Required
            })
        });
        if typecheck_build_required {
            let effective = self.effective_config();
            let (typecheck_build, linter, test_runner) =
                live_diagnostics_availability(language, &effective);
            snapshot = snapshot.with_diagnostics_resolution(typecheck_build, linter, test_runner);
        }
        self.plan_operation_with_snapshot(intent, language, &snapshot)
    }

    /// F7 fix (`F7_FORMATTER_LIVE_AVAILABILITY_NOT_OVERLAID_IN_ROUTING`): the
    /// same derivation as [`Self::plan_operation_for_language`], but against
    /// a caller-supplied `snapshot` rather than always the compiled-in
    /// [`ProviderSnapshot::current`] -- the seam both
    /// [`Self::begin_change`]/[`begin_change`] and
    /// [`Self::plan_operation_for_language`] itself use to inject a real,
    /// live overlay (`Formatter` via F7,
    /// `TypecheckBuild`/`Linter`/`TestRunner` via the P-M05-R1 fix)
    /// without a second, parallel derivation path. `pub(crate)`: this is an
    /// internal seam, not a second public derivation entry point Architecture
    /// Rule H's "sole public entry point" contract would otherwise forbid.
    #[must_use]
    pub(crate) fn plan_operation_with_snapshot(
        &self,
        intent: OperationIntent,
        language: Option<wht_corulix_core::LanguageId>,
        snapshot: &ProviderSnapshot,
    ) -> ToolPlan {
        planning::plan_operation(intent, self.target_scope(), snapshot, language)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::CorulixError;

    fn temp_workspace(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-engine-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    /// Proves `CorulixEngine` correctly delegates confinement to
    /// `wht_corulix_workspace` end-to-end -- the confinement *algorithm*
    /// itself (traversal/absolute-path/symlink-escape rejection) is
    /// exhaustively tested in `wht_corulix_workspace`'s own test suite
    /// (Architecture Rule F: this crate owns no duplicate implementation
    /// of that algorithm, so it is not re-tested here).
    #[tokio::test]
    async fn resolve_confined_delegates_to_workspace_crate() -> CorulixResult<()> {
        let path = temp_workspace("single");
        let root = wht_corulix_workspace::WorkspaceRoot::open(&path)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));
        assert!(matches!(
            engine
                .resolve_confined(PathBuf::from("../outside.rs"), None)
                .await,
            Err(CorulixError::PathDenied)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[tokio::test]
    async fn multi_root_engine_requires_explicit_selector_for_parse() -> CorulixResult<()> {
        let a = temp_workspace("multi-a");
        let b = temp_workspace("multi-b");
        let _ = fs::write(a.join("main.rs"), "fn main() {}");
        let context = WorkspaceContext::from_roots(vec![
            (
                wht_corulix_workspace::WorkspaceRoot::open(&a)?,
                "a".to_string(),
            ),
            (
                wht_corulix_workspace::WorkspaceRoot::open(&b)?,
                "b".to_string(),
            ),
        ])?;
        let engine = Arc::new(CorulixEngine::open(context));
        // No selector: must fail closed, never silently pick the first root.
        assert!(
            engine
                .parse_relative_file(PathBuf::from("main.rs"), None)
                .await
                .is_err()
        );
        // Explicit, correct selector: succeeds.
        assert!(
            engine
                .parse_relative_file(PathBuf::from("main.rs"), Some("a".to_string()))
                .await
                .is_ok()
        );
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    /// A confinement rejection must surface as a structured error through
    /// the async boundary, never a panic or a silently swallowed failure.
    #[tokio::test]
    async fn parse_relative_file_propagates_confinement_failure() -> CorulixResult<()> {
        let root_dir = temp_workspace("async-parse-denied");
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));

        let outcome = engine
            .parse_relative_file(PathBuf::from("../outside.rs"), None)
            .await;
        assert!(matches!(outcome, Err(CorulixError::PathDenied)));

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// Proves the async orchestration boundary genuinely awaits Workspace's
    /// and Syntax's own canonical async entry points end to end (not merely
    /// callable via `#[test]`) and produces a correct parse result.
    #[tokio::test]
    async fn parse_relative_file_produces_a_correct_parse_result() -> CorulixResult<()> {
        let root_dir = temp_workspace("async-parse");
        fs::write(root_dir.join("main.rs"), "fn corulix_demo() {}")
            .map_err(|_| CorulixError::Internal)?;
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = Arc::new(CorulixEngine::open(context));

        let (summary, facts) = engine
            .parse_relative_file(PathBuf::from("main.rs"), None)
            .await?;
        assert!(!summary.has_syntax_error);
        assert!(
            summary
                .symbols
                .iter()
                .any(|symbol| symbol.name == "corulix_demo")
        );
        assert!(
            facts.iter().any(|fact| fact.name == "corulix_demo"),
            "expected a compact structural fact for the parsed symbol"
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    #[test]
    fn multi_root_workspace_info_reports_root_count() -> CorulixResult<()> {
        let a = temp_workspace("info-a");
        let b = temp_workspace("info-b");
        let context = WorkspaceContext::from_roots(vec![
            (
                wht_corulix_workspace::WorkspaceRoot::open(&a)?,
                "a".to_string(),
            ),
            (
                wht_corulix_workspace::WorkspaceRoot::open(&b)?,
                "b".to_string(),
            ),
        ])?;
        let engine = CorulixEngine::open(context);
        assert!(engine.workspace_info().root_label.contains('2'));
        assert_eq!(engine.topology_summary().roots.len(), 2);
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        Ok(())
    }

    /// `plan_operation_for_language` genuinely reaches
    /// `planning::plan_operation`'s language-aware path (Section 19): a
    /// language-scoped semantic plan and the pre-existing category-level
    /// `plan_operation` agree on `Unexecutable` here (the compiled-in
    /// `ProviderSnapshot::current()` this engine derives from carries no
    /// per-language resolutions yet), but they now go through genuinely
    /// distinct code paths rather than `plan_operation_for_language`
    /// silently ignoring its own `language` argument.
    #[test]
    fn plan_operation_for_language_reaches_the_language_aware_routing_path() -> CorulixResult<()> {
        let path = temp_workspace("plan-language");
        let root = wht_corulix_workspace::WorkspaceRoot::open(&path)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = CorulixEngine::open(context);
        let category_level = engine.plan_operation(OperationIntent::SemanticDefinition);
        let language_scoped = engine.plan_operation_for_language(
            OperationIntent::SemanticDefinition,
            Some(wht_corulix_core::LanguageId::Rust),
        );
        assert_eq!(category_level.executability, language_scoped.executability);
        assert!(matches!(
            language_scoped.executability,
            wht_corulix_core::PlanExecutability::Unexecutable {
                reason: wht_corulix_core::ReasonCode::RequiredProviderUnavailable
            }
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }
}
