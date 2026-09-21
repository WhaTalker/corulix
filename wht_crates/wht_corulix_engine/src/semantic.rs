// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13: the real, gated `semantic` capability behind the `semantic`
//! MCP tool (`definition | references | diagnostics | rename_preview`).
//!
//! Architecture Rule H: `RiskClass`/`ToolPlan`/required-gate derivation
//! still runs exactly once, through [`planning::plan_operation`] -- this
//! module never re-derives that logic, only feeds it a fresh
//! [`ProviderSnapshot`] whose `LanguageServer` overlay reflects a *real*
//! per-call resolution attempt (via `CorulixEngine::ensure_rust_lsp_session`)
//! rather than the compiled-in, always-unavailable
//! [`ProviderSnapshot::current`] alone.
//!
//! Real for [`LanguageId::Rust`] only, this phase (Section 19/49 of the
//! mandate scopes Go/TypeScript/Python semantic wiring as later, separate
//! work): a real, managed-first-then-`HOST_ONLY`
//! [`wht_corulix_lsp::LspSession`] (rust-analyzer) is spawned and driven
//! through this crate's own `effective_config`/`resolve_workspace_root`,
//! calling `wht_corulix_lsp`'s own real
//! `definition`/`references`/`diagnostics`/`rename_preview` entry points --
//! never re-implementing LSP transport/JSON-RPC here (Architecture Rule L
//! stays `wht_corulix_lsp`'s alone). Every other [`LanguageId`] still
//! reports `Unavailable` honestly: no session is even attempted for them.
//!
//! Every `wht_corulix_lsp` DTO (`DefinitionResult`, `ReferencesResult`,
//! `DiagnosticsResult`, `RenameEditPreview`, ...) is intentionally not
//! `Serialize`/`JsonSchema` (Rule L keeps that crate's public surface
//! Rust-internal) -- this module owns the one translation into this
//! crate's own serializable DTOs, the same pattern `wht_corulix_mcp`'s own
//! `dto.rs` already establishes for MCP-facing types.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use wht_corulix_core::{
    LanguageId, OperationIntent, Position, ProviderAvailability, ReasonCode, SourceRange,
};

use crate::CorulixEngine;
use crate::planning;
use crate::providers::ProviderSnapshot;

/// Which of the four `semantic` sub-operations a caller requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SemanticOperation {
    Definition,
    References,
    Diagnostics,
    RenamePreview,
}

impl SemanticOperation {
    fn intent(self) -> OperationIntent {
        match self {
            Self::Definition => OperationIntent::SemanticDefinition,
            Self::References => OperationIntent::SemanticReferences,
            Self::Diagnostics => OperationIntent::SemanticDiagnostics,
            Self::RenamePreview => OperationIntent::SemanticRename,
        }
    }
}

/// A caller-supplied target: workspace-relative path plus a full source
/// position (line, UTF-8 byte column, and byte offset -- every field
/// [`wht_corulix_core::Position`] itself requires). `new_name` is read only
/// for [`SemanticOperation::RenamePreview`].
#[derive(Debug, Clone)]
pub struct SemanticTarget {
    pub relative_path: String,
    pub position: Position,
    pub new_name: Option<String>,
}

/// This crate's own serializable mirror of [`wht_corulix_lsp::SemanticLocation`].
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct SemanticLocationDto {
    pub relative_path: String,
    pub range: SourceRange,
}

impl From<&wht_corulix_lsp::SemanticLocation> for SemanticLocationDto {
    fn from(value: &wht_corulix_lsp::SemanticLocation) -> Self {
        Self {
            relative_path: value.path.relative_path.clone(),
            range: value.range,
        }
    }
}

/// This crate's own serializable mirror of [`wht_corulix_lsp::DefinitionResult`].
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DefinitionResultDto {
    None,
    Single(SemanticLocationDto),
    Multiple { locations: Vec<SemanticLocationDto> },
}

/// This crate's own serializable mirror of [`wht_corulix_lsp::ReferencesResult`].
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReferencesResultDto {
    NotReady,
    Found { locations: Vec<SemanticLocationDto> },
}

#[derive(Debug, Clone, Copy, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverityDto {
    Error,
    Warning,
    Information,
    Hint,
}

impl From<wht_corulix_lsp::DiagnosticSeverity> for DiagnosticSeverityDto {
    fn from(value: wht_corulix_lsp::DiagnosticSeverity) -> Self {
        match value {
            wht_corulix_lsp::DiagnosticSeverity::Error => Self::Error,
            wht_corulix_lsp::DiagnosticSeverity::Warning => Self::Warning,
            wht_corulix_lsp::DiagnosticSeverity::Information => Self::Information,
            wht_corulix_lsp::DiagnosticSeverity::Hint => Self::Hint,
        }
    }
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct SemanticDiagnosticDto {
    pub range: SourceRange,
    pub severity: DiagnosticSeverityDto,
    pub message: String,
    pub source: Option<String>,
    pub code: Option<String>,
}

impl From<&wht_corulix_lsp::SemanticDiagnostic> for SemanticDiagnosticDto {
    fn from(value: &wht_corulix_lsp::SemanticDiagnostic) -> Self {
        Self {
            range: value.range,
            severity: value.severity.into(),
            message: value.message.clone(),
            source: value.source.clone(),
            code: value.code.clone(),
        }
    }
}

/// This crate's own serializable mirror of [`wht_corulix_lsp::DiagnosticsResult`].
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiagnosticsResultDto {
    NotReady,
    Reported {
        diagnostics: Vec<SemanticDiagnosticDto>,
    },
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ProposedTextEditDto {
    pub range: SourceRange,
    pub new_text: String,
}

/// This crate's own serializable mirror of [`wht_corulix_lsp::RenameEditPreview`].
/// `RENAME_PREVIEW_MUTATION_COUNT=0` here too: this is a translation of an
/// already-computed preview, never an applied edit.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RenameEditPreviewDto {
    pub edits_by_path: Vec<(String, Vec<ProposedTextEditDto>)>,
}

impl From<&wht_corulix_lsp::RenameEditPreview> for RenameEditPreviewDto {
    fn from(value: &wht_corulix_lsp::RenameEditPreview) -> Self {
        Self {
            edits_by_path: value
                .edits_by_path
                .iter()
                .map(|(path, edits)| {
                    (
                        path.relative_path.clone(),
                        edits
                            .iter()
                            .map(|edit| ProposedTextEditDto {
                                range: edit.range,
                                new_text: edit.new_text.clone(),
                            })
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

/// The outcome of one `semantic` call.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SemanticOutcome {
    /// The gate never opened: no real session could be resolved/spawned/
    /// readied for `language`, or the derived `ToolPlan` itself reports
    /// `Unexecutable`.
    Unavailable {
        operation: SemanticOperation,
        reason_code: ReasonCode,
    },
    Definition {
        result: DefinitionResultDto,
    },
    References {
        result: ReferencesResultDto,
    },
    Diagnostics {
        result: DiagnosticsResultDto,
    },
    RenamePreview {
        result: RenameEditPreviewDto,
    },
    /// The session was available but the real request itself failed (a
    /// transport error, an unrepresentable result, a target outside the
    /// workspace, ...) -- reported honestly, never silently retried as a
    /// fabricated success.
    RequestFailed {
        operation: SemanticOperation,
        reason_code: ReasonCode,
    },
}

fn lsp_error_reason(error: &wht_corulix_lsp::LspError) -> ReasonCode {
    match error {
        wht_corulix_lsp::LspError::ProviderSpawnFailed
        | wht_corulix_lsp::LspError::InitializationFailed
        // M09-P8: both indicate the provider/session is permanently
        // unusable (terminated on an observed root-identity mismatch, or
        // already invalidated by a prior one) -- the same bucket as an
        // outright spawn/initialization failure, never a merely-transient
        // capability gap.
        | wht_corulix_lsp::LspError::RootIdentityMismatch
        | wht_corulix_lsp::LspError::SessionInvalidated => {
            ReasonCode::RequiredProviderUnavailable
        }
        wht_corulix_lsp::LspError::NotReady(_) => ReasonCode::RequiredCapabilityUnavailable,
        wht_corulix_lsp::LspError::Transport(_)
        | wht_corulix_lsp::LspError::ResultOutsideWorkspace
        | wht_corulix_lsp::LspError::UnrepresentableResult
        | wht_corulix_lsp::LspError::SourceUnavailable => ReasonCode::RequiredCapabilityUnavailable,
    }
}

/// Runs a freshly-[`wht_corulix_lsp::LspSession::spawn`]ed session's
/// remaining readiness steps -- `ensure_open(target_path)` first when
/// `target_path` is `Some` (gopls/Pyright/TS's document-scoped readiness
/// signals require the document be open before they ever fire; see each
/// `ensure_*_lsp_session`'s own doc comment), then `wait_until_ready` -- and
/// atomically caches the session into `slot` only once every step succeeds.
///
/// Shared by every `ensure_*_lsp_session` method (Rust/Go/TypeScript/Tsx/
/// JavaScript/Python) so this lifecycle guarantee is generic, not
/// duplicated -- or, worse, accidentally divergent -- per language.
///
/// # Why this exists: `FAILED_LSP_STARTUP_LEAK_COUNT=0`
///
/// `LspSession` has no `Drop` impl (deliberately -- shutdown is a multi-step
/// async LSP exchange, `shutdown`/`exit`/graceful-wait/force-terminate, that
/// cannot run inside a synchronous `Drop::drop`), so a session that is
/// spawned but never becomes *this engine's own cached, owned* session for
/// its language must be explicitly [`wht_corulix_lsp::LspSession::shutdown`]
/// before this function returns -- on **every** path that does not end in
/// `*guard = Some(...)`: `ensure_open` failing, `wait_until_ready` failing,
/// and even the success path racing another concurrent caller and losing
/// (the just-readied session is still real and still running; it must be
/// shut down like any other session this engine decided not to keep, not
/// silently dropped). Found and fixed after repeated failed Rust session
/// attempts against a real workspace left multiple orphaned managed
/// `rust-analyzer` processes running on a real host -- confirmed empirically,
/// not assumed.
async fn ready_and_cache_session(
    slot: &tokio::sync::Mutex<Option<Arc<wht_corulix_lsp::LspSession>>>,
    session: wht_corulix_lsp::LspSession,
    target_path: Option<&std::path::Path>,
    readiness_timeout: std::time::Duration,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<Arc<wht_corulix_lsp::LspSession>, ReasonCode> {
    if let Some(path) = target_path
        && let Err(error) = session.ensure_open(path).await
    {
        // Root-cause observability (internal only -- the returned
        // `ReasonCode::RequiredCapabilityUnavailable` is unchanged and
        // stays externally indistinguishable from the readiness-timeout
        // branch below, matching this crate's own existing convention of
        // never conflating the *readiness* class with the resolution/
        // spawn class instrumented in `ensure_rust_lsp_session` above).
        tracing::warn!(
            failure_stage = "LSP_INITIALIZATION",
            internal_failure_kind = ?error,
            "ensure_open failed before readiness could even be awaited"
        );
        session.shutdown(cancellation).await;
        return Err(ReasonCode::RequiredCapabilityUnavailable);
    }
    if let Err(error) = session.wait_until_ready(readiness_timeout).await {
        tracing::warn!(
            failure_stage = "LSP_READINESS",
            internal_failure_kind = ?error,
            readiness_timeout_ms = readiness_timeout.as_millis() as u64,
            "wait_until_ready timed out or the readiness channel closed"
        );
        session.shutdown(cancellation).await;
        return Err(ReasonCode::RequiredCapabilityUnavailable);
    }

    let session = Arc::new(session);
    let mut guard = slot.lock().await;
    if let Some(existing) = guard.as_ref() {
        let existing = Arc::clone(existing);
        drop(guard);
        session.shutdown(cancellation).await;
        return Ok(existing);
    }
    *guard = Some(Arc::clone(&session));
    Ok(session)
}

/// A real, cheap (no process spawn), managed-first-only availability check
/// for `rustfmt` -- `Available` only when both the managed `rustfmt`
/// component and its managed Rust-semantic-runtime dependency are actually
/// provisioned (`wht_corulix_tooling::provisioning::resolve_owned_managed_component`,
/// the same ownership-checked authority every other managed-first spawn
/// path in this workspace uses), matching
/// `wht_corulix_formatter::managed::resolve_rustfmt`'s own managed-branch
/// precedence exactly. Never consults ambient `PATH`; never attempts the
/// `HOST_ONLY`/system fallback (this engine's bare `effective_config`
/// grants no approved directories for it to succeed against anyway -- see
/// `format_preview`'s own module doc for the identical reasoning).
fn real_managed_formatter_resolution(
    managed_root: &std::path::Path,
) -> wht_corulix_config::ProviderResolution {
    use wht_corulix_core::{ExecutionClass, ProviderAvailability, ProviderCategory, ReasonCode};
    use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

    let (rustfmt_state, _) = provisioning::resolve_owned_managed_component(
        managed_root,
        &wht_corulix_formatter::managed_toolchain::RUSTFMT_LINUX_X64,
    );
    let (runtime_state, _) = provisioning::resolve_owned_managed_component(
        managed_root,
        &wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64,
    );
    let available = rustfmt_state == ManagedComponentState::Available
        && runtime_state == ManagedComponentState::Available;

    wht_corulix_config::ProviderResolution {
        category: ProviderCategory::Formatter,
        availability: if available {
            ProviderAvailability::Available
        } else {
            ProviderAvailability::ProviderUnavailable
        },
        resolved_path: None,
        provenance: None,
        execution_class: ExecutionClass::ControlledExternalTool,
        reason: if available {
            None
        } else {
            Some(ReasonCode::RequiredProviderUnavailable)
        },
    }
}

/// `SemanticOperation::RenamePreview`'s policy entry (`SEMANTIC_RENAME`)
/// also requires `ProviderCategory::TypecheckBuild` (`Authoritative`,
/// `High`-risk minimum-sufficient-tooling) and `ProviderCategory::Linter`
/// (`SupportingOnly`) -- both real, cheap, no-process-spawn checks reusing
/// this crate's own already-certified `diagnostics::resolve_runtime`/
/// `resolve_clippy_binaries` (the exact same managed runtime
/// `validate_change`'s real `cargo check`/`cargo clippy` invocation already
/// resolves through), never a second, divergent resolution path.
fn real_managed_typecheck_and_linter_resolutions(
    managed_root: &std::path::Path,
) -> [wht_corulix_config::ProviderResolution; 2] {
    use wht_corulix_core::{ExecutionClass, ProviderAvailability, ProviderCategory, ReasonCode};

    let install_dir = crate::diagnostics::resolve_runtime(managed_root).ok();
    let typecheck_available = install_dir.is_some();
    let linter_available = install_dir.is_some()
        && crate::diagnostics::resolve_clippy_binaries(
            managed_root,
            &crate::diagnostics::rust_semantic_runtime_host_native(),
        )
        .is_ok();

    let resolution = |category, available: bool| wht_corulix_config::ProviderResolution {
        category,
        availability: if available {
            ProviderAvailability::Available
        } else {
            ProviderAvailability::ProviderUnavailable
        },
        resolved_path: None,
        provenance: None,
        execution_class: ExecutionClass::ControlledExternalTool,
        reason: if available {
            None
        } else {
            Some(ReasonCode::RequiredProviderUnavailable)
        },
    };
    [
        resolution(ProviderCategory::TypecheckBuild, typecheck_available),
        resolution(ProviderCategory::Linter, linter_available),
    ]
}

/// M03 rename_preview managed auxiliary capability closure: managed-first,
/// `HOST_ONLY`-fallback-on-legitimate-absence availability resolution for
/// Go's three non-LSP provider categories, so a Go `SEMANTIC_RENAME` plan --
/// whose policy entry requires `Formatter` (`SupportingOnly`),
/// `TypecheckBuild` (`Authoritative`) and `Linter` (`SupportingOnly`) in
/// addition to `LanguageServer` -- is evaluated against Go's *real*
/// providers rather than against Rust's managed components, which are
/// irrelevant to a Go operation and would make every Go rename spuriously
/// `Unexecutable`.
///
/// Category mapping is `crate::go_providers`'s own table: `Formatter` =
/// `gofmt`, `TypecheckBuild` = `go` (`go build`), `Linter` = `go` (`go
/// vet`). `TypecheckBuild`/`Linter` are wired to
/// [`crate::go_providers::resolve_go_toolchain`] -- the same managed-first
/// resolver `crate::go_validation`/`crate::go_testing` already use for the
/// real `go build`/`go vet`/`go test` invocations this policy check must
/// agree with (before this pass, this function called
/// `wht_corulix_config::resolve_provider` directly, a real wiring gap: the
/// managed tier existed and was already used elsewhere in this crate, but
/// this policy check alone never consulted it, so a host with only a
/// managed Go toolchain -- no `HostConfig` grant at all -- saw every Go
/// rename spuriously `Unexecutable` despite `go build`/`go vet` themselves
/// working). `Formatter` mirrors [`real_managed_formatter_resolution`]'s own
/// shape: a real, cheap (no process spawn) managed-tier presence/ownership
/// check against the shared go-semantic-runtime component, structurally
/// guaranteed consistent with `wht_corulix_formatter::managed::resolve_formatter`'s
/// own independent resolution of the same component (both read the same
/// ownership records; neither calls the other -- the same "two call sites,
/// one ground truth" precedent [`real_managed_formatter_resolution`]
/// already establishes for Rust).
async fn real_go_provider_resolutions(
    managed_root: &std::path::Path,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    cancellation: &wht_corulix_core::CancellationToken,
) -> [wht_corulix_config::ProviderResolution; 3] {
    use wht_corulix_core::{ExecutionClass, ProviderAvailability, ProviderCategory, ReasonCode};
    use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

    let go_runtime_manifest = crate::go_providers::managed_go_runtime_manifest();
    let (runtime_state, _) =
        provisioning::resolve_owned_managed_component(managed_root, &go_runtime_manifest);
    let formatter = if runtime_state == ManagedComponentState::Available {
        wht_corulix_config::ProviderResolution {
            category: ProviderCategory::Formatter,
            availability: ProviderAvailability::Available,
            resolved_path: None,
            provenance: None,
            execution_class: ExecutionClass::ControlledExternalTool,
            reason: None,
        }
    } else {
        // Managed tier genuinely not provisioned (or present-but-invalid --
        // this policy check intentionally does not distinguish the two, it
        // only decides whether to try managed *first*; the real invocation
        // in `wht_corulix_formatter::managed::resolve_formatter` is the one
        // that fails closed on `Corrupt`/`Incompatible` rather than
        // silently falling through). Mirrors `wht_corulix_formatter`'s own
        // managed-then-`HOST_ONLY` precedence for `gofmt` exactly -- a host
        // that grants `approved_system_directories` for a real `gofmt` (but
        // has no managed go-semantic-runtime provisioned) must still be
        // reported `Available` here, or this policy check would disagree
        // with what the real invocation actually resolves.
        wht_corulix_config::resolve_provider(
            effective,
            workspace_root,
            ProviderCategory::Formatter,
            "gofmt",
        )
        .await
    };

    async fn resolve_go_category(
        managed_root: &std::path::Path,
        effective: &wht_corulix_config::EffectiveConfig,
        workspace_root: &wht_corulix_workspace::WorkspaceRoot,
        category: ProviderCategory,
        cancellation: &wht_corulix_core::CancellationToken,
    ) -> wht_corulix_config::ProviderResolution {
        let available = crate::go_providers::resolve_go_toolchain(
            managed_root,
            effective,
            workspace_root,
            category,
            cancellation,
        )
        .await
        .is_ok();
        wht_corulix_config::ProviderResolution {
            category,
            availability: if available {
                ProviderAvailability::Available
            } else {
                ProviderAvailability::ProviderUnavailable
            },
            resolved_path: None,
            provenance: None,
            execution_class: ExecutionClass::ControlledExternalTool,
            reason: if available {
                None
            } else {
                Some(ReasonCode::RequiredProviderUnavailable)
            },
        }
    }
    let typecheck = resolve_go_category(
        managed_root,
        effective,
        workspace_root,
        ProviderCategory::TypecheckBuild,
        cancellation,
    )
    .await;
    let linter = resolve_go_category(
        managed_root,
        effective,
        workspace_root,
        ProviderCategory::Linter,
        cancellation,
    )
    .await;
    [formatter, typecheck, linter]
}

/// P16: real, cheap (no process spawn) formatter/typecheck/linter
/// availability resolution for the TS-family languages
/// (`TypeScript`/`Tsx`/`JavaScript`), mirroring
/// [`real_managed_typecheck_and_linter_resolutions`]'s managed-first-only
/// precedent but against this phase's own admitted managed components
/// (`dprint`, version-routed `tsc`, `biome`) rather than Rust's. Replaces
/// the pre-P16 `_ =>` arm in [`CorulixEngine::semantic_at`], which
/// evaluated these languages against Rust's own `rustfmt`/`cargo check`/
/// `clippy` managed resolutions -- an unrelated language's provider
/// availability that would make every TS/TSX/JS rename spuriously
/// `Unexecutable` for reasons that have nothing to do with TypeScript or
/// JavaScript. `ADR 0010` is this decision's authority.
fn real_typescript_javascript_provider_resolutions(
    managed_root: &std::path::Path,
) -> [wht_corulix_config::ProviderResolution; 3] {
    use wht_corulix_core::{ExecutionClass, ProviderAvailability, ProviderCategory, ReasonCode};
    use wht_corulix_tooling::provisioning::{self, ManagedComponentState};

    let resolution = |category, available: bool| wht_corulix_config::ProviderResolution {
        category,
        availability: if available {
            ProviderAvailability::Available
        } else {
            ProviderAvailability::ProviderUnavailable
        },
        resolved_path: None,
        provenance: None,
        execution_class: ExecutionClass::ControlledExternalTool,
        reason: if available {
            None
        } else {
            Some(ReasonCode::RequiredProviderUnavailable)
        },
    };

    // Biome is one managed component backing two `ProviderCategory`
    // authorities (`Formatter` and `Linter`) -- resolved once, never as two
    // independently-provisioned identities. Resolved against
    // `BIOME_HOST_NATIVE` (P17-W Stage F), never a hardcoded
    // `BIOME_LINUX_X64` literal -- before this, a real Windows host's own
    // managed-Biome resolution was refused at the platform/architecture
    // admission gate before a single byte was downloaded, even with a valid
    // Windows manifest present.
    let (biome_state, _) = provisioning::resolve_owned_managed_component(
        managed_root,
        &wht_corulix_formatter::managed_toolchain::BIOME_HOST_NATIVE,
    );
    let biome_available = biome_state == ManagedComponentState::Available;
    let formatter_available = biome_available;
    let linter_available = biome_available;

    // Typecheck authority is `tsc`, bundled inside the TS7-native managed
    // component's own tarball (`package/lib/tsc`) -- available whenever the
    // same managed component `ensure_typescript_javascript_lsp_session`'s
    // TS7 branch requires is itself provisioned. This phase does not
    // additionally probe the TS6 component's own `tsc`-equivalent here:
    // per ADR 0010, typecheck version-routing mirrors LSP version-routing,
    // and the common case (`None`/`Some(7)`) is TS7-native.
    let (ts7_state, _) = provisioning::resolve_owned_managed_component(
        managed_root,
        &wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_LINUX_X64,
    );
    let typecheck_available = ts7_state == ManagedComponentState::Available;

    [
        resolution(ProviderCategory::Formatter, formatter_available),
        resolution(ProviderCategory::TypecheckBuild, typecheck_available),
        resolution(ProviderCategory::Linter, linter_available),
    ]
}

/// M03 Python managed-auxiliary final closure: real formatter/typecheck/
/// linter availability resolution for [`LanguageId::Python`], mirroring
/// [`real_go_provider_resolutions`]'s own managed-first-then-`HOST_ONLY`
/// two-tier shape exactly. `Formatter`/`Linter` resolve through
/// `crate::python_providers::resolve_ruff_tool` (managed Ruff 0.16.3 first);
/// `TypecheckBuild` resolves through `crate::python_providers::resolve_pyright_cli`
/// (managed Node + managed Pyright CLI first). `pytest`/`python3` are
/// unaffected by this and continue to resolve `HOST_ONLY`-only elsewhere
/// (ADR 0011 §4/§5, unmodified).
///
/// A managed-tier failure (`Corrupt`/`Incompatible`) reports
/// `ProviderUnavailable` here rather than propagating a distinct error type
/// -- this function's own contract is a `[ProviderResolution; 3]` triple,
/// exactly mirroring how [`real_go_provider_resolutions`]'s TypecheckBuild/
/// Linter arms already map `Err` to `ProviderUnavailable` uniformly. This is
/// availability *reporting* for `SemanticRename`'s Minimum-Sufficient-Tooling
/// gate, not the validators themselves -- `python_validation::run_typecheck`/
/// `run_lint` (invoked only once rename_preview's own plan proceeds) are the
/// ones that would fail closed on a genuinely corrupt managed installation.
async fn real_python_provider_resolutions(
    managed_root: &std::path::Path,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    cancellation: &wht_corulix_core::CancellationToken,
) -> [wht_corulix_config::ProviderResolution; 3] {
    use wht_corulix_core::{ExecutionClass, ProviderAvailability, ProviderCategory};

    fn resolution_from(
        category: ProviderCategory,
        resolved: Result<
            crate::python_providers::ResolvedPythonTool,
            crate::python_providers::PythonProviderError,
        >,
    ) -> wht_corulix_config::ProviderResolution {
        match resolved {
            Ok(tool) => wht_corulix_config::ProviderResolution {
                category,
                availability: ProviderAvailability::Available,
                resolved_path: Some(tool.executable),
                provenance: None,
                execution_class: ExecutionClass::ControlledExternalTool,
                reason: None,
            },
            Err(crate::python_providers::PythonProviderError::ProviderUnavailable(reason)) => {
                wht_corulix_config::ProviderResolution {
                    category,
                    availability: ProviderAvailability::ProviderUnavailable,
                    resolved_path: None,
                    provenance: None,
                    execution_class: ExecutionClass::ControlledExternalTool,
                    reason,
                }
            }
            Err(_) => wht_corulix_config::ProviderResolution {
                category,
                availability: ProviderAvailability::ProviderUnavailable,
                resolved_path: None,
                provenance: None,
                execution_class: ExecutionClass::ControlledExternalTool,
                reason: Some(ReasonCode::RequiredProviderUnavailable),
            },
        }
    }

    let formatter_resolved = crate::python_providers::resolve_ruff_tool(
        managed_root,
        effective,
        workspace_root,
        ProviderCategory::Formatter,
        cancellation,
    )
    .await;
    let linter_resolved = crate::python_providers::resolve_ruff_tool(
        managed_root,
        effective,
        workspace_root,
        ProviderCategory::Linter,
        cancellation,
    )
    .await;
    let typecheck_resolved = crate::python_providers::resolve_pyright_cli(
        managed_root,
        effective,
        workspace_root,
        cancellation,
    )
    .await
    .map(|cli| crate::python_providers::ResolvedPythonTool {
        executable: cli.executable_and_leading_arguments().0,
        version: cli.version().to_string(),
    });

    [
        resolution_from(ProviderCategory::Formatter, formatter_resolved),
        resolution_from(ProviderCategory::TypecheckBuild, typecheck_resolved),
        resolution_from(ProviderCategory::Linter, linter_resolved),
    ]
}

/// P16: bounded, best-effort detection of a workspace's *declared*
/// TypeScript major version from its own `package.json` (ADR 0010:
/// `TS_VERSION_ROUTING_POLICY` -- never an ambient/globally installed
/// TypeScript). Reads `dependencies.typescript`/`devDependencies.typescript`
/// (checked in that order) and extracts the leading digit after any
/// `^`/`~`/`>=` range prefix. Absent, malformed, oversized, or unparseable
/// input all return `None` -- which routes to TS7-native, the documented
/// default -- rather than failing the whole operation: this is a *routing
/// hint*, not a required capability, exactly mirroring how an absent
/// `rustfmt.toml` means "use rustfmt's defaults", not "formatting
/// unavailable".
pub(crate) async fn detect_declared_typescript_major(
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
) -> Option<u32> {
    const MAX_PACKAGE_JSON_BYTES: u64 = 1024 * 1024;
    let bytes = wht_corulix_workspace::confined_read(
        workspace_root.clone(),
        std::path::PathBuf::from("package.json"),
        MAX_PACKAGE_JSON_BYTES,
    )
    .await
    .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let declared = value
        .get("dependencies")
        .and_then(|deps| deps.get("typescript"))
        .or_else(|| {
            value
                .get("devDependencies")
                .and_then(|deps| deps.get("typescript"))
        })
        .and_then(|version| version.as_str())?;
    let digits: String = declared
        .trim_start_matches(['^', '~', '>', '=', ' '])
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u32>().ok()
}

impl CorulixEngine {
    /// P16: this engine's cached, real, *semantically ready*
    /// [`wht_corulix_lsp::LspSession`] for the TS-family languages
    /// (`TypeScript`/`Tsx`/`JavaScript`), spawning one on first use --
    /// mirrors [`Self::ensure_go_lsp_session`]'s exact shape (document-scoped
    /// readiness: `ensure_open` before `wait_until_ready`), since TS7's own
    /// [`wht_corulix_lsp::profile::ReadinessStrategy::FirstPullDiagnosticsResponse`]
    /// is, like gopls's `FirstDiagnosticsPublished`, a per-document signal.
    ///
    /// `declared_major` selects TS7-native vs TS6-managed-compat via
    /// [`wht_corulix_lsp::profile::typescript_profile_for_declared_major`]/
    /// `javascript_profile_for_declared_major`/`tsx_profile_for_declared_major`
    /// (ADR 0010: `TS_VERSION_ROUTING_POLICY`) -- never an ambient/globally
    /// installed TypeScript version. An unsupported declared major (i.e.
    /// `Some(5)` or any value other than `6`/`7`) returns
    /// `RequiredProviderUnavailable` before any process is spawned, per
    /// that same routing table's own `None`-on-unsupported-major contract.
    ///
    /// Unlike Go, no Corulix-owned scratch/cache directory is bound here:
    /// TS7-native and TS6-managed-compat both run as pure, self-contained
    /// analyzers over the files `wht_corulix_lsp` opens for them and create
    /// no build-cache directory of their own the way `go build`/`gopls`
    /// require (`P16_TS7_MANAGED_ROOT_RUNTIME_STATE=[]`,
    /// `P16_TS6_MANAGED_ROOT_RUNTIME_STATE=[]` --
    /// `P16_TS_LSP_ROOT_SCOPED_SCRATCH_BINDING=NOT_APPLICABLE_WITH_EVIDENCE`).
    async fn ensure_typescript_javascript_lsp_session(
        &self,
        managed_root: &std::path::Path,
        language: LanguageId,
        declared_major: Option<u32>,
        target_path: &std::path::Path,
    ) -> Result<Arc<wht_corulix_lsp::LspSession>, ReasonCode> {
        let slot = match language {
            LanguageId::TypeScript => self.typescript_lsp_session(),
            LanguageId::Tsx => self.tsx_lsp_session(),
            LanguageId::JavaScript => self.javascript_lsp_session(),
            _ => return Err(ReasonCode::RequiredProviderUnavailable),
        };

        {
            let guard = slot.lock().await;
            if let Some(session) = guard.as_ref() {
                return Ok(Arc::clone(session));
            }
        }

        let profile = match language {
            LanguageId::TypeScript => {
                wht_corulix_lsp::profile::typescript_profile_for_declared_major(declared_major)
            }
            LanguageId::Tsx => {
                wht_corulix_lsp::profile::tsx_profile_for_declared_major(declared_major)
            }
            LanguageId::JavaScript => {
                wht_corulix_lsp::profile::javascript_profile_for_declared_major(declared_major)
            }
            _ => None,
        }
        .ok_or(ReasonCode::RequiredProviderUnavailable)?;

        let root = self
            .resolve_workspace_root(None)
            .map_err(|_| ReasonCode::RequiredCapabilityUnavailable)?;
        let effective = self.effective_config();
        let launch =
            wht_corulix_lsp::profile::resolve_launch_at(&profile, &effective, &root, managed_root)
                .await
                .map_err(|_| ReasonCode::RequiredProviderUnavailable)?;

        let cancellation = wht_corulix_core::CancellationToken::new();
        let session = wht_corulix_lsp::LspSession::spawn(
            launch,
            &profile,
            root,
            wht_corulix_core::WorkspaceRootId(0),
            &cancellation,
        )
        .await
        .map_err(|_| ReasonCode::RequiredProviderUnavailable)?;

        // Document-scoped readiness (TS7's FirstPullDiagnosticsResponse and
        // TS6's FirstDiagnosticsPublished are both per-document signals):
        // open first, then wait -- see `Self::ensure_go_lsp_session`'s own
        // doc comment for why this ordering matters.
        ready_and_cache_session(
            slot,
            session,
            Some(target_path),
            profile.readiness_timeout,
            &cancellation,
        )
        .await
    }

    /// P17: this engine's cached, real, *semantically ready*
    /// [`wht_corulix_lsp::LspSession`] for [`LanguageId::Python`], spawning
    /// one on first use -- mirrors [`Self::ensure_go_lsp_session`]'s exact
    /// shape (document-scoped readiness: `ensure_open` before
    /// `wait_until_ready`), since Pyright's own
    /// [`wht_corulix_lsp::profile::ReadinessStrategy::FirstDiagnosticsPublished`]
    /// is, like gopls's, a per-document signal (ADR 0009, unchanged by this
    /// phase).
    ///
    /// Routed entirely through the pre-existing `wht_corulix_lsp` machinery
    /// -- [`wht_corulix_lsp::profile::LspProviderProfile::pyright_managed`],
    /// [`wht_corulix_lsp::profile::resolve_launch_at`],
    /// [`wht_corulix_lsp::LspSession::spawn`] -- so `P17_SEMANTIC_PROVIDER=
    /// pyright` holds without a second LSP client, a second provider
    /// resolver, or a second process runtime. Unlike Go, no Corulix-owned
    /// scratch/cache directory is bound here: Pyright's own capability probe
    /// (ADR 0009) confirmed zero project-Python execution and zero
    /// filesystem write of its own.
    async fn ensure_python_lsp_session(
        &self,
        managed_root: &std::path::Path,
        target_path: &std::path::Path,
    ) -> Result<Arc<wht_corulix_lsp::LspSession>, ReasonCode> {
        {
            let guard = self.python_lsp_session().lock().await;
            if let Some(session) = guard.as_ref() {
                return Ok(Arc::clone(session));
            }
        }

        let root = self
            .resolve_workspace_root(None)
            .map_err(|_| ReasonCode::RequiredCapabilityUnavailable)?;
        let effective = self.effective_config();
        // M03 managed-provider-readiness fix: this engine previously called
        // the unmanaged `pyright()` profile (`managed_component: None`),
        // which can only ever resolve `HOST_ONLY`/system, and the default
        // `HostConfig` grants no approved system directories -- so this
        // session could never become available regardless of what was
        // provisioned. `pyright_managed()` already existed, fully built and
        // tested (`real_pyright_managed_e2e.rs`), but nothing in production
        // ever called it. Same defect class as the P16 TS/JS provider
        // misclassification this crate already fixed once.
        let profile = wht_corulix_lsp::profile::LspProviderProfile::pyright_managed();
        let launch =
            wht_corulix_lsp::profile::resolve_launch_at(&profile, &effective, &root, managed_root)
                .await
                .map_err(|_| ReasonCode::RequiredProviderUnavailable)?;

        let cancellation = wht_corulix_core::CancellationToken::new();
        let session = wht_corulix_lsp::LspSession::spawn(
            launch,
            &profile,
            root,
            wht_corulix_core::WorkspaceRootId(0),
            &cancellation,
        )
        .await
        .map_err(|_| ReasonCode::RequiredProviderUnavailable)?;

        // Document-scoped readiness: open first, then wait. See this
        // method's own doc comment.
        ready_and_cache_session(
            self.python_lsp_session(),
            session,
            Some(target_path),
            profile.readiness_timeout,
            &cancellation,
        )
        .await
    }

    /// P15: this engine's cached, real, *semantically ready*
    /// [`wht_corulix_lsp::LspSession`] for [`LanguageId::Go`], spawning one
    /// on first use.
    ///
    /// Routed entirely through the pre-existing multi-language
    /// `wht_corulix_lsp` machinery -- [`wht_corulix_lsp::profile::LspProviderProfile::gopls_managed`]
    /// (M03 managed-provider-readiness pass: previously wired to the
    /// unmanaged [`wht_corulix_lsp::profile::LspProviderProfile::gopls`],
    /// which can only ever resolve `HOST_ONLY`/system and therefore never
    /// becomes available under the default `HostConfig`. An initial attempt
    /// to switch straight to `gopls_managed()` regressed
    /// `real_p15_gopls_active_scratch_lifecycle_e2e.rs`'s real,
    /// explicitly-approved `HOST_ONLY` system-Go scenario, because that
    /// profile's `managed_go_semantic_runtime` had no `HOST_ONLY` fallback
    /// at all at the time -- unlike
    /// [`wht_corulix_lsp::profile::LspProviderProfile::pyright_managed`],
    /// which only *adds* a managed component/interpreter on top of
    /// [`wht_corulix_lsp::profile::LspProviderProfile::pyright`], falling
    /// back to `HOST_ONLY` unchanged. Root cause and owner-authorized fix:
    /// `wht_corulix_engine::go_providers::resolve_go_toolchain` had already
    /// shipped a managed-first-then-`HOST_ONLY`-fallback policy for the
    /// identical `GO_SEMANTIC_RUNTIME_*` component on the `go build`/`go
    /// vet`/`go test` path (Stage A / P17-W Master Closure Order); that
    /// policy had simply never been ported to this LSP-facing resolution.
    /// `managed_go_semantic_runtime`'s resolution in
    /// [`wht_corulix_lsp::profile::resolve_launch_at`] now carries the same
    /// two-tier policy (see that field's own doc comment for the port and
    /// its one deliberate refinement, a `Corrupt`/`Incompatible` fail-closed
    /// guard with no fallback), closing the parity gap rather than leaving
    /// Go managed-only or reverting to unmanaged),
    /// [`wht_corulix_lsp::profile::resolve_launch_at`],
    /// [`wht_corulix_lsp::LspSession::spawn`] -- so
    /// `P15_GO_SEMANTIC_PROVIDER=gopls` and `P15_GOPLS_AUTHORITY=AUTHORITATIVE`
    /// hold without a second LSP client, a second provider resolver, or a
    /// second process runtime existing anywhere (§4/§8). This crate issues no
    /// shell command and spawns no subprocess of its own for Go semantics.
    ///
    /// # Readiness is document-scoped, unlike Rust's
    ///
    /// `P15_GOPLS_READINESS_SIGNAL_PROVEN`: gopls has no
    /// `experimental/serverStatus` equivalent, so its profile uses
    /// `ReadinessStrategy::FirstDiagnosticsPublished` -- and gopls only
    /// publishes diagnostics for a document once that document has been
    /// *opened* (established empirically in Phase 7B and re-proven by P15's
    /// own `real_p15_go_semantic_authority_e2e`). `ensure_open` therefore runs
    /// **before** `wait_until_ready` here, which is the one structural
    /// difference from [`Self::ensure_rust_lsp_session`] and the reason this
    /// method takes `target_path` at all. `PROCESS_STARTED != SEMANTIC_READY`:
    /// until readiness is genuinely observed, `wht_corulix_lsp` reports
    /// `NotReady` rather than an empty result, so no empty answer here can
    /// masquerade as authoritative absence.
    ///
    /// # Go caches never touch the governed workspace
    ///
    /// gopls shells out to the `go` command, which requires a writable build
    /// cache (empirically: it fails outright without one under a cleared
    /// environment). Those caches are Corulix-owned scratch under
    /// `managed_root`, via `crate::go_providers::ensure_go_scratch` -- the
    /// same authority and reasoning `crate::testing` uses for
    /// `CARGO_TARGET_DIR`, never a directory inside the workspace being
    /// governed.
    async fn ensure_go_lsp_session(
        &self,
        managed_root: &std::path::Path,
        target_path: &std::path::Path,
    ) -> Result<Arc<wht_corulix_lsp::LspSession>, ReasonCode> {
        {
            let guard = self.go_lsp_session().lock().await;
            if let Some(session) = guard.as_ref() {
                return Ok(Arc::clone(session));
            }
        }

        let root = self
            .resolve_workspace_root(None)
            .map_err(|_| ReasonCode::RequiredCapabilityUnavailable)?;
        let effective = self.effective_config();
        // M03 managed-provider-readiness fix (owner-authorized Go
        // reconciliation): `gopls_managed()`'s Go-semantic-runtime
        // resolution now carries the same managed-first-then-`HOST_ONLY`
        // policy already shipped for `go build`/`go vet`/`go test` -- see
        // this method's doc comment above and
        // `wht_corulix_lsp::profile::LspProviderProfile::managed_go_semantic_runtime`'s
        // own doc comment for the ported policy.
        let profile = wht_corulix_lsp::profile::LspProviderProfile::gopls_managed();
        let launch =
            wht_corulix_lsp::profile::resolve_launch_at(&profile, &effective, &root, managed_root)
                .await
                .map_err(|_| ReasonCode::RequiredProviderUnavailable)?;

        let scratch = crate::go_providers::ensure_go_scratch(managed_root, root.canonical_path())
            .map_err(|_| ReasonCode::RequiredCapabilityUnavailable)?;
        let environment = launch
            .environment
            .with_var(
                "GOCACHE",
                scratch.build_cache.to_string_lossy().into_owned(),
            )
            .with_var(
                "GOMODCACHE",
                scratch.module_cache.to_string_lossy().into_owned(),
            )
            .with_var("GOPATH", scratch.gopath.to_string_lossy().into_owned())
            .with_var("GOPROXY", "off")
            .with_var("GOFLAGS", "-mod=readonly")
            .with_var("GOTOOLCHAIN", "local");

        // This session's Go caches are Corulix-owned scratch under
        // `managed_root` (the `with_var` calls immediately above), so this
        // live process consumes managed root-level state for its entire
        // run and must be discoverable to the uninstall lifecycle as such.
        // `resolve_launch_at` cannot know that: it fills in the *component*
        // axis, and on a host where `gopls` and `go` both resolve
        // `HOST_ONLY` (`GOPLS_ARTIFACT_DISTRIBUTION_GATE=BLOCKED`) there is
        // no managed component to name, so it correctly returns no binding
        // at all. Declaring the root axis here -- at the one place that
        // actually binds this process to `<root>/scratch` -- is what lets
        // `full_uninstall`'s scratch stage signal, stop, reap and *then*
        // delete, instead of destroying this session's build cache
        // underneath it (Phase 15 gopls lifecycle closure; the pre-fix
        // behavior is reproduced in
        // `real_p15_gopls_active_scratch_lifecycle_e2e`).
        //
        // No lease is constructed or registered here: this only supplies
        // the declaration to `ManagedProcess::spawn` through the existing
        // `ResolvedLaunch::managed_lease` field, exactly as
        // `resolve_launch_at` does, keeping `wht_corulix_tooling` the sole
        // lease authority.
        let root_identity =
            wht_corulix_tooling::provisioning::ownership::root_identity(managed_root);
        let managed_lease = Some(
            launch
                .managed_lease
                .clone()
                .unwrap_or_else(|| {
                    wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                        wht_corulix_tooling::provisioning::lease::RootIdentity::of(managed_root),
                        wht_corulix_lsp::profile::LspProviderProfile::gopls_managed().provider_id,
                        Vec::new(),
                    )
                })
                .in_managed_root(root_identity),
        );
        let launch = wht_corulix_lsp::ResolvedLaunch {
            environment,
            managed_lease,
            ..launch
        };

        let cancellation = wht_corulix_core::CancellationToken::new();
        let session = wht_corulix_lsp::LspSession::spawn(
            launch,
            &profile,
            root,
            wht_corulix_core::WorkspaceRootId(0),
            &cancellation,
        )
        .await
        .map_err(|_| ReasonCode::RequiredProviderUnavailable)?;

        // Document-scoped readiness: open first, then wait. See this
        // method's own doc comment.
        ready_and_cache_session(
            self.go_lsp_session(),
            session,
            Some(target_path),
            profile.readiness_timeout,
            &cancellation,
        )
        .await
    }

    /// Returns this engine's cached, real, ready [`wht_corulix_lsp::LspSession`]
    /// for [`LanguageId::Rust`], spawning and readying one on first use if
    /// none is cached yet. `Err` is the real, honest outcome of a genuine
    /// resolution/spawn/readiness attempt -- never a stub.
    ///
    /// Managed-first-then-`HOST_ONLY` (via
    /// [`wht_corulix_lsp::profile::resolve_launch`], the same real
    /// resolution precedent every other managed provider in this workspace
    /// uses): this engine's own [`Self::effective_config`] grants no
    /// approved system directories, so in practice this only succeeds once
    /// a real managed rust-analyzer *and* managed Rust semantic runtime are
    /// provisioned under the real
    /// [`wht_corulix_tooling::provisioning::managed_toolchain_root`] --
    /// genuinely fail-closed otherwise.
    ///
    /// `managed_root` is threaded explicitly (never resolved internally)
    /// so that an isolated test context can exercise this real path
    /// without ever touching the shared, host-wide
    /// `wht_corulix_tooling::provisioning::managed_toolchain_root()` --
    /// mirroring `wht_corulix_formatter::format_preview_at`'s and
    /// `wht_corulix_lsp::profile::resolve_launch_at`'s own precedent. The
    /// resulting session is cached on this engine instance regardless of
    /// which root produced it: whichever caller wins the race first
    /// determines the root for the lifetime of this engine (documented
    /// here, not hidden) -- callers that need two different roots against
    /// one workspace must use two separate `CorulixEngine` instances, the
    /// same isolation boundary every other `_at`-parameterized entry point
    /// in this workspace already assumes.
    // Root-cause observability (internal only -- see this function's own
    // instrumented error-mapping sites below): `tracing::instrument`
    // reuses this workspace's existing `tracing` convention (never a new,
    // parallel correlation mechanism) to give every diagnostic emitted
    // during one managed-provider lifecycle attempt -- resolution,
    // spawn, initialization, readiness -- a single shared span, so they
    // can be correlated after the fact without inventing a manual
    // attempt-id field threaded through every call.
    #[tracing::instrument(skip(self, managed_root), fields(provider_id = "rust-analyzer"))]
    async fn ensure_rust_lsp_session(
        &self,
        managed_root: &std::path::Path,
    ) -> Result<Arc<wht_corulix_lsp::LspSession>, ReasonCode> {
        {
            let guard = self.rust_lsp_session().lock().await;
            if let Some(session) = guard.as_ref() {
                return Ok(Arc::clone(session));
            }
        }

        let root = self
            .resolve_workspace_root(None)
            .map_err(|_| ReasonCode::RequiredCapabilityUnavailable)?;
        let effective = self.effective_config();
        let profile = wht_corulix_lsp::profile::LspProviderProfile::rust_analyzer_managed();
        let launch =
            wht_corulix_lsp::profile::resolve_launch_at(&profile, &effective, &root, managed_root)
                .await
                .map_err(|error| {
                    tracing::warn!(
                        failure_stage = "MANAGED_EXECUTABLE_RESOLUTION",
                        internal_failure_kind = ?error,
                        "resolve_launch_at failed"
                    );
                    ReasonCode::RequiredProviderUnavailable
                })?;

        let cancellation = wht_corulix_core::CancellationToken::new();
        let spawn_started_at = std::time::Instant::now();
        let session = wht_corulix_lsp::LspSession::spawn(
            launch,
            &profile,
            root,
            wht_corulix_core::WorkspaceRootId(0),
            &cancellation,
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                failure_stage = "LSP_PROCESS_SPAWN",
                internal_failure_kind = ?error,
                elapsed_ms = spawn_started_at.elapsed().as_millis() as u64,
                "LspSession::spawn failed"
            );
            ReasonCode::RequiredProviderUnavailable
        })?;

        ready_and_cache_session(
            self.rust_lsp_session(),
            session,
            None,
            profile.readiness_timeout,
            &cancellation,
        )
        .await
    }

    /// The real, gated `semantic` capability, resolved against the real,
    /// shared, host-wide
    /// [`wht_corulix_tooling::provisioning::managed_toolchain_root`]. This
    /// is the production entry point (used by `wht_corulix_mcp`'s
    /// `semantic` tool handler); see [`Self::semantic_at`] for the
    /// isolated-root variant real E2E tests must use instead, to avoid
    /// polluting the shared root's state for the rest of the test suite.
    pub async fn semantic(
        &self,
        operation: SemanticOperation,
        language: LanguageId,
        target: SemanticTarget,
    ) -> SemanticOutcome {
        let managed_root = match wht_corulix_tooling::provisioning::managed_toolchain_root() {
            Ok(root) => root,
            Err(_) => {
                return SemanticOutcome::Unavailable {
                    operation,
                    reason_code: ReasonCode::RequiredProviderUnavailable,
                };
            }
        };
        self.semantic_at(&managed_root, operation, language, target)
            .await
    }

    /// The real logic behind [`Self::semantic`], parameterized on an
    /// explicit `managed_root` rather than resolving the host-wide
    /// canonical root internally -- the same `_at(root)` precedent already
    /// established by `wht_corulix_formatter::format_preview_at` and
    /// `wht_corulix_lsp::profile::resolve_launch_at`, kept `pub` for the
    /// same reason those are. The real, positive-path `semantic` E2E
    /// (`wht_corulix_mcp/tests/real_p13_mcp_managed_provider_isolated_e2e.rs`)
    /// exercises this method only indirectly -- by spawning the real
    /// compiled binary with `XDG_DATA_HOME` redirected to a disposable,
    /// isolated root, so the real `semantic` MCP tool's own call into
    /// [`Self::semantic`] resolves that same isolated root and, in turn,
    /// calls this method internally -- rather than calling it directly,
    /// since that E2E must exercise the real MCP tool end to end, never
    /// bypass it (see CHANGELOG.md's Phase 13 Section L). This is also
    /// why provisioning a real rust-analyzer/rustfmt for that test never
    /// changes the outcome of unrelated tests elsewhere that assume
    /// nothing is provisioned in the real, shared, process-wide root.
    pub async fn semantic_at(
        &self,
        managed_root: &std::path::Path,
        operation: SemanticOperation,
        language: LanguageId,
        target: SemanticTarget,
    ) -> SemanticOutcome {
        let scope = self.target_scope();

        // P15/P16: Go, then TypeScript/Tsx/JavaScript, join Rust as
        // genuinely-wired languages. Every remaining `LanguageId` (Python)
        // stays honestly unattempted -- no session is even spawned for it --
        // until its own phase (P17) admits a provider.
        let session_attempt = match language {
            LanguageId::Rust => self.ensure_rust_lsp_session(managed_root).await,
            LanguageId::Go => {
                // gopls readiness is document-scoped, so the session must be
                // opened against the very file this call targets. The path is
                // resolved under workspace confinement (Rule F) before being
                // handed to `wht_corulix_lsp`, so a traversal attempt in
                // `relative_path` can never reach outside the root.
                match self
                    .resolve_confined(std::path::PathBuf::from(&target.relative_path), None)
                    .await
                {
                    Ok(absolute) => self.ensure_go_lsp_session(managed_root, &absolute).await,
                    Err(_) => Err(ReasonCode::RequiredCapabilityUnavailable),
                }
            }
            LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript => {
                // TS7/TS6 readiness is likewise document-scoped -- see
                // `Self::ensure_typescript_javascript_lsp_session`'s own doc
                // comment. `declared_major` is a routing hint read from this
                // same confined workspace, never an ambient TypeScript
                // install.
                match self
                    .resolve_confined(std::path::PathBuf::from(&target.relative_path), None)
                    .await
                {
                    Ok(absolute) => match self.resolve_workspace_root(None) {
                        Ok(root) => {
                            let declared_major = detect_declared_typescript_major(&root).await;
                            self.ensure_typescript_javascript_lsp_session(
                                managed_root,
                                language,
                                declared_major,
                                &absolute,
                            )
                            .await
                        }
                        Err(_) => Err(ReasonCode::RequiredCapabilityUnavailable),
                    },
                    Err(_) => Err(ReasonCode::RequiredCapabilityUnavailable),
                }
            }
            LanguageId::Python => {
                // Pyright readiness is document-scoped too (see
                // `Self::ensure_python_lsp_session`'s own doc comment), so
                // this must resolve the target's confined absolute path
                // before spawning/opening -- exactly the same pattern as the
                // Go and TS/JS arms above.
                match self
                    .resolve_confined(std::path::PathBuf::from(&target.relative_path), None)
                    .await
                {
                    Ok(absolute) => {
                        self.ensure_python_lsp_session(managed_root, &absolute)
                            .await
                    }
                    Err(_) => Err(ReasonCode::RequiredCapabilityUnavailable),
                }
            }
            _ => Err(ReasonCode::RequiredProviderUnavailable),
        };

        let availability = match &session_attempt {
            Ok(_) => ProviderAvailability::Available,
            Err(_) => ProviderAvailability::ProviderUnavailable,
        };
        // `SemanticOperation::RenamePreview`'s policy entry (`SEMANTIC_RENAME`
        // in `policy.rs`) also requires `ProviderCategory::Formatter`
        // (`SupportingOnly` authority, but still `Required`) -- a real,
        // managed-first-only check (mirroring `wht_corulix_formatter::
        // managed::resolve_rustfmt`'s own precedence; this engine's
        // `effective_config` grants no `HostConfig` approved directories,
        // so only the `CORULIX_MANAGED` path can ever succeed for a bare
        // session here, exactly as `format_preview` already established).
        //
        // P15: which providers those are is language-dependent. Rust's are
        // `CORULIX_MANAGED` components; Go's are `HOST_ONLY`-resolved
        // `gofmt`/`go` (see `real_go_provider_resolutions`). Evaluating a Go
        // rename against Rust's managed components would report every Go
        // rename `Unexecutable` for reasons that have nothing to do with Go.
        // P16 fix: this used to be a single `_ => { .. Rust's own managed
        // resolutions .. }` arm applying to *every* non-Go language,
        // including TypeScript/Tsx/JavaScript -- misclassifying them
        // against rustfmt/cargo-check/clippy availability that has nothing
        // to do with TS/JS (ADR 0010, `PROVIDER_RESOLUTION_MODEL`;
        // `P16_TS_JS_RUST_PROVIDER_MISCLASSIFICATION_COUNT=0`). Every
        // language now gets its own explicit arm; a language with no
        // admitted resolution yet (currently only `LanguageId::Python`)
        // reports a real, typed "not yet admitted" outcome rather than
        // silently inheriting another language's providers.
        let resolutions: [wht_corulix_config::ProviderResolution; 3] = match language {
            LanguageId::Rust => {
                let formatter_resolution = real_managed_formatter_resolution(managed_root);
                let [typecheck_resolution, linter_resolution] =
                    real_managed_typecheck_and_linter_resolutions(managed_root);
                [
                    formatter_resolution,
                    typecheck_resolution,
                    linter_resolution,
                ]
            }
            LanguageId::Go => match self.resolve_workspace_root(None) {
                Ok(root) => {
                    let cancellation = wht_corulix_core::CancellationToken::new();
                    real_go_provider_resolutions(
                        managed_root,
                        &self.effective_config(),
                        &root,
                        &cancellation,
                    )
                    .await
                }
                Err(_) => {
                    return SemanticOutcome::Unavailable {
                        operation,
                        reason_code: ReasonCode::RequiredCapabilityUnavailable,
                    };
                }
            },
            LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript => {
                real_typescript_javascript_provider_resolutions(managed_root)
            }
            LanguageId::Python => match self.resolve_workspace_root(None) {
                Ok(root) => {
                    let cancellation = wht_corulix_core::CancellationToken::new();
                    real_python_provider_resolutions(
                        managed_root,
                        &self.effective_config(),
                        &root,
                        &cancellation,
                    )
                    .await
                }
                Err(_) => {
                    return SemanticOutcome::Unavailable {
                        operation,
                        reason_code: ReasonCode::RequiredCapabilityUnavailable,
                    };
                }
            },
            _ => {
                use wht_corulix_core::{ExecutionClass, ProviderAvailability, ProviderCategory};
                let unavailable = |category| wht_corulix_config::ProviderResolution {
                    category,
                    availability: ProviderAvailability::ProviderUnavailable,
                    resolved_path: None,
                    provenance: None,
                    execution_class: ExecutionClass::ControlledExternalTool,
                    reason: Some(ReasonCode::RequiredProviderUnavailable),
                };
                [
                    unavailable(ProviderCategory::Formatter),
                    unavailable(ProviderCategory::TypecheckBuild),
                    unavailable(ProviderCategory::Linter),
                ]
            }
        };
        let snapshot = ProviderSnapshot::from_resolutions(&resolutions)
            .with_language_server_resolutions(&[(language, availability)]);

        let plan = planning::plan_operation(operation.intent(), scope, &snapshot, Some(language));
        let session = match plan.executability {
            wht_corulix_core::PlanExecutability::Unexecutable { reason } => {
                return SemanticOutcome::Unavailable {
                    operation,
                    reason_code: reason,
                };
            }
            wht_corulix_core::PlanExecutability::Executable => match session_attempt {
                Ok(session) => session,
                Err(reason_code) => {
                    return SemanticOutcome::Unavailable {
                        operation,
                        reason_code,
                    };
                }
            },
            _ => {
                return SemanticOutcome::Unavailable {
                    operation,
                    reason_code: ReasonCode::RequiredProviderUnavailable,
                };
            }
        };

        let absolute_path = session
            .workspace_root()
            .canonical_path()
            .join(&target.relative_path);
        let cancellation = wht_corulix_core::CancellationToken::new();

        match operation {
            SemanticOperation::Definition => {
                match wht_corulix_lsp::definition(
                    &session,
                    &absolute_path,
                    &target.position,
                    &cancellation,
                )
                .await
                {
                    Ok(result) => SemanticOutcome::Definition {
                        result: match &result {
                            wht_corulix_lsp::DefinitionResult::None => DefinitionResultDto::None,
                            wht_corulix_lsp::DefinitionResult::Single(location) => {
                                DefinitionResultDto::Single(location.into())
                            }
                            wht_corulix_lsp::DefinitionResult::Multiple(locations) => {
                                DefinitionResultDto::Multiple {
                                    locations: locations.iter().map(Into::into).collect(),
                                }
                            }
                        },
                    },
                    Err(error) => SemanticOutcome::RequestFailed {
                        operation,
                        reason_code: lsp_error_reason(&error),
                    },
                }
            }
            SemanticOperation::References => {
                match wht_corulix_lsp::references(
                    &session,
                    &absolute_path,
                    &target.position,
                    &cancellation,
                )
                .await
                {
                    Ok(result) => SemanticOutcome::References {
                        result: match &result {
                            wht_corulix_lsp::ReferencesResult::NotReady => {
                                ReferencesResultDto::NotReady
                            }
                            wht_corulix_lsp::ReferencesResult::Found(locations) => {
                                ReferencesResultDto::Found {
                                    locations: locations.iter().map(Into::into).collect(),
                                }
                            }
                        },
                    },
                    Err(error) => SemanticOutcome::RequestFailed {
                        operation,
                        reason_code: lsp_error_reason(&error),
                    },
                }
            }
            SemanticOperation::Diagnostics => {
                match wht_corulix_lsp::diagnostics(&session, &absolute_path).await {
                    Ok(result) => SemanticOutcome::Diagnostics {
                        result: match &result {
                            wht_corulix_lsp::DiagnosticsResult::NotReady => {
                                DiagnosticsResultDto::NotReady
                            }
                            wht_corulix_lsp::DiagnosticsResult::Reported(diagnostics) => {
                                DiagnosticsResultDto::Reported {
                                    diagnostics: diagnostics.iter().map(Into::into).collect(),
                                }
                            }
                        },
                    },
                    Err(error) => SemanticOutcome::RequestFailed {
                        operation,
                        reason_code: lsp_error_reason(&error),
                    },
                }
            }
            SemanticOperation::RenamePreview => {
                let Some(new_name) = target.new_name.as_deref() else {
                    return SemanticOutcome::RequestFailed {
                        operation,
                        reason_code: ReasonCode::RequiredCapabilityUnavailable,
                    };
                };
                match wht_corulix_lsp::rename_preview(
                    &session,
                    &absolute_path,
                    &target.position,
                    new_name,
                    &cancellation,
                )
                .await
                {
                    Ok(result) => SemanticOutcome::RenamePreview {
                        result: (&result).into(),
                    },
                    Err(error) => SemanticOutcome::RequestFailed {
                        operation,
                        reason_code: lsp_error_reason(&error),
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_workspace::WorkspaceContext;

    fn temp_workspace(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root =
            std::env::temp_dir().join(format!("corulix-engine-semantic-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    fn engine(label: &str) -> wht_corulix_core::CorulixResult<CorulixEngine> {
        let root_dir = temp_workspace(label);
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        Ok(CorulixEngine::open(context))
    }

    fn target() -> SemanticTarget {
        SemanticTarget {
            relative_path: "main.rs".to_string(),
            position: Position {
                line_zero_based: 0,
                byte_column_zero_based: 0,
                byte_offset: 0,
            },
            new_name: None,
        }
    }

    /// P17 wired `LanguageId::Python` (the last remaining language this
    /// module used to report unconditionally unwired), so every
    /// [`LanguageId`] variant that exists today is now genuinely wired: no
    /// language is left for this module to assert as structurally unattempted
    /// any more. This test is Python's own honest negative counterpart to
    /// [`go_without_host_provider_authority_fails_closed`]: a host that
    /// grants no Python provider authority (the default `HostConfig`) must
    /// still report a real `Unavailable` -- never a silent host fallback to
    /// an ambient `PATH` `pyright`, and never a downgraded gate.
    #[tokio::test]
    async fn python_without_host_provider_authority_fails_closed()
    -> wht_corulix_core::CorulixResult<()> {
        for operation in [
            SemanticOperation::Definition,
            SemanticOperation::References,
            SemanticOperation::Diagnostics,
            SemanticOperation::RenamePreview,
        ] {
            let outcome = engine("gate")?
                .semantic(operation, LanguageId::Python, target())
                .await;
            assert!(
                matches!(outcome, SemanticOutcome::Unavailable { .. }),
                "Python with no host provider authority must be Unavailable, got {outcome:?}"
            );
        }
        Ok(())
    }

    /// `P15_GO_REQUIRED_GOPLS_MISSING_FAILS_CLOSED` (§26) at the unit level:
    /// Go is a wired language, but an engine whose host grants **no** Go
    /// provider authority (the default `HostConfig`, i.e. no approved
    /// directories and no absolute provider paths) must still report a real
    /// `Unavailable` for every semantic operation -- never a silent host
    /// fallback to an ambient `PATH` `gopls`, and never a downgraded gate.
    ///
    /// This is the honest counterpart to the real, positive-path Go semantic
    /// E2E: the same code path, the same real resolver, an empty authority
    /// envelope, and a truthful negative answer.
    #[tokio::test]
    async fn go_without_host_provider_authority_fails_closed() -> wht_corulix_core::CorulixResult<()>
    {
        for operation in [
            SemanticOperation::Definition,
            SemanticOperation::References,
            SemanticOperation::Diagnostics,
            SemanticOperation::RenamePreview,
        ] {
            let outcome = engine("go-no-authority")?
                .semantic(operation, LanguageId::Go, target())
                .await;
            assert!(
                matches!(outcome, SemanticOutcome::Unavailable { .. }),
                "Go with no host provider authority must be Unavailable, got {outcome:?}"
            );
        }
        Ok(())
    }

    /// The provider-authority envelope must never be able to elevate trust:
    /// a `HostConfig` that sets `workspace_trust: Trusted` and
    /// `allow_trusted_workspace_execution: true` is handed to
    /// `open_with_host_config` with `trusted: false`, and the derived
    /// `EffectiveConfig` must still refuse
    /// `TrustedWorkspaceExecution`. `P15_PROVIDER_CONFIG_TRUST_ELEVATION_PATH_COUNT=0`.
    #[test]
    fn host_provider_authority_can_never_elevate_workspace_trust()
    -> wht_corulix_core::CorulixResult<()> {
        let root_dir = temp_workspace("trust-elevation");
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let smuggled = wht_corulix_config::HostConfig {
            workspace_trust: wht_corulix_core::WorkspaceTrust::Trusted,
            allow_trusted_workspace_execution: true,
            ..wht_corulix_config::HostConfig::default()
        };
        let engine = CorulixEngine::open_with_host_config(context, false, smuggled);
        assert!(
            !engine.effective_config().is_execution_class_allowed(
                wht_corulix_core::ExecutionClass::TrustedWorkspaceExecution
            ),
            "a provider-authority HostConfig must not grant trusted workspace execution"
        );
        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    /// `P16_TS_JS_RUST_PROVIDER_MISCLASSIFICATION_COUNT=0`, proven the strong
    /// way this module's own doc comment on
    /// `real_typescript_javascript_provider_resolutions` promises: with only
    /// Biome provisioned into a fresh, isolated root (rustfmt deliberately
    /// absent), TS/JS's own `Formatter`/`Linter` resolutions must report
    /// `Available` while Rust's own `real_managed_formatter_resolution`
    /// against that *same* root reports `Unavailable` -- proving the two are
    /// genuinely independent resolutions, not the same `_ =>` arm the pre-P16
    /// bug used (which would have made TS/JS's formatter/linter track
    /// Rust's rustfmt/clippy availability instead of Biome's).
    #[tokio::test]
    async fn typescript_javascript_provider_resolutions_are_independent_of_rust_e2e()
    -> wht_corulix_core::CorulixResult<()> {
        let root_dir = temp_workspace("ts-js-resolution-independence");
        let biome_manifest = wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64;
        let (state, _) = wht_corulix_tooling::provisioning::resolve_managed_component(
            &root_dir,
            &biome_manifest,
        );
        if state != wht_corulix_tooling::provisioning::ManagedComponentState::Available
            && wht_corulix_tooling::provisioning::provision(&root_dir, &biome_manifest)
                .await
                .is_err()
        {
            eprintln!("BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: biome");
            let _ = fs::remove_dir_all(&root_dir);
            return Ok(());
        }

        let resolutions = real_typescript_javascript_provider_resolutions(&root_dir);
        let [formatter, typecheck, linter] = resolutions;
        assert_eq!(
            formatter.category,
            wht_corulix_core::ProviderCategory::Formatter
        );
        assert_eq!(
            formatter.availability,
            wht_corulix_core::ProviderAvailability::Available,
            "TS/JS formatter (Biome) must be Available once Biome alone is provisioned"
        );
        assert_eq!(linter.category, wht_corulix_core::ProviderCategory::Linter);
        assert_eq!(
            linter.availability,
            wht_corulix_core::ProviderAvailability::Available,
            "TS/JS linter (Biome) must be Available once Biome alone is provisioned"
        );
        assert_eq!(
            typecheck.category,
            wht_corulix_core::ProviderCategory::TypecheckBuild
        );
        assert_eq!(
            typecheck.availability,
            wht_corulix_core::ProviderAvailability::ProviderUnavailable,
            "typecheck (managed tsc, bundled with TS7) must stay Unavailable: only Biome was provisioned"
        );

        // The discriminating half: Rust's own resolution, against this exact
        // same root, must independently report Unavailable (rustfmt/cargo
        // were never provisioned here). If TS/JS's formatter resolution were
        // still (as the pre-P16 bug had it) actually calling Rust's own
        // `real_managed_formatter_resolution`, the assertion above
        // (`Available`) and this one (`Unavailable`) could not both hold --
        // this is the test that fails against the reverted bug.
        let rust_formatter = real_managed_formatter_resolution(&root_dir);
        assert_eq!(
            rust_formatter.availability,
            wht_corulix_core::ProviderAvailability::ProviderUnavailable,
            "Rust's own formatter resolution must stay Unavailable in a root where only Biome was provisioned"
        );

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }
}
