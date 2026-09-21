// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Semantic operations: definition, references, document/workspace
//! symbols, diagnostics, rename preview, and hover (supporting evidence
//! only). Every operation translates `ls_types` responses into this
//! crate's own DTOs (`crate::dto`) before returning -- no raw `ls_types`
//! value ever crosses this module's public boundary -- and validates every
//! server-supplied location against `wht_corulix_workspace`'s confinement
//! before trusting it.

use std::path::Path;
use std::time::Duration;
use wht_corulix_core::{CancellationToken, Position};

use crate::{
    dto::{
        DefinitionResult, DiagnosticSeverity, DiagnosticsResult, HoverEvidence, ProposedTextEdit,
        ReferencesResult, RenameEditPreview, SemanticDiagnostic, SemanticLocation, SemanticSymbol,
    },
    error::LspError,
    position, readiness,
    session::LspSession,
};

/// Bound on how much of a resolved-location's source file this module will
/// read to translate an LSP range into a Corulix `SourceRange`.
pub(crate) const MAX_LOCATION_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

/// Bound on how long [`diagnostics`] waits for the first
/// `textDocument/publishDiagnostics` naming a just-opened document, via
/// `LspSession::wait_for_diagnostics`.
const DIAGNOSTICS_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// The pure, lexical half of "does this server-supplied `file://` URI stay
/// inside the workspace": strips the workspace root's canonical prefix off
/// an already-absolute path. Never itself canonicalizes or confirms the
/// target exists -- that proof is `wht_corulix_workspace::confined_read`'s,
/// called by [`resolve_and_read`] immediately after this. Kept as its own
/// function purely so it can be unit-tested without spawning a real
/// language-server session.
fn relative_to_workspace_root(
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    absolute: &std::path::Path,
) -> Result<std::path::PathBuf, LspError> {
    // Both sides are normalized against Windows's `\\?\` extended-length
    // prefix before comparison: `workspace_root.canonical_path()` carries
    // it (real `std::fs`-canonicalization output), but `absolute` (decoded
    // from a server-supplied `file://` URI by `crate::uri::file_uri_to_path`)
    // never does -- an unnormalized comparison rejected a genuinely-inside-
    // the-workspace `definition` result as `ResultOutsideWorkspace` during
    // P17-W-R4-C3's native Windows certification. A no-op on Unix.
    let normalized_root =
        crate::uri::strip_windows_verbatim_prefix(workspace_root.canonical_path());
    let normalized_absolute = crate::uri::strip_windows_verbatim_prefix(absolute);
    normalized_absolute
        .strip_prefix(&normalized_root)
        .map(std::path::Path::to_path_buf)
        .map_err(|_| LspError::ResultOutsideWorkspace)
}

/// Confines a server-supplied `file://` URI against `session`'s workspace
/// root and returns both the resulting [`wht_corulix_core::WorkspacePath`]
/// and the file's text. Every step (confinement, canonicalization) is
/// performed by `wht_corulix_workspace::confined_read` -- this module never
/// implements its own path-safety check.
async fn resolve_and_read(
    session: &LspSession,
    file_uri: &ls_types::Uri,
) -> Result<(wht_corulix_core::WorkspacePath, String), LspError> {
    let absolute = crate::uri::file_uri_to_path(file_uri).ok_or(LspError::UnrepresentableResult)?;
    let relative = relative_to_workspace_root(session.workspace_root(), &absolute)?;
    let bytes = wht_corulix_workspace::confined_read(
        session.workspace_root().clone(),
        relative.clone(),
        MAX_LOCATION_SOURCE_BYTES,
    )
    .await
    .map_err(|_| LspError::ResultOutsideWorkspace)?;
    let text = String::from_utf8(bytes).map_err(|_| LspError::UnrepresentableResult)?;
    let relative_path = relative.to_string_lossy().to_string();
    Ok((
        wht_corulix_core::WorkspacePath {
            root: session.root_id(),
            relative_path,
        },
        text,
    ))
}

async fn location_to_semantic(
    session: &LspSession,
    location: &ls_types::Location,
) -> Result<SemanticLocation, LspError> {
    let (path, text) = resolve_and_read(session, &location.uri).await?;
    let range = position::lsp_range_to_core(&text, &location.range)
        .ok_or(LspError::UnrepresentableResult)?;
    Ok(SemanticLocation { path, range })
}

/// Opens `path` (already confined by the caller against
/// `session.workspace_root()`) and converts `position` into an LSP
/// position + `TextDocumentIdentifier`, ready to embed in a request.
async fn open_and_position(
    session: &LspSession,
    path: &Path,
    position: &Position,
) -> Result<(ls_types::TextDocumentIdentifier, ls_types::Position), LspError> {
    let (file_uri, text) = session.ensure_open(path).await?;
    let lsp_position =
        position::core_to_lsp(&text, position).ok_or(LspError::UnrepresentableResult)?;
    Ok((
        ls_types::TextDocumentIdentifier { uri: file_uri },
        lsp_position,
    ))
}

/// `textDocument/definition`. Never claims a result when the server
/// returned `null` -- see [`DefinitionResult::None`].
pub async fn definition(
    session: &LspSession,
    path: &Path,
    position: &Position,
    cancellation: &CancellationToken,
) -> Result<DefinitionResult, LspError> {
    session.ensure_root_identity_or_invalidate().await?;
    let (text_document, lsp_position) = open_and_position(session, path, position).await?;
    let params = ls_types::GotoDefinitionParams {
        text_document_position_params: ls_types::TextDocumentPositionParams {
            text_document,
            position: lsp_position,
        },
        work_done_progress_params: Default::default(),
        partial_result_params: Default::default(),
    };
    let params_value = serde_json::to_value(params).map_err(|_| LspError::UnrepresentableResult)?;
    let response = session
        .transport()
        .request(
            "textDocument/definition",
            params_value,
            crate::session::DEFAULT_REQUEST_TIMEOUT,
            cancellation,
        )
        .await?;
    if response.is_null() {
        return Ok(DefinitionResult::None);
    }
    let typed: ls_types::GotoDefinitionResponse =
        serde_json::from_value(response).map_err(|_| LspError::UnrepresentableResult)?;
    match typed {
        ls_types::GotoDefinitionResponse::Scalar(location) => Ok(DefinitionResult::Single(
            location_to_semantic(session, &location).await?,
        )),
        ls_types::GotoDefinitionResponse::Array(locations) => {
            let mut resolved = Vec::with_capacity(locations.len());
            for location in &locations {
                resolved.push(location_to_semantic(session, location).await?);
            }
            Ok(DefinitionResult::Multiple(resolved))
        }
        ls_types::GotoDefinitionResponse::Link(links) => {
            let mut resolved = Vec::with_capacity(links.len());
            for link in &links {
                let location = ls_types::Location {
                    uri: link.target_uri.clone(),
                    range: link.target_selection_range,
                };
                resolved.push(location_to_semantic(session, &location).await?);
            }
            Ok(DefinitionResult::Multiple(resolved))
        }
    }
}

/// `textDocument/references`. `SEMANTIC_NOT_READY != ZERO_REFERENCES`:
/// this checks `crate::readiness` before ever reporting
/// [`ReferencesResult::Found`] with zero entries as authoritative.
///
/// `references` is a whole-project query (unlike `definition`, which only
/// needs to resolve one target), so before issuing the request this primes
/// bounded, deterministic sibling documents via
/// `crate::project_priming::prime_same_project_documents` -- otherwise,
/// for a TypeScript-family provider running in inferred-project mode, the
/// result would silently depend on which unrelated documents earlier,
/// unrelated calls happened to have opened rather than on this query alone
/// (proven directly: Corulix 1.0.0 M03 references root-cause trace). A
/// no-op for every other provider.
pub async fn references(
    session: &LspSession,
    path: &Path,
    position: &Position,
    cancellation: &CancellationToken,
) -> Result<ReferencesResult, LspError> {
    session.ensure_root_identity_or_invalidate().await?;
    if session.readiness().await != readiness::Readiness::Ready {
        return Ok(ReferencesResult::NotReady);
    }
    let (text_document, lsp_position) = open_and_position(session, path, position).await?;
    crate::project_priming::prime_same_project_documents(session, path).await;
    let params = ls_types::ReferenceParams {
        text_document_position: ls_types::TextDocumentPositionParams {
            text_document,
            position: lsp_position,
        },
        work_done_progress_params: Default::default(),
        partial_result_params: Default::default(),
        context: ls_types::ReferenceContext {
            include_declaration: false,
        },
    };
    let params_value = serde_json::to_value(params).map_err(|_| LspError::UnrepresentableResult)?;
    let response = session
        .transport()
        .request(
            "textDocument/references",
            params_value,
            crate::session::DEFAULT_REQUEST_TIMEOUT,
            cancellation,
        )
        .await?;
    if response.is_null() {
        return Ok(ReferencesResult::Found(Vec::new()));
    }
    let locations: Vec<ls_types::Location> =
        serde_json::from_value(response).map_err(|_| LspError::UnrepresentableResult)?;
    let mut resolved = Vec::with_capacity(locations.len());
    for location in &locations {
        resolved.push(location_to_semantic(session, location).await?);
    }
    Ok(ReferencesResult::Found(resolved))
}

fn symbol_kind_from_lsp(kind: ls_types::SymbolKind) -> wht_corulix_core::SymbolKind {
    use wht_corulix_core::SymbolKind as Core;
    match kind {
        ls_types::SymbolKind::MODULE | ls_types::SymbolKind::NAMESPACE => Core::Module,
        ls_types::SymbolKind::CLASS => Core::Class,
        ls_types::SymbolKind::INTERFACE => Core::Interface,
        ls_types::SymbolKind::STRUCT => Core::Struct,
        ls_types::SymbolKind::ENUM | ls_types::SymbolKind::ENUM_MEMBER => Core::Enum,
        ls_types::SymbolKind::FUNCTION => Core::Function,
        ls_types::SymbolKind::METHOD => Core::Method,
        ls_types::SymbolKind::CONSTRUCTOR => Core::Constructor,
        ls_types::SymbolKind::VARIABLE => Core::Variable,
        ls_types::SymbolKind::CONSTANT => Core::Constant,
        ls_types::SymbolKind::PROPERTY | ls_types::SymbolKind::FIELD => Core::Field,
        _ => Core::Unknown,
    }
}

async fn document_symbol_to_semantic(
    session: &LspSession,
    file_uri: &ls_types::Uri,
    text: &str,
    symbol: &ls_types::DocumentSymbol,
) -> Result<SemanticSymbol, LspError> {
    let (path, _) = resolve_and_read(session, file_uri).await?;
    let range =
        position::lsp_range_to_core(text, &symbol.range).ok_or(LspError::UnrepresentableResult)?;
    let mut children = Vec::new();
    if let Some(nested) = &symbol.children {
        for child in nested {
            children
                .push(Box::pin(document_symbol_to_semantic(session, file_uri, text, child)).await?);
        }
    }
    Ok(SemanticSymbol {
        name: symbol.name.clone(),
        kind: symbol_kind_from_lsp(symbol.kind),
        container_name: None,
        location: SemanticLocation { path, range },
        children,
    })
}

/// `textDocument/documentSymbol`.
pub async fn document_symbols(
    session: &LspSession,
    path: &Path,
    cancellation: &CancellationToken,
) -> Result<Vec<SemanticSymbol>, LspError> {
    let (file_uri, text) = session.ensure_open(path).await?;
    let params = ls_types::DocumentSymbolParams {
        text_document: ls_types::TextDocumentIdentifier {
            uri: file_uri.clone(),
        },
        work_done_progress_params: Default::default(),
        partial_result_params: Default::default(),
    };
    let params_value = serde_json::to_value(params).map_err(|_| LspError::UnrepresentableResult)?;
    let response = session
        .transport()
        .request(
            "textDocument/documentSymbol",
            params_value,
            crate::session::DEFAULT_REQUEST_TIMEOUT,
            cancellation,
        )
        .await?;
    if response.is_null() {
        return Ok(Vec::new());
    }
    let typed: ls_types::DocumentSymbolResponse =
        serde_json::from_value(response).map_err(|_| LspError::UnrepresentableResult)?;
    let mut results = Vec::new();
    match typed {
        ls_types::DocumentSymbolResponse::Nested(symbols) => {
            for symbol in &symbols {
                results.push(document_symbol_to_semantic(session, &file_uri, &text, symbol).await?);
            }
        }
        ls_types::DocumentSymbolResponse::Flat(infos) => {
            for info in &infos {
                let semantic_location = location_to_semantic(session, &info.location).await?;
                results.push(SemanticSymbol {
                    name: info.name.clone(),
                    kind: symbol_kind_from_lsp(info.kind),
                    container_name: info.container_name.clone(),
                    location: semantic_location,
                    children: Vec::new(),
                });
            }
        }
    }
    Ok(results)
}

/// `workspace/symbol`.
pub async fn workspace_symbols(
    session: &LspSession,
    query: &str,
    cancellation: &CancellationToken,
) -> Result<Vec<SemanticSymbol>, LspError> {
    let params = ls_types::WorkspaceSymbolParams {
        query: query.to_string(),
        partial_result_params: Default::default(),
        work_done_progress_params: Default::default(),
    };
    let params_value = serde_json::to_value(params).map_err(|_| LspError::UnrepresentableResult)?;
    let response = session
        .transport()
        .request(
            "workspace/symbol",
            params_value,
            crate::session::DEFAULT_REQUEST_TIMEOUT,
            cancellation,
        )
        .await?;
    if response.is_null() {
        return Ok(Vec::new());
    }
    let typed: ls_types::WorkspaceSymbolResponse =
        serde_json::from_value(response).map_err(|_| LspError::UnrepresentableResult)?;
    let mut results = Vec::new();
    match typed {
        ls_types::WorkspaceSymbolResponse::Flat(infos) => {
            for info in &infos {
                let semantic_location = location_to_semantic(session, &info.location).await?;
                results.push(SemanticSymbol {
                    name: info.name.clone(),
                    kind: symbol_kind_from_lsp(info.kind),
                    container_name: info.container_name.clone(),
                    location: semantic_location,
                    children: Vec::new(),
                });
            }
        }
        ls_types::WorkspaceSymbolResponse::Nested(symbols) => {
            for symbol in &symbols {
                let location = match &symbol.location {
                    ls_types::OneOf::Left(location) => location.clone(),
                    ls_types::OneOf::Right(workspace_location) => ls_types::Location {
                        uri: workspace_location.uri.clone(),
                        range: ls_types::Range::default(),
                    },
                };
                let semantic_location = location_to_semantic(session, &location).await?;
                results.push(SemanticSymbol {
                    name: symbol.name.clone(),
                    kind: symbol_kind_from_lsp(symbol.kind),
                    container_name: symbol.container_name.clone(),
                    location: semantic_location,
                    children: Vec::new(),
                });
            }
        }
    }
    Ok(results)
}

fn severity_from_lsp(severity: Option<ls_types::DiagnosticSeverity>) -> DiagnosticSeverity {
    match severity {
        Some(ls_types::DiagnosticSeverity::WARNING) => DiagnosticSeverity::Warning,
        Some(ls_types::DiagnosticSeverity::INFORMATION) => DiagnosticSeverity::Information,
        Some(ls_types::DiagnosticSeverity::HINT) => DiagnosticSeverity::Hint,
        _ => DiagnosticSeverity::Error,
    }
}

/// Diagnostics via `textDocument/publishDiagnostics`, the mode this crate
/// actually proved against a real rust-analyzer process during this
/// phase's research gate -- the pull-based `textDocument/diagnostic`
/// request is not implemented, and this crate never claims both modes.
/// Semantic LSP evidence only; it does not replace a future clippy/`cargo
/// check`/`cargo build` authority.
pub async fn diagnostics(session: &LspSession, path: &Path) -> Result<DiagnosticsResult, LspError> {
    session.ensure_root_identity_or_invalidate().await?;
    if session.readiness().await != readiness::Readiness::Ready {
        return Ok(DiagnosticsResult::NotReady);
    }
    let (file_uri, text) = session.ensure_open(path).await?;
    // Diagnostics are pushed asynchronously by every provider this crate
    // supports; wait for the first publish rather than sleeping a fixed
    // duration -- proven event-driven and bounded (never a hang) by
    // `LspSession::wait_for_diagnostics`.
    let raw = session
        .wait_for_diagnostics(&file_uri, DIAGNOSTICS_WAIT_TIMEOUT)
        .await;
    let mut translated = Vec::with_capacity(raw.len());
    for diagnostic in &raw {
        let range = position::lsp_range_to_core(&text, &diagnostic.range)
            .ok_or(LspError::UnrepresentableResult)?;
        translated.push(SemanticDiagnostic {
            range,
            severity: severity_from_lsp(diagnostic.severity),
            message: diagnostic.message.clone(),
            source: diagnostic.source.clone(),
            code: diagnostic.code.as_ref().map(number_or_string_to_string),
        });
    }
    Ok(DiagnosticsResult::Reported(translated))
}

fn number_or_string_to_string(value: &ls_types::NumberOrString) -> String {
    match value {
        ls_types::NumberOrString::Number(n) => n.to_string(),
        ls_types::NumberOrString::String(s) => s.clone(),
    }
}

/// TypeScript-family canonical-anchor redirect for [`rename_preview`]
/// (Corulix 1.0.0 M03 rename_preview AST-based anchor classification pass).
///
/// Classifies the anchor's syntactic role via
/// [`wht_corulix_syntax::classify_anchor_role`] (structural-only; this crate
/// stays the sole semantic-resolution authority per Architecture Rule L) and
/// redirects the rename request to a canonical declaration ONLY when every
/// one of these holds:
///
/// - the anchor's file has a recognized TypeScript-family language
///   (`.ts`/`.tsx`/`.js`/...) -- a no-op, returning `None`, for every other
///   language (`NON_TS_LANGUAGE_BEHAVIOR_MUTATED=NO`);
/// - the classifier reports [`wht_corulix_syntax::AnchorRole::ValueUsage`]
///   -- an import specifier, import/export alias binding, declaration name,
///   type position, or unclassifiable anchor is never redirected, preserving
///   the provider's own local rename intent exactly as before this pass
///   (proven unsafe to redirect blindly: Corulix 1.0.0 M03 TS/TSX
///   rename_preview canonical anchor resolution trace);
/// - `textDocument/definition` resolves to exactly one location (reusing
///   [`definition`], never a second request-building/parsing path) --
///   `None`/`Multiple` results are never guessed at and leave the anchor
///   unredirected.
///
/// Returns the canonical location's own `(TextDocumentIdentifier, Position)`
/// pair, already opened and primed, ready to embed directly into the
/// `RenameParams`/`prepareRename` request -- callers never need to re-derive
/// a position from a [`crate::dto::SemanticLocation`] themselves.
async fn canonical_rename_anchor(
    session: &LspSession,
    path: &Path,
    position: &Position,
    cancellation: &CancellationToken,
) -> Result<Option<(ls_types::TextDocumentIdentifier, ls_types::Position)>, LspError> {
    let Some(language) = wht_corulix_syntax::detect_language(path) else {
        return Ok(None);
    };
    if !matches!(
        language,
        wht_corulix_core::LanguageId::TypeScript
            | wht_corulix_core::LanguageId::Tsx
            | wht_corulix_core::LanguageId::JavaScript
    ) {
        return Ok(None);
    }

    let (_, anchor_text) = session.ensure_open(path).await?;
    let role = match wht_corulix_syntax::classify_anchor_role(
        language,
        &anchor_text,
        position.byte_offset,
    ) {
        Ok(role) => role,
        Err(_) => return Ok(None),
    };
    if !role.eligible_for_canonical_redirect() {
        return Ok(None);
    }

    // `DefinitionResult::Single` vs `Multiple` reflects the LSP response's
    // own wire shape (`GotoDefinitionResponse::Scalar` vs `::Array`), not
    // the resolved location *count* -- the pinned TS7-native provider
    // always answers with an `Array`, even carrying exactly one location
    // (confirmed directly: Corulix 1.0.0 M03 rename_preview AST-based
    // anchor classification pass, raw-LSP probe evidence). `CANONICAL_
    // DEFINITION_UNIQUE` must therefore be judged by the resolved count,
    // never by which response variant carried it.
    let target = match definition(session, path, position, cancellation).await? {
        DefinitionResult::Single(target) => target,
        DefinitionResult::Multiple(mut targets) if targets.len() == 1 => targets.remove(0),
        // `None` (no definition) or a genuinely ambiguous `Multiple`
        // (0 or >1 resolved locations) -- never guess across candidates;
        // preserve the provider's own anchor behavior.
        DefinitionResult::None | DefinitionResult::Multiple(_) => return Ok(None),
    };

    let target_absolute = session
        .workspace_root()
        .canonical_path()
        .join(&target.path.relative_path);
    crate::project_priming::prime_same_project_documents(session, &target_absolute).await;
    let (canonical_document, canonical_position) =
        open_and_position(session, &target_absolute, &target.range.start).await?;
    Ok(Some((canonical_document, canonical_position)))
}

/// `textDocument/rename`, preview only.
/// `RENAME_PREVIEW_MUTATION_COUNT=0`: nothing here ever writes to disk.
/// Any edit whose target does not resolve inside the active workspace is
/// rejected outright rather than silently dropped or included unchecked.
///
/// `rename_preview` is a whole-project query exactly like [`references`]
/// (a rename must find every real usage across the inferred project, not
/// just the anchor's own file), so it primes the same bounded,
/// deterministic sibling documents via
/// `crate::project_priming::prime_same_project_documents` before issuing
/// the request -- otherwise, from a cold session, a TypeScript-family
/// provider in inferred-project mode silently returns an edit set scoped
/// to only the anchor's own already-open document rather than the whole
/// project (proven directly: Corulix 1.0.0 M03 TS/TSX rename_preview
/// fresh-session determinism trace). A no-op for every other provider,
/// identical to `references`'s own priming call.
///
/// For a TypeScript-family anchor classified as an ordinary value/call use
/// of a symbol that resolves to exactly one canonical declaration, the
/// request is additionally redirected to that declaration
/// (`canonical_rename_anchor`) before being issued, so a project-wide
/// rename's impact no longer depends on whether the request started from
/// the declaration or from a genuine usage (Corulix 1.0.0 M03 rename_preview
/// AST-based anchor classification pass). Every other anchor role (import/
/// export/alias/declaration/type-position/unknown) is issued exactly as
/// before this pass.
pub async fn rename_preview(
    session: &LspSession,
    path: &Path,
    position: &Position,
    new_name: &str,
    cancellation: &CancellationToken,
) -> Result<RenameEditPreview, LspError> {
    session.ensure_root_identity_or_invalidate().await?;
    let (text_document, lsp_position) = open_and_position(session, path, position).await?;
    crate::project_priming::prime_same_project_documents(session, path).await;
    let (text_document, lsp_position) =
        match canonical_rename_anchor(session, path, position, cancellation).await? {
            Some(canonical) => canonical,
            None => (text_document, lsp_position),
        };
    let params = ls_types::RenameParams {
        text_document_position: ls_types::TextDocumentPositionParams {
            text_document,
            position: lsp_position,
        },
        new_name: new_name.to_string(),
        work_done_progress_params: Default::default(),
    };
    let params_value = serde_json::to_value(params).map_err(|_| LspError::UnrepresentableResult)?;
    let response = session
        .transport()
        .request(
            "textDocument/rename",
            params_value,
            crate::session::DEFAULT_REQUEST_TIMEOUT,
            cancellation,
        )
        .await?;
    if response.is_null() {
        return Ok(RenameEditPreview {
            edits_by_path: Vec::new(),
        });
    }
    let edit: ls_types::WorkspaceEdit =
        serde_json::from_value(response).map_err(|_| LspError::UnrepresentableResult)?;
    let mut edits_by_path = Vec::new();

    if let Some(document_changes) = &edit.document_changes {
        match document_changes {
            ls_types::DocumentChanges::Edits(document_edits) => {
                for document_edit in document_edits {
                    let uri = &document_edit.text_document.uri;
                    let (path, text) = resolve_and_read(session, uri).await?;
                    let mut proposed = Vec::with_capacity(document_edit.edits.len());
                    for edit in &document_edit.edits {
                        let text_edit = match edit {
                            ls_types::OneOf::Left(edit) => edit,
                            ls_types::OneOf::Right(annotated) => &annotated.text_edit,
                        };
                        let range = position::lsp_range_to_core(&text, &text_edit.range)
                            .ok_or(LspError::UnrepresentableResult)?;
                        proposed.push(ProposedTextEdit {
                            range,
                            new_text: text_edit.new_text.clone(),
                        });
                    }
                    edits_by_path.push((path, proposed));
                }
            }
            ls_types::DocumentChanges::Operations(_) => {
                // Create/rename/delete file operations are out of scope
                // for a rename *preview* -- this crate proposes text
                // edits only, never filesystem operations.
                return Err(LspError::UnrepresentableResult);
            }
        }
    } else if let Some(changes) = &edit.changes {
        for (uri, text_edits) in changes {
            let (path, text) = resolve_and_read(session, uri).await?;
            let mut proposed = Vec::with_capacity(text_edits.len());
            for text_edit in text_edits {
                let range = position::lsp_range_to_core(&text, &text_edit.range)
                    .ok_or(LspError::UnrepresentableResult)?;
                proposed.push(ProposedTextEdit {
                    range,
                    new_text: text_edit.new_text.clone(),
                });
            }
            edits_by_path.push((path, proposed));
        }
    }

    Ok(RenameEditPreview { edits_by_path })
}

/// `textDocument/hover`. `HOVER_AUTHORITY=SUPPORTING_ONLY` -- never used to
/// satisfy definition/references/rename/diagnostics.
pub async fn hover(
    session: &LspSession,
    path: &Path,
    position: &Position,
    cancellation: &CancellationToken,
) -> Result<Option<HoverEvidence>, LspError> {
    let (text_document, lsp_position) = open_and_position(session, path, position).await?;
    let params = ls_types::HoverParams {
        text_document_position_params: ls_types::TextDocumentPositionParams {
            text_document,
            position: lsp_position,
        },
        work_done_progress_params: Default::default(),
    };
    let params_value = serde_json::to_value(params).map_err(|_| LspError::UnrepresentableResult)?;
    let response = session
        .transport()
        .request(
            "textDocument/hover",
            params_value,
            crate::session::DEFAULT_REQUEST_TIMEOUT,
            cancellation,
        )
        .await?;
    if response.is_null() {
        return Ok(None);
    }
    let typed: ls_types::Hover =
        serde_json::from_value(response).map_err(|_| LspError::UnrepresentableResult)?;
    let contents = match typed.contents {
        ls_types::HoverContents::Scalar(ls_types::MarkedString::String(text)) => text,
        ls_types::HoverContents::Scalar(ls_types::MarkedString::LanguageString(language)) => {
            language.value
        }
        ls_types::HoverContents::Array(entries) => entries
            .into_iter()
            .map(|entry| match entry {
                ls_types::MarkedString::String(text) => text,
                ls_types::MarkedString::LanguageString(language) => language.value,
            })
            .collect::<Vec<_>>()
            .join("\n\n"),
        ls_types::HoverContents::Markup(markup) => markup.value,
    };
    let (_file_uri, text) = session.ensure_open(path).await?;
    let range = typed
        .range
        .as_ref()
        .and_then(|range| position::lsp_range_to_core(&text, range));
    Ok(Some(HoverEvidence { contents, range }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_workspace::WorkspaceRoot;

    fn temp_workspace() -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("corulix-lsp-ops-test-{stamp}"));
        let _ = fs::create_dir_all(&root);
        root
    }

    #[test]
    fn location_inside_workspace_resolves_to_a_relative_path() -> Result<(), String> {
        let path = temp_workspace();
        let root = WorkspaceRoot::open(&path).map_err(|error| format!("{error:?}"))?;
        let absolute = root.canonical_path().join("src/main.rs");
        let relative =
            relative_to_workspace_root(&root, &absolute).map_err(|error| format!("{error:?}"))?;
        assert_eq!(relative, std::path::Path::new("src/main.rs"));
        let _ = fs::remove_dir_all(&path);
        Ok(())
    }

    #[test]
    fn location_outside_workspace_is_rejected() -> Result<(), String> {
        let path = temp_workspace();
        let outside = temp_workspace();
        let root = WorkspaceRoot::open(&path).map_err(|error| format!("{error:?}"))?;
        let absolute = outside.join("secret.rs");
        let result = relative_to_workspace_root(&root, &absolute);
        assert_eq!(result, Err(LspError::ResultOutsideWorkspace));
        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }
}
