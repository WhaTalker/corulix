// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13: the real `begin_change` capability behind the `begin_change`
//! MCP tool.
//!
//! The one place `wht_corulix_mcp` reaches a freshly-opened, freshly-
//! baselined [`ChangeSession`] without constructing a
//! `wht_corulix_mutation::MutationExecutor` itself (Architecture Rule B).
//! Composes only already-real, already-tested primitives: [`CorulixEngine::
//! resolve_workspace_root`], [`ChangeSession::generate_id`],
//! [`ChangeSession::open`]/`enter_scope`/`baseline`, and
//! [`CorulixEngine::plan_operation_for_language`] (the sole Architecture
//! Rule H derivation point) -- it introduces no new authority of its own.

use std::path::PathBuf;

use wht_corulix_core::{
    ConnectionId, CorulixError, CorulixResult, LanguageId, OperationIntent, ProviderCategory,
    ToolApplicability, WorkspaceIdentity,
};
use wht_corulix_mutation::MutationExecutor;

use crate::CorulixEngine;
use crate::diagnostics_readiness::live_diagnostics_availability;
use crate::policy::policy_entry;
use crate::providers::ProviderSnapshot;
use crate::session::{ChangeSession, SessionScope};

impl CorulixEngine {
    /// Opens, scopes, and baselines a new [`ChangeSession`] for `intent`,
    /// bound to `workspace_identity`/`connection_id` and confined to
    /// `scope_prefixes`. `creation_sequence` is caller-supplied (Phase 13:
    /// `wht_corulix_mcp` uses its own session-store size as a simple
    /// monotonic counter) rather than derived here, since this crate has no
    /// session-store state of its own to count from.
    ///
    /// Fails only for a bad `root_selector` (propagated from
    /// [`Self::resolve_workspace_root`]) or a `ChangeSession::generate_id`
    /// CSPRNG failure -- `enter_scope`/`baseline` cannot fail against a
    /// freshly-opened session (both preconditions are satisfied by
    /// construction), so their `Result`s are mapped to
    /// `CorulixError::Internal` rather than silently discarded, matching
    /// this crate's "never `.unwrap()`/`.expect()` away an unreachable
    /// case" convention.
    ///
    /// # F7 fix (`F7_FORMATTER_LIVE_AVAILABILITY_NOT_OVERLAID_IN_ROUTING`)
    ///
    /// This method is `async` (unlike every other pre-F7 derivation in this
    /// module) for exactly one reason: `intent`'s policy entry may require
    /// `ProviderCategory::Formatter` as `ToolApplicability::Required`
    /// (`SOURCE_CREATE`/`SOURCE_MODIFY`), and that requirement's real
    /// availability can only be answered by awaiting
    /// [`wht_corulix_formatter::resolve_formatter_availability`] -- the same
    /// authority `format_preview`/`validate_change`'s real `gate.format`
    /// closure already trust, never a second, parallel "is it available"
    /// predicate. Before this fix, [`Self::plan_operation_for_language`]
    /// always evaluated `Formatter` against [`ProviderSnapshot::current`]'s
    /// unconditional `ProviderUnavailable`, so a real, live, resolvable
    /// Biome/rustfmt provider was never once consulted for `gate.edit`ance
    /// -- every `SOURCE_CREATE`/`SOURCE_MODIFY` session opened already
    /// `Blocked(gate.edit, REQUIRED_PROVIDER_UNAVAILABLE)`, regardless of
    /// real provider state (see the `#[cfg(test)]` module's own pre-F7
    /// comment below, now stale and updated to match).
    ///
    /// The language this resolution targets is `language` when the caller
    /// declared one, else detected from `scope_prefixes`' first entry via
    /// the same [`wht_corulix_syntax::detect_language`] extension-based
    /// detection [`wht_corulix_formatter`]'s own real formatting path uses
    /// on the actual target file -- never a new, independent detection
    /// authority. This detected language is used *only* to select which
    /// `Formatter` resolution to attempt; it is never passed as this
    /// session's own `language` (that stays exactly the caller-declared
    /// value, unchanged, so the pre-existing `LanguageServer` per-language
    /// check this same `ToolPlan` derivation performs is completely
    /// unaffected by this addition). Resolution is attempted at all only
    /// when `intent`'s policy entry actually lists `Formatter` as
    /// `Required` -- a `SOURCE_DELETE`/read-only/other intent with no such
    /// requirement never triggers a formatter-resolution attempt (which can
    /// itself trigger real, F6 on-demand managed-component acquisition),
    /// matching Minimum Sufficient Tooling.
    ///
    /// # P-M05-R1 fix (the same defect class, generalized)
    ///
    /// The exact same staleness the F7 fix above closed for `Formatter`
    /// applied identically to `TypecheckBuild`/`Linter`/`TestRunner`: every
    /// `ValidateChange` session (and any other intent whose policy requires
    /// `TypecheckBuild`) opened already `Blocked(gate.diagnostics,
    /// REQUIRED_PROVIDER_UNAVAILABLE)` regardless of real provider state,
    /// discovered during the M05 qualification pass despite `validate_change`
    /// itself executing real diagnostics correctly (proven by 16/16 exact
    /// oracle-matched qualification cases). Resolved via
    /// `crate::diagnostics_readiness::live_diagnostics_availability` --
    /// synchronous (unlike the Formatter overlay above, which needs
    /// `.await` for its own `HOST_ONLY`-fallback-aware resolution; this
    /// checks the `CORULIX_MANAGED` tier only via the same
    /// [`wht_corulix_tooling::provisioning::resolve_owned_managed_component`]
    /// primitive every language's real validator already calls, never a
    /// second detection authority) -- gated the same way, only when
    /// `intent`'s policy lists `TypecheckBuild` as `Required`.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_change(
        &self,
        intent: OperationIntent,
        language: Option<LanguageId>,
        root_selector: Option<&str>,
        scope_prefixes: Vec<String>,
        workspace_identity: WorkspaceIdentity,
        connection_id: ConnectionId,
        creation_sequence: u64,
    ) -> CorulixResult<ChangeSession> {
        // F4 fix: `SemanticRename`/`SourceRefactor` are the only two mutation
        // intents whose policy entry requires `GateId::Discovery` and
        // `GateId::SemanticConfirm` (`crate::policy::SEMANTIC_RENAME`/
        // `SOURCE_REFACTOR`) -- and no production code anywhere in this
        // workspace ever constructs Evidence for either gate (both exist
        // only in `#[cfg(test)]` fixtures). Worse, `submit_edit` is not
        // confined to a point in the gate walk (see its own doc comment) and
        // unconditionally advances straight from wherever it is called to
        // `next_required_gate_after(Edit)` = `Format`, silently skipping
        // past `Discovery`/`SemanticConfirm` without ever visiting them.
        // Letting a session for either intent open would allow a real
        // mutation to commit (`gate.edit` closes normally) while two
        // Required gates can never receive Evidence -- exactly the
        // `SOURCE_CHANGE_COMMITTED_UNCOMPLETABLE_STATE` this fix must make
        // impossible. Rejected here, before any `ChangeSession` exists and
        // before any mutation is possible, rather than discovered later at
        // `complete_change` after bytes have already changed.
        if matches!(
            intent,
            OperationIntent::SemanticRename | OperationIntent::SourceRefactor
        ) {
            return Err(CorulixError::OperationNotSupported(
                "SemanticRename/SourceRefactor require gate.discovery/gate.semantic_confirm \
                 Evidence, which no production code path can currently record; opening this \
                 session would leave any committed mutation permanently uncompletable",
            ));
        }
        let root = self.resolve_workspace_root(root_selector)?;

        // F7 fix: resolve `Formatter` live, exactly once, before this
        // session's `ToolPlan` is derived -- see this method's own doc
        // comment above for the full rationale. `scope_prefixes` is only
        // borrowed here (`.iter()`), never consumed, so it remains
        // available for `SessionScope::new` below.
        let mut snapshot = ProviderSnapshot::current();
        if let Some(entry) = policy_entry(intent) {
            let formatter_required = entry.requirements.iter().any(|requirement| {
                requirement.category == ProviderCategory::Formatter
                    && requirement.applicability == ToolApplicability::Required
            });
            if formatter_required {
                // The first scope prefix whose extension actually detects a
                // language -- not merely `scope_prefixes[0]`: a session
                // scoped e.g. `["src/", "main.rs"]` must not fail this
                // detection just because an extensionless directory prefix
                // happens to be listed first.
                let detected_language = language.or_else(|| {
                    scope_prefixes.iter().find_map(|prefix| {
                        wht_corulix_syntax::detect_language(&PathBuf::from(prefix))
                    })
                });
                if let Some(target_language) = detected_language
                    && let Ok(managed_root) =
                        wht_corulix_tooling::provisioning::managed_toolchain_root()
                {
                    let effective = self.effective_config();
                    let availability = wht_corulix_formatter::resolve_formatter_availability(
                        target_language,
                        &effective,
                        &root,
                        &managed_root,
                    )
                    .await;
                    snapshot = snapshot.with_formatter_resolution(availability);
                }
            }

            // P-M05-R1 fix: the generalized counterpart of the F7 Formatter
            // overlay above, for `TypecheckBuild`/`Linter`/`TestRunner` --
            // resolved live, synchronously (see
            // `crate::diagnostics_readiness`'s own module doc for why no
            // `.await` is needed here), only when `intent`'s policy
            // actually requires `TypecheckBuild` (Minimum Sufficient
            // Tooling, mirroring the Formatter branch's own gating).
            // Without this, every `ValidateChange` session (and any other
            // intent requiring these categories) opened already `Blocked`
            // with `REQUIRED_PROVIDER_UNAVAILABLE` regardless of real
            // provider state -- the exact defect class F7 already closed
            // for `Formatter` alone.
            let typecheck_build_required = entry.requirements.iter().any(|requirement| {
                requirement.category == ProviderCategory::TypecheckBuild
                    && requirement.applicability == ToolApplicability::Required
            });
            if typecheck_build_required {
                let effective = self.effective_config();
                let (typecheck_build, linter, test_runner) =
                    live_diagnostics_availability(language, &effective);
                snapshot =
                    snapshot.with_diagnostics_resolution(typecheck_build, linter, test_runner);
            }
        }

        let executor = MutationExecutor::new(root);
        let id = ChangeSession::generate_id()?;
        let mut session = ChangeSession::open(
            id,
            workspace_identity,
            connection_id,
            creation_sequence,
            executor,
        );
        // P15 production-routing closure: retained so
        // `CorulixEngine::validate_change` can later dispatch to the
        // correct language's real validators (see `ChangeSession::language`'s
        // own doc comment) -- never consulted for `ToolPlan` derivation
        // itself, which already happened via `plan_operation_with_snapshot`
        // below.
        session.set_language(language);
        session
            .enter_scope(SessionScope::new(scope_prefixes))
            .map_err(|_| CorulixError::Internal)?;
        let plan = self.plan_operation_with_snapshot(intent, language, &snapshot);
        session
            .baseline(plan, Vec::new())
            .map_err(|_| CorulixError::Internal)?;
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_workspace::WorkspaceContext;

    fn engine(label: &str) -> CorulixResult<CorulixEngine> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root_dir: PathBuf =
            std::env::temp_dir().join(format!("corulix-engine-begin-change-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&root_dir);
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        Ok(CorulixEngine::open(WorkspaceContext::single_root(
            root,
            "root".to_string(),
        )))
    }

    #[tokio::test]
    async fn begin_change_opens_a_baselined_session() -> CorulixResult<()> {
        let workspace_identity = WorkspaceIdentity::from_opaque_token("wsid".to_string())?;
        let connection_id = ConnectionId::from_opaque_token("cid".to_string())?;
        // `DocumentationModify` has no `ProviderCategory` requirements at
        // all (see `policy::DOCUMENTATION_MODIFY`), so its plan is always
        // `Executable` under today's compiled-in `ProviderSnapshot`.
        // `SourceModify`/`SourceCreate` no longer land a fresh session
        // unconditionally `Blocked` either (F7 fix,
        // `F7_FORMATTER_LIVE_AVAILABILITY_NOT_OVERLAID_IN_ROUTING`): whether
        // they reach `GatePending` now genuinely depends on the real,
        // live-resolved `Formatter` provider for the detected target
        // language -- see `wht_corulix_mcp/tests/
        // real_f7_formatter_live_availability_routing_e2e.rs` for that
        // positive/negative-path proof (a real spawned MCP server is
        // required to control `HostConfig`, so it lives alongside the
        // other real MCP E2E suites rather than in this crate).
        let session = engine("happy")?
            .begin_change(
                OperationIntent::DocumentationModify,
                None,
                None,
                vec!["docs/".to_string()],
                workspace_identity,
                connection_id,
                0,
            )
            .await?;
        assert!(matches!(
            session.status(),
            wht_corulix_core::ChangeSessionStatus::GatePending(wht_corulix_core::GateId::Edit)
        ));
        Ok(())
    }
}
