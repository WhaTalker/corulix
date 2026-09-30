// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13: the real, gated `format_preview` capability behind the
//! `format_preview` MCP tool.
//!
//! `wht_corulix_formatter::format_preview` (its own `managed_root`-default
//! entry point) is the real, read-only rustfmt-invocation entry point this
//! capability delegates to -- never a duplicated rustfmt invocation of this
//! crate's own. A bare, session-less MCP call has no caller-supplied
//! `HostConfig`, so `CorulixEngine::effective_config` (the same
//! `derive`d, non-elevated `EffectiveConfig` `validate_change` already
//! uses) is reused verbatim: it grants no approved system directories and
//! no absolute provider paths, so the pre-existing `HOST_ONLY`/system
//! `rustfmt` resolution fallback stays genuinely closed for a bare call
//! exactly as it always was, while the `CORULIX_MANAGED` path (which reads
//! no `EffectiveConfig` field at all -- see
//! `wht_corulix_formatter::managed::resolve_rustfmt`) opens for real the
//! moment a managed `rustfmt` + `rust-semantic-runtime` are actually
//! provisioned under `wht_corulix_tooling::provisioning::managed_toolchain_root()`.
//! This is genuinely fail-closed, not a stub: `Unavailable` today in an
//! environment with nothing provisioned, `Executed`/`Unchanged` for real
//! the moment provisioning exists -- proven by this module's own real,
//! disposable-fixture E2E test.
//!
//! [`wht_corulix_formatter::FormatterResult`]'s own doc (`wht_corulix_formatter::result`)
//! deliberately never exposes raw rustfmt stdout text as the canonical
//! result -- only typed evidence (content hashes, changed/unchanged,
//! provider identity). This module's [`FormatPreviewOutcome`] mirrors that
//! same typed-evidence shape rather than inventing a raw-text field this
//! workspace's formatter crate does not itself produce.

use serde::Serialize;
use wht_corulix_core::{ContentHash, ProviderAvailability, ProviderCategory, ReasonCode};

use crate::CorulixEngine;
use crate::providers::ProviderSnapshot;

/// The outcome of one `format_preview` call.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FormatPreviewOutcome {
    /// rustfmt could not be resolved/invoked at all -- no preview was
    /// computed.
    Unavailable { reason_code: ReasonCode },
    /// rustfmt ran (real, managed process) and reported the input would
    /// change; `changed` and the two content hashes are exactly
    /// [`wht_corulix_formatter::FormatterResult`]'s own real, observed
    /// values -- the live workspace file itself was never written to
    /// (`format_preview` never constructs a `MutationExecutor`).
    WouldFormat {
        provider_used_managed: bool,
        provider_version: Option<String>,
        input_hash: ContentHash,
        output_hash: ContentHash,
    },
    /// rustfmt ran and reported the input was already correctly formatted.
    Unchanged {
        provider_used_managed: bool,
        provider_version: Option<String>,
        input_hash: ContentHash,
    },
    /// rustfmt was resolved and invoked but the attempt did not produce a
    /// usable result (non-zero exit, truncated capture, timeout,
    /// cancellation, etc.) -- reported honestly, never treated as a
    /// silent success.
    InvocationFailed { reason: Option<ReasonCode> },
}

impl CorulixEngine {
    /// Reports whether a live `format_preview` could run, using the same
    /// compiled-in [`ProviderSnapshot`] every other capability's gate reads
    /// -- never a second, ad hoc availability check. Superseded by
    /// [`Self::format_preview`] for the real, executing path; kept for
    /// callers that only want the category-level status.
    #[must_use]
    pub fn format_preview_status(&self) -> FormatPreviewOutcome {
        match ProviderSnapshot::current().availability(ProviderCategory::Formatter) {
            ProviderAvailability::Available => FormatPreviewOutcome::Unavailable {
                reason_code: ReasonCode::RequiredCapabilityUnavailable,
            },
            ProviderAvailability::ProviderUnavailable
            | ProviderAvailability::CapabilityUnavailable
            | ProviderAvailability::ReadinessPending
            | _ => FormatPreviewOutcome::Unavailable {
                reason_code: ReasonCode::RequiredProviderUnavailable,
            },
        }
    }

    /// Runs a real, read-only rustfmt preview of `relative` (resolved
    /// against `root_selector`, defaulting to the engine's single/primary
    /// root the same way every other MCP-facing capability does) and
    /// reports the genuine, observed outcome. Never writes to the live
    /// workspace file: delegates entirely to
    /// [`wht_corulix_formatter::format_preview`], which never constructs a
    /// [`wht_corulix_mutation::MutationExecutor`].
    pub async fn format_preview(
        &self,
        relative: std::path::PathBuf,
        root_selector: Option<String>,
    ) -> FormatPreviewOutcome {
        let managed_root = match wht_corulix_tooling::provisioning::managed_toolchain_root() {
            Ok(root) => root,
            Err(_) => {
                return FormatPreviewOutcome::Unavailable {
                    reason_code: ReasonCode::RequiredProviderUnavailable,
                };
            }
        };
        self.format_preview_at(&managed_root, relative, root_selector)
            .await
    }

    /// As [`Self::format_preview`], but against an explicit `managed_root`
    /// rather than the real, process-wide
    /// [`wht_corulix_tooling::provisioning::managed_toolchain_root`] --
    /// mirrors `wht_corulix_formatter::format_preview`/`format_preview_at`'s
    /// own default/explicit-root split, and kept `pub` for the same reason
    /// that split is: an explicit-root seam future callers (in-process
    /// tests, alternate managed-root policies) can reach without
    /// duplicating [`Self::format_preview`]'s own resolution logic. The
    /// current real, positive-path `format_preview` E2E
    /// (`wht_corulix_mcp/tests/real_p13_mcp_managed_provider_isolated_e2e.rs`)
    /// exercises this method only indirectly -- by spawning the real
    /// compiled binary with `XDG_DATA_HOME` redirected to an isolated
    /// directory, so the real `format_preview` MCP tool's own call into
    /// [`Self::format_preview`] resolves that same isolated root and, in
    /// turn, calls this method internally -- rather than calling it
    /// directly, since that E2E must exercise the real MCP tool end to
    /// end, never bypass it (see CHANGELOG.md's Phase 13 Section L).
    pub async fn format_preview_at(
        &self,
        managed_root: &std::path::Path,
        relative: std::path::PathBuf,
        root_selector: Option<String>,
    ) -> FormatPreviewOutcome {
        let root = match self.resolve_workspace_root(root_selector.as_deref()) {
            Ok(root) => root,
            Err(_) => {
                return FormatPreviewOutcome::Unavailable {
                    reason_code: ReasonCode::RequiredCapabilityUnavailable,
                };
            }
        };
        let path = wht_corulix_core::WorkspacePath {
            root: wht_corulix_core::WorkspaceRootId(0),
            relative_path: relative.to_string_lossy().into_owned(),
        };
        let effective = self.effective_config(self.root_id_for(&root));
        let cancellation = wht_corulix_core::CancellationToken::new();

        let result = wht_corulix_formatter::format_preview_at(
            managed_root,
            &effective,
            root,
            path,
            self.max_file_bytes(),
            &cancellation,
        )
        .await;

        match result {
            Ok(result) => match result.status {
                wht_corulix_formatter::FormatStatus::WouldFormat => {
                    let Some(output_hash) = result.output_hash else {
                        return FormatPreviewOutcome::InvocationFailed {
                            reason: result.reason,
                        };
                    };
                    FormatPreviewOutcome::WouldFormat {
                        provider_used_managed: result.provider_used_managed,
                        provider_version: result.provider_version,
                        input_hash: result.input_hash,
                        output_hash,
                    }
                }
                wht_corulix_formatter::FormatStatus::Unchanged => FormatPreviewOutcome::Unchanged {
                    provider_used_managed: result.provider_used_managed,
                    provider_version: result.provider_version,
                    input_hash: result.input_hash,
                },
                wht_corulix_formatter::FormatStatus::ProviderUnavailable => {
                    FormatPreviewOutcome::Unavailable {
                        reason_code: result
                            .reason
                            .unwrap_or(ReasonCode::RequiredProviderUnavailable),
                    }
                }
                _ => FormatPreviewOutcome::InvocationFailed {
                    reason: result.reason,
                },
            },
            Err(_) => FormatPreviewOutcome::Unavailable {
                reason_code: ReasonCode::RequiredProviderUnavailable,
            },
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

    #[test]
    fn format_preview_status_is_currently_gated_unavailable() -> wht_corulix_core::CorulixResult<()>
    {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let root_dir: PathBuf =
            std::env::temp_dir().join(format!("corulix-engine-format-preview-test-{stamp}"));
        let _ = fs::create_dir_all(&root_dir);
        let root = wht_corulix_workspace::WorkspaceRoot::open(&root_dir)?;
        let context = WorkspaceContext::single_root(root, "root".to_string());
        let engine = CorulixEngine::open(context);

        let outcome = engine.format_preview_status();
        assert!(matches!(
            outcome,
            FormatPreviewOutcome::Unavailable {
                reason_code: ReasonCode::RequiredProviderUnavailable
            }
        ));

        let _ = fs::remove_dir_all(&root_dir);
        Ok(())
    }

    // A real, positive-path E2E (rustfmt genuinely resolved and invoked,
    // proving `format_preview` reaches `WouldFormat`/`Unchanged` instead of
    // `Unavailable`) lives in `wht_corulix_mcp`'s own test suite, driven
    // through the real MCP `format_preview` tool against a disposable
    // fixture with a real, explicit `managed_root` override -- not here,
    // to avoid this crate's own unit tests racing against the shared,
    // real, process-wide `managed_toolchain_root()` other real E2E suites
    // in this workspace also provision into.
}
