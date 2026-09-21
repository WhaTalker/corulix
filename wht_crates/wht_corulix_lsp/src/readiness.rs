// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Semantic-readiness tracking. Every provider's actual readiness signal is
//! empirically validated against a real process (rust-analyzer during
//! Phase 7's research gate; gopls during this phase's multi-language
//! capability probe) and selected per-provider via
//! `crate::profile::ReadinessStrategy` -- this module never assumes one
//! provider's signal generalizes to another's.
//!
//! **`SEMANTIC_NOT_READY != ZERO_RESULTS`**: `initialize` completing does
//! not mean the semantic database is populated. Before [`Readiness::Ready`]
//! is observed, an empty semantic answer (references, definition,
//! diagnostics) must never be reported by this crate as an authoritative
//! zero -- see `crate::operations`, every one of which checks readiness
//! before treating an empty/absent result as meaningful.
//!
//! [`ReadinessStrategy::ServerStatusNotification`](crate::profile::ReadinessStrategy::ServerStatusNotification)
//! providers (rust-analyzer) emit `experimental/serverStatus`:
//! `health == "ok"` **and** `quiescent == true`. This is a rust-analyzer
//! *extension*, not part of the LSP 3.17 specification, so `ls-types` has
//! no typed model for it -- this module defines the minimal
//! request/notification shape itself. rust-analyzer only sends this
//! notification if the client advertises the corresponding experimental
//! capability in `initialize` (see
//! [`LspProviderProfile::rust_analyzer`](crate::profile::LspProviderProfile::rust_analyzer)),
//! and omitting it would silently make the signal unobservable (proven
//! during Phase 7's own research probe).
//!
//! [`ReadinessStrategy::FirstDiagnosticsPublished`](crate::profile::ReadinessStrategy::FirstDiagnosticsPublished)
//! providers (gopls) have no such extension -- proven by this phase's own
//! capability probe, which observed zero `experimental/serverStatus`-class
//! notifications across a full gopls package-load cycle -- so
//! `crate::session` derives readiness from the first
//! `textDocument/publishDiagnostics` it receives instead; see
//! [`LspProviderProfile::gopls`](crate::profile::LspProviderProfile::gopls).

use tokio::sync::watch;

/// The exact notification method name to watch for.
pub const SERVER_STATUS_METHOD: &str = "experimental/serverStatus";

/// Whether the language server has proven it has finished its initial
/// indexing/analysis pass. `Ready` is the only state under which an empty
/// semantic result may be treated as authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    NotReady,
    Ready,
}

/// Parses one `experimental/serverStatus` notification's params. Returns
/// `None` if the payload does not look like a `serverStatus` notification
/// at all (defensive against a malformed/unexpected payload -- never
/// panics on unexpected JSON shape).
#[must_use]
pub fn interpret_server_status(params: &serde_json::Value) -> Option<Readiness> {
    let health = params.get("health")?.as_str()?;
    let quiescent = params
        .get("quiescent")
        .and_then(serde_json::Value::as_bool)?;
    if health.eq_ignore_ascii_case("ok") && quiescent {
        Some(Readiness::Ready)
    } else {
        Some(Readiness::NotReady)
    }
}

/// Why [`ReadinessWatch::wait_until_ready`] did not observe readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessTimeoutError {
    Timeout,
    ChannelClosed,
}

/// The write side, held by the session's background notification pump.
#[derive(Clone)]
pub struct ReadinessSink {
    tx: watch::Sender<Readiness>,
}

impl ReadinessSink {
    pub fn record(&self, readiness: Readiness) {
        let _ = self.tx.send(readiness);
    }
}

/// The read side, held by callers that need to gate a semantic operation on
/// proven readiness.
pub struct ReadinessWatch {
    rx: watch::Receiver<Readiness>,
}

impl ReadinessWatch {
    #[must_use]
    pub fn current(&self) -> Readiness {
        *self.rx.borrow()
    }

    /// Awaits [`Readiness::Ready`], bounded by `timeout`. Never blocks
    /// forever: a server that never reaches quiescence is a deterministic
    /// timeout, not a hang.
    pub async fn wait_until_ready(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<(), ReadinessTimeoutError> {
        if self.current() == Readiness::Ready {
            return Ok(());
        }
        tokio::select! {
            result = wait_for_ready(&mut self.rx) => result,
            () = tokio::time::sleep(timeout) => Err(ReadinessTimeoutError::Timeout),
        }
    }
}

async fn wait_for_ready(rx: &mut watch::Receiver<Readiness>) -> Result<(), ReadinessTimeoutError> {
    loop {
        if *rx.borrow() == Readiness::Ready {
            return Ok(());
        }
        if rx.changed().await.is_err() {
            return Err(ReadinessTimeoutError::ChannelClosed);
        }
    }
}

/// Constructs a linked [`ReadinessSink`]/[`ReadinessWatch`] pair, starting
/// at [`Readiness::NotReady`] -- readiness is never assumed true at
/// construction.
#[must_use]
pub fn channel() -> (ReadinessSink, ReadinessWatch) {
    let (tx, rx) = watch::channel(Readiness::NotReady);
    (ReadinessSink { tx }, ReadinessWatch { rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_ok_and_quiescent_is_ready() {
        let params = serde_json::json!({ "health": "ok", "quiescent": true, "message": null });
        assert_eq!(interpret_server_status(&params), Some(Readiness::Ready));
    }

    #[test]
    fn health_ok_but_not_quiescent_is_not_ready() {
        let params = serde_json::json!({ "health": "ok", "quiescent": false, "message": null });
        assert_eq!(interpret_server_status(&params), Some(Readiness::NotReady));
    }

    #[test]
    fn health_error_is_not_ready_even_if_quiescent() {
        let params = serde_json::json!({ "health": "error", "quiescent": true, "message": null });
        assert_eq!(interpret_server_status(&params), Some(Readiness::NotReady));
    }

    #[test]
    fn malformed_payload_is_not_misinterpreted() {
        let params = serde_json::json!({ "unrelated": "field" });
        assert_eq!(interpret_server_status(&params), None);
    }

    #[tokio::test]
    async fn wait_until_ready_times_out_before_any_ready_signal() {
        let (_sink, mut watch) = channel();
        let result = watch
            .wait_until_ready(std::time::Duration::from_millis(50))
            .await;
        assert_eq!(result, Err(ReadinessTimeoutError::Timeout));
    }

    #[tokio::test]
    async fn wait_until_ready_resolves_once_sink_records_ready() {
        let (sink, mut watch) = channel();
        assert_eq!(watch.current(), Readiness::NotReady);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            sink.record(Readiness::Ready);
        });
        let result = watch
            .wait_until_ready(std::time::Duration::from_secs(5))
            .await;
        assert_eq!(result, Ok(()));
        assert_eq!(watch.current(), Readiness::Ready);
    }
}
