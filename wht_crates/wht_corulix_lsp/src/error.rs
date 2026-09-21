// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! This crate's typed error taxonomy. Never a bare string, never a panic:
//! every failure mode a caller can hit is one of these variants.

use crate::readiness::ReadinessTimeoutError;
use crate::transport::TransportError;

/// Why an operation observed [`LspError::NotReady`] -- preserved rather than
/// collapsed, because the two causes are operationally different failure
/// modes (P17-W-R3-C5, closing the observability gap C4 identified: a
/// session that is merely slow to finish indexing looks nothing like one
/// whose readiness-signal channel has already gone away).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReadyCause {
    /// `crate::readiness::ReadinessWatch::wait_until_ready`'s bound
    /// elapsed before [`crate::readiness::Readiness::Ready`] was observed.
    /// The session may still be alive and could still become ready later --
    /// this is an ordinary "not finished yet" outcome, not evidence the
    /// session is gone.
    Timeout,
    /// The readiness watch channel closed (its
    /// `crate::readiness::ReadinessSink` was dropped, e.g. because the
    /// owning session's notification pump task ended) before
    /// [`crate::readiness::Readiness::Ready`] was observed. Unlike
    /// [`Self::Timeout`], this means readiness can never arrive on this
    /// channel again -- the pump that would have delivered it is gone.
    ChannelClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LspError {
    /// The configured/resolved provider path could not be spawned as a
    /// process at all.
    ProviderSpawnFailed,
    /// The `initialize` handshake did not complete within its bound
    /// (either the request timed out or the process exited first).
    InitializationFailed,
    /// A request/notification could not be sent or its response could not
    /// be correlated -- see the wrapped [`TransportError`] for specifics.
    Transport(TransportError),
    /// The language server has not proven [`crate::readiness::Readiness::Ready`]
    /// within the caller's bound -- an operation gated on readiness must
    /// never silently substitute an authoritative empty result for this.
    /// Carries [`NotReadyCause`] so the underlying
    /// `ReadinessTimeoutError` variant (`Timeout` vs. `ChannelClosed`) is
    /// never lost on the way into this crate's public error surface --
    /// collapsing the two here would erase exactly the causal distinction
    /// that made diagnosing the root-scoped lease-stop defect
    /// (P17-W-R3-C4/C5) slower than it needed to be.
    NotReady(NotReadyCause),
    /// A location or edit target the server returned does not resolve
    /// inside the active [`wht_corulix_workspace`] confinement -- rejected
    /// rather than surfaced to the caller.
    ResultOutsideWorkspace,
    /// The server's result could not be translated into this crate's own
    /// DTOs (a URI that is not a `file://` URI, an unparseable position,
    /// or a shape this crate does not model).
    UnrepresentableResult,
    /// The requested file could not be read from the confined workspace
    /// path supplied by the caller.
    SourceUnavailable,
    /// M09-P8: [`wht_corulix_workspace::WorkspaceRoot::verify_current_path_identity`]
    /// reported that this session's root pathname no longer resolves to
    /// the exact filesystem object pinned at session construction (an
    /// ordinary-directory, symlink, or ancestor replacement observed
    /// either immediately before the `initialize` request was sent, or at
    /// a later semantic-request boundary). The already-spawned provider
    /// process has been terminated/reaped as part of returning this error
    /// -- never left running against a replaced root. This session is now
    /// permanently invalid; see [`Self::SessionInvalidated`] for what a
    /// later call on the same session observes.
    RootIdentityMismatch,
    /// A prior operation on this exact session already observed
    /// [`Self::RootIdentityMismatch`] (or the session was otherwise marked
    /// invalid). No later operation on this session may proceed -- fail
    /// closed, no reuse, no silent re-binding to whatever object the
    /// pathname now resolves to; the caller must discard this session and
    /// (if still needed) construct a brand new one via [`crate::LspSession::spawn`].
    SessionInvalidated,
}

impl From<TransportError> for LspError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<ReadinessTimeoutError> for LspError {
    fn from(value: ReadinessTimeoutError) -> Self {
        Self::NotReady(match value {
            ReadinessTimeoutError::Timeout => NotReadyCause::Timeout,
            ReadinessTimeoutError::ChannelClosed => NotReadyCause::ChannelClosed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `LSP_READINESS_TIMEOUT_DISTINGUISHABLE=PASS` /
    /// `LSP_READINESS_CHANNEL_CLOSED_DISTINGUISHABLE=PASS` (P17-W-R3-C5):
    /// the two `ReadinessTimeoutError` variants must map to two distinct,
    /// pattern-matchable `LspError::NotReady` payloads -- never the same
    /// undifferentiated variant.
    #[test]
    fn readiness_timeout_and_channel_closed_map_to_distinguishable_not_ready_causes() {
        let from_timeout: LspError = ReadinessTimeoutError::Timeout.into();
        let from_channel_closed: LspError = ReadinessTimeoutError::ChannelClosed.into();
        assert_eq!(from_timeout, LspError::NotReady(NotReadyCause::Timeout));
        assert_eq!(
            from_channel_closed,
            LspError::NotReady(NotReadyCause::ChannelClosed)
        );
        assert_ne!(from_timeout, from_channel_closed);
    }
}
