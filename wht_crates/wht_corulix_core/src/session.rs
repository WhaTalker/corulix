// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! `ChangeSession` identity and status contracts.
//!
//! Neither type implements the `ChangeSession` state machine itself (a
//! later Engine phase); these are the vocabulary that machine will use.

use crate::error::{CorulixError, CorulixResult};
use crate::gate::GateId;
use serde::{Deserialize, Serialize};

/// An opaque `ChangeSession` identifier.
///
/// A session ID is an identifier, **not** authorization by itself -- later
/// phases bind a session to workspace identity, connection identity, scope,
/// and policy context before treating it as authorized to mutate anything.
/// Core performs no entropy generation for this type (no
/// `uuid`/`getrandom`/CSPRNG dependency); a later runtime phase that
/// actually creates sessions is responsible for producing an unpredictable
/// token before constructing this value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct ChangeSessionId(String);

impl ChangeSessionId {
    pub fn from_opaque_token(token: String) -> CorulixResult<Self> {
        if token.is_empty() {
            return Err(CorulixError::InvalidInput(
                "change session id token must not be empty".into(),
            ));
        }
        Ok(Self(token))
    }

    pub fn as_opaque_token(&self) -> &str {
        &self.0
    }
}

/// An opaque identifier for the host/MCP connection that created a
/// `ChangeSession`.
///
/// Phase 10's own binding requirement: for stdio v1, session-mutating
/// operations (`submit_edit`/`validate_change`/`complete_change`/
/// `abort_change`) must originate from the exact connection that created
/// the session -- a valid [`ChangeSessionId`] alone is never sufficient
/// authorization (`SESSION_ID_ONLY_AUTHORIZATION=NO`). Like
/// [`ChangeSessionId`], this performs no entropy generation itself; a
/// later runtime layer supplies an unpredictable-enough token identifying
/// the connection (for stdio, the process-lifetime connection handle is
/// sufficient -- there is exactly one connection per stdio process).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct ConnectionId(String);

impl ConnectionId {
    pub fn from_opaque_token(token: String) -> CorulixResult<Self> {
        if token.is_empty() {
            return Err(CorulixError::InvalidInput(
                "connection id token must not be empty".into(),
            ));
        }
        Ok(Self(token))
    }

    pub fn as_opaque_token(&self) -> &str {
        &self.0
    }
}

/// The truthful lifecycle status of a `ChangeSession`.
///
/// This is status vocabulary only -- it does not encode a fixed universal
/// seven-gate sequence (the gate identified by `GatePending`/`Blocked` comes
/// from whichever gate a session's own `ToolPlan` is currently walking, not
/// a hardcoded position). `Completed` and `Aborted` are the only terminal
/// states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub enum ChangeSessionStatus {
    Opened,
    Scoped,
    Baselined,
    GatePending(GateId),
    Blocked(GateId),
    ExitEvaluation,
    Completed,
    Aborted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_session_id_rejects_empty_token() {
        assert!(matches!(
            ChangeSessionId::from_opaque_token(String::new()),
            Err(CorulixError::InvalidInput(_))
        ));
    }

    #[test]
    fn change_session_id_accepts_nonempty_token() -> CorulixResult<()> {
        let id = ChangeSessionId::from_opaque_token("sess-abc123".to_string())?;
        assert_eq!(id.as_opaque_token(), "sess-abc123");
        Ok(())
    }

    #[test]
    fn completed_and_aborted_are_distinct_terminal_variants() {
        assert_ne!(
            std::mem::discriminant(&ChangeSessionStatus::Completed),
            std::mem::discriminant(&ChangeSessionStatus::Aborted)
        );
    }

    #[test]
    fn connection_id_rejects_empty_token() {
        assert!(matches!(
            ConnectionId::from_opaque_token(String::new()),
            Err(CorulixError::InvalidInput(_))
        ));
    }

    #[test]
    fn connection_id_accepts_nonempty_token() -> CorulixResult<()> {
        let id = ConnectionId::from_opaque_token("conn-abc123".to_string())?;
        assert_eq!(id.as_opaque_token(), "conn-abc123");
        Ok(())
    }

    #[test]
    fn gate_pending_and_blocked_carry_the_specific_gate_not_a_fixed_position() {
        let pending = ChangeSessionStatus::GatePending(GateId::Discovery);
        let blocked = ChangeSessionStatus::Blocked(GateId::Tests);
        assert!(matches!(
            pending,
            ChangeSessionStatus::GatePending(GateId::Discovery)
        ));
        assert!(matches!(
            blocked,
            ChangeSessionStatus::Blocked(GateId::Tests)
        ));
    }
}
