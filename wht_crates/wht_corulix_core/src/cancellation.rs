// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The one canonical cancellation primitive propagated across every async
//! boundary in the workspace: MCP/CLI -> Engine -> provider -> Tooling.
//!
//! Lives in `wht_corulix_core` (Enterprise Async-First Canonical Rebaseline)
//! rather than in a lower layer such as `wht_corulix_tooling`, because
//! `wht_corulix_engine` does not (and per the architecture docs should not
//! yet) depend on Tooling -- a single propagated token has to live somewhere
//! every layer can already reach. It is a plain `Arc<AtomicBool>`, not
//! `tokio_util::sync::CancellationToken`: it already satisfies every
//! requirement this rebaseline needs (cheap, `Clone`, thread-safe, callable
//! from outside any async runtime) without a new dependency, and Core stays
//! Tokio-free by keeping it that way.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A cheap, cloneable, thread-safe flag a caller can use to cancel an
/// in-progress operation from another thread or task. Cloning shares the
/// same underlying flag -- it is not a new, independent token.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Idempotent; safe to call from any thread or
    /// task, including concurrently with the operation it cancels.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloned_token_shares_cancellation_state() {
        let token = CancellationToken::new();
        let clone = token.clone();
        assert!(!token.is_cancelled());
        clone.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn default_token_starts_uncancelled() {
        assert!(!CancellationToken::new().is_cancelled());
    }
}
