// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The one reusable bounded-concurrency primitive for future operational
//! orchestration (provider invocations, controlled process executions via
//! `wht_corulix_tooling`).
//!
//! Async-first does not mean unlimited parallelism: a caller that fans out
//! N concurrent operations without a ceiling can exhaust file descriptors,
//! process slots, or memory just as easily as a synchronous implementation
//! can. [`ConcurrencyLimiter`] is a thin, cheaply-`Clone`-able wrapper over
//! `tokio::sync::Semaphore` that any future orchestration path admits
//! through before starting real work.
//!
//! This module does not itself call any provider or spawn any process --
//! doing so merely to exercise this limiter would be exactly the kind of
//! premature implementation this rebaseline's own mandate forbids. It is
//! deliberately available-but-unwired, the same posture `wht_corulix_tooling`
//! had at the end of Phase 5 before anything called into it.
//!
//! # Composing per-workspace/per-provider limits (design support, not yet wired)
//!
//! A single [`ConcurrencyLimiter`] enforces one global ceiling. A future
//! caller that wants a *separate* ceiling per workspace root or per provider
//! category does not need a new primitive for that -- it composes multiple
//! `ConcurrencyLimiter` instances, e.g. keyed in a
//! `HashMap<WorkspaceRootId, ConcurrencyLimiter>` or
//! `HashMap<ProviderCategory, ConcurrencyLimiter>`, and acquires from
//! whichever one(s) apply to a given operation. That composition is left
//! unimplemented here because there is no real per-workspace/per-provider
//! orchestration caller yet to size it correctly against.

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A reasonable, named default ceiling for a single Corulix process's
/// concurrent operational tasks, until a real orchestration caller
/// justifies a different, deliberately-chosen value.
pub const DEFAULT_MAX_CONCURRENT_OPERATIONS: usize = 8;

/// Caps the number of concurrent operational tasks admitted at once.
/// Cloning shares the same underlying ceiling -- it is not a new,
/// independent limit.
#[derive(Debug, Clone)]
pub struct ConcurrencyLimiter {
    semaphore: Arc<Semaphore>,
}

impl ConcurrencyLimiter {
    /// `max_concurrent` is clamped to at least `1`: a limiter that could
    /// never admit any operation would fail closed in the wrong way (an
    /// operation that should eventually run would instead hang forever).
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent.max(1))),
        }
    }

    /// A limiter sized to [`DEFAULT_MAX_CONCURRENT_OPERATIONS`].
    #[must_use]
    pub fn global_default() -> Self {
        Self::new(DEFAULT_MAX_CONCURRENT_OPERATIONS)
    }

    /// Admits one more concurrent operation, waiting (never busy-polling --
    /// this awaits Tokio's own semaphore wait queue) if the ceiling is
    /// already reached. The returned permit releases its slot when dropped.
    ///
    /// Returns `None` only if the underlying semaphore has been closed,
    /// which is never true for a limiter this type constructs (nothing in
    /// this crate ever calls `Semaphore::close`) -- the `Option` return
    /// keeps this fail-closed rather than panicking on that
    /// impossible-in-practice case.
    pub async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.semaphore).acquire_owned().await.ok()
    }

    /// The number of operations that could be admitted right now without
    /// waiting. Diagnostic only -- never used to decide whether to call
    /// [`Self::acquire`], since the count can change between the check and
    /// the call.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn zero_is_clamped_to_at_least_one_permit() {
        let limiter = ConcurrencyLimiter::new(0);
        assert_eq!(limiter.available_permits(), 1);
    }

    #[tokio::test]
    async fn acquire_never_exceeds_the_configured_ceiling() {
        let limiter = ConcurrencyLimiter::new(2);
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let limiter = limiter.clone();
            let concurrent = Arc::clone(&concurrent);
            let max_observed = Arc::clone(&max_observed);
            handles.push(tokio::spawn(async move {
                let Some(_permit) = limiter.acquire().await else {
                    return;
                };
                let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                max_observed.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                concurrent.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for handle in handles {
            let _ = handle.await;
        }

        assert!(
            max_observed.load(Ordering::SeqCst) <= 2,
            "never more than 2 concurrent holders"
        );
    }

    #[tokio::test]
    async fn released_permit_becomes_available_again() {
        let limiter = ConcurrencyLimiter::new(1);
        {
            let _permit = limiter.acquire().await;
            assert_eq!(limiter.available_permits(), 0);
        }
        assert_eq!(limiter.available_permits(), 1);
    }
}
