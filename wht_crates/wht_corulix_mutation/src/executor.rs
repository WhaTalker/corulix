// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The canonical mutation transaction: PREPARE -> STAGE -> COMMIT -> VERIFY,
//! with internal partial-commit recovery on failure.
//!
//! `MUTATION_MODEL=CORULIX_CONTROLLED`: this is the sole path through which
//! a governed batch of filesystem writes reaches the live workspace.
//! Commit order is deterministic (the batch's own order). Per-file
//! replacement is atomic where the platform's `rename` semantics support
//! it (`PER_FILE_ATOMICITY_WHERE_SUPPORTED=YES`); there is no portable
//! multi-file atomic transaction primitive
//! (`MULTIFILE_ATOMICITY=CORULIX_RECOVERY_MODEL`, never
//! `MULTIFILE_ATOMIC_OS_TRANSACTION=YES`). `AUTO_REVERT_ON_GATE_FAILURE=NO`:
//! this module never reverts a successfully committed batch because some
//! later, unrelated gate (lint/test/format) fails -- recovery here exists
//! only to protect *this transaction's own* atomicity when an internal
//! commit step itself fails partway through.
//!
//! M09-P5 (Unix) / M09-P9 (Windows): every irreversible filesystem action in
//! COMMIT/VERIFY/ROLLBACK acts on an opaque `wht_corulix_workspace`
//! capability (`PinnedTarget`/`PinnedParent`) resolved during PREPARE/STAGE
//! -- never a raw pathname re-resolved after authorization. Platform
//! -agnostic: see `prepare.rs`'s own module doc for why this crate never
//! needs its own `#[cfg(unix)]`/`#[cfg(windows)]` split (Architecture Rule
//! F).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use wht_corulix_core::ContentHash;
use wht_corulix_workspace::WorkspaceRoot;

use crate::{
    error::MutationError,
    journal::{Journal, JournalEntry},
    prepare::{self, PreparedItem},
    types::{MutationBatch, MutationLimits, MutationResult},
};

type StagedItem = wht_corulix_workspace::PinnedTarget;

/// The successful, fully-verified outcome of one executed [`MutationBatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationOutcome {
    pub results: Vec<MutationResult>,
}

/// Why [`MutationExecutor::recover`] was invoked -- distinguishes "the
/// commit-time filesystem operation itself failed", "the operation's
/// syscall said `Ok`, but post-commit verification disagreed with the
/// actual on-disk state", and (P-M08-R1) "commit-time revalidation proved
/// the item's own precondition no longer holds", per this crate's error
/// taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RecoveryCause {
    Commit,
    Verification,
    /// P-M08-R1: a mandatory final revalidation, performed immediately
    /// before the irreversible filesystem write, found the target (or a
    /// `MoveFile`'s destination) no longer in the state PREPARE observed.
    /// Carries the exact [`MutationError`] `recover` should return once any
    /// earlier-committed items in the same batch are safely undone --
    /// never the generic [`MutationError::CommitFailed`]/
    /// [`MutationError::VerificationFailed`], so the caller sees the real,
    /// actionable stale/collision reason instead.
    PreconditionAtCommit(MutationError),
}

/// Internal, test-only injection points proving this module's recovery
/// behavior deterministically rather than via flaky timing. Never
/// constructible outside `#[cfg(any(test, feature = "test-support"))]` --
/// this compiles this entire type, and every constructor that sets it, out
/// of a release build (`test-support` is off by default and is enabled
/// only by another workspace crate's own `[dev-dependencies]`, never by a
/// release build of this crate or of `corulix`; see `Cargo.toml`).
/// `pub` (not `pub(crate)`) specifically so `wht_corulix_engine`'s real
/// recovery-lock `ChangeSession` E2E can drive this crate's own real
/// recovery-undo-failure path from across the crate boundary, without this
/// module inventing a second, parallel injection mechanism just for that
/// caller (Phase 10-R1 §5's "internal seam for workspace tests").
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureInjectionPoint {
    /// Fail before the very first item commits -- proves a failure with
    /// nothing yet committed needs no recovery.
    BeforeFirstCommit,
    /// Fail immediately after item `index` commits and is journaled --
    /// proves recovery of one or more already-committed items.
    AfterCommitAt(usize),
    /// Let item `index`'s real operation succeed, journal it, then treat
    /// the disagreement as a verification failure -- proves
    /// `VerificationFailed` triggers recovery exactly like a commit
    /// failure does.
    DuringVerificationAt(usize),
    /// Force every recovery undo attempt to fail -- proves
    /// `RecoveryRequired` and the resulting write-lock.
    DuringRecovery,
}

/// Executes governed [`MutationBatch`]es against exactly one
/// [`WorkspaceRoot`]. Holds the recovery-lock state
/// (`FURTHER_MUTATION_WRITES_DENIED=YES` once set) across calls -- a
/// caller that observes [`MutationError::RecoveryRequired`] must discard
/// this executor and construct a fresh one only once it has independently
/// confirmed/repaired the workspace state; this crate does not attempt an
/// automatic re-recovery.
pub struct MutationExecutor {
    workspace_root: WorkspaceRoot,
    limits: MutationLimits,
    locked: Arc<AtomicBool>,
    #[cfg(any(test, feature = "test-support"))]
    failure_injection: Option<FailureInjectionPoint>,
    /// P-M08-R1 test-only synchronization seam: invoked, synchronously,
    /// with the batch-order index of the item about to be committed,
    /// immediately BEFORE that item's own commit-time precondition
    /// revalidation runs -- letting a test deterministically mutate the
    /// filesystem exactly inside the PREPARE-to-COMMIT window this pass
    /// closes, rather than relying on timing/races. Never alters
    /// production timing or semantics: this field is entirely absent from
    /// a release build (same `cfg` gate as `failure_injection`), and even
    /// under `cfg(test)` a `None` hook costs one option check per item.
    #[cfg(any(test, feature = "test-support"))]
    precommit_hook: Option<Arc<dyn Fn(usize) + Send + Sync>>,
}

impl MutationExecutor {
    #[must_use]
    pub fn new(workspace_root: WorkspaceRoot) -> Self {
        Self::with_limits(workspace_root, MutationLimits::default())
    }

    #[must_use]
    pub fn with_limits(workspace_root: WorkspaceRoot, limits: MutationLimits) -> Self {
        Self {
            workspace_root,
            limits,
            locked: Arc::new(AtomicBool::new(false)),
            #[cfg(any(test, feature = "test-support"))]
            failure_injection: None,
            #[cfg(any(test, feature = "test-support"))]
            precommit_hook: None,
        }
    }

    /// Constructs an executor that will deterministically drive its own
    /// real PREPARE -> STAGE -> COMMIT -> VERIFY -> RECOVER path (never a
    /// mocked `is_locked()`/`MutationError::RecoveryRequired`) into
    /// `point`'s failure -- see [`FailureInjectionPoint`] for why this is
    /// the real recovery mechanism and not a shortcut around it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_failure_injection(
        workspace_root: WorkspaceRoot,
        point: FailureInjectionPoint,
    ) -> Self {
        let mut executor = Self::with_limits(workspace_root, MutationLimits::default());
        executor.failure_injection = Some(point);
        executor
    }

    /// P-M08-R1: constructs an executor whose `commit_one` calls `hook`
    /// (synchronously, with the item's batch-order index) immediately
    /// before that item's own final precondition revalidation -- see
    /// `precommit_hook`'s own doc comment.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_precommit_hook(
        workspace_root: WorkspaceRoot,
        hook: impl Fn(usize) + Send + Sync + 'static,
    ) -> Self {
        let mut executor = Self::with_limits(workspace_root, MutationLimits::default());
        executor.precommit_hook = Some(Arc::new(hook));
        executor
    }

    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    /// This executor's bound [`WorkspaceRoot`] -- read-only (`Clone`, never
    /// a second write path). Lets an already-governed caller that owns this
    /// executor (e.g. `wht_corulix_engine::session::ChangeSession`) invoke
    /// another already-certified governance component requiring an owned
    /// `WorkspaceRoot` (e.g. `wht_corulix_formatter::format_and_apply`)
    /// against the exact same root this executor itself writes to, without
    /// that caller having to separately track/duplicate it.
    #[must_use]
    pub fn workspace_root(&self) -> &WorkspaceRoot {
        &self.workspace_root
    }

    #[cfg(any(test, feature = "test-support"))]
    fn should_fail_before(&self, index: usize) -> bool {
        matches!(
            self.failure_injection,
            Some(FailureInjectionPoint::BeforeFirstCommit) if index == 0
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    fn should_fail_after(&self, index: usize) -> Option<RecoveryCause> {
        if matches!(
            self.failure_injection,
            Some(FailureInjectionPoint::AfterCommitAt(target)) if target == index
        ) {
            return Some(RecoveryCause::Commit);
        }
        if matches!(
            self.failure_injection,
            Some(FailureInjectionPoint::DuringVerificationAt(target)) if target == index
        ) {
            return Some(RecoveryCause::Verification);
        }
        // `DuringRecovery` alone would never actually invoke `recover()`
        // (nothing else fails) -- it also forces a commit failure right
        // after the first item, so its own dedicated undo-failure
        // behavior (in `should_fail_recovery`) has something to prove
        // against.
        if matches!(
            self.failure_injection,
            Some(FailureInjectionPoint::DuringRecovery)
        ) && index == 0
        {
            return Some(RecoveryCause::Commit);
        }
        None
    }

    #[cfg(any(test, feature = "test-support"))]
    fn should_fail_recovery(&self) -> bool {
        matches!(
            self.failure_injection,
            Some(FailureInjectionPoint::DuringRecovery)
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    fn call_precommit_hook(&self, index: usize) {
        if let Some(hook) = &self.precommit_hook {
            hook(index);
        }
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn should_fail_before(&self, _index: usize) -> bool {
        false
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn should_fail_after(&self, _index: usize) -> Option<RecoveryCause> {
        None
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn call_precommit_hook(&self, _index: usize) {}

    #[cfg(not(any(test, feature = "test-support")))]
    fn should_fail_recovery(&self) -> bool {
        false
    }

    /// PREPARE -> STAGE -> COMMIT -> VERIFY, with internal recovery on a
    /// partial-commit failure.
    pub async fn execute(&self, batch: MutationBatch) -> Result<MutationOutcome, MutationError> {
        if self.is_locked() {
            return Err(MutationError::ExecutorLocked);
        }

        let mut prepared = prepare::prepare(&batch, &self.workspace_root, &self.limits).await?;
        let mut staged = self.stage(&mut prepared).await?;

        let mut journal = Journal::bounded(self.limits.max_journal_entries);
        let mut results = Vec::with_capacity(prepared.len());

        for (index, item) in prepared.into_iter().enumerate() {
            if self.should_fail_before(index) {
                return self.recover(journal, RecoveryCause::Commit).await;
            }

            self.call_precommit_hook(index);
            let staged_item = staged.get_mut(index).and_then(Option::take);
            let outcome = self.commit_one(item, staged_item).await;
            let (entry, result) = match outcome {
                Ok(pair) => pair,
                Err(CommitAttemptError::Operation) => {
                    return self.recover(journal, RecoveryCause::Commit).await;
                }
                Err(CommitAttemptError::Verification) => {
                    return self.recover(journal, RecoveryCause::Verification).await;
                }
                Err(CommitAttemptError::PreconditionAtCommit(original_error)) => {
                    return self
                        .recover(journal, RecoveryCause::PreconditionAtCommit(original_error))
                        .await;
                }
            };

            if !journal.push(entry) {
                // Structurally unreachable given max_journal_entries >=
                // max_mutation_count, but never trust that invariant
                // silently -- treat it exactly like any other commit-time
                // failure and recover.
                return self.recover(journal, RecoveryCause::Commit).await;
            }
            results.push(result);

            if let Some(cause) = self.should_fail_after(index) {
                return self.recover(journal, cause).await;
            }
        }

        Ok(MutationOutcome { results })
    }

    async fn stage(
        &self,
        prepared: &mut [PreparedItem],
    ) -> Result<Vec<Option<StagedItem>>, MutationError> {
        let mut staged = Vec::with_capacity(prepared.len());
        let mut total_staged_bytes: u64 = 0;
        for item in prepared.iter_mut() {
            match item {
                PreparedItem::ReplaceLike(replace) => {
                    total_staged_bytes =
                        total_staged_bytes.saturating_add(replace.final_bytes.len() as u64);
                    if total_staged_bytes > self.limits.max_total_staged_bytes {
                        cleanup_staged(staged).await;
                        return Err(MutationError::ResourceLimitExceeded);
                    }
                    let Some(parent_capability) = replace.parent_capability.take() else {
                        cleanup_staged(staged).await;
                        return Err(MutationError::PrepareFailed);
                    };
                    let final_bytes = replace.final_bytes.clone();
                    let stage_result = tokio::task::spawn_blocking(move || {
                        parent_capability
                            .create_exclusive_temp_sibling(&final_bytes)
                            .map(|(stage_target, _stage_file)| stage_target)
                    })
                    .await
                    .map_err(|_| MutationError::PrepareFailed)?;
                    match stage_result {
                        Ok(stage_target) => staged.push(Some(stage_target)),
                        Err(_) => {
                            cleanup_staged(staged).await;
                            return Err(MutationError::PrepareFailed);
                        }
                    }
                }
                PreparedItem::Create(_) | PreparedItem::Delete(_) | PreparedItem::Move(_) => {
                    staged.push(None);
                }
            }
        }
        Ok(staged)
    }

    async fn commit_one(
        &self,
        item: PreparedItem,
        staged_temp: Option<StagedItem>,
    ) -> Result<(JournalEntry, MutationResult), CommitAttemptError> {
        capability_commit::commit_one(item, staged_temp).await
    }

    /// Undoes every journaled item, most-recently-committed first. If
    /// every undo succeeds, the transaction had no lasting live effect
    /// ([`MutationError::CommitFailed`]/[`MutationError::VerificationFailed`],
    /// matching `cause`). If any undo itself fails, this executor is
    /// locked (`FURTHER_MUTATION_WRITES_DENIED=YES`) and
    /// [`MutationError::RecoveryRequired`] is returned, carrying every
    /// journaled path recovery did not confirm undone.
    async fn recover(
        &self,
        journal: Journal,
        cause: RecoveryCause,
    ) -> Result<MutationOutcome, MutationError> {
        let entries = journal.into_entries_in_commit_order();
        let ordered_paths: Vec<wht_corulix_core::WorkspacePath> = entries
            .iter()
            .rev()
            .map(|entry| entry.workspace_path().clone())
            .collect();
        let mut recovered_paths = Vec::with_capacity(entries.len());
        let mut entries_rev = entries.into_iter().rev();
        for (position, path) in ordered_paths.iter().enumerate() {
            let Some(entry) = entries_rev.next() else {
                break;
            };
            if self.should_fail_recovery() || undo(entry, &self.workspace_root).await.is_err() {
                self.locked.store(true, Ordering::SeqCst);
                let unrecovered_paths = ordered_paths[position..].to_vec();
                return Err(MutationError::RecoveryRequired { unrecovered_paths });
            }
            recovered_paths.push(path.clone());
        }
        match cause {
            RecoveryCause::Commit => Err(MutationError::CommitFailed { recovered_paths }),
            RecoveryCause::Verification => {
                Err(MutationError::VerificationFailed { recovered_paths })
            }
            // P-M08-R1: any earlier-committed items in this batch are
            // already safely undone above (or this path was never taken at
            // all -- the common single-item-batch case, matching today's
            // PREPARE-time rejection shape exactly, empty journal). Return
            // the real, specific precondition/collision error the
            // commit-time recheck found, never the generic recovery codes.
            RecoveryCause::PreconditionAtCommit(original_error) => Err(original_error),
        }
    }
}

/// The internal-only distinction [`MutationExecutor::commit_one`] uses to
/// tell its caller which [`RecoveryCause`] to attribute -- never exposed
/// outside this module; the public [`MutationError`] carries the final
/// classification instead.
enum CommitAttemptError {
    Operation,
    Verification,
    /// P-M08-R1: commit-time revalidation found the target/source/
    /// destination no longer in the state PREPARE observed. Carries the
    /// exact [`MutationError`] `execute`'s caller should ultimately see.
    PreconditionAtCommit(MutationError),
}

async fn undo(entry: JournalEntry, root: &WorkspaceRoot) -> Result<(), ()> {
    use std::path::PathBuf;

    match entry {
        JournalEntry::Create { path } => {
            let root = root.clone();
            let relative = PathBuf::from(&path.relative_path);
            let result = tokio::task::spawn_blocking(move || {
                wht_corulix_workspace::resolve_existing_target(&root, &relative)
                    .and_then(|capability| capability.unlink())
            })
            .await
            .map_err(|_| ())?;
            result.map_err(|_| ())
        }
        JournalEntry::ReplaceLike {
            path,
            original_bytes,
        } => {
            let root = root.clone();
            let relative = PathBuf::from(&path.relative_path);
            let result = tokio::task::spawn_blocking(move || {
                let target = wht_corulix_workspace::resolve_existing_target(&root, &relative)?;
                let parent = wht_corulix_workspace::resolve_parent(&root, &relative)?;
                let (stage_target, _stage_file) =
                    parent.create_exclusive_temp_sibling(&original_bytes)?;
                stage_target.rename_into(target)
            })
            .await
            .map_err(|_| ())?;
            result.map_err(|_| ())
        }
        JournalEntry::Delete {
            path,
            original_bytes,
        } => {
            let root = root.clone();
            let relative = PathBuf::from(&path.relative_path);
            let result = tokio::task::spawn_blocking(move || {
                let target = wht_corulix_workspace::resolve_new_target(&root, &relative)?;
                target.create_exclusive(&original_bytes).map(|_| ())
            })
            .await
            .map_err(|_| ())?;
            result.map_err(|_| ())
        }
        JournalEntry::Move {
            source_path,
            destination_path,
        } => {
            let root = root.clone();
            let source_relative = PathBuf::from(&source_path.relative_path);
            let destination_relative = PathBuf::from(&destination_path.relative_path);
            let result = tokio::task::spawn_blocking(move || {
                let current =
                    wht_corulix_workspace::resolve_existing_target(&root, &destination_relative)?;
                let restored_source =
                    wht_corulix_workspace::resolve_new_target(&root, &source_relative)?;
                current.rename_into(restored_source)
            })
            .await
            .map_err(|_| ())?;
            result.map_err(|_| ())
        }
    }
}

// =====================================================================
// Capability-based COMMIT (M09-P5 Unix, M09-P9 Windows) -- platform
// -agnostic; see `prepare.rs`'s own module doc comment.
// =====================================================================

mod capability_commit {
    use super::{CommitAttemptError, ContentHash, JournalEntry, MutationError, MutationResult};
    use crate::prepare::{PreparedCreate, PreparedDelete, PreparedItem, PreparedMove};
    use wht_corulix_workspace::PinnedTarget;

    pub(super) async fn commit_one(
        item: PreparedItem,
        staged_temp: Option<PinnedTarget>,
    ) -> Result<(JournalEntry, MutationResult), CommitAttemptError> {
        match item {
            PreparedItem::Create(create) => commit_create(create).await,
            PreparedItem::ReplaceLike(replace) => {
                let staged = staged_temp.ok_or(CommitAttemptError::Operation)?;
                commit_replace_like(replace, staged).await
            }
            PreparedItem::Delete(delete) => commit_delete(delete).await,
            PreparedItem::Move(move_item) => commit_move(move_item).await,
        }
    }

    enum CreateAttempt {
        OperationFailed,
        VerificationFailed,
        Success(ContentHash),
    }

    async fn commit_create(
        create: PreparedCreate,
    ) -> Result<(JournalEntry, MutationResult), CommitAttemptError> {
        let PreparedCreate {
            path,
            capability,
            content,
        } = create;
        let content_for_closure = content.clone();
        let attempt = tokio::task::spawn_blocking(move || {
            // `create_exclusive` opens `WRONLY` (Section 19/`SECURE_CREATE`
            // in `wht_corulix_workspace::capability` -- a write-only fd is
            // never itself readable back). Verification reopens the SAME
            // already-pinned `(parent_fd, leaf)` pair read-only via
            // `capability.open_file()` -- not a re-walk, just a second
            // `openat` against the identical fd/leaf this capability was
            // bound to at PREPARE time.
            if capability.create_exclusive(&content_for_closure).is_err() {
                return CreateAttempt::OperationFailed;
            }
            let bound = (content_for_closure.len() as u64).saturating_add(1);
            let actual = match capability
                .open_file()
                .and_then(|file| file.read_bytes(bound))
            {
                Ok(bytes) => bytes,
                Err(_) => return CreateAttempt::VerificationFailed,
            };
            if actual != content_for_closure {
                return CreateAttempt::VerificationFailed;
            }
            CreateAttempt::Success(ContentHash::compute_sha256(&actual))
        })
        .await
        .map_err(|_| CommitAttemptError::Operation)?;

        match attempt {
            CreateAttempt::OperationFailed => Err(CommitAttemptError::Operation),
            CreateAttempt::VerificationFailed => Err(CommitAttemptError::Verification),
            CreateAttempt::Success(hash) => Ok((
                JournalEntry::Create { path: path.clone() },
                MutationResult::Created { path, hash },
            )),
        }
    }

    enum ReplaceAttempt {
        Stale,
        OperationFailed,
        VerificationFailed,
        Success(ContentHash),
    }

    async fn commit_replace_like(
        replace: crate::prepare::PreparedReplaceLike,
        staged: PinnedTarget,
    ) -> Result<(JournalEntry, MutationResult), CommitAttemptError> {
        let crate::prepare::PreparedReplaceLike {
            path,
            target_capability,
            parent_capability: _parent_capability,
            final_bytes,
            original_bytes,
        } = replace;
        let revalidate_bound = (original_bytes.len() as u64).saturating_add(1);
        let final_bytes_for_closure = final_bytes.clone();
        let original_bytes_for_closure = original_bytes.clone();
        let attempt = tokio::task::spawn_blocking(move || {
            let current = match target_capability
                .open_file()
                .and_then(|file| file.read_bytes(revalidate_bound))
            {
                Ok(bytes) => bytes,
                Err(_) => return ReplaceAttempt::Stale,
            };
            if current != original_bytes_for_closure {
                return ReplaceAttempt::Stale;
            }
            let reopened = match staged.rename_into_verified(target_capability) {
                Ok(file) => file,
                Err(_) => return ReplaceAttempt::OperationFailed,
            };
            let verify_bound = (final_bytes_for_closure.len() as u64).saturating_add(1);
            let actual = match reopened.read_bytes(verify_bound) {
                Ok(bytes) => bytes,
                Err(_) => return ReplaceAttempt::VerificationFailed,
            };
            if actual != final_bytes_for_closure {
                return ReplaceAttempt::VerificationFailed;
            }
            ReplaceAttempt::Success(ContentHash::compute_sha256(&actual))
        })
        .await
        .map_err(|_| CommitAttemptError::Operation)?;

        match attempt {
            ReplaceAttempt::Stale => Err(CommitAttemptError::PreconditionAtCommit(
                MutationError::StalePreconditionHash { path: path.clone() },
            )),
            ReplaceAttempt::OperationFailed => Err(CommitAttemptError::Operation),
            ReplaceAttempt::VerificationFailed => Err(CommitAttemptError::Verification),
            ReplaceAttempt::Success(hash) => Ok((
                JournalEntry::ReplaceLike {
                    path: path.clone(),
                    original_bytes,
                },
                MutationResult::Replaced { path, hash },
            )),
        }
    }

    enum DeleteAttempt {
        Stale,
        OperationFailed,
        Success,
    }

    async fn commit_delete(
        delete: PreparedDelete,
    ) -> Result<(JournalEntry, MutationResult), CommitAttemptError> {
        let PreparedDelete {
            path,
            capability,
            original_bytes,
        } = delete;
        let revalidate_bound = (original_bytes.len() as u64).saturating_add(1);
        let original_bytes_for_closure = original_bytes.clone();
        let attempt = tokio::task::spawn_blocking(move || {
            let current = match capability
                .open_file()
                .and_then(|file| file.read_bytes(revalidate_bound))
            {
                Ok(bytes) => bytes,
                Err(_) => return DeleteAttempt::Stale,
            };
            if current != original_bytes_for_closure {
                return DeleteAttempt::Stale;
            }
            match capability.unlink_verified() {
                Ok(()) => DeleteAttempt::Success,
                Err(_) => DeleteAttempt::OperationFailed,
            }
        })
        .await
        .map_err(|_| CommitAttemptError::Operation)?;

        match attempt {
            DeleteAttempt::Stale => Err(CommitAttemptError::PreconditionAtCommit(
                MutationError::StalePreconditionHash { path: path.clone() },
            )),
            DeleteAttempt::OperationFailed => Err(CommitAttemptError::Operation),
            DeleteAttempt::Success => Ok((
                JournalEntry::Delete {
                    path: path.clone(),
                    original_bytes,
                },
                MutationResult::Deleted { path },
            )),
        }
    }

    enum MoveAttempt {
        Stale,
        DestinationCollision,
        OperationFailed,
        VerificationFailed,
        Success(ContentHash),
    }

    async fn commit_move(
        move_item: PreparedMove,
    ) -> Result<(JournalEntry, MutationResult), CommitAttemptError> {
        let PreparedMove {
            source_path,
            destination_path,
            source_capability,
            destination_capability,
            source_original_bytes,
        } = move_item;
        let bound = (source_original_bytes.len() as u64).saturating_add(1);
        let attempt = tokio::task::spawn_blocking(move || {
            let current = match source_capability
                .open_file()
                .and_then(|file| file.read_bytes(bound))
            {
                Ok(bytes) => bytes,
                Err(_) => return MoveAttempt::Stale,
            };
            if current != source_original_bytes {
                return MoveAttempt::Stale;
            }
            match destination_capability.still_absent() {
                Ok(true) => {}
                _ => return MoveAttempt::DestinationCollision,
            }
            let reopened = match source_capability.rename_into_verified(destination_capability) {
                Ok(file) => file,
                Err(_) => return MoveAttempt::OperationFailed,
            };
            let actual = match reopened.read_bytes(bound) {
                Ok(bytes) => bytes,
                Err(_) => return MoveAttempt::VerificationFailed,
            };
            if actual != source_original_bytes {
                return MoveAttempt::VerificationFailed;
            }
            MoveAttempt::Success(ContentHash::compute_sha256(&actual))
        })
        .await
        .map_err(|_| CommitAttemptError::Operation)?;

        match attempt {
            MoveAttempt::Stale => Err(CommitAttemptError::PreconditionAtCommit(
                MutationError::StalePreconditionHash {
                    path: source_path.clone(),
                },
            )),
            MoveAttempt::DestinationCollision => Err(CommitAttemptError::PreconditionAtCommit(
                MutationError::MoveCollision {
                    destination: destination_path.clone(),
                },
            )),
            MoveAttempt::OperationFailed => Err(CommitAttemptError::Operation),
            MoveAttempt::VerificationFailed => Err(CommitAttemptError::Verification),
            MoveAttempt::Success(hash) => Ok((
                JournalEntry::Move {
                    source_path: source_path.clone(),
                    destination_path: destination_path.clone(),
                },
                MutationResult::Moved {
                    source: source_path,
                    destination: destination_path,
                    hash,
                },
            )),
        }
    }
}

async fn cleanup_staged(staged: Vec<Option<StagedItem>>) {
    for item in staged.into_iter().flatten() {
        let _ = tokio::task::spawn_blocking(move || item.unlink()).await;
    }
}

#[cfg(test)]
mod tests;
