// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! PREPARE: validates the entire batch -- every path, every precondition
//! hash, every collision, every edit range, every resource bound, and the
//! final bytes each mutation would produce -- before any live workspace
//! write happens. If any single item fails, the whole batch fails and
//! `LIVE_WORKSPACE_MUTATION_COUNT=0` (this module performs no write of any
//! kind; every filesystem call it makes is a read).
//!
//! Path confinement is never re-implemented here (Architecture Rule F).
//! M09-P5 (Unix) / M09-P9 (Windows): every target/source is resolved into
//! an opaque `wht_corulix_workspace` capability (`PinnedTarget`/
//! `PinnedParent`) via the crate's cross-crate acquisition API
//! (`resolve_existing_target`/`resolve_new_target`/`resolve_parent`) --
//! never a raw pathname carried forward for later mutation I/O. This code
//! is platform-agnostic: `wht_corulix_workspace` exposes the identical
//! capability API on both platforms (Unix via `openat`/`fstat`, Windows via
//! handle-relative `NtCreateFile`/`SetFileInformationByHandle`), so this
//! crate never needs its own platform split -- Architecture Rule F keeps
//! all platform-specific filesystem-authority mechanics inside
//! `wht_corulix_workspace` alone. This crate never depends on either
//! platform's narrow unsafe-FFI boundary crate directly and never will
//! (Architecture Rule Y.4) -- it only ever consumes `wht_corulix_workspace`'s
//! own safe capability API.

use std::path::PathBuf;
use wht_corulix_core::{ContentHash, ContentHashAlgorithm, WorkspacePath};
use wht_corulix_workspace::WorkspaceRoot;

use crate::{
    edits,
    error::MutationError,
    types::{Mutation, MutationBatch, MutationLimits},
};

pub(crate) struct PreparedCreate {
    pub path: WorkspacePath,
    pub capability: wht_corulix_workspace::PinnedTarget,
    pub content: Vec<u8>,
}

pub(crate) struct PreparedReplaceLike {
    pub path: WorkspacePath,
    pub target_capability: wht_corulix_workspace::PinnedTarget,
    /// `Some` from PREPARE until STAGE consumes it to create the ephemeral
    /// stage sibling; `None` afterward (COMMIT never needs it again).
    pub parent_capability: Option<wht_corulix_workspace::PinnedParent>,
    pub final_bytes: Vec<u8>,
    pub original_bytes: Vec<u8>,
}

pub(crate) struct PreparedDelete {
    pub path: WorkspacePath,
    pub capability: wht_corulix_workspace::PinnedTarget,
    pub original_bytes: Vec<u8>,
}

pub(crate) struct PreparedMove {
    pub source_path: WorkspacePath,
    pub destination_path: WorkspacePath,
    pub source_capability: wht_corulix_workspace::PinnedTarget,
    pub destination_capability: wht_corulix_workspace::PinnedTarget,
    pub source_original_bytes: Vec<u8>,
}

pub(crate) enum PreparedItem {
    Create(PreparedCreate),
    ReplaceLike(PreparedReplaceLike),
    Delete(PreparedDelete),
    Move(PreparedMove),
}

/// A canonical [`ContentHash::compute_sha256`] digest is always exactly 64
/// lowercase hex characters (`hex_digest`'s own `format!("{byte:02x}")`).
/// Anything else is not a possible real digest this workspace ever
/// produced -- a caller-supplied string that fails this check is malformed
/// input, never a genuinely-stale-but-well-formed hash.
fn is_well_formed_sha256_hex(digest_hex: &str) -> bool {
    digest_hex.len() == 64
        && digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn check_hash(
    path: &WorkspacePath,
    expected: &ContentHash,
    actual_bytes: &[u8],
) -> Result<(), MutationError> {
    // P-M08-R1 reason-code precision fix: a malformed expected hash (wrong
    // length, non-hex characters, uppercase, or a non-Sha256 algorithm) is
    // a caller-input defect, never a genuine staleness signal -- reject it
    // distinctly, before ever comparing, so it can never be misreported as
    // an ordinary stale precondition.
    if expected.algorithm != ContentHashAlgorithm::Sha256
        || !is_well_formed_sha256_hex(&expected.digest_hex)
    {
        return Err(MutationError::MalformedPreconditionHash { path: path.clone() });
    }
    let actual = ContentHash::compute_sha256(actual_bytes);
    if &actual != expected {
        return Err(MutationError::StalePreconditionHash { path: path.clone() });
    }
    Ok(())
}

struct BudgetTracker {
    total_input_bytes: u64,
    total_recovery_bytes: u64,
    total_edits: usize,
    limits: MutationLimits,
}

impl BudgetTracker {
    fn new(limits: MutationLimits) -> Self {
        Self {
            total_input_bytes: 0,
            total_recovery_bytes: 0,
            total_edits: 0,
            limits,
        }
    }

    fn add_input(&mut self, bytes: u64) -> Result<(), MutationError> {
        self.total_input_bytes = self.total_input_bytes.saturating_add(bytes);
        if self.total_input_bytes > self.limits.max_total_input_bytes {
            return Err(MutationError::ResourceLimitExceeded);
        }
        Ok(())
    }

    fn add_recovery(&mut self, bytes: u64) -> Result<(), MutationError> {
        self.total_recovery_bytes = self.total_recovery_bytes.saturating_add(bytes);
        if self.total_recovery_bytes > self.limits.max_recovery_capture_bytes {
            return Err(MutationError::ResourceLimitExceeded);
        }
        Ok(())
    }

    fn add_edits(&mut self, count: usize) -> Result<(), MutationError> {
        if count > self.limits.max_edits_per_file {
            return Err(MutationError::ResourceLimitExceeded);
        }
        self.total_edits = self.total_edits.saturating_add(count);
        if self.total_edits > self.limits.max_total_edits {
            return Err(MutationError::ResourceLimitExceeded);
        }
        Ok(())
    }
}

// =====================================================================
// Capability-based resolution (M09-P5 Unix, M09-P9 Windows) -- platform
// -agnostic; see this file's own module doc comment.
// =====================================================================

mod capability_resolve {
    use super::{MutationError, PathBuf, WorkspacePath, WorkspaceRoot};
    use wht_corulix_workspace::{PinnedParent, PinnedTarget};

    /// Distinguishes "lexically safe, merely absent" from "genuine
    /// confinement violation" for an EXISTING-target resolution failure,
    /// without weakening confinement (P-M08-R1's own precision fix,
    /// reproduced here for the capability path): if a NEW_TARGET resolution
    /// of the SAME relative path succeeds, the parent chain confines fine
    /// and the leaf is genuinely absent, so the original failure was mere
    /// absence. If NEW_TARGET also fails, either the parent itself does not
    /// confine, or something (a file, directory, or symlink) already
    /// occupies the leaf in a way `resolve_existing_target` could not
    /// safely use -- both are real confinement-adjacent denials, never
    /// conflated with plain absence.
    async fn classify_existing_failure(
        root: &WorkspaceRoot,
        path: &WorkspacePath,
    ) -> MutationError {
        let root = root.clone();
        let relative = PathBuf::from(&path.relative_path);
        let merely_absent = tokio::task::spawn_blocking(move || {
            wht_corulix_workspace::resolve_new_target(&root, &relative).is_ok()
        })
        .await
        .unwrap_or(false);
        if merely_absent {
            MutationError::TargetNotFound { path: path.clone() }
        } else {
            MutationError::ConfinementViolation { path: path.clone() }
        }
    }

    /// `EXISTING_TARGET_FOLLOW_SAFE_FINAL_SYMLINK` resolution, exposed to
    /// this crate only through `wht_corulix_workspace::resolve_existing_target`
    /// (Section 3 of the P5 mandate: `WorkspaceRoot` + a workspace-relative
    /// path in, an opaque capability out -- never a raw leaf/fd/handle).
    pub(crate) async fn capability_existing(
        root: &WorkspaceRoot,
        path: &WorkspacePath,
    ) -> Result<PinnedTarget, MutationError> {
        let root_owned = root.clone();
        let relative = PathBuf::from(&path.relative_path);
        let resolved = tokio::task::spawn_blocking(move || {
            wht_corulix_workspace::resolve_existing_target(&root_owned, &relative)
        })
        .await
        .map_err(|_| MutationError::PrepareFailed)?;
        match resolved {
            Ok(capability) => Ok(capability),
            Err(_) => Err(classify_existing_failure(root, path).await),
        }
    }

    /// `PIN_PARENT_ONLY` resolution, exposed the same way -- used only for
    /// STAGE (creating an ephemeral, internally-named sibling in the same
    /// directory as an existing target).
    pub(crate) async fn capability_parent(
        root: &WorkspaceRoot,
        path: &WorkspacePath,
    ) -> Result<PinnedParent, MutationError> {
        let root_owned = root.clone();
        let relative = PathBuf::from(&path.relative_path);
        let path_owned = path.clone();
        tokio::task::spawn_blocking(move || {
            wht_corulix_workspace::resolve_parent(&root_owned, &relative)
        })
        .await
        .map_err(|_| MutationError::PrepareFailed)?
        .map_err(|_| MutationError::ConfinementViolation { path: path_owned })
    }

    /// `NEW_TARGET_REQUIRE_ABSENT_FINAL_ENTRY` resolution, exposed the same
    /// way. `collision_error` supplies the operation-specific collision
    /// variant (`CreateCollision` for `CreateFile`, `MoveCollision` for
    /// `MoveFile`'s destination) -- the confinement-vs-collision
    /// distinction itself never depends on the caller's choice.
    pub(crate) async fn capability_new(
        root: &WorkspaceRoot,
        path: &WorkspacePath,
        collision_error: impl FnOnce() -> MutationError,
    ) -> Result<PinnedTarget, MutationError> {
        let root_for_parent = root.clone();
        let relative_for_parent = PathBuf::from(&path.relative_path);
        let parent_ok = tokio::task::spawn_blocking(move || {
            wht_corulix_workspace::resolve_parent(&root_for_parent, &relative_for_parent).is_ok()
        })
        .await
        .map_err(|_| MutationError::PrepareFailed)?;
        if !parent_ok {
            return Err(MutationError::ConfinementViolation { path: path.clone() });
        }
        let root_for_new = root.clone();
        let relative_for_new = PathBuf::from(&path.relative_path);
        let resolved = tokio::task::spawn_blocking(move || {
            wht_corulix_workspace::resolve_new_target(&root_for_new, &relative_for_new)
        })
        .await
        .map_err(|_| MutationError::PrepareFailed)?;
        resolved.map_err(|_| collision_error())
    }

    /// Opens `capability` as a regular file and reads its bytes, hard-
    /// bounded by `max_bytes` (M09-P5 Section 9: `PinnedFile::read_bytes`'s
    /// P4R hard bound, never a raw unbounded `fs::read`). Returns the
    /// capability back alongside the bytes so the caller can retain it for
    /// later STAGE/COMMIT use -- nothing here consumes it beyond this read.
    /// Any failure (missing/not-a-regular-file/oversized/other read error)
    /// is classified `TargetNotFound`/`ResourceLimitExceeded` exactly like
    /// the pre-P5 `fs::read`-based `read_existing` classified any read
    /// failure as `TargetNotFound` -- except the NEW `FileTooLarge` case,
    /// which pre-P5 code could never produce (its read was unbounded) and
    /// which this migration intentionally introduces as a hardening.
    pub(crate) async fn read_via_capability(
        capability: PinnedTarget,
        path: &WorkspacePath,
        max_bytes: u64,
    ) -> Result<(PinnedTarget, Vec<u8>), MutationError> {
        let path_owned = path.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let file = capability.open_file()?;
            let bytes = file.read_bytes(max_bytes)?;
            Ok::<(PinnedTarget, Vec<u8>), wht_corulix_core::CorulixError>((capability, bytes))
        })
        .await
        .map_err(|_| MutationError::PrepareFailed)?;
        outcome.map_err(|error| match error {
            wht_corulix_core::CorulixError::FileTooLarge => MutationError::ResourceLimitExceeded,
            _ => MutationError::TargetNotFound {
                path: path_owned.clone(),
            },
        })
    }
}

/// Validates and prepares the entire batch. Reads only -- never writes.
pub(crate) async fn prepare(
    batch: &MutationBatch,
    root: &WorkspaceRoot,
    limits: &MutationLimits,
) -> Result<Vec<PreparedItem>, MutationError> {
    use capability_resolve::{
        capability_existing, capability_new, capability_parent, read_via_capability,
    };

    if batch.mutations.len() > limits.max_mutation_count {
        return Err(MutationError::ResourceLimitExceeded);
    }

    let mut budget = BudgetTracker::new(*limits);
    let mut prepared = Vec::with_capacity(batch.mutations.len());
    let max_read_bytes = limits.max_recovery_capture_bytes;

    for mutation in &batch.mutations {
        match mutation {
            Mutation::CreateFile { path, content } => {
                budget.add_input(content.len() as u64)?;
                let capability = capability_new(root, path, || MutationError::CreateCollision {
                    path: path.clone(),
                })
                .await?;
                prepared.push(PreparedItem::Create(PreparedCreate {
                    path: path.clone(),
                    capability,
                    content: content.clone(),
                }));
            }
            Mutation::ReplaceFile {
                path,
                expected_precondition_hash,
                content,
            } => {
                budget.add_input(content.len() as u64)?;
                let target_capability = capability_existing(root, path).await?;
                let (target_capability, original_bytes) =
                    read_via_capability(target_capability, path, max_read_bytes).await?;
                budget.add_recovery(original_bytes.len() as u64)?;
                check_hash(path, expected_precondition_hash, &original_bytes)?;
                let parent_capability = capability_parent(root, path).await?;
                prepared.push(PreparedItem::ReplaceLike(PreparedReplaceLike {
                    path: path.clone(),
                    target_capability,
                    parent_capability: Some(parent_capability),
                    final_bytes: content.clone(),
                    original_bytes,
                }));
            }
            Mutation::ApplyTextEdits {
                path,
                expected_precondition_hash,
                edits: requested_edits,
            } => {
                budget.add_edits(requested_edits.len())?;
                let target_capability = capability_existing(root, path).await?;
                let (target_capability, original_bytes) =
                    read_via_capability(target_capability, path, max_read_bytes).await?;
                budget.add_recovery(original_bytes.len() as u64)?;
                check_hash(path, expected_precondition_hash, &original_bytes)?;
                let final_bytes = edits::apply_text_edits(path, &original_bytes, requested_edits)?;
                budget.add_input(final_bytes.len() as u64)?;
                let parent_capability = capability_parent(root, path).await?;
                prepared.push(PreparedItem::ReplaceLike(PreparedReplaceLike {
                    path: path.clone(),
                    target_capability,
                    parent_capability: Some(parent_capability),
                    final_bytes,
                    original_bytes,
                }));
            }
            Mutation::DeleteFile {
                path,
                expected_precondition_hash,
            } => {
                let target_capability = capability_existing(root, path).await?;
                let (target_capability, original_bytes) =
                    read_via_capability(target_capability, path, max_read_bytes).await?;
                budget.add_recovery(original_bytes.len() as u64)?;
                check_hash(path, expected_precondition_hash, &original_bytes)?;
                prepared.push(PreparedItem::Delete(PreparedDelete {
                    path: path.clone(),
                    capability: target_capability,
                    original_bytes,
                }));
            }
            Mutation::MoveFile {
                source,
                destination,
                expected_source_hash,
            } => {
                let source_capability = capability_existing(root, source).await?;
                let (source_capability, source_bytes) =
                    read_via_capability(source_capability, source, max_read_bytes).await?;
                check_hash(source, expected_source_hash, &source_bytes)?;
                budget.add_recovery(source_bytes.len() as u64)?;
                let destination_capability =
                    capability_new(root, destination, || MutationError::MoveCollision {
                        destination: destination.clone(),
                    })
                    .await?;
                prepared.push(PreparedItem::Move(PreparedMove {
                    source_path: source.clone(),
                    destination_path: destination.clone(),
                    source_capability,
                    destination_capability,
                    source_original_bytes: source_bytes,
                }));
            }
        }
    }

    Ok(prepared)
}
