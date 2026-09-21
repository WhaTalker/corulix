// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::types::{Mutation, MutationBatch, MutationLimits, TextEdit};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use wht_corulix_core::{ContentHash, Position, SourceRange, WorkspacePath, WorkspaceRootId};

fn temp_workspace() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!("corulix-mutation-test-{stamp}-{unique}"));
    let _ = fs::create_dir_all(&root);
    root
}

fn open_root(path: &Path) -> wht_corulix_core::CorulixResult<WorkspaceRoot> {
    WorkspaceRoot::open(path)
}

fn workspace_path(relative: &str) -> WorkspacePath {
    WorkspacePath {
        root: WorkspaceRootId(0),
        relative_path: relative.to_string(),
    }
}

fn range(start: u64, end: u64) -> SourceRange {
    SourceRange {
        start: Position {
            line_zero_based: 0,
            byte_column_zero_based: 0,
            byte_offset: start,
        },
        end: Position {
            line_zero_based: 0,
            byte_column_zero_based: 0,
            byte_offset: end,
        },
    }
}

#[tokio::test]
async fn failure_before_first_commit_needs_no_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let executor = MutationExecutor::with_failure_injection(
        open_root(&dir)?,
        FailureInjectionPoint::BeforeFirstCommit,
    );
    let batch = MutationBatch {
        mutations: vec![Mutation::CreateFile {
            path: workspace_path("never-written.rs"),
            content: b"content".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::CommitFailed {
            recovered_paths: Vec::new()
        })
    );
    assert!(!dir.join("never-written.rs").exists());
    assert!(!executor.is_locked());
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn create_file_succeeds_and_is_verified() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::CreateFile {
            path: workspace_path("new.rs"),
            content: b"fn new_fn() {}".to_vec(),
        }],
    };
    let outcome = executor.execute(batch).await?;
    assert_eq!(outcome.results.len(), 1);
    assert_eq!(fs::read(dir.join("new.rs"))?, b"fn new_fn() {}");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn create_collision_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("exists.rs"), b"already here");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::CreateFile {
            path: workspace_path("exists.rs"),
            content: b"overwrite attempt".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::CreateCollision {
            path: workspace_path("exists.rs")
        })
    );
    assert_eq!(fs::read(dir.join("exists.rs"))?, b"already here");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn replace_file_succeeds_with_correct_precondition_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("existing.rs"), b"old content");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: workspace_path("existing.rs"),
            expected_precondition_hash: ContentHash::compute_sha256(b"old content"),
            content: b"new content".to_vec(),
        }],
    };
    executor.execute(batch).await?;
    assert_eq!(fs::read(dir.join("existing.rs"))?, b"new content");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn stale_precondition_hash_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("existing.rs"), b"actual content");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: workspace_path("existing.rs"),
            expected_precondition_hash: ContentHash::compute_sha256(b"a stale guess"),
            content: b"new content".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::StalePreconditionHash {
            path: workspace_path("existing.rs")
        })
    );
    assert_eq!(fs::read(dir.join("existing.rs"))?, b"actual content");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn manual_out_of_band_edit_causes_next_precondition_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("observed.rs"), b"observed content");
    let observed_hash = ContentHash::compute_sha256(b"observed content");
    // Simulates an external, out-of-band edit landing between the
    // caller's observation and its mutation attempt.
    let _ = fs::write(dir.join("observed.rs"), b"externally modified content");

    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: workspace_path("observed.rs"),
            expected_precondition_hash: observed_hash,
            content: b"caller's intended new content".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert!(matches!(
        result,
        Err(MutationError::StalePreconditionHash { .. })
    ));
    assert_eq!(
        fs::read(dir.join("observed.rs"))?,
        b"externally modified content"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn apply_text_edits_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("edit.rs"), b"fn target() {}");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::ApplyTextEdits {
            path: workspace_path("edit.rs"),
            expected_precondition_hash: ContentHash::compute_sha256(b"fn target() {}"),
            edits: vec![TextEdit {
                range: range(3, 9),
                new_text: "renamed".to_string(),
            }],
        }],
    };
    executor.execute(batch).await?;
    assert_eq!(fs::read(dir.join("edit.rs"))?, b"fn renamed() {}");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn out_of_range_edit_is_rejected_without_writing() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("edit.rs"), b"short");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::ApplyTextEdits {
            path: workspace_path("edit.rs"),
            expected_precondition_hash: ContentHash::compute_sha256(b"short"),
            edits: vec![TextEdit {
                range: range(0, 100),
                new_text: "x".to_string(),
            }],
        }],
    };
    let result = executor.execute(batch).await;
    assert!(matches!(
        result,
        Err(MutationError::InvalidEditRange { .. })
    ));
    assert_eq!(fs::read(dir.join("edit.rs"))?, b"short");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn overlapping_edits_are_rejected_without_writing() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = temp_workspace();
    let _ = fs::write(dir.join("edit.rs"), b"aaaaaaaaaa");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::ApplyTextEdits {
            path: workspace_path("edit.rs"),
            expected_precondition_hash: ContentHash::compute_sha256(b"aaaaaaaaaa"),
            edits: vec![
                TextEdit {
                    range: range(0, 5),
                    new_text: "X".to_string(),
                },
                TextEdit {
                    range: range(3, 8),
                    new_text: "Y".to_string(),
                },
            ],
        }],
    };
    let result = executor.execute(batch).await;
    assert!(matches!(
        result,
        Err(MutationError::OverlappingEdits { .. })
    ));
    assert_eq!(fs::read(dir.join("edit.rs"))?, b"aaaaaaaaaa");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn delete_file_succeeds_and_verifies_absence() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("gone.rs"), b"to be deleted");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::DeleteFile {
            path: workspace_path("gone.rs"),
            expected_precondition_hash: ContentHash::compute_sha256(b"to be deleted"),
        }],
    };
    executor.execute(batch).await?;
    assert!(!dir.join("gone.rs").exists());
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn move_file_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("from.rs"), b"moved content");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::MoveFile {
            source: workspace_path("from.rs"),
            destination: workspace_path("to.rs"),
            expected_source_hash: ContentHash::compute_sha256(b"moved content"),
        }],
    };
    executor.execute(batch).await?;
    assert!(!dir.join("from.rs").exists());
    assert_eq!(fs::read(dir.join("to.rs"))?, b"moved content");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn move_collision_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("from.rs"), b"source");
    let _ = fs::write(dir.join("to.rs"), b"already occupied");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::MoveFile {
            source: workspace_path("from.rs"),
            destination: workspace_path("to.rs"),
            expected_source_hash: ContentHash::compute_sha256(b"source"),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::MoveCollision {
            destination: workspace_path("to.rs")
        })
    );
    assert_eq!(fs::read(dir.join("from.rs"))?, b"source");
    assert_eq!(fs::read(dir.join("to.rs"))?, b"already occupied");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn multi_file_batch_commits_all_in_deterministic_order()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("replace.rs"), b"before");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![
            Mutation::CreateFile {
                path: workspace_path("first.rs"),
                content: b"first".to_vec(),
            },
            Mutation::ReplaceFile {
                path: workspace_path("replace.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"before"),
                content: b"after".to_vec(),
            },
            Mutation::CreateFile {
                path: workspace_path("third.rs"),
                content: b"third".to_vec(),
            },
        ],
    };
    let outcome = executor.execute(batch).await?;
    assert_eq!(outcome.results.len(), 3);
    assert_eq!(fs::read(dir.join("first.rs"))?, b"first");
    assert_eq!(fs::read(dir.join("replace.rs"))?, b"after");
    assert_eq!(fs::read(dir.join("third.rs"))?, b"third");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn multifile_preflight_is_all_or_none() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let executor = MutationExecutor::new(open_root(&dir)?);
    // Second mutation targets a file that does not exist -- the whole
    // batch must fail PREPARE with zero live writes, including for
    // the first, individually-valid CreateFile.
    let batch = MutationBatch {
        mutations: vec![
            Mutation::CreateFile {
                path: workspace_path("would-be-created.rs"),
                content: b"content".to_vec(),
            },
            Mutation::DeleteFile {
                path: workspace_path("does-not-exist.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"anything"),
            },
        ],
    };
    let result = executor.execute(batch).await;
    assert!(matches!(result, Err(MutationError::TargetNotFound { .. })));
    assert!(
        !dir.join("would-be-created.rs").exists(),
        "MULTIFILE_PREFLIGHT_ALL_OR_NONE: the first mutation must not have been \
         committed just because a later mutation in the same batch was valid on its own"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn outside_workspace_target_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::CreateFile {
            path: workspace_path("../escape.rs"),
            content: b"content".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert!(matches!(
        result,
        Err(MutationError::ConfinementViolation { .. })
    ));
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_escape_target_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let dir = temp_workspace();
    let outside = temp_workspace();
    let link = dir.join("escape_dir");
    let _ = symlink(&outside, &link);
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::CreateFile {
            path: workspace_path("escape_dir/new.rs"),
            content: b"content".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert!(matches!(
        result,
        Err(MutationError::ConfinementViolation { .. })
    ));
    assert!(!outside.join("new.rs").exists());
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&outside);
    Ok(())
}

#[tokio::test]
async fn batch_resource_limits_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let limits = MutationLimits {
        max_mutation_count: 1,
        ..MutationLimits::default()
    };
    let executor = MutationExecutor::with_limits(open_root(&dir)?, limits);
    let batch = MutationBatch {
        mutations: vec![
            Mutation::CreateFile {
                path: workspace_path("a.rs"),
                content: b"a".to_vec(),
            },
            Mutation::CreateFile {
                path: workspace_path("b.rs"),
                content: b"b".to_vec(),
            },
        ],
    };
    let result = executor.execute(batch).await;
    assert_eq!(result, Err(MutationError::ResourceLimitExceeded));
    assert!(!dir.join("a.rs").exists());
    assert!(!dir.join("b.rs").exists());
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

fn stray_staging_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".corulix-stage-"))
        })
        .collect()
}

#[tokio::test]
async fn no_staging_files_remain_after_a_successful_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("existing.rs"), b"old");
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: workspace_path("existing.rs"),
            expected_precondition_hash: ContentHash::compute_sha256(b"old"),
            content: b"new".to_vec(),
        }],
    };
    executor.execute(batch).await?;
    assert_eq!(
        stray_staging_files(&dir),
        Vec::<PathBuf>::new(),
        "JOURNAL_CLEANUP: no ephemeral staging file must survive a successful commit"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn staging_bound_exceeded_cleans_up_already_staged_files_and_writes_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let _ = fs::write(dir.join("first.rs"), b"first-old");
    let _ = fs::write(dir.join("second.rs"), b"second-old");
    let limits = MutationLimits {
        max_total_staged_bytes: 5,
        ..MutationLimits::default()
    };
    let executor = MutationExecutor::with_limits(open_root(&dir)?, limits);
    let batch = MutationBatch {
        mutations: vec![
            Mutation::ReplaceFile {
                path: workspace_path("first.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"first-old"),
                content: b"1234".to_vec(),
            },
            Mutation::ReplaceFile {
                path: workspace_path("second.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"second-old"),
                content: b"5678".to_vec(),
            },
        ],
    };
    let result = executor.execute(batch).await;
    assert_eq!(result, Err(MutationError::ResourceLimitExceeded));
    assert_eq!(fs::read(dir.join("first.rs"))?, b"first-old");
    assert_eq!(fs::read(dir.join("second.rs"))?, b"second-old");
    assert_eq!(
        stray_staging_files(&dir),
        Vec::<PathBuf>::new(),
        "JOURNAL_CLEANUP: a staging-bound failure must clean up whatever was already staged"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn commit_failure_after_one_item_recovers_it() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    let executor = MutationExecutor::with_failure_injection(
        open_root(&dir)?,
        FailureInjectionPoint::AfterCommitAt(0),
    );
    let batch = MutationBatch {
        mutations: vec![
            Mutation::CreateFile {
                path: workspace_path("first.rs"),
                content: b"first".to_vec(),
            },
            Mutation::CreateFile {
                path: workspace_path("second.rs"),
                content: b"second".to_vec(),
            },
        ],
    };
    let result = executor.execute(batch).await;
    assert!(matches!(result, Err(MutationError::CommitFailed { .. })));
    assert!(
        !dir.join("first.rs").exists(),
        "PARTIAL_COMMIT_RECOVERY: the already-committed first item must be undone"
    );
    assert!(!dir.join("second.rs").exists());
    assert!(!executor.is_locked());
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn verification_failure_after_commit_also_recovers() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = temp_workspace();
    let executor = MutationExecutor::with_failure_injection(
        open_root(&dir)?,
        FailureInjectionPoint::DuringVerificationAt(0),
    );
    let batch = MutationBatch {
        mutations: vec![Mutation::CreateFile {
            path: workspace_path("verify-fail.rs"),
            content: b"content".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert!(matches!(
        result,
        Err(MutationError::VerificationFailed { .. })
    ));
    assert!(!dir.join("verify-fail.rs").exists());
    assert!(!executor.is_locked());
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn recovery_failure_locks_further_writes() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    // `DuringRecovery` forces a commit failure right after the first
    // item commits (so `recover()` is actually invoked) and then
    // forces every undo attempt during that recovery to fail.
    let recovery_executor = MutationExecutor::with_failure_injection(
        open_root(&dir)?,
        FailureInjectionPoint::DuringRecovery,
    );
    let batch = MutationBatch {
        mutations: vec![
            Mutation::CreateFile {
                path: workspace_path("locked-1.rs"),
                content: b"one".to_vec(),
            },
            Mutation::CreateFile {
                path: workspace_path("locked-2.rs"),
                content: b"two".to_vec(),
            },
        ],
    };

    let result = recovery_executor.execute(batch).await;
    assert!(matches!(
        result,
        Err(MutationError::RecoveryRequired { .. })
    ));
    assert!(
        recovery_executor.is_locked(),
        "FURTHER_MUTATION_WRITES_DENIED: the executor must be locked after a failed recovery"
    );

    let followup = recovery_executor
        .execute(MutationBatch {
            mutations: vec![Mutation::CreateFile {
                path: workspace_path("should-not-be-written.rs"),
                content: b"denied".to_vec(),
            }],
        })
        .await;
    assert_eq!(followup, Err(MutationError::ExecutorLocked));
    assert!(!dir.join("should-not-be-written.rs").exists());
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

// -----------------------------------------------------------------
// P-M08-R1: commit-time precondition revalidation (TOCTOU closure).
// Every test below uses `with_precommit_hook` -- a real, deterministic
// synchronization seam (`cfg(test)`-only, zero production cost) fired
// exactly at the PREPARE-to-COMMIT boundary -- never timing/races.
// -----------------------------------------------------------------

#[tokio::test]
async fn replace_changed_after_prepare_is_rejected_at_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    fs::write(dir.join("target.rs"), b"original")?;
    let expected_hash = ContentHash::compute_sha256(b"original");
    let dir_for_hook = dir.clone();
    let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
        // Simulate a real external writer landing exactly in the
        // PREPARE-to-COMMIT window.
        let _ = fs::write(
            dir_for_hook.join("target.rs"),
            b"externally changed after prepare",
        );
    });
    let batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: workspace_path("target.rs"),
            expected_precondition_hash: expected_hash,
            content: b"agent's edit".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::StalePreconditionHash {
            path: workspace_path("target.rs")
        })
    );
    assert_eq!(
        fs::read(dir.join("target.rs"))?,
        b"externally changed after prepare",
        "the external writer's newer bytes must survive -- never silently overwritten"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn apply_text_edits_changed_after_prepare_is_rejected_at_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    fs::write(dir.join("target.rs"), b"fn target() {}")?;
    let expected_hash = ContentHash::compute_sha256(b"fn target() {}");
    let dir_for_hook = dir.clone();
    let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
        let _ = fs::write(
            dir_for_hook.join("target.rs"),
            b"fn changed_externally() {}",
        );
    });
    let batch = MutationBatch {
        mutations: vec![Mutation::ApplyTextEdits {
            path: workspace_path("target.rs"),
            expected_precondition_hash: expected_hash,
            edits: vec![TextEdit {
                range: range(3, 9),
                new_text: "renamed".to_string(),
            }],
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::StalePreconditionHash {
            path: workspace_path("target.rs")
        })
    );
    assert_eq!(
        fs::read(dir.join("target.rs"))?,
        b"fn changed_externally() {}"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn delete_changed_after_prepare_is_rejected_at_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    fs::write(dir.join("target.rs"), b"original")?;
    let expected_hash = ContentHash::compute_sha256(b"original");
    let dir_for_hook = dir.clone();
    let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
        let _ = fs::write(
            dir_for_hook.join("target.rs"),
            b"externally changed, must not be deleted",
        );
    });
    let batch = MutationBatch {
        mutations: vec![Mutation::DeleteFile {
            path: workspace_path("target.rs"),
            expected_precondition_hash: expected_hash,
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::StalePreconditionHash {
            path: workspace_path("target.rs")
        })
    );
    assert_eq!(
        fs::read(dir.join("target.rs"))?,
        b"externally changed, must not be deleted",
        "a target that changed after PREPARE must never be deleted based on stale bytes"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn move_source_changed_after_prepare_is_rejected_at_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    fs::write(dir.join("from.rs"), b"original source")?;
    let dir_for_hook = dir.clone();
    let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
        let _ = fs::write(dir_for_hook.join("from.rs"), b"externally changed source");
    });
    let batch = MutationBatch {
        mutations: vec![Mutation::MoveFile {
            source: workspace_path("from.rs"),
            destination: workspace_path("to.rs"),
            expected_source_hash: ContentHash::compute_sha256(b"original source"),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::StalePreconditionHash {
            path: workspace_path("from.rs")
        })
    );
    assert_eq!(fs::read(dir.join("from.rs"))?, b"externally changed source");
    assert!(
        !dir.join("to.rs").exists(),
        "a stale-source move must never create the destination"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn move_destination_appearing_after_prepare_is_rejected_at_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    fs::write(dir.join("from.rs"), b"source content")?;
    let dir_for_hook = dir.clone();
    let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
        // A destination that PREPARE proved absent appears just before
        // COMMIT -- ordinary `rename` semantics would silently replace
        // it; this must instead fail closed and leave it untouched.
        let _ = fs::write(dir_for_hook.join("to.rs"), b"appeared just before commit");
    });
    let batch = MutationBatch {
        mutations: vec![Mutation::MoveFile {
            source: workspace_path("from.rs"),
            destination: workspace_path("to.rs"),
            expected_source_hash: ContentHash::compute_sha256(b"source content"),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::MoveCollision {
            destination: workspace_path("to.rs")
        })
    );
    assert_eq!(
        fs::read(dir.join("from.rs"))?,
        b"source content",
        "the rejected move must not have touched the source either"
    );
    assert_eq!(
        fs::read(dir.join("to.rs"))?,
        b"appeared just before commit",
        "the destination that appeared must survive untouched, never silently replaced"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn original_wide_toctou_batch_is_now_rejected_stale() -> Result<(), Box<dyn std::error::Error>>
{
    // The permanent, deterministic replacement for this defect's
    // original discovery reproduction (which used a large multi-item
    // batch plus a timing-based external race, per the historical
    // qualification harness -- preserved as evidence, never rewritten,
    // outside this product repository). Same semantic shape (a batch
    // whose other item's own PREPARE/STAGE work widens the real window
    // for item 0), but now deterministic via the precommit hook.
    //
    // NOTE (M09-P5 clarification, Section 2 of the P5 mandate): this is
    // M08's own historical CONTENT-STATE TOCTOU regression (a stale
    // precondition-hash rejection), NOT the M09 Q22 PATH-AUTHORITY
    // parent-swap exploit -- see `true_m09_q22_parent_swap_after_stage_
    // does_not_escape` below for that one. Preserved here unweakened and
    // unmerged with the Q22 test, per the mandate's own instruction never
    // to substitute one for the other.
    let dir = temp_workspace();
    fs::write(dir.join("target.rs"), b"original")?;
    let dir_for_hook = dir.clone();
    let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |index| {
        if index == 0 {
            let _ = fs::write(
                dir_for_hook.join("target.rs"),
                b"EXTERNAL WRITE DURING THE WINDOW",
            );
        }
    });
    let batch = MutationBatch {
        mutations: vec![
            Mutation::ReplaceFile {
                path: workspace_path("target.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"original"),
                content: b"agent's legitimate edit, based on the ORIGINAL content".to_vec(),
            },
            Mutation::CreateFile {
                path: workspace_path("filler.rs"),
                content: b"filler".to_vec(),
            },
        ],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::StalePreconditionHash {
            path: workspace_path("target.rs")
        })
    );
    assert_eq!(
        fs::read(dir.join("target.rs"))?,
        b"EXTERNAL WRITE DURING THE WINDOW"
    );
    assert!(
        !dir.join("filler.rs").exists(),
        "the whole batch must fail together -- the filler item must not have committed either"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn malformed_precondition_hash_is_rejected_without_touching_filesystem()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    fs::write(dir.join("target.rs"), b"original")?;
    let executor = MutationExecutor::new(open_root(&dir)?);
    let malformed = ContentHash {
        algorithm: wht_corulix_core::ContentHashAlgorithm::Sha256,
        digest_hex: "not-a-valid-hex-digest-at-all".to_string(),
    };
    let batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: workspace_path("target.rs"),
            expected_precondition_hash: malformed,
            content: b"should never land".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::MalformedPreconditionHash {
            path: workspace_path("target.rs")
        })
    );
    assert_eq!(fs::read(dir.join("target.rs"))?, b"original");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn well_formed_but_wrong_hash_still_reports_stale_not_malformed()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    fs::write(dir.join("target.rs"), b"original")?;
    let executor = MutationExecutor::new(open_root(&dir)?);
    // Well-formed (64 lowercase hex chars) but simply does not match
    // "original"'s real digest -- must stay a stale-precondition
    // rejection, never conflated with the malformed-input case.
    let wrong_but_well_formed = ContentHash::compute_sha256(b"a completely different baseline");
    let batch = MutationBatch {
        mutations: vec![Mutation::ReplaceFile {
            path: workspace_path("target.rs"),
            expected_precondition_hash: wrong_but_well_formed,
            content: b"should never land".to_vec(),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::StalePreconditionHash {
            path: workspace_path("target.rs")
        })
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn missing_target_reports_target_not_found_not_confinement_violation()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_workspace();
    // Never created -- a lexically-safe, in-workspace path whose leaf
    // simply does not exist (its parent, the workspace root itself,
    // genuinely does).
    let executor = MutationExecutor::new(open_root(&dir)?);
    let batch = MutationBatch {
        mutations: vec![Mutation::DeleteFile {
            path: workspace_path("never-existed.rs"),
            expected_precondition_hash: ContentHash::compute_sha256(b"anything"),
        }],
    };
    let result = executor.execute(batch).await;
    assert_eq!(
        result,
        Err(MutationError::TargetNotFound {
            path: workspace_path("never-existed.rs")
        }),
        "a lexically-safe, merely-absent target must report TargetNotFound, never the \
         security-flavored ConfinementViolation"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

// =====================================================================
// M09-P5: cross-crate capability acquisition, TRUE Q22, and every
// parent/root/nested-ancestor swap variant. Unix-only: capability
// migration is Unix-scoped (P9 owns Windows).
// =====================================================================

#[cfg(unix)]
mod p5_namespace_authority {
    use super::*;
    use std::os::unix::fs::symlink;

    /// M09 Section 20: the TRUE, historical path-authority parent-swap
    /// exploit -- NOT M08's content-state TOCTOU (see
    /// `original_wide_toctou_batch_is_now_rejected_stale` above, which is a
    /// deliberately distinct, unmodified permanent test). PREPARE
    /// authorizes a `ReplaceFile` inside `a/`; STAGE creates the ephemeral
    /// sibling inside the SAME pinned `a` directory object; the attacker
    /// then renames `a` aside and symlinks the OLD `a` pathname to an
    /// outside directory, strictly between STAGE and COMMIT (via the
    /// precommit hook). Before P5, COMMIT re-walked the raw pathname and
    /// could land outside; after P5, COMMIT acts only on the fd captured
    /// during PREPARE/STAGE, so the write lands in the ORIGINAL (now
    /// relocated) directory object -- CONFINED, never ESCAPED.
    #[tokio::test]
    async fn true_m09_q22_parent_swap_after_stage_does_not_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::create_dir_all(dir.join("a"))?;
        fs::write(dir.join("a/target.rs"), b"original")?;
        let outside = temp_workspace();
        let a_moved = temp_workspace();
        fs::remove_dir_all(&a_moved)?;

        let dir_for_hook = dir.clone();
        let a_moved_for_hook = a_moved.clone();
        let outside_for_hook = outside.clone();
        let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
            let _ = fs::rename(dir_for_hook.join("a"), &a_moved_for_hook);
            let _ = symlink(&outside_for_hook, dir_for_hook.join("a"));
        });

        let batch = MutationBatch {
            mutations: vec![Mutation::ReplaceFile {
                path: workspace_path("a/target.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"original"),
                content: b"agent's legitimate edit, confined".to_vec(),
            }],
        };
        let result = executor.execute(batch).await;

        assert!(
            !outside.join("target.rs").exists(),
            "M09_ORIGINAL_Q22_OUTSIDE_WRITE_COUNT must be 0 -- ESCAPE detected"
        );
        assert!(result.is_ok(), "expected CONFINED, got {result:?}");
        assert_eq!(
            fs::read(a_moved.join("target.rs"))?,
            b"agent's legitimate edit, confined",
            "the write must land in the ORIGINAL pinned directory object, wherever its \
             pathname now points"
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn text_edit_parent_swap_after_prepare_does_not_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::create_dir_all(dir.join("a"))?;
        fs::write(dir.join("a/target.rs"), b"fn original() {}")?;
        let outside = temp_workspace();
        let a_moved = temp_workspace();
        fs::remove_dir_all(&a_moved)?;

        let dir_for_hook = dir.clone();
        let a_moved_for_hook = a_moved.clone();
        let outside_for_hook = outside.clone();
        let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
            let _ = fs::rename(dir_for_hook.join("a"), &a_moved_for_hook);
            let _ = symlink(&outside_for_hook, dir_for_hook.join("a"));
        });

        let batch = MutationBatch {
            mutations: vec![Mutation::ApplyTextEdits {
                path: workspace_path("a/target.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"fn original() {}"),
                edits: vec![TextEdit {
                    range: range(3, 11),
                    new_text: "renamed".to_string(),
                }],
            }],
        };
        let result = executor.execute(batch).await;

        assert!(!outside.join("target.rs").exists());
        assert!(result.is_ok(), "expected CONFINED, got {result:?}");
        assert_eq!(fs::read(a_moved.join("target.rs"))?, b"fn renamed() {}");

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn delete_parent_swap_after_prepare_does_not_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::create_dir_all(dir.join("a"))?;
        fs::write(dir.join("a/target.rs"), b"original")?;
        let outside = temp_workspace();
        fs::write(outside.join("target.rs"), b"OUTSIDE SENTINEL")?;
        let a_moved = temp_workspace();
        fs::remove_dir_all(&a_moved)?;

        let dir_for_hook = dir.clone();
        let a_moved_for_hook = a_moved.clone();
        let outside_for_hook = outside.clone();
        let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
            let _ = fs::rename(dir_for_hook.join("a"), &a_moved_for_hook);
            let _ = symlink(&outside_for_hook, dir_for_hook.join("a"));
        });

        let batch = MutationBatch {
            mutations: vec![Mutation::DeleteFile {
                path: workspace_path("a/target.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"original"),
            }],
        };
        let result = executor.execute(batch).await;

        assert!(result.is_ok(), "expected CONFINED, got {result:?}");
        assert!(
            outside.join("target.rs").exists(),
            "the outside sentinel file must never be touched"
        );
        assert_eq!(fs::read(outside.join("target.rs"))?, b"OUTSIDE SENTINEL");
        assert!(
            !a_moved.join("target.rs").exists(),
            "the real, pinned target must be gone"
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn move_source_parent_swap_after_prepare_does_not_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::create_dir_all(dir.join("a"))?;
        fs::write(dir.join("a/from.rs"), b"payload")?;
        let outside = temp_workspace();
        let a_moved = temp_workspace();
        fs::remove_dir_all(&a_moved)?;

        let dir_for_hook = dir.clone();
        let a_moved_for_hook = a_moved.clone();
        let outside_for_hook = outside.clone();
        let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
            let _ = fs::rename(dir_for_hook.join("a"), &a_moved_for_hook);
            let _ = symlink(&outside_for_hook, dir_for_hook.join("a"));
        });

        let batch = MutationBatch {
            mutations: vec![Mutation::MoveFile {
                source: workspace_path("a/from.rs"),
                destination: workspace_path("to.rs"),
                expected_source_hash: ContentHash::compute_sha256(b"payload"),
            }],
        };
        let result = executor.execute(batch).await;

        assert!(result.is_ok(), "expected CONFINED, got {result:?}");
        assert!(!outside.join("from.rs").exists());
        assert_eq!(fs::read(dir.join("to.rs"))?, b"payload");

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn move_destination_parent_swap_after_prepare_does_not_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::create_dir_all(dir.join("b"))?;
        fs::write(dir.join("from.rs"), b"payload")?;
        let outside = temp_workspace();
        let b_moved = temp_workspace();
        fs::remove_dir_all(&b_moved)?;

        let dir_for_hook = dir.clone();
        let b_moved_for_hook = b_moved.clone();
        let outside_for_hook = outside.clone();
        let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
            let _ = fs::rename(dir_for_hook.join("b"), &b_moved_for_hook);
            let _ = symlink(&outside_for_hook, dir_for_hook.join("b"));
        });

        let batch = MutationBatch {
            mutations: vec![Mutation::MoveFile {
                source: workspace_path("from.rs"),
                destination: workspace_path("b/to.rs"),
                expected_source_hash: ContentHash::compute_sha256(b"payload"),
            }],
        };
        let result = executor.execute(batch).await;

        assert!(result.is_ok(), "expected CONFINED, got {result:?}");
        assert!(!outside.join("to.rs").exists());
        assert_eq!(fs::read(b_moved.join("to.rs"))?, b"payload");

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&b_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn create_parent_swap_after_prepare_does_not_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::create_dir_all(dir.join("a"))?;
        let outside = temp_workspace();
        let a_moved = temp_workspace();
        fs::remove_dir_all(&a_moved)?;

        let dir_for_hook = dir.clone();
        let a_moved_for_hook = a_moved.clone();
        let outside_for_hook = outside.clone();
        let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
            let _ = fs::rename(dir_for_hook.join("a"), &a_moved_for_hook);
            let _ = symlink(&outside_for_hook, dir_for_hook.join("a"));
        });

        let batch = MutationBatch {
            mutations: vec![Mutation::CreateFile {
                path: workspace_path("a/new.rs"),
                content: b"created payload".to_vec(),
            }],
        };
        let result = executor.execute(batch).await;

        assert!(!outside.join("new.rs").exists());
        assert!(result.is_ok(), "expected CONFINED, got {result:?}");
        assert_eq!(fs::read(a_moved.join("new.rs"))?, b"created payload");

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn nested_ancestor_swap_after_prepare_does_not_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::create_dir_all(dir.join("a/b"))?;
        fs::write(dir.join("a/b/target.rs"), b"original")?;
        let outside = temp_workspace();
        let a_moved = temp_workspace();
        fs::remove_dir_all(&a_moved)?;

        let dir_for_hook = dir.clone();
        let a_moved_for_hook = a_moved.clone();
        let outside_for_hook = outside.clone();
        let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
            // Swap the OUTER ancestor `a` (not the immediate parent `a/b`).
            let _ = fs::rename(dir_for_hook.join("a"), &a_moved_for_hook);
            let _ = symlink(&outside_for_hook, dir_for_hook.join("a"));
        });

        let batch = MutationBatch {
            mutations: vec![Mutation::ReplaceFile {
                path: workspace_path("a/b/target.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"original"),
                content: b"confined nested edit".to_vec(),
            }],
        };
        let result = executor.execute(batch).await;

        assert!(!outside.join("target.rs").exists());
        assert!(result.is_ok(), "expected CONFINED, got {result:?}");
        assert_eq!(
            fs::read(a_moved.join("b/target.rs"))?,
            b"confined nested edit"
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&a_moved);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn root_replacement_after_prepare_does_not_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::write(dir.join("target.rs"), b"original")?;
        let dir_moved = temp_workspace();
        fs::remove_dir_all(&dir_moved)?;

        let dir_for_hook = dir.clone();
        let dir_moved_for_hook = dir_moved.clone();
        let executor = MutationExecutor::with_precommit_hook(open_root(&dir)?, move |_index| {
            // Move the ENTIRE workspace root aside and put an impostor
            // directory at its old pathname.
            let _ = fs::rename(&dir_for_hook, &dir_moved_for_hook);
            let _ = fs::create_dir_all(&dir_for_hook);
            let _ = fs::write(dir_for_hook.join("target.rs"), b"IMPOSTOR");
        });

        let batch = MutationBatch {
            mutations: vec![Mutation::ReplaceFile {
                path: workspace_path("target.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"original"),
                content: b"confined root-survival edit".to_vec(),
            }],
        };
        let result = executor.execute(batch).await;

        assert!(result.is_ok(), "expected CONFINED, got {result:?}");
        assert_eq!(
            fs::read(dir_moved.join("target.rs"))?,
            b"confined root-survival edit",
            "must write to the ORIGINAL pinned root object, never the impostor"
        );
        assert_eq!(
            fs::read(dir.join("target.rs"))?,
            b"IMPOSTOR",
            "the impostor directory placed at the old root pathname must be untouched"
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir_moved);
        Ok(())
    }

    // -- final-symlink mutation contract (Section 24) --------------------

    #[tokio::test]
    async fn replace_final_internal_symlink_target_succeeds()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::write(dir.join("real.rs"), b"original")?;
        symlink("real.rs", dir.join("link.rs"))?;
        let executor = MutationExecutor::new(open_root(&dir)?);
        let batch = MutationBatch {
            mutations: vec![Mutation::ReplaceFile {
                path: workspace_path("link.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"original"),
                content: b"via internal symlink".to_vec(),
            }],
        };
        executor.execute(batch).await?;
        assert_eq!(fs::read(dir.join("real.rs"))?, b"via internal symlink");
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn replace_final_outside_symlink_target_is_denied()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        let outside = temp_workspace();
        fs::write(outside.join("secret.rs"), b"SECRET")?;
        symlink(outside.join("secret.rs"), dir.join("link.rs"))?;
        let executor = MutationExecutor::new(open_root(&dir)?);
        let batch = MutationBatch {
            mutations: vec![Mutation::ReplaceFile {
                path: workspace_path("link.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"SECRET"),
                content: b"should never land".to_vec(),
            }],
        };
        let result = executor.execute(batch).await;
        assert!(result.is_err());
        assert_eq!(fs::read(outside.join("secret.rs"))?, b"SECRET");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn delete_final_internal_symlink_target_succeeds()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::write(dir.join("real.rs"), b"content")?;
        symlink("real.rs", dir.join("link.rs"))?;
        let executor = MutationExecutor::new(open_root(&dir)?);
        let batch = MutationBatch {
            mutations: vec![Mutation::DeleteFile {
                path: workspace_path("link.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"content"),
            }],
        };
        executor.execute(batch).await?;
        assert!(!dir.join("real.rs").exists());
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn delete_final_outside_symlink_target_is_denied()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        let outside = temp_workspace();
        fs::write(outside.join("secret.rs"), b"SECRET")?;
        symlink(outside.join("secret.rs"), dir.join("link.rs"))?;
        let executor = MutationExecutor::new(open_root(&dir)?);
        let batch = MutationBatch {
            mutations: vec![Mutation::DeleteFile {
                path: workspace_path("link.rs"),
                expected_precondition_hash: ContentHash::compute_sha256(b"SECRET"),
            }],
        };
        let result = executor.execute(batch).await;
        assert!(result.is_err());
        assert!(outside.join("secret.rs").exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn move_source_final_internal_symlink_target_succeeds()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::write(dir.join("real.rs"), b"payload")?;
        symlink("real.rs", dir.join("link.rs"))?;
        let executor = MutationExecutor::new(open_root(&dir)?);
        let batch = MutationBatch {
            mutations: vec![Mutation::MoveFile {
                source: workspace_path("link.rs"),
                destination: workspace_path("moved.rs"),
                expected_source_hash: ContentHash::compute_sha256(b"payload"),
            }],
        };
        executor.execute(batch).await?;
        assert_eq!(fs::read(dir.join("moved.rs"))?, b"payload");
        assert!(!dir.join("real.rs").exists());
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn move_source_final_outside_symlink_target_is_denied()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        let outside = temp_workspace();
        fs::write(outside.join("secret.rs"), b"SECRET")?;
        symlink(outside.join("secret.rs"), dir.join("link.rs"))?;
        let executor = MutationExecutor::new(open_root(&dir)?);
        let batch = MutationBatch {
            mutations: vec![Mutation::MoveFile {
                source: workspace_path("link.rs"),
                destination: workspace_path("moved.rs"),
                expected_source_hash: ContentHash::compute_sha256(b"SECRET"),
            }],
        };
        let result = executor.execute(batch).await;
        assert!(result.is_err());
        assert!(!dir.join("moved.rs").exists());
        assert_eq!(fs::read(outside.join("secret.rs"))?, b"SECRET");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    // -- new-target collision (Section 25) -------------------------------

    #[tokio::test]
    async fn create_target_outside_symlink_collision_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        let outside = temp_workspace();
        symlink(&outside, dir.join("link.rs"))?;
        let executor = MutationExecutor::new(open_root(&dir)?);
        let batch = MutationBatch {
            mutations: vec![Mutation::CreateFile {
                path: workspace_path("link.rs"),
                content: b"should never land".to_vec(),
            }],
        };
        let result = executor.execute(batch).await;
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    #[tokio::test]
    async fn move_destination_outside_symlink_collision_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        fs::write(dir.join("from.rs"), b"payload")?;
        let outside = temp_workspace();
        symlink(&outside, dir.join("link.rs"))?;
        let executor = MutationExecutor::new(open_root(&dir)?);
        let batch = MutationBatch {
            mutations: vec![Mutation::MoveFile {
                source: workspace_path("from.rs"),
                destination: workspace_path("link.rs"),
                expected_source_hash: ContentHash::compute_sha256(b"payload"),
            }],
        };
        let result = executor.execute(batch).await;
        assert!(result.is_err());
        assert_eq!(fs::read(dir.join("from.rs"))?, b"payload");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        Ok(())
    }

    // -- cross-workspace move (Section 15) -------------------------------

    #[tokio::test]
    async fn cross_workspace_move_is_denied_with_zero_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir_a = temp_workspace();
        let dir_b = temp_workspace();
        fs::write(dir_a.join("from.rs"), b"payload")?;

        // `MutationExecutor` is bound to exactly one `WorkspaceRoot`
        // (`dir_a`), so a "cross-workspace" destination is expressed as a
        // destination path that would only resolve inside `dir_b` -- the
        // executor has no way to reach `dir_b` at all, so this exercises
        // the ordinary confinement path, not `PinnedTarget::rename_into`'s
        // own root-identity check directly (that primitive's dedicated
        // proof already lives in `wht_corulix_workspace`'s own P3 test
        // suite, `cross_workspace_rename_is_denied`). This test's own
        // contribution is confirming `MutationExecutor` itself never
        // constructs two capabilities from different roots in the first
        // place, and that a nonsensical destination fails closed with
        // zero mutation.
        let executor = MutationExecutor::new(open_root(&dir_a)?);
        let batch = MutationBatch {
            mutations: vec![Mutation::MoveFile {
                source: workspace_path("from.rs"),
                destination: workspace_path("../outside-of-a/to.rs"),
                expected_source_hash: ContentHash::compute_sha256(b"payload"),
            }],
        };
        let result = executor.execute(batch).await;
        assert!(matches!(
            result,
            Err(MutationError::ConfinementViolation { .. })
        ));
        assert_eq!(fs::read(dir_a.join("from.rs"))?, b"payload");
        assert!(!dir_b.join("to.rs").exists());

        let _ = fs::remove_dir_all(&dir_a);
        let _ = fs::remove_dir_all(&dir_b);
        Ok(())
    }

    // -- resource lifetime / fd retention (Section 29) -------------------

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|entries| entries.filter_map(Result::ok).count())
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn mutation_executor_fd_retention_across_repeated_cycles()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_workspace();
        let executor = MutationExecutor::new(open_root(&dir)?);
        let before = open_fd_count();

        for index in 0..50 {
            let name = format!("cycle-{index}.rs");
            executor
                .execute(MutationBatch {
                    mutations: vec![Mutation::CreateFile {
                        path: workspace_path(&name),
                        content: b"cycle".to_vec(),
                    }],
                })
                .await?;
            executor
                .execute(MutationBatch {
                    mutations: vec![Mutation::DeleteFile {
                        path: workspace_path(&name),
                        expected_precondition_hash: ContentHash::compute_sha256(b"cycle"),
                    }],
                })
                .await?;
        }

        let after = open_fd_count();
        assert!(
            after <= before + 4,
            "fd count grew from {before} to {after} after 50 create/delete cycles -- possible leak"
        );
        assert_eq!(
            stray_staging_files(&dir),
            Vec::<PathBuf>::new(),
            "no ephemeral stage file may survive 50 successful cycles"
        );

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
