// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P16 formatter-governance closure: real, end-to-end proof that Biome is
//! the governed `format_preview` formatting authority for TypeScript, TSX,
//! and JavaScript -- the last remaining "implemented but zero production
//! callers" gap this phase disclosed (CHANGELOG.md Phase 16 section G'').
//!
//! Everything here drives the real production path against the real,
//! network-provisioned `biome@2.5.11` binary shared with
//! `real_p16_typescript_production_routing_e2e.rs`'s own `managed_toolchain_root()`
//! convention:
//!
//! ```text
//! source bytes -> confined read + precondition hash
//!              -> wht_corulix_formatter::managed::resolve_formatter (CORULIX_MANAGED, Biome)
//!              -> wht_corulix_tooling::ManagedProcess (stdin/stdout, Rule G)
//!              -> verified formatted bytes
//!              -> preview (never written)
//! ```
//!
//! `P16_FORMATTER_LIVE_INPLACE_WRITE_COUNT=0` is guaranteed by construction,
//! not by cleanup: Biome's `format` subcommand is invoked with
//! `--stdin-file-path` and no positional path, so Biome's own process is
//! never given a filesystem path it could write to (see
//! `wht_corulix_formatter::profile::FormatterProfile::biome_typescript`/
//! `biome_tsx`/`biome_javascript`).
//!
//! If Biome is not provisioned and provisioning fails (no network), every
//! test reports and exits early with
//! `P16_TS_JS_FORMAT_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED` rather
//! than substituting a mock.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, ContentHash, WorkspacePath, WorkspaceRootId};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

#[derive(Debug)]
struct TestFailure(String);
impl fmt::Display for TestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl Error for TestFailure {}
fn fail(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(TestFailure(message.into()))
}

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

/// Serializes every test in this file against the real, shared managed
/// root -- mirrors `real_p16_typescript_production_routing_e2e.rs`'s own
/// `REAL_P16_TS_VALIDATE_LOCK` precedent.
static REAL_P16_TS_FORMAT_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn session_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_P16_TS_FORMAT_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

async fn ensure_biome_provisioned(root: &Path) -> bool {
    let manifest = wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64;
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

macro_rules! require_biome {
    ($root:expr) => {
        if !ensure_biome_provisioned($root).await {
            eprintln!(
                "P16_TS_JS_FORMAT_E2E=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED (biome unavailable)"
            );
            return Ok(());
        }
    };
}

fn resolved_biome_path(root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let manifest = wht_corulix_formatter::managed_toolchain::BIOME_LINUX_X64;
    let (state, path) = provisioning::resolve_owned_managed_component(root, &manifest);
    if state != ManagedComponentState::Available {
        return Err(fail(
            "biome must be Available for this test to prove anything",
        ));
    }
    path.ok_or_else(|| fail("an Available biome component must carry a resolved path"))
}

/// A minimal envelope: the `CORULIX_MANAGED` Biome path never reads
/// `EffectiveConfig` at all (see `wht_corulix_formatter::managed::resolve_formatter`),
/// so this grants nothing -- proving the managed-first path opens without
/// any `HOST_ONLY` authority.
fn empty_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

/// What the real, independently-invoked Biome binary produces for `source`
/// under `stdin_file_path` -- a test oracle deliberately independent of the
/// production path (comparing Corulix's governed result against itself
/// would be circular).
fn canonical_biome_format(
    biome_executable: &Path,
    stdin_file_path: &str,
    source: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut child = Command::new(biome_executable)
        .arg("format")
        .arg(format!("--stdin-file-path={stdin_file_path}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| fail("no stdin on the oracle biome process"))?
        .write_all(source.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(fail(format!(
            "the oracle biome invocation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

struct Fixture {
    root_dir: PathBuf,
}

impl Fixture {
    fn new(label: &str, file_name: &str, contents: &str) -> Self {
        let root_dir =
            std::env::temp_dir().join(format!("corulix-p16-ts-js-format-{label}-{}", stamp()));
        let _ = fs::create_dir_all(&root_dir);
        let _ = fs::write(root_dir.join(file_name), contents);
        Self { root_dir }
    }

    fn root(&self) -> Result<WorkspaceRoot, Box<dyn Error>> {
        Ok(WorkspaceRoot::open(&self.root_dir)?)
    }

    fn target(&self, file_name: &str) -> WorkspacePath {
        WorkspacePath {
            root: WorkspaceRootId(0),
            relative_path: file_name.to_string(),
        }
    }

    fn live_bytes(&self, file_name: &str) -> Vec<u8> {
        fs::read(self.root_dir.join(file_name)).unwrap_or_default()
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.root_dir);
    }
}

/// One (language, file name, stdin extension, unformatted source) case
/// shared by the three per-language tests below.
struct Case {
    label: &'static str,
    file_name: &'static str,
    stdin_file_path: &'static str,
    unformatted: &'static str,
}

const CASES: &[Case] = &[
    Case {
        label: "ts",
        file_name: "main.ts",
        stdin_file_path: "stdin.ts",
        unformatted: "const   x:number=1\nconsole.log(x)\n",
    },
    Case {
        label: "tsx",
        file_name: "main.tsx",
        stdin_file_path: "stdin.tsx",
        unformatted: "const App=()=>{return <div>{1+1}</div>}\n",
    },
    Case {
        label: "js",
        file_name: "main.js",
        stdin_file_path: "stdin.js",
        unformatted: "const   x=1\nconsole.log(x)\n",
    },
];

/// `P16_REAL_TS_FORMAT_PREVIEW_E2E`, `P16_REAL_TSX_FORMAT_PREVIEW_E2E`,
/// `P16_REAL_JS_FORMAT_PREVIEW_E2E`: badly-formatted TS/TSX/JS previews as
/// `WouldFormat`, the previewed output hash equals the hash of the real
/// Biome binary's own canonical output (invoked independently as an
/// oracle), and the live file is byte-identical afterwards.
#[tokio::test]
async fn real_ts_js_format_preview_e2e_reports_canonical_biome_output_without_writing()
-> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    require_biome!(&managed_root);
    let biome_executable = resolved_biome_path(&managed_root)?;

    for case in CASES {
        let fixture = Fixture::new(case.label, case.file_name, case.unformatted);
        let before = fixture.live_bytes(case.file_name);

        let result = wht_corulix_formatter::format_preview_at(
            &managed_root,
            &empty_config(),
            fixture.root()?,
            fixture.target(case.file_name),
            wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
            &CancellationToken::new(),
        )
        .await
        .map_err(|error| fail(format!("[{}] biome preview failed: {error:?}", case.label)))?;

        if result.status != wht_corulix_formatter::FormatStatus::WouldFormat {
            return Err(fail(format!(
                "[{}] expected WouldFormat for badly formatted source, got {:?} (reason {:?})",
                case.label, result.status, result.reason
            )));
        }
        if !result.changed {
            return Err(fail(format!(
                "[{}] WouldFormat must report changed == true",
                case.label
            )));
        }
        if !result.provider_used_managed {
            return Err(fail(format!(
                "[{}] Biome must resolve via CORULIX_MANAGED",
                case.label
            )));
        }

        let canonical =
            canonical_biome_format(&biome_executable, case.stdin_file_path, case.unformatted)?;
        let expected_hash = ContentHash::compute_sha256(&canonical);
        let Some(observed_hash) = result.output_hash.clone() else {
            return Err(fail(format!(
                "[{}] WouldFormat must carry an output hash",
                case.label
            )));
        };
        if observed_hash != expected_hash {
            return Err(fail(format!(
                "[{}] the governed preview's output hash does not match real Biome's canonical output",
                case.label
            )));
        }

        if fixture.live_bytes(case.file_name) != before {
            return Err(fail(format!(
                "[{}] format_preview mutated live source -- P16_FORMATTER_LIVE_INPLACE_WRITE_COUNT must be 0",
                case.label
            )));
        }

        eprintln!(
            "P16_REAL_{}_FORMAT_PREVIEW_E2E=PASS",
            case.label.to_uppercase()
        );
        fixture.cleanup();
    }

    Ok(())
}

/// Already-canonical TS/TSX/JS reports `Unchanged` through the governed
/// path, and Biome is idempotent on its own output (verified via the
/// independent oracle).
#[tokio::test]
async fn real_ts_js_format_idempotency_e2e() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    require_biome!(&managed_root);
    let biome_executable = resolved_biome_path(&managed_root)?;

    for case in CASES {
        let canonical =
            canonical_biome_format(&biome_executable, case.stdin_file_path, case.unformatted)?;
        let canonical_text = String::from_utf8(canonical.clone())
            .map_err(|_| fail("biome produced non-UTF-8 output"))?;

        let fixture = Fixture::new(
            &format!("{}-idempotent", case.label),
            case.file_name,
            &canonical_text,
        );
        let result = wht_corulix_formatter::format_preview_at(
            &managed_root,
            &empty_config(),
            fixture.root()?,
            fixture.target(case.file_name),
            wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
            &CancellationToken::new(),
        )
        .await
        .map_err(|error| fail(format!("[{}] biome preview failed: {error:?}", case.label)))?;

        if result.status != wht_corulix_formatter::FormatStatus::Unchanged {
            return Err(fail(format!(
                "[{}] already-canonical source must report Unchanged, got {:?}",
                case.label, result.status
            )));
        }
        if result.changed {
            return Err(fail(format!(
                "[{}] Unchanged must report changed == false",
                case.label
            )));
        }

        let second =
            canonical_biome_format(&biome_executable, case.stdin_file_path, &canonical_text)?;
        if second != canonical {
            return Err(fail(format!(
                "[{}] biome is not idempotent on its own output",
                case.label
            )));
        }

        fixture.cleanup();
    }

    Ok(())
}

/// Python is P17's own `ruff format` authority now (not Biome's) -- it must
/// never be silently routed to Biome. Since the M03 Python managed-auxiliary
/// final closure, `ruff` resolves `CORULIX_MANAGED` first (owner-pinned Ruff
/// 0.16.3, see `wht_corulix_formatter::profile::FormatterProfile::ruff_format`'s
/// own doc comment) -- on a host with Ruff genuinely provisioned (this test
/// suite's own shared `managed_toolchain_root()`, via
/// `corulix setup --only python`), a bare `empty_config()` (no approved
/// `HOST_ONLY` directories) therefore no longer makes `ruff` unavailable, so
/// this test's real proof is now positive rather than negative: Python's
/// resolved `provider_path` must be the real managed **Ruff** binary, never
/// Biome's (which would also report `Available` here and mask the bug this
/// test exists to catch).
#[tokio::test]
async fn python_is_not_routed_to_biome() -> Result<(), Box<dyn Error>> {
    let _guard = session_lock().await;
    let managed_root = provisioning::managed_toolchain_root()
        .map_err(|error| fail(format!("managed_toolchain_root: {error:?}")))?;
    let fixture = Fixture::new("unsupported", "app.py", "x=1\n");

    let outcome = wht_corulix_formatter::format_preview_at(
        &managed_root,
        &empty_config(),
        fixture.root()?,
        fixture.target("app.py"),
        wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await;

    match outcome {
        Ok(result) if result.status == wht_corulix_formatter::FormatStatus::ProviderUnavailable => {
            // Ruff genuinely not provisioned on this host -- still an
            // honest, acceptable outcome (never a silent Biome fallback).
        }
        Ok(ref result @ wht_corulix_formatter::FormatterResult { .. })
            if result.provider_path.as_deref().is_some_and(|path| {
                path.components()
                    .any(|component| component.as_os_str() == "ruff")
            }) => {}
        other => {
            return Err(fail(format!(
                "Python must resolve the real managed ruff formatter (never fall back to Biome), got {other:?}"
            )));
        }
    }
    fixture.cleanup();
    Ok(())
}
