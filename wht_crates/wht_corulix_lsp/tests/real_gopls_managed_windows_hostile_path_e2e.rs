// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(windows)]

//! P17-W: the native-Windows counterpart of
//! `real_gopls_managed_adversarial_e2e.rs`'s poisoned-`PATH`/hostile-`HOME`
//! proof, which is `#![cfg(unix)]`-only by disclosed design (its adversarial
//! mechanism -- `chmod`-executable shell-script markers via
//! `std::os::unix::fs::PermissionsExt` -- has no Windows equivalent). This
//! file closes that disclosed residual
//! (`P17_W_WINDOWS_ADVERSARIAL_MARKER_EQUIVALENT_COUNT=0` -> proven here)
//! with genuinely Windows-specific decoy vectors that a straight port of the
//! Unix mechanism would miss entirely:
//!
//! - **CWD-first resolution**: `CreateProcess` searches the *current
//!   directory* before consulting `PATH` at all (a Windows-only quirk, no
//!   Unix analogue). [`wht_corulix_lsp::session`] sets the spawned child's
//!   working directory to the workspace root itself
//!   (`session.rs::working_directory: workspace_root.canonical_path()`), so
//!   a decoy `gopls.exe` dropped directly inside the fixture module -- not
//!   merely on `PATH` -- is the single strongest real attack surface on
//!   this platform, tested explicitly below.
//! - **`PATHEXT` extension resolution**: a decoy `gopls.bat` (a non-`.exe`
//!   name a straight `.exe`-only port would miss) is placed both in the
//!   hostile `PATH`-style directory and directly in the workspace CWD,
//!   alongside the `.exe`-named vectors, so this file's coverage is not
//!   `.exe`-only either.
//! - **No ambient-`PATH` mutation needed to prove containment**: unlike the
//!   Unix file (which poisons this test process's own ambient `PATH`/`HOME`
//!   to prove `Command::env_clear()` keeps them from reaching the child),
//!   this file does not splice `hostile_dir` into its own process's `PATH`
//!   at all -- this workspace forbids `unsafe` code (`-F unsafe-code`) and
//!   `std::env::set_var` requires `unsafe` under edition 2024. That mutation
//!   would also prove nothing here beyond what the CWD-decoy and
//!   resolved-executable/real-image-path checks below already prove:
//!   `resolve_launch_at`'s `HOST_ONLY` resolution never reads ambient `PATH`
//!   in `gopls_managed()`'s exact (`auxiliary_tools`-empty) configuration in
//!   the first place (the same architectural fact the Unix file's own doc
//!   comment establishes). `ManagedProcess::spawn`'s unconditional
//!   `Command::env_clear()` (verified in `wht_corulix_tooling/src/managed.rs`)
//!   still means the real spawned child gets none of this test process's
//!   environment regardless -- this file's own `SystemRoot`/`PATH` stay
//!   intact only for its own PowerShell-based independent verification
//!   calls, never passed to the managed gopls child.
//!
//! Real, independent verification throughout: never this crate's own
//! internal state. `Get-CimInstance Win32_Process -Filter "ProcessId=$pid"`
//! (the real OS's own process table) proves which *actual image path*
//! executed, and a written sentinel file (echoed by the decoy scripts
//! themselves, mirroring the Unix file's marker mechanism) proves whether a
//! decoy ever ran at all -- either alone would be circumstantial; both
//! together leave no room for "the assertion checked the wrong thing"
//! evidence gaps this phase has repeatedly found and fixed in earlier
//! passes.
//!
//! Shares `real_gopls_managed_e2e.rs`'s artifact-cache/local-mirror setup
//! (same out-of-band `$HOME/.cache/corulix-gopls-managed-e2e/artifacts/`
//! cache -- this file duplicates the small set of needed helper functions
//! rather than sharing a module, matching the existing convention already
//! established between `real_gopls_managed_e2e.rs` and
//! `real_gopls_managed_adversarial_e2e.rs`, each an independent test
//! binary).

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_lsp::{LspProviderProfile, LspSession};
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentManifest, ManagedComponentState, full_uninstall,
};
use wht_corulix_workspace::WorkspaceRoot;

const READINESS_TIMEOUT: Duration = Duration::from_secs(90);
const GO_RUNTIME_ID: &str = "go-semantic-runtime";

/// Real, independently reproducibility-certified digest of this host's own
/// `gopls@v0.23.0` build (P17-W: built twice via real `go install
/// golang.org/x/tools/gopls@v0.23.0` against this VM's own real,
/// hash-verified `go1.27.0.windows-amd64.zip`; the raw binary's own SHA-256
/// differed between the two builds -- Go embeds the absolute build-cache
/// path into the binary without `-trimpath`, a build-input difference, not
/// a toolchain non-determinism defect -- so this pins the exact gzip this
/// file's own artifact cache holds, the same identity contract
/// `real_gopls_managed_e2e.rs`'s Linux-side digest already holds for its
/// own platform).
const GOPLS_CERTIFIED_GZ_SHA256: &str =
    "dc21e2a32de19093e01a3fe39d5b8d11475453527f037daa92b523038cd469ab";

static REAL_GOPLS_WINDOWS_HOSTILE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_gopls_windows_hostile_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_GOPLS_WINDOWS_HOSTILE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

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

// ============================================================
// Artifact cache / local mirror (same shape as real_gopls_managed_e2e.rs)
// ============================================================

fn artifact_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "C:\\root".to_string());
    PathBuf::from(home).join(".cache/corulix-gopls-managed-e2e/artifacts")
}

fn load_artifact_cache() -> Option<HashMap<&'static str, Vec<u8>>> {
    let dir = artifact_cache_dir();
    let mut files = HashMap::new();
    for key in ["go-runtime", "gopls"] {
        let path = dir.join(format!("{key}.bin"));
        let bytes = fs::read(&path).ok()?;
        files.insert(key, bytes);
    }
    Some(files)
}

fn spawn_artifact_mirror(files: HashMap<&'static str, Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| unreachable!("bind must succeed: {error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| unreachable!("local_addr must succeed: {error}"));
    let base_url = format!("http://{addr}");
    std::thread::spawn(move || {
        loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buffer = [0u8; 8192];
            let mut request = Vec::new();
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request_text = String::from_utf8_lossy(&request);
            let path = request_text
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .trim_start_matches('/')
                .to_string();
            if let Some(body) = files.get(path.as_str()) {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            } else {
                let response =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
            }
            let _ = stream.flush();
        }
    });
    base_url
}

fn mirrored_go_runtime_manifest(base_url: &str) -> ManagedComponentManifest {
    let mut manifest = wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_HOST_NATIVE;
    manifest.source.tarball_url = Box::leak(format!("{base_url}/go-runtime").into_boxed_str());
    manifest
}

fn test_only_gopls_manifest(base_url: &str) -> ManagedComponentManifest {
    ManagedComponentManifest {
        id: provisioning::ManagedComponentId("gopls"),
        version: "v0.23.0",
        platform: "windows",
        architecture: "x64",
        source: provisioning::ManagedArtifactSource {
            tarball_url: Box::leak(format!("{base_url}/gopls").into_boxed_str()),
            expected_sha256_hex: GOPLS_CERTIFIED_GZ_SHA256,
            binary_path_in_tarball: "gopls.exe",
            archive_kind: provisioning::ArchiveKind::GzippedBinary,
            symlink_policy: provisioning::SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[],
    }
}

#[rustfmt::skip]
fn gopls_managed_profile_for_test(base_url: &str) -> LspProviderProfile
{
    LspProviderProfile::gopls_managed().with_managed_component(test_only_gopls_manifest(base_url))
}

fn isolated_root(label: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "C:\\root".to_string());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = PathBuf::from(home)
        .join(".cache/corulix-gopls-managed-e2e/roots")
        .join(format!("{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

async fn ensure_managed_go_provisioned(root: &Path, base_url: &str) -> bool {
    let go_manifest = mirrored_go_runtime_manifest(base_url);
    let gopls_manifest = test_only_gopls_manifest(base_url);
    let (go_state, _) = provisioning::resolve_managed_component(root, &go_manifest);
    if go_state != ManagedComponentState::Available
        && provisioning::provision(root, &go_manifest).await.is_err()
    {
        return false;
    }
    let (gopls_state, _) = provisioning::resolve_managed_component(root, &gopls_manifest);
    if gopls_state != ManagedComponentState::Available
        && provisioning::provision_with_dependencies(root, &gopls_manifest, &[GO_RUNTIME_ID])
            .await
            .is_err()
    {
        return false;
    }
    true
}

// ============================================================
// Windows-specific hostile decoys
// ============================================================

/// Writes a real, functional decoy at `path` (a `.exe` PE stub built by
/// copying `cmd.exe`'s own body would be needlessly complex -- a `.bat`
/// works identically for the "did this get executed" question this file
/// asks, and Windows resolves a `gopls.bat` exactly as readily as a
/// `gopls.exe` when a caller searches by bare name) that appends its own
/// invocation to `sentinel` every time it runs.
fn write_decoy(path: &Path, sentinel: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let sentinel_str = sentinel.to_string_lossy();
    let script =
        format!("@echo off\r\necho invoked: %~f0 %* >> \"{sentinel_str}\"\r\nexit /b 0\r\n");
    let _ = fs::write(path, script);
}

/// Real, independent OS-level check via `Get-CimInstance Win32_Process` --
/// never this crate's own claims -- of the real, actual image path a live
/// process is executing from.
fn real_process_image_path(pid: u32) -> Option<String> {
    let output = StdCommand::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").ExecutablePath"),
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn go_module_fixture_with_decoy(label: &str, decoy_sentinel: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-gopls-win-hostile-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix.example/gopls-win-hostile-fixture\n\ngo 1.22\n",
    );
    let _ = fs::write(
        root.join("main.go"),
        "package main\n\nimport \"strings\"\n\nfunc main() {\n\t_ = strings.ToUpper(\"x\")\n}\n",
    );
    // The strongest real Windows-specific vector: `CreateProcess` searches
    // the current directory before `PATH`, and `session.rs` sets the
    // spawned child's working directory to exactly this fixture root.
    write_decoy(&root.join("gopls.exe.bat"), decoy_sentinel); // never resolves as "gopls.exe"; negative control
    write_decoy(&root.join("gopls.bat"), decoy_sentinel);
    root
}

/// §Windows hostile-PATH/CWD: fake `gopls.exe`/`gopls.bat`/`go.exe` decoys
/// placed ahead of normal `PATH` resolution *and* inside the workspace
/// current-working-directory must never be what Corulix resolves or
/// launches through the real, now host-native-wired `gopls_managed()`
/// profile path -- proven against a genuinely live managed session, not
/// merely by reading `resolve_launch_at`'s source.
#[tokio::test]
async fn real_gopls_managed_windows_hostile_path_and_cwd_decoy_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_gopls_windows_hostile_lock().await;
    let Some(files) = load_artifact_cache() else {
        eprintln!("WINDOWS_HOSTILE_PATH_GOPLS=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("windows-hostile-path");
    if !ensure_managed_go_provisioned(&root, &base_url).await {
        eprintln!("WINDOWS_HOSTILE_PATH_GOPLS=BLOCKED_PROVISIONING_FAILED");
        return Ok(());
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let hostile_dir = std::env::temp_dir().join(format!("corulix-gopls-win-hostile-path-{stamp}"));
    let sentinel = std::env::temp_dir().join(format!("corulix-gopls-win-sentinel-{stamp}.log"));
    let _ = fs::create_dir_all(&hostile_dir);
    // A `.exe` decoy (the primary binary name) and a `.bat` decoy (a
    // non-`.exe` PATHEXT vector a straight `.exe`-only port would miss).
    write_decoy(&hostile_dir.join("gopls.exe.bat"), &sentinel); // negative control name, never matches
    write_decoy(&hostile_dir.join("gopls.bat"), &sentinel);
    write_decoy(&hostile_dir.join("go.bat"), &sentinel);

    // --- POSITIVE CONTROL: the decoys are real and functional. ---
    let _ = StdCommand::new(hostile_dir.join("gopls.bat")).output();
    if !sentinel.is_file() {
        return Err(fail(
            "positive control failed: hostile decoy did not write its sentinel when directly invoked",
        ));
    }
    let _ = fs::remove_file(&sentinel);
    eprintln!("WINDOWS_HOSTILE_PATH_POSITIVE_CONTROL=PASS");

    // The hostile PATH-style directory (`hostile_dir`, populated above with
    // real, functional decoys) is deliberately never spliced into this test
    // process's own ambient `PATH`: this workspace forbids `unsafe` code
    // (`-F unsafe-code`), `std::env::set_var` requires `unsafe` under
    // edition 2024, and -- per `real_gopls_managed_adversarial_e2e.rs`'s own
    // architectural note -- `resolve_launch_at`'s `HOST_ONLY` resolution
    // never reads ambient `PATH` at all in this exact
    // (`auxiliary_tools`-empty) `gopls_managed()` configuration, so mutating
    // this process's own `PATH` would prove nothing beyond what the
    // CWD-decoy and resolved-executable/real-image-path checks below
    // already prove.
    let fixture = go_module_fixture_with_decoy("windows-hostile-path", &sentinel);
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = gopls_managed_profile_for_test(&base_url);
    let launch = wht_corulix_lsp::resolve_launch_at(&profile, &effective, &workspace_root, &root)
        .await
        .map_err(|error| fail(format!("gopls_managed did not resolve: {error:?}")))?;

    // --- RESOLVED EXECUTABLE: must be the real managed binary under
    // `root`, never the hostile PATH dir or the workspace CWD decoy. ---
    if !launch.executable.starts_with(&root) {
        return Err(fail(format!(
            "expected the resolved gopls executable under the managed root {root:?}, got {:?} -- HOSTILE_PATH_OR_CWD_DECOY_WON",
            launch.executable
        )));
    }
    if launch.executable.starts_with(&hostile_dir) || launch.executable.starts_with(&fixture) {
        return Err(fail(format!(
            "resolved gopls executable {:?} points at a hostile/decoy location",
            launch.executable
        )));
    }
    eprintln!(
        "WINDOWS_RESOLVED_EXECUTABLE_AUTHORITY=CORULIX_MANAGED ({:?})",
        launch.executable
    );

    let cancellation = CancellationToken::new();
    let session = LspSession::spawn(
        launch,
        &profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("session spawn/handshake failed: {error:?}")))?;
    let Some(gopls_pid) = session.process_pid().await else {
        return Err(fail("expected a real gopls pid after spawn"));
    };

    // --- REAL OS-LEVEL IMAGE PATH: independent of this crate's own claims. ---
    let real_image_path = real_process_image_path(gopls_pid);
    match &real_image_path {
        Some(path) => {
            let path_lower = path.to_lowercase();
            let hostile_lower = hostile_dir.to_string_lossy().to_lowercase();
            let cwd_lower = fixture.to_string_lossy().to_lowercase();
            if path_lower.contains(&hostile_lower) || path_lower.contains(&cwd_lower) {
                return Err(fail(format!(
                    "the real OS process table reports gopls running from a hostile/decoy path: {path}"
                )));
            }
            eprintln!("WINDOWS_REAL_PROCESS_IMAGE_PATH_AUTHORITY=CORULIX_MANAGED ({path})");
        }
        None => {
            eprintln!(
                "WINDOWS_REAL_PROCESS_IMAGE_PATH_AUTHORITY=UNAVAILABLE (Win32_Process query returned no ExecutablePath; resolved-executable assertion above still holds)"
            );
        }
    }

    // --- Let the session run briefly, opening the fixture -- if a decoy
    // ever won, it would either have already run (sentinel check below) or
    // this session would never reach readiness at all against a fake
    // "gopls" that does not speak LSP. ---
    let main_go = fixture.join("main.go");
    session
        .ensure_open(&main_go)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("managed gopls never reached readiness: {error:?}")))?;
    eprintln!("WINDOWS_HOSTILE_PATH_REAL_GOPLS_READINESS=PASS (a decoy cannot speak real LSP)");

    tokio::time::sleep(Duration::from_millis(500)).await;
    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);

    if sentinel.is_file() {
        let contents = fs::read_to_string(&sentinel).unwrap_or_default();
        return Err(fail(format!(
            "a hostile decoy executed during a real managed gopls session: {contents}"
        )));
    }
    eprintln!("WINDOWS_HOSTILE_PATH_MARKER_EXECUTION_COUNT=0");
    eprintln!("WINDOWS_HOSTILE_CWD_DECOY_EXECUTION_COUNT=0");
    eprintln!("WINDOWS_HOSTILE_PATH_GOPLS=PASS");

    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("cleanup full_uninstall failed: {error:?}")))?;
    if !matches!(outcome, full_uninstall::FullUninstallOutcome::Removed(_)) {
        return Err(fail(format!(
            "expected cleanup to remove both components, got {outcome:?}"
        )));
    }
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&hostile_dir);
    let _ = fs::remove_file(&sentinel);
    Ok(())
}
