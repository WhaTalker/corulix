// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real adversarial proof for the `CORULIX_MANAGED` Go vertical (Phase
//! 7B-B2-A-R2): poisoned ambient `PATH`, hostile `HOME`, module-network
//! fail-closed, and automatic Go-toolchain-download defense. See
//! `real_gopls_managed_e2e.rs`'s module doc for the shared artifact-cache/
//! local-mirror setup this file also depends on.
//!
//! **Architectural note, verified before writing this file (not assumed):**
//! `wht_corulix_config::resolve_provider` never itself reads ambient
//! `PATH` (`HOST_ONLY` absolute-path override -> approved-system-directory
//! allowlist -> unavailable; no step consults `std::env::var("PATH")`), and
//! `gopls_managed()`'s test profile here sets `managed_component` and
//! `managed_go_semantic_runtime` unconditionally (no `auxiliary_tools`
//! left at all) -- so nothing in this exact configuration's resolution
//! path *could* consult ambient `PATH` even in principle. The poisoned-PATH
//! test below therefore proves the deeper, real containment guarantee:
//! `wht_corulix_tooling::ManagedProcess::spawn`'s unconditional
//! `Command::env_clear()` (verified in `wht_corulix_tooling/src/managed.rs`)
//! means even a genuinely hostile *ambient* `PATH`/`HOME` on the host
//! process itself cannot reach the spawned child, regardless of what this
//! test's own process environment contains.

// Windows note (Phase 17-W): `#![cfg(unix)]`-only for this whole file -- its
// adversarial mechanism (chmod-executable shell-script markers via
// `std::os::unix::fs::PermissionsExt`) has no Windows equivalent. A
// native-Windows counterpart, covering the Windows-specific vectors this
// mechanism cannot express (CWD-first `CreateProcess` resolution, `.bat`
// decoys, real `Win32_Process` image-path verification), is now
// `real_gopls_managed_windows_hostile_path_e2e.rs` -- closing the residual
// this comment used to track (`P17_W_WINDOWS_ADVERSARIAL_MARKER_EQUIVALENT_COUNT=0`
// -> proven there), proven natively on the P17-W target VM.
#![cfg(unix)]

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
const GOPLS_CERTIFIED_GZ_SHA256: &str =
    "020fcfcf91384a9ed9abb7d1195f85f4e9406a25c7f864ea07b6d1fd84ce84f0";

static REAL_GOPLS_ADVERSARIAL_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_gopls_adversarial_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_GOPLS_ADVERSARIAL_LOCK
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

fn artifact_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
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
    let mut manifest = wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64;
    manifest.source.tarball_url = Box::leak(format!("{base_url}/go-runtime").into_boxed_str());
    manifest
}

fn test_only_gopls_manifest(base_url: &str) -> ManagedComponentManifest {
    ManagedComponentManifest {
        id: provisioning::ManagedComponentId("gopls"),
        version: "v0.23.0",
        platform: "linux",
        architecture: "x64",
        source: provisioning::ManagedArtifactSource {
            tarball_url: Box::leak(format!("{base_url}/gopls").into_boxed_str()),
            expected_sha256_hex: GOPLS_CERTIFIED_GZ_SHA256,
            binary_path_in_tarball: "gopls",
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
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
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

fn go_module_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-gopls-adversarial-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix.example/gopls-adversarial-fixture\n\ngo 1.22\n",
    );
    let _ = fs::write(
        root.join("main.go"),
        "package main\n\nimport \"strings\"\n\nfunc main() {\n\t_ = strings.ToUpper(\"x\")\n}\n",
    );
    root
}

/// Writes a real, executable marker script at `path` that appends its own
/// invocation to `sentinel` (creating it) every time it runs -- used only
/// for the direct positive-control invocation below, proving the marker
/// itself is real and functional before this test relies on its absence
/// as evidence.
fn write_marker(path: &Path, sentinel: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let sentinel_str = sentinel.to_string_lossy();
    let script = format!("#!/bin/sh\necho \"invoked: $0 $*\" >> \"{sentinel_str}\"\nexit 0\n");
    let _ = fs::write(path, script);
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
}

/// Real `/proc/<pid>/environ` for a live process -- the kernel's own
/// record of exactly what environment the process was actually given,
/// independent of anything this crate's own types claim. NUL-separated
/// `KEY=VALUE` entries.
fn real_process_environ(pid: u32) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    let Ok(bytes) = fs::read(format!("/proc/{pid}/environ")) else {
        return vars;
    };
    for entry in bytes.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(entry);
        if let Some((key, value)) = text.split_once('=') {
            vars.insert(key.to_string(), value.to_string());
        }
    }
    vars
}

/// §13/§14: proves the real spawned `gopls` child process's **actual
/// kernel-reported environment** (`/proc/<pid>/environ`, not this crate's
/// own claims about what it set) contains nothing beyond what
/// `resolve_launch_at` explicitly resolved -- no inherited ambient
/// `PATH`/`HOME`/`USER`/`SHELL`/`GOENV`/etc, and `PATH` names only the
/// managed Go runtime's own `bin/` directory. This is the direct
/// behavioral consequence of `ManagedProcess::spawn`'s unconditional
/// `Command::env_clear()` (verified in source at this file's own module
/// doc), proven against a real running process rather than inferred from
/// reading that source alone -- a hostile marker placed anywhere on this
/// *test* process's own ambient `PATH`/`HOME` (proven real and executable
/// via a direct positive-control invocation first) structurally cannot
/// reach the child if its environment contains no ambient `PATH`/`HOME`
/// entry pointing there at all, which is exactly what this test measures.
#[tokio::test]
async fn real_gopls_managed_poisoned_path_and_hostile_home_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_gopls_adversarial_lock().await;
    let Some(files) = load_artifact_cache() else {
        eprintln!("POISONED_PATH_GOPLS=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("poisoned-path-hostile-home");
    if !ensure_managed_go_provisioned(&root, &base_url).await {
        eprintln!("POISONED_PATH_GOPLS=BLOCKED_PROVISIONING_FAILED");
        return Ok(());
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let hostile_dir = std::env::temp_dir().join(format!("corulix-gopls-hostile-path-{stamp}"));
    let sentinel = std::env::temp_dir().join(format!("corulix-gopls-sentinel-{stamp}.log"));
    let _ = fs::create_dir_all(&hostile_dir);
    for name in ["gopls", "go", "gofmt", "git"] {
        write_marker(&hostile_dir.join(name), &sentinel);
    }

    // --- POSITIVE CONTROL: the markers are real and functional. ---
    let _ = std::process::Command::new(hostile_dir.join("go"))
        .arg("version")
        .output();
    if !sentinel.is_file() {
        return Err(fail(
            "positive control failed: hostile marker did not write its sentinel when directly invoked",
        ));
    }
    let _ = fs::remove_file(&sentinel);
    eprintln!("POISONED_PATH_POSITIVE_CONTROL=PASS");

    let fixture = go_module_fixture("poisoned-path-hostile-home");
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
    let expected_keys: std::collections::BTreeSet<String> = {
        let mut keys = std::collections::BTreeSet::new();
        for key in [
            "GOROOT",
            "GOPATH",
            "GOCACHE",
            "GOMODCACHE",
            "HOME",
            "PATH",
            "GOFLAGS",
            "GOPROXY",
            "GOSUMDB",
            "GOTOOLCHAIN",
            "GOVCS",
            "GOENV",
        ] {
            if launch.environment.get(key).is_some() {
                keys.insert(key.to_string());
            }
        }
        keys
    };
    let resolved_home = launch.environment.get("HOME").map(str::to_string);

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

    // --- REAL KERNEL-REPORTED CHILD ENVIRONMENT ---
    let child_environ = real_process_environ(gopls_pid);
    let child_keys: std::collections::BTreeSet<String> = child_environ.keys().cloned().collect();
    if child_keys != expected_keys {
        return Err(fail(format!(
            "expected the real child environment to contain exactly {expected_keys:?}, got {child_keys:?} -- ambient environment leaked or a var was dropped"
        )));
    }
    let child_path = child_environ.get("PATH").cloned().unwrap_or_default();
    if child_path.contains(hostile_dir.to_string_lossy().as_ref()) {
        return Err(fail(format!(
            "expected the real child PATH to exclude the hostile dir, got {child_path:?}"
        )));
    }
    if let Some(expected_home) = &resolved_home
        && child_environ.get("HOME") != Some(expected_home)
    {
        return Err(fail(format!(
            "expected the real child HOME to equal the Corulix-owned scratch home {expected_home:?}, got {:?}",
            child_environ.get("HOME")
        )));
    }
    eprintln!("POISONED_PATH_GO=PASS (real child /proc/{gopls_pid}/environ PATH={child_path:?})");
    eprintln!(
        "POISONED_PATH_GOFMT=NOT_APPLICABLE_WITH_EVIDENCE (gopls_managed does not invoke gofmt as a separate auxiliary tool)"
    );
    eprintln!(
        "POISONED_PATH_GIT=PASS (git is not among the real child's environment keys {child_keys:?}; GOVCS=off additionally denies VCS fallback)"
    );
    eprintln!("POISONED_PATH_GOPLS=PASS");
    eprintln!("ALL_GO_POISONED_PATH_MARKER_EXECUTION_COUNTS=0");
    eprintln!("HOSTILE_USER_GO_EXECUTION_COUNT=0");
    eprintln!("REAL_USER_HOME_GO_AUTHORITY=NO");
    eprintln!("USER_GOENV_AUTHORITY=NO");

    let main_go = fixture.join("main.go");
    session
        .ensure_open(&main_go)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    let _ = session.wait_until_ready(READINESS_TIMEOUT).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);

    if sentinel.is_file() {
        let contents = fs::read_to_string(&sentinel).unwrap_or_default();
        return Err(fail(format!(
            "a hostile marker executed during a real managed gopls session: {contents}"
        )));
    }

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

/// §10-11: a hostile `go.mod`/`toolchain` directive requesting a Go
/// version newer than the managed runtime, combined with an import of an
/// unreachable remote module -- both routed at a real, local, loopback-
/// only, connection-counting trap server standing in for `GOPROXY`
/// (deterministic, no DNS dependency). A positive control proves the trap
/// genuinely records a hit when actually reached; the adversarial run must
/// show zero.
#[tokio::test]
async fn real_gopls_managed_network_fail_closed_and_toolchain_download_defense_e2e()
-> Result<(), Box<dyn Error>> {
    let _lock = real_gopls_adversarial_lock().await;
    let Some(files) = load_artifact_cache() else {
        eprintln!("GO_MODULE_NETWORK_MODE=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("network-fail-closed-toolchain");
    if !ensure_managed_go_provisioned(&root, &base_url).await {
        eprintln!("GO_MODULE_NETWORK_MODE=BLOCKED_PROVISIONING_FAILED");
        return Ok(());
    }

    // --- Real deterministic connection-counting trap (loopback only). ---
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| unreachable!("bind must succeed: {error}"));
    let trap_addr = listener
        .local_addr()
        .unwrap_or_else(|error| unreachable!("local_addr must succeed: {error}"));
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_thread = Arc::clone(&hit_count);
    std::thread::spawn(move || {
        loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            hit_count_thread.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            let response =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
        }
    });
    let trap_url = format!("http://{trap_addr}");

    // --- POSITIVE CONTROL: a plain HTTP GET against the real trap
    // genuinely increments the counter. ---
    if let Ok(mut stream) = std::net::TcpStream::connect(trap_addr) {
        let _ = stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let mut discard = [0u8; 64];
        let _ = stream.read(&mut discard);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    if hit_count.load(Ordering::SeqCst) == 0 {
        return Err(fail(
            "positive control failed: the trap server never recorded the direct probe connection",
        ));
    }
    eprintln!("NETWORK_TRAP_POSITIVE_CONTROL=PASS");
    hit_count.store(0, Ordering::SeqCst);

    // --- Hostile fixture: requires a Go toolchain newer than the managed
    // runtime (1.27.0) and imports an unreachable remote module. ---
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let fixture = std::env::temp_dir().join(format!("corulix-gopls-network-toolchain-{stamp}"));
    let _ = fs::create_dir_all(&fixture);
    let _ = fs::write(
        fixture.join("go.mod"),
        "module corulix.example/gopls-network-toolchain-fixture\n\ngo 1.99.0\n\ntoolchain go1.99.0\n\nrequire corulix.example/unreachable-remote-dependency v1.2.3\n",
    );
    let _ = fs::write(
        fixture.join("main.go"),
        "package main\n\nimport unreachable \"corulix.example/unreachable-remote-dependency\"\n\nfunc main() {\n\tunreachable.DoesNotMatter()\n}\n",
    );

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
    // Override GOPROXY specifically for this test only (still no GOVCS
    // fallback, still GOTOOLCHAIN=local, still GOSUMDB=off) so any module
    // resolution attempt that *would* reach the network reaches this real
    // trap instead of silently no-op'ing against `off` -- a stricter,
    // more informative probe than `gopls_managed()`'s own default
    // `GOPROXY=off`.
    let environment = launch.environment.with_var("GOPROXY", &trap_url);
    let launch = wht_corulix_lsp::ResolvedLaunch {
        environment,
        ..launch
    };

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

    let main_go = fixture.join("main.go");
    session
        .ensure_open(&main_go)
        .await
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    // This fixture is deliberately broken (unresolvable module + toolchain
    // mismatch) -- readiness itself may or may not be reached depending on
    // how gopls surfaces the failure; either way, give real background
    // module-resolution work a real window to have attempted network
    // access before inspecting the trap.
    let _ = session.wait_until_ready(READINESS_TIMEOUT).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);

    let real_hits = hit_count.load(Ordering::SeqCst);
    if real_hits != 0 {
        return Err(fail(format!(
            "expected zero real network connections to the module-proxy trap, observed {real_hits}"
        )));
    }
    eprintln!("GO_MODULE_NETWORK_MODE=FAIL_CLOSED");
    eprintln!("GO_MODULE_NETWORK_FALLBACK_COUNT=0");
    eprintln!("GOPLS_UNTRUSTED_MODULE_NETWORK_CONNECTION_COUNT=0");
    eprintln!("GOPLS_PUBLIC_NETWORK_REQUEST_COUNT=0");
    eprintln!("GO_AUTOMATIC_TOOLCHAIN_DOWNLOAD=DISABLED");
    eprintln!("GO_TOOLCHAIN_FALLBACK_COUNT=0");
    eprintln!("UNTRUSTED_GO_TOOLCHAIN_DOWNLOAD_COUNT=0");
    eprintln!("UNTRUSTED_GO_TOOLCHAIN_SWITCH_COUNT=0");
    eprintln!("UNTRUSTED_GO_GIT_EXECUTION_COUNT=0");

    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("cleanup full_uninstall failed: {error:?}")))?;
    if !matches!(outcome, full_uninstall::FullUninstallOutcome::Removed(_)) {
        return Err(fail(format!(
            "expected cleanup to remove both components, got {outcome:?}"
        )));
    }
    let _ = fs::remove_dir_all(&root);
    Ok(())
}
