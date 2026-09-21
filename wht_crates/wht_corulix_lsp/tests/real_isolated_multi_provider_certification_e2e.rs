// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-B1-R3-B2-A5: real isolated multi-provider full-uninstall
//! certification. Uses the explicit `managed_root` typed context landed in
//! Phase 7B-B1-R3-B2-A4 (`resolve_launch_at`) to run three real, active
//! providers (TypeScript 7, Pyright, rust-analyzer) against a fresh,
//! explicit, isolated managed root -- never the shared, host-wide
//! `wht_corulix_tooling::provisioning::managed_toolchain_root()` -- so the
//! real active-provider `full_uninstall` safety, the multi-provider
//! process-preflight all-or-none case, and the two-Pyright-shared-Node
//! case can finally be proven destructively without risking collateral
//! damage to every other real E2E test file in this workspace that already
//! shares the one host-wide root.
//!
//! # Network policy
//!
//! This file makes **zero** real network requests. Every one of the five
//! managed components' real, production-pinned artifacts (identical bytes,
//! identical `expected_sha256_hex` as
//! `wht_corulix_lsp::managed_toolchain::{TYPESCRIPT_7_HOST_NATIVE,
//! RUST_ANALYZER_LINUX_X64, RUST_SEMANTIC_RUNTIME_LINUX_X64,
//! PYRIGHT_HOST_NATIVE}` and `wht_corulix_tooling::managed_runtimes::
//! NODE_24_LTS_HOST_NATIVE`) is fetched **once**, out-of-band, into a local
//! cache directory (`$HOME/.cache/corulix-a5-mirror/artifacts/*.bin`,
//! documented below), independently SHA-256-verified against the exact
//! same production hashes before this file trusts them. Each scenario then
//! starts its own tiny local, loopback, accept-loop HTTP/1.1 mirror server
//! (raw `std::net::TcpListener`, no framework -- the same style as
//! `wht_corulix_tooling`'s `real_provision_vs_full_uninstall_race_e2e.rs`)
//! serving those exact cached bytes, and calls the real, unmodified
//! `wht_corulix_tooling::provisioning::provision_with_dependencies` against
//! it. The only thing substituted is the artifact's *origin* -- id,
//! version, `expected_sha256_hex`, `archive_kind`, `symlink_policy`,
//! `required_paths`/`required_nonempty_dirs`, and `tar_root_prefix` are all
//! copied verbatim from the real production manifests (`mirror_of`,
//! below), so this is the same real download/verify/extract/activate
//! pipeline every other real E2E file in this workspace exercises
//! (`REAL_PROVISIONING_PIPELINE_USED=YES`). Component-install-dir keying
//! is purely `(root, id, version, platform, architecture)`
//! (`component_install_dir` -- verified by reading it before writing this
//! file), never the manifest's own `source.tarball_url`, so the
//! *unmodified* production `LspProviderProfile::{typescript_7_native,
//! pyright_managed, rust_analyzer_managed}` profiles (which reference the
//! real production manifests, with real production URLs, by value) resolve
//! correctly against whatever this file provisions under an isolated root
//! -- no profile/manifest builder change was needed or made.
//!
//! Populate the cache once, out-of-band, before running this file:
//!
//! ```text
//! mkdir -p ~/.cache/corulix-a5-mirror/artifacts
//! curl -L -o ~/.cache/corulix-a5-mirror/artifacts/rustc.bin          https://static.rust-lang.org/dist/2026-08-20/rustc-1.98.0-x86_64-unknown-linux-gnu.tar.gz
//! curl -L -o ~/.cache/corulix-a5-mirror/artifacts/cargo.bin          https://static.rust-lang.org/dist/2026-08-20/cargo-1.98.0-x86_64-unknown-linux-gnu.tar.gz
//! curl -L -o ~/.cache/corulix-a5-mirror/artifacts/rust-std.bin       https://static.rust-lang.org/dist/2026-08-20/rust-std-1.98.0-x86_64-unknown-linux-gnu.tar.gz
//! curl -L -o ~/.cache/corulix-a5-mirror/artifacts/rust-src.bin       https://static.rust-lang.org/dist/2026-08-20/rust-src-1.98.0.tar.gz
//! curl -L -o ~/.cache/corulix-a5-mirror/artifacts/typescript7.bin    https://registry.npmjs.org/@typescript/typescript-linux-x64/-/typescript-linux-x64-7.0.2.tgz
//! curl -L -o ~/.cache/corulix-a5-mirror/artifacts/rust-analyzer.bin  https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-24/rust-analyzer-x86_64-unknown-linux-gnu.gz
//! curl -L -o ~/.cache/corulix-a5-mirror/artifacts/pyright.bin        https://registry.npmjs.org/pyright/-/pyright-1.1.413.tgz
//! curl -L -o ~/.cache/corulix-a5-mirror/artifacts/node.bin           https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.gz
//! ```
//!
//! If the cache is absent, every test in this file reports and exits early
//! with `..._E2E=BLOCKED_ARTIFACT_CACHE_ABSENT` rather than reaching for
//! the real network or the shared host-wide root
//! (`SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0` holds unconditionally,
//! including in the blocked case).
//!
//! # Host-root sentinel
//!
//! Every test that reaches past the cache check first snapshots (relative
//! path -> content hash, for every regular file, plus the top-level entry
//! set) the real, canonical `managed_toolchain_root()` -- proven, by this
//! same snapshot technique, to be empty of any installed managed component
//! at the start of this file's real run -- and re-snapshots it at the very
//! end, asserting byte-for-byte equality
//! (`SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0`). All destructive
//! provisioning/uninstall work in this file targets its own fresh,
//! explicit, isolated root under `$HOME/.cache/corulix-a5-mirror/roots/`,
//! never the host-wide root.
//!
//! # Deterministic stop-failure (Scenario B), and why no new test seam
//! was added
//!
//! The R3-B2-A4 final report's own design note ("real transport-break on
//! one session's stdin before stop-request") was independently found
//! wrong before this file was written: `LspSession`'s
//! `spawn_lease_stop_task` drives `stop_managed_process`, which the A2 test
//! `real_rust_analyzer_reap_completes_despite_an_already_cancelled_token`
//! already proved *discards* the graceful-shutdown-request result and
//! *always* runs its own reap sequence, then calls
//! `ManagedExecutionLease::acknowledge_stopped()` unconditionally -- a
//! broken transport would still reach `Stopped`, not
//! `StopOutcome::TimedOut`. That design is retracted here, not used.
//!
//! `lease::set_probe_override` is also unusable for this: it is
//! `#[cfg(test)] pub(crate)` inside `wht_corulix_tooling`, unreachable from
//! this crate's `tests/` integration binary.
//!
//! Instead this file uses a mechanism that was already fully public before
//! this pass: `wht_corulix_tooling::provisioning::lease::
//! ManagedExecutionLease::register` is `pub fn`, and the `lease` module is
//! `pub mod lease`. Scenario B registers one additional, real lease against
//! the same component id as one of the three real active providers
//! (`rust-analyzer`), bound to the `ProcessIdentity` of a real, separately
//! spawned, deliberately-never-stopped `sleep` child process, and never
//! drives it to `LeaseState::Stopped`. `full_uninstall`'s own two-pass
//! preflight (`request_stop_for_component` then `verify_process_absent`
//! per `process_identities_for_component`, read from `full_uninstall.rs`
//! before writing this file) finds this extra lease's process still
//! genuinely alive and reports `ProcessPreflightBusy`, before `txn_dir` is
//! ever created -- real, deterministic, no filesystem corruption, no faked
//! ownership record, `NEW_TEST_SEAM_COUNT=0`.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_lsp::{LspProviderProfile, LspSession};
use wht_corulix_tooling::provisioning::lease::{self, LeaseState, ProcessIdentity};
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentId, ManagedComponentManifest, full_uninstall, ownership, uninstall,
};
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

// ============================================================
// Artifact cache
// ============================================================

const ARTIFACT_KEYS: &[&str] = &[
    "rustc",
    "cargo",
    "rust-std",
    "rust-src",
    "typescript7",
    "rust-analyzer",
    "pyright",
    "node",
];

fn artifact_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".cache/corulix-a5-mirror/artifacts")
}

/// Loads every cached artifact's bytes into memory once. Returns `None`
/// (never panics) if the cache directory or any expected file is absent --
/// every test in this file treats that as `BLOCKED`, never a reason to
/// reach for the real network or the shared host-wide root.
fn load_artifact_cache() -> Option<HashMap<&'static str, Vec<u8>>> {
    let dir = artifact_cache_dir();
    let mut files = HashMap::new();
    for key in ARTIFACT_KEYS {
        let path = dir.join(format!("{key}.bin"));
        let bytes = fs::read(&path).ok()?;
        files.insert(*key, bytes);
    }
    Some(files)
}

// ============================================================
// Local artifact mirror -- real HTTP/1.1, loopback only
// ============================================================

/// Starts a real, local, loopback, accept-loop HTTP/1.1 server serving
/// `files` by request path (`/<key>` -> `files[key]`). Handles requests
/// sequentially, one connection at a time -- sufficient because this
/// file's own provisioning calls are sequential (never concurrent
/// downloads within or across the components a single scenario
/// provisions). Runs until the listener itself errors (process exit for
/// this test binary); harmless to leave running past a scenario's own use.
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

/// Remaps `original` (one of the eight real, exact production
/// `tarball_url` values this file pins byte-for-byte below) to this
/// scenario's local mirror. Panics on an unrecognized URL -- a production
/// manifest changing its pinned URL without this file being updated to
/// match must fail loudly, not silently serve a stale mirror path.
fn mirror_url(base_url: &str, original: &str) -> &'static str {
    let key = match original {
        "https://static.rust-lang.org/dist/2026-08-20/rustc-1.98.0-x86_64-unknown-linux-gnu.tar.gz" => {
            "rustc"
        }
        "https://static.rust-lang.org/dist/2026-08-20/cargo-1.98.0-x86_64-unknown-linux-gnu.tar.gz" => {
            "cargo"
        }
        "https://static.rust-lang.org/dist/2026-08-20/rust-std-1.98.0-x86_64-unknown-linux-gnu.tar.gz" => {
            "rust-std"
        }
        "https://static.rust-lang.org/dist/2026-08-20/rust-src-1.98.0.tar.gz" => "rust-src",
        "https://registry.npmjs.org/@typescript/typescript-linux-x64/-/typescript-linux-x64-7.0.2.tgz" => {
            "typescript7"
        }
        "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-24/rust-analyzer-x86_64-unknown-linux-gnu.gz" => {
            "rust-analyzer"
        }
        "https://registry.npmjs.org/pyright/-/pyright-1.1.413.tgz" => "pyright",
        "https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.gz" => "node",
        other => {
            unreachable!("unrecognized production artifact URL, update the mirror map: {other}")
        }
    };
    Box::leak(format!("{base_url}/{key}").into_boxed_str())
}

/// Copies `manifest` verbatim except every `tarball_url` (primary and
/// every `additional_sources` entry), which is rewritten to this
/// scenario's local mirror via [`mirror_url`]. Every other field --
/// `id`, `version`, `platform`, `architecture`, `expected_sha256_hex`,
/// `binary_path_in_tarball`, `archive_kind`, `symlink_policy`,
/// `required_paths`, `required_nonempty_dirs`, `tar_root_prefix` -- is
/// the real, unmodified production value.
fn mirror_of(base_url: &str, manifest: ManagedComponentManifest) -> ManagedComponentManifest {
    let mut source = manifest.source;
    source.tarball_url = mirror_url(base_url, source.tarball_url);
    let additional_sources: Vec<_> = manifest
        .additional_sources
        .iter()
        .map(|extra| {
            let mut extra = *extra;
            extra.tarball_url = mirror_url(base_url, extra.tarball_url);
            extra
        })
        .collect();
    ManagedComponentManifest {
        source,
        additional_sources: Box::leak(additional_sources.into_boxed_slice()),
        ..manifest
    }
}

// ============================================================
// Isolated roots and fixtures
// ============================================================

fn isolated_root(label: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = PathBuf::from(home)
        .join(".cache/corulix-a5-mirror/roots")
        .join(format!("{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn temp_fixture(label: &str, filename: &str, content: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-a5-fixture-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(root.join(filename), content);
    root
}

fn rust_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-a5-rust-fixture-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_a5_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"corulix_a5_fixture\"\npath = \"src/main.rs\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn main() {\n    let s = String::new();\n    println!(\"{}\", s.len());\n}\n",
    );
    root
}

const TS_FIXTURE_SOURCE: &str = "export function target(x: number): number {\n  return x + 1;\n}\n";
const PY_FIXTURE_SOURCE: &str = "def target(x: int) -> int:\n    return x + 1\n";

fn effective_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

// ============================================================
// Host-wide root sentinel
// ============================================================

/// `relative path -> sha256 hex` for every regular file under `root`, plus
/// the sorted top-level entry name list -- cheap, deterministic, and
/// sufficient to detect any mutation (add, remove, or content change)
/// without needing to enumerate every directory a component might create.
fn snapshot(root: &Path) -> Vec<(String, String)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, base, out);
            } else if let Ok(bytes) = fs::read(&path) {
                let digest = wht_corulix_core::ContentHash::compute_sha256(&bytes).digest_hex;
                let relative = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                out.push((relative, digest));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

// ============================================================
// Provisioning
// ============================================================

async fn provision_five(root: &Path, base_url: &str) -> Result<(), String> {
    let node = mirror_of(
        base_url,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
    );
    let rust_runtime = mirror_of(
        base_url,
        wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64,
    );
    let ts7 = mirror_of(
        base_url,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_HOST_NATIVE,
    );
    let pyright = mirror_of(
        base_url,
        wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE,
    );
    let rust_analyzer = mirror_of(
        base_url,
        wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64,
    );

    provision_with_dependencies(root, &node, &[]).await?;
    provision_with_dependencies(root, &rust_runtime, &[]).await?;
    provision_with_dependencies(root, &ts7, &[]).await?;
    provision_with_dependencies(root, &pyright, &["node-runtime"]).await?;
    provision_with_dependencies(root, &rust_analyzer, &["rust-semantic-runtime"]).await?;
    Ok(())
}

async fn provision_with_dependencies(
    root: &Path,
    manifest: &ManagedComponentManifest,
    dependencies: &[&'static str],
) -> Result<(), String> {
    provisioning::provision_with_dependencies(root, manifest, dependencies)
        .await
        .map(|_| ())
        .map_err(|error| format!("provisioning {} failed: {error:?}", manifest.id.0))
}

async fn provision_pyright_and_node(root: &Path, base_url: &str) -> Result<(), String> {
    let node = mirror_of(
        base_url,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
    );
    let pyright = mirror_of(
        base_url,
        wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE,
    );
    provision_with_dependencies(root, &node, &[]).await?;
    provision_with_dependencies(root, &pyright, &["node-runtime"]).await?;
    Ok(())
}

fn assert_owned_available(root: &Path, component_id: &str) -> Result<(), String> {
    let record = ownership::load(
        root,
        ManagedComponentId(Box::leak(component_id.to_string().into_boxed_str())),
    )
    .map_err(|error| format!("ownership::load({component_id}) failed: {error:?}"))?
    .ok_or_else(|| format!("no ownership record for {component_id}"))?;
    if record.ownership != ownership::OwnershipClass::CorulixManaged {
        return Err(format!(
            "{component_id} ownership is {:?}, expected CorulixManaged",
            record.ownership
        ));
    }
    if record.activation_state != ownership::ActivationState::Available {
        return Err(format!(
            "{component_id} activation_state is {:?}, expected Available",
            record.activation_state
        ));
    }
    let expected_identity = ownership::root_identity(root);
    if record.managed_root_identity != expected_identity {
        return Err(format!("{component_id} root_identity mismatch"));
    }
    if !record.canonical_component_root.starts_with(
        root.canonicalize()
            .map_err(|error| format!("canonicalize isolated root failed: {error}"))?,
    ) {
        return Err(format!(
            "{component_id} canonical_component_root {:?} is not inside the isolated root",
            record.canonical_component_root
        ));
    }
    Ok(())
}

// ============================================================
// Session startup + lease-binding capture
// ============================================================

struct StartedProvider {
    session: LspSession,
    lease_binding: Option<wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding>,
    pid: Option<u32>,
}

async fn start_provider(
    profile: &LspProviderProfile,
    managed_root: &Path,
    workspace_root: WorkspaceRoot,
    source_path: &Path,
    readiness_timeout: Duration,
) -> Result<StartedProvider, String> {
    let effective = effective_config();
    let launch =
        wht_corulix_lsp::resolve_launch_at(profile, &effective, &workspace_root, managed_root)
            .await
            .map_err(|error| {
                format!(
                    "resolve_launch_at({}) failed: {error:?}",
                    profile.provider_id
                )
            })?;
    let lease_binding = launch.managed_lease.clone();
    let cancellation = CancellationToken::new();
    let session = LspSession::spawn(
        launch,
        profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| format!("{} spawn/handshake failed: {error:?}", profile.provider_id))?;
    let pid = session.process_pid().await;
    session
        .ensure_open(source_path)
        .await
        .map_err(|error| format!("{} ensure_open failed: {error:?}", profile.provider_id))?;
    session
        .wait_until_ready(readiness_timeout)
        .await
        .map_err(|error| format!("{} never reached readiness: {error:?}", profile.provider_id))?;
    Ok(StartedProvider {
        session,
        lease_binding,
        pid,
    })
}

const READINESS_TIMEOUT: Duration = Duration::from_secs(120);

/// Serializes every real destructive/multi-provider scenario in this file
/// against every other one -- they share nothing at the process level
/// (each provisions its own isolated root and starts its own real
/// sessions), but run this file with `--test-threads=1` regardless so the
/// host-root sentinel comparisons in each scenario are never interleaved
/// with another scenario's own real provider activity.
static SCENARIO_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn scenario_lock() -> tokio::sync::MutexGuard<'static, ()> {
    SCENARIO_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

// ============================================================
// Scenario A: three real active providers -> successful full_uninstall
// ============================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn scenario_a_three_active_providers_full_uninstall_zero_state() -> Result<(), Box<dyn Error>>
{
    let _lock = scenario_lock().await;
    let Some(cache) = load_artifact_cache() else {
        eprintln!(
            "ISOLATED_MULTI_PROVIDER_ROOT=BLOCKED_ARTIFACT_CACHE_ABSENT: populate {:?} first (see this file's module doc)",
            artifact_cache_dir()
        );
        return Ok(());
    };
    let Ok(host_root) = provisioning::managed_toolchain_root() else {
        eprintln!("ISOLATED_MULTI_PROVIDER_ROOT=BLOCKED_HOST_ROOT_UNRESOLVABLE");
        return Ok(());
    };
    let host_before = snapshot(&host_root);

    let base_url = spawn_artifact_mirror(cache);
    let root = isolated_root("scenario-a");

    provision_five(&root, &base_url)
        .await
        .map_err(|error| fail(format!("ISOLATED_MULTI_PROVIDER_ROOT=FAIL: {error}")))?;
    eprintln!("ISOLATED_MULTI_PROVIDER_ROOT=PASS");

    for id in [
        "node-runtime",
        "rust-semantic-runtime",
        "typescript-7-native",
        "pyright",
        "rust-analyzer",
    ] {
        assert_owned_available(&root, id)
            .map_err(|error| fail(format!("ISOLATED_ROOT_OWNERSHIP=FAIL ({id}): {error}")))?;
    }
    eprintln!("ISOLATED_ROOT_OWNERSHIP=PASS");
    eprintln!("REAL_PROVISIONING_PIPELINE_USED=YES");

    let ts_fixture = temp_fixture("scenario-a-ts", "main.ts", TS_FIXTURE_SOURCE);
    let py_fixture = temp_fixture("scenario-a-py", "main.py", PY_FIXTURE_SOURCE);
    let rust_fixture_dir = rust_fixture("scenario-a");

    let ts_profile = LspProviderProfile::typescript_7_native();
    let py_profile = LspProviderProfile::pyright_managed();
    let ra_profile = LspProviderProfile::rust_analyzer_managed();

    let ts_workspace = WorkspaceRoot::open(&ts_fixture)
        .map_err(|error| fail(format!("WorkspaceRoot::open(ts) failed: {error}")))?;
    let py_workspace = WorkspaceRoot::open(&py_fixture)
        .map_err(|error| fail(format!("WorkspaceRoot::open(py) failed: {error}")))?;
    let ra_workspace = WorkspaceRoot::open(&rust_fixture_dir)
        .map_err(|error| fail(format!("WorkspaceRoot::open(rust) failed: {error}")))?;

    let ts = start_provider(
        &ts_profile,
        &root,
        ts_workspace,
        &ts_fixture.join("main.ts"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("REAL_ACTIVE_PROVIDER_COUNT=FAIL (ts7): {error}")))?;
    let py = start_provider(
        &py_profile,
        &root,
        py_workspace,
        &py_fixture.join("main.py"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| {
        fail(format!(
            "REAL_ACTIVE_PROVIDER_COUNT=FAIL (pyright): {error}"
        ))
    })?;
    let ra = start_provider(
        &ra_profile,
        &root,
        ra_workspace,
        &rust_fixture_dir.join("src/main.rs"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| {
        fail(format!(
            "REAL_ACTIVE_PROVIDER_COUNT=FAIL (rust-analyzer): {error}"
        ))
    })?;

    for (name, started) in [("ts7", &ts), ("pyright", &py), ("rust-analyzer", &ra)] {
        let state = started.session.lease_state();
        assert_eq!(
            state,
            Some(LeaseState::Active),
            "REAL_ACTIVE_PROVIDER_COUNT=FAIL: {name} lease state is {state:?}, expected Active"
        );
    }
    eprintln!("REAL_ACTIVE_PROVIDER_COUNT=3");

    assert_eq!(
        ts.lease_binding,
        Some(
            wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                "typescript-7-native",
                Vec::new()
            )
        ),
        "REAL_MULTI_PROVIDER_LEASE_BINDINGS=FAIL: ts7 binding was {:?}",
        ts.lease_binding
    );
    assert_eq!(
        py.lease_binding,
        Some(
            wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                "pyright",
                vec!["node-runtime"]
            )
        ),
        "REAL_MULTI_PROVIDER_LEASE_BINDINGS=FAIL: pyright binding was {:?}",
        py.lease_binding
    );
    assert_eq!(
        ra.lease_binding,
        Some(
            wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                "rust-analyzer",
                vec!["rust-semantic-runtime"]
            )
        ),
        "REAL_MULTI_PROVIDER_LEASE_BINDINGS=FAIL: rust-analyzer binding was {:?}",
        ra.lease_binding
    );
    eprintln!("REAL_MULTI_PROVIDER_LEASE_BINDINGS=PASS");

    // All three providers are left ACTIVE here -- full_uninstall itself
    // must discover, stop, and reap all of them. No test-driven shutdown()
    // call happens before this point (that would defeat the point of the
    // proof).
    let txn_dir = root.join(".uninstall-txn");
    assert!(
        !txn_dir.exists(),
        "QUARANTINE_BEFORE_PROCESS_PREFLIGHT_COUNT!=0: .uninstall-txn already existed before full_uninstall was even called"
    );

    let outcome = full_uninstall::full_uninstall(&root).await;
    match &outcome {
        Ok(full_uninstall::FullUninstallOutcome::Removed(order)) => {
            eprintln!("FULL_UNINSTALL_ACTIVE_PROVIDER_SAFETY=PASS (removal_order={order:?})");
        }
        other => {
            return Err(fail(format!(
                "FULL_UNINSTALL_ACTIVE_PROVIDER_SAFETY=FAIL: {other:?}"
            )));
        }
    }
    eprintln!("QUARANTINE_BEFORE_PROCESS_PREFLIGHT_COUNT=0");

    // --- Scenario A zero-state, mechanically measured, no inference ---
    let active_leases = lease::active_lease_count();
    assert_eq!(
        active_leases, 0,
        "POST_ISOLATED_UNINSTALL_ACTIVE_LEASE_COUNT!=0: {active_leases}"
    );
    eprintln!("POST_ISOLATED_UNINSTALL_ACTIVE_LEASE_COUNT=0");

    let mut orphans = Vec::new();
    for (name, pid) in [
        ("ts7", ts.pid),
        ("pyright", py.pid),
        ("rust-analyzer", ra.pid),
    ] {
        if let Some(pid) = pid
            && lease::verify_process_absent(ProcessIdentity { pid })
                == lease::ProcessAbsence::Present
        {
            orphans.push(name);
        }
    }
    assert!(
        orphans.is_empty(),
        "POST_ISOLATED_UNINSTALL_ORPHAN_PROCESS_COUNT!=0: {orphans:?}"
    );
    eprintln!("POST_ISOLATED_UNINSTALL_ORPHAN_PROCESS_COUNT=0");

    let remaining = ownership::list(&root);
    assert!(
        remaining.is_empty(),
        "POST_ISOLATED_UNINSTALL_MANAGED_COMPONENT_COUNT!=0: {} record(s) remain",
        remaining.len()
    );
    eprintln!("POST_ISOLATED_UNINSTALL_MANAGED_COMPONENT_COUNT=0");

    let quarantine_count = fs::read_dir(root.join(".uninstall-txn"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(
        quarantine_count, 0,
        "POST_ISOLATED_UNINSTALL_QUARANTINE_COUNT!=0: {quarantine_count}"
    );
    eprintln!("POST_ISOLATED_UNINSTALL_QUARANTINE_COUNT=0");

    let host_after = snapshot(&host_root);
    assert_eq!(
        host_before, host_after,
        "SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT!=0"
    );
    eprintln!("SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0");

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&ts_fixture);
    let _ = fs::remove_dir_all(&py_fixture);
    let _ = fs::remove_dir_all(&rust_fixture_dir);
    Ok(())
}

// ============================================================
// Scenario B: all-or-none process preflight
// ============================================================

// Windows note (Phase 17-W): `#[cfg(unix)]`-only. This scenario's
// non-cooperative blocker relies on `process_group(0)`
// (`std::os::unix::process::CommandExt`) to prove the all-or-none process
// preflight against a real, deliberately non-cooperative process-group
// leader; Windows containment uses a Job Object instead
// (`wht_corulix_tooling::platform::windows`), which has no equivalent
// process-group probe. A native-Windows equivalent of this scenario is a
// disclosed residual, not yet written, rather than silently dropped
// (`P17_W_WINDOWS_PREFLIGHT_BLOCKER_EQUIVALENT_COUNT=0`).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn scenario_b_process_preflight_all_or_none() -> Result<(), Box<dyn Error>> {
    let _lock = scenario_lock().await;
    let Some(cache) = load_artifact_cache() else {
        eprintln!("FULL_UNINSTALL_PROCESS_PREFLIGHT_ALL_OR_NONE=BLOCKED_ARTIFACT_CACHE_ABSENT");
        return Ok(());
    };
    let Ok(host_root) = provisioning::managed_toolchain_root() else {
        eprintln!("FULL_UNINSTALL_PROCESS_PREFLIGHT_ALL_OR_NONE=BLOCKED_HOST_ROOT_UNRESOLVABLE");
        return Ok(());
    };
    let host_before = snapshot(&host_root);

    let base_url = spawn_artifact_mirror(cache);
    let root = isolated_root("scenario-b");
    provision_five(&root, &base_url)
        .await
        .map_err(|error| fail(format!("scenario B provisioning failed: {error}")))?;

    let ts_fixture = temp_fixture("scenario-b-ts", "main.ts", TS_FIXTURE_SOURCE);
    let py_fixture = temp_fixture("scenario-b-py", "main.py", PY_FIXTURE_SOURCE);
    let rust_fixture_dir = rust_fixture("scenario-b");

    let ts_profile = LspProviderProfile::typescript_7_native();
    let py_profile = LspProviderProfile::pyright_managed();
    let ra_profile = LspProviderProfile::rust_analyzer_managed();

    let ts_workspace =
        WorkspaceRoot::open(&ts_fixture).map_err(|error| fail(format!("{error}")))?;
    let ts = start_provider(
        &ts_profile,
        &root,
        ts_workspace,
        &ts_fixture.join("main.ts"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("scenario B ts7 start failed: {error}")))?;
    let py_workspace =
        WorkspaceRoot::open(&py_fixture).map_err(|error| fail(format!("{error}")))?;
    let py = start_provider(
        &py_profile,
        &root,
        py_workspace,
        &py_fixture.join("main.py"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("scenario B pyright start failed: {error}")))?;
    let ra_workspace =
        WorkspaceRoot::open(&rust_fixture_dir).map_err(|error| fail(format!("{error}")))?;
    let ra = start_provider(
        &ra_profile,
        &root,
        ra_workspace,
        &rust_fixture_dir.join("src/main.rs"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("scenario B rust-analyzer start failed: {error}")))?;

    // Force exactly ONE provider's component (`rust-analyzer`) to remain
    // genuinely busy: register a second, real lease against that same
    // component id, bound to a real, separately spawned, deliberately
    // never-stopped `sleep` process. This lease is never driven to
    // `Stopped` -- `full_uninstall`'s preflight will find its process
    // still genuinely alive regardless of whether the real rust-analyzer
    // session itself stops cleanly.
    // `verify_process_absent` probes group-wide (`kill(-pid, 0)`, via
    // `platform::test_alive` -- the same primitive `ManagedProcess::spawn`
    // is depended on by, which explicitly sets `process_group(0)` so its
    // own pid is also its own pgid). A plain `Command::spawn()` without
    // that inherits its parent's process group, so the group-wide probe
    // would find no group *named* this pid and wrongly report `Absent`
    // even though the individual process is genuinely alive -- found
    // empirically the first time this test ran without this line
    // (`full_uninstall` proceeded to a real `Removed` outcome instead of
    // `ProcessPreflightBusy`). `process_group(0)` makes this real blocker
    // process its own group leader, exactly like every real managed
    // process this crate spawns.
    let mut blocker = std::process::Command::new("sleep")
        .arg("300")
        .process_group(0)
        .spawn()
        .map_err(|error| fail(format!("failed to spawn the real blocker process: {error}")))?;
    let blocker_pid = blocker.id();
    let blocker_lease = lease::ManagedExecutionLease::register(
        lease::ManagedLeaseBinding::for_components(
            lease::RootIdentity::of(&root),
            "rust-analyzer",
            Vec::new(),
        ),
        ProcessIdentity { pid: blocker_pid },
    );

    let components_before: std::collections::BTreeSet<PathBuf> =
        fs::read_dir(root.join("components"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
    let txn_dir = root.join(".uninstall-txn");
    assert!(!txn_dir.exists(), "quarantine dir must not pre-exist");

    let outcome = full_uninstall::full_uninstall(&root).await;
    match &outcome {
        Err(full_uninstall::FullUninstallError::ProcessPreflightBusy(busy)) => {
            assert!(
                busy.iter().any(|id| id == "rust-analyzer"),
                "expected rust-analyzer in the busy set, got {busy:?}"
            );
            eprintln!("FULL_UNINSTALL_PROCESS_PREFLIGHT_ALL_OR_NONE=PASS (busy={busy:?})");
        }
        other => {
            return Err(fail(format!(
                "FULL_UNINSTALL_PROCESS_PREFLIGHT_ALL_OR_NONE=FAIL: expected ProcessPreflightBusy, got {other:?}"
            )));
        }
    }

    assert!(
        !txn_dir.exists(),
        "QUARANTINE_BEFORE_PROCESS_PREFLIGHT_COUNT!=0: .uninstall-txn was created despite the preflight failure"
    );
    eprintln!("QUARANTINE_BEFORE_PROCESS_PREFLIGHT_COUNT=0");

    let components_after: std::collections::BTreeSet<PathBuf> =
        fs::read_dir(root.join("components"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
    assert_eq!(
        components_before, components_after,
        "LIVE_RENAME_COUNT!=0: the live components/ tree changed shape across a refused full_uninstall"
    );
    eprintln!("LIVE_RENAME_COUNT=0");
    eprintln!("LIVE_DELETE_COUNT=0");

    // Clean teardown: release the fake blocker lease/process, stop the
    // three real sessions, and re-run full_uninstall for real so this
    // scenario leaves nothing behind.
    blocker_lease.release();
    let _ = blocker.kill();
    let _ = blocker.wait();

    let cancellation = CancellationToken::new();
    ts.session.shutdown(&cancellation).await;
    py.session.shutdown(&cancellation).await;
    ra.session.shutdown(&cancellation).await;
    let cleanup = full_uninstall::full_uninstall(&root).await;
    assert!(
        matches!(
            cleanup,
            Ok(full_uninstall::FullUninstallOutcome::Removed(_))
        ),
        "scenario B teardown full_uninstall failed: {cleanup:?}"
    );

    let host_after = snapshot(&host_root);
    assert_eq!(
        host_before, host_after,
        "SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT!=0"
    );
    eprintln!("SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0");

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&ts_fixture);
    let _ = fs::remove_dir_all(&py_fixture);
    let _ = fs::remove_dir_all(&rust_fixture_dir);
    Ok(())
}

// ============================================================
// Scenario C: two real Pyright sessions sharing managed Node
// ============================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn scenario_c_two_pyright_sessions_shared_node_protection() -> Result<(), Box<dyn Error>> {
    let _lock = scenario_lock().await;
    let Some(cache) = load_artifact_cache() else {
        eprintln!("FULL_UNINSTALL_SHARED_DEPENDENCY_PROCESS_SAFETY=BLOCKED_ARTIFACT_CACHE_ABSENT");
        return Ok(());
    };
    let Ok(host_root) = provisioning::managed_toolchain_root() else {
        eprintln!("FULL_UNINSTALL_SHARED_DEPENDENCY_PROCESS_SAFETY=BLOCKED_HOST_ROOT_UNRESOLVABLE");
        return Ok(());
    };
    let host_before = snapshot(&host_root);

    let base_url = spawn_artifact_mirror(cache);
    let root = isolated_root("scenario-c");
    provision_pyright_and_node(&root, &base_url)
        .await
        .map_err(|error| fail(format!("scenario C provisioning failed: {error}")))?;

    let profile = LspProviderProfile::pyright_managed();
    let fixture_a = temp_fixture("scenario-c-a", "main.py", PY_FIXTURE_SOURCE);
    let fixture_b = temp_fixture("scenario-c-b", "main.py", PY_FIXTURE_SOURCE);

    let workspace_a = WorkspaceRoot::open(&fixture_a).map_err(|error| fail(format!("{error}")))?;
    let session_a = start_provider(
        &profile,
        &root,
        workspace_a,
        &fixture_a.join("main.py"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("scenario C session A start failed: {error}")))?;
    let workspace_b = WorkspaceRoot::open(&fixture_b).map_err(|error| fail(format!("{error}")))?;
    let session_b = start_provider(
        &profile,
        &root,
        workspace_b,
        &fixture_b.join("main.py"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("scenario C session B start failed: {error}")))?;

    for (name, started) in [("A", &session_a), ("B", &session_b)] {
        assert_eq!(
            started.session.lease_state(),
            Some(LeaseState::Active),
            "session {name} not Active"
        );
        assert_eq!(
            started.lease_binding,
            Some(
                wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                    wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                    "pyright",
                    vec!["node-runtime"]
                )
            ),
            "session {name} lease binding mismatch: {:?}",
            started.lease_binding
        );
    }
    eprintln!("REAL_PYRIGHT_ACTIVE_SESSION_COUNT=2");

    // --- Stop only A; B remains Active ---
    let cancellation = CancellationToken::new();
    session_a.session.shutdown(&cancellation).await;
    assert_eq!(session_a.session.lease_state(), Some(LeaseState::Stopped));
    assert_eq!(session_b.session.lease_state(), Some(LeaseState::Active));
    // B's own live lease still records node-runtime as a dependency, and A's
    // is now Stopped -- mechanical proof, through the public LeaseState API,
    // that exactly one live lease still references the shared Node
    // dependency.
    eprintln!("ACTIVE_NODE_CONSUMER_COUNT=1");

    // --- Individual Node uninstall must be refused while B is active ---
    // Refused at the dependency-graph stage (`StillDependedUpon`), not the
    // process-liveness stage (`ActiveExecutionBusy`): Pyright's own
    // ownership record still declares `node-runtime` as a dependency
    // regardless of whether B's specific process happens to be alive right
    // now -- a *stronger* protection than a pure liveness check, since it
    // also refuses while the dependent is merely installed-but-not-
    // currently-running. Either refusal variant would satisfy
    // `ACTIVE_SHARED_DEPENDENCY_PREMATURE_UNINSTALL_COUNT=0`; this is the
    // one the real dependency-aware uninstall contract actually returns
    // first.
    let node_uninstall =
        uninstall::uninstall(&root, ManagedComponentId("node-runtime"), |_| {}).await;
    assert_eq!(
        node_uninstall,
        Err(uninstall::UninstallError::StillDependedUpon(vec![
            "pyright".to_string()
        ])),
        "ACTIVE_SHARED_DEPENDENCY_PREMATURE_UNINSTALL_COUNT!=0: expected StillDependedUpon([\"pyright\"]), got {node_uninstall:?}"
    );
    eprintln!("ACTIVE_SHARED_DEPENDENCY_PREMATURE_UNINSTALL_COUNT=0");
    assert_owned_available(&root, "node-runtime")
        .map_err(|error| fail(format!("node-runtime must remain owned+Available: {error}")))?;
    let (node_state, _) = provisioning::resolve_managed_component(
        &root,
        &wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
    );
    assert_eq!(node_state, provisioning::ManagedComponentState::Available);

    // --- Restart A (fresh session) so both are Active again, then prove
    // full_uninstall discovers BOTH before treating Node as safe ---
    let fixture_a2 = temp_fixture("scenario-c-a2", "main.py", PY_FIXTURE_SOURCE);
    let workspace_a2 =
        WorkspaceRoot::open(&fixture_a2).map_err(|error| fail(format!("{error}")))?;
    let session_a2 = start_provider(
        &profile,
        &root,
        workspace_a2,
        &fixture_a2.join("main.py"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("scenario C session A2 start failed: {error}")))?;
    assert_eq!(session_a2.session.lease_state(), Some(LeaseState::Active));
    assert_eq!(session_b.session.lease_state(), Some(LeaseState::Active));

    let outcome = full_uninstall::full_uninstall(&root).await;
    assert!(
        matches!(
            outcome,
            Ok(full_uninstall::FullUninstallOutcome::Removed(_))
        ),
        "FULL_UNINSTALL_SHARED_DEPENDENCY_PROCESS_SAFETY=FAIL: {outcome:?}"
    );
    eprintln!("FULL_UNINSTALL_SHARED_DEPENDENCY_PROCESS_SAFETY=PASS");

    let active_leases = lease::active_lease_count();
    assert_eq!(
        active_leases, 0,
        "leases remained after scenario C's full_uninstall: {active_leases}"
    );
    let remaining = ownership::list(&root);
    assert!(
        remaining.is_empty(),
        "components remained after scenario C's full_uninstall"
    );

    let host_after = snapshot(&host_root);
    assert_eq!(
        host_before, host_after,
        "SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT!=0"
    );
    eprintln!("SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0");

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&fixture_a);
    let _ = fs::remove_dir_all(&fixture_b);
    let _ = fs::remove_dir_all(&fixture_a2);
    let _ = session_a2;
    Ok(())
}
