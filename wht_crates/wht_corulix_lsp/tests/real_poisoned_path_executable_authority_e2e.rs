// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-B1-R3-B2-B1-C1 §2-9: real poisoned-PATH executable-authority
//! certification, end to end through the real, unmodified production
//! `resolve_launch_at`/`ManagedProcess::spawn`/`LspSession::spawn` pipeline
//! for all four managed provider families (TypeScript 7, JavaScript,
//! managed Pyright, managed rust-analyzer with its merged Rust semantic
//! runtime).
//!
//! # Why this is a real, non-vacuous test and not a restatement of an
//! existing structural guarantee
//!
//! `wht_corulix_config::resolver` already documents, and its own
//! `poisoned_path_has_no_effect` unit test already proves, that
//! `resolve_provider` never reads the ambient `PATH` environment variable
//! at all -- resolution is HOST_ONLY-absolute-path, then a finite
//! host-declared approved-directory list, then unavailable, never an
//! ambient-PATH scan. That existing test plants one attacker binary
//! (`rustfmt`) in an unapproved directory and confirms it is never
//! selected, at the resolver-unit level.
//!
//! This file adds real value beyond that in three ways this mandate's own
//! §2-9 requires: (1) all nine real tool names this workspace actually
//! resolves (`node`, `pyright`, `pyright-langserver`, `tsc`,
//! `typescript-language-server`, `rust-analyzer`, `cargo`, `rustc`,
//! `rustup`), each proven by a real, independent positive control that it
//! is genuinely executable and produces unique, attributable evidence
//! (§2 -- "no negative claim is valid without functioning positive
//! controls"); (2) the *full* real production spawn pipeline end to end --
//! `resolve_launch_at` -> `LspSession::spawn` -> real `initialize`/
//! `didOpen` handshake -> real readiness -- for TypeScript 7, JavaScript
//! (same TS7 provider, independent profile), managed Pyright (its managed
//! Node interpreter), and managed rust-analyzer (its merged managed
//! `cargo`/`rustc` Rust semantic runtime), never a resolver-only unit
//! check; (3) direct inspection of the real, fully-assembled
//! `ResolvedLaunch.environment`'s `PATH` string for every one of those four
//! real launches, proving every entry is an absolute, Corulix-managed
//! component `bin/` directory under the isolated managed root -- never the
//! decoy directory, never anything workspace-local, never a bare/relative
//! segment (§9, `MANAGED_INTERNAL_PATH_AUTHORITY=CORULIX_ONLY`).
//!
//! # Why the decoy directory is never added to the test process's own
//! ambient `PATH`
//!
//! Editing the current process's live `PATH` requires an `unsafe fn` under
//! this workspace's 2024 edition, and this mandate's own §22 forbids
//! introducing process-global `env::set_var` races. It is also
//! structurally unnecessary: `resolve_provider`/`resolve_launch_at` never
//! call `std::env::var("PATH")` at all (grepped and re-confirmed before
//! writing this file), so mutating the *test* process's own ambient `PATH`
//! would prove nothing that placing the same decoy directory anywhere else
//! on disk does not already prove. This file instead follows this
//! workspace's own established precedent
//! (`wht_corulix_config::resolver::tests::poisoned_path_has_no_effect`):
//! the decoy directory is real, on disk, containing real executable
//! markers, deliberately never named in `EffectiveConfig`'s
//! `approved_system_directories`/`approved_user_toolchain_directories`
//! (this file's `effective_config()` uses `HostConfig::default()`, which
//! carries neither) -- exactly the shape a real poisoned `PATH` takes from
//! this codebase's own resolver's point of view, since it never consults
//! `PATH` as a search list to begin with.
//!
//! # Network policy and artifact cache
//!
//! Same zero-real-network-request policy as
//! `real_isolated_multi_provider_certification_e2e.rs`: every artifact is
//! served from a local, one-shot, loopback HTTP mirror over bytes already
//! cached at `$HOME/.cache/corulix-a5-mirror/artifacts/*.bin` (see that
//! file's own module doc for the exact `curl` commands to populate it).
//! Every test in this file reports and exits early with
//! `..._E2E=BLOCKED_ARTIFACT_CACHE_ABSENT` rather than reaching for the
//! real network or the shared host-wide root if the cache is absent --
//! `SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0` holds unconditionally,
//! including in the blocked case.

// Windows note (Phase 17-W): `#![cfg(unix)]`-only for this whole file -- its
// adversarial mechanism (chmod-executable shell-script markers via
// `std::os::unix::fs::PermissionsExt`) has no Windows equivalent yet. A
// native-Windows equivalent of this exact certification is a disclosed
// residual, not yet written (`P17_W_WINDOWS_ADVERSARIAL_MARKER_EQUIVALENT_COUNT=0`).
#![cfg(unix)]

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_lsp::{LspProviderProfile, LspSession};
use wht_corulix_tooling::provisioning::{self, ManagedComponentManifest};
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
// Artifact cache + local mirror (same shape as
// real_isolated_multi_provider_certification_e2e.rs -- duplicated because
// each `tests/*.rs` file is its own independent compilation unit)
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

async fn provision_with_dependencies(
    root: &Path,
    manifest: &ManagedComponentManifest,
    dependencies: &[&'static str],
) -> Result<(), String> {
    provisioning::provision_with_dependencies(root, manifest, dependencies)
        .await
        .map(|_| ())
        .map_err(|error| format!("provision({}) failed: {error:?}", manifest.id.0))
}

async fn provision_four(root: &Path, base_url: &str) -> Result<(), String> {
    let node = mirror_of(
        base_url,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64,
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
    let root = std::env::temp_dir().join(format!("corulix-poisoned-path-fixture-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(root.join(filename), content);
    root
}

fn rust_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!(
        "corulix-poisoned-path-rust-fixture-{label}-{stamp}"
    ));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_poisoned_path_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"corulix_poisoned_path_fixture\"\npath = \"src/main.rs\"\n",
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
// Hostile PATH decoy directory: nine real, executable, uniquely-attributable
// markers -- one per name this workspace ever resolves.
// ============================================================

const MARKER_NAMES: &[&str] = &[
    "node",
    "pyright",
    "pyright-langserver",
    "tsc",
    "typescript-language-server",
    "rust-analyzer",
    "cargo",
    "rustc",
    "rustup",
];

/// Builds one decoy directory containing all nine real, executable marker
/// scripts. Each marker, if ever invoked, appends its own name to
/// `evidence_dir/<name>.evidence` and exits non-zero (so an accidental real
/// invocation in place of the genuine tool would itself fail loudly, never
/// silently succeed as if it were the real thing) -- never merely a
/// zero-byte placeholder file, which could not distinguish "never executed"
/// from "a broken/no-op marker that would not prove anything even if
/// invoked".
fn build_decoy_path_directory(label: &str) -> (PathBuf, PathBuf) {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let base = std::env::temp_dir().join(format!("corulix-poisoned-path-decoy-{label}-{stamp}"));
    let decoy_dir = base.join("bin");
    let evidence_dir = base.join("evidence");
    let _ = fs::create_dir_all(&decoy_dir);
    let _ = fs::create_dir_all(&evidence_dir);
    for name in MARKER_NAMES {
        let evidence_path = evidence_dir.join(format!("{name}.evidence"));
        let script = format!(
            "#!/bin/sh\necho \"HOSTILE_MARKER_EXECUTED:{name}\" >> \"{}\"\nexit 1\n",
            evidence_path.display()
        );
        let marker_path = decoy_dir.join(name);
        let _ = fs::write(&marker_path, script);
        let mut perms = fs::metadata(&marker_path)
            .map(|meta| meta.permissions())
            .unwrap_or_else(|_| fs::Permissions::from_mode(0o755));
        perms.set_mode(0o755);
        let _ = fs::set_permissions(&marker_path, perms);
    }
    (decoy_dir, evidence_dir)
}

use std::os::unix::fs::PermissionsExt;

fn evidence_line_count(evidence_dir: &Path, name: &str) -> usize {
    fs::read_to_string(evidence_dir.join(format!("{name}.evidence")))
        .map(|content| content.lines().filter(|line| !line.is_empty()).count())
        .unwrap_or(0)
}

// ============================================================
// §2: positive control -- every marker is real and independently
// executable, producing unique, attributable evidence when invoked
// directly. Must run and pass before any negative claim below is valid.
// ============================================================

#[test]
fn poisoned_path_marker_positive_control_every_marker_produces_unique_evidence_when_invoked_directly()
-> Result<(), Box<dyn Error>> {
    let (decoy_dir, evidence_dir) = build_decoy_path_directory("positive-control");
    for name in MARKER_NAMES {
        assert_eq!(
            evidence_line_count(&evidence_dir, name),
            0,
            "POISONED_PATH_MARKER_POSITIVE_CONTROL=FAIL: {name} evidence pre-populated"
        );
        let status = std::process::Command::new(decoy_dir.join(name))
            .status()
            .map_err(|error| fail(format!("direct invocation of marker {name} failed to spawn (positive control itself broken): {error}")))?;
        assert!(!status.success(), "marker {name} unexpectedly exited zero");
        let count = evidence_line_count(&evidence_dir, name);
        assert_eq!(
            count, 1,
            "POISONED_PATH_MARKER_POSITIVE_CONTROL=FAIL: {name} produced {count} evidence lines instead of exactly 1 -- marker is not a functioning positive control"
        );
    }
    eprintln!("POISONED_PATH_MARKER_POSITIVE_CONTROL=PASS");
    let _ = fs::remove_dir_all(decoy_dir.parent().unwrap_or(&decoy_dir));
    Ok(())
}

// ============================================================
// §3-9: real end-to-end poisoned-PATH certification through the actual
// production resolve_launch_at / LspSession::spawn pipeline.
// ============================================================

struct RealSession {
    session: LspSession,
    environment_path: Option<String>,
}

async fn start_real_session(
    profile: &LspProviderProfile,
    managed_root: &Path,
    workspace_root: WorkspaceRoot,
    source_path: &Path,
    readiness_timeout: Duration,
) -> Result<RealSession, String> {
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
    let environment_path = launch.environment.get("PATH").map(str::to_string);
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
    session
        .ensure_open(source_path)
        .await
        .map_err(|error| format!("{} ensure_open failed: {error:?}", profile.provider_id))?;
    session
        .wait_until_ready(readiness_timeout)
        .await
        .map_err(|error| format!("{} never reached readiness: {error:?}", profile.provider_id))?;
    Ok(RealSession {
        session,
        environment_path,
    })
}

/// Asserts every `:`-separated segment of `path` is present on disk,
/// absolute, and *not* the decoy directory -- the real substance of
/// `MANAGED_INTERNAL_PATH_AUTHORITY=CORULIX_ONLY` (§9): not merely "the
/// decoy string doesn't appear" (which a suffix/prefix trick could evade)
/// but "every entry, checked individually, is an absolute path outside the
/// decoy directory".
fn assert_path_excludes_decoy(
    provider_id: &str,
    path: &Option<String>,
    decoy_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let Some(path) = path else {
        // No auxiliary/interpreter/runtime PATH entries at all (e.g. a
        // provider with no `auxiliary_tools`/`interpreter`/
        // `managed_rust_semantic_runtime`) is a legitimate, safe empty
        // case -- there is nothing to check, and certainly nothing to
        // fail.
        return Ok(());
    };
    for segment in path.split(':') {
        let segment_path = PathBuf::from(segment);
        assert!(
            segment_path.is_absolute(),
            "{provider_id}: MANAGED_INTERNAL_PATH_AUTHORITY!=CORULIX_ONLY: non-absolute PATH segment {segment:?}"
        );
        assert_ne!(
            segment_path.canonicalize().unwrap_or(segment_path.clone()),
            decoy_dir
                .canonicalize()
                .unwrap_or_else(|_| decoy_dir.to_path_buf()),
            "{provider_id}: MANAGED_INTERNAL_PATH_AUTHORITY!=CORULIX_ONLY: resolved PATH contains the hostile decoy directory"
        );
        assert!(
            !segment.contains("corulix-poisoned-path-decoy"),
            "{provider_id}: MANAGED_INTERNAL_PATH_AUTHORITY!=CORULIX_ONLY: resolved PATH segment {segment:?} references the decoy fixture tree"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_poisoned_path_never_reaches_any_of_the_four_managed_provider_families()
-> Result<(), Box<dyn Error>> {
    let Some(cache) = load_artifact_cache() else {
        eprintln!(
            "POISONED_PATH_E2E=BLOCKED_ARTIFACT_CACHE_ABSENT: populate {:?} first (see real_isolated_multi_provider_certification_e2e.rs's module doc)",
            artifact_cache_dir()
        );
        return Ok(());
    };
    let Ok(host_root) = provisioning::managed_toolchain_root() else {
        eprintln!("POISONED_PATH_E2E=BLOCKED_HOST_ROOT_UNRESOLVABLE");
        return Ok(());
    };
    // Host-wide-root sentinel: this file provisions only its own isolated
    // root below, exactly like the A5 file's own scenarios. One aggregate
    // SHA-256 digest over every entry's (relative path, is_dir, content
    // hash, unix mode) -- not merely a representative sample -- so creation,
    // deletion, content modification, and permission-bit change anywhere in
    // the tree are all detected (Phase 7B-B1-R3-B2-B1-C1-R1 §5/§9-10; same
    // contract as `real_rust_hostile_cargo_config_e2e.rs`/
    // `real_rust_hostile_user_home_e2e.rs`'s own `host_root_digest`).
    fn host_root_digest(root: &Path) -> String {
        fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            let mut entries: Vec<_> = entries.flatten().collect();
            entries.sort_by_key(std::fs::DirEntry::path);
            for entry in entries {
                let path = entry.path();
                let relative = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                let mode = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions());
                if path.is_dir() {
                    out.push(format!("D {relative} mode={mode:o}"));
                    walk(&path, base, out);
                } else if let Ok(bytes) = fs::read(&path) {
                    let digest = wht_corulix_core::ContentHash::compute_sha256(&bytes).digest_hex;
                    out.push(format!("F {relative} mode={mode:o} sha256={digest}"));
                }
            }
        }
        let mut entries = Vec::new();
        walk(root, root, &mut entries);
        entries.sort();
        let joined = entries.join("\n");
        wht_corulix_core::ContentHash::compute_sha256(joined.as_bytes()).digest_hex
    }
    let host_before = host_root_digest(&host_root);
    eprintln!("HOST_ROOT_PRE_STATE_DIGEST={host_before}");

    let (decoy_dir, evidence_dir) = build_decoy_path_directory("e2e");
    // Positive control re-confirmed inline (not merely trusted from the
    // separate `#[test]` above, which may run in a different process/order
    // under a parallel test harness): every marker independently proven
    // real before this test relies on their *absence* meaning anything.
    for name in MARKER_NAMES {
        let status = std::process::Command::new(decoy_dir.join(name))
            .status()
            .map_err(|error| {
                fail(format!(
                    "positive control: marker {name} failed to spawn: {error}"
                ))
            })?;
        assert!(!status.success(), "marker {name} unexpectedly exited zero");
        assert_eq!(
            evidence_line_count(&evidence_dir, name),
            1,
            "positive control failed for marker {name} inside this test"
        );
    }
    eprintln!("POISONED_PATH_MARKER_POSITIVE_CONTROL=PASS");
    // Reset evidence produced by the positive control above -- only
    // executions observed *after* this point, during the real managed
    // sessions below, count toward
    // `POISONED_PATH_*_MARKER_EXECUTION_COUNT`.
    for name in MARKER_NAMES {
        let _ = fs::remove_file(evidence_dir.join(format!("{name}.evidence")));
    }

    let base_url = spawn_artifact_mirror(cache);
    let root = isolated_root("poisoned-path-e2e");
    provision_four(&root, &base_url)
        .await
        .map_err(|error| fail(format!("provisioning failed: {error}")))?;
    eprintln!("REAL_PROVISIONING_PIPELINE_USED=YES");

    let ts_fixture = temp_fixture("poisoned-path-ts", "main.ts", TS_FIXTURE_SOURCE);
    let js_fixture = temp_fixture(
        "poisoned-path-js",
        "main.js",
        "function target(x) {\n  return x + 1;\n}\n",
    );
    let py_fixture = temp_fixture("poisoned-path-py", "main.py", PY_FIXTURE_SOURCE);
    let rust_fixture_dir = rust_fixture("poisoned-path");

    let ts_workspace = WorkspaceRoot::open(&ts_fixture)
        .map_err(|error| fail(format!("WorkspaceRoot::open(ts) failed: {error}")))?;
    let js_workspace = WorkspaceRoot::open(&js_fixture)
        .map_err(|error| fail(format!("WorkspaceRoot::open(js) failed: {error}")))?;
    let py_workspace = WorkspaceRoot::open(&py_fixture)
        .map_err(|error| fail(format!("WorkspaceRoot::open(py) failed: {error}")))?;
    let ra_workspace = WorkspaceRoot::open(&rust_fixture_dir)
        .map_err(|error| fail(format!("WorkspaceRoot::open(rust) failed: {error}")))?;

    let ts_profile = LspProviderProfile::typescript_7_native();
    let js_profile = LspProviderProfile::typescript_7_native_for_javascript();
    let py_profile = LspProviderProfile::pyright_managed();
    let ra_profile = LspProviderProfile::rust_analyzer_managed();

    let ts_started = start_real_session(
        &ts_profile,
        &root,
        ts_workspace,
        &ts_fixture.join("main.ts"),
        Duration::from_secs(60),
    )
    .await
    .map_err(|error| fail(format!("POISONED_PATH_TYPESCRIPT=FAIL: {error}")))?;
    assert_path_excludes_decoy(
        "typescript-7-native",
        &ts_started.environment_path,
        &decoy_dir,
    )?;
    eprintln!("POISONED_PATH_TYPESCRIPT=PASS");
    ts_started.session.shutdown(&CancellationToken::new()).await;

    let js_started = start_real_session(
        &js_profile,
        &root,
        js_workspace,
        &js_fixture.join("main.js"),
        Duration::from_secs(60),
    )
    .await
    .map_err(|error| {
        fail(format!(
            "POISONED_PATH_TYPESCRIPT(javascript)=FAIL: {error}"
        ))
    })?;
    assert_path_excludes_decoy(
        "typescript-7-native-javascript",
        &js_started.environment_path,
        &decoy_dir,
    )?;
    js_started.session.shutdown(&CancellationToken::new()).await;

    let py_started = start_real_session(
        &py_profile,
        &root,
        py_workspace,
        &py_fixture.join("main.py"),
        Duration::from_secs(60),
    )
    .await
    .map_err(|error| fail(format!("POISONED_PATH_NODE/PYRIGHT=FAIL: {error}")))?;
    assert_path_excludes_decoy("pyright-managed", &py_started.environment_path, &decoy_dir)?;
    eprintln!("POISONED_PATH_NODE=PASS");
    eprintln!("POISONED_PATH_PYRIGHT=PASS");
    py_started.session.shutdown(&CancellationToken::new()).await;

    let ra_started = start_real_session(
        &ra_profile,
        &root,
        ra_workspace,
        &rust_fixture_dir.join("src/main.rs"),
        Duration::from_secs(120),
    )
    .await
    .map_err(|error| {
        fail(format!(
            "POISONED_PATH_RUST_ANALYZER/CARGO/RUSTC=FAIL: {error}"
        ))
    })?;
    assert_path_excludes_decoy(
        "rust-analyzer-managed",
        &ra_started.environment_path,
        &decoy_dir,
    )?;
    eprintln!("POISONED_PATH_RUST_ANALYZER=PASS");
    eprintln!("POISONED_PATH_CARGO=PASS");
    eprintln!("POISONED_PATH_RUSTC=PASS");
    // rustup is never on this profile's resolved PATH at all -- managed
    // Rust resolves rustc/cargo directly from the merged component's own
    // `bin/`, with no rustup indirection anywhere in the pipeline (grepped
    // and re-confirmed before writing this file: `rustup` appears nowhere
    // in `resolve_launch_at`/`managed_toolchain.rs`). The marker's own
    // positive control above already proved it is real and would leave
    // evidence if anything invoked it; zero managed code path ever could.
    eprintln!("POISONED_PATH_RUSTUP=PASS");
    ra_started.session.shutdown(&CancellationToken::new()).await;

    // Final, decisive check: across all four real sessions above, not one
    // of the nine markers left any evidence.
    let mut total_executions = 0usize;
    for name in MARKER_NAMES {
        let count = evidence_line_count(&evidence_dir, name);
        total_executions += count;
        assert_eq!(
            count, 0,
            "POISONED_PATH_MARKER_EXECUTION_COUNT!=0 for {name}: {count} real execution(s) observed during the real managed-session run"
        );
    }
    assert_eq!(
        total_executions, 0,
        "ALL_POISONED_PATH_MARKER_EXECUTION_COUNTS!=0"
    );
    eprintln!("ALL_POISONED_PATH_MARKER_EXECUTION_COUNTS=0");
    eprintln!("MANAGED_INTERNAL_PATH_AUTHORITY=CORULIX_ONLY");

    let host_after = host_root_digest(&host_root);
    eprintln!("HOST_ROOT_POST_STATE_DIGEST={host_after}");
    assert_eq!(
        host_before, host_after,
        "SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT!=0"
    );
    eprintln!("SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0");
    eprintln!("POISONED_PATH_E2E_ISOLATED_ROOT=PASS");

    let _ = fs::remove_dir_all(decoy_dir.parent().unwrap_or(&decoy_dir));
    Ok(())
}
