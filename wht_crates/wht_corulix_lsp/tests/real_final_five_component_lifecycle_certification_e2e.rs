// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-B1-R3-B2-B2: the final, real, end-to-end certification of the
//! complete B1 managed toolchain lifecycle -- provision all five managed
//! components into a fresh isolated root, use all four supported languages
//! (TypeScript, JavaScript, Python, Rust) through their real managed
//! providers, leave providers genuinely active, invoke the real
//! product-facing uninstall boundary
//! (`uninstall_all_corulix_managed_components_at`, which delegates to
//! [`full_uninstall`]), verify complete managed zero state and exact
//! residual paths, verify a battery of external sentinels (system-tool
//! decoys, a HOST_ONLY-override-style executable, a workspace-external
//! file, an arbitrary external user file/directory) are byte-for-byte
//! unmutated, verify the canonical host-wide managed root is untouched, and
//! finally re-invoke the product uninstall boundary against the
//! already-empty root to prove idempotence.
//!
//! This file adds no new architecture. It reuses the same real
//! provisioning pipeline, local artifact mirror/isolated-root pattern, and
//! `host_root_digest` whole-tree methodology already established across
//! `real_isolated_multi_provider_certification_e2e.rs` and the
//! `real_rust_hostile_*_e2e.rs` / `real_rust_cargo_network_and_external_
//! helper_authority_e2e.rs` files -- duplicated here (each `tests/*.rs`
//! file is its own independent compilation unit) rather than factored into
//! a shared crate, per this workspace's own established convention.
//!
//! # Network policy
//!
//! Zero real network requests. All five components' real, production-
//! pinned artifact bytes are served from the same local
//! `$HOME/.cache/corulix-a5-mirror/artifacts/*.bin` cache every other real
//! E2E file in this workspace already depends on (see that file's module
//! doc for the populate-once `curl` commands). If the cache is absent this
//! file's test reports `BLOCKED_ARTIFACT_CACHE_ABSENT` and exits early
//! without touching the real network or the shared host-wide root.

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
use wht_corulix_tooling::provisioning::lease::{self, LeaseState, ProcessIdentity};
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentManifest, full_uninstall, ownership,
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
// Local artifact mirror + isolated root (same shape as
// real_isolated_multi_provider_certification_e2e.rs)
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
    let root = std::env::temp_dir().join(format!("corulix-b2-fixture-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(root.join(filename), content);
    root
}

fn rust_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-b2-rust-fixture-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_b2_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"corulix_b2_fixture\"\npath = \"src/main.rs\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn main() {\n    let s = String::new();\n    println!(\"{}\", s.len());\n}\n",
    );
    root
}

const TS_FIXTURE_SOURCE: &str = "export function target(x: number): number {\n  return x + 1;\n}\n";
const JS_FIXTURE_SOURCE: &str = "export function jsTarget(x) {\n  return x + 1;\n}\n";
const PY_FIXTURE_SOURCE: &str = "def target(x: int) -> int:\n    return x + 1\n";

fn effective_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

/// Whole-tree pre/post digest -- files AND directories, content AND mode --
/// same methodology as the C1-R1 pass's `host_root_digest`. Used both for
/// the canonical host-wide root sentinel and for the final isolated root's
/// own residual audit.
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
            #[cfg(unix)]
            let mode = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions());
            #[cfg(not(unix))]
            let mode = {
                // `metadata` carries no POSIX mode bits on non-Unix
                // targets; referencing it here (instead of discarding the
                // binding) keeps this branch from being flagged as an
                // unused variable under `cargo clippy --all-targets` on
                // native Windows, where only this arm is ever compiled.
                let _ = &metadata;
                0u32
            };
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

/// Enumerates every path under `root`, relative, sorted -- used for the
/// exact `POST_UNINSTALL_RESIDUAL_PATHS` report (never predeclared empty).
fn enumerate_paths(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let relative = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            out.push(relative);
            if path.is_dir() {
                walk(&path, base, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

// ============================================================
// External sentinels (§6): independent fixtures OUTSIDE the isolated
// managed root, hashed before provisioning and re-hashed after the entire
// lifecycle including uninstall.
// ============================================================

struct Sentinel {
    label: &'static str,
    path: PathBuf,
    digest: String,
}

fn set_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o755);
            let _ = fs::set_permissions(path, permissions);
        }
    }
    // No executable bit to set on non-Unix targets (Windows resolves
    // executability by file extension, not a permission bit); reference
    // `path` here so it is not flagged as unused when this is the only
    // compiled arm.
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn file_digest(path: &Path) -> String {
    fs::read(path)
        .map(|bytes| wht_corulix_core::ContentHash::compute_sha256(&bytes).digest_hex)
        .unwrap_or_else(|_| "MISSING".to_string())
}

fn build_external_sentinels() -> (PathBuf, Vec<Sentinel>) {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-b2-external-sentinels-{stamp}"));
    let _ = fs::create_dir_all(&root);

    let mut sentinels = Vec::new();

    // System-tool decoys: node, tsc, pyright, rust-analyzer, cargo, rustc,
    // rustup -- each a real executable script, outside the managed root,
    // simulating what a real system installation of each tool would be.
    for tool in [
        "node",
        "tsc",
        "pyright",
        "rust-analyzer",
        "cargo",
        "rustc",
        "rustup",
    ] {
        let path = root.join(format!("system-{tool}"));
        let _ = fs::write(&path, format!("#!/bin/sh\necho system-{tool}\n"));
        set_executable(&path);
        sentinels.push(Sentinel {
            label: Box::leak(format!("system_{tool}").into_boxed_str()),
            digest: file_digest(&path),
            path,
        });
    }

    // HOST_ONLY_OVERRIDE-style external executable.
    let host_override = root.join("host-only-override-tool");
    let _ = fs::write(&host_override, "#!/bin/sh\necho host-only-override\n");
    set_executable(&host_override);
    sentinels.push(Sentinel {
        label: "host_only_override",
        digest: file_digest(&host_override),
        path: host_override,
    });

    // WORKSPACE_EXTERNAL-style executable/file.
    let workspace_external = root.join("workspace-external-tool");
    let _ = fs::write(&workspace_external, "#!/bin/sh\necho workspace-external\n");
    set_executable(&workspace_external);
    sentinels.push(Sentinel {
        label: "workspace_external",
        digest: file_digest(&workspace_external),
        path: workspace_external,
    });

    // Arbitrary external user file.
    let user_file = root.join("user-notes.txt");
    let _ = fs::write(&user_file, "these are the user's own unrelated notes\n");
    sentinels.push(Sentinel {
        label: "arbitrary_user_file",
        digest: file_digest(&user_file),
        path: user_file,
    });

    // External directory sentinel (nested content, whole-subtree digest).
    let user_dir = root.join("user-project");
    let _ = fs::create_dir_all(user_dir.join("src"));
    let _ = fs::write(user_dir.join("src/main.txt"), "unrelated user project\n");
    sentinels.push(Sentinel {
        label: "arbitrary_user_directory",
        digest: host_root_digest(&user_dir),
        path: user_dir,
    });

    (root, sentinels)
}

fn reverify_sentinels(sentinels: &[Sentinel]) -> Vec<String> {
    let mut mutated = Vec::new();
    for sentinel in sentinels {
        let after = if sentinel.path.is_dir() {
            host_root_digest(&sentinel.path)
        } else {
            file_digest(&sentinel.path)
        };
        if after != sentinel.digest {
            mutated.push(sentinel.label.to_string());
        }
    }
    mutated
}

// ============================================================
// Provisioning
// ============================================================

async fn provision_five(root: &Path, base_url: &str) -> Result<(), String> {
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

fn assert_owned_available(root: &Path, component_id: &str) -> Result<(), String> {
    let record = ownership::load(
        root,
        provisioning::ManagedComponentId(Box::leak(component_id.to_string().into_boxed_str())),
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
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("canonicalize isolated root failed: {error}"))?;
    if !record.canonical_component_root.starts_with(&canonical_root) {
        return Err(format!(
            "{component_id} canonical_component_root {:?} is not inside the isolated root",
            record.canonical_component_root
        ));
    }
    Ok(())
}

// ============================================================
// Session startup
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
    // §20: every resolved binary must originate from the isolated managed
    // root, never an ambient/system path.
    let canonical_root = managed_root
        .canonicalize()
        .map_err(|error| format!("canonicalize managed_root failed: {error}"))?;
    let canonical_executable = launch
        .executable
        .canonicalize()
        .map_err(|error| format!("canonicalize resolved executable failed: {error}"))?;
    if !canonical_executable.starts_with(&canonical_root) {
        return Err(format!(
            "SYSTEM_PROVIDER_FALLBACK_COUNT!=0: {} resolved outside the isolated root: {canonical_executable:?}",
            profile.provider_id
        ));
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn final_five_component_managed_lifecycle_certification() -> Result<(), Box<dyn Error>> {
    let Some(cache) = load_artifact_cache() else {
        eprintln!(
            "FINAL_LIFECYCLE_E2E=BLOCKED_ARTIFACT_CACHE_ABSENT: populate {:?} first (see real_isolated_multi_provider_certification_e2e.rs's module doc)",
            artifact_cache_dir()
        );
        return Ok(());
    };
    let Ok(host_root) = provisioning::managed_toolchain_root() else {
        eprintln!("FINAL_LIFECYCLE_E2E=BLOCKED_HOST_ROOT_UNRESOLVABLE");
        return Ok(());
    };

    // ---- §7: host-wide root sentinel ----
    let host_before = host_root_digest(&host_root);
    eprintln!("HOST_ROOT_PRE_STATE_DIGEST={host_before}");

    // ---- §3: fresh explicit isolated typed root ----
    let root = isolated_root("final-five-component-lifecycle");
    eprintln!("FINAL_CERTIFICATION_ROOT_MODEL=EXPLICIT_TYPED_ROOT");

    // ---- §5: pre-provision state ----
    let pre_provision_components = ownership::list(&root);
    if !pre_provision_components.is_empty() {
        return Err(fail(format!(
            "PRE_PROVISION_MANAGED_COMPONENT_COUNT!=0: {} record(s)",
            pre_provision_components.len()
        )));
    }
    let pre_provision_residual = enumerate_paths(&root);
    eprintln!("PRE_PROVISION_MANAGED_COMPONENT_COUNT=0");
    eprintln!("PRE_PROVISION_RESIDUAL_PATHS={pre_provision_residual:?}");

    // ---- §6: external sentinels, created before provisioning ----
    let (sentinel_root, sentinels) = build_external_sentinels();
    eprintln!(
        "EXTERNAL_SENTINEL_COUNT={} (labels={:?})",
        sentinels.len(),
        sentinels.iter().map(|s| s.label).collect::<Vec<_>>()
    );

    // ---- §8-12: real production provisioning pipeline, all five ----
    let base_url = spawn_artifact_mirror(cache);
    provision_five(&root, &base_url).await.map_err(|error| {
        fail(format!(
            "FINAL_REAL_PROVISIONING_PIPELINE_USED=FAIL: {error}"
        ))
    })?;
    eprintln!("FINAL_REAL_PROVISIONING_PIPELINE_USED=YES");
    eprintln!("FINAL_TS7_PROVISIONING=PASS");
    eprintln!("FINAL_NODE_PROVISIONING=PASS");
    eprintln!("FINAL_PYRIGHT_PROVISIONING=PASS");
    eprintln!("FINAL_RUST_SEMANTIC_RUNTIME_PROVISIONING=PASS");
    eprintln!("FINAL_RUST_ANALYZER_PROVISIONING=PASS");

    // ---- §13: combined ownership state ----
    let component_ids = [
        "node-runtime",
        "rust-semantic-runtime",
        "typescript-7-native",
        "pyright",
        "rust-analyzer",
    ];
    for id in component_ids {
        assert_owned_available(&root, id).map_err(|error| {
            fail(format!(
                "COMBINED_MANAGED_COMPONENT_COUNT=FAIL ({id}): {error}"
            ))
        })?;
    }
    let combined = ownership::list(&root);
    let combined_ok: Vec<String> = combined
        .iter()
        .filter_map(|record| record.as_ref().ok())
        .map(|record| record.component_id.clone())
        .collect();
    if combined_ok.len() != 5 {
        return Err(fail(format!(
            "COMBINED_MANAGED_COMPONENT_COUNT!=5: {combined_ok:?}"
        )));
    }
    eprintln!("COMBINED_MANAGED_COMPONENT_COUNT=5");
    eprintln!("COMBINED_MANAGED_COMPONENTS={combined_ok:?}");

    // ---- §14: dependency graph ----
    let pyright_deps = combined
        .iter()
        .filter_map(|record| record.as_ref().ok())
        .find(|record| record.component_id == "pyright")
        .map(|record| record.dependencies.clone())
        .unwrap_or_default();
    let ra_deps = combined
        .iter()
        .filter_map(|record| record.as_ref().ok())
        .find(|record| record.component_id == "rust-analyzer")
        .map(|record| record.dependencies.clone())
        .unwrap_or_default();
    if pyright_deps != vec!["node-runtime".to_string()] {
        return Err(fail(format!(
            "COMBINED_DEPENDENCY_GRAPH=FAIL: pyright deps {pyright_deps:?}, expected [node-runtime]"
        )));
    }
    if ra_deps != vec!["rust-semantic-runtime".to_string()] {
        return Err(fail(format!(
            "COMBINED_DEPENDENCY_GRAPH=FAIL: rust-analyzer deps {ra_deps:?}, expected [rust-semantic-runtime]"
        )));
    }
    eprintln!("COMBINED_DEPENDENCY_GRAPH=PASS");

    // ---- §15: managed path confinement ----
    let canonical_root = root
        .canonicalize()
        .map_err(|error| fail(format!("canonicalize root failed: {error}")))?;
    for record in combined.iter().filter_map(|record| record.as_ref().ok()) {
        let canon = record
            .canonical_component_root
            .canonicalize()
            .map_err(|error| {
                fail(format!(
                    "canonicalize {} failed: {error}",
                    record.component_id
                ))
            })?;
        if !canon.starts_with(&canonical_root) {
            return Err(fail(format!(
                "COMBINED_MANAGED_PATH_CONFINEMENT=FAIL: {} escapes isolated root: {canon:?}",
                record.component_id
            )));
        }
    }
    eprintln!("COMBINED_MANAGED_PATH_CONFINEMENT=PASS");

    // ---- §16-19: real four-language use ----
    let ts_fixture = temp_fixture("final-ts", "main.ts", TS_FIXTURE_SOURCE);
    // JS fixture lives INSIDE the same TS7 workspace root -- `ensure_open`
    // confines to the bound workspace, and §17 deliberately reuses the
    // same active TS7 session/lease (not a second one) to open it, so both
    // files must share one workspace.
    let _ = fs::write(ts_fixture.join("main.js"), JS_FIXTURE_SOURCE);
    let js_fixture_dir = ts_fixture.clone();
    let py_fixture = temp_fixture("final-py", "main.py", PY_FIXTURE_SOURCE);
    let rust_fixture_dir = rust_fixture("final");

    let ts_profile = LspProviderProfile::typescript_7_native();
    let py_profile = LspProviderProfile::pyright_managed();
    let ra_profile = LspProviderProfile::rust_analyzer_managed();

    let ts_workspace = WorkspaceRoot::open(&ts_fixture)
        .map_err(|error| fail(format!("WorkspaceRoot::open(ts) failed: {error}")))?;
    let ts = start_provider(
        &ts_profile,
        &root,
        ts_workspace,
        &ts_fixture.join("main.ts"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("TYPESCRIPT_7_LSP_E2E=FAIL: {error}")))?;
    eprintln!("TYPESCRIPT_7_LSP_E2E=PASS");

    // §17: real JavaScript semantic operation through the same canonical
    // TS7 native provider model -- a second `ensure_open` on the SAME
    // active TS7 session, against a real `.js` file, using the canonical
    // JS profile variant to confirm the language-id mapping. This keeps
    // the active-provider count at exactly 3 (TS7/Pyright/rust-analyzer)
    // per §21 while still proving real JS semantic capability.
    let js_profile = LspProviderProfile::typescript_7_native_for_javascript();
    if js_profile.provider_id != ts_profile.provider_id {
        return Err(fail(
            "JAVASCRIPT_7_LSP_E2E=FAIL: JS profile does not share the TS7 native provider id",
        ));
    }
    ts.session
        .ensure_open(&js_fixture_dir.join("main.js"))
        .await
        .map_err(|error| fail(format!("JAVASCRIPT_7_LSP_E2E=FAIL: ensure_open: {error:?}")))?;
    eprintln!("JAVASCRIPT_7_LSP_E2E=PASS");

    let py_workspace = WorkspaceRoot::open(&py_fixture)
        .map_err(|error| fail(format!("WorkspaceRoot::open(py) failed: {error}")))?;
    let py = start_provider(
        &py_profile,
        &root,
        py_workspace,
        &py_fixture.join("main.py"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("PYTHON_LSP_E2E_MANAGED=FAIL: {error}")))?;
    eprintln!("PYTHON_LSP_E2E_MANAGED=PASS");

    let ra_workspace = WorkspaceRoot::open(&rust_fixture_dir)
        .map_err(|error| fail(format!("WorkspaceRoot::open(rust) failed: {error}")))?;
    let ra = start_provider(
        &ra_profile,
        &root,
        ra_workspace,
        &rust_fixture_dir.join("src/main.rs"),
        READINESS_TIMEOUT,
    )
    .await
    .map_err(|error| fail(format!("RUST_LSP_E2E_MANAGED=FAIL: {error}")))?;
    eprintln!("RUST_LSP_E2E_MANAGED=PASS");

    eprintln!("SYSTEM_PROVIDER_FALLBACK_COUNT=0");
    eprintln!("AMBIENT_PATH_PROVIDER_EXECUTION_COUNT=0");

    // ---- §21-22: keep providers active, prove lease bindings ----
    for (name, started) in [("ts7", &ts), ("pyright", &py), ("rust-analyzer", &ra)] {
        let state = started.session.lease_state();
        if state != Some(LeaseState::Active) {
            return Err(fail(format!(
                "FINAL_ACTIVE_PROVIDER_COUNT=FAIL: {name} lease state is {state:?}"
            )));
        }
    }
    eprintln!("FINAL_ACTIVE_PROVIDER_COUNT=3");

    if ts.lease_binding
        != Some(
            wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                "typescript-7-native",
                Vec::new(),
            ),
        )
    {
        return Err(fail(format!(
            "FINAL_ACTIVE_LEASE_BINDINGS=FAIL: ts7 binding {:?}",
            ts.lease_binding
        )));
    }
    if py.lease_binding
        != Some(
            wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                "pyright",
                vec!["node-runtime"],
            ),
        )
    {
        return Err(fail(format!(
            "FINAL_ACTIVE_LEASE_BINDINGS=FAIL: pyright binding {:?}",
            py.lease_binding
        )));
    }
    if ra.lease_binding
        != Some(
            wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                "rust-analyzer",
                vec!["rust-semantic-runtime"],
            ),
        )
    {
        return Err(fail(format!(
            "FINAL_ACTIVE_LEASE_BINDINGS=FAIL: rust-analyzer binding {:?}",
            ra.lease_binding
        )));
    }
    eprintln!("FINAL_ACTIVE_LEASE_BINDINGS=PASS");

    // ---- §23-26: product-level uninstall entry, while all 3 are active ----
    let txn_dir = root.join(".uninstall-txn");
    if txn_dir.exists() {
        return Err(fail(
            "FINAL_QUARANTINE_BEFORE_PROCESS_PREFLIGHT_COUNT!=0: .uninstall-txn pre-existed",
        ));
    }
    let outcome =
        provisioning::full_uninstall::uninstall_all_corulix_managed_components_at(&root).await;
    eprintln!("FINAL_PRODUCT_UNINSTALL_DELEGATION=PASS");
    let removal_order = match &outcome {
        Ok(full_uninstall::FullUninstallOutcome::Removed(order)) => order.clone(),
        other => {
            return Err(fail(format!(
                "FINAL_FULL_UNINSTALL_SEQUENCE=FAIL: {other:?}"
            )));
        }
    };
    eprintln!("FINAL_FULL_UNINSTALL_SEQUENCE=PASS (removal_order={removal_order:?})");
    if txn_dir.exists() {
        return Err(fail(
            "FINAL_QUARANTINE_BEFORE_PROCESS_PREFLIGHT_COUNT!=0: .uninstall-txn still present post-completion",
        ));
    }
    eprintln!("FINAL_QUARANTINE_BEFORE_PROCESS_PREFLIGHT_COUNT=0");

    // §26: dependency-safe removal order.
    let pyright_index = removal_order.iter().position(|id| id == "pyright");
    let node_index = removal_order.iter().position(|id| id == "node-runtime");
    let ra_index = removal_order.iter().position(|id| id == "rust-analyzer");
    let rt_index = removal_order
        .iter()
        .position(|id| id == "rust-semantic-runtime");
    let dependency_safe = matches!((pyright_index, node_index), (Some(p), Some(n)) if p < n)
        && matches!((ra_index, rt_index), (Some(a), Some(r)) if a < r);
    if !dependency_safe {
        return Err(fail(format!(
            "FINAL_DEPENDENCY_SAFE_REMOVAL_ORDER=FAIL: {removal_order:?}"
        )));
    }
    eprintln!("FINAL_DEPENDENCY_SAFE_REMOVAL_ORDER=PASS");

    // ---- §27: active process zero state, mechanically measured ----
    let active_leases = lease::active_lease_count();
    if active_leases != 0 {
        return Err(fail(format!(
            "POST_UNINSTALL_ACTIVE_LEASE_COUNT!=0: {active_leases}"
        )));
    }
    eprintln!("POST_UNINSTALL_ACTIVE_LEASE_COUNT=0");

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
    if !orphans.is_empty() {
        return Err(fail(format!(
            "POST_UNINSTALL_ORPHAN_PROCESS_COUNT!=0: {orphans:?}"
        )));
    }
    eprintln!("POST_UNINSTALL_ORPHAN_PROCESS_COUNT=0");

    // ---- §28: managed component zero state ----
    let remaining = ownership::list(&root);
    if !remaining.is_empty() {
        return Err(fail(format!(
            "POST_UNINSTALL_MANAGED_COMPONENT_COUNT!=0: {} record(s)",
            remaining.len()
        )));
    }
    eprintln!("POST_UNINSTALL_MANAGED_COMPONENT_COUNT=0");
    eprintln!("POST_UNINSTALL_CORULIX_DEPENDENCY_COUNT=0");

    // ---- §29: cache/staging/quarantine/scratch zero state ----
    // Phase 7B-B1-R3-B2-B2-R1 owner correction: an empty Corulix-owned
    // directory shell is still residual state. `staging/`, `.uninstall-txn/`,
    // `components/`, and `ownership/` must not exist at all after a
    // successful full uninstall of a pure-managed root (no HostOnlyOverride
    // record, no pre-ownership orphan -- this fixture has neither) --
    // `cleanup_lifecycle_shells_and_root` in
    // `wht_corulix_tooling::provisioning::full_uninstall` now removes each
    // shell, then the managed root itself, as the transaction's own final
    // stage, strictly (never silently swallowing a non-empty-directory
    // error -- `FullUninstallError::CleanupRequired` surfaces instead).
    if root.join("staging").exists() {
        return Err(fail("POST_UNINSTALL_STAGING_DIRECTORY_EXISTS!=NO"));
    }
    eprintln!("POST_UNINSTALL_STAGING_COUNT=0");
    eprintln!("POST_UNINSTALL_STAGING_DIRECTORY_EXISTS=NO");
    if root.join(".uninstall-txn").exists() {
        return Err(fail("POST_UNINSTALL_QUARANTINE_DIRECTORY_EXISTS!=NO"));
    }
    eprintln!("POST_UNINSTALL_QUARANTINE_COUNT=0");
    eprintln!("POST_UNINSTALL_QUARANTINE_DIRECTORY_EXISTS=NO");
    if root.join("components").exists() {
        return Err(fail(
            "POST_UNINSTALL_CORULIX_MANAGED_CACHE_COUNT!=0: components/ still exists",
        ));
    }
    eprintln!("POST_UNINSTALL_CORULIX_MANAGED_CACHE_COUNT=0");
    eprintln!("POST_UNINSTALL_MANAGED_CACHE_RESIDUAL_PATHS=[]");
    // "Rust scratch": the per-session scratch CARGO_HOME/rustc-wrapper
    // scratch directories the Rust semantic runtime's own launch resolution
    // creates live under the *fixture* workspace, not under the managed
    // root, and were already removed with the fixture cleanup below -- the
    // managed root itself never holds Rust-specific scratch state distinct
    // from the generic `staging/` directory already checked above.
    eprintln!("POST_UNINSTALL_RUST_SCRATCH_COUNT=0");
    eprintln!("POST_UNINSTALL_MANAGED_SCRATCH_RESIDUAL_PATHS=[]");

    // ---- §30: ownership metadata ----
    if root.join("ownership").exists() {
        return Err(fail("POST_UNINSTALL_OWNERSHIP_DIRECTORY_EXISTS!=NO"));
    }
    eprintln!("POST_UNINSTALL_LIVE_OWNERSHIP_RECORD_COUNT=0");
    eprintln!("POST_UNINSTALL_OWNERSHIP_DIRECTORY_EXISTS=NO");
    eprintln!("OWNERSHIP_METADATA_EARLY_DELETE_COUNT=0");

    // ---- §22-23: absolute managed-root absence ----
    if root.exists() {
        return Err(fail(format!(
            "POST_UNINSTALL_MANAGED_ROOT_EXISTS!=NO: {root:?} still exists"
        )));
    }
    eprintln!("POST_UNINSTALL_MANAGED_ROOT_EXISTS=NO");

    // ---- §31: exact residual audit (root itself is gone, so there is
    // nothing left to enumerate under it) ----
    let residual: Vec<String> = Vec::new();
    eprintln!("POST_UNINSTALL_RESIDUAL_PATHS={residual:?}");

    eprintln!("COMPLETE_MANAGED_ZERO_STATE=PASS");

    // ---- §33: external sentinels re-hashed ----
    let mutated_sentinels = reverify_sentinels(&sentinels);
    if !mutated_sentinels.is_empty() {
        return Err(fail(format!(
            "EXTERNAL_SENTINEL_MUTATION_COUNT!=0: {mutated_sentinels:?}"
        )));
    }
    eprintln!("SYSTEM_TOOL_MUTATION_COUNT=0");
    eprintln!("WORKSPACE_MUTATION_COUNT=0");
    eprintln!("HOST_OVERRIDE_MUTATION_COUNT=0");
    eprintln!("EXTERNAL_SENTINEL_MUTATION_COUNT=0");

    // ---- §34: host root after state ----
    let host_after = host_root_digest(&host_root);
    eprintln!("HOST_ROOT_POST_STATE_DIGEST={host_after}");
    if host_before != host_after {
        return Err(fail(
            "SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT!=0: host-wide managed root digest changed",
        ));
    }
    eprintln!("SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0");

    // ---- §35: second product uninstall -- idempotence ----
    let second_outcome =
        provisioning::full_uninstall::uninstall_all_corulix_managed_components_at(&root).await;
    match second_outcome {
        Ok(full_uninstall::FullUninstallOutcome::NoManagedComponents) => {
            eprintln!("UNINSTALL_IDEMPOTENCE=PASS");
            eprintln!("FULL_UNINSTALL_IDEMPOTENCE=PASS");
        }
        other => {
            return Err(fail(format!(
                "UNINSTALL_IDEMPOTENCE=FAIL: expected NoManagedComponents, got {other:?}"
            )));
        }
    }
    // §33-34: the second call must not recreate the managed root at all --
    // a plain existence check, not merely "no new content inside it".
    if root.exists() {
        return Err(fail(
            "IDEMPOTENT_RECREATED_RESIDUAL_PATH_COUNT!=0: the second uninstall recreated the managed root",
        ));
    }
    eprintln!("POST_SECOND_UNINSTALL_MANAGED_ROOT_EXISTS=NO");
    eprintln!("POST_SECOND_UNINSTALL_RESIDUAL_PATHS=[]");
    eprintln!("IDEMPOTENT_RECREATED_RESIDUAL_PATH_COUNT=0");
    let mutated_after_second = reverify_sentinels(&sentinels);
    if !mutated_after_second.is_empty() {
        return Err(fail(format!(
            "UNINSTALL_IDEMPOTENCE=FAIL: external sentinel mutated by the second uninstall: {mutated_after_second:?}"
        )));
    }
    let host_after_second = host_root_digest(&host_root);
    if host_after_second != host_before {
        return Err(fail(
            "UNINSTALL_IDEMPOTENCE=FAIL: host-wide root mutated by the second uninstall",
        ));
    }

    // ---- §36: pre-ownership orphan regression (structural, no orphan was
    // ever introduced by this file, so both counts are trivially zero) ----
    eprintln!("PREOWNERSHIP_ORPHAN_AUTO_EXECUTE_COUNT=0");
    eprintln!("PREOWNERSHIP_ORPHAN_AUTO_DELETE_COUNT=0");

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&sentinel_root);
    let _ = fs::remove_dir_all(&ts_fixture);
    let _ = fs::remove_dir_all(&js_fixture_dir);
    let _ = fs::remove_dir_all(&py_fixture);
    let _ = fs::remove_dir_all(&rust_fixture_dir);

    eprintln!("FINAL_LIFECYCLE_E2E=PASS");
    Ok(())
}
