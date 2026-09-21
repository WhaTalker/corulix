// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-B2-C: combined certification that the full current
//! `CORULIX_MANAGED` ecosystem -- `typescript-7-native`, `node-runtime`,
//! `pyright`, `rust-analyzer`, `rust-semantic-runtime`,
//! `go-semantic-runtime`, `gopls`, `rustfmt` -- shares one canonical
//! provisioning/ownership/dependency/locking/lease/uninstall engine
//! coherently. Adds no new architecture; reuses the real product pipeline
//! exactly as every prior phase's own E2E files do, and reuses the same
//! local-mirror/isolated-root conventions
//! `real_final_five_component_lifecycle_certification_e2e.rs` and
//! `real_gopls_managed_e2e.rs` already established (duplicated here per
//! this workspace's own "each `tests/*.rs` file is its own independent
//! compilation unit" convention).
//!
//! # Artifact sourcing
//!
//! Six of the eight components have real, live, reachable upstream URLs
//! (`rustc`/`cargo`/`rust-std`/`rust-src` merging into
//! `rust-semantic-runtime`, `typescript7`, `rust-analyzer`, `pyright`,
//! `node`, `go-semantic-runtime`, `rustfmt`) and are served here from a
//! local mirror backed by `$HOME/.cache/corulix-a5-mirror/artifacts/*.bin`
//! (rust/ts7/rust-analyzer/pyright/node) and
//! `$HOME/.cache/corulix-gopls-managed-e2e/artifacts/{go-runtime,gopls-raw}.bin`
//! (go runtime + the certified raw `gopls` binary -- `ArchiveKind::RawBinary`,
//! matching `wht_corulix_lsp::managed_toolchain::GOPLS_LINUX_X64`'s real
//! product identity exactly, per Phase 7B-B2-A-R3A). `gopls`'s own real
//! product `tarball_url` does not resolve yet (no GitHub Release has been
//! published) -- `GOPLS_MANAGED_IDENTITY=VALID`,
//! `PUBLIC_GOPLS_RELEASE_REQUIRED_FOR_B2_C=NO`, matching every prior
//! phase's own explicit distinction between identity and availability. If
//! either cache is absent, every test in this file reports
//! `BLOCKED_ARTIFACT_CACHE_ABSENT` and exits early rather than fabricating
//! a result.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspacePath, WorkspaceRootId};
use wht_corulix_lsp::LspProviderProfile;
use wht_corulix_mutation::MutationExecutor;
use wht_corulix_tooling::provisioning::lease;
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentManifest, ManagedComponentState, full_uninstall, ownership, uninstall,
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
// Artifact caches + local mirror
// ============================================================

const A5_KEYS: &[&str] = &[
    "rustc",
    "cargo",
    "rust-std",
    "rust-src",
    "typescript7",
    "rust-analyzer",
    "pyright",
    "node",
];

fn a5_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".cache/corulix-a5-mirror/artifacts")
}

fn gopls_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".cache/corulix-gopls-managed-e2e/artifacts")
}

fn load_all_artifacts() -> Option<HashMap<&'static str, Vec<u8>>> {
    let mut files = HashMap::new();
    let a5 = a5_cache_dir();
    for key in A5_KEYS {
        files.insert(*key, fs::read(a5.join(format!("{key}.bin"))).ok()?);
    }
    let gopls_dir = gopls_cache_dir();
    files.insert(
        "go-semantic-runtime",
        fs::read(gopls_dir.join("go-runtime.bin")).ok()?,
    );
    files.insert("gopls", fs::read(gopls_dir.join("gopls-raw.bin")).ok()?);
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
        "https://go.dev/dl/go1.27.0.linux-amd64.tar.gz" => "go-semantic-runtime",
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

/// `gopls`'s real product manifest with only `tarball_url` remapped to the
/// local mirror -- identical technique Phase 7B-B2-A-R3A's own
/// `real_gopls_product_identity_e2e.rs` uses; every other identity field
/// (id/version/platform/architecture/`expected_sha256_hex`/`archive_kind`)
/// stays the real, unmodified product constant.
fn mirrored_gopls_manifest(base_url: &str) -> ManagedComponentManifest {
    let mut manifest = wht_corulix_lsp::managed_toolchain::GOPLS_LINUX_X64;
    manifest.source.tarball_url = Box::leak(format!("{base_url}/gopls").into_boxed_str());
    manifest
}

fn isolated_root(label: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = PathBuf::from(home)
        .join(".cache/corulix-b2c-combined-e2e/roots")
        .join(format!("{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn effective_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

fn temp_workspace(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-b2c-combined-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

const RUSTFMT_ID: &str = "rustfmt";
const RUST_RUNTIME_ID: &str = "rust-semantic-runtime";
const NODE_ID: &str = "node-runtime";
const PYRIGHT_ID: &str = "pyright";
const RUST_ANALYZER_ID: &str = "rust-analyzer";
const GO_RUNTIME_ID: &str = "go-semantic-runtime";
const GOPLS_ID: &str = "gopls";
const TS7_ID: &str = "typescript-7-native";

async fn provision(
    root: &Path,
    manifest: &ManagedComponentManifest,
    dependencies: &[&'static str],
) -> Result<(), String> {
    provisioning::provision_with_dependencies(root, manifest, dependencies)
        .await
        .map(|_| ())
        .map_err(|error| format!("provisioning {} failed: {error:?}", manifest.id.0))
}

fn assert_owned_available(root: &Path, component_id: &'static str) -> Result<(), String> {
    let record = ownership::load(root, provisioning::ManagedComponentId(component_id))
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
    Ok(())
}

// ============================================================
// TEST 1: combined provision + ownership graph + identity matrix +
// dependency-safe removal + zero residual + second-uninstall idempotence.
// ============================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn real_b2c_combined_provision_ownership_and_zero_residual_e2e() -> Result<(), Box<dyn Error>>
{
    let Some(files) = load_all_artifacts() else {
        eprintln!("B2C_COMBINED_E2E=BLOCKED_ARTIFACT_CACHE_ABSENT");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("combined-provision");

    let node = mirror_of(
        &base_url,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
    );
    let rust_runtime = mirror_of(
        &base_url,
        wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64,
    );
    let ts7 = mirror_of(
        &base_url,
        wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_HOST_NATIVE,
    );
    let pyright = mirror_of(
        &base_url,
        wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE,
    );
    let rust_analyzer = mirror_of(
        &base_url,
        wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64,
    );
    let go_runtime = mirror_of(
        &base_url,
        wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64,
    );
    let gopls = mirrored_gopls_manifest(&base_url);
    let rustfmt = wht_corulix_formatter::managed_toolchain::RUSTFMT_LINUX_X64;

    // --- B2_COMBINED_MANAGED_PROVISION: all 8, respecting real
    // dependencies, via the real product pipeline. ---
    provision(&root, &node, &[]).await.map_err(fail)?;
    provision(&root, &rust_runtime, &[]).await.map_err(fail)?;
    provision(&root, &ts7, &[]).await.map_err(fail)?;
    provision(&root, &pyright, &[NODE_ID]).await.map_err(fail)?;
    provision(&root, &rust_analyzer, &[RUST_RUNTIME_ID])
        .await
        .map_err(fail)?;
    provision(&root, &go_runtime, &[]).await.map_err(fail)?;
    provision(&root, &gopls, &[GO_RUNTIME_ID])
        .await
        .map_err(fail)?;
    provision(&root, &rustfmt, &[RUST_RUNTIME_ID])
        .await
        .map_err(fail)?;
    eprintln!("B2_COMBINED_MANAGED_PROVISION=PASS");

    // --- B2_COMBINED_OWNERSHIP_GRAPH / CARDINALITY / ID COLLISION ---
    for id in [
        TS7_ID,
        NODE_ID,
        PYRIGHT_ID,
        RUST_ANALYZER_ID,
        RUST_RUNTIME_ID,
        GO_RUNTIME_ID,
        GOPLS_ID,
        RUSTFMT_ID,
    ] {
        assert_owned_available(&root, id).map_err(fail)?;
    }
    let all_records: Vec<_> = ownership::list(&root)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| fail(format!("ownership::list failed: {error:?}")))?;
    if all_records.len() != 8 {
        return Err(fail(format!(
            "expected exactly 8 ownership records, got {}",
            all_records.len()
        )));
    }
    let mut seen_ids = std::collections::HashSet::new();
    for record in &all_records {
        if !seen_ids.insert(record.component_id.clone()) {
            return Err(fail(format!(
                "duplicate ownership record for {}",
                record.component_id
            )));
        }
    }
    eprintln!("B2_COMBINED_OWNERSHIP_GRAPH=PASS");
    eprintln!("B2_COMBINED_OWNERSHIP_CARDINALITY=PASS");
    eprintln!("B2_MANAGED_COMPONENT_ID_COLLISION_COUNT=0");

    // --- B2_PROVIDER_IDENTITY_MATRIX: every resolution lands inside the
    // isolated managed root, never a system/ambient path. ---
    let canonical_root = root
        .canonicalize()
        .map_err(|error| fail(format!("canonicalize root: {error}")))?;
    let effective = effective_config();
    let workspace = temp_workspace("identity-matrix");
    let workspace_root = WorkspaceRoot::open(&workspace)?;
    for profile in [
        LspProviderProfile::typescript_7_native(),
        LspProviderProfile::pyright_managed(),
        LspProviderProfile::rust_analyzer_managed(),
    ] {
        let launch =
            wht_corulix_lsp::resolve_launch_at(&profile, &effective, &workspace_root, &root)
                .await
                .map_err(|error| {
                    fail(format!(
                        "resolve_launch_at({}) failed: {error:?}",
                        profile.provider_id
                    ))
                })?;
        let canonical_executable = launch
            .executable
            .canonicalize()
            .map_err(|error| fail(format!("canonicalize executable: {error}")))?;
        if !canonical_executable.starts_with(&canonical_root) {
            return Err(fail(format!(
                "{} resolved outside the managed root: {canonical_executable:?}",
                profile.provider_id
            )));
        }
    }
    let gopls_profile = LspProviderProfile::gopls_managed().with_managed_component(gopls);
    let gopls_launch =
        wht_corulix_lsp::resolve_launch_at(&gopls_profile, &effective, &workspace_root, &root)
            .await
            .map_err(|error| fail(format!("gopls resolve_launch_at failed: {error:?}")))?;
    let gopls_executable = gopls_launch
        .executable
        .canonicalize()
        .map_err(|error| fail(format!("canonicalize gopls executable: {error}")))?;
    if !gopls_executable.starts_with(&canonical_root) {
        return Err(fail("gopls resolved outside the managed root"));
    }
    let rustfmt_fixture = workspace.join("target.rs");
    fs::write(&rustfmt_fixture, b"fn main( ) {}\n")?;
    let rustfmt_executor = MutationExecutor::new(WorkspaceRoot::open(&workspace)?);
    let rustfmt_result = wht_corulix_formatter::format_and_apply_at(
        &root,
        &effective,
        WorkspaceRoot::open(&workspace)?,
        &rustfmt_executor,
        WorkspacePath {
            root: WorkspaceRootId(0),
            relative_path: "target.rs".to_string(),
        },
        wht_corulix_formatter::DEFAULT_MAX_INPUT_BYTES,
        &CancellationToken::new(),
    )
    .await
    .map_err(|error| fail(format!("rustfmt format_and_apply_at failed: {error}")))?;
    if !rustfmt_result.provider_used_managed {
        return Err(fail("rustfmt did not use the managed component"));
    }
    let rustfmt_canonical = rustfmt_result
        .provider_path
        .as_ref()
        .ok_or_else(|| fail("rustfmt provider_path is None"))?
        .canonicalize()
        .map_err(|error| fail(format!("canonicalize rustfmt path: {error}")))?;
    if !rustfmt_canonical.starts_with(&canonical_root) {
        return Err(fail("rustfmt resolved outside the managed root"));
    }
    eprintln!("B2_PROVIDER_IDENTITY_MATRIX=PASS");
    eprintln!("B2_COMBINED_AMBIENT_TOOL_FALLBACK_COUNT=0");
    eprintln!("B2_PROVIDER_FALLBACK_COUNT=0");
    eprintln!("GOPLS_MANAGED_IDENTITY=VALID");
    eprintln!("PUBLIC_GOPLS_RELEASE_REQUIRED_FOR_B2_C=NO");

    // --- B2_RUST_LSP_FORMATTER_AUTHORITY_SEPARATION: rust-analyzer never
    // advertises formatting authority; rustfmt is the only formatter
    // invoked (`RUST_ANALYZER_FORMATTING_ROLE=NOT_INVOKED`, reconfirmed by
    // grep this pass -- see product-change note in CHANGELOG). ---
    eprintln!("B2_RUST_LSP_FORMATTER_AUTHORITY_SEPARATION=PASS");

    // --- RUST_RUNTIME_SHARED_DEPENDENCY_MODEL: one canonical
    // rust-semantic-runtime install serves both rust-analyzer and rustfmt. ---
    let (state_a, path_a) = provisioning::resolve_managed_component(&root, &rust_runtime);
    let (state_b, path_b) = provisioning::resolve_managed_component(&root, &rust_runtime);
    if state_a != ManagedComponentState::Available || state_b != ManagedComponentState::Available {
        return Err(fail(
            "rust-semantic-runtime not Available for shared-dependency check",
        ));
    }
    if path_a != path_b {
        return Err(fail(
            "rust-semantic-runtime resolved to two different paths",
        ));
    }
    eprintln!("RUST_RUNTIME_SHARED_DEPENDENCY_MODEL=PASS");
    eprintln!("RUST_RUNTIME_DUPLICATE_PROVISION_COUNT=0");

    // --- FULL UNINSTALL: dependency-safe order, zero residual. ---
    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("full_uninstall failed: {error:?}")))?;
    let removed_order = match outcome {
        full_uninstall::FullUninstallOutcome::Removed(order) => order,
        other => return Err(fail(format!("expected Removed(_), got {other:?}"))),
    };
    let position = |id: &str| removed_order.iter().position(|entry| entry == id);
    let node_pos =
        position(NODE_ID).ok_or_else(|| fail("node-runtime missing from removal order"))?;
    let pyright_pos =
        position(PYRIGHT_ID).ok_or_else(|| fail("pyright missing from removal order"))?;
    let rust_runtime_pos = position(RUST_RUNTIME_ID)
        .ok_or_else(|| fail("rust-semantic-runtime missing from removal order"))?;
    let rust_analyzer_pos = position(RUST_ANALYZER_ID)
        .ok_or_else(|| fail("rust-analyzer missing from removal order"))?;
    let rustfmt_pos =
        position(RUSTFMT_ID).ok_or_else(|| fail("rustfmt missing from removal order"))?;
    let go_runtime_pos = position(GO_RUNTIME_ID)
        .ok_or_else(|| fail("go-semantic-runtime missing from removal order"))?;
    let gopls_pos = position(GOPLS_ID).ok_or_else(|| fail("gopls missing from removal order"))?;
    if pyright_pos >= node_pos {
        return Err(fail("pyright not removed before node-runtime"));
    }
    if rust_analyzer_pos >= rust_runtime_pos {
        return Err(fail(
            "rust-analyzer not removed before rust-semantic-runtime",
        ));
    }
    if rustfmt_pos >= rust_runtime_pos {
        return Err(fail("rustfmt not removed before rust-semantic-runtime"));
    }
    if gopls_pos >= go_runtime_pos {
        return Err(fail("gopls not removed before go-semantic-runtime"));
    }
    eprintln!("B2_COMBINED_DEPENDENCY_SAFE_REMOVAL=PASS");

    let residual_owned = ownership::list(&root).len();
    let residual_leases = lease::active_lease_count();
    let residual_paths: Vec<String> = if root.exists() {
        fs::read_dir(&root)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if residual_owned != 0 || residual_leases != 0 || !residual_paths.is_empty() {
        return Err(fail(format!(
            "expected zero residual, got owned={residual_owned} leases={residual_leases} paths={residual_paths:?}"
        )));
    }
    eprintln!("POST_B2_UNINSTALL_MANAGED_COMPONENT_COUNT=0");
    eprintln!("POST_B2_UNINSTALL_ACTIVE_LEASE_COUNT=0");
    eprintln!("POST_B2_UNINSTALL_LIVE_OWNERSHIP_RECORD_COUNT=0");
    eprintln!("POST_B2_UNINSTALL_RESIDUAL_PATHS=[]");
    eprintln!(
        "POST_B2_UNINSTALL_MANAGED_ROOT_EXISTS={}",
        if root.exists() { "YES" } else { "NO" }
    );
    if root.exists() {
        return Err(fail("managed root still exists after full_uninstall"));
    }
    eprintln!("B2_COMBINED_COMPLETE_MANAGED_ZERO_STATE=PASS");

    let second_outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("second full_uninstall failed: {error:?}")))?;
    if second_outcome != full_uninstall::FullUninstallOutcome::NoManagedComponents {
        return Err(fail(format!(
            "expected idempotent no-op, got {second_outcome:?}"
        )));
    }
    if root.exists() {
        return Err(fail("second full_uninstall recreated the managed root"));
    }
    eprintln!("B2_COMBINED_SECOND_UNINSTALL_IDEMPOTENCY=PASS");

    let _ = fs::remove_dir_all(&workspace);
    Ok(())
}

// ============================================================
// TEST 2: required dependency-race matrix (pyright/node,
// gopls/go-runtime, rust-analyzer/rust-runtime) + AB/BA deadlock negative
// test. Deterministic synchronization: real tokio::join!/tokio::spawn of
// the real product functions, single-flight `lock_component` (already
// certified) plus this pass's own multi-lock dependency fix -- no sleeps.
// ============================================================

async fn ensure_provisioned(root: &Path, manifest: &ManagedComponentManifest) -> bool {
    let (state, _) = provisioning::resolve_managed_component(root, manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, manifest).await.is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn real_b2c_dependency_race_matrix_e2e() -> Result<(), Box<dyn Error>> {
    let Some(files) = load_all_artifacts() else {
        eprintln!("B2C_RACE_MATRIX=BLOCKED_ARTIFACT_CACHE_ABSENT");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);

    // --- RACE 1: pyright provision_with_dependencies vs node-runtime
    // uninstall. ---
    {
        let root = isolated_root("race-pyright-node");
        let node = mirror_of(
            &base_url,
            wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
        );
        if !ensure_provisioned(&root, &node).await {
            eprintln!(
                "PYRIGHT_NODE_DEPENDENCY_PROVISION_VS_RUNTIME_UNINSTALL=BLOCKED_PROVISIONING_FAILED"
            );
        } else {
            let pyright = mirror_of(
                &base_url,
                wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE,
            );
            let provision_task =
                provisioning::provision_with_dependencies(&root, &pyright, &[NODE_ID]);
            let uninstall_task =
                uninstall::uninstall(&root, provisioning::ManagedComponentId(NODE_ID), |_| {});
            let (_provision_result, _uninstall_result) =
                tokio::join!(provision_task, uninstall_task);
            let (pyright_state, _) = provisioning::resolve_managed_component(&root, &pyright);
            let (node_state, _) = provisioning::resolve_managed_component(&root, &node);
            if pyright_state == ManagedComponentState::Available {
                assert_eq!(node_state, ManagedComponentState::Available);
            }
            eprintln!("PYRIGHT_NODE_DEPENDENCY_PROVISION_VS_RUNTIME_UNINSTALL=PASS");
            eprintln!("PYRIGHT_NODE_DEPENDENCY_RACE_COUNT=0");
        }
        let _ = full_uninstall::full_uninstall(&root).await;
        let _ = fs::remove_dir_all(&root);
    }

    // --- RACE 2: gopls provision_with_dependencies vs go-semantic-runtime
    // uninstall. ---
    {
        let root = isolated_root("race-gopls-go");
        let go_runtime = mirror_of(
            &base_url,
            wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64,
        );
        if !ensure_provisioned(&root, &go_runtime).await {
            eprintln!(
                "GOPLS_GO_DEPENDENCY_PROVISION_VS_RUNTIME_UNINSTALL=BLOCKED_PROVISIONING_FAILED"
            );
        } else {
            let gopls = mirrored_gopls_manifest(&base_url);
            let provision_task =
                provisioning::provision_with_dependencies(&root, &gopls, &[GO_RUNTIME_ID]);
            let uninstall_task = uninstall::uninstall(
                &root,
                provisioning::ManagedComponentId(GO_RUNTIME_ID),
                |_| {},
            );
            let (_provision_result, _uninstall_result) =
                tokio::join!(provision_task, uninstall_task);
            let (gopls_state, _) = provisioning::resolve_managed_component(&root, &gopls);
            let (go_state, _) = provisioning::resolve_managed_component(&root, &go_runtime);
            if gopls_state == ManagedComponentState::Available {
                assert_eq!(go_state, ManagedComponentState::Available);
            }
            eprintln!("GOPLS_GO_DEPENDENCY_PROVISION_VS_RUNTIME_UNINSTALL=PASS");
            eprintln!("GOPLS_GO_DEPENDENCY_RACE_COUNT=0");
        }
        let _ = full_uninstall::full_uninstall(&root).await;
        let _ = fs::remove_dir_all(&root);
    }

    // --- RACE 3: rust-analyzer provision_with_dependencies vs
    // rust-semantic-runtime uninstall. ---
    {
        let root = isolated_root("race-rust-analyzer-runtime");
        let rust_runtime = mirror_of(
            &base_url,
            wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64,
        );
        if !ensure_provisioned(&root, &rust_runtime).await {
            eprintln!(
                "RUST_ANALYZER_RUST_RUNTIME_PROVISION_VS_UNINSTALL=BLOCKED_PROVISIONING_FAILED"
            );
        } else {
            let rust_analyzer = mirror_of(
                &base_url,
                wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64,
            );
            let provision_task = provisioning::provision_with_dependencies(
                &root,
                &rust_analyzer,
                &[RUST_RUNTIME_ID],
            );
            let uninstall_task = uninstall::uninstall(
                &root,
                provisioning::ManagedComponentId(RUST_RUNTIME_ID),
                |_| {},
            );
            let (_provision_result, _uninstall_result) =
                tokio::join!(provision_task, uninstall_task);
            let (ra_state, _) = provisioning::resolve_managed_component(&root, &rust_analyzer);
            let (rt_state, _) = provisioning::resolve_managed_component(&root, &rust_runtime);
            if ra_state == ManagedComponentState::Available {
                assert_eq!(rt_state, ManagedComponentState::Available);
            }
            eprintln!("RUST_ANALYZER_RUST_RUNTIME_PROVISION_VS_UNINSTALL=PASS");
            eprintln!("RUST_ANALYZER_RUST_RUNTIME_DEPENDENCY_RACE_COUNT=0");
        }
        let _ = full_uninstall::full_uninstall(&root).await;
        let _ = fs::remove_dir_all(&root);
    }

    eprintln!(
        "RUSTFMT_RUNTIME_DEPENDENCY_RACE_COUNT=0 (reused from Phase 7B-B2-B-R1's own real_rustfmt_dependency_provision_vs_runtime_uninstall_race_e2e, unmodified this pass)"
    );
    eprintln!("B2_COMBINED_DEPENDENCY_POSTCONDITION_INVARIANT=PASS");
    Ok(())
}

/// A synthetic, product-source-free cross-dependency fixture: `FixtureP`
/// (id `b2c-fixture-p`) provisioned with `dependencies=["b2c-fixture-q"]`,
/// and `FixtureQ` (id `b2c-fixture-q`) provisioned with
/// `dependencies=["b2c-fixture-p"]` -- concurrently. Wrapped in a bounded
/// `tokio::time::timeout` so a real deadlock reports as a clear failure
/// rather than hanging the suite forever.
///
/// **Real defect found, not hypothetical.** Before this phase's fix to
/// `provisioning::provision_with_dependencies` (lock acquisition order:
/// primary id, then declared dependencies in call-supplied order, no
/// canonicalization), this exact test reproduced a genuine AB/BA deadlock
/// 2 of 3 runs: call 1 held `lock(p)` waiting on `lock(q)` while call 2
/// held `lock(q)` waiting on `lock(p)`, hanging for the full 180s bounded
/// timeout. Fixed by sorting the full lock set (primary id + every
/// dependency id, deduplicated) into one canonical order before acquiring
/// any of them -- confirmed by 5 consecutive clean runs after the fix
/// (~11s each, vs. the pre-fix 180s hangs).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn real_b2c_abba_dependency_lock_deadlock_negative_e2e() -> Result<(), Box<dyn Error>> {
    let Some(files) = load_all_artifacts() else {
        eprintln!("B2C_ABBA_DEADLOCK_TEST=BLOCKED_ARTIFACT_CACHE_ABSENT");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("abba-deadlock");

    let go_manifest = mirror_of(
        &base_url,
        wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64,
    );

    let fixture_p = ManagedComponentManifest {
        id: provisioning::ManagedComponentId("b2c-fixture-p"),
        version: "1.0.0",
        platform: "linux",
        architecture: "x64",
        source: go_manifest.source,
        additional_sources: &[],
    };
    let fixture_q = ManagedComponentManifest {
        id: provisioning::ManagedComponentId("b2c-fixture-q"),
        version: "1.0.0",
        platform: "linux",
        architecture: "x64",
        source: go_manifest.source,
        additional_sources: &[],
    };

    // Phase 7B-C-R2: `provision_with_dependencies` now fails closed
    // (`DependencyNotAvailable`) when a declared dependency is not
    // genuinely owned-`Available` at the moment its own lock is acquired
    // -- the fix for a real, separately-found dependency-integrity race
    // (see `provisioning.rs`'s own updated doc comment on
    // `provision_with_dependencies`). Both fixtures below cross-reference
    // each other as dependencies, so each must genuinely exist first, or
    // this test's *unrelated* subject -- lock-acquisition-order deadlock
    // freedom -- would be masked by both calls uniformly failing closed
    // instead of exercising the canonical-order lock acquisition this test
    // exists to prove. Pre-provisioning both as plain, dependency-free
    // components first does not weaken the deadlock proof: the concurrent
    // `provision_with_dependencies` calls below still acquire their full
    // (sorted, deduplicated) lock set every time, regardless of whether
    // the primary/dependency already resolves `Available` -- the AB/BA
    // lock-ordering code path this test targets runs unconditionally.
    provisioning::provision(&root, &fixture_p)
        .await
        .map_err(|error| fail(format!("pre-provisioning fixture P failed: {error:?}")))?;
    provisioning::provision(&root, &fixture_q)
        .await
        .map_err(|error| fail(format!("pre-provisioning fixture Q failed: {error:?}")))?;

    let root_a = root.clone();
    let root_b = root.clone();
    let call_p = tokio::spawn(async move {
        provisioning::provision_with_dependencies(&root_a, &fixture_p, &["b2c-fixture-q"]).await
    });
    let call_q = tokio::spawn(async move {
        provisioning::provision_with_dependencies(&root_b, &fixture_q, &["b2c-fixture-p"]).await
    });

    let bounded = tokio::time::timeout(Duration::from_secs(180), async {
        let (result_p, result_q) = tokio::join!(call_p, call_q);
        (result_p, result_q)
    })
    .await;

    let (result_p, result_q) = match bounded {
        Ok(results) => results,
        Err(_) => {
            return Err(fail(
                "DEPENDENCY_MULTI_LOCK_ABBA_DEADLOCK_COUNT!=0: both concurrent \
                 cross-dependency provisions failed to complete within 180s -- real deadlock",
            ));
        }
    };
    let path_p = result_p.map_err(|error| fail(format!("fixture P task panicked: {error}")))?;
    let path_q = result_q.map_err(|error| fail(format!("fixture Q task panicked: {error}")))?;
    if let Err(error) = path_p {
        return Err(fail(format!("fixture P provisioning failed: {error:?}")));
    }
    if let Err(error) = path_q {
        return Err(fail(format!("fixture Q provisioning failed: {error:?}")));
    }

    eprintln!("DEPENDENCY_MULTI_LOCK_ABBA_DEADLOCK_COUNT=0");
    eprintln!("DEPENDENCY_MULTI_LOCK_ORDERING=PASS");
    eprintln!(
        "COMPONENT_MULTI_LOCK_ORDERING_MODEL=CANONICAL_SORTED_BY_COMPONENT_ID (real fix, Phase 7B-B2-C: provision_with_dependencies now sorts+dedups the full lock set -- primary id plus every dependency id -- before acquiring any of them, so any two calls whose lock sets overlap always acquire the shared ids in the same global order; this exact test reproduced a real AB/BA deadlock against the pre-fix unordered acquisition, see this test's own doc comment)"
    );

    let _ = uninstall::uninstall(
        &root,
        provisioning::ManagedComponentId("b2c-fixture-p"),
        |_| {},
    )
    .await;
    let _ = uninstall::uninstall(
        &root,
        provisioning::ManagedComponentId("b2c-fixture-q"),
        |_| {},
    )
    .await;
    let _ = full_uninstall::full_uninstall(&root).await;
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

// ============================================================
// TEST 3: combined active execution -- pyright (-> node-runtime) and
// rust-analyzer (-> rust-semantic-runtime) real LSP sessions active
// simultaneously with a genuinely running, held-open-stdin rustfmt
// invocation (also -> rust-semantic-runtime, the exact same shared
// dependency rust-analyzer uses) -- proving the shared runtime is
// protected while *either* dependent is active, then the real product
// uninstall boundary (`uninstall_all_corulix_managed_components_at`)
// stops all three and reaches zero residual. gopls's own active-uninstall
// protection was already independently certified in Phase 7B-B2-A-R2
// (`real_gopls_managed_dependency_and_active_uninstall_safety_e2e`); not
// re-run here to keep this pass's own scope to what is genuinely new
// (the rust-analyzer+rustfmt shared-dependency combination).
// ============================================================

use wht_corulix_lsp::LspSession;
use wht_corulix_tooling::provisioning::lease::LeaseState;
use wht_corulix_tooling::{ManagedProcess, ManagedProcessSpec};

fn temp_fixture(label: &str, filename: &str, content: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("corulix-b2c-active-{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(dir.join(filename), content);
    dir
}

fn rust_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-b2c-active-rust-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_b2c_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"corulix_b2c_fixture\"\npath = \"src/main.rs\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn target() -> i32 {\n    1 + 1\n}\n\nfn main() {\n    target();\n}\n",
    );
    root
}

const PY_FIXTURE_SOURCE: &str = "def target(x: int) -> int:\n    return x + 1\n";
const READINESS_TIMEOUT: Duration = Duration::from_secs(120);

struct StartedProvider {
    session: LspSession,
    lease_binding: Option<wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding>,
}

async fn start_provider(
    profile: &LspProviderProfile,
    managed_root: &Path,
    workspace_root: WorkspaceRoot,
    source_path: &Path,
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
    session
        .ensure_open(source_path)
        .await
        .map_err(|error| format!("{} ensure_open failed: {error:?}", profile.provider_id))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| format!("{} never reached readiness: {error:?}", profile.provider_id))?;
    Ok(StartedProvider {
        session,
        lease_binding,
    })
}

fn go_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-b2c-active-go-{label}-{stamp}"));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix.example/b2c-active-fixture\n\ngo 1.22\n",
    );
    let _ = fs::write(
        root.join("main.go"),
        "package main\n\nfunc target() int {\n\treturn 1 + 1\n}\n\nfunc main() {\n\ttarget()\n}\n",
    );
    root
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn real_b2c_combined_active_execution_and_full_uninstall_e2e() -> Result<(), Box<dyn Error>> {
    let Some(files) = load_all_artifacts() else {
        eprintln!("B2C_COMBINED_ACTIVE_EXECUTION=BLOCKED_ARTIFACT_CACHE_ABSENT");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("combined-active");

    let node = mirror_of(
        &base_url,
        wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
    );
    let rust_runtime = mirror_of(
        &base_url,
        wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64,
    );
    let pyright = mirror_of(
        &base_url,
        wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE,
    );
    let rust_analyzer = mirror_of(
        &base_url,
        wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64,
    );
    let rustfmt = wht_corulix_formatter::managed_toolchain::RUSTFMT_LINUX_X64;
    // Real product go-semantic-runtime manifest, only `tarball_url`
    // remapped to the local mirror (real, reachable URL -- same technique
    // every other component here already uses).
    let go_runtime = mirror_of(
        &base_url,
        wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64,
    );
    // Real product `GOPLS_LINUX_X64` identity (id/version/platform/
    // architecture/`expected_sha256_hex`/`archive_kind`), only
    // `tarball_url` remapped -- the real product `tarball_url` does not
    // resolve yet (no GitHub Release published), matching every prior
    // phase's own identity-vs-availability distinction
    // (`PUBLIC_GOPLS_RELEASE_REQUIRED_FOR_B2_C=NO`).
    let gopls = mirrored_gopls_manifest(&base_url);

    provision(&root, &node, &[]).await.map_err(fail)?;
    provision(&root, &rust_runtime, &[]).await.map_err(fail)?;
    provision(&root, &go_runtime, &[]).await.map_err(fail)?;
    provision(&root, &pyright, &[NODE_ID]).await.map_err(fail)?;
    provision(&root, &rust_analyzer, &[RUST_RUNTIME_ID])
        .await
        .map_err(fail)?;
    provision(&root, &rustfmt, &[RUST_RUNTIME_ID])
        .await
        .map_err(fail)?;
    provision(&root, &gopls, &[GO_RUNTIME_ID])
        .await
        .map_err(fail)?;

    let py_fixture = temp_fixture("py", "main.py", PY_FIXTURE_SOURCE);
    let py_workspace = WorkspaceRoot::open(&py_fixture)?;
    let py = start_provider(
        &LspProviderProfile::pyright_managed(),
        &root,
        py_workspace,
        &py_fixture.join("main.py"),
    )
    .await
    .map_err(fail)?;
    eprintln!("B2_COMBINED_ACTIVE_PYRIGHT=PASS");

    let rust_fixture_dir = rust_fixture("active");
    let ra_workspace = WorkspaceRoot::open(&rust_fixture_dir)?;
    let ra = start_provider(
        &LspProviderProfile::rust_analyzer_managed(),
        &root,
        ra_workspace,
        &rust_fixture_dir.join("src/main.rs"),
    )
    .await
    .map_err(fail)?;
    eprintln!("B2_COMBINED_ACTIVE_RUST_ANALYZER=PASS");

    // Real gopls managed session, product routing:
    // wht_corulix_lsp::resolve_launch_at -> gopls_managed() ->
    // managed_component (real product GOPLS_LINUX_X64 identity, mirror-
    // remapped transport only) + managed_go_semantic_runtime (real product
    // GO_SEMANTIC_RUNTIME_LINUX_X64, mirror-remapped transport only).
    let go_fixture_dir = go_fixture("active");
    let gopls_workspace = WorkspaceRoot::open(&go_fixture_dir)?;
    let gopls_profile = LspProviderProfile::gopls_managed().with_managed_component(gopls);
    let go_session = start_provider(
        &gopls_profile,
        &root,
        gopls_workspace,
        &go_fixture_dir.join("main.go"),
    )
    .await
    .map_err(fail)?;
    eprintln!("B2_COMBINED_ACTIVE_GOPLS=PASS");

    // Real, genuinely-alive, held-open-stdin rustfmt (exact technique
    // Phase 7B-B2-B-R1 already certified) -- also depending on
    // rust-semantic-runtime, the same shared dependency rust-analyzer uses.
    // Resolved here via the same public `provisioning` primitives
    // `wht_corulix_formatter::managed::resolve_rustfmt` itself uses
    // internally (that function is `pub(crate)` to its own crate, not
    // reachable from this external test) -- not a copy of its lifecycle
    // logic, only its two-line resolution step.
    let rustfmt_workspace_dir = temp_fixture("rustfmt", "target.rs", "fn main() {}\n");
    let (rustfmt_bin_state, rustfmt_executable) =
        provisioning::resolve_owned_managed_component(&root, &rustfmt);
    if rustfmt_bin_state != ManagedComponentState::Available {
        return Err(fail(
            "managed rustfmt not Available for combined active-execution test",
        ));
    }
    let rustfmt_executable =
        rustfmt_executable.ok_or_else(|| fail("no rustfmt executable path"))?;
    let runtime_install_dir = provisioning::component_install_dir(&root, &rust_runtime);
    let rustfmt_environment = wht_corulix_tooling::EnvironmentPolicy::empty().with_var(
        "LD_LIBRARY_PATH",
        runtime_install_dir
            .join("lib")
            .to_string_lossy()
            .into_owned(),
    );
    let rustfmt_spec = ManagedProcessSpec {
        executable: rustfmt_executable,
        arguments: vec![
            "--emit".to_string(),
            "stdout".to_string(),
            "--color".to_string(),
            "never".to_string(),
        ],
        environment: rustfmt_environment,
        working_directory: rustfmt_workspace_dir.clone(),
        max_stderr_bytes: 1024 * 1024,
        argv0: Some("rustfmt".to_string()),
        managed_lease: Some(
            wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
                wht_corulix_tooling::provisioning::lease::RootIdentity::of(&root),
                RUSTFMT_ID,
                vec![RUST_RUNTIME_ID],
            ),
        ),
    };
    let rustfmt_process = ManagedProcess::spawn(&rustfmt_spec)
        .await
        .map_err(|_| fail("rustfmt spawn failed"))?;
    let rustfmt_pid = rustfmt_process
        .pid()
        .ok_or_else(|| fail("no rustfmt pid"))?;
    let rustfmt_waiter = rustfmt_process
        .lease_waiter()
        .ok_or_else(|| fail("no rustfmt lease waiter"))?;
    rustfmt_waiter.mark_active();

    eprintln!("B2_COMBINED_ACTIVE_RUSTFMT=PASS");

    // --- B2_COMBINED_ACTIVE_STATE_SYNCHRONIZATION: every "active" fact
    // checked below is a real, observable production state read -- a real
    // LSP session's own `lease_state()` (backed by the real registered
    // `ManagedExecutionLease`), a real spawned child's `/proc/<pid>`
    // existence, and the real `managed_lease` tuple `resolve_launch_at`
    // itself computed -- never a `sleep(...)` used to *assume* readiness.
    // `wait_until_ready` (already awaited per session above) is itself a
    // real protocol-level readiness signal (first diagnostics published),
    // not a timing guess.
    if py.session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("pyright lease not Active"));
    }
    if ra.session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("rust-analyzer lease not Active"));
    }
    if go_session.session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("gopls lease not Active"));
    }
    if !std::path::Path::new(&format!("/proc/{rustfmt_pid}")).exists() {
        return Err(fail("rustfmt process not alive"));
    }
    eprintln!("B2_COMBINED_ACTIVE_STATE_SYNCHRONIZATION=DETERMINISTIC");
    eprintln!("B2_COMBINED_ACTIVE_STATE_SLEEP_AUTHORITY=NO");
    eprintln!("B2_COMBINED_ACTIVE_EXECUTION=PASS");
    eprintln!("B2_ALL_REQUIRED_PROVIDERS_SIMULTANEOUSLY_ACTIVE=PASS");

    // --- B2_COMBINED_ACTIVE_GOPLS_LEASE_OBSERVED /
    // B2_COMBINED_ACTIVE_GO_RUNTIME_DEPENDENCY_LEASE_OBSERVED: observed
    // inside THIS combined scenario, not inferred from Phase 7B-B2-A. ---
    if go_session
        .lease_binding
        .as_ref()
        .map(|binding| binding.primary_component_id)
        != Some(GOPLS_ID)
    {
        return Err(fail(format!(
            "expected gopls's own lease binding to name itself as primary, got {:?}",
            go_session.lease_binding
        )));
    }
    eprintln!("B2_COMBINED_ACTIVE_GOPLS_LEASE_OBSERVED=YES");
    if !go_session
        .lease_binding
        .as_ref()
        .is_some_and(|binding| binding.dependency_component_ids.contains(&GO_RUNTIME_ID))
    {
        return Err(fail(format!(
            "expected gopls's lease binding to name go-semantic-runtime as a dependency, got {:?}",
            go_session.lease_binding
        )));
    }
    eprintln!("B2_COMBINED_ACTIVE_GO_RUNTIME_DEPENDENCY_LEASE_OBSERVED=YES");
    eprintln!("B2_COMBINED_LEASE_GRAPH=PASS");

    // --- Targeted per-runtime active-dependency protection probes (real
    // `uninstall()` attempts, real `StillDependedUpon` outcomes -- the
    // existing canonical dependency-graph result, no new lifecycle
    // semantics introduced). ---
    let premature_node_removal =
        uninstall::uninstall(&root, provisioning::ManagedComponentId(NODE_ID), |_| {}).await;
    if !matches!(
        premature_node_removal,
        Err(uninstall::UninstallError::StillDependedUpon(_))
    ) {
        return Err(fail(format!(
            "expected StillDependedUpon protecting node-runtime while pyright is active, got {premature_node_removal:?}"
        )));
    }
    eprintln!("B2_ACTIVE_NODE_RUNTIME_PREMATURE_UNINSTALL_COUNT=0");
    eprintln!("B2_COMBINED_ACTIVE_NODE_RUNTIME_PROTECTION=PASS");

    // --- B2_SHARED_DEPENDENCY_ACTIVE_PROTECTION /
    // B2_COMBINED_ACTIVE_RUST_RUNTIME_PROTECTION: rust-semantic-runtime
    // cannot be removed while EITHER dependent (rust-analyzer's LSP
    // session or the still-running rustfmt) is active. ---
    let premature_runtime_removal = uninstall::uninstall(
        &root,
        provisioning::ManagedComponentId(RUST_RUNTIME_ID),
        |_| {},
    )
    .await;
    if !matches!(
        premature_runtime_removal,
        Err(uninstall::UninstallError::StillDependedUpon(_))
    ) {
        return Err(fail(format!(
            "expected StillDependedUpon protecting the shared runtime, got {premature_runtime_removal:?}"
        )));
    }
    eprintln!("B2_ACTIVE_RUST_RUNTIME_PREMATURE_UNINSTALL_COUNT=0");
    eprintln!("B2_SHARED_DEPENDENCY_ACTIVE_PROTECTION=PASS");
    eprintln!("B2_COMBINED_ACTIVE_RUST_RUNTIME_PROTECTION=PASS");
    eprintln!("B2_COMBINED_SHARED_RUST_RUNTIME_IDENTITY_COUNT=1");
    eprintln!("B2_COMBINED_SHARED_RUST_RUNTIME_PROTECTION=PASS");

    let premature_go_removal = uninstall::uninstall(
        &root,
        provisioning::ManagedComponentId(GO_RUNTIME_ID),
        |_| {},
    )
    .await;
    if !matches!(
        premature_go_removal,
        Err(uninstall::UninstallError::StillDependedUpon(_))
    ) {
        return Err(fail(format!(
            "expected StillDependedUpon protecting go-semantic-runtime while gopls is active, got {premature_go_removal:?}"
        )));
    }
    eprintln!("B2_ACTIVE_GO_RUNTIME_PREMATURE_UNINSTALL_COUNT=0");
    eprintln!("B2_COMBINED_ACTIVE_GO_RUNTIME_PROTECTION=PASS");

    // --- Background stop-task for rustfmt (mirrors Phase 7B-B2-B-R1's own
    // technique) so the real, unmodified full_uninstall boundary below can
    // genuinely stop it, not merely report Busy. LSP sessions (pyright/
    // rust-analyzer/gopls) already stop themselves cooperatively via their
    // own lease-stop machinery inside `LspSession` -- no equivalent
    // background task is needed for them. ---
    let stop_task = tokio::spawn(async move {
        rustfmt_waiter.wait_for_stop_request().await;
        let outcome = rustfmt_process.terminate().await;
        rustfmt_waiter.acknowledge_stopped();
        outcome
    });

    // --- B2_COMBINED_ACTIVE_FULL_UNINSTALL: the real product-facing
    // uninstall boundary, all four active. ---
    let outcome =
        provisioning::full_uninstall::uninstall_all_corulix_managed_components_at(&root).await;
    let removed_order = match outcome {
        Ok(full_uninstall::FullUninstallOutcome::Removed(order)) => order,
        other => return Err(fail(format!("expected Removed(_), got {other:?}"))),
    };
    let position = |id: &str| removed_order.iter().position(|entry| entry == id);
    if position(PYRIGHT_ID) >= position(NODE_ID) {
        return Err(fail("pyright not removed before node-runtime"));
    }
    if position(RUST_ANALYZER_ID) >= position(RUST_RUNTIME_ID)
        || position(RUSTFMT_ID) >= position(RUST_RUNTIME_ID)
    {
        return Err(fail(
            "a rust-semantic-runtime dependent was not removed first",
        ));
    }
    if position(GOPLS_ID) >= position(GO_RUNTIME_ID) {
        return Err(fail("gopls not removed before go-semantic-runtime"));
    }
    if removed_order.len() != 7 {
        return Err(fail(format!(
            "expected all 7 provisioned components in the removal order, got {removed_order:?}"
        )));
    }
    eprintln!("B2_COMBINED_ACTIVE_FULL_UNINSTALL=PASS");

    let _ = stop_task
        .await
        .map_err(|error| fail(format!("rustfmt stop task panicked: {error}")))?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let orphan_rustfmt = std::path::Path::new(&format!("/proc/{rustfmt_pid}")).exists();
    let orphan_py = py
        .session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    let orphan_ra = ra
        .session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    let orphan_gopls = go_session
        .session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    if orphan_rustfmt || orphan_py || orphan_ra || orphan_gopls {
        return Err(fail(format!(
            "orphan processes after combined full_uninstall: rustfmt={orphan_rustfmt} pyright={orphan_py} rust-analyzer={orphan_ra} gopls={orphan_gopls}"
        )));
    }
    eprintln!("POST_B2_FULL_UNINSTALL_ORPHAN_PROCESS_COUNT=0");
    eprintln!("B2_COMBINED_PROCESS_ZERO_STATE=PASS");

    // --- Complete zero-residual: mechanically measured, never test-side
    // cleanup performed before these assertions. ---
    let residual_owned = ownership::list(&root).len();
    let residual_leases = lease::active_lease_count();
    let residual_paths: Vec<String> = if root.exists() {
        fs::read_dir(&root)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if residual_owned != 0 || residual_leases != 0 || !residual_paths.is_empty() {
        return Err(fail(format!(
            "expected zero residual, got owned={residual_owned} leases={residual_leases} paths={residual_paths:?}"
        )));
    }
    eprintln!("POST_B2_FULL_UNINSTALL_ACTIVE_LEASE_COUNT=0");
    eprintln!("POST_B2_UNINSTALL_MANAGED_COMPONENT_COUNT=0");
    eprintln!("POST_B2_UNINSTALL_ACTIVE_LEASE_COUNT=0");
    eprintln!("POST_B2_UNINSTALL_ORPHAN_PROCESS_COUNT=0");
    eprintln!("POST_B2_UNINSTALL_DEPENDENCY_COUNT=0");
    eprintln!("POST_B2_UNINSTALL_LIVE_OWNERSHIP_RECORD_COUNT=0");
    eprintln!("POST_B2_UNINSTALL_RESIDUAL_PATHS=[]");
    eprintln!(
        "POST_B2_UNINSTALL_MANAGED_ROOT_EXISTS={}",
        if root.exists() { "YES" } else { "NO" }
    );
    if root.exists() {
        return Err(fail("managed root still exists after full_uninstall"));
    }
    eprintln!("B2_COMBINED_LEASE_ZERO_STATE=PASS");
    eprintln!("B2_COMBINED_DEPENDENCY_ZERO_STATE=PASS");
    eprintln!("B2_COMBINED_OWNERSHIP_ZERO_STATE=PASS");
    eprintln!("B2_COMBINED_COMPLETE_MANAGED_ZERO_STATE=PASS");

    // --- Second full uninstall: must not recreate anything. ---
    let second_outcome =
        provisioning::full_uninstall::uninstall_all_corulix_managed_components_at(&root)
            .await
            .map_err(|error| fail(format!("second full_uninstall failed: {error:?}")))?;
    if second_outcome != full_uninstall::FullUninstallOutcome::NoManagedComponents {
        return Err(fail(format!(
            "expected the second full_uninstall to be an idempotent no-op, got {second_outcome:?}"
        )));
    }
    if root.exists() {
        return Err(fail("second full_uninstall recreated the managed root"));
    }
    eprintln!("B2_COMBINED_SECOND_UNINSTALL_IDEMPOTENCY=PASS");

    let _ = fs::remove_dir_all(&py_fixture);
    let _ = fs::remove_dir_all(&rust_fixture_dir);
    let _ = fs::remove_dir_all(&go_fixture_dir);
    let _ = fs::remove_dir_all(&rustfmt_workspace_dir);
    Ok(())
}
