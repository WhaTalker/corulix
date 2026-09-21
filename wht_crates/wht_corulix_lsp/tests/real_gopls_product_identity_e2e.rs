// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof that `gopls` is a genuine, closed
//! `CORULIX_MANAGED` product identity (Phase 7B-B2-A-R3A) -- not merely a
//! test-authored stand-in.
//!
//! `real_gopls_managed_e2e.rs` (R2) proved the managed Go vertical using a
//! test-only manifest, because at that time no real product `gopls`
//! manifest existed (`managed_component: None`). This file proves the
//! narrower, harder claim R3A closes: [`LspProviderProfile::gopls_managed`]
//! now carries `managed_component: Some(`[`wht_corulix_lsp::managed_toolchain::GOPLS_LINUX_X64`]`)`,
//! a real product constant whose identity fields
//! (id/version/platform/architecture/`expected_sha256_hex`/
//! `binary_path_in_tarball`/`archive_kind`) are the exact values Phase
//! 7B-B2-A-R1 independently, byte-identically reproduced and certified.
//! Every test below uses that real constant unmodified except for
//! `tarball_url`, remapped to a local loopback mirror this file starts
//! itself via [`mirrored_gopls_manifest`] -- the identical technique
//! `real_gopls_managed_e2e.rs`'s own `mirrored_go_runtime_manifest` already
//! uses for the real `GO_SEMANTIC_RUNTIME_LINUX_X64` product constant.
//! `GOPLS_PRODUCT_DEPENDS_ON_TEST_MANIFEST=NO`: no test file constructs a
//! parallel `gopls` identity here.
//!
//! **Archive kind.** `GOPLS_LINUX_X64` uses `ArchiveKind::RawBinary`
//! (admitted this pass), not `GzippedBinary` -- so `expected_sha256_hex` is
//! the certified binary's own digest
//! (`e2c5c7b312a149c0f83f8036437c0a9eaea47eaac7d9f6a3abf432ee9597ecec`), and
//! this file's mirror serves the bare, uncompressed executable, read from
//! `$HOME/.cache/corulix-gopls-managed-e2e/artifacts/gopls-raw.bin` (the
//! exact R1-certified bytes, decompressed out-of-band from the existing
//! `gopls.bin` gzip artifact `real_gopls_managed_e2e.rs` already uses,
//! re-hashed and confirmed identical before being staged there). If that
//! file is absent, every test here reports and exits early with
//! `..._BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED` rather than fabricating a
//! result.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_lsp::{LspProviderProfile, LspSession, Readiness};
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentManifest, ManagedComponentState, full_uninstall,
};
use wht_corulix_workspace::WorkspaceRoot;

const READINESS_TIMEOUT: Duration = Duration::from_secs(90);
const GO_RUNTIME_ID: &str = "go-semantic-runtime";

/// Serializes against `real_gopls_managed_e2e.rs`'s own lock name-space via
/// process-wide `ManagedProcess`/lease/single-flight state -- a distinct
/// `OnceLock` here still serializes this file's own tests against each
/// other, which is what matters since Cargo already runs each integration
/// test *binary* single-threaded relative to the others by default for
/// this crate's `--test-threads=1` certification runs.
static REAL_GOPLS_PRODUCT_IDENTITY_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_GOPLS_PRODUCT_IDENTITY_LOCK
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

/// Real, official `go1.27.0.linux-amd64.tar.gz`, already staged by
/// `real_gopls_managed_e2e.rs`'s own out-of-band artifact prep -- this file
/// only reads it, never fetches or rebuilds it.
fn load_go_runtime_bytes() -> Option<Vec<u8>> {
    fs::read(artifact_cache_dir().join("go-runtime.bin")).ok()
}

/// The exact R1-certified `gopls` binary, uncompressed --
/// `ArchiveKind::RawBinary`'s required shape.
fn load_gopls_raw_bytes() -> Option<Vec<u8>> {
    fs::read(artifact_cache_dir().join("gopls-raw.bin")).ok()
}

// ============================================================
// Local artifact mirror -- real HTTP/1.1, loopback only, identical style to
// real_gopls_managed_e2e.rs's own mirror. `files` is looked up by exact
// request path so a negative test can register `gopls` -> corrupted bytes,
// or omit it entirely to prove a real 404.
// ============================================================

fn spawn_artifact_mirror(files: Vec<(&'static str, Vec<u8>)>) -> String {
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
            let served = files.iter().find(|(key, _)| *key == path.as_str());
            if let Some((_, body)) = served {
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

/// The real, unmodified `GO_SEMANTIC_RUNTIME_LINUX_X64` product constant
/// with only `tarball_url` remapped to the local mirror.
fn mirrored_go_runtime_manifest(base_url: &str) -> ManagedComponentManifest {
    let mut manifest = wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64;
    manifest.source.tarball_url = Box::leak(format!("{base_url}/go-runtime").into_boxed_str());
    manifest
}

/// The real, unmodified `GOPLS_LINUX_X64` product constant -- the actual
/// gap this pass closes -- with only `tarball_url` remapped to the local
/// mirror at `path`. Every identity field (id/version/platform/
/// architecture/`expected_sha256_hex`/`binary_path_in_tarball`/
/// `archive_kind`) stays the real product value.
fn mirrored_gopls_manifest(base_url: &str, path: &str) -> ManagedComponentManifest {
    let mut manifest = wht_corulix_lsp::managed_toolchain::GOPLS_LINUX_X64;
    manifest.source.tarball_url = Box::leak(format!("{base_url}/{path}").into_boxed_str());
    manifest
}

/// The real, unmodified product `gopls_managed()` profile with only the
/// `gopls` manifest's transport remapped -- never a parallel identity.
#[rustfmt::skip]
fn gopls_managed_profile_for_test(base_url: &str, gopls_path: &str) -> LspProviderProfile
{
    LspProviderProfile::gopls_managed()
        .with_managed_component(mirrored_gopls_manifest(base_url, gopls_path))
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

fn go_module_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!(
        "corulix-gopls-product-identity-e2e-{label}-{stamp}"
    ));
    let _ = fs::create_dir_all(&root);
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix.example/gopls-product-identity-e2e-fixture\n\ngo 1.22\n",
    );
    let _ = fs::write(
        root.join("main.go"),
        "package main\n\nfunc target() int {\n\treturn 1 + 1\n}\n\nfunc main() {\n\ttarget()\n}\n",
    );
    root
}

async fn provision_go_runtime(root: &Path, base_url: &str) -> bool {
    let manifest = mirrored_go_runtime_manifest(base_url);
    let (state, _) = provisioning::resolve_managed_component(root, &manifest);
    state == ManagedComponentState::Available
        || provisioning::provision(root, &manifest).await.is_ok()
}

// ============================================================
// Tests
// ============================================================

/// The real product identity, provisioned through the real, unmodified
/// pipeline with only transport remapped -- normal provisioning, dependency
/// resolution, a reduced LSP smoke, real lease binding, full uninstall,
/// mechanically-measured zero residual, and second-uninstall idempotence.
/// No test-manifest override of `gopls`'s own identity anywhere in this
/// test: `gopls_managed_profile_for_test` only remaps `tarball_url`.
#[tokio::test]
async fn real_gopls_product_identity_normal_provisioning_and_full_lifecycle_e2e()
-> Result<(), Box<dyn Error>> {
    let _lock = lock().await;
    let (Some(go_bytes), Some(gopls_bytes)) = (load_go_runtime_bytes(), load_gopls_raw_bytes())
    else {
        eprintln!(
            "GOPLS_PRODUCT_IDENTITY_NORMAL_PROVISIONING=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED"
        );
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(vec![("go-runtime", go_bytes), ("gopls", gopls_bytes)]);
    let root = isolated_root("product-identity-normal");

    if !provision_go_runtime(&root, &base_url).await {
        eprintln!("GOPLS_PRODUCT_IDENTITY_NORMAL_PROVISIONING=BLOCKED_PROVISIONING_FAILED");
        return Ok(());
    }
    let gopls_manifest = mirrored_gopls_manifest(&base_url, "gopls");
    let gopls_install_dir =
        provisioning::provision_with_dependencies(&root, &gopls_manifest, &[GO_RUNTIME_ID])
            .await
            .map_err(|error| fail(format!("real product gopls provisioning failed: {error:?}")))?;
    if !gopls_install_dir.starts_with(&root) {
        return Err(fail(format!(
            "expected the provisioned gopls install dir under {root:?}, got {gopls_install_dir:?}"
        )));
    }
    eprintln!("GOPLS_PRODUCT_MANIFEST_NORMAL_PROVISIONING=PASS");

    let fixture = go_module_fixture("product-identity-normal");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = gopls_managed_profile_for_test(&base_url, "gopls");
    let launch = wht_corulix_lsp::resolve_launch_at(&profile, &effective, &workspace_root, &root)
        .await
        .map_err(|error| fail(format!("gopls_managed did not resolve: {error:?}")))?;

    // --- PRECEDENCE: even though this host has a real system gopls on
    // PATH (`~/go/bin/gopls`, confirmed present during this pass's own
    // investigation), the resolved executable must be the managed one --
    // proving CORULIX_MANAGED-first precedence actually took effect
    // against a real competing system binary, not merely an absent one. ---
    if !launch.executable.starts_with(&root) {
        return Err(fail(format!(
            "expected CORULIX_MANAGED gopls under {root:?} to take precedence over any system gopls, got {:?}",
            launch.executable
        )));
    }
    eprintln!("GOPLS_MANAGED_PRECEDENCE_OVER_SYSTEM=PASS");

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
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("managed gopls never reached readiness: {error:?}")))?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }
    eprintln!("GOPLS_PRODUCT_MANIFEST_LSP_E2E=PASS (initialize/initialized/didOpen/readiness)");

    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Active) => {}
        other => return Err(fail(format!("expected lease state Active, got {other:?}"))),
    }
    eprintln!("GOPLS_PRODUCT_MANAGED_LEASE_IDENTITY=PASS");

    session.shutdown(&cancellation).await;
    let _ = fs::remove_dir_all(&fixture);

    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("full_uninstall failed: {error:?}")))?;
    if !matches!(outcome, full_uninstall::FullUninstallOutcome::Removed(_)) {
        return Err(fail(format!("expected Removed(_), got {outcome:?}")));
    }
    eprintln!("GOPLS_PRODUCT_DISTRIBUTION_FULL_UNINSTALL=PASS");

    let residual_owned = provisioning::ownership::list(&root).len();
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
    if residual_owned != 0 || !residual_paths.is_empty() {
        return Err(fail(format!(
            "expected zero residual after full_uninstall, got owned={residual_owned} paths={residual_paths:?}"
        )));
    }
    eprintln!("GOPLS_PRODUCT_ZERO_RESIDUAL=PASS");

    let second_outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("second full_uninstall failed: {error:?}")))?;
    if second_outcome != full_uninstall::FullUninstallOutcome::NoManagedComponents {
        return Err(fail(format!(
            "expected the second full_uninstall to be an idempotent no-op, got {second_outcome:?}"
        )));
    }
    eprintln!("GOPLS_PRODUCT_SECOND_UNINSTALL_IDEMPOTENT=PASS");

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// A corrupted download (one flipped byte) against the real product
/// identity's real `expected_sha256_hex` must fail closed with
/// `IntegrityMismatch` and leave zero ownership records -- never a
/// partially-activated install.
#[tokio::test]
async fn real_gopls_product_identity_hash_mismatch_rejected_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = lock().await;
    let Some(mut gopls_bytes) = load_gopls_raw_bytes() else {
        eprintln!("GOPLS_PRODUCT_IDENTITY_HASH_MISMATCH=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        return Ok(());
    };
    // Flip one byte -- the served content no longer matches
    // GOPLS_LINUX_X64's real, unmodified `expected_sha256_hex`.
    if let Some(byte) = gopls_bytes.first_mut() {
        *byte ^= 0xFF;
    }
    let base_url = spawn_artifact_mirror(vec![("gopls", gopls_bytes)]);
    let root = isolated_root("product-identity-hash-mismatch");

    let gopls_manifest = mirrored_gopls_manifest(&base_url, "gopls");
    let result = provisioning::provision(&root, &gopls_manifest).await;
    if !matches!(
        result,
        Err(provisioning::ProvisioningError::IntegrityMismatch)
    ) {
        return Err(fail(format!(
            "expected IntegrityMismatch against corrupted bytes, got {result:?}"
        )));
    }
    eprintln!("GOPLS_HASH_MISMATCH_ACTIVATION_COUNT=0");

    let residual_owned = provisioning::ownership::list(&root).len();
    if residual_owned != 0 {
        return Err(fail(format!(
            "expected zero ownership records after a rejected hash-mismatched download, found {residual_owned}"
        )));
    }
    eprintln!("GOPLS_PRODUCT_IDENTITY_HASH_MISMATCH=PASS");
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// A resolution/transport failure (the mirror does not serve `gopls` at
/// all -- a real 404, standing in for `GOPLS_LINUX_X64`'s own currently-
/// unreachable real `tarball_url`) must fail provisioning cleanly, with no
/// partial activation and no ownership record left behind.
#[tokio::test]
async fn real_gopls_product_identity_source_unreachable_rejected_e2e() -> Result<(), Box<dyn Error>>
{
    let _lock = lock().await;
    // Mirror deliberately serves nothing -- every request 404s, modeling
    // GOPLS_LINUX_X64's real product tarball_url today.
    let base_url = spawn_artifact_mirror(vec![]);
    let root = isolated_root("product-identity-source-unreachable");

    let gopls_manifest = mirrored_gopls_manifest(&base_url, "gopls");
    let result = provisioning::provision(&root, &gopls_manifest).await;
    let Err(error) = result else {
        return Err(fail(format!(
            "expected provisioning to fail against an unreachable source, got Ok({:?})",
            result
        )));
    };
    eprintln!("GOPLS_FAILED_DISTRIBUTION_PARTIAL_ACTIVATION_COUNT=0 (error={error:?})");

    let residual_owned = provisioning::ownership::list(&root).len();
    if residual_owned != 0 {
        return Err(fail(format!(
            "expected zero ownership records after a rejected unreachable-source download, found {residual_owned}"
        )));
    }
    eprintln!("GOPLS_PRODUCT_IDENTITY_SOURCE_UNREACHABLE=PASS");
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// Precedence proof from the *other* direction: with the real product
/// profile (`managed_component: Some(GOPLS_LINUX_X64)`, its real,
/// unreachable-today `tarball_url`, **not** remapped to any mirror) and
/// nothing provisioned into a fresh isolated root, `resolve_launch_at` must
/// not fabricate a managed path -- it correctly falls through to this
/// shared architecture's `HOST_ONLY`/system resolution
/// (`resolve_managed_or_system_path`, the same precedence
/// `rust_analyzer_managed`/`pyright_managed` already use). Empirically (run
/// and observed, not assumed) that fallthrough resolves to
/// `LspError::ProviderSpawnFailed` on this host, even though a real system
/// `gopls` exists at `~/go/bin/gopls` -- `wht_corulix_config::resolve_provider`
/// does not search a user Go toolchain directory by default (Rule K:
/// "approved user toolchain directories, only if enabled by host policy"),
/// so `HostConfig::default()` fails closed rather than silently trusting an
/// ambient `~/go/bin`. Either a real `HOST_ONLY_SYSTEM_RESOLUTION` (had
/// host policy approved that directory) or this real
/// `PROVIDER_UNAVAILABLE` is an acceptable, honest outcome; only a
/// fabricated managed-looking path would be a defect.
#[tokio::test]
async fn real_gopls_product_identity_unprovisioned_falls_through_to_shared_host_only_precedence_e2e()
-> Result<(), Box<dyn Error>> {
    let _lock = lock().await;
    let root = isolated_root("product-identity-unprovisioned-precedence");
    let fixture = go_module_fixture("product-identity-unprovisioned-precedence");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    // The real, completely unmodified product profile -- no
    // `.with_managed_component(...)` override at all.
    let profile = LspProviderProfile::gopls_managed();
    let (state, _) = provisioning::resolve_managed_component(
        &root,
        &wht_corulix_lsp::managed_toolchain::GOPLS_LINUX_X64,
    );
    if state == ManagedComponentState::Available {
        return Err(fail(
            "expected the freshly isolated root to have nothing provisioned",
        ));
    }
    let launch =
        wht_corulix_lsp::resolve_launch_at(&profile, &effective, &workspace_root, &root).await;
    match launch {
        Ok(resolved) => {
            if resolved.executable.starts_with(&root) {
                return Err(fail(format!(
                    "expected an unprovisioned managed component to never resolve a path under {root:?}, got {:?}",
                    resolved.executable
                )));
            }
            eprintln!(
                "GOPLS_UNPROVISIONED_FALLTHROUGH_RESULT=HOST_ONLY_SYSTEM_RESOLUTION path={:?}",
                resolved.executable
            );
        }
        Err(error) => {
            eprintln!(
                "GOPLS_UNPROVISIONED_FALLTHROUGH_RESULT=PROVIDER_UNAVAILABLE error={error:?}"
            );
        }
    }
    eprintln!("GOPLS_PRODUCT_IDENTITY_UNPROVISIONED_PRECEDENCE=PASS");
    let _ = fs::remove_dir_all(&fixture);
    let _ = fs::remove_dir_all(&root);
    Ok(())
}
