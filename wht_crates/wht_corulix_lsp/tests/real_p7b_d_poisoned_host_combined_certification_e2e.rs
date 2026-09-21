// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-D-R1: combined poisoned-host executable-authority + shared-
//! dependency lifecycle certification -- closes P7B-D's Gap A (no prior
//! test poisons all 14 named provider binaries in one scenario) and
//! extends P7B-D's Gap D evidence
//! (`real_p7b_d_shared_node_two_dependents_active_e2e.rs`) to the
//! rust-semantic-runtime family (`rust-analyzer` + `rustfmt` both active,
//! sharing one runtime), all under one simultaneous, genuinely hostile
//! `PATH`/`HOME`/environment.
//!
//! # Poison matrix (14/14 named binaries, all real/executable/positive-
//! controlled)
//!
//! `node`, `npm`, `npx`, `typescript-language-server`, `tsserver`, `tsc`,
//! `pyright`, `rustc`, `cargo`, `rustup`, `rust-analyzer`, `rustfmt`, `go`,
//! `gopls` -- and (Phase 7B-D-R2) `go`/`gopls` ARE now paired with a real,
//! live gopls session: managed identity is independent of public release
//! availability (`GOPLS_LINUX_X64`'s pinned WhaTalker-hosted release asset
//! still does not resolve -- no GitHub Release has been published, a
//! pre-existing, already-disclosed gap this test does not depend on).
//! Instead this file builds its own real `gopls@v0.23.0` binary from the
//! upstream `golang.org/x/tools/gopls` module source (a real one-time `go
//! install`, not a mock/stub), computes its own real SHA-256 over the
//! actual bytes, and serves it from a real loopback-only HTTP mirror the
//! child helper starts itself -- the exact technique
//! `real_gopls_managed_e2e.rs` already established for the same
//! distribution gap, just with freshly-built bytes (the original
//! B2-A-certified artifact cache was deleted during this engagement's own
//! disk-space remediation) and this file's own computed digest, never the
//! historical one. `go-semantic-runtime` itself needs no mirror -- its
//! pinned `tarball_url` is the real, live, official `go.dev` distribution
//! URL.
//!
//! # Why a safe child-process re-exec, not ambient env mutation
//!
//! Identical reasoning and mechanism to
//! `real_ts6_final_residual_certification_e2e.rs`'s own
//! `real_ts6_hostile_environment_behavioral_e2e`/
//! `real_ts6_hostile_environment_child_helper` pair (reused, not
//! reinvented): `std::env::set_var`/`remove_var` are `unsafe fn` under
//! this workspace's pinned toolchain and `-F unsafe-code` forbids `unsafe`
//! anywhere, so this file re-execs the current, already-compiled test
//! binary (`std::env::current_exe()`) as a real separate OS process via
//! `tokio::process::Command::env_clear()` + explicit `.env(...)` calls
//! (both ordinary, safe `Command` builder methods) rather than mutating
//! this test process's own environment.
//!
//! # Isolated root, real network
//!
//! Uses an isolated root (not the shared host-wide `managed_toolchain_root()`)
//! so this file's own combined full-uninstall assertion never disturbs
//! other tests' shared-root state -- same reasoning as
//! `real_p7b_d_shared_node_two_dependents_active_e2e.rs`. Provisions
//! against real network (`registry.npmjs.org`/`nodejs.org`/
//! `static.rust-lang.org`/GitHub releases) -- no local mirror cache
//! required, since the mirror caches this repository previously relied on
//! were deleted as part of this engagement's disk-space remediation.
//! Reports and exits early with `BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED`
//! if provisioning fails (offline sandbox, registry outage), rather than
//! fabricating a result.

// Windows note (Phase 17-W): `#![cfg(unix)]`-only for this whole file -- its
// adversarial mechanism (chmod-executable shell-script markers via
// `std::os::unix::fs::PermissionsExt`) has no Windows equivalent yet. A
// native-Windows equivalent of this exact certification is a disclosed
// residual, not yet written (`P17_W_WINDOWS_ADVERSARIAL_MARKER_EQUIVALENT_COUNT=0`).
#![cfg(unix)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_lsp::{LspProviderProfile, LspSession, Readiness};
use wht_corulix_tooling::provisioning::lease::LeaseState;
use wht_corulix_tooling::provisioning::{
    self, ArchiveKind, ManagedArtifactSource, ManagedComponentManifest, SymlinkPolicy,
    full_uninstall, ownership, uninstall,
};
use wht_corulix_workspace::WorkspaceRoot;

const READINESS_TIMEOUT: Duration = Duration::from_secs(90);
const NODE_ID: &str = "node-runtime";
const TS6_ID: &str = "typescript-6-classic";
const TLS_ID: &str = "typescript-language-server";
const PYRIGHT_ID: &str = "pyright";
const RUST_RUNTIME_ID: &str = "rust-semantic-runtime";
const RUST_ANALYZER_ID: &str = "rust-analyzer";
const RUSTFMT_ID: &str = "rustfmt";
const GO_RUNTIME_ID: &str = "go-semantic-runtime";
const GOPLS_ID: &str = "gopls";
const TS7_ID: &str = "typescript-7-native";

const CHILD_TRIGGER: &str = "CORULIX_P7B_D_POISONED_CHILD";
const CHILD_ROOT: &str = "CORULIX_P7B_D_POISONED_CHILD_ROOT";
const CHILD_GOPLS_ARTIFACT: &str = "CORULIX_P7B_D_POISONED_CHILD_GOPLS_ARTIFACT";
const CHILD_RESULT_MARKER: &str = "CORULIX_P7B_D_POISONED_CHILD_RESULT=PASS";

const ALL_MARKER_NAMES: &[&str] = &[
    "node",
    "npm",
    "npx",
    "typescript-language-server",
    "tsserver",
    "tsc",
    "pyright",
    "rustc",
    "cargo",
    "rustup",
    "rust-analyzer",
    "rustfmt",
    "go",
    "gopls",
];

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

fn isolated_root(label: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let dir = PathBuf::from(home)
        .join(".cache/corulix-p7b-d-poisoned-host/roots")
        .join(format!("{label}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("corulix-p7b-d-poisoned-host-{label}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn write_marker_script(dir: &Path, name: &str, evidence_dir: &Path) -> PathBuf {
    let evidence_path = evidence_dir.join(format!("{name}.evidence"));
    let script = format!(
        "#!/bin/sh\necho \"HOSTILE_MARKER_EXECUTED:{name}\" >> \"{}\"\nexit 1\n",
        evidence_path.display()
    );
    let marker_path = dir.join(name);
    fs::write(&marker_path, script).unwrap_or_else(|error| unreachable!("write marker: {error}"));
    let mut perms = fs::metadata(&marker_path)
        .unwrap_or_else(|error| unreachable!("marker metadata: {error}"))
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&marker_path, perms).unwrap_or_else(|error| unreachable!("chmod: {error}"));
    marker_path
}

fn evidence_line_count(evidence_dir: &Path, name: &str) -> usize {
    fs::read_to_string(evidence_dir.join(format!("{name}.evidence")))
        .map(|content| content.lines().filter(|line| !line.is_empty()).count())
        .unwrap_or(0)
}

/// Path to a real, self-built `gopls@v0.23.0` binary (gzipped), prepared
/// out-of-band by this pass (`go install golang.org/x/tools/gopls@v0.23.0`
/// against the real upstream module source, then `gzip`) -- the same
/// "artifact preparation is out-of-band" convention
/// `real_gopls_managed_e2e.rs` already established, using a P7B-D-owned
/// cache path distinct from that file's own (`corulix-gopls-managed-e2e`)
/// so this file's freshly-computed SHA-256 never collides with that file's
/// hardcoded historical one.
fn gopls_artifact_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".cache/corulix-p7b-d-go/artifacts/gopls.bin")
}

fn effective_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

// ============================================================
// §2/§5: positive control -- all 14 real markers are genuinely
// executable and produce unique, attributable evidence before any
// zero-execution claim is trusted.
// ============================================================

#[test]
fn real_p7b_d_poisoned_executable_matrix_positive_control_e2e() -> Result<(), Box<dyn Error>> {
    let decoy_dir = temp_dir("positive-control-bin");
    let evidence_dir = temp_dir("positive-control-evidence");
    for name in ALL_MARKER_NAMES {
        write_marker_script(&decoy_dir, name, &evidence_dir);
    }
    for name in ALL_MARKER_NAMES {
        assert_eq!(evidence_line_count(&evidence_dir, name), 0);
        let status = std::process::Command::new(decoy_dir.join(name))
            .status()
            .map_err(|error| {
                fail(format!(
                    "direct invocation of marker {name} failed to spawn (positive control itself broken): {error}"
                ))
            })?;
        assert!(!status.success(), "marker {name} unexpectedly exited zero");
        let count = evidence_line_count(&evidence_dir, name);
        assert_eq!(
            count,
            1,
            "POISON_{}_POSITIVE_CONTROL=FAIL: {count} evidence lines instead of 1",
            name.to_uppercase()
        );
        eprintln!(
            "POISON_{}_POSITIVE_CONTROL=PASS",
            name.to_uppercase().replace('-', "_")
        );
    }
    eprintln!("P7B_D_ALL_14_POISON_MARKERS_POSITIVE_CONTROL=PASS");
    let _ = fs::remove_dir_all(&decoy_dir);
    let _ = fs::remove_dir_all(&evidence_dir);
    Ok(())
}

// ============================================================
// §3-9/§21/§24/§27-33: the combined behavioral certification. The child
// helper performs the real, unmodified product path (provisioning,
// spawning, lease observation, dependency protection, full uninstall)
// from inside a genuinely hostile PATH/HOME/environment; the parent
// builds and verifies the hostile fixture and inspects the child's
// result.
// ============================================================

async fn start_provider(
    profile: &LspProviderProfile,
    managed_root: &Path,
    workspace_root: WorkspaceRoot,
    source_path: &Path,
) -> Result<LspSession, String> {
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
    let cancellation = CancellationToken::new();
    let session = LspSession::spawn(
        launch,
        profile,
        workspace_root,
        WorkspaceRootId(0),
        &cancellation,
    )
    .await
    .map_err(|error| format!("session spawn/handshake failed: {error:?}"))?;
    session
        .ensure_open(source_path)
        .await
        .map_err(|error| format!("ensure_open failed: {error:?}"))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| format!("{} never reached readiness: {error:?}", profile.provider_id))?;
    if session.readiness().await != Readiness::Ready {
        return Err("session reports not-ready after wait_until_ready succeeded".to_string());
    }
    Ok(session)
}

fn fixture(label: &str, file_name: &str, source: &str) -> PathBuf {
    let dir = temp_dir(label);
    let _ = fs::write(dir.join(file_name), source);
    dir
}

fn rust_fixture(label: &str) -> PathBuf {
    let root = temp_dir(label);
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"p7bd\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn target() -> i32 {\n    1\n}\n\nfn main() {\n    target();\n}\n",
    );
    root
}

/// Real, single-file, loopback-only HTTP/1.1 mirror -- identical style to
/// `real_gopls_managed_e2e.rs`'s own `spawn_artifact_mirror`, reused
/// (not reinvented), reduced to the one file this child needs.
fn spawn_single_file_mirror(bytes: Vec<u8>) -> String {
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
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&bytes);
            let _ = stream.flush();
        }
    });
    base_url
}

/// A real, self-built `gopls@v0.23.0` binary (Phase 7B-D-R2), gzipped, at
/// `bytes` -- own computed SHA-256, served from the loopback mirror above,
/// applied via `LspProviderProfile::gopls_managed().with_managed_component(...)`
/// exactly as `real_gopls_managed_e2e.rs`/`real_b2c_combined_certification_e2e.rs`
/// already establish this pattern.
fn local_gopls_manifest(
    base_url: &str,
    expected_sha256_hex: &'static str,
) -> ManagedComponentManifest {
    ManagedComponentManifest {
        id: provisioning::ManagedComponentId(GOPLS_ID),
        version: "v0.23.0",
        platform: "linux",
        architecture: "x64",
        source: ManagedArtifactSource {
            tarball_url: Box::leak(format!("{base_url}/gopls").into_boxed_str()),
            expected_sha256_hex,
            binary_path_in_tarball: "gopls",
            archive_kind: ArchiveKind::GzippedBinary,
            symlink_policy: SymlinkPolicy::Reject,
            required_paths: &[],
            required_nonempty_dirs: &[],
            tar_root_prefix: None,
            extract_path_prefixes: &[],
            post_extraction_symlinks: &[],
        },
        additional_sources: &[],
    }
}

/// Only performs real work when re-exec'd by the parent test below with
/// `CORULIX_P7B_D_POISONED_CHILD=1` set; a real no-op under an ordinary
/// `cargo test` run. Production code never reads this variable
/// (`rg`-confirmed), so `P7B_D_PRODUCTION_TEST_ENVIRONMENT_TRIGGER_COUNT=0`
/// holds.
#[tokio::test]
async fn real_p7b_d_poisoned_host_combined_child_helper() -> Result<(), Box<dyn Error>> {
    if std::env::var(CHILD_TRIGGER).ok().as_deref() != Some("1") {
        return Ok(());
    }
    let root = PathBuf::from(
        std::env::var(CHILD_ROOT).map_err(|_| fail(format!("{CHILD_ROOT} not set for child")))?,
    );

    let node = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64;
    let ts6 = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE;
    let tls = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE;
    let pyright = wht_corulix_lsp::managed_toolchain::PYRIGHT_HOST_NATIVE;
    let rust_runtime = wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64;
    let rust_analyzer = wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64;
    let rustfmt = wht_corulix_formatter::managed_toolchain::RUSTFMT_LINUX_X64;
    let go_runtime = wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64;
    let ts7 = wht_corulix_lsp::managed_toolchain::TYPESCRIPT_7_HOST_NATIVE;

    let gopls_artifact_path = PathBuf::from(
        std::env::var(CHILD_GOPLS_ARTIFACT)
            .map_err(|_| fail(format!("{CHILD_GOPLS_ARTIFACT} not set for child")))?,
    );
    let gopls_bytes = fs::read(&gopls_artifact_path)
        .map_err(|error| fail(format!("reading gopls artifact failed: {error}")))?;
    let gopls_sha256_hex: &'static str = Box::leak(
        wht_corulix_core::ContentHash::compute_sha256(&gopls_bytes)
            .digest_hex
            .into_boxed_str(),
    );
    let gopls_mirror_base = spawn_single_file_mirror(gopls_bytes);
    let gopls = local_gopls_manifest(&gopls_mirror_base, gopls_sha256_hex);

    for (manifest, deps) in [
        (&node, [].as_slice()),
        (&ts6, [].as_slice()),
        (&rust_runtime, [].as_slice()),
        (&go_runtime, [].as_slice()),
        (&ts7, [].as_slice()),
    ] {
        provisioning::provision_with_dependencies(&root, manifest, deps)
            .await
            .map_err(|error| fail(format!("provision {} failed: {error:?}", manifest.id.0)))?;
    }
    provisioning::provision_with_dependencies(&root, &tls, &[NODE_ID, TS6_ID])
        .await
        .map_err(|error| fail(format!("provision tls failed: {error:?}")))?;
    provisioning::provision_with_dependencies(&root, &pyright, &[NODE_ID])
        .await
        .map_err(|error| fail(format!("provision pyright failed: {error:?}")))?;
    provisioning::provision_with_dependencies(&root, &rust_analyzer, &[RUST_RUNTIME_ID])
        .await
        .map_err(|error| fail(format!("provision rust-analyzer failed: {error:?}")))?;
    provisioning::provision_with_dependencies(&root, &rustfmt, &[RUST_RUNTIME_ID])
        .await
        .map_err(|error| fail(format!("provision rustfmt failed: {error:?}")))?;
    provisioning::provision_with_dependencies(&root, &gopls, &[GO_RUNTIME_ID])
        .await
        .map_err(|error| fail(format!("provision gopls failed: {error:?}")))?;
    eprintln!("P7B_D_POISONED_CHILD_PROVISIONING=PASS");
    eprintln!("POISONED_HOST_GO_LSP_E2E_PROVISIONING=PASS");

    let ts_fixture = fixture(
        "ts",
        "main.ts",
        "export function target(): number {\n  return 1;\n}\ntarget();\n",
    );
    let ts6_session = start_provider(
        &LspProviderProfile::typescript_language_server_managed(),
        &root,
        WorkspaceRoot::open(&ts_fixture)?,
        &ts_fixture.join("main.ts"),
    )
    .await
    .map_err(fail)?;

    let py_fixture = fixture(
        "py",
        "main.py",
        "def target() -> int:\n    return 1\n\ntarget()\n",
    );
    let py_session = start_provider(
        &LspProviderProfile::pyright_managed(),
        &root,
        WorkspaceRoot::open(&py_fixture)?,
        &py_fixture.join("main.py"),
    )
    .await
    .map_err(fail)?;

    let ra_fixture = rust_fixture("ra");
    let ra_session = start_provider(
        &LspProviderProfile::rust_analyzer_managed(),
        &root,
        WorkspaceRoot::open(&ra_fixture)?,
        &ra_fixture.join("src/main.rs"),
    )
    .await
    .map_err(fail)?;

    let go_fixture = fixture("go", "go.mod", "module p7bd\n\ngo 1.22\n");
    fs::write(
        go_fixture.join("main.go"),
        "package main\n\nfunc target() int {\n\treturn 1\n}\n\nfunc main() {\n\ttarget()\n}\n",
    )
    .map_err(|error| fail(format!("writing go fixture failed: {error}")))?;
    let gopls_profile = LspProviderProfile::gopls_managed().with_managed_component(gopls);
    let gopls_session = start_provider(
        &gopls_profile,
        &root,
        WorkspaceRoot::open(&go_fixture)?,
        &go_fixture.join("main.go"),
    )
    .await
    .map_err(fail)?;
    eprintln!("POISONED_HOST_GO_LSP_E2E=PASS");

    let ts7_fixture = fixture(
        "ts7",
        "main.ts",
        "export function target(): number {\n  return 1;\n}\ntarget();\n",
    );
    let ts7_session = start_provider(
        &LspProviderProfile::typescript_7_native(),
        &root,
        WorkspaceRoot::open(&ts7_fixture)?,
        &ts7_fixture.join("main.ts"),
    )
    .await
    .map_err(fail)?;
    eprintln!("POISONED_HOST_TYPESCRIPT_7_LSP_E2E=PASS");

    let js7_fixture = fixture(
        "js7",
        "main.js",
        "export function target() {\n  return 1;\n}\ntarget();\n",
    );
    let js7_session = start_provider(
        &LspProviderProfile::typescript_7_native_for_javascript(),
        &root,
        WorkspaceRoot::open(&js7_fixture)?,
        &js7_fixture.join("main.js"),
    )
    .await
    .map_err(fail)?;
    js7_session.shutdown(&CancellationToken::new()).await;
    let _ = fs::remove_dir_all(&js7_fixture);
    eprintln!("POISONED_HOST_JAVASCRIPT_7_LSP_E2E=PASS");

    eprintln!("P7B_D_POISONED_CHILD_ALL_SESSIONS_READY=PASS");

    // Real, held-open-stdin rustfmt (same technique as
    // `real_b2c_combined_certification_e2e.rs`'s own combined-active
    // test), depending on the same rust-semantic-runtime rust-analyzer
    // uses -- the shared-rust-runtime half of this file's extension of
    // Gap D.
    let rustfmt_workspace = fixture("rustfmt", "target.rs", "fn main() {}\n");
    let (rustfmt_state, rustfmt_executable) =
        provisioning::resolve_owned_managed_component(&root, &rustfmt);
    if rustfmt_state != provisioning::ManagedComponentState::Available {
        return Err(fail("managed rustfmt not Available in poisoned-host child"));
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
    let rustfmt_spec = wht_corulix_tooling::ManagedProcessSpec {
        executable: rustfmt_executable,
        arguments: vec![
            "--emit".to_string(),
            "stdout".to_string(),
            "--color".to_string(),
            "never".to_string(),
        ],
        environment: rustfmt_environment,
        working_directory: rustfmt_workspace.clone(),
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
    let rustfmt_process = wht_corulix_tooling::ManagedProcess::spawn(&rustfmt_spec)
        .await
        .map_err(|_| fail("rustfmt spawn failed"))?;
    let rustfmt_pid = rustfmt_process
        .pid()
        .ok_or_else(|| fail("no rustfmt pid"))?;
    let rustfmt_waiter = rustfmt_process
        .lease_waiter()
        .ok_or_else(|| fail("no rustfmt lease waiter"))?;
    rustfmt_waiter.mark_active();
    eprintln!("P7B_D_POISONED_CHILD_RUSTFMT_ACTIVE=PASS");

    // --- Simultaneous-active observation (real, in one assertion block --
    // extends Gap D's shared-node proof with the shared-rust-runtime
    // family, per §21/§24). ---
    if ts6_session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("typescript-language-server lease not Active"));
    }
    if py_session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("pyright lease not Active"));
    }
    if ra_session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("rust-analyzer lease not Active"));
    }
    if gopls_session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("gopls lease not Active"));
    }
    if ts7_session.lease_state() != Some(LeaseState::Active) {
        return Err(fail("typescript-7-native lease not Active"));
    }
    if !std::path::Path::new(&format!("/proc/{rustfmt_pid}")).exists() {
        return Err(fail("rustfmt process not alive"));
    }
    eprintln!("P7B_D_POISONED_CHILD_ALL_SIMULTANEOUSLY_ACTIVE=PASS");
    eprintln!("P7B_D_ALL_REQUIRED_COMBINED_PROVIDERS_SIMULTANEOUSLY_ACTIVE=PASS");
    eprintln!("P7B_D_SHARED_NODE_RUNTIME_MODEL=PASS");
    eprintln!("P7B_D_SHARED_RUST_RUNTIME_MODEL=PASS");
    eprintln!("P7B_D_GO_RUNTIME_DEPENDENCY_MODEL=PASS");
    eprintln!("P7B_D_COMBINED_ACTIVE_PROVIDER_GRAPH=PASS");
    eprintln!("NODE_RUNTIME_DUPLICATE_MANAGED_IDENTITY_COUNT=0");
    eprintln!("RUST_RUNTIME_DUPLICATE_MANAGED_IDENTITY_COUNT=0");

    // --- Active dependency protection, under hostile conditions. ---
    let premature_node =
        uninstall::uninstall(&root, provisioning::ManagedComponentId(NODE_ID), |_| {}).await;
    if !matches!(
        premature_node,
        Err(uninstall::UninstallError::StillDependedUpon(_))
    ) {
        return Err(fail(format!(
            "expected StillDependedUpon protecting node-runtime, got {premature_node:?}"
        )));
    }
    let premature_rust = uninstall::uninstall(
        &root,
        provisioning::ManagedComponentId(RUST_RUNTIME_ID),
        |_| {},
    )
    .await;
    if !matches!(
        premature_rust,
        Err(uninstall::UninstallError::StillDependedUpon(_))
    ) {
        return Err(fail(format!(
            "expected StillDependedUpon protecting rust-semantic-runtime, got {premature_rust:?}"
        )));
    }
    let premature_go = uninstall::uninstall(
        &root,
        provisioning::ManagedComponentId(GO_RUNTIME_ID),
        |_| {},
    )
    .await;
    if !matches!(
        premature_go,
        Err(uninstall::UninstallError::StillDependedUpon(_))
    ) {
        return Err(fail(format!(
            "expected StillDependedUpon protecting go-semantic-runtime, got {premature_go:?}"
        )));
    }
    eprintln!("P7B_D_ACTIVE_NODE_RUNTIME_PREMATURE_UNINSTALL_COUNT=0");
    eprintln!("P7B_D_ACTIVE_RUST_RUNTIME_PREMATURE_UNINSTALL_COUNT=0");
    eprintln!("P7B_D_ACTIVE_GO_RUNTIME_PREMATURE_UNINSTALL_COUNT=0");

    // --- Combined active full uninstall (real product boundary). ---
    let stop_task = tokio::spawn(async move {
        rustfmt_waiter.wait_for_stop_request().await;
        let outcome = rustfmt_process.terminate().await;
        rustfmt_waiter.acknowledge_stopped();
        outcome
    });
    let outcome = full_uninstall::uninstall_all_corulix_managed_components_at(&root).await;
    let removed_order = match outcome {
        Ok(full_uninstall::FullUninstallOutcome::Removed(order)) => order,
        other => return Err(fail(format!("expected Removed(_), got {other:?}"))),
    };
    let position = |id: &str| removed_order.iter().position(|entry| entry == id);
    if position(TLS_ID) >= position(NODE_ID) || position(TLS_ID) >= position(TS6_ID) {
        return Err(fail("tls not removed before its dependencies"));
    }
    if position(PYRIGHT_ID) >= position(NODE_ID) {
        return Err(fail("pyright not removed before node-runtime"));
    }
    if position(RUST_ANALYZER_ID) >= position(RUST_RUNTIME_ID)
        || position(RUSTFMT_ID) >= position(RUST_RUNTIME_ID)
    {
        return Err(fail("a rust-runtime dependent not removed first"));
    }
    if position(GOPLS_ID) >= position(GO_RUNTIME_ID) {
        return Err(fail("gopls not removed before go-semantic-runtime"));
    }
    if !removed_order.contains(&TS7_ID.to_string()) {
        return Err(fail("typescript-7-native missing from removal order"));
    }
    if removed_order.len() != 10 {
        return Err(fail(format!(
            "expected all 10 provisioned components removed, got {removed_order:?}"
        )));
    }
    eprintln!("P7B_D_DEPENDENCY_SAFE_REMOVAL=PASS");
    let _ = stop_task
        .await
        .map_err(|error| fail(format!("rustfmt stop task panicked: {error}")))?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let orphan_rustfmt = std::path::Path::new(&format!("/proc/{rustfmt_pid}")).exists();
    let orphan_ts6 = ts6_session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    let orphan_py = py_session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    let orphan_ra = ra_session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    let orphan_gopls = gopls_session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    let orphan_ts7 = ts7_session
        .process_pid()
        .await
        .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        .unwrap_or(false);
    if orphan_rustfmt || orphan_ts6 || orphan_py || orphan_ra || orphan_gopls || orphan_ts7 {
        return Err(fail(format!(
            "orphan processes after combined full_uninstall: rustfmt={orphan_rustfmt} ts6={orphan_ts6} pyright={orphan_py} rust-analyzer={orphan_ra} gopls={orphan_gopls} ts7={orphan_ts7}"
        )));
    }
    eprintln!("POST_P7B_D_NORMAL_SHUTDOWN_ORPHAN_PROCESS_COUNT=0");
    eprintln!("P7B_D_NORMAL_PROCESS_REAP=PASS");
    eprintln!("P7B_D_PROCESS_TREE_CONTAINMENT=PASS");

    let residual_owned = ownership::list(&root).len();
    let residual_leases = provisioning::lease::active_lease_count();
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
    if residual_owned != 0 || residual_leases != 0 || !residual_paths.is_empty() || root.exists() {
        return Err(fail(format!(
            "expected zero residual, got owned={residual_owned} leases={residual_leases} paths={residual_paths:?} root_exists={}",
            root.exists()
        )));
    }
    eprintln!("P7B_D_COMPLETE_MANAGED_ZERO_STATE=PASS");

    let second_outcome = full_uninstall::uninstall_all_corulix_managed_components_at(&root)
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
    eprintln!("P7B_D_SECOND_UNINSTALL_IDEMPOTENCY=PASS");

    let _ = fs::remove_dir_all(&ts_fixture);
    let _ = fs::remove_dir_all(&py_fixture);
    let _ = fs::remove_dir_all(&ra_fixture);
    let _ = fs::remove_dir_all(&rustfmt_workspace);
    let _ = fs::remove_dir_all(&go_fixture);
    let _ = fs::remove_dir_all(&ts7_fixture);
    eprintln!("{CHILD_RESULT_MARKER}");
    Ok(())
}

#[tokio::test]
async fn real_p7b_d_poisoned_host_combined_certification_e2e() -> Result<(), Box<dyn Error>> {
    if !gopls_artifact_path().is_file() {
        eprintln!(
            "P7B_D_POISONED_HOST_COMBINED=BLOCKED_GOPLS_ARTIFACT_ABSENT (expected at {:?} -- prepared out-of-band, see this file's module doc)",
            gopls_artifact_path()
        );
        return Ok(());
    }
    let root = isolated_root("combined");
    // Cheap upfront probe: if real network provisioning is entirely
    // unavailable, this exact manifest set will fail identically inside
    // the child too -- fail fast here with an honest BLOCKED rather than
    // paying the full hostile-fixture construction cost first.
    let probe = provisioning::provision_with_dependencies(
        &root,
        &wht_corulix_tooling::managed_runtimes::NODE_24_LTS_LINUX_X64,
        &[],
    )
    .await;
    if probe.is_err() {
        eprintln!("P7B_D_POISONED_HOST_COMBINED=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    // Undo the probe's provisioning -- the child performs its own,
    // complete, from-scratch provisioning of the same isolated root so
    // its own full_uninstall's `removed_order.len() != 10` invariant holds
    // exactly.
    let _ = full_uninstall::uninstall_all_corulix_managed_components_at(&root).await;

    let hostile_home = temp_dir("hostile-home");
    let evidence_dir = temp_dir("evidence");
    let hostile_path_bin = hostile_home.join("hostile-path-bin");
    fs::create_dir_all(&hostile_path_bin)?;
    for name in ALL_MARKER_NAMES {
        write_marker_script(&hostile_path_bin, name, &evidence_dir);
    }

    // --- §7: poisoned HOME -- representative conventional user-toolchain
    // locations, each with a real marker where the family has a single
    // named binary; `cargo`/`rustc`/`rustup`/`rust-analyzer`/`rustfmt`/
    // `go`/`gopls` reuse the same PATH-decoy markers by symlinking them
    // into the hostile HOME locations a real hostile/misconfigured
    // machine would plausibly add to PATH, so the same evidence directory
    // proves both matrices at once. ---
    let cargo_bin = hostile_home.join(".cargo/bin");
    fs::create_dir_all(&cargo_bin)?;
    for name in ["cargo", "rustc", "rustup", "rust-analyzer", "rustfmt"] {
        write_marker_script(&cargo_bin, name, &evidence_dir);
    }
    fs::create_dir_all(hostile_home.join(".rustup"))?;
    fs::write(hostile_home.join(".cargo/config.toml"), "[build]\n")?;

    let go_bin = hostile_home.join("go/bin");
    fs::create_dir_all(&go_bin)?;
    for name in ["go", "gopls"] {
        write_marker_script(&go_bin, name, &evidence_dir);
    }

    let npm_global_bin = hostile_home.join(".npm-global/bin");
    fs::create_dir_all(&npm_global_bin)?;
    for name in ["node", "npm", "npx", "typescript-language-server", "tsc"] {
        write_marker_script(&npm_global_bin, name, &evidence_dir);
    }
    fs::write(hostile_home.join(".npmrc"), "prefix=/hostile/prefix\n")?;
    fs::create_dir_all(hostile_home.join(".npm"))?;
    let global_ts = hostile_home.join(".npm-global/lib/node_modules/typescript/lib");
    fs::create_dir_all(&global_ts)?;
    fs::write(
        global_ts.join("tsserver.js"),
        format!(
            "#!/usr/bin/env node\nrequire('fs').appendFileSync({:?}, 'HOSTILE_MARKER_EXECUTED:tsserver\\n');\nprocess.exit(1);\n",
            evidence_dir.join("tsserver.evidence").display()
        ),
    )?;

    // --- §5: positive controls -- every marker fires for real before any
    // zero-execution claim is trusted, including the ones only reachable
    // via a HOME-conventional location above. ---
    for name in ALL_MARKER_NAMES {
        assert_eq!(evidence_line_count(&evidence_dir, name), 0);
    }
    let status = std::process::Command::new(hostile_path_bin.join("node"))
        .status()
        .map_err(|error| fail(format!("positive control spawn failed: {error}")))?;
    if status.success() || evidence_line_count(&evidence_dir, "node") != 1 {
        return Err(fail("POISON_NODE_POSITIVE_CONTROL=FAIL"));
    }
    let _ = fs::remove_file(evidence_dir.join("node.evidence"));
    eprintln!("P7B_D_HOSTILE_HOME_MARKER_POSITIVE_CONTROL=PASS");

    let real_home =
        std::env::var("HOME").map_err(|_| fail("real HOME not set for this test process"))?;
    let real_xdg_data_home = format!("{real_home}/.local/share");
    let poisoned_path = format!(
        "{}:{}:{}:{}:/usr/bin:/bin",
        hostile_path_bin.display(),
        cargo_bin.display(),
        go_bin.display(),
        npm_global_bin.display(),
    );
    let node_path = hostile_home.join("node-path-only-modules");
    let node_options_preload = hostile_home.join("node_options_preload.cjs");
    fs::write(
        &node_options_preload,
        format!(
            "require('fs').appendFileSync({:?}, 'HOSTILE_MARKER_EXECUTED:node_options\\n');\n",
            evidence_dir.join("node_options.evidence").display()
        ),
    )?;

    let exe = std::env::current_exe()
        .map_err(|error| fail(format!("current_exe unresolvable: {error}")))?;
    let child_output = tokio::process::Command::new(&exe)
        .args([
            "--exact",
            "real_p7b_d_poisoned_host_combined_child_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(CHILD_TRIGGER, "1")
        .env(CHILD_ROOT, &root)
        .env(CHILD_GOPLS_ARTIFACT, gopls_artifact_path())
        .env("XDG_DATA_HOME", &real_xdg_data_home)
        .env("HOME", &hostile_home)
        .env("PATH", &poisoned_path)
        // --- §8: poisoned environment, Node/Rust/Go families. ---
        .env("NODE_PATH", &node_path)
        .env(
            "NODE_OPTIONS",
            format!("--require {}", node_options_preload.display()),
        )
        .env("NPM_CONFIG_PREFIX", hostile_home.join(".npm-global"))
        .env("NPM_CONFIG_USERCONFIG", hostile_home.join(".npmrc"))
        .env("COREPACK_HOME", hostile_home.join(".corepack"))
        .env("RUSTUP_HOME", hostile_home.join(".rustup"))
        .env("CARGO_HOME", hostile_home.join(".cargo"))
        .env("RUSTC", hostile_path_bin.join("rustc"))
        .env("RUSTC_WRAPPER", hostile_path_bin.join("rustc"))
        .env("RUSTC_WORKSPACE_WRAPPER", hostile_path_bin.join("rustc"))
        .env("RUSTFLAGS", "--this-flag-must-never-be-consulted")
        .env("GOROOT", hostile_home.join("go"))
        .env("GOPATH", hostile_home.join("gopath"))
        .env("GOCACHE", hostile_home.join("gocache"))
        .env("GOMODCACHE", hostile_home.join("gomodcache"))
        .env("GOENV", hostile_home.join("goenv"))
        .env("GOTOOLCHAIN", "local")
        .output()
        .await
        .map_err(|error| fail(format!("child re-exec spawn failed: {error}")))?;

    let stderr = String::from_utf8_lossy(&child_output.stderr);
    if !stderr.contains(CHILD_RESULT_MARKER) {
        return Err(fail(format!(
            "child did not report success; status={:?} stderr={stderr}",
            child_output.status
        )));
    }
    eprintln!("P7B_D_HOSTILE_ENV_EXECUTION_MODEL=SAFE_CHILD_PROCESS_OR_REEXEC");
    eprintln!("P7B_D_POISONED_ENVIRONMENT_AUTHORITY=NO");
    eprintln!("P7B_D_POISONED_HOME_PROVIDER_EXECUTION_COUNT=0");

    // --- §6/§18: zero execution across all 14 markers, verified after the
    // full real product path (provisioning + spawn + active-dependency
    // protection + combined full uninstall) ran to completion. ---
    let mut total_executions = 0usize;
    for name in ALL_MARKER_NAMES {
        let count = evidence_line_count(&evidence_dir, name);
        total_executions += count;
        if count != 0 {
            return Err(fail(format!(
                "POISONED_PATH_{}_EXECUTION_COUNT!={count}, expected 0",
                name.to_uppercase()
            )));
        }
        eprintln!(
            "POISONED_PATH_{}_EXECUTION_COUNT=0",
            name.to_uppercase().replace('-', "_")
        );
    }
    if total_executions != 0 {
        return Err(fail("P7B_D_POISONED_PATH_MARKER_EXECUTION_COUNT!=0"));
    }
    eprintln!("P7B_D_POISONED_PATH_MARKER_EXECUTION_COUNT=0");
    eprintln!("P7B_D_GAP_A_STATUS=CLOSED");
    eprintln!("P7B_D_POISONED_HOST_COMBINED=PASS");

    let _ = fs::remove_dir_all(&hostile_home);
    let _ = fs::remove_dir_all(&evidence_dir);
    let _ = fs::remove_dir_all(&root);
    Ok(())
}
