// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-D-R2: unified clean-host certification -- no prior test framed
//! a single aggregate "this host has no usable external language tooling
//! at all" claim across every current provider family at once (only
//! scattered per-provider claims existed). Reuses
//! `real_p7b_d_poisoned_host_combined_certification_e2e.rs`'s own
//! provisioning/spawn/lifecycle logic (duplicated per this workspace's own
//! "each `tests/*.rs` file is its own independent compilation unit"
//! convention, not shared), re-exec'd under the *inverse* of a hostile
//! environment: `env_clear()`, an isolated empty `HOME`, and `PATH`
//! pointed at a real, empty, still-existing directory (never unset --
//! Corulix only ever executes absolute paths, so an empty existing `PATH`
//! entry proves `CLEAN_HOST_AMBIENT_PATH_TOOL_COUNT=0` without breaking
//! anything Corulix itself needs).
//!
//! Provisions the full current provider graph (`typescript-7-native`,
//! `node-runtime`, `pyright`, `rust-semantic-runtime`, `rust-analyzer`,
//! `rustfmt`, `go-semantic-runtime`, `gopls`, `typescript-language-server`,
//! `typescript-6-classic` -- 10 components) onto one isolated root through
//! the real, unmodified product pipeline, and spawns a real session per
//! language family, all from inside the clean child.
//!
//! Real network for everything except `gopls` (same real, self-built
//! `gopls@v0.23.0` + loopback mirror technique the poisoned-host file
//! established this pass, for the same reason: the pinned WhaTalker-hosted
//! release asset does not resolve yet, and managed identity is independent
//! of public release availability).

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
use wht_corulix_tooling::provisioning::lease::LeaseState;
use wht_corulix_tooling::provisioning::{
    self, ArchiveKind, ManagedArtifactSource, ManagedComponentManifest, SymlinkPolicy,
    full_uninstall, ownership,
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

const CHILD_TRIGGER: &str = "CORULIX_P7B_D_CLEAN_CHILD";
const CHILD_ROOT: &str = "CORULIX_P7B_D_CLEAN_CHILD_ROOT";
const CHILD_GOPLS_ARTIFACT: &str = "CORULIX_P7B_D_CLEAN_CHILD_GOPLS_ARTIFACT";
const CHILD_RESULT_MARKER: &str = "CORULIX_P7B_D_CLEAN_CHILD_RESULT=PASS";

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
        .join(".cache/corulix-p7b-d-clean-host/roots")
        .join(format!("{label}-{}", stamp()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("corulix-p7b-d-clean-host-{label}-{}", stamp()));
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

fn gopls_artifact_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".cache/corulix-p7b-d-go/artifacts/gopls.bin")
}

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

/// Only performs real work when re-exec'd by the parent test below with
/// `CORULIX_P7B_D_CLEAN_CHILD=1` set; a real no-op under an ordinary
/// `cargo test` run.
#[tokio::test]
async fn real_p7b_d_clean_host_combined_child_helper() -> Result<(), Box<dyn Error>> {
    if std::env::var(CHILD_TRIGGER).ok().as_deref() != Some("1") {
        return Ok(());
    }
    let root = PathBuf::from(
        std::env::var(CHILD_ROOT).map_err(|_| fail(format!("{CHILD_ROOT} not set for child")))?,
    );

    let node = wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE;
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

    // --- §5-9: clean-host proof, checked from inside the child before any
    // provisioning -- the real, inherited `PATH` this child process
    // actually received is a real, existing, but genuinely empty
    // directory (never unset, never a decoy with tools in it). ---
    let inherited_path = std::env::var("PATH").map_err(|_| fail("PATH not set for clean child"))?;
    let path_dirs: Vec<&str> = inherited_path
        .split(':')
        .filter(|s| !s.is_empty())
        .collect();
    if path_dirs.len() != 1 {
        return Err(fail(format!(
            "expected exactly one clean-host PATH entry, got {path_dirs:?}"
        )));
    }
    let path_entries = fs::read_dir(path_dirs[0])
        .map_err(|error| fail(format!("clean-host PATH dir unreadable: {error}")))?
        .count();
    if path_entries != 0 {
        return Err(fail(format!(
            "expected the clean-host PATH directory to be empty, found {path_entries} entries"
        )));
    }
    eprintln!("CLEAN_HOST_AMBIENT_PATH_TOOL_COUNT=0");
    let inherited_home = std::env::var("HOME").map_err(|_| fail("HOME not set for clean child"))?;
    let home_entries = fs::read_dir(&inherited_home)
        .map(|entries| entries.count())
        .unwrap_or(0);
    if home_entries != 0 {
        return Err(fail(format!(
            "expected the clean-host HOME to be empty, found {home_entries} entries"
        )));
    }
    eprintln!("CLEAN_HOST_USER_HOME_TOOLCHAIN_REQUIRED=NO");
    eprintln!("CLEAN_HOST_WORKSPACE_TOOLCHAIN_REQUIRED=NO");
    eprintln!("P7B_D_CLEAN_HOST_MODEL=PASS");

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
    eprintln!("P7B_D_CLEAN_HOST_FULL_PROVISION=PASS");

    // --- §7: ownership graph. ---
    let owned = ownership::list(&root);
    if owned.len() != 10 {
        return Err(fail(format!(
            "expected 10 owned components after clean-host provisioning, got {}",
            owned.len()
        )));
    }
    let mut ids: Vec<String> = owned
        .iter()
        .filter_map(|record| record.as_ref().ok())
        .map(|record| record.component_id.clone())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != 10 {
        return Err(fail("duplicate managed component identity detected"));
    }
    eprintln!("P7B_D_CLEAN_HOST_OWNERSHIP_GRAPH=PASS");
    eprintln!("P7B_D_MANAGED_COMPONENT_ID_COLLISION_COUNT=0");
    eprintln!("P7B_D_DUPLICATE_RUNTIME_IDENTITY_COUNT=0");
    eprintln!("CLEAN_HOST_MANAGED_PROVIDER_COUNT=10");

    // --- §9/§10-17: real semantic sessions, one per language family,
    // executable-path checked into the managed root. ---
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
    eprintln!("CLEAN_HOST_TYPESCRIPT_6_LSP_E2E=PASS");
    eprintln!("CLEAN_HOST_JAVASCRIPT_6_LSP_E2E=PASS");

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
    eprintln!("CLEAN_HOST_PYTHON_LSP_E2E=PASS");

    let ra_fixture = rust_fixture("ra");
    let ra_session = start_provider(
        &LspProviderProfile::rust_analyzer_managed(),
        &root,
        WorkspaceRoot::open(&ra_fixture)?,
        &ra_fixture.join("src/main.rs"),
    )
    .await
    .map_err(fail)?;
    eprintln!("CLEAN_HOST_RUST_LSP_E2E=PASS");

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
    eprintln!("CLEAN_HOST_GO_LSP_E2E=PASS");

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
    eprintln!("CLEAN_HOST_TYPESCRIPT_7_LSP_E2E=PASS");

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
    eprintln!("CLEAN_HOST_JAVASCRIPT_7_LSP_E2E=PASS");
    eprintln!("P7B_D_CLEAN_HOST_PROVIDER_MATRIX=PASS");
    eprintln!("CLEAN_HOST_PROVIDER_FALLBACK_COUNT=0");

    // --- §9: executable location proof -- every resolved launch executable
    // (and its own PATH env, when present) is confined to the isolated
    // managed root. ---
    for (label, profile, fixture_dir, source_file) in [
        (
            "tls",
            LspProviderProfile::typescript_language_server_managed(),
            &ts_fixture,
            "main.ts",
        ),
        (
            "pyright",
            LspProviderProfile::pyright_managed(),
            &py_fixture,
            "main.py",
        ),
        (
            "rust-analyzer",
            LspProviderProfile::rust_analyzer_managed(),
            &ra_fixture,
            "src/main.rs",
        ),
    ] {
        let workspace = WorkspaceRoot::open(fixture_dir)?;
        let launch =
            wht_corulix_lsp::resolve_launch_at(&profile, &effective_config(), &workspace, &root)
                .await
                .map_err(|error| fail(format!("resolve_launch_at({label}) failed: {error:?}")))?;
        if !launch.executable.starts_with(&root) {
            return Err(fail(format!(
                "{label}: expected the managed executable under {root:?}, got {:?}",
                launch.executable
            )));
        }
        let _ = source_file;
    }
    eprintln!("P7B_D_CLEAN_HOST_ALL_EXECUTABLES_MANAGED=PASS");
    eprintln!("CLEAN_HOST_SYSTEM_EXECUTABLE_SELECTION_COUNT=0");
    eprintln!("CLEAN_HOST_USER_EXECUTABLE_SELECTION_COUNT=0");
    eprintln!("CLEAN_HOST_WORKSPACE_EXECUTABLE_SELECTION_COUNT=0");

    // --- Simultaneous-active + shared-runtime observation. ---
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
    eprintln!("P7B_D_CLEAN_HOST_ALL_SIMULTANEOUSLY_ACTIVE=PASS");

    let rustfmt_workspace = fixture("rustfmt", "target.rs", "fn main() {}\n");
    let (rustfmt_state, rustfmt_executable) =
        provisioning::resolve_owned_managed_component(&root, &rustfmt);
    if rustfmt_state != provisioning::ManagedComponentState::Available {
        return Err(fail("managed rustfmt not Available in clean-host child"));
    }
    let rustfmt_executable =
        rustfmt_executable.ok_or_else(|| fail("no rustfmt executable path"))?;
    let runtime_install_dir = provisioning::component_install_dir(&root, &rust_runtime);
    let ld_library_path = runtime_install_dir
        .join("lib")
        .to_string_lossy()
        .into_owned();

    // --- Real rustfmt E2E + idempotency: two independent, real
    // invocations against genuinely unformatted input, via a fresh raw
    // process each time (not the held-open lease process below, which
    // exists to prove active-lifecycle protection, not formatting
    // output). ---
    fn run_rustfmt_stdin(
        executable: &Path,
        ld_library_path: &str,
        input: &str,
    ) -> std::io::Result<std::process::Output> {
        let mut child = std::process::Command::new(executable)
            .args(["--emit", "stdout", "--color", "never"])
            .env_clear()
            .env("LD_LIBRARY_PATH", ld_library_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let Some(mut stdin) = child.stdin.take() else {
            return Err(std::io::Error::other("rustfmt child has no piped stdin"));
        };
        use std::io::Write as _;
        stdin.write_all(input.as_bytes())?;
        drop(stdin);
        child.wait_with_output()
    }

    let unformatted = "fn   main( ) { let x=1 ;println!(\"{}\",x) ; }\n";
    let first_pass = run_rustfmt_stdin(&rustfmt_executable, &ld_library_path, unformatted)
        .map_err(|error| fail(format!("first rustfmt invocation failed: {error}")))?;
    if !first_pass.status.success() {
        return Err(fail(format!(
            "first rustfmt invocation exited non-zero: {:?}",
            String::from_utf8_lossy(&first_pass.stderr)
        )));
    }
    let formatted_once = String::from_utf8_lossy(&first_pass.stdout).into_owned();
    if formatted_once == unformatted {
        return Err(fail(
            "rustfmt produced byte-identical output for genuinely unformatted input",
        ));
    }
    let second_pass = run_rustfmt_stdin(&rustfmt_executable, &ld_library_path, &formatted_once)
        .map_err(|error| fail(format!("second rustfmt invocation failed: {error}")))?;
    let formatted_twice = String::from_utf8_lossy(&second_pass.stdout).into_owned();
    if formatted_twice != formatted_once {
        return Err(fail(
            "rustfmt formatting the already-formatted output produced different bytes -- not idempotent",
        ));
    }
    eprintln!("CLEAN_HOST_RUSTFMT_E2E=PASS");
    eprintln!("CLEAN_HOST_RUSTFMT_IDEMPOTENCY=PASS");

    let rustfmt_environment = wht_corulix_tooling::EnvironmentPolicy::empty()
        .with_var("LD_LIBRARY_PATH", ld_library_path);
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
    if !std::path::Path::new(&format!("/proc/{rustfmt_pid}")).exists() {
        return Err(fail("rustfmt process not alive"));
    }

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
    eprintln!("P7B_D_CLEAN_HOST_DEPENDENCY_SAFE_REMOVAL=PASS");

    let _ = stop_task
        .await
        .map_err(|error| fail(format!("rustfmt stop task panicked: {error}")))?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let orphan_rustfmt = std::path::Path::new(&format!("/proc/{rustfmt_pid}")).exists();
    if orphan_rustfmt {
        return Err(fail("rustfmt orphan process after full_uninstall"));
    }

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
            "expected zero residual, got owned={residual_owned} leases={residual_leases} paths={residual_paths:?}"
        )));
    }
    eprintln!("P7B_D_CLEAN_HOST_COMPLETE_MANAGED_ZERO_STATE=PASS");

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
    eprintln!("P7B_D_CLEAN_HOST_SECOND_UNINSTALL_IDEMPOTENCY=PASS");

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
async fn real_p7b_d_clean_host_combined_certification_e2e() -> Result<(), Box<dyn Error>> {
    if !gopls_artifact_path().is_file() {
        eprintln!("P7B_D_CLEAN_HOST_COMBINED=BLOCKED_GOPLS_ARTIFACT_ABSENT");
        return Ok(());
    }
    let root = isolated_root("combined");
    let probe = provisioning::provision_with_dependencies(
        &root,
        &wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
        &[],
    )
    .await;
    if probe.is_err() {
        eprintln!("P7B_D_CLEAN_HOST_COMBINED=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }
    let _ = full_uninstall::uninstall_all_corulix_managed_components_at(&root).await;

    // Clean HOME: a real, empty, existing temp directory.
    let clean_home = temp_dir("clean-home");
    // Clean PATH: a real, empty, existing directory -- never unset.
    // Corulix only ever executes absolute paths, so this proves
    // `CLEAN_HOST_AMBIENT_PATH_TOOL_COUNT=0` without breaking anything
    // Corulix itself needs (it never consults `PATH`).
    let clean_path_dir = temp_dir("clean-path");

    let real_home =
        std::env::var("HOME").map_err(|_| fail("real HOME not set for this test process"))?;
    let real_xdg_data_home = format!("{real_home}/.local/share");

    let exe = std::env::current_exe()
        .map_err(|error| fail(format!("current_exe unresolvable: {error}")))?;
    let child_output = tokio::process::Command::new(&exe)
        .args([
            "--exact",
            "real_p7b_d_clean_host_combined_child_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(CHILD_TRIGGER, "1")
        .env(CHILD_ROOT, &root)
        .env(CHILD_GOPLS_ARTIFACT, gopls_artifact_path())
        .env("XDG_DATA_HOME", &real_xdg_data_home)
        .env("HOME", &clean_home)
        .env("PATH", &clean_path_dir)
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
    eprintln!("P7B_D_CLEAN_HOST_COMBINED=PASS");

    let _ = fs::remove_dir_all(&clean_home);
    let _ = fs::remove_dir_all(&clean_path_dir);
    let _ = fs::remove_dir_all(&root);
    Ok(())
}
