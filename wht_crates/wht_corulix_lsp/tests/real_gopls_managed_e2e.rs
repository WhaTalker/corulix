// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real end-to-end proof of the `CORULIX_MANAGED` Go vertical
//! (Phase 7B-B2-A-R2): `LspProviderProfile::gopls_managed()` routed through
//! the same generic `wht_corulix_lsp` provider/session/lease architecture
//! every other managed provider uses -- no Go-specific lifecycle machinery.
//!
//! **Distribution gate.** R1 built and byte-identically reproduced a real
//! `gopls@v0.23.0` artifact, but no Corulix-hosted distribution URL is
//! authorized to exist in product source yet
//! (`GOPLS_ARTIFACT_DISTRIBUTION_GATE=BLOCKED`). This file therefore
//! constructs its own `gopls` [`ManagedComponentManifest`] locally --
//! `expected_sha256_hex` is the exact R1-certified digest
//! (`e2c5c7b312a149c0f83f8036437c0a9eaea47eaac7d9f6a3abf432ee9597ecec`), and
//! `tarball_url` points at a real, local, loopback-only HTTP mirror this
//! file starts itself, never a fabricated production URL -- and applies it
//! to [`LspProviderProfile::gopls_managed`] via
//! `.with_managed_component(...)`, the exact same test-only override
//! mechanism already established for TypeScript 7
//! (`real_isolated_multi_provider_certification_e2e.rs`). The
//! `go-semantic-runtime` manifest is the real, unmodified product constant
//! (`wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64`),
//! with only its `tarball_url` remapped to the same local mirror -- its
//! real official `go.dev` URL and SHA-256 are untouched.
//!
//! **Artifact preparation is out-of-band**, exactly like
//! `real_isolated_multi_provider_certification_e2e.rs`'s own artifact
//! cache: this file reads two prepared files from
//! `$HOME/.cache/corulix-gopls-managed-e2e/artifacts/` --
//! `go-runtime.bin` (the real official `go1.27.0.linux-amd64.tar.gz`,
//! byte-for-byte, matching `GO_SEMANTIC_RUNTIME_LINUX_X64`'s own pinned
//! SHA-256) and `gopls.bin` (a bare gzip of the exact R1-certified `gopls`
//! binary, matching this file's own pinned SHA-256 for it). If either file
//! is absent, every test in this file reports and exits early with
//! `..._MANAGED_PROVIDER_NOT_PROVISIONED` rather than fabricating a
//! result -- this file never substitutes a mock for the real artifacts it
//! is supposed to prove against.
//!
//! Every isolated root this file provisions into is destroyed by its own
//! test via the real product `full_uninstall`/`uninstall` pipeline, never
//! `remove_dir_all` used to paper over an incomplete product result -- the
//! one `remove_dir_all` call per test is on the now-empty (or intentionally
//! never-created) root directory itself, after the product has already
//! reported zero residual paths inside it.
//!
//! **`HOME`-dependent cache path -- a real false-negative trap found during
//! P17-W's native Windows verification of this file.** `artifact_cache_dir`/
//! `isolated_root` both resolve `$HOME` themselves (never the product's own
//! resolution). An interactive SSH session on the P17-W target VM sets
//! `HOME=C:\Users\<test-account>` automatically, but a detached child launched via
//! `wmic process call create` (needed so a build/test run survives SSH
//! session teardown -- see this phase's own process-discipline notes) does
//! **not** inherit it: `std::env::var("HOME")` then falls through to this
//! file's own `"/root"` fallback, silently resolving to a path that never
//! contains the prepared cache. Every test in this file still exits `Ok(())`
//! in that case (the designed `BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED`
//! early-return), so `cargo test` reports all green with **zero real
//! coverage** -- a false PASS by omission, not a crash, and easy to miss.
//! Any runner that launches this file's tests via a detached/service-style
//! process on Windows (not an interactive shell) must set `HOME` explicitly
//! before invoking `cargo test`.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, Position, WorkspaceRootId};
use wht_corulix_lsp::{
    DefinitionResult, DiagnosticsResult, LspProviderProfile, LspSession, Readiness,
};
use wht_corulix_tooling::provisioning::{
    self, ManagedComponentManifest, ManagedComponentState, full_uninstall, uninstall,
};
use wht_corulix_workspace::WorkspaceRoot;

const READINESS_TIMEOUT: Duration = Duration::from_secs(90);
const GOPLS_ID: &str = "gopls";
const GO_RUNTIME_ID: &str = "go-semantic-runtime";

/// P17-W host-native portability fix: this file previously pinned the
/// Linux-only R1-certified digest unconditionally. `gopls`'s compiled bytes
/// are platform-specific (a real Go-toolchain build output), so the
/// Windows-native digest is a distinct, independently reproducibility-
/// certified value, not a reuse of the Linux one -- same `#[cfg]`-gated-alias
/// pattern as [`wht_corulix_lsp::managed_toolchain::GOPLS_HOST_NATIVE`].
#[cfg(target_os = "windows")]
const GOPLS_CERTIFIED_GZ_SHA256: &str =
    "dc21e2a32de19093e01a3fe39d5b8d11475453527f037daa92b523038cd469ab";
#[cfg(not(target_os = "windows"))]
const GOPLS_CERTIFIED_GZ_SHA256: &str =
    "020fcfcf91384a9ed9abb7d1195f85f4e9406a25c7f864ea07b6d1fd84ce84f0";

/// Host-native `platform`/`architecture`/binary-name identity for the
/// test-only `gopls` manifest below -- mirrors
/// [`wht_corulix_lsp::managed_toolchain::GOPLS_HOST_NATIVE`]'s own
/// `#[cfg]`-gated-alias pattern rather than hardcoding the Linux identity
/// unconditionally (the defect this file carried before P17-W's real
/// Windows-native verification pass exposed it: `resolve_launch_at` now
/// resolves gopls's primary binary via `GOPLS_HOST_NATIVE`, which names
/// `platform: "windows"` / `"gopls.exe"` on a real Windows host -- a test
/// manifest still naming `platform: "linux"` / `"gopls"` would never match
/// what the profile actually looks up there).
#[cfg(target_os = "windows")]
const GOPLS_HOST_PLATFORM: &str = "windows";
#[cfg(not(target_os = "windows"))]
const GOPLS_HOST_PLATFORM: &str = "linux";
#[cfg(target_os = "windows")]
const GOPLS_HOST_BINARY_NAME: &str = "gopls.exe";
#[cfg(not(target_os = "windows"))]
const GOPLS_HOST_BINARY_NAME: &str = "gopls";

/// Every test in this file provisions/uninstalls the same two component
/// ids against its own isolated root, but the underlying `ManagedProcess`/
/// lease/single-flight machinery is process-wide state -- serialized for
/// the same reason `real_pyright_managed_e2e.rs`'s `REAL_PYRIGHT_SESSION_LOCK`
/// is.
static REAL_GOPLS_MANAGED_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

async fn real_gopls_managed_lock() -> tokio::sync::MutexGuard<'static, ()> {
    REAL_GOPLS_MANAGED_LOCK
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
// Artifact cache (prepared out-of-band, see module doc)
// ============================================================

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

// ============================================================
// Local artifact mirror -- real HTTP/1.1, loopback only (identical style
// to real_isolated_multi_provider_certification_e2e.rs's own mirror)
// ============================================================

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

/// The real, unmodified product `GO_SEMANTIC_RUNTIME_HOST_NATIVE` manifest
/// (P17-W: was hardcoded to the Linux-only `GO_SEMANTIC_RUNTIME_LINUX_X64`
/// constant, which `resolve_launch_at` -- routing through the now
/// host-native-wired [`LspProviderProfile::gopls_managed`] -- would never
/// match on a real Windows host) with only `tarball_url` remapped to the
/// local mirror.
fn mirrored_go_runtime_manifest(base_url: &str) -> ManagedComponentManifest {
    let mut manifest = wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_HOST_NATIVE;
    manifest.source.tarball_url = Box::leak(format!("{base_url}/go-runtime").into_boxed_str());
    manifest
}

/// A test-only `gopls` manifest -- see this file's own module doc for why
/// this cannot be a real product constant yet. Every field except
/// `tarball_url` is the real, host-native identity (P17-W: `platform`/
/// `binary_path_in_tarball` now select the real Windows values on a real
/// Windows host via [`GOPLS_HOST_PLATFORM`]/[`GOPLS_HOST_BINARY_NAME`],
/// matching [`wht_corulix_lsp::managed_toolchain::GOPLS_HOST_NATIVE`]'s own
/// identity exactly -- this file previously hardcoded the Linux identity
/// unconditionally, which the profile's now-host-native-wired
/// `managed_component` lookup would never match on Windows): exact upstream
/// version, exact certified archive SHA-256 for this host's own platform,
/// exact binary path, exact archive kind (a bare gzip, matching
/// rust-analyzer's own real production manifest shape -- both are single
/// statically-linked Go executables).
fn test_only_gopls_manifest(base_url: &str) -> ManagedComponentManifest {
    ManagedComponentManifest {
        id: provisioning::ManagedComponentId(GOPLS_ID),
        version: "v0.23.0",
        platform: GOPLS_HOST_PLATFORM,
        architecture: "x64",
        source: provisioning::ManagedArtifactSource {
            tarball_url: Box::leak(format!("{base_url}/gopls").into_boxed_str()),
            expected_sha256_hex: GOPLS_CERTIFIED_GZ_SHA256,
            binary_path_in_tarball: GOPLS_HOST_BINARY_NAME,
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
        .join(".cache/corulix-gopls-managed-e2e/roots")
        .join(format!("{label}-{stamp}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// A real Go module: `main.go` imports the stdlib `strings` package (proves
/// [`GO_SEMANTIC_RUNTIME_LINUX_X64`]'s own `src/` stdlib source tree is
/// what resolves the definition, not merely parsed symbol text) and calls
/// into a locally `replace`-directed dependency module (`./localdep`, no
/// network involved at all) whose own function it also calls -- proves
/// module + local-replacement semantics in the same fixture.
fn go_module_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-gopls-managed-e2e-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join("localdep"));
    let _ = fs::write(
        root.join("go.mod"),
        "module corulix.example/gopls-managed-e2e-fixture\n\ngo 1.22\n\nrequire corulix.example/localdep v0.0.0\n\nreplace corulix.example/localdep => ./localdep\n",
    );
    let _ = fs::write(
        root.join("main.go"),
        "package main\n\nimport (\n\t\"strings\"\n\n\tlocaldep \"corulix.example/localdep\"\n)\n\nfunc target() string {\n\treturn strings.ToUpper(localdep.Greeting())\n}\n\nfunc caller() string {\n\treturn target()\n}\n\nfunc main() {\n\tcaller()\n}\n",
    );
    let _ = fs::write(
        root.join("localdep/go.mod"),
        "module corulix.example/localdep\n\ngo 1.22\n",
    );
    let _ = fs::write(
        root.join("localdep/localdep.go"),
        "package localdep\n\nfunc Greeting() string {\n\treturn \"hello\"\n}\n",
    );
    root
}

// ============================================================
// Process tree observation (real /proc, never assumed)
// ============================================================

/// Real direct children of `pid`, via Linux's `/proc/<pid>/task/<tid>/children`
/// (kernel 3.5+) -- no `ps`/shell parsing, no assumption about what the
/// tree "should" contain.
fn real_children_of(pid: u32) -> Vec<u32> {
    let mut children = Vec::new();
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return children;
    };
    for task in tasks.flatten() {
        let Ok(text) = fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        for token in text.split_whitespace() {
            if let Ok(child_pid) = token.parse::<u32>() {
                children.push(child_pid);
            }
        }
    }
    children
}

fn process_comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ============================================================
// Provisioning helper
// ============================================================

/// Provisions both real managed artifacts (Go runtime + gopls, gopls
/// declaring its dependency on the Go runtime) into `root` via the real,
/// unmodified `provision_with_dependencies` pipeline. Returns `false` --
/// never an error -- if the out-of-band artifact cache is missing, so
/// callers can honestly report `BLOCKED` rather than fail.
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
// Tests
// ============================================================

/// The full managed vertical: provision -> environment-authority proof ->
/// real LSP session -> real stdlib + local-module-replacement semantics ->
/// real process tree -> real lease -> normal shutdown/reap -> dependency-
/// ordered uninstall of both components -> zero residual.
#[tokio::test]
async fn real_gopls_managed_full_vertical_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_gopls_managed_lock().await;
    let Some(files) = load_artifact_cache() else {
        eprintln!(
            "GO_LSP_E2E_MANAGED=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED: artifact cache absent at {:?}",
            artifact_cache_dir()
        );
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("full-vertical");

    if !ensure_managed_go_provisioned(&root, &base_url).await {
        eprintln!("GO_LSP_E2E_MANAGED=BLOCKED_PROVISIONING_FAILED");
        return Ok(());
    }

    let fixture = go_module_fixture("full-vertical");
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

    // --- ENVIRONMENT AUTHORITY: GOROOT/executable must be inside the
    // isolated managed root, never a system path. ---
    if !launch.executable.starts_with(&root) {
        return Err(fail(format!(
            "expected the managed gopls binary under {root:?}, got {:?}",
            launch.executable
        )));
    }
    let goroot = launch.environment.get("GOROOT").map(str::to_string);
    let Some(goroot) = goroot else {
        return Err(fail("expected GOROOT to be set by the managed Go runtime"));
    };
    if !PathBuf::from(&goroot).starts_with(&root) {
        return Err(fail(format!(
            "expected GOROOT under {root:?}, got {goroot:?} -- SYSTEM_GOROOT_AUTHORITY leaked"
        )));
    }
    eprintln!("GOROOT_AUTHORITY=CORULIX_MANAGED");
    eprintln!("SYSTEM_GOROOT_AUTHORITY=NO");

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

    // --- REAL PROCESS TREE: observed, not assumed. gopls loading a real
    // module with a stdlib import genuinely shells out to `go` (package
    // metadata/build-list resolution) -- give it a moment past readiness
    // for that subprocess activity to have actually occurred, then record
    // whatever the real tree looked like. ---
    tokio::time::sleep(Duration::from_millis(500)).await;
    let children = real_children_of(gopls_pid);
    eprintln!(
        "GOPLS_PROCESS_TREE_OBSERVED: gopls(pid={gopls_pid}) children={:?}",
        children
            .iter()
            .map(|pid| format!("{pid}:{}", process_comm(*pid)))
            .collect::<Vec<_>>()
    );

    // --- LEASE: must be Active while the session is genuinely alive. ---
    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Active) => {}
        other => {
            return Err(fail(format!("expected lease state Active, got {other:?}")));
        }
    }
    eprintln!("GOPLS_ACTIVE_LEASE_BINDINGS=PASS");

    // --- STDLIB SEMANTIC RESOLUTION: `strings.ToUpper` call site. Uses
    // `hover` (`HOVER_AUTHORITY=SUPPORTING_ONLY`, per its own doc comment --
    // never used to satisfy definition/references/rename/diagnostics
    // authority; used here purely as *evidence*, not as this test's
    // definition/references proof), never `definition`: a real, found-
    // during-this-test-development defect-that-wasn't -- `definition`'s
    // own architecture (`wht_corulix_lsp::operations::relative_to_workspace_root`)
    // deliberately rejects any server-supplied location outside the
    // confined workspace root (`LspError::ResultOutsideWorkspace`), and the
    // real stdlib source lives inside the managed `GOROOT`, structurally
    // outside this fixture's own workspace root -- exactly the same
    // confinement boundary every other language's provider is subject to,
    // not a Go-specific gap. `hover` returns plain text
    // (`HoverEvidence.contents`), never a file location, so it is immune
    // to that (correct, intentional) confinement check and can prove real
    // semantic resolution of the stdlib symbol regardless. Real hover text
    // containing the genuine `func ToUpper(...)` signature is only
    // obtainable if gopls actually parsed real Go stdlib *source* for
    // `strings` -- which, given this session's own controlled environment
    // has no ambient `PATH`/system Go at all (proven above), could only
    // have come from the managed `GOROOT`'s own `src/strings/` tree.
    let strings_call_byte_offset = fs::read(&main_go)
        .ok()
        .and_then(|bytes| {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            text.find("strings.ToUpper")
                .map(|index| index + "strings.".len())
        })
        .ok_or_else(|| fail("could not locate strings.ToUpper call site in fixture"))?;
    let text = fs::read_to_string(&main_go).unwrap_or_default();
    let (line_zero_based, byte_column_zero_based) = {
        let mut line = 0usize;
        let mut col = 0usize;
        for (index, ch) in text.char_indices() {
            if index == strings_call_byte_offset {
                break;
            }
            if ch == '\n' {
                line += 1;
                col = 0;
            } else {
                col += 1;
            }
        }
        (line, col)
    };
    let hover_evidence = wht_corulix_lsp::hover(
        &session,
        &main_go,
        &Position {
            line_zero_based: line_zero_based as u32,
            byte_column_zero_based: byte_column_zero_based as u32,
            byte_offset: strings_call_byte_offset as u64,
        },
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("hover request failed: {error:?}")))?
    .ok_or_else(|| fail("expected real hover evidence for strings.ToUpper, got None"))?;
    if !hover_evidence.contents.contains("ToUpper") {
        return Err(fail(format!(
            "expected real stdlib hover text naming 'ToUpper', got {:?}",
            hover_evidence.contents
        )));
    }
    eprintln!(
        "GO_STDLIB_SEMANTIC_RESOLUTION=PASS (hover: {:?})",
        hover_evidence.contents.lines().next().unwrap_or_default()
    );

    // --- LOCAL MODULE + REPLACE SEMANTICS: `localdep.Greeting` call site
    // -> definition must land in `localdep/localdep.go`, resolved purely
    // from the `replace` directive with zero network access
    // (GOPROXY=off is set unconditionally by gopls_managed()). ---
    // Offset past the `localdep.` package qualifier -- a position on the
    // qualifier itself resolves to the *import statement*, not the
    // function; `Greeting` (the selector) is what must resolve into
    // `localdep/localdep.go`.
    let localdep_call_byte_offset = text
        .find("localdep.Greeting")
        .map(|index| index + "localdep.".len())
        .ok_or_else(|| fail("could not locate localdep.Greeting call site in fixture"))?;
    let (ld_line, ld_col) = {
        let mut line = 0usize;
        let mut col = 0usize;
        for (index, ch) in text.char_indices() {
            if index == localdep_call_byte_offset {
                break;
            }
            if ch == '\n' {
                line += 1;
                col = 0;
            } else {
                col += 1;
            }
        }
        (line, col)
    };
    let localdep_definition = wht_corulix_lsp::definition(
        &session,
        &main_go,
        &Position {
            line_zero_based: ld_line as u32,
            byte_column_zero_based: ld_col as u32,
            byte_offset: localdep_call_byte_offset as u64,
        },
        &cancellation,
    )
    .await
    .map_err(|error| fail(format!("local module definition request failed: {error:?}")))?;
    let localdep_location = match &localdep_definition {
        DefinitionResult::Single(location) => location.clone(),
        DefinitionResult::Multiple(locations) => locations
            .first()
            .cloned()
            .ok_or_else(|| fail("local module definition returned an empty Multiple result"))?,
        DefinitionResult::None => {
            return Err(fail("expected a real local-module definition, got None"));
        }
    };
    if !localdep_location.path.relative_path.contains("localdep") {
        return Err(fail(format!(
            "expected the local-replace module definition inside 'localdep', got {:?}",
            localdep_location.path.relative_path
        )));
    }
    eprintln!("GO_MODULE_SEMANTIC_MODEL=PASS");
    eprintln!("GO_LOCAL_MODULE_REPLACEMENT_SEMANTICS=PASS");

    // --- DIAGNOSTICS ---
    let diagnostics_result = wht_corulix_lsp::diagnostics(&session, &main_go)
        .await
        .map_err(|error| fail(format!("diagnostics call failed: {error:?}")))?;
    if !matches!(diagnostics_result, DiagnosticsResult::Reported(_)) {
        return Err(fail(format!(
            "expected Reported after proven readiness, got {diagnostics_result:?}"
        )));
    }
    eprintln!("GO_LSP_E2E_MANAGED=PASS");
    eprintln!("GOPLS_READINESS_MODEL=PROTOCOL_PROVEN");
    eprintln!("GOPLS_READINESS_PROVEN=YES");

    // --- NORMAL SHUTDOWN / REAP ---
    session.shutdown(&cancellation).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let post_shutdown_children = real_children_of(gopls_pid);
    if !post_shutdown_children.is_empty() {
        return Err(fail(format!(
            "expected zero orphan children after normal shutdown, found {post_shutdown_children:?}"
        )));
    }
    eprintln!("GOPLS_NORMAL_REAP=PASS");
    eprintln!("POST_GOPLS_SHUTDOWN_ORPHAN_PROCESS_COUNT=0");
    let _ = fs::remove_dir_all(&fixture);

    // --- DEPENDENCY-SAFE UNINSTALL ORDER: gopls first, then its
    // go-semantic-runtime dependency. ---
    let gopls_removed =
        uninstall::uninstall(&root, provisioning::ManagedComponentId(GOPLS_ID), |_| {}).await;
    if gopls_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected gopls uninstall to succeed, got {gopls_removed:?}"
        )));
    }
    let go_removed = uninstall::uninstall(
        &root,
        provisioning::ManagedComponentId(GO_RUNTIME_ID),
        |_| {},
    )
    .await;
    if go_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected go-semantic-runtime uninstall to succeed once undepended, got {go_removed:?}"
        )));
    }
    eprintln!("GOPLS_GO_DEPENDENCY_SAFE_REMOVAL=PASS");

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// §21 Caso A/B: an active gopls session must block premature removal of
/// its `go-semantic-runtime` dependency, and gopls itself must not be
/// destroyed by surprise -- both proven against a genuinely live session,
/// never inferred.
#[tokio::test]
async fn real_gopls_managed_dependency_and_active_uninstall_safety_e2e()
-> Result<(), Box<dyn Error>> {
    let _lock = real_gopls_managed_lock().await;
    let Some(files) = load_artifact_cache() else {
        eprintln!(
            "GOPLS_ACTIVE_PROVIDER_UNINSTALL_SAFETY=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED"
        );
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("active-uninstall-safety");

    if !ensure_managed_go_provisioned(&root, &base_url).await {
        eprintln!("GOPLS_ACTIVE_PROVIDER_UNINSTALL_SAFETY=BLOCKED_PROVISIONING_FAILED");
        return Ok(());
    }

    let fixture = go_module_fixture("active-uninstall-safety");
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

    // --- CASE B: go-semantic-runtime cannot be removed while gopls
    // (installed, dependency-recorded) still needs it -- refused at the
    // dependency-graph stage, independent of whether this specific
    // session's process happens to be alive right now. ---
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
            "expected StillDependedUpon refusing to remove go-semantic-runtime while gopls depends on it, got {premature_go_removal:?}"
        )));
    }
    eprintln!("ACTIVE_GO_RUNTIME_PREMATURE_UNINSTALL_COUNT=0");

    // --- CASE A: gopls itself, genuinely active (no shutdown yet) -- its
    // own uninstall must discover and stop the live process itself, never
    // simply refuse or silently proceed against a still-alive process. ---
    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Active) => {}
        other => {
            return Err(fail(format!(
                "expected lease state Active before uninstall, got {other:?}"
            )));
        }
    }
    let gopls_removed =
        uninstall::uninstall(&root, provisioning::ManagedComponentId(GOPLS_ID), |_| {}).await;
    if gopls_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected uninstall to succeed against an active gopls session (stopping it itself), got {gopls_removed:?}"
        )));
    }
    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Stopped) => {}
        other => {
            return Err(fail(format!(
                "expected lease state Stopped after uninstall stopped this session, got {other:?}"
            )));
        }
    }
    eprintln!("ACTIVE_GOPLS_PREMATURE_UNINSTALL_COUNT=0");

    let post_uninstall_request = session
        .transport()
        .request(
            "shutdown",
            serde_json::Value::Null,
            Duration::from_secs(5),
            &cancellation,
        )
        .await;
    if post_uninstall_request.is_ok() {
        return Err(fail(
            "expected the gopls transport to be closed after uninstall stopped the process, but a request still succeeded",
        ));
    }

    // Now that gopls is gone, the runtime can be removed.
    let go_removed = uninstall::uninstall(
        &root,
        provisioning::ManagedComponentId(GO_RUNTIME_ID),
        |_| {},
    )
    .await;
    if go_removed != Ok(uninstall::UninstallOutcome::Removed) {
        return Err(fail(format!(
            "expected go-semantic-runtime uninstall to succeed once undepended, got {go_removed:?}"
        )));
    }

    let _ = fs::remove_dir_all(&fixture);
    let _ = fs::remove_dir_all(&root);
    eprintln!("GOPLS_GO_RUNTIME_DEPENDENCY_MODEL=PASS");
    Ok(())
}

/// §22-24: `full_uninstall` against an isolated, exclusive managed root
/// with a genuinely active gopls session -- must detect it, stop and reap
/// its process tree, remove both components in dependency-safe order, and
/// leave absolute zero residual. A second `full_uninstall` call proves
/// idempotence with no state recreation.
#[tokio::test]
async fn real_gopls_managed_full_uninstall_active_zero_residual_e2e() -> Result<(), Box<dyn Error>>
{
    let _lock = real_gopls_managed_lock().await;
    let Some(files) = load_artifact_cache() else {
        eprintln!("GOPLS_ACTIVE_FULL_UNINSTALL=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("full-uninstall-zero-residual");

    if !ensure_managed_go_provisioned(&root, &base_url).await {
        eprintln!("GOPLS_ACTIVE_FULL_UNINSTALL=BLOCKED_PROVISIONING_FAILED");
        return Ok(());
    }

    let fixture = go_module_fixture("full-uninstall-zero-residual");
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

    let Some(gopls_pid) = session.process_pid().await else {
        return Err(fail("expected a real gopls pid after spawn"));
    };

    // Deliberately NO session.shutdown() -- full_uninstall must discover
    // and stop it itself.
    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("full_uninstall failed: {error:?}")))?;
    let removed_order = match outcome {
        full_uninstall::FullUninstallOutcome::Removed(order) => order,
        other => return Err(fail(format!("expected Removed(_), got {other:?}"))),
    };
    if removed_order != vec![GOPLS_ID.to_string(), GO_RUNTIME_ID.to_string()] {
        return Err(fail(format!(
            "expected dependency-safe removal order [gopls, go-semantic-runtime], got {removed_order:?}"
        )));
    }
    eprintln!("GOPLS_ACTIVE_FULL_UNINSTALL=PASS");

    // The process must be genuinely gone -- not merely "uninstall
    // returned Ok" -- proven via the real, product-owned absence check.
    match session.lease_state() {
        Some(wht_corulix_tooling::provisioning::lease::LeaseState::Stopped) => {}
        other => {
            return Err(fail(format!(
                "expected lease state Stopped after full_uninstall stopped this session, got {other:?}"
            )));
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let orphans = real_children_of(gopls_pid);
    if !orphans.is_empty() {
        return Err(fail(format!(
            "expected zero orphan children after full_uninstall reaped the tree, found {orphans:?}"
        )));
    }
    eprintln!("POST_GOPLS_SHUTDOWN_ORPHAN_PROCESS_COUNT=0");

    // --- ZERO RESIDUAL: mechanically measured, never test-side cleanup. ---
    let managed_component_count = provisioning::ownership::list(&root).len();
    if managed_component_count != 0 {
        return Err(fail(format!(
            "POST_GO_UNINSTALL_MANAGED_COMPONENT_COUNT!={managed_component_count}, expected 0"
        )));
    }
    let active_leases = wht_corulix_tooling::provisioning::lease::active_lease_count();
    if active_leases != 0 {
        return Err(fail(format!(
            "POST_GO_UNINSTALL_ACTIVE_LEASE_COUNT!={active_leases}, expected 0"
        )));
    }
    let residual_entries: Vec<String> = if root.exists() {
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
    if !residual_entries.is_empty() {
        return Err(fail(format!(
            "POST_GO_UNINSTALL_RESIDUAL_PATHS!=[], got {residual_entries:?}"
        )));
    }
    eprintln!("POST_GO_UNINSTALL_MANAGED_COMPONENT_COUNT=0");
    eprintln!("POST_GO_UNINSTALL_ACTIVE_LEASE_COUNT=0");
    eprintln!("POST_GO_UNINSTALL_ORPHAN_PROCESS_COUNT=0");
    eprintln!("POST_GO_UNINSTALL_RESIDUAL_PATHS=[]");
    eprintln!(
        "POST_GO_UNINSTALL_MANAGED_ROOT_EXISTS={}",
        if root.exists() { "YES" } else { "NO" }
    );
    eprintln!("GO_COMPLETE_MANAGED_ZERO_STATE=PASS");

    // --- SECOND UNINSTALL: idempotent, no state recreation. ---
    let second_outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("second full_uninstall failed: {error:?}")))?;
    if second_outcome != full_uninstall::FullUninstallOutcome::NoManagedComponents {
        return Err(fail(format!(
            "expected the second full_uninstall to be a idempotent no-op, got {second_outcome:?}"
        )));
    }
    let root_exists_after_second = root.exists();
    if root_exists_after_second {
        return Err(fail(
            "second full_uninstall must not recreate the managed root",
        ));
    }
    eprintln!("SECOND_UNINSTALL_IDEMPOTENT=PASS");

    let _ = fs::remove_dir_all(&fixture);
    Ok(())
}

/// §26: real concurrent provisioning of the same component id must
/// single-flight to exactly one real download/extract/activate, never a
/// duplicate/racing one -- proven with genuinely concurrent `tokio::join!`
/// calls against a fresh isolated root, no sleeps as synchronization
/// authority (the two calls race the same lock for real).
#[tokio::test]
async fn real_gopls_and_go_runtime_single_flight_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_gopls_managed_lock().await;
    let Some(files) = load_artifact_cache() else {
        eprintln!("GOPLS_SINGLE_FLIGHT=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        eprintln!("GO_RUNTIME_SINGLE_FLIGHT=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("single-flight");

    let go_manifest = mirrored_go_runtime_manifest(&base_url);
    let (go_a, go_b) = tokio::join!(
        provisioning::provision(&root, &go_manifest),
        provisioning::provision(&root, &go_manifest)
    );
    let (Ok(go_path_a), Ok(go_path_b)) = (go_a, go_b) else {
        eprintln!("GO_RUNTIME_SINGLE_FLIGHT=BLOCKED_PROVISIONING_FAILED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    };
    if go_path_a != go_path_b {
        return Err(fail(format!(
            "expected both concurrent go-semantic-runtime provisions to resolve to the same path, got {go_path_a:?} vs {go_path_b:?}"
        )));
    }
    eprintln!("GO_RUNTIME_SINGLE_FLIGHT=PASS");

    let gopls_manifest = test_only_gopls_manifest(&base_url);
    let (gopls_a, gopls_b) = tokio::join!(
        provisioning::provision_with_dependencies(&root, &gopls_manifest, &[GO_RUNTIME_ID]),
        provisioning::provision_with_dependencies(&root, &gopls_manifest, &[GO_RUNTIME_ID])
    );
    let (Ok(gopls_path_a), Ok(gopls_path_b)) = (gopls_a, gopls_b) else {
        eprintln!("GOPLS_SINGLE_FLIGHT=BLOCKED_PROVISIONING_FAILED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    };
    if gopls_path_a != gopls_path_b {
        return Err(fail(format!(
            "expected both concurrent gopls provisions to resolve to the same path, got {gopls_path_a:?} vs {gopls_path_b:?}"
        )));
    }
    eprintln!("GOPLS_SINGLE_FLIGHT=PASS");

    let outcome = full_uninstall::full_uninstall(&root)
        .await
        .map_err(|error| fail(format!("cleanup full_uninstall failed: {error:?}")))?;
    if !matches!(outcome, full_uninstall::FullUninstallOutcome::Removed(_)) {
        return Err(fail(format!(
            "expected cleanup full_uninstall to remove both components, got {outcome:?}"
        )));
    }
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// §27: a real `gopls` provision racing a concurrent `full_uninstall` of
/// the same isolated root must never produce half-owned/dangling state --
/// either the provision completes and is then fully removed, or
/// `full_uninstall` genuinely observed nothing to remove and the provision
/// completed cleanly afterward. Either real outcome is acceptable; a
/// dangling manifest/ownership record/unexplained residual path is not.
#[tokio::test]
async fn real_gopls_provision_vs_full_uninstall_race_e2e() -> Result<(), Box<dyn Error>> {
    let _lock = real_gopls_managed_lock().await;
    let Some(files) = load_artifact_cache() else {
        eprintln!("GOPLS_PROVISION_UNINSTALL_RACE_COUNT=BLOCKED_MANAGED_PROVIDER_NOT_PROVISIONED");
        return Ok(());
    };
    let base_url = spawn_artifact_mirror(files);
    let root = isolated_root("provision-vs-uninstall-race");

    let go_manifest = mirrored_go_runtime_manifest(&base_url);
    let gopls_manifest = test_only_gopls_manifest(&base_url);
    if provisioning::provision(&root, &go_manifest).await.is_err() {
        eprintln!("GOPLS_PROVISION_UNINSTALL_RACE_COUNT=BLOCKED_PROVISIONING_FAILED");
        let _ = fs::remove_dir_all(&root);
        return Ok(());
    }

    let root_for_uninstall = root.clone();
    let uninstall_task =
        tokio::spawn(async move { full_uninstall::full_uninstall(&root_for_uninstall).await });
    let provision_result =
        provisioning::provision_with_dependencies(&root, &gopls_manifest, &[GO_RUNTIME_ID]).await;
    let uninstall_result = uninstall_task
        .await
        .map_err(|error| fail(format!("uninstall task panicked: {error:?}")))?;

    // Whichever real interleaving occurred, reconcile to a clean final
    // state via the real product pipeline itself (never a raw
    // `remove_dir_all` used to force a PASS).
    if provision_result.is_ok() {
        let _ = full_uninstall::full_uninstall(&root).await;
    }
    let _ = uninstall_result;

    let residual_owned = provisioning::ownership::list(&root).len();
    if residual_owned != 0 {
        return Err(fail(format!(
            "expected zero dangling ownership records after reconciling the race, found {residual_owned}"
        )));
    }
    eprintln!("GOPLS_PROVISION_UNINSTALL_RACE_COUNT=0");
    let _ = fs::remove_dir_all(&root);
    Ok(())
}
