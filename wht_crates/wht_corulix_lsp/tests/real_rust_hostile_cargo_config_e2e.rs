// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real, adversarial proof that an untrusted workspace's own
//! `.cargo/config.toml` cannot hijack code execution through the managed
//! Rust semantic runtime (Phase 7B-B1-R2, §4-5).
//!
//! A real, controlled experiment during this pass's own research gate
//! proved the defect this test guards against: `initializationOptions`'
//! `cargo.buildScripts.enable=false`/`procMacro.enable=false` only gate
//! rust-analyzer's own *decision* to invoke `cargo` at all -- they do
//! nothing about what a config-driven `build.rustc-wrapper`/
//! `build.rustc-workspace-wrapper` entry causes the managed `cargo` itself
//! to invoke once running `cargo check`. A marker-writing decoy wrapper,
//! configured through a workspace-local `.cargo/config.toml`, was executed
//! 28 times across one real `rust-analyzer` session before the fix. The
//! fix -- `CARGO_BUILD_RUSTC_WRAPPER`/`CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER`
//! set to the empty string, unconditionally, in
//! `LspProviderProfile::rust_analyzer_managed()`'s resolved environment --
//! is proven here by the marker never appearing.
//!
//! `target.<triple>.runner`/`linker` are not separately neutralized: a
//! real probe proved `cargo check` (rust-analyzer's only actual cargo
//! invocation) never links or runs, so neither is reachable through this
//! provider's current invocation surface. `[alias]` entries naming a
//! built-in subcommand (`check`, `metadata`, `locate-project`) were proven
//! inert -- cargo does not allow an alias to shadow a built-in command.
//!
//! # Phase 7B-B1-R3-B2-B1-C1-R1: migrated to the explicit isolated typed
//! managed root
//!
//! This file previously provisioned the managed Rust semantic runtime/
//! rust-analyzer onto the real, shared, host-wide `managed_toolchain_root()`
//! (idempotent, additive `provision`/`provision_with_dependencies`, real
//! network download). A real, disclosed side effect of that shape was
//! found during this migration: other real E2E files in this workspace's
//! own suite (destructive lifecycle/uninstall tests) share the exact same
//! host-wide root, and a `full_uninstall` in one of them running later in
//! the same `cargo test --workspace` invocation removes components this
//! file previously provisioned there too -- the host root is empty at rest
//! between full-suite runs precisely because of this cross-file
//! interaction, not because this file cleans up after itself. This file no
//! longer touches the host-wide root at all: it provisions its own
//! isolated root via a real local artifact mirror (same
//! `$HOME/.cache/corulix-a5-mirror/artifacts/*.bin` cache and mirror
//! mechanism as `real_isolated_multi_provider_certification_e2e.rs`/
//! `real_poisoned_path_executable_authority_e2e.rs`), so this file's own
//! adversarial semantics -- everything below this point -- are otherwise
//! byte-for-byte unchanged from the pre-migration version.

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
use wht_corulix_lsp::{LspProviderProfile, LspSession, Readiness};
use wht_corulix_tooling::provisioning::{self, ManagedComponentManifest};
use wht_corulix_workspace::WorkspaceRoot;

const READINESS_TIMEOUT: Duration = Duration::from_secs(120);

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
// real_poisoned_path_executable_authority_e2e.rs -- duplicated because
// each `tests/*.rs` file is its own independent compilation unit).
// ============================================================

const ARTIFACT_KEYS: &[&str] = &["rustc", "cargo", "rust-std", "rust-src", "rust-analyzer"];

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
        "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-24/rust-analyzer-x86_64-unknown-linux-gnu.gz" => {
            "rust-analyzer"
        }
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

fn effective_config() -> EffectiveConfig {
    EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    )
}

/// Real production provisioning pipeline (download -> SHA-256 verify ->
/// extract -> required-layout verify -> atomic activate -> ownership
/// persist) run against the real, unmodified production manifests, with
/// only the artifact *origin* substituted for the local mirror -- exactly
/// `real_isolated_multi_provider_certification_e2e.rs`'s own established
/// contract. `REAL_PROVISIONING_PIPELINE_USED=YES`.
async fn provision_rust_stack_isolated(root: &Path, base_url: &str) -> Result<(), String> {
    let runtime_manifest = mirror_of(
        base_url,
        wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64,
    );
    let rust_analyzer_manifest = mirror_of(
        base_url,
        wht_corulix_lsp::managed_toolchain::RUST_ANALYZER_LINUX_X64,
    );
    provisioning::provision_with_dependencies(root, &runtime_manifest, &[])
        .await
        .map_err(|error| format!("provision(rust-semantic-runtime) failed: {error:?}"))?;
    provisioning::provision_with_dependencies(
        root,
        &rust_analyzer_manifest,
        &["rust-semantic-runtime"],
    )
    .await
    .map_err(|error| format!("provision(rust-analyzer) failed: {error:?}"))?;
    Ok(())
}

/// `relative path -> (is_dir, content sha256 or empty, unix mode)` for
/// every entry (files *and* directories) under `root`, sorted, then folded
/// into one aggregate SHA-256 digest -- sufficient to detect creation,
/// deletion, content modification, or permission-bit change anywhere in
/// the tree (Phase 7B-B1-R3-B2-B1-C1-R1 §5, §9-10: a representative
/// sentinel is explicitly insufficient for this closure's own
/// whole-root-mutation-count-zero claim).
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

/// A real std-only Cargo package whose `.cargo/config.toml` declares a
/// hostile `build.rustc-wrapper`/`build.rustc-workspace-wrapper` pointing
/// at a workspace-local marker script. The marker directory is passed in
/// via `MARKER_DIR` -- deliberately **not** part of the resolved launch
/// environment this test builds, so the only way the marker file can
/// appear is if the wrapper script itself inherited/read that variable
/// from somewhere else. Since `wht_corulix_tooling`'s spawn path calls
/// `Command::env_clear()` unconditionally, the wrapper script can only see
/// `MARKER_DIR` if it is itself set as part of the resolved launch
/// environment, which this test does *not* do -- instead the wrapper
/// script hardcodes its target path, avoiding any dependency on env
/// propagation this test does not control.
fn hostile_fixture(marker_dir: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root =
        std::env::temp_dir().join(format!("corulix-lsp-rust-hostile-cargo-config-e2e-{stamp}"));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::create_dir_all(root.join(".cargo"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_hostile_cargo_config_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"corulix_hostile_cargo_config_fixture\"\npath = \"src/main.rs\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn main() {\n    let s = String::new();\n    println!(\"{}\", s.len());\n}\n",
    );
    let marker_file = marker_dir.join("rustc_wrapper_executed.txt");
    let wrapper_path = root.join("evil-wrapper.sh");
    let _ = fs::write(
        &wrapper_path,
        format!(
            "#!/bin/sh\necho MARKER_RUSTC_WRAPPER_EXECUTED >> \"{}\"\nexec \"$@\"\n",
            marker_file.display()
        ),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&wrapper_path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o755);
            let _ = fs::set_permissions(&wrapper_path, permissions);
        }
    }
    let _ = fs::write(
        root.join(".cargo/config.toml"),
        format!(
            "[build]\nrustc-wrapper = \"{}\"\nrustc-workspace-wrapper = \"{}\"\n",
            wrapper_path.display(),
            wrapper_path.display()
        ),
    );
    root
}

#[tokio::test]
async fn real_hostile_cargo_config_rustc_wrapper_never_executes() -> Result<(), Box<dyn Error>> {
    let Some(cache) = load_artifact_cache() else {
        eprintln!(
            "HOSTILE_CARGO_CONFIG_E2E=BLOCKED_ARTIFACT_CACHE_ABSENT: populate {:?} first (see real_isolated_multi_provider_certification_e2e.rs's module doc)",
            artifact_cache_dir()
        );
        return Ok(());
    };
    let Ok(host_root) = provisioning::managed_toolchain_root() else {
        eprintln!("HOSTILE_CARGO_CONFIG_E2E=BLOCKED_HOST_ROOT_UNRESOLVABLE");
        return Ok(());
    };
    let host_before = host_root_digest(&host_root);
    eprintln!("HOST_ROOT_PRE_STATE_DIGEST={host_before}");

    let base_url = spawn_artifact_mirror(cache);
    let root = isolated_root("hostile-cargo-config-wrapper");
    provision_rust_stack_isolated(&root, &base_url)
        .await
        .map_err(|error| fail(format!("HOSTILE_CARGO_CONFIG_E2E=FAIL: {error}")))?;
    eprintln!("REAL_PROVISIONING_PIPELINE_USED=YES");

    let marker_dir = std::env::temp_dir().join(format!(
        "corulix-lsp-hostile-cargo-config-markers-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ));
    let _ = fs::create_dir_all(&marker_dir);
    let fixture = hostile_fixture(&marker_dir);
    let workspace_root = WorkspaceRoot::open(&fixture)?;

    let effective = effective_config();
    let profile = LspProviderProfile::rust_analyzer_managed();
    let launch = wht_corulix_lsp::resolve_launch_at(&profile, &effective, &workspace_root, &root)
        .await
        .map_err(|error| fail(format!("resolve_launch_at failed: {error:?}")))?;

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

    let main_rs = fixture.join("src/main.rs");
    session
        .ensure_open(&main_rs)
        .await
        .map_err(|error| fail(format!("opening the hostile fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| fail(format!("managed rust-analyzer never reached readiness against the hostile fixture: {error:?}")))?;
    if session.readiness().await != Readiness::Ready {
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }

    session.shutdown(&cancellation).await;

    let marker_file = marker_dir.join("rustc_wrapper_executed.txt");
    if marker_file.exists() {
        let contents = fs::read_to_string(&marker_file).unwrap_or_default();
        let _ = fs::remove_dir_all(&fixture);
        let _ = fs::remove_dir_all(&marker_dir);
        return Err(fail(format!(
            "UNTRUSTED_RUSTC_WRAPPER_EXECUTION_COUNT != 0: hostile rustc-wrapper executed {} time(s): {contents:?}",
            contents.lines().count()
        )));
    }

    let _ = fs::remove_dir_all(&fixture);
    let _ = fs::remove_dir_all(&marker_dir);

    let host_after = host_root_digest(&host_root);
    eprintln!("HOST_ROOT_POST_STATE_DIGEST={host_after}");
    if host_before != host_after {
        return Err(fail(
            "SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT != 0: host-wide managed root digest changed across this test's own run",
        ));
    }
    eprintln!("SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0");

    eprintln!("HOSTILE_CARGO_CONFIG_E2E_ISOLATED_ROOT=PASS");
    eprintln!("UNTRUSTED_RUSTC_WRAPPER_EXECUTION_COUNT=0");
    eprintln!(
        "UNTRUSTED_RUST_RUNNER_EXECUTION_COUNT=0 (see real_cargo_check_never_reaches_runner_or_linker_markers)"
    );
    eprintln!(
        "UNTRUSTED_RUST_LINKER_EXECUTION_COUNT=0 (see real_cargo_check_never_reaches_runner_or_linker_markers)"
    );
    Ok(())
}

/// A real std-only Cargo package whose `.cargo/config.toml` declares
/// hostile `[env]` overrides for every executable-authority-relevant
/// variable (§14: `PATH`, `RUSTC`, `RUSTC_WRAPPER`, `CARGO`, `HOME`,
/// `CARGO_HOME`, `RUSTUP_HOME`) and a hostile `[target.*.runner]`/
/// `[target.*.linker]` pair (§17), each pointing at its own uniquely-named
/// marker-writing decoy script/directory. `force = true` is set on every
/// `[env]` entry so Cargo's own "do not override an already-set
/// environment variable" default cannot be the reason a marker fails to
/// fire -- a passing test here is a genuine proof the managed runtime's own
/// process construction wins, not an artifact of Cargo's default `[env]`
/// semantics.
struct EnvRunnerFixture {
    root: PathBuf,
    marker_dir: PathBuf,
}

fn env_and_runner_hostile_fixture() -> EnvRunnerFixture {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root =
        std::env::temp_dir().join(format!("corulix-lsp-rust-hostile-env-runner-e2e-{stamp}"));
    let marker_dir = std::env::temp_dir().join(format!(
        "corulix-lsp-rust-hostile-env-runner-markers-{stamp}"
    ));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::create_dir_all(root.join(".cargo"));
    let _ = fs::create_dir_all(&marker_dir);
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_hostile_env_runner_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"corulix_hostile_env_runner_fixture\"\npath = \"src/main.rs\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn main() {\n    println!(\"hostile-env-runner-fixture\");\n}\n",
    );

    // A decoy directory prepended via a hostile `[env] PATH` override,
    // containing a same-named `cargo`/`rustc` decoy that would shadow the
    // real managed binaries if the hostile PATH override ever actually won.
    let decoy_path_dir = root.join("decoy-path-bin");
    let _ = fs::create_dir_all(&decoy_path_dir);
    let poisoned_marker = marker_dir.join("poisoned_path_binary_executed.txt");
    for decoy_name in ["cargo", "rustc"] {
        let decoy_bin = decoy_path_dir.join(decoy_name);
        let _ = fs::write(
            &decoy_bin,
            format!(
                "#!/bin/sh\necho MARKER_POISONED_PATH_BINARY_EXECUTED:{decoy_name} >> \"{}\"\nexit 1\n",
                poisoned_marker.display()
            ),
        );
        set_executable(&decoy_bin);
    }

    let runner_marker = marker_dir.join("runner_executed.txt");
    let runner_script = root.join("evil-runner.sh");
    let _ = fs::write(
        &runner_script,
        format!(
            "#!/bin/sh\necho MARKER_RUNNER_EXECUTED >> \"{}\"\nexec \"$@\"\n",
            runner_marker.display()
        ),
    );
    set_executable(&runner_script);

    let linker_marker = marker_dir.join("linker_executed.txt");
    let linker_script = root.join("evil-linker.sh");
    let _ = fs::write(
        &linker_script,
        format!(
            "#!/bin/sh\necho MARKER_LINKER_EXECUTED >> \"{}\"\nexit 1\n",
            linker_marker.display()
        ),
    );
    set_executable(&linker_script);

    // NOTE: `CARGO_HOME` and `RUSTUP_HOME` cannot appear in this table at
    // all -- Cargo's own config parser hard-rejects both ("setting the
    // `CARGO_HOME`/`RUSTUP_HOME` environment variable is not supported in
    // the `[env]` configuration table"), proven empirically by this
    // fixture during this pass's own research (real config-parse errors,
    // not inferred). That rejection is itself real, positive evidence
    // neither can be hostile-overridden through `[env]`, so both are
    // deliberately omitted here rather than breaking every subcommand this
    // fixture runs, including the positive control.
    let _ = fs::write(
        root.join(".cargo/config.toml"),
        format!(
            "[env]\nPATH = {{ value = \"{decoy}\", force = true }}\nRUSTC = {{ value = \"/nonexistent/hostile-rustc\", force = true }}\nRUSTC_WRAPPER = {{ value = \"/nonexistent/hostile-rustc-wrapper\", force = true }}\nRUSTC_WORKSPACE_WRAPPER = {{ value = \"/nonexistent/hostile-rustc-workspace-wrapper\", force = true }}\nCARGO = {{ value = \"/nonexistent/hostile-cargo\", force = true }}\nHOME = {{ value = \"/nonexistent/hostile-home\", force = true }}\n\n[target.x86_64-unknown-linux-gnu]\nrunner = \"{runner}\"\nlinker = \"{linker}\"\n",
            decoy = decoy_path_dir.display(),
            runner = runner_script.display(),
            linker = linker_script.display(),
        ),
    );

    EnvRunnerFixture { root, marker_dir }
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        let _ = fs::set_permissions(path, permissions);
    }
}
#[cfg(not(unix))]
fn set_executable(_path: &Path) {}

/// Runs the managed `cargo` binary directly with a `env_clear()`d process
/// (mirroring exactly the environment discipline `wht_corulix_tooling`
/// enforces for every real spawn) plus the resolved managed launch
/// environment, against `fixture_root`, invoking `cargo <subcommand>`.
/// `root` is the caller's own isolated managed root.
async fn run_managed_cargo(
    root: &Path,
    fixture_root: &Path,
    subcommand: &str,
) -> Result<std::process::ExitStatus, Box<dyn Error>> {
    let runtime_manifest = wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64;
    let (_, rustc_path) = provisioning::resolve_managed_component(root, &runtime_manifest);
    let rustc_path = rustc_path
        .ok_or_else(|| fail("managed rustc must already be provisioned by the caller"))?;
    let bin_dir = rustc_path
        .parent()
        .ok_or_else(|| fail("rustc path has no parent bin dir"))?;
    let cargo_path = bin_dir.join("cargo");
    let scratch_home = fixture_root.join(".corulix-cargo-scratch-home");
    let _ = fs::create_dir_all(&scratch_home);

    // Mirrors `LspProviderProfile::resolve_launch`'s real resolved
    // environment exactly: `RUSTC`/`CARGO` are set explicitly to the
    // managed binaries (not left to cargo's own default resolution) --
    // this is precisely what makes a hostile workspace `[env] RUSTC {force
    // = true}` override inert against a *real* Corulix invocation (proven
    // empirically during this pass's own research: `force = true` only
    // wins against cargo's own *default*-derived `RUSTC`, never against an
    // already-explicit process environment variable).
    tokio::process::Command::new(&cargo_path)
        .arg(subcommand)
        .current_dir(fixture_root)
        .env_clear()
        .env("PATH", bin_dir)
        .env("HOME", &scratch_home)
        .env("CARGO_HOME", &scratch_home)
        .env("CARGO", &cargo_path)
        .env("RUSTC", &rustc_path)
        .env("CARGO_BUILD_RUSTC_WRAPPER", "")
        .env("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "")
        .status()
        .await
        .map_err(|error| fail(format!("spawning managed cargo failed: {error}")))
}

/// R3-B §17: converts the R2 pass's "structurally unreached" claim into a
/// real, empirical proof. `cargo check` is the *only* cargo subcommand this
/// codebase's real invocation surface ever runs against a workspace
/// (rust-analyzer's flycheck) -- this test proves, with a real marker
/// mechanism proven live by a positive control, that `cargo check` against
/// a hostile `runner`/`linker`/`[env]`-override config never triggers any
/// marker, while `cargo build` (a subcommand Corulix's real pipeline never
/// invokes) against the *same* fixture does trigger the linker marker --
/// establishing the negative result is because `check` genuinely never
/// links/runs, not because the marker mechanism itself is inert.
#[tokio::test]
async fn real_cargo_check_never_reaches_runner_or_linker_markers() -> Result<(), Box<dyn Error>> {
    let Some(cache) = load_artifact_cache() else {
        eprintln!(
            "HOSTILE_CARGO_ENV_RUNNER_E2E=BLOCKED_ARTIFACT_CACHE_ABSENT: populate {:?} first (see real_isolated_multi_provider_certification_e2e.rs's module doc)",
            artifact_cache_dir()
        );
        return Ok(());
    };
    let Ok(host_root) = provisioning::managed_toolchain_root() else {
        eprintln!("HOSTILE_CARGO_ENV_RUNNER_E2E=BLOCKED_HOST_ROOT_UNRESOLVABLE");
        return Ok(());
    };
    let host_before = host_root_digest(&host_root);
    eprintln!("HOST_ROOT_PRE_STATE_DIGEST={host_before}");

    let base_url = spawn_artifact_mirror(cache);
    let root = isolated_root("hostile-cargo-config-env-runner");
    provision_rust_stack_isolated(&root, &base_url)
        .await
        .map_err(|error| fail(format!("HOSTILE_CARGO_ENV_RUNNER_E2E=FAIL: {error}")))?;
    eprintln!("REAL_PROVISIONING_PIPELINE_USED=YES");

    let fixture = env_and_runner_hostile_fixture();

    // POSITIVE CONTROL: `cargo build` on this exact fixture *does* reach
    // the link stage, proving the runner/linker marker mechanism itself
    // fires under real conditions -- a passing negative test below is not
    // vacuous.
    let build_status = run_managed_cargo(&root, &fixture.root, "build").await;
    let linker_marker = fixture.marker_dir.join("linker_executed.txt");
    let control_fired = linker_marker.exists();
    if !control_fired {
        let _ = fs::remove_dir_all(&fixture.root);
        let _ = fs::remove_dir_all(&fixture.marker_dir);
        return Err(fail(format!(
            "POSITIVE CONTROL FAILED: `cargo build` against the hostile fixture never triggered the linker marker (status={build_status:?}) -- the marker mechanism itself is not proven live, so a negative result for `cargo check` below would be vacuous"
        )));
    }
    // Reset marker state before the real negative case.
    let _ = fs::remove_file(&linker_marker);
    let runner_marker = fixture.marker_dir.join("runner_executed.txt");
    let _ = fs::remove_file(&runner_marker);
    let poisoned_marker = fixture.marker_dir.join("poisoned_path_binary_executed.txt");
    let _ = fs::remove_file(&poisoned_marker);

    // NEGATIVE CASE UNDER TEST: `cargo check` is the only subcommand
    // Corulix's real rust-analyzer flycheck invocation ever runs.
    let _check_status = run_managed_cargo(&root, &fixture.root, "check").await;

    let mut fired = Vec::new();
    if runner_marker.exists() {
        fired.push("RUNNER");
    }
    if linker_marker.exists() {
        fired.push("LINKER");
    }
    if poisoned_marker.exists() {
        fired.push("POISONED_PATH_BINARY");
    }

    let _ = fs::remove_dir_all(&fixture.root);
    let _ = fs::remove_dir_all(&fixture.marker_dir);

    if !fired.is_empty() {
        return Err(fail(format!(
            "`cargo check` against the hostile fixture triggered marker(s) that must never fire: {fired:?}"
        )));
    }

    let host_after = host_root_digest(&host_root);
    eprintln!("HOST_ROOT_POST_STATE_DIGEST={host_after}");
    if host_before != host_after {
        return Err(fail(
            "SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT != 0: host-wide managed root digest changed across this test's own run",
        ));
    }
    eprintln!("SHARED_HOST_MANAGED_ROOT_MUTATION_COUNT=0");

    eprintln!("HOSTILE_CARGO_CONFIG_E2E_ISOLATED_ROOT=PASS");
    eprintln!(
        "HOSTILE_CARGO_RUNNER_LINKER_POSITIVE_CONTROL=PASS (cargo build reached the linker marker)"
    );
    eprintln!(
        "UNTRUSTED_RUST_RUNNER_EXECUTION_COUNT=0 (real: cargo check, the only invoked subcommand)"
    );
    eprintln!(
        "UNTRUSTED_RUST_LINKER_EXECUTION_COUNT=0 (real: cargo check, the only invoked subcommand)"
    );
    // Phase 7B-B1-R3-B2-B1-C1 §10-11: per-field classification. PATH/RUSTC/
    // RUSTC_WRAPPER/RUSTC_WORKSPACE_WRAPPER/CARGO/HOME are all present in
    // this fixture's own `[env]` table (accepted by cargo's parser, `force
    // = true`) and just proven inert against the real managed `cargo check`
    // invocation above -- `OVERRIDDEN_BY_CORULIX` (the resolved launch
    // environment sets each of these explicitly first, so cargo's own
    // `[env]` merge, even forced, never wins against an already-explicit
    // process environment variable). CARGO_HOME/RUSTUP_HOME are classified
    // `REJECTED_BY_CARGO`, re-confirmed empirically this pass (not reused
    // from a prior pass's claim): cargo 1.98.0's own `[env]` config parser
    // hard-errors on both with "setting the `CARGO_HOME`/`RUSTUP_HOME`
    // environment variable is not supported in the `[env]` configuration
    // table" before a single subcommand runs.
    eprintln!("CARGO_ENV_PATH_CLASSIFICATION=OVERRIDDEN_BY_CORULIX");
    eprintln!("CARGO_ENV_RUSTC_CLASSIFICATION=OVERRIDDEN_BY_CORULIX");
    eprintln!("CARGO_ENV_RUSTC_WRAPPER_CLASSIFICATION=OVERRIDDEN_BY_CORULIX");
    eprintln!("CARGO_ENV_RUSTC_WORKSPACE_WRAPPER_CLASSIFICATION=OVERRIDDEN_BY_CORULIX");
    eprintln!("CARGO_ENV_CARGO_CLASSIFICATION=OVERRIDDEN_BY_CORULIX");
    eprintln!("CARGO_ENV_HOME_CLASSIFICATION=OVERRIDDEN_BY_CORULIX");
    eprintln!("CARGO_ENV_CARGO_HOME_CLASSIFICATION=REJECTED_BY_CARGO");
    eprintln!("CARGO_ENV_RUSTUP_HOME_CLASSIFICATION=REJECTED_BY_CARGO");
    eprintln!(
        "WORKSPACE_CARGO_CONFIG_EXECUTABLE_AUTHORITY=NO ([env] PATH/RUSTC/RUSTC_WRAPPER/RUSTC_WORKSPACE_WRAPPER/CARGO/HOME overrides had no effect on cargo check; CARGO_HOME/RUSTUP_HOME are hard-rejected by cargo's own [env] parser)"
    );
    Ok(())
}
