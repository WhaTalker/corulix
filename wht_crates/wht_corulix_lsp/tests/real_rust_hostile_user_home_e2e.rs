// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7B-B1-R3-B2-B1-C1 §13-20: real hostile real-user-`$HOME` isolation
//! certification for the managed Rust semantic runtime.
//!
//! # What is built and why
//!
//! A fake, external "hostile user HOME" directory (never inside the
//! Corulix managed root) containing `.cargo/config.toml`, `.rustup/`, and
//! decoy `cargo`/`rustc`/`rustup`/`node` binaries -- exactly the shape a
//! real attacker-controlled home directory would take if Corulix ever ran
//! with `HOME` pointed at it.
//!
//! # Positive control (§16), avoiding a vacuous PASS
//!
//! Before claiming Corulix ignores this hostile HOME, this file first
//! proves the HOME's own `.cargo/config.toml` *is* real, load-bearing
//! configuration: a genuinely unmanaged `cargo` invocation (this
//! workspace's own real rustup-installed build toolchain --
//! `rustup which cargo`, never the Corulix-managed one) is run with `HOME`
//! set to the hostile directory and nothing else overridden, and is proven
//! to pick up the hostile `[build] rustc-wrapper` entry (a real marker
//! fires). If this positive control did not fire, a negative result for
//! Corulix's own managed path below would prove nothing.
//!
//! # Corulix isolation (§17-20)
//!
//! The real, unmodified production `resolve_launch`/`resolve_launch_at`
//! (`wht_corulix_lsp::profile`) already sets `HOME`/`CARGO_HOME`/
//! `CARGO_TARGET_DIR` explicitly to a Corulix-owned scratch directory
//! nested inside the managed Rust semantic runtime's own
//! `component_install_dir` (read from `profile.rs` before writing this
//! file -- see its own doc comment on why: `Command::env_clear()` means the
//! child never inherits any `HOME` at all unless explicitly set, and cargo/
//! rust-analyzer need *some* resolvable `HOME` to locate their config/
//! registry-index cache). This file proves that scratch directory is what
//! actually reaches the real spawned process -- never the hostile fake
//! HOME -- both by inspecting `ResolvedLaunch.environment` directly and by
//! running a real, full managed rust-analyzer session against a fixture
//! and confirming not one of the hostile HOME's decoy binaries or its
//! `.cargo/config.toml`'s marker-writing wrapper ever fires, even though
//! the hostile HOME sits on disk the entire time this test runs.
//!
//! `USER_RUSTUP_AUTHORITY=NO` (§19) follows from the same evidence plus a
//! structural fact re-confirmed before writing this file: `rustup` never
//! appears anywhere in `resolve_launch_at`/`managed_toolchain.rs` --
//! managed `rustc`/`cargo` are resolved directly from the merged
//! component's own `bin/`, with no rustup indirection at any point.
//!
//! `USER_CREDENTIALS_AUTHORITY=NO` (§20, informational only -- credential
//! *helper execution* is out of scope for this pass, deferred to C2)
//! follows from the same `CARGO_HOME` override: cargo resolves
//! `credentials.toml` relative to `$CARGO_HOME`, which is the Corulix
//! scratch directory here, never the hostile fake HOME's `.cargo/`.
//!
//! # Phase 7B-B1-R3-B2-B1-C1-R1: migrated to the explicit isolated typed
//! managed root
//!
//! Same migration, same reasoning, as
//! `real_rust_hostile_cargo_config_e2e.rs`'s own module doc: this file no
//! longer provisions the managed Rust semantic runtime/rust-analyzer onto
//! the real, shared, host-wide `managed_toolchain_root()`. It provisions
//! its own isolated root via the same real local artifact mirror mechanism,
//! and this file's own adversarial semantics -- everything else below --
//! are otherwise unchanged.

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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wht_corulix_config::{EffectiveConfig, HostConfig, RepositoryHints, RequestOptions};
use wht_corulix_core::{CancellationToken, WorkspaceRootId};
use wht_corulix_lsp::{LspProviderProfile, LspSession, Readiness};
use wht_corulix_tooling::provisioning::{self, ManagedComponentManifest};
use wht_corulix_workspace::WorkspaceRoot;

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

/// Real production provisioning pipeline against the real, unmodified
/// production manifests, artifact origin substituted for the local mirror
/// only -- same contract as
/// `real_rust_hostile_cargo_config_e2e.rs::provision_rust_stack_isolated`.
/// `REAL_PROVISIONING_PIPELINE_USED=YES`.
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
/// into one aggregate SHA-256 digest -- same contract as
/// `real_rust_hostile_cargo_config_e2e.rs::host_root_digest`.
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
            let mode = metadata.permissions().mode();
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

fn set_executable(path: &Path) {
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        let _ = fs::set_permissions(path, permissions);
    }
}

struct HostileHome {
    root: PathBuf,
    marker_file: PathBuf,
}

/// Builds a fake, external hostile user `HOME`: `.cargo/config.toml`
/// (hostile `build.rustc-wrapper`), `.cargo/config` (legacy filename,
/// cargo reads either), `.cargo/credentials`/`.cargo/credentials.toml`
/// (decoy content -- credential *use* is out of scope this pass, but their
/// mere presence must never be read as authority), a `.rustup/` directory,
/// and decoy `cargo`/`rustc`/`rustup`/`node` binaries under
/// `.cargo/bin`/`.rustup/bin` (the real locations `rustup`-style installs
/// use). Never placed inside the Corulix managed root.
fn build_hostile_home(label: &str) -> HostileHome {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("corulix-hostile-user-home-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join(".cargo/bin"));
    let _ = fs::create_dir_all(root.join(".rustup/bin"));

    let marker_file = root.join("hostile_home_wrapper_executed.txt");
    let wrapper_path = root.join(".cargo/evil-home-wrapper.sh");
    let _ = fs::write(
        &wrapper_path,
        format!(
            "#!/bin/sh\necho MARKER_HOSTILE_HOME_WRAPPER_EXECUTED >> \"{}\"\nexec \"$@\"\n",
            marker_file.display()
        ),
    );
    set_executable(&wrapper_path);

    let config_body = format!(
        "[build]\nrustc-wrapper = \"{}\"\nrustc-workspace-wrapper = \"{}\"\n",
        wrapper_path.display(),
        wrapper_path.display()
    );
    let _ = fs::write(root.join(".cargo/config.toml"), &config_body);
    let _ = fs::write(root.join(".cargo/config"), &config_body);
    let _ = fs::write(
        root.join(".cargo/credentials"),
        "[registry]\ntoken = \"hostile-decoy-token-never-real\"\n",
    );
    let _ = fs::write(
        root.join(".cargo/credentials.toml"),
        "[registry]\ntoken = \"hostile-decoy-token-never-real\"\n",
    );

    for (dir, name) in [
        (root.join(".cargo/bin"), "cargo"),
        (root.join(".cargo/bin"), "rustc"),
        (root.join(".rustup/bin"), "rustup"),
        (root.join(".cargo/bin"), "node"),
    ] {
        let decoy = dir.join(name);
        let decoy_marker = root.join(format!("hostile_home_decoy_{name}_executed.txt"));
        let _ = fs::write(
            &decoy,
            format!(
                "#!/bin/sh\necho MARKER_HOSTILE_HOME_DECOY_EXECUTED:{name} >> \"{}\"\nexit 1\n",
                decoy_marker.display()
            ),
        );
        set_executable(&decoy);
    }

    HostileHome { root, marker_file }
}

fn decoy_marker(home: &HostileHome, name: &str) -> PathBuf {
    home.root
        .join(format!("hostile_home_decoy_{name}_executed.txt"))
}

fn rust_fixture(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let root =
        std::env::temp_dir().join(format!("corulix-hostile-home-rust-fixture-{label}-{stamp}"));
    let _ = fs::create_dir_all(root.join("src"));
    let _ = fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"corulix_hostile_home_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"corulix_hostile_home_fixture\"\npath = \"src/main.rs\"\n",
    );
    let _ = fs::write(
        root.join("src/main.rs"),
        "fn main() {\n    let s = String::new();\n    println!(\"{}\", s.len());\n}\n",
    );
    root
}

#[tokio::test]
async fn real_hostile_user_home_never_reaches_managed_rust_analyzer() -> Result<(), Box<dyn Error>>
{
    let Some(cache) = load_artifact_cache() else {
        eprintln!(
            "HOSTILE_USER_HOME_E2E=BLOCKED_ARTIFACT_CACHE_ABSENT: populate {:?} first (see real_isolated_multi_provider_certification_e2e.rs's module doc)",
            artifact_cache_dir()
        );
        return Ok(());
    };
    let Ok(host_root) = provisioning::managed_toolchain_root() else {
        eprintln!("HOSTILE_USER_HOME_E2E=BLOCKED_HOST_ROOT_UNRESOLVABLE");
        return Ok(());
    };
    let host_before = host_root_digest(&host_root);
    eprintln!("HOST_ROOT_PRE_STATE_DIGEST={host_before}");

    let base_url = spawn_artifact_mirror(cache);
    let managed_root = isolated_root("hostile-user-home");
    provision_rust_stack_isolated(&managed_root, &base_url)
        .await
        .map_err(|error| fail(format!("HOSTILE_USER_HOME_E2E=FAIL: {error}")))?;
    eprintln!("REAL_PROVISIONING_PIPELINE_USED=YES");

    let home = build_hostile_home("rust-analyzer");

    // §16: POSITIVE CONTROL -- an unmanaged real cargo invocation, run with
    // HOME pointed at the hostile directory and nothing else touched, must
    // actually pick up the hostile config. Uses this workspace's own real
    // rustup-installed build toolchain (never the Corulix-managed one) so
    // this control is independent of anything this codebase's own
    // hardening might already affect.
    let rustup_which = std::process::Command::new("rustup")
        .args(["which", "cargo"])
        .output();
    let unmanaged_cargo = match rustup_which {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => {
            eprintln!(
                "HOSTILE_USER_HOME_POSITIVE_CONTROL=BLOCKED_NO_UNMANAGED_CARGO_AVAILABLE: `rustup which cargo` failed in this environment"
            );
            let _ = fs::remove_dir_all(&home.root);
            return Ok(());
        }
    };

    let fixture = rust_fixture("positive-control");
    let unmanaged_cargo_dir = Path::new(&unmanaged_cargo)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/usr/bin"));
    // `env_clear()` here, not merely `.env("HOME", ...)`, is deliberate:
    // this test process's own `cargo test` was itself launched through this
    // repository's pinned `rust-toolchain.toml`, which sets `RUSTUP_HOME`/
    // `RUSTUP_TOOLCHAIN` in the *test binary's own* ambient environment
    // (confirmed empirically -- an earlier revision of this positive
    // control inherited them unintentionally via `tokio::process::Command`'s
    // default env-inheritance and observed a false PASS: the child's
    // `rustc-wrapper` fired, but the rustup shim it `exec`'d then resolved
    // its toolchain from the *inherited* `RUSTUP_TOOLCHAIN` pin rather than
    // from `HOME`, masking exactly the property this control exists to
    // prove). A genuinely hostile HOME takeover has no reason to assume a
    // benign `RUSTUP_TOOLCHAIN` pin is present in the victim's real
    // environment, so this control's own environment must not assume it
    // either -- only `PATH` (the real toolchain's own bin dir, so `rustc`
    // resolves to the real compiler rather than nothing at all) and `HOME`
    // (the hostile directory under test) survive.
    let status = tokio::process::Command::new(&unmanaged_cargo)
        .arg("check")
        .current_dir(&fixture)
        .env_clear()
        .env("PATH", &unmanaged_cargo_dir)
        .env("HOME", &home.root)
        .status()
        .await
        .map_err(|error| {
            fail(format!(
                "spawning unmanaged cargo for the positive control failed: {error}"
            ))
        })?;
    let _ = status; // exit code is irrelevant; only the marker matters.
    let control_fired = home.marker_file.exists();
    let _ = fs::remove_dir_all(&fixture);
    if !control_fired {
        let _ = fs::remove_dir_all(&home.root);
        return Err(fail(
            "HOSTILE_USER_HOME_POSITIVE_CONTROL=FAIL: an unmanaged cargo run with HOME pointed at the hostile directory never triggered its rustc-wrapper marker -- the hostile fixture is not proven live, so a negative result for the managed path below would be vacuous",
        ));
    }
    eprintln!("HOSTILE_USER_HOME_POSITIVE_CONTROL=PASS");
    // Reset for the real negative case below.
    let _ = fs::remove_file(&home.marker_file);
    for name in ["cargo", "rustc", "rustup", "node"] {
        let _ = fs::remove_file(decoy_marker(&home, name));
    }

    // §17-20: the real managed session, with the hostile HOME sitting on
    // disk the whole time (never referenced, never cleaned up early).
    let fixture = rust_fixture("negative-case");
    let workspace_root = WorkspaceRoot::open(&fixture)?;
    let effective = EffectiveConfig::derive(
        &HostConfig::default(),
        &RepositoryHints::default(),
        &RequestOptions::default(),
    );
    let profile = LspProviderProfile::rust_analyzer_managed();
    let launch =
        wht_corulix_lsp::resolve_launch_at(&profile, &effective, &workspace_root, &managed_root)
            .await
            .map_err(|error| fail(format!("resolve_launch_at failed: {error:?}")))?;

    let resolved_home = launch.environment.get("HOME").map(str::to_string);
    let resolved_cargo_home = launch.environment.get("CARGO_HOME").map(str::to_string);
    let hostile_home_str = home.root.to_string_lossy().to_string();
    for (label, value) in [
        ("HOME", &resolved_home),
        ("CARGO_HOME", &resolved_cargo_home),
    ] {
        let Some(value) = value else {
            let _ = fs::remove_dir_all(&fixture);
            let _ = fs::remove_dir_all(&home.root);
            return Err(fail(format!(
                "REAL_USER_HOME_RUST_AUTHORITY check failed: resolved launch environment carries no {label} at all"
            )));
        };
        assert_ne!(
            value, &hostile_home_str,
            "REAL_USER_HOME_RUST_AUTHORITY!=NO: resolved {label} is the hostile fake HOME"
        );
        assert!(
            !value.starts_with(&hostile_home_str),
            "REAL_USER_HOME_RUST_AUTHORITY!=NO: resolved {label} is nested inside the hostile fake HOME"
        );
    }
    eprintln!("REAL_USER_HOME_RUST_AUTHORITY=NO");

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
        .map_err(|error| fail(format!("opening the fixture failed: {error:?}")))?;
    session
        .wait_until_ready(READINESS_TIMEOUT)
        .await
        .map_err(|error| {
            fail(format!(
                "managed rust-analyzer never reached readiness: {error:?}"
            ))
        })?;
    if session.readiness().await != Readiness::Ready {
        let _ = fs::remove_dir_all(&fixture);
        let _ = fs::remove_dir_all(&home.root);
        return Err(fail(
            "session reports not-ready after wait_until_ready succeeded",
        ));
    }
    session.shutdown(&cancellation).await;

    let mut fired = Vec::new();
    if home.marker_file.exists() {
        fired.push("HOME_CONFIG_WRAPPER".to_string());
    }
    for name in ["cargo", "rustc", "rustup", "node"] {
        if decoy_marker(&home, name).exists() {
            fired.push(format!("DECOY_{}", name.to_uppercase()));
        }
    }

    let _ = fs::remove_dir_all(&fixture);
    let _ = fs::remove_dir_all(&home.root);

    if !fired.is_empty() {
        return Err(fail(format!(
            "HOSTILE_USER_HOME_EXECUTION_COUNT != 0: real managed rust-analyzer session triggered: {fired:?}"
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

    eprintln!("HOSTILE_USER_HOME_E2E_ISOLATED_ROOT=PASS");
    eprintln!("HOSTILE_USER_HOME_EXECUTION_COUNT=0");
    eprintln!(
        "USER_RUSTUP_AUTHORITY=NO (rustup never referenced anywhere in resolve_launch_at/managed_toolchain.rs; managed rustc/cargo resolve directly from the merged component's own bin/)"
    );
    eprintln!(
        "USER_CREDENTIALS_AUTHORITY=NO (CARGO_HOME is the Corulix scratch directory; ~/.cargo/credentials* under the hostile HOME is unreachable -- credential *helper execution* itself is out of scope this pass, deferred to C2)"
    );
    Ok(())
}
