// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! F1 fix (`CORULIX_HOST_CONFIG_INTERFACE`): the real, external,
//! operator-facing TOML file format for [`HostConfig`], and the sole
//! function that turns one into a real [`HostConfig`].
//!
//! # Why this exists
//!
//! Before this fix, the real production stdio entrypoint
//! (`wht_corulix_mcp::serve_stdio`, reached via `corulix mcp stdio`) had no
//! way to construct anything but `HostConfig::default()` -- there was no
//! CLI flag, no environment variable, no file format, nothing. Every field
//! `HostConfig` exists to carry (an approved system directory, a
//! host-configured absolute provider path, `TRUSTED_WORKSPACE_EXECUTION`
//! opt-in) was reachable only from `#[cfg(test)]` code across this
//! workspace, never from the shipped binary. `corulix mcp stdio
//! --host-config <FILE>` (`wht_corulix_cli`) is the real, operator-facing
//! wiring; this module is where the file itself is parsed and validated.
//!
//! # Trust model (unchanged, made reachable)
//!
//! This is still, and only, the `HOST_ONLY` configuration source
//! [`crate::trust`]'s own module doc describes: nothing here reads a
//! workspace file, an MCP request field, or a repository hint. The file
//! this module parses must be named by the host/operator via an explicit,
//! absolute CLI flag value -- never discovered, never workspace-relative,
//! and (enforced by [`load_host_config_file`] itself) never allowed to
//! resolve inside the very workspace it would configure, which would be a
//! self-elevation smell (a workspace could plant its own "host" config and
//! read it back as if an operator had authored it).
//!
//! # Format
//!
//! TOML, matching this crate's `HostConfig`'s seven fields exactly. Every
//! field is optional (absent = the same value `HostConfig::default()`
//! already carries for it), and an unknown field is rejected outright
//! (`#[serde(deny_unknown_fields)]`) rather than silently ignored -- a typo
//! in a security-relevant config file must be a hard error, never a
//! silently-dropped no-op.
//!
//! ```toml
//! workspace_trust = "TRUSTED"
//! allow_trusted_workspace_execution = true
//! enable_user_toolchain_directories = false
//! managed_provisioning_policy = "INHERIT"
//! approved_system_directories = ["/home/operator/.cargo/bin"]
//! approved_user_toolchain_directories = []
//!
//! [[provider_absolute_paths]]
//! category = "FORMATTER"
//! path = "/home/operator/.cargo/bin/rustfmt"
//! ```
//!
//! `managed_provisioning_policy` (Installation-Contract-V1 fix,
//! `HOSTCONFIG_AUTHORITY_MODEL_AMBIGUITY`) defaults to `"INHERIT"`: the host
//! has no opinion, so real `CORULIX_MANAGED` acquisition is permitted or
//! denied purely by the persisted install profile's own intent
//! (`wht_corulix_tooling`'s install-profile subsystem). `"DENY"` is an
//! unconditional host veto no profile can override; `"ALLOW"` unconditionally
//! permits acquisition regardless of profile state. See
//! [`crate::trust::ManagedProvisioningPolicy`]'s own doc comment for why a
//! bare boolean could not represent this correctly.
//!
//! `workspace_trust` reuses [`wht_corulix_core::WorkspaceTrust`]'s own
//! `SCREAMING_SNAKE_CASE` wire form (`"TRUSTED"`/`"UNTRUSTED"`) and
//! `provider_absolute_paths[].category` reuses
//! [`wht_corulix_core::ProviderCategory`]'s own wire form
//! (`"LANGUAGE_SERVER"`/`"FORMATTER"`/`"LINTER"`/`"TYPECHECK_BUILD"`/
//! `"TEST_RUNNER"`/`"RUNTIME"`) directly -- both types already derive
//! `Deserialize` for the MCP wire contract, so this file format reuses the
//! exact same vocabulary rather than inventing a second one that could
//! drift from it. An unrecognized category name is a real parse failure
//! ([`HostConfigLoadError::Malformed`]), never silently ignored.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use wht_corulix_core::{ProviderCategory, WorkspaceTrust};

use crate::trust::ManagedProvisioningPolicy;
use wht_corulix_workspace::canonicalize_external_path;

use crate::trust::HostConfig;

/// Hard bound on the host-config file's own size, read before any TOML
/// parsing is attempted. This is a six-field configuration file, not a
/// data payload -- comfortably above any legitimate real-world size (a
/// large `approved_system_directories`/`provider_absolute_paths` list would
/// still be a tiny fraction of this) and small enough that a caller can
/// never be forced into an unbounded read merely by pointing
/// `--host-config` at an oversized file.
pub const MAX_HOST_CONFIG_FILE_BYTES: u64 = 64 * 1024;

/// Every way loading a host-config file fails closed. Never a bare string
/// as the sole machine-readable authority -- [`Self::Malformed`]'s payload
/// is a bounded, human-readable diagnostic only, not itself parsed by any
/// caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostConfigLoadError {
    /// The path given to `--host-config` was not absolute.
    PathNotAbsolute,
    /// The path does not canonicalize (missing, permission error, symlink
    /// cycle).
    PathUnresolvable,
    /// The path canonicalizes, but does not name a regular file (e.g. a
    /// directory).
    NotARegularFile,
    /// The canonicalized path resolves inside the currently-selected
    /// workspace -- a host-config file living inside the very workspace it
    /// would configure is a self-elevation smell, rejected outright.
    ResolvesInsideWorkspace,
    /// The file's real, on-disk size exceeds [`MAX_HOST_CONFIG_FILE_BYTES`].
    TooLarge,
    /// The file could not be read (race with [`Self::PathUnresolvable`]'s
    /// own check, permission change, or similar).
    ReadFailed,
    /// The file's bytes are not valid UTF-8.
    NotUtf8,
    /// The file's content is not well-formed TOML, does not match this
    /// format's expected shape, names an unknown field, or names an
    /// unrecognized `workspace_trust`/provider-category value. Carries a
    /// bounded (never unbounded) diagnostic string.
    Malformed(String),
    /// A `provider_absolute_paths` entry's `path` was not absolute.
    RelativeProviderPath { category: ProviderCategory },
    /// An `approved_system_directories`/`approved_user_toolchain_directories`
    /// entry was not absolute.
    RelativeApprovedDirectory,
}

impl std::fmt::Display for HostConfigLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathNotAbsolute => write!(f, "--host-config path is not absolute"),
            Self::PathUnresolvable => write!(f, "--host-config path could not be resolved"),
            Self::NotARegularFile => write!(f, "--host-config path is not a regular file"),
            Self::ResolvesInsideWorkspace => {
                write!(f, "--host-config path resolves inside the active workspace")
            }
            Self::TooLarge => write!(f, "--host-config file exceeds the maximum allowed size"),
            Self::ReadFailed => write!(f, "--host-config file could not be read"),
            Self::NotUtf8 => write!(f, "--host-config file is not valid UTF-8"),
            Self::Malformed(detail) => write!(f, "--host-config file is malformed: {detail}"),
            Self::RelativeProviderPath { category } => {
                write!(
                    f,
                    "--host-config provider path for {category:?} is not absolute"
                )
            }
            Self::RelativeApprovedDirectory => {
                write!(f, "--host-config approved directory entry is not absolute")
            }
        }
    }
}

impl std::error::Error for HostConfigLoadError {}

/// One `[[provider_absolute_paths]]` entry. Reuses
/// [`wht_corulix_core::ProviderCategory`]'s own `Deserialize` derive
/// directly for `category` -- an unrecognized category name is rejected by
/// serde itself, never accepted and silently miscategorized.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderAbsolutePathEntry {
    category: ProviderCategory,
    path: PathBuf,
}

/// The real, on-the-wire shape of a `--host-config` TOML file. Every field
/// defaults to the same value [`HostConfig::default()`] already carries for
/// it when absent, so a minimal (or empty) file is equivalent to that
/// default rather than a parse failure.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostConfigFile {
    #[serde(default)]
    workspace_trust: WorkspaceTrust,
    #[serde(default)]
    allow_trusted_workspace_execution: bool,
    #[serde(default)]
    provider_absolute_paths: Vec<ProviderAbsolutePathEntry>,
    #[serde(default)]
    approved_system_directories: Vec<PathBuf>,
    #[serde(default)]
    approved_user_toolchain_directories: Vec<PathBuf>,
    #[serde(default)]
    enable_user_toolchain_directories: bool,
    #[serde(default)]
    managed_provisioning_policy: ManagedProvisioningPolicy,
}

/// Bounds a `toml`/`std::fmt::Display` error's own rendered text so a
/// pathological error message can never itself become an unbounded string
/// this crate hands back to a caller.
fn bounded_error_text(text: String) -> String {
    const MAX_BYTES: usize = 2048;
    if text.len() <= MAX_BYTES {
        return text;
    }
    let mut cut = MAX_BYTES;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}... (truncated)", &text[..cut])
}

/// Loads, validates, and converts one real `--host-config` file into a real
/// [`HostConfig`]. The sole entry point this module exposes.
///
/// `path` must be absolute (fails closed with [`HostConfigLoadError::PathNotAbsolute`]
/// otherwise -- never silently resolved against the process's current
/// directory). `workspace_root_boundaries` is every member root's own
/// canonical absolute path for the currently-selected workspace (a
/// single-root workspace passes one; a multi-root `.code-workspace` passes
/// every member) -- the caller (`wht_corulix_cli`) already has these from
/// its own workspace resolution and is the one place in this workspace that
/// legitimately reads raw canonical root paths for this purpose.
///
/// Canonicalization reuses [`canonicalize_external_path`]
/// (`wht_corulix_workspace`, Architecture Rule F) rather than implementing a
/// second one -- this crate's own `resolver` module already establishes
/// this exact reuse pattern.
///
/// Fails closed, never partially: any error variant means no [`HostConfig`]
/// is returned at all, and the caller's own documented behavior (per
/// `corulix mcp stdio --help`) is to exit non-zero without starting an MCP
/// session -- there is no "best effort" partial host configuration.
pub async fn load_host_config_file(
    path: &Path,
    workspace_root_boundaries: &[&Path],
) -> Result<HostConfig, HostConfigLoadError> {
    if !path.is_absolute() {
        return Err(HostConfigLoadError::PathNotAbsolute);
    }

    let (canonical, is_file) = canonicalize_external_path(path.to_path_buf())
        .await
        .map_err(|_| HostConfigLoadError::PathUnresolvable)?;
    if !is_file {
        return Err(HostConfigLoadError::NotARegularFile);
    }
    for boundary in workspace_root_boundaries {
        if canonical.starts_with(boundary) {
            return Err(HostConfigLoadError::ResolvesInsideWorkspace);
        }
    }

    // This crate has no `tokio` `"fs"` feature enabled workspace-wide (the
    // established convention elsewhere in this workspace --
    // `wht_corulix_workspace::confine`'s own blocking-core-plus-
    // `spawn_blocking` pattern -- is to keep the real filesystem call
    // synchronous and bounce it onto Tokio's blocking-task pool, never to
    // widen `tokio`'s own feature set), so the bounded size check and the
    // read itself run together in one blocking closure, mirroring that same
    // pattern rather than introducing a second I/O convention.
    let read_target = canonical.clone();
    let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, HostConfigLoadError> {
        let metadata =
            std::fs::metadata(&read_target).map_err(|_| HostConfigLoadError::ReadFailed)?;
        if metadata.len() > MAX_HOST_CONFIG_FILE_BYTES {
            return Err(HostConfigLoadError::TooLarge);
        }
        std::fs::read(&read_target).map_err(|_| HostConfigLoadError::ReadFailed)
    })
    .await
    .map_err(|_| HostConfigLoadError::ReadFailed)??;
    let text = String::from_utf8(bytes).map_err(|_| HostConfigLoadError::NotUtf8)?;

    let parsed: HostConfigFile = toml::from_str(&text)
        .map_err(|error| HostConfigLoadError::Malformed(bounded_error_text(error.to_string())))?;

    let mut provider_absolute_paths = Vec::with_capacity(parsed.provider_absolute_paths.len());
    for entry in parsed.provider_absolute_paths {
        if !entry.path.is_absolute() {
            return Err(HostConfigLoadError::RelativeProviderPath {
                category: entry.category,
            });
        }
        provider_absolute_paths.push((entry.category, entry.path));
    }
    for directory in parsed
        .approved_system_directories
        .iter()
        .chain(parsed.approved_user_toolchain_directories.iter())
    {
        if !directory.is_absolute() {
            return Err(HostConfigLoadError::RelativeApprovedDirectory);
        }
    }

    Ok(HostConfig {
        workspace_trust: parsed.workspace_trust,
        allow_trusted_workspace_execution: parsed.allow_trusted_workspace_execution,
        provider_absolute_paths,
        approved_system_directories: parsed.approved_system_directories,
        approved_user_toolchain_directories: parsed.approved_user_toolchain_directories,
        enable_user_toolchain_directories: parsed.enable_user_toolchain_directories,
        managed_provisioning_policy: parsed.managed_provisioning_policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_core::{CorulixError, CorulixResult};

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("corulix-hostfile-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    /// Test-fixture setup only: a write failure here surfaces as a later
    /// assertion mismatch (this workspace's own `resolver.rs` test module
    /// already establishes this "ignore the write result, let the real
    /// assertion fail loudly if setup somehow failed" convention), never a
    /// `.expect()`/`.unwrap()` -- this crate's workspace-wide
    /// `clippy::expect_used`/`unwrap_used = "deny"` lints apply to test code
    /// exactly as they do to production code.
    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let _ = fs::write(&path, content);
        path
    }

    /// Real, workspace-owned canonicalization ([`canonicalize_external_path`])
    /// rather than a bare `fs::canonicalize` call -- Architecture Rule F
    /// reserves that primitive to `wht_corulix_workspace` alone, and this
    /// test module is not exempt merely because it is test-only code (the
    /// same convention `wht_corulix_config::resolver`'s own test module
    /// already follows).
    async fn canonical(path: &Path) -> CorulixResult<PathBuf> {
        canonicalize_external_path(path.to_path_buf())
            .await
            .map(|(canonical, _)| canonical)
            .map_err(|_| CorulixError::Internal)
    }

    /// A syntactically absolute example provider path for the host platform
    /// running the test, built from `basename`. These are parser/
    /// validation-shape tests -- they exercise TOML round-tripping and
    /// `PathBuf::is_absolute()` acceptance in [`load_host_config_file`],
    /// never real filesystem existence -- so the path never needs to exist
    /// on disk, only be genuinely absolute on the host actually running the
    /// test. A `/usr/bin/...`-shaped literal is not `.is_absolute()` on
    /// Windows (no drive/UNC prefix), so this returns a real Windows-shaped
    /// absolute literal there instead of reusing the Unix one -- a single
    /// shared helper rather than five separately hand-duplicated
    /// `#[cfg(unix)]`/`#[cfg(windows)]` literal pairs across this module's
    /// tests.
    #[cfg(unix)]
    fn platform_absolute_example_path(basename: &str) -> PathBuf {
        PathBuf::from(format!("/usr/bin/{basename}"))
    }
    #[cfg(windows)]
    fn platform_absolute_example_path(basename: &str) -> PathBuf {
        PathBuf::from(format!(r"C:\Program Files\Corulix Test\{basename}"))
    }

    #[tokio::test]
    async fn relative_path_fails_closed_before_any_io() {
        let result = load_host_config_file(Path::new("relative/host.toml"), &[]).await;
        assert_eq!(result, Err(HostConfigLoadError::PathNotAbsolute));
    }

    #[tokio::test]
    async fn nonexistent_absolute_path_fails_closed() {
        let dir = temp_dir("nonexistent");
        let missing = dir.join("does-not-exist.toml");
        let result = load_host_config_file(&missing, &[]).await;
        assert_eq!(result, Err(HostConfigLoadError::PathUnresolvable));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn directory_path_is_rejected_as_not_a_regular_file() {
        let dir = temp_dir("directory-target");
        let result = load_host_config_file(&dir, &[]).await;
        assert_eq!(result, Err(HostConfigLoadError::NotARegularFile));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn path_inside_workspace_boundary_is_rejected() -> CorulixResult<()> {
        let workspace = temp_dir("workspace");
        let file = write_file(&workspace, "host.toml", "");
        let canonical_workspace = canonical(&workspace).await?;
        let result = load_host_config_file(&file, &[canonical_workspace.as_path()]).await;
        assert_eq!(result, Err(HostConfigLoadError::ResolvesInsideWorkspace));
        let _ = fs::remove_dir_all(&workspace);
        Ok(())
    }

    #[tokio::test]
    async fn oversized_file_is_rejected_before_parsing() {
        let dir = temp_dir("oversized");
        let oversized = "x".repeat(MAX_HOST_CONFIG_FILE_BYTES as usize + 1);
        let file = write_file(&dir, "host.toml", &oversized);
        let result = load_host_config_file(&file, &[]).await;
        assert_eq!(result, Err(HostConfigLoadError::TooLarge));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_file_matches_host_config_default() -> CorulixResult<()> {
        let dir = temp_dir("empty");
        let file = write_file(&dir, "host.toml", "");
        let loaded = load_host_config_file(&file, &[])
            .await
            .map_err(|_| CorulixError::Internal)?;
        assert_eq!(loaded, HostConfig::default());
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_field_is_rejected_not_silently_ignored() {
        let dir = temp_dir("unknown-field");
        let file = write_file(&dir, "host.toml", "this_field_does_not_exist = true\n");
        let result = load_host_config_file(&file, &[]).await;
        assert!(matches!(result, Err(HostConfigLoadError::Malformed(_))));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unrecognized_provider_category_name_is_rejected() {
        let dir = temp_dir("bad-category");
        let path = platform_absolute_example_path("x")
            .to_string_lossy()
            .into_owned();
        let file = write_file(
            &dir,
            "host.toml",
            &format!(
                "[[provider_absolute_paths]]\ncategory = \"NOT_A_REAL_CATEGORY\"\npath = {path:?}\n"
            ),
        );
        let result = load_host_config_file(&file, &[]).await;
        assert!(matches!(result, Err(HostConfigLoadError::Malformed(_))));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn relative_provider_path_is_rejected() {
        let dir = temp_dir("relative-provider-path");
        let file = write_file(
            &dir,
            "host.toml",
            "[[provider_absolute_paths]]\ncategory = \"FORMATTER\"\npath = \"relative/rustfmt\"\n",
        );
        let result = load_host_config_file(&file, &[]).await;
        assert_eq!(
            result,
            Err(HostConfigLoadError::RelativeProviderPath {
                category: ProviderCategory::Formatter
            })
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn relative_approved_directory_is_rejected() {
        let dir = temp_dir("relative-approved-dir");
        let file = write_file(
            &dir,
            "host.toml",
            "approved_system_directories = [\"relative/bin\"]\n",
        );
        let result = load_host_config_file(&file, &[]).await;
        assert_eq!(result, Err(HostConfigLoadError::RelativeApprovedDirectory));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Every one of the six real `ProviderCategory` names this crate's own
    /// `EXTERNALLY_RESOLVABLE_CATEGORIES` names must round-trip through this
    /// file format -- confirms the wire-form assumption (`SCREAMING_SNAKE_CASE`
    /// rendering of each variant) rather than merely asserting it in a
    /// doc comment.
    #[tokio::test]
    async fn every_externally_resolvable_category_name_parses() -> CorulixResult<()> {
        let dir = temp_dir("all-categories");
        let names = [
            ("LANGUAGE_SERVER", ProviderCategory::LanguageServer),
            ("FORMATTER", ProviderCategory::Formatter),
            ("LINTER", ProviderCategory::Linter),
            ("TYPECHECK_BUILD", ProviderCategory::TypecheckBuild),
            ("TEST_RUNNER", ProviderCategory::TestRunner),
            ("RUNTIME", ProviderCategory::Runtime),
        ];
        let example_path = platform_absolute_example_path("example");
        let example_path_toml = example_path.to_string_lossy().into_owned();
        for (name, expected) in names {
            let content = format!(
                "[[provider_absolute_paths]]\ncategory = \"{name}\"\npath = {example_path_toml:?}\n"
            );
            let file = write_file(&dir, &format!("{name}.toml"), &content);
            let loaded = load_host_config_file(&file, &[])
                .await
                .map_err(|_| CorulixError::Internal)?;
            assert_eq!(
                loaded.provider_absolute_paths,
                vec![(expected, example_path.clone())],
                "category {name} did not round-trip"
            );
        }
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn workspace_trust_true_form_parses() -> CorulixResult<()> {
        let dir = temp_dir("trusted");
        let file = write_file(
            &dir,
            "host.toml",
            "workspace_trust = \"TRUSTED\"\nallow_trusted_workspace_execution = true\n",
        );
        let loaded = load_host_config_file(&file, &[])
            .await
            .map_err(|_| CorulixError::Internal)?;
        assert_eq!(loaded.workspace_trust, WorkspaceTrust::Trusted);
        assert!(loaded.allow_trusted_workspace_execution);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn full_real_file_parses_into_the_expected_host_config() -> CorulixResult<()> {
        let dir = temp_dir("full");
        let system_dir = temp_dir("full-system-dir");
        let rustfmt_path = platform_absolute_example_path("rustfmt");
        let rustfmt_path_toml = rustfmt_path.to_string_lossy().into_owned();
        let content = format!(
            "workspace_trust = \"UNTRUSTED\"\n\
             allow_trusted_workspace_execution = false\n\
             enable_user_toolchain_directories = true\n\
             managed_provisioning_policy = \"ALLOW\"\n\
             approved_system_directories = [{sys:?}]\n\
             approved_user_toolchain_directories = []\n\
             \n\
             [[provider_absolute_paths]]\n\
             category = \"FORMATTER\"\n\
             path = {rustfmt_path_toml:?}\n",
            sys = system_dir.to_string_lossy()
        );
        let file = write_file(&dir, "host.toml", &content);
        let loaded = load_host_config_file(&file, &[])
            .await
            .map_err(|_| CorulixError::Internal)?;
        assert_eq!(loaded.workspace_trust, WorkspaceTrust::Untrusted);
        assert!(!loaded.allow_trusted_workspace_execution);
        assert!(loaded.enable_user_toolchain_directories);
        assert_eq!(
            loaded.managed_provisioning_policy,
            ManagedProvisioningPolicy::Allow
        );
        assert_eq!(loaded.approved_system_directories, vec![system_dir.clone()]);
        assert!(loaded.approved_user_toolchain_directories.is_empty());
        assert_eq!(
            loaded.provider_absolute_paths,
            vec![(ProviderCategory::Formatter, rustfmt_path)]
        );
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&system_dir);
        Ok(())
    }

    #[tokio::test]
    async fn managed_provisioning_policy_defaults_to_inherit_when_absent() -> CorulixResult<()> {
        let dir = temp_dir("managed-provisioning-absent");
        let file = write_file(&dir, "host.toml", "workspace_trust = \"UNTRUSTED\"\n");
        let loaded = load_host_config_file(&file, &[])
            .await
            .map_err(|_| CorulixError::Internal)?;
        assert_eq!(
            loaded.managed_provisioning_policy,
            ManagedProvisioningPolicy::Inherit
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn managed_provisioning_policy_deny_form_parses() -> CorulixResult<()> {
        let dir = temp_dir("managed-provisioning-deny");
        let file = write_file(
            &dir,
            "host.toml",
            "managed_provisioning_policy = \"DENY\"\n",
        );
        let loaded = load_host_config_file(&file, &[])
            .await
            .map_err(|_| CorulixError::Internal)?;
        assert_eq!(
            loaded.managed_provisioning_policy,
            ManagedProvisioningPolicy::Deny
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn managed_provisioning_policy_allow_form_parses() -> CorulixResult<()> {
        let dir = temp_dir("managed-provisioning-allow");
        let file = write_file(
            &dir,
            "host.toml",
            "managed_provisioning_policy = \"ALLOW\"\n",
        );
        let loaded = load_host_config_file(&file, &[])
            .await
            .map_err(|_| CorulixError::Internal)?;
        assert_eq!(
            loaded.managed_provisioning_policy,
            ManagedProvisioningPolicy::Allow
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn managed_provisioning_policy_unrecognized_value_is_rejected() {
        let dir = temp_dir("managed-provisioning-bad");
        let file = write_file(
            &dir,
            "host.toml",
            "managed_provisioning_policy = \"NOT_A_REAL_POLICY\"\n",
        );
        let result = load_host_config_file(&file, &[]).await;
        assert!(matches!(result, Err(HostConfigLoadError::Malformed(_))));
        let _ = fs::remove_dir_all(&dir);
    }
}
