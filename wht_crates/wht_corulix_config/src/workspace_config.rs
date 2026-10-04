// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Corulix 1.1.0 (`ADR 0012`): the real, workspace-authored
//! `WhaTalker_Corulix_JSON_Config.json` format, and the structural +
//! semantic validation that turns raw bytes into a typed, validated
//! [`WorkspaceConfig`].
//!
//! # Scope of this module (Phase B)
//!
//! This module owns **parsing and validation only** -- structural shape,
//! `configName`/`schemaVersion` enforcement, duplicate-array/duplicate-key
//! rejection, and delegation to [`wht_corulix_core::validate_tool_policy`]
//! for the shared tool-policy semantic rules. It does **not** perform any
//! filesystem I/O and does **not** resolve `rootOverrides[].root` against a
//! live `WorkspaceContext` -- that binding (canonical-path matching,
//! `WorkspaceRootId` resolution, the safe descriptor-sibling/confined read
//! primitives) is `wht_corulix_workspace`'s and this crate's own Phase C
//! responsibility, layered on top of [`parse_workspace_config`]'s pure,
//! synchronous output. This split keeps the parser itself fully unit-
//! testable with zero filesystem or workspace-context dependency.
//!
//! # Two-phase, direct-to-struct parsing
//!
//! Every parse in this module deserializes directly from the source `&str`
//! into a named struct -- **never** through `serde_json::Value` or any
//! `HashMap`/`BTreeMap` intermediate. This is the load-bearing anti-
//! duplicate-key control: `serde_derive`'s generated `Visitor::visit_map`
//! rejects a repeated known field with its own `duplicate_field` error
//! (format-independent -- this applies to `serde_json` exactly as it does to
//! `toml`), whereas a `Value`/map intermediate would silently keep the last
//! occurrence. A duplicate top-level or nested JSON key is therefore already
//! rejected by construction, surfaced here as a bounded
//! [`WorkspaceConfigError::Malformed`] (this crate does not need, and does
//! not maintain, a second literal-array-duplicate check for JSON keys
//! themselves -- only for the semantically-significant repeated *values*
//! inside `disabledTools`/`disabledCategories` arrays, which serde's own
//! duplicate-key protection cannot see).
//!
//! Phase 1 (envelope) checks only `configName`/`schemaVersion` before Phase
//! 2 (the strict, `#[serde(deny_unknown_fields)]` v1 body) ever runs -- a
//! `schemaVersion` other than `1` is reported as
//! [`WorkspaceConfigError::UnsupportedSchemaVersion`], never drowned out by
//! "unknown field" noise from a future version's shape.

use std::collections::HashSet;

use serde::Deserialize;
use wht_corulix_core::{EffectiveToolSet, ProviderCategory, ToolPolicyValidationError};

/// The canonical, non-negotiable filename. Corulix 1.1.0 reads this file
/// only from its own canonical fixed location (per root, or beside a
/// resolved `.code-workspace` descriptor) -- there is no
/// `--workspace-config <FILE>` explicit-path mode in this release (ADR
/// 0012), so this constant is never compared against an operator-supplied
/// path, only used to open the one location Corulix itself resolves.
pub const WORKSPACE_CONFIG_FILE_NAME: &str = "WhaTalker_Corulix_JSON_Config.json";
/// The required literal value of the file's own `configName` field.
pub const WORKSPACE_CONFIG_NAME: &str = "WhaTalker Corulix JSON Config";
/// The only `schemaVersion` this release accepts.
pub const WORKSPACE_CONFIG_SCHEMA_VERSION: u32 = 1;
/// Hard bound on the file's own size, checked before any parse is
/// attempted -- mirrors [`crate::MAX_HOST_CONFIG_FILE_BYTES`]'s own bound
/// and rationale (a handful of tool names/category names/root overrides is
/// comfortably tiny; this exists only to make an oversized file a fast,
/// bounded rejection rather than an unbounded read).
pub const MAX_WORKSPACE_CONFIG_FILE_BYTES: u64 = 64 * 1024;

/// Every way loading/validating a workspace config fails closed.
/// `#[non_exhaustive]` from this, its first release, matching this crate's
/// own established convention on [`crate::HostConfigLoadError`]'s sibling
/// error types.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkspaceConfigError {
    /// No file exists at the canonical location -- **not an error state on
    /// its own**; callers treat this the same as `Ok(WorkspaceConfig::default())`.
    /// Kept as a loader-outcome variant (matching the plan's own "`NotPresent`
    /// may be represented as a loader outcome rather than an error variant"
    /// allowance) so the absent/denied distinction stays explicit at every
    /// call site.
    NotPresent,
    /// The file exists but could not be read for a reason other than
    /// genuine absence (permission denied, unexpected type at that path,
    /// I/O error) -- fails closed, never silently treated as absent.
    PathDenied,
    /// The file's real size exceeds [`MAX_WORKSPACE_CONFIG_FILE_BYTES`].
    TooLarge,
    /// The file's bytes are not valid UTF-8.
    NotUtf8,
    /// Malformed JSON, an unknown field, an invalid field type, a
    /// duplicate JSON key, or any other structural parse failure. Carries a
    /// bounded (never unbounded) diagnostic string, mirroring
    /// [`crate::HostConfigLoadError::Malformed`]'s own bound.
    Malformed(String),
    /// `configName` was present but did not equal
    /// [`WORKSPACE_CONFIG_NAME`] byte-for-byte.
    WrongConfigName,
    /// `schemaVersion` was present, a valid JSON integer, but not `1`.
    /// Reported distinctly from [`Self::Malformed`] so a future v2 file is
    /// never confused with an ordinary v1 shape error.
    UnsupportedSchemaVersion(u32),
    /// `rootOverrides[].root` was empty or an absolute path -- rejected at
    /// the syntactic stage, before any filesystem access. A `..`-containing
    /// relative locator is **not** rejected here (real `.code-workspace`
    /// descriptors legitimately use parent-relative `folders[].path`
    /// values); it is validated at the Phase C root-binding stage instead,
    /// against the live, already-authorized `WorkspaceContext`.
    InvalidRootLocator(String),
    /// A duplicate entry within one `disabledCategories` array (either
    /// `defaults` or a specific `rootOverrides[]` entry). The `String`
    /// names which array (`"defaults"`, or the offending entry's own
    /// authored `root` locator).
    DuplicateCategoryInPolicy(String, ProviderCategory),
    /// `toolPolicy.disabledTools` failed the shared semantic validator in
    /// `wht_corulix_core`. Wrapped, never re-implemented -- this is the
    /// single-authority invariant ADR 0012 requires.
    ToolPolicy(ToolPolicyValidationError),
    /// Phase C root-binding: `rootOverrides[].root` canonicalized (relative
    /// to the resolved workspace's own descriptor directory or single
    /// root), but the result matched zero of the live `WorkspaceContext`'s
    /// own already-authorized member roots. Covers both "the path does not
    /// exist" and "it exists but is not a declared member root" -- these
    /// are deliberately not distinguished (distinguishing them would leak
    /// filesystem existence information to a config author who may not be
    /// authorized to know what exists outside the workspace). The `String`
    /// is the offending entry's own authored locator.
    UnknownRootOverride(String),
    /// Phase C root-binding: two or more `rootOverrides[]` entries
    /// canonicalized to the *same* member root. Never silently merged --
    /// the `String` is the second (duplicate-binding) entry's own authored
    /// locator.
    DuplicateRootOverride(String),
}

impl std::fmt::Display for WorkspaceConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPresent => write!(f, "workspace config file is not present"),
            Self::PathDenied => write!(f, "workspace config file could not be read"),
            Self::TooLarge => write!(f, "workspace config file exceeds the maximum allowed size"),
            Self::NotUtf8 => write!(f, "workspace config file is not valid UTF-8"),
            Self::Malformed(detail) => write!(f, "workspace config file is malformed: {detail}"),
            Self::WrongConfigName => write!(
                f,
                "workspace config file's configName does not match {WORKSPACE_CONFIG_NAME:?}"
            ),
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    f,
                    "workspace config file's schemaVersion {version} is not supported (expected {WORKSPACE_CONFIG_SCHEMA_VERSION})"
                )
            }
            Self::InvalidRootLocator(reason) => {
                write!(f, "rootOverrides[].root is invalid: {reason}")
            }
            Self::DuplicateCategoryInPolicy(scope, category) => {
                write!(
                    f,
                    "duplicate disabledCategories entry {category:?} in {scope}"
                )
            }
            Self::ToolPolicy(error) => write!(f, "tool policy: {error}"),
            Self::UnknownRootOverride(root) => {
                write!(
                    f,
                    "rootOverrides entry {root:?} does not resolve to any known workspace root"
                )
            }
            Self::DuplicateRootOverride(root) => {
                write!(
                    f,
                    "rootOverrides entry {root:?} resolves to the same workspace root as another entry"
                )
            }
        }
    }
}

impl std::error::Error for WorkspaceConfigError {}

impl From<ToolPolicyValidationError> for WorkspaceConfigError {
    fn from(error: ToolPolicyValidationError) -> Self {
        Self::ToolPolicy(error)
    }
}

/// Phase 1: envelope only. Checked before [`WorkspaceConfigFileV1`] is ever
/// attempted, so a wrong/future `schemaVersion` is reported precisely,
/// never as "unknown field" noise from a v1-shaped strict parse.
#[derive(Debug, Deserialize)]
struct WorkspaceConfigEnvelope {
    #[serde(rename = "configName")]
    config_name: String,
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
}

/// Phase 2: the strict v1 body. `deny_unknown_fields` on every nested
/// struct -- every `HostConfig` privilege field (`workspace_trust`,
/// `allow_trusted_workspace_execution`, `provider_absolute_paths`,
/// `approved_system_directories`, `approved_user_toolchain_directories`,
/// `enable_user_toolchain_directories`, `managed_provisioning_policy`) is
/// structurally absent -- not declared as a field at all -- so any attempt
/// to set one here is a normal "unknown field" parse error, never a
/// runtime-recognized (and therefore potentially silently-ignored) name.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WorkspaceConfigFileV1 {
    #[serde(rename = "configName")]
    #[allow(dead_code)]
    config_name: String,
    #[serde(rename = "schemaVersion")]
    #[allow(dead_code)]
    schema_version: u32,
    #[serde(default, rename = "toolPolicy")]
    tool_policy: ToolPolicyFile,
    #[serde(default)]
    defaults: WorkspaceDefaultsFile,
    #[serde(default, rename = "rootOverrides")]
    root_overrides: Vec<WorkspaceRootOverrideEntryFile>,
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ToolPolicyFile {
    #[serde(default, rename = "disabledTools")]
    disabled_tools: Vec<String>,
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WorkspaceDefaultsFile {
    #[serde(default, rename = "disabledCategories")]
    disabled_categories: Vec<ProviderCategory>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WorkspaceRootOverrideEntryFile {
    /// Workspace-relative folder locator, matching `.code-workspace`'s own
    /// `folders[].path` convention. **Never itself authority** -- Phase C
    /// resolves it to a canonical `WorkspaceRootId` against the live
    /// `WorkspaceContext`; this module only performs the syntactic checks
    /// that require no filesystem access at all.
    root: String,
    #[serde(default, rename = "disabledCategories")]
    disabled_categories: Vec<ProviderCategory>,
    // toolPolicy is deliberately absent here -- tool exposure is
    // workspace-wide only (ADR 0012); a root override may never carry one.
}

/// A parsed, structurally- and semantically-validated `defaults` block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkspaceDefaults {
    pub disabled_categories: HashSet<ProviderCategory>,
}

/// A parsed, structurally-validated (but **not yet root-bound**)
/// `rootOverrides[]` entry. `root` is the raw authored locator string --
/// Phase C's own root-binding step consumes this type and produces the
/// final `(WorkspaceRootId, WorkspaceRootOverrides)` pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawWorkspaceRootOverride {
    pub root: String,
    pub disabled_categories: HashSet<ProviderCategory>,
}

/// The fully parsed and validated (short of root-binding) workspace
/// configuration. `tool_policy` is already the final, immutable
/// [`EffectiveToolSet`] -- validated once, here, by the single shared
/// authority in `wht_corulix_core`; no other layer re-derives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceConfig {
    pub tool_policy: EffectiveToolSet,
    pub defaults: WorkspaceDefaults,
    pub root_overrides: Vec<RawWorkspaceRootOverride>,
}

/// Bounds a serde error's own rendered text, mirroring
/// [`crate::hostfile`]'s identical helper (kept crate-private and
/// duplicated rather than shared publicly, since both call sites are
/// small, format-specific, and this crate has no existing shared "text
/// utils" module to promote it into without over-engineering a two-call-site
/// helper).
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

/// Checks `values` for a repeated entry, returning the first duplicate
/// found (in authored order). Used for both `disabledTools` (via the
/// shared `wht_corulix_core` validator, which performs its own equivalent
/// check) and every `disabledCategories` array here, so a config author's
/// mistake is surfaced precisely rather than silently collapsed by a
/// `HashSet`/`BTreeSet` conversion.
fn first_duplicate_category(values: &[ProviderCategory]) -> Option<ProviderCategory> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Some(*value);
        }
    }
    None
}

/// Host-OS-independent rooted/absolute check for an authored `rootOverrides`
/// locator string.
///
/// `WhaTalker_Corulix_JSON_Config.json` is portable data: the same file may
/// be authored on one platform and loaded on another (Section 5's own
/// design), so a locator this validator must reject can be written in any
/// supported platform's own absolute/rooted syntax -- not only the syntax
/// native to whichever OS happens to be running the parser. `P17-W`
/// Windows native certification found `std::path::Path::is_absolute()`
/// alone insufficient here: it is host-native by design (a bare `/etc/passwd`
/// is absolute on Unix but NOT `is_absolute()` under Rust's own Windows path
/// semantics, which require a drive/UNC prefix), so relying on it exclusively
/// let a POSIX-absolute locator pass through un-rejected when the validator
/// itself happened to run on Windows -- a fail-open gap for exactly the
/// security-relevant class this function exists to close.
///
/// Rejects, regardless of host OS:
/// - POSIX absolute (`/foo`, `/foo/bar`);
/// - Windows rooted-without-drive (`\foo`);
/// - UNC (`\\server\share`, `\\server\share\folder`);
/// - extended-length / device namespace (`\\?\C:\foo`, `\\?\UNC\server\share`,
///   `\\.\...`) -- all share the same `\\` prefix as UNC above;
/// - Windows drive-absolute (`C:\foo`, `C:/foo`, `D:\workspace`);
/// - Windows drive-relative (`C:foo`, `C:`) -- ambiguous (relative to that
///   drive's current directory), rejected rather than guessed.
///
/// Accepts every other syntactic form, including forward- or
/// backslash-separated relative locators (`foo/bar`, `foo\bar`,
/// `./foo/bar`, `.\foo\bar`) and parent-relative locators (`../sibling`) --
/// see this module's own doc comment and `WorkspaceConfigError::InvalidRootLocator`
/// for why a leading `..` is deliberately not rejected here.
fn is_disallowed_rooted_locator(root: &str) -> bool {
    if root.starts_with('/') || root.starts_with('\\') {
        return true;
    }
    let bytes = root.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn validate_root_locator(root: &str) -> Result<(), WorkspaceConfigError> {
    if root.is_empty() {
        return Err(WorkspaceConfigError::InvalidRootLocator(
            "must not be empty".to_string(),
        ));
    }
    if is_disallowed_rooted_locator(root) {
        return Err(WorkspaceConfigError::InvalidRootLocator(
            "must not be an absolute or rooted path (POSIX absolute, Windows drive-absolute/drive-relative, or UNC/device-namespace syntax)".to_string(),
        ));
    }
    // A `..` component is deliberately NOT rejected here -- see this
    // module's own doc comment and `WorkspaceConfigError::InvalidRootLocator`.
    Ok(())
}

/// Parses and fully structurally/semantically validates `text` as a
/// Corulix 1.1.0 workspace config file, **except** for root-to-
/// `WorkspaceRootId` binding (Phase C). Pure and synchronous -- no
/// filesystem I/O, no `WorkspaceContext` dependency, so this function alone
/// is exactly what `corulix config validate`/`config schema`'s structural
/// layer and every unit test in this module exercise directly.
///
/// `empty_catalog_supported` is threaded straight through to
/// [`wht_corulix_core::validate_tool_policy`] -- see that function's own
/// doc comment for why this crate never guesses or re-derives it.
///
/// # Errors
///
/// Returns the first applicable [`WorkspaceConfigError`], in this fixed
/// order: malformed JSON (envelope phase) -> wrong `configName` -> wrong
/// `schemaVersion` -> malformed JSON (strict v1 body phase, includes
/// unknown fields and duplicate JSON keys) -> invalid root locator syntax
/// -> duplicate category entries -> tool-policy semantic validation.
pub fn parse_workspace_config(
    text: &str,
    empty_catalog_supported: bool,
) -> Result<WorkspaceConfig, WorkspaceConfigError> {
    let envelope: WorkspaceConfigEnvelope = serde_json::from_str(text)
        .map_err(|error| WorkspaceConfigError::Malformed(bounded_error_text(error.to_string())))?;

    if envelope.config_name != WORKSPACE_CONFIG_NAME {
        return Err(WorkspaceConfigError::WrongConfigName);
    }
    if envelope.schema_version != WORKSPACE_CONFIG_SCHEMA_VERSION {
        return Err(WorkspaceConfigError::UnsupportedSchemaVersion(
            envelope.schema_version,
        ));
    }

    let parsed: WorkspaceConfigFileV1 = serde_json::from_str(text)
        .map_err(|error| WorkspaceConfigError::Malformed(bounded_error_text(error.to_string())))?;

    for entry in &parsed.root_overrides {
        validate_root_locator(&entry.root)?;
        if let Some(duplicate) = first_duplicate_category(&entry.disabled_categories) {
            return Err(WorkspaceConfigError::DuplicateCategoryInPolicy(
                entry.root.clone(),
                duplicate,
            ));
        }
    }
    if let Some(duplicate) = first_duplicate_category(&parsed.defaults.disabled_categories) {
        return Err(WorkspaceConfigError::DuplicateCategoryInPolicy(
            "defaults".to_string(),
            duplicate,
        ));
    }

    let tool_policy = wht_corulix_core::validate_tool_policy(
        &parsed.tool_policy.disabled_tools,
        empty_catalog_supported,
    )?;

    Ok(WorkspaceConfig {
        tool_policy,
        defaults: WorkspaceDefaults {
            disabled_categories: parsed.defaults.disabled_categories.into_iter().collect(),
        },
        root_overrides: parsed
            .root_overrides
            .into_iter()
            .map(|entry| RawWorkspaceRootOverride {
                root: entry.root,
                disabled_categories: entry.disabled_categories.into_iter().collect(),
            })
            .collect(),
    })
}

/// A parsed, root-*bound* `rootOverrides[]` entry's value portion -- the
/// root itself is the map/vec key (a [`wht_corulix_core::WorkspaceRootId`]),
/// never the raw authored string, per [`bind_workspace_config_roots`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkspaceRootOverrides {
    pub disabled_categories: HashSet<ProviderCategory>,
}

/// The final, fully bound Corulix 1.1.0 workspace configuration -- every
/// `rootOverrides[].root` locator has been resolved to the canonical
/// [`wht_corulix_core::WorkspaceRootId`] of an already-authorized member
/// root of the live `WorkspaceContext` this was bound against. Produced
/// only by [`bind_workspace_config_roots`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundWorkspaceConfig {
    pub tool_policy: EffectiveToolSet,
    pub defaults: WorkspaceDefaults,
    pub root_overrides: Vec<(wht_corulix_core::WorkspaceRootId, WorkspaceRootOverrides)>,
}

/// Resolves every `rootOverrides[].root` in `config` (Phase B's pure,
/// unbound output) against `context`'s live, already-authorized member
/// roots, per the algorithm in ADR 0012 / the 1.1.0 plan's Section 5
/// "Complete root-locator semantics":
///
/// 1. Join the (already syntax-checked -- non-empty, non-absolute) locator
///    onto the workspace's own join base: `context`'s descriptor location
///    for a multi-root context, or its single root's own canonical path for
///    a single-root context.
/// 2. Canonicalize the joined path -- via
///    [`wht_corulix_workspace::canonicalize_external_path`] only (Architecture
///    Rule F: this crate never independently canonicalizes a path itself).
/// 3. Match the canonicalized result against every member root's own
///    canonical path via
///    [`wht_corulix_workspace::WorkspaceContext::resolve_root_id_by_canonical_path`]
///    -- never an independent canonical-path comparison in this crate.
///
/// A `..`-containing locator is therefore accepted exactly when it
/// canonicalizes to a real, already-authorized member root -- never merely
/// because it canonicalizes to *something* -- closing the "parent-relative
/// escape" class the plan's threat model names explicitly.
///
/// # Errors
///
/// [`WorkspaceConfigError::UnknownRootOverride`] if a locator fails to
/// canonicalize, or its canonical path matches zero member roots (both
/// outcomes are folded together deliberately -- see that variant's own doc
/// comment). [`WorkspaceConfigError::DuplicateRootOverride`] if two or more
/// entries resolve to the same member root.
pub async fn bind_workspace_config_roots(
    config: WorkspaceConfig,
    context: &wht_corulix_workspace::WorkspaceContext,
) -> Result<BoundWorkspaceConfig, WorkspaceConfigError> {
    let join_base: std::path::PathBuf = if let Some(descriptor) = context.descriptor_location() {
        descriptor.canonical_path().to_path_buf()
    } else {
        // Single-root context: the workspace's own one root is the join
        // base. `resolve_root(None)` always succeeds for a single-root
        // context (it ignores the selector) -- see that method's own doc
        // comment.
        context
            .resolve_root(None)
            .map_err(|_| WorkspaceConfigError::PathDenied)?
            .canonical_path()
            .to_path_buf()
    };

    let mut bound: Vec<(wht_corulix_core::WorkspaceRootId, WorkspaceRootOverrides)> =
        Vec::with_capacity(config.root_overrides.len());
    let mut bound_ids: HashSet<wht_corulix_core::WorkspaceRootId> = HashSet::new();

    for entry in config.root_overrides {
        let joined = join_base.join(&entry.root);
        let (canonical, _is_file) = wht_corulix_workspace::canonicalize_external_path(joined)
            .await
            .map_err(|_| WorkspaceConfigError::UnknownRootOverride(entry.root.clone()))?;
        let root_id = context
            .resolve_root_id_by_canonical_path(&canonical)
            .ok_or_else(|| WorkspaceConfigError::UnknownRootOverride(entry.root.clone()))?;
        if !bound_ids.insert(root_id) {
            return Err(WorkspaceConfigError::DuplicateRootOverride(entry.root));
        }
        bound.push((
            root_id,
            WorkspaceRootOverrides {
                disabled_categories: entry.disabled_categories,
            },
        ));
    }

    Ok(BoundWorkspaceConfig {
        tool_policy: config.tool_policy,
        defaults: config.defaults,
        root_overrides: bound,
    })
}

/// Reads, and fully structurally + semantically validates, the workspace's
/// own canonical `WhaTalker_Corulix_JSON_Config.json` -- the single entry
/// point that ties Phase B's pure parser and Phase C's root-binding to the
/// real, confined, fail-closed filesystem read Corulix 1.1.0 was missing
/// until now (ADR 0012).
///
/// Discovery location is never a caller-supplied path (there is no
/// `--workspace-config <FILE>` in 1.1.0): a multi-root (descriptor-based)
/// `context` reads the file beside its own `descriptor_location`; a
/// single-root `context` reads it directly inside its one root. Both reduce
/// to the exact same confined, single-open-handle, symlink-safe read
/// ([`wht_corulix_workspace::confined_read_optional`]) because a resolved
/// `.code-workspace` descriptor directory is itself stored as an ordinary,
/// already-authorized [`wht_corulix_workspace::WorkspaceRoot`]
/// (`WorkspaceContext::with_descriptor_location`) -- there is no second,
/// weaker "arbitrary directory" read path to reason about.
///
/// Genuine absence of the file is **not** treated as failure: it is
/// Corulix 1.0.0's own exact behavior (all 14 tools enabled, no category
/// narrowing, no root overrides), returned here as
/// `Ok(BoundWorkspaceConfig)` with defaults. Every other failure --
/// permission denied, oversized file, invalid UTF-8, malformed/invalid
/// content, semantic tool-policy violation, unresolvable root override --
/// fails closed as the corresponding [`WorkspaceConfigError`], never
/// silently substituting defaults for an ambiguous outcome.
///
/// # Errors
///
/// See [`parse_workspace_config`] and [`bind_workspace_config_roots`] for
/// the full parse/bind error surface; additionally
/// [`WorkspaceConfigError::PathDenied`] (file exists but could not be
/// opened/read for a reason other than absence) and
/// [`WorkspaceConfigError::TooLarge`]/[`WorkspaceConfigError::NotUtf8`] for
/// the bytes actually read.
pub async fn load_workspace_config(
    context: &wht_corulix_workspace::WorkspaceContext,
) -> Result<BoundWorkspaceConfig, WorkspaceConfigError> {
    load_workspace_config_with_catalog_mode(context, false).await
}

/// Same as [`load_workspace_config`], but threads `empty_catalog_supported`
/// through to [`wht_corulix_core::validate_tool_policy`] explicitly --
/// separated out so a caller that has already settled Phase D's empirical
/// empty-catalog protocol probe (or a test) never has to guess which
/// default [`load_workspace_config`] itself uses.
///
/// # Errors
///
/// Identical error surface to [`load_workspace_config`].
pub async fn load_workspace_config_with_catalog_mode(
    context: &wht_corulix_workspace::WorkspaceContext,
    empty_catalog_supported: bool,
) -> Result<BoundWorkspaceConfig, WorkspaceConfigError> {
    let root: wht_corulix_workspace::WorkspaceRoot = match context.descriptor_location() {
        Some(descriptor) => descriptor.clone(),
        None => context
            .resolve_root(None)
            .map_err(|_| WorkspaceConfigError::PathDenied)?
            .clone(),
    };

    let bytes = wht_corulix_workspace::confined_read_optional(
        root,
        std::path::PathBuf::from(WORKSPACE_CONFIG_FILE_NAME),
        MAX_WORKSPACE_CONFIG_FILE_BYTES,
    )
    .await
    .map_err(|error| match error {
        wht_corulix_core::CorulixError::FileTooLarge => WorkspaceConfigError::TooLarge,
        _ => WorkspaceConfigError::PathDenied,
    })?;

    let Some(bytes) = bytes else {
        return Ok(BoundWorkspaceConfig {
            tool_policy: EffectiveToolSet::all_enabled(),
            defaults: WorkspaceDefaults::default(),
            root_overrides: Vec::new(),
        });
    };

    let text = std::str::from_utf8(&bytes).map_err(|_| WorkspaceConfigError::NotUtf8)?;
    let config = parse_workspace_config(text, empty_catalog_supported)?;
    bind_workspace_config_roots(config, context).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_MINIMAL: &str = r#"{
        "configName": "WhaTalker Corulix JSON Config",
        "schemaVersion": 1
    }"#;

    #[test]
    fn minimal_valid_file_parses_to_all_enabled_defaults() -> Result<(), WorkspaceConfigError> {
        let config = parse_workspace_config(VALID_MINIMAL, false)?;
        assert_eq!(config.tool_policy, EffectiveToolSet::all_enabled());
        assert!(config.defaults.disabled_categories.is_empty());
        assert!(config.root_overrides.is_empty());
        Ok(())
    }

    #[test]
    fn empty_tool_policy_and_empty_disabled_tools_are_equivalent_to_absent()
    -> Result<(), WorkspaceConfigError> {
        let with_empty_object = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "toolPolicy": {}
        }"#;
        let with_empty_array = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "toolPolicy": { "disabledTools": [] }
        }"#;
        for text in [VALID_MINIMAL, with_empty_object, with_empty_array] {
            let config = parse_workspace_config(text, false)?;
            assert_eq!(config.tool_policy, EffectiveToolSet::all_enabled());
        }
        Ok(())
    }

    #[test]
    fn full_conceptual_example_parses_correctly() -> Result<(), WorkspaceConfigError> {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "toolPolicy": { "disabledTools": ["begin_change", "submit_edit", "validate_change", "change_status", "complete_change", "abort_change"] },
            "defaults": { "disabledCategories": ["FORMATTER"] },
            "rootOverrides": [
                { "root": "wht_backend", "disabledCategories": ["FORMATTER", "LINTER"] },
                { "root": "wht_frontend", "disabledCategories": ["FORMATTER"] }
            ]
        }"#;
        let config = parse_workspace_config(text, false)?;
        assert_eq!(config.tool_policy.effective_visible_tool_count(), 8);
        assert_eq!(
            config.defaults.disabled_categories,
            HashSet::from([ProviderCategory::Formatter])
        );
        assert_eq!(config.root_overrides.len(), 2);
        assert_eq!(config.root_overrides[0].root, "wht_backend");
        assert_eq!(
            config.root_overrides[0].disabled_categories,
            HashSet::from([ProviderCategory::Formatter, ProviderCategory::Linter])
        );
        Ok(())
    }

    #[test]
    fn wrong_config_name_is_rejected() {
        let text = r#"{"configName": "Not The Right Name", "schemaVersion": 1}"#;
        assert_eq!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::WrongConfigName)
        );
    }

    #[test]
    fn missing_config_name_is_malformed() {
        let text = r#"{"schemaVersion": 1}"#;
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::Malformed(_))
        ));
    }

    #[test]
    fn missing_schema_version_is_malformed() {
        let text = r#"{"configName": "WhaTalker Corulix JSON Config"}"#;
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::Malformed(_))
        ));
    }

    #[test]
    fn unsupported_schema_version_is_reported_before_body_parse() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 2,
            "thisFieldDoesNotExistInV1": true
        }"#;
        assert_eq!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::UnsupportedSchemaVersion(2))
        );
    }

    #[test]
    fn schema_version_as_string_is_rejected_not_coerced() {
        let text = r#"{"configName": "WhaTalker Corulix JSON Config", "schemaVersion": "1"}"#;
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::Malformed(_))
        ));
    }

    #[test]
    fn schema_version_as_float_is_rejected() {
        let text = r#"{"configName": "WhaTalker Corulix JSON Config", "schemaVersion": 1.0}"#;
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::Malformed(_))
        ));
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "extra": true
        }"#;
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::Malformed(_))
        ));
    }

    #[test]
    fn host_config_privilege_field_is_rejected_as_unknown() {
        for field in [
            "workspace_trust",
            "allow_trusted_workspace_execution",
            "provider_absolute_paths",
            "approved_system_directories",
            "approved_user_toolchain_directories",
            "enable_user_toolchain_directories",
            "managed_provisioning_policy",
        ] {
            let text = format!(
                r#"{{"configName": "WhaTalker Corulix JSON Config", "schemaVersion": 1, "{field}": true}}"#
            );
            assert!(
                matches!(
                    parse_workspace_config(&text, false),
                    Err(WorkspaceConfigError::Malformed(_))
                ),
                "expected {field} to be rejected as an unknown field"
            );
        }
    }

    #[test]
    fn duplicate_json_key_is_rejected_not_last_value_wins() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "schemaVersion": 2
        }"#;
        // The envelope phase parses `WorkspaceConfigEnvelope` directly (no
        // `Value` intermediate) -- serde_derive's generated visitor rejects
        // the repeated `schemaVersion` key itself, before either value is
        // ever compared to `WORKSPACE_CONFIG_SCHEMA_VERSION`.
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::Malformed(_))
        ));
    }

    #[test]
    fn malformed_json_is_rejected() {
        let text = "{ this is not valid json";
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::Malformed(_))
        ));
    }

    #[test]
    fn duplicate_tool_in_policy_is_rejected() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "toolPolicy": { "disabledTools": ["search", "search"] }
        }"#;
        assert_eq!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::ToolPolicy(
                ToolPolicyValidationError::DuplicateToolInPolicy("search".to_string())
            ))
        );
    }

    #[test]
    fn unknown_tool_name_is_rejected() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "toolPolicy": { "disabledTools": ["delete_repo"] }
        }"#;
        assert_eq!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::ToolPolicy(
                ToolPolicyValidationError::UnknownToolName("delete_repo".to_string())
            ))
        );
    }

    #[test]
    fn duplicate_category_in_defaults_is_rejected() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "defaults": { "disabledCategories": ["FORMATTER", "FORMATTER"] }
        }"#;
        assert_eq!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::DuplicateCategoryInPolicy(
                "defaults".to_string(),
                ProviderCategory::Formatter
            ))
        );
    }

    #[test]
    fn duplicate_category_in_root_override_is_rejected() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "rootOverrides": [
                { "root": "wht_backend", "disabledCategories": ["LINTER", "LINTER"] }
            ]
        }"#;
        assert_eq!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::DuplicateCategoryInPolicy(
                "wht_backend".to_string(),
                ProviderCategory::Linter
            ))
        );
    }

    #[test]
    fn absolute_root_locator_is_rejected() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "rootOverrides": [{"root": "/etc/passwd"}]
        }"#;
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::InvalidRootLocator(_))
        ));
    }

    /// P17-W corrective pass: `/etc/passwd` above is the exact Windows-
    /// discovered regression case (host-native `Path::is_absolute()` does
    /// not consider a bare `/`-prefixed string absolute on Windows), plus
    /// every other rooted/absolute syntax class this validator must reject
    /// regardless of which host OS actually runs the parser -- proving the
    /// portable, string-based `is_disallowed_rooted_locator` check rather
    /// than relying on host-native path semantics. Runs identically on
    /// Linux and Windows (pure string logic, no filesystem I/O).
    #[test]
    fn cross_platform_rooted_locator_classes_are_rejected() {
        let disallowed = [
            "/etc/passwd",               // POSIX absolute
            "/foo",                      // POSIX absolute
            "/foo/bar",                  // POSIX absolute
            "\\foo",                     // Windows rooted-without-drive
            "\\\\server\\share",         // UNC
            "\\\\server\\share\\folder", // UNC with subpath
            "\\\\?\\C:\\foo",            // extended-length / device namespace
            "\\\\?\\UNC\\server\\share", // extended-length UNC
            "\\\\.\\PhysicalDrive0",     // device namespace
            "C:\\foo",                   // Windows drive-absolute (backslash)
            "C:/foo",                    // Windows drive-absolute (forward slash)
            "D:\\workspace",             // Windows drive-absolute, non-C drive
            "C:foo",                     // Windows drive-relative (ambiguous)
            "C:",                        // Windows drive-relative, bare
        ];
        for locator in disallowed {
            let text = format!(
                r#"{{
                    "configName": "WhaTalker Corulix JSON Config",
                    "schemaVersion": 1,
                    "rootOverrides": [{{"root": {locator:?}}}]
                }}"#
            );
            assert!(
                matches!(
                    parse_workspace_config(&text, false),
                    Err(WorkspaceConfigError::InvalidRootLocator(_))
                ),
                "expected {locator:?} to be rejected as InvalidRootLocator on every host OS"
            );
        }
    }

    /// Sibling proof to the rejection matrix above: every legitimate
    /// relative locator syntax (POSIX-separated, Windows-separated, and
    /// parent-relative) must still parse past this stage -- this validator
    /// narrows to rooted/absolute forms only, it must never reject a
    /// genuinely relative locator on either platform.
    #[test]
    fn cross_platform_relative_locator_classes_are_accepted_at_the_syntactic_stage()
    -> Result<(), WorkspaceConfigError> {
        let allowed = [
            "foo/bar",
            "./foo/bar",
            "foo\\bar",
            ".\\foo\\bar",
            "../sibling",
        ];
        for locator in allowed {
            let text = format!(
                r#"{{
                    "configName": "WhaTalker Corulix JSON Config",
                    "schemaVersion": 1,
                    "rootOverrides": [{{"root": {locator:?}}}]
                }}"#
            );
            parse_workspace_config(&text, false)?;
        }
        Ok(())
    }

    #[test]
    fn empty_root_locator_is_rejected() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "rootOverrides": [{"root": ""}]
        }"#;
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::InvalidRootLocator(_))
        ));
    }

    #[test]
    fn parent_relative_root_locator_is_accepted_at_the_syntactic_stage()
    -> Result<(), WorkspaceConfigError> {
        // Real .code-workspace descriptors legitimately use "../sibling"
        // (wht_corulix_workspace::descriptor's own
        // `parses_comments_and_trailing_commas` test) -- this module must
        // not reject it; canonical-path authorization happens in Phase C.
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "rootOverrides": [{"root": "../sibling"}]
        }"#;
        let config = parse_workspace_config(text, false)?;
        assert_eq!(config.root_overrides[0].root, "../sibling");
        Ok(())
    }

    #[test]
    fn toolpolicy_key_inside_root_override_is_rejected_as_unknown_field() {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "rootOverrides": [{"root": "wht_backend", "toolPolicy": {"disabledTools": []}}]
        }"#;
        assert!(matches!(
            parse_workspace_config(text, false),
            Err(WorkspaceConfigError::Malformed(_))
        ));
    }

    // ---------------------------------------------------------------
    // Phase C: bind_workspace_config_roots
    // ---------------------------------------------------------------

    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wht_corulix_workspace::{WorkspaceContext, WorkspaceRoot};

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let dir =
            std::env::temp_dir().join(format!("corulix-workspace-config-test-{label}-{stamp}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn config_with_root_override(root: &str) -> WorkspaceConfig {
        let text = format!(
            r#"{{"configName": "WhaTalker Corulix JSON Config", "schemaVersion": 1, "rootOverrides": [{{"root": {root:?}, "disabledCategories": ["FORMATTER"]}}]}}"#
        );
        parse_workspace_config(&text, false).unwrap_or_else(|_| WorkspaceConfig {
            tool_policy: EffectiveToolSet::all_enabled(),
            defaults: WorkspaceDefaults::default(),
            root_overrides: Vec::new(),
        })
    }

    #[tokio::test]
    async fn single_root_workspace_binds_dot_locator_to_its_own_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("single-dot");
        let context = WorkspaceContext::single_root(WorkspaceRoot::open(&dir)?, "solo".to_string());
        let config = config_with_root_override(".");
        let bound = bind_workspace_config_roots(config, &context).await?;
        assert_eq!(bound.root_overrides.len(), 1);
        assert_eq!(
            bound.root_overrides[0].0,
            wht_corulix_core::WorkspaceRootId(0)
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn single_root_workspace_rejects_unrelated_locator()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("single-unrelated");
        let context = WorkspaceContext::single_root(WorkspaceRoot::open(&dir)?, "solo".to_string());
        let config = config_with_root_override("does-not-exist-here");
        let result = bind_workspace_config_roots(config, &context).await;
        assert!(matches!(
            result,
            Err(WorkspaceConfigError::UnknownRootOverride(_))
        ));
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn multi_root_workspace_binds_sibling_locator_via_descriptor_location()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = temp_dir("multi-parent");
        let backend = parent.join("wht_backend");
        let frontend = parent.join("wht_frontend");
        let _ = fs::create_dir_all(&backend);
        let _ = fs::create_dir_all(&frontend);
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&backend)?, "wht_backend".to_string()),
            (WorkspaceRoot::open(&frontend)?, "wht_frontend".to_string()),
        ])?
        .with_descriptor_location(WorkspaceRoot::open(&parent)?);
        let config = config_with_root_override("wht_backend");
        let bound = bind_workspace_config_roots(config, &context).await?;
        assert_eq!(bound.root_overrides.len(), 1);
        assert_eq!(
            bound.root_overrides[0].0,
            wht_corulix_core::WorkspaceRootId(0)
        );
        assert_eq!(
            bound.root_overrides[0].1.disabled_categories,
            HashSet::from([ProviderCategory::Formatter])
        );
        let _ = fs::remove_dir_all(&parent);
        Ok(())
    }

    #[tokio::test]
    async fn parent_relative_locator_resolving_to_an_authorized_sibling_is_accepted()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = temp_dir("parent-relative-ok");
        let a = parent.join("a");
        let b = parent.join("b");
        let _ = fs::create_dir_all(&a);
        let _ = fs::create_dir_all(&b);
        // A resolved from within `b` (via a `.code-workspace` sitting in
        // `parent`, so the descriptor_location join base is `parent`
        // itself, not `b`) -- but the same "../sibling" shape a real
        // .code-workspace root can carry (`descriptor.rs`'s own
        // `parses_comments_and_trailing_commas` test) is exercised here as
        // a root override locator authored relative to `parent`.
        let context = WorkspaceContext::from_roots(vec![
            (WorkspaceRoot::open(&a)?, "a".to_string()),
            (WorkspaceRoot::open(&b)?, "b".to_string()),
        ])?
        .with_descriptor_location(WorkspaceRoot::open(&parent)?);
        let config = config_with_root_override("b");
        let bound = bind_workspace_config_roots(config, &context).await?;
        assert_eq!(
            bound.root_overrides[0].0,
            wht_corulix_core::WorkspaceRootId(1)
        );
        let _ = fs::remove_dir_all(&parent);
        Ok(())
    }

    #[tokio::test]
    async fn locator_resolving_outside_the_authorized_root_set_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = temp_dir("escape-parent");
        let workspace_root = parent.join("workspace");
        let outside = parent.join("outside-sibling");
        let _ = fs::create_dir_all(&workspace_root);
        let _ = fs::create_dir_all(&outside);
        let context = WorkspaceContext::from_roots(vec![(
            WorkspaceRoot::open(&workspace_root)?,
            "workspace".to_string(),
        )])?
        .with_descriptor_location(WorkspaceRoot::open(&workspace_root)?);
        // "../outside-sibling" canonicalizes to a real directory on disk,
        // but one that is NOT one of this context's own authorized member
        // roots -- must be rejected, not silently accepted merely because
        // canonicalization succeeded.
        let config = config_with_root_override("../outside-sibling");
        let result = bind_workspace_config_roots(config, &context).await;
        assert!(matches!(
            result,
            Err(WorkspaceConfigError::UnknownRootOverride(_))
        ));
        let _ = fs::remove_dir_all(&parent);
        Ok(())
    }

    // ---------------------------------------------------------------
    // load_workspace_config: real filesystem read (NotPresent/PathDenied)
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn absent_config_file_loads_as_all_enabled_defaults()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("load-absent");
        let context = WorkspaceContext::single_root(WorkspaceRoot::open(&dir)?, "solo".to_string());
        let bound = load_workspace_config(&context).await?;
        assert_eq!(bound.tool_policy, EffectiveToolSet::all_enabled());
        assert!(bound.defaults.disabled_categories.is_empty());
        assert!(bound.root_overrides.is_empty());
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn present_valid_config_file_loads_and_binds() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("load-present");
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "toolPolicy": { "disabledTools": ["search"] },
            "defaults": { "disabledCategories": ["FORMATTER"] }
        }"#;
        fs::write(dir.join(WORKSPACE_CONFIG_FILE_NAME), text)?;
        let context = WorkspaceContext::single_root(WorkspaceRoot::open(&dir)?, "solo".to_string());
        let bound = load_workspace_config(&context).await?;
        assert!(!bound.tool_policy.is_enabled("search"));
        assert_eq!(
            bound.defaults.disabled_categories,
            HashSet::from([ProviderCategory::Formatter])
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn present_but_unreadable_config_file_fails_closed_as_path_denied()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("load-denied");
        let config_path = dir.join(WORKSPACE_CONFIG_FILE_NAME);
        fs::write(&config_path, "irrelevant, made unreadable before parse")?;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o000))?;

        // Empirical privilege probe via plain, safe `std::fs` (never
        // `geteuid()` -- this crate is `#![forbid(unsafe_code)]`): a
        // root/privileged test runner bypasses Unix permission bits
        // entirely, so a direct open would still succeed despite `0o000`.
        // Only skip the strict assertion below if this exact runner
        // actually demonstrates that bypass against this exact file.
        let runner_is_privileged = fs::File::open(&config_path).is_ok();

        let context = WorkspaceContext::single_root(WorkspaceRoot::open(&dir)?, "solo".to_string());
        let result = load_workspace_config(&context).await;
        let _ = fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644));
        let _ = fs::remove_dir_all(&dir);
        if runner_is_privileged {
            return Ok(());
        }
        assert_eq!(result, Err(WorkspaceConfigError::PathDenied));
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_root_binding_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("duplicate-binding");
        let context = WorkspaceContext::single_root(WorkspaceRoot::open(&dir)?, "solo".to_string());
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "rootOverrides": [
                {"root": ".", "disabledCategories": ["FORMATTER"]},
                {"root": ".", "disabledCategories": ["LINTER"]}
            ]
        }"#;
        let config = parse_workspace_config(text, false)?;
        let result = bind_workspace_config_roots(config, &context).await;
        assert!(matches!(
            result,
            Err(WorkspaceConfigError::DuplicateRootOverride(_))
        ));
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}

/// Emits the canonical JSON Schema for `WhaTalker_Corulix_JSON_Config.json`
/// v1 -- `corulix config schema` and a future Python Configurator consume
/// this instead of hand-duplicating Corulix's own validation rules (ADR
/// 0012: "Corulix, not a future Python Configurator, owns schema
/// authority"). The `toolPolicy.disabledTools` item enum is injected from
/// the single shared [`wht_corulix_core::CANONICAL_MCP_TOOL_NAMES`]
/// catalog -- never a second, hand-maintained list -- so it can never
/// silently drift from the real semantic validator
/// (`schema_tool_name_enum_matches_canonical_catalog` proves this
/// exactly).
///
/// This schema documents shape-level constraints only: root-selector
/// resolution, cross-root uniqueness, and the mutation-lifecycle/gate-
/// visibility semantic rules remain [`bind_workspace_config_roots`]/
/// [`wht_corulix_core::validate_tool_policy`]'s own responsibility, never
/// representable in JSON Schema alone.
#[must_use]
pub fn workspace_config_json_schema() -> serde_json::Value {
    let schema = schemars::schema_for!(WorkspaceConfigFileV1);
    let mut value = serde_json::to_value(schema).unwrap_or(serde_json::Value::Null);
    inject_tool_name_enum(&mut value);
    value
}

/// The one place the real, generated schema's `toolPolicy.disabledTools`
/// array-item schema is widened with an `enum` constraint sourced
/// programmatically from [`wht_corulix_core::CANONICAL_MCP_TOOL_NAMES`].
/// Targets `/$defs/ToolPolicyFile/properties/disabledTools/items` -- the
/// exact path `schemars` 1.2.2 places this nested struct's schema at
/// (confirmed by direct inspection of a real generated schema this
/// session, not assumed) -- and is a silent no-op if that path is ever
/// absent (a future `schemars` version changing its own `$ref`/inlining
/// strategy must never panic this function; `schema_tool_name_enum_matches_canonical_catalog`
/// is the real proof this injection still lands correctly).
fn inject_tool_name_enum(value: &mut serde_json::Value) {
    let enum_values: Vec<serde_json::Value> = wht_corulix_core::CANONICAL_MCP_TOOL_NAMES
        .iter()
        .map(|name| serde_json::Value::String((*name).to_string()))
        .collect();
    if let Some(items) = value.pointer_mut("/$defs/ToolPolicyFile/properties/disabledTools/items")
        && let Some(object) = items.as_object_mut()
    {
        object.insert("enum".to_string(), serde_json::Value::Array(enum_values));
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;

    #[test]
    fn schema_tool_name_enum_matches_canonical_catalog() {
        let schema = workspace_config_json_schema();
        let enum_values = schema
            .pointer("/$defs/ToolPolicyFile/properties/disabledTools/items/enum")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let names: HashSet<String> = enum_values
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
        let canonical: HashSet<String> = wht_corulix_core::CANONICAL_MCP_TOOL_NAMES
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        assert_eq!(
            names, canonical,
            "config schema's disabledTools enum has drifted from CANONICAL_MCP_TOOL_NAMES"
        );
    }

    #[test]
    fn schema_agrees_with_real_loader_for_valid_shape() -> Result<(), Box<dyn std::error::Error>> {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "toolPolicy": { "disabledTools": ["search"] },
            "defaults": { "disabledCategories": ["FORMATTER"] }
        }"#;
        let parsed: serde_json::Value = serde_json::from_str(text)?;
        let compiled = jsonschema::validator_for(&workspace_config_json_schema())?;
        assert!(
            compiled.is_valid(&parsed),
            "real loader accepts this fixture but the emitted schema rejects it"
        );
        assert!(
            parse_workspace_config(text, false).is_ok(),
            "fixture used for schema/loader agreement must itself be loader-valid"
        );
        Ok(())
    }

    #[test]
    fn schema_agrees_with_real_loader_for_unknown_field() -> Result<(), Box<dyn std::error::Error>>
    {
        let text = r#"{
            "configName": "WhaTalker Corulix JSON Config",
            "schemaVersion": 1,
            "extraUnknownField": true
        }"#;
        let parsed: serde_json::Value = serde_json::from_str(text)?;
        let compiled = jsonschema::validator_for(&workspace_config_json_schema())?;
        assert!(
            !compiled.is_valid(&parsed),
            "real loader rejects this fixture (unknown field) but the emitted schema accepts it"
        );
        assert!(parse_workspace_config(text, false).is_err());
        Ok(())
    }
}
