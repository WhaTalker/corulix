// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Sole owner of workspace-trust authorization, the `HOST_ONLY` /
//! `REPOSITORY_HINT` / `REQUEST_SCOPED` configuration merge model, and
//! canonical async-first provider resolution for WhaTalker Corulix
//! (Architecture Rule K).
//!
//! `DEFAULT_WORKSPACE_TRUST=UNTRUSTED`: trust is a distinct axis from
//! workspace/path validity, provider availability, `RiskClass`, or any
//! MCP-level authentication -- none of those elevate it. Only `HOST_ONLY`
//! owner/operator configuration ([`HostConfig`]) may grant
//! `TRUSTED_WORKSPACE_EXECUTION`; [`RepositoryHints`] and [`RequestOptions`]
//! are structurally incapable of elevating trust or widening provider
//! resolution, since neither type carries a trust, execution-class, or
//! provider-path field at all.
//!
//! Provider resolution ([`resolve_provider`]) never consults ambient `PATH`
//! (`AMBIENT_PATH_PROVIDER_AUTHORITY=NO`) and never accepts a candidate that
//! canonicalizes to a location inside the active workspace for
//! `CONTROLLED_EXTERNAL_TOOL` -- see `resolver` for the exact precedence
//! and the reused Workspace (Rule F) canonicalization boundary.
//!
//! This crate implements no provider *execution* (Phase 7+): every
//! resolution result here is data only -- a category, an availability, a
//! canonicalized path, a provenance, an execution class, and a reason
//! code -- never a function pointer, closure, or process handle.
//!
//! F1 fix: [`load_host_config_file`] (`hostfile` module) is the real,
//! external, operator-facing TOML file format behind `corulix mcp stdio
//! --host-config <FILE>` -- the concrete answer to "how does a `HOST_ONLY`
//! [`HostConfig`] ever reach the shipped binary" this crate previously had
//! no answer to at all.

mod hostfile;
mod resolver;
mod trust;
mod workspace_config;

pub use hostfile::{HostConfigLoadError, MAX_HOST_CONFIG_FILE_BYTES, load_host_config_file};
pub use resolver::{ProviderResolution, resolve_provider};
pub use trust::{
    EXTERNALLY_RESOLVABLE_CATEGORIES, EffectiveConfig, HostConfig, ManagedProvisioningPolicy,
    RepositoryHints, RequestOptions,
};
pub use workspace_config::{
    BoundWorkspaceConfig, MAX_WORKSPACE_CONFIG_FILE_BYTES, RawWorkspaceRootOverride,
    WORKSPACE_CONFIG_FILE_NAME, WORKSPACE_CONFIG_NAME, WORKSPACE_CONFIG_SCHEMA_VERSION,
    WorkspaceConfig, WorkspaceConfigError, WorkspaceDefaults, WorkspaceRootOverrides,
    bind_workspace_config_roots, load_workspace_config, load_workspace_config_with_catalog_mode,
    parse_workspace_config, workspace_config_json_schema,
};
