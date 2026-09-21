// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! `CORULIX_MANAGED`-first-then-`HOST_ONLY`/system resolution for
//! `rustfmt` (Phase 7B-B2-B). Mirrors
//! `wht_corulix_lsp::profile::resolve_managed_or_system_path`'s own
//! precedent -- this crate's own resolution glue, layered on top of
//! `wht_corulix_config::resolve_provider` rather than duplicated inside it,
//! exactly as `wht_corulix_lsp` already does for its own providers. Rule K
//! (`wht_corulix_config` is sole `HOST_ONLY`/system trust authority) is
//! unaffected: this module never second-guesses what `resolve_provider`
//! returns for the fallback path, it only decides whether to try the
//! managed path *first*.
//!
//! **Formatter authority (no collision).** `wht_corulix_lsp`'s
//! `textDocument/formatting` capability is never invoked anywhere in this
//! workspace (Rule N, unaffected by this phase); `RUST_ANALYZER_FORMATTING_ROLE=NOT_INVOKED`.
//! `cargo fmt`/`cargo-fmt` is never invoked either -- this module resolves
//! and this crate's `invocation` module spawns plain `rustfmt` directly
//! over stdin/stdout, exactly as the pre-existing `HOST_ONLY` path already
//! did; `CARGO_FMT_PRODUCT_ROLE=NOT_APPLICABLE`. `RUST_FORMATTER_AUTHORITY=MANAGED_RUSTFMT`
//! when available, falling through to the pre-existing `HOST_ONLY`/system
//! `rustfmt` otherwise -- always `rustfmt` itself, never a second tool
//! pretending to the same authority.

use std::path::PathBuf;

use wht_corulix_core::{ProviderAvailability, ProviderCategory, ReasonCode};
use wht_corulix_tooling::EnvironmentPolicy;
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
use wht_corulix_workspace::WorkspaceRoot;

use crate::managed_toolchain::{BIOME_HOST_NATIVE, RUSTFMT_HOST_NATIVE};
use crate::profile::{FormatterProfile, ManagedFormatter};

/// A resolved, ready-to-spawn formatter -- either `CORULIX_MANAGED` (with
/// `LD_LIBRARY_PATH` pointed at the managed rust-semantic-runtime's `lib/`,
/// see [`RUSTFMT_LINUX_X64`]'s own doc comment for why that env var, not a
/// directory merge, is the correct mechanism) or the pre-existing
/// `HOST_ONLY`/system resolution, environment-empty exactly as before this
/// phase.
pub(crate) struct ResolvedFormatter {
    pub executable: PathBuf,
    pub environment: EnvironmentPolicy,
    pub used_managed: bool,
    /// The managed component id whose lease must be held while this
    /// resolution's own `ManagedProcess` invocation runs (`None` when
    /// `used_managed` is `false`). Distinct from `used_managed` alone
    /// because a caller building the invocation's `ManagedLeaseBinding` (see
    /// `crate::compute_formatted`) must lease the component that was
    /// *actually* resolved -- rustfmt, biome, or the shared
    /// go-semantic-runtime -- never a different formatter's hardcoded id.
    pub managed_primary_component_id: Option<&'static str>,
    /// Additional managed components the primary one depends on and whose
    /// lease must also be held (rustfmt's separate `rust-semantic-runtime`
    /// dependency; empty for a self-contained component like biome or
    /// go-semantic-runtime, which provides both `go` and `gofmt` from one
    /// component).
    pub managed_dependency_component_ids: Vec<&'static str>,
}

/// Resolves the formatter named by `profile`.
///
/// When `profile.managed` names a real `CORULIX_MANAGED` component
/// ([`ManagedFormatter::RustfmtLinuxX64`] today), that path is tried first
/// against [`RUSTFMT_HOST_NATIVE`] -- this host's own real manifest
/// ([`crate::managed_toolchain::RUSTFMT_LINUX_X64`] on Linux,
/// [`crate::managed_toolchain::RUSTFMT_WINDOWS_X64`] on Windows), never a
/// hardcoded platform literal.
/// (Both the component itself and its `rust-semantic-runtime` dependency
/// must independently be [`ManagedComponentState::Available`] under
/// `managed_root`, via [`provisioning::resolve_owned_managed_component`] --
/// never the weaker, filesystem-presence-only `resolve_managed_component`,
/// matching the mandatory rule every other managed-first spawn path in this
/// workspace already follows). Every [`ManagedFormatter`] variant now names a
/// real `CORULIX_MANAGED` component (M03 Python managed-auxiliary final
/// closure: Ruff 0.16.3 was the last profile still resolving `HOST_ONLY`-only).
///
/// Either way, resolution then proceeds through the pre-existing
/// `HOST_ONLY`/system precedence (`wht_corulix_config::resolve_provider`,
/// Rule K) unchanged. On failure, returns `resolve_provider`'s own specific
/// [`ReasonCode`] verbatim (e.g. `ProviderResolvedInsideWorkspace`, not a
/// generic substitute) -- the managed path never having been attempted at
/// all carries no reason of its own to report; `resolve_provider`'s is
/// always the real, final word here.
/// This host's own real `rust-semantic-runtime` manifest -- `&'static
/// ManagedComponentManifest`, exactly mirroring [`RUSTFMT_HOST_NATIVE`]'s
/// own `#[cfg]`-gated-alias pattern rather than a runtime `if cfg!(...)`
/// branch, so a build for the "wrong" platform cannot even compile a path
/// that resolves the other platform's manifest. Added P17-W-R4-C2: before
/// this, [`resolve_formatter`] resolved
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64`]
/// unconditionally regardless of host -- harmless on Linux (the only
/// platform managed rustfmt could actually reach `Available` on before this
/// phase), but the exact hardcoded-to-Linux defect class
/// `RUSTFMT_HOST_NATIVE` itself was introduced to close for the *rustfmt*
/// manifest lookup one call above; this closes the same class for its
/// *runtime dependency* lookup.
#[cfg(target_os = "windows")]
pub(crate) fn rust_semantic_runtime_host_native()
-> &'static wht_corulix_tooling::provisioning::ManagedComponentManifest {
    &wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn rust_semantic_runtime_host_native()
-> &'static wht_corulix_tooling::provisioning::ManagedComponentManifest {
    &wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64
}

/// This host's own real `go-semantic-runtime` manifest -- same
/// `#[cfg]`-gated-alias pattern as [`rust_semantic_runtime_host_native`].
/// Resolved directly against `wht_corulix_tooling::managed_runtimes` (this
/// crate already depends on `wht_corulix_tooling`, not `wht_corulix_lsp` --
/// see that module's own doc comment for why the manifest lives there now
/// that both `wht_corulix_lsp` and this crate consume it).
#[cfg(target_os = "windows")]
pub(crate) fn go_semantic_runtime_host_native()
-> &'static wht_corulix_tooling::provisioning::ManagedComponentManifest {
    &wht_corulix_tooling::managed_runtimes::GO_SEMANTIC_RUNTIME_WINDOWS_X64
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn go_semantic_runtime_host_native()
-> &'static wht_corulix_tooling::provisioning::ManagedComponentManifest {
    &wht_corulix_tooling::managed_runtimes::GO_SEMANTIC_RUNTIME_LINUX_X64
}

/// This host's own real `ruff` manifest -- same `#[cfg]`-gated-alias pattern
/// as [`go_semantic_runtime_host_native`]. Resolved directly against
/// `wht_corulix_tooling::managed_runtimes` (this crate already depends on
/// `wht_corulix_tooling`). The **identical** underlying constant is also
/// referenced by `wht_corulix_engine::python_providers`'s own `ruff_host_native`
/// accessor for the Linter category -- both point at the same
/// `pub const RUFF_LINUX_X64`/`RUFF_WINDOWS_X64` value declared once in
/// `wht_corulix_tooling::managed_runtimes`, so Formatter and Linter can never
/// drift onto two independently defined manifests (M03 Python
/// managed-auxiliary final closure, Ruff 0.16.3).
#[cfg(target_os = "windows")]
pub(crate) fn ruff_host_native()
-> &'static wht_corulix_tooling::provisioning::ManagedComponentManifest {
    &wht_corulix_tooling::managed_runtimes::RUFF_WINDOWS_X64
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn ruff_host_native()
-> &'static wht_corulix_tooling::provisioning::ManagedComponentManifest {
    &wht_corulix_tooling::managed_runtimes::RUFF_LINUX_X64
}

/// `gofmt`'s own filename, sibling to `go` in the go-semantic-runtime
/// component's `bin/` directory -- platform-suffixed exactly as the
/// manifest's own `required_paths` entries are (`bin/gofmt` vs
/// `bin/gofmt.exe`).
#[cfg(target_os = "windows")]
const GOFMT_EXECUTABLE_NAME: &str = "gofmt.exe";
#[cfg(not(target_os = "windows"))]
const GOFMT_EXECUTABLE_NAME: &str = "gofmt";

/// Builds the one environment variable managed `rustfmt` needs to resolve
/// its `rust-semantic-runtime` dependency's dynamic libraries at load time
/// -- platform-adaptive, never a single hardcoded mechanism, because the
/// two platforms' dynamic linkers use genuinely different, non-overlapping
/// resolution knobs:
///
/// - **Unix** (`LD_LIBRARY_PATH`): the real, already-certified
///   `rustc-1.98.0-x86_64-unknown-linux-gnu.tar.gz` places its shared
///   objects under a separate `lib/` directory; `rustfmt`'s own `RUNPATH`
///   (`$ORIGIN/../lib`, confirmed via `readelf -d`) already resolves
///   relative to wherever `rustfmt` itself sits, so this variable exists
///   only to point the *runtime's own* `lib/` at the *separate component
///   directory* `rustfmt` is not installed inside of -- see
///   [`RUSTFMT_LINUX_X64`]'s own doc comment.
/// - **Windows** (`PATH`): there is no `LD_LIBRARY_PATH`/`RPATH`/`RUNPATH`
///   equivalent. The managed `rust-semantic-runtime` Windows manifest's own
///   doc comment records the real, verified root cause (`tar tzf` against
///   the actual downloaded artifact): `rustc_driver-<hash>.dll` and
///   `std-<hash>.dll` sit as real PE DLLs directly inside that runtime's
///   own `bin/` directory, with no separate `lib/`. The Windows PE loader's
///   own documented DLL search order includes each directory listed in the
///   *calling process's own* `PATH` environment variable, so prepending
///   (here: setting, since this crate's spawn path already `env_clear()`s
///   first -- see `wht_corulix_tooling::execute`'s own doc comment) that
///   one `bin/` directory as this managed `rustfmt.exe` child's entire
///   `PATH` lets the OS loader find both DLLs at process start, without
///   ever touching the *ambient* system `PATH`, the parent Corulix
///   process's own `PATH`, or any directory this crate does not itself
///   own. This is exactly the "process-local Corulix-owned PATH prepend
///   containing ONLY owned runtime directories" mechanism named as the
///   correct fix for `WINDOWS_RUST_DLL_RESOLUTION` -- never a copy of the
///   two DLLs into `rustfmt`'s own install directory (which would silently
///   duplicate already-hash-verified bytes under a second, unverified
///   path), and never a merge with the ambient/system `PATH` (which is
///   exactly the `WINDOWS_RUST_AMBIENT_PATH_AUTHORITY` a hostile
///   `PATH`-planted `rustc_driver-*.dll` could otherwise exploit).
#[cfg(target_os = "windows")]
pub(crate) fn rust_semantic_runtime_dll_environment(
    runtime_install_dir: &std::path::Path,
) -> EnvironmentPolicy {
    let bin_dir = runtime_install_dir.join("bin");
    EnvironmentPolicy::empty().with_var("PATH", bin_dir.to_string_lossy().into_owned())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn rust_semantic_runtime_dll_environment(
    runtime_install_dir: &std::path::Path,
) -> EnvironmentPolicy {
    let lib_dir = runtime_install_dir.join("lib");
    EnvironmentPolicy::empty().with_var("LD_LIBRARY_PATH", lib_dir.to_string_lossy().into_owned())
}

pub(crate) async fn resolve_formatter(
    profile: &FormatterProfile,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &WorkspaceRoot,
    managed_root: &std::path::Path,
) -> Result<ResolvedFormatter, Option<ReasonCode>> {
    if profile.managed == ManagedFormatter::RustfmtLinuxX64 {
        let (rustfmt_state, rustfmt_path) =
            provisioning::resolve_owned_managed_component(managed_root, &RUSTFMT_HOST_NATIVE);
        if rustfmt_state == ManagedComponentState::Available
            && let Some(executable) = rustfmt_path
        {
            let runtime_manifest = rust_semantic_runtime_host_native();
            let (runtime_state, _) =
                provisioning::resolve_owned_managed_component(managed_root, runtime_manifest);
            if runtime_state == ManagedComponentState::Available {
                let runtime_install_dir =
                    provisioning::component_install_dir(managed_root, runtime_manifest);
                let environment = rust_semantic_runtime_dll_environment(&runtime_install_dir);
                return Ok(ResolvedFormatter {
                    executable,
                    environment,
                    used_managed: true,
                    managed_primary_component_id: Some(RUSTFMT_HOST_NATIVE.id.0),
                    managed_dependency_component_ids: vec![runtime_manifest.id.0],
                });
            }
        }
    }

    // Biome (P16, Windows-native as of P17-W Stage F): a single,
    // statically-linked native binary with no sibling-runtime dependency
    // (unlike rustfmt's rust-semantic-runtime requirement, on either
    // platform -- see `BIOME_WINDOWS_X64`'s own doc comment) --
    // `resolve_owned_managed_component` reporting `Available` is the whole
    // gate, and no environment variable is ever required
    // (`EnvironmentPolicy::empty()`, exactly the `HOST_ONLY`/system path's
    // own environment). Resolved against `BIOME_HOST_NATIVE` -- this host's
    // own real manifest (`BIOME_LINUX_X64` on Linux, `BIOME_WINDOWS_X64` on
    // Windows), never a hardcoded platform literal; mirrors
    // `RUSTFMT_HOST_NATIVE`'s own rationale one arm above.
    if profile.managed == ManagedFormatter::BiomeLinuxX64 {
        let (biome_state, biome_path) =
            provisioning::resolve_owned_managed_component(managed_root, &BIOME_HOST_NATIVE);
        if biome_state == ManagedComponentState::Available
            && let Some(executable) = biome_path
        {
            return Ok(ResolvedFormatter {
                executable,
                environment: EnvironmentPolicy::empty(),
                used_managed: true,
                managed_primary_component_id: Some(BIOME_HOST_NATIVE.id.0),
                managed_dependency_component_ids: Vec::new(),
            });
        }
    }

    // `gofmt` (M03 rename_preview managed auxiliary capability closure):
    // managed-first against the shared `go-semantic-runtime` component --
    // the same component `wht_corulix_engine::go_providers::resolve_go_toolchain`
    // already resolves managed-first for `go build`/`go vet`/`go test`.
    // `gofmt` sits as a sibling of `go` in that component's own `bin/`
    // directory; `bin/gofmt`/`bin/gofmt.exe` is already a `required_paths`
    // entry on both platform manifests, so its presence is verified at
    // provisioning time exactly like `go` itself -- this branch re-verifies
    // it on disk defensively rather than trusting that alone.
    //
    // Fail-closed on `Corrupt`/`Incompatible`, mirroring
    // `go_providers::resolve_managed_go_toolchain`'s own precedent exactly:
    // a present-but-invalid managed installation must never silently fall
    // through to an explicit approved `HOST_ONLY` `gofmt`, which would mask
    // it (`INVALID_MANAGED_STATE_HOST_FALLBACK_COUNT` must stay `0`). Only a
    // genuinely not-yet-provisioned state falls through to the
    // `HOST_ONLY`/system precedence below -- `P15_AUTO_INSTALL_EXTERNAL_TOOLING=NO`
    // is unchanged: this branch never acquires the runtime itself, it only
    // resolves an already-provisioned one.
    if profile.managed == ManagedFormatter::GoSemanticRuntimeHostNative {
        let runtime_manifest = go_semantic_runtime_host_native();
        let (runtime_state, go_executable, _reason) =
            provisioning::resolve_owned_managed_component_detailed(managed_root, runtime_manifest);
        match runtime_state {
            ManagedComponentState::Available => {
                if let Some(go_executable) = go_executable {
                    let gofmt_path = go_executable.with_file_name(GOFMT_EXECUTABLE_NAME);
                    if gofmt_path.is_file() {
                        return Ok(ResolvedFormatter {
                            executable: gofmt_path,
                            environment: EnvironmentPolicy::empty(),
                            used_managed: true,
                            managed_primary_component_id: Some(runtime_manifest.id.0),
                            managed_dependency_component_ids: Vec::new(),
                        });
                    }
                }
            }
            ManagedComponentState::Corrupt | ManagedComponentState::Incompatible => {
                return Err(Some(ReasonCode::RequiredProviderUnavailable));
            }
            ManagedComponentState::NotProvisioned | ManagedComponentState::Provisioning | _ => {}
        }
    }

    // `ruff format` (M03 Python managed-auxiliary final closure, owner-pinned
    // Ruff 0.16.3): managed-first against the single, statically-linked
    // `ruff` component -- no sibling-runtime dependency, mirroring Biome's
    // shape exactly (unlike rustfmt's separate `rust-semantic-runtime`
    // requirement). Fail-closed on `Corrupt`/`Incompatible`, same precedent
    // as every other managed-first branch in this function: a present but
    // invalid managed installation must never silently fall through to an
    // explicit approved `HOST_ONLY` `ruff`, which would mask it. Only a
    // genuinely not-yet-provisioned state falls through to the
    // `HOST_ONLY`/system precedence below.
    if profile.managed == ManagedFormatter::RuffLinuxX64 {
        let ruff_manifest = ruff_host_native();
        let (ruff_state, ruff_executable, _reason) =
            provisioning::resolve_owned_managed_component_detailed(managed_root, ruff_manifest);
        match ruff_state {
            ManagedComponentState::Available => {
                if let Some(executable) = ruff_executable {
                    return Ok(ResolvedFormatter {
                        executable,
                        environment: EnvironmentPolicy::empty(),
                        used_managed: true,
                        managed_primary_component_id: Some(ruff_manifest.id.0),
                        managed_dependency_component_ids: Vec::new(),
                    });
                }
            }
            ManagedComponentState::Corrupt | ManagedComponentState::Incompatible => {
                return Err(Some(ReasonCode::RequiredProviderUnavailable));
            }
            ManagedComponentState::NotProvisioned | ManagedComponentState::Provisioning | _ => {}
        }
    }

    let resolution = wht_corulix_config::resolve_provider(
        effective,
        workspace_root,
        ProviderCategory::Formatter,
        profile.provider_id,
    )
    .await;
    if resolution.availability == ProviderAvailability::Available
        && let Some(executable) = resolution.resolved_path
    {
        return Ok(ResolvedFormatter {
            executable,
            environment: EnvironmentPolicy::empty(),
            used_managed: false,
            managed_primary_component_id: None,
            managed_dependency_component_ids: Vec::new(),
        });
    }

    // F6 fix (`F6_PRODUCTION_MANAGED_PROVISIONING_UNREACHABLE`), policy-gated
    // (Installation-Contract-V1): neither a strongly-owned managed artifact
    // nor a `HOST_ONLY`/system provider resolved above -- only now, and only
    // when `effective.managed_provisioning_permitted` grants this specific
    // component (persisted install-profile intent, subject to `HostConfig`'s
    // `ManagedProvisioningPolicy` override -- see that type's own doc
    // comment), is real managed acquisition attempted. An operator with an
    // already-working system formatter keeps resolving to it exactly as
    // before this fix regardless of permission; a host/profile combination
    // that does not permit it observes identical behavior to before the F6
    // fix.
    if profile.managed == ManagedFormatter::RustfmtLinuxX64
        && effective.managed_provisioning_permitted(provisioning::install_profile::grants_intent(
            managed_root,
            RUSTFMT_HOST_NATIVE.id.0,
        ))
    {
        let runtime_manifest = rust_semantic_runtime_host_native();
        if provisioning::resolve_or_acquire_owned(managed_root, runtime_manifest, &[])
            .await
            .is_ok()
            && let Ok(executable) = provisioning::resolve_or_acquire_owned(
                managed_root,
                &RUSTFMT_HOST_NATIVE,
                &[runtime_manifest.id.0],
            )
            .await
        {
            let runtime_install_dir =
                provisioning::component_install_dir(managed_root, runtime_manifest);
            let environment = rust_semantic_runtime_dll_environment(&runtime_install_dir);
            return Ok(ResolvedFormatter {
                executable,
                environment,
                used_managed: true,
                managed_primary_component_id: Some(RUSTFMT_HOST_NATIVE.id.0),
                managed_dependency_component_ids: vec![runtime_manifest.id.0],
            });
        }
    }
    if profile.managed == ManagedFormatter::BiomeLinuxX64
        && effective.managed_provisioning_permitted(provisioning::install_profile::grants_intent(
            managed_root,
            BIOME_HOST_NATIVE.id.0,
        ))
        && let Ok(executable) =
            provisioning::resolve_or_acquire_owned(managed_root, &BIOME_HOST_NATIVE, &[]).await
    {
        return Ok(ResolvedFormatter {
            executable,
            environment: EnvironmentPolicy::empty(),
            used_managed: true,
            managed_primary_component_id: Some(BIOME_HOST_NATIVE.id.0),
            managed_dependency_component_ids: Vec::new(),
        });
    }

    // No acquire branch for `GoSemanticRuntimeHostNative`: unlike rustfmt/
    // biome, `P15_AUTO_INSTALL_EXTERNAL_TOOLING=NO` governs Go specifically
    // (see `wht_corulix_engine::go_providers`'s own module doc), and this
    // branch must not acquire a runtime that crate's own managed-first `go
    // build`/`go vet`/`go test` resolution does not itself acquire either --
    // both verticals resolve the same already-provisioned-or-not component,
    // never diverge on who is allowed to provision it.
    //
    // No acquire branch for `RuffLinuxX64` either, for the same reason: Ruff
    // is provisioned exclusively through the canonical `corulix setup --only
    // python` install-group mechanism (`wht_corulix_engine::groups`'s
    // `"python"` group now names `ruff` alongside `pyright`), never through
    // an on-demand acquire-during-formatting path. This also keeps Formatter
    // and Linter symmetric: neither category auto-acquires Ruff on its own.

    Err(resolution.reason)
}
