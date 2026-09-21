// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15: the single place this crate resolves the real `go` toolchain, builds
//! its controlled child environment, and records its exact provider
//! identity.
//!
//! # Stage A (P17-W Master Closure Order): managed-first, `HOST_ONLY`-fallback
//!
//! Until this pass, this module resolved `go` exclusively through the
//! Phase-6 secure provider resolver's `HOST_ONLY`/approved-directory
//! precedence, because `go`/`gofmt` were treated as already-installed
//! *system* tooling and `P15_AUTO_INSTALL_EXTERNAL_TOOLING=NO` forbade P15
//! from introducing a new download path. That was correct as far as it
//! went, but it left Windows with no path to a working Go toolchain at all:
//! Windows ships no system Go, and the Master Closure Order's own §6
//! forbids solving that by manually installing one onto the host.
//!
//! [`wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64`]/
//! `_WINDOWS_X64` already exist as real, SHA-256-verified, `CORULIX_MANAGED`
//! artifact manifests (admitted for `gopls`'s own semantic-runtime
//! dependency in an earlier pass) but, per their own doc comments, were
//! never wired into this crate's `go build`/`go vet`/`go test` routing.
//! This module now resolves in two tiers, in order:
//!
//! 1. **`CORULIX_MANAGED`.** `resolve_managed_go_toolchain` checks
//!    whether this platform's `GO_SEMANTIC_RUNTIME_*` manifest is already
//!    provisioned and *owned* (`resolve_owned_managed_component_detailed` --
//!    presence on disk alone is never enough, per that function's own
//!    ownership-record requirement) under `managed_root`. If so, its `go`
//!    binary is used and its version is independently re-probed (never
//!    assumed from the manifest's own version string) before being trusted.
//! 2. **`HOST_ONLY`/approved-directory** (unchanged from before this pass).
//!    Tried only when tier 1 reports a genuinely not-yet-provisioned state
//!    (`NotProvisioned`/`Provisioning`) -- never as a silent substitute for
//!    a *present but invalid* managed installation
//!    (`ManagedComponentState::Corrupt`/`Incompatible`, e.g. a missing/
//!    malformed/mismatched ownership record or a tampered artifact --
//!    managed-toolchain ownership/integrity hardening pass), which
//!    `resolve_managed_go_toolchain` now fails closed on instead of
//!    folding into "not available" -- `INVALID_MANAGED_STATE_HOST_FALLBACK_COUNT`
//!    must be `0`.
//!
//! This is a deliberate widening of `P15_PROVIDER_FALLBACK_COUNT` from `0`
//! to `1` (one bounded, ordered fallback tier, not an open-ended search):
//! `GO_SEMANTIC_RUNTIME_LINUX_X64` is not provisioned into this
//! environment's managed root today, so on Linux tier 1 reports
//! `NotProvisioned` and every existing `HOST_ONLY`-dependent P15 test and
//! production path is unaffected byte-for-byte. On a host where the
//! managed component *is* provisioned (the Windows VM, once Stage A's own
//! provisioning step runs there), tier 1 resolves first and `HOST_ONLY` is
//! never reached -- `WINDOWS_GO_PRODUCT_ROUTING` no longer depends on any
//! ambient system Go existing at all.
//!
//! `P15_AMBIENT_PATH_AUTHORITY=NO` is unchanged by this: neither tier reads
//! ambient `PATH`. Tier 1 resolves a fixed, versioned path under
//! `managed_root`; tier 2 is the pre-existing
//! `wht_corulix_config::resolve_provider` call, which -- verified in Phase
//! 7B-B2-A-R2's own architectural note, re-confirmed unchanged by this
//! pass -- never reads ambient `PATH` either. A workspace-local `./go` can
//! never satisfy either tier (`ReasonCode::ProviderResolvedInsideWorkspace`
//! for tier 2; tier 1 never looks inside the workspace at all).
//!
//! # One-shot execution: scratch guard, not a `ManagedLeaseBinding`
//!
//! Unlike `wht_corulix_lsp::profile::resolve_launch_at`'s long-lived LSP
//! sessions (which *do* register a root-scoped `ManagedLeaseBinding` so
//! `full_uninstall` cannot remove a runtime a live session still holds),
//! `go build`/`go vet`/`go test` are bounded, one-shot
//! `wht_corulix_tooling::execute` invocations with no persistent process to
//! lease. This mirrors `crate::testing`/`crate::diagnostics`'s own
//! analogous one-shot `cargo`/`rustc` invocations exactly: both already
//! protect their managed-root scratch state with
//! `wht_corulix_tooling::provisioning::acquire_managed_execution_scratch_guard`
//! (held for the whole governed execution) rather than a lease, and
//! `crate::go_validation`/`crate::go_testing` already do the same for Go.
//! Adding a `ManagedLeaseBinding` here would not follow any existing
//! one-shot-execution precedent in this crate -- it would copy a
//! long-lived-process pattern onto a call shape that never has one.
//!
//! # Category mapping (no new policy entries)
//!
//! P15 introduces **no** Go-specific policy table. The existing,
//! language-agnostic [`crate::policy`] entries already carry exactly the two
//! categories Go needs, and this module maps Go's real tools onto them on
//! the strength of a real, empirical behavioural split:
//!
//! ```text
//! ProviderCategory::TypecheckBuild -> go build   (Authoritative)
//! ProviderCategory::Linter         -> go vet     (SupportingOnly)
//! ProviderCategory::TestRunner     -> go test    (Authoritative for gate.tests)
//! ProviderCategory::Formatter      -> gofmt      (wht_corulix_formatter's own profile)
//! ProviderCategory::LanguageServer -> gopls      (wht_corulix_lsp's own profile)
//! ```
//!
//! The `TypecheckBuild`/`Linter` split is not an assumption: a fixture whose
//! only defect is a `fmt.Printf("%d", "a string")` format-string mismatch was
//! observed to **pass** `go build` (exit 0) and **fail** `go vet` (exit 1)
//! against the real `go1.26.6` on this host. `go vet` therefore has genuinely
//! distinct authority from `go build`, exactly as `clippy` does from
//! `cargo check`, and inherits `Linter`'s workspace-wide
//! never-`Authoritative` invariant
//! (`crate::policy::tests::linter_is_never_authoritative_anywhere_in_the_table`).
//!
//! # Environment (`env_clear`-safe, empirically derived)
//!
//! `wht_corulix_tooling::ManagedProcess::spawn`/`execute` unconditionally
//! `env_clear()` the child, so the Go command starts with *nothing* -- not
//! even `HOME`. Verified empirically: under a cleared environment the `go`
//! command fails outright with `failed to initialize build cache at
//! /nonexistent/.cache/go-build`. Every variable [`go_environment`] sets is
//! therefore load-bearing, and each one is justified in that function's own
//! doc comment. None is inherited from this process.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use wht_corulix_core::{CancellationToken, ExecutionClass, ProviderCategory, ReasonCode};
use wht_corulix_tooling::provisioning::{ManagedComponentManifest, ManagedComponentState};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, TerminationReason};

/// The `go` command's own executable name, as looked for inside approved
/// directories. Never joined onto an ambient `PATH` entry.
pub(crate) const GO_EXECUTABLE: &str = "go";

/// Why a real `go` toolchain could not be resolved or identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoProviderError {
    /// Neither the `CORULIX_MANAGED` tier nor the `HOST_ONLY` fallback tier
    /// resolved a usable `go`. Carries the `HOST_ONLY` resolver's own
    /// specific [`ReasonCode`] verbatim (e.g.
    /// `ProviderResolvedInsideWorkspace` for a workspace-local hijack
    /// attempt) when that tier is the one that produced it -- `None` when
    /// the managed tier's own presence/ownership/identity check is what
    /// failed (that tier has no `ReasonCode` of its own; see
    /// `resolve_managed_go_toolchain`'s doc comment). `P15_PROVIDER_FALLBACK_COUNT=1`:
    /// exactly the one ordered managed-to-`HOST_ONLY` tier this module's
    /// own doc comment describes, never an open-ended search.
    ProviderUnavailable(Option<ReasonCode>),
    /// The resolved `go` executable did not answer `go version` with a
    /// usable identity string. Fails closed: P15 §29 requires Evidence to
    /// carry the *exact* provider identity, so an unidentifiable toolchain
    /// is never used to produce Evidence that would have to describe it as
    /// an ambiguous "system go".
    IdentityUnavailable,
    /// The Corulix-owned Go scratch directories could not be created.
    /// Fails closed rather than letting the Go command fall back to its own
    /// defaults, which would write a build cache into `$HOME` (or fail) and
    /// a module cache outside Corulix's ownership.
    ScratchUnavailable,
    /// The `CORULIX_MANAGED` Go semantic runtime is present on disk but
    /// classified `ManagedComponentState::Corrupt`/`Incompatible` (managed-
    /// toolchain ownership/integrity hardening pass: missing/malformed/
    /// mismatched ownership record, or a tampered artifact -- see
    /// `wht_corulix_tooling::provisioning::ManagedInvalidReason`). Fails
    /// closed here, before tier 2 is ever consulted -- an invalid managed
    /// installation must never fall through to an explicit approved
    /// `HOST_ONLY` `go`, which would silently mask it.
    ManagedComponentInvalid,
}

/// A resolved, identified Go toolchain: the canonicalized, trust-verified
/// `go` executable plus its real, probed version identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGoToolchain {
    /// The canonicalized `go` executable `resolve_provider` approved.
    pub executable: PathBuf,
    /// Real `go version` output, verbatim and trimmed (e.g.
    /// `go version go1.26.6 linux/amd64`). Never a hard-coded constant and
    /// never the string "system go" -- `P15_GO_EVIDENCE_PROVIDER_IDENTITY`.
    pub version: String,
}

impl ResolvedGoToolchain {
    /// `GOROOT` for this toolchain: the parent of the `bin/` directory the
    /// resolved executable sits in. Derived from the already-canonicalized,
    /// already-approved path -- never from an ambient `GOROOT` env var of
    /// this process (which `env_clear` would discard anyway) and never
    /// guessed.
    #[must_use]
    pub fn goroot(&self) -> Option<PathBuf> {
        self.executable
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
    }
}

/// Corulix-owned scratch directories for the Go command's caches.
#[derive(Debug, Clone)]
pub struct GoScratch {
    pub build_cache: PathBuf,
    pub module_cache: PathBuf,
    pub gopath: PathBuf,
    /// A writable directory for `go build`'s output. Never inside the
    /// governed workspace -- see [`ensure_go_scratch`].
    pub build_output: PathBuf,
}

/// Deterministic, Corulix-owned scratch directory *names*, relative to
/// `managed_root`, keyed by a stable hash of `workspace_root`'s own path
/// string.
///
/// Reuses `crate::testing::test_target_dir_relative`'s exact reasoning and
/// shape (see that function's own doc comment): repeated runs against the
/// same workspace reuse their caches instead of recompiling the standard
/// library from empty every call, while two different workspaces never share
/// (and cannot collide in) the same directory. Never under `workspace_root`.
fn go_scratch_relative(workspace_root: &Path, leaf: &str) -> String {
    let mut hasher = DefaultHasher::new();
    workspace_root.hash(&mut hasher);
    let key = hasher.finish();
    format!("scratch/p15-go/{key:016x}/{leaf}")
}

/// Creates (or reuses) this workspace's Corulix-owned Go scratch
/// directories under `managed_root`.
///
/// # Why the governed workspace cannot hold these
///
/// Two independent reasons, both empirically observed:
///
/// 1. `go build` with no `-o` **writes the compiled binary into the module
///    directory** (confirmed: a `corulixfixture` executable appeared in the
///    fixture root). That is an unrequested, undisclosed mutation of content
///    a `ChangeSession` may be actively baselining, and it would trip P15's
///    own self-mutation coherence check.
/// 2. The Go build/module caches are large, long-lived, and shared across
///    runs; writing them into a governed workspace would make every
///    validation run mutate the tree it is validating.
///
/// This mirrors `crate::testing`'s `CARGO_TARGET_DIR` redirection exactly --
/// same authority (`ensure_scratch_directory`, the sole filesystem-write
/// authority for Corulix's own managed-toolchain scratch state, Rules M/G),
/// same rationale, no second mechanism.
pub fn ensure_go_scratch(
    managed_root: &Path,
    workspace_root: &Path,
) -> Result<GoScratch, GoProviderError> {
    let make = |leaf: &str| {
        wht_corulix_tooling::provisioning::ensure_scratch_directory(
            managed_root,
            &go_scratch_relative(workspace_root, leaf),
        )
        .map_err(|_| GoProviderError::ScratchUnavailable)
    };
    Ok(GoScratch {
        build_cache: make("build-cache")?,
        module_cache: make("module-cache")?,
        gopath: make("gopath")?,
        build_output: make("build-output")?,
    })
}

/// This platform's `GO_SEMANTIC_RUNTIME_*` managed-component manifest --
/// the exact same manifest [`wht_corulix_lsp::profile::LspProviderProfile::gopls_managed`]
/// already admits for `gopls`'s own semantic-runtime dependency. Reused
/// verbatim rather than duplicated: P15's own mandate forbids a second Go
/// policy/manifest table, and identical `id`/`version` across both
/// call sites is what lets [`wht_corulix_tooling::provisioning::ownership`]
/// treat "the managed Go runtime" as one component with one lifecycle,
/// shared by the LSP vertical and this build/vet/test vertical alike,
/// rather than as two independently-provisioned copies.
#[must_use]
pub(crate) fn managed_go_runtime_manifest() -> ManagedComponentManifest {
    #[cfg(target_os = "windows")]
    {
        wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_WINDOWS_X64
    }
    #[cfg(not(target_os = "windows"))]
    {
        wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64
    }
}

/// Tier 1 of [`resolve_go_toolchain`]: resolves this platform's managed Go
/// runtime, purely from local, already-verified state -- no network, no
/// re-extraction, no re-hashing (that already happened once, during
/// provisioning). `None` on *any* failure (not provisioned, provisioned but
/// not Corulix-owned, or provisioned but the binary fails a real `go
/// version` probe) so the caller falls through to the `HOST_ONLY` tier
/// rather than surfacing a managed-tier-specific error that would prevent
/// that fallback -- this function deliberately reports "not available",
/// never "broken", because from this module's precedence contract those
/// are the same outcome.
async fn resolve_managed_go_toolchain(
    managed_root: &Path,
    cancellation: &CancellationToken,
) -> Result<Option<ResolvedGoToolchain>, GoProviderError> {
    let manifest = managed_go_runtime_manifest();
    let (state, executable, _reason) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component_detailed(
            managed_root,
            &manifest,
        );
    match state {
        ManagedComponentState::Available => {}
        // Present but invalid/tampered: fail closed, never fall through to
        // tier 2 (managed-toolchain ownership/integrity hardening pass).
        ManagedComponentState::Corrupt | ManagedComponentState::Incompatible => {
            return Err(GoProviderError::ManagedComponentInvalid);
        }
        // Genuinely not (yet) provisioned (or any future variant this
        // crate does not yet know about -- `ManagedComponentState` is
        // `#[non_exhaustive]`): a clean "not available", the caller falls
        // through to tier 2.
        ManagedComponentState::NotProvisioned | ManagedComponentState::Provisioning | _ => {
            return Ok(None);
        }
    }
    let Some(executable) = executable else {
        return Ok(None);
    };
    // Real identity, independently re-probed -- never the manifest's own
    // `version` string trusted as this toolchain's reported identity.
    // Mirrors tier 2's own `probe_go_version` call exactly, and mirrors
    // `ResolvedGoToolchain::version`'s own doc comment
    // ("never a hard-coded constant").
    let Some(version) = probe_go_version(&executable, cancellation).await else {
        return Ok(None);
    };
    Ok(Some(ResolvedGoToolchain {
        executable,
        version,
    }))
}

/// Resolves the real `go` executable for `category`, then probes its real
/// identity. Two ordered tiers -- see this module's own doc comment for the
/// full rationale:
///
/// 1. `CORULIX_MANAGED` (`resolve_managed_go_toolchain`), tried first.
/// 2. `HOST_ONLY`/approved-directory, through the Phase-6 secure provider
///    resolver (unchanged from before this pass) -- tried only when tier 1
///    did not resolve.
///
/// `category` is the [`ProviderCategory`] the *operation* needs (see this
/// module's own category-mapping table): `TypecheckBuild` for `go build`,
/// `Linter` for `go vet`, `TestRunner` for `go test`. Resolving per-category
/// rather than once-for-all is deliberate -- it is what lets a host
/// legitimately grant `go build` authority while withholding `go test`
/// authority, and it is the same category granularity
/// `wht_corulix_config::EffectiveConfig::category_enabled` already enforces
/// for tier 2. Tier 1 does not vary by category: a provisioned managed
/// runtime is either genuinely owned and identity-verified or it is not,
/// independent of which Go subcommand a caller intends to run with it --
/// `EffectiveConfig::category_enabled` still gates *use*, this function
/// only resolves *identity*.
pub async fn resolve_go_toolchain(
    managed_root: &Path,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    category: ProviderCategory,
    cancellation: &CancellationToken,
) -> Result<ResolvedGoToolchain, GoProviderError> {
    if let Some(managed) = resolve_managed_go_toolchain(managed_root, cancellation).await? {
        return Ok(managed);
    }

    let resolution =
        wht_corulix_config::resolve_provider(effective, workspace_root, category, GO_EXECUTABLE)
            .await;
    if resolution.availability != wht_corulix_core::ProviderAvailability::Available {
        return Err(GoProviderError::ProviderUnavailable(resolution.reason));
    }
    let Some(executable) = resolution.resolved_path else {
        return Err(GoProviderError::ProviderUnavailable(resolution.reason));
    };

    let version = probe_go_version(&executable, cancellation)
        .await
        .ok_or(GoProviderError::IdentityUnavailable)?;
    Ok(ResolvedGoToolchain {
        executable,
        version,
    })
}

/// Runs `go version` through the controlled process runtime and returns its
/// trimmed stdout. `None` on any failure -- the caller fails closed with
/// [`GoProviderError::IdentityUnavailable`] rather than fabricating an
/// identity.
///
/// `ExecutionClass::ControlledExternalTool`, not
/// `TrustedWorkspaceExecution`: `go version` reads no repository content,
/// runs in a temporary directory rather than the workspace, and cannot
/// execute repository-authored code -- so it legitimately needs no trust
/// grant. This is the one Go invocation in this crate that is genuinely
/// read-only with respect to the workspace.
pub async fn probe_go_version(
    executable: &Path,
    cancellation: &CancellationToken,
) -> Option<String> {
    let goroot = executable.parent().and_then(Path::parent)?;
    let spec = ProcessSpec {
        executable: executable.to_path_buf(),
        arguments: vec!["version".to_string()],
        environment: EnvironmentPolicy::empty()
            .with_var("GOROOT", goroot.to_string_lossy().into_owned()),
        working_directory: std::env::temp_dir(),
        limits: ProcessLimits::default(),
        timeout: std::time::Duration::from_secs(10),
        execution_class: ExecutionClass::ControlledExternalTool,
        argv0: None,
    };
    let outcome = wht_corulix_tooling::execute(&spec, cancellation).await;
    if !matches!(outcome.termination, TerminationReason::Exited { code: 0 }) {
        return None;
    }
    let text = String::from_utf8(outcome.stdout.bytes).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Builds the complete, allowlist-only child environment for a real `go`
/// invocation. Every variable is load-bearing; nothing is inherited.
///
/// | Variable | Why it is set |
/// |---|---|
/// | `GOROOT` | Derived from the resolved, approved executable's own location -- how the Go command finds its own standard library and internal tools. |
/// | `PATH` | The resolved toolchain's own `bin/` directory **only**. No system-directory suffix, no ambient fallthrough (`P15_AMBIENT_PATH_AUTHORITY=NO`). |
/// | `GOCACHE` | Corulix-owned build cache. **Mandatory**: with the environment cleared, the Go command otherwise tries `$HOME/.cache/go-build` and fails outright (empirically confirmed). |
/// | `GOMODCACHE`, `GOPATH` | Corulix-owned, so no host-wide Go state is read or written. |
/// | `GOPROXY=off` | No module proxy is ever contacted. |
/// | `GOFLAGS=-mod=readonly` | The Go command may not rewrite the repository's own `go.mod`/`go.sum`. Deliberately **not** `-mod=mod`, which would permit exactly that mutation. |
/// | `GOTOOLCHAIN=local` | **Load-bearing for `P15_AUTO_INSTALL_EXTERNAL_TOOLING=NO`.** Empirically confirmed: a repository-authored `go.mod` carrying `toolchain go1.99.0` makes the Go command *download and execute a different toolchain* (`go: downloading go1.99.0`); with `GOTOOLCHAIN=local` the same fixture builds with the resolved toolchain and no download is attempted. |
/// | `GOWORK=off` | A repository-authored `go.work` cannot silently widen the module set under validation beyond the governed root. |
/// | `CGO_ENABLED=0` | Closes the strongest repository-authored-code-execution vector: with a C compiler reachable, `go build` compiles and links repository-authored C under repository-controlled `#cgo CFLAGS` (empirically confirmed). See the note below. |
/// | `GOFIPS140=off`, `GOEXPERIMENT` unset | No experiment/toolchain mode is inherited from the host. |
///
/// # `CGO_ENABLED=0` -- a real narrowing, disclosed
///
/// This is a genuine hardening, not a convenience: it makes the cgo
/// execution vector unreachable rather than merely unlikely (under this
/// environment `PATH` holds no C compiler, so `CGO_ENABLED` would resolve to
/// `0` anyway -- but that is an environment coincidence, and this makes it a
/// stated policy). The honest cost: **Corulix's Go build/vet/test validation
/// does not cover a repository's cgo code paths.** A cgo-dependent package
/// will report a real, authoritative failure rather than a silent pass --
/// which is the fail-closed direction -- but a caller must not read a clean
/// Go validation as evidence about cgo content.
///
/// Note that `CGO_ENABLED=0` does **not** change the execution
/// classification. `P15_GO_BUILD_EXECUTION_CLASS`/
/// `P15_GO_VET_EXECUTION_CLASS`/`P15_GO_TEST_EXECUTION_CLASS` are all
/// `TRUSTED_WORKSPACE_EXECUTION` because the classification describes what
/// the operation *is authorized to do*, not what one environment flag
/// happens to prevent today.
#[must_use]
pub fn go_environment(toolchain: &ResolvedGoToolchain, scratch: &GoScratch) -> EnvironmentPolicy {
    let bin_dir = toolchain
        .executable
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let goroot = toolchain.goroot().unwrap_or_default();
    EnvironmentPolicy::empty()
        .with_var("GOROOT", goroot.to_string_lossy().into_owned())
        .with_var("PATH", bin_dir.to_string_lossy().into_owned())
        .with_var(
            "GOCACHE",
            scratch.build_cache.to_string_lossy().into_owned(),
        )
        .with_var(
            "GOMODCACHE",
            scratch.module_cache.to_string_lossy().into_owned(),
        )
        .with_var("GOPATH", scratch.gopath.to_string_lossy().into_owned())
        .with_var("GOPROXY", "off")
        .with_var("GOFLAGS", "-mod=readonly")
        .with_var("GOTOOLCHAIN", "local")
        .with_var("GOWORK", "off")
        .with_var("CGO_ENABLED", "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scratch naming: deterministic per workspace, never colliding across
    /// two distinct roots, always Corulix-owned (never under the workspace),
    /// and always relative so it can only be joined onto a Corulix root.
    #[test]
    fn go_scratch_is_deterministic_corulix_owned_and_workspace_distinct() {
        let a = go_scratch_relative(Path::new("/home/user/ws-a"), "build-cache");
        let b = go_scratch_relative(Path::new("/home/user/ws-b"), "build-cache");
        let a_again = go_scratch_relative(Path::new("/home/user/ws-a"), "build-cache");
        assert_eq!(a, a_again);
        assert_ne!(a, b);
        assert!(!Path::new(&a).is_absolute());
        assert!(a.starts_with("scratch/p15-go/"));
    }

    /// Distinct leaves never collide within one workspace.
    #[test]
    fn go_scratch_leaves_are_distinct() {
        let root = Path::new("/home/user/ws");
        let names = [
            go_scratch_relative(root, "build-cache"),
            go_scratch_relative(root, "module-cache"),
            go_scratch_relative(root, "gopath"),
            go_scratch_relative(root, "build-output"),
        ];
        let mut unique = names.to_vec();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), names.len());
    }

    fn sample_toolchain() -> ResolvedGoToolchain {
        ResolvedGoToolchain {
            executable: PathBuf::from("/usr/local/go/bin/go"),
            version: "go version go1.26.6 linux/amd64".to_string(),
        }
    }

    fn sample_scratch() -> GoScratch {
        GoScratch {
            build_cache: PathBuf::from("/managed/scratch/build-cache"),
            module_cache: PathBuf::from("/managed/scratch/module-cache"),
            gopath: PathBuf::from("/managed/scratch/gopath"),
            build_output: PathBuf::from("/managed/scratch/build-output"),
        }
    }

    #[test]
    fn goroot_is_derived_from_the_resolved_executable() {
        assert_eq!(
            sample_toolchain().goroot(),
            Some(PathBuf::from("/usr/local/go"))
        );
    }

    /// Every security-relevant variable this module's own doc table claims
    /// is set really is set, with the exact value claimed. Guards against a
    /// future edit quietly dropping `GOTOOLCHAIN=local` (which would re-open
    /// the toolchain-download vector) or relaxing `GOFLAGS` to `-mod=mod`
    /// (which would let the Go command rewrite the repository's `go.mod`).
    #[test]
    fn go_environment_sets_every_load_bearing_variable() {
        let environment = go_environment(&sample_toolchain(), &sample_scratch());
        let rendered = format!("{environment:?}");
        for (key, value) in [
            ("GOPROXY", "off"),
            ("GOFLAGS", "-mod=readonly"),
            ("GOTOOLCHAIN", "local"),
            ("GOWORK", "off"),
            ("CGO_ENABLED", "0"),
        ] {
            assert!(
                rendered.contains(key) && rendered.contains(value),
                "{key}={value} must be set: {rendered}"
            );
        }
        // The build cache is mandatory: without it the Go command fails
        // outright under a cleared environment.
        assert!(rendered.contains("GOCACHE"));
        // PATH is the toolchain's own bin/ only -- no system suffix.
        assert!(rendered.contains("/usr/local/go/bin"));
        assert!(
            !rendered.contains("/usr/bin") && !rendered.contains(":/bin"),
            "PATH must carry no ambient/system directory suffix: {rendered}"
        );
    }

    /// `-mod=mod` must never appear: it would authorize the Go command to
    /// rewrite the repository's own `go.mod`/`go.sum` as a side effect of a
    /// validation run.
    #[test]
    fn go_environment_never_permits_go_mod_mutation() {
        let rendered = format!(
            "{:?}",
            go_environment(&sample_toolchain(), &sample_scratch())
        );
        assert!(!rendered.contains("-mod=mod"));
    }

    /// Stage A (P17-W Master Closure Order): this crate's managed Go
    /// runtime selection must be the exact same manifest identity
    /// (`id`/`version`) `wht_corulix_lsp` already admits for `gopls`'s own
    /// dependency -- never a silently-forked duplicate that could drift out
    /// of sync and leave two "managed Go runtime" records under one
    /// `managed_root`. Also pins the platform this build's own manifest
    /// selection resolves to, so a future edit that flips the `cfg` the
    /// wrong way fails a fast unit test rather than only a slow, real
    /// Windows-VM E2E run.
    #[test]
    fn managed_go_runtime_manifest_matches_the_lsp_crates_own_identity_for_this_platform() {
        let manifest = managed_go_runtime_manifest();
        assert_eq!(manifest.id.0, "go-semantic-runtime");
        #[cfg(target_os = "windows")]
        {
            let reference = wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_WINDOWS_X64;
            assert_eq!(manifest.platform, "windows");
            assert_eq!(manifest.version, reference.version);
            assert_eq!(manifest.platform, reference.platform);
            assert_eq!(manifest.architecture, reference.architecture);
            assert_eq!(
                manifest.source.expected_sha256_hex,
                reference.source.expected_sha256_hex
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            let reference = wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64;
            assert_eq!(manifest.platform, "linux");
            assert_eq!(manifest.version, reference.version);
            assert_eq!(manifest.platform, reference.platform);
            assert_eq!(manifest.architecture, reference.architecture);
            assert_eq!(
                manifest.source.expected_sha256_hex,
                reference.source.expected_sha256_hex
            );
        }
    }

    /// Stage A negative proof, no real toolchain required: an empty
    /// `managed_root` (nothing ever provisioned into it) must make
    /// [`resolve_managed_go_toolchain`] report `None` -- not an error, a
    /// clean "not available" that this module's own precedence contract
    /// requires so the caller falls through to tier 2. Confirms tier 1
    /// never fabricates availability from a bare, empty directory.
    #[tokio::test]
    async fn managed_tier_reports_unavailable_against_an_empty_managed_root() {
        let temp =
            std::env::temp_dir().join(format!("corulix-go-providers-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp);
        let cancellation = CancellationToken::new();
        let resolved = resolve_managed_go_toolchain(&temp, &cancellation).await;
        assert!(
            matches!(resolved, Ok(None)),
            "an empty managed_root must never resolve a managed Go toolchain or error: {resolved:?}"
        );
        let _ = std::fs::remove_dir_all(&temp);
    }
}
