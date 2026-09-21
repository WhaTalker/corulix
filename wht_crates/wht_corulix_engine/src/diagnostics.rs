// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P11: `CORULIX_MANAGED` `cargo check` (`ProviderCategory::TypecheckBuild`)
//! and clippy (`ProviderCategory::Linter`) invocation, composing real
//! Evidence for `GateId::Diagnostics`.
//!
//! # No system fallback (`P11_CARGO_PROVIDER_AUTHORITY=CORULIX_MANAGED`)
//!
//! Unlike `wht_corulix_formatter::managed::resolve_rustfmt` (which falls
//! back to a `HOST_ONLY`/system `rustfmt` when the managed component is
//! unprovisioned), this module has **no such fallback** -- it mirrors
//! `wht_corulix_lsp::profile::LspProviderProfile::managed_rust_semantic_runtime`'s
//! own no-fallback contract instead. A caller sees
//! [`RustValidatorError::ManagedRuntimeUnavailable`] rather than this module
//! silently reaching for an ambient system `cargo`/`rustc`/`rustup`; there
//! is no code path here that resolves a provider from `PATH`, a workspace
//! directory, or any `wht_corulix_config::resolve_provider` call --
//! `P11_SYSTEM_CARGO_SELECTION_COUNT=0` is a structural guarantee, not a
//! runtime check.
//!
//! # One managed runtime, both validators
//!
//! P11 merged clippy (`clippy-driver` + `cargo-clippy`) as a fifth
//! `additional_sources` entry onto the *same*
//! [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64`]
//! manifest `cargo`/`rustc`/`rust-std`/`rust-src` already share, rather than
//! a second, independently-versioned manifest -- confirmed via `ldd` against
//! the real extracted `clippy-driver` binary during P11's research gate:
//! it links `librustc_driver-28a98848f7a7c026.so`, the exact same
//! hash-named library the existing four-artifact manifest's own doc comment
//! already cites for managed `rustfmt`'s linkage, proving this is the same
//! build, not a coincidentally-matching version. One resolution therefore
//! backs both [`run_cargo_check`] and [`run_clippy`]: `RUST_VERSION_COMPATIBILITY=PASS`
//! by construction, never four artifacts and a fifth independently paired
//! after the fact.
//!
//! # Execution class (P11-R1 correction)
//!
//! Both validators run as [`ExecutionClass::TrustedWorkspaceExecution`],
//! **not** [`ExecutionClass::ControlledExternalTool`]. P11's original pass
//! classified them as `ControlledExternalTool` by analogy with
//! rust-analyzer's own stance -- that analogy was wrong: rust-analyzer's
//! `cargo.buildScripts.enable`/`procMacro.enable` are unconditionally
//! *disabled*, which is precisely what makes `ControlledExternalTool` a
//! true label for it. This module's `cargo check`/`cargo clippy` invocation
//! carries no equivalent flag and genuinely executes a workspace's own
//! `build.rs` and proc macros -- real repository-authored code execution.
//! Empirically confirmed during P11-R1's research gate: a real build-script
//! marker file was observed written to disk by a real `cargo check` run
//! against a controlled fixture (see `real_p11_r1_trust_enforcement_e2e.rs`).
//! `ExecutionClass::TrustedWorkspaceExecution` is therefore the honest
//! classification, matching Core's own definition
//! (`wht_corulix_core::execution`) of the class that covers "build/test
//! commands that can execute repository-authored code".
//!
//! **`PROVIDER_EXECUTABLE_AUTHORITY != WORKSPACE_EXECUTION_TRUST_CLASS`**:
//! `cargo`/`rustc`/`clippy` remain fully `CORULIX_MANAGED` (resolved by
//! explicit path under `resolve_runtime`, never PATH search) regardless of
//! this reclassification -- trust governs whether the *operation* may run
//! repository-authored code at all, not which binary Corulix trusts to run
//! it. See `run_validator` for the enforcement point: `wht_corulix_config::
//! EffectiveConfig::is_execution_class_allowed(TrustedWorkspaceExecution)` is
//! checked **before** `ProcessSpec` construction -- an untrusted workspace
//! never reaches a `cargo`/`clippy` process spawn at all
//! (`P11_UNTRUSTED_CARGO_PROCESS_SPAWN_COUNT=0`,
//! `P11_UNTRUSTED_CLIPPY_PROCESS_SPAWN_COUNT=0`). This check does not live
//! inside `wht_corulix_tooling::execute` -- that crate's own doc comment
//! states it "never decides policy" (Rule H); the trust gate is Engine-side,
//! here.
//!
//! # System linker dependency (disclosed on Unix; closed on Windows -- P18)
//!
//! On Unix, `managed_environment` appends the fixed system directories
//! `/usr/bin` and `/bin` to `PATH` *after* the managed `bin/` directory --
//! **only** because compiling a workspace's own `build.rs` (a real, separate
//! executable cargo must link before it can run) requires a system linker
//! (`cc`/`ld`) the managed runtime does not bundle (same
//! `SYSTEM_LINKER_REQUIRED_NOT_MANAGED` fact already disclosed below for
//! `cargo build` -- P11's original pass under-scoped that disclosure to
//! `cargo build` alone; empirically, `cargo check` needs it too whenever the
//! checked crate has a build script, since cargo always runs `build.rs`
//! before checking, never merely reading its source). This is a *fixed,
//! disclosed, narrow* addition -- never derived from, prepended to, or
//! merged with this process's own ambient `PATH` -- and it cannot itself
//! select a system `cargo`/`rustc`/`clippy`: those three remain resolved
//! exclusively via `install_dir.join(...)` explicit paths, never PATH
//! lookup, so `P11_SYSTEM_CARGO_SELECTION_COUNT=0`/
//! `P11_SYSTEM_RUSTC_SELECTION_COUNT=0`/`P11_SYSTEM_CLIPPY_SELECTION_COUNT=0`
//! remain structural guarantees unaffected by this addition.
//!
//! P18 closes the Windows equivalent of this gap for `run_cargo_check`
//! specifically: see `resolve_diagnostics_runtime` and
//! `diagnostics_link_environment` for the fully self-contained,
//! `CORULIX_MANAGED` GNU-hosted/MSVC-target-checked replacement --
//! `SYSTEM_LINKER_SEARCH_DIRS` (below) is never consulted on
//! `cfg(target_os = "windows")` and Windows's own `managed_environment`
//! caller path is not used by [`run_cargo_check`] at all on that platform.
//!
//! # `cargo build` is out of scope for this phase
//!
//! `P11_CARGO_BUILD_LINKER_AUTHORITY=SYSTEM_LINKER_REQUIRED_NOT_MANAGED`:
//! the managed runtime bundles `rustc`/`cargo`/`rust-std`/`rust-src` (plus
//! clippy) but no `cc`/`ld` -- linking a real binary on Linux still requires
//! a system linker. No policy entry in `crate::policy` requires
//! `cargo build` today, and this phase deliberately does not add one: doing
//! so would create a required capability this module cannot satisfy from
//! `CORULIX_MANAGED` alone, manufacturing a policy-level blocker rather than
//! disclosing a real one. `cargo check` (no linking, full type/borrow/trait
//! authority) is authoritative for `ProviderCategory::TypecheckBuild`
//! instead.

use std::path::{Path, PathBuf};

use wht_corulix_core::{CorulixError, CorulixResult, ExecutionClass};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
#[cfg(not(unix))]
use wht_corulix_tooling::{BoundedOutput, ExecutionOutcome};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, TerminationReason};

/// Bounded well below [`wht_corulix_core::EVIDENCE_RESULT_SUMMARY_MAX_BYTES`]
/// so the summary construction in [`RustDiagnosticsOutcome::result_summary`]
/// can never itself exceed the Evidence contract's own hard cap.
const MAX_SUMMARY_BYTES: usize = 3800;

/// Real, bounded process limits for `cargo check`/`cargo clippy`: both can
/// legitimately emit megabytes of JSON diagnostic output on a large crate.
const VALIDATOR_LIMITS: ProcessLimits = ProcessLimits {
    max_stdout_bytes: 16 * 1024 * 1024,
    max_stderr_bytes: 4 * 1024 * 1024,
};

const VALIDATOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Why a managed Rust validator (`cargo check`/clippy) could not produce a
/// result. Never a free-form string -- a caller matches on this to decide
/// whether the *tool* failed to run (fail closed, no Evidence recorded) or
/// the tool ran and reported real findings (a [`RustDiagnosticsOutcome`],
/// handled by the caller separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustValidatorError {
    /// The managed `rust-semantic-runtime` component (which now also
    /// carries clippy) is not `Available` under the supplied managed root.
    /// There is no fallback path from here -- see this module's own doc
    /// comment.
    ManagedRuntimeUnavailable,
    /// The merged runtime component itself is `Available`, but the specific
    /// `bin/cargo-clippy`/`bin/clippy-driver` binaries are missing from its
    /// install directory. Distinct from [`Self::ManagedRuntimeUnavailable`]
    /// on purpose: P11-R1's research gate proved empirically that cargo's
    /// own built-in `clippy` subcommand does **not** fail loudly when
    /// `clippy-driver` is unresolvable -- it silently falls back to a plain
    /// `cargo check`-equivalent compile (exit `0`, no lint diagnostics, no
    /// warning of any kind). Relying on cargo's own exit code/output here
    /// would produce exactly the false-clean-evidence defect class P11-R1
    /// exists to close, so this module verifies both binaries exist on disk
    /// *before* ever invoking `cargo clippy` at all.
    ManagedClippyUnavailable,
    /// The `cargo-clippy`/`clippy-driver` binaries are present, but the
    /// segment-aware installed-payload digest recorded for them (Managed
    /// Installed-Payload Integrity pass, `"clippy"` segment) does not
    /// match -- a present-but-tampered clippy must never be treated as
    /// merely unavailable, and must never execute
    /// (`OPTIONAL_PRESENT_TAMPERED_EXECUTABLE_ALLOWED=NO`). Distinct from
    /// [`Self::ManagedClippyUnavailable`] (files simply absent) so a caller
    /// can tell "not installed" apart from "installed but corrupted".
    ManagedClippyTampered,
    /// This operation is [`ExecutionClass::TrustedWorkspaceExecution`] (it
    /// can execute the workspace's own `build.rs`/proc macros), and the
    /// effective configuration does not currently authorize that class --
    /// see [`wht_corulix_config::EffectiveConfig::is_execution_class_allowed`].
    /// No process is spawned when this is returned
    /// (`P11_UNTRUSTED_CARGO_PROCESS_SPAWN_COUNT=0`/
    /// `P11_UNTRUSTED_CLIPPY_PROCESS_SPAWN_COUNT=0`) -- this check runs
    /// before [`ProcessSpec`] is even constructed.
    WorkspaceExecutionNotAuthorized,
    /// The validator process exited with a non-zero code, but its own
    /// `--message-format=json` stream carried **zero** `compiler-message`
    /// entries -- e.g. a malformed `Cargo.toml`, a missing manifest, or any
    /// other invocation-level failure that occurs before real compilation
    /// (and therefore before any real diagnostic) begins. Reported as a
    /// distinct, fail-closed error rather than folded into a silently
    /// "clean" [`RustDiagnosticsOutcome`] with `error_count: 0` -- a
    /// non-zero exit with no findings is never legitimate evidence of a
    /// clean pass, only of an unexamined one.
    ValidatorInvocationFailed,
    /// The child process could not be spawned at all.
    SpawnFailed,
    /// The configured timeout elapsed before the validator exited.
    TimedOut,
    /// The caller's [`wht_corulix_core::CancellationToken`] fired before
    /// the validator exited.
    Cancelled,
    /// Termination of a timed-out/cancelled process tree could not be
    /// confirmed to have succeeded.
    TerminationFailed,
    /// The validator exited with a signal rather than a normal exit code.
    Signaled,
}

/// The real, structured outcome of one `cargo check`/`cargo clippy`
/// invocation that actually ran to completion (any non-`Exited`
/// [`TerminationReason`] is a [`RustValidatorError`] instead, never folded
/// into this type with a zero-finding default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustDiagnosticsOutcome {
    pub error_count: u32,
    pub warning_count: u32,
    /// `true` if cargo's own JSON stream, or this module's own bounded
    /// summary construction, dropped content. Always propagated to
    /// `Evidence::truncated` by the caller -- a truncated result is never
    /// silently presented as complete.
    pub truncated: bool,
    /// A bounded, human-readable summary (first findings' rendered text),
    /// always `<= ``MAX_SUMMARY_BYTES`` bytes -- safe to pass directly
    /// into [`wht_corulix_core::EvidenceResultSummary::try_from`].
    pub summary: String,
    /// The resolved managed component's own pinned version string (e.g.
    /// `"1.98.0"`) -- the real `provider_version` for
    /// [`wht_corulix_core::EvidenceProvenance`], never a caller-supplied or
    /// guessed value.
    pub provider_version: String,
}

impl RustDiagnosticsOutcome {
    /// Whether this outcome represents a clean pass (no errors). A clean
    /// clippy run may still have `warning_count > 0` -- clippy findings are
    /// almost always emitted as `warning`, not `error`; only `error_count`
    /// determines gate failure, matching this phase's own `SupportingOnly`/
    /// `Authoritative` split (a `TypecheckBuild` finding blocks, a `Linter`
    /// finding informs).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.error_count == 0
    }
}

/// Resolves the merged managed Rust semantic runtime's install directory,
/// verifying it is genuinely owned-`Available` under `managed_root` --
/// never merely filesystem-present (see
/// [`provisioning::resolve_owned_managed_component`]'s own doc comment for
/// why the ownership check matters). Both [`run_cargo_check`] and
/// [`run_clippy`] call this exact function; there is no second, divergent
/// resolution path for either.
pub(crate) fn resolve_runtime(managed_root: &Path) -> Result<PathBuf, RustValidatorError> {
    let manifest = rust_semantic_runtime_host_native();
    let (state, _binary) = provisioning::resolve_owned_managed_component(managed_root, &manifest);
    if state != ManagedComponentState::Available {
        return Err(RustValidatorError::ManagedRuntimeUnavailable);
    }
    Ok(provisioning::component_install_dir(managed_root, &manifest))
}

/// This host's own real `rust-semantic-runtime` manifest -- a `#[cfg]`-gated
/// alias (never a runtime `if cfg!(...)` branch, so a build for the "wrong"
/// platform cannot even compile a path that resolves the other platform's
/// manifest), mirroring
/// [`wht_corulix_formatter::managed::rust_semantic_runtime_host_native`]'s
/// own precedent exactly. Added alongside this phase's P12 Windows
/// trusted-execution work: before this fix, [`resolve_runtime`] (and
/// therefore every one of its callers, including
/// [`crate::testing::run_cargo_test_with_limits`]) resolved
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64`]
/// unconditionally regardless of host -- harmless on Linux (the only
/// platform this resolution could ever reach `Available` on before this
/// fix), but the exact hardcoded-to-Linux defect class
/// `RUST_SEMANTIC_RUNTIME_HOST_NATIVE`-style aliases already exist to close
/// elsewhere in this workspace. `crate::testing`'s own P12-R2 GNU-link-runtime
/// resolution stays a separate, distinct fix (see that module's own
/// `resolve_link_runtime`); this one closes the shared Rust-semantic-runtime
/// lookup both `crate::diagnostics` (`cargo check`/`cargo clippy`, unchanged
/// in scope/behavior on Windows this phase) and `crate::testing`
/// (`cargo test`, the actual P12 Windows target) depend on.
pub(crate) fn rust_semantic_runtime_host_native()
-> wht_corulix_tooling::provisioning::ManagedComponentManifest {
    #[cfg(target_os = "windows")]
    {
        wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64
    }
    #[cfg(not(target_os = "windows"))]
    {
        wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64
    }
}

/// Verifies the specific `cargo-clippy`/`clippy-driver` binaries exist
/// (independent of [`resolve_runtime`]'s whole-component `Available` check
/// -- required because `ManagedComponentState` is atomic across the merged
/// manifest's five sources (cargo/rustc/rust-std/rust-src/clippy): there is
/// no provisioning state where the runtime is `Available` but clippy
/// specifically is absent) **and**, when both are present, that clippy's own
/// recorded installed-payload digest -- the `"clippy"`
/// [`provisioning::OptionalSegment`], Managed Installed-Payload Integrity
/// pass -- has not been tampered with
/// (`P11_R1_DEGRADATION_CONTRACT=PRESERVE`: clippy absence still degrades
/// cleanly; clippy *tamper* must fail closed, never silently execute).
///
/// A caller that wants to exercise "clippy unavailable, cargo/rustc
/// unaffected" cannot do so via provisioning state alone -- only by removing
/// these two files from an isolated copy of an install directory (never the
/// canonical/shared managed root) -- and the file-presence half of this
/// function is what turns that file-level absence into a typed, pre-spawn
/// [`RustValidatorError::ManagedClippyUnavailable`] rather than letting
/// cargo's own silent clippy-driver fallback (see
/// [`RustValidatorError::ManagedClippyUnavailable`]'s own doc comment)
/// produce a falsely-clean result.
pub(crate) fn resolve_clippy_binaries(
    managed_root: &Path,
    manifest: &provisioning::ManagedComponentManifest,
) -> Result<(), RustValidatorError> {
    let install_dir = provisioning::component_install_dir(managed_root, manifest);
    let bin_dir = install_dir.join("bin");
    if !(bin_dir.join("cargo-clippy").is_file() && bin_dir.join("clippy-driver").is_file()) {
        return Err(RustValidatorError::ManagedClippyUnavailable);
    }
    match provisioning::resolve_optional_segment(managed_root, manifest, "clippy") {
        provisioning::SegmentState::Tampered => Err(RustValidatorError::ManagedClippyTampered),
        // `Available`/`Absent`, and any future `#[non_exhaustive]` addition:
        // only a confirmed `Tampered` verdict fails closed here.
        _ => Ok(()),
    }
}

/// The managed runtime's own pinned version string, exposed for
/// `EvidenceProvenance::provider_version` construction without a second,
/// independent source of truth for it.
#[must_use]
pub fn managed_runtime_version() -> &'static str {
    rust_semantic_runtime_host_native().version
}

/// Fixed, disclosed system directories appended to `PATH` after the managed
/// `bin/` directory, solely so cargo can locate a system linker (`cc`/`ld`)
/// when a checked crate has a `build.rs` -- see this module's own top-level
/// doc comment ("System linker dependency"). Never derived from this
/// process's own ambient `PATH`; always exactly these two fixed entries.
pub(crate) const SYSTEM_LINKER_SEARCH_DIRS: &str = "/usr/bin:/bin";

/// Builds the environment every managed validator invocation shares:
/// `LD_LIBRARY_PATH` for `librustc_driver`/`libLLVM` (mirroring
/// `wht_corulix_formatter::managed::resolve_rustfmt`'s own precedent
/// exactly -- same runtime, same requirement), `PATH` set to the merged
/// `bin/` directory followed by [`SYSTEM_LINKER_SEARCH_DIRS`] (so `cargo`'s
/// own subcommand discovery finds `cargo-clippy` next to itself first, and
/// a system `cc`/`ld` is reachable only for build-script linking -- never
/// ambient, never process-`PATH`-derived), `CARGO`/`RUSTC` pointed at the
/// merged binaries explicitly, and `CARGO_NET_OFFLINE=true` (this phase's
/// admitted use is validating already-resolved/vendored dependency graphs,
/// not resolving new ones -- see
/// [`wht_corulix_lsp::profile::LspProviderProfile::rust_analyzer_managed`]'s
/// own identical `CARGO_NET_OFFLINE` rationale).
pub(crate) fn managed_environment(install_dir: &Path) -> EnvironmentPolicy {
    let bin_dir = install_dir.join("bin");
    let lib_dir = install_dir.join("lib");
    let path = format!("{}:{SYSTEM_LINKER_SEARCH_DIRS}", bin_dir.display());
    EnvironmentPolicy::empty()
        .with_var("LD_LIBRARY_PATH", lib_dir.to_string_lossy().into_owned())
        .with_var("PATH", path)
        .with_var(
            "CARGO",
            bin_dir.join("cargo").to_string_lossy().into_owned(),
        )
        .with_var(
            "RUSTC",
            bin_dir.join("rustc").to_string_lossy().into_owned(),
        )
        .with_var("CARGO_NET_OFFLINE", "true")
}

/// One line of cargo's `--message-format=json` stream this module actually
/// consumes -- only `compiler-message` entries carry a real
/// error/warning/note finding; every other `reason` (`build-script-executed`,
/// `compiler-artifact`, ...) is silently skipped, matching cargo's own
/// documented message schema rather than guessing at undocumented fields.
#[derive(serde::Deserialize)]
struct CargoMessageLine {
    reason: Option<String>,
    message: Option<CargoDiagnosticMessage>,
}

#[derive(serde::Deserialize)]
struct CargoDiagnosticMessage {
    level: Option<String>,
    rendered: Option<String>,
}

/// Parses a real `cargo check`/`cargo clippy` `--message-format=json`
/// stdout stream (newline-delimited JSON, one object per line -- a
/// malformed/non-JSON line is silently skipped rather than aborting the
/// whole parse, since cargo itself can interleave non-JSON diagnostic
/// output on some configurations) into error/warning counts and a bounded
/// summary of the first findings' rendered text.
pub(crate) fn parse_cargo_json_stream(
    stdout: &[u8],
    stdout_truncated: bool,
) -> RustDiagnosticsOutcome {
    let text = String::from_utf8_lossy(stdout);
    let mut error_count = 0u32;
    let mut warning_count = 0u32;
    let mut summary = String::new();
    let mut summary_truncated = false;

    for line in text.lines() {
        let Ok(parsed) = serde_json::from_str::<CargoMessageLine>(line) else {
            continue;
        };
        if parsed.reason.as_deref() != Some("compiler-message") {
            continue;
        }
        let Some(message) = parsed.message else {
            continue;
        };
        match message.level.as_deref() {
            Some("error") => error_count = error_count.saturating_add(1),
            Some("warning") => warning_count = warning_count.saturating_add(1),
            _ => continue,
        }
        if let Some(rendered) = message.rendered {
            if summary.len() + rendered.len() > MAX_SUMMARY_BYTES {
                summary_truncated = true;
                continue;
            }
            summary.push_str(&rendered);
        }
    }

    RustDiagnosticsOutcome {
        error_count,
        warning_count,
        truncated: stdout_truncated || summary_truncated,
        summary,
        provider_version: managed_runtime_version().to_string(),
    }
}

/// The one, load-bearing trust enforcement point for both validators:
/// checked **before** [`ProcessSpec`] is constructed, so an unauthorized
/// call never reaches `wht_corulix_tooling::execute` at all -- no process is
/// spawned, matching `wht_corulix_tooling`'s own stance that it "never
/// decides policy" (Rule H). Both [`run_cargo_check`] and [`run_clippy`] are
/// [`ExecutionClass::TrustedWorkspaceExecution`] (see this module's own doc
/// comment), so both call this before anything else.
pub(crate) fn authorize_trusted_execution(
    effective: &wht_corulix_config::EffectiveConfig,
) -> Result<(), RustValidatorError> {
    if effective.is_execution_class_allowed(ExecutionClass::TrustedWorkspaceExecution) {
        Ok(())
    } else {
        Err(RustValidatorError::WorkspaceExecutionNotAuthorized)
    }
}

/// The one process-spawn/outcome-classification body shared by every
/// managed-validator invocation ([`run_cargo_check`]'s non-Windows path,
/// [`run_cargo_check`]'s P18 Windows path, and [`run_clippy`]) -- extracted
/// from the pre-P18 `run_validator` so the P18 Windows path (a genuinely
/// different runtime resolution and environment, see
/// [`resolve_diagnostics_runtime`]/[`diagnostics_link_environment`]) does not
/// duplicate this classification logic a second time
/// (`P18_DIAGNOSTICS_VALIDATOR_OUTCOME_LOGIC_AUTHORITY_COUNT=1`).
async fn execute_validator_process(
    executable: PathBuf,
    environment: EnvironmentPolicy,
    workspace_root: &Path,
    pinned_workspace_root: Option<&wht_corulix_workspace::WorkspaceRoot>,
    arguments: Vec<String>,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustDiagnosticsOutcome, RustValidatorError> {
    let spec = ProcessSpec {
        executable,
        arguments,
        environment,
        working_directory: workspace_root.to_path_buf(),
        limits: VALIDATOR_LIMITS,
        timeout: VALIDATOR_TIMEOUT,
        execution_class: ExecutionClass::TrustedWorkspaceExecution,
        argv0: None,
    };
    // M09-P7: `pinned_workspace_root` binds the child's cwd to the real
    // workspace root object on Unix (`Some`, via the `_with_workspace_root`
    // public entry points); the pre-P7 unpinned `None` path is unchanged,
    // out of P10's scope (Section 36: Unix execution policy is frozen).
    #[cfg(unix)]
    let outcome = match pinned_workspace_root {
        Some(root) => {
            wht_corulix_tooling::execute_with_workspace_root(&spec, root, cancellation).await
        }
        None => wht_corulix_tooling::execute(&spec, cancellation).await,
    };
    // M09-P10: `execution_class` here is always `TrustedWorkspaceExecution`
    // (see this function's own construction of `spec` above) -- on Windows
    // this must fail closed regardless of whether `pinned_workspace_root`
    // is `Some` or `None`, since neither case has a pathname-cwd-free way
    // to bind the child to the real workspace object. Never falls through
    // to `wht_corulix_tooling::execute` (that would spawn `cargo.exe` with
    // a raw pathname cwd -- exactly the pattern this phase forbids). No
    // `Command` is constructed on this path.
    #[cfg(not(unix))]
    let outcome = {
        let _ = (pinned_workspace_root, &spec, cancellation);
        ExecutionOutcome {
            termination: TerminationReason::SpawnFailed,
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
        }
    };
    match outcome.termination {
        TerminationReason::Exited { code } => {
            let parsed = parse_cargo_json_stream(&outcome.stdout.bytes, outcome.stdout.truncated);
            // A non-zero exit with zero real findings is never legitimate
            // "clean" evidence -- see `RustValidatorError::
            // ValidatorInvocationFailed`'s own doc comment for the real,
            // empirically-observed failure mode (a malformed `Cargo.toml`)
            // this closes. A non-zero exit *with* findings (the ordinary
            // "cargo exits 101 because rustc reported real errors" case) is
            // not affected -- `parsed.error_count > 0` there, so this arm is
            // not taken.
            if code != 0 && parsed.error_count == 0 && parsed.warning_count == 0 {
                Err(RustValidatorError::ValidatorInvocationFailed)
            } else {
                Ok(parsed)
            }
        }
        TerminationReason::Signaled { .. } => Err(RustValidatorError::Signaled),
        TerminationReason::TimedOut => Err(RustValidatorError::TimedOut),
        TerminationReason::Cancelled => Err(RustValidatorError::Cancelled),
        TerminationReason::SpawnFailed => Err(RustValidatorError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(RustValidatorError::TerminationFailed),
    }
}

/// Pre-P18 managed-runtime validator path -- still the *only* path for
/// [`run_clippy`] (any platform) and for [`run_cargo_check`] on non-Windows
/// hosts. Resolves [`resolve_runtime`]/[`managed_environment`] (the
/// single, pre-existing `MANAGED_PROVIDER_HOST_TARGET`-pinned runtime) and
/// hands off to [`execute_validator_process`].
async fn run_validator(
    managed_root: &Path,
    workspace_root: &Path,
    pinned_workspace_root: Option<&wht_corulix_workspace::WorkspaceRoot>,
    effective: &wht_corulix_config::EffectiveConfig,
    arguments: Vec<String>,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustDiagnosticsOutcome, RustValidatorError> {
    authorize_trusted_execution(effective)?;
    let install_dir = resolve_runtime(managed_root)?;
    let executable_name = if cfg!(target_os = "windows") {
        "cargo.exe"
    } else {
        "cargo"
    };
    let executable = install_dir.join("bin").join(executable_name);
    execute_validator_process(
        executable,
        managed_environment(&install_dir),
        workspace_root,
        pinned_workspace_root,
        arguments,
        cancellation,
    )
    .await
}

/// P18: resolves
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64`]
/// -- [`run_cargo_check`]'s own, `gate.diagnostics`-only Windows managed
/// runtime, verifying it is genuinely owned-`Available` under
/// `managed_root`, exactly the same ownership-checked pattern
/// [`resolve_runtime`] and `crate::testing::resolve_link_runtime` already
/// use for their own distinct components. See that manifest's own doc
/// comment for the full architecture rationale (why a separate component
/// from both [`RUST_SEMANTIC_RUNTIME_WINDOWS_X64`](wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_X64)
/// and `gate.tests`'s own `RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`).
#[cfg(target_os = "windows")]
pub(crate) fn resolve_diagnostics_runtime(
    managed_root: &Path,
) -> Result<PathBuf, RustValidatorError> {
    let manifest =
        wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64;
    let (state, _binary) = provisioning::resolve_owned_managed_component(managed_root, &manifest);
    if state != ManagedComponentState::Available {
        return Err(RustValidatorError::ManagedRuntimeUnavailable);
    }
    Ok(provisioning::component_install_dir(managed_root, &manifest))
}

/// The GNU-hosted install directory's own host triple, relative to
/// `install_dir` -- both the location of the self-contained MinGW linker
/// driver ([`diagnostics_link_environment`]) and the `CARGO_TARGET_<TRIPLE>_*`
/// env-var key that targets it (cargo's own uppercased,
/// underscore-separated triple naming convention:
/// `x86_64-pc-windows-gnu` -> `X86_64_PC_WINDOWS_GNU`).
#[cfg(target_os = "windows")]
const DIAGNOSTICS_HOST_TRIPLE: &str = "x86_64-pc-windows-gnu";

/// The canonical checked workspace target for `gate.diagnostics` on Windows
/// -- `x86_64-pc-windows-msvc`, matching every other Windows provider
/// (Corulix's own binary, managed `rustfmt`, managed `rust-analyzer`); see
/// `RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64`'s own doc comment for
/// why this deliberately differs from `gate.tests`'s own
/// `x86_64-pc-windows-gnu` trusted-execution target.
#[cfg(target_os = "windows")]
pub(crate) const DIAGNOSTICS_CHECK_TARGET_TRIPLE: &str = "x86_64-pc-windows-msvc";

/// P18: builds the environment for a managed, fully self-contained Windows
/// `cargo check --target x86_64-pc-windows-msvc` -- `install_dir` is
/// [`resolve_diagnostics_runtime`]'s resolved GNU-hosted install directory
/// (host `rustc.exe`/`cargo.exe`, plus this same component's own merged
/// `x86_64-pc-windows-msvc` target `rust-std` sysroot, plus the bundled
/// `rust-mingw` self-contained MinGW-w64 linker).
///
/// # Why `CARGO_TARGET_<HOST-TRIPLE>_*`, not bare `RUSTFLAGS`
///
/// Host (`x86_64-pc-windows-gnu`) and checked target
/// (`x86_64-pc-windows-msvc`) genuinely differ here -- unlike `gate.tests`'s
/// own Windows [`crate::testing::link_environment`], which needs no
/// `--target` flag at all because its host and trusted-execution target are
/// the same GNU triple. `cargo`'s own `build.rs`/proc-macro compilation is
/// *always* for the host triple, never the `--target` triple, and this
/// phase's own research (see
/// `RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`'s doc comment on the earlier,
/// empirically-rejected "MSVC-hosted, cross-compile to GNU" design)
/// empirically confirmed that a bare env `RUSTFLAGS` applies only to the
/// invocation's cross `--target` artifacts under cargo's cross-compilation
/// model -- never to `build.rs`/proc-macro artifacts compiled for the host
/// triple. A target-triple-*keyed* override
/// (`CARGO_TARGET_<TRIPLE>_LINKER`/`CARGO_TARGET_<TRIPLE>_RUSTFLAGS`), by
/// contrast, is cargo's own documented mechanism for supplying a
/// *per-target* linker/flags configuration regardless of whether that named
/// target triple is acting as the host or as the `--target` cross target --
/// exactly this scenario, keyed here by [`DIAGNOSTICS_HOST_TRIPLE`] (the
/// host), never by [`DIAGNOSTICS_CHECK_TARGET_TRIPLE`] (the checked target,
/// which is never linked by `cargo check` and therefore needs no linker
/// configuration of its own at all). `-C link-self-contained=y` is required
/// for the identical reason `crate::testing::link_environment`'s own Windows
/// branch requires it: without it, rustc never passes the `-B`-style
/// search-path arguments that make the self-contained
/// `x86_64-w64-mingw32-gcc.exe` look inside its own bundled
/// `bin/self-contained`/`lib/self-contained` directories, mirroring that
/// module's own empirically-derived finding exactly (same underlying
/// `rust-mingw` artifact, same `windows_gnu_base` target-spec mechanism).
///
/// No Visual Studio, no Windows SDK, no `link.exe`, no ambient system `PATH`
/// entry of any kind (`WINDOWS_DIAGNOSTICS_SYSTEM_LINKER_AUTHORITY=NO`,
/// `AMBIENT_PATH_AUTHORITY=NO`) -- `PATH` here is exactly this component's
/// own `bin/` directory plus its own bundled
/// `lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/` directory, never
/// anything derived from this process's own ambient `PATH`.
#[cfg(target_os = "windows")]
pub(crate) fn diagnostics_link_environment(install_dir: &Path) -> EnvironmentPolicy {
    let bin_dir = install_dir.join("bin");
    let self_contained_bin = install_dir
        .join("lib/rustlib")
        .join(DIAGNOSTICS_HOST_TRIPLE)
        .join("bin/self-contained");
    let gcc = self_contained_bin.join("x86_64-w64-mingw32-gcc.exe");
    let path = format!("{};{}", bin_dir.display(), self_contained_bin.display());

    // Cargo's own env-var naming convention for a target-specific override:
    // the triple, uppercased, with every `-` replaced by `_`.
    let target_env_key_stem = "CARGO_TARGET_X86_64_PC_WINDOWS_GNU";

    EnvironmentPolicy::empty()
        .with_var("PATH", path)
        .with_var(
            "CARGO",
            bin_dir.join("cargo.exe").to_string_lossy().into_owned(),
        )
        .with_var(
            "RUSTC",
            bin_dir.join("rustc.exe").to_string_lossy().into_owned(),
        )
        .with_var("CARGO_NET_OFFLINE", "true")
        .with_var(
            format!("{target_env_key_stem}_LINKER"),
            gcc.to_string_lossy().into_owned(),
        )
        .with_var(
            format!("{target_env_key_stem}_RUSTFLAGS"),
            "-C link-self-contained=y",
        )
}

/// Runs real, managed `cargo check --message-format=json` against
/// `workspace_root` -- the authoritative `ProviderCategory::TypecheckBuild`
/// validator: full type/borrow/trait-resolution authority, no *target*
/// linking (see this module's own doc comment for why `cargo build` is out
/// of scope; a checked crate's own `build.rs`, if present, is still
/// compiled and run -- see "Execution class" above). `effective` must
/// authorize [`ExecutionClass::TrustedWorkspaceExecution`]
/// (`wht_corulix_config::HostConfig::workspace_trust == Trusted` and
/// `allow_trusted_workspace_execution == true`) or this returns
/// [`RustValidatorError::WorkspaceExecutionNotAuthorized`] before spawning
/// anything.
pub async fn run_cargo_check(
    managed_root: &Path,
    workspace_root: &Path,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustDiagnosticsOutcome, RustValidatorError> {
    run_cargo_check_impl(managed_root, workspace_root, None, effective, cancellation).await
}

/// As [`run_cargo_check`], but binds the spawned `cargo check`'s cwd to
/// `workspace_root`'s pinned root object (M09-P7, Unix only) instead of a
/// re-resolvable pathname. Additive: [`run_cargo_check`] and its `&Path`
/// signature are unchanged, so every existing (including external,
/// published) caller is unaffected.
pub async fn run_cargo_check_with_workspace_root(
    managed_root: &Path,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustDiagnosticsOutcome, RustValidatorError> {
    run_cargo_check_impl(
        managed_root,
        workspace_root.canonical_path(),
        Some(workspace_root),
        effective,
        cancellation,
    )
    .await
}

async fn run_cargo_check_impl(
    managed_root: &Path,
    workspace_root: &Path,
    pinned_workspace_root: Option<&wht_corulix_workspace::WorkspaceRoot>,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustDiagnosticsOutcome, RustValidatorError> {
    // P18: Windows `gate.diagnostics` uses a dedicated, self-contained
    // GNU-hosted runtime (`resolve_diagnostics_runtime`) with an explicit
    // `--target x86_64-pc-windows-msvc` -- see `diagnostics_link_environment`'s
    // own doc comment for why this differs from both the non-Windows path
    // below and from `gate.tests`'s own Windows runtime. Non-Windows hosts
    // are entirely unaffected: `run_validator`/`resolve_runtime`/
    // `managed_environment` are unchanged.
    #[cfg(target_os = "windows")]
    {
        authorize_trusted_execution(effective)?;
        let install_dir = resolve_diagnostics_runtime(managed_root)?;
        let executable = install_dir.join("bin/cargo.exe");
        // `execute_validator_process` -> `parse_cargo_json_stream` stamps
        // `provider_version` from `managed_runtime_version()`
        // (`rust_semantic_runtime_host_native()`'s version), which on
        // Windows is `RUST_SEMANTIC_RUNTIME_WINDOWS_X64`'s own version
        // string -- the *pre-P18* runtime this branch no longer resolves.
        // Both manifests happen to share `"1.98.0"` today, so this is
        // numerically correct by coincidence, not by construction; corrected
        // here explicitly so `EvidenceProvenance::provider_version` never
        // silently misattributes the runtime that actually ran the moment
        // the two versions diverge.
        let mut outcome = execute_validator_process(
            executable,
            diagnostics_link_environment(&install_dir),
            workspace_root,
            pinned_workspace_root,
            vec![
                "check".to_string(),
                "--target".to_string(),
                DIAGNOSTICS_CHECK_TARGET_TRIPLE.to_string(),
                "--message-format=json".to_string(),
                "--quiet".to_string(),
            ],
            cancellation,
        )
        .await?;
        outcome.provider_version =
            wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_DIAGNOSTICS_X64
                .version
                .to_string();
        Ok(outcome)
    }
    #[cfg(not(target_os = "windows"))]
    {
        run_validator(
            managed_root,
            workspace_root,
            pinned_workspace_root,
            effective,
            vec![
                "check".to_string(),
                "--message-format=json".to_string(),
                "--quiet".to_string(),
            ],
            cancellation,
        )
        .await
    }
}

/// Runs real, managed `cargo clippy --message-format=json` against
/// `workspace_root` -- the `ProviderCategory::Linter` validator, always
/// `SupportingOnly` per `crate::policy` (see [`policy_entry`](crate::policy_entry)):
/// clippy's own findings never close `gate.diagnostics` by themselves. Same
/// trust-authorization precondition as [`run_cargo_check`]. Additionally
/// verifies the real `cargo-clippy`/`clippy-driver` binaries exist (see
/// `resolve_clippy_binaries`) before ever invoking `cargo clippy` --
/// cargo's own built-in `clippy` subcommand does not fail when
/// `clippy-driver` is unresolvable, it silently compiles without linting.
pub async fn run_clippy(
    managed_root: &Path,
    workspace_root: &Path,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustDiagnosticsOutcome, RustValidatorError> {
    run_clippy_impl(managed_root, workspace_root, None, effective, cancellation).await
}

/// As [`run_clippy`], but binds the spawned `cargo clippy`'s cwd to
/// `workspace_root`'s pinned root object (M09-P7, Unix only). Additive,
/// mirroring [`run_cargo_check_with_workspace_root`]'s own rationale.
pub async fn run_clippy_with_workspace_root(
    managed_root: &Path,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustDiagnosticsOutcome, RustValidatorError> {
    run_clippy_impl(
        managed_root,
        workspace_root.canonical_path(),
        Some(workspace_root),
        effective,
        cancellation,
    )
    .await
}

async fn run_clippy_impl(
    managed_root: &Path,
    workspace_root: &Path,
    pinned_workspace_root: Option<&wht_corulix_workspace::WorkspaceRoot>,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustDiagnosticsOutcome, RustValidatorError> {
    authorize_trusted_execution(effective)?;
    resolve_runtime(managed_root)?;
    resolve_clippy_binaries(managed_root, &rust_semantic_runtime_host_native())?;
    run_validator(
        managed_root,
        workspace_root,
        pinned_workspace_root,
        effective,
        vec![
            "clippy".to_string(),
            "--message-format=json".to_string(),
            "--quiet".to_string(),
        ],
        cancellation,
    )
    .await
}

/// Converts a real [`RustDiagnosticsOutcome`]'s bounded `summary` into an
/// [`wht_corulix_core::EvidenceResultSummary`] -- a thin, explicit
/// conversion boundary so callers never construct that type from raw,
/// unbounded provider output themselves.
pub fn evidence_result_summary(
    outcome: &RustDiagnosticsOutcome,
) -> CorulixResult<wht_corulix_core::EvidenceResultSummary> {
    wht_corulix_core::EvidenceResultSummary::try_from(outcome.summary.clone())
        .map_err(|_| CorulixError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_error_and_warning_counts_from_a_real_shaped_cargo_json_stream() {
        let stream = concat!(
            r#"{"reason":"compiler-artifact","package_id":"foo"}"#,
            "\n",
            r#"{"reason":"compiler-message","message":{"level":"error","rendered":"error[E0308]: mismatched types\n"}}"#,
            "\n",
            r#"{"reason":"compiler-message","message":{"level":"warning","rendered":"warning: unused variable\n"}}"#,
            "\n",
            r#"{"reason":"build-finished","success":false}"#,
        );
        let outcome = parse_cargo_json_stream(stream.as_bytes(), false);
        assert_eq!(outcome.error_count, 1);
        assert_eq!(outcome.warning_count, 1);
        assert!(!outcome.truncated);
        assert!(outcome.summary.contains("E0308"));
        assert!(outcome.summary.contains("unused variable"));
    }

    #[test]
    fn a_clean_stream_reports_zero_errors_and_is_is_clean() {
        let stream = r#"{"reason":"build-finished","success":true}"#;
        let outcome = parse_cargo_json_stream(stream.as_bytes(), false);
        assert!(outcome.is_clean());
        assert_eq!(outcome.warning_count, 0);
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let stream = concat!(
            "not json at all\n",
            r#"{"reason":"compiler-message","message":{"level":"error","rendered":"real error\n"}}"#,
        );
        let outcome = parse_cargo_json_stream(stream.as_bytes(), false);
        assert_eq!(outcome.error_count, 1);
    }

    #[test]
    fn truncated_stdout_propagates_to_the_outcome() {
        let outcome = parse_cargo_json_stream(b"", true);
        assert!(outcome.truncated);
    }

    /// `P11_SYSTEM_CARGO_SELECTION_COUNT=0` structural proof: the built
    /// `PATH` is *exactly* the managed `bin/` directory followed by the
    /// fixed [`SYSTEM_LINKER_SEARCH_DIRS`] -- never anything derived from
    /// this process's own ambient `PATH`. `real_p11_diagnostics_e2e.rs`'s
    /// own poisoned-PATH E2E depends on this holding for real, not merely
    /// on `wht_corulix_tooling::execute`'s independent `env_clear()`. The
    /// fixed linker-search suffix cannot itself select a system `cargo`/
    /// `rustc`/`clippy` -- those three are always resolved via
    /// `install_dir.join(...)` explicit paths (see [`run_validator`]/
    /// [`resolve_clippy_binaries`]), never PATH lookup.
    #[test]
    fn managed_environment_path_is_the_managed_bin_dir_plus_fixed_linker_dirs_never_ambient() {
        let install_dir = Path::new("/opt/corulix-managed/rust-semantic-runtime");
        let env = managed_environment(install_dir);
        let expected = format!(
            "{}:{SYSTEM_LINKER_SEARCH_DIRS}",
            install_dir.join("bin").display()
        );
        assert_eq!(env.get("PATH"), Some(expected.as_str()));
    }

    /// `RustValidatorError::ManagedClippyUnavailable` proof: whole-component
    /// availability is not enough -- the specific clippy binaries must exist
    /// on disk, and their absence is a distinct, pre-spawn typed error. No
    /// ownership record exists under this fresh, isolated `managed_root`, so
    /// the segment-tamper half of [`resolve_clippy_binaries`] reports
    /// `SegmentState::Absent` (not `Available`) once both files exist --
    /// still mapped to `Ok(())`, exactly like a genuine "never recorded"
    /// legacy state (see [`provisioning::resolve_optional_segment`]'s own
    /// doc comment); this test's own scope is the file-presence check.
    #[test]
    fn resolve_clippy_binaries_fails_closed_when_either_file_is_missing() -> CorulixResult<()> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let managed_root =
            std::env::temp_dir().join(format!("corulix-p11r1-clippy-binaries-{stamp}"));
        let manifest = rust_semantic_runtime_host_native();
        let install_dir = provisioning::component_install_dir(&managed_root, &manifest);
        let bin = install_dir.join("bin");
        std::fs::create_dir_all(&bin).map_err(|_| CorulixError::Internal)?;
        assert_eq!(
            resolve_clippy_binaries(&managed_root, &manifest),
            Err(RustValidatorError::ManagedClippyUnavailable)
        );
        std::fs::write(bin.join("cargo-clippy"), b"").map_err(|_| CorulixError::Internal)?;
        assert_eq!(
            resolve_clippy_binaries(&managed_root, &manifest),
            Err(RustValidatorError::ManagedClippyUnavailable),
            "cargo-clippy alone, without clippy-driver, must still fail closed"
        );
        std::fs::write(bin.join("clippy-driver"), b"").map_err(|_| CorulixError::Internal)?;
        assert_eq!(resolve_clippy_binaries(&managed_root, &manifest), Ok(()));
        let _ = std::fs::remove_dir_all(&managed_root);
        Ok(())
    }

    /// `RustValidatorError::ManagedClippyTampered` proof (P11 Section 10):
    /// both clippy binaries present, but a genuine ownership record
    /// declares a `"clippy"` segment digest that does not match their real
    /// bytes. Must fail closed as `ManagedClippyTampered`, never treated as
    /// merely `ManagedClippyUnavailable` (absent) or silently `Ok(())`.
    /// Built entirely through `wht_corulix_tooling::provisioning`'s public
    /// API (`uninstall::build_record`/`ownership::save`) -- no real network
    /// provisioning required.
    #[test]
    fn resolve_clippy_binaries_fails_closed_when_segment_digest_is_tampered() -> CorulixResult<()> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let managed_root =
            std::env::temp_dir().join(format!("corulix-p11r1-clippy-tampered-{stamp}"));
        let manifest = rust_semantic_runtime_host_native();
        let install_dir = provisioning::component_install_dir(&managed_root, &manifest);
        let bin = install_dir.join("bin");
        std::fs::create_dir_all(&bin).map_err(|_| CorulixError::Internal)?;
        std::fs::write(bin.join("cargo-clippy"), b"real cargo-clippy bytes")
            .map_err(|_| CorulixError::Internal)?;
        std::fs::write(bin.join("clippy-driver"), b"real clippy-driver bytes")
            .map_err(|_| CorulixError::Internal)?;

        let mut optional_segment_digests = std::collections::BTreeMap::new();
        // Deliberately wrong -- any real digest of the bytes just written
        // would never legitimately equal 64 zeros.
        optional_segment_digests.insert("clippy".to_string(), "0".repeat(64));
        let mut record = provisioning::uninstall::build_record(
            &managed_root,
            provisioning::uninstall::NewInstallation {
                component_id: manifest.id.0,
                version: manifest.version,
                platform: manifest.platform,
                architecture: manifest.architecture,
                canonical_component_root: install_dir,
                dependencies: Vec::new(),
                installation_sequence: 1,
                artifact_digest: "0".repeat(64),
                ownership: provisioning::ownership::OwnershipClass::CorulixManaged,
                installed_payload_digest: String::new(),
                installed_payload_kind: provisioning::ownership::InstalledPayloadKind::SingleFile,
                optional_segment_digests,
            },
        );
        provisioning::ownership::save(&managed_root, &mut record)
            .map_err(|_| CorulixError::Internal)?;

        assert_eq!(
            resolve_clippy_binaries(&managed_root, &manifest),
            Err(RustValidatorError::ManagedClippyTampered)
        );
        let _ = std::fs::remove_dir_all(&managed_root);
        Ok(())
    }

    /// The trust gate itself: a default (`Untrusted`) `EffectiveConfig`
    /// denies `TrustedWorkspaceExecution`; explicit `HOST_ONLY` grant
    /// (`workspace_trust: Trusted` + `allow_trusted_workspace_execution:
    /// true`) authorizes it. Pure-function proof beneath the real E2E's own
    /// process-level proof in `real_p11_r1_trust_enforcement_e2e.rs`.
    #[test]
    fn authorize_trusted_execution_matches_effective_config_trust_state() {
        let untrusted = wht_corulix_config::EffectiveConfig::derive(
            &wht_corulix_config::HostConfig::default(),
            &wht_corulix_config::RepositoryHints::default(),
            &wht_corulix_config::RequestOptions::default(),
        );
        assert_eq!(
            authorize_trusted_execution(&untrusted),
            Err(RustValidatorError::WorkspaceExecutionNotAuthorized)
        );

        let trusted_host = wht_corulix_config::HostConfig {
            workspace_trust: wht_corulix_core::WorkspaceTrust::Trusted,
            allow_trusted_workspace_execution: true,
            ..wht_corulix_config::HostConfig::default()
        };
        let trusted = wht_corulix_config::EffectiveConfig::derive(
            &trusted_host,
            &wht_corulix_config::RepositoryHints::default(),
            &wht_corulix_config::RequestOptions::default(),
        );
        assert_eq!(authorize_trusted_execution(&trusted), Ok(()));
    }

    /// `P11_OPTIONAL_PROVIDER_FAKE_EVIDENCE_COUNT=0` unit-level proof: a
    /// non-zero exit with zero parsed findings must never be folded into a
    /// "clean" outcome by `run_validator`'s own discriminator logic. This
    /// exercises exactly the boolean expression `run_validator` evaluates,
    /// against the two real shapes P11-R1's research gate observed: a
    /// broken-manifest failure (zero messages, non-zero exit) and a real
    /// compile error (real messages, non-zero exit).
    #[test]
    fn nonzero_exit_with_zero_findings_is_distinguished_from_nonzero_exit_with_real_findings() {
        let no_findings = parse_cargo_json_stream(br#"{"reason":"build-finished"}"#, false);
        let code = 101;
        let is_invocation_failure =
            code != 0 && no_findings.error_count == 0 && no_findings.warning_count == 0;
        assert!(is_invocation_failure);

        let real_error = parse_cargo_json_stream(
            br#"{"reason":"compiler-message","message":{"level":"error","rendered":"e\n"}}"#,
            false,
        );
        let is_invocation_failure =
            code != 0 && real_error.error_count == 0 && real_error.warning_count == 0;
        assert!(!is_invocation_failure);
    }

    #[test]
    fn summary_construction_never_exceeds_the_evidence_bound() {
        // A single findings' `rendered` text far larger than
        // `MAX_SUMMARY_BYTES` must still yield a summary this module's own
        // bound accepts, never one `EvidenceResultSummary::try_from` would
        // reject.
        let huge = "x".repeat(MAX_SUMMARY_BYTES * 3);
        let line = format!(
            r#"{{"reason":"compiler-message","message":{{"level":"error","rendered":"{huge}"}}}}"#
        );
        let outcome = parse_cargo_json_stream(line.as_bytes(), false);
        assert!(outcome.summary.len() <= wht_corulix_core::EVIDENCE_RESULT_SUMMARY_MAX_BYTES);
        let result = evidence_result_summary(&outcome);
        assert!(result.is_ok());
    }
}
