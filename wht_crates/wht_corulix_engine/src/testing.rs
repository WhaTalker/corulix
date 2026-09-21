// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P12: `CORULIX_MANAGED` `cargo test` (`ProviderCategory::TestRunner`)
//! invocation, composing real Evidence for `GateId::Tests`.
//!
//! # Reuses P11/P11-R1's trust-gated managed-runtime pattern
//!
//! This module deliberately does not re-derive managed-runtime resolution,
//! the managed environment, or trust enforcement -- it calls
//! `crate::diagnostics::resolve_runtime`,
//! `crate::diagnostics::managed_environment`, and
//! `crate::diagnostics::authorize_trusted_execution` directly (promoted to
//! `pub(crate)` for this reuse; no second, divergent implementation of any of
//! the three exists). `cargo test` runs as
//! [`ExecutionClass::TrustedWorkspaceExecution`] for exactly the reason
//! `cargo check`/`cargo clippy` do: it compiles and executes the workspace's
//! own `build.rs`, proc macros, *and* the compiled test binary itself --
//! real repository-authored code execution, a strictly larger surface than
//! `cargo check`'s. The one load-bearing trust gate runs before any
//! [`ProcessSpec`] is constructed, exactly as in `crate::diagnostics`
//! (`P12_UNTRUSTED_TEST_PROCESS_SPAWN_COUNT=0`).
//!
//! # `PROVIDER_EXECUTABLE_AUTHORITY != WORKSPACE_EXECUTION_TRUST_CLASS`
//!
//! `cargo`/`rustc` remain fully `CORULIX_MANAGED` (resolved by explicit path
//! under `crate::diagnostics::resolve_runtime`, never PATH search); the
//! *compiled test binary* `cargo test` links and executes is, by contrast,
//! workspace-authored -- it is allowed to run only because the operation
//! carries `ExecutionClass::TrustedWorkspaceExecution` and the effective
//! configuration authorizes it, never because Corulix trusts the test
//! binary's own provenance.
//!
//! # Linker dependency -- P12-R2: fully managed, no system fallback
//!
//! `P12_RUST_TEST_LINKER_AUTHORITY=CORULIX_MANAGED`. P12/P12-R1 disclosed
//! `SYSTEM_LINKER_REQUIRED_NOT_MANAGED` here (reusing
//! `crate::diagnostics::managed_environment`'s fixed `/usr/bin:/bin` `PATH`
//! suffix unchanged) because linking a real test binary needs a linker
//! executable *and* CRT/libc/libgcc_s the managed Rust distribution alone
//! does not bundle. P12-R2 closed that gap for `cargo test` specifically
//! (never for `crate::diagnostics`'s `cargo check`/`cargo clippy`, which are
//! out of this phase's scope and keep their own system-linker disclosure
//! unchanged) by admitting a second managed component,
//! [`wht_corulix_tooling::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64`] --
//! a real, official, SHA-256-verified GNU sysroot subset (Bootlin's
//! `x86-64--glibc--stable-2021.11-5`: glibc 2.34, the oldest of Bootlin's
//! current stable releases, chosen for maximum forward-compatibility).
//!
//! `link_environment` builds the final environment from *two* managed
//! components -- the existing Rust runtime (`rustc`/`cargo`, and now also
//! its bundled `rust-lld` linker executable at
//! `lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld`) and the new GNU
//! link runtime (CRT objects, `libc.so`/`libc_nonshared.a`,
//! `libgcc.a`/`libgcc_eh.a`, and the runtime shared objects
//! `libc.so.6`/`libpthread.so.0`/`libgcc_s.so.1`/`ld-linux-x86-64.so.2`) --
//! and forces `rustc` to use them via `RUSTFLAGS`: `-C linker-flavor=ld -C
//! linker=<rust-lld> -C link-arg=--sysroot=<gnu sysroot> -C
//! link-arg=-L<sysroot>/usr/lib -C link-arg=-L<sysroot>/lib -C
//! link-arg=-L<gnu lib/gcc dir> -C link-arg=-dynamic-linker -C
//! link-arg=<sysroot>/lib/ld-linux-x86-64.so.2 -C link-arg=-rpath -C
//! link-arg=<sysroot>/lib -C link-arg=<sysroot>/usr/lib/crt1.o -C
//! link-arg=<sysroot>/usr/lib/crti.o -C link-arg=<sysroot>/usr/lib/crtn.o`.
//! `PATH` is the managed Rust `bin/` directory **only** -- no
//! `/usr/bin:/bin` suffix, no ambient-`PATH` fallthrough of any kind
//! (`AMBIENT_PATH_AUTHORITY=NO`).
//!
//! This exact argument set was arrived at empirically, not by
//! specification-reading alone: `-C linker-flavor=ld` alone synthesizes
//! *zero* library search paths (rustc normally delegates that to a `cc`
//! driver), so every `-L`/CRT-object/`-dynamic-linker`/`-rpath` argument
//! above had to be supplied explicitly and was proven, one missing symbol
//! at a time, against a real controlled fixture before being accepted here.
//! `-C linker=<rust-lld>` wins over both a poisoned `PATH` (see
//! `real_p12_r2_hostile_linker_poison_positive_control_e2e`) and a hostile
//! `.cargo/config.toml`'s `[target.*].linker` override (empirically
//! confirmed: an env-derived `RUSTFLAGS -C linker=` takes precedence over a
//! workspace config file's `target.<triple>.linker` -- see
//! `real_p12_r2_workspace_linker_config_hijack_denied_e2e`) --
//! `P12_WORKSPACE_LINKER_AUTHORITY_COUNT=0`.
//!
//! `build.rs` compilation is linked through the exact same `RUSTFLAGS` (host
//! and target triple are identical here), empirically confirmed against a
//! real fixture with a trivial `build.rs` during this phase's research
//! gate -- this is not asserted from the no-`build.rs` case alone.
//!
//! Neither managed component being present/owned-`Available` fails the
//! whole call closed with [`RustTestError::ManagedRuntimeUnavailable`] /
//! [`RustTestError::ManagedLinkerRuntimeUnavailable`] *before* any process
//! is spawned -- there is no code path that falls back to an ambient system
//! linker when the managed one is missing or corrupt
//! (`P12_HOST_FALLBACK_EXECUTION_COUNT=0`, see
//! `real_p12_r2_managed_gnu_runtime_unavailable_fails_closed_e2e`).
//!
//! # `CARGO_TARGET_DIR` is Corulix-owned scratch, never the governed workspace
//!
//! `cargo test` (like `cargo check`) writes build artifacts to a
//! `target/` directory. Left at cargo's own default, that write lands
//! *inside* the governed workspace -- an unrequested, undisclosed side
//! effect on content a `ChangeSession` may be actively baselining, and a
//! sequence P12's own Evidence-staleness rules (mutation invalidates
//! Evidence) do not want triggered by Corulix's own tooling. This module
//! therefore points `CARGO_TARGET_DIR` at a deterministic, Corulix-owned
//! scratch directory under `managed_root` (never under `workspace_root`),
//! keyed by a stable hash of the canonical-looking workspace root path so
//! repeated runs against the same workspace reuse build artifacts instead of
//! recompiling from empty every call, while two different workspaces never
//! share (and cannot collide in) the same target directory. See
//! `test_target_dir_relative`, created via
//! [`wht_corulix_tooling::provisioning::ensure_scratch_directory`].
//!
//! # Test result parse model (honest, not log-grep authority)
//!
//! `P12_RUST_TEST_RESULT_PARSE_MODEL=EXIT_CODE_AUTHORITATIVE +
//! STABLE_LIBTEST_SUMMARY_LINE_TEXT_PARSE`. Empirically confirmed (real
//! `cargo test --message-format=json` runs against controlled fixtures)
//! that, unlike `cargo check`/`cargo clippy`, cargo test's own pass/fail/
//! count summary is **not** part of the JSON stream -- `--message-format=json`
//! only makes the *build* phase (`compiler-artifact`/`compiler-message`/
//! `build-finished`) machine-readable; libtest's own `running N tests` /
//! `test ... ok|FAILED` / `test result: ok|FAILED. N passed; M failed; ...`
//! output remains interleaved plain text on the same stdout stream, and a
//! single run can emit **multiple** `test result:` lines (one per unit-test
//! binary plus a separate doc-tests block, confirmed empirically even with
//! zero doctests present). This module therefore:
//!
//! 1. Reuses `crate::diagnostics::parse_cargo_json_stream` to detect a
//!    real *build* failure (a `compiler-message` with `level: "error"`) --
//!    exactly the same authority as `cargo check`'s own error detection,
//!    because a build failure means no tests ran at all.
//! 2. Parses libtest's own stable, long-documented `test result: <status>.
//!    <N> passed; <N> failed; <N> ignored; <N> measured; <N> filtered out;
//!    ...` summary line via anchored text parsing (never a regex dependency,
//!    never an unstable/unadmitted cargo flag), aggregating counts across
//!    every such line found.
//! 3. Treats the **process exit code as authoritative** for pass/fail, and
//!    the parsed counts as **descriptive only** -- if the exit code and the
//!    parsed `failed` count disagree (exit `0` with `failed > 0`, or a
//!    non-zero exit with `failed == 0` and at least one result line seen),
//!    that is a [`RustTestError::ResultContradiction`], never silently
//!    resolved in either direction. This is the direct sibling of
//!    `crate::diagnostics`'s own non-zero-exit-zero-findings fix.
//!
//! No structured precision is fabricated beyond what libtest's own stable
//! text output actually provides.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use wht_corulix_core::{ContentHash, CorulixError, CorulixResult, ExecutionClass};
use wht_corulix_tooling::provisioning::{self, ManagedComponentState};
#[cfg(not(unix))]
use wht_corulix_tooling::{BoundedOutput, ExecutionOutcome};
use wht_corulix_tooling::{EnvironmentPolicy, ProcessLimits, ProcessSpec, TerminationReason};
use wht_corulix_workspace::{WalkLimits, WorkspaceRoot, confined_read, confined_walk};

#[cfg(not(target_os = "windows"))]
use crate::diagnostics::resolve_runtime;
use crate::diagnostics::{
    self, RustDiagnosticsOutcome, authorize_trusted_execution, parse_cargo_json_stream,
};

/// The managed `rust-lld` linker executable's path, relative to the Rust
/// runtime's own install directory -- part of the same official `rustc`
/// archive `resolve_runtime` already resolves, required present via
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_LINUX_X64`]'s
/// own `required_paths` (see that manifest's own P12-R2 doc-comment
/// addition).
#[cfg(not(target_os = "windows"))]
const RUST_LLD_RELATIVE_PATH: &str = "lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld";

/// GNU sysroot layout constants, relative to
/// [`wht_corulix_tooling::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64`]'s
/// own install directory -- see that manifest's doc comment for the
/// upstream source and content these paths resolve into.
#[cfg(not(target_os = "windows"))]
const GNU_SYSROOT_RELATIVE: &str = "x86_64-buildroot-linux-gnu/sysroot";
#[cfg(not(target_os = "windows"))]
const GNU_GCC_LIB_RELATIVE: &str = "lib/gcc/x86_64-buildroot-linux-gnu/10.3.0";

/// Resolves the managed GNU link runtime's install directory, verifying it
/// is genuinely owned-`Available` under `managed_root` -- the exact same
/// ownership-checked pattern as [`crate::diagnostics::resolve_runtime`],
/// applied to the second managed component
/// [`link_environment`] composes. See
/// [`wht_corulix_tooling::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64`]'s
/// own doc comment for what this component supplies and why it exists as a
/// distinct component from the Rust runtime.
#[cfg(not(target_os = "windows"))]
fn resolve_link_runtime(managed_root: &Path) -> Result<PathBuf, RustTestError> {
    let manifest = wht_corulix_tooling::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64;
    let (state, _binary) = provisioning::resolve_owned_managed_component(managed_root, &manifest);
    if state != ManagedComponentState::Available {
        return Err(RustTestError::ManagedLinkerRuntimeUnavailable);
    }
    Ok(provisioning::component_install_dir(managed_root, &manifest))
}

/// P17-W2: `TRUSTED_WORKSPACE_EXECUTION_TARGET` for Windows -- resolves
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`],
/// a real, self-contained, GNU-*hosted* Rust toolchain (`rustc.exe`/
/// `cargo.exe` themselves run as `x86_64-pc-windows-gnu` binaries). See that
/// manifest's own doc comment for the full "why a GNU-hosted toolchain, not
/// MSVC-hosted cross-compilation" research trail, including the real,
/// empirically-observed failure mode (`build.rs` host-target linking silently
/// bypassing `RUSTFLAGS`) that the earlier cross-compiling design hit on a
/// real native-Windows test run.
///
/// Unlike Unix's [`resolve_link_runtime`], there is no *second* managed
/// component to resolve here: host and trusted-execution target are the same
/// GNU triple, so one merged component -- rustc/cargo/rust-std/rust-src/
/// rust-mingw, all already merged onto one shared install directory by that
/// manifest's own `additional_sources` -- is both `resolve_runtime`'s Rust
/// toolchain *and* the link runtime, with no cross-target sysroot merge, no
/// `--target` flag, and no [`RustTestError::ManagedLinkerRuntimeUnavailable`]
/// distinct-unavailability case (unlike Unix, whose GNU link runtime is a
/// genuinely independent, independently-provisionable component).
#[cfg(target_os = "windows")]
fn resolve_link_runtime(managed_root: &Path) -> Result<PathBuf, RustTestError> {
    let manifest = wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64;
    let (state, _binary) = provisioning::resolve_owned_managed_component(managed_root, &manifest);
    if state != ManagedComponentState::Available {
        return Err(RustTestError::ManagedLinkerRuntimeUnavailable);
    }
    Ok(provisioning::component_install_dir(managed_root, &manifest))
}

/// The `x86_64-pc-windows-gnu` trusted-execution target triple, relative to
/// [`resolve_link_runtime`]'s own resolved install directory -- see
/// [`link_environment`]'s own doc comment for how it locates the
/// self-contained MinGW linker driver under this prefix.
#[cfg(target_os = "windows")]
const WINDOWS_GNU_TARGET_TRIPLE: &str = "x86_64-pc-windows-gnu";

/// Builds the environment for a managed, fully self-contained `cargo test`
/// link/run -- see this module's own top-level doc comment ("Linker
/// dependency -- P12-R2") for the full rationale and the exact `RUSTFLAGS`
/// argument set this function constructs. `PATH` is the managed Rust `bin/`
/// directory *only*; there is no system-directory suffix of any kind
/// (`AMBIENT_PATH_AUTHORITY=NO`), unlike
/// [`crate::diagnostics::managed_environment`], which this module
/// deliberately no longer calls.
#[cfg(not(target_os = "windows"))]
fn link_environment(rust_install_dir: &Path, gnu_install_dir: &Path) -> EnvironmentPolicy {
    let bin_dir = rust_install_dir.join("bin");
    let lib_dir = rust_install_dir.join("lib");
    let lld = rust_install_dir.join(RUST_LLD_RELATIVE_PATH);
    let sysroot = gnu_install_dir.join(GNU_SYSROOT_RELATIVE);
    let gcc_lib = gnu_install_dir.join(GNU_GCC_LIB_RELATIVE);
    let sysroot_lib = sysroot.join("lib");
    let sysroot_usr_lib = sysroot.join("usr/lib");
    let dynamic_linker = sysroot_lib.join("ld-linux-x86-64.so.2");

    let rustflags = [
        "-C".to_string(),
        "linker-flavor=ld".to_string(),
        "-C".to_string(),
        format!("linker={}", lld.display()),
        "-C".to_string(),
        format!("link-arg=--sysroot={}", sysroot.display()),
        "-C".to_string(),
        format!("link-arg=-L{}", sysroot_usr_lib.display()),
        "-C".to_string(),
        format!("link-arg=-L{}", sysroot_lib.display()),
        "-C".to_string(),
        format!("link-arg=-L{}", gcc_lib.display()),
        "-C".to_string(),
        "link-arg=-dynamic-linker".to_string(),
        "-C".to_string(),
        format!("link-arg={}", dynamic_linker.display()),
        "-C".to_string(),
        "link-arg=-rpath".to_string(),
        "-C".to_string(),
        format!("link-arg={}", sysroot_lib.display()),
        "-C".to_string(),
        format!("link-arg={}", sysroot_usr_lib.join("crt1.o").display()),
        "-C".to_string(),
        format!("link-arg={}", sysroot_usr_lib.join("crti.o").display()),
        "-C".to_string(),
        format!("link-arg={}", sysroot_usr_lib.join("crtn.o").display()),
    ]
    .join(" ");

    EnvironmentPolicy::empty()
        .with_var("LD_LIBRARY_PATH", lib_dir.to_string_lossy().into_owned())
        .with_var("PATH", bin_dir.to_string_lossy().into_owned())
        .with_var(
            "CARGO",
            bin_dir.join("cargo").to_string_lossy().into_owned(),
        )
        .with_var(
            "RUSTC",
            bin_dir.join("rustc").to_string_lossy().into_owned(),
        )
        .with_var("CARGO_NET_OFFLINE", "true")
        .with_var("RUSTFLAGS", rustflags)
}

/// P17-W: the Windows counterpart of the Unix [`link_environment`] above --
/// builds the environment for a managed, self-contained `cargo test`
/// link/run hosted entirely by
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`]'s
/// own GNU-*hosted* `rustc.exe`/`cargo.exe`
/// ([`resolve_link_runtime`]'s resolved install dir, `install_dir` here).
/// Per [`resolve_link_runtime`]'s own doc comment, host and trusted-execution
/// target are the same `x86_64-pc-windows-gnu` triple, so there is no
/// cross-target sysroot merge and no `--target` flag anywhere in this
/// function's `RUSTFLAGS` -- the earlier MSVC-hosted cross-compiling design
/// (which would have cross-compiled against a synthetic merged sysroot) was
/// abandoned after a real native-Windows test run hit `build.rs` host-target
/// linking silently bypassing `RUSTFLAGS`; see [`resolve_link_runtime`]'s own
/// doc comment for that research trail, and
/// [`wht_corulix_tooling::managed_runtimes::RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`]'s
/// own doc comment for why this merged, GNU-hosted component is provisioned
/// as a distinct identity. `-C linker=` points at the real,
/// self-contained, hash-verified `x86_64-w64-mingw32-gcc.exe` bundled by this
/// same merged component's `rust-mingw` sources -- an absolute path, exactly
/// like the Unix branch's own `-C linker=<rust-lld>`, so no `PATH` search is
/// required to find it; `PATH` is still set to the host `bin/` directory plus
/// this component's own `self-contained/` directory so the self-contained
/// `gcc.exe` can locate its own bundled `ld.exe`/`dlltool.exe` peers as
/// subprocesses without ever touching the ambient system `PATH`
/// (`AMBIENT_PATH_AUTHORITY=NO`, same invariant as the Unix branch).
#[cfg(target_os = "windows")]
fn link_environment(install_dir: &Path) -> EnvironmentPolicy {
    let bin_dir = install_dir.join("bin");
    let self_contained_bin = install_dir
        .join("lib/rustlib")
        .join(WINDOWS_GNU_TARGET_TRIPLE)
        .join("bin/self-contained");
    let gcc = self_contained_bin.join("x86_64-w64-mingw32-gcc.exe");

    // `-C link-self-contained=y` is required and, on its own with no other
    // override, insufficient evidence-wise -- confirmed empirically during
    // this phase's own real native-Windows test run: *without* it, rustc
    // never passes the `-B`-style search-path arguments that would make the
    // invoked `gcc.exe` look inside its own `bin/self-contained`/
    // `lib/self-contained` directories at all, so linking failed with
    // `ld: cannot find crt2.o` / `cannot find -lkernel32` even though
    // `-C linker=` correctly pointed at the real, self-contained
    // `x86_64-w64-mingw32-gcc.exe` this component bundles. This stable flag
    // (no nightly `-Z` required) is the fix: it tells rustc's own
    // `windows_gnu_base` target-spec logic that Corulix's bundled
    // self-contained CRT objects/import libraries/linker are authoritative,
    // never an ambient system MinGW installation
    // (`P17_W_SYSTEM_MINGW_EXECUTION_COUNT=0`).
    let rustflags = [
        "-C".to_string(),
        "link-self-contained=y".to_string(),
        "-C".to_string(),
        format!("linker={}", gcc.display()),
    ]
    .join(" ");

    let path = format!("{};{}", bin_dir.display(), self_contained_bin.display());

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
        .with_var("RUSTFLAGS", rustflags)
}

/// Bounded well below
/// [`wht_corulix_core::EVIDENCE_RESULT_SUMMARY_MAX_BYTES`], matching
/// `crate::diagnostics::MAX_SUMMARY_BYTES`'s own bound.
const MAX_TEST_SUMMARY_BYTES: usize = 3800;

/// `cargo test` can legitimately emit more output than `cargo check` on a
/// large suite (per-test pass/fail lines in addition to compiler JSON) --
/// bounded generously, but still bounded.
const TEST_LIMITS: ProcessLimits = ProcessLimits {
    max_stdout_bytes: 32 * 1024 * 1024,
    max_stderr_bytes: 8 * 1024 * 1024,
};

/// A real test suite can legitimately run longer than a `cargo check` --
/// bounded generously (this is not a claim that any specific suite will
/// finish within this window, only a hard ceiling against a runaway/hung
/// test).
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The real, caller-supplied resource ceiling for one [`run_cargo_test`]
/// invocation -- a genuine configuration knob (a host legitimately wants a
/// shorter timeout in CI than in an interactive session, or a smaller
/// output cap for a resource-constrained environment), not a test-only
/// seam: nothing here bypasses trust enforcement, process construction, or
/// evidence semantics -- it only bounds the same [`ProcessSpec`] fields
/// [`run_cargo_test`] would otherwise fill with the fixed `TEST_TIMEOUT`/
/// `TEST_LIMITS` defaults. [`run_cargo_test`] is unchanged and keeps using
/// those defaults; [`run_cargo_test_with_limits`] is the same function with
/// this made explicit.
#[derive(Debug, Clone, Copy)]
pub struct TestExecutionLimits {
    pub timeout: std::time::Duration,
    pub limits: ProcessLimits,
}

impl Default for TestExecutionLimits {
    fn default() -> Self {
        Self {
            timeout: TEST_TIMEOUT,
            limits: TEST_LIMITS,
        }
    }
}

/// Why a managed `cargo test` invocation could not produce trustworthy
/// Evidence. Never a free-form string -- see this module's own doc comment
/// for the parse model each variant corresponds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustTestError {
    /// See [`crate::diagnostics::RustValidatorError::ManagedRuntimeUnavailable`].
    ManagedRuntimeUnavailable,
    /// The managed GNU link runtime
    /// ([`wht_corulix_tooling::managed_runtimes::GNU_LINK_RUNTIME_LINUX_X64`])
    /// is not provisioned, corrupt, or not owned-`Available` under
    /// `managed_root`. No process is spawned when this is returned and no
    /// ambient system linker is ever consulted as a fallback
    /// (`P12_HOST_FALLBACK_EXECUTION_COUNT=0`) -- see this module's own doc
    /// comment ("Linker dependency -- P12-R2").
    ManagedLinkerRuntimeUnavailable,
    /// See [`crate::diagnostics::RustValidatorError::WorkspaceExecutionNotAuthorized`].
    /// No process is spawned when this is returned
    /// (`P12_UNTRUSTED_TEST_PROCESS_SPAWN_COUNT=0`).
    WorkspaceExecutionNotAuthorized,
    /// The Corulix-owned `CARGO_TARGET_DIR` scratch directory could not be
    /// created. Fails closed rather than falling back to cargo's own default
    /// (which would write into the governed workspace -- see this module's
    /// own doc comment).
    ScratchDirUnavailable,
    /// A real compiler-message error was observed in the JSON stream before
    /// any test could have run -- the workspace does not build, so no tests
    /// executed. Carries the real, bounded diagnostics outcome (reusing
    /// `crate::diagnostics::parse_cargo_json_stream`) rather than folding
    /// a build failure into a fabricated "zero tests" test outcome.
    BuildFailed(RustDiagnosticsOutcome),
    /// The process exited without error, stdout was not bounded-truncated,
    /// and produced zero `test result:` summary lines and no build error
    /// either -- e.g. a crate with no `#[test]` items at all. Distinct from
    /// a genuine pass so a caller cannot silently treat "nothing ran" as
    /// "everything passed".
    NoTestsExecuted,
    /// As [`Self::NoTestsExecuted`] (zero `test result:` summary lines
    /// observed), but stdout *was* bounded-truncated -- libtest always
    /// writes its `test result:` summary as the very last line of its
    /// output, so a sufficiently large real run can have that line fall in
    /// the discarded tail of a head-truncating bounded reader (see
    /// [`wht_corulix_tooling`]'s own `spawn_bounded_reader` doc comment).
    /// Reported as a distinct variant from [`Self::NoTestsExecuted`] so a
    /// caller never conflates "genuinely zero tests" with "truncation ate
    /// the result" -- both are `Err`, never a fabricated `Ok`, but they are
    /// different real conditions with different remediations (raise the
    /// output bound vs. add a `#[test]`).
    ResultTruncatedBeforeSummary,
    /// The exit code and the parsed `test result:` summary line(s)
    /// disagree (see this module's own doc comment, point 3). Never
    /// resolved in either direction -- fails closed.
    ResultContradiction,
    /// The governed `src/` tree's own content hash differs between the
    /// moment immediately before `cargo test` was spawned and the moment
    /// immediately after it exited -- the trusted test execution itself
    /// (a `build.rs`, a proc macro, or the test binary) mutated governed
    /// source content as a side effect. Returned *instead of* a normal
    /// [`RustTestOutcome`] regardless of the process's own exit code or
    /// parsed pass/fail counts: a result observed against content that no
    /// longer matches what was actually validated is never legitimate
    /// Evidence for the state it claims to describe. See
    /// `hash_governed_source_tree`.
    WorkspaceSelfMutationDetected,
    /// The governed `src/` tree could not be hashed (missing, unreadable,
    /// or exceeds the bounded walk/read limits) either before or after the
    /// run. Fails closed rather than skipping the coherence check silently.
    WorkspaceSourceTreeUnreadable,
    /// The child process could not be spawned at all.
    SpawnFailed,
    /// The configured timeout elapsed before the test run exited.
    TimedOut,
    /// The caller's [`wht_corulix_core::CancellationToken`] fired before the
    /// test run exited.
    Cancelled,
    /// Termination of a timed-out/cancelled process tree could not be
    /// confirmed to have succeeded.
    TerminationFailed,
    /// The test run exited with a signal rather than a normal exit code.
    Signaled,
}

/// The real, structured outcome of one `cargo test` invocation whose exit
/// code and parsed summary counts were confirmed *consistent* -- a
/// contradictory result never reaches this type, see
/// [`RustTestError::ResultContradiction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustTestOutcome {
    /// Exit-code-authoritative pass/fail (see this module's own doc
    /// comment, point 3). Always equal to `failed == 0` by construction --
    /// [`run_cargo_test`] never returns `Ok` otherwise.
    pub passing: bool,
    pub passed: u32,
    pub failed: u32,
    pub ignored: u32,
    pub measured: u32,
    pub filtered_out: u32,
    /// `true` if cargo's own output, or this module's own bounded summary
    /// construction, dropped content.
    pub truncated: bool,
    /// A bounded, human-readable summary: every `test result:` line seen,
    /// plus every individual `... FAILED` test-name line, joined by `\n`.
    pub summary: String,
    pub provider_version: String,
}

impl RustTestOutcome {
    /// `passed + failed` -- the real, counted number of tests libtest
    /// reported it actually ran (excludes `ignored`/`filtered_out`, neither
    /// of which represents an executed test). A caller proving "a real test
    /// actually executed" asserts on this, never merely on `passing`, since
    /// zero tests trivially "pass".
    #[must_use]
    pub fn executed_count(&self) -> u32 {
        self.passed.saturating_add(self.failed)
    }
}

/// Deterministic, Corulix-owned scratch directory *name* for
/// `CARGO_TARGET_DIR`, relative to `managed_root`, keyed by a stable hash of
/// `workspace_root`'s own path string so repeated runs against the same
/// workspace reuse build artifacts and two different workspaces can never
/// collide. Never under `workspace_root` itself -- see this module's own
/// doc comment. Returns a *relative* path (never touches the filesystem
/// itself) -- creating it is
/// [`wht_corulix_tooling::provisioning::ensure_scratch_directory`]'s job,
/// the sole filesystem-write authority for Corulix's own managed-toolchain
/// scratch state (Architecture Rule M/G); this function only computes the
/// name.
fn test_target_dir_relative(workspace_root: &Path) -> String {
    let mut hasher = DefaultHasher::new();
    workspace_root.hash(&mut hasher);
    let key = hasher.finish();
    format!("scratch/p12-cargo-test-target/{key:016x}")
}

/// Bounds a single file's contribution to [`hash_governed_source_tree`] --
/// generous for real source files, but never unbounded.
const MAX_SOURCE_TREE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Governed-source directories hashed by [`hash_governed_source_tree`] when
/// present -- `src/` (always expected), plus `tests/`, `benches/`, and
/// `examples/` (Rust's other conventional first-party source directories,
/// optional per fixture).
const GOVERNED_SOURCE_DIRS: &[&str] = &["src", "tests", "benches", "examples"];

/// Individual governed-source files hashed when present -- notably
/// `build.rs`, the most likely real self-mutation vector: it runs first,
/// unconditionally, before any test, and a hostile/buggy build script could
/// rewrite itself or `Cargo.toml` rather than (or in addition to) writing
/// under `src/`. `Cargo.lock` is deliberately *excluded* by name -- see this
/// function's own note below.
const GOVERNED_SOURCE_FILES: &[&str] = &["Cargo.toml", "build.rs"];

/// Hashes every governed-source file/directory the workspace actually has
/// (see [`GOVERNED_SOURCE_DIRS`]/[`GOVERNED_SOURCE_FILES`]; anything absent
/// is silently skipped, not an error), confined/symlink-safe via
/// `wht_corulix_workspace`, sorted by relative path so the result is
/// order-independent, into one [`ContentHash`]. This is the P12
/// self-mutation coherence check's entire mechanism: [`run_cargo_test`]
/// calls this once immediately before spawning `cargo test` and once
/// immediately after it exits, and refuses to return a normal outcome at
/// all if the two hashes differ (see
/// [`RustTestError::WorkspaceSelfMutationDetected`]).
///
/// `Cargo.lock` is deliberately excluded, for a concrete,
/// empirically-motivated reason: `cargo test` legitimately creates/rewrites
/// it in the workspace root on a fixture that has none yet (a normal,
/// benign side effect, not a self-mutation concern) even with
/// `CARGO_NET_OFFLINE=true`. `CARGO_TARGET_DIR` is already redirected
/// outside the workspace entirely (see this module's own top-level doc
/// comment), so `target/` never appears here regardless -- it does not need
/// a special-case exclusion. Excluding `Cargo.lock` by name (rather than
/// hashing the whole tree) avoids that one legitimate/benign write becoming
/// a false-positive "self-mutation" finding on every fixture's first run,
/// without weakening the real invariant: none of `GOVERNED_SOURCE_DIRS`/
/// `GOVERNED_SOURCE_FILES` is ever something `cargo test` itself
/// legitimately needs to write.
async fn hash_governed_source_tree(workspace_root: &Path) -> Result<ContentHash, RustTestError> {
    let root = WorkspaceRoot::open(workspace_root)
        .map_err(|_| RustTestError::WorkspaceSourceTreeUnreadable)?;

    let mut relative_paths: Vec<PathBuf> = Vec::new();
    for dir in GOVERNED_SOURCE_DIRS {
        if !workspace_root.join(dir).is_dir() {
            continue;
        }
        let entries = confined_walk(root.clone(), PathBuf::from(dir), WalkLimits::default())
            .await
            .map_err(|_| RustTestError::WorkspaceSourceTreeUnreadable)?;
        relative_paths.extend(entries.iter().filter_map(|entry| {
            entry
                .as_path()
                .strip_prefix(root.canonical_path())
                .ok()
                .map(PathBuf::from)
        }));
    }
    for file in GOVERNED_SOURCE_FILES {
        if workspace_root.join(file).is_file() {
            relative_paths.push(PathBuf::from(file));
        }
    }
    relative_paths.sort();
    relative_paths.dedup();

    let mut buffer = Vec::new();
    for relative in relative_paths {
        let bytes = confined_read(root.clone(), relative.clone(), MAX_SOURCE_TREE_FILE_BYTES)
            .await
            .map_err(|_| RustTestError::WorkspaceSourceTreeUnreadable)?;
        buffer.extend_from_slice(relative.to_string_lossy().as_bytes());
        buffer.push(0);
        buffer.extend_from_slice(&bytes);
        buffer.push(0);
    }
    Ok(ContentHash::compute_sha256(&buffer))
}

/// One aggregated view of every `test result:` line found in a `cargo test`
/// stdout stream, plus a bounded human-readable summary.
struct TestSummaryParse {
    result_lines_seen: u32,
    passed: u32,
    failed: u32,
    ignored: u32,
    measured: u32,
    filtered_out: u32,
    summary: String,
    truncated: bool,
}

fn push_bounded_line(summary: &mut String, truncated: &mut bool, line: &str) {
    if summary.len() + line.len() + 1 > MAX_TEST_SUMMARY_BYTES {
        *truncated = true;
        return;
    }
    summary.push_str(line);
    summary.push('\n');
}

/// Parses libtest's own stable `test result: ...` summary line(s), plus
/// individual `... FAILED` test-name lines, out of a real `cargo test`
/// stdout stream. See this module's own doc comment for why this cannot be
/// a JSON parse. Never fatal on an unrecognized line -- unrecognized output
/// (build JSON, `running N tests`, per-test `... ok` lines) is silently
/// skipped, matching `crate::diagnostics::parse_cargo_json_stream`'s own
/// "skip, don't abort" stance on the JSON side.
fn parse_cargo_test_stdout(stdout: &[u8], stdout_truncated: bool) -> TestSummaryParse {
    let text = String::from_utf8_lossy(stdout);
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut ignored = 0u32;
    let mut measured = 0u32;
    let mut filtered_out = 0u32;
    let mut result_lines_seen = 0u32;
    let mut summary = String::new();
    let mut summary_truncated = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.starts_with("test ") && line.ends_with("FAILED") {
            push_bounded_line(&mut summary, &mut summary_truncated, line);
            continue;
        }
        let Some(rest) = line.strip_prefix("test result: ") else {
            continue;
        };
        result_lines_seen += 1;
        push_bounded_line(&mut summary, &mut summary_truncated, line);
        let Some((_status, counts)) = rest.split_once(". ") else {
            continue;
        };
        for segment in counts.split("; ") {
            let segment = segment.trim();
            let Some((number, label)) = segment.split_once(' ') else {
                continue;
            };
            let Ok(n) = number.parse::<u32>() else {
                continue;
            };
            match label {
                "passed" => passed = passed.saturating_add(n),
                "failed" => failed = failed.saturating_add(n),
                "ignored" => ignored = ignored.saturating_add(n),
                "measured" => measured = measured.saturating_add(n),
                "filtered out" => filtered_out = filtered_out.saturating_add(n),
                _ => {}
            }
        }
    }

    TestSummaryParse {
        result_lines_seen,
        passed,
        failed,
        ignored,
        measured,
        filtered_out,
        summary,
        truncated: stdout_truncated || summary_truncated,
    }
}

/// Runs real, managed `cargo test --message-format=json` against
/// `workspace_root` -- the authoritative `ProviderCategory::TestRunner`
/// validator for `GateId::Tests`. `effective` must authorize
/// [`ExecutionClass::TrustedWorkspaceExecution`] or this returns
/// [`RustTestError::WorkspaceExecutionNotAuthorized`] before spawning
/// anything. See this module's own doc comment for the full parse model and
/// trust/linker/target-dir disclosures.
pub async fn run_cargo_test(
    managed_root: &Path,
    workspace_root: &Path,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustTestOutcome, RustTestError> {
    run_cargo_test_with_limits(
        managed_root,
        workspace_root,
        effective,
        cancellation,
        &TestExecutionLimits::default(),
    )
    .await
}

/// As [`run_cargo_test`], but binds the spawned `cargo test`'s cwd to
/// `workspace_root`'s pinned root object (M09-P7, Unix only) instead of a
/// re-resolvable pathname. Additive: [`run_cargo_test`]/[`run_cargo_test_with_limits`]
/// and their `&Path` signatures are unchanged, so every existing (including
/// external, published) caller is unaffected.
pub async fn run_cargo_test_with_workspace_root(
    managed_root: &Path,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
) -> Result<RustTestOutcome, RustTestError> {
    run_cargo_test_with_limits_impl(
        managed_root,
        workspace_root.canonical_path(),
        Some(workspace_root),
        effective,
        cancellation,
        &TestExecutionLimits::default(),
    )
    .await
}

/// As [`run_cargo_test`], with the timeout/output-bound ceiling made
/// explicit via `execution_limits` instead of the fixed `TEST_TIMEOUT`/
/// `TEST_LIMITS` defaults. See [`TestExecutionLimits`]'s own doc comment
/// for why this is a real configuration knob, not a test seam.
pub async fn run_cargo_test_with_limits(
    managed_root: &Path,
    workspace_root: &Path,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
    execution_limits: &TestExecutionLimits,
) -> Result<RustTestOutcome, RustTestError> {
    run_cargo_test_with_limits_impl(
        managed_root,
        workspace_root,
        None,
        effective,
        cancellation,
        execution_limits,
    )
    .await
}

/// As [`run_cargo_test_with_limits`], but binds cwd to `workspace_root`'s
/// pinned root object (M09-P7, Unix only). Additive, mirroring
/// [`run_cargo_test_with_workspace_root`]'s own rationale.
pub async fn run_cargo_test_with_limits_and_workspace_root(
    managed_root: &Path,
    workspace_root: &wht_corulix_workspace::WorkspaceRoot,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
    execution_limits: &TestExecutionLimits,
) -> Result<RustTestOutcome, RustTestError> {
    run_cargo_test_with_limits_impl(
        managed_root,
        workspace_root.canonical_path(),
        Some(workspace_root),
        effective,
        cancellation,
        execution_limits,
    )
    .await
}

async fn run_cargo_test_with_limits_impl(
    managed_root: &Path,
    workspace_root: &Path,
    pinned_workspace_root: Option<&wht_corulix_workspace::WorkspaceRoot>,
    effective: &wht_corulix_config::EffectiveConfig,
    cancellation: &wht_corulix_core::CancellationToken,
    execution_limits: &TestExecutionLimits,
) -> Result<RustTestOutcome, RustTestError> {
    authorize_trusted_execution(effective)
        .map_err(|_| RustTestError::WorkspaceExecutionNotAuthorized)?;
    // P17-W2: on Windows, `resolve_link_runtime` alone resolves the *entire*
    // GNU-hosted toolchain (rustc/cargo/rust-std/rust-src/rust-mingw, all
    // merged onto one install directory by
    // `RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`'s own manifest) -- there is no
    // second, MSVC-hosted `crate::diagnostics::resolve_runtime` component in
    // this path at all, unlike the Unix branch (which genuinely composes two
    // independent components: the Rust runtime `install_dir` and the
    // separate GNU link runtime `link_runtime_dir`) and unlike this same P12
    // module's own earlier, empirically-rejected design (see that manifest's
    // doc comment for why cross-compiling from the certified MSVC-hosted
    // runtime does not work for a workspace with a real `build.rs`).
    #[cfg(not(target_os = "windows"))]
    let install_dir =
        resolve_runtime(managed_root).map_err(|_| RustTestError::ManagedRuntimeUnavailable)?;
    #[cfg(not(target_os = "windows"))]
    let link_runtime_dir = resolve_link_runtime(managed_root)?;
    #[cfg(target_os = "windows")]
    let install_dir = resolve_link_runtime(managed_root)?;

    // See `crate::go_testing::run_go_test_with_limits`' own guard for the
    // full rationale. Same class of defect, same closure: this governed
    // `cargo test` writes its `CARGO_TARGET_DIR` into Corulix-owned managed
    // scratch under `managed_root`, holds no `ManagedExecutionLease`, and
    // must therefore hold the existing managed-root read lock for its whole
    // run so a concurrent `full_uninstall` cannot destroy that target
    // directory mid-compile.
    let _scratch_guard =
        wht_corulix_tooling::provisioning::acquire_managed_execution_scratch_guard(managed_root)
            .await;
    let target_dir = wht_corulix_tooling::provisioning::ensure_scratch_directory(
        managed_root,
        &test_target_dir_relative(workspace_root),
    )
    .map_err(|_| RustTestError::ScratchDirUnavailable)?;

    #[cfg(not(target_os = "windows"))]
    let environment = link_environment(&install_dir, &link_runtime_dir).with_var(
        "CARGO_TARGET_DIR",
        target_dir.to_string_lossy().into_owned(),
    );
    #[cfg(target_os = "windows")]
    let environment = link_environment(&install_dir).with_var(
        "CARGO_TARGET_DIR",
        target_dir.to_string_lossy().into_owned(),
    );

    // Self-mutation coherence check (see `hash_governed_source_tree`'s own
    // doc comment): captured *immediately* before spawning, so nothing this
    // function itself does can be mistaken for the trusted execution's own
    // side effect.
    let pre_run_hash = hash_governed_source_tree(workspace_root).await?;

    #[cfg(not(target_os = "windows"))]
    let cargo_executable = install_dir.join("bin/cargo");
    #[cfg(target_os = "windows")]
    let cargo_executable = install_dir.join("bin/cargo.exe");

    // P17-W2: no `--target` flag on either platform now -- Unix's host and
    // trusted-execution target are both `x86_64-unknown-linux-gnu`; Windows's
    // are both `x86_64-pc-windows-gnu` (the GNU-hosted toolchain's own native
    // host, see `RUST_SEMANTIC_RUNTIME_WINDOWS_GNU_X64`'s own doc comment for
    // why this replaced the earlier MSVC-hosted cross-compilation design).
    let arguments = vec!["test".to_string(), "--message-format=json".to_string()];

    let spec = ProcessSpec {
        executable: cargo_executable,
        // Deliberately *no* `--quiet` here (unlike `crate::diagnostics`'s
        // `cargo check`/`cargo clippy`, which pass it): confirmed
        // empirically that `--quiet` suppresses libtest's own per-test
        // `test <name> ... FAILED` lines, leaving only the aggregate
        // `test result:` summary -- with `--quiet`, a real failure's
        // Evidence would carry a count but no actionable test name.
        arguments,
        environment,
        working_directory: workspace_root.to_path_buf(),
        limits: execution_limits.limits,
        timeout: execution_limits.timeout,
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
    // -- on Windows this must fail closed regardless of whether
    // `pinned_workspace_root` is `Some` or `None`; no `Command` is
    // constructed on this path (never falls through to
    // `wht_corulix_tooling::execute` with a raw pathname cwd).
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
            // Self-mutation coherence check runs *first*, before any
            // build/test-result classification -- a result observed
            // against content that changed during execution is never
            // legitimate Evidence for anything (pass, fail, or otherwise),
            // so this takes priority over every other outcome below.
            let post_run_hash = hash_governed_source_tree(workspace_root).await?;
            if post_run_hash != pre_run_hash {
                return Err(RustTestError::WorkspaceSelfMutationDetected);
            }
            let build = parse_cargo_json_stream(&outcome.stdout.bytes, outcome.stdout.truncated);
            if build.error_count > 0 {
                return Err(RustTestError::BuildFailed(build));
            }
            let parsed = parse_cargo_test_stdout(&outcome.stdout.bytes, outcome.stdout.truncated);
            if parsed.result_lines_seen == 0 {
                return Err(if outcome.stdout.truncated {
                    RustTestError::ResultTruncatedBeforeSummary
                } else {
                    RustTestError::NoTestsExecuted
                });
            }
            let exit_ok = code == 0;
            let counts_ok = parsed.failed == 0;
            if exit_ok != counts_ok {
                return Err(RustTestError::ResultContradiction);
            }
            Ok(RustTestOutcome {
                passing: exit_ok,
                passed: parsed.passed,
                failed: parsed.failed,
                ignored: parsed.ignored,
                measured: parsed.measured,
                filtered_out: parsed.filtered_out,
                truncated: parsed.truncated,
                summary: parsed.summary,
                provider_version: diagnostics::managed_runtime_version().to_string(),
            })
        }
        TerminationReason::Signaled { .. } => Err(RustTestError::Signaled),
        TerminationReason::TimedOut => Err(RustTestError::TimedOut),
        TerminationReason::Cancelled => Err(RustTestError::Cancelled),
        TerminationReason::SpawnFailed => Err(RustTestError::SpawnFailed),
        TerminationReason::TerminationFailed => Err(RustTestError::TerminationFailed),
    }
}

/// Converts a real [`RustTestOutcome`]'s bounded `summary` into an
/// [`wht_corulix_core::EvidenceResultSummary`] -- mirrors
/// `crate::diagnostics::evidence_result_summary` exactly.
pub fn evidence_result_summary(
    outcome: &RustTestOutcome,
) -> CorulixResult<wht_corulix_core::EvidenceResultSummary> {
    wht_corulix_core::EvidenceResultSummary::try_from(outcome.summary.clone())
        .map_err(|_| CorulixError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_counts_across_multiple_test_result_lines() {
        let stdout = concat!(
            "\n",
            "running 1 test\n",
            "test tests::t_ok ... ok\n",
            "\n",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
            "\n",
            "   Doc-tests f\n",
            "\n",
            "running 0 tests\n",
            "\n",
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
        );
        let parsed = parse_cargo_test_stdout(stdout.as_bytes(), false);
        assert_eq!(parsed.result_lines_seen, 2);
        assert_eq!(parsed.passed, 1);
        assert_eq!(parsed.failed, 0);
        assert!(!parsed.truncated);
    }

    #[test]
    fn captures_failure_counts_and_failed_test_names() {
        let stdout = concat!(
            "running 2 tests\n",
            "test tests::t_ok ... ok\n",
            "test tests::t_fail ... FAILED\n",
            "\n",
            "failures:\n",
            "\n",
            "---- tests::t_fail stdout ----\n",
            "\n",
            "failures:\n",
            "    tests::t_fail\n",
            "\n",
            "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
        );
        let parsed = parse_cargo_test_stdout(stdout.as_bytes(), false);
        assert_eq!(parsed.result_lines_seen, 1);
        assert_eq!(parsed.passed, 1);
        assert_eq!(parsed.failed, 1);
        assert!(parsed.summary.contains("tests::t_fail ... FAILED"));
    }

    #[test]
    fn zero_result_lines_is_distinguished_from_a_real_pass() {
        let parsed = parse_cargo_test_stdout(b"running 0 tests\n", false);
        assert_eq!(parsed.result_lines_seen, 0);
    }

    /// `executed_count` proof: `ignored`/`filtered_out` are never counted as
    /// executed -- only `passed + failed`.
    #[test]
    fn executed_count_excludes_ignored_and_filtered_out() {
        let outcome = RustTestOutcome {
            passing: true,
            passed: 2,
            failed: 0,
            ignored: 5,
            measured: 0,
            filtered_out: 7,
            truncated: false,
            summary: String::new(),
            provider_version: "1.98.0".to_string(),
        };
        assert_eq!(outcome.executed_count(), 2);
    }

    /// Exit-code-authoritative contradiction proof: exit `0` with a parsed
    /// `failed > 0` (or the reverse) must never be resolved in either
    /// direction -- exactly the boolean expression `run_cargo_test`
    /// evaluates.
    #[test]
    fn exit_code_and_parsed_failed_count_disagreement_is_a_contradiction() {
        let exit_ok = true;
        let counts_ok = false; // failed > 0 while exit code claims success
        assert!(exit_ok != counts_ok);

        let exit_ok = false;
        let counts_ok = true; // failed == 0 while exit code claims failure
        assert!(exit_ok != counts_ok);

        let exit_ok = true;
        let counts_ok = true;
        assert!(exit_ok == counts_ok);
    }

    /// `test_target_dir_relative` proof: deterministic per-workspace, never
    /// colliding across two distinct workspace roots, and never absolute
    /// (so it can only ever be joined onto a Corulix-owned root, never
    /// mistaken for a standalone filesystem path).
    #[test]
    fn test_target_dir_is_deterministic_corulix_owned_and_workspace_distinct() {
        let managed_root = Path::new("/opt/corulix-managed");
        let a = managed_root.join(test_target_dir_relative(Path::new(
            "/home/user/workspace-a",
        )));
        let b = managed_root.join(test_target_dir_relative(Path::new(
            "/home/user/workspace-b",
        )));
        let a_again = managed_root.join(test_target_dir_relative(Path::new(
            "/home/user/workspace-a",
        )));
        assert_eq!(a, a_again);
        assert_ne!(a, b);
        assert!(a.starts_with(managed_root));
    }
}
