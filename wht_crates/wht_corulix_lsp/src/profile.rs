// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed, per-language provider identity (Architecture Rule P). Replaces
//! any hypothetical Rust-only string-switch routing: every language this
//! crate supports is described by exactly one [`LspProviderProfile`], and
//! every session-lifecycle behavior that varies by provider (`textDocument/
//! didOpen` `languageId`, `initialize`'s `initializationOptions`/
//! `capabilities.experimental`, and the readiness signal proven empirically
//! for that provider) is read from the profile rather than hard-coded in
//! `crate::session`.
//!
//! `ReadinessStrategy` and `LspProviderProfile` are both `#[non_exhaustive]`
//! (matching this workspace's own convention on `wht_corulix_core::{LanguageId,
//! ProviderCategory, CapabilityState}`): a future language's profile is an
//! additive variant/field, never a breaking change to this module's public
//! shape.

use std::path::PathBuf;
use std::time::Duration;

use wht_corulix_core::{LanguageId, ProviderCategory};
use wht_corulix_tooling::EnvironmentPolicy;
use wht_corulix_workspace::WorkspaceRoot;

use crate::error::LspError;

/// How this crate proves a spawned language server has finished enough of
/// its initial analysis pass that an empty semantic answer becomes
/// authoritative (`SEMANTIC_NOT_READY != ZERO_RESULTS`). Never sleep-based;
/// every variant here is a real signal a real provider was empirically
/// observed to emit during this phase's own capability probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadinessStrategy {
    /// rust-analyzer's `experimental/serverStatus` extension:
    /// `health == "ok" && quiescent == true`. Requires
    /// `capabilities.experimental.serverStatusNotification = true` in
    /// `initialize`, or the notification is never emitted at all (proven
    /// during Phase 7's own research gate).
    ServerStatusNotification,
    /// No vendor readiness extension exists for this provider. Treats the
    /// first `textDocument/publishDiagnostics` notification received for
    /// *any* opened document as proof the server has completed its initial
    /// workspace/package load. Empirically validated against a real gopls
    /// process during this phase's capability probe: gopls's
    /// `window/showMessage "Finished loading packages."` and its first
    /// `publishDiagnostics` for the just-opened fixture both land at the
    /// same event boundary, and gopls has no `experimental/serverStatus`
    /// (or equivalent) notification at all -- this is the strongest real
    /// signal this provider exposes, not a fallback of convenience.
    FirstDiagnosticsPublished,
    /// TypeScript 7's native LSP (`serverInfo.name == "typescript-go"`),
    /// admitted this phase. This provider's `initialize` capabilities
    /// declare `diagnosticProvider` (the LSP 3.17 *pull* model,
    /// `workspaceDiagnostics: false`) rather than an unconditional push
    /// guarantee, and this phase's own capability probe proved the
    /// consequence empirically: for a file with a real diagnostic to
    /// report, this server *does* proactively push an unsolicited
    /// `textDocument/publishDiagnostics` after `didOpen` -- but for a
    /// clean, error-free file it pushes nothing at all, ever.
    /// `FirstDiagnosticsPublished` would therefore hang indefinitely on
    /// exactly the common case (a valid file), which is precisely how this
    /// strategy was discovered to be necessary: the real E2E first failed
    /// with `NotReady` after 60s against a clean fixture, and adding a raw
    /// JSON-RPC probe using this exact server showed zero
    /// `publishDiagnostics` notifications despite a healthy, completed
    /// compile. `crate::session::LspSession::ensure_open` instead *actively*
    /// issues one `textDocument/diagnostic` pull request immediately after
    /// `didOpen` and records [`Readiness::Ready`](crate::readiness::Readiness::Ready)
    /// on receiving any real response (proven to return promptly, in
    /// single-digit milliseconds, once the document's snapshot is loaded) --
    /// this is not a fallback of convenience either: it is the only signal
    /// this provider's own declared capabilities actually promise.
    FirstPullDiagnosticsResponse,
}

/// One external tool, beyond the language-server binary itself, a provider
/// needs on its own `PATH` to function (e.g. gopls shells out to `go`).
/// Resolved exclusively through `wht_corulix_config::resolve_provider`
/// (Rule K) -- never ambient `PATH` -- by `resolve_environment`.
#[derive(Debug, Clone, Copy)]
pub struct AuxiliaryToolRequirement {
    pub provider_name: &'static str,
    pub category: ProviderCategory,
}

/// Everything `crate::session::LspSession::spawn` needs to run one language
/// server correctly and safely, without hard-coding any provider's identity.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LspProviderProfile {
    pub language: LanguageId,
    /// Stable identity for logs/evidence -- never a raw process path.
    pub provider_id: &'static str,
    /// The exact string sent as `textDocument/didOpen`'s
    /// `TextDocumentItem.languageId`.
    pub lsp_language_id: &'static str,
    pub readiness_strategy: ReadinessStrategy,
    pub readiness_timeout: Duration,
    /// `initialize`'s `capabilities.experimental` fragment, if this
    /// provider requires one to unlock its readiness signal.
    pub experimental_capability: Option<fn() -> serde_json::Value>,
    /// `initialize`'s `initializationOptions`, if this provider requires
    /// one -- most importantly to enforce `UNTRUSTED_LSP_WORKSPACE_CODE_EXECUTION_COUNT=0`
    /// (see [`Self::rust_analyzer`]).
    pub initialization_options: Option<fn() -> serde_json::Value>,
    /// External tools this provider needs on its own resolved `PATH` (see
    /// [`resolve_launch`]).
    pub auxiliary_tools: &'static [AuxiliaryToolRequirement],
    /// Additional literal environment variables this provider needs beyond
    /// the auxiliary-tool `PATH` entries (e.g. `GOFLAGS=-mod=readonly`).
    /// Never a credential/secret; `CREDENTIAL_FORWARDING_DEFAULT=DENY`
    /// remains unaffected -- these are provider-behavior flags only.
    pub literal_environment: &'static [(&'static str, &'static str)],
    /// If `Some`, this provider's own resolved `LanguageServer` path is a
    /// script (`#!/usr/bin/env <interpreter>`), never executed directly --
    /// executing it would delegate interpreter lookup to `env`'s own
    /// ambient-`PATH` search, which this crate's sanitized child
    /// environment does not provide and must not route around
    /// (`AMBIENT_PATH_NODE_AUTHORITY=NO`). Instead [`resolve_launch`]
    /// resolves the named interpreter as its own auxiliary tool (exactly
    /// like [`Self::auxiliary_tools`], via `resolve_provider`) and invokes
    /// it directly as the process executable, with the resolved script
    /// path as an explicit `argv[1]` -- the shebang line itself is never
    /// read or relied upon.
    pub interpreter: Option<AuxiliaryToolRequirement>,
    /// Extra literal arguments appended after the script path (or, for a
    /// native-executable provider with `interpreter: None`, the sole
    /// arguments) -- e.g. `["--stdio"]`.
    pub extra_arguments: &'static [&'static str],
    /// If `Some`, this provider is resolved from Corulix's own managed
    /// toolchain *first* (`CORULIX_MANAGED` precedence, Phase 7B-A) --
    /// [`resolve_launch`] checks `wht_corulix_tooling::provisioning::resolve_managed_component`
    /// before ever consulting `wht_corulix_config::resolve_provider`'s
    /// `HOST_ONLY`/system/user-toolchain precedence for this provider's
    /// own `LanguageServer` category. A provider with `None` here is
    /// entirely unaffected -- it resolves exactly as it always has, through
    /// `wht_corulix_config::resolve_provider` alone.
    pub managed_component: Option<wht_corulix_tooling::provisioning::ManagedComponentManifest>,
    /// Same `CORULIX_MANAGED`-first precedence as [`Self::managed_component`],
    /// applied to [`Self::interpreter`] specifically. A script provider
    /// whose interpreter is *also* Corulix-managed (e.g. managed Pyright's
    /// managed Node) sets both fields; `resolve_launch` resolves the
    /// interpreter through the managed toolchain first, falling back to the
    /// existing `HOST_ONLY`/system precedence unchanged when this is `None`
    /// or the managed artifact is not yet provisioned.
    pub managed_interpreter: Option<wht_corulix_tooling::provisioning::ManagedComponentManifest>,
    /// If `Some`, this provider additionally requires a full managed Rust
    /// semantic runtime (`rustc` + `cargo` + `rust-std` + `rust-src`, merged
    /// -- see `wht_corulix_lsp::managed_toolchain::RUST_SEMANTIC_RUNTIME_LINUX_X64`)
    /// on its resolved `PATH`, with `CARGO`/`RUSTC` set to the merged
    /// install's own `bin/cargo`/`bin/rustc` (Phase 7B-B1-R1). Unlike
    /// [`Self::managed_interpreter`], this has **no system fallback**: a
    /// provider declaring this field resolves the runtime from
    /// `CORULIX_MANAGED` only, and `resolve_launch` fails closed
    /// (`ProviderSpawnFailed`) rather than falling back to an ambient/
    /// `HOST_ONLY` system Rust toolchain if it is not yet provisioned --
    /// this is precisely the field whose presence is what makes
    /// `RUST_SEMANTIC_RUNTIME_SELF_CONTAINED=YES` a structural guarantee
    /// rather than a claim, for the specific profile that sets it
    /// ([`Self::rust_analyzer_managed`]). [`Self::rust_analyzer`] (unmanaged)
    /// leaves this `None` and is entirely unaffected.
    pub managed_rust_semantic_runtime:
        Option<wht_corulix_tooling::provisioning::ManagedComponentManifest>,
    /// If `Some`, this provider additionally requires a full managed Go
    /// semantic runtime (`go` + `gofmt` + the stdlib source tree, merged --
    /// see `wht_corulix_lsp::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64`)
    /// on its resolved `PATH`, with `GOROOT` set to the merged install root
    /// and `GOPATH`/`GOCACHE`/`GOMODCACHE` pointed at a Corulix-owned
    /// scratch directory when the managed tier resolves (Phase 7B-B2-A-R2).
    ///
    /// **M03 Go LSP/toolchain parity port**: unlike
    /// [`Self::managed_rust_semantic_runtime`] (still genuinely
    /// `CORULIX_MANAGED`-only, no fallback), this field's resolution now
    /// carries the same managed-first-then-explicit-`HOST_ONLY`-fallback
    /// policy `wht_corulix_engine::go_providers::resolve_go_toolchain`
    /// already established for `go build`/`go vet`/`go test` (Stage A /
    /// P17-W Master Closure Order) -- see [`resolve_launch_at`]'s own
    /// go-runtime block for the ported logic. Before this port, this field
    /// had no fallback at all, which was a genuine parity gap against the
    /// already-shipped toolchain policy for the identical underlying
    /// component, not a deliberate security boundary: falling through to an
    /// explicitly-approved `HOST_ONLY` `go` never grants the managed
    /// directory's contents any authority, and ambient `PATH` is never
    /// consulted either way (`AMBIENT_PATH_AUTHORITY=NO` unaffected).
    /// [`Self::gopls`] (unmanaged) leaves this `None` and is entirely
    /// unaffected.
    pub managed_go_semantic_runtime:
        Option<wht_corulix_tooling::provisioning::ManagedComponentManifest>,
    /// If `Some`, this provider additionally requires the managed classic
    /// TypeScript 6 runtime (`typescript@6.x`'s own `lib/tsserver.js` --
    /// see `wht_corulix_lsp::managed_toolchain::TYPESCRIPT_6_LINUX_X64`),
    /// resolved from `CORULIX_MANAGED` only (no system/workspace fallback,
    /// matching [`Self::managed_rust_semantic_runtime`]/
    /// [`Self::managed_go_semantic_runtime`]'s own no-fallback model, so
    /// `WORKSPACE_TYPESCRIPT_AUTHORITY=NO`/`SYSTEM_TYPESCRIPT_AUTHORITY=NO`
    /// are structural guarantees rather than claims). Unlike the Rust/Go
    /// runtimes, this is never put on `PATH` or exposed via an environment
    /// variable -- `resolve_launch_at` resolves its `lib/tsserver.js` path
    /// directly and injects it as `initializationOptions.tsserver.path`
    /// (Phase 7B-C's own research proved this is checked *before* any
    /// workspace/bundled resolution `typescript-language-server` would
    /// otherwise perform). [`Self::typescript_language_server`]/
    /// [`Self::typescript_language_server_for_javascript`] (unmanaged)
    /// leave this `None` and are entirely unaffected.
    pub managed_typescript_6_runtime:
        Option<wht_corulix_tooling::provisioning::ManagedComponentManifest>,
}

impl LspProviderProfile {
    /// rust-analyzer, regression-audited during this phase's security
    /// rebaseline. `initializationOptions` explicitly disables
    /// `cargo.buildScripts.enable` and `procMacro.enable` -- both execute
    /// repository-authored code (build scripts / proc macros) and default
    /// to *enabled* upstream. This crate has no workspace-trust input wired
    /// to it yet (no caller currently grants `TRUSTED_WORKSPACE_EXECUTION`
    /// to an `LspSession`), so the safe, fail-closed default is to disable
    /// both unconditionally rather than assume trust -- this is the
    /// concrete fix for the gap this phase's security rebaseline found:
    /// before this profile existed, `initialize` sent no
    /// `initializationOptions` at all, leaving both at their
    /// code-executing upstream defaults.
    #[must_use]
    pub const fn rust_analyzer() -> Self {
        Self {
            language: LanguageId::Rust,
            provider_id: "rust-analyzer",
            lsp_language_id: "rust",
            readiness_strategy: ReadinessStrategy::ServerStatusNotification,
            readiness_timeout: Duration::from_secs(60),
            experimental_capability: Some(
                || serde_json::json!({ "serverStatusNotification": true }),
            ),
            initialization_options: Some(|| {
                serde_json::json!({
                    "cargo": { "buildScripts": { "enable": false } },
                    "procMacro": { "enable": false }
                })
            }),
            auxiliary_tools: &[],
            literal_environment: &[],
            interpreter: None,
            extra_arguments: &[],
            managed_component: None,
            managed_interpreter: None,
            managed_rust_semantic_runtime: None,
            managed_go_semantic_runtime: None,
            managed_typescript_6_runtime: None,
        }
    }

    /// `CORULIX_MANAGED` rust-analyzer (Phase 7B-B1-R1): the same provider
    /// identity, readiness model, and `initializationOptions` fail-closed
    /// security posture as [`Self::rust_analyzer`], but the server binary
    /// itself resolves from Corulix's own managed toolchain
    /// (`managed_component: Some(RUST_ANALYZER_LINUX_X64)`) and its Rust
    /// project/crate-graph/std resolution runs against Corulix's own
    /// managed Rust semantic runtime (`managed_rust_semantic_runtime:
    /// Some(RUST_SEMANTIC_RUNTIME_LINUX_X64)`) rather than any system
    /// `cargo`/`rustc`/`rustup`. Unlike [`Self::pyright_managed`]'s
    /// `managed_interpreter` (which falls back to a `HOST_ONLY`/system
    /// Node when unprovisioned), the Rust semantic runtime has **no
    /// fallback** here -- see [`Self::managed_rust_semantic_runtime`]'s doc
    /// comment. `CARGO_NET_OFFLINE=true` is set unconditionally: this
    /// profile's admitted use is workspace *inspection* (definition/
    /// references/diagnostics against an already-vendored/std-only
    /// fixture), not dependency resolution, so `cargo metadata`/`cargo
    /// check`'s own registry/index network access is denied by the same
    /// provider-specific offline flag this workspace already uses for
    /// Go (`GOPROXY=off`) -- `UNTRUSTED_RUST_NETWORK_DEPENDENCY_FETCH=NO`.
    #[must_use]
    pub const fn rust_analyzer_managed() -> Self {
        Self {
            managed_component: Some(crate::managed_toolchain::RUST_ANALYZER_HOST_NATIVE),
            managed_rust_semantic_runtime: Some(
                crate::managed_toolchain::RUST_SEMANTIC_RUNTIME_HOST_NATIVE,
            ),
            literal_environment: &[("CARGO_NET_OFFLINE", "true")],
            ..Self::rust_analyzer()
        }
    }

    /// gopls, admitted this phase. Verified upstream to have no
    /// `experimental/serverStatus`-equivalent notification (this phase's
    /// capability probe against a real gopls process observed zero such
    /// notifications across a full package-load cycle), hence
    /// [`ReadinessStrategy::FirstDiagnosticsPublished`] rather than reusing
    /// rust-analyzer's untested-for-gopls signal. `go list`/`go build`/`go
    /// vet` (which gopls shells out to) do not execute arbitrary
    /// repository-authored code the way a Cargo build script or proc macro
    /// does -- Go's module system has no equivalent hook -- but module
    /// resolution can still reach the network and can still rewrite
    /// `go.mod`, so `GOPROXY=off` and `GOFLAGS=-mod=readonly` are set
    /// unconditionally (`UNTRUSTED_LSP_WORKSPACE_CODE_EXECUTION_COUNT=0`
    /// preserved: no workspace-authored code executes as a side effect of
    /// these read-only, network-denied module operations).
    #[must_use]
    pub const fn gopls() -> Self {
        Self {
            language: LanguageId::Go,
            provider_id: "gopls",
            lsp_language_id: "go",
            readiness_strategy: ReadinessStrategy::FirstDiagnosticsPublished,
            readiness_timeout: Duration::from_secs(60),
            experimental_capability: None,
            initialization_options: None,
            auxiliary_tools: &[AuxiliaryToolRequirement {
                provider_name: "go",
                category: ProviderCategory::TypecheckBuild,
            }],
            literal_environment: &[("GOFLAGS", "-mod=readonly"), ("GOPROXY", "off")],
            interpreter: None,
            extra_arguments: &[],
            managed_component: None,
            managed_interpreter: None,
            managed_rust_semantic_runtime: None,
            managed_go_semantic_runtime: None,
            managed_typescript_6_runtime: None,
        }
    }

    /// `CORULIX_MANAGED` gopls (Phase 7B-B2-A-R2): the same provider
    /// identity and readiness model as [`Self::gopls`], but `go` resolves
    /// exclusively from Corulix's own managed Go semantic runtime
    /// (`managed_go_semantic_runtime: Some(GO_SEMANTIC_RUNTIME_HOST_NATIVE)`)
    /// rather than [`Self::gopls`]'s `auxiliary_tools`-based `HOST_ONLY`/
    /// system `go` resolution -- `auxiliary_tools` is therefore empty here,
    /// not merely unused; there is no fallback path left for it to guard.
    /// `managed_component` (the `gopls` binary itself) is
    /// `Some(`[`crate::managed_toolchain::GOPLS_HOST_NATIVE`]`)` as of Phase
    /// 7B-B2-A-R3A, closing the gap R2 left open: that manifest's identity
    /// fields (id/version/platform/architecture/`expected_sha256_hex`/
    /// `binary_path_in_tarball`/`archive_kind`) are the exact values Phase
    /// 7B-B2-A-R1 independently reproducibility-certified. Primary-binary
    /// resolution follows the same shared `CORULIX_MANAGED`-first-then-
    /// `HOST_ONLY` precedence as [`Self::rust_analyzer_managed`] and
    /// [`Self::pyright_managed`] (`resolve_managed_or_system_path`): the
    /// managed artifact is tried first, and only an unavailable/not-yet-
    /// provisioned managed component falls through to system `gopls`
    /// resolution -- this is the pre-existing, shared architecture, not a
    /// new gopls-specific fallback.
    ///
    /// **M03 Go LSP/toolchain parity port**: the Go *runtime* underneath it
    /// (`managed_go_semantic_runtime`) now carries the same
    /// managed-first-then-explicit-`HOST_ONLY`-fallback policy as the
    /// primary binary, ported from `wht_corulix_engine::go_providers`'s
    /// already-shipped Go-toolchain resolution (Stage A / P17-W Master
    /// Closure Order) rather than the strict no-fallback model
    /// [`Self::managed_rust_semantic_runtime`] still uses. See
    /// [`Self::managed_go_semantic_runtime`]'s own doc comment and
    /// [`resolve_launch_at`]'s go-runtime block.
    ///
    /// P17-W (Windows-native certification pass): both fields were migrated
    /// from the Linux-hardcoded [`crate::managed_toolchain::GOPLS_LINUX_X64`]/
    /// [`crate::managed_toolchain::GO_SEMANTIC_RUNTIME_LINUX_X64`] constants to
    /// the `#[cfg(target_os = "windows")]`-gated
    /// [`crate::managed_toolchain::GOPLS_HOST_NATIVE`]/
    /// [`crate::managed_toolchain::GO_SEMANTIC_RUNTIME_HOST_NATIVE`] aliases --
    /// the identical defect class, and identical fix, that
    /// `RUST_ANALYZER_HOST_NATIVE`/
    /// `RUST_SEMANTIC_RUNTIME_HOST_NATIVE`
    /// closed for [`Self::rust_analyzer_managed`] during P17-W-R4-C2. Before
    /// this fix, resolving this profile on a real Windows host would
    /// unconditionally look up the `platform: "linux"` identity of both
    /// manifests via `resolve_owned_managed_component`, which can never match
    /// what a real Windows provisioning run installs (`platform: "windows"`)
    /// -- `resolve_launch_at` would silently fail to find the managed
    /// artifacts and every gopls session on Windows would either fall back to
    /// an unmanaged system `gopls`/`go` (for the primary binary, which still
    /// has a `HOST_ONLY` fallback) or fail closed with `ProviderSpawnFailed`
    /// (for the Go semantic runtime, which has none) -- never an actual
    /// managed-Windows-runtime session. `GOPLS_HOST_NATIVE`'s `tarball_url` is
    /// inert on either platform (see that constant's own doc comment: real
    /// provisioning goes through `provision_go_module_build` with
    /// [`GOPLS_BUILD_SOURCE_HOST_NATIVE`](crate::managed_toolchain::GOPLS_BUILD_SOURCE_HOST_NATIVE),
    /// not the download-based `provision` pipeline this field's unreachable
    /// `tarball_url` would otherwise imply) -- this profile-level fix only
    /// changes which platform's *identity* `resolve_owned_managed_component`
    /// looks up on disk, not the provisioning mechanism itself.
    ///
    /// `literal_environment` hardens beyond [`Self::gopls`]'s own
    /// `GOFLAGS`/`GOPROXY`, empirically motivated by this phase's own
    /// adversarial probes (see `CHANGELOG.md`): `GOSUMDB=off` (redundant
    /// with `GOPROXY=off`'s own network denial, set explicitly for
    /// defense-in-depth rather than relying on one flag alone),
    /// `GOTOOLCHAIN=local` (a real hostile `go.mod`/`toolchain` directive
    /// requesting a newer Go was proven, without this, capable of
    /// triggering an automatic toolchain download/switch --
    /// `UNTRUSTED_GO_TOOLCHAIN_SWITCH_COUNT` must be `0`), `GOVCS=off`
    /// (blocks the Go command's own direct-VCS-fetch fallback for import
    /// paths not satisfied by the module proxy), and `GOENV=off` (a
    /// hostile `$HOME/.config/go/env` must not be read -- this crate's
    /// child processes never inherit the real user `$HOME` in the first
    /// place, but this closes the flag-level path too).
    #[must_use]
    pub const fn gopls_managed() -> Self {
        Self {
            auxiliary_tools: &[],
            literal_environment: &[
                ("GOFLAGS", "-mod=readonly"),
                ("GOPROXY", "off"),
                ("GOSUMDB", "off"),
                ("GOTOOLCHAIN", "local"),
                ("GOVCS", "off"),
                ("GOENV", "off"),
            ],
            managed_go_semantic_runtime: Some(
                crate::managed_toolchain::GO_SEMANTIC_RUNTIME_HOST_NATIVE,
            ),
            managed_component: Some(crate::managed_toolchain::GOPLS_HOST_NATIVE),
            ..Self::gopls()
        }
    }

    /// `typescript-language-server`, admitted this phase after evaluating it
    /// against `vtsls` (see `wht_docs/wht_adr/wht_0008-typescript-javascript-lsp-provider.md`):
    /// actively maintained, explicit `tsserver.path`/`plugins`/typing-
    /// acquisition controls, and no upstream reliability caveat, versus
    /// `vtsls`'s own README-documented "best-effort" reliability posture
    /// and bundled-TypeScript-by-default model. `initializationOptions`
    /// unconditionally sets `plugins: []` and
    /// `preferences.disableAutomaticTypingAcquisition: true`
    /// (`UNTRUSTED_TS_JS_PLUGIN_LOADING=NO`,
    /// `UNTRUSTED_TS_JS_AUTOMATIC_TYPE_ACQUISITION=NO`) -- this crate has no
    /// workspace-trust input wired to any `LspSession`, so both are
    /// disabled unconditionally rather than trust-conditionally, mirroring
    /// [`Self::rust_analyzer`]'s own fail-closed default. `tsserver.path`
    /// is deliberately left unset here (Core has no host-configuration
    /// surface for it yet); a caller resolving this profile in production
    /// must supply a host-approved `tsserver.path` override before
    /// `TYPESCRIPT_LSP_E2E`/`JAVASCRIPT_LSP_E2E` can be claimed `PASS` --
    /// see the ADR for why this host's own installed TypeScript (the
    /// native/Go-ported "tsgo" rewrite, which ships no `tsserver.js`)
    /// cannot itself serve as that path.
    #[must_use]
    pub const fn typescript_language_server() -> Self {
        Self {
            language: LanguageId::TypeScript,
            provider_id: "typescript-language-server",
            lsp_language_id: "typescript",
            readiness_strategy: ReadinessStrategy::FirstDiagnosticsPublished,
            readiness_timeout: Duration::from_secs(60),
            experimental_capability: None,
            initialization_options: Some(|| {
                serde_json::json!({
                    "plugins": [],
                    "preferences": { "disableAutomaticTypingAcquisition": true }
                })
            }),
            auxiliary_tools: &[],
            literal_environment: &[],
            interpreter: Some(AuxiliaryToolRequirement {
                provider_name: "node",
                category: ProviderCategory::Runtime,
            }),
            extra_arguments: &["--stdio"],
            managed_component: None,
            managed_interpreter: None,
            managed_rust_semantic_runtime: None,
            managed_go_semantic_runtime: None,
            managed_typescript_6_runtime: None,
        }
    }

    /// The same `typescript-language-server` provider identity, addressed
    /// under [`LanguageId::JavaScript`] -- `typescript-language-server`
    /// serves both languages through the same `tsserver`-backed process
    /// family, but Corulix certifies each language's real E2E separately
    /// (Section 13 of the Phase 7B mandate: "Do not infer JS PASS from TS
    /// PASS").
    #[must_use]
    pub const fn typescript_language_server_for_javascript() -> Self {
        Self {
            language: LanguageId::JavaScript,
            lsp_language_id: "javascript",
            ..Self::typescript_language_server()
        }
    }

    /// `CORULIX_MANAGED` `typescript-language-server` (Phase 7B-C): the
    /// TypeScript-6/JavaScript-6 compatibility backend. Three managed
    /// components resolve here, mirroring [`Self::pyright_managed`]'s
    /// managed-Node-interpreter pattern plus [`Self::rust_analyzer_managed`]/
    /// [`Self::gopls_managed`]'s no-fallback managed-semantic-runtime
    /// pattern in the same profile: `managed_component: Some(TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE)`
    /// (the server itself, falling back to `HOST_ONLY`/system if not yet
    /// provisioned -- matching Pyright's own precedent), `managed_interpreter:
    /// Some(NODE_24_LTS_HOST_NATIVE)` (the exact same managed Node identity
    /// [`Self::pyright_managed`] and rust-analyzer's Pyright sibling already
    /// share -- `NODE_RUNTIME_DUPLICATE_MANAGED_IDENTITY_COUNT=0`), and
    /// `managed_typescript_6_runtime: Some(TYPESCRIPT_6_HOST_NATIVE)` (no
    /// fallback: a hostile/absent workspace TypeScript must never become
    /// this provider's `tsserver.path` authority). `resolve_launch_at`
    /// resolves the TypeScript 6 runtime's `lib/tsserver.js` and injects it
    /// as `initializationOptions.tsserver.path` on top of this profile's own
    /// `initialization_options`, taking precedence over any workspace/
    /// bundled resolution `typescript-language-server` would otherwise
    /// perform (Phase 7B-C's own research, reading the real `cli.mjs`
    /// `findTypescriptVersion` implementation, proved the `tsserver.path`
    /// user-setting is checked first). **P17-W Stage D**: `_HOST_NATIVE`
    /// (not `_LINUX_X64` directly) for all three fields, closing this
    /// profile's own hardcoded-to-Linux defect -- `pyright_managed`'s
    /// equivalent `NODE_24_LTS_LINUX_X64` reference is a separate,
    /// still-open defect left for the Pyright stage.
    #[must_use]
    pub const fn typescript_language_server_managed() -> Self {
        Self {
            managed_component: Some(
                crate::managed_toolchain::TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE,
            ),
            managed_interpreter: Some(
                wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
            ),
            managed_typescript_6_runtime: Some(crate::managed_toolchain::TYPESCRIPT_6_HOST_NATIVE),
            ..Self::typescript_language_server()
        }
    }

    /// The managed TypeScript-6 backend, addressed under
    /// [`LanguageId::JavaScript`] -- the JavaScript-6 counterpart to
    /// [`Self::typescript_language_server_managed`], certified with its own
    /// separate real E2E (Section 13 of the Phase 7B mandate: "Do not infer
    /// JS PASS from TS PASS").
    #[must_use]
    pub const fn typescript_language_server_managed_for_javascript() -> Self {
        Self {
            language: LanguageId::JavaScript,
            lsp_language_id: "javascript",
            ..Self::typescript_language_server_managed()
        }
    }

    /// Pyright, admitted this phase after evaluating it against
    /// `python-lsp-server` (see
    /// `wht_docs/wht_adr/wht_0009-python-lsp-provider.md`): a static
    /// analyzer with no plugin-loading architecture at all (unlike
    /// `python-lsp-server`'s plugin model, whose formatter/linter plugin
    /// surface would overlap Phase 17's future, separately governed
    /// authority), so `UNTRUSTED_PYTHON_PLUGIN_LOADING=NO` holds
    /// structurally rather than by configuration. This phase's own
    /// capability probe against a real pyright process confirmed
    /// definition/references/document-symbol/diagnostics all resolve
    /// correctly from pure static analysis, with zero project-Python
    /// execution and zero network access, even with no Python interpreter
    /// resolvable in its (sanitized) environment at all
    /// (`UNTRUSTED_PYTHON_WORKSPACE_CODE_EXECUTION=NO`). Diagnostics push
    /// unsolicited immediately after `didOpen` in that same probe, so
    /// [`ReadinessStrategy::FirstDiagnosticsPublished`] applies exactly as
    /// it does for gopls -- no new readiness strategy was needed.
    #[must_use]
    pub const fn pyright() -> Self {
        Self {
            language: LanguageId::Python,
            provider_id: "pyright-langserver",
            lsp_language_id: "python",
            readiness_strategy: ReadinessStrategy::FirstDiagnosticsPublished,
            readiness_timeout: Duration::from_secs(60),
            experimental_capability: None,
            initialization_options: None,
            auxiliary_tools: &[],
            literal_environment: &[],
            interpreter: Some(AuxiliaryToolRequirement {
                provider_name: "node",
                category: ProviderCategory::Runtime,
            }),
            extra_arguments: &["--stdio"],
            managed_component: None,
            managed_interpreter: None,
            managed_rust_semantic_runtime: None,
            managed_go_semantic_runtime: None,
            managed_typescript_6_runtime: None,
        }
    }

    /// `CORULIX_MANAGED` Pyright (Phase 7B-B1): the same provider identity
    /// and readiness model as [`Self::pyright`], but both the Pyright
    /// script and its Node interpreter resolve from Corulix's own managed
    /// toolchain first (`managed_component: Some(PYRIGHT_HOST_NATIVE)`,
    /// `managed_interpreter: Some(NODE_24_LTS_HOST_NATIVE)`), falling back to
    /// the existing `HOST_ONLY`/system precedence unchanged for either one
    /// individually if its managed artifact is not yet provisioned. Never
    /// executes `dist/pyright-langserver.js` via its own shebang --
    /// [`resolve_launch`] always invokes the resolved Node interpreter
    /// directly with the resolved script path as an explicit `argv[1]`,
    /// exactly like [`Self::pyright`].
    ///
    /// P17-W: previously hardcoded to `PYRIGHT_LINUX_X64`/
    /// `NODE_24_LTS_LINUX_X64` regardless of host OS -- the same
    /// hardcoded-to-Linux defect class already closed for
    /// [`Self::rust_analyzer_managed`]/[`Self::typescript_language_server_managed`].
    /// Now resolves [`crate::managed_toolchain::PYRIGHT_HOST_NATIVE`]/
    /// [`wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE`],
    /// each `#[cfg(target_os = "windows")]`-gated to the real Windows
    /// manifest on Windows and the existing Linux manifest everywhere else.
    #[must_use]
    pub const fn pyright_managed() -> Self {
        Self {
            managed_component: Some(crate::managed_toolchain::PYRIGHT_HOST_NATIVE),
            managed_interpreter: Some(
                wht_corulix_tooling::managed_runtimes::NODE_24_LTS_HOST_NATIVE,
            ),
            ..Self::pyright()
        }
    }

    /// TypeScript 7's native LSP, admitted this phase
    /// (`TYPESCRIPT_7_PROVIDER=NATIVE_TYPESCRIPT_LSP`,
    /// `TYPESCRIPT_7_REQUIRES_TYPESCRIPT_LANGUAGE_SERVER=NO`,
    /// `TYPESCRIPT_7_REQUIRES_TSSERVER_JS=NO`). Empirically proven this
    /// phase against the real, official `@typescript/typescript-linux-x64`
    /// platform package (fetched fresh from the npm registry, not the
    /// incomplete local install that produced Phase 7B's earlier
    /// `TS7_NATIVE_LSP_CAPABILITY=ABSENT` misclassification): the flag is
    /// undocumented in `tsc --help --all` but real -- a raw JSON-RPC probe
    /// against `tsc --lsp --stdio` returns a genuine `initialize` result
    /// with `serverInfo.name == "typescript-go"` and `definitionProvider`/
    /// `referencesProvider`/`documentSymbolProvider`/
    /// `workspaceSymbolProvider`/`renameProvider.prepareProvider` all
    /// `true`. The binary is a statically-linked Go executable (`file`
    /// confirms no dynamic interpreter dependency), so `interpreter: None`
    /// here is not an assumption -- `TS7_NODE_RUNTIME_REQUIRED=NO` was
    /// proven by running it directly with no Node on the resolved `PATH`
    /// at all.
    ///
    /// Readiness uses the new [`ReadinessStrategy::FirstPullDiagnosticsResponse`],
    /// not [`ReadinessStrategy::FirstDiagnosticsPublished`] -- an initial
    /// probe against a fixture *with* a real type error observed an
    /// unsolicited `textDocument/publishDiagnostics` land immediately after
    /// `didOpen`, which looked like `FirstDiagnosticsPublished` applied
    /// unchanged; but the real E2E against a clean, error-free fixture then
    /// hung for the full 60s readiness timeout. A second, targeted probe
    /// against the exact same clean fixture proved why: this server never
    /// sends an unsolicited `publishDiagnostics` at all when a file has zero
    /// diagnostics to report -- proactive push is conditional on non-empty
    /// content, not an unconditional "initial pass complete" signal the way
    /// it is for gopls/Pyright. `crate::session::LspSession::ensure_open`
    /// therefore actively issues one `textDocument/diagnostic` pull request
    /// for this strategy and records readiness from its response, matching
    /// what this server's own `initialize` capabilities actually promise
    /// (`diagnosticProvider`, the LSP 3.17 pull model). (The same probe also
    /// found this server sends a `client/registerCapability` *request*, not
    /// merely a notification, immediately after `initialized`;
    /// `crate::transport::Transport` already auto-answers every
    /// server-to-client request with a null result on the exact same
    /// reader-loop path proven against rust-analyzer, so no change was
    /// needed there.)
    ///
    /// `initialization_options`/`experimental_capability` are both `None`:
    /// this server exposes no vendor `initializationOptions` surface at all
    /// (`grep` across the real binary found no `initializationOptions`/
    /// `UserPreferences`/`disableAutomaticTypingAcquisition` string). The
    /// untrusted-workspace guarantee this phase's security audit found
    /// necessary -- this server's compiled-in `internal/project/ata`
    /// package genuinely shells out to a real `npm install` for Automatic
    /// Type Acquisition on an inferred (no-`tsconfig`/`jsconfig`) JS
    /// project, proven empirically by opening a bare `require("lodash")`
    /// fixture and observing `"Triggering ATA for project ..."` plus a
    /// real, failed `npm install` attempt in the server's own log output --
    /// is therefore enforced structurally at the environment level, not via
    /// a config flag this provider does not expose: [`resolve_launch`]
    /// never adds `npm` to any resolved `PATH` entry for this profile
    /// (`auxiliary_tools` is empty and there is no `npm`-category resolver
    /// anywhere in this crate), so ATA's `os/exec.Command("npm", ...)` call
    /// structurally cannot resolve an `npm` binary regardless of what a
    /// hostile workspace's own `tsconfig.json`/`jsconfig.json` declares --
    /// proven by the same probe with a poisoned `PATH`, which produced
    /// `"ATA installation failed ... npm install failed"` rather than a
    /// successful install (`UNTRUSTED_TS7_PACKAGE_INSTALL=NO`). This
    /// server's Go binary was also found to contain zero plugin-loading
    /// infrastructure (`grep` for `languageServicePlugin`/`loadPlugin`/
    /// `pluginProbeLocation` returns nothing at all, structurally
    /// consistent with a Go rewrite that embeds no JavaScript runtime to
    /// `require()` a plugin module in the first place) --
    /// `UNTRUSTED_TS7_WORKSPACE_PLUGIN_EXECUTION=NO` holds structurally,
    /// mirroring [`Self::pyright`]'s own no-plugin-architecture finding.
    #[must_use]
    pub const fn typescript_7_native() -> Self {
        Self {
            language: LanguageId::TypeScript,
            provider_id: "typescript-7-native",
            lsp_language_id: "typescript",
            readiness_strategy: ReadinessStrategy::FirstPullDiagnosticsResponse,
            readiness_timeout: Duration::from_secs(60),
            experimental_capability: None,
            initialization_options: None,
            auxiliary_tools: &[],
            literal_environment: &[],
            interpreter: None,
            extra_arguments: &["--lsp", "--stdio"],
            // P17-W Stage C: was hardcoded to `TYPESCRIPT_7_LINUX_X64`
            // regardless of host -- the same hardcoded-to-Linux defect
            // class `RUST_ANALYZER_HOST_NATIVE`/
            // `RUST_SEMANTIC_RUNTIME_HOST_NATIVE` were introduced to close
            // for managed rust-analyzer/the Rust semantic runtime. Fixed to
            // route through the `#[cfg(target_os = "windows")]`-gated host
            // alias so native Windows hosts resolve
            // `TYPESCRIPT_7_WINDOWS_X64` instead of silently reusing the
            // Linux artifact identity.
            managed_component: Some(crate::managed_toolchain::TYPESCRIPT_7_HOST_NATIVE),
            managed_interpreter: None,
            managed_rust_semantic_runtime: None,
            managed_go_semantic_runtime: None,
            managed_typescript_6_runtime: None,
        }
    }

    /// The same native TypeScript 7 LSP provider, addressed under
    /// [`LanguageId::JavaScript`] -- certified by its own independent real
    /// E2E, never inferred from the TypeScript result (mirrors
    /// [`Self::typescript_language_server_for_javascript`]'s own contract).
    #[must_use]
    pub const fn typescript_7_native_for_javascript() -> Self {
        Self {
            language: LanguageId::JavaScript,
            lsp_language_id: "javascript",
            ..Self::typescript_7_native()
        }
    }

    /// The same native TypeScript 7 LSP provider, addressed under
    /// [`LanguageId::Tsx`] (P16). `"typescriptreact"` is the LSP
    /// `languageId` both `tsserver`/`typescript-language-server` and this
    /// server's own `tsc --lsp` frontend document as the TSX identifier
    /// (distinct from plain `"typescript"`, which never enables JSX
    /// parsing) -- `LanguageId::Tsx` must never be silently treated as
    /// ordinary `.ts` by only reusing `typescript_7_native()` unchanged.
    /// Certified by its own independent real E2E (`P16_REAL_TSX_*`), never
    /// inferred from the TypeScript result.
    #[must_use]
    pub const fn typescript_7_native_for_tsx() -> Self {
        Self {
            language: LanguageId::Tsx,
            lsp_language_id: "typescriptreact",
            ..Self::typescript_7_native()
        }
    }

    /// The [`LanguageId::Tsx`] counterpart to
    /// [`Self::typescript_language_server_managed`], mirroring
    /// [`Self::typescript_language_server_managed_for_javascript`]'s own
    /// pattern.
    #[must_use]
    pub const fn typescript_language_server_managed_for_tsx() -> Self {
        Self {
            language: LanguageId::Tsx,
            lsp_language_id: "typescriptreact",
            ..Self::typescript_language_server_managed()
        }
    }

    /// Overrides `initialization_options` on an already-built profile.
    /// `LspProviderProfile` is `#[non_exhaustive]`, so no caller outside
    /// this crate can construct one via struct-literal/update syntax even
    /// with every field named; this is the sole supported way for a host
    /// to layer in configuration this crate's own `const fn` constructors
    /// cannot express at compile time (e.g. a `tsserver.path` resolved only
    /// at runtime -- see `wht_docs/wht_adr/wht_0008-typescript-javascript-lsp-provider.md`).
    /// Every other field -- readiness strategy, auxiliary tools,
    /// interpreter, environment -- is untouched, so the provider's proven
    /// security posture is preserved.
    #[must_use]
    pub fn with_initialization_options(mut self, options: fn() -> serde_json::Value) -> Self {
        self.initialization_options = Some(options);
        self
    }

    /// Overrides `managed_component` on an already-built profile -- the
    /// same non-exhaustive-struct-literal workaround as
    /// [`Self::with_initialization_options`], used by this crate's own
    /// tests to exercise `resolve_launch`'s `CORULIX_MANAGED` precedence
    /// against a manifest guaranteed never to be provisioned on the real,
    /// host-wide `managed_toolchain_root()`, without depending on (or
    /// racing) whether the real pinned TypeScript 7 component happens to be
    /// provisioned there by another test run.
    #[must_use]
    pub fn with_managed_component(
        mut self,
        manifest: wht_corulix_tooling::provisioning::ManagedComponentManifest,
    ) -> Self {
        self.managed_component = Some(manifest);
        self
    }
}

/// TypeScript/JavaScript major-version routing (Phase 7B-C). No existing
/// contract for this was found anywhere in this workspace (`wht_corulix_config`,
/// `wht_corulix_engine`, `wht_corulix_syntax` -- confirmed by a real `rg`
/// sweep during this phase's own research gate) -- this is real, minimal,
/// newly-admitted policy, not a rediscovery of prior behavior, kept
/// entirely inside `wht_corulix_lsp::profile` (Architecture Rule P: sole
/// `LspProviderProfile` construction authority) with no file I/O of its
/// own; a caller (a future workspace-detection pass) determines
/// `declared_major` from `package.json`/`tsconfig.json`/`jsconfig.json` and
/// passes it in here as plain data.
///
/// `declared_major`: `None` or `Some(7)` routes to the native TS7 LSP
/// (default/primary, unaffected by this phase); `Some(6)` routes to the
/// managed TS6 compatibility backend; any other value (explicitly including
/// `Some(5)`) returns `None` -- `TS5_SILENT_COMPATIBILITY_FALLBACK_COUNT=0`
/// is a structural guarantee of this function's own signature, not a
/// runtime check a caller could accidentally skip: there is no code path in
/// which an unsupported major produces *any* `LspProviderProfile` at all.
#[must_use]
pub fn typescript_profile_for_declared_major(
    declared_major: Option<u32>,
) -> Option<LspProviderProfile> {
    match declared_major {
        None | Some(7) => Some(LspProviderProfile::typescript_7_native()),
        Some(6) => Some(LspProviderProfile::typescript_language_server_managed()),
        Some(_) => None,
    }
}

/// The [`LanguageId::JavaScript`] counterpart to
/// [`typescript_profile_for_declared_major`] -- same routing table, same
/// `TS5_SILENT_COMPATIBILITY_FALLBACK_COUNT=0` guarantee.
#[must_use]
pub fn javascript_profile_for_declared_major(
    declared_major: Option<u32>,
) -> Option<LspProviderProfile> {
    match declared_major {
        None | Some(7) => Some(LspProviderProfile::typescript_7_native_for_javascript()),
        Some(6) => Some(LspProviderProfile::typescript_language_server_managed_for_javascript()),
        Some(_) => None,
    }
}

/// The [`LanguageId::Tsx`] counterpart to
/// [`typescript_profile_for_declared_major`] (P16) -- same routing table,
/// same `TS5_SILENT_COMPATIBILITY_FALLBACK_COUNT=0` guarantee, distinct
/// provider identity (`"typescriptreact"`) so TSX is never silently routed
/// through plain TypeScript's profile.
#[must_use]
pub fn tsx_profile_for_declared_major(declared_major: Option<u32>) -> Option<LspProviderProfile> {
    match declared_major {
        None | Some(7) => Some(LspProviderProfile::typescript_7_native_for_tsx()),
        Some(6) => Some(LspProviderProfile::typescript_language_server_managed_for_tsx()),
        Some(_) => None,
    }
}

/// The fully-resolved, ready-to-spawn shape of one [`LspProviderProfile`]:
/// exactly the `executable`/`arguments`/`environment` triple
/// `wht_corulix_tooling::ManagedProcessSpec` needs. This crate never
/// constructs an OS process itself (Rule G) -- it only ever produces this
/// typed, already-resolved launch specification and hands it to
/// `wht_corulix_tooling::ManagedProcess::spawn` (see `crate::session::LspSession::spawn`).
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedLaunch {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: EnvironmentPolicy,
    /// `Some(binding)` iff this launch consumes at least one
    /// `CORULIX_MANAGED` component -- the primary provider itself, or one of
    /// `managed_interpreter`/`managed_rust_semantic_runtime`/
    /// `managed_go_semantic_runtime`/`managed_typescript_6_runtime`.
    /// `LspSession::spawn` passes this straight through to
    /// `ManagedProcessSpec::managed_lease` (Phase 7B-B1-R3-A §3).
    ///
    /// This function fills in the *component* axis only. A caller that then
    /// points the resolved launch at a managed root's root-level execution
    /// scratch (`<root>/scratch`) owes the additional
    /// `ManagedLeaseBinding::in_managed_root` declaration on top, because
    /// that state's lifecycle is `full_uninstall`'s scratch stage, not any
    /// component's `owned_paths`. `wht_corulix_engine::semantic::ensure_go_lsp_session`
    /// is the one such caller today, and its
    /// `real_p15_gopls_active_scratch_lifecycle_e2e` covers it.
    pub managed_lease: Option<wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding>,
    /// A JSON fragment to merge on top of `profile.initialization_options`'s
    /// own static value (`crate::session::LspSession::spawn` performs the
    /// merge). Exists because `initialization_options` is a plain `fn() ->
    /// Value` -- it cannot close over a value only known at resolution time,
    /// such as [`LspProviderProfile::managed_typescript_6_runtime`]'s
    /// resolved `lib/tsserver.js` path (Phase 7B-C). `None` for every
    /// profile that declares no such field.
    pub extra_initialization_options: Option<serde_json::Value>,
}

/// Resolves `profile`'s own `LanguageServer` provider path plus every
/// [`LspProviderProfile::auxiliary_tools`] entry (and, if present,
/// [`LspProviderProfile::interpreter`]) exclusively through
/// `wht_corulix_config::resolve_provider` (never ambient `PATH`), then
/// builds the [`ResolvedLaunch`] `LspSession::spawn` should use.
///
/// For a native-executable provider (`interpreter: None`), `executable` is
/// the resolved provider path itself. For a script provider
/// (`interpreter: Some(_)`), `executable` is the resolved interpreter path
/// and the resolved provider path becomes an explicit `argv[1]` --
/// `profile.provider_id`'s own `#!/usr/bin/env <interpreter>` shebang line
/// is never read or relied upon (`AMBIENT_PATH_NODE_AUTHORITY=NO`,
/// `WORKSPACE_LOCAL_NODE_AUTHORITY=NO`). Every auxiliary tool's resolved
/// parent directory becomes `PATH` (joined with `:` -- Unix path-list
/// semantics, the only platform this phase supports), `literal_environment`
/// is applied verbatim, and nothing else is forwarded.
///
/// Fails closed with [`LspError::ProviderSpawnFailed`] if the provider
/// itself, its interpreter, or any auxiliary tool cannot be resolved -- a
/// language whose server (or its interpreter) is unavailable is honestly
/// `BLOCKED_PROVIDER_UNAVAILABLE`, never silently degraded to running
/// without it.
/// Resolves `profile`'s own `LanguageServer` provider path under the
/// rebaselined Phase 7B-A precedence: `CORULIX_MANAGED` first, when
/// `profile.managed_component` names one, then the existing
/// `wht_corulix_config::resolve_provider` `HOST_ONLY`/system/user-toolchain
/// precedence unchanged (Section 16 of the mandate: existing
/// system-resolution code is not removed, only demoted to a fallback for
/// providers that declare a managed component -- and left entirely
/// untouched for providers that do not).
async fn resolve_provider_path(
    profile: &LspProviderProfile,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &WorkspaceRoot,
    managed_root: &std::path::Path,
) -> Result<(PathBuf, bool), LspError> {
    // F6 fix: every OTHER managed manifest this profile declares (its
    // interpreter, and whichever one of the mutually-exclusive
    // language-runtime fields is `Some` for this profile) is this primary
    // component's own dependency set for acquisition purposes -- collected
    // generically from the profile's own declarative fields, never a
    // per-language `if TypeScript6 .. if Biome ..` branch (F6_LANGUAGE_AGNOSTIC).
    let dependency_manifests: Vec<wht_corulix_tooling::provisioning::ManagedComponentManifest> = [
        profile.managed_interpreter,
        profile.managed_rust_semantic_runtime,
        profile.managed_go_semantic_runtime,
        profile.managed_typescript_6_runtime,
    ]
    .into_iter()
    .flatten()
    .collect();
    resolve_managed_or_system_path(
        profile.managed_component,
        &dependency_manifests,
        effective,
        workspace_root,
        ProviderCategory::LanguageServer,
        profile.provider_id,
        managed_root,
    )
    .await
}

/// Shared `CORULIX_MANAGED`-first-then-`HOST_ONLY`/system resolution,
/// factored out so both the primary provider path
/// ([`resolve_provider_path`]) and an interpreter that is *itself*
/// Corulix-managed (`LspProviderProfile::managed_interpreter`, e.g. managed
/// Pyright's managed Node) share exactly one precedence implementation
/// rather than two independently-maintained copies.
///
/// F6 fix (`F6_PRODUCTION_MANAGED_PROVISIONING_UNREACHABLE`): a third rung
/// is added after the pre-existing managed-then-system precedence, never
/// before it -- an operator with an already-working `HOST_ONLY`/system
/// provider configured for a category that has one (e.g.
/// `TYPESCRIPT_LANGUAGE_SERVER_HOST_NATIVE`'s own documented system
/// fallback) keeps resolving to that same provider exactly as before this
/// fix; real managed acquisition is only attempted once *neither* the
/// managed artifact nor a system-configured one already resolves.
/// `dependency_manifests` are this component's own sibling managed
/// manifests (interpreter/runtime); each is itself acquired-if-absent
/// (single level -- no manifest in this workspace declares a dependency
/// that is itself dependent on a further manifest) before the primary is
/// acquired with their ids recorded, mirroring this product's own tested
/// `ensure_managed_ts6_provisioned` recipe (leaf dependencies first, then
/// the top-level component last).
async fn resolve_managed_or_system_path(
    managed: Option<wht_corulix_tooling::provisioning::ManagedComponentManifest>,
    dependency_manifests: &[wht_corulix_tooling::provisioning::ManagedComponentManifest],
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &WorkspaceRoot,
    category: ProviderCategory,
    provider_name: &'static str,
    managed_root: &std::path::Path,
) -> Result<(PathBuf, bool), LspError> {
    if let Some(manifest) = managed {
        let (state, managed_path, reason) =
            wht_corulix_tooling::provisioning::resolve_owned_managed_component_detailed(
                managed_root,
                &manifest,
            );
        if state == wht_corulix_tooling::provisioning::ManagedComponentState::Available
            && let Some(managed_path) = managed_path
        {
            return Ok((managed_path, true));
        }
        // Managed-toolchain ownership/integrity hardening: a present but
        // invalid/tampered managed artifact (`Corrupt`/`Incompatible`) must
        // fail closed here, never fall through to an explicit approved
        // `HOST_ONLY` provider below -- `INVALID_MANAGED_STATE != NOT_PROVISIONED`.
        // Only a genuinely not-yet-provisioned state
        // (`NotProvisioned`/`Provisioning`) may reach the `HOST_ONLY` tier.
        if matches!(
            state,
            wht_corulix_tooling::provisioning::ManagedComponentState::Corrupt
                | wht_corulix_tooling::provisioning::ManagedComponentState::Incompatible
        ) {
            // Root-cause observability (internal only -- never exposed via
            // any public MCP contract; the external `ReasonCode::
            // RequiredProviderUnavailable` this still maps to, several
            // lines up the call chain in `wht_corulix_engine`, is
            // unchanged). Before this instrumentation, `reason` was
            // discarded (bound as `_reason`) at exactly the point that
            // would have distinguished `RootIdentityMismatch`/
            // `OwnershipMissing`/`OwnershipMalformed` from every other
            // cause `LspError::ProviderSpawnFailed` collapses into.
            tracing::warn!(
                provider_id = manifest.id.0,
                failure_stage = "MANAGED_OWNERSHIP_VALIDATION",
                managed_component_state = ?state,
                internal_failure_kind = ?reason,
                "managed provider resolution failed closed: present artifact is not usable"
            );
            return Err(LspError::ProviderSpawnFailed);
        }
    }
    let provider_resolution =
        wht_corulix_config::resolve_provider(effective, workspace_root, category, provider_name)
            .await;
    if let Some(resolved_path) = provider_resolution.resolved_path {
        return Ok((resolved_path, false));
    }
    if let Some(manifest) = managed {
        let mut dependency_ids: Vec<&'static str> = Vec::with_capacity(dependency_manifests.len());
        for dependency in dependency_manifests {
            resolve_or_acquire_if_allowed(effective, managed_root, dependency, &[]).await?;
            dependency_ids.push(dependency.id.0);
        }
        // `gopls` is not acquired via the generic download pipeline
        // `resolve_or_acquire_if_allowed` calls below -- its manifest's
        // `source.tarball_url` is an inert sentinel (see
        // `crate::managed_toolchain::GOPLS_LINUX_X64`'s own doc comment);
        // the real acquisition mechanism is
        // `wht_corulix_tooling::provisioning::provision_go_module_build`
        // against `GOPLS_BUILD_SOURCE_HOST_NATIVE`, using the already-
        // acquired managed Go semantic runtime (one of `dependency_manifests`
        // above, matched by id rather than by position -- `gopls_managed()`
        // declares exactly one dependency today, but this does not assume
        // that ordering) as the build-time compiler. This is a per-*component*
        // dispatch on the manifest's own declared identity, not a
        // per-language branch (F6_LANGUAGE_AGNOSTIC is about the generic
        // dependency-collection mechanism above, which is unaffected).
        if manifest.id.0 == crate::managed_toolchain::GOPLS_HOST_NATIVE.id.0 {
            let Some(compiler) = dependency_manifests.iter().find(|candidate| {
                candidate.id.0
                    == crate::managed_toolchain::GO_SEMANTIC_RUNTIME_HOST_NATIVE
                        .id
                        .0
            }) else {
                return Err(LspError::ProviderSpawnFailed);
            };
            let acquired_path = resolve_or_acquire_gopls_via_module_build_if_allowed(
                effective,
                managed_root,
                &manifest,
                compiler,
            )
            .await?;
            return Ok((acquired_path, true));
        }
        let acquired_path =
            resolve_or_acquire_if_allowed(effective, managed_root, &manifest, &dependency_ids)
                .await?;
        return Ok((acquired_path, true));
    }
    Err(LspError::ProviderSpawnFailed)
}

/// F6 fix, policy-gated (`F6_PRODUCTION_MANAGED_PROVISIONING_UNREACHABLE`,
/// Installation-Contract-V1): the one call site every real-acquisition
/// attempt in this module funnels through. Permission is
/// `effective.managed_provisioning_permitted(profile_grants_intent)`:
/// `profile_grants_intent` comes from the persisted install profile
/// (`wht_corulix_tooling::provisioning::install_profile::grants_intent`) --
/// `Full`/`OnDemand` grant any component, `Selective` grants only its
/// resolved set, and no persisted profile grants nothing -- while
/// `HostConfig`'s `ManagedProvisioningPolicy` can override that answer in
/// either direction (`Deny` always wins, `Allow` always wins, `Inherit`
/// defers to it). When permission is denied, this performs only the
/// pre-F6 passive check (`resolve_owned_managed_component`) and never
/// attempts network acquisition -- including an already-owned component
/// (e.g. provisioned by an earlier manual `cargo test` run against the
/// same managed root) still resolving successfully. Only when permitted
/// does this reach real `resolve_or_acquire_owned`.
async fn resolve_or_acquire_if_allowed(
    effective: &wht_corulix_config::EffectiveConfig,
    managed_root: &std::path::Path,
    manifest: &wht_corulix_tooling::provisioning::ManagedComponentManifest,
    dependencies: &[&'static str],
) -> Result<PathBuf, LspError> {
    let profile_grants_intent = wht_corulix_tooling::provisioning::install_profile::grants_intent(
        managed_root,
        manifest.id.0,
    );
    if effective.managed_provisioning_permitted(profile_grants_intent) {
        let started_at = std::time::Instant::now();
        return wht_corulix_tooling::provisioning::resolve_or_acquire_owned(
            managed_root,
            manifest,
            dependencies,
        )
        .await
        .map_err(|error| {
            // Root-cause observability (internal only, see the matching
            // comment above in `resolve_managed_or_system_path`): this is
            // the real-network re-acquisition path reached when a managed
            // component was not found already owned/available -- its own
            // `ProvisioningError` was previously discarded here entirely.
            tracing::warn!(
                provider_id = manifest.id.0,
                failure_stage = "MANAGED_PROVIDER_RESOLUTION",
                internal_failure_kind = ?error,
                elapsed_ms = started_at.elapsed().as_millis() as u64,
                "managed provider acquisition failed"
            );
            LspError::ProviderSpawnFailed
        });
    }
    let (state, path) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component(managed_root, manifest);
    if state == wht_corulix_tooling::provisioning::ManagedComponentState::Available {
        path.ok_or(LspError::ProviderSpawnFailed)
    } else {
        Err(LspError::ProviderSpawnFailed)
    }
}

/// `gopls`'s own sibling of [`resolve_or_acquire_if_allowed`], real Go module
/// build acquisition instead of the generic download pipeline
/// (`GOPLS_LINUX_X64`/`GOPLS_WINDOWS_X64`'s `source.tarball_url` is an inert
/// sentinel precisely because this is the real mechanism, not that one --
/// see those constants' own doc comments). Same permission gate as
/// [`resolve_or_acquire_if_allowed`] (`Deny`/`Allow`/`Inherit`-vs-persisted-
/// profile, identical semantics); only the acquisition primitive itself
/// differs, and only for this one component.
async fn resolve_or_acquire_gopls_via_module_build_if_allowed(
    effective: &wht_corulix_config::EffectiveConfig,
    managed_root: &std::path::Path,
    manifest: &wht_corulix_tooling::provisioning::ManagedComponentManifest,
    compiler: &wht_corulix_tooling::provisioning::ManagedComponentManifest,
) -> Result<PathBuf, LspError> {
    let profile_grants_intent = wht_corulix_tooling::provisioning::install_profile::grants_intent(
        managed_root,
        manifest.id.0,
    );
    if effective.managed_provisioning_permitted(profile_grants_intent) {
        return wht_corulix_tooling::provisioning::provision_go_module_build(
            managed_root,
            manifest,
            &crate::managed_toolchain::GOPLS_BUILD_SOURCE_HOST_NATIVE,
            compiler,
        )
        .await
        .map_err(|_| LspError::ProviderSpawnFailed);
    }
    let (state, path) =
        wht_corulix_tooling::provisioning::resolve_owned_managed_component(managed_root, manifest);
    if state == wht_corulix_tooling::provisioning::ManagedComponentState::Available {
        path.ok_or(LspError::ProviderSpawnFailed)
    } else {
        Err(LspError::ProviderSpawnFailed)
    }
}

/// The list separator this host's own dynamic loader/shell convention uses
/// for a `PATH`-shaped environment variable -- `;` on Windows, `:` on every
/// other platform this workspace runs on. Added P17-W-R4-C2: before this,
/// [`resolve_launch_at`] always joined `path_entries` with a literal `:`,
/// which is not merely wrong but actively dangerous on Windows (a `C:\...`
/// path entry already contains a `:` as its own drive-letter separator).
#[must_use]
const fn platform_path_separator() -> &'static str {
    if cfg!(target_os = "windows") {
        ";"
    } else {
        ":"
    }
}

/// Resolves `profile` into a spawn-ready [`ResolvedLaunch`] against the
/// real, host-wide `wht_corulix_tooling::provisioning::managed_toolchain_root()`.
/// This is the canonical entry point every production caller uses; it is a
/// thin wrapper over [`resolve_launch_at`] and carries no resolution logic
/// of its own (Phase 7B-B1-R3-B2-A4 §3-6 -- the same `_at(root)` precedent
/// already established for
/// `wht_corulix_tooling::provisioning::uninstall_all_corulix_managed_components_at`).
pub async fn resolve_launch(
    profile: &LspProviderProfile,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &WorkspaceRoot,
) -> Result<ResolvedLaunch, LspError> {
    let root = wht_corulix_tooling::provisioning::managed_toolchain_root()
        .map_err(|_| LspError::ProviderSpawnFailed)?;
    resolve_launch_at(profile, effective, workspace_root, &root).await
}

/// The real resolution logic behind [`resolve_launch`], parameterized on an
/// explicit `managed_root` rather than resolving the host-wide canonical
/// root internally. This lets an isolated, explicit managed-root test
/// context (never a workspace/user-config-settable value -- see
/// `RULE_Q_TOOLING_LIFECYCLE_AUTHORITY`) exercise the real production
/// provider-resolution and launch path without touching the shared
/// host-wide `managed_toolchain_root()` (Phase 7B-B1-R3-B2-A4 §3-6).
pub async fn resolve_launch_at(
    profile: &LspProviderProfile,
    effective: &wht_corulix_config::EffectiveConfig,
    workspace_root: &WorkspaceRoot,
    managed_root: &std::path::Path,
) -> Result<ResolvedLaunch, LspError> {
    let (provider_path, primary_used_managed) =
        resolve_provider_path(profile, effective, workspace_root, managed_root).await?;

    let mut path_entries: Vec<String> = Vec::new();
    for tool in profile.auxiliary_tools {
        let resolution = wht_corulix_config::resolve_provider(
            effective,
            workspace_root,
            tool.category,
            tool.provider_name,
        )
        .await;
        let resolved_path = resolution
            .resolved_path
            .ok_or(LspError::ProviderSpawnFailed)?;
        let parent = resolved_path
            .parent()
            .ok_or(LspError::ProviderSpawnFailed)?;
        let parent_str = parent.to_str().ok_or(LspError::ProviderSpawnFailed)?;
        path_entries.push(parent_str.to_string());
    }

    // The interpreter (when present) resolves through the same
    // `CORULIX_MANAGED`-first-then-system precedence as the primary
    // provider itself, via `profile.managed_interpreter` -- e.g. managed
    // Pyright's managed Node, resolved independently of whether Pyright's
    // own script came from the managed toolchain or a `HOST_ONLY`/system
    // fallback.
    let mut interpreter_path: Option<PathBuf> = None;
    let mut interpreter_used_managed = false;
    if let Some(interpreter) = profile.interpreter {
        let (resolved_path, used_managed) = resolve_managed_or_system_path(
            profile.managed_interpreter,
            &[],
            effective,
            workspace_root,
            interpreter.category,
            interpreter.provider_name,
            managed_root,
        )
        .await?;
        interpreter_used_managed = used_managed;
        let parent = resolved_path
            .parent()
            .ok_or(LspError::ProviderSpawnFailed)?;
        let parent_str = parent.to_str().ok_or(LspError::ProviderSpawnFailed)?;
        path_entries.push(parent_str.to_string());
        interpreter_path = Some(resolved_path);
    }

    // Managed Rust semantic runtime (rustc + cargo + rust-std + rust-src,
    // merged): `CORULIX_MANAGED`-only, no system fallback (see
    // `LspProviderProfile::managed_rust_semantic_runtime`'s doc comment).
    // Its `bin/` directory becomes both a `PATH` entry (so rust-analyzer's
    // own internal `cd <workspace> && cargo ...`/`rustc --print ...` shells
    // resolve `cargo`/`rustc` there) and the explicit `CARGO`/`RUSTC`
    // environment variables rust-analyzer reads in preference to `PATH`
    // lookup -- both point at the exact same managed binaries, so there is
    // no gap between what `PATH` search and the explicit override would
    // each resolve.
    let mut runtime_env_vars: Vec<(String, String)> = Vec::new();
    if let Some(rust_runtime) = profile.managed_rust_semantic_runtime {
        // F6 fix: acquire-if-absent, never a passive-only check -- see
        // `resolve_or_acquire_owned`'s own doc comment. This runtime has no
        // system fallback by design, so absence here means "provision it or
        // fail closed", never "try somewhere else".
        let rustc_path =
            resolve_or_acquire_if_allowed(effective, managed_root, &rust_runtime, &[]).await?;
        let bin_dir = rustc_path.parent().ok_or(LspError::ProviderSpawnFailed)?;
        let bin_dir_str = bin_dir.to_str().ok_or(LspError::ProviderSpawnFailed)?;
        path_entries.push(bin_dir_str.to_string());
        // `cargo`'s own file name is platform-dependent -- `rustc_path`
        // itself already resolved through the manifest's own
        // `binary_path_in_tarball` (`bin/rustc.exe` on Windows, `bin/rustc`
        // on Unix), so mirroring that same suffix here (rather than a bare
        // `"cargo"`, which would silently miss on Windows -- `bin/cargo`
        // does not exist there, only `bin/cargo.exe`) is the correct,
        // manifest-derived choice, not a hardcoded guess.
        let cargo_file_name = match rustc_path.extension() {
            Some(extension) => format!("cargo.{}", extension.to_string_lossy()),
            None => "cargo".to_string(),
        };
        let cargo_path = bin_dir
            .join(cargo_file_name)
            .to_str()
            .ok_or(LspError::ProviderSpawnFailed)?
            .to_string();
        let rustc_path_str = rustc_path
            .to_str()
            .ok_or(LspError::ProviderSpawnFailed)?
            .to_string();
        runtime_env_vars.push(("CARGO".to_string(), cargo_path));
        runtime_env_vars.push(("RUSTC".to_string(), rustc_path_str));

        // `cargo`/rust-analyzer's own workspace-loading logic needs a
        // resolvable `HOME` (this crate's child processes never inherit
        // one -- see `wht_corulix_tooling`'s unconditional `env_clear`) to
        // locate its own config/registry-index cache directory; without
        // one, `cargo metadata` never settles and rust-analyzer's
        // background task queue never reaches `quiescent`. A dedicated,
        // Corulix-owned scratch directory (never the real user's `$HOME`)
        // serves this exactly the way `CONTROLLED_STAGING_DIRECTORY`
        // already does for the formatter governance model.
        //
        // Deliberately placed *inside* the Rust semantic runtime's own
        // `component_install_dir` (rather than a sibling directory under
        // `managed_toolchain_root()`) so it is covered by that component's
        // existing `owned_paths: [PathBuf::from(".")]` -- the whole
        // component root -- and is therefore quarantined/removed by the
        // ordinary `uninstall()` pipeline with no special-case cleanup
        // path. A prior revision placed it at the toolchain-root level,
        // where it survived `uninstall()` entirely
        // (`POST_UNINSTALL_RUST_SCRATCH_COUNT` was never actually 0) --
        // found and fixed during Phase 7B-B1-R2's own hardening pass.
        let component_root =
            wht_corulix_tooling::provisioning::component_install_dir(managed_root, &rust_runtime);
        let scratch_target = wht_corulix_tooling::provisioning::ensure_scratch_directory(
            &component_root,
            ".corulix-scratch-home/target",
        )
        .map_err(|_| LspError::ProviderSpawnFailed)?;
        let scratch_home = component_root.join(".corulix-scratch-home");
        let scratch_home_str = scratch_home
            .to_str()
            .ok_or(LspError::ProviderSpawnFailed)?
            .to_string();
        let scratch_target_str = scratch_target
            .to_str()
            .ok_or(LspError::ProviderSpawnFailed)?
            .to_string();
        runtime_env_vars.push(("HOME".to_string(), scratch_home_str.clone()));
        runtime_env_vars.push(("CARGO_HOME".to_string(), scratch_home_str));
        runtime_env_vars.push(("CARGO_TARGET_DIR".to_string(), scratch_target_str));

        // Hostile `.cargo/config.toml` neutralization (Phase 7B-B1-R2,
        // §4-8): a real, adversarial probe against this exact merged
        // runtime proved an untrusted workspace's `build.rustc-wrapper`/
        // `build.rustc-workspace-wrapper` config entry *is* honored by the
        // managed `cargo` during rust-analyzer's own `cargo check`
        // flycheck invocation -- `initializationOptions`'
        // `cargo.buildScripts.enable=false`/`procMacro.enable=false` only
        // gate rust-analyzer's *decision* to run cargo at all; they do
        // nothing about what a config-driven wrapper cargo itself invokes
        // once running. The same real probe proved cargo's own env-over-
        // config precedence treats an explicitly-set *empty* env var as
        // "no wrapper", not "wrapper is the empty string" -- setting these
        // unconditionally neutralizes any workspace-declared wrapper
        // regardless of its own config value.
        // `target.<triple>.runner`/`linker` were separately probed and
        // found unreachable through rust-analyzer's actual invocation
        // surface (`cargo check` never links or runs) rather than fixed
        // here; a future profile change that adds `cargo build`/`run`/
        // `test` to this provider's own invocations would need the
        // equivalent `CARGO_TARGET_<TRIPLE>_RUNNER`/`CARGO_TARGET_<TRIPLE>_LINKER`
        // treatment at that time.
        runtime_env_vars.push(("CARGO_BUILD_RUSTC_WRAPPER".to_string(), String::new()));
        runtime_env_vars.push((
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER".to_string(),
            String::new(),
        ));
    }

    // Managed Go semantic runtime (`go` + `gofmt` + stdlib source, merged):
    // M03 Go LSP/toolchain parity port -- managed-first, then explicit
    // `HOST_ONLY`/approved-directory fallback, ported verbatim (as a
    // policy, not a shared function -- `wht_corulix_lsp` cannot depend on
    // `wht_corulix_engine`) from `wht_corulix_engine::go_providers::resolve_go_toolchain`'s
    // already-shipped two-tier Go-toolchain resolution (Stage A / P17-W
    // Master Closure Order). `resolve_managed_or_system_path` (used here
    // exactly as it already is for `managed_interpreter` above) provides
    // the managed-then-`HOST_ONLY`-then-acquire-if-permitted precedence;
    // `ProviderCategory::TypecheckBuild`/`"go"` are the identical
    // category/name [`Self::gopls`]'s own (unmanaged) `auxiliary_tools`
    // entry already resolves.
    //
    // Managed-toolchain ownership/integrity hardening pass: a present but
    // invalid/tampered Go semantic runtime (`Corrupt`) fails closed with
    // **no** `HOST_ONLY` fallback -- enforced generically inside
    // `resolve_managed_or_system_path` itself (which now distinguishes
    // `Corrupt`/`Incompatible` from `NotProvisioned`/`Provisioning` via
    // `resolve_owned_managed_component_detailed`), not re-checked
    // separately here.
    //
    // `GOROOT`/`GOPATH`/`GOCACHE`/`GOMODCACHE`/`HOME` are only set when the
    // managed tier actually resolved: a `HOST_ONLY` system `go` needs none
    // of Corulix's own managed-layout wiring, exactly like
    // [`Self::gopls`]'s pre-existing unmanaged `auxiliary_tools` path never
    // set them either. `wht_corulix_engine::semantic::ensure_go_lsp_session`
    // still overrides `GOCACHE`/`GOMODCACHE`/`GOPATH`/`GOPROXY`/`GOFLAGS`/
    // `GOTOOLCHAIN` afterward with its own workspace-scoped scratch
    // regardless of which tier resolved here
    // (`EnvironmentPolicy::with_var` replaces by key, so that later
    // override is always authoritative) -- this block's own scratch vars
    // exist only so a managed `go`, resolved for some *other* caller of
    // this function, is immediately self-sufficient without relying on a
    // caller-supplied override.
    let mut go_runtime_used_managed = false;
    if let Some(go_runtime) = profile.managed_go_semantic_runtime {
        let (go_path, used_managed) = resolve_managed_or_system_path(
            Some(go_runtime),
            &[],
            effective,
            workspace_root,
            ProviderCategory::TypecheckBuild,
            "go",
            managed_root,
        )
        .await?;
        go_runtime_used_managed = used_managed;

        let bin_dir = go_path.parent().ok_or(LspError::ProviderSpawnFailed)?;
        let bin_dir_str = bin_dir.to_str().ok_or(LspError::ProviderSpawnFailed)?;
        path_entries.push(bin_dir_str.to_string());

        if used_managed {
            let goroot = bin_dir.parent().ok_or(LspError::ProviderSpawnFailed)?;
            let goroot_str = goroot
                .to_str()
                .ok_or(LspError::ProviderSpawnFailed)?
                .to_string();
            runtime_env_vars.push(("GOROOT".to_string(), goroot_str));

            let component_root =
                wht_corulix_tooling::provisioning::component_install_dir(managed_root, &go_runtime);
            let scratch_home = component_root.join(".corulix-scratch-home");
            let scratch_gopath = wht_corulix_tooling::provisioning::ensure_scratch_directory(
                &component_root,
                ".corulix-scratch-home/gopath",
            )
            .map_err(|_| LspError::ProviderSpawnFailed)?;
            let scratch_gocache = wht_corulix_tooling::provisioning::ensure_scratch_directory(
                &component_root,
                ".corulix-scratch-home/gocache",
            )
            .map_err(|_| LspError::ProviderSpawnFailed)?;
            let scratch_gomodcache = wht_corulix_tooling::provisioning::ensure_scratch_directory(
                &component_root,
                ".corulix-scratch-home/gomodcache",
            )
            .map_err(|_| LspError::ProviderSpawnFailed)?;
            let scratch_home_str = scratch_home
                .to_str()
                .ok_or(LspError::ProviderSpawnFailed)?
                .to_string();
            let scratch_gopath_str = scratch_gopath
                .to_str()
                .ok_or(LspError::ProviderSpawnFailed)?
                .to_string();
            let scratch_gocache_str = scratch_gocache
                .to_str()
                .ok_or(LspError::ProviderSpawnFailed)?
                .to_string();
            let scratch_gomodcache_str = scratch_gomodcache
                .to_str()
                .ok_or(LspError::ProviderSpawnFailed)?
                .to_string();
            runtime_env_vars.push(("HOME".to_string(), scratch_home_str));
            runtime_env_vars.push(("GOPATH".to_string(), scratch_gopath_str));
            runtime_env_vars.push(("GOCACHE".to_string(), scratch_gocache_str));
            runtime_env_vars.push(("GOMODCACHE".to_string(), scratch_gomodcache_str));
        }
    }

    // Managed classic TypeScript 6 runtime (`typescript@6.x`'s own
    // `lib/tsserver.js`): `CORULIX_MANAGED`-only, no system fallback --
    // mirrors the Rust/Go blocks' fail-closed precedent, but unlike them
    // this component contributes no `PATH` entry and no environment
    // variable. Its resolved path becomes `initializationOptions.tsserver.path`
    // via `extra_initialization_options` instead (Phase 7B-C) -- proven
    // (by extracting and reading the real `typescript-language-server`
    // source) to be checked *before* any workspace `node_modules/typescript`
    // or bundled resolution, which is exactly what makes
    // `WORKSPACE_TYPESCRIPT_AUTHORITY=NO`/`SYSTEM_TYPESCRIPT_AUTHORITY=NO`
    // structural guarantees for a profile that sets this field, not merely
    // a claim.
    let mut extra_initialization_options: Option<serde_json::Value> = None;
    if let Some(ts6_runtime) = profile.managed_typescript_6_runtime {
        // F6 fix: acquire-if-absent -- mirrors the Rust/Go runtime blocks
        // above; this runtime also has no system/workspace fallback by
        // design (`WORKSPACE_TYPESCRIPT_AUTHORITY=NO`/
        // `SYSTEM_TYPESCRIPT_AUTHORITY=NO`, see the doc comment above).
        let tsserver_path =
            resolve_or_acquire_if_allowed(effective, managed_root, &ts6_runtime, &[]).await?;
        let tsserver_path_str = tsserver_path
            .to_str()
            .ok_or(LspError::UnrepresentableResult)?
            .to_string();
        extra_initialization_options = Some(serde_json::json!({
            "tsserver": { "path": tsserver_path_str }
        }));
    }

    let (executable, mut arguments) = if profile.interpreter.is_some() {
        let interpreter_path = interpreter_path.ok_or(LspError::ProviderSpawnFailed)?;
        let script = provider_path
            .to_str()
            .ok_or(LspError::UnrepresentableResult)?
            .to_string();
        (interpreter_path, vec![script])
    } else {
        (provider_path, Vec::new())
    };
    arguments.extend(
        profile
            .extra_arguments
            .iter()
            .map(|value| (*value).to_string()),
    );

    let mut environment = EnvironmentPolicy::empty();
    if !path_entries.is_empty() {
        // `:` is the Unix `PATH`-list separator; Windows uses `;` -- a
        // literal `:` joined into a Windows child's `PATH` would parse as
        // one single, nonexistent directory entry (worse: `C:\foo` already
        // contains a `:` as its drive-letter separator, so joining with
        // `:` could even mis-split a legitimate entry), silently defeating
        // every `path_entries` push above on that platform.
        environment = environment.with_var("PATH", path_entries.join(platform_path_separator()));
    }
    for (key, value) in profile.literal_environment {
        environment = environment.with_var(*key, *value);
    }
    for (key, value) in runtime_env_vars {
        environment = environment.with_var(key, value);
    }

    // The lease binding mirrors exactly what was actually resolved through
    // `CORULIX_MANAGED` above -- a `HOST_ONLY`/system fallback is never
    // leased (Corulix does not own that process's lifecycle), and the Rust/Go
    // semantic runtimes have no fallback at all (present here iff they
    // resolved, per `resolve_launch`'s own fail-closed check above). The
    // gate is deliberately **not** `primary_used_managed` alone: a profile
    // may leave `managed_component` unset (the primary binary resolves
    // `HOST_ONLY`/system, e.g. `gopls_managed()` today --
    // `GOPLS_ARTIFACT_DISTRIBUTION_GATE=BLOCKED`) while its runtime
    // dependency is still genuinely `CORULIX_MANAGED` -- that dependency
    // must still be leased, or `full_uninstall`/`uninstall()`'s active-
    // lease safety check (which matches a live lease's `dependencies` list,
    // independent of its `primary_component_id` label -- see
    // `wht_corulix_tooling::provisioning::lease`) would never see it and
    // could remove a genuinely in-use managed runtime out from under a live
    // session (Phase 7B-B2-A-R2: an earlier draft of this function gated on
    // `primary_used_managed` alone, which -- traced through this exact
    // `managed_component: None` / `managed_go_semantic_runtime: Some(_)`
    // configuration before any test was written -- would leave
    // `managed_lease` permanently `None`, leasing nothing at all; fixed
    // before the corresponding active-uninstall-safety test was added, and
    // that test now exercises exactly this configuration to keep it that
    // way).
    //
    // `go_runtime_used` is deliberately `go_runtime_used_managed` (the
    // actual resolved tier), not `profile.managed_go_semantic_runtime.is_some()`
    // like the Rust/TS6 runtimes above use -- M03's parity port gave the Go
    // runtime a genuine `HOST_ONLY` fallback, so unlike Rust/TS6 (still
    // truly managed-only whenever the field is `Some`), the field being set
    // no longer implies the managed component was actually used this call.
    // Leasing it regardless would let a purely `HOST_ONLY`-resolved Go
    // session declare a lease dependency on a managed component it never
    // touched.
    let go_runtime_used = go_runtime_used_managed;
    let rust_runtime_used = profile.managed_rust_semantic_runtime.is_some();
    let ts6_runtime_used = profile.managed_typescript_6_runtime.is_some();
    let any_managed_dependency_used = primary_used_managed
        || interpreter_used_managed
        || rust_runtime_used
        || go_runtime_used
        || ts6_runtime_used;
    let managed_lease = any_managed_dependency_used.then(|| {
        let mut dependencies = Vec::new();
        if interpreter_used_managed && let Some(manifest) = profile.managed_interpreter {
            dependencies.push(manifest.id.0);
        }
        if let Some(rust_runtime) = profile.managed_rust_semantic_runtime {
            dependencies.push(rust_runtime.id.0);
        }
        if go_runtime_used && let Some(go_runtime) = profile.managed_go_semantic_runtime {
            dependencies.push(go_runtime.id.0);
        }
        if let Some(ts6_runtime) = profile.managed_typescript_6_runtime {
            dependencies.push(ts6_runtime.id.0);
        }
        wht_corulix_tooling::provisioning::lease::ManagedLeaseBinding::for_components(
            wht_corulix_tooling::provisioning::lease::RootIdentity::of(managed_root),
            profile
                .managed_component
                .map(|manifest| manifest.id.0)
                .unwrap_or(profile.provider_id),
            dependencies,
        )
    });

    Ok(ResolvedLaunch {
        executable,
        arguments,
        environment,
        managed_lease,
        extra_initialization_options,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes every test that can reach `resolve_or_acquire_if_allowed`'s
    /// real acquisition-failure branch. On this host, a real
    /// `install-profile.json` with `FULL` intent already exists at the real
    /// host-wide managed-toolchain root (left behind by earlier real E2E
    /// provisioning), so `install_profile::grants_intent` returns `true`
    /// for ANY component id -- including these tests' own fixture-only ids
    /// -- meaning `typescript_7_native_falls_closed_when_not_yet_provisioned`
    /// also reaches real acquisition (against its own slow, real
    /// `https://example.invalid` URL) rather than being blocked earlier by
    /// the permission gate, exactly like
    /// `not_yet_provisioned_acquisition_failure_emits_managed_provider_resolution_diagnostic`
    /// below. Both hit the identical `tracing::warn!` callsite inside
    /// `resolve_or_acquire_if_allowed`'s `map_err`. Unlike
    /// `wht_corulix_tooling::managed`'s own diagnostic test (where a shared
    /// `tokio::sync::Mutex` was proven necessary: 3/8 full-crate reruns
    /// dropped the tracing event without it, 0/12 with it), this crate's
    /// diagnostic test reached 15/15 clean purely from switching its own
    /// fixture off the slow real network call onto an instantly-refused
    /// local port (see that test's own `tarball_url` comment) -- this lock
    /// was added as unproven extra safety alongside that fix, not verified
    /// as independently necessary here.
    static ACQUISITION_FAILURE_CALLSITE_LOCK: tokio::sync::Mutex<()> =
        tokio::sync::Mutex::const_new(());

    #[test]
    fn typescript_major_routing_defaults_and_declared_7_go_native() {
        for major in [None, Some(7)] {
            let profile = typescript_profile_for_declared_major(major)
                .unwrap_or_else(|| unreachable!("expected a profile for {major:?}"));
            assert!(profile.managed_component.is_some());
            assert_eq!(profile.language, LanguageId::TypeScript);
            let js_profile = javascript_profile_for_declared_major(major)
                .unwrap_or_else(|| unreachable!("expected a profile for {major:?}"));
            assert_eq!(js_profile.language, LanguageId::JavaScript);
        }
    }

    #[test]
    fn typescript_major_routing_declared_6_goes_managed_compatibility_backend() {
        let profile = typescript_profile_for_declared_major(Some(6))
            .unwrap_or_else(|| unreachable!("expected a profile for major 6"));
        assert_eq!(profile.provider_id, "typescript-language-server");
        assert!(profile.managed_typescript_6_runtime.is_some());
        assert!(profile.managed_interpreter.is_some());
        let js_profile = javascript_profile_for_declared_major(Some(6))
            .unwrap_or_else(|| unreachable!("expected a profile for major 6"));
        assert_eq!(js_profile.language, LanguageId::JavaScript);
        assert!(js_profile.managed_typescript_6_runtime.is_some());
    }

    #[test]
    fn typescript_5_never_silently_falls_back_to_6() {
        assert!(typescript_profile_for_declared_major(Some(5)).is_none());
        assert!(javascript_profile_for_declared_major(Some(5)).is_none());
        // Every unsupported major, not merely 5 -- no silent fallback for
        // any out-of-scope version.
        assert!(typescript_profile_for_declared_major(Some(4)).is_none());
        assert!(typescript_profile_for_declared_major(Some(99)).is_none());
    }

    #[test]
    fn rust_analyzer_profile_disables_workspace_code_execution() {
        let profile = LspProviderProfile::rust_analyzer();
        let Some(build_options) = profile.initialization_options else {
            unreachable!("rust-analyzer must declare initializationOptions");
        };
        let options = build_options();
        assert_eq!(
            options["cargo"]["buildScripts"]["enable"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            options["procMacro"]["enable"],
            serde_json::Value::Bool(false)
        );
    }

    #[test]
    fn gopls_profile_uses_first_diagnostics_readiness_and_denies_network() {
        let profile = LspProviderProfile::gopls();
        assert_eq!(
            profile.readiness_strategy,
            ReadinessStrategy::FirstDiagnosticsPublished
        );
        assert!(profile.literal_environment.contains(&("GOPROXY", "off")));
        assert!(
            profile
                .literal_environment
                .contains(&("GOFLAGS", "-mod=readonly"))
        );
    }

    #[test]
    fn typescript_and_javascript_profiles_disable_plugins_and_type_acquisition() {
        for profile in [
            LspProviderProfile::typescript_language_server(),
            LspProviderProfile::typescript_language_server_for_javascript(),
        ] {
            let Some(build_options) = profile.initialization_options else {
                unreachable!("typescript-language-server must declare initializationOptions");
            };
            let options = build_options();
            assert_eq!(options["plugins"], serde_json::json!([]));
            assert_eq!(
                options["preferences"]["disableAutomaticTypingAcquisition"],
                serde_json::Value::Bool(true)
            );
            assert_eq!(
                profile.interpreter.map(|tool| tool.provider_name),
                Some("node")
            );
        }
        assert_eq!(
            LspProviderProfile::typescript_language_server().language,
            LanguageId::TypeScript
        );
        assert_eq!(
            LspProviderProfile::typescript_language_server_for_javascript().language,
            LanguageId::JavaScript
        );
    }

    #[test]
    fn pyright_profile_has_no_plugin_architecture_and_needs_node() {
        let profile = LspProviderProfile::pyright();
        assert_eq!(
            profile.readiness_strategy,
            ReadinessStrategy::FirstDiagnosticsPublished
        );
        assert_eq!(
            profile.interpreter.map(|tool| tool.provider_name),
            Some("node")
        );
        assert!(profile.extra_arguments.contains(&"--stdio"));
    }

    #[test]
    fn typescript_7_native_profile_needs_no_interpreter_and_declares_a_managed_component() {
        for profile in [
            LspProviderProfile::typescript_7_native(),
            LspProviderProfile::typescript_7_native_for_javascript(),
        ] {
            assert_eq!(
                profile.readiness_strategy,
                ReadinessStrategy::FirstPullDiagnosticsResponse
            );
            assert!(profile.interpreter.is_none());
            assert!(profile.auxiliary_tools.is_empty());
            assert_eq!(profile.extra_arguments, &["--lsp", "--stdio"]);
            assert!(profile.managed_component.is_some());
        }
        assert_eq!(
            LspProviderProfile::typescript_7_native().language,
            LanguageId::TypeScript
        );
        assert_eq!(
            LspProviderProfile::typescript_7_native_for_javascript().language,
            LanguageId::JavaScript
        );
    }

    #[test]
    fn typescript_7_native_never_resolves_npm_on_any_environment_path() {
        // Section 11's ATA guard (`UNTRUSTED_TS7_PACKAGE_INSTALL=NO`): this
        // provider's `auxiliary_tools`/`interpreter` are the only source of
        // resolved `PATH` entries `resolve_launch` ever builds -- since
        // neither names `npm`, the server's own `os/exec.Command("npm",
        // ...)` Automatic Type Acquisition call structurally cannot resolve
        // an `npm` binary regardless of what a hostile workspace's own
        // `tsconfig.json`/`jsconfig.json` declares (proven empirically
        // against the real binary during this phase's research gate: a
        // poisoned-`PATH` probe produced `"npm install failed"`, never a
        // successful install).
        let profile = LspProviderProfile::typescript_7_native();
        assert!(
            profile
                .auxiliary_tools
                .iter()
                .chain(profile.interpreter.iter())
                .all(|tool| tool.provider_name != "npm")
        );
    }

    #[tokio::test]
    async fn typescript_7_native_falls_closed_when_not_yet_provisioned() {
        let _serial = ACQUISITION_FAILURE_CALLSITE_LOCK.lock().await;
        // Uses a fabricated manifest with an impossible version, never the
        // real pinned `managed_toolchain::TYPESCRIPT_7_LINUX_X64` constant
        // -- `managed_toolchain_root()` resolves to the real, host-wide
        // application-data location (by design, it is not per-test), so
        // asserting "not provisioned" against the real component would
        // race against (and be broken by) this crate's own real E2E test
        // provisioning it for real elsewhere in the same test run/host.
        // With no `HOST_ONLY` override configured either, resolution must
        // still fail closed rather than silently falling back to an
        // unmanaged/ambient lookup -- there is no such lookup:
        // `resolve_provider_path` only ever tries `CORULIX_MANAGED` then
        // the existing `wht_corulix_config::resolve_provider` precedence.
        let fixture_manifest = wht_corulix_tooling::provisioning::ManagedComponentManifest {
            id: wht_corulix_tooling::provisioning::ManagedComponentId(
                "typescript-7-native-never-provisioned-fixture",
            ),
            version: "0.0.0-test-fixture",
            platform: "linux",
            architecture: "x64",
            source: wht_corulix_tooling::provisioning::ManagedArtifactSource {
                tarball_url: "https://example.invalid/never-fetched.tgz",
                expected_sha256_hex: "0",
                binary_path_in_tarball: "package/lib/tsc",
                archive_kind: wht_corulix_tooling::provisioning::ArchiveKind::TarGz,
                symlink_policy: wht_corulix_tooling::provisioning::SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: None,
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            additional_sources: &[],
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let workspace =
            std::env::temp_dir().join(format!("corulix-lsp-ts7-notprovisioned-{stamp}"));
        let _ = std::fs::create_dir_all(&workspace);
        let root = match WorkspaceRoot::open(&workspace) {
            Ok(root) => root,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&workspace);
                unreachable!("a freshly created temp directory always opens as a WorkspaceRoot");
            }
        };
        let effective = wht_corulix_config::EffectiveConfig::derive(
            &wht_corulix_config::HostConfig::default(),
            &wht_corulix_config::RepositoryHints::default(),
            &wht_corulix_config::RequestOptions::default(),
        );
        let profile =
            LspProviderProfile::typescript_7_native().with_managed_component(fixture_manifest);
        let result = resolve_launch(&profile, &effective, &root).await;
        assert_eq!(result, Err(LspError::ProviderSpawnFailed));
        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// A minimal, hand-rolled [`tracing::Subscriber`] recording only the
    /// `failure_stage` field of every event -- deliberately not
    /// `tracing-subscriber` (not a dependency of this crate), mirroring the
    /// identical recorder added to `wht_corulix_tooling::managed`'s own test
    /// module for the same root-cause observability mandate.
    struct FailureStageRecorder {
        stages: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl tracing::field::Visit for FailureStageRecorder {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "failure_stage"
                && let Ok(mut stages) = self.stages.lock()
            {
                stages.push(format!("{value:?}"));
            }
        }
    }

    struct CapturingSubscriber {
        captured: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl tracing::Subscriber for CapturingSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = FailureStageRecorder {
                stages: self.captured.clone(),
            };
            event.record(&mut visitor);
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Diagnostic-observability test (not a provider-functionality test):
    /// proves `resolve_or_acquire_if_allowed`'s instrumentation tags a real
    /// acquisition failure as `MANAGED_PROVIDER_RESOLUTION`, distinct from
    /// `LSP_PROCESS_SPAWN`/`LSP_INITIALIZATION`/`LSP_READINESS`. Unlike
    /// `typescript_7_native_falls_closed_when_not_yet_provisioned` above,
    /// this uses `ManagedProvisioningPolicy::Allow` (host-level override,
    /// wins unconditionally per `managed_provisioning_permitted`'s own
    /// contract) so the real network-acquisition branch is actually reached
    /// rather than short-circuited by the permission gate -- reusing that
    /// existing fixture's `HostConfig::default()` would silently skip the
    /// instrumented call entirely, since no persisted install profile grants
    /// intent for a fixture-only component id. `resolve_launch_at` (not
    /// `resolve_launch`) is used with an isolated temp `managed_root`, never
    /// the real host-wide `managed_toolchain_root()`, so this never touches
    /// or races real managed-toolchain state.
    #[tokio::test]
    async fn not_yet_provisioned_acquisition_failure_emits_managed_provider_resolution_diagnostic()
    -> Result<(), String> {
        let _serial = ACQUISITION_FAILURE_CALLSITE_LOCK.lock().await;
        let fixture_manifest = wht_corulix_tooling::provisioning::ManagedComponentManifest {
            id: wht_corulix_tooling::provisioning::ManagedComponentId(
                "typescript-7-native-diagnostic-observability-fixture",
            ),
            version: "0.0.0-test-fixture",
            platform: "linux",
            architecture: "x64",
            source: wht_corulix_tooling::provisioning::ManagedArtifactSource {
                // Unlike the sibling fixtures above/below (which never reach
                // the network -- they fail closed earlier, at the
                // permission gate or the ownership-corruption check), this
                // test's `ManagedProvisioningPolicy::Allow` deliberately
                // reaches the real `resolve_or_acquire_owned` acquisition
                // attempt. A reserved `.invalid` TLD (RFC 2606) still
                // engages this host's real resolver/network stack and was
                // observed taking ~30s per attempt (a real connect/DNS
                // timeout, not an immediate NXDOMAIN) -- both needlessly
                // slow for a unit test and, empirically, a source of
                // intermittent tracing-capture flakiness under `cargo
                // test`'s default parallelism (2/10 full-suite reruns
                // dropped the event during that 30s window). A literal
                // loopback address on a port with no listener fails
                // instantly with a real, deterministic `ConnectionRefused`
                // -- no DNS involved at all -- while still exercising the
                // exact same real acquisition-failure code path.
                tarball_url: "http://127.0.0.1:1/never-fetched.tgz",
                expected_sha256_hex: "0",
                binary_path_in_tarball: "package/lib/tsc",
                archive_kind: wht_corulix_tooling::provisioning::ArchiveKind::TarGz,
                symlink_policy: wht_corulix_tooling::provisioning::SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: None,
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            additional_sources: &[],
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let workspace =
            std::env::temp_dir().join(format!("corulix-lsp-ts7-diag-workspace-{stamp}"));
        let managed_root =
            std::env::temp_dir().join(format!("corulix-lsp-ts7-diag-managed-root-{stamp}"));
        let _ = std::fs::create_dir_all(&workspace);
        let _ = std::fs::create_dir_all(&managed_root);
        let root = match WorkspaceRoot::open(&workspace) {
            Ok(root) => root,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&workspace);
                let _ = std::fs::remove_dir_all(&managed_root);
                unreachable!("a freshly created temp directory always opens as a WorkspaceRoot");
            }
        };
        let host = wht_corulix_config::HostConfig {
            managed_provisioning_policy: wht_corulix_config::ManagedProvisioningPolicy::Allow,
            ..wht_corulix_config::HostConfig::default()
        };
        let effective = wht_corulix_config::EffectiveConfig::derive(
            &host,
            &wht_corulix_config::RepositoryHints::default(),
            &wht_corulix_config::RequestOptions::default(),
        );
        let profile =
            LspProviderProfile::typescript_7_native().with_managed_component(fixture_manifest);
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = tracing::subscriber::set_default(CapturingSubscriber {
            captured: captured.clone(),
        });
        let result = resolve_launch_at(&profile, &effective, &root, &managed_root).await;
        assert_eq!(result, Err(LspError::ProviderSpawnFailed));
        let stages = captured
            .lock()
            .map_err(|_| "captured-stages mutex poisoned".to_string())?;
        assert!(
            stages
                .iter()
                .any(|stage| stage.contains("MANAGED_PROVIDER_RESOLUTION")),
            "expected a captured tracing event tagging failure_stage=MANAGED_PROVIDER_RESOLUTION, got: {stages:?}"
        );
        drop(stages);
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&managed_root);
        Ok(())
    }

    /// Diagnostic-observability test for the ownership-corruption branch:
    /// proves `resolve_managed_or_system_path`'s instrumentation tags a
    /// present-but-tampered managed artifact as `MANAGED_OWNERSHIP_VALIDATION`
    /// with `internal_failure_kind` reflecting the exact
    /// `ManagedInvalidReason` (`OwnershipMalformed` here), distinct from
    /// `MANAGED_PROVIDER_RESOLUTION`/`LSP_PROCESS_SPAWN`/`LSP_INITIALIZATION`/
    /// `LSP_READINESS`. The `Corrupt` state is directly representable using
    /// only this crate's public dependency surface -- no private
    /// `wht_corulix_tooling` test helper is reachable across the crate
    /// boundary -- by writing a deliberately malformed ownership record
    /// directly at the exact path `wht_corulix_tooling::provisioning::
    /// ownership`'s own `record_path`/`ownership_dir` helpers construct
    /// (`<managed_root>/ownership/<component_id>.json`), mirroring that
    /// module's own `regression_matrix_c_malformed_ownership_file_fails_closed`
    /// fixture technique. This never touches the real host-wide managed
    /// toolchain root.
    #[tokio::test]
    async fn corrupt_ownership_record_emits_managed_ownership_validation_diagnostic()
    -> Result<(), String> {
        let fixture_manifest = wht_corulix_tooling::provisioning::ManagedComponentManifest {
            id: wht_corulix_tooling::provisioning::ManagedComponentId(
                "corrupt-ownership-diagnostic-observability-fixture",
            ),
            version: "0.0.0-test-fixture",
            platform: "linux",
            architecture: "x64",
            source: wht_corulix_tooling::provisioning::ManagedArtifactSource {
                tarball_url: "https://example.invalid/never-fetched.tgz",
                expected_sha256_hex: "0",
                binary_path_in_tarball: "package/lib/tsc",
                archive_kind: wht_corulix_tooling::provisioning::ArchiveKind::TarGz,
                symlink_policy: wht_corulix_tooling::provisioning::SymlinkPolicy::Reject,
                required_paths: &[],
                required_nonempty_dirs: &[],
                tar_root_prefix: None,
                extract_path_prefixes: &[],
                post_extraction_symlinks: &[],
            },
            additional_sources: &[],
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let workspace =
            std::env::temp_dir().join(format!("corulix-lsp-corrupt-diag-workspace-{stamp}"));
        let managed_root =
            std::env::temp_dir().join(format!("corulix-lsp-corrupt-diag-managed-root-{stamp}"));
        let ownership_dir = managed_root.join("ownership");
        let _ = std::fs::create_dir_all(&workspace);
        let _ = std::fs::create_dir_all(&ownership_dir);
        // `resolve_owned_managed_component_detailed` checks the installed
        // artifact's presence (`resolve_managed_component`, via the public
        // `component_install_dir`) *before* it ever consults the ownership
        // record -- a component with no installed binary resolves
        // `NotProvisioned` regardless of what the ownership record says,
        // never `Corrupt`. The installed binary must exist for this
        // fixture to reach the ownership-validation branch at all.
        let install_dir = wht_corulix_tooling::provisioning::component_install_dir(
            &managed_root,
            &fixture_manifest,
        );
        let binary_path = install_dir.join(fixture_manifest.source.binary_path_in_tarball);
        let _ = std::fs::create_dir_all(binary_path.parent().unwrap_or(&install_dir));
        std::fs::write(&binary_path, b"fixture binary contents")
            .map_err(|error| format!("writing the installed fixture binary failed: {error}"))?;
        let record_path = ownership_dir.join(format!("{}.json", fixture_manifest.id.0));
        std::fs::write(&record_path, b"{ not valid json at all").map_err(|error| {
            format!("writing the deliberately malformed ownership record failed: {error}")
        })?;
        let root = match WorkspaceRoot::open(&workspace) {
            Ok(root) => root,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&workspace);
                let _ = std::fs::remove_dir_all(&managed_root);
                unreachable!("a freshly created temp directory always opens as a WorkspaceRoot");
            }
        };
        let effective = wht_corulix_config::EffectiveConfig::derive(
            &wht_corulix_config::HostConfig::default(),
            &wht_corulix_config::RepositoryHints::default(),
            &wht_corulix_config::RequestOptions::default(),
        );
        let profile =
            LspProviderProfile::typescript_7_native().with_managed_component(fixture_manifest);
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = tracing::subscriber::set_default(CapturingSubscriber {
            captured: captured.clone(),
        });
        let result = resolve_launch_at(&profile, &effective, &root, &managed_root).await;
        assert_eq!(result, Err(LspError::ProviderSpawnFailed));
        let stages = captured
            .lock()
            .map_err(|_| "captured-stages mutex poisoned".to_string())?;
        assert!(
            stages
                .iter()
                .any(|stage| stage.contains("MANAGED_OWNERSHIP_VALIDATION")),
            "expected a captured tracing event tagging failure_stage=MANAGED_OWNERSHIP_VALIDATION, got: {stages:?}"
        );
        drop(stages);
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&managed_root);
        Ok(())
    }

    #[tokio::test]
    async fn resolve_launch_fails_closed_when_auxiliary_tool_is_unavailable() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let workspace = std::env::temp_dir().join(format!("corulix-lsp-profile-test-{stamp}"));
        let _ = std::fs::create_dir_all(&workspace);
        let root = match WorkspaceRoot::open(&workspace) {
            Ok(root) => root,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&workspace);
                unreachable!("a freshly created temp directory always opens as a WorkspaceRoot");
            }
        };
        let effective = wht_corulix_config::EffectiveConfig::derive(
            &wht_corulix_config::HostConfig::default(),
            &wht_corulix_config::RepositoryHints::default(),
            &wht_corulix_config::RequestOptions::default(),
        );
        let profile = LspProviderProfile::gopls();
        let result = resolve_launch(&profile, &effective, &root).await;
        assert_eq!(result, Err(LspError::ProviderSpawnFailed));
        let _ = std::fs::remove_dir_all(&workspace);
    }
}
