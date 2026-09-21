// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! P15: the per-language formatter profile table -- the one place this crate
//! decides *which* formatter is authoritative for a language, what argv it
//! is invoked with, whether repository formatter-config discovery applies,
//! whether a `CORULIX_MANAGED` component exists for it, and how its real
//! provider version identity is obtained.
//!
//! # Why a profile table rather than a second formatter crate
//!
//! Before P15 this crate was Rust-welded: a hard `detect_language(..) !=
//! Some(LanguageId::Rust)` guard, a `RUSTFMT_ARGV0` constant, a
//! `managed::resolve_rustfmt` entry point, and a `rustfmt --version` probe.
//! Every one of those is *provider* detail; none of it is *governance*
//! detail. The governance -- bounded confined read, pre-format precondition
//! hash, stdin/stdout-only invocation through
//! [`wht_corulix_tooling::ManagedProcess`], verified output bytes, and the
//! single `wht_corulix_mutation::MutationExecutor` apply -- is entirely
//! language-independent and was already certified by Phases 9/10/10-R2.
//!
//! P15 therefore adds Go by parameterizing the provider detail and leaving
//! the certified governance path byte-for-byte unchanged. The Rust arm
//! (`FormatterProfile::rustfmt`) reproduces exactly the arguments, argv0,
//! config-discovery behavior, managed pinning, and version probe the
//! pre-P15 code hard-coded -- proven by
//! `crate::tests::rust_profile_matches_the_pre_p15_hardcoded_invocation`.
//!
//! `P15_GO_FORMATTER=gofmt`, `P15_GOFMT_AUTHORITY=AUTHORITATIVE`: gofmt is
//! the sole formatting authority for Go source in this workspace. `gopls`'s
//! own `textDocument/formatting` capability is never invoked (Rule N,
//! unchanged), and `goimports` is deliberately **not** admitted -- see
//! [`GOIMPORTS_DECISION`].
//!
//! # `-w` is structurally absent
//!
//! `P15_GOFMT_LIVE_INPLACE_WRITE_COUNT=0` is a construction guarantee, not a
//! claim: real `gofmt` writes in place only when given `-w` *and* a
//! positional file path (verified empirically against the installed
//! `gofmt` shipped with `go1.26.6` -- `gofmt -h` lists `-w  write result to
//! (source) file instead of stdout`). This table's Go arm supplies neither,
//! and `FormatterProfile::forbids_in_place_write` asserts that
//! structurally for every profile in the table.

use wht_corulix_core::LanguageId;

/// `P15_GOIMPORTS_DECISION=NOT_REQUIRED`.
///
/// `goimports` is not installed on this host (confirmed by P15's own
/// discovery pass), §5 of the P15 mandate forbids installing it, and -- the
/// decisive architectural reason, independent of availability -- admitting
/// it would create a *second* formatting authority for Go alongside `gofmt`.
/// `goimports` is a strict superset of `gofmt`'s formatting plus import
/// add/remove, i.e. a semantic source transformation, not a formatting one;
/// routing it through `gate.format` would let an import graph change ride in
/// on a formatting gate's authority. Go's canonical formatter authority is
/// `gofmt`, and P15 does not change that. No ADR is opened: there is no
/// decision pending, only a rejected expansion of scope.
pub const GOIMPORTS_DECISION: &str = "NOT_REQUIRED";

/// Whether, and how, a repository's own formatter configuration file
/// influences an invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigDiscovery {
    /// rustfmt: bounded upward `rustfmt.toml`/`.rustfmt.toml` discovery from
    /// the target's containing directory to the workspace root inclusive,
    /// passed as `--config-path <dir>`. See [`crate::config_discovery`]'s own
    /// module doc for the empirical research behind the exact mechanism.
    RustfmtToml,
    /// gofmt: none. Verified empirically against the installed `gofmt`
    /// (`go1.26.6`): its entire flag surface is
    /// `-cpuprofile/-d/-e/-l/-r/-s/-w`, and it reads no configuration file of
    /// any kind -- Go's formatting is defined by the tool, not by
    /// per-repository configuration. Reusing rustfmt's discovery here would
    /// have invented semantics gofmt does not have.
    ///
    /// Also Biome's (P16, TS/TSX/JS): ADR 0010's `P16_CONFIG_PRECEDENCE`
    /// deliberately does not read a repository `biome.json` this phase --
    /// `biome format` is invoked with only minimal, fixed
    /// `--stdin-file-path` options, never with an implicitly-loaded
    /// repository config (`P16_FORMATTER_CONFIG_EXECUTION_MODEL=DECLARATIVE_JSON_ONLY`).
    None,
}

/// Whether a `CORULIX_MANAGED` component backs this formatter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedFormatter {
    /// `rustfmt`, backed by [`crate::managed_toolchain::RUSTFMT_LINUX_X64`]
    /// plus its managed Rust-semantic-runtime dependency.
    RustfmtLinuxX64,
    /// `gofmt`, backed by the shared `go-semantic-runtime` component
    /// (`wht_corulix_tooling::managed_runtimes::GO_SEMANTIC_RUNTIME_LINUX_X64`/
    /// `_WINDOWS_X64`) -- the same component
    /// `wht_corulix_engine::go_providers::resolve_go_toolchain` already
    /// resolves managed-first for `go build`/`go vet`/`go test` (M03
    /// rename_preview managed auxiliary capability closure). `gofmt` sits as
    /// a sibling of `go` in that component's own `bin/` directory
    /// (`bin/gofmt`/`bin/gofmt.exe`, already a `required_paths` entry on
    /// both platform manifests, so its presence is verified at provisioning
    /// time exactly like `go` itself). Before this pass `gofmt` resolved
    /// `HOST_ONLY`-only ([`Self::None`]) because nothing on this host had
    /// provisioned the runtime and P15 was not authorized to wire a
    /// managed-first branch that could only ever miss; the owner has since
    /// authorized closing that gap by reusing (never duplicating) this
    /// runtime.
    GoSemanticRuntimeHostNative,
    /// `biome`, backed by [`crate::managed_toolchain::BIOME_LINUX_X64`]
    /// (P16). A single, statically-linked native binary with no sibling
    /// runtime dependency (`ldd` against the downloaded artifact reports no
    /// unresolved shared objects, confirmed during ADR 0010's own research
    /// gate) -- resolution therefore never sets any environment variable,
    /// unlike [`Self::RustfmtLinuxX64`]'s `LD_LIBRARY_PATH` requirement.
    BiomeLinuxX64,
    /// `ruff format`, backed by
    /// `wht_corulix_tooling::managed_runtimes::RUFF_LINUX_X64`/`_WINDOWS_X64`
    /// (M03 Python managed-auxiliary final closure, owner-pinned Ruff
    /// 0.16.3). A single, statically-linked native binary with no sibling
    /// runtime dependency (`ldd` against the downloaded artifact reports only
    /// standard glibc libraries) -- resolution never sets any environment
    /// variable, exactly like [`Self::BiomeLinuxX64`]. `ruff check` (the
    /// Linter category, resolved in `wht_corulix_engine::python_providers`,
    /// not this crate) resolves the **same** underlying component -- Formatter
    /// and Linter must never diverge onto two independently provisioned Ruff
    /// copies.
    RuffLinuxX64,
}

/// How a resolved formatter's real version identity is obtained.
/// `P15_GO_EVIDENCE_PROVIDER_IDENTITY`: never the string "system go".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionProbe {
    /// The formatter itself answers `--version` (rustfmt).
    SelfVersionFlag,
    /// The formatter has no version flag of its own, and its identity is
    /// the identity of the Go toolchain that ships it.
    ///
    /// Verified empirically: `gofmt --version` fails with `flag provided but
    /// not defined: -version`, and `gofmt`'s documented flag surface carries
    /// no version option at all. The real identity is therefore obtained
    /// from `go version`, resolved as the `go` executable sitting in the
    /// *same already-trust-verified directory* as the resolved `gofmt`
    /// (`/usr/local/go/bin/gofmt` and `/usr/local/go/bin/go` in a standard
    /// Go distribution). No ambient `PATH` lookup is performed
    /// (`P15_AMBIENT_PATH_AUTHORITY=NO`) and no directory outside the one
    /// `wht_corulix_config::resolve_provider` already canonicalized and
    /// approved is ever consulted; a sibling `go` that is absent simply
    /// yields `None`, and formatting proceeds with an honestly-unknown
    /// version rather than a fabricated one.
    SiblingGoVersion,
}

/// One language's complete formatter provider definition.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FormatterProfile {
    pub language: LanguageId,
    /// The binary name `wht_corulix_config::resolve_provider` looks for
    /// inside approved directories.
    pub provider_id: &'static str,
    /// The `argv[0]` presented to the child (Unix), independent of the
    /// resolved executable's real filesystem path -- see
    /// [`Self::rustfmt`]'s own note for why this matters for rustfmt.
    pub argv0: &'static str,
    /// Fixed arguments, in order. Never contains an in-place-write flag --
    /// see this module's own doc comment.
    pub fixed_arguments: &'static [&'static str],
    pub config_discovery: ConfigDiscovery,
    pub managed: ManagedFormatter,
    pub version_probe: VersionProbe,
}

impl FormatterProfile {
    /// The Rust formatter authority. Every field here reproduces exactly
    /// what this crate hard-coded before P15 -- `RUSTFMT_FORMATTING_AUTHORITY=YES`
    /// and the whole Phase 9/10/10-R2 certified invocation are unchanged.
    ///
    /// `argv0` is `"rustfmt"` rather than the resolved path because a
    /// common real-world `rustfmt` (a `rustup`-managed toolchain) is a
    /// symlink to a multi-call proxy that dispatches on its own `argv[0]`;
    /// executing the canonicalized target with the OS-default `argv[0]`
    /// breaks that dispatch (empirically verified in Phase 9). This never
    /// changes *which* binary runs.
    #[must_use]
    pub const fn rustfmt() -> Self {
        Self {
            language: LanguageId::Rust,
            provider_id: "rustfmt",
            argv0: "rustfmt",
            fixed_arguments: &["--emit", "stdout", "--color", "never"],
            config_discovery: ConfigDiscovery::RustfmtToml,
            managed: ManagedFormatter::RustfmtLinuxX64,
            version_probe: VersionProbe::SelfVersionFlag,
        }
    }

    /// The Go formatter authority (P15).
    ///
    /// `fixed_arguments` is deliberately **empty**: bare `gofmt`, with no
    /// positional path and no flags, reads Go source from stdin and writes
    /// the canonically-formatted result to stdout (verified empirically
    /// against the installed `gofmt` from `go1.26.6`; exit `2` with a
    /// `<standard input>:line:col: message` diagnostic on unparseable
    /// input). That is the identical stdin/stdout contract
    /// [`crate::invocation`] already implements for rustfmt, so no new
    /// invocation mechanism is needed.
    ///
    /// Notably absent: `-s` (simplify) and `-r` (rewrite rules). Both are
    /// source *transformations* beyond canonical formatting -- including
    /// them would make Corulix's `gate.format` silently rewrite code
    /// semantics under a formatting authority. `-l`/`-d` are also absent:
    /// they suppress the formatted output this crate needs.
    #[must_use]
    pub const fn gofmt() -> Self {
        Self {
            language: LanguageId::Go,
            provider_id: "gofmt",
            argv0: "gofmt",
            fixed_arguments: &[],
            config_discovery: ConfigDiscovery::None,
            managed: ManagedFormatter::GoSemanticRuntimeHostNative,
            version_probe: VersionProbe::SiblingGoVersion,
        }
    }

    /// The Biome formatter authority for TypeScript (P16). `--stdin-file-path`
    /// carries a *fixed*, extension-only synthetic name -- Biome only
    /// inspects the extension to select its TypeScript parser, never the
    /// real workspace path (which never reaches Biome's own process at all;
    /// see [`crate::invocation`]'s stdin/stdout-only contract, identical to
    /// rustfmt's). `format` (not `check`/`lint`) is Biome's own formatting
    /// subcommand, empirically re-verified this phase to write the
    /// reformatted result to stdout when given `--stdin-file-path` with no
    /// positional path (ADR 0010's own research gate).
    #[must_use]
    pub const fn biome_typescript() -> Self {
        Self {
            language: LanguageId::TypeScript,
            provider_id: "biome",
            argv0: "biome",
            fixed_arguments: &["format", "--stdin-file-path=stdin.ts"],
            config_discovery: ConfigDiscovery::None,
            managed: ManagedFormatter::BiomeLinuxX64,
            version_probe: VersionProbe::SelfVersionFlag,
        }
    }

    /// The Biome formatter authority for TSX (P16). TSX gets its own
    /// synthetic `--stdin-file-path` extension (`.tsx`) so Biome selects its
    /// JSX-aware TypeScript parser rather than plain `.ts` -- mirroring the
    /// same "TSX must never be silently treated as ordinary `.ts`"
    /// discipline the semantic vertical already established for the LSP
    /// side (`typescriptreact` `lsp_language_id`).
    #[must_use]
    pub const fn biome_tsx() -> Self {
        Self {
            language: LanguageId::Tsx,
            provider_id: "biome",
            argv0: "biome",
            fixed_arguments: &["format", "--stdin-file-path=stdin.tsx"],
            config_discovery: ConfigDiscovery::None,
            managed: ManagedFormatter::BiomeLinuxX64,
            version_probe: VersionProbe::SelfVersionFlag,
        }
    }

    /// The Biome formatter authority for JavaScript (P16).
    #[must_use]
    pub const fn biome_javascript() -> Self {
        Self {
            language: LanguageId::JavaScript,
            provider_id: "biome",
            argv0: "biome",
            fixed_arguments: &["format", "--stdin-file-path=stdin.js"],
            config_discovery: ConfigDiscovery::None,
            managed: ManagedFormatter::BiomeLinuxX64,
            version_probe: VersionProbe::SelfVersionFlag,
        }
    }

    /// The `ruff format` formatter authority for Python (P17, ADR 0011 §1).
    ///
    /// `--stdin-filename stdin.py` carries a fixed, extension-only synthetic
    /// name -- ruff only inspects the extension to select its Python
    /// formatting rules, never the real workspace path (which never reaches
    /// ruff's own process at all; see [`crate::invocation`]'s stdin/stdout-
    /// only contract, identical to rustfmt's/Biome's). The trailing `-` is
    /// ruff's own "read source from stdin" marker (empirically confirmed by
    /// ADR 0011: `ruff format --stdin-filename foo.py -q -` reads stdin,
    /// writes the formatted result to stdout, and never touches a live
    /// file). `-q` suppresses ruff's own informational banner on stderr,
    /// which this crate never reads back anyway (mirrors rustfmt's
    /// `--color never`: reducing incidental output, not load-bearing for
    /// correctness).
    ///
    /// `ManagedFormatter::RuffLinuxX64`: `ruff` now resolves
    /// `CORULIX_MANAGED`-first (owner-pinned Ruff 0.16.3), falling through to
    /// `wht_corulix_config::resolve_provider`'s `HOST_ONLY`/approved-directory
    /// precedence only when genuinely not provisioned -- ADR 0011 §1's
    /// original `HOST_ONLY`-only stance is explicitly, narrowly superseded for
    /// this auxiliary tier by the M03 Python managed-auxiliary final closure
    /// (the ADR's historical record is preserved, not rewritten).
    #[must_use]
    pub const fn ruff_format() -> Self {
        Self {
            language: LanguageId::Python,
            provider_id: "ruff",
            argv0: "ruff",
            fixed_arguments: &["format", "--stdin-filename", "stdin.py", "-q", "-"],
            config_discovery: ConfigDiscovery::None,
            managed: ManagedFormatter::RuffLinuxX64,
            version_probe: VersionProbe::SelfVersionFlag,
        }
    }

    /// Structural proof that no profile in the table can ever ask a
    /// formatter to write the live workspace file itself. Checked as an
    /// invariant over [`ALL`] by this crate's own test suite, so a future
    /// edit that adds `-w`/`--write`/`--in-place` to any arm fails the build
    /// gate rather than silently gaining live-write authority.
    ///
    /// `#[cfg(test)]`: this is a build-time structural assertion over a
    /// `const` table, not a runtime guard. Compiling it into production
    /// would be dead defensive code for a condition the table already makes
    /// unreachable -- the invariant belongs in the gate that checks it, and
    /// that gate is the test suite.
    #[must_use]
    #[cfg(test)]
    pub fn forbids_in_place_write(&self) -> bool {
        const IN_PLACE_FLAGS: &[&str] = &["-w", "--write", "-i", "--in-place", "--emit=files"];
        !self
            .fixed_arguments
            .iter()
            .any(|argument| IN_PLACE_FLAGS.contains(argument))
    }
}

/// Every language this crate has a formatter authority for. A language
/// absent from this table is refused before any process is spawned (see
/// [`profile_for`]).
pub(crate) const ALL: &[FormatterProfile] = &[
    FormatterProfile::rustfmt(),
    FormatterProfile::gofmt(),
    FormatterProfile::biome_typescript(),
    FormatterProfile::biome_tsx(),
    FormatterProfile::biome_javascript(),
    FormatterProfile::ruff_format(),
];

/// The formatter profile for `language`, or `None` when this crate has no
/// admitted formatter authority for it. Fail-closed by construction: a new
/// [`LanguageId`] variant gains no formatter until a profile is deliberately
/// added here, and never inherits another language's arm.
#[must_use]
pub(crate) fn profile_for(language: LanguageId) -> Option<FormatterProfile> {
    ALL.iter()
        .find(|profile| profile.language == language)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact invocation the pre-P15 code hard-coded, asserted field by
    /// field so the certified Phase 9/10/10-R2 Rust path cannot silently
    /// change shape while being generalized.
    #[test]
    fn rust_profile_matches_the_pre_p15_hardcoded_invocation() {
        let profile = FormatterProfile::rustfmt();
        assert_eq!(profile.provider_id, "rustfmt");
        assert_eq!(profile.argv0, "rustfmt");
        assert_eq!(
            profile.fixed_arguments,
            &["--emit", "stdout", "--color", "never"]
        );
        assert_eq!(profile.config_discovery, ConfigDiscovery::RustfmtToml);
        assert_eq!(profile.managed, ManagedFormatter::RustfmtLinuxX64);
        assert_eq!(profile.version_probe, VersionProbe::SelfVersionFlag);
    }

    /// `P15_GOFMT_LIVE_INPLACE_WRITE_COUNT=0` as a structural invariant over
    /// the whole table, not a per-arm spot check.
    #[test]
    fn no_profile_can_request_an_in_place_write() {
        for profile in ALL {
            assert!(
                profile.forbids_in_place_write(),
                "{:?} carries an in-place-write flag: {:?}",
                profile.language,
                profile.fixed_arguments
            );
        }
    }

    /// gofmt takes no positional path and no flags -- the construction that
    /// makes a live in-place write impossible rather than merely unrequested.
    #[test]
    fn gofmt_profile_passes_no_arguments_at_all() {
        assert!(FormatterProfile::gofmt().fixed_arguments.is_empty());
    }

    /// gofmt has no configuration file, so reusing rustfmt's discovery would
    /// invent semantics the real tool does not have.
    #[test]
    fn gofmt_profile_performs_no_config_discovery() {
        assert_eq!(
            FormatterProfile::gofmt().config_discovery,
            ConfigDiscovery::None
        );
    }

    /// Exactly one profile per language, and no language shares another's
    /// arm.
    #[test]
    fn the_table_has_one_distinct_profile_per_language() {
        let mut languages: Vec<LanguageId> = ALL.iter().map(|profile| profile.language).collect();
        let total = languages.len();
        languages.sort_by_key(std::string::ToString::to_string);
        languages.dedup();
        assert_eq!(languages.len(), total, "duplicate language in the table");
        assert_eq!(
            profile_for(LanguageId::Rust).map(|p| p.provider_id),
            Some("rustfmt")
        );
        assert_eq!(
            profile_for(LanguageId::Go).map(|p| p.provider_id),
            Some("gofmt")
        );
        assert_eq!(
            profile_for(LanguageId::TypeScript).map(|p| p.provider_id),
            Some("biome")
        );
        assert_eq!(
            profile_for(LanguageId::Tsx).map(|p| p.provider_id),
            Some("biome")
        );
        assert_eq!(
            profile_for(LanguageId::JavaScript).map(|p| p.provider_id),
            Some("biome")
        );
        assert_eq!(
            profile_for(LanguageId::Python).map(|p| p.provider_id),
            Some("ruff")
        );
    }

    /// P17: `ruff format` never requests an in-place write and performs no
    /// repository config discovery this phase (ADR 0011 §1).
    #[test]
    fn ruff_format_profile_matches_adr_0011() {
        let profile = FormatterProfile::ruff_format();
        assert_eq!(profile.provider_id, "ruff");
        assert_eq!(profile.managed, ManagedFormatter::RuffLinuxX64);
        assert_eq!(profile.config_discovery, ConfigDiscovery::None);
        assert!(profile.forbids_in_place_write());
        assert!(profile.fixed_arguments.contains(&"stdin.py"));
    }

    /// P16: each TS-family language gets its own distinct `--stdin-file-path`
    /// extension, so Biome never misclassifies TSX as plain TypeScript or
    /// JavaScript as either.
    #[test]
    fn biome_profiles_use_distinct_stdin_file_path_extensions() {
        assert!(
            FormatterProfile::biome_typescript()
                .fixed_arguments
                .contains(&"--stdin-file-path=stdin.ts")
        );
        assert!(
            FormatterProfile::biome_tsx()
                .fixed_arguments
                .contains(&"--stdin-file-path=stdin.tsx")
        );
        assert!(
            FormatterProfile::biome_javascript()
                .fixed_arguments
                .contains(&"--stdin-file-path=stdin.js")
        );
    }

    /// P16: Biome never performs repository `biome.json` discovery this
    /// phase (ADR 0010 `P16_CONFIG_PRECEDENCE`).
    #[test]
    fn biome_profiles_perform_no_config_discovery() {
        for profile in [
            FormatterProfile::biome_typescript(),
            FormatterProfile::biome_tsx(),
            FormatterProfile::biome_javascript(),
        ] {
            assert_eq!(profile.config_discovery, ConfigDiscovery::None);
        }
    }

    /// P15 §14, recorded as a checked constant rather than only as prose in
    /// a changelog.
    #[test]
    fn goimports_is_not_admitted() {
        assert_eq!(GOIMPORTS_DECISION, "NOT_REQUIRED");
        assert!(
            ALL.iter().all(|profile| profile.provider_id != "goimports"),
            "goimports must never appear as a formatter authority"
        );
    }
}
