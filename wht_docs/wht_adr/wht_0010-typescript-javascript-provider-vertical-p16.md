# ADR 0010 — TypeScript/JavaScript Provider Vertical (Phase 16)

**Status:** Accepted (supersedes ADR 0008)

## 1.0.0 reconciliation note

This ADR preserves point-in-time implementation reasoning. Any statements below that describe TypeScript/JavaScript formatter, `validate_change`, typecheck, lint, or test-runner wiring as future/pending work are **historical intermediate state**. Those integration items were subsequently completed before the 1.0.0 baseline. The current capability authority is `wht_docs/wht_language_support.md`; this ADR remains the design-decision record.

## Relationship to ADR 0008

ADR 0008 admitted `typescript-language-server` as the TS/JS `LanguageServer`
provider but closed `TYPESCRIPT_LSP_E2E=BLOCKED_PROVIDER_UNAVAILABLE`: this
development host had no host-approved classic TypeScript install exposing
`tsserver.js` (the host's only installed TypeScript was the native/Go-ported
`tsgo` rewrite, which ships no `tsserver.js` at all), and
`AUTO_INSTALL_LSP_PROVIDER=NO` forbade installing one to unblock it.

Since ADR 0008 closed, `wht_corulix_lsp::profile` gained two structurally
different, already-implemented provider profiles
(`LspProviderProfile::typescript_7_native`/`typescript_7_native_for_javascript`
and `LspProviderProfile::typescript_language_server_managed`/
`typescript_language_server_managed_for_javascript`) and
`wht_corulix_lsp::managed_toolchain` gained pinned, checksummed manifests for
both: `TYPESCRIPT_7_LINUX_X64` (native TS7, `@typescript/typescript-linux-x64@7.0.2`)
and `TYPESCRIPT_LANGUAGE_SERVER_LINUX_X64` + its own pinned
`TYPESCRIPT_6_LINUX_X64` component supplying a real `lib/tsserver.js`
extracted directly from an npm-published `typescript-language-server`
tarball and injected as `initializationOptions.tsserver.path`. This
structurally resolves ADR 0008's exact gap: Corulix no longer depends on a
host-approved directory happening to contain a classic TypeScript install --
it manages its own pinned one. ADR 0008 is therefore stale and this ADR
supersedes it; ADR 0008's security proof and rejection of `vtsls` remain
historically accurate and are not re-litigated here.

## Decisions

### `LSP_PROVIDER_TS7`

`wht_corulix_lsp::profile::LspProviderProfile::typescript_7_native()` --
native TypeScript 7 LSP, backed by the pinned `TYPESCRIPT_7_LINUX_X64`
managed component. **PRESERVED** from the existing architecture; not
replaced.

### `LSP_PROVIDER_TS6`

`wht_corulix_lsp::profile::LspProviderProfile::typescript_language_server_managed()`
-- managed Node + managed `typescript-language-server`, with its
`tsserver.path` pointed at the pinned `TYPESCRIPT_6_LINUX_X64` component's
`lib/tsserver.js`. **PRESERVED**. TypeScript 6 is current supported
compatibility, not legacy; no TypeScript 5 support is introduced.

### `LSP_PROVIDER_JAVASCRIPT`

The same TS-family profiles, `_for_javascript` variants
(`typescript_7_native_for_javascript` / `typescript_language_server_managed_for_javascript`),
selected by the same version-routing rule as TS. JavaScript is not a third,
independently-provisioned provider family; it rides the same managed
components as TypeScript, exactly as `profile.rs` already models it.

### `FORMATTER_PROVIDER` = **Biome**

Candidates evaluated: dprint, Biome, Prettier.

| Criterion         | dprint                                                                                 | Biome                                                                                                                                                                              | Prettier                                                                                                                                                                                                                                       |
| ----------------- | -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| stdin -> stdout   | `dprint fmt --stdin <ext>`, stable across releases                                     | `biome format --stdin-file-path=...`, but a documented history of stdin regressions (e.g. a 2.4 regression that broke stdin formatting outright, GH #9095/#6419/#5673/#1355/#3633) | `--stdin-filepath`, mature and stable                                                                                                                                                                                                          |
| Config execution  | `dprint.json` is plain JSON; plugins are WASM, sandboxed, no ambient FS/network access | `biome.json` is plain JSON; no plugin system for formatting at all                                                                                                                 | `.prettierrc.js`/`prettier.config.js` is arbitrary executed JavaScript; plugins are arbitrary npm packages with full Node.js access (demonstrated supply-chain incidents: the `eslint-config-prettier` npm compromise, `prettier-s` typosquat) |
| Distribution      | Single native binary per platform, checksummed release table (0.56.1, 2026-08-21)      | Single native binary per platform                                                                                                                                                  | No standalone binary with real config/plugin support; fundamentally a Node.js + npm-plugin-tree tool                                                                                                                                           |
| License           | MIT                                                                                    | MIT/Apache-2.0                                                                                                                                                                     | MIT                                                                                                                                                                                                                                            |
| TS/TSX/JS support | Full                                                                                   | Full                                                                                                                                                                               | Full                                                                                                                                                                                                                                           |

`dprint` was the technically preferred candidate on format-quality/stdin-
stability grounds (WASM-sandboxed plugin model, no regression history
comparable to Biome's), but **is rejected for this phase** on a distinct,
narrower ground: every dprint release publishes only `.zip` archives for
every platform (verified against the live GitHub Releases API for the
current release, `dprint-x86_64-unknown-linux-gnu.zip`), and
`wht_corulix_tooling::provisioning::ArchiveKind` -- the sole extraction
authority every existing managed component (rustfmt, gofmt, rust-analyzer,
gopls, Pyright, TypeScript 7/6, Node) already uses -- supports only
`TarGz`/`TarBz2`/`GzippedBinary`/`RawBinary`. Adding a fifth, zip-specific
extraction path to that shared authority is real, cross-cutting surface
this phase's own scope (a formatter _decision_, not a provisioning-pipeline
extension) does not need to take on when a fully equivalent, already-
supported alternative exists. Prettier is rejected outright regardless: its
config/plugin model executes arbitrary JavaScript with full host access and
requires a Node.js + npm plugin tree, incompatible with a single-pinned-
binary `CONTROLLED_EXTERNAL_TOOL` posture.

**Biome is selected instead**, as both formatter and linter authority (one
managed component, two invocations -- `biome format`/`biome lint`, never a
second managed identity for what is architecturally one binary). Biome
publishes a bare, uncompressed `biome-linux-x64` executable per release --
`ArchiveKind::RawBinary`, already supported with zero provisioning changes.
Its documented stdin-formatting regression history
(`FORMATTER_PROVIDER` research, GH #9095 et al.) was independently
re-verified this phase against the exact pinned release
(`@biomejs/biome@2.5.11`): `echo 'const   x=1' | biome format
--stdin-file-path=test.ts` returns `const x = 1;` correctly (real,
empirical re-test, not assumed from the research pass), and `biome lint
--reporter=json` against a real fixture returns well-formed, accurate JSON
diagnostics. `biome.json` is purely declarative JSON; Biome's only
extension mechanism (GritQL, `.grit` files) is a declarative structural-
pattern-matching DSL, not general-purpose executable code, and is never
invoked by Corulix's own fixed invocation. `P16_FORMATTER_DECISION=Biome`,
`P16_FORMATTER_AUTHORITY_ROLE=AUTHORITATIVE`.

### `FORMATTER_DISCOVERY_POLICY`

No repository-config-file discovery is admitted this phase (mirrors gofmt's
`ConfigDiscovery::None`, not rustfmt's upward-search model): `biome.json`
discovery/parsing is deferred; Biome is invoked with Corulix's own fixed,
minimal formatting options via `--stdin-file-path`, never with a
repository-supplied `biome.json` loaded implicitly. This keeps the
formatter's own configuration surface fully `HOST_ONLY`/Corulix-controlled
for this phase, consistent with `P16_CONFIG_PRECEDENCE` below.

### `P16_FORMATTER_EXECUTION_CLASS` / `CONFIG_EXECUTION_MODEL` / `PLUGIN_EXECUTION_MODEL`

```text
P16_FORMATTER_EXECUTION_CLASS=CONTROLLED_EXTERNAL_TOOL
P16_FORMATTER_CONFIG_EXECUTION_MODEL=DECLARATIVE_JSON_ONLY (no repository biome.json is read this phase; see FORMATTER_DISCOVERY_POLICY)
P16_FORMATTER_PLUGIN_EXECUTION_MODEL=NOT_LOADED_THIS_PHASE (Biome's own GritQL plugin mechanism is declarative-only and is never invoked by Corulix's own fixed invocation)
```

### `LINTER_PROVIDER` = **Biome** (built-in rules only)

Candidates evaluated: ESLint, Biome, Oxlint.

- **ESLint** rejected: flat config (`eslint.config.js`, default since v9)
  and legacy `.eslintrc.js` are executable JavaScript; ESLint's own
  maintainers have discussed and rejected a non-executing config
  alternative as impractical
  (`github.com/eslint/eslint/discussions/17853`); real-world usage
  universally pulls plugin packages (`@typescript-eslint`, framework
  plugins). Supply-chain precedent: CVE-2025-54313
  (`eslint-config-prettier` compromise). `EXECUTES_REPOSITORY_AUTHORED_CODE`
  -- not admissible as `CONTROLLED_EXTERNAL_TOOL` this phase.
- **Oxlint** viable in principle (single Rust binary, zero-config
  baseline, declarative `.oxlintrc.json`), but its "JS Plugins" feature
  (alpha, March 2026) is explicitly ESLint-plugin-compatible arbitrary JS
  loading; admitting Oxlint would require Corulix to positively reject
  that config surface at ingestion, an extra proof this phase does not
  need to take on given Biome already covers the same ground.
- **Biome** selected: single native binary, `biome.json` purely
  declarative JSON, 200+ built-in TS/TSX/JS/JSX rules give a real
  zero-plugin baseline, and its only extension mechanism (GritQL, `.grit`
  files) is a declarative structural-pattern-matching DSL, not
  general-purpose executable code -- no JS/native plugin bridge is shipped.

Biome's linter is invoked read-only against a confined staged copy of the
target file (never the live workspace path, and never over stdin/stdout --
linting produces findings, not rewritten bytes), which also sidesteps
Biome's stdin-formatting regression history entirely: that history is
specific to `biome format --stdin-*`, not to `biome lint <path>` reading a
real file. `P16_LINTER_DECISION=Biome (built-in rules only; GritQL plugin
config keys are rejected at ingestion, not merely unused)`,
`P16_LINTER_AUTHORITY_ROLE=SupportingOnly` (folds into the same
`gate.diagnostics` record the LSP/typecheck outcome produces, exactly as
`clippy`/`go vet` do for their languages -- it can only make an
already-clean diagnostics verdict stricter, never independently close or
fail the gate). `P16_LINTER_EXECUTION_CLASS=CONTROLLED_EXTERNAL_TOOL`.

### `LINTER_DISCOVERY_POLICY`

No repository `biome.json` discovery this phase, for the identical reason
as the formatter: Biome is invoked with Corulix's own fixed built-in-rule
selection, never a repository-supplied config file.

### `TYPESCRIPT_TYPECHECK_AUTHORITY`

`tsc --noEmit`, version-routed to the session's declared TypeScript major:
the TS7-native managed component's own bundled `tsc` entry point for TS7
projects (`TYPESCRIPT_7_LINUX_X64`'s `binary_path_in_tarball` is
`package/lib/tsc`, already pinned, and is a real CLI entry point --
confirmed by this ADR's own decision text elsewhere in this document).

**Known gap, disclosed rather than glossed over:** for TS6 projects, this
decision is **not yet implementable exactly as stated** against the
currently-pinned `TYPESCRIPT_6_LINUX_X64` manifest. That manifest pins
`binary_path_in_tarball: "package/lib/tsserver.js"` with `required_paths:
["package/lib/_tsserver.js", "package/lib/typescript.js"]` -- `typescript.js`
is a **library** (the TypeScript compiler API surface), not a CLI, and
cannot itself be invoked with `--noEmit` the way `tsc` can. Neither
`lib/tsc.js` nor `bin/tsc` is currently a pinned path on that manifest. A
follow-on pass implementing TS6 typecheck must either add `lib/tsc.js`
(the real npm `typescript@6.0.3` tarball does ship one, alongside
`bin/tsc`) as an additional `required_paths`/`binary_path_in_tarball`
entry on `TYPESCRIPT_6_LINUX_X64`, or admit a second, TS6-specific managed
component pinning it explicitly. `P16_TS6_TYPECHECK_MANIFEST_GAP=DISCLOSED_NOT_CLOSED`.
Project selection for whichever TS6 typecheck entry point a future pass
adds: the nearest `tsconfig.json` found by bounded upward
search from the target file to the workspace root (never outside it,
mirroring rustfmt's own bounded-upward-search precedent); `--noEmit` is
always supplied so no build artifact is ever written; a project reference
graph, if present, is resolved by `tsc` itself (`--build` is not used --
`--noEmit` on the root project's own `tsconfig.json` is the authority, not
a multi-project build orchestration this phase does not admit).
`P16_TYPESCRIPT_TYPECHECK_AUTHORITY=tsc --noEmit (version-routed TS7/TS6 managed tsc)`,
`P16_TYPESCRIPT_TYPECHECK_EXECUTION_CLASS=CONTROLLED_EXTERNAL_TOOL` (the
managed `tsc` itself is Corulix-pinned; it may still execute a
repository's own `tsconfig.json` **path references**, which is why Rule
45's confinement proof matters -- the _tool_ is controlled, the _project
graph it is told to check_ is repository data, not code).

### `JAVASCRIPT_CHECK_POLICY` = EXPLICIT

- Plain JavaScript with no `jsconfig.json`: no `TypecheckBuild` category is
  attempted; `gate.diagnostics` is satisfied by LSP diagnostics (+ Biome
  SupportingOnly) alone, exactly as for any language with no typecheck
  authority.
- A `jsconfig.json` (or `tsconfig.json` targeting `.js` via `allowJs`) is
  present but `checkJs` is not enabled: same as above -- Corulix does not
  force TypeScript-compiler-grade diagnostics onto a project that has not
  opted in.
- `checkJs: true` (in `jsconfig.json` or `tsconfig.json`) is present,
  including JSDoc-typed JavaScript: `tsc --noEmit` is run against that
  project exactly as for a TypeScript project, using its own declared
  `allowJs`/`checkJs`/JSDoc settings -- Corulix never overrides them.

### `PROJECT_TEST_RUNNER_DISCOVERY_POLICY` (deterministic)

Evidence checked in this order, from the workspace root's own
`package.json` (never a global assumption):

1. `package.json#scripts.test` is read. Its command string is classified
   against a finite, named set of recognized patterns:
   `node --test` / `node --test <path>` (Node's own built-in runner, fully
   offline, zero-install), `jest`, `vitest`, `mocha`, `ava`, `tap`/`node-tap`.
   Classification is a literal-prefix/word match against the _documented_
   invocation forms of each -- never a fuzzy heuristic.
2. If `scripts.test` is absent, empty, or matches none of the recognized
   patterns: `P16_AMBIGUOUS_TEST_RUNNER_RESULT=RequiredCapabilityUnavailable`
   (typed, fail-closed) -- **no** silent default to `npm test`/`jest`.
3. A recognized runner's own _invocation_ is executed as declared
   (`node --test`, etc.) via `wht_corulix_tooling::execute`, never
   reimplemented; Corulix does not parse the runner's own further config
   (e.g. `jest.config.js`) -- it trusts the `package.json` script exactly as
   written, since the script itself is already `TRUSTED_WORKSPACE_EXECUTION`
   (see below).

`P16_TEST_RUNNER_DISCOVERY=DETERMINISTIC`,
`P16_GLOBAL_TEST_FRAMEWORK_ASSUMPTION_COUNT=0`.

### `PACKAGE_MANAGER_DISCOVERY_POLICY`

1. `package.json#packageManager` (corepack-style `"npm@x"`/`"pnpm@x"`/`"yarn@x"`)
   is authoritative when present and well-formed.
2. Otherwise, lockfile presence: `package-lock.json` -> npm,
   `pnpm-lock.yaml` -> pnpm, `yarn.lock` -> yarn.
3. More than one lockfile present, or neither `packageManager` nor a
   recognized lockfile: `P16_UNSUPPORTED_PACKAGE_MANAGER_BEHAVIOR=RequiredCapabilityUnavailable`
   (fail closed, never guessed).

`P16_PACKAGE_MANAGER_DISCOVERY_POLICY` = as above,
`P16_SUPPORTED_PACKAGE_MANAGERS=[npm, pnpm, yarn]`. Corulix never invokes
`npm install`/`pnpm install`/`yarn install`/`npx --yes` as implicit tooling
acquisition; package-manager discovery exists only to disambiguate which
manager's lockfile is authoritative for dependency-tree evidence a future
phase may consult, not to trigger installation. This phase makes no
practical use of package-manager identity beyond this discovery contract
(no dependency install occurs in the test-runner or typecheck path).

### `TS_VERSION_ROUTING_POLICY`

Unchanged from the existing, already-certified architecture
(`profile.rs::route_for_declared_major`-equivalent table, lines 713-714/
727-728): a session's declared TypeScript major (`None` or `Some(7)` ->
TS7 native; `Some(6)` -> TS6 managed-compat) selects the provider profile.
`P16_TS_VERSION_ROUTING_DETERMINISTIC=PASS`.
`P16_AMBIGUOUS_TS_VERSION_BEHAVIOR=No ambient/globally-installed TypeScript
version is ever consulted; a project with no resolvable declared major
routes to the same default as `None` (TS7 native) -- there is no
"ambiguous" state distinct from "undeclared", by construction.`

### `PROVIDER_RESOLUTION_MODEL`

Language-aware, mirroring the pattern already established for Rust and Go
in `wht_corulix_engine::semantic::semantic_at`: the `[ProviderResolution; 3]`
formatter/typecheck/linter triple is resolved by an explicit `match language`
arm per admitted language family (`LanguageId::Rust` -> Rust's own managed
resolutions, `LanguageId::Go` -> Go's own `HOST_ONLY` resolutions,
`LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript` -> this
phase's own TS/JS resolutions), with a distinct, honest `_` arm for every
language that has no admitted resolution yet (currently only
`LanguageId::Python`) returning a typed "not yet admitted" outcome. This
replaces the pre-P16 `_ => { real_managed_formatter_resolution(...) ;
real_managed_typecheck_and_linter_resolutions(...) }` arm, which
incorrectly evaluated every non-Go language (including the languages this
ADR admits) against Rust's own `CORULIX_MANAGED` rustfmt/cargo
check/clippy resolutions.
`P16_TS_JS_RUST_PROVIDER_MISCLASSIFICATION_COUNT=0` after this fix.

### `TRUST_MODEL`

- TS7-native/TS6-managed LSP sessions, `Biome`, and `tsc`: `CONTROLLED_EXTERNAL_TOOL`,
  resolved exclusively through their pinned `CORULIX_MANAGED` components --
  no `HOST_ONLY`/ambient resolution path exists for them (mirrors Rust's
  own managed-first posture).
- `package.json` test/build scripts (i.e. the resolved `scripts.test`
  command actually executed): `TRUSTED_WORKSPACE_EXECUTION`, requiring
  `HOST_ONLY` trust exactly as Go's `go build`/`go test` do -- a
  repository's own script content cannot self-elevate, and an untrusted
  `ChangeSession` denies execution before the script is ever spawned.

### `CONFIG_PRECEDENCE`

`HOST_ONLY` / `REPOSITORY_HINT` / `REQUEST_SCOPED`, per the existing
`wht_corulix_config::trust::EffectiveConfig` precedence (unchanged --
`resolve_provider`'s own documented precedence: `HOST_ONLY` absolute-path
override, then approved system directories, then approved user-toolchain
directories if host-enabled, else unavailable). `package.json`,
`tsconfig.json`/`jsconfig.json`, and any linter/formatter config file are
all `REPOSITORY_HINT`-tier data at most (a project can _select_ which
declared major/test script/project file Corulix reads) -- none of them can
lower the security floor `HOST_ONLY` sets (e.g. a repository cannot make an
otherwise-untrusted session able to execute `package.json` scripts by
declaring anything in its own files).

### `NETWORK_BEHAVIOR`

`OS_LEVEL_NETWORK_ISOLATION=NOT_CLAIMED` (per Rule 36's own instruction: no
real OS-level network deny exists in this environment, so this is the
honest claim, not a stronger one). Corulix's own configuration continues
disabling Automatic Typing Acquisition for the TS/JS LSP sessions (already
proven in ADR 0008's security posture, unchanged); no other Corulix-
triggered network access is introduced for the formatter, linter, typecheck,
or test-runner paths in this phase -- all four operate purely on
already-resolved, already-managed, or already-workspace-local inputs.

### `KNOWN_LIMITATIONS`

- No repository-supplied `dprint.json`/`biome.json` is read this phase
  (`FORMATTER_DISCOVERY_POLICY`/`LINTER_DISCOVERY_POLICY` above); a
  project's own formatting/linting preferences are not yet honored.
- Monorepo/multi-package `tsconfig.json` project-reference graphs are
  typechecked via `tsc`'s own reference resolution from the nearest
  `tsconfig.json`, but Corulix does not independently discover "which
  package a file belongs to" the way it discovers a Go module boundary;
  see `P16_MONOREPO_PROJECT_DISCOVERY` in the final report.
- `PROJECT_TEST_RUNNER_DISCOVERY_POLICY` recognizes a finite, named set of
  runner invocations; an unrecognized custom test script fails closed
  (`RequiredCapabilityUnavailable`) rather than executing an unclassified
  command.

### `REJECTED_ALTERNATIVES`

```text
REJECTED_ALTERNATIVES=[
  vtsls (LSP; carried over from ADR 0008, upstream best-effort reliability posture),
  dprint (formatter; technically preferred on format-quality/stdin-stability grounds, but rejected this phase because its only distributed linux-x64 artifact is a .zip archive, and wht_corulix_tooling::provisioning::ArchiveKind does not yet support zip extraction -- extending the shared provisioning pipeline is out of this phase's bounded scope when Biome's RawBinary artifact already fits it),
  Prettier (formatter; executes-repository-code config/plugin model, no single-binary distribution),
  ESLint (linter; executable flat/legacy config, real-world plugin dependence),
  Oxlint (linter; viable but redundant given Biome already covers the same declarative-only ground, and its JS-plugin alpha would need explicit rejection Biome does not require),
]
```

## Process note: ADR-before-code was not strictly honored for `FORMATTER_PROVIDER`

```text
P16_ADR_REVISION_NOTE=FORMATTER_PROVIDER was first closed in this ADR as
dprint, and production code (managed_toolchain.rs, semantic.rs) was written
against that decision before the ArchiveKind zip gap was discovered during
implementation. The ADR was then revised to Biome and the code updated to
match. The revision itself is evidence-driven and is fully documented above
(candidate table, rejection reasoning, real re-verified stdin/lint probes);
the §3 hard-gate ordering (ADR FINAL strictly before any code mutation) was
therefore not strictly honored for this one decision. Disclosed here rather
than silently corrected, per this workspace's own fail-closed evidence
discipline.
```
