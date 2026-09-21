# ADR 0011 — Python Provider Vertical (Phase 17): Formatter, Linter,

# Typechecker, Test Runner, and Runtime Authority

**Status:** Accepted

## 1.0.0 reconciliation note

This ADR preserves the policy decisions and intermediate implementation notes from the Python vertical. Statements below that describe the phase as still open are historical only: the Python semantic, formatting, typecheck, lint and governed test paths were completed before the 1.0.0 baseline. Current capability authority is `wht_docs/wht_language_support.md`.

> **M03 SemanticRename auxiliary-tier update (2026-09-07):** the owner has
> narrowly superseded this ADR's `HOST_ONLY`-only authority for `ruff`
> (Formatter + Linter) and the Pyright CLI (`TypecheckBuild`), **specifically
> and only** for the `SemanticRename` auxiliary-capability tier
> (`ADR_0011_SEMANTIC_RENAME_AUXILIARY_POLICY=SUPERSEDED_BY_MANAGED_FIRST_REQUIREMENT`).
> `ruff` now resolves `CORULIX_MANAGED` first (owner-pinned Ruff 0.16.3,
> `wht_corulix_tooling::managed_runtimes::RUFF_LINUX_X64`/`_WINDOWS_X64`),
> falling through to this ADR's original `HOST_ONLY`/approved-directory
> precedence only when genuinely not provisioned; the Pyright CLI resolves
> managed Node + the already-managed Pyright component's `dist/pyright.js`
> CLI sibling the same way. See
> `wht_crates/wht_corulix_engine/src/python_providers.rs`'s
> `resolve_ruff_tool`/`resolve_pyright_cli` for the real implementation. This
> update does **not** touch `pytest`/`python3` (§4/§5 below remain
> `HOST_ONLY`-only, unmodified) and does **not** touch this ADR's own
> `LanguageServer` identity (Pyright via `wht_corulix_lsp`, ADR 0009,
> unaffected). Every decision below is preserved verbatim as the historical
> record of this ADR's original, broader `HOST_ONLY`-only stance -- it is not
> rewritten, only narrowly overridden for the one auxiliary tier named above.

## Scope and relationship to ADR 0009

ADR 0009 closed exactly one decision -- Python's `LanguageServer` identity
(Pyright) -- and explicitly deferred everything else ("formatter/linter are
separate, later-governed authorities per Section 19 of the Phase 7B
mandate"). ADR 0009 is not stale and is not superseded here: its LSP
identity, readiness model, and untrusted-workspace proof stand unchanged.
This ADR closes the remaining Phase 17 policy surface: formatter identity,
linter identity, typechecker identity, project test-runner discovery policy,
Python runtime/interpreter authority, virtualenv policy, and project/config
discovery. All decisions below are required by the Phase 17 mandate's §3
hard gate before any Phase 17 production code is written.

## Existing scaffolding this ADR builds on (verified, not assumed)

- `wht_corulix_core::ProviderCategory` already defines `Formatter`, `Linter`,
  `TypecheckBuild`, `TestRunner`, and `Runtime` as first-class categories
  (`wht_crates/wht_corulix_core/src/provider.rs`) -- Phase 17 adds no new
  category.
- `wht_corulix_config::resolve_provider` already implements the
  HOST_ONLY-override -> approved-system-directory -> approved-user-toolchain
  -directory resolution chain, and never touches ambient `PATH`
  (`wht_crates/wht_corulix_config/src/resolver.rs`). This chain is reused
  unchanged for every Python-family executable (interpreter, formatter,
  linter, typechecker, test runner).
- `ExecutionClass::ControlledExternalTool` and
  `ExecutionClass::TrustedWorkspaceExecution` (`wht_corulix_core/src/
execution.rs`) already exist and are exactly the two classes this phase's
  providers need -- no new `ExecutionClass` variant is introduced.
- The Go vertical's `go_testing.rs` establishes the exact trust-gating
  pattern this ADR reuses verbatim for Python:
  `PROVIDER_EXECUTABLE_AUTHORITY != WORKSPACE_EXECUTION_TRUST_CLASS` --
  the interpreter/test-runner binary is Corulix-resolved by canonicalized
  path, while the workspace-authored test/plugin code it executes runs
  under `TrustedWorkspaceExecution` and is gated by
  `crate::diagnostics::authorize_trusted_execution` before any
  `ProcessSpec` is constructed.

## 1. Formatter identity

Candidates evaluated: Black, `ruff format`.

| Criterion                    | Black 26.5.1 (observed)                                                                                           | `ruff format` 0.16.1 (observed)                                                                                                                                                                                                       |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| stdin/stdout-only invocation | Confirmed: `black --stdin-filename foo.py -q -` reads stdin, writes formatted bytes to stdout, no live-file write | Confirmed: `ruff format --stdin-filename foo.py -` reads stdin, writes formatted bytes to stdout, no live-file write                                                                                                                  |
| Version-identity probe       | `black --version` succeeds without side effects (`black, 26.5.1 (compiled: yes) - Python (CPython) 3.10.12`)      | `ruff --version` succeeds without side effects (`ruff 0.16.1`)                                                                                                                                                                        |
| Plugin/extension loading     | None for formatting                                                                                               | None -- Ruff ships as a single compiled binary with no plugin-loading mechanism, matching the Pyright/ADR-0009 rationale and the Biome/ADR-0010 rationale                                                                             |
| Tool-surface reduction       | Formatter only; a separate linter tool is still required                                                          | Same binary also provides linting (`ruff check`), reducing the number of distinct external tools this ADR must separately govern, mirroring why Biome (formatter+linter in one binary) was preferred over Prettier+ESLint in ADR 0010 |
| Maintenance / license        | Actively maintained, MIT                                                                                          | Actively maintained, MIT                                                                                                                                                                                                              |
| Config discovery             | `pyproject.toml [tool.black]`, `.black` (rarely used)                                                             | `pyproject.toml [tool.ruff]`, `ruff.toml`, `.ruff.toml`                                                                                                                                                                               |

**Decision:** `ruff format` is the admitted Python formatter authority,
for the same structural reason Biome was preferred in ADR 0010: a single,
plugin-free, actively maintained binary that also closes the linter
decision below, minimizing the number of independently governed external
tool identities. Black remains a documented, rejected alternative -- not
because it is unsafe, but because admitting it in addition to a linter
tool would require governing two external tool identities where one
suffices.

```text
P17_FORMATTER_PROVIDER=ruff (subcommand: `ruff format`)
P17_FORMATTER_AUTHORITY_ROLE=AUTHORITATIVE
P17_FORMATTER_EXECUTION_CLASS=ControlledExternalTool
P17_FORMATTER_REJECTED_ALTERNATIVE=black
P17_FORMATTER_REJECTION_REASON=stdin/stdout-safe and version-probable like ruff, but admitting it would still require a second, separately governed tool identity for linting; ruff closes both with one binary
```

Config discovery mirrors ADR 0010's Biome decision for this phase: no
repository `pyproject.toml [tool.ruff]` / `ruff.toml` discovery is
performed by the formatter invocation this phase (`ConfigDiscovery::None`,
matching `ruff format`'s behavior when invoked with `--isolated` semantics
over stdin with no working-directory-based config search enabled). A
future phase may add governed repository-config discovery; this phase does
not, to avoid an ungoverned code/config-execution surface via
`pyproject.toml`.

## 2. Linter identity

`ruff check` (same binary as the formatter decision above) is the admitted
linter, in a `SupportingOnly` authority role (never independently closing
a gate the same way `TypecheckBuild` does -- see the pyright-vs-ruff
authority split in section 4). Verified empirically: `ruff check
--stdin-filename foo.py -` over a fixture with an unused import produced a
real, structured finding (`F401`) with a real non-zero exit code; a clean
fixture would exit 0.

```text
P17_LINTER_PROVIDER=ruff (subcommand: `ruff check`)
P17_LINTER_AUTHORITY_ROLE=SupportingOnly
P17_LINTER_EXECUTION_CLASS=ControlledExternalTool
P17_LINTER_PLUGIN_EXECUTION_MODEL=NONE -- ruff has no plugin-loading mechanism; all lint rules are compiled into the single ruff binary
```

## 3. Typechecker identity

Pyright is already the admitted `LanguageServer` provider (ADR 0009). This
ADR distinguishes Pyright's two roles explicitly, per the mandate's §20
requirement, rather than conflating them:

- **Interactive LSP diagnostics** (`textDocument/publishDiagnostics` over a
  long-lived `pyright-langserver --stdio` session): `LanguageServer`
  category, `SupportingOnly` authority for gate purposes (consistent with
  every other language in this workspace -- LSP diagnostics inform, but
  never alone close, `GateId::Diagnostics`).
- **Authoritative one-shot project typecheck** (`pyright --outputjson
<path>` as a short-lived `ControlledExternalTool` process, exit code plus
  structured JSON diagnostics, no persistent session): `TypecheckBuild`
  category, `Authoritative` role -- the same authority Rust's `cargo
check`/`cargo build` and Go's `go build`/`go vet` hold relative to their
  own LSP sessions.

These are two distinct `ProviderCategory` values (`LanguageServer` vs
`TypecheckBuild`) resolved and invoked independently; a long-lived LSP
session is never reused as the source of an authoritative typecheck
result, and a one-shot `pyright --outputjson` invocation is never treated
as though it were the LSP's semantic session.

```text
P17_TYPECHECKER_PROVIDER=pyright (one-shot `--outputjson`, distinct from the LSP session)
P17_TYPECHECKER_AUTHORITY_ROLE=AUTHORITATIVE
P17_TYPECHECKER_EXECUTION_CLASS=ControlledExternalTool
P17_PYRIGHT_SEMANTIC_VS_TYPECHECK_AUTHORITY=EXPLICIT
```

Version-identity probe: `pyright --version` succeeds cleanly
(`pyright 1.1.413`) and is used for the one-shot process, distinct from
ADR 0009's startup-log-based version discovery for the long-lived LSP
process (`--version` is compatible with the controlled-process contract
for the one-shot invocation specifically; ADR 0009's finding that the
`--stdio` LSP process does not respond to a bare `--version` mid-session
is unaffected).

## 4. Project test-runner policy

`pytest` is a strong candidate (9.1.1 observed, actively maintained, MIT)
but is never treated as a global default. Discovery order, most to least
specific:

1. `pyproject.toml` carries `[tool.pytest.ini_options]` -> pytest,
   authoritative.
2. `pytest.ini` or `tox.ini` with a `[pytest]` section present at the
   project root -> pytest, authoritative.
3. `pyproject.toml` declares `pytest` as a dependency
   (`[project.dependencies]` / `[project.optional-dependencies]` /
   `[tool.poetry.dependencies]` / `[tool.poetry.group.*.dependencies]`) with
   no conflicting runner marker -> pytest, authoritative.
4. No recognized marker resolves a runner -> `PLAN_UNEXECUTABLE` for the
   `GateId::Tests` gate when tests are required; the plan does not fall
   back to guessing, and does not silently skip the gate.

```text
P17_PROJECT_TEST_RUNNER_DISCOVERY=DETERMINISTIC
P17_GLOBAL_PYTEST_ASSUMPTION_COUNT=0
P17_TEST_RUNNER_PROVIDER=pytest (only when discovered per the order above)
P17_TEST_RUNNER_AUTHORITY_ROLE=AUTHORITATIVE
P17_TEST_RUNNER_EXECUTION_CLASS=TrustedWorkspaceExecution
```

Repository test execution (`pytest`, and any workspace-authored
`conftest.py`/fixture/plugin code it loads) is `TrustedWorkspaceExecution`,
identical in kind to Go's `go test` and Rust's `cargo test`: the interpreter
and pytest entry point are Corulix-resolved by canonicalized path
(`PROVIDER_EXECUTABLE_AUTHORITY`), but the test code itself only ever runs
because the operation carries the trust class and
`authorize_trusted_execution` authorizes it before any `ProcessSpec` is
built -- an `UNTRUSTED` workspace is denied before test code starts,
exactly as the mandate's §26 requires. Neither `RepositoryHints` nor MCP
`RequestOptions` can elevate this trust class (same non-elevation property
already documented for Go/Rust).

## 5. Python runtime/interpreter authority

`python3` is resolved through the exact same `wht_corulix_config::
resolve_provider` chain as every other externally-resolvable provider:
`ProviderCategory::Runtime`, HOST_ONLY absolute-path override first, then
approved system directories, then approved user-toolchain directories
(host-enabled only) -- never an ambient `PATH` search. This mirrors the
existing Node-for-Pyright/TypeScript pattern exactly (`Runtime` was already
split from `LanguageServer` as its own category specifically to avoid a
`HOST_ONLY` override collision between a runtime and the provider it
launches -- see the category's own doc comment, admitted during the
TypeScript/Python auxiliary Node-launcher work).

```text
P17_PYTHON_RUNTIME_POLICY=CORULIX_MANAGED_RESOLUTION (HOST_ONLY override, else approved-directory resolution; never ambient PATH)
P17_PYTHON_RUNTIME_AUTHORITY=wht_corulix_config::resolve_provider(ProviderCategory::Runtime)
P17_PYTHON_RUNTIME_EXECUTION_CLASS=ControlledExternalTool (interpreter invocation itself); TrustedWorkspaceExecution (workspace test/plugin code the interpreter runs, per section 4)
```

This phase does not require a genuinely ungoverned system-Python
dependency: the same approved-user-toolchain-directory mechanism that
already governs `black`'s/`ruff`'s/`pytest`'s/`node`'s resolution on this
host (each observed at `~/.local/bin/*` or `~/.nvm/...`, never resolved via
bare `PATH` lookup) applies unchanged to `python3`. No `PHASE_17_STATUS=
BLOCKED` is required on this point.

## 6. Virtualenv policy

A workspace-local `.venv`/`venv` directory is repository state, exactly
like a workspace-local `node_modules/.bin` binary already excluded by
`CandidateOutcome::WorkspaceLocal` in the resolver. A workspace `.venv`'s
interpreter or installed console-scripts (e.g. a project-pinned `pytest`
inside `.venv/bin/`) is classified `WORKSPACE_EXTERNAL` /
`PROJECT_CONTROLLED_EXECUTION`, never eligible to satisfy
`ProviderCategory::Runtime`/`Formatter`/`Linter`/`TypecheckBuild`
`ControlledExternalTool` authority -- it cannot silently become the
Corulix-trusted interpreter/formatter/linter/typechecker. A project-pinned
test runner living inside `.venv` may still be _invoked_ as the trusted
workspace's own test entry point under `TrustedWorkspaceExecution` (section
4), the same way a Go module's own `go.mod`-pinned toolchain is invoked as
workspace-trusted execution rather than as `ControlledExternalTool`
authority -- but this is the `TestRunner`/trusted-execution path, never the
`Runtime`/`ControlledExternalTool` path, and the two are never conflated.

```text
P17_VIRTUALENV_POLICY=WORKSPACE_EXTERNAL (never CONTROLLED_EXTERNAL_TOOL authority)
P17_WORKSPACE_VENV_EXECUTION_CLASS=TrustedWorkspaceExecution-only, gated exactly like any other repository-authored execution
```

## 7. Project/config discovery markers

Audited support surface for Phase 17 (discovery only -- these markers
inform runner/config decisions in sections 1 and 4, they are never
themselves executed as code):

```text
P17_SUPPORTED_PROJECT_MARKERS=[pyproject.toml, requirements.txt, setup.cfg, setup.py (name/presence only, never executed), tox.ini, pytest.ini, .python-version, .venv, venv]
P17_PROJECT_ROOT_DISCOVERY_POLICY=nearest ancestor directory (relative to the target file, bounded at the workspace root) containing pyproject.toml, else setup.cfg/setup.py, else the workspace root itself -- same nearest-ancestor-bounded-at-workspace-root model already used for Go's go.mod discovery
```

`setup.py`'s presence is a discovery marker only; per the mandate's §49
this ADR does not admit any PEP-517/518 build-backend execution
(`setuptools`/`poetry-core`/`hatchling` etc.) as part of Phase 17 policy.
No build backend is invoked by any Phase 17 provider.

## 8. Config precedence

```text
P17_CONFIG_PRECEDENCE=HOST_ONLY absolute-path/category-enablement overrides first and always win; REPOSITORY_HINT (pyproject.toml/pytest.ini/etc. discovery) may only narrow which already-admitted provider identity applies (e.g. "this project's tests run under pytest"), never introduce a new provider identity or raise trust/authority; REQUEST_SCOPED (MCP RequestOptions) carries no trust-elevation field at all, matching Go/Rust/TS-JS
```

## Consequence for this phase's exit gate

```text
P17_PROVIDER_ADR_STATUS=FINAL
P17_LSP_PROVIDER=pyright (unchanged from ADR 0009)
P17_FORMATTER_PROVIDER=ruff format
P17_LINTER_PROVIDER=ruff check
P17_TYPECHECKER_PROVIDER=pyright --outputjson (one-shot, distinct from the LSP session)
P17_TEST_RUNNER_PROVIDER=pytest (discovered, never assumed globally)
P17_PYTHON_RUNTIME_PROVIDER=python3 (resolved via wht_corulix_config::resolve_provider, ProviderCategory::Runtime)
P17_MCP_SURFACE_CHANGE=NONE (no new MCP tool; this ADR governs provider identity only, routed through the existing validate_change/format_preview/semantic tools)
```

Implementation (semantic routing confirmation, formatter wiring, linter/
typecheck/test-runner wiring into `validate_change`'s `ToolPlan`, security
matrix proofs, full and blocked governance E2Es, lifecycle/zero-residual
proof, and quality gates) is tracked separately and is **not** closed by
this document. This ADR satisfies the Phase 17 mandate's §3 hard gate
("ADR before code") only; `PHASE_17_STATUS` remains open until the
downstream implementation and verification sections of the mandate are
independently satisfied and reported.
