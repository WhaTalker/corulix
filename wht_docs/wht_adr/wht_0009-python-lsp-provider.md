# ADR 0009 — Python LSP Provider

**Status:** Accepted

## 1.0.0 reconciliation note

The Pyright semantic-provider decision remains current. References below to a “future Phase 17” formatter/linter/typecheck/test authority are historical point-in-time wording: ADR 0011 and the final 1.0.0 implementation subsequently completed that Python provider vertical. Current capability authority is `wht_docs/wht_language_support.md`.

## Decision

Pyright (`pyright-langserver`) is Corulix's admitted `LanguageServer`
provider for Python (`wht_corulix_lsp::profile::LspProviderProfile::pyright`).

## Candidates evaluated

| Criterion                        | Pyright                                                                                                                                                                              | `python-lsp-server`                                                                                                                                                           |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Maintenance                      | Actively maintained, current release 1.1.413 observed on this host                                                                                                                   | Actively maintained                                                                                                                                                           |
| License                          | MIT                                                                                                                                                                                  | MIT                                                                                                                                                                           |
| Plugin architecture              | None -- Pyright has no plugin-loading mechanism at all                                                                                                                               | Plugin-based; loads built-in, optional, and third-party entry-point plugins by design                                                                                         |
| Formatter/linter overlap         | None -- Pyright is a type checker/analyzer only                                                                                                                                      | Significant -- bundles/loads formatter and linter plugins (autopep8, yapf, pyflakes, pycodestyle, etc.), which would overlap a future, separately governed Phase 17 authority |
| Interpreter/venv handling        | Configurable via `venvPath`/`pythonPath`, but these are editor-supplied _client settings_, not project-config-file settings Pyright will honor from a workspace `pyrightconfig.json` | Uses whatever interpreter it is launched with/configured to use; more execution surface by design                                                                             |
| Workspace code-execution surface | None observed for baseline LSP capabilities (static analysis only)                                                                                                                   | Larger, by virtue of its plugin architecture                                                                                                                                  |
| Automatic install/download       | None observed                                                                                                                                                                        | None observed                                                                                                                                                                 |
| Operational complexity           | Single-purpose language server                                                                                                                                                       | Larger surface due to plugin ecosystem                                                                                                                                        |

Pyright was selected because its complete absence of a plugin-loading
architecture makes `UNTRUSTED_PYTHON_PLUGIN_LOADING=NO` a structural
property rather than a configuration Corulix must maintain and re-verify
against every `python-lsp-server` release. `python-lsp-server` was rejected
primarily for this reason: its plugin model's formatter/linter capabilities
would duplicate authority this project's own governance model reserves for
a future, separately governed Phase 17 vertical (LSP = semantic authority
only; formatter/linter are separate, later-governed authorities per Section
19 of the Phase 7B mandate), and its larger workspace-code-execution surface
is a less defensible default for `UNTRUSTED` workspaces. `python-lsp-server`
is not installed on this host; it was not evaluated further empirically
because doing so would require installation, which
`AUTO_INSTALL_LSP_PROVIDER=NO` forbids.

## Security proof (`UNTRUSTED_PYTHON_*`)

Two real probes were run against a real `pyright-langserver` process (Node
v22.22.0, Pyright 1.1.413):

1. **Baseline (no interpreter configured):** with a completely sanitized
   environment (no `HOME`, `PATH` scoped to Node's own directory only, no
   Python interpreter resolvable at all), Pyright logged `"Unable to get
Python version from interpreter"` as a non-fatal warning and still
   correctly served `initialize`, `publishDiagnostics` (unsolicited, proving
   the readiness signal below), and `textDocument/definition` (a correct,
   real result) purely from static analysis. No process other than
   `pyright-langserver` itself was ever spawned.
2. **Hostile workspace:** a `pyrightconfig.json` declaring `pythonPath`
   pointing at a shell script that writes a marker file if ever executed,
   plus a fake `venvPath`/`venv`. Result: Pyright logged `"Config contains
unrecognized setting \"pythonPath\""` (this key is a client/editor
   setting, not a project-config-file setting Pyright honors from a
   workspace file) and the marker file was **never created** -- the hostile
   interpreter was never executed.

```text
UNTRUSTED_PYTHON_WORKSPACE_CODE_EXECUTION=NO
UNTRUSTED_PYTHON_PLUGIN_LOADING=NO
PYTHON_AUTO_INSTALL=NO
```

## Readiness

`publishDiagnostics` arrives unsolicited immediately after `textDocument/
didOpen` in both probes above (no vendor-specific readiness notification
exists for Pyright, mirroring gopls). `ReadinessStrategy::
FirstDiagnosticsPublished` (already admitted for gopls) applies unchanged;
no new `ReadinessStrategy` variant was needed for Python.

```text
PYTHON_READINESS_MODEL=FirstDiagnosticsPublished (reused from gopls; empirically re-confirmed against a real pyright process)
PYTHON_READINESS_PROVEN=YES
```

## Version discovery

Pyright's `pyright-langserver --stdio` process does not respond to a bare
`--version` invocation compatible with the controlled-process contract, and
this crate's `wht_corulix_tooling::ManagedProcess` never invokes a second,
ad hoc process to probe it. Pyright logs its own version unsolicited at
startup (`"Pyright language server 1.1.413 starting"`, observed in both
probes above) -- that log line, plus `package.json` adjacent to the
canonically resolved script (`wht_corulix_config::canonicalize_external_path`'s
resolved parent directory), are the two verified mechanisms.

```text
PYTHON_VERSION_DISCOVERY_MODEL=startup `window/logMessage` ("Pyright language server <version> starting", empirically observed) plus package.json adjacent to the canonical resolved script -- never an ambient `--version` invocation
```

## `TYPESCRIPT_LSP_E2E`-class environment gap: not applicable here

Unlike `typescript-language-server`, Pyright requires no companion runtime
comparable to `tsserver.js` for its baseline LSP capabilities
(definition/references/document-symbol/diagnostics all resolved correctly
from pure static analysis with no Python interpreter resolved at all in
the probes above). `PYTHON_LSP_E2E` is therefore achievable on this host.

## Node launcher

Pyright's canonical script (`lib/node_modules/pyright/langserver.index.js`)
carries its own `#!/usr/bin/env node` shebang and is never executed
directly for the same reason `typescript-language-server`'s is not (see
`wht_0008-typescript-javascript-lsp-provider.md`): the shebang line is
never read, and Node is resolved as an explicit
`AuxiliaryToolRequirement` and invoked directly as the process executable
with the script path as `argv[1]`.

## Network behavior

```text
PYTHON_NETWORK_BEHAVIOR=No Corulix-triggered network access configured; Pyright's own optional stub-package auto-download behavior was not exercised or enabled by any Corulix-supplied configuration in either probe. NETWORK_ISOLATION_CLAIMED=NO -- this is a configuration/non-invocation guard, not an OS-level network deny.
```

## Consequence for this phase's exit gate

```text
PYTHON_ADR_STATUS=CLOSED
PYTHON_LSP_PROVIDER=pyright
PYTHON_PROVIDER_ALTERNATIVE_REJECTED=python-lsp-server
PYTHON_PROVIDER_REJECTION_REASON_FOR_ALTERNATIVE=plugin architecture overlaps future Phase 17 formatter/linter authority and enlarges the untrusted-workspace code-execution surface by design; not installed on this host, so auto-install would have been required to evaluate further
PYTHON_LSP_E2E=PASS (real gopls-pattern E2E, see tests/real_pyright_e2e.rs)
```
