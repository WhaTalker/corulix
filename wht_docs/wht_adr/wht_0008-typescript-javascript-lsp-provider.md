# ADR 0008 — TypeScript/JavaScript LSP Provider

**Status:** Superseded by ADR 0010

## 1.0.0 reconciliation note

This ADR is retained as the historical TypeScript/JavaScript LSP-provider decision. ADR 0010 and the final 1.0.0 implementation supersede its host-availability assumptions and current provider-routing status. Current capability authority is `wht_docs/wht_language_support.md`.

## Decision

`typescript-language-server` is Corulix's admitted `LanguageServer` provider
for TypeScript and JavaScript (`wht_corulix_lsp::profile::LspProviderProfile::
typescript_language_server`/`typescript_language_server_for_javascript`).

## Candidates evaluated

| Criterion                                  | `typescript-language-server`                                     | `vtsls`                                                                                                     |
| ------------------------------------------ | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Maintenance                                | Actively maintained, current release 5.3.0 observed on this host | Wraps the VS Code TypeScript extension                                                                      |
| License                                    | Apache-2.0                                                       | MIT                                                                                                         |
| Explicit `tsserver.path` override          | Yes (`initializationOptions.tsserver.path`)                      | Yes (`typescript.tsdk`), but documents `autoUseWorkspaceTsdk`                                               |
| Explicit plugin disable                    | Yes (`initializationOptions.plugins`)                            | Yes (`typescript.tsserver.pluginPaths`/`globalPlugins`), less centrally documented                          |
| Explicit typing-acquisition disable        | Yes (`preferences.disableAutomaticTypingAcquisition`)            | Automatic Type Acquisition is a tsserver-level setting; same mechanism, less explicit in `vtsls`'s own docs |
| Reliability posture (upstream's own words) | No caveat found in current README                                | Upstream README describes reliability as best-effort                                                        |
| Bundled TypeScript                         | None bundled; requires host-provided `tsserver.path`             | Bundles a TypeScript version by default                                                                     |
| Operational complexity                     | Single well-documented LSP wrapper                               | Wraps VS Code extension internals not designed as a standalone server                                       |

`typescript-language-server` was selected on maintenance activity, license,
and the absence of a documented reliability caveat, and because its smaller,
single-purpose wrapper surface is easier to audit than `vtsls`'s VS
Code-extension-internals wrapper. `vtsls` was rejected primarily for its own
upstream-documented best-effort reliability posture, which does not meet the
bar for an enterprise semantic-authority provider; it was not evaluated
further empirically because it is not installed on this host and installing
it would violate `AUTO_INSTALL_LSP_PROVIDER=NO`.

## Security proof (`UNTRUSTED_TS_JS_*`)

A real hostile-workspace test was run against a real `typescript-language-server`
process (Node v22.22.0, `typescript-language-server` 5.3.0) with:

- `node_modules/typescript/lib/tsserver.js` — a workspace-planted fake
  TypeScript that writes a marker file if ever loaded/executed.
- `node_modules/evil-plugin/` — a `tsconfig.json`-declared
  `compilerOptions.plugins` entry that writes a marker file if ever loaded.

Corulix's canonical `initializationOptions` (`plugins: []`,
`preferences.disableAutomaticTypingAcquisition: true`, an explicit
`tsserver.path` pointed at a real, host-approved-for-the-probe TypeScript
5.9.3 install) was sent. Result: `initialize` succeeded, `textDocument/
definition` returned a correct real result, and **neither marker file was
ever created** — the workspace-planted `tsserver.js` was never loaded and
the `tsconfig.json`-declared plugin was never loaded. This proves
Corulix's canonical profile does not fall back to workspace-local
TypeScript or workspace-declared plugins even when a hostile workspace
tries to force it to.

```text
UNTRUSTED_TS_JS_LOCAL_TYPESCRIPT_LOADING=NO
UNTRUSTED_TS_JS_PLUGIN_LOADING=NO
UNTRUSTED_TS_JS_AUTOMATIC_TYPE_ACQUISITION=NO
```

## `TS_JS_TSSERVER_SOURCE` — the real environment gap

`typescript-language-server` bundles no TypeScript of its own and requires
an explicit `tsserver.path` pointing at a classic, `tsserver.js`-capable
TypeScript install. This development host's only installed TypeScript
(resolved via `nvm`, version `7.0.2`) is the current native/Go-ported
compiler rewrite ("tsgo"), which ships `tsc.js` but **no `tsserver.js` at
all** — confirmed empirically: `initialize` against this host's installed
TypeScript fails outright with `"Could not find a valid TypeScript
installation... valid tsserver.path is specified."`.

The security proof above used a compatible TypeScript 5.9.3 found bundled
inside an unrelated IDE's private extension directory
(`/opt/antigravity-ide/resources/app/extensions/node_modules/typescript/`).
This was legitimate for a one-time research probe answering "can the
security configuration work at all", but it is **not** a legitimate
`HOST_ONLY`-approved production `tsserver.path`: it is another
application's incidental, private bundled resource, not an intentional
host/operator toolchain decision, and Corulix's provider-resolution model
(`wht_corulix_config::resolve_provider`) never reaches into another
application's private directories. `LspProviderProfile::
typescript_language_server()` therefore deliberately leaves `tsserver.path`
unset; Core has no host-configuration surface for it yet.

```text
TS_JS_LSP_BINARY_SOURCE=resolve_provider(LanguageServer, "typescript-language-server") via approved system/user-toolchain directory
TS_JS_TSSERVER_SOURCE=UNRESOLVED_ON_THIS_HOST (no host-approved classic-TypeScript install exists; the installed TypeScript is the native/Go-ported rewrite with no tsserver.js)
```

## Consequence for this phase's exit gate

```text
TS_JS_ADR_STATUS=CLOSED
TS_JS_LSP_PROVIDER=typescript-language-server
TS_JS_PROVIDER_ALTERNATIVE_REJECTED=vtsls
TS_JS_PROVIDER_REJECTION_REASON_FOR_ALTERNATIVE=upstream-documented best-effort reliability posture; not installed on this host, so auto-install would have been required to evaluate further
TYPESCRIPT_LSP_E2E=BLOCKED_PROVIDER_UNAVAILABLE
JAVASCRIPT_LSP_E2E=BLOCKED_PROVIDER_UNAVAILABLE
```

The ADR closes accepted because the security model is proven satisfiable;
the E2E is honestly blocked because this specific host has no legitimate
host-approved TypeScript runtime to point the provider at, and
`AUTO_INSTALL_LSP_PROVIDER=NO` forbids installing one. A future phase (or
this same phase on a differently-provisioned host) can close this the
moment a host administrator provides an approved, classic-TypeScript
directory via `HostConfig`.

## Version discovery

```text
TS_JS_VERSION_DISCOVERY_MODEL=$/typescriptVersion notification (sent unsolicited by typescript-language-server after initialize; empirically observed) for the tsserver runtime version, plus package.json adjacent to the canonical resolved script (wht_corulix_config::canonicalize_external_path's resolved parent directory) for the typescript-language-server package's own version -- never an ambient `--version` invocation, since that would be a second, unaudited process execution outside `wht_corulix_tooling`'s controlled contract.
```

## Network behavior

```text
TS_JS_NETWORK_BEHAVIOR=Automatic Typing Acquisition (which can reach the network to download @types packages) is unconditionally disabled via `preferences.disableAutomaticTypingAcquisition=true`. No other Corulix-triggered network access is configured. NETWORK_ISOLATION_CLAIMED=NO -- this is a configuration guard, not an OS-level network deny.
```
