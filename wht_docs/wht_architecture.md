# Architecture

This document describes the **current Corulix 1.1.0 architecture** (unchanged from 1.0.0 except for the additive workspace-configuration/tool-policy layer noted where relevant). Historical implementation phases and temporary qualification states are intentionally not used as current architecture authority.

## Architectural model

Corulix separates protocol transport, policy/orchestration, workspace authority, textual search, structural syntax, semantic providers, external process execution, governed mutation, formatter integration, configuration/trust, and operator CLI concerns.

```text
AI/MCP client
    │
    │ stdio
    ▼
wht_corulix_mcp
    │
    ▼
wht_corulix_engine
    ├── wht_corulix_core
    ├── wht_corulix_workspace
    ├── wht_corulix_search
    ├── wht_corulix_syntax
    ├── wht_corulix_index
    ├── wht_corulix_config
    ├── wht_corulix_lsp
    ├── wht_corulix_formatter
    ├── wht_corulix_mutation
    └── wht_corulix_tooling

corulix CLI ──► engine / MCP / setup & inspection flows
```

The exact Cargo dependency graph is authoritative in the workspace manifests. The diagram above expresses ownership, not every compile-time edge.

## Canonical crate roles

| Crate | Responsibility |
| --- | --- |
| `wht_corulix_core` | Protocol-agnostic domain contracts, errors, evidence, operation/gate/session vocabulary |
| `wht_corulix_workspace` | Filesystem/workspace identity, canonicalization, confinement, traversal, multi-root descriptor handling |
| `wht_corulix_search` | Bounded textual search over confined workspace content |
| `wht_corulix_syntax` | Tree-sitter structural parsing and structural symbol/scope extraction |
| `wht_corulix_index` | Structural snapshot/index contracts |
| `wht_corulix_config` | Host-only trust/configuration merge and provider-resolution authority |
| `wht_corulix_lsp` | LSP/JSON-RPC transport and compiler-grade semantic operations |
| `wht_corulix_tooling` | Controlled external-process construction, managed process lifecycle, component provisioning/ownership/uninstall |
| `wht_corulix_process_win32` | Windows-specific process support used by the controlled runtime boundary |
| `wht_corulix_mutation` | Canonical live-workspace mutation transaction and atomic edit authority |
| `wht_corulix_formatter` | Formatter resolution/invocation and staging-oriented formatting integration |
| `wht_corulix_engine` | Application policy, planning, routing, provider orchestration, gates, evidence and `ChangeSession` behavior |
| `wht_corulix_mcp` | MCP presentation/transport adapter |
| `wht_corulix_cli` | Human/operator command-line entry point (`corulix`) |
| `wht_corulix_process_fixture` | Non-publishable process test fixture used by permanent regression tests |

## Authority boundaries

### Core

`wht_corulix_core` owns shared domain vocabulary. It does not own MCP transport, Tree-sitter runtime objects, filesystem traversal, or process spawning.

### Workspace

`wht_corulix_workspace` is the filesystem/workspace authority. Workspace-relative inputs are resolved through canonicalized confinement rather than pathname trust. Other crates consume confined results instead of reimplementing workspace escape logic.

### Search

`wht_corulix_search` is textual intelligence only. It does not claim compiler-grade definition/reference authority and it operates through the workspace boundary.

### Syntax

`wht_corulix_syntax` is structural intelligence only. Tree-sitter objects are converted into Corulix-owned models before crossing the crate boundary.

### Semantic providers

`wht_corulix_lsp` owns LSP framing/session behavior and semantic operations such as definitions, references, diagnostics and rename preview. Language-server processes are launched through the controlled tooling layer rather than directly.

### Configuration and provider resolution

`wht_corulix_config` owns host-only trust and provider resolution. Repository and request data may narrow behavior but cannot elevate workspace trust or grant new executable authority. Ambient `PATH` is not provider authority.

### External processes

`wht_corulix_tooling` is the controlled process/runtime boundary. External commands use typed argv, explicit environment policy, explicit working directory, timeout/cancellation handling, bounded output capture, and platform-specific process-tree containment.

The tooling layer does not make a general OS-sandbox claim. Network/filesystem isolation beyond the controls explicitly documented by a provider is not implied.

### Mutation

`wht_corulix_mutation` owns live workspace writes. Mutation is performed through governed transactions rather than arbitrary tool-side file writes.

### Formatting

`wht_corulix_formatter` resolves admitted formatter providers and produces/stages formatted bytes under the governed architecture. Public non-mutating formatting is exposed through `format_preview`; mutation is governed through the change-session path.

### Engine

`wht_corulix_engine` is the application policy and orchestration authority. It binds operation intent to tools/providers/gates, records evidence, routes supported languages, and drives the `ChangeSession` lifecycle.

### MCP

`wht_corulix_mcp` is a transport/presentation adapter. It exposes exactly 14 public tools (unchanged since 1.0.0, including in 1.1.0) and delegates product behavior to the engine/core layers.

## Change lifecycle

The governed mutation model is explicit:

```text
begin_change
    ↓
submit_edit / governed formatting as applicable
    ↓
validate_change
    ↓
change_status (inspection at any point)
    ↓
complete_change   OR   abort_change
```

A session may complete only when its required gates have current passing evidence. Abort is terminal and does not silently rewrite the workspace back to older bytes.

## Structural, semantic and execution authority are separate

Corulix intentionally does not collapse “language support” into one provider:

```text
Text search      -> wht_corulix_search
Structure        -> wht_corulix_syntax / Tree-sitter
Semantics        -> wht_corulix_lsp / language server
Formatting       -> wht_corulix_formatter
Build/type/lint  -> language-aware engine validation through controlled tooling
Tests            -> language-aware governed test execution
```

This prevents a structural parser from being presented as a compiler and prevents a language server from silently becoming mutation or formatter authority.

## Managed component model

Selected runtimes/providers are provisioned into Corulix-owned application data using pinned identities and cryptographic hashes. Provisioning, ownership, execution leases, and uninstall are managed product concerns; local managed state is not part of the public source publication set.

`.corulix-rust/`, `vendor/`, `target/`, and private `release/` material are therefore not architectural source components of the standard public source package. See `wht_publication_scope.md`.

## Async runtime and cancellation

Corulix uses one async-first runtime model for I/O and external-process orchestration. CPU/blocking work is isolated behind bounded blocking boundaries where required. Cancellation is represented by Corulix-owned core state and propagates through controlled process execution where supported.

## Windows security semantics

Windows x86_64 is a supported, natively-certified release platform since 1.0.0 (Corulix 1.1.0 additionally completed a full native Windows re-certification). For workspace-bound execution, Corulix uses the strongest safe authority available to the platform implementation and **fails closed** where a safe object/process-root binding cannot be established. A pathname-only fallback is not treated as an equivalent security authority.

This stricter behavior is intentional security policy, not an implementation error.

## Publication architecture

The source publication is defined by `PACKAGE_MANIFEST.txt`. Build output, local toolchain state, vendored cache material, private release tooling, Brain/governance storage, and temporary benchmark/qualification workspaces are outside the standard public source set.

## Machine-enforced boundaries

`wht_scripts/wht_verify_architecture.py` is the machine-readable enforcement authority for project-specific architecture rules. `wht_scripts/wht_verify_repository.py` validates repository/package invariants. Public documentation describes the rules; the validators enforce the exact current checks.
