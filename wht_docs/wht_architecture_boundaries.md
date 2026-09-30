# Architecture Boundaries

This document summarizes the **current Corulix 1.1.0 boundary invariants** (unchanged from 1.0.0 except where this document notes a 1.1.0 addition). Historical phase-by-phase implementation notes are intentionally omitted from the current-facing contract. The exact static checks are enforced by `wht_scripts/wht_verify_architecture.py` and repository validation.

## 1. Protocol-independent Core

`wht_corulix_core` owns shared domain contracts. It must not become an MCP transport crate, Tree-sitter wrapper, filesystem traversal layer, or process launcher.

## 2. MCP is an adapter

`wht_corulix_mcp` owns MCP request/response mapping and transport-facing schemas. It delegates product behavior to engine/core services and must not bypass them to perform parsing, provider execution, or filesystem mutation directly.

## 3. Workspace authority is centralized

`wht_corulix_workspace` owns canonicalization, confinement, root selection, multi-root descriptor resolution, and workspace membership checks.

Security rule: **object authority takes precedence over pathname authority**. A path string alone is not proof that an operation is safely bound to the intended workspace object.

## 4. Search is textual authority only

`wht_corulix_search` owns bounded text search. It does not claim compiler-grade semantic authority and does not implement an independent filesystem escape policy.

## 5. Syntax is structural authority only

`wht_corulix_syntax` is the sole Tree-sitter structural/syntax owner. Structural results do not claim compiler-grade definitions, references, rename correctness, type inference, or diagnostics.

## 6. LSP is semantic authority

`wht_corulix_lsp` owns LSP/JSON-RPC framing, sessions and semantic operations. It launches providers only through the controlled process layer and does not become formatter or mutation authority merely because an LSP server advertises those capabilities.

## 7. Provider and trust authority is centralized

`wht_corulix_config` owns host-only workspace trust/configuration and provider resolution.

Required invariants:

- workspace/repository data cannot elevate itself to `HOST_ONLY` authority;
- request-scoped data cannot elevate trust;
- ambient `PATH` is not provider authority;
- explicitly configured invalid provider paths fail closed rather than silently falling through;
- workspace-local executables cannot masquerade as controlled external providers.

## 8. External processes are centralized

`wht_corulix_tooling` owns external process construction and lifecycle. Other product crates do not create ad-hoc shell/process execution paths.

The controlled process contract requires, as applicable:

- typed argv rather than shell command strings;
- explicit environment handling;
- explicit working directory;
- timeout and cancellation behavior;
- bounded stdout/stderr handling;
- process-tree containment and reap behavior;
- platform-specific fail-closed semantics.

## 9. Managed components stay outside workspaces

Managed runtimes/providers are activated under Corulix-owned application data, never inside the inspected workspace. Component identity, integrity, ownership, dependencies, active execution leases, uninstall and residual cleanup are governed by the tooling layer.

Local managed state is not public source.

## 10. Mutation has one live-write authority

`wht_corulix_mutation` owns canonical live-workspace mutation transactions. Provider crates and formatter/LSP/tooling integrations must not create alternate workspace-write paths.

## 11. Formatting does not bypass mutation governance

`wht_corulix_formatter` may invoke admitted formatters and stage/return formatted bytes, but live source application is governed through the mutation/session architecture.

## 12. Engine owns policy, planning and gates

`wht_corulix_engine` owns operation intent, policy/routing, provider applicability, gate/evidence state, language-specific validation and `ChangeSession` orchestration.

Transport/provider crates do not redefine policy independently.

## 13. Async-first product surface

Public operational entry points that perform I/O/process work are async-first. Internal blocking work may exist only behind controlled implementation boundaries; public synchronous escape hatches must not be introduced casually.

## 14. Fail closed on missing authority

When a required provider, safe workspace binding, validation authority, trust grant, or platform primitive is unavailable, Corulix reports an explicit unavailable/denied state. It does not silently downgrade to a weaker security model.

## 15. Windows object/process authority

On Windows, supported functionality may be stricter than on Unix when equivalent safe object authority cannot be established. Workspace-bound execution fails closed rather than substituting a pathname-only approximation.

## 16. Language provider boundaries

Each language has independent authorities for structure, semantics, formatting, validation/lint and tests. A “supported language” claim must describe which of those authorities are available; one provider does not imply all of them.

Current detailed matrix: `wht_language_support.md`.

## 17. Public MCP surface is frozen since 1.0.0, unchanged in 1.1.0

The public MCP surface has contained exactly 14 tools since 1.0.0, unchanged in 1.1.0:

```text
abort_change
begin_change
change_status
complete_change
format_preview
parse_file
plan_operation
runtime_identity
search
semantic
submit_edit
toolchain_status
validate_change
workspace_info
```

Schema/name changes require a future versioned product decision; documentation changes must not silently change this contract.

## 18. Publication boundary

The public source package is defined by `PACKAGE_MANIFEST.txt`. Generated/private/local-state directories such as `.corulix-rust/`, `release/`, `vendor/`, and `target/` are excluded from the standard public 1.1.0 source set.

See `wht_publication_scope.md`.
