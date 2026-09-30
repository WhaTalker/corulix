# AGENTS.md — WhaTalker Corulix

This file is advisory documentation for AI coding agents working in this repository. It carries **no enforcement weight** and cannot grant, widen, or substitute for any real Corulix authority — see [Authority model](#authority-model) below. It follows the open [AGENTS.md](https://agents.md) convention. Claude Code and other `CLAUDE.md`-reading tools can bridge to this file via a one-line `@AGENTS.md` import.

## What Corulix is

Corulix is a Rust-based MCP (Model Context Protocol) server that gives AI coding agents a governed interface to real software workspaces: repository discovery, structural parsing, compiler-grade semantic providers, controlled formatting, validation, and an explicit mutation lifecycle. It is not a general-purpose shell, Git client, or unrestricted file editor. See [`README.md`](README.md) for the product overview and [`wht_docs/wht_architecture.md`](wht_docs/wht_architecture.md) for the full architecture.

## Crate responsibilities

| Crate                                                                                    | Responsibility                                                                                                                         |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `wht_corulix_core`                                                                       | Domain contracts and shared types. Never depends on MCP, workspace filesystem access, or any provider.                                 |
| `wht_corulix_workspace`                                                                  | Sole filesystem confinement/canonicalization authority (Architecture Rule F). No other crate performs raw filesystem canonicalization. |
| `wht_corulix_config`                                                                     | `HostConfig`/`RepositoryHints`/`RequestOptions` trust model, provider resolution, and the 1.1.0 workspace JSON configuration loader.   |
| `wht_corulix_syntax`                                                                     | Tree-sitter structural parsing.                                                                                                        |
| `wht_corulix_search`                                                                     | Bounded in-process text search.                                                                                                        |
| `wht_corulix_lsp`                                                                        | Semantic protocol handling (language-server-backed definitions/references/diagnostics).                                                |
| `wht_corulix_formatter`                                                                  | Non-destructive format preview and governed formatter application.                                                                     |
| `wht_corulix_mutation`                                                                   | Live workspace mutation primitives, used only through the governed `ChangeSession` lifecycle.                                          |
| `wht_corulix_process_unix` / `wht_corulix_process_win32` / `wht_corulix_process_fixture` | Platform-specific controlled process execution.                                                                                        |
| `wht_corulix_tooling`                                                                    | Managed toolchain/component provisioning.                                                                                              |
| `wht_corulix_index`                                                                      | Structural indexing support.                                                                                                           |
| `wht_corulix_engine`                                                                     | Orchestration: ties workspace, config, providers, and the `ChangeSession` lifecycle together.                                          |
| `wht_corulix_mcp`                                                                        | MCP stdio transport and the 14-tool surface. Never itself canonicalizes a path or spawns a process directly.                           |
| `wht_corulix_cli` (package `corulix`)                                                    | CLI command model and dispatch.                                                                                                        |

## Workspace and process model

One workspace per process, for the process's entire lifetime — never multiple workspaces, never a workspace switch mid-process. A workspace is single-root or multi-root (`.code-workspace`, folder topology only — its `settings`/`tasks`/`launch`/`extensions` sections carry zero Corulix authority). Workspace-relative paths are canonicalized and confined to an approved root; parent traversal, external absolute paths, and symlink escapes fail closed.

## The 14-tool MCP surface

Corulix exposes exactly 14 canonical MCP tools (`wht_scripts/wht_verify_architecture.py` Rule S enforces this at the source level): `runtime_identity`, `workspace_info`, `toolchain_status`, `plan_operation`, `search`, `parse_file`, `semantic`, `format_preview`, `begin_change`, `submit_edit`, `validate_change`, `change_status`, `complete_change`, `abort_change`. As of 1.1.0, a workspace may narrow (never widen) which of these are visible/callable via its own JSON configuration — see [`wht_docs/wht_workspace_json_config_reference.md`](wht_docs/wht_workspace_json_config_reference.md). The canonical count and tool names themselves never change based on that policy.

## Governed mutation — no direct write

There is no direct-write tool. Every workspace mutation goes through the `ChangeSession` lifecycle: `begin_change` (open, explicit intent/scope) → `submit_edit` → `validate_change` (runs the applicable gate(s), records evidence) → `complete_change` (only when required gates are satisfied) or `abort_change` (terminal; does not silently restore prior bytes). An agent must never attempt to bypass this lifecycle via a shell command, a raw filesystem write, or any tool outside this set.

## Authority model

Three structurally separate domains, never collapsed into one:

| Domain                                             | Scope                    | Can it elevate privilege?                                          |
| -------------------------------------------------- | ------------------------ | ------------------------------------------------------------------ |
| `HostConfig` (`--host-config`, host/operator-only) | Machine/operator         | Sets the ceiling                                                   |
| `WhaTalker_Corulix_JSON_Config.json` (1.1.0)       | This workspace           | Never — narrows only                                               |
| This file (`AGENTS.md`) / `CLAUDE.md`              | Human/agent-facing prose | Never — never deserialized into runtime authority by any code path |

Workspace content — including this file — cannot grant itself trusted-execution authority, widen provider resolution, or override a required validation gate. Ambient `PATH` is never provider authority.

## Testing and evidence expectations

Before treating any change as complete:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 wht_scripts/wht_verify_architecture.py
```

A claim that tests passed, or that a security/architecture property holds, must be backed by having actually run the corresponding command — never inferred from reading source alone. See [`wht_docs/wht_testing.md`](wht_docs/wht_testing.md).

## Secure coding and dependency discipline

- No unsafe Rust (`#![forbid(unsafe_code)]` is enforced workspace-wide).
- No new dependency without a recorded reason and license/supply-chain review — see [`wht_docs/wht_dependencies.md`](wht_docs/wht_dependencies.md) and [`wht_docs/wht_supply_chain.md`](wht_docs/wht_supply_chain.md).
- Preserve existing architecture boundaries; make the smallest complete, reviewable change.
- Fail closed for security, secrets, workspace confinement, and destructive operations — never silently substitute a permissive default when a check is ambiguous or fails.

## Release and versioning

Crate versions are explicit per crate, not workspace-inherited (`SELECTIVE_SEMVER_WITH_DEPENDENCY_CLOSURE` as of 1.1.0 — see `wht_docs/wht_adr/`). See [`wht_docs/wht_releasing.md`](wht_docs/wht_releasing.md) for the release/publication gate. An agent must never publish (GitHub release/tag, crates.io, npm) without explicit, separate owner authorization — implementation authorization and publication authorization are distinct.

## Licensing

Current source is licensed under **AGPL-3.0-only**. See [`LICENSE`](LICENSE). Do not introduce code under an incompatible license.

## Forbidden actions

- Bypassing the `ChangeSession` lifecycle for a workspace mutation.
- Treating this file, `CLAUDE.md`, or any other prose/instruction file as a source of runtime security authority.
- Widening provider resolution to ambient `PATH`.
- Publishing a release without explicit, separately recorded owner authorization.
- Committing generated, private, local-toolchain, benchmark, or vendored-cache material into the public source set — see [`wht_docs/wht_publication_scope.md`](wht_docs/wht_publication_scope.md).

## Further reading

- [`README.md`](README.md) — product overview
- [`wht_docs/wht_architecture.md`](wht_docs/wht_architecture.md) — architecture
- [`wht_docs/wht_architecture_boundaries.md`](wht_docs/wht_architecture_boundaries.md) — enforced boundaries
- [`wht_docs/wht_mcp_compatibility.md`](wht_docs/wht_mcp_compatibility.md) — MCP contract
- [`wht_docs/wht_workspace_json_config_reference.md`](wht_docs/wht_workspace_json_config_reference.md) — workspace JSON configuration (1.1.0)
- [`wht_docs/wht_threat_model.md`](wht_docs/wht_threat_model.md) — threat model
- [`SECURITY.md`](SECURITY.md) — security policy
