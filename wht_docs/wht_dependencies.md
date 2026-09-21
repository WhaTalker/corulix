# Dependency Admission

Corulix admits dependencies deliberately. Workspace manifests and `Cargo.lock` are the executable authority for the resolved Rust dependency graph; this document describes the current policy and notable direct baseline.

## Admission criteria

A dependency must satisfy all applicable criteria:

- authoritative upstream source or registry identity;
- license compatibility with the Corulix distribution model and `deny.toml`;
- clear necessity and owning crate;
- acceptable maintenance/security posture;
- no prohibited architecture edge;
- explicit version discipline with locked release resolution;
- review of target-specific native/FFI implications where applicable.

## Current direct baseline

| Package | Baseline | Role |
| --- | ---: | --- |
| `rmcp` | `3.0.1` | MCP Rust SDK |
| `tree-sitter` | `0.26.11` | structural parsing runtime |
| `tree-sitter-javascript` | `0.25.0` | JavaScript/JSX grammar |
| `tree-sitter-typescript` | `0.23.2` | TypeScript/TSX grammar |
| `tree-sitter-python` | `0.25.0` | Python grammar |
| `tree-sitter-rust` | `0.24.2` | Rust grammar |
| `tree-sitter-go` | `0.25.0` | Go grammar |
| `serde` / `serde_json` | workspace-controlled | serialization |
| `thiserror` | workspace-controlled | typed errors |
| `tokio` | workspace-controlled | async runtime/process/time/I/O/synchronization |
| `tracing` / `tracing-subscriber` | workspace-controlled | structured diagnostics |
| `clap` | `=4.6.6` | CLI command model |
| `jsonc-parser` | `=0.33.1` | `.code-workspace` JSONC parsing |
| `ignore` | `=0.4.33` | ignore-policy evaluation |
| `grep-matcher` | `=0.1.9` | embedded search matcher abstraction |
| `grep-regex` | `=0.1.14` | regex/literal matcher construction |
| `grep-searcher` | `=0.1.17` | line-oriented search engine |
| `rustix` | `=1.1.4` (Unix) | process-group control |
| `win32job` | `=2.0.3` (Windows) | Job Object process-tree containment |

Exact resolved transitive versions remain authoritative in `Cargo.lock`.

## Security-qualified TLS baseline

The qualified 1.0.0 dependency state uses `rustls 0.23.45`, which resolves the `RUSTSEC-2026-0285` condition identified during release qualification. Dependency upgrades must not silently replace the frozen 1.0.0 release identity.

## Ownership principles

- CLI parsing dependencies remain owned by the CLI layer.
- Workspace/JSONC dependencies remain owned by the workspace layer.
- Search-specific dependencies remain owned by the search layer.
- Tree-sitter runtime/grammars remain owned by the syntax layer.
- OS process-control dependencies remain owned by the tooling/platform layer.
- Protocol dependencies remain isolated from protocol-agnostic Core.

## Vendor policy

`vendor/` is **not part of the standard public 1.0.0 source publication**. It may exist locally as controlled dependency/build support, but public source consumers use the manifests and `Cargo.lock` unless a separate offline/vendored source artifact is explicitly published.

Do not interpret deletion/exclusion of a local vendor cache as removal of dependency metadata from the product.

## Review on change

Any dependency addition or version change requires re-running the applicable license, advisory, architecture, build and test gates before it can become part of a future release candidate.
