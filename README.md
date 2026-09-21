# WhaTalker Corulix™

**Enterprise code intelligence and governed code mutation for AI coding agents over Model Context Protocol (MCP).**

Built by **[WhaTalker Inc.](https://whatalker.com)**. Product website: **[corulix.com](https://corulix.com)**.

[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](./LICENSE)
[![Rust 1.97.1](https://img.shields.io/badge/rust-1.97.1-orange.svg)](./rust-toolchain.toml)
[![Version 1.0.0](https://img.shields.io/badge/version-1.0.0-informational.svg)](./VERSION)

```text
Product:           WhaTalker Corulix
Brand:             Corulix™
CLI:               corulix
Version:           1.0.0
License:           AGPL-3.0-only
MCP transport:     stdio
Public MCP tools:  14
Supported source:  Rust, Go, TypeScript/TSX, JavaScript/JSX, Python
```

## What Corulix is

Corulix is a Rust-based MCP server that gives AI coding agents a governed interface to real software workspaces. It combines repository discovery, structural parsing, compiler-grade semantic providers, controlled formatting, validation, and an explicit mutation lifecycle while keeping filesystem, process, provider, and workspace-trust boundaries fail closed.

Corulix is not a general-purpose shell, Git client, or unrestricted file editor. Workspace changes are made only through the declared change-session workflow and are subject to the product's validation and authority model.

## Core capabilities

| Capability              | Current 1.0.0 behavior                                                                                         |
| ----------------------- | -------------------------------------------------------------------------------------------------------------- |
| Workspace discovery     | Single-root and VS Code multi-root workspace discovery with bounded, canonicalized resolution                  |
| Text search             | Bounded in-process search constrained to the active workspace                                                  |
| Structural intelligence | Tree-sitter parsing, symbols, scopes and structural analysis                                                   |
| Semantic intelligence   | Language-server-backed definitions, references, diagnostics and rename preview                                 |
| Governed mutation       | Explicit `ChangeSession` lifecycle with scoped edits, validation evidence and terminal completion/abort states |
| Formatting              | Non-destructive format preview plus governed formatter application inside change sessions                      |
| Validation              | Language-aware type/build, lint and test authorities where applicable                                          |
| Provider control        | Managed and operator-approved providers; ambient `PATH` is not provider authority                              |
| Managed toolchains      | Pinned/checksummed component provisioning with lifecycle ownership and uninstall handling                      |
| Workspace security      | Canonicalized confinement, trust separation and fail-closed execution policy                                   |
| Cross-platform runtime  | Linux and native Windows release support for 1.0.0                                                             |

## Supported languages

| Language         | Structural parsing     | Semantic provider                                                | Formatter     | Validation / lint                                                  | Tests                                       |
| ---------------- | ---------------------- | ---------------------------------------------------------------- | ------------- | ------------------------------------------------------------------ | ------------------------------------------- |
| Rust             | Tree-sitter Rust       | rust-analyzer                                                    | `rustfmt`     | `cargo check` and governed Rust diagnostics                        | `cargo test`                                |
| Go               | Tree-sitter Go         | `gopls`                                                          | `gofmt`       | `go build` + `go vet`                                              | `go test`                                   |
| TypeScript / TSX | Tree-sitter TypeScript | native TypeScript 7 LSP, with managed TypeScript 6 compatibility | Biome         | `tsc --noEmit` + Biome lint where applicable                       | Deterministic project test-runner discovery |
| JavaScript / JSX | Tree-sitter JavaScript | TypeScript language-service backends                             | Biome         | LSP + Biome; `tsc --noEmit` when the project opts into JS checking | Deterministic project test-runner discovery |
| Python           | Tree-sitter Python     | Pyright                                                          | `ruff format` | `pyright --outputjson` + `ruff check`                              | `pytest` when deterministically discovered  |

See [`wht_docs/wht_language_support.md`](wht_docs/wht_language_support.md) for the detailed capability and trust model.

## MCP

Corulix 1.0.0 exposes exactly **14 public MCP tools** over stdio:

| Tool               | Purpose                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------- |
| `runtime_identity` | Return runtime/product identity                                                             |
| `workspace_info`   | Return active workspace identity and topology information                                   |
| `toolchain_status` | Report real provider/toolchain availability                                                 |
| `plan_operation`   | Produce the governed tool plan for an operation intent                                      |
| `search`           | Run bounded workspace text search                                                           |
| `parse_file`       | Parse one confined workspace-relative source file                                           |
| `semantic`         | Definitions, references, diagnostics and rename preview through admitted semantic providers |
| `format_preview`   | Preview formatter output without directly mutating the live file                            |
| `begin_change`     | Open a governed `ChangeSession` with explicit intent and scope                              |
| `submit_edit`      | Submit a governed edit to an open change session                                            |
| `validate_change`  | Run the applicable validation gate(s) and record evidence                                   |
| `change_status`    | Return an audit-safe session state snapshot                                                 |
| `complete_change`  | Complete a session only when its required gates are satisfied                               |
| `abort_change`     | Permanently abort a session; abort is terminal and does not silently restore prior bytes    |

Canonical stdio invocation:

```sh
corulix mcp stdio --workspace <DIRECTORY>
```

For a VS Code multi-root workspace:

```sh
corulix mcp stdio --workspace-file <FILE.code-workspace>
```

See [`wht_docs/wht_mcp_compatibility.md`](wht_docs/wht_mcp_compatibility.md).

## AI clients validated with Corulix

Corulix is a standard MCP stdio server, so any MCP-capable AI client can in
principle connect to it. This section states, honestly, and to the exact
scope actually exercised, which AI clients have completed part of Corulix's
own validation process — not which clients are merely expected to work.

**AI clients with completed Corulix validation evidence:**

| AI client                | Status                                 | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------ | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Claude** (Claude Code) | MCP connection and discovery validated | Real MCP stdio connection, full discovery of all 14 public tools, and one verified safe tool invocation (`runtime_identity`) under a governed host configuration — see [`wht_docs/wht_host_profiles/wht_claude_code.toml`](wht_docs/wht_host_profiles/wht_claude_code.toml). This does not constitute end-to-end functional validation of every tool; it is the connection/discovery/safe-invocation evidence actually on record. |

Other MCP-capable AI clients — including Codex CLI, OpenCode, and VS Code
with built-in GitHub Copilot Chat — may be compatible with Corulix but have
not yet completed even this scope of Corulix's validation process. Absence
from the table above does not mean incompatibility; it means this evidence
has not yet been produced for that client.

Do not confuse this with **Host Enforcement Certification**, a separate,
narrower security property covering whether a host's own sandbox/permission
system can be made to prevent bypassing Corulix's governance entirely. Four
hosts (Claude Code, Codex CLI, OpenCode, and VS Code + built-in GitHub
Copilot Chat) currently hold that certification — see
[`wht_docs/wht_host_enforcement.md`](wht_docs/wht_host_enforcement.md) — but
holding it does not by itself establish the connection/discovery/
safe-invocation evidence this section documents. Claude Code currently
holds both; the other three currently hold only Host Enforcement
Certification.

## Workspace trust and security

Workspaces start untrusted. Workspace validity and workspace trust are separate concepts: a path can be a valid workspace while still being unauthorized for operations that execute repository-authored build or test code.

Key properties:

- workspace-relative paths are canonicalized and confined to an approved root;
- parent traversal, external absolute paths and symlink escapes fail closed;
- repository content cannot grant itself trusted-execution authority;
- provider resolution does not treat ambient `PATH` as authority;
- managed or host-approved provider paths are independently resolved and classified;
- stdio stdout is reserved for MCP protocol messages; operational diagnostics go to stderr;
- Windows operations fail closed when the required safe workspace/process authority cannot be established.

### Host configuration

Operator-controlled configuration may be supplied at process start:

```sh
corulix mcp stdio --workspace <DIRECTORY> --host-config <ABSOLUTE_FILE>
```

Example:

```toml
workspace_trust = "TRUSTED"
allow_trusted_workspace_execution = true
approved_system_directories = ["/opt/toolchain/bin"]

[[provider_absolute_paths]]
category = "FORMATTER"
path = "/opt/toolchain/bin/rustfmt"
```

A workspace, MCP request, or repository-local configuration cannot elevate itself into this host-only authority.

See [`SECURITY.md`](SECURITY.md), [`wht_docs/wht_threat_model.md`](wht_docs/wht_threat_model.md), and [`wht_docs/wht_architecture.md`](wht_docs/wht_architecture.md).

## Managed toolchains

Corulix can provision selected language-service/runtime/tooling components into Corulix-owned application data rather than relying on workspace-local executables. Provisioned artifacts are pinned and checksum-verified before activation.

Install profiles:

| Profile     | Behavior                                                          |
| ----------- | ----------------------------------------------------------------- |
| `full`      | Provision all applicable managed components proactively           |
| `selective` | Provision only selected component groups                          |
| `on-demand` | Provision a component only when an operation actually requires it |

Examples:

```sh
corulix setup
corulix setup --profile on-demand
corulix setup --only rust,python
corulix setup --exclude go
```

The local managed-toolchain state is runtime data, not public source. In particular, `.corulix-rust/` is excluded from the 1.0.0 publication set. See [`wht_docs/wht_publication_scope.md`](wht_docs/wht_publication_scope.md).

## Platform support

The 1.0.0 release surface is qualified for Linux and native Windows.

| Platform       | 1.0.0 distribution status                                                          |
| -------------- | ---------------------------------------------------------------------------------- |
| Linux x86_64   | Supported (native build, full test suite)                                          |
| Linux ARM64    | Supported (cross-compiled build; native ARM64 runtime execution not yet performed) |
| Windows x86_64 | Supported (native MSVC build, full test suite)                                     |
| macOS x86_64   | Not part of the 1.0.0 binary distribution                                          |
| macOS ARM64    | Not part of the 1.0.0 binary distribution                                          |

Source code may contain target-specific branches beyond the packaged 1.0.0 binary matrix; that does not constitute a release-support claim for an unqualified platform.

## Installation

Corulix 1.0.0 uses three strictly-separated publication channels:

- **GitHub** — the public **source repository only**. It contains the
  source tree, permanent regression tests, documentation, and build
  instructions. It never contains Linux/Windows release binaries, npm
  package payloads, crates.io `.crate` packages, or any binary release
  asset — not even via GitHub Releases. Do not expect, or ask for, a
  Corulix binary download from GitHub; build from source, or use the npm
  or crates.io channel below.
- **npm** — the official prebuilt-binary distribution for Node.js users,
  published directly to the npm registry (never mirrored through GitHub).
- **crates.io** — the official Rust/Cargo source-package distribution,
  published directly to crates.io (never mirrored through GitHub). Users
  install through Cargo, which builds the real binary from source; no
  precompiled binary is shipped through this channel.

### Build from the 1.0.0 source package

Obtain the official 1.0.0 source package, extract it, then run:

```sh
cargo build --release --locked --package corulix
./target/release/corulix --version
```

Expected version:

```text
1.0.0
```

The public source package does **not** require `vendor/`, `.corulix-rust/`, `release/`, or `target/`. Dependency resolution is defined by the Cargo manifests and `Cargo.lock`; an offline vendored source bundle, if ever offered, is a separate distribution artifact rather than part of the standard publication set.

### npm package

The npm distribution name is:

```text
@whatalker/corulix
```

When version `1.0.0` is available on the npm registry:

```sh
npm install -g @whatalker/corulix
corulix --version
corulix --help
```

Registry availability is authoritative for whether a package version has actually been published. Node.js is used by the npm launcher/install path; the Corulix runtime itself is a native executable.

### crates.io / Cargo package

The Cargo package name is:

```text
corulix
```

When version `1.0.0` is available on crates.io:

```sh
cargo install corulix
corulix --version
corulix --help
```

Registry availability is authoritative for whether a package version has actually been published — `cargo install corulix` resolves whatever the latest published version actually is. An earlier `0.1.0-alpha.2` line was published under the historical `GPL-3.0-only` terms; it is not the current 1.0.0 product and is not retroactively relicensed. To install that specific historical release explicitly:

```sh
cargo install corulix --version 0.1.0-alpha.2
```

## CLI

```text
corulix toolchain status   [--workspace PATH | --workspace-file FILE]
corulix languages list     [--workspace PATH | --workspace-file FILE]
corulix workspace detect   [--workspace PATH | --workspace-file FILE]
corulix workspace inspect  [--workspace PATH | --workspace-file FILE] [--workspace-root ROOT]
corulix parse <FILE>       [--workspace PATH | --workspace-file FILE] [--workspace-root ROOT]
corulix mcp stdio          [--workspace PATH | --workspace-file FILE]
corulix setup              [--profile full|on-demand] [--only GROUP...] [--exclude GROUP...]
```

The executable's own `--help` output is the command-line parser authority. See [`wht_docs/wht_cli.md`](wht_docs/wht_cli.md).

## Architecture

The workspace separates domain contracts, workspace authority, search, structural syntax, semantic providers, controlled process execution, mutation, formatting, policy orchestration, MCP transport, and CLI concerns into distinct crates. The most security-sensitive boundaries are intentionally centralized: filesystem confinement in `wht_corulix_workspace`, provider/trust resolution in `wht_corulix_config`, external process lifecycle in `wht_corulix_tooling`, semantic protocol handling in `wht_corulix_lsp`, and live workspace mutation in `wht_corulix_mutation`/the governed engine session path.

See [`wht_docs/wht_architecture.md`](wht_docs/wht_architecture.md) and [`wht_docs/wht_architecture_boundaries.md`](wht_docs/wht_architecture_boundaries.md).

## Public source scope

The public 1.0.0 source set is defined by [`PACKAGE_MANIFEST.txt`](PACKAGE_MANIFEST.txt). The standard source publication intentionally excludes local/generated/private material including:

```text
.corulix-rust/
release/
vendor/
target/
private release tooling
local publication staging (wht_public_core/)
internal Brain/governance storage
benchmark scratch/evidence workspaces
internal status reports
```

See [`wht_docs/wht_publication_scope.md`](wht_docs/wht_publication_scope.md) for the rationale and exact policy.

## Documentation

- [`wht_docs/README.md`](wht_docs/README.md) — documentation index
- [`wht_docs/wht_architecture.md`](wht_docs/wht_architecture.md) — current architecture
- [`wht_docs/wht_architecture_boundaries.md`](wht_docs/wht_architecture_boundaries.md) — enforced architecture/security boundaries
- [`wht_docs/wht_language_support.md`](wht_docs/wht_language_support.md) — language/provider capability matrix
- [`wht_docs/wht_mcp_compatibility.md`](wht_docs/wht_mcp_compatibility.md) — MCP contract and tool surface
- [`wht_docs/wht_cli.md`](wht_docs/wht_cli.md) — CLI reference
- [`wht_docs/wht_publication_scope.md`](wht_docs/wht_publication_scope.md) — public/private publication boundary
- [`wht_docs/wht_releasing.md`](wht_docs/wht_releasing.md) — release preparation and publication gate
- [`wht_docs/wht_testing.md`](wht_docs/wht_testing.md) — quality gates
- [`wht_docs/wht_dependencies.md`](wht_docs/wht_dependencies.md) — dependency policy and current direct baseline
- [`wht_docs/wht_supply_chain.md`](wht_docs/wht_supply_chain.md) — supply-chain controls
- [`wht_docs/wht_reproducible_builds.md`](wht_docs/wht_reproducible_builds.md) — reproducibility model
- [`wht_docs/wht_threat_model.md`](wht_docs/wht_threat_model.md) — threat model
- [`CHANGELOG.md`](CHANGELOG.md) — release-oriented change history

## License

Current 1.0.0 source is licensed under **AGPL-3.0-only**. See [`LICENSE`](LICENSE).

The historical `0.1.0-alpha.2` release remains under its original `GPL-3.0-only` terms.

## Trademark

**WhaTalker®**, **WhaTalker Corulix™**, and **Corulix™** are WhaTalker Inc. brand identifiers. Trademark policy is separate from the AGPL source-code license. See [`wht_docs/wht_trademarks.md`](wht_docs/wht_trademarks.md).

## Copyright

Copyright © 2026 WhaTalker Inc.
