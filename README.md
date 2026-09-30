# WhaTalker Corulix™

**Enterprise code intelligence and governed code mutation for AI coding agents over Model Context Protocol (MCP).**

Built by **[WhaTalker Inc.](https://whatalker.com)**. Product website: **[corulix.com](https://corulix.com)**.

[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](./LICENSE)
[![Rust 1.97.1](https://img.shields.io/badge/rust-1.97.1-orange.svg)](./rust-toolchain.toml)
[![Version 1.1.0](https://img.shields.io/badge/version-1.1.0-informational.svg)](./VERSION)

```text
Product:           WhaTalker Corulix
Brand:             Corulix™
CLI:               corulix
Version:           1.1.0
License:           AGPL-3.0-only
MCP transport:     stdio
Public MCP tools:  14 (workspace-policy downscopeable)
Supported source:  Rust, Go, TypeScript/TSX, JavaScript/JSX, Python
```

## What Corulix is

Corulix is a Rust-based MCP server that gives AI coding agents a governed interface to real software workspaces. It combines repository discovery, structural parsing, compiler-grade semantic providers, controlled formatting, validation, and an explicit mutation lifecycle while keeping filesystem, process, provider, and workspace-trust boundaries fail closed.

Corulix is not a general-purpose shell, Git client, or unrestricted file editor. Workspace changes are made only through the declared change-session workflow and are subject to the product's validation and authority model.

## What's new in Corulix 1.1.0

**New in 1.1.0:**

- **Workspace JSON configuration** — an optional, workspace-scoped, non-privileged `WhaTalker_Corulix_JSON_Config.json` that can narrow (never widen) MCP tool exposure and provider-category availability. See [Workspace JSON configuration](#workspace-json-configuration-110) below.
- **Tool-policy downscoping** — `toolPolicy.disabledTools` lets a workspace hide a subset of the canonical MCP tools from discovery and direct invocation, subject to fixed mutation-lifecycle dependency rules.
- **Provider-category narrowing** — `defaults.disabledCategories`, optionally narrowed further per member root via `rootOverrides[]`.
- **Portable rooted-locator rejection** — an absolute or rooted `rootOverrides[].root` locator (POSIX absolute, Windows drive-absolute/drive-relative, or UNC/device-namespace syntax) is rejected the same way regardless of which host OS runs the validator.
- **`corulix config` command family** — `config validate`, `config inspect`, and `config schema`, all zero-mutation, sharing one validator with `corulix mcp stdio`'s own startup path.
- **`corulix instructions generate`** — renders the workspace's effective configuration as an advisory `AGENTS.md` (or a `CLAUDE.md` `@AGENTS.md` import bridge), with managed-write safety (no `--force`; an unmanaged existing file is never overwritten).
- **Native Windows x86_64 certification** — full native MSVC build, complete workspace test suite, PE32+/AMD64 binary-format certification, and CLI/MCP/config-policy runtime certification, alongside the existing Linux x86_64 native certification.
- **Linux ARM64 release artifact** — a real `aarch64-unknown-linux-gnu` cross-built binary, architecture-verified; see [Platform support](#platform-support) for its exact certification scope.

**Unchanged public contract:** the 14 public MCP tools, their names and semantics, the `ChangeSession` governed-mutation lifecycle, the managed-toolchain model, and the workspace trust/security model are all unchanged from 1.0.0. Workspace JSON configuration can only ever reduce the effective MCP tool surface below its unchanged canonical set of 14 — it can never add a 15th tool or grant any additional privilege.

## Core capabilities

| Capability              | Current 1.1.0 behavior                                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------------------------------- |
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
| Workspace configuration | Optional `WhaTalker_Corulix_JSON_Config.json` narrowing MCP tool exposure and provider categories (new in 1.1.0) |
| Cross-platform runtime  | Native Linux x86_64 and native Windows x86_64 release support, plus a Linux ARM64 cross-built release artifact  |

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

Corulix 1.1.0 exposes exactly **14 public MCP tools** over stdio:

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

## Workspace JSON configuration (1.1.0)

A workspace may optionally carry its own `WhaTalker_Corulix_JSON_Config.json` — the exact canonical filename, case-sensitive. It is read only from its canonical fixed location (beside a `.code-workspace` descriptor for a multi-root workspace, or directly inside a single root) — there is no explicit `--workspace-config <FILE>` path in 1.1.0.

This file is Corulix's own **workspace policy/configuration**. It is not, and does not replace, your MCP host or client's own connection configuration (e.g. how your AI client is told to launch `corulix mcp stdio`) — that remains entirely your host's own concern.

An absent config file reproduces Corulix 1.0.0's exact behavior (all 14 tools enabled, no category narrowing). Every other read failure (permission denied, oversized, invalid UTF-8, malformed content) fails closed — never silently treated as absent.

### Complete valid example

```json
{
  "configName": "WhaTalker Corulix JSON Config",
  "schemaVersion": 1,
  "toolPolicy": {
    "disabledTools": [
      "begin_change",
      "submit_edit",
      "validate_change",
      "change_status",
      "complete_change",
      "abort_change"
    ]
  },
  "defaults": {
    "disabledCategories": ["FORMATTER"]
  },
  "rootOverrides": [
    { "root": "wht_backend", "disabledCategories": ["FORMATTER", "LINTER"] },
    { "root": "wht_frontend", "disabledCategories": ["FORMATTER"] }
  ]
}
```

This example is machine-validated against the real Corulix 1.1.0 binary in a two-root `wht_backend`/`wht_frontend` workspace: `corulix config validate --workspace-file <Project.code-workspace>` reports `workspace_config_status: "OK"`, `effective_visible_tool_count: 8`, and `root_override_count: 2`; `corulix config inspect --workspace-file <Project.code-workspace> --workspace-root wht_backend` reports that root's own effective disabled categories as the union `["FORMATTER", "LINTER"]`.

### Field reference

| Field | Type | Required | Purpose / effective behavior |
| --- | --- | --- | --- |
| `configName` | string | yes | Must be exactly `"WhaTalker Corulix JSON Config"`. Any other value fails closed before the rest of the file is even parsed. |
| `schemaVersion` | integer | yes | Must be exactly `1` for Corulix 1.1.0. An unsupported or non-integer value fails closed with a dedicated error, checked before the strict body is parsed — so a future schema version reports "unsupported version," never generic "unknown field" noise. |
| `toolPolicy.disabledTools` | array of string | no (default: empty) | A deny-list of canonical MCP tool names to hide from MCP discovery and direct invocation. Absent or empty means all 14 tools stay visible. Reduces only — it can never add a tool beyond the canonical 14. A duplicate entry, or a name that isn't one of the 14 canonical tools, is rejected. Disabling `begin_change`, `complete_change`, or `submit_edit` without also disabling their required lifecycle companions is rejected (see the mutation-lifecycle rules below). |
| `defaults.disabledCategories` | array of string | no (default: empty) | Provider categories (`TEXT_SEARCH`, `STRUCTURAL_PARSE`, `LANGUAGE_SERVER`, `FORMATTER`, `LINTER`, `TYPECHECK_BUILD`, `TEST_RUNNER`, `RUNTIME`) disabled workspace-wide. A duplicate entry is rejected. |
| `rootOverrides[].root` | string | — | A workspace-relative folder locator matching `.code-workspace`'s own `folders[].path` convention. Rejected outright, on every host OS, if it is a POSIX absolute path, a Windows drive-absolute/drive-relative path, or a UNC/device-namespace path — this rejection is a pure string check, not host-native path semantics, so the same locator is rejected identically whether Corulix itself is running on Linux or Windows. The accepted string is never itself authority: it is canonicalized and matched only against the workspace's own already-authorized member roots; a locator that doesn't resolve to one of them is rejected the same way whether it "almost" resolved or doesn't exist at all. |
| `rootOverrides[].disabledCategories` | array of string | — | That one root's own additional disabled categories. The root's effective set is the union of this array and `defaults.disabledCategories` — narrowing only, never re-enabling something a broader scope already disabled. |

### Tool-policy example (14 → 8)

Disabling the entire six-tool mutation family is the canonical read-only pattern:

```json
{
  "configName": "WhaTalker Corulix JSON Config",
  "schemaVersion": 1,
  "toolPolicy": {
    "disabledTools": [
      "begin_change",
      "submit_edit",
      "validate_change",
      "change_status",
      "complete_change",
      "abort_change"
    ]
  }
}
```

Machine-verified: `corulix config inspect --workspace <DIRECTORY>` reports `effective_visible_tool_count: 8` (the 8 non-mutation tools remain: `runtime_identity`, `workspace_info`, `toolchain_status`, `plan_operation`, `search`, `parse_file`, `semantic`, `format_preview`), and a live MCP `tools/list` returns exactly those same 8 names.

Three static rules keep a policy internally consistent, enforced identically by `config validate` and by `corulix mcp stdio` at startup — so a policy that passes `config validate` is guaranteed not to later be refused by the MCP server for the same reason, and vice versa:

1. If `begin_change` is disabled, all five downstream lifecycle tools (`submit_edit`, `validate_change`, `change_status`, `complete_change`, `abort_change`) must also be disabled.
2. If `complete_change` is enabled, both `begin_change` and `validate_change` must be enabled.
3. If `submit_edit` is enabled, `begin_change`, `validate_change`, and `complete_change` must all be enabled — `submit_edit` is the file-mutating capability, and Corulix refuses to expose a mutation with no visible, governed path to validated completion.

### Invalid example — rejected on every host OS

```json
{
  "configName": "WhaTalker Corulix JSON Config",
  "schemaVersion": 1,
  "rootOverrides": [
    { "root": "C:\\Windows\\System32", "disabledCategories": ["FORMATTER"] }
  ]
}
```

`corulix config validate` rejects this with exit code `9` and `REASON=rootOverrides[].root is invalid: must not be an absolute or rooted path (POSIX absolute, Windows drive-absolute/drive-relative, or UNC/device-namespace syntax)` — verified identically on the certified Linux x86_64 and Windows x86_64 1.1.0 binaries.

### CLI commands

```sh
corulix config validate  [--workspace PATH | --workspace-file FILE]
corulix config inspect   [--workspace PATH | --workspace-file FILE] [--workspace-root ROOT]
corulix config schema
```

All three are zero-mutation: they open no engine, start no MCP server, and provision nothing. `config schema` takes no flags and emits the canonical JSON Schema (JSON by default — there is no `--json` flag). Exit codes: `0` valid (including a genuinely absent config file); `3` the workspace itself could not be resolved; `9` the config file exists but is malformed, structurally invalid, or fails semantic tool-policy validation.

See [`wht_docs/wht_workspace_json_config_reference.md`](wht_docs/wht_workspace_json_config_reference.md) for the complete schema, authority model, and additional worked examples.

`corulix instructions generate` renders this same effective configuration as an advisory `AGENTS.md` (or a one-line `CLAUDE.md` `@AGENTS.md` import bridge). It is advisory documentation only — it carries no Corulix enforcement weight and is never deserialized back into runtime authority. Default prints to stdout; `--write` creates or safely replaces a Corulix-managed file (never an unmanaged/hand-authored one — there is no `--force`); `--check` reports drift without mutating anything.

```sh
corulix instructions generate --workspace <DIRECTORY> --write
```


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

The local managed-toolchain state is runtime data, not public source. In particular, `.corulix-rust/` is excluded from the publication set. See [`wht_docs/wht_publication_scope.md`](wht_docs/wht_publication_scope.md).

## Platform support

The Corulix 1.1.0 release surface is qualified for native Linux x86_64, native Windows x86_64, and a cross-built Linux ARM64 artifact.

| Platform       | 1.1.0 status                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Linux x86_64   | Native build, full native workspace test suite, native runtime/CLI/MCP/config-policy verification                                                     |
| Windows x86_64 | Native MSVC build, full native workspace test suite, PE32+/AMD64 binary-format certification, native runtime/CLI/MCP (14-tool)/config-policy verification |
| Linux ARM64    | Real `aarch64-unknown-linux-gnu` binary built via the approved cross-compile path, architecture-verified. Runtime classification: **cross-compile build only** — native ARM64 runtime execution has not been performed and is not claimed |
| macOS x86_64   | Not part of the 1.1.0 binary distribution                                                                                                              |
| macOS ARM64    | Not part of the 1.1.0 binary distribution                                                                                                              |

Source code may contain target-specific branches beyond the packaged binary matrix; that does not constitute a release-support claim for an unqualified platform. Registry/publication availability (see [Installation](#installation)) is a separate question from release-candidate certification: this table describes what has been built and certified, not what is currently live on a public registry.

## Installation

Corulix uses three strictly-separated publication channels:

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

### Build from source

Obtain the official 1.1.0 source package, extract it, then run:

```sh
cargo build --release --locked --package corulix
./target/release/corulix --version
```

Expected version:

```text
1.1.0
```

The public source package does **not** require `vendor/`, `.corulix-rust/`, `release/`, or `target/`. Dependency resolution is defined by the Cargo manifests and `Cargo.lock`; an offline vendored source bundle, if ever offered, is a separate distribution artifact rather than part of the standard publication set.

### npm package

The npm distribution name is:

```text
@whatalker/corulix
```

When version `1.1.0` is available on the npm registry:

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

When version `1.1.0` is available on crates.io:

```sh
cargo install corulix
corulix --version
corulix --help
```

Registry availability is authoritative for whether a package version has actually been published — `cargo install corulix` resolves whatever the latest published version actually is. An earlier `0.1.0-alpha.2` line was published under the historical `GPL-3.0-only` terms; it is not the current 1.1.0 product and is not retroactively relicensed. To install that specific historical release explicitly:

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
corulix config validate    [--workspace PATH | --workspace-file FILE]
corulix config inspect     [--workspace PATH | --workspace-file FILE] [--workspace-root ROOT]
corulix config schema
corulix instructions generate [--workspace PATH | --workspace-file FILE] [--format agents|claude] [--write | --check]
corulix setup              [--profile full|on-demand] [--only GROUP...] [--exclude GROUP...]
```

The executable's own `--help` output is the command-line parser authority. See [`wht_docs/wht_cli.md`](wht_docs/wht_cli.md).

## Architecture

The workspace separates domain contracts, workspace authority, search, structural syntax, semantic providers, controlled process execution, mutation, formatting, policy orchestration, MCP transport, and CLI concerns into distinct crates. The most security-sensitive boundaries are intentionally centralized: filesystem confinement in `wht_corulix_workspace`, provider/trust resolution in `wht_corulix_config`, external process lifecycle in `wht_corulix_tooling`, semantic protocol handling in `wht_corulix_lsp`, and live workspace mutation in `wht_corulix_mutation`/the governed engine session path.

See [`wht_docs/wht_architecture.md`](wht_docs/wht_architecture.md) and [`wht_docs/wht_architecture_boundaries.md`](wht_docs/wht_architecture_boundaries.md).

## Public source scope

The public 1.1.0 source set is defined by [`PACKAGE_MANIFEST.txt`](PACKAGE_MANIFEST.txt). The standard source publication intentionally excludes local/generated/private material including:

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
- [`wht_docs/wht_workspace_json_config_reference.md`](wht_docs/wht_workspace_json_config_reference.md) — `WhaTalker_Corulix_JSON_Config.json` schema, authority model, and `corulix config` CLI reference (1.1.0)
- [`wht_docs/wht_publication_scope.md`](wht_docs/wht_publication_scope.md) — public/private publication boundary
- [`wht_docs/wht_releasing.md`](wht_docs/wht_releasing.md) — release preparation and publication gate
- [`wht_docs/wht_testing.md`](wht_docs/wht_testing.md) — quality gates
- [`wht_docs/wht_dependencies.md`](wht_docs/wht_dependencies.md) — dependency policy and current direct baseline
- [`wht_docs/wht_supply_chain.md`](wht_docs/wht_supply_chain.md) — supply-chain controls
- [`wht_docs/wht_reproducible_builds.md`](wht_docs/wht_reproducible_builds.md) — reproducibility model
- [`wht_docs/wht_threat_model.md`](wht_docs/wht_threat_model.md) — threat model
- [`CHANGELOG.md`](CHANGELOG.md) — release-oriented change history

## License

Current 1.1.0 source is licensed under **AGPL-3.0-only**. See [`LICENSE`](LICENSE).

The historical `0.1.0-alpha.2` release remains under its original `GPL-3.0-only` terms.

## Trademark

**WhaTalker®**, **WhaTalker Corulix™**, and **Corulix™** are WhaTalker Inc. brand identifiers. Trademark policy is separate from the AGPL source-code license. See [`wht_docs/wht_trademarks.md`](wht_docs/wht_trademarks.md).

## Copyright

Copyright © 2026 WhaTalker Inc.
