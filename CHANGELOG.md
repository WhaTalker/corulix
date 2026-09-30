# Changelog

This changelog is release-oriented. It records externally meaningful product changes and intentionally excludes temporary qualification logs, benchmark transcripts, scratch paths, local machine details, and internal decision IDs.

## 1.1.0

Corulix 1.1.0 is a backward-compatible MINOR release (see `wht_docs/wht_adr/wht_0012-corulix-1-1-0-workspace-config-and-tool-policy.md`). Native Linux x86_64, native Windows x86_64, and cross-built Linux ARM64 artifacts are all built, tested, and certified. Publication (GitHub/crates.io/npm) remains a separate, explicitly-gated lifecycle stage — see [Installation](README.md#installation) for how to check current registry availability.

### Added

- **Workspace JSON configuration.** An optional, workspace-scoped, non-privileged `WhaTalker_Corulix_JSON_Config.json`, read only from its canonical fixed location. It can narrow (never widen) the effective MCP tool set and provider-category availability, with per-root overrides. An absent file reproduces Corulix 1.0.0's exact behavior. See `wht_docs/wht_workspace_json_config_reference.md`.
- **Reduce-only MCP tool exposure policy.** All 14 canonical tools, including `runtime_identity` and `workspace_info`, are individually downscopeable via `toolPolicy.disabledTools`, subject to mutation-lifecycle dependency rules that keep a policy internally consistent. There is no product-mandatory tool. A disabled tool is both invisible to `tools/list` discovery and rejected on direct invocation.
- **`corulix config` CLI.** `config validate`, `config inspect [--workspace-root]`, and `config schema` — all zero-mutation, sharing the exact same structural/semantic validator the MCP server itself uses at startup, so CLI validation and MCP construction can never disagree.
- **`workspace_info` count-only tool-policy introspection.** `canonical_tool_count`, `effective_visible_tool_count`, and `tool_policy_configured` fields, carried on a new wrapper type so the published `WorkspaceInfo` type itself was never modified. Never reveals which specific tools are disabled.

### Changed

- Crate versioning moved from workspace-wide inherited (`version.workspace = true`) to explicit per-crate declarations (`SELECTIVE_SEMVER_WITH_DEPENDENCY_CLOSURE`): the directly-affected crates (`wht_corulix_core`, `wht_corulix_config`, `wht_corulix_workspace`, `wht_corulix_engine`, `wht_corulix_mcp`, `corulix`) report `1.1.0`; unaffected publishable crates remain explicitly pinned at `1.0.0`.

## 1.0.0

Corulix 1.0.0 is the first complete enterprise baseline of the current architecture and the current source identity under `AGPL-3.0-only`.

### Added

- A 14-tool MCP stdio surface:
  - `abort_change`
  - `begin_change`
  - `change_status`
  - `complete_change`
  - `format_preview`
  - `parse_file`
  - `plan_operation`
  - `runtime_identity`
  - `search`
  - `semantic`
  - `submit_edit`
  - `toolchain_status`
  - `validate_change`
  - `workspace_info`
- Governed `ChangeSession` mutation lifecycle with scoped edits, validation evidence, completion gates, and terminal abort behavior.
- Single-root and `.code-workspace` multi-root workspace discovery with canonicalized confinement.
- Bounded in-process text search and Tree-sitter structural parsing for Rust, Go, TypeScript/TSX, JavaScript/JSX, and Python.
- Compiler-grade semantic provider integration for Rust, Go, TypeScript/JavaScript, and Python.
- Language-aware formatter, type/build, lint, and test validation paths, including Rust, Go, TypeScript/JavaScript, and Python governed verticals.
- Managed toolchain/component provisioning with pinned artifact verification, ownership tracking, execution leases, and uninstall handling.
- Host-only workspace trust/provider configuration and fail-closed provider resolution without ambient `PATH` authority.
- Native Windows process containment and platform-specific fail-closed execution semantics.
- Linux and native Windows release support for the 1.0.0 distribution surface.

### Security and reliability

- Centralized filesystem authority in the workspace layer and object-authority-first security semantics for workspace-bound operations.
- Strict MCP input schemas and protocol stdout/stderr separation.
- Controlled external process execution with explicit argv/environment/working-directory/timeout/cancellation policy.
- Workspace content cannot self-authorize trusted execution or provider paths.
- Provider/runtime selection fails closed when required authority or safe platform binding is unavailable.
- The 1.0.0 qualified dependency baseline includes `rustls 0.23.45`, resolving the previously identified `RUSTSEC-2026-0285` advisory condition.

### Changed

- Current WhaTalker-authored source is licensed under `AGPL-3.0-only`.
- Version identity advanced from the historical `0.1.0-alpha.2` line to `1.0.0`.
- The public documentation was reconciled to the final 1.0.0 architecture and tool surface.
- Release/publication scope is explicit: generated, private, local-toolchain, benchmark, and vendored-cache directories are not part of the standard public source set unless a separately identified artifact says otherwise.

### Platform scope

- Linux: supported release platform.
- Windows x86_64: supported native release platform.
- macOS binaries are not part of the 1.0.0 packaged distribution.
- Windows workspace-bound execution intentionally fails closed when the required safe object/process authority cannot be established; no pathname-only security fallback is claimed.

### Publication scope

The standard public source set is defined by `PACKAGE_MANIFEST.txt`. It excludes `.corulix-rust/`, `release/`, `vendor/`, `target/`, private release tooling, internal governance storage, benchmark scratch/evidence directories, and internal status reports. See `wht_docs/wht_publication_scope.md`.

### Phase 14 -- HOST ENFORCEMENT PROFILES

Four canonical, machine-readable host enforcement profiles were established under `wht_docs/wht_host_profiles/`, each certifying a single, narrow security property: whether a given AI coding host's own sandbox/permission system can be made to prevent bypassing Corulix's governance, and whether a bypass attempt can be detected. This is a security/governance property, distinct from Corulix AI-client functional validation; see `wht_docs/wht_host_enforcement.md` for the terminology distinction. Every classification below was established by executing the real installed host binary against a real fixture workspace, never from documentation, and every preventive claim required a positive control (the same prompt, version, and fixture run twice: once with the control removed, where the operation must occur, and once with the certified configuration, where it must not).

- **Claude Code evidence subsection.** Claude Code 2.1.247, certified 2026-08-27: `can_prevent_bypass = YES`, `can_detect_bypass = YES`. Prevention was proven by two independent mechanisms under positive control -- schema removal of the direct-mutation tools from the model's advertised tool list, and a `PreToolUse` guard hook that changed the outcome from a completed mutation to a blocked one under an otherwise fully permissive configuration. Detection was proven via the run result document's own denial record and the guard hook's own audit payload. See `wht_docs/wht_host_profiles/wht_claude_code.toml`.
- **Codex evidence subsection.** Codex CLI 0.142.4, certified 2026-08-27: `can_prevent_bypass = YES`, `can_detect_bypass = YES`. Prevention was proven at the kernel level via an operating-system sandbox refusal under the certified `read-only` mode, including a nested re-invocation attempt that could not escape the sandbox. Detection was proven via the persistent session rollout recording the blocked command and its failure. See `wht_docs/wht_host_profiles/wht_codex.toml`.
- **OpenCode evidence subsection.** OpenCode 1.17.18, certified 2026-08-27: `can_prevent_bypass = PARTIAL`, `can_detect_bypass = PARTIAL`. Prevention is capped at `PARTIAL` because a project-level configuration file can fully re-enable a globally denied tool, and because an unrecognized permission key is silently ignored rather than rejected. The language model itself was replaced with a deterministic stub that attempted the bypass unconditionally, isolating the host's own permission layer as the property under test. See `wht_docs/wht_host_profiles/wht_opencode.toml`.
- **K. VS Code residual closed.** VS Code 1.123.0 with its built-in GitHub Copilot Chat 0.51.0, certified 2026-08-28 in a direct follow-up pass: `can_prevent_bypass = PARTIAL`, `can_detect_bypass = YES`. The real gate is a one-time human-approval modal recorded in the profile's own application storage, not a `settings.json` key; prevention is `PARTIAL`, not `YES`, because the gate is a one-time approval rather than a standing refusal. Detection was proven via the persistent chat-session transcript recording the exact command and the approval mechanism that authorized it, corroborated independently by the extension host's own log. See `wht_docs/wht_host_profiles/wht_vscode_copilot_chat.toml`.

All four profiles record `host_trust_elevation = 0`, `host_risk_override = 0`, and `host_gate_override = 0`: no host configuration can grant a host authority to set Corulix `WorkspaceTrust`, `RiskClass`, `ToolPlan`, required gates, or evidence. This phase added no MCP surface and no Rust behavior change; the 14-tool contract and existing test baseline were re-verified, not expanded.

## 0.1.0-alpha.2

Historical public alpha released under `GPL-3.0-only`.

Notable changes from the initial alpha included:

- CLI/package identity standardized on `corulix`.
- Public project branding and package metadata were normalized.
- Early architecture, workspace confinement, MCP stdio, structural parsing, governance, provenance, and release-policy foundations were established.
- Developer-local workspace/topology files were removed from the intended public publication set.

This historical release is not the current 1.0.0 product and is not retroactively relicensed.

## 0.1.0-alpha.1

Initial source baseline establishing the first Corulix crate boundaries, workspace confinement, Tree-sitter structural parsing, MCP stdio adapter, CLI skeleton, governance documentation, provenance policy, and repository validators.
