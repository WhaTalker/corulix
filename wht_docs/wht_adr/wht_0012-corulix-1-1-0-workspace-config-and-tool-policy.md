# ADR 0012 — Corulix 1.1.0: Workspace JSON Configuration, Tool Exposure Policy, and Enterprise AGENTS.md

**Status:** Accepted (contract frozen; implementation authorized for Phases A0-O only, per owner authorization 2026-09-23)

## Context

Corulix 1.0.0 is closed and immutable. This ADR records the frozen contract for the next, backward-compatible MINOR release, 1.1.0, covering three additive capabilities that did not exist in 1.0.0: a workspace-scoped JSON configuration file, a reduce-only MCP tool exposure policy, and enterprise `AGENTS.md`/instruction-generation support. The full design rationale, source audits, and decision history live in the owner-approved implementation plan (`/home/whtroot/.claude/plans/mandato-de-implementaci-n-lexical-peacock.md` at authorization time); this ADR is the durable, in-repository record of what was frozen, since the plan file itself is not part of the repository.

## Decision

The following are frozen for 1.1.0 and require a new owner decision to change:

1. **Canonical config filename and identity keys**: `WhaTalker_Corulix_JSON_Config.json`, containing `"configName": "WhaTalker Corulix JSON Config"` and `"schemaVersion": 1`. Casing is part of the contract (verified on Windows via directory-entry-name comparison in Phase P, not case-insensitive path existence).
2. **JSON key casing**: camelCase throughout (`toolPolicy`, `disabledTools`, `disabledCategories`, `rootOverrides`).
3. **Discovery**: canonical fixed-location only. No `--workspace-config <FILE>` explicit-path flag exists in 1.1.0 — this deliberately avoids introducing a new explicit-path TOCTOU surface.
4. **Authority model**: three structurally separate domains — `HostConfig` (TOML, `HOST_ONLY`, privileged, unchanged), `WhaTalker_Corulix_JSON_Config.json` (workspace-scoped, non-privileged, runtime-authoritative for what it does control), and `AGENTS.md`/`CLAUDE.md` (advisory prose, never deserialized into runtime authority). A workspace JSON config can only narrow, never elevate, host-granted authority.
5. **Root-locator semantics**: `rootOverrides[].root` is an authored, workspace-relative folder path (parent-relative `..` components permitted, matching real `.code-workspace` `folders[].path` support, confirmed via `wht_corulix_workspace/src/descriptor.rs`'s own `parses_comments_and_trailing_commas` test). The authored string is never itself authority; only a canonical-path match against an already-authorized member root of the live `WorkspaceContext` is.
6. **Tool exposure policy**: deny-list only (`toolPolicy.disabledTools: [String]`), workspace-wide (never per-root, since MCP `tools/list` answers once per connection before any root is known). All 14 canonical MCP tools are individually downscopeable, including `runtime_identity` and `workspace_info` — there is no product-mandatory tool. Canonical tool count remains exactly 14 (compile-time, `wht_scripts/wht_verify_architecture.py` Rule S, unchanged). The mutation family is exactly 6 tools (`begin_change`, `submit_edit`, `validate_change`, `change_status`, `complete_change`, `abort_change`); disabling `begin_change` requires disabling all 5 downstream tools; `complete_change` requires `validate_change`; `submit_edit` requires `validate_change` and `complete_change` both visible.
7. **Single shared policy authority**: the canonical tool catalog, mutation-family metadata, and semantic validation rules are declared once (`wht_corulix_core`) and consumed identically by `corulix config validate`, `corulix config schema`, MCP server construction, and the instruction generator. `config validate` PASS/FAIL must always agree with MCP construction PASS/FAIL for the same policy.
8. **`WorkspaceInfo` (`wht_corulix_core`, published to crates.io) is never modified.** It has all-public fields and no `#[non_exhaustive]`, so adding fields to it directly would be a real Rust SemVer break (confirmed via source read during the 1.1.0 preflight SemVer audit). The new tool-policy introspection fields are carried on a new, `wht_corulix_mcp`-local response type that additively wraps `WorkspaceInfo` (e.g. via `#[serde(flatten)]`), preserving every existing JSON key and adding only new ones — additive at the wire/schema level without touching the Rust type.
9. **Instruction generation**: `corulix instructions generate --format {agents|claude}`, default `--stdout`, explicit `--write` opt-in, `--check` for drift detection. No `--force` flag exists — an existing unmanaged (non-Corulix-generated) target is never overwritten. `--format claude` emits only the one-line `@AGENTS.md` import-stub bridge (verified against current official Anthropic documentation of `CLAUDE.md`'s `@path/to/import` support); no standalone/duplicated `CLAUDE.md` content mode exists in 1.1.0.
10. **Versioning**: Corulix 1.1.0 is a MINOR, backward-compatible release. Crate versioning moved from workspace-wide inherited (`version.workspace = true`) to explicit per-crate (`SELECTIVE_SEMVER_WITH_DEPENDENCY_CLOSURE`) — see this ADR's own migration, Section "Versioning migration" below. Directly-affected crates (`wht_corulix_core`, `wht_corulix_config`, `wht_corulix_workspace`, `wht_corulix_engine`, `wht_corulix_mcp`, `corulix`) start the 1.1.0 line; unaffected crates remain explicitly pinned at `1.0.0`. Phase M determines the final publish set from the actual implementation diff.
11. **Platform sequence**: Linux x64 native, then Linux ARM64 cross-build (never represented as native runtime certification unless actually executed on real ARM64 hardware), then a hard stop. Windows x64 native certification requires a separate, later owner authorization and is not started as part of this ADR's scope.
12. **Documentation**: the authoritative full reference lives at `wht_docs/wht_workspace_json_config_reference.md`; root `README.md`/`AGENTS.md` link to it rather than duplicating schema.

## Versioning migration (Phase A0, executed under this ADR)

Prior to 1.1.0, every crate's `[package]` section used `version.workspace = true`, inheriting one shared version from `[workspace.package].version`. This made per-crate selective versioning structurally impossible. As part of freezing this contract, `[workspace.package].version` was removed, and every one of the 16 workspace member crates was given an explicit `version` field:

- `1.1.0`: `wht_corulix_core`, `wht_corulix_config`, `wht_corulix_workspace`, `wht_corulix_engine`, `wht_corulix_mcp`, `corulix` (package name of the `wht_corulix_cli` crate directory).
- `1.0.0` (explicit, unchanged, pinned): `wht_corulix_formatter`, `wht_corulix_index`, `wht_corulix_lsp`, `wht_corulix_mutation`, `wht_corulix_process_fixture` (non-publishable, `publish = false`), `wht_corulix_process_unix`, `wht_corulix_process_win32`, `wht_corulix_search`, `wht_corulix_syntax`, `wht_corulix_tooling`.

Internal `[workspace.dependencies]` version _requirement_ strings (e.g. `wht_corulix_core = { path = "...", version = "1.0.0" }`) are deliberately left unraised at this step — a `"1.0.0"` requirement already permits resolving to a local `1.1.0` path dependency (semver-compatible, same major, higher minor). Requirement floors are raised only phase-by-phase, exactly when a specific new 1.1.0 API item is actually consumed cross-crate, never mechanically ahead of real usage.

Verified this pass: `cargo metadata` succeeds; `cargo check --workspace --all-targets --locked` passes; `Cargo.lock` reconciles deterministically to the split versions; `corulix --version` reports `corulix 1.1.0` from a real built-and-executed binary.

## Consequences

- Future crate releases must use this same selective-versioning discipline — there is no shared workspace version to fall back on.
- Any future addition to `WorkspaceInfo` must go through the same SemVer discipline this ADR applied: either compose a wrapping type, or obtain an explicit new owner decision to accept a documented break.
- `AGENTS.md`/`CLAUDE.md` remain permanently advisory-only for this product; no future Corulix feature may deserialize their content into runtime authority without superseding this ADR explicitly.

## Related

- `wht_docs/wht_iso_alignment.md`
- `wht_docs/wht_releasing.md`
- `wht_docs/wht_host_profiles/{wht_codex,wht_claude_code}.toml`
- `wht_docs/wht_corulix_1_1_0_risk_register.md`
