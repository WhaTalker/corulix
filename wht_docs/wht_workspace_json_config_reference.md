# WhaTalker Corulix JSON Config Reference (1.1.0)

This document is the authoritative reference for `WhaTalker_Corulix_JSON_Config.json`, Corulix 1.1.0's optional, workspace-scoped, non-privileged configuration file (ADR 0012). It is implemented by `wht_corulix_config::workspace_config` and consumed identically by `corulix config validate`/`config inspect` and by `corulix mcp stdio` at startup — the CLI and the MCP server share one validator, never two.

## 1. Where it lives

Corulix 1.1.0 reads this file only from its own canonical fixed location. There is no `--workspace-config <FILE>` explicit-path flag.

- **Multi-root workspace** (a `.code-workspace` descriptor was resolved): beside the descriptor file, in the same directory.
- **Single-root workspace**: directly inside the one workspace root.

Genuine absence is valid and reproduces Corulix 1.0.0's exact behavior: all 14 canonical MCP tools enabled, no provider-category narrowing, no root overrides. Every other read failure (permission denied, oversized, invalid UTF-8, malformed content) fails closed — it is never silently treated as absent.

## 2. Required envelope

```jsonc
{
  "configName": "WhaTalker Corulix JSON Config",
  "schemaVersion": 1
}
```

Both fields are checked in a first parsing pass, before the strict body is parsed — so a wrong `configName` or an unsupported `schemaVersion` is reported precisely, never drowned out by "unknown field" noise from a shape the current version doesn't recognize.

## 3. Full schema (v1)

```jsonc
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

Every top-level and nested object rejects unknown fields. A `HostConfig` privilege field (`workspace_trust`, `allow_trusted_workspace_execution`, `provider_absolute_paths`, `approved_system_directories`, `approved_user_toolchain_directories`, `enable_user_toolchain_directories`, `managed_provisioning_policy`) is not a declared field anywhere in this schema — supplying one is rejected as an ordinary unknown-field error, not a runtime-recognized (and therefore potentially silently honored) name. This is the strongest guarantee in the design: it is structural, not a runtime check that could be bypassed.

Fetch the machine-readable schema directly from the product itself rather than hand-copying this document:

```sh
corulix config schema
```

The emitted `toolPolicy.disabledTools` item enum is generated from Corulix's own single canonical tool-name catalog — it can never drift from the real semantic validator.

### `toolPolicy.disabledTools`

A deny-list of canonical MCP tool names to hide from this connection. Absent or empty means all 14 tools stay enabled (Corulix 1.0.0's exact behavior). A duplicate entry is rejected, never silently deduplicated. Tool exposure is **workspace-wide only** — it cannot be set per root, because `tools/list` is answered once per MCP connection, before any operation selects a root.

### `defaults.disabledCategories` / `rootOverrides[].disabledCategories`

Provider categories (`TEXT_SEARCH`, `STRUCTURAL_PARSE`, `LANGUAGE_SERVER`, `FORMATTER`, `LINTER`, `TYPECHECK_BUILD`, `TEST_RUNNER`, `RUNTIME`) to disable. `defaults` applies workspace-wide; each `rootOverrides[]` entry narrows further for that one member root. The effective set for a root is the union of `defaults.disabledCategories` and that root's own override — narrowing only, never re-enabling something the workspace-wide defaults or the host already disabled. A duplicate entry within either array is rejected, never silently collapsed.

### `rootOverrides[].root`

A workspace-relative folder locator, matching `.code-workspace`'s own `folders[].path` convention (a parent-relative `"../sibling"` locator is accepted, since real `.code-workspace` descriptors already use that shape). The raw string is never itself authority: it is canonicalized and matched against the live, already-authorized set of member roots. A locator that canonicalizes to a real path outside that set is rejected identically to one that doesn't resolve at all — both simply "don't bind to anything real" — so this document deliberately does not tell you which case you hit, since that would leak filesystem existence information to a config author who may not be authorized to know what exists outside the workspace. Two entries resolving to the same root are rejected as a duplicate binding. On every load, resolution is by canonical path, not position, so reordering `folders[]` in the descriptor never silently rebinds an override to a different root.

## 4. Tool exposure: dependency rules

All 14 canonical tools — including `runtime_identity` and `workspace_info` — may be named in `disabledTools`; there is no product-mandatory tool. Disabling the mutation family is the canonical read-only pattern:

```jsonc
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

Three static rules keep a policy internally consistent, checked identically by `config validate` and MCP startup:

1. If `begin_change` is disabled, all five downstream lifecycle tools (`submit_edit`, `validate_change`, `change_status`, `complete_change`, `abort_change`) must also be disabled.
2. If `complete_change` is enabled, both `begin_change` and `validate_change` must be enabled.
3. If `submit_edit` is enabled, `begin_change`, `validate_change`, and `complete_change` must all be enabled — `submit_edit` is the file-mutating capability, and Corulix refuses to expose a mutation with no visible, governed path to validated completion.

An unknown tool name, a duplicate entry, or a violation of any rule above is rejected with a specific, typed reason — never silently normalized.

## 5. Authority model

Three structurally separate domains, never collapsed into one:

| Domain                                                   | Scope                    | Can it elevate privilege?                                                                                    |
| -------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `HostConfig` (`--host-config`, TOML, host/operator-only) | Machine/operator         | Sets the ceiling; nothing below it can raise it                                                              |
| `WhaTalker_Corulix_JSON_Config.json`                     | This workspace           | **Never** — every `HostConfig` field is structurally absent from this schema, not merely rejected at runtime |
| `AGENTS.md` / `CLAUDE.md`                                | Human/agent-facing prose | **Never** — never deserialized by any code path into runtime authority                                       |

## 6. CLI reference

```sh
corulix config validate  [--workspace PATH | --workspace-file FILE]
corulix config inspect   [--workspace PATH | --workspace-file FILE] [--workspace-root ROOT]
corulix config schema
```

All three commands are zero-mutation: they open no engine, start no MCP server, and provision nothing.

- **`config validate`** — loads and fully validates the resolved workspace's own config file (structural shape, duplicate/unknown-field rejection, root binding, semantic tool-policy rules) — the exact same path `corulix mcp stdio` uses at startup. Prints `WORKSPACE_CONFIG_STATUS=OK|FAILED` plus a JSON summary on success.
- **`config inspect`** — reports the resolved effective configuration: canonical/effective tool counts, the specific disabled tool names, workspace-wide default disabled categories, and the configured root-override count. With `--workspace-root <ROOT>`, additionally reports that one root's own effective disabled categories (the union described in §3). This remains available as a local diagnostic surface even when `workspace_info`'s own MCP tool is disabled by the active policy.
- **`config schema`** — emits the canonical JSON Schema described in §3. Performs no workspace resolution.

Exit codes: `0` valid (including a genuinely absent config file); `3` the workspace itself could not be resolved; `9` (`WORKSPACE_CONFIG_FAILURE`) the config file exists but is malformed, structurally invalid, or fails semantic tool-policy validation.

## 7. Worked examples

**Minimal — no config file at all.** `corulix config validate` reports `WORKSPACE_CONFIG_STATUS=OK` with `effective_visible_tool_count: 14` and `tool_policy_configured: false` — byte-for-byte Corulix 1.0.0 behavior.

**Read-only workspace, formatter disabled everywhere:**

```jsonc
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
  "defaults": { "disabledCategories": ["FORMATTER"] }
}
```

**Multi-root workspace, one root additionally excluded from linting:**

```jsonc
{
  "configName": "WhaTalker Corulix JSON Config",
  "schemaVersion": 1,
  "defaults": { "disabledCategories": ["FORMATTER"] },
  "rootOverrides": [
    { "root": "wht_backend", "disabledCategories": ["FORMATTER", "LINTER"] }
  ]
}
```

`wht_backend`'s own effective disabled set is `{FORMATTER, LINTER}` (the union); every other root's is `{FORMATTER}` alone.

**Invalid — rooted/absolute locator (rejected on every host OS, including Linux and Windows x64, verified against the current certified binaries):**

```jsonc
{
  "configName": "WhaTalker Corulix JSON Config",
  "schemaVersion": 1,
  "rootOverrides": [
    { "root": "C:\\Windows\\System32", "disabledCategories": ["FORMATTER"] }
  ]
}
```

`corulix config validate` rejects this with `WORKSPACE_CONFIG_FAILURE` (exit `9`) and `REASON=rootOverrides[].root is invalid: must not be an absolute or rooted path (POSIX absolute, Windows drive-absolute/drive-relative, or UNC/device-namespace syntax)` — the same syntactic rejection stage on Linux x64 and Windows x64 alike, independent of which host actually runs the parser. A POSIX form (`/etc/passwd`), a bare Windows-rooted form (`\foo`), a UNC form (`\\server\share`), and a Windows drive-relative form (`C:foo`) are all rejected the same way.

## 8. Security notes

- Fixed-location reads use a pinned, single-open-handle, symlink-safe primitive (`wht_corulix_workspace::confined_read_optional`) — never a second, weaker read path.
- The file is bounded to 64 KiB before any parse is attempted.
- Parsing is direct-to-struct at every level (never through a `serde_json::Value`/map intermediate), which is what makes a duplicate JSON key a hard parse error rather than a silent last-value-wins.
- A parent-relative (`..`) root locator is accepted syntactically (matching what real `.code-workspace` descriptors already permit) but can only ever bind to a path that canonicalizes to an already-authorized member root of the live workspace — it can never widen confinement.
