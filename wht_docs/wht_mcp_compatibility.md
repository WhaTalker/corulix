# MCP Compatibility

## MCP tool surface baseline (established 1.0.0, unchanged in 1.1.0)

```text
SDK:                rmcp 3.0.1
Reviewed MCP line:  2026-07-28
Transport:          stdio
Public tools:       14
```

MCP implementation details are confined to `wht_corulix_mcp` and delegated into Corulix-owned engine/domain contracts.

## Transport contract

- `stdin` carries MCP protocol input.
- `stdout` is reserved for MCP protocol output once the server starts.
- `stderr` carries diagnostics and operational logging.
- Network MCP transports are not part of the baseline (stdio only, unchanged in 1.1.0).

## Public tool surface

Corulix exposes exactly (unchanged since 1.0.0):

| Tool | Category |
| --- | --- |
| `runtime_identity` | runtime inspection |
| `workspace_info` | workspace inspection |
| `toolchain_status` | provider/toolchain inspection |
| `plan_operation` | policy/planning |
| `search` | textual discovery |
| `parse_file` | structural parsing |
| `semantic` | semantic discovery/diagnostics/rename preview |
| `format_preview` | non-mutating formatting preview |
| `begin_change` | change-session lifecycle |
| `submit_edit` | governed mutation |
| `validate_change` | governed validation |
| `change_status` | change-session inspection |
| `complete_change` | change-session lifecycle |
| `abort_change` | change-session lifecycle |

Runtime MCP discovery remains the executable authority for exact schemas.

## Workspace binding

One server invocation binds one logical workspace context. It may be:

- a single root selected with `--workspace`; or
- a VS Code multi-root descriptor selected with `--workspace-file`.

Workspace inputs remain subject to canonicalized confinement and root-selection rules.

## Client expectations

Clients should expect:

- strict typed inputs with unknown/unadmitted fields rejected by the schema layer;
- typed tool errors instead of raw internal stack traces;
- workspace-boundary enforcement for file operations;
- explicit unavailable/denied results when provider/trust/platform authority is missing;
- no diagnostic text mixed into stdout's MCP protocol stream;
- no requirement that every available tool be used for every task.

## Mutation model

Mutation-capable operations are not ambient file writes. They participate in the governed `ChangeSession` contract:

```text
begin_change -> submit_edit -> validate_change -> complete_change
                                     └──────────-> abort_change
```

`change_status` may inspect session state during the lifecycle. `format_preview` itself does not mutate live source.

## Compatibility changes

Changes to public tool names or schemas are versioned product changes. No publication may add, remove, or silently rename any of the 14 tools above.
