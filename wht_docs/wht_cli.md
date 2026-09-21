# `corulix` CLI Reference

This document summarizes the `corulix` command-line contract for human
readers. It is **not** the parser specification: the executable authority for
command names, options, mutual exclusions, and help text is the `clap`
derive command model in `wht_crates/wht_corulix_cli/src/cli.rs`
(Architecture Rule I). If this document and the running binary's own
`--help` output ever disagree, the binary is correct and this document is
stale.

## Command hierarchy

```text
corulix --help | -h | --version
corulix help [COMMAND...]

corulix toolchain status   [--workspace PATH | --workspace-file FILE]
corulix languages list     [--workspace PATH | --workspace-file FILE]
corulix workspace detect   [--workspace PATH | --workspace-file FILE]
corulix workspace inspect  [--workspace PATH | --workspace-file FILE] [--workspace-root ROOT]
corulix parse <FILE>       [--workspace PATH | --workspace-file FILE] [--workspace-root ROOT]
corulix mcp stdio          [--workspace PATH | --workspace-file FILE]
corulix setup              [--profile full|on-demand] [--only GROUP...] [--exclude GROUP...]
```

There are no positional workspace arguments and no legacy aliases (`doctor`,
`languages <workspace>`, `workspace inspect <workspace>`, `parse <workspace>
<file>`, `mcp stdio <workspace>` are all removed, not deprecated-and-kept).

## Workspace modes

Corulix binds exactly one logical workspace per process for the process's
entire lifetime:

- **Single-root** -- `--workspace <DIRECTORY>`: one filesystem directory.
- **Multi-root** -- `--workspace-file <FILE.code-workspace>`: several
  directories imported from one VS Code multi-root workspace file. This is
  still one Corulix workspace context with several member roots, never
  several independent sessions.

`--workspace` and `--workspace-file` are mutually exclusive (enforced by
`clap`, not just documented).

Root-scoped commands (`parse`, and `workspace inspect` for single-root
detail) accept `--workspace-root <ROOT>` to select one member root by
display name or opaque numeric ID when the workspace is multi-root. A
single-root workspace ignores this flag. There is no "try every root and use
the first match" behavior anywhere.

## Workspace resolution precedence

1. explicit `--workspace-file`
2. explicit `--workspace`
3. environment configuration (`CORULIX_WORKSPACE` / `CORULIX_WORKSPACE_FILE`
   -- both present is a fail-closed, ambiguous configuration error)
4. bounded, cwd-seeded discovery (a `.code-workspace` file takes precedence
   over an ordinary project marker at the same ancestor directory level)
5. fail closed

An explicit, authoritative source (a flag or an environment variable) that
does not resolve to a valid location is a terminal failure -- it is never
silently downgraded to a lower-precedence source. The current directory is
only ever a discovery seed; it is never itself treated as a valid workspace
merely because it exists.

An **automatically discovered** `.code-workspace` that references a location
outside its own containing directory is not bound automatically: Corulix
reports that explicit selection (`--workspace-file`) is required. An
**explicitly selected** `--workspace-file`/`CORULIX_WORKSPACE_FILE` carries
no such restriction, since the operator already authorized that topology.

## `.code-workspace` security

Corulix reads only `folders[].path` and `folders[].name` from a
`.code-workspace` file. Its `settings`/`tasks`/`launch`/`extensions` sections
(and any other top-level key) carry zero Corulix security or execution
authority: a workspace file cannot mark itself trusted, disable
confinement, select provider binaries, or otherwise change Corulix's
security policy. Workspace roots are `Untrusted` by default regardless of
source; validity is not trust.

## `setup` -- managed-toolchain install profile

`corulix setup` is a host/operator maintenance command, not an MCP tool: no
MCP request, workspace, or repository content can trigger or influence it.
It has no workspace concept -- it acts on this host's shared managed-toolchain
root.

- No flags: bootstraps the persisted install profile to `full` if none has
  ever been chosen on this host, or leaves an existing explicit choice
  untouched, then reconciles toward whatever profile results.
- `--profile full`: persists `FULL` (every applicable managed component
  granted intent) and reconciles the complete set now, overwriting any
  prior explicit choice.
- `--profile on-demand`: persists `ON_DEMAND` (nothing acquired eagerly;
  each component is acquired lazily the first time a real operation needs
  it). No reconciliation runs.
- `--only <GROUP>[,<GROUP>...]`: persists a `SELECTIVE` profile -- the
  named groups' components plus their mandatory dependencies, expanded and
  reconciled now. Repeatable or comma-delimited.
- `--exclude <GROUP>[,<GROUP>...]`: without `--only`, starts from the full
  set and removes the named groups' own component ids (wherever they were
  contributed from); a component still needed by a surviving component is
  never stranded.
- `--only` and `--exclude` together: the named `--only` groups minus the
  named `--exclude` groups' component ids.

Canonical groups: `rust`, `go`, `typescript` (synonym for `typescript7`),
`typescript6`, `javascript`, `biome`, `python`.

Rejected up front, before any persistence or reconciliation (so a rejected
invocation never leaves partial state): `--profile on-demand` combined with
`--only`/`--exclude`; the same group named in both `--only` and
`--exclude`; an unrecognized group name.

## Environment variables

| Variable                 | Meaning                                                      |
| ------------------------ | ------------------------------------------------------------ |
| `CORULIX_WORKSPACE`      | Single-root workspace directory for this terminal/session.   |
| `CORULIX_WORKSPACE_FILE` | Multi-root `.code-workspace` file for this terminal/session. |

Both configure processes started from that shell session only; Corulix
cannot modify the calling shell's environment.

## Exit codes

| Code | Meaning                                                             |
| ---: | ------------------------------------------------------------------- |
|    0 | success, help, or version                                           |
|    2 | CLI usage/parser error (unrecognized command or option)             |
|    3 | workspace resolution or selection failure                           |
|    4 | operational failure: request denied by workspace confinement        |
|    5 | operational failure: unsupported input or a size limit was exceeded |
|    6 | `mcp stdio --host-config` could not be loaded                       |
|    7 | `setup` rejected a flag conflict or unrecognized group name          |
|    8 | `setup` reconciliation completed but left a component not ready     |
|    1 | any other internal failure                                          |

## Stdout/stderr discipline

Normal, successful human-facing command output is written to stdout; errors
and diagnostics are written to stderr. Once `mcp stdio` starts, stdout is
reserved exclusively for the MCP protocol stream -- no diagnostic, log, or
help text is written to stdout after that point, and requesting `--help` on
`mcp stdio` terminates before the MCP session starts.

## Help

`--help`/`-h`/`help` and their nested per-command forms are all rendered
directly from the `clap` command model and are side-effect free: they never
resolve a workspace, parse a `.code-workspace` descriptor, construct the
engine, or start an MCP session, even when `CORULIX_WORKSPACE`/
`CORULIX_WORKSPACE_FILE` are set to an invalid value.
