// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! Centralized long-form help text for the `corulix` CLI.
//!
//! These are plain string constants consumed by `cli.rs`'s clap command
//! model (`long_about`/`after_help`) -- they do not define command syntax
//! themselves (that stays exclusively in the clap derive model in `cli.rs`,
//! Architecture Rule I), only prose. Every command, flag, and environment
//! variable named below must exist in the real parser; `POST_EDIT_RG_AUDIT`
//! and the CLI test suite both check this.
//!
//! Side-effect discipline: nothing in this module performs I/O. It is pure
//! string data, rendered by clap only when `--help`/`-h`/`help` is actually
//! requested, before any workspace resolution or engine construction.

pub const TOP_LEVEL_LONG_ABOUT: &str = "\
WhaTalker Corulix is an enterprise code-intelligence and governance CLI and \
MCP server: workspace-aware parsing, structural inspection, and toolchain \
diagnostics for AI agents and human engineers alike.

WORKSPACE MODEL
  Corulix binds exactly one logical workspace per process for the whole \
process lifetime. That workspace is either:
    Single-root  -- one filesystem directory (--workspace <DIRECTORY>)
    Multi-root   -- multiple directories imported from one VS Code \
`.code-workspace` file (--workspace-file <FILE>)
  A multi-root `.code-workspace` describes ONE workspace with several \
member roots -- it never starts several independent Corulix sessions.

WORKSPACE SELECTION (highest precedence first)
  1. --workspace-file <FILE.code-workspace>
  2. --workspace <DIRECTORY>
  3. CORULIX_WORKSPACE / CORULIX_WORKSPACE_FILE (terminal environment)
  4. automatic discovery, seeded from the current directory
  --workspace and --workspace-file are mutually exclusive.

TERMINAL SESSION CONFIGURATION
  export CORULIX_WORKSPACE=/path/to/project
  export CORULIX_WORKSPACE_FILE=/path/to/Project.code-workspace
  These only configure Corulix processes started from that shell session; \
Corulix cannot modify your shell's environment.

DISCOVERY
  When no explicit or environment source is given, Corulix walks upward \
from the current directory (a bounded number of levels) looking first for \
a `.code-workspace` file, then for an ordinary project marker \
(Cargo.toml, package.json, pyproject.toml, go.mod, .git, and similar). The \
current directory is only ever a discovery seed -- it is never itself \
treated as a valid workspace merely because it exists.

SECURITY
  - Workspace resolution fails closed: an explicit --workspace/--workspace-file \
(or its environment-variable equivalent) that does not resolve to a valid \
location is a hard error, never silently downgraded to a lower-precedence \
source.
  - Workspace roots are UNTRUSTED by default. Validity is not trust.
  - `.code-workspace` files are read only for their folder topology. \
Corulix never executes or trusts their `settings`/`tasks`/`launch`/ \
`extensions` sections, and such a file cannot elevate its own trust or \
weaken Corulix's security policy.
  - An automatically discovered `.code-workspace` that references a \
location outside its own directory is not bound automatically; rerun with \
--workspace-file to select it explicitly if that is intentional.

MULTI-ROOT ADDRESSING
  Operations that target one specific file (e.g. `parse`) require \
--workspace-root <ROOT> whenever the workspace has more than one root -- \
the same relative path could otherwise exist in more than one root, and \
Corulix never guesses which one you mean.

EXIT CODES
  0  success, help, or version
  2  CLI usage/parser error (unrecognized command or option)
  3  workspace resolution or selection failure
  4  operational failure: request denied by workspace confinement
  5  operational failure: unsupported input or size limit exceeded
  6  --host-config could not be loaded (see `corulix help mcp stdio`)
  7  `setup` rejected a flag conflict or unrecognized group name
  8  `setup` reconciliation completed but left a component not ready
  1  any other internal failure

Run `corulix help <COMMAND>` or `corulix <COMMAND> --help` for details on a \
specific command.";

pub const TOOLCHAIN_LONG_ABOUT: &str = "\
Diagnose the toolchain/runtime available to Corulix in the active workspace.

Reports Corulix's own build/version fingerprint and pinned component \
versions. This is the current, truthful subset of toolchain information \
available at this stage of Corulix's development -- it does not yet report \
per-language provider (formatter/linter/build-tool) availability; that is a \
later capability.";

pub const TOOLCHAIN_STATUS_LONG_ABOUT: &str = "\
Print Corulix's runtime identity and pinned component versions for the \
active workspace.

Resolves the workspace using the canonical precedence (see `corulix --help`), \
then reports product/version/toolchain metadata. Fails closed with exit \
code 3 if the workspace cannot be resolved.

EXAMPLE
  corulix toolchain status --workspace ./project";

pub const LANGUAGES_LONG_ABOUT: &str = "\
Inspect Corulix's supported languages and their structural (Tree-sitter/syntax) \
capabilities.

Lists every language Corulix currently has a structural grammar adapter for, \
independent of any one workspace's actual contents. This reports structural/syntax \
capability only -- it does not report semantic capability (definitions, \
references, rename), which is provided by a separate, not-yet-implemented \
provider.";

pub const LANGUAGES_LIST_LONG_ABOUT: &str = "\
List every language Corulix currently supports structurally, with its pinned \
Tree-sitter grammar package and version.

Resolves the workspace using the canonical precedence, but the reported \
list itself is not workspace-specific -- it reflects Corulix's own build.

EXAMPLE
  corulix languages list --workspace ./project";

pub const WORKSPACE_LONG_ABOUT: &str = "\
Detect and inspect the active Corulix workspace context.

Corulix supports two workspace topologies:
  Single-root: one directory (--workspace <DIRECTORY>).
  Multi-root:  several directories imported from one VS Code \
`.code-workspace` file (--workspace-file <FILE>), addressed via \
--workspace-root <ROOT> where an operation must target one specific root.

`.code-workspace` files are trusted ONLY for their folder topology \
(`folders[].path`/`folders[].name`). Their `settings`/`tasks`/`launch`/ \
`extensions` sections carry zero Corulix security or execution authority.

See `corulix help workspace detect` and `corulix help workspace inspect` \
for the two workspace subcommands.";

pub const WORKSPACE_DETECT_LONG_ABOUT: &str = "\
Report how Corulix would resolve the active workspace, without opening it.

Detection is diagnostic only: it does NOT imply trust, does not execute any \
`.code-workspace` configuration, and does not recursively scan the \
filesystem beyond the bounded discovery walk described in `corulix --help`.

If an automatically discovered `.code-workspace` references a location \
outside its own directory, `detect` reports that explicit selection is \
required (via --workspace-file) rather than silently widening scope. \
Multiple equally-authoritative `.code-workspace` candidates at the same \
directory level are reported as ambiguous, never resolved by picking the \
first one found.

EXAMPLES
  corulix workspace detect
  corulix workspace detect --workspace-file ./Project.code-workspace";

pub const WORKSPACE_INSPECT_LONG_ABOUT: &str = "\
Report the resolved logical workspace context: single- or multi-root \
topology, and (for multi-root) each member root's opaque ID and safe \
display name.

This does not grant or imply trust, and it never prints a raw canonical \
absolute path -- only redacted, display-safe metadata. Pass \
--workspace-root to inspect one specific member root instead of the whole \
topology.

EXAMPLES
  corulix workspace inspect --workspace ./project
  corulix workspace inspect --workspace-file ./Project.code-workspace
  corulix workspace inspect --workspace-file ./Project.code-workspace --workspace-root api";

pub const PARSE_LONG_ABOUT: &str = "\
Parse one workspace-relative source file and report its structural summary.

FILE is always workspace-relative -- an absolute path is rejected by \
workspace confinement (exit code 4), and confinement is enforced against \
whichever member root is selected (or the sole root, in a single-root \
workspace).

In a multi-root workspace, --workspace-root is required whenever the \
target file could exist under more than one root; Corulix never guesses \
which root you mean.

EXAMPLES
  corulix parse src/main.rs --workspace ./project
  corulix parse src/main.rs --workspace-file ./Project.code-workspace --workspace-root api";

pub const MCP_LONG_ABOUT: &str = "\
Model Context Protocol transports.

See `corulix help mcp stdio` for the stdio transport.";

pub const MCP_STDIO_LONG_ABOUT: &str = "\
Serve the Model Context Protocol over stdio for the active workspace.

Workspace resolution happens exactly once, before the MCP session starts; \
the bound workspace does not change for the process's lifetime. Once the \
MCP session starts, stdout is reserved exclusively for MCP protocol \
frames -- no diagnostic, log, or help text is written to stdout after that \
point. Requesting `--help` on this command terminates before the MCP \
session starts, exactly as for every other command.

HOST CONFIGURATION (--host-config)
  --host-config <ABSOLUTE_FILE> optionally names a TOML file the host/ \
operator authors to grant this one process a wider provider-resolution \
envelope than the safe default: an approved system/user-toolchain \
directory list, an explicit absolute path for one provider category, and \
(only when the file explicitly opts in) authorization to execute trusted \
workspace code.
  By default (DEFAULT_INSTALL_PROFILE=FULL), this process reconciles every \
supported CORULIX_MANAGED component on first run and real network-triggered \
acquisition needs no host-config at all -- `managed_provisioning_policy` \
lets an operator override that default explicitly: DENY is an unconditional \
veto no install profile can override, ALLOW unconditionally permits \
acquisition regardless of profile state, and the default, INHERIT, defers \
entirely to the persisted install profile (see `corulix setup --help`).
  Omitting this flag is safe and unchanged for every other field: the \
process behaves exactly as it always has (no approved provider directories \
or paths, no trusted workspace execution) except that managed acquisition \
now follows the persisted install profile by default, per the product's own \
installation contract.
  This is a host/operator-only decision, made once at process launch. No \
MCP request, no `.code-workspace` file, and no repository content can ever \
grant, widen, or substitute for it -- there is no path from any of those \
three sources to this configuration, by construction. Ambient PATH is \
never consulted for provider resolution regardless of this flag.
  The path must be absolute and must not resolve inside the workspace this \
process is about to serve (a host-config file living inside the very \
workspace it configures is rejected outright). A relative path, a \
nonexistent or unreadable file, malformed content, an unknown field, or an \
unrecognized value is a hard error (exit code 6) -- this process never \
starts an MCP session on a host configuration it could only partially \
understand.

EXAMPLES
  corulix mcp stdio --workspace ./project
  corulix mcp stdio --workspace-file ./Project.code-workspace
  corulix mcp stdio --workspace ./project --host-config /etc/corulix/host.toml";

pub const SETUP_LONG_ABOUT: &str = "\
Bootstrap or change this host's persisted managed-toolchain install profile, \
and converge the managed root toward it.

This is a host/operator-only maintenance command -- it is not an MCP tool, \
and no MCP request, workspace file, or repository content can trigger it. \
It has no workspace concept: it acts on this host's shared managed-toolchain \
root, independent of any project.

INSTALL GROUPS
  rust, go, typescript (= typescript7), typescript6, javascript, biome, python
  Each group names a user-facing bundle of managed components plus their \
mandatory dependencies -- never a raw component id.

INVOCATIONS
  corulix setup
    No flags: bootstraps to `full` if no profile has ever been persisted on \
this host, or leaves an existing explicit choice untouched, then reconciles \
toward whatever profile results.
  corulix setup --profile full
    Persists FULL (every applicable component granted intent) and reconciles \
the complete set now, overwriting any prior explicit choice.
  corulix setup --profile on-demand
    Persists ON_DEMAND (nothing acquired eagerly; components are acquired \
lazily on first real use). No reconciliation runs.
  corulix setup --only <GROUP>[,<GROUP>...]
    Persists a SELECTIVE profile: the named groups' components plus their \
mandatory dependencies, expanded and reconciled now. Repeatable \
(--only rust --only python) or comma-delimited (--only rust,python).
  corulix setup --exclude <GROUP>[,<GROUP>...]
    Without --only, starts from the full set and removes the named groups' \
own component ids -- wherever those exact ids also appear (e.g. `biome` is \
both its own group and part of `javascript`; excluding either removes it \
everywhere it was kept). A component still needed transitively by a \
surviving component (e.g. node-runtime, shared by typescript6 and python) is \
never stranded: it is dropped only once nothing kept still depends on it.
  corulix setup --only <GROUPS> --exclude <GROUPS>
    Combines both: the named --only groups minus the named --exclude groups' \
component ids, under the same rule.

FLAG CONFLICTS (rejected before any persistence or reconciliation)
  - --profile on-demand combined with --only or --exclude: on-demand selects \
nothing eagerly, so naming groups to install now is contradictory.
  - The same group named in both --only and --exclude.
  - An unrecognized group name (see INSTALL GROUPS above for the exact list).

EXIT CODES
  0  the persisted profile's desired set reconciled to fully ready \
(or --profile on-demand persisted with nothing to reconcile)
  1  internal failure (managed root unresolvable, profile persistence failed)
  7  a flag conflict or unrecognized group name was rejected
  8  reconciliation completed but left one or more components not ready

EXAMPLES
  corulix setup
  corulix setup --profile on-demand
  corulix setup --only rust,python
  corulix setup --exclude go";
