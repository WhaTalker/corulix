#!/usr/bin/env python3
"""
WhaTalker Corulix -- Architecture Boundary Validator

Copyright (c) 2026 WhaTalker Inc.
SPDX-License-Identifier: AGPL-3.0-only

Fail-closed check that the Corulix crate dependency graph never violates
its intended layering:

  * wht_corulix_core must never depend on, or reference in source, the MCP
    layer (rmcp / wht_corulix_mcp) -- core stays protocol-agnostic.
  * wht_corulix_mcp must never depend on, or reference in source, any
    Tree-sitter grammar directly -- it only talks to the engine/index
    layers, never parses source itself. It must also never write to stdout
    directly with println!/print! -- the MCP protocol stream goes through
    `rmcp`'s own stdio transport, never a raw print macro, so any such
    write in this crate specifically would risk corrupting a live session.
    (wht_corulix_cli is intentionally exempt from this stdout ban -- see
    Rule I below; ordinary human-facing command output belongs on stdout,
    with errors/diagnostics on stderr, and stdout is reserved exclusively
    for the MCP protocol stream only once `mcp stdio` itself starts.)
  * Rule I -- enterprise CLI authority: only the `clap` derive command
    model in wht_corulix_cli::cli defines the public CLI grammar. No manual
    `env::args()` dispatch tree, no parallel/hand-written help implementation,
    and no legacy command aliases.
  * Rule F -- workspace security ownership: only wht_corulix_workspace may
    implement filesystem canonicalization. No other crate may depend on it
    for anything but the sanctioned direction (workspace -> core only), and
    no other crate's source may contain a `canonicalize(` call -- that
    implementation lives in exactly one place.
  * Rule D -- embedded search isolation: only wht_corulix_search may depend
    on the ripgrep-family crates (`ignore`, `grep-matcher`, `grep-regex`,
    `grep-searcher`). No external `rg`/shell process may ever be spawned to
    perform a search (no `Command::new(` anywhere in wht_corulix_search),
    and wht_corulix_search must never construct its own independent
    filesystem walker (`ignore::WalkBuilder`) or its own canonicalization --
    both remain wht_corulix_workspace's exclusively under Rule F, unchanged
    by Search's existence.
  * Rule C -- syntax isolation (`RULE_C_SYNTAX_ISOLATION`): only
    wht_corulix_syntax may depend on, or reference in source, Tree-sitter
    (the runtime crate or any grammar crate). Structural/syntax
    intelligence is that crate's authority alone; it has no authority over
    text search, semantic definitions/references/rename, formatting,
    linting, typechecking, tests, workspace discovery, filesystem
    confinement, or policy/gate derivation -- those belong respectively to
    Search, a future LSP provider, a future tooling provider, Workspace,
    and Engine.
  * Rule H -- Engine policy authority (`RULE_H_ENGINE_AUTHORITY`): only
    wht_corulix_engine may derive a `RiskClass`, a `ToolPlan`, provider
    applicability/authority, or a required-gate list for a concrete
    operation. No other crate may construct a `ToolPlan { ... }` literal,
    reference the `PolicyEntry` policy-table type, or define a
    `policy_entry`/`derive_risk_class` function -- CLI, MCP, Search,
    Syntax, and Workspace consume a `ToolPlan` `wht_corulix_engine` handed
    them; none of them computes one independently.
  * Rule G -- process construction authority (`RULE_G_PROCESS_CONSTRUCTION`):
    only wht_corulix_tooling may construct an external process. No other
    crate's source may contain `std::process::Command`, `Command::new(`,
    or `tokio::process::Command` -- Search/Syntax's own in-process
    behavior is unaffected (neither ever needed process construction in
    the first place), and no crate may resolve *which* provider binary to
    run (that remains a later phase's responsibility); Tooling only
    executes an already-selected, already-typed `ProcessSpec` it is
    handed.
  * Rule J -- async runtime authority (`RULE_J_ASYNC_RUNTIME`): Tokio is
    the single canonical async runtime, owned at the top level exclusively
    by the `wht_corulix_cli` binary's `#[tokio::main]`. No library crate
    (every crate except the CLI binary) may construct a second, nested
    runtime (`tokio::runtime::Runtime`/`tokio::runtime::Builder`/
    `Runtime::new(`/its own `#[tokio::main]`), and no library crate may call
    `.block_on(` to bridge back into synchronous code from inside an
    already-async context. `wht_corulix_tooling`'s canonical process
    execution entry point must remain `pub async fn execute` -- never a
    synchronous `pub fn execute` reintroduced alongside or instead of it.
  * Rule N -- formatter governance authority (`RULE_N_FORMATTER_GOVERNANCE`,
    Phase 9): only wht_corulix_formatter owns Rust formatter (rustfmt)
    governance. `RUSTFMT_FORMATTING_AUTHORITY=YES`,
    `LSP_FORMATTING_AUTHORITY=NO`: wht_corulix_lsp must never implement or
    claim `textDocument/formatting` as authoritative. rustfmt is executed
    only through wht_corulix_tooling (Rule G is unaffected -- Formatter is
    simply added to that rule's own scanned-crate list, proving it never
    constructs a process directly either), and every live-workspace write
    this crate produces goes exclusively through
    wht_corulix_mutation::MutationExecutor (Rule M is unaffected --
    Formatter is added to that rule's scanned-crate list too, proving its
    own production code never calls a filesystem-write primitive directly).
    No public blocking formatter operational API is ever exposed (Rule J's
    own `pub fn *_blocking` ban is extended to this crate).
  * Rule R -- ChangeSession format-write state atomicity
    (`RULE_R_CHANGESESSION_FORMAT_STATE_ATOMICITY`, Phase 10-R2): a
    governed format write and `ChangeSession`'s own current-state
    advancement must remain one inseparable operation.
    `wht_corulix_engine::session::ChangeSession::format_and_apply` is the
    sole call site, across the entire first-party workspace, permitted to
    reach the raw `wht_corulix_formatter::format_and_apply` free function
    -- no other crate's production source may call it directly (a
    `session.format_and_apply(...)` *method* call from elsewhere is the
    sanctioned pattern and is never flagged).
  * Rule S -- canonical MCP surface (`RULE_S_MCP_CANONICAL_SURFACE`, Phase
    13): `wht_corulix_mcp` exposes exactly 14 typed tools and stays a thin
    adapter over `wht_corulix_core`/`wht_corulix_engine` only (sharpening
    Rule B into its own checked letter). Its production dependency graph
    (checked against its manifest, never its `[dev-dependencies]`, which
    legitimately carries a test-only `wht_corulix_workspace` fixture
    dependency) may never widen; no legacy `-> String` ad-hoc-JSON tool
    response shape may reappear; it may never construct a process directly
    (Rule G), never write to the workspace directly (Rule M), and never
    depend on or reference Search/LSP/Tooling/Formatter/Mutation directly
    -- every one of those is reachable only through
    `wht_corulix_engine`'s own public API. No MCP Roots capability and no
    MCP protocol Logging capability usage is permitted anywhere in this
    crate.

  * Rule U -- Go provider boundary (`RULE_U_GO_PROVIDER_BOUNDARY`, Phase
    15): the Go vertical is routed through existing machinery, never
    reimplemented beside it. `wht_corulix_engine`'s `go_providers`/
    `go_validation`/`go_testing` modules must construct no process
    themselves (Rule G), must spawn only through
    `wht_corulix_tooling::execute`, must reuse the one shared
    `authorize_trusted_execution` trust gate rather than deriving a second,
    must resolve providers only through `wht_corulix_config::resolve_provider`
    (Rule K) and never inspect ambient `PATH` or an approved-directory list
    themselves, and must contain no LSP protocol detail (Rule L). The Go
    environment's load-bearing security controls (`GOTOOLCHAIN=local`,
    `GOPROXY=off`, `GOFLAGS=-mod=readonly`) may not be dropped or relaxed to
    `-mod=mod`; `go build`'s output must stay redirected off the governed
    workspace; the formatter crate may never reference an in-place write
    flag (`-w`/`--write`/`--in-place`), since only `wht_corulix_mutation`
    holds live-write authority (Rules N/M); `wht_corulix_mcp`'s production
    source may never name a Go provider or entry point (Rules S/B); and no
    Go force/skip/fake test seam may exist anywhere. Rule U.11 (P15
    production-routing regression closure): `validate_change.rs`'s
    production dispatch path must genuinely call
    `go_validation::run_go_validator`/`go_testing::run_go_test` and must
    branch on `ChangeSession::language()` -- the Go validators must have a
    real Engine route, never merely exist as reachable-only-from-tests
    modules.

Usage: python3 wht_scripts/wht_verify_architecture.py   (from the repository root)
Exit status: 0 on PASS, 1 on FAIL (with each violation printed).
"""

from pathlib import Path
import re
import sys
import tomllib

# Step 1: Resolve the repository root relative to this script's own
# location, so this check works regardless of the caller's cwd.
ROOT = Path(__file__).resolve().parents[1]
failures: list[str] = []


def manifest(crate: str) -> dict:
    """Step 2 helper: load one crate's Cargo.toml as a plain dict."""
    path = ROOT / "wht_crates" / crate / "Cargo.toml"
    with path.open("rb") as handle:
        return tomllib.load(handle)


def dependency_names(crate: str) -> set[str]:
    """Step 2 helper: the set of direct [dependencies] names for a crate."""
    return set(manifest(crate).get("dependencies", {}))


# Step 3: Check the manifest-level dependency direction for core and mcp.
core_deps = dependency_names("wht_corulix_core")

for forbidden in {"rmcp", "wht_corulix_mcp"}:
    if forbidden in core_deps:
        failures.append(f"wht_corulix_core has forbidden dependency: {forbidden}")

# Rule C (RULE_C_SYNTAX_ISOLATION): only wht_corulix_syntax may depend on
# Tree-sitter or any grammar crate. Checked across every other crate in the
# workspace, not just wht_corulix_mcp -- structural/syntax intelligence is
# wht_corulix_syntax's authority alone.
TREE_SITTER_CRATES = {
    "tree-sitter",
    "tree-sitter-javascript",
    "tree-sitter-typescript",
    "tree-sitter-python",
    "tree-sitter-rust",
    "tree-sitter-go",
}
for crate in (
    "wht_corulix_core",
    "wht_corulix_workspace",
    "wht_corulix_search",
    "wht_corulix_index",
    "wht_corulix_config",
    "wht_corulix_lsp",
    "wht_corulix_engine",
    "wht_corulix_mcp",
    "wht_corulix_cli",
):
    overlap = TREE_SITTER_CRATES & dependency_names(crate)
    for forbidden in sorted(overlap):
        failures.append(
            f"{crate} has forbidden dependency: {forbidden} (Architecture Rule C violation)"
        )


def scan(crate: str, forbidden_tokens: tuple[str, ...]) -> None:
    """Step 4 helper: source-level defense in depth -- catches a forbidden
    reference even if it somehow bypassed the manifest-level check above
    (e.g. via a transitive re-export).

    Production source only: a file's own `#[cfg(test)] mod tests { ... }`
    block (the same convention Step 20 already applies to
    `wht_corulix_mcp/src/lib.rs` specifically) legitimately builds
    disposable test fixtures/diagnostics -- that is test-only setup, never
    a production bypass, so it is excluded here too, consistently, rather
    than each call site re-deriving its own ad hoc production/test split.
    A bare `println!(`/`print!(` check also must not false-positive on
    `eprintln!(`/`eprint!(` (stderr, never the MCP stdio protocol stream
    this rule protects) -- matched only when not immediately preceded by
    `e`.
    """
    src = ROOT / "wht_crates" / crate / "src"
    test_marker = "#[cfg(test)]"
    for path in src.rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        production_text = text.split(test_marker, 1)[0]
        for token in forbidden_tokens:
            if token in ("println!(", "print!("):
                e_variant = f"e{token}"
                stripped = production_text.replace(e_variant, "")
                if token in stripped:
                    failures.append(
                        f"{path.relative_to(ROOT)} contains forbidden token {token!r}"
                    )
            elif token in production_text:
                failures.append(
                    f"{path.relative_to(ROOT)} contains forbidden token {token!r}"
                )


def production_source_excluding_cfg_test(text: str) -> str:
    """M09-P6VR structural replacement for the truncating idiom
    `text.split("#[cfg(test)]", 1)[0]` (proven, in the M09-P6V audit, to
    silently hide real production code that happens to appear physically
    AFTER an early `#[cfg(test)]` item in the same file -- a synthetic
    production `Command::new(...).spawn()` appended after
    `wht_corulix_engine/src/lib.rs`'s own early `#[cfg(test)] mod tests`
    passed the old truncating check and is caught by this one).

    Removes exactly the span of every `#[cfg(test)]`-annotated item --
    its own attribute plus whatever brace-delimited body (`mod`/`fn`/
    `impl`/...) or semicolon-terminated declaration (`use`/`mod x;`/...)
    it decorates -- wherever in the file it physically appears, via a
    single linear scan that tracks paren/bracket/brace nesting depth and
    is aware of line/block comments, string literals (including raw
    strings), and char literals/lifetimes, so a brace or semicolon inside
    a comment, string, or char literal is never mistaken for a real one,
    and a `#[cfg(test)]`-looking substring embedded inside a string
    literal (e.g. a formatter/clippy test fixture's own source-as-data)
    is never mistaken for a real attribute. No third-party dependency is
    added; this is intentionally not a full Rust parser, only enough
    structural awareness to make the item-boundary determination exact
    for this rule's own purposes.
    """
    n = len(text)
    out: list[str] = []
    i = 0
    paren = 0
    bracket = 0
    brace = 0
    # Every recognized marker is UNCONDITIONALLY test-only: `#[cfg(test)]`
    # alone, or `#[cfg(all(test, <predicate>))]` where `test` is one of
    # several `all(...)` CONJUNCTS (so the item can never be present unless
    # `test` holds too). Deliberately NOT recognized: `#[cfg(any(test,
    # feature = "..."))]`-style predicates (real production code in this
    # workspace, e.g. `wht_corulix_workspace`/`wht_corulix_mutation`'s own
    # `test-support`-feature-gated helpers) -- those can be compiled into a
    # non-test build under a feature flag, so this scanner deliberately
    # keeps them visible as production text (fail closed: ambiguous
    # cfg-gating is treated as production, never silently excluded).
    STRICT_TEST_ONLY_MARKERS = (
        "#[cfg(test)]",
        "#[cfg(all(test, windows))]",
        "#[cfg(all(test, unix))]",
    )
    excluding = False
    exclude_baseline_brace = 0
    exclude_entered_body = False
    emit_start = 0

    def raw_string_end(j: int) -> int | None:
        k = j
        if k < n and text[k] == "b":
            k += 1
        if k >= n or text[k] != "r":
            return None
        k += 1
        hashes = 0
        while k < n and text[k] == "#":
            hashes += 1
            k += 1
        if k >= n or text[k] != '"':
            return None
        k += 1
        closing = '"' + ("#" * hashes)
        end = text.find(closing, k)
        return (end + len(closing)) if end != -1 else n

    while i < n:
        c = text[i]

        if c == "/" and i + 1 < n and text[i + 1] == "/":
            newline = text.find("\n", i)
            i = newline + 1 if newline != -1 else n
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if text[j : j + 2] == "/*":
                    depth += 1
                    j += 2
                elif text[j : j + 2] == "*/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            i = j
            continue

        if c in ("r", "b"):
            raw_end = raw_string_end(i)
            if raw_end is not None:
                i = raw_end
                continue

        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue

        if c == "'":
            j = i + 1
            if j < n and text[j] == "\\":
                k = j + 1
                if k < n and text[k] == "u" and k + 1 < n and text[k + 1] == "{":
                    end = text.find("}", k)
                    k = end + 1 if end != -1 else k + 1
                else:
                    k += 1
                i = k + 1 if k < n and text[k] == "'" else j
                continue
            if j + 1 < n and text[j + 1] == "'":
                i = j + 2
                continue
            i = i + 1
            continue

        _matched_marker = None
        if not excluding and paren == 0 and bracket == 0:
            for _candidate in STRICT_TEST_ONLY_MARKERS:
                if text[i : i + len(_candidate)] == _candidate:
                    _matched_marker = _candidate
                    break
        if _matched_marker is not None:
            out.append(text[emit_start:i])
            excluding = True
            exclude_baseline_brace = brace
            exclude_entered_body = False
            i += len(_matched_marker)
            continue

        if c == "(":
            paren += 1
        elif c == ")":
            paren -= 1
        elif c == "[":
            bracket += 1
        elif c == "]":
            bracket -= 1
        elif c == "{":
            brace += 1
            if excluding:
                exclude_entered_body = True
        elif c == "}":
            brace -= 1
            if excluding and exclude_entered_body and brace == exclude_baseline_brace:
                excluding = False
                emit_start = i + 1
        elif c == ";":
            if (
                excluding
                and not exclude_entered_body
                and paren == 0
                and bracket == 0
                and brace == exclude_baseline_brace
            ):
                excluding = False
                emit_start = i + 1

        i += 1

    if not excluding:
        out.append(text[emit_start:])
    return "".join(out)


_EXTERNAL_CFG_TEST_MODULE_RE = re.compile(
    r"#\[cfg\(test\)\]\s*(?:#!?\[[^\]]*\]\s*)*mod\s+(\w+)\s*;"
)


def external_cfg_test_module_files(path: Path, text: str) -> set[Path]:
    """M09-P6VR helper: resolves every `#[cfg(test)] mod <name>;` EXTERNAL
    file-module declaration in `text` (declared in `path`) to the Rust
    source file it points at, per Rust's own module-file resolution (a
    sibling `<name>.rs` next to `path` when `path` is itself `lib.rs`/
    `mod.rs`/`main.rs`, otherwise `<path's own stem>/<name>.rs`, or the
    legacy `.../mod.rs` form), so that file can be excluded wholesale as
    entirely test-only content. This generalizes what was previously a
    single hand-coded `if path.name == "tests.rs": continue` special case
    for `wht_corulix_formatter` alone into a mechanism that covers every
    crate using this equally common "large test module lives in its own
    sibling file" convention (`wht_corulix_mutation`, `wht_corulix_tooling`,
    `wht_corulix_formatter`, and any future crate written the same way).
    """
    resolved: set[Path] = set()
    module_dir = (
        path.parent if path.stem in ("lib", "mod", "main") else path.parent / path.stem
    )
    for match in _EXTERNAL_CFG_TEST_MODULE_RE.finditer(text):
        name = match.group(1)
        sibling = module_dir / f"{name}.rs"
        legacy = module_dir / name / "mod.rs"
        if sibling.is_file():
            resolved.add(sibling)
        elif legacy.is_file():
            resolved.add(legacy)
    return resolved


def strip_comments_and_strings(text: str) -> str:
    """M09-P6VRERT helper: returns `text` with the CONTENTS of every line
    comment, block comment, and string literal blanked out to spaces (never
    removed -- every character position is preserved 1:1, so any span
    computed against this stripped view lines up exactly with the same span
    in the original text). Used so the Command-type-surface scan below
    never mistakes a doc-comment's own English prose (e.g. a sentence that
    happens to say "a Command" or "the Command type") for a real Rust type
    reference -- proven necessary: a bare-word `Command` scan against RAW
    text produced 5 false positives on `wht_corulix_process_unix/src/
    lib.rs`'s own extensive, legitimate documentation before this stripping
    was added; against the stripped view it produces zero.
    """
    n = len(text)
    out = list(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            end = end if end != -1 else n
            for k in range(i, end):
                out[k] = " "
            i = end
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = end + 2 if end != -1 else n
            for k in range(i, end):
                if out[k] != "\n":
                    out[k] = " "
            i = end
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def strip_route_evidence_view(text: str) -> str:
    """M09-P10 owner-authorized helper
    (`M09_P10_ARCHITECTURE_VERIFIER_MUTATION_SCOPE=
    RULE_ROUTE_TOKEN_COMMENT_STRING_HARDENING_AND_TS_COVERAGE`): blanks the
    CONTENTS of every line comment, block comment (nesting-aware -- Rust
    block comments genuinely nest, unlike `strip_comments_and_strings`
    above's non-nesting `find("*/", ...)`), raw string literal
    (`r"..."`/`r#"..."#`/`br"..."`/...), and ordinary string literal to
    spaces -- position-preserving, mirroring `strip_comments_and_strings`'s
    own line-comment/normal-string recognition, but additionally raw-string
    aware (mirroring `raw_string_end`'s recognition inside the
    `#[cfg(test)]`-item stripper above), which `strip_comments_and_strings`
    deliberately is not -- that function's own existing callers (Rule G's
    Command-surface scan) never needed it.

    Scoped narrowly to the route-token architecture checks that require
    genuine production-CALL evidence (Rule U.2/W.6/X.2): a secure entry
    point's own literal name appearing only inside a comment or string can
    never again satisfy those checks (owner-authorized remediation of the
    P10 negative-control-G finding). This is deliberately not a general
    Rust parser -- unlike the `#[cfg(test)]`-item stripper, no brace/paren
    nesting is tracked here at all, since blanking a comment/string span
    never needs it; only enough lexical recognition to skip past every
    comment/string/raw-string span without being fooled by a `"` or `/`
    that is itself inside one of the others. Raw-string recognition is
    checked BEFORE the plain-string check below so a raw string's own `"`
    is never misread as starting an escaped string, which would corrupt
    the scan of everything after it for a hash-delimited raw string
    containing an internal `"`.
    """
    n = len(text)
    out = list(text)
    i = 0

    def blank(start: int, end: int) -> None:
        for k in range(start, end):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]

        if c == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            end = end if end != -1 else n
            blank(i, end)
            i = end
            continue

        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if text[j : j + 2] == "/*":
                    depth += 1
                    j += 2
                elif text[j : j + 2] == "*/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue

        if c in ("r", "b"):
            k = i
            if k < n and text[k] == "b":
                k += 1
            if k < n and text[k] == "r":
                k += 1
                hashes = 0
                while k < n and text[k] == "#":
                    hashes += 1
                    k += 1
                if k < n and text[k] == '"':
                    k += 1
                    closing = '"' + ("#" * hashes)
                    end = text.find(closing, k)
                    end = (end + len(closing)) if end != -1 else n
                    blank(i, end)
                    i = end
                    continue

        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue

        i += 1

    return "".join(out)


# M09-P6VRERT: the Command-type SURFACE itself -- in ANY form (owned,
# shared reference, mutable reference, wrapped in `Option`/`Box`, a struct
# field, a function return type, or reached only via an import/type alias
# whose own declaration must still spell the qualified path at least once)
# -- is denied by default outside wht_corulix_tooling. Exactly these two
# named (crate, file, function) triples are authorized to CONFIGURE an
# already-constructed Command -- traced exhaustively against the real tree
# (these are the only two non-tooling production occurrences of either
# qualified type path anywhere). Any OTHER function, in ANY crate
# (workspace and process_unix themselves included), that references the
# type at all -- even without ever calling spawn/output/status on it -- is
# itself a violation: the authorization is bound to the exact function,
# never the whole crate.
#
# M09-P6VRER's own model (a regex for `&mut ...Command`-shaped PARAMETERS
# only) is superseded here: it was proven, via scratch controls compiled
# and verified with real `rustc`, to miss an owned-by-value parameter
# (`command: std::process::Command`), a shared reference
# (`&std::process::Command`), an import alias (`use ... as X`), a type
# alias (`type X = ...`), `Option<...>`/`Box<...>`-wrapped forms, a
# function return type, and a struct field -- none of those shapes is
# `&mut ...Command`, so the old regex never even looked at them. Every one
# of those forms, however, still has to spell the qualified path
# `std::process::Command`/`tokio::process::Command` literally at least
# once (in its own declaration, even if only to define an alias others
# then use bare) -- so a plain substring search for the qualified path,
# with the two named boundaries carved out as authorized spans, catches
# all of them uniformly without needing to enumerate every wrapper shape.
RULE_G_PROCESS_COMMAND_QUALIFIED_TYPE_TOKENS = (
    "std::process::Command",
    "tokio::process::Command",
)
RULE_G_AUTHORIZED_COMMAND_CONFIGURATION_BOUNDARIES = {
    ("wht_corulix_workspace", "confine.rs", "bind_process_cwd"),
    ("wht_corulix_process_unix", "lib.rs", "bind_cwd"),
}
# `wht_corulix_process_unix::bind_cwd` receives its parameter as bare
# `Command`, relying on this exact `use` import rather than spelling the
# qualified path inline (unlike `wht_corulix_workspace::bind_process_cwd`,
# which spells it inline and needs no import). The import line is
# authorized as its own tiny span -- but, per this pass's own mandate, it
# must never "grant file-wide authority": a second, unauthorized function
# added later to the same file could otherwise reuse the already-imported
# bare name (`command: &mut Command`) without ever re-spelling the
# qualified path itself, invisible to the substring scan above. The bare-
# word scan below closes exactly that gap, scoped only to files that
# actually carry one of these authorized imports.
RULE_G_AUTHORIZED_COMMAND_IMPORT_LINES = {
    ("wht_corulix_process_unix", "lib.rs"): "use std::process::Command;",
}
_BARE_COMMAND_RE = re.compile(r"\bCommand\b")

# Within one of the two authorized boundaries above, execution is banned by
# BARE TOKEN -- not `<param>.spawn(` alone -- specifically because the
# M09-P6VRE parameter-name-qualified check was proven (scratch negative
# controls: a local alias, a double alias, and a UFCS/method-value-alias
# call, none containing the parameter's own name immediately before
# `.spawn(`) to miss every one of: reassigning the parameter to a new local
# binding before calling `.spawn(`/`.output(`/`.status(` on THAT name
# instead; invoking the method via UFCS (`std::process::Command::spawn(
# command)`, which never has `.spawn(` immediately after any identifier at
# all -- it is `Command::spawn(`, not `<name>.spawn(`); or via a bare
# function-item value (`let f = Command::spawn; f(command);`). A whole-
# crate bare-token ban on `spawn(`/`output(`/`status(` would be too broad
# (Rule G's own audit found 24 unrelated `.status()` calls on domain types
# like `ChangeSessionStatus`/`IndexState` elsewhere in this workspace) --
# but within these two specific, tiny, single-purpose, exhaustively-read
# functions (confirmed by direct reading to never legitimately need any of
# these six substrings in any form), a bare-token ban is precise and
# alias/UFCS/method-value-proof by construction: whatever new name a value
# is rebound to, the literal source text `spawn(`/`output(`/`status(`
# still has to appear somewhere for the call to happen at all, and any
# UFCS/method-value form still has to spell `Command::spawn`/`Command::
# output`/`Command::status` somewhere to name the method without a receiver
# expression.
RULE_G_EXECUTION_BAN_TOKENS_WITHIN_BOUNDARY = (
    "spawn(",
    "output(",
    "status(",
    "Command::spawn",
    "Command::output",
    "Command::status",
)


def _find_matching_paren(text: str, open_idx: int) -> int | None:
    """`text[open_idx] == '('`; returns the index of the matching `)`, or
    `None` if unbalanced. Used to find a function's own parameter list
    span, so a `&mut ...Command`-typed match can be attributed to the
    exact enclosing function that declares it.
    """
    n = len(text)
    depth = 0
    i = open_idx
    while i < n:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def named_function_span(text: str, function_name: str) -> tuple[int, int] | None:
    """M09-P6VRERT: finds the function named EXACTLY `function_name`'s own
    full span, from its `fn` keyword through the closing brace of its body
    -- used to authorize the two named Command-configuration boundaries by
    their real, compiled identity, never by convention or position.
    Returns `None` if no such function is found, or it has no body (a
    trait method signature ending in `;`).
    """
    pattern = re.compile(
        r"\bfn\s+" + re.escape(function_name) + r"\s*(?:<[^>]*>)?\s*\("
    )
    match = pattern.search(text)
    if match is None:
        return None
    paren_open = match.end() - 1
    paren_close = _find_matching_paren(text, paren_open)
    if paren_close is None:
        return None
    i = paren_close + 1
    n = len(text)
    while i < n and text[i] not in "{;":
        i += 1
    if i >= n or text[i] != "{":
        return None
    return (match.start(), _find_matching_brace(text, i))


def _find_matching_brace(text: str, open_idx: int) -> int:
    """Shared brace-matcher: `text[open_idx] == '{'`; returns the index just
    past the matching `}`, comment/string-aware so a brace inside either is
    never mistaken for a real one. Reused by both
    `production_source_excluding_cfg_test` (via its own inline copy of this
    same logic) and `named_function_span` above.
    """
    n = len(text)
    depth = 0
    i = open_idx
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            newline = text.find("\n", i)
            i = newline + 1 if newline != -1 else n
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = end + 2 if end != -1 else n
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            i += 1
            if depth == 0:
                return i
            continue
        i += 1
    return n


# Step 4: Run the source-level scans for both boundaries.
scan("wht_corulix_core", ("rmcp", "modelcontextprotocol", "wht_corulix_mcp"))
# wht_corulix_mcp keeps its own stdout ban unconditionally: the MCP protocol
# stream goes through rmcp's stdio transport, never a raw print macro, so
# this crate has no legitimate reason to ever call println!/print! itself.
scan("wht_corulix_mcp", ("println!(",))

# Step 4b (Rule C -- RULE_C_SYNTAX_ISOLATION): source-level defense in
# depth for the manifest-level Tree-sitter check above -- no other crate's
# source may reference the runtime crate or a grammar crate path, even via
# a transitive re-export that bypassed the direct-dependency check. Each
# grammar-crate token is deliberately followed by `::` so this never
# false-positives on an unrelated identifier that merely starts with the
# same prefix (e.g. `wht_corulix_core::RuntimeIdentity::tree_sitter_runtime`,
# a metadata field name, not a crate-path reference).
TREE_SITTER_SOURCE_TOKENS = (
    "tree_sitter::",
    "tree_sitter_javascript::",
    "tree_sitter_typescript::",
    "tree_sitter_python::",
    "tree_sitter_rust::",
    "tree_sitter_go::",
)
for crate in (
    "wht_corulix_core",
    "wht_corulix_workspace",
    "wht_corulix_search",
    "wht_corulix_index",
    "wht_corulix_config",
    "wht_corulix_lsp",
    "wht_corulix_engine",
    "wht_corulix_mcp",
    "wht_corulix_cli",
):
    scan(crate, TREE_SITTER_SOURCE_TOKENS)

# Step 5 (Rule I -- enterprise CLI authority): the CLI binary must parse its
# public grammar exclusively through the `clap` derive command model in
# `cli.rs`. `env::args(` is the exact token a hand-rolled manual dispatch
# tree would need (as the pre-Phase-2 CLI's own now-replaced implementation
# did) -- its absence is a precise, structural proof that no second, manual
# parser exists alongside `clap`. Unlike the retired stdout ban, this check
# is not about which stream output goes to (see the module docstring): a
# deliberate Enterprise CLI Help mandate makes stdout the correct stream for
# ordinary human-facing command output in this crate, with errors/diagnostics
# on stderr and stdout reserved exclusively for the MCP protocol stream only
# once `mcp stdio` itself starts -- so this crate's own println!/print! use
# is intentional and is not scanned for here.
for path in (ROOT / "wht_crates" / "wht_corulix_cli" / "src").rglob("*.rs"):
    text = path.read_text(encoding="utf-8")
    if "env::args(" in text or "std::env::args(" in text:
        failures.append(
            f"{path.relative_to(ROOT)} contains a manual env::args() dispatch "
            "token (Architecture Rule I violation -- clap must be the sole "
            "CLI grammar authority)"
        )

# Step 6 (Rule F): only wht_corulix_workspace may own filesystem
# canonicalization/confinement. Manifest-level: it may depend on nothing
# beyond wht_corulix_core.
workspace_crate_deps = dependency_names("wht_corulix_workspace")
forbidden_for_workspace_crate = {
    "wht_corulix_engine",
    "wht_corulix_mcp",
    "wht_corulix_cli",
    "wht_corulix_search",
    "wht_corulix_lsp",
    "wht_corulix_tooling",
    "wht_corulix_syntax",
    "wht_corulix_config",
    "tree-sitter",
    "rmcp",
    "clap",
    "ls-types",
}
for forbidden in forbidden_for_workspace_crate:
    if forbidden in workspace_crate_deps:
        failures.append(f"wht_corulix_workspace has forbidden dependency: {forbidden}")

# Step 7 (Rule F): source-level defense in depth -- the exact
# canonicalization primitive (`canonicalize(`) must appear in exactly one
# crate's source. This precise, function-call-shaped token (not the bare
# word "canonicalize") avoids false-positiving on prose/doc-comments that
# merely discuss canonicalization without implementing it.
crates_dir = ROOT / "wht_crates"
for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir() or crate_dir.name == "wht_corulix_workspace":
        continue
    for path in (crate_dir / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        if "canonicalize(" in text:
            failures.append(
                f"{path.relative_to(ROOT)} implements canonicalization outside "
                "wht_corulix_workspace (Architecture Rule F violation)"
            )

# Step 7b (Rule F expansion): only wht_corulix_workspace may parse
# `.code-workspace` descriptors. Manifest-level: no other crate may depend
# on the admitted `jsonc-parser` crate. Source-level: no other crate may
# reference the `jsonc_parser` module path (precise -- unlike the file
# extension string, this token never legitimately appears in prose/help
# text describing the feature).
for crate in (
    "wht_corulix_core",
    "wht_corulix_config",
    "wht_corulix_engine",
    "wht_corulix_mcp",
    "wht_corulix_cli",
):
    if "jsonc-parser" in dependency_names(crate):
        failures.append(
            f"{crate} has forbidden dependency: jsonc-parser (Architecture Rule F violation)"
        )
for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir() or crate_dir.name == "wht_corulix_workspace":
        continue
    for path in (crate_dir / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        if "jsonc_parser" in text:
            failures.append(
                f"{path.relative_to(ROOT)} references jsonc_parser outside "
                "wht_corulix_workspace (Architecture Rule F violation)"
            )

# Step 7c (Rule D -- embedded search isolation): only wht_corulix_search may
# depend on the ripgrep-family crates. Manifest-level: no other crate may
# depend on any of them.
ripgrep_family = {"ignore", "grep-matcher", "grep-regex", "grep-searcher"}
for crate in (
    "wht_corulix_core",
    "wht_corulix_workspace",
    "wht_corulix_config",
    "wht_corulix_lsp",
    "wht_corulix_engine",
    "wht_corulix_mcp",
    "wht_corulix_cli",
):
    overlap = ripgrep_family & dependency_names(crate)
    for forbidden in sorted(overlap):
        failures.append(
            f"{crate} has forbidden dependency: {forbidden} (Architecture Rule D violation)"
        )

# Step 7d (Rule D): wht_corulix_search must never spawn an external process
# (no embedded search implementation may shell out to `rg` or any other
# binary) and must never construct its own independent filesystem walker --
# `ignore::WalkBuilder` would be a second, competing traversal authority,
# which Rule F forbids regardless of which crate attempted it.
search_forbidden_tokens = ("Command::new(", "std::process::Command", "WalkBuilder")
for path in (ROOT / "wht_crates" / "wht_corulix_search" / "src").rglob("*.rs"):
    text = path.read_text(encoding="utf-8")
    for token in search_forbidden_tokens:
        if token in text:
            failures.append(
                f"{path.relative_to(ROOT)} contains forbidden token {token!r} "
                "(Architecture Rule D violation)"
            )

# Step 9 (Rule H -- RULE_H_ENGINE_AUTHORITY): only wht_corulix_engine may
# derive policy (RiskClass/ToolPlan/required gates/provider
# applicability-authority) for a concrete operation. Source-level: no other
# crate may construct a `ToolPlan {` literal (wht_corulix_core legitimately
# defines and unit-tests the *type* itself, so it is exempt -- Rule H is
# about *deriving* a plan for a real operation, not defining its shape), nor
# reference the engine's own `PolicyEntry` policy-table type or its
# `policy_entry`/`derive_risk_class` functions.
RULE_H_FORBIDDEN_TOKENS = (
    "ToolPlan {",
    "PolicyEntry",
    "fn policy_entry",
    "fn derive_risk_class",
)
for crate in (
    "wht_corulix_workspace",
    "wht_corulix_search",
    "wht_corulix_syntax",
    "wht_corulix_index",
    "wht_corulix_config",
    "wht_corulix_lsp",
    "wht_corulix_mcp",
    "wht_corulix_cli",
):
    for path in (ROOT / "wht_crates" / crate / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        for token in RULE_H_FORBIDDEN_TOKENS:
            if token in text:
                failures.append(
                    f"{path.relative_to(ROOT)} contains forbidden token {token!r} "
                    "(Architecture Rule H violation -- only wht_corulix_engine may "
                    "derive policy)"
                )

# Step 11 (Rule G -- RULE_G_PROCESS_CONSTRUCTION, remediated M09-P6VR):
# only wht_corulix_tooling may construct an external process. Two defects
# the M09-P6V audit proved via scratch-copy negative controls are fixed
# here, both structurally rather than by patching the symptom:
#
#   1. Cfg(test) position blind spot -- the previous helper (`scan()`)
#      determined "production text" by truncating a file at its FIRST
#      `#[cfg(test)]` marker, silently exempting real production code
#      that happened to appear physically AFTER an early test item in the
#      same file (proven: a synthetic `Command::new(...).spawn()`
#      appended after `wht_corulix_engine/src/lib.rs`'s own early
#      `#[cfg(test)] mod tests` passed the old check). This is now
#      `production_source_excluding_cfg_test`, a structural, position-
#      independent item-range extractor (see its own docstring above).
#   2. Mutation coverage gap -- the crate list below was a hand-maintained
#      partial enumeration that omitted `wht_corulix_mutation` entirely
#      (proven: a synthetic production spawn there passed undetected). The
#      scan set is now DERIVED from the real on-disk crate inventory
#      (`crates_dir.iterdir()`) rather than another hand-maintained list,
#      so a future crate is covered automatically, with exactly two
#      explicitly-classified, documented exemptions:
#        * `wht_corulix_tooling` -- this rule's own authority, expected to
#          construct processes.
#        * `wht_corulix_process_fixture` -- a `publish = false`, bin-only
#          cross-crate TEST FIXTURE binary (never a library, never a
#          product dependency of anything): its own `main()` legitimately
#          constructs/spawns child processes as its sole purpose (the
#          `print-argv`/`print-cwd`/`print-fd-count`/etc. dispatch modes
#          other crates' test suites build and invoke via `escargot`).
#
# The construction-token set is also narrowed to exactly the three
# substrings that can only ever appear as a real construction call:
# `Command::new(` is the *only* public constructor either standard-library
# or tokio's `Command` type exposes (no other associated function or
# struct literal can build one), so these three tokens are exhaustive for
# real construction and never ambiguous with a mere type mention, `use`
# import, or doc comment -- unlike the previous bare `std::process::
# Command`/`tokio::process::Command` type-name tokens, which required a
# separate, narrower, hand-maintained token list just for
# `wht_corulix_workspace` (M09-P6's `bind_process_cwd`, which only
# CONFIGURES an already-constructed `&mut Command`) and would have newly
# false-positived on `wht_corulix_process_win32`'s own doc comments once
# that crate is swept in by the derived crate list below. No crate needs
# its own narrower list any longer: the same precise three tokens apply to
# every scanned crate uniformly.
#
# A crate's own `#[cfg(test)] mod <name>;` EXTERNAL file-module
# declarations (e.g. `wht_corulix_mutation/src/executor.rs` declaring
# `executor/tests.rs`, `wht_corulix_formatter/src/lib.rs` declaring
# `src/tests.rs` and `src/fixture_support.rs`) are resolved structurally
# via `external_cfg_test_module_files` and excluded wholesale, replacing
# the previous single hand-coded `if path.name == "tests.rs"` special case
# (which covered `wht_corulix_formatter` alone) with a general mechanism
# that covers every crate using this convention.
RULE_G_PRODUCTION_CONSTRUCTION_TOKENS = (
    "Command::new(",
    "tokio::process::Command::new(",
    "std::process::Command::new(",
)
RULE_G_EXEMPT_CRATES = {
    "wht_corulix_tooling",
    "wht_corulix_process_fixture",
}
for _rule_g_crate_dir in sorted(crates_dir.iterdir()):
    if not _rule_g_crate_dir.is_dir() or _rule_g_crate_dir.name in RULE_G_EXEMPT_CRATES:
        continue
    _rule_g_src = _rule_g_crate_dir / "src"
    if not _rule_g_src.exists():
        continue
    _rule_g_all_paths = list(_rule_g_src.rglob("*.rs"))
    _rule_g_texts = {p: p.read_text(encoding="utf-8") for p in _rule_g_all_paths}
    _rule_g_excluded_files: set[Path] = set()
    for _rule_g_path, _rule_g_text in _rule_g_texts.items():
        _rule_g_excluded_files |= external_cfg_test_module_files(
            _rule_g_path, _rule_g_text
        )
    for _rule_g_path in _rule_g_all_paths:
        if _rule_g_path in _rule_g_excluded_files:
            continue
        _rule_g_production_text = production_source_excluding_cfg_test(
            _rule_g_texts[_rule_g_path]
        )
        for _rule_g_token in RULE_G_PRODUCTION_CONSTRUCTION_TOKENS:
            if _rule_g_token in _rule_g_production_text:
                failures.append(
                    f"{_rule_g_path.relative_to(ROOT)} contains forbidden token "
                    f"{_rule_g_token!r} (Architecture Rule G violation -- only "
                    "wht_corulix_tooling may construct an external process; every "
                    "other crate may at most CONFIGURE an already-constructed "
                    "Command it was handed, never call ::new( itself)"
                )
        # Rule G Command-authority TYPE SURFACE + execution ownership
        # (remediated M09-P6VRERT): a `&mut ...Command`-shaped PARAMETER
        # regex (M09-P6VRER's own model) was proven, via scratch controls
        # compiled and verified with real `rustc`, to miss an owned-by-
        # value parameter, a shared reference, an import alias, a type
        # alias, `Option<...>`/`Box<...>`-wrapped forms, a function return
        # type, and a struct field -- none of those shapes is `&mut
        # ...Command`. The model is now: scan a COMMENT/STRING-STRIPPED
        # view of the production text (so a doc comment's own English
        # prose is never mistaken for a type reference -- proven necessary
        # against `wht_corulix_process_unix`'s own extensive documentation)
        # for the qualified path `std::process::Command`/`tokio::process::
        # Command` as a bare substring, which every one of those forms
        # still has to spell at least once in its own declaration; any
        # occurrence outside the two named (crate, file, function)
        # boundaries in `RULE_G_AUTHORIZED_COMMAND_CONFIGURATION_BOUNDARIES`
        # is a violation. For `wht_corulix_process_unix::bind_cwd`
        # specifically (which receives a bare `Command`, relying on its own
        # `use std::process::Command;` import rather than spelling the
        # qualified path inline), that one import line is authorized as its
        # own tiny span, and a bare-word `Command` scan (also comment/
        # string-stripped) closes the residual gap where a second,
        # unauthorized function added later to the same file could
        # otherwise reuse the already-imported bare name without ever
        # re-spelling the qualified path. Within the authorized boundary's
        # own body, execution remains banned by BARE TOKEN (not parameter-
        # qualified) -- alias/UFCS/method-value-proof by construction, per
        # M09-P6VRER's own reasoning, preserved unchanged here.
        _rule_g_stripped_text = strip_comments_and_strings(_rule_g_production_text)
        _rule_g_authorized_spans: list[tuple[int, int]] = []
        _rule_g_boundary_fn = next(
            (
                fn
                for (
                    crate_name,
                    file_name,
                    fn,
                ) in RULE_G_AUTHORIZED_COMMAND_CONFIGURATION_BOUNDARIES
                if crate_name == _rule_g_crate_dir.name
                and file_name == _rule_g_path.name
            ),
            None,
        )
        _rule_g_boundary_span: tuple[int, int] | None = None
        if _rule_g_boundary_fn is not None:
            _rule_g_boundary_span = named_function_span(
                _rule_g_stripped_text, _rule_g_boundary_fn
            )
            if _rule_g_boundary_span is not None:
                _rule_g_authorized_spans.append(_rule_g_boundary_span)
        _rule_g_import_line = RULE_G_AUTHORIZED_COMMAND_IMPORT_LINES.get(
            (_rule_g_crate_dir.name, _rule_g_path.name)
        )
        if _rule_g_import_line is not None:
            _rule_g_import_idx = _rule_g_stripped_text.find(_rule_g_import_line)
            if _rule_g_import_idx != -1:
                _rule_g_authorized_spans.append(
                    (_rule_g_import_idx, _rule_g_import_idx + len(_rule_g_import_line))
                )

        def _rule_g_is_authorized(pos: int) -> bool:
            return any(start <= pos < end for start, end in _rule_g_authorized_spans)

        for _rule_g_qualified_token in RULE_G_PROCESS_COMMAND_QUALIFIED_TYPE_TOKENS:
            _rule_g_search_from = 0
            while True:
                _rule_g_pos = _rule_g_stripped_text.find(
                    _rule_g_qualified_token, _rule_g_search_from
                )
                if _rule_g_pos == -1:
                    break
                _rule_g_search_from = _rule_g_pos + 1
                if _rule_g_is_authorized(_rule_g_pos):
                    continue
                failures.append(
                    f"{_rule_g_path.relative_to(ROOT)} references "
                    f"{_rule_g_qualified_token} outside the two named, function-scoped "
                    "configuration boundaries (Architecture Rule G violation -- the "
                    "Command-type surface, in any form -- owned, shared reference, "
                    "wrapped in Option/Box, a struct field, a return type, or an "
                    "import/type alias -- is denied by default outside "
                    "wht_corulix_tooling)"
                )
        if (
            _rule_g_import_line is not None
            and _rule_g_import_line in _rule_g_stripped_text
        ):
            for _rule_g_bare_match in _BARE_COMMAND_RE.finditer(_rule_g_stripped_text):
                if not _rule_g_is_authorized(_rule_g_bare_match.start()):
                    failures.append(
                        f"{_rule_g_path.relative_to(ROOT)} references bare `Command` "
                        "outside the authorized configuration boundary (Architecture "
                        "Rule G violation -- this file's own authorized "
                        f"{_rule_g_import_line!r} import must never grant file-wide "
                        "Command authority to any other function)"
                    )

        if _rule_g_boundary_fn is not None and _rule_g_boundary_span is not None:
            _rule_g_body = _rule_g_stripped_text[
                _rule_g_boundary_span[0] : _rule_g_boundary_span[1]
            ]
            for _rule_g_execution_token in RULE_G_EXECUTION_BAN_TOKENS_WITHIN_BOUNDARY:
                if _rule_g_execution_token in _rule_g_body:
                    failures.append(
                        f"{_rule_g_path.relative_to(ROOT)}::{_rule_g_boundary_fn} contains "
                        f"forbidden execution token {_rule_g_execution_token!r} "
                        "(Architecture Rule G violation -- this authorized "
                        "configuration boundary may CONFIGURE its Command parameter "
                        "but may never EXECUTE it, under any alias, UFCS form, or "
                        "method-value indirection)"
                    )

# Step 12 (Rule J -- RULE_J_ASYNC_RUNTIME): Tokio is the single canonical
# async runtime, owned at the top level exclusively by wht_corulix_cli's
# own `#[tokio::main]`. No *library* crate (every crate except the CLI
# binary) may construct a second, nested runtime, and no library crate may
# call `.block_on(` to bridge back into synchronous code from inside an
# already-async context -- both defeat the single-runtime, structured-
# concurrency model this rule protects.
RUNTIME_CONSTRUCTION_TOKENS = (
    "tokio::runtime::Runtime",
    "tokio::runtime::Builder",
    "Runtime::new(",
    "#[tokio::main]",
)
BLOCK_ON_TOKENS = (".block_on(",)
for crate in (
    "wht_corulix_core",
    "wht_corulix_workspace",
    "wht_corulix_search",
    "wht_corulix_syntax",
    "wht_corulix_index",
    "wht_corulix_config",
    "wht_corulix_lsp",
    "wht_corulix_engine",
    "wht_corulix_tooling",
    "wht_corulix_mcp",
):
    scan(crate, RUNTIME_CONSTRUCTION_TOKENS)
    scan(crate, BLOCK_ON_TOKENS)

# Step 12b (Rule J): wht_corulix_tooling's canonical process-execution entry
# point must remain `pub async fn execute` -- a synchronous `pub fn execute`
# reintroduced alongside or instead of it would silently regress this
# crate's real containment invariants back onto a thread-based design this
# rule exists to keep out.
_tooling_lib = ROOT / "wht_crates" / "wht_corulix_tooling" / "src" / "lib.rs"
_tooling_text = _tooling_lib.read_text(encoding="utf-8")
if "pub fn execute(" in _tooling_text:
    failures.append(
        f"{_tooling_lib.relative_to(ROOT)} contains a synchronous 'pub fn execute(' "
        "(Architecture Rule J violation -- the canonical process-execution entry "
        "point must be 'pub async fn execute', not a synchronous fallback)"
    )

# Step 12c (Rule J): every other canonical async-first provider/operational
# entry point must be the sole public name for its operation -- a
# synchronous `pub fn` under the exact same name kept alongside the async
# one would be exactly the "canonical sync + async wrapper" duplication
# this rule forbids.
CANONICAL_ASYNC_ENTRY_POINTS = {
    "wht_corulix_search": ("src/engine.rs", "search"),
    "wht_corulix_syntax": ("src/lib.rs", "parse_source"),
    "wht_corulix_engine": ("src/lib.rs", ("parse_relative_file", "resolve_confined")),
    "wht_corulix_workspace": (
        "src/confine.rs",
        ("resolve_confined", "confined_metadata", "confined_read", "confined_walk"),
    ),
}
for crate, (relative_path, function_names) in CANONICAL_ASYNC_ENTRY_POINTS.items():
    if isinstance(function_names, str):
        function_names = (function_names,)
    source_path = ROOT / "wht_crates" / crate / relative_path
    source_text = source_path.read_text(encoding="utf-8")
    for function_name in function_names:
        if f"pub fn {function_name}(" in source_text:
            failures.append(
                f"{source_path.relative_to(ROOT)} contains a synchronous "
                f"'pub fn {function_name}(' (Architecture Rule J violation -- the "
                f"canonical entry point must be 'pub async fn {function_name}', "
                "not a synchronous fallback)"
            )
        if f"pub async fn {function_name}(" not in source_text:
            failures.append(
                f"{source_path.relative_to(ROOT)} is missing the canonical "
                f"'pub async fn {function_name}(' entry point (Architecture Rule J "
                "violation)"
            )
if "pub async fn execute(" not in _tooling_text:
    failures.append(
        f"{_tooling_lib.relative_to(ROOT)} is missing the canonical "
        "'pub async fn execute(' entry point (Architecture Rule J violation)"
    )
_tooling_lib_extra = (
    ROOT / "wht_crates" / "wht_corulix_workspace" / "src" / "resolver.rs"
)
_resolver_text = _tooling_lib_extra.read_text(encoding="utf-8")
if "pub fn resolve_workspace(" in _resolver_text:
    failures.append(
        f"{_tooling_lib_extra.relative_to(ROOT)} contains a synchronous "
        "'pub fn resolve_workspace(' (Architecture Rule J violation)"
    )
if "pub async fn resolve_workspace(" not in _resolver_text:
    failures.append(
        f"{_tooling_lib_extra.relative_to(ROOT)} is missing the canonical "
        "'pub async fn resolve_workspace(' entry point (Architecture Rule J violation)"
    )

# Step 12d (Rule J -- public operational blocking-bypass ban): no crate that
# owns a canonical async-first operational/provider/filesystem boundary
# (Workspace, Search, Syntax, Engine) may expose ANY `pub fn <name>_blocking`
# -- a distinctly-named blocking core is only acceptable as a private
# (or, within a crate's own modules, `pub(crate)`) composition primitive.
# Public visibility of a `_blocking` name is itself the violation this
# check exists to catch, regardless of what the name is.
BLOCKING_BYPASS_CRATES = (
    "wht_corulix_workspace",
    "wht_corulix_search",
    "wht_corulix_syntax",
    "wht_corulix_config",
    "wht_corulix_engine",
    "wht_corulix_formatter",
)
_BLOCKING_PUB_PATTERN = re.compile(r"pub fn (\w*_blocking)\(")
for crate in BLOCKING_BYPASS_CRATES:
    for path in (ROOT / "wht_crates" / crate / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        for match in _BLOCKING_PUB_PATTERN.finditer(text):
            failures.append(
                f"{path.relative_to(ROOT)} exposes a public blocking bypass "
                f"'pub fn {match.group(1)}(' (Architecture Rule J violation -- "
                "operational/provider/filesystem blocking cores must never be "
                "public; use a private or pub(crate) core behind the canonical "
                "async entry point instead)"
            )

# Step 13 (Rule K -- RULE_K_TRUST_CONFIG_PROVIDER_RESOLUTION, Phase 6): only
# wht_corulix_config owns workspace-trust authorization, the
# HOST_ONLY/REPOSITORY_HINT/REQUEST_SCOPED configuration merge, and
# canonical async-first provider resolution. This rule is defense-in-depth
# on top of the real, tested behavior in that crate (monotonic merge,
# poisoned-PATH-has-no-effect, workspace-local-candidate rejection) -- these
# static scans catch a *structural* regression even if a future edit
# forgets to keep those tests passing.

# Step 13a: only wht_corulix_config may define the provider-resolution
# entry point. A second `fn resolve_provider(` anywhere else would be a
# second, competing resolution authority.
_RESOLVE_PROVIDER_PATTERN = re.compile(r"\bfn resolve_provider\(")
for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir() or crate_dir.name == "wht_corulix_config":
        continue
    for path in (crate_dir / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        if _RESOLVE_PROVIDER_PATTERN.search(text):
            failures.append(
                f"{path.relative_to(ROOT)} defines a provider-resolution entry "
                "point outside wht_corulix_config (Architecture Rule K violation)"
            )

# Step 13b: ambient PATH must have zero provider-resolution authority
# anywhere in the workspace (AMBIENT_PATH_PROVIDER_AUTHORITY=NO) -- no
# crate may read the PATH environment variable at all.
_AMBIENT_PATH_TOKENS = ('env::var("PATH")', 'env::var("Path")', 'var("PATH")')
for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir():
        continue
    for path in (crate_dir / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        for token in _AMBIENT_PATH_TOKENS:
            if token in text:
                failures.append(
                    f"{path.relative_to(ROOT)} reads the ambient PATH environment "
                    f"variable ({token!r}) (Architecture Rule K violation -- "
                    "AMBIENT_PATH_PROVIDER_AUTHORITY=NO)"
                )

# Step 13c: REPOSITORY_HINT (`RepositoryHints`) and REQUEST_SCOPED
# (`RequestOptions`) must remain structurally incapable of elevating trust
# -- neither struct body may reference `WorkspaceTrust` at all. This is a
# stronger guarantee than a passing test: it proves no such field could be
# added without also being caught here.
_config_trust_path = ROOT / "wht_crates" / "wht_corulix_config" / "src" / "trust.rs"
if _config_trust_path.exists():
    _trust_text = _config_trust_path.read_text(encoding="utf-8")
    for struct_name in ("RepositoryHints", "RequestOptions"):
        marker = f"struct {struct_name} {{"
        start = _trust_text.find(marker)
        if start == -1:
            failures.append(
                f"{_config_trust_path.relative_to(ROOT)} is missing the expected "
                f"'{marker}' definition (Architecture Rule K violation)"
            )
            continue
        end = _trust_text.find("\n}", start)
        body = _trust_text[start:end] if end != -1 else _trust_text[start:]
        if "WorkspaceTrust" in body:
            failures.append(
                f"{_config_trust_path.relative_to(ROOT)}: {struct_name} references "
                "WorkspaceTrust (Architecture Rule K violation -- "
                "REPOSITORY_TRUST_ELEVATION_PATH_COUNT/REQUEST_TRUST_ELEVATION_PATH_COUNT "
                "must be 0)"
            )

# Step 13d: no premature ADMIN_ONLY configuration-source implementation --
# no authenticated remote admin plane exists yet, so the `AdminOnly`
# identifier must not appear anywhere in the workspace's source.
for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir():
        continue
    for path in (crate_dir / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        if "AdminOnly" in text:
            failures.append(
                f"{path.relative_to(ROOT)} references 'AdminOnly' (Architecture Rule "
                "K violation -- no authenticated remote admin plane exists yet)"
            )

# Step 13e: wht_corulix_config's resolver must retain its workspace-local
# rejection check -- a positive-presence proxy for "the resolver still
# compares a candidate's canonical location against the workspace root"
# rather than a full semantic proof (that proof is this crate's own real
# tests, e.g. `workspace_local_symlink_indirection_is_rejected`).
_config_resolver_path = (
    ROOT / "wht_crates" / "wht_corulix_config" / "src" / "resolver.rs"
)
if _config_resolver_path.exists():
    _resolver_text = _config_resolver_path.read_text(encoding="utf-8")
    if "canonical_path()" not in _resolver_text or "starts_with(" not in _resolver_text:
        failures.append(
            f"{_config_resolver_path.relative_to(ROOT)} is missing the expected "
            "workspace-membership rejection check (Architecture Rule K violation)"
        )

# Step 14 (Rule L -- RULE_L_LSP_SEMANTIC_AUTHORITY, Phase 7): only
# wht_corulix_lsp owns LSP transport/client protocol and semantic
# (definition/references/symbols/diagnostics/rename-preview) intelligence.
# SEARCH = textual intelligence, SYNTAX = structural intelligence,
# LSP = semantic intelligence -- neither Search nor Syntax may become a
# second semantic authority, and no raw `ls_types` value may leak into any
# other canonical layer. LSP-reported formatting capability is never
# authoritative: `rustfmt` (a future phase) remains the sole formatter
# authority regardless of what a language server claims to support.

# Step 14a: manifest-level -- only wht_corulix_lsp may depend on the
# admitted LSP 3.17 typed-model crate.
for crate in (
    "wht_corulix_core",
    "wht_corulix_workspace",
    "wht_corulix_search",
    "wht_corulix_syntax",
    "wht_corulix_index",
    "wht_corulix_config",
    "wht_corulix_tooling",
    "wht_corulix_engine",
    "wht_corulix_mcp",
    "wht_corulix_cli",
):
    if "ls-types" in dependency_names(crate):
        failures.append(
            f"{crate} has forbidden dependency: ls-types (Architecture Rule L violation)"
        )

# Step 14b: source-level defense in depth -- no other crate's source may
# reference the `ls_types` module path at all, even via a transitive
# re-export that bypassed the manifest-level check above.
for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir() or crate_dir.name == "wht_corulix_lsp":
        continue
    for path in (crate_dir / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        if "ls_types::" in text:
            failures.append(
                f"{path.relative_to(ROOT)} references ls_types outside "
                "wht_corulix_lsp (Architecture Rule L violation)"
            )
    for path in (
        (crate_dir / "tests").rglob("*.rs") if (crate_dir / "tests").exists() else ()
    ):
        text = path.read_text(encoding="utf-8")
        if "ls_types::" in text:
            failures.append(
                f"{path.relative_to(ROOT)} references ls_types outside "
                "wht_corulix_lsp (Architecture Rule L violation)"
            )

# Step 14c: only wht_corulix_lsp may implement LSP JSON-RPC/Content-Length
# framing (a second, competing transport implementation would be exactly
# the kind of authority split this rule forbids).
_lsp_framing_token = "Content-Length:"
for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir() or crate_dir.name == "wht_corulix_lsp":
        continue
    for path in (crate_dir / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        if _lsp_framing_token in text:
            failures.append(
                f"{path.relative_to(ROOT)} implements LSP Content-Length framing "
                "outside wht_corulix_lsp (Architecture Rule L violation)"
            )

# Step 15 (Rule M -- RULE_M_MUTATION_AUTHORITY, Phase 8): only
# wht_corulix_mutation may perform a governed live-workspace write.
# `MUTATION_MODEL=CORULIX_CONTROLLED`, `HOST_DIRECT_APPLY=FORBIDDEN`: Search,
# Syntax, LSP, MCP, CLI, Tooling, Config, and Workspace itself have no
# direct mutation authority -- Workspace owns confinement/canonicalization
# only (Rule F), never the write/rename/remove syscall itself.
#
# This scan deliberately excludes each file's own `#[cfg(test)]` region
# (everything from the first such attribute onward, by this repository's
# own consistent convention of putting the test module last) so it never
# false-positives on legitimate test-fixture setup, which every one of
# these crates' own test suites already uses (e.g. `wht_corulix_search`'s
# fixture files, `wht_corulix_config`'s fixture provider binaries).
MUTATION_WRITE_TOKENS = (
    "fs::write(",
    "fs::remove_file(",
    "fs::rename(",
    "fs::remove_dir_all(",
    "fs::remove_dir(",
    "fs::create_dir(",
    "fs::create_dir_all(",
)
_RULE_M_SCANNED_CRATES = (
    "wht_corulix_workspace",
    "wht_corulix_search",
    "wht_corulix_syntax",
    "wht_corulix_index",
    "wht_corulix_config",
    "wht_corulix_lsp",
    "wht_corulix_engine",
    "wht_corulix_tooling",
    "wht_corulix_formatter",
    "wht_corulix_mcp",
    "wht_corulix_cli",
)

# Rule M's rationale (`MUTATION_MODEL=CORULIX_CONTROLLED`,
# `HOST_DIRECT_APPLY=FORBIDDEN`) is specifically about a *workspace source
# file* mutation -- the governed, precondition/hash-checked ChangeSession/
# MutationBatch model. `wht_corulix_tooling::provisioning` (Phase 7B-A)
# writes to Corulix's *own* managed-toolchain application-data directory
# (`managed_toolchain_root()`, always outside any workspace -- proven by its
# own `MANAGED_TOOLCHAIN_OUTSIDE_WORKSPACE` test) with its own,
# independently-documented atomicity model (download -> verify hash ->
# extract to a sibling staging directory -> verify content -> a single
# atomic `fs::rename` into the canonical install path -- see that module's
# own doc comment). This is categorically not a workspace source-file write:
# there is no precondition hash, no collision semantics, no
# ChangeSession/MutationBatch involved, and no user-authored content is ever
# touched. The exemption is scoped to this one file only -- every other file
# in `wht_corulix_tooling` (`managed.rs`, `platform.rs`, `lib.rs`) remains
# fully scanned, so a *future* file in this crate that starts writing
# workspace-adjacent content is still caught.
# Phase 7B-B1 adds provisioning/ownership.rs (persists/removes the
# ManagedInstallationRecord ownership manifest under the same managed-
# toolchain application-data root) and provisioning/uninstall.rs (the
# transactional quarantine-by-rename uninstall pipeline that deletes only
# inside that same root, after canonicalizing every target through
# wht_corulix_workspace's Rule F primitive). Both are the same category of
# write as provisioning.rs itself -- Corulix's own managed-toolchain
# lifecycle, never a workspace source-file mutation -- so the same
# rationale extends to them rather than duplicating it.
# provisioning/full_uninstall.rs is the same category of write as the three
# files above -- its every `fs::rename` call site (the whole-managed-root
# cleanup quarantine/rollback in `full_uninstall` itself, and the per-
# component quarantine path in its rollback helper) operates exclusively on
# paths confined to the managed-toolchain root's own `.uninstall-txn/`
# transaction directory and `MANAGED_SCRATCH_DIR` scratch area -- never a
# workspace source file -- so the same Corulix-owned-lifecycle rationale
# extends to it too. It is already granted the equivalent exemption under
# Rule V's own `_RULE_V_REMOVE_DIR_ALL_ALLOWED` allowlist below.
# Installation-Contract-V1 adds provisioning/install_profile.rs: its `save`
# writes only `<managed_root>/install-profile.json` (via the same sibling
# `.tmp`-file-then-`fs::rename` atomicity convention `ownership.rs` already
# uses), and `ensure_bootstrapped` calls that same `save`. The persisted
# install-profile record is Corulix's own managed-toolchain lifecycle state,
# never a workspace source file, so the identical rationale applies.
_RULE_M_EXEMPT_FILES = frozenset(
    {
        ROOT / "wht_crates" / "wht_corulix_tooling" / "src" / "provisioning.rs",
        ROOT
        / "wht_crates"
        / "wht_corulix_tooling"
        / "src"
        / "provisioning"
        / "ownership.rs",
        ROOT
        / "wht_crates"
        / "wht_corulix_tooling"
        / "src"
        / "provisioning"
        / "uninstall.rs",
        ROOT
        / "wht_crates"
        / "wht_corulix_tooling"
        / "src"
        / "provisioning"
        / "full_uninstall.rs",
        ROOT
        / "wht_crates"
        / "wht_corulix_tooling"
        / "src"
        / "provisioning"
        / "install_profile.rs",
    }
)

for crate in _RULE_M_SCANNED_CRATES:
    for path in (ROOT / "wht_crates" / crate / "src").rglob("*.rs"):
        if path.name == "tests.rs":
            # A whole separate file that is itself only ever compiled
            # under `#[cfg(test)] mod tests;` in its parent module (e.g.
            # `wht_corulix_tooling`), so the attribute never appears
            # inside the file's own text for the split below to find.
            continue
        if path in _RULE_M_EXEMPT_FILES:
            continue
        text = path.read_text(encoding="utf-8")
        production_text = text.split("#[cfg(test)]", 1)[0]
        for token in MUTATION_WRITE_TOKENS:
            if token in production_text:
                failures.append(
                    f"{path.relative_to(ROOT)} performs a live filesystem write "
                    f"({token!r}) outside wht_corulix_mutation (Architecture Rule M "
                    "violation)"
                )

# Step 16 (Rule N -- RULE_N_FORMATTER_GOVERNANCE, Phase 9): only
# wht_corulix_formatter owns Rust formatter (rustfmt) governance.
# `RUSTFMT_FORMATTING_AUTHORITY=YES`, `LSP_FORMATTING_AUTHORITY=NO`.

# Step 16a: wht_corulix_lsp must never implement or claim
# `textDocument/formatting` as authoritative -- rustfmt remains the sole
# formatter authority regardless of what a language server advertises.
_lsp_src_dir = ROOT / "wht_crates" / "wht_corulix_lsp" / "src"
for path in _lsp_src_dir.rglob("*.rs"):
    text = path.read_text(encoding="utf-8")
    if "textDocument/formatting" in text:
        failures.append(
            f"{path.relative_to(ROOT)} references 'textDocument/formatting' "
            "(Architecture Rule N violation -- LSP_FORMATTING_AUTHORITY=NO, "
            "rustfmt remains the sole formatter authority)"
        )

# Step 16b: wht_corulix_formatter must actually resolve the "rustfmt"
# provider name through wht_corulix_config -- a positive-presence proof
# this crate has not silently detached from Rule K's canonical resolution
# entry point. Scans every `.rs` file in the crate (not just `lib.rs`):
# as of Phase 7B-B2-B, the `wht_corulix_config::resolve_provider(...,
# "rustfmt")` call site lives in `managed.rs` (the crate's own
# `CORULIX_MANAGED`-first-then-`HOST_ONLY` resolution glue, mirroring
# `wht_corulix_lsp::profile`'s precedent), not `lib.rs` directly -- the
# invariant this check proves (rustfmt is always resolved through the
# canonical Rule K entry point, never invented independently) does not
# depend on which file the call textually lives in.
_formatter_src_dir = ROOT / "wht_crates" / "wht_corulix_formatter" / "src"
_formatter_lib = _formatter_src_dir / "lib.rs"
if _formatter_lib.exists():
    _formatter_crate_files = sorted(_formatter_src_dir.rglob("*.rs"))
    _formatter_crate_text = "\n".join(
        path.read_text(encoding="utf-8") for path in _formatter_crate_files
    )
    if (
        "resolve_provider(" not in _formatter_crate_text
        or '"rustfmt"' not in _formatter_crate_text
    ):
        failures.append(
            f"{_formatter_lib.relative_to(ROOT)} does not resolve the 'rustfmt' "
            "provider through wht_corulix_config::resolve_provider (Architecture "
            "Rule N violation -- RUSTFMT_FORMATTING_AUTHORITY must be resolved "
            "via the canonical Rule K entry point, never invented independently)"
        )
    if "MutationExecutor" not in _formatter_crate_text:
        failures.append(
            f"{_formatter_lib.relative_to(ROOT)} does not reference "
            "wht_corulix_mutation::MutationExecutor (Architecture Rule N "
            "violation -- every live-workspace write this crate produces must "
            "flow through the canonical Rule M mutation authority)"
        )

    # Step 16c: wht_corulix_formatter must never itself construct a
    # MutationBatch/precondition-hash bypass shaped write -- i.e. it must
    # never define its own `fn execute(` that could compete with
    # `wht_corulix_mutation::MutationExecutor::execute`. This is defense in
    # depth on top of Step 16b's positive-presence check and Rule M's own
    # filesystem-write-token scan (which already covers this crate via
    # `_RULE_M_SCANNED_CRATES` above). Scans the whole crate, not just
    # `lib.rs`, for the same reason as Step 16b above.
    if re.search(r"\bfn execute\(", _formatter_crate_text):
        failures.append(
            f"wht_crates/wht_corulix_formatter/src defines its own 'fn execute(' "
            "(Architecture Rule N violation -- MutationBatch application must "
            "remain wht_corulix_mutation::MutationExecutor's sole entry point)"
        )

# Step 17 (Rule P -- RULE_P_MULTILANGUAGE_LSP_AUTHORITY, Phase 7B): typed,
# per-language LSP provider identity replaces any string-switch routing.
# `wht_corulix_lsp::profile::LspProviderProfile` is the sole owner of
# per-provider identity (readiness signal, `initializationOptions`,
# `textDocument/didOpen` languageId, auxiliary-tool resolution) -- no other
# crate may construct a profile by hand, and `crate::session` must never
# regress to a hard-coded single-language literal (the exact class of bug
# this phase's own regression audit found and fixed in the pre-Phase-7B
# `ensure_open`).

_lsp_profile_path = ROOT / "wht_crates" / "wht_corulix_lsp" / "src" / "profile.rs"
_lsp_session_path = ROOT / "wht_crates" / "wht_corulix_lsp" / "src" / "session.rs"

# Step 17a: no crate may hand-construct an `LspProviderProfile` value --
# every provider identity must go through one of profile.rs's own named
# constructors (e.g. `LspProviderProfile::rust_analyzer()`,
# `LspProviderProfile::gopls()`), never a struct literal assembled ad hoc
# elsewhere (which would silently reintroduce per-caller, un-audited
# provider behavior).
for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir():
        continue
    search_dirs = [crate_dir / "src"]
    if (crate_dir / "tests").exists():
        search_dirs.append(crate_dir / "tests")
    for search_dir in search_dirs:
        for path in search_dir.rglob("*.rs"):
            if path == _lsp_profile_path:
                continue
            text = path.read_text(encoding="utf-8")
            if "LspProviderProfile {" in text:
                failures.append(
                    f"{path.relative_to(ROOT)} hand-constructs an "
                    "LspProviderProfile struct literal outside "
                    "wht_corulix_lsp::profile (Architecture Rule P violation "
                    "-- every provider identity must go through profile.rs's "
                    "own named constructors)"
                )

# Steps 17b-17d read both profile.rs and session.rs once, guarded by a
# single existence check, so neither text variable is ever referenced
# unbound (mirrors this script's own established Rule N fix for the same
# possibly-unbound-variable class of issue).
if _lsp_profile_path.exists() and _lsp_session_path.exists():
    _profile_text = _lsp_profile_path.read_text(encoding="utf-8")
    _session_text = _lsp_session_path.read_text(encoding="utf-8")

    # Step 17b: `crate::session`'s didOpen path must never hard-code a
    # language literal -- it must read the languageId from the
    # caller-supplied profile, never a bare string like the pre-Phase-7B
    # `"rust".to_string()`.
    if re.search(r'language_id:\s*"[a-z]+"\.to_string\(\)', _session_text):
        failures.append(
            f"{_lsp_session_path.relative_to(ROOT)} hard-codes a literal "
            "language_id string (Architecture Rule P violation -- "
            "textDocument/didOpen's languageId must come from the caller-"
            "supplied LspProviderProfile, never a single-language literal)"
        )

    # Step 17c: every ReadinessStrategy variant profile.rs defines must be
    # handled by crate::session's notification pump -- a future provider
    # added to profile.rs with a readiness strategy the pump never
    # dispatches would silently never reach Readiness::Ready.
    _strategy_variants = (
        set(
            re.findall(
                r"^\s{4}(\w+),$",
                _profile_text.split("pub enum ReadinessStrategy {", 1)[-1].split(
                    "\n}", 1
                )[0],
                re.MULTILINE,
            )
        )
        if "pub enum ReadinessStrategy {" in _profile_text
        else set()
    )
    for variant in _strategy_variants:
        if f"ReadinessStrategy::{variant}" not in _session_text:
            failures.append(
                f"{_lsp_session_path.relative_to(ROOT)} never dispatches "
                f"ReadinessStrategy::{variant} (Architecture Rule P violation "
                "-- every readiness strategy profile.rs defines must be "
                "handled by the notification pump)"
            )

    # Step 17d: every LspProviderProfile::auxiliary_tools entry must be
    # resolved exclusively through wht_corulix_config::resolve_provider
    # (Rule K) -- never ambient PATH/`which` lookup, even for this phase's
    # new auxiliary-tool concept.
    if "auxiliary_tools" in _profile_text and "resolve_provider(" not in _profile_text:
        failures.append(
            f"{_lsp_profile_path.relative_to(ROOT)} declares auxiliary_tools "
            "but never resolves them via wht_corulix_config::resolve_provider "
            "(Architecture Rule P violation -- AMBIENT_PATH_LSP_AUTHORITY=NO "
            "applies to auxiliary tools exactly as it applies to the "
            "language-server binary itself)"
        )

# Step 17e: wht_corulix_engine::providers::ProviderSnapshot's per-language
# LanguageServer overlay must stay privately held -- only reachable through
# its own named accessor/constructor -- never a public field a caller could
# mutate without going through the typed resolution-overlay API.
_providers_path = ROOT / "wht_crates" / "wht_corulix_engine" / "src" / "providers.rs"
if _providers_path.exists():
    _providers_text = _providers_path.read_text(encoding="utf-8")
    if "pub language_server_by_language" in _providers_text:
        failures.append(
            f"{_providers_path.relative_to(ROOT)} exposes "
            "language_server_by_language as a public field (Architecture "
            "Rule P violation -- the per-language LanguageServer overlay "
            "must only be mutated through with_language_server_resolutions)"
        )
    if "language_server_availability_for" not in _providers_text:
        failures.append(
            f"{_providers_path.relative_to(ROOT)} does not define "
            "language_server_availability_for (Architecture Rule P "
            "violation -- Section 19's per-language provider-availability "
            "registry must be a real, reachable accessor, not merely "
            "documented intent)"
        )

# Step 17f (Rule P extension, Phase 7B final closure): an
# `LspProviderProfile` with `interpreter: Some(_)` must resolve that
# interpreter under `ProviderCategory::Runtime`, never under the same
# category as the provider it launches (e.g. `LanguageServer`) -- reusing
# the provider's own category was a real defect this phase found
# empirically: `HostConfig::provider_absolute_paths` is keyed by category
# alone, so a `HOST_ONLY` absolute-path override configured for the LSP
# provider would silently answer for the interpreter resolution too.
if _lsp_profile_path.exists():
    _profile_text = _lsp_profile_path.read_text(encoding="utf-8")
    if "interpreter: Some(AuxiliaryToolRequirement {" in _profile_text:
        _interpreter_blocks = re.findall(
            r"interpreter: Some\(AuxiliaryToolRequirement \{[^}]*\}\)",
            _profile_text,
        )
        for _block in _interpreter_blocks:
            if "ProviderCategory::Runtime" not in _block:
                failures.append(
                    f"{_lsp_profile_path.relative_to(ROOT)} resolves an "
                    "interpreter under a category other than "
                    "ProviderCategory::Runtime (Architecture Rule P "
                    "violation -- see the category-collision defect this "
                    "phase found and fixed)"
                )

    # Step 17g (Rule P extension): a script-provider's own shebang line
    # must never be relied upon in *code* -- this crate always constructs
    # argv explicitly with the resolved interpreter as the process
    # executable. Structural proof: `crate::profile` must never contain
    # `/usr/bin/env` as a Rust string literal (this deliberately excludes
    # `//`/`///` doc-comment prose explaining *why*, which legitimately
    # names the shebang path for the reader).
    if '"/usr/bin/env' in _profile_text:
        failures.append(
            f"{_lsp_profile_path.relative_to(ROOT)} references "
            "'/usr/bin/env' as a string literal (Architecture Rule P "
            "violation -- AMBIENT_PATH_NODE_AUTHORITY=NO: a script "
            "provider's own shebang line must never be read or relied upon "
            "in code)"
        )

# Step 17h (Rule P extension): the Engine's live routing path
# (`wht_corulix_engine::routing::evaluate`) must actually dispatch to the
# per-language overlay -- `LanguageServer == rust-analyzer` (or any single
# hard-coded provider) must not remain the live routing model now that a
# genuine per-language registry exists (Section 16 of the Phase 7B
# mandate).
_routing_path = ROOT / "wht_crates" / "wht_corulix_engine" / "src" / "routing.rs"
if _routing_path.exists():
    _routing_text = _routing_path.read_text(encoding="utf-8")
    if "language_server_availability_for" not in _routing_text:
        failures.append(
            f"{_routing_path.relative_to(ROOT)} never dispatches to "
            "language_server_availability_for (Architecture Rule P "
            "violation -- the live routing path must not remain "
            "category-only-shaped now that a per-language registry exists)"
        )

# Step 18 (Rule Q -- RULE_Q_TOOLING_LIFECYCLE_AUTHORITY, Phase
# 7B-B1-R3-B2-A2): full managed-lifecycle authority, process-lifecycle
# authority, and full-uninstall authority all remain exclusively in
# wht_corulix_tooling. Deliberately narrow (3 checks only) -- the mandate's
# own explicit instruction was not to attempt the full remaining B1
# architecture-rule matrix yet.

# Step 18a: product-uninstall delegates to the canonical Tooling full
# uninstall -- no other crate may define its own top-level
# `fn full_uninstall(` / `fn uninstall_all_corulix_managed_components`,
# and the canonical implementation must actually exist.
_full_uninstall_path = (
    ROOT
    / "wht_crates"
    / "wht_corulix_tooling"
    / "src"
    / "provisioning"
    / "full_uninstall.rs"
)
# Initialized here (mirrors this script's own established Rule N fix for
# the same possibly-unbound-variable class of issue) so Step 18c's later
# guarded read never references an unbound name.
_full_uninstall_text = ""
if not _full_uninstall_path.exists():
    failures.append(
        "wht_corulix_tooling/src/provisioning/full_uninstall.rs is missing "
        "(Architecture Rule Q violation -- the canonical Tooling full-uninstall "
        "primitive must exist)"
    )
else:
    _full_uninstall_text = _full_uninstall_path.read_text(encoding="utf-8")
    if (
        "pub async fn uninstall_all_corulix_managed_components_at("
        not in _full_uninstall_text
    ):
        failures.append(
            f"{_full_uninstall_path.relative_to(ROOT)} does not define "
            "uninstall_all_corulix_managed_components_at (Architecture Rule Q "
            "violation -- the product-uninstall boundary must delegate to an "
            "explicit-root-injected real implementation testable without unsafe "
            "code or environment mutation)"
        )
    if "async fn full_uninstall(" not in _full_uninstall_text:
        failures.append(
            f"{_full_uninstall_path.relative_to(ROOT)} does not define "
            "full_uninstall (Architecture Rule Q violation -- the canonical "
            "transactional full-uninstall primitive must exist)"
        )

for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir() or crate_dir.name == "wht_corulix_tooling":
        continue
    for search_dir in (crate_dir / "src", crate_dir / "tests"):
        if not search_dir.exists():
            continue
        for path in search_dir.rglob("*.rs"):
            text = path.read_text(encoding="utf-8")
            if re.search(r"\bfn\s+full_uninstall\s*\(", text) or re.search(
                r"\bfn\s+uninstall_all_corulix_managed_components\w*\s*\(", text
            ):
                failures.append(
                    f"{path.relative_to(ROOT)} defines its own "
                    "full_uninstall/uninstall_all_corulix_managed_components* "
                    "(Architecture Rule Q violation -- full-uninstall authority "
                    "remains exclusively wht_corulix_tooling's, every other crate "
                    "must call the canonical implementation, never duplicate it)"
                )

# Step 18b (Rule Q, remediated M09-P6VR): only wht_corulix_tooling may
# reference the real OS process-tree primitives (`rustix::process::`,
# `kill_process_group(`). Any other crate calling these directly would be
# constructing its own competing process-termination authority.
#
# The previous M09-P6 exemption for `wht_corulix_process_unix` excluded
# that ENTIRE crate from this rule by name -- the M09-P6V audit proved,
# via a scratch-copy negative control, that this let a synthetic
# `rustix::process::kill_process(...)` call added to that crate pass
# undetected (`wht_corulix_process_unix`'s own manifest already enables
# rustix's `process` feature for its one legitimate `fchdir` call, so no
# further dependency change would even be needed to add such a call for
# real). The exemption is narrowed here from "exempt the whole crate" to
# "every `rustix::process::<primitive>` reference this crate's own
# PRODUCTION source contains must name exactly the one authorized
# primitive, `fchdir`, and there must be exactly one such reference" --
# any other primitive (`kill_process`, `kill_process_group`, `setsid`,
# etc.), any bare `kill_process_group(` token, or a callsite count other
# than exactly one, fails closed exactly like any other crate. Test code
# in this crate is held to the same blanket ban as every other crate's
# test code always was (its own `dev-dependencies` intentionally omit
# rustix's `process` feature, so no test code there can reference these
# primitives at all today) -- only its `src/` production text (using the
# same structural, position-independent `#[cfg(test)]` extraction Rule G
# now uses) is eligible for the narrowed allowance.
RULE_Q_PROCESS_TOKEN_RE = re.compile(r"rustix::process::(\w+)")
RULE_Q_NARROW_EXCEPTION_CRATE = "wht_corulix_process_unix"
RULE_Q_NARROW_EXCEPTION_PRIMITIVE = "fchdir"
RULE_Q_NARROW_EXCEPTION_EXPECTED_COUNT = 1
_rule_q_narrow_exception_matches = 0
for crate_dir in sorted(crates_dir.iterdir()):
    if not crate_dir.is_dir() or crate_dir.name == "wht_corulix_tooling":
        continue
    _is_narrow_exception_crate = crate_dir.name == RULE_Q_NARROW_EXCEPTION_CRATE
    for search_dir in (crate_dir / "src", crate_dir / "tests"):
        if not search_dir.exists():
            continue
        for path in search_dir.rglob("*.rs"):
            text = path.read_text(encoding="utf-8")
            _eligible_for_narrow_allowance = (
                _is_narrow_exception_crate and search_dir.name == "src"
            )
            scan_text = (
                production_source_excluding_cfg_test(text)
                if _eligible_for_narrow_allowance
                else text
            )
            if "kill_process_group(" in scan_text:
                failures.append(
                    f"{path.relative_to(ROOT)} references a real OS process-tree "
                    "primitive directly (Architecture Rule Q violation -- process "
                    "lifecycle authority remains exclusively wht_corulix_tooling's)"
                )
            for _rule_q_match in RULE_Q_PROCESS_TOKEN_RE.finditer(scan_text):
                _primitive = _rule_q_match.group(1)
                if (
                    _eligible_for_narrow_allowance
                    and _primitive == RULE_Q_NARROW_EXCEPTION_PRIMITIVE
                ):
                    _rule_q_narrow_exception_matches += 1
                    continue
                failures.append(
                    f"{path.relative_to(ROOT)} references a real OS process-tree "
                    f"primitive directly (rustix::process::{_primitive}) (Architecture "
                    "Rule Q violation -- process lifecycle authority remains "
                    "exclusively wht_corulix_tooling's"
                    + (
                        f"; {RULE_Q_NARROW_EXCEPTION_CRATE}'s own narrow exception "
                        f"permits only rustix::process::{RULE_Q_NARROW_EXCEPTION_PRIMITIVE})"
                        if _is_narrow_exception_crate
                        else ")"
                    )
                )
if _rule_q_narrow_exception_matches != RULE_Q_NARROW_EXCEPTION_EXPECTED_COUNT:
    failures.append(
        f"wht_crates/{RULE_Q_NARROW_EXCEPTION_CRATE}'s own production source contains "
        f"{_rule_q_narrow_exception_matches} authorized "
        f"rustix::process::{RULE_Q_NARROW_EXCEPTION_PRIMITIVE} callsite(s), expected "
        f"exactly {RULE_Q_NARROW_EXCEPTION_EXPECTED_COUNT} (Architecture Rule Q "
        "violation -- the approved unix cwd-binding boundary's own authorized "
        "callsite count must stay exact, not merely non-zero)"
    )

# Step 18c: no loop-of-individual-uninstalls may stand in as the canonical
# full-uninstall implementation -- the global transaction primitive
# (`full_uninstall`) remains the sole authority, never
# `for component in components { uninstall(component) }`. Scoped narrowly
# to the two product-facing wrapper functions this rule actually governs
# (a workspace-wide "no for-loop near uninstall(" scan would be too
# fragile/false-positive-prone to be trustworthy, per this mandate's own
# instruction not to fake a validator PASS with a rule that cannot be
# robustly represented statically).
if _full_uninstall_path.exists():
    # Spans from the first wrapper's signature through to the start of the
    # canonical `full_uninstall` primitive itself -- i.e. both wrapper
    # function bodies in full, not merely the second one -- so a loop
    # inserted into *either* wrapper is caught.
    _wrapper_match = re.search(
        r"pub async fn uninstall_all_corulix_managed_components\(\)"
        r"(?P<body>.*?)"
        r"\npub async fn full_uninstall\(",
        _full_uninstall_text,
        re.DOTALL,
    )
    if _wrapper_match is None:
        failures.append(
            f"{_full_uninstall_path.relative_to(ROOT)}: could not locate the "
            "product-uninstall wrapper functions to check for loop authority "
            "(Architecture Rule Q violation -- the expected wrapper shape is "
            "missing or was restructured without updating this check)"
        )
    elif re.search(r"\bfor\b", _wrapper_match.group("body")):
        failures.append(
            f"{_full_uninstall_path.relative_to(ROOT)}: the product-uninstall "
            "wrapper contains a 'for' loop (Architecture Rule Q violation -- "
            "product-level full uninstall must delegate to the single global "
            "transaction primitive, never iterate individual component "
            "uninstalls as its own implementation)"
        )

# Step 19 (Rule R -- RULE_R_CHANGESESSION_FORMAT_STATE_ATOMICITY, Phase
# 10-R2): a governed format write and this session's own current-state
# advancement must remain one inseparable product operation -- the exact
# bypass this rule closes is a caller obtaining
# `wht_corulix_formatter::format_and_apply`'s real committed outcome
# through some path other than `wht_corulix_engine::session::ChangeSession
# ::format_and_apply`, which could then omit the paired
# `advance_content_state` call. `wht_corulix_engine/src/session.rs` is the
# one, sole authorized call site across the entire first-party workspace.
# Deliberately distinguishes the raw free-function
# `wht_corulix_formatter::format_and_apply(...)` (the actual bypass) from a
# `session.format_and_apply(...)`/`self.format_and_apply(...)` *method*
# call on `ChangeSession` (the sanctioned, governed boundary a future
# caller in another crate, e.g. the eventual P13 MCP tool handler, is
# expected to use) -- a bare identifier immediately preceded by `.` is
# never flagged.
_qualified_bypass_call = re.compile(
    r"wht_corulix_formatter::format_and_apply(_at)?\s*\("
)
_bare_import_of_symbol = re.compile(
    r"\buse\s+wht_corulix_formatter::(\{[^;]*\bformat_and_apply\b[^;]*\}|format_and_apply)\b"
)
_bare_free_function_call = re.compile(r"(?<![.\w])format_and_apply\s*\(")
_session_rs_path = ROOT / "wht_crates" / "wht_corulix_engine" / "src" / "session.rs"
for _crate_dir in sorted((ROOT / "wht_crates").iterdir()):
    _src_dir = _crate_dir / "src"
    if _crate_dir.name == "wht_corulix_formatter" or not _src_dir.is_dir():
        # The formatter crate defines `format_and_apply`/`format_and_apply_at`
        # itself (including its own internal `_impl` call), and its own
        # unit tests call it directly -- that is the definition, not a
        # bypass of this rule.
        continue
    for path in _src_dir.rglob("*.rs"):
        if path == _session_rs_path:
            continue
        text = path.read_text(encoding="utf-8")
        _violation = _qualified_bypass_call.search(text) or (
            _bare_import_of_symbol.search(text)
            and _bare_free_function_call.search(text)
        )
        if _violation:
            failures.append(
                f"{path.relative_to(ROOT)} calls the raw "
                "wht_corulix_formatter::format_and_apply(...) outside "
                "wht_corulix_engine/src/session.rs (Architecture Rule R "
                "violation -- ChangeSession::format_and_apply is the sole "
                "session-owned boundary pairing a governed format write with "
                "its own content-state advancement; no other production call "
                "site may reach the raw formatter function directly)"
            )

# Step 20 (Rule S -- RULE_S_MCP_CANONICAL_SURFACE, Phase 13): the MCP
# public surface is exactly 14 typed tools, `wht_corulix_mcp` stays a thin
# adapter (Architecture Rule B, sharpened this phase into a checked rule of
# its own letter), and no legacy ad-hoc-JSON-string tool shape survives.
MCP_LIB_PATH = ROOT / "wht_crates" / "wht_corulix_mcp" / "src" / "lib.rs"
_mcp_lib_text = MCP_LIB_PATH.read_text(encoding="utf-8")
# Production source only: this crate's own `#[cfg(test)] mod tests` block
# legitimately builds disposable temp-workspace fixtures (real
# `wht_corulix_workspace::WorkspaceRoot::open`, real `fs::write`) to drive
# real invocation tests -- that is test fixture setup, not a production
# bypass of Rule B/M/G, so every check below operates on the source that
# precedes the test module only.
_mcp_test_marker = "#[cfg(test)]"
_mcp_production_text = _mcp_lib_text.split(_mcp_test_marker, 1)[0]

# (a) Manifest-level: wht_corulix_mcp's production [dependencies] must
# never widen beyond the thin-adapter set.
#
# Contract Validation Gate admission (owner mandate): `jsonschema` is added
# here deliberately -- the centralized Contract Gate (`wht_corulix_mcp::
# contract_gate`) compiles/runs it entirely inside this crate (no new
# crate boundary, no circular dependency), validating every tool's
# input/output against the exact schema `rmcp::handler::server::common::
# schema_for_input`/`schema_for_output` already generate. This does not
# widen the thin-adapter *shape* (still zero business-logic crates beyond
# core/engine); it is a pure, synchronous, in-process validation library
# with no HTTP/file/async resolver features enabled (see this crate's own
# Cargo.toml comment).
_mcp_allowed_deps = {
    "wht_corulix_core",
    "wht_corulix_engine",
    "rmcp",
    "serde",
    "serde_json",
    "tokio",
    "tracing",
    "jsonschema",
}
for dep in dependency_names("wht_corulix_mcp"):
    if dep not in _mcp_allowed_deps:
        failures.append(
            f"wht_corulix_mcp has forbidden production dependency: {dep} "
            "(Architecture Rule S/B violation -- the MCP layer must stay a "
            "thin adapter over wht_corulix_core/wht_corulix_engine only)"
        )

# (b) Exactly 14 #[tool(...)] declarations -- `#[tool_router]`/
# `#[tool_handler]` share the `tool` identifier but never `#[tool(`.
_tool_count = len(re.findall(r"#\[tool\(", _mcp_production_text))
if _tool_count != 14:
    failures.append(
        f"wht_corulix_mcp declares {_tool_count} #[tool(...)] entries, "
        "expected exactly 14 (Architecture Rule S violation -- "
        "FINAL_MCP_TOOL_COUNT=14)"
    )

# (c) No legacy tool name reappears, and no tool reverts to the retired
# ad-hoc-JSON-string response shape (`-> String`) -- every canonical tool
# returns a typed `CallToolResult` with real structuredContent/outputSchema.
_legacy_tool_fn_pattern = re.compile(r"fn\s+\w+\([^)]*\)\s*->\s*String\s*\{")
if _legacy_tool_fn_pattern.search(_mcp_production_text):
    failures.append(
        "wht_corulix_mcp still declares a tool handler returning a plain "
        "String (Architecture Rule S violation -- the retired ad-hoc-JSON "
        "response shape must not reappear)"
    )

# (d) wht_corulix_mcp must never construct a process directly (Rule G is
# unaffected -- this crate is added to that rule's own scanned-crate list
# too, immediately below).
for _token in ("std::process::Command", "Command::new(", "tokio::process::Command"):
    if _token in _mcp_production_text:
        failures.append(
            f"wht_corulix_mcp contains forbidden token {_token!r} "
            "(Architecture Rule S/G violation -- it must never spawn a "
            "process directly, only wht_corulix_tooling may)"
        )

# (e) wht_corulix_mcp must never mutate the workspace filesystem directly
# -- every live write goes through wht_corulix_engine::session::ChangeSession
# (which itself owns the sole wht_corulix_mutation::MutationExecutor, per
# Rule M).
for _token in (
    "std::fs::write(",
    "std::fs::remove_file(",
    "std::fs::remove_dir",
    "tokio::fs::write(",
    "tokio::fs::remove_file(",
    "File::create(",
):
    if _token in _mcp_production_text:
        failures.append(
            f"wht_corulix_mcp contains forbidden token {_token!r} "
            "(Architecture Rule S/M violation -- it must never write to "
            "the workspace directly, only wht_corulix_mutation::"
            "MutationExecutor -- reached exclusively through "
            "wht_corulix_engine::session::ChangeSession -- may)"
        )

# (f) wht_corulix_mcp must never call Search/LSP/Tooling/Formatter/Mutation
# directly -- every one of those is reached only through
# wht_corulix_engine's own public API.
for _token in (
    "wht_corulix_search::",
    "wht_corulix_lsp::",
    "wht_corulix_tooling::",
    "wht_corulix_formatter::",
    "wht_corulix_mutation::",
):
    # Production text only (see `_mcp_production_text` above): this
    # crate's own `#[cfg(test)] mod tests` block legitimately provisions
    # real managed rust-analyzer/rustfmt fixtures directly (Phase 13 items
    # 3/4's own real E2E tests) to prove the real capability
    # `wht_corulix_engine` exposes -- that is real-fixture test setup, not
    # a production bypass of Rule B; only code reachable by the release
    # `corulix` binary is checked here.
    if _token in _mcp_production_text:
        failures.append(
            f"wht_corulix_mcp contains forbidden token {_token!r} "
            "(Architecture Rule S/B violation -- Search/LSP/Tooling/"
            "Formatter/Mutation are reachable only through "
            "wht_corulix_engine's own public API, never directly)"
        )

# (g) No MCP Roots capability usage anywhere in this crate (deprecated by
# SEP-2577; this server never advertises or reads one).
for _token in ("RootsCapability", "list_roots", ".roots(", "roots_list_changed"):
    if _token in _mcp_lib_text:
        failures.append(
            f"wht_corulix_mcp contains forbidden token {_token!r} "
            "(Architecture Rule S violation -- no MCP Roots capability "
            "usage is permitted)"
        )

# (h) No MCP protocol Logging capability usage -- `ServerCapabilities::
# logging` must stay unset (`None` via `Default`/the `.builder()` path,
# which has no logging-enabling method at all in the admitted rmcp SDK).
for _token in ("enable_logging", "capabilities.logging = Some", ".logging = Some("):
    if _token in _mcp_lib_text:
        failures.append(
            f"wht_corulix_mcp contains forbidden token {_token!r} "
            "(Architecture Rule S violation -- no MCP protocol Logging "
            "capability usage is permitted)"
        )

# Step 21 (Rule S continued): extend Rule G's process-construction scan and
# Rule M's live-write scan to explicitly cover wht_corulix_mcp too, using
# the same production-source (pre-`#[cfg(test)]`) text.
if (
    "Command::new(" in _mcp_production_text
    or "process::Command" in _mcp_production_text
):
    failures.append(
        "wht_corulix_mcp production source constructs a process directly "
        "(Architecture Rule G violation)"
    )

# Step 22 (Rule T -- RULE_T_HOST_ENFORCEMENT_HONESTY): host enforcement is a
# per-host, per-version, per-configuration property. Documentation may state
# the global routing boundary only as HOST_DEPENDENT, and a preventive claim
# about a specific host is legitimate only when that host owns a canonical
# machine-readable profile carrying real evidence. This is a real structural
# boundary: the profiles are the single authority, and prose must not be able
# to out-claim them.
_HOST_PROFILE_DIR = ROOT / "wht_docs" / "wht_host_profiles"
_REQUIRED_HOST_PROFILES = (
    "wht_claude_code.toml",
    "wht_codex.toml",
    "wht_opencode.toml",
    "wht_vscode_copilot_chat.toml",
)
_REQUIRED_PROFILE_KEYS = (
    "profile_id",
    "host",
    "tested_version",
    "certified_host_version",
    "certification_date",
    "mcp_transport",
    "can_prevent_bypass",
    "can_detect_bypass",
    "can_only_advise",
    "required_configuration",
    "known_limitations",
    "certification_scope",
    "evidence_type",
    "evidence_reference",
)
_ALLOWED_CLASSIFICATIONS = {"YES", "NO", "PARTIAL"}

# Rule T.1: every required profile exists, parses, and carries every
# mandatory field with a classification drawn from the strict vocabulary.
for _profile_name in _REQUIRED_HOST_PROFILES:
    _profile_path = _HOST_PROFILE_DIR / _profile_name
    if not _profile_path.is_file():
        failures.append(
            f"missing canonical host enforcement profile {_profile_name} "
            "(Architecture Rule T violation)"
        )
        continue
    try:
        _profile = tomllib.loads(_profile_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as _exc:
        failures.append(
            f"host enforcement profile {_profile_name} is not valid TOML: "
            f"{_exc} (Architecture Rule T violation)"
        )
        continue
    for _key in _REQUIRED_PROFILE_KEYS:
        if _key not in _profile:
            failures.append(
                f"host enforcement profile {_profile_name} omits the "
                f"mandatory field '{_key}' (Architecture Rule T violation)"
            )
    for _key in ("can_prevent_bypass", "can_detect_bypass", "can_only_advise"):
        _value = _profile.get(_key)
        if _value is not None and _value not in _ALLOWED_CLASSIFICATIONS:
            failures.append(
                f"host enforcement profile {_profile_name} field '{_key}' is "
                f"{_value!r}, which is outside the strict classification "
                "vocabulary YES/NO/PARTIAL (Architecture Rule T violation)"
            )

# Rule T.2: no document may assert the global routing boundary as PROVABLE,
# and no document may claim a host cannot be bypassed in the abstract. The
# only admissible global statement is HOST_DEPENDENT.
_GLOBAL_ENFORCEMENT_CLAIM = re.compile(
    r"HOST_GLOBAL_ROUTING_ENFORCEMENT\s*=\s*PROVABLE"
)
_UNQUALIFIED_BYPASS_CLAIMS = (
    re.compile(r"(?:the\s+)?AI\s+cannot\s+bypass\s+Corulix", re.IGNORECASE),
    re.compile(r"cannot\s+be\s+bypassed\s+by\s+any\s+host", re.IGNORECASE),
)
_DOC_ROOTS = (ROOT / "wht_docs", ROOT / "README.md", ROOT / "CHANGELOG.md")
_scanned_docs: list[Path] = []
for _doc_root in _DOC_ROOTS:
    if _doc_root.is_file():
        _scanned_docs.append(_doc_root)
    elif _doc_root.is_dir():
        _scanned_docs.extend(sorted(_doc_root.rglob("*.md")))
        _scanned_docs.extend(sorted(_doc_root.rglob("*.toml")))

for _doc in _scanned_docs:
    _text = _doc.read_text(encoding="utf-8", errors="replace")
    _relative = _doc.relative_to(ROOT)
    if _GLOBAL_ENFORCEMENT_CLAIM.search(_text):
        failures.append(
            f"{_relative} asserts HOST_GLOBAL_ROUTING_ENFORCEMENT=PROVABLE; "
            "host routing enforcement is host-dependent and may only be "
            "claimed per host through a certified profile "
            "(Architecture Rule T violation)"
        )
    for _pattern in _UNQUALIFIED_BYPASS_CLAIMS:
        if _pattern.search(_text):
            failures.append(
                f"{_relative} makes an unqualified claim that Corulix cannot "
                "be bypassed; such a claim requires a specific host profile "
                "with real evidence (Architecture Rule T violation)"
            )

# =====================================================================
# Step 23 (Rule U -- RULE_U_GO_PROVIDER_BOUNDARY, Phase 15): the Go
# provider vertical must be *routed through* existing machinery, never
# reimplemented alongside it.
#
# P15 added Go as a fully governed language (gopls semantic, gofmt
# formatter, go build/vet validation, go test behavioural authority). The
# real risk that introduces is not a missing feature but a duplicated
# authority: a second process runtime, a second provider resolver, a second
# trust gate, a formatter with live-write authority, or Go provider logic
# leaking into the MCP adapter. Each check below is structural (a named
# module's real content, or a real manifest), not a repository-wide grep for
# a suggestive word.
# =====================================================================

_GO_ENGINE_MODULES = (
    "go_providers.rs",
    "go_validation.rs",
    "go_testing.rs",
)
_go_engine_src = ROOT / "wht_crates" / "wht_corulix_engine" / "src"
_go_module_texts: dict[str, str] = {}
for _module in _GO_ENGINE_MODULES:
    _path = _go_engine_src / _module
    if not _path.is_file():
        failures.append(
            f"wht_corulix_engine/src/{_module} is missing -- the Go vertical's "
            "named boundary module must exist (Architecture Rule U violation)"
        )
        continue
    _text = _path.read_text(encoding="utf-8")
    # Production half only: a module's own #[cfg(test)] block legitimately
    # builds fixtures, exactly as `scan()` already reasons.
    _go_module_texts[_module] = _text.split("#[cfg(test)]", 1)[0]

# Rule U.1: no Go module may construct a process itself -- every Go
# invocation goes through wht_corulix_tooling (Rule G, restated for the
# specific modules P15 added so a future edit cannot quietly regress it).
for _module, _text in _go_module_texts.items():
    for _token in ("Command::new(", "std::process::Command", "tokio::process::Command"):
        if _token in _text:
            failures.append(
                f"wht_corulix_engine/src/{_module} constructs a process directly "
                f"('{_token}') -- only wht_corulix_tooling may "
                "(Architecture Rule U/G violation)"
            )

# Rule U.2: the Go validators/test runner must genuinely spawn through
# Tooling's canonical entry point, not merely avoid Command.
#
# M09-P10 update (owner-authorized narrow Rule U.2 synchronization,
# `M09_P10_ARCHITECTURE_VERIFIER_MUTATION_SCOPE=RULE_U2_X2_SECURE_WORKSPACE_ENTRYPOINT_REQUIREMENT_ONLY`,
# mirrors the M09-P7 Rule U.12 precedent above): `go_validation.rs`/
# `go_testing.rs` are `TRUSTED_WORKSPACE_EXECUTION` -- their production spawn
# must be `wht_corulix_tooling::execute_with_workspace_root(`, the secure,
# object-bound-on-Unix/fail-closed-on-Windows entry point, never the legacy
# pathname-cwd `wht_corulix_tooling::execute(`. The legacy token is
# deliberately NOT accepted as an alternative here: accepting it would let a
# future regression back onto the unpinned/pathname-cwd route pass this gate
# silently (`M09_P10_RULE_U2_LEGACY_WORKSPACE_ROUTE_ACCEPTED=NO`,
# `M09_P10_RULE_U2_SECURE_WORKSPACE_ROUTE_REQUIRED=YES`). This does not ban
# `wht_corulix_tooling::execute(` from appearing elsewhere in these modules --
# a genuinely `CONTROLLED_EXTERNAL_TOOL_NON_WORKSPACE` call site may still use
# it -- it only stops that unrelated call from being sufficient evidence that
# the workspace-bound route itself is secure.
#
# M09-P10 second update (owner-authorized comment/string-bypass
# remediation, `M09_P10_ARCHITECTURE_VERIFIER_MUTATION_SCOPE=
# RULE_ROUTE_TOKEN_COMMENT_STRING_HARDENING_AND_TS_COVERAGE`): checked
# against `strip_route_evidence_view(_text)`, never the raw production
# text -- a comment or string literal that merely NAMES the secure token
# (e.g. `// FAKE EVIDENCE PROBE: wht_corulix_tooling::execute_with_workspace_root(`)
# no longer satisfies this check (closes the P10 negative-control-G gap).
for _module in ("go_validation.rs", "go_testing.rs"):
    _text = _go_module_texts.get(_module, "")
    _route_evidence = strip_route_evidence_view(_text) if _text else ""
    if (
        _text
        and "wht_corulix_tooling::execute_with_workspace_root(" not in _route_evidence
    ):
        failures.append(
            f"wht_corulix_engine/src/{_module} does not spawn its workspace-bound "
            "execution through a genuine (non-comment, non-string) call to "
            "wht_corulix_tooling::execute_with_workspace_root( -- the secure, "
            "object-bound/fail-closed workspace entry point is mandatory for "
            "TRUSTED_WORKSPACE_EXECUTION; the legacy pathname-cwd "
            "wht_corulix_tooling::execute( does not satisfy this requirement, and "
            "neither does the token's name appearing only in a comment or string "
            "(Architecture Rule U.2/G violation)"
        )

# Rule U.3: no second trust gate. The Go validators/test runner must reuse
# `crate::diagnostics::authorize_trusted_execution` and must never evaluate
# `is_execution_class_allowed` themselves -- a private re-derivation of the
# trust decision is exactly how a trust gate silently stops being
# load-bearing.
for _module in ("go_validation.rs", "go_testing.rs"):
    _text = _go_module_texts.get(_module, "")
    if not _text:
        continue
    if "authorize_trusted_execution" not in _text:
        failures.append(
            f"wht_corulix_engine/src/{_module} never calls "
            "authorize_trusted_execution -- go build/vet/test are "
            "TRUSTED_WORKSPACE_EXECUTION and must be trust-gated "
            "(Architecture Rule U violation)"
        )
    if "is_execution_class_allowed" in _text:
        failures.append(
            f"wht_corulix_engine/src/{_module} evaluates is_execution_class_allowed "
            "directly -- it must reuse the one shared trust gate, never derive a "
            "second (Architecture Rule U violation)"
        )

# Rule U.4: no second provider resolver. Go provider resolution must go
# through `wht_corulix_config::resolve_provider` (Rule K), and no Go module
# may read an approved-directory list or an ambient PATH itself.
_providers_text = _go_module_texts.get("go_providers.rs", "")
if _providers_text and "wht_corulix_config::resolve_provider(" not in _providers_text:
    failures.append(
        "wht_corulix_engine/src/go_providers.rs does not resolve through "
        "wht_corulix_config::resolve_provider( -- wht_corulix_config is the sole "
        "provider-resolution authority (Architecture Rule U/K violation)"
    )
for _module, _text in _go_module_texts.items():
    for _token in (
        'env::var("PATH")',
        "approved_system_directories",
        "approved_user_toolchain_directories",
    ):
        if _token in _text:
            failures.append(
                f"wht_corulix_engine/src/{_module} inspects '{_token}' -- provider "
                "authority belongs to wht_corulix_config alone, and ambient PATH "
                "carries none (Architecture Rule U/K violation)"
            )

# Rule U.5: the Go toolchain's security-critical environment controls must
# stay present and must never be relaxed. `GOTOOLCHAIN=local` is what stops a
# repository-authored `go.mod` `toolchain` directive from downloading and
# executing a different toolchain (empirically confirmed in Phase 15);
# `-mod=readonly` is what stops the Go command rewriting the repository's own
# `go.mod`/`go.sum` as a validation side effect.
if _providers_text:
    for _required in (
        '"GOTOOLCHAIN", "local"',
        '"GOPROXY", "off"',
        '"GOFLAGS", "-mod=readonly"',
    ):
        if _required not in _providers_text:
            failures.append(
                f"wht_corulix_engine/src/go_providers.rs no longer sets {_required} "
                "-- this control is load-bearing for "
                "P15_AUTO_INSTALL_EXTERNAL_TOOLING=NO / no-go.mod-mutation "
                "(Architecture Rule U violation)"
            )
    # The real `with_var` call, not the bare substring: this module's own doc
    # comment legitimately *names* `-mod=mod` to explain why it is rejected,
    # and a rule that fired on prose would punish the documentation rather
    # than the behaviour.
    if '"GOFLAGS", "-mod=mod"' in _providers_text:
        failures.append(
            "wht_corulix_engine/src/go_providers.rs permits GOFLAGS=-mod=mod -- that "
            "authorizes the Go command to rewrite the repository's own go.mod "
            "(Architecture Rule U violation)"
        )

# Rule U.6: `go build` must never write its compiled artifact into the
# governed workspace. Bare `go build` was empirically confirmed to drop the
# binary into the module directory, so the output redirection is mandatory.
_validation_text = _go_module_texts.get("go_validation.rs", "")
if _validation_text and '"-o".to_string()' not in _validation_text:
    failures.append(
        "wht_corulix_engine/src/go_validation.rs no longer redirects `go build`'s "
        "output -- bare `go build` writes the compiled binary into the governed "
        "workspace (Architecture Rule U/M violation)"
    )

# Rule U.7: the Go formatter must never be able to write live source itself.
# Real `gofmt` writes in place only when given `-w`; the formatter crate's
# production source must therefore never contain that flag anywhere.
_formatter_src = ROOT / "wht_crates" / "wht_corulix_formatter" / "src"
for _path in _formatter_src.rglob("*.rs"):
    _production = _path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
    for _flag in ('"-w"', '"--write"', '"--in-place"'):
        if _flag in _production:
            failures.append(
                f"wht_corulix_formatter/src/{_path.name} references the in-place "
                f"write flag {_flag} -- the formatter must never hold live-write "
                "authority; only wht_corulix_mutation does "
                "(Architecture Rule U/N/M violation)"
            )

# Rule U.8: no Go provider logic in the MCP adapter. `wht_corulix_mcp` must
# reach Go exclusively through `wht_corulix_engine`'s public API -- it may
# never name a Go provider binary or call a Go provider entry point. Checked
# against production source only (the crate's own #[cfg(test)] block
# legitimately builds real Go fixtures for its E2E tests, exactly as Rule S
# already permits for its other fixtures).
_mcp_src = ROOT / "wht_crates" / "wht_corulix_mcp" / "src"
_GO_PROVIDER_LEAK_TOKENS = (
    "gopls",
    "gofmt",
    "resolve_go_toolchain",
    "run_go_validator",
    "run_go_test",
    "go_environment(",
    "GoValidator",
)
for _path in _mcp_src.rglob("*.rs"):
    _production = _path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
    for _token in _GO_PROVIDER_LEAK_TOKENS:
        if _token in _production:
            failures.append(
                f"wht_corulix_mcp/src/{_path.name} references Go provider detail "
                f"('{_token}') in production source -- Go must be reachable only "
                "through wht_corulix_engine's public API "
                "(Architecture Rule U/S/B violation)"
            )

# Rule U.9: no second LSP client for Go. Only wht_corulix_lsp may own a gopls
# session; the Engine must route through its profile/session API rather than
# constructing transport itself.
for _module, _text in _go_module_texts.items():
    for _token in ("Content-Length", "textDocument/", "jsonrpc"):
        if _token in _text:
            failures.append(
                f"wht_corulix_engine/src/{_module} contains LSP protocol detail "
                f"('{_token}') -- wht_corulix_lsp is the sole LSP authority "
                "(Architecture Rule U/L violation)"
            )

# Rule U.10: no production test seam anywhere in the Go vertical. A public
# force/skip/fake switch is how a governed vertical silently stops being
# governed.
_GO_FORBIDDEN_SEAMS = (
    "force_gopls_available",
    "skip_go_trust_gate",
    "fake_go_test_success",
    "force_gofmt_success",
    "disable_go_provider_validation",
)
for _crate in (
    "wht_corulix_engine",
    "wht_corulix_formatter",
    "wht_corulix_lsp",
    "wht_corulix_mcp",
):
    for _path in (ROOT / "wht_crates" / _crate / "src").rglob("*.rs"):
        _text = _path.read_text(encoding="utf-8")
        for _seam in _GO_FORBIDDEN_SEAMS:
            if _seam in _text:
                failures.append(
                    f"{_crate}/src/{_path.name} defines or references the forbidden "
                    f"test seam '{_seam}' (Architecture Rule U violation)"
                )

# Rule U.11 (P15 production-routing regression closure): the Go validation
# providers must have a *production Engine route*, not merely exist as
# named modules. A P16 discovery pass found `run_go_validator`/`run_go_test`
# reachable only from their own modules' unit tests and a standalone E2E
# file -- never from `validate_change`, the real capability behind the
# `validate_change` MCP tool. Rule U.8 above already guarantees these
# providers cannot be invoked directly from MCP; this check guarantees the
# complementary half -- that the Engine's own production dispatcher
# (`validate_change.rs`) genuinely calls them, so a future edit cannot
# silently regress back to Rust-only dispatch while leaving the Go modules
# looking wired. Checked against production source only (the module's own
# `#[cfg(test)]` block legitimately calls these too, for its unit tests).
_validate_change_path = _go_engine_src / "validate_change.rs"
_validate_change_production = ""
if not _validate_change_path.is_file():
    failures.append(
        "wht_corulix_engine/src/validate_change.rs is missing -- the production "
        "validate_change capability must exist (Architecture Rule U/H violation)"
    )
else:
    _validate_change_production = _validate_change_path.read_text(
        encoding="utf-8"
    ).split("#[cfg(test)]", 1)[0]
    for _token in ("go_validation::run_go_validator(", "go_testing::run_go_test("):
        if _token not in _validate_change_production:
            failures.append(
                f"wht_corulix_engine/src/validate_change.rs does not call '{_token}' "
                "in its production dispatch path -- the Go validation providers have "
                "no production Engine route (Architecture Rule U violation)"
            )
    # And the reverse of Rule U.8: `validate_change.rs` must actually branch on
    # the session's declared language, never hardcode a single language's
    # validator regardless of what `ChangeSession::language()` reports --
    # that hardcoding is the literal shape of the regression this rule exists
    # to prevent from recurring.
    if "session.language()" not in _validate_change_production:
        failures.append(
            "wht_corulix_engine/src/validate_change.rs no longer dispatches on "
            "session.language() -- language-aware routing is mandatory "
            "(Architecture Rule U violation)"
        )

# Rule U.12 (Rust production-routing regression closure, mirrors Rule U.11
# exactly, for the Rust vertical): `diagnostics::run_clippy_with_workspace_root`
# and `testing::run_cargo_test_with_workspace_root` must have a *production
# Engine route*, not merely exist as fully-implemented, individually-unit-
# tested functions. A closure pass found `validate_change_rust` called only
# `diagnostics::run_cargo_check` unconditionally, with clippy/`cargo test`
# reachable only from their own modules' unit tests -- the identical shape of
# gap Rule U.11 already closed for Go. This check guarantees the production
# dispatcher genuinely calls both, and that it consults
# `ChangeSession::requirement_authority` before running `cargo check` at all
# (Minimum Sufficient Tooling), so a future edit cannot silently regress back
# to an unconditional, policy-blind `cargo check`-only call while leaving
# `run_clippy`/`run_cargo_test` looking wired.
#
# M09-P7 update (owner-authorized narrow Rule U.12 synchronization,
# `M09_P7_ARCHITECTURE_VERIFIER_MUTATION_SCOPE=RULE_U12_SECURE_ROUTE_TOKEN_UPDATE_ONLY`):
# P7 wired every workspace-bound Rust validator through
# `WorkspaceRoot::bind_process_cwd`'s pinned-root-object cwd authority
# instead of a re-resolvable pathname, via new, additive
# `_with_workspace_root` entry points (`wht_corulix_tooling::execute_with_workspace_root`,
# `diagnostics::run_clippy_with_workspace_root`,
# `testing::run_cargo_test_with_workspace_root`) that leave the original
# `run_clippy`/`run_cargo_test`/`ProcessSpec` public API untouched
# (`EXTERNAL_PUBLIC_RUST_API_BREAK=NO`). The production route in
# `validate_change_rust` now uses these secure entry points exclusively, so
# the required tokens are updated to match -- deliberately NOT accepting the
# legacy pathname-based token as an alternative, since that would let a
# future regression back onto the unpinned route pass this gate silently
# (`M09_P7_RULE_U12_LEGACY_WORKSPACE_ROUTE_ACCEPTED=NO`,
# `M09_P7_RULE_U12_PINNED_WORKSPACE_ROUTE_REQUIRED=YES`). Checked against
# production source only (the module's own `#[cfg(test)]` block legitimately
# calls the legacy functions too, for its own unit tests).
if _validate_change_path.is_file():
    for _token in (
        "diagnostics::run_clippy_with_workspace_root(",
        "testing::run_cargo_test_with_workspace_root(",
    ):
        if _token not in _validate_change_production:
            failures.append(
                f"wht_corulix_engine/src/validate_change.rs does not call '{_token}' "
                "in its production dispatch path -- the Rust clippy/cargo-test "
                "validation providers have no production, pinned-workspace-root "
                "Engine route (Architecture Rule U.12 violation)"
            )
    if (
        "requirement_authority(ProviderCategory::TypecheckBuild)"
        not in _validate_change_production
    ):
        failures.append(
            "wht_corulix_engine/src/validate_change.rs no longer consults "
            "ChangeSession::requirement_authority(TypecheckBuild) before running "
            "cargo check -- validate_change_rust must not hardcode an "
            "unconditional cargo-check-only policy (Architecture Rule U.12 "
            "violation)"
        )

# Rule U.12 also forbids the MCP adapter from ever calling into the Rust
# validator implementation modules directly -- the mirror of Rule U.8, for
# Rust. `wht_corulix_mcp` must reach clippy/cargo test/cargo check
# exclusively through `wht_corulix_engine::CorulixEngine::validate_change`.
#
# M09-P7R update (owner-authorized narrow anti-leak token-set
# synchronization, `M09_P7R_ARCHITECTURE_VERIFIER_MUTATION_SCOPE=PROVIDER_ANTILEAK_TOKEN_SET_ONLY`):
# P7 introduced additive, secure `_with_workspace_root` provider entry
# points (`diagnostics::run_cargo_check_with_workspace_root`,
# `diagnostics::run_clippy_with_workspace_root`,
# `testing::run_cargo_test_with_workspace_root`,
# `testing::run_cargo_test_with_limits_and_workspace_root`) alongside the
# original legacy names. Both the legacy AND the new secure names are
# forbidden here -- `wht_corulix_mcp` must never call ANY of them directly,
# regardless of which cwd-authority model a given provider name uses; only
# `wht_corulix_engine::CorulixEngine::validate_change` may.
_RUST_PROVIDER_LEAK_TOKENS = (
    "run_cargo_check(",
    "run_cargo_check_with_workspace_root(",
    "run_clippy(",
    "run_clippy_with_workspace_root(",
    "run_cargo_test(",
    "run_cargo_test_with_workspace_root(",
    "run_cargo_test_with_limits_and_workspace_root(",
    "resolve_clippy_binaries(",
    "managed_environment(",
)
for _path in _mcp_src.rglob("*.rs"):
    _production = _path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
    for _token in _RUST_PROVIDER_LEAK_TOKENS:
        if _token in _production:
            failures.append(
                f"wht_corulix_mcp/src/{_path.name} references a Rust validator "
                f"implementation detail ('{_token}') in production source -- Rust "
                "validation must be reachable only through "
                "wht_corulix_engine::CorulixEngine::validate_change "
                "(Architecture Rule U.12/B violation)"
            )

# ---------------------------------------------------------------------------
# Rule V (RULE_V_MANAGED_CACHE_LIFECYCLE): the managed execution cache is
# owned, tracked and removed by exactly one authority.
#
# Phase 15's cache closure introduced a durable structural boundary, so it is
# encoded here rather than left to review: a governed execution's build/module
# cache lives under `<managed root>/scratch/`, is created only through
# `provisioning::ensure_scratch_directory`, and is destroyed only by the
# existing `full_uninstall` transaction. The failure modes below are exactly
# the ones that would silently reintroduce a second deletion authority --
# `P15_NEW_GLOBAL_DELETE_AUTHORITY_COUNT=0`,
# `P15_CACHE_LIFECYCLE_ARCHITECTURE_RULES=PASS`.
# ---------------------------------------------------------------------------

# V.1: recursive deletion of a whole subtree is the one primitive that could
# delete state Corulix does not own. In production source it may appear only
# in the two provisioning lifecycle modules that already hold the
# quarantine/destroy authority, plus `wht_corulix_mutation` (the governed
# workspace-write authority, Rule M).
_RULE_V_REMOVE_DIR_ALL_ALLOWED = {
    "wht_corulix_tooling/src/provisioning/full_uninstall.rs",
    "wht_corulix_tooling/src/provisioning/uninstall.rs",
    "wht_corulix_tooling/src/provisioning.rs",
}
for _crate in _RULE_M_SCANNED_CRATES:
    for _path in (ROOT / "wht_crates" / _crate / "src").rglob("*.rs"):
        # A whole-file test module (`tests.rs`, compiled only under
        # `#[cfg(test)]` via its parent's `mod tests;`) is not production
        # source -- the same exemption Rule M's own scan applies.
        if _path.name == "tests.rs":
            continue
        _text = _path.read_text(encoding="utf-8")
        # Same `#[cfg(test)]`-tail convention Rule M's own scan uses.
        _marker = _text.find("#[cfg(test)]")
        _production = _text if _marker == -1 else _text[:_marker]
        if "fs::remove_dir_all(" not in _production:
            continue
        _relative = _path.relative_to(ROOT / "wht_crates").as_posix()
        if _relative in _RULE_V_REMOVE_DIR_ALL_ALLOWED:
            continue
        if _crate == "wht_corulix_mutation":
            continue
        failures.append(
            f"{_relative} performs a recursive subtree deletion "
            f"('fs::remove_dir_all(') in production source; only the managed "
            f"lifecycle's own quarantine/destroy authority may "
            f"(Architecture Rule V.1 violation)"
        )

# V.2: no shell-based deletion anywhere. `NO_SHELL_DELETION=YES`.
_RULE_V_SHELL_DELETION_TOKENS = (
    '"rm"',
    "'rm'",
    '"rmdir"',
    '"del"',
    '"rd"',
    "rm -rf",
    "rm -fr",
)
for _crate in _RULE_M_SCANNED_CRATES:
    for _path in (ROOT / "wht_crates" / _crate / "src").rglob("*.rs"):
        if _path.name == "tests.rs":
            continue
        _text = _path.read_text(encoding="utf-8")
        _marker = _text.find("#[cfg(test)]")
        _production = _text if _marker == -1 else _text[:_marker]
        for _token in _RULE_V_SHELL_DELETION_TOKENS:
            if _token in _production:
                failures.append(
                    f"{_crate}/src/{_path.name} appears to invoke an external "
                    f"deletion command ({_token}); every removal must go through "
                    f"filesystem APIs and the existing lifecycle "
                    f"(Architecture Rule V.2 violation)"
                )

# V.3: no language- or phase-specific global cleanup engine. A
# `delete_go_cache`/`delete_rust_cache`/`cleanup_p15_cache`-shaped function is
# by definition a second deletion authority parallel to `full_uninstall`.
_RULE_V_FORBIDDEN_CLEANUP_ENGINES = (
    "delete_go_cache",
    "delete_rust_cache",
    "cleanup_go_cache",
    "cleanup_rust_cache",
    "cleanup_p15_cache",
    "cleanup_p12_cache",
    "purge_managed_cache",
    "wipe_managed_cache",
    "force_cache_cleanup",
    "force_zero_residual",
    "skip_ownership_check",
    "test_cache_override",
    "disable_uninstall_integrity",
)
for _crate in _RULE_M_SCANNED_CRATES:
    for _path in (ROOT / "wht_crates" / _crate / "src").rglob("*.rs"):
        _text = _path.read_text(encoding="utf-8")
        for _name in _RULE_V_FORBIDDEN_CLEANUP_ENGINES:
            if _name in _text:
                failures.append(
                    f"{_crate}/src/{_path.name} defines or references "
                    f"'{_name}', a cache-specific deletion authority or "
                    f"uninstall-integrity test seam parallel to full_uninstall "
                    f"(Architecture Rule V.3 violation)"
                )

# V.4: the managed-root-level scratch location is a single constant owned by
# the provisioning authority; no other crate may hard-code it. A hard-coded
# `"scratch"` join elsewhere is how the lifecycle loses track of a cache
# again -- the exact defect this rule exists to prevent recurring.
_RULE_V_SCRATCH_OWNER = ROOT / "wht_crates/wht_corulix_tooling/src/provisioning.rs"
_rule_v_owner_text = _RULE_V_SCRATCH_OWNER.read_text(encoding="utf-8")
if 'MANAGED_SCRATCH_DIR: &str = "scratch"' not in _rule_v_owner_text:
    failures.append(
        "wht_corulix_tooling::provisioning must define the canonical "
        "MANAGED_SCRATCH_DIR constant for the managed execution cache root "
        "(Architecture Rule V.4 violation)"
    )
# The exact declaration site and the exact use site, not a bare substring:
# a substring check passes vacuously against a renamed variant such as
# `ScratchPathNotConfinedX` (found by mutation-testing this very rule).
if (
    "    ScratchPathNotConfined,\n" not in _rule_v_owner_text
    or "Err(ProvisioningError::ScratchPathNotConfined)" not in _rule_v_owner_text
):
    failures.append(
        "wht_corulix_tooling::provisioning::ensure_scratch_directory must "
        "reject unconfined relative scratch paths before creating them "
        "(Architecture Rule V.4 violation)"
    )
_rule_v_full_uninstall_text = (
    ROOT / "wht_crates/wht_corulix_tooling/src/provisioning/full_uninstall.rs"
).read_text(encoding="utf-8")
for _required in ("MANAGED_SCRATCH_DIR", "canonicalize_confined", "symlink_metadata"):
    if _required not in _rule_v_full_uninstall_text:
        failures.append(
            f"full_uninstall must reach the managed execution cache through "
            f"'{_required}' -- an unconfined managed cache deletion is "
            f"forbidden (Architecture Rule V.4 violation)"
        )

# V.5: every managed-root-level scratch directory must be obtained from that
# one authority. No crate outside `wht_corulix_tooling` may join a literal
# `"scratch"` onto a managed root itself.
for _crate in _RULE_M_SCANNED_CRATES:
    if _crate == "wht_corulix_tooling":
        continue
    for _path in (ROOT / "wht_crates" / _crate / "src").rglob("*.rs"):
        if _path.name == "tests.rs":
            continue
        _text = _path.read_text(encoding="utf-8")
        _marker = _text.find("#[cfg(test)]")
        _production = _text if _marker == -1 else _text[:_marker]
        if 'join("scratch")' in _production:
            failures.append(
                f'{_crate}/src/{_path.name} joins a literal "scratch" '
                f"directory onto a path directly; use "
                f"wht_corulix_tooling::provisioning::ensure_scratch_directory "
                f"and MANAGED_SCRATCH_DIR (Architecture Rule V.5 violation)"
            )

# =====================================================================
# Rule W (RULE_W_TYPESCRIPT_JAVASCRIPT_PROVIDER_BOUNDARY, Phase 16): the
# TypeScript/TSX/JavaScript provider vertical must be genuinely wired into
# the real Engine dispatcher, must never be misclassified against Rust's own
# managed providers (the confirmed P16 bug this phase closed), and must
# never leak provider detail into the MCP adapter -- the same three-part
# discipline Rule U already established for Go, checked against this
# phase's own real production source (`wht_corulix_engine/src/semantic.rs`),
# not a repository-wide grep for a suggestive word.
# =====================================================================

_semantic_rs_path = ROOT / "wht_crates" / "wht_corulix_engine" / "src" / "semantic.rs"
if not _semantic_rs_path.is_file():
    failures.append(
        "wht_corulix_engine/src/semantic.rs is missing -- the real `semantic` "
        "capability's production dispatcher must exist (Architecture Rule W violation)"
    )
else:
    _semantic_rs_text = _semantic_rs_path.read_text(encoding="utf-8")
    _semantic_rs_production = _semantic_rs_text.split("#[cfg(test)]", 1)[0]

    # W.1: the real session-establishment dispatch (`semantic_at`'s own
    # `match language` over `session_attempt`) must explicitly branch on
    # every TS-family `LanguageId`, and must genuinely *call* the real
    # `ensure_typescript_javascript_lsp_session` entry point -- not merely
    # define that method as dead code reachable only from its own tests.
    #
    # Both tokens below are deliberately checked in a way that cannot pass
    # merely because the method/arm is *defined* somewhere in this file:
    # `self.ensure_typescript_javascript_lsp_session(` only matches a real
    # call site (the method's own `async fn ensure_typescript_javascript_lsp_session(`
    # definition has no `self.` prefix), and the language-arm literal is
    # required to appear **twice** -- once in the session-establishment
    # dispatch, once in the provider-resolution dispatch -- so deleting
    # either dispatch arm while leaving the other (or the method definition)
    # untouched still fails this check.
    if "self.ensure_typescript_javascript_lsp_session(" not in _semantic_rs_production:
        failures.append(
            "wht_corulix_engine/src/semantic.rs never calls "
            "self.ensure_typescript_javascript_lsp_session( -- the method may be "
            "defined but has no real production caller "
            "(Architecture Rule W violation)"
        )
    _ts_family_arm_token = (
        "LanguageId::TypeScript | LanguageId::Tsx | LanguageId::JavaScript"
    )
    _ts_family_arm_count = _semantic_rs_production.count(_ts_family_arm_token)
    if _ts_family_arm_count < 2:
        failures.append(
            f"wht_corulix_engine/src/semantic.rs contains '{_ts_family_arm_token}' "
            f"only {_ts_family_arm_count} time(s) in production source (expected at "
            "least 2: session-establishment dispatch and provider-resolution "
            "dispatch) -- TypeScript/Tsx/JavaScript no longer has a real "
            "production Engine route on both axes (Architecture Rule W violation)"
        )

    # W.2 (the confirmed P16 misclassification bug, closed): the provider-
    # resolution `match language` block must give TS/Tsx/JavaScript their own
    # explicit arm that genuinely *calls* their own resolution function --
    # not merely define it. Checked by requiring the function name to appear
    # at least twice in production source (its own `fn` definition, plus a
    # real call site); a bare `_ =>` arm that silently applied Rust's own
    # `real_managed_formatter_resolution`/
    # `real_managed_typecheck_and_linter_resolutions` to TS/JS instead must
    # never return.
    _ts_js_resolutions_fn = "real_typescript_javascript_provider_resolutions("
    if _semantic_rs_production.count(_ts_js_resolutions_fn) < 2:
        failures.append(
            "wht_corulix_engine/src/semantic.rs does not genuinely call "
            "real_typescript_javascript_provider_resolutions( from production "
            "dispatch (found only its own definition, if that) -- TypeScript/Tsx/"
            "JavaScript provider resolution has no dedicated production route "
            "(Architecture Rule W violation)"
        )
    if "LanguageId::Rust => {" not in _semantic_rs_production:
        failures.append(
            "wht_corulix_engine/src/semantic.rs's provider-resolution dispatch "
            "no longer gives LanguageId::Rust its own explicit match arm -- a "
            "bare `_ =>` arm reintroduces the exact misclassification bug this "
            "phase closed, where every other language silently inherited "
            "Rust's own managed providers (Architecture Rule W violation)"
        )

    # W.3: no Go-style dedicated TS/JS provider module was introduced this
    # phase (the LSP-session/provider-resolution logic lives inside
    # `semantic.rs` itself, mirroring the pattern already established before
    # Go's own dedicated modules existed) -- so, unlike Rule U.1/U.2, there is
    # no separate `ts_providers.rs`/`ts_validation.rs` to check for direct
    # process construction. What *is* checked: `semantic.rs` itself must
    # never construct a process directly -- every spawn must still go through
    # `wht_corulix_lsp::LspSession::spawn` (Rule G/L), never a second,
    # divergent process-construction path added for TS/JS.
    for _token in ("Command::new(", "std::process::Command", "tokio::process::Command"):
        if _token in _semantic_rs_production:
            failures.append(
                f"wht_corulix_engine/src/semantic.rs constructs a process "
                f"directly ('{_token}') -- only wht_corulix_tooling/"
                "wht_corulix_lsp may (Architecture Rule W/G/L violation)"
            )

# W.4: no TS/JS provider logic in the MCP adapter -- mirrors Rule U.8 exactly.
_RULE_W_TS_JS_PROVIDER_LEAK_TOKENS = (
    "typescript-language-server",
    "typescript-7-native",
    "biome",
    "dprint",
    "resolve_typescript_toolchain",
    "ensure_typescript_javascript_lsp_session",
    "real_typescript_javascript_provider_resolutions",
)
for _path in (ROOT / "wht_crates" / "wht_corulix_mcp" / "src").rglob("*.rs"):
    _production = _path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
    for _token in _RULE_W_TS_JS_PROVIDER_LEAK_TOKENS:
        if _token in _production:
            failures.append(
                f"wht_corulix_mcp/src/{_path.name} references TS/JS provider "
                f"detail ('{_token}') in production source -- TS/JS must be "
                "reachable only through wht_corulix_engine's public API "
                "(Architecture Rule W/S/B violation)"
            )

# W.5: no production test seam for the TS/JS vertical (mirrors Rule U.10).
_RULE_W_FORBIDDEN_SEAMS = (
    "force_ts7_available",
    "force_ts6_available",
    "fake_biome_success",
    "fake_formatter_success",
    "fake_linter_success",
    "fake_test_runner_success",
    "skip_ts_trust_gate",
    "disable_ts_provider_validation",
)
for _crate in (
    "wht_corulix_engine",
    "wht_corulix_formatter",
    "wht_corulix_lsp",
    "wht_corulix_mcp",
):
    for _path in (ROOT / "wht_crates" / _crate / "src").rglob("*.rs"):
        _text = _path.read_text(encoding="utf-8")
        for _seam in _RULE_W_FORBIDDEN_SEAMS:
            if _seam in _text:
                failures.append(
                    f"{_crate}/src/{_path.name} defines or references the forbidden "
                    f"test seam '{_seam}' (Architecture Rule W violation)"
                )

# W.6 (M09-P10 owner-authorized addition,
# `M09_P10_ARCHITECTURE_VERIFIER_MUTATION_SCOPE=
# RULE_ROUTE_TOKEN_COMMENT_STRING_HARDENING_AND_TS_COVERAGE`): W.3's own
# comment above ("unlike Rule U.1/U.2, there is no separate
# ts_validation.rs/ts_testing.rs to check") is now stale -- both files exist,
# with real, separately-classified TRUSTED_WORKSPACE_EXECUTION call sites
# (real `tsc`/pyright-style workspace typecheck, and the real ts/js test
# runner), added to the engine after Rule W was first written. This mirrors
# Rule U.2/X.2 exactly: their production spawn must be a genuine
# (non-comment, non-string) call to
# `wht_corulix_tooling::execute_with_workspace_root(`, never the legacy
# pathname-cwd `wht_corulix_tooling::execute(`
# (`M09_P10_TS_WORKSPACE_ROUTE_VERIFIER_COVERAGE=PRESENT`). `ts_validation.rs`
# also contains a genuinely `CONTROLLED_EXTERNAL_TOOL_NON_WORKSPACE` call
# (staged-file `biome` linting, cwd = managed/scratch dir, never the real
# workspace) that legitimately keeps using the legacy `execute(` -- exactly
# like Rule X.2's own `ruff` case, this check requires the secure token
# specifically so that unrelated call can never stand in as evidence the
# workspace-bound route itself is secure. Checked against
# `strip_route_evidence_view(...)` of the production (non-`#[cfg(test)]`)
# source, so a comment/string naming the token cannot satisfy this either.
_TS_ENGINE_MODULES = ("ts_validation.rs", "ts_testing.rs")
_ts_engine_src = ROOT / "wht_crates" / "wht_corulix_engine" / "src"
_ts_module_texts: dict[str, str] = {}
for _module in _TS_ENGINE_MODULES:
    _path = _ts_engine_src / _module
    if not _path.is_file():
        failures.append(
            f"wht_corulix_engine/src/{_module} is missing -- the TypeScript/"
            "JavaScript vertical's workspace-bound validator/test-runner module "
            "must exist (Architecture Rule W.6 violation)"
        )
        continue
    _ts_module_texts[_module] = production_source_excluding_cfg_test(
        _path.read_text(encoding="utf-8")
    )
for _module, _text in _ts_module_texts.items():
    _route_evidence = strip_route_evidence_view(_text)
    if "wht_corulix_tooling::execute_with_workspace_root(" not in _route_evidence:
        failures.append(
            f"wht_corulix_engine/src/{_module} does not spawn its workspace-bound "
            "execution through a genuine (non-comment, non-string) call to "
            "wht_corulix_tooling::execute_with_workspace_root( -- the secure, "
            "object-bound/fail-closed workspace entry point is mandatory for "
            "TRUSTED_WORKSPACE_EXECUTION; the legacy pathname-cwd "
            "wht_corulix_tooling::execute( does not satisfy this requirement, "
            "even if present elsewhere in the file for an unrelated non-workspace "
            "call, and neither does the token's name appearing only in a comment "
            "or string (Architecture Rule W.6/G violation)"
        )

# =====================================================================
# Rule X (RULE_X_PYTHON_PROVIDER_BOUNDARY, Phase 17): the Python provider
# vertical must be *routed through* existing machinery, never reimplemented
# alongside it -- the same three-part discipline Rule U (Go) and Rule W
# (TypeScript/JavaScript) already establish, checked against this phase's own
# real production source (`python_providers.rs`/`python_validation.rs`/
# `python_testing.rs`/`validate_change.rs`), not a repository-wide grep for a
# suggestive word.
#
# `pyright`/`ruff`/`pytest` all resolve through `wht_corulix_config::
# resolve_provider` (Rule K, ADR 0011 -- the same HOST_ONLY/approved-directory
# chain Go already uses), never a CORULIX_MANAGED download path and never a
# second resolver -- structurally distinct from Rule W's TS7/Biome managed-
# component checks, and checked accordingly below.
#
# "No Python-specific parallel uninstall/deletion authority" is not a
# separate check here: Rule V.1/V.2 (below, repository-wide) already forbid
# any second recursive-deletion authority and any shell/external-command
# deletion anywhere in this workspace, Python's own vertical included -- a
# duplicate, Python-scoped restatement of that same repository-wide
# allowlist would check nothing Rule V does not already cover.
# =====================================================================

_PYTHON_ENGINE_MODULES = (
    "python_providers.rs",
    "python_validation.rs",
    "python_testing.rs",
)
_python_module_texts: dict[str, str] = {}
for _module in _PYTHON_ENGINE_MODULES:
    _path = _go_engine_src / _module
    if not _path.is_file():
        failures.append(
            f"wht_corulix_engine/src/{_module} is missing -- the Python vertical's "
            "named boundary module must exist (Architecture Rule X violation)"
        )
        continue
    _text = _path.read_text(encoding="utf-8")
    # Production half only: a module's own #[cfg(test)] block legitimately
    # builds fixtures, exactly as Rule U/W already reason.
    _python_module_texts[_module] = _text.split("#[cfg(test)]", 1)[0]

# Rule X.1: no Python module may construct a process itself -- every
# invocation goes through wht_corulix_tooling (Rule G, restated for the
# specific modules P17 added so a future edit cannot quietly regress it).
for _module, _text in _python_module_texts.items():
    for _token in ("Command::new(", "std::process::Command", "tokio::process::Command"):
        if _token in _text:
            failures.append(
                f"wht_corulix_engine/src/{_module} constructs a process directly "
                f"('{_token}') -- only wht_corulix_tooling may "
                "(Architecture Rule X/G violation)"
            )

# Rule X.2: the Python validators/test runner must genuinely spawn through
# Tooling's canonical entry point, not merely avoid Command.
#
# M09-P10 update (owner-authorized narrow Rule X.2 synchronization,
# `M09_P10_ARCHITECTURE_VERIFIER_MUTATION_SCOPE=RULE_U2_X2_SECURE_WORKSPACE_ENTRYPOINT_REQUIREMENT_ONLY`,
# mirrors Rule U.2 above and the M09-P7 Rule U.12 precedent): both
# `python_validation.rs` (pyright) and `python_testing.rs` (pytest) have a
# `TRUSTED_WORKSPACE_EXECUTION` call site whose production spawn must be
# `wht_corulix_tooling::execute_with_workspace_root(`, never the legacy
# pathname-cwd `wht_corulix_tooling::execute(`
# (`M09_P10_RULE_X2_LEGACY_WORKSPACE_ROUTE_ACCEPTED=NO`,
# `M09_P10_RULE_X2_SECURE_WORKSPACE_ROUTE_REQUIRED=YES`). `python_validation.rs`
# also contains a genuinely `CONTROLLED_EXTERNAL_TOOL_NON_WORKSPACE` call
# (staged-file `ruff` linting, cwd = managed/scratch dir, never the real
# workspace) that legitimately keeps using the legacy `execute(` -- this
# check requires the secure token specifically so that unrelated call can
# never stand in as evidence the workspace-bound route itself is secure.
#
# M09-P10 second update (owner-authorized comment/string-bypass
# remediation, `M09_P10_ARCHITECTURE_VERIFIER_MUTATION_SCOPE=
# RULE_ROUTE_TOKEN_COMMENT_STRING_HARDENING_AND_TS_COVERAGE`): checked
# against `strip_route_evidence_view(_text)`, never the raw production
# text -- mirrors Rule U.2's identical remediation above.
for _module in ("python_validation.rs", "python_testing.rs"):
    _text = _python_module_texts.get(_module, "")
    _route_evidence = strip_route_evidence_view(_text) if _text else ""
    if (
        _text
        and "wht_corulix_tooling::execute_with_workspace_root(" not in _route_evidence
    ):
        failures.append(
            f"wht_corulix_engine/src/{_module} does not spawn its workspace-bound "
            "execution through a genuine (non-comment, non-string) call to "
            "wht_corulix_tooling::execute_with_workspace_root( -- the secure, "
            "object-bound/fail-closed workspace entry point is mandatory for "
            "TRUSTED_WORKSPACE_EXECUTION; the legacy pathname-cwd "
            "wht_corulix_tooling::execute( does not satisfy this requirement, "
            "even if present elsewhere in the file for an unrelated non-workspace "
            "call, and neither does the token's name appearing only in a comment "
            "or string (Architecture Rule X.2/G violation)"
        )

# Rule X.3: no second trust gate for the one Python module that genuinely
# executes repository-authored code -- `python_testing.rs` (`pytest`, plus
# any workspace-authored conftest.py/fixture/plugin it loads,
# TrustedWorkspaceExecution per ADR 0011 §4). Unlike Go's build/vet,
# `python_validation.rs`'s `ruff check`/`pyright --outputjson` are
# ControlledExternalTool (ADR 0011 §1-§3: neither executes repository code),
# so it legitimately never calls authorize_trusted_execution -- that absence
# is correct, not a violation, and is not checked here.
_python_testing_text = _python_module_texts.get("python_testing.rs", "")
if _python_testing_text:
    # The real call site, not a bare mention: this module's own doc comment
    # and `use` import legitimately *name* `authorize_trusted_execution`
    # without a trailing '(' (e.g. "`authorize_trusted_execution` before any
    # ProcessSpec"), and checking the bare token would still pass even if the
    # real call site were deleted -- exactly the vacuous-pass failure mode
    # this pass's own mutation test must catch, mirrored from Rule U.11's
    # own real-call-site discipline.
    if "authorize_trusted_execution(" not in _python_testing_text:
        failures.append(
            "wht_corulix_engine/src/python_testing.rs never calls "
            "authorize_trusted_execution( -- pytest is TRUSTED_WORKSPACE_EXECUTION "
            "and must be trust-gated (Architecture Rule X violation)"
        )
    if "is_execution_class_allowed" in _python_testing_text:
        failures.append(
            "wht_corulix_engine/src/python_testing.rs evaluates "
            "is_execution_class_allowed directly -- it must reuse the one shared "
            "trust gate, never derive a second (Architecture Rule X violation)"
        )
    # No hardcoded global pytest assumption (ADR 0011 §4): the real,
    # deterministic discovery call site -- not merely the enum variant it
    # returns on failure -- must genuinely gate the pytest invocation.
    # Checking only `AmbiguousTestRunner` would still pass if the discovery
    # call itself were deleted while the error variant stayed defined
    # elsewhere, which is exactly the vacuous-pass shape this pass's own
    # mutation-testing discipline (Rule X.3's own fix, above) exists to rule
    # out.
    # A bare substring count of 1 would still pass if only the function's own
    # `async fn discover_pytest_runner(...)` signature remained and its real
    # call site inside `run_pytest` were deleted -- the signature itself
    # contains the same substring. Requiring at least 2 occurrences (the
    # definition plus a real call site) is what makes this check fail when
    # the call site specifically is removed, mirroring Rule U.11's own
    # "appears at least twice" discipline for exactly this reason.
    if _python_testing_text.count("discover_pytest_runner(") < 2:
        failures.append(
            "wht_corulix_engine/src/python_testing.rs does not genuinely call "
            "discover_pytest_runner( from run_pytest (found only its own "
            "definition, if that) -- pytest must never run without ADR 0011 §4's "
            "deterministic discovery gate (Architecture Rule X violation)"
        )
    if "AmbiguousTestRunner" not in _python_testing_text:
        failures.append(
            "wht_corulix_engine/src/python_testing.rs no longer defines/returns "
            "AmbiguousTestRunner -- no recognized marker resolving a runner must "
            "fail closed, never silently assume a global pytest "
            "(Architecture Rule X violation)"
        )

# Rule X.4a: no validation-time package-installation authority anywhere in
# the Python vertical -- a `pip install`/`uv pip install` call at validation
# time would be an ungoverned, network-reaching code-execution surface ADR
# 0011 never admits (§49's PEP-517/518 build-backend prohibition, restated
# here for package installation specifically).
for _module, _text in _python_module_texts.items():
    # Only the real invocation-shaped tokens, not a bare quoted "pip" --
    # Rule U.5 hit exactly this false-positive shape (a bare token punishing
    # documentation/prose rather than behavior) and fixed it by matching the
    # real call form instead; a bare `"pip"` here would fire on any future
    # legitimate prose or identifier containing that literal string.
    for _token in ("pip install", "uv pip"):
        if _token in _text:
            failures.append(
                f"wht_corulix_engine/src/{_module} references '{_token}' -- no "
                "Python module may perform validation-time package installation "
                "(Architecture Rule X violation)"
            )

# Rule X.4: no second provider resolver, and no ambient-authority inspection.
# Python provider resolution must go through
# `wht_corulix_config::resolve_provider` (Rule K), and no Python module may
# read an approved-directory list or an ambient PATH itself.
_python_providers_text = _python_module_texts.get("python_providers.rs", "")
if (
    _python_providers_text
    and "wht_corulix_config::resolve_provider(" not in _python_providers_text
):
    failures.append(
        "wht_corulix_engine/src/python_providers.rs does not resolve through "
        "wht_corulix_config::resolve_provider( -- wht_corulix_config is the sole "
        "provider-resolution authority (Architecture Rule X/K violation)"
    )
for _module, _text in _python_module_texts.items():
    for _token in (
        'env::var("PATH")',
        "approved_system_directories",
        "approved_user_toolchain_directories",
    ):
        if _token in _text:
            failures.append(
                f"wht_corulix_engine/src/{_module} inspects '{_token}' -- provider "
                "authority belongs to wht_corulix_config alone, and ambient PATH "
                "carries none (Architecture Rule X/K violation)"
            )

# Rule X.5: the Python formatter (`ruff format`) must never be able to write
# live source itself -- mirrors Rule U.7 exactly, for the same
# `wht_corulix_formatter` crate Rule U.7 already scans in full. Restated here
# with ruff's own flag name so a future edit specific to the Python
# formatter profile cannot quietly regress it even if Rule U.7 were ever
# narrowed.
_formatter_src_x = ROOT / "wht_crates" / "wht_corulix_formatter" / "src"
for _path in _formatter_src_x.rglob("*.rs"):
    _production = _path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
    for _flag in ('"-w"', '"--write"', '"--in-place"'):
        if _flag in _production:
            failures.append(
                f"wht_corulix_formatter/src/{_path.name} references the in-place "
                f"write flag {_flag} -- ruff format must never hold live-write "
                "authority; only wht_corulix_mutation does "
                "(Architecture Rule X/N/M violation)"
            )

# Rule X.6: no Python provider logic in the MCP adapter. `wht_corulix_mcp`
# must reach Python exclusively through `wht_corulix_engine`'s public API --
# it may never name a Python provider binary or call a Python provider entry
# point. Checked against production source only (the crate's own
# #[cfg(test)] block legitimately builds real Python fixtures for its E2E
# tests, exactly as Rule S already permits for its other fixtures).
#
# Word-boundary regex, not a bare substring: "ruff"/"pyright"/"pytest" are
# all substrings of common English/license-header prose ("Copyright"
# contains "pyright"; a bare substring check would fail on every file's own
# SPDX header) -- \b anchors avoid that false positive while still catching
# a genuine identifier/token reference.
_RULE_X_PYTHON_PROVIDER_LEAK_PATTERNS = (
    re.compile(r"\bruff\b"),
    re.compile(r"\bpyright\b"),
    re.compile(r"\bpytest\b"),
    re.compile(r"resolve_python_tool\("),
    re.compile(r"run_typecheck\("),
    re.compile(r"run_lint\("),
    re.compile(r"run_pytest\("),
    re.compile(r"PythonValidator\b"),
    # The implementation modules themselves must never be imported from MCP
    # (the mandate's own explicit wording) -- a bare `use
    # wht_corulix_engine::python_testing;` plus any `PythonTestError`/etc.
    # reference would slip every pattern above while still constituting a
    # direct dependency on the implementation module rather than the
    # engine's public API surface.
    re.compile(r"\bpython_validation\b"),
    re.compile(r"\bpython_testing\b"),
    re.compile(r"\bpython_providers\b"),
)
for _path in _mcp_src.rglob("*.rs"):
    _production = _path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
    for _pattern in _RULE_X_PYTHON_PROVIDER_LEAK_PATTERNS:
        if _pattern.search(_production):
            failures.append(
                f"wht_corulix_mcp/src/{_path.name} references Python provider detail "
                f"('{_pattern.pattern}') in production source -- Python must be "
                "reachable only through wht_corulix_engine's public API "
                "(Architecture Rule X/S/B violation)"
            )

# Rule X.7: no second LSP client for Python. Only wht_corulix_lsp may own a
# pyright session; the Engine's own Python provider modules must never
# contain LSP protocol detail themselves.
for _module, _text in _python_module_texts.items():
    for _token in ("Content-Length", "textDocument/", "jsonrpc"):
        if _token in _text:
            failures.append(
                f"wht_corulix_engine/src/{_module} contains LSP protocol detail "
                f"('{_token}') -- wht_corulix_lsp is the sole LSP authority "
                "(Architecture Rule X/L violation)"
            )

# Rule X.8: no production test seam anywhere in the Python vertical. A
# public force/skip/fake switch is how a governed vertical silently stops
# being governed.
_PYTHON_FORBIDDEN_SEAMS = (
    "force_pyright_available",
    "force_ruff_success",
    "fake_python_formatter",
    "fake_pytest_success",
    "skip_python_trust_gate",
    "disable_python_provider_validation",
)
for _crate in (
    "wht_corulix_engine",
    "wht_corulix_formatter",
    "wht_corulix_lsp",
    "wht_corulix_mcp",
):
    for _path in (ROOT / "wht_crates" / _crate / "src").rglob("*.rs"):
        _text = _path.read_text(encoding="utf-8")
        for _seam in _PYTHON_FORBIDDEN_SEAMS:
            if _seam in _text:
                failures.append(
                    f"{_crate}/src/{_path.name} defines or references the forbidden "
                    f"test seam '{_seam}' (Architecture Rule X violation)"
                )

# Rule X.9 (production-routing regression closure, mirrors Rule U.11/W.1):
# the Python validation/test providers must have a *production Engine
# route*, not merely exist as named, individually-unit-tested modules.
# Checked against production source only (the module's own `#[cfg(test)]`
# block legitimately calls these too, for its unit tests).
if _validate_change_path.is_file():
    for _token in (
        "python_validation::run_typecheck(",
        "python_validation::run_lint(",
        "python_testing::run_pytest(",
    ):
        if _token not in _validate_change_production:
            failures.append(
                f"wht_corulix_engine/src/validate_change.rs does not call '{_token}' "
                "in its production dispatch path -- the Python validation providers "
                "have no production Engine route (Architecture Rule X violation)"
            )
    if "Some(LanguageId::Python)" not in _validate_change_production:
        failures.append(
            "wht_corulix_engine/src/validate_change.rs no longer gives "
            "LanguageId::Python its own explicit dispatch arm -- a bare `_ =>` arm "
            "would silently drop Python routing (Architecture Rule X violation)"
        )

# =====================================================================
# Rule Y (RULE_Y_UNSAFE_FFI_BOUNDARY, P17-W-R2 + M09-P6 + M09-P9): every
# crate in this workspace inherits `unsafe_code = "forbid"` (via
# `[workspace.lints.rust]`, reproduced per-crate through `[lints] workspace
# = true`), which cannot be locally overridden by an inner
# `#[allow(unsafe_code)]` (`E0453`) -- that is the entire semantic
# difference between `forbid` and `deny`. Two narrow, deliberate exceptions
# exist, each closing a real TOCTOU/race that requires raw platform FFI a
# safe wrapper crate exposes only as `unsafe fn`s:
#   * `wht_corulix_process_win32` (P17-W-R2 + M09-P9) -- the Windows Job
#     Object spawn-then-assign race (`resume_primary_thread`/
#     `terminate_process`), approved consumer `wht_corulix_tooling`; and,
#     as of M09-P9, the handle-relative filesystem-authority primitives
#     (`open_root_directory`/`open_relative`/`rename_relative`/
#     `delete_relative`/`query_identity`), approved consumer
#     `wht_corulix_workspace` (mirrors the Unix
#     `wht_corulix_process_unix` -> `wht_corulix_workspace` shape exactly).
#     This crate now has TWO approved consumers -- the first crate in this
#     workspace for which that is true, which is why the dict's values
#     below are now an explicit tuple/set of consumers rather than a bare
#     string (M09_P9_RULE_Y4_MULTI_CONSUMER_MODEL_AUTHORIZED).
#   * `wht_corulix_process_unix` (M09-P6) -- pinning a spawned child's cwd
#     to a `WorkspaceRoot`'s pinned root fd (`bind_cwd`, registering
#     `std::os::unix::process::CommandExt::pre_exec`), approved consumer
#     `wht_corulix_workspace`.
# Each defines its own `[lints]` table with `unsafe_code = "deny"` (not
# `workspace = true`), and grants exactly one `#[allow(unsafe_code)]` to
# its own `ffi` submodule. This rule verifies that boundary structurally
# (via each crate's own `Cargo.toml` lint configuration), not via a
# fragile source-text grep for the word "unsafe" -- prose already
# legitimately uses that word outside any real attribute or keyword (e.g.
# `wht_corulix_config/src/resolver.rs` discusses an `unsafe fn` in a
# comment without containing one), which a bare substring match would
# misclassify as a violation.
#
# NOTE (M09-P9 generalization): each approved crate now maps to a TUPLE of
# approved consumer crate names (never a bare string) -- this widens Rule
# Y.4's exclusion set per approved crate, but the underlying invariant is
# unchanged and NOT weakened: every crate not explicitly named in that
# tuple still fails the moment it references the approved crate at all
# (Rule Y.4 below), and Rule Y.3's "exactly one `#![allow(unsafe_code)]`,
# exactly one `ffi` submodule" structural check is completely untouched by
# this generalization -- widening the consumer SET is not the same as
# widening the unsafe boundary itself, which stays exactly as narrow as
# before.
_APPROVED_UNSAFE_FFI_CRATES = {
    "wht_corulix_process_win32": ("wht_corulix_tooling", "wht_corulix_workspace"),
    "wht_corulix_process_unix": ("wht_corulix_workspace",),
}

for _approved_crate in _APPROVED_UNSAFE_FFI_CRATES:
    if not (crates_dir / _approved_crate / "Cargo.toml").is_file():
        failures.append(
            f"wht_crates/{_approved_crate}/Cargo.toml is missing -- an "
            "approved narrow unsafe FFI boundary crate must exist "
            "(Architecture Rule Y violation)"
        )

# Rule Y.1: every crate other than the approved exceptions must still
# inherit the workspace-wide `forbid` lint verbatim (`[lints] workspace =
# true`) -- the carve-out must stay exactly as wide as the approved set,
# never silently spread by a future edit relaxing a third crate's own
# `[lints]` table.
for _crate_dir in sorted(crates_dir.iterdir()):
    if not _crate_dir.is_dir() or _crate_dir.name in _APPROVED_UNSAFE_FFI_CRATES:
        continue
    _manifest_path = _crate_dir / "Cargo.toml"
    if not _manifest_path.is_file():
        continue
    with _manifest_path.open("rb") as _handle:
        _crate_manifest = tomllib.load(_handle)
    _lints = _crate_manifest.get("lints", {})
    if _lints.get("workspace") is not True:
        failures.append(
            f"wht_crates/{_crate_dir.name}/Cargo.toml does not set "
            "[lints] workspace = true -- every crate other than "
            f"{sorted(_APPROVED_UNSAFE_FFI_CRATES)} must keep inheriting "
            'the workspace-wide unsafe_code = "forbid" lint verbatim '
            "(Architecture Rule Y violation)"
        )

for _approved_crate, _approved_consumers in _APPROVED_UNSAFE_FFI_CRATES.items():
    if not (crates_dir / _approved_crate / "Cargo.toml").is_file():
        continue

    # Rule Y.2: the approved crate's own manifest must diverge deliberately
    # -- its own `[lints.rust]` table, `unsafe_code` set to `deny` (never
    # `forbid`, which could not be locally overridden, and never `allow`,
    # which would relax the boundary workspace-wide within the crate).
    with (crates_dir / _approved_crate / "Cargo.toml").open("rb") as _handle:
        _ffi_crate_manifest = tomllib.load(_handle)
    _ffi_lints = _ffi_crate_manifest.get("lints", {})
    if _ffi_lints.get("workspace") is True:
        failures.append(
            f"wht_crates/{_approved_crate}/Cargo.toml sets "
            "[lints] workspace = true -- it must define its own [lints.rust] "
            'table with unsafe_code = "deny" instead, or its one approved '
            "unsafe carve-out could never compile (Architecture Rule Y "
            "violation)"
        )
    _ffi_rust_lints = _ffi_lints.get("rust", {})
    if _ffi_rust_lints.get("unsafe_code") != "deny":
        failures.append(
            f"wht_crates/{_approved_crate}/Cargo.toml's "
            '[lints.rust] unsafe_code is not exactly "deny" -- "forbid" '
            'cannot be locally overridden and "allow"/absent would not '
            "reproduce the workspace's own default posture within this crate "
            "(Architecture Rule Y violation)"
        )

    # Rule Y.3: the carve-out itself must be exactly one occurrence -- a
    # single inner attribute applying `allow(unsafe_code)` (Rust spells a
    # module-scoped inner attribute `#![...]`, written as the first item
    # inside that module's own braces -- NOT the outer-attribute `#[...]`
    # form, which cannot target the module block it is written inside) on
    # the one approved `ffi` submodule, and the crate root must apply
    # `deny(unsafe_code)` (never `forbid(...)`, which would make its own
    # local override impossible, and never `allow(...)` at the true crate
    # root, which would relax the boundary far wider than the one submodule
    # this rule intends). Because both the crate-root and the nested `ffi`
    # module spell their inner attribute identically (`#![...]`), a bare
    # substring match cannot tell which scope it applies to -- this check
    # splits the file at the `mod ffi {` boundary and requires the crate-root
    # portion (before that split) to carry `deny` but never `allow`, and the
    # `ffi`-module portion (from that split onward) to carry `allow` exactly
    # once.
    _ffi_lib_path = crates_dir / _approved_crate / "src" / "lib.rs"
    if not _ffi_lib_path.is_file():
        failures.append(
            f"wht_crates/{_approved_crate}/src/lib.rs is missing "
            "(Architecture Rule Y violation)"
        )
    else:
        _ffi_lib_text = _ffi_lib_path.read_text(encoding="utf-8")
        _ffi_module_marker = "mod ffi {"
        if _ffi_module_marker not in _ffi_lib_text:
            failures.append(
                f"wht_crates/{_approved_crate}/src/lib.rs does not "
                "define a `mod ffi {{ ... }}` submodule -- the approved narrow "
                "FFI boundary must be structurally isolated in its own named "
                "submodule (Architecture Rule Y violation)"
            )
        else:
            _crate_root_part, _ffi_module_part = _ffi_lib_text.split(
                _ffi_module_marker, 1
            )
            if "#![deny(unsafe_code)]" not in _crate_root_part:
                failures.append(
                    f"wht_crates/{_approved_crate}/src/lib.rs does not "
                    "declare #![deny(unsafe_code)] at the crate root (before its "
                    "`mod ffi` submodule) (Architecture Rule Y violation)"
                )
            if "#![forbid(unsafe_code)]" in _crate_root_part:
                failures.append(
                    f"wht_crates/{_approved_crate}/src/lib.rs declares "
                    "#![forbid(unsafe_code)] at the crate root -- forbid cannot "
                    "be locally overridden and would make this crate's one "
                    "approved carve-out impossible (Architecture Rule Y "
                    "violation)"
                )
            if "#![allow(unsafe_code)]" in _crate_root_part:
                failures.append(
                    f"wht_crates/{_approved_crate}/src/lib.rs grants "
                    "#![allow(unsafe_code)] before its `mod ffi` submodule -- "
                    "the carve-out must be scoped to the one approved ffi "
                    "submodule only, never the whole crate root (Architecture "
                    "Rule Y violation)"
                )
            _ffi_module_allow_count = _ffi_module_part.count("#![allow(unsafe_code)]")
            if _ffi_module_allow_count == 0:
                failures.append(
                    f"wht_crates/{_approved_crate}/src/lib.rs's `ffi` "
                    "submodule never grants #![allow(unsafe_code)] -- the "
                    "approved narrow FFI boundary would be unable to compile its "
                    "raw calls (Architecture Rule Y violation)"
                )
            elif _ffi_module_allow_count > 1:
                failures.append(
                    f"wht_crates/{_approved_crate}/src/lib.rs grants "
                    f"#![allow(unsafe_code)] {_ffi_module_allow_count} times "
                    "within its `ffi` submodule -- the approved carve-out must "
                    "stay exactly one narrow attribute wide (Architecture Rule "
                    "Y violation)"
                )

    # Rule Y.4: no crate other than one of this boundary's own approved
    # consumers may reference it at all. `_approved_consumers` is always a
    # tuple now (even for the single-consumer `wht_corulix_process_unix`
    # case) -- every crate NOT explicitly named in it still fails the
    # instant it references the approved crate, exactly as strictly as
    # before this rule was generalized to support more than one consumer.
    for _crate_dir in sorted(crates_dir.iterdir()):
        if not _crate_dir.is_dir() or _crate_dir.name in (
            _approved_crate,
            *_approved_consumers,
        ):
            continue
        for _search_dir in (_crate_dir / "src", _crate_dir / "tests"):
            if not _search_dir.exists():
                continue
            for _path in _search_dir.rglob("*.rs"):
                if _approved_crate in _path.read_text(encoding="utf-8"):
                    failures.append(
                        f"{_path.relative_to(ROOT)} references "
                        f"{_approved_crate}:: -- only "
                        f"{', '.join(sorted(_approved_consumers))} may "
                        "consume this approved FFI boundary (Architecture "
                        "Rule Y/G violation)"
                    )

# Rule Y.5: wht_corulix_tooling's own Windows platform module must
# genuinely dispatch to the win32 boundary's real entry points (a
# production route, not merely a stale mention) -- mirrors the
# "real call site, not a bare mention" discipline Rule U.11/X.9 already
# establish for other production-routing checks.
_windows_platform_path = (
    crates_dir / "wht_corulix_tooling" / "src" / "platform" / "windows.rs"
)
if not _windows_platform_path.is_file():
    failures.append(
        "wht_crates/wht_corulix_tooling/src/platform/windows.rs is missing "
        "(Architecture Rule Y violation)"
    )
else:
    _windows_platform_text = _windows_platform_path.read_text(encoding="utf-8")
    for _entry_point in (
        "wht_corulix_process_win32::resume_primary_thread(",
        "wht_corulix_process_win32::terminate_process(",
    ):
        if _entry_point not in _windows_platform_text:
            failures.append(
                "wht_crates/wht_corulix_tooling/src/platform/windows.rs "
                f"does not call {_entry_point} -- the assign-before-resume "
                "Windows containment path has no real production route to "
                "the approved FFI boundary (Architecture Rule Y violation)"
            )
    if "#[allow(unsafe_code)]" in _windows_platform_text:
        failures.append(
            "wht_crates/wht_corulix_tooling/src/platform/windows.rs grants "
            "#[allow(unsafe_code)] -- wht_corulix_tooling must never carry "
            "its own unsafe carve-out; all raw Win32 FFI belongs exclusively "
            "to wht_corulix_process_win32 (Architecture Rule Y violation)"
        )

# Rule Y.5b (M09-P9): wht_corulix_workspace, the SECOND approved consumer
# of wht_corulix_process_win32 (added alongside wht_corulix_tooling above
# for the Windows handle-relative filesystem-authority boundary), must
# itself genuinely dispatch to that boundary's real filesystem entry point
# -- same "real call site, not a bare mention" discipline as Rule Y.5/Y.6.
# Deliberately a SEPARATE block from Y.5 (rather than folded into a single
# generic loop) because each approved consumer's own required entry points
# and target file differ; this mirrors Y.5/Y.6 already being two separate
# blocks for two different (crate, consumer) pairs.
_workspace_confine_path = crates_dir / "wht_corulix_workspace" / "src" / "confine.rs"
if not _workspace_confine_path.is_file():
    failures.append(
        "wht_crates/wht_corulix_workspace/src/confine.rs is missing "
        "(Architecture Rule Y violation)"
    )
else:
    _workspace_confine_text = _workspace_confine_path.read_text(encoding="utf-8")
    if "wht_corulix_process_win32::open_root_directory(" not in _workspace_confine_text:
        failures.append(
            "wht_crates/wht_corulix_workspace/src/confine.rs does not call "
            "wht_corulix_process_win32::open_root_directory( -- "
            "WorkspaceRoot's own Windows handle-authority construction has "
            "no real production route to the approved win32 filesystem FFI "
            "boundary (Architecture Rule Y violation)"
        )
    if "#[allow(unsafe_code)]" in _workspace_confine_text:
        failures.append(
            "wht_crates/wht_corulix_workspace/src/confine.rs grants "
            "#[allow(unsafe_code)] -- wht_corulix_workspace must never "
            "carry its own unsafe carve-out; all raw Win32/NT FFI belongs "
            "exclusively to wht_corulix_process_win32 (Architecture Rule Y "
            "violation)"
        )

# Rule Y.6 (M09-P6): wht_corulix_workspace's own WorkspaceRoot must
# genuinely dispatch to the unix cwd-binding boundary's real entry point --
# a production route, not merely a stale mention (same discipline as Rule
# Y.5 above).
_confine_path = crates_dir / "wht_corulix_workspace" / "src" / "confine.rs"
if not _confine_path.is_file():
    failures.append(
        "wht_crates/wht_corulix_workspace/src/confine.rs is missing "
        "(Architecture Rule Y violation)"
    )
else:
    _confine_text = _confine_path.read_text(encoding="utf-8")
    if "wht_corulix_process_unix::bind_cwd(" not in _confine_text:
        failures.append(
            "wht_crates/wht_corulix_workspace/src/confine.rs does not call "
            "wht_corulix_process_unix::bind_cwd( -- WorkspaceRoot's own "
            "process-cwd-pinning method has no real production route to the "
            "approved unix FFI boundary (Architecture Rule Y violation)"
        )
    if "#[allow(unsafe_code)]" in _confine_text:
        failures.append(
            "wht_crates/wht_corulix_workspace/src/confine.rs grants "
            "#[allow(unsafe_code)] -- wht_corulix_workspace must never carry "
            "its own unsafe carve-out; all raw pre_exec/fchdir FFI belongs "
            "exclusively to wht_corulix_process_unix (Architecture Rule Y "
            "violation)"
        )
# =====================================================================

# Step 10: Report and exit non-zero on any violation; otherwise PASS.
if failures:
    print("ARCHITECTURE_BOUNDARY: FAIL")
    for failure in failures:
        print(f" - {failure}")
    sys.exit(1)

print("ARCHITECTURE_BOUNDARY: PASS")
print("wht_corulix_core -> MCP direct knowledge: ABSENT")
print("wht_corulix_syntax -> sole Tree-sitter owner: CONFIRMED (Rule C)")
print("wht_corulix_mcp  -> Tree-sitter direct knowledge: ABSENT (Rule C)")
print("wht_corulix_workspace -> sole canonicalization/confinement owner: CONFIRMED")
print("wht_corulix_workspace -> sole .code-workspace descriptor parser: CONFIRMED")
print("wht_corulix_cli -> manual env::args() dispatch tree: ABSENT (Rule I)")
print("wht_corulix_search -> sole ripgrep-family search owner: CONFIRMED (Rule D)")
print("wht_corulix_search -> external rg/shell process spawn: ABSENT (Rule D)")
print(
    "wht_corulix_search -> independent filesystem walker (ignore::WalkBuilder): ABSENT (Rule D)"
)
print(
    "wht_corulix_engine -> sole RiskClass/ToolPlan/gate derivation authority: CONFIRMED (Rule H)"
)
print("wht_corulix_tooling -> sole process construction authority: CONFIRMED (Rule G)")
print("wht_corulix_cli -> sole top-level Tokio runtime owner: CONFIRMED (Rule J)")
print("library crates -> nested runtime construction / .block_on(: ABSENT (Rule J)")
print(
    "wht_corulix_tooling -> canonical 'pub async fn execute' entry point: CONFIRMED (Rule J)"
)
print(
    "wht_corulix_search/wht_corulix_syntax/wht_corulix_engine -> canonical async "
    "provider entry points, no legacy sync duplicate: CONFIRMED (Rule J)"
)
print(
    "wht_corulix_workspace/wht_corulix_search/wht_corulix_syntax/wht_corulix_engine "
    "-> public 'pub fn *_blocking' bypass: ABSENT (Rule J)"
)
print(
    "wht_corulix_config -> sole trust/config/provider-resolution authority: "
    "CONFIRMED (Rule K)"
)
print("workspace -> ambient PATH provider authority: ABSENT (Rule K)")
print(
    "wht_corulix_config::RepositoryHints/RequestOptions -> WorkspaceTrust "
    "elevation path: ABSENT (Rule K)"
)
print("workspace -> premature ADMIN_ONLY implementation: ABSENT (Rule K)")
print(
    "wht_corulix_lsp -> sole LSP transport/client protocol and semantic "
    "authority: CONFIRMED (Rule L)"
)
print("workspace -> raw ls_types leakage outside wht_corulix_lsp: ABSENT (Rule L)")
print("workspace -> second LSP Content-Length framing implementation: ABSENT (Rule L)")
print(
    "wht_corulix_mutation -> sole governed live-workspace-write authority: "
    "CONFIRMED (Rule M)"
)
print(
    "wht_corulix_search/syntax/lsp/mcp/cli/tooling/config/workspace -> direct "
    "live filesystem write authority: ABSENT (Rule M)"
)
print("wht_corulix_lsp -> textDocument/formatting authority claim: ABSENT (Rule N)")
print(
    "wht_corulix_formatter -> resolves 'rustfmt' via wht_corulix_config::resolve_provider: "
    "CONFIRMED (Rule N)"
)
print(
    "wht_corulix_formatter -> applies via wht_corulix_mutation::MutationExecutor: "
    "CONFIRMED (Rule N)"
)
print("wht_corulix_formatter -> competing 'fn execute(' authority: ABSENT (Rule N)")
print(
    "wht_corulix_lsp::profile -> sole LspProviderProfile construction authority: "
    "CONFIRMED (Rule P)"
)
print("wht_corulix_lsp::session -> hard-coded single-language literal: ABSENT (Rule P)")
print(
    "wht_corulix_lsp::session -> every ReadinessStrategy variant dispatched: "
    "CONFIRMED (Rule P)"
)
print(
    "wht_corulix_lsp::profile -> auxiliary tools resolved via "
    "wht_corulix_config::resolve_provider: CONFIRMED (Rule P)"
)
print(
    "wht_corulix_engine::providers -> per-language LanguageServer overlay is "
    "privately held: CONFIRMED (Rule P)"
)
print(
    "wht_corulix_lsp::profile -> interpreter resolved under "
    "ProviderCategory::Runtime, never the provider's own category: "
    "CONFIRMED (Rule P)"
)
print(
    "wht_corulix_lsp::profile -> script-provider shebang ('/usr/bin/env') "
    "reliance: ABSENT (Rule P)"
)
print(
    "wht_corulix_engine::routing -> live per-language LanguageServer "
    "dispatch: CONFIRMED (Rule P)"
)
print(
    "wht_corulix_engine::session -> sole format_and_apply(...) call site "
    "outside wht_corulix_formatter: CONFIRMED (Rule R)"
)
print("wht_corulix_mcp -> production dependency graph: thin adapter CONFIRMED (Rule S)")
print(
    f"wht_corulix_mcp -> public MCP tool count: {_tool_count} == 14 CONFIRMED (Rule S)"
)
print("wht_corulix_mcp -> legacy '-> String' tool response shape: ABSENT (Rule S)")
print("wht_corulix_mcp -> direct process construction: ABSENT (Rule S/G)")
print("wht_corulix_mcp -> direct workspace filesystem write: ABSENT (Rule S/M)")
print(
    "wht_corulix_mcp -> direct Search/LSP/Tooling/Formatter/Mutation "
    "dependency: ABSENT (Rule S/B)"
)
print("wht_corulix_mcp -> MCP Roots capability usage: ABSENT (Rule S)")
print("wht_corulix_mcp -> MCP protocol Logging capability usage: ABSENT (Rule S)")
print(
    f"wht_docs/wht_host_profiles -> canonical host profiles: "
    f"{len(_REQUIRED_HOST_PROFILES)} present and well-formed CONFIRMED (Rule T)"
)
print(
    f"wht_docs + README + CHANGELOG -> unqualified global enforcement claim "
    f"across {len(_scanned_docs)} documents: ABSENT (Rule T)"
)
print(
    f"wht_corulix_engine -> Go boundary modules present "
    f"({len(_go_module_texts)}/{len(_GO_ENGINE_MODULES)}): CONFIRMED (Rule U)"
)
print("wht_corulix_engine Go modules -> direct process construction: ABSENT (Rule U/G)")
print(
    "wht_corulix_engine Go modules -> spawn via wht_corulix_tooling::execute: "
    "CONFIRMED (Rule U/G)"
)
print(
    "wht_corulix_engine Go modules -> single shared trust gate, no second "
    "derivation: CONFIRMED (Rule U)"
)
print(
    "wht_corulix_engine::go_providers -> resolution via "
    "wht_corulix_config::resolve_provider only: CONFIRMED (Rule U/K)"
)
print(
    "wht_corulix_engine Go modules -> ambient PATH / approved-directory "
    "inspection: ABSENT (Rule U/K)"
)
print(
    "wht_corulix_engine::go_providers -> GOTOOLCHAIN=local / GOPROXY=off / "
    "GOFLAGS=-mod=readonly: CONFIRMED (Rule U)"
)
print(
    "wht_corulix_engine::go_validation -> `go build` output redirected off the "
    "governed workspace: CONFIRMED (Rule U/M)"
)
print(
    "wht_corulix_formatter -> in-place write flag (-w/--write/--in-place): "
    "ABSENT (Rule U/N/M)"
)
print("wht_corulix_mcp -> Go provider detail in production source: ABSENT (Rule U/S/B)")
print("wht_corulix_engine Go modules -> LSP protocol detail: ABSENT (Rule U/L)")
print("workspace -> Go production test seam (force/skip/fake): ABSENT (Rule U)")
print(
    "wht_corulix_engine::validate_change -> real production Engine route to "
    "go_validation::run_go_validator/go_testing::run_go_test, language-aware "
    "dispatch via session.language(): CONFIRMED (Rule U.11)"
)
print(
    "wht_corulix_tooling::provisioning -> sole managed execution cache "
    "path/ownership authority (MANAGED_SCRATCH_DIR + confined "
    "ensure_scratch_directory): CONFIRMED (Rule V)"
)
print(
    "wht_corulix_tooling::provisioning::full_uninstall -> sole managed cache "
    "deletion authority, confined and symlink-checked: CONFIRMED (Rule V)"
)
print(
    "workspace -> second recursive deletion authority outside the managed "
    "lifecycle: ABSENT (Rule V.1)"
)
print("workspace -> shell/external-command deletion: ABSENT (Rule V.2)")
print(
    "workspace -> Go/Rust-specific global cache cleanup engine or "
    "uninstall-integrity test seam: ABSENT (Rule V.3)"
)
print(
    "workspace -> hard-coded managed-root scratch path outside the "
    "provisioning authority: ABSENT (Rule V.5)"
)
