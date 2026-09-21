# Third-Party Notices

Corulix uses third-party libraries through its dependency graph. Each component
retains its own upstream copyright and license terms.

## Primary upstream components

| Component | License | Role |
|---|---|---|
| Tree-sitter (`tree-sitter`) | MIT | Parsing runtime |
| Tree-sitter JavaScript grammar | MIT | JavaScript/JSX grammar |
| Tree-sitter TypeScript grammar | MIT | TypeScript/TSX grammar |
| Tree-sitter Python grammar | MIT | Python grammar |
| Tree-sitter Rust grammar | MIT | Rust grammar |
| Tree-sitter Go grammar | MIT | Go grammar |
| MCP Rust SDK (`rmcp`) | Apache-2.0 | MCP protocol adapter |

Additional direct and transitive dependencies are resolved by Cargo and are
represented by the lockfile and release SBOM.

## Attribution

Third-party components are not relicensed by the `AGPL-3.0-only` license used
for WhaTalker-authored Corulix source. Their own upstream license terms remain
applicable.

## Release completeness

Before an official binary/package release, the resolved dependency graph must
be reviewed and the release process must produce the required SBOM and notices
artifacts from the exact release lockfile. Human-readable notices should be
generated from authoritative dependency data rather than maintained as an
unverified manual list.

If a notice appears incomplete or incorrect, report the specific dependency
and resolved version through the project's public issue/security process as
appropriate.
