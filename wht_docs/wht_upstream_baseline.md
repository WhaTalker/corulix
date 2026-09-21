# Upstream Baseline

The Corulix workspace currently targets the following reviewed top-level
baseline:

- Rust toolchain: `1.97.1`
- MCP Rust SDK (`rmcp`): `3.0.1`
- MCP protocol line reviewed by the project: `2026-07-28`
- Tree-sitter runtime: `0.26.11`
- JavaScript grammar: `0.25.0`
- TypeScript/TSX grammar: `0.23.2`
- Python grammar: `0.25.0`
- Rust grammar: `0.24.2`
- Go grammar: `0.25.0`

The workspace manifests and `Cargo.lock` are authoritative for exact package
resolution. Any baseline update must repeat dependency, security, license,
quality, and compatibility checks before release.
