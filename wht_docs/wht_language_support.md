# Language Support Matrix

This document describes the **current Corulix 1.1.0 language/provider surface** (unchanged from 1.0.0). Historical phase-status text is not current capability authority.

Corulix supports these source families:

- Rust
- Go
- TypeScript / TSX
- JavaScript / JSX
- Python

## Capability matrix

| Language | Structural parsing | Semantic authority | Formatter | Type/build authority | Lint authority | Test authority |
| --- | --- | --- | --- | --- | --- | --- |
| Rust | Tree-sitter Rust | rust-analyzer | `rustfmt` | `cargo check` | governed Rust diagnostics/tooling as configured | `cargo test` |
| Go | Tree-sitter Go | `gopls` | `gofmt` | `go build` | `go vet` | `go test` |
| TypeScript / TSX | Tree-sitter TypeScript | TypeScript 7 native LSP; managed TypeScript 6 compatibility | Biome | `tsc --noEmit` | Biome built-in lint | deterministic project test-runner discovery |
| JavaScript / JSX | Tree-sitter JavaScript | TypeScript language-service backends | Biome | `tsc --noEmit` only when project configuration opts into JS checking | Biome built-in lint | deterministic project test-runner discovery |
| Python | Tree-sitter Python | Pyright | `ruff format` | `pyright --outputjson` | `ruff check` | `pytest` when deterministically discovered |

## Structural vs semantic authority

Tree-sitter is structural authority only. It provides syntax, structural symbols and scopes; it is not presented as a compiler-grade definition/reference/type system.

Compiler-grade semantic operations are routed through language-specific LSP providers owned by `wht_corulix_lsp`.

## Rust

- Structural parser: Tree-sitter Rust.
- Semantic provider: rust-analyzer.
- Formatter: `rustfmt`.
- Validation: governed Cargo/Rust validation.
- Tests: `cargo test` where the operation/session policy permits trusted workspace execution.

rust-analyzer is configured conservatively for untrusted workspaces; repository-authored build-script/proc-macro execution is not silently enabled by workspace content.

## Go

| Concern | Provider | Authority |
| --- | --- | --- |
| Structure | Tree-sitter Go | structural |
| Semantics | `gopls` | compiler-grade semantic |
| Formatting | `gofmt` | formatter |
| Build/type graph | `go build` | authoritative validation |
| Lint | `go vet` | supporting diagnostic authority |
| Tests | `go test` | authoritative test execution |

Go build/vet/test operations are trusted-workspace execution because the Go toolchain may execute repository-controlled build behavior. Corulix applies explicit trust and environment controls rather than treating these as harmless read-only subprocesses.

## TypeScript / TSX

### Semantic providers

- TypeScript 7: managed native `tsc --lsp --stdio` (`typescript-go`) provider.
- TypeScript 6 compatibility: managed Node + `typescript-language-server` + managed classic TypeScript runtime.

### Formatting and lint

Biome is the admitted formatter and built-in-rule linter authority. Formatter preview is non-destructive; governed application occurs through the change-session/mutation path.

### Type checking

TypeScript projects are validated with the appropriate managed `tsc --noEmit` authority and bounded project discovery. Corulix does not silently turn a typecheck into a build that writes normal project artifacts.

### Test runner

Project test-runner discovery is deterministic. Recognized `package.json` test-script forms include the admitted Node/Jest/Vitest/Mocha/Ava/Tap families implemented by the current resolver. Unrecognized/ambiguous runners fail closed rather than defaulting to an arbitrary package-manager command.

Test execution is trusted-workspace execution because repository-authored test scripts execute project code.

## JavaScript / JSX

JavaScript shares the TypeScript semantic backends and Biome formatting/linting path.

Type-check policy is explicit:

- plain JavaScript with no opted-in `checkJs` project does not fabricate a compiler-grade typecheck requirement;
- projects that enable JS checking through their JS/TS configuration may use `tsc --noEmit` under the same governed model;
- LSP diagnostics remain available through the admitted semantic backend.

## Python

| Concern | Provider | Authority |
| --- | --- | --- |
| Structure | Tree-sitter Python | structural |
| Semantics | Pyright language server | compiler-grade semantic |
| Formatting | `ruff format` | formatter |
| Type checking | `pyright --outputjson` | authoritative validation |
| Lint | `ruff check` | supporting diagnostic authority |
| Tests | `pytest` | authoritative test execution when discovered |

Python test execution is trusted-workspace execution because tests and fixtures may execute repository-authored Python code. Formatting, lint and typecheck providers are controlled external tools under the current provider-resolution model.

## Provider resolution and trust

Provider availability and workspace execution trust are separate axes.

- A provider executable must resolve through admitted managed/host authority.
- A safely resolved executable does not automatically grant permission to execute repository-authored code.
- Repository content cannot self-elevate workspace trust.
- Ambient `PATH` does not become provider authority.
- Missing providers/ambiguous runners fail closed.

## Windows behavior

Language capability claims remain subject to the platform security model. On Windows, workspace-bound process execution may be unavailable where the implementation cannot establish the required safe object/process binding. Corulix reports that unavailability instead of falling back to pathname-only authority.

## Capability terminology

- **Supported** — part of the current product surface for the stated authority.
- **Conditional** — supported only when the project/provider/trust conditions explicitly described above are satisfied.
- **Unavailable** — required authority/provider is not available; Corulix fails closed rather than inventing a fallback.

The executable schemas, workspace manifests, provider-resolution code and permanent regression tests remain the implementation authority if documentation ever drifts.
