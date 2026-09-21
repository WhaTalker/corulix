# Threat Model

This document describes the principal assets, trust boundaries, threats, and
baseline mitigations for Corulix.

## Scope

Corulix inspects a user-selected source workspace and exposes structural code
intelligence through MCP. The primary threat model includes malformed or
hostile MCP requests, malicious workspace content, path-boundary attacks,
parser/resource-exhaustion inputs, and compromised dependency inputs.

A fully compromised host operating system is outside the component security
boundary; supply-chain and release controls reduce, but do not eliminate,
risks from build and dependency infrastructure.

## Assets

- source files and workspace metadata;
- host filesystem content outside the approved workspace;
- index/snapshot integrity;
- MCP protocol-stream integrity;
- release artifacts and provenance;
- official repository and release identity.

## Trust boundaries

```text
MCP input                 -> MCP adapter
MCP adapter               -> Corulix application API
workspace-relative path   -> filesystem boundary
source bytes              -> parser/language adapter
build/dependency inputs   -> release artifacts
```

## Primary threats and mitigations

| Threat | Baseline mitigation |
|---|---|
| Parent traversal | Reject unsafe path components and enforce the canonical workspace root |
| Absolute external path | Deny paths outside the approved workspace |
| Symlink escape | Canonical target must remain under the canonical workspace root |
| Oversized input | Apply bounded input and file-size limits before expensive processing |
| Invalid encoding | Return typed errors rather than panics or silent truncation |
| Malformed source | Treat parser input as untrusted and return typed parse results/errors |
| Protocol corruption | Reserve stdout for MCP messages; route diagnostics to stderr |
| Unexpected tool fields | Strict typed request validation |
| Dependency compromise | Lockfile, dependency policy, advisory checks, SBOM and release gates |
| Architecture boundary bypass | Automated architecture validation in CI |
| Unauthorized source inclusion | Publication-set and provenance controls |
| Unofficial release confusion | Repository governance, release provenance, and trademark policy |

## Residual risk

Security is an ongoing process. Fuzzing depth, platform-specific filesystem
behavior, dependency advisories, protocol interoperability, and release
supply-chain evidence must be re-evaluated as the implementation and supported
platforms evolve.

A mitigation documented here is a design/control requirement; release claims
must be backed by the applicable executed validation for the exact release
candidate.
