# Source Provenance

Corulix maintains an explicit provenance boundary for project-authored source,
tests, queries, fixtures, documentation, and release material.

## Authorized implementation inputs

Authorized inputs include:

- WhaTalker product and architecture requirements;
- public technical specifications;
- official MCP specifications and SDK documentation;
- official Tree-sitter runtime and grammar documentation;
- official Rust documentation;
- public language specifications;
- independently designed tests and fixtures;
- third-party dependencies admitted under `wht_dependencies.md`.

## Admission rule

Material from another project is incorporated only when its origin, license,
and intended use are explicit and compatible with this repository. Uncertain
or unlicensed copied source is excluded.

## Verification

Repository review, dependency metadata, source headers, publication-set
controls, and release evidence are used together to maintain provenance. A
provenance statement does not replace the independent license/security review
required for third-party dependencies.
