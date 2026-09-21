# Contributing

## Current status

External source-code contributions are **not currently accepted** while WhaTalker Inc.'s contributor-agreement workflow remains inactive. Issues, design discussion, documentation feedback and reproducible defect reports may still be useful, but external code should not be submitted with an expectation that it can be merged under the current policy.

See `wht_docs/wht_cla_policy.md` and `wht_docs/wht_dco_policy.md` for the legal/contribution-policy status.

## Engineering expectations for future contribution support

If external code contributions are enabled in a future policy revision, accepted changes will be expected to preserve at least these boundaries:

- `wht_corulix_core` remains protocol-agnostic;
- `wht_corulix_workspace` remains the workspace/filesystem authority;
- direct Tree-sitter ownership remains in `wht_corulix_syntax`;
- LSP framing/semantic provider behavior remains in `wht_corulix_lsp`;
- external process creation remains in `wht_corulix_tooling`;
- live workspace writes remain governed through mutation/session authority;
- `wht_corulix_mcp` remains a transport/presentation adapter rather than a second application layer.

See `wht_docs/wht_architecture.md` and `wht_docs/wht_architecture_boundaries.md`.

## Provenance

Contributed material must have explicit, compatible provenance. Do not copy source, tests, fixtures, queries or patches from another project unless the origin, license and intended use are known and acceptable under this repository's provenance policy.

See `wht_docs/wht_provenance.md` and `wht_docs/wht_clean_room.md`.

## Quality baseline

Future accepted source changes are expected to satisfy the applicable project gates, including:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
python3 wht_scripts/wht_verify_architecture.py
python3 wht_scripts/wht_verify_repository.py
```

Dependency changes additionally require dependency/security/license review.

## No-Git release authority

Corulix's official 1.0.0 release authority is not defined by local Git history. The release process is documented in `wht_docs/wht_releasing.md`.

## Legal note

This document is not itself a Contributor License Agreement and does not promise when external code contributions will open.
