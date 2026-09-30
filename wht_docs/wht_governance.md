# Governance

WhaTalker Corulix is maintained by WhaTalker Inc. This document defines public project authority; it does not expose private operational governance records.

## Project identity

```text
Maintainer:           WhaTalker Inc.
Product:              WhaTalker Corulix
CLI:                  corulix
Optional npm package: @whatalker/corulix
Version line:         1.0.x
```

## Roles

- **WhaTalker Inc.** owns product direction, official release authorization, brand decisions and authoritative publication decisions.
- **Approved maintainers** may receive architecture, review, packaging or release responsibilities explicitly delegated by WhaTalker Inc.
- **External contributors** are subject to `CONTRIBUTING.md` and the current CLA/DCO policy state.

## Decision domains

- Architecture changes must preserve `wht_architecture.md` and `wht_architecture_boundaries.md`.
- Dependency changes follow `wht_dependencies.md` and `wht_supply_chain.md`.
- Security changes follow `SECURITY.md` and `wht_threat_model.md`.
- Official releases follow `wht_releasing.md` and the publication set defined by `PACKAGE_MANIFEST.txt`.

## Source/release authority

Corulix uses a no-Git release authority model, unchanged in 1.1.0. Local Git history, commit IDs and tags are not required source identity. The public source set and checksums, version/license metadata, validated binaries and explicit owner release authorization are the relevant release authorities.

A public hosting platform may provide discovery, issues, downloads or mirrors, but hosting metadata does not override the content of an authorized release artifact.

## Amendments

WhaTalker Inc. may amend this governance model. Material public changes should be reflected in the release-oriented changelog or applicable policy document.
