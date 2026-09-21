# Publication Scope — Corulix 1.0.0

## Authority

The standard public **source** set for Corulix 1.0.0 is the file list in the repository-root `PACKAGE_MANIFEST.txt`. `SHA256SUMS.txt` binds publication-set files to SHA-256 digests; the checksum file intentionally does not checksum itself.

The publication set describes source/documentation content. Platform binaries, npm packages, SBOMs, attestations and other release assets are separate artifacts with their own identities.

## Included by default

The standard source publication includes the source, permanent regression tests/fixtures, build metadata, public documentation, license, package manifest/checksums, architecture/repository validators, and public hosting metadata explicitly enumerated by `PACKAGE_MANIFEST.txt`.

Permanent regression tests are product maintenance assets; they are not treated as disposable benchmark scratch merely because they were used during qualification.

## Explicitly excluded from the standard public source set

### `.corulix-rust/`

**Do not publish.** This is local/generated toolchain/runtime state rather than authoritative product source. It is not listed by `PACKAGE_MANIFEST.txt`.

### `release/`

**Do not publish from the Corulix public source tree.** Release-policy/private publication machinery belongs to private release tooling/operations and is not part of the product source publication set.

### `vendor/`

**Do not publish in the standard source package.** `Cargo.toml` + `Cargo.lock` define dependency resolution for the normal public source distribution. A vendored/offline bundle, if WhaTalker ever chooses to publish one, must be a separately identified artifact with its own manifest and checksums.

### `target/`

**Do not publish.** Rust build output is generated/disposable. Certified release binaries must be retained as release artifacts outside `target/` before build output is cleaned.

### Private/internal material

Do not publish as part of the standard source set:

- WhaTalker private release-tooling repositories/directories;
- Brain/internal governance stores and private decision logs;
- temporary benchmark/qualification workspaces, prompts, transcripts, oracles and manifests;
- internal status/audit reports unless separately approved for public release;
- developer-local IDE/workspace topology files;
- caches, logs, scratch copies and local machine state;
- credentials, keys, tokens or private environment material.

## `SHASUMS256.txt`

A root-level upstream checksum capture named `SHASUMS256.txt` is not part of the current `PACKAGE_MANIFEST.txt` and is not required by the public source documentation. Do not include such a file in the standard publication merely because it exists locally; managed component integrity belongs to the product's pinned component metadata and release/supply-chain process.

## No-Git publication model

The 1.0.0 source set is content-defined. Local `.git` state, commit IDs, tree IDs and tags are not required source authority. A hosting platform may mirror/distribute the source, but it does not replace the publication manifest/checksum identity.

## Publication rule

Before public release:

1. compare the candidate package against `PACKAGE_MANIFEST.txt`;
2. reject any unexpected private/generated path;
3. verify `SHA256SUMS.txt` for the candidate source files;
4. verify version/license/tool-surface consistency;
5. verify platform release artifacts separately;
6. publish only after explicit owner authorization.
