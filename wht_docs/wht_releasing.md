# Release Process

Source publication and an official versioned release are separate lifecycle stages. This document describes the **no-Git release authority model used by Corulix**, unchanged in 1.1.0.

## Release authority

Official releases are authorized by WhaTalker Inc. Publication must be bound to an exact source/publication identity and exact release artifacts.

Corulix release authority does **not** depend on a local `.git` repository, commit SHA, Git tree ID, tag, or Git command.

## Required source identity

A release must record and verify, as applicable:

```text
RELEASE_VERSION
PACKAGE_MANIFEST.txt
SHA256SUMS.txt
Cargo.lock
rust-toolchain.toml
platform artifact SHA-256 values
package metadata/version/license
```

`PACKAGE_MANIFEST.txt` defines the standard public source set. `SHA256SUMS.txt` binds that set (except the checksum file itself) to content hashes.

## No-Git policy

The release workflow must not require or execute Git operations. Hosting-platform repositories/tags, if used as distribution metadata, are not the cryptographic/source authority for the release.

## Mandatory release gates

Applicable gates include:

```text
format / lint
unit + integration tests
locked release build
architecture/repository validation
dependency policy + advisory review
security/secret scan
SBOM generation
package-content validation
platform artifact verification
release provenance / attestations
registry/package verification
public source-package verification
```

A gate that did not execute against the exact release candidate must not be represented as PASS.

## Publication-set boundary

The standard public source set excludes local/generated/private material such as:

```text
.corulix-rust/
release/
vendor/
target/
private release tooling
Brain/internal governance storage
benchmark/qualification scratch trees
internal status reports
```

See `wht_publication_scope.md`.

`vendor/` may be used locally for controlled/offline dependency work, but it is not part of the standard public source package. A separately published offline/vendored source bundle would be a distinct release artifact with its own manifest/checksums.

## Package registries

Cargo and npm publication are separately authorized. Registry availability is verified after publication; local documentation must not claim a package exists merely because packaging metadata is ready.

Internal package dependency ordering may require supporting packages to become available before dependent packages can be published.

## Preferred ordering

```text
clean source tree
    ↓
publication-set manifest + checksums
    ↓
quality / security / package gates
    ↓
platform artifact verification
    ↓
owner publication authorization
    ↓
Cargo/npm/source-host publication as applicable
    ↓
registry/artifact verification
    ↓
final release record
```

## Hard stops

Publication stops on unresolved source drift, failed required validation, unacceptable security findings, incompatible licenses, package identity conflicts, missing required platform artifacts, or provenance/attestation failures.

## Release credentials

Signing keys, registry credentials and other publication secrets are operational secrets and are never stored in the public source package.
