# Supply-Chain Security

Corulix treats dependencies, build inputs, package metadata, managed provider artifacts and release binaries as part of the software supply chain.

## Required controls

Before an official release, the applicable pipeline should establish:

1. locked dependency resolution;
2. dependency license-policy validation;
3. dependency advisory/vulnerability review;
4. source and secret scanning;
5. SBOM generation where required;
6. controlled/pinned build tooling;
7. least-privilege release credentials;
8. artifact checksums and provenance/attestation evidence;
9. package/source-set validation;
10. registry/artifact verification after publication.

## Dependency authority

`Cargo.toml` manifests and `Cargo.lock` define the Rust dependency graph for the source release. `deny.toml` defines dependency policy gates. `wht_dependencies.md` documents the human-readable admission policy.

The standard source publication does not require `vendor/`; if a vendored/offline source bundle is ever published, it is a separate artifact with its own content manifest and checksums.

## Managed provider artifacts

Corulix-managed runtime/provider components are outside the inspected workspace and are admitted through explicit identity/integrity metadata. Managed component acquisition must verify the expected artifact before activation and must not grant workspace-local binaries provider authority.

## CI / hosting metadata

If a hosting/CI platform is used, third-party workflow components should be pinned according to the applicable platform policy. Hosting metadata is not a substitute for the source publication manifest/checksum authority.

## Secrets

Release tokens, signing keys, package-registry credentials and other secrets must not be stored in the public source package. Operational credentials should be scoped to the minimum publication actions required.

## Relationship to reproducibility

Supply-chain integrity establishes trusted/recorded inputs. Reproducibility asks whether equivalent inputs produce equivalent outputs. They are related but independent controls.
