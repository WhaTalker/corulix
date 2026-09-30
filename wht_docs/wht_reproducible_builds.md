# Reproducible Builds

## Goal

Corulix aims for reproducible release artifacts where practical and, at minimum, for every material build input to be explicit and auditable.

## Source identity without Git

The reproducibility model does not require a Git checkout or commit identity. Record at least:

- `VERSION`;
- `PACKAGE_MANIFEST.txt`;
- `SHA256SUMS.txt`;
- `Cargo.lock`;
- `rust-toolchain.toml`;
- target triple;
- release build command/features;
- relevant environment controls;
- produced artifact name, size and SHA-256.

## Verification procedure

For each supported target:

1. start from an exact copy of the declared source publication set;
2. verify source checksums before building;
3. use the locked dependency graph and documented toolchain;
4. use the documented target/build flags;
5. generate artifact digests immediately after the build;
6. repeat in an equivalent clean environment when bit-for-bit reproducibility is a release requirement;
7. investigate any unexplained binary difference rather than silently replacing the expected artifact identity.

## Generated/local state

`target/`, `.corulix-rust/`, and `vendor/` are not release source identity in the standard public source package. A local `vendor/` tree may support controlled/offline builds, but an offline vendored distribution must be separately manifested if published.

## Common sources of nondeterminism

Review timestamps, absolute paths, archive metadata, linker/build IDs, locale/timezone, generated source, build-script environment inputs, toolchain patch versions, linker versions and target-specific metadata.

A reproducibility claim applies only to the artifacts and environments actually compared.
