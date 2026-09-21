# Testing and Quality Gates

Corulix uses layered validation so architecture, security boundaries, package metadata and runtime behavior are checked independently.

## Repository and architecture validation

```bash
python3 wht_scripts/wht_verify_architecture.py
python3 wht_scripts/wht_verify_repository.py
```

## Rust quality gates

Applicable release-quality commands include:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --release --locked
cargo doc --workspace --no-deps --locked
cargo deny check
```

## Security-focused tests

Permanent regression coverage should exercise relevant boundaries, including:

- parent traversal and external absolute-path rejection;
- symlink/reparse escape behavior;
- object-authority/fail-closed platform behavior;
- invalid/oversized input handling;
- strict MCP schemas;
- stdout/stderr protocol separation;
- provider-resolution and poisoned-environment resistance;
- controlled process lifecycle/cancellation;
- governed mutation/gate behavior.

## Language tests

Each supported language needs representative structural, provider, validation and security coverage appropriate to the capabilities claimed in `wht_language_support.md`.

## Permanent tests vs disposable benchmark data

Permanent regression tests and `wht_tests/` fixtures are product maintenance assets and remain in the public source set when listed by `PACKAGE_MANIFEST.txt`.

Temporary benchmark workspaces, transcripts, oracle copies, trial manifests and local harness registrations are not product tests and are not release dependencies.

## Evidence discipline

Exact test counts and one-time PASS/FAIL logs belong to the release-validation run in which they were produced. Public documentation defines the required categories and current product contract rather than retaining temporary benchmark/qualification evidence.
