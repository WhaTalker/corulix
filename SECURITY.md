# Security Policy

WhaTalker Corulix operates directly on software workspaces, so workspace authority, provider resolution, process execution and controlled mutation are first-class security boundaries.

## Supported version

```text
Product:  WhaTalker Corulix
Version:  1.1.0
License:  AGPL-3.0-only
```

The historical `0.1.0-alpha.2` line is superseded and is not the current security-supported product baseline.

## Reporting a vulnerability

Use the repository/hosting provider's private vulnerability-reporting mechanism when it is enabled for the official Corulix publication. Do **not** disclose a suspected vulnerability through a public issue before the maintainers have had an opportunity to triage it.

Corulix does not claim a dedicated public security mailbox or PGP workflow in this source package. Any future reporting channel must be documented here before it is represented as operational.

## Security design principles

- **Governed mutation only.** Discovery/search/parse/semantic/preview operations do not gain ambient live-write authority. Source edits are made through the explicit `ChangeSession`/mutation model.
- **Workspace confinement.** Workspace-relative paths are canonicalized and confined to approved roots; traversal, external absolute paths and symlink escape attempts fail closed.
- **Object authority over pathname authority.** A pathname is not accepted as equivalent to a safely bound workspace/process object. Platform limitations therefore may produce a deliberate deny/unavailable result.
- **Trust cannot self-elevate.** Repository content and individual MCP requests cannot grant themselves host-only workspace execution trust or provider authority.
- **No ambient provider PATH authority.** External providers resolve through managed or operator-approved authorities.
- **Controlled external execution.** Child processes use explicit argv/environment/working-directory/timeout/cancellation policy and platform containment where available.
- **Protocol stdout is protected.** MCP stdio stdout is protocol-only after startup; logs/diagnostics use stderr.
- **Strict schemas.** Public MCP inputs are strongly typed and unknown/unadmitted fields are rejected by the schema layer.
- **Sensitive data minimization.** Tool responses should not leak credentials, unrelated host environment values, unnecessary absolute host paths or raw internal stack traces.
- **Dependency/provenance discipline.** Dependencies and external source inputs follow the project dependency, provenance and clean-room policies.

## Windows fail-closed behavior

Windows x86_64 is a supported platform, natively certified since 1.0.0 and re-certified for 1.1.0. Some workspace-bound execution paths intentionally fail closed when the implementation cannot establish the required safe object/process binding. A pathname-only fallback is not claimed as an equivalent security boundary.

## Managed toolchains

Managed components are installed under Corulix-owned application data, outside inspected workspaces. Provisioning verifies pinned artifact identity before activation and tracks ownership/lifecycle state. Local managed-toolchain directories are runtime state, not public source.

## Scope

This policy covers official Corulix source and official release artifacts. It does not cover:

- unofficial forks or redistributions;
- vulnerabilities in third-party projects themselves (report upstream as appropriate);
- vulnerabilities solely in the MCP host/client unless Corulix's own integration is the affected component.

See also:

- `wht_docs/wht_threat_model.md`
- `wht_docs/wht_supply_chain.md`
- `wht_docs/wht_dependencies.md`
- `wht_docs/wht_architecture_boundaries.md`
