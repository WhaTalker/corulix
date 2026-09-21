# ISO-Aligned Control Design

## Purpose and disclaimer

This document maps Corulix engineering practices to high-level themes found in
widely used ISO/IEC information-security and application-security standards.
It is an engineering alignment guide only.

**Corulix is not represented by this document as ISO certified, formally ISO
compliant, or independently audited.** Certification requires an applicable
management system, defined scope, evidence, and an accredited audit process
outside the scope of this repository.

## Referenced themes

The control design draws primarily from themes in:

- ISO/IEC 27001:2022;
- ISO/IEC 27002:2022;
- ISO/IEC 27034-1.

## Control mapping

| Theme | Corulix practice |
|---|---|
| Asset and trust-boundary identification | `wht_threat_model.md` |
| Least privilege | Read-only workspace model and constrained protocol surface |
| Input validation | Typed MCP inputs and workspace-path boundary checks |
| Secure architecture | Mechanically checked crate/layer boundaries |
| Dependency governance | `wht_dependencies.md`, `wht_supply_chain.md` |
| Source provenance | `wht_provenance.md`, `wht_clean_room.md` |
| Change governance | Protected-branch/PR model and `wht_governance.md` |
| Release integrity | `wht_releasing.md`, checksums, SBOM and attestations where required |
| Build reproducibility | `wht_reproducible_builds.md` |
| Vulnerability management | Advisory/security scanning gates |
| Security reporting | Repository `SECURITY.md` |

## Evidence discipline

A documented control is not automatically evidence that the control executed
successfully for a particular release. Runtime/build/security claims must be
bound to the exact source and release candidate they describe.

## Scope limitation

This repository does not make claims about SOC 2, PCI DSS, GDPR compliance, or
other regulatory frameworks. Downstream deployment and organizational controls
must be assessed by the operator for its own use case.
