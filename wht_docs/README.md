# Corulix Documentation

This directory contains the public product, architecture, security, governance and release documentation for **WhaTalker Corulix™ 1.1.0**.

## Documentation map

| Area                            | Documents                                                                                                                                                                          |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture                    | [`wht_architecture.md`](wht_architecture.md), [`wht_architecture_boundaries.md`](wht_architecture_boundaries.md)                                                                   |
| Language and MCP                | [`wht_language_support.md`](wht_language_support.md), [`wht_mcp_compatibility.md`](wht_mcp_compatibility.md), [`wht_cli.md`](wht_cli.md)                                           |
| Workspace configuration (1.1.0) | [`wht_workspace_json_config_reference.md`](wht_workspace_json_config_reference.md)                                                                                                 |
| Security                        | [`wht_threat_model.md`](wht_threat_model.md), [`wht_supply_chain.md`](wht_supply_chain.md), [`wht_reproducible_builds.md`](wht_reproducible_builds.md)                             |
| Dependencies                    | [`wht_dependencies.md`](wht_dependencies.md), [`wht_third_party_notices.md`](wht_third_party_notices.md), [`wht_upstream_baseline.md`](wht_upstream_baseline.md)                   |
| Publication/release             | [`wht_publication_scope.md`](wht_publication_scope.md), [`wht_releasing.md`](wht_releasing.md), [`wht_testing.md`](wht_testing.md)                                                 |
| Host enforcement                | [`wht_host_enforcement.md`](wht_host_enforcement.md), [`wht_host_profiles/`](wht_host_profiles/)                                                                                   |
| Governance                      | [`wht_governance.md`](wht_governance.md), [`wht_code_of_conduct.md`](wht_code_of_conduct.md), [`wht_cla_policy.md`](wht_cla_policy.md), [`wht_dco_policy.md`](wht_dco_policy.md)   |
| Provenance                      | [`wht_provenance.md`](wht_provenance.md), [`wht_clean_room.md`](wht_clean_room.md), [`wht_provenance/wht_implementation_sources.md`](wht_provenance/wht_implementation_sources.md) |
| Legal/brand                     | [`wht_copyright.md`](wht_copyright.md), [`wht_trademarks.md`](wht_trademarks.md)                                                                                                   |
| Control alignment               | [`wht_iso_alignment.md`](wht_iso_alignment.md)                                                                                                                                     |
| Architecture decisions          | [`wht_adr/`](wht_adr/)                                                                                                                                                             |

## Documentation principles

- Current-facing documents describe the actual current product, not temporary development phases.
- ADRs may preserve point-in-time decisions; a superseded ADR must identify its current replacement/status.
- Private Brain records, temporary benchmark evidence, scratch workspaces and release-operation internals are not public documentation dependencies.
- `PACKAGE_MANIFEST.txt` defines the standard public source set.
- Runtime schemas/source remain implementation authority if a public document drifts.
