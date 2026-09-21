# Host Enforcement

## Terminology: this is not AI-client functional validation

This document and the profiles it indexes certify a single, narrow security
property per host: **can this host's own sandbox/permission system be made to
prevent bypassing Corulix's governance, and can a bypass attempt be
detected.** That property is called **Host Enforcement Certified** throughout
this documentation set.

It is a different claim from **Corulix Functionally Validated AI Client** —
whether Corulix's own MCP tool surface has completed formal end-to-end
functional validation with a given AI client's real coding workflows. A host
being Host Enforcement Certified here does not, by itself, mean that host is
a Corulix Functionally Validated AI Client; see the root
[`README.md`](../README.md) for which AI clients currently hold that
separate status. The two properties are independent and may coexist for the
same host when the evidence supports both.

## The honest boundary

Corulix strictly governs work that is routed through its own process. MCP alone
cannot force a host to route work through Corulix.

```text
CORULIX_INTERNAL_ENFORCEMENT=PROVABLE
HOST_GLOBAL_ROUTING_ENFORCEMENT=HOST_DEPENDENT
```

Whether an agent can perform governed work _without_ Corulix is a property of
the host and of its configuration, not a property of Corulix or of MCP. It must
therefore be established per host, per version, and per configuration.

Corulix documentation must never assert that a host makes such a bypass
impossible unless that host's profile records real evidence for that exact
claim, on that exact version, under that exact configuration.

## Where the certified answers live

The certified classifications are **not** restated here. Each host has one
canonical machine-readable profile, and those profiles are the only authority:

| Host                                   | Canonical profile                                                                                  |
| -------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Claude Code                            | [`wht_host_profiles/wht_claude_code.toml`](wht_host_profiles/wht_claude_code.toml)                 |
| Codex CLI                              | [`wht_host_profiles/wht_codex.toml`](wht_host_profiles/wht_codex.toml)                             |
| OpenCode                               | [`wht_host_profiles/wht_opencode.toml`](wht_host_profiles/wht_opencode.toml)                       |
| VS Code + built-in GitHub Copilot Chat | [`wht_host_profiles/wht_vscode_copilot_chat.toml`](wht_host_profiles/wht_vscode_copilot_chat.toml) |

Each profile carries `can_prevent_bypass`, `can_detect_bypass`,
`can_only_advise`, `required_configuration`, `known_limitations`,
`certification_scope`, `certified_host_version`, `certification_date`,
`evidence_type` and `evidence_reference`. Read the profile; do not rely on a
summary of it.

## How a profile is allowed to claim prevention

These rules are strict, and they are why the four profiles do not agree with
each other.

- `can_prevent_bypass = "YES"` requires that the certified configuration blocks
  the relevant path **technically** — by removing the capability, or by having
  the operating system or an external guard refuse the operation. Instructing
  the model not to do something is never prevention.
- `can_detect_bypass = "YES"` requires a real signal or audit record that
  actually distinguishes the blocked attempt, not merely the absence of a
  result.
- `can_only_advise = "YES"` is the correct answer whenever the protection rests
  on prompts, instruction files, or the model's voluntary cooperation.

A written policy addressed to the model is not enforcement.

## How the classifications were established

Every classification rests on execution against the real installed product, not
on documentation. Two methodological points matter when reading the evidence.

**Positive control.** Demonstrating that an operation did not happen proves
nothing unless the same test is shown to be capable of producing it. Each host
with a preventive claim was therefore run twice with an identical prompt and an
identical fixture workspace: once with the control removed, where the operation
must occur, and once with the certified configuration, where it must not. A
profile whose `positive_control.performed` is `false` makes no preventive
claim.

**Distinguishing refusal from prevention.** An absent result can mean the tool
layer refused the call, or merely that the model chose not to try. These are
completely different security properties and were separated deliberately: by
comparing the tool schema actually advertised to the model between
configurations, by reading structured denial records, and — for OpenCode — by
replacing the language model with a deterministic stub that attempted the
bypass unconditionally, so that a missing result could only be the permission
layer. The first run of the Claude Code case was in fact discarded for exactly
this reason: the model declined on policy grounds before the permission layer
was ever reached, which would have produced a flattering but meaningless
result.

## Configuration precedence is part of the answer

A control that a lower-authority configuration can switch off is not
prevention. Each profile records `host_config_downgrade_path` explicitly, and
where a downgrade path is real and unmitigated the profile is capped at
`PARTIAL` or `NO` regardless of how the control behaves when it does apply.

This is the single largest difference between the four hosts, and it is worth
checking before selecting a host for governed work.

## Scope discipline

A profile certifies one host at one version under one configuration. It does
not extend to other versions of the same host, to other clients that embed it,
or to a product family. In particular, the VS Code profile certifies one named
client and explicitly declines to generalize to VS Code as a category.

Where a required behaviour could not be exercised in the certifying
environment, the profile says so in `known_limitations` and
`certification_scope` and makes no claim in its place. An unexercised mechanism
is recorded as unexercised, never counted as enforcement.

## Trust is never delegated to the host

No host configuration grants a host authority to set Corulix `WorkspaceTrust`,
`RiskClass`, `ToolPlan`, required gates, or `Evidence`. The MCP tool inputs
expose no field through which a host could do so, and unknown fields are
rejected rather than ignored. Every profile records this as
`host_trust_elevation`, `host_risk_override` and `host_gate_override`, all
zero.

Corulix decides. The host asks.
