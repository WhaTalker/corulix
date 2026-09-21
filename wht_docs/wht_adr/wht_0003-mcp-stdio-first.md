# ADR 0003 — MCP stdio First

**Status:** Accepted

The baseline MCP transport is stdio. This keeps the initial protocol surface
local and narrow while preserving transport concerns inside `wht_corulix_mcp`.
Network transports require a separate architecture and threat-model review.
