# ADR 0005 — Snapshot Index Architecture

**Status:** Accepted

Readers observe an immutable active snapshot. Refresh work builds and validates
a replacement state before atomic publication rather than partially mutating
the active index.
