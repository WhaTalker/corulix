# ADR 0006 — Workspace Root as a Security Boundary

**Status:** Accepted

Source reads are rooted under an explicitly opened canonical workspace.
Parent traversal, disallowed absolute paths, and canonicalized path escapes are
denied before file content is returned to higher layers.
