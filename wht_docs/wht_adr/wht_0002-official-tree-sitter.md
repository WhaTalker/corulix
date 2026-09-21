# ADR 0002 — Official Tree-sitter Upstream

**Status:** Accepted

Corulix uses the official Tree-sitter runtime and approved upstream language
grammars. Tree-sitter implementation details are isolated in
`wht_corulix_syntax` (renamed from `wht_corulix_languages` in the Enterprise
Canonical Core Rebaseline's Syntax crate rebaseline; the decision recorded
here is unchanged, only the owning crate's name).
