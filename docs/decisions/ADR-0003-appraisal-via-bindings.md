# ADR-0003 — Appraisal causes via semantic bindings, not EMO duplication

- Status: ACCEPTED (2026-09-28; implemented in WP-005/WP-011)

Causes and targets of affect ("fear *elicited_by* possible dismissal") are
expressed as separately maskable `SemanticBinding`s. They are not copied into
EMO. Disclosure is default-deny and requires both endpoint types to be
disclosed (plan §§12–13).
