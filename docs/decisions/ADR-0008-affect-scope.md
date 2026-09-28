# ADR-0008 — `affect_scope`: content-side vs. subject-side affect

- Status: ACCEPTED (2026-09-28; implemented in WP-003/WP-004/WP-011)
- Resolves: GAP-001
- Class: `V13_NORMATIVE` boundary, `V13_COMPATIBLE_ADDENDUM` encoding

## Decision

Every EMO statement carries `affect_scope ∈ {CONTENT, SELF_DECLARED,
INFERRED_SUBJECT, MACHINE_RELAY}` with the rules of plan §4.5:

- `SELF_DECLARED` only from `self_report` (or a simulated self report from
  `synthetic_ground_truth`);
- `INFERRED_SUBJECT` only from inferential sources, and only on profile L2 or
  higher;
- synthetic ground truth never carries `INFERRED_SUBJECT` or `MACHINE_RELAY`;
- on the wire it is carried by `AFFECT_DESCRIPTOR` (ADR-0011), inside the
  AEAD payload.

Code: `esp.semantics.scope`. Tests: `tests/unit/semantics/`, `tests/unit/frame/`.
