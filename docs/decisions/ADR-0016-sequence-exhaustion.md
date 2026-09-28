# ADR-0016 — `segment_seq` never wraps

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-009
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-017, WP-065

## Decision

- `segment_seq` is a 32-bit counter that starts at 0 per timeline and only
  increases. The sender MUST close the session (and open a new session with
  new keys) before using `2^32 - 1`. The last usable value is
  `2^32 - 2`, so that "exhausted" is detectable.
- Receivers MUST NOT interpret a small `segment_seq` after a large one as a
  wrap; it is replay/outside-window and is rejected.
- Loss of sender sequence state (crash, restore, VM clone) ⇒ terminate the
  session, fresh Noise IK handshake (V13 §9.2 rule ii). Persisted sequence
  state is written *before* the packet is released (fail closed).
