# ADR-0025 — Strict semantic-fidelity levels and custom type-set profiles

- Status: ACCEPTED (2026-09-28, maintainer decision "strict")
- Resolves: GAP-027
- Work package: WP-063

## Decision

1. The SF table of V13 §8.6 is enforced strictly. A data packet at level `s`
   carries every required type of `s` and no type outside
   `required ∪ optional`. The only optional types are SEN in SF4 and EMO in
   SF6 (explicit opt-in).
2. The sender restricts disclosure to the profile. If consent withholds a
   required type, the sender refuses the frame; moving to another SF level
   needs a new handshake (no silent downgrade).
3. Establishment fails if sender and receiver consent together do not
   cover the profile's required types.
4. Receivers check the profile inside the quarantine, before decoding.
5. Custom type-set profiles (V13 §17, for example `MEB-HANDOVER` = INT, CTX,
   TEM, SEN) are registry entries pinned in the session descriptor. Their
   packets carry `sf_level = 0`. Only one custom profile may be active per
   session.

## Consequence

"Share KNO+INT+CTX, later add EMO" works at SF2 → SF6 only with a new
session, or directly in SF6 with EMO masked first and then opted in.
