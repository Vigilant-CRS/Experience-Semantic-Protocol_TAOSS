# ADR-0013 — Static-key binding and session binding

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-006
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-018, WP-052

## Context

V13 §9.3 requires two things. The responder publishes its X25519 static key
cross-signed with Ed25519, and the initiator verifies that signature before
the first application packet. The per-session `sender_id` must be bound to
the Noise session. V13 gives no byte format for either.

## Decision

`STATIC_KEY_BINDING` (0x84, ADR-0011), published out of band and/or in the
responder's first handshake payload:

```text
t u8 = 0x84 · length u32 · version u8 = 1
x25519_static_pk[32] · identity_pk[32] (Ed25519) · valid_until_ns u64
sig[64] = Ed25519(identity_sk, "esp/v1/static-binding" || all previous bytes)
```

`SESSION_BINDING` (0x85), sent by each side inside its Noise handshake
payload once the handshake hash is known. In IK, the initiator sends it in
its first transport message; the responder sends it in message 2.

```text
t u8 = 0x85 · length u32 · version u8 = 1
session_pk[32] (= header sender_id) · noise_h[32]
sig[64] = Ed25519(session_sk, "esp/v1/session-binding" || all previous bytes)
```

The long-term identity is linked only by the optional, encrypted, once-per-
session `TLV_IDENTITY_PROOF` (0x20), unchanged from V13.

## Consequences

`sender_id` values of two sessions are unlinkable. A session binding
replayed into another handshake fails because `noise_h` differs.
