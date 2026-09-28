# ADR-0012 — Session descriptor and session-control messages

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-005, GAP-024 (declaration part)
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-024, WP-048, WP-065

## Decision

The **session descriptor** is a canonical binary object carried inside the
Noise IK handshake payloads. Each side sends its own descriptor, so it is
confidential and authenticated by Noise. Both descriptors are hashed into
the application transcript:

```text
transcript = BLAKE2b-256("esp/v1/transcript" || noise_h || H(desc_initiator) || H(desc_responder)
                         || H(sender_capability) || H(receiver_capability_or_default_id))
```

Descriptor fields (all integers big-endian):

```text
version u8 = 1
profile u8                     V13 header profile byte (L1 = 0x01)
sf_level u8
nonce_mode u8                  0 = DETERMINISTIC (ADR-0009), 1 = RANDOM
pq_mode u8                     0 = CLASSICAL_ONLY, 1 = HYBRID_OUTER, 2 = HYBRID_NOISE
dp_level u8                    V13 DP_LEVEL enum
w_back u16, w_fwd u16          replay windows (V13 §9.5)
rate_sensor_mhz u32            the four rates of V13 §16, in milli-Hz
rate_latent_mhz u32
rate_packet_mhz u32
rate_privacy_mhz u32
max_payload_len u32            ADR-0010
clock_tolerance_ms u32         ADR-0019
n_registries u8                then per entry: name_len u8, name, digest[32]
                               (pins e.g. esp-emo-v13-basic8-v1, esp-addendum-v1)
decoder_policy u8[6]           per TAOSS type: 0 STRICT_REFUSE, 1 GRACEFUL, 2 PRIOR_IMPUTE
```

Rules:

- A descriptor change requires a new handshake. There are no silent profile
  upgrades (plan WP-024 property).
- `pq_mode = CLASSICAL_ONLY` is the only v1 value; it must never be presented
  as post-quantum.
- Control messages after establishment (SESSION_CLOSE, ERROR,
  REGISTRY_DIGEST, KEY_ROTATION via V13 0x41/0x42, REVOCATION via 0x23) travel
  as TLVs in ordinary ESP packets on the reliable control stream.
- PANIC is `TLV_REVOCATION_INTENT` with `TERMINATE_SESSIONS` on the reliable
  control stream, never a datagram.
