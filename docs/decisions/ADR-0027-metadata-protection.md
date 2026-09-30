# ADR-0027 — Metadata protection profile

- Status: ACCEPTED (2026-09-30, maintainer decision)
- Resolves: GAP-029
- Work package: WP-062

## Context

V13 §8.3 lists mitigations against metadata leaks: a constant type bitmap
with dummy content, decoy traffic, `TIMING_OBF` and an onion overlay. It does
not say how a receiver tells dummies from real content, how masking is
conveyed when `EMO_MASKED` would itself leak, or how both sides agree to use
the mitigations.

## Decision

Registry profile `esp-metadata-protection-v1`, pinned by both descriptors.
Its digest is BLAKE2b-256 over the name and the canonical configuration
(`constant_bitmap`, `pad_to`, `timing_bucket_ns`). A different configuration
fails negotiation. A side that configures protection refuses a session in
which the peer does not pin it. There is no silent fallback.

- Every packet (data, control, decoy) carries `types_bitmap = constant_bitmap`.
  The constant set must cover every type the session's SF profile allows.
- Absent or masked types are filled with random N(0,1) typed latents of the
  L1 dimension, in TAOSS order.
- Addendum TLV `0x87` `DUMMY_TYPES` (inside the AEAD, exactly one per packet)
  carries `dummy_bitmap u16 · masked_bitmap u16`.
  - `EMO_MASKED` is never set in the header.
  - The receiver takes the mask from `masked_bitmap`.
- Addendum TLV `0x88` `FILLER` (zero bytes) pads the plaintext to a multiple
  of `pad_to`.
- With `timing_bucket_ns > 0`:
  - `timestamp_ns` is rounded down to the bucket;
  - `dt_ms = 0`;
  - `TIMING_OBF` is set.

  This is timing obfuscation, not differential privacy. It never touches
  `DP_LEVEL`.
- A decoy is a packet whose real type set is empty and which carries no
  control TLV. The receiver authenticates it, advances the replay window and
  discards it.
- Receiver order:
  1. authenticate;
  2. check the constant bitmap, the absent `EMO_MASKED`, the padding, the
     timing and exactly one `0x87`;
  3. check dummies ⊆ constant set and that every declared dummy has its
     latent;
  4. strip dummies, `0x87` and `0x88`;
  5. continue with the *real* header (real bitmap, `EMO_MASKED` from the
     encrypted mask) through the unchanged quarantine and Accept pipeline.
- Constant-rate sending is a driver concern (`PacedSender`: one packet per
  tick, a decoy when idle).
- The onion/mixnet overlay is a `Connection` wrapper (`LayeredConnection`).

## Consequences

- Observers see a constant bitmap, a constant size (as long as frames fit in
  `pad_to`) and a constant rate. Tests show that header and size features
  are identical with and without EMO.
- Cost: bandwidth for dummies and padding, plus up to one tick of added
  latency. With all six types, a protected packet does not fit a single QUIC
  DATAGRAM (1100 bytes) at F32. Use STATE, or INT8 with fewer types.
- A real type marked as a dummy is only dropped. It cannot smuggle content
  past consent, because the Accept predicate runs on the real set.
