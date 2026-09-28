# ADR-0009 — Deterministic AEAD nonce derivation and ESP traffic keys

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-002
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-016, WP-017

## Context

V13 §9.2 says the 96-bit packet nonce is "deterministically derived from the
session traffic key namespace plus `timeline_id || segment_seq`, or randomly
generated", but fixes no KDF, no key, no truncation. `timeline_id ||
segment_seq` is 20 bytes; the nonce is 12. Receivers read the nonce from the
cleartext header, so interoperability does not depend on the derivation,
but **uniqueness** does, and golden vectors need one fixed algorithm.

## Decision

### Traffic keys

After the Noise IK handshake, let `k_i2r`, `k_r2i` be the two 32-byte keys of
Noise `Split()` (initiator→responder, responder→initiator). They are **never**
used directly. For each direction `d`:

```text
k_aead[d]  = BLAKE2b-256(key = k_split[d], data = "esp/v1/aead-key")
k_nonce[d] = BLAKE2b-256(key = k_split[d], data = "esp/v1/nonce-key")
```

(BLAKE2b in keyed mode, RFC 7693, 32-byte output.) Noise transport messages
are not used for ESP application packets, so `k_split` has exactly one use:
deriving these keys.

### Deterministic nonce profile (`NONCE_DETERMINISTIC`, default)

```text
timeline_tag = BLAKE2b(key = k_nonce[d], data = "esp/v1/timeline-tag" || timeline_id, digest_size = 8)
nonce        = timeline_tag (8 bytes) || segment_seq (uint32 big-endian)
```

Properties:

- Within one timeline the map `segment_seq → nonce` is injective, so nonce
  uniqueness reduces to "never reuse a `segment_seq`" (ADR-0016, V13 rule ii).
- Across timelines under the same key, the sender **must** keep the set of
  timeline tags used under `k_aead[d]` and must not open a timeline whose tag
  collides (probability ≈ n²/2⁶⁵; checked, not assumed).

### Random nonce profile (`NONCE_RANDOM`)

12 bytes from the OS CSPRNG; the sender keeps the set of used nonces under
the current key and redraws duplicates *before* encryption (V13 rule iii).
Sessions are bounded to 2³² packets so that the birthday bound stays below
2⁻³² (V13 SHOULD).

### Receiver

In the deterministic profile the receiver recomputes the nonce and rejects
packets whose header nonce differs. In both profiles the receiver keeps a
replay cache for the lifetime of the key.

## Consequences

- Golden vectors can be produced from fixed `k_split` test keys.
- Losing sender sequence state requires a new session (ADR-0016).
- Errata proposal for V13.1 (WP-085).
