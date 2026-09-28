# ADR-0010 — `payload_len` counts the ciphertext only

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-003
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-014, WP-016

## Context

V13 Appendix A lists `payload_len` without saying whether it includes the
16-byte Poly1305 tag and the 64-byte signature.

## Decision

`payload_len` = number of AEAD ciphertext bytes, **excluding** the tag and
the signature. A packet is exactly:

```text
100 (header) + payload_len (ciphertext) + 16 (tag) + 64 (signature)
```

ChaCha20 is a stream cipher, so `payload_len` equals the plaintext length.

Evidence that this is V13's intent: the §16 wire-rate arithmetic adds a fixed
180-byte overhead (100 + 16 + 64) to the typed payload.

Receivers reject packets whose total length differs from the formula, and
packets whose `payload_len` exceeds the profile maximum
(`max_payload_len`, default 1 MiB for L1) **before** any cryptographic work.

## Consequences

Framing is self-delimiting from the header alone, which also bounds memory
per packet.
