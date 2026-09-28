# ADR-0015 — Signature input of signed TLVs and optional capability fields

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-008
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-019, WP-020, WP-051, WP-053

## Context

V13 §9.2 defines `canonical(x)` as the deterministic big-endian field
serialization "in the order shown". Most signed TLVs (0x22, 0x23, 0x24, 0x41,
0x70) sign `domain || canonical(all previous fields)`, which includes `t` and
`length`. `ReceiverCapability` (0x21) is written as
`canonical(t || version || … || noise_h)`, which reads as skipping `length`.
It also has fields that exist only "if EMO accepted".

## Decision

1. For every TLV whose V13 schema says "canonical(all previous fields)" or
   uses an ellipsis notation, the signature input is

   ```text
   domain_separator || tlv_bytes[0 : total_length - 64]
   ```

   That is every byte of the TLV as transmitted (including `t` and `length`)
   up to the signature. The `length` value already counts the 64-byte
   signature. This applies uniformly to 0x21, 0x22, 0x23, 0x24, 0x41 and 0x70.
2. TLVs with an explicitly spelled-out message (0x20 identity proof, 0x40
   vendor provenance, 0x42 rotation core `m_rot`) sign exactly that message.
3. `ReceiverCapability`: `valence_bounds[2]` is present **iff** EMO (bit 2)
   is set in `accept_types`, and is omitted otherwise (V13 §9.7: "omitted
   from the canonical capability"). `max_norm[n_types]` follows the set bits
   of `accept_types`, LSB first, and `n_types` must equal
   `popcount(accept_types)`.
4. Parsers reject any trailing bytes and any length mismatch.

## Consequences

One signature rule for all "all previous fields" objects. The 0x21 ellipsis
notation goes into the V13.1 errata (WP-085).
