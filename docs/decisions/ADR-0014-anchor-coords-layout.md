# ADR-0014 — Layout of `TLV_ANCHOR_COORDS` (0x50)

- Status: PROPOSED (implemented in `esp.codec.frame_wire`, awaiting approval)
- Resolves: GAP-007
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-050, WP-049

## Context

V13 §5.4 assigns code 0x50 but defers the layout to an "Anchor Coordinate
Companion Specification" that does not exist yet.

## Proposal

```text
t u8 = 0x50 · length u32
type_code u8          0x60..0x65, the TAOSS type the coordinates describe
anchor_set_id[16]     deterministic registry UUID of the anchor set (uuid5, esp.ontology)
similarity_kind u8    0 = cosine (v1); 1 = projection, 2 = RBF reserved
m u16                 number of anchors, must equal the pinned anchor set size
float32[m]            coordinates in the anchor-set order, big-endian binary32
```

- The anchor set must be pinned in the session (registry digest in the
  session descriptor). Unknown sets are rejected.
- Coordinates cover exactly the anchor set, with no partial vectors.
- At most one 0x50 TLV per TAOSS type per payload.
- Interpretation-only mode (V13 §5.4) is a payload with 0x50 and without the
  corresponding typed latent. It sets the type bit (ADR-0011 invariant).
