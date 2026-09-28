# ADR-0011 — Addendum TLV profile `esp-addendum-v1`

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-004 (and the control-TLV part of GAP-005)
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-048, WP-049

## Context

V13 assigns the v1 codes 0x01, 0x10–0x11, 0x20–0x24, 0x30, 0x40–0x42,
0x50–0x52, 0x60–0x65 and 0x70–0x73. It leaves all other codes "unassigned
unless a registry-pinned profile explicitly allocates them". The plan's
addendum objects (bindings, evidence claims, affect descriptors, episodes,
intention states) and the session-control messages need codes.

## Decision

The registry profile `esp-addendum-v1` allocates the range **0x80–0x9F**. A
session uses the profile only if the session descriptor (ADR-0012) pins
`esp-addendum-v1` together with its registry digest. Without that pin, codes
0x80–0x9F are unknown: they are **ignored, never reinterpreted**, and never
passed on to the application.

| Code | Object | Body encoding |
|---|---|---|
| 0x80 | `SESSION_DESCRIPTOR` | binary, ADR-0012 |
| 0x81 | `SESSION_CLOSE` | `reason u8` · `detail_len u16` · UTF-8 detail |
| 0x82 | `ERROR` | `code u16` (ErrorCode register) · `detail_len u16` · UTF-8 |
| 0x83 | `REGISTRY_DIGEST` | `name_len u8` · name · `digest[32]` |
| 0x84 | `STATIC_KEY_BINDING` | ADR-0013 |
| 0x85 | `SESSION_BINDING` | ADR-0013 |
| 0x90 | `SEMANTIC_BINDING` | `encoding u8 = 1` · ESP canonical JSON v1 |
| 0x91 | `EVIDENCE_CLAIM` | `encoding u8 = 1` · ESP canonical JSON v1 |
| 0x92 | `AFFECT_DESCRIPTOR` (carries `affect_scope`) | `encoding u8 = 1` · ESP canonical JSON v1 |
| 0x93 | `EMOTION_EPISODE` | `encoding u8 = 1` · ESP canonical JSON v1 |
| 0x94 | `INTENTION_STATE` | `encoding u8 = 1` · ESP canonical JSON v1 |
| 0x95 | `FRAME_METADATA` (frame id, clock stamp, provenance, consent ref, masked types) | `encoding u8 = 1` · ESP canonical JSON v1 |

JSON-bodied objects are not signed individually; the packet signature and
AEAD cover them. Each masked object is **absent from the payload**. A packet
may carry at most one `AFFECT_DESCRIPTOR` per source, and an
`AFFECT_DESCRIPTOR` is only valid if the EMO typed latent or the EMO anchor
coordinates are present (it describes EMO).

## Consequences

No V13 code is touched. V13-only receivers remain conformant: they ignore
0x80–0x9F.

## Type-presence invariant (added with WP-049)

Bit `t` of `types_bitmap` is set **iff** at least one wire object of type `t`
is present: a typed latent, anchor coordinates, or an addendum object of that
type (0x92/0x93 → EMO, 0x94 → INT; 0x90 requires both endpoint types).
Receivers reject any object whose type bit is clear. Without this rule an EMO
descriptor could travel next to `EMO_MASKED = 1`.
