<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0030 — Replay-pattern watermark

- Status: PROPOSED (implemented; awaiting maintainer review)
- Resolves: GAP-016
- Work package: WP-057 (covert-channel hardening), WP-068 (recall path)
- Code: `src/esp/xcf/watermark.py`, `src/esp/session/endpoint.py`
- Vectors: `vectors/replay/watermark.json`

## Context

V13's covert-channel section lists five hardening constraints. The fifth reads:
"Replay segments include vendor-side watermark TLVs preventing replay-timing
patterns from being repurposed as a steganographic carrier." V13 assigns no TLV
code, body or verification rule. The threat: a sender that is allowed to replay
a stored capsule (V13 "Recall Path", `RECALL_FRAME` 0x51) but masks EMO could
encode masked content in *when* segments are sent, in their header timestamps,
in their order, or in which segments it drops.

## Decision

**Replay segment.** A data packet that carries `RECALL_FRAME` (0x51).

**TLV.** Addendum code `0x89 REPLAY_WATERMARK` in `esp-addendum-v1`. It MUST be
the last TLV of the payload. Body, 48 bytes, big-endian:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 16 | `vendor_id` |
| 16 | 4 | `replay_epoch` (u32) |
| 20 | 4 | `replay_index` (u32) |
| 24 | 8 | `scheduled_offset_ns` (u64) |
| 32 | 16 | `tag` |

```
tag = BLAKE2b-128(key = vendor_key,
                  "esp/v1/replay-watermark" ‖ timeline_id[16] ‖ replay_epoch u32
                  ‖ replay_index u32 ‖ scheduled_offset_ns u64 ‖ BLAKE2b-256(prefix))
prefix = all payload bytes before the watermark TLV (includes RECALL_FRAME)
```

`segment_seq` is deliberately not in the tag. The sequence number is assigned
only after the payload is final (retransmissions reuse it), and the AEAD
already binds the header, including `segment_seq`, to the whole payload.

**Schedule.** Replay timing comes from the vendor key, not from the sender:

```
offset(0) = 0
offset(i) = i · period_ns
          + (u64_be(BLAKE2b-64(key = vendor_key,
                "esp/v1/replay-schedule" ‖ vendor_id ‖ epoch u32 ‖ i u32)) mod (jitter_ns + 1))
```

with `jitter_ns < period_ns` and `tolerance_ns < period_ns / 2`. The declared
schedule is `(period_ns, jitter_ns, tolerance_ns, start_grid_ns)`.

**Receiver rules.**

1. A replay segment needs `ALLOW_REPLAY` in the sender capability.
2. A receiver without a replay-watermark policy refuses replay segments (fail
   closed). Replay is not defined under `esp-metadata-protection-v1` in this
   version.
3. Exactly one watermark, as the last TLV; a watermark on a non-replay segment
   is refused.
4. `vendor_id` is trusted; the tag verifies (constant-time comparison).
5. `scheduled_offset_ns` equals `offset(index)` recomputed from the schedule.
6. Epochs are numbered per session from 0 without gaps. Index 0 starts an
   epoch; its header timestamp is the epoch base and must lie on the
   `start_grid_ns` grid. Indices are contiguous.
7. `header.timestamp_ns = base + scheduled_offset_ns` exactly.
8. `|arrival(i) − arrival(0) − scheduled_offset_ns| ≤ tolerance_ns`.
9. The verifier state advances only when the packet is finally accepted.

Refusals carry `REPLAY_WATERMARK_INVALID` (0x0401) in `esp-error-codes-v1`.

The sender side (`SenderEndpoint.send_replay_segment`) refuses to send outside
`tolerance_ns` of the scheduled time and stamps the scheduled time in the header.

## Consequences

- Within an epoch, the sender has no timing, ordering or selection choice
  beyond `tolerance_ns` of arrival jitter. Tests show that every bit string
  modulated within the tolerance yields the same accepted header timeline, and
  that modulation beyond it breaks the stream.
- **Residual:** per epoch the sender chooses the start slot on the
  `start_grid_ns` grid. Every epoch needs a fresh recall (capability, types,
  DP budget, expiry), which rate-limits that residual. The covert-channel
  audit (WP-057) still measures what remains.
- The vendor key is symmetric. Receivers that verify can also create tags, so
  the tag authenticates the vendor-side replay component only to receivers
  that trust it. A public-key variant (Ed25519 over the same message) is a
  possible later profile at 64 bytes per segment.
- The reference receiver holds the vendor key. A deployment may put the check
  behind a verifier service instead.
