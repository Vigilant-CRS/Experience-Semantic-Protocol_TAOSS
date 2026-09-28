# ADR-0017 — Handling of reserved and unassigned header bits in v1

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-011
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-014, WP-061

## Decision

| Field | Bits | Sender | Receiver |
|---|---|---|---|
| `reserved` (byte 0x07) | all | 0 | reject if ≠ 0 |
| `types_bitmap` | 6–15 | 0 | reject |
| `consent_flags` | 3–15 | 0 | reject |
| `privacy_flags` | 6–15 | 0 | reject |
| `privacy_flags.DP_LEVEL` | values 4–15 | never | reject |
| `capabilities` | 12–14 (reserved) | 0 | reject |
| `capabilities` | 0–11 ("I2I and feature flags", unassigned in v1) | 0 | ignore (forward compatibility) |
| `capabilities` | 15 `CAPS_EXT_PRESENT` | as needed | if set, `TLV_CAPABILITIES_EXT` must be present |
| `version_major` | — | 0x01 | reject ≠ 0x01 |
| `version_minor` | — | 0x00 | accept ≥ 0x00 (minor versions are backward compatible) |
| `sf_level` | — | 0–7 | reject > 7 |
| `magic` | — | `ESP` | reject |

Bits 0–11 of `capabilities` are assigned only through a registry entry.
Until then they carry no meaning, and a receiver must not act on them.
