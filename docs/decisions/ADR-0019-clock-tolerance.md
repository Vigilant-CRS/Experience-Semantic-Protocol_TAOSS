# ADR-0019 — Default clock tolerance Δ_clock

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-013
- Class: `V13_COMPATIBLE_ADDENDUM`
- Work packages: WP-019, WP-051

## Decision

`Δ_clock` in the V13 §9.7 Accept predicate is taken from the session
descriptor (`clock_tolerance_ms`). Profile defaults:

| Profile | Δ_clock |
|---|---|
| L1 default | 2000 ms |
| L1 high-stakes | 500 ms |
| I2I (L3+) | 250 ms |

Receivers compare against their own clock; they never trust sender time for
expiry.
