# ADR-0018 — DP reference profiles and accountant

- Status: ACCEPTED (2026-09-28). It records values that V13 §12 states
  verbatim and introduces no new design.
- Resolves: GAP-012
- Work package: WP-055

## Decision

| DP_LEVEL | ε_p | δ_p | C | σ = 2C·√(2 ln(1.25/δ_p))/ε_p |
|---|---|---|---|---|
| `L1_BALANCED_REF` (1) | 0.5 | 1e-8 | 1.0 | 24.425… |
| `L1_PRIVATE_REF` (2) | 0.1 | 1e-8 | 1.0 | 122.127… |

- The classical calibration is only used for ε ∈ (0, 1).
- Sensitivity is Δ₂ = 2C (replace-one adjacency).
- The accountant is RDP optimal-α in closed form: `ε = c + 2√(c·ln(1/δ_tot))`,
  where `c = Σ_releases Σ_types (2C_t)²/(2σ_t²)` and δ_tot = 1e-6. A grid
  accountant over V13's α grid is available and must be logged.
- The ledger is persisted per capability before each release and never
  decreases. Retransmitting the same privatized sample is free.
- Receivers recompute ε from `(C_t, σ_t, k, δ)`. They reject declarations
  below the accountant value, above the ceiling, or rolled back, and they
  reject σ below the reference for reference levels.
- With runtime DP, only privatized latents may be sent. Anchor coordinates,
  descriptors or bindings computed from un-noised data are refused.
- Reproduced numbers: per type ε ≈ 4.64 (α* ≈ 7.42); joint over 5 types
  ε ≈ 11.30 (α* ≈ 3.87); information bound 1.2·10⁻³ bit per type and frame
  (`vectors/privacy/dp_accounting.json`).

## Known limitation

Noise comes from a floating-point Gaussian sampler with a CSPRNG seed.
Floating-point samplers can leak through their low-order bits (Mironov
2012). Certified profiles need a discrete Gaussian sampler; this is tracked
as an open item for WP-055 hardening.
