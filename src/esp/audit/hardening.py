# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Covert-channel hardening (WP-057; V13 covert-channel budget).

- **randomized quantization**: stochastic rounding onto the INT8 grid destroys
  information a sender hides below the quantization step (e.g. in low-order
  mantissa bits), while staying unbiased in expectation;
- **TEM pattern band**: receivers check that TEM coordinates stay inside a
  declared band (a stego sender needs out-of-band excursions to signal);
- **gating sparsity band**: the fraction of near-zero coordinates must stay in
  a declared band (on/off patterns are a classic covert carrier).
Norm caps are enforced by the Accept predicate (condition 10). The replay
watermark stays DEFERRED until V13 assigns a TLV code.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

F64 = NDArray[np.float64]


def randomized_quantize(x: F64, rng: np.random.Generator) -> F64:
    """Stochastic rounding to the INT8_SYM grid ``s * q`` (unbiased: E[out] = x)."""
    peak = float(np.max(np.abs(x))) if x.size else 0.0
    s = float(np.float32(max(peak / 127.0, 2.0**-24)))
    scaled = x / s
    low = np.floor(scaled)
    q = low + (rng.uniform(size=x.shape) < (scaled - low))
    out: F64 = np.clip(q, -127, 127) * s
    return out


def tem_band_violations(tem: F64, lo: float, hi: float) -> int:
    """Number of frames with any TEM coordinate outside ``[lo, hi]``."""
    return int(np.sum(np.any((tem < lo) | (tem > hi), axis=1)))


def gating_sparsity_ok(z: F64, band: tuple[float, float], eps: float = 1e-6) -> bool:
    share = float(np.mean(np.abs(z) <= eps))
    return band[0] <= share <= band[1]
