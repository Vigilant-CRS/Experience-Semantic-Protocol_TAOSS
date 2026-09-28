# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded-influence dynamics: the Friedkin-Johnsen typed hive update (V13 "Bounded Influence").

``x(k+1) = Λ W x(k) + (I - Λ) x(0)``, where ``W`` is nonnegative and
row-stochastic, and ``λ_i ∈ [0, 1)`` is the *signed consent* coupling of
member ``i`` for the type. With ``λ_max < 1``:

- the equilibrium is ``x* = P x(0)`` with ``P = (I - ΛW)^{-1}(I - Λ)``,
  which is row-stochastic and nonnegative;
- autonomy: ``a_i = P_ii >= 1 - λ_i``;
- social power: ``π_j = mean_i P_ij``;
- drift: ``||x*_i - x_i(0)|| <= λ_i max_j ||x_j(0) - x_i(0)||``.

EMO mixing into human members must be zero in v1. :func:`check_coupling`
rejects any non-zero EMO coupling, whatever the grant says.

For machine members these are state guarantees. For humans they bound only
the hive-derived signal a compliant renderer delivers, not psychological
uptake (V13 scope note).
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from numpy.typing import NDArray

from esp.core.taoss_types import TaossType
from esp.hive.tlv import HiveError

F64 = NDArray[np.float64]


def check_coupling(t: TaossType, w: F64, lam: Sequence[float], caps: Sequence[float]) -> None:
    """Validate ``W`` and ``Λ`` for type ``t`` against the members' granted ``lambda_max``."""
    w = np.asarray(w, dtype=np.float64)
    n = len(lam)
    if w.shape != (n, n) or len(caps) != n:
        msg = "W must be n-by-n with one coupling and one cap per member"
        raise HiveError(msg)
    if np.any(w < 0) or not np.allclose(w.sum(axis=1), 1.0, atol=1e-12):
        msg = "W must be nonnegative and row-stochastic"
        raise HiveError(msg)
    if t is TaossType.EMO and any(v != 0.0 for v in lam):
        msg = "EMO mixing must be 0 for human members (v1 individuality invariant)"
        raise HiveError(msg)
    for v, cap in zip(lam, caps, strict=True):
        if not 0.0 <= v < 1.0:
            msg = "coupling must lie in [0, 1)"
            raise HiveError(msg)
        if v > cap:
            msg = f"coupling {v} exceeds the member's granted lambda_max {cap}"
            raise HiveError(msg)


def fj_step(x: F64, x0: F64, w: F64, lam: Sequence[float]) -> F64:
    lam_d = np.asarray(lam, dtype=np.float64)[:, None]
    return lam_d * (np.asarray(w) @ x) + (1.0 - lam_d) * x0


def fj_run(x0: F64, w: F64, lam: Sequence[float], rounds: int) -> list[F64]:
    xs = [np.asarray(x0, dtype=np.float64)]
    for _ in range(rounds):
        xs.append(fj_step(xs[-1], xs[0], w, lam))
    return xs


def equilibrium_matrix(w: F64, lam: Sequence[float]) -> F64:
    lam_m = np.diag(np.asarray(lam, dtype=np.float64))
    eye = np.eye(len(lam))
    return np.linalg.solve(eye - lam_m @ np.asarray(w), eye - lam_m)


def autonomy(p: F64) -> F64:
    return np.diag(p).copy()


def social_power(p: F64) -> F64:
    return np.asarray(p).mean(axis=0)


def diversity(x: F64) -> float:
    """``D = 1/(n(n-1)) Σ_{i≠j} ||x_i - x_j||²``."""
    x = np.asarray(x, dtype=np.float64)
    n = x.shape[0]
    if n < 2:
        return 0.0
    d = ((x[:, None, :] - x[None, :, :]) ** 2).sum(axis=-1)
    return float(d.sum() / (n * (n - 1)))


def normalized_diversity(x0: F64, xk: F64) -> float | None:
    """``D(k)/D(0)``, or ``None`` where ``D(0) = 0`` (no diversity claim possible)."""
    d0 = diversity(x0)
    return None if d0 == 0.0 else diversity(xk) / d0


def uniform_w(n: int) -> F64:
    """Complete graph without self-loops, uniform weights."""
    w = np.ones((n, n)) - np.eye(n)
    return w / (n - 1)
