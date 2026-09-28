# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Dependence estimators for the audit suite (WP-058; V13 section 13). numpy only.

- KSG mutual information (Kraskov-Stoegbauer-Grassberger, estimator 1,
  max-norm), in bits; ``k`` in 4..10, default 6;
- surrogate reduction for high-dimensional types (PCA to <= 32 dims),
  always reported;
- HSIC with RBF kernels (median heuristic) and a permutation p-value;
- distance correlation;
- cluster bootstrap over split units (never IID frames);
- estimator dissent trigger ``dI > max(0.01 bit, 0.05 * sqrt(d_eff / N))``.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

F64 = NDArray[np.float64]
LN2 = math.log(2.0)


def _digamma(x: F64 | float) -> F64:
    """Digamma via recurrence + asymptotic series (accurate to ~1e-10 for x >= 1)."""
    v = np.asarray(x, dtype=np.float64).copy()
    result = np.zeros_like(v)
    while np.any(v < 6):
        small = v < 6
        result[small] -= 1.0 / v[small]
        v[small] += 1.0
    inv = 1.0 / v
    inv2 = inv * inv
    series = inv2 * (1 / 12 - inv2 * (1 / 120 - inv2 * (1 / 252 - inv2 * (1 / 240 - inv2 / 132))))
    return result + np.log(v) - 0.5 * inv - series


def _as2d(x: F64) -> F64:
    x = np.asarray(x, dtype=np.float64)
    return x[:, None] if x.ndim == 1 else x


def pca_surrogate(x: F64, max_dims: int = 32) -> tuple[F64, int]:
    """Project onto the top principal components; returns (surrogate, dims used)."""
    x = _as2d(x)
    if x.shape[1] <= max_dims:
        return x, x.shape[1]
    xc = x - x.mean(0)
    _, _, vt = np.linalg.svd(xc, full_matrices=False)
    return xc @ vt[:max_dims].T, max_dims


def ksg_mi(x: F64, y: F64, k: int = 6) -> float:
    """KSG estimator 1 of I(X;Y) in bits (Chebyshev metric, brute-force neighbours)."""
    if not 4 <= k <= 10:
        msg = "k must be in 4..10 (plan WP-058)"
        raise ValueError(msg)
    x, y = _as2d(x), _as2d(y)
    n = x.shape[0]
    if n <= k + 1 or y.shape[0] != n:
        msg = "need matching samples and n > k + 1"
        raise ValueError(msg)
    dx = np.max(np.abs(x[:, None, :] - x[None, :, :]), axis=2)
    dy = np.max(np.abs(y[:, None, :] - y[None, :, :]), axis=2)
    dz = np.maximum(dx, dy)
    np.fill_diagonal(dz, np.inf)
    eps = np.partition(dz, k - 1, axis=1)[:, k - 1]
    np.fill_diagonal(dx, np.inf)
    np.fill_diagonal(dy, np.inf)
    nx = np.sum(dx < eps[:, None], axis=1)
    ny = np.sum(dy < eps[:, None], axis=1)
    mi = _digamma(k) + _digamma(n) - np.mean(_digamma(nx + 1) + _digamma(ny + 1))
    return max(0.0, float(mi)) / LN2


def gaussian_mi_bits(rho: float, dims: int = 1) -> float:
    """Analytic MI of ``dims`` independent bivariate normal pairs with correlation rho."""
    return -0.5 * dims * math.log(1.0 - rho**2) / LN2


def _rbf(x: F64) -> F64:
    sq = np.sum((x[:, None, :] - x[None, :, :]) ** 2, axis=2)
    med = np.median(sq[np.triu_indices_from(sq, 1)])
    return np.exp(-sq / (med if med > 0 else 1.0))


def hsic(x: F64, y: F64, *, permutations: int = 200, seed: int = 0) -> tuple[float, float]:
    """Biased HSIC statistic with RBF kernels and its permutation p-value."""
    x, y = _as2d(x), _as2d(y)
    n = x.shape[0]
    h = np.eye(n) - 1.0 / n
    kx, ky = h @ _rbf(x) @ h, _rbf(y)
    stat = float(np.sum(kx * ky)) / n**2
    rng = np.random.default_rng(seed)
    exceed = 0
    for _ in range(permutations):
        p = rng.permutation(n)
        exceed += float(np.sum(kx * ky[np.ix_(p, p)])) / n**2 >= stat
    return stat, (exceed + 1) / (permutations + 1)


def distance_correlation(x: F64, y: F64) -> float:
    x, y = _as2d(x), _as2d(y)

    def centered(z: F64) -> F64:
        d = np.sqrt(np.sum((z[:, None, :] - z[None, :, :]) ** 2, axis=2))
        return d - d.mean(0) - d.mean(1)[:, None] + d.mean()

    a, b = centered(x), centered(y)
    dcov = np.mean(a * b)
    denom = math.sqrt(np.mean(a * a) * np.mean(b * b))
    return math.sqrt(max(0.0, dcov) / denom) if denom > 0 else 0.0


@dataclass(frozen=True, slots=True)
class BootstrapCI:
    estimate: float
    low: float
    high: float
    units: int


def cluster_bootstrap(
    stat: Callable[[F64, F64], float],
    x: F64,
    y: F64,
    units: NDArray[np.int64],
    *,
    b: int = 1000,
    seed: int = 0,
) -> BootstrapCI:
    """Resample whole split units (sessions/subjects), never individual frames."""
    ids = np.unique(units)
    if ids.size < 2:
        msg = "cluster bootstrap needs at least two split units"
        raise ValueError(msg)
    members = {u: np.nonzero(units == u)[0] for u in ids}
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(b):
        pick = np.concatenate([members[u] for u in rng.choice(ids, ids.size, replace=True)])
        vals.append(stat(x[pick], y[pick]))
    lo, hi = np.quantile(vals, [0.025, 0.975])
    return BootstrapCI(stat(x, y), float(lo), float(hi), int(ids.size))


def dissent(i_a: float, i_b: float, *, d_eff: int, n: int) -> bool:
    """Estimator dissent trigger (bits): ``|dI| > max(0.01, 0.05 * sqrt(d_eff / N))``."""
    return abs(i_a - i_b) > max(0.01, 0.05 * math.sqrt(d_eff / n))
