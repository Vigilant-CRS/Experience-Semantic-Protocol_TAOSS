# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-type leakage harness (WP-033). numpy only; works on any typed latents.

For every ordered pair ``(t -> s)`` a ridge probe predicts ``E_s`` from ``E_t``
(pairwise), and from all other types jointly (joint probe). Discipline:

- one fixed, seeded train/test split shared by every probe (no peeking);
- probes are fit on train only, scored on test (out-of-sample R^2);
- bootstrap confidence intervals over test samples;
- a *shuffled* baseline (targets permuted) gives the chance level.

Output: a leakage matrix ``R2[s, t]`` with CIs. It measures linear
predictability relative to probe capacity; it does not prove independence.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

F64 = NDArray[np.float64]


@dataclass(frozen=True, slots=True)
class Split:
    train: NDArray[np.int64]
    test: NDArray[np.int64]

    @classmethod
    def fixed(cls, n: int, *, test_fraction: float = 0.3, seed: int = 0) -> Split:
        if not 0.0 < test_fraction < 1.0 or n < 10:
            msg = "need n >= 10 and 0 < test_fraction < 1"
            raise ValueError(msg)
        perm = np.random.default_rng(seed).permutation(n)
        k = round(n * test_fraction)
        return cls(train=np.sort(perm[k:]), test=np.sort(perm[:k]))


@dataclass(frozen=True, slots=True)
class ProbeResult:
    r2: float
    ci_low: float
    ci_high: float
    baseline_r2: float


def _standardize(x: F64, ref: F64) -> F64:
    mu, sd = ref.mean(axis=0), ref.std(axis=0)
    return (x - mu) / np.where(sd > 0, sd, 1.0)


def _ridge_predict(xtr: F64, ytr: F64, xte: F64, alpha: float) -> F64:
    xs, ys = _standardize(xtr, xtr), ytr - ytr.mean(axis=0)
    w = np.linalg.solve(xs.T @ xs + alpha * np.eye(xs.shape[1]), xs.T @ ys)
    return _standardize(xte, xtr) @ w + ytr.mean(axis=0)


def _r2(y: F64, yhat: F64, center: F64) -> float:
    ss_res = float(np.sum((y - yhat) ** 2))
    ss_tot = float(np.sum((y - center) ** 2))
    return 1.0 - ss_res / ss_tot if ss_tot > 0 else 0.0


def probe(
    x: F64, y: F64, split: Split, *, alpha: float = 1.0, n_boot: int = 200, seed: int = 0
) -> ProbeResult:
    """Out-of-sample R^2 of a ridge probe ``x -> y`` with a bootstrap CI and shuffled baseline."""
    xtr, xte, ytr, yte = x[split.train], x[split.test], y[split.train], y[split.test]
    yhat = _ridge_predict(xtr, ytr, xte, alpha)
    center = ytr.mean(axis=0)
    rng = np.random.default_rng(seed)
    boots = []
    for _ in range(n_boot):
        i = rng.integers(0, yte.shape[0], yte.shape[0])
        boots.append(_r2(yte[i], yhat[i], center))
    shuffled = ytr[rng.permutation(ytr.shape[0])]
    base = _r2(yte, _ridge_predict(xtr, shuffled, xte, alpha), center)
    lo, hi = np.quantile(boots, [0.025, 0.975])
    return ProbeResult(_r2(yte, yhat, center), float(lo), float(hi), base)


@dataclass(frozen=True, slots=True)
class LeakageMatrix:
    types: tuple[str, ...]
    pairwise: dict[tuple[str, str], ProbeResult]
    """``(target s, source t) -> probe E_t -> E_s``."""
    joint: dict[str, ProbeResult]
    """``target s -> probe from all other types``."""

    def max_pairwise(self) -> float:
        return max(r.r2 for r in self.pairwise.values())

    def significant(self, margin: float = 0.05) -> list[tuple[str, str]]:
        """Pairs whose CI lower bound exceeds the shuffled baseline by ``margin``."""
        return sorted(k for k, r in self.pairwise.items() if r.ci_low > r.baseline_r2 + margin)


def leakage_matrix(
    latents: Mapping[str, F64], *, seed: int = 0, alpha: float = 1.0, n_boot: int = 200
) -> LeakageMatrix:
    types = tuple(latents)
    n = {v.shape[0] for v in latents.values()}
    if len(n) != 1:
        msg = "all types need the same number of samples"
        raise ValueError(msg)
    split = Split.fixed(n.pop(), seed=seed)
    pairwise = {
        (s, t): probe(latents[t], latents[s], split, alpha=alpha, n_boot=n_boot, seed=seed)
        for s in types
        for t in types
        if s != t
    }
    joint = {
        s: probe(
            np.concatenate([latents[t] for t in types if t != s], axis=1),
            latents[s],
            split,
            alpha=alpha,
            n_boot=n_boot,
            seed=seed,
        )
        for s in types
    }
    return LeakageMatrix(types, pairwise, joint)
