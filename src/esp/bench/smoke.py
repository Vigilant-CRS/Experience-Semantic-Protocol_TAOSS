# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic smoke corpus and encoder variants for ExperienceBench (WP-034).

Everything here is *smoke data*: it exercises the benchmark machinery and
has no evidential value for H1/H2/H3 (V13 section 14).

Ground truth: independent factors per TAOSS type, grouped into split units
(sessions). Derived labels: an action class (INT), beat events (TEM), scene
metadata (CTX) and an OOD split with shifted EMO anchors.

Encoder variants (same total dimension):

- ``taoss``: typed blocks, each driven by its own factor;
- ``taoss_cov_only``: ablation with residual cross-type mixing;
- ``mono``: one dense latent mixing all factors; nominal blocks are a
  preregistered post-hoc readout partition (V13 pinned baseline);
- ``mono_leace``: ``mono`` with LEACE-style linear erasure of the masked
  types at disclosure time (learned selective-privacy baseline).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

F64 = NDArray[np.float64]
TYPES = ("KNO", "INT", "EMO", "CTX", "SEN", "TEM")
BLOCK = {"KNO": 12, "INT": 6, "EMO": 6, "CTX": 6, "SEN": 6, "TEM": 4}
FACTOR = 4
N_ACTIONS = 4


@dataclass(frozen=True, slots=True)
class SmokeCorpus:
    factors: dict[str, F64]
    units: NDArray[np.int64]
    actions: NDArray[np.int64]
    beats: NDArray[np.int64]
    scene: NDArray[np.int64]
    ood: NDArray[np.bool_]

    @property
    def n(self) -> int:
        return int(self.units.size)


def make_corpus(
    n: int = 800, *, sessions: int = 40, seed: int = 0, ood_shift: float = 0.3
) -> SmokeCorpus:
    rng = np.random.default_rng(seed)
    factors = {t: rng.normal(size=(n, FACTOR)) for t in TYPES}
    ood = np.zeros(n, dtype=bool)
    ood[n - n // 5 :] = True
    factors["EMO"][ood] += ood_shift  # anchor distribution shift for the OOD split
    w = np.random.default_rng(seed + 1).normal(size=(FACTOR, N_ACTIONS))
    actions = np.argmax(factors["INT"] @ w, axis=1)
    beats = (factors["TEM"][:, 0] > 0.5).astype(np.int64)
    scene = np.argmax(factors["CTX"][:, :3], axis=1)
    units = np.repeat(np.arange(sessions), int(np.ceil(n / sessions)))[:n]
    return SmokeCorpus(factors, units, actions, beats, scene, ood)


def _mix(seed: int, rows: int, cols: int) -> F64:
    q, _ = np.linalg.qr(np.random.default_rng(seed).normal(size=(max(rows, cols), max(rows, cols))))
    return q[:rows, :cols]


def encode(
    corpus: SmokeCorpus, variant: str, *, noise: float = 0.05, seed: int = 0
) -> dict[str, F64]:
    rng = np.random.default_rng(seed + 100)
    f = corpus.factors
    if variant in {"taoss", "taoss_cov_only"}:
        leak = 0.0 if variant == "taoss" else 0.3
        out = {}
        for i, t in enumerate(TYPES):
            src = f[t] + leak * f[TYPES[(i + 1) % len(TYPES)]]
            out[t] = src @ _mix(seed + i, FACTOR, BLOCK[t]) + noise * rng.normal(
                size=(corpus.n, BLOCK[t])
            )
        return out
    if variant in {"mono", "mono_leace"}:
        stacked = np.concatenate([f[t] for t in TYPES], axis=1)
        d = sum(BLOCK.values())
        z = stacked @ _mix(seed + 50, stacked.shape[1], d) + noise * rng.normal(size=(corpus.n, d))
        out, start = {}, 0
        for t in TYPES:  # preregistered post-hoc readout partition
            out[t] = z[:, start : start + BLOCK[t]]
            start += BLOCK[t]
        return out
    msg = f"unknown encoder variant {variant!r}"
    raise ValueError(msg)


def leace_erase(x: F64, concept: F64, *, train: NDArray[np.bool_] | None = None) -> F64:
    """LEACE (Belrose et al. 2023): least-squares linear concept erasure of ``concept`` from ``x``.

    ``r(x) = x - W^+ P W (x - mu)`` with whitening ``W = Sigma_xx^{-1/2}`` and ``P`` the
    orthogonal projection onto ``span(W Sigma_xz)``. After erasure no linear
    predictor of ``concept`` beats a constant.
    """
    fitted_x = x if train is None else x[train]
    fitted_concept = concept if train is None else concept[train]
    mu = fitted_x.mean(0)
    xc = fitted_x - mu
    zc = fitted_concept - fitted_concept.mean(0)
    sxx = xc.T @ xc / (fitted_x.shape[0] - 1)
    sxz = xc.T @ zc / (fitted_x.shape[0] - 1)
    evals, evecs = np.linalg.eigh(sxx)
    keep = evals > 1e-10 * evals.max()
    w = evecs[:, keep] @ np.diag(evals[keep] ** -0.5) @ evecs[:, keep].T
    w_pinv = evecs[:, keep] @ np.diag(evals[keep] ** 0.5) @ evecs[:, keep].T
    u, s, _ = np.linalg.svd(w @ sxz, full_matrices=False)
    u = u[:, s > 1e-10 * s.max()] if s.size else u[:, :0]
    p = u @ u.T
    erased: F64 = x - ((x - mu) @ (w_pinv @ p @ w).T)
    return erased
