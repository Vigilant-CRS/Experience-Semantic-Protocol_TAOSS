# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit suite report (WP-058) and covert-channel score (WP-057).

Audit of a pair of typed latents ``(Z_s, Z_t)``:

- KSG MI (primary) on a logged surrogate (PCA <= 32 dims) plus a second
  estimator; dissent between them is flagged, never averaged away;
- HSIC permutation test, distance correlation;
- probes: continuous ``R^2 <= 0.02`` (ridge, out of sample);
- cluster bootstrap over split units.

**No-free-lunch rule:** a report without a probe result is an audit failure.

Covert channel (WP-057, GAP-015/016): leakage as *fixed-null predictive
V-information* ``L = H0(Z_M) - H_V(Z_M | Z_V)`` estimated with a ladder of
probe families (linear, then polynomial features of degree 2 and 3).
The null model is fit once per target and split. The ladder is monotone:
a larger family never reports less leakage (we take the running maximum and
check it). A red-team sender that hides EMO inside TEM must fail the audit.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field

import numpy as np
from numpy.typing import NDArray

from esp.audit.estimators import (
    BootstrapCI,
    cluster_bootstrap,
    dissent,
    distance_correlation,
    hsic,
    ksg_mi,
    pca_surrogate,
)
from esp.training.leakage import Split, probe

F64 = NDArray[np.float64]
PROBE_R2_LIMIT = 0.02
LN2 = math.log(2.0)


@dataclass(frozen=True, slots=True)
class PairAudit:
    source: str
    target: str
    mi_bits: float
    mi_bits_k_alt: float
    surrogate_dims: tuple[int, int]
    dissent: bool
    hsic_p: float
    dcor: float
    probe_r2: float | None
    mi_ci: BootstrapCI | None = None

    @property
    def passed(self) -> bool:
        if self.probe_r2 is None:
            return False  # no-free-lunch: a report without a probe result fails
        return self.probe_r2 <= PROBE_R2_LIMIT and not self.dissent


@dataclass(frozen=True, slots=True)
class AuditReport:
    pairs: tuple[PairAudit, ...]
    notes: tuple[str, ...] = field(default=())

    @property
    def passed(self) -> bool:
        return bool(self.pairs) and all(p.passed for p in self.pairs)


def audit_pair(
    source: str,
    target: str,
    zs: F64,
    zt: F64,
    *,
    units: NDArray[np.int64] | None = None,
    k: int = 6,
    with_probe: bool = True,
    bootstrap: int = 0,
    seed: int = 0,
) -> PairAudit:
    xs, ds = pca_surrogate(zs)
    xt, dt = pca_surrogate(zt)
    mi = ksg_mi(xs, xt, k=k)
    mi_alt = ksg_mi(xs, xt, k=4 if k != 4 else 8)
    _, p = hsic(xs, xt, permutations=100, seed=seed)
    r2 = probe(xs, xt, Split.fixed(xs.shape[0], seed=seed)).r2 if with_probe else None
    ci = None
    if bootstrap and units is not None:
        ci = cluster_bootstrap(
            lambda a, b: ksg_mi(a, b, k=k), xs, xt, units, b=bootstrap, seed=seed
        )
    return PairAudit(
        source=source,
        target=target,
        mi_bits=mi,
        mi_bits_k_alt=mi_alt,
        surrogate_dims=(ds, dt),
        dissent=dissent(mi, mi_alt, d_eff=ds + dt, n=xs.shape[0]),
        hsic_p=p,
        dcor=distance_correlation(xs, xt),
        probe_r2=r2,
        mi_ci=ci,
    )


# --- covert channel: fixed-null predictive V-information --------------------------------------


def _gaussian_entropy_bits(resid: F64) -> float:
    """Differential entropy (bits) of a Gaussian with the residual covariance (per sample)."""
    cov = np.atleast_2d(np.cov(resid, rowvar=False)) + 1e-9 * np.eye(resid.shape[1])
    sign, logdet = np.linalg.slogdet(2 * math.pi * math.e * cov)
    return 0.5 * logdet / LN2 if sign > 0 else float("-inf")


def _features(x: F64, degree: int) -> F64:
    """Polynomial probe family: all monomials of the standardized inputs up to degree."""
    z = (x - x.mean(0)) / (x.std(0) + 1e-12)
    cols = [z]
    if degree >= 2:
        i, j = np.triu_indices(z.shape[1])
        cols.append(z[:, i] * z[:, j])
    if degree >= 3:
        i, j, k = (a.ravel() for a in np.meshgrid(*[np.arange(z.shape[1])] * 3, indexing="ij"))
        keep = (i <= j) & (j <= k)
        cols.append(z[:, i[keep]] * z[:, j[keep]] * z[:, k[keep]])
    return np.concatenate(cols, axis=1)


def v_information_ladder(
    visible: F64, masked: F64, *, degrees: Sequence[int] = (1, 2, 3), seed: int = 0
) -> list[float]:
    """``L = H0(Z_M) - H_V(Z_M | Z_V)`` in bits for growing probe families (monotone)."""
    split = Split.fixed(visible.shape[0], seed=seed)
    ytr, yte = masked[split.train], masked[split.test]
    h0 = _gaussian_entropy_bits(yte - ytr.mean(0))  # null model: fixed once per target and split
    out, best = [], 0.0
    for degree in degrees:
        f = _features(visible, degree)
        mu, sd = f[split.train].mean(0), f[split.train].std(0) + 1e-12
        ftr, fte = (f[split.train] - mu) / sd, (f[split.test] - mu) / sd
        w = np.linalg.solve(ftr.T @ ftr + 1.0 * np.eye(ftr.shape[1]), ftr.T @ (ytr - ytr.mean(0)))
        hv = _gaussian_entropy_bits(yte - (fte @ w + ytr.mean(0)))
        best = max(best, h0 - hv)  # a larger family can always fall back to a smaller one
        out.append(best)
    return out


@dataclass(frozen=True, slots=True)
class CovertAudit:
    ladder_bits: tuple[float, ...]
    threshold_bits: float

    @property
    def leakage_bits(self) -> float:
        return self.ladder_bits[-1]

    @property
    def passed(self) -> bool:
        return self.leakage_bits <= self.threshold_bits


def covert_channel_audit(visible: F64, masked: F64, *, threshold_bits: float = 0.1) -> CovertAudit:
    return CovertAudit(tuple(v_information_ladder(visible, masked)), threshold_bits)
