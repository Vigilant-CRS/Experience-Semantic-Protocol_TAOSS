# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-domain alignment for the MEB (V13 definitions alignmap and etacompat). EXPERIMENTAL.

Per matched type ``t ∈ U ⊆ T_mach`` there is a pair of maps
``A^(t)_{m→h}, A^(t)_{h→m} : R^{d_t} → R^{d_t}``. The bridge is their direct sum,
so it is **block-preserving by construction**: :class:`BridgeMaps` holds one map
per type and never mixes blocks. Training minimizes (eq. lbridge)::

    L = Σ_t ||A_mh(z_m) - z_h||² + λ_cycle Σ_t ||A_hm(A_mh(z_m)) - z_m||²

with linear maps and a ridge term ``r(||A_mh||² + ||A_hm||²)``. Training is exact
block-coordinate descent: each step solves its sub-problem in closed form (the
``A_mh`` step is a Sylvester equation solved in a shared eigenbasis), so the
objective never increases (tested).

Cross-type adapters (one type mapped into another) are forbidden unless declared.
A declared one yields output only together with a *passed* cross-type leakage audit
(:mod:`esp.audit.suite`) on the adapted representation. The audit cannot be skipped.

A cycle-consistent alignment is a regularizer, not a proof of semantic alignment
(V13 section 17.7). Paired data here are synthetic.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from esp.audit.suite import AuditReport, audit_pair
from esp.core.taoss_types import TaossType
from esp.meb.profiles import MebError, check_machine_types

F64 = NDArray[np.float64]


def _check_pairs(zm: Mapping[TaossType, F64], zh: Mapping[TaossType, F64]) -> None:
    if set(zm) != set(zh):
        msg = "machine and human samples must cover the same type set U"
        raise MebError(msg)
    check_machine_types(zm)
    for t in zm:
        if zm[t].shape != zh[t].shape or zm[t].ndim != 2:
            msg = f"{t.name}: paired samples must be (n, d_t) arrays of equal shape"
            raise MebError(msg)


@dataclass(frozen=True, slots=True)
class BridgeMaps:
    """``A_{m→h} = ⊕_t A^(t)_{m→h}`` and its reverse; row convention ``z @ W``."""

    mh: Mapping[TaossType, F64]
    hm: Mapping[TaossType, F64]

    @staticmethod
    def _apply(maps: Mapping[TaossType, F64], z: Mapping[TaossType, F64]) -> dict[TaossType, F64]:
        unknown = set(z) - set(maps)
        if unknown:
            msg = f"no alignment for {sorted(t.name for t in unknown)} (U is fixed at training)"
            raise MebError(msg)
        return {t: np.asarray(v, dtype=np.float64) @ maps[t] for t, v in z.items()}

    def to_human(self, z: Mapping[TaossType, F64]) -> dict[TaossType, F64]:
        return self._apply(self.mh, z)

    def to_machine(self, z: Mapping[TaossType, F64]) -> dict[TaossType, F64]:
        return self._apply(self.hm, z)


def bridge_loss(
    maps: BridgeMaps,
    zm: Mapping[TaossType, F64],
    zh: Mapping[TaossType, F64],
    *,
    lambda_cycle: float,
    human_cycle: bool = False,
) -> float:
    """eq. lbridge (mean over samples). ``human_cycle`` adds the optional human-anchored term."""
    _check_pairs(zm, zh)
    to_h = maps.to_human(zm)
    loss = sum(float(np.sum((to_h[t] - zh[t]) ** 2)) for t in zm)
    back = maps.to_machine(to_h)
    loss += lambda_cycle * sum(float(np.sum((back[t] - zm[t]) ** 2)) for t in zm)
    if human_cycle:
        round_trip = maps.to_human(maps.to_machine(zh))
        loss += lambda_cycle * sum(float(np.sum((round_trip[t] - zh[t]) ** 2)) for t in zh)
    n = next(iter(zm.values())).shape[0]
    return float(loss / n)


def _objective(xm: F64, xh: F64, w1: F64, w2: F64, *, lam: float, ridge: float) -> float:
    y = xm @ w1
    return float(
        np.sum((y - xh) ** 2)
        + lam * np.sum((y @ w2 - xm) ** 2)
        + ridge * (np.sum(w1**2) + np.sum(w2**2))
    )


def _solve_w1(xm: F64, xh: F64, w2: F64, lam: float, ridge: float) -> F64:
    """argmin_W1 ||Xm W1 - Xh||² + λ||Xm W1 W2 - Xm||² + r||W1||² (Sylvester, eigenbasis)."""
    d = w2.shape[0]
    g = xm.T @ xm
    h = np.eye(d) + lam * (w2 @ w2.T)
    c = xm.T @ xh + lam * g @ w2.T
    gv, u = np.linalg.eigh(g)
    hv, v = np.linalg.eigh(h)
    ct = u.T @ c @ v
    wt = ct / (np.outer(gv, hv) + ridge)
    return u @ wt @ v.T


def _solve_w2(xm: F64, w1: F64, lam: float, ridge: float) -> F64:
    """argmin_W2 λ||Y W2 - Xm||² + r||W2||² with Y = Xm W1."""
    y = xm @ w1
    return np.linalg.solve(lam * (y.T @ y) + ridge * np.eye(y.shape[1]), lam * (y.T @ xm))


@dataclass(frozen=True, slots=True)
class TrainingTrace:
    objective: tuple[float, ...]
    """Regularized objective after each half-step (non-increasing)."""


def train_bridge(
    zm: Mapping[TaossType, F64],
    zh: Mapping[TaossType, F64],
    *,
    lambda_cycle: float = 1.0,
    ridge: float = 1e-3,
    iterations: int = 20,
) -> tuple[BridgeMaps, dict[TaossType, TrainingTrace]]:
    """Fit per-type linear maps by exact block-coordinate descent on eq. lbridge + ridge."""
    if lambda_cycle <= 0 or ridge <= 0 or iterations < 1:
        msg = "lambda_cycle and ridge must be positive and iterations >= 1"
        raise ValueError(msg)
    _check_pairs(zm, zh)
    mh: dict[TaossType, F64] = {}
    hm: dict[TaossType, F64] = {}
    traces: dict[TaossType, TrainingTrace] = {}
    for t in sorted(zm):
        xm, xh = np.asarray(zm[t], dtype=np.float64), np.asarray(zh[t], dtype=np.float64)
        d = xm.shape[1]
        # start from the cycle-free ridge regression m→h and its best inverse
        w1 = np.linalg.solve(xm.T @ xm + ridge * np.eye(d), xm.T @ xh)
        w2 = _solve_w2(xm, w1, lambda_cycle, ridge)
        trace = [_objective(xm, xh, w1, w2, lam=lambda_cycle, ridge=ridge)]
        for _ in range(iterations):
            w2 = _solve_w2(xm, w1, lambda_cycle, ridge)
            trace.append(_objective(xm, xh, w1, w2, lam=lambda_cycle, ridge=ridge))
            w1 = _solve_w1(xm, xh, w2, lambda_cycle, ridge)
            trace.append(_objective(xm, xh, w1, w2, lam=lambda_cycle, ridge=ridge))
        mh[t], hm[t], traces[t] = w1, w2, TrainingTrace(tuple(trace))
    return BridgeMaps(mh, hm), traces


def eta_compatibility(
    maps: BridgeMaps, zm: Mapping[TaossType, F64], zh: Mapping[TaossType, F64]
) -> dict[TaossType, float]:
    """``E ||A^(t)_{m→h}(z_t) - z^(h)_t||²`` per type (definition etacompat)."""
    _check_pairs(zm, zh)
    to_h = maps.to_human(zm)
    return {t: float(np.mean(np.sum((to_h[t] - zh[t]) ** 2, axis=1))) for t in zm}


def is_eta_compatible(
    maps: BridgeMaps,
    zm: Mapping[TaossType, F64],
    zh: Mapping[TaossType, F64],
    eta: Mapping[TaossType, float],
) -> bool:
    """η-compatible on U iff the bound holds for *every* t ∈ U (a missing η_t fails)."""
    errors = eta_compatibility(maps, zm, zh)
    return all(t in eta and errors[t] <= eta[t] for t in errors)


# --- cross-type adapters -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CrossTypeDeclaration:
    source: TaossType
    target: TaossType
    justification: str

    def __post_init__(self) -> None:
        check_machine_types((self.source, self.target))
        if self.source is self.target:
            msg = "a same-type map is an ordinary alignment, not a cross-type adapter"
            raise MebError(msg)
        if not self.justification.strip():
            msg = "a cross-type declaration needs a justification"
            raise MebError(msg)


class UndeclaredCrossTypeError(MebError):
    pass


class CrossTypeAuditFailed(MebError):  # noqa: N818 - a protocol outcome
    def __init__(self, message: str, report: AuditReport) -> None:
        super().__init__(message)
        self.report = report


@dataclass(frozen=True, slots=True)
class AuditedCrossType:
    """Adapted values; only constructed together with a passed audit report."""

    declaration: CrossTypeDeclaration
    values: F64
    report: AuditReport


def cross_type_adapt(
    source_values: F64,
    weights: F64,
    *,
    source: TaossType,
    target: TaossType,
    declarations: frozenset[CrossTypeDeclaration],
    representation: Mapping[TaossType, F64],
    seed: int = 0,
) -> AuditedCrossType:
    """Map ``source`` into ``target``: refused unless declared, released only if audited.

    ``representation`` holds the other blocks released alongside the adapted
    ``target`` block (same samples). The cross-type leakage audit runs on every
    pair (adapted target, other block); any failed pair refuses the release.
    """
    decl = next((d for d in declarations if (d.source, d.target) == (source, target)), None)
    if decl is None:
        msg = (
            f"undeclared cross-type adapter {source.name}→{target.name}: an adapter "
            "must not silently map one semantic type into another"
        )
        raise UndeclaredCrossTypeError(msg)
    if target in representation:
        msg = "the representation already has a target block; the adapter would overwrite it"
        raise MebError(msg)
    check_machine_types(representation)
    if not representation:
        msg = "the audit needs the representation the adapted block is released with"
        raise MebError(msg)
    values = np.asarray(source_values, dtype=np.float64) @ np.asarray(weights, dtype=np.float64)
    pairs = tuple(
        audit_pair(target.name, t.name, values, np.asarray(z, dtype=np.float64), seed=seed)
        for t, z in sorted(representation.items())
    )
    report = AuditReport(pairs, notes=(f"cross-type {source.name}->{target.name}",))
    if not report.passed:
        failed = [f"{p.target}(R2={p.probe_r2})" for p in pairs if not p.passed]
        msg = f"cross-type leakage audit failed against {failed}; release refused"
        raise CrossTypeAuditFailed(msg, report)
    return AuditedCrossType(decl, values, report)
