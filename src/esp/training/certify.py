# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent verification of the certified-stability mode (WP-073; V13 App. B). numpy only.

This module deliberately does not import torch or the encoder: it receives the
*exported* attention weights (:func:`esp.training.encoder.export_fusion`) and
the attention inputs observed at audit time, and re-derives everything:

1. **Premise:** bias-free projections (the theorem is stated for ``Q = E W_Q``).
2. **Input radius:** the observed ``R = max ||E||_2`` must not exceed ``R_max``
   (V13: certified deployments log the observed R and assert it; without the
   spectral clip this fails).
3. **Operator norms:** every ``||W_Q^h||_2, ||W_K^h||_2, ||W_V^h||_2`` and
   ``||W_O||_2`` by exact SVD, cross-checked by power iteration.
4. **Bound:** ``L_MH(R_max) = ||W_O|| (sum_h L_h(R_max)^2)^(1/2)`` with
   ``L_h(R) = sqrt(n) ||W_V^h|| + 2 sqrt(n) R^2 / tau ||W_Q^h|| ||W_K^h|| ||W_V^h||``
   must not exceed the declared ceiling.
5. **Empirical probe:** a numpy re-implementation of multi-head attention;
   the largest measured ratio ``||Phi(E') - Phi(E)||_2 / ||E' - E||_2`` over
   random, targeted and locally optimized pairs in ``B_{R_max}`` must not exceed
   the bound. The targeted pair ``(0, c 1 u^T)`` attains ``sigma_max(W_V W_O)``
   exactly (uniform attention), so the probe provably has teeth.

The bound certifies the fusion operator on its clipped input only.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import asdict, dataclass

import numpy as np
from numpy.typing import NDArray

F64 = NDArray[np.float64]
RADIUS_TOL = 1e-4
"""Relative float32 slack for the observed radius (the clip is computed in float32)."""


@dataclass(frozen=True, slots=True)
class AttentionWeights:
    """Theorem orientation: ``Q = E W_Q`` with ``W_Q`` of shape (d, d); ``W_O`` (H d_v, d)."""

    w_q: F64
    w_k: F64
    w_v: F64
    w_o: F64
    heads: int
    tokens: int
    has_bias: bool

    @classmethod
    def from_export(cls, exported: Mapping[str, F64]) -> AttentionWeights:
        w_in = np.asarray(exported["in_proj_weight"], dtype=np.float64)
        d = w_in.shape[1]
        # structural premise: a bias parameter may become non-zero in training even if it is 0 now
        has_bias = any(k.endswith("bias") for k in exported)
        return cls(
            w_q=w_in[:d].T,
            w_k=w_in[d : 2 * d].T,
            w_v=w_in[2 * d :].T,
            w_o=np.asarray(exported["out_proj.weight"], dtype=np.float64).T,
            heads=int(exported["heads"]),
            tokens=int(exported["tokens"]),
            has_bias=has_bias,
        )

    @property
    def d_k(self) -> int:
        return int(self.w_q.shape[1]) // self.heads

    def head(self, w: F64, h: int) -> F64:
        return w[:, h * self.d_k : (h + 1) * self.d_k]


def spectral_norm(w: F64) -> float:
    return float(np.linalg.svd(w, compute_uv=False)[0])


def power_iteration(w: F64, iters: int = 500, seed: int = 0) -> float:
    v: F64 = np.asarray(np.random.default_rng(seed).normal(size=w.shape[1]), dtype=np.float64)
    for _ in range(iters):
        v = w.T @ (w @ v)
        norm = float(np.linalg.norm(v))
        if norm == 0.0:
            return 0.0
        v /= norm
    return float(np.linalg.norm(w @ v))


def mha(weights: AttentionWeights, e: F64) -> F64:
    """Bias-free multi-head scaled dot-product self-attention on one (n, d) input."""
    tau = math.sqrt(weights.d_k)
    outs = []
    for h in range(weights.heads):
        q = e @ weights.head(weights.w_q, h)
        k = e @ weights.head(weights.w_k, h)
        v = e @ weights.head(weights.w_v, h)
        s = q @ k.T / tau
        a = np.exp(s - s.max(axis=1, keepdims=True))
        a /= a.sum(axis=1, keepdims=True)
        outs.append(a @ v)
    out: F64 = np.concatenate(outs, axis=1) @ weights.w_o
    return out


def lipschitz_bound(weights: AttentionWeights, r: float) -> float:
    """V13 Proposition (multi-head bound) instantiated from the actual weights."""
    tau = math.sqrt(weights.d_k)
    root_n = math.sqrt(weights.tokens)
    per_head = []
    for h in range(weights.heads):
        nq, nk, nv = (
            spectral_norm(weights.head(w, h)) for w in (weights.w_q, weights.w_k, weights.w_v)
        )
        per_head.append(root_n * nv + 2.0 * root_n * r**2 / tau * nq * nk * nv)
    return spectral_norm(weights.w_o) * math.sqrt(sum(x * x for x in per_head))


def _ratio(weights: AttentionWeights, e: F64, e2: F64) -> float:
    den = np.linalg.norm(e2 - e, 2)
    return 0.0 if den == 0 else float(np.linalg.norm(mha(weights, e2) - mha(weights, e), 2) / den)


def _into_ball(e: F64, r: float) -> F64:
    n = np.linalg.norm(e, 2)
    return e if n <= r else e * (r / n)


def empirical_lipschitz(
    weights: AttentionWeights, r: float, *, samples: int = 200, climb: int = 200, seed: int = 0
) -> tuple[float, float]:
    """(largest measured ratio in ``B_r``, ratio of the targeted uniform-attention pair)."""
    rng = np.random.default_rng(seed)
    n, d = weights.tokens, weights.w_q.shape[0]
    # targeted pair: E = 0 and E' = c 1 u^T give uniform attention, ratio = sigma_max(W_V W_O)
    u = np.linalg.svd(weights.w_v @ weights.w_o)[0][:, 0]
    target = np.outer(np.ones(n), u) * (0.5 * r / math.sqrt(n))
    targeted = _ratio(weights, np.zeros((n, d)), target)
    best, best_pair = targeted, (np.zeros((n, d)), target)
    for _ in range(samples):
        e = rng.normal(size=(n, d))
        e *= r * rng.uniform(0.05, 1.0) / max(np.linalg.norm(e, 2), 1e-12)
        eps = r * 10.0 ** rng.uniform(-4, -1)
        e2 = _into_ball(e + eps * rng.normal(size=(n, d)) / math.sqrt(n * d), r)
        ratio = _ratio(weights, e, e2)
        if ratio > best:
            best, best_pair = ratio, (e, e2)
    e, e2 = best_pair
    for _ in range(climb):  # local search: perturb the best pair, keep improvements
        step = 0.05 * r / math.sqrt(n * d)
        c1 = _into_ball(e + step * rng.normal(size=(n, d)), r)
        c2 = _into_ball(e2 + step * rng.normal(size=(n, d)), r)
        ratio = _ratio(weights, c1, c2)
        if ratio > best:
            best, e, e2 = ratio, c1, c2
    return best, targeted


@dataclass(frozen=True, slots=True)
class CertificateReport:
    r_max: float
    r_observed: float
    ceiling: float
    bound: float
    empirical: float
    targeted: float
    w_o_norm: float
    power_iteration_agrees: bool
    has_bias: bool
    failures: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.failures

    def to_json(self) -> str:
        return json.dumps(asdict(self) | {"passed": self.passed}, sort_keys=True, indent=2)


def verify(
    exported: Mapping[str, F64],
    observed_inputs: F64,
    *,
    r_max: float,
    ceiling: float,
    seed: int = 0,
) -> CertificateReport:
    """Check the certified-mode claims from exported weights and observed attention inputs."""
    w = AttentionWeights.from_export(exported)
    obs = np.asarray(observed_inputs, dtype=np.float64)
    if obs.ndim != 3 or obs.shape[1:] != (w.tokens, w.w_q.shape[0]):
        msg = "observed inputs must have shape (batch, tokens, d_model)"
        raise ValueError(msg)
    r_obs = max(float(np.linalg.norm(e, 2)) for e in obs)
    mats = [w.w_o] + [w.head(m, h) for m in (w.w_q, w.w_k, w.w_v) for h in range(w.heads)]
    agrees = all(
        abs(power_iteration(m) - spectral_norm(m)) <= 1e-3 * max(spectral_norm(m), 1e-12)
        for m in mats
    )
    bound = lipschitz_bound(w, r_max)
    empirical, targeted = empirical_lipschitz(w, r_max, seed=seed)
    checks = [
        (not w.has_bias, "attention projections carry biases (theorem premise violated)"),
        (r_obs <= r_max * (1 + RADIUS_TOL), f"observed input radius {r_obs:.4g} > R_max {r_max}"),
        (agrees, "power iteration disagrees with SVD"),
        (bound <= ceiling, f"measured bound {bound:.4g} exceeds the ceiling {ceiling:.4g}"),
        (empirical <= bound, f"empirical ratio {empirical:.4g} exceeds the bound {bound:.4g}"),
    ]
    return CertificateReport(
        r_max=r_max,
        r_observed=r_obs,
        ceiling=ceiling,
        bound=bound,
        empirical=empirical,
        targeted=targeted,
        w_o_norm=spectral_norm(w.w_o),
        power_iteration_agrees=agrees,
        has_bias=w.has_bias,
        failures=tuple(msg for ok, msg in checks if not ok),
    )
