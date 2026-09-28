# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Friedkin-Johnsen theorem and lemmas (V13 Bounded Influence), checked numerically."""

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from esp.core.taoss_types import TaossType as T
from esp.hive.dynamics import (
    autonomy,
    check_coupling,
    diversity,
    equilibrium_matrix,
    fj_run,
    normalized_diversity,
    social_power,
    uniform_w,
)
from esp.hive.tlv import HiveError


def random_w(rng: np.random.Generator, n: int) -> np.ndarray:
    w = rng.random((n, n))
    return w / w.sum(axis=1, keepdims=True)


@settings(max_examples=60, deadline=None)
@given(st.integers(2, 8), st.integers(0, 2**31), st.floats(0.0, 0.95))
def test_convergence_autonomy_drift(n: int, seed: int, lmax: float) -> None:
    rng = np.random.default_rng(seed)
    w = random_w(rng, n)
    lam = rng.uniform(0.0, lmax, size=n) if lmax > 0 else np.zeros(n)
    x0 = rng.normal(size=(n, 3))
    p = equilibrium_matrix(w, lam)
    assert np.all(p >= -1e-12)
    assert np.allclose(p.sum(axis=1), 1.0)
    xs = fj_run(x0, w, lam, 40)
    star = p @ x0
    err0 = np.max(np.linalg.norm(x0 - star, axis=1))
    for k, xk in enumerate(xs):  # geometric convergence at rate lambda_max
        assert np.max(np.linalg.norm(xk - star, axis=1)) <= (max(lam) ** k) * err0 + 1e-9
    assert np.all(autonomy(p) >= 1.0 - lam - 1e-12)  # autonomy floor
    spread = np.max(np.linalg.norm(x0[:, None, :] - x0[None, :, :], axis=-1), axis=1)
    assert np.all(np.linalg.norm(star - x0, axis=1) <= lam * spread + 1e-9)  # drift bound
    assert np.isclose(social_power(p).sum(), 1.0)
    if np.sum(1.0 - lam) > 1.0:  # no-consensus lemma
        assert np.linalg.matrix_rank(p, tol=1e-9) >= 2


def test_emo_mixing_rejected_even_if_granted() -> None:
    w = uniform_w(5)
    with pytest.raises(HiveError, match="EMO mixing must be 0"):
        check_coupling(T.EMO, w, [0.1] * 5, [0.9] * 5)
    check_coupling(T.EMO, w, [0.0] * 5, [0.0] * 5)


def test_coupling_bounded_by_grant_and_w_validated() -> None:
    w = uniform_w(4)
    with pytest.raises(HiveError, match="lambda_max"):
        check_coupling(T.KNO, w, [0.3] * 4, [0.3, 0.3, 0.3, 0.2])
    check_coupling(T.KNO, w, [0.3] * 4, [0.3] * 4)
    bad = w.copy()
    bad[0, 1] = -0.1
    with pytest.raises(HiveError, match="row-stochastic"):
        check_coupling(T.KNO, bad, [0.3] * 4, [0.5] * 4)
    with pytest.raises(HiveError, match=r"\[0, 1\)"):
        check_coupling(T.KNO, w, [1.0] * 4, [1.0] * 4)


def test_degroot_limit_collapses_diversity_fj_does_not() -> None:
    rng = np.random.default_rng(0)
    x0 = rng.normal(size=(6, 2))
    w = uniform_w(6)
    near_degroot = fj_run(x0, w, [0.99] * 6, 400)[-1]
    bounded = fj_run(x0, w, [0.3] * 6, 400)[-1]
    assert normalized_diversity(x0, near_degroot) < 0.01  # monoculture
    nd = normalized_diversity(x0, bounded)
    assert nd is not None
    assert nd > 0.3  # anchoring keeps a large share of the diversity
    assert normalized_diversity(np.zeros((3, 2)), np.zeros((3, 2))) is None
    assert diversity(np.zeros((1, 2))) == 0.0


def test_hub_capture_detected_by_social_power() -> None:
    n = 5
    w = np.zeros((n, n))
    w[:, 0] = 1.0  # everybody listens only to member 0
    w[0] = np.r_[0.0, np.ones(n - 1) / (n - 1)]
    p = equilibrium_matrix(w, [0.0, 0.9, 0.9, 0.9, 0.9])
    assert social_power(p).max() > 0.5
