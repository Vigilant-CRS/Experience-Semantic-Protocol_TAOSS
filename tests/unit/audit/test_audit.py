# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-058 audit suite and WP-057 covert-channel audit."""

import math

import numpy as np
import pytest

from esp.audit.estimators import (
    _digamma,
    cluster_bootstrap,
    dissent,
    distance_correlation,
    gaussian_mi_bits,
    hsic,
    ksg_mi,
    pca_surrogate,
)
from esp.audit.suite import audit_pair, covert_channel_audit, v_information_ladder


def pairs(rho: float, n: int = 800, dims: int = 1, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    x = rng.normal(size=(n, dims))
    y = rho * x + math.sqrt(1 - rho**2) * rng.normal(size=(n, dims))
    return x, y


def test_digamma_matches_known_values() -> None:
    euler = 0.5772156649015329
    np.testing.assert_allclose(
        _digamma(np.array([1.0, 2.0, 0.5])),
        [-euler, 1 - euler, -euler - 2 * math.log(2)],
        atol=1e-9,
    )


@pytest.mark.parametrize(("rho", "dims"), [(0.0, 1), (0.5, 1), (0.8, 1), (0.6, 2)])
def test_ksg_recovers_analytic_gaussian_mi(rho: float, dims: int) -> None:
    x, y = pairs(rho, dims=dims)
    truth = gaussian_mi_bits(rho, dims)
    assert ksg_mi(x, y, k=6) == pytest.approx(truth, abs=0.06 + 0.05 * truth)


def test_k_range_is_enforced() -> None:
    x, y = pairs(0.5, n=50)
    with pytest.raises(ValueError, match=r"4\.\.10"):
        ksg_mi(x, y, k=3)


def test_hsic_and_dcor_detect_nonlinear_dependence() -> None:
    rng = np.random.default_rng(2)
    x = rng.uniform(-2, 2, 300)
    y = x**2 + 0.1 * rng.normal(size=300)  # uncorrelated but dependent
    assert abs(np.corrcoef(x, y)[0, 1]) < 0.15
    _, p_dep = hsic(x, y, permutations=100)
    _, p_ind = hsic(x, rng.normal(size=300), permutations=100)
    assert p_dep < 0.02
    assert p_ind > 0.05
    assert distance_correlation(x, y) > 0.3


def test_surrogate_for_high_dimensional_types_is_reported() -> None:
    z = np.random.default_rng(0).normal(size=(100, 240))
    s, d = pca_surrogate(z)
    assert s.shape == (100, 32)
    assert d == 32


def test_cluster_bootstrap_resamples_units() -> None:
    x, y = pairs(0.7, n=400)
    units = np.repeat(np.arange(20), 20)
    ci = cluster_bootstrap(
        lambda a, b: float(np.corrcoef(a[:, 0], b[:, 0])[0, 1]), x, y, units, b=200
    )
    assert ci.units == 20
    assert ci.low < ci.estimate < ci.high
    with pytest.raises(ValueError, match="two split units"):
        cluster_bootstrap(lambda a, b: 0.0, x, y, np.zeros(400, dtype=np.int64))


def test_dissent_trigger() -> None:
    assert not dissent(0.10, 0.105, d_eff=2, n=1000)
    assert dissent(0.10, 0.2, d_eff=2, n=1000)


def test_audit_report_pass_fail_and_no_free_lunch() -> None:
    x, y = pairs(0.0, n=500, dims=3)
    honest = audit_pair("EMO", "KNO", x, y)
    assert honest.passed
    leaky = audit_pair("EMO", "KNO", *pairs(0.8, n=500, dims=3))
    assert not leaky.passed
    assert leaky.probe_r2 is not None
    assert leaky.probe_r2 > 0.5
    no_probe = audit_pair("EMO", "KNO", x, y, with_probe=False)
    assert not no_probe.passed  # a report without a probe result is an audit failure


def red_team(n: int = 1500, seed: int = 0) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """TEM that hides EMO steganographically (nonlinear phase code, low amplitude)."""
    rng = np.random.default_rng(seed)
    emo = rng.normal(size=(n, 2))
    tem_honest = rng.normal(size=(n, 4))
    hidden = np.concatenate([np.sin(1.2 * emo), np.cos(1.2 * emo)], axis=1)
    return emo, tem_honest, tem_honest + 0.7 * hidden


def test_ladder_is_monotone() -> None:
    emo, _, tem = red_team()
    ladder = v_information_ladder(tem, emo)
    assert ladder == sorted(ladder)


def test_red_team_sender_fails_and_honest_sender_passes() -> None:
    emo, honest, stego = red_team()
    ok = covert_channel_audit(honest, emo)
    assert ok.passed
    assert ok.leakage_bits < 0.02
    audit = covert_channel_audit(stego, emo)
    assert not audit.passed
    assert audit.leakage_bits > 0.2


def test_nonlinear_rung_finds_what_the_linear_rung_misses() -> None:
    """EMO intensity hidden sign-symmetrically in TEM: invisible to linear probes."""
    rng = np.random.default_rng(4)
    emo = rng.normal(size=(1500, 2))
    tem = emo + 0.3 * rng.normal(size=emo.shape)  # the sign carries no intensity information
    intensity = np.sum(emo**2, axis=1, keepdims=True)
    linear, quadratic, cubic = v_information_ladder(tem, intensity)
    assert linear < 0.05
    assert quadratic > 1.0
    assert cubic >= quadratic
