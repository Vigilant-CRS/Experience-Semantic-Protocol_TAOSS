# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Drift-robust decoder family (claims level 4 prep): synthetic, CPU, fast."""

import numpy as np
import pytest

from esp.bench.neural_decoders import (
    Coral,
    DayStats,
    GruConfig,
    GruDecoder,
    Ridge,
    hardware_record,
    lag_stack,
    r2_variance_weighted,
    shrunk_cov,
    smooth,
)

torch = pytest.importorskip("torch")


def test_smooth_matches_the_recursive_definition() -> None:
    x = np.random.default_rng(0).poisson(1.0, size=(200, 3)).astype(float)
    a = np.exp(-1 / 4.0)
    ref = np.zeros_like(x)
    acc = np.zeros(3)
    for t in range(len(x)):
        acc = a * acc + (1 - a) * x[t]
        ref[t] = acc
    np.testing.assert_allclose(smooth(x, 4.0), ref, atol=1e-12)
    np.testing.assert_array_equal(smooth(x, 0.0), x)


def test_lag_stack_with_stride_is_causal() -> None:
    x = np.arange(10.0)[:, None]
    z = lag_stack(x, 2, stride=3)
    assert z[9].tolist() == [9.0, 6.0, 3.0]
    assert z[4].tolist() == [4.0, 1.0, 0.0]


def test_day_stats_floor_silent_channels() -> None:
    x = np.zeros((100, 2))
    x[:, 0] = np.random.default_rng(1).normal(size=100)
    st = DayStats.of(x)
    assert st.std[1] == pytest.approx(0.05)
    assert np.isfinite(st.apply(x)).all()


def test_coral_maps_a_new_day_onto_the_reference_covariance() -> None:
    rng = np.random.default_rng(2)
    q1, _ = np.linalg.qr(rng.normal(size=(4, 4)))
    q2, _ = np.linalg.qr(rng.normal(size=(4, 4)))
    ref = rng.normal(size=(20000, 4)) @ np.diag([1.0, 1.5, 2.0, 3.0]) @ q1  # well conditioned
    new = rng.normal(size=(20000, 4)) @ np.diag([3.0, 0.8, 1.2, 2.0]) @ q2 + 3.0
    c = Coral.fit_reference(ref, shrink=0.0)
    out = c.transform(new, new)
    np.testing.assert_allclose(
        np.cov(out, rowvar=False), shrunk_cov(ref, 0.0), rtol=0.05, atol=0.05
    )
    assert np.allclose(out.mean(axis=0), 0.0, atol=1e-8)


def test_weighted_ridge_follows_the_heavy_samples() -> None:
    rng = np.random.default_rng(3)
    x = rng.normal(size=(400, 2))
    y = np.where(np.arange(400)[:, None] < 300, x[:, :1] * 1.0, x[:, :1] * -1.0)
    w = np.where(np.arange(400) < 300, 1.0, 100.0)
    r = Ridge(1e-6).fit(x, y, w)
    assert r.w is not None
    assert r.w[0, 0] < 0  # the last 100 rows dominate


def test_r2() -> None:
    y = np.random.default_rng(4).normal(size=(50, 3))
    assert r2_variance_weighted(y, y) == 1.0
    assert r2_variance_weighted(y, np.tile(y.mean(0), (50, 1))) == pytest.approx(0.0)


def _task(n: int = 1500, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    v = np.zeros((n, 2))
    for t in range(1, n):  # stationary AR(1) "velocity"
        v[t] = 0.95 * v[t - 1] + 0.3 * rng.normal(size=2)
    x = v @ rng.normal(size=(2, 12)) + 0.3 * rng.normal(size=(n, 12))
    return x, v


def test_gru_learns_and_is_deterministic_on_cpu(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ESP_DEVICE", "cpu")
    x, y = _task()
    m = np.ones(len(x), bool)
    cfg = GruConfig(hidden=16, epochs=6, chunk=100, batch=8, seed=3)
    a = GruDecoder(12, 2, cfg).fit([x[:1000]], [y[:1000]], [m[:1000]])
    b = GruDecoder(12, 2, cfg).fit([x[:1000]], [y[:1000]], [m[:1000]])
    pa, pb = a.predict(x[1000:]), b.predict(x[1000:])
    np.testing.assert_array_equal(pa, pb)
    assert r2_variance_weighted(y[1000:], pa) > 0.3
    assert hardware_record()["device"] == "cpu"
