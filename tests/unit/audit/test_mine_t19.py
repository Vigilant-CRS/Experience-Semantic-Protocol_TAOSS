# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-058: MINE second estimator, T19 audits, query-limited black-box probe."""

import math

import numpy as np
import pytest

from esp.audit.estimators import dissent, gaussian_mi_bits, ksg_mi
from esp.audit.mine import mine_mi
from esp.audit.t19 import black_box_probe, t19_audit


def pairs(rho: float, n: int = 2000, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    x = rng.normal(size=(n, 1))
    return x, rho * x + math.sqrt(1 - rho**2) * rng.normal(size=(n, 1))


@pytest.mark.parametrize("rho", [0.0, 0.8])
def test_mine_tracks_analytic_mi_and_agrees_with_ksg(rho: float) -> None:
    x, y = pairs(rho)
    truth = gaussian_mi_bits(rho)
    m = mine_mi(x, y)
    assert m == pytest.approx(truth, abs=0.15 + 0.2 * truth)
    assert mine_mi(x, y) == m  # seeded: reproducible
    k = ksg_mi(x[:800], y[:800])
    assert not dissent(k, m, d_eff=2, n=800) or abs(k - m) < 0.2


def test_t19_detects_invertible_release_and_anchor_only_is_safer() -> None:
    rng = np.random.default_rng(3)
    x = rng.normal(size=(8000, 8))  # source features (large: chance + 0.02 needs a tight estimate)
    attribute = (x[:, 0] > 0).astype(np.int64)  # sensitive attribute hidden in the source
    z_raw = x @ rng.normal(size=(8, 16))  # a latent that keeps everything
    task = x[:, 1:3]
    anchors = np.tanh(task @ rng.normal(size=(2, 4)))  # anchor-only: task-relevant only
    report = t19_audit(z_raw, anchors, x, attribute)
    assert report.inversion_r2 > 0.9
    assert report.attribute_bacc > 0.75  # nearest-centroid probe on a threshold attribute
    assert not report.passed()
    assert report.anchor_only_inversion_r2 < 0.5
    assert report.anchor_only_attribute_bacc < report.chance + 0.05
    safe = t19_audit(anchors, anchors, x, attribute)
    assert safe.passed(r2_limit=0.5)


def test_black_box_probe_budget_is_monotone() -> None:
    rng = np.random.default_rng(4)
    emo = rng.normal(size=(1200, 2))
    tem = emo + 0.3 * rng.normal(size=emo.shape)
    target = np.sum(emo**2, axis=1, keepdims=True)
    best, trace = black_box_probe(tem, target, budget=3, seeds=(0,))
    assert trace == sorted(trace)
    assert best > 1.0  # finds the quadratic channel within the budget
    small, _ = black_box_probe(tem, target, budget=1, seeds=(0,))
    assert small <= best
