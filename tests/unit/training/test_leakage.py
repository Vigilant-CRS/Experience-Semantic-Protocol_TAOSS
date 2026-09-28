# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-033: cross-type leakage harness on latents with known dependence."""

import numpy as np
import pytest

from esp.training.leakage import Split, leakage_matrix, probe


def latents(leak: float, n: int = 600, seed: int = 0) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    a, b, c = (rng.normal(size=(n, 4)) for _ in range(3))
    b = np.sqrt(1 - leak) * b + np.sqrt(leak) * a  # planted A -> B dependence
    return {"A": a @ rng.normal(size=(4, 8)), "B": b @ rng.normal(size=(4, 6)), "C": c}


def test_independent_types_show_no_leakage() -> None:
    m = leakage_matrix(latents(0.0))
    assert m.max_pairwise() < 0.05
    assert m.significant() == []
    for r in m.pairwise.values():
        assert r.ci_low <= r.r2 <= r.ci_high


def test_planted_leakage_is_detected_with_confidence_intervals() -> None:
    m = leakage_matrix(latents(0.6))
    assert m.pairwise[("B", "A")].r2 > 0.4
    assert m.pairwise[("A", "B")].r2 > 0.4
    assert set(m.significant()) == {("A", "B"), ("B", "A")}
    assert m.pairwise[("C", "A")].r2 < 0.05  # C stays independent
    assert m.joint["B"].r2 >= m.pairwise[("B", "A")].r2 - 0.02  # joint >= best single source


def test_fixed_split_discipline_and_determinism() -> None:
    s1, s2 = Split.fixed(100, seed=3), Split.fixed(100, seed=3)
    assert np.array_equal(s1.test, s2.test)
    assert not set(s1.train) & set(s1.test)
    assert len(s1.test) == 30
    m1, m2 = leakage_matrix(latents(0.5)), leakage_matrix(latents(0.5))
    assert m1.pairwise == m2.pairwise
    with pytest.raises(ValueError, match="n >= 10"):
        Split.fixed(5)


def test_shuffled_baseline_is_chance_level() -> None:
    rng = np.random.default_rng(1)
    x = rng.normal(size=(400, 5))
    r = probe(x, x @ rng.normal(size=(5, 3)), Split.fixed(400))
    assert r.r2 > 0.95
    assert r.baseline_r2 < 0.05
