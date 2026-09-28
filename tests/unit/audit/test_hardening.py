# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-057 hardening and WP-036 learned privacy filter."""

import numpy as np

from esp.audit.hardening import gating_sparsity_ok, randomized_quantize, tem_band_violations
from esp.audit.suite import v_information_ladder
from esp.bench.filter import learned_filter
from esp.bench.smoke import TYPES, encode, make_corpus


def test_randomized_quantization_destroys_sub_step_payloads() -> None:
    rng = np.random.default_rng(0)
    n, step = 3000, 0.05
    secret = rng.integers(0, 2, size=(n, 1)).astype(float)
    cover = rng.integers(-100, 100, size=(n, 8)) * step  # an honest encoder's INT8 grid values
    cover[:, 0] = 127 * step  # pins the quantization scale
    stego = cover.copy()
    stego[:, 1:] += 0.3 * step * secret  # one bit per frame, hidden below the step

    def adversary(x: np.ndarray) -> np.ndarray:  # reads the offset from the grid
        return np.mod(x[:, 1:] / step, 1.0)

    assert v_information_ladder(adversary(stego), secret, degrees=(1,))[-1] > 0.5
    hardened = np.stack([randomized_quantize(row, rng) for row in stego])
    assert v_information_ladder(adversary(hardened), secret, degrees=(1,))[-1] < 0.02
    x = rng.normal(size=10000)
    assert abs(np.mean(randomized_quantize(x, rng) - x)) < 0.01  # unbiased


def test_bands() -> None:
    tem = np.zeros((10, 4))
    tem[3, 1] = 9.0
    assert tem_band_violations(tem, -5.0, 5.0) == 1
    z = np.zeros((10, 10))
    z[:, :5] = 1.0
    assert gating_sparsity_ok(z, (0.4, 0.6))
    assert not gating_sparsity_ok(z, (0.0, 0.2))


def test_learned_filter_reduces_nonlinear_leakage_at_task_utility() -> None:
    c = make_corpus(n=600)
    mono = encode(c, "mono")
    full = np.concatenate([mono[t] for t in TYPES], axis=1)
    protected = c.factors["EMO"]
    before = v_information_ladder(full, protected, degrees=(1, 2))[-1]
    filtered = learned_filter(full, c.actions, protected, steps=300)
    after = v_information_ladder(filtered, protected, degrees=(1, 2))[-1]
    assert after < 0.5 * before
