# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Confidence calibration (WP-030): isotonic regression and expected calibration error.

A source's raw confidence is mapped to the empirical rate at which its claims
were correct on labeled calibration data (pool-adjacent-violators). The
mapping is monotone, deterministic and stored as knots.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True, slots=True)
class IsotonicCalibrator:
    knots_x: tuple[float, ...]
    knots_y: tuple[float, ...]

    @classmethod
    def fit(cls, confidence: Sequence[float], correct: Sequence[bool]) -> IsotonicCalibrator:
        x = np.asarray(confidence, dtype=np.float64)
        y = np.asarray(correct, dtype=np.float64)
        if x.size == 0 or x.size != y.size or np.any((x < 0) | (x > 1)):
            msg = "need matching confidences in [0, 1] and outcomes"
            raise ValueError(msg)
        order = np.argsort(x, kind="stable")
        x, y = x[order], y[order]
        # pool adjacent violators on (value, weight) blocks
        values, weights, lefts = [], [], []
        for xi, yi in zip(x, y, strict=True):
            values.append(float(yi))
            weights.append(1.0)
            lefts.append(float(xi))
            while len(values) > 1 and values[-2] > values[-1]:
                w = weights[-2] + weights[-1]
                v = (values[-2] * weights[-2] + values[-1] * weights[-1]) / w
                values[-2:], weights[-2:] = [v], [w]
                lefts.pop()
        return cls(tuple(lefts), tuple(values))

    def __call__(self, confidence: float) -> float:
        if not 0.0 <= confidence <= 1.0:
            msg = "confidence must be in [0, 1]"
            raise ValueError(msg)
        return float(np.interp(confidence, self.knots_x, self.knots_y))


def expected_calibration_error(
    confidence: Sequence[float], correct: Sequence[bool], bins: int = 10
) -> float:
    x = np.asarray(confidence, dtype=np.float64)
    y = np.asarray(correct, dtype=np.float64)
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(x, edges[1:-1]), 0, bins - 1)
    total = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            total += m.mean() * abs(x[m].mean() - y[m].mean())
    return float(total)
