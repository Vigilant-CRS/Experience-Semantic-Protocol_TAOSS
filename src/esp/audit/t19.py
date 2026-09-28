# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""T19 audits (WP-058; V13 receiver threats): latent inversion and semantic over-recovery.

For a released representation ``Z`` of source data ``X``:

- **inversion**: how well ``X`` can be reconstructed from ``Z`` (held-out R^2);
- **attribute inference**: balanced accuracy of predicting a registry-declared
  sensitive attribute from ``Z`` against chance ``1/K``;
- **utility-matched comparison** against an anchor-only release;
- a **query-limited black-box probe**: an adversary with ``budget`` queries of
  probe configurations searches for the strongest leakage (the audit reports
  the maximum it found, so a larger budget never reports less).

Empirical only: passing does not prove non-invertibility (V13).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from esp.audit.suite import v_information_ladder
from esp.training.leakage import Split, probe

F64 = NDArray[np.float64]


def inversion_r2(z: F64, x: F64, *, seed: int = 0) -> float:
    return probe(z, x, Split.fixed(z.shape[0], seed=seed)).r2


def attribute_balanced_accuracy(
    z: F64, labels: NDArray[np.int64], *, seed: int = 0
) -> tuple[float, float]:
    """(balanced accuracy, chance) of a nearest-centroid attribute probe on a fixed split."""
    split = Split.fixed(z.shape[0], seed=seed)
    classes = np.unique(labels[split.train])
    cents = np.stack([z[split.train][labels[split.train] == c].mean(0) for c in classes])
    pred = classes[np.argmin(((z[split.test][:, None, :] - cents[None]) ** 2).sum(-1), axis=1)]
    truth = labels[split.test]
    recalls = [np.mean(pred[truth == c] == c) for c in classes if np.any(truth == c)]
    return float(np.mean(recalls)), 1.0 / len(classes)


@dataclass(frozen=True, slots=True)
class T19Report:
    inversion_r2: float
    attribute_bacc: float
    chance: float
    anchor_only_inversion_r2: float
    anchor_only_attribute_bacc: float

    def passed(self, *, r2_limit: float = 0.3, margin: float = 0.02) -> bool:
        return self.inversion_r2 <= r2_limit and self.attribute_bacc <= self.chance + margin


def t19_audit(
    z: F64, anchors: F64, x: F64, attribute: NDArray[np.int64], *, seed: int = 0
) -> T19Report:
    bacc, chance = attribute_balanced_accuracy(z, attribute, seed=seed)
    abacc, _ = attribute_balanced_accuracy(anchors, attribute, seed=seed)
    return T19Report(
        inversion_r2=inversion_r2(z, x, seed=seed),
        attribute_bacc=bacc,
        chance=chance,
        anchor_only_inversion_r2=inversion_r2(anchors, x, seed=seed),
        anchor_only_attribute_bacc=abacc,
    )


def black_box_probe(
    visible: F64, masked: F64, *, budget: int, seeds: Sequence[int] = (0,)
) -> tuple[float, list[float]]:
    """Query-limited search over probe families (degree x split seed); running maximum."""
    configs = [(d, s) for d in (1, 2, 3) for s in seeds]
    rng = np.random.default_rng(0)
    order = rng.permutation(len(configs))
    best, trace = 0.0, []
    for q in order[:budget]:
        degree, seed = configs[q]
        best = max(best, v_information_ladder(visible, masked, degrees=(degree,), seed=seed)[-1])
        trace.append(best)
    return best, trace
