# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M8 gate: trainable TAOSS on a tiny dataset.

Training converges, types have the right shape, gradients are valid, the
leakage harness works, checkpoints are reproducible (details in
``tests/unit/training``). Here: the adversarial + covariance terms reduce
planted cross-type leakage relative to a task-only run, as measured by the
leakage harness. No H1/H2/H3 claim.
"""

import dataclasses
import re
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

from esp.training.harness import DataConfig, TrainConfig, Trainer  # noqa: E402
from esp.training.leakage import leakage_matrix  # noqa: E402

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]


def test_m8_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-031", "WP-032", "WP-033"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


def test_decorrelation_trades_task_fit_for_less_measured_leakage(tmp_path: Path) -> None:
    """Planted cross-type dependence (EMO <-> CTX): stronger decorrelation must reduce the
    leakage the harness measures on that pair, at a visible cost in task fit."""
    base = TrainConfig(steps=400, data=DataConfig(n=1024, leak=0.6))
    runs = {}
    for name, (lam, beta) in {"task_only": (0.0, 0.0), "taoss": (5.0, 0.1)}.items():
        t = Trainer(dataclasses.replace(base, lambda_cov=lam, beta_adv=beta), tmp_path / name)
        first = t.train(until_step=1)["task"]
        last = t.train()["task"]
        lat = {k.name: v for k, v in t.encode_all().items()}
        runs[name] = (first, last, leakage_matrix(lat, n_boot=50))
    for first, last, _ in runs.values():
        assert last < 0.2 * first  # both converge
    leak_task_only = runs["task_only"][2].pairwise[("EMO", "CTX")].r2
    leak_taoss = runs["taoss"][2].pairwise[("EMO", "CTX")].r2
    assert leak_task_only > 0.5  # the harness sees the planted dependence
    assert leak_taoss < leak_task_only - 0.05  # decorrelation reduces it ...
    assert runs["taoss"][1] > runs["task_only"][1]  # ... at a cost in task fit (honest trade-off)
