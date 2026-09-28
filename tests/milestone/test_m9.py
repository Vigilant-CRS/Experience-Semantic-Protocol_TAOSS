# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M9 gate: ExperienceBench exploratory.

All benchmarks run on the smoke dataset; no confirmatory claims (runs are
labelled exploratory without a preregistration). Plan 54a adds: the
red-team sender is detected (WP-057) and the preregistration guard works
(WP-083); the audit suite recovers known MI (WP-058).
"""

import re
from pathlib import Path

import pytest

from esp.audit.suite import covert_channel_audit
from esp.bench.prereg import Hypothesis, RunRecord, SplitUnit, label_run
from esp.bench.smoke import make_corpus
from esp.bench.tasks import FAMILIES, h1, h2, h3, run_all, smoke_label
from tests.unit.audit.test_audit import red_team

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]


def test_m9_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-034", "WP-035", "WP-036", "WP-037", "WP-057", "WP-058", "WP-083"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


def test_every_benchmark_runs_on_smoke_data_and_nothing_is_confirmatory() -> None:
    corpus = make_corpus(seed=7)
    results = run_all(corpus)
    assert len(results) == len(FAMILIES) == 9
    for fn in (h1, h2, h3):
        assert not fn(corpus, smoke_label()).claimable
    unregistered = RunRecord(
        Hypothesis.H1, "effective_policies", (), (0,), ("smoke",), SplitUnit.SESSION, 1
    )
    assert label_run(unregistered, None).name == "exploratory"


def test_red_team_sender_is_detected() -> None:
    emo, honest, stego = red_team(seed=11)
    assert covert_channel_audit(honest, emo).passed
    assert not covert_channel_audit(stego, emo).passed
