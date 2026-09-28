# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Preregistration, multiplicity correction and the confirmatory guard (WP-083; V13 section 14).

A benchmark run counts as *confirmatory* evidence for H1/H2/H3 only if a
preregistration fixing hypotheses, primary metrics, thresholds, split unit,
baselines, seeds and the multiplicity procedure existed **before** the run,
and the run matches it. Everything else is labelled *exploratory*.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Hypothesis(StrEnum):
    H1 = "H1"
    H2 = "H2"
    H3 = "H3"


class SplitUnit(StrEnum):
    SUBJECT = "subject"
    SESSION = "session"
    MEDIA_ITEM = "media_item"


@dataclass(frozen=True, slots=True)
class Preregistration:
    hypothesis: Hypothesis
    primary_metric: str
    threshold: float
    split_unit: SplitUnit
    baselines: tuple[str, ...]
    seeds: tuple[int, ...]
    datasets: tuple[str, ...]
    multiplicity: str = "holm"
    alpha: float = 0.05
    registered_at_ns: int = 0
    registry_ref: str = ""
    """e.g. an OSF identifier; empty for local drafts."""
    notes: str = ""

    def __post_init__(self) -> None:
        if self.multiplicity != "holm":
            msg = "only Holm (or stricter, not implemented) is accepted"
            raise ValueError(msg)
        if not self.baselines or not self.seeds or not self.datasets:
            msg = "baselines, seeds and datasets must be declared"
            raise ValueError(msg)

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()

    def osf_export(self) -> dict[str, object]:
        """OSF-compatible preregistration fields (JSON)."""
        return {
            "title": f"ESP ExperienceBench {self.hypothesis.value}",
            "hypotheses": self.hypothesis.value,
            "dependent_variables": self.primary_metric,
            "inference_criteria": (
                f"{self.primary_metric} threshold {self.threshold}; alpha {self.alpha}"
            ),
            "multiple_comparisons": self.multiplicity,
            "sampling_plan": f"split unit {self.split_unit.value}; datasets {list(self.datasets)}",
            "analysis_plan": f"baselines {list(self.baselines)}; seeds {list(self.seeds)}",
            "digest": self.digest(),
        }


@dataclass(frozen=True, slots=True)
class RunRecord:
    hypothesis: Hypothesis
    primary_metric: str
    baselines: tuple[str, ...]
    seeds: tuple[int, ...]
    datasets: tuple[str, ...]
    split_unit: SplitUnit
    started_at_ns: int
    prereg_digest: str | None = None


@dataclass(frozen=True, slots=True)
class Label:
    confirmatory: bool
    reasons: tuple[str, ...] = field(default=())

    @property
    def name(self) -> str:
        return "confirmatory" if self.confirmatory else "exploratory"


def label_run(run: RunRecord, prereg: Preregistration | None) -> Label:
    """Confirmatory only with a matching preregistration that predates the run."""
    if prereg is None:
        return Label(False, ("no preregistration",))
    checks = [
        (run.prereg_digest == prereg.digest(), "run does not pin the preregistration digest"),
        (prereg.registered_at_ns < run.started_at_ns, "preregistration does not predate the run"),
        (run.hypothesis is prereg.hypothesis, "hypothesis differs"),
        (run.primary_metric == prereg.primary_metric, "primary metric differs"),
        (set(prereg.baselines) <= set(run.baselines), "a preregistered baseline is missing"),
        (run.seeds == prereg.seeds, "seeds differ"),
        (run.datasets == prereg.datasets, "datasets differ"),
        (run.split_unit is prereg.split_unit, "split unit differs"),
    ]
    reasons = tuple(msg for ok, msg in checks if not ok)
    return Label(not reasons, reasons)


def holm(p_values: Sequence[float], alpha: float = 0.05) -> list[bool]:
    """Holm-Bonferroni step-down: which hypotheses are rejected at family-wise ``alpha``."""
    order = sorted(range(len(p_values)), key=lambda i: p_values[i])
    reject = [False] * len(p_values)
    m = len(p_values)
    for rank, i in enumerate(order):
        if p_values[i] <= alpha / (m - rank):
            reject[i] = True
        else:
            break
    return reject
