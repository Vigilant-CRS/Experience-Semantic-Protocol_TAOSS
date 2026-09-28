# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-034..037 ExperienceBench on smoke data and WP-083 preregistration guard."""

import dataclasses

import numpy as np
import pytest

from esp.bench.prereg import (
    Hypothesis,
    Preregistration,
    RunRecord,
    SplitUnit,
    holm,
    label_run,
)
from esp.bench.smoke import TYPES, encode, leace_erase, make_corpus
from esp.bench.tasks import (
    FAMILIES,
    REQUIRED_BASELINES,
    causal_controls,
    h1,
    h2,
    h3,
    human_interpretability,
    ndcg_at_k,
    run_all,
    smoke_label,
    unit_split,
)

CORPUS = make_corpus()


def test_all_nine_families_run_on_the_smoke_fixture() -> None:
    assert sorted(FAMILIES) == list(range(1, 10))
    for variant in ("taoss", "mono", "taoss_cov_only"):
        results = run_all(CORPUS, variant)
        assert [r.family for r in results] == list(range(1, 10))
        for r in results:
            assert all(np.isfinite(v) for v in r.metrics.values()), (variant, r.task)


def test_split_is_by_unit_and_excludes_ood() -> None:
    train, test = unit_split(CORPUS)
    assert not set(CORPUS.units[train]) & set(CORPUS.units[test])
    assert not (train | test)[CORPUS.ood].any()


def test_human_study_is_never_simulated() -> None:
    r = human_interpretability(CORPUS, {})
    assert r.status == "deferred"
    assert r.metrics == {}
    assert "ethics" in r.notes[0]


def test_ndcg() -> None:
    rel = np.array([3.0, 2.0, 0.0, 1.0])
    assert ndcg_at_k(rel, np.array([4.0, 3.0, 1.0, 2.0])) == pytest.approx(1.0)
    assert ndcg_at_k(rel, np.array([1.0, 2.0, 4.0, 3.0])) < 0.7


def test_leace_removes_linear_predictability() -> None:
    rng = np.random.default_rng(0)
    concept = rng.normal(size=(2000, 2))
    x = np.concatenate([concept @ rng.normal(size=(2, 5)), rng.normal(size=(2000, 3))], 1)
    erased = leace_erase(x, concept)
    xc, zc = erased - erased.mean(0), concept - concept.mean(0)
    assert np.abs(xc.T @ zc / 2000).max() < 1e-10  # no linear covariance left
    assert np.linalg.norm(erased[:, 5:] - x[:, 5:]) < 0.2 * np.linalg.norm(
        x[:, 5:]
    )  # minimal change


def test_h1_h2_h3_on_smoke_data_are_never_claimable() -> None:
    for fn in (h1, h2, h3):
        r = fn(CORPUS, smoke_label())
        assert not r.claimable
        assert set(r.baselines_missing) >= {"text_llm", "clip_class"}
    r1 = h1(CORPUS, smoke_label())
    assert r1.values["taoss_effective_policies"] > r1.values["mono_effective_policies"]
    r2 = h2(CORPUS, smoke_label())
    assert r2.values["taoss_mean_bits"] < 0.5 * r2.values["mono_mean_bits"]
    assert r2.values["taoss_cov_only_mean_bits"] > r2.values["taoss_mean_bits"]


def test_h3_causal_controls_detect_use_of_the_latent() -> None:
    z = encode(CORPUS, "taoss")
    ctrl = causal_controls(CORPUS, z)
    assert set(ctrl) == {"zero", "shuffled", "moment"}
    assert all(gap > 0.2 and p < 0.01 for gap, p in ctrl.values())
    # a receiver that ignores the latent: controls are indistinguishable
    ignore = dict(z) | {"INT": np.zeros_like(z["INT"])}
    null = causal_controls(CORPUS, ignore)
    assert null["zero"][0] == 0.0
    assert null["zero"][1] > 0.5


def test_holm() -> None:
    assert holm([0.01, 0.04, 0.03], 0.05) == [True, False, False]
    assert holm([0.001, 0.01, 0.02], 0.05) == [True, True, True]
    assert holm([0.2, 0.001], 0.05) == [False, True]


def prereg(**kw: object) -> Preregistration:
    base: dict[str, object] = {
        "hypothesis": Hypothesis.H2,
        "primary_metric": "mean_pairwise_v_information",
        "threshold": 0.5,
        "split_unit": SplitUnit.SESSION,
        "baselines": REQUIRED_BASELINES,
        "seeds": (0, 1, 2),
        "datasets": ("smoke-v1",),
        "registered_at_ns": 100,
        "registry_ref": "osf.io/abcde",
    }
    return Preregistration(**(base | kw))  # type: ignore[arg-type]


def run(p: Preregistration, **kw: object) -> RunRecord:
    base: dict[str, object] = {
        "hypothesis": p.hypothesis,
        "primary_metric": p.primary_metric,
        "baselines": p.baselines,
        "seeds": p.seeds,
        "datasets": p.datasets,
        "split_unit": p.split_unit,
        "started_at_ns": 200,
        "prereg_digest": p.digest(),
    }
    return RunRecord(**(base | kw))  # type: ignore[arg-type]


def test_confirmatory_only_with_a_matching_prior_preregistration() -> None:
    p = prereg()
    assert label_run(run(p), p).confirmatory
    assert label_run(run(p), None).name == "exploratory"
    cases = {
        "predate": {"started_at_ns": 50},
        "metric": {"primary_metric": "r2"},
        "baseline": {"baselines": ("mono",)},
        "seeds": {"seeds": (0,)},
        "digest": {"prereg_digest": "0" * 64},
        "split unit": {"split_unit": SplitUnit.MEDIA_ITEM},
    }
    for reason, change in cases.items():
        label = label_run(run(p, **change), p)
        assert not label.confirmatory
        assert any(reason in r for r in label.reasons), (reason, label.reasons)
    changed = dataclasses.replace(p, threshold=0.4)
    assert changed.digest() != p.digest()  # editing after the fact breaks the pin
    assert p.osf_export()["multiple_comparisons"] == "holm"
    with pytest.raises(ValueError, match="Holm"):
        prereg(multiplicity="none")


def test_types_constant() -> None:
    assert TYPES == ("KNO", "INT", "EMO", "CTX", "SEN", "TEM")
