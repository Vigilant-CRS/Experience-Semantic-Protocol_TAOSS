# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Preregistered predictive-emergence audit (whole-minus-sum Ψ) and admissibility flags."""

import dataclasses

import numpy as np
import pytest

from esp.core.taoss_types import TaossType as T
from esp.hive.audit import (
    EmergencePrereg,
    EmergenceResult,
    Thresholds,
    TypeAudit,
    admissibility,
    emergence_test,
    gaussian_mi,
)
from esp.hive.tlv import HiveError


def episodes(
    kind: str, count: int = 12, n: int = 5, steps: int = 60, seed: int = 1
) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    out = {}
    for e in range(count):
        x = np.zeros((steps, n, 1))
        z = rng.normal(size=(n, 1))
        for k in range(steps):
            if kind == "ar":  # independent members with memory: the mean predicts itself
                z = 0.9 * z + np.sqrt(0.19) * rng.normal(size=(n, 1))
            elif kind == "iid":  # no temporal structure at all
                z = rng.normal(size=(n, 1))
            else:  # "copy": fully redundant members, Ψ strongly negative
                c = 0.9 * z[0] + np.sqrt(0.19) * rng.normal(size=1)
                z = np.tile(c, (n, 1)) + 0.01 * rng.normal(size=(n, 1))
            x[k] = z
        out[f"a{e}"] = x
    return out


def prereg(eps: dict[str, np.ndarray], **kw: object) -> EmergencePrereg:
    fields: dict[str, object] = {
        "primary_type": T.KNO,
        "emergence_types": (T.KNO,),
        "lag": 1,
        "task": "mean-forecast",
        "fit_episodes": ("f0",),
        "audit_episodes": tuple(sorted(eps)),
        "n_boot": 80,
        "n_null": 8,
    }
    return EmergencePrereg(**(fields | kw))  # type: ignore[arg-type]


def mean(s: np.ndarray) -> np.ndarray:
    return s.mean(axis=0)


@pytest.mark.parametrize(("kind", "passes"), [("ar", True), ("iid", False), ("copy", False)])
def test_emergence_detects_only_real_synergy(kind: str, passes: bool) -> None:
    eps = episodes(kind)
    pre = prereg(eps)
    r = emergence_test(pre, pre.digest(), T.KNO, eps, mean)
    assert r.passed is passes
    if kind == "ar":
        # theory for n=5, a=0.9: I(V;V') - 5 I(X_j;V') = -0.5 ln(0.19) + 2.5 ln(1 - 0.81/5) ≈ 0.39
        assert 0.2 < r.psi < 0.55
    if kind == "copy":
        assert r.psi < 0.0


def test_gaussian_mi_matches_closed_form() -> None:
    rng = np.random.default_rng(0)
    rho = 0.8
    a = rng.normal(size=20000)
    b = rho * a + np.sqrt(1 - rho**2) * rng.normal(size=20000)
    assert abs(gaussian_mi(a, b) - (-0.5 * np.log(1 - rho**2))) < 0.02
    assert gaussian_mi(a, rng.normal(size=20000)) < 0.005


def test_preregistration_is_binding() -> None:
    eps = episodes("ar", count=6)
    pre = prereg(eps)
    digest = pre.digest()
    changed = dataclasses.replace(pre, lag=2)
    with pytest.raises(HiveError, match="preregistration"):
        emergence_test(changed, digest, T.KNO, eps, mean)
    with pytest.raises(HiveError, match="held-out"):
        emergence_test(pre, digest, T.KNO, {k: eps[k] for k in list(eps)[:3]}, mean)
    with pytest.raises(HiveError, match="not preregistered"):
        emergence_test(pre, digest, T.CTX, eps, mean)
    with pytest.raises(HiveError, match="disjoint"):
        prereg(eps, fit_episodes=(next(iter(eps)),))
    with pytest.raises(HiveError, match="fit episodes"):
        emergence_test(pre, digest, T.KNO, {**eps, "f0": eps["a0"]}, mean)
    with pytest.raises(HiveError, match="primary"):
        prereg(eps, primary_type=T.CTX)


def _ta(**kw: object) -> TypeAudit:
    fields: dict[str, object] = {
        "type": T.KNO,
        "emergence": EmergenceResult(T.KNO, 0.4, 0.0, 0.2, True),
        "normalized_diversity": 0.6,
        "min_autonomy": 0.8,
        "max_social_power": 0.2,
        "privacy_ok": True,
        "emo_mixing": 0.0,
    }
    return TypeAudit(**(fields | kw))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("change", "flag"),
    [
        ({"emergence": EmergenceResult(T.KNO, 0.4, 0.0, -0.1, False)}, "no-emergence"),
        ({"normalized_diversity": 0.1}, "monoculture:KNO"),
        ({"min_autonomy": 0.3}, "autonomy-breach:KNO"),
        ({"max_social_power": 0.9}, "captured:KNO"),
        ({"privacy_ok": False}, "privacy:KNO"),
    ],
)
def test_each_admissibility_condition_blocks_the_hive_label(
    change: dict[str, object], flag: str
) -> None:
    th = Thresholds(d_min=0.2, a_min=0.5, pi_max=0.5)
    assert admissibility([_ta()], (T.KNO,), th, "IDENTIFIED").label == "hive"
    r = admissibility([_ta(**change)], (T.KNO,), th, "IDENTIFIED")
    assert r.label == "collective"
    assert flag in r.flags


def test_emo_mixing_flag() -> None:
    th = Thresholds()
    emo = _ta(type=T.EMO, emergence=None, emo_mixing=0.1)
    r = admissibility([_ta(), emo], (T.KNO,), th, "IDENTIFIED")
    assert "emo-mixing" in r.flags
    assert r.label == "collective"


def test_lower_bound_is_taken_against_the_null(monkeypatch: pytest.MonkeyPatch) -> None:
    """The statistic is Ψ_obs - mean Ψ_null, bootstrapped; a stubbed Ψ makes it exact."""
    eps = episodes("iid", count=4, steps=10)
    pre = prereg(eps, n_boot=10, n_null=3)
    calls = {"i": 0}

    def fake_psi(x: np.ndarray, v: np.ndarray, vf: np.ndarray) -> float:
        k = calls["i"] % (1 + pre.n_null)  # per statistic: 1 observed, then n_null surrogates
        calls["i"] += 1
        return 1.0 if k == 0 else 0.9

    monkeypatch.setattr("esp.hive.audit.psi", fake_psi)
    r = emergence_test(pre, pre.digest(), T.KNO, eps, mean)
    assert r.psi == 1.0
    assert r.psi_null_mean == pytest.approx(0.9)
    assert r.lower_bound == pytest.approx(0.1)
