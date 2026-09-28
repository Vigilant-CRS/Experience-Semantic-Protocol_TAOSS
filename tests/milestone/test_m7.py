# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M7 gate: multimodal inference baseline on synthetic and replayed data.

The gate conditions (missing sensor, conflicting evidence, poor signal
quality, calibration differences) are covered in
``tests/unit/estimators/test_multimodal.py``. Here the whole chain runs on
data: signal -> features (WP-028) -> personal calibration (WP-029) ->
multimodal estimate (WP-030), at L1 (no subject affect) and under an L2
authorization (WP-081). No psychological validity is claimed.
"""

import re
from pathlib import Path

import numpy as np
import pytest

from esp.calibration.pipeline import BaselineCollector, CalibrationPipeline, build_profile
from esp.core.provenance import AffectScope, SourceKind
from esp.estimators.base import EstimationContext
from esp.estimators.multimodal import MultimodalBaseline, MultimodalInputs
from esp.features.physio import eda_features, heart_rate, windows
from tests.unit.estimators.test_multimodal import AUTH
from tests.unit.features.test_physio_features import ecg

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "external" / "physionet-wearable-stress-s01"


def test_m7_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-030", "WP-081"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


def chain(hr_windows: list[float], baseline_n: int, at_l2: bool) -> list:  # type: ignore[type-arg]
    collector = BaselineCollector("hr", "bpm", min_samples=baseline_n)
    feats = [
        next(f for f in heart_rate(w, 250.0, 0) if f.name == "hr")  # type: ignore[arg-type]
        for w in hr_windows
    ]
    collector.extend(feats[:baseline_n])
    pipe = CalibrationPipeline(
        build_profile("subj-synthetic1", [collector.finish()], created_at_ns=0, valid_for_ns=10**15)
    )
    ctx = EstimationContext(at_ns=10**9, profile=0x02 if at_l2 else 0x01)
    out = []
    for f in feats[baseline_n:]:
        sf = pipe.standardize(f, device_id="dev", at_ns=1)
        out.append(
            MultimodalBaseline().run(
                MultimodalInputs(physiology=((sf, f.quality),)), ctx, AUTH if at_l2 else None
            )
        )
    return out


def test_synthetic_chain_l1_and_l2() -> None:
    calm = [ecg([0.95 + 0.02 * np.sin(k)] * 25, seed=k) for k in range(8)]
    active = [ecg([0.6] * 25, seed=100 + k) for k in range(3)]
    l1 = chain(calm + active, 8, at_l2=False)
    assert all(not e.inferred_affect_allowed for e in l1)
    assert all(c.affect_scope is None for e in l1 for c in e.estimate.claims)
    act = [e.estimate.claims[0].value for e in l1]
    assert min(act) > 0.9  # 100 bpm vs a ~63 bpm personal baseline
    l2 = chain(calm + active, 8, at_l2=True)
    inferred = [
        c for e in l2 for c in e.estimate.claims if c.affect_scope is AffectScope.INFERRED_SUBJECT
    ]
    assert len(inferred) == 3
    assert all(c.provenance.source_kind is SourceKind.MODEL_INFERENCE for c in inferred)
    assert (
        chain(calm + active, 8, at_l2=False)[0].estimate.claims[0].value == act[0]
    )  # deterministic


@pytest.mark.dataset
@pytest.mark.skipif(not DATA.exists(), reason="run scripts/fetch_datasets.py")
def test_replay_chain_on_real_wearable_data() -> None:
    from esp.adapters.physio.files import read_empatica  # noqa: PLC0415

    rec = read_empatica(DATA)
    eda = rec.block("eda")
    fs = eda.nominal_rate_hz or 4.0
    feats = [
        next(
            f
            for f in eda_features(eda.values[a:b, 0], fs, int(eda.timestamps_ns[a]))
            if f.name == "eda_scl"
        )
        for a, b in windows(eda.n_samples, fs, 60.0, 60.0)
    ]
    collector = BaselineCollector("eda_scl", "uS", min_samples=5)
    collector.extend(feats[:5])  # first five minutes: baseline phase of the protocol
    pipe = CalibrationPipeline(
        build_profile("subj-physionet01", [collector.finish()], created_at_ns=0, valid_for_ns=2**63)
    )
    ctx = EstimationContext(at_ns=int(eda.timestamps_ns[-1]), profile=0x01)
    results = []
    for f in feats[5:]:
        sf = pipe.standardize(f, device_id="e4", at_ns=1)
        results.append(
            MultimodalBaseline().run(MultimodalInputs(physiology=((sf, f.quality),)), ctx)
        )
    assert len(results) >= 20
    assert all(set(r.missing) >= {"voice", "text", "self_report"} for r in results)
    assert all(
        c.affect_scope is None for r in results for c in r.estimate.claims
    )  # L1: features only
    values = [r.estimate.claims[0].value for r in results if r.estimate.claims]
    assert all(-1.0 <= v <= 1.0 for v in values)
    assert np.std(values) > 0.05  # the replayed session is not flat
