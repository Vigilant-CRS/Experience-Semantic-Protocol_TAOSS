# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-030 multimodal baseline and WP-081 L2 subject-affect gate (M7 gate conditions)."""

import uuid

import numpy as np
import pytest

from esp.calibration.pipeline import BaselineCollector, CalibrationPipeline, build_profile
from esp.core.clock import ClockStamp
from esp.core.provenance import AffectScope, SourceKind
from esp.estimators.base import EstimationContext
from esp.estimators.confidence import IsotonicCalibrator, expected_calibration_error
from esp.estimators.multimodal import (
    L2Authorization,
    MultimodalBaseline,
    MultimodalInputs,
    SignalInput,
)
from esp.evidence.claim import ClaimType
from esp.features.physio import FeatureValue
from esp.observation.model import Modality
from esp.regulatory.guard import (
    DeploymentContext,
    ProhibitedPracticeError,
    Regime,
    RegulatoryDeclaration,
)
from esp.semantics.self_report import Construct, SelfReport, SelfReportItem

L1 = EstimationContext(at_ns=10**9, profile=0x01)
L2 = EstimationContext(at_ns=10**9, profile=0x02)
STAMP = ClockStamp(source_ns=1, monotonic_ns=1, clock_domain="t", sequence=0)


def declaration(**kw: object) -> RegulatoryDeclaration:
    base: dict[str, object] = {
        "regimes": (Regime.EU_AI_ACT,),
        "intended_use": "research study with informed consent",
        "deployment_context": DeploymentContext.OTHER,
        "biometric_inputs": True,
        "affect_scopes": (AffectScope.INFERRED_SUBJECT, AffectScope.SELF_DECLARED),
        "high_risk_declared": True,
    }
    return RegulatoryDeclaration(**(base | kw))  # type: ignore[arg-type]


AUTH = L2Authorization(declaration(), consent_ref="cap:0d3e6b4a")


def report(arousal: int = 2) -> SelfReport:
    return SelfReport(
        id=uuid.UUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"),
        instrument="likert5",
        vocabulary_id="esp-emo-v13-basic8-v1",
        timestamp=STAMP,
        items=(
            SelfReportItem(kind=Construct.AROUSAL, raw=arousal, scale_min=1, scale_max=5),
            SelfReportItem(
                kind=Construct.EMOTION_CATEGORY, label="joy", raw=4, scale_min=1, scale_max=5
            ),
        ),
    )


def physio(value_bpm: float, baseline: list[float], quality: float = 1.0):  # type: ignore[no-untyped-def]
    c = BaselineCollector("hr", "bpm", min_samples=3)
    c.extend(FeatureValue("hr", v, "bpm", Modality.ECG, 0, 1, 10, 1.0) for v in baseline)
    pipe = CalibrationPipeline(
        build_profile("subj-aaaaaaaa", [c.finish()], created_at_ns=0, valid_for_ns=10**12)
    )
    f = FeatureValue("hr", value_bpm, "bpm", Modality.ECG, 0, 1, 10, quality)
    return (pipe.standardize(f, device_id="d", at_ns=1), quality)


CALM = [60.0, 61.0, 59.0, 62.0, 58.0]


def claims(est, name: str, scope=None):  # type: ignore[no-untyped-def]
    return [c for c in est.estimate.claims if c.claim == name and c.affect_scope is scope]


def test_missing_sensors_yield_no_guesses() -> None:
    est = MultimodalBaseline().run(MultimodalInputs(self_report=report()), L2, AUTH)
    assert set(est.missing) == {"voice", "physiology", "text", "context"}
    assert all(c.affect_scope is AffectScope.SELF_DECLARED for c in est.estimate.claims)
    assert est.fused == ()


def test_l1_never_infers_subject_affect() -> None:
    inputs = MultimodalInputs(
        voice=(SignalInput("pitch_z", 2.0, 1.0, "obs:1"),),
        physiology=(physio(90.0, CALM),),
        text=SignalInput("valence", -0.8, 1.0, "text:1"),
    )
    est = MultimodalBaseline().run(inputs, L1, AUTH)
    assert not est.inferred_affect_allowed
    assert all(c.claim_type is ClaimType.SENSORY for c in est.estimate.claims)
    assert any("profile L1" in n for n in est.notes)
    assert any("text valence not used" in n for n in est.notes)


@pytest.mark.parametrize(
    ("auth", "reason"),
    [
        (None, "no L2 authorization"),
        (
            L2Authorization(
                declaration(
                    affect_scopes=(AffectScope.SELF_DECLARED,),
                    biometric_inputs=False,
                    high_risk_declared=False,
                ),
                "cap:1",
            ),
            "does not cover",
        ),
        (L2Authorization(declaration(), ""), "missing L2 consent"),
    ],
)
def test_l2_requires_declaration_and_consent(auth: L2Authorization | None, reason: str) -> None:
    inputs = MultimodalInputs(physiology=(physio(90.0, CALM),))
    est = MultimodalBaseline().run(inputs, L2, auth)
    assert not est.inferred_affect_allowed
    assert any(reason in n for n in est.notes)
    assert not claims(est, "arousal", AffectScope.INFERRED_SUBJECT)


def test_prohibited_workplace_inference_stops_the_pipeline() -> None:
    bad = L2Authorization(declaration(deployment_context=DeploymentContext.WORKPLACE), "cap:1")
    with pytest.raises(ProhibitedPracticeError):
        MultimodalBaseline().run(MultimodalInputs(physiology=(physio(90.0, CALM),)), L2, bad)


def test_authorized_l2_inference_has_provenance_and_keeps_self_report() -> None:
    inputs = MultimodalInputs(
        self_report=report(arousal=1),  # self: very calm (0.0)
        physiology=(physio(95.0, CALM),),  # body: strongly activated
        voice=(SignalInput("pitch_z", 2.5, 0.9, "obs:voice"),),
        context=("meeting",),
    )
    est = MultimodalBaseline().run(inputs, L2, AUTH)
    assert est.inferred_affect_allowed
    inferred = claims(est, "arousal", AffectScope.INFERRED_SUBJECT)
    assert len(inferred) == 2
    for c in inferred:
        assert c.provenance.source_kind is SourceKind.MODEL_INFERENCE
        assert c.provenance.source_refs
    (declared,) = claims(est, "arousal", AffectScope.SELF_DECLARED)
    assert declared.value == 0.0  # never overwritten
    assert est.self_vs_inferred
    assert "self report stands" in est.self_vs_inferred[0]
    assert len(est.fused) == 1  # voice + physiology fused, as an additional derived claim


def test_conflicting_modalities_are_reported() -> None:
    inputs = MultimodalInputs(
        physiology=(physio(100.0, CALM),),  # very high activation
        voice=(SignalInput("pitch_z", -3.0, 1.0, "obs:v"),),  # very low
    )
    est = MultimodalBaseline().run(inputs, L2, AUTH)
    assert [c.claim for c in est.conflicts] == ["arousal"]


def test_poor_signal_quality_downweights_and_drops() -> None:
    mm = MultimodalBaseline(min_quality=0.3)
    good = mm.run(MultimodalInputs(physiology=(physio(80.0, CALM, 1.0),)), L1)
    weak = mm.run(MultimodalInputs(physiology=(physio(80.0, CALM, 0.5),)), L1)
    gone = mm.run(MultimodalInputs(physiology=(physio(80.0, CALM, 0.1),)), L1)
    (g,), (w,) = claims(good, "physiology_activation"), claims(weak, "physiology_activation")
    assert w.confidence == pytest.approx(g.confidence * 0.5)
    assert not claims(gone, "physiology_activation")
    assert gone.dropped_low_quality == ("physiology:hr",)


def test_calibration_differences_change_the_estimate() -> None:
    mm = MultimodalBaseline()
    calm_person = mm.run(MultimodalInputs(physiology=(physio(80.0, CALM),)), L1)
    fast_person = mm.run(
        MultimodalInputs(physiology=(physio(80.0, [79.0, 81.0, 80.0, 82.0, 78.0]),)), L1
    )
    (a,), (b,) = (
        claims(calm_person, "physiology_activation"),
        claims(fast_person, "physiology_activation"),
    )
    assert a.value > 0.9  # same 80 bpm: high for one person
    assert abs(b.value) < 0.2  # ordinary for the other


def test_isotonic_confidence_calibration_reduces_ece() -> None:
    rng = np.random.default_rng(0)
    raw = rng.uniform(0.5, 1.0, 4000)
    correct = rng.uniform(size=raw.size) < (raw - 0.4)  # overconfident source
    cal = IsotonicCalibrator.fit(raw[:2000], correct[:2000])
    test_raw, test_y = raw[2000:], correct[2000:]
    calibrated = [cal(x) for x in test_raw]
    assert expected_calibration_error(calibrated, test_y) < 0.5 * expected_calibration_error(
        test_raw, test_y
    )
    xs = np.linspace(0, 1, 50)
    ys = [cal(x) for x in xs]
    assert ys == sorted(ys)  # monotone
    mm = MultimodalBaseline(calibrators={"physiology": cal})
    (c,) = claims(
        mm.run(MultimodalInputs(physiology=(physio(80.0, CALM),)), L1), "physiology_activation"
    )
    assert c.confidence == pytest.approx(cal(0.6))


def test_low_quality_voice_is_dropped() -> None:
    est = MultimodalBaseline(min_quality=0.3).run(
        MultimodalInputs(voice=(SignalInput("pitch_z", 2.0, 0.1, "obs:v"),)), L1
    )
    assert est.dropped_low_quality == ("voice:pitch_z",)
    assert not claims(est, "voice_activation")
