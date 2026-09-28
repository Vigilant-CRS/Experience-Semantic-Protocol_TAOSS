# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-013 acceptance tests."""

import uuid
from pathlib import Path

import pytest

from esp.calibration.model import CalibrationProfile, ChannelBaseline
from esp.core.provenance import AffectScope, SourceKind
from esp.estimators.base import EstimationContext, StateEstimator
from esp.estimators.fusion import ConfidenceWeightedFusion
from esp.estimators.oracle import OracleEstimator
from esp.estimators.rule_based import ActivationRule, RuleBasedEstimator
from esp.evidence.claim import ClaimType, EvidenceClaim
from esp.observation.model import Modality
from esp.semantics.scope import AffectScopeError
from esp.simulation.engine import simulate
from esp.simulation.spec import load_episode_yaml
from tests.unit.semantics.helpers import MODEL, NOW, SELF

EXAMPLE = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "synthetic_sender_receiver"
    / "fear_at_work.yaml"
)


@pytest.fixture(scope="module")
def episode():  # type: ignore[no-untyped-def]
    return simulate(load_episode_yaml(EXAMPLE))


def test_oracle_reproduces_ground_truth_exactly(episode) -> None:  # type: ignore[no-untyped-def]
    oracle = OracleEstimator(episode)
    assert isinstance(oracle, StateEstimator)
    for point in episode.ground_truth:
        est = oracle.estimate(episode.observations, EstimationContext(at_ns=point.t_ns))
        got = {}
        for c in est.claims:
            key = c.claim if c.claim_type is ClaimType.AFFECT_DIMENSION else None
            prefix = {
                ClaimType.EMOTION_CATEGORY: "emotion.",
                ClaimType.ACTION_READINESS: "readiness.",
                ClaimType.CONTEXT: "context.",
            }.get(c.claim_type, "")
            got[key or prefix + c.claim] = c.value
            assert c.confidence == 1.0
            assert c.provenance.source_kind is SourceKind.SYNTHETIC_GROUND_TRUTH
        assert got == dict(point.values)  # exact equality, no tolerance


def test_oracle_is_deterministic(episode) -> None:  # type: ignore[no-untyped-def]
    ctx = EstimationContext(at_ns=2_500_000_000)
    a = OracleEstimator(episode).estimate((), ctx)
    b = OracleEstimator(simulate(episode.spec)).estimate((), ctx)
    assert a.canonical_json() == b.canonical_json()


def test_oracle_affect_is_simulated_self_report(episode) -> None:  # type: ignore[no-untyped-def]
    est = OracleEstimator(episode).estimate((), EstimationContext(at_ns=0))
    affect = [c for c in est.claims if c.affect_scope is not None]
    assert affect
    assert all(c.affect_scope is AffectScope.SELF_DECLARED for c in affect)


def calibration() -> CalibrationProfile:
    return CalibrationProfile(
        id=uuid.uuid4(),
        subject_id="subj-sim00001",
        version=1,
        created_at_ns=0,
        valid_from_ns=0,
        valid_until_ns=10**12,
        baselines=(
            ChannelBaseline.from_samples(
                Modality.ECG, "heart_rate", "bpm", [66.0, 68.0, 70.0, 72.0, 74.0]
            ),
        ),
        model_version="0.1.0",
    )


def test_rule_based_produces_derived_features_not_emotions(episode) -> None:  # type: ignore[no-untyped-def]
    rule = ActivationRule(
        Modality.ECG,
        "heart_rate",
        "physiological-activation-hr",
        window_ns=2 * 10**9,
        expected_samples=8,
    )
    est = RuleBasedEstimator([rule], calibration())
    low = est.estimate(episode.observations, EstimationContext(at_ns=int(1.9e9)))
    high = est.estimate(episode.observations, EstimationContext(at_ns=int(5.9e9)))
    assert [c.claim_type for c in (*low.claims, *high.claims)] == [ClaimType.SENSORY] * 2
    assert high.claims[0].value > low.claims[0].value
    assert all(c.affect_scope is None for c in high.claims)
    assert high.claims[0].provenance.source_kind is SourceKind.DERIVED
    assert high.claims[0].provenance.source_refs  # traceable to observations


def test_rule_based_missing_modality_yields_no_claim(episode) -> None:  # type: ignore[no-untyped-def]
    rule = ActivationRule(Modality.RESPIRATION, "rate", "resp", window_ns=10**9, expected_samples=4)
    est = RuleBasedEstimator([rule], calibration())
    assert est.estimate(episode.observations, EstimationContext(at_ns=int(5e9))).claims == ()


def _claim(value: float, confidence: float, provenance, scope: AffectScope) -> EvidenceClaim:  # type: ignore[no-untyped-def]
    return EvidenceClaim(
        id=uuid.uuid4(),
        claim_type=ClaimType.EMOTION_CATEGORY,
        claim="fear",
        value=value,
        confidence=confidence,
        affect_scope=scope,
        provenance=provenance,
        timestamp=NOW,
    )


def test_fusion_keeps_inputs_and_makes_conflicts_visible() -> None:
    report = _claim(0.8, 0.9, SELF, AffectScope.SELF_DECLARED)
    voice = _claim(0.6, 0.6, MODEL, AffectScope.INFERRED_SUBJECT)
    physio = _claim(0.3, 0.4, MODEL, AffectScope.INFERRED_SUBJECT)
    result = ConfidenceWeightedFusion().fuse(
        [report, voice, physio], EstimationContext(at_ns=1, profile=2)
    )
    assert result.inputs == (report, voice, physio)  # self report never overwritten
    assert len(result.conflicts) == 1
    assert result.conflicts[0].spread == pytest.approx(0.5)
    fused = result.fused[0]
    assert fused.affect_scope is AffectScope.INFERRED_SUBJECT
    assert set(fused.provenance.source_refs) == {str(report.id), str(voice.id), str(physio.id)}


def test_fused_affect_forbidden_on_l1() -> None:
    a = _claim(0.8, 0.9, SELF, AffectScope.SELF_DECLARED)
    b = _claim(0.7, 0.5, MODEL, AffectScope.INFERRED_SUBJECT)
    with pytest.raises(AffectScopeError, match="requires profile"):
        ConfidenceWeightedFusion().fuse([a, b], EstimationContext(at_ns=1, profile=1))
