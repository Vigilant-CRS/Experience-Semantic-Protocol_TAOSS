# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-004 acceptance tests (plan sections 8-11)."""

import math
import uuid

import pytest
from pydantic import ValidationError

from esp.core.provenance import AffectScope, Provenance, SourceKind
from esp.semantics.affect import AffectiveDescriptor, CategoryEstimate, DimensionValue
from esp.semantics.episode import AffectTrace, EmotionEpisode, TracePoint
from esp.semantics.intention import ActionReadiness, CommittedIntention, IntentionState
from esp.semantics.scope import AffectScopeError, check_scope_profile
from esp.semantics.self_report import Construct, SelfReport, SelfReportItem
from tests.unit.semantics.helpers import ANNOTATOR, MODEL, NOW, SELF, VOCAB


def descriptor(
    cats: dict[str, float], *, scope: AffectScope = AffectScope.SELF_DECLARED, **kw: object
) -> AffectiveDescriptor:
    provenance = {
        AffectScope.SELF_DECLARED: SELF,
        AffectScope.INFERRED_SUBJECT: MODEL,
        AffectScope.CONTENT: ANNOTATOR,
    }[scope]
    data: dict[str, object] = {
        "vocabulary_id": VOCAB,
        "affect_scope": scope,
        "provenance": provenance,
        "categories": tuple(CategoryEstimate(label=k, intensity=v) for k, v in cats.items()),
    }
    data.update(kw)
    return AffectiveDescriptor.model_validate(data)


# --- critical test: absolute intensity survives -----------------------------


def test_same_mix_different_absolute_intensity_stays_distinct() -> None:
    a = descriptor({"fear": 0.8, "sadness": 0.7, "tenderness": 0.6})
    b = descriptor({"fear": 0.2, "sadness": 0.175, "tenderness": 0.15})
    a2 = AffectiveDescriptor.from_json(a.canonical_json())
    b2 = AffectiveDescriptor.from_json(b.canonical_json())
    assert a2 == a
    assert b2 == b
    assert a2 != b2
    assert a2.canonical_json() != b2.canonical_json()
    # ... while their derived relative composition is the same:
    ca, cb = a2.composition(), b2.composition()
    assert ca.keys() == cb.keys()
    for k in ca:
        assert math.isclose(ca[k], cb[k], rel_tol=1e-12)


# --- mixed emotions, no normalization ---------------------------------------


@pytest.mark.parametrize(
    "cats",
    [
        {"joy": 0.9, "sadness": 0.9},
        {"love": 0.95, "fear": 0.9},
        {"relief": 0.8, "grief": 0.85},
        {"anger": 0.9, "attachment": 0.8},
        {"fear": 0.9, "sadness": 0.8, "anger": 0.7},
    ],
)
def test_mixed_emotions_preserved_without_sum_constraint(cats: dict[str, float]) -> None:
    d = AffectiveDescriptor.from_json(descriptor(cats).canonical_json())
    assert {c.label: c.intensity for c in d.categories} == cats
    assert sum(c.intensity for c in d.categories) > 1.0
    assert set(d.active_categories(0.7)) == {k for k, v in cats.items() if v >= 0.7}


def test_categories_canonically_sorted_and_unique() -> None:
    d1 = descriptor({"sadness": 0.2, "fear": 0.5})
    d2 = descriptor({"fear": 0.5, "sadness": 0.2})
    assert d1 == d2
    assert [c.label for c in d1.categories] == ["fear", "sadness"]
    with pytest.raises(ValidationError, match="unique"):
        AffectiveDescriptor(
            vocabulary_id=VOCAB,
            affect_scope=AffectScope.SELF_DECLARED,
            provenance=SELF,
            categories=(
                CategoryEstimate(label="fear", intensity=0.1),
                CategoryEstimate(label="fear", intensity=0.2),
            ),
        )


def test_composition_is_derived_and_empty_for_zero() -> None:
    assert descriptor({"fear": 0.0, "joy": 0.0}).composition() == {}
    assert "composition" not in descriptor({"fear": 0.5}).model_dump()


def test_four_quantities_kept_apart() -> None:
    c = CategoryEstimate(
        label="fear", intensity=0.9, confidence=0.42, model_probability=0.67, anchor_similarity=-0.1
    )
    assert (c.intensity, c.confidence, c.model_probability, c.anchor_similarity) == (
        0.9,
        0.42,
        0.67,
        -0.1,
    )


# --- V13 default dimensions + addendum dimensions ---------------------------


def test_v13_dimensions_ranges() -> None:
    d = descriptor({}, valence=-1.0, arousal=0.0, intensity=1.0)
    assert (d.valence, d.arousal, d.intensity) == (-1.0, 0.0, 1.0)
    for field, bad in (("valence", 1.1), ("arousal", -0.1), ("intensity", 1.5)):
        with pytest.raises(ValidationError):
            descriptor({}, **{field: bad})


def test_additional_dimensions_are_declared_and_bounded() -> None:
    dom = DimensionValue(name="dominance", value=0.3, minimum=-1.0, maximum=1.0)
    d = descriptor({}, additional_dimensions=(dom,))
    assert d.additional_dimensions == (dom,)
    with pytest.raises(ValidationError, match="outside declared"):
        DimensionValue(name="agency", value=2.0, minimum=0.0, maximum=1.0)
    with pytest.raises(ValidationError, match="V13 default fields"):
        descriptor(
            {},
            additional_dimensions=(
                DimensionValue(name="valence", value=0.0, minimum=-1, maximum=1),
            ),
        )


# --- affect scope (plan section 4.5) ----------------------------------------


def test_scope_must_match_source() -> None:
    with pytest.raises(ValidationError, match="self_declared affect requires"):
        AffectiveDescriptor(
            vocabulary_id=VOCAB, affect_scope=AffectScope.SELF_DECLARED, provenance=MODEL
        )
    content = descriptor({"sadness": 0.6}, scope=AffectScope.CONTENT)
    assert content.affect_scope is AffectScope.CONTENT


def test_subject_affect_forbidden_on_l1_profile() -> None:
    check_scope_profile(AffectScope.CONTENT, 0x01)
    check_scope_profile(AffectScope.SELF_DECLARED, 0x01)
    check_scope_profile(AffectScope.INFERRED_SUBJECT, 0x02)
    for scope in (AffectScope.INFERRED_SUBJECT, AffectScope.MACHINE_RELAY):
        with pytest.raises(AffectScopeError, match="requires profile"):
            check_scope_profile(scope, 0x01)


def test_machine_relay_requires_human_origin_reference() -> None:
    relay_without_ref = Provenance(source_kind=SourceKind.HUMAN_ANNOTATION)
    with pytest.raises(ValidationError, match="machine_relay"):
        AffectiveDescriptor(
            vocabulary_id=VOCAB,
            affect_scope=AffectScope.MACHINE_RELAY,
            provenance=relay_without_ref,
        )


# --- action readiness != committed intention --------------------------------


def test_action_readiness_is_not_committed_intention() -> None:
    state = IntentionState(
        provenance=SELF,
        readiness=(ActionReadiness(tendency="avoid", intensity=0.95),),
        commitments=(),
    )
    again = IntentionState.from_json(state.canonical_json())
    assert again.readiness[0].intensity == 0.95
    assert again.commitments == ()
    assert "commitment" not in ActionReadiness.model_fields
    assert "intensity" not in CommittedIntention.model_fields


# --- self reports ------------------------------------------------------------


def wizard_report() -> SelfReport:
    return SelfReport(
        id=uuid.uuid4(),
        instrument="esp-wizard-of-oz-likert5",
        vocabulary_id=VOCAB,
        timestamp=NOW,
        items=(
            SelfReportItem(
                kind=Construct.EMOTION_CATEGORY, label="fear", raw=4, scale_min=1, scale_max=5
            ),
            SelfReportItem(
                kind=Construct.EMOTION_CATEGORY, label="sadness", raw=2, scale_min=1, scale_max=5
            ),
            SelfReportItem(
                kind=Construct.ACTION_READINESS, label="avoid", raw=5, scale_min=1, scale_max=5
            ),
            SelfReportItem(kind=Construct.VALENCE, raw=1, scale_min=1, scale_max=5),
        ),
    )


def test_wizard_of_oz_report_maps_linearly_and_keeps_raw() -> None:
    report = wizard_report()
    d = report.to_affective_descriptor()
    assert d.affect_scope is AffectScope.SELF_DECLARED
    assert d.provenance.source_kind is SourceKind.SELF_REPORT
    assert {c.label: c.intensity for c in d.categories} == {"fear": 0.75, "sadness": 0.25}
    assert d.valence == -1.0
    intent = report.to_intention_state()
    assert intent.readiness[0].tendency == "avoid"
    assert intent.readiness[0].intensity == 1.0
    assert SelfReport.from_json(report.canonical_json()).items[0].raw == 4


def test_self_report_item_validation() -> None:
    with pytest.raises(ValidationError, match="outside scale"):
        SelfReportItem(kind=Construct.AROUSAL, raw=6, scale_min=1, scale_max=5)
    with pytest.raises(ValidationError, match="label is required"):
        SelfReportItem(kind=Construct.EMOTION_CATEGORY, raw=3, scale_min=1, scale_max=5)
    with pytest.raises(ValidationError, match="label is not allowed"):
        SelfReportItem(kind=Construct.AROUSAL, label="x", raw=3, scale_min=1, scale_max=5)


# --- episodes & traces -------------------------------------------------------


def test_episode_ordering_and_rise_time() -> None:
    ep = EmotionEpisode(
        id=uuid.uuid4(), label="fear", onset_ns=0, peak_ns=250_000_000, end_ns=10**9
    )
    assert ep.rise_time_ms == 250.0
    with pytest.raises(ValidationError, match="peak must not precede onset"):
        EmotionEpisode(id=uuid.uuid4(), onset_ns=10, peak_ns=5)
    with pytest.raises(ValidationError, match="end must not precede peak"):
        EmotionEpisode(id=uuid.uuid4(), onset_ns=0, peak_ns=10, end_ns=5)


def test_trace_requires_strictly_increasing_time() -> None:
    AffectTrace(
        quantity="fear", points=(TracePoint(t_ns=1, value=0.1), TracePoint(t_ns=2, value=0.3))
    )
    with pytest.raises(ValidationError, match="strictly increase"):
        AffectTrace(
            quantity="fear", points=(TracePoint(t_ns=2, value=0.1), TracePoint(t_ns=2, value=0.3))
        )


def test_synthetic_ground_truth_scope_rules() -> None:
    synthetic = Provenance(source_kind=SourceKind.SYNTHETIC_GROUND_TRUTH)
    for scope in (AffectScope.SELF_DECLARED, AffectScope.CONTENT):
        AffectiveDescriptor(vocabulary_id=VOCAB, affect_scope=scope, provenance=synthetic)
    with pytest.raises(ValidationError, match="synthetic ground truth may only"):
        AffectiveDescriptor(
            vocabulary_id=VOCAB,
            affect_scope=AffectScope.MACHINE_RELAY,
            provenance=synthetic.model_validate(synthetic.model_dump() | {"source_refs": ("x",)}),
        )
    with pytest.raises(ValidationError, match="synthetic ground truth may only"):
        AffectiveDescriptor(
            vocabulary_id=VOCAB, affect_scope=AffectScope.INFERRED_SUBJECT, provenance=synthetic
        )
