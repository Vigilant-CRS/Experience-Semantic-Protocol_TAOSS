# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-003 acceptance tests."""

import uuid

import pytest
from pydantic import ValidationError

from esp.core.provenance import AffectScope, Provenance, SourceKind
from esp.evidence.claim import ClaimType, EvidenceClaim
from tests.unit.semantics.helpers import MODEL, NOW, SELF


def claim(**overrides: object) -> EvidenceClaim:
    data: dict[str, object] = {
        "id": uuid.uuid4(),
        "claim_type": ClaimType.EMOTION_CATEGORY,
        "claim": "fear",
        "value": 0.9,
        "confidence": 0.4,
        "affect_scope": AffectScope.INFERRED_SUBJECT,
        "provenance": MODEL,
        "timestamp": NOW,
    }
    data.update(overrides)
    return EvidenceClaim.model_validate(data)


def test_golden_fear_intensity_09_confidence_04_roundtrips_losslessly() -> None:
    c = claim(value=0.9, confidence=0.4, model_probability=0.67)
    raw = c.canonical_json()
    again = EvidenceClaim.from_json(raw)
    assert again == c
    assert (again.value, again.confidence, again.model_probability) == (0.9, 0.4, 0.67)
    assert again.canonical_json() == raw
    assert b'"value":0.9' in raw
    assert b'"confidence":0.4' in raw
    assert b'"model_probability":0.67' in raw


def test_no_inference_without_provenance() -> None:
    with pytest.raises(ValidationError, match="requires producer_id"):
        claim(
            provenance=Provenance.from_data(
                {"source_kind": "model_inference", "source_refs": ["obs_1"]}
            )
        )


@pytest.mark.parametrize(
    ("value", "confidence", "probability"),
    [(0.9, 0.1, 0.2), (0.1, 0.99, 0.95), (1.0, 0.0, None), (0.0, 1.0, 1.0)],
)
def test_confidence_and_probability_independent_of_intensity(
    value: float, confidence: float, probability: float | None
) -> None:
    c = claim(value=value, confidence=confidence, model_probability=probability)
    assert (c.value, c.confidence, c.model_probability) == (value, confidence, probability)


def test_intensity_claims_are_unit_valued_but_dimensions_signed() -> None:
    with pytest.raises(ValidationError, match=r"must lie in \[0, 1\]"):
        claim(value=-0.2)
    valence = claim(claim_type=ClaimType.AFFECT_DIMENSION, claim="valence", value=-0.6)
    assert valence.value == -0.6


def test_affect_claims_require_scope_and_others_forbid_it() -> None:
    with pytest.raises(ValidationError, match="require affect_scope"):
        claim(affect_scope=None)
    with pytest.raises(ValidationError, match="only allowed on affect claims"):
        claim(claim_type=ClaimType.CONTEXT, claim="meeting", value=0.8)
    ctx = claim(claim_type=ClaimType.CONTEXT, claim="meeting", value=0.8, affect_scope=None)
    assert ctx.affect_scope is None


def test_self_report_is_its_own_source() -> None:
    c = claim(affect_scope=AffectScope.SELF_DECLARED, provenance=SELF)
    assert c.provenance.source_kind is SourceKind.SELF_REPORT
    with pytest.raises(ValidationError, match="self_declared affect requires"):
        claim(affect_scope=AffectScope.SELF_DECLARED, provenance=MODEL)
    with pytest.raises(ValidationError, match="a self report is self_declared"):
        claim(affect_scope=AffectScope.INFERRED_SUBJECT, provenance=SELF)


def test_inferred_subject_requires_inference() -> None:
    sensor = Provenance(source_kind=SourceKind.SENSOR_OBSERVATION)
    with pytest.raises(ValidationError, match="requires an inferential source"):
        claim(affect_scope=AffectScope.INFERRED_SUBJECT, provenance=sensor)
