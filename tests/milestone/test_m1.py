# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M1 gate: psychologically sound, serializable ExperienceFrame model.

Gate tests (plan section 54, M1):
1. Mixed emotion  2. Intensity preservation  3. Confidence/intensity separation
4. Observation/inference separation  5. Binding masking  6. Legacy movie mapping
7. TAOSS block invariants
Demo: self report -> ExperienceFrame -> JSON -> ExperienceFrame, lossless.
"""

import itertools
import uuid
from pathlib import Path

import numpy as np
import pytest
from pydantic import ValidationError

from esp.adapters.legacy_movie.ontology import (
    VOCABULARY_ID,
    LegacyOntologyError,
    LegacyRetrievalWeights,
    load_legacy_ontology,
    to_registry,
)
from esp.core.provenance import AffectScope
from esp.core.taoss_types import TaossType
from esp.evidence.claim import ClaimType, EvidenceClaim
from esp.frame.model import DisclosurePolicy, ExperienceFrame
from esp.observation.model import Observation
from esp.semantics.affect import AffectiveDescriptor, CategoryEstimate
from esp.taoss.blocks import TAOSS6_L1
from tests.unit.frame.factory import BINDING, STAMP, full_frame, self_report
from tests.unit.semantics.helpers import MODEL, SELF, VOCAB

pytestmark = pytest.mark.milestone
T = TaossType
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_movie_minimal"


def _descriptor(cats: dict[str, float]) -> AffectiveDescriptor:
    return AffectiveDescriptor(
        vocabulary_id=VOCAB,
        affect_scope=AffectScope.SELF_DECLARED,
        provenance=SELF,
        categories=tuple(CategoryEstimate(label=k, intensity=v) for k, v in cats.items()),
    )


def test_gate1_mixed_emotion() -> None:
    d = AffectiveDescriptor.from_json(_descriptor({"joy": 0.9, "sadness": 0.9}).canonical_json())
    assert set(d.active_categories(0.85)) == {"joy", "sadness"}


def test_gate2_intensity_preservation() -> None:
    a = _descriptor({"fear": 0.8, "sadness": 0.7, "tenderness": 0.6})
    b = _descriptor({"fear": 0.2, "sadness": 0.175, "tenderness": 0.15})
    assert AffectiveDescriptor.from_json(a.canonical_json()) != AffectiveDescriptor.from_json(
        b.canonical_json()
    )


def test_gate3_confidence_intensity_separation() -> None:
    c = EvidenceClaim(
        id=uuid.uuid4(),
        claim_type=ClaimType.EMOTION_CATEGORY,
        claim="fear",
        value=0.9,
        confidence=0.4,
        affect_scope=AffectScope.INFERRED_SUBJECT,
        provenance=MODEL,
        timestamp=STAMP,
    )
    again = EvidenceClaim.from_json(c.canonical_json())
    assert (again.value, again.confidence) == (0.9, 0.4)


def test_gate4_observation_inference_separation() -> None:
    assert not {"affect", "intensity", "confidence", "label"} & set(Observation.model_fields)
    with pytest.raises(ValidationError, match="requires an inferential source"):
        EvidenceClaim.from_data(
            {
                "id": str(uuid.uuid4()),
                "claim_type": "emotion_category",
                "claim": "fear",
                "value": 0.75,
                "confidence": 0.5,
                "affect_scope": "inferred_subject",
                "provenance": {"source_kind": "sensor_observation"},
                "timestamp": STAMP.model_dump(mode="json"),
            }
        )


def test_gate5_binding_masking() -> None:
    disclosed = full_frame().disclose(DisclosurePolicy(allowed_types=(T.KNO, T.EMO)))
    raw = disclosed.canonical_json()
    assert disclosed.block(T.EMO) is not None
    assert str(BINDING).encode() not in raw
    assert b"possible_dismissal" not in raw


def test_gate6_legacy_movie_mapping() -> None:
    registry, _ = to_registry(load_legacy_ontology(FIXTURE))
    assert registry.resolve_label(VOCABULARY_ID, "fear").id == "esp:emo:movie3-fear:v1"
    with pytest.raises(LegacyOntologyError):
        LegacyRetrievalWeights({"fear": 1.0}).to_category_intensities()


def test_gate7_taoss_block_invariants() -> None:
    p = {t: TAOSS6_L1.projection(t) for t in TAOSS6_L1.types}
    for s, t in itertools.permutations(TAOSS6_L1.types, 2):
        assert not np.any(p[s] @ p[t])
    assert np.array_equal(sum(p.values()), np.eye(512))
    x = np.random.default_rng(1).normal(size=512)
    assert np.array_equal(TAOSS6_L1.compose(TAOSS6_L1.split(x)), x)


def test_demo_self_report_to_frame_to_json_and_back() -> None:
    report = self_report()
    frame = full_frame()
    emo = frame.block(T.EMO)
    assert emo is not None
    assert emo.affect == (report.to_affective_descriptor(),)
    raw = frame.canonical_json()
    again = ExperienceFrame.from_json(raw)
    assert again == frame
    assert again.canonical_json() == raw
    restored = again.block(T.EMO)
    assert restored is not None
    fear = restored.affect[0].category("fear")
    assert fear is not None
    assert fear.intensity == 0.75
    assert restored.affect[0].affect_scope is AffectScope.SELF_DECLARED
