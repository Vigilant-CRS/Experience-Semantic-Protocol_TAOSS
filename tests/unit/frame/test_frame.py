# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-011 acceptance tests and the WP-005 protocol-object privacy test."""

import json
from pathlib import Path

import jsonschema
import numpy as np
import pytest
from pydantic import ValidationError

from esp.core.provenance import AffectScope, Provenance, SourceKind
from esp.core.taoss_types import TaossType
from esp.frame.model import DisclosurePolicy, ExperienceFrame, TypeBlock
from esp.semantics.affect import AffectiveDescriptor, CategoryEstimate
from esp.semantics.bindings import BindingPolicy, RelationClass
from tests.unit.frame.factory import BINDING, full_frame

SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"
T = TaossType


def test_canonical_serialization_roundtrip_and_determinism() -> None:
    frame = full_frame()
    raw = frame.canonical_json()
    again = ExperienceFrame.from_json(raw)
    assert again == frame
    assert again.canonical_json() == raw
    assert full_frame().canonical_json() == raw  # deterministic construction
    shuffled = ExperienceFrame.model_validate(
        frame.model_dump() | {"types": tuple(reversed(frame.types))}
    )
    assert shuffled.canonical_json() == raw


def test_json_schema_validation() -> None:
    schema = json.loads((SCHEMAS / "experience_frame.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(json.loads(full_frame().canonical_json()))
    broken = json.loads(full_frame().canonical_json())
    broken["types"][0]["type"] = 0
    assert list(validator.iter_errors(broken))


def test_missing_type_handling_absence_is_not_zero() -> None:
    frame = full_frame().disclose(DisclosurePolicy(allowed_types=(T.KNO, T.CTX)))
    assert frame.block(T.EMO) is None
    with pytest.raises(ValueError, match=r"INT latent is absent \(⊥\)"):
        frame.latent_vector()
    zeros = ExperienceFrame.model_validate(
        frame.model_dump()
        | {
            "masked_types": (),
            "types": (*frame.types, TypeBlock(type=T.EMO, latent=(0.0,) * 64)),
        }
    )
    assert zeros.block(T.EMO) is not None
    assert zeros.block(T.EMO).latent == (0.0,) * 64  # type: ignore[union-attr]


def test_full_latent_vector() -> None:
    v = full_frame().latent_vector()
    assert v.shape == (512,)
    assert np.all(np.isfinite(v))


def test_masked_type_omission() -> None:
    frame = full_frame()
    emo_latent = frame.block(T.EMO).latent  # type: ignore[union-attr]
    assert emo_latent is not None
    disclosed = frame.disclose(DisclosurePolicy(allowed_types=(T.KNO, T.INT, T.CTX)))
    assert disclosed.present_types == (T.KNO, T.INT, T.CTX)
    assert disclosed.masked_types == (T.EMO, T.SEN, T.TEM)
    raw = disclosed.canonical_json()
    for x in emo_latent[:8]:
        assert json.dumps(x).encode() not in raw
    for marker in (b"fear", b"sadness", b"esp:emo:", b"affect_scope", b"emotion_episode"):
        assert marker not in raw
    assert b"obs_eda_441" not in raw  # evidence refs dropped by default


def test_critical_share_emotion_without_its_cause() -> None:
    """Protocol-object form of the WP-005 critical privacy test."""
    frame = full_frame()
    # Recipient may see EMO and even KNO, but the elicited_by binding is not permitted.
    disclosed = frame.disclose(DisclosurePolicy(allowed_types=(T.KNO, T.EMO)))
    raw = disclosed.canonical_json()
    assert disclosed.block(T.EMO) is not None
    assert disclosed.bindings == ()
    for marker in (str(BINDING).encode(), b"elicited_by", b"possible_dismissal"):
        assert marker not in raw
    # KNO withheld: even an explicitly permitted binding must not appear.
    emo_only = frame.disclose(
        DisclosurePolicy(
            allowed_types=(T.EMO,),
            bindings=BindingPolicy(allowed_relations=(RelationClass.ELICITED_BY,)),
        )
    )
    assert emo_only.bindings == ()
    assert b"possible_dismissal" not in emo_only.canonical_json()
    # Only when both endpoints and the binding are permitted does it appear.
    full = frame.disclose(
        DisclosurePolicy(
            allowed_types=(T.KNO, T.EMO), bindings=BindingPolicy(allowed_binding_ids=(BINDING,))
        )
    )
    assert [b.binding_id for b in full.bindings] == [BINDING]


def test_default_policy_discloses_nothing() -> None:
    disclosed = full_frame().disclose(DisclosurePolicy())
    assert disclosed.types == ()
    assert disclosed.masked_types == tuple(TaossType)


def test_frame_rules() -> None:
    frame = full_frame()
    with pytest.raises(ValidationError, match="at most once"):
        ExperienceFrame.model_validate(
            frame.model_dump() | {"types": (*frame.types, frame.types[0])}
        )
    with pytest.raises(ValidationError, match="both present and masked"):
        ExperienceFrame.model_validate(frame.model_dump() | {"masked_types": (T.EMO,)})
    short_ctx = TypeBlock(type=T.CTX, latent=(0.0,) * 63)
    with pytest.raises(ValidationError, match="must have 64 dims"):
        ExperienceFrame.model_validate(frame.model_dump() | {"types": (short_ctx,), "bindings": ()})
    with pytest.raises(ValidationError, match="not present"):
        ExperienceFrame.model_validate(frame.model_dump() | {"types": (frame.types[2],)})


def test_block_rules() -> None:
    with pytest.raises(ValidationError, match="no content"):
        TypeBlock(type=T.KNO)
    with pytest.raises(ValidationError, match="only allowed in the EMO block"):
        TypeBlock(type=T.CTX, affect=full_frame().block(T.EMO).affect)  # type: ignore[union-attr]
    with pytest.raises(ValidationError, match="require anchor_set_id"):
        TypeBlock.model_validate(
            full_frame().block(T.EMO).model_dump() | {"anchor_set_id": None}  # type: ignore[union-attr]
        )


def test_inferred_subject_affect_rejected_in_l1_frame() -> None:
    inferred = AffectiveDescriptor(
        vocabulary_id="esp-emo-v13-basic8-v1",
        affect_scope=AffectScope.INFERRED_SUBJECT,
        provenance=Provenance(
            source_kind=SourceKind.MODEL_INFERENCE,
            producer_id="esp-emo-fusion",
            producer_version="0.1.0",
            source_refs=("obs_eda_441",),
        ),
        categories=(CategoryEstimate(label="fear", intensity=0.7),),
    )
    frame = full_frame(with_binding=False)
    emo = TypeBlock(type=T.EMO, latent=(0.0,) * 64, affect=(inferred,))
    others = tuple(b for b in frame.types if b.type is not T.EMO)
    with pytest.raises(ValidationError, match="requires profile >= 0x02"):
        ExperienceFrame.model_validate(frame.model_dump() | {"types": (*others, emo)})
    l2 = ExperienceFrame.model_validate(
        frame.model_dump() | {"types": (*others, emo), "profile": 2}
    )
    assert l2.profile == 2
