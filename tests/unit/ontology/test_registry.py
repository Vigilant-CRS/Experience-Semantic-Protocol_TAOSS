# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-008 acceptance tests: duplicate ids, semantic mutation, digest, deprecation."""

import pytest
from pydantic import ValidationError

from esp.core.errors import RegistryError
from esp.core.taoss_types import TaossType
from esp.ontology.registry import (
    Anchor,
    AnchorSet,
    AnchorStatus,
    EncoderRealization,
    Registry,
    ValidityRegion,
    Vocabulary,
    check_evolution,
)

VOCAB = "test-emo-v1"


def anchor(label: str, version: int = 1, **kw: object) -> Anchor:
    data: dict[str, object] = {
        "id": f"esp:emo:{label}:v{version}",
        "type": TaossType.EMO,
        "label": label,
        "vocabulary_id": VOCAB,
        "definition": f"definition of {label}",
        "version": version,
    }
    data.update(kw)
    return Anchor.model_validate(data)


def registry(*anchors: Anchor, **kw: object) -> Registry:
    vocab = Vocabulary(
        id=VOCAB,
        type=TaossType.EMO,
        version="1.0.0",
        title="test",
        license="CC-BY-SA-4.0",
        anchors=tuple(a.id for a in anchors),
    )
    data: dict[str, object] = {
        "name": "test-registry",
        "version": "1.0.0",
        "anchors": anchors,
        "vocabularies": (vocab,),
    }
    data.update(kw)
    return Registry.model_validate(data)


def test_duplicate_ids_rejected() -> None:
    vocab = Vocabulary(
        id=VOCAB,
        type=TaossType.EMO,
        version="1.0.0",
        title="t",
        license="CC-BY-SA-4.0",
        anchors=("esp:emo:fear:v1",),
    )
    with pytest.raises(ValidationError, match="duplicate anchor ids"):
        Registry(
            name="rr",
            version="1.0.0",
            anchors=(anchor("fear"), anchor("fear", definition="other")),
            vocabularies=(vocab,),
        )
    with pytest.raises(ValidationError, match="vocabulary anchors must be unique"):
        registry(anchor("fear"), anchor("fear"))


def test_anchor_id_must_match_fields() -> None:
    with pytest.raises(ValidationError, match="does not match label"):
        Anchor.model_validate(anchor("fear").model_dump() | {"label": "dread"})
    with pytest.raises(ValidationError, match="does not match version"):
        Anchor.model_validate(anchor("fear").model_dump() | {"version": 2})
    with pytest.raises(ValidationError, match="does not match type"):
        Anchor.model_validate(anchor("fear").model_dump() | {"type": TaossType.KNO})


def test_types_serialize_by_name_and_reject_integers() -> None:
    a = anchor("fear")
    assert b'"type":"EMO"' in a.canonical_json()
    with pytest.raises(ValidationError, match="TAOSS type name"):
        Anchor.from_data(a.model_dump(mode="json") | {"type": 2})


def test_with_anchor_idempotent_but_conflict_is_error() -> None:
    r = registry(anchor("fear"))
    assert r.with_anchor(anchor("fear")) is r
    with pytest.raises(RegistryError, match="different content"):
        r.with_anchor(anchor("fear", definition="redefined"))


def test_semantic_mutation_requires_new_version() -> None:
    old = registry(anchor("fear"))
    mutated = registry(anchor("fear", definition="now means something else"))
    with pytest.raises(RegistryError, match="changed meaning"):
        check_evolution(old, mutated)
    both_active = (anchor("fear"), anchor("fear", version=2, definition="refined"))
    with pytest.raises(ValidationError, match="ambiguous among active"):
        registry(*both_active)
    bumped = registry(
        anchor("fear", status=AnchorStatus.DEPRECATED),
        anchor("fear", version=2, definition="refined"),
    )
    check_evolution(old, bumped)
    assert bumped.resolve_label(VOCAB, "fear").id == "esp:emo:fear:v2"
    assert bumped.anchor("esp:emo:fear:v1").status is AnchorStatus.DEPRECATED


def test_removal_forbidden_deprecation_allowed_and_resolvable() -> None:
    old = registry(anchor("fear"), anchor("dread"))
    with pytest.raises(RegistryError, match="was removed"):
        check_evolution(old, registry(anchor("fear")))
    new = old.deprecated("esp:emo:dread:v1")
    check_evolution(old, new)
    resolved = new.anchor("esp:emo:dread:v1")
    assert resolved.status is AnchorStatus.DEPRECATED
    with pytest.raises(RegistryError, match="un-deprecated"):
        check_evolution(new, old)


def test_aliases_only_grow_and_must_be_unambiguous() -> None:
    old = registry(anchor("fear", aliases=("afraid",)))
    with pytest.raises(RegistryError, match="lost aliases"):
        check_evolution(old, registry(anchor("fear")))
    assert old.resolve_label(VOCAB, "afraid").id == "esp:emo:fear:v1"
    with pytest.raises(ValidationError, match="ambiguous"):
        registry(anchor("fear", aliases=("scared",)), anchor("dread", aliases=("scared",)))


def test_deterministic_digest_independent_of_input_order() -> None:
    a, b = anchor("fear"), anchor("joy")
    r1 = registry(a, b)
    r2 = Registry.model_validate(r1.model_dump() | {"anchors": (b, a)})
    assert r1.digest_hex() == r2.digest_hex()
    assert r1.digest_hex() != registry(a, anchor("joy", definition="x")).digest_hex()
    assert len(r1.digest_hex()) == 64


def test_unknown_ids() -> None:
    r = registry(anchor("fear"))
    with pytest.raises(RegistryError, match="unknown anchor id"):
        r.anchor("esp:emo:joy:v1")
    with pytest.raises(RegistryError, match="not found"):
        r.resolve_label(VOCAB, "joy")


def test_referential_integrity() -> None:
    with pytest.raises(ValidationError, match="not listed in vocabulary"):
        Registry(name="rr", version="1.0.0", anchors=(anchor("fear"),))
    s = AnchorSet(id="set-1", type=TaossType.KNO, anchors=("esp:emo:fear:v1",))
    with pytest.raises(ValidationError, match="wrong type"):
        registry(anchor("fear"), anchor_sets=(s,))


def test_encoder_realizations_are_per_encoder_and_dimensioned() -> None:
    real = EncoderRealization(
        anchor_id="esp:emo:fear:v1",
        encoder_id="encoder-x@1.2.0",
        vector=(0.0,) * 64,
        validity=ValidityRegion(kind="cosine_min", threshold=0.6),
    )
    r = registry(anchor("fear"), realizations=(real,))
    assert r.realizations == (real,)
    wrong_dim = real.model_copy(update={"vector": (0.0,) * 63})
    with pytest.raises(ValidationError, match="wrong dimension"):
        registry(anchor("fear"), realizations=(wrong_dim,))
    with pytest.raises(ValidationError, match="one realization per"):
        registry(anchor("fear"), realizations=(real, real))
    with pytest.raises(ValidationError):
        ValidityRegion(kind="l2_ball", threshold=0.0)
