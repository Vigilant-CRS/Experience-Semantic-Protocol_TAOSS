# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
import math
import uuid

import pytest
from pydantic import ValidationError

from esp.core.ids import UUID4, AnchorId, anchor_major_version, new_uuid4
from esp.core.model import EspModel
from esp.core.scalars import Confidence, Intensity, Similarity, UInt32, UInt64, Valence


class Scalars(EspModel):
    intensity: Intensity
    confidence: Confidence
    valence: Valence
    similarity: Similarity


class Ints(EspModel):
    u32: UInt32
    u64: UInt64


class Ids(EspModel):
    frame_id: UUID4
    anchor: AnchorId


def make(**overrides: object) -> Scalars:
    values: dict[str, object] = {
        "intensity": 0.5,
        "confidence": 0.5,
        "valence": 0.0,
        "similarity": 0.0,
    }
    values.update(overrides)
    return Scalars.model_validate(values)


@pytest.mark.parametrize("value", [0.0, 1.0, 0.5, 5e-324])
def test_unit_interval_accepts_closed_bounds(value: float) -> None:
    assert make(intensity=value).intensity == value


@pytest.mark.parametrize("value", [-1e-12, 1.0000001, -0.5, 2.0])
def test_unit_interval_rejects_out_of_range(value: float) -> None:
    with pytest.raises(ValidationError):
        make(intensity=value)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_rejected(value: float) -> None:
    with pytest.raises(ValidationError):
        make(confidence=value)


@pytest.mark.parametrize("value", ["0.5", True, None, b"0.5"])
def test_strict_no_coercion(value: object) -> None:
    with pytest.raises(ValidationError):
        make(intensity=value)


def test_integers_accepted_as_floats() -> None:
    assert make(intensity=1).intensity == 1.0


@pytest.mark.parametrize(("value", "ok"), [(-1.0, True), (1.0, True), (-1.0001, False)])
def test_valence_range(value: float, ok: bool) -> None:
    if ok:
        assert make(valence=value).valence == value
    else:
        with pytest.raises(ValidationError):
            make(valence=value)


def test_negative_zero_is_canonicalized() -> None:
    a = make(valence=-0.0)
    b = make(valence=0.0)
    assert math.copysign(1.0, a.valence) == 1.0
    assert a.canonical_json() == b.canonical_json()


@pytest.mark.parametrize(
    ("u32", "u64", "ok"),
    [
        (0, 0, True),
        (2**32 - 1, 2**64 - 1, True),
        (2**32, 0, False),
        (0, 2**64, False),
        (-1, 0, False),
    ],
)
def test_unsigned_ranges(u32: int, u64: int, ok: bool) -> None:
    if ok:
        Ints(u32=u32, u64=u64)
    else:
        with pytest.raises(ValidationError):
            Ints(u32=u32, u64=u64)


def test_uuid4_accepted_and_other_versions_rejected() -> None:
    Ids(frame_id=new_uuid4(), anchor="esp:emo:fear:v1")
    with pytest.raises(ValidationError):
        Ids(frame_id=uuid.uuid1(), anchor="esp:emo:fear:v1")
    with pytest.raises(ValidationError):
        Ids(frame_id=uuid.UUID(int=0), anchor="esp:emo:fear:v1")


def test_uuid_from_json_string() -> None:
    value = new_uuid4()
    parsed = Ids.from_json(f'{{"frame_id":"{value}","anchor":"esp:emo:fear:v1"}}')
    assert parsed.frame_id == value


@pytest.mark.parametrize(
    "anchor",
    [
        "esp:emo:fear:v0",
        "esp:xyz:fear:v1",
        "esp:emo:Fear:v1",
        "emo:fear:v1",
        "esp:emo::v1",
        "esp:emo:fear",
    ],
)
def test_invalid_anchor_ids(anchor: str) -> None:
    with pytest.raises(ValidationError):
        Ids(frame_id=new_uuid4(), anchor=anchor)


def test_anchor_major_version() -> None:
    assert anchor_major_version("esp:emo:fear:v1") == 1
    assert anchor_major_version("esp:kno:possible-dismissal:v12") == 12
    with pytest.raises(ValueError, match="not an anchor id"):
        anchor_major_version("fear")
