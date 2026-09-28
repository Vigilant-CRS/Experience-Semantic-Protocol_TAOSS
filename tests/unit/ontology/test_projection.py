# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-050: anchor projection π_t (cosine / projection / RBF) and the three modes."""

import numpy as np
import pytest

from esp.codec.frame_wire import WireOptions, frame_to_payload
from esp.codec.tlv import TYPED_LATENT_CODES, iter_tlvs
from esp.core.taoss_types import TaossType
from esp.ontology.profiles import BASIC8_ID, basic8_registry
from esp.ontology.projection import (
    Mode,
    ProjectionError,
    SimilarityKind,
    local_coordinates,
    project,
    realizations_for,
    with_anchor_coordinates,
)
from esp.ontology.registry import EncoderRealization, Registry, ValidityRegion
from tests.unit.frame.factory import full_frame

T = TaossType
ENC = "esp-demo-projection@0.1.0"


def registry_with_realizations() -> Registry:
    base = basic8_registry()
    anchors = base.anchor_set(BASIC8_ID).anchors
    rng = np.random.default_rng(0)
    reals = tuple(
        EncoderRealization(
            anchor_id=a,
            encoder_id=ENC,
            vector=tuple(float(x) for x in rng.normal(size=64)),
            validity=ValidityRegion(kind="cosine_min", threshold=0.5),
        )
        for a in anchors
    )
    return Registry.model_validate(base.model_dump() | {"realizations": reals})


REG = registry_with_realizations()


@pytest.mark.parametrize("kind", list(SimilarityKind))
def test_same_latent_and_anchor_set_give_bit_identical_coordinates(kind: SimilarityKind) -> None:
    anchors = realizations_for(REG, BASIC8_ID, ENC)
    z = tuple(np.random.default_rng(1).normal(size=64))
    a, b = project(z, anchors, kind), project(z, anchors, kind)
    assert a == b
    assert [c.anchor_id for c in a] == list(REG.anchor_set(BASIC8_ID).anchors)  # set order
    assert all(np.float32(c.similarity) == c.similarity for c in a)  # wire precision


def test_similarity_kinds_mean_what_they_say() -> None:
    anchors = realizations_for(REG, BASIC8_ID, ENC)
    _, a0 = anchors[0]
    cos = project(tuple(a0 * 3), anchors, SimilarityKind.COSINE)[0].similarity
    proj = project(tuple(a0 * 0.5), anchors, SimilarityKind.PROJECTION)[0].similarity
    rbf = project(tuple(a0), anchors, SimilarityKind.RBF)[0].similarity
    assert cos == pytest.approx(1.0)
    assert proj == pytest.approx(0.5, abs=1e-6)  # least-squares coefficient on the anchor span
    assert rbf == pytest.approx(1.0)


def test_interpretation_only_packet_contains_no_latent_tlv() -> None:
    frame = full_frame(with_binding=False)
    only = with_anchor_coordinates(frame, T.EMO, REG, BASIC8_ID, ENC, mode=Mode.INSTEAD)
    emo = only.block(T.EMO)
    assert emo is not None
    assert emo.latent is None
    assert len(emo.anchors) == 8
    wire = WireOptions(addendum=True, anchor_sets={BASIC8_ID: REG.anchor_set(BASIC8_ID)})
    codes = [t.code for t in iter_tlvs(frame_to_payload(only, wire).payload)]
    assert T.EMO.tlv_code not in codes  # the EMO latent is not on the wire
    assert 0x50 in codes
    alongside = with_anchor_coordinates(frame, T.EMO, REG, BASIC8_ID, ENC, mode=Mode.ALONGSIDE)
    assert alongside.block(T.EMO).latent is not None  # type: ignore[union-attr]
    assert {
        t.code for t in iter_tlvs(frame_to_payload(alongside, wire).payload)
    } & TYPED_LATENT_CODES


def test_anchors_are_not_the_latent_state() -> None:
    """Different latents can share coordinates (projection onto the anchor span)."""
    anchors = realizations_for(REG, BASIC8_ID, ENC)
    basis = np.stack([a for _, a in anchors])  # 8 x 64
    z1 = np.random.default_rng(2).normal(size=64)
    q, _ = np.linalg.qr(basis.T)  # orthonormal basis of the anchor span
    orth = np.random.default_rng(3).normal(size=64)
    orth -= q @ (q.T @ orth)  # component orthogonal to every anchor
    z2 = z1 + 5 * orth
    c1 = project(tuple(z1), anchors, SimilarityKind.PROJECTION)
    c2 = project(tuple(z2), anchors, SimilarityKind.PROJECTION)
    assert [c.similarity for c in c1] == pytest.approx([c.similarity for c in c2], abs=1e-5)
    assert np.linalg.norm(z1 - z2) > 1.0  # yet the states are different


def test_receiver_local_mode_matches_sender_side() -> None:
    frame = full_frame(with_binding=False)
    sent = with_anchor_coordinates(frame, T.EMO, REG, BASIC8_ID, ENC, mode=Mode.ALONGSIDE)
    assert local_coordinates(frame, T.EMO, REG, BASIC8_ID, ENC) == sent.block(T.EMO).anchors  # type: ignore[union-attr]


def test_missing_realizations_are_refused() -> None:
    with pytest.raises(ProjectionError, match="no realization"):
        realizations_for(basic8_registry(), BASIC8_ID, ENC)


@pytest.mark.parametrize("kind", list(SimilarityKind))
def test_similarity_kind_travels_on_the_wire(kind: SimilarityKind) -> None:
    from tests.unit.frame.test_frame_wire import roundtrip  # noqa: PLC0415

    frame = with_anchor_coordinates(
        full_frame(with_binding=False), T.EMO, REG, BASIC8_ID, ENC, kind=kind
    )
    back = roundtrip(frame)
    emo = back.block(T.EMO)
    assert emo is not None
    assert emo.similarity_kind == kind.name.lower()
    assert emo.anchors == frame.block(T.EMO).anchors  # type: ignore[union-attr]
