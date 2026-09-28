# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-049 acceptance tests: ExperienceFrame <-> payload, type-presence invariant."""

import dataclasses
import uuid

import numpy as np
import pytest

from esp.codec.errors import WireError
from esp.codec.frame_wire import (
    WireOptions,
    consent_flags_for,
    frame_to_payload,
    payload_to_frame,
)
from esp.codec.header import Header
from esp.codec.tlv import LatentEncoding, encode_tlv
from esp.core.taoss_types import TaossType
from esp.frame.model import DisclosurePolicy, ExperienceFrame, TypeBlock
from esp.ontology.profiles import BASIC8_ID, basic8_registry
from esp.semantics.bindings import BindingPolicy
from tests.unit.frame.factory import BINDING, full_frame

T = TaossType
BASIC8_SET = basic8_registry().anchor_set(BASIC8_ID)


def full_anchor_frame() -> ExperienceFrame:
    """The factory frame with anchor coordinates for the whole basic-8 set."""
    frame = full_frame()
    emo = frame.block(T.EMO)
    assert emo is not None
    coords = [
        {"anchor_id": a, "similarity": round(0.1 * i - 0.3, 3)}
        for i, a in enumerate(BASIC8_SET.anchors)
    ]
    new_emo = TypeBlock.from_data(emo.model_dump(mode="json") | {"anchors": coords})
    types = tuple(new_emo if b.type is T.EMO else b for b in frame.types)
    return ExperienceFrame.model_validate(frame.model_dump() | {"types": types})


OPTS = WireOptions(addendum=True, anchor_sets={BASIC8_ID: BASIC8_SET})


def header_for(types_bitmap: int, consent_flags: int, *, quantized: bool = False) -> Header:
    return Header(
        profile=1,
        sf_level=7,
        types_bitmap=types_bitmap,
        consent_flags=consent_flags,
        privacy_flags=0x10 if quantized else 0,
        capabilities=0,
        timestamp_ns=1,
        timeline_id=full_frame().timeline_id,
        segment_seq=123,
        dt_ms=0,
        phase=0.0,
        sender_id=bytes(32),
        payload_len=0,
        nonce=bytes(12),
    )


def f32(values: tuple[float, ...] | None) -> tuple[float, ...] | None:
    return None if values is None else tuple(float(np.float32(v)) for v in values)


def as_transmitted(frame: ExperienceFrame) -> ExperienceFrame:
    """The frame with latents and anchor similarities rounded to binary32."""
    types = []
    for b in frame.types:
        data = b.model_dump(mode="json")
        data["latent"] = f32(b.latent)
        data["anchors"] = [
            a | {"similarity": float(np.float32(a["similarity"]))} for a in data["anchors"]
        ]
        types.append(TypeBlock.from_data(data))
    return ExperienceFrame.model_validate(frame.model_dump() | {"types": tuple(types)})


def roundtrip(frame: ExperienceFrame, opts: WireOptions = OPTS) -> ExperienceFrame:
    enc = frame_to_payload(frame, opts)
    header = header_for(enc.types_bitmap, consent_flags_for(enc))
    return payload_to_frame(header, enc.payload, opts)


def test_full_frame_roundtrip_with_addendum_and_anchors() -> None:
    frame = full_anchor_frame()
    assert roundtrip(frame) == as_transmitted(frame)


def test_masked_emo_is_absent_from_payload_and_flagged() -> None:
    disclosed = full_frame().disclose(DisclosurePolicy(allowed_types=(T.KNO, T.INT, T.CTX)))
    enc = frame_to_payload(disclosed, OPTS)
    assert enc.types_bitmap == T.KNO.bit | T.INT.bit | T.CTX.bit
    assert enc.emo_masked
    for marker in (b"\x62\x00\x00", b"fear", b"sadness", b"affect_scope", b"elicited_by"):
        assert marker not in enc.payload
    back = payload_to_frame(header_for(enc.types_bitmap, consent_flags_for(enc)), enc.payload, OPTS)
    assert back.block(T.EMO) is None
    assert T.EMO in back.masked_types


def test_binding_masked_at_protocol_level() -> None:
    frame = full_anchor_frame()
    without = frame_to_payload(frame.disclose(DisclosurePolicy(allowed_types=(T.KNO, T.EMO))), OPTS)
    assert b"possible_dismissal" not in without.payload
    assert str(BINDING).encode() not in without.payload
    allowed = frame.disclose(
        DisclosurePolicy(
            allowed_types=(T.KNO, T.EMO), bindings=BindingPolicy(allowed_binding_ids=(BINDING,))
        )
    )
    with_binding = frame_to_payload(allowed, OPTS)
    assert b"possible_dismissal" in with_binding.payload


def test_smuggled_emo_descriptor_is_rejected() -> None:
    frame = full_anchor_frame().disclose(DisclosurePolicy(allowed_types=(T.KNO, T.EMO)))
    enc = frame_to_payload(frame, OPTS)
    # attacker clears the EMO bit and sets EMO_MASKED while keeping EMO objects in the payload
    lying_header = header_for(T.KNO.bit, 0x0001)
    with pytest.raises(WireError, match="type-presence invariant"):
        payload_to_frame(lying_header, enc.payload, OPTS)
    emo_descriptor_only = enc.payload
    only_kno = frame_to_payload(frame.disclose(DisclosurePolicy(allowed_types=(T.KNO,))), OPTS)
    smuggled = only_kno.payload + emo_descriptor_only[emo_descriptor_only.index(b"\x92") :]
    with pytest.raises(WireError):
        payload_to_frame(header_for(T.KNO.bit, 0x0001), smuggled, OPTS)


def test_declared_type_without_object_is_rejected() -> None:
    enc = frame_to_payload(full_frame().disclose(DisclosurePolicy(allowed_types=(T.KNO,))), OPTS)
    with pytest.raises(WireError, match="type-presence invariant"):
        payload_to_frame(header_for(T.KNO.bit | T.CTX.bit, 0), enc.payload, OPTS)


def test_addendum_requires_pinning() -> None:
    frame = full_frame()
    with pytest.raises(WireError, match="not pinned"):
        frame_to_payload(frame, WireOptions())
    latents_only = ExperienceFrame.model_validate(
        frame.model_dump()
        | {
            "types": tuple(TypeBlock(type=b.type, latent=b.latent) for b in frame.types),
            "bindings": (),
        }
    )
    enc = frame_to_payload(latents_only, WireOptions())
    back = payload_to_frame(header_for(enc.types_bitmap, 0), enc.payload, WireOptions())
    assert back.present_types == tuple(TaossType)
    again = payload_to_frame(header_for(enc.types_bitmap, 0), enc.payload, WireOptions())
    assert again.frame_id == back.frame_id  # deterministic without metadata
    # addendum TLVs sent to a peer that did not pin the profile are never interpreted
    stray = enc.payload + encode_tlv(0x92, b"\x01{}")
    assert payload_to_frame(header_for(enc.types_bitmap, 0), stray, WireOptions()) == back


def test_anchor_sets_must_be_pinned_and_complete() -> None:
    frame = full_anchor_frame()
    with pytest.raises(WireError, match="not pinned"):
        frame_to_payload(frame, WireOptions(addendum=True))
    partial = full_frame()  # factory frame has only two of the eight anchors
    with pytest.raises(WireError, match="exactly the anchor set"):
        frame_to_payload(partial, OPTS)


@pytest.mark.parametrize("encoding", list(LatentEncoding))
def test_latent_encodings_through_frames(encoding: LatentEncoding) -> None:
    frame = full_anchor_frame()
    opts = dataclasses.replace(OPTS, encoding=encoding)
    enc = frame_to_payload(frame, opts)
    header = header_for(enc.types_bitmap, 0, quantized=encoding is LatentEncoding.INT8_SYM)
    back = payload_to_frame(header, enc.payload, opts)
    for t in TaossType:
        a, b = frame.block(t), back.block(t)
        assert a is not None
        assert b is not None
        assert a.latent is not None
        assert b.latent is not None
        tol = {
            LatentEncoding.F32_BE: 1e-6,
            LatentEncoding.F16_BE: 5e-3,
            LatentEncoding.INT8_SYM: 0.05,
        }[encoding]
        assert np.allclose(a.latent, b.latent, atol=tol * max(1.0, float(np.max(np.abs(a.latent)))))
    wrong = header_for(enc.types_bitmap, 0, quantized=encoding is not LatentEncoding.INT8_SYM)
    with pytest.raises(WireError, match="QUANTIZED"):
        payload_to_frame(wrong, enc.payload, opts)


def test_random_frame_ids_survive_with_metadata() -> None:
    frame = ExperienceFrame.model_validate(
        full_anchor_frame().model_dump() | {"frame_id": uuid.uuid4()}
    )
    assert roundtrip(frame).frame_id == frame.frame_id


def test_invalid_addendum_objects_raise_wire_errors_only() -> None:
    enc = frame_to_payload(full_anchor_frame(), OPTS)
    header = header_for(enc.types_bitmap, 0)
    for bad_body in (b"\x01{not json", b"\x01{}", b"\x02{}", b""):
        with pytest.raises(WireError):
            payload_to_frame(header, enc.payload + encode_tlv(0x92, bad_body), OPTS)


def test_inferred_subject_affect_on_l1_rejected_while_parsing() -> None:
    from esp.core.provenance import AffectScope, Provenance, SourceKind  # noqa: PLC0415
    from esp.semantics.affect import AffectiveDescriptor, CategoryEstimate  # noqa: PLC0415

    inferred = AffectiveDescriptor(
        vocabulary_id="esp-emo-v13-basic8-v1",
        affect_scope=AffectScope.INFERRED_SUBJECT,
        provenance=Provenance(
            source_kind=SourceKind.MODEL_INFERENCE,
            producer_id="m",
            producer_version="0.1.0",
            source_refs=("obs",),
        ),
        categories=(CategoryEstimate(label="fear", intensity=0.7),),
    )
    enc = frame_to_payload(full_anchor_frame(), OPTS)
    smuggled = enc.payload + encode_tlv(0x92, b"\x01" + inferred.canonical_json())
    with pytest.raises(WireError, match="valid ExperienceFrame"):
        payload_to_frame(header_for(enc.types_bitmap, 0), smuggled, OPTS)
