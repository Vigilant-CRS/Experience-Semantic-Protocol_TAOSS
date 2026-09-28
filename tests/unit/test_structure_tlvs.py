# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-061 acceptance tests: bundle mode, capability extension, type profile."""

import dataclasses
import uuid

import numpy as np
import pytest
from hypothesis import given
from hypothesis import strategies as st

from esp.codec.errors import WireError
from esp.codec.header import Header
from esp.codec.structure import (
    CapabilitiesExt,
    TypeProfile,
    check_caps_ext_promise,
    encode_bundle,
    parse_bundle,
)
from esp.codec.tlv import Tlv, decode_typed_latent, encode_tlv, encode_typed_latent, parse_payload
from esp.core.taoss_types import TaossType

T = TaossType


def segment(seed: int) -> bytes:
    rng = np.random.default_rng(seed)
    return encode_typed_latent(T.INT, rng.normal(size=64)) + encode_typed_latent(
        T.TEM, rng.normal(size=16)
    )


@pytest.mark.parametrize("n", [1, 2, 16, 64])
def test_bundle_roundtrip(n: int) -> None:
    payload = encode_bundle([segment(i) for i in range(n)], trailing=encode_tlv(0x52, b"t" * 4))
    bundle = parse_bundle(payload)
    assert len(bundle.segments) == n
    for i, seg in enumerate(bundle.segments):
        values = decode_typed_latent(seg.known[0]).values
        assert np.allclose(values, np.random.default_rng(i).normal(size=64), atol=1e-6)
    assert [t.code for t in bundle.top_level.known] == [0x52]


def test_bundle_amortizes_overhead() -> None:
    single = len(segment(0)) + 180
    bundled = len(encode_bundle([segment(i) for i in range(10)])) + 180
    assert bundled / 10 < single  # ~180/N header+signature overhead per segment


def test_bundle_rules() -> None:
    with pytest.raises(WireError, match=r"1\.\.256"):
        encode_bundle([])
    with pytest.raises(WireError, match="must not mix"):
        parse_bundle(encode_bundle([segment(0)]) + segment(1))
    nested = encode_tlv(0x01, encode_tlv(0x01, segment(0)))
    with pytest.raises(WireError, match="must not nest"):
        parse_bundle(nested)
    with pytest.raises(WireError, match="duplicate TLV 0x61"):
        parse_bundle(encode_tlv(0x01, segment(0) + segment(1)))
    with pytest.raises(WireError, match="not a bundle"):
        parse_bundle(segment(0))


@given(st.lists(st.booleans(), max_size=100))
def test_capabilities_ext_roundtrip(bits: list[bool]) -> None:
    ext = CapabilitiesExt(tuple(bits))
    assert CapabilitiesExt.decode(ext.encode()) == ext
    assert not ext.has(len(bits) + 5)  # unknown bits read as not set


def test_capabilities_ext_encoding_msb_first_and_padding() -> None:
    assert CapabilitiesExt((True, False, True)).encode().value == b"\x00\x03\xa0"
    with pytest.raises(WireError, match="padding"):
        CapabilitiesExt.decode(Tlv(0x10, b"\x00\x03\xa1"))
    with pytest.raises(WireError, match="length"):
        CapabilitiesExt.decode(Tlv(0x10, b"\x00\x09\xff"))


def test_caps_ext_promise_both_directions() -> None:
    header = Header(
        profile=1,
        sf_level=0,
        types_bitmap=1,
        consent_flags=0,
        privacy_flags=0,
        capabilities=0,
        timestamp_ns=0,
        timeline_id=uuid.uuid4(),
        segment_seq=0,
        dt_ms=0,
        phase=0.0,
        sender_id=bytes(32),
        payload_len=0,
        nonce=bytes(12),
    )
    ext = CapabilitiesExt((True,)).encode().encode()
    assert check_caps_ext_promise(header, parse_payload(b"")) is None
    with pytest.raises(WireError, match="disagrees"):
        check_caps_ext_promise(header, parse_payload(ext))
    flagged = dataclasses.replace(header, capabilities=0x8000)
    assert check_caps_ext_promise(flagged, parse_payload(ext)) == CapabilitiesExt((True,))
    with pytest.raises(WireError, match="disagrees"):
        check_caps_ext_promise(flagged, parse_payload(b""))


def test_type_profile_must_be_pinned() -> None:
    pid = uuid.uuid4()
    digest = b"\x42" * 32
    tlv = TypeProfile(pid, 12, digest).encode()
    assert TypeProfile.decode(tlv, pinned={pid: digest}).type_count == 12
    with pytest.raises(WireError, match="not pinned"):
        TypeProfile.decode(tlv, pinned={})
    with pytest.raises(WireError, match="digest mismatch"):
        TypeProfile.decode(tlv, pinned={pid: b"\x00" * 32})


def test_alternate_profile_latents_decoded_with_declared_dims() -> None:
    # A TAOSS-12 style profile could declare 32 dims for code 0x60; TAOSS-6 defaults reject it.
    tlv = parse_payload(encode_typed_latent(T.KNO, np.zeros(32))).known[0]
    with pytest.raises(WireError, match="expected 240"):
        decode_typed_latent(tlv)
    assert decode_typed_latent(tlv, expected_dims=32).values.shape == (32,)
