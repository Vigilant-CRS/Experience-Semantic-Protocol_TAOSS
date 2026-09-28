# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-014 unit and property tests for the 100-byte header."""

import dataclasses
import struct
import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st

from esp.codec.errors import WireError
from esp.codec.header import Header, float32


@st.composite
def headers(draw: st.DrawFn) -> Header:
    types = draw(st.integers(0, 0x3F))
    consent = draw(st.integers(0, 0x7))
    if types & 0x4:
        consent &= ~0x1  # respect the mask-bit invariant
    return Header(
        profile=draw(st.integers(1, 255)),
        sf_level=draw(st.integers(0, 7)),
        types_bitmap=types,
        consent_flags=consent,
        privacy_flags=draw(st.integers(0, 3)) | draw(st.sampled_from([0, 0x10, 0x20, 0x30])),
        capabilities=draw(st.integers(0, 0x0FFF)) | draw(st.sampled_from([0, 0x8000])),
        timestamp_ns=draw(st.integers(0, 2**64 - 1)),
        timeline_id=draw(st.uuids(version=4)),
        segment_seq=draw(st.integers(0, 2**32 - 1)),
        dt_ms=draw(st.integers(0, 2**32 - 1)),
        phase=draw(st.floats(0.0, 1.0, exclude_max=True, width=32)),
        sender_id=draw(st.binary(min_size=32, max_size=32)),
        payload_len=draw(st.integers(0, 2**32 - 1)),
        nonce=draw(st.binary(min_size=12, max_size=12)),
    )


@given(headers())
def test_roundtrip(h: Header) -> None:
    raw = h.encode()
    assert len(raw) == 100
    assert Header.decode(raw) == h
    assert Header.decode(raw).encode() == raw


@given(st.binary(min_size=100, max_size=100))
def test_arbitrary_bytes_either_rejected_or_canonical(raw: bytes) -> None:
    try:
        h = Header.decode(raw)
    except WireError:
        return
    assert h.encode() == raw


@given(headers(), st.integers(0, 799))
def test_single_bit_flip_never_crashes(h: Header, bit: int) -> None:
    raw = bytearray(h.encode())
    raw[bit // 8] ^= 1 << (bit % 8)
    try:
        decoded = Header.decode(bytes(raw))
    except WireError:
        return
    assert decoded != h  # any accepted flip must change the decoded header


def test_emo_mask_invariant_on_construction() -> None:
    with pytest.raises(WireError, match="mask-bit invariant"):
        Header(
            profile=1,
            sf_level=7,
            types_bitmap=0x04,
            consent_flags=0x01,
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


def test_phase_must_be_binary32_exact() -> None:
    base = Header(
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
    with pytest.raises(WireError, match="binary32"):
        dataclasses.replace(base, phase=0.1)
    ok = dataclasses.replace(base, phase=float32(0.1))
    assert struct.unpack(">f", ok.encode()[48:52])[0] == ok.phase
    with pytest.raises(WireError, match="phase"):
        dataclasses.replace(base, phase=0)  # type: ignore[arg-type]
    with pytest.raises(WireError, match="sender_id"):
        dataclasses.replace(base, sender_id=bytes(31))
    with pytest.raises(WireError, match="segment_seq"):
        dataclasses.replace(base, segment_seq=2**32)
    with pytest.raises(WireError, match="profile"):
        dataclasses.replace(base, profile=True)  # type: ignore[arg-type]


def test_packet_length_formula() -> None:
    h = Header.decode(
        bytes.fromhex(
            "4553500100010000000100000000000017f78959971980005f0c6a8e3b7d4c4e9a532f6a1d9e8b10"
            "000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b"
            "1c1d1e1f00000000000102030405060708090a0b"
        )
    )
    assert h.packet_len == 180
