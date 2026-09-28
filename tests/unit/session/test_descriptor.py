# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-048 acceptance tests: session descriptor, negotiation, transcript, control TLVs."""

import dataclasses

import pytest
from hypothesis import given
from hypothesis import strategies as st

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.core.errors import ErrorCode
from esp.core.taoss_types import TaossType
from esp.session.control import CloseReason, ErrorNotice, RegistryDigest, SessionClose
from esp.session.descriptor import (
    DecoderPolicy,
    NegotiationError,
    NonceMode,
    PqMode,
    SessionDescriptor,
    negotiate,
    transcript_hash,
)

BASIC8 = ("esp-emo-v13-basic8-v1", bytes.fromhex("dd" * 32))
ADDENDUM = ("esp-addendum-v1", bytes.fromhex("aa" * 32))


def desc(**kw: object) -> SessionDescriptor:
    fields: dict[str, object] = {
        "profile": 1,
        "sf_level": 3,
        "rate_sensor_mhz": 250_000,
        "rate_latent_mhz": 50_000,
        "rate_packet_mhz": 50_000,
        "registries": dict([BASIC8, ADDENDUM]),
    }
    fields.update(kw)
    return SessionDescriptor(**fields)  # type: ignore[arg-type]


def test_roundtrip_and_canonical_registry_order() -> None:
    d = desc()
    raw = d.encode()
    again = SessionDescriptor.decode(raw)
    assert again == d
    reordered = desc(registries=dict([ADDENDUM, BASIC8]))
    assert reordered.encode() == raw
    assert raw.index(b"esp-addendum-v1") < raw.index(b"esp-emo-v13-basic8-v1")


@given(
    sf=st.integers(0, 7),
    w_back=st.integers(1024, 8192),
    w_fwd=st.integers(128, 8192),
    rates=st.lists(st.integers(0, 2**32 - 1), min_size=4, max_size=4),
    policies=st.lists(st.sampled_from(DecoderPolicy), min_size=6, max_size=6),
)
def test_roundtrip_property(
    sf: int, w_back: int, w_fwd: int, rates: list[int], policies: list[DecoderPolicy]
) -> None:
    d = desc(
        sf_level=sf,
        w_back=w_back,
        w_fwd=w_fwd,
        rate_sensor_mhz=rates[0],
        rate_latent_mhz=rates[1],
        rate_packet_mhz=rates[2],
        rate_privacy_mhz=rates[3],
        decoder_policy=dict(zip(TaossType, policies, strict=True)),
    )
    assert SessionDescriptor.decode(d.encode()) == d


def test_invalid_descriptors() -> None:
    with pytest.raises(WireError, match="CLASSICAL_ONLY"):
        desc(pq_mode=PqMode.HYBRID_OUTER)
    with pytest.raises(WireError, match="w_back"):
        desc(w_back=10)
    with pytest.raises(WireError, match="all six types"):
        desc(decoder_policy={TaossType.KNO: DecoderPolicy.GRACEFUL})
    with pytest.raises(WireError, match="registry name"):
        desc(registries={"Bad Name": bytes(32)})
    raw = desc().encode()
    for broken in (raw[:-1], raw + b"\x00", raw[:15]):
        with pytest.raises(WireError, match="malformed"):
            SessionDescriptor.decode(broken)


def test_negotiation_never_silently_changes_profile() -> None:
    base = desc()
    for field_name, value in (
        ("profile", 2),
        ("sf_level", 7),
        ("nonce_mode", NonceMode.RANDOM),
        ("dp_level", 2),
    ):
        other = dataclasses.replace(base, **{field_name: value})
        with pytest.raises(NegotiationError, match=f"mismatch on {field_name}"):
            negotiate(base, other)


def test_negotiation_registries_and_tolerance() -> None:
    i = desc(clock_tolerance_ms=2000)
    r = desc(registries=dict([BASIC8]), clock_tolerance_ms=500)
    session = negotiate(i, r)
    assert dict(session.registries) == dict([BASIC8])  # addendum only active if both pin it
    assert session.clock_tolerance_ms == 500
    tampered = desc(registries={BASIC8[0]: bytes(32)})
    with pytest.raises(NegotiationError, match="different digests"):
        negotiate(i, tampered)


def test_transcript_binds_every_input() -> None:
    kw = {
        "noise_h": b"\x01" * 32,
        "initiator": desc(),
        "responder": desc(clock_tolerance_ms=500),
        "sender_capability": b"cap-S",
        "receiver_capability": b"cap-R",
    }
    base = transcript_hash(**kw)  # type: ignore[arg-type]
    variants = {
        "noise_h": b"\x02" * 32,
        "initiator": desc(sf_level=4),
        "responder": desc(),
        "sender_capability": b"cap-S2",
        "receiver_capability": None,
    }
    for key, value in variants.items():
        assert transcript_hash(**(kw | {key: value})) != base  # type: ignore[arg-type]
    swapped = transcript_hash(**(kw | {"initiator": kw["responder"], "responder": kw["initiator"]}))  # type: ignore[arg-type]
    assert swapped != base


def test_control_tlvs() -> None:
    close = SessionClose(CloseReason.SEQUENCE_EXHAUSTED, "segment_seq exhausted")
    assert SessionClose.decode(close.encode()) == close
    err = ErrorNotice(ErrorCode.DECODER_POLICY_FAILED, "EMO absent, strict policy")
    assert ErrorNotice.decode(err.encode()) == err
    reg = RegistryDigest(*BASIC8)
    assert RegistryDigest.decode(reg.encode()) == reg
    for bad in (
        Tlv(0x81, b"\x09\x00\x00"),
        Tlv(0x81, b"\x00\x00\x05ab"),
        Tlv(0x82, b"\xff\xff\x00\x00"),
    ):
        with pytest.raises(WireError):
            (SessionClose if bad.code == 0x81 else ErrorNotice).decode(bad)
    with pytest.raises(WireError):
        RegistryDigest.decode(Tlv(0x83, b"\x03abc" + bytes(31)))
