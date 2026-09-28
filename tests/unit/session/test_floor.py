# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-064: turn tokens (0x52), SOS."""

import uuid

import pytest

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.session.floor import TurnFloor, TurnToken, is_sos, sos_tlv

TL = uuid.uuid4()
MOD, ALICE, BOB, EVE = (bytes([i]) * 32 for i in (1, 2, 3, 4))


def token(
    seq: int, holder: bytes, *, until: int = 1000, budget: int = 0, flags: int = 0
) -> TurnToken:
    return TurnToken(TL, seq, holder, budget, until, flags)


def test_codec_roundtrip_and_layout() -> None:
    t = token(7, ALICE, budget=3)
    tlv = t.encode()
    assert len(tlv.value) == 69
    assert TurnToken.decode(tlv) == t
    with pytest.raises(WireError, match="malformed"):
        TurnToken.decode(Tlv(0x52, tlv.value[:-1]))
    with pytest.raises(WireError, match="YIELD requires"):
        token(1, ALICE, flags=1)
    with pytest.raises(WireError, match="bits 1-7"):
        token(1, ALICE, flags=2)


def test_only_holder_or_moderator_moves_the_floor() -> None:
    floor = TurnFloor(TL, MOD)
    assert not floor.apply(
        token(0, ALICE), sender_pk=EVE, now_ns=0
    )  # initial token must come from MOD
    assert floor.apply(token(0, ALICE), sender_pk=MOD, now_ns=0)
    assert not floor.apply(token(1, EVE), sender_pk=EVE, now_ns=1)  # non-holder: ignored
    assert floor.holder == ALICE
    assert floor.apply(token(1, BOB), sender_pk=ALICE, now_ns=2)  # holder hands over
    assert not floor.apply(token(2, ALICE), sender_pk=ALICE, now_ns=3)  # ALICE no longer holds it
    assert floor.apply(token(2, ALICE), sender_pk=MOD, now_ns=3)  # moderator may always assign
    assert len(floor.ignored) == 3


def test_monotone_sequence_expiry_yield_and_budget() -> None:
    floor = TurnFloor(TL, MOD)
    floor.apply(token(5, ALICE, budget=2, until=100), sender_pk=MOD, now_ns=0)
    assert not floor.apply(token(5, BOB), sender_pk=MOD, now_ns=1)  # seq must increase
    assert floor.may_send(ALICE, now_ns=10)
    assert floor.may_send(ALICE, now_ns=11)
    assert not floor.may_send(ALICE, now_ns=12)  # budget exhausted
    assert not floor.may_send(BOB, now_ns=12)
    assert not floor.apply(token(6, BOB), sender_pk=ALICE, now_ns=200)  # expired holder
    assert floor.apply(token(6, bytes(32), flags=1), sender_pk=MOD, now_ns=200)  # yield
    assert floor.holder is None
    assert not floor.may_send(ALICE, now_ns=201)
    assert not floor.apply(token(7, ALICE, until=150), sender_pk=MOD, now_ns=200)  # already expired


def test_sos_is_a_single_bit() -> None:
    assert is_sos(sos_tlv())
    assert not is_sos(Tlv(0x81, b"\x01"))
    with pytest.raises(WireError):
        is_sos(Tlv(0x86, b"\x02"))
