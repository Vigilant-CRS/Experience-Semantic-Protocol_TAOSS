# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Turn-taking (TLV_TURN_TOKEN 0x52), SOS and PANIC (V13 sections 8.4, 16; WP-064).

Turn-token authority (V13, V13 closure):

- the token established by a packet names the holder *after* that packet;
- the initial token comes from the profile-declared moderator;
- afterwards a token is accepted only if the authenticated enclosing packet
  was sent by the current holder or by the moderator — tokens from anyone
  else are *ignored*, even if well formed;
- ``turn_seq`` strictly increases; ``YIELD`` requires an all-zero holder and
  leaves the floor unassigned; tokens expire (``valid_until_ns``);
- ``packet_budget`` bounds the holder's packets (0 = until yield/expiry).

SOS (GAP-028, ADR-0026 proposal): addendum TLV ``0x86`` with a single byte
``0x01`` on the CONTROL channel — a 1-bit signal without EMO or KNO.
PANIC: ``TLV_REVOCATION_INTENT`` with ``TERMINATE_SESSIONS`` on CONTROL.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from typing import Final

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv

TURN_TOKEN_CODE: Final = 0x52
SOS_CODE: Final = 0x86
_TOKEN: Final = struct.Struct(">16sQ32sIQB")  # 69 bytes
YIELD: Final = 0x01
ZERO_PK: Final = bytes(32)


@dataclass(frozen=True, slots=True)
class TurnToken:
    timeline_id: uuid.UUID
    turn_seq: int
    holder_session_pk: bytes
    packet_budget: int
    valid_until_ns: int
    flags: int = 0

    def __post_init__(self) -> None:
        if self.flags & ~YIELD:
            msg = "turn token flags bits 1-7 must be zero"
            raise WireError(msg)
        if len(self.holder_session_pk) != 32:
            msg = "holder key must be 32 bytes"
            raise WireError(msg)
        if (self.flags & YIELD) and self.holder_session_pk != ZERO_PK:
            msg = "YIELD requires an all-zero holder"
            raise WireError(msg)

    @property
    def is_yield(self) -> bool:
        return bool(self.flags & YIELD)

    def encode(self) -> Tlv:
        return Tlv(
            TURN_TOKEN_CODE,
            _TOKEN.pack(
                self.timeline_id.bytes,
                self.turn_seq,
                self.holder_session_pk,
                self.packet_budget,
                self.valid_until_ns,
                self.flags,
            ),
        )

    @classmethod
    def decode(cls, tlv: Tlv) -> TurnToken:
        if tlv.code != TURN_TOKEN_CODE or len(tlv.value) != _TOKEN.size:
            msg = "malformed turn token"
            raise WireError(msg)
        tid, seq, holder, budget, until, flags = _TOKEN.unpack(tlv.value)
        return cls(uuid.UUID(bytes=tid), seq, holder, budget, until, flags)


@dataclass(slots=True)
class TurnFloor:
    """Receiver-side floor state for one timeline."""

    timeline_id: uuid.UUID
    moderator_pk: bytes
    holder: bytes | None = None
    last_seq: int = -1
    valid_until_ns: int = 0
    budget: int = 0
    used: int = 0
    ignored: list[TurnToken] = field(default_factory=list)

    def apply(self, token: TurnToken, *, sender_pk: bytes, now_ns: int) -> bool:
        """Apply a token carried by an authenticated packet from ``sender_pk``."""
        authorized = sender_pk == self.moderator_pk or (
            self.holder is not None and sender_pk == self.holder and self._current(now_ns)
        )
        valid = (
            authorized
            and token.timeline_id == self.timeline_id
            and token.turn_seq > self.last_seq
            and token.valid_until_ns > now_ns
        )
        if not valid:
            self.ignored.append(token)  # ignored, never an error: non-holders cannot move the floor
            return False
        self.last_seq = token.turn_seq
        self.holder = None if token.is_yield else token.holder_session_pk
        self.valid_until_ns = token.valid_until_ns
        self.budget = token.packet_budget
        self.used = 0
        return True

    def _current(self, now_ns: int) -> bool:
        return self.holder is not None and now_ns < self.valid_until_ns

    def may_send(self, sender_pk: bytes, *, now_ns: int) -> bool:
        """Is ``sender_pk`` the current holder with budget left? Counts the packet if so."""
        if not self._current(now_ns) or sender_pk != self.holder:
            return False
        if self.budget and self.used >= self.budget:
            return False
        self.used += 1
        return True


def sos_tlv() -> Tlv:
    return Tlv(SOS_CODE, b"\x01")


def is_sos(tlv: Tlv) -> bool:
    if tlv.code != SOS_CODE:
        return False
    if tlv.value != b"\x01":
        msg = "malformed SOS"
        raise WireError(msg)
    return True
