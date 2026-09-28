# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Transport abstraction (plan section 31, ADR-0001).

ESP is an application protocol. It needs:

- CONTROL: reliable, ordered (HELLO/negotiation, capabilities, consent,
  revocation, PANIC, close) — never an unreliable datagram (plan 31.5);
- STATE: reliable, ordered ExperienceFrames;
- BULK: reliable (registry snapshots, bundles, benchmark data);
- DATAGRAM: optional unreliable real-time state (stale frames are worthless).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Final, Protocol

from esp.core.errors import ErrorCode, EspError

MAX_MESSAGE: Final = (1 << 20) + 4096

#: Conservative ESP payload limit for one QUIC DATAGRAM frame: the frame must fit in a
#: single QUIC packet (1200-byte minimum datagram size minus short header, packet
#: number, AEAD tag and frame overhead). Oversized datagrams are refused, never queued.
DEFAULT_MAX_DATAGRAM_PAYLOAD: Final = 1100


@unique
class Channel(IntEnum):
    CONTROL = 0
    STATE = 1
    BULK = 2
    DATAGRAM = 3


RELIABLE: Final = frozenset({Channel.CONTROL, Channel.STATE, Channel.BULK})


class TransportError(EspError):
    code = ErrorCode.SESSION_STATE


class ConnectionClosedError(TransportError):
    """The peer closed the connection (or it failed)."""


@dataclass(frozen=True, slots=True)
class Message:
    channel: Channel
    data: bytes


class Connection(Protocol):
    async def send(self, channel: Channel, data: bytes) -> None: ...

    async def receive(self) -> Message: ...

    async def close(self) -> None: ...

    def rtt_sample(self) -> float | None:
        """Latest RTT estimate in seconds, if the transport measures one."""
        ...

    @property
    def max_datagram_payload(self) -> int:
        """Largest message accepted on the DATAGRAM channel."""
        ...


def check_datagram_size(data: bytes, limit: int) -> None:
    if len(data) > limit:
        msg = (
            f"{len(data)}-byte packet exceeds the {limit}-byte datagram limit; "
            "use the STATE channel, INT8 quantization or fewer types"
        )
        raise TransportError(msg)


class StreamDeframer:
    """Length-prefixed framing on reliable byte streams (``u32 length || data``)."""

    __slots__ = ("_buffer",)

    def __init__(self) -> None:
        self._buffer = bytearray()

    @staticmethod
    def frame(data: bytes) -> bytes:
        if len(data) > MAX_MESSAGE:
            msg = "message exceeds the transport maximum"
            raise TransportError(msg)
        return struct.pack(">I", len(data)) + data

    def feed(self, chunk: bytes) -> list[bytes]:
        self._buffer += chunk
        out: list[bytes] = []
        while len(self._buffer) >= 4:
            (n,) = struct.unpack_from(">I", self._buffer, 0)
            if n > MAX_MESSAGE:
                msg = "peer announced an oversized message"
                raise TransportError(msg)
            if len(self._buffer) < 4 + n:
                break
            out.append(bytes(self._buffer[4 : 4 + n]))
            del self._buffer[: 4 + n]
        if len(self._buffer) > MAX_MESSAGE + 4:  # pragma: no cover - guarded above
            msg = "stream buffer overflow"
            raise TransportError(msg)
        return out
