# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Plain TCP test transport (interop with independent implementations, WP-042).

Framing: ``len u32 BE · channel u8 · data`` (``len`` counts channel + data).
No transport security: ESP's Noise/AEAD/signature layer still protects end to
end, but metadata is exposed — use QUIC (ADR-0001) outside of tests.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from typing import Final

from esp.transport.base import (
    DEFAULT_MAX_DATAGRAM_PAYLOAD,
    MAX_MESSAGE,
    Channel,
    ConnectionClosedError,
    Message,
    TransportError,
)

_LEN: Final = struct.Struct(">I")


class TcpConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader, self._writer = reader, writer
        self._closed = False

    async def send(self, channel: Channel, data: bytes) -> None:
        if self._closed:
            msg = "connection closed"
            raise ConnectionClosedError(msg)
        if len(data) + 1 > MAX_MESSAGE:
            msg = "message too large"
            raise TransportError(msg)
        self._writer.write(_LEN.pack(len(data) + 1) + bytes([channel]) + data)
        await self._writer.drain()

    async def receive(self) -> Message:
        try:
            (n,) = _LEN.unpack(await self._reader.readexactly(4))
            if not 1 <= n <= MAX_MESSAGE:
                msg = "bad frame length"
                raise TransportError(msg)
            body = await self._reader.readexactly(n)
        except (asyncio.IncompleteReadError, ConnectionError):
            msg = "peer closed the connection"
            raise ConnectionClosedError(msg) from None
        try:
            channel = Channel(body[0])
        except ValueError:
            msg = "unknown channel"
            raise TransportError(msg) from None
        return Message(channel, body[1:])

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await self._writer.wait_closed()

    def rtt_sample(self) -> float | None:
        return None

    @property
    def max_datagram_payload(self) -> int:
        return DEFAULT_MAX_DATAGRAM_PAYLOAD


async def connect_tcp(host: str, port: int) -> TcpConnection:
    reader, writer = await asyncio.open_connection(host, port)
    return TcpConnection(reader, writer)
