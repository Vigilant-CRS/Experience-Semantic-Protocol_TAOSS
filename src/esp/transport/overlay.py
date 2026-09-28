# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Onion/mixnet hook (WP-062): wrap any ``Connection`` with byte-level layers.

ESP's end-to-end protection does not depend on the overlay. An overlay adds
network-level unlinkability (who talks to whom), which ESP alone cannot
provide. :class:`LayeredConnection` is the integration point: ``wrap`` is
applied to every outgoing message and ``unwrap`` to every incoming one
(e.g. Sphinx packet construction and processing by a mixnet client library).
"""

from __future__ import annotations

from collections.abc import Callable

from esp.transport.base import Channel, Connection, Message

Layer = Callable[[Channel, bytes], bytes]


class LayeredConnection:
    def __init__(self, inner: Connection, *, wrap: Layer, unwrap: Layer) -> None:
        self._inner = inner
        self._wrap = wrap
        self._unwrap = unwrap

    async def send(self, channel: Channel, data: bytes) -> None:
        await self._inner.send(channel, self._wrap(channel, data))

    async def receive(self) -> Message:
        message = await self._inner.receive()
        return Message(message.channel, self._unwrap(message.channel, message.data))

    async def close(self) -> None:
        await self._inner.close()

    def rtt_sample(self) -> float | None:
        return self._inner.rtt_sample()

    @property
    def max_datagram_payload(self) -> int:
        return self._inner.max_datagram_payload
