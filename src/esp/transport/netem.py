# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""UDP impairment proxy ("netem") for testing QUIC under adverse networks (M4 gate).

Listens on a local UDP port, forwards the client's datagrams to the server and
the server's replies back, applying per-direction latency, jitter (which also
reorders), loss and duplication with a deterministic RNG.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable
from dataclasses import dataclass, field

from esp.transport.memory import FaultProfile


def _datagram(transport: asyncio.BaseTransport) -> asyncio.DatagramTransport:
    if not isinstance(transport, asyncio.DatagramTransport):
        msg = "expected a datagram transport"
        raise TypeError(msg)
    return transport


@dataclass(slots=True)
class _Stats:
    forwarded: int = 0
    dropped: int = 0
    duplicated: int = 0


class _Upstream(asyncio.DatagramProtocol):
    def __init__(self, proxy: NetemProxy) -> None:
        self._proxy = proxy
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = _datagram(transport)

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        del addr
        self._proxy.downstream(data)


@dataclass(slots=True)
class NetemProxy(asyncio.DatagramProtocol):
    server: tuple[str, int]
    up: FaultProfile
    down: FaultProfile
    stats: dict[str, _Stats] = field(default_factory=lambda: {"up": _Stats(), "down": _Stats()})
    _rng: random.Random = field(init=False)
    _transport: asyncio.DatagramTransport | None = field(default=None, init=False)
    _upstream: _Upstream | None = field(default=None, init=False)
    _client: tuple[str | int, ...] | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.up.seed * 7919 + self.down.seed)  # noqa: S311 - simulation

    async def start(self, host: str = "127.0.0.1") -> int:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(lambda: self, local_addr=(host, 0))
        self._transport = transport
        _, upstream = await loop.create_datagram_endpoint(
            lambda: _Upstream(self), remote_addr=self.server
        )
        self._upstream = upstream
        port: int = transport.get_extra_info("sockname")[1]
        return port

    async def rebind(self) -> None:
        """NAT rebinding: forward upstream from a new source port (QUIC migration test)."""
        old = self._upstream
        _, upstream = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: _Upstream(self), remote_addr=self.server
        )
        self._upstream = upstream
        if old is not None and old.transport is not None:
            old.transport.close()

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
        if self._upstream is not None and self._upstream.transport is not None:
            self._upstream.transport.close()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = _datagram(transport)

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        self._client = addr
        self._schedule(data, self.up, self.stats["up"], self._send_up)

    def downstream(self, data: bytes) -> None:
        self._schedule(data, self.down, self.stats["down"], self._send_down)

    def _schedule(
        self, data: bytes, profile: FaultProfile, stats: _Stats, sink: Callable[[bytes], None]
    ) -> None:
        if self._rng.random() < profile.loss:
            stats.dropped += 1
            return
        loop = asyncio.get_running_loop()
        copies = 2 if self._rng.random() < profile.duplicate else 1
        stats.duplicated += copies - 1
        for _ in range(copies):
            delay = max(
                0.0, profile.latency_s + self._rng.uniform(-profile.jitter_s, profile.jitter_s)
            )
            loop.call_later(delay, sink, data)
            stats.forwarded += 1

    def _send_up(self, data: bytes) -> None:
        if self._upstream is not None and self._upstream.transport is not None:
            self._upstream.transport.sendto(data)

    def _send_down(self, data: bytes) -> None:
        if self._transport is not None and self._client is not None:
            self._transport.sendto(data, self._client)
