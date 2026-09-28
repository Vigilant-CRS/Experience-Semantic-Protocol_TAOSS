# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic in-memory network with fault injection (ADR-0001).

Reliable channels behave like QUIC streams: ordered and lossless; loss only
shows up as retransmission delay (head-of-line). Datagrams may be dropped,
reordered (via jitter) or duplicated.
"""

from __future__ import annotations

import asyncio
import dataclasses
import random
from dataclasses import dataclass, field

from esp.transport.base import (
    DEFAULT_MAX_DATAGRAM_PAYLOAD,
    RELIABLE,
    Channel,
    ConnectionClosedError,
    Message,
    check_datagram_size,
)

_ORDER_EPSILON_S = 1e-6


@dataclass(frozen=True, slots=True)
class FaultProfile:
    latency_s: float = 0.0
    jitter_s: float = 0.0
    loss: float = 0.0
    duplicate: float = 0.0
    seed: int = 0

    def __post_init__(self) -> None:
        for name in ("latency_s", "jitter_s"):
            if getattr(self, name) < 0.0:
                msg = f"{name} must be non-negative"
                raise ValueError(msg)
        for name in ("loss", "duplicate"):
            if not 0.0 <= getattr(self, name) < 1.0:
                msg = f"{name} must be in [0, 1)"
                raise ValueError(msg)


@dataclass(slots=True)
class _Direction:
    profile: FaultProfile
    rng: random.Random
    last_reliable: dict[Channel, float] = field(default_factory=dict)
    stats: dict[str, int] = field(
        default_factory=lambda: {"sent": 0, "dropped": 0, "duplicated": 0}
    )


class MemoryConnection:
    """One end of an in-memory link."""

    def __init__(self, direction: _Direction) -> None:
        self._out = direction
        self._queue: asyncio.Queue[Message | None] = asyncio.Queue()
        self._peer: MemoryConnection | None = None
        self._closed = False

    def _delay(self) -> float:
        p = self._out.profile
        return max(0.0, p.latency_s + self._out.rng.uniform(-p.jitter_s, p.jitter_s))

    async def send(self, channel: Channel, data: bytes) -> None:
        peer = self._peer
        if self._closed or peer is None or peer._closed:
            msg = "connection closed"
            raise ConnectionClosedError(msg)
        loop = asyncio.get_running_loop()
        now = loop.time()
        direction = self._out
        direction.stats["sent"] += 1
        delay = self._delay()
        if channel in RELIABLE:
            # loss => retransmission after ~3 RTTs; order preserved (head-of-line)
            while direction.rng.random() < direction.profile.loss:
                delay += 3 * max(direction.profile.latency_s, 0.001) * 2
            # strictly increasing per channel: asyncio does not order equal deadlines
            at = max(now + delay, direction.last_reliable.get(channel, 0.0) + _ORDER_EPSILON_S)
            direction.last_reliable[channel] = at
            loop.call_at(at, peer._deliver, Message(channel, data))
            return
        check_datagram_size(data, self.max_datagram_payload)
        if direction.rng.random() < direction.profile.loss:
            direction.stats["dropped"] += 1
            return
        loop.call_at(now + delay, peer._deliver, Message(channel, data))
        if direction.rng.random() < direction.profile.duplicate:
            direction.stats["duplicated"] += 1
            loop.call_at(now + self._delay(), peer._deliver, Message(channel, data))

    def _deliver(self, message: Message) -> None:
        if not self._closed:
            self._queue.put_nowait(message)

    async def receive(self) -> Message:
        if self._closed:
            msg = "connection closed"
            raise ConnectionClosedError(msg)
        item = await self._queue.get()
        if item is None:
            msg = "peer closed the connection"
            raise ConnectionClosedError(msg)
        return item

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._queue.put_nowait(None)  # wake a receive() pending on this side
            if self._peer is not None and not self._peer._closed:
                self._peer._queue.put_nowait(None)

    def rtt_sample(self) -> float | None:
        return 2 * self._out.profile.latency_s

    @property
    def max_datagram_payload(self) -> int:
        return DEFAULT_MAX_DATAGRAM_PAYLOAD

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._out.stats)


def memory_link(
    a_to_b: FaultProfile | None = None, b_to_a: FaultProfile | None = None
) -> tuple[MemoryConnection, MemoryConnection]:
    """Two connected ends; ``b_to_a`` defaults to ``a_to_b`` with its own seed."""
    ab = a_to_b if a_to_b is not None else FaultProfile()
    ba = b_to_a if b_to_a is not None else dataclasses.replace(ab, seed=ab.seed + 1)
    a = MemoryConnection(_Direction(ab, random.Random(ab.seed)))  # noqa: S311 - simulation only
    b = MemoryConnection(_Direction(ba, random.Random(ba.seed)))  # noqa: S311 - simulation only
    a._peer, b._peer = b, a
    return a, b
