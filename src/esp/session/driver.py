# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run ESP endpoints over a transport ``Connection`` (WP-024).

- Establishment messages and every control packet (revocation, PANIC,
  close) travel on the reliable CONTROL channel (plan section 31.5).
- Frames go on STATE (reliable) or DATAGRAM (real time, may be lost).
- :class:`ReceiverPump` feeds every packet through the quarantined
  receiver and records per-frame metrics (plan WP-023).
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from esp.frame.model import DisclosurePolicy, ExperienceFrame
from esp.session.endpoint import ReceiverEndpoint, ReceiveResult, SenderEndpoint
from esp.session.state import SessionState
from esp.transport.base import Channel, Connection, ConnectionClosedError, TransportError

Clock = Callable[[], int]


def wall_clock_ns() -> int:
    """Default clock. Capabilities carry absolute (Unix epoch) validity times."""
    return time.time_ns()


async def _control(conn: Connection, timeout: float) -> bytes:
    while True:
        message = await asyncio.wait_for(conn.receive(), timeout)
        if message.channel is Channel.CONTROL:
            return message.data


async def establish_sender(
    sender: SenderEndpoint, conn: Connection, *, timeout: float = 10.0
) -> None:
    await conn.send(Channel.CONTROL, sender.start())
    sender.on_handshake2(await _control(conn, timeout))
    t2 = sender.on_transport1(await _control(conn, timeout))
    await conn.send(Channel.CONTROL, t2)


async def establish_receiver(
    receiver: ReceiverEndpoint, conn: Connection, *, timeout: float = 10.0
) -> None:
    hs2, t1 = receiver.on_handshake1(await _control(conn, timeout))
    await conn.send(Channel.CONTROL, hs2)
    await conn.send(Channel.CONTROL, t1)
    receiver.on_transport2(await _control(conn, timeout))


async def send_frame(
    sender: SenderEndpoint,
    conn: Connection,
    frame: ExperienceFrame,
    policy: DisclosurePolicy,
    *,
    channel: Channel = Channel.STATE,
    clock: Clock = wall_clock_ns,
) -> bytes:
    if channel is Channel.CONTROL or channel is Channel.BULK:
        msg = "frames travel on STATE or DATAGRAM"
        raise TransportError(msg)
    packet = sender.send_frame(frame, policy, now_ns=clock())
    await conn.send(channel, packet)
    return packet


async def send_control(
    sender: SenderEndpoint, conn: Connection, tlvs: bytes, *, clock: Clock = wall_clock_ns
) -> bytes:
    """Control packets are only ever sent on the reliable CONTROL channel."""
    packet = sender.send_control(tlvs, now_ns=clock())
    await conn.send(Channel.CONTROL, packet)
    return packet


@dataclass(frozen=True, slots=True)
class Delivery:
    channel: Channel
    result: ReceiveResult
    latency_ns: int


@dataclass(slots=True)
class Metrics:
    deliveries: list[Delivery] = field(default_factory=list)

    def latencies_ms(self) -> list[float]:
        return sorted(
            d.latency_ns / 1e6 for d in self.deliveries if d.result.accepted and d.result.frame
        )

    def percentile_ms(self, q: float) -> float:
        values = self.latencies_ms()
        if not values:
            return math.nan
        return values[min(len(values) - 1, max(0, math.ceil(q * len(values)) - 1))]

    @property
    def accepted_frames(self) -> int:
        return sum(1 for d in self.deliveries if d.result.accepted and d.result.frame is not None)

    @property
    def rejected(self) -> int:
        return sum(1 for d in self.deliveries if not d.result.accepted)


class ReceiverPump:
    """Consumes a connection and pushes every packet through the receiver."""

    def __init__(
        self, receiver: ReceiverEndpoint, conn: Connection, *, clock: Clock = wall_clock_ns
    ) -> None:
        self._receiver = receiver
        self._conn = conn
        self._clock = clock
        self.metrics = Metrics()
        self._frames: asyncio.Queue[ReceiveResult] = asyncio.Queue()

    async def run(self) -> None:
        try:
            while self._receiver.state is not SessionState.CLOSED:
                message = await self._conn.receive()
                arrived = self._clock()
                result = self._receiver.receive(message.data, now_ns=arrived)
                sent_at = _header_timestamp(message.data)
                self.metrics.deliveries.append(
                    Delivery(message.channel, result, max(0, arrived - sent_at))
                )
                if result.accepted and result.frame is not None:
                    self._frames.put_nowait(result)
        except ConnectionClosedError:
            return

    async def next_frame(self, timeout: float = 5.0) -> ReceiveResult:
        return await asyncio.wait_for(self._frames.get(), timeout)


def _header_timestamp(packet: bytes) -> int:
    if len(packet) < 24:
        return 0
    return int.from_bytes(packet[16:24], "big")
