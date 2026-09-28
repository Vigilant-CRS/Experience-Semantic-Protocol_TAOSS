# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-023 open items: disconnect/reconnect, QUIC connection migration, metrics report.

V13 mandates a fresh handshake after state loss and has no resumption: a
reconnect is a *new* ESP session. Consent state (revocations, segment
budgets) lives in the receiver and must survive it.
"""

import asyncio
import contextlib
from pathlib import Path

import pytest

from esp.consent.accept import AcceptState
from esp.consent.capability import SenderCapability
from esp.consent.revocation import RevocationRegistry
from esp.crypto.noise_ik import StaticKeyPair
from esp.crypto.primitives import CryptoError
from esp.session.driver import ReceiverPump, establish_receiver, establish_sender, send_frame
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint
from esp.session.state import SessionState
from esp.transport.base import Channel, ConnectionClosedError
from esp.transport.memory import FaultProfile, memory_link
from esp.transport.netem import NetemProxy
from esp.transport.quic import QuicConnection, connect_quic, self_signed_certificate, serve_quic
from tests.integration.test_endpoint import (
    MASTER,
    RECEIVER_ID,
    descriptor,
    receiver_capability_for,
    sender_capability,
)
from tests.integration.test_transport import KNO, WIRE_INT8, make_clock, wait_until
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = pytest.mark.integration


class ReceiverHost:
    """A receiver host whose consent state outlives individual sessions."""

    def __init__(self) -> None:
        self.static = StaticKeyPair.generate()
        self.accept_state = AcceptState()
        self.revocations = RevocationRegistry()

    def endpoint(self) -> ReceiverEndpoint:
        return ReceiverEndpoint(
            identity=RECEIVER_ID,
            static=self.static,
            descriptor=descriptor(),
            capability=receiver_capability_for(0x3F),
            trusted_issuers=frozenset({MASTER.public_bytes}),
            wire=WIRE_INT8,
            accept_state=self.accept_state,
            revocations=self.revocations,
        )


def sender_for(host: ReceiverHost, cap: SenderCapability, tmp_path: Path) -> SenderEndpoint:
    return SenderEndpoint(
        master=MASTER,
        static=StaticKeyPair.generate(),
        responder_static=host.static.public_bytes,
        receiver_identity=RECEIVER_ID.public_bytes,
        descriptor=descriptor(),
        capability=cap,
        state_dir=tmp_path,
        wire=WIRE_INT8,
    )


def test_reconnect_is_a_new_session_and_consent_state_survives(tmp_path: Path) -> None:
    host = ReceiverHost()
    cap = sender_capability(max_segments=15)

    async def session(n_frames: int, *, revoke: bool = False) -> tuple[int, SenderEndpoint]:
        sender, receiver = sender_for(host, cap, tmp_path), host.endpoint()
        a, b = memory_link(FaultProfile(latency_s=0.005, seed=4))
        await asyncio.gather(establish_sender(sender, a), establish_receiver(receiver, b))
        clock = make_clock()
        pump = ReceiverPump(receiver, b, clock=clock)
        task = asyncio.create_task(pump.run())
        for _ in range(n_frames):
            await send_frame(sender, a, full_anchor_frame(), KNO, clock=clock)
        await wait_until(lambda: len(pump.metrics.deliveries) >= n_frames)
        if revoke:
            await a.send(Channel.CONTROL, sender.revoke(now_ns=clock()))
            await wait_until(lambda: bool(host.revocations.revoked_capabilities))
        await b.close()  # the link dies (receiver side)
        await asyncio.wait_for(task, 5)
        assert receiver.state is SessionState.CLOSED
        if not revoke:  # a revoked sender refuses before touching the transport
            with pytest.raises(ConnectionClosedError):
                await send_frame(sender, a, full_anchor_frame(), KNO, clock=clock)
            assert sender.state is SessionState.CLOSED  # no resumption of the old session
        return pump.metrics.accepted_frames, sender

    async def scenario() -> tuple[int, int, SenderEndpoint, SenderEndpoint]:
        first, s1 = await session(10)
        second, s2 = await session(10, revoke=True)
        return first, second, s1, s2

    first, second, s1, s2 = asyncio.run(scenario())
    assert first == 10
    assert second == 5  # max_segments = 15 counted across sessions
    assert s1.timeline_id != s2.timeline_id  # a fresh handshake, a fresh timeline

    # after revocation the capability cannot open a new session at all
    sender, receiver = sender_for(host, cap, tmp_path), host.endpoint()
    hs2, t1 = receiver.on_handshake1(sender.start())
    sender.on_handshake2(hs2)
    with pytest.raises(CryptoError, match="revoked"):
        receiver.on_transport2(sender.on_transport1(t1))
    assert receiver.state is SessionState.CLOSED


async def _quic_setup(host: ReceiverHost) -> tuple[bytes, object, int]:
    cert, key = self_signed_certificate("localhost")
    accepted: asyncio.Queue[QuicConnection] = asyncio.Queue()
    server = await serve_quic(
        "127.0.0.1", 0, certificate_pem=cert, key_pem=key, on_connection=accepted.put_nowait
    )
    host.quic_accepted = accepted  # type: ignore[attr-defined]
    return cert, server, server._transport.get_extra_info("sockname")[1]


def test_quic_connection_migration_keeps_the_esp_session(tmp_path: Path) -> None:
    host = ReceiverHost()

    async def scenario() -> tuple[int, tuple[object, object]]:
        cert, server, port = await _quic_setup(host)
        proxy = NetemProxy(("127.0.0.1", port), up=FaultProfile(), down=FaultProfile())
        target = await proxy.start()
        sender, receiver = sender_for(host, sender_capability(), tmp_path), host.endpoint()
        try:
            async with connect_quic("127.0.0.1", target, ca_pem=cert) as client:
                server_conn = await asyncio.wait_for(host.quic_accepted.get(), 10)  # type: ignore[attr-defined]
                await asyncio.gather(
                    establish_sender(sender, client), establish_receiver(receiver, server_conn)
                )
                clock = make_clock()
                pump = ReceiverPump(receiver, server_conn, clock=clock)
                task = asyncio.create_task(pump.run())
                paths = server_conn._protocol._quic._network_paths
                before = paths[0].addr
                for _ in range(10):
                    await send_frame(sender, client, full_anchor_frame(), KNO, clock=clock)
                await wait_until(lambda: pump.metrics.accepted_frames >= 10)
                await proxy.rebind()  # NAT rebinding: new source address for the client
                for _ in range(10):
                    await send_frame(sender, client, full_anchor_frame(), KNO, clock=clock)
                await wait_until(lambda: pump.metrics.accepted_frames >= 20)
                after = server_conn._protocol._quic._network_paths[0].addr
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                return pump.metrics.accepted_frames, (before, after)
        finally:
            proxy.close()
            server.close()  # type: ignore[attr-defined]

    accepted, (before, after) = asyncio.run(scenario())
    assert accepted == 20
    assert before != after  # the server migrated to the new path, the ESP session continued


def test_quic_disconnect_then_reconnect_with_fresh_handshake(tmp_path: Path) -> None:
    host = ReceiverHost()

    async def scenario() -> list[int]:
        cert, server, port = await _quic_setup(host)
        counts = []
        try:
            for _ in range(2):
                sender, receiver = sender_for(host, sender_capability(), tmp_path), host.endpoint()
                async with connect_quic("127.0.0.1", port, ca_pem=cert) as client:
                    server_conn = await asyncio.wait_for(host.quic_accepted.get(), 10)  # type: ignore[attr-defined]
                    await asyncio.gather(
                        establish_sender(sender, client), establish_receiver(receiver, server_conn)
                    )
                    clock = make_clock()
                    pump = ReceiverPump(receiver, server_conn, clock=clock)
                    task = asyncio.create_task(pump.run())
                    for _ in range(5):
                        await send_frame(sender, client, full_anchor_frame(), KNO, clock=clock)
                    await wait_until(lambda p=pump: p.metrics.accepted_frames >= 5)
                    counts.append(pump.metrics.accepted_frames)
                await asyncio.wait_for(task, 10)  # client gone -> pump ends, session aborted
                assert receiver.state is SessionState.CLOSED
        finally:
            server.close()  # type: ignore[attr-defined]
        return counts

    assert asyncio.run(scenario()) == [5, 5]


def test_metrics_report_covers_the_wp023_set(tmp_path: Path) -> None:
    host = ReceiverHost()

    async def scenario() -> dict[str, float]:
        sender, receiver = sender_for(host, sender_capability(), tmp_path), host.endpoint()
        a, b = memory_link(FaultProfile(latency_s=0.02, jitter_s=0.005, loss=0.1, seed=8))
        await asyncio.gather(establish_sender(sender, a), establish_receiver(receiver, b))
        clock = make_clock()
        pump = ReceiverPump(receiver, b, clock=clock)
        task = asyncio.create_task(pump.run())
        for _ in range(50):
            await send_frame(
                sender, a, full_anchor_frame(), KNO, channel=Channel.DATAGRAM, clock=clock
            )
            await asyncio.sleep(0.002)
        await asyncio.sleep(0.1)
        report = pump.metrics.report(frames_sent=50, now_ns=clock())
        await a.close()
        await asyncio.wait_for(task, 5)
        return report

    r = asyncio.run(scenario())
    assert set(r) >= {
        "p50_latency_ms",
        "p95_latency_ms",
        "p99_latency_ms",
        "throughput_frames_s",
        "throughput_kbit_s",
        "mean_frame_age_ms",
        "loss",
        "freshness_ms",
    }
    assert 15 <= r["p50_latency_ms"] <= r["p95_latency_ms"] <= r["p99_latency_ms"] < 200
    assert 0.0 < r["loss"] < 0.35  # ~10 % configured datagram loss
    assert r["throughput_frames_s"] > 0
    assert r["freshness_ms"] >= 100  # newest frame was sent >= 100 ms before the report
