# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-023 / WP-024: ESP over in-memory links with faults and over real QUIC."""

import asyncio
import contextlib
import dataclasses
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from esp.codec.tlv import LatentEncoding
from esp.core.taoss_types import TaossType
from esp.frame.model import DisclosurePolicy
from esp.session.driver import (
    ReceiverPump,
    establish_receiver,
    establish_sender,
    send_frame,
)
from esp.session.state import SessionState, SessionStateError
from esp.transport.base import (
    Channel,
    Connection,
    StreamDeframer,
    TransportError,
)
from esp.transport.memory import FaultProfile, memory_link
from esp.transport.netem import NetemProxy
from esp.transport.quic import QuicConnection, connect_quic, self_signed_certificate, serve_quic
from tests.integration.test_endpoint import NOW, WIRE, pair
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = pytest.mark.integration

#: INT8 latents keep a KNO frame inside one QUIC datagram.
WIRE_INT8 = dataclasses.replace(WIRE, encoding=LatentEncoding.INT8_SYM)


async def wait_until(predicate: Callable[[], bool], timeout: float = 15.0) -> None:
    """Condition-based waiting instead of fixed sleeps (robust under large latency)."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            msg = "condition not reached in time"
            raise TimeoutError(msg)
        await asyncio.sleep(0.01)


def make_clock() -> Callable[[], int]:
    """Starts at the fixtures' NOW and advances with real elapsed time."""
    start = time.monotonic_ns()
    return lambda: NOW + (time.monotonic_ns() - start)


T = TaossType
KNO = DisclosurePolicy(allowed_types=(T.KNO,))


# --- transport primitives ---------------------------------------------------------


def test_stream_deframer_handles_fragmentation_and_limits() -> None:
    d = StreamDeframer()
    framed = StreamDeframer.frame(b"hello") + StreamDeframer.frame(b"world!")
    out: list[bytes] = []
    for i in range(len(framed)):
        out += d.feed(framed[i : i + 1])
    assert out == [b"hello", b"world!"]
    with pytest.raises(TransportError, match="oversized"):
        StreamDeframer().feed(b"\xff\xff\xff\xff")


def test_memory_reliable_channels_are_ordered_and_lossless_under_faults() -> None:
    async def scenario() -> tuple[list[int], dict[str, int]]:
        a, b = memory_link(
            FaultProfile(latency_s=0.01, jitter_s=0.01, loss=0.3, duplicate=0.2, seed=3)
        )
        for i in range(200):
            await a.send(Channel.STATE, i.to_bytes(2, "big"))
            await a.send(Channel.DATAGRAM, i.to_bytes(2, "big"))
        got_state: list[int] = []
        got_dgram = 0
        while len(got_state) < 200:
            m = await asyncio.wait_for(b.receive(), 5)
            if m.channel is Channel.STATE:
                got_state.append(int.from_bytes(m.data, "big"))
            else:
                got_dgram += 1
        await asyncio.sleep(0.05)
        while not b._queue.empty():
            got_dgram += 1
            b._queue.get_nowait()
        return got_state, a.stats | {"datagrams_received": got_dgram}

    state, stats = asyncio.run(scenario())
    assert state == list(range(200))  # reliable: complete and ordered despite 30% loss
    assert stats["dropped"] > 20
    assert stats["duplicated"] > 0


# --- ESP over an impaired in-memory network (M4 gate conditions) ---------------------


async def run_session(
    tmp_path: Path, profile: FaultProfile, *, channel: Channel
) -> tuple[ReceiverPump, int]:
    sender, receiver = pair(tmp_path, wire=WIRE_INT8 if channel is Channel.DATAGRAM else WIRE)
    s_conn, r_conn = memory_link(profile)
    await asyncio.gather(establish_sender(sender, s_conn), establish_receiver(receiver, r_conn))
    clock = make_clock()
    policy = KNO
    pump = ReceiverPump(receiver, r_conn, clock=clock)
    task = asyncio.create_task(pump.run())
    sent = 0
    for _ in range(40):
        await send_frame(sender, s_conn, full_anchor_frame(), policy, channel=channel, clock=clock)
        sent += 1
    expected_min = sent if channel is Channel.STATE else 1
    await wait_until(lambda: pump.metrics.accepted_frames >= expected_min)
    await asyncio.sleep(profile.latency_s + profile.jitter_s + 0.05)  # let stragglers land
    revocation = sender.revoke(now_ns=0)
    await s_conn.send(Channel.CONTROL, revocation)
    await wait_until(lambda: receiver.revocations.revoked_capabilities != set())
    with pytest.raises(SessionStateError, match="consent was withdrawn"):
        await send_frame(sender, s_conn, full_anchor_frame(), policy, channel=channel, clock=clock)
    # a misbehaving sender that ignores its own revocation is still rejected
    sender._revoked = False
    before = len(pump.metrics.deliveries)
    await send_frame(sender, s_conn, full_anchor_frame(), KNO, channel=Channel.STATE, clock=clock)
    await wait_until(lambda: len(pump.metrics.deliveries) > before)
    await s_conn.close()
    await asyncio.wait_for(task, 5)
    return pump, sent


@pytest.mark.parametrize(
    "profile",
    [
        FaultProfile(latency_s=0.0, seed=1),
        FaultProfile(latency_s=0.05, jitter_s=0.02, loss=0.05, seed=2),
        FaultProfile(latency_s=0.2, jitter_s=0.05, loss=0.1, duplicate=0.05, seed=3),
    ],
    ids=["ideal", "moderate", "m4-worst-case"],
)
@pytest.mark.parametrize("channel", [Channel.STATE, Channel.DATAGRAM])
def test_esp_session_over_impaired_link(
    tmp_path: Path, profile: FaultProfile, channel: Channel
) -> None:
    pump, sent = asyncio.run(run_session(tmp_path, profile, channel=channel))
    deliveries = pump.metrics.deliveries
    revoked_at = next(
        i for i, d in enumerate(deliveries) if d.channel is Channel.CONTROL and d.result.control
    )
    # nothing is accepted after the revocation was processed
    assert all(not d.result.accepted for d in deliveries[revoked_at + 1 :])
    assert any(
        "13:capability or timeline revoked" in d.result.violations
        for d in deliveries[revoked_at + 1 :]
    )
    accepted = pump.metrics.accepted_frames
    if channel is Channel.STATE:
        assert accepted == sent  # reliable: every frame arrives, in order, exactly once
    else:
        assert accepted <= sent  # datagrams may be lost; duplicates are rejected as replays
        assert accepted >= sent * (1 - profile.loss) * 0.6
    assert not any(
        "replayed" not in " ".join(d.result.violations)
        and "13:" not in " ".join(d.result.violations)
        for d in deliveries
        if not d.result.accepted and d.channel is not Channel.CONTROL
    )


# --- real QUIC ---------------------------------------------------------------------------


async def quic_scenario(
    tmp_path: Path, *, netem: FaultProfile | None
) -> tuple[ReceiverPump, dict[str, float]]:
    cert, key = self_signed_certificate("localhost")
    accepted: asyncio.Queue[QuicConnection] = asyncio.Queue()
    server = await serve_quic(
        "127.0.0.1", 0, certificate_pem=cert, key_pem=key, on_connection=accepted.put_nowait
    )
    port = server._transport.get_extra_info("sockname")[1]
    proxy = None
    target_port = port
    if netem is not None:
        proxy = NetemProxy(("127.0.0.1", port), up=netem, down=netem)
        target_port = await proxy.start()
    sender, receiver = pair(tmp_path, wire=WIRE_INT8)
    try:
        async with connect_quic("127.0.0.1", target_port, ca_pem=cert) as client:
            server_conn: Connection = await asyncio.wait_for(accepted.get(), 10)
            await asyncio.wait_for(
                asyncio.gather(
                    establish_sender(sender, client), establish_receiver(receiver, server_conn)
                ),
                20,
            )
            clock = make_clock()
            pump = ReceiverPump(receiver, server_conn, clock=clock)
            task = asyncio.create_task(pump.run())
            for _ in range(20):
                await send_frame(
                    sender, client, full_anchor_frame(), KNO, channel=Channel.STATE, clock=clock
                )
                await send_frame(
                    sender, client, full_anchor_frame(), KNO, channel=Channel.DATAGRAM, clock=clock
                )
                await asyncio.sleep(0.005)
            await asyncio.sleep(1.0)
            await client.send(Channel.CONTROL, sender.revoke(now_ns=0))
            await asyncio.sleep(1.0)
            sender._revoked = False
            await send_frame(sender, client, full_anchor_frame(), KNO, channel=Channel.STATE)
            await asyncio.sleep(1.0)
            rtt = client.rtt_sample()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            return pump, {"rtt_s": rtt or 0.0}
    finally:
        if proxy is not None:
            proxy.close()
        server.close()


@pytest.mark.parametrize(
    "netem",
    [None, FaultProfile(latency_s=0.03, jitter_s=0.01, loss=0.1, seed=11)],
    ids=["loopback", "netem-10pct-loss"],
)
def test_esp_over_quic(tmp_path: Path, netem: FaultProfile | None) -> None:
    pump, info = asyncio.run(quic_scenario(tmp_path, netem=netem))
    d = pump.metrics.deliveries
    state_ok = [x for x in d if x.channel is Channel.STATE and x.result.accepted and x.result.frame]
    dgram_ok = [
        x for x in d if x.channel is Channel.DATAGRAM and x.result.accepted and x.result.frame
    ]
    revoked_at = next(
        i for i, x in enumerate(d) if x.channel is Channel.CONTROL and x.result.control
    )
    assert len(state_ok) == 20  # QUIC streams retransmit: all 20 reliable frames arrive
    assert 0 < len(dgram_ok) <= 20
    assert all(not x.result.accepted for x in d[revoked_at + 1 :])
    assert pump.metrics.percentile_ms(0.99) < 5000
    assert info["rtt_s"] > 0.0


def test_oversized_datagram_is_refused_not_silently_lost(tmp_path: Path) -> None:
    async def scenario() -> None:
        sender, receiver = pair(tmp_path)
        s_conn, r_conn = memory_link()
        await asyncio.gather(establish_sender(sender, s_conn), establish_receiver(receiver, r_conn))
        with pytest.raises(TransportError, match="datagram limit"):
            await send_frame(sender, s_conn, full_anchor_frame(), KNO, channel=Channel.DATAGRAM)

    asyncio.run(scenario())


def test_panic_and_sos_arrive_under_loss_and_stop_data(tmp_path: Path) -> None:
    async def scenario() -> tuple[int, SessionState, int]:
        sender, receiver = pair(tmp_path)
        s_conn, r_conn = memory_link(FaultProfile(latency_s=0.05, jitter_s=0.02, loss=0.1, seed=9))
        await asyncio.gather(establish_sender(sender, s_conn), establish_receiver(receiver, r_conn))
        clock = make_clock()
        pump = ReceiverPump(receiver, r_conn, clock=clock)
        task = asyncio.create_task(pump.run())
        await s_conn.send(Channel.CONTROL, sender.sos(now_ns=clock()))
        await send_frame(
            sender, s_conn, full_anchor_frame(), KNO, channel=Channel.STATE, clock=clock
        )
        await s_conn.send(Channel.CONTROL, sender.panic(now_ns=clock()))
        await wait_until(lambda: receiver.state is SessionState.CLOSED)
        await asyncio.wait_for(task, 5)
        return receiver.sos_signals, receiver.state, pump.metrics.accepted_frames

    sos, state, frames = asyncio.run(scenario())
    assert sos == 1
    assert state is SessionState.CLOSED  # PANIC terminated the session
    assert frames <= 1
