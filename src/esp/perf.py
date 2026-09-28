# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Performance and rate benchmarks (WP-043).

Per frame, over a real established session (Noise IK, capabilities):

- encode latency (frame -> payload), crypto latency (seal + open),
  decode latency (payload -> frame), total (send + quarantined receive),
- bandwidth (wire bytes per frame and kbit/s at 10 / 25 / 50 Hz, compared
  with the V13 rate arithmetic), network latency over the in-memory link,
- memory (tracemalloc peak) and CPU (process time / wall time).

Results are a JSON-able dict; ``python -m esp.perf`` prints one.
"""

from __future__ import annotations

import asyncio
import json
import statistics
import sys
import tempfile
import time
import tracemalloc
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from esp.codec.frame_wire import WireOptions, frame_to_payload, payload_to_frame
from esp.codec.header import HEADER_LEN, Header
from esp.codec.tlv import LatentEncoding
from esp.conformance.interop import DECLARATION
from esp.consent.capability import AudienceMode, ReceiverCapability, Rights, SenderCapability
from esp.core.clock import ClockStamp
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.crypto.envelope import open_packet
from esp.crypto.noise_ik import StaticKeyPair
from esp.crypto.primitives import SigningKey
from esp.frame.model import DisclosurePolicy, ExperienceFrame, TypeBlock
from esp.session.descriptor import SessionDescriptor
from esp.session.driver import ReceiverPump, send_frame
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint
from esp.session.profiles import bitrate_kbit_s, profile_for, release_bytes
from esp.transport.memory import FaultProfile, memory_link

RATES_HZ = (10, 25, 50)
HOUR = 3600 * 10**9


def frame(types: tuple[TaossType, ...], seq: int = 0) -> ExperienceFrame:
    blocks = tuple(
        TypeBlock(type=t, latent=tuple(((i * 31 + seq) % 17 - 8) / 8.0 for i in range(L1_DIMS[t])))
        for t in types
    )
    now = time.time_ns()
    return ExperienceFrame(
        frame_id=uuid.uuid4(),
        timeline_id=uuid.uuid4(),
        sequence=seq,
        timestamp=ClockStamp(source_ns=now, monotonic_ns=now, clock_domain="bench", sequence=seq),
        types=blocks,
    )


def session(
    sf: int, encoding: LatentEncoding, state_dir: Path
) -> tuple[SenderEndpoint, ReceiverEndpoint]:
    master, identity, r_static = (
        SigningKey.generate(),
        SigningKey.generate(),
        StaticKeyPair.generate(),
    )
    wire = WireOptions(encoding=encoding)

    def cap(noise_h: bytes) -> ReceiverCapability:
        return ReceiverCapability(
            accept_types=0x3F,
            max_norm=(1000.0,) * 6,
            valence_bounds=(-1.0, 1.0),
            rate_limit_hz=10000,
            valid_from_ns=0,
            valid_until_ns=time.time_ns() + HOUR,
            nonce=uuid.uuid4().bytes,
            pk_receiver=identity.public_bytes,
            noise_h=noise_h,
        )

    sender = SenderEndpoint(
        master=master,
        static=StaticKeyPair.generate(),
        responder_static=r_static.public_bytes,
        receiver_identity=identity.public_bytes,
        descriptor=SessionDescriptor(sf_level=sf),
        capability=SenderCapability(
            capability_id=uuid.uuid4(),
            types_allowed=0x3F,
            rights=Rights(0),
            max_segments=10**9,
            dp_epsilon_ceiling=0.0,
            valid_until_ns=time.time_ns() + HOUR,
            audience_mode=AudienceMode.RECIPIENT_PUBKEY,
            audience_value=identity.public_bytes,
            issuer_pk=master.public_bytes,
            nonce=uuid.uuid4().bytes,
        ),
        state_dir=state_dir,
        wire=wire,
        declaration=DECLARATION,
    )
    receiver = ReceiverEndpoint(
        identity=identity,
        static=r_static,
        descriptor=SessionDescriptor(sf_level=sf),
        capability=cap,
        trusted_issuers=frozenset({master.public_bytes}),
        wire=wire,
        declaration=DECLARATION,
    )
    hs2, t1 = receiver.on_handshake1(sender.start())
    sender.on_handshake2(hs2)
    receiver.on_transport2(sender.on_transport1(t1))
    return sender, receiver


def _timed(fn: Callable[[], object], n: int) -> list[float]:
    out = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        out.append((time.perf_counter_ns() - t0) / 1e6)
    return out


def _stats(ms: list[float]) -> dict[str, float]:
    s = sorted(ms)
    return {
        "p50_ms": round(s[len(s) // 2], 4),
        "p99_ms": round(s[int(len(s) * 0.99) - 1], 4),
        "mean_ms": round(statistics.fmean(s), 4),
    }


def bench_profile(sf: int, encoding: LatentEncoding, n: int = 300) -> dict[str, Any]:
    types = tuple(sorted(profile_for(sf).required, key=lambda t: t.value))
    policy = DisclosurePolicy(allowed_types=types)
    with tempfile.TemporaryDirectory() as d:
        sender, receiver = session(sf, encoding, Path(d))
        f = frame(types)
        wire = WireOptions(encoding=encoding)
        encoded = frame_to_payload(f, wire)
        packets: list[bytes] = []
        now = time.time_ns()

        def total() -> None:
            p = sender.send_frame(f, policy, now_ns=now)
            packets.append(p)
            r = receiver.receive(p, now_ns=now)
            if not r.accepted:  # pragma: no cover - benchmark sanity
                msg = f"benchmark packet rejected: {r.violations}"
                raise RuntimeError(msg)

        tracemalloc.start()
        cpu0, wall0 = time.process_time(), time.perf_counter()
        total_ms = _timed(total, n)
        cpu = (time.process_time() - cpu0) / (time.perf_counter() - wall0)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        header = Header.decode(packets[0][:HEADER_LEN])
        active = receiver._active  # measurement only
        if active is None:  # pragma: no cover
            msg = "session not active"
            raise RuntimeError(msg)
        keys = active.keys
        crypto_ms = _timed(
            lambda: open_packet(
                packets[0], keys, expected_sender=header.sender_id, max_payload_len=1 << 20
            ),
            n,
        )
        encode_ms = _timed(lambda: frame_to_payload(f, wire), n)
        decode_ms = _timed(lambda: payload_to_frame(header, encoded.payload, wire), n)
        size = len(packets[0])
        bpc = {LatentEncoding.F32_BE: 4, LatentEncoding.F16_BE: 2, LatentEncoding.INT8_SYM: 1}[
            encoding
        ]
        return {
            "sf_level": sf,
            "encoding": encoding.name,
            "types": [t.name for t in types],
            "encode": _stats(encode_ms),
            "open_verify_decrypt": _stats(crypto_ms),
            "decode": _stats(decode_ms),
            "total_send_receive": _stats(total_ms),
            "wire_bytes_per_frame": size,
            "v13_bytes_per_release": release_bytes(frozenset(types), bytes_per_coordinate=bpc),
            "kbit_s": {f"{hz}Hz": round(bitrate_kbit_s(size, hz), 1) for hz in RATES_HZ},
            "max_sustainable_hz": round(1000 / _stats(total_ms)["p99_ms"]),
            "peak_memory_kib": round(peak / 1024, 1),
            "cpu_fraction": round(cpu, 3),
        }


def network_latency(n: int = 50, latency_s: float = 0.0) -> dict[str, float]:
    async def run() -> list[float]:
        with tempfile.TemporaryDirectory() as d:
            sender, receiver = session(0, LatentEncoding.INT8_SYM, Path(d))
            # re-run the handshake over the link is not needed: endpoints are already ACTIVE
            a, b = memory_link(FaultProfile(latency_s=latency_s, seed=1))
            pump = ReceiverPump(receiver, b, clock=time.time_ns)
            task = asyncio.create_task(pump.run())
            f = frame((TaossType.KNO,))
            policy = DisclosurePolicy(allowed_types=(TaossType.KNO,))
            for _ in range(n):
                await send_frame(sender, a, f, policy, clock=time.time_ns)
                await asyncio.sleep(0.002)
            await asyncio.sleep(latency_s + 0.1)
            await a.close()
            await asyncio.wait_for(task, 5)
            return pump.metrics.latencies_ms()

    lat = asyncio.run(run())
    return _stats(lat) | {"frames": float(len(lat))}


def report(n: int = 300) -> dict[str, Any]:
    return {
        "python": sys.version.split()[0],
        "profiles": [
            bench_profile(sf, enc, n)
            for sf in (0, 3, 7)
            for enc in (LatentEncoding.F32_BE, LatentEncoding.INT8_SYM)
        ],
        "network_memory_link": network_latency(),
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))
