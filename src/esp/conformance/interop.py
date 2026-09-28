# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Live interoperability against an external peer (WP-039/042).

Peer contract (as implemented by ``rust/esp-rs``), TCP test transport
``len u32 · channel u8 · data``, JSON lines on stdout:

- ``PEER send --addr H:P --responder-static HEX --receiver-id HEX --master-seed HEX
  --static-seed HEX --frames N [--revoke-after K --ignore-revocation yes]``
- ``PEER receive --addr H:P --static-seed HEX --identity-seed HEX --trusted HEX``
  (prints ``listening``/``active``/``frame``/``revoked``/``rejected``/``closed``)
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from esp.codec.frame_wire import WireOptions
from esp.consent.capability import AudienceMode, ReceiverCapability, Rights, SenderCapability
from esp.core.provenance import AffectScope
from esp.crypto.noise_ik import StaticKeyPair
from esp.crypto.primitives import SigningKey
from esp.frame.model import DisclosurePolicy, ExperienceFrame, TypeBlock
from esp.regulatory.guard import DeploymentContext, Regime, RegulatoryDeclaration
from esp.session.descriptor import SessionDescriptor
from esp.session.driver import ReceiverPump, establish_receiver, establish_sender, send_frame
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint
from esp.transport.base import Channel
from esp.transport.tcp import TcpConnection, connect_tcp

if TYPE_CHECKING:
    from esp.conformance.runner import Suite

HOUR: Final = 3600 * 10**9
KNO: Final = DisclosurePolicy(allowed_types=("KNO",))  # type: ignore[arg-type]
DECLARATION: Final = RegulatoryDeclaration(
    regimes=(Regime.EU_AI_ACT, Regime.EU_GDPR),
    intended_use="ESP conformance and interoperability testing (synthetic data)",
    deployment_context=DeploymentContext.OTHER,
    biometric_inputs=False,
    affect_scopes=(AffectScope.CONTENT, AffectScope.SELF_DECLARED),
)


def now() -> int:
    return time.time_ns()


def kno_frame(seq: int) -> ExperienceFrame:
    from esp.core.clock import ClockStamp  # noqa: PLC0415

    latent = tuple(float((i * 7 + seq) % 13 - 6) / 6.0 for i in range(240))
    return ExperienceFrame(
        frame_id=uuid.uuid4(),
        timeline_id=uuid.uuid4(),
        sequence=seq,
        timestamp=ClockStamp(
            source_ns=now(), monotonic_ns=now(), clock_domain="interop", sequence=seq
        ),
        types=(TypeBlock(type="KNO", latent=latent),),  # type: ignore[arg-type]
    )


def sender_args(  # noqa: PLR0917 - mirrors the peer CLI arguments
    port: int,
    r_static: bytes,
    receiver_id: bytes,
    master_seed: bytes,
    frames: int,
    revoke_after: int | None,
) -> list[str]:
    args = [
        "send",
        "--addr",
        f"127.0.0.1:{port}",
        "--responder-static",
        r_static.hex(),
        "--receiver-id",
        receiver_id.hex(),
        "--master-seed",
        master_seed.hex(),
        "--static-seed",
        os.urandom(32).hex(),
        "--frames",
        str(frames),
    ]
    if revoke_after is not None:
        args += ["--revoke-after", str(revoke_after), "--ignore-revocation", "yes"]
    return args


def peer_receiver(peer: Path, trusted: bytes) -> tuple[subprocess.Popen[str], int, bytes, bytes]:
    identity_seed, static_seed = os.urandom(32), os.urandom(32)
    proc = subprocess.Popen(  # noqa: S603 - fixed argv to a user-selected peer binary
        [
            str(peer),
            "receive",
            "--addr",
            "127.0.0.1:0",
            "--static-seed",
            static_seed.hex(),
            "--identity-seed",
            identity_seed.hex(),
            "--trusted",
            trusted.hex(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.stdout is None:  # pragma: no cover
        msg = "peer stdout unavailable"
        raise RuntimeError(msg)
    port = int(json.loads(proc.stdout.readline())["port"])
    identity = SigningKey.from_seed(identity_seed).public_bytes
    return proc, port, identity, StaticKeyPair.from_private_bytes(static_seed).public_bytes


def finish(proc: subprocess.Popen[str]) -> tuple[int, list[dict[str, Any]], str]:
    out, err = proc.communicate(timeout=30)
    return proc.returncode, [json.loads(line) for line in out.splitlines() if line.strip()], err


def python_receiver(trusted: bytes) -> tuple[ReceiverEndpoint, SigningKey, StaticKeyPair]:
    identity, r_static = SigningKey.generate(), StaticKeyPair.generate()

    def cap(noise_h: bytes) -> ReceiverCapability:
        return ReceiverCapability(
            accept_types=0x01,
            max_norm=(1000.0,),
            valence_bounds=None,
            rate_limit_hz=1000,
            valid_from_ns=0,
            valid_until_ns=now() + HOUR,
            nonce=os.urandom(16),
            pk_receiver=identity.public_bytes,
            noise_h=noise_h,
        )

    receiver = ReceiverEndpoint(
        identity=identity,
        static=r_static,
        descriptor=SessionDescriptor(),
        capability=cap,
        trusted_issuers=frozenset({trusted}),
        wire=WireOptions(),
        declaration=DECLARATION,
    )
    return receiver, identity, r_static


def python_sender(
    state_dir: Path, receiver_id: bytes, r_static: bytes, master: SigningKey
) -> SenderEndpoint:
    return SenderEndpoint(
        master=master,
        static=StaticKeyPair.generate(),
        responder_static=r_static,
        receiver_identity=receiver_id,
        descriptor=SessionDescriptor(),
        capability=SenderCapability(
            capability_id=uuid.uuid4(),
            types_allowed=0x3F,
            rights=Rights(0),
            max_segments=100,
            dp_epsilon_ceiling=0.0,
            valid_until_ns=now() + HOUR,
            audience_mode=AudienceMode.RECIPIENT_PUBKEY,
            audience_value=receiver_id,
            issuer_pk=master.public_bytes,
            nonce=os.urandom(16),
        ),
        state_dir=state_dir,
        wire=WireOptions(),
        declaration=DECLARATION,
    )


def peer_to_python(
    peer: Path, *, frames: int, revoke_after: int | None = None, trust: bool = True
) -> tuple[ReceiverEndpoint, ReceiverPump, dict[str, Any]]:
    master_seed = os.urandom(32)
    master = SigningKey.from_seed(master_seed)
    receiver, identity, r_static = python_receiver(master.public_bytes if trust else os.urandom(32))

    async def scenario() -> tuple[ReceiverPump, dict[str, Any]]:
        conns: asyncio.Queue[TcpConnection] = asyncio.Queue()
        server = await asyncio.start_server(
            lambda r, w: conns.put_nowait(TcpConnection(r, w)), "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]
        proc = await asyncio.create_subprocess_exec(
            str(peer),
            *sender_args(
                port,
                r_static.public_bytes,
                identity.public_bytes,
                master_seed,
                frames,
                revoke_after,
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        conn = await asyncio.wait_for(conns.get(), 10)
        try:
            await establish_receiver(receiver, conn)
        except Exception:
            await conn.close()
            await proc.wait()
            raise
        finally:
            server.close()
        pump = ReceiverPump(receiver, conn, clock=now)
        out, err = await asyncio.wait_for(proc.communicate(), 30)
        if proc.returncode != 0:
            msg = f"peer sender failed: {err.decode()}"
            raise RuntimeError(msg)
        await asyncio.wait_for(pump.run(), 10)
        await conn.close()
        report: dict[str, Any] = json.loads(out.decode().strip().splitlines()[-1])
        return pump, report

    pump, report = asyncio.run(scenario())
    return receiver, pump, report


def python_to_peer(
    peer: Path, state_dir: Path, *, revoke: bool, trusted_ok: bool = True, frames: int = 4
) -> tuple[int, list[dict[str, Any]], str]:
    master = SigningKey.generate()
    proc, port, identity, r_static = peer_receiver(
        peer, master.public_bytes if trusted_ok else os.urandom(32)
    )
    sender = python_sender(state_dir, identity, r_static, master)

    async def scenario() -> None:
        conn = await connect_tcp("127.0.0.1", port)
        await establish_sender(sender, conn)
        for i in range(frames):
            if revoke and i == 2:
                await conn.send(Channel.CONTROL, sender.revoke(now_ns=now()))
                sender._revoked = False  # a misbehaving sender keeps going
            await send_frame(sender, conn, kno_frame(i), KNO, clock=now)
        await asyncio.sleep(0.2)
        await conn.close()

    try:
        asyncio.run(scenario())
    finally:
        result = finish(proc)
    return result


def run_interop(suite: Suite, peer: Path) -> None:
    """Add the live interop cells for ``peer`` to the suite report."""
    import tempfile  # noqa: PLC0415

    from esp.conformance.runner import _require  # noqa: PLC0415

    def peer_sends() -> None:
        _, pump, _ = peer_to_python(peer, frames=3)
        _require(pump.metrics.accepted_frames == 3, "python did not accept 3 peer frames")

    def peer_revokes() -> None:
        receiver, pump, _ = peer_to_python(peer, frames=4, revoke_after=2)
        accepted = [d.result.accepted for d in pump.metrics.deliveries]
        _require(accepted == [True, True, True, False, False], f"acceptance pattern {accepted}")
        _require(receiver.decoder_invocations == 2, "decoded after revocation")

    def python_sends() -> None:
        with tempfile.TemporaryDirectory() as d:
            rc, events, err = python_to_peer(peer, Path(d), revoke=False)
        _require(rc == 0, err)
        _require([e["seq"] for e in events if e["event"] == "frame"] == [0, 1, 2, 3], "peer frames")

    def python_revokes() -> None:
        with tempfile.TemporaryDirectory() as d:
            rc, events, err = python_to_peer(peer, Path(d), revoke=True)
        _require(rc == 0, err)
        kinds = [e["event"] for e in events]
        _require(
            kinds == ["active", "frame", "frame", "revoked", "rejected", "rejected", "closed"],
            f"peer events {kinds}",
        )

    for name, fn in (
        ("peer->python", peer_sends),
        ("peer->python revocation", peer_revokes),
        ("python->peer", python_sends),
        ("python->peer revocation", python_revokes),
    ):
        suite.check("interop", name, fn)
