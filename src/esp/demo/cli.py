# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""BCI-free end-to-end demo as two independent processes (WP-025, M5 gate).

::

    esp-demo init DIR                       # keys, TLS cert, public.json
    esp-demo receive DIR --port 4433 --events recv.jsonl --sessions 4
    esp-demo send DIR --port 4433 --capture send.jsonl

The sender runs the M5 script (plan M5 gate):

1. session 1, capability without EMO: KNO+INT+CTX shared, EMO masked;
2. session 2, capability with EMO (a rights-increasing grant needs a new
   handshake, V13 section 11): EMO and the EMO->KNO binding appear; then the
   binding is masked separately; then the EMO capability is revoked;
3. session 3 tries the revoked capability again: the receiver refuses it;
4. session 4 is back on the EMO-free capability: EMO is masked again.

The receiver logs, per packet, the authenticated header, the plaintext TLV
*codes* (never values) and the decoded application view. The sender logs a
packet capture. Both are JSON lines for the gate test and the inspector.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import secrets
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, TextIO

import numpy as np

from esp.codec.frame_wire import WireOptions
from esp.codec.header import HEADER_LEN, Header
from esp.codec.tlv import ParsedPayload
from esp.consent.accept import AcceptState
from esp.consent.capability import AudienceMode, ReceiverCapability, Rights, SenderCapability
from esp.consent.revocation import RevocationRegistry
from esp.core.errors import EspError
from esp.core.provenance import AffectScope
from esp.core.taoss_types import TaossType, bitmap_to_types, types_to_bitmap
from esp.crypto.noise_ik import StaticKeyPair
from esp.crypto.primitives import SigningKey
from esp.decoder.core import (
    Decoder,
    DecodeRefused,
    audit_absence_handling,
    check_against_session,
    run_decoder,
)
from esp.decoder.outputs import TextOutput
from esp.decoder.reference import LinearDecoder, NearestAnchorDecoder
from esp.decoder.render import transparency_panel
from esp.demo.compose import DemoState, compose_frame
from esp.demo.inspector import write_report
from esp.frame.model import DisclosurePolicy, ExperienceFrame
from esp.ontology.profiles import BASIC8_ID, basic8_registry
from esp.regulatory.guard import DeploymentContext, Regime, RegulatoryDeclaration
from esp.semantics.bindings import BindingPolicy, RelationClass
from esp.session.descriptor import DecoderPolicy, SessionDescriptor
from esp.session.driver import establish_receiver, establish_sender
from esp.session.endpoint import ReceiverEndpoint, ReceiveResult, SenderEndpoint
from esp.session.profiles import custom_profile_digest
from esp.session.state import SessionState, SessionStateError
from esp.transport.base import Channel, ConnectionClosedError, Message
from esp.transport.quic import QuicConnection, connect_quic, self_signed_certificate, serve_quic

T = TaossType
PROFILE_NAME: Final = "esp-typeset-demo-v1"
#: Demo pin for the addendum profile (the digest identifies ADR-0011's code table).
ADDENDUM_DIGEST: Final = hashlib.blake2b(b"esp-addendum-v1/ADR-0011", digest_size=32).digest()
RECEIVER_TYPES: Final = frozenset({T.KNO, T.INT, T.EMO, T.CTX})
NO_EMO: Final = frozenset({T.KNO, T.INT, T.CTX})
WITH_EMO: Final = frozenset({T.KNO, T.INT, T.EMO, T.CTX})
CAP_NO_EMO: Final = uuid.UUID("0d3e6b4a-1c2f-4e5a-8b7c-9d0e1f2a3b4c")
CAP_WITH_EMO: Final = uuid.UUID("5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9")
STATE: Final = DemoState(
    emotions={"fear": 4, "sadness": 2},
    valence=2,
    arousal=4,
    readiness={"avoid": 5},
    context=("work", "meeting"),
    knowledge=("possible_dismissal",),
)
ALL_BINDINGS: Final = BindingPolicy(allowed_relations=(RelationClass.ELICITED_BY,))
HOUR_NS: Final = 3600 * 10**9
_REALIZATION_TL: Final = uuid.UUID("7a7a7a7a-7a7a-4a7a-8a7a-7a7a7a7a7a7a")
#: WP-078: the demo shares only the sender's own, self-declared affect; no biometric inputs.
DECLARATION: Final = RegulatoryDeclaration(
    regimes=(Regime.EU_AI_ACT, Regime.EU_GDPR),
    intended_use="BCI-free demonstration of typed consent between two consenting parties",
    deployment_context=DeploymentContext.OTHER,
    biometric_inputs=False,
    affect_scopes=(AffectScope.SELF_DECLARED,),
)


def wire() -> WireOptions:
    registry = basic8_registry()
    return WireOptions(addendum=True, anchor_sets={BASIC8_ID: registry.anchor_set(BASIC8_ID)})


#: Decoder policies the demo profile declares (V13 section 7.2): EMO may be absent.
DECODER_POLICIES: Final = dict.fromkeys(TaossType, DecoderPolicy.STRICT_REFUSE) | {
    T.EMO: DecoderPolicy.GRACEFUL
}


def descriptor() -> SessionDescriptor:
    registry = basic8_registry()
    return SessionDescriptor(
        profile=1,
        sf_level=0,
        decoder_policy=DECODER_POLICIES,
        registries={
            "esp-addendum-v1": ADDENDUM_DIGEST,
            BASIC8_ID: bytes.fromhex(registry.digest_hex()),
            PROFILE_NAME: custom_profile_digest(PROFILE_NAME),
        },
    )


# --- key material ----------------------------------------------------------------------


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def init(directory: Path) -> None:
    master_seed, identity_seed = secrets.token_bytes(32), secrets.token_bytes(32)
    static = StaticKeyPair.generate()
    cert, key = self_signed_certificate("localhost")
    _write_secret(directory / "sender" / "master.seed", master_seed)
    _write_secret(directory / "receiver" / "identity.seed", identity_seed)
    _write_secret(directory / "receiver" / "static.key", static.private_bytes())
    _write_secret(directory / "receiver" / "tls-key.pem", key)
    (directory / "sender" / "state").mkdir(mode=0o700, exist_ok=True)
    public = {
        "sender_master_pk": SigningKey.from_seed(master_seed).public_bytes.hex(),
        "receiver_identity_pk": SigningKey.from_seed(identity_seed).public_bytes.hex(),
        "receiver_static_pk": static.public_bytes.hex(),
        "tls_certificate_pem": cert.decode(),
    }
    (directory / "public.json").write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8")


def _public(directory: Path) -> dict[str, str]:
    data: dict[str, str] = json.loads((directory / "public.json").read_text(encoding="utf-8"))
    return data


# --- JSON views ------------------------------------------------------------------------


def header_view(h: Header) -> dict[str, Any]:
    return {
        "types": [t.name for t in bitmap_to_types(h.types_bitmap)],
        "emo_masked": h.emo_masked,
        "consent_flags": h.consent_flags,
        "privacy_flags": h.privacy_flags,
        "segment_seq": h.segment_seq,
        "payload_len": h.payload_len,
    }


def frame_view(f: ExperienceFrame) -> dict[str, Any]:
    return {
        "present_types": [t.name for t in f.present_types],
        "masked_types": [t.name for t in f.masked_types],
        "bindings": [
            {
                "relation": str(b.relation),
                "source": b.source.type.name,
                "target": b.target.type.name,
            }
            for b in f.bindings
        ],
        "affect_descriptors": sum(len(b.affect) for b in f.types),
        "emo_anchor_coordinates": sum(len(b.anchors) for b in f.types if b.type is T.EMO),
        "provenance": {
            "encoder_id": f.provenance.encoder_id,
            "evidence_refs": list(f.provenance.evidence_refs),
        },
        "consent_capability_id": str(f.consent.capability_id) if f.consent.capability_id else None,
    }


class EventLog:
    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def __call__(self, event: str, **fields: object) -> None:
        record = {"event": event, "t_ns": time.time_ns(), **fields}
        self._stream.write(json.dumps(record, sort_keys=True) + "\n")
        self._stream.flush()


# --- receiver ----------------------------------------------------------------------------


def demo_decoders() -> list[Decoder]:
    """EMO -> anchor label (GRACEFUL) and KNO/INT/CTX -> state vector (STRICT)."""
    labels = basic8_registry().anchor_set(BASIC8_ID).anchors
    realizations = {}
    for anchor in labels:
        label = anchor.split(":")[2]
        emo = compose_frame(
            DemoState(emotions={label: 5}), timeline_id=_REALIZATION_TL, sequence=0, now_ns=0
        ).block(T.EMO)
        if emo is None or emo.latent is None:  # pragma: no cover - composer always sets EMO
            msg = "anchor realization missing"
            raise RuntimeError(msg)
        realizations[label] = emo.latent
    decoders: list[Decoder] = [
        NearestAnchorDecoder("demo-emotion-label@1", T.EMO, realizations, DecoderPolicy.GRACEFUL),
        LinearDecoder(
            "demo-state-vector@1", dict.fromkeys((T.KNO, T.INT, T.CTX), DecoderPolicy.STRICT_REFUSE)
        ),
    ]
    for d in decoders:
        check_against_session(d.profile, DECODER_POLICIES)
        audit_absence_handling(d)  # no silent ⊥ -> 0
    return decoders


def decode_view(frame: ExperienceFrame, decoders: list[Decoder]) -> dict[str, Any]:
    results = []
    outputs: dict[str, dict[str, object]] = {}
    for d in decoders:
        try:
            r = run_decoder(d, frame)
        except DecodeRefused as exc:
            outputs[d.profile.decoder_id] = {"refused": str(exc)}
            continue
        results.append(r)
        out = r.output
        outputs[d.profile.decoder_id] = (
            {"text": out.text}
            if isinstance(out, TextOutput)
            else {"vector_l2": round(float(np.linalg.norm(getattr(out, "values", ()))), 6)}
        )
    return {"outputs": outputs, "transparency": transparency_panel(frame, results, "text")}


def receiver_capability(identity: SigningKey) -> Callable[[bytes], ReceiverCapability]:
    types = types_to_bitmap(RECEIVER_TYPES)

    def factory(noise_h: bytes) -> ReceiverCapability:
        now = time.time_ns()
        return ReceiverCapability(
            accept_types=types,
            max_norm=(10.0,) * len(RECEIVER_TYPES),
            valence_bounds=(-1.0, 1.0),
            rate_limit_hz=100,
            valid_from_ns=now - HOUR_NS,
            valid_until_ns=now + HOUR_NS,
            nonce=secrets.token_bytes(16),
            pk_receiver=identity.public_bytes,
            noise_h=noise_h,
        )

    return factory


async def receive(directory: Path, port: int, events: TextIO, sessions: int) -> int:
    log = EventLog(events)
    public = _public(directory)
    identity = SigningKey.from_seed((directory / "receiver" / "identity.seed").read_bytes())
    static = StaticKeyPair.from_private_bytes((directory / "receiver" / "static.key").read_bytes())
    trusted = frozenset({bytes.fromhex(public["sender_master_pk"])})
    accept_state, revocations = AcceptState(), RevocationRegistry()  # outlive sessions
    decoders = demo_decoders()
    connections: asyncio.Queue[QuicConnection] = asyncio.Queue()
    server = await serve_quic(
        "127.0.0.1",
        port,
        certificate_pem=public["tls_certificate_pem"].encode(),
        key_pem=(directory / "receiver" / "tls-key.pem").read_bytes(),
        on_connection=connections.put_nowait,
    )
    transport = server._transport
    if transport is None:  # pragma: no cover - serve() always binds
        msg = "server socket missing"
        raise RuntimeError(msg)
    log("listening", port=transport.get_extra_info("sockname")[1])
    try:
        for n in range(1, sessions + 1):
            conn = await connections.get()
            inspected: dict[str, Any] = {}

            def inspector(
                h: Header, parsed: ParsedPayload, box: dict[str, Any] = inspected
            ) -> None:
                box["header"] = header_view(h)
                box["plaintext_tlv_codes"] = [f"0x{t.code:02x}" for t in parsed.known]

            receiver = ReceiverEndpoint(
                identity=identity,
                static=static,
                descriptor=descriptor(),
                capability=receiver_capability(identity),
                trusted_issuers=trusted,
                wire=wire(),
                declaration=DECLARATION,
                accept_state=accept_state,
                revocations=revocations,
                inspector=inspector,
            )
            await _serve_session(n, conn, receiver, inspected, log, decoders=decoders)
            await conn.close()
    finally:
        server.close()
    log("done")
    return 0


async def _serve_session(
    n: int,
    conn: QuicConnection,
    receiver: ReceiverEndpoint,
    inspected: dict[str, Any],
    log: EventLog,
    *,
    decoders: list[Decoder],
) -> None:
    log("session_start", session=n)
    try:
        await establish_receiver(receiver, conn)
    except (EspError, TimeoutError) as exc:
        log("session_refused", session=n, reason=str(exc))
        return
    log("session_active", session=n)
    while receiver.state is not SessionState.CLOSED:
        try:
            message: Message = await asyncio.wait_for(conn.receive(), 10)
        except (ConnectionClosedError, TimeoutError):
            receiver.abort()
            break
        inspected.clear()
        result: ReceiveResult = receiver.receive(message.data, now_ns=time.time_ns())
        log(
            "packet",
            session=n,
            channel=message.channel.name,
            accepted=result.accepted,
            violations=list(result.violations),
            wire_header=header_view(Header.decode(message.data[:HEADER_LEN])),
            **inspected,
            frame=frame_view(result.frame) if result.frame is not None else None,
            decoded=decode_view(result.frame, decoders) if result.frame is not None else None,
            control=[f"0x{t.code:02x}" for t in result.control],
        )
    log("session_end", session=n, decoder_invocations=receiver.decoder_invocations)


# --- sender ------------------------------------------------------------------------------


def sender_capability(master: SigningKey, receiver_pk: bytes, *, emo: bool) -> SenderCapability:
    return SenderCapability(
        capability_id=CAP_WITH_EMO if emo else CAP_NO_EMO,
        types_allowed=types_to_bitmap(WITH_EMO if emo else NO_EMO),
        rights=Rights(0),
        max_segments=1000,
        dp_epsilon_ceiling=0.0,
        valid_until_ns=time.time_ns() + HOUR_NS,
        audience_mode=AudienceMode.RECIPIENT_PUBKEY,
        audience_value=receiver_pk,
        issuer_pk=master.public_bytes,
        nonce=secrets.token_bytes(16),
    )


class SenderSession:
    def __init__(self, directory: Path, capture: EventLog, n: int, *, emo: bool) -> None:
        public = _public(directory)
        master = SigningKey.from_seed((directory / "sender" / "master.seed").read_bytes())
        receiver_pk = bytes.fromhex(public["receiver_identity_pk"])
        self.n = n
        self.capture = capture
        self.cert = public["tls_certificate_pem"].encode()
        self.endpoint = SenderEndpoint(
            master=master,
            static=StaticKeyPair.generate(),
            responder_static=bytes.fromhex(public["receiver_static_pk"]),
            receiver_identity=receiver_pk,
            descriptor=descriptor(),
            capability=sender_capability(master, receiver_pk, emo=emo),
            state_dir=directory / "sender" / "state",
            wire=wire(),
            declaration=DECLARATION,
        )
        self.capability_id = CAP_WITH_EMO if emo else CAP_NO_EMO
        self.sequence = 0

    async def send(
        self, conn: QuicConnection, step: str, *, bindings: BindingPolicy = ALL_BINDINGS
    ) -> None:
        self.sequence += 1
        frame = compose_frame(
            STATE,
            timeline_id=self.endpoint.timeline_id,
            sequence=self.sequence,
            now_ns=time.time_ns(),
            capability_id=self.capability_id,
        )
        policy = DisclosurePolicy(allowed_types=tuple(T), bindings=bindings)
        try:
            packet = self.endpoint.send_frame(frame, policy, now_ns=time.time_ns())
        except SessionStateError as exc:
            self.capture("send_refused", session=self.n, step=step, reason=str(exc))
            return
        await conn.send(Channel.STATE, packet)
        self._record(step, Channel.STATE, packet)

    async def control(self, conn: QuicConnection, step: str, packet: bytes) -> None:
        await conn.send(Channel.CONTROL, packet)
        self._record(step, Channel.CONTROL, packet)

    def _record(self, step: str, channel: Channel, packet: bytes) -> None:
        self.capture(
            "captured",
            session=self.n,
            step=step,
            channel=channel.name,
            header=header_view(Header.decode(packet[:HEADER_LEN])),
            packet_hex=packet.hex(),
        )


async def _session(
    directory: Path,
    port: int,
    capture: EventLog,
    n: int,
    *,
    emo: bool,
    body: Callable[[SenderSession, QuicConnection], Any],
) -> None:
    session = SenderSession(directory, capture, n, emo=emo)
    async with connect_quic("127.0.0.1", port, ca_pem=session.cert) as conn:
        try:
            await establish_sender(session.endpoint, conn)
        except (EspError, TimeoutError) as exc:
            capture("session_failed", session=n, reason=str(exc))
            return
        capture("session_active", session=n, capability=str(session.capability_id))
        await body(session, conn)
        await asyncio.sleep(0.3)  # let the receiver drain before the connection closes


async def send(directory: Path, port: int, capture_stream: TextIO) -> int:
    capture = EventLog(capture_stream)

    async def s1(s: SenderSession, conn: QuicConnection) -> None:
        await s.send(conn, "share_without_emo_consent")
        await s.control(conn, "close", s.endpoint.close(now_ns=time.time_ns()))

    async def s2(s: SenderSession, conn: QuicConnection) -> None:
        await s.send(conn, "emo_consented")
        await s.send(conn, "binding_masked", bindings=BindingPolicy())
        await s.control(conn, "revoke_emo", s.endpoint.revoke(now_ns=time.time_ns()))
        await s.send(conn, "emo_after_revoke")
        await asyncio.sleep(0.2)

    async def s3(s: SenderSession, conn: QuicConnection) -> None:
        with contextlib.suppress(ConnectionClosedError):
            await s.send(conn, "revoked_capability_reused")

    async def s4(s: SenderSession, conn: QuicConnection) -> None:
        await s.send(conn, "emo_masked_again")
        await s.control(conn, "close", s.endpoint.close(now_ns=time.time_ns()))

    for n, emo, body in ((1, False, s1), (2, True, s2), (3, True, s3), (4, False, s4)):
        await _session(directory, port, capture, n, emo=emo, body=body)
    capture("done")
    return 0


# --- entry point -------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="esp-demo", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p_init = sub.add_parser("init", help="generate keys and certificate")
    p_init.add_argument("dir", type=Path)
    p_recv = sub.add_parser("receive", help="run the receiver")
    p_recv.add_argument("dir", type=Path)
    p_recv.add_argument("--port", type=int, required=True)
    p_recv.add_argument("--events", type=Path, required=True)
    p_recv.add_argument("--sessions", type=int, default=4)
    p_send = sub.add_parser("send", help="run the M5 sender script")
    p_send.add_argument("dir", type=Path)
    p_send.add_argument("--port", type=int, required=True)
    p_send.add_argument("--capture", type=Path, required=True)
    p_insp = sub.add_parser("inspect", help="render the wire inspector HTML page")
    p_insp.add_argument("--events", type=Path, required=True)
    p_insp.add_argument("--capture", type=Path, required=True)
    p_insp.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "inspect":
        write_report(args.events, args.capture, args.out)
        return 0
    if args.command == "init":
        init(args.dir)
        return 0
    if args.command == "receive":
        with args.events.open("w", encoding="utf-8") as events:
            return asyncio.run(receive(args.dir, args.port, events, args.sessions))
    with args.capture.open("w", encoding="utf-8") as capture:
        return asyncio.run(send(args.dir, args.port, capture))


if __name__ == "__main__":
    sys.exit(main())
