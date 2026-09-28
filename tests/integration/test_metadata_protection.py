# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-062: constant bitmap, padding, decoys and TIMING_OBF end to end."""

import asyncio
import dataclasses
import struct
from pathlib import Path

import numpy as np
import pytest

from esp.codec.errors import WireError
from esp.codec.header import HEADER_LEN, ConsentFlags, Header, PrivacyFlags
from esp.codec.tlv import ParsedPayload, Tlv, encode_typed_latent, iter_tlvs
from esp.core.taoss_types import TaossType
from esp.crypto.noise_ik import StaticKeyPair
from esp.frame.model import DisclosurePolicy
from esp.privacy import metadata as metadata_module
from esp.privacy.metadata import MetadataProtection, filler
from esp.session.descriptor import NegotiationError
from esp.session.driver import PacedSender, ReceiverPump, establish_receiver, establish_sender
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint
from esp.transport.base import Channel, Message
from esp.transport.memory import FaultProfile, memory_link
from esp.transport.overlay import LayeredConnection
from tests.integration.test_endpoint import (
    DECLARATION,
    MASTER,
    NOW,
    RECEIVER_ID,
    REGISTRIES,
    WIRE,
    descriptor,
    establish,
    receiver_capability_for,
    sender_capability,
)
from tests.integration.test_transport import make_clock, wait_until
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = pytest.mark.integration
T = TaossType
ALL = DisclosurePolicy(allowed_types=tuple(T))
NO_EMO = DisclosurePolicy(allowed_types=(T.KNO, T.INT, T.CTX, T.SEN, T.TEM))
BUCKET = 50_000_000  # 50 ms
PROTECT = MetadataProtection(frozenset(T), pad_to=4096, timing_bucket_ns=BUCKET)


def pinned(config: MetadataProtection | None) -> dict[str, bytes]:
    return REGISTRIES | (dict([config.registry_entry()]) if config else {})


def build(
    tmp_path: Path,
    *,
    s_meta: MetadataProtection | None = PROTECT,
    r_meta: MetadataProtection | None = PROTECT,
    sf: int = 6,
    receiver_types: int = 0x3B,
) -> tuple[SenderEndpoint, ReceiverEndpoint]:
    r_static = StaticKeyPair.generate()
    sender = SenderEndpoint(
        master=MASTER,
        static=StaticKeyPair.generate(),
        responder_static=r_static.public_bytes,
        receiver_identity=RECEIVER_ID.public_bytes,
        descriptor=descriptor(sf_level=sf, registries=pinned(s_meta)),
        capability=sender_capability(),
        state_dir=tmp_path,
        wire=WIRE,
        declaration=DECLARATION,
        metadata=s_meta,
    )
    receiver = ReceiverEndpoint(
        identity=RECEIVER_ID,
        static=r_static,
        descriptor=descriptor(sf_level=sf, registries=pinned(r_meta)),
        capability=receiver_capability_for(receiver_types),
        trusted_issuers=frozenset({MASTER.public_bytes}),
        wire=WIRE,
        declaration=DECLARATION,
        metadata=r_meta,
    )
    return sender, receiver


def header(packet: bytes) -> Header:
    return Header.decode(packet[:HEADER_LEN])


def test_observer_cannot_tell_data_masking_control_or_decoy_apart(tmp_path: Path) -> None:
    s, r = build(tmp_path)
    establish(s, r)
    packets = [
        s.send_frame(full_anchor_frame(), ALL, now_ns=NOW + 1),  # EMO masked by receiver consent
        s.send_frame(full_anchor_frame(), NO_EMO, now_ns=NOW + 7_000_001),  # sender omits EMO
        s.decoy(now_ns=NOW + 12_345_678),
        s.sos(now_ns=NOW + 20_000_003),
    ]
    heads = [header(p) for p in packets]
    assert {h.types_bitmap for h in heads} == {0x3F}  # constant bitmap everywhere
    assert not any(h.consent_flags & ConsentFlags.EMO_MASKED for h in heads)
    assert {len(p) for p in packets} == {len(packets[0])}  # constant size
    assert all(h.privacy_flags & PrivacyFlags.TIMING_OBF for h in heads)
    assert all(h.timestamp_ns % BUCKET == 0 and h.dt_ms == 0 for h in heads)

    first = r.receive(packets[0], now_ns=NOW)
    assert first.accepted, first.violations
    assert first.frame is not None
    assert first.frame.present_types == (T.KNO, T.INT, T.CTX, T.SEN, T.TEM)
    assert first.frame.masked_types == (T.EMO,)  # learned from the encrypted mask only
    second = r.receive(packets[1], now_ns=NOW)
    assert second.accepted, second.violations
    assert second.frame is not None
    assert T.EMO not in second.frame.present_types
    decoy = r.receive(packets[2], now_ns=NOW)
    assert decoy.accepted
    assert decoy.frame is None
    assert decoy.control == ()
    assert r.decoys_discarded == 1
    assert r.receive(packets[3], now_ns=NOW).accepted
    assert r.sos_signals == 1
    assert r.decoder_invocations == 2


def test_dummy_latents_look_like_data_and_never_reach_the_application(tmp_path: Path) -> None:
    s, r = build(tmp_path)
    establish(s, r)
    frame = full_anchor_frame()
    result = r.receive(s.send_frame(frame, ALL, now_ns=NOW), now_ns=NOW)
    assert result.frame is not None
    emo = result.frame.block(T.EMO)
    assert emo is None  # the dummy EMO latent was stripped before the decoder


@pytest.mark.parametrize(
    ("s_meta", "r_meta"),
    [(PROTECT, None), (None, PROTECT)],
    ids=["receiver-unprotected", "sender-unprotected"],
)
def test_one_sided_protection_refuses_the_session(
    tmp_path: Path, s_meta: MetadataProtection | None, r_meta: MetadataProtection | None
) -> None:
    s, r = build(tmp_path, s_meta=s_meta, r_meta=r_meta)
    with pytest.raises(WireError, match="refusing unprotected session"):
        establish(s, r)


def test_configuration_mismatch_fails_negotiation(tmp_path: Path) -> None:
    other = dataclasses.replace(PROTECT, pad_to=1024)
    s, r = build(tmp_path, r_meta=other)
    with pytest.raises(NegotiationError, match="different digests"):
        establish(s, r)


def test_pin_must_match_configuration(tmp_path: Path) -> None:
    with pytest.raises(WireError, match="pinned"):
        SenderEndpoint(
            master=MASTER,
            static=StaticKeyPair.generate(),
            responder_static=StaticKeyPair.generate().public_bytes,
            receiver_identity=RECEIVER_ID.public_bytes,
            descriptor=descriptor(sf_level=6),
            capability=sender_capability(),
            state_dir=tmp_path,
            wire=WIRE,
            declaration=DECLARATION,
            metadata=PROTECT,
        )


def test_constant_set_must_cover_the_profile(tmp_path: Path) -> None:
    narrow = MetadataProtection(frozenset({T.KNO, T.INT, T.CTX, T.TEM, T.SEN}))
    s, r = build(tmp_path, s_meta=narrow, r_meta=narrow)
    with pytest.raises(WireError, match="constant type set"):
        establish(s, r)


class Misbehaving:
    """A sender-side protection that breaks one rule (receiver must notice)."""

    def __init__(self, base: MetadataProtection, rule: str) -> None:
        self.base, self.rule = base, rule
        self.bitmap = base.bitmap & ~T.EMO.bit if rule == "narrow-bitmap" else base.bitmap

    def protect(self, **kw: object) -> bytes:
        body: bytes = self.base.protect(**kw)  # type: ignore[arg-type]
        if self.rule == "no-marker":
            return body.replace(b"\x87\x00\x00\x00\x04", b"\x9f\x00\x00\x00\x04")
        if self.rule == "missing-dummy":  # declares EMO a dummy but omits its latent
            kept = [t.encode() for t in iter_tlvs(body) if t.code not in {0x62, 0x88}]
            core = b"".join(kept)
            return core + filler(len(core), self.base.pad_to)
        if self.rule == "double-marker":
            marker = next(t.encode() for t in iter_tlvs(body) if t.code == 0x87)
            core = b"".join(t.encode() for t in iter_tlvs(body) if t.code != 0x88) + marker
            return core + filler(len(core), self.base.pad_to)
        if self.rule == "unpadded":
            return body + b"\x88\x00\x00\x00\x00"
        return body

    def header_fields(self, now_ns: int, privacy: int) -> tuple[int, int]:
        if self.rule == "timing":
            return now_ns + 1, privacy | PrivacyFlags.TIMING_OBF
        return self.base.header_fields(now_ns, privacy)


@pytest.mark.parametrize(
    "rule",
    [
        "no-marker",
        "double-marker",
        "missing-dummy",
        "narrow-bitmap",
        "unpadded",
        "timing",
        "switched-off",
    ],
)
def test_receiver_rejects_a_sender_that_stops_protecting(tmp_path: Path, rule: str) -> None:
    s, r = build(tmp_path)
    establish(s, r)
    s._metadata = None if rule == "switched-off" else Misbehaving(PROTECT, rule)  # type: ignore[assignment]
    result = r.receive(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW), now_ns=NOW)
    assert not result.accepted
    assert "metadata protection" in " ".join(result.violations)
    assert r.decoder_invocations == 0


def test_real_type_outside_constant_set_is_refused_at_the_sender() -> None:
    narrow = MetadataProtection(frozenset({T.KNO}))
    with pytest.raises(WireError, match="not in constant set"):
        narrow.protect(
            types_bitmap=0b11,
            masked=frozenset(),
            payload=b"",
            encoding=WIRE.encoding,
            rng=np.random.default_rng(0),
        )


def test_emo_masked_in_the_cleartext_header_is_rejected(tmp_path: Path) -> None:
    """With EMO in the constant set the header codec already forbids it; without, unwrap does."""
    s, r = build(tmp_path)
    establish(s, r)
    h = header(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW))
    no_emo = MetadataProtection(frozenset(T) - {T.EMO})
    leaky = dataclasses.replace(
        h, types_bitmap=no_emo.bitmap, consent_flags=h.consent_flags | ConsentFlags.EMO_MASKED
    )
    with pytest.raises(WireError, match="EMO_MASKED"):
        no_emo.unwrap(leaky, b"", ParsedPayload((), ()))


def test_dummy_type_outside_the_constant_set_is_rejected(tmp_path: Path) -> None:
    s, r = build(tmp_path)
    establish(s, r)
    h = header(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW))
    no_emo = MetadataProtection(frozenset(T) - {T.EMO})
    marker = Tlv(0x87, struct.pack(">HH", T.EMO.bit, 0))
    latent = Tlv(0x62, encode_typed_latent(T.EMO, np.zeros(64), WIRE.encoding)[5:])
    with pytest.raises(WireError, match="outside the constant set"):
        no_emo.unwrap(
            dataclasses.replace(h, types_bitmap=no_emo.bitmap),
            b"",
            ParsedPayload((latent, marker), ()),
        )


def observable(packet: bytes) -> tuple[int, ...]:
    """Everything a passive observer sees except per-packet counters (seq, nonce, time)."""
    h = header(packet)
    return (
        len(packet),
        h.profile,
        h.sf_level,
        h.types_bitmap,
        h.consent_flags,
        h.privacy_flags,
        h.capabilities,
        h.dt_ms,
        h.payload_len,
    )


@pytest.mark.parametrize("protected", [True, False], ids=["protected", "unprotected-control"])
def test_traffic_analysis_cannot_classify_emo_presence(tmp_path: Path, protected: bool) -> None:
    meta = PROTECT if protected else None
    s, r = build(tmp_path, s_meta=meta, r_meta=meta, receiver_types=0x3F)
    establish(s, r)
    with_emo = {
        observable(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW + i)) for i in range(20)
    }
    without = {
        observable(s.send_frame(full_anchor_frame(), NO_EMO, now_ns=NOW + i)) for i in range(20)
    }
    decoys = {observable(s.decoy(now_ns=NOW + i)) for i in range(5)} if protected else set()
    if protected:
        # identical observable features: no classifier beats chance (50 %)
        assert with_emo == without == decoys
        assert len(with_emo) == 1
    else:
        assert with_emo.isdisjoint(without)  # without mitigation EMO presence is visible


def test_constant_rate_decoys_over_an_overlay(tmp_path: Path) -> None:
    def xor(_: Channel, data: bytes) -> bytes:  # stand-in for an onion layer
        return bytes(b ^ 0x5A for b in data)

    async def scenario() -> tuple[PacedSender, ReceiverPump, list[Message]]:
        s, r = build(tmp_path)
        a, b = memory_link(FaultProfile(latency_s=0.002, seed=5))
        seen: list[Message] = []

        def tap(channel: Channel, data: bytes) -> bytes:
            seen.append(Message(channel, data))  # what the overlay's next hop observes
            return xor(channel, data)

        s_conn = LayeredConnection(a, wrap=tap, unwrap=xor)
        r_conn = LayeredConnection(b, wrap=xor, unwrap=xor)
        await asyncio.gather(establish_sender(s, s_conn), establish_receiver(r, r_conn))
        clock = make_clock()
        pump = ReceiverPump(r, r_conn, clock=clock)
        task = asyncio.create_task(pump.run())
        seen.clear()
        paced = PacedSender(s, s_conn, ALL, interval_s=0.01, clock=clock)
        for _ in range(5):
            paced.submit(full_anchor_frame())
        await paced.run(ticks=30)
        await wait_until(lambda: len(pump.metrics.deliveries) >= 30)
        await s_conn.close()
        await asyncio.wait_for(task, 5)
        return paced, pump, seen

    paced, pump, seen = asyncio.run(scenario())
    assert (paced.frames_sent, paced.decoys_sent) == (5, 25)
    assert pump.metrics.accepted_frames == 5
    assert all(d.result.accepted for d in pump.metrics.deliveries)
    assert len({(m.channel, len(m.data)) for m in seen}) == 1  # one channel, one size


def test_timing_obf_is_not_differential_privacy() -> None:
    """TIMING_OBF must never set or imply a DP level (V13 section 8.3)."""
    ts, flags = PROTECT.header_fields(NOW + 123_456_789, 0)
    assert flags & 0x0F == 0
    assert ts % BUCKET == 0
    doc = metadata_module.__doc__ or ""
    assert "not* differential privacy" in doc
