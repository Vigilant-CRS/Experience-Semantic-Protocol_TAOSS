# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GAP-016 over real endpoints: replay segments need consent and a verified watermark.

Negative tests craft packets with the sender's own valid session keys
(``_seal``), so only the replay-watermark rules can refuse them. The decoder
never runs for a refused segment.
"""

import uuid
from pathlib import Path

import pytest

from esp.codec.frame_wire import consent_flags_for, frame_to_payload
from esp.codec.tlv import encode_tlv
from esp.consent.capability import AudienceMode, ReceiverCapability, Rights, SenderCapability
from esp.core.errors import ErrorCode
from esp.core.taoss_types import TaossType, types_to_bitmap
from esp.crypto.noise_ik import StaticKeyPair
from esp.crypto.primitives import SigningKey
from esp.demo.cli import DECLARATION, descriptor, wire
from esp.demo.compose import DemoState, compose_frame
from esp.frame.model import DisclosurePolicy, ExperienceFrame
from esp.session.endpoint import ReceiverEndpoint, ReceiverHardening, SenderEndpoint
from esp.session.state import SessionStateError
from esp.xcf.gate import RecallFrame
from esp.xcf.watermark import (
    ReplaySchedule,
    ReplayWatermarker,
    ReplayWatermarkError,
    ReplayWatermarkPolicy,
    VendorKey,
)

pytestmark = [pytest.mark.integration, pytest.mark.security]
T = TaossType
TYPES = (T.KNO, T.INT, T.EMO, T.CTX)
ALL = DisclosurePolicy(allowed_types=TYPES)
MASTER = SigningKey.from_seed(b"\x51" * 32)
IDENTITY = SigningKey.from_seed(b"\x52" * 32)
HOUR = 3600 * 10**9
START = 2_000 * 10**9  # on the 1 s start grid
VENDOR = VendorKey(b"V" * 16, b"\x77" * 32)
SCHEDULE = ReplaySchedule(period_ns=200_000_000, jitter_ns=50_000_000, tolerance_ns=5_000_000)
POLICY = ReplayWatermarkPolicy(vendors={VENDOR.vendor_id: VENDOR.key}, schedule=SCHEDULE)
CID = b"\xc1" * 32


def pair(
    tmp_path: Path,
    *,
    rights: Rights = Rights.ALLOW_REPLAY,
    policy: ReplayWatermarkPolicy | None = POLICY,
) -> tuple[SenderEndpoint, ReceiverEndpoint]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    r_static = StaticKeyPair.generate()

    def rc(noise_h: bytes) -> ReceiverCapability:
        return ReceiverCapability(
            accept_types=types_to_bitmap(TYPES),
            max_norm=(10.0,) * len(TYPES),
            valence_bounds=(-1.0, 1.0),
            rate_limit_hz=1000,
            valid_from_ns=0,
            valid_until_ns=START + HOUR,
            nonce=b"\x08" * 16,
            pk_receiver=IDENTITY.public_bytes,
            noise_h=noise_h,
        )

    sender = SenderEndpoint(
        master=MASTER,
        static=StaticKeyPair.generate(),
        responder_static=r_static.public_bytes,
        receiver_identity=IDENTITY.public_bytes,
        descriptor=descriptor(),
        capability=SenderCapability(
            capability_id=uuid.uuid4(),
            types_allowed=types_to_bitmap(TYPES),
            rights=rights,
            max_segments=1000,
            dp_epsilon_ceiling=0.0,
            valid_until_ns=START + HOUR,
            audience_mode=AudienceMode.RECIPIENT_PUBKEY,
            audience_value=IDENTITY.public_bytes,
            issuer_pk=MASTER.public_bytes,
            nonce=b"\x07" * 16,
        ),
        state_dir=tmp_path,
        wire=wire(),
        declaration=DECLARATION,
    )
    receiver = ReceiverEndpoint(
        identity=IDENTITY,
        static=r_static,
        descriptor=descriptor(),
        capability=rc,
        trusted_issuers=frozenset({MASTER.public_bytes}),
        wire=wire(),
        declaration=DECLARATION,
        hardening=ReceiverHardening(replay_watermark=policy),
    )
    hs2, t1 = receiver.on_handshake1(sender.start())
    sender.on_handshake2(hs2)
    receiver.on_transport2(sender.on_transport1(t1))
    return sender, receiver


def frame(sender: SenderEndpoint, seq: int, now_ns: int) -> ExperienceFrame:
    state = DemoState(emotions={"joy": 4}, context=("replay",), knowledge=("capsule",))
    return compose_frame(state, timeline_id=sender.timeline_id, sequence=seq, now_ns=now_ns)


def recall(i: int) -> RecallFrame:
    return RecallFrame(CID, offset_ns=i * SCHEDULE.period_ns, span_ns=SCHEDULE.period_ns)


def honest_stream(sender: SenderEndpoint, n: int) -> list[tuple[bytes, int]]:
    """(packet, arrival time) for ``n`` segments sent exactly on schedule."""
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    marker.start_epoch(START - 123)  # rounds up to START
    out = []
    for i in range(n):
        t = marker.scheduled_time()
        out.append(
            (sender.send_replay_segment(frame(sender, i, t), ALL, recall(i), marker, now_ns=t), t)
        )
    return out


def test_scheduled_replay_segments_are_accepted_and_decoded(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path)
    for i, (packet, t) in enumerate(honest_stream(sender, 5)):
        result = receiver.receive(packet, now_ns=t + 1_000_000)  # 1 ms network delay
        assert result.accepted, (i, result.violations)
    assert receiver.decoder_invocations == 5


def test_second_epoch_follows_the_first(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path)
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    for epoch_start in (START, START + 10**10):
        marker.start_epoch(epoch_start)
        for i in range(2):
            t = marker.scheduled_time()
            p = sender.send_replay_segment(frame(sender, i, t), ALL, recall(i), marker, now_ns=t)
            assert receiver.receive(p, now_ns=t).accepted
    assert marker.epoch == 1


def test_replay_without_watermark_is_refused_before_decoding(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path)
    f = frame(sender, 0, START)
    encoded = frame_to_payload(f, wire())
    payload = encoded.payload + recall(0).encode().encode()
    packet = sender._seal(
        encoded.types_bitmap, consent_flags_for(encoded, sender._rights_flags()), payload, START
    )
    result = receiver.receive(packet, now_ns=START)
    assert not result.accepted
    assert any("exactly one watermark" in v for v in result.violations)
    assert receiver.decoder_invocations == 0


def test_watermark_on_live_segment_is_refused(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path)
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    marker.start_epoch(START)
    f = frame(sender, 0, START)
    encoded = frame_to_payload(f, wire())
    mark, _ = marker.watermark(sender.timeline_id, encoded.payload)
    flags = consent_flags_for(encoded, sender._rights_flags())
    packet = sender._seal(encoded.types_bitmap, flags, encoded.payload + mark, START)
    result = receiver.receive(packet, now_ns=START)
    assert not result.accepted
    assert any("non-replay" in v for v in result.violations)


def test_receiver_without_policy_fails_closed(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path, policy=None)
    packet, t = honest_stream(sender, 1)[0]
    result = receiver.receive(packet, now_ns=t)
    assert not result.accepted
    assert any("fail closed" in v for v in result.violations)
    assert receiver.decoder_invocations == 0
    # live frames are unaffected
    assert receiver.receive(
        sender.send_frame(frame(sender, 1, t), ALL, now_ns=t), now_ns=t
    ).accepted


def test_replay_needs_allow_replay_consent(tmp_path: Path) -> None:
    sender, _ = pair(tmp_path, rights=Rights(0))
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    marker.start_epoch(START)
    with pytest.raises(SessionStateError, match="ALLOW_REPLAY"):
        sender.send_replay_segment(frame(sender, 0, START), ALL, recall(0), marker, now_ns=START)
    # a crafted segment is refused by the receiver as well
    sender2, receiver2 = pair(tmp_path / "b", rights=Rights(0))
    f = frame(sender2, 0, START)
    encoded = frame_to_payload(f, wire())
    payload = encoded.payload + recall(0).encode().encode()
    mark, ts = marker.watermark(sender2.timeline_id, payload)
    flags = consent_flags_for(encoded, sender2._rights_flags())
    packet = sender2._seal(encoded.types_bitmap, flags, payload + mark, ts)
    result = receiver2.receive(packet, now_ns=ts)
    assert not result.accepted
    assert any("ALLOW_REPLAY" in v for v in result.violations)


def test_sender_cannot_send_off_schedule(tmp_path: Path) -> None:
    sender, _ = pair(tmp_path)
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    marker.start_epoch(START)
    late = START + SCHEDULE.tolerance_ns + 1
    with pytest.raises(ReplayWatermarkError, match="scheduled time") as exc:
        sender.send_replay_segment(frame(sender, 0, late), ALL, recall(0), marker, now_ns=late)
    assert exc.value.code is ErrorCode.REPLAY_WATERMARK_INVALID


def _stego_stream(
    tmp_path: Path, bits: list[int], *, delta_ns: int
) -> tuple[list[bool], list[int], ReceiverEndpoint]:
    """A covert sender delays segment i by bits[i]·delta_ns (arrival timing as a carrier)."""
    sender, receiver = pair(tmp_path)
    accepted, stamps = [], []
    for (packet, t), bit in zip(honest_stream(sender, len(bits)), bits, strict=True):
        result = receiver.receive(packet, now_ns=t + bit * delta_ns)
        accepted.append(result.accepted)
        if result.accepted and result.frame is not None:
            stamps.append(t)
    return accepted, stamps, receiver


def test_timing_modulation_beyond_tolerance_is_refused(tmp_path: Path) -> None:
    bits = [0, 1, 1, 0, 1]
    accepted, _, receiver = _stego_stream(tmp_path, bits, delta_ns=20_000_000)
    assert accepted[0]  # segment 0 anchors the epoch
    assert accepted[1:] == [False, False, False, False]  # stream breaks at the first delayed bit
    assert any("tolerance" in v for vs in receiver.rejections for v in vs)


def test_accepted_timing_carries_no_sender_bits(tmp_path: Path) -> None:
    """Within the tolerance every bit string yields the same accepted timestamps."""
    runs = []
    for k, bits in enumerate(([0, 0, 0, 0], [0, 1, 0, 1], [0, 1, 1, 1])):
        accepted, stamps, _ = _stego_stream(tmp_path / str(k), bits, delta_ns=4_000_000)
        assert all(accepted)
        runs.append([s - stamps[0] for s in stamps])
    assert runs[0] == runs[1] == runs[2]  # the header timeline is the vendor's, not the sender's


def test_header_timestamp_modulation_is_refused(tmp_path: Path) -> None:
    """A covert sender that shifts the header timestamp (1 ms per bit) is refused."""
    sender, receiver = pair(tmp_path)
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    marker.start_epoch(START)
    for i, bit in enumerate([0, 1]):
        t = marker.scheduled_time()
        f = frame(sender, i, t)
        encoded = frame_to_payload(f, wire())
        payload = encoded.payload + recall(i).encode().encode()
        mark, ts = marker.watermark(sender.timeline_id, payload)
        flags = consent_flags_for(encoded, sender._rights_flags())
        packet = sender._seal(encoded.types_bitmap, flags, payload + mark, ts + bit * 1_000_000)
        result = receiver.receive(packet, now_ns=t)
        assert result.accepted is (bit == 0), result.violations
    assert any("off the replay schedule" in v for v in receiver.rejections[-1])


def test_tampered_recall_frame_breaks_the_tag(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path)
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    marker.start_epoch(START)
    f = frame(sender, 0, START)
    encoded = frame_to_payload(f, wire())
    payload = encoded.payload + recall(0).encode().encode()
    mark, ts = marker.watermark(sender.timeline_id, payload)
    swapped = encoded.payload + encode_tlv(0x51, (b"\xc2" * 32) + recall(0).encode().value[32:])
    flags = consent_flags_for(encoded, sender._rights_flags())
    packet = sender._seal(encoded.types_bitmap, flags, swapped + mark, ts)
    result = receiver.receive(packet, now_ns=ts)
    assert not result.accepted
    assert any("tag does not verify" in v for v in result.violations)
