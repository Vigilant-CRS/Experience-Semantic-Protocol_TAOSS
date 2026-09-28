# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GAP-016 / ADR-0030: REPLAY_WATERMARK 0x89 layout, vendor schedule and verifier rules."""

import dataclasses
import itertools
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from esp.codec.header import Header
from esp.codec.tlv import ADDENDUM_V1_CODES, Tlv, encode_tlv, parse_payload
from esp.core.errors import ErrorCode
from esp.registry_service import ADDENDUM_TLV_CODES
from esp.xcf.gate import RecallFrame
from esp.xcf.watermark import (
    BODY_LEN,
    REPLAY_WATERMARK_CODE,
    ReplaySchedule,
    ReplayVerifier,
    ReplayWatermarker,
    ReplayWatermarkError,
    ReplayWatermarkPolicy,
    VendorKey,
    Watermark,
    scheduled_offset,
    watermark_tag,
)

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[3]
TIMELINE = uuid.UUID("5f0c6a8e-3b7d-4c4e-9a53-2f6a1d9e8b10")
VENDOR = VendorKey(b"V" * 16, b"\x77" * 32)
SCHEDULE = ReplaySchedule(period_ns=200_000_000, jitter_ns=50_000_000, tolerance_ns=5_000_000)
POLICY = ReplayWatermarkPolicy(vendors={VENDOR.vendor_id: VENDOR.key}, schedule=SCHEDULE)
START = 1_727_000_000_000_000_000
BODY = encode_tlv(0x60, b"\x00" * 16)  # stands in for the frame TLVs


def header(timestamp_ns: int, seq: int = 0) -> Header:
    return Header(
        profile=1,
        sf_level=0,
        types_bitmap=0x0001,
        consent_flags=0,
        privacy_flags=0,
        capabilities=0,
        timestamp_ns=timestamp_ns,
        timeline_id=TIMELINE,
        segment_seq=seq,
        dt_ms=0,
        phase=0.0,
        sender_id=bytes(32),
        payload_len=0,
        nonce=bytes(12),
    )


def segment(marker: ReplayWatermarker, i: int) -> tuple[Header, bytes]:
    prefix = BODY + RecallFrame(b"\xc1" * 32, i, 1).encode().encode()
    mark, ts = marker.watermark(TIMELINE, prefix)
    return header(ts, i), prefix + mark


def check(v: ReplayVerifier, h: Header, payload: bytes, now_ns: int) -> None:
    parsed = parse_payload(payload, extra_codes=ADDENDUM_V1_CODES)
    advance = v.check(h, payload, parsed, now_ns=now_ns)
    assert advance is not None
    v.commit(advance)


def stream(n: int) -> list[tuple[Header, bytes]]:
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    marker.start_epoch(START)
    return [segment(marker, i) for i in range(n)]


# --- wire -----------------------------------------------------------------------------------------


def test_layout_is_48_bytes_and_roundtrips() -> None:
    wm = Watermark(b"V" * 16, 7, 9, 123_456_789, b"\xaa" * 16)
    tlv = wm.encode()
    assert tlv.code == REPLAY_WATERMARK_CODE == 0x89
    assert len(tlv.value) == BODY_LEN == 48
    assert tlv.value[16:20] == (7).to_bytes(4, "big")
    assert tlv.value[24:32] == (123_456_789).to_bytes(8, "big")
    assert Watermark.decode(tlv) == wm
    for bad in (tlv.value[:-1], tlv.value + b"\x00"):
        with pytest.raises(ReplayWatermarkError, match="malformed"):
            Watermark.decode(Tlv(0x89, bad))


def test_code_is_registered_in_the_addendum_profile() -> None:
    assert ADDENDUM_TLV_CODES[0x89] == "REPLAY_WATERMARK"
    assert 0x89 in ADDENDUM_V1_CODES
    assert ErrorCode.REPLAY_WATERMARK_INVALID == 0x0401


# --- schedule -------------------------------------------------------------------------------------


def test_schedule_is_keyed_deterministic_and_increasing() -> None:
    offs = [scheduled_offset(VENDOR, 0, i, SCHEDULE) for i in range(50)]
    assert offs[0] == 0
    assert offs == [scheduled_offset(VENDOR, 0, i, SCHEDULE) for i in range(50)]
    for i, o in enumerate(offs[1:], start=1):
        assert i * SCHEDULE.period_ns <= o <= i * SCHEDULE.period_ns + SCHEDULE.jitter_ns
    assert all(b > a for a, b in itertools.pairwise(offs))
    other = VendorKey(VENDOR.vendor_id, b"\x78" * 32)
    assert offs != [scheduled_offset(other, 0, i, SCHEDULE) for i in range(50)]
    assert offs != [scheduled_offset(VENDOR, 1, i, SCHEDULE) for i in range(50)]
    jitters = {o % SCHEDULE.period_ns for o in offs[1:]}
    assert len(jitters) > 40  # the jitter actually varies


@pytest.mark.parametrize(
    "kw",
    [
        {"period_ns": 0, "jitter_ns": 0, "tolerance_ns": 0},
        {"period_ns": 100, "jitter_ns": 100, "tolerance_ns": 0},
        {"period_ns": 100, "jitter_ns": 10, "tolerance_ns": 50},
        {"period_ns": 100, "jitter_ns": 10, "tolerance_ns": 1, "start_grid_ns": 0},
    ],
)
def test_bad_schedules_rejected(kw: dict[str, int]) -> None:
    with pytest.raises(ReplayWatermarkError):
        ReplaySchedule(**kw)


def test_bad_vendor_keys_rejected() -> None:
    with pytest.raises(ReplayWatermarkError):
        VendorKey(b"V" * 15, b"\x00" * 32)
    with pytest.raises(ReplayWatermarkError):
        VendorKey(b"V" * 16, b"\x00" * 31)
    assert "77" not in repr(VENDOR)  # the key never appears in logs


def test_epoch_start_rounds_up_to_the_grid() -> None:
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    assert marker.start_epoch(START + 1) == START + SCHEDULE.start_grid_ns
    assert marker.epoch == 0
    with pytest.raises(ReplayWatermarkError, match="start an epoch"):
        ReplayWatermarker(VENDOR, SCHEDULE).watermark(TIMELINE, b"")


# --- verifier -------------------------------------------------------------------------------------


def test_honest_stream_verifies() -> None:
    v = ReplayVerifier(POLICY)
    for h, payload in stream(6):
        check(v, h, payload, now_ns=h.timestamp_ns + 2_000_000)


def test_non_replay_segment_without_watermark_is_ignored() -> None:
    v = ReplayVerifier(POLICY)
    parsed = parse_payload(BODY, extra_codes=ADDENDUM_V1_CODES)
    assert v.check(header(START), BODY, parsed, now_ns=START) is None


def _refused(v: ReplayVerifier, h: Header, payload: bytes, now_ns: int, match: str) -> None:
    parsed = parse_payload(payload, extra_codes=ADDENDUM_V1_CODES)
    with pytest.raises(ReplayWatermarkError, match=match) as exc:
        v.check(h, payload, parsed, now_ns=now_ns)
    assert exc.value.code is ErrorCode.REPLAY_WATERMARK_INVALID


def test_missing_duplicate_or_misplaced_watermark_refused() -> None:
    (h, payload), *_ = stream(1)
    prefix, mark = payload[:-53], payload[-53:]
    v = ReplayVerifier(POLICY)
    _refused(v, h, prefix, START, "exactly one watermark")
    _refused(v, h, prefix + mark + mark, START, "exactly one watermark")
    _refused(v, h, prefix + mark + encode_tlv(0x88, b""), START, "exactly one watermark")
    _refused(v, h, BODY + mark, START, "non-replay")


def test_untrusted_vendor_and_bad_tag_refused() -> None:
    (h, payload), *_ = stream(1)
    other = ReplayWatermarkPolicy(vendors={b"W" * 16: VENDOR.key}, schedule=SCHEDULE)
    _refused(ReplayVerifier(other), h, payload, START, "untrusted vendor")
    flipped = payload[:-1] + bytes([payload[-1] ^ 1])
    _refused(ReplayVerifier(POLICY), h, flipped, START, "tag does not verify")
    changed_body = b"\x61" + payload[1:]  # any prefix change breaks the tag
    _refused(ReplayVerifier(POLICY), h, changed_body, START, "tag does not verify")
    other_timeline = dataclasses.replace(h, timeline_id=uuid.uuid4())
    _refused(ReplayVerifier(POLICY), other_timeline, payload, START, "tag does not verify")


def test_key_holder_cannot_choose_the_offset() -> None:
    """Even with the key, an offset that differs from the schedule is refused."""
    (h0, p0), (_, p1) = stream(2)
    v = ReplayVerifier(POLICY)
    check(v, h0, p0, START)
    prefix = p1[:-53]
    wm = Watermark.decode(Tlv(0x89, p1[-48:]))
    forged_offset = wm.scheduled_offset_ns + 3_000_000  # within tolerance, but chosen
    tag = watermark_tag(VENDOR, TIMELINE, epoch=0, index=1, offset_ns=forged_offset, prefix=prefix)
    forged = Watermark(wm.vendor_id, 0, 1, forged_offset, tag).encode().encode()
    h = header(START + forged_offset, 1)
    _refused(v, h, prefix + forged, START + forged_offset, "differs from the vendor schedule")


def test_epochs_start_at_zero_and_advance_by_one() -> None:
    marker = ReplayWatermarker(VENDOR, SCHEDULE)
    marker.epoch = 4  # a sender choosing its epoch number
    marker.start_epoch(START)
    h, payload = segment(marker, 0)
    _refused(ReplayVerifier(POLICY), h, payload, START, "epoch must be 0")
    v = ReplayVerifier(POLICY)
    for h, payload in stream(1):
        check(v, h, payload, START)
    (h, payload), *_ = stream(1)  # epoch 0 again: a replayed epoch
    _refused(v, h, payload, START + 10**10, "epoch must be 1")


def test_indices_must_be_contiguous() -> None:
    segs = stream(4)
    v = ReplayVerifier(POLICY)
    check(v, *segs[0], now_ns=START)
    h2, p2 = segs[2]  # skipping index 1 (choosing which segments to drop is a carrier)
    _refused(v, h2, p2, h2.timestamp_ns, "next contiguous index")
    h1, p1 = segs[1]
    check(v, h1, p1, h1.timestamp_ns)
    _refused(v, h1, p1, h1.timestamp_ns, "next contiguous index")  # repeat


def test_index_without_epoch_start_refused() -> None:
    h1, p1 = stream(2)[1]
    _refused(ReplayVerifier(POLICY), h1, p1, h1.timestamp_ns, "next contiguous index")


def test_header_timestamp_must_match_schedule_and_grid() -> None:
    segs = stream(2)
    v = ReplayVerifier(POLICY)
    h0, p0 = segs[0]
    _refused(v, dataclasses.replace(h0, timestamp_ns=START + 1), p0, START, "start grid")
    check(v, h0, p0, START)
    h1, p1 = segs[1]
    shifted = dataclasses.replace(h1, timestamp_ns=h1.timestamp_ns + 1)
    _refused(v, shifted, p1, h1.timestamp_ns, "off the replay schedule")


def test_arrival_must_follow_the_schedule() -> None:
    segs = stream(3)
    v = ReplayVerifier(POLICY)
    arrival0 = START + 7_000_000  # constant network delay is fine
    check(v, *segs[0], now_ns=arrival0)
    h1, p1 = segs[1]
    offset1 = h1.timestamp_ns - START
    _refused(v, h1, p1, arrival0 + offset1 + SCHEDULE.tolerance_ns + 1, "tolerance")
    _refused(v, h1, p1, arrival0 + offset1 - SCHEDULE.tolerance_ns - 1, "tolerance")
    check(v, h1, p1, arrival0 + offset1 + SCHEDULE.tolerance_ns)


def test_state_advances_only_on_commit() -> None:
    segs = stream(2)
    v = ReplayVerifier(POLICY)
    h0, p0 = segs[0]
    parsed = parse_payload(p0, extra_codes=ADDENDUM_V1_CODES)
    assert v.check(h0, p0, parsed, now_ns=START) is not None  # not committed (packet refused later)
    h1, p1 = segs[1]
    _refused(v, h1, p1, h1.timestamp_ns, "next contiguous index")
    check(v, h0, p0, START)  # the retransmitted segment 0 still starts epoch 0


# --- golden vectors -------------------------------------------------------------------------------


def _vectors() -> list[dict[str, Any]]:
    doc = json.loads((ROOT / "vectors" / "replay" / "watermark.json").read_text("utf-8"))
    vectors: list[dict[str, Any]] = doc["vectors"]
    return vectors


def test_golden_vectors_reproduce_and_verify() -> None:
    vectors = _vectors()
    valid = [x for x in vectors if x["valid"]]
    assert len(valid) == 4
    first = valid[0]
    vendor = VendorKey(bytes.fromhex(first["vendor_id"]), bytes.fromhex(first["vendor_key"]))
    schedule = ReplaySchedule(
        period_ns=first["period_ns"],
        jitter_ns=first["jitter_ns"],
        tolerance_ns=first["tolerance_ns"],
        start_grid_ns=first["start_grid_ns"],
    )
    v = ReplayVerifier(ReplayWatermarkPolicy({vendor.vendor_id: vendor.key}, schedule))
    for x in valid:
        assert x["scheduled_offset_ns"] == scheduled_offset(
            vendor, x["epoch"], x["index"], schedule
        )
        assert x["header_timestamp_ns"] == x["base_timestamp_ns"] + x["scheduled_offset_ns"]
        payload = bytes.fromhex(x["prefix_hex"]) + bytes.fromhex(x["tlv_hex"])
        h = dataclasses.replace(
            header(x["header_timestamp_ns"]), timeline_id=uuid.UUID(x["timeline_id"])
        )
        check(v, h, payload, now_ns=x["header_timestamp_ns"])
    for x in (x for x in vectors if not x["valid"]):
        fresh = ReplayVerifier(ReplayWatermarkPolicy({vendor.vendor_id: vendor.key}, schedule))
        h0 = dataclasses.replace(
            header(valid[0]["header_timestamp_ns"]), timeline_id=uuid.UUID(x["timeline_id"])
        )
        check(
            fresh,
            h0,
            bytes.fromhex(valid[0]["prefix_hex"]) + bytes.fromhex(valid[0]["tlv_hex"]),
            now_ns=valid[0]["header_timestamp_ns"],
        )
        payload = bytes.fromhex(x["prefix_hex"]) + bytes.fromhex(x["tlv_hex"])
        h = dataclasses.replace(
            header(x["header_timestamp_ns"]), timeline_id=uuid.UUID(x["timeline_id"])
        )
        parsed = parse_payload(payload, extra_codes=ADDENDUM_V1_CODES)
        with pytest.raises(ReplayWatermarkError, match=x["expect_error"]):
            fresh.check(h, payload, parsed, now_ns=x["header_timestamp_ns"])
