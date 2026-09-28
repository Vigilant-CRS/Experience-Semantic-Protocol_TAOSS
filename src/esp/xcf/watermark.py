# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Replay-pattern watermark (GAP-016 reference proposal, ADR-0030).

V13 covert-channel hardening, item 5: "Replay segments include vendor-side
watermark TLVs preventing replay-timing patterns from being repurposed as a
steganographic carrier." V13 assigns no code; this is the reference proposal.

**Replay segment.** An ESP data packet that carries ``RECALL_FRAME`` (0x51),
i.e. a stored capsule replayed as a live stream (V13 "Recall Path").

**Wire.** Addendum TLV ``0x89 REPLAY_WATERMARK`` (profile ``esp-addendum-v1``).
It MUST be the last TLV of the payload. Body, 48 bytes, big-endian::

    vendor_id[16] ‖ replay_epoch u32 ‖ replay_index u32 ‖ scheduled_offset_ns u64 ‖ tag[16]

    tag = BLAKE2b-128(key = vendor_key,
                      "esp/v1/replay-watermark" ‖ timeline_id[16] ‖ replay_epoch u32
                      ‖ replay_index u32 ‖ scheduled_offset_ns u64 ‖ BLAKE2b-256(prefix))

``prefix`` is every payload byte before the watermark TLV (it contains the
``RECALL_FRAME``, so the watermark is bound to the replayed CID and span).
``segment_seq`` is *not* in the tag: the sequence number is assigned after the
payload is final (retransmissions reuse it), and the AEAD already binds the
header, including ``segment_seq``, to the whole payload.

**Schedule.** Replay timing is decided by the vendor key, not by the sender::

    offset(0) = 0
    offset(i) = i · period_ns + (u64_be(BLAKE2b-64(key = vendor_key,
                    "esp/v1/replay-schedule" ‖ vendor_id ‖ epoch u32 ‖ i u32)) mod (jitter_ns + 1))

with ``jitter_ns < period_ns`` (strictly increasing offsets). Epochs are
numbered per session from 0 without gaps. Segment ``i`` of an epoch MUST carry
``header.timestamp_ns = base_ns + offset(i)`` exactly, where ``base_ns`` is the
timestamp of segment 0 and a multiple of ``start_grid_ns``. It MUST arrive at
``arrival(0) + offset(i) ± tolerance_ns``. Indices are contiguous.

**Receiver rules** (:class:`ReplayVerifier`):

- a replay segment without exactly one watermark, as the last TLV, is refused;
- a watermark on a non-replay segment is refused;
- unknown vendor, bad tag, wrong epoch or index, an offset that differs from
  the schedule, a header timestamp off the schedule or off the start grid, and
  an arrival outside the tolerance are refused.

The error code is ``REPLAY_WATERMARK_INVALID`` (0x0401).

**What remains.** Within one epoch the sender has no timing choice beyond
``tolerance_ns`` of arrival jitter. Per epoch it chooses the start slot on the
``start_grid_ns`` grid. Each epoch needs a fresh recall (capability, types, DP
budget, expiry), which rate-limits that residual. The vendor key is symmetric:
whoever verifies can also produce tags, so the tag authenticates the vendor
component to receivers that trust it, not to third parties.
"""

from __future__ import annotations

import hmac
import struct
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from esp.codec.header import Header
from esp.codec.tlv import TLV_HEADER_LEN, ParsedPayload, Tlv, iter_tlvs
from esp.core.errors import ErrorCode, EspError
from esp.crypto.primitives import blake2b

REPLAY_WATERMARK_CODE: Final = 0x89
RECALL_FRAME_CODE: Final = 0x51
TAG_DOMAIN: Final = b"esp/v1/replay-watermark"
SCHEDULE_DOMAIN: Final = b"esp/v1/replay-schedule"
_BODY: Final = struct.Struct(">16sIIQ16s")
BODY_LEN: Final = _BODY.size  # 48
TLV_LEN: Final = TLV_HEADER_LEN + BODY_LEN


class ReplayWatermarkError(EspError):
    """A replay segment violates the replay-watermark rules (GAP-016, ADR-0030)."""

    code = ErrorCode.REPLAY_WATERMARK_INVALID


@dataclass(frozen=True, slots=True)
class VendorKey:
    vendor_id: bytes
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.vendor_id) != 16 or len(self.key) != 32:
            msg = "vendor_id must be 16 bytes and the vendor key 32 bytes"
            raise ReplayWatermarkError(msg)


@dataclass(frozen=True, slots=True)
class ReplaySchedule:
    period_ns: int
    """Nominal spacing between replay segments."""
    jitter_ns: int
    """Keyed pseudo-random jitter window; must be smaller than the period."""
    tolerance_ns: int
    """Allowed arrival deviation (network jitter)."""
    start_grid_ns: int = 1_000_000_000
    """Epoch start timestamps lie on this grid (bounds the per-epoch start choice)."""

    def __post_init__(self) -> None:
        if self.period_ns <= 0 or not 0 <= self.jitter_ns < self.period_ns:
            msg = "need period_ns > 0 and 0 <= jitter_ns < period_ns"
            raise ReplayWatermarkError(msg)
        if not 0 <= self.tolerance_ns < self.period_ns // 2 or self.start_grid_ns <= 0:
            msg = "need 0 <= tolerance_ns < period_ns / 2 and start_grid_ns > 0"
            raise ReplayWatermarkError(msg)


@dataclass(frozen=True, slots=True)
class Watermark:
    vendor_id: bytes
    epoch: int
    index: int
    scheduled_offset_ns: int
    tag: bytes

    def encode(self) -> Tlv:
        return Tlv(
            REPLAY_WATERMARK_CODE,
            _BODY.pack(self.vendor_id, self.epoch, self.index, self.scheduled_offset_ns, self.tag),
        )

    @classmethod
    def decode(cls, tlv: Tlv) -> Watermark:
        if tlv.code != REPLAY_WATERMARK_CODE or len(tlv.value) != BODY_LEN:
            msg = "malformed REPLAY_WATERMARK"
            raise ReplayWatermarkError(msg)
        return cls(*_BODY.unpack(tlv.value))


def scheduled_offset(vendor: VendorKey, epoch: int, index: int, schedule: ReplaySchedule) -> int:
    if index == 0:
        return 0
    seed = SCHEDULE_DOMAIN + vendor.vendor_id + struct.pack(">II", epoch, index)
    jitter = int.from_bytes(blake2b(seed, key=vendor.key, digest_size=8), "big")
    return index * schedule.period_ns + jitter % (schedule.jitter_ns + 1)


def watermark_tag(
    vendor: VendorKey,
    timeline_id: uuid.UUID,
    *,
    epoch: int,
    index: int,
    offset_ns: int,
    prefix: bytes,
) -> bytes:
    msg = (
        TAG_DOMAIN
        + timeline_id.bytes
        + struct.pack(">IIQ", epoch, index, offset_ns)
        + blake2b(prefix, digest_size=32)
    )
    return blake2b(msg, key=vendor.key, digest_size=16)


# --- vendor side ----------------------------------------------------------------------------------


@dataclass
class ReplayWatermarker:
    """Vendor-side replay component: owns the key and the schedule, not the sender's clock."""

    vendor: VendorKey
    schedule: ReplaySchedule
    epoch: int = -1
    base_ns: int = 0
    next_index: int = 0

    def start_epoch(self, now_ns: int) -> int:
        """Begin the next epoch at the first start-grid slot at or after ``now_ns``."""
        grid = self.schedule.start_grid_ns
        self.epoch += 1
        self.base_ns = -(-now_ns // grid) * grid
        self.next_index = 0
        return self.base_ns

    def scheduled_time(self, index: int | None = None) -> int:
        i = self.next_index if index is None else index
        return self.base_ns + scheduled_offset(self.vendor, self.epoch, i, self.schedule)

    def watermark(self, timeline_id: uuid.UUID, prefix: bytes) -> tuple[bytes, int]:
        """Return (encoded 0x89 TLV, scheduled header timestamp) for the next segment."""
        if self.epoch < 0:
            msg = "start an epoch first"
            raise ReplayWatermarkError(msg)
        i = self.next_index
        offset = scheduled_offset(self.vendor, self.epoch, i, self.schedule)
        tag = watermark_tag(
            self.vendor, timeline_id, epoch=self.epoch, index=i, offset_ns=offset, prefix=prefix
        )
        self.next_index += 1
        wm = Watermark(self.vendor.vendor_id, self.epoch, i, offset, tag)
        return wm.encode().encode(), self.base_ns + offset


# --- receiver side --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReplayWatermarkPolicy:
    """Receiver configuration: trusted vendors and the declared schedule."""

    vendors: Mapping[bytes, bytes]
    """vendor_id -> vendor key."""
    schedule: ReplaySchedule


@dataclass(frozen=True, slots=True)
class _Epoch:
    epoch: int
    base_ns: int
    arrival0_ns: int
    next_index: int


@dataclass(frozen=True, slots=True)
class ReplayAdvance:
    """Verifier state after one segment; applied only if the packet is accepted."""

    vendor_id: bytes
    state: _Epoch


def is_replay_segment(parsed: ParsedPayload) -> bool:
    return parsed.get(RECALL_FRAME_CODE) is not None


def _last_tlv(plaintext: bytes) -> Tlv | None:
    tlvs: Sequence[Tlv] = iter_tlvs(plaintext)
    return tlvs[-1] if tlvs else None


@dataclass
class ReplayVerifier:
    policy: ReplayWatermarkPolicy
    _epochs: dict[bytes, _Epoch] = field(default_factory=dict)

    def check(
        self, header: Header, plaintext: bytes, parsed: ParsedPayload, *, now_ns: int
    ) -> ReplayAdvance | None:
        """Validate one data packet. ``None`` for non-replay packets without a watermark."""
        marks = parsed.all(REPLAY_WATERMARK_CODE)
        if not is_replay_segment(parsed):
            if marks:
                msg = "watermark on a non-replay segment"
                raise ReplayWatermarkError(msg)
            return None
        last = _last_tlv(plaintext)
        if len(marks) != 1 or last is None or last.code != REPLAY_WATERMARK_CODE:
            msg = "replay segment needs exactly one watermark as its last TLV"
            raise ReplayWatermarkError(msg)
        wm = Watermark.decode(last)
        key = self.policy.vendors.get(wm.vendor_id)
        if key is None:
            msg = "watermark from an untrusted vendor"
            raise ReplayWatermarkError(msg)
        vendor = VendorKey(wm.vendor_id, key)
        prefix = plaintext[: len(plaintext) - TLV_LEN]
        expected = watermark_tag(
            vendor,
            header.timeline_id,
            epoch=wm.epoch,
            index=wm.index,
            offset_ns=wm.scheduled_offset_ns,
            prefix=prefix,
        )
        if not hmac.compare_digest(expected, wm.tag):
            msg = "replay watermark tag does not verify"
            raise ReplayWatermarkError(msg)
        schedule = self.policy.schedule
        if wm.scheduled_offset_ns != scheduled_offset(vendor, wm.epoch, wm.index, schedule):
            msg = "scheduled offset differs from the vendor schedule"
            raise ReplayWatermarkError(msg)
        state = self._next_state(wm, header, now_ns)
        if header.timestamp_ns != state.base_ns + wm.scheduled_offset_ns:
            msg = "header timestamp is off the replay schedule"
            raise ReplayWatermarkError(msg)
        arrival = now_ns - state.arrival0_ns
        if abs(arrival - wm.scheduled_offset_ns) > schedule.tolerance_ns:
            msg = "replay segment arrived outside the scheduled tolerance"
            raise ReplayWatermarkError(msg)
        return ReplayAdvance(wm.vendor_id, state)

    def _next_state(self, wm: Watermark, header: Header, now_ns: int) -> _Epoch:
        current = self._epochs.get(wm.vendor_id)
        if wm.index == 0:
            expected_epoch = 0 if current is None else current.epoch + 1
            if wm.epoch != expected_epoch:
                msg = f"replay epoch must be {expected_epoch}"
                raise ReplayWatermarkError(msg)
            if header.timestamp_ns % self.policy.schedule.start_grid_ns:
                msg = "replay epoch start is off the start grid"
                raise ReplayWatermarkError(msg)
            return _Epoch(wm.epoch, header.timestamp_ns, now_ns, 1)
        if current is None or wm.epoch != current.epoch or wm.index != current.next_index:
            msg = "replay index is not the next contiguous index of the current epoch"
            raise ReplayWatermarkError(msg)
        return _Epoch(current.epoch, current.base_ns, current.arrival0_ns, wm.index + 1)

    def commit(self, advance: ReplayAdvance) -> None:
        self._epochs[advance.vendor_id] = advance.state
