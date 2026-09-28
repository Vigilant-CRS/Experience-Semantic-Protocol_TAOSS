# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The 100-byte fixed ESP header (V13 Appendix A). ``V13_NORMATIVE``.

Byte layout (big-endian)::

    0x00  3  magic "ESP"          0x10  8  timestamp_ns
    0x03  1  version_major = 1    0x18 16  timeline_id (UUIDv4)
    0x04  1  version_minor = 0    0x28  4  segment_seq
    0x05  1  profile (L1 = 1)     0x2C  4  dt_ms
    0x06  1  sf_level 0..7        0x30  4  phase (IEEE-754 binary32, [0, 1))
    0x07  1  reserved = 0         0x34 32  sender_id (per-session Ed25519 pk)
    0x08  2  types_bitmap         0x54  4  payload_len (ciphertext bytes, ADR-0010)
    0x0A  2  consent_flags        0x58 12  nonce
    0x0C  2  privacy_flags
    0x0E  2  capabilities

Validation follows ADR-0017. Decoding is strict: every accepted header
re-encodes to the identical 100 bytes (``encode(decode(b)) == b``).
"""

from __future__ import annotations

import math
import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum, IntFlag, unique
from typing import Final

from esp.codec.errors import WireError
from esp.core.taoss_types import TYPES_BITMAP_ASSIGNED_MASK, TaossType

HEADER_LEN: Final = 100
TAG_LEN: Final = 16
SIGNATURE_LEN: Final = 64
PACKET_OVERHEAD: Final = HEADER_LEN + TAG_LEN + SIGNATURE_LEN  # 180
MAGIC: Final = b"ESP"
VERSION_MAJOR: Final = 0x01
VERSION_MINOR: Final = 0x00

_STRUCT: Final = struct.Struct(">3sBBBBBHHHHQ16sIIf32sI12s")
if _STRUCT.size != HEADER_LEN:  # pragma: no cover - import-time invariant
    msg = "header struct must be 100 bytes"
    raise RuntimeError(msg)


class ConsentFlags(IntFlag):
    EMO_MASKED = 1 << 0
    NO_REPLAY = 1 << 1
    NO_STORE = 1 << 2


CONSENT_ASSIGNED_MASK: Final = 0x0007


@unique
class DpLevel(IntEnum):
    """V13 ``DP_LEVEL`` — labels, not an ordered scale."""

    NONE = 0
    L1_BALANCED_REF = 1
    L1_PRIVATE_REF = 2
    PROFILE_DEFINED = 3


class PrivacyFlags(IntFlag):
    QUANTIZED = 1 << 4
    TIMING_OBF = 1 << 5


DP_LEVEL_MASK: Final = 0x000F
PRIVACY_ASSIGNED_MASK: Final = 0x003F

CAPS_EXT_PRESENT: Final = 1 << 15
CAPS_RESERVED_MASK: Final = 0x7000  # bits 12-14
CAPS_UNASSIGNED_MASK: Final = 0x0FFF  # bits 0-11: ignored on receive (ADR-0017)


@dataclass(frozen=True, slots=True)
class Header:
    profile: int
    sf_level: int
    types_bitmap: int
    consent_flags: int
    privacy_flags: int
    capabilities: int
    timestamp_ns: int
    timeline_id: uuid.UUID
    segment_seq: int
    dt_ms: int
    phase: float
    sender_id: bytes
    payload_len: int
    nonce: bytes
    version_major: int = VERSION_MAJOR
    version_minor: int = VERSION_MINOR

    def __post_init__(self) -> None:
        _validate(self)

    @property
    def types(self) -> tuple[TaossType, ...]:
        return tuple(t for t in TaossType if self.types_bitmap & t.bit)

    @property
    def dp_level(self) -> DpLevel:
        return DpLevel(self.privacy_flags & DP_LEVEL_MASK)

    @property
    def quantized(self) -> bool:
        return bool(self.privacy_flags & PrivacyFlags.QUANTIZED)

    @property
    def emo_masked(self) -> bool:
        return bool(self.consent_flags & ConsentFlags.EMO_MASKED)

    @property
    def packet_len(self) -> int:
        return PACKET_OVERHEAD + self.payload_len

    def encode(self) -> bytes:
        return _STRUCT.pack(
            MAGIC,
            self.version_major,
            self.version_minor,
            self.profile,
            self.sf_level,
            0,
            self.types_bitmap,
            self.consent_flags,
            self.privacy_flags,
            self.capabilities,
            self.timestamp_ns,
            self.timeline_id.bytes,
            self.segment_seq,
            self.dt_ms,
            self.phase,
            self.sender_id,
            self.payload_len,
            self.nonce,
        )

    @classmethod
    def decode(cls, data: bytes) -> Header:
        if len(data) != HEADER_LEN:
            msg = f"header must be exactly {HEADER_LEN} bytes, got {len(data)}"
            raise WireError(msg)
        (
            magic,
            vmaj,
            vmin,
            profile,
            sf_level,
            reserved,
            types_bitmap,
            consent,
            privacy,
            caps,
            timestamp_ns,
            timeline,
            seq,
            dt_ms,
            phase,
            sender_id,
            payload_len,
            nonce,
        ) = _STRUCT.unpack(data)
        if magic != MAGIC:
            msg = "bad magic"
            raise WireError(msg)
        if reserved != 0:
            msg = "reserved byte must be zero"
            raise WireError(msg)
        if math.copysign(1.0, phase) < 0.0:
            msg = "phase must not be negative (including -0.0)"
            raise WireError(msg)
        header = cls(
            profile=profile,
            sf_level=sf_level,
            types_bitmap=types_bitmap,
            consent_flags=consent,
            privacy_flags=privacy,
            capabilities=caps,
            timestamp_ns=timestamp_ns,
            timeline_id=uuid.UUID(bytes=timeline),
            segment_seq=seq,
            dt_ms=dt_ms,
            phase=phase,
            sender_id=sender_id,
            payload_len=payload_len,
            nonce=nonce,
            version_major=vmaj,
            version_minor=vmin,
        )
        if header.encode() != data:  # pragma: no cover - defence in depth
            msg = "header is not in canonical form"
            raise WireError(msg)
        return header


def _check_range(name: str, value: int, lo: int, hi: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
        msg = f"{name} out of range [{lo}, {hi}]: {value!r}"
        raise WireError(msg)


def _validate(h: Header) -> None:
    _check_range("version_major", h.version_major, VERSION_MAJOR, VERSION_MAJOR)
    _check_range("version_minor", h.version_minor, 0, 0xFF)
    _check_range("profile", h.profile, 0x01, 0xFF)
    _check_range("sf_level", h.sf_level, 0, 7)
    for name, value in (
        ("types_bitmap", h.types_bitmap),
        ("consent_flags", h.consent_flags),
        ("privacy_flags", h.privacy_flags),
        ("capabilities", h.capabilities),
    ):
        _check_range(name, value, 0, 0xFFFF)
    _check_range("timestamp_ns", h.timestamp_ns, 0, 2**64 - 1)
    _check_range("segment_seq", h.segment_seq, 0, 2**32 - 1)
    _check_range("dt_ms", h.dt_ms, 0, 2**32 - 1)
    _check_range("payload_len", h.payload_len, 0, 2**32 - 1)
    if h.types_bitmap & ~TYPES_BITMAP_ASSIGNED_MASK:
        msg = "reserved types_bitmap bits set"
        raise WireError(msg)
    if h.consent_flags & ~CONSENT_ASSIGNED_MASK:
        msg = "reserved consent_flags bits set"
        raise WireError(msg)
    if h.privacy_flags & ~PRIVACY_ASSIGNED_MASK:
        msg = "reserved privacy_flags bits set"
        raise WireError(msg)
    if (h.privacy_flags & DP_LEVEL_MASK) > max(DpLevel):
        msg = "reserved DP_LEVEL value"
        raise WireError(msg)
    if h.capabilities & CAPS_RESERVED_MASK:
        msg = "reserved capabilities bits 12-14 set"
        raise WireError(msg)
    if (h.types_bitmap & TaossType.EMO.bit) and (h.consent_flags & ConsentFlags.EMO_MASKED):
        msg = "mask-bit invariant violated: EMO present and EMO_MASKED set"
        raise WireError(msg)
    if (
        not isinstance(h.timeline_id, uuid.UUID)
        or h.timeline_id.version != 4
        or (h.timeline_id.variant != uuid.RFC_4122)
    ):
        msg = "timeline_id must be a UUIDv4"
        raise WireError(msg)
    if not isinstance(h.phase, float) or not math.isfinite(h.phase) or not 0.0 <= h.phase < 1.0:
        msg = f"phase must be a finite float in [0, 1): {h.phase!r}"
        raise WireError(msg)
    if struct.unpack(">f", struct.pack(">f", h.phase))[0] != h.phase:
        msg = "phase must be exactly representable as binary32"
        raise WireError(msg)
    if not isinstance(h.sender_id, bytes) or len(h.sender_id) != 32:
        msg = "sender_id must be 32 bytes"
        raise WireError(msg)
    if not isinstance(h.nonce, bytes) or len(h.nonce) != 12:
        msg = "nonce must be 12 bytes"
        raise WireError(msg)


def float32(value: float) -> float:
    """Round a Python float to the nearest binary32 value (for ``phase``)."""
    rounded: float = struct.unpack(">f", struct.pack(">f", value))[0]
    return rounded
