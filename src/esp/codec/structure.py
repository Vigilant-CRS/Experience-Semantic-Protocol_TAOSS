# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bundle mode (0x01), capability extension (0x10), type profile (0x11). ``V13_NORMATIVE``.

Bundle mode (V13 section 8.7): ``N`` inner segments share one header and
signature. Each ``TLV_INNER_SEGMENT`` carries typed-latent TLVs for one
segment and is parsed with the same rules as a top-level payload
(one latent per type, TAOSS order). Precisions (errata WP-085): segments do
not nest, and a bundle payload carries no top-level typed latents.

Capability extension (V13 section 8.5): ``ext_count u16 || ext_bits`` packed
MSB-first in ``ceil(ext_count / 8)`` bytes; padding bits must be zero. The
header bit ``CAPS_EXT_PRESENT`` promises the TLV and vice versa. Unknown
extension bits are ignored.

Type profile (V13 section 8.4): ``profile_id[16] || type_count u16 ||
registry_digest[32]``; alternate TAOSS profiles must be pinned this way and
never reinterpret the six TAOSS-6 latent codes.
"""

from __future__ import annotations

import struct
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from esp.codec.errors import WireError
from esp.codec.header import CAPS_EXT_PRESENT, Header
from esp.codec.tlv import TYPED_LATENT_CODES, ParsedPayload, Tlv, encode_tlv, parse_payload

INNER_SEGMENT_CODE: Final = 0x01
CAPABILITIES_EXT_CODE: Final = 0x10
TYPE_PROFILE_CODE: Final = 0x11
MAX_SEGMENTS_PER_BUNDLE: Final = 256


# --- bundle mode ------------------------------------------------------------------


def encode_bundle(segments: Sequence[bytes], trailing: bytes = b"") -> bytes:
    """Wrap per-segment latent payloads into inner-segment TLVs (+ trailing control TLVs)."""
    if not 1 <= len(segments) <= MAX_SEGMENTS_PER_BUNDLE:
        msg = f"a bundle holds 1..{MAX_SEGMENTS_PER_BUNDLE} segments"
        raise WireError(msg)
    return b"".join(encode_tlv(INNER_SEGMENT_CODE, s) for s in segments) + trailing


@dataclass(frozen=True, slots=True)
class Bundle:
    segments: tuple[ParsedPayload, ...]
    top_level: ParsedPayload


def parse_bundle(payload: bytes, *, extra_codes: frozenset[int] = frozenset()) -> Bundle:
    top = parse_payload(payload, extra_codes=extra_codes)
    segments_raw = top.all(INNER_SEGMENT_CODE)
    if not segments_raw:
        msg = "not a bundle payload"
        raise WireError(msg)
    if len(segments_raw) > MAX_SEGMENTS_PER_BUNDLE:
        msg = "too many inner segments"
        raise WireError(msg)
    if any(t.code in TYPED_LATENT_CODES for t in top.known):
        msg = "bundle payload must not mix top-level typed latents with inner segments"
        raise WireError(msg)
    segments = []
    for seg in segments_raw:
        parsed = parse_payload(seg.value, extra_codes=extra_codes)
        if parsed.get(INNER_SEGMENT_CODE) is not None:
            msg = "inner segments must not nest"
            raise WireError(msg)
        segments.append(parsed)
    rest = tuple(t for t in top.known if t.code != INNER_SEGMENT_CODE)
    return Bundle(tuple(segments), ParsedPayload(rest, top.unknown))


# --- capability extension --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CapabilitiesExt:
    bits: tuple[bool, ...]

    def encode(self) -> Tlv:
        n = len(self.bits)
        if n > 0xFFFF:
            msg = "too many extension bits"
            raise WireError(msg)
        packed = bytearray((n + 7) // 8)
        for i, bit in enumerate(self.bits):
            if bit:
                packed[i // 8] |= 0x80 >> (i % 8)
        return Tlv(CAPABILITIES_EXT_CODE, struct.pack(">H", n) + bytes(packed))

    @classmethod
    def decode(cls, tlv: Tlv) -> CapabilitiesExt:
        v = tlv.value
        if tlv.code != CAPABILITIES_EXT_CODE or len(v) < 2:
            msg = "malformed capabilities extension"
            raise WireError(msg)
        (n,) = struct.unpack_from(">H", v, 0)
        packed = v[2:]
        if len(packed) != (n + 7) // 8:
            msg = "ext_bits length does not match ext_count"
            raise WireError(msg)
        bits = tuple(bool(packed[i // 8] & (0x80 >> (i % 8))) for i in range(n))
        if n % 8 and packed[-1] & (0xFF >> (n % 8)):
            msg = "capability extension padding bits must be zero"
            raise WireError(msg)
        return cls(bits)

    def has(self, index: int) -> bool:
        """Unknown (out-of-range) bits read as not set."""
        return 0 <= index < len(self.bits) and self.bits[index]


def check_caps_ext_promise(header: Header, parsed: ParsedPayload) -> CapabilitiesExt | None:
    """Header bit 15 ⇔ presence of TLV_CAPABILITIES_EXT."""
    tlv = parsed.get(CAPABILITIES_EXT_CODE)
    flagged = bool(header.capabilities & CAPS_EXT_PRESENT)
    if flagged != (tlv is not None):
        msg = "CAPS_EXT_PRESENT disagrees with TLV_CAPABILITIES_EXT presence"
        raise WireError(msg)
    return None if tlv is None else CapabilitiesExt.decode(tlv)


# --- type profile -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TypeProfile:
    profile_id: uuid.UUID
    type_count: int
    registry_digest: bytes

    def encode(self) -> Tlv:
        if not 1 <= self.type_count <= 0xFFFF or len(self.registry_digest) != 32:
            msg = "invalid type profile"
            raise WireError(msg)
        return Tlv(
            TYPE_PROFILE_CODE,
            self.profile_id.bytes + struct.pack(">H", self.type_count) + self.registry_digest,
        )

    @classmethod
    def decode(cls, tlv: Tlv, *, pinned: dict[uuid.UUID, bytes]) -> TypeProfile:
        """Decode and require the profile to be pinned with a matching registry digest."""
        v = tlv.value
        if tlv.code != TYPE_PROFILE_CODE or len(v) != 16 + 2 + 32:
            msg = "malformed type profile"
            raise WireError(msg)
        profile = cls(uuid.UUID(bytes=v[:16]), struct.unpack_from(">H", v, 16)[0], v[18:])
        expected = pinned.get(profile.profile_id)
        if expected is None:
            msg = "type profile is not pinned in this session"
            raise WireError(msg)
        if expected != profile.registry_digest:
            msg = "type profile registry digest mismatch"
            raise WireError(msg)
        if profile.type_count == 0:
            msg = "type_count must be positive"
            raise WireError(msg)
        return profile
